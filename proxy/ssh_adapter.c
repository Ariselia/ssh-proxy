#include "ssh-includes.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ssh_adapter.h"
#include "ssh/priv.h"
#include "ssh/ssh-api.h"
#include "ssh/server.h"
#include "ssh/pki.h"
#include "ssh/buffer.h"
#include "ssh/session.h"

#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/*
 * <wspiapi.h> is necessary for getaddrinfo before Windows XP, but it isn't
 * available on some platforms like MinGW.
 */
#ifdef HAVE_WSPIAPI_H
# include <wspiapi.h>
#endif

#define SOCKOPT_TYPE_ARG4 char

#else /* _WIN32 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#define SOCKOPT_TYPE_ARG4 int

#endif /* _WIN32 */

void ssh_adapter_free(ssh_adapter_t *adapter)
{
  int i;

  if (adapter == NULL) {
    return;
  }

  /* options */
  SAFE_FREE(adapter->banner);
  SAFE_FREE(adapter->bindaddr);

  SAFE_FREE(adapter->dsakey);
  SAFE_FREE(adapter->rsakey);
  SAFE_FREE(adapter->ecdsakey);

  ssh_key_free(adapter->dsa);
  adapter->dsa = NULL;
  ssh_key_free(adapter->rsa);
  adapter->rsa = NULL;
  ssh_key_free(adapter->ecdsa);
  adapter->ecdsa = NULL;

  for (i = 0; i < 10; i++) {
    if (adapter->wanted_methods[i]) {
      SAFE_FREE(adapter->wanted_methods[i]);
    }
  }

  SAFE_FREE(adapter);
}


ssh_adapter_t * ssh_adapter_new(void)
{
  ssh_adapter_t * ptr = NULL;

  ptr = malloc(sizeof(ssh_adapter_t));
  if (ptr == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(ptr);
  //ptr->bindfd = SSH_INVALID_SOCKET;
  ptr->bindport= 22;
  ptr->common.log_verbosity = 0;

  return ptr;
}


static int adapter_import_keys(ssh_adapter_t *adapter) {
  int rc;

  if (adapter->ecdsakey == NULL &&
      adapter->dsakey == NULL &&
      adapter->rsakey == NULL) {
      trace_err("ECDSA, DSA, or RSA host key file must be set");
      return SSH_ERROR;
  }

#ifdef HAVE_ECC
  if (adapter->ecdsa == NULL && adapter->ecdsakey != NULL) {
      rc = ssh_pki_import_privkey_file(adapter->ecdsakey,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &adapter->ecdsa);
      if (rc == SSH_ERROR || rc == SSH_EOF) {
          do_error("Failed to import private ECDSA host key");
          return SSH_ERROR;
      }

      if (ssh_key_type(adapter->ecdsa) != SSH_KEYTYPE_ECDSA) {
          do_error("The ECDSA host key has the wrong type");
          ssh_key_free(adapter->ecdsa);
          adapter->ecdsa = NULL;
          return SSH_ERROR;
      }
  }
#endif

  if (adapter->dsa == NULL && adapter->dsakey != NULL) {
      rc = ssh_pki_import_privkey_file(adapter->dsakey,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &adapter->dsa);
      if (rc == SSH_ERROR || rc == SSH_EOF) {
          do_error("Failed to import private DSA host key");
          return SSH_ERROR;
      }

      if (ssh_key_type(adapter->dsa) != SSH_KEYTYPE_DSS) {
          do_error("The DSA host key has the wrong type: %d",
                  ssh_key_type(adapter->dsa));
          ssh_key_free(adapter->dsa);
          adapter->dsa = NULL;
          return SSH_ERROR;
      }
  }

  if (adapter->rsa == NULL && adapter->rsakey != NULL) {
      rc = ssh_pki_import_privkey_file(adapter->rsakey,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &adapter->rsa);
      if (rc == SSH_ERROR || rc == SSH_EOF) {
          do_error("Failed to import private RSA host key");
          return SSH_ERROR;
      }

      if (ssh_key_type(adapter->rsa) != SSH_KEYTYPE_RSA &&
          ssh_key_type(adapter->rsa) != SSH_KEYTYPE_RSA1) {
          do_error("The RSA host key has the wrong type");
          ssh_key_free(adapter->rsa);
          adapter->rsa = NULL;
          return SSH_ERROR;
      }
  }

  return SSH_OK;
}

int ssh_adapter_init(ssh_adapter_t *adapter)
{
	const char *host;
	int rc;
	
	if (ssh_init() < 0) {
		trace_err("ssh_init() failed");
		return -1;
	}
	
	rc = adapter_import_keys(adapter);
	if (rc != SSH_OK) {
		return SSH_ERROR;
	}
	
	host = adapter->bindaddr;
	if (host == NULL) {
		host = "0.0.0.0";
	}

	return SSH_OK;
}


int ssh_adapter_accept(ssh_adapter_t *adapter, ssh_session_t * session)
{
    int i, rc;

    if (session == NULL){
        trace_err("session is null");
        return SSH_ERROR;
    }

    session->server = 1;
    session->version = 2;

    /* copy options */
    for (i = 0; i < 10; ++i) {
      if (adapter->wanted_methods[i]) {
        session->opts.wanted_methods[i] = strdup(adapter->wanted_methods[i]);
        if (session->opts.wanted_methods[i] == NULL) {
          return SSH_ERROR;
        }
      }
    }

    if (adapter->bindaddr == NULL) {
      session->opts.bindaddr = NULL;
	} else {
      SAFE_FREE(session->opts.bindaddr);
      session->opts.bindaddr = strdup(adapter->bindaddr);
      if (session->opts.bindaddr == NULL) {
        return SSH_ERROR;
      }
    }

    session->common.log_verbosity = adapter->common.log_verbosity;
    if(adapter->banner != NULL) {
    	session->opts.custombanner = strdup(adapter->banner);
    }
    
    /* We must try to import any keys that could be imported in case
     * we are not using ssh_bind_listen (which is the other place
     * where keys can be imported) on this ssh_bind and are instead
     * only using ssh_bind_accept_fd to manage sockets ourselves.
     */
    rc = adapter_import_keys(adapter);
    if (rc != SSH_OK) {
      return SSH_ERROR;
    }

#ifdef HAVE_ECC
    if (adapter->ecdsa) {
        session->srv.ecdsa_key = ssh_key_dup(adapter->ecdsa);
        if (session->srv.ecdsa_key == NULL) {
          //ssh_set_error_oom(adapter);
          return SSH_ERROR;
        }
    }
#endif
    if (adapter->dsa) {
        session->srv.dsa_key = ssh_key_dup(adapter->dsa);
        if (session->srv.dsa_key == NULL) {
          //ssh_set_error_oom(adapter);
          return SSH_ERROR;
        }
    }
    if (adapter->rsa) {
        session->srv.rsa_key = ssh_key_dup(adapter->rsa);
        if (session->srv.rsa_key == NULL) {
          //ssh_set_error_oom(adapter);
          return SSH_ERROR;
        }
    }
    /* force PRNG to change state in case we fork after ssh_bind_accept */
    ssh_reseed();
    return SSH_OK;
}

static int adapter_options_set_algo(ssh_adapter_t *sshbind, int algo,
    const char *list) {
  if (!verify_existing_algo(algo, list)) {
    trace_err("Setting method: no algorithm for method \"%s\" (%s)\n",
        ssh_kex_get_description(algo), list);
    return -1;
  }

  SAFE_FREE(sshbind->wanted_methods[algo]);
  sshbind->wanted_methods[algo] = strdup(list);
  if (sshbind->wanted_methods[algo] == NULL) {
    //ssh_set_error_oom(sshbind);
    return -1;
  }

  return 0;
}

/**
 * @brief This function can set all possible ssh bind options.
 *
 * @param  sshbind      An allocated ssh bind structure.
 *
 * @param  type         The option type to set. This could be one of the
 *                      following:
 *
 *                      SSH_BIND_OPTIONS_LOG_VERBOSITY:
 *                        Set the session logging verbosity (integer).
 *
 *                        The verbosity of the messages. Every log smaller or
 *                        equal to verbosity will be shown.
 *                          SSH_LOG_NOLOG: No logging
 *                          SSH_LOG_RARE: Rare conditions or warnings
 *                          SSH_LOG_ENTRY: API-accessible entrypoints
 *                          SSH_LOG_PACKET: Packet id and size
 *                          SSH_LOG_FUNCTIONS: Function entering and leaving
 *
 *                      SSH_BIND_OPTIONS_LOG_VERBOSITY_STR:
 *                        Set the session logging verbosity (integer).
 *
 *                        The verbosity of the messages. Every log smaller or
 *                        equal to verbosity will be shown.
 *                          SSH_LOG_NOLOG: No logging
 *                          SSH_LOG_RARE: Rare conditions or warnings
 *                          SSH_LOG_ENTRY: API-accessible entrypoints
 *                          SSH_LOG_PACKET: Packet id and size
 *                          SSH_LOG_FUNCTIONS: Function entering and leaving
 *
 *                      SSH_BIND_OPTIONS_BINDADDR:
 *                        Set the bind address.
 *
 *                      SSH_BIND_OPTIONS_BINDPORT:
 *                        Set the bind port, default is 22.
 *
 *                      SSH_BIND_OPTIONS_HOSTKEY:
 *                        Set the server public key type: ssh-rsa or ssh-dss
 *                        (string).
 *
 *                      SSH_BIND_OPTIONS_DSAKEY:
 *                        Set the path to the dsa ssh host key (string).
 *
 *                      SSH_BIND_OPTIONS_RSAKEY:
 *                        Set the path to the ssh host rsa key (string).
 *
 *                      SSH_BIND_OPTIONS_BANNER:
 *                        Set the server banner sent to clients (string).
 *
 * @param  value        The value to set. This is a generic pointer and the
 *                      datatype which is used should be set according to the
 *                      type set.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_adapter_options_set(ssh_adapter_t *sshbind, enum ssh_bind_options_e type,
    const void *value) {
  char *p, *q;
  int i;

  if (sshbind == NULL) {
    return -1;
  }

  switch (type) {
    case SSH_BIND_OPTIONS_HOSTKEY:
      if (value == NULL) {
        //ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        if (adapter_options_set_algo(sshbind, SSH_HOSTKEYS, value) < 0)
          return -1;
      }
      break;
    case SSH_BIND_OPTIONS_BINDADDR:
      if (value == NULL) {
        //ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        SAFE_FREE(sshbind->bindaddr);
        sshbind->bindaddr = strdup(value);
        if (sshbind->bindaddr == NULL) {
          //ssh_set_error_oom(sshbind);
          return -1;
        }
      }
      break;
    case SSH_BIND_OPTIONS_BINDPORT:
      if (value == NULL) {
        //ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        int *x = (int *) value;
        sshbind->bindport = *x & 0xffff;
      }
      break;
    case SSH_BIND_OPTIONS_BINDPORT_STR:
      if (value == NULL) {
        sshbind->bindport = 22 & 0xffff;
      } else {
        q = strdup(value);
        if (q == NULL) {
          //ssh_set_error_oom(sshbind);
          return -1;
        }
        i = strtol(q, &p, 10);
        if (q == p) {
          SAFE_FREE(q);
        }
        SAFE_FREE(q);

        sshbind->bindport = i & 0xffff;
      }
      break;
    case SSH_BIND_OPTIONS_DSAKEY:
      if (value == NULL) {
        //ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        SAFE_FREE(sshbind->dsakey);
        sshbind->dsakey = strdup(value);
        if (sshbind->dsakey == NULL) {
          //ssh_set_error_oom(sshbind);
          return -1;
        }
      }
      break;
    case SSH_BIND_OPTIONS_RSAKEY:
      if (value == NULL) {
        //ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        SAFE_FREE(sshbind->rsakey);
        sshbind->rsakey = strdup(value);
        if (sshbind->rsakey == NULL) {
          //ssh_set_error_oom(sshbind);
          return -1;
        }
      }
      break;
    case SSH_BIND_OPTIONS_BANNER:
      if (value == NULL) {
        //ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        SAFE_FREE(sshbind->banner);
        sshbind->banner = strdup(value);
        if (sshbind->banner == NULL) {
          //ssh_set_error_oom(sshbind);
          return -1;
        }
      }
      break;
	case SSH_BIND_OPTIONS_LOG_VERBOSITY_STR:
	  ssh_set_log_level(4 & 0xffff);
	  break;
    default:
      trace_err("Unknown ssh option %d", type);
      return -1;
    break;
  }

  return 0;
}

