#include "ssh-includes.h"

#include "ssh/callbacks.h"
#include "ssh/session.h"


/* LEGACY */
static void ssh_legacy_log_callback(int priority,
                                    const char *function,
                                    const char *buffer,
                                    void *userdata)
{
    ssh_session_t * session = (ssh_session_t *)userdata;
    ssh_log_callback log_fn = session->common.callbacks->log_function;
    void *log_data = session->common.callbacks->userdata;

    (void)function; /* unused */

    log_fn(session, priority, buffer, log_data);
}

int ssh_set_callbacks(ssh_session_t * session, ssh_callbacks cb) {
  if (session == NULL || cb == NULL) {
    return SSH_ERROR;
  }

  if(cb->size <= 0 || cb->size > 1024 * sizeof(void *)){
  	ssh_set_error(session,SSH_FATAL,
  			"Invalid callback passed in (badly initialized)");

  	return SSH_ERROR;
  }
  session->common.callbacks = cb;

  /* LEGACY */
  if (ssh_get_log_callback() == NULL && cb->log_function) {
      ssh_set_log_callback(ssh_legacy_log_callback);
      ssh_set_log_userdata(session);
  }

  return 0;
}

int ssh_set_channel_callbacks(ssh_channel_t * channel, ssh_channel_callbacks cb) {
  ssh_session_t * session = NULL;
  if (channel == NULL || cb == NULL) {
    return SSH_ERROR;
  }
  session = channel->session;

  if(cb->size <= 0 || cb->size > 1024 * sizeof(void *)){
  	ssh_set_error(session,SSH_FATAL,
  			"Invalid channel callback passed in (badly initialized)");

  	return SSH_ERROR;
  }
  channel->callbacks = cb;

  return 0;
}

int ssh_set_server_callbacks(ssh_session_t * session, ssh_server_callbacks cb){
	if (session == NULL || cb == NULL) {
		trace_err("session == NULL || cb == NULL");
		return SSH_ERROR;
	}

	if(cb->size <= 0 || cb->size > 1024 * sizeof(void *)){
		ssh_set_error(session,SSH_FATAL,
				"Invalid callback passed in (badly initialized)");
		trace_err("Invalid callback passed in (badly initialized)");
		return SSH_ERROR;
	}
	session->server_callbacks = cb;

	return 0;
}
