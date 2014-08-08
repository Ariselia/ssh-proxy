#include "ssh_adapter.h"
#include "ssh_packet.h"
#include "ssh/buffer.h"
#include "ssh-includes.h"

#include <string.h>
#include <stdlib.h>

#include "ssh/priv.h"
#include "ssh/ssh-api.h"
#include "ssh/crypto.h"
#include "ssh/server.h"
#include "ssh/ssh2.h"
#include "ssh/packet.h"
#include "ssh/session.h"
#include "ssh/misc.h"
#include "ssh/buffer.h"

#define MACSIZE SHA_DIGEST_LEN

#include "ssh_compat.h"

/**
 * @internal
 *
 * @brief Gets the banner from socket and saves it in session.
 * Updates the session state
 *
 * @param  data pointer to the beginning of header
 * @param  len size of the banner
 * @param  user is a pointer to session
 * @returns Number of bytes processed, or zero if the banner is not complete.
 */
static int banner_parse(ssh_session_t *session, const void *data, size_t len) {
    char *buffer = (char *) data;
    char *str = NULL;
    size_t i;
    int ret=0;
	int mismatch, protocol = SSH_PROTO_2;
	int remote_major, remote_minor;
	char remote_version[256];	/* Must be at least as big as buf. */
	
    for (i = 0; i < len; i++) {
        if (buffer[i] == '\r') {
            buffer[i]='\0';
        }
        if (buffer[i] == '\n') {
            buffer[i]='\0';

            str = strdup(buffer);
            /* number of bytes read */
            ret = i + 1;
			if(session->type == SSH_SESSION_CLIENT) {
				session->clientbanner = str;
				//session->serverbanner = strdup("SSH-2.0-OpenSSH_5.3");
			} else {
				session->serverbanner = str;
			}
            session->session_state = SSH_SESSION_STATE_BANNER_RECEIVED;
            trace_out("Received banner: %s", str);
			if(sscanf(buffer, "SSH-%d.%d-%[^\n]\n",
	    			&remote_major, &remote_minor, remote_version) != 3){
	    			trace_out("Bad protocol version identification '%.100s'", buffer);
			} else {
				trace_out("protocol version %d.%d; software version %.100s\n",
	    			remote_major, remote_minor, remote_version);
	    		ssh_log(session, "version=%d, banner=%.100s",
	    				session->version, remote_version);
			}
			compat_datafellows(session, remote_version);
			if ((session->datafellows & SSH_BUG_PROBE) != 0) {
				trace_err("probed from %s with %s.  Don't panic.",
				session->sip, buffer);
				//cleanup_exit(255);
			}
			if ((session->datafellows & SSH_BUG_SCANNER) != 0) {
				trace_err("scanned from %s with %s.  Don't panic.",
				session->sip, buffer);
				//cleanup_exit(255);
			}
			if ((session->datafellows & SSH_BUG_RSASIGMD5) != 0) {
				trace_err("Client version \"%.100s\" uses unsafe RSA signature "
					"scheme; disabling use of RSA keys", remote_version);
			}
			if ((session->datafellows & SSH_BUG_DERIVEKEY) != 0) {
				trace_err("Client version \"%.100s\" uses unsafe key agreement; "
					"refusing connection", remote_version);
			}

			mismatch = 0;
			switch (remote_major) {
			case 1:
				if (remote_minor == 99) {
					if (protocol & SSH_PROTO_2) {
						enable_compat20(session);
					} else {
						mismatch = 1;
					}
					break;
				}
				if (!(protocol & SSH_PROTO_1)) {
					mismatch = 1;
					break;
				}
				if (remote_minor < 3) {
					trace_out("Your ssh version is too old and "
						"is no longer supported.  Please install a newer version.");
				} else if (remote_minor == 3) {
					/* note that this disables agent-forwarding */
					enable_compat13(session);
				}
				break;
			case 2:
				if (protocol & SSH_PROTO_2) {
					enable_compat20(session);
					break;
				}
				/* FALLTHROUGH */
			default:
				mismatch = 1;
				break;
			}
			
			//chop(server_version_string);
			trace_out("Local version string %.200s", buffer);
			if (mismatch) {
				trace_out("Protocol major versions differ for %s: %.200s vs. %.200s",
				session->sip,
				buffer, buffer);
			}
			trace_out("compat: 13(%d), 20(%d)", session->compat13, session->compat20);
			if(session->ssh_connection_callback) {
            	session->ssh_connection_callback(session);
			}
			if(session->type == SSH_SESSION_CLIENT)
            {
				ssh_packet_set_default_callbacks(session);
            }
			session->command = 1;
            return ret;
        }

        if(i > 127) {
            /* Too big banner */
            session->session_state = SSH_SESSION_STATE_ERROR;
            do_error("Receiving banner: too large banner");

            return 0;
        }
    }

    return ret;
}

/*
=0,
	,
	,
	SSH_SESSION_STATE_BANNER_RECEIVED,
	SSH_SESSION_STATE_INITIAL_KEX,
	SSH_SESSION_STATE_KEXINIT_RECEIVED,
	SSH_SESSION_STATE_DH,
	SSH_SESSION_STATE_AUTHENTICATING,
	SSH_SESSION_STATE_AUTHENTICATED,
	SSH_SESSION_STATE_ERROR,
	SSH_SESSION_STATE_DISCONNECTED

static int key_exchange(ssh_session_t *session, const char *data, size_t receivedlen)
{
	int iRet = 0;
	switch(session->session_state)
	{
	case SSH_SESSION_STATE_NONE:
	case SSH_SESSION_STATE_CONNECTING:
	case SSH_SESSION_STATE_SOCKET_CONNECTED:
		iRet = banner_parse(session, data, receivedlen);
		break;
	case SSH_SESSION_STATE_BANNER_RECEIVED:
		break;
	}

	return iRet;
}
*/

static int packet_parse(ssh_session_t *session,const char *data, size_t receivedlen)
{
    unsigned int blocksize = (session->current_crypto ?
                              session->current_crypto->in_cipher->blocksize : 8);
    int current_macsize = session->current_crypto ? MACSIZE : 0;
    unsigned char mac[30] = {0};
    char buffer[16] = {0};
    const uint8_t *packet = NULL;
    int to_be_read = 0;
    int rc = 0;
    uint32_t len = 0, compsize = 0, payloadsize = 0;
	uint32_t  remaining = 0, toomuch = 0;
    uint8_t padding = 0;
    size_t processed = 0; /* number of byte processed from the callback */
	const char *command_name = NULL;

	if (data == NULL) {
        goto error;
    }
	if (session->session_state == SSH_SESSION_STATE_ERROR) {
        goto error;
    }

    switch(session->packet_state) {
        case PACKET_STATE_INIT:
            memset(&session->in_packet, 0, sizeof(PACKET));
            if (session->in_buffer) {
                rc = buffer_reinit(session->in_buffer);
                if (rc < 0) {
                    goto error;
                }
            } else {
                session->in_buffer = ssh_buffer_new();
                if (session->in_buffer == NULL) {
                    goto error;
                }
            }
			session->packet_state = PACKET_STATE_INIT_SIZEREAD;
		case PACKET_STATE_INIT_SIZEREAD:
			remaining = buffer_get_len(session->in_buffer);
			if (receivedlen + remaining < blocksize) {
                /*
                 * We didn't receive enough data to read at least one
                 * block size, give up
                 */
                //return 0;
                buffer_add_data(session->in_buffer, data, receivedlen);
				return receivedlen;
            }
			
			if(remaining < blocksize) {
				memcpy(buffer, buffer_get_rest(session->in_buffer), remaining);
				memcpy(buffer + remaining, data, blocksize - remaining);
				processed += blocksize - remaining;
			} else {
				//memcpy(buffer, buffer_get_rest(session->in_buffer), blocksize);
				//processed += 0;
				do_assert(remaining < blocksize);
			}
			len = packet_decrypt_len(session, buffer);

            if(remaining > 0)
			{
				char *tt = ssh_buffer_get_begin(session->in_buffer);
				memcpy(tt, buffer, remaining);	
            }
			rc = buffer_add_data(session->in_buffer, buffer + remaining, blocksize - remaining);
			if (rc < 0) {
                goto error;
            }
			do_assert(len <= MAX_PACKET_LEN);
            if (len > MAX_PACKET_LEN) {
                trace_err("read_packet(): Packet len too high(%u %.4x)",
                              len, len);
                goto error;
            }
			
            to_be_read = len - blocksize + sizeof(uint32_t);
            if (to_be_read < 0) {
                /* remote sshd sends invalid sizes? */
                trace_err("Given numbers of bytes left to be read < 0 (%d)!",
                              to_be_read);
                goto error;
            }

            /* Saves the status of the current operations */
            session->in_packet.len = len;
            session->packet_state = PACKET_STATE_SIZEREAD;
            /* FALL TROUGH */
        case PACKET_STATE_SIZEREAD:
			remaining = buffer_get_len(session->in_buffer) - blocksize;
			len = session->in_packet.len;
            to_be_read = len - blocksize + sizeof(uint32_t) + current_macsize;
            /* if to_be_read is zero, the whole packet was blocksize bytes. */
            if (to_be_read != 0) {
                if (receivedlen + remaining - processed < (unsigned int)to_be_read) {
                    /* give up, not enough data in buffer */
                    SSH_INFO(SSH_LOG_PACKET, "packet: partial packet (read len) [len=%d]", len);
					// WANGFENG: proxy
					if(receivedlen > processed) {
						packet = ((uint8_t*)data) + processed;
						buffer_add_data(session->in_buffer, packet, receivedlen - processed);
						processed += (receivedlen - processed);
					}
                    return processed;
                }
				
                packet = ((uint8_t *)data) + processed;
				// WANGFENG: proxy
				toomuch = 0;
				if(to_be_read - current_macsize > remaining) {
	                rc = buffer_add_data(session->in_buffer,
	                                     packet,
	                                     to_be_read - current_macsize - remaining);
					do_assert(rc >= 0);
	                if (rc < 0) {
	                    goto error;
	                }
	                processed += to_be_read - current_macsize - remaining;
				} else {
					//mac partial data in session->in_buffer, 
					toomuch = remaining - (to_be_read - current_macsize);
				}
            }

            if (session->current_crypto) {
                /*
                 * Decrypt the rest of the packet (blocksize bytes already
                 * have been decrypted)
                 */
                uint32_t buffer_len = buffer_get_rest_len(session->in_buffer);
				/* The following check avoids decrypting zero bytes */
                if (buffer_len > blocksize) {
                    uint8_t *payload = ((uint8_t*)buffer_get_rest(session->in_buffer) + blocksize);
                    uint32_t plen = buffer_len - blocksize;
					
					if(toomuch > 0) {
						plen -= toomuch;
					}
					rc = packet_decrypt(session, payload, plen);
					if (rc < 0) {
                        trace_err("Decrypt error");
                        goto error;
                    }
                }
				
                /* copy the last part from the incoming buffer */
                packet = ((uint8_t *)data) + processed;
				if(toomuch > 0) {
					uint8_t *pdata = (uint8_t *)buffer_get_rest(session->in_buffer);
					memcpy(mac, pdata + buffer_get_rest_len(session->in_buffer) - toomuch, toomuch);
				}
                memcpy(mac + toomuch, packet, MACSIZE - toomuch);
				buffer_pass_bytes_end(session->in_buffer, toomuch);
				rc = packet_hmac_verify(session, session->in_buffer, mac);
				do_assert(rc >= 0);
                if (rc < 0) {
                    trace_err("HMAC error");
                    goto error;
                }
				
                processed += current_macsize - toomuch;
            }
			/* skip the size field which has been processed before */
            buffer_pass_bytes(session->in_buffer, sizeof(uint32_t));
			
            rc = buffer_get_u8(session->in_buffer, &padding);
            if (rc == 0) {
                trace_err("Packet too short to read padding");
                goto error;
            }
			
            if (padding > buffer_get_rest_len(session->in_buffer)) {
                trace_err("Invalid padding: %d (%d left)",
                              padding,
                              buffer_get_rest_len(session->in_buffer));
                goto error;
            }
            buffer_pass_bytes_end(session->in_buffer, padding);
            compsize = buffer_get_rest_len(session->in_buffer);
			
		#ifdef WITH_ZLIB
            if (session->current_crypto
                && session->current_crypto->do_compress_in
                && buffer_get_rest_len(session->in_buffer) > 0) {
                rc = decompress_buffer(session, session->in_buffer, MAX_PACKET_LEN);
                if (rc < 0) {
                    goto error;
                }
            }
		#endif /* WITH_ZLIB */
            payloadsize = buffer_get_rest_len(session->in_buffer);
            session->recv_seq++;
			
            /*
             * We don't want to rewrite a new packet while still executing the
             * packet callbacks
             */
            session->packet_state = PACKET_STATE_PROCESSING;
            ssh_packet_parse_type(session);
            SSH_INFO(SSH_LOG_PACKET,
                    "packet: read type %hhd [len=%d,padding=%hhd,comp=%d,payload=%d]",
                    session->in_packet.type, len, padding, compsize, payloadsize);
			{
				// WWANGFENG: 
				ssh2_command_t *cmd = session_get_callback(session->in_packet.type);
				if(cmd != NULL) {
					command_name = cmd->command_name;
				} else {
					command_name = "UNKNOWN";
				}
            }
            // WANGFENG: proxy, Execute callbacks
            ssh_packet_process(session, session->in_packet.type, command_name);
            session->packet_state = PACKET_STATE_INIT;
            if (processed < receivedlen) {
                /* Handle a potential packet left in socket buffer */
                SSH_INFO(SSH_LOG_PACKET,
                        "Processing %" PRIdS " bytes left in socket buffer",
                        receivedlen - processed);
				
                packet = ((uint8_t*)data) + processed;
				rc = packet_parse(session, (const char *)packet, receivedlen - processed);
                processed += rc;
            }

            return processed;
        case PACKET_STATE_PROCESSING:
            SSH_INFO(SSH_LOG_RARE, "Nested packet processing. Delaying.");
            return 0;
    }
	
    trace_err("Invalid state into packet_read2(): %d",
                  session->packet_state);

error:
    session->session_state= SSH_SESSION_STATE_ERROR;

    return processed;
}


/** @internal
 * @handles a data received event. It then calls the handlers for the different packet types
 * or and exception handler callback.
 * @param user pointer to current ssh_session_t *
 * @param data pointer to the data received
 * @len length of data received. It might not be enough for a complete packet
 * @returns number of bytes read and processed.
 */
int session_packet_handler(ssh_session_t *session, const char *data, size_t receivedlen)
{
	int iRet = 0;
	if(session->command < 1) {
		iRet = banner_parse(session, data, receivedlen);
	} else {
		iRet = packet_parse(session, data, receivedlen);
		session_request_handler(session);
	}
	return iRet;
}

