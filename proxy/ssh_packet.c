#include "ssh_packet.h"

#include "ssh/kex.h"
#include "ssh/session.h"
#include "ssh/crypto.h"
#include "ssh/options.h"
#include "ssh/pki.h"

#include "ssh/messages.h"
#include "ssh/buffer.h"

#include "ssh/sftp.h"

#define VS(x) #x

#if 0
static const char *session_states[] = {
	VS(SSH_SESSION_STATE_NONE),
	VS(SSH_SESSION_STATE_CONNECTING),
	VS(SSH_SESSION_STATE_SOCKET_CONNECTED),
	VS(SSH_SESSION_STATE_BANNER_RECEIVED),
	VS(SSH_SESSION_STATE_INITIAL_KEX),
	VS(SSH_SESSION_STATE_KEXINIT_RECEIVED),
	VS(SSH_SESSION_STATE_DH),
	VS(SSH_SESSION_STATE_AUTHENTICATING),
	VS(SSH_SESSION_STATE_AUTHENTICATED),
	VS(SSH_SESSION_STATE_ERROR),
	VS(SSH_SESSION_STATE_DISCONNECTED),
	NULL

};
#endif

#define SSH2_MSG_EXCHANGE_VERSION 0

SPI_PACKET_CALLBACK(ssh2cb_ignore);
SPI_PACKET_CALLBACK(ssh2cb_exchange_version);
SPI_PACKET_CALLBACK(ssh2cb_disconnect);
SPI_PACKET_CALLBACK(ssh2cb_userauth_request);


SPI_PACKET_CALLBACK(ssh2cb_ignore)
{
	(void)session;

	return SSH_OK;
}

SPI_PACKET_CALLBACK(ssh2cb_exchange_version)
{
	(void)session;
	return SSH_OK;
}

SPI_PACKET_CALLBACK(ssh2cb_disconnect)
{
	(void)session;
	return SSH_OK;
}

SPI_PACKET_CALLBACK(ssh2cb_userauth_request)
{
	return SSH_OK;
}

static ssh2_command_t ssh2_commands[] = {
{SSH2_MSG_EXCHANGE_VERSION,         VS(SSH2_MSG_EXCHANGE_VERSION), ssh2cb_exchange_version},    // 0
/* transport layer: generic */
{SSH2_MSG_DISCONNECT,               VS(SSH2_MSG_DISCONNECT),                ssh2cb_disconnect}, // 1 
{SSH2_MSG_IGNORE,                   VS(SSH2_MSG_IGNORE),                    ssh2cb_ignore},     // 2 
{SSH2_MSG_UNIMPLEMENTED,            VS(SSH2_MSG_UNIMPLEMENTED),             ssh2cb_ignore},     // 3 
{SSH2_MSG_DEBUG,                    VS(SSH2_MSG_DEBUG),                     ssh2cb_ignore},     // 4 
{SSH2_MSG_SERVICE_REQUEST,          VS(SSH2_MSG_SERVICE_REQUEST),           ssh2cb_ignore},     // 5 
{SSH2_MSG_SERVICE_ACCEPT,           VS(SSH2_MSG_SERVICE_ACCEPT),            ssh2cb_ignore},     // 6 
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},       // 7-11
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},       // 12-16
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},                                           // 17-19
/* transport layer: alg negotiation */
{SSH2_MSG_KEXINIT,                  VS(SSH2_MSG_KEXINIT),                   ssh2cb_ignore},     // 20 
{SSH2_MSG_NEWKEYS,                  VS(SSH2_MSG_NEWKEYS),                   ssh2cb_ignore},     // 21 
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},       // 22-26
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},                                           // 27-29
/* transport layer: kex specific messages, can be reused */
{SSH2_MSG_KEXDH_INIT,               VS(SSH2_MSG_KEXDH_INIT),                ssh2cb_ignore},     // 30
                                                            // SSH2_MSG_KEX_DH_GEX_REQUEST_OLD     30
{SSH2_MSG_KEXDH_REPLY,              VS(SSH2_MSG_KEXDH_REPLY),               ssh2cb_ignore},     // 31
                                                            // SSH2_MSG_KEX_DH_GEX_GROUP           31
{0XFF,NULL,NULL},                                            // SSH2_MSG_KEX_DH_GEX_INIT           32
{0XFF,NULL,NULL},                                            // SSH2_MSG_KEX_DH_GEX_REPLY          33
{0XFF,NULL,NULL},                                            // SSH2_MSG_KEX_DH_GEX_REQUEST        34
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},       // 35-39
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},       // 40-44
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},       // 45-49
/* user authentication: generic */
{SSH2_MSG_USERAUTH_REQUEST,         VS(SSH2_MSG_USERAUTH_REQUEST),          ssh2cb_ignore},     // 50 
{SSH2_MSG_USERAUTH_FAILURE,         VS(SSH2_MSG_USERAUTH_FAILURE),          ssh2cb_ignore},     // 51 
{SSH2_MSG_USERAUTH_SUCCESS,         VS(SSH2_MSG_USERAUTH_SUCCESS),          ssh2cb_ignore},     // 52 
{SSH2_MSG_USERAUTH_BANNER,          VS(SSH2_MSG_USERAUTH_BANNER),           ssh2cb_ignore},     // 53 
{0XFF,NULL,NULL},{0XFF,NULL,NULL},{0XFF,NULL,NULL},{0XFF,NULL,NULL},{0XFF,NULL,NULL},           // 54-58
{0XFF,NULL,NULL},                                                                               // 59
{SSH2_MSG_USERAUTH_PK_OK,           VS(SSH2_MSG_USERAUTH_PK_OK),            ssh2cb_ignore},     // 60 
                                                         // SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ     60
                                                         // SSH2_MSG_USERAUTH_INFO_REQUEST         60
                                                         // SSH2_MSG_USERAUTH_GSSAPI_RESPONSE      60
{SSH2_MSG_USERAUTH_INFO_RESPONSE,   VS(SSH2_MSG_USERAUTH_INFO_RESPONSE),    ssh2cb_ignore},     // 61 
                                                         // SSH2_MSG_USERAUTH_GSSAPI_TOKEN         61
{0XFF,NULL,NULL},                                        //                                        62
{0XFF,NULL,NULL},                                // SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE     63
{0XFF,NULL,NULL},                                            // SSH2_MSG_USERAUTH_GSSAPI_ERROR     64
{0XFF,NULL,NULL},                                           // SSH2_MSG_USERAUTH_GSSAPI_ERRTOK     65
{SSH2_MSG_USERAUTH_GSSAPI_MIC,      VS(SSH2_MSG_USERAUTH_GSSAPI_MIC),       ssh2cb_ignore},     // 66 
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},       // 67-71
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},       // 72-76
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},                                           // 77-79
/* connection protocol: generic */
{SSH2_MSG_GLOBAL_REQUEST,           VS(SSH2_MSG_GLOBAL_REQUEST),            ssh2cb_ignore},     // 80 
{SSH2_MSG_REQUEST_SUCCESS,          VS(SSH2_MSG_REQUEST_SUCCESS),           ssh2cb_ignore},     // 81 
{SSH2_MSG_REQUEST_FAILURE,          VS(SSH2_MSG_REQUEST_FAILURE),           ssh2cb_ignore},     // 82 
{0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL}, {0XFF,NULL,NULL},       // 83-87
{0XFF,NULL,NULL}, {0XFF,NULL,NULL},                                                             // 88-89
{SSH2_MSG_CHANNEL_OPEN,             VS(SSH2_MSG_CHANNEL_OPEN),              ssh2cb_ignore},     // 90 
{SSH2_MSG_CHANNEL_OPEN_CONFIRMATION,VS(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION), ssh2cb_ignore},     // 91 
{SSH2_MSG_CHANNEL_OPEN_FAILURE,     VS(SSH2_MSG_CHANNEL_OPEN_FAILURE),      ssh2cb_ignore},     // 92 
{SSH2_MSG_CHANNEL_WINDOW_ADJUST,    VS(SSH2_MSG_CHANNEL_WINDOW_ADJUST),     ssh2cb_ignore},     // 93 
{SSH2_MSG_CHANNEL_DATA,             VS(SSH2_MSG_CHANNEL_DATA),              ssh2cb_ignore},     // 94 
{SSH2_MSG_CHANNEL_EXTENDED_DATA,    VS(SSH2_MSG_CHANNEL_EXTENDED_DATA),     ssh2cb_ignore},     // 95 
{SSH2_MSG_CHANNEL_EOF,              VS(SSH2_MSG_CHANNEL_EOF),               ssh2cb_ignore},     // 96 
{SSH2_MSG_CHANNEL_CLOSE,            VS(SSH2_MSG_CHANNEL_CLOSE),             ssh2cb_ignore},     // 97 
{SSH2_MSG_CHANNEL_REQUEST,          VS(SSH2_MSG_CHANNEL_REQUEST),           ssh2cb_ignore},     // 98 
{SSH2_MSG_CHANNEL_SUCCESS,          VS(SSH2_MSG_CHANNEL_SUCCESS),           ssh2cb_ignore},     // 99 
{SSH2_MSG_CHANNEL_FAILURE,          VS(SSH2_MSG_CHANNEL_FAILURE),           ssh2cb_ignore}      // 100
};

ssh2_command_t *
session_get_callback(uint8_t cmd)
{
	ssh2_command_t *cb = NULL;
	int len = (int)(sizeof(ssh2_commands) / sizeof(ssh2_commands[0]));
	if(cmd < len) {
		cb = ssh2_commands + cmd;
	}
	
	return cb;
}

////////////////////////////////////////////////////////////////////////////////

/**
 *
 * @see SSH File Transfer Protocol
 * @see http://tools.ietf.org/html/draft-ietf-secsh-filexfer-12
 */
static int 
sftp_data_process(ssh_session_t *session, ssh_buffer_t *packet)
{
	ssh_session_t *peer = session->session_ptr;
	uint32_t plen = 0;
	uint8_t  pcmd = 0;
	uint32_t prequestId = 0;
	int processed = 0;
	
	buffer_get_u8(packet, &pcmd);
	processed += 1;
	buffer_get_u32(packet, &prequestId);
	prequestId = ntohl(prequestId);
	processed += 4;

	trace_out("sftp[%d]: command=%d, reqId=%d", session->sftp.expect_data, pcmd, prequestId);
	
	switch(pcmd)
	{
	case SSH_FXP_INIT://	 1
		break;
	case SSH_FXP_VERSION://  2
		{
			session->sftp.version = prequestId;
			trace_out("sftp> version: %d", session->sftp.version);
		}
		break;
	case SSH_FXP_OPEN://	 3
		{
			ssh_string_t *str = buffer_get_ssh_string(packet);
			session->sftp.filename = ssh_string_to_char(str);
			trace_out("sftp> open file = %s", session->sftp.filename);
			ssh_string_free(str);
		}
		break;
	case SSH_FXP_CLOSE://	 4
		{
			ssh_session_t *s = session->sftp.file == -1 ? peer:session;
			if(s->sftp.file != -1) {
				close(s->sftp.file);
				s->sftp.file = -1;
				s->sftp.expect_data = 0;
				trace_out("sftp> close file");
			}
		}
		break;
	case SSH_FXP_READ://	 5
		// http://tools.ietf.org/html/draft-ietf-secsh-filexfer-12#section-8.2.1
		{
			ssh_session_t *s = peer;
			int rc = 0;
			ssh_string_t *str = NULL;
			uint64_t offset = 0;
			uint32_t length = 0;
			// download, data from session to peer
			if(s->sftp.file == -1) {
				ssh_log(s, "sftp> download %s, length %llu", session->sftp.filename, s->sftp.fsize);
				s->sftp.file = sftp_file_open(s->username, session->sftp.filename);
				//s->sftp.expect_data = 0;
				//s->sftp.fsize = 0;
				s->sftp.offset = 0;
			}
			// string handle
			str = buffer_get_ssh_string(packet);
			//processed += ssh_string_len(str) + 4;
			// uint64 offset
			rc = buffer_get_u64(packet, &offset);
			do_assert(rc == 8);
			offset = ntohll(offset);
			//processed += 8;
			// uint32 length
			rc = buffer_get_u32(packet, &length);
			do_assert(rc == 4);
			length = ntohl(length);
			trace_out("sftp> read offset=%llu, length = %d", offset, length);
			ssh_string_free(str);
		}
		break;
	case SSH_FXP_WRITE://	 6
		{
			// remaining ???
			ssh_session_t *s = session;
			uint64_t tlen = 9, val = 0;
			ssh_string_t *str = buffer_get_ssh_string(packet);
			
			// upload, data from session to peer
			if(s->sftp.file == -1) {
				ssh_log(s, "sftp> upload %s, length %llu", s->sftp.filename, s->sftp.fsize);
				s->sftp.file = sftp_file_open(s->username, s->sftp.filename);
				//peer->sftp.expect_data = 0;
				//peer->sftp.fsize = 0;
				s->sftp.offset = 0;
			}
			
			tlen += ssh_string_len(str) + 4;
			trace_out("tlen = %llu", tlen);
			buffer_get_u64(packet, &val);
			val = ntohll(val);
			trace_out("val = %llu", val);
			tlen +=  8;
			trace_out("tlen = %llu", tlen);
			
			if(s->sftp.fsize == 0) {
				s->sftp.fsize = plen - tlen;
				trace_out("sftp> file-length %llu bytes", s->sftp.fsize);
			}
			ssh_string_free(str);
			s->sftp.expect_data = 0;
			str = buffer_get_ssh_string(packet);
			if(str != NULL) {
				val = ssh_string_len(str);
				write(s->sftp.file, ssh_string_data(str), val);
				s->sftp.offset += val;
				trace_out("sftp> expect %llu, offset %llu, write %llu bytes", session->sftp.expect_data, s->sftp.offset, val);
			} else {
				trace_out("str is NULL");
				abort();
			}
		}
		break;
	case SSH_FXP_LSTAT://	 7
	case SSH_FXP_FSTAT://	 8
	case SSH_FXP_SETSTAT://  9
	case SSH_FXP_FSETSTAT:// 10
	case SSH_FXP_OPENDIR://  11
	case SSH_FXP_READDIR://  12
	case SSH_FXP_REMOVE://	 13
	case SSH_FXP_MKDIR://	 14
	case SSH_FXP_RMDIR://	 15
	case SSH_FXP_REALPATH:// 16
	case SSH_FXP_STAT://	 17
	case SSH_FXP_RENAME://	 18
	case SSH_FXP_READLINK:// 19
	case SSH_FXP_SYMLINK://  20
	case SSH_FXP_STATUS://	 101
		break;
	case SSH_FXP_HANDLE://	 102
		{
			ssh_string_t *handle = buffer_get_ssh_string(packet);
			if(handle == NULL) {
				trace_out("open file failed.");
			} else {
				ssh_string_free(handle);
			}
		}
		break;
	case SSH_FXP_DATA://	 103
		{
			uint64_t tlen = 9;
			ssh_session_t *s = session;
			if(s->sftp.file != -1) {
				ssh_string_t *str = NULL;
				
				str = buffer_get_ssh_string(packet);
				if(str != NULL) {
					size_t flen = ssh_string_len(str);
					void *fdata = ssh_string_data(str);
					tlen += flen + 4;
					trace_out("sftp> file block length=%d", flen);
					if(s->sftp.fsize - s->sftp.offset < flen) {
						flen = s->sftp.fsize - s->sftp.offset;
					}
					(void)write(s->sftp.file, fdata, flen);
					s->sftp.offset += flen;
					trace_out("sftp> expect %llu, offset %llu, write %llu bytes", s->sftp.expect_data, s->sftp.offset, flen);
				} else {
					trace_out("str - 2 is NULL");
					abort();
				}
				ssh_string_free(str);
			}else {
				//
			}
		}
		break;
	case SSH_FXP_NAME://	 104
		break;
	case SSH_FXP_ATTRS://	 105
		{
			uint32_t val = 0, flags = 0;
			uint64_t flen = 0;
			buffer_get_u32(packet, &val);
			flags = ntohl(val);
			if(flags & SSH_FILEXFER_ATTR_SIZE) {
				buffer_get_u64(packet, &flen);
				flen = ntohll(flen);
				trace_out("sftp> file length = %llu", flen);
				session->sftp.fsize = flen;
				session->sftp.offset = 0;
				if(session->sftp.file == -1 && peer->sftp.file != -1) {
					session->sftp.file = peer->sftp.file;
					peer->sftp.file = -1;
					peer->sftp.fsize = 0;
					peer->sftp.offset = 0;
				}
			}
		}
		break;
	case SSH_FXP_EXTENDED://	   200
	case SSH_FXP_EXTENDED_REPLY:// 201
		break;
	default:
		break;
	}

	return processed;
}

/**
 * @brief SSH channel data callback. Called when data is available on a channel
 * @param session Current session handler
 * @param channel the actual channel
 * @param data the data that has been read on the channel
 * @param len the length of the data
 * @param is_stderr is 0 for stdout or 1 for stderr
 * @param userdata Userdata to be passed to the callback function.
 * @returns number of bytes processed by the callee. The remaining bytes will
 * be sent in the next callback message, when more data is available. 
 */
static int 
proxy_channel_data_handler(ssh_session_t *session, ssh_channel_t *channel,
		void *data, uint32_t receivedlen, int is_stderr, void *userdata)
{
	int iRet = 1; // denied
	ssh_session_t *peer = (ssh_session_t *)session->session_ptr;
	int processed = 0;
	
	trace_out("channel->subsystem = [%s]................................BEGIN", channel->subsystem);
	trace_out("[%llu]from: %s, to: %s", receivedlen, SESSION_TYPE(session), SESSION_TYPE(peer));
	channel_write_common(peer->chan, data, receivedlen, is_stderr);

	if(channel->type == SSH_CHANNEL_REQUEST_EXEC)
	{
		// scp
		char *buf = (char *)data;
		ssh_session_t *from = NULL, *to;
		#if 1
		char temp[50];
		uint32_t tlen = receivedlen;
		
		if(tlen >= sizeof(temp)) {
			tlen = sizeof(temp) - 1;
		}
		memset(temp, 0x00, sizeof(temp));
		strncpy(temp, buf, tlen);
		trace_out("exec data=[%s]", temp);
		#endif
		if(session->sftp.expect_data) {
			from = session;
			to = peer;
		} else {
			from = peer;
			to = session;
		}
		trace_out("scp> state %d.", session->sftp.pstate);
		switch(session->sftp.pstate)
		{
		case 0:
			if(receivedlen == 1 && buf[0] == 0x00) {
				// server response
				peer->sftp.pstate = 1;
			}
			break;
		case 1:
			{
				// read file info
				char fattr[20];
				char fname[1024];
				int fsize = 0;
				int rc = 0;
				memset(fattr, 0x00, sizeof(fattr));
				memset(fname, 0x00, sizeof(fname));
				rc = sscanf(buf, "%s %d %[^\r\n][\r\n]", fattr, &fsize, fname);
				if(rc != 3) {
					ssh_log(session, "scp> parse %s failed.", buf);
				} else {
					ssh_log(session, "scp> %s file %s, length %d.", 
						session->sftp.expect_data ? "upload":"download",
						fname, fsize);
					session->sftp.file = sftp_file_open(session->username, fname);
					session->sftp.fsize = fsize;
					session->sftp.offset = 0;
				}
				peer->sftp.pstate = 2;
			}
			break;
		case 2:
			if(receivedlen == 1 && buf[0] == 0x00) {
				// server response
				peer->sftp.pstate = 3;
			}
			break;
		case 3:
			{
				if(session->sftp.file != -1 && session->sftp.offset < session->sftp.fsize) {
					uint32_t wlen = receivedlen;
					if(session->sftp.offset + wlen >= session->sftp.fsize) {
						wlen = session->sftp.fsize - session->sftp.offset;
					}
					session->sftp.offset += write(session->sftp.file, data, wlen);
				}
				if(session->sftp.offset >= session->sftp.fsize){
					close(session->sftp.file);
					session->sftp.file = -1;
				}
			}
			break;
		default:
			break;
		}
	} else if(channel->type == SSH_CHANNEL_REQUEST_SUBSYSTEM
			&& channel->subsystem != NULL && !strcmp(channel->subsystem, "sftp"))
	{
		// sftp process...
		int pLen = 0, rc = 0, remaining = 0;
		ssh_buffer_t *packet = NULL;
		do{
			//
			trace_out("recv %llu, process %llu, state = %d", receivedlen, processed, session->sftp.pstate);
			switch(session->sftp.pstate)
			{
			case PACKET_STATE_INIT:
				buffer_reinit(session->sftp.in_buffer);
				session->sftp.expect_data = 0;
				if(receivedlen - processed < 4) {
					buffer_add_data(session->sftp.in_buffer, (char *)data + processed, receivedlen - processed);
					processed += receivedlen - processed;
					session->sftp.pstate = PACKET_STATE_INIT_SIZEREAD;
					goto end;
				}
			case PACKET_STATE_INIT_SIZEREAD:
				memcpy((void *)&pLen, data + processed, 4);
				pLen = ntohl(pLen);
				processed += 4;
				session->sftp.expect_data = pLen;
				session->sftp.pstate = PACKET_STATE_SIZEREAD;
			case PACKET_STATE_SIZEREAD:
				remaining = buffer_get_rest_len(session->sftp.in_buffer);
				pLen = session->sftp.expect_data;
				if(receivedlen - processed  + remaining < pLen) {
					buffer_add_data(session->sftp.in_buffer, (char *)data + processed, receivedlen - processed);
					processed += receivedlen - processed;
					goto end;
				}
				packet = ssh_buffer_new();
				buffer_add_buffer(packet, session->sftp.in_buffer);
				buffer_add_data(packet, (char *)data + processed, pLen - remaining);
				processed += pLen - remaining;
				rc = sftp_data_process(session, packet);
				ssh_buffer_free(packet);
				session->sftp.pstate = PACKET_STATE_INIT;
				break;
			}
			//
		}while(receivedlen > processed);
		packet = NULL;
	} else if(session->type == SSH_SESSION_CLIENT && 
			(channel->type == SSH_CHANNEL_REQUEST_SHELL || 
			 channel->type == SSH_CHANNEL_REQUEST_PTY))
	{
		char *buf = (char *)data;
		int cmd_len = strlen(session->bash);
		uint8_t ch = '0';
		uint32_t i = 0;
		char temp[1024];
		
		memset(temp, 0x00, sizeof(temp));
		strncpy(temp, buf, sizeof(temp) - 1);
		trace_out("data=[%s]", temp);
		for(i = 0; i < receivedlen; i++) {
			ch = buf[i];
			trace_out("ch = %02x", ch);
			if(ch == '\r') {
				// enter
				ssh_log(session, "\"SHELL: %s\"", session->bash);
				memset(session->bash, 0x00, sizeof(session->bash));
			} else if(ch == 0x08) {
				// backspace
				session->bash[strlen(session->bash)] = 0x00;
			} else if(strlen(session->bash) + 1 < sizeof(session->bash)){
				session->bash[cmd_len + i] = ch;
			}
		}
	}
end:
	// must return len
	iRet = receivedlen;
	trace_out("channel->subsystem = [%s]................................END", channel->subsystem);
	return iRet;
}

/**
 * @brief SSH channel eof callback. Called when a channel receives EOF
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
static void
proxy_request_eof(ssh_session_t *session, ssh_channel_t *channel, void *userdata)
{
	ssh_session_t *peer = session->session_ptr;
	ssh_channel_send_eof(peer->chan);
}

/**
 * @brief SSH channel close callback. Called when a channel is closed by remote peer
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
static void 
proxy_request_close(ssh_session_t *session, ssh_channel_t *channel, void *userdata)
{
	//(void)session;
	//(void)channel;
	//(void)userdata;
	ssh_session_t *peer = session->session_ptr;
	
	ssh_log(session, "CLOSE");
	ssh_channel_close(peer->chan);
	ssh_channel_close(channel);
}

#ifdef _WIN32
static struct ssh_channel_callbacks_struct channel_cb;
#else
static struct ssh_channel_callbacks_struct channel_cb = {
	.channel_eof_function = proxy_request_eof,
	.channel_close_function = proxy_request_close,
	.channel_data_function = proxy_channel_data_handler,
	//.channel_exec_request_function = request_exec,
    //.channel_pty_request_function = request_pty,
    //.channel_shell_request_function = request_shell
};
#endif

static void
proxy_channel_set_callback(ssh_session_t *session, void *userdata)
{
    (void) session;
    (void) userdata;
#ifdef _WIN32
	channel_cb.channel_eof_function = proxy_request_eof;
	channel_cb.channel_close_function = proxy_request_close;
	channel_cb.channel_data_function = proxy_channel_data_handler;
	//channel_cb.channel_exec_request_function = request_exec;
	//channel_cb.channel_pty_request_function = request_pty;
	//channel_cb.channel_shell_request_function = request_shell;
#endif
    ssh_callbacks_init(&channel_cb);
    ssh_set_channel_callbacks(session->chan, &channel_cb);
}

/**
 * @brief Try to authenticate through the "none" method.
 *
 * @param[in] session   The ssh session to use.
 * @param[in] username    The username, this SHOULD be NULL.
 * @returns SSH_AUTH_ERROR:   A serious error happened.\n
 *          SSH_AUTH_DENIED:  Authentication failed: use another method\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method\n
 *          SSH_AUTH_SUCCESS: Authentication success\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 *
 * @note Most server implementations do not permit changing the username during
 * authentication. The username should only be set with ssh_options_set() only
 * before you connect to the server.
 */
static int 
proxy_userauth_request_none(ssh_session_t *session, const char *username)
{
	//(void)session;
	//(void)username;
	
    ssh_string_t *str = NULL;
    int rc;

    /* request */
    rc = buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_REQUEST);
    if (rc < 0) {
        goto fail;
    }

    /* username */
    if (username) {
        str = ssh_string_from_char(username);
    } else {
        str = ssh_string_from_char(session->opts.username);
    }
    if (str == NULL) {
        goto fail;
    }
	
    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }

    /* service */
    str = ssh_string_from_char("ssh-connection");
    if (str == NULL) {
        goto fail;
    }

    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }

    /* method */
    str = ssh_string_from_char("none");
    if (str == NULL) {
        goto fail;
    }

    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }

    session->auth_state = SSH_AUTH_STATE_NONE;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_NONE;
    rc = packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }
	//ssh_log(session, "\"SSH2_MSG_USERAUTH_REQUEST(50)\"");
    return rc;
fail:
    ssh_set_error_oom(session);
    buffer_reinit(session->out_buffer);

    return SSH_AUTH_ERROR;
}

/**
 * @brief Try to authenticate by password.
 *
 * This authentication method is normally disabled on SSHv2 server. You should
 * use keyboard-interactive mode.
 *
 * The 'password' value MUST be encoded UTF-8.  It is up to the server how to
 * interpret the password and validate it against the password database.
 * However, if you read the password in some other encoding, you MUST convert
 * the password to UTF-8.
 *
 * @param[in] session   The ssh session to use.
 * @param[in] username  The username, this SHOULD be NULL.
 * @param[in] password  The password to authenticate in UTF-8.
 *
 * @returns SSH_AUTH_ERROR:   A serious error happened.\n
 *          SSH_AUTH_DENIED:  Authentication failed: use another method\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method\n
 *          SSH_AUTH_SUCCESS: Authentication success\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 *
 * @note Most server implementations do not permit changing the username during
 * authentication. The username should only be set with ssh_options_set() only
 * before you connect to the server.
 *
 * @see ssh_userauth_none()
 * @see ssh_userauth_kbdint()
 */
static int 
proxy_userauth_request_password(ssh_session_t * session, 
		const char *username, const char *password)
{
	//(void)session;
	//(void)username;
	//(void)password;
    ssh_session_t *peer = session->session_ptr;
	ssh_string_t *str = NULL;
    int rc = SSH_ERROR;

	if(session->username != NULL) {
		SAFE_FREE(session->username);
	}
	if(peer->username != NULL) {
		SAFE_FREE(peer->username);
	}
	session->username = strdup(username);
	peer->username = strdup(username);
#ifdef WITH_SSH1
    if (session->version == 1) {
        rc = ssh_userauth1_password(session, username, password);
        return rc;
    }
#endif
	
    /* request */
    rc = buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_REQUEST);
    if (rc < 0) {
        goto fail;
    }
	
    /* username */
    if (username) {
        str = ssh_string_from_char(username);
    } else {
        str = ssh_string_from_char(session->opts.username);
    }
    if (str == NULL) {
        goto fail;
    }
	
    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }
	
    /* service */
    str = ssh_string_from_char("ssh-connection");
    if (str == NULL) {
        goto fail;
    }
	
    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }
	
    /* method */
    str = ssh_string_from_char("password");
    if (str == NULL) {
        goto fail;
    }
	
    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }
	
    /* FALSE */
    rc = buffer_add_u8(session->out_buffer, 0);
    if (rc < 0) {
        goto fail;
    }
	
    /* password */
    str = ssh_string_from_char(password);
    if (str == NULL) {
        goto fail;
    }
	
    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }
	
    session->auth_state = SSH_AUTH_STATE_NONE;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_OFFER_PUBKEY;
    rc = packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }
	rc = SSH_OK;
	ssh_log(session, "\"SSH2_MSG_USERAUTH_REQUEST(50)\", password=\"%s\"", password);
    return rc;
fail:
    ssh_set_error_oom(session);
    buffer_reinit(session->out_buffer);
	
    return SSH_AUTH_ERROR;
}

/**
 * @internal
 *
 * @brief Open a channel by sending a SSH_OPEN_CHANNEL message and
 *        wait for the reply.
 *
 * @param[in]  channel  The current channel.
 * @param[in]  type_c   A C string describing the kind of channel (e.g. "exec").
 * @param[in]  window   The receiving window of the channel. The window is the
 *                      maximum size of data that can stay in buffers and
 *                      network.
 * @param[in]  maxpacket The maximum packet size allowed (like MTU).
 * @param[in]  payload   The buffer containing additional payload for the query.
 */
static int 
proxy_channel_request_open(ssh_channel_t *channel, ssh_message_t *msg)
{
  ssh_session_t *session = channel->session;
  ssh_string_t *type = NULL;
  const char *type_c = "session";
  int err = SSH_ERROR;

  switch(channel->state){
  case SSH_CHANNEL_STATE_NOT_OPEN:
    break;
  case SSH_CHANNEL_STATE_OPENING:
    goto pending;
  case SSH_CHANNEL_STATE_OPEN:
  case SSH_CHANNEL_STATE_CLOSED:
  case SSH_CHANNEL_STATE_OPEN_DENIED:
    goto end;
  default:
    ssh_set_error(session,SSH_FATAL,"Bad state in channel_open: %d",channel->state);
  }
  channel->local_channel = ssh_channel_new_id(session);
  channel->local_maxpacket = msg->channel_request_open.packet_size;
  channel->local_window = msg->channel_request_open.window;

  SSH_INFO(SSH_LOG_PROTOCOL,
      "Creating a channel %d with %d window and %d max packet",
      channel->local_channel, channel->local_window, channel->local_maxpacket);

  type = ssh_string_from_char(type_c);
  if (type == NULL) {
    ssh_set_error_oom(session);

    return err;
  }

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_CHANNEL_OPEN) < 0 ||
      buffer_add_ssh_string(session->out_buffer, type) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(channel->local_channel)) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(channel->local_window)) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(channel->local_maxpacket)) < 0) {
    ssh_set_error_oom(session);
    ssh_string_free(type);

    return err;
  }

  ssh_string_free(type);
  
  channel->state = SSH_CHANNEL_STATE_OPENING;
  if (packet_send(session) == SSH_ERROR) {
    return err;
  }

  SSH_INFO(SSH_LOG_PACKET,
      "Sent a SSH_MSG_CHANNEL_OPEN type %s for channel %d",
      type_c, channel->local_channel);
  //ssh_log(session, "\"SSH2_MSG_CHANNEL_OPEN(90)\"");
pending:
  //
end:
  if(channel->state == SSH_CHANNEL_STATE_OPEN) {
    err = SSH_OK;
  }

  return err;
}

/*
// server->proxy, proxy forward, session MUST is SSH_SESSION_SERVER
static int proxy_response(ssh_session_t *session)
{
	int rc = SSH_ERROR;

	rc = SSH_OK;
	
	return rc;
}
*/

// client->proxy, proxy forward, session MUST is SSH_SESSION_CLIENT
static int
proxy_request(ssh_session_t *session, ssh_message_t *msg)
{
    ssh_channel_t *channel = NULL;
	ssh_session_t *srv = session->session_ptr;
    int rc;

	trace_out("-----------------------------------------------  begin");
	trace_out("message.type = %d.%d", msg->type, ssh_message_subtype(msg));
	
	switch(msg->type) {
    case SSH_REQUEST_AUTH:
		if (msg->auth_request.method == SSH_AUTH_METHOD_NONE) {
            rc = proxy_userauth_request_none(srv,  msg->auth_request.username);
        } else if (msg->auth_request.method == SSH_AUTH_METHOD_PASSWORD) {
        	rc = proxy_userauth_request_password(srv, msg->auth_request.username, msg->auth_request.password);
        } else if(msg->auth_request.method == SSH_AUTH_METHOD_PUBLICKEY) {
        	// WANGFENG: proxy
        	ssh_auth_callback auth_fn = NULL;
    		void *auth_data = NULL;
			ssh_key_t *privkey = NULL;
			if (session->common.callbacks) {
        		auth_fn = session->common.callbacks->auth_function;
        		auth_data = session->common.callbacks->userdata;
    		}
			rc = ssh_pki_import_privkey_file("/home/runtime/.ssh/runtime",
                        "WangFeng#@))",
                        auth_fn,
                        auth_data,
                        &privkey);
            if (rc == SSH_ERROR) {
				trace_out("read private key failed.");
            }
            trace_out("username = %s, password = %s", msg->auth_request.username, msg->auth_request.password);
        	//rc = ssh_userauth_try_publickey(srv, msg->auth_request.username, msg->auth_request.pubkey);
        	//rc = ssh_userauth_publickey_auto(srv, msg->auth_request.username, msg->auth_request.password);
			rc = ssh_userauth_publickey(srv, msg->auth_request.username, privkey);
			//buffer_reinit(srv->out_buffer);
			//buffer_add_buffer(srv->out_buffer, msg->packet);
			//buffer_reinit(msg->packet);
			//rc = packet_send(srv);
        } else if(ssh_message_subtype(msg) == SSH_AUTH_METHOD_INTERACTIVE) {
        	trace_out("srv->auth_state = [%d]", srv->auth_state);
			//rc = ssh_userauth_kbdint_setanswer(srv, srv->sftp.offset++, msg->auth_request.password);
			trace_out("kdb - 1");
			if(msg->auth_request.kbdint_response != 1) {
				srv->pending_call_state = SSH_PENDING_CALL_NONE;
			} else {
				// send response
				int i = 0;
				srv->pending_call_state = SSH_PENDING_CALL_NONE;
				trace_out("kbdint->nanswers: %d, %d", session->kbdint->nanswers, srv->kbdint->nanswers);
				for(i = 0; i < session->kbdint->nanswers; i++) {
					trace_out("answers: %d, [%s]", i, session->kbdint->answers[i]);
					ssh_userauth_kbdint_setanswer(srv, i, session->kbdint->answers[i]);
				}
			}
			rc = ssh_userauth_kbdint(srv, msg->auth_request.username,  NULL);
			trace_out("kdb - 2");
        } else {
        	rc = SSH_AGAIN;
        }
        break;
    case SSH_REQUEST_CHANNEL_OPEN:
        if (msg->channel_request_open.type == SSH_CHANNEL_SESSION) {
			// client -> proxy, proxy request server
			srv->chan = ssh_channel_new(srv);
    		rc = proxy_channel_request_open(srv->chan, msg);
        }
        break;
    case SSH_REQUEST_CHANNEL:
        channel = msg->channel_request.channel;
		channel = srv->chan;
		trace_out("SSH_REQUEST_CHANNEL: %d", msg->channel_request.type);
		channel->type = msg->channel_request.type;
        if (msg->channel_request.type == SSH_CHANNEL_REQUEST_PTY) {
			rc = ssh_channel_request_pty_size(channel, msg->channel_request.TERM,
                    msg->channel_request.width, msg->channel_request.height);
        } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_SHELL) {
             rc = ssh_channel_request_shell(channel);
        } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_X11) {
        	rc = ssh_channel_request_x11(channel,
              msg->channel_request.x11_single_connection, msg->channel_request.x11_auth_protocol,
              msg->channel_request.x11_auth_cookie, msg->channel_request.x11_screen_number);
        } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_WINDOW_CHANGE) {
            rc = ssh_channel_change_pty_size(channel,
				msg->channel_request.width, msg->channel_request.height);
        } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_EXEC) {
        	trace_out("exec ------------ begin, command[%s]", msg->channel_request.command);
			if(channel->subsystem == NULL) {
				const char *cmd = msg->channel_request.command;
				if(cmd != NULL && strstr(cmd, "scp")) {
					channel->type = SSH_CHANNEL_REQUEST_EXEC;
					session->chan->type = SSH_CHANNEL_REQUEST_EXEC;
					SAFE_FREE(channel->subsystem);
        			channel->subsystem = strdup("scp");
					SAFE_FREE(session->chan->subsystem);
					session->chan->subsystem = strdup("scp");
					trace_out("exec ------------ protocol[%s]", channel->subsystem);
					if(strstr(cmd, "scp -f")) {
						srv->sftp.expect_data = 0;
						session->sftp.expect_data = 0;
					} else {
						srv->sftp.expect_data = 1;
						session->sftp.expect_data = 1;
					}
					srv->sftp.pstate = 0;
					session->sftp.pstate = 0;
				}
			}
			rc = ssh_channel_request_exec(channel, msg->channel_request.command);
			trace_out("exec ------------ end");
        } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_ENV) {
            rc = ssh_channel_request_env(channel, 
				msg->channel_request.var_name, msg->channel_request.var_value);
        } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_SUBSYSTEM) {
        	trace_out("subsystem ------------ begin");
			channel->subsystem = strdup(msg->channel_request.subsystem);
            rc = ssh_channel_request_subsystem(channel, msg->channel_request.subsystem);
			trace_out("subsystem ------------ end");
        } else {
        	rc = ssh_message_channel_request_reply_success(msg);
        	//rc = SSH_AGAIN;
        }
        break;
    case SSH_REQUEST_SERVICE:
		rc = ssh_service_request(srv, msg->service_request.service);
		break;
    case SSH_REQUEST_GLOBAL:
		rc = SSH_AGAIN;
        break;
    }
	trace_out("rc = %d", rc);
	if(rc == SSH_AGAIN) {
		//msg->channel_request.want_reply = 1;
		ssh_message_reply_default(msg);
		ssh_message_free(msg);
		msg = NULL;
	} else {
		srv->msg = msg;
	}
	trace_out("-----------------------------------------------  end");
    return rc;
}


void session_request_handler(ssh_session_t *session)
{
	int bClient = 0;
	ssh_session_t *cli = NULL, *srv = NULL;
	if(session->type == SSH_SESSION_SERVER && session->client) {
		cli = session->session_ptr;
		srv = session;
		bClient = 0;
	} else {
		cli = session;
		srv = session->session_ptr;
		bClient = 1;
	}
	trace_out("CLIENT:%d, SERVER:%d", cli->session_state, srv->session_state);
	if(cli->session_state >= SSH_SESSION_STATE_AUTHENTICATING && 
		srv->session_state >= SSH_SESSION_STATE_AUTHENTICATING) {
		ssh_message_t *message = NULL;
		trace_out("%s(%d) process......", SESSION_TYPE(session), bClient);
		if(bClient) {
			// client
			
		} else {
			// server
			uint8_t cmd = srv->command;
			switch(cmd) {
			case SSH2_MSG_SERVICE_ACCEPT:
				ssh_message_service_reply_success(srv->msg);
				ssh_message_free(srv->msg);
				srv->msg = NULL;
				srv->command |= 0x80;
				break;
			case SSH2_MSG_USERAUTH_FAILURE:
				// WANGFENG: proxy, fix publickey
				ssh_message_auth_set_methods(srv->msg, session->auth_methods);
                ssh_message_reply_default(srv->msg);
				ssh_message_free(srv->msg);
				srv->msg = NULL;
				srv->command |= 0x80;
				break;
			case SSH2_MSG_USERAUTH_SUCCESS:
				ssh_message_auth_reply_success(srv->msg, 0);
				ssh_message_free(srv->msg);
				srv->msg = NULL;
				srv->command |= 0x80;
				break;
			case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
				//ssh_message_channel_request_open_reply_accept(srv->msg);
				cli->chan = ssh_channel_new(cli);
				ssh_message_channel_request_open_reply_accept_channel(srv->msg, cli->chan);
				ssh_message_free(srv->msg);
				srv->msg = NULL;
				session->command |= 0x80;
				do_assert(srv->chan != NULL);
				proxy_channel_set_callback(srv, NULL);
				proxy_channel_set_callback(cli, NULL);
				break;
			case SSH2_MSG_CHANNEL_SUCCESS:
				srv->chan->type = ssh_message_subtype(srv->msg);
				cli->chan->type = ssh_message_subtype(srv->msg);
				if(srv->msg->channel_request.subsystem != NULL) {
					// sftp from msg->channel_request.subsystem
					SAFE_FREE(cli->chan->subsystem);
					cli->chan->subsystem = strdup(srv->msg->channel_request.subsystem);
				}
				ssh_message_channel_request_reply_success(srv->msg);
				ssh_message_free(srv->msg);
				srv->msg = NULL;
				session->command |= 0x80;
				break;
			case SSH2_MSG_USERAUTH_PK_OK:
				trace_out("srv->auth_state = [%d]", srv->auth_state);
				if(srv->auth_state == SSH_AUTH_STATE_INFO) {
					ssh_message_auth_interactive_request(srv->msg,
						srv->kbdint->name, srv->kbdint->instruction, srv->kbdint->nprompts,
						(const char **)srv->kbdint->prompts, srv->kbdint->echo);
				} else {
					// publickey/GSSAPI
					ssh_message_auth_reply_success(srv->msg, 0);
				}
				ssh_message_free(srv->msg);
				srv->msg = NULL;
				srv->command |= 0x80;
				break;
			default:
				if(cmd & 0x80) {
					trace_out("message(%d) processed.", cmd & 0x7f);
				}
				break;
			}
		}
		while((message = ssh_message_pop_head(cli)) != NULL) {
			proxy_request(cli, message);
		}
		//....
	}
}

