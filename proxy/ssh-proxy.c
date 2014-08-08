// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <aio/bufferevent_ssl.h>
#include <aio/bufferevent.h>
#include <aio/buffer.h>
#include <aio/listener.h>
#include <aio/util.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static struct event_base *base = NULL;
static struct sockaddr_storage listen_on_addr;
static struct sockaddr_storage connect_to_addr;
static int connect_to_addrlen;

#define MAX_OUTPUT (1024*1024)

#include "ssh_adapter.h"
#include "api_misc.h"
#include "ssh_packet.h"

#ifdef _WIN32
#define xKEYS_FOLDER "/runtime/etc/ssh/127.0.0.1/"
#else
#define xKEYS_FOLDER "/home/runtime/etc/ssh/127.0.0.1/"
#endif

static ssh_adapter_t *adapter = NULL;
static void drained_writecb(struct bufferevent *bev, void *ctx);

static void data_write_handler(struct bufferevent *bev, void *arg);
static void data_read_handler(struct bufferevent *bev, void *ctx);
static void event_error_handler(struct bufferevent *bev, short what, void *ctx);

static int 
session_data_send(ssh_session_t *session, uint8_t command, const void* data, int len)
{
	int iRet = -1;
#if 1
	ssh2_command_t *cb = session_get_callback(command);
	if(session->type == SSH_SESSION_SERVER) {
		session->direct = IP_PS;
	} else {
		session->direct = IP_PC;
	}
	if(cb != NULL) {
		//ssh_log(session, "\"%s(%d)\"", cb->command_name, cb->command);
		trace_out("\"%s(%d)\"", cb->command_name, cb->command);
	}
	
	if(session->evbuffer) {
		iRet = evbuffer_add(session->evbuffer, data, len);
	}
#endif
	return 0;
}

static void
session_filter_handler(const char *role, ssh_session_t *session, struct evbuffer *in, struct evbuffer *out)
{
	int nbytes = 0;
	char data[4096];
	const char *fromIp, *toIp;
	int fromPort, toPort;
	
	if(session->type == SSH_SESSION_CLIENT) {
		fromIp = session->cip;
		fromPort = session->cport;
		toIp = session->sip;
		toPort = session->sport;
	} else {
		fromIp = session->sip;
		fromPort = session->sport;
		toIp = session->cip;
		toPort = session->cport;
	}
	nbytes = evbuffer_get_length(in);
#if 1
	trace_out("session[%s:%d > %s:%d]: v%d.%d, command(%d), len(%d)\n", 
		fromIp, fromPort, toIp, toPort, 
		SSH_VERSION_S(session->version), session->command, nbytes);
#endif
	memset(data, 0x00, sizeof(data));
	while((nbytes = evbuffer_get_length(in)) > 0) {
		#if 1
		if (nbytes > sizeof(data)) {
			nbytes = sizeof(data);
		}
		#endif
		evbuffer_remove(in, data, nbytes);
		//evbuffer_add(out, data, nbytes);
		//if(session->type == SSH_SESSION_CLIENT)
		{
			int pos = 0, rc = 0;
			do{
				rc = session_packet_handler(session, data + pos, nbytes - pos);
				trace_out("nbytes = %d, pos = %d, rc = %d", nbytes, pos, rc);
				pos += rc;
			}while(rc > 0 && pos < nbytes);
			pos = 0, rc = 0;
		}
	}
}

static void
data_read_handler(struct bufferevent *bev, void *ctx)
{
	const char *func = __FUNCTION__;
	struct bufferevent *partner = NULL;
	struct evbuffer *in = NULL, *out = NULL;
	size_t len;
	
	ssh_session_t *session = ctx;
	if(session == NULL || session->owner_ptr == NULL) {
		do_error("[%s: 0]: c-ERROR: .....................", func);
	} else {
		if(session->type == SSH_SESSION_SERVER) {
			func = "CLIENT";
			session->direct = IP_SP;
		} else {
			func = "SERVER";
			session->direct = IP_CP;
		}
		partner= session->owner_ptr;
	}
	
	in = bufferevent_get_input(bev);
	len = evbuffer_get_length(in);
	if (!partner) {
		do_error("[%s: 1-1]: .....................", func);
		evbuffer_drain(in, len);
		return;
	}
	out = bufferevent_get_output(partner);
	if( len > 0 ) {
		session_filter_handler(func, session, in, out);
	}
	
	if (evbuffer_get_length(out) >= MAX_OUTPUT) {
		/* We're giving the other side data faster than it can
		 * pass it on.  Stop reading here until we have drained the
		 * other side to MAX_OUTPUT/2 bytes.
		 */
		do_error("[%s: 2-1]: .....................", func);
		bufferevent_setcb(partner, data_read_handler, drained_writecb,
		    event_error_handler, bev);
		bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
		    MAX_OUTPUT);
		bufferevent_disable(bev, EV_READ);
	}
}

static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
	ssh_session_t *session = ctx;
	struct bufferevent *partner = session->owner_ptr;
	printf("2----------------------------------------\r\n");

	/* We were choking the other side until we drained our outbuf a bit.
	 * Now it seems drained.
	 */
	bufferevent_setcb(bev, data_read_handler, NULL, event_error_handler, ctx);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner) {
		bufferevent_enable(partner, EV_READ);
	}
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);
	printf("3----------------------------------------\r\n");
	
	if (evbuffer_get_length(b) == 0) {
		bufferevent_free(bev);
	}
}

static void
event_error_handler(struct bufferevent *bev, short what, void *ctx)
{
	struct bufferevent *partner = NULL;
	ssh_session_t *session = ctx;
	
	if(session == NULL || session->owner_ptr == NULL) {
		trace_err("ERROR: .....................");
	} else {
		partner= session->owner_ptr;
	}
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (what & BEV_EVENT_ERROR) {
			unsigned long err;
			while ((err = (bufferevent_get_openssl_error(bev)))) {
				const char *msg = (const char*)ERR_reason_error_string(err);
				const char *lib = (const char*)ERR_lib_error_string(err);
				const char *func = (const char*)ERR_func_error_string(err);
				fprintf(stderr, "%s in %s %s\n", msg, lib, func);
			}
			if (errno) {
				trace_err("connection error");
			}
		}
		
		if (partner) {
			/* Flush all pending data */
			data_read_handler(bev, ctx);
			if (evbuffer_get_length(bufferevent_get_output(partner))) {
				/* We still have to flush data from the other
				 * side, but when that's done, close the other
				 * side.
				 */
				bufferevent_setcb(partner,
				    NULL, close_on_finished_writecb,
				    event_error_handler, NULL);
				bufferevent_disable(partner, EV_READ);
			} else {
				/* We have nothing left to say to the other
				 * side; close it. 
				 */
				bufferevent_free(partner);
				ssh_log(session, "\"%s:closed\"", SESSION_TYPE(session));
			}
		}
		bufferevent_free(bev);
	}
}

/**
 * Called by libevent when the write buffer reaches 0.  We only
 * provide this because libevent expects it, but we don't use it.
 */
static void 
data_write_handler(struct bufferevent *bev, void *arg)
{
	//
}

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int slen, void *p)
{
	ssh_session_t *session_in = NULL, *session_out = NULL;
	struct bufferevent *b_out, *b_in;
	// Create two linked bufferevent objects: one to connect, one for the new connection
	b_in = bufferevent_socket_new(base, fd,
	    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	
	b_out = bufferevent_socket_new(base, -1,
	    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	
	do_assert(b_in && b_out);
	
	if (bufferevent_socket_connect(b_out,
		(struct sockaddr*)&connect_to_addr, connect_to_addrlen)<0) {
		perror("bufferevent_socket_connect");
		bufferevent_free(b_out);
		bufferevent_free(b_in);
		return;
	}

	// client
	session_in = ssh_new();
	// server
	session_out = ssh_new();
	
	session_in->proxy = 1;
	session_in->type = SSH_SESSION_CLIENT;
	session_in->owner_ptr =  b_out;
	api_name_from_addr(sa, slen, &(session_in->cip),&(session_in->cport));
	api_name_from_addr((struct sockaddr *)&connect_to_addr, connect_to_addrlen, &(session_in->sip),&(session_in->sport));
	ssh_adapter_accept(adapter, session_in);
	session_in->session_ptr = session_out;
	session_in->evbuffer = bufferevent_get_output(b_in);
	session_in->data_send = session_data_send;
	//session_callback_init(session_in);
	ssh_handle_key_exchange(session_in);
	
	bufferevent_setcb(b_in, data_read_handler, data_write_handler, event_error_handler, session_in);
	
	session_out->proxy = 1;
	session_out->session_state = SSH_SESSION_STATE_SOCKET_CONNECTED;
	session_out->type = SSH_SESSION_SERVER;
	session_out->owner_ptr = b_in;
	api_name_from_addr(sa, slen, &(session_out->cip),&(session_out->cport));
	api_name_from_addr((struct sockaddr*)&connect_to_addr, connect_to_addrlen, 
		&(session_out->sip),&(session_out->sport));
	//ssh_adapter_accept(adapter, session_out);
	session_out->session_ptr = session_in;
	session_out->evbuffer = bufferevent_get_output(b_out);
	session_out->data_send = session_data_send;
	//session_callback_init(session_out);
	{
		int ret = ssh_connect(session_out);
		if(ret != SSH_OK) {
			trace_err("init proxy-client failed.");
		}
		/*
		ret = knownhost_verify(session_out);
		if(ret != SSH_OK) {
			trace_err("iknownhost_verify failed.");
		}*/
	}
	ssh_log(session_in, "accept a new session: [%s:%d] -> [%s:%d]",
			session_in->cip, session_in->cport,
			session_in->sip, session_in->sport);
	
	bufferevent_setcb(b_out, data_read_handler, data_write_handler, event_error_handler, session_out);

	bufferevent_enable(b_in, EV_READ|EV_WRITE);
	bufferevent_enable(b_out, EV_READ|EV_WRITE);
}

static void
syntax(void)
{
	fputs("Syntax:\n", stderr);
	fputs("   ssh-proxy <listen-on-addr> <connect-to-addr>\n", stderr);
	fputs("Example:\n", stderr);
	fputs("   ssh-proxy 0.0.0.0:10022 192.168.1.110:22\n", stderr);
	
	exit(1);
}

int
main(int argc, char **argv)
{
	int socklen;
	struct evconnlistener *listener;
	
	if (argc < 2) {
		syntax();
	}
	adapter = ssh_adapter_new();
	if(adapter == NULL) {
		trace_err("ssh_adapter create failed.");
		return 0x01;
	}
	
	//ssh_adapter_options_set(adapter, SSH_BIND_OPTIONS_HOSTKEY, xKEYS_FOLDER "ssh_host_key");
	ssh_adapter_options_set(adapter, SSH_BIND_OPTIONS_DSAKEY, xKEYS_FOLDER "ssh_host_dsa_key");
    ssh_adapter_options_set(adapter, SSH_BIND_OPTIONS_RSAKEY, xKEYS_FOLDER "ssh_host_rsa_key");
	ssh_adapter_options_set(adapter, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "4");
	ssh_adapter_init(adapter);

	memset(&listen_on_addr, 0, sizeof(listen_on_addr));
	socklen = sizeof(listen_on_addr);
	if (evutil_parse_sockaddr_port(argv[1],
		(struct sockaddr*)&listen_on_addr, &socklen)<0) {
		int p = atoi(argv[1]);
		struct sockaddr_in *sin = (struct sockaddr_in*)&listen_on_addr;
		if (p < 1 || p > 65535) {
			syntax();
		}
		sin->sin_port = htons(p);
		sin->sin_addr.s_addr = htonl(0x7f000001);
		sin->sin_family = AF_INET;
		socklen = sizeof(struct sockaddr_in);
	}
	
	memset(&connect_to_addr, 0, sizeof(connect_to_addr));
	connect_to_addrlen = sizeof(connect_to_addr);
	if (evutil_parse_sockaddr_port(argv[2],
		(struct sockaddr*)&connect_to_addr, &connect_to_addrlen)<0) {
		syntax();
	}
	base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		return 1;
	}
	
	listener = evconnlistener_new_bind(base, accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr*)&listen_on_addr, socklen);
	
	if (!listener) {
		fprintf(stderr, "Couldn't open listener.\n");
		event_base_free(base);
		return 1;
	}
	
	event_base_dispatch(base);
	
	evconnlistener_free(listener);
	event_base_free(base);
	
	return 0;
}

