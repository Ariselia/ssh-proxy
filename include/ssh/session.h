#ifndef SSH_SESSION_H
#define SSH_SESSION_H

#include "ssh/priv.h"
#include "ssh/kex.h"
#include "ssh/packet.h"
#include "ssh/auth.h"
#include "ssh/channels.h"
#include "ssh/poll.h"
#include "ssh/crypto.h"
#include "ssh/misc.h"

#define SSH_SESSION_UNKNOWN (0)
#define SSH_SESSION_CLIENT  (1)
#define SSH_SESSION_SERVER  (2)

/* These are the different states a SSH session can be into its life */
enum ssh_session_state_e {
	SSH_SESSION_STATE_NONE=0,
	SSH_SESSION_STATE_CONNECTING,
	SSH_SESSION_STATE_SOCKET_CONNECTED,
	SSH_SESSION_STATE_BANNER_RECEIVED,
	SSH_SESSION_STATE_INITIAL_KEX,
	SSH_SESSION_STATE_KEXINIT_RECEIVED,
	SSH_SESSION_STATE_DH,
	SSH_SESSION_STATE_AUTHENTICATING,
	SSH_SESSION_STATE_AUTHENTICATED,
	SSH_SESSION_STATE_ERROR,
	SSH_SESSION_STATE_DISCONNECTED
};

enum ssh_dh_state_e {
  DH_STATE_INIT=0,
  DH_STATE_INIT_SENT,
  DH_STATE_NEWKEYS_SENT,
  DH_STATE_FINISHED
};

enum ssh_pending_call_e {
	SSH_PENDING_CALL_NONE = 0,
	SSH_PENDING_CALL_CONNECT,
	SSH_PENDING_CALL_AUTH_NONE,
	SSH_PENDING_CALL_AUTH_PASSWORD,
	SSH_PENDING_CALL_AUTH_OFFER_PUBKEY,
	SSH_PENDING_CALL_AUTH_PUBKEY,
	SSH_PENDING_CALL_AUTH_AGENT,
	SSH_PENDING_CALL_AUTH_KBDINT_INIT,
	SSH_PENDING_CALL_AUTH_KBDINT_SEND,
	SSH_PENDING_CALL_AUTH_GSSAPI_MIC
};

/* libssh calls may block an undefined amount of time */
#define SSH_SESSION_FLAG_BLOCKING 1

/* Client successfully authenticated */
#define SSH_SESSION_FLAG_AUTHENTICATED 2

/* codes to use with ssh_handle_packets*() */
/* Infinite timeout */
#define SSH_TIMEOUT_INFINITE -1
/* Use the timeout defined by user if any. Mostly used with new connections */
#define SSH_TIMEOUT_USER -2
/* Use the default timeout, depending on ssh_is_blocking() */
#define SSH_TIMEOUT_DEFAULT -3
/* Don't block at all */
#define SSH_TIMEOUT_NONBLOCKING 0

/* members that are common to ssh_session_t * and ssh_bind_t * */
struct ssh_common_struct {
    struct error_struct error;
    ssh_callbacks callbacks; /* Callbacks to user functions */
    int log_verbosity; /* verbosity of the log functions */
};

struct ssh_session_struct {
    struct ssh_common_struct common;
    struct ssh_socket_struct *socket;
    char *serverbanner;
    char *clientbanner;
    int protoversion;
    int server; // is server ?
    int client; // is client ?
    int openssh;
    uint32_t send_seq;
    uint32_t recv_seq;

    int connected; // is connected ?
    /* !=0 when the user got a session handle */
    int alive;
    /* two previous are deprecated */
    /* int auth_service_asked; */

    /* session flags (SSH_SESSION_FLAG_*) */
    int flags;

    ssh_string_t * banner; /* that's the issue banner from
                       the server */
    char *discon_msg; /* disconnect message from
                         the remote host */
    ssh_buffer_t * in_buffer;
    PACKET in_packet;
    ssh_buffer_t * out_buffer;

    /* the states are used by the nonblocking stuff to remember */
    /* where it was before being interrupted */
    enum ssh_pending_call_e  pending_call_state;
    enum ssh_session_state_e session_state;
    int packet_state;
    enum ssh_dh_state_e dh_handshake_state;
    enum ssh_auth_service_state_e auth_service_state;
    enum ssh_auth_state_e auth_state;
    enum ssh_channel_request_state_e global_req_state;
    struct ssh_agent_state_struct *agent_state;
    struct ssh_auth_auto_state_struct *auth_auto_state;

    ssh_buffer_t * in_hashbuf;
    ssh_buffer_t * out_hashbuf;
    ssh_crypto_t *current_crypto;
    ssh_crypto_t *next_crypto;  /* next_crypto is going to be used after a SSH2_MSG_NEWKEYS */

    ssh_list_t *channels; /* linked list of channels */
    int maxchannel;
    int exec_channel_opened; /* version 1 only. more
                                info in channels1.c */
    ssh_agent_t * agent; /* ssh agent */

	/* keyb interactive data */
    struct ssh_kbdint_struct *kbdint;
    struct ssh_gssapi_struct *gssapi;
    int version; /* 1 or 2 */
    /* server host keys */
    struct {
        ssh_key_t * rsa_key;
        ssh_key_t * dsa_key;
        ssh_key_t * ecdsa_key;

        /* The type of host key wanted by client */
        enum ssh_keytypes_e hostkey;
    } srv;
    /* auths accepted by server */
    int auth_methods;
    ssh_list_t *ssh_message_list; /* list of delayed SSH messages */
    int (*ssh_message_callback)( ssh_session_t *session, ssh_message_t * msg, void *userdata);
    void *ssh_message_callback_data;
    ssh_server_callbacks server_callbacks;
    void (*ssh_connection_callback)( ssh_session_t *session);
    struct ssh_packet_callbacks_struct default_packet_callbacks;
    ssh_list_t *packet_callbacks;
    struct ssh_socket_callbacks_struct socket_callbacks;
    ssh_poll_ctx default_poll_ctx;
    /* options */
    struct {
        ssh_list_t *identity;
        char *username;
        char *host;
        char *bindaddr; /* bind the client to an ip addr */
        char *sshdir;
        char *knownhosts;
        char *wanted_methods[10];
        char *ProxyCommand;
        char *custombanner;
        unsigned long timeout; /* seconds */
        unsigned long timeout_usec;
        unsigned int port;
        socket_t fd;
        int StrictHostKeyChecking;
        int ssh2;
        int ssh1;
        char compressionlevel;
        char *gss_server_identity;
        char *gss_client_identity;
        int gss_delegate_creds;
    } opts;
	// WANGFENG: PROXY_FLAG
	int      proxy; // default 0-proxy, >0 - network
	void    *owner_ptr; // for struct buffervent
	void    *session_ptr; // no free
	uint8_t  state; //
	uint8_t  type; // client or server
	uint8_t  command;
	char	*cip;
	int 	 cport;
	char    *sip;
	int 	 sport;
	// WANGFENG: OpenSSH version check
	int      compat13;
	int      compat20;
	int      datafellows;
	// WANGFENG: data send
	void    *evbuffer;
	char    *username;
	char     bash[1024];
	ssh_channel_t *chan;
	ssh_message_t *msg;
	const char *direct; // ip routr
	int      (*data_send)(ssh_session_t *session, uint8_t command,const void* data, int len);
};

/** @internal
 * @brief a termination function evaluates the status of an object
 * @param user[in] object to evaluate
 * @returns 1 if the polling routine should terminate, 0 instead
 */
typedef int (*ssh_termination_function)(void *user);
int ssh_handle_packets(ssh_session_t * session, int timeout);
int ssh_handle_packets_termination(ssh_session_t * session, int timeout,
    ssh_termination_function fct, void *user);
void ssh_socket_exception_callback(int code, int errno_code, void *user);
void ssh_session_set_proxy(ssh_session_t *session, int flag);

#endif /* ! SSH_SESSION_H */
