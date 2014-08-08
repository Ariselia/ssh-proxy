#ifndef SSH_CHANNELS_H
#define SSH_CHANNELS_H

#include "ssh/priv.h"

/**  @internal
 * Describes the different possible states in a
 * outgoing (client) channel request
 */
enum ssh_channel_request_state_e {
	/** No request has been made */
	SSH_CHANNEL_REQ_STATE_NONE = 0,
	/** A request has been made and answer is pending */
	SSH_CHANNEL_REQ_STATE_PENDING,
	/** A request has been replied and accepted */
	SSH_CHANNEL_REQ_STATE_ACCEPTED,
	/** A request has been replied and refused */
	SSH_CHANNEL_REQ_STATE_DENIED,
	/** A request has been replied and an error happend */
	SSH_CHANNEL_REQ_STATE_ERROR
};

enum ssh_channel_state_e {
  SSH_CHANNEL_STATE_NOT_OPEN = 0,
  SSH_CHANNEL_STATE_OPENING,
  SSH_CHANNEL_STATE_OPEN_DENIED,
  SSH_CHANNEL_STATE_OPEN,
  SSH_CHANNEL_STATE_CLOSED
};

/* The channel has been closed by the remote side */
#define SSH_CHANNEL_FLAG_CLOSED_REMOTE 0x1
/* The channel has been freed by the calling program */
#define SSH_CHANNEL_FLAG_FREED_LOCAL 0x2
/* the channel has not yet been bound to a remote one */
#define SSH_CHANNEL_FLAG_NOT_BOUND 0x4

struct ssh_channel_struct {
    ssh_session_t * session; /* SSH_SESSION pointer */
    uint32_t local_channel;
    uint32_t local_window;
    int local_eof;
    uint32_t local_maxpacket;

    uint32_t remote_channel;
    uint32_t remote_window;
    int remote_eof; /* end of file received */
    uint32_t remote_maxpacket;
    enum ssh_channel_state_e state;
    int delayed_close;
    int flags;
    ssh_buffer_t * stdout_buffer;
    ssh_buffer_t * stderr_buffer;
    void *userarg;
    int version;
    int exit_status;
    enum ssh_channel_request_state_e request_state;
    ssh_channel_callbacks callbacks;
	// WANGFENG: proxy
	char *subsystem;
	int type;
};

SSH_PACKET_CALLBACK(ssh_packet_channel_open_conf);
SSH_PACKET_CALLBACK(ssh_packet_channel_open_fail);
SSH_PACKET_CALLBACK(ssh_packet_channel_success);
SSH_PACKET_CALLBACK(ssh_packet_channel_failure);
SSH_PACKET_CALLBACK(ssh_request_success);
SSH_PACKET_CALLBACK(ssh_request_denied);

SSH_PACKET_CALLBACK(channel_rcv_change_window);
SSH_PACKET_CALLBACK(channel_rcv_eof);
SSH_PACKET_CALLBACK(channel_rcv_close);
SSH_PACKET_CALLBACK(channel_rcv_request);
SSH_PACKET_CALLBACK(channel_rcv_data);

//ssh_channel_t * ssh_channel_new(ssh_session_t * session);
int channel_default_bufferize(ssh_channel_t * channel, void *data, int len,
        int is_stderr);
int ssh_channel_flush(ssh_channel_t * channel);
SSH_API uint32_t ssh_channel_new_id(ssh_session_t * session);
ssh_channel_t * ssh_channel_from_local(ssh_session_t * session, uint32_t id);
SSH_API int channel_write_common(ssh_channel_t * channel, const void *data,
    uint32_t len, int is_stderr);
void ssh_channel_do_free(ssh_channel_t * channel);
#ifdef WITH_SSH1
SSH_PACKET_CALLBACK(ssh_packet_data1);
SSH_PACKET_CALLBACK(ssh_packet_close1);
SSH_PACKET_CALLBACK(ssh_packet_exist_status1);

/* channels1.c */
int channel_open_session1(ssh_channel_t * channel);
int channel_request_pty_size1(ssh_channel_t * channel, const char *terminal,
    int cols, int rows);
int channel_change_pty_size1(ssh_channel_t * channel, int cols, int rows);
int channel_request_shell1(ssh_channel_t * channel);
int channel_request_exec1(ssh_channel_t * channel, const char *cmd);
int channel_write1(ssh_channel_t * channel, const void *data, int len);
ssh_channel_t * ssh_get_channel1(ssh_session_t * session);
#endif

#endif /* ! SSH_CHANNELS_H */
