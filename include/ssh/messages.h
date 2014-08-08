#ifndef SSH_MESSAGES_H
#define SSH_MESSAGES_H

#include "ssh-includes.h"

struct ssh_auth_request {
    char *username;
    int method;
    char *password;
    ssh_key_t *pubkey;
    char signature_state;
    char kbdint_response;
};

struct ssh_channel_request_open {
    int type;
    uint32_t sender;
    uint32_t window;
    uint32_t packet_size;
    char *originator;
    uint16_t originator_port;
    char *destination;
    uint16_t destination_port;
};

struct ssh_service_request {
    char *service;
};

struct ssh_global_request {
    int type;
    uint8_t want_reply;
    char *bind_address;
    uint16_t bind_port;
};

struct ssh_channel_request {
    int type;
    ssh_channel_t * channel;
    uint8_t want_reply;
    /* pty-req type specifics */
    char *TERM;
    uint32_t width;
    uint32_t height;
    uint32_t pxwidth;
    uint32_t pxheight;
    ssh_string_t * modes;

    /* env type request */
    char *var_name;
    char *var_value;
    /* exec type request */
    char *command;
    /* subsystem */
    char *subsystem;

    /* X11 */
    uint8_t x11_single_connection;
    const char *x11_auth_protocol;
    const char *x11_auth_cookie;
    uint32_t x11_screen_number;
};

struct ssh_message_struct {
    ssh_session_t * session;
    int type;
    struct ssh_auth_request auth_request;
    struct ssh_channel_request_open channel_request_open;
    struct ssh_channel_request channel_request;
    struct ssh_service_request service_request;
    struct ssh_global_request global_request;
	// WANGFENG: proxy
	ssh_buffer_t *packet;
};

SSH_PACKET_CALLBACK(ssh_packet_channel_open);
SSH_PACKET_CALLBACK(ssh_packet_global_request);

#ifdef WITH_SERVER
SSH_PACKET_CALLBACK(ssh_packet_service_request);
SSH_PACKET_CALLBACK(ssh_packet_userauth_request);
#endif /* WITH_SERVER */

SSH_API int ssh_message_handle_channel_request(ssh_session_t * session, ssh_channel_t * channel, ssh_buffer_t * packet,
    const char *request, uint8_t want_reply);
SSH_API void ssh_message_queue(ssh_session_t * session, ssh_message_t * message);
SSH_API ssh_message_t * ssh_message_pop_head(ssh_session_t * session);
SSH_API int ssh_message_channel_request_open_reply_accept_channel(ssh_message_t * msg, ssh_channel_t * chan);

#endif /* SSH_MESSAGES_H */
