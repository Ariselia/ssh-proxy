/**
 * @defgroup libssh_server The libssh server API
 *
 * @{
 */

#ifndef SSH_SERVER_H
#define SSH_SERVER_H

#include "ssh/ssh-api.h"
#define SERVERBANNER CLIENTBANNER

#ifdef __cplusplus
extern "C" {
#endif

enum ssh_bind_options_e {
  SSH_BIND_OPTIONS_BINDADDR,
  SSH_BIND_OPTIONS_BINDPORT,
  SSH_BIND_OPTIONS_BINDPORT_STR,
  SSH_BIND_OPTIONS_HOSTKEY,
  SSH_BIND_OPTIONS_DSAKEY,
  SSH_BIND_OPTIONS_RSAKEY,
  SSH_BIND_OPTIONS_BANNER,
  SSH_BIND_OPTIONS_LOG_VERBOSITY,
  SSH_BIND_OPTIONS_LOG_VERBOSITY_STR
};

typedef struct ssh_bind_struct ssh_bind_t;

/* Callback functions */

/**
 * @brief Incoming connection callback. This callback is called when a ssh_bind_t *
 *        has a new incoming connection.
 * @param sshbind Current sshbind session handler
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_bind_incoming_connection_callback) (ssh_bind_t * sshbind,
    void *userdata);

/**
 * @brief These are the callbacks exported by the ssh_bind_t * structure.
 *
 * They are called by the server module when events appear on the network.
 */
struct ssh_bind_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /** A new connection is available. */
  ssh_bind_incoming_connection_callback incoming_connection;
};
typedef struct ssh_bind_callbacks_struct *ssh_bind_callbacks;

/**
 * @brief Creates a new SSH server bind.
 *
 * @return A newly allocated ssh_bind_t * session pointer.
 */
SSH_API ssh_bind_t * ssh_bind_new(void);
SSH_API ssh_bind_t * ssh_bind_new2(int port);


/**
 * @brief Set the options for the current SSH server bind.
 *
 * @param  sshbind     The ssh server bind to configure.
 *
 * @param  type The option type to set. This could be one of the
 *              following:
 *
 *              - SSH_BIND_OPTIONS_BINDADDR
 *                The ip address to bind (const char *).
 *
 *              - SSH_BIND_OPTIONS_BINDPORT
 *                The port to bind (unsigned int).
 *
 *              - SSH_BIND_OPTIONS_BINDPORT_STR
 *                The port to bind (const char *).
 *
 *              - SSH_BIND_OPTIONS_HOSTKEY
 *                This specifies the file containing the private host key used
 *                by SSHv1. (const char *).
 *
 *              - SSH_BIND_OPTIONS_DSAKEY
 *                This specifies the file containing the private host dsa key
 *                used by SSHv2. (const char *).
 *
 *              - SSH_BIND_OPTIONS_RSAKEY
 *                This specifies the file containing the private host dsa key
 *                used by SSHv2. (const char *).
 *
 *              - SSH_BIND_OPTIONS_BANNER
 *                That the server banner (version string) for SSH.
 *                (const char *).
 *
 *              - SSH_BIND_OPTIONS_LOG_VERBOSITY
 *                Set the session logging verbosity (int).\n
 *                \n
 *                The verbosity of the messages. Every log smaller or
 *                equal to verbosity will be shown.
 *                - SSH_LOG_NOLOG: No logging
 *                - SSH_LOG_RARE: Rare conditions or warnings
 *                - SSH_LOG_ENTRY: API-accessible entrypoints
 *                - SSH_LOG_PACKET: Packet id and size
 *                - SSH_LOG_FUNCTIONS: Function entering and leaving
 *
 *              - SSH_BIND_OPTIONS_LOG_VERBOSITY_STR
 *                Set the session logging verbosity (const char *).\n
 *                \n
 *                The verbosity of the messages. Every log smaller or
 *                equal to verbosity will be shown.
 *                - SSH_LOG_NOLOG: No logging
 *                - SSH_LOG_RARE: Rare conditions or warnings
 *                - SSH_LOG_ENTRY: API-accessible entrypoints
 *                - SSH_LOG_PACKET: Packet id and size
 *                - SSH_LOG_FUNCTIONS: Function entering and leaving
 *                \n
 *                See the corresponding numbers in ssh-api.h.
 *
 * @param  value The value to set. This is a generic pointer and the
 *               datatype which is used should be set according to the
 *               type set.
 *
 * @returns     SSH_OK on success, SSH_ERROR on invalid option or parameter.
 */
SSH_API int ssh_bind_options_set(ssh_bind_t * sshbind,
    enum ssh_bind_options_e type, const void *value);

/**
 * @brief Start listening to the socket.
 *
 * @param  ssh_bind_o     The ssh server bind to use.
 *
 * @return 0 on success, < 0 on error.
 */
SSH_API int ssh_bind_listen(ssh_bind_t * ssh_bind_o);

/**
 * @brief Set the callback for this bind.
 *
 * @param[in] sshbind   The bind to set the callback on.
 *
 * @param[in] callbacks An already set up ssh_bind_callbacks instance.
 *
 * @param[in] userdata  A pointer to private data to pass to the callbacks.
 *
 * @return              SSH_OK on success, SSH_ERROR if an error occured.
 *
 * @code
 *     struct ssh_callbacks_struct cb = {
 *         .userdata = data,
 *         .auth_function = my_auth_function
 *     };
 *     ssh_callbacks_init(&cb);
 *     ssh_bind_set_callbacks(session, &cb);
 * @endcode
 */
SSH_API int ssh_bind_set_callbacks(ssh_bind_t * sshbind, ssh_bind_callbacks callbacks,
    void *userdata);

/**
 * @brief  Set the session to blocking/nonblocking mode.
 *
 * @param  ssh_bind_o     The ssh server bind to use.
 *
 * @param  blocking     Zero for nonblocking mode.
 */
SSH_API void ssh_bind_set_blocking(ssh_bind_t * ssh_bind_o, int blocking);

/**
 * @brief Recover the file descriptor from the session.
 *
 * @param  ssh_bind_o     The ssh server bind to get the fd from.
 *
 * @return The file descriptor.
 */
SSH_API socket_t ssh_bind_get_fd(ssh_bind_t * ssh_bind_o);

/**
 * @brief Set the file descriptor for a session.
 *
 * @param  ssh_bind_o     The ssh server bind to set the fd.
 *
 * @param  fd           The file descriptssh_bind B
 */
SSH_API void ssh_bind_set_fd(ssh_bind_t * ssh_bind_o, socket_t fd);

/**
 * @brief Allow the file descriptor to accept new sessions.
 *
 * @param  ssh_bind_o     The ssh server bind to use.
 */
SSH_API void ssh_bind_fd_toaccept(ssh_bind_t * ssh_bind_o);

/**
 * @brief Accept an incoming ssh connection and initialize the session.
 *
 * @param  ssh_bind_o     The ssh server bind to accept a connection.
 * @param  session			A preallocated ssh session
 * @see ssh_new
 * @return SSH_OK when a connection is established
 */
SSH_API int ssh_bind_accept(ssh_bind_t * ssh_bind_o, ssh_session_t * session);

/**
 * @brief Accept an incoming ssh connection on the given file descriptor
 *        and initialize the session.
 *
 * @param  ssh_bind_o     The ssh server bind to accept a connection.
 * @param  session        A preallocated ssh session
 * @param  fd             A file descriptor of an already established TCP
 *                          inbound connection
 * @see ssh_new
 * @see ssh_bind_accept
 * @return SSH_OK when a connection is established
 */
SSH_API int ssh_bind_accept_fd(ssh_bind_t * ssh_bind_o, ssh_session_t * session,
        socket_t fd);

SSH_API ssh_gssapi_creds ssh_gssapi_get_creds(ssh_session_t * session);

/**
 * @brief Handles the key exchange and set up encryption
 *
 * @param  session			A connected ssh session
 * @see ssh_bind_accept
 * @return SSH_OK if the key exchange was successful
 */
SSH_API int ssh_handle_key_exchange(ssh_session_t * session);

/**
 * @brief Free a ssh servers bind.
 *
 * @param  ssh_bind_o     The ssh server bind to free.
 */
SSH_API void ssh_bind_free(ssh_bind_t * ssh_bind_o);

SSH_API void ssh_set_auth_methods(ssh_session_t * session, int auth_methods);

/**********************************************************
 * SERVER MESSAGING
 **********************************************************/

/**
 * @brief Reply with a standard reject message.
 *
 * Use this function if you don't know what to respond or if you want to reject
 * a request.
 *
 * @param[in] msg       The message to use for the reply.
 *
 * @return              0 on success, -1 on error.
 *
 * @see ssh_message_get()
 */
SSH_API int ssh_message_reply_default(ssh_message_t * msg);

/**
 * @brief Get the name of the authenticated user.
 *
 * @param[in] msg       The message to get the username from.
 *
 * @return              The username or NULL if an error occured.
 *
 * @see ssh_message_get()
 * @see ssh_message_type()
 */
SSH_API const char *ssh_message_auth_user(ssh_message_t * msg);

/**
 * @brief Get the password of the authenticated user.
 *
 * @param[in] msg       The message to get the password from.
 *
 * @return              The username or NULL if an error occured.
 *
 * @see ssh_message_get()
 * @see ssh_message_type()
 */
SSH_API const char *ssh_message_auth_password(ssh_message_t * msg);

/**
 * @brief Get the publickey of the authenticated user.
 *
 * If you need the key for later user you should duplicate it.
 *
 * @param[in] msg       The message to get the public key from.
 *
 * @return              The public key or NULL.
 *
 * @see ssh_key_dup()
 * @see ssh_key_cmp()
 * @see ssh_message_get()
 * @see ssh_message_type()
 */
SSH_API ssh_key_t * ssh_message_auth_pubkey(ssh_message_t * msg);

SSH_API int ssh_message_auth_kbdint_is_response(ssh_message_t * msg);
SSH_API enum ssh_publickey_state_e ssh_message_auth_publickey_state(ssh_message_t * msg);
SSH_API int ssh_message_auth_reply_success(ssh_message_t * msg,int partial);
SSH_API int ssh_message_auth_reply_pk_ok(ssh_message_t * msg, ssh_string_t * algo, ssh_string_t * pubkey);
SSH_API int ssh_message_auth_reply_pk_ok_simple(ssh_message_t * msg);

SSH_API int ssh_message_auth_set_methods(ssh_message_t * msg, int methods);

SSH_API int ssh_message_auth_interactive_request(ssh_message_t * msg,
                    const char *name, const char *instruction,
                    unsigned int num_prompts, const char **prompts, char *echo);

SSH_API int ssh_message_service_reply_success(ssh_message_t * msg);
SSH_API const char *ssh_message_service_service(ssh_message_t * msg);

SSH_API int ssh_message_global_request_reply_success(ssh_message_t * msg,
                                                        uint16_t bound_port);

SSH_API void ssh_set_message_callback(ssh_session_t * session,
    int(*ssh_bind_message_callback)(ssh_session_t * session, ssh_message_t * msg, void *data),
    void *data);
SSH_API int ssh_execute_message_callbacks(ssh_session_t * session);

SSH_API const char *ssh_message_channel_request_open_originator(ssh_message_t * msg);
SSH_API int ssh_message_channel_request_open_originator_port(ssh_message_t * msg);
SSH_API const char *ssh_message_channel_request_open_destination(ssh_message_t * msg);
SSH_API int ssh_message_channel_request_open_destination_port(ssh_message_t * msg);

SSH_API ssh_channel_t * ssh_message_channel_request_channel(ssh_message_t * msg);

SSH_API const char *ssh_message_channel_request_pty_term(ssh_message_t * msg);
SSH_API int ssh_message_channel_request_pty_width(ssh_message_t * msg);
SSH_API int ssh_message_channel_request_pty_height(ssh_message_t * msg);
SSH_API int ssh_message_channel_request_pty_pxwidth(ssh_message_t * msg);
SSH_API int ssh_message_channel_request_pty_pxheight(ssh_message_t * msg);

SSH_API const char *ssh_message_channel_request_env_name(ssh_message_t * msg);
SSH_API const char *ssh_message_channel_request_env_value(ssh_message_t * msg);

SSH_API const char *ssh_message_channel_request_command(ssh_message_t * msg);

SSH_API const char *ssh_message_channel_request_subsystem(ssh_message_t * msg);

SSH_API int ssh_message_channel_request_x11_single_connection(ssh_message_t * msg);
SSH_API const char *ssh_message_channel_request_x11_auth_protocol(ssh_message_t * msg);
SSH_API const char *ssh_message_channel_request_x11_auth_cookie(ssh_message_t * msg);
SSH_API int ssh_message_channel_request_x11_screen_number(ssh_message_t * msg);

SSH_API const char *ssh_message_global_request_address(ssh_message_t * msg);
SSH_API int ssh_message_global_request_port(ssh_message_t * msg);

SSH_API int ssh_channel_open_reverse_forward(ssh_channel_t * channel, const char *remotehost,
    int remoteport, const char *sourcehost, int localport);
SSH_API int ssh_channel_open_x11(ssh_channel_t * channel, 
                                        const char *orig_addr, int orig_port);

SSH_API int ssh_channel_request_send_exit_status(ssh_channel_t * channel,
                                                int exit_status);
SSH_API int ssh_channel_request_send_exit_signal(ssh_channel_t * channel,
                                                const char *signum,
                                                int core,
                                                const char *errmsg,
                                                const char *lang);
SSH_API int ssh_channel_write_stderr(ssh_channel_t * channel,
                                                const void *data,
                                                uint32_t len);

SSH_API int ssh_send_keepalive(ssh_session_t * session);

/* deprecated functions */
SSH_DEPRECATED SSH_API int ssh_accept(ssh_session_t * session);
SSH_DEPRECATED SSH_API int channel_write_stderr(ssh_channel_t * channel,
        const void *data, uint32_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ! SSH_SERVER_H */

/** @} */
