/* Since ssh-api.h includes legacy.h, it's important that ssh-api.h is included
 * first. we don't define LEGACY_H now because we want it to be defined when
 * included from ssh-api.h
 * All function calls declared in this header are deprecated and meant to be
 * removed in future.
 */

#ifndef SSH_LEGACY_H
#define SSH_LEGACY_H

typedef struct ssh_private_key_struct* ssh_private_key;
typedef struct ssh_public_key_struct* ssh_public_key;

SSH_API int ssh_auth_list(ssh_session_t * session);
SSH_API int ssh_userauth_offer_pubkey(ssh_session_t * session, const char *username, int type, ssh_string_t * publickey);
SSH_API int ssh_userauth_pubkey(ssh_session_t * session, const char *username, ssh_string_t * publickey, ssh_private_key privatekey);
#ifndef _WIN32
SSH_API int ssh_userauth_agent_pubkey(ssh_session_t * session, const char *username,
    ssh_public_key publickey);
#endif
SSH_API int ssh_userauth_autopubkey(ssh_session_t * session, const char *passphrase);
SSH_API int ssh_userauth_privatekey_file(ssh_session_t * session, const char *username,
    const char *filename, const char *passphrase);

SSH_API void buffer_free(ssh_buffer_t * buffer);
SSH_API void *buffer_get(ssh_buffer_t * buffer);
SSH_API uint32_t buffer_get_len(ssh_buffer_t * buffer);
SSH_API ssh_buffer_t * buffer_new(void);

SSH_API ssh_channel_t * channel_accept_x11(ssh_channel_t * channel, int timeout_ms);
SSH_API int channel_change_pty_size(ssh_channel_t * channel,int cols,int rows);
SSH_API ssh_channel_t * channel_forward_accept(ssh_session_t * session, int timeout_ms);
SSH_API int channel_close(ssh_channel_t * channel);
SSH_API int channel_forward_cancel(ssh_session_t * session, const char *address, int port);
SSH_API int channel_forward_listen(ssh_session_t * session, const char *address, int port, int *bound_port);
SSH_API void channel_free(ssh_channel_t * channel);
SSH_API int channel_get_exit_status(ssh_channel_t * channel);
SSH_API ssh_session_t * channel_get_session(ssh_channel_t * channel);
SSH_API int channel_is_closed(ssh_channel_t * channel);
SSH_API int channel_is_eof(ssh_channel_t * channel);
SSH_API int channel_is_open(ssh_channel_t * channel);
SSH_API ssh_channel_t * channel_new(ssh_session_t * session);
SSH_API int channel_open_forward(ssh_channel_t * channel, const char *remotehost,
    int remoteport, const char *sourcehost, int localport);
SSH_API int channel_open_session(ssh_channel_t * channel);
SSH_API int channel_poll(ssh_channel_t * channel, int is_stderr);
SSH_API int channel_read(ssh_channel_t * channel, void *dest, uint32_t count, int is_stderr);

SSH_API int channel_read_buffer(ssh_channel_t * channel, ssh_buffer_t * buffer, uint32_t count,
    int is_stderr);

SSH_API int channel_read_nonblocking(ssh_channel_t * channel, void *dest, uint32_t count,
    int is_stderr);
SSH_API int channel_request_env(ssh_channel_t * channel, const char *name, const char *value);
SSH_API int channel_request_exec(ssh_channel_t * channel, const char *cmd);
SSH_API int channel_request_pty(ssh_channel_t * channel);
SSH_API int channel_request_pty_size(ssh_channel_t * channel, const char *term,
    int cols, int rows);
SSH_API int channel_request_shell(ssh_channel_t * channel);
SSH_API int channel_request_send_signal(ssh_channel_t * channel, const char *signum);
SSH_API int channel_request_sftp(ssh_channel_t * channel);
SSH_API int channel_request_subsystem(ssh_channel_t * channel, const char *subsystem);
SSH_API int channel_request_x11(ssh_channel_t * channel, int single_connection, const char *protocol,
    const char *cookie, int screen_number);
SSH_API int channel_send_eof(ssh_channel_t * channel);
SSH_API int channel_select(ssh_channel_t * *readchans, ssh_channel_t * *writechans, ssh_channel_t * *exceptchans, struct
        timeval * timeout);
SSH_API void channel_set_blocking(ssh_channel_t * channel, int blocking);
SSH_API int channel_write(ssh_channel_t * channel, const void *data, uint32_t len);

SSH_API void privatekey_free(ssh_private_key prv);
SSH_API ssh_private_key privatekey_from_file(ssh_session_t * session, const char *filename,
    int type, const char *passphrase);
SSH_API void publickey_free(ssh_public_key key);
SSH_API int ssh_publickey_to_file(ssh_session_t * session, const char *file,
    ssh_string_t * pubkey, int type);
SSH_API ssh_string_t * publickey_from_file(ssh_session_t * session, const char *filename,
    int *type);
SSH_API ssh_public_key publickey_from_privatekey(ssh_private_key prv);
SSH_API ssh_string_t * publickey_to_string(ssh_public_key key);
SSH_API int ssh_try_publickey_from_file(ssh_session_t * session, const char *keyfile,
    ssh_string_t * *publickey, int *type);
SSH_API enum ssh_keytypes_e ssh_privatekey_type(ssh_private_key privatekey);

SSH_API ssh_string_t * ssh_get_pubkey(ssh_session_t * session);

SSH_API ssh_message_t * ssh_message_retrieve(ssh_session_t * session, uint32_t packettype);
SSH_API ssh_public_key ssh_message_auth_publickey(ssh_message_t * msg);

SSH_API void string_burn(ssh_string_t * str);
SSH_API ssh_string_t * string_copy(ssh_string_t * str);
SSH_API void *string_data(ssh_string_t * str);
SSH_API int string_fill(ssh_string_t * str, const void *data, size_t len);
SSH_API void string_free(ssh_string_t * str);
SSH_API ssh_string_t * string_from_char(const char *what);
SSH_API size_t string_len(ssh_string_t * str);
SSH_API ssh_string_t * string_new(size_t size);
SSH_API char *string_to_char(ssh_string_t * str);

#endif /* ! SSH_LEGACY_H */
