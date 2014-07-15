#ifndef SSH_API_H
#define SSH_API_H

#if defined _WIN32 || defined __CYGWIN__
  #ifdef LIBSSH_STATIC
    #define SSH_API
  #else
    #ifdef LIBSSH_EXPORTS
      #ifdef __GNUC__
        #define SSH_API __attribute__((dllexport))
      #else
        #define SSH_API __declspec(dllexport)
      #endif
    #else
      #ifdef __GNUC__
        #define SSH_API __attribute__((dllimport))
      #else
        #define SSH_API __declspec(dllimport)
      #endif
    #endif
  #endif
#else
  #if __GNUC__ >= 4 && !defined(__OS2__)
    #define SSH_API __attribute__((visibility("default")))
  #else
    #define SSH_API
  #endif
#endif

#ifdef _MSC_VER
  /* Visual Studio hasn't inttypes.h so it doesn't know uint32_t */
  typedef int int32_t;
  typedef unsigned int uint32_t;
  typedef unsigned short uint16_t;
  typedef unsigned char uint8_t;
  typedef unsigned long long uint64_t;
  typedef int mode_t;
#else /* _MSC_VER */
  #include <unistd.h>
  #include <inttypes.h>
#endif /* _MSC_VER */

#ifdef _WIN32
  #include <winsock2.h>
#else /* _WIN32 */
 #include <sys/select.h> /* for fd_set * */
 #include <netdb.h>
#endif /* _WIN32 */

#define SSH_STRINGIFY(s) SSH_TOSTRING(s)
#define SSH_TOSTRING(s) #s

/* libssh version macros */
#define SSH_VERSION_INT(a, b, c) ((a) << 16 | (b) << 8 | (c))
#define SSH_VERSION_DOT(a, b, c) a ##.## b ##.## c
#define SSH_VERSION(a, b, c) SSH_VERSION_DOT(a, b, c)

/* libssh version */
#define LIBSSH_VERSION_MAJOR  0
#define LIBSSH_VERSION_MINOR  6
#define LIBSSH_VERSION_MICRO  3

#define LIBSSH_VERSION_INT SSH_VERSION_INT(LIBSSH_VERSION_MAJOR, \
                                           LIBSSH_VERSION_MINOR, \
                                           LIBSSH_VERSION_MICRO)
#define LIBSSH_VERSION     SSH_VERSION(LIBSSH_VERSION_MAJOR, \
                                       LIBSSH_VERSION_MINOR, \
                                       LIBSSH_VERSION_MICRO)

/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* __GNUC__ */

#ifdef __GNUC__
#define SSH_DEPRECATED __attribute__ ((deprecated))
#else
#define SSH_DEPRECATED
#endif

#ifdef __cplusplus
extern "C" {
#endif


typedef struct ssh_agent_struct ssh_agent_t;
typedef struct ssh_buffer_struct ssh_buffer_t;
typedef struct ssh_channel_struct ssh_channel_t;
typedef struct ssh_message_struct ssh_message_t;
typedef struct ssh_pcap_file_struct ssh_pcap_file_t;
typedef struct ssh_key_struct ssh_key_t;
typedef struct ssh_kex_struct ssh_kex_t;
typedef struct ssh_scp_struct ssh_scp_t;
typedef struct ssh_session_struct ssh_session_t;
typedef struct ssh_string_struct ssh_string_t;
typedef struct ssh_event_struct ssh_event_t;
typedef void* ssh_gssapi_creds;

/* Socket type */
#ifdef _WIN32
#ifndef socket_t
typedef SOCKET socket_t;
#endif /* socket_t */
#else /* _WIN32 */
#ifndef socket_t
typedef int socket_t;
#endif
#endif /* _WIN32 */

#define SSH_INVALID_SOCKET ((socket_t) -1)

/* the offsets of methods */
enum ssh_kex_types_e {
	SSH_KEX=0,
	SSH_HOSTKEYS,
	SSH_CRYPT_C_S,
	SSH_CRYPT_S_C,
	SSH_MAC_C_S,
	SSH_MAC_S_C,
	SSH_COMP_C_S,
	SSH_COMP_S_C,
	SSH_LANG_C_S,
	SSH_LANG_S_C
};

#define SSH_CRYPT 2
#define SSH_MAC 3
#define SSH_COMP 4
#define SSH_LANG 5

enum ssh_auth_e {
	SSH_AUTH_SUCCESS=0,
	SSH_AUTH_DENIED,
	SSH_AUTH_PARTIAL,
	SSH_AUTH_INFO,
	SSH_AUTH_AGAIN,
	SSH_AUTH_ERROR=-1
};

/* auth flags */
#define SSH_AUTH_METHOD_UNKNOWN 0
#define SSH_AUTH_METHOD_NONE 0x0001
#define SSH_AUTH_METHOD_PASSWORD 0x0002
#define SSH_AUTH_METHOD_PUBLICKEY 0x0004
#define SSH_AUTH_METHOD_HOSTBASED 0x0008
#define SSH_AUTH_METHOD_INTERACTIVE 0x0010
#define SSH_AUTH_METHOD_GSSAPI_MIC 0x0020

/* messages */
enum ssh_requests_e {
	SSH_REQUEST_AUTH=1,
	SSH_REQUEST_CHANNEL_OPEN,
	SSH_REQUEST_CHANNEL,
	SSH_REQUEST_SERVICE,
	SSH_REQUEST_GLOBAL
};

enum ssh_channel_type_e {
	SSH_CHANNEL_UNKNOWN=0,
	SSH_CHANNEL_SESSION,
	SSH_CHANNEL_DIRECT_TCPIP,
	SSH_CHANNEL_FORWARDED_TCPIP,
	SSH_CHANNEL_X11
};

enum ssh_channel_requests_e {
	SSH_CHANNEL_REQUEST_UNKNOWN=0,
	SSH_CHANNEL_REQUEST_PTY,
	SSH_CHANNEL_REQUEST_EXEC,
	SSH_CHANNEL_REQUEST_SHELL,
	SSH_CHANNEL_REQUEST_ENV,
	SSH_CHANNEL_REQUEST_SUBSYSTEM,
	SSH_CHANNEL_REQUEST_WINDOW_CHANGE,
	SSH_CHANNEL_REQUEST_X11
};

enum ssh_global_requests_e {
	SSH_GLOBAL_REQUEST_UNKNOWN=0,
	SSH_GLOBAL_REQUEST_TCPIP_FORWARD,
	SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD,
};

enum ssh_publickey_state_e {
	SSH_PUBLICKEY_STATE_ERROR=-1,
	SSH_PUBLICKEY_STATE_NONE=0,
	SSH_PUBLICKEY_STATE_VALID=1,
	SSH_PUBLICKEY_STATE_WRONG=2
};

/* Status flags */
/** Socket is closed */
#define SSH_CLOSED 0x01
/** Reading to socket won't block */
#define SSH_READ_PENDING 0x02
/** Session was closed due to an error */
#define SSH_CLOSED_ERROR 0x04
/** Output buffer not empty */
#define SSH_WRITE_PENDING 0x08

enum ssh_server_known_e {
	SSH_SERVER_ERROR=-1,
	SSH_SERVER_NOT_KNOWN=0,
	SSH_SERVER_KNOWN_OK,
	SSH_SERVER_KNOWN_CHANGED,
	SSH_SERVER_FOUND_OTHER,
	SSH_SERVER_FILE_NOT_FOUND
};

#ifndef MD5_DIGEST_LEN
    #define MD5_DIGEST_LEN 16
#endif
/* errors */

enum ssh_error_types_e {
	SSH_NO_ERROR=0,
	SSH_REQUEST_DENIED,
	SSH_FATAL,
	SSH_EINTR
};

/* some types for keys */
enum ssh_keytypes_e{
  SSH_KEYTYPE_UNKNOWN=0,
  SSH_KEYTYPE_DSS=1,
  SSH_KEYTYPE_RSA,
  SSH_KEYTYPE_RSA1,
  SSH_KEYTYPE_ECDSA
};

enum ssh_keycmp_e {
  SSH_KEY_CMP_PUBLIC = 0,
  SSH_KEY_CMP_PRIVATE
};

/* Error return codes */
#define SSH_OK 0     /* No error */
#define SSH_ERROR -1 /* Error of some kind */
#define SSH_AGAIN -2 /* The nonblocking call must be repeated */
#define SSH_EOF -127 /* We have already a eof */

/**
 * @addtogroup libssh_log
 *
 * @{
 */

enum {
	/** No logging at all
	 */
	SSH_LOG_NOLOG=0,
	/** Only warnings
	 */
	SSH_LOG_WARNING,
	/** High level protocol information
	 */
	SSH_LOG_PROTOCOL,
	/** Lower level protocol infomations, packet level
	 */
	SSH_LOG_PACKET,
	/** Every function path
	 */
	SSH_LOG_FUNCTIONS
};
/** @} */
#define SSH_LOG_RARE SSH_LOG_WARNING

/**
 * @name Logging levels
 *
 * @brief Debug levels for logging.
 * @{
 */

/** No logging at all */
#define SSH_LOG_NONE 0
/** Show only warnings */
#define SSH_LOG_WARN 1
/** Get some information what's going on */
#define SSH_LOG_INFO 2
/** Get detailed debuging information **/
#define SSH_LOG_DEBUG 3
/** Get trace output, packet information, ... */
#define SSH_LOG_TRACE 4

/** @} */

enum ssh_options_e {
  SSH_OPTIONS_HOST,
  SSH_OPTIONS_PORT,
  SSH_OPTIONS_PORT_STR,
  SSH_OPTIONS_FD,
  SSH_OPTIONS_USER,
  SSH_OPTIONS_SSH_DIR,
  SSH_OPTIONS_IDENTITY,
  SSH_OPTIONS_ADD_IDENTITY,
  SSH_OPTIONS_KNOWNHOSTS,
  SSH_OPTIONS_TIMEOUT,
  SSH_OPTIONS_TIMEOUT_USEC,
  SSH_OPTIONS_SSH1,
  SSH_OPTIONS_SSH2,
  SSH_OPTIONS_LOG_VERBOSITY,
  SSH_OPTIONS_LOG_VERBOSITY_STR,
  SSH_OPTIONS_CIPHERS_C_S,
  SSH_OPTIONS_CIPHERS_S_C,
  SSH_OPTIONS_COMPRESSION_C_S,
  SSH_OPTIONS_COMPRESSION_S_C,
  SSH_OPTIONS_PROXYCOMMAND,
  SSH_OPTIONS_BINDADDR,
  SSH_OPTIONS_STRICTHOSTKEYCHECK,
  SSH_OPTIONS_COMPRESSION,
  SSH_OPTIONS_COMPRESSION_LEVEL,
  SSH_OPTIONS_KEY_EXCHANGE,
  SSH_OPTIONS_HOSTKEYS,
  SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,
  SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
  SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
};

enum {
  /** Code is going to write/create remote files */
  SSH_SCP_WRITE,
  /** Code is going to read remote files */
  SSH_SCP_READ,
  SSH_SCP_RECURSIVE=0x10
};

enum ssh_scp_request_types {
  /** A new directory is going to be pulled */
  SSH_SCP_REQUEST_NEWDIR=1,
  /** A new file is going to be pulled */
  SSH_SCP_REQUEST_NEWFILE,
  /** End of requests */
  SSH_SCP_REQUEST_EOF,
  /** End of directory */
  SSH_SCP_REQUEST_ENDDIR,
  /** Warning received */
  SSH_SCP_REQUEST_WARNING
};

SSH_API int ssh_blocking_flush(ssh_session_t * session, int timeout);
SSH_API ssh_channel_t * ssh_channel_accept_x11(ssh_channel_t * channel, int timeout_ms);
SSH_API int ssh_channel_change_pty_size(ssh_channel_t * channel,int cols,int rows);
SSH_API int ssh_channel_close(ssh_channel_t * channel);
SSH_API void ssh_channel_free(ssh_channel_t * channel);
SSH_API int ssh_channel_get_exit_status(ssh_channel_t * channel);
SSH_API ssh_session_t * ssh_channel_get_session(ssh_channel_t * channel);
SSH_API int ssh_channel_is_closed(ssh_channel_t * channel);
SSH_API int ssh_channel_is_eof(ssh_channel_t * channel);
SSH_API int ssh_channel_is_open(ssh_channel_t * channel);
SSH_API ssh_channel_t * ssh_channel_new(ssh_session_t * session);
SSH_API int ssh_channel_open_auth_agent(ssh_channel_t * channel);
SSH_API int ssh_channel_open_forward(ssh_channel_t * channel, const char *remotehost,
    int remoteport, const char *sourcehost, int localport);
SSH_API int ssh_channel_open_session(ssh_channel_t * channel);
SSH_API int ssh_channel_open_x11(ssh_channel_t * channel, const char *orig_addr, int orig_port);
SSH_API int ssh_channel_poll(ssh_channel_t * channel, int is_stderr);
SSH_API int ssh_channel_poll_timeout(ssh_channel_t * channel, int timeout, int is_stderr);
SSH_API int ssh_channel_read(ssh_channel_t * channel, void *dest, uint32_t count, int is_stderr);
SSH_API int ssh_channel_read_timeout(ssh_channel_t * channel, void *dest, uint32_t count, int is_stderr, int timeout_ms);
SSH_API int ssh_channel_read_nonblocking(ssh_channel_t * channel, void *dest, uint32_t count,
    int is_stderr);
SSH_API int ssh_channel_request_env(ssh_channel_t * channel, const char *name, const char *value);
SSH_API int ssh_channel_request_exec(ssh_channel_t * channel, const char *cmd);
SSH_API int ssh_channel_request_pty(ssh_channel_t * channel);
SSH_API int ssh_channel_request_pty_size(ssh_channel_t * channel, const char *term,
    int cols, int rows);
SSH_API int ssh_channel_request_shell(ssh_channel_t *channel);
SSH_API int ssh_channel_request_send_signal(ssh_channel_t *channel, const char *signum);
SSH_API int ssh_channel_request_sftp(ssh_channel_t *channel);
SSH_API int ssh_channel_request_subsystem(ssh_channel_t *channel, const char *subsystem);
SSH_API int ssh_channel_request_x11(ssh_channel_t *channel, int single_connection, const char *protocol,
    const char *cookie, int screen_number);
SSH_API int ssh_channel_send_eof(ssh_channel_t *channel);
SSH_API int ssh_channel_select(ssh_channel_t * *readchans, ssh_channel_t * *writechans, ssh_channel_t * *exceptchans, struct
        timeval * timeout);
SSH_API void ssh_channel_set_blocking(ssh_channel_t * channel, int blocking);
SSH_API int ssh_channel_write(ssh_channel_t * channel, const void *data, uint32_t len);
SSH_API uint32_t ssh_channel_window_size(ssh_channel_t * channel);

SSH_API char *ssh_basename (const char *path);
SSH_API void ssh_clean_pubkey_hash(unsigned char **hash);
SSH_API int ssh_connect(ssh_session_t * session);
SSH_API const char *ssh_copyright(void);
SSH_API void ssh_disconnect(ssh_session_t * session);
SSH_API char *ssh_dirname (const char *path);
SSH_API int ssh_finalize(void);
SSH_API ssh_channel_t * ssh_forward_accept(ssh_session_t * session, int timeout_ms);
SSH_API ssh_channel_t * ssh_channel_accept_forward(ssh_session_t * session, int timeout_ms, int *destination_port);
SSH_API int ssh_forward_cancel(ssh_session_t * session, const char *address, int port);
SSH_API int ssh_forward_listen(ssh_session_t * session, const char *address, int port, int *bound_port);
SSH_API void ssh_free(ssh_session_t * session);
SSH_API const char *ssh_get_disconnect_message(ssh_session_t * session);
SSH_API const char *ssh_get_error(void *error);
SSH_API int ssh_get_error_code(void *error);
SSH_API socket_t ssh_get_fd(ssh_session_t * session);
SSH_API char *ssh_get_hexa(const unsigned char *what, size_t len);
SSH_API char *ssh_get_issue_banner(ssh_session_t * session);
SSH_API int ssh_get_openssh_version(ssh_session_t * session);

SSH_API int ssh_get_publickey(ssh_session_t * session, ssh_key_t * *key);

enum ssh_publickey_hash_type {
    SSH_PUBLICKEY_HASH_SHA1,
    SSH_PUBLICKEY_HASH_MD5
};
SSH_API int ssh_get_publickey_hash(const ssh_key_t * key,
                                      enum ssh_publickey_hash_type type,
                                      unsigned char **hash,
                                      size_t *hlen);

SSH_DEPRECATED SSH_API int ssh_get_pubkey_hash(ssh_session_t * session, unsigned char **hash);

SSH_API int ssh_get_random(void *where,int len,int strong);
SSH_API int ssh_get_version(ssh_session_t * session);
SSH_API int ssh_get_status(ssh_session_t * session);
SSH_API int ssh_get_poll_flags(ssh_session_t * session);
SSH_API int ssh_init(void);
SSH_API int ssh_is_blocking(ssh_session_t * session);
SSH_API int ssh_is_connected(ssh_session_t * session);
SSH_API int ssh_is_server_known(ssh_session_t * session);

/* LOGGING */
SSH_API int ssh_set_log_level(int level);
SSH_API int ssh_get_log_level(void);
SSH_API void *ssh_get_log_userdata(void);
SSH_API int ssh_set_log_userdata(void *data);
SSH_API void _ssh_log(int verbosity,
                         const char *function,
                         const char *format, ...) PRINTF_ATTRIBUTE(3, 4);

SSH_API int ssh_log(ssh_session_t *session, const char *format, ...);

/* legacy */
SSH_DEPRECATED SSH_API void _ssh_log2(ssh_session_t * session,
                                       int prioriry,
                                       const char *format, ...) PRINTF_ATTRIBUTE(3, 4);

SSH_API ssh_channel_t * ssh_message_channel_request_open_reply_accept(ssh_message_t * msg);
SSH_API int ssh_message_channel_request_reply_success(ssh_message_t * msg);
SSH_API void ssh_message_free(ssh_message_t * msg);
SSH_API ssh_message_t * ssh_message_get(ssh_session_t * session);
SSH_API int ssh_message_subtype(ssh_message_t * msg);
SSH_API int ssh_message_type(ssh_message_t * msg);
SSH_API int ssh_mkdir (const char *pathname, mode_t mode);
SSH_API ssh_session_t * ssh_new(void);

SSH_API int ssh_options_copy(ssh_session_t * src, ssh_session_t * *dest);
SSH_API int ssh_options_getopt(ssh_session_t * session, int *argcptr, char **argv);
SSH_API int ssh_options_parse_config(ssh_session_t * session, const char *filename);
SSH_API int ssh_options_set(ssh_session_t * session, enum ssh_options_e type,
    const void *value);
SSH_API int ssh_options_get(ssh_session_t * session, enum ssh_options_e type,
    char **value);
SSH_API int ssh_options_get_port(ssh_session_t * session, unsigned int * port_target);
SSH_API int ssh_pcap_file_close(ssh_pcap_file_t * pcap);
SSH_API void ssh_pcap_file_free(ssh_pcap_file_t * pcap);
SSH_API ssh_pcap_file_t * ssh_pcap_file_new(void);
SSH_API int ssh_pcap_file_open(ssh_pcap_file_t * pcap, const char *filename);

/**
 * @brief SSH authentication callback.
 *
 * @param prompt        Prompt to be displayed.
 * @param buf           Buffer to save the password. You should null-terminate it.
 * @param len           Length of the buffer.
 * @param echo          Enable or disable the echo of what you type.
 * @param verify        Should the password be verified?
 * @param userdata      Userdata to be passed to the callback function. Useful
 *                      for GUI applications.
 *
 * @return              0 on success, < 0 on error.
 */
typedef int (*ssh_auth_callback) (const char *prompt, char *buf, size_t len,
    int echo, int verify, void *userdata);

SSH_API ssh_key_t * ssh_key_new(void);
SSH_API void ssh_key_free (ssh_key_t * key);
SSH_API enum ssh_keytypes_e ssh_key_type(const ssh_key_t * key);
SSH_API const char *ssh_key_type_to_char(enum ssh_keytypes_e type);
SSH_API enum ssh_keytypes_e ssh_key_type_from_name(const char *name);
SSH_API int ssh_key_is_public(const ssh_key_t * k);
SSH_API int ssh_key_is_private(const ssh_key_t * k);
SSH_API int ssh_key_cmp(const ssh_key_t * k1,
                           const ssh_key_t * k2,
                           enum ssh_keycmp_e what);

SSH_API int ssh_pki_generate(enum ssh_keytypes_e type, int parameter,
        ssh_key_t * *pkey);
SSH_API int ssh_pki_import_privkey_base64(const char *b64_key,
                                             const char *passphrase,
                                             ssh_auth_callback auth_fn,
                                             void *auth_data,
                                             ssh_key_t * *pkey);
SSH_API int ssh_pki_import_privkey_file(const char *filename,
                                           const char *passphrase,
                                           ssh_auth_callback auth_fn,
                                           void *auth_data,
                                           ssh_key_t * *pkey);
SSH_API int ssh_pki_export_privkey_file(const ssh_key_t * privkey,
                                           const char *passphrase,
                                           ssh_auth_callback auth_fn,
                                           void *auth_data,
                                           const char *filename);

SSH_API int ssh_pki_import_pubkey_base64(const char *b64_key,
                                            enum ssh_keytypes_e type,
                                            ssh_key_t * *pkey);
SSH_API int ssh_pki_import_pubkey_file(const char *filename,
                                          ssh_key_t * *pkey);

SSH_API int ssh_pki_export_privkey_to_pubkey(const ssh_key_t * privkey,
                                                ssh_key_t * *pkey);
SSH_API int ssh_pki_export_pubkey_base64(const ssh_key_t * key,
                                            char **b64_key);
SSH_API int ssh_pki_export_pubkey_file(const ssh_key_t * key,
                                          const char *filename);

SSH_API void ssh_print_hexa(const char *descr, const unsigned char *what, size_t len);
SSH_API int ssh_send_ignore (ssh_session_t * session, const char *data);
SSH_API int ssh_send_debug (ssh_session_t * session, const char *message, int always_display);
SSH_API void ssh_gssapi_set_creds(ssh_session_t * session, const ssh_gssapi_creds creds);
SSH_API int ssh_scp_accept_request(ssh_scp_t * scp);
SSH_API int ssh_scp_close(ssh_scp_t * scp);
SSH_API int ssh_scp_deny_request(ssh_scp_t * scp, const char *reason);
SSH_API void ssh_scp_free(ssh_scp_t * scp);
SSH_API int ssh_scp_init(ssh_scp_t * scp);
SSH_API int ssh_scp_leave_directory(ssh_scp_t * scp);
SSH_API ssh_scp_t * ssh_scp_new(ssh_session_t * session, int mode, const char *location);
SSH_API int ssh_scp_pull_request(ssh_scp_t * scp);
SSH_API int ssh_scp_push_directory(ssh_scp_t * scp, const char *dirname, int mode);
SSH_API int ssh_scp_push_file(ssh_scp_t * scp, const char *filename, size_t size, int perms);
SSH_API int ssh_scp_push_file64(ssh_scp_t * scp, const char *filename, uint64_t size, int perms);
SSH_API int ssh_scp_read(ssh_scp_t * scp, void *buffer, size_t size);
SSH_API const char *ssh_scp_request_get_filename(ssh_scp_t * scp);
SSH_API int ssh_scp_request_get_permissions(ssh_scp_t * scp);
SSH_API size_t ssh_scp_request_get_size(ssh_scp_t * scp);
SSH_API uint64_t ssh_scp_request_get_size64(ssh_scp_t * scp);
SSH_API const char *ssh_scp_request_get_warning(ssh_scp_t * scp);
SSH_API int ssh_scp_write(ssh_scp_t * scp, const void *buffer, size_t len);
SSH_API int ssh_select(ssh_channel_t * *channels, ssh_channel_t * *outchannels, socket_t maxfd,
    fd_set *readfds, struct timeval *timeout);
SSH_API int ssh_service_request(ssh_session_t * session, const char *service);
SSH_API int ssh_set_agent_channel(ssh_session_t * session, ssh_channel_t * channel);
SSH_API void ssh_set_blocking(ssh_session_t * session, int blocking);
SSH_API void ssh_set_fd_except(ssh_session_t * session);
SSH_API void ssh_set_fd_toread(ssh_session_t * session);
SSH_API void ssh_set_fd_towrite(ssh_session_t * session);
SSH_API void ssh_silent_disconnect(ssh_session_t * session);
SSH_API int ssh_set_pcap_file(ssh_session_t * session, ssh_pcap_file_t * pcapfile);

/* USERAUTH */
SSH_API int ssh_userauth_none(ssh_session_t * session, const char *username);
SSH_API int ssh_userauth_list(ssh_session_t * session, const char *username);
SSH_API int ssh_userauth_try_publickey(ssh_session_t * session,
                                          const char *username,
                                          const ssh_key_t * pubkey);
SSH_API int ssh_userauth_publickey(ssh_session_t * session,
                                      const char *username,
                                      const ssh_key_t * privkey);
#ifndef _WIN32
SSH_API int ssh_userauth_agent(ssh_session_t * session,
                                  const char *username);
#endif
SSH_API int ssh_userauth_publickey_auto(ssh_session_t * session,
                                           const char *username,
                                           const char *passphrase);
SSH_API int ssh_userauth_password(ssh_session_t * session,
                                     const char *username,
                                     const char *password);

SSH_API int ssh_userauth_kbdint(ssh_session_t * session, const char *user, const char *submethods);
SSH_API const char *ssh_userauth_kbdint_getinstruction(ssh_session_t * session);
SSH_API const char *ssh_userauth_kbdint_getname(ssh_session_t * session);
SSH_API int ssh_userauth_kbdint_getnprompts(ssh_session_t * session);
SSH_API const char *ssh_userauth_kbdint_getprompt(ssh_session_t * session, unsigned int i, char *echo);
SSH_API int ssh_userauth_kbdint_getnanswers(ssh_session_t * session);
SSH_API const char *ssh_userauth_kbdint_getanswer(ssh_session_t * session, unsigned int i);
SSH_API int ssh_userauth_kbdint_setanswer(ssh_session_t * session, unsigned int i,
    const char *answer);
SSH_API int ssh_userauth_gssapi(ssh_session_t * session);
SSH_API const char *ssh_version(int req_version);
SSH_API int ssh_write_knownhost(ssh_session_t * session);

SSH_API void ssh_string_burn(ssh_string_t * str);
SSH_API ssh_string_t * ssh_string_copy(const ssh_string_t * str);
SSH_API void *ssh_string_data(ssh_string_t * str);
SSH_API int ssh_string_fill(ssh_string_t * str, const void *data, size_t len);
SSH_API void ssh_string_free(ssh_string_t * str);
SSH_API ssh_string_t *ssh_string_from_char(const char *what);
SSH_API size_t ssh_string_len(const ssh_string_t * str);
SSH_API ssh_string_t * ssh_string_new(size_t size);
SSH_API const char *ssh_string_get_char(ssh_string_t * str);
SSH_API char *ssh_string_to_char(ssh_string_t * str);
SSH_API void ssh_string_free_char(char *s);

SSH_API int ssh_getpass(const char *prompt, char *buf, size_t len, int echo,
    int verify);


typedef int (*ssh_event_callback)(socket_t fd, int revents, void *userdata);

SSH_API ssh_event_t * ssh_event_new(void);
SSH_API int ssh_event_add_fd(ssh_event_t * event, socket_t fd, short events,
                                    ssh_event_callback cb, void *userdata);
SSH_API int ssh_event_add_session(ssh_event_t * event, ssh_session_t * session);
SSH_API int ssh_event_dopoll(ssh_event_t * event, int timeout);
SSH_API int ssh_event_remove_fd(ssh_event_t * event, socket_t fd);
SSH_API int ssh_event_remove_session(ssh_event_t * event, ssh_session_t * session);
SSH_API void ssh_event_free(ssh_event_t * event);
SSH_API const char* ssh_get_clientbanner(ssh_session_t * session);
SSH_API const char* ssh_get_serverbanner(ssh_session_t * session);
SSH_API const char* ssh_get_cipher_in(ssh_session_t * session);
SSH_API const char* ssh_get_cipher_out(ssh_session_t * session);

#ifndef LIBSSH_LEGACY_0_4
#include "ssh/legacy.h"
#endif

#ifdef __cplusplus
}
#endif
#endif /* ! SSH_API_H */
/* vim: set ts=2 sw=2 et cindent: */
