#ifndef SSH_SOCKET_H
#define SSH_SOCKET_H

#include "ssh/callbacks.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ssh_poll_handle_struct;
/* socket.c */

struct ssh_socket_struct;
typedef struct ssh_socket_struct* ssh_socket;

int ssh_socket_init(void);
void ssh_socket_cleanup(void);
ssh_socket ssh_socket_new(ssh_session_t * session);
void ssh_socket_reset(ssh_socket s);
void ssh_socket_free(ssh_socket s);
void ssh_socket_set_fd(ssh_socket s, socket_t fd);
socket_t ssh_socket_get_fd_in(ssh_socket s);
#ifndef _WIN32
int ssh_socket_unix(ssh_socket s, const char *path);
void ssh_execute_command(const char *command, socket_t in, socket_t out);
int ssh_socket_connect_proxycommand(ssh_socket s, const char *command);
#endif
void ssh_socket_close(ssh_socket s);
int ssh_socket_write(ssh_socket s,const void *buffer, int len);
int ssh_socket_is_open(ssh_socket s);
int ssh_socket_fd_isset(ssh_socket s, fd_set *set);
void ssh_socket_fd_set(ssh_socket s, fd_set *set, socket_t *max_fd);
void ssh_socket_set_fd_in(ssh_socket s, socket_t fd);
void ssh_socket_set_fd_out(ssh_socket s, socket_t fd);
int ssh_socket_nonblocking_flush(ssh_socket s);
void ssh_socket_set_write_wontblock(ssh_socket s);
void ssh_socket_set_read_wontblock(ssh_socket s);
void ssh_socket_set_except(ssh_socket s);
int ssh_socket_get_status(ssh_socket s);
int ssh_socket_get_poll_flags(ssh_socket s);
int ssh_socket_buffered_write_bytes(ssh_socket s);
int ssh_socket_data_available(ssh_socket s);
int ssh_socket_data_writable(ssh_socket s);
int ssh_socket_set_nonblocking(socket_t fd);
int ssh_socket_set_blocking(socket_t fd);

void ssh_socket_set_callbacks(ssh_socket s, ssh_socket_callbacks callbacks);
int ssh_socket_pollcallback(struct ssh_poll_handle_struct *p, socket_t fd, int revents, void *v_s);
struct ssh_poll_handle_struct * ssh_socket_get_poll_handle_in(ssh_socket s);
struct ssh_poll_handle_struct * ssh_socket_get_poll_handle_out(ssh_socket s);

int ssh_socket_connect(ssh_socket s, const char *host, int port, const char *bind_addr);

#ifdef __cplusplus
}
#endif

#endif /* ! SSH_SOCKET_H */
