#ifndef SSH_EXAMPLES_COMMON_H
#define SSH_EXAMPLES_COMMON_H

#include <ssh/ssh-api.h>
int authenticate_console(ssh_session_t *session);
int authenticate_kbdint(ssh_session_t *session, const char *password);
int verify_knownhost(ssh_session_t *session);
ssh_session_t *connect_ssh(const char *hostname, const char *user, int verbosity);

#endif /* ! SSH_EXAMPLES_COMMON_H */
