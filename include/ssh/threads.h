#ifndef SSH_THREADS_H
#define SSH_THREADS_H

#include <ssh/ssh-api.h>
#include <ssh/callbacks.h>

int ssh_threads_init(void);
void ssh_threads_finalize(void);
const char *ssh_threads_get_type(void);

#endif /* ! SSH_THREADS_H */
