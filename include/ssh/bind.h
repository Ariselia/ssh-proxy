#ifndef SSH_BIND_H
#define SSH_BIND_H

#include "ssh/priv.h"
#include "ssh/session.h"

struct ssh_bind_struct {
  struct ssh_common_struct common; /* stuff common to ssh_bind_t * and ssh_session_t * */
  struct ssh_bind_callbacks_struct *bind_callbacks;
  void *bind_callbacks_userdata;

  struct ssh_poll_handle_struct *poll;
  /* options */
  char *wanted_methods[10];
  char *banner;
  char *ecdsakey;
  char *dsakey;
  char *rsakey;
  ssh_key_t * ecdsa;
  ssh_key_t * dsa;
  ssh_key_t * rsa;
  char *bindaddr;
  socket_t bindfd;
  unsigned int bindport;
  int blocking;
  int toaccept;
};

struct ssh_poll_handle_struct *ssh_bind_get_poll(struct ssh_bind_struct *bind);


#endif /* ! SSH_BIND_H */
