#ifndef ECDH_H_
#define ECDH_H_

#include "ssh-includes.h"

#ifdef HAVE_LIBCRYPTO
#ifdef HAVE_OPENSSL_ECDH_H

#ifdef HAVE_ECC
#define HAVE_ECDH 1
#endif

#endif /* HAVE_OPENSSL_ECDH_H */
#endif /* HAVE_LIBCRYPTO */

SSH_API int ssh_client_ecdh_init(ssh_session_t * session);
SSH_API int ssh_client_ecdh_reply(ssh_session_t * session, ssh_buffer_t * packet);

#ifdef WITH_SERVER
SSH_API int ssh_server_ecdh_init(ssh_session_t * session, ssh_buffer_t * packet);
#endif /* WITH_SERVER */

#endif /* ECDH_H_ */
