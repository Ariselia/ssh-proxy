#ifndef SSH_CURVE25519_H
#define SSH_CURVE25519_H

#include "ssh-includes.h"
#include "ssh-api.h"

#ifdef WITH_NACL

#include <nacl/crypto_scalarmult_curve25519.h>
#define CURVE25519_PUBKEY_SIZE crypto_scalarmult_curve25519_BYTES
#define CURVE25519_PRIVKEY_SIZE crypto_scalarmult_curve25519_SCALARBYTES
#define crypto_scalarmult_base crypto_scalarmult_curve25519_base
#define crypto_scalarmult crypto_scalarmult_curve25519
#else

#define CURVE25519_PUBKEY_SIZE 32
#define CURVE25519_PRIVKEY_SIZE 32
int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);
int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p);
#endif /* WITH_NACL */

#ifdef HAVE_ECC
#define HAVE_CURVE25519 1
#endif

typedef unsigned char ssh_curve25519_pubkey[CURVE25519_PUBKEY_SIZE];
typedef unsigned char ssh_curve25519_privkey[CURVE25519_PRIVKEY_SIZE];


int ssh_client_curve25519_init(ssh_session_t * session);
int ssh_client_curve25519_reply(ssh_session_t * session, ssh_buffer_t * packet);

#ifdef WITH_SERVER
int ssh_server_curve25519_init(ssh_session_t * session, ssh_buffer_t * packet);
#endif /* WITH_SERVER */

#endif /* SSH_CURVE25519_H */
