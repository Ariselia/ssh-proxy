#ifndef SSH_KEYS_H
#define SSH_KEYS_H

#include "ssh-includes.h"
#include "ssh/ssh-api.h"
#include "ssh/wrapper.h"

struct ssh_public_key_struct {
    int type;
    const char *type_c; /* Don't free it ! it is static */
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_pub;
    gcry_sexp_t rsa_pub;
#elif HAVE_LIBCRYPTO
    DSA *dsa_pub;
    RSA *rsa_pub;
#endif
};

struct ssh_private_key_struct {
    int type;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_priv;
    gcry_sexp_t rsa_priv;
#elif defined HAVE_LIBCRYPTO
    DSA *dsa_priv;
    RSA *rsa_priv;
#endif
};

const char *ssh_type_to_char(int type);
int ssh_type_from_name(const char *name);

ssh_public_key publickey_from_string(ssh_session_t * session, ssh_string_t * pubkey_s);

#endif /* ! SSH_KEYS_H */
