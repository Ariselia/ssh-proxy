#ifndef SSH_PKI_H
#define SSH_PKI_H

#ifdef HAVE_OPENSSL_EC_H
#include <openssl/ec.h>
#endif
#ifdef HAVE_OPENSSL_ECDSA_H
#include <openssl/ecdsa.h>
#endif

#include "ssh/crypto.h"

#define MAX_PUBKEY_SIZE 0x100000 /* 1M */
#define MAX_PRIVKEY_SIZE 0x400000 /* 4M */

#define SSH_KEY_FLAG_EMPTY   0x0
#define SSH_KEY_FLAG_PUBLIC  0x0001
#define SSH_KEY_FLAG_PRIVATE 0x0002

struct ssh_key_struct {
    enum ssh_keytypes_e type;
    int flags;
    const char *type_c; /* Don't free it ! it is static */
    int ecdsa_nid;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa;
    gcry_sexp_t rsa;
    void *ecdsa;
#elif HAVE_LIBCRYPTO
    DSA *dsa;
    RSA *rsa;
#ifdef HAVE_OPENSSL_ECC
    EC_KEY *ecdsa;
#else
    void *ecdsa;
#endif /* HAVE_OPENSSL_EC_H */
#endif
    void *cert;
};

struct ssh_signature_struct {
    enum ssh_keytypes_e type;
    const char *type_c;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_sig;
    gcry_sexp_t rsa_sig;
    void *ecdsa_sig;
#elif defined HAVE_LIBCRYPTO
    DSA_SIG *dsa_sig;
    ssh_string_t * rsa_sig;
# ifdef HAVE_OPENSSL_ECC
    ECDSA_SIG *ecdsa_sig;
# else
    void *ecdsa_sig;
# endif
#endif
};

typedef struct ssh_signature_struct *ssh_signature;


#ifdef __cplusplus
extern "C" {
#endif

/* SSH Key Functions */
SSH_API ssh_key_t * ssh_key_dup(const ssh_key_t * key);
SSH_API void ssh_key_clean (ssh_key_t * key);

/* SSH Signature Functions */
SSH_API ssh_signature ssh_signature_new(void);
SSH_API void ssh_signature_free(ssh_signature sign);

SSH_API int ssh_pki_export_signature_blob(const ssh_signature sign,
                                  ssh_string_t * *sign_blob);
SSH_API int ssh_pki_import_signature_blob(const ssh_string_t * sig_blob,
                                  const ssh_key_t * pubkey,
                                  ssh_signature *psig);
SSH_API int ssh_pki_signature_verify_blob(ssh_session_t * session,
                                  ssh_string_t * sig_blob,
                                  const ssh_key_t * key,
                                  unsigned char *digest,
                                  size_t dlen);

/* SSH Public Key Functions */
SSH_API int ssh_pki_export_pubkey_blob(const ssh_key_t * key,
                               ssh_string_t * *pblob);
SSH_API int ssh_pki_import_pubkey_blob(const ssh_string_t * key_blob,
                               ssh_key_t * *pkey);
SSH_API int ssh_pki_export_pubkey_rsa1(const ssh_key_t * key,
                               const char *host,
                               char *rsa1,
                               size_t rsa1_len);

/* SSH Signing Functions */
SSH_API ssh_string_t * ssh_pki_do_sign(ssh_session_t * session, ssh_buffer_t * sigbuf,
    const ssh_key_t * privatekey);
SSH_API ssh_string_t * ssh_pki_do_sign_agent(ssh_session_t * session,
                                 ssh_buffer_t *buf,
                                 const ssh_key_t * pubkey);
SSH_API ssh_string_t * ssh_srv_pki_do_sign_sessionid(ssh_session_t * session,
                                         const ssh_key_t * privkey);

/* Temporary functions, to be removed after migration to ssh_key_t * */
SSH_API ssh_public_key ssh_pki_convert_key_to_publickey(const ssh_key_t * key);
SSH_API ssh_private_key ssh_pki_convert_key_to_privatekey(const ssh_key_t * key);


#ifdef __cplusplus
}
#endif

#endif /* ! SSH_PKI_H */
