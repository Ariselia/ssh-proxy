#ifndef SSH_WRAPPER_H
#define SSH_WRAPPER_H

#include "ssh-includes.h"
#include "ssh/ssh-crypto.h"
#include "ssh/ssh-gcrypt.h"

enum ssh_mac_e {
  SSH_MAC_SHA1=1,
  SSH_MAC_SHA256,
  SSH_MAC_SHA384,
  SSH_MAC_SHA512
};

enum ssh_hmac_e {
  SSH_HMAC_SHA1 = 1,
  SSH_HMAC_MD5
};

enum ssh_des_e {
  SSH_3DES,
  SSH_DES
};

typedef struct ssh_mac_ctx_struct *ssh_mac_ctx;

MD5CTX md5_init(void);
void md5_update(MD5CTX c, const void *data, unsigned long len);
void md5_final(unsigned char *md,MD5CTX c);
SHACTX sha1_init(void);
void sha1_update(SHACTX c, const void *data, unsigned long len);
void sha1_final(unsigned char *md,SHACTX c);
void sha1(unsigned char *digest,int len,unsigned char *hash);
void sha256(unsigned char *digest, int len, unsigned char *hash);

void evp(int nid, unsigned char *digest, int len, unsigned char *hash, unsigned int *hlen);
EVPCTX evp_init(int nid);
void evp_update(EVPCTX ctx, const void *data, unsigned long len);
void evp_final(EVPCTX ctx, unsigned char *md, unsigned int *mdlen);

ssh_mac_ctx ssh_mac_ctx_init(enum ssh_mac_e type);
void ssh_mac_update(ssh_mac_ctx ctx, const void *data, unsigned long len);
void ssh_mac_final(unsigned char *md, ssh_mac_ctx ctx);

HMACCTX hmac_init(const void *key,int len, enum ssh_hmac_e type);
void hmac_update(HMACCTX c, const void *data, unsigned long len);
void hmac_final(HMACCTX ctx,unsigned char *hashmacbuf,unsigned int *len);

int crypt_set_algorithms(ssh_session_t * session, enum ssh_des_e des_type);
int crypt_set_algorithms_server(ssh_session_t * session);
struct ssh_crypto_struct *crypto_new(void);
SSH_API void crypto_free(struct ssh_crypto_struct *crypto);

SSH_API void ssh_reseed(void);

#endif /* SSH_WRAPPER_H */
