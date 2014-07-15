#ifndef SSH_PKI_PRIV_H
#define SSH_PKI_PRIV_H

#define RSA_HEADER_BEGIN "-----BEGIN RSA PRIVATE KEY-----"
#define RSA_HEADER_END "-----END RSA PRIVATE KEY-----"
#define DSA_HEADER_BEGIN "-----BEGIN DSA PRIVATE KEY-----"
#define DSA_HEADER_END "-----END DSA PRIVATE KEY-----"
#define ECDSA_HEADER_BEGIN "-----BEGIN EC PRIVATE KEY-----"
#define ECDSA_HEADER_END "-----END EC PRIVATE KEY-----"

#define ssh_pki_log(...) \
    _ssh_pki_log(__FUNCTION__, __VA_ARGS__)
void _ssh_pki_log(const char *function,
                  const char *format, ...) PRINTF_ATTRIBUTE(2, 3);

int pki_key_ecdsa_nid_from_name(const char *name);

/* SSH Key Functions */
ssh_key_t * pki_key_dup(const ssh_key_t * key, int demote);
int pki_key_generate_rsa(ssh_key_t * key, int parameter);
int pki_key_generate_dss(ssh_key_t * key, int parameter);
int pki_key_generate_ecdsa(ssh_key_t * key, int parameter);
int pki_key_compare(const ssh_key_t * k1,
                    const ssh_key_t * k2,
                    enum ssh_keycmp_e what);

/* SSH Private Key Functions */
enum ssh_keytypes_e pki_privatekey_type_from_string(const char *privkey);
ssh_key_t * pki_private_key_from_base64(const char *b64_key,
                                    const char *passphrase,
                                    ssh_auth_callback auth_fn,
                                    void *auth_data);

ssh_string_t * pki_private_key_to_pem(const ssh_key_t * key,
                                  const char *passphrase,
                                  ssh_auth_callback auth_fn,
                                  void *auth_data);

/* SSH Public Key Functions */
int pki_pubkey_build_dss(ssh_key_t * key,
                         ssh_string_t * p,
                         ssh_string_t * q,
                         ssh_string_t * g,
                         ssh_string_t * pubkey);
int pki_pubkey_build_rsa(ssh_key_t * key,
                         ssh_string_t * e,
                         ssh_string_t * n);
int pki_pubkey_build_ecdsa(ssh_key_t * key, int nid, ssh_string_t * e);
ssh_string_t * pki_publickey_to_blob(const ssh_key_t * key);
int pki_export_pubkey_rsa1(const ssh_key_t * key,
                           const char *host,
                           char *rsa1,
                           size_t rsa1_len);

/* SSH Signature Functions */
ssh_string_t * pki_signature_to_blob(const ssh_signature sign);
ssh_signature pki_signature_from_blob(const ssh_key_t * pubkey,
                                      const ssh_string_t * sig_blob,
                                      enum ssh_keytypes_e type);
int pki_signature_verify(ssh_session_t * session,
                         const ssh_signature sig,
                         const ssh_key_t * key,
                         const unsigned char *hash,
                         size_t hlen);

/* SSH Signing Functions */
ssh_signature pki_do_sign(const ssh_key_t * privkey,
                          const unsigned char *hash,
                          size_t hlen);
ssh_signature pki_do_sign_sessionid(const ssh_key_t * key,
                                    const unsigned char *hash,
                                    size_t hlen);
#endif /* ! SSH_PKI_PRIV_H */
