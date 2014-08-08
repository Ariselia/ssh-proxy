#ifndef SSH_DH_H
#define SSH_DH_H

#include "ssh-includes.h"
#include "ssh/crypto.h"

void ssh_print_bignum(const char *which,bignum num);
int dh_generate_e(ssh_session_t * session);
int dh_generate_f(ssh_session_t * session);
int dh_generate_x(ssh_session_t * session);
int dh_generate_y(ssh_session_t * session);

int ssh_crypto_init(void);
void ssh_crypto_finalize(void);

ssh_string_t * dh_get_e(ssh_session_t * session);
ssh_string_t * dh_get_f(ssh_session_t * session);
int dh_import_f(ssh_session_t * session,ssh_string_t * f_string);
int dh_import_e(ssh_session_t * session, ssh_string_t * e_string);
void dh_import_pubkey(ssh_session_t * session,ssh_string_t * pubkey_string);
int dh_build_k(ssh_session_t * session);
int ssh_client_dh_init(ssh_session_t * session);
int ssh_client_dh_reply(ssh_session_t * session, ssh_buffer_t * packet);

int make_sessionid(ssh_session_t * session);
/* add data for the final cookie */
int hashbufin_add_cookie(ssh_session_t * session, unsigned char *cookie);
int hashbufout_add_cookie(ssh_session_t * session);
int generate_session_keys(ssh_session_t * session);
bignum make_string_bn(ssh_string_t * string);
ssh_string_t * make_bignum_string(bignum num);


#endif /* ! SSH_DH_H */
