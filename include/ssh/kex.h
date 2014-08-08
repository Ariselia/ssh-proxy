#ifndef SSH_KEX_H
#define SSH_KEX_H

#include "ssh/priv.h"
#include "ssh/callbacks.h"

#define SSH_KEX_METHODS 10

struct ssh_kex_struct {
    unsigned char cookie[16];
    char *methods[SSH_KEX_METHODS];
};

SSH_PACKET_CALLBACK(ssh_packet_kexinit);
#ifdef WITH_SSH1
SSH_PACKET_CALLBACK(ssh_packet_publickey1);
#endif

SSH_API int ssh_send_kex(ssh_session_t * session, int server_kex);
SSH_API void ssh_list_kex(ssh_kex_t *kex);
SSH_API int set_client_kex(ssh_session_t * session);
SSH_API int ssh_kex_select_methods(ssh_session_t * session);
SSH_API int verify_existing_algo(int algo, const char *name);
SSH_API char **space_tokenize(const char *chain);
SSH_API int ssh_get_kex1(ssh_session_t * session);
SSH_API char *ssh_find_matching(const char *in_d, const char *what_d);
SSH_API const char *ssh_kex_get_supported_method(uint32_t algo);
SSH_API const char *ssh_kex_get_description(uint32_t algo);

#endif /* ! SSH_KEX_H */
