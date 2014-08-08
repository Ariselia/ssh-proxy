#ifndef SSH_GSSAPI_H
#define SSH_GSSAPI_H

#include "ssh-includes.h"
#include "ssh/session.h"

/* all OID begin with the tag identifier + length */
#define SSH_OID_TAG 06

typedef struct ssh_gssapi_struct *ssh_gssapi;

#ifdef WITH_SERVER
int ssh_gssapi_handle_userauth(ssh_session_t * session, const char *user, uint32_t n_oid, ssh_string_t * *oids);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_server);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_mic);
#endif /* WITH_SERVER */

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_client);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_response);


int ssh_gssapi_auth_mic(ssh_session_t * session);

#endif /* ! SSH_GSSAPI_H */
