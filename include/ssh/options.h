#ifndef SSH_OPTIONS_H
#define SSH_OPTIONS_H

SSH_API int ssh_config_parse_file(ssh_session_t * session, const char *filename);
SSH_API int ssh_options_set_algo(ssh_session_t * session, int algo, const char *list);
SSH_API int ssh_options_apply(ssh_session_t * session);

#endif /* ! SSH_OPTIONS_H */
