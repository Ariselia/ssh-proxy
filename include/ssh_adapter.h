/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2014 by Wang Feng
 *
 */

#ifndef SSH_PROXY_ADAPTER_H
#define SSH_PROXY_ADAPTER_H

#include "api_log.h"

#include "ssh/priv.h"
#include "ssh/session.h"
#include "ssh/server.h"

#define SSH_VERSION_S(x) (x) >> 4, (x) & 0X0F

#define SSHFUNCTION_DISABLE_NETWORK (0)


#ifdef __cplusplus
extern "C" {
#endif

typedef struct ssh_adapter_struct {
	struct ssh_common_struct common; /* stuff common to ssh_bind and ssh_session_t * */
	struct ssh_bind_callbacks_struct *bind_callbacks;
	void *bind_callbacks_userdata;
	
	struct ssh_poll_handle_struct *poll;
	/* options */
	char *wanted_methods[10];
	char *banner;
	char *ecdsakey;
	char *dsakey;
	char *rsakey;
	ssh_key_t * ecdsa;
	ssh_key_t * dsa;
	ssh_key_t * rsa;
	char *bindaddr; // WANGFENG
	//socket_t bindfd;
	unsigned int bindport;
}ssh_adapter_t;

void ssh_adapter_free(ssh_adapter_t *adapter);
ssh_adapter_t * ssh_adapter_new(void);
int ssh_adapter_init(ssh_adapter_t *adapter);
int ssh_adapter_accept(ssh_adapter_t *adapter, ssh_session_t * session);
int ssh_adapter_options_set(ssh_adapter_t *adapter, enum ssh_bind_options_e type,
    const void *value);

int session_packet_handler(ssh_session_t *session, const char *data, size_t receivedlen);


#ifdef __cplusplus
}
#endif

#endif /* ! SSH_PROXY_ADAPTER_H */

