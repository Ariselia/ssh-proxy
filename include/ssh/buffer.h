#ifndef SSH_BUFFER_H
#define SSH_BUFFER_H

#include "ssh/ssh-api.h"
/*
 * Describes a buffer state
 * [XXXXXXXXXXXXDATA PAYLOAD       XXXXXXXXXXXXXXXXXXXXXXXX]
 * ^            ^                  ^                       ^]
 * \_data points\_pos points here  \_used points here |    /
 *   here                                          Allocated
 */
struct ssh_buffer_struct {
    char *data;
    uint32_t used;
    uint32_t allocated;
    uint32_t pos;
};

SSH_API void ssh_buffer_free(ssh_buffer_t * buffer);
SSH_API void *ssh_buffer_get_begin(ssh_buffer_t * buffer);
SSH_API uint32_t ssh_buffer_get_len(ssh_buffer_t * buffer);
SSH_API ssh_buffer_t * ssh_buffer_new(void);
SSH_API int buffer_add_ssh_string(ssh_buffer_t * buffer, ssh_string_t * string);
SSH_API int buffer_add_u8(ssh_buffer_t * buffer, uint8_t data);
SSH_API int buffer_add_u16(ssh_buffer_t * buffer, uint16_t data);
SSH_API int buffer_add_u32(ssh_buffer_t * buffer, uint32_t data);
SSH_API int buffer_add_u64(ssh_buffer_t * buffer, uint64_t data);
SSH_API int buffer_add_data(ssh_buffer_t * buffer, const void *data, uint32_t len);
SSH_API int buffer_prepend_data(ssh_buffer_t * buffer, const void *data, uint32_t len);
SSH_API int buffer_add_buffer(ssh_buffer_t * buffer, ssh_buffer_t * source);
SSH_API int buffer_reinit(ssh_buffer_t * buffer);

/* buffer_get_rest returns a pointer to the current position into the buffer */
SSH_API void *buffer_get_rest(ssh_buffer_t * buffer);
/* buffer_get_rest_len returns the number of bytes which can be read */
SSH_API uint32_t buffer_get_rest_len(ssh_buffer_t * buffer);

/* buffer_read_*() returns the number of bytes read, except for ssh strings */
SSH_API int buffer_get_u8(ssh_buffer_t * buffer, uint8_t *data);
SSH_API int buffer_get_u32(ssh_buffer_t * buffer, uint32_t *data);
SSH_API int buffer_get_u64(ssh_buffer_t * buffer, uint64_t *data);

SSH_API uint32_t buffer_get_data(ssh_buffer_t * buffer, void *data, uint32_t requestedlen);
/* buffer_get_ssh_string() is an exception. if the String read is too large or invalid, it will answer NULL. */
SSH_API ssh_string_t * buffer_get_ssh_string(ssh_buffer_t * buffer);
/* gets a string out of a SSH-1 mpint */
SSH_API ssh_string_t * buffer_get_mpint(ssh_buffer_t * buffer);
/* buffer_pass_bytes acts as if len bytes have been read (used for padding) */
SSH_API uint32_t buffer_pass_bytes_end(ssh_buffer_t * buffer, uint32_t len);
SSH_API uint32_t buffer_pass_bytes(ssh_buffer_t * buffer, uint32_t len);

#endif /* ! SSH_BUFFER_H */
