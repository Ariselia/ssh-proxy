#ifndef SSH_PROXY_PACKET_H
#define SSH_PROXY_PACKET_H

#include "ssh_adapter.h"
#include "ssh/ssh1.h"
#include "ssh/ssh2.h"

#ifdef __cplusplus
extern "C" {
#endif

// CLIENT -> PROXY
#define IP_CP "CP"
// PROXY  -> SERVER
#define IP_PS "PS"
// SERVER -> PROXY
#define IP_SP "SP"
// PROXY  -> CLIENT
#define IP_PC "PC"

/** @brief Prototype for a packet callback, to be called when a new packet arrives
 * @param session The current session of the packet
 * @param type packet type (see ssh2.h)
 * @param packet buffer containing the packet, excluding size, type and padding fields
 * @param user user argument to the callback
 * and are called each time a packet shows up
 * @returns SSH_PACKET_USED Packet was parsed and used
 * @returns SSH_PACKET_NOT_USED Packet was not used or understood, processing must continue
 */
typedef int (*spi_packet_callback) (ssh_session_t *session, uint8_t type, ssh_buffer_t *packet, void *user);

#define SPI_PACKET_CALLBACK(name) \
	int name (ssh_session_t *session, uint8_t type, ssh_buffer_t *packet, void *user)

typedef struct ssh2_command_struct
{
	uint8_t command;
	const char *command_name;
	spi_packet_callback invoke;
} ssh2_command_t;

int session_callback_init(ssh_session_t *session);

ssh2_command_t * session_get_callback(uint8_t cmd);

#define SESSION_TYPE(session) (session)->type == SSH_SESSION_SERVER ? "SERVER":"CLIENT"


int knownhost_verify(ssh_session_t *session);
void session_request_handler(ssh_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* ! SSH_PROXY_PACKET_H */
