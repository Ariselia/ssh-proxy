#ifndef SSH_PACKET_H
#define SSH_PACKET_H

struct ssh_socket_struct;

/* this structure should go someday */
typedef struct packet_struct {
	int valid;
	uint32_t len;
	uint8_t type;
} PACKET;

/** different state of packet reading. */
enum ssh_packet_state_e {
  /** Packet not initialized, must read the size of packet */
  PACKET_STATE_INIT,
  /** WANGFENG: proxy, Packet initialized, must read the size of packet */
  PACKET_STATE_INIT_SIZEREAD,
  /** Size was read, waiting for the rest of data */
  PACKET_STATE_SIZEREAD,
  /** Full packet was read and callbacks are being called. Future packets
   * should wait for the end of the callback. */
  PACKET_STATE_PROCESSING
};

SSH_API int packet_send(ssh_session_t * session);

#ifdef WITH_SSH1
int packet_send1(ssh_session_t * session) ;
void ssh_packet_set_default_callbacks1(ssh_session_t * session);

SSH_PACKET_CALLBACK(ssh_packet_disconnect1);
SSH_PACKET_CALLBACK(ssh_packet_smsg_success1);
SSH_PACKET_CALLBACK(ssh_packet_smsg_failure1);
int ssh_packet_socket_callback1(const void *data, size_t receivedlen, void *user);

#endif

SSH_PACKET_CALLBACK(ssh_packet_unimplemented);
SSH_PACKET_CALLBACK(ssh_packet_disconnect_callback);
SSH_PACKET_CALLBACK(ssh_packet_ignore_callback);
SSH_PACKET_CALLBACK(ssh_packet_dh_reply);
SSH_PACKET_CALLBACK(ssh_packet_newkeys);
SSH_PACKET_CALLBACK(ssh_packet_service_accept);

#ifdef WITH_SERVER
SSH_PACKET_CALLBACK(ssh_packet_kexdh_init);
#endif

SSH_API int ssh_packet_send_unimplemented(ssh_session_t * session, uint32_t seqnum);
SSH_API int ssh_packet_parse_type(ssh_session_t * session);
//int packet_flush(ssh_session_t * session, int enforce_blocking);

SSH_API int ssh_packet_socket_callback(const void *data, size_t len, void *user);
SSH_API void ssh_packet_register_socket_callback(ssh_session_t * session, struct ssh_socket_struct *s);
SSH_API void ssh_packet_set_callbacks(ssh_session_t * session, ssh_packet_callbacks callbacks);
SSH_API void ssh_packet_set_default_callbacks(ssh_session_t * session);
SSH_API void ssh_packet_process(ssh_session_t * session, uint8_t type, const char *name);

/* PACKET CRYPT */
SSH_API uint32_t packet_decrypt_len(ssh_session_t * session, char *crypted);
SSH_API int packet_decrypt(ssh_session_t * session, void *packet, unsigned int len);
SSH_API unsigned char *packet_encrypt(ssh_session_t * session,
                              void *packet,
                              unsigned int len);
SSH_API int packet_hmac_verify(ssh_session_t * session,ssh_buffer_t * buffer,
                       unsigned char *mac);

#endif /* ! SSH_PACKET_H */
