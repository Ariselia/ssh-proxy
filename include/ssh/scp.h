#ifndef SSH_SCP_H
#define SSH_SCP_H

enum ssh_scp_states {
  SSH_SCP_NEW,          //Data structure just created
  SSH_SCP_WRITE_INITED, //Gave our intention to write
  SSH_SCP_WRITE_WRITING,//File was opened and currently writing
  SSH_SCP_READ_INITED,  //Gave our intention to read
  SSH_SCP_READ_REQUESTED, //We got a read request
  SSH_SCP_READ_READING, //File is opened and reading
  SSH_SCP_ERROR,         //Something bad happened
  SSH_SCP_TERMINATED	//Transfer finished
};

struct ssh_scp_struct {
  ssh_session_t * session;
  int mode;
  int recursive;
  ssh_channel_t * channel;
  char *location;
  enum ssh_scp_states state;
  uint64_t filelen;
  uint64_t processed;
  enum ssh_scp_request_types request_type;
  char *request_name;
  char *warning;
  int request_mode;
};

int ssh_scp_read_string(ssh_scp_t * scp, char *buffer, size_t len);
int ssh_scp_integer_mode(const char *mode);
char *ssh_scp_string_mode(int mode);
int ssh_scp_response(ssh_scp_t * scp, char **response);

#endif /* ! SSH_SCP_H */
