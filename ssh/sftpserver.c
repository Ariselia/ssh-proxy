#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "ssh/ssh-api.h"
#include "ssh/sftp.h"
#include "ssh/ssh2.h"
#include "ssh/priv.h"
#include "ssh/buffer.h"
#include "ssh/misc.h"

sftp_client_message_t * 
sftp_get_client_message(sftp_session_t *sftp)
{
    ssh_session_t *session = sftp->session;
  	sftp_packet_t *packet;
  	sftp_client_message_t *msg = NULL;
  	ssh_buffer_t *payload = NULL;
  	ssh_string_t *tmp;
	
  	msg = malloc(sizeof (sftp_client_message_t));
  	if (msg == NULL) {
        ssh_set_error_oom(session);
    	return NULL;
  	}
  	ZERO_STRUCTP(msg);
	
  	packet = sftp_packet_read(sftp);
  	if (packet == NULL) {
    	ssh_set_error_oom(session);
    	sftp_client_message_free(msg);
    	return NULL;
  	}
	
  	payload = packet->payload;
  	msg->type = packet->type;
  	msg->sftp = sftp;

  	/* take a copy of the whole packet */
  	msg->complete_message = ssh_buffer_new();
  	buffer_add_data(msg->complete_message, buffer_get_rest(payload), buffer_get_rest_len(payload));

  	buffer_get_u32(payload, &msg->id);
    	
  	switch(msg->type) {
    case SSH_FXP_CLOSE:
    case SSH_FXP_READDIR:
      	msg->handle = buffer_get_ssh_string(payload);
      	if (msg->handle == NULL) {
        	ssh_set_error_oom(session);
        	sftp_client_message_free(msg);
        	return NULL;
      	}
     	break;
    case SSH_FXP_READ:
        msg->handle = buffer_get_ssh_string(payload);
        if (msg->handle == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        buffer_get_u64(payload, &msg->offset);
        buffer_get_u32(payload, &msg->len);
        break;
    case SSH_FXP_WRITE:
        msg->handle = buffer_get_ssh_string(payload);
        if (msg->handle == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        buffer_get_u64(payload, &msg->offset);
        msg->data = buffer_get_ssh_string(payload);
        if (msg->data == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        break;
    case SSH_FXP_REMOVE:
    case SSH_FXP_RMDIR:
    case SSH_FXP_OPENDIR:
    case SSH_FXP_READLINK:
    case SSH_FXP_REALPATH:
        tmp = buffer_get_ssh_string(payload);
        if (tmp == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        msg->filename = ssh_string_to_char(tmp);
        ssh_string_free(tmp);
        if (msg->filename == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        break;
    case SSH_FXP_RENAME:
    case SSH_FXP_SYMLINK:
        tmp = buffer_get_ssh_string(payload);
        if (tmp == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        msg->filename = ssh_string_to_char(tmp);
        ssh_string_free(tmp);
        if (msg->filename == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        msg->data = buffer_get_ssh_string(payload);
        if (msg->data == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        break;
    case SSH_FXP_MKDIR:
    case SSH_FXP_SETSTAT:
        tmp = buffer_get_ssh_string(payload);
        if (tmp == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        msg->filename=ssh_string_to_char(tmp);
        ssh_string_free(tmp);
        if (msg->filename == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        msg->attr = sftp_parse_attr(sftp, payload, 0);
        if (msg->attr == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        break;
    case SSH_FXP_FSETSTAT:
        msg->handle = buffer_get_ssh_string(payload);
        if (msg->handle == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        msg->attr = sftp_parse_attr(sftp, payload, 0);
        if (msg->attr == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        break;
    case SSH_FXP_LSTAT:
    case SSH_FXP_STAT:
        tmp = buffer_get_ssh_string(payload);
        if (tmp == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        msg->filename = ssh_string_to_char(tmp);
        ssh_string_free(tmp);
        if (msg->filename == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        if(sftp->version > 3) {
            buffer_get_u32(payload,&msg->flags);
        }
        break;
    case SSH_FXP_OPEN:
        tmp = buffer_get_ssh_string(payload);
        if (tmp == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        msg->filename = ssh_string_to_char(tmp);
        ssh_string_free(tmp);
        if (msg->filename == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        buffer_get_u32(payload,&msg->flags);
        msg->attr = sftp_parse_attr(sftp, payload, 0);
        if (msg->attr == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        break;
    case SSH_FXP_FSTAT:
        msg->handle = buffer_get_ssh_string(payload);
        if (msg->handle == NULL) {
            ssh_set_error_oom(session);
            sftp_client_message_free(msg);
            return NULL;
        }
        buffer_get_u32(payload, &msg->flags);
        break;
    default:
        ssh_set_error(sftp->session, SSH_FATAL,
                "Received unhandled sftp message %d\n", msg->type);
        sftp_client_message_free(msg);
        return NULL;
    }
    
    msg->flags = ntohl(msg->flags);
    msg->offset = ntohll(msg->offset);
    msg->len = ntohl(msg->len);
    sftp_packet_free(packet);
    
    return msg;
}

/* Send an sftp client message. Can be used in cas of proxying */
int sftp_send_client_message(sftp_session_t *sftp, sftp_client_message_t * msg)
{
	return sftp_packet_write(sftp, msg->type, msg->complete_message);
}

uint8_t sftp_client_message_get_type(sftp_client_message_t * msg)
{
	return msg->type;
}

const char *sftp_client_message_get_filename(sftp_client_message_t * msg)
{
	return msg->filename;
}

void sftp_client_message_set_filename(sftp_client_message_t * msg, const char *newname)
{
	free(msg->filename);
	msg->filename = strdup(newname);
}

const char *sftp_client_message_get_data(sftp_client_message_t * msg)
{
	if (msg->str_data == NULL) {
		msg->str_data = ssh_string_to_char(msg->data);
	}
	return msg->str_data;
}

uint32_t sftp_client_message_get_flags(sftp_client_message_t * msg)
{
	return msg->flags;
}

void sftp_client_message_free(sftp_client_message_t * msg)
{
  	if (msg == NULL) {
    	return;
  	}
	
  	SAFE_FREE(msg->filename);
  	ssh_string_free(msg->data);
  	ssh_string_free(msg->handle);
  	sftp_attributes_free(msg->attr);
  	ssh_buffer_free(msg->complete_message);
  	SAFE_FREE(msg->str_data);
  	ZERO_STRUCTP(msg);
  	SAFE_FREE(msg);
}

int sftp_reply_name(sftp_client_message_t * msg, const char *name,
    sftp_attributes_t *attr)
{
  	ssh_buffer_t * out;
  	ssh_string_t * file;
	
  	out = ssh_buffer_new();
  	if (out == NULL) {
    	return -1;
  	}
	
  	file = ssh_string_from_char(name);
  	if (file == NULL) {
    	ssh_buffer_free(out);
    	return -1;
  	}

  	if (buffer_add_u32(out, msg->id) < 0 ||
      	buffer_add_u32(out, htonl(1)) < 0 ||
      	buffer_add_ssh_string(out, file) < 0 ||
      	buffer_add_ssh_string(out, file) < 0 || /* The protocol is broken here between 3 & 4 */
      	buffer_add_attributes(out, attr) < 0 ||
      	sftp_packet_write(msg->sftp, SSH_FXP_NAME, out) < 0)
   	{
    	ssh_buffer_free(out);
    	ssh_string_free(file);
    	return -1;
  	}
  	ssh_buffer_free(out);
  	ssh_string_free(file);
	
  	return 0;
}

int sftp_reply_handle(sftp_client_message_t * msg, ssh_string_t * handle)
{
  	ssh_buffer_t *out = NULL;
	
  	out = ssh_buffer_new();
  	if (out == NULL) {
    	return -1;
  	}
	
  	if (buffer_add_u32(out, msg->id) < 0 ||
      	buffer_add_ssh_string(out, handle) < 0 ||
      	sftp_packet_write(msg->sftp, SSH_FXP_HANDLE, out) < 0) {
    	ssh_buffer_free(out);
    	return -1;
  	}
  	ssh_buffer_free(out);
	
  	return 0;
}

int sftp_reply_attr(sftp_client_message_t * msg, sftp_attributes_t *attr)
{
  	ssh_buffer_t * out;
	
  	out = ssh_buffer_new();
  	if (out == NULL) {
    	return -1;
  	}
	
  	if (buffer_add_u32(out, msg->id) < 0 ||
      	buffer_add_attributes(out, attr) < 0 ||
      	sftp_packet_write(msg->sftp, SSH_FXP_ATTRS, out) < 0) {
    	ssh_buffer_free(out);
    	return -1;
  	}
  	ssh_buffer_free(out);
	
  	return 0;
}

int sftp_reply_names_add(sftp_client_message_t * msg, const char *file,
    const char *longname, sftp_attributes_t *attr)
{
  	ssh_string_t *name = NULL;
	
  	name = ssh_string_from_char(file);
  	if (name == NULL) {
    	return -1;
  	}
	
  	if (msg->attrbuf == NULL) {
    	msg->attrbuf = ssh_buffer_new();
    	if (msg->attrbuf == NULL) {
      		ssh_string_free(name);
      		return -1;
    	}
  	}
	
  	if (buffer_add_ssh_string(msg->attrbuf, name) < 0) {
    	ssh_string_free(name);
    	return -1;
  	}
	
  	ssh_string_free(name);
  	name = ssh_string_from_char(longname);
  	if (name == NULL) {
    	return -1;
  	}
  	if (buffer_add_ssh_string(msg->attrbuf,name) < 0 ||
      	buffer_add_attributes(msg->attrbuf,attr) < 0) {
    	ssh_string_free(name);
    	return -1;
	}
  	ssh_string_free(name);
  	msg->attr_num++;
	
  	return 0;
}

int sftp_reply_names(sftp_client_message_t * msg)
{
  	ssh_buffer_t *out = NULL;
	
  	out = ssh_buffer_new();
  	if (out == NULL) {
    	ssh_buffer_free(msg->attrbuf);
    	return -1;
  	}
	
  	if (buffer_add_u32(out, msg->id) < 0 ||
      	buffer_add_u32(out, htonl(msg->attr_num)) < 0 ||
      	buffer_add_data(out, buffer_get_rest(msg->attrbuf),
        buffer_get_rest_len(msg->attrbuf)) < 0 ||
      	sftp_packet_write(msg->sftp, SSH_FXP_NAME, out) < 0) {
    	ssh_buffer_free(out);
    	ssh_buffer_free(msg->attrbuf);
    	return -1;
  	}
	
  	ssh_buffer_free(out);
  	ssh_buffer_free(msg->attrbuf);
	
  	msg->attr_num = 0;
  	msg->attrbuf = NULL;
	
  	return 0;
}

int sftp_reply_status(sftp_client_message_t * msg, uint32_t status,
    const char *message) {
  ssh_buffer_t * out;
  ssh_string_t * s;

  out = ssh_buffer_new();
  if (out == NULL) {
    return -1;
  }

  s = ssh_string_from_char(message ? message : "");
  if (s == NULL) {
    ssh_buffer_free(out);
    return -1;
  }

  if (buffer_add_u32(out, msg->id) < 0 ||
      buffer_add_u32(out, htonl(status)) < 0 ||
      buffer_add_ssh_string(out, s) < 0 ||
      buffer_add_u32(out, 0) < 0 || /* language string */
      sftp_packet_write(msg->sftp, SSH_FXP_STATUS, out) < 0) {
    ssh_buffer_free(out);
    ssh_string_free(s);
    return -1;
  }

  ssh_buffer_free(out);
  ssh_string_free(s);

  return 0;
}

int sftp_reply_data(sftp_client_message_t *msg, const void *data, int len) {
  	ssh_buffer_t *out = NULL;
	
  	out = ssh_buffer_new();
  	if (out == NULL) {
    	return -1;
  	}
	
  	if (buffer_add_u32(out, msg->id) < 0 ||
      	buffer_add_u32(out, ntohl(len)) < 0 ||
      	buffer_add_data(out, data, len) < 0 ||
      	sftp_packet_write(msg->sftp, SSH_FXP_DATA, out) < 0) {
    	ssh_buffer_free(out);
    	return -1;
  	}
  	ssh_buffer_free(out);
	
  	return 0;
}

/*
 * This function will return you a new handle to give the client.
 * the function accepts an info that can be retrieved later with
 * the handle. Care is given that a corrupted handle won't give a
 * valid info (or worse).
 */
ssh_string_t * sftp_handle_alloc(sftp_session_t *sftp, void *info)
{
    ssh_string_t *ret = NULL;
    uint32_t val;
    int i;
    
    if (sftp->handles == NULL) {
        sftp->handles = malloc(sizeof(void *) * SFTP_HANDLES);
        if (sftp->handles == NULL) {
            return NULL;
        }
        memset(sftp->handles, 0, sizeof(void *) * SFTP_HANDLES);
    }
    
    for (i = 0; i < SFTP_HANDLES; i++) {
        if (sftp->handles[i] == NULL) {
            break;
        }
    }
    
    if (i == SFTP_HANDLES) {
        return NULL; /* no handle available */
    }
    
    val = i;
    ret = ssh_string_new(4);
    if (ret == NULL) {
        return NULL;
    }
    
    memcpy(ssh_string_data(ret), &val, sizeof(uint32_t));
    sftp->handles[i] = info;
    
    return ret;
}

void *sftp_handle(sftp_session_t *sftp, ssh_string_t * handle)
{
    uint32_t val;
    
    if (sftp->handles == NULL) {
        return NULL;
    }
    
    if (ssh_string_len(handle) != sizeof(uint32_t)) {
        return NULL;
    }
    
    memcpy(&val, ssh_string_data(handle), sizeof(uint32_t));
    
    if (val > SFTP_HANDLES) {
        return NULL;
    }
    
    return sftp->handles[val];
}

void sftp_handle_remove(sftp_session_t *sftp, void *handle) {
    int i;
    
    for (i = 0; i < SFTP_HANDLES; i++) {
        if (sftp->handles[i] == handle) {
            sftp->handles[i] = NULL;
            break;
        }
    }
}

/* vim: set ts=4 sw=4 et cindent: */
