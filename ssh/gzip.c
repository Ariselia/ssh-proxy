#include "ssh-includes.h"

#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include "ssh/priv.h"
#include "ssh/buffer.h"
#include "ssh/crypto.h"
#include "ssh/session.h"

#define BLOCKSIZE 4092

static z_stream *initcompress(ssh_session_t * session, int level) {
  z_stream *stream = NULL;
  int status;

  stream = malloc(sizeof(z_stream));
  if (stream == NULL) {
    return NULL;
  }
  memset(stream, 0, sizeof(z_stream));

  status = deflateInit(stream, level);
  if (status != Z_OK) {
    SAFE_FREE(stream);
    ssh_set_error(session, SSH_FATAL,
        "status %d inititalising zlib deflate", status);
    return NULL;
  }

  return stream;
}

static ssh_buffer_t * gzip_compress(ssh_session_t * session,ssh_buffer_t * source,int level){
  z_stream *zout = session->current_crypto->compress_out_ctx;
  void *in_ptr = buffer_get_rest(source);
  unsigned long in_size = buffer_get_rest_len(source);
  ssh_buffer_t * dest = NULL;
  unsigned char out_buf[BLOCKSIZE] = {0};
  unsigned long len;
  int status;

  if(zout == NULL) {
    zout = session->current_crypto->compress_out_ctx = initcompress(session, level);
    if (zout == NULL) {
      return NULL;
    }
  }

  dest = ssh_buffer_new();
  if (dest == NULL) {
    return NULL;
  }

  zout->next_out = out_buf;
  zout->next_in = in_ptr;
  zout->avail_in = in_size;
  do {
    zout->avail_out = BLOCKSIZE;
    status = deflate(zout, Z_PARTIAL_FLUSH);
    if (status != Z_OK) {
      ssh_buffer_free(dest);
      ssh_set_error(session, SSH_FATAL,
          "status %d deflating zlib packet", status);
      return NULL;
    }
    len = BLOCKSIZE - zout->avail_out;
    if (buffer_add_data(dest, out_buf, len) < 0) {
      ssh_buffer_free(dest);
      return NULL;
    }
    zout->next_out = out_buf;
  } while (zout->avail_out == 0);

  return dest;
}

int compress_buffer(ssh_session_t * session, ssh_buffer_t * buf) {
  ssh_buffer_t * dest = NULL;

  dest = gzip_compress(session, buf, session->opts.compressionlevel);
  if (dest == NULL) {
    return -1;
  }

  if (buffer_reinit(buf) < 0) {
    ssh_buffer_free(dest);
    return -1;
  }

  if (buffer_add_data(buf, buffer_get_rest(dest), buffer_get_rest_len(dest)) < 0) {
    ssh_buffer_free(dest);
    return -1;
  }

  ssh_buffer_free(dest);
  return 0;
}

/* decompression */

static z_stream *initdecompress(ssh_session_t * session) {
  z_stream *stream = NULL;
  int status;

  stream = malloc(sizeof(z_stream));
  if (stream == NULL) {
    return NULL;
  }
  memset(stream,0,sizeof(z_stream));

  status = inflateInit(stream);
  if (status != Z_OK) {
    SAFE_FREE(stream);
    ssh_set_error(session, SSH_FATAL,
        "Status = %d initiating inflate context!", status);
    return NULL;
  }

  return stream;
}

static ssh_buffer_t * gzip_decompress(ssh_session_t * session, ssh_buffer_t * source, size_t maxlen) {
  z_stream *zin = session->current_crypto->compress_in_ctx;
  void *in_ptr = buffer_get_rest(source);
  unsigned long in_size = buffer_get_rest_len(source);
  unsigned char out_buf[BLOCKSIZE] = {0};
  ssh_buffer_t * dest = NULL;
  unsigned long len;
  int status;

  if (zin == NULL) {
    zin = session->current_crypto->compress_in_ctx = initdecompress(session);
    if (zin == NULL) {
      return NULL;
    }
  }

  dest = ssh_buffer_new();
  if (dest == NULL) {
    return NULL;
  }

  zin->next_out = out_buf;
  zin->next_in = in_ptr;
  zin->avail_in = in_size;

  do {
    zin->avail_out = BLOCKSIZE;
    status = inflate(zin, Z_PARTIAL_FLUSH);
    if (status != Z_OK && status != Z_BUF_ERROR) {
      ssh_set_error(session, SSH_FATAL,
          "status %d inflating zlib packet", status);
      ssh_buffer_free(dest);
      return NULL;
    }

    len = BLOCKSIZE - zin->avail_out;
    if (buffer_add_data(dest,out_buf,len) < 0) {
      ssh_buffer_free(dest);
      return NULL;
    }
    if (buffer_get_rest_len(dest) > maxlen){
      /* Size of packet exceeded, avoid a denial of service attack */
      ssh_buffer_free(dest);
      return NULL;
    }
    zin->next_out = out_buf;
  } while (zin->avail_out == 0);

  return dest;
}

int decompress_buffer(ssh_session_t * session,ssh_buffer_t * buf, size_t maxlen){
  ssh_buffer_t * dest = NULL;

  dest = gzip_decompress(session,buf, maxlen);
  if (dest == NULL) {
    return -1;
  }

  if (buffer_reinit(buf) < 0) {
    ssh_buffer_free(dest);
    return -1;
  }

  if (buffer_add_data(buf, buffer_get_rest(dest), buffer_get_rest_len(dest)) < 0) {
    ssh_buffer_free(dest);
    return -1;
  }

  ssh_buffer_free(dest);
  return 0;
}

/* vim: set ts=2 sw=2 et cindent: */
