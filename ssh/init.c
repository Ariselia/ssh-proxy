#include "ssh-includes.h"
#include "ssh/priv.h"
#include "ssh/socket.h"
#include "ssh/dh.h"
#include "ssh/poll.h"
#include "ssh/threads.h"

#ifdef _WIN32
#include <winsock2.h>
//#pragma comment(lib, "misc")
#endif

/**
 * @defgroup libssh The libssh API
 *
 * The libssh library is implementing the SSH protocols and some of its
 * extensions. This group of functions is mostly used to implment a SSH client.
 * Some function are needed to implement a SSH server too.
 *
 * @{
 */

/**
 * @brief Initialize global cryptographic data structures.
 *
 * This function should only be called once, at the beginning of the program, in
 * the main thread. It may be omitted if your program is not multithreaded.
 *
 * @returns             0 on success, -1 if an error occured.
 */
int ssh_init(void) {
  if(ssh_threads_init())
    return -1;
  if(ssh_crypto_init())
    return -1;
  if(ssh_socket_init())
    return -1;
  return 0;
}


/**
 * @brief Finalize and cleanup all libssh and cryptographic data structures.
 *
 * This function should only be called once, at the end of the program!
 *
 * @returns             0 on succes, -1 if an error occured.
 *
   @returns 0 otherwise
 */
int ssh_finalize(void) {
  ssh_crypto_finalize();
  ssh_socket_cleanup();
  /* It is important to finalize threading after CRYPTO because
   * it still depends on it */
  ssh_threads_finalize();

  return 0;
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
