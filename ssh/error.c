#include <stdio.h>
#include <stdarg.h>
#include "ssh/priv.h"
#include "ssh/session.h"

/**
 * @defgroup libssh_error The SSH error functions.
 * @ingroup libssh
 *
 * Functions for error handling.
 *
 * @{
 */

/**
 * @internal
 *
 * @brief Registers an error with a description.
 *
 * @param  error       The place to store the error.
 * @param  code        The class of error.
 * @param  descr       The description, which can be a format string.
 * @param  ...         The arguments for the format string.
 */
void _ssh_set_error(void *error, int code, const char *function, const char *descr, ...)
{
    struct ssh_common_struct *err = error;
    va_list va;
	
    va_start(va, descr);
    vsnprintf(err->error.error_buffer, ERROR_BUFFERLEN, descr, va);
    va_end(va);
	
    err->error.error_code = code;
    if (ssh_get_log_level() >= SSH_LOG_WARN) {
        ssh_log_function(SSH_LOG_WARN, function, err->error.error_buffer);
    }
}

/**
 * @internal
 *
 * @brief Registers an out of memory error
 * @param  error       The place to store the error.
 *
 */
void _ssh_set_error_oom(void *error, const char *function)
{
    struct error_struct *err = error;
    snprintf(err->error_buffer, sizeof(err->error_buffer),
            "%s: Out of memory", function);
    err->error_code = SSH_FATAL;
}

/**
 * @internal
 *
 * @brief Registers an invalid argument error
 * @param  error       The place to store the error.
 * @param  function    The function the error happened in.
 *
 */
void _ssh_set_error_invalid(void *error, const char *function)
{
    _ssh_set_error(error, SSH_FATAL, function,
                   "Invalid argument in %s", function);
}

/**
 * @brief Retrieve the error text message from the last error.
 *
 * @param  error        An ssh_session_t * or ssh_bind_t *.
 *
 * @return A static string describing the error.
 */
const char *ssh_get_error(void *error) {
	struct error_struct *err = error;
	
	return err->error_buffer;
}

/**
 * @brief Retrieve the error code from the last error.
 *
 * @param  error        An ssh_session_t * or ssh_bind_t *.
 *
 * \return SSH_NO_ERROR       No error occurred\n
 *         SSH_REQUEST_DENIED The last request was denied but situation is
 *                            recoverable\n
 *         SSH_FATAL          A fatal error occurred. This could be an unexpected
 *                            disconnection\n
 *
 *         Other error codes are internal but can be considered same than
 *         SSH_FATAL.
 */
int ssh_get_error_code(void *error) {
	struct error_struct *err = error;
	
	return err->error_code;
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
