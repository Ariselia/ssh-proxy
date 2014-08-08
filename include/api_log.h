#ifndef API_LOG_H
#define API_LOG_H

#include "api.h"
#include "ssh-includes.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#ifdef _WIN32
#include <io.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LOG_LEVEL_QUIET,
	LOG_LEVEL_FATAL,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_INFO,
	LOG_LEVEL_VERBOSE,
	LOG_LEVEL_DEBUG1,
	LOG_LEVEL_DEBUG2,
	LOG_LEVEL_DEBUG3,
	LOG_LEVEL_NOT_SET = -1
} log_level_e;

// stdout.log ???
#define trace_out(fmt, ...)  api_log_trace(LOG_LEVEL_VERBOSE, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define trace_err(fmt, ...)  api_log_trace(LOG_LEVEL_ERROR, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

// access.log
#define do_info(fmt, ...)    api_log_message(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define do_out(fmt, ...)     api_log_message(LOG_LEVEL_VERBOSE, fmt, ##__VA_ARGS__)
#define do_error(fmt, ...)   api_log_message(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define do_fatal(fmt, ...)   api_log_fatal(LOG_LEVEL_FATAL, fmt, ##__VA_ARGS__)
#define do_assert(exp)       api_log_assert(LOG_LEVEL_FATAL, (exp), #exp, __FILE__, __LINE__, __FUNCTION__) 

API_DECLARE(int) api_log(log_level_e level, const char *fmt, va_list args);

API_DECLARE(int) api_log_message(log_level_e level, const char *format, ...);

API_DECLARE(int) api_log_trace(log_level_e level, const char *filename, int line, const char *function, const char *format, ...);

API_DECLARE(void) api_log_fatal(log_level_e level, const char *fmt,...);
API_DECLARE(void) api_log_assert(log_level_e level, int exp, const char *exps, const char *filename, int line, const char *function);

API int api_sftpfile_open(const char *username, const char *filename);

#ifdef __cplusplus
}
#endif


#endif /* ! API_LOG_H */

