#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <fcntl.h> // for file 
#include <sys/stat.h>

#include "api_log.h"
#include "api_misc.h"

#ifndef _WIN32
#include <sys/time.h>
#else
#include <sys/utime.h>
#include <direct.h>
#endif
#include <time.h>

#ifdef _WIN32
static const char *log_path = "/runtime/logs/proxy/";
#else
static const char *log_path = "/home/runtime/logs/proxy/";
#endif
static const char *log_access = "access.log";
static int log_fd_access = -1;
//static const char *log_stdout = "stdout.log";
//static int log_fd_stdout = -1;


#ifndef F_OK
#define F_OK (0)
#endif

static int createDir(const char *pathname)
{
	char dName[256];
	int i, len;
	memset(dName, 0x00, sizeof(dName));
	strcpy(dName, pathname);
	len = strlen(dName);
	if(dName[len - 1] != '/') {
		strcat(dName, "/");
	}
	for(i = 1; i < len; i++) {
		if(dName[i] == '/') {
			dName[i] = 0;
			if(access(dName, F_OK) != 0 ) {
				if(mkdir(dName
				#ifndef _WIN32
					, S_IRWXU
				#endif
					) == -1) {
					return -1;
				}
			}
			dName[i] = '/';
		}
	}
	return 0;
}

static const char *fmt_trace = "%s(%d) : %s: ";

#ifdef _WIN32
#define SSH_USEC_IN_SEC         1000000LL
#define SSH_SECONDS_SINCE_1601  11644473600LL

int gettimeofday(struct timeval *__p, void *__t) {
	union {
		unsigned long long ns100; /* time since 1 Jan 1601 in 100ns units */
		FILETIME ft;
	} now;

	GetSystemTimeAsFileTime (&now.ft);
	__p->tv_usec = (long) ((now.ns100 / 10LL) % SSH_USEC_IN_SEC);
	__p->tv_sec  = (long)(((now.ns100 / 10LL ) / SSH_USEC_IN_SEC) - SSH_SECONDS_SINCE_1601);

	return (0);
}
#endif

static int current_timestring(int hires, char *buf, size_t len)
{
    char tbuf[64];
    struct timeval tv;
    struct tm *tm;
    time_t t;

    gettimeofday(&tv, NULL);
    t = (time_t) tv.tv_sec;

    tm = localtime(&t);
    if (tm == NULL) {
        return -1;
    }

    if (hires) {
        strftime(tbuf, sizeof(tbuf) - 1, "%Y/%m/%d %H:%M:%S", tm);
        snprintf(buf, len, "%s.%06ld", tbuf, (long)tv.tv_usec);
    } else {
        strftime(tbuf, sizeof(tbuf) - 1, "%Y/%m/%d %H:%M:%S", tm);
        snprintf(buf, len, "%s", tbuf);
    }

    return 0;
}

int api_sftpfile_open(const char *username, const char *filename)
{
	int fp = -1;
	time_t t = time(NULL);
	struct tm *dt = localtime(&t);
	char dir[256];
	char tbuf[64];
	char sftpfile[1024];

	memset(dir, 0x00, sizeof(dir));
	memset(sftpfile, 0x00, sizeof(sftpfile));
	snprintf(dir, sizeof(dir) - 1, "%s/%4i/%.2i/%.2i/",
		log_path,
		dt->tm_year + 1900,
		dt->tm_mon + 1,
		dt->tm_mday);
	if(access(dir, F_OK) != 0) {
		if(createDir(dir) != 0) {
			trace_err("mkdir error: %s", dir);
		}
	}
	strftime(tbuf, sizeof(tbuf) - 1, "%H%M%S", dt);
	snprintf(sftpfile, sizeof(sftpfile) - 1, "%s/%s-%s-%s", dir, username, tbuf, filename);
	if((fp = open(sftpfile, O_RDWR|O_CREAT|O_APPEND
#ifndef _WIN32
		, S_IRUSR|S_IWUSR
#endif
		)) == -1) {
		fp = -1;
		trace_out("can not open file: %s", sftpfile);
	}
	return fp;
}

API_DECLARE(int) 
api_log(log_level_e level, const char *fmt, va_list args)
{
	int iRet = -1;
	int len = 0;
	FILE *out = NULL;
	FILE *fInfo = stdout;
	FILE *fError = stderr;
	char fmtbuf[1024] = {0};
	char msgbuf[4096] = {0};
	char *prefix = NULL;
	
	switch (level) {
		case LOG_LEVEL_FATAL:
			prefix = "fatal";
			out = fError;
			break;
		case LOG_LEVEL_ERROR:
			prefix = "error";
			out = fError;
			break;
		case LOG_LEVEL_INFO:
			prefix = "info";
			out = fInfo;
			break;
		case LOG_LEVEL_VERBOSE:
			prefix = "info";
			out = fInfo;
			break;
		case LOG_LEVEL_DEBUG1:
			prefix = "debug1";
			out = fInfo;
			break;
		case LOG_LEVEL_DEBUG2:
			prefix = "debug2";
			out = fInfo;
			break;
		case LOG_LEVEL_DEBUG3:
			prefix = "debug3";
			out = fInfo;
			break;
		default:
			prefix = "warn";
			out = fError;
			break;
	}
	memset(fmtbuf, 0x00, sizeof(fmtbuf));
	memset(msgbuf, 0x00, sizeof(msgbuf));
	if(level == LOG_LEVEL_INFO) {
		char ts[100];
		memset(ts, 0x00, sizeof(ts));
		current_timestring(1, ts, sizeof(ts));
		snprintf(fmtbuf, sizeof(fmtbuf), "[%s] %s", ts, fmt);
	} else {
		snprintf(fmtbuf, sizeof(fmtbuf), "%s: %s", prefix, fmt);
	}
	len = vsnprintf(msgbuf, sizeof(msgbuf) - 2, fmtbuf, args);
	if(len > 0) {
		char *p = msgbuf;
		while(len > 0)
	    {
			if(strchr(" \t\r\n", *(p + len - 1))) {
	            *(p + len - 1) = 0x00;
	            len--;
	        } else {
	            break;
	        }
	    }
	}
	iRet = fprintf(out, "%s\r\n", msgbuf);
	if(level == LOG_LEVEL_INFO)
	{
		if(log_fd_access == -1) {
			time_t t = time(NULL);
			struct tm *dt = localtime(&t);
			char dir[256];
			char logfile[1024];

			memset(dir, 0x00, sizeof(dir));
			memset(logfile, 0x00, sizeof(logfile));
			snprintf(dir, sizeof(dir) - 1, "%s/%4i/%.2i/%.2i/",
				log_path,
				dt->tm_year + 1900,
				dt->tm_mon + 1,
				dt->tm_mday);
			if(access(dir, F_OK) != 0) {
				if(createDir(dir) != 0) {
					trace_err("mkdir error: %s", dir);
				}
			}
			snprintf(logfile, sizeof(logfile) - 1, "%s/%s", dir, log_access);
			if((log_fd_access = open(logfile, O_RDWR|O_CREAT|O_APPEND
#ifndef _WIN32
				, S_IRUSR|S_IWUSR
#endif
				)) == -1) {
				log_fd_access = -1;
				trace_out("can not open file: %s", logfile);
			}
		}
		if(log_fd_access > 0) {
			strcat(msgbuf, "\r\n");
			iRet = write(log_fd_access, msgbuf, strlen(msgbuf));
		}
	}
	return iRet;
}


/*
if (common->log_indent > 255) {
      min = 255;
    } else {
      min = common->log_indent;
    }

    memset(indent, ' ', min);
    indent[min] = '\0';

*/

API_DECLARE(int) api_log_message(log_level_e level, const char *format, ...)
{
	int iRet = -1;
	va_list args;
	va_start(args, format);
	iRet = api_log(level, format, args);
	va_end(args);
	return iRet;
}

API_DECLARE(int) api_log_trace(log_level_e level, const char *filename, int line, const char *function, const char *fmt, ...)
{
	int iRet = -1;
	char tmpbuf[1024] = {0};
	char fmtbuf[1024] = {0};
	va_list args;
	
	iRet = snprintf(tmpbuf, sizeof(tmpbuf), fmt_trace, filename, line, function);
	if(iRet > 0) {
		tmpbuf[iRet] = 0x00;
	}
	va_start(args, fmt);
	iRet = snprintf(fmtbuf, sizeof(fmtbuf), "%s%s", tmpbuf, fmt);
	if(iRet > 0) {
		fmtbuf[iRet] = 0x00;
	}
	iRet = api_log(level, fmtbuf, args);
	va_end(args);
	
	return iRet;
}

API_DECLARE(void)
api_log_fatal(log_level_e level, const char *fmt,...)
{
	va_list args;
	va_start(args, fmt);
	api_log(level, fmt, args);
	va_end(args);
	exit(255);
}

API_DECLARE(void) api_log_assert(log_level_e level, int exp, const char *exps, const char *filename, int line, const char *function)
{
	if(!exp) {
		char fmtbuf[1024] = {0};
		snprintf(fmtbuf, sizeof(fmtbuf), "%s, (%s), abort.", fmt_trace, exps);
		api_log_message(level, fmtbuf, filename, line, function);
		abort();
	}
}


