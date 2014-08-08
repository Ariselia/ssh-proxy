#ifndef API_MISC_H
#define API_MISC_H

#include "api_log.h"
#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else 
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>


#ifdef __cplusplus
extern "C" {
#endif

//----------------< memory operation functions >----------------

#ifndef SAFE_FREE
/** Free memory space */
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)
#endif

#ifndef ZERO_STRUCT
/** Zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif

#ifndef ZERO_STRUCTP
/** Zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)
#endif

#ifndef ARRAY_SIZE
/** Get the size of an array */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);

#endif

#ifdef _WIN32
#ifndef snprintf
#define snprintf _snprintf
#endif
#endif

#ifndef HAVE_VASPRINTF
int vasprintf(char **, const char *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *, size_t, const char *, va_list);
#endif
#ifdef _WIN32
#define vsnprintf _vsnprintf
#endif

void *xmalloc(size_t);
void *xcalloc(size_t, size_t);
void *xrealloc(void *, size_t, size_t);
char *xstrdup(const char *);
int xasprintf(char **, const char *, ...);


//----------------< sockaddr operation functions >----------------

char * api_addr_from_sock(int sock);
int api_port_from_sock(int sock);

API_DECLARE(void) api_name_from_addr(struct sockaddr *sa, int salen, char **phost, int *pport);


#ifdef __cplusplus
}
#endif


#endif /* ! API_MISC_H */
