#include "api_misc.h"

#define SIZE_T_MAX (sizeof(size_t)-1)

#ifndef HAVE_STRLCPY

#include <sys/types.h>
#include <string.h>

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}

#endif /* !HAVE_STRLCPY */

void * xmalloc(size_t size)
{
	void *ptr = NULL;

	if (size == 0)
		trace_err("xmalloc: zero size");
	ptr = malloc(size);
	if (ptr == NULL)
		trace_err("xmalloc: out of memory (allocating %zu bytes)", size);
	return ptr;
}

void * xcalloc(size_t nmemb, size_t size)
{
	void *ptr = NULL;

	if (size == 0 || nmemb == 0)
		trace_err("xcalloc: zero size");
	if (SIZE_T_MAX / nmemb < size)
		trace_err("xcalloc: nmemb * size > SIZE_T_MAX");
	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		trace_err("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	return ptr;
}

void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr = NULL;
	size_t new_size = nmemb * size;

	if (new_size == 0)
		trace_err("xrealloc: zero size");
	if (SIZE_T_MAX / nmemb < size)
		trace_err("xrealloc: nmemb * size > SIZE_T_MAX");
	if (ptr == NULL)
		new_ptr = malloc(new_size);
	else
		new_ptr = realloc(ptr, new_size);
	if (new_ptr == NULL)
		trace_err("xrealloc: out of memory (new_size %zu bytes)",
		    new_size);
	return new_ptr;
}

char *
xstrdup(const char *str)
{
	size_t len;
	char *cp = NULL;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	strlcpy(cp, str, len);
	return cp;
}

int
xasprintf(char **ret, const char *fmt, ...)
{
	va_list ap;
	int i;

	va_start(ap, fmt);
	i = vasprintf(ret, fmt, ap);
	va_end(ap);

	if (i < 0 || *ret == NULL) {
		trace_err("xasprintf: could not allocate memory");
	}
	return (i);
}
#ifdef _WIN32
#ifndef HAVE_VASPRINTF

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>

#ifndef VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# else
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  else
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#define INIT_SZ	128

int
vasprintf(char **str, const char *fmt, va_list ap)
{
	int ret = -1;
	va_list ap2;
	char *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	if ((string = malloc(INIT_SZ)) == NULL)
		goto fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	if (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} else if (ret == INT_MAX || ret < 0) { /* Bad length */
		free(string);
		goto fail;
	} else {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		if ((newstr = realloc(string, len)) == NULL) {
			free(string);
			goto fail;
		} else {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			if (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} else { /* failed with realloc'ed string, give up */
				free(newstr);
				goto fail;
			}
		}
	}
	va_end(ap2);
	return (ret);

fail:
	*str = NULL;
	errno = ENOMEM;
	va_end(ap2);
	return (-1);
}
#endif
#endif

//----------------< sockaddr operation functions >----------------

static char *
get_socket_address(int sock, int remote, int flags)
{
	struct sockaddr_in addr;
	socklen_t addrlen;
	char ntop[NI_MAXHOST];
	int r;

	/* Get IP address of client. */
	addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));

	if (remote) {
		if (getpeername(sock, (struct sockaddr *)&addr, &addrlen)
		    < 0)
			return NULL;
	} else {
		if (getsockname(sock, (struct sockaddr *)&addr, &addrlen)
		    < 0)
			return NULL;
	}

	//ipv4_normalise_mapped(&addr, &addrlen);

	/* Get the address in ascii. */
	if ((r = getnameinfo((struct sockaddr *)&addr, addrlen, ntop,
	    sizeof(ntop), NULL, 0, flags)) != 0) {
		return NULL;
	}
	return xstrdup(ntop);
}

char * get_peer_ipaddr(int sock)
{
	char *p;

	if ((p = get_socket_address(sock, 1, NI_NUMERICHOST|NI_NUMERICSERV)) != NULL) {
		return p;
	}
	return xstrdup("UNKNOWN");
}

char * get_local_ipaddr(int sock)
{
	char *p;

	if ((p = get_socket_address(sock, 0, NI_NUMERICHOST|NI_NUMERICSERV)) != NULL)
		return p;
	return xstrdup("UNKNOWN");
}

int get_sock_port(int sock, int local)
{
	struct sockaddr_in from;
	socklen_t fromlen;
	char strport[NI_MAXSERV];
	int r;

	/* Get IP address of client. */
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	if (local) {
		if (getsockname(sock, (struct sockaddr *)&from, &fromlen) < 0) {
			trace_err("getsockname failed: %.100s", strerror(errno));
			return 0;
		}
	} else {
		if (getpeername(sock, (struct sockaddr *)&from, &fromlen) < 0) {
			trace_err("getpeername failed: %.100s", strerror(errno));
			return -1;
		}
	}

	/* Return port number. */
	if ((r = getnameinfo((struct sockaddr *)&from, fromlen, NULL, 0,
	    strport, sizeof(strport), NI_NUMERICSERV)) != 0)
		trace_err("get_sock_port: getnameinfo NI_NUMERICSERV failed: %d",
		    r);
	return atoi(strport);
}

int 
api_port_from_sock(int sock)
{
	return get_sock_port(sock, 1);
}

char *
api_addr_from_sock(int sock)
{
	char *host = NULL, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	if ((host = get_socket_address(sock, 0, NI_NAMEREQD)) != NULL) {
		return host;
	}
	/* Handle the case where we were passed a pipe */
	if (gethostname(myname, sizeof(myname)) == -1) {
		//verbose("get_local_name: gethostname: %s", strerror(errno));
	} else {
		host = xstrdup(myname);
	}
	
	return host;
}

#ifndef AIO_HAVE_GETNAMEINFO
#define NI_MAXSERV 32
#define NI_MAXHOST 1025

#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST 1
#endif

#ifndef NI_NUMERICSERV
#define NI_NUMERICSERV 2
#endif

static int
fake_getnameinfo(const struct sockaddr *sa, size_t salen, char *host,
	size_t hostlen, char *serv, size_t servlen, int flags)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	if (serv != NULL) {
		char tmpserv[16];
		snprintf(tmpserv, sizeof(tmpserv),
		    "%d", ntohs(sin->sin_port));
		if (strlcpy(serv, tmpserv, servlen) >= servlen)
			return (-1);
	}

	if (host != NULL) {
		if (flags & NI_NUMERICHOST) {
			if (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				return (-1);
			else
				return (0);
		} else {
			struct hostent *hp;
			hp = gethostbyaddr((char *)&sin->sin_addr,
			    sizeof(struct in_addr), AF_INET);
			if (hp == NULL)
				return (-2);

			if (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				return (-1);
			else
				return (0);
		}
	}
	return (0);
}

#endif

API_DECLARE(void) api_name_from_addr(struct sockaddr *sa, int salen, char **phost, int *pport)
{
	char ntop[NI_MAXHOST];
	char strport[NI_MAXSERV];
	int ni_result;

#ifdef AIO_HAVE_GETNAMEINFO
	ni_result = getnameinfo(sa, salen,
		ntop, sizeof(ntop), strport, sizeof(strport),
		NI_NUMERICHOST|NI_NUMERICSERV);

	if (ni_result != 0) {
#ifdef EAI_SYSTEM
		/* Windows doesn't have an EAI_SYSTEM. */
		if (ni_result == EAI_SYSTEM)
			do_log_err("getnameinfo failed");
		else
#endif
			do_log_err("getnameinfo failed");
		return;
	}
#else
	ni_result = fake_getnameinfo(sa, salen,
		ntop, sizeof(ntop), strport, sizeof(strport),
		NI_NUMERICHOST|NI_NUMERICSERV);
	if (ni_result != 0)
			return;
#endif

	*phost = xstrdup(ntop);
	*pport = atoi(strport);
}

