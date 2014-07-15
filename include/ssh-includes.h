#ifndef SSH_PROXY_INCLUDES_H
#define SSH_PROXY_INCLUDES_H

#ifdef _WIN32
#include "ssh/ssh-config-win32.h"
#else
#include "ssh/ssh-config-linux.h"
#endif

#include "api_log.h"

#endif /* ! SSH_PROXY_INCLUDES_H */

