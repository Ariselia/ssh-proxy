#ifndef SSH_STRING_H
#define SSH_STRING_H

#include "ssh/priv.h"

/* must be 32 bits number + immediately our data */
#ifdef _MSC_VER
#pragma pack(1)
#endif
struct ssh_string_struct {
	uint32_t size;
	unsigned char data[1];
}
#if defined(__GNUC__)
__attribute__ ((packed))
#endif
#ifdef _MSC_VER
#pragma pack()
#endif
;

#endif /* ! SSH_STRING_H */
