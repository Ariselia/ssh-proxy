#ifndef API_H
#define API_H

#if defined _WIN32 || defined __CYGWIN__
  #ifdef API_STATIC
    #define API
  #else
    #ifdef API_EXPORTS
      #ifdef __GNUC__
        #define API __attribute__((dllexport))
      #else
        #define API __declspec(dllexport)
		#define API_DECLARE_EXPORT
      #endif
    #else
      #ifdef __GNUC__
        #define API __attribute__((dllimport))
      #else
        #define API __declspec(dllimport)
      #endif
    #endif
  #endif
#else
  #if __GNUC__ >= 4 && !defined(__OS2__)
    #define API __attribute__((visibility("default")))
  #else
    #define API
  #endif
#endif


#ifdef __cplusplus
extern "C" {
#endif

#if defined(DOXYGEN) || !defined(WIN32)

/**
 * The public API functions are declared with API_DECLARE(), so they may
 * use the most appropriate calling convention.  Public API functions with 
 * variable arguments must use API_DECLARE_NONSTD().
 *
 * @remark Both the declaration and implementations must use the same macro.
 *
 * <PRE>
 * API_DECLARE(rettype) api_func(args)
 * </PRE>
 * @see API_DECLARE_NONSTD @see API_DECLARE_DATA
 * @remark Note that when API compiles the library itself, it passes the 
 * symbol -DAPI_DECLARE_EXPORT to the compiler on some platforms (e.g. Win32) 
 * to export public symbols from the dynamic library build.\n
 * The user must define the API_DECLARE_STATIC when compiling to target
 * the static API library on some platforms (e.g. Win32.)  The public symbols 
 * are neither exported nor imported when API_DECLARE_STATIC is defined.\n
 * By default, compiling an application and including the API public
 * headers, without defining API_DECLARE_STATIC, will prepare the code to be
 * linked to the dynamic library.
 */
#define API_DECLARE(type)            type 

/**
 * The public API functions using variable arguments are declared with 
 * API_DECLARE_NONSTD(), as they must follow the C language calling convention.
 * @see API_DECLARE @see API_DECLARE_DATA
 * @remark Both the declaration and implementations must use the same macro.
 * <PRE>
 *
 * API_DECLARE_NONSTD(rettype) api_func(args, ...);
 *
 * </PRE>
 */
#define API_DECLARE_NONSTD(type)     type

/**
 * The public API variables are declared with API_DECLARE_DATA.
 * This assures the appropriate indirection is invoked at compile time.
 * @see API_DECLARE @see API_DECLARE_NONSTD
 * @remark Note that the declaration and implementations use different forms,
 * but both must include the macro.
 * 
 * <PRE>
 *
 * extern API_DECLARE_DATA type api_variable;\n
 * API_DECLARE_DATA type api_variable = value;
 *
 * </PRE>
 */
#define API_DECLARE_DATA

#elif defined(API_DECLARE_STATIC)
#define API_DECLARE(type)            type __stdcall
#define API_DECLARE_NONSTD(type)     type __cdecl
#define API_DECLARE_DATA
#elif defined(API_DECLARE_EXPORT)
#define API_DECLARE(type)            __declspec(dllexport) type __stdcall
#define API_DECLARE_NONSTD(type)     __declspec(dllexport) type __cdecl
#define API_DECLARE_DATA             __declspec(dllexport)
#else
#define API_DECLARE(type)            __declspec(dllimport) type __stdcall
#define API_DECLARE_NONSTD(type)     __declspec(dllimport) type __cdecl
#define API_DECLARE_DATA             __declspec(dllimport)
#endif


#ifdef _MSC_VER
  /* Visual Studio hasn't inttypes.h so it doesn't know uint32_t */
  typedef signed   char      int8_t;
  typedef unsigned char      uint8_t;
  typedef short    int       int16_t;
  typedef unsigned short     uint16_t;
  typedef int                int32_t;
  typedef unsigned int       uint32_t;
  typedef unsigned long long uint64_t;
  typedef int mode_t;
#else /* _MSC_VER */
  #include <unistd.h>
  #include <inttypes.h>
#endif /* _MSC_VER */

#ifdef _WIN32
  #include <winsock2.h>
#else /* _WIN32 */
 #include <sys/select.h> /* for fd_set * */
 #include <netdb.h>
#endif /* _WIN32 */

#define API_STRINGIFY(s) SSH_TOSTRING(s)
#define API_TOSTRING(s) #s

#ifdef HAVE_CONFIG_H
#include "config.h"
#define HAVE_LIBCRYPTO 1
#endif

#ifdef __cplusplus
}
#endif


#endif /* ! API_H */
