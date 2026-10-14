#pragma once

#include "libuvb_winconfig.h"

// Winsock defines its own error codes that are analogous to but
// different from those in <errno.h>. The error macros have similar
// names, for example
// EINTR -> WSAEINTR
// ECONNREFUSED -> WSAECONNREFUSED
// But the values are different. The errno codes are small integers,
// while the Winsock codes start at 10000 or so.
// http://msdn.microsoft.com/en-us/library/ms737828

// Later in this file there is a block of code that defines the errno
// names to their Winsock equivalents, so that you can write code using
// the errno names only, and have it still work on Windows. However this
// causes some problems that are worked around in the following few
// lines. First, we prohibit the inclusion of <errno.h>, so that the
// only error codes visible are those we explicitly define in this file.
// This will cause a compilation error if someone uses a code we're not
// yet aware of instead of using an incompatible value at runtime.
// Second, because <errno.h> is not defined, the C++0x header
// <system_error> doesn't compile, so we pretend not to have C++0x to
// avoid it. */
#if _MSC_VER < 1600 // Breaks on VS2010 and later
#define _INC_ERRNO  // suppress errno.h
#define _ERRNO_H_ // Also for errno.h suppression
#define _SYSTEM_ERROR_
#undef _HAS_CPP0X
#define _HAS_CPP0X 0
#else
// VS2013: we include errno.h, then redefine the constants we want.
// This may work in other versions, but haven't tested (since the other method
// has been working just fine).
#include <errno.h>
#endif

// Suppress winsock.h
#define _WINSOCKAPI_
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> // IPv6 stuff
#if HAVE_WSPIAPI_H
// <wspiapi.h> is necessary for getaddrinfo before Windows XP, but it isn't
// available on some platforms like MinGW
#include <wspiapi.h>
#endif
#include <time.h>
#include <iptypes.h>
#include <stdlib.h>
#include <malloc.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <process.h>
#include <limits.h>
#include <WINCRYPT.H>
#include <math.h>


#define SIOCGIFCONF 0x8912 // get iface list

#ifndef GLOBALS
#define GLOBALS 1

#endif

#define munmap(ptr, len) win32_munmap(ptr, len)

// Windows error message names
#undef  ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#undef ECONNRESET
#define ECONNRESET WSAECONNRESET
#undef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#undef  EAGAIN
#define EAGAIN WSAEWOULDBLOCK
#undef EWOULDBLOCK
#define EWOULDBLOCK	WSAEWOULDBLOCK
#undef EHOSTUNREACH
#define EHOSTUNREACH WSAEHOSTUNREACH
#undef ENETDOWN
#define ENETDOWN WSAENETDOWN
#undef ENETUNREACH
#define ENETUNREACH	WSAENETUNREACH
#undef ENETRESET
#define ENETRESET WSAENETRESET
#undef ETIMEDOUT
#define ETIMEDOUT WSAETIMEDOUT
#undef EHOSTDOWN
#define EHOSTDOWN WSAEHOSTDOWN
#undef EINPROGRESS
#define EINPROGRESS	WSAEINPROGRESS
#undef  EINVAL
#define EINVAL WSAEINVAL // Invalid argument
#undef  EPERM
#define EPERM WSAEACCES // Operation not permitted
#undef  EACCES
#define EACCES WSAEACCES // Operation not permitted
#undef  EINTR
#define EINTR WSAEINTR // Interrupted system call
#undef ENOBUFS
#define ENOBUFS WSAENOBUFS // No buffer space available
#undef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE // Message too long
#undef  ENOMEM
#define ENOMEM WSAENOBUFS
#undef  ENOTSOCK
#define ENOTSOCK WSAENOTSOCK
#undef  EOPNOTSUPP
#define EOPNOTSUPP WSAEOPNOTSUPP
#undef  EIO
#define EIO WSASYSCALLFAILURE
#undef  ENOTCONN
#define ENOTCONN WSAENOTCONN

// This is not used by our network code, and causes problems in programs using
// Nbase that legitimately use ENOENT for file operations.
// #undef  ENOENT
// #define ENOENT WSAENOENT

#define close(x) closesocket(x)

typedef unsigned short u_short_t;

#ifdef __cplusplus
extern "C" {
#endif

int win_stdin_start_thread(void);

#ifdef __cplusplus
}
#endif




































