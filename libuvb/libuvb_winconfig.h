#pragma once

// Define the earliest version of Windows we support.  These control
// what parts of the Windows API are available. The available constants
// are in <sdkddkver.h>.
// http://msdn.microsoft.com/en-us/library/aa383745.aspx
// http://blogs.msdn.com/oldnewthing/archive/2007/04/11/2079137.aspx */
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7
#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7

// This disables the warning 4800 http://msdn.microsoft.com/en-us/library/b6801kcy(v=vs.71).aspx
#pragma warning(disable : 4800)
// It doesn't really have struct IP, but we use a different one instead
// of the one that comes with LibUVB
#define HAVE_STRUCT_IP 1
// #define HAVE_STRUCT_ICMP 1 */
#define HAVE_STRNCASECMP 1
#define HAVE_IP_IP_SUM 1
#define STDC_HEADERS 1
#define HAVE_STRING_H 1
#define HAVE_MEMORY_H 1
#define HAVE_FCNTL_H 1
#define HAVE_ERRNO_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_MEMCPY 1
#define HAVE_STRERROR 1
// #define HAVE_SYS_SOCKIO_H 1
// #undef HAVE_TERMIOS_H
#define HAVE_ERRNO_H 1
#define HAVE_GAI_STRERROR 1
// #define HAVE_STRCASESTR 1
#define HAVE_STRCASECMP 1
#define HAVE_NETINET_IF_ETHER_H 1
#define HAVE_SYS_STAT_H 1
// #define HAVE_INTTYPES_H

// These functions are available on Vista and later
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= _WIN32_WINNT_WIN6
#define HAVE_INET_PTON 1
#define HAVE_INET_NTOP 1
#endif

#ifdef _MSC_VER
// <wspiapi.h> only comes with Visual Studio.
#define HAVE_WSPIAPI_H 1
#else
#undef HAVE_WSPIAPI_H
#endif

#define HAVE_GETADDRINFO 1
#define HAVE_GETNAMEINFO 1

#define HAVE_SNPRINTF 1
// #undef HAVE_VASPRINTF
#define HAVE_VSNPRINTF 1

typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
typedef signed __int8 int8_t;
typedef signed __int16 int16_t;
typedef signed __int32 int32_t;
typedef signed __int64 int64_t;

#define HAVE_IPV6 1
#define HAVE_AF_INET6 1
#define HAVE_SOCKADDR_STORAGE 1

// Without these, Windows will give us all sorts of crap about using functions
// like strcpy() even if they are done safely */
#define _CRT_SECURE_NO_DEPRECATE 1
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 1
#endif
#pragma warning(disable: 4996)

#ifdef __GNUC__
#define bzero(addr, num) __builtin_memset (addr, '\0', num)
#else
#define __attribute__(x)
#endif

// Apparently __func__ isn't yet supported
#define __func__ __FUNCTION__







































