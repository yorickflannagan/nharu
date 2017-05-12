/** **********************************************************
 ****h* Nharu library
 *  **********************************************************
 * NAME
 *	Nharu Library
 *
 * AUTHOR
 *	Copyleft (C) 2015 by The Crypthing Initiative
 *
 * PURPOSE
 *	Enhanced X.509 parser
 *
 * COMMANDS
 * 	Make arguments (set by -D):
 *	_DEBUG_: flag for DEBUG (naturally)
 *	_ALIGN_: if set use pragma pack for low memory environments
 *
 * NOTES
 *	This library implements Cryptoki 2.20 data types (but not PKCS #11 exported functions)
 *	Third party pieces of software:
 *		Cryptographic primitives implementation by OpenSSl 1.0.1 at www.openssl.org
 *		Shamir scheme implementation for secret sharing (libgfshare) by Daniel Silverstone <dsilvers@digital-scurf.org>
 *
 ******
 *
 *  ***********************************************************
 */
#ifndef __BASE_H__
#define __BASE_H__

#include "cryptoki.h"

#ifdef _MSC_VER
#pragma warning(disable : 4996)	/* Do not care Microsoft's deprecations... */
#endif

/* Supported OS: Linux, Windows and Solaris */
#if (defined(__APPLE__) || defined(linux) || defined(__linux) || defined(__linux__) || defined(__gnu_linux))
#define NH_LINUX_IMPL
#elif (defined(_WIN32) || defined(_WIN64))
#define NH_WINDOWS_IMPL
#elif (defined(sun) || defined(__sun) || defined(__SVR4))
#define NH_SOLARIS_IMPL
#endif
#if defined(NH_LINUX_IMPL) || defined(NH_SOLARIS_IMPL)
#define UNIX_IMPL				1
#define _GNU_SOURCE			1
#include <unistd.h>
#define STDC_VERSION			_POSIX_VERSION
#endif

/* Windows SDK requirement */
#ifdef NH_WINDOWS_IMPL
#include <windows.h>
#define STDC_VERSION			200809L			/* MS Visual Studio is always updated... */
#endif

/* Supported compilers: GCC and Microsoft Visual C */
#if defined(__GNUC__)
#define _IN_				const
#define _OUT_
#define _INOUT_
#define _CONSTRUCTOR_			__attribute__((constructor))
#define _DESTRUCTOR_			__attribute__((destructor))
#define _UNUSED_				__attribute__((unused))
#define NH_EXPORT
#define NH_HIDDEN				__attribute__((__visibility__("internal")))
#define NH_EXTERNAL
#if defined(__x86_64__)
#define NH_CALL_SPEC
#else
#define NH_CALL_SPEC			__attribute__((cdecl))
#endif
#define INLINE				__inline__
#define _NOP_				__asm__("nop")
#elif defined(_MSC_VER)
#include <sal.h>
#define _IN_				_In_ const
#define _OUT_				_Out_
#define _INOUT_				_Inout_
#define _CONSTRUCTOR_
#define _DESTRUCTOR_
#define _UNUSED_
#define NH_EXPORT				__declspec(dllexport)
#define NH_HIDDEN
#define NH_EXTERNAL			extern
#if !defined(_WIN64)
#define NH_CALL_SPEC			__cdecl
#else
#define NH_CALL_SPEC
#endif
#define INLINE				__inline
#define _NOP_				__asm nop
#else
#define _IN_
#define _OUT_
#define _INOUT_
#define NH_EXPORT
#define NH_HIDDEN
#define NH_EXTERNAL
#define NH_CALL_SPEC
#define INLINE
#define _NOP_
#endif
#define NH_FUNCTION(type, name)	NH_EXTERNAL type NH_EXPORT NH_CALL_SPEC name	/* Exportend functions */
#define NH_UTILITY(type, name)	NH_HIDDEN type NH_CALL_SPEC name			/* Internal functions */
#define NH_METHOD(type, name)		type (NH_CALL_SPEC *name)				/* Struct member fnctions */
#define NH_CALLBACK(type, name)	NH_METHOD(type, name)					/* Callback functions */

#ifndef NULL
#if defined(__cplusplus)
#if (__cplusplus >= 201100L)
#define NULL				null_ptr
#else
#define NULL				((void *) 0)
#endif
#else
#define NULL				0
#endif
#endif
#ifdef TRUE
#undef TRUE
#endif
#define TRUE				0xFF
#ifndef FALSE
#define FALSE				0x00
#endif
typedef CK_RV				NH_RV;
#include <time.h>
typedef struct tm				NH_TIME;
typedef NH_TIME*				NH_PTIME;
typedef struct NH_BLOB
{
	unsigned char*		data;
	size_t			length;

} NH_BLOB, NH_BIG_INTEGER, NH_UTF8CHAR, NH_SYMKEY, NH_IV;

#if defined(__cplusplus)
#define EXTERN				extern "C"
#else
#define EXTERN				extern
#endif


#endif /* BASE_H */
