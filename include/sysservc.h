#ifndef __SYSSERVC_H__
#define __SYSSERVC_H__

#if defined(_ALIGN_)
#pragma pack(push, _svc_align, 1)
#endif

#include "error.h"

/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 * Mutex implementation
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
#ifdef UNIX_IMPL
#include <pthread.h>
typedef pthread_mutex_t*	NH_MUTEX;
#else
typedef HANDLE			NH_MUTEX;
#endif
typedef struct NH_MUTEX_HANDLE_STR	NH_MUTEX_HANDLE_STR;

/*
 ****f* NH_MUTEX_HANDLE/lock
 *
 * NAME
 *	lock
 *
 * PURPOSE
 *	Acquires the mutex.
 *
 * ARGUMENTS
 *	NH_MUTEX_HANDLE self: the mutex handle
 *
 * RESULT
 *	NH_INVALID_ARG on handle NULL.
 *	NH_CANNOT_LOCK on mutex acquire error. Use G_SYSERROR() to get OS error code.
 *
 * SEE ALSO
 *	NH_create_mutex
 *
 ******
 *
 */
/*
 ****f* NH_MUTEX_HANDLE/unlock
 *
 * NAME
 *	unlock
 *
 * PURPOSE
 *	Releases the mutex lock
 *
 * ARGUMENTS
 *	NH_MUTEX_HANDLE self: the mutex handle
 *
 * RESULT
 *	NH_INVALID_ARG on handle NULL.
 *	NH_CANNOT_UNLOCK on mutex release error. Use G_SYSERROR() to get OS error code.
 *
 * SEE ALSO
 *	NH_create_mutex
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_MUTEX_FUNCTION)(_IN_ NH_MUTEX_HANDLE_STR*);

/*
 ****s* Nharu/NH_MUTEX_HANDLE
 *
 * NAME
 *	NH_MUTEX_HANDLE
 *
 * PURPOSE
 *	Handler to mutex objects
 *
 * SYNOPSIS
 */
struct NH_MUTEX_HANDLE_STR
{
	NH_MUTEX				mutex;	/* System mutex object */
	NH_MUTEX_FUNCTION			lock;		/* Acquires mutex object */
	NH_MUTEX_FUNCTION			unlock;	/* Releases mutex object */
};
typedef NH_MUTEX_HANDLE_STR*		NH_MUTEX_HANDLE;
/*
 ******* */


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 * Memory container implementation
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
/*
 ****f* Nharu/NH_CRYPTOZEROIZE_FUNCTION
 *
 * NAME
 *	NH_CRYPTOZEROIZE_FUNCTION
 *
 * PURPOSE
 *	Perform cryptographic zeroization callback.
 *
 * ARGUMENTS
 *	_INOUT_ void *buffer: memory segment.
 *	_IN_ size_t size: buffer size.
 *
 ******
 *
 */
typedef NH_CALLBACK(void, NH_CRYPTOZEROIZE_FUNCTION)(_INOUT_ void*, _IN_ size_t);

typedef struct NH_FREIGHT_CAR_STR
{
	void*					buffer;	/* Memory wagon */
	size_t				size;		/* Size of buffer */
	void*					available;	/* Next available position in buffer */
	size_t				remaining;	/* Size of available */
	struct NH_FREIGHT_CAR_STR*	next;		/* Next memory wagon */

} NH_FREIGHT_CAR;
typedef struct NH_CARGO_CONTAINER_STR	NH_CARGO_CONTAINER_STR;


/*
 ****f* NH_CARGO_CONTAINER/bite_chunk
 *
 * NAME
 *	bite_chunk
 *
 * PURPOSE
 *	Get a memory segment.
 *
 * ARGUMENTS
 *	_INOUT_ NH_CARGO_CONTAINER_STR* self: memory container handle.
 *	_IN_ size_t size: segment size.
 *	_OUT_ void **ret: pointer to segment.
 *
 * RESULT
 *	NH_MUTEX_HANDLE->lock() results.
 *
 * SEE ALSO
 *	NH_MUTEX_HANDLE->lock
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CARGO_FUNCTION)(_INOUT_ NH_CARGO_CONTAINER_STR*, _IN_ size_t, _OUT_ void**);

/*
 ****f* NH_CARGO_CONTAINER/grow_chunk
 *
 * NAME
 *	grow_chunk
 *
 * PURPOSE
 *	Increments specified memory segment
 *
 * ARGUMENTS
 *	_INOUT_ NH_CARGO_CONTAINER_STR* self: memory container handle.
 *	_INOUT_ void **old: old segment
 *	_IN_ size_t oldsize: old segment size
 *	_IN_ size_t newsize: new segment size.
 *
 * RESULT
 *	NH_MUTEX_HANDLE->lock() results.
 *
 * SEE ALSO
 *	NH_MUTEX_HANDLE->lock
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_GROW_FUNCTION)(_INOUT_ NH_CARGO_CONTAINER_STR*, _INOUT_ void**, _IN_ size_t, _IN_ size_t);

/*
 ****f* NH_CARGO_CONTAINER/zeroize
 *
 * NAME
 *	zeroize
 *
 * PURPOSE
 *	Perform cryptographic zeroization of memory container
 *
 * ARGUMENTS
 *	_INOUT_ NH_CARGO_CONTAINER_STR* self: memory container handle.
 *	_IN_ NH_CRYPTOZEROIZE_FUNCTION method: cryptographic zeroization callback function.
 *
 * SEE ALSO
 *	NH_CRYPTOZEROIZE_FUNCTION
 *
 * NOTES
 *
 *
 ******
 *
 */
typedef NH_METHOD(void, NH_ZEROIZE_FUNCTION)(_INOUT_ NH_CARGO_CONTAINER_STR*, _IN_ NH_CRYPTOZEROIZE_FUNCTION);


/*
 ****s* Nharu/NH_CARGO_CONTAINER
 *
 * NAME
 *	NH_CARGO_CONTAINER
 *
 * PURPOSE
 *	Handler to memory containers
 *
 * SYNOPSIS
 */
struct NH_CARGO_CONTAINER_STR
{
	NH_MUTEX_HANDLE			hMutex;	/* Mutex handle */
	NH_FREIGHT_CAR*			first;	/* First memory weagon */
	NH_FREIGHT_CAR*			current;	/* Current memory wagon */

	NH_CARGO_FUNCTION			bite_chunk;	/* Gets a segment of wagon */
	NH_ZEROIZE_FUNCTION		zeroize;	/* Cryptographic zeroization function */
	NH_GROW_FUNCTION			grow_chunk;	/* Increments specified memory segment */
};
typedef NH_CARGO_CONTAINER_STR*	NH_CARGO_CONTAINER;
/*
 ******* */


#if defined(__cplusplus)
extern "C" {
#endif

/*
 ****f* Nharu/NH_create_mutex
 *
 * NAME
 *	NH_create_mutex
 *
 * PURPOSE
 *	Create a new mutex.
 *
 * ARGUMENTS
 *	_OUT_ NH_MUTEX_HANDLE* hHandle: the mutex handle.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR on out of memory.
 *	NH_CANNOT_CREATE_MUTEX on mutex creation error. Use G_SYSERROR() to get OS error code.
 *
 * SEE ALSO
 *	NH_release_mutex().
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_create_mutex)(_OUT_ NH_MUTEX_HANDLE*);

/*
 ****f* Nharu/NH_release_mutex
 *
 * NAME
 *	NH_release_mutex
 *
 * PURPOSE
 *	Releases mutex handle.
 *
 * ARGUMENTS
 *	IN_ NH_MUTEX_HANDLE hHndle: mutex handle.
 *
 * RESULT
 *	NH_INVALID_ARG on hHandle NULL.
 *	NH_CANNOT_RELEASE_MUTEX on mutex release error. Use G_SYSERROR() to get OS error code.
 *
 * SEE ALSO
 *	NH_create_mutex()
 *
 * NOTES
 *	Under Unix systems link to libpthread.so
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_release_mutex)(_IN_ NH_MUTEX_HANDLE);


/*
 ****f* Nharu/NH_freight_container
 *
 * NAME
 *	NH_freight_container
 *
 * PURPOSE
 *	Allocs a memory container
 *
 * ARGUMENTS
 *	_IN_ size_t chunk: size of memory wagon.
 *	_OUT_ NH_CARGO_CONTAINER *hHandle: handle to container.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR if out of memory.
 *	Possible fail returns of NH_create_mutex().
 *
 * SEE ALSO
 *	NH_create_mutex
 *	NH_release_container
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_freight_container)(_IN_ size_t, _OUT_ NH_CARGO_CONTAINER*);

/*
 ****f* Nharu/NH_release_container
 *
 * NAME
 *	NH_release_container
 *
 * PURPOSE
 *	Releases a memory container
 *
 * ARGUMENTS
 *	_IN_ NH_CARGO_CONTAINER hHandle: memory handle.
 *
 * RESULT
 *	NH_release_mutex() function returns.
 *
 * SEE ALSO
 *	NH_release_mutex
 *	NH_freight_container
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_release_container)(_IN_ NH_CARGO_CONTAINER);

/*
 ****f* Nharu/NH_swap
 *
 * NAME
 *	NH_swap
 *
 * PURPOSE
 *	Changes the endian of an array of bytes.
 *
 * ARGUMENTS
 *	_INOUT_ unsigned char *value: the value to change the endian
 *	_IN_ size_t size: size of value.
 *
 ******
 *
 */
NH_FUNCTION(void, NH_swap)(_INOUT_ unsigned char*, _IN_ size_t);


#if defined(__cplusplus)
}
#endif


/*
 ****d* Nharu/GUARD
 *
 * NAME
 *	GUARD
 *
 * PURPOSE
 *	Ensure that only one thread executes a block of code.
 *
 * ARGUMENTS
 *	_IN_ NH_MUTEX_HANDLE _hMut:  mutex handle.
 *	_OUT_ NH_RV _mrv: mutex handle return value.
 *	_block: the block to be guarded.
 *
 ******
 *
 */
#define GUARD(_hMut, _mrv, _block)		if (NH_SUCCESS((_mrv = _hMut->lock(_hMut)))) { _block; _mrv = _hMut->unlock(_hMut); }


#if defined(_ALIGN_)
#pragma pack(pop, _svc_align)
#endif

#endif /* __SYSSERVC_H__ */
