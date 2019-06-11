#include "sysservc.h"
#include <string.h>
#include <stdlib.h>


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 * Mutex implementation
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
NH_UTILITY(NH_RV, NH_mutex_lock)(_IN_ NH_MUTEX_HANDLE_STR* self)
{
	NH_RV rv = NH_OK;
	NH_SYSRV ret = 0;

	if (!self || !self->mutex) return NH_INVALID_ARG;

#ifdef UNIX_IMPL

	if ((ret = pthread_mutex_lock(self->mutex))) rv = S_SYSERROR(ret) | NH_CANNOT_LOCK;

#else

	if ((ret = WaitForSingleObject(self->mutex, INFINITE)) != WAIT_OBJECT_0)
	{
		if (ret == WAIT_ABANDONED) rv = S_SYSERROR(ret) | NH_CANNOT_LOCK;
		else rv = S_SYSERROR(GetLastError()) | NH_CANNOT_LOCK;
	}

#endif
	return rv;
}

NH_UTILITY(NH_RV, NH_mutex_unlock)(_IN_ NH_MUTEX_HANDLE_STR* self)
{
	NH_RV rv = NH_OK;
#ifdef UNIX_IMPL
	NH_SYSRV ret = 0;
#endif

	if (!self || !self->mutex) return NH_INVALID_ARG;

#ifdef UNIX_IMPL

	if ((ret = pthread_mutex_unlock(self->mutex))) rv = S_SYSERROR(ret) | NH_CANNOT_UNLOCK;

#else

	if (!(ReleaseMutex(self->mutex))) rv = S_SYSERROR(GetLastError()) | NH_CANNOT_UNLOCK;

#endif
	return rv;
}

static NH_MUTEX_HANDLE_STR defMutexHandler =
{
	NULL,
	NH_mutex_lock,
	NH_mutex_unlock
};

NH_FUNCTION(NH_RV, NH_create_mutex)(_OUT_ NH_MUTEX_HANDLE *hHandle)
{
	NH_MUTEX_HANDLE handle;
	NH_RV rv = NH_OK;
#ifdef UNIX_IMPL
	NH_SYSRV ret = 0;
#endif

	if (!(handle = (NH_MUTEX_HANDLE) malloc(sizeof(NH_MUTEX_HANDLE_STR)))) return NH_OUT_OF_MEMORY_ERROR;
	memcpy(handle, &defMutexHandler, sizeof(NH_MUTEX_HANDLE_STR));

#ifdef UNIX_IMPL

	if (!(handle->mutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t)))) rv = NH_OUT_OF_MEMORY_ERROR;
	else if ((ret = pthread_mutex_init(handle->mutex, NULL))) rv = S_SYSERROR(ret) | NH_CANNOT_CREATE_MUTEX;

#else

	if (!(handle->mutex = CreateMutex(NULL, FALSE, NULL))) rv = S_SYSERROR(GetLastError()) | NH_CANNOT_CREATE_MUTEX;

#endif

	if (NH_FAIL(rv))
	{
		free(handle);
#ifdef UNIX_IMPL
		if (handle->mutex) free(handle->mutex);
#endif
	}
	else *hHandle = handle;
	return rv;
}

NH_FUNCTION(NH_RV, NH_release_mutex)(_IN_ NH_MUTEX_HANDLE hHandle)
{
	NH_RV rv = NH_OK;
#ifdef UNIX_IMPL
	NH_SYSRV ret;
#endif
	if (!hHandle) return NH_INVALID_ARG;

#ifdef UNIX_IMPL

	if ((ret = pthread_mutex_destroy(hHandle->mutex))) rv = S_SYSERROR(ret) | NH_CANNOT_RELEASE_MUTEX;
	free(hHandle->mutex);

#else

	if (!(CloseHandle(hHandle->mutex))) rv = S_SYSERROR(GetLastError()) | NH_CANNOT_RELEASE_MUTEX;

#endif

	free(hHandle);
	return rv;
}


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 * Memory container implementation
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
INLINE NH_UTILITY(NH_RV, alloc_wagon)(_IN_ size_t chunk, _OUT_ NH_FREIGHT_CAR **hWagon)
{
	NH_FREIGHT_CAR *ret;

	if ((ret = (NH_FREIGHT_CAR*) malloc(sizeof(NH_FREIGHT_CAR))))
	{
		if ((ret->buffer = malloc(chunk)))
		{
			ret->size = chunk;
			ret->available = ret->buffer;
			ret->remaining = chunk;
			ret->next = NULL;
			*hWagon = ret;
			return NH_OK;
		}
		free(ret);
	}
	return NH_OUT_OF_MEMORY_ERROR;
}

NH_UTILITY(NH_RV, NH_bite_chunk)(_INOUT_ NH_CARGO_CONTAINER_STR* self, _IN_ size_t size, _OUT_ void **ret)
{
	NH_RV mrv, rv = NH_OK;
	size_t wagonsize;
	void *pret;

	if (!self) return NH_INVALID_ARG;
	GUARD(self->hMutex, mrv,
	{
		if (self->current->remaining < size)
		{
			wagonsize = self->current->size < size ? size : self->current->size;
			if (NH_SUCCESS(rv = alloc_wagon(wagonsize, &self->current->next))) self->current = self->current->next;
		}
		if (NH_SUCCESS(rv))
		{
			pret = self->current->available;
			self->current->available = (unsigned char *) self->current->available + size;
			self->current->remaining -= size;
		}
	});
	if (NH_FAIL(mrv)) return mrv;
	if (NH_SUCCESS(rv)) *ret = pret;
	return (rv);
}

NH_UTILITY(NH_RV, NH_grow_chunk)(_INOUT_ NH_CARGO_CONTAINER_STR *self, _INOUT_ void **old, _IN_ size_t oldsize, _IN_ size_t newsize)
{
	NH_RV rv = NH_OK;
	void *newsegment;

	if (oldsize >= newsize) newsegment = *old;
	else
	{
		if (NH_SUCCESS(self->bite_chunk(self, newsize, &newsegment)))
		{
			memcpy(newsegment, *old, oldsize);
			*old = newsegment;
		}
	}
	return rv;
}

NH_UTILITY(void, NH_zeroize)(_INOUT_ NH_CARGO_CONTAINER_STR* self, _IN_ NH_CRYPTOZEROIZE_FUNCTION method)
{
	NH_RV rv;
	NH_FREIGHT_CAR *wagon;

	if (!self) return;
	wagon = self->first;
	GUARD(self->hMutex, rv,
	{
		while (wagon)
		{
			if (wagon->buffer)
			{
				if (method) method(wagon->buffer, wagon->size);
				else memset(wagon->buffer, 0, wagon->size);
			}
			wagon = wagon->next;
		}
	});
}

static NH_CARGO_CONTAINER_STR defContainerHandler =
{
	NULL,
	NULL,
	NULL,
	NH_bite_chunk,
	NH_zeroize,
	NH_grow_chunk
};

NH_FUNCTION(NH_RV, NH_freight_container)(_IN_ size_t chunk, _OUT_ NH_CARGO_CONTAINER *hHandle)
{
	NH_CARGO_CONTAINER ret = NULL;
	NH_RV rv = NH_OUT_OF_MEMORY_ERROR;

	if ((ret = (NH_CARGO_CONTAINER) malloc(sizeof(NH_CARGO_CONTAINER_STR))))
	{
		memcpy(ret, &defContainerHandler, sizeof(NH_CARGO_CONTAINER_STR));
		if (NH_SUCCESS(rv = NH_create_mutex(&ret->hMutex)))
		{
			if (NH_SUCCESS(rv = alloc_wagon(chunk, &ret->first)))
			{
				ret->current = ret->first;
				*hHandle = ret;
				return NH_OK;
			}
		}
	}
	NH_release_container(ret);
	return rv;
}

NH_FUNCTION(NH_RV, NH_release_container)(_IN_ NH_CARGO_CONTAINER hHandle)
{
	NH_RV rv = NH_OK;
	NH_FREIGHT_CAR *wagon;

	if (!hHandle) return NH_INVALID_ARG;
	rv = NH_release_mutex(hHandle->hMutex);
	while (hHandle->first)
	{
		if (hHandle->first->buffer) free(hHandle->first->buffer);
		wagon = hHandle->first;
		hHandle->first = hHandle->first->next;
		free(wagon);
	}
	free(hHandle);
	return rv;
}

NH_FUNCTION(void, NH_swap)(_INOUT_ unsigned char *value, _IN_ size_t size)
{
	register unsigned int i = 0;
	register unsigned int j = size - 1;
	unsigned char temp;
	while (i < j)
	{
		temp = value[i];
		value[i] = value[j];
		value[j] = temp;
		i++, j--;
	}
}

INLINE NH_FUNCTION(int, ROUNDUP)(_IN_ int y)
{
	int x = y;
	--x;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	return ++x;
}
