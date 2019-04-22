#include "jcrypto.h"

/** ****************************
 *  Hash implementation
 *  ****************************/
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_provider_NharuDigest_nhcDigest
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jbyteArray buffer,
	jint mechanism
)
{
	jbyte *jbuffer;
	jsize len;
	NH_RV rv;
	NH_HASH_HANDLER hHash;
	unsigned char *out;
	size_t size;
	jbyteArray ret = NULL;

	len = (*env)->GetArrayLength(env, buffer);
	if ((jbuffer = (*env)->GetByteArrayElements(env, buffer, NULL)))
	{
		if (NH_SUCCESS(rv = NH_new_hash(&hHash)))
		{
			if
			(
				NH_SUCCESS(rv = hHash->init(hHash, mechanism)) &&
				NH_SUCCESS(rv = hHash->update(hHash, (unsigned char*) jbuffer, len)) &&
				NH_SUCCESS(rv = hHash->finish(hHash, NULL, &size))
			)
			{
				if (NH_SUCCESS(rv = (out = (unsigned char*) malloc(size)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
				{
					if (NH_SUCCESS(rv = hHash->finish(hHash, out, &size)))
					{
						if
						(
							(ret = (*env)->NewByteArray(env, size))
						)	(*env)->SetByteArrayRegion(env, ret, 0L, size, (jbyte*) out);
						else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
					}
					free(out);
				}
			}
			NH_release_hash(hHash);
		}
		(*env)->ReleaseByteArrayElements(env, buffer, jbuffer, JNI_ABORT);
		if (NH_FAIL(rv)) throw_new(env, J_NATIVE_EX, J_NATIVE_ERROR, rv);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}
