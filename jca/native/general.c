#include "jca.h"
#include "x509.h"
#include "b64/cdecode.h"
#include "b64/cencode.h"
#include "sb8/crc.h"
#include <stdio.h>
#include <string.h>

#if defined (_WIN32)
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

#endif


JNIEXPORT void JNICALL Java_org_crypthing_security_provider_NharuProvider_nharuInitPRNG(_UNUSED_ JNIEnv *env, _UNUSED_ jclass c)
{
	NH_NOISE_HANDLER hNoise;
	if (NH_SUCCESS(NH_new_noise_device(&hNoise))) NH_release_noise_device(hNoise);
}


/** ****************************
 *  Utilities
 *  ****************************/
INLINE NH_UTILITY(jsize, remove_PEM_armour)(_IN_ jbyte *jbuffer, _IN_ jsize len, _OUT_ jbyte **start, _OUT_ jsize *newlen)
{
	jint idx = 0;
	jsize nlen = 0, armourlen;

	while (jbuffer[idx] == 0x2D && idx < len) idx++;	/* Remove ---- */
	if (idx == 0)							/* PEM without armour? Just a base64 encoding... Support legacy MIME multipart/signed */
	{
		*start = (jbyte*) jbuffer;
		*newlen = len;
		return 0;
	}
	while (jbuffer[idx] != 0x2D && idx < len) idx++;	/* Remove BEGIN XXXX */
	while (jbuffer[idx] == 0x2D && idx < len) idx++;	/* Remove ---- */
	if (idx == 0 || idx == len) return -1;
	*start = (jbyte*) &jbuffer[idx];
	armourlen = idx;
	while (jbuffer[idx] != 0x2D && idx < len)
	{
		idx++;
		nlen++;
	}
	*newlen = nlen;
	return armourlen;
}

#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(jsize, pem_to_DER)(_IN_ jbyte *from, _IN_ jsize len, _OUT_ jbyte *to)
{
	jsize newlen = 0;
	jbyte *start;
	base64_decodestate state_in;

	if (remove_PEM_armour(from, len, &start, &newlen) != -1)
	{
		base64_init_decodestate(&state_in);
		newlen = base64_decode_block((char*) start, newlen, (char*) to, &state_in);
	}
	return newlen;
}

NH_UTILITY(void, throw_new)(JNIEnv *env, char *jc, char *msg, NH_RV nhc)
{
      char buffer[2048];
      jclass e;

	(*env)->ExceptionClear(env);
	if ((e = (*env)->FindClass(env, jc)))
	{
		if (nhc > 0) sprintf(buffer, "%s - error code: %lu", msg, nhc);
		else sprintf(buffer, "%s", msg);
		(*env)->ThrowNew(env, e, buffer);
	}
}


NH_UTILITY(void, throw_new_with_rv)(JNIEnv *env, char *jc, char *msg, NH_RV nhc)
{
      char buffer[2048];
	  jclass e;
	  jobject ex;
	  jmethodID constructor;

	(*env)->ExceptionClear(env);
	if ((e = (*env)->FindClass(env, jc)))
	{
		if (nhc > 0) sprintf(buffer, "%s - error code: %lu", msg, nhc);
		else sprintf(buffer, "%s", msg);

		constructor = (*env)->GetMethodID(env, e, "<init>", "(Ljava/lang/String;I)V");
		if(constructor)
		{

			ex = (*env)->NewObject(env, e, constructor, (*env)->NewStringUTF(env, buffer), nhc);
			(*env)->Throw(env, ex);
		}
		else
		{
			(*env)->ThrowNew(env, e, buffer);
		}
	}
}


const static int elapsed_days[]	= { -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333 };
const static int elapsed_days_leap[]	= { -1, 30, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(jlong, java_mktime)(_IN_ NH_PTIME instant)
{
	jlong isLeap, yearDays, pre, daysUntilNow, year, adjust = 0;

	year = instant->tm_year + 1900;
	isLeap = ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0));
	yearDays = isLeap ? elapsed_days_leap[instant->tm_mon] + instant->tm_mday : elapsed_days[instant->tm_mon] + instant->tm_mday;
	if (year > 1972)
	{
		pre = year - 1601;
		/* adjust = ano1972  + possiveisbissextos - (regra de anos centenarios vs anos quatrocentenarios) + correcao da regra  */
		adjust = 1 + ((year - 1973) / 4) - (pre / 100) + (pre / 400) + 3;
	}
	daysUntilNow = 365 * (year - 1970) + adjust + yearDays;
	return (daysUntilNow * 86400 + instant->tm_hour * 3600 + instant->tm_min * 60 + instant->tm_sec) * 1000;
}

#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(jbyteArray, get_node_encoding)(JNIEnv *env, _IN_ NH_ASN1_PNODE node)
{
	jbyteArray ret = NULL;

	if (!(ret = (*env)->NewByteArray(env, node->size + node->contents - node->identifier))) throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	else (*env)->SetByteArrayRegion(env, ret, 0L, node->size + node->contents - node->identifier, (jbyte*) node->identifier);
	return ret;
}

INLINE NH_UTILITY(jbyteArray, get_node_value)(JNIEnv *env, _IN_ NH_ASN1_PNODE node)
{
	jbyteArray ret = NULL;

	if ((ret = (*env)->NewByteArray(env, node->valuelen))) (*env)->SetByteArrayRegion(env, ret, 0L, node->valuelen, (jbyte*) node->value);
	else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	return ret;
}

#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(jbyteArray, get_node_contents)(JNIEnv *env, _IN_ NH_ASN1_PNODE node)
{
	jbyteArray ret = NULL;

	if (!(ret = (*env)->NewByteArray(env, node->size))) throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	else (*env)->SetByteArrayRegion(env, ret, 0L, node->size, (jbyte*) node->contents);
	return ret;
}
NH_RV sign_callback
(
	_IN_ NH_BLOB *data,
	_UNUSED_ _IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ void *params,
	_OUT_ unsigned char *signature,
	_INOUT_ size_t *sigSize
)
{
	JNH_RSA_CALLBACK callback = (JNH_RSA_CALLBACK) params;
	jmethodID methodID;
	jbyteArray buffer;
	jint size = 0;
	jobject ret;
	jbyte *jBuffer;
	NH_RV rv = NH_OK;

	if (!signature)
	{
		if ((methodID = (*callback->env)->GetMethodID(callback->env, callback->clazz, "signatureLength", "(Ljava/lang/String;)I")))
		{
			size = (jint) (*callback->env)->CallLongMethod(callback->env, callback->iface, methodID, callback->algorithm);
			*sigSize = size;
		}
		else rv = JCLASS_ACCESS_ERROR;
	}
	else
	{
		if ((methodID = (*callback->env)->GetMethodID(callback->env, callback->clazz, "sign", "([BLjava/lang/String;)[B")))
		{
			if ((buffer = (*callback->env)->NewByteArray(callback->env, (jsize) data->length)))
			{
				(*callback->env)->SetByteArrayRegion(callback->env, buffer, 0L, (jsize) data->length, (jbyte*) data->data);
				ret = (*callback->env)->CallObjectMethod(callback->env, callback->iface, methodID, buffer, callback->algorithm);
				size = (*callback->env)->GetArrayLength(callback->env, ret);
				if (*sigSize < (size_t) size) rv = NH_BUF_TOO_SMALL;
				else
				{
					if ((jBuffer = (*callback->env)->GetByteArrayElements(callback->env, ret, NULL)))
					{
						memcpy(signature, jBuffer, size);
						(*callback->env)->ReleaseByteArrayElements(callback->env, ret, jBuffer, JNI_ABORT);
					}
					else rv = JRUNTIME_ERROR;
				}
			}
			else rv = JRUNTIME_ERROR;
		}
		else rv = JCLASS_ACCESS_ERROR;

	}
	return rv;
}


/** ****************************
 *  Array operations
 *  ****************************/
JNIEXPORT jboolean JNICALL Java_org_crypthing_util_NharuArrays_nhIsEquals
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jbyteArray a,
	jbyteArray b
)
{
	jsize alen, blen;
	jbyte *abuffer, *bbuffer;
	jboolean ret = JNI_FALSE;

	alen = (*env)->GetArrayLength(env, a);
	if ((abuffer = (*env)->GetByteArrayElements(env, a, NULL)))
	{
		blen = (*env)->GetArrayLength(env, b);
		if ((bbuffer = (*env)->GetByteArrayElements(env, b, NULL)))
		{
			ret = (alen == blen && memcmp(abuffer, bbuffer, alen) == 0) ? JNI_TRUE : JNI_FALSE;
			(*env)->ReleaseByteArrayElements(env, b, bbuffer, JNI_ABORT);
		}
		else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
		(*env)->ReleaseByteArrayElements(env, a, abuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_crypthing_util_NharuArrays_nhGetHashCode(JNIEnv *env, _UNUSED_ jclass ignored, jbyteArray a)
{
	jsize len;
	jbyte *jbuffer;
	jint ret = 0;

	len = (*env)->GetArrayLength(env, a);
	if ((jbuffer = (*env)->GetByteArrayElements(env, a, NULL)))
	{
		ret = crc32c_sb8_64_bit(NULL, (uint8_t*) jbuffer, len, 0, MODE_BODY);
		(*env)->ReleaseByteArrayElements(env, a, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_util_NharuArrays_nhFromBase64(JNIEnv *env, _UNUSED_ jclass ignored, jbyteArray encoding)
{
	jsize len, newlen;
	jbyte *jbuffer, *out;
	base64_decodestate state_in;
	jbyteArray ret = NULL;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if ((out = (jbyte*) malloc(len * sizeof(jbyte))))
		{
			base64_init_decodestate(&state_in);
			newlen = base64_decode_block((char*) jbuffer, len, (char*) out, &state_in);
			if ((ret = (*env)->NewByteArray(env, newlen))) (*env)->SetByteArrayRegion(env, ret, 0L, newlen, out);
			else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
			free(out);
		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_util_NharuArrays_nhToBase64(JNIEnv *env, _UNUSED_ jclass ignored, jbyteArray data)
{
	jsize len, newlen;
	jbyte *jbuffer, *out;
	base64_encodestate state_in;
	jbyteArray ret = NULL;

	len = (*env)->GetArrayLength(env, data);
	if ((jbuffer = (*env)->GetByteArrayElements(env, data, NULL)))
	{
		newlen = (((len + ((len % 3) ? (3 - (len % 3)) : 0)) / 3) * 4);
		newlen += (newlen / 72) + 3;
		if ((out = (jbyte*) malloc(newlen * sizeof(jbyte))))
		{
			base64_init_encodestate(&state_in);
			newlen = base64_encode_block((char*) jbuffer, len, (char*) out, &state_in);
			newlen += base64_encode_blockend((char*) out + newlen, &state_in);
			if ((ret = (*env)->NewByteArray(env, newlen))) (*env)->SetByteArrayRegion(env, ret, 0L, newlen, out);
			else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
			free(out);
		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		(*env)->ReleaseByteArrayElements(env, data, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}


/** ******************************
 *  NharuPublicKey interface
 *  ******************************/
JNIEXPORT jlong JNICALL
Java_org_crypthing_security_NharuPublicKey_nhixParsePublicKey
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jbyteArray encoding
)
{
	jsize len;
	jbyte *jbuffer, *copy = NULL;
	NH_RV rv = NH_OK;
	NHIX_PUBLIC_KEY hPubkey = NULL;
	JPUBKEY_HANDLER hHandler;
	jlong ret = 0L;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if ((copy = (jbyte*) malloc(len)))
		{
			memcpy(copy, jbuffer, len * sizeof(jbyte));
			if (NH_SUCCESS(rv = NHIX_pubkey_parser((unsigned char*) copy, len, &hPubkey)))
			{
				if ((hHandler = (JPUBKEY_HANDLER) malloc(sizeof(JPUBKEY_HANDLER_STR))))
				{
					hHandler->encoding = copy;
					hHandler->len = len;
					hHandler->hPubkey = hPubkey;
					ret = (jlong) hHandler;
				}
				else { throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0); rv = NH_OUT_OF_MEMORY_ERROR; }
			}
			else throw_new(env, J_CERT_ENCODING_EX, J_PUBKEY_PARSE_ERROR, rv);
		}
		else { throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0); rv = NH_OUT_OF_MEMORY_ERROR; }
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else { throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0); rv = NH_GENERAL_ERROR; }
	if (NH_FAIL(rv))
	{
		if (copy) free(copy);
		if (hPubkey) NHIX_release_pubkey(hPubkey);
	}
	return ret;
}
JNIEXPORT void JNICALL 
Java_org_crypthing_security_NharuPublicKey_nhixReleasePublicKey
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JPUBKEY_HANDLER hHandler = (JPUBKEY_HANDLER) handle;
	if (hHandler)
	{
		free(hHandler->encoding);
		NHIX_release_pubkey(hHandler->hPubkey);
		free(hHandler);
	}
}
JNIEXPORT jint JNICALL
Java_org_crypthing_security_NharuPublicKey_nhixGetPublicKeyType
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JPUBKEY_HANDLER hHandler = (JPUBKEY_HANDLER) handle;
	jint ret = 0L;

	if (NH_match_oid(rsaEncryption_oid, NHC_RSA_ENCRYPTION_OID_COUNT, (unsigned int*) hHandler->hPubkey->algorithm->value, hHandler->hPubkey->algorithm->valuelen)) ret = NHIX_RSA_ALGORITHM;
	else if (NH_match_oid(ecPublicKey_oid, NHC_ECDSA_PUBKEY_OID_COUNT, (unsigned int*) hHandler->hPubkey->algorithm->value, hHandler->hPubkey->algorithm->valuelen)) ret = NHIX_EC_ALGORITHM;
	else if (NH_match_oid(dsa_oid, NHC_DSA_OID_COUNT, (unsigned int*) hHandler->hPubkey->algorithm->value, hHandler->hPubkey->algorithm->valuelen)) ret = NHIX_DSA_ALGORITHM;
	return ret;
}


/** ******************************
 *  NharuRSAPublicKey interface
 *  ******************************/
JNIEXPORT jbyteArray JNICALL
Java_org_crypthing_security_NharuRSAPublicKey_nhixGetRSAKeyModulus
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JPUBKEY_HANDLER hHandler = (JPUBKEY_HANDLER) handle;
	NH_ASN1_PNODE node;
	jbyteArray ret = NULL;

	if ((node = hHandler->hPubkey->hParser->sail(hHandler->hPubkey->pubkey, NH_PARSE_SOUTH | 2)))
	{
		ret = get_node_value(env, node);
	}
	else throw_new(env, J_RUNTIME_EX, J_PARSE_ERROR, 0);
	return ret;
}
JNIEXPORT jbyteArray JNICALL
Java_org_crypthing_security_NharuRSAPublicKey_nhixGetRSAKeyPublicExponent
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JPUBKEY_HANDLER hHandler = (JPUBKEY_HANDLER) handle;
	NH_ASN1_PNODE node;
	jbyteArray ret = NULL;

	if ((node = hHandler->hPubkey->hParser->sail(hHandler->hPubkey->pubkey, ((NH_PARSE_SOUTH | 2) << 8) | NH_SAIL_SKIP_EAST)))
	{
		ret = get_node_value(env, node);
	}
	else throw_new(env, J_RUNTIME_EX, J_PARSE_ERROR, 0);
	return ret;
}
JNIEXPORT jlong JNICALL
Java_org_crypthing_security_NharuRSAPublicKey_nhixGetPublicKeyInfoNode
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return (jlong) ((JPUBKEY_HANDLER) handle)->hPubkey->hParser->root;
}
JNIEXPORT jbyteArray JNICALL
Java_org_crypthing_security_NharuRSAPublicKey_getKeyEncoding
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	NH_PBITSTRING_VALUE block;
	jbyteArray ret = NULL;

	block = (NH_PBITSTRING_VALUE) ((JPUBKEY_HANDLER) handle)->hPubkey->pubkey->value;
	if ((ret = (*env)->NewByteArray(env, (jsize) block->len))) (*env)->SetByteArrayRegion(env, ret, 0L, (jsize) block->len, (jbyte*) block->string);
	else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);

	return ret;
}

/** ****************************
 *  RSA private key operations
 *  ****************************/
JNIEXPORT jlong JNICALL Java_org_crypthing_security_NharuRSAPrivateKey_nharuNewRSAPrivateKey
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jbyteArray encoding
)
{
	jlong ret = 0L;
	jbyte *jbuffer;
	jsize len;
	NH_RV rv = NH_OK;
	NH_RSA_PRIVKEY_HANDLER hKey = NULL;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if
		(
			NH_SUCCESS(rv = NH_new_RSA_privkey_handler(&hKey)) &&
			NH_SUCCESS(rv = hKey->from_privkey_info(hKey, (unsigned char*) jbuffer, len))
		)	ret = (jlong) hKey;
		else throw_new(env, J_KEY_EX, J_KEY_ERROR, rv);
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	if (NH_FAIL(rv) && hKey) NH_release_RSA_privkey_handler(hKey);
	return ret;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_NharuRSAPrivateKey_nharuReleaseRSAPrivateKey
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle
)
{
	NH_release_RSA_privkey_handler((NH_RSA_PRIVKEY_HANDLER) handle);
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_NharuRSAPrivateKey_nharuRSASign
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle,
	jbyteArray data,
	jint mechanism
)
{
	NH_RSA_PRIVKEY_HANDLER hKey = (NH_RSA_PRIVKEY_HANDLER) handle;
	jbyte *jbuffer;
	jsize len;
	jbyteArray ret = NULL;
	NH_RV rv;
	unsigned char *signature;
	size_t size;

	len = (*env)->GetArrayLength(env, data);
	if ((jbuffer = (*env)->GetByteArrayElements(env, data, NULL)))
	{
		if (NH_SUCCESS(rv = hKey->sign(hKey, mechanism, (unsigned char*) jbuffer, len, NULL, &size)))
		{
			if ((signature = (unsigned char*) malloc(size)))
			{
				if (NH_SUCCESS(rv = hKey->sign(hKey, mechanism, (unsigned char*) jbuffer, len, signature, &size)))
				{
					if ((ret = (*env)->NewByteArray(env, (jsize) size))) (*env)->SetByteArrayRegion(env, ret, 0L, (jsize) size, (jbyte*) signature);
					else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
				}
				else throw_new(env, J_KEY_EX, J_KEY_ERROR, rv);
				free(signature);
			}
			else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		}
		else throw_new(env, J_KEY_EX, J_KEY_ERROR, rv);
		(*env)->ReleaseByteArrayElements(env, data, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_crypthing_security_NharuRSAPrivateKey_nharuRSASignatureLength
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle
)
{
	return RSA_size(((NH_RSA_PRIVKEY_HANDLER) handle)->key);
}

NH_UTILITY(jbyteArray, bignum_to_java_array)(JNIEnv *env, _IN_ BIGNUM *n)
{
	unsigned char *buffer;
	size_t num_bytes, offset;
	jbyteArray ret = NULL;

	num_bytes = BN_num_bytes(n);
	offset = (BN_num_bits(n) == num_bytes * 8) ? 1 : 0;
	if ((buffer = (unsigned char*) malloc(num_bytes + offset)))
	{
		memset(buffer, 0, num_bytes + offset);
		BN_bn2bin(n, buffer + offset);
		if ((ret = (*env)->NewByteArray(env, (jsize) (num_bytes + offset)))) (*env)->SetByteArrayRegion(env, ret, 0L, (jsize) (num_bytes + offset), (jbyte*) buffer);
		else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
		free(buffer);
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_NharuRSAPrivateKey_nharuGetRSAModulus
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle
)
{
	BIGNUM *n;
    #if OPENSSL_VERSION_NUMBER >= 0x10100001L
    RSA_get0_key((const RSA *)(((NH_RSA_PRIVKEY_HANDLER) handle)->key), (const BIGNUM **)&n, NULL, NULL);
    #else
    n=((NH_RSA_PRIVKEY_HANDLER) handle)->key->n;
    #endif
	return bignum_to_java_array(env, n);
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_NharuRSAPrivateKey_nharuGetRSAPrivateExponent
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle
)
{
	BIGNUM *d;
    #if OPENSSL_VERSION_NUMBER >= 0x10100001L
    RSA_get0_key((const RSA *)(((NH_RSA_PRIVKEY_HANDLER) handle)->key), NULL, NULL, (const BIGNUM **)&d);
    #else
    n=((NH_RSA_PRIVKEY_HANDLER) handle)->key->d;
    #endif
	return bignum_to_java_array(env, d);
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_NharuRSAPrivateKey_nharuRSADecrypt
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle,
	jbyteArray data,
	jint mechanism
)
{
	NH_RSA_PRIVKEY_HANDLER hKey = (NH_RSA_PRIVKEY_HANDLER) handle;
	jbyte *jbuffer;
	jsize len;
	jbyteArray ret = NULL;
	NH_RV rv;
	unsigned char *plaintext;
	size_t size;

	len = (*env)->GetArrayLength(env, data);
	if ((jbuffer = (*env)->GetByteArrayElements(env, data, NULL)))
	{
		if (NH_SUCCESS(rv = hKey->decrypt(hKey, mechanism, (unsigned char*) jbuffer, len, NULL, &size)))
		{
			if ((plaintext = (unsigned char*) malloc(size)))
			{
				if (NH_SUCCESS(rv = hKey->decrypt(hKey, mechanism, (unsigned char*) jbuffer, len, plaintext, &size)))
				{
					if ((ret = (*env)->NewByteArray(env, (jsize) size))) (*env)->SetByteArrayRegion(env, ret, 0L, (jsize) size, (jbyte*) plaintext);
					else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
				}
				else throw_new(env, J_INVALID_KEY_EX, J_KEY_ERROR, rv);
				free(plaintext);
			}
			else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		}
		else throw_new(env, J_INVALID_KEY_EX, J_KEY_ERROR, rv);
		(*env)->ReleaseByteArrayElements(env, data, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_provider_NharuProvider_leakageStop(_UNUSED_ JNIEnv *env, _UNUSED_ jclass c)
{
#ifdef _DEBUG_
	printf("Debug stop only\n");
#endif
}


/** ****************************
 *  RSA key pair operations
 *  ****************************/
JNIEXPORT void JNICALL
Java_org_crypthing_security_NharuRSAKeyPairGenerator_nharuSeedPRNG(JNIEnv *env, _UNUSED_ jclass ignored, jbyteArray seed)
{
	jsize len;
	jbyte *buffer;
	NH_RV rv;
	NH_NOISE_HANDLER hNoise;

	len = (*env)->GetArrayLength(env, seed);
	if ((buffer = (*env)->GetByteArrayElements(env, seed, NULL)))
	{
		if (NH_SUCCESS(rv = NH_new_noise_device(&hNoise)))
		{
			hNoise->seed((unsigned char*) buffer, len);
			NH_release_noise_device(hNoise);
		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, rv);
		(*env)->ReleaseByteArrayElements(env, seed, buffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
}
JNIEXPORT jlong JNICALL
Java_org_crypthing_security_NharuRSAKeyPairGenerator_nharuGenerateRSAKeys(JNIEnv *env, _UNUSED_ jclass ignored, jint bits, jlong e)
{
	jlong ret = 0L;
	NH_RV rv;
	JRSA_KEYPAIR_HANDLER hHandler;

	if ((hHandler = (JRSA_KEYPAIR_HANDLER) malloc(sizeof(JRSA_KEYPAIR_HANDLER_STR))))
	{
		if (NH_SUCCESS(rv = NH_generate_RSA_keys(bits, e, &hHandler->hPubKey, &hHandler->hPrivKey))) ret = (jlong) hHandler;
		else { free(hHandler); throw_new(env, J_GENERAL_SECURITY_EX, J_KEY_GEN_ERROR, rv); }
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
	return ret;
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_NharuRSAKeyPairGenerator_nharuReleaseRSAKeys(_UNUSED_ JNIEnv *env, _UNUSED_ jclass ignored, jlong handle)
{
	JRSA_KEYPAIR_HANDLER hHandler = (JRSA_KEYPAIR_HANDLER) handle;
	if (hHandler)
	{
		NH_release_RSA_pubkey_handler(hHandler->hPubKey);
		NH_release_RSA_privkey_handler(hHandler->hPrivKey);
		free(hHandler);
	}
}
static NH_NODE_WAY __root_map[] = {{ NH_PARSE_ROOT, NH_ASN1_SEQUENCE, NULL, 0 }};
JNIEXPORT jbyteArray JNICALL
Java_org_crypthing_security_NharuRSAKeyPairGenerator_nharuGetPrivateKey(JNIEnv *env, _UNUSED_ jclass ignored, jlong handle)
{
	jbyteArray ret = NULL;
	NH_RV rv;
	JRSA_KEYPAIR_HANDLER hHandler = (JRSA_KEYPAIR_HANDLER) handle;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	NH_ASN1_PNODE node;
	size_t ulKeySize;
	unsigned char *pKey;

	if (NH_SUCCESS(rv = NH_new_encoder(16, 4096, &hEncoder)))
	{
		if
		(
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, __root_map, 1, &node)) &&
			NH_SUCCESS(rv = hHandler->hPrivKey->to_privkey_info(hHandler->hPrivKey, hEncoder, NH_PARSE_ROOT)) &&
			NH_SUCCESS(rv = (ulKeySize = hEncoder->encoded_size(hEncoder, hEncoder->root)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
			NH_SUCCESS(rv = (pKey = (unsigned char*) malloc(ulKeySize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pKey)))
			{
				if (!(ret = (*env)->NewByteArray(env, (jsize) ulKeySize))) throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
				else (*env)->SetByteArrayRegion(env, ret, 0L, (jsize) ulKeySize, (jbyte*) pKey);
			}
			else throw_new(env, J_CERT_ENCODING_EX, J_CERT_ENCODING_ERROR, rv);
			free(pKey);
		}
		else throw_new(env, J_CERT_ENCODING_EX, J_CERT_ENCODING_ERROR, rv);
		NH_release_encoder(hEncoder);
	}
	else throw_new(env, J_CERT_ENCODING_EX, J_CERT_ENCODING_ERROR, rv);
	return ret;
}
JNIEXPORT jbyteArray JNICALL
Java_org_crypthing_security_NharuRSAKeyPairGenerator_nharuGetPublicKey(JNIEnv *env, _UNUSED_ jclass ignored, jlong handle)
{
	jbyteArray ret = NULL;
	NH_RV rv;
	JRSA_KEYPAIR_HANDLER hHandler = (JRSA_KEYPAIR_HANDLER) handle;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	NH_ASN1_PNODE node;
	size_t ulKeySize;
	unsigned char *pKey;

	if (NH_SUCCESS(rv = NH_new_encoder(16, 4096, &hEncoder)))
	{
		if
		(
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, __root_map, 1, &node)) &&
			NH_SUCCESS(rv = hHandler->hPubKey->encode_info(hHandler->hPubKey, hEncoder, NH_PARSE_ROOT)) &&
			NH_SUCCESS(rv = (ulKeySize = hEncoder->encoded_size(hEncoder, hEncoder->root)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
			NH_SUCCESS(rv = (pKey = (unsigned char*) malloc(ulKeySize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pKey)))
			{
				if (!(ret = (*env)->NewByteArray(env, (jsize) ulKeySize))) throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
				else (*env)->SetByteArrayRegion(env, ret, 0L, (jsize) ulKeySize, (jbyte*) pKey);
			}
			else throw_new(env, J_CERT_ENCODING_EX, J_CERT_ENCODING_ERROR, rv);
			free(pKey);
		}
		else throw_new(env, J_CERT_ENCODING_EX, J_CERT_ENCODING_ERROR, rv);
		NH_release_encoder(hEncoder);
	}
	else throw_new(env, J_CERT_ENCODING_EX, J_CERT_ENCODING_ERROR, rv);
	return ret;
}