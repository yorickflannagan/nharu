#include "jca.h"
#include "b64/cdecode.h"
#include "b64/cencode.h"
#include "sb8/crc.h"
#include <stdio.h>
#include <string.h>


/** ****************************
 *  Utilities
 *  ****************************/
INLINE NH_UTILITY(jsize, remove_PEM_armour)(_INOUT_ jbyte *jbuffer, _IN_ jsize len, _OUT_ jbyte **start, _OUT_ jsize *end)
{
	jint idx = 0;
	jsize nlen = 0, armourlen;

	while (jbuffer[idx] == 0x2D && idx < len) idx++;	/* Remove ---- */
	while (jbuffer[idx] != 0x2D && idx < len) idx++;	/* Remove BEGIN XXXX */
	while (jbuffer[idx] == 0x2D && idx < len) idx++;	/* Remove ---- */
	if (idx == 0 || idx == len) return 0;
	*start = &jbuffer[idx];
	armourlen = idx;
	while (jbuffer[idx] != 0x2D && idx < len)
	{
		idx++;
		nlen++;
	}
	*end = nlen;
	return armourlen;
}

INLINE NH_UTILITY(jsize, pem_to_DER)(_INOUT_ jbyte *jbuffer, _IN_ jsize len)
{
	jsize newlen = 0;
	jbyte *inbuffer = NULL;
	base64_decodestate state_in;

	if (jbuffer[0] == 0x30) return len;
	if (remove_PEM_armour(jbuffer, len, &inbuffer, &newlen) > 0)
	{
		base64_init_decodestate(&state_in);
		newlen = base64_decode_block((char*) inbuffer, newlen, (char*) jbuffer, &state_in);
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

const static int elapsed_days[]	= { -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333 };
const static int elapsed_days_leap[]	= { -1, 30, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
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

INLINE NH_UTILITY(jbyteArray, get_node_contents)(JNIEnv *env, _IN_ NH_ASN1_PNODE node)
{
	jbyteArray ret = NULL;

	if (!(ret = (*env)->NewByteArray(env, node->size))) throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	else (*env)->SetByteArrayRegion(env, ret, 0L, node->size, (jbyte*) node->contents);
	return ret;
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
