#include "x509.h"
#include "sb8/crc.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <math.h>


/** ******************************
 *  NharuX509Name interface
 *  ******************************/
JNIEXPORT jboolean JNICALL Java_org_crypthing_security_x509_NharuX509Name_nhixMatchName
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong aHandle,
	jlong bHandle
)
{
	return strcmp(((NH_NAME_NODE) aHandle)->stringprep, ((NH_NAME_NODE) bHandle)->stringprep) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509Name_nhixGetNameHash
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return crc32c_sb8_64_bit
	(
		NULL,
		(uint8_t*) ((NH_NAME_NODE) handle)->stringprep,
		strlen(((NH_NAME_NODE) handle)->stringprep),
		0,
		MODE_BODY
	);
}

/** ******************************
 *  NharuX509Certificate interface
 *  ******************************/
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixParseCertificate
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jbyteArray encoding
)
{
	jbyte *jbuffer, *copy;
	jsize len, elen;
	NH_RV rv = NH_OK;
	NH_CERTIFICATE_HANDLER hCert = NULL;
	JNH_CERTIFICATE_HANDLER hHandler;
	jlong ret = 0L;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if ((copy = (jbyte*) malloc(len)))
		{
			memcpy(copy, jbuffer, len * sizeof(jbyte));
			elen = pem_to_DER(copy, len);
			if (NH_SUCCESS(rv = NH_parse_certificate((unsigned char*) copy, elen, &hCert)))
			{
				if ((hHandler = (JNH_CERTIFICATE_HANDLER) malloc(sizeof(JNH_CERTIFICATE_HANDLER_STR))))
				{
					hHandler->encoding = copy;
					hHandler->len = elen;
					hHandler->hCert = hCert;
					ret = (jlong) hHandler;
				}
				else
				{
					rv = NH_OUT_OF_MEMORY_ERROR;
					throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
				}
			}
			else throw_new(env, J_CERTIFICATE_EX, J_CERT_PARSE_ERROR, rv);
			if (NH_FAIL(rv))
			{
				free(copy);
				if (hCert) NH_release_certificate(hCert);
			}
		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixReleaseCertificate
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	if (hHandler)
	{
		if (hHandler->hCert) NH_release_certificate(hHandler->hCert);
		if (hHandler->encoding) free(hHandler->encoding);
		free(hHandler);
	}
}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetIssuerNode
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return (jlong) ((JNH_CERTIFICATE_HANDLER) handle)->hCert->issuer;
}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSubjectNode
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return (jlong) ((JNH_CERTIFICATE_HANDLER) handle)->hCert->subject;
}


/** ******************************
 *  X509Certificate interface
 *  ******************************/
JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixCheckValidity
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jlong instant
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_PTIME now;
	time_t tinstant = (time_t) (instant / 1000);
	NH_RV rv;

	now = gmtime(&tinstant);
	switch (rv = hHandler->hCert->check_validity(hHandler->hCert, now))
	{
	case NH_OK:
		break;
	case NH_CERT_EXPIRE_ERROR:
		throw_new(env, J_CERT_EXPIRE_EX, J_CERT_EXPIRE__ERROR, 0);
		break;
	case NH_CERT_NOT_VALID_ERROR:
		throw_new(env, J_CERT_NOT_VALID_EX, J_CERT_NOT_VALID_ERROR, 0);
		break;
	default: throw_new(env, J_CERTIFICATE_EX, J_CERT_PARSE_ERROR, rv);
	}
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSubject
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_node_encoding(env, ((JNH_CERTIFICATE_HANDLER) handle)->hCert->subject->node);
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetIssuer
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_node_encoding(env, ((JNH_CERTIFICATE_HANDLER) handle)->hCert->issuer->node);
}

JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetVersion
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jint ret = 0;

	if (NH_SUCCESS(rv = hHandler->hCert->version(hHandler->hCert, &node)))
	{
		if (ASN_IS_PRESENT(node)) ret = *(int*) node->child->value;
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ++ret;
}

JNIEXPORT jintArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSignatureMechanismOID
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jintArray ret = NULL;

	if (NH_SUCCESS(rv = hHandler->hCert->signature_mech(hHandler->hCert, &node)))
	{
		if ((ret = (*env)->NewIntArray(env, node->child->valuelen))) (*env)->SetIntArrayRegion(env, ret, 0L, node->child->valuelen, (jint*) node->child->value);
		else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSignatureAlgParameters
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jbyteArray ret = NULL;

	if (NH_SUCCESS(rv = hHandler->hCert->signature_mech(hHandler->hCert, &node)))
	{
		if (ASN_IS_PRESENT(node->child->next)) ret = get_node_encoding(env, node->child->next);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetNotBefore
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jlong ret = 0L;

	if (NH_SUCCESS(rv = hHandler->hCert->not_before(hHandler->hCert, &node)))
	{
            ret = java_mktime((NH_PTIME) node->value);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;

}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetNotAfter
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jlong ret = 0L;

	if (NH_SUCCESS(rv = hHandler->hCert->not_after(hHandler->hCert, &node)))
	{
            ret = java_mktime((NH_PTIME) node->value);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetBasicConstraints
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jint ret = -1;

	if (NH_SUCCESS(rv = hHandler->hCert->basic_constraints(hHandler->hCert, &node)))
	{
		if (node && (node = node->child) && ASN_IS_PRESENT(node) && *(unsigned char*) node->value)
		{
			if ((node = node->next) && ASN_IS_PRESENT(node)) ret = *(int *) node->value;
			else ret = INTEGER_MAX_VALUE;
		}
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetExtendedKeyUsage
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jobject ret = NULL, cls;
	jmethodID ctor, add;
	jintArray value;

	if (NH_SUCCESS(rv = hHandler->hCert->ext_key_usage(hHandler->hCert, &node)))
	{
		if (node && (node = node->child))
		{
			if (!(cls = (*env)->FindClass(env, "java/util/ArrayList")))
			{
				throw_new(env, J_CLASS_NOT_FOUND_EX, J_CLASS_NOT_FOUND_ERROR, 0);
				return NULL;
			}
			if (!(ctor = (*env)->GetMethodID(env, cls, "<init>", "()V")) || !(add = (*env)->GetMethodID(env, cls, "add", "(Ljava/lang/Object;)Z")))
			{
				throw_new(env, J_METH_NOT_FOUND_EX, J_METH_NOT_FOUND_ERROR, 0);
				return NULL;
			}
			if (!(ret = (*env)->NewObject(env, cls, ctor)))
			{
				throw_new(env, J_METH_NOT_FOUND_EX, J_METH_NOT_FOUND_ERROR, 0);
				return NULL;
			}
			while (node)
			{
				if (!(value = (*env)->NewIntArray(env, node->valuelen)))
				{
					throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
					return NULL;
				}
				(*env)->SetIntArrayRegion(env, value, 0L, node->valuelen, (jint*) node->value);
				(*env)->CallObjectMethod(env, ret, add, value);
				node = node->next;
			}
		}
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetKeyUsage
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jbyteArray ret = NULL;

	if (NH_SUCCESS(rv = hHandler->hCert->key_usage(hHandler->hCert, &node)))
	{
		if (node) ret = get_node_contents(env, node);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSerialNumber
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	return get_node_value(env, hHandler->hCert->serialNumber);
}

static unsigned int j_rsaEncryption_oid[]			= { 1, 2, 840, 113549, 1, 1, 1  };
static unsigned int j_md2WithRsa_oid[]			= { 1, 3, 14,  7,      2, 3, 1  };
static unsigned int j_md5WithRSA_oid[]			= { 1, 3, 14,  3,      2, 3     };
static unsigned int j_sha1WithRSAEncryption[]		= { 1, 2, 840, 113549, 1, 1, 5  };
static unsigned int j_sha256WithRSAEncryption[]		= { 1, 2, 840, 113549, 1, 1, 11 };
static unsigned int j_sha384WithRSAEncryption[]		= { 1, 2, 840, 113549, 1, 1, 12 };
static unsigned int j_sha512WithRSAEncryption[]		= { 1, 2, 840, 113549, 1, 1, 13 };
static unsigned int j_dsa_oid[]				= { 1, 2, 840, 10040,  4, 1     };
static unsigned int j_dsa_with_sha1_oid[]			= { 1, 2, 840, 10040,  4, 3     };
static unsigned int j_dsa_with_recommended_oid[]	= { 1, 2, 840, 10045,  4, 2     };
static unsigned int j_ecdsa_with_SHA1_oid[]		= { 1, 2, 840, 10045,  4, 1     };
static unsigned int j_ecdsa_with_SHA256_oid[]		= { 1, 2, 840, 10045,  4, 3, 2  };
static unsigned int j_ecdsa_with_SHA384_oid[]		= { 1, 2, 840, 10045,  4, 3, 3  };
static unsigned int j_ecdsa_with_SHA512_oid[]		= { 1, 2, 840, 10045,  4, 3, 4  };
static unsigned int j_md5WithRSA_oid_alvestrand[]	= { 1, 2, 840, 113549, 1, 1, 4  };
static unsigned int* sigmech_oids[]	=
{
	j_sha256WithRSAEncryption,
	j_sha1WithRSAEncryption,
	j_sha512WithRSAEncryption,
	j_rsaEncryption_oid,
	j_md2WithRsa_oid,
	j_md5WithRSA_oid,
	j_sha384WithRSAEncryption,
	j_dsa_oid,
	j_dsa_with_sha1_oid,
	j_dsa_with_recommended_oid,
	j_ecdsa_with_SHA1_oid,
	j_ecdsa_with_SHA256_oid,
	j_ecdsa_with_SHA384_oid,
	j_ecdsa_with_SHA512_oid,
	j_md5WithRSA_oid_alvestrand
};
static size_t oid_count[] = { 7, 7, 7, 7, 7, 6, 7, 6, 6, 6, 6, 7, 7, 7, 7 } ;
static jint sigmech[] =
{
	NHIX_SHA256withRSA_ALGORITHM,
	NHIX_SHA1withRSA_ALGORITHM,
	NHIX_SHA512withRSA_ALGORITHM,
	NHIX_NONEwithRSA_ALGORITHM,
	NHIX_MD2withRSA_ALGORITHM,
	NHIX_MD5withRSA_ALGORITHM,
	NHIX_SHA384withRSA_ALGORITHM,
	NHIX_NONEwithDSA_ALGORITHM,
	NHIX_SHA1withDSA_ALGORITHM,
	NHIX_NONEwithECDSA_ALGORITHM,
	NHIX_SHA1withECDSA_ALGORITHM,
	NHIX_SHA256withECDSA_ALGORITHM,
	NHIX_SHA384withECDSA_ALGORITHM,
	NHIX_SHA512withECDSA_ALGORITHM,
	NHIX_MD5withRSA_ALGORITHM
};
INLINE NH_UTILITY(jint, find_mechanism)(_IN_ NH_ASN1_PNODE node)
{
	size_t i;

	if (!node) return -1;
	for (i = 0; i < 15; i++) if (NH_match_oid((unsigned int *) node->child->value, node->child->valuelen, sigmech_oids[i], oid_count[i])) return sigmech[i];
	return -1;
}
JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSignatureMechanism
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jint ret = 0;

	if (NH_SUCCESS(rv = hHandler->hCert->signature_mech(hHandler->hCert, &node)))
	{
		if ((ret = find_mechanism(node)) < 0) throw_new(env, J_UNSUP_MECH_EX, J_UNSUP_MECH_ERROR, 0);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

INLINE NH_UTILITY(jbyteArray, encode_signature)(JNIEnv *env, _IN_ NH_ASN1_PNODE node)
{
	jbyteArray ret = NULL;

	if (node)
	{
		if ((ret = (*env)->NewByteArray(env, ((NH_PBITSTRING_VALUE) node->value)->len))) (*env)->SetByteArrayRegion
		(
			env,
			ret,
			0L,
			((NH_PBITSTRING_VALUE) node->value)->len,
			(jbyte*) ((NH_PBITSTRING_VALUE) node->value)->string
		);
		else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	}
	else throw_new(env, J_RUNTIME_EX, J_PARSE_ERROR, 0);
	return ret;
}
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSignature
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return encode_signature
	(
		env,
		((JNH_CERTIFICATE_HANDLER) handle)->hCert->hParser->sail(((JNH_CERTIFICATE_HANDLER) handle)->hCert->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))
	);
}

static unsigned int COMMON_NAME[] = { 2, 5, 4, 3 };
static unsigned int COUNTRY[] = { 2, 5, 4, 6 };
static unsigned int ORGANIZATION[] = { 2, 5, 4, 10 };
static unsigned int ORGANIZATIONAL_UNIT[] = { 2, 5, 4, 11 };
static unsigned int STATE[] = { 2, 5, 4, 8 };
static unsigned int LOCALITY[] = { 2, 5, 4, 7 };
static unsigned int EMAIL[] = { 1, 2, 840, 113549, 1, 9, 1 };
static unsigned int DOMAIN_COMPONENT[] = { 0, 9, 2342, 19200300, 100, 1, 25 };
static unsigned int DISTINGUISHED_NAME_QUALIFIER[] = { 2, 5, 4, 46 };
static unsigned int SERIAL_NUMBER[] = { 2, 5, 4, 5 };
static unsigned int SURNAME[] = { 2, 5, 4, 4 };
static unsigned int TITLE[] = { 2, 5, 4, 12 };
static unsigned int GIVEN_NAME[] = { 2, 5, 4, 42 };
static unsigned int INITIALS[] = { 2, 5, 4, 43 };
static unsigned int PSEUDONYM[] = { 2, 5, 4, 65 };
static unsigned int GERNERAL_QUALIFIER[] = { 2, 5, 4, 64 };
static unsigned int DISTINGUISHED_NAME[] = { 2, 5, 4, 49 };
static unsigned int* oid_names[] =
{
	COMMON_NAME,
	COUNTRY,
	ORGANIZATION,
	ORGANIZATIONAL_UNIT,
	STATE,
	LOCALITY,
	EMAIL,
	DOMAIN_COMPONENT,
	DISTINGUISHED_NAME_QUALIFIER,
	SERIAL_NUMBER,
	SURNAME,
	TITLE,
	GIVEN_NAME,
	INITIALS,
	PSEUDONYM,
	GERNERAL_QUALIFIER,
	DISTINGUISHED_NAME
};
static char* names[] =
{
	"CN=",
	"C=",
	"O=",
	"OU=",
	"ST=",
	"L=",
	"E=",
	"DC=",
	"DNQUALIFIER=",
	"SERIALNUMBER=",
	"SN=",
	"TITLE=",
	"GIVENNAME=",
	"INITIALS=",
	"PSEUDONYM=",
	"GERNERAL_QUALIFIER=",
	"DN="
};
static char* NAME_SEP = ", ";
INLINE NH_UTILITY(int, find_name_by_oid)(_IN_ unsigned int* oid, _IN_ size_t count)
{
	int i;
	for (i = 0; i < 17; i++) if (NH_match_oid(oid, count, oid_names[i], sizeof(oid_names[i]) / sizeof(unsigned int))) return i;
	return -1;
}
INLINE NH_UTILITY(jstring, make_rfc2253_name)(JNIEnv *env, _IN_ NH_ASN1_PNODE node)
{
	size_t len = 0;
	NH_ASN1_PNODE name, set = node->child;
	char *buffer, *szName;
	int idx;
	jstring ret = NULL;

	while (set)
	{
		if ((name = set->child) && name->child && name->child->next) len += name->child->next->valuelen + 20;
		set = set->next;
	}
	if (!(buffer = (char*) malloc(len)))
	{
		throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		return NULL;
	}
	memset(buffer, 0, len);
	set = node->child;
	while (set)
	{
		if ((name = set->child) && name->child && name->child->next && (idx = find_name_by_oid((unsigned int*) name->child->value, name->child->valuelen)) > -1)
		{
			if (!(szName = (char*) malloc(name->child->next->valuelen + 1)))
			{
				throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
				free(buffer);
				return NULL;
			}
			memset(szName, 0, name->child->next->valuelen + 1);
			memcpy(szName, name->child->next->value, name->child->next->valuelen);
			strcat(buffer, names[idx]);
			strcat(buffer, szName);
			if (set->next) strcat(buffer, NAME_SEP);
			free(szName);
		}
		set = set->next;
	}
	if (!(ret = (*env)->NewStringUTF(env, buffer))) throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	free(buffer);
	return ret;
}
INLINE NH_UTILITY(char*, format)(char *buffer, _IN_ int num)
{
	sprintf(buffer, "%d", num);
	return buffer + strlen(buffer);
}
INLINE NH_UTILITY(jstring, dot)(JNIEnv *env, _IN_ unsigned char* fromC, _IN_ unsigned int* fromI, _IN_ size_t count)
{
	char *buffer, *tmp;
	jstring ret = NULL;
	size_t i;
	static int INT_LEN = 0;

	if (!INT_LEN) INT_LEN = (int) ceil(log10(INT_MAX));
	if ((buffer = (char*) malloc(count * (INT_LEN + 1))))
	{
		tmp = buffer;
		for (i = 0; i < count; i++)
		{
			tmp = format(tmp, fromC ? fromC[i] : fromI[i]);
			if (i < count - 1)
			{
				*tmp = '.';
				tmp++;
			}
		}
		if (!(ret = (*env)->NewStringUTF(env, buffer))) throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
		free(buffer);
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
	return ret;
}
NH_UTILITY(jobject, make_freak_list)(JNIEnv *env, _IN_ NH_ASN1_PNODE node)
{
	jobject list, integer, newNames, nameEntry;
	jmethodID ctor, add, valueof;
	NH_ASN1_PNODE cur = node->child;
	int tag;
	char *szString;
	jstring string;

	if (!(list = (*env)->FindClass(env, "java/util/ArrayList")) || !(integer = (*env)->FindClass(env, "java/lang/Integer")))
	{
		throw_new(env, J_CLASS_NOT_FOUND_EX, J_CLASS_NOT_FOUND_ERROR, 0);
		return NULL;
	}
	if
	(
		!(ctor = (*env)->GetMethodID(env, list, "<init>", "()V")) ||
		!(add = (*env)->GetMethodID(env, list, "add", "(Ljava/lang/Object;)Z")) ||
		!(valueof = (*env)->GetStaticMethodID(env, integer, "valueOf", "(I)Ljava/lang/Integer;"))
	)
	{
		throw_new(env, J_METH_NOT_FOUND_EX, J_METH_NOT_FOUND_ERROR, 0);
		return NULL;
	}

	if (!(newNames = (*env)->NewObject(env, list, ctor)))
	{
		throw_new(env, J_METH_NOT_FOUND_EX, J_METH_NOT_FOUND_ERROR, 0);
		return NULL;
	}
	while (cur)
	{
		if (!(nameEntry = (*env)->NewObject(env, list, ctor)))
		{
			throw_new(env, J_METH_NOT_FOUND_EX, J_METH_NOT_FOUND_ERROR, 0);
			return NULL;
		}
		tag = *cur->identifier & NH_ASN1_TAG_MASK;
		(*env)->CallObjectMethod(env, nameEntry, add, (*env)->CallStaticObjectMethod(env, integer, valueof, tag));
		switch(*cur->identifier & NH_ASN1_TAG_MASK)
		{
		case 0x00:
		case 0x03:
		case 0x05:
			(*env)->CallObjectMethod(env, nameEntry, add, get_node_encoding(env, cur));
			break;
		case 0x01:
		case 0x02:
		case 0x06:
			if (!(szString = (char*) malloc(cur->valuelen + 1)))
			{
				throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
				return NULL;
			}
			memset(szString, 0, cur->valuelen + 1);
			memcpy(szString, cur->value, cur->valuelen);
			if (!(string = (*env)->NewStringUTF(env, szString)))
			{
				throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
				free(szString);
				return NULL;
			}
			(*env)->CallObjectMethod(env, nameEntry, add, string);
			free(szString);
			break;
		case 0x04:
			if (!(string = make_rfc2253_name(env, cur))) return NULL;
			(*env)->CallObjectMethod(env, nameEntry, add, string);
			break;
		case 0x07:
			if (!(string = dot(env, (unsigned char*) cur->value, NULL, cur->valuelen))) return NULL;
			(*env)->CallObjectMethod(env, nameEntry, add, string);
			break;
		case 0x08:
			if (!(string = dot(env, NULL, (unsigned int*) cur->value, cur->valuelen))) return NULL;
			(*env)->CallObjectMethod(env, nameEntry, add, string);
			break;
		default:
			throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, 0);
			return NULL;
		}
		(*env)->CallObjectMethod(env, newNames, add, nameEntry);
		cur = cur->next;
	}
	return newNames;
}
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSubjectAltNames
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jobject ret = NULL;

	if (NH_SUCCESS(rv = hHandler->hCert->subject_alt_names(hHandler->hCert, &node)))
	{
		if (node) ret = make_freak_list(env, node);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetIssuerAltNames
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jobject ret = NULL;

	if (NH_SUCCESS(rv = hHandler->hCert->issuer_alt_names(hHandler->hCert, &node)))
	{
		if (node) ret = make_freak_list(env, node);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetTBSCertificate
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_node_encoding(env, ((JNH_CERTIFICATE_HANDLER) handle)->hCert->hParser->root->child);
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetIssuerUniqueID
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jbyteArray ret = NULL;

	if (NH_SUCCESS(rv = hHandler->hCert->issuer_id(hHandler->hCert, &node)))
	{
		if (node) ret = get_node_contents(env, node);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSubjectUniqueID
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jbyteArray ret = NULL;

	if (NH_SUCCESS(rv = hHandler->hCert->subject_id(hHandler->hCert, &node)))
	{
		if (node) ret = get_node_contents(env, node);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}


/** ******************************
 *  Certificate interface
 *  ******************************/
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetEncoded
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	jbyteArray ret = NULL;

	if ((ret = (*env)->NewByteArray(env, hHandler->len))) (*env)->SetByteArrayRegion(env, ret, 0L, hHandler->len, hHandler->encoding);
	else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	return ret;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixVerify
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong certHandle,
	jlong keyHandle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) certHandle;
	NH_ASN1_PNODE pubkey = (NH_ASN1_PNODE) keyHandle;
	NH_RV rv = hHandler->hCert->verify(hHandler->hCert, pubkey);
	switch (G_ERROR(rv))
	{
	case NH_OK:
		break;
	case NH_RSA_VERIFY_ERROR:
		throw_new(env, J_SIGNATURE_EX, J_SIGNATURE_ERROR, rv);
		break;
	case NH_UNSUPPORTED_MECH_ERROR:
		throw_new(env, J_UNSUP_MECH_EX, J_UNSUP_MECH_ERROR, rv);
		break;
	default:
		throw_new(env, J_CERTIFICATE_EX, J_CERT_PARSE_ERROR, rv);
	}
}


/** ******************************
 *  X509Extension interface
 *  ******************************/
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetExtension
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jintArray oid
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node, ext;
	jsize oidlen;
	jint *OID;
	NH_RV rv;
	jbyteArray ret = NULL;

	oidlen = (*env)->GetArrayLength(env, oid);
	if ((OID = (*env)->GetIntArrayElements(env, oid, NULL)))
	{
		if
		(
			(node = hHandler->hCert->hParser->sail
			(
				hHandler->hCert->hParser->root,
				((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 9))
			) &&
			NH_SUCCESS(rv = hHandler->hCert->find_extension(hHandler->hCert, (unsigned int*) OID, oidlen, node, &ext))
		)
		{
			if (ext)
			{
				if ((node = hHandler->hCert->hParser->sail(ext, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) ret = get_node_encoding(env, node);
				else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, 0);
			}
		}
		else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, 0);
		(*env)->ReleaseIntArrayElements(env, oid, OID, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

INLINE NH_UTILITY(jobject, get_extensions_oids)
(
	JNIEnv *env,
	_IN_ NH_ASN1_PARSER_HANDLE hParser,
	_IN_ NH_ASN1_PNODE from,
	_IN_ unsigned int where,
	int critical
)
{
	NH_ASN1_PNODE node;
	jobject ret = NULL, cls;
	jmethodID ctor, add;
	jintArray value;

	if (ASN_IS_PRESENT(from) && (node = hParser->sail(from, where)))
	{
		if
		(
			(cls = (*env)->FindClass(env, "java/util/HashSet")) &&
			(ctor = (*env)->GetMethodID(env, cls, "<init>", "()V")) &&
			(add = (*env)->GetMethodID(env, cls, "add", "(Ljava/lang/Object;)Z")) &&
			(ret = (*env)->NewObject(env, cls, ctor))
		)
		{
			while (node)
			{
				if
				(
					(critical && ASN_IS_PRESENT(node->child->next) && *(unsigned char*) node->child->next->value) ||
					(!critical && (!ASN_IS_PRESENT(node->child->next) || !*(unsigned char*) node->child->next->value))
				)
				{
					if (!(value = (*env)->NewIntArray(env, node->child->valuelen)))
					{
						throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
						return NULL;
					}
					(*env)->SetIntArrayRegion(env, value, 0L, node->child->valuelen, (jint*) node->child->value);
					(*env)->CallObjectMethod(env, ret, add, value);
				}
				node = node->next;
			}
		}
		else throw_new(env, J_CLASS_NOT_FOUND_EX, J_CLASS_NOT_FOUND_ERROR, 0);
	}
	return ret;
}


JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetCriticalExtensionOIDs
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv = NH_OK;
	jobject ret = NULL;

	if
	(
		(node = hHandler->hCert->hParser->sail(hHandler->hCert->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 9))) &&
		NH_SUCCESS(rv = hHandler->hCert->map_extensions(hHandler->hCert, node))
	)	ret = get_extensions_oids(env, hHandler->hCert->hParser, node, NH_PARSE_SOUTH | 2, TRUE);
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetNonCriticalExtensionOIDs
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv = NH_OK;
	jobject ret = NULL;

	if
	(
		(node = hHandler->hCert->hParser->sail(hHandler->hCert->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 9))) &&
		NH_SUCCESS(rv = hHandler->hCert->map_extensions(hHandler->hCert, node))
	)	ret = get_extensions_oids(env, hHandler->hCert->hParser, node, NH_PARSE_SOUTH | 2, FALSE);
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}


/** ******************************
 *  NharuPKIBRParser interface
 *  ******************************/
INLINE NH_UTILITY(jlong, parse_pkibr_extension)(JNIEnv *env, _IN_ unsigned char *buffer, _IN_ size_t size)
{
	NH_RV rv;
	JNH_PKIBR_HANDLER hHandler = NULL;

	if ((hHandler = (JNH_PKIBR_HANDLER) malloc(sizeof(JNH_PKIBR_HANDLER_STR))))
	{
		if ((hHandler->encoding = (jbyte*) malloc(size)))
		{
			memcpy(hHandler->encoding, buffer, size);
			hHandler->len = size;
			if (NH_FAIL(rv = NH_parse_pkibr_extension((unsigned char*) hHandler->encoding, hHandler->len, &hHandler->hExt)))
			{
				free(hHandler->encoding);
				free(hHandler);
				hHandler = NULL;
				throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
			}
		}
		else
		{
			free(hHandler);
			hHandler = NULL;
			throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		}
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
	return (jlong) hHandler;
}
static NH_NODE_WAY extnValue[] = {{ NH_PARSE_ROOT, NH_ASN1_OCTET_STRING, NULL, 0 }};
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRParseEncoding
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jbyteArray encoding
)
{
	jbyte *jbuffer;
	jsize len;
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node;
	jlong ret = 0L;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if (NH_SUCCESS(rv = NH_new_parser((unsigned char*) jbuffer, len, 1, 8, &hParser)))
		{
			if
			(
				NH_SUCCESS(rv = hParser->map(hParser, extnValue, ASN_NODE_WAY_COUNT(extnValue))) &&
				NH_SUCCESS(rv = hParser->new_node(hParser->container, &node))
			)
			{
				node->parent = hParser->root;
				hParser->root->child = node;
				node->identifier = hParser->root->contents;
				rv = NHIX_parse_general_names(hParser, node);
			}
			if (NH_SUCCESS(rv)) ret = parse_pkibr_extension(env, node->identifier, node->size + node->contents - node->identifier);
			else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
			NH_release_parser(hParser);
		}
		else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRParseNode
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERTIFICATE_HANDLER hHandler = (JNH_CERTIFICATE_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv = NH_OK;
	jlong ret = 0L;

	if (NH_SUCCESS(rv = hHandler->hCert->subject_alt_names(hHandler->hCert, &node)))
	{
		ret = parse_pkibr_extension(env, node->identifier, node->size + node->contents - node->identifier);
	}
	else throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRReleaseHandle
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_PKIBR_HANDLER hHandler = (JNH_PKIBR_HANDLER) handle;

	NH_release_pkibr_extension(hHandler->hExt);
	free(hHandler->encoding);
	free(hHandler);
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetEncoding
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_PKIBR_HANDLER hHandler = (JNH_PKIBR_HANDLER) handle;
	jbyteArray ret = NULL;

	if (!(ret = (*env)->NewByteArray(env, hHandler->len))) throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	else (*env)->SetByteArrayRegion(env, ret, 0L, hHandler->len, hHandler->encoding);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetType
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_PKIBR_HANDLER hHandler = (JNH_PKIBR_HANDLER) handle;

	if (hHandler->hExt->subject_id && hHandler->hExt->subject_te && hHandler->hExt->subject_cei) return NHPKIBR_PF_CERT;
	if (hHandler->hExt->sponsor_id && hHandler->hExt->sponsor_name && hHandler->hExt->company_id && hHandler->hExt->company_cei) return NHPKIBR_PJ_CERT;
	if (hHandler->hExt->company_name && hHandler->hExt->company_id && hHandler->hExt->sponsor_name && hHandler->hExt->sponsor_id) return NHPKIBR_URL_CERT;
	return NHPKIBR_NONPKIBR_CERT;
}

INLINE NH_UTILITY(jcharArray, get_field)(JNIEnv *env, _IN_ NH_ASN1_PNODE node)
{
	char *utf;
	jstring str;
	jsize len;
	const jchar *buff;
	jcharArray ret = NULL;

	if (node)
	{
		if ((utf = (char*) malloc(node->valuelen + 1)))
		{
			memset(utf, 0, node->valuelen + 1);
			memcpy(utf, node->value, node->valuelen);
			if ((str = (*env)->NewStringUTF(env, utf)))
			{
				len = (*env)->GetStringLength(env, str);
				if ((buff = (*env)->GetStringChars(env, str, NULL)))
				{
					if ((ret = (*env)->NewCharArray(env, len))) (*env)->SetCharArrayRegion(env, ret, 0L, len, buff);
					else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
					(*env)->ReleaseStringChars(env, str, buff);
				}
				else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
			}
			else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
			free(utf);
		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
	}
	return ret;
}
JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSubjectId
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_field(env, ((JNH_PKIBR_HANDLER) handle)->hExt->subject_id);
}

JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSponsorName
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_field(env, ((JNH_PKIBR_HANDLER) handle)->hExt->sponsor_name);
}

JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetCompanyId
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_field(env, ((JNH_PKIBR_HANDLER) handle)->hExt->company_id);
}

JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSponsorId
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_field(env, ((JNH_PKIBR_HANDLER) handle)->hExt->sponsor_id);
}

JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSubjectTE
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_field(env, ((JNH_PKIBR_HANDLER) handle)->hExt->subject_te);
}

JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSubjectCEI
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_field(env, ((JNH_PKIBR_HANDLER) handle)->hExt->subject_cei);
}

JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetCompanyCEI
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_field(env, ((JNH_PKIBR_HANDLER) handle)->hExt->company_cei);
}

JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetCompanyName
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_field(env, ((JNH_PKIBR_HANDLER) handle)->hExt->company_name);
}


/** ******************************
 *  NharuX509CRL interface
 *  ******************************/
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixParseCRL(JNIEnv *env, _UNUSED_ jclass ignored, jbyteArray encoding)
{
	jbyte *jbuffer, *copy;
	jsize len, elen;
	NH_RV rv;
	NH_CRL_HANDLER hCRL;
	JNH_CRL_HANDLER hHandler = NULL;
	jlong ret = 0L;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if ((copy = (jbyte*) malloc(len)))
		{
			memcpy(copy, jbuffer, len * sizeof(jbyte));
			elen = pem_to_DER(copy, len);
			if (NH_SUCCESS(rv = NH_parse_crl((unsigned char*) copy, elen, &hCRL)))
			{
				if ((hHandler = (JNH_CRL_HANDLER) malloc(sizeof(JNH_CRL_HANDLER_STR))))
				{
					hHandler->encoding = copy;
					hHandler->len = elen;
					hHandler->hCRL = hCRL;
					ret = (jlong) hHandler;
				}
				else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
			}
			else throw_new(env, J_CRL_EX, J_CRL_PARSE_ERROR, rv);
			if (NH_FAIL(rv)) free(copy);
		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;

}

JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixReleaseCRL
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	if (hHandler)
	{
		if (hHandler->encoding) free(hHandler->encoding);
		if (hHandler->hCRL) NH_release_crl(hHandler->hCRL);
		free(hHandler);
	}
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetEncoded(JNIEnv *env, _UNUSED_ jclass ignored, jlong handle)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	jbyteArray ret = NULL;

	if ((ret = (*env)->NewByteArray(env, hHandler->len))) (*env)->SetByteArrayRegion(env, ret, 0L, hHandler->len, hHandler->encoding);
	else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	return ret;
}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetNextUpdate
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	jlong ret = 0L;

	if (ASN_IS_PRESENT(hHandler->hCRL->nextUpdate)) ret = java_mktime((NH_PTIME) hHandler->hCRL->nextUpdate->value);
	return ret;
}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetThisUpdate
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return java_mktime((NH_PTIME) ((JNH_CRL_HANDLER) handle)->hCRL->thisUpdate->value);
}

JNIEXPORT jboolean JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixIsRevoked
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jbyteArray serialNumber
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	jbyte *jbuffer;
	jsize len;
	NH_BIG_INTEGER serial;
	jboolean ret = JNI_FALSE;


	len = (*env)->GetArrayLength(env, serialNumber);
	if ((jbuffer = (*env)->GetByteArrayElements(env, serialNumber, NULL)))
	{
		serial.data = (unsigned char*) jbuffer;
		serial.length = len;
		ret = hHandler->hCRL->is_revoked(hHandler->hCRL, &serial);
		(*env)->ReleaseByteArrayElements(env, serialNumber, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetSignatureMechanism
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	NH_ASN1_PARSER_HANDLE hHandler = ((JNH_CRL_HANDLER) handle)->hCRL->hParser;
	jint ret;
	if ((ret = find_mechanism(hHandler->sail(hHandler->root, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST))) < 0) throw_new(env, J_UNSUP_MECH_EX, J_UNSUP_MECH_ERROR, 0);
	return ret;
}

JNIEXPORT jintArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetSignatureMechanismOID(JNIEnv *env, _UNUSED_ jclass ignored, jlong handle)
{
	NH_ASN1_PARSER_HANDLE hHandler = ((JNH_CRL_HANDLER) handle)->hCRL->hParser;
	jintArray ret = NULL;
	NH_ASN1_PNODE node;

	if ((node = hHandler->sail(hHandler->root, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)))
	{
		if ((ret = (*env)->NewIntArray(env, node->child->valuelen))) (*env)->SetIntArrayRegion(env, ret, 0L, node->child->valuelen, (jint*) node->child->value);
		else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	}
	else throw_new(env, J_RUNTIME_EX, J_CRL_PARSE_ERROR, 0);
	return ret;

}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetSignatureAlgParameters
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	NH_ASN1_PARSER_HANDLE hHandler = ((JNH_CRL_HANDLER) handle)->hCRL->hParser;
	NH_ASN1_PNODE node;
	jbyteArray ret = NULL;

	if ((node = hHandler->sail(hHandler->root, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)))
	{
		if (ASN_IS_PRESENT(node->child->next)) ret = get_node_encoding(env, node->child->next);
	}
	else throw_new(env, J_RUNTIME_EX, J_CRL_PARSE_ERROR, 0);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetSignature
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return encode_signature
	(
		env,
		((JNH_CRL_HANDLER) handle)->hCRL->hParser->sail(((JNH_CRL_HANDLER) handle)->hCRL->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))
	);
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetTBSCertList
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_node_encoding(env, ((JNH_CRL_HANDLER) handle)->hCRL->hParser->root->child);
}

JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetVersion
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv;
	jint ret = 0;

	if (NH_SUCCESS(rv = hHandler->hCRL->version(hHandler->hCRL, &node)))
	{
		if (ASN_IS_PRESENT(node)) ret = *(int*) node->value;
	}
	else throw_new(env, J_RUNTIME_EX, J_CRL_PARSE_ERROR, rv);
	return ++ret;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixVerify
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong crlHandle,
	jlong keyHandle
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) crlHandle;
	NH_ASN1_PNODE pubkey = (NH_ASN1_PNODE) keyHandle;
	NH_RV rv = hHandler->hCRL->verify(hHandler->hCRL, pubkey);
	switch (G_ERROR(rv))
	{
	case NH_OK:
		break;
	case NH_RSA_VERIFY_ERROR:
		throw_new(env, J_SIGNATURE_EX, J_SIGNATURE_ERROR, rv);
		break;
	case NH_UNSUPPORTED_MECH_ERROR:
		throw_new(env, J_UNSUP_MECH_EX, J_UNSUP_MECH_ERROR, rv);
		break;
	default:
		throw_new(env, J_CRL_EX, J_CRL_PARSE_ERROR, rv);
	}
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetIssuer
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_node_encoding(env, ((JNH_CRL_HANDLER) handle)->hCRL->issuer->node);
}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetIssuerNode
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return (jlong) ((JNH_CRL_HANDLER) handle)->hCRL->issuer;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetExtension
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jintArray oid
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	NH_ASN1_PNODE node, ext;
	jsize oidlen;
	jint *OID;
	NH_RV rv;
	jbyteArray ret = NULL;

	oidlen = (*env)->GetArrayLength(env, oid);
	if ((OID = (*env)->GetIntArrayElements(env, oid, NULL)))
	{
		if
		(
			(node = hHandler->hCRL->hParser->sail
			(
				hHandler->hCRL->hParser->root,
				((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 6))
			) &&
			NH_SUCCESS(rv = hHandler->hCRL->find_extension(hHandler->hCRL, (unsigned int*) OID, oidlen, node, &ext))
		)
		{
			if (ext)
			{
				if ((node = hHandler->hCRL->hParser->sail(ext, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) ret = get_node_encoding(env, node);
				else throw_new(env, J_RUNTIME_EX, J_CRL_PARSE_ERROR, 0);
			}
		}
		else throw_new(env, J_RUNTIME_EX, J_CRL_PARSE_ERROR, 0);
		(*env)->ReleaseIntArrayElements(env, oid, OID, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetCriticalExtensionOIDs
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv = NH_OK;
	jobject ret = NULL;

	if
	(
		(node = hHandler->hCRL->hParser->sail(hHandler->hCRL->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 6))) &&
		NH_SUCCESS(rv = hHandler->hCRL->map_extensions(hHandler->hCRL, node))
	)	ret = get_extensions_oids(env, hHandler->hCRL->hParser, node, NH_PARSE_SOUTH | 2, TRUE);
	else throw_new(env, J_RUNTIME_EX, J_CRL_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetNonCriticalExtensionOIDs
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	NH_ASN1_PNODE node;
	NH_RV rv = NH_OK;
	jobject ret = NULL;

	if
	(
		(node = hHandler->hCRL->hParser->sail(hHandler->hCRL->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 6))) &&
		NH_SUCCESS(rv = hHandler->hCRL->map_extensions(hHandler->hCRL, node))
	)	ret = get_extensions_oids(env, hHandler->hCRL->hParser, node, NH_PARSE_SOUTH | 2, FALSE);
	else throw_new(env, J_RUNTIME_EX, J_CRL_PARSE_ERROR, rv);
	return ret;
}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetRevoked
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jbyteArray serial
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	jbyte *jbuffer;
	jsize len;
	NH_BIG_INTEGER serialNumber;
	NH_RV rv;
	NH_ASN1_PNODE revoked;
	jlong ret = 0L;

	len = (*env)->GetArrayLength(env, serial);
	if ((jbuffer = (*env)->GetByteArrayElements(env, serial, NULL)))
	{
		serialNumber.data = (unsigned char*) jbuffer;
		serialNumber.length = len;
		if (NH_SUCCESS(rv = hHandler->hCRL->get_revoked(hHandler->hCRL, &serialNumber, &revoked)))
		{
			if (revoked) ret = (jlong) revoked;
		}
		else throw_new(env, J_RUNTIME_EX, J_CRL_PARSE_ERROR, rv);
		(*env)->ReleaseByteArrayElements(env, serial, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetRevokedCertificates
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) handle;
	NH_RV rv;
	NH_ASN1_PNODE list, node;
	jobject ret = NULL, cls, entry, instance;
	jmethodID ctor, add, entryctor;

	if (NH_SUCCESS(rv = hHandler->hCRL->revoked_certs(hHandler->hCRL, &list)))
	{
		if (ASN_IS_PRESENT(list) && (list->child))
		{
			if
			(
				(cls = (*env)->FindClass(env, "java/util/HashSet")) &&
				(ctor = (*env)->GetMethodID(env, cls, "<init>", "()V")) &&
				(add = (*env)->GetMethodID(env, cls, "add", "(Ljava/lang/Object;)Z")) &&
				(ret = (*env)->NewObject(env, cls, ctor)) &&
				(entry = (*env)->FindClass(env, "org/crypthing/security/x509/NharuCRLEntry")) &&
				(entryctor = (*env)->GetMethodID(env, entry, "<init>", "(JJ)V"))
			)
			{
				node = list->child;
				while (node)
				{
					if (!(instance = (*env)->NewObject(env, entry, entryctor, handle, (jlong) node)))
					{
						throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
						break;
					}
					else (*env)->CallObjectMethod(env, ret, add, instance);
					node = node->next;
				}

			}
			else throw_new(env, J_CLASS_NOT_FOUND_EX, J_CLASS_NOT_FOUND_ERROR, 0);
		}
	}
	else throw_new(env, J_RUNTIME_EX, J_CRL_PARSE_ERROR, rv);
	return ret;
}


/** ******************************
 *  NharuCRLEntry interface
 *  ******************************/
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetCriticalExtensionOIDs
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong parent,
	jlong handle
)
{
	return get_extensions_oids(env, ((JNH_CRL_HANDLER) parent)->hCRL->hParser, ((NH_ASN1_PNODE) handle)->child->next->next, NH_SAIL_SKIP_SOUTH, TRUE);
}

JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetNonCriticalExtensionOIDs
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong parent,
	jlong handle
)
{
	return get_extensions_oids(env, ((JNH_CRL_HANDLER) parent)->hCRL->hParser, ((NH_ASN1_PNODE) handle)->child->next->next, NH_SAIL_SKIP_SOUTH, FALSE);
}

JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetExtensions
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong parent,
	jlong handle
)
{
	JNH_CRL_HANDLER hHandler = (JNH_CRL_HANDLER) parent;
	NH_ASN1_PNODE revoked = (NH_ASN1_PNODE) handle, node;
	jobject ret = NULL, cls;
	jmethodID ctor, put;
	jintArray key;
	jbyteArray value;

	if
	(
		(cls = (*env)->FindClass(env, "java/util/HashMap")) &&
		(ctor = (*env)->GetMethodID(env, cls, "<init>", "()V")) &&
		(put = (*env)->GetMethodID(env, cls, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;")) &&
		(ret = (*env)->NewObject(env, cls, ctor))
	)
	{
		node = hHandler->hCRL->hParser->sail(revoked, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2));
		if (ASN_IS_PRESENT(node) && node->child)
		{
			node = node->child;
			while (node)
			{
				if (!(key = (*env)->NewIntArray(env, node->child->valuelen)))
				{
					throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
					break;
				}
				(*env)->SetIntArrayRegion(env, key, 0L, node->child->valuelen, (jint*) node->child->value);
				if (!(value = (*env)->NewByteArray(env, node->child->next->next->valuelen)))
				{
					throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
					break;
				}
				(*env)->SetByteArrayRegion(env, value, 0L, node->child->next->next->valuelen, (jbyte*) node->child->next->next->value);
				(*env)->CallObjectMethod(env, ret, put, key, value);
				node = node->next;
			}
		}
	}
	else throw_new(env, J_CLASS_NOT_FOUND_EX, J_CLASS_NOT_FOUND_ERROR, 0);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetEncoded
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	_UNUSED_ jlong parent,
	jlong handle
)
{
	return get_node_encoding(env, (NH_ASN1_PNODE) handle);
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetSerialNumber
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	_UNUSED_ jlong parent,
	jlong handle
)
{
	return get_node_value(env, ((NH_ASN1_PNODE) handle)->child);
}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetRevocationDate
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	_UNUSED_ jlong parent,
	jlong handle
)
{
	return java_mktime((NH_PTIME) ((NH_ASN1_PNODE) handle)->child->next->value);
}
