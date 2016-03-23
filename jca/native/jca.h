
/** **********************************************************
 ****h* Nharu JCA Provider/Provider
 *  **********************************************************
 * NAME
 *	Provider
 *
 * AUTHOR
 *	Copyleft (C) 2015-2016 by The Crypthing Initiative
 *
 * PURPOSE
 *	JCA provider basics
 *
 * NOTES
 *	Third party pieces of software:
 *		Cryptographic primitives implementation by OpenSSl 1.0.1 at www.openssl.org
 *		Base 64 conversion: libb64 by Chris Venter at http://sourceforge.net/projects/libb64
 *		CRC32 checksum: slicing-by-8 by Intel Corporation at http://slicing-by-8.sourceforge.net/
 *
 * SEE ALSO
 *
 ******
 *
 *  ***********************************************************
 */

#ifndef __JCA_H__
#define __JCA_H__

#if defined(__GNUC__)	/* To pass pointers to and from Java we must do some questionable things... */
	#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
	#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	#pragma GCC diagnostic ignored "-Wlong-long"
#endif

#include <jni.h>
#include "pkibr.h"

/** ****************************
 *  Java magic numbers
 *  ****************************/
#define INTEGER_MAX_VALUE			0x7fffffff
#define NHIX_NONEwithRSA_ALGORITHM		1
#define NHIX_MD2withRSA_ALGORITHM		2
#define NHIX_MD5withRSA_ALGORITHM		3
#define NHIX_SHA1withRSA_ALGORITHM		4
#define NHIX_SHA256withRSA_ALGORITHM	5
#define NHIX_SHA384withRSA_ALGORITHM	6
#define NHIX_SHA512withRSA_ALGORITHM	7
#define NHIX_NONEwithDSA_ALGORITHM		8
#define NHIX_SHA1withDSA_ALGORITHM		9
#define NHIX_NONEwithECDSA_ALGORITHM	10
#define NHIX_SHA1withECDSA_ALGORITHM	11
#define NHIX_SHA256withECDSA_ALGORITHM	12
#define NHIX_SHA384withECDSA_ALGORITHM	13
#define NHIX_SHA512withECDSA_ALGORITHM	14


/** ****************************
 *  Java Exceptions
 *  ****************************/
#define J_DEREF_ERROR			"Could not dereference Java type"
#define J_NEW_ERROR			"Could not instantiate Java type"
#define J_PARSE_ERROR			"An unexpected error has occurred during parsing"
#define J_OUTOFMEM_ERROR		"Out of memory error"
#define J_CERT_PARSE_ERROR		"Could not parse certificate"
#define J_CERT_EXPIRE__ERROR		"Certificate has expired"
#define J_CERT_NOT_VALID_ERROR	"Certificate is not valid yet"
#define J_SIGNATURE_ERROR		"Signature does not match"
#define J_UNSUP_MECH_ERROR		"Unsupported mechanism"
#define J_CLASS_NOT_FOUND_ERROR	"Could not find Java class"
#define J_METH_NOT_FOUND_ERROR	"Could not find Java method"
#define J_CRL_PARSE_ERROR		"Could not parse CRL"
#define J_CMS_PARSE_ERROR		"Could not parse CMS SignedData document"
#define J_CMS_SIG_ERROR			"Invalid signature"
#define J_CMS_VALIDATE_ERROR		"Invalid CMS SignedData document"
#define J_KEY_ERROR			"Invalid cryptographic key"
#define J_CMS_SIGFAIL_ERROR		"Could not sign CMS SignedData document"

#define J_RUNTIME_EX			"java/lang/RuntimeException"
#define J_OUTOFMEM_EX			"java/lang/OutOfMemoryError"
#define J_CERTIFICATE_EX		"java/security/cert/CertificateException"
#define J_CERT_EXPIRE_EX		"java/security/cert/CertificateExpiredException"
#define J_CERT_NOT_VALID_EX		"java/security/cert/CertificateNotYetValidException"
#define J_SIGNATURE_EX			"java/security/SignatureException"
#define J_UNSUP_MECH_EX			"java/security/NoSuchAlgorithmException"
#define J_CLASS_NOT_FOUND_EX		"java/lang/ClassNotFoundException"
#define J_METH_NOT_FOUND_EX		"java/lang/NoSuchMethodException"
#define J_CRL_EX				"java/security/cert/CRLException"
#define J_CMS_PARSE_EX			"org/crypthing/security/cms/CMSParsingException"
#define J_CMS_SIG_EX			"org/crypthing/security/cms/CMSSignatureException"
#define J_CMS_VALIDATE_EX		"org/crypthing/security/cms/CMSInvalidAttributesException"
#define J_KEY_EX				"java/security/KeyException"


#define JRUNTIME_ERROR			(NH_VENDOR_DEFINED_ERROR + 1)	/* NH_RV that means could not instantiate Java object */
#define JCLASS_ACCESS_ERROR		(NH_VENDOR_DEFINED_ERROR + 2)	/* NH_RV that means could not access a Java class */

#ifdef __cplusplus
extern "C" {
#endif


/** ****************************
 *  Utilities
 *  ****************************/
NH_UTILITY(jsize, pem_to_DER)(_INOUT_ jbyte*, _IN_ jsize);
NH_UTILITY(void, throw_new)(JNIEnv*, char*, char*, NH_RV);
NH_UTILITY(jlong, java_mktime)(_IN_ NH_PTIME);
NH_UTILITY(jbyteArray, get_node_contents)(JNIEnv*, _IN_ NH_ASN1_PNODE);
NH_UTILITY(jbyteArray, get_node_encoding)(JNIEnv*, _IN_ NH_ASN1_PNODE);
NH_UTILITY(jbyteArray, get_node_value)(JNIEnv*, _IN_ NH_ASN1_PNODE);
NH_UTILITY(jbyteArray, get_node_contents)(JNIEnv*, _IN_ NH_ASN1_PNODE);


/** ****************************
 *  Array operations
 *  ****************************/
/*
 * Class:     org_crypthing_util_NharuArrays
 * Method:    nhIsEquals
 * Signature: ([B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_crypthing_util_NharuArrays_nhIsEquals(JNIEnv*, jclass, jbyteArray, jbyteArray);
/*
 * Class:     org_crypthing_util_NharuArrays
 * Method:    nhGetHashCode
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_util_NharuArrays_nhGetHashCode(JNIEnv*, jclass, jbyteArray);
/*
 * Class:     org_crypthing_util_NharuArrays
 * Method:    nhFromBase64
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_util_NharuArrays_nhFromBase64(JNIEnv*, jclass, jbyteArray);
/*
 * Class:     org_crypthing_util_NharuArrays
 * Method:    nhToBase64
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_util_NharuArrays_nhToBase64(JNIEnv*, jclass, jbyteArray);


#ifdef __cplusplus
}
#endif


#endif /* __JCA_H__ */
