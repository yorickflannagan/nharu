
/** **********************************************************
 ****h* Nharu JCA Provider/X.509
 *  **********************************************************
 * NAME
 *	X.509
 *
 * AUTHOR
 *	Copyleft (C) 2015-2016 by The Crypthing Initiative
 *
 * PURPOSE
 *	JCA X.509 provider interface
 *
 * SEE ALSO
 *
 ******
 *
 *  ***********************************************************
 */

#ifndef __X509_H__
#define __X509_H__

#include "jca.h"


typedef struct JNH_CERTIFICATE_HANDLER_STR
{
	jbyte*			encoding;
	jsize				len;
	NH_CERTIFICATE_HANDLER	hCert;

} JNH_CERTIFICATE_HANDLER_STR, *JNH_CERTIFICATE_HANDLER;


#define NHIX_DSA_ALGORITHM		1L
#define NHIX_RSA_ALGORITHM		2L
#define NHIX_EC_ALGORITHM		3L


typedef struct JNH_PKIBR_HANDLER_STR
{
	jbyte*			encoding;
	jsize				len;
	NH_PKIBR_EXTENSION	hExt;

} JNH_PKIBR_HANDLER_STR, *JNH_PKIBR_HANDLER;

#define NHPKIBR_PF_CERT			1L
#define NHPKIBR_PJ_CERT			2L
#define NHPKIBR_URL_CERT		3L
#define NHPKIBR_NONPKIBR_CERT		4L

typedef struct JNH_CRL_HANDLER_STR
{
	jbyte*			encoding;
	jsize				len;
	NH_CRL_HANDLER		hCRL;

} JNH_CRL_HANDLER_STR, *JNH_CRL_HANDLER;


#ifdef __cplusplus
extern "C" {
#endif

/** ******************************
 *  NharuX509Name interface
 *  ******************************/
/*
 * Class:     org_crypthing_security_x509_NharuX509Name
 * Method:    nhixMatchName
 * Signature: (JJ)Z
 */
JNIEXPORT jboolean JNICALL Java_org_crypthing_security_x509_NharuX509Name_nhixMatchName(JNIEnv*, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Name
 * Method:    nhixGetNameHash
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509Name_nhixGetNameHash(JNIEnv*, jclass, jlong);


/** ******************************
 *  NharuPublicKey interface
 *  ******************************/
/*
 * Class:     org_crypthing_security_x509_NharuPublicKey
 * Method:    nhixGetPublicKeyInfo
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuPublicKey_nhixGetPublicKeyInfo(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPublicKey
 * Method:    nhixGetPublicKeyType
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuPublicKey_nhixGetPublicKeyType(JNIEnv*, jclass, jlong);


/** ******************************
 *  NharuRSAPublicKey interface
 *  ******************************/
/*
 * Class:     org_crypthing_security_x509_NharuRSAPublicKey
 * Method:    nhixGetRSAKeyModulus
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuRSAPublicKey_nhixGetRSAKeyModulus(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuRSAPublicKey
 * Method:    nhixGetRSAKeyPublicExponent
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuRSAPublicKey_nhixGetRSAKeyPublicExponent(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuRSAPublicKey
 * Method:    nhixGetPublicKeyHandle
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuRSAPublicKey_nhixGetPublicKeyHandle(JNIEnv*, jclass, jlong);


/** ******************************
 *  NharuX509Certificate interface
 *  ******************************/
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixParseCertificate
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixParseCertificate(JNIEnv *, jclass, jbyteArray);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixReleaseCertificate
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixReleaseCertificate(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixCheckValidity
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixCheckValidity(JNIEnv *, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetSubject
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSubject(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetIssuer
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetIssuer(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetIssuerNode
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetIssuerNode(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetSubjectNode
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSubjectNode(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixVerify
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixVerify(JNIEnv*, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetVersion
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetVersion(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetSignatureMechanismOID
 * Signature: (J)[I
 */
JNIEXPORT jintArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSignatureMechanismOID(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetSignatureAlgParameters
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSignatureAlgParameters(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetNotBefore
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetNotBefore(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetNotAfter
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetNotAfter(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetBasicConstraints
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetBasicConstraints(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetExtendedKeyUsage
 * Signature: (J)Ljava/util/List;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetExtendedKeyUsage(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetKeyUsage
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetKeyUsage(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetSerialNumber
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSerialNumber(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetSignatureMechanism
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSignatureMechanism(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetSignature
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSignature(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetExtension
 * Signature: (J[I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetExtension(JNIEnv *, jclass, jlong, jintArray);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetSubjectAltNames
 * Signature: (J)Ljava/util/Collection;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSubjectAltNames(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetIssuerAltNames
 * Signature: (J)Ljava/util/Collection;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetIssuerAltNames(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetEncoded
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetEncoded(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetTBSCertificate
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetTBSCertificate(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetIssuerUniqueID
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetIssuerUniqueID(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetSubjectUniqueID
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetSubjectUniqueID(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetCriticalExtensionOIDs
 * Signature: (J)Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetCriticalExtensionOIDs(JNIEnv *, jclass, jlong);

/*
 * Class:     org_crypthing_security_x509_NharuX509Certificate
 * Method:    nhixGetNonCriticalExtensionOIDs
 * Signature: (J)Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509Certificate_nhixGetNonCriticalExtensionOIDs(JNIEnv *, jclass, jlong);


/** ******************************
 *  NharuPKIBRParser interface
 *  ******************************/
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRParseEncoding
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRParseEncoding(JNIEnv *, jobject, jbyteArray);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRParseNode
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRParseNode(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRReleaseHandle
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRReleaseHandle(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetEncoding
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetEncoding(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetType
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetType(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetSubjectId
 * Signature: (J)[C
 */
JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSubjectId(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetSponsorName
 * Signature: (J)[C
 */
JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSponsorName(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetCompanyId
 * Signature: (J)[C
 */
JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetCompanyId(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetSponsorId
 * Signature: (J)[C
 */
JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSponsorId(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetSubjectTE
 * Signature: (J)[C
 */
JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSubjectTE(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetSubjectCEI
 * Signature: (J)[C
 */
JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetSubjectCEI(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetCompanyCEI
 * Signature: (J)[C
 */
JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetCompanyCEI(JNIEnv *, jobject, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuPKIBRParser
 * Method:    nhixPKIBRGetCompanyName
 * Signature: (J)[C
 */
JNIEXPORT jcharArray JNICALL Java_org_crypthing_security_x509_NharuPKIBRParser_nhixPKIBRGetCompanyName(JNIEnv *, jobject, jlong);


/** ******************************
 *  NharuX509CRL interface
 *  ******************************/
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixParseCRL
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixParseCRL(JNIEnv*, jclass, jbyteArray);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixReleaseCRL
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixReleaseCRL(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetEncoded
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetEncoded(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetNextUpdate
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetNextUpdate(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetThisUpdate
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetThisUpdate(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixIsRevoked
 * Signature: (J[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixIsRevoked(JNIEnv *, jclass, jlong, jbyteArray);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetSignatureMechanism
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetSignatureMechanism(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetSignatureMechanismOID
 * Signature: (J)[I
 */
JNIEXPORT jintArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetSignatureMechanismOID(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetSignatureAlgParameters
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetSignatureAlgParameters(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetSignature
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetSignature(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetTBSCertList
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetTBSCertList(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetVersion
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetVersion(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixVerify
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixVerify(JNIEnv *, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetIssuer
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetIssuer(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetIssuerNode
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetIssuerNode(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetExtension
 * Signature: (J[I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetExtension(JNIEnv *, jclass, jlong, jintArray);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetCriticalExtensionOIDs
 * Signature: (J)Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetCriticalExtensionOIDs(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetNonCriticalExtensionOIDs
 * Signature: (J)Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetNonCriticalExtensionOIDs(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixGetRevoked
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetRevoked(JNIEnv *, jclass, jlong, jbyteArray);
/*
 * Class:     org_crypthing_security_x509_NharuX509CRL
 * Method:    nhixgetRevokedCertificates
 * Signature: (J)Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuX509CRL_nhixGetRevokedCertificates(JNIEnv *, jclass, jlong);


/** ******************************
 *  NharuCRLEntry interface
 *  ******************************/
/*
 * Class:     org_crypthing_security_x509_NharuCRLEntry
 * Method:    nhixGetCriticalExtensionOIDs
 * Signature: (JJ)Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetCriticalExtensionOIDs(JNIEnv *, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuCRLEntry
 * Method:    nhixGetNonCriticalExtensionOIDs
 * Signature: (JJ)Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetNonCriticalExtensionOIDs(JNIEnv *, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuCRLEntry
 * Method:    nhixGetExtensions
 * Signature: (JJ)Ljava/util/Map;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetExtensions(JNIEnv *, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuCRLEntry
 * Method:    nhixGetEncoded
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetEncoded(JNIEnv *, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuCRLEntry
 * Method:    nhixGetSerialNumber
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetSerialNumber(JNIEnv *, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_x509_NharuCRLEntry
 * Method:    nhixGetRevocationDate
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_x509_NharuCRLEntry_nhixGetRevocationDate(JNIEnv *, jclass, jlong, jlong);


#ifdef __cplusplus
}
#endif


#endif /* __X509_H__ */
