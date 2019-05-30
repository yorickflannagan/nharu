/**
 * @file jissue.h
 * @author yorick.flannagan@gmail.com
 * @brief Support for certificate issuing
 * @version 1.3.0
 * @date 2019-04-11
 * 
 * @copyright Copyleft (C) 2015-2019 by The Crypthing Initiative
 * 
 */
#ifndef __JISSUE_H__
#define __JISSUE_H__

#include "jca.h"


typedef struct JCERT_REQUEST_HANDLER_STR
{
	jbyte*			encoding;
	jsize				len;
	NH_CREQUEST_PARSER	hCert;

} JCERT_REQUEST_HANDLER_STR, *JCERT_REQUEST_HANDLER;

typedef struct JNH_CERT_ENCODER_STR
{
	NH_TBSCERT_ENCODER	hTBS;
	NH_CERT_ENCODER		hCert;

} JNH_CERT_ENCODER_STR, *JNH_CERT_ENCODER;


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequest
 * Method:    nhCertParseRequest
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertParseRequest(JNIEnv*, jclass, jbyteArray);

/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequest
 * Method:    nhCertReleaseRequestParser
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertReleaseRequestParser(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequest
 * Method:    nhCertGetSubject
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertGetSubject(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequest
 * Method:    nhCertGetPubkey
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertGetPubkey(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequest
 * Method:    nhCertVerify
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertVerify(JNIEnv*, jclass, jlong);

/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceNewCertificateEncoder
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceNewCertificateEncoder(JNIEnv*, jclass);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceReleaseCertificateEncoder
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceReleaseCertificateEncoder(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetVersion
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetVersion(JNIEnv*, jclass, jlong, jint);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetSerial
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSerial(JNIEnv*, jclass, jlong, jbyteArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetSignatureAlgorithm
 * Signature: (J[I)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSignatureAlgorithm(JNIEnv*, jclass, jlong, jintArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetIssuer
 * Signature: (J[Lorg/crypthing/security/NharuX500Name;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetIssuer(JNIEnv*, jclass, jlong, jobjectArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetSubject
 * Signature: (J[Lorg/crypthing/security/NharuX500Name;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSubject(JNIEnv*, jclass, jlong, jobjectArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetValidity
 * Signature: (JLjava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetValidity(JNIEnv*, jclass, jlong, jstring, jstring);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetPubkey
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetPubkey(JNIEnv*, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetAKI
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetAKI(JNIEnv*, jclass, jlong, jbyteArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetKeyUsage
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetKeyUsage(JNIEnv*, jclass, jlong, jbyteArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetSubjectAltName
 * Signature: (J[Lorg/crypthing/security/issue/NharuOtherName;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSubjectAltName(JNIEnv*, jclass, jlong, jobjectArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetCDP
 * Signature: (J[Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetCDP(JNIEnv*, jclass, jlong, jobjectArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetBasicConstraint
 * Signature: (JZ)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetBasicConstraint(JNIEnv*, jclass, jlong, jboolean);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSetSKI
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSKI(JNIEnv*, jclass, jlong, jbyteArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceSign
 * Signature: (JILorg/crypthing/security/SignerInterface;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSign(JNIEnv*, jclass, jlong, jint, jobject);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceEncode
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceEncode(JNIEnv*, jclass, jlong);


/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequestBuilder
 * Method:    nhceNewRequestBuilder
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_issue_NharuCertificateRequestBuilder_nhceNewRequestBuilder(JNIEnv*, jclass);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequestBuilder
 * Method:    nhceReleaseRequestBuilder
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateRequestBuilder_nhceReleaseRequestBuilder(JNIEnv*, jclass, jlong);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequestBuilder
 * Method:    nhceSetSubject
 * Signature: (J[Lorg/crypthing/security/NharuX500Name;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateRequestBuilder_nhceSetSubject(JNIEnv*, jclass, jlong, jobjectArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequestBuilder
 * Method:    nhceSetPubKey
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateRequestBuilder_nhceSetPubKey(JNIEnv*, jclass, jlong, jbyteArray);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequestBuilder
 * Method:    nhceSignRequest
 * Signature: (JILorg/crypthing/security/SignerInterface;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateRequestBuilder_nhceSignRequest(JNIEnv *, jclass, jlong, jint, jobject);
/*
 * Class:     org_crypthing_security_issue_NharuCertificateRequestBuilder
 * Method:    nhceEncodeRequest
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_issue_NharuCertificateRequestBuilder_nhceEncodeRequest(JNIEnv*, jclass, jlong);


#ifdef __cplusplus
}
#endif


#endif	/* __JISSUE_H__ */