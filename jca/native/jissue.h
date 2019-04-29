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



typedef struct JNH_CERT_ENCODER_STR
{
	NH_TBSCERT_ENCODER	hTBS;
	NH_CERT_ENCODER		hCert;

} JNH_CERT_ENCODER_STR, *JNH_CERT_ENCODER;
/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceNewCertificateEncoder
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceNewCertificateEncoder(JNIEnv*, jclass);

/*
 * Class:     org_crypthing_security_issue_NharuCertificateEncoder
 * Method:    nhceReleaseCertificageEncoder
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceReleaseCertificageEncoder(JNIEnv*, jclass, jlong);
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


#ifdef __cplusplus
}
#endif


#endif	/* __JISSUE_H__ */