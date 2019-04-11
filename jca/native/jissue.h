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
#include "pki-issue.h"


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

#ifdef __cplusplus
}
#endif


#endif	/* __JISSUE_H__ */