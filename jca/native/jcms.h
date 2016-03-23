
/** **********************************************************
 ****h* Nharu JCA Provider/CMS
 *  **********************************************************
 * NAME
 *	CMS
 *
 * AUTHOR
 *	Copyleft (C) 2015-2016 by The Crypthing Initiative
 *
 * PURPOSE
 *	java interface for RFC 3852 implementation
 *
 * NOTES
 *
 * SEE ALSO
 *
 ******
 *
 *  ***********************************************************
 */

#ifndef __JCMS_H__
#define __JCMS_H__

#include "jca.h"
#include "cms.h"


typedef struct JNH_CMS_PARSING_HANDLER_STR
{
	jbyte*		encoding;
	jsize			len;
	NH_CMS_SD_PARSER	hCMS;

} JNH_CMS_PARSING_HANDLER_STR, *JNH_CMS_PARSING_HANDLER;

typedef struct JNH_CMS_ENCODING_HANDLER_STR
{
	NH_BLOB		eContent;
	NH_CMS_SD_ENCODER	hBuilder;

} JNH_CMS_ENCODING_HANDLER_STR, *JNH_CMS_ENCODING_HANDLER;

typedef struct JNH_SIGNER_CALLBACK_STR
{
	JNIEnv*				env;
	jstring				algorithm;
	jobject				signer;
	jclass				clazz;

} JNH_SIGNER_CALLBACK_STR, *JNH_SIGNER_CALLBACK;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     org_crypthing_security_cms_CMSDocument
 * Method:    nhcmsDiscover
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_cms_CMSDocument_nhcmsDiscover(JNIEnv *, jclass, jbyteArray);


/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsParseSignedData
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsParseSignedData(JNIEnv *, jclass, jbyteArray);
/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsReleaseHandle
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsReleaseHandle(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsGetContent
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsGetContent(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsGetCertificates
 * Signature: (J)[J
 */
JNIEXPORT jlongArray JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsGetCertificates(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsVerify
 * Signature: (JIJ)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsVerify(JNIEnv *, jclass, jlong, jint, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsValidate
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsValidate(JNIEnv *, jclass, jlong, jbyteArray);
/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsValidateAttached
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsValidateAttached(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsCountSigners
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsCountSigners(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsGetSignerCertificate
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsGetSignerCertificate(JNIEnv *, jclass, jlong, jint);



/*
 * Class:     org_crypthing_security_cms_BlindSigner
 * Method:    nhcmsNewRSAPrivateKey
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_BlindSigner_nhcmsNewRSAPrivateKey(JNIEnv *, jclass, jbyteArray);
/*
 * Class:     org_crypthing_security_cms_BlindSigner
 * Method:    nhcmsReleaseRSAPrivateKey
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_BlindSigner_nhcmsReleaseRSAPrivateKey(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_BlindSigner
 * Method:    nhcmsRSASign
 * Signature: (J[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_cms_BlindSigner_nhcmsRSASign(JNIEnv *, jclass, jlong, jbyteArray, jint);
/*
 * Class:     org_crypthing_security_cms_BlindSigner
 * Method:    nhcmsRSASignatureLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_cms_BlindSigner_nhcmsRSASignatureLength(JNIEnv *, jclass, jlong);



/*
 * Class:     org_crypthing_security_cms_CMSSignedDataBuilder
 * Method:    nhcmsNewSignedDataBuilder
 * Signature: ([BZ)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsNewSignedDataBuilder(JNIEnv *, jclass, jbyteArray, jboolean);
/*
 * Class:     org_crypthing_security_cms_CMSSignedDataBuilder
 * Method:    nhcmsReleaseSignedDataBuilder
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsReleaseSignedDataBuilder(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSSignedDataBuilder
 * Method:    nhcmsAddCert
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsAddCert(JNIEnv *, jclass, jlong, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSSignedDataBuilder
 * Method:    nhcmsSign
 * Signature: (JILorg/crypthing/security/cms/SignerInterface;)V
 */
/*
 * Class:     org_crypthing_security_cms_CMSSignedDataBuilder
 * Method:    nhcmsSign
 * Signature: (JJILorg/crypthing/security/cms/SignerInterface;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsSign(JNIEnv *, jclass, jlong, jlong, jint, jobject);
/*
 * Class:     org_crypthing_security_cms_CMSSignedDataBuilder
 * Method:    nhcmsEncode
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsEncode(JNIEnv *, jclass, jlong);


#ifdef __cplusplus
}
#endif


#endif /* __JCMS_H__ */
