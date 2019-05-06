
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


typedef struct JNH_CMSSD_PARSING_HANDLER_STR
{
	jbyte*		encoding;
	jsize			len;
	NH_CMS_SD_PARSER	hCMS;

} JNH_CMSSD_PARSING_HANDLER_STR, *JNH_CMSSD_PARSING_HANDLER;

typedef struct JNH_CMS_ENCODING_HANDLER_STR
{
	NH_BLOB		eContent;
	NH_CMS_SD_ENCODER	hBuilder;

} JNH_CMS_ENCODING_HANDLER_STR, *JNH_CMS_ENCODING_HANDLER;

typedef struct JNH_CMSENV_PARSING_HANDLER_STR
{
	jbyte*		encoding;
	jsize			len;
	NH_CMS_ENV_PARSER	hCMS;

} JNH_CMSENV_PARSING_HANDLER_STR, *JNH_CMSENV_PARSING_HANDLER;

typedef struct JNH_CMSENV_ENCODING_HANDLER_STR
{
	NH_BLOB			eContent;
	NH_CMS_ENV_ENCODER	hBuilder;

} JNH_CMSENV_ENCODING_HANDLER_STR, *JNH_CMSENV_ENCODING_HANDLER;


#ifdef __cplusplus
extern "C" {
#endif


/*
 * Class:     org_crypthing_security_cms_CMSDocument
 * Method:    nhcmsDiscover
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_org_crypthing_security_cms_CMSDocument_nhcmsDiscover(JNIEnv *, jclass, jbyteArray);


/** *********************************
 *  CMS SignedData parsing operations
 *  *********************************/
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
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsGetSignerIdentifier
 * Signature: (JI)Lorg/crypthing/security/cms/SignerIdentifier;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsGetSignerIdentifier(JNIEnv*, jclass, jlong, jint);
/*
 * Class:     org_crypthing_security_cms_CMSSignedData
 * Method:    nhcmsHasCertificates
 * Signature: (J)Z
 */
JNIEXPORT jboolean JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsHasCertificates(JNIEnv*, jclass, jlong);



/** *********************************
 *  CMS SignedData building operations
 *  *********************************/
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
 * Signature: (JJILorg/crypthing/security/cms/SignerInterface;)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsSign(JNIEnv *, jclass, jlong, jlong, jint, jobject);
/*
 * Class:     org_crypthing_security_cms_CMSSignedDataBuilder
 * Method:    nhcmsEncode
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsEncode(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSSignedDataBuilder
 * Method:    nhcmsNewEmptySignedData
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsNewEmptySignedData(JNIEnv*, jclass);



/** ************************************
 *  CMS EnvelopedData parsing operations
 *  ************************************/
/*
 * Class:     org_crypthing_security_cms_CMSEnvelopedData
 * Method:    nhcmsParseEnvelopedData
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSEnvelopedData_nhcmsParseEnvelopedData(JNIEnv *, jclass, jbyteArray);
/*
 * Class:     org_crypthing_security_cms_CMSEnvelopedData
 * Method:    nhcmsReleaseHandle
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSEnvelopedData_nhcmsReleaseHandle(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSEnvelopedData
 * Method:    getRID
 * Signature: (J)Lorg/crypthing/security/cms/IssuerAndSerialNumber;
 */
JNIEXPORT jobject JNICALL Java_org_crypthing_security_cms_CMSEnvelopedData_getRID(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSEnvelopedData
 * Method:    nhcmsDecrypt
 * Signature: (JLorg/crypthing/security/DecryptInterface;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_cms_CMSEnvelopedData_nhcmsDecrypt(JNIEnv *, jclass, jlong, jobject);


/** *************************************
 *  CMS EnvelopedData building operations
 *  *************************************/
/*
 * Class:     org_crypthing_security_cms_CMSEnvelopedDataBuilder
 * Method:    nhcmsNewEnvelopedDataBuilder
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSEnvelopedDataBuilder_nhcmsNewEnvelopedDataBuilder(JNIEnv *, jclass, jbyteArray);
/*
 * Class:     org_crypthing_security_cms_CMSEnvelopedDataBuilder
 * Method:    nhcmsReleaseenvelopedDataBuilder
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSEnvelopedDataBuilder_nhcmsReleaseEnvelopedDataBuilder(JNIEnv *, jclass, jlong);
/*
 * Class:     org_crypthing_security_cms_CMSEnvelopedDataBuilder
 * Method:    nhcmsEncrypt
 * Signature: (JIII)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSEnvelopedDataBuilder_nhcmsEncrypt(JNIEnv *, jclass, jlong, jint, jint, jint);
/*
 * Class:     org_crypthing_security_cms_CMSEnvelopedDataBuilder
 * Method:    nhcmsAddKeyTransRecip
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSEnvelopedDataBuilder_nhcmsAddKeyTransRecip(JNIEnv *, jclass, jlong, jlong, jint);
/*
 * Class:     org_crypthing_security_cms_CMSEnvelopedDataBuilder
 * Method:    nhcmsEncode
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_cms_CMSEnvelopedDataBuilder_nhcmsEncode(JNIEnv *, jclass, jlong);


#ifdef __cplusplus
}
#endif


#endif /* __JCMS_H__ */
