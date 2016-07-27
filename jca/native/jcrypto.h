
/** **********************************************************
 ****h* Nharu JCA Provider/Cryptographic algorithms
 *  **********************************************************
 * NAME
 *	Cryptographic algorithms
 *
 * AUTHOR
 *	Copyleft (C) 2015-2016 by The Crypthing Initiative
 *
 * PURPOSE
 *	Provider cryptographic algorithms interface
 *
 ******
 *
 *  ***********************************************************
 */

#ifndef __JCRYPTO_H__
#define __JCRYPTO_H__

#include "jca.h"


#ifdef __cplusplus
extern "C" {
#endif


/** ****************************
 *  Hash implementation
 *  ****************************/
/*
 * Class:     org_crypthing_security_provider_NharuDigest
 * Method:    nhcDigest
 * Signature: ([BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_provider_NharuDigest_nhcDigest(JNIEnv*, jclass, jbyteArray, jint);


#ifdef __cplusplus
}
#endif



#endif /* __JCRYPTO_H__ */
