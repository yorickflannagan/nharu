
#ifndef __VERSION_H__
#define __VERSION_H__

#include <jni.h>
#include "jca.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     org_crypthing_security_provider_NharuProvider
 * Method:    getNativeVersion
 * Signature: (J)java/lang/String;
 */

JNIEXPORT jstring JNICALL Java_org_crypthing_security_provider_Version_getNativeVersion(JNIEnv*, jclass);

const char *NHARU_getVersion();

#ifdef __cplusplus
}
#endif


#endif /* __VERSION_H__ */