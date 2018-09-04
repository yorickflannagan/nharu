#include "version.h"

JNIEXPORT jstring JNICALL Java_org_crypthing_security_provider_Version_getNativeVersion
(
	JNIEnv *env,
	_UNUSED_ jclass ignored
)
{
	jstring version = (*env)->NewStringUTF(env, NHARU_getVersion()); 
	if (!version) throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	return version;
}