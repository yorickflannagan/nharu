#include "jissue.h"
#include <stdlib.h>
#include <string.h>


JNIEXPORT jlong JNICALL 
Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertParseRequest
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jbyteArray encoding
)
{
	NH_RV rv = NH_OK;
	jsize len, elen;
	jbyte *jbuffer, *copy = NULL;
	NH_CREQUEST_PARSER hCert = NULL;
	JCERT_REQUEST_HANDLER hHandler;
	jlong ret = 0L;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if ((copy = (jbyte*) malloc(len)))
		{
			if (*jbuffer == NH_ASN1_SEQUENCE)
			{
				memcpy(copy, jbuffer, len * sizeof(jbyte));
				elen = len;
			}
			else elen = pem_to_DER(jbuffer, len, copy);
			if (NH_SUCCESS(rv = NH_parse_cert_request((unsigned char*) copy, (size_t) elen, &hCert)))
			{
				if ((hHandler = (JCERT_REQUEST_HANDLER) malloc(sizeof(JCERT_REQUEST_HANDLER_STR))))
				{
					hHandler->encoding = copy;
					hHandler->len = elen;
					hHandler->hCert = hCert;
					ret = (jlong) hHandler;
				}
				else { throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0); rv = NH_OUT_OF_MEMORY_ERROR; }
			}
			else throw_new(env, J_CERT_ENCODING_EX, J_CERTREQ_PARSE_ERROR, rv);
		}
		else { throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0); rv = NH_OUT_OF_MEMORY_ERROR; }
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else { throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0); rv = NH_GENERAL_ERROR; }
	if (NH_FAIL(rv))
	{
		if (copy) free(copy);
		if (hCert) NH_release_cert_request(hCert);
	}
	return ret;
}

JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertReleaseRequestParser
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong hHandle
)
{
	JCERT_REQUEST_HANDLER hHandler = (JCERT_REQUEST_HANDLER) hHandle;
	if (hHandler)
	{
		if (hHandler->encoding) free (hHandler->encoding);
		if (hHandler->hCert) NH_release_cert_request(hHandler->hCert);
		free(hHandler);
	}
}

JNIEXPORT jbyteArray JNICALL
Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertGetSubject
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong hHandle
)
{
	JCERT_REQUEST_HANDLER hHandler = (JCERT_REQUEST_HANDLER) hHandle;
	jbyteArray ret = NULL;
	if (hHandler) ret = get_node_encoding(env, hHandler->hCert->subject->node);
	return ret;
}