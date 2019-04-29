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
	jlong handle
)
{
	JCERT_REQUEST_HANDLER hHandler = (JCERT_REQUEST_HANDLER) handle;
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
	jlong handle
)
{
	return get_node_encoding(env, ((JCERT_REQUEST_HANDLER) handle)->hCert->subject->node);
}
JNIEXPORT jbyteArray JNICALL
Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertGetPubkey
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	return get_node_encoding(env, ((JCERT_REQUEST_HANDLER) handle)->hCert->subjectPKInfo);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateRequest_nhCertVerify
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JCERT_REQUEST_HANDLER hHandler = (JCERT_REQUEST_HANDLER) handle;
	NH_RV rv = hHandler->hCert->verify(hHandler->hCert);
	if (NH_FAIL(rv)) throw_new(env, J_SIGNATURE_EX, J_SIGNATURE_ERROR, rv);
}


JNIEXPORT jlong JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceNewCertificateEncoder
(
	JNIEnv *env,
	_UNUSED_ jclass ignored
)
{
	jlong ret = 0L;
	NH_TBSCERT_ENCODER hEncoder = NULL;
	NH_CERT_ENCODER hCert = NULL;
	JNH_CERT_ENCODER hHandler;
	NH_RV rv;

	if
	(
		NH_SUCCESS(rv = NH_new_tbscert_encoder(&hEncoder)) &&
		NH_SUCCESS(rv = NH_new_cert_encoder(&hCert)) &&
		NH_SUCCESS(rv = (hHandler = (JNH_CERT_ENCODER) malloc(sizeof(JNH_CERT_ENCODER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		hHandler->hTBS = hEncoder;
		hHandler->hCert = hCert;
		ret = (jlong) hHandler;
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, rv);
	if (NH_FAIL(rv))
	{
		if (hEncoder) NH_delete_tbscert_encoder(hEncoder);
		if (hCert) NH_delete_cert_encoder(hCert);
	}
	return ret;
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceReleaseCertificageEncoder
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	JNH_CERT_ENCODER hHandler = (JNH_CERT_ENCODER) handle;
	NH_delete_tbscert_encoder(hHandler->hTBS);
	NH_delete_cert_encoder(hHandler->hCert);
	free(hHandler);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetVersion
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jint version
)
{
	NH_RV rv;
	JNH_CERT_ENCODER hHandler = (JNH_CERT_ENCODER) handle;
	if (NH_FAIL(rv = hHandler->hTBS->put_version(hHandler->hTBS, version))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSerial
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jbyteArray value
)
{
	NH_RV rv;
	JNH_CERT_ENCODER hHandler = (JNH_CERT_ENCODER) handle;
	NH_BIG_INTEGER pSerial = { NULL, 0 };
	jsize len;
	jbyte *jbuffer;

	len = (*env)->GetArrayLength(env, value);
	if ((jbuffer = (*env)->GetByteArrayElements(env, value, NULL)))
	{
		pSerial.data = (unsigned char*) jbuffer;
		pSerial.length = len;
		if (NH_FAIL(rv = hHandler->hTBS->put_serial(hHandler->hTBS, &pSerial))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
		(*env)->ReleaseByteArrayElements(env, value, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
}

JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSignatureAlgorithm
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jintArray value
)
{
	NH_RV rv;
	JNH_CERT_ENCODER hHandler = (JNH_CERT_ENCODER) handle;
	NH_OID_STR pOID = { NULL, 0 };
	jsize len;
	jint *jbuffer;

	len = (*env)->GetArrayLength(env, value);
	if ((jbuffer = (*env)->GetIntArrayElements(env, value, NULL)))
	{
		pOID.pIdentifier = (unsigned int*) jbuffer;
		pOID.uCount = len;
		if (NH_FAIL(rv = hHandler->hTBS->put_sign_alg(hHandler->hTBS, &pOID))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
		(*env)->ReleaseIntArrayElements(env, value, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
}