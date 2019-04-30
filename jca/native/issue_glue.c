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
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	if (NH_FAIL(rv = hHandler->put_version(hHandler, version))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
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
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	NH_BIG_INTEGER pSerial = { NULL, 0 };
	jsize len;
	jbyte *jbuffer;

	len = (*env)->GetArrayLength(env, value);
	if ((jbuffer = (*env)->GetByteArrayElements(env, value, NULL)))
	{
		pSerial.data = (unsigned char*) jbuffer;
		pSerial.length = len;
		if (NH_FAIL(rv = hHandler->put_serial(hHandler, &pSerial))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
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
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	NH_OID_STR pOID = { NULL, 0 };
	jsize len;
	jint *jbuffer;

	len = (*env)->GetArrayLength(env, value);
	if ((jbuffer = (*env)->GetIntArrayElements(env, value, NULL)))
	{
		pOID.pIdentifier = (unsigned int*) jbuffer;
		pOID.uCount = len;
		if (NH_FAIL(rv = hHandler->put_sign_alg(hHandler, &pOID))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
		(*env)->ReleaseIntArrayElements(env, value, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
}
static jboolean __get_name(JNIEnv *env, jobject jName, NH_NAME name)
{
	jclass classz;
	jfieldID fid;
	jintArray jOIDValue;
	jint *jOID;
	jsize oidLen, valueLen;
	jstring jValue;
	const char *value;
	jboolean ret = JNI_FALSE;

	classz = (*env)->GetObjectClass(env, jName);
	if ((fid = (*env)->GetFieldID(env, classz, "oid", "[I")))
	{
		jOIDValue = (jintArray)(*env)->GetObjectField(env, jName, fid);
		oidLen = (*env)->GetArrayLength(env, jOIDValue);
		if ((jOID = (*env)->GetIntArrayElements(env, jOIDValue, NULL)))
		{
			if ((fid = (*env)->GetFieldID(env, classz, "value", "Ljava/lang/String")))
			{
				jValue = (jstring)(*env)->GetObjectField(env, jName, fid);
				valueLen = (*env)->GetStringUTFLength(env, jValue);
				if ((value = (*env)->GetStringUTFChars(env, jValue, NULL)))
				{
					if ((name->pOID = (NH_OID) malloc(sizeof(NH_OID_STR))))
					{
						memset(name->pOID, 0, sizeof(NH_OID_STR));
						if ((name->pOID->pIdentifier = (unsigned int*) malloc(oidLen * sizeof(unsigned int))))
						{
							memcpy(name->pOID->pIdentifier, jOID, oidLen * sizeof(unsigned int));
							name->pOID->uCount = oidLen;
							if ((name->szValue = (char*) malloc(valueLen + 1)))
							{
								memset(name->szValue, 0, valueLen + 1);
								memcpy(name->szValue, value, valueLen);
								ret = JNI_TRUE;
							}
							else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
						}
						else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
					}
					else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
					(*env)->ReleaseStringUTFChars(env, jValue, value);
				}
				else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
			}
			else throw_new(env, J_ILLEGAL_ARG_EX, J_INVALID_ARG_ERROR, 0);
			(*env)->ReleaseIntArrayElements(env, jOIDValue, jOID, JNI_ABORT);
		}
		else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	}
	else throw_new(env, J_ILLEGAL_ARG_EX, J_INVALID_ARG_ERROR, 0);
	if (!ret && name)
	{
		if (name->pOID)			
		{
			if (name->pOID->pIdentifier) free(name->pOID->pIdentifier);
			free(name->pOID);
		}
		if (name->szValue) free(name->szValue);
	}
	return ret;
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetIssuer
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jobjectArray value
)
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	jsize len, i;
	NH_NAME *name = NULL;
	jboolean ok;

	len = (*env)->GetArrayLength(env, value);
	if (NH_SUCCESS(rv = (name = (NH_NAME*) malloc(len * sizeof(NH_NAME_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memset(name, 0, len * sizeof(NH_NAME_STR));
		for (i = 0; i < len; i++) if (!(ok = __get_name(env, (*env)->GetObjectArrayElement(env, value, i), name[i]))) break;
		if (ok) if (NH_FAIL(rv = hHandler->put_issuer(hHandler, name, len))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
		free(name);
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, rv);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSubject
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jobjectArray value
)
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	jsize len, i;
	NH_NAME *name = NULL;
	jboolean ok;

	len = (*env)->GetArrayLength(env, value);
	if (NH_SUCCESS(rv = (name = (NH_NAME*) malloc(len * sizeof(NH_NAME_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memset(name, 0, len * sizeof(NH_NAME_STR));
		for (i = 0; i < len; i++) if (!(ok = __get_name(env, (*env)->GetObjectArrayElement(env, value, i), name[i]))) break;
		if (ok) if (NH_FAIL(rv = hHandler->put_subject(hHandler, name, len))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
		free(name);
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, rv);
}
JNIEXPORT void JNICALL 
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetValidity
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jstring notBefore,
	jstring notAfter
)
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	const char *nobValue, *noaValue;

	if ((nobValue = (*env)->GetStringUTFChars(env, notBefore, NULL)))
	{
		if ((noaValue = (*env)->GetStringUTFChars(env, notAfter, NULL)))
		{
			if (NH_FAIL(rv = hHandler->put_validity(hHandler, nobValue, noaValue))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
			(*env)->ReleaseStringUTFChars(env, notAfter, noaValue);
		}
		else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
		(*env)->ReleaseStringUTFChars(env, notBefore, nobValue);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetPubkey
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jlong value
)
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	NH_ASN1_PNODE pPubkey = (NH_ASN1_PNODE) value;
	if (NH_FAIL(rv = hHandler->put_pubkey(hHandler, pPubkey))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
}
static INLINE void __set_octets(JNIEnv *env, jlong handle, jbyteArray value, NH_TBS_SETOCTET method)
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	NH_OCTET_SRING pValue = { NULL, 0 };
	jsize len;
	jbyte *jbuffer;

	len = (*env)->GetArrayLength(env, value);
	if ((jbuffer = (*env)->GetByteArrayElements(env, value, NULL)))
	{
		pValue.data = (unsigned char*) jbuffer;
		pValue.length = len;
		if (NH_FAIL(rv = method(hHandler, &pValue))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
		(*env)->ReleaseByteArrayElements(env, value, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetAKI
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jbyteArray value
)
{
	__set_octets(env, handle, value, ((JNH_CERT_ENCODER) handle)->hTBS->put_aki);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetKeyUsage
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jbyteArray value
)
{
	__set_octets(env, handle, value, ((JNH_CERT_ENCODER) handle)->hTBS->put_key_usage);
}

JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSubjectAltName
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jobjectArray value
)
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	jsize len, i;
	NH_NAME *name = NULL;
	jboolean ok;

	len = (*env)->GetArrayLength(env, value);
	if (NH_SUCCESS(rv = (name = (NH_NAME*) malloc(len * sizeof(NH_NAME_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memset(name, 0, len * sizeof(NH_NAME_STR));
		for (i = 0; i < len; i++) if (!(ok = __get_name(env, (*env)->GetObjectArrayElement(env, value, i), name[i]))) break;
		if (ok) if (NH_FAIL(rv = hHandler->put_subject_altname(hHandler, name, len))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
		free(name);
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, rv);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetCDP
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jobjectArray value
)
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	jsize len, i, size = 1;
	jstring szURI;
	char *szCDP, *pBuffer;
	const char *jBuffer;
	jboolean ok = JNI_TRUE;

	len = (*env)->GetArrayLength(env, value);
	for (i = 0; i < len; i++)
	{
		szURI = (jstring) (*env)->GetObjectArrayElement(env, value, i);
		size += (*env)->GetStringUTFLength(env, szURI) + 1;
	}
	if (NH_SUCCESS(rv = (szCDP = (char*) malloc(size)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memset(szCDP, 0, size);
		pBuffer = szCDP;
		while (ok && i < len)
		{
			szURI = (jstring) (*env)->GetObjectArrayElement(env, value, i);
			size = (*env)->GetStringUTFLength(env, szURI) + 1;
			if ((jBuffer = (*env)->GetStringUTFChars(env, szURI, NULL)))
			{
				memcpy(pBuffer, jBuffer, size);
				pBuffer += size + 1;
				(*env)->ReleaseStringUTFChars(env, szURI, jBuffer);
			}
			else { throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0); ok = JNI_FALSE; }
			i++;
		}
		if (ok && NH_FAIL(rv = hHandler->put_cdp(hHandler, szCDP))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
		free(szCDP);
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, rv);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetBasicConstraint
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jboolean value
)
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hHandler = ((JNH_CERT_ENCODER) handle)->hTBS;
	if (NH_FAIL(rv = hHandler->put_basic_constraints(hHandler, value))) throw_new(env, J_CERT_ENCODING_EX, J_TBS_PUT_ERROR, rv);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSetSKI
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jbyteArray value
)
{
	__set_octets(env, handle, value, ((JNH_CERT_ENCODER) handle)->hTBS->put_ski);
}
JNIEXPORT void JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceSign
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle,
	jint mechanism,
	jobject signer
)
{
	NH_RV rv;
	const char *algorithm;
	JNH_RSA_CALLBACK_STR params;
	JNH_CERT_ENCODER hHandler = (JNH_CERT_ENCODER) handle;

	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		algorithm = "SHA1withRSA";
		break;
	case CKM_SHA256_RSA_PKCS:
		algorithm = "SHA256withRSA";
		break;
	case CKM_SHA384_RSA_PKCS:
		algorithm = "SHA384withRSA";
		break;
	case CKM_SHA512_RSA_PKCS:
		algorithm = "SHA512withRSA";
		break;
	case CKM_MD5_RSA_PKCS:
		algorithm = "MD5withRSA";
		break;
	default:
		throw_new(env, J_UNSUP_MECH_EX, J_UNSUP_MECH_ERROR, 0);
		return;
	}
	if
	(
		(params.algorithm = (*env)->NewStringUTF(env, algorithm)) &&
		(params.clazz = (*env)->FindClass(env, "org/crypthing/security/SignerInterface"))
	)
	{
		params.env = env;
		params.iface = signer;
		rv = hHandler->hCert->sign(hHandler->hCert, hHandler->hTBS, mechanism, sign_callback, &params);
		if (NH_FAIL(rv)) throw_new(env, J_SIGNATURE_EX, J_SIGN_CERT_ERROR, rv);
	}
	else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
}
JNIEXPORT jbyteArray JNICALL
Java_org_crypthing_security_issue_NharuCertificateEncoder_nhceEncode
(
	JNIEnv *env,
	_UNUSED_ jclass ignored,
	jlong handle
)
{
	NH_RV rv;
	JNH_CERT_ENCODER hHandler = (JNH_CERT_ENCODER) handle;
	size_t size;
	unsigned char *pBuffer;
	jbyteArray ret = NULL;

	size = hHandler->hCert->hEncoder->encoded_size(hHandler->hCert->hEncoder, hHandler->hCert->hEncoder->root);
	if (NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(size)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		if
		(
			NH_SUCCESS(rv = hHandler->hCert->hEncoder->encode(hHandler->hCert->hEncoder, hHandler->hCert->hEncoder->root, pBuffer)) &&
			NH_SUCCESS(rv = (ret = (*env)->NewByteArray(env, size)) ? NH_OK : JRUNTIME_ERROR)
		)	(*env)->SetByteArrayRegion(env, ret, 0L, size, (jbyte*) pBuffer);
		else throw_new(env, J_CERT_ENCODING_EX, J_CERT_ENCODING_ERROR, rv);
		free(pBuffer);
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, rv);
	return ret;
}