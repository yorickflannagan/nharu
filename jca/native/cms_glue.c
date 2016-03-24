#include "jcms.h"
#include "x509.h"
#include <string.h>

INLINE NH_UTILITY(jlong, nharu_to_java_handler)(JNIEnv *env, _IN_ NH_CERTIFICATE_HANDLER hCert)
{
	JNH_CERTIFICATE_HANDLER jCert;
	jlong ret = 0L;

	if ((jCert = (JNH_CERTIFICATE_HANDLER) malloc(sizeof(JNH_CERTIFICATE_HANDLER_STR))))
	{
		if ((jCert->encoding = (jbyte*) malloc(hCert->hParser->length)))
		{
			memcpy(jCert->encoding, hCert->hParser->encoding, hCert->hParser->length);
			jCert->len = hCert->hParser->length;
			jCert->hCert = hCert;
			ret = (jlong) jCert;
		}
		else
		{
			free(jCert);
			throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		}
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_crypthing_security_cms_CMSDocument_nhcmsDiscover
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jbyteArray encoding
)
{
	jbyte *jbuffer, *copy;
	jsize len, elen;
	jint ret = NH_UNKNOWN_CTYPE;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if ((copy = (jbyte*) malloc(len)))
		{
			memcpy(copy, jbuffer, len * sizeof(jbyte));
			elen = pem_to_DER(copy, len);
			ret = NH_cms_discover((unsigned char*) copy, elen);
			free(copy);
		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}


/** *********************************
 *  CMS SignedData parsing operations
 *  *********************************/
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsParseSignedData
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jbyteArray encoding
)
{
	jbyte *jbuffer, *copy;
	jsize len, elen;
	NH_RV rv;
	NH_CMS_SD_PARSER hCMS = NULL;
	JNH_CMSSD_PARSING_HANDLER hHandler;
	jlong ret = 0L;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if ((copy = (jbyte*) malloc(len)))
		{
			memcpy(copy, jbuffer, len * sizeof(jbyte));
			elen = pem_to_DER(copy, len);
			if (NH_SUCCESS(rv = NH_cms_parse_signed_data((unsigned char*) copy, elen, &hCMS)))
			{
				if ((hHandler = (JNH_CMSSD_PARSING_HANDLER) malloc(sizeof(JNH_CMSSD_PARSING_HANDLER_STR))))
				{
					hHandler->encoding = copy;
					hHandler->len = elen;
					hHandler->hCMS = hCMS;
					ret = (jlong) hHandler;
				}
				else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
			}
			else throw_new(env, J_CMS_PARSE_EX, J_CMS_PARSE_ERROR, rv);
			if (NH_FAIL(rv))
			{
				free(copy);
				if (hCMS) NH_cms_release_sd_parser(hCMS);
			}
		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsReleaseHandle
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle
)
{
	JNH_CMSSD_PARSING_HANDLER hHandler = (JNH_CMSSD_PARSING_HANDLER) handle;
	if (hHandler)
	{
		if (hHandler->hCMS) NH_cms_release_sd_parser(hHandler->hCMS);
		if (hHandler->encoding) free (hHandler->encoding);
		free(hHandler);
	}
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsGetContent(JNIEnv *env, _UNUSED_ jclass c, jlong handle)
{
	JNH_CMSSD_PARSING_HANDLER hHandler = (JNH_CMSSD_PARSING_HANDLER) handle;
	NH_ASN1_PNODE node;
	jbyteArray ret = NULL;

	if
	(
		(node = hHandler->hCMS->hParser->sail(hHandler->hCMS->encapContentInfo, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) &&
		ASN_IS_PRESENT(node) &&
		ASN_IS_PARSED(node)
	)	ret = get_node_value(env, node);
	return ret;
}

JNIEXPORT jlongArray JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsGetCertificates(JNIEnv *env, _UNUSED_ jclass c, jlong handle)
{
	JNH_CMSSD_PARSING_HANDLER hHandler = (JNH_CMSSD_PARSING_HANDLER) handle;
	NH_ASN1_PNODE node;
	jsize count = 0;
	NH_RV rv;
	NH_CERTIFICATE_HANDLER hCert;
	jlong pointer;
	jlongArray ret = NULL;

	if (hHandler->hCMS->certificates && (node = hHandler->hCMS->certificates->child))
	{
		while (node)
		{
			count++;
			node = node->next;
		}
		if ((ret = (*env)->NewLongArray(env, count)))
		{
			count = 0;
			node = hHandler->hCMS->certificates->child;
			while (node)
			{
				if (NH_SUCCESS(rv = NH_parse_certificate(node->identifier, node->size + node->contents - node->identifier, &hCert)))
				{
					pointer = nharu_to_java_handler(env, hCert);
					(*env)->SetLongArrayRegion(env, ret, count++, 1, &pointer);
				}
				else
				{
					throw_new(env, J_RUNTIME_EX, J_CERT_PARSE_ERROR, rv);
					return ret;
				}
				node = node->next;
			}
		}
		else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
	}
	return ret;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsVerify
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jlong cmsHandle,
	jint idx,
	jlong keyHandle
)
{
	JNH_CMSSD_PARSING_HANDLER hHandler = (JNH_CMSSD_PARSING_HANDLER) cmsHandle;
	NH_ASN1_PNODE pubkeyInfo = (NH_ASN1_PNODE) keyHandle;
	NH_RV rv;

	if (NH_FAIL(rv = hHandler->hCMS->verify(hHandler->hCMS, idx, pubkeyInfo))) throw_new(env, J_CMS_SIG_EX, J_CMS_SIG_ERROR, rv);
}

JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsValidate
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle,
	jbyteArray eContent
)
{
	JNH_CMSSD_PARSING_HANDLER hHandler = (JNH_CMSSD_PARSING_HANDLER) handle;
	jbyte *jbuffer;
	jsize len;
	NH_RV rv;

	len = (*env)->GetArrayLength(env, eContent);
	if ((jbuffer = (*env)->GetByteArrayElements(env, eContent, NULL)))
	{
		if (NH_FAIL(rv = hHandler->hCMS->validate(hHandler->hCMS, (unsigned char*) jbuffer, len))) throw_new(env, J_CMS_VALIDATE_EX, J_CMS_VALIDATE_ERROR, rv);
		(*env)->ReleaseByteArrayElements(env, eContent, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
}

JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsValidateAttached(JNIEnv *env, _UNUSED_ jclass c, jlong handle)
{
	JNH_CMSSD_PARSING_HANDLER hHandler = (JNH_CMSSD_PARSING_HANDLER) handle;
	NH_RV rv;
	if (NH_FAIL(rv = hHandler->hCMS->validate_attached(hHandler->hCMS))) throw_new(env, J_CMS_VALIDATE_EX, J_CMS_VALIDATE_ERROR, rv);
}

JNIEXPORT jint JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsCountSigners(_UNUSED_ JNIEnv *env, _UNUSED_ jclass c, jlong handle)
{
	return ((JNH_CMSSD_PARSING_HANDLER) handle)->hCMS->count;
}

JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSSignedData_nhcmsGetSignerCertificate
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle,
	jint idx
)
{
	JNH_CMSSD_PARSING_HANDLER hHandler = (JNH_CMSSD_PARSING_HANDLER) handle;
	NH_CMS_ISSUER_SERIAL sid;
	NH_CERTIFICATE_HANDLER hCert;
	jlong ret = 0L;

	if
	(
		NH_SUCCESS(hHandler->hCMS->get_sid(hHandler->hCMS, idx, &sid)) &&
		NH_SUCCESS(hHandler->hCMS->get_cert(hHandler->hCMS, sid, &hCert))
	)	ret = nharu_to_java_handler(env, hCert);
	return ret;
}


/** *********************************
 *  CMS SignedData building operations
 *  *********************************/
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsNewSignedDataBuilder
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jbyteArray eContent,
	jboolean attach
)
{
	jlong ret = 0L;
	jbyte *jbuffer;
	jsize len;
	NH_RV rv;
	JNH_CMS_ENCODING_HANDLER hRet;

	len = (*env)->GetArrayLength(env, eContent);
	if ((jbuffer = (*env)->GetByteArrayElements(env, eContent, NULL)))
	{
		if ((hRet = (JNH_CMS_ENCODING_HANDLER) malloc(sizeof(JNH_CMS_ENCODING_HANDLER_STR))))
		{
			if ((hRet->eContent.data = (unsigned char*) malloc(len)))
			{
				memcpy(hRet->eContent.data, jbuffer, len);
				hRet->eContent.length = len;
				if (NH_SUCCESS(rv = NH_cms_encode_signed_data(&hRet->hBuilder, &hRet->eContent)))
				{
					if (NH_SUCCESS(rv = hRet->hBuilder->data_ctype(hRet->hBuilder, attach))) ret = (jlong) hRet;
					else
					{
						NH_cms_release_sd_encoder(hRet->hBuilder);
						free(hRet->eContent.data);
						free(hRet);
						throw_new(env, J_CMS_PARSE_EX, J_CMS_PARSE_ERROR, rv);
					}
				}
				else
				{
					free(hRet->eContent.data);
					free(hRet);
					throw_new(env, J_CMS_PARSE_EX, J_CMS_PARSE_ERROR, rv);
				}
			}
			else
			{
				free(hRet);
				throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
			}

		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		(*env)->ReleaseByteArrayElements(env, eContent, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsReleaseSignedDataBuilder
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle
)
{
	JNH_CMS_ENCODING_HANDLER hHandler = (JNH_CMS_ENCODING_HANDLER) handle;
	if (hHandler)
	{
		NH_cms_release_sd_encoder(hHandler->hBuilder);
		free(hHandler->eContent.data);
		free(hHandler);
	}
}

JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsAddCert
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jlong cmsHandle,
	jlong certHandle
)
{
	JNH_CMS_ENCODING_HANDLER hHandler = (JNH_CMS_ENCODING_HANDLER) cmsHandle;
	JNH_CERTIFICATE_HANDLER jCert = (JNH_CERTIFICATE_HANDLER) certHandle;
	NH_RV rv;

	if (NH_FAIL(rv = hHandler->hBuilder->add_cert(hHandler->hBuilder, jCert->hCert))) throw_new(env, J_CMS_PARSE_EX, J_CMS_PARSE_ERROR, rv);
}

NH_RV sign_callback
(
	_IN_ NH_BLOB *data,
	_UNUSED_ _IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ void *params,
	_OUT_ unsigned char *signature,
	_INOUT_ size_t *sigSize
)
{
	JNH_RSA_CALLBACK callback = (JNH_RSA_CALLBACK) params;
	jmethodID methodID;
	jbyteArray buffer;
	jint size = 0;
	jobject ret;
	jbyte *jBuffer;
	NH_RV rv = NH_OK;

	if (!signature)
	{
		if ((methodID = (*callback->env)->GetMethodID(callback->env, callback->clazz, "signatureLength", "(Ljava/lang/String;)I")))
		{
			size = (*callback->env)->CallLongMethod(callback->env, callback->iface, methodID, callback->algorithm);
			*sigSize = size;
		}
		else rv = JCLASS_ACCESS_ERROR;
	}
	else
	{
		if ((methodID = (*callback->env)->GetMethodID(callback->env, callback->clazz, "sign", "([BLjava/lang/String;)[B")))
		{
			if ((buffer = (*callback->env)->NewByteArray(callback->env, data->length)))
			{
				(*callback->env)->SetByteArrayRegion(callback->env, buffer, 0L, data->length, (jbyte*) data->data);
				ret = (*callback->env)->CallObjectMethod(callback->env, callback->iface, methodID, buffer, callback->algorithm);
				size = (*callback->env)->GetArrayLength(callback->env, ret);
				if (*sigSize < size) rv = NH_BUF_TOO_SMALL;
				else
				{
					if ((jBuffer = (*callback->env)->GetByteArrayElements(callback->env, ret, NULL)))
					{
						memcpy(signature, jBuffer, size);
						(*callback->env)->ReleaseByteArrayElements(callback->env, ret, jBuffer, JNI_ABORT);
					}
					else rv = JRUNTIME_ERROR;
				}
			}
			else rv = JRUNTIME_ERROR;
		}
		else rv = JCLASS_ACCESS_ERROR;

	}
	return rv;
}

JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsSign
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jlong cmshandle,
	jlong certHandle,
	jint mechanism,
	jobject signer
)
{
	JNH_CMS_ENCODING_HANDLER hHandler = (JNH_CMS_ENCODING_HANDLER) cmshandle;
	JNH_CERTIFICATE_HANDLER jCert = (JNH_CERTIFICATE_HANDLER) certHandle;
	const char *algorithm;
	NH_CMS_ISSUER_SERIAL_STR sid = { NULL, NULL, NULL };
	JNH_RSA_CALLBACK_STR callback;
	NH_RV rv;

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
	callback.env = env;
	callback.algorithm = (*env)->NewStringUTF(env, algorithm);
	callback.iface = signer;
	callback.clazz = (*env)->FindClass(env, "org/crypthing/security/SignerInterface");
	if (callback.algorithm && callback.clazz)
	{
		sid.name = jCert->hCert->issuer;
		sid.serial = jCert->hCert->serialNumber;
		rv = hHandler->hBuilder->sign(hHandler->hBuilder, &sid, mechanism, sign_callback, &callback);
		if (NH_FAIL(rv)) throw_new(env, J_CMS_SIG_EX, J_CMS_SIGFAIL_ERROR, rv);
	}
	else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
}

JNIEXPORT jbyteArray JNICALL Java_org_crypthing_security_cms_CMSSignedDataBuilder_nhcmsEncode
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle
)
{
	JNH_CMS_ENCODING_HANDLER hHandler = (JNH_CMS_ENCODING_HANDLER) handle;
	unsigned char *encoding;
	size_t size;
	NH_RV rv;
	jbyteArray ret = NULL;

	size = hHandler->hBuilder->hEncoder->encoded_size(hHandler->hBuilder->hEncoder, hHandler->hBuilder->hEncoder->root);
	if ((encoding = malloc(size)))
	{
		if (NH_SUCCESS(rv = hHandler->hBuilder->hEncoder->encode(hHandler->hBuilder->hEncoder, hHandler->hBuilder->hEncoder->root, encoding)))
		{
			if ((ret = (*env)->NewByteArray(env, size))) (*env)->SetByteArrayRegion(env, ret, 0L, size, (jbyte*) encoding);
			else throw_new(env, J_RUNTIME_EX, J_NEW_ERROR, 0);
		}
		else throw_new(env, J_CMS_PARSE_EX, J_CMS_PARSE_ERROR, rv);
		free(encoding);
	}
	else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
	return ret;
}


/** ************************************
 *  CMS EnvelopedData parsing operations
 *  ************************************/
JNIEXPORT jlong JNICALL Java_org_crypthing_security_cms_CMSEnvelopedData_nhcmsParseEnvelopedData
(
	JNIEnv *env,
	_UNUSED_ jclass c,
	jbyteArray encoding
)
{
	jbyte *jbuffer, *copy;
	jsize len, elen;
	NH_RV rv;
	NH_CMS_ENV_PARSER hCMS = NULL;
	JNH_CMSENV_PARSING_HANDLER hHandler;
	jlong ret = 0L;

	len = (*env)->GetArrayLength(env, encoding);
	if ((jbuffer = (*env)->GetByteArrayElements(env, encoding, NULL)))
	{
		if ((copy = (jbyte*) malloc(len)))
		{
			memcpy(copy, jbuffer, len * sizeof(jbyte));
			elen = pem_to_DER(copy, len);
			if (NH_SUCCESS(rv = NH_cms_parse_enveloped_data((unsigned char*) copy, elen, &hCMS)))
			{
				if ((hHandler = (JNH_CMSENV_PARSING_HANDLER) malloc(sizeof(JNH_CMSENV_PARSING_HANDLER_STR))))
				{
					hHandler->encoding = copy;
					hHandler->len = elen;
					hHandler->hCMS = hCMS;
					ret = (jlong) hHandler;
				}
				else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
			}
			else throw_new(env, J_CMS_PARSE_EX, J_CMS_PARSE_ERROR, rv);
			if (NH_FAIL(rv))
			{
				free(copy);
				if (hCMS) NH_cms_release_env_parser(hCMS);
			}
		}
		else throw_new(env, J_OUTOFMEM_EX, J_OUTOFMEM_ERROR, 0);
		(*env)->ReleaseByteArrayElements(env, encoding, jbuffer, JNI_ABORT);
	}
	else throw_new(env, J_RUNTIME_EX, J_DEREF_ERROR, 0);
	return ret;

}

JNIEXPORT void JNICALL Java_org_crypthing_security_cms_CMSEnvelopedData_nhcmsReleaseHandle
(
	_UNUSED_ JNIEnv *env,
	_UNUSED_ jclass c,
	jlong handle
)
{
	JNH_CMSENV_PARSING_HANDLER hHandler = (JNH_CMSENV_PARSING_HANDLER) handle;
	if (hHandler)
	{
		if (hHandler->hCMS) NH_cms_release_env_parser(hHandler->hCMS);
		if (hHandler->encoding) free (hHandler->encoding);
		free(hHandler);
	}

}
