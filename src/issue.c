#include "pki-issue.h"
#include <string.h>

static NH_RV __add_child(_IN_ NH_ASN1_ENCODER_HANDLE hEncoder, _IN_ NH_ASN1_PNODE pCurrent, _IN_ unsigned char tag)
{
	NH_RV rv;
	NH_ASN1_PNODE pChild;
	
	if
	(
		NH_SUCCESS(rv = (pChild = hEncoder->add_child(hEncoder->container, pCurrent)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR) &&
		NH_SUCCESS(rv = hEncoder->container->bite_chunk(hEncoder->container, sizeof(unsigned char*), (void*) &pChild->identifier))
	)
	{
		*pChild->identifier = tag;
		pChild->knowledge = tag;
	}
	return rv;
}
INLINE static NH_RV __add_next(_IN_ NH_ASN1_ENCODER_HANDLE hEncoder, _IN_ NH_ASN1_PNODE pCurrent, _IN_ unsigned char tag)
{
	NH_RV rv;
	NH_ASN1_PNODE pNext;
	
	if
	(
		NH_SUCCESS(rv = (pNext = hEncoder->add_next(hEncoder->container, pCurrent)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR) &&
		NH_SUCCESS(rv = hEncoder->container->bite_chunk(hEncoder->container, sizeof(unsigned char*), (void*) &pNext->identifier))
	)
	{
		*pNext->identifier = tag;
		pNext->knowledge = tag;
	}
	return rv;
}
static NH_NODE_WAY __x509_name[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SET | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_EAST,
		NH_ASN1_PRINTABLE_STRING,
		NULL,
		0
	}
};
static NH_RV __put_name(_INOUT_ NH_ASN1_ENCODER_HANDLE hHandler, _IN_ unsigned int uPath, _IN_ NH_NAME *pName, _IN_ size_t ulCount)
{
	NH_RV rv;
	NH_ASN1_PNODE node, name;
	size_t i;

	if
	(
		NH_SUCCESS(rv = pName && ulCount > 0 ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (name = hHandler->sail(hHandler->root, uPath)) ? NH_OK : NH_CANNOT_SAIL)
	)	i = 0;
	while (NH_SUCCESS(rv) && i < ulCount)
	{
		if
		(
			NH_SUCCESS(rv = (node = hHandler->add_to_set(hHandler->container, name)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR) &&
			NH_SUCCESS(rv = hHandler->chart_from(hHandler, node, __x509_name, ASN_NODE_WAY_COUNT(__x509_name))) &&
			NH_SUCCESS(rv = (node = hHandler->sail(node, NH_PARSE_SOUTH | 2)) ? NH_OK : NH_CANNOT_SAIL) &&
			NH_SUCCESS(rv = hHandler->put_objectid(hHandler, node, pName[i]->pOID->pIdentifier, pName[i]->pOID->uCount, FALSE)) &&
			NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL) &&
			NH_SUCCESS(rv = hHandler->put_printable_string(hHandler, node, pName[i]->szValue, strlen(pName[i]->szValue)))
		)	i++;
	}
	return rv;
}



static NH_RV __verify(_IN_ NH_CREQUEST_PARSER_STR *hHandler)
{
	NH_RV rv;
	NH_ASN1_PNODE pAlg, pSig, pInfo;
	CK_MECHANISM_TYPE hashAlg;

	if
	(
		NH_SUCCESS(rv = (pInfo = hHandler->hParser->sail(hHandler->hParser->root, NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
		NH_SUCCESS(rv = (pAlg = hHandler->hParser->sail(pInfo, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
		NH_SUCCESS(rv = (pSig = hHandler->hParser->sail(pInfo, NH_PARSE_EAST | 2)) ? NH_OK : NH_UNEXPECTED_ENCODING)
	)
	{
		switch(NH_oid_to_mechanism(pAlg->value, pAlg->valuelen))
		{
		case CKM_SHA256_RSA_PKCS:
			hashAlg = CKM_SHA256;
			break;
		case CKM_SHA1_RSA_PKCS:
			hashAlg = CKM_SHA_1;
			break;
		case CKM_SHA384_RSA_PKCS:
			hashAlg = CKM_SHA384;
			break;
		case CKM_SHA512_RSA_PKCS:
			hashAlg = CKM_SHA512;
			break;
		case CKM_MD5_RSA_PKCS:
			hashAlg = CKM_MD5;
			break;
		case CKM_ECDSA_SHA1:
		default: return NH_UNSUPPORTED_MECH_ERROR;
		}
		rv = NH_SUCCESS(NHIX_verify_signature(pInfo, hHandler->subjectPKInfo, hashAlg, pSig)) ? NH_OK : NH_ISSUE_INVALID_SIG_ERROR;
	}
	return rv;
}

/**
 * @brief PKCS#10 definition
 * 
 * <pre>
 *  CertificationRequest ::= SEQUENCE {
 *  	certificationRequestInfo CertificationRequestInfo,
 *  	signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
 *  	signature BIT STRING
 *  }
 *  CertificationRequestInfo ::= SEQUENCE {
 *  	version INTEGER { v1(0) } (v1,...),
 *  	subject Name,
 *  	subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *  	attributes [0] Attributes{{ CRIAttributes }}
 *  }
 *  SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
 *  	algorithm AlgorithmIdentifier {{IOSet}},
 *  	subjectPublicKey BIT STRING
 *  }
 * </pre>
 */
static NH_NODE_WAY __cert_request_info_map[] =
{
	{	/* CertificationRequestInfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* version */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* subject */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* Name */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		pkix_x500_rdn_map,
		PKIX_X500_RDN_COUNT
	},
	{	/* subjectPKInfo */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* algorithm */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* subjectPublicKey */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_BIT_STRING,
		NULL,
		0
	},
	{	/* attributes */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_SET,
		NULL,
		0
	}
};
static NH_NODE_WAY __cert_request_map[] =
{
	{	/* CertificationRequest */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* CertificationRequestInfo */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_PORTOLANI_BIT,
		__cert_request_info_map,
		ASN_NODE_WAY_COUNT(__cert_request_info_map)
	},
	{	/* signatureAlgorithm */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* signature */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_BIT_STRING,
		NULL,
		0
	}
};
static NH_CREQUEST_PARSER_STR __hRequest =
{
	NULL,
	NULL,
	NULL,
	__verify
};
NH_FUNCTION(NH_RV, NH_parse_cert_request)(_IN_ unsigned char *pBuffer, _IN_ size_t ulBuflen, _OUT_ NH_CREQUEST_PARSER *hHandle)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser = NULL;
	NH_ASN1_PNODE node;
	NH_NAME_NODE subject = NULL;
	NH_CREQUEST_PARSER hOut;

	if (NH_FAIL(rv = NH_new_parser(pBuffer, ulBuflen, 24, 1024, &hParser))) return rv;
	if (NH_SUCCESS(rv)) rv = hParser->map(hParser, __cert_request_map, ASN_NODE_WAY_COUNT(__cert_request_map));
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_bitstring(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = NHIX_parse_name(hParser, node, &subject);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(node, NH_SAIL_SKIP_EAST)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = NHIX_parse_pubkey(hParser, node);
	if (NH_SUCCESS(rv))
	{
		rv = (hOut = (NH_CREQUEST_PARSER) malloc(sizeof(NH_CREQUEST_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
		if (NH_SUCCESS(rv))
		{
			memcpy(hOut, &__hRequest, sizeof(NH_CREQUEST_PARSER_STR));
			hOut->hParser = hParser;
			hOut->subject = subject;
			hOut->subjectPKInfo = node;
			*hHandle = hOut;
		}
	}
	if (NH_FAIL(rv)) NH_release_parser(hParser);
	return rv;
}
NH_FUNCTION(void, NH_release_cert_request)(_INOUT_ NH_CREQUEST_PARSER hHandle)
{
	if (hHandle)
	{
		NH_release_parser(hHandle->hParser);
		free(hHandle);
	}
}


#define __IS_SET(_a, _b)		(((_a) & (_b)) == (_a))
#define __NH_CRVERSION_SET		1
#define __NH_CRSUBJECT_SET		(__NH_CRVERSION_SET << 1)
#define __NH_CRPUBKEY_SET		(__NH_CRVERSION_SET << 2)
#define __NH_CRSDIGN_SET		(__NH_CRVERSION_SET << 3)
#define __NH_READY_TO_SIGN		0x07
#define __NH_WELLFORMED_REQUEST	0x0F
static NH_RV __request_put_version(_INOUT_ NH_CREQUEST_ENCODER_STR *hEncoder, _IN_ unsigned int uVersion)
{
	NH_RV rv = NH_OK;
	NH_ASN1_PNODE node;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_CRVERSION_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = (node = hEncoder->hRequestInfo->root->child) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = hEncoder->hRequestInfo->put_little_integer(hEncoder->hRequestInfo, node, uVersion))
	)	hEncoder->fields |= __NH_CRVERSION_SET;	return rv;

}
static NH_RV __request_put_subject(_INOUT_ NH_CREQUEST_ENCODER_STR *hEncoder, _IN_ NH_NAME *pSubject, _IN_ size_t ulCount)
{
	NH_RV rv;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_CRSUBJECT_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = __put_name(hEncoder->hRequestInfo, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST, pSubject, ulCount))
	)	hEncoder->fields |= __NH_CRSUBJECT_SET;
	return rv;
}
static NH_RV __request_put_pubkey(_INOUT_ NH_CREQUEST_ENCODER_STR *hEncoder, _IN_ NH_RSA_PUBKEY_HANDLER hPubKey)
{
	NH_RV rv;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_CRPUBKEY_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = hPubKey->encode_info(hPubKey, hEncoder->hRequestInfo, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))
	)	hEncoder->fields |= __NH_CRPUBKEY_SET;
	return rv;	
}
static NH_RV __request_sign
(
	_INOUT_ NH_CREQUEST_ENCODER_STR *hEncoder,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ NH_CMS_SIGN_FUNCTION callback,
	_IN_ void *pParams
)
{
	CK_MECHANISM_TYPE hashAlg;
	const unsigned int *sigOID;
	size_t sigOIDCount;
	NH_RV rv;
	NH_BLOB requestInfo = { NULL, 0 }, hash = { NULL, 0 };
	NH_HASH_HANDLER hHash;
	NH_BITSTRING_VALUE_STR pString = { 0, NULL, 0 };
	NH_ASN1_PNODE node;

	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		hashAlg = CKM_SHA_1;
		sigOID = sha1WithRSAEncryption;
		sigOIDCount = NHC_SHA1_WITH_RSA_OID_COUNT;
		break;
	case CKM_SHA256_RSA_PKCS:
		hashAlg = CKM_SHA256;
		sigOID = sha256WithRSAEncryption;
		sigOIDCount = NHC_SHA256_WITH_RSA_OID_COUNT;
		break;
	case CKM_SHA384_RSA_PKCS:
		hashAlg = CKM_SHA384;
		sigOID = sha384WithRSAEncryption;
		sigOIDCount = NHC_SHA384_WITH_RSA_OID_COUNT;
		break;
	case CKM_SHA512_RSA_PKCS:
		hashAlg = CKM_SHA512;
		sigOID = sha512WithRSAEncryption;
		sigOIDCount = NHC_SHA512_WITH_RSA_OID_COUNT;
		break;
	case CKM_MD5_RSA_PKCS:
		hashAlg = CKM_MD5;
		sigOID = md5WithRSA_oid;
		sigOIDCount = NHC_MD5_WITH_RSA_OID_COUNT;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_CRSDIGN_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = hEncoder->fields == __NH_READY_TO_SIGN ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (requestInfo.length = hEncoder->hRequestInfo->encoded_size(hEncoder->hRequestInfo, hEncoder->hRequestInfo->root)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
		NH_SUCCESS(rv = (requestInfo.data = (unsigned char*) malloc(requestInfo.length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		if
		(
			NH_SUCCESS(rv = hEncoder->hRequestInfo->encode(hEncoder->hRequestInfo, hEncoder->hRequestInfo->root, requestInfo.data)) &&
			NH_SUCCESS(rv = NH_new_hash(&hHash))
		)
		{
			if
			(
				NH_SUCCESS(rv = hHash->init(hHash, hashAlg)) &&
				NH_SUCCESS(rv = hHash->update(hHash, requestInfo.data, requestInfo.length)) &&
				NH_SUCCESS(rv = hHash->finish(hHash, NULL, &hash.length)) &&
				NH_SUCCESS(rv = (hash.data = (unsigned char*) malloc(hash.length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if
				(
					NH_SUCCESS(hHash->finish(hHash, hash.data, &hash.length)) &&
					NH_SUCCESS(rv = callback(&hash, mechanism, pParams, NULL, &pString.len)) &&
					NH_SUCCESS(rv = (pString.string = (unsigned char*) malloc(pString.len)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
				)
				{
					if
					(
						NH_SUCCESS(rv = callback(&hash, mechanism, pParams, pString.string, &pString.len)) &&
						NH_SUCCESS(rv = (node = hEncoder->hRequest->root->child) ? NH_OK : NH_CANNOT_SAIL) &&
						NH_SUCCESS(rv = hEncoder->hRequest->container->bite_chunk(hEncoder->hRequest->container, requestInfo.length, (void*) &node->identifier))
					)
					{
						memcpy(node->identifier, requestInfo.data, requestInfo.length);
						node->size = requestInfo.length - ((requestInfo.data[1] & 0x80) ? ((requestInfo.data[1] & 0x7F) + 2) : 2);
						node->contents = node->identifier + (requestInfo.length - node->size);
						if
						(
							NH_SUCCESS(rv = (node = hEncoder->hRequest->sail(node,  (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL) &&
							NH_SUCCESS(rv = hEncoder->hRequest->put_objectid(hEncoder->hRequest, node, sigOID, sigOIDCount, FALSE)) &&
							NH_SUCCESS(rv = (node = hEncoder->hRequest->sail(node, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_CANNOT_SAIL) &&
							NH_SUCCESS(rv = hEncoder->hRequest->put_bitstring(hEncoder->hRequest, node, &pString))
						)	hEncoder->fields |= __NH_CRSDIGN_SET;
					}
					free(pString.string);
				}
				free(hash.data);
			}
			NH_release_hash(hHash);
		}
		free(requestInfo.data);
	}
	return rv;
}
static NH_RV __request_encode(_IN_ NH_CREQUEST_ENCODER_STR *hEncoder, _OUT_ unsigned char *pBuffer, _INOUT_ size_t *ulSize)
{
	NH_RV rv;
	size_t size;

	if
	(
		NH_SUCCESS(rv = hEncoder->fields == __NH_WELLFORMED_REQUEST ? NH_OK : NH_ISSUE_INCOMPLETEOB_ERROR) &&
		NH_SUCCESS(rv = (size = hEncoder->hRequest->encoded_size(hEncoder->hRequest, hEncoder->hRequest->root)) > 0 ? NH_OK : NH_INVALID_DER_TYPE)
	)
	{
		if (!pBuffer) *ulSize = size;
		else if (NH_SUCCESS(rv = *ulSize >= size ? NH_OK : NH_BUF_TOO_SMALL)) rv = hEncoder->hRequest->encode(hEncoder->hRequest, hEncoder->hRequest->root, pBuffer);
	}
	return rv;
}
static NH_CREQUEST_ENCODER_STR __hCertRequest =
{
	NULL,
	NULL,
	0,
	__request_put_version,
	__request_put_subject,
	__request_put_pubkey,
	__request_sign,
	__request_encode
};
NH_FUNCTION(NH_RV, NH_new_certificate_request)(_OUT_ NH_CREQUEST_ENCODER *hEncoder)
{
	NH_RV rv;
	NH_CREQUEST_ENCODER hOut;
	NH_ASN1_PNODE node;

	if (NH_SUCCESS(rv = (hOut = (NH_CREQUEST_ENCODER) malloc(sizeof(NH_CREQUEST_ENCODER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memset(hOut, 0, sizeof(NH_CREQUEST_ENCODER_STR));
		memcpy(hOut, &__hCertRequest, sizeof(__hCertRequest));
		if
		(
			NH_SUCCESS(rv = NH_new_encoder(16, 4096, &hOut->hRequestInfo)) &&
			NH_SUCCESS(rv = NH_new_encoder(8, 4096, &hOut->hRequest)) &&
			NH_SUCCESS(rv = hOut->hRequestInfo->chart(hOut->hRequestInfo, __cert_request_info_map, ASN_NODE_WAY_COUNT(__cert_request_info_map), &node)) &&
			NH_SUCCESS(rv = hOut->hRequest->chart(hOut->hRequest, __cert_request_map, ASN_NODE_WAY_COUNT(__cert_request_map), &node))
		)	*hEncoder = hOut;
		if (NH_FAIL(rv)) NH_delete_certificate_request(hOut);
	}
	return rv;
}
NH_FUNCTION(void, NH_delete_certificate_request)(_INOUT_ NH_CREQUEST_ENCODER hEncoder)
{
	if (hEncoder)
	{
		if (hEncoder->hRequestInfo) NH_release_encoder(hEncoder->hRequestInfo);
		if (hEncoder->hRequest) NH_release_encoder(hEncoder->hRequest);
		free(hEncoder);
	}
}


/* * * * * * * * * * * * * * * * * * * * *
 * X.509 Certificate encoding
 * * * * * * * * * * * * * * * * * * * * *
 */
static NH_NODE_WAY __time_map[] =
{
	{	/* utcTime */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_UTC_TIME | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	},
	{	/* generalTime */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT | NH_ASN1_GENERALIZED_TIME | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
static NH_NODE_WAY __tbscert_map[] =
{
	{	/* tbsCertificate */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* version */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT | NH_ASN1_DEFAULT_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* serialNumber */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* signature */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* issuer */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* validity */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* notBefore */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_CHOICE_BIT,
		__time_map,
		ASN_NODE_WAY_COUNT(__time_map)
	},
	{	/* notAfter */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_CHOICE_BIT,
		__time_map,
		ASN_NODE_WAY_COUNT(__time_map)
	},
	{	/* subject */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* subjectPublicKeyInfo */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* issuerUniqueID */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_BIT_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* subjectUniqueID */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_BIT_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_2 | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* extensions */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_3 | NH_ASN1_EXPLICIT_BIT | NH_ASN1_OPTIONAL_BIT | NH_ASN1_EXP_CONSTRUCTED_BIT,
		NULL,
		0
	}
};
#define __NH_VERSION_SET		1
#define __NH_SERIAL_SET			(__NH_VERSION_SET << 1)
#define __NH_SIGN_ALG_SET		(__NH_VERSION_SET << 2)
#define __NH_ISSUER_SET			(__NH_VERSION_SET << 3)
#define __NH_SUBJECT_SET		(__NH_VERSION_SET << 4)
#define __NH_VALIDITY_SET		(__NH_VERSION_SET << 5)
#define __NH_PUBKEY_SET			(__NH_VERSION_SET << 6)
#define __NH_AKI_SET			(__NH_VERSION_SET << 7)
#define __NH_KEYUSAGE_SET		(__NH_VERSION_SET << 8)
#define __NH_CDP_SET			(__NH_VERSION_SET << 9)
#define __NH_WELLFORMED_TBS		0x03FF
#define __PATH_TO_EXTENSIONS		((NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 9) << 8) | NH_SAIL_SKIP_SOUTH)
static NH_RV __put_version(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ unsigned int uVersion)
{
	NH_RV rv = NH_OK;
	NH_ASN1_PNODE node;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_VERSION_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		uVersion > 0 &&
		NH_SUCCESS(rv = (node = hEncoder->hHandler->root->child) ? NH_OK : NH_CANNOT_SAIL)
	)
	{
		*node->identifier = NH_asn_get_tag(node->knowledge);
		if
		(
			NH_SUCCESS(rv = __add_child(hEncoder->hHandler, node, NH_ASN1_INTEGER)) &&
			NH_SUCCESS(rv = (node = node->child) ? NH_OK : NH_CANNOT_SAIL)
		)	rv = hEncoder->hHandler->put_little_integer(hEncoder->hHandler, node, uVersion);
	}
	if (NH_SUCCESS(rv)) hEncoder->fields |= __NH_VERSION_SET;
	return rv;
}
static NH_RV  __put_serial(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ NH_BIG_INTEGER *pSerial)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_SERIAL_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = pSerial ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (node = hEncoder->hHandler->sail(hEncoder->hHandler->root, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = hEncoder->hHandler->put_integer(hEncoder->hHandler, node, pSerial->data, pSerial->length))
	)	hEncoder->fields |= __NH_SERIAL_SET;
	return rv;
}
static NH_RV __put_sign_alg(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ NH_OID pOid)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_SIGN_ALG_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = pOid ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (node = hEncoder->hHandler->sail(hEncoder->hHandler->root, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = hEncoder->hHandler->put_objectid(hEncoder->hHandler, node, pOid->pIdentifier, pOid->uCount, FALSE))
	)	hEncoder->fields |= __NH_SIGN_ALG_SET;
	return rv;
}
static NH_RV __put_issuer(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ NH_NAME *pIssuer, _IN_ size_t ulCount)
{
	NH_RV rv;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_ISSUER_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = __put_name(hEncoder->hHandler, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 3), pIssuer, ulCount))
	)	hEncoder->fields |= __NH_ISSUER_SET;
	return rv;
}
static NH_RV __put_subject(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ NH_NAME *pSubject, _IN_ size_t ulCount)
{
	NH_RV rv;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_SUBJECT_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = __put_name(hEncoder->hHandler, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 5), pSubject, ulCount))
	)	hEncoder->fields |= __NH_SUBJECT_SET;
	return rv;
}
static NH_RV __put_validity(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ char *szNotBefore, _IN_ char *szNotAfter)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_VALIDITY_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = szNotBefore && szNotAfter ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (node = hEncoder->hHandler->sail(hEncoder->hHandler->root, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 4) << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL)
	)
	{
		*node->identifier = NH_ASN1_GENERALIZED_TIME;
		node->knowledge = NH_ASN1_GENERALIZED_TIME;
		if
		(
			NH_SUCCESS(rv = hEncoder->hHandler->put_generalized_time(hEncoder->hHandler, node, szNotBefore, strlen(szNotBefore))) &&
			NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			*node->identifier = NH_ASN1_GENERALIZED_TIME;
			node->knowledge = NH_ASN1_GENERALIZED_TIME;
			if
			(
				NH_SUCCESS(rv = hEncoder->hHandler->put_generalized_time(hEncoder->hHandler, node, szNotAfter, strlen(szNotAfter)))
			)	hEncoder->fields |= __NH_VALIDITY_SET;
		}
	}
	return rv;
}
static NH_RV __put_pubkey(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ NH_ASN1_PNODE pPubkey)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_PUBKEY_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = pPubkey ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (node = hEncoder->hHandler->sail(hEncoder->hHandler->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 6))) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = NH_asn_clone_node(hEncoder->hHandler->container, pPubkey, &node))
	)	hEncoder->fields |= __NH_PUBKEY_SET;
	return rv;
}
static NH_RV __put_aki(_INOUT_ NH_TBSCERT_ENCODER_STR *hTBS, _IN_ NH_OCTET_SRING *pValue)
{
	NH_RV rv;
	NH_ASN1_PNODE ext;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	size_t uSize;
	unsigned char *pBuffer;
	NH_OCTET_SRING extValue = { 0, 0 };
	NH_OID_STR oid = { aki_oid, AKI_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_AKI_SET, hTBS->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = pValue ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = 	NH_new_encoder(8, 1024, &hEncoder))
	)
	{
		if
		(
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, pkix_aki_map, PKIX_AKI_MAP_COUNT, &ext)) &&
			NH_SUCCESS(rv = (ext = ext->child) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			*ext->identifier = NH_asn_get_tag(ext->knowledge);
			if
			(
				NH_SUCCESS(rv = hEncoder->put_octet_string(hEncoder, ext, pValue->data, pValue->length)) &&
				NH_SUCCESS(rv = (uSize = hEncoder->encoded_size(hEncoder, hEncoder->root)) > 0 ? NH_OK : NH_UNEXPECTED_ENCODING) &&
				NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pBuffer)))
				{
					extValue.data = pBuffer;
					extValue.length = uSize;
					if (NH_SUCCESS(rv = hTBS->put_extension(hTBS, &oid, FALSE, &extValue))) hTBS->fields |= __NH_AKI_SET;
				}
				free(pBuffer);
			}
		}
		NH_release_encoder(hEncoder);
	}
	return rv;
}
static NH_RV __put_ski(_INOUT_ NH_TBSCERT_ENCODER_STR *hTBS, _IN_ NH_OCTET_SRING *pValue)
{
	NH_RV rv;
	NH_ASN1_PNODE ext;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	size_t uSize;
	unsigned char *pBuffer;
	NH_OCTET_SRING extValue = { 0, 0 };
	NH_OID_STR oid = { ski_oid, SKI_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = pValue ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = 	NH_new_encoder(8, 1024, &hEncoder))
	)
	{
		if ( NH_SUCCESS(rv = hEncoder->chart(hEncoder, pkix_ski_map, PKIX_SKI_MAP_COUNT, &ext)))
		{
			*ext->identifier = NH_asn_get_tag(ext->knowledge);
			if
			(
				NH_SUCCESS(rv = hEncoder->put_octet_string(hEncoder, ext, pValue->data, pValue->length)) &&
				NH_SUCCESS(rv = (uSize = hEncoder->encoded_size(hEncoder, hEncoder->root)) > 0 ? NH_OK : NH_UNEXPECTED_ENCODING) &&
				NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pBuffer)))
				{
					extValue.data = pBuffer;
					extValue.length = uSize;
					rv = hTBS->put_extension(hTBS, &oid, FALSE, &extValue);
				}
				free(pBuffer);
			}
		}
		NH_release_encoder(hEncoder);
	}
	return rv;
}
static NH_NODE_WAY __key_usage[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_BIT_STRING,
		NULL,
		0
	}
};
static NH_RV __put_key_usage(_INOUT_ NH_TBSCERT_ENCODER_STR *hTBS, _IN_ NH_OCTET_SRING *pValue)
{
	NH_RV rv;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	NH_ASN1_PNODE ext;
	NH_BITSTRING_VALUE_STR string = { 0, NULL, 0 };
	size_t uSize;
	unsigned char *pBuffer;
	NH_OCTET_SRING extValue = { 0, 0 };
	NH_OID_STR oid = { key_usage_oid, KEYUSAGE_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_KEYUSAGE_SET, hTBS->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = NH_new_encoder(4, 512, &hEncoder))
	)
	{
		if (NH_SUCCESS(rv = hEncoder->chart(hEncoder, __key_usage, ASN_NODE_WAY_COUNT(__key_usage), &ext)))
		{
			string.padding = pValue->data[0];
			string.len = pValue->length - 1;
			string.string = pValue->data + 1;
			if
			(
				NH_SUCCESS(rv = hEncoder->put_bitstring(hEncoder, ext, &string)) &&
				NH_SUCCESS(rv = (uSize = hEncoder->encoded_size(hEncoder, hEncoder->root)) > 0 ? NH_OK : NH_UNEXPECTED_ENCODING) &&
				NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pBuffer)))
				{
					extValue.data = pBuffer;
					extValue.length = uSize;
					
					if (NH_SUCCESS(rv = hTBS->put_extension(hTBS, &oid, TRUE, &extValue))) hTBS->fields |= __NH_KEYUSAGE_SET;
				}
				free(pBuffer);
			}
		}
		NH_release_encoder(hEncoder);
	}
	return rv;
}
#define __OTHER_NAME_KNOWLEDGE		(NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT | NH_ASN1_EXP_CONSTRUCTED_BIT | NH_ASN1_HAS_NEXT_BIT)
#define __NAME_STRING_KNOWLEDGE		(NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT)
static NH_NODE_WAY __pkix_other_name_map[] =
{
	{
		NH_PARSE_ROOT,
		__OTHER_NAME_KNOWLEDGE,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_EAST,
		__NAME_STRING_KNOWLEDGE,
		NULL,
		0
	}
};
static NH_NODE_WAY __pkix_general_names_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		__pkix_other_name_map,
		ASN_NODE_WAY_COUNT(__pkix_other_name_map)
	}
};
INLINE static NH_RV __add_other_name(_IN_ NH_ASN1_ENCODER_HANDLE hEncoder, _INOUT_ NH_ASN1_PNODE ext, _IN_ NH_OTHER_NAME pValue)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if
	(
		NH_SUCCESS(rv = ext && pValue ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = __add_child(hEncoder, ext, NH_ASN1_OBJECT_ID)) &&
		NH_SUCCESS(rv = (node = ext->child) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = hEncoder->put_objectid(hEncoder, node, pValue->pOID->pIdentifier, pValue->pOID->uCount, FALSE)) &&
		NH_SUCCESS(rv = __add_next(hEncoder, node, NH_asn_get_tag(__NAME_STRING_KNOWLEDGE))) &&
		NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = __add_child(hEncoder, node, NH_ASN1_OCTET_STRING)) &&
		NH_SUCCESS(rv = (node = node->child) ? NH_OK : NH_CANNOT_SAIL)
	)	rv = hEncoder->put_octet_string(hEncoder, node, pValue->szValue, strlen(pValue->szValue));
	return rv;
}
static NH_RV __put_subject_altname(_INOUT_ NH_TBSCERT_ENCODER_STR *hTBS, _IN_ NH_OTHER_NAME *pValue, _IN_ size_t ulCount)
{
	NH_RV rv;
	NH_ASN1_PNODE ext;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	size_t uSize, i = 0;
	unsigned char *pBuffer;
	NH_OCTET_SRING extValue = { 0, 0 };
	NH_OID_STR oid = { subject_alt_names_oid, SUBJECT_ALTNAMES_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = pValue && ulCount > 0 ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = 	NH_new_encoder(ulCount * 4, 4096, &hEncoder))
	)
	{
		if
		(
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, __pkix_general_names_map, ASN_NODE_WAY_COUNT(__pkix_general_names_map), &ext)) &&
			NH_SUCCESS(rv = __add_child(hEncoder, ext, NH_asn_get_tag(__OTHER_NAME_KNOWLEDGE))) &&
			NH_SUCCESS(rv = (ext = ext->child) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			rv = __add_other_name(hEncoder, ext, pValue[0]);
			while (NH_SUCCESS(rv) && ++i < ulCount)
			{
				if
				(
					NH_SUCCESS(rv = __add_next(hEncoder, ext, NH_asn_get_tag(__OTHER_NAME_KNOWLEDGE))) &&
					NH_SUCCESS(rv = (ext = ext->next) ? NH_OK : NH_CANNOT_SAIL)
				)	rv = __add_other_name(hEncoder, ext, pValue[i]);
			}
			if
			(
				NH_SUCCESS(rv) &&
				NH_SUCCESS(rv = (uSize = hEncoder->encoded_size(hEncoder, hEncoder->root)) > 0 ? NH_OK : NH_UNEXPECTED_ENCODING) &&
				NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pBuffer)))
				{
					extValue.data = pBuffer;
					extValue.length = uSize;
					rv = hTBS->put_extension(hTBS, &oid, FALSE, &extValue);
				}
				free(pBuffer);
			}
		}
		NH_release_encoder(hEncoder);
	}
	return rv;
}
static NH_RV __put_basic_constraints(_INOUT_ NH_TBSCERT_ENCODER_STR *hTBS, _IN_ int isCA)
{
	NH_RV rv = NH_OK;
	NH_ASN1_PNODE ext;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	size_t uSize;
	unsigned char *pBuffer;
	NH_OCTET_SRING extValue = { 0, 0 };
	NH_OID_STR oid = { basic_constraints_oid, BASIC_CONSTRAINTS_OID_COUNT };

	if (isCA && NH_SUCCESS(rv = NH_new_encoder(8, 1024, &hEncoder)))
	{
		if
		(
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, pkix_cert_basic_constraints_map, PKIX_BASIC_CONSTRAINTS_MAP_COUNT, &ext)) &&
			NH_SUCCESS(rv = (ext = ext->child) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			*ext->identifier = NH_asn_get_tag(ext->knowledge);
			if
			(
				NH_SUCCESS(rv = hEncoder->put_boolean(hEncoder, ext, TRUE)) &&
				NH_SUCCESS(rv = (uSize = hEncoder->encoded_size(hEncoder, hEncoder->root)) > 0 ? NH_OK : NH_UNEXPECTED_ENCODING) &&
				NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pBuffer)))
				{
					extValue.data = pBuffer;
					extValue.length = uSize;
					if (NH_SUCCESS(rv = hTBS->put_extension(hTBS, &oid, FALSE, &extValue))) hTBS->fields |= __NH_AKI_SET;
				}
				free(pBuffer);
			}
		}
		NH_release_encoder(hEncoder);
	}
	return rv;
}
static NH_RV __put_extkey_usage(_INOUT_ NH_TBSCERT_ENCODER_STR *hTBS, _IN_ NH_OID *pValues, _IN_ size_t ulCount)
{
	NH_RV rv = NH_OK;
	NH_ASN1_PNODE ext;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	size_t uSize, i = 0;
	unsigned char *pBuffer;
	NH_OCTET_SRING extValue = { 0, 0 };
	NH_OID_STR oid = { aki_oid, AKI_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = pValues && ulCount > 0 ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = 	NH_new_encoder(ulCount * 3, 1024, &hEncoder))
	)
	{
		if
		(
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, pkix_cert_ext_key_usage_map, PKIX_EXT_KEYUSAGE_MAP_COUNT, &ext)) &&
			NH_SUCCESS(rv = __add_child(hEncoder, ext, NH_ASN1_OBJECT_ID)) &&
			NH_SUCCESS(rv = (ext = ext->child) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			rv = hEncoder->put_objectid(hEncoder, ext, pValues[0]->pIdentifier, pValues[0]->uCount, FALSE);
			while (NH_SUCCESS(rv) && ++i < ulCount)
			{
				if
				(
					NH_SUCCESS(rv = __add_next(hEncoder, ext, NH_ASN1_OBJECT_ID)) &&
					NH_SUCCESS(rv = (ext = ext->next) ? NH_OK : NH_CANNOT_SAIL)
				)	rv = hEncoder->put_objectid(hEncoder, ext, pValues[i]->pIdentifier, pValues[i]->uCount, FALSE);
			}
			if
			(
				NH_SUCCESS(rv) &&
				NH_SUCCESS(rv = (uSize = hEncoder->encoded_size(hEncoder, hEncoder->root)) > 0 ? NH_OK : NH_UNEXPECTED_ENCODING) &&
				NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pBuffer)))
				{
					extValue.data = pBuffer;
					extValue.length = uSize;
					rv = hTBS->put_extension(hTBS, &oid, FALSE, &extValue);
				}
				free(pBuffer);
			}
		}
		NH_release_encoder(hEncoder);
	}
	return rv;
}
static NH_NODE_WAY __distribution_point_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_IA5_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_6,
		NULL,
		0
	}
};
static NH_NODE_WAY __cdp_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		__distribution_point_map,
		ASN_NODE_WAY_COUNT(__distribution_point_map)
	}
};
static unsigned int __cpd_oid[] = { 2, 5, 29, 31 };
#define __CDP_OID_COUNT					4
static NH_RV __put_cdp(_INOUT_ NH_TBSCERT_ENCODER_STR *hTBS, char *pValues)
{
	NH_RV rv;
	NH_ASN1_PNODE ext, node;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	char *szURI;
	size_t uSize;
	unsigned char *pBuffer;
	NH_OCTET_SRING extValue = { 0, 0 };
	NH_OID_STR oid = { __cpd_oid, __CDP_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_CDP_SET, hTBS->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = pValues ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = 	NH_new_encoder(16, 2048, &hEncoder))
	)
	{
		if (NH_SUCCESS(rv = hEncoder->chart(hEncoder, __cdp_map, ASN_NODE_WAY_COUNT(__cdp_map), &ext)))
		{
			szURI = pValues;
			while (NH_SUCCESS(rv) && *szURI)
			{
				if
				(
					NH_SUCCESS(rv = (node = hEncoder->add_to_set(hEncoder->container, ext)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR) &&
					NH_SUCCESS(rv = hEncoder->chart_from(hEncoder, node, __distribution_point_map, ASN_NODE_WAY_COUNT(__distribution_point_map))) &&
					NH_SUCCESS(rv = (node = hEncoder->sail(node, (NH_PARSE_SOUTH | 3))) ? NH_OK : NH_CANNOT_SAIL) &&
					NH_SUCCESS(rv = hEncoder->put_ia5_string(hEncoder, node, szURI, strlen(szURI)))
				)	szURI += strlen(szURI) + 1;
			}
			if
			(
				NH_SUCCESS(rv) &&
				NH_SUCCESS(rv = (uSize = hEncoder->encoded_size(hEncoder, hEncoder->root)) > 0 ? NH_OK : NH_UNEXPECTED_ENCODING) &&
				NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pBuffer)))
				{
					extValue.data = pBuffer;
					extValue.length = uSize;
					if (NH_SUCCESS(rv = hTBS->put_extension(hTBS, &oid, FALSE, &extValue))) hTBS->fields |= __NH_CDP_SET;
				}
				free(pBuffer);
			}
		}
		NH_release_encoder(hEncoder);
	}
	return rv;
}
static NH_RV __put_extension(_IN_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ NH_OID pOID, _IN_ int isCritical, _IN_ NH_OCTET_SRING *pValue)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if
	(
		NH_SUCCESS(rv = pOID && pValue ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (node = hEncoder->hHandler->sail(hEncoder->hHandler->root, __PATH_TO_EXTENSIONS)) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = (node = hEncoder->hHandler->add_to_set(hEncoder->hHandler->container, node)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR) &&
		NH_SUCCESS(rv = hEncoder->hHandler->chart_from(hEncoder->hHandler, node, pkix_extension_map, PKIX_EXTENSION_MAP_COUNT)) &&
		NH_SUCCESS(rv = (node = node->child) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = hEncoder->hHandler->put_objectid(hEncoder->hHandler, node, pOID->pIdentifier, pOID->uCount, FALSE)) &&
		NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL)
	)
	{
		if (isCritical)
		{
			hEncoder->hHandler->register_optional(node);
			rv = hEncoder->hHandler->put_boolean(hEncoder->hHandler, node, TRUE);
		}
		if
		(
			NH_SUCCESS(rv) &&
			NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL)
		)	rv = hEncoder->hHandler->put_octet_string(hEncoder->hHandler, node, pValue->data, pValue->length);
	}
	return rv;
}
static NH_RV __encode(_IN_ NH_TBSCERT_ENCODER_STR *hEncoder, _OUT_ unsigned char *pBuffer, _INOUT_ size_t *ulSize)
{
	NH_RV rv;
	size_t size;

	if
	(
		NH_SUCCESS(rv = hEncoder->fields == __NH_WELLFORMED_TBS ? NH_OK : NH_ISSUE_INCOMPLETEOB_ERROR) &&
		NH_SUCCESS(rv = (size = hEncoder->hHandler->encoded_size(hEncoder->hHandler, hEncoder->hHandler->root)) > 0 ? NH_OK : NH_INVALID_DER_TYPE)
	)
	{
		if (!pBuffer) *ulSize = size;
		else if (NH_SUCCESS(rv = *ulSize >= size ? NH_OK : NH_BUF_TOO_SMALL)) rv = hEncoder->hHandler->encode(hEncoder->hHandler, hEncoder->hHandler->root, pBuffer);
	}
	return rv;	
}
static NH_TBSCERT_ENCODER_STR __hTBSCertificate =
{
	NULL,
	0,

	__put_version,
	__put_serial,
	__put_sign_alg,
	__put_issuer,
	__put_subject,
	__put_validity,
	__put_pubkey,
	__put_aki,
	__put_ski,
	__put_key_usage,
	__put_subject_altname,
	__put_basic_constraints,
	__put_extkey_usage,
	__put_cdp,
	__put_extension,
	__encode
};
NH_FUNCTION(NH_RV, NH_new_tbscert_encoder)(_OUT_ NH_TBSCERT_ENCODER *hHandler)
{
	NH_RV rv;
	NH_ASN1_ENCODER_HANDLE hEncoder = NULL;
	NH_ASN1_PNODE node;
	NH_TBSCERT_ENCODER hOut = NULL;

	if (NH_SUCCESS(rv = (hOut = (NH_TBSCERT_ENCODER) malloc(sizeof(NH_TBSCERT_ENCODER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memcpy(hOut, &__hTBSCertificate, sizeof(NH_TBSCERT_ENCODER_STR));
		if
		(
			NH_SUCCESS(rv = NH_new_encoder(64, 4096, &hEncoder)) &&
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, __tbscert_map, ASN_NODE_WAY_COUNT(__tbscert_map), &node)) &&
			NH_SUCCESS(rv = (node = hEncoder->sail(hEncoder->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 9))) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			*node->identifier = NH_asn_get_tag(node->knowledge);
			if
			(
				NH_SUCCESS(rv = (node = hEncoder->add_child(hEncoder->container, node)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR) &&
				NH_SUCCESS(rv = hEncoder->container->bite_chunk(hEncoder->container, sizeof(unsigned char*), (void*) &node->identifier))
			)
			{
				*node->identifier = NH_ASN1_SEQUENCE;
				node->knowledge = NH_ASN1_SEQUENCE;
				hOut->hHandler = hEncoder;
				*hHandler = hOut;
			}
		}
	}
	if (NH_FAIL(rv))
	{
		if (hEncoder) NH_release_encoder(hEncoder);
		if (hOut) free(hOut);
	}
	return rv;
}
NH_FUNCTION(void, NH_delete_tbscert_encoder)(_INOUT_ NH_TBSCERT_ENCODER hHandler)
{
	if (hHandler)
	{
		if (hHandler->hHandler) NH_release_encoder(hHandler->hHandler);
		free(hHandler);
	}
}



static NH_RV __sign
(
	_IN_ NH_CERT_ENCODER_STR *hHandler,
	_IN_ NH_TBSCERT_ENCODER hCert,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ NH_CMS_SIGN_FUNCTION callback,
	_IN_ void *pParams
)
{
	NH_RV rv;
	const unsigned int *sigOID;
	size_t sigOIDCount, uSize, uSigsize;
	CK_MECHANISM_TYPE hashAlg;
	unsigned char *pBuffer, *pSignature;
	NH_HASH_HANDLER hHash;
	NH_BLOB hash = { NULL, 0 };
	NH_BITSTRING_VALUE_STR pString = { 0, NULL, 0 };
	NH_ASN1_PNODE node;

	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		hashAlg = CKM_SHA_1;
		sigOID = sha1WithRSAEncryption;
		sigOIDCount = NHC_SHA1_WITH_RSA_OID_COUNT;
		break;
	case CKM_SHA256_RSA_PKCS:
		hashAlg = CKM_SHA256;
		sigOID = sha256WithRSAEncryption;
		sigOIDCount = NHC_SHA256_WITH_RSA_OID_COUNT;
		break;
	case CKM_SHA384_RSA_PKCS:
		hashAlg = CKM_SHA384;
		sigOID = sha384WithRSAEncryption;
		sigOIDCount = NHC_SHA384_WITH_RSA_OID_COUNT;
		break;
	case CKM_SHA512_RSA_PKCS:
		hashAlg = CKM_SHA512;
		sigOID = sha512WithRSAEncryption;
		sigOIDCount = NHC_SHA512_WITH_RSA_OID_COUNT;
		break;
	case CKM_MD5_RSA_PKCS:
		hashAlg = CKM_MD5;
		sigOID = md5WithRSA_oid;
		sigOIDCount = NHC_MD5_WITH_RSA_OID_COUNT;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if
	(
		NH_SUCCESS(rv = (hCert && hCert->fields == __NH_WELLFORMED_TBS && callback) ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = hCert->encode(hCert, NULL, &uSize)) &&
		NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		if
		(
			NH_SUCCESS(rv = hCert->encode(hCert, pBuffer, &uSize)) &&
			NH_SUCCESS(rv = NH_new_hash(&hHash))
		)
		{
			if
			(
				NH_SUCCESS(rv = hHash->init(hHash, hashAlg)) &&
				NH_SUCCESS(rv = hHash->update(hHash, pBuffer, uSize)) &&
				NH_SUCCESS(rv = hHash->finish(hHash, NULL, &hash.length)) &&
				NH_SUCCESS(rv = (hash.data = (unsigned char*) malloc(hash.length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if
				(
					NH_SUCCESS(hHash->finish(hHash, hash.data, &hash.length)) &&
					NH_SUCCESS(rv = callback(&hash, mechanism, pParams, NULL, &uSigsize)) &&
					NH_SUCCESS(rv = (pSignature = (unsigned char*) malloc(uSigsize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
				)
				{
					if
					(
						NH_SUCCESS(rv = callback(&hash, mechanism, pParams, pSignature, &uSigsize)) &&
						NH_SUCCESS(rv = (node = hHandler->hEncoder->root->child) ? NH_OK : NH_CANNOT_SAIL) &&
						NH_SUCCESS(rv = hHandler->hEncoder->container->bite_chunk(hHandler->hEncoder->container, uSize, (void*) &node->identifier))
					)
					{
						pString.string = pSignature;
						pString.len = uSigsize;
						memcpy(node->identifier, pBuffer, uSize);
						node->size = uSize - ((pBuffer[1] & 0x80) ? ((pBuffer[1] & 0x7F) + 2) : 2);
						node->contents = node->identifier + (uSize - node->size);
						if
						(
							NH_SUCCESS(rv = (node = hHandler->hEncoder->sail(node, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL) &&
							NH_SUCCESS(rv = hHandler->hEncoder->put_objectid(hHandler->hEncoder, node, sigOID, sigOIDCount, FALSE)) &&
							NH_SUCCESS(rv = (node = hHandler->hEncoder->sail(node, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_CANNOT_SAIL)
						)	rv = hHandler->hEncoder->put_bitstring(hHandler->hEncoder, node, &pString);
					}
					free(pSignature);
				}
				free(hash.data);
			}
			NH_release_hash(hHash);
		}
		free(pBuffer);
	}
	return rv;
}
static NH_NODE_WAY __certificate_map[] =
{
	{	/* Certificate */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* tbsCertificate */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* signatureAlgorithm */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE  | NH_ASN1_HAS_NEXT_BIT,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* signatureValue */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_BIT_STRING,
		NULL,
		0
	}
};
static NH_CERT_ENCODER_STR __hCertificate =
{
	NULL,
	__sign
};
NH_FUNCTION(NH_RV, NH_new_cert_encoder)(_OUT_ NH_CERT_ENCODER *hHandler)
{
	NH_RV rv;
	NH_ASN1_ENCODER_HANDLE hEncoder = NULL;
	NH_ASN1_PNODE node;
	NH_CERT_ENCODER hOut = NULL;
	

	if (NH_SUCCESS(rv = (hOut = (NH_CERT_ENCODER) malloc(sizeof(NH_CERT_ENCODER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memcpy(hOut, &__hCertificate, sizeof(NH_CERT_ENCODER_STR));
		if
		(
			NH_SUCCESS(rv = NH_new_encoder(4, 4096, &hEncoder)) &&
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, __certificate_map, ASN_NODE_WAY_COUNT(__certificate_map), &node))
		)
		{
			hOut->hEncoder = hEncoder;
			*hHandler = hOut;
		}
	}
	if (NH_FAIL(rv))
	{
		if (hEncoder) NH_release_encoder(hEncoder);
		if (hOut) free(hOut);
	}
	return rv;
}
NH_FUNCTION(void, NH_delete_cert_encoder)(_INOUT_ NH_CERT_ENCODER hHandler)
{
	if (hHandler)
	{
		if (hHandler->hEncoder) NH_release_encoder(hHandler->hEncoder);
		free(hHandler);
	}
}