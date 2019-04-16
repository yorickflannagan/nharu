#include "pki-issue.h"
#include <string.h>


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
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
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
	},
	{	/* version */
		((NH_PARSE_WEST | 2) << 8) | NH_SAIL_SKIP_SOUTH,
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
	{	/* Name */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		pkix_x500_rdn_map,
		PKIX_X500_RDN_COUNT
	},
	{	/* validity */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
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
	{	/* Name */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		pkix_x500_rdn_map,
		PKIX_X500_RDN_COUNT
	},
	{	/* subjectPublicKeyInfo */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* algorithm */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* subjectPublicKey */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_BIT_STRING,
		NULL,
		0
	},
	{	/* issuerUniqueID */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
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
#define __NH_SKI_SET			(__NH_VERSION_SET << 8)
#define __NH_KEYUSAGE_SET		(__NH_VERSION_SET << 9)
#define __NH_ALTNAME_SET		(__NH_VERSION_SET << 10)
#define __NH_EXTKEYUSAGE_SET		(__NH_VERSION_SET << 11)
#define __NH_CDP_SET			(__NH_VERSION_SET << 12)
#define __NH_WELLFORMED_TBS		0x1FFF
#define __IS_SET(_a, _b)		(((_a) & (_b)) == (_a))
#define __PATH_TO_EXTENSIONS		((NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 9) << 8) | NH_SAIL_SKIP_SOUTH)
INLINE static NH_RV __add_child(_IN_ NH_ASN1_ENCODER_HANDLE hEncoder, _IN_ NH_ASN1_PNODE pCurrent, _IN_ unsigned char tag)
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
			NH_SUCCESS(rv = __add_child(hEncoder->hHandler, node, node->knowledge & NH_ASN1_TAG_MASK))
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
static NH_RV __add_name(_IN_ NH_ASN1_ENCODER_HANDLE hEncoder, _IN_ NH_ASN1_PNODE pCurrent, _IN_ NH_NAME pName)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if
	(
		NH_SUCCESS(rv = __add_child(hEncoder, pCurrent, NH_ASN1_SET)) &&
		NH_SUCCESS(rv = (node = pCurrent->child) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = __add_child(hEncoder, node, NH_ASN1_SEQUENCE)) &&
		NH_SUCCESS(rv = (node = node->child) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = __add_child(hEncoder, node, NH_ASN1_OBJECT_ID)) &&
		NH_SUCCESS(rv = (node = node->child) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = hEncoder->put_objectid(hEncoder, node, pName->pOID->pIdentifier, pName->pOID->uCount, FALSE)) &&
		NH_SUCCESS(rv = __add_next(hEncoder, node, NH_ASN1_PRINTABLE_STRING)) &&
		NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL)
	)	rv = hEncoder->put_printable_string(hEncoder, node, pName->szValue, strlen(pName->szValue));
	return rv;
}
static NH_RV __put_name(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ unsigned int uPath, _IN_ NH_NAME *pName, _IN_ size_t ulCount)
{
	NH_RV rv;
	NH_ASN1_PNODE node;
	size_t i;

	if
	(
		NH_SUCCESS(rv = pName && ulCount > 0 ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (node = hEncoder->hHandler->sail(hEncoder->hHandler->root, uPath)) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = __add_name(hEncoder->hHandler, node, pName[0]))
	)	i = 1;
	while (NH_SUCCESS(rv) && i < ulCount) rv = __add_name(hEncoder->hHandler, node, pName[i++]);
	return rv;
}
static NH_RV __put_issuer(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ NH_NAME *pIssuer, _IN_ size_t ulCount)
{
	NH_RV rv;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_ISSUER_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = __put_name(hEncoder, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 3), pIssuer, ulCount))
	)	hEncoder->fields |= __NH_ISSUER_SET;
	return rv;
}
static NH_RV __put_subject(_INOUT_ NH_TBSCERT_ENCODER_STR *hEncoder, _IN_ NH_NAME *pSubject, _IN_ size_t ulCount)
{
	NH_RV rv;

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_SUBJECT_SET, hEncoder->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = __put_name(hEncoder, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 5), pSubject, ulCount))
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
		if
		(
			NH_SUCCESS(rv = hEncoder->hHandler->put_generalized_time(hEncoder->hHandler, node, szNotBefore, strlen(szNotBefore))) &&
			NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			*node->identifier = NH_ASN1_GENERALIZED_TIME;
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
static NH_RV __add_extension(_IN_ NH_ASN1_ENCODER_HANDLE hEncoder, _IN_ NH_OID pOID, _IN_ int isCritical, _IN_ NH_OCTET_SRING *pValue)
{
	NH_RV rv;
	NH_ASN1_PNODE node;
	if
	(
		NH_SUCCESS(rv = pOID && pValue ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (node = hEncoder->sail(hEncoder->root, __PATH_TO_EXTENSIONS)) ? NH_OK : NH_CANNOT_SAIL) &&
		NH_SUCCESS(rv = (node = hEncoder->add_to_set(hEncoder->container, node)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		*node->identifier = NH_ASN1_SEQUENCE;
		node->knowledge = NH_ASN1_SEQUENCE;
		if
		(
			NH_SUCCESS(rv = __add_child(hEncoder, node, NH_ASN1_OBJECT_ID)) &&
			NH_SUCCESS(rv = (node = node->child) ? NH_OK : NH_CANNOT_SAIL) &&
			NH_SUCCESS(rv = hEncoder->put_objectid(hEncoder, node, pOID->pIdentifier, pOID->uCount, FALSE))
		)
		{
			if (isCritical)
			{
				if
				(
					NH_SUCCESS(rv = __add_next(hEncoder, node, NH_ASN1_BOOLEAN)) &&
					NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL)
				)	rv = hEncoder->put_boolean(hEncoder, node, CK_TRUE);
			}
			if
			(
				NH_SUCCESS(rv) &&
				NH_SUCCESS(rv = __add_next(hEncoder, node, NH_ASN1_OCTET_STRING)) &&
				NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL)
			)	rv = hEncoder->put_octet_string(hEncoder, node, pValue->data, pValue->length);
		}
	}
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
					if (NH_SUCCESS(rv = __add_extension(hTBS->hHandler, &oid, FALSE, &extValue))) hTBS->fields |= __NH_AKI_SET;
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
	NH_OID_STR oid = { ski_oid, SKI_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_SKI_SET, hTBS->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = __add_extension(hTBS->hHandler, &oid, FALSE, pValue))
	)	hTBS->fields |= __NH_SKI_SET;
	return rv;
}
static NH_RV __put_key_usage(_INOUT_ NH_TBSCERT_ENCODER_STR *hTBS, _IN_ NH_OCTET_SRING *pValue)
{
	NH_RV rv;
	NH_OID_STR oid = { key_usage_oid, KEYUSAGE_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_KEYUSAGE_SET, hTBS->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = __add_extension(hTBS->hHandler, &oid, TRUE, pValue))
	)	hTBS->fields |= __NH_KEYUSAGE_SET;
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
		NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL)
	)	rv = hEncoder->put_octet_string(hEncoder, node, pValue->szValue, strlen(pValue->szValue));
	return rv;
}
static NH_RV __put_subject_altname(_INOUT_ NH_TBSCERT_ENCODER_STR *hTBS, _IN_ NH_OTHER_NAME *pValue, _IN_ size_t ulCount)
{
	NH_RV rv;
	NH_ASN1_PNODE ext;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	size_t uSize, i = 1;
	unsigned char *pBuffer;
	NH_OCTET_SRING extValue = { 0, 0 };
	NH_OID_STR oid = { subject_alt_names_oid, SUBJECT_ALTNAMES_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_ALTNAME_SET, hTBS->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = pValue && ulCount > 0 ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = 	NH_new_encoder(ulCount * 4, 4096, &hEncoder))
	)
	{
		if
		(
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, __pkix_general_names_map, ASN_NODE_WAY_COUNT(__pkix_general_names_map), &ext)) &&
			NH_SUCCESS(rv = (ext = ext->child) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			*ext->identifier = NH_asn_get_tag(__OTHER_NAME_KNOWLEDGE);
			rv = __add_other_name(hEncoder, ext, pValue[0]);
			while (NH_SUCCESS(rv) && i < ulCount)
			{
				if
				(
					NH_SUCCESS(rv = __add_next(hEncoder, ext, NH_asn_get_tag(__OTHER_NAME_KNOWLEDGE))) &&
					NH_SUCCESS(rv = (ext = ext->next) ? NH_OK : NH_CANNOT_SAIL)
				)	rv = __add_other_name(hEncoder, ext, pValue[i++]);
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
					if (NH_SUCCESS(rv = __add_extension(hTBS->hHandler, &oid, FALSE, &extValue))) hTBS->fields |= __NH_ALTNAME_SET;
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
	NH_RV rv;
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
				NH_SUCCESS(rv = hEncoder->put_boolean(hEncoder, ext, CK_TRUE)) &&
				NH_SUCCESS(rv = (uSize = hEncoder->encoded_size(hEncoder, hEncoder->root)) > 0 ? NH_OK : NH_UNEXPECTED_ENCODING) &&
				NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pBuffer)))
				{
					extValue.data = pBuffer;
					extValue.length = uSize;
					if (NH_SUCCESS(rv = __add_extension(hTBS->hHandler, &oid, FALSE, &extValue))) hTBS->fields |= __NH_AKI_SET;
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
	NH_RV rv;
	NH_ASN1_PNODE ext;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	size_t uSize, i = 0;
	unsigned char *pBuffer;
	NH_OCTET_SRING extValue = { 0, 0 };
	NH_OID_STR oid = { aki_oid, AKI_OID_COUNT };

	if
	(
		NH_SUCCESS(rv = !__IS_SET(__NH_EXTKEYUSAGE_SET, hTBS->fields) ? NH_OK : NH_ISSUE_ALREADY_PUT_ERROR) &&
		NH_SUCCESS(rv = pValues && ulCount > 0 ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = 	NH_new_encoder(ulCount * 3, 1024, &hEncoder))
	)
	{
		if
		(
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, pkix_cert_ext_key_usage_map, PKIX_EXT_KEYUSAGE_MAP_COUNT, &ext)) &&
			NH_SUCCESS(rv = (ext = ext->child) ? NH_OK : NH_CANNOT_SAIL)
		)
		{

			*ext->identifier = NH_ASN1_OBJECT_ID;
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
					if (NH_SUCCESS(rv = __add_extension(hTBS->hHandler, &oid, FALSE, &extValue))) hTBS->fields |= __NH_EXTKEYUSAGE_SET;
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
		NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_IA5_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_6 | NH_ASN1_EXPLICIT_BIT,
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
		if
		(
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, __cdp_map, ASN_NODE_WAY_COUNT(__cdp_map), &ext)) &&
			NH_SUCCESS(rv = (ext = ext->child) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			*ext->identifier = NH_ASN1_SEQUENCE;
			szURI = pValues;
			while (NH_SUCCESS(rv) && *szURI)
			{
				if
				(
					NH_SUCCESS(rv = (node = hEncoder->add_to_set(hEncoder->container, ext)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR) &&
					NH_SUCCESS(rv = hEncoder->chart_from(hEncoder, node, __distribution_point_map, ASN_NODE_WAY_COUNT(__distribution_point_map))) &&
					NH_SUCCESS(rv = (node = hEncoder->sail(node, (NH_PARSE_SOUTH | 4))) ? NH_OK : NH_CANNOT_SAIL) &&
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
					if (NH_SUCCESS(rv = __add_extension(hTBS->hHandler, &oid, FALSE, &extValue))) hTBS->fields |= __NH_CDP_SET;
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
	return __add_extension(hEncoder->hHandler, pOID, isCritical, pValue);
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
			NH_SUCCESS(rv = NH_new_encoder(128, 4096, &hOut->hHandler)) &&
			NH_SUCCESS(rv = hEncoder->chart(hEncoder, __tbscert_map, sizeof(__tbscert_map), &node)) &&
			NH_SUCCESS(rv = (node = hEncoder->sail(hEncoder->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 9))) ? NH_OK : NH_CANNOT_SAIL)
		)
		{
			*node->identifier = node->knowledge & NH_ASN1_TAG_MASK;
			if (NH_SUCCESS(rv = (node = hEncoder->add_child(hEncoder->container, node)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
			{
				*node->identifier = NH_ASN1_SEQUENCE;
				node->knowledge = NH_ASN1_SEQUENCE;
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