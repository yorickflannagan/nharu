/**
 * @file pfx.c
 * @author yorick.flannagan@gmail.com
 * 
 * @brief PKCS #12 parsing implementation
 * @see https://tools.ietf.org/html/rfc7292
 * @version 0.1
 * @date 2020-03-03
 * 
 * @copyright Copyleft (c) 2020 by The Crypthing Initiative. All rigths reversed.
 * 
 */
#include "pfx.h"
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wlong-long"
#endif
#include <openssl/pkcs12.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

/**
 * PFX ::= SEQUENCE {
 * 	version     INTEGER {v3(3)}(v3,...),
 * 	authSafe    ContentInfo,
 * 	macData     MacData OPTIONAL
 * }
 * ContentInfo ::= SEQUENCE {
 * 	contentType ContentType, -- id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }
 * 	content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 * ContentType ::= OBJECT IDENTIFIER
 * MacData ::= SEQUENCE {
 * 	mac         DigestInfo,
 * 	macSalt     OCTET STRING,
 * 	iterations  INTEGER DEFAULT 1	-- Note: The default is for historical reasons and its use is deprecated.
 * }
 * DigestInfo ::= SEQUENCE {
 * 	digestAlgorithm DigestAlgorithmIdentifier,
 * 	digest Digest
 * }
 * Digest ::= OCTET STRING
 * 
 */
static NH_NODE_WAY __pfx_map[] =
{
	{	/* PFX */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* version */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* authSafe */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* contentType */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* content */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_ANY_TAG_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT,
		NULL,
		0
	},
	{	/* explicit content */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OCTET_STRING,
		NULL,
		0
	},
	{	/* macData */
		((NH_PARSE_NORTH | 2) << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
static NH_NODE_WAY __mac_data_map[] =
{
	{	/* MacData*/
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* mac */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* digestAlgorithm */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* digest */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING,
		NULL,
		0
	},
	{	/* macSalt */
		(NH_SAIL_SKIP_WEST << 16) | (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* iterations */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER,
		NULL,
		0
	}
};
#define PBE_KEY_LEN		20
static NH_RV __pfx_verify_mac(_IN_ NH_PDU_PARSER_STR *self, _IN_ char *szSecret)
{
	NH_RV rv;
	NH_ASN1_PNODE pMacNode, pNode;
	unsigned char *pBuffer, *pMac, *pSalt, pKey[PBE_KEY_LEN], pMd[EVP_MAX_MD_SIZE];
	unsigned int uiBufLen, uMacLen, uiSaltLen, uiIterCount, uiMdLen;
	HMAC_CTX *pCtx;

	if
	(
		NH_SUCCESS(rv = szSecret ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = ASN_IS_PRESENT((pMacNode = self->hParser->sail(self->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) ? NH_OK : NH_PFX_MAC_NOT_PRESENT_ERROR) &&
		NH_SUCCESS(rv = self->contents(self, &pBuffer, &uiBufLen)) &&
		NH_SUCCESS(rv = self->salt(self, &pSalt, &uiSaltLen)) &&
		NH_SUCCESS(rv = self->iterations(self, &uiIterCount)) &&
		NH_SUCCESS(rv = (pNode = self->hParser->sail(pMacNode, ((NH_PARSE_SOUTH | 2) << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
	)
	{
		pMac = (unsigned char*) pNode->value;
		uMacLen = pNode->valuelen;
		if
		(
			NH_SUCCESS(rv = PKCS12_key_gen(szSecret, strlen(szSecret), pSalt, uiSaltLen, PKCS12_MAC_ID, uiIterCount, PBE_KEY_LEN, pKey, EVP_sha1()) ? NH_OK : NH_PFX_OPENSSL_ERROR) &&
			NH_SUCCESS(rv = (pCtx = HMAC_CTX_new()) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if
			(
				NH_SUCCESS(rv = HMAC_Init_ex(pCtx, pKey, PBE_KEY_LEN, EVP_sha1(), NULL) ? NH_OK : NH_PFX_OPENSSL_ERROR) &&
				NH_SUCCESS(rv = HMAC_Update(pCtx, pBuffer, uiBufLen) ? NH_OK : NH_PFX_OPENSSL_ERROR) &&
				NH_SUCCESS(rv = HMAC_Final(pCtx, pMd, &uiMdLen) ? NH_OK : NH_PFX_OPENSSL_ERROR)
			)	rv = (uMacLen == uiMdLen) && (memcmp(pMd, pMac, uMacLen) == 0) ? NH_OK : NH_PFX_MAC_FAILURE_ERROR;
			HMAC_CTX_free(pCtx);
		}
	}
	return rv;
}
static NH_RV __pfx_contents(_IN_ NH_PDU_PARSER_STR *self, _OUT_ unsigned char **ppBuffer, _OUT_ unsigned int *puiBufLen)
{
	NH_RV rv;
	NH_ASN1_PNODE pNode;

	if (NH_SUCCESS(rv = (pNode = self->hParser->sail(self->hParser->root->child, (NH_SAIL_SKIP_EAST << 24) | (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR))
	{
		*ppBuffer = (unsigned char*) pNode->value;
		*puiBufLen = pNode->valuelen;
	}
	return rv;
}
static NH_RV __pfx_salt(_IN_ NH_PDU_PARSER_STR *self, _OUT_ unsigned char **ppBuffer, _OUT_ unsigned int *puiBufLen)
{
	NH_RV rv;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = ASN_IS_PRESENT((pNode = self->hParser->sail(self->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) ? NH_OK : NH_PFX_MAC_NOT_PRESENT_ERROR) &&
		NH_SUCCESS(rv = (pNode = self->hParser->sail(pNode, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
	)
	{
		*ppBuffer = (unsigned char*) pNode->value;
		*puiBufLen = pNode->valuelen;
	}
	return rv;
}
static NH_RV __pfx_iterations(_IN_ NH_PDU_PARSER_STR *self, _OUT_ unsigned int *puiBufLen)
{
	NH_RV rv;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = ASN_IS_PRESENT((pNode = self->hParser->sail(self->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) ? NH_OK : NH_PFX_MAC_NOT_PRESENT_ERROR) &&
		NH_SUCCESS(rv = (pNode = self->hParser->sail(pNode, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
	)	*puiBufLen = *(unsigned int*) pNode->value;
	return rv;
}
static NH_PDU_PARSER_STR __default_pfx_parser =
{
	NULL,				/* hParser */
	__pfx_verify_mac,
	__pfx_contents,
	__pfx_salt,
	__pfx_iterations
};
NH_FUNCTION(void, __delete_pdu_parser)(_INOUT_ NH_PDU_PARSER hPfx)
{
	if (hPfx)
	{
		if (hPfx->hParser) NH_release_parser(hPfx->hParser);
		free(hPfx);
	}
}
NH_FUNCTION(NH_RV, __new_pdu_parser)(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _OUT_ NH_PDU_PARSER *hOut)
{
	NH_RV rv;
	NH_ASN1_PNODE pNode;
	NH_PDU_PARSER hPfx;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (hPfx = (NH_PDU_PARSER) malloc(sizeof(NH_PDU_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		memcpy(hPfx, &__default_pfx_parser, sizeof(NH_PDU_PARSER_STR));
		if
		(
			NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 16, 8192, &hPfx->hParser)) &&
			NH_SUCCESS(rv = hPfx->hParser->map(hPfx->hParser, __pfx_map, ASN_NODE_WAY_COUNT(__pfx_map))) &&
			NH_SUCCESS(rv = (pNode = hPfx->hParser->sail(hPfx->hParser->root, NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hPfx->hParser->parse_little_integer(hPfx->hParser, pNode)) &&
			NH_SUCCESS(rv = *(long int*) pNode->value == 3 ? NH_OK : NH_PFX_WRONG_VERSION_ERROR) &&
			NH_SUCCESS(rv = (pNode = hPfx->hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hPfx->hParser->parse_objectid(hPfx->hParser, pNode, FALSE)) &&
			NH_SUCCESS(rv = NH_match_oid((unsigned int*) pNode->value, pNode->valuelen, cms_data_ct_oid, CMS_DATA_CTYPE_OID_COUNT) ? NH_OK : NH_PFX_UNSUPPORTED_TYPE_ERROR) &&
			NH_SUCCESS(rv = (pNode = hPfx->hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hPfx->hParser->parse_octetstring(hPfx->hParser, pNode)) &&
			NH_SUCCESS(rv = (pNode = hPfx->hParser->sail(hPfx->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
		)
		{
			if
			(
				ASN_IS_PRESENT(pNode) &&
				NH_SUCCESS(rv = hPfx->hParser->map_from(hPfx->hParser, pNode, __mac_data_map, ASN_NODE_WAY_COUNT(__mac_data_map))) &&
				NH_SUCCESS(rv = (pNode = hPfx->hParser->sail(pNode, (NH_PARSE_SOUTH | 3))) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
				NH_SUCCESS(rv = hPfx->hParser->parse_objectid(hPfx->hParser, pNode, FALSE)) &&
				NH_SUCCESS(rv = NH_match_oid((unsigned int*) pNode->value, pNode->valuelen, sha1_oid, NHC_SHA1_OID_COUNT) ? NH_OK : NH_PFX_UNSUPPORTED_HASH_ERROR) &&
				NH_SUCCESS(rv = (pNode = hPfx->hParser->sail(pNode, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
				NH_SUCCESS(rv = hPfx->hParser->parse_octetstring(hPfx->hParser, pNode)) &&
				NH_SUCCESS(rv = (pNode = hPfx->hParser->sail(pNode, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
				NH_SUCCESS(rv = hPfx->hParser->parse_octetstring(hPfx->hParser, pNode)) &&
				NH_SUCCESS(rv = (pNode = hPfx->hParser->sail(pNode, NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
			)	rv = hPfx->hParser->parse_little_integer(hPfx->hParser, pNode);
		}
		if (NH_SUCCESS(rv)) *hOut = hPfx;
		else __delete_pdu_parser(hPfx);
	}
	return rv;
}


/**
 *
 * AuthenticatedSafe ::= SEQUENCE OF ContentInfo
 * 	-- Data if unencrypted
 * 	-- EncryptedData if password-encrypted
 * 	-- EnvelopedData if public key-encrypted
 */
static NH_NODE_WAY __content_info_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* contentType */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* content */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT,
		NULL,
		0
	}
};
static NH_NODE_WAY __authenticated_safe_map[] =
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
		__content_info_map,
		ASN_NODE_WAY_COUNT(__content_info_map)
	}
};
static NH_RV __auth_contents(_IN_ NH_AUTH_SAFE_PARSER_STR *self, _IN_ int n, _OUT_ unsigned char **ppBuffer, _OUT_ unsigned int *puiBufLen)
{
	NH_RV rv;
	NH_ASN1_PNODE pNode;
	int i = 0;

	if
	(
		NH_SUCCESS(rv = n > -1 && n < self->count ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (pNode = self->hParser->root->child) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
	)
	{
		while (i < n && pNode)
		{
			pNode = pNode->next;
			i++;
		}
		if (NH_SUCCESS(rv = (pNode = self->hParser->sail(pNode, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR))
		{
			*ppBuffer = (unsigned char*) pNode->value;
			*puiBufLen = pNode->valuelen;
		}
	}
	return rv;
}
static NH_AUTH_SAFE_PARSER_STR __default_auth_parser =
{
	NULL,			/* hParser */
	0,			/* count */
	__auth_contents
};
NH_FUNCTION(void, __delete_authenticated_safe_parser)(_INOUT_ NH_AUTH_SAFE_PARSER hAuth)
{
	if (hAuth)
	{
		if (hAuth->hParser) NH_release_parser(hAuth->hParser);
		free(hAuth);
	}
}
NH_FUNCTION(NH_RV, __new_authenticated_safe_parser)(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _OUT_ NH_AUTH_SAFE_PARSER *hOut)
{
	NH_RV rv;
	NH_ASN1_PNODE pSet, pNode;
	NH_AUTH_SAFE_PARSER hAuth;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (hAuth = (NH_AUTH_SAFE_PARSER) malloc(sizeof(NH_AUTH_SAFE_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		memcpy(hAuth, &__default_auth_parser, sizeof(NH_AUTH_SAFE_PARSER_STR));
		if
		(
			NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 16, 8192, &hAuth->hParser)) &&
			NH_SUCCESS(rv = hAuth->hParser->map(hAuth->hParser, __authenticated_safe_map, ASN_NODE_WAY_COUNT(__authenticated_safe_map)))
		)
		{
			pSet = hAuth->hParser->root->child;
			while (NH_SUCCESS(rv) && pSet)
			{
				hAuth->count++;
				if
				(
					NH_SUCCESS(rv = (pNode = pSet->child) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
					NH_SUCCESS(rv = hAuth->hParser->parse_objectid(hAuth->hParser, pNode, FALSE)) &&
					NH_SUCCESS(rv = NH_match_oid((unsigned int*) pNode->value, pNode->valuelen, cms_data_ct_oid, CMS_DATA_CTYPE_OID_COUNT) ? NH_OK : NH_PFX_UNSUPPORTED_TYPE_ERROR) &&
					NH_SUCCESS(rv = (pNode = hAuth->hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
				)	rv = hAuth->hParser->parse_octetstring(hAuth->hParser, pNode);
				pSet = pSet->next;
			}
		}
		if (NH_SUCCESS(rv)) *hOut = hAuth;
		else __delete_authenticated_safe_parser(hAuth);
	}
	return rv;
}

/*
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 * 	encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 * 	encryptedData        EncryptedData
 * }
 * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier { CONTENT-ENCRYPTION, { KeyEncryptionAlgorithms }}
 * EncryptedData ::= OCTET STRING -- Encrypted PrivateKeyInfo
 */
static NH_NODE_WAY __pkcs8ShroudedKeyBag_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* encryptionAlgorithm */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* encryptedData */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING,
		NULL,
		0
	},
	{
		/* AlgorithmIdentifier */
		NH_SAIL_SKIP_WEST << 8 | NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* parameters */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* iv */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* iteration count */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER,
		NULL,
		0
	}
};
NH_FUNCTION(void, __delete_shroudedkeybag)(_INOUT_ NH_SHROUDEDKEYBAG hBag)
{
	if (hBag)
	{
		if (hBag->algorithm.pIdentifier) free(hBag->algorithm.pIdentifier);
		if (hBag->contents.data) free(hBag->contents.data);
		if (hBag->iv.data) free(hBag->iv.data);
		free(hBag);
	}
}
NH_FUNCTION(NH_RV, __parse_shroudedkeybag)(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _OUT_ NH_SHROUDEDKEYBAG *hBag)
{
	NH_RV rv;
	NH_SHROUDEDKEYBAG hOut;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (hOut = (NH_SHROUDEDKEYBAG) malloc(sizeof(NH_SHROUDEDKEYBAG_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		memset(hOut, 0, sizeof(NH_SHROUDEDKEYBAG_STR));
		if (NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 4, 8192, &hParser)))
		{
			if
			(
				NH_SUCCESS(rv = hParser->map(hParser, __pkcs8ShroudedKeyBag_map, ASN_NODE_WAY_COUNT(__pkcs8ShroudedKeyBag_map))) &&
				NH_SUCCESS(rv = (pNode = hParser->sail(hParser->root, NH_PARSE_SOUTH | 2)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
				NH_SUCCESS(rv = hParser->parse_oid(hParser, pNode)) &&
				NH_SUCCESS(rv = (hOut->algorithm.pIdentifier = (unsigned int*) malloc(pNode->valuelen * sizeof(unsigned int))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				memcpy(hOut->algorithm.pIdentifier, pNode->value, pNode->valuelen * sizeof(unsigned int));
				hOut->algorithm.uCount = pNode->valuelen;
				if
				(
					NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
					NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode)) &&
					NH_SUCCESS(rv = (hOut->iv.data = (unsigned char*) malloc(pNode->valuelen)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
				)
				{
					memcpy(hOut->iv.data, pNode->value, pNode->valuelen);
					hOut->iv.length = pNode->valuelen;
					if
					(
						NH_SUCCESS(rv = (pNode = pNode->next) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
						NH_SUCCESS(rv = hParser->parse_little_integer(hParser, pNode))
					)
					{
						hOut->iCount = *(int*) pNode->value;
						if
						(
							NH_SUCCESS(rv = (pNode = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
							NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode)) &&
							NH_SUCCESS(rv = (hOut->contents.data = (unsigned char*) malloc(pNode->valuelen)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
						)
						{
							memcpy(hOut->contents.data, pNode->value, pNode->valuelen);
							hOut->contents.length = pNode->valuelen;
							*hBag = hOut;
						}
					}
				}
			}
			NH_release_parser(hParser);
		}
		if (NH_FAIL(rv)) __delete_shroudedkeybag(hOut);
	}
	return rv;
}


/*
 * CertBag ::= SEQUENCE {
 * 	certId      BAG-TYPE.&id   ({CertTypes}),
 * 	certValue   [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
 * }
 * x509Certificate BAG-TYPE ::= {OCTET STRING IDENTIFIED BY {certTypes 1}} -- DER-encoded X.509 certificate stored in OCTET STRING
 * sdsiCertificate BAG-TYPE ::= {IA5String IDENTIFIED BY {certTypes 2}}    -- Base64-encoded SDSI certificate stored in IA5String
 * CertTypes BAG-TYPE ::= {
 * 	x509Certificate |
 * 	sdsiCertificate,
 * 	... -- For future extensions
 * }
 */
static NH_NODE_WAY __certbag_map[] =
{
	{
		NH_PARSE_ROOT,
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
		NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT,
		NULL,
		0
	}
};
NH_FUNCTION(void, __delete_certbag)(_INOUT_ NH_CERTBAG hBag)
{
	if (hBag)
	{
		if (hBag->certType.pIdentifier) free(hBag->certType.pIdentifier);
		if (hBag->contents.data) free(hBag->contents.data);
		free(hBag);
	}
}
NH_FUNCTION(NH_RV, __parse_certbag)(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _OUT_ NH_CERTBAG *hBag)
{
	NH_RV rv;
	NH_CERTBAG hOut;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (hOut = (NH_CERTBAG) malloc(sizeof(NH_CERTBAG_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		memset(hOut, 0, sizeof(NH_CERTBAG_STR));
		if (NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 4, 8192, &hParser)))
		{
			if
			(
				NH_SUCCESS(rv = hParser->map(hParser, __certbag_map, ASN_NODE_WAY_COUNT(__certbag_map))) &&
				NH_SUCCESS(rv = (pNode = hParser->root->child) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
				NH_SUCCESS(rv = hParser->parse_oid(hParser, pNode)) &&
				NH_SUCCESS(rv = (hOut->certType.pIdentifier = (unsigned int*) malloc(pNode->valuelen * sizeof(unsigned int))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				memcpy(hOut->certType.pIdentifier, pNode->value, pNode->valuelen * sizeof(unsigned int));
				hOut->certType.uCount = pNode->valuelen;
				if
				(
					NH_SUCCESS(rv = (pNode = hParser->sail(pNode, NH_SAIL_SKIP_EAST << 8 | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
					NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode)) &&
					NH_SUCCESS(rv = (hOut->contents.data = (unsigned char*) malloc(pNode->valuelen)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
				)
				{
					memcpy(hOut->contents.data, pNode->value, pNode->valuelen);
					hOut->contents.length = pNode->valuelen;
					*hBag = hOut;
				}
			}
			NH_release_parser(hParser);
		}
		if (NH_FAIL(rv)) __delete_certbag(hOut);
	}
	return rv;
}


/**
 * SafeContents ::= SEQUENCE OF SafeBag
 * SafeBag ::= SEQUENCE {
 * 	bagId          BAG-TYPE.&id ({PKCS12BagSet})
 * 	bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
 * 	bagAttributes  SET OF PKCS12Attribute OPTIONAL
 * }
 */
static NH_NODE_WAY __safe_bag_map[] =
{
	{	/* SafeBag*/
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* bagId */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* bagValue */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT | NH_ASN1_EXP_CONSTRUCTED_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* bagAttributes */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_SET | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
static NH_NODE_WAY __safe_contents_map[] =
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
		__safe_bag_map,
		ASN_NODE_WAY_COUNT(__safe_bag_map)
	}
};
static NH_SAFE_BAG __bag_enumerate(_IN_ NH_SAFE_CONTENTS_PARSER_STR *self, _IN_ unsigned int n)
{
	NH_SAFE_BAG pRet = NULL;
	if (n >= 0 && n < self->bagCount) pRet = &self->bagSet[n];
	return pRet;
}
static NH_SAFE_CONTENTS_PARSER_STR __default_safe_contents = 
{
	NULL,			/* hParser */
	NULL,			/* bagSet */
	0,			/* bagCount */
	__bag_enumerate
};
unsigned int pfx_keyBag_oid[]				= { 1, 2, 840, 113549, 1, 12, 10, 1, 1 };
unsigned int pfx_pkcs8ShroudedKeyBag_oid[]	= { 1, 2, 840, 113549, 1, 12, 10, 1, 2 };
unsigned int pfx_certBag_oid[]			= { 1, 2, 840, 113549, 1, 12, 10, 1, 3 };
unsigned int pfx_crlBag_oid[]				= { 1, 2, 840, 113549, 1, 12, 10, 1, 4 };
unsigned int pfx_secretBag_oid[]			= { 1, 2, 840, 113549, 1, 12, 10, 1, 5 };
unsigned int pfx_safeContentsBag_oid[]		= { 1, 2, 840, 113549, 1, 12, 10, 1, 6 };
unsigned int pkcs9_x509_certificate_oid[]		= { 1, 2, 840, 113549, 1,  9, 22, 1    };

NH_FUNCTION(void, __delete_safe_contents_parser)(_INOUT_ NH_SAFE_CONTENTS_PARSER hSafe)
{
	unsigned int i;
	NH_SAFE_BAG pBag;

	if (hSafe)
	{
		if (hSafe->bagSet)
		{
			/* TODO: Release bag resources */
			for (i = 0; i < hSafe->bagCount; i++)
			{
				if ((pBag = hSafe->enumerate(hSafe, i)))
				{
					switch (pBag->id)
					{
					case PFX_keyBag:
						break;
					case PFX_pkcs8ShroudedKeyBag:
						__delete_shroudedkeybag(pBag->bag.pkcs8ShroudedKeyBag);
						break;
					case PFX_certBag:
						__delete_certbag(pBag->bag.certBag);
						break;
					case PFX_crlBag:
					case PFX_secretBag:
					case PFX_safeContentsBag:
						break;
						/* TODO */
					}
				}
			}
		}
		if (hSafe->hParser) NH_release_parser(hSafe->hParser);
		free(hSafe);
	}
}
NH_FUNCTION(NH_RV, __new_safe_contents_parser)(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _OUT_ NH_SAFE_CONTENTS_PARSER *hOut)
{
	NH_RV rv;
	NH_SAFE_CONTENTS_PARSER hSafe;
	NH_ASN1_PNODE pBag, pNode;
	int i = 0;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (hSafe = (NH_SAFE_CONTENTS_PARSER) malloc(sizeof(NH_SAFE_CONTENTS_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		memcpy(hSafe, &__default_safe_contents, sizeof(NH_SAFE_CONTENTS_PARSER_STR));
		if
		(
			NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 16, 8192, &hSafe->hParser)) &&
			NH_SUCCESS(rv = hSafe->hParser->map(hSafe->hParser, __safe_contents_map, ASN_NODE_WAY_COUNT(__safe_contents_map)))
		)
		{
			pBag = hSafe->hParser->root->child;
			while (NH_SUCCESS(rv) && pBag)
			{
				if
				(
					NH_SUCCESS(rv = (pNode = pBag->child) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
					NH_SUCCESS(rv = hSafe->hParser->parse_objectid(hSafe->hParser, pNode, FALSE))
				)	hSafe->bagCount++;
				pBag = pBag->next;
			}
			
			if
			(
				NH_SUCCESS(rv) &&
				NH_SUCCESS(rv = hSafe->hParser->container->bite_chunk(hSafe->hParser->container, hSafe->bagCount * sizeof(NH_SAFE_BAG_STR), (void*) &hSafe->bagSet))
			)
			{
				memset(hSafe->bagSet, 0, hSafe->bagCount * sizeof(NH_SAFE_BAG_STR));
				pBag = hSafe->hParser->root->child;
				while
				(
					pBag &&
					NH_SUCCESS(rv = (pNode = hSafe->hParser->sail(pBag->child, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
				)
				{
					hSafe->bagSet[i].bagType.pIdentifier = (unsigned int*) pBag->child->value;
					hSafe->bagSet[i].bagType.uCount = pBag->child->valuelen;
					hSafe->bagSet[i].contents.data = pNode->identifier;
					hSafe->bagSet[i].contents.length = pNode->size + pNode->contents - pNode->identifier;
					pBag = pBag->next;
				}
			}
		}
		if (NH_SUCCESS(rv)) *hOut = hSafe;
		else __delete_safe_contents_parser(hSafe);
	}
	return rv;
}
NH_FUNCTION(NH_RV, NHFX_new_pfx_parser)(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _IN_ char *szSecret, _OUT_ NH_PFX_PARSER *hParser)
{
	NH_RV rv;
	unsigned char *pData;
	unsigned int uiDataLen, i, j;
	NH_SAFE_BAG pBag;

	NH_PDU_PARSER hPDU = NULL;
	NH_AUTH_SAFE_PARSER hAuth = NULL;
	NH_SAFE_CONTENTS_PARSER hSafe = NULL;
	NH_PFX_PARSER hOut;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = __new_pdu_parser(pBuffer, uiBufLen, &hPDU)) &&
		NH_SUCCESS(rv = hPDU->verify_mac(hPDU, szSecret)) &&
		NH_SUCCESS(rv = hPDU->contents(hPDU, &pData, &uiDataLen)) &&
		NH_SUCCESS(rv = __new_authenticated_safe_parser(pData, uiDataLen, &hAuth))
	)
	{
		i = 0;
		while
		(
			NH_SUCCESS(rv) &&
			i < hAuth->count &&
			NH_SUCCESS(rv = hAuth->contents(hAuth, i++, &pData, &uiDataLen)) &&
			NH_SUCCESS(rv = __new_safe_contents_parser(pData, uiDataLen, &hSafe))
		)
		{
			j = 0;
			while
			(
				NH_SUCCESS(rv) &&
				j < hSafe->bagCount &&
				NH_SUCCESS(rv = (pBag = hSafe->enumerate(hSafe, j++)) ? NH_OK : NH_PFX_BAG_ERROR)
			)
			{
				if (NH_match_oid(pBag->bagType.pIdentifier, pBag->bagType.uCount, pfx_keyBag_oid, NHC_OID_COUNT(pfx_keyBag_oid)))
				{
					pBag->id = PFX_keyBag;
					/* TODO */
				}
				else if (NH_match_oid(pBag->bagType.pIdentifier, pBag->bagType.uCount, pfx_pkcs8ShroudedKeyBag_oid, NHC_OID_COUNT(pfx_pkcs8ShroudedKeyBag_oid)))
				{
					pBag->id = PFX_pkcs8ShroudedKeyBag;
					rv = __parse_shroudedkeybag(pBag->contents.data, pBag->contents.length, &pBag->bag.pkcs8ShroudedKeyBag);
				}
				else if (NH_match_oid(pBag->bagType.pIdentifier, pBag->bagType.uCount, pfx_certBag_oid, NHC_OID_COUNT(pfx_certBag_oid)))
				{
					pBag->id = PFX_certBag;
					rv = __parse_certbag(pBag->contents.data, pBag->contents.length, &pBag->bag.certBag);
				}
				else if (NH_match_oid(pBag->bagType.pIdentifier, pBag->bagType.uCount, pfx_crlBag_oid, NHC_OID_COUNT(pfx_crlBag_oid))) pBag->id = PFX_crlBag;
				else if (NH_match_oid(pBag->bagType.pIdentifier, pBag->bagType.uCount, pfx_secretBag_oid, NHC_OID_COUNT(pfx_secretBag_oid))) pBag->id = PFX_secretBag;
				else if (NH_match_oid(pBag->bagType.pIdentifier, pBag->bagType.uCount, pfx_safeContentsBag_oid, NHC_OID_COUNT(pfx_safeContentsBag_oid))) pBag->id = PFX_safeContentsBag;
				else rv = NH_PFX_BAG_ERROR;
			}
		}
	}
	if
	(
		NH_SUCCESS(rv) &&
		NH_SUCCESS(rv = (hOut = (NH_PFX_PARSER) malloc(sizeof(NH_PFX_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		hOut->hPDU = hPDU;
		hOut->hAuth = hAuth;
		hOut->hSafe = hSafe;
		*hParser = hOut;
	}
	else
	{
		if (hSafe) __delete_safe_contents_parser(hSafe);
		if (hAuth) __delete_authenticated_safe_parser(hAuth);
		if (hPDU) __delete_pdu_parser(hPDU);
	}
	return rv;
}
NH_FUNCTION(void, NHFX_delete_pfx_parser)(_INOUT_ NH_PFX_PARSER hParser)
{
	if (hParser)
	{
		if (hParser->hSafe) __delete_safe_contents_parser(hParser->hSafe);
		if (hParser->hAuth) __delete_authenticated_safe_parser(hParser->hAuth);
		if (hParser->hPDU) __delete_pdu_parser(hParser->hPDU);
		free(hParser);
	}
}
