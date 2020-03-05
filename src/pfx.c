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
static NH_RV __pfx_verify_mac(_IN_ NH_PFX_PARSER_STR *self, _IN_ char *szSecret)
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
static NH_RV __pfx_contents(_IN_ NH_PFX_PARSER_STR *self, _OUT_ unsigned char **ppBuffer, _OUT_ unsigned int *puiBufLen)
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
static NH_RV __pfx_salt(_IN_ NH_PFX_PARSER_STR *self, _OUT_ unsigned char **ppBuffer, _OUT_ unsigned int *puiBufLen)
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
static NH_RV __pfx_iterations(_IN_ NH_PFX_PARSER_STR *self, _OUT_ unsigned int *puiBufLen)
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
static NH_PFX_PARSER_STR __default_pfx_parser =
{
	NULL,				/* hParser */
	__pfx_verify_mac,
	__pfx_contents,
	__pfx_salt,
	__pfx_iterations
};
NH_FUNCTION(NH_RV, NHFX_new_pfx_parser)(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _OUT_ NH_PFX_PARSER *hOut)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser = NULL;
	NH_ASN1_PNODE pNode;
	NH_PFX_PARSER hPfx;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 16, 8192, &hParser)) &&
		NH_SUCCESS(rv = hParser->map(hParser, __pfx_map, ASN_NODE_WAY_COUNT(__pfx_map))) &&
		NH_SUCCESS(rv = (pNode = hParser->sail(hParser->root, NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
		NH_SUCCESS(rv = hParser->parse_little_integer(hParser, pNode)) &&
		NH_SUCCESS(rv = *(long int*) pNode->value == 3 ? NH_OK : NH_PFX_WRONG_VERSION_ERROR) &&
		NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
		NH_SUCCESS(rv = hParser->parse_objectid(hParser, pNode, FALSE)) &&
		NH_SUCCESS(rv = NH_match_oid((unsigned int*) pNode->value, pNode->valuelen, cms_data_ct_oid, CMS_DATA_CTYPE_OID_COUNT) ? NH_OK : NH_PFX_UNSUPPORTED_TYPE_ERROR) &&
		NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
		NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode)) &&
		NH_SUCCESS(rv = (pNode = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
	)
	{
		if
		(
			ASN_IS_PRESENT(pNode) &&
			NH_SUCCESS(rv = hParser->map_from(hParser, pNode, __mac_data_map, ASN_NODE_WAY_COUNT(__mac_data_map))) &&
			NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_PARSE_SOUTH | 3))) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_objectid(hParser, pNode, FALSE)) &&
			NH_SUCCESS(rv = NH_match_oid((unsigned int*) pNode->value, pNode->valuelen, sha1_oid, NHC_SHA1_OID_COUNT) ? NH_OK : NH_PFX_UNSUPPORTED_HASH_ERROR) &&
			NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode)) &&
			NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode)) &&
			NH_SUCCESS(rv = (pNode = hParser->sail(pNode, NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
		)	rv = hParser->parse_little_integer(hParser, pNode);
	}
	if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (hPfx = (NH_PFX_PARSER) malloc(sizeof(NH_PFX_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memcpy(hPfx, &__default_pfx_parser, sizeof(NH_PFX_PARSER_STR));
		hPfx->hParser = hParser;
		*hOut = hPfx;
	}
	else if (hParser) NH_release_parser(hParser);
	return rv;
}
NH_FUNCTION(void, NHFX_delete_pfx_parser)(_INOUT_ NH_PFX_PARSER hPfx)
{
	if (hPfx)
	{
		if (hPfx->hParser) NH_release_parser(hPfx->hParser);
		free(hPfx);
	}
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
		while (i <= n && pNode)
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
NH_FUNCTION(NH_RV, NHFX_new_authenticated_safe_parser)(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _OUT_ NH_AUTH_SAFE_PARSER *hOut)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser = NULL;
	NH_ASN1_PNODE pSet, pNode;
	int iCount = 0;
	NH_AUTH_SAFE_PARSER hAuth;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 16, 8192, &hParser)) &&
		NH_SUCCESS(rv = hParser->map(hParser, __authenticated_safe_map, ASN_NODE_WAY_COUNT(__authenticated_safe_map)))
	)
	{
		pSet = hParser->root->child;
		while (NH_SUCCESS(rv) && pSet)
		{
			iCount++;
			if
			(
				NH_SUCCESS(rv = (pNode = pSet->child) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
				NH_SUCCESS(rv = hParser->parse_objectid(hParser, pNode, FALSE)) &&
				NH_SUCCESS(rv = NH_match_oid((unsigned int*) pNode->value, pNode->valuelen, cms_data_ct_oid, CMS_DATA_CTYPE_OID_COUNT) ? NH_OK : NH_PFX_UNSUPPORTED_TYPE_ERROR) &&
				NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
			)	rv = hParser->parse_octetstring(hParser, pNode);
			pSet = pSet->next;
		}
	}
	if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (hAuth = (NH_AUTH_SAFE_PARSER) malloc(sizeof(NH_AUTH_SAFE_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memcpy(hAuth, &__default_auth_parser, sizeof(NH_AUTH_SAFE_PARSER_STR));
		hAuth->hParser = hParser;
		hAuth->count = iCount;
		*hOut = hAuth;
	}
	else if (hParser) NH_release_parser(hParser);
	return rv;
}
NH_FUNCTION(void, NHFX_delete_authenticated_safe_parser)(_INOUT_ NH_AUTH_SAFE_PARSER hAuth)
{
	if (hAuth)
	{
		if (hAuth->hParser) NH_release_parser(hAuth->hParser);
		free(hAuth);
	}
}


/**
 * SafeContents ::= SEQUENCE OF SafeBag
 * SafeBag ::= SEQUENCE {
 * 	bagId          BAG-TYPE.&id ({PKCS12BagSet})
 * 	bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
 * 	bagAttributes  SET OF PKCS12Attribute OPTIONAL
 * }
 */
unsigned int pfx_keyBag_oid[]				= { 1, 2, 840, 113549, 1, 12, 10, 1, 1 };
unsigned int pfx_pkcs8ShroudedKeyBag_oid[]	= { 1, 2, 840, 113549, 1, 12, 10, 1, 2 };
unsigned int pfx_certBag_oid[]			= { 1, 2, 840, 113549, 1, 12, 10, 1, 3 };
unsigned int pfx_crlBag_oid[]				= { 1, 2, 840, 113549, 1, 12, 10, 1, 4 };
unsigned int pfx_secretBag_oid[]			= { 1, 2, 840, 113549, 1, 12, 10, 1, 5 };
unsigned int pfx_safeContentsBag_oid[]		= { 1, 2, 840, 113549, 1, 12, 10, 1, 6 };

static NH_NODE_WAY __safe_bag_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
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
		NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_EAST,
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



