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
 * @brief RFC 7292
 * 
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
const static NH_NODE_WAY __pfx_map[] =
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
const static NH_NODE_WAY __mac_data_map[] =
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
static NH_RV __parse_pdu(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _OUT_ NH_ASN1_PARSER_HANDLE *hOut)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser = NULL;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 16, 8192, &hParser)) &&
		NH_SUCCESS(rv = hParser->map(hParser, __pfx_map, ASN_NODE_WAY_COUNT(__pfx_map))) &&
		NH_SUCCESS(rv = (pNode = hParser->sail(hParser->root, NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
		NH_SUCCESS(rv = hParser->parse_little_integer(hParser, pNode)) &&
		NH_SUCCESS(rv = *(long int*) pNode->value == 3 ? NH_OK : NH_PFX_WRONG_VERSION_ERROR) &&
		NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
		NH_SUCCESS(rv = hParser->parse_oid(hParser, pNode)) &&
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
			NH_SUCCESS(rv = (pNode = hParser->sail(pNode, NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_little_integer(hParser, pNode))
		)	*hOut = hParser;
	}
	if (NH_FAIL(rv)) NH_release_parser(hParser);
	return rv;
}
static NH_RV __pfx_contents(_IN_ NH_ASN1_PARSER_HANDLE hParser, _OUT_ unsigned char **ppBuffer, _OUT_ unsigned int *puiBufLen)
{
	NH_RV rv;
	NH_ASN1_PNODE pNode;

	if (NH_SUCCESS(rv = (pNode = hParser->sail(hParser->root->child, (NH_SAIL_SKIP_EAST << 24) | (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR))
	{
		*ppBuffer = (unsigned char*) pNode->value;
		*puiBufLen = pNode->valuelen;
	}
	return rv;
}
static NH_RV __pfx_salt(_IN_ NH_ASN1_PARSER_HANDLE hParser, _OUT_ unsigned char **ppBuffer, _OUT_ unsigned int *puiBufLen)
{
	NH_RV rv;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = ASN_IS_PRESENT((pNode = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) ? NH_OK : NH_PFX_MAC_NOT_PRESENT_ERROR) &&
		NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
	)
	{
		*ppBuffer = (unsigned char*) pNode->value;
		*puiBufLen = pNode->valuelen;
	}
	return rv;
}
static NH_RV __pfx_iterations(_IN_ NH_ASN1_PARSER_HANDLE hParser, _OUT_ unsigned int *puiBufLen)
{
	NH_RV rv;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = ASN_IS_PRESENT((pNode = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) ? NH_OK : NH_PFX_MAC_NOT_PRESENT_ERROR) &&
		NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
	)	*puiBufLen = *(unsigned int*) pNode->value;
	return rv;
}
static NH_RV __pfx_verify_mac(_IN_ NH_ASN1_PARSER_HANDLE hParser, _IN_ char *szSecret, _INOUT_ NH_PFX_PARSER hPFX)
{
	NH_RV rv;
	NH_ASN1_PNODE pMacNode, pNode;
	unsigned char *pBuffer, *pMac, *pSalt, pKey[PBE_MAC_KEY_LEN], pMd[EVP_MAX_MD_SIZE];
	unsigned int uiBufLen, uMacLen, uiSaltLen, uiIterCount, uiMdLen;
	HMAC_CTX *pCtx;

	if
	(
		NH_SUCCESS(rv = szSecret && hPFX ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = ASN_IS_PRESENT((pMacNode = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) ? NH_OK : NH_PFX_MAC_NOT_PRESENT_ERROR) &&
		NH_SUCCESS(rv = __pfx_contents(hParser, &pBuffer, &uiBufLen)) &&
		NH_SUCCESS(rv = __pfx_salt(hParser, &pSalt, &uiSaltLen)) &&
		NH_SUCCESS(rv = __pfx_iterations(hParser, &uiIterCount)) &&
		NH_SUCCESS(rv = (pNode = hParser->sail(pMacNode, ((NH_PARSE_SOUTH | 2) << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
	)
	{
		pMac = (unsigned char*) pNode->value;
		uMacLen = pNode->valuelen;
		if
		(
			NH_SUCCESS(rv = PKCS12_key_gen(szSecret, strlen(szSecret), pSalt, uiSaltLen, PKCS12_MAC_ID, uiIterCount, PBE_MAC_KEY_LEN, pKey, EVP_sha1()) ? NH_OK : NH_PFX_OPENSSL_ERROR) &&
			NH_SUCCESS(rv = (pCtx = HMAC_CTX_new()) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if
			(
				NH_SUCCESS(rv = HMAC_Init_ex(pCtx, pKey, PBE_MAC_KEY_LEN, EVP_sha1(), NULL) ? NH_OK : NH_PFX_OPENSSL_ERROR) &&
				NH_SUCCESS(rv = HMAC_Update(pCtx, pBuffer, uiBufLen) ? NH_OK : NH_PFX_OPENSSL_ERROR) &&
				NH_SUCCESS(rv = HMAC_Final(pCtx, pMd, &uiMdLen) ? NH_OK : NH_PFX_OPENSSL_ERROR)
			)	rv = (uMacLen == uiMdLen) && (memcmp(pMd, pMac, uMacLen) == 0) ? NH_OK : NH_PFX_MAC_FAILURE_ERROR;
			HMAC_CTX_free(pCtx);
		}
	}
	if (NH_SUCCESS(rv) && NH_SUCCESS(rv = hPFX->hContainer->bite_chunk(hPFX->hContainer, uiSaltLen, (void*) &hPFX->salt.data)))
	{
		memcpy(hPFX->salt.data, pSalt, uiSaltLen);
		hPFX->salt.length = uiSaltLen;
		hPFX->iterations = uiIterCount;
	}
	NH_safe_zeroize(pKey, PBE_MAC_KEY_LEN);
	return rv;
}


/**
 * @brief RFC 5652
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
const static NH_NODE_WAY __authenticated_safe_map[] =
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
static NH_RV __parse_authenticated_safe(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _OUT_ NH_ASN1_PARSER_HANDLE *hAuth)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE pSet, pNode;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 16, 8192, &hParser)) &&
		NH_SUCCESS(rv = hParser->map(hParser, __authenticated_safe_map, ASN_NODE_WAY_COUNT(__authenticated_safe_map)))
	)
	{
		pSet = hParser->root->child;
		while
		(
			pSet &&
			NH_SUCCESS(rv = (pNode = pSet->child) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_objectid(hParser, pNode, FALSE)) &&
			NH_SUCCESS(rv = NH_match_oid((unsigned int*) pNode->value, pNode->valuelen, cms_data_ct_oid, CMS_DATA_CTYPE_OID_COUNT) ? NH_OK : NH_PFX_UNSUPPORTED_TYPE_ERROR) &&
			NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode))
		)	pSet = pSet->next;
		if (NH_SUCCESS(rv)) *hAuth = hParser;
		else NH_release_parser(hParser);
	}
	return rv;
}
static NH_ASN1_PNODE __next_content_info
(
	_IN_ NH_ASN1_PARSER_HANDLE hParser,
	_IN_ NH_ASN1_PNODE pCurrent,
	_OUT_ unsigned char **ppBuffer,
	_OUT_ unsigned int *puiBufLen
)
{
	NH_ASN1_PNODE pSet = pCurrent ? pCurrent : hParser->root->child, pNode;

	if (!pSet) return NULL;
	if ((pNode = hParser->sail(pSet, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)))
	{
		*ppBuffer = (unsigned char*) pNode->value;
		*puiBufLen = pNode->valuelen;
	}
	return pSet->next;
}



/**
 * @brief RFC 5958
 * 
 * PrivateKeyInfo ::= OneAsymmetricKey
 * OneAsymmetricKey ::= SEQUENCE {
 * 	version                   Version,
 * 	privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 * 	privateKey                PrivateKey,
 * 	attributes            [0] Attributes OPTIONAL,
 * 	...,
 * 	[[2: publicKey        [1] PublicKey OPTIONAL ]],
 * 	...
 * }
 * PrivateKey ::= OCTET STRING
 * PublicKey ::= BIT STRING
 * Attributes ::= SET OF Attribute { { OneAsymmetricKeyAttributes } }
 */
/* TODO: */


/**
 * @brief RFC 5958
 * 
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 * 	encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 * 	encryptedData        EncryptedData
 * }
 * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier { CONTENT-ENCRYPTION, { KeyEncryptionAlgorithms }}
 * EncryptedData ::= OCTET STRING -- Encrypted PrivateKeyInfo
 */
const static NH_NODE_WAY __pkcs8ShroudedKeyBag_map[] =
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
static NH_RV __parse_shroudedkeybag
(
	_IN_ NH_CARGO_CONTAINER hContainer,
	_IN_ unsigned char *pBuffer,
	_IN_ unsigned int uiBufLen,
	_OUT_ NH_SHROUDEDKEYBAG *hBag
)
{
	NH_RV rv;
	NH_SHROUDEDKEYBAG hOut;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = hContainer->bite_chunk(hContainer, sizeof(NH_SHROUDEDKEYBAG_STR), (void*) &hOut))
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
				NH_SUCCESS(rv = hContainer->bite_chunk(hContainer, pNode->valuelen * sizeof(unsigned int), (void*) &hOut->algorithm.pIdentifier))
			)
			{
				memcpy(hOut->algorithm.pIdentifier, pNode->value, pNode->valuelen * sizeof(unsigned int));
				hOut->algorithm.uCount = pNode->valuelen;
				if
				(
					NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
					NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode)) &&
					NH_SUCCESS(rv = hContainer->bite_chunk(hContainer, pNode->valuelen, (void*) &hOut->salt.data))
				)
				{
					memcpy(hOut->salt.data, pNode->value, pNode->valuelen);
					hOut->salt.length = pNode->valuelen;
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
							NH_SUCCESS(rv = hContainer->bite_chunk(hContainer, pNode->valuelen, (void*) &hOut->contents.data))
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
const static NH_NODE_WAY __certbag_map[] =
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
static NH_RV __parse_certbag
(
	_IN_ NH_CARGO_CONTAINER hContainer,
	_IN_ unsigned char *pBuffer,
	_IN_ unsigned int uiBufLen,
	_OUT_ NH_CERTBAG *hBag
)
{
	NH_RV rv;
	NH_CERTBAG hOut;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = hContainer->bite_chunk(hContainer, sizeof(NH_CERTBAG_STR), (void*) &hOut))
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
				NH_SUCCESS(rv = hContainer->bite_chunk(hContainer, pNode->valuelen * sizeof(unsigned int), (void*) &hOut->certType.pIdentifier))
			)
			{
				memcpy(hOut->certType.pIdentifier, pNode->value, pNode->valuelen * sizeof(unsigned int));
				hOut->certType.uCount = pNode->valuelen;
				if
				(
					NH_SUCCESS(rv = (pNode = hParser->sail(pNode, NH_SAIL_SKIP_EAST << 8 | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
					NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode)) &&
					NH_SUCCESS(rv = hContainer->bite_chunk(hContainer, pNode->valuelen, (void*) &hOut->contents.data))
				)
				{
					memcpy(hOut->contents.data, pNode->value, pNode->valuelen);
					hOut->contents.length = pNode->valuelen;
					*hBag = hOut;
				}
			}
			NH_release_parser(hParser);
		}
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
const static NH_NODE_WAY __safe_contents_map[] =
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
static unsigned int pfx_keyBag_oid[]			= { 1, 2, 840, 113549, 1, 12, 10, 1, 1 };
static unsigned int pfx_pkcs8ShroudedKeyBag_oid[]	= { 1, 2, 840, 113549, 1, 12, 10, 1, 2 };
static unsigned int pfx_certBag_oid[]			= { 1, 2, 840, 113549, 1, 12, 10, 1, 3 };
static unsigned int pfx_crlBag_oid[]			= { 1, 2, 840, 113549, 1, 12, 10, 1, 4 };
static unsigned int pfx_secretBag_oid[]			= { 1, 2, 840, 113549, 1, 12, 10, 1, 5 };
static unsigned int pfx_safeContentsBag_oid[]		= { 1, 2, 840, 113549, 1, 12, 10, 1, 6 };
unsigned int pkcs9_x509_certificate_oid[]			= { 1, 2, 840, 113549, 1,  9, 22, 1    };
static NH_RV __parse_safe_contents
(
	_IN_ NH_CARGO_CONTAINER hContainer,
	_IN_ unsigned char *pBuffer,
	_IN_ unsigned int uiBufLen,
	_INOUT_ NH_SAFE_BAG *ppBagSet
)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE pBag, pNode;
	NH_SAFE_BAG pLastBag, pNewBag;

	if
	(
		NH_SUCCESS(rv = hContainer && pBuffer ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = NH_new_parser(pBuffer, uiBufLen, 16, 8192, &hParser)) &&
		NH_SUCCESS(rv = hParser->map(hParser, __safe_contents_map, ASN_NODE_WAY_COUNT(__safe_contents_map)))
	)
	{
		pBag = hParser->root->child;
		pLastBag = *ppBagSet;
		while
		(
			pBag &&
			NH_SUCCESS(rv = (pNode = pBag->child) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_oid(hParser, pNode)) &&
			NH_SUCCESS(rv = hContainer->bite_chunk(hContainer, sizeof(NH_SAFE_BAG_STR), (void*) &pNewBag)) &&
			NH_SUCCESS(rv)
		)
		{
			memset(pNewBag, 0, sizeof(NH_SAFE_BAG_STR));
			pNewBag->bagType.pIdentifier = (unsigned int*) pNode->value;
			pNewBag->bagType.uCount = pNode->valuelen;
			if (NH_match_oid(pNewBag->bagType.pIdentifier, pNewBag->bagType.uCount, pfx_keyBag_oid, NHC_OID_COUNT(pfx_keyBag_oid))) pNewBag->type = PFX_keyBag;
			else if (NH_match_oid(pNewBag->bagType.pIdentifier, pNewBag->bagType.uCount, pfx_pkcs8ShroudedKeyBag_oid, NHC_OID_COUNT(pfx_pkcs8ShroudedKeyBag_oid))) pNewBag->type = PFX_pkcs8ShroudedKeyBag;
			else if (NH_match_oid(pNewBag->bagType.pIdentifier, pNewBag->bagType.uCount, pfx_certBag_oid, NHC_OID_COUNT(pfx_certBag_oid))) pNewBag->type = PFX_certBag;
			else if (NH_match_oid(pNewBag->bagType.pIdentifier, pNewBag->bagType.uCount, pfx_crlBag_oid, NHC_OID_COUNT(pfx_crlBag_oid))) pNewBag->type = PFX_crlBag;
			else if (NH_match_oid(pNewBag->bagType.pIdentifier, pNewBag->bagType.uCount, pfx_secretBag_oid, NHC_OID_COUNT(pfx_secretBag_oid))) pNewBag->type = PFX_secretBag;
			else if (NH_match_oid(pNewBag->bagType.pIdentifier, pNewBag->bagType.uCount, pfx_safeContentsBag_oid, NHC_OID_COUNT(pfx_safeContentsBag_oid))) pNewBag->type = PFX_safeContentsBag;
			else rv = NH_PFX_BAG_ERROR;
			if
			(
				NH_SUCCESS(rv) &&
				NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR)
			)
			{
				pNewBag->contents.data = pNode->identifier;
				pNewBag->contents.length = pNode->size + pNode->contents - pNode->identifier;
				pNewBag->previous = pLastBag;
				if (!pLastBag) pLastBag = pNewBag;
				else pLastBag->next = pNewBag;
				pLastBag = pNewBag;
				switch (pNewBag->type)
				{
				case PFX_keyBag:
					/* TODO */
					break;
				case PFX_pkcs8ShroudedKeyBag:
					rv = __parse_shroudedkeybag(hContainer, pNewBag->contents.data, pNewBag->contents.length, &pNewBag->bag.pkcs8ShroudedKeyBag);
					break;
				case PFX_certBag:
					rv = __parse_certbag(hContainer, pNewBag->contents.data, pNewBag->contents.length, &pNewBag->bag.certBag);
					break;
				default:
					break;
				}
			}
			pBag = pBag->next;
		}
		NH_release_parser(hParser);
	}
	if (NH_SUCCESS(rv)) *ppBagSet = pLastBag;
	return rv;
}


/**
 * @brief RFC 8017
 * 
 * RSAPrivateKey ::= SEQUENCE {
 *    version           Version,
 *    modulus           INTEGER,  -- n
 *    publicExponent    INTEGER,  -- e
 *    privateExponent   INTEGER,  -- d
 *    prime1            INTEGER,  -- p
 *    prime2            INTEGER,  -- q
 *    exponent1         INTEGER,  -- d mod (p-1)
 *    exponent2         INTEGER,  -- d mod (q-1)
 *    coefficient       INTEGER,  -- (inverse of q) mod p
 *    otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 */
const static NH_NODE_WAY __rsa_privkey_pkcs_map[] =
{
	{	/* RSAPrivateKey */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* Version */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* modulus n */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* publicExponent e */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* privateExponent d */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* prime1 p */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* prime2 q */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* exponent1 dmp */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* exponent2 dmq */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* coefficient qmp */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* OtherPrimeInfos */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
static NH_RV __pfx_parse_rsa_key(_IN_ NH_BLOB *pKey, _OUT_ NH_ASN1_PARSER_HANDLE *hOut)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = pKey && pKey->data ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = NH_new_parser(pKey->data, pKey->length, 8, 4096, &hParser))
	)
	{
		if
		(
			NH_SUCCESS(rv = hParser->map(hParser, __rsa_privkey_pkcs_map, ASN_NODE_WAY_COUNT(__rsa_privkey_pkcs_map))) &&
			NH_SUCCESS(rv = (pNode = hParser->root->child) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_little_integer(hParser, pNode)) &&
			NH_SUCCESS(rv = (pNode = pNode->next) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			(NH_SUCCESS(rv = hParser->parse_integer(pNode))) &&
			NH_SUCCESS(rv = (pNode = pNode->next) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			(NH_SUCCESS(rv = hParser->parse_integer(pNode))) &&
			NH_SUCCESS(rv = (pNode = pNode->next) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			(NH_SUCCESS(rv = hParser->parse_integer(pNode))) &&
			NH_SUCCESS(rv = (pNode = pNode->next) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			(NH_SUCCESS(rv = hParser->parse_integer(pNode))) &&
			NH_SUCCESS(rv = (pNode = pNode->next) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			(NH_SUCCESS(rv = hParser->parse_integer(pNode))) &&
			NH_SUCCESS(rv = (pNode = pNode->next) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			(NH_SUCCESS(rv = hParser->parse_integer(pNode))) &&
			NH_SUCCESS(rv = (pNode = pNode->next) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			(NH_SUCCESS(rv = hParser->parse_integer(pNode))) &&
			NH_SUCCESS(rv = (pNode = pNode->next) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			(NH_SUCCESS(rv = hParser->parse_integer(pNode)))
		)	*hOut = hParser;
		else NH_release_parser(hParser);
	}
	return rv;
}
/**
 * @brief RFC 5208
 * 
 *  PrivateKeyInfo ::= SEQUENCE {
 *    version Version,
 *    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
 *    privateKey PrivateKey,
 *    attributes [0] Attributes OPTIONAL }
 * PrivateKey ::= OCTET STRING
 * PublicKey ::= BIT STRING
 * Attributes ::= SET OF Attribute { { OneAsymmetricKeyAttributes } }
 */
const static NH_NODE_WAY __privkey_info_map[] =
{
	{	/* PrivateKeyInfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* Version */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* PrivateKeyAlgorithmIdentifier */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* PrivateKey */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* attributes */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
static NH_RV __pfx_parse_privatekey(_IN_ NH_BLOB *pKey, _OUT_ NH_ASN1_PARSER_HANDLE *hOut)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE pNode;

	if
	(
		NH_SUCCESS(rv = pKey && pKey->data ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = NH_new_parser(pKey->data, pKey->length, 8, 4096, &hParser))
	)
	{
		if
		(
			NH_SUCCESS(rv = hParser->map(hParser, __privkey_info_map, ASN_NODE_WAY_COUNT(__privkey_info_map))) &&
			NH_SUCCESS(rv = (pNode = hParser->root->child) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_little_integer(hParser, pNode)) &&
			NH_SUCCESS(rv = (pNode = hParser->sail(pNode, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_oid(hParser, pNode)) &&
			NH_SUCCESS(rv = (pNode = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_PFX_INVALID_ENCODING_ERROR) &&
			NH_SUCCESS(rv = hParser->parse_octetstring(hParser, pNode))
		)	*hOut = hParser;
		else NH_release_parser(hParser);
	}
	return rv;
}
const static unsigned int pbeWithSHA1And3_KeyTripleDES_CBC_oid[] = { 1, 2, 840, 113549, 1, 12, 1, 3 };
static NH_RV __pfx_unpack_key(_IN_ NH_PFX_PARSER_STR *self, _IN_ NH_SAFE_BAG pBag, _IN_ char *szSecret, _INOUT_ NH_BLOB *pPlaintext)
{
	NH_RV rv;
	unsigned char *pBuffer;
	int iBufLen, iTempLen;
	EVP_CIPHER_CTX *ctx;
	unsigned char pKey[PBE_DES_KEY_LEN], pIV[PBE_DES_KEY_IV_LEN];

	if
	(
		NH_SUCCESS(rv = pBag && pBag->type == PFX_pkcs8ShroudedKeyBag && pBag->bag.pkcs8ShroudedKeyBag->contents.data && pPlaintext ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = NH_match_oid(pBag->bag.pkcs8ShroudedKeyBag->algorithm.pIdentifier, pBag->bag.pkcs8ShroudedKeyBag->algorithm.uCount, pbeWithSHA1And3_KeyTripleDES_CBC_oid, NHC_OID_COUNT(pbeWithSHA1And3_KeyTripleDES_CBC_oid)) ? NH_OK : NH_UNSUPPORTED_MECH_ERROR) &&
		NH_SUCCESS(rv = PKCS12_key_gen(szSecret, strlen(szSecret), pBag->bag.pkcs8ShroudedKeyBag->salt.data, pBag->bag.pkcs8ShroudedKeyBag->salt.length, PKCS12_KEY_ID, self->iterations, PBE_DES_KEY_LEN, pKey, EVP_sha1()) ? NH_OK : NH_PFX_OPENSSL_ERROR) &&
		NH_SUCCESS(rv = PKCS12_key_gen(szSecret, strlen(szSecret), pBag->bag.pkcs8ShroudedKeyBag->salt.data, pBag->bag.pkcs8ShroudedKeyBag->salt.length, PKCS12_IV_ID, self->iterations, PBE_DES_KEY_IV_LEN, pIV, EVP_sha1()) ? NH_OK : NH_PFX_OPENSSL_ERROR) &&
		NH_SUCCESS(rv = (ctx = EVP_CIPHER_CTX_new()) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		if
		(
			NH_SUCCESS(rv = EVP_CipherInit_ex(ctx, EVP_des_ede3_cbc(), NULL, pKey, pIV, 0) ? NH_OK : NH_CIPHER_INIT_ERROR) &&
			(iBufLen = EVP_CIPHER_CTX_block_size(ctx) + pBag->bag.pkcs8ShroudedKeyBag->contents.length) &&
			NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(iBufLen)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if
			(
				NH_SUCCESS(rv = EVP_CipherUpdate(ctx, pBuffer, &iBufLen, pBag->bag.pkcs8ShroudedKeyBag->contents.data, (int) pBag->bag.pkcs8ShroudedKeyBag->contents.length) ? NH_OK : NH_CIPHER_ERROR) &&
				NH_SUCCESS(rv = EVP_CipherFinal_ex(ctx, pBuffer + iBufLen, &iTempLen) ? NH_OK : NH_CIPHER_ERROR)
			)
			{
				pPlaintext->data = pBuffer;
				pPlaintext->length = iBufLen + iTempLen;
			}
			else free(pBuffer);
		}
		EVP_CIPHER_CTX_free(ctx);
	}
	NH_safe_zeroize(pKey, PBE_DES_KEY_LEN);
	return rv;
}
static NH_RV __pfx_first_bag(_IN_ NH_PFX_PARSER_STR *self, _INOUT_ NH_PFX_QUERY pQuery)
{
	unsigned int uiCount = 0, i;
	NH_SAFE_BAG pBag;

	pBag = self->pBagSet;
	while (pBag)
	{
		if (pBag->type == pQuery->bagType) uiCount++;
		pBag = pBag->next;
	}
	if (uiCount > 0)
	{
		i = 1;
		pBag = self->pBagSet;
		while (pBag && pBag->type != pQuery->bagType) pBag = pBag->next;
	}
	else
	{
		i = 0;
		pBag = NULL;
	}
	pQuery->pResult = pBag;
	pQuery->uiCount = uiCount;
	pQuery->uiCurrent = i;
	return NH_OK;
}
static NH_RV __pfx_next_bag(_IN_ NH_PFX_PARSER_STR *self, _INOUT_ NH_PFX_QUERY pQuery)
{
	NH_SAFE_BAG pBag;

	if (!(pQuery && pQuery->bagType)) return NH_INVALID_ARG;
	if (!pQuery->pResult) return __pfx_first_bag(self, pQuery);
	if (pQuery->uiCurrent < pQuery->uiCount)
	{
		pBag = pQuery->pResult->next;
		while (pBag && pBag->type != pQuery->bagType) pBag = pBag->next;
		pQuery->uiCurrent++;
		pQuery->pResult = pBag;
	}
	else pQuery->pResult = NULL;
	return NH_OK;
}
static NH_PFX_PARSER_STR __default_pfx =
{
	NULL,				/* hContainer */
	{ NULL, 0UL },		/* salt */
	0,				/* iterations */
	NULL,				/* pBagSet */
	__pfx_next_bag,		/* next_bag */
	__pfx_unpack_key,		/* unpack_key */
	__pfx_parse_privatekey,	/* parse_privkey */
	__pfx_parse_rsa_key	/* parse_rsa_key */
};
NH_FUNCTION(NH_RV, NHFX_new_pfx_parser)(_IN_ unsigned char *pBuffer, _IN_ unsigned int uiBufLen, _IN_ char *szSecret, _OUT_ NH_PFX_PARSER *hPFX)
{
	NH_RV rv;
	NH_PFX_PARSER hSelf = NULL;
	NH_ASN1_PARSER_HANDLE hPDU = NULL, hAuth;
	unsigned char *pContents, *pData;
	unsigned int uiContentsLen, uiDataLen;
	NH_ASN1_PNODE pNode;
	NH_SAFE_BAG pBagSet = NULL;
	
	if
	(
		NH_SUCCESS(rv = pBuffer && szSecret ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (hSelf = (NH_PFX_PARSER) malloc(sizeof(NH_PFX_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		memcpy(hSelf, &__default_pfx, sizeof(NH_PFX_PARSER_STR));
		if(
			NH_SUCCESS(rv = NH_freight_container(4024, &hSelf->hContainer)) &&
			NH_SUCCESS(rv = __parse_pdu(pBuffer, uiBufLen, &hPDU))
		)
		{
			if
			(
				NH_SUCCESS(rv = __pfx_verify_mac(hPDU, szSecret, hSelf)) &&
				NH_SUCCESS(rv = __pfx_contents(hPDU, &pContents, &uiContentsLen)) &&
				NH_SUCCESS(rv = __parse_authenticated_safe(pContents, uiContentsLen, &hAuth))
			)
			{
				pNode = NULL;
				do
				{
					pData = NULL;
					pNode = __next_content_info(hAuth, pNode, &pData, &uiDataLen);
					if (pData) rv = __parse_safe_contents(hSelf->hContainer, pData, uiDataLen, &pBagSet);
				}
				while (NH_SUCCESS(rv) && pNode);
				NH_release_parser(hAuth);
			}
			if (NH_SUCCESS(rv))
			{
				while (pBagSet->previous) pBagSet = pBagSet->previous;
				hSelf->pBagSet = pBagSet;
				*hPFX = hSelf;
			}
			NH_release_parser(hPDU);
		}
		
	}
	return rv;
}
NH_FUNCTION(void, NHFX_delete_pfx_parser)(_INOUT_ NH_PFX_PARSER hParser)
{
	if (hParser)
	{
		NH_release_container(hParser->hContainer);
		free(hParser);
	}
}