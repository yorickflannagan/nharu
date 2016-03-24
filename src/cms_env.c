#include "cms.h"
#include <string.h>


/** ****************************
 *  CMS EnvelopedData parsing
 *  ****************************/
NH_UTILITY(NH_RV, cms_env_get_rid)(_IN_ NH_CMS_ENV_PARSER_STR *self, _IN_ size_t idx, _OUT_ NH_CMS_ISSUER_SERIAL *ret)
{
	NH_ASN1_PNODE node;

	if (idx >= self->count || !self->recips) return NH_INVALID_SIGNER_ERROR;
	if (!(node = self->hParser->sail(self->recips[idx], (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST))) return NH_CANNOT_SAIL;
	return NH_cms_get_rid(self->hParser, self->mutex, node, ret);
}


NH_UTILITY(NH_RV, cms_env_decrypt)(_INOUT_ NH_CMS_ENV_PARSER_STR *self, _IN_ size_t idx, _IN_ NH_CMS_PDEC_FUNCTION callback, _IN_ void *params)
{
	NH_ASN1_PNODE node, encryptedContent;
	CK_MECHANISM_TYPE mechanism;
	NH_RV rv, gRV;
	NH_SYMKEY cipherKey,  key = { NULL, 0 };
	NH_IV iv;
	NH_SYMKEY_HANDLER hCipher;

	if (self->plaintext.data) return NH_OK;
	if (!callback) return NH_INVALID_ARG;
	if (idx >= self->count || !self->recips) return NH_INVALID_SIGNER_ERROR;
	if (!(encryptedContent = self->hParser->sail(self->content, (NH_SAIL_SKIP_SOUTH << 24) | ((NH_PARSE_EAST | 3) << 16) | (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) return NH_CMS_ENV_NOECONTENT_ERROR;
	if (!(node = self->hParser->sail(self->recips[idx], (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) || !node->child) return NH_CANNOT_SAIL;

	if (NH_match_oid(node->child->value, node->child->valuelen, rsaEncryption_oid, NHC_RSA_ENCRYPTION_OID_COUNT)) mechanism = CKM_RSA_PKCS;
	else if (NH_match_oid(node->child->value, node->child->valuelen, rsaes_oaep_oid, NHC_RSAES_OAEP_OID_COUNT)) mechanism = CKM_RSA_PKCS_OAEP;
	else if (NH_match_oid(node->child->value, node->child->valuelen, rsa_x509_oid, NHC_RSA_X509_OID_COUNT)) mechanism = CKM_RSA_X_509;
	else return NH_UNSUPPORTED_MECH_ERROR;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	cipherKey.data = node->value;
	cipherKey.length = node->valuelen;
	if (NH_FAIL(rv = callback(&cipherKey, mechanism, params, NULL, &key.length))) return rv;
	if (!(key.data = (unsigned char*) malloc(key.length))) return NH_OUT_OF_MEMORY_ERROR;
	rv = callback(&cipherKey, mechanism, params, key.data, &key.length);

	if (NH_SUCCESS(rv)) rv = (node = self->hParser->sail(self->content, (NH_SAIL_SKIP_SOUTH << 24) | ((NH_PARSE_EAST | 3) << 16) | (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST))  && node->child && node->child->next ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = (mechanism = NH_oid_to_mechanism(node->child->value, node->child->valuelen)) != CK_UNAVAILABLE_INFORMATION ? NH_OK : NH_UNSUPPORTED_MECH_ERROR;
	if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_symkey_handler(CK_UNAVAILABLE_INFORMATION, &hCipher)))
	{

		hCipher->key = &key;
		iv.data = node->child->next->value;
		iv.length = node->child->next->valuelen;
		rv = hCipher->decrypt_init(hCipher, mechanism, &iv);
		if (NH_SUCCESS(rv))
		{
			GUARD(self->mutex, gRV,
			{
				rv = hCipher->decrypt(hCipher, encryptedContent->value, encryptedContent->valuelen, NULL, &self->plaintext.length);
				if (NH_SUCCESS(rv)) rv = (self->plaintext.data = (unsigned char*) malloc(self->plaintext.length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
				if (NH_SUCCESS(rv)) rv = hCipher->decrypt(hCipher, encryptedContent->value, encryptedContent->valuelen, self->plaintext.data, &self->plaintext.length);
			})
			if (NH_FAIL(gRV)) rv = gRV;
		}
		hCipher->key = NULL;
		NH_release_symkey_handler(hCipher);
	}
	NH_safe_zeroize(key.data, key.length);
	free(key.data);
	return rv;
}

const static NH_CMS_ENV_PARSER_STR defCMS_env_parser =
{
	NULL,			/* mutex */
	NULL,			/* hParser */
	NULL,			/* content */
	NULL,			/* recips */
	0,			/* count */
	{ NULL, 0 },	/* plaintext */

	cms_env_get_rid,
	cms_env_decrypt
};

/*
 * KeyTransRecipientInfo ::= SEQUENCE {
 *	version                CMSVersion,        -- always set to 0 or 2
 *	rid                    RecipientIdentifier,
 *	keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *	encryptedKey           EncryptedKey }
 * RecipientIdentifier ::= CHOICE {
 *	issuerAndSerialNumber    IssuerAndSerialNumber,
 *	subjectKeyIdentifier [0] SubjectKeyIdentifier }
 *
 * KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * EncryptedKey ::= OCTET STRING
 */
const static NH_NODE_WAY key_trans_recip_info[] =
{
	{	/* version */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* rid/issuerAndSerialNumber */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CHOICE_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* rid/subjectKeyIdentifier */
		NH_PARSE_ROOT,
		NH_ASN1_OCTET_STRING | NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* keyEncryptionAlgorithm */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* encryptedKey */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING,
		NULL,
		0
	}
};

/*
 * RecipientInfo ::= CHOICE {
 *	ktri      KeyTransRecipientInfo, -- supported RecipientInfo
 *	kari  [1] KeyAgreeRecipientInfo,
 *	kekri [2] KEKRecipientInfo,
 *	pwri  [3] PasswordRecipientinfo,
 *	ori   [4] OtherRecipientInfo }
 */
static NH_NODE_WAY cms_recip_info_map[] =
{
	{
		/* KeyTransRecipientInfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CHOICE_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* KeyAgreeRecipientInfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_CHOICE_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* KEKRecipientInfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_2 | NH_ASN1_CHOICE_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* PasswordRecipientinfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_3 | NH_ASN1_CHOICE_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* OtherRecipientInfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_4 | NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	}
};
/*
 * EnvelopedData ::= SEQUENCE {
 *	version CMSVersion,
 *	originatorInfo   [0] IMPLICIT OriginatorInfo OPTIONAL,
 *	recipientInfos       RecipientInfos,
 *	encryptedContentInfo EncryptedContentInfo,
 *	unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 *
 * OriginatorInfo ::= SEQUENCE {
 *	certs [0] IMPLICIT CertificateSet OPTIONAL,
 *	crls  [1] IMPLICIT RevocationInfoChoices OPTIONAL }
 *
 * RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
 *
 * EncryptedContentInfo ::= SEQUENCE {
 *	contentType                ContentType,
 *	contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *	encryptedContent      [0] IMPLICIT EncryptedContent OPTIONAL }
 * ContentType ::= OBJECT IDENTIFIER
 * ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * EncryptedContent ::= OCTET STRING
 *
 * UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
 */
const static NH_NODE_WAY cms_enveloped_data_map[] =
{
	{	/* EnvelopedData */
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
	{	/* originatorInfo */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* recipientInfos */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		cms_recip_info_map,
		ASN_NODE_WAY_COUNT(cms_recip_info_map)
	},
	{	/* encryptedContentInfo */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
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
	{	/* contentEncryptionAlgorithm */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	},
	{	/* unprotectedAttrs */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_SET | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};

NH_FUNCTION(NH_RV, NH_cms_parse_enveloped_data)(_IN_ unsigned char *encoding, _IN_ size_t size, _OUT_ NH_CMS_ENV_PARSER *hHandler)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node, content, recip, *recips;
	size_t count = 0, i;
	NH_CMS_ENV_PARSER ret = NULL;

	if (NH_FAIL(rv = NH_new_parser(encoding, size, 24, size + 512, &hParser))) return rv;
	if (NH_SUCCESS(rv = hParser->map(hParser, cms_map, CMS_MAP)) && (node = hParser->root->child)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = NH_find_content_type(node) == NH_ENVELOPED_DATA_CTYPE ? NH_OK : NH_INVALID_CT_ERROR;
	if (NH_SUCCESS(rv)) rv = (node = node->next) && (node = node->child) && (content = node) ? NH_OK : NH_UNEXPECTED_ENCODING;

	if (NH_SUCCESS(rv)) rv = hParser->map_from(hParser, node, cms_enveloped_data_map, ASN_NODE_WAY_COUNT(cms_enveloped_data_map));
	if (NH_SUCCESS(rv)) rv = (recip = hParser->sail(content, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING;
	while (NH_SUCCESS(rv) && recip)
	{
		rv = ASN_TAG_IS_PRESENT(recip, NH_ASN1_SEQUENCE) ? NH_OK : NH_CMS_UNSUP_RECIP_ERROR;
		if (NH_SUCCESS(rv)) rv = hParser->map_from(hParser, recip, key_trans_recip_info, ASN_NODE_WAY_COUNT(key_trans_recip_info));
		if (NH_SUCCESS(rv)) rv = (node = hParser->sail(recip, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv))
		{
			if (ASN_TAG_IS_PRESENT(node, NH_ASN1_SEQUENCE)) rv = hParser->map_from(hParser, node, cms_issuer_serial, CMS_ISSUERSERIAL_MAP_COUNT);
			else rv = hParser->parse_octetstring(node);
		}
		if (NH_SUCCESS(rv)) rv = (node = hParser->sail(recip, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) |NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
		if (NH_SUCCESS(rv)) rv = (node = hParser->sail(recip, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 3))) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv)) rv = hParser->parse_octetstring(node);
		recip = recip->next;
		count++;

	}
	if (NH_SUCCESS(rv) && count > 0) rv = hParser->container->bite_chunk(hParser->container, count * sizeof(NH_ASN1_PNODE), (void*) &recips);
	if (NH_SUCCESS(rv)) rv = (recip = hParser->sail(content, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv))
	{
		for (i = 0; i < count; i++)
		{
			recips[i] = recip;
			recip = recip->next;
		}
	}

	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(content, (NH_SAIL_SKIP_SOUTH << 24) | ((NH_PARSE_EAST | 3) << 16) | (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST))  && node->child ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node->child);
	if (NH_SUCCESS(rv)) rv = node->child->next && ASN_TAG_IS_PRESENT(node->child->next, NH_ASN1_OCTET_STRING) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_octetstring(node->child->next);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_octetstring(node);
	if (NH_SUCCESS(rv)) rv = (ret = (NH_CMS_ENV_PARSER) malloc(sizeof(NH_CMS_ENV_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv))
	{
		memcpy(ret, &defCMS_env_parser, sizeof(NH_CMS_ENV_PARSER_STR));
		rv = NH_create_mutex(&ret->mutex);
	}
	if (NH_SUCCESS(rv))
	{
		ret->hParser = hParser;
		ret->content = content;
		ret->recips = recips;
		ret->count = count;
		*hHandler = ret;
	}
	else
	{
		if (ret) free(ret);
		NH_release_parser(hParser);
	}
	return rv;
}

NH_FUNCTION(void, NH_cms_release_env_parser)(_INOUT_ NH_CMS_ENV_PARSER hHandler)
{
	if (hHandler)
	{
		if (hHandler->mutex) NH_release_mutex(hHandler->mutex);
		if (hHandler->hParser) NH_release_parser(hHandler->hParser);
		if (hHandler->plaintext.data) free(hHandler->plaintext.data);
		free(hHandler);
	}
}
