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

NH_UTILITY(NH_RV, cms_env_key_encryption_algorithm)
(
	_IN_ NH_CMS_ENV_PARSER_STR *self,
	_IN_ size_t idx,
	_OUT_ NH_ASN1_PNODE *alg_id,
	_OUT_ CK_MECHANISM_TYPE_PTR alg
)
{
	NH_ASN1_PNODE node;
	CK_MECHANISM_TYPE mechanism;

	if (idx >= self->count || !self->recips) return NH_INVALID_SIGNER_ERROR;
	if (!(node = self->hParser->sail(self->recips[idx], (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) || !node->child) return NH_CANNOT_SAIL;
	if (NH_match_oid(node->child->value, node->child->valuelen, rsaEncryption_oid, NHC_RSA_ENCRYPTION_OID_COUNT)) mechanism = CKM_RSA_PKCS;
	else if (NH_match_oid(node->child->value, node->child->valuelen, rsaes_oaep_oid, NHC_RSAES_OAEP_OID_COUNT)) mechanism = CKM_RSA_PKCS_OAEP;
	else if (NH_match_oid(node->child->value, node->child->valuelen, rsa_x509_oid, NHC_RSA_X509_OID_COUNT)) mechanism = CKM_RSA_X_509;
	else return NH_UNSUPPORTED_MECH_ERROR;
	*alg_id = node;
	*alg = mechanism;
	return NH_OK;
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
	if (NH_FAIL(rv = self->key_encryption_algorithm(self, idx, &node, &mechanism))) return rv;
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
	cms_env_key_encryption_algorithm,
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


/** ****************************
 *  CMS EnvelopedData encoding
 *  ****************************/
NH_UTILITY(NH_RV, put_EncryptedContentInfo)
(
	_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder,
	_IN_ NH_ASN1_PNODE from,
	_IN_ CK_MECHANISM_TYPE cipher,
	_IN_ size_t keySize,
	_IN_ NH_BLOB *iv,
	_IN_ NH_BLOB *cipherText
)
{
	NH_ASN1_PNODE node;
	unsigned int *oid;
	size_t oidCount;
	NH_RV rv;

	if (!from || !(node = from->child)) return NH_CANNOT_SAIL;
	switch (cipher)
	{
	case CKM_RC2_CBC:
		oid = rc2_cbc_oid;
		oidCount = NHC_RC2_CBC_OID_COUNT;
		break;
	case CKM_DES3_CBC:
		oid = des3_cbc_oid;
		oidCount = NHC_DES3_CBC_OID_COUNT;
		break;
	case CKM_AES_CBC:
		switch (keySize)
		{
		case 16:
			oid = aes128_cbc_oid;
			oidCount = NHC_AES128_CBC_OID_COUNT;
			break;
		case 24:
			oid = aes192_cbc_oid;
			oidCount = AES192_CBC_OID_COUNT;
			break;
		case 32:
			oid = aes256_cbc_oid;
			oidCount = AES256_CBC_OID_COUNT;
			break;
		default: return NH_UNSUPPORTED_MECH_ERROR;
		}
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if (NH_FAIL(rv = hEncoder->put_objectid(hEncoder, node, cms_data_ct_oid, CMS_DATA_CTYPE_OID_COUNT, CK_FALSE))) return rv;
	if (!(node = hEncoder->sail(node, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->put_objectid(hEncoder, node, oid, oidCount, CK_FALSE))) return rv;
	if (!(node = node->next)) return NH_CANNOT_SAIL;
	*node->identifier = NH_ASN1_OCTET_STRING;
	node->knowledge = NH_ASN1_OCTET_STRING;
	if (NH_FAIL(rv = hEncoder->put_octet_string(hEncoder, node, iv->data, iv->length))) return rv;
	if (!(node = hEncoder->sail(from, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) return NH_CANNOT_SAIL;
	hEncoder->register_optional(node);
	return hEncoder->put_octet_string(hEncoder, node, cipherText->data, cipherText->length);
}
NH_UTILITY(NH_RV, cms_env_encrypt)
(
	_INOUT_ NH_CMS_ENV_ENCODER_STR *self,
	_IN_ CK_MECHANISM_TYPE keyGen,
	_IN_ size_t keySize,
	_IN_ CK_MECHANISM_TYPE cipher
)
{
	NH_RV rv;
	NH_SYMKEY_HANDLER hKey;
	NH_IV *iv;
	NH_BLOB cipherText;

	if (self->key.data) return NH_CMS_ALREADYSET_ERROR;
	if (NH_SUCCESS(rv = NH_new_symkey_handler(keyGen, &hKey)))
	{
		if
		(
			NH_SUCCESS(rv = hKey->generate(hKey, keySize)) &&
			NH_SUCCESS(rv = (self->key.data = (unsigned char*) malloc(hKey->key->length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if (NH_SUCCESS(rv = hKey->new_iv(cipher, &iv)))
			{
				if
				(
					NH_SUCCESS(rv = hKey->encrypt_init(hKey, cipher, iv)) &&
					NH_SUCCESS(rv = hKey->encrypt(hKey, self->plainContent.data, self->plainContent.length, NULL, &cipherText.length)) &&
					NH_SUCCESS(rv = (cipherText.data = (unsigned char*) malloc(cipherText.length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
				)
				{
					if
					(
						NH_SUCCESS(rv = hKey->encrypt
						(
							hKey,
							self->plainContent.data,
							self->plainContent.length,
							cipherText.data,
							&cipherText.length
						))
					)	rv = put_EncryptedContentInfo
						(
							self->hEncoder,
							self->hEncoder->sail(self->content, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 3)),
							cipher,
							keySize,
							iv,
							&cipherText
						);
					free(cipherText.data);
				}
				hKey->release_iv(iv);
			}
			if (NH_SUCCESS(rv))
			{
				memcpy(self->key.data, hKey->key->data, hKey->key->length);
				self->key.length = hKey->key->length;
			}
		}
		NH_release_symkey_handler(hKey);
	}
	return rv;
}

const static NH_NODE_WAY key_trans_recip_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, cms_env_key_trans_recip)
(
	_INOUT_ NH_CMS_ENV_ENCODER_STR *self,
	_IN_ NH_CERTIFICATE_HANDLER hCert,
	_IN_ CK_MECHANISM_TYPE mechanism
)
{
	NH_RV rv;
	NH_ASN1_PNODE node, rsakey;
	unsigned int *oid;
	size_t oidCount;
	NH_RSA_PUBKEY_HANDLER hPubKey;
	NH_BIG_INTEGER n, e;
	unsigned char *buffer;
	size_t buflen;

	if (!self->key.data) return NH_CMS_ENV_NOKEY_ERROR;
	if (!hCert) return NH_INVALID_ARG;
	if (NH_oid_to_mechanism(hCert->pubkey->child->child->value, hCert->pubkey->child->child->valuelen) != CKM_RSA_PKCS_KEY_PAIR_GEN) return NH_UNSUPPORTED_MECH_ERROR;
	switch (mechanism)
	{
	case CKM_RSA_PKCS_OAEP:
		oid = rsaes_oaep_oid;
		oidCount = NHC_RSAES_OAEP_OID_COUNT;
		break;
	case CKM_RSA_PKCS:
		oid = rsaEncryption_oid;
		oidCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	case CKM_RSA_X_509:
		oid = rsa_x509_oid;
		oidCount = NHC_RSA_X509_OID_COUNT;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if (!(node = self->hEncoder->sail(self->content, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) return NH_CANNOT_SAIL;
	if (!(node = self->hEncoder->add_to_set(self->hEncoder->container, node))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, key_trans_recip_map, ASN_NODE_WAY_COUNT(key_trans_recip_map)))) return rv;
	if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, key_trans_recip_info, ASN_NODE_WAY_COUNT(key_trans_recip_info)))) return rv;
	if (!(node = node->child)) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = self->hEncoder->put_little_integer(self->hEncoder, node, 0))) return rv;
	if (!(node = node->next)) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, issuer_serial_map, ISSUER_SERIAL_MAP_COUNT))) return rv;
	if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, cms_issuer_serial, CMS_ISSUERSERIAL_MAP_COUNT))) return rv;
	if (!node->child) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = NH_asn_clone_node(self->hEncoder->container, hCert->issuer->node, &node->child))) return rv;
	if (!node->child->next) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = self->hEncoder->put_integer(self->hEncoder, node->child->next, hCert->serialNumber->value, hCert->serialNumber->valuelen))) return rv;
	if (!(node = node->next) || !(node->child)) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = self->hEncoder->put_objectid(self->hEncoder, node->child, oid, oidCount, CK_FALSE))) return rv;
	if (mechanism == CKM_RSA_PKCS_OAEP)
	{
		if (!(node->child->next)) return NH_CANNOT_SAIL;
		*node->child->next->identifier = NH_ASN1_SEQUENCE;
	}
	if (!(node = node->next)) return NH_CANNOT_SAIL;

	rsakey = hCert->pubkey->child->next->child;
	if (NH_SUCCESS(rv = NH_new_RSA_pubkey_handler(&hPubKey)))
	{
		buffer = rsakey->child->value;
		buflen = rsakey->child->valuelen;
		if (!buffer[0])
		{
			buffer++;
			buflen--;
		}
		n.data = buffer;
		n.length = buflen;
		buffer = rsakey->child->next->value;
		buflen = rsakey->child->next->valuelen;
		if (!buffer[0])
		{
			buffer++;
			buflen--;
		}
		e.data = buffer;
		e.length = buflen;
		if
		(
			NH_SUCCESS(rv = hPubKey->create(hPubKey, &n, &e)) &&
			NH_SUCCESS(rv = hPubKey->encrypt(hPubKey, mechanism, self->key.data, self->key.length, NULL, &buflen)) &&
			NH_SUCCESS(rv = (buffer = (unsigned char*) malloc(buflen)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if
			(
				NH_SUCCESS(rv = hPubKey->encrypt(hPubKey, mechanism, self->key.data, self->key.length, buffer, &buflen))
			)	rv = self->hEncoder->put_octet_string(self->hEncoder, node, buffer, buflen);
			free(buffer);
		}
		NH_release_RSA_pubkey_handler(hPubKey);
	}
	return rv;
}

const static NH_CMS_ENV_ENCODER_STR defCMS_ENV_encoder =
{
	NULL,			/* hEncoder */
	NULL,			/* content */
	{ NULL, 0 },	/* plainContent */
	{ NULL, 0 },	/* key */

	cms_env_encrypt,
	cms_env_key_trans_recip
};

NH_FUNCTION(NH_RV, NH_cms_encode_encode_enveloped_data)(_IN_ NH_BLOB *eContent, _OUT_ NH_CMS_ENV_ENCODER *hHandler)
{
	NH_RV rv;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	NH_ASN1_PNODE node, content;
	NH_CMS_ENV_ENCODER ret = NULL;

	if (!eContent || !eContent->data) return NH_INVALID_ARG;
	if (NH_FAIL(rv = NH_new_encoder(64, 4096, &hEncoder))) return rv;
	rv = hEncoder->chart(hEncoder, cms_map, CMS_MAP, &node);

	if (NH_SUCCESS(rv)) rv = hEncoder->put_objectid(hEncoder, node->child, cms_enveloped_data_ct_oid, CMS_ENVELOPED_DATA_OID_COUNT, CK_FALSE);
	if (NH_SUCCESS(rv)) rv = (content = hEncoder->sail(node, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL;

	if (NH_SUCCESS(rv)) rv = hEncoder->chart_from(hEncoder, content, cms_enveloped_data_map, ASN_NODE_WAY_COUNT(cms_enveloped_data_map));
	if (NH_SUCCESS(rv)) rv = (node = content->child) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hEncoder->put_little_integer(hEncoder, node, 0);
	if (NH_SUCCESS(rv)) rv = (ret = malloc(sizeof(NH_CMS_ENV_ENCODER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv))
	{
		memcpy(ret, &defCMS_ENV_encoder, sizeof(NH_CMS_ENV_ENCODER_STR));
		if (eContent && NH_SUCCESS(rv = (ret->plainContent.data = (unsigned char*) malloc(eContent->length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
		{
			memcpy(ret->plainContent.data, eContent->data, eContent->length);
			ret->plainContent.length = eContent->length;
		}
	}
	if (NH_SUCCESS(rv))
	{
		ret->hEncoder = hEncoder;
		ret->content = content;
		*hHandler = ret;
	}
	else
	{
		if (ret)
		{
			if (ret->plainContent.data) free(ret->plainContent.data);
			free(ret);
		}
		NH_release_encoder(hEncoder);
	}
	return rv;
}

NH_FUNCTION(void, NH_cms_release_env_encoder)(_INOUT_ NH_CMS_ENV_ENCODER hHandler)
{
	if (hHandler)
	{
		if (hHandler->plainContent.data) free(hHandler->plainContent.data);
		if (hHandler->hEncoder) NH_release_encoder(hHandler->hEncoder);
		if (hHandler->key.data)
		{
			NH_safe_zeroize(hHandler->key.data, hHandler->key.length);
			free(hHandler->key.data);
		}
		free(hHandler);
	}
}
