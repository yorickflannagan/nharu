#include "cms.h"
#include <string.h>
#include <time.h>
#include <stdio.h>


/** ****************************
 *  CMS SignedData discovery
 *  ****************************/
unsigned int cms_data_ct_oid[]					= { 1, 2, 840, 113549, 1, 7, 1 };
const static unsigned int cms_signed_data_ct_oid[]		= { 1, 2, 840, 113549, 1, 7, 2 };
unsigned int cms_enveloped_data_ct_oid[]				= { 1, 2, 840, 113549, 1, 7, 3 };
const static unsigned int cms_digested_data_ct_oid[]		= { 1, 2, 840, 113549, 1, 7, 5 };
const static unsigned int cms_encrypted_data_ct_oid[]		= { 1, 2, 840, 113549, 1, 7, 6 };
const static unsigned int cms_authenticated_data_ct_oid[]	= { 1, 2, 840, 113549, 1, 9, 16, 1, 2 };
const static unsigned int* cms_content_types[] =
{
	cms_data_ct_oid,
	cms_signed_data_ct_oid,
	cms_enveloped_data_ct_oid,
	cms_digested_data_ct_oid,
	cms_encrypted_data_ct_oid,
	cms_authenticated_data_ct_oid
};
const static size_t type_size[] =
{
	NHC_OID_COUNT(cms_data_ct_oid),
	NHC_OID_COUNT(cms_signed_data_ct_oid),
	NHC_OID_COUNT(cms_enveloped_data_ct_oid),
	NHC_OID_COUNT(cms_digested_data_ct_oid),
	NHC_OID_COUNT(cms_encrypted_data_ct_oid),
	NHC_OID_COUNT(cms_authenticated_data_ct_oid)
};
INLINE NH_UTILITY(NH_CMS_CONTENT_TYPE, NH_find_content_type)(_IN_ NH_ASN1_PNODE node)
{
	int i;

	for (i = 0; i < 6; i++)
		if (NH_match_oid((unsigned int*) node->value, node->valuelen, cms_content_types[i], type_size[i])) return i;
	return NH_UNKNOWN_CTYPE;
}

NH_NODE_WAY cms_map[] =
{
	{	/* ContentInfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
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
	}
};

NH_FUNCTION(NH_CMS_CONTENT_TYPE, NH_cms_discover)(_IN_ unsigned char *buffer, _IN_ size_t size)
{
	NH_ASN1_PARSER_HANDLE hParser;
	NH_CMS_CONTENT_TYPE ret = NH_UNKNOWN_CTYPE;

	if (NH_SUCCESS(NH_new_parser(buffer, size, 3, 128, &hParser)))
	{
		if
		(
			NH_SUCCESS(hParser->map(hParser, cms_map, CMS_MAP)) &&
			hParser->root->child &&
			NH_SUCCESS(hParser->parse_oid(hParser, hParser->root->child))
		)	ret = NH_find_content_type(hParser->root->child);
		NH_release_parser(hParser);
	}
	return ret;
}

INLINE NH_UTILITY(NH_RV, NH_cms_get_rid)
(
	_INOUT_ NH_ASN1_PARSER_HANDLE hParser,
	_IN_ NH_MUTEX_HANDLE mutex,
	_IN_ NH_ASN1_PNODE node,
	_OUT_ NH_CMS_ISSUER_SERIAL *ret
)
{
	NH_RV rv = NH_OK, gRV;
	NH_NAME_NODE name = NULL;
	NH_ASN1_PNODE serial = NULL, keyId = NULL;
	NH_CMS_ISSUER_SERIAL sid;

	if (!node) return NH_INVALID_ARG;
	GUARD(mutex, gRV,
	{
		if (ASN_TAG_IS_PRESENT(node, NH_ASN1_SEQUENCE) && NH_SUCCESS(rv = NHIX_parse_name(hParser, node->child, &name)))
		{
			if ((serial = node->child->next)) rv = hParser->parse_integer(serial);
			else rv = NH_CANNOT_SAIL;
		}
		else keyId = node;
	})
	if (NH_FAIL(gRV)) return gRV;
	if (!name && !serial && !keyId) return NH_INVALID_CMS_ERROR;
	if (NH_SUCCESS(rv))
	{
		rv = hParser->container->bite_chunk(hParser->container, sizeof(NH_CMS_ISSUER_SERIAL_STR), (void*) &sid);
		if (NH_SUCCESS(rv))
		{
			sid->name = name;
			sid->serial = serial;
			sid->keyIdentifier = keyId;
			*ret = sid;
		}
	}
	return rv;
}



/** ****************************
 *  CMS SignedData parsing
 *  ****************************/
NH_UTILITY(NH_RV, cms_sd_get_sid)(_IN_ NH_CMS_SD_PARSER_STR *self, _IN_ size_t idx, _OUT_ NH_CMS_ISSUER_SERIAL *ret)
{
	NH_ASN1_PNODE node;

	if (idx >= self->count || !self->signers) return NH_INVALID_SIGNER_ERROR;
	if (!(node = self->hParser->sail(self->signers[idx], (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST))) return NH_CANNOT_SAIL;
	return NH_cms_get_rid(self->hParser, self->mutex, node, ret);
}

NH_UTILITY(NH_RV, cms_sd_get_cert)(_IN_ NH_CMS_SD_PARSER_STR *self, _IN_ NH_CMS_ISSUER_SERIAL sid, _OUT_ NH_CERTIFICATE_HANDLER *ret)
{
	NH_ASN1_PNODE node, ski;
	NH_RV rv = NH_OK;
	NH_CERTIFICATE_HANDLER hCert;

	if (!ASN_IS_PRESENT(self->certificates)) return NH_CERT_NOT_PRESENT_ERROR;
	if (!sid || (!sid->keyIdentifier && (!sid->name || !sid->serial))) return NH_INVALID_ARG;
	node = self->certificates->child;
	while (node && NH_SUCCESS(rv))
	{
		if (NH_SUCCESS(rv = NH_parse_certificate(node->identifier, node->size + node->contents - node->identifier, &hCert)))
		{
			if (sid->keyIdentifier)
			{
				if
				(
					NH_SUCCESS(rv = hCert->ski(hCert, &ski)) &&
					ski &&
					ski->valuelen == sid->keyIdentifier->valuelen &&
					memcmp(ski->value, sid->keyIdentifier->value, ski->valuelen)
				)
				{
					*ret = hCert;
					return NH_OK;
				}
			}
			else
			{
				if
				(
					strcmp(hCert->issuer->stringprep, sid->name->stringprep) == 0 &&
					hCert->serialNumber->valuelen == sid->serial->valuelen  &&
					memcmp(hCert->serialNumber->value, sid->serial->value, hCert->serialNumber->valuelen) == 0
				)
				{
					*ret = hCert;
					return NH_OK;
				}
			}
			NH_release_certificate(hCert);
		}
		node = node->next;
	}
	if (NH_SUCCESS(rv)) rv = NH_CERT_NOT_PRESENT_ERROR;
	return rv;
}

NH_UTILITY(NH_RV, cms_sd_verify)(_IN_ NH_CMS_SD_PARSER_STR *self, _IN_ size_t idx, _IN_ NH_ASN1_PNODE pubKeyInfo)
{
	NH_ASN1_PNODE node, sig;
	CK_MECHANISM_TYPE hash;
	NH_RV rv;

	if (idx >= self->count || !self->signers) return NH_INVALID_SIGNER_ERROR;
	if (!(node = self->hParser->sail(self->signers[idx], (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) | NH_SAIL_SKIP_SOUTH))) return NH_CANNOT_SAIL;
	if ((hash = NH_oid_to_mechanism(node->value, node->valuelen)) == CK_UNAVAILABLE_INFORMATION) return NH_UNSUPPORTED_MECH_ERROR;
	if (!(sig = self->hParser->sail(self->signers[idx], (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 5)))) return NH_CANNOT_SAIL;
	if (!(node = self->hParser->sail(self->signers[idx], (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 3)))) return NH_CANNOT_SAIL;
	if (!ASN_IS_PRESENT(node)) return NH_CMS_NO_SIGATTRS_ERROR;
	*node->identifier = NH_ASN1_SET;
	rv = NHIX_verify_signature(node, pubKeyInfo, hash, sig);
	*node->identifier = 0xA0;
	return rv;
}


NH_UTILITY(NH_RV, _verify_signature_)
(
	_IN_ NH_ASN1_PNODE node,
	_IN_ NH_RSA_PUBKEY_HANDLER pubKey,
	_IN_ CK_MECHANISM_TYPE hashAlg,
	_IN_ NH_ASN1_PNODE sig
)
{
	NH_RV rv;
	NH_HASH_HANDLER hHash;
	unsigned char *hash, *signature;
	size_t hashsize, siglen;
	CK_MECHANISM_TYPE sigAlg;

	if (NH_SUCCESS(rv = NH_new_hash(&hHash)))
	{
		if
		(
			NH_SUCCESS(rv = hHash->init(hHash, hashAlg)) &&
			NH_SUCCESS(rv = hHash->digest(hHash, node->identifier, node->contents - node->identifier + node->size, NULL, &hashsize)) &&
			NH_SUCCESS(rv = (hash = (unsigned char*) malloc(hashsize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if (NH_SUCCESS(rv = hHash->digest(hHash, node->identifier, node->contents - node->identifier + node->size, hash, &hashsize)))
			{
				switch (hashAlg)
				{
				case CKM_SHA_1:
					sigAlg = CKM_SHA1_RSA_PKCS;
					break;
				case CKM_SHA256:
					sigAlg = CKM_SHA256_RSA_PKCS;
					break;
				case CKM_SHA384:
					sigAlg = CKM_SHA384_RSA_PKCS;
					break;
				case CKM_SHA512:
					sigAlg = CKM_SHA512_RSA_PKCS;
					break;
				case CKM_MD5:
					sigAlg = CKM_MD5_RSA_PKCS;
					break;
				default: rv = NH_UNSUPPORTED_MECH_ERROR;
				}
				if (NH_SUCCESS(rv))
				{
					if (ASN_TAG_IS_PRESENT(sig, NH_ASN1_BIT_STRING))
					{
						signature = ((NH_PBITSTRING_VALUE) sig->value)->string;
						siglen = ((NH_PBITSTRING_VALUE) sig->value)->len;
					}
					else
					{
						signature = sig->value;
						siglen = sig->valuelen;
					}
					rv = pubKey->verify(pubKey, sigAlg, hash, hashsize, signature, siglen);
				}
			}
			free(hash);
		}
		NH_release_hash(hHash);
	}
	return rv;
}
#define HASH_PATH_KNOWLEDGE		((NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) | NH_SAIL_SKIP_SOUTH)
#define SIGNATURE_PATH_KNOWLEDGE	((NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 5))
#define SIGNED_DATA_PATH_KNOWLEDGE	((NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 3))
NH_UTILITY(NH_RV, cms_sd_verify_rsa)(_IN_ NH_CMS_SD_PARSER_STR *self, _IN_ size_t idx, _IN_ NH_RSA_PUBKEY_HANDLER pubKey)
{
	NH_ASN1_PNODE node, sig;
	CK_MECHANISM_TYPE hashAlg;
	NH_RV rv;

	if
	(
		NH_SUCCESS(rv = idx < self->count && self->signers ? NH_OK : NH_INVALID_SIGNER_ERROR) &&
		NH_SUCCESS(rv = (node = self->hParser->sail(self->signers[idx], HASH_PATH_KNOWLEDGE)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
		NH_SUCCESS(rv = (hashAlg = NH_oid_to_mechanism(node->value, node->valuelen)) != CK_UNAVAILABLE_INFORMATION ? NH_OK : NH_UNSUPPORTED_MECH_ERROR) &&
		NH_SUCCESS(rv = (sig = self->hParser->sail(self->signers[idx], SIGNATURE_PATH_KNOWLEDGE)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
		NH_SUCCESS(rv = ASN_IS_PARSED(sig) ? NH_OK : NH_INVALID_ARG) &&
		NH_SUCCESS(rv = (node = self->hParser->sail(self->signers[idx], SIGNED_DATA_PATH_KNOWLEDGE)) ? NH_OK : NH_UNEXPECTED_ENCODING) &&
		NH_SUCCESS(rv = ASN_IS_PRESENT(node) ? NH_OK : NH_CMS_NO_SIGATTRS_ERROR)
	)
	{
		*node->identifier = NH_ASN1_SET;
		rv = _verify_signature_(node, pubKey, hashAlg, sig);
		*node->identifier = 0xA0;
	}
	return rv;
}

static const unsigned int content_type_oid[]	= { 1, 2, 840, 113549, 1, 9, 3 };
static const unsigned int message_digest_oid[]	= { 1, 2, 840, 113549, 1, 9, 4 };
static const unsigned int signing_time_oid[]	= { 1, 2, 840, 113549, 1, 9, 5 };
static const NH_NODE_WAY content_type_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_OBJECT_ID,
		NULL,
		0
	}
};
static const NH_NODE_WAY message_digest_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_OCTET_STRING,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, cms_sd_validate)(_IN_ NH_CMS_SD_PARSER_STR *self, _IN_ unsigned char *eContent, _IN_ size_t eSize)
{
	NH_RV rv = NH_OK, gRV;
	size_t i = 0;
	NH_ASN1_PNODE node, cur;
	CK_MECHANISM_TYPE hashAlg, lastHash = CK_UNAVAILABLE_INFORMATION;
	NH_HASH_HANDLER hHash;
	unsigned char *hash = NULL;
	size_t hashsize;
	CK_BBOOL ct_match = CK_FALSE, md_match = CK_FALSE;

	if (!eContent) return NH_INVALID_ARG;
	if (self->count == 0 || !self->signers) return NH_CMS_NO_SIGNED_ERROR;
	while (NH_SUCCESS(rv) && i < self->count)
	{
		rv = (node = self->hParser->sail(self->signers[i], (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL;
		if (NH_SUCCESS(rv)) rv = (hashAlg = NH_oid_to_mechanism(node->value, node->valuelen)) != CK_UNAVAILABLE_INFORMATION ? NH_OK : NH_UNSUPPORTED_MECH_ERROR;
		if (NH_SUCCESS(rv) && hashAlg != lastHash)
		{
			lastHash = hashAlg;
			if (hash)
			{
				free(hash);
				hash = NULL;
			}
			rv = NH_new_hash(&hHash);
			if (NH_SUCCESS(rv)) rv = hHash->init(hHash, hashAlg);
			if (NH_SUCCESS(rv)) rv = hHash->digest(hHash, eContent, eSize, NULL, &hashsize);
			if
			(
				NH_SUCCESS(rv) &&
				NH_SUCCESS(rv = (hash = (unsigned char*) malloc(hashsize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)	rv = hHash->digest(hHash, eContent, eSize, hash, &hashsize);
			if (hHash)
			{
				NH_release_hash(hHash);
				hHash = NULL;
			}
		}
		if (NH_SUCCESS(rv)) rv = (node = self->hParser->sail(self->signers[i], (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 3))) ? NH_OK : NH_CANNOT_SAIL;
		if (NH_SUCCESS(rv)) rv = ASN_IS_PRESENT(node) && (node = node->child) ? NH_OK : NH_CMS_NO_SIGATTRS_ERROR;
		while (NH_SUCCESS(rv) && node && (!ct_match || !md_match))
		{
			if (NH_SUCCESS(rv = (cur = node->child) ? NH_OK : NH_CANNOT_SAIL))
			{
				if (NH_match_oid(content_type_oid, NHC_OID_COUNT(content_type_oid), cur->value, cur->valuelen))
				{
					ct_match = CK_TRUE;
					rv = (cur = cur->next) && (cur = cur->child) ? NH_OK : NH_CANNOT_SAIL;
					if (NH_SUCCESS(rv))
					{
						GUARD(self->mutex, gRV,
						{
							if (!ASN_IS_PARSED(cur)) rv = self->hParser->map_from(self->hParser, cur, content_type_map, ASN_NODE_WAY_COUNT(content_type_map));
							if (NH_SUCCESS(rv) && !ASN_IS_PARSED(cur)) rv = self->hParser->parse_oid(self->hParser, cur);
						})
						if (NH_FAIL(gRV)) rv = gRV;
					}
					if (NH_SUCCESS(rv)) rv = self->encapContentInfo->child->valuelen == self->encapContentInfo->child->valuelen && memcmp(self->encapContentInfo->child->value, cur->value, cur->valuelen) == 0 ? NH_OK : NH_CMS_CTYPE_NOMATCH_ERROR;
				}
				else if (NH_match_oid(message_digest_oid, NHC_OID_COUNT(message_digest_oid), cur->value, cur->valuelen))
				{
					md_match = CK_TRUE;
					rv = (cur = cur->next) && (cur = cur->child) ? NH_OK : NH_CANNOT_SAIL;
					if (NH_SUCCESS(rv))
					{
						GUARD(self->mutex, gRV,
						{
							if (!ASN_IS_PARSED(cur)) rv = self->hParser->map_from(self->hParser, cur, message_digest_map, ASN_NODE_WAY_COUNT(message_digest_map));
							if (NH_SUCCESS(rv) && !ASN_IS_PARSED(cur)) rv = self->hParser->parse_octetstring(self->hParser, cur);
						})
						if (NH_FAIL(gRV)) rv = gRV;
					}
					if (NH_SUCCESS(rv)) rv =  hashsize == cur->valuelen && memcmp(hash, cur->value, hashsize) == 0 ? NH_OK : NH_CMS_MD_NOMATCH_ERROR;
				}
			}
			node = node->next;
		}
		if (NH_SUCCESS(rv)) rv = ct_match && md_match ? NH_OK : NH_CMS_SD_SIGATT_ERROR;
		i++;
	}
	if (hash) free(hash);
	return rv;
}

NH_UTILITY(NH_RV, cms_sd_validate_attached)(_IN_ NH_CMS_SD_PARSER_STR *self)
{
	NH_ASN1_PNODE eContent = self->hParser->sail(self->encapContentInfo, NH_ECONTENT_INFO_PATH);
	if (!eContent) return NH_CMS_SD_NOECONTENT_ERROR;
	return self->validate(self, eContent->value, eContent->valuelen);
}

const static NH_CMS_SD_PARSER_STR defCMS_SD_parser =
{
	NULL,					/* mutext */
	NULL,					/* hParser */

	NULL,					/* content */
	NULL,					/* encapContentInfo */
	NULL,					/* certificates */
	NULL,					/* signers */
	0,					/* count */

	cms_sd_get_sid,			/* get_sid */
	cms_sd_get_cert,			/* get_cert */
	cms_sd_verify,			/* verify */
	cms_sd_verify_rsa,		/* verify_rsa */
	cms_sd_validate,			/* validate */
	cms_sd_validate_attached	/* validate_attached */
};


const static NH_NODE_WAY cms_certificates[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	}
};
NH_NODE_WAY cms_issuer_serial[] =
{
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER,
		NULL,
		0
	},
	{
		(NH_SAIL_SKIP_WEST << 8) | NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		pkix_x500_rdn_map,
		PKIX_X500_RDN_COUNT
	},
};
static NH_NODE_WAY cms_eci_map[] =
{
	{	/* EncapsulatedContentInfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* eContentType */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* eContent */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
static NH_NODE_WAY cms_attributes_map[] =
{
	{	/* Attribute */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* attrType */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* attrValues */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET,
		NULL,
		0
	}
};
static NH_NODE_WAY cms_signerinfo_map[] =
{
	{	/* SignerInfo */
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
	{	/* sid/issuerAndSerialNumber */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CHOICE_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* sid/subjectKeyIdentifier */
		NH_PARSE_ROOT,
		NH_ASN1_OCTET_STRING | NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* digestAlgorithm */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* signedAttrs */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		cms_attributes_map,
		ASN_NODE_WAY_COUNT(cms_attributes_map)
	},
	{	/* signatureAlgorithm */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* signature */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* unsignedAttrs */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
const static NH_NODE_WAY cms_signed_data_map[] =
{
	{	/* SignedData */
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
	{	/* digestAlgorithms */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* encapContentInfo */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		cms_eci_map,
		ASN_NODE_WAY_COUNT(cms_eci_map)
	},
	{	/* certificates */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* crls */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* signerInfos */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET,
		NULL,
		0
	}
};
const static NH_NODE_WAY signer_infos_map[] =
{
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		cms_signerinfo_map,
		ASN_NODE_WAY_COUNT(cms_signerinfo_map)
	}
};
NH_FUNCTION(NH_RV, NH_cms_parse_signed_data)(_IN_ unsigned char *buffer, _IN_ size_t size, _OUT_ NH_CMS_SD_PARSER *hHandler)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node, content, encapContentInfo, certificates, signer, *signers = NULL;
	size_t count = 0, i;
	NH_CMS_SD_PARSER ret = NULL;

	if (NH_FAIL(rv = NH_new_parser(buffer, size, 64, 2048, &hParser))) return rv;
	if (NH_SUCCESS(rv = hParser->map(hParser, cms_map, CMS_MAP)) && (node = hParser->root->child)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = NH_find_content_type(node) == NH_SIGNED_DATA_CTYPE ? NH_OK : NH_INVALID_CT_ERROR;
	if (NH_SUCCESS(rv)) rv = (node = node->next) && (node = node->child) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->map_from(hParser, node, cms_signed_data_map, ASN_NODE_WAY_COUNT(cms_signed_data_map));
	if (NH_SUCCESS(rv)) rv = (content = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = (encapContentInfo = hParser->sail(content, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = (node = encapContentInfo->child) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv) && ASN_IS_PRESENT(node) && (node = node->child)) rv = hParser->parse_octetstring(hParser, node);
	if (NH_SUCCESS(rv)) rv = (certificates = encapContentInfo->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv) && ASN_IS_PRESENT(certificates)) rv = hParser->map_set_of(hParser, certificates->child, cms_certificates, ASN_NODE_WAY_COUNT(cms_certificates));
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(content, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 5))) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv) && node->size > 0)
	{
		rv = hParser->map_from(hParser, node, signer_infos_map, ASN_NODE_WAY_COUNT(signer_infos_map));
		if (NH_SUCCESS(rv)) signer = node->child;
	}
	else signer = NULL;

	while (NH_SUCCESS(rv) && signer)
	{
		if (NH_SUCCESS(rv = (node = hParser->sail(signer, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_UNEXPECTED_ENCODING))
		{
			if (ASN_TAG_IS_PRESENT(node, NH_ASN1_SEQUENCE)) rv = hParser->map_from(hParser, node, cms_issuer_serial, CMS_ISSUERSERIAL_MAP_COUNT);
			else rv = hParser->parse_octetstring(hParser, node);
			if (NH_SUCCESS(rv)) rv = (node = hParser->sail(signer, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING;
			if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
			if (NH_SUCCESS(rv)) rv = (node = hParser->sail(signer, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 3))) ? NH_OK : NH_UNEXPECTED_ENCODING;
			if (NH_SUCCESS(rv) && ASN_IS_PRESENT(node) && (node = node->child))
			{
				while (NH_SUCCESS(rv) && node)
				{
					rv = hParser->parse_oid(hParser, node->child);
					node = node->next;
				}
			}
			if (NH_SUCCESS(rv)) rv = (node = hParser->sail(signer, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 4) << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING;
			if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
			if (NH_SUCCESS(rv)) rv = (node = hParser->sail(signer, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 5))) ? NH_OK : NH_UNEXPECTED_ENCODING;
			if (NH_SUCCESS(rv)) rv = hParser->parse_octetstring(hParser, node);
		}
		signer = signer->next;
		count++;
	}
	if (NH_SUCCESS(rv) && count > 0) rv = hParser->container->bite_chunk(hParser->container, count * sizeof(NH_ASN1_PNODE), (void*) &signers);
	if (NH_SUCCESS(rv)) rv = (signer = hParser->sail(content, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 5) << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv))
	{
		for (i = 0; i < count; i++)
		{
			signers[i] = signer;
			signer = signer->next;
		}
		rv = (ret = (NH_CMS_SD_PARSER) malloc(sizeof(NH_CMS_SD_PARSER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
		if (NH_SUCCESS(rv)) memcpy(ret, &defCMS_SD_parser, sizeof(NH_CMS_SD_PARSER_STR));
	}
	if (NH_SUCCESS(rv)) rv = NH_create_mutex(&ret->mutex);
	if (NH_SUCCESS(rv))
	{
		ret->hParser = hParser;
		ret->content = content;
		ret->encapContentInfo = encapContentInfo;
		ret->certificates = certificates;
		ret->signers = signers;
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

NH_FUNCTION(void, NH_cms_release_sd_parser)(_INOUT_ NH_CMS_SD_PARSER hHandler)
{
	if (hHandler)
	{
		if (hHandler->mutex) NH_release_mutex(hHandler->mutex);
		if (hHandler->hParser) NH_release_parser(hHandler->hParser);
		free(hHandler);
	}
}



/** ****************************
 *  CMS SignedData encoding
 *  ****************************/
const static NH_NODE_WAY eContent_map[] =
{
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OCTET_STRING,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, cms_sd_data_ctype)(_INOUT_ NH_CMS_SD_ENCODER_STR *self, _IN_ CK_BBOOL attach)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if (!self->eContent.data) return NH_CMS_SD_NOECONTENT_ERROR;
	if (!(node = self->hEncoder->sail(self->content, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) |  NH_SAIL_SKIP_SOUTH))) return NH_CANNOT_SAIL;
	if (ASN_IS_PARSED(node)) return NH_CMS_ALREADYSET_ERROR;
	if (NH_FAIL(rv = self->hEncoder->put_objectid(self->hEncoder, node, cms_data_ct_oid, NHC_OID_COUNT(cms_data_ct_oid), FALSE))) return rv;
	if (attach && NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL))
	{
		self->hEncoder->register_optional(node);
		if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, eContent_map, ASN_NODE_WAY_COUNT(eContent_map)))) return rv;
		if (NH_SUCCESS(rv = (node = node->child) ? NH_OK : NH_CANNOT_SAIL)) rv = self->hEncoder->put_octet_string(self->hEncoder, node, self->eContent.data, self->eContent.length);
	}
	return rv;
}

NH_UTILITY(NH_RV, cms_sd_add_cert)(_INOUT_ NH_CMS_SD_ENCODER_STR *self, _IN_ NH_CERTIFICATE_HANDLER hCert)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if (!hCert) return NH_INVALID_ARG;
	if (!(node = self->hEncoder->sail(self->content, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 3)))) return NH_CANNOT_SAIL;
	if (!ASN_IS_PRESENT(node)) self->hEncoder->register_optional(node);
	if (!(node = self->hEncoder->add_to_set(self->hEncoder->container, node))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, cms_certificates, ASN_NODE_WAY_COUNT(cms_certificates)))) return rv;
	return NH_asn_clone_node(self->hEncoder->container, hCert->hParser->root, &node);
}

NH_NODE_WAY subkeyid_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0,
		NULL,
		0
	}
};
NH_NODE_WAY issuer_serial_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, add_content_type)
(
	_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder,
	_INOUT_ NH_ASN1_PNODE set,
	_IN_ NH_ASN1_PNODE eContentType
)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if (!ASN_IS_PARSED(eContentType)) return NH_CMS_SD_NOECONTENT_ERROR;
	if (!(node = hEncoder->add_to_set(hEncoder->container, set))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, cms_attributes_map, ASN_NODE_WAY_COUNT(cms_attributes_map)))) return rv;
	if (!(node = node->child)) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->put_objectid(hEncoder, node, content_type_oid, NHC_OID_COUNT(content_type_oid), CK_FALSE))) return rv;
	if (!(node = node->next)) return NH_CANNOT_SAIL;
	if (!(node = hEncoder->add_to_set(hEncoder->container, node))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, content_type_map, ASN_NODE_WAY_COUNT(content_type_map)))) return rv;
	return hEncoder->put_objectid(hEncoder, node, eContentType->value, eContentType->valuelen, CK_FALSE);
}
const static NH_NODE_WAY signing_time_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_GENERALIZED_TIME,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, add_signing_time)(_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder, _INOUT_ NH_ASN1_PNODE set)
{
	NH_RV rv;
	NH_ASN1_PNODE node;
	char utc[16];
	time_t instant;
	NH_PTIME now;

	if (!(node = hEncoder->add_to_set(hEncoder->container, set))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, cms_attributes_map, ASN_NODE_WAY_COUNT(cms_attributes_map)))) return rv;
	if (!(node = node->child)) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->put_objectid(hEncoder, node, signing_time_oid, NHC_OID_COUNT(signing_time_oid), CK_FALSE))) return rv;
	if (!(node = node->next)) return NH_CANNOT_SAIL;
	if (!(node = hEncoder->add_to_set(hEncoder->container, node))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, signing_time_map, ASN_NODE_WAY_COUNT(signing_time_map)))) return rv;
	time(&instant);
	now = gmtime(&instant);
	sprintf(utc, "%04d%02d%02d%02d%02d%02dZ", now->tm_year + 1900, now->tm_mon, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
	return hEncoder->put_generalized_time(hEncoder, node, utc, sizeof(utc));
}
NH_UTILITY(NH_RV, add_message_digest)(_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder, _INOUT_ NH_ASN1_PNODE set, _IN_ NH_BLOB *hash)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if (!(node = hEncoder->add_to_set(hEncoder->container, set))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, cms_attributes_map, ASN_NODE_WAY_COUNT(cms_attributes_map)))) return rv;
	if (!(node = node->child)) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->put_objectid(hEncoder, node, message_digest_oid, NHC_OID_COUNT(message_digest_oid), CK_FALSE))) return rv;
	if (!(node = node->next)) return NH_CANNOT_SAIL;
	if (!(node = hEncoder->add_to_set(hEncoder->container, node))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, message_digest_map, ASN_NODE_WAY_COUNT(message_digest_map)))) return rv;
	return hEncoder->put_octet_string(hEncoder, node, hash->data, hash->length);
}
NH_UTILITY(NH_RV, cms_sd_sign_init)
(
	_INOUT_ NH_CMS_SD_ENCODER_STR *self,
	_IN_ NH_CMS_ISSUER_SERIAL sid,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_OUT_ NH_ASN1_PNODE *signedAttrsNode
)
{
	NH_RV rv;
	NH_ASN1_PNODE set, node;
	const unsigned int *hashOID, *sigOID;
	size_t hashOIDCount, sigOIDCount;
	CK_MECHANISM_TYPE hashAlg;
	CK_BBOOL found = CK_FALSE;
	NH_HASH_HANDLER hHash;
	NH_BLOB hash = { NULL, 0 };

	if (!sid || (!sid->keyIdentifier && (!sid->name || !sid->serial)) || !self->eContent.data) return NH_INVALID_ARG;
	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		hashOID = sha1_oid;
		hashOIDCount = NHC_SHA1_OID_COUNT;
		hashAlg = CKM_SHA_1;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	case CKM_SHA256_RSA_PKCS:
		hashOID = sha256_oid;
		hashOIDCount = NHC_SHA256_OID_COUNT;
		hashAlg = CKM_SHA256;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	case CKM_SHA384_RSA_PKCS:
		hashOID = sha384_oid;
		hashOIDCount = NHC_SHA384_OID_COUNT;
		hashAlg = CKM_SHA384;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	case CKM_SHA512_RSA_PKCS:
		hashOID = sha512_oid;
		hashOIDCount = NHC_SHA512_OID_COUNT;
		hashAlg = CKM_SHA512;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	case CKM_MD5_RSA_PKCS:
		hashOID = md5_oid;
		hashOIDCount = NHC_MD5_OID_COUNT;
		hashAlg = CKM_MD5;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}

	if (!(set = self->hEncoder->sail(self->content, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST))) return NH_CANNOT_SAIL;
	if (set->child)
	{
		node = set->child;
		while (node && !found)
		{
			found = NH_match_oid(node->child->value, node->child->valuelen, hashOID, hashOIDCount);
			node = node->next;
		}
	}
	if (!found)
	{
		if (!(node = self->hEncoder->add_to_set(self->hEncoder->container, set))) return NH_CANNOT_SAIL;
		if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, pkix_algid_map, PKIX_ALGID_COUNT))) return rv;
		if (NH_FAIL(rv = self->hEncoder->put_objectid(self->hEncoder, node->child, hashOID, hashOIDCount, CK_FALSE))) return rv;
	}

	if (!(node = self->hEncoder->sail(self->content, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 5)))) return NH_CANNOT_SAIL;
	if (!(node = self->hEncoder->add_to_set(self->hEncoder->container, node))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, cms_signerinfo_map, ASN_NODE_WAY_COUNT(cms_signerinfo_map)))) return rv;
	if (!(node = node->child)) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = self->hEncoder->put_little_integer(self->hEncoder, node, 1))) return rv;
	if (!(node = node->next)) return NH_CANNOT_SAIL;
	if (sid->keyIdentifier)
	{
		if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, subkeyid_map, ASN_NODE_WAY_COUNT(subkeyid_map)))) return rv;
		if (NH_FAIL(rv = self->hEncoder->put_octet_string(self->hEncoder, node, sid->keyIdentifier->value, sid->keyIdentifier->valuelen))) return rv;
	}
	else
	{
		if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, issuer_serial_map, ASN_NODE_WAY_COUNT(issuer_serial_map)))) return rv;
		if (NH_FAIL(rv = self->hEncoder->chart_from(self->hEncoder, node, cms_issuer_serial, CMS_ISSUERSERIAL_MAP_COUNT))) return rv;
		if (!node->child) return NH_CANNOT_SAIL;
		if (NH_FAIL(rv = NH_asn_clone_node(self->hEncoder->container, sid->name->node, &node->child))) return rv;
		if (!node->child->next) return NH_CANNOT_SAIL;
		if (NH_FAIL(rv = self->hEncoder->put_integer(self->hEncoder, node->child->next, sid->serial->value, sid->serial->valuelen))) return rv;
	}
	if (!(node = node->next) || !node->child) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv - self->hEncoder->put_objectid(self->hEncoder, node->child, hashOID, hashOIDCount, CK_FALSE))) return rv;

	if (!(set = node->next)) return NH_CANNOT_SAIL;
	self->hEncoder->register_optional(set);
	if (NH_FAIL(rv = add_content_type(self->hEncoder, set, self->hEncoder->sail(self->content, (NH_SAIL_SKIP_SOUTH << 16) | ((NH_PARSE_EAST | 2) << 8) | NH_SAIL_SKIP_SOUTH)))) return rv;
	if (NH_FAIL(rv = add_signing_time(self->hEncoder, set))) return rv;
	if (NH_FAIL(rv = NH_new_hash(&hHash))) return rv;
	rv = hHash->init(hHash, hashAlg);
	if (NH_SUCCESS(rv)) rv = hHash->digest(hHash, self->eContent.data, self->eContent.length, NULL, &hash.length);
	if (NH_SUCCESS(rv)) rv = (hash.data = (unsigned char*) malloc(hash.length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv)) rv = hHash->digest(hHash, self->eContent.data, self->eContent.length, hash.data, &hash.length);
	NH_release_hash(hHash);
	if (NH_SUCCESS(rv)) rv = add_message_digest(self->hEncoder, set, &hash);
	if (hash.data) free(hash.data);
	if (NH_SUCCESS(rv)) *signedAttrsNode = set;
	return rv;
}
NH_UTILITY(NH_RV, cms_sd_sign_finish)
(
	_INOUT_ NH_CMS_SD_ENCODER_STR *self,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ NH_ASN1_PNODE signedAttrsNode,
	_IN_ NH_CMS_SIGN_FUNCTION callback,
	_IN_ void *params
)
{
	NH_RV rv;
	NH_ASN1_PNODE set = signedAttrsNode, node, bro;
	const unsigned int *sigOID;
	size_t sigOIDCount, sigsize, encodingsize;
	CK_MECHANISM_TYPE hashAlg;
	NH_HASH_HANDLER hHash;
	NH_BLOB hash = { NULL, 0 };
	unsigned char *signature = NULL, save, *encoding;

	if (!signedAttrsNode || !callback || !self->eContent.data) return NH_INVALID_ARG;
	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		hashAlg = CKM_SHA_1;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	case CKM_SHA256_RSA_PKCS:
		hashAlg = CKM_SHA256;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	case CKM_SHA384_RSA_PKCS:
		hashAlg = CKM_SHA384;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	case CKM_SHA512_RSA_PKCS:
		hashAlg = CKM_SHA512;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	case CKM_MD5_RSA_PKCS:
		hashAlg = CKM_MD5;
		sigOID = rsaEncryption_oid;
		sigOIDCount = NHC_RSA_ENCRYPTION_OID_COUNT;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}

	save = *set->identifier;
	bro = set->next;
	set->next = NULL;
	*set->identifier = NH_ASN1_SET;
	encodingsize = self->hEncoder->encoded_size(self->hEncoder, set);
	if (!(encoding = (unsigned char*) malloc(encodingsize))) return NH_OUT_OF_MEMORY_ERROR;
	rv = self->hEncoder->encode(self->hEncoder, set, encoding);
	*set->identifier = save;
	set->next = bro;
	if (NH_SUCCESS(rv))
	{
		rv = NH_new_hash(&hHash);
		if (NH_SUCCESS(rv)) rv = hHash->init(hHash, hashAlg);
		if (NH_SUCCESS(rv)) rv = hHash->digest(hHash, encoding, encodingsize, NULL, &hash.length);
		if (NH_SUCCESS(rv)) rv = (hash.data = (unsigned char*) malloc(hash.length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
		if (NH_SUCCESS(rv)) rv = hHash->digest(hHash, encoding, encodingsize, hash.data, &hash.length);
		NH_release_hash(hHash);
	}
	free(encoding);
	if (NH_SUCCESS(rv))
	{
		rv = callback(&hash, mechanism, params, NULL, &sigsize);
		if (NH_SUCCESS(rv)) rv = (signature = (unsigned char*) malloc(sigsize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
		if (NH_SUCCESS(rv)) rv = callback(&hash, mechanism, params, signature, &sigsize);
	}
	if (hash.data) free(hash.data);

	if (NH_SUCCESS(rv))
	{
		rv = (node = set->next) && node->child ? NH_OK : NH_CANNOT_SAIL;
		if (NH_SUCCESS(rv)) rv = self->hEncoder->put_objectid(self->hEncoder, node->child, sigOID, sigOIDCount, CK_FALSE);
		if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL;
		if (NH_SUCCESS(rv)) rv = self->hEncoder->put_octet_string(self->hEncoder, node, signature, sigsize);
	}
	if (signature) free(signature);
	return rv;
}
NH_UTILITY(NH_RV, cms_sd_sign)
(
	_INOUT_ NH_CMS_SD_ENCODER_STR *self,
	_IN_ NH_CMS_ISSUER_SERIAL sid,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ NH_CMS_SIGN_FUNCTION callback,
	_IN_ void *params
)
{
	NH_RV rv;
	NH_ASN1_PNODE set;

	if (NH_SUCCESS(rv = self->sign_init(self, sid, mechanism, &set))) rv = self->sign_finish(self, mechanism, set, callback, params);
	return rv;
}
/**
 * id-aa-signingCertificate OBJECT IDENTIFIER ::= { iso(1)
 *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
 *    smime(16) id-aa(2) 12 }
 * SigningCertificate ::=  SEQUENCE {
 *    certs        SEQUENCE OF ESSCertID,
 *    policies     SEQUENCE OF PolicyInformation OPTIONAL
 * }
 * ESSCertID ::=  SEQUENCE {
 * 	certHash                 Hash,
 * 	issuerSerial             IssuerSerial OPTIONAL
 * }
 * Hash ::= OCTET STRING -- SHA1 hash of entire certificate
 * IssuerSerial ::= SEQUENCE {
 * 	issuer                   GeneralNames,
 * 	serialNumber             CertificateSerialNumber
 * }
 */
static const unsigned int signing_certificate_oid[]	  = { 1, 2, 840, 113549, 1, 9, 16, 2, 12 };
static const NH_NODE_WAY ess_certID_map[] =
{
	{ NH_PARSE_ROOT, NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT, NULL, 0 },
	{ NH_SAIL_SKIP_SOUTH, NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT, NULL, 0 },	/* Hash */
	{ NH_SAIL_SKIP_EAST, NH_ASN1_SEQUENCE | NH_ASN1_OPTIONAL_BIT, NULL, 0 }			/* issuerSerial */
};
static const NH_NODE_WAY signing_certificate_map[] =
{
	{ NH_PARSE_ROOT, NH_ASN1_SEQUENCE, NULL, 0 },
	{ NH_SAIL_SKIP_SOUTH, NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT, (NH_NODE_WAY*) ess_certID_map, ASN_NODE_WAY_COUNT(ess_certID_map) },	/* ESSCertID */
	{ NH_SAIL_SKIP_EAST, NH_ASN1_SEQUENCE | NH_ASN1_OPTIONAL_BIT, NULL, 0 }													/* PolicyInformation */
};

/**
 * id-aa-signingCertificateV2 OBJECT IDENTIFIER ::= { iso(1)
 *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
 *    smime(16) id-aa(2) 47 }
 * SigningCertificateV2 ::=  SEQUENCE {
 *    certs        SEQUENCE OF ESSCertIDv2,
 *    policies     SEQUENCE OF PolicyInformation OPTIONAL
 * }
 * ESSCertIDv2 ::=  SEQUENCE {
 * 	hashAlgorithm           AlgorithmIdentifier DEFAULT {algorithm id-sha256},
 * 	certHash                Hash,
 * 	issuerSerial            IssuerSerial OPTIONAL
 * }
 * Hash ::= OCTET STRING
 * IssuerSerial ::= SEQUENCE {
 * 	issuer                  GeneralNames,
 * 	serialNumber            CertificateSerialNumber
 * }
 */
static const unsigned int signing_certificatev2_oid[] = { 1, 2, 840, 113549, 1, 9, 16, 2, 47 };
static const NH_NODE_WAY ess_certIDv2_map[] =
{
	{ NH_PARSE_ROOT, NH_ASN1_SEQUENCE, NULL, 0 },
	{ NH_SAIL_SKIP_SOUTH, NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_DEFAULT_BIT, NULL, 0 },	/* AlgorithmIdentifier */
	{ NH_SAIL_SKIP_EAST, NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT, NULL, 0 },					/* certHash */
	{ NH_SAIL_SKIP_EAST, NH_ASN1_SEQUENCE | NH_ASN1_OPTIONAL_BIT, NULL, 0 }							/* issuerSerial */
};
static const NH_NODE_WAY signing_certificatev2_map[] =
{
	{ NH_PARSE_ROOT, NH_ASN1_SEQUENCE, NULL, 0 },
	{ NH_SAIL_SKIP_SOUTH, NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT, (NH_NODE_WAY*) ess_certIDv2_map, ASN_NODE_WAY_COUNT(ess_certIDv2_map) },	/* ESSCertIDv2 */
	{ NH_SAIL_SKIP_EAST, NH_ASN1_SEQUENCE | NH_ASN1_OPTIONAL_BIT, NULL, 0 }																	/* PolicyInformation */
};
NH_UTILITY(NH_RV, add_signing_cert)(_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder, _IN_ NH_CERTIFICATE_HANDLER signingCert, _IN_ CK_MECHANISM_TYPE mechanism, _INOUT_ NH_ASN1_PNODE set)
{
	NH_RV rv;
	CK_MECHANISM_TYPE hashAlg;
	NH_HASH_HANDLER hHash = NULL;
	NH_BLOB hash = { NULL, 0 };
	NH_ASN1_PNODE node;
	unsigned int *attOID = (unsigned int *) signing_certificatev2_oid, *hashOID = (unsigned int *) sha512_oid;
	size_t attOID_t = NHC_OID_COUNT(signing_certificatev2_oid), hashOID_t = NHC_SHA512_OID_COUNT;

	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		hashAlg = CKM_SHA_1;
		attOID = (unsigned int *) signing_certificate_oid;
		attOID_t = NHC_OID_COUNT(signing_certificate_oid);
		break;
	case CKM_SHA256_RSA_PKCS:
		hashAlg = CKM_SHA256;
		break;
	case CKM_SHA384_RSA_PKCS:
		hashAlg = CKM_SHA384;
		hashOID = (unsigned int *) sha384_oid;
		hashOID_t = NHC_SHA384_OID_COUNT;
		break;
	case CKM_SHA512_RSA_PKCS:
		hashAlg = CKM_SHA512;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if (NH_SUCCESS(rv = NH_new_hash(&hHash)))
	{
		if
		(
			NH_SUCCESS(rv = hHash->init(hHash, hashAlg)) &&
			NH_SUCCESS(rv = hHash->digest(hHash, signingCert->hParser->encoding, signingCert->hParser->length, NULL, &hash.length)) &&
			NH_SUCCESS(rv = (hash.data = (unsigned char*) malloc(hash.length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if
			(
				NH_SUCCESS(rv = (node = hEncoder->add_to_set(hEncoder->container, set)) ? NH_OK : NH_CANNOT_SAIL) &&
				NH_SUCCESS(rv = hEncoder->chart_from(hEncoder, node, cms_attributes_map, ASN_NODE_WAY_COUNT(cms_attributes_map))) &&
				NH_SUCCESS(rv = (node = node->child) ? NH_OK : NH_CANNOT_SAIL) &&
				NH_SUCCESS(rv = hEncoder->put_objectid(hEncoder, node, attOID, attOID_t, CK_FALSE)) &&
				NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL) &&
				NH_SUCCESS(rv = (node = hEncoder->add_to_set(hEncoder->container, node)) ? NH_OK : NH_CANNOT_SAIL)
			)
			{
				if (hashAlg == CKM_SHA_1)
				{
					if (NH_SUCCESS(rv = hEncoder->chart_from(hEncoder, node, signing_certificate_map, ASN_NODE_WAY_COUNT(signing_certificate_map))))
						rv = (node = node->child) && (node = node->child) ? NH_OK : NH_CANNOT_SAIL;
				}
				else
				{
					if
					(
						NH_SUCCESS(rv = hEncoder->chart_from(hEncoder, node, signing_certificatev2_map, ASN_NODE_WAY_COUNT(signing_certificatev2_map))) &&
						NH_SUCCESS(rv = (node = node->child) && (node = node->child) ? NH_OK : NH_CANNOT_SAIL)
					)
					{
						if (hashAlg != CKM_SHA256)
						{
							hEncoder->register_optional(node);
							if
							(
								NH_SUCCESS(rv = hEncoder->chart_from(hEncoder, node, pkix_algid_map, PKIX_ALGID_COUNT)) &&
								NH_SUCCESS(rv = (node = node->child) ? NH_OK : NH_CANNOT_SAIL)
							)	rv = hEncoder->put_objectid(hEncoder, node, hashOID, hashOID_t, 0);
						}
						if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL;
					}
				}
				if (NH_SUCCESS(rv)) rv = hEncoder->put_octet_string(hEncoder, node, hash.data, hash.length);
			}
			free(hash.data);
		}
		NH_release_hash(hHash);
	}
	return rv;
}
NH_UTILITY(NH_RV, cms_sd_sign_cades_bes)
(
	_INOUT_ NH_CMS_SD_ENCODER_STR *self,
	_IN_ NH_CERTIFICATE_HANDLER signingCert,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ NH_CMS_SIGN_FUNCTION callback,
	_IN_ void *params
)
{
	NH_RV rv;
	NH_ASN1_PNODE set;
	NH_CMS_ISSUER_SERIAL_STR sid = { NULL, NULL, NULL };

	if (NH_SUCCESS(rv = (signingCert && callback) ? NH_OK : NH_INVALID_ARG))
	{
		sid.name = signingCert->issuer;
		sid.serial = signingCert->serialNumber;
		if
		(
			NH_SUCCESS(rv = self->sign_init(self, &sid, mechanism, &set)) &&
			NH_SUCCESS(rv = add_signing_cert(self->hEncoder, signingCert, mechanism, set))
		)	rv = self->sign_finish(self, mechanism, set, callback, params);
	}
	return rv;
}


const static NH_CMS_SD_ENCODER_STR defCMS_SD_encoder =
{
	NULL,				/* hEncoder */
	NULL,				/* content */
	{ NULL, 0 },		/* eContent */

	cms_sd_data_ctype,	/* data_ctype */
	cms_sd_add_cert,	/* add_cert */
	cms_sd_sign,		/* sign */
	cms_sd_sign_init,	/* sign_init */
	cms_sd_sign_finish,	/* sign_finish */
	cms_sd_sign_cades_bes
};

NH_FUNCTION(NH_RV, NH_cms_encode_signed_data)(_IN_ NH_BLOB *eContent, _OUT_ NH_CMS_SD_ENCODER *hHandler)
{
	NH_RV rv;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	NH_ASN1_PNODE node, content;
	NH_CMS_SD_ENCODER ret = NULL;

	if (NH_FAIL(rv = NH_new_encoder(64, 4096, &hEncoder))) return rv;
	rv = hEncoder->chart(hEncoder, cms_map, CMS_MAP, &node);
	if (NH_SUCCESS(rv)) rv = hEncoder->put_objectid(hEncoder, node->child, cms_signed_data_ct_oid, NHC_OID_COUNT(cms_signed_data_ct_oid), CK_FALSE);
	if (NH_SUCCESS(rv)) rv = (content = hEncoder->sail(node, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hEncoder->chart_from(hEncoder, content, cms_signed_data_map, ASN_NODE_WAY_COUNT(cms_signed_data_map));
	if (NH_SUCCESS(rv)) rv = (node = content->child) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hEncoder->put_little_integer(hEncoder, node, 1);
	if (NH_SUCCESS(rv)) rv = (ret = malloc(sizeof(NH_CMS_SD_ENCODER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv))
	{
		memcpy(ret, &defCMS_SD_encoder, sizeof(NH_CMS_SD_ENCODER_STR));
		if (eContent && NH_SUCCESS(rv = (ret->eContent.data = (unsigned char*) malloc(eContent->length)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
		{
			memcpy(ret->eContent.data, eContent->data, eContent->length);
			ret->eContent.length = eContent->length;
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
			if (ret->eContent.data) free(ret->eContent.data);
			free(ret);
		}
		NH_release_encoder(hEncoder);
	}
	return rv;
}


NH_FUNCTION(void, NH_cms_release_sd_encoder)(_INOUT_ NH_CMS_SD_ENCODER hHandler)
{
	if (hHandler)
	{
		if (hHandler->eContent.data) free(hHandler->eContent.data);
		if (hHandler->hEncoder) NH_release_encoder(hHandler->hEncoder);
		free(hHandler);
	}
}
