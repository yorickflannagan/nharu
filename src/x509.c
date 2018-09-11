#include "pkix.h"
#include <string.h>


/** ****************************
 *  Common functions
 *  ****************************/
NH_UTILITY(NH_RV, verify)
(
	_IN_ NH_ASN1_PNODE sigOID,
	_IN_ NH_ASN1_PNODE sigValue,
	_IN_ NH_ASN1_PNODE tbs,
	_IN_ NH_ASN1_PNODE pubkeyInfo
)
{
	CK_MECHANISM_TYPE hashAlg;

	if
	(
		!sigOID ||
		!sigOID->child ||
		!ASN_TAG_IS_PRESENT(sigOID->child, NH_ASN1_OBJECT_ID) ||
		!sigValue ||
		!ASN_TAG_IS_PRESENT(sigValue, NH_ASN1_BIT_STRING) ||
		!tbs
	)	return NH_INVALID_ARG;
	switch(NH_oid_to_mechanism(sigOID->child->value, sigOID->child->valuelen))
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
	return NHIX_verify_signature(tbs, pubkeyInfo, hashAlg, sigValue);
}


/** ****************************
 *  X.509 Certificate handler
 *  ****************************/
static NH_NODE_WAY pkix_extension_map[] =
{
	{	/* Extension */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* extnID */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* critical */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_BOOLEAN | NH_ASN1_DEFAULT_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* extnValue */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING,
		NULL,
		0
	}
};
static NH_NODE_WAY pkix_extensions_map[] =
{
	{	/* Extensions */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* Extension */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		pkix_extension_map,
		ASN_NODE_WAY_COUNT(pkix_extension_map)
	}
};

INLINE NH_UTILITY(NH_RV, find_extension)
(
	_INOUT_ NH_ASN1_PARSER_HANDLE hParser,
	_IN_ NH_MUTEX_HANDLE mutex,
	_IN_ unsigned int *OID,
	_IN_ size_t count,
	_IN_ NH_ASN1_PNODE from,
	_OUT_ NH_ASN1_PNODE *extension
)
{
	NH_RV rv = NH_OK, gRV;
	NH_ASN1_PNODE node, ret = NULL, next;

	if (ASN_IS_PRESENT(from) && (node = from->child))
	{
		GUARD(mutex, gRV,
		{
			if (node->size == UINT_MAX) rv = hParser->map_from(hParser, node->parent, pkix_extensions_map, ASN_NODE_WAY_COUNT(pkix_extensions_map));
		})
		if (NH_FAIL(gRV)) rv = gRV;
		if (NH_FAIL(rv)) return rv;
		node = node->child;
		while (!ret && node)
		{
			if (!(next = node->child)) return NH_UNEXPECTED_ENCODING;
			GUARD(mutex, gRV,
			{
				if (!ASN_IS_PARSED(next)) rv = hParser->parse_oid(hParser, next);
			})
			if (NH_FAIL(gRV)) rv = gRV;
			if (NH_FAIL(rv)) return rv;
			if (NH_match_oid(OID, count, next->value, next->valuelen))
			{
				if (!(next->next) || !(next = next->next->next)) return NH_UNEXPECTED_ENCODING;
				GUARD(mutex, gRV,
				{
					if (!ASN_IS_PARSED(next)) rv = hParser->parse_octetstring(hParser, next);
				})
				if (NH_FAIL(gRV)) rv = gRV;
				if (NH_FAIL(rv)) return rv;
				ret = node;
			}
			node = node->next;
		}
	}
	*extension = ret;
	return rv;
}

NH_UTILITY(NH_RV, cert_find_extension)
(
	_IN_ NH_CERTIFICATE_HANDLER_STR *self,
	_IN_ unsigned int *OID,
	_IN_ size_t count,
	_IN_ NH_ASN1_PNODE from,
	_OUT_ NH_ASN1_PNODE *extension
)
{
	return find_extension(self->hParser, self->mutex, OID, count, from, extension);
}

INLINE NH_UTILITY(NH_RV, map_extensions)
(
	_INOUT_ NH_ASN1_PARSER_HANDLE hParser,
	_IN_ NH_MUTEX_HANDLE mutex,
	_IN_ NH_ASN1_PNODE from
)
{
	NH_RV rv = NH_OK, gRV;
	NH_ASN1_PNODE node, next;

	if (ASN_IS_PRESENT(from) && (node = from->child))
	{
		GUARD(mutex, gRV,
		{
			if (node->size == UINT_MAX) rv = hParser->map_from(hParser, node->parent, pkix_extensions_map, ASN_NODE_WAY_COUNT(pkix_extensions_map));
		})
		if (NH_FAIL(gRV)) rv = gRV;
		if (NH_FAIL(rv)) return rv;
		node = node->child;
		while (node)
		{
			if (!(next = node->child)) return NH_UNEXPECTED_ENCODING;
			GUARD(mutex, gRV,
			{
				if (!ASN_IS_PARSED(next)) rv = hParser->parse_oid(hParser, next);
			})
			if (NH_FAIL(gRV)) rv = gRV;
			if (NH_FAIL(rv)) return rv;
			if (!(next = next->next)) return NH_UNEXPECTED_ENCODING;
			if (ASN_IS_PRESENT(next))
			{
				GUARD(mutex, gRV,
				{
					if (!ASN_IS_PARSED(next)) rv = hParser->parse_boolean(next);
				})
			}
			node = node->next;
		}
	}
	return rv;
}

NH_UTILITY(NH_RV, cert_map_extensions)
(
	_IN_ NH_CERTIFICATE_HANDLER_STR *self,
	_IN_ NH_ASN1_PNODE from
)
{
	return map_extensions(self->hParser, self->mutex, from);
}


/*
 * Time ::= CHOICE {
 *    utcTime        UTCTime,
 *    generalTime    GeneralizedTime
 * }
 */
NH_NODE_WAY pkix_time_map[] =
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
/*
 * TBSCertificate  ::=  SEQUENCE  {
 *    version         [0]  Version DEFAULT v1,
 *    serialNumber         CertificateSerialNumber,
 *    signature            AlgorithmIdentifier,
 *    issuer               Name,
 *    validity             Validity,
 *    subject              Name,
 *    subjectPublicKeyInfo SubjectPublicKeyInfo,
 *    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
 *    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
 *    extensions      [3]  Extensions OPTIONAL -- If present, version MUST be v3 --
 * }
 * Validity ::= SEQUENCE {
 *    notBefore      Time,
 *    notAfter       Time
 * }
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *    algorithm            AlgorithmIdentifier,
 *    subjectPublicKey     BIT STRING
 * }
 */
static NH_NODE_WAY pkix_tbscert_map[] =
{
	{	/* version */
		NH_PARSE_ROOT,
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
		pkix_time_map,
		ASN_NODE_WAY_COUNT(pkix_time_map)
	},
	{	/* notAfter */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_CHOICE_BIT,
		pkix_time_map,
		ASN_NODE_WAY_COUNT(pkix_time_map)
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
/*
 * Certificate  ::=  SEQUENCE  {
 *    tbsCertificate       TBSCertificate,
 *    signatureAlgorithm   AlgorithmIdentifier,
 *    signatureValue       BIT STRING
 * }
 */
static NH_NODE_WAY pkix_certificate_map[] =
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
		NH_ASN1_SEQUENCE,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* signatureValue */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_BIT_STRING,
		NULL,
		0
	},
	{	/* TBSCertificate */
		((NH_PARSE_WEST | 2) << 8) | NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE,
		pkix_tbscert_map,
		ASN_NODE_WAY_COUNT(pkix_tbscert_map)
	}
};


NH_UTILITY(CK_BBOOL, match_subject)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _IN_ NH_NAME_NODE name)
{
	return strcmp(name->stringprep, self->subject->stringprep) == 0 ? CK_TRUE : CK_FALSE;
}

NH_UTILITY(NH_RV, check_validity)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _IN_ NH_PTIME instant)
{
	time_t before, after, current;
	NH_TIME tmp, ext;
	NH_ASN1_PNODE node;

	if (!(node = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 4)))) return NH_CANNOT_SAIL;
	if (!ASN_TAG_IS_PRESENT(node, NH_ASN1_SEQUENCE) || !ASN_IS_PARSED(node->child)) return NH_UNEXPECTED_ENCODING;
	memset(&ext, 0, sizeof(NH_TIME));
	memcpy(&ext, instant, sizeof(NH_TIME));
	memset(&tmp, 0, sizeof(NH_TIME));
	memcpy(&tmp, node->child->value, sizeof(NH_TIME));
	before = mktime(&tmp);
	node = node->child->next;
	if (!ASN_IS_PARSED(node)) return NH_UNEXPECTED_ENCODING;
	memcpy(&tmp, node->value, sizeof(NH_TIME));
	after = mktime(&tmp);
	current = mktime(&ext);
	if (current > after) return NH_CERT_EXPIRE_ERROR;
	if (current < before) return NH_CERT_NOT_VALID_ERROR;
	return NH_OK;
}

NH_UTILITY(NH_RV, verify_certificate)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _IN_ NH_ASN1_PNODE pubkeyInfo)
{
	return verify
	(
		self->hParser->sail(self->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST),
		self->hParser->sail(self->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)),
		self->hParser->sail(self->hParser->root, NH_SAIL_SKIP_SOUTH),
		pubkeyInfo
	);
}

NH_UTILITY(NH_RV, certificate_version)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_RV rv = NH_OK, gRV;
	NH_ASN1_PNODE cur;

	if (!(cur = self->hParser->sail(self->hParser->root, NH_PARSE_SOUTH | 2))) return NH_UNEXPECTED_ENCODING;
	if (ASN_IS_PRESENT(cur))
	{
		cur = cur->child;
		GUARD(self->mutex, gRV,
		{
			if (!ASN_IS_PARSED(cur)) rv = self->hParser->parse_little_integer(self->hParser, cur);
		})
		if (NH_FAIL(gRV)) rv = gRV;
		cur = cur->parent;
	}
	if (NH_SUCCESS(rv)) *node = cur;
	return rv;
}

NH_UTILITY(NH_RV, certificate_signature_mech)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_RV rv = NH_OK, gRV;
	NH_ASN1_PNODE cur;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 16) | ((NH_PARSE_EAST | 2) << 8) | NH_SAIL_SKIP_SOUTH))) return NH_UNEXPECTED_ENCODING;
	GUARD(self->mutex, gRV,
	{
		if (!ASN_IS_PARSED(cur)) rv = self->hParser->parse_oid(self->hParser, cur);
	})
	if (NH_FAIL(gRV)) rv = gRV;
	if (NH_SUCCESS(rv)) *node = cur->parent;
	return rv;
}

NH_UTILITY(NH_RV, not_before)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_ASN1_PNODE cur;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 16) | ((NH_PARSE_EAST | 4) << 8) | NH_SAIL_SKIP_SOUTH))) return NH_UNEXPECTED_ENCODING;
	*node = cur;
	return NH_OK;
}

NH_UTILITY(NH_RV, not_after)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_ASN1_PNODE cur;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 24) | ((NH_PARSE_EAST | 4) << 16) | (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST))) return NH_UNEXPECTED_ENCODING;
	*node = cur;
	return NH_OK;
}

NH_UTILITY(NH_RV, issuer_unique_ID)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_RV rv = NH_OK, gRV;
	NH_ASN1_PNODE cur;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 7)))) return NH_UNEXPECTED_ENCODING;
	GUARD(self->mutex, gRV,
	{
		if (ASN_IS_PRESENT(cur) && NH_SUCCESS(rv = self->hParser->parse_bitstring(self->hParser, cur))) *node = cur;
		else *node = NULL;
	})
	return rv;
}

NH_UTILITY(NH_RV, subject_unique_ID)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_RV rv = NH_OK, gRV;
	NH_ASN1_PNODE cur;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 8)))) return NH_UNEXPECTED_ENCODING;
	GUARD(self->mutex, gRV,
	{
		if (ASN_IS_PRESENT(cur) && NH_SUCCESS(rv = self->hParser->parse_bitstring(self->hParser, cur))) *node = cur;
		else *node = NULL;
	})
	return rv;
}

/** ************************************
 *  X.509 Certificate extensions parsing
 *  ************************************/
const static unsigned int aki_oid[] = { 2, 5, 29, 35 };
static NH_NODE_WAY pkix_aki_map[] =
{
	{	/* AuthorityKeyIdentifier */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* keyIdentifier */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* authorityCertIssuer */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* authorityCertSerialNumber */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_2 | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, aki)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_RV rv, gRV;
	NH_ASN1_PNODE cur, ext, value, extnValue;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 9)))) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = self->find_extension(self, aki_oid, NHC_OID_COUNT(aki_oid), cur, &ext))) return rv;
	if (ext)
	{
		if (!(extnValue = self->hParser->sail(ext, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) return NH_UNEXPECTED_ENCODING;
		GUARD(self->mutex, gRV,
		{
			if (!extnValue->child)
			{
				if (NH_SUCCESS(rv = self->hParser->new_node(self->hParser->container, &value)))
				{
					value->parent = extnValue;
					extnValue->child = value;
					value->identifier = extnValue->contents;
					rv = self->hParser->map_from(self->hParser, value, pkix_aki_map, ASN_NODE_WAY_COUNT(pkix_aki_map));
				}
				if (NH_SUCCESS(rv)) rv = (cur = value->child) ? NH_OK : NH_UNEXPECTED_ENCODING;
				if (NH_SUCCESS(rv) && ASN_IS_PRESENT(cur)) rv = self->hParser->parse_octetstring(self->hParser, cur);
				if (NH_SUCCESS(rv)) rv = (cur = cur->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
				if (NH_SUCCESS(rv) && ASN_IS_PRESENT(cur) && cur->child) rv = NHIX_parse_general_name(self->hParser, cur->child);
				if (NH_SUCCESS(rv)) rv = (cur = cur->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
				if (NH_SUCCESS(rv) && ASN_IS_PRESENT(cur)) rv = self->hParser->parse_integer(cur);
			}
		})
		if (NH_FAIL(gRV)) rv = gRV;
		if (NH_FAIL(rv)) return rv;
		*node = extnValue->child;
	}
	else *node = NULL;
	return rv;
}

const static unsigned int ski_oid[] = { 2, 5, 29, 14 };
static NH_NODE_WAY pkix_ski_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_OCTET_STRING,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, ski)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_RV rv, gRV;
	NH_ASN1_PNODE cur, ext, value, extnValue;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 9)))) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = self->find_extension(self, ski_oid, NHC_OID_COUNT(ski_oid), cur, &ext))) return rv;
	if (ext)
	{
		if (!(extnValue = self->hParser->sail(ext, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) return NH_UNEXPECTED_ENCODING;
		GUARD(self->mutex, gRV,
		{
			if (!extnValue->child)
			{
				if (NH_SUCCESS(rv = self->hParser->new_node(self->hParser->container, &value)))
				{
					value->parent = extnValue;
					extnValue->child = value;
					value->identifier = extnValue->contents;
					rv = self->hParser->map_from(self->hParser, value, pkix_ski_map, ASN_NODE_WAY_COUNT(pkix_ski_map));
				}
				if (NH_SUCCESS(rv)) rv = self->hParser->parse_octetstring(self->hParser, value);
			}
		})
		if (NH_FAIL(gRV)) rv = gRV;
		if (NH_FAIL(rv)) return rv;
		*node = extnValue->child;
	}
	else *node = NULL;
	return rv;
}

const static unsigned int key_usage_oid[] = { 2, 5, 29, 15 };
static NH_NODE_WAY key_usage_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_BIT_STRING,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, key_usage)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_RV rv, gRV;
	NH_ASN1_PNODE cur, ext, value, extnValue;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 9)))) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = self->find_extension(self, key_usage_oid, NHC_OID_COUNT(key_usage_oid), cur, &ext))) return rv;
	if (ext)
	{
		if (!(extnValue = self->hParser->sail(ext, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) return NH_UNEXPECTED_ENCODING;
		GUARD(self->mutex, gRV,
		{
			if (!extnValue->child)
			{
				if (NH_SUCCESS(rv = self->hParser->new_node(self->hParser->container, &value)))
				{
					value->parent = extnValue;
					extnValue->child = value;
					value->identifier = extnValue->contents;
					rv = self->hParser->map_from(self->hParser, value, key_usage_map, ASN_NODE_WAY_COUNT(key_usage_map));
				}
				if (NH_SUCCESS(rv)) rv = self->hParser->parse_bitstring(self->hParser, value);
			}
		})
		if (NH_FAIL(gRV)) rv = gRV;
		if (NH_FAIL(rv)) return rv;
		*node = extnValue->child;
	}
	else *node = NULL;
	return rv;
}

const static unsigned int subject_alt_names_oid[] = { 2, 5, 29, 17 };
const static unsigned int issuer_alt_names_oid[] = { 2, 5, 29, 18 };
INLINE NH_UTILITY(NH_RV, parse_alt_names)
(
	_IN_ NH_CERTIFICATE_HANDLER_STR *self,
	_IN_ unsigned int *oid,
	_IN_ size_t oidCount,
	_OUT_ NH_ASN1_PNODE *node
)
{
	NH_RV rv, gRV;
	NH_ASN1_PNODE cur, ext, value, extnValue;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 9)))) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = self->find_extension(self, oid, oidCount, cur, &ext))) return rv;
	if (ext)
	{
		if (!(extnValue = self->hParser->sail(ext, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) return NH_UNEXPECTED_ENCODING;
		GUARD(self->mutex, gRV,
		{
			if (!extnValue->child && NH_SUCCESS(rv = self->hParser->new_node(self->hParser->container, &value)))
			{
				value->parent = extnValue;
				extnValue->child = value;
				value->identifier = extnValue->contents;
				rv = NHIX_parse_general_names(self->hParser, value);
			}
		})
		if (NH_FAIL(gRV)) rv = gRV;
		if (NH_FAIL(rv)) return rv;
		*node = extnValue->child;
	}
	else *node = NULL;
	return rv;
}
NH_UTILITY(NH_RV, subject_alt_names)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	return parse_alt_names(self, subject_alt_names_oid, NHC_OID_COUNT(subject_alt_names_oid), node);
}

NH_UTILITY(NH_RV, issuer_alt_names)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	return parse_alt_names(self, issuer_alt_names_oid, NHC_OID_COUNT(issuer_alt_names_oid), node);
}

const static unsigned int basic_constraints_oid[] = { 2, 5, 29, 19 };
static NH_NODE_WAY pkix_cert_basic_constraints_map[] =
{
	{	/* BasicConstraints */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* cA */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_BOOLEAN | NH_ASN1_DEFAULT_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* pathLenConstraint */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};

NH_UTILITY(NH_RV, basic_constraints)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_RV rv, gRV;
	NH_ASN1_PNODE cur, ext, value, extnValue;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 9)))) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = self->find_extension(self, basic_constraints_oid, NHC_OID_COUNT(basic_constraints_oid), cur, &ext))) return rv;
	if (ext)
	{
		if (!(extnValue = self->hParser->sail(ext, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) return NH_UNEXPECTED_ENCODING;
		GUARD(self->mutex, gRV,
		{
			if (!extnValue->child)
			{
				if (NH_SUCCESS(rv = self->hParser->new_node(self->hParser->container, &value)))
				{
					value->parent = extnValue;
					extnValue->child = value;
					value->identifier = extnValue->contents;
					rv = self->hParser->map_from(self->hParser, value, pkix_cert_basic_constraints_map, ASN_NODE_WAY_COUNT(pkix_cert_basic_constraints_map));
				}
				if (NH_SUCCESS(rv)) rv = (cur = value->child) ? NH_OK : NH_UNEXPECTED_ENCODING;
				if (NH_SUCCESS(rv) && ASN_IS_PRESENT(cur)) rv = self->hParser->parse_boolean(cur);
				if (NH_SUCCESS(rv)) rv = (cur = cur->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
				if (NH_SUCCESS(rv) && ASN_IS_PRESENT(cur)) rv = self->hParser->parse_little_integer(self->hParser, cur);
			}
		})
		if (NH_FAIL(gRV)) rv = gRV;
		if (NH_FAIL(rv)) return rv;
		*node = extnValue->child;
	}
	else *node = NULL;
	return rv;
}

const static unsigned int ext_key_usage_oid[] = { 2, 5, 29, 37 };
static NH_NODE_WAY pkix_cert_key_purpose_id_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	}
};
NH_NODE_WAY pkix_cert_ext_key_usage_map[] =
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
		pkix_cert_key_purpose_id_map,
		ASN_NODE_WAY_COUNT(pkix_cert_key_purpose_id_map)
	}
};
NH_UTILITY(NH_RV, ext_key_usage)(_IN_ NH_CERTIFICATE_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *node)
{
	NH_RV rv, gRV;
	NH_ASN1_PNODE cur, ext, value, extnValue;

	if (!(cur = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 9)))) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = self->find_extension(self, ext_key_usage_oid, NHC_OID_COUNT(ext_key_usage_oid), cur, &ext))) return rv;
	if (ext)
	{
		if (!(extnValue = self->hParser->sail(ext, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)))) return NH_UNEXPECTED_ENCODING;
		GUARD(self->mutex, gRV,
		{
			if (!extnValue->child)
			{
				if (NH_SUCCESS(rv = self->hParser->new_node(self->hParser->container, &value)))
				{
					value->parent = extnValue;
					extnValue->child = value;
					value->identifier = extnValue->contents;
					rv = self->hParser->map_from(self->hParser, value, pkix_cert_ext_key_usage_map, ASN_NODE_WAY_COUNT(pkix_cert_ext_key_usage_map));
				}
				if (NH_SUCCESS(rv)) rv = (cur = value->child) ? NH_OK : NH_UNEXPECTED_ENCODING;
				while (NH_SUCCESS(rv) && cur)
				{
					rv = self->hParser->parse_oid(self->hParser, cur);
					cur = cur->next;
				}
			}
		})
		if (NH_FAIL(gRV)) rv = gRV;
		if (NH_FAIL(rv)) return rv;
		*node = extnValue->child;
	}
	else *node = NULL;
	return rv;
}


static const NH_CERTIFICATE_HANDLER_STR defCertHandler =
{
	NULL,		/* mutex */
	NULL,		/* hParser */
	NULL,		/* serialNumber */
	NULL,		/* issuer */
	NULL,		/* subject */
	NULL,		/* pubkey */

	match_subject,
	check_validity,
	verify_certificate,

	/* Certificate fields */
	certificate_version,
	certificate_signature_mech,
	not_before,
	not_after,
	issuer_unique_ID,
	subject_unique_ID,

	/* Certificate extensions */
	cert_find_extension,
	aki,
	ski,
	key_usage,
	subject_alt_names,
	issuer_alt_names,
	basic_constraints,
	ext_key_usage,
	cert_map_extensions
};
NH_FUNCTION(NH_RV, NH_parse_certificate)(_IN_ unsigned char *buffer, _IN_ size_t size, _OUT_ NH_CERTIFICATE_HANDLER *hHandler)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node;
	NH_NAME_NODE issuer = NULL, subject = NULL;
	NH_CERTIFICATE_HANDLER ret = NULL;

	if (NH_FAIL(rv = NH_new_parser(buffer, size, 128, 2048, &hParser))) return rv;
	rv = hParser->map(hParser, pkix_certificate_map, ASN_NODE_WAY_COUNT(pkix_certificate_map));
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = ((node = hParser->sail(node, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_bitstring(hParser, node);

	if (NH_SUCCESS(rv)) rv = ((node = hParser->sail(node, ((NH_PARSE_WEST | 2) << 16) | (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_integer(node);
	if (NH_SUCCESS(rv)) rv = ((node = hParser->sail(node, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = ((node = hParser->sail(node, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = NHIX_parse_name(hParser, node, &issuer);
	if (NH_SUCCESS(rv)) rv = ((node = hParser->sail(node, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_time(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_time(hParser, node);
	if (NH_SUCCESS(rv)) rv = ((node = hParser->sail(node, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = NHIX_parse_name(hParser, node, &subject);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = NHIX_parse_pubkey(hParser, node);
	if (NH_SUCCESS(rv)) rv = (ret = (NH_CERTIFICATE_HANDLER) malloc(sizeof(NH_CERTIFICATE_HANDLER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv))
	{
		memcpy(ret, &defCertHandler, sizeof(NH_CERTIFICATE_HANDLER_STR));
		rv = NH_create_mutex(&ret->mutex);
	}
	if (NH_SUCCESS(rv))
	{
		ret->serialNumber = hParser->sail(hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | NH_SAIL_SKIP_EAST);
		ret->issuer = issuer;
		ret->subject = subject;
		ret->pubkey = hParser->sail(hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 6));
		if (!ret->serialNumber || !ret->issuer || !ret->subject || !ret->pubkey) rv = NH_CANNOT_SAIL;
	}

	if (NH_SUCCESS(rv))
	{
		ret->hParser = hParser;
		*hHandler = ret;
	}
	else
	{
		if (ret) NH_release_certificate(ret);
		else NH_release_parser(hParser);
	}
	return rv;
}

NH_FUNCTION(void, NH_release_certificate)(_INOUT_ NH_CERTIFICATE_HANDLER hHandler)
{
	if (hHandler)
	{
		if (hHandler->hParser) NH_release_parser(hHandler->hParser);
		if (hHandler->mutex) NH_release_mutex(hHandler->mutex);
		free(hHandler);
	}
}


/** ****************************
 *  X.509 CRL handler
 *  ****************************/
INLINE NH_UTILITY(int, comp_integer)(_IN_ unsigned char *fvalue, _IN_ size_t flength, _IN_ unsigned char *svalue, _IN_ size_t slength)
{
	unsigned int realflen, realslen, i = 0, j = 0;

	while (i < flength && fvalue[i] == 0) i++;
	realflen = flength - i;
	while (j < slength && svalue[j] == 0) j++;
	realslen = slength - j;
	if (realflen != realslen) return (realflen - realslen);
	return memcmp(fvalue + i, svalue + j, realflen);
}
INLINE NH_UTILITY(NH_RV, inc_integer)(_INOUT_ NH_CARGO_CONTAINER container, NH_BIG_INTEGER *num, NH_BIG_INTEGER **result)
{
	NH_RV rv;
	int i;
	NH_BIG_INTEGER *buffer = (*result);

	if (!buffer)
	{
		if (NH_FAIL(rv = container->bite_chunk(container, sizeof(NH_BIG_INTEGER), (void*) &buffer))) return rv;
		memset(buffer, 0, sizeof(NH_BIG_INTEGER));
	}
	if (!buffer->data || buffer->length != num->length)
	{
		if (NH_FAIL(rv = container->bite_chunk(container, num->length, (void*) &buffer->data))) return rv;
		buffer->length = num->length;
	}
	memcpy(buffer->data, num->data, num->length);
	for (i = num->length - 1; i > -1; i--)
	{
		if (buffer->data[i] == 0xFF) buffer->data[i] = 0x00;
		else
		{
			buffer->data[i]++;
			*result = buffer;
			return NH_OK;
		}
	}
	if (i == -1)
	{
		if (NH_FAIL(rv = container->bite_chunk(container, num->length + 1, (void*) &buffer->data))) return rv;
		buffer->length = num->length + 1;
		memset(buffer->data + 1, 0x00, num->length);
		buffer->data[0] = 0x01;
	}
	*result = buffer;
	return NH_OK;
}

INLINE NH_UTILITY(NH_RV, dec_integer)(_INOUT_ NH_CARGO_CONTAINER container, NH_BIG_INTEGER *num, NH_BIG_INTEGER **result)
{
	NH_RV rv;
	int i;
	NH_BIG_INTEGER *buffer = (*result);

	if (!buffer)
	{
		if (NH_FAIL(rv = container->bite_chunk(container, sizeof(NH_BIG_INTEGER), (void*) &buffer))) return rv;
		memset(buffer, 0, sizeof(NH_BIG_INTEGER));
	}
	if (!buffer->data || buffer->length != num->length)
	{
		if (NH_FAIL(rv = container->bite_chunk(container, num->length, (void*) &buffer->data))) return rv;
		buffer->length = num->length;
	}
	memcpy(buffer->data, num->data, num->length);
	for (i = num->length - 1; i > -1; i--)
	{
		if (buffer->data[i] == 0x00) buffer->data[i] = 0xFF;
		else
		{
			buffer->data[i]--;
			*result = buffer;
			return NH_OK;
		}
	}
	return NH_OK;
}

/* *************************************************************
 * binary search
 * ************************************************************* */
typedef NH_INTERVAL			BTREE;
typedef NH_BIG_INTEGER*			BDATA;
#define IS_GREATER_THAN(a, b)		(comp_integer(a->data, a->length, b->last->data,b->last->length) > 0)
#define IS_LESSER_THAN(a, b)		(comp_integer(a->data, a->length, b->first->data, b->first->length) < 0)
INLINE NH_UTILITY(int, binary_search)(_IN_ BTREE array[], _IN_ int n, _IN_ BDATA key)
{
	int min = 0, max = n - 1, i;

	while (max >= min)
	{
		i = (min + max) / 2;
		if (IS_LESSER_THAN(key, array[i])) max = i - 1;
		else if (IS_GREATER_THAN(key, array[i])) min = i + 1;
		else  return i;
	}
	return -min;
}
/* ************************************************************* */
NH_UTILITY(CK_BBOOL, is_revoked)(_IN_ NH_CRL_HANDLER_STR *self, NH_BIG_INTEGER *serial)
{
	if (!serial) return CK_FALSE;
	if (self->rcount == 0) return CK_FALSE;
	return binary_search(self->revoked, self->rcount, serial) < 0 ? CK_TRUE : CK_FALSE;
}

NH_UTILITY(NH_RV, verify_crl)(_IN_ NH_CRL_HANDLER_STR *self, _IN_ NH_ASN1_PNODE pubkeyInfo)
{
	return verify
	(
		self->hParser->sail(self->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST),
		self->hParser->sail(self->hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2)),
		self->hParser->sail(self->hParser->root, NH_SAIL_SKIP_SOUTH),
		pubkeyInfo
	);
}

static NH_NODE_WAY crl_extensions_map[] =
{
	{	/* Extensions */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* Extension */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		pkix_extension_map,
		ASN_NODE_WAY_COUNT(pkix_extension_map)
	}
};
INLINE NH_UTILITY(NH_RV, parse_revoked)(_INOUT_ NH_ASN1_PARSER_HANDLE hParser, _INOUT_ NH_ASN1_PNODE revoked)
{
	NH_RV rv = NH_OK;
	NH_ASN1_PNODE node, next;

	if (!((node = revoked->child) && (node = node->next))) return NH_UNEXPECTED_ENCODING;
	if (!ASN_IS_PARSED(node)) if (NH_FAIL(rv = hParser->parse_time(hParser, node))) return rv;
	node = node->next;
	if (ASN_IS_PRESENT(node) && (node = node->child))
	{
		if (node->size == UINT_MAX) rv = hParser->map_from(hParser, node->parent, crl_extensions_map, ASN_NODE_WAY_COUNT(crl_extensions_map));
		if (NH_FAIL(rv)) return rv;
		while(node)
		{
			if (!(next = node->child)) return NH_UNEXPECTED_ENCODING;
			if (!ASN_IS_PARSED(next)) if (NH_FAIL(rv =hParser->parse_oid(hParser, next))) return rv;
			if (!(next = next->next)) return NH_UNEXPECTED_ENCODING;
			if (ASN_IS_PRESENT(next) && !ASN_IS_PARSED(next)) if (NH_FAIL(rv = hParser->parse_boolean(next))) return rv;
			if (!(next = next->next)) return NH_UNEXPECTED_ENCODING;
			if (!ASN_IS_PARSED(next)) if (NH_FAIL(rv = hParser->parse_octetstring(hParser, next))) return rv;
			node = node->next;
		}
	}
	return NH_OK;
}
NH_UTILITY(NH_RV, get_revoked)(_IN_ NH_CRL_HANDLER_STR *self, _IN_ NH_BIG_INTEGER *serial, _OUT_ NH_ASN1_PNODE *ret)
{
	NH_RV rv = NH_OK, gRV;
	int idx, i;
	NH_INTERVAL interval;
	NH_ASN1_PNODE revoked;

	if (!serial) return NH_INVALID_ARG;
	*ret = NULL;
	if (self->rcount == 0) return NH_OK;
	idx = binary_search(self->revoked, self->rcount, (BDATA) serial);
	if (idx >= 0) return NH_OK;
	idx *= -1;
	interval = self->revoked[idx];
	for (i = 0; (size_t) i < interval->rcount; i++)
	{
		revoked = interval->revoked[i];
		if (comp_integer(serial->data, serial->length, (unsigned char*) revoked->child->value, revoked->child->valuelen) == 0)
		{
			GUARD(self->mutex, gRV,
			{
				rv = parse_revoked(self->hParser, revoked);
			})
			if (NH_FAIL(gRV)) rv = gRV;
			if (NH_SUCCESS(rv)) *ret = revoked;
			break;
		}
	}
	return rv;
}

NH_UTILITY(NH_RV, revoked_certs)(_IN_ NH_CRL_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *list)
{
	NH_ASN1_PNODE node;
	NH_RV rv = NH_OK, gRV;

	*list = NULL;
	if (!(node = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 5)))) return NH_CANNOT_SAIL;
	if (ASN_IS_PRESENT(node) && (node->child))
	{
		node = node->child;
		while (NH_SUCCESS(rv) && node)
		{
			GUARD(self->mutex, gRV,
			{
				rv = parse_revoked(self->hParser, node);
			})
			if (NH_FAIL(gRV)) rv = gRV;
			node = node->next;
		}
		if (NH_SUCCESS(rv)) *list = self->hParser->sail(self->hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 5));
	}
	return rv;
}

NH_UTILITY(NH_RV, crl_version)(_IN_ NH_CRL_HANDLER_STR *self, _OUT_ NH_ASN1_PNODE *version)
{
	NH_ASN1_PNODE node;
	NH_RV rv = NH_OK, gRV;

	node = self->hParser->sail(self->hParser->root, NH_PARSE_SOUTH | 2);
	if (ASN_IS_PRESENT(node))
	{
		GUARD(self->mutex, gRV,
		{
			rv = self->hParser->parse_little_integer(self->hParser, node);
		})
		if (NH_FAIL(gRV)) rv = gRV;
	}
	if (NH_SUCCESS(rv)) *version = node;
	return rv;
}

NH_UTILITY(NH_RV, crl_find_extension)
(
	_IN_ NH_CRL_HANDLER_STR *self,
	_IN_ unsigned int *OID,
	_IN_ size_t count,
	_IN_ NH_ASN1_PNODE from,
	_OUT_ NH_ASN1_PNODE *extension
)
{
	return find_extension(self->hParser, self->mutex, OID, count, from, extension);
}

NH_UTILITY(NH_RV, crl_map_extensions)(_IN_ NH_CRL_HANDLER_STR *self, _IN_ NH_ASN1_PNODE from)
{
	return map_extensions(self->hParser, self->mutex, from);
}


static const NH_CRL_HANDLER_STR defCRLHandler =
{
	NULL,		/* mutex */
	NULL,		/* hParser */

	NULL,		/* issuer */
	NULL,		/* thisUpdate */
	NULL,		/* nextUpdate */
	NULL,		/* revoked */
	0,		/* rcount */

	is_revoked,
	verify_crl,
	get_revoked,
	revoked_certs,
	crl_version,
	crl_find_extension,
	crl_map_extensions
};

static NH_NODE_WAY pkix_revoked_entry_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* userCertificate */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* revocationDate */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_CHOICE_BIT,
		pkix_time_map,
		ASN_NODE_WAY_COUNT(pkix_time_map)
	},
	{	/* crlEntryExtensions */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
static NH_NODE_WAY pkix_tbsCertList_map[] =
{
	{	/* version */
		NH_PARSE_ROOT,
		NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
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
	{	/* thisUpdate */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_CHOICE_BIT,
		pkix_time_map,
		ASN_NODE_WAY_COUNT(pkix_time_map)
	},
	{	/* nextUpdate */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_CHOICE_BIT,
		pkix_time_map,
		ASN_NODE_WAY_COUNT(pkix_time_map)
	},
	{	/* revokedCertificates */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* crlExtensions */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT | NH_ASN1_OPTIONAL_BIT | NH_ASN1_EXP_CONSTRUCTED_BIT,
		NULL,
		0
	}
};
static NH_NODE_WAY pkix_CertificateList_map[] =
{
	{
		/* CertificateList */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* tbsCertList */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_SEQUENCE,
		pkix_tbsCertList_map,
		ASN_NODE_WAY_COUNT(pkix_tbsCertList_map)
	},
	{	/* signatureAlgorithm */
		(NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
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
#define PKIX_CRL_DEFAULT_NODES		11	/* Ratio used to estimate nodes to be previously allocated to parse a CRL */
#define PKIX_CRL_DEFAULT_DATA_SIZE		2048	/* Estimated size to CRL values buffer */

/*	***************************************************************
 *	quicksort
 *	http://www.cs.auckland.ac.nz/~jmor159/PLDS210/niemann/s_qui.htm
 *	*************************************************************** */
typedef NH_ASN1_PNODE	T;		/* type of item to be sorted */
typedef int 		tblIndex;	/* type of subscript */
#define compGT(a, b)	(comp_integer((unsigned char*) a->child->value, a->child->valuelen, (unsigned char*) b->child->value, b->child->valuelen) > 0)
NH_UTILITY(void, insertSort)(_INOUT_ T *a, _IN_ tblIndex lb, _IN_ tblIndex ub)
{
	T t;
	tblIndex i, j;

	/* **************************
	 *  sort array a[lb..ub]    *
	 ************************** */
	for (i = lb + 1; i <= ub; i++)
	{
		t = a[i];

		/*	Shift elements down until
			insertion point found.		*/
		for (j = i-1; j >= lb && compGT(a[j], t); j--) a[j+1] = a[j];

		/* insert */
		a[j+1] = t;
	}
}
INLINE NH_UTILITY(tblIndex, partition)(_INOUT_ T *a, _IN_ tblIndex lb, _IN_ tblIndex ub)
{
	T t, pivot;
	tblIndex i, j, p;

	/* ******************************
	*  partition array a[lb..ub]    *
	******************************* */

	/* select pivot and exchange with 1st element */
	p = lb + ((ub - lb) >> 1);
	pivot = a[p];
	a[p] = a[lb];

	/* sort lb+1..ub based on pivot */
	i = lb + 1;
	j = ub;
	while (1)
	{
		while (i < j && compGT(pivot, a[i])) i++;
		while (j >= i && compGT(a[j], pivot)) j--;
		if (i >= j) break;
		t = a[i];
		a[i] = a[j];
		a[j] = t;
		j--; i++;
	}

	/* pivot belongs in a[j] */
	a[lb] = a[j];
	a[j] = pivot;

	return j;
}
NH_UTILITY(void, quickSort)(_INOUT_ T *a, _INOUT_ tblIndex lb, _INOUT_ tblIndex ub)
{
	tblIndex m;

	/**************************
	*  sort array a[lb..ub]  *
	**************************/

	while (lb < ub)
	{

		/* quickly sort short lists */
		if (ub - lb <= 12)
		{
			insertSort(a, lb, ub);
			return;
		}

		/* partition into two segments */
		m = partition (a, lb, ub);

		/* sort the smallest partition    */
		/* to minimize stack requirements */
		if (m - lb <= ub - m)
		{
			quickSort(a, lb, m - 1);
			lb = m + 1;
		}
		else
		{
			quickSort(a, m + 1, ub);
			ub = m - 1;
		}
	}
}
/* ******************************************************************** */
static unsigned char nhix_fu[] =
{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
INLINE NH_UTILITY(NH_RV, alloc_interval)
(
	_INOUT_ NH_CARGO_CONTAINER container,
	_IN_ NH_BIG_INTEGER *first,
	_IN_ NH_BIG_INTEGER *last,
	_OUT_ NH_INTERVAL *interval
)
{
	NH_RV rv;
	NH_INTERVAL ret;

	if (NH_SUCCESS(rv = container->bite_chunk(container, sizeof(NH_INTERVAL_STR), (void*) &ret)))
	{
		memset(ret, 0, sizeof(NH_INTERVAL_STR));
		ret->first = (NH_BIG_INTEGER*) first;
		ret->last = (NH_BIG_INTEGER*) last;
		*interval = ret;
	}
	return rv;
}
INLINE NH_UTILITY(NH_RV, alloc_integer)(_INOUT_ NH_CARGO_CONTAINER container, _IN_ size_t size, _OUT_ NH_BIG_INTEGER **out)
{
	NH_RV rv;
	NH_BIG_INTEGER *ret;

	if (NH_SUCCESS(rv = container->bite_chunk(container, sizeof(NH_BIG_INTEGER), (void*) &ret)))
	{
		if (NH_SUCCESS(rv = container->bite_chunk(container, size, (void*) &ret->data)))
		{
			ret->length = size;
			*out = ret;
		}
	}
	return rv;
}
INLINE NH_UTILITY(NH_RV, add_crl_node)(_INOUT_ NH_CARGO_CONTAINER container, _INOUT_ NH_INTERVAL node, _IN_ NH_ASN1_PNODE newnode)
{
	NH_RV rv;

	rv = container->grow_chunk(container, (void**) &node->revoked, node->rcount * sizeof(NH_ASN1_PNODE), (node->rcount + 1) * sizeof(NH_ASN1_PNODE));
	if (NH_SUCCESS(rv)) node->revoked[node->rcount++] = newnode;
	return rv;
}
NH_UTILITY(NH_RV, sort_crl)(_INOUT_ NH_ASN1_PARSER_HANDLE hParser, _IN_ NH_ASN1_PNODE from, _OUT_ NH_INTERVAL **list, _OUT_ size_t *lcount)
{
	NH_RV rv;
	NH_ASN1_PNODE node = from->child, *toSort;
	size_t count = 0, i = 0, nodes = 1;
	NH_INTERVAL current, firstInterval = NULL, *ret;
	NH_BIG_INTEGER it, *tit;
	int first;

	while (node)
	{
		if (NH_FAIL(rv = hParser->parse_integer(node->child))) return rv;
		count++;
		node = node->next;
	}
	if (!(toSort = (NH_ASN1_PNODE*) malloc(sizeof(NH_ASN1_PNODE) * count))) return NH_OUT_OF_MEMORY_ERROR;
	node = from->child;
	while (node)
	{
		toSort[i++] = node;
		node = node->next;
	}
	quickSort(toSort, 0, count - 1);
	if
	(
		NH_SUCCESS(rv = alloc_interval(hParser->container, NULL, NULL, &current)) &&
		NH_SUCCESS(rv = alloc_integer(hParser->container, 1, &current->first))
	)
	{
		*current->first->data = 0;
		if (NH_SUCCESS(rv = alloc_integer(hParser->container, 20, &current->last)))
		{
			memcpy(current->last->data, &nhix_fu, 20);
			firstInterval = current;
		}
	}
	i = 0;
	while (NH_SUCCESS(rv) && i < count)
	{
		it.data = (unsigned char*) toSort[i]->child->value;
		it.length = toSort[i]->child->valuelen;
		first = comp_integer(it.data, it.length, current->first->data, current->first->length);
		if (first > 0)
		{
			tit = NULL;
			if
			(
				NH_SUCCESS(rv = inc_integer(hParser->container, &it, &tit)) &&
				NH_SUCCESS(rv = alloc_interval(hParser->container, tit, current->last, &current->next))
			)
			{
				current->last = NULL;
				if (NH_SUCCESS(rv = dec_integer(hParser->container, &it, &current->last)))
				{
					current->next->previous = current;
					rv = add_crl_node(hParser->container, current->next, toSort[i]);
					current = current->next;
					nodes++;
				}
			}
		}
		else if (first == 0)
		{
			rv = inc_integer(hParser->container, current->first, &current->first);
			if (NH_SUCCESS(rv)) rv = add_crl_node(hParser->container, current, toSort[i]);
		}
		else rv = NH_MALFORMED_CRL_SERIAL; /* We hope that this piece of shit will never happen */
		i++;
	}
	free(toSort);
	if (NH_SUCCESS(rv))
	{
		rv = hParser->container->bite_chunk(hParser->container, sizeof(NH_INTERVAL) * nodes, (void*) &ret);
		if (NH_SUCCESS(rv))
		{
			current = firstInterval;
			for (i = 0; i < nodes; i++)
			{
				ret[i] = current;
				current = current->next;
			}
			*list = ret;
			*lcount = nodes;
		}
	}
	return rv;
}

NH_FUNCTION(NH_RV, NH_parse_crl)(_IN_ unsigned char *buffer, _IN_ size_t size, _OUT_ NH_CRL_HANDLER *hHandler)
{
	NH_CRL_HANDLER ret;
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser = NULL;
	NH_ASN1_PNODE node;

	if (!(ret = (NH_CRL_HANDLER) malloc(sizeof(NH_CRL_HANDLER_STR)))) return NH_OUT_OF_MEMORY_ERROR;
	memcpy(ret, &defCRLHandler, sizeof(NH_CRL_HANDLER_STR));
	rv = NH_create_mutex(&ret->mutex);
	if (NH_SUCCESS(rv)) rv = NH_new_parser(buffer, size, size / PKIX_CRL_DEFAULT_NODES, size / PKIX_CRL_DEFAULT_DATA_SIZE, &hParser);
	if (NH_SUCCESS(rv)) rv = hParser->map(hParser, pkix_CertificateList_map, ASN_NODE_WAY_COUNT(pkix_CertificateList_map));
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 2) )) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = NHIX_parse_name(hParser, node, &ret->issuer);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_time(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv) && ASN_IS_PRESENT(node)) rv = hParser->parse_time(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_bitstring(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 5))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv) && ASN_IS_PRESENT(node) && node->child)
	{
		rv = hParser->map_set_of(hParser, node->child, pkix_revoked_entry_map, ASN_NODE_WAY_COUNT(pkix_revoked_entry_map));
		if (NH_SUCCESS(rv)) rv = sort_crl(hParser, node, &ret->revoked, &ret->rcount);
	}
	if (NH_SUCCESS(rv))
	{
		ret->hParser = hParser;
		ret->thisUpdate = hParser->sail(hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 3));
		ret->nextUpdate = hParser->sail(hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | (NH_PARSE_EAST | 4));
		*hHandler = ret;
	}
	else
	{
		if (ret->mutex) NH_release_mutex(ret->mutex);
		if (hParser) NH_release_parser(hParser);
		free(ret);
	}
	return rv;
}

NH_FUNCTION(void, NH_release_crl)(_INOUT_ NH_CRL_HANDLER hHandler)
{
	if (hHandler)
	{
		if (hHandler->mutex) NH_release_mutex(hHandler->mutex);
		if (hHandler->hParser) NH_release_parser(hHandler->hParser);
		free(hHandler);
	}
}
