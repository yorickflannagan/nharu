#include "pkix.h"
#include <string.h>
#include <stringprep.h>

/** ****************************
 *  PKIX general functions
 *  ****************************/
/*
 * Name ::= CHOICE { -- only one possibility for now --
 *    rdnSequence  RDNSequence
 * }
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 * AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue
 * }
 * AttributeType   ::= OBJECT IDENTIFIER
 * AttributeValue  ::= ANY -- DEFINED BY AttributeType
 * DirectoryString ::= CHOICE {
 *    teletexString    TeletexString (SIZE (1..MAX)),
 *    printableString  PrintableString (SIZE (1..MAX)),
 *    universalString  UniversalString (SIZE (1..MAX)),
 *    utf8String       UTF8String (SIZE (1..MAX)),
 *    bmpString        BMPString (SIZE (1..MAX))
 * }
 */
NH_NODE_WAY pkix_attribute_map[] =
{
	{	/* AttributeTypeAndValue */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* type */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* teletexString */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_CHOICE_BIT | NH_ASN1_TELETEX_STRING,
		NULL,
		0
	},
	{	/* printableString */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_PRINTABLE_STRING,
		NULL,
		0
	},
	{	/* universalString */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_UNIVERSAL_STRING,
		NULL,
		0
	},
	{	/* utf8String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_UTF8_STRING,
		NULL,
		0
	},
	{	/* bmpString */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_BMP_STRING,
		NULL,
		0
	},
	{
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_IA5_STRING | NH_ASN1_CHOICE_END_BIT,
		NULL,
		0
	}
};
NH_NODE_WAY pkix_x500_rdn_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SET | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		pkix_attribute_map,
		ASN_NODE_WAY_COUNT(pkix_attribute_map)
	}
};


INLINE NH_UTILITY(NH_RV, handle_spaces)(_IN_ char *buffer, _OUT_ char *prepared, _INOUT_ size_t *start, _IN_ size_t end)
{
	size_t i = 0, current = *start;

	if (current > end - 2) return NH_STRINGPREP_ERROR + STRINGPREP_TOO_SMALL_BUFFER;
	while (buffer[i] == 0x20) i++;
	prepared[current++] = 0x20;
	while (buffer[i] && current < end - 1)
	{
		if (buffer[i] != 0x20) prepared[current++] = buffer[i++];
		else
		{
			prepared[current++] = 0x20;
			prepared[current++] = 0x20;
			while (buffer[i] == 0x20) i++;
		}
	}
	if (current > end - 2) return NH_STRINGPREP_ERROR + STRINGPREP_TOO_SMALL_BUFFER;
	if (buffer[i - 1] == 0x20) prepared[--current] = 0;
	else
	{
		prepared[current++] = 0x20;
		prepared[current] = 0;
	}
	*start = current;
	return NH_OK;
}
NH_UTILITY(NH_RV, prep_name)
(
	_INOUT_ NH_ASN1_PARSER_HANDLE hParser,
	_IN_ size_t max,
	_IN_ size_t length,
	_IN_ NH_ASN1_PNODE from,
	_OUT_ char **to
)
{
	char *buffer, *str;
	size_t buflen = max * 3 + 1, end = length * 3, start = 0;
	int rc;
	NH_RV rv;
	NH_ASN1_PNODE set = from->child, att, node;

	if (!(buffer = (char*) malloc(buflen))) return NH_OUT_OF_MEMORY_ERROR;
	rv = hParser->container->bite_chunk(hParser->container, end + 1, (void*) &str);
	while (NH_SUCCESS(rv) && set)
	{
		att = set->child;
		while (NH_SUCCESS(rv) && att)
		{
			node = att->child->next;
			memset(buffer, 0, buflen);
			memcpy(buffer, node->value, node->valuelen);
			if ((rc = stringprep(buffer, buflen, 0, stringprep_nameprep)) != STRINGPREP_OK) rv = NH_STRINGPREP_ERROR + rc;
			if (NH_SUCCESS(rv)) rv = handle_spaces(buffer, str, &start, end);
			att = att->next;
		}
		set = set->next;
	}
	free(buffer);
	if (NH_SUCCESS(rv)) *to = str;
	return rv;
}

#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(NH_RV, NHIX_parse_name)(_INOUT_ NH_ASN1_PARSER_HANDLE hParser, _IN_ NH_ASN1_PNODE from, _OUT_ NH_NAME_NODE *to)
{
	NH_ASN1_PNODE set = from->child, att, node;
	NH_RV rv;
	size_t max = 0, length = 0;
	char *buffer;
	NH_NAME_NODE out;

	while (set)
	{
		att = set->child;
		while (att)
		{
			if (!(node = att->child)) return NH_UNEXPECTED_ENCODING;
			if (NH_FAIL(rv = hParser->parse_oid(hParser, node))) return rv;
			if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
			if (NH_FAIL(rv = hParser->parse_string(node))) return rv;
			length += node->valuelen + 2;
			if (node->valuelen + 2 > max) max = node->valuelen + 2;
			att = att->next;
		}
		set = set->next;
	}
	if
	(
		NH_SUCCESS(rv = prep_name(hParser, max, length, from, &buffer)) &&
		NH_SUCCESS(rv = hParser->container->bite_chunk(hParser->container, sizeof(NH_NAME_NODE_STR), (void*) &out))
	)
	{
		out->stringprep = buffer;
		out->node = from;
		*to = out;
	}
	return rv;
}

static NH_NODE_WAY pkix_general_name_map[] =
{
	{	/* otherName */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_CHOICE_BIT | NH_ASN1_EXPLICIT_BIT | NH_ASN1_EXP_CONSTRUCTED_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* rfc822Name */
		NH_PARSE_ROOT,
		NH_ASN1_IA5_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_CHOICE_BIT | NH_ASN1_EXPLICIT_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* dNSName */
		NH_PARSE_ROOT,
		NH_ASN1_IA5_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_2 | NH_ASN1_CHOICE_BIT | NH_ASN1_EXPLICIT_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* x400Address */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_3 | NH_ASN1_CHOICE_BIT | NH_ASN1_EXPLICIT_BIT | NH_ASN1_EXP_CONSTRUCTED_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* directoryName */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_4 | NH_ASN1_CHOICE_BIT | NH_ASN1_EXPLICIT_BIT | NH_ASN1_EXP_CONSTRUCTED_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* ediPartyName */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_5 | NH_ASN1_CHOICE_BIT | NH_ASN1_EXPLICIT_BIT | NH_ASN1_EXP_CONSTRUCTED_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* uniformResourceIdentifier */
		NH_PARSE_ROOT,
		NH_ASN1_IA5_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_6 | NH_ASN1_CHOICE_BIT | NH_ASN1_EXPLICIT_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* iPAddress */
		NH_PARSE_ROOT,
		NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_7 | NH_ASN1_CHOICE_BIT | NH_ASN1_EXPLICIT_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* registeredID */
		NH_PARSE_ROOT,
		NH_ASN1_OBJECT_ID | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_8 | NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT | NH_ASN1_EXPLICIT_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	}
};
INLINE NH_UTILITY(NH_RV, parse_names)(_IN_ NH_ASN1_PARSER_HANDLE hParser, _IN_ NH_ASN1_PNODE first)
{
	NH_RV rv = NH_OK;
	NH_ASN1_PNODE node = first;
	NH_NAME_NODE ignored;

	while (node)
	{
		switch(*node->identifier & NH_ASN1_TAG_MASK)
		{
		case 0x00:
		case 0x03:
		case 0x05:
			break;
		case 0x01:
		case 0x02:
		case 0x06:
			rv = hParser->parse_string(node);
			break;
		case 0x04:
			rv = hParser->map_set_of(hParser, node->child, pkix_x500_rdn_map, PKIX_X500_RDN_COUNT);
			if (NH_SUCCESS(rv)) rv = NHIX_parse_name(hParser, node, &ignored);
			break;
		case 0x07:
			rv = hParser->parse_octetstring(hParser, node);
			break;
		case 0x08:
			rv = hParser->parse_oid(hParser, node);
			break;
		default: return NH_UNEXPECTED_ENCODING;
		}
		node = node->next;
	}
	return rv;
}

#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(NH_RV, NHIX_parse_general_name)(_IN_ NH_ASN1_PARSER_HANDLE hParser, _IN_ NH_ASN1_PNODE first)
{
	NH_RV rv;

	rv = hParser->map_set_of(hParser, first, pkix_general_name_map, ASN_NODE_WAY_COUNT(pkix_general_name_map));
	if (NH_SUCCESS(rv)) rv = parse_names(hParser, first);
	return rv;
}

static NH_NODE_WAY pkix_general_names_map[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		pkix_general_name_map,
		ASN_NODE_WAY_COUNT(pkix_general_name_map)
	}
};

#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(NH_RV, NHIX_parse_general_names)(_IN_ NH_ASN1_PARSER_HANDLE hParser, _IN_ NH_ASN1_PNODE from)
{
	NH_RV rv;

	rv = hParser->map_from(hParser, from, pkix_general_names_map, ASN_NODE_WAY_COUNT(pkix_general_names_map));
	if (NH_SUCCESS(rv)) rv = parse_names(hParser, from->child);
	return rv;
}


static NH_NODE_WAY pkix_rsa_pubkey[] =
{
	{ NH_PARSE_ROOT, NH_ASN1_SEQUENCE, NULL, 0 },
	{ NH_SAIL_SKIP_SOUTH, NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT, NULL, 0 },
	{ NH_SAIL_SKIP_EAST, NH_ASN1_INTEGER, NULL, 0 }
};
#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(NH_RV, NHIX_parse_pubkey)(_IN_ NH_ASN1_PARSER_HANDLE hParser, _INOUT_ NH_ASN1_PNODE from)
{
	CK_MECHANISM_TYPE key;
	NH_ASN1_PNODE node, keynode;
	NH_RV rv;

	if (!(node = hParser->sail(from, NH_PARSE_SOUTH | 2))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hParser->parse_oid(hParser, node))) return rv;
	if ((key = NH_oid_to_mechanism(node->value, node->valuelen)) == CK_UNAVAILABLE_INFORMATION) return NH_UNEXPECTED_ENCODING;
	if (!(node = hParser->sail(node, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST))) return NH_CANNOT_SAIL;
	if (NH_FAIL(rv = hParser->parse_bitstring(hParser, node))) return rv;
	if (NH_FAIL(rv = hParser->new_node(hParser->container, &keynode))) return rv;
	keynode->parent = node;
	node->child = keynode;
	keynode->identifier = ((NH_PBITSTRING_VALUE) node->value)->string;
	switch (key)
	{
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		if (NH_FAIL(rv = hParser->map_from(hParser, keynode, pkix_rsa_pubkey, ASN_NODE_WAY_COUNT(pkix_rsa_pubkey)))) return rv;
		if (!(node = keynode->child)) return NH_CANNOT_SAIL;
		if (NH_FAIL(rv = hParser->parse_integer(node))) return rv;
		if (!(node = node->next)) return NH_CANNOT_SAIL;
		if (NH_FAIL(rv = hParser->parse_integer(node))) return rv;
		break;
	case CKM_ECDSA_KEY_PAIR_GEN:
		break;
	}
	return rv;
}


NH_UTILITY(NH_RV, verify_rsa)
(
	_IN_ NH_ASN1_PNODE rsakey,
	_IN_ unsigned char *hash,
	_IN_ size_t hashSize,
	_IN_ CK_MECHANISM_TYPE sigAlg,
	_IN_ NH_ASN1_PNODE sigValue
)
{
	NH_RV rv;
	unsigned char *buffer, *signature;
	size_t buflen, siglen;
	NH_BIG_INTEGER n, e;
	NH_RSA_PUBKEY_HANDLER pubKey;

	if (ASN_TAG_IS_PRESENT(sigValue, NH_ASN1_BIT_STRING))
	{
		signature = ((NH_PBITSTRING_VALUE) sigValue->value)->string;
		siglen = ((NH_PBITSTRING_VALUE) sigValue->value)->len;
	}
	else
	{
		signature = sigValue->value;
		siglen = sigValue->valuelen;
	}
	if (NH_FAIL(rv = NH_new_RSA_pubkey_handler(&pubKey))) return rv;
	buffer = rsakey->child->value;
	buflen = rsakey->child->valuelen;
	if (!buffer[0])
	{
		buffer++;
		buflen--;
	}
	n.data = buffer;
	n.length = buflen;
	e.data = rsakey->child->next->value;
	e.length = rsakey->child->next->valuelen;
	if (NH_SUCCESS(rv = pubKey->create(pubKey, &n, &e))) rv = pubKey->verify(pubKey, sigAlg, hash, hashSize, signature, siglen);
	NH_release_RSA_pubkey_handler(pubKey);
	return rv;
}
NH_UTILITY(NH_RV, NHIX_verify_signature)
(
	_IN_ NH_ASN1_PNODE data,
	_IN_ NH_ASN1_PNODE pubkeyInfo,
	_IN_ CK_MECHANISM_TYPE hashAlg,
	_IN_ NH_ASN1_PNODE signature
)
{
	NH_RV rv;
	NH_HASH_HANDLER hHash;
	unsigned char *hash = NULL;
	size_t hashsize;
	CK_MECHANISM_TYPE sigAlg;

	if
	(
		!data ||
		!pubkeyInfo ||
		!ASN_TAG_IS_PRESENT(pubkeyInfo, NH_ASN1_SEQUENCE) ||
		!pubkeyInfo->child ||
		!ASN_TAG_IS_PRESENT(pubkeyInfo->child, NH_ASN1_SEQUENCE) ||
		!pubkeyInfo->child->child ||
		!ASN_TAG_IS_PRESENT(pubkeyInfo->child->child, NH_ASN1_OBJECT_ID) ||
		!pubkeyInfo->child->next ||
		!ASN_TAG_IS_PRESENT(pubkeyInfo->child->next, NH_ASN1_BIT_STRING) ||
		!ASN_IS_PARSED(pubkeyInfo->child->child) ||
		!ASN_IS_PARSED(pubkeyInfo->child->next) ||
		!signature ||
		!ASN_IS_PARSED(signature)
	)	return NH_INVALID_ARG;

	if (NH_FAIL(rv = NH_new_hash(&hHash))) return rv;
	rv = hHash->init(hHash, hashAlg);
	if (NH_SUCCESS(rv)) rv = hHash->digest(hHash, data->identifier, data->contents - data->identifier + data->size, NULL, &hashsize);
	if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (hash = (unsigned char*) malloc(hashsize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		rv = hHash->digest(hHash, data->identifier, data->contents - data->identifier + data->size, hash, &hashsize);
		NH_release_hash(hHash);
		if (NH_SUCCESS(rv))
		{
			switch (NH_oid_to_mechanism(pubkeyInfo->child->child->value, pubkeyInfo->child->child->valuelen))
			{
			case CKM_RSA_PKCS_KEY_PAIR_GEN:
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
				if (NH_SUCCESS(rv)) rv = verify_rsa(pubkeyInfo->child->next->child, hash, hashsize, sigAlg, signature);
				break;
			case CKM_ECDSA_KEY_PAIR_GEN:
			default: rv = NH_UNSUPPORTED_MECH_ERROR;
			}
		}
		free(hash);
	}
	return rv;
}
