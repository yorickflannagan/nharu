#include "pki-issue.h"
#include <string.h>


static NH_RV __verify(_IN_ NH_CREQUEST_PARSER_STR *hHandler)
{
	/* TODO: */
	return NH_OK;
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
NH_NODE_WAY cert_request_map[] =
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
	if (NH_SUCCESS(rv)) rv = hParser->map(hParser, cert_request_map, ASN_NODE_WAY_COUNT(cert_request_map));
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_bitstring(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, ((NH_PARSE_SOUTH | 2) << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = NHIX_parse_name(hParser, node, &subject);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(node, (NH_SAIL_SKIP_EAST << 8) | (NH_PARSE_SOUTH | 2))) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(node, (NH_SAIL_SKIP_NORTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hParser->parse_bitstring(hParser, node);
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(node, (NH_SAIL_SKIP_WEST << 8) | NH_SAIL_SKIP_NORTH)) ? NH_OK : NH_CANNOT_SAIL;
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