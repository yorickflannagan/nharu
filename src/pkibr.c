#include "pkibr.h"
#include <stdlib.h>
#include <string.h>

/* 
	Microsoft user principal name (UPN, OID 1.3.6.1.4.1.311.20.2.3) is defined as an UTF8String
	(see https://msdn.microsoft.com/en-us/library/ff842518.aspx), but other string types were
	seen, depending on issuer. So, we will accept (almost) any string type
*/
static NH_NODE_WAY pkibr_extension_value[] =
{
	{	/* Octet String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	},
	{	/* Printable String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_PRINTABLE_STRING ,
		NULL,
		0
	},
	{	/* UTF8String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_UTF8_STRING ,
		NULL,
		0
	},
	{	/* T61 String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_T61_STRING ,
		NULL,
		0
	},
	{	/* Videotex String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_VIDEOTEX_STRING ,
		NULL,
		0
	},
	{	/* IA5String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_IA5_STRING ,
		NULL,
		0
	},
	{	/* Visible String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_VISIBLE_STRING ,
		NULL,
		0
	},
	{	/* GeneralString */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_GENERAL_STRING ,
		NULL,
		0
	},
	{	/* Universal String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_UNIVERSAL_STRING ,
		NULL,
		0
	},
	{	/* Teletex String */
		NH_PARSE_ROOT,
		NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT | NH_ASN1_TELETEX_STRING,
		NULL,
		0
	}
};


static NH_NODE_WAY pkibr_extension[] =
{
	{
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT | NH_ASN1_EXP_CONSTRUCTED_BIT,
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
		NH_ASN1_ANY_TAG_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_EXPLICIT_BIT,
		NULL,
		0
	},
	{	/* Value */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_CHOICE_BIT,
		pkibr_extension_value,
		ASN_NODE_WAY_COUNT(pkibr_extension_value)
	}
};



static unsigned int pkibr_subject_id_oid[]		= { 2, 16, 76, 1, 3, 1 }; /* subject_id: PF identidade civil                            */
static unsigned int pkibr_company_sponsor_name_oid[]	= { 2, 16, 76, 1, 3, 2 }; /* sponsor_name: PJ/Equipamento nome empresarial              */
static unsigned int pkibr_company_subject_id_oid[]	= { 2, 16, 76, 1, 3, 3 }; /* company_id: PJ/Equipamento registro CNPJ                   */
static unsigned int pkibr_company_sponsor_id_oid[]	= { 2, 16, 76, 1, 3, 4 }; /* sponsor_id: PJ/Equipamento identidade civil do responsavel */
static unsigned int pkibr_subject_te_id_oid[]		= { 2, 16, 76, 1, 3, 5 }; /* subject_te: PF registro eleitoral                          */
static unsigned int pkibr_subject_cei_id_oid[]		= { 2, 16, 76, 1, 3, 6 }; /* subject_cei: PF reigstro CEI                               */
static unsigned int pkibr_company_subject_cei_oid[]	= { 2, 16, 76, 1, 3, 7 }; /* company_cei: PJ registro CEI                               */
static unsigned int pkibr_company_name_oid[]		= { 2, 16, 76, 1, 3, 8 }; /* company_name: Equipamento nome empresarial                 */

#define NODE_IS_OTHER_NAME(_n)	(_n && _n->identifier && *_n->identifier == (NH_ASN1_CONSTRUCTED_BIT | NH_ASN1_CONTEXT | NH_ASN1_CT_TAG_0))

NH_FUNCTION(NH_RV, NH_parse_pkibr_extension)(_IN_ unsigned char *buffer, _IN_ size_t size, _OUT_ NH_PKIBR_EXTENSION *hHandler)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node, cur;
	NH_PKIBR_EXTENSION out = NULL;

	if (!buffer) return NH_INVALID_ARG;
	if (NH_FAIL(rv = NH_new_parser(buffer, size, 16, 128, &hParser))) return rv;
	if (NH_SUCCESS(rv = hParser->new_node(hParser->container, &node)))
	{
		node->identifier = (unsigned char*) buffer;
		hParser->root = node;
		rv = NHIX_parse_general_names(hParser, node);
	}
	if (NH_SUCCESS(rv))
	{
		node = node->child;
		while (NH_SUCCESS(rv) && node)
		{
			if (NODE_IS_OTHER_NAME(node))
			{
				rv = hParser->map_from(hParser, node, pkibr_extension, ASN_NODE_WAY_COUNT(pkibr_extension));
				if (NH_SUCCESS(rv)) rv = (cur = node->child) ? NH_OK : NH_UNEXPECTED_ENCODING;
				if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, cur);
				if (NH_SUCCESS(rv)) rv = (cur = cur->next) && (cur = cur->child) ? NH_OK : NH_UNEXPECTED_ENCODING;
				if (NH_SUCCESS(rv)){
					if(ASN_FOUND(NH_ASN1_OCTET_STRING, *cur->identifier))
						rv = hParser->parse_octetstring(hParser, cur);
					else  if(ASN_FOUND(NH_ASN1_PRINTABLE_STRING, *cur->identifier))
						rv = hParser->parse_string(cur);
					/*else rv = NH_UNEXPECTED_ENCODING;*/
				}
			}
			node = node->next;
		}
	}
	if (NH_SUCCESS(rv))
	{
		rv = (out = malloc(sizeof(NH_PKIBR_EXTENSION_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
		if (NH_SUCCESS(rv)) memset(out, 0, sizeof(NH_PKIBR_EXTENSION_STR));
		node = hParser->root->child;
		while (NH_SUCCESS(rv) && node)
		{
			if (NODE_IS_OTHER_NAME(node))
			{
				cur = node->child;
				if(cur->value && cur->next && cur->next->child && cur->next->child->value)
				{
					if (NH_match_oid(cur->value, cur->valuelen, pkibr_subject_id_oid, NHC_OID_COUNT(pkibr_subject_id_oid))) out->subject_id = cur->next->child;
					else if (NH_match_oid(cur->value, cur->valuelen, pkibr_company_sponsor_name_oid, NHC_OID_COUNT(pkibr_company_sponsor_name_oid))) out->sponsor_name = cur->next->child;
					else if (NH_match_oid(cur->value, cur->valuelen, pkibr_company_subject_id_oid, NHC_OID_COUNT(pkibr_company_subject_id_oid))) out->company_id = cur->next->child;
					else if (NH_match_oid(cur->value, cur->valuelen, pkibr_company_sponsor_id_oid, NHC_OID_COUNT(pkibr_company_sponsor_id_oid))) out->sponsor_id = cur->next->child;
					else if (NH_match_oid(cur->value, cur->valuelen, pkibr_subject_te_id_oid, NHC_OID_COUNT(pkibr_subject_te_id_oid))) out->subject_te = cur->next->child;
					else if (NH_match_oid(cur->value, cur->valuelen, pkibr_subject_cei_id_oid, NHC_OID_COUNT(pkibr_subject_cei_id_oid))) out->subject_cei = cur->next->child;
					else if (NH_match_oid(cur->value, cur->valuelen, pkibr_company_subject_cei_oid, NHC_OID_COUNT(pkibr_company_subject_cei_oid))) out->company_cei = cur->next->child;
					else if (NH_match_oid(cur->value, cur->valuelen, pkibr_company_name_oid, NHC_OID_COUNT(pkibr_company_name_oid))) out->company_name = cur->next->child;
				} /* Obtain the maximum amount of information.*/
				/*else rv = NH_UNEXPECTED_ENCODING;*/
			}
			node = node->next;
		}
	}
	if (NH_SUCCESS(rv))
	{
		out->hParser = hParser;
		*hHandler = out;
	}
	else
	{
		NH_release_parser(hParser);
		if (out) free(out);
	}
	return rv;
}

NH_FUNCTION(void, NH_release_pkibr_extension)(_INOUT_ NH_PKIBR_EXTENSION hHandler)
{
	if (hHandler)
	{
		NH_release_parser(hHandler->hParser);
		free (hHandler);
	}
}
