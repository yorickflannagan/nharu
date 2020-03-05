/**
 * @file pfx.h
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
#ifndef __PFX_H__
#define __PFX_H__

#include "pki-issue.h"

typedef struct NH_PFX_PARSER_STR				NH_PFX_PARSER_STR;
typedef NH_METHOD(NH_RV, NHFX_VERIFY_MAC)
(
	_IN_ NH_PFX_PARSER_STR*,				/* self */
	_IN_ char*							/* szSecret */
);
typedef NH_METHOD(NH_RV, NHFX_GET_BYTE_VALUE)
(
	_IN_ NH_PFX_PARSER_STR*,				/* self */
	_OUT_ unsigned char**,					/* ppBuffer */
	_OUT_ unsigned int*					/* puiBufLen */
);
typedef NH_METHOD(NH_RV, NHFX_GET_INT_VALUE)
(
	_IN_ NH_PFX_PARSER_STR*,				/* self */
	_OUT_ unsigned int*					/* puiBuffer */
);
struct NH_PFX_PARSER_STR
{
	NH_ASN1_PARSER_HANDLE	hParser;			/* ASN.1 parser */
	NHFX_VERIFY_MAC		verify_mac;			/* Verify HMAC, if present */
	NHFX_GET_BYTE_VALUE	contents;			/* Get eContents of data ContentInfo */
	NHFX_GET_BYTE_VALUE	salt;				/* Get HMAC salt, if present */
	NHFX_GET_INT_VALUE	iterations;			/* Get iteration count, if present */
};
typedef struct NH_PFX_PARSER_STR*				NH_PFX_PARSER;


typedef struct NH_AUTH_SAFE_PARSER_STR			NH_AUTH_SAFE_PARSER_STR;
typedef NH_METHOD(NH_RV, NHFX_GET_N_VALUE)
(
	_IN_ NH_AUTH_SAFE_PARSER_STR*,			/* self */
	_IN_ int,							/* n */
	_OUT_ unsigned char**,					/* ppBuffer */
	_OUT_ unsigned int*					/* puiBufLen */
);
struct NH_AUTH_SAFE_PARSER_STR
{
	NH_ASN1_PARSER_HANDLE	hParser;			/* ASN.1 parser */
	int				count;			/* Content info count */
	NHFX_GET_N_VALUE		contents;			/* Get the nth content info value */
};
typedef struct  NH_AUTH_SAFE_PARSER_STR*			NH_AUTH_SAFE_PARSER;





EXTERN unsigned int pfx_keyBag_oid[];
EXTERN unsigned int pfx_pkcs8ShroudedKeyBag_oid[];
EXTERN unsigned int pfx_certBag_oid[];
EXTERN unsigned int pfx_crlBag_oid[];
EXTERN unsigned int pfx_secretBag_oid[];
EXTERN unsigned int pfx_safeContentsBag_oid[];


#if defined(__cplusplus)
extern "C" {
#endif


NH_FUNCTION(NH_RV, NHFX_new_pfx_parser)
(									/* Parse given DER encoded PKCS #12 document */
	_IN_ unsigned char*,					/* pBuffer */
	_IN_ unsigned int,					/* uiBufLen */
	_OUT_ NH_PFX_PARSER*					/* hOut */
);
NH_FUNCTION(void, NHFX_delete_pfx_parser)
(									/* Release PKCS #12 parser */
	_INOUT_ NH_PFX_PARSER					/* hPfx */
);
NH_FUNCTION(NH_RV, NHFX_new_authenticated_safe_parser)
(									/* Parse giver DER encoded PKCS #12 data contents */
	_IN_ unsigned char*,					/* pBuffer */
	_IN_ unsigned int,					/* uiBufLen */
	_OUT_ NH_AUTH_SAFE_PARSER*				/* hOut */
);
NH_FUNCTION(void, NHFX_delete_authenticated_safe_parser)
(									/* Release PKCS #12 data contents parser */
	_INOUT_ NH_AUTH_SAFE_PARSER				/* hAuth*/
);

#if defined(__cplusplus)
}
#endif

#endif /* __PFX_H__ */