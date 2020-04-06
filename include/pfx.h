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


/**
 * @brief PFX
 * 
 */
typedef struct NH_PDU_PARSER_STR				NH_PDU_PARSER_STR;
typedef NH_METHOD(NH_RV, NHFX_VERIFY_MAC)
(
	_IN_ NH_PDU_PARSER_STR*,				/* self */
	_IN_ char*							/* szSecret */
);
typedef NH_METHOD(NH_RV, NHFX_GET_BYTE_VALUE)
(
	_IN_ NH_PDU_PARSER_STR*,				/* self */
	_OUT_ unsigned char**,					/* ppBuffer */
	_OUT_ unsigned int*					/* puiBufLen */
);
typedef NH_METHOD(NH_RV, NHFX_GET_INT_VALUE)
(
	_IN_ NH_PDU_PARSER_STR*,				/* self */
	_OUT_ unsigned int*					/* puiBuffer */
);
#define PBE_KEY_LEN						20
struct NH_PDU_PARSER_STR					/* PDU parser */
{
	unsigned char*			pKey;			/* PBE key */
	NH_ASN1_PARSER_HANDLE		hParser;		/* ASN.1 parser */
	NHFX_VERIFY_MAC			verify_mac;		/* Verify HMAC, if present */
	NHFX_GET_BYTE_VALUE		contents;		/* Get eContents of data ContentInfo */
	NHFX_GET_BYTE_VALUE		salt;			/* Get HMAC salt, if present */
	NHFX_GET_INT_VALUE		iterations;		/* Get iteration count, if present */
};
typedef struct NH_PDU_PARSER_STR*				NH_PDU_PARSER;


/**
 * @brief AuthenticatedSafe
 * 
 */
typedef struct NH_AUTH_SAFE_PARSER_STR			NH_AUTH_SAFE_PARSER_STR;
typedef NH_METHOD(NH_ASN1_PNODE, NHFX_NEXT_CONTENT)
(
	_IN_ NH_AUTH_SAFE_PARSER_STR*,			/* self */
	_IN_ NH_ASN1_PNODE,					/* pCurrent */
	_OUT_ unsigned char**,					/* ppBuffer */
	_OUT_ unsigned int*					/* puiBufLen */
);
struct NH_AUTH_SAFE_PARSER_STR				/* AuthenticatedSafe parser */
{
	NH_ASN1_PARSER_HANDLE		hParser;		/* ASN.1 parser */
	NHFX_NEXT_CONTENT			next;			/* Get the next content info value */
};
typedef struct  NH_AUTH_SAFE_PARSER_STR*			NH_AUTH_SAFE_PARSER;


/**
 * @brief PKCS12BagSet
 * 
 */
typedef enum PFX_SAFE_BAG					/* PKCS12BagSet BAG-TYPE */
{
	PFX_keyBag,
	PFX_pkcs8ShroudedKeyBag,
	PFX_certBag,
	PFX_crlBag,
	PFX_secretBag,
	PFX_safeContentsBag

} PFX_SAFE_BAG;
typedef struct NH_RSA_PRIVATE_KEY_STR			/* RSA private key */
{
	NH_BLOB			modulus;			/* Big Integer modulus n */
	NH_BLOB			pubExponent;		/* Big Integer public exponent e */
	NH_BLOB			privExponent;		/* Big Integer private exponent d */
	NH_BLOB			primeP;			/* Big Integer prime p */
	NH_BLOB			primeQ;			/* Big Integer prime q */
	NH_BLOB			exponent1;			/* Big Integer private exponent d modulo p-1 */
	NH_BLOB			exponent2;			/* Big Integer private exponent d modulo q-1 */
	NH_BLOB			coefficient;		/* Big Integer CRT coefficient q mod p */

} NH_RSA_PRIVATE_KEY_STR, *NH_RSA_PRIVATE_KEY;
typedef union NH_PRIVKEY_CONTENTS
{
	NH_RSA_PRIVATE_KEY_STR	rsa;				/* RSA private key */
	/* TODO */

} NH_PRIVKEY_CONTENTS;
typedef struct NH_KEYBAG_STR					/* keyBag */
{
	NH_OID_STR				algorithm;		/* Private Key Algorithm identifier */
	NH_BLOB				privkey;		/* DER encoded private key */
	NH_PRIVKEY_CONTENTS		contents;

} NH_KEYBAG_STR, *NH_KEYBAG;
typedef struct NH_SHROUDEDKEYBAG_STR			/* pkcs8ShroudedKeyBag */
{
	NH_OID_STR				algorithm;		/* encryption algorithm identifier */
	NH_BLOB				iv;			/* encryption initialization vector */
	int					iCount;		/* iteration count */
	NH_BLOB				contents;		/* encrypted data contents */

} NH_SHROUDEDKEYBAG_STR, *NH_SHROUDEDKEYBAG;
typedef struct NH_CERTBAG_STR					/* certBag */
{
	NH_OID_STR				certType;		/* certId */
	NH_BLOB				contents;		/* OCTET STRING contents */

} NH_CERTBAG_STR, *NH_CERTBAG;

typedef union NH_BAG_TYPE
{
	NH_KEYBAG				keyBag;
	NH_SHROUDEDKEYBAG			pkcs8ShroudedKeyBag;
	NH_CERTBAG				certBag;

} NH_BAG_TYPE;
typedef struct NH_SAFE_BAG_STR				NH_SAFE_BAG_STR;
struct NH_SAFE_BAG_STR						/* SafeBag */
{
	NH_OID_STR				bagType;		/* bagId */
	NH_BLOB				contents;		/* bagValue */
	PFX_SAFE_BAG			type;			/* enum */
	NH_BAG_TYPE				bag;			/* the bag itself */
	NH_SAFE_BAG_STR*			next;			/* next bag */

};
typedef struct NH_SAFE_BAG_STR*				NH_SAFE_BAG;


/**
 * @brief SafeContents
 * 
 */
typedef struct NH_SAFE_CONTENTS_PARSER_STR		NH_SAFE_CONTENTS_PARSER_STR;
struct NH_SAFE_CONTENTS_PARSER_STR
{
	NH_ASN1_PARSER_HANDLE		hParser;
	NH_SAFE_BAG				bagSet;
};
typedef struct NH_SAFE_CONTENTS_PARSER_STR*		NH_SAFE_CONTENTS_PARSER;




typedef struct NH_PFX_PARSER_STR				NH_PFX_PARSER_STR;
struct NH_PFX_PARSER_STR					/* PKCS #12 parser */
{
	NH_CARGO_CONTAINER		hContainer;		/* Memory management handler */
	NH_PDU_PARSER			hPDU;			/* PDU parsing handler */
	NH_AUTH_SAFE_PARSER		hAuth;		/* AuthenticatedSafe */
	NH_SAFE_CONTENTS_PARSER		hSafe;		/* SafeContents */
};
typedef NH_PFX_PARSER_STR*					NH_PFX_PARSER;



#if defined(__cplusplus)
extern "C" {
#endif

NH_FUNCTION(NH_RV, NHFX_new_pfx_parser)
(
	_IN_ unsigned char*,					/* pBuffer */
	_IN_ unsigned int,					/* uiBufLen */
	_IN_ char*,							/* szSecret */
	_OUT_ NH_PFX_PARSER*					/* hParser */
);
NH_FUNCTION(void, NHFX_delete_pfx_parser)
(
	_INOUT_ NH_PFX_PARSER					/* hParser*/
);

#if defined(__cplusplus)
}
#endif

#endif /* __PFX_H__ */
