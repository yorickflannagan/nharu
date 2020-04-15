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
 * @brief PKCS12BagSet
 * 
 */
typedef enum PFX_SAFE_BAG					/* PKCS12BagSet BAG-TYPE */
{
	PFX_keyBag = 1,
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
	NH_BLOB				salt;			/* encryption salt */
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
	NH_SAFE_BAG_STR*			previous;		/* previous bag */

};
typedef struct NH_SAFE_BAG_STR*				NH_SAFE_BAG;


/**
 * @brief PFX
 * 
 */
EXTERN unsigned int pkcs9_x509_certificate_oid[];
#define PKCS9_X509_CERTIFICATE_OID_COUNT			8
#define PBE_MAC_KEY_LEN						20
#define PBE_DES_KEY_LEN						24
#define PBE_DES_KEY_IV_LEN					8
typedef struct NH_PFX_QUERY_STR				/* Bag cursor for queries */
{
	PFX_SAFE_BAG			bagType;		/* Input: bag type to query */
	unsigned int			uiCurrent;		/* Internal: current bag */
	unsigned int			uiCount;		/* Internal: found bags */
	NH_SAFE_BAG				pResult;		/* Output: current bag returned, if any */

} NH_PFX_QUERY_STR, *NH_PFX_QUERY;
#define NH_PFX_INIT_QUERY(_val)				{ _val, 0, 0, NULL }

typedef struct NH_PFX_PARSER_STR				NH_PFX_PARSER_STR;
typedef NH_METHOD(NH_RV, NHFX_QUERY)
(
	_IN_ NH_PFX_PARSER_STR*,				/* self */
	_INOUT_ NH_PFX_QUERY					/* pQuery */
);
typedef NH_METHOD(NH_RV, NHFX_UNPACK_SHROUDED)
(
	_IN_ NH_PFX_PARSER_STR*,				/* self */
	_IN_ NH_SAFE_BAG,						/* pBag */
	_IN_ char*,							/* szSecret */
	_INOUT_ NH_BLOB*						/* pPlaintext */
);
typedef NH_METHOD(NH_RV, NHFX_PARSE_KEY)
(
	_IN_ NH_BLOB*,						/* pKey */
	_OUT_ NH_ASN1_PARSER_HANDLE*				/* hOut */
);
struct NH_PFX_PARSER_STR					/* PKCS #12 parser */
{
	NH_CARGO_CONTAINER		hContainer;		/* Memory management handler */
	NH_BLOB				salt;			/* Encryption salt */
	int					iterations;		/* PBE iteration count */
	NH_SAFE_BAG				pBagSet;		/* PKCS12BagSet */
	NHFX_QUERY				next_bag;		/* Get next bag in a query */
	NHFX_UNPACK_SHROUDED		unpack_key;		/* Decrypt shrouded key bag contents*/
	NHFX_PARSE_KEY			parse_privkey;	/* Parse RFC 5208 PrivateKeyInfo */
	NHFX_PARSE_KEY			parse_rsa_key;	/* Parse RFC 8017 RSAPrivateKey */
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
