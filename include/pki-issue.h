/**
 * @brief 
 *  **********************************************************
 *
 * AUTHOR
 *	Copyleft (C) 2019 by The Crypthing Initiative
 *
 * PURPOSE
 *	RFC 2986 parsing and certificate issue implementation
 *
 * NOTES
 * 	https://tools.ietf.org/html/rfc2986
 * 	https://tools.ietf.org/html/rfc5280
 * 	https://tools.ietf.org/html/rfc6818
 *
 * SEE ALSO
 *
 ******
 *
 *  ***********************************************************
 */
#ifndef __PKI_ISSUE_H__
#define __PKI_ISSUE_H__


#include "cms.h"


typedef struct  NH_CREQUEST_PARSER_STR		NH_CREQUEST_PARSER_STR;
/** 
 * @brief NH_CREQUEST_PARSER/verify
 *
 * PURPOSE
 *	Verifies PKCS#10 signature
 *
 * ARGUMENTS
 *	@param _IN_ NH_CREQUEST_PARSER_STR *self: the handler
 *
 * RESULT
 * 	@return
 * 
 * 
 * 	@see https://tools.ietf.org/html/rfc2986
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, CR_VRFY_FUNCTION)(_IN_ NH_CREQUEST_PARSER_STR*);

/**
 * @brief Certificate request parser handler
 * 
 * 	Warning: parser is not thread safe
 * 
 */
struct NH_CREQUEST_PARSER_STR
{
	NH_ASN1_PARSER_HANDLE	hParser;		/**< ASN.1 parser */

	NH_NAME_NODE		subject;		/**< Request subject */
	NH_ASN1_PNODE		subjectPKInfo;	/**< Request publick key info */
	CR_VRFY_FUNCTION		verify;		/**< Verify signature */
};
typedef NH_CREQUEST_PARSER_STR			*NH_CREQUEST_PARSER;

/**
 * @brief An Object Identifier
 * 
 */
typedef struct NH_OID_STR
{
	unsigned int*	pIdentifier;	/**< OID itself */
	size_t		uCount;		/**< OID count */

} NH_OID_STR, *NH_OID;

/**
 * @brief X.500 Name
 * 
 */
typedef struct NH_NAME_STR
{
	NH_OID		pOID;			/**< Object identifier */
	char*			szName;		/**< Name value (must be NULL terminated) */

} NH_NAME_STR, *NH_NAME;


typedef struct  NH_CERTIFICATE_ENCODER_STR	NH_CERTIFICATE_ENCODER_STR;
/**
 * @brief NH_CERTIFICATE_ENCODER->set_version
 * 
 * PURPOSE:
 * 	Sets X.509 certificate version number
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_CERTIFICATE_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ unsigned int uVersion: version number { v1(0), v2(1), v3(2) }
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_CENC_SETVER)(_IN_ NH_CERTIFICATE_ENCODER_STR*, _IN_ unsigned int);

/**
 * @brief NH_CERTIFICATE_ENCODER->set_serial
 * 
 * PURPOSE:
 * 	Sets X.509 certificate serial number
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_CERTIFICATE_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param __IN_ NH_BIG_INTEGER *pSerial: serial number (little endian)
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_CENC_SETSERIAL)(_IN_ NH_CERTIFICATE_ENCODER_STR*, _IN_ NH_BIG_INTEGER*);

/**
 * @brief NH_CERTIFICATE_ENCODER->set_sign_alg
 * 
 * PURPOSE:
 * 	Sets X.509 certificate signature algorithm
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_CERTIFICATE_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_OID pOID: signature algorithm object identifier
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_CENC_SETSIGNALG)(_IN_ NH_CERTIFICATE_ENCODER_STR*, _IN_ NH_OID);

/**
 * @brief NH_CERTIFICATE_ENCODER->set_issuer/set_subject
 * 
 * PURPOSE:
 * 	Sets X.509 certificate issuer or subject
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_CERTIFICATE_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_NAME pIssuer: certificate issuer/subject
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_CENC_SETNAME)(_IN_ NH_CERTIFICATE_ENCODER_STR*, _IN_ NH_NAME);

/**
 * @brief NH_CERTIFICATE_ENCODER->set_validity
 * 
 * PURPOSE:
 * 	Sets X.509 certificate validity
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_CERTIFICATE_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ char *szNotBefore: notBefore instant in form YYYYMMDDHHSSZ (must be NULL terminated)
 * 	@param _IN_ char *szNotAfter: notAfter instant in form YYYYMMDDHHSSZ (must be NULL terminated)
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_CENC_SETVALIDITY)(_IN_ NH_CERTIFICATE_ENCODER_STR*, _IN_ char*, _IN_ char*);

/**
 * @brief NH_CERTIFICATE_ENCODER->set_pubkey
 * 
 * PURPOSE:
 * 	Sets X.509 certificate subject public key info
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_CERTIFICATE_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_NH_ASN1_PNODE pPubkey: subjectPublicKeyInfo (extracted from PKCS#10)
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_CENC_SETPUBKEY)(_IN_ NH_CERTIFICATE_ENCODER_STR*, _IN_ NH_ASN1_PNODE);

/**
 * @brief X.509 Certificate Encoder
 * 
 * 	Warning: encoder is not thread safe
 * 
 */
struct  NH_CERTIFICATE_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE	hEncoder;		/**< ASN.1 encoder */

	NH_CENC_SETVER		set_version;	/**< Set certificate version number */
	NH_CENC_SETSERIAL		set_serial;		/**< Set certificate serial number */
	NH_CENC_SETSIGNALG	set_sign_alg;	/**< Set certificate signature algorithm */
	NH_CENC_SETNAME		set_issuer;		/**< Set certificate issuer */
	NH_CENC_SETNAME		set_subject;	/**< Set certificate subject */
	NH_CENC_SETVALIDITY	set_validity;	/**< Set certificage validity */
	NH_CENC_SETPUBKEY		set_pubkey;		/**< Set subject public key info */
};
typedef struct  NH_CERTIFICATE_ENCODER_STR	*NH_CERTIFICATE_ENCODER;


#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Parses specified certificate request
 * 
 * ARGUMENTS
 * 	@param _IN_ unsigned char *pBuffer: DER encoded certificate request buffer
 * 	@param _IN_ size_t ulBuflen: size of buffer
 * 	@param _OUT_ NH_CREQUEST_PARSER *hHandle: handler to certificate request parser
 */
NH_FUNCTION(NH_RV, NH_parse_cert_request)(_IN_ unsigned char*, _IN_ size_t, _OUT_ NH_CREQUEST_PARSER*);

/**
 * @brief Releases certificate request parser
 * 
 * ARGUMENTS
 * 	@param _INOUT_ NH_CREQUEST_PARSER *hHandle: handler to certificate request parser
 */
NH_FUNCTION(void, NH_release_cert_request)(_INOUT_ NH_CREQUEST_PARSER*);


#if defined(__cplusplus)
}
#endif


#endif	/* __PKI_ISSUE_H__ */