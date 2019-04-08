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


typedef struct  NH_CREQUEST_PARSER_STR			NH_CREQUEST_PARSER_STR;
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
 * Implements basic operations on RFC 2986 documents
 * PKCS #10: Certification Request Syntax Specification
 * 
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
 *  AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
 *  	algorithm ALGORITHM.&id({IOSet}),
 *  	parameters ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
 *  }
 * 
 */
struct NH_CREQUEST_PARSER_STR
{
	NH_ASN1_PARSER_HANDLE	hParser;			/**< ASN.1 parser */

	NH_NAME_NODE		subject;			/**< Request subject */
	NH_ASN1_PNODE		subjectPKInfo;		/**< Request publick key info */
	CR_VRFY_FUNCTION		verify;			/**< Verify signature */
};
typedef NH_CREQUEST_PARSER_STR				*NH_CREQUEST_PARSER;

/**
 * @brief An Object Identifier
 * 
 */
typedef struct NH_OID_STR
{
	unsigned int*	pIdentifier;			/**< OID itself */
	size_t		uCount;				/**< OID count */

} NH_OID_STR, *NH_OID;

/**
 * @brief X.500 Name
 * 
 */
typedef struct NH_NAME_STR
{
	NH_OID		pOID;					/**< Object identifier */
	char*			szValue;				/**< Object value (must be NULL terminated) */

} NH_NAME_STR, *NH_NAME;

/**
 * @brief ASN.1 OCTET STRING type alias
 * 
 */
typedef struct NH_BLOB						NH_OCTET_SRING;

/**
 * @brief General Name Other Name
 * 
 */
typedef struct NH_NAME_STR*					NH_OTHER_NAME;


typedef struct  NH_TBSCERT_ENCODER_STR			NH_TBSCERT_ENCODER_STR;
/**
 * @brief NH_TBSCERT_ENCODER->set_version
 * 
 * PURPOSE:
 * 	Sets X.509 certificate version number
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ unsigned int uVersion: version number { v1(0), v2(1), v3(2) }
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETVER)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ unsigned int);

/**
 * @brief NH_TBSCERT_ENCODER->set_serial
 * 
 * PURPOSE:
 * 	Sets X.509 certificate serial number
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param __IN_ NH_BIG_INTEGER *pSerial: serial number (little endian)
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETSERIAL)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_BIG_INTEGER*);

/**
 * @brief NH_TBSCERT_ENCODER->set_sign_alg
 * 
 * PURPOSE:
 * 	Sets X.509 certificate signature algorithm
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_OID pOID: signature algorithm object identifier
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETSIGNALG)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OID);

/**
 * @brief NH_TBSCERT_ENCODER->set_issuer
 * 
 * PURPOSE:
 * 	Sets X.509 certificate issuer
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_NAME *pIssuer: certificate issuer
 * 	@param _IN_ size_t ulCount: pIssuer count
 * 
 * RESULT
 * 	@return
 * 
 */
/**
 * @brief NH_TBSCERT_ENCODER->set_subject
 * 
 * PURPOSE:
 * 	Sets X.509 certificate suject
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_NAME *pSubject: certificate subject
 * 	@param _IN_ size_t ulCount: pSubject count
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETNAME)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_NAME, _IN_ size_t);

/**
 * @brief NH_TBSCERT_ENCODER->set_validity
 * 
 * PURPOSE:
 * 	Sets X.509 certificate validity
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ char *szNotBefore: notBefore instant in form YYYYMMDDHHSSZ (must be NULL terminated)
 * 	@param _IN_ char *szNotAfter: notAfter instant in form YYYYMMDDHHSSZ (must be NULL terminated)
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETVALIDITY)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ char*, _IN_ char*);

/**
 * @brief NH_TBSCERT_ENCODER->set_pubkey
 * 
 * PURPOSE:
 * 	Sets X.509 certificate subject public key info
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_NH_ASN1_PNODE pPubkey: subjectPublicKeyInfo (extracted from PKCS#10)
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETPUBKEY)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_ASN1_PNODE);

/**
 * @brief NH_TBSCERT_ENCODER->set_aki
 * 
 * PURPOSE:
 * 	Sets X.509 certificate authority key identifier extension
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_OCTET_SRING pValue: extension value
 * 
 * RESULT
 * 	@return
 * 
 */
/**
 * @brief NH_TBSCERT_ENCODER->set_ski
 * 
 * PURPOSE:
 * 	Sets X.509 certificate subject key identifier extension
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_OCTET_SRING pValue: extension value
 * 
 * RESULT
 * 	@return
 * 
 */
/**
 * @brief NH_TBSCERT_ENCODER->set_key_usage
 * 
 * PURPOSE:
 * 	Sets X.509 certificate key usage extension
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_OCTET_SRING pValue: extension value
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETOCTET)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OCTET_SRING*);

/**
 * @brief NH_TBSCERT_ENCODER->set_subject_altname
 * 
 * PURPOSE:
 * 	Sets X.509 certificate subject alternative name extension
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_OTHER_NAME *pValue: extension value
 * 	@param _IN_ size_t ulCount: pValue count.
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETSUBALTNAME)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OTHER_NAME*, _IN_ size_t);

/**
 * @brief NH_TBSCERT_ENCODER->set_basic_constraints
 * 
 * PURPOSE:
 * 	Sets X.509 certificate basic constraints extension
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ int isCA: TRUE if this is a CA certificate
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETBASCONSTRAINT)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ int);

/**
 * @brief NH_TBSCERT_ENCODER->set_extkey_usage
 * 
 * PURPOSE:
 * 	Sets X.509 certificate extended key usage extension
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_OID *pValues: extension value
 * 	@param _IN_ size_t ulCount: pValues count.
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETEXTKEYUSAGE)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OID*, _IN_ size_t);

/**
 * @brief NH_TBSCERT_ENCODER->set_cdp
 * 
 * PURPOSE:
 * 	Sets X.509 certificate CRL distribution points extension
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ char *pValues: double-null-terminated string of URLs.
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETCDP)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ char*);

/**
 * @brief NH_TBSCERT_ENCODER->set_extension
 * 
 * PURPOSE:
 * 	Sets X.509 certificate extension
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
 * 	@param _IN_ NH_OID pOID: extension identifier
 * 	@param _IN_ int isCritical: critical extension indicator
 * 	@param _IN_ NH_OCTET_SRING *pValue: extension value
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_TBS_SETEXT)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OID, _IN_ int, _IN_ NH_OCTET_SRING*);

/**
 * @brief X.509 TBSCertificate Encoder
 * 
 * 	Warning: encoder is not thread safe
 * 
 */
struct  NH_TBSCERT_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE	hEncoder;			/**< ASN.1 encoder */

	NH_TBS_SETVER		set_version;		/**< Set certificate version number */
	NH_TBS_SETSERIAL		set_serial;			/**< Set certificate serial number */
	NH_TBS_SETSIGNALG		set_sign_alg;		/**< Set certificate signature algorithm */
	NH_TBS_SETNAME		set_issuer;			/**< Set certificate issuer */
	NH_TBS_SETNAME		set_subject;		/**< Set certificate subject */
	NH_TBS_SETVALIDITY	set_validity;		/**< Set certificage validity */
	NH_TBS_SETPUBKEY		set_pubkey;			/**< Set subject public key info */
	NH_TBS_SETOCTET		set_aki;			/**< Set authority key identifier extension */
	NH_TBS_SETOCTET		set_ski;			/**< Set subject key identifier extension */
	NH_TBS_SETOCTET		set_key_usage;		/**< Set key usage extension */
	NH_TBS_SETSUBALTNAME	set_subject_altname;	/**< Set subject alternative name extension */
	NH_TBS_SETBASCONSTRAINT	set_basic_constraints;	/**< Set basic constraint extension */
	NH_TBS_SETEXTKEYUSAGE	set_extkey_usage;		/**< Set extended key usage extension */
	NH_TBS_SETCDP		set_cdp;			/**< Set CRL distribution points extension */
	NH_TBS_SETEXT		set_extension;		/**< Set certificate extension */
};
typedef struct  NH_TBSCERT_ENCODER_STR			*NH_TBSCERT_ENCODER;


typedef struct NH_CERT_ENCODER_STR				NH_CERT_ENCODER_STR;
/**
 * @brief NH_CERT_ENCODER->sign
 * 
 * PURPOSE:
 * 	Signs a complete TBSCertificate 
 * 
 * ARGUMENTS:
 * 	@param _IN_ NH_CERT_ENCODER_STR *hHandler: certificate encoder handler
 * 	@param _IN_ NH_TBSCERT_ENCODER hCert: TBSCertificate encoder handler
 * 	@param _IN_ CK_MECHANISM_TYPE mechanism: PKCS#11 signature mechanism constant
 * 	@param _IN_ NH_CMS_SIGN_FUNCTION callback: signature callback function
 * 	@param _IN_ void *pParams: parameters to callback function.
 * 
 * RESULT
 * 	@return
 * 
 */
typedef NH_METHOD(NH_RV, NH_CERT_SIGN)(_IN_ NH_CERT_ENCODER_STR*, _IN_ NH_TBSCERT_ENCODER, _IN_ CK_MECHANISM_TYPE, _IN_ NH_CMS_SIGN_FUNCTION, _IN_ void*);
/**
 * @brief X.509 Certificate encoder
 * 
 * 	Warning: encoder is not thread safe
 * 
 */
struct NH_CERT_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE	hEncoder;			/**< ASN.1 encoder */
	NH_CERT_SIGN		sign;				/**< Signs TBSCertificate encoded data */
};
typedef NH_CERT_ENCODER_STR					*NH_CERT_ENCODER;

#if defined(__cplusplus)
extern "C" {
#endif

/**NH_TBSCERT_ENCODER_STR
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

/**
 * @brief Creates a new TBSCertificate encoder
 * 
 * ARGUMENTS
 * 	@param _OUT_ NH_TBSCERT_ENCODER *hHandler: encoder handler
 * 
 */
NH_FUNCTION(NH_RV, NH_new_tbscert_encoder)(_OUT_ NH_TBSCERT_ENCODER*);

/**
 * @brief Releases TBSCertificate encoder
 * 
 * ARGUMENTS:
 * 	@param _INOUT_ NH_TBSCERT_ENCODER hHandler: the handler
 * 
 */
NH_FUNCTION(void, NH_delete_tbscert_encoder)(_INOUT_ NH_TBSCERT_ENCODER);

/**
 * @brief Creates a new Certificate encoder
 * 
 * ARGUMENTS
 * 	@param _OUT_ NH_CERT_ENCODER *hHandler: encoder handler
 * 
 */
NH_FUNCTION(NH_RV, NH_new_cert_encoder)(_OUT_ NH_CERT_ENCODER*);

/**
 * @brief Releases Certificate encoder
 * 
 * ARGUMENTS:
 * 	@param _INOUT_ NH_CERT_ENCODER hHandler: the handler
 * 
 */
NH_FUNCTION(void, NH_delete_cert_encoder)(_INOUT_ NH_CERT_ENCODER);

#if defined(__cplusplus)
}
#endif


#endif	/* __PKI_ISSUE_H__ */