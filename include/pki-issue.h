/**
 * @brief Certificate Issuing
 *
 * @author Copyleft (C) 2019 by The Crypthing Initiative
 * RFC 2986 parsing and certificate issue implementation
 * @see https://tools.ietf.org/html/rfc2986
 * @see https://tools.ietf.org/html/rfc5280
 * @see https://tools.ietf.org/html/rfc6818
 *
 */
#ifndef __PKI_ISSUE_H__
#define __PKI_ISSUE_H__


#include "cms.h"


typedef struct  NH_CREQUEST_PARSER_STR			NH_CREQUEST_PARSER_STR;
typedef NH_METHOD(NH_RV, CR_VRFY_FUNCTION)(_IN_ NH_CREQUEST_PARSER_STR*);
/**
 * @brief Certificate request parser handler
 * <em>Warning: parser is not thread safe</em>
 * <p>
 * Implements basic operations on RFC 2986 documents<br>
 * PKCS #10: Certification Request Syntax Specification
 * </p>
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
 *  AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
 *  	algorithm ALGORITHM.&id({IOSet}),
 *  	parameters ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
 *  }
 * </pre>
 * @see https://tools.ietf.org/html/rfc2986
 */
struct NH_CREQUEST_PARSER_STR
{
	NH_ASN1_PARSER_HANDLE	hParser;			/**< ASN.1 parser */

	NH_NAME_NODE		subject;			/**< Request subject */
	NH_ASN1_PNODE		subjectPKInfo;		/**< Request publick key info */
	/** 
	 * @brief Verifies PKCS#10 signature
	 * @param NH_CREQUEST_PARSER_STR *self: the handler
	 * @return
	 * 	NH_UNEXPECTED_ENCODING
	 * 	NH_UNSUPPORTED_MECH_ERROR
	 * 	NH_ISSUE_INVALID_SIG_ERROR
	 *
	 */
	CR_VRFY_FUNCTION		verify;
};
typedef NH_CREQUEST_PARSER_STR				*NH_CREQUEST_PARSER;


/** @brief An Object Identifier */
typedef struct NH_OID_STR
{
	unsigned int*		pIdentifier;		/**< OID itself */
	size_t			uCount;			/**< OID count */

} NH_OID_STR, *NH_OID;
/** @brief X.500 Name */
typedef struct NH_NAME_STR
{
	NH_OID			pOID;				/**< Object identifier */
	char*				szValue;			/**< Object value (must be NULL terminated) */

} NH_NAME_STR, *NH_NAME;
typedef struct NH_BLOB						NH_OCTET_SRING;	/**< ASN.1 OCTET STRING type alias */
typedef struct NH_NAME_STR*					NH_OTHER_NAME;	/**< General Name Other Name */


typedef struct NH_CREQUEST_ENCODER_STR			NH_CREQUEST_ENCODER_STR;
typedef NH_METHOD(NH_RV, NH_CR_SETVER)(_INOUT_ NH_CREQUEST_ENCODER_STR*, _IN_ unsigned int);
typedef NH_METHOD(NH_RV, NH_CR_SETNAME)(_INOUT_ NH_CREQUEST_ENCODER_STR*, _IN_ NH_NAME*, _IN_ size_t);
typedef NH_METHOD(NH_RV, NH_CR_SETPUBKEY)(_INOUT_ NH_CREQUEST_ENCODER_STR*, _IN_ NH_RSA_PUBKEY_HANDLER);
typedef NH_METHOD(NH_RV, NH_CR_SIGN)(_INOUT_ NH_CREQUEST_ENCODER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ NH_CMS_SIGN_FUNCTION, _IN_ void*);
typedef NH_METHOD(NH_RV, NH_CR_ENCODE)(_IN_ NH_CREQUEST_ENCODER_STR*, _OUT_ unsigned char*, _INOUT_ size_t*);
/**
 * @brief Certificate request encoder
 * <em>Warning: encoder is not thread safe</em>
 * @see https://tools.ietf.org/html/rfc2986
 * 
 */
struct NH_CREQUEST_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE	hRequestInfo;	/**< ASN.1 CertificationRequestInfo encoder */
	NH_ASN1_ENCODER_HANDLE	hRequest;		/**< ASN.1 CertificationRequest encoder */
	int				fields;		/**< Well formed request flag */
	/**
	 * @brief Sets certificate request version
	 * @param NH_CREQUEST_ENCODER_STR hEncoder: handler to encoder
	 * @param unsigned int c: version number { v1(0) } (v1,...)
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_CR_SETVER		put_version;
	/**
	 * @brief Sets certificate request suject distinguished name
	 * @param NH_CREQUEST_ENCODER_STR *hEncoder: handler to encoder
	 * @param NH_NAME *pSubject: subject distinguished name
	 * @param size_t ulCount: pSubject count
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_CR_SETNAME		put_subject;
	/**
	 * @brief Sets certificate request subject public key info
	 * @param NH_CREQUEST_ENCODER_STR *hEncoder: handler to encoder
	 * @param NH_RSA_PUBKEY_HANDLER pPubkey: RSA public key handler
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_CR_SETPUBKEY		put_pubkey;
	/**
	 * @brief Signs a certificate request info
	 * @param NH_CREQUEST_ENCODER_STR *hEncoder: handler to encoder
	 * @param CK_MECHANISM_TYPE mechanism: PKCS#11 signature mechanism constant
	 * @param NH_CMS_SIGN_FUNCTION callback: signature callback function
	 * @param void *pParams: parameters to callback function.
	 * @return
	 * 	NH_UNSUPPORTED_MECH_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_CANNOT_SAIL
	 * 	encoding type errors
	 */
	NH_CR_SIGN			sign;
	/**
	 * @brief Encodes this signed certificate request
	 * @param NH_CREQUEST_ENCODER_STR *hEncoder: handler to encoder
	 * @param unsigned char *pBuffer: output buffer
	 * @param size_t *ulSize: size of pBuffer; if pBuffer is NULL, returns required buffer size;
	 * @return
	 * 	NH_ISSUE_INCOMPLETEOB_ERROR
	 * 	NH_BUF_TOO_SMALL
	 * 	NH_INVALID_DER_TYPE
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_UNEXPECTED_ENCODING
	 */
	NH_CR_ENCODE		encode;
};
typedef struct NH_CREQUEST_ENCODER_STR			*NH_CREQUEST_ENCODER;



typedef struct  NH_TBSCERT_ENCODER_STR			NH_TBSCERT_ENCODER_STR;
typedef NH_METHOD(NH_RV, NH_TBS_SETVER)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ unsigned int);
typedef NH_METHOD(NH_RV, NH_TBS_SETSERIAL)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_BIG_INTEGER*);
typedef NH_METHOD(NH_RV, NH_TBS_SETSIGNALG)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OID);
typedef NH_METHOD(NH_RV, NH_TBS_SETNAME)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_NAME*, _IN_ size_t);
typedef NH_METHOD(NH_RV, NH_TBS_SETVALIDITY)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ char*, _IN_ char*);
typedef NH_METHOD(NH_RV, NH_TBS_SETPUBKEY)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_ASN1_PNODE);
typedef NH_METHOD(NH_RV, NH_TBS_SETOCTET)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OCTET_SRING*);
typedef NH_METHOD(NH_RV, NH_TBS_SETSUBALTNAME)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OTHER_NAME*, _IN_ size_t);
typedef NH_METHOD(NH_RV, NH_TBS_SETBASCONSTRAINT)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ int);
typedef NH_METHOD(NH_RV, NH_TBS_SETEXTKEYUSAGE)(_INOUT_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OID*, _IN_ size_t);
typedef NH_METHOD(NH_RV, NH_TBS_SETCDP)(_INOUT_ NH_TBSCERT_ENCODER_STR*, char*);
typedef NH_METHOD(NH_RV, NH_TBS_SETEXT)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OID, _IN_ int, _IN_ NH_OCTET_SRING*);
typedef NH_METHOD(NH_RV, NH_TBS_ENCODE)(_IN_ NH_TBSCERT_ENCODER_STR*, _OUT_ unsigned char*, _INOUT_ size_t*);
/**
 * @brief X.509 TBSCertificate Encoder
 * <em>Warning: encoder is not thread safe</em>
 * @see https://tools.ietf.org/html/rfc5280
 * 
 */
struct  NH_TBSCERT_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE	hHandler;			/**< ASN.1 encoder */
	int				fields;			/**< Fields bitmap (for validation) */
	/**
	 * @brief Sets X.509 certificate version number
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param unsigned int uVersion: version number { v1(0), v2(1), v3(2) }
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETVER		put_version;
	/**
	 * @brief Sets X.509 certificate serial number
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param __IN_ NH_BIG_INTEGER *pSerial: serial number (little endian)
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETSERIAL		put_serial;
	/**
	 * @brief Sets X.509 certificate signature algorithm
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OID pOID: signature algorithm object identifier
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETSIGNALG		put_sign_alg;
	/**
	 * @brief Sets X.509 certificate issuer
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_NAME *pIssuer: certificate issuer
	 * @param size_t ulCount: pIssuer count
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETNAME		put_issuer;
	/**
	 * @brief Sets X.509 certificate suject
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_NAME *pSubject: certificate subject
	 * @param size_t ulCount: pSubject count
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETNAME		put_subject;
	/**
	 * @brief Sets X.509 certificate validity
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param char *szNotBefore: notBefore instant in form YYYYMMDDHHSSZ (must be NULL terminated)
	 * @param char *szNotAfter: notAfter instant in form YYYYMMDDHHSSZ (must be NULL terminated)
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETVALIDITY	put_validity;
	/**
	 * @brief Sets X.509 certificate subject public key info
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_ASN1_PNODE pPubkey: subjectPublicKeyInfo (extracted from PKCS#10)
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETPUBKEY		put_pubkey;
	/**
	 * @brief Sets X.509 certificate authority key identifier extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OCTET_SRING *pValue: extension value
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETOCTET		put_aki;
	/**
	 * @brief Sets X.509 certificate subject key identifier extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OCTET_SRING *pValue: extension value
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETOCTET		put_ski;
	/**
	 * @brief Sets X.509 certificate key usage extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OCTET_SRING *pValue: extension value
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETOCTET		put_key_usage;
	/**
	 * @brief Sets X.509 certificate subject alternative name extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OTHER_NAME *pValue: extension value
	 * @param size_t ulCount: pValue count.
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETSUBALTNAME	put_subject_altname;
	/**
	 * @brief Sets X.509 certificate basic constraints extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param int isCA: TRUE if this is a CA certificate
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETBASCONSTRAINT	put_basic_constraints;
	/**
	 * @brief Sets X.509 certificate extended key usage extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OID *pValues: extension value
	 * @param size_t ulCount: pValues count.
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETEXTKEYUSAGE	put_extkey_usage;
	/**
	 * @brief Sets X.509 certificate CRL distribution points extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param char *pValues: double-null-terminated string of URLs.
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETCDP		put_cdp;
	/**
	 * @brief Sets X.509 certificate extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OID pOID: extension identifier
	 * @param int isCritical: critical extension indicator
	 * @param NH_OCTET_SRING *pValue: extension value
	 * @return
	 * 	NH_ISSUE_ALREADY_PUT_ERROR
	 * 	NH_INVALID_ARG
	 * 	NH_CANNOT_SAIL
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_INVALID_DER_TYPE
	 */
	NH_TBS_SETEXT		put_extension;
	/**
	 * @brief Encodes this TBS certificate
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param unsigned char *pBuffer: output buffer
	 * @param size_t *ulSize: size of pBuffer; if pBuffer is NULL, returns required buffer size;
	 * @return
	 * 	NH_ISSUE_INCOMPLETEOB_ERROR
	 * 	NH_BUF_TOO_SMALL
	 * 	NH_INVALID_DER_TYPE
	 * 	NH_OUT_OF_MEMORY_ERROR
	 * 	NH_UNEXPECTED_ENCODING
	 */
	NH_TBS_ENCODE		encode;
};
typedef struct  NH_TBSCERT_ENCODER_STR			*NH_TBSCERT_ENCODER;


typedef struct NH_CERT_ENCODER_STR				NH_CERT_ENCODER_STR;
typedef NH_METHOD(NH_RV, NH_CERT_SIGN)(_IN_ NH_CERT_ENCODER_STR*, _IN_ NH_TBSCERT_ENCODER, _IN_ CK_MECHANISM_TYPE, _IN_ NH_CMS_SIGN_FUNCTION, _IN_ void*);
/**
 * @brief X.509 Certificate encoder
 * <em>Warning: encoder is not thread safe</em>
 * @see https://tools.ietf.org/html/rfc5280
 * 
 */
struct NH_CERT_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE	hEncoder;			/**< ASN.1 encoder */
	/**
	 * @brief Signs a complete TBSCertificate 
	 * @param NH_CERT_ENCODER_STR *hHandler: certificate encoder handler
	 * @param NH_TBSCERT_ENCODER hCert: TBSCertificate encoder handler
	 * @param CK_MECHANISM_TYPE mechanism: PKCS#11 signature mechanism constant
	 * @param NH_CMS_SIGN_FUNCTION callback: signature callback function
	 * @param void *pParams: parameters to callback function.
	 * @return
	 * 
	 */
	NH_CERT_SIGN		sign;
};
typedef NH_CERT_ENCODER_STR					*NH_CERT_ENCODER;



typedef struct NH_TBSCERTLIST_ENCODER_STR			NH_TBSCERTLIST_ENCODER_STR;
typedef NH_METHOD(NH_RV, NH_TBSCL_ADD_REVOKED)(_INOUT_ NH_TBSCERTLIST_ENCODER_STR*, _IN_ NH_BIG_INTEGER*, _IN_ char*, _IN_ unsigned int);
struct NH_TBSCERTLIST_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE	hEncoder;			/**< ASN.1 encoder */
	NH_ASN1_PNODE		revokedCertificates;	/**< Shortcut to revoked list */
	/**
	 * @brief Adds a new certificate to revoked list
	 * @param NH_TBSCERTLIST_ENCODER_STR *hHandler: TBSCertificateList encoder handler
	 * @param NH_BIG_INTEGER *serial: certificate serial number
	 * @param char *szRevocation: revocation date in format YYYYMMDDHHSSZ. Must be NULL terminated
	 * @param unsigned int reason: CRLReason enumerated
	 * CRLReason ::= ENUMERATED {
	 *    unspecified             (0),
	 *    keyCompromise           (1),
	 *    cACompromise            (2),
	 *    affiliationChanged      (3),
	 *    superseded              (4),
	 *    cessationOfOperation    (5),
	 *    certificateHold         (6),
	 *    -- value 7 is not used
	 *    removeFromCRL           (8),
	 *    privilegeWithdrawn      (9),
	 *    aACompromise           (10) }
	 * 
	 */
	NH_TBSCL_ADD_REVOKED	add_cert;
};
typedef NH_TBSCERTLIST_ENCODER_STR				*NH_TBSCERTLIST_ENCODER;


#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Parses specified certificate request
 * @param unsigned char *pBuffer: DER encoded certificate request buffer
 * @param size_t ulBuflen: size of buffer
 * @param NH_CREQUEST_PARSER *hHandle: handler to certificate request parser
 * @return
 * 	NH_OUT_OF_MEMORY_ERROR
 */
NH_FUNCTION(NH_RV, NH_parse_cert_request)(_IN_ unsigned char*, _IN_ size_t, _OUT_ NH_CREQUEST_PARSER*);

/**
 * @brief Releases certificate request parser
 * @param NH_CREQUEST_PARSER *hHandle: handler to certificate request parser
 */
NH_FUNCTION(void, NH_release_cert_request)(_INOUT_ NH_CREQUEST_PARSER);

/**
 * @brief Creates a new certificate request encoder
 * @param NH_CREQUEST_ENCODER *hEncoder: the encoder handler
 * @return
 * 	NH_OUT_OF_MEMORY_ERROR
 * 
 */
NH_FUNCTION(NH_RV, NH_new_certificate_request)(_OUT_ NH_CREQUEST_ENCODER*);

/**
 * @brief Releases certificate request encoder
 * @param NH_CREQUEST_ENCODER hEncoder: the encoder handler
 * 
 */
NH_FUNCTION(void, NH_delete_certificate_request)(_INOUT_ NH_CREQUEST_ENCODER);

/**
 * @brief Creates a new TBSCertificate encoder
 * @param NH_TBSCERT_ENCODER *hHandler: encoder handler
 * 
 */
NH_FUNCTION(NH_RV, NH_new_tbscert_encoder)(_OUT_ NH_TBSCERT_ENCODER*);

/**
 * @brief Releases TBSCertificate encoder
 * @param NH_TBSCERT_ENCODER hHandler: the handler
 * 
 */
NH_FUNCTION(void, NH_delete_tbscert_encoder)(_INOUT_ NH_TBSCERT_ENCODER);

/**
 * @brief Creates a new Certificate encoder
 * @param NH_CERT_ENCODER *hHandler: encoder handler
 * 
 */
NH_FUNCTION(NH_RV, NH_new_cert_encoder)(_OUT_ NH_CERT_ENCODER*);

/**
 * @brief Releases Certificate encoder
 * @param NH_CERT_ENCODER hHandler: the handler
 * 
 */
NH_FUNCTION(void, NH_delete_cert_encoder)(_INOUT_ NH_CERT_ENCODER);

NH_FUNCTION(NH_RV, NH_new_tbsCertList_encoder)(_OUT_ NH_TBSCERTLIST_ENCODER*);
NH_FUNCTION(void, NH_delete_tbsCertiList_encoder)(_INOUT_ NH_TBSCERTLIST_ENCODER);


#if defined(__cplusplus)
}
#endif


#endif	/* __PKI_ISSUE_H__ */