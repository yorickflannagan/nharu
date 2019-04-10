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
	 *
	 */
	CR_VRFY_FUNCTION		verify;
};
typedef NH_CREQUEST_PARSER_STR				*NH_CREQUEST_PARSER;


/** @brief An Object Identifier */
typedef struct NH_OID_STR
{
	unsigned int*	pIdentifier;			/**< OID itself */
	size_t		uCount;				/**< OID count */

} NH_OID_STR, *NH_OID;
/** @brief X.500 Name */
typedef struct NH_NAME_STR
{
	NH_OID		pOID;					/**< Object identifier */
	char*			szValue;				/**< Object value (must be NULL terminated) */

} NH_NAME_STR, *NH_NAME;
typedef struct NH_BLOB						NH_OCTET_SRING;	/**< ASN.1 OCTET STRING type alias */
typedef struct NH_NAME_STR*					NH_OTHER_NAME;	/**< General Name Other Name */


typedef struct  NH_TBSCERT_ENCODER_STR			NH_TBSCERT_ENCODER_STR;
typedef NH_METHOD(NH_RV, NH_TBS_SETVER)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ unsigned int);
typedef NH_METHOD(NH_RV, NH_TBS_SETSERIAL)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_BIG_INTEGER*);
typedef NH_METHOD(NH_RV, NH_TBS_SETSIGNALG)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OID);
typedef NH_METHOD(NH_RV, NH_TBS_SETNAME)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_NAME, _IN_ size_t);
typedef NH_METHOD(NH_RV, NH_TBS_SETVALIDITY)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ char*, _IN_ char*);
typedef NH_METHOD(NH_RV, NH_TBS_SETPUBKEY)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_ASN1_PNODE);
typedef NH_METHOD(NH_RV, NH_TBS_SETOCTET)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OCTET_SRING*);
typedef NH_METHOD(NH_RV, NH_TBS_SETSUBALTNAME)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OTHER_NAME*, _IN_ size_t);
typedef NH_METHOD(NH_RV, NH_TBS_SETBASCONSTRAINT)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ int);
typedef NH_METHOD(NH_RV, NH_TBS_SETEXTKEYUSAGE)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OID*, _IN_ size_t);
typedef NH_METHOD(NH_RV, NH_TBS_SETCDP)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ char*);
typedef NH_METHOD(NH_RV, NH_TBS_SETEXT)(_IN_ NH_TBSCERT_ENCODER_STR*, _IN_ NH_OID, _IN_ int, _IN_ NH_OCTET_SRING*);
/**
 * @brief X.509 TBSCertificate Encoder
 * <em>Warning: encoder is not thread safe</em>
 * @see https://tools.ietf.org/html/rfc5280
 * 
 */
struct  NH_TBSCERT_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE	hEncoder;			/**< ASN.1 encoder */
	/**
	 * @brief Sets X.509 certificate version number
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param unsigned int uVersion: version number { v1(0), v2(1), v3(2) }
	 * @return
	 */
	NH_TBS_SETVER		set_version;
	/**
	 * @brief Sets X.509 certificate serial number
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param __IN_ NH_BIG_INTEGER *pSerial: serial number (little endian)
	 * @return
	 * 
	 */
	NH_TBS_SETSERIAL		set_serial;
	/**
	 * @brief Sets X.509 certificate signature algorithm
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OID pOID: signature algorithm object identifier
	 * @return
	 * 
	 */
	NH_TBS_SETSIGNALG		set_sign_alg;
	/**
	 * @brief Sets X.509 certificate issuer
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_NAME *pIssuer: certificate issuer
	 * @param size_t ulCount: pIssuer count
	 * @return
	 * 
	 */
	NH_TBS_SETNAME		set_issuer;
	/**
	 * @brief Sets X.509 certificate suject
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_NAME *pSubject: certificate subject
	 * @param size_t ulCount: pSubject count
	 * @return
	 * 
	 */
	NH_TBS_SETNAME		set_subject;
	/**
	 * @brief Sets X.509 certificate validity
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param char *szNotBefore: notBefore instant in form YYYYMMDDHHSSZ (must be NULL terminated)
	 * @param char *szNotAfter: notAfter instant in form YYYYMMDDHHSSZ (must be NULL terminated)
	 * @return
	 * 
	 */
	NH_TBS_SETVALIDITY	set_validity;
	/**
	 * @brief Sets X.509 certificate subject public key info
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param _IN_NH_ASN1_PNODE pPubkey: subjectPublicKeyInfo (extracted from PKCS#10)
	 * @return
	 * 
	 */
	NH_TBS_SETPUBKEY		set_pubkey;
	/**
	 * @brief Sets X.509 certificate authority key identifier extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OCTET_SRING pValue: extension value
	 * @return
	 * 
	 */
	NH_TBS_SETOCTET		set_aki;
	/**
	 * @brief Sets X.509 certificate subject key identifier extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OCTET_SRING pValue: extension value
	 * @return
	 * 
	 */
	NH_TBS_SETOCTET		set_ski;
	/**
	 * @brief Sets X.509 certificate key usage extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OCTET_SRING pValue: extension value
	 * @return
	 * 
	 */
	NH_TBS_SETOCTET		set_key_usage;
	/**
	 * @brief Sets X.509 certificate subject alternative name extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OTHER_NAME *pValue: extension value
	 * @param size_t ulCount: pValue count.
	 * @return
	 * 
	 */
	NH_TBS_SETSUBALTNAME	set_subject_altname;
	/**
	 * @brief Sets X.509 certificate basic constraints extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param int isCA: TRUE if this is a CA certificate
	 * @return
	 * 
	 */
	NH_TBS_SETBASCONSTRAINT	set_basic_constraints;
	/**
	 * @brief Sets X.509 certificate extended key usage extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OID *pValues: extension value
	 * @param size_t ulCount: pValues count.
	 * @return
	 * 
	 */
	NH_TBS_SETEXTKEYUSAGE	set_extkey_usage;
	/**
	 * @brief Sets X.509 certificate CRL distribution points extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param char *pValues: double-null-terminated string of URLs.
	 * @return
	 * 
	 */
	NH_TBS_SETCDP		set_cdp;
	/**
	 * @brief Sets X.509 certificate extension
	 * @param NH_TBSCERT_ENCODER_STR *hEncoder: ASN.1 encoder handler
	 * @param NH_OID pOID: extension identifier
	 * @param int isCritical: critical extension indicator
	 * @param NH_OCTET_SRING *pValue: extension value
	 * @return
	 * 
	 */
	NH_TBS_SETEXT		set_extension;
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


#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Parses specified certificate request
 * @param unsigned char *pBuffer: DER encoded certificate request buffer
 * @param size_t ulBuflen: size of buffer
 * @param NH_CREQUEST_PARSER *hHandle: handler to certificate request parser
 * @return
 */
NH_FUNCTION(NH_RV, NH_parse_cert_request)(_IN_ unsigned char*, _IN_ size_t, _OUT_ NH_CREQUEST_PARSER*);

/**
 * @brief Releases certificate request parser
 * @param NH_CREQUEST_PARSER *hHandle: handler to certificate request parser
 */
NH_FUNCTION(void, NH_release_cert_request)(_INOUT_ NH_CREQUEST_PARSER);

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

#if defined(__cplusplus)
}
#endif


#endif	/* __PKI_ISSUE_H__ */