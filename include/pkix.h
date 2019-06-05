/** **********************************************************
 ****h*  Nharu library/PKIX
 *  **********************************************************
 * NAME
 *	PKIX
 *
 * AUTHOR
 *	Copyleft (C) 2015 by The Crypthing Initiative
 *
 * PURPOSE
 *	RFC 5280 objects parsing implementation
 *
 * NOTES
 *
 * SEE ALSO
 *	NH_CERTIFICATE_HANDLER
 *	NH_INTERVAL
 *	NH_CRL_HANDLER
 *	NHIX_parse_general_name
 *	NHIX_parse_general_names
 *	NHIX_parse_name
 *	NHIX_parse_pubkey
 *	NH_parse_certificate
 *	NH_release_certificate
 *	NH_parse_crl
 *	NH_release_crl
 *	pkix_x500_rdn_map
 *
 ******
 *
 *  ***********************************************************
 */

#ifndef __PKIX_H__
#define __PKIX_H__

#include "crypto.h"

#if defined(_ALIGN_)
#pragma pack(push, pkix_align, 1)
#endif

typedef struct NH_NAME_NODE_STR
{
	char*			stringprep;
	NH_ASN1_PNODE	node;

} NH_NAME_NODE_STR, *NH_NAME_NODE;


/** ****************************
 *  X.509 Certificate handler
 *  ****************************/
typedef struct NH_CERTIFICATE_HANDLER_STR		NH_CERTIFICATE_HANDLER_STR;
/*
 ****f* NH_CERTIFICATE_HANDLER/match_subject
 *
 * NAME
 *	match_subject
 *
 * PURPOSE
 *	Checks if specified ASN.1 node and certificate subject field match.
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_IN_ NH_NAME_NODE name: pointer to a completely parsed ASN.1 node.
 *
 * RESULT
 *	CK_TRUE if subject matches according to RFC 5280 rules
 *
 ******
 *
 */
typedef NH_METHOD(CK_BBOOL, NH_CERT_MATCH_FUNCTION)(_IN_ NH_CERTIFICATE_HANDLER_STR*, _IN_ NH_NAME_NODE);

/*
 ****f* NH_CERTIFICATE_HANDLER/check_validity
 *
 * NAME
 *	check_validity
 *
 * PURPOSE
 *	Checks validity of this certificate.
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_IN_ NH_PTIME instant: time instant.
 *
 * RESULT
 *	NH_OK if validity matches
 *	NH_CANNOT_SAIL
 *	NH_UNEXPECTED_ENCODING
 *	NH_CERT_VALIDITY_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CERT_CHECK_FUNCTION)(_IN_ NH_CERTIFICATE_HANDLER_STR*, _IN_ NH_PTIME);

/*
 ****f* NH_CERTIFICATE_HANDLER/verify
 *
 * NAME
 *	verify
 *
 * PURPOSE
 *	Verifies this certificate signature
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_IN_ NH_ASN1_PNODE pubkeyInfo: completeley parsed issuer certificate subjectPublicKeyInfo
 *
 * RESULT
 *	NH_UNEXPECTED_ENCODING
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_new_hash() return codes
 *	NH_HASH_HANDLER methods return codes
 *	NH_OUT_OF_MEMORY_ERROR
 *	NH_new_RSA_pubkey_handler() return codes
 *	NH_RSA_PUBKEY_HANDLER methods return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CERT_VRFY_FUNCTION)(_IN_ NH_CERTIFICATE_HANDLER_STR*, _IN_ NH_ASN1_PNODE);

/*
 ****f* NH_CERTIFICATE_HANDLER/version
 *
 * NAME
 *	version
 *
 * PURPOSE
 *	Gets the version node of this certificate
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: certificate version field node. If !ASN_IS_PRESENT(*node), the version is v1;
 *	otherwise, it is an ASN.1 INTEGER node
 *
 * RESULT
 *	NH_UNEXPECTED_ENCODING
 *	NH_MUTEX_HANDLE methods return codes
 *	NH_ASN1_PARSER_HANDLE methods return codes
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/signature
 *
 * NAME
 *	signature
 *
 * PURPOSE
 *	Gets the signature node of this certificate
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: signature OID field node.
 *
 * RESULT
 *	NH_UNEXPECTED_ENCODING
 *	NH_MUTEX_HANDLE methods return codes
 *	NH_ASN1_PARSER_HANDLE methods return codes
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/not_before
 *
 * NAME
 *	not_before
 *
 * PURPOSE
 *	Gets the Validity/not_before node of this certificate
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: Validity/not_before field node.
 *
 * RESULT
 *	NH_UNEXPECTED_ENCODING
 *	NH_MUTEX_HANDLE methods return codes
 *	NH_ASN1_PARSER_HANDLE methods return codes
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/not_after
 *
 * NAME
 *	not_after
 *
 * PURPOSE
 *	Gets the Validity/not_after node of this certificate
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: Validity/not_after field node.
 *
 * RESULT
 *	NH_UNEXPECTED_ENCODING
 *	NH_MUTEX_HANDLE methods return codes
 *	NH_ASN1_PARSER_HANDLE methods return codes
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/issuer_id
 *
 * NAME
 *	issuer_id
 *
 * PURPOSE
 *	Gets the issuerUniqueID field of this certificate, if present.
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: issuerUniqueID field node or NULL.
 *
 * RESULT
 *	NH_UNEXPECTED_ENCODING
 *	NH_MUTEX_HANDLE methods return codes
 *	NH_ASN1_PARSER_HANDLE methods return codes
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/subject_id
 *
 * NAME
 *	subject_id
 *
 * PURPOSE
 *	Gets the subjectUniqueID field of this certificate, if present.
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: subjectUniqueID field node or NULL.
 *
 * RESULT
 *	NH_UNEXPECTED_ENCODING
 *	NH_MUTEX_HANDLE methods return codes
 *	NH_ASN1_PARSER_HANDLE methods return codes
 *
 ******
 *
 */

/*
 ****f* NH_CERTIFICATE_HANDLER/aki
 *
 * NAME
 *	aki
 *
 * PURPOSE
 *	Gets the Authority Key Identifier certificate extension
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: extension field node
 *
 * RESULT
 *	find_extension() return codes
 *
 * NOTES
 *	AuthorityKeyIdentifier ::= SEQUENCE {
 *	   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *	   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *	   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
 *	}
 *	KeyIdentifier ::= OCTET STRING
 *	CertificateSerialNumber  ::=  INTEGER
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/ski
 *
 * NAME
 *	ski
 *
 * PURPOSE
 *	Gets the Subject Key Identifier certificate extension
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: extension field node
 *
 * RESULT
 *	find_extension() return codes
 *
 * NOTES
 *	KeyIdentifier ::= OCTET STRING
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/key_usage
 *
 * NAME
 *	key_usage
 *
 * PURPOSE
 *	Gets the Key Usage certificate extension
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: extension field node
 *
 * RESULT
 *	find_extension() return codes
 *
 * NOTES
 *	id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
 *	KeyUsage ::= BIT STRING {
 *	   digitalSignature        (0),
 *	   nonRepudiation          (1), -- recent editions of X.509 have renamed this bit to contentCommitment
 *	   keyEncipherment         (2),
 *	   dataEncipherment        (3),
 *	   keyAgreement            (4),
 *	   keyCertSign             (5),
 *	   cRLSign                 (6),
 *	   encipherOnly            (7),
 *	   decipherOnly            (8)
 *	}
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/basic_constraints
 *
 * NAME
 *	basic_constraints
 *
 * PURPOSE
 *	Gets the BasicConstraints certificate extension
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: extension field node
 *
 * RESULT
 *	find_extension() return codes
 *
 * NOTES
 *	id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
 *	BasicConstraints ::= SEQUENCE {
 *	   cA                BOOLEAN DEFAULT FALSE,
 *	   pathLenConstraint INTEGER (0..MAX) OPTIONAL
 *	}
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/ext_key_usage
 *
 * NAME
 *	ext_key_usage
 *
 * PURPOSE
 *	Gets the Extended Key Usage certificate extension
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: extension field node
 *
 * RESULT
 *	find_extension() return codes
 *
 * NOTES
 *	id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
 *	ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *	KeyPurposeId ::= OBJECT IDENTIFIER
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/subject_alt_names
 *
 * NAME
 *	subject_alt_names
 *
 * PURPOSE
 *	Gets the Subject Alternative Names certificate extension
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: extension field node
 *
 * RESULT
 *	find_extension() return codes
 *
 * NOTES
 *	SubjectAltName ::= GeneralNames
 *
 ******
 *
 */
/*
 ****f* NH_CERTIFICATE_HANDLER/issuer_alt_names
 *
 * NAME
 *	issuer_alt_names
 *
 * PURPOSE
 *	Gets the Issuer Alternative Names certificate extension
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *node: extension field node
 *
 * RESULT
 *	find_extension() return codes
 *
 * NOTES
 *	SubjectAltName ::= GeneralNames
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CERT_PARSE_FUNCTION)(_IN_ NH_CERTIFICATE_HANDLER_STR*, _OUT_ NH_ASN1_PNODE*);

/*
 ****f* NH_CERTIFICATE_HANDLER/find_extension
 *
 * NAME
 *	find_extension
 *
 * PURPOSE
 *	Finds extension specified by its object identifier
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR * self: the handler
 *	_IN_ unsigned int *OID: extension OID
 *	_IN_ size_t count: count of OID
 *	_IN_ NH_ASN1_PNODE from: extensions parent node
 *	_OUT_ NH_ASN1_PNODE *extension: requested extension or NULL, if it is not present.
 *
 * RESULT
 *	NH_MUTEX_HANDLE return codes
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CERT_FIND_FUNCTION)(_IN_ NH_CERTIFICATE_HANDLER_STR*, _IN_ unsigned int*, _IN_ size_t, _IN_ NH_ASN1_PNODE, _OUT_ NH_ASN1_PNODE*);

/*
 ****f* NH_CERTIFICATE_HANDLER/map_extensions
 *
 * NAME
 *	map_extensions
 *
 * PURPOSE
 *	Maps all extensions and parsers their's extnID and critical fields
 *
 * ARGUMENTS
 *	_IN_ NH_CERTIFICATE_STR *self: the handler
 *	_IN_ NH_ASN1_PNODE from: extensions parent node
 *
 * RESULT
 *	NH_MUTEX_HANDLE return codes
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CERT_MAP_FUNCTION)(_IN_ NH_CERTIFICATE_HANDLER_STR*, _IN_ NH_ASN1_PNODE);

/*
 ****s* PKIX/NH_CERTIFICATE_HANDLER
 *
 * NAME
 *	NH_CERTIFICATE_HANDLER
 *
 * PURPOSE
 *	Handles X.509 certificate parsing.
 *
 * SYNOPSIS
 */
struct NH_CERTIFICATE_HANDLER_STR
{
	NH_MUTEX_HANDLE		mutex;
	NH_ASN1_PARSER_HANDLE	hParser;

	NH_ASN1_PNODE		serialNumber;	/* Shortcut to certificate serial number parsed node */
	NH_NAME_NODE		issuer;		/* Shortcut to certificate issuer parsed node */
	NH_NAME_NODE		subject;		/* Shortcut to certificate subject parsed node */
	NH_ASN1_PNODE		pubkey;		/* Shortcut to certificate SubjectPublicKeyInfo parsed node */

	NH_CERT_MATCH_FUNCTION	match_subject;	/* Checks if specified ASN.1 node and certificate subject field match. */
	NH_CERT_CHECK_FUNCTION	check_validity;	/* Checks validity of this certificate. */
	NH_CERT_VRFY_FUNCTION	verify;		/* Verifies this certificate signature */

	NH_CERT_PARSE_FUNCTION	version;		/* Gets the version node of this certificate */
	NH_CERT_PARSE_FUNCTION	signature_mech;	/* Gets the signature algorithm node of this certificate */
	NH_CERT_PARSE_FUNCTION	not_before;		/* Gets the Validity/not_before node of this certificate */
	NH_CERT_PARSE_FUNCTION	not_after;		/* Gets the Validity/not_after node of this certificate */

	NH_CERT_PARSE_FUNCTION	issuer_id;		/* Gets the issuerUniqueID field of this certificate, if present. */
	NH_CERT_PARSE_FUNCTION	subject_id;		/* Gets the subjectUniqueID field of this certificate, if present. */

	NH_CERT_FIND_FUNCTION	find_extension;	/* Finds extension specified by its object identifier */
	NH_CERT_PARSE_FUNCTION	aki;			/* Gets the Authority Key Identifier certificate extension */
	NH_CERT_PARSE_FUNCTION	ski;			/* Gets the Subject Key Identifier certificate extension */
	NH_CERT_PARSE_FUNCTION	key_usage;		/* Gets the Key Usage certificate extension */
	NH_CERT_PARSE_FUNCTION	subject_alt_names;/* Gets the Subject Alternative Names certificate extension */
	NH_CERT_PARSE_FUNCTION	issuer_alt_names; /* Gets the Issuer Alternative Names certificate extension */
	NH_CERT_PARSE_FUNCTION	basic_constraints;/* Gets the BasicConstraints certificate extension */
	NH_CERT_PARSE_FUNCTION	ext_key_usage;	/* Gets the Extended Key Usage certificate extension */
	NH_CERT_MAP_FUNCTION	map_extensions;	/* Maps all extensions and parsers their's extnID and critical fields */
};
/* ****** */
typedef struct NH_CERTIFICATE_HANDLER_STR*	NH_CERTIFICATE_HANDLER;


/*
 ****s* PKIX/NH_INTERVAL
 *
 * NAME
 *	NH_INTERVAL
 *
 * PURPOSE
 *	An interval of non-revoked certificate serial numbers within a CRL.
 *
 * SYNOPSIS
 */
typedef struct NH_INTERVAL_STR
{
	NH_BIG_INTEGER*		first;
	NH_BIG_INTEGER*		last;
	NH_ASN1_PNODE*		revoked;
	size_t			rcount;
	struct NH_INTERVAL_STR*	next;
	struct NH_INTERVAL_STR*	previous;

} NH_INTERVAL_STR, *NH_INTERVAL;
/*
 * INPUTS
 *	first		- First non-revoked certificate (including 0)
 *	last		- Last non-revoked certificate  (including 2 ^ 65 - 1)
 *	revoked	- Revoked certificates lesser then first
 *	rcount	- Revoked certificates count
 *	next		- Next interval
 *	previous	- Previous interval
 *
 * REMARKS
 * 	The serial number MUST be a positive integer assigned by the CA to
 * 	each certificate.  It MUST be unique for each certificate issued by a
 * 	given CA (i.e., the issuer name and serial number identify a unique
 * 	certificate).  CAs MUST force the serialNumber to be a non-negative
 * 	integer.
 * 	Given the uniqueness requirements above, serial numbers can be
 * 	expected to contain long integers.  Certificate users MUST be able to
 * 	handle serialNumber values up to 20 octets.  Conforming CAs MUST NOT
 * 	use serialNumber values longer than 20 octets.
 * 	Note: Non-conforming CAs may issue certificates with serial numbers
 * 	that are negative or zero.  Certificate users SHOULD be prepared to
 * 	gracefully handle such certificates.
 *
 *******/

typedef struct NH_CRL_HANDLER_STR		NH_CRL_HANDLER_STR;

/*
 ****f* NH_CRL_HANDLER/is_revoked
 *
 * NAME
 *	is_revoked
 *
 * PURPOSE
 *	Checks if specified certificate serial number is on CRL
 *
 * ARGUMENTS
 *	_IN_ NH_CRL_HANDLER_STR *self: the handler
 *	_IN_ NH_BIG_INTEGER serial: certificate serial number
 *
 * RESULT
 *	CK_TRUE if certificate is revoked; otherwise, CK_FALSE.
 *
 ******
 *
 */
typedef NH_METHOD(CK_BBOOL, NH_CRL_REVOKED_FUNCTION)(_IN_ NH_CRL_HANDLER_STR*, NH_BIG_INTEGER*);

/*
 ****f* NH_CRL_HANDLER/get_revoked
 *
 * NAME
 *	get_revoked
 *
 * PURPOSE
 *	Gets and completely parses the revoked certificate SEQUENCE, if serial is found.
 *
 * ARGUMENTS
 *	_IN_ NH_CRL_HANDLER_STR *self: the handler
 *	_IN_ NH_BIG_INTEGER serial: certificate serial number
 *	 _OUT_ NH_ASN1_PNODE *ret: the completely parsed revoked certificate node or NULL.
 *
 * RESULT
 *	NH_INVALID_ARG
 *	NH_MUTEX_HANDLE return codes
 *	NH_ASN1_PARSER_HANDLE return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CRL_GET_RVK_FUNCTION)(_IN_ NH_CRL_HANDLER_STR*, _IN_ NH_BIG_INTEGER*, _OUT_ NH_ASN1_PNODE*);

/*
 ****f* NH_CRL_HANDLER/verify
 *
 * NAME
 *	verify
 *
 * PURPOSE
 *	Verifies this CRL signature
 *
 * ARGUMENTS
 *	_IN_ NH_CRL_HANDLER_STR * self: the handler
 *	_IN_ NH_ASN1_PNODE pubkeyInfo: completeley parsed issuer certificate subjectPublicKeyInfo
 *
 * RESULT
 *	NH_UNEXPECTED_ENCODING
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_new_hash() return codes
 *	NH_HASH_HANDLER methods return codes
 *	NH_OUT_OF_MEMORY_ERROR
 *	NH_new_RSA_pubkey_handler() return codes
 *	NH_RSA_PUBKEY_HANDLER methods return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CRL_VERIFY_FUNCTION)(_IN_ NH_CRL_HANDLER_STR*, _IN_ NH_ASN1_PNODE);

/*
 ****f* NH_CRL_HANDLER/revoked_certs
 *
 * NAME
 *	revoked_certs
 *
 * PURPOSE
 *	Gets revoked certificates SEQUENCE, if any
 *
 * ARGUMENTS
 *	_IN_ NH_CRL_HANDLER_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE* list: completeley parsed revokedCertificates CRL field
 *
 * RESULT
 *	NH_MUTEX_HANDLE return codes
 *	NH_ASN1_PARSER_HANDLE return codes
 *
 ******
 *
 */
/*
 ****f* NH_CRL_HANDLER/version
 *
 * NAME
 *	version
 *
 * PURPOSE
 *	Gets version field of this CRL
 *
 * ARGUMENTS
 *	_IN_ NH_CRL_HANDLER_STR * self: the handler
 *	_OUT_ NH_ASN1_PNODE *version: completeley parsed version CRL field
 *
 * RESULT
 *	NH_MUTEX_HANDLE return codes
 *	NH_ASN1_PARSER_HANDLE return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CRL_GETNODE_FUNCTION)(_IN_ NH_CRL_HANDLER_STR*, _OUT_ NH_ASN1_PNODE*);

/*
 ****f* NH_CRL_HANDLER/find_extension
 *
 * NAME
 *	find_extension
 *
 * PURPOSE
 *	Finds extension specified by its object identifier
 *
 * ARGUMENTS
 *	_IN_ NH_CRL_HANDLER_STR * self: the handler
 *	_IN_ unsigned int *OID: extension OID
 *	_IN_ size_t count: count of OID
 *	_IN_ NH_ASN1_PNODE from: extensions parent node
 *	_OUT_ NH_ASN1_PNODE *extension: requested extension or NULL, if it is not present.
 *
 * RESULT
 *	NH_MUTEX_HANDLE return codes
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CRL_FIND_FUNCTION)(_IN_ NH_CRL_HANDLER_STR*, _IN_ unsigned int*, _IN_ size_t, _IN_ NH_ASN1_PNODE, _OUT_ NH_ASN1_PNODE*);

/*
 ****f* NH_CRL_HANDLER_STR/map_extensions
 *
 * NAME
 *	map_extensions
 *
 * PURPOSE
 *	Maps all extensions and parsers their's extnID and critical fields
 *
 * ARGUMENTS
 *	_IN_ NH_CRL_HANDLER_STR *self: the handler
 *	_IN_ NH_ASN1_PNODE from: extensions parent node
 *
 * RESULT
 *	NH_MUTEX_HANDLE return codes
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CRL_MAP_FUNCTION)(_IN_ NH_CRL_HANDLER_STR*, _IN_ NH_ASN1_PNODE);

/*
 ****s* PKIX/NH_CRL_HANDLER
 *
 * NAME
 *	NH_CRL_HANDLER
 *
 * PURPOSE
 *	Handles X.509 CertificateList parsing
 *
 * SYNOPSIS
 */
struct NH_CRL_HANDLER_STR
{
	NH_MUTEX_HANDLE		mutex;
	NH_ASN1_PARSER_HANDLE	hParser;

	NH_NAME_NODE		issuer;		/* Shortcut to CRL issuer parsed node */
	NH_ASN1_PNODE		thisUpdate;		/* Shortcut to CRL thisUpdate field */
	NH_ASN1_PNODE		nextUpdate;		/* Shortcut to CRL nextUpdate field, if any */
	NH_INTERVAL*		revoked;		/* Pointer to ordered list where revoked certificates searches are done */
	size_t			rcount;		/* Revoked list count */

	NH_CRL_REVOKED_FUNCTION	is_revoked;		/* Checks if specified certificate serial number is on CRL */
	NH_CRL_VERIFY_FUNCTION	verify;		/* Verifies this CRL signature */
	NH_CRL_GET_RVK_FUNCTION	get_revoked;	/* Gets and completely parses the revoked certificate SEQUENCE, if serial is found. */
	NH_CRL_GETNODE_FUNCTION	revoked_certs;	/* Gets revoked certificates SEQUENCE, if any */
	NH_CRL_GETNODE_FUNCTION	version;		/* Gets version field of this CRL */
	NH_CRL_FIND_FUNCTION	find_extension;	/* Finds extension specified by its object identifier */
	NH_CRL_MAP_FUNCTION	map_extensions;	/* Maps all extensions and parsers their's extnID and critical fields */
};
/* ****** */
typedef struct NH_CRL_HANDLER_STR		*NH_CRL_HANDLER;


typedef struct NHIX_PUBLIC_KEY_STR
{
	NH_ASN1_PARSER_HANDLE	hParser;
	NH_ASN1_PNODE		algorithm;
	NH_ASN1_PNODE		pubkey;

} NHIX_PUBLIC_KEY_STR, *NHIX_PUBLIC_KEY;


#if defined(__cplusplus)
extern "C" {
#endif


/** ****************************
 *  PKIX general functions
 *  ****************************/

/*
 ****f* PKIX/NHIX_parse_general_name
 *
 * NAME
 *	NHIX_parse_general_name
 *
 * PURPOSE
 *	Parses an X.509 GeneralName
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_HANDLE hParser: ASN.1 parser handler
 *	_IN_ NH_ASN1_PNODE first: first GeneralName node
 *
 * RESULT
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *
 * NOTES
 *	GeneralName ::= CHOICE {
 *	   otherName                 [0] OtherName,
 *	   rfc822Name                [1] IA5String,
 *	   dNSName                   [2] IA5String,
 *	   x400Address               [3] ORAddress,
 *	   directoryName             [4] Name,
 *	   ediPartyName              [5] EDIPartyName,
 *	   uniformResourceIdentifier [6] IA5String,
 *	   iPAddress                 [7] OCTET STRING,
 *	   registeredID              [8] OBJECT IDENTIFIER
 *	}
 *	OtherName ::= SEQUENCE {
 *	   type-id    OBJECT IDENTIFIER,
 *	   value  [0] EXPLICIT ANY DEFINED BY type-id
 *	}
 *	EDIPartyName ::= SEQUENCE {
 *	   nameAssigner [0] DirectoryString OPTIONAL,
 *	   partyName    [1] DirectoryString
 *	}
 *	ORAddress ::= SEQUENCE {
 *	   built-in-standard-attributes       BuiltInStandardAttributes,
 *	   built-in-domain-defined-attributes BuiltInDomainDefinedAttributes OPTIONAL,
 *	                                      -- see also teletex-domain-defined-attributes
 *	   extension-attributes               ExtensionAttributes OPTIONAL
 *
 ******
 *
 */
NH_UTILITY(NH_RV, NHIX_parse_general_name)(_IN_ NH_ASN1_PARSER_HANDLE, _IN_ NH_ASN1_PNODE);

/*
 ****f* PKIX/NHIX_parse_general_names
 *
 * NAME
 *	NHIX_parse_general_names
 *
 * PURPOSE
 *	Parses an X.509 GeneralNames
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_HANDLE hParser: ASN.1 parser handler
 *	_IN_ NH_ASN1_PNODE from: the node
 *
 * RESULT
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *
 * NOTES
 *	GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 ******
 *
 */
NH_UTILITY(NH_RV, NHIX_parse_general_names)(_IN_ NH_ASN1_PARSER_HANDLE, _IN_ NH_ASN1_PNODE);

/*
 ****f* PKIX/NHIX_parse_name
 *
 * NAME
 *	NHIX_parse_name
 *
 * PURPOSE
 *	Parses an X.509 Name
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_HANDLE hParser: ASN.1 parser handler
 *	_IN_ NH_ASN1_PNODE first: first GeneralName node
 *	_OUT_ NH_NAME_NODE *name: the output parsed Name
 *
 * RESULT
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *
 ******
 *
 */
NH_UTILITY(NH_RV, NHIX_parse_name)(_INOUT_ NH_ASN1_PARSER_HANDLE, _IN_ NH_ASN1_PNODE, _OUT_ NH_NAME_NODE*);

/*
 ****f* PKIX/NHIX_parse_pubkey
 *
 * NAME
 *	NHIX_parse_pubkey
 *
 * PURPOSE
 *	Parses an X.509 SubjectPublicKeyInfo
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_HANDLE hParser: ASN.1 parser handler
 *	_INOUT_ NH_ASN1_PNODE from: field root node
 *
 * RESULT
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *
 ******
 *
 */
NH_UTILITY(NH_RV, NHIX_parse_pubkey)(_IN_ NH_ASN1_PARSER_HANDLE, _INOUT_ NH_ASN1_PNODE);

/*
 ****f* PKIX/NHIX_verify_signature
 *
 * NAME
 *	NHIX_verify_signature
 *
 * PURPOSE
 *	Verifies signature of a parsed document
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PNODE data: data to verify (must be mapped at least)
 *	_IN_ NH_ASN1_PNODE pubkeyInfo: public key node
 *	_IN_ CK_MECHANISM_TYPE hashAlg: hash mechanism
 *	_IN_ NH_ASN1_PNODE signature: signature value. May be a BIT STRING or OCTET STRING node
 *
 * RESULT
 *	NH_INVALID_ARG
 *	NH_HASH_HANDLER return codes
 *	NH_OUT_OF_MEMORY_ERROR
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_RSA_PUBKEY_HANDLER return codes
 *
 ******
 *
 */
NH_UTILITY(NH_RV, NHIX_verify_signature)(_IN_ NH_ASN1_PNODE, _IN_ NH_ASN1_PNODE, _IN_ CK_MECHANISM_TYPE, _IN_ NH_ASN1_PNODE);


/** ****************************
 *  X.509 PKI functions
 *  ****************************/
/*
 ****f* PKIX/NH_parse_certificate
 *
 * NAME
 *	NH_parse_certificate
 *
 * PURPOSE
 *	Parses the X.509 certificate encoded in this buffer
 *
 * ARGUMENTS
 *	_IN_ unsigned char *buffer: DER encoded certificate. This buffer is not copied and must not be freed before handler release.
 *	_IN_ size_t size: size of buffer
 *	_OUT_ NH_CERTIFICATE_HANDLER *hHandler: the handler itself
 *
 * RESULT
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_CANNOT_SAIL
 *	NH_OUT_OF_MEMORY_ERROR
 *
 * NOTES
 *	See RFC 5280
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_parse_certificate)(_IN_ unsigned char*, _IN_ size_t, _OUT_ NH_CERTIFICATE_HANDLER*);

/*
 ****f* PKIX/NH_release_certificate
 *
 * NAME
 *	NH_release_certificate
 *
 * PURPOSE
 *	Releases certificate handler
 *
 * ARGUMENTS
 *	_INOUT_ NH_CERTIFICATE_HANDLER hHandler: the handler itself
 *
 ******
 *
 */
NH_FUNCTION(void, NH_release_certificate)(_INOUT_ NH_CERTIFICATE_HANDLER);

/*
 ****f* PKIX/NH_parse_crl
 *
 * NAME
 *	NH_parse_crl
 *
 * PURPOSE
 *	Parses the X.509 CRL encoded in this buffer
 *
 * ARGUMENTS
 *	_IN_ unsigned char *buffer: DER encoded certificate. This buffer is not copied and must not be freed before handler release.
 *	_IN_ size_t size: size of buffer
 *	_OUT_ NH_CRL_HANDLER *hHandler: the handler itself
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_CANNOT_SAIL
 *	NH_MALFORMED_CRL_SERIAL
 *
 *
 * NOTES
 *	See RFC 5280
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_parse_crl)(_IN_ unsigned char*, _IN_ size_t, _OUT_ NH_CRL_HANDLER*);

/*
 ****f* PKIX/NH_release_crl
 *
 * NAME
 *	NH_release_crl
 *
 * PURPOSE
 *	Releases CRL handler
 *
 * ARGUMENTS
 *	_INOUT_ NH_CRL_HANDLER hHandler: the handler itself
 *
 ******
 *
 */
NH_FUNCTION(void, NH_release_crl)(_INOUT_ NH_CRL_HANDLER);


#if defined(__cplusplus)
}
#endif


/*
 ****v* PKIX/pkix_x500_rdn_map
 *
 * NAME
 *	pkix_x500_rdn_map
 *
 * PURPOSE
 *	Nharu ASN.1 parser defintion to map or chart a Name.
 *
 * NOTES
 *    Name ::= CHOICE { -- only one possibility for now --
 *       rdnSequence  RDNSequence
 *    }
 *    RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *    RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *    AttributeTypeAndValue ::= SEQUENCE {
 *       type     AttributeType,
 *       value    AttributeValue
 *    }
 *    AttributeType   ::= OBJECT IDENTIFIER
 *    AttributeValue  ::= ANY -- DEFINED BY AttributeType
 *    DirectoryString ::= CHOICE {
 *       teletexString    TeletexString (SIZE (1..MAX)),
 *       printableString  PrintableString (SIZE (1..MAX)),
 *       universalString  UniversalString (SIZE (1..MAX)),
 *       utf8String       UTF8String (SIZE (1..MAX)),
 *       bmpString        BMPString (SIZE (1..MAX))
 *    }
 *
 ******
 *
 */
EXTERN NH_NODE_WAY pkix_x500_rdn_map[];
#define PKIX_X500_RDN_COUNT			2
EXTERN unsigned int aki_oid[];
#define AKI_OID_COUNT					4
EXTERN NH_NODE_WAY pkix_aki_map[];
#define PKIX_AKI_MAP_COUNT				4
EXTERN unsigned int ski_oid[];
#define SKI_OID_COUNT					4
EXTERN NH_NODE_WAY pkix_ski_map[];
#define PKIX_SKI_MAP_COUNT				1
EXTERN unsigned int key_usage_oid[];
#define KEYUSAGE_OID_COUNT				4
EXTERN NH_NODE_WAY key_usage_map[];
#define PKIX_KEYUSAGE_MAP_COUNT			1
EXTERN unsigned int subject_alt_names_oid[];
#define SUBJECT_ALTNAMES_OID_COUNT			4
EXTERN unsigned int basic_constraints_oid[];
#define BASIC_CONSTRAINTS_OID_COUNT			4
EXTERN NH_NODE_WAY pkix_cert_basic_constraints_map[];
#define PKIX_BASIC_CONSTRAINTS_MAP_COUNT		3
EXTERN unsigned int ext_key_usage_oid[];
#define EXT_KEYUSAGE_OID_COUNT			4
EXTERN NH_NODE_WAY pkix_cert_ext_key_usage_map[];
#define PKIX_EXT_KEYUSAGE_MAP_COUNT			2
EXTERN NH_NODE_WAY pkix_extension_map[];
#define PKIX_EXTENSION_MAP_COUNT			4
EXTERN NH_NODE_WAY pkix_revoked_entry_map[];
#define PKIX_REVOKEDENTRY_MAP_COUNT			4
EXTERN NH_NODE_WAY pkix_tbsCertList_map[];
#define PKIX_TBSCERTLIST_MAP_COUNT			8
EXTERN NH_NODE_WAY pkix_CertificateList_map[];
#define PKIX_CERTLIST_MAP_COUNT			5


NH_FUNCTION(NH_RV, NHIX_pubkey_parser)(_IN_ unsigned char*, _IN_ size_t, _OUT_ NHIX_PUBLIC_KEY*);
NH_FUNCTION(void, NHIX_release_pubkey)(_INOUT_ NHIX_PUBLIC_KEY);

#if defined(_ALIGN_)
#pragma pack(pop, pkix_align)
#endif

#endif /* __PKIX_H__ */
