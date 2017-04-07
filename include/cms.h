
/** **********************************************************
 ****h* Nharu library/CMS
 *  **********************************************************
 * NAME
 *	CMS
 *
 * AUTHOR
 *	Copyleft (C) 2016 by The Crypthing Initiative
 *
 * PURPOSE
 *	RFC 3852 objects parsing implementation
 *
 * NOTES
 *
 * SEE ALSO
 *
 ******
 *
 *  ***********************************************************
 */

#ifndef __CMS_H__
#define __CMS_H__

#include "pkibr.h"

/*
 ****it* CMS/NH_CMS_CONTENT_TYPE
 *
 * NAME
 *	NH_CMS_CONTENT_TYPE
 *
 * PURPOSE
 *	Content types enumeration
 *
 * SYNOPSIS
 */
typedef enum
{
	NH_UNKNOWN_CTYPE			= (-1),
	NH_DATA_CTYPE			= 0,	/* CMS Data Content Type */
	NH_SIGNED_DATA_CTYPE,			/* CMS Signed-data Content Type */
	NH_ENVELOPED_DATA_CTYPE,		/* CMS Enveloped-data Content Type */
	NH_DIGESTED_DATA_CTYPE,			/* CMS Digested-data Content Type */
	NH_ENCRYPTED_DATA_CTYPE,		/* CMS Encrypted-data Content Type */
	NH_AUTH_DATA_CTYPE			/* CMS Authenticated-data Content Type */

} NH_CMS_CONTENT_TYPE;
/* *******/

typedef struct NH_CMS_ISSUER_SERIAL_STR
{
	NH_NAME_NODE	name;
	NH_ASN1_PNODE	serial;
	NH_ASN1_PNODE	keyIdentifier;

} NH_CMS_ISSUER_SERIAL_STR, *NH_CMS_ISSUER_SERIAL;

typedef struct NH_CMS_SD_PARSER_STR		NH_CMS_SD_PARSER_STR;

/*
 ****f* NH_CMS_SD_PARSER/get_sid
 *
 * NAME
 *	get_sid
 *
 * PURPOSE
 *	Gets the SignerIdentifier CMS field for the specified SignerInfo.
 *
 * ARGUMENTS
 *	_IN_ NH_CMS_SD_PARSER_STR *self: the handler
 *	_IN_ size_t idx: SignerInfo index. Must be a value between 0 and count.
 *	_OUT_ NH_CMS_ISSUER_SERIAL *ret: sid node or NULL if idx was not ound. If sid is a SubjectKeyIdentifier,
 *	only keyIdentifier member is not NULL; otherwise, name and serial members are not NULL.
 *
 * RESULT
 *	NH_INVALID_SIGNER_ERROR
 *	NH_CANNOT_SAIL
 *	NHIX_parse_name() return codes
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_INVALID_CMS_ERROR
 *	NH_CARGO_CONTAINER return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSSD_SID_FUNCTION)(_IN_ NH_CMS_SD_PARSER_STR*, _IN_ size_t, _OUT_ NH_CMS_ISSUER_SERIAL*);

/*
 ****f* NH_CMS_SD_PARSER/get_cert
 *
 * NAME
 *	get_cert
 *
 * PURPOSE
 *	Gets the signing certificate if it was embedded in this CMS.
 *
 * ARGUMENTS
 *	_IN_ NH_CMS_SD_PARSER_STR *self: the handler
 *	_IN_ NH_CMS_ISSUER_SERIAL sid: SignerIdentifier (returned from get_sid)
 *	_OUT_ NH_CERTIFICATE_HANDLER *ret: Certificate handler, if it is present. If it is not NULL, you must NH_release_certificate()
 *	by yourself before NH_cms_release_sd_parser().
 *
 * RESULT
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSSD_CERT_FUNCTION)(_IN_ NH_CMS_SD_PARSER_STR*, _IN_ NH_CMS_ISSUER_SERIAL, _OUT_ NH_CERTIFICATE_HANDLER*);

/*
 ****f* NH_CMS_SD_PARSER/verify
 *
 * NAME
 *	verify
 *
 * PURPOSE
 *	Verifies signed attributes of specified SignerInfo
 *
 * ARGUMENTS
 *	_IN_ NH_CMS_SD_PARSER_STR *self: the handler
 *	_IN_ size_t idx: SignerInfo index. Must be between 0 and count.
 *	_IN_ NH_ASN1_PNODE pubKeyInfo: public key used to verify signature
 *
 * RESULT
 *	NH_INVALID_SIGNER_ERROR
 *	NH_CANNOT_SAIL
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_CMS_NO_SIGATTRS_ERROR
 *	NHIX_verify_signature() return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSSD_VRFY_FUNCTION)(_IN_ NH_CMS_SD_PARSER_STR*, _IN_ size_t, _IN_ NH_ASN1_PNODE);

/*
 ****f* NH_CMS_SD_PARSER/verify_rsa
 *
 * NAME
 *	verify_rsa
 *
 * PURPOSE
 *	Verifies signed attributes of specified SignerInfo using an RSA public key
 *
 * ARGUMENTS
 *	_IN_ NH_CMS_SD_PARSER_STR *self: the handler
 *	_IN_ size_t idx: SignerInfo index. Must be between 0 and count.
 *	_IN_ NH_RSA_PUBKEY_HANDLER pubKey: public key used to verify signature
 *
 * RESULT
 *	NH_INVALID_SIGNER_ERROR
 *	NH_UNEXPECTED_ENCODING
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_CMS_NO_SIGATTRS_ERROR
 *	NH_HASH_HANDLER return codes
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSSD_VRFYRSA_FUNCTION)(_IN_ NH_CMS_SD_PARSER_STR*, _IN_ size_t, _IN_ NH_RSA_PUBKEY_HANDLER);

/*
 ****f* NH_CMS_SD_PARSER/validate
 *
 * NAME
 *	validate
 *
 * PURPOSE
 *	Validates Content Type and Message Digest signed attributes of all SignerInfos against specified eContent
 *
 * ARGUMENTS
 *	_IN_ NH_CMS_SD_PARSER_STR *self: the handler
 *	_IN_ unsigned char *eContent: signed content
 *	_IN_ size_t eSize: size of eContent
 *
 * RESULT
 *	NH_INVALID_ARG
 *	NH_CMS_NO_SIGNED_ERROR
 *	NH_CANNOT_SAIL
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_HASH_HANDLER return codes
 *	NH_CMS_NO_SIGATTRS_ERROR
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_MUTEX_HANDLE return codes
 *	NH_CMS_CTYPE_NOMATCH_ERROR
 *	NH_CMS_MD_NOMATCH_ERROR
 *	NH_CMS_SD_SIGATT_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSSD_VDTE_FUNCTION)(_IN_ NH_CMS_SD_PARSER_STR*, _IN_ unsigned char*, _IN_ size_t);

/*
 ****f* NH_CMS_SD_PARSER/validate_attached
 *
 * NAME
 *	validate_attached
 *
 * PURPOSE
 *	Validates Content Type and Message Digest signed attributes of all SignerInfos against embbeded EncapsulatedContentInfo
 *
 * ARGUMENTS
 *	_IN_ NH_CMS_SD_PARSER_STR *self: the handler
 *
 * RESULT
 *	NH_CMS_SD_NOECONTENT_ERROR
 *	validate() return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSSD_VDTEA_FUNCTION)(_IN_ NH_CMS_SD_PARSER_STR*);

/*
 ****s* CMS/NH_CMS_SD_PARSER
 *
 * NAME
 *	NH_CMS_SD_PARSER
 *
 * PURPOSE
 *	Handles CMS SignedData parser
 *
 * SYNOPSIS
 */
struct NH_CMS_SD_PARSER_STR
{
	NH_MUTEX_HANDLE		mutex;
	NH_ASN1_PARSER_HANDLE	hParser;

	NH_ASN1_PNODE			content;		/* Shortcut to CMSSignedData root node */
	NH_ASN1_PNODE			encapContentInfo;	/* Shortcut to  EncapsulatedContentInfo node */
	NH_ASN1_PNODE			certificates;	/* Shortcut to CertificateSet not */
	NH_ASN1_PNODE*			signers;		/* Array of shortcuts to SignerInfo nodes */
	size_t				count;		/* Count of signers */

	NH_CMSSD_SID_FUNCTION		get_sid;		/* Gets the SignerIdentifier CMS field for the specified SignerInfo. */
	NH_CMSSD_CERT_FUNCTION		get_cert;		/* Gets the signing certificate if it was embedded in this CMS. */
	NH_CMSSD_VRFY_FUNCTION		verify;		/* Verifies signed attributes of specified SignerInfo */
	NH_CMSSD_VRFYRSA_FUNCTION	verify_rsa;		/* _IN_ NH_CMS_SD_PARSER_STR*, _IN_ size_t, _IN_ NH_RSA_PUBKEY_HANDLER */
	NH_CMSSD_VDTE_FUNCTION		validate;		/* Validates Content Type and Message Digest signed attributes of all SignerInfos against specified eContent */
	NH_CMSSD_VDTEA_FUNCTION		validate_attached;/* Validates Content Type and Message Digest signed attributes of all SignerInfos against embbeded EncapsulatedContentInfo */
};
/* ****** */
typedef struct NH_CMS_SD_PARSER_STR*	NH_CMS_SD_PARSER;

/* TODO: NH_CMS_SD_PARSER must support another features:
 *	Verify signature without signed attributes;
 *	Attributes validation according RFC 5126
 */


typedef struct NH_CMS_SD_ENCODER_STR	NH_CMS_SD_ENCODER_STR;

/*
 ****f* NH_CMS_SD_ENCODER/data_ctype
 *
 * NAME
 *	data_ctype
 *
 * PURPOSE
 *	Declares that this CMS SignedData refers to a data content type
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_SD_ENCODER_STR *self: the handler
 *	_IN_ CK_BBOOL attach: CK_TRUE, if signed content must be attached; otherwise CK_FALSE;
 *
 * RESULT
 *	NH_CMS_SD_NOECONTENT_ERROR
 *	NH_CANNOT_SAIL
 *	NH_CMS_SD_ALREADYSET_ERROR
 *	NH_ASN1_ENCODER_HANDLE return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSSD_SDCT_FUNCTION)(_INOUT_ NH_CMS_SD_ENCODER_STR*, _IN_ CK_BBOOL);

/*
 ****f* NH_CMS_SD_ENCODER/add_cert
 *
 * NAME
 *	add_cert
 *
 * PURPOSE
 *	Adds a certficate to this CMS SignedData
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_SD_ENCODER_STR *self: the handler
 *	_IN_ NH_CERTIFICATE_HANDLER hCert: certificate handler
 *
 * RESULT
 *	NH_INVALID_ARG
 *	NH_CANNOT_SAIL
 *	NH_ASN1_ENCODER_HANDLE return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSSD_ADDCER_FUNCTION)(_INOUT_ NH_CMS_SD_ENCODER_STR*, _IN_ NH_CERTIFICATE_HANDLER);

/*
 ****f* NH_CMS_SD_ENCODER/NH_CMS_SIGN_FUNCTION
 *
 * NAME
 *	NH_CMS_SIGN_FUNCTION
 *
 * PURPOSE
 *	Signature callback
 *
 * ARGUMENTS
 *	_IN_ NH_BLOB *data: data to be signed.
 *	_IN_ CK_MECHANISM_TYPE mechanism: signature algorithm
 *	_IN_ void *params: any desired parameter
 *	_OUT_ unsigned char *signature: the signature result, or NULL if signature size is required.
 *	_INOUT_ size_t *sigSize: size of signature
 *
 * RESULT
 *	NH_OK or whatever...
 *
 ******
 *
 */
typedef NH_CALLBACK(NH_RV, NH_CMS_SIGN_FUNCTION)(_IN_ NH_BLOB*, _IN_ CK_MECHANISM_TYPE, _IN_ void*, _OUT_ unsigned char*, _INOUT_ size_t*);

/*
 ****f* NH_CMS_SD_ENCODER/sign
 *
 * NAME
 *	sign
 *
 * PURPOSE
 *	Signs CMS signed attributes
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_SD_ENCODER_STR *self: the handler
 *	_IN_ NH_CMS_ISSUER_SERIAL sid: SignerIdentifier returned by get_sid()
 *	_IN_ CK_MECHANISM_TYPE mechanism: signing cryptographic mechanism as a PKCS #11 constant
 *	_IN_ NH_CMS_SIGN_FUNCTION callback; function that really signs the data
 *	_IN_ void *params: any parameter needed by callback() or NULL, if none.
 *
 * RESULT
 *	NH_INVALID_ARG
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_CANNOT_SAIL
 *	NH_ASN1_ENCODER_HANDLE return codes
 *	NH_HASH_HANDLER return codes
 *	NH_OUT_OF_MEMORY_ERROR
 *	any callback() return code
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSSD_SIG_FUNCTION)(_INOUT_ NH_CMS_SD_ENCODER_STR*, _IN_ NH_CMS_ISSUER_SERIAL, _IN_ CK_MECHANISM_TYPE, _IN_ NH_CMS_SIGN_FUNCTION, _IN_ void*);

/*
 ****s* CMS/NH_CMS_SD_ENCODER
 *
 * NAME
 *	NH_CMS_SD_ENCODER
 *
 * PURPOSE
 *	Handles CMS SignedData encoder. All function members are not thread safe.
 *
 * SYNOPSIS
 */
struct NH_CMS_SD_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE		hEncoder;

	NH_ASN1_PNODE			content;	/* Shortcut to CMSSignedData root node */
	NH_BLOB				eContent;	/* Buffer for EncapsulatedContentInfo (if any) */

	NH_CMSSD_SDCT_FUNCTION		data_ctype;	/* Declares that this CMS SignedData refers to a data content type */
	NH_CMSSD_ADDCER_FUNCTION	add_cert;	/* Adds a certficate to this CMS SignedData */
	NH_CMSSD_SIG_FUNCTION		sign;		/* Signs CMS signed attributes */
};
/* ****** */
typedef struct NH_CMS_SD_ENCODER_STR*	NH_CMS_SD_ENCODER;


typedef struct NH_CMS_ENV_PARSER_STR	NH_CMS_ENV_PARSER_STR;
/*
 ****f* NH_CMS_ENV_PARSER/get_rid
 *
 * NAME
 *	get_rid
 *
 * PURPOSE
 *	Gets the RecipientIdentifier CMS field for the specified KeyTransRecipientInfo.
 *
 * ARGUMENTS
 *	_IN_ NH_CMS_ENV_PARSER *self: the handler
 *	_IN_ size_t idx: RecipientInfo index. Must be a value between 0 and count.
 *	_OUT_ NH_CMS_ISSUER_SERIAL *ret: sid node or NULL if idx was not ound. If sid is a SubjectKeyIdentifier,
 *	only keyIdentifier member is not NULL; otherwise, name and serial members are not NULL.
 *
 * RESULT
 *	NH_INVALID_SIGNER_ERROR
 *	NH_CANNOT_SAIL
 *	NHIX_parse_name() return codes
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_INVALID_CMS_ERROR
 *	NH_CARGO_CONTAINER return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSENV_RID_FUNCTION)(_IN_ NH_CMS_ENV_PARSER_STR*, _IN_ size_t, _OUT_ NH_CMS_ISSUER_SERIAL*);

/*
 ****f* NH_CMS_ENV_PARSER/key_encryption_algorithm
 *
 * NAME
 *	key_encryption_algorithm
 *
 * PURPOSE
 *	Gets the KeyEncryptionAlgorithmIdentifier node of the specified KeyTransRecipientInfo
 *
 * ARGUMENTS
 *	_IN_ NH_CMS_ENV_PARSER *self: the handler
 *	_IN_ size_t idx: RecipientInfo index. Must be a value between 0 and count.
 *	_OUT_ NH_ASN1_PNODE *alg_id: KeyEncryptionAlgorithmIdentifier node.
 *	_OUT_ CK_MECHANISM_TYPE_PTR alg: key encryption PKCS #11 mechanism
 *
 * RESULT
 *	NH_INVALID_SIGNER_ERROR
 *	NH_CANNOT_SAIL
 *	NH_UNSUPPORTED_MECH_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSENV_KALG_FUNCTION)(_IN_ NH_CMS_ENV_PARSER_STR*, _IN_ size_t, _OUT_ NH_ASN1_PNODE*, _OUT_ CK_MECHANISM_TYPE_PTR);

/*
 ****f* NH_CMS_ENV_PARSER/NH_CMS_PDEC_FUNCTION
 *
 * NAME
 *	NH_CMS_PDEC_FUNCTION
 *
 * PURPOSE
 *	Private decryption callback
 *
 * ARGUMENTS
 *	_IN_ NH_BLOB *data: data to be decrypted.
 *	_IN_ CK_MECHANISM_TYPE mechanism: private decryption algorithm
 *	_IN_ void *params: any desired parameter
 *	_OUT_ unsigned char *plaintext: the plain text, or NULL if plain size is required.
 *	_INOUT_ size_t *plainSize: size of plaintext
 *
 * RESULT
 *	NH_OK or whatever...
 *
 ******
 *
 */
typedef NH_CALLBACK(NH_RV, NH_CMS_PDEC_FUNCTION)(_IN_ NH_BLOB*, _IN_ CK_MECHANISM_TYPE, _IN_ void*, _OUT_ unsigned char*, _INOUT_ size_t*);

/*
 ****f* NH_CMS_ENV_PARSER/decrypt
 *
 * NAME
 *	decrypt
 *
 * PURPOSE
 *	Decrypts EncryptedContentInfo, if present
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_ENV_PARSER *self: the handler
 *	_IN_ size_t idx: RecipientInfo index. Must be a value between 0 and count.
 *	_IN_ NH_CMS_PDEC_FUNCTION callback: private decryption callback
 *	, _IN_ void *params: any parameter to callback
 *
 * RESULT
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSENV_DEC_FUNCTION)(_INOUT_ NH_CMS_ENV_PARSER_STR*, _IN_ size_t, _IN_ NH_CMS_PDEC_FUNCTION, _IN_ void*);

/*
 ****s* CMS/NH_CMS_ENV_PARSER
 *
 * NAME
 *	NH_CMS_ENV_PARSER
 *
 * PURPOSE
 *
 *
 * SYNOPSIS
 */
struct NH_CMS_ENV_PARSER_STR
{
	NH_MUTEX_HANDLE		mutex;
	NH_ASN1_PARSER_HANDLE	hParser;

	NH_ASN1_PNODE		content;				/* Shortcut to CMSEnvelopedData root node */
	NH_ASN1_PNODE*		recips;				/* Array of shortcuts to KeyTransRecipientInfo nodes */
	size_t			count;				/* Count of recips */
	NH_BLOB			plaintext;				/* Decrypted EncryptedContentInfo */

	NH_CMSENV_RID_FUNCTION	get_rid;				/* Gets the RecipientIdentifier CMS field for the specified KeyTransRecipientInfo. */
	NH_CMSENV_KALG_FUNCTION	key_encryption_algorithm;	/* Gets the KeyEncryptionAlgorithmIdentifier node of the specified KeyTransRecipientInfo */
	NH_CMSENV_DEC_FUNCTION	decrypt;				/* Decrypts EncryptedContentInfo, if present */
};
/* ****** */
typedef struct NH_CMS_ENV_PARSER_STR*	NH_CMS_ENV_PARSER;


typedef struct NH_CMS_ENV_ENCODER_STR	NH_CMS_ENV_ENCODER_STR;
/*
 ****f* NH_CMS_ENV_PARSER/encrypt
 *
 * NAME
 *	encrypt
 *
 * PURPOSE
 *	Encrypts content. The content-encryption key is generated at random. The EncryptedContentInfo ContentType will be data...
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_ENV_ENCODER_STR *self: the handler
 *	_IN_ CK_MECHANISM_TYPE keyGen: key generation mechanism (see PKCS #11)
 *	_IN_ size_t keySize: size of generated key (unit depends on keyGen)
 *	_IN_ CK_MECHANISM_TYPE cipher: symetric encryption mechanism
 *
 * RESULT
 *	NH_CMS_ALREADYSET_ERROR
 *	NH_SYMKEY_HANDLER return codes
 *	NH_OUT_OF_MEMORY_ERROR
 *	NH_CANNOT_SAIL
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_ASN1_ENCODER_HANDLE return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSENV_ENC_FUNCTION)(_INOUT_ NH_CMS_ENV_ENCODER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ size_t, _IN_ CK_MECHANISM_TYPE);

/*
 ****f* NH_CMS_ENV_PARSER/key_trans_recip
 *
 * NAME
 *	key_trans_recip
 *
 * PURPOSE
 *	Adds a new KeyTransRecipientInfo using specified X.509 certificate.
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_ENV_ENCODER_STR *self: the handler
 *	_IN_ NH_CERTIFICATE_HANDLER hCert: certificate handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: key encryption mechanism
 *
 * RESULT
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSENV_RCP_FUNCTION)(_INOUT_ NH_CMS_ENV_ENCODER_STR*, _IN_ NH_CERTIFICATE_HANDLER, _IN_ CK_MECHANISM_TYPE);

/*
 ****f* NH_CMS_ENV_PARSER/rsa_key_trans_recip
 *
 * NAME
 *	rsa_key_trans_recip
 *
 * PURPOSE
 *	Adds a new KeyTransRecipientInfo using specified RSA public key handler
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_ENV_ENCODER_STR *self: the handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: key encryption mechanism
 *	_IN_ NH_BLOB *keyid: subject key identifier
 *	_IN_ NH_RSA_PUBKEY_HANDLER hPubKey: RSA public key handler
 *
 * RESULT
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_CMS_ENV_NOKEY_ERROR
 *	NH_CANNOT_SAIL
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_CMSENV_RSARCP_FUNCTION)(_INOUT_ NH_CMS_ENV_ENCODER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ NH_BLOB*, _IN_ NH_RSA_PUBKEY_HANDLER);

/*
 ****s* CMS/NH_CMS_ENV_PARSER
 *
 * NAME
 *	NH_CMS_ENV_PARSER
 *
 * PURPOSE
 *
 *
 * SYNOPSIS
 */
struct NH_CMS_ENV_ENCODER_STR
{
	NH_ASN1_ENCODER_HANDLE	hEncoder;

	NH_ASN1_PNODE			content;		/* Shortcut to CMSEnvelopedData root node */
	NH_BLOB				plainContent;	/* Contents to be encrypted */
	NH_BLOB				key;			/* Encryption key */

	NH_CMSENV_ENC_FUNCTION		encrypt;		/* Encrypts content. The content-encryption key is generated at random. The EncryptedContentInfo ContentType will be data... */
	NH_CMSENV_RCP_FUNCTION		key_trans_recip;
	NH_CMSENV_RSARCP_FUNCTION	rsa_key_trans_recip;
};
/* ****** */
typedef struct NH_CMS_ENV_ENCODER_STR*	NH_CMS_ENV_ENCODER;


#if defined(__cplusplus)
extern "C" {
#endif


/*
 ****f* CMS/NH_cms_discover
 *
 * NAME
 *	NH_cms_discover
 *
 * PURPOSE
 *	Gets the CMS document content type
 *
 * ARGUMENTS
 *	_IN_ unsigned char *buffer: DER encoded input data
 *	_IN_ size_t size: size of buffer
 *
 * RESULT
 *	ContentType enumeration. If a parsing error occurs, the function assumes that buffer is of NH_UNKNOWN_CTYPE type.
 *
 * NOTES
 *	ContentInfo ::= SEQUENCE {
 *	   contentType ContentType,
 *	   content [0] EXPLICIT ANY DEFINED BY contentType }
 *
 * SEE ALSO
 *	NH_CMS_CONTENT_TYPE
 *	cms_map
 *
 ******
 *
 */
NH_FUNCTION(NH_CMS_CONTENT_TYPE, NH_cms_discover)(_IN_ unsigned char*, _IN_ size_t);


/*
 ****f* CMS/NH_cms_parse_signed_data
 *
 * NAME
 *	NH_cms_parse_signed_data
 *
 * PURPOSE
 *	Parses CMS SignedData document
 *
 * ARGUMENTS
 *	_IN_ unsigned char *buffer: DER encoded input data
 *	_IN_ size_t size: size of buffer
 *	_OUT_ NH_CMS_SD_PARSER *hHandler:
 *
 * RESULT
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *	NH_OUT_OF_MEMORY_ERROR
 *
 * NOTES
 *	SignedData ::= SEQUENCE {
 *	   version CMSVersion,
 *	   digestAlgorithms DigestAlgorithmIdentifiers,
 *	   encapContentInfo EncapsulatedContentInfo,
 *	   certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *	   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *	signerInfos SignerInfos }
 *
 *	DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 *	DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 *	EncapsulatedContentInfo ::= SEQUENCE {
 *	   eContentType ContentType,
 *	   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 *	ContentType ::= OBJECT IDENTIFIER
 *	CertificateSet ::= SET OF CertificateChoices -- We only support RFC 5280 Certificate
 *	RevocationInfoChoices ::= SET OF RevocationInfoChoice -- We only support RFC 5280 CertificateList
 *
 *	SignerInfos ::= SET OF SignerInfo
 *	SignerInfo ::= SEQUENCE {
 *	   version CMSVersion,
 *	   sid SignerIdentifier,
 *	   digestAlgorithm DigestAlgorithmIdentifier,
 *	   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *	   signatureAlgorithm SignatureAlgorithmIdentifier,
 *	   signature SignatureValue,
 *	   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
 *
 *	CMSVersion ::= INTEGER
 *
 *	SignerIdentifier ::= CHOICE {
 *	   issuerAndSerialNumber IssuerAndSerialNumber,
 *	   subjectKeyIdentifier [0] SubjectKeyIdentifier }
 *
 *	SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *	UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *	Attribute ::= SEQUENCE {
 *	   attrType OBJECT IDENTIFIER,
 *	   attrValues SET OF AttributeValue }
 *	AttributeValue ::= ANY
 *
 *	SignatureValue ::= OCTET STRING
 *
 * SEE ALSO
 *	NH_CMS_CONTENT_TYPE
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_cms_parse_signed_data)(_IN_ unsigned char*, _IN_ size_t, _OUT_ NH_CMS_SD_PARSER*);

/*
 ****f* CMS/NH_cms_release_sd_parser
 *
 * NAME
 *	NH_cms_release_sd_parser
 *
 * PURPOSE
 *	Releases CMS SignedData handler
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_SD_PARSER hHandler: the handler itself
 *
 ******
 *
 */
NH_FUNCTION(void, NH_cms_release_sd_parser)(_INOUT_ NH_CMS_SD_PARSER);

/*
 ****f* CMS/NH_cms_encode_signed_data
 *
 * NAME
 *	NH_cms_encode_signed_data
 *
 * PURPOSE
 *	Initializes a CMS SignedData encoder
 *
 * ARGUMENTS
 *	_IN_ NH_BLOB *eContent: the encapsulated content info to be encoded.
 *	_OUT_ NH_CMS_SD_ENCODER *hHandler: the encoding handler
 *
 * RESULT
 *	NH_ASN1_ENCODER_HANDLE retur codes
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_cms_encode_signed_data)(_IN_ NH_BLOB*, _OUT_ NH_CMS_SD_ENCODER*);

/*
 ****f* CMS/NH_cms_release_sd_encoder
 *
 * NAME
 *	NH_cms_release_sd_encoder
 *
 * PURPOSE
 *	Releases CMS SignedData encoder
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_SD_ENCODER hHandler: the handler itself
 *
 ******
 *
 */
NH_FUNCTION(void, NH_cms_release_sd_encoder)(_INOUT_ NH_CMS_SD_ENCODER);


/*
 ****f* CMS/NH_find_content_type
 *
 * NAME
 *	NH_find_content_type
 *
 * PURPOSE
 *	Returns the CMS content type as a constant
 *
 * ARGUMENTS
 *	__IN_ NH_ASN1_PNODE node: the OID node
 *
 * RESULT
 *	NH_CMS_CONTENT_TYPE
 *
 ******
 *
 */
NH_UTILITY(NH_CMS_CONTENT_TYPE, NH_find_content_type)(_IN_ NH_ASN1_PNODE);

/*
 ****f* CMS/NH_cms_get_rid
 *
 * NAME
 *	NH_cms_get_rid
 *
 * PURPOSE
 *	Returns the CMS document identifier
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_PARSER_HANDLE hParser
 *	_IN_ NH_MUTEX_HANDLE mutex
 *	_IN_ NH_ASN1_PNODE node
 *	_OUT_ NH_CMS_ISSUER_SERIAL *ret
 *
 ******
 *
 */
NH_UTILITY(NH_RV, NH_cms_get_rid)(_INOUT_ NH_ASN1_PARSER_HANDLE, _IN_ NH_MUTEX_HANDLE, _IN_ NH_ASN1_PNODE, _OUT_ NH_CMS_ISSUER_SERIAL*);

/*
 ****f* CMS/NH_cms_parse_enveloped_data
 *
 * NAME
 *	NH_cms_parse_enveloped_data
 *
 * PURPOSE
 *	Parses CMS EnvelopedData document
 *
 * ARGUMENTS
 *	_IN_ unsigned char *encoding: DER encoded input data
 *	_IN_ size_t size: size of buffer
 *	_OUT_ NH_CMS_ENV_PARSER *hHandler:
 *
 * RESULT
 *	NH_ASN1_PARSER_HANDLE return codes
 *	NH_UNEXPECTED_ENCODING
 *	NH_OUT_OF_MEMORY_ERROR
 *
 * NOTES
 * EnvelopedData ::= SEQUENCE {
 *	version CMSVersion,
 *	originatorInfo   [0] IMPLICIT OriginatorInfo OPTIONAL,
 *	recipientInfos       RecipientInfos,
 *	encryptedContentInfo EncryptedContentInfo,
 *	unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 *
 * OriginatorInfo ::= SEQUENCE {
 *	certs [0] IMPLICIT CertificateSet OPTIONAL,
 *	crls  [1] IMPLICIT RevocationInfoChoices OPTIONAL }
 * RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
 * RecipientInfo ::= CHOICE {
 *	ktri      KeyTransRecipientInfo, -- supported RecipientInfo
 *	kari  [1] KeyAgreeRecipientInfo,
 *	kekri [2] KEKRecipientInfo,
 *	pwri  [3] PasswordRecipientinfo,
 *	ori   [4] OtherRecipientInfo }
 * KeyTransRecipientInfo ::= SEQUENCE {
 *	version                CMSVersion,        -- always set to 0 or 2
 *	rid                    RecipientIdentifier,
 *	keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *	encryptedKey           EncryptedKey }
 * RecipientIdentifier ::= CHOICE {
 *	issuerAndSerialNumber    IssuerAndSerialNumber,
 *	subjectKeyIdentifier [0] SubjectKeyIdentifier }
 *
 * KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * EncryptedKey ::= OCTET STRING
 *
 * EncryptedContentInfo ::= SEQUENCE {
 *	contentType                ContentType,
 *	contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *	encryptedContent      [0] IMPLICIT EncryptedContent OPTIONAL }
 * ContentType ::= OBJECT IDENTIFIER
 * ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * EncryptedContent ::= OCTET STRING
 *
 * UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 * SEE ALSO
 *	NH_CMS_CONTENT_TYPE
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_cms_parse_enveloped_data)(_IN_ unsigned char*, _IN_ size_t, _OUT_ NH_CMS_ENV_PARSER*);

/*
 ****f* CMS/NH_cms_release_env_parser
 *
 * NAME
 *	NH_cms_release_env_parser
 *
 * PURPOSE
 *	Releases CMS EnvelopedData handler
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_ENV_PARSER hHandler: the handler itself
 *
 ******
 *
 */
NH_FUNCTION(void, NH_cms_release_env_parser)(_INOUT_ NH_CMS_ENV_PARSER);

/*
 ****f* CMS/NH_cms_encode_enveloped_data
 *
 * NAME
 *	NH_cms_encode_enveloped_data
 *
 * PURPOSE
 *	Initializes a CMS EnvelopedData encoder
 *
 * ARGUMENTS
 *	_IN_ NH_BLOB *eContent: the plain text to be encrypted.
 *	_OUT_ NH_CMS_ENV_ENCODER *hHandler: the encoding handler
 *
 * RESULT
 *	NH_ASN1_ENCODER_HANDLE retur codes
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_cms_encode_enveloped_data)(_IN_ NH_BLOB*, _OUT_ NH_CMS_ENV_ENCODER*);

/*
 ****f* CMS/NH_cms_release_env_encoder
 *
 * NAME
 *	NH_cms_release_env_encoder
 *
 * PURPOSE
 *	Releases CMS EnvelopedData encoder
 *
 * ARGUMENTS
 *	_INOUT_ NH_CMS_ENV_ENCODER hHandler: the handler itself
 *
 ******
 *
 */
NH_FUNCTION(void, NH_cms_release_env_encoder)(_INOUT_ NH_CMS_ENV_ENCODER);


#if defined(__cplusplus)
}
#endif

/*
 *	IssuerAndSerialNumber ::= SEQUENCE {
 *	   issuer Name,
 *	   serialNumber CertificateSerialNumber }
 *	CertificateSerialNumber ::= INTEGER
 *	SubjectKeyIdentifier ::= OCTET STRING
 */
EXTERN NH_NODE_WAY cms_issuer_serial[];
#define CMS_ISSUERSERIAL_MAP_COUNT		3
EXTERN NH_NODE_WAY issuer_serial_map[];
#define ISSUER_SERIAL_MAP_COUNT		1
EXTERN NH_NODE_WAY subkeyid_map[];
#define SUBJECT_KEYID_MAP_COUNT		1

EXTERN NH_NODE_WAY cms_map[];
#define CMS_MAP					3

EXTERN unsigned int cms_enveloped_data_ct_oid[];
#define CMS_ENVELOPED_DATA_OID_COUNT	7

EXTERN unsigned int cms_data_ct_oid[];
#define CMS_DATA_CTYPE_OID_COUNT		7

#endif /* __CMS_H__ */
