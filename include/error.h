#ifndef __ERROR_H__
#define __ERROR_H__

#include "base.h"

#ifdef NH_WINDOWS_IMPL
typedef DWORD				NH_SYSRV;
#else
typedef int					NH_SYSRV;
#endif

/**
 * @brief Error handling
 * NH_RV is an unsigned int, where:
 *	the 16 most significant bits carries Nharu specific code
 *	the 16 lest significant bits carries underlying system error code, if any.
 * Use G_SYSERROR() macro to get system error code.
 * Use G_ERROR() macro to get Nharu specified error code.
 * 
 */

/**
 * @brief System Errors
 * 
 */
#define NH_OK				CKR_OK			/**< Operation succeded */
#define NH_BASE_ERROR			1024
#define NH_BUF_TOO_SMALL		(NH_BASE_ERROR + 1)	/**< Output buffer to small to fit returned value */
#define NH_INVALID_ARG			(NH_BASE_ERROR + 2)	/**< Invalid argument */
#define NH_OUT_OF_MEMORY_ERROR	(NH_BASE_ERROR + 3)	/**< malloc/realloc failure */
#define NH_CANNOT_CREATE_MUTEX	(NH_BASE_ERROR + 4)	/**< Cannot create a mutex object */
#define NH_CANNOT_RELEASE_MUTEX	(NH_BASE_ERROR + 5)	/**< Cannot release mutex object */
#define NH_CANNOT_LOCK			(NH_BASE_ERROR + 6)	/**< Cannot acquire the mutex object */
#define NH_CANNOT_UNLOCK		(NH_BASE_ERROR + 7)	/**< Cannot release lock from mutex object */
#define NH_GENERAL_ERROR		(NH_BASE_ERROR + 8)	/**< Unexpected error */

/**
 * @brief ASN.1 parser errors 
 * 
 */
#define NH_PARSER_ERROR			(NH_BASE_ERROR + 16)
#define NH_SMALL_DER_ENCODING		(NH_PARSER_ERROR + 1)	/**< DER encoding buffer is too small to read size */
#define NH_UNSUPPORTED_DER_LENGTH	(NH_PARSER_ERROR + 2)	/**< DER encoding too big */
#define NH_WRONG_ASN1_KNOWLEDGE	(NH_PARSER_ERROR + 3)	/**< ASN.1 knowledge array is wrong */
#define NH_UNEXPECTED_ENCODING	(NH_PARSER_ERROR + 4)	/**< Unexpected DER encoding */
#define NH_INVALID_DER_TYPE		(NH_PARSER_ERROR + 5)	/**< Parse function does not fit to identifier octet */
#define NH_CANNOT_SAIL			(NH_PARSER_ERROR + 6)	/**< Cannot sail to a node */
#define NH_TYPE_INCOMPATIBLE		(NH_PARSER_ERROR + 7)	/**< Data type incompatible with ASN.1 types */

/**
 * @brief Cryptographic errors
 * 
 */
#define NH_CRYPTO_ERROR			(NH_PARSER_ERROR + 16)
#define NH_DEV_RND_ERROR		(NH_CRYPTO_ERROR + 1)	/**< Error accessign /dev/random device */
#define NH_RND_GEN_ERROR		(NH_CRYPTO_ERROR + 2)	/**< Error during random number generation */
#define NH_UNSUPPORTED_MECH_ERROR	(NH_CRYPTO_ERROR + 3)	/**< Unsupported cryptographic mechanism */
#define NH_HASH_ERROR			(NH_CRYPTO_ERROR + 4)	/**< Error during digest operation */
#define NH_SHARE_INIT_ERROR		(NH_CRYPTO_ERROR + 5)	/**< Could not intialize GFShare context */
#define NH_INVALID_STATE_ERROR	(NH_CRYPTO_ERROR + 6)	/**< Method cannot be invoked in this context. Perhaps you should have a key... Or not! */
#define NH_INVALID_KEYSIZE_ERROR	(NH_CRYPTO_ERROR + 7)	/**< Specified key size not consistent to key generation mechanism */
#define NH_INVALID_IV_ERROR		(NH_CRYPTO_ERROR + 8)	/**< Specified initialization vector not consistent to encryption mechanism */
#define NH_CIPHER_INIT_ERROR		(NH_CRYPTO_ERROR + 9)	/**< Encryption initialization failure */
#define NH_CIPHER_KEYSIZE_ERROR	(NH_CRYPTO_ERROR + 10)	/**< This key size is not consistent to cipher mechanism */
#define NH_CIPHER_ERROR			(NH_CRYPTO_ERROR + 11)	/**< Encryption/decryption failure */
#define NH_RSA_GEN_ERROR		(NH_CRYPTO_ERROR + 12)	/**< RSA key generation error */
#define NH_RSA_VERIFY_ERROR		(NH_CRYPTO_ERROR + 13)	/**< RSA signature verification error */
#define NH_RSA_ENCRYPT_ERROR		(NH_CRYPTO_ERROR + 14)	/**< RSA public key encryption error */
#define NH_RSA_IMPORT_ERROR		(NH_CRYPTO_ERROR + 15)	/**< RSA key import error */
#define NH_RSA_SIGN_ERROR		(NH_CRYPTO_ERROR + 16)	/**< RSA key signature error */
#define NH_RSA_DECRYPT_ERROR		(NH_CRYPTO_ERROR + 17)	/**< RSA private key decryption error */
#define NH_RSA_CLONE_ERROR		(NH_CRYPTO_ERROR + 18)	/**< RSA key clone error */
#define NH_UNSUP_PKEY_ERROR		(NH_CRYPTO_ERROR + 19)	/**< Unsupported private key error */
#define NH_OPENSSL_INIT_ERROR		(NH_CRYPTO_ERROR + 20)	/**< Could not initialize OpenSSL for debug */

/**
 * @brief X.509 parsing errors
 * 
 */
#define NH_PKIX_ERROR			(NH_CRYPTO_ERROR + 32)
#define NH_PKIX_MATCH_NAME_ERROR	(NH_PKIX_ERROR + 1)	/**< PKIX Name does not match */
#define NH_CERT_EXPIRE_ERROR		(NH_PKIX_ERROR + 2)	/**< Certificate is expired */
#define NH_CERT_NOT_VALID_ERROR	(NH_PKIX_ERROR + 3)	/**< Certificate is not valid yet */
#define NH_MALFORMED_CRL_SERIAL	(NH_PKIX_ERROR + 4)	/**< Serial number is not in accordance with 4.1.2.2 section of RFC 5280 */
#define NH_STRINGPREP_ERROR		(NH_PKIX_ERROR + 5)	/**< stringprep.h error codes are added to this value (max is 201) */

/**
 * @brief CMS Errors
 * 
 */
#define NH_CMS_ERROR			(NH_PKIX_ERROR + 64)
#define NH_INVALID_CT_ERROR		(NH_CMS_ERROR + 1)	/**< Document content type does not match parsing request */
#define NH_INVALID_SIGNER_ERROR	(NH_CMS_ERROR + 2)	/**< Specified SignerInfo is not valid */
#define NH_INVALID_CMS_ERROR		(NH_CMS_ERROR + 3)	/**< CMS encoding is not a valid one */
#define NH_CERT_NOT_PRESENT_ERROR	(NH_CMS_ERROR + 4)	/**< CertificateSet is not present in CMS */
#define NH_CMS_NO_SIGATTRS_ERROR	(NH_CMS_ERROR + 5)	/**< This CMS SignedData SignerInfo has no signers signed attributes */
#define NH_CMS_NO_SIGNED_ERROR	(NH_CMS_ERROR + 6)	/**< This CMS SignedData document is not signed... */
#define NH_CMS_CTYPE_NOMATCH_ERROR	(NH_CMS_ERROR + 7)	/**< Signed ContentType does not match CMS SignedData document */
#define NH_CMS_MD_NOMATCH_ERROR	(NH_CMS_ERROR + 8)	/**< Signed Message Digest does not match CMS SignedData document */
#define NH_CMS_SD_SIGATT_ERROR	(NH_CMS_ERROR + 9)	/**< Critical signed attribute not found */
#define NH_CMS_SD_NOECONTENT_ERROR	(NH_CMS_ERROR + 10)	/**< EncapsulatedContentInfo misses eContent */
#define NH_CMS_ALREADYSET_ERROR	(NH_CMS_ERROR + 11)	/**< Requested field was already setted */
#define NH_CMS_UNSUP_RECIP_ERROR	(NH_CMS_ERROR + 12)	/**< Unsupported RecipientInfo choice */
#define NH_CMS_ENV_NOECONTENT_ERROR	(NH_CMS_ERROR + 13)	/**< EncryptedContentInfo misses encryptedContent */
#define NH_CMS_ENV_NOKEY_ERROR	(NH_CMS_ERROR + 14)	/**< A symetric key was not generated to be encrypted to recip */


/**
 * @brief Certificate Issue Errors
 * 
 */
#define NH_ISSUE_ERROR			(NH_CMS_ERROR + 128)
#define NH_ISSUE_INVALID_SIG_ERROR	(NH_ISSUE_ERROR + 1)	/**< Certificate request signature validation failure */
#define NH_ISSUE_ALREADY_PUT_ERROR	(NH_ISSUE_ERROR + 2)	/**< Field alread set */


#define NH_VENDOR_DEFINED_ERROR	(NH_ISSUE_ERROR + 32)	/**< Slot for new range of error codes consistent with this library */


#define NH_SUCCESS(rv)			((rv) == NH_OK)
#define NH_FAIL(rv)			((rv))
#define S_SYSERROR(err)			(err << 16)
#define G_SYSERROR(err)			(err >> 16)
#define G_ERROR(rv)			(rv & 0xFFFF)


#endif /* __ERROR_H__ */
