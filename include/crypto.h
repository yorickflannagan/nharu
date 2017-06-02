/** **********************************************************
 ****h* Nharu library/Crypto
 *  **********************************************************
 * NAME
 *	Crypto
 *
 * AUTHOR
 *	Copyleft (C) 2015 by The Crypthing Initiative
 *
 * PURPOSE
 *	Cryptographic primitives
 *
 * NOTES
 *
 * SEE ALSO
 *	NH_NOISE_HANDLER
 *	NH_safe_zeroize
 *	NH_new_noise_device
 *	NH_release_noise_device
 *
 ******
 *
 *  ***********************************************************
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "parser.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>

#if defined(_ALIGN_)
#pragma pack(push, _crypto_align, 1)
#endif

#if defined(_DEBUG_)
#define NH_DEFAULT_SEED			16
#define NH_ZEROIZE_STEPS		1
#else
#define NH_DEFAULT_SEED			32
#define NH_ZEROIZE_STEPS		3
#endif
#ifndef EVP_MAX_BLOCK_LENGTH
#define NH_MAX_BLOCK_LENGTH		32
#else
#define NH_MAX_BLOCK_LENGTH		EVP_MAX_BLOCK_LENGTH
#endif
#ifndef EVP_MAX_IV_LENGTH
#define NH_MAX_IV_LENGTH		16
#else
#define NH_MAX_IV_LENGTH		EVP_MAX_IV_LENGTH
#endif


/* OpenSSL warnings suppression for Valgrind */
#if defined(_DEBUG_)
#include <valgrind/memcheck.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
    #define NH_MALLOC(x)				debug_malloc(x, __FILE__ , __LINE__)
#else
    #define NH_MALLOC(x)				debug_malloc(x)
#endif

#else
#define NH_MALLOC(x)				malloc(x)
#endif



/** **********************
 *  Noise device handler
 *  **********************/
typedef struct NH_NOISE_HANDLER_STR	NH_NOISE_HANDLER_STR;
/*
 ****f* NH_NOISE_HANDLER/noise
 *
 * NAME
 *	noise
 *
 * PURPOSE
 *	Get some noise from internal noise device
 *
 * ARGUMENTS
 *	_IN_ NH_NOISE_HANDLER_STR *self: noise device handler
 *	_OUT_ unsigned char *buffer: the buffer to fill with noise
 *	_IN_ size_t len: size of buffer.
 *
 * RESULT
 *	NH_DEV_RND_ERROR. Use G_SYSERROR() to get extended information.
 *
 ******
 *
 */
/*
 ****f* NH_NOISE_HANDLER/rand
 *
 * NAME
 *	rand
 *
 * PURPOSE
 *	Generate some random data
 *
 * ARGUMENTS
 *	_IN_ NH_NOISE_HANDLER_STR *self: noise device handler
 *	_OUT_ unsigned char *buffer: the buffer to fill with random data
 *	_IN_ size_t len: size of buffer.
 *
 * RESULT
 *	NH_RND_GEN_ERROR. Use G_SYSERROR() to get extended information.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_NOISE_FUNCTION)(_OUT_ unsigned char*, _IN_ size_t);

/*
 ****f* NH_NOISE_HANDLER/zeroize
 *
 * NAME
 *	zeroize
 *
 * PURPOSE
 *	Cryptographic zeroization function
 *
 * ARGUMENTS
 *	_IN_ NH_NOISE_HANDLER_STR *self: noise device handler
 *	_OUT_ unsigned char *buffer: the buffer to fill with random data
 *	_IN_ size_t len: size of buffer.
 *
 ******
 *
 */
typedef NH_METHOD(void, NH_ZERO_FUNCTION)(_INOUT_ void*, _IN_ size_t);

/*
 ****f* NH_NOISE_HANDLER/seed
 *
 * NAME
 *	seed
 *
 * PURPOSE
 *	Seed internal noise device with this value
 *
 * ARGUMENTS
 *	_IN_ NH_NOISE_HANDLER_STR *self: noise device handler
 *	_IN_ unsigned char *noise: the buffer with random data
 *	_IN_ size_t len: size of noise.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SEED_FUNCTION)(_IN_ unsigned char*, _IN_ size_t);


/*
 ****s* Crypto/NH_NOISE_HANDLER
 *
 * NAME
 *	NH_NOISE_HANDLER
 *
 * PURPOSE
 *	Handles the noise device.
 *
 * SYNOPSIS
 */
struct NH_NOISE_HANDLER_STR
{
	int			seeded;	/* TRUE if internal noise device has been seeded */
	NH_NOISE_FUNCTION	noise;	/* Get some noise from internal noise device */
	NH_SEED_FUNCTION	seed;		/* Seed internal noise device with this value */
	NH_NOISE_FUNCTION	rand;		/* Generate some random data */
	NH_ZERO_FUNCTION	zeroize;	/* Zeroize this buffer */
};
/* ****** */
typedef NH_NOISE_HANDLER_STR*		NH_NOISE_HANDLER;


/** *****************************
 *  Shamir secret sharing handler
 *  *****************************/
typedef struct NH_SHARE_STR		NH_SHARE_STR;
typedef struct NH_SHARE_HANDLER_STR	NH_SHARE_HANDLER_STR;
/*
 ****f* NH_SHARE_HANDLER/set
 *
 * NAME
 *	set
 *
 * PURPOSE
 *	Sets a share
 *
 * ARGUMENTS
 *	_INOUT_ NH_SHARE_HANDLER_STR *self: the handler
 *	_IN_ unsigned char i: index of share. Must be lesser then count
 *	_IN_ NH_SHARE_STR *share: the share to set
 *
 * NOTES
 *	The handler must be created with proper size
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SSET_FUNCTION)(_INOUT_ NH_SHARE_HANDLER_STR*, _IN_ unsigned char, _IN_ NH_SHARE_STR*);

/*
 ****f* NH_SHARE_HANDLER/get
 *
 * NAME
 *	get
 *
 * PURPOSE
 *	Gets a share
 *
 * ARGUMENTS
 *	_IN_ NH_SHARE_HANDLER_STR *self: the handler
 *	_IN_ unsigned char i: index of share. Must be lesser then count
 *	_OUT_ NH_SHARE_STR *share: output buffer. Must be created with proper size.
 *
 * RESULT
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SGET_FUNCTION)(_IN_ NH_SHARE_HANDLER_STR*, _IN_ unsigned char, _OUT_ NH_SHARE_STR*);

/*
 ****f* NH_SHARE_HANDLER/split
 *
 * NAME
 *	split
 *
 * PURPOSE
 *	Splits a secret
 *
 * ARGUMENTS
 *	_INOUT_ NH_SHARE_HANDLER_STR *self: the handler
 *	_IN_ unsigned char *secret: the secret to share
 *	_IN_ size_t size: sizeof of secret.
 *	_IN_ unsigned char k: minimum k parts required to reconstruct the secret
 *	_IN_ unsigned char n: n parts that will shared the secret
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *	NH_SHARE_INIT_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SSPLIT_FUNCTION)(_INOUT_ NH_SHARE_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t, _IN_ unsigned char, _IN_ unsigned char);

/*
 ****f* NH_SHARE_HANDLER/join
 *
 * NAME
 *	join
 *
 * PURPOSE
 *	Reconstructs the secret
 *
 * ARGUMENTS
 *	_IN_ NH_SHARE_HANDLER_STR *self: the handler
 *	_OUT_ unsigned char *secret: output buffer. Must be great enough to hold the secret.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *	NH_SHARE_INIT_ERROR
 *
 * NOTES
 *	NH_new_secret_share() must be called with action k partes used to reconstruct the secret
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SJOIN_FUNCTION)(_IN_ NH_SHARE_HANDLER_STR*, _OUT_ unsigned char*);

struct NH_SHARE_STR
{
	int				ylen;
	unsigned char*		y;
	unsigned char		x;
};
typedef NH_SHARE_STR		*NH_SHARE;
/*
 ****s* Crypto/NH_SHARE_HANDLER
 *
 * NAME
 *	NH_SHARE_HANDLER
 *
 * PURPOSE
 *	Handles the secret sharing device.
 *
 * SYNOPSIS
 */
struct NH_SHARE_HANDLER_STR
{
	NH_SHARE*			shares;	/* Array of shares */
	unsigned char		count;	/* Count of shares array */

	NH_SSET_FUNCTION		set;		/* _INOUT_ NH_SHARE_HANDLER_STR*, _IN_ size_t, _IN_ NH_SHARE_STR*: sets a share */
	NH_SGET_FUNCTION		get;		/* _IN_ NH_SHARE_HANDLER_STR*, _IN_ size_t, _OUT_ NH_SHARE_STR*: gets a share */
	NH_SSPLIT_FUNCTION	split;	/* _INOUT_ NH_SHARE_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t, _IN_ unsigned char, _IN_ unsigned char: Splits a secret */
	NH_SJOIN_FUNCTION		join;		/* _IN_ NH_SHARE_HANDLER_STR*, _OUT_ unsigned char*: Reconstructs the secret */
};
typedef NH_SHARE_HANDLER_STR	*NH_SHARE_HANDLER;
/* ****** */


/** **********************
 *  Hash handler
 *  **********************/
typedef struct NH_HASH_HANDLER_STR	NH_HASH_HANDLER_STR;
/*
 ****f* NH_HASH_HANDLER/init
 *
 * NAME
 *	init
 *
 * PURPOSE
 *	Initializes a digest operation
 *
 * ARGUMENTS
 *	_INOUT_ NH_HASH_HANDLER_STR *hHash: hash handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: Cryptoki constant
 *
 * RESULT
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_HASH_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_IDGST_FUNCTION)(_INOUT_ NH_HASH_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE);

/*
 ****f* NH_HASH_HANDLER/update
 *
 * NAME
 *	update
 *
 * PURPOSE
 *	Updates a digest
 *
 * ARGUMENTS
 *	_IN_ NH_HASH_HANDLER_STR *hHash: hash handler
 *	_IN_ unsigned char *data: data to hash
 *	_IN_ size_t size: size of data.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_HASH_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_UDGST_FUNCTION)(_IN_ NH_HASH_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t);

/*
 ****f* NH_HASH_HANDLER/finish
 *
 * NAME
 *	finish
 *
 * PURPOSE
 *	Finalizes a digest
 *
 * ARGUMENTS
 *	_INOUT_ NH_HASH_HANDLER_STR *hHash: hash handler
 *	_OUT_ unsigned char *buffer: output buffer. If NULL, required size is returned in size.
 *	__INOUT_ size_t *size: size of buffer.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_HASH_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_FDGST_FUNCTION)(_INOUT_ NH_HASH_HANDLER_STR*, _OUT_ unsigned char*, _INOUT_ size_t*);

/*
 ****f* NH_HASH_HANDLER/digest
 *
 * NAME
 *	digest
 *
 * PURPOSE
 *	Single pass hash
 *
 * ARGUMENTS
 *	_INOUT_ NH_HASH_HANDLER_STR *hHash: hash handler
 *	_IN_ unsigned char *data: data to hash
 *	_IN_ size_t size: size of data.
 *	_OUT_ unsigned char *buffer: output buffer. If NULL, required size is returned in size.
 *	__INOUT_ size_t *size: size of buffer.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_HASH_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_DGSTALL_FUNCTION)(_INOUT_ NH_HASH_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t, _OUT_ unsigned char*, _INOUT_ size_t*);

/*
 ****f* NH_HASH_HANDLER/copy
 *
 * NAME
 *	copy
 *
 * PURPOSE
 *	Copies current hash state to a new object.
 *
 * ARGUMENTS
 *	_IN_ NH_HASH_HANDLER_STR *hCurrent: hash handler
 *	_OUT_ NH_HASH_HANDLER **hNew: the new handler.
 *
 * RESULT
 *	NH_HASH_ERROR
 *	NH_new_hash() return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SDGST_FUNCTION)(_IN_ NH_HASH_HANDLER_STR*, _OUT_ NH_HASH_HANDLER_STR**);

/*
 ****s* Crypto/NH_HASH_HANDLER
 *
 * NAME
 *	NH_HASH_HANDLER
 *
 * PURPOSE
 *	Handles a hash operation that could be reinitialized.
 *
 * SYNOPSIS
 */
struct NH_HASH_HANDLER_STR
{
	CK_MECHANISM_TYPE		mechanism;	/* Cryptoki mechanism constant */
	EVP_MD*			md;		/* OpenSSL mechanism constant */
	EVP_MD_CTX*			ctx;		/* OpenSSL hashing context */

	NH_IDGST_FUNCTION		init;		/* _IN_ CK_MECHANISM_TYPE, _INOUT_ NH_HASH_HANDLER_STR*: Initializes a digest operation */
	NH_UDGST_FUNCTION		update;	/* _IN_ NH_HASH_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t: Updates a digest */
	NH_FDGST_FUNCTION		finish;	/* _IN_ NH_HASH_HANDLER_STR*, _OUT_ unsigned char*, _INOUT_ size_t*: Finalizes a digest. For handler reuse, call init() */
	NH_DGSTALL_FUNCTION	digest;	/* _INOUT_ NH_HASH_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t _OUT_ unsigned char*, _INOUT_ size_t*: Single pass hash */
	NH_SDGST_FUNCTION		copy;		/* _IN_ NH_HASH_HANDLER_STR*, _OUT_ NH_HASH_HANDLER_STR**: Copies current hash state to a new object. */
};
typedef NH_HASH_HANDLER_STR	*NH_HASH_HANDLER;
/* ****** */


/** **********************
 *  Symetric key handler
 *  **********************/
typedef struct NH_SYMKEY_HANDLER_STR	NH_SYMKEY_HANDLER_STR;
/*
 ****f* NH_SYMKEY_HANDLER/generate
 *
 * NAME
 *	generate
 *
 * PURPOSE
 *	Generates a random key to this mechanism
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_IN_ size_t keysize: the key size (of course)
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_INVALID_KEYSIZE_ERROR
 *	NH_new_noise_device() return codes.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SKGEN_FUNCTION)(_INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ size_t);

/*
 ****f* NH_SYMKEY_HANDLER/new_iv
 *
 * NAME
 *	new_iv
 *
 * PURPOSE
 *	Creates a new random initialization vector to this mechanism
 *
 * ARGUMENTS
 *	_IN_ CK_MECHANISM_TYPE mechanism: symetric mechanism
 *	_OUT_ NH_IV **iv: output iv
 *
 * RESULT
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SKIV_FUNCTION)(_IN_ CK_MECHANISM_TYPE, _OUT_ NH_IV**);

/*
 ****f* NH_SYMKEY_HANDLER/release_iv
 *
 * NAME
 *	release_iv
 *
 * PURPOSE
 *	Releases an initialization vector
 *
 * ARGUMENTS
 *	_OUT_ NH_IV *iv: the stuff
 *
 ******
 *
 */
typedef NH_METHOD(void, NH_SKRIV_FUNCTION)(_OUT_ NH_IV*);

/*
 ****f* NH_SYMKEY_HANDLER/encrypt_init
 *
 * NAME
 *	encrypt_init
 *
 * PURPOSE
 *	Initializes a symetric encryption operation.
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: symetric encryption mechanis type
 *	_IN_ NH_IV *iv: initialization vector. Must have the length required by this key.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_INVALID_IV_ERROR
 *	NH_CIPHER_INIT_ERROR
 *	NH_CIPHER_KEYSIZE_ERROR
 *
 ******
 *
 */
/*
 ****f* NH_SYMKEY_HANDLER/decrypt_init
 *
 * NAME
 *	decrypt_init
 *
 * PURPOSE
 *	Initializes a symetric decryption operation.
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: symetric encryption mechanis type
 *	_IN_ NH_IV *iv: initialization vector. Must have the length required by this key.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_INVALID_IV_ERROR
 *	NH_CIPHER_INIT_ERROR
 *	NH_CIPHER_KEYSIZE_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SENCINIT_FUNCTION)(_INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ NH_IV*);

/*
 ****f* NH_SYMKEY_HANDLER/encrypt_update
 *
 * NAME
 *	encrypt_update
 *
 * PURPOSE
 *	Updates a symetric encryption operation.
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_IN_ unsigned char *in: input data
 *	_IN_ size_t inlen: sizeof in
 *	_OUT_ unsigned char *out: output buffer. If NULL, required size is returned in outlen.
 *	_INOUT_ size_t *outlen: size of out.
 *
 * RESULT
 *	NH_BUF_TOO_SMALL
 *	NH_CIPHER_ERROR
 *	NH_INVALID_STATE_ERROR
 *
 ******
 *
 */
/*
 ****f* NH_SYMKEY_HANDLER/decrypt_update
 *
 * NAME
 *	decrypt_update
 *
 * PURPOSE
 *	Updates a symetric decryption operation.
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_IN_ unsigned char *in: input data
 *	_IN_ size_t inlen: sizeof in
 *	_OUT_ unsigned char *out: output buffer. If NULL, required size is returned in outlen.
 *	_INOUT_ size_t *outlen: size of out.
 *
 * RESULT
 *	NH_BUF_TOO_SMALL
 *	NH_CIPHER_ERROR
 *	NH_INVALID_STATE_ERROR
 *
 ******
 *
 */
/*
 ****f* NH_SYMKEY_HANDLER/encrypt
 *
 * NAME
 *	encrypt
 *
 * PURPOSE
 *	Single pass encryption
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_IN_ unsigned char *in: input data
 *	_IN_ size_t inlen: sizeof in
 *	_OUT_ unsigned char *out: output buffer. If NULL, required size is returned in outlen.
 *	_INOUT_ size_t *outlen: size of out.
 *
 * RESULT
 *	NH_BUF_TOO_SMALL
 *	NH_CIPHER_ERROR
 *	encrypt_update() return codes.
 *
 ******
 *
 */
/*
 ****f* NH_SYMKEY_HANDLER/decrypt
 *
 * NAME
 *	decrypt
 *
 * PURPOSE
 *	Single pass decryption
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_IN_ unsigned char *in: input data
 *	_IN_ size_t inlen: sizeof in
 *	_OUT_ unsigned char *out: output buffer. If NULL, required size is returned in outlen.
 *	_INOUT_ size_t *outlen: size of out.
 *
 * RESULT
 *	NH_BUF_TOO_SMALL
 *	NH_CIPHER_ERROR
 *	decrypt_update() return codes.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SENCUPD_FUNCTION)(_INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t, _OUT_ unsigned char*, _INOUT_ size_t*);

/*
 ****f* NH_SYMKEY_HANDLER/encrypt_final
 *
 * NAME
 *	encrypt_final
 *
 * PURPOSE
 *	Finalizes a symetric encryption operation.
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_OUT_ unsigned char *out: output buffer. If NULL, required size is returned in outlen.
 *	_INOUT_ size_t *outlen: size of out.
 *
 * RESULT
 *	NH_CIPHER_ERROR
 *
 ******
 *
 */
/*
 ****f* NH_SYMKEY_HANDLER/decrypt_final
 *
 * NAME
 *	decrypt_final
 *
 * PURPOSE
 *	Finalizes a symetric decryption operation.
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_OUT_ unsigned char *out: output buffer. If NULL, required size is returned in outlen.
 *	_INOUT_ size_t *outlen: size of out.
 *
 * RESULT
 *	NH_CIPHER_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SENCFNL_FUNCTION)(_INOUT_ NH_SYMKEY_HANDLER_STR*, _OUT_ unsigned char*, _INOUT_ size_t*);

/*
 ****f* NH_SYMKEY_HANDLER/encode
 *
 * NAME
 *	encode
 *
 * PURPOSE
 *	Encodes this key to DER format, encrypting the key material
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: the mechanism to encrypt sensitive material
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *hEncryption: handler to desired encryption mechanism. If NULL, the key is encoded as plaintext.
 *	_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder: handler to ASN.1 parser
 *	_IN_ unsigned int path: path to node where the key is charted.
 *
 * RESULT
 *
 * NOTES
 *	This functions assumes that container ASN.1 object was completely paved. An initialization vector is
 *	allways randomly generated.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SENCENC_FUNCTION)(_INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _INOUT_ NH_SYMKEY_HANDLER_STR*, _INOUT_ NH_ASN1_ENCODER_HANDLE, _IN_ unsigned int);

/*
 ****f* NH_SYMKEY_HANDLER/decode
 *
 * NAME
 *	decode
 *
 * PURPOSE
 *	Decodes this key from DER format, decrypting the key material
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *hEncryption: handler to desired decrypion mechanism.
 *	_INOUT_ NH_ASN1_PARSER_HANDLE hParser: handler to ASN.1 parser
 *	_IN_ unsigned int path: path to node where the key is mapped.
 *
 * RESULT
 *
 *
 * NOTES
 *	This functions assumes that container ASN.1 object was completely mapped.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_SENCDEC_FUNCTION)(_INOUT_ NH_SYMKEY_HANDLER_STR*, _INOUT_ NH_SYMKEY_HANDLER_STR*, _INOUT_ NH_ASN1_PARSER_HANDLE, _IN_ unsigned int);

/*
 ****f* NH_SYMKEY_HANDLER/key_type
 *
 * NAME
 *	key_type
 *
 * PURPOSE
 *	Gets the Cryptoki CKA_KEY_TYPE for this CKA_KEY_GEN_MECHANISM
 *
 * ARGUMENTS
 *	_IN_ NH_SYMKEY_HANDLER_STR *self: the handler
 *
 * RESULT
 *	Proper CK_KEY_TYPE or CK_UNAVAILABLE_INFORMATION, if mechanism was not set or is unsupported
 *
 ******
 *
 */
typedef NH_METHOD(CK_KEY_TYPE, NH_SENCKEYTYPE_FUNCTION)(_IN_ NH_SYMKEY_HANDLER_STR*);

/*
 ****f* NH_SYMKEY_HANDLER/set_key_gen
 *
 * NAME
 *	set_key_gen
 *
 * PURPOSE
 *	Sets keygen member from this Cryptoki CKA_KEY_TYPE if known.
 *
 * ARGUMENTS
 *	_INOUT_ NH_SYMKEY_HANDLER_STR *self: the handler
 *	_IN_ CK_KEY_TYPE keyType: Cryptoki constant
 *
 ******
 *
 */
typedef NH_METHOD(void, NH_SENCSETGEN_FUNCTION)(_INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ CK_KEY_TYPE);

/*
 ****s* Crypto/NH_SYMKEY_HANDLER
 *
 * NAME
 *	NH_SYMKEY_HANDLER
 *
 * PURPOSE
 *	Handles a symetric encryption operation.
 *
 * NOTES
 *	ANS.1 definition to persistent keys:
 *	SymKey      ::= SEQUENCE {
 *	   keygen       INTEGER,      -- Cryptoki key generation constant
 *       material ::= CHOICE   {
 *          secret    OCTET STRING, -- Key plain text
 *	      code  ::= SEQUENCE {    -- Encrypted key material
 *	         cipher INTEGER,      -- Cryptoki mechanism used to encrypt sensitive material
 *	         iv     OCTET STRING, -- Encryption initialization vector
 *	         key    OCTET STRING  -- Key cipher text
 *	      }
 *       }
 *	}
 *
 * SYNOPSIS
 */
struct NH_SYMKEY_HANDLER_STR
{
	CK_MECHANISM_TYPE		keygen;		/* Cryptoki key generation mechanism constant */
	NH_SYMKEY*			key;			/* The key itself */
	EVP_CIPHER*			cipher;		/* OpenSSL cipher mechanism constant */
	EVP_CIPHER_CTX*		ctx;			/* OpenSSL encryption context */

	NH_SKGEN_FUNCTION		generate;		/* _IN_ size_t: Generates a random key to this mechanism */
	NH_SKIV_FUNCTION		new_iv;		/* _IN_ CK_MECHANISM_TYPE, _OUT_ NH_IV**: Creates a new random initialization vector to this mechanism */
	NH_SKRIV_FUNCTION		release_iv;		/* _IN_ NH_IV*: Releases an initialization vector */
	NH_SENCINIT_FUNCTION	encrypt_init;	/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ NH_IV*: Initializes a symetric encryption operation. */
	NH_SENCUPD_FUNCTION	encrypt_update;	/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t, _OUT_ unsigned char*, _INOUT_ size_t*: Updates a symetric encryption operation. */
	NH_SENCFNL_FUNCTION	encrypt_final;	/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _OUT_ unsigned char*, _INOUT_ size_t*: Finalizes a symetric encryption operation. */
	NH_SENCINIT_FUNCTION	decrypt_init;	/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ NH_IV*: Initializes a symetric decryption operation. */
	NH_SENCUPD_FUNCTION	decrypt_update;	/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t, _OUT_ unsigned char*, _INOUT_ size_t*: Updates a symetric decryption operation. */
	NH_SENCFNL_FUNCTION	decrypt_final;	/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _OUT_ unsigned char*, _INOUT_ size_t*: Finalizes a symetric decryption operation. */
	NH_SENCUPD_FUNCTION	encrypt;		/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t, _OUT_ unsigned char*, _INOUT_ size_t*: Single pass encryption. */
	NH_SENCUPD_FUNCTION	decrypt;		/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t, _OUT_ unsigned char*, _INOUT_ size_t*: Single pass decryption. */
	NH_SENCENC_FUNCTION	encode;		/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _INOUT_ NH_SYMKEY_HANDLER_STR*, _INOUT_ NH_ASN1_ENCODER_HANDLE, _IN_ unsigned int: Encodes this key to DER format, encrypting the key material */
	NH_SENCDEC_FUNCTION	decode;		/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _INOUT_ NH_SYMKEY_HANDLER_STR*, _INOUT_ NH_ASN1_PARSER_HANDLE, _IN_ unsigned int: Decodes this key from DER format, decrypting the key material */
	NH_SENCKEYTYPE_FUNCTION	key_type;		/* _IN_ NH_SYMKEY_HANDLER_STR*: Gets the Cryptoki CKA_KEY_TYPE for this CKA_KEY_GEN_MECHANISM */
	NH_SENCSETGEN_FUNCTION	set_key_gen;	/* _INOUT_ NH_SYMKEY_HANDLER_STR*, _IN_ CK_KEY_TYPE: Sets keygen member from this Cryptoki CKA_KEY_TYPE if known. */
};
typedef NH_SYMKEY_HANDLER_STR*		NH_SYMKEY_HANDLER;
/* ****** */

/*
 ****v* Crypto/symkey_map
 *
 * NAME
 *	symkey_map
 *
 * PURPOSE
 *	Nharu ASN.1 parser defintion to map or chart symetric keys.
 *
 * NOTES
 *	Use SYMKEY_MAP_COUNT to get symkey_map count.
 *
 ******
 *
 */
EXTERN NH_NODE_WAY symkey_map[];
#define SYMKEY_MAP_COUNT			4


/** **********************
 *  RSA public key handler
 *  **********************/
/*
 ****v* Crypto/pubkey_map
 *
 * NAME
 *	pubkey_map
 *
 * PURPOSE
 *	Nharu ASN.1 parser defintion to map or chart a public key.
 *
 * NOTES
 *	Use PUBKEY_MAP_COUNT to get pubkey_map count.
 *
 ******
 *
 */
EXTERN NH_NODE_WAY pubkey_map[];
#define PUBKEY_MAP_COUNT			4

typedef struct NH_RSA_PUBKEY_HANDLER_STR		NH_RSA_PUBKEY_HANDLER_STR;
/*
 ****f* NH_RSA_PUBKEY_HANDLER/verify
 *
 * NAME
 *	verify
 *
 * PURPOSE
 *	Verifies specified signature.
 *
 * ARGUMENTS
 *	_INOUT_ NH_RSA_PUBKEY_HANDLER_STR *hHandler: the handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: Cryptoki signature mechanism
 *	_IN_ unsigned char *data: signed data (generally a digest)
 *	_IN_ size_t size: size of data
 *	_IN_ unsigned char *signature: the signature
 *	_IN_ size_t sigSize: size of signature
 *
 * RESULT
 *	NH_INVALID_ARG
 *	NH_INVALID_STATE_ERROR
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_RSA_VERIFY_ERROR: use G_SYSERROR() to get extended information
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PUBK_VFY_FUNCTION)(_IN_ NH_RSA_PUBKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ unsigned char*, _IN_ size_t, _IN_ unsigned char*, _IN_ size_t);

/*
 ****f* NH_RSA_PUBKEY_HANDLER/encrypt
 *
 * NAME
 *	encrypt
 *
 * PURPOSE
 *	Encrypts (generally wraps a key) specified contens
 *
 * ARGUMENTS
 *	_INOUT_ NH_RSA_PUBKEY_HANDLER_STR *hHandler: the handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: Cryptoki encryption mechanism
 *	_IN_ unsigned char *data: data to be encrypted (must fit encryption mechanism)
 *	_IN_ size_t size: size of data
 *	OUT_ unsigned char *ciphertext: output buffer (must fit key size). If NULL, required size is returned in cipherSize
 *	_INOUT_ size_t *cipherSize: size of ciphertext
 *
 * RESULT
 *	NH_INVALID_ARG
 *	NH_INVALID_STATE_ERROR
 *	NH_BUF_TOO_SMALL
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_RSA_ENCRYPT_ERROR: use G_SYSERROR() to get extended information
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PUBK_CIP_FUNCTION)(_IN_ NH_RSA_PUBKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ unsigned char*, _IN_ size_t, _OUT_ unsigned char*, _INOUT_ size_t*);

/*
 ****f* NH_RSA_PUBKEY_HANDLER/encode
 *
 * NAME
 *	encode
 *
 * PURPOSE
 *	Encodes this key to DER format
 *
 * ARGUMENTS
 *	_INOUT_ NH_RSA_PUBKEY_HANDLER_STR *hHandler: the handler
 *	_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder: handler to ASN.1 parser
 *	_IN_ unsigned int path: path to node where the key is charted.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_INVALID_ARG
 *	NH_CANNOT_SAIL
 *	NH_ASN1_ENCODER_HANDLE return codes
 *
 * NOTES
 * PublicKey ::= SEQUENCE {
 *    keytype    INTEGER,
 *    key        CHOICE {
 *       rsa [0] RSAPubKey,
 *       dsa [1] DSAPubKey
 *    }
 * }
 * RSAPubKey ::=  SEQUENCE {
 *    modulus  INTEGER,
 *    exponent INTEGER,
 *    bits     INTEGER OPTIONAL
 * }
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PUBK_ECD_FUNCTION)(_IN_ NH_RSA_PUBKEY_HANDLER_STR*, _INOUT_ NH_ASN1_ENCODER_HANDLE, _IN_ unsigned int);

/*
 ****f* NH_RSA_PUBKEY_HANDLER/decode
 *
 * NAME
 *	decode
 *
 * PURPOSE
 *	Decodes this key from DER format
 *
 * ARGUMENTS
 *	_INOUT_ NH_RSA_PUBKEY_HANDLER_STR *hHandler: the handler
 *	_INOUT_ NH_ASN1_PARSER_HANDLE hParser: handler to ASN.1 parser
 *	_IN_ unsigned int path: path to node where the key is mapped.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_INVALID_ARG
 *	NH_CANNOT_SAIL
 *	NH_UNEXPECTED_ENCODING
 *	NH_ASN1_PARSER_HANDLE return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PUBK_DCD_FUNCTION)(_INOUT_ NH_RSA_PUBKEY_HANDLER_STR*, _INOUT_ NH_ASN1_PARSER_HANDLE, _IN_ unsigned int);

/*
 ****f* NH_RSA_PUBKEY_HANDLER/create
 *
 * NAME
 *	create
 *
 * PURPOSE
 *	Imports an RSA publick key
 *
 * ARGUMENTS
 *	_INOUT_ NH_RSA_PUBKEY_HANDLER_STR *hHandler: the handler
 *	_IN_ NH_BIG_INTEGER *n: modulus. Must be a PKCS #11 unsigned big integer.
 *	_IN_ NH_BIG_INTEGER *e: public exponent. Must be a PKCS #11 unsigned big integer.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_INVALID_ARG
 *	NH_RSA_IMPORT_ERROR: use G_SYSERROR() to get extended information
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PUBK_IMP_FUNCTION)(_INOUT_ NH_RSA_PUBKEY_HANDLER_STR*, _IN_ NH_BIG_INTEGER*, _IN_ NH_BIG_INTEGER*);

/*
 ****f* NH_RSA_PUBKEY_HANDLER/clone
 *
 * NAME
 *	clone
 *
 * PURPOSE
 *	Clones this object
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PUBKEY_HANDLER_STR *hHandler: the handler
 *	_OUT_ NH_RSA_PUBKEY_HANDLER_STR *hDolly: the clone
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PUBK_CLO_FUNCTION)(_IN_ NH_RSA_PUBKEY_HANDLER_STR*, _OUT_ NH_RSA_PUBKEY_HANDLER_STR**);

/*
 ****f* NH_RSA_PUBKEY_HANDLER/obj_size
 *
 * NAME
 *	obj_size
 *
 * PURPOSE
 *	Gets this object size
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PUBKEY_HANDLER_STR *hHandler: the handler
 *
 ******
 *
 */
typedef NH_METHOD(size_t, NH_PUBK_SIZ_FUNCTION)(_IN_ NH_RSA_PUBKEY_HANDLER_STR*);

/*
 ****s* Crypto/NH_RSA_PUBKEY_HANDLER
 *
 * NAME
 *	NH_RSA_PUBKEY_HANDLER
 *
 * PURPOSE
 *	Handles operations with an RSA public key.
 *
 * SYNOPSIS
 */
struct NH_RSA_PUBKEY_HANDLER_STR
{
	RSA*				key;			/* OpenSSL RSA public key attributes */
	size_t			size;			/* Length in bits of modulus n */
	NH_PUBK_VFY_FUNCTION	verify;		/* Verifies specified signature */
	NH_PUBK_CIP_FUNCTION	encrypt;		/* Encrypts (generally wraps a key) specified contens */
	NH_PUBK_ECD_FUNCTION	encode;		/* Encodes this key to DER format */
	NH_PUBK_DCD_FUNCTION	decode;		/* Decodes this key from DER format */
	NH_PUBK_IMP_FUNCTION	create;		/* Imports an RSA publick key */
	NH_PUBK_CLO_FUNCTION	clone;		/* Clones this object */
	NH_PUBK_SIZ_FUNCTION	obj_size;		/* Gets this object size */
};
typedef NH_RSA_PUBKEY_HANDLER_STR*			NH_RSA_PUBKEY_HANDLER;
/* ****** */

/** **********************
 *  RSA private key handler
 *  **********************/
/*
 ****v* Crypto/privatekey_map
 *
 * NAME
 *	privatekey_map
 *
 * PURPOSE
 *	Nharu ASN.1 parser defintion to map or chart a private key.
 *
 * NOTES
 *	Use PRIVKEY_MAP_COUNT to get privatekey_map count.
 *
 ******
 *
 */
EXTERN NH_NODE_WAY privatekey_map[];
#define PRIVKEY_MAP_COUNT			4

typedef struct NH_RSA_PRIVKEY_HANDLER_STR		NH_RSA_PRIVKEY_HANDLER_STR;
/*
 ****f* NH_RSA_PRIVKEY_HANDLER/sign
 *
 * NAME
 *	sign
 *
 * PURPOSE
 *	Signs specified message
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler: the handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: Cryptoki signature mechanism
 *	_IN_ unsigned char *data: data to be signed (usually a digest)
 *	_IN_ size_t size: size of data.
 *	_OUT_ unsigned char *signature: output buffer. If NULL, required size is returned in sigSize.
 *	_INOUT_ size_t *sigSize: size of signature
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_INVALID_ARG
 *	NH_BUF_TOO_SMALL
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_RSA_SIGN_ERROR: use G_SYSERROR() to get extended information
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PRVK_SIG_FUNCTION)(_IN_ NH_RSA_PRIVKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ unsigned char*, _IN_ size_t, _OUT_ unsigned char*, _INOUT_ size_t*);

/*
 ****f* NH_RSA_PRIVKEY_HANDLER/decrypt
 *
 * NAME
 *	decrypt
 *
 * PURPOSE
 *	Decrypts (generally unwraps a key) specified content
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler: the handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: Cryptoki encryption mechanism
 *	_IN_ unsigned char *ciphertext: cipher text
 *	_IN_ size_t cipherSize: size of ciphertext
 *	_OUT_ unsigned char *plaintext: output buffer. If NULL, required size is returned in plainSize
 *	_INOUT_ size_t *plainSize: size of plaintext
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_INVALID_ARG
 *	NH_BUF_TOO_SMALL
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_RSA_DECRYPT_ERROR: use G_SYSERROR() to get extended information
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PRVK_DEC_FUNCTION)(_IN_ NH_RSA_PRIVKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _IN_ unsigned char*, _IN_ size_t, _OUT_ unsigned char*, _INOUT_ size_t*);

/*
 ****f* NH_RSA_PRIVKEY_HANDLER/encode
 *
 * NAME
 *	encode
 *
 * PURPOSE
 *	Encodes this key to DER format, encrypting the key material
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler: the handler
 *	_IN_ CK_MECHANISM_TYPE mechanism: Cryptoki encryption mechanism for sensitive data.  Ignored if hEncryption is NULL.
 *	_INOUT_ NH_SYMKEY_HANDLER hEncryption: encryption handler. If NULL, sensitive data is stored in plain text
 *	_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder: ASN.1 encoder handler.
 *	_IN_ unsigned int path: path to node where object is charted.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_INVALID_ARG
 *	NH_CANNOT_SAIL
 *	NH_UNEXPECTED_ENCODING
 *	NH_SYMKEY_HANDLER return codes.
 *	NH_ASN1_ENCODER_HANDLE return codes
 *
 * NOTES
 * PrivateKey ::= SEQUENCE {
 *    keytype     INTEGER,
 *    key         CHOICE {
 *       rsa [0]  RSAPrivKey,
 *       dsa [1]  DSAPrivKey
 *    }
 * }
 * RSAPrivKey   ::= SEQUENCE {
 *    modulus       INTEGER,
 *    pubExponent   INTEGER OPTIONAL,
 *    sensitive ::= CHOICE {
 *       plain  [0] KeyMaterial,
 *       cipher [1] EncryptedMaterial
 *    }
 * }
 * KeyMaterial ::= SEQUENCE {
 *    privExponent     INTEGER,
 *    prime1       [0] INTEGER OPTIONAL,
 *    prime2       [1] INTEGER OPTIONAL,
 *    exponent1    [2] INTEGER OPTIONAL,
 *    exponent2    [3] INTEGER OPTIONAL,
 *    coefficient  [4] INTEGER OPTIONAL
 * }
 * EncryptedMaterial ::= SEQUENCE {
 *    cipher             INTEGER,      -- Cryptoki mechanism used to encrypt sensitive material
 *    iv                 OCTET STRING, -- Encryption initialization vector
 *    privExponent       OCTET STRING,
 *    prime1       [0]   OCTET STRING OPTIONAL,
 *    prime2       [1]   OCTET STRING OPTIONAL,
 *    exponent1    [2]   OCTET STRING OPTIONAL,
 *    exponent2    [3]   OCTET STRING OPTIONAL,
 *    coefficient  [4]   OCTET STRING OPTIONAL
 * }
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PRVK_ECD_FUNCTION)(_IN_ NH_RSA_PRIVKEY_HANDLER_STR*, _IN_ CK_MECHANISM_TYPE, _INOUT_ NH_SYMKEY_HANDLER, _INOUT_ NH_ASN1_ENCODER_HANDLE, _IN_ unsigned int);

/*
 ****f* NH_RSA_PRIVKEY_HANDLER/decode
 *
 * NAME
 *	decode
 *
 * PURPOSE
 *	Decodes this key from DER format, decrypting the key material
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler: the handler
 *	_INOUT_ NH_SYMKEY_HANDLER hEncryption: encryption handler or NULL if sensitive data was stored as plain text
 *	_INOUT_ NH_ASN1_PARSER_HANDLE hParser: ASN.1 parser handler.
 *	_IN_ unsigned int path: path to node where object is mapped.
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_INVALID_ARG
 *	NH_CANNOT_SAIL
 *	NH_UNEXPECTED_ENCODING
 *	NH_SYMKEY_HANDLER return codes.
 *	NH_ASN1_PARSER_HANDLE return codes
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PRVK_DCD_FUNCTION)(_INOUT_ NH_RSA_PRIVKEY_HANDLER_STR*, _INOUT_ NH_SYMKEY_HANDLER, _INOUT_ NH_ASN1_PARSER_HANDLE, _IN_ unsigned int);

/*
 ****f* NH_RSA_PRIVKEY_HANDLER/create
 *
 * NAME
 *	create
 *
 * PURPOSE
 *	Imports an RSA private key
 *
 * ARGUMENTS
 *	_INOUT_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler: the handler
 *	_IN_ NH_BIG_INTEGER *n: modulus. Must be a PKCS #11 unsigned big integer.
 *	_IN_ NH_BIG_INTEGER *e: public exponent or NULL. If set, must be a PKCS #11 unsigned big integer
 *	_IN_ NH_BIG_INTEGER *d: private exponent. Must be a PKCS #11 unsigned big integer.
 *	_IN_ NH_BIG_INTEGER *p: prime p or NULL. If set, must be a PKCS #11 unsigned big integer
 *	_IN_ NH_BIG_INTEGER *q: prime q or NULL. If set, must be a PKCS #11 unsigned big integer
 *	_IN_ NH_BIG_INTEGER *dmp: Private exponent d modulo p-1 or NULL. If set, must be a PKCS #11 unsigned big integer
 *	_IN_ NH_BIG_INTEGER *dmq: Private exponent d modulo q-1 or NULL. If set, must be a PKCS #11 unsigned big integer
 *	_IN_ NH_BIG_INTEGER *qmp: CRT coefficient q -1 mod p or NULL. If set, must be a PKCS #11 unsigned big integer
 *
 * RESULT
 *	NH_INVALID_STATE_ERROR
 *	NH_INVALID_ARG
 *	NH_RSA_IMPORT_ERROR: use G_SYSERROR() to get extended information
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PRVK_IMP_FUNCTION)(_INOUT_ NH_RSA_PRIVKEY_HANDLER_STR*, _IN_ NH_BIG_INTEGER*, _IN_ NH_BIG_INTEGER*, _IN_ NH_BIG_INTEGER*, _IN_ NH_BIG_INTEGER*, _IN_ NH_BIG_INTEGER*, _IN_ NH_BIG_INTEGER*, _IN_ NH_BIG_INTEGER*, _IN_ NH_BIG_INTEGER*);

/*
 ****f* NH_RSA_PRIVKEY_HANDLER/clone
 *
 * NAME
 *	clone
 *
 * PURPOSE
 *	Clones this object
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler: the handler
 *	_OUT_ NH_RSA_PRIVKEY_HANDLER_STR *hDolly: the clone
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PRVK_CLO_FUNCTION)(_IN_ NH_RSA_PRIVKEY_HANDLER_STR*, _OUT_ NH_RSA_PRIVKEY_HANDLER_STR**);

/*
 ****f* NH_RSA_PRIVKEY_HANDLER/obj_size
 *
 * NAME
 *	obj_size
 *
 * PURPOSE
 *	Gets this object size
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler: the handler
 *
 ******
 *
 */
typedef NH_METHOD(size_t, NH_PRVK_SIZ_FUNCTION)(_IN_ NH_RSA_PRIVKEY_HANDLER_STR*);

/*
 ****f* NH_RSA_PRIVKEY_HANDLER/from_privkey_info
 *
 * NAME
 *	from_privkey_info
 *
 * PURPOSE
 *	Imports an RSA private key from a DER encoded PrivateKeyInfo
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler: the handler
 *	_IN_ unsigned char *encoding: encoding buffer
 *	_IN_ size_t size: size of encoding
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_PRVK_P8_FUNCTION)(_INOUT_ NH_RSA_PRIVKEY_HANDLER_STR*, _IN_ unsigned char*, _IN_ size_t);


/*
 ****s* Crypto/NH_RSA_PRIVKEY_HANDLER
 *
 * NAME
 *	NH_RSA_PRIVKEY_HANDLER
 *
 * PURPOSE
 *	Handles operations with an RSA private key.
 *
 * SYNOPSIS
 */
struct NH_RSA_PRIVKEY_HANDLER_STR
{
	RSA*				key;			/* OpenSSL RSA private key attributes */
	NH_PRVK_SIG_FUNCTION	sign;			/* Signs specified message */
	NH_PRVK_DEC_FUNCTION	decrypt;		/* Decrypts (generally unwraps a key) specified content */
	NH_PRVK_ECD_FUNCTION	encode;		/* Encodes this key to DER format, encrypting the key material */
	NH_PRVK_DCD_FUNCTION	decode;		/* Decodes this key from DER format, decrypting the key material */
	NH_PRVK_IMP_FUNCTION	create;		/* Imports an RSA private key */
	NH_PRVK_CLO_FUNCTION	clone;		/* Clones this object */
	NH_PRVK_SIZ_FUNCTION	obj_size;		/* Gets this object size */
	NH_PRVK_P8_FUNCTION	from_privkey_info;/* Imports an RSA private key from a DER encoded PrivateKeyInfo */
};
typedef NH_RSA_PRIVKEY_HANDLER_STR*			NH_RSA_PRIVKEY_HANDLER;
/* ****** */


#if defined(__cplusplus)
extern "C" {
#endif


/** **********************
 *  RSA functions
 *  **********************/
/*
 ****f* Crypto/NH_new_RSA_pubkey_handler
 *
 * NAME
 *	NH_new_RSA_pubkey_handler
 *
 * PURPOSE
 *	Creates a new RSA public key handler
 *
 * ARGUMENTS
 *	_OUT_ NH_RSA_PUBKEY_HANDLER *hHandler: the handler
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *
 * SEE ALSO
 *	NH_release_RSA_pubkey_handler
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_new_RSA_pubkey_handler)(_OUT_ NH_RSA_PUBKEY_HANDLER*);

/*
 ****f* Crypto/NH_release_RSA_pubkey_handler
 *
 * NAME
 *	NH_release_RSA_pubkey_handler
 *
 * PURPOSE
 *	Releases RSA public key handler
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PUBKEY_HANDLER hHandler: the handler
 *
 * SEE ALSO
 *	NH_new_RSA_pubkey_handler and NH_generate_RSA_keys
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_release_RSA_pubkey_handler)(_IN_ NH_RSA_PUBKEY_HANDLER);

/*
 ****f* Crypto/NH_new_RSA_privkey_handler
 *
 * NAME
 *	NH_new_RSA_privkey_handler
 *
 * PURPOSE
 *	Creates a new RSA private key handler
 *
 * ARGUMENTS
 *	_OUT_ NH_RSA_PRIVKEY_HANDLER *hHandler: the handler
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *
 * SEE ALSO
 *	NH_release_RSA_privkey_handler
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_new_RSA_privkey_handler)(_OUT_ NH_RSA_PRIVKEY_HANDLER*);

/*
 ****f* Crypto/NH_release_RSA_privkey_handler
 *
 * NAME
 *	NH_release_RSA_privkey_handler
 *
 * PURPOSE
 *	Releases RSA private key handler
 *
 * ARGUMENTS
 *	_IN_ NH_RSA_PRIVKEY_HANDLER hHandler: the handler
 *
 * SEE ALSO
 *	NH_new_RSA_privkey_handler and NH_generate_RSA_keys
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_release_RSA_privkey_handler)(_IN_ NH_RSA_PRIVKEY_HANDLER);

/*
 ****f* Crypto/NH_generate_RSA_keys
 *
 * NAME
 *	NH_generate_RSA_keys
 *
 * PURPOSE
 *	Generates an RSA key pair
 *
 * ARGUMENTS
 *	_IN_ int bits: key size
 *	_IN_ unsigned long exponent: public exponent e
 *	_OUT_ NH_RSA_PUBKEY_HANDLER *hPubKey: RSA public key handler
 	_OUT_ NH_RSA_PRIVKEY_HANDLER *hPrivKey: RSA private key handler
 *
 * RESULT
 *	NH_INVALID_ARG
 *	NH_RSA_GEN_ERROR: use G_SYSERROR() to possibly get extended information
 *	NH_new_RSA_pubkey_handler return codes
 *	NH_new_RSA_privkey_handler return codes
 *
 *
 * SEE ALSO
 *	NH_release_RSA_privkey_handler
 *	NH_release_RSA_pubkey_handler
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_generate_RSA_keys)(_IN_ int, _IN_ unsigned long, _OUT_ NH_RSA_PUBKEY_HANDLER*, _OUT_ NH_RSA_PRIVKEY_HANDLER*);


/** **********************
 *  Noise device functions
 *  **********************/
/*
 ****f* Crypto/NH_safe_zeroize
 *
 * NAME
 *	NH_safe_zeroize
 *
 * PURPOSE
 *	Cryptographic zeroization function
 *
 * ARGUMENTS
 *	_INOUT_ void *buffer: memory segment.
 *	_IN_ size_t size: buffer size.
 *
 * SEE ALSO
 *	NH_CRYPTOZEROIZE_FUNCTION
 *
 ******
 *
 */
NH_FUNCTION(void, NH_safe_zeroize)(_INOUT_ void*, _IN_ size_t);

/*
 ****f* Crypto/NH_new_noise_device
 *
 * NAME
 *	NH_new_noise_device
 *
 * PURPOSE
 *	Creates a new noise device handler.
 *
 * ARGUMENTS
 *	_OUT_ NH_NOISE_HANDLER *hHandler: the handler itself.
 *
 * RESULT
 *	NH_NOISE_HANDLER/noise return codes.
 *	NH_NOISE_HANDLER/seed return codes.
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_new_noise_device)(_OUT_ NH_NOISE_HANDLER*);

/*
 ****f* Crypto/NH_release_noise_device
 *
 * NAME
 *	NH_release_noise_device
 *
 * PURPOSE
 *	Releases noise device handler.
 *
 * ARGUMENTS
 *	_IN_ NH_NOISE_HANDLER hHandler: the handler itself.
 *
 ******
 *
 */
NH_FUNCTION(void, NH_release_noise_device)(_IN_ NH_NOISE_HANDLER);


/** *****************************
 *  Shamir secret sharing handler
 *  *****************************/
/*
 ****f* Crypto/NH_new_share
 *
 * NAME
 *	NH_new_share
 *
 * PURPOSE
 *	Creates a new share to secret sharing handler
 *
 * ARGUMENTS
 *	_IN_ size_t size: size of secret (in bytes)
 *	_OUT_ NH_SHARE *share: the share itself.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_new_share)(_IN_ size_t, _OUT_ NH_SHARE*);

/*
 ****f* Crypto/NH_release_share
 *
 * NAME
 *	NH_release_share
 *
 * PURPOSE
 *	Releases a share from secret sharing handler
 *
 * ARGUMENTS
 *	_IN_ NH_SHARE share: the share itself.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_release_share)(_IN_ NH_SHARE);

/*
 ****f* Crypto/NH_new_secret_share
 *
 * NAME
 *	NH_new_secret_share
 *
 * PURPOSE
 *	Creates a new secret sharing handler
 *
 * ARGUMENTS
 *	_IN_ unsigned char count: count of share parts required.
 *	_IN_ size_t size: size of secret (in bytes)
 *	_OUT_ NH_SHARE_HANDLER *hShare: handler.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_new_secret_share)(_IN_ unsigned char, _IN_ size_t, _OUT_ NH_SHARE_HANDLER*);

/*
 ****f* Crypto/NH_release_secret_share
 *
 * NAME
 *	NH_release_secret_share
 *
 * PURPOSE
 *	Releases secret sharing handler
 *
 * ARGUMENTS
 *	_IN_ NH_HASH_HANDLER hShare: handler.
 *
 * RESULT
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_release_secret_share)(_IN_ NH_SHARE_HANDLER);


/** **********************
 *  Hash functions
 *  **********************/
/*
 ****f* Crypto/NH_new_hash
 *
 * NAME
 *	NH_new_hash
 *
 * PURPOSE
 *	Creates a new hash handler.
 *
 * ARGUMENTS
 *	_OUT_ NH_HASH_HANDLER *hHandler: the handler itself.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR
 *	NH_HASH_ERROR
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_new_hash)(_OUT_ NH_HASH_HANDLER*);

/*
 ****f* Crypto/NH_release_hash
 *
 * NAME
 *	NH_release_hash
 *
 * PURPOSE
 *	Creates a new hash handler.
 *
 * ARGUMENTS
 *	_IN_ NH_HASH_HANDLER *hHandler: the handler itself.
 *
 ******
 *
 */
NH_FUNCTION(void, NH_release_hash)(_IN_ NH_HASH_HANDLER);


/** **********************
 *  Symetric key functions
 *  **********************/
/*
 ****f* Crypto/NH_new_symkey_handler
 *
 * NAME
 *	NH_new_symkey_handler
 *
 * PURPOSE
 *	Creates a new symetric key handler.
 *
 * ARGUMENTS
 *	_IN_ CK_MECHANISM_TYPE keygen: key generation mechanism type
 *	_OUT_ NH_SYMKEY_HANDLER *hHandler: the handler itself.
 *
 * RESULT
 *	NH_UNSUPPORTED_MECH_ERROR
 *	NH_OUT_OF_MEMORY_ERROR
 *
 * NOTES
 *	Both keygen and mechanism must be consistent to each other, otherwise an NH_UNSUPPORTED_MECH_ERROR is returned.
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_new_symkey_handler)(_IN_ CK_MECHANISM_TYPE, _OUT_ NH_SYMKEY_HANDLER*);

/*
 ****f* Crypto/NH_release_symkey_handler
 *
 * NAME
 *	NH_release_symkey_handler
 *
 * PURPOSE
 *	Releases a symetric key handler.
 *
 * ARGUMENTS
 *	_IN_ NH_SYMKEY_HANDLER *hHandler: the handler itself.
 *
 * NOTES
 *	The contained key is zeroized.
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_release_symkey_handler)(_IN_ NH_SYMKEY_HANDLER);


/** ****************************
 *  General utilities
 *  ****************************/
/*
 ****f* PKIX/NH_match_oid
 *
 * NAME
 *	NH_match_oid
 *
 * PURPOSE
 *	Compares two object identifiers.
 *
 * ARGUMENTS
 *	_IN_ unsigned int *a: foirst OID
 *	_IN_ size_t acount: a count
 *	_IN_ unsigned int *b: second OID
 *	_IN_ size_t bcount: b count
 *
 * RESULT
 *	CK_TRUE if the match; otherwise, CK_FALSE
 *
 ******
 *
 */
NH_UTILITY(CK_BBOOL, NH_match_oid)(_IN_ unsigned int*, _IN_ size_t, _IN_ unsigned int*, _IN_ size_t);

/*
 ****f* PKIX/NH_oid_to_mechanism
 *
 * NAME
 *	NH_oid_to_mechanism
 *
 * PURPOSE
 *	Gets the Cryptoki mechanism constant for this OID
 *
 * ARGUMENTS
 *	_IN_ unsigned int *OID: object identifier
 *	_IN_ size_t count: count of OID array
 *
 * RESULT
 *	 CK_UNAVAILABLE_INFORMATION (if OID is unknown)
 *
 ******
 *
 */
NH_UTILITY(CK_MECHANISM_TYPE, NH_oid_to_mechanism)(_IN_ unsigned int*, _IN_ size_t);


#if defined(_DEBUG_)
    #if OPENSSL_VERSION_NUMBER >= 0x10100001L
        NH_FUNCTION(void*, debug_malloc)(size_t, const char *, int);
    #else
        NH_FUNCTION(void*, debug_malloc)(size_t);
    #endif
#endif

#if defined(__cplusplus)
}
#endif


/** ****************************
 *  Supported cryptographic OIDs
 *  ****************************/
EXTERN unsigned int rsaEncryption_oid[];
#define NHC_RSA_ENCRYPTION_OID_COUNT	7
EXTERN unsigned int rsaes_oaep_oid[];
#define NHC_RSAES_OAEP_OID_COUNT		7
EXTERN unsigned int rsa_x509_oid[];
#define NHC_RSA_X509_OID_COUNT		5
EXTERN unsigned int md5WithRSA_oid[];
#define NHC_MD5_WITH_RSA_OID_COUNT		6
EXTERN unsigned int sha1WithRSAEncryption[];
#define NHC_SHA1_WITH_RSA_OID_COUNT		7
EXTERN unsigned int sha256WithRSAEncryption[];
#define NHC_SHA256_WITH_RSA_OID_COUNT	7
EXTERN unsigned int sha384WithRSAEncryption[];
#define NHC_SHA384_WITH_RSA_OID_COUNT	7
EXTERN unsigned int sha512WithRSAEncryption[];
#define NHC_SHA512_WITH_RSA_OID_COUNT	7
EXTERN unsigned int ecPublicKey_oid[];
#define NHC_ECDSA_PUBKEY_OID_COUNT		6
EXTERN unsigned int sha1_oid[];
#define NHC_SHA1_OID_COUNT			6
EXTERN unsigned int sha256_oid[];
#define NHC_SHA256_OID_COUNT			9
EXTERN unsigned int sha384_oid[];
#define NHC_SHA384_OID_COUNT			9
EXTERN unsigned int sha512_oid[];
#define NHC_SHA512_OID_COUNT			9
EXTERN unsigned int md5_oid[];
#define NHC_MD5_OID_COUNT			6
EXTERN unsigned int rc2_cbc_oid[];
#define NHC_RC2_CBC_OID_COUNT			6
EXTERN unsigned int des3_cbc_oid[];
#define NHC_DES3_CBC_OID_COUNT		6
EXTERN unsigned int aes128_cbc_oid[];
#define NHC_AES128_CBC_OID_COUNT		9
EXTERN unsigned int aes192_cbc_oid[];
#define AES192_CBC_OID_COUNT			9
EXTERN unsigned int aes256_cbc_oid[];
#define AES256_CBC_OID_COUNT			9


/* Unsupported. Used only for Java compatibility */
EXTERN unsigned int dsa_oid[];
#define NHC_DSA_OID_COUNT			6

#define NHC_OID_COUNT(_o)			(sizeof(_o) / sizeof(unsigned int))


/*
 ****v* PKIX/pkix_algid_map
 *
 * NAME
 *	pkix_algid_map
 *
 * PURPOSE
 *	Nharu ASN.1 parser defintion to map or chart an AlgorithmIdentifier.
 *
 * NOTES
 *    AlgorithmIdentifier ::= SEQUENCE  {
 *       algorithm            OBJECT IDENTIFIER,
 *       parameters           ANY DEFINED BY algorithm OPTIONAL
 *    }
 *
 ******
 *
 */
EXTERN NH_NODE_WAY pkix_algid_map[];
#define PKIX_ALGID_COUNT		3

#if defined(_ALIGN_)
#pragma pack(pop, _crypto_align)
#endif

#endif /* __CRYPTO_H__ */
