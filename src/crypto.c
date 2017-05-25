#include "crypto.h"
#include "libgfshare.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef UNIX_IMPL
#include <stdio.h>
#include <errno.h>
#if defined(_DEBUG_)
#define RND_SOURCE			"/dev/urandom"
#else
#define RND_SOURCE			"/dev/random"
#endif
#else
#include <windows.h>
#include <wincrypt.h>
#endif
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>



/*
 * AlgorithmIdentifier ::= SEQUENCE  {
 *    algorithm            OBJECT IDENTIFIER,
 *    parameters           ANY DEFINED BY algorithm OPTIONAL
 * }
 */
NH_NODE_WAY pkix_algid_map[] =
{
	{	/* AlgorithmIdentifier */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* algorithm */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_OBJECT_ID | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* parameters */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_ANY_TAG_BIT | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};


/** **********************
 *  Noise device functions
 *  **********************/
NH_UTILITY(NH_RV, NH_noise)(_OUT_ unsigned char *buffer, _IN_ size_t len)
{
	NH_RV rv = NH_OK;
#ifdef UNIX_IMPL
	FILE *rdev;

	if (!buffer) return NH_INVALID_ARG;
	if (!(rdev = fopen(RND_SOURCE, "rb"))) return (S_SYSERROR(errno) | NH_DEV_RND_ERROR);
	if (fread(buffer, sizeof(unsigned char), len, rdev) != len) rv = (S_SYSERROR(ferror(rdev)) | NH_DEV_RND_ERROR);
	fclose(rdev);
#else
	DWORD cbSize;
	LPTSTR pszName;
	HCRYPTPROV hProv;

	if (CryptGetDefaultProvider(PROV_RSA_FULL, NULL, CRYPT_USER_DEFAULT, NULL, &cbSize))
	{
		if ((pszName = (LPTSTR) malloc(cbSize)))
		{
			if
			(
				CryptGetDefaultProvider(PROV_RSA_FULL, NULL, CRYPT_USER_DEFAULT, pszName, &cbSize) &&
				CryptAcquireContext(&hProv, NULL, pszName, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)
			)
			{
				if (!CryptGenRandom(hProv, buffer, len)) rv = (S_SYSERROR(GetLastError()) | NH_DEV_RND_ERROR);
				CryptReleaseContext(hProv, 0);
			}
			else rv = (S_SYSERROR(GetLastError()) | NH_DEV_RND_ERROR);
			free(pszName);
		}
		else rv = NH_OUT_OF_MEMORY_ERROR;
	}
	else rv = (S_SYSERROR(GetLastError()) | NH_DEV_RND_ERROR);
#endif
	return rv;
}

NH_UTILITY(NH_RV, NH_seed)(_IN_ unsigned char *noise, _IN_ size_t len)
{
	if (!noise) return NH_INVALID_ARG;
	RAND_seed(noise, len);
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_rand)(_OUT_ unsigned char *buffer, _IN_ size_t len)
{
	if (!buffer) return NH_INVALID_ARG;
	if (!RAND_bytes(buffer, len)) return (S_SYSERROR(ERR_get_error()) | NH_RND_GEN_ERROR);
	return NH_OK;
}

NH_FUNCTION(void, NH_safe_zeroize)(_INOUT_ void *buffer, _IN_ size_t len)
{
	int i;
	if (buffer)
	{
		for (i = 0; i < NH_ZEROIZE_STEPS; i++) NH_rand(buffer, len);
		OPENSSL_cleanse(buffer, len);
	}
}


static NH_NOISE_HANDLER_STR hDevice =
{
	FALSE,
	NH_noise,
	NH_seed,
	NH_rand,
	NH_safe_zeroize
};

#if defined(_DEBUG_)
NH_FUNCTION(void*, debug_malloc)(size_t num)
{
	void *ret = malloc(num);
	VALGRIND_MAKE_MEM_DEFINED(ret, num);
	return ret;
}
#endif
INLINE NH_UTILITY(NH_RV, seed)()
{
	NH_RV rv = NH_OK;
	unsigned char seedb[NH_DEFAULT_SEED];
#if defined(_DEBUG_)
	void *(*r)(void *, size_t) = NULL;
	void (*f)(void *) = NULL;
#endif
	if (!hDevice.seeded)
	{
#if defined(_DEBUG_)
		CRYPTO_get_mem_functions(NULL, &r, &f);
		if (NH_FAIL(CRYPTO_set_mem_functions(debug_malloc, r, f))) return NH_OPENSSL_INIT_ERROR;
#endif
		if
		(
			NH_SUCCESS(rv = NH_noise(seedb, NH_DEFAULT_SEED)) &&
			NH_SUCCESS(rv = NH_seed((unsigned char*) seedb, NH_DEFAULT_SEED))
		)	hDevice.seeded = TRUE;
	}
	return rv;
}

NH_FUNCTION(NH_RV, NH_new_noise_device)(_OUT_ NH_NOISE_HANDLER *self)
{
	NH_NOISE_HANDLER out;
	NH_RV rv;
	if
	(
		NH_SUCCESS(rv = seed()) &&
		NH_SUCCESS(rv = (out = (NH_NOISE_HANDLER) malloc(sizeof(NH_NOISE_HANDLER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
	)
	{
		memcpy(out, &hDevice, sizeof(NH_NOISE_HANDLER_STR));
		*self = out;
	}
	return rv;
}

NH_FUNCTION(void, NH_release_noise_device)(_IN_ NH_NOISE_HANDLER self)
{
	if (self) free(self);
}


/** *******************************
 *  Shamir secret sharing functions
 *  *******************************/
NH_UTILITY(NH_RV, NH_set_share)(_INOUT_ NH_SHARE_HANDLER_STR *hShare, _IN_ unsigned char i, _IN_ NH_SHARE_STR *share)
{
	if (i >= hShare->count || !share || !share->y || share->ylen != hShare->shares[i]->ylen) return NH_INVALID_ARG;
	hShare->shares[i]->x = share->x;
	memcpy(hShare->shares[i]->y, share->y, hShare->shares[i]->ylen);
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_get_share)(_IN_ NH_SHARE_HANDLER_STR *hShare, _IN_ unsigned char i, _OUT_ NH_SHARE_STR *share)
{
	if (i >= hShare->count || !share || !share->y || share->ylen != hShare->shares[i]->ylen) return NH_INVALID_ARG;
	share->x = hShare->shares[i]->x;
	memcpy(share->y, hShare->shares[i]->y, hShare->shares[i]->ylen);
	return NH_OK;
}

#ifndef UNIX_IMPL
int random(void) { return rand(); }	/* Required only for libgfshare compiling */
#endif
INLINE NH_UTILITY(int, has_value)(_IN_ unsigned char *buffer, _IN_ size_t count, _IN_ unsigned char value)
{
    size_t i;
    for(i = 0; i < count; i++) if(buffer[i] == value) return TRUE;
    return FALSE;
}
INLINE NH_UTILITY(void, fill_no_zeros)(_INOUT_ unsigned char *buffer, _IN_ size_t count)
{
    size_t i;
    gfshare_fill_rand(buffer, count);
    for(i = 0; i < count; i++) while (buffer[i] == 0 || (i > 0 && has_value(buffer, i , *(buffer + i)))) gfshare_fill_rand((buffer + i), 1);
}
NH_UTILITY(void, rand_func)(unsigned char *buffer, unsigned int size)
{
	seed();
	NH_rand(buffer, size);
}
NH_UTILITY(NH_RV, NH_split_shares)
(
	_INOUT_ NH_SHARE_HANDLER_STR *self,
	_IN_ unsigned char *secret,
	_IN_ size_t size,
	_IN_ unsigned char k,
	_IN_ unsigned char n
)
{
	unsigned char i, *rnd_xxx;
	gfshare_ctx *G;
	NH_RV rv;

	if (k > n || n != self->count) return NH_INVALID_ARG;
	if (!(rnd_xxx = (unsigned char*) NH_MALLOC(n))) return NH_OUT_OF_MEMORY_ERROR;
	gfshare_fill_rand = rand_func;
	fill_no_zeros(rnd_xxx, n);
	if (NH_SUCCESS(rv = (G = gfshare_ctx_init_enc(rnd_xxx, n, k, size)) ? NH_OK : NH_SHARE_INIT_ERROR))
	{
		gfshare_ctx_enc_setsecret(G, (unsigned char*) secret);
		for (i = 0; i < n; i++)
		{
			self->shares[i]->x = rnd_xxx[i];
			gfshare_ctx_enc_getshare(G, i, self->shares[i]->y);
		}
		gfshare_ctx_free(G);
	}
	free(rnd_xxx);
	return rv;
}

NH_UTILITY(NH_RV, NH_join_shares)(_IN_ NH_SHARE_HANDLER_STR *self, _OUT_ unsigned char *secret)
{
	NH_RV rv;
	gfshare_ctx *G;
	unsigned char *x, i;

	if (!(x = (unsigned char*) malloc(self->count))) return NH_OUT_OF_MEMORY_ERROR;
	for (i = 0; i < self->count; i++) x[i] = self->shares[i]->x;

	if (NH_SUCCESS(rv = (G = gfshare_ctx_init_dec(x, self->count, self->shares[0]->ylen)) ? NH_OK : NH_SHARE_INIT_ERROR))
	{
		for (i = 0; i < self->count; i++) gfshare_ctx_dec_giveshare(G, i, self->shares[i]->y);
		gfshare_ctx_dec_extract(G, secret);
		gfshare_ctx_free(G);
	}
	free(x);
	return rv;

}

const static NH_SHARE_HANDLER_STR defShareHandler =
{
	NULL,
	0,
	NH_set_share,
	NH_get_share,
	NH_split_shares,
	NH_join_shares
};

NH_FUNCTION(NH_RV, NH_new_share)(_IN_ size_t size, _OUT_ NH_SHARE *share)
{
	NH_SHARE ret;

	if (!(ret = (NH_SHARE) malloc(sizeof(NH_SHARE_STR)))) return NH_OUT_OF_MEMORY_ERROR;
	memset(ret, 0, sizeof(NH_SHARE_STR));
	if (!(ret->y = (unsigned char*) malloc(size)))
	{
		free(ret);
		return NH_OUT_OF_MEMORY_ERROR;
	}
	memset(ret->y, 0, size);
	ret->ylen = size;
	*share = ret;
	return NH_OK;
}

NH_FUNCTION(NH_RV, NH_release_share)(_IN_ NH_SHARE share)
{
	if (share)
	{
		if (share->y)
		{
			NH_safe_zeroize(share->y, share->ylen);
			free(share->y);
		}
		free(share);
	}
	return NH_OK;
}

NH_FUNCTION(NH_RV, NH_new_secret_share)(_IN_ unsigned char count, _IN_ size_t size, _OUT_ NH_SHARE_HANDLER *hShare)
{
	NH_SHARE_HANDLER ret;
	NH_RV rv;
	unsigned char i = 0;

	if (!(ret = (NH_SHARE_HANDLER) malloc(sizeof(NH_SHARE_HANDLER_STR)))) return NH_OUT_OF_MEMORY_ERROR;
	memcpy(ret, &defShareHandler, sizeof(NH_SHARE_HANDLER_STR));
	if (NH_SUCCESS(rv = (ret->shares = (NH_SHARE*) malloc(count * sizeof(NH_SHARE))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		memset(ret->shares, 0, count * sizeof(NH_SHARE));
		ret->count = count;
		while (NH_SUCCESS(rv) && i < count)
		{
			rv = NH_new_share(size, &ret->shares[i]);
			i++;
		}
	}
	if (NH_SUCCESS(rv)) *hShare = ret;
	else NH_release_secret_share(ret);
	return rv;
}

NH_FUNCTION(NH_RV, NH_release_secret_share)(_IN_ NH_SHARE_HANDLER hShare)
{
	unsigned char i;

	if (!hShare) return NH_INVALID_ARG;
	for (i = 0; i < hShare->count; i++) NH_release_share(hShare->shares[i]);
	free(hShare->shares);
	free(hShare);
	return NH_OK;
}


/** **********************
 *  Hash functions
 *  **********************/
NH_UTILITY(NH_RV, NH_init_hash)(_INOUT_ NH_HASH_HANDLER_STR *hHash, _IN_ CK_MECHANISM_TYPE mechanism)
{
	const EVP_MD *md;

	switch (mechanism)
      {
	case CKM_SHA_1:
		md = EVP_sha1();
		break;
	case CKM_SHA256:
		md = EVP_sha256();
		break;
	case CKM_SHA512:
		md = EVP_sha512();
		break;
	case CKM_MD5:
		md = EVP_md5();
		break;
	case CKM_SHA224:
		md = EVP_sha224();
		break;
	case CKM_SHA384:
		md = EVP_sha384();
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
      }
	hHash->mechanism = mechanism;
	hHash->md = (EVP_MD*) md;
	return EVP_DigestInit_ex(hHash->ctx, hHash->md, NULL) ? NH_OK : NH_HASH_ERROR;
}

NH_UTILITY(NH_RV, NH_hash_update)(_IN_ NH_HASH_HANDLER_STR *hHash, _IN_ unsigned char *data, _IN_ size_t size)
{
	if (!hHash->md || hHash->mechanism == UINT_MAX) return NH_INVALID_STATE_ERROR;
	return EVP_DigestUpdate(hHash->ctx, data, size) ? NH_OK : NH_HASH_ERROR;
}

NH_UTILITY(NH_RV, NH_hash_finish)(_INOUT_ NH_HASH_HANDLER_STR *hHash, _OUT_ unsigned char *buffer, _INOUT_ size_t *size)
{
	int len;
	NH_RV rv;

	if (!hHash->md || hHash->mechanism == UINT_MAX) return NH_INVALID_STATE_ERROR;
	len = EVP_MD_CTX_size(hHash->ctx);
	if (!buffer)
	{
		*size = len;
		return NH_OK;
	}
	if (*size < len) return NH_BUF_TOO_SMALL;
	rv = EVP_DigestFinal_ex(hHash->ctx, buffer, (unsigned int*)size) ? NH_OK : NH_HASH_ERROR;
	hHash->md = NULL;
	hHash->mechanism = UINT_MAX;
	return rv;
}

NH_UTILITY(NH_RV, NH_digest)
(
	_INOUT_ NH_HASH_HANDLER_STR *hHash,
	_IN_ unsigned char *data,
	_IN_ size_t size,
	_OUT_ unsigned char *buffer,
	_INOUT_ size_t *bufsize
)
{
	int len;
	NH_RV rv;

	if (!hHash->md || hHash->mechanism == UINT_MAX) return NH_INVALID_STATE_ERROR;
	len = EVP_MD_CTX_size(hHash->ctx);
	if (!buffer)
	{
		*bufsize = len;
		return NH_OK;
	}
	if (*bufsize < len) return NH_BUF_TOO_SMALL;
	if (NH_FAIL(rv = hHash->update(hHash, data, size))) return rv;
	return hHash->finish(hHash, buffer, bufsize);
}

NH_UTILITY(NH_RV, NH_hash_copy)(_IN_ NH_HASH_HANDLER_STR *hCurrent, _OUT_ NH_HASH_HANDLER_STR **hNew)
{
	NH_RV rv;
	NH_HASH_HANDLER_STR *clone;

	if (!hCurrent->md || hCurrent->mechanism == UINT_MAX) return NH_INVALID_STATE_ERROR;
	if (NH_FAIL(rv = NH_new_hash(&clone))) return rv;
	clone->mechanism = hCurrent->mechanism;
	clone->md = hCurrent->md;
	if (NH_SUCCESS(rv = EVP_MD_CTX_copy_ex(clone->ctx, hCurrent->ctx) ? NH_OK : NH_HASH_ERROR)) *hNew = clone;
	else  NH_release_hash(clone);
	return rv;
}

const static NH_HASH_HANDLER_STR defHashHandler =
{
	UINT_MAX,
	NULL,
	NULL,
	NH_init_hash,
	NH_hash_update,
	NH_hash_finish,
	NH_digest,
	NH_hash_copy
};

NH_FUNCTION(NH_RV, NH_new_hash)(_OUT_ NH_HASH_HANDLER *hHandler)
{
	NH_HASH_HANDLER ret;
	NH_RV rv;
	EVP_MD_CTX *ctx;

      if (!(ret = (NH_HASH_HANDLER) malloc(sizeof(NH_HASH_HANDLER_STR)))) return NH_OUT_OF_MEMORY_ERROR;
      if (NH_SUCCESS(rv = (ctx = EVP_MD_CTX_create()) ? NH_OK : NH_HASH_ERROR))
	{
		memcpy(ret, &defHashHandler, sizeof(NH_HASH_HANDLER_STR));
		ret->ctx = ctx;
		*hHandler = ret;
	}
	else free(ret);
      return rv;
}

NH_FUNCTION(void, NH_release_hash)(_IN_ NH_HASH_HANDLER hHash)
{
	if (hHash)
	{
		if (hHash->ctx) EVP_MD_CTX_destroy(hHash->ctx);
		free(hHash);
	}
}


/** **********************
 *  Symetric key functions
 *  **********************/
NH_UTILITY(NH_RV, NH_generate_key)(_INOUT_ NH_SYMKEY_HANDLER_STR *self, _IN_ size_t keysize)
{
	NH_NOISE_HANDLER hNoise;
	NH_SYMKEY *key = NULL;
	NH_RV rv;

	if (self->key) return NH_INVALID_STATE_ERROR;
	switch (self->keygen)
	{
	case CKM_DES3_KEY_GEN:
		if (keysize != 24) return NH_INVALID_KEYSIZE_ERROR;
		break;
	case CKM_RC2_KEY_GEN:
		if (keysize < 40 || keysize > 128) return NH_INVALID_KEYSIZE_ERROR;
		break;
	case CKM_AES_KEY_GEN:
		if (keysize != 16 && keysize != 24 && keysize != 32) return NH_INVALID_KEYSIZE_ERROR;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if (NH_FAIL(rv = NH_new_noise_device(&hNoise))) return rv;
	rv = (key = (NH_SYMKEY*) malloc(sizeof(NH_SYMKEY))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv))
	{
		memset(key, 0, sizeof(NH_SYMKEY));
		rv = (key->data = (unsigned char*) NH_MALLOC(keysize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
		if (NH_SUCCESS(rv))
		{
			key->length = keysize;
			rv = hNoise->rand(key->data, keysize);
		}
	}
	if (NH_FAIL(rv))
	{
		if (key)
		{
			if (key->data)
			{
				hNoise->zeroize(key->data, keysize);
				free(key->data);
			}
			free(key);
		}
	}
	else self->key = key;
	NH_release_noise_device(hNoise);
	return rv;
}

NH_UTILITY(NH_RV, NH_new_iv)(_IN_ CK_MECHANISM_TYPE mechanism, _OUT_ NH_IV **iv)
{
	NH_IV *ret = NULL;
	size_t len = 0;
	unsigned char *piv;
	NH_NOISE_HANDLER hNoise;
	NH_RV rv;

	switch (mechanism)
	{
	case CKM_DES3_CBC:
	case CKM_RC2_CBC:
		len = 8;
		break;
	case CKM_AES_CBC:
		len = 16;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if (NH_SUCCESS(rv = NH_new_noise_device(&hNoise)))
	{
		if (NH_SUCCESS(rv = (piv = (unsigned char*) NH_MALLOC(len)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
		{
			if
			(
				NH_SUCCESS(rv = hNoise->rand(piv, len)) &&
				NH_SUCCESS(rv = (ret = (NH_IV*) malloc(sizeof(NH_IV))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			)
			{
				ret->data = piv;
				ret->length = len;
				*iv = ret;
			}
			else free(piv);
		}
		NH_release_noise_device(hNoise);
	}
	return rv;
}

NH_UTILITY(void, NH_release_iv)(_OUT_ NH_IV *iv)
{
	if (iv)
	{
		if (iv->data) free(iv->data);
		free (iv);
	}
}


NH_UTILITY(NH_RV, init_cipher)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ NH_IV *iv,
	int enc
)
{
	if (!self->key) return NH_INVALID_STATE_ERROR;
	if (!iv || !iv->data) return NH_INVALID_ARG;
	switch (mechanism)
	{
	case CKM_DES3_CBC:
		if (iv->length != 8) return NH_INVALID_IV_ERROR;
		self->cipher = (EVP_CIPHER*) EVP_des_ede3_cbc();
		break;
	case CKM_RC2_CBC:
		if (iv->length != 8) return NH_INVALID_IV_ERROR;
		self->cipher = (EVP_CIPHER*) EVP_rc2_cbc();
		break;
	case CKM_AES_CBC:
		if (iv->length != 16) return NH_INVALID_IV_ERROR;
		switch (self->key->length)
		{
		case 16:
			self->cipher = (EVP_CIPHER*) EVP_aes_128_cbc();
			break;
		case 24:
			self->cipher = (EVP_CIPHER*) EVP_aes_192_cbc();
			break;
		default: self->cipher = (EVP_CIPHER*) EVP_aes_256_cbc();
		}
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if (!EVP_CipherInit_ex(self->ctx, self->cipher, NULL, NULL, NULL, enc)) return NH_CIPHER_INIT_ERROR;
	if (!EVP_CIPHER_CTX_set_key_length(self->ctx, self->key->length)) return NH_CIPHER_KEYSIZE_ERROR;
	return EVP_CipherInit_ex(self->ctx, self->cipher, NULL, self->key->data, iv->data, enc) ? NH_OK : NH_CIPHER_INIT_ERROR;
}
INLINE NH_UTILITY(NH_RV, update_cipher)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_IN_ unsigned char *in,
	_IN_ size_t inlen,
	_OUT_ unsigned char *out,
	_INOUT_ size_t *outlen
)
{
	NH_RV rv;

	if (!in) return NH_INVALID_ARG;
	if (!self->cipher) return NH_INVALID_STATE_ERROR;
	rv = EVP_CipherUpdate(self->ctx, out, (int*) outlen, in, inlen) ? NH_OK : NH_CIPHER_ERROR;
	if (NH_FAIL(rv)) EVP_CIPHER_CTX_cleanup(self->ctx);
	return rv;
}
INLINE NH_UTILITY(NH_RV, final_cipher)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_OUT_ unsigned char *out,
	_INOUT_ size_t *outlen
)
{
	NH_RV rv;

	if (!self->cipher) return NH_INVALID_STATE_ERROR;
	rv = EVP_CipherFinal_ex(self->ctx, out, (int*) outlen) ? NH_OK : NH_CIPHER_ERROR;
	EVP_CIPHER_CTX_cleanup(self->ctx);
	self->cipher = NULL;
	return rv;
}

NH_UTILITY(NH_RV, NH_encrypt_init)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ NH_IV *iv
)
{
	return init_cipher(self, mechanism, iv, 1);
}

NH_UTILITY(NH_RV, NH_encrypt_update)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_IN_ unsigned char *in,
	_IN_ size_t inlen,
	_OUT_ unsigned char *out,
	_INOUT_ size_t *outlen
)
{
	size_t block;

	block = EVP_CIPHER_CTX_block_size(self->ctx) + inlen;
	if (!out)
	{
		*outlen = block;
		return NH_OK;
	}
	if (*outlen < block) return NH_BUF_TOO_SMALL;
	return update_cipher(self, in, inlen, out, outlen);
}

NH_UTILITY(NH_RV, NH_encrypt_final)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_OUT_ unsigned char *out,
	_INOUT_ size_t *outlen
)
{
	size_t block;

	block = EVP_CIPHER_CTX_block_size(self->ctx);
	if (!out)
	{
		*outlen = block;
		return NH_OK;
	}
	if (*outlen < block) return NH_BUF_TOO_SMALL;
	return final_cipher(self, out, outlen);
}

NH_UTILITY(NH_RV, NH_decrypt_init)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ NH_IV *iv
)
{
	return init_cipher(self, mechanism, iv, 0);
}

NH_UTILITY(NH_RV, NH_decrypt_update)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_IN_ unsigned char *in,
	_IN_ size_t inlen,
	_OUT_ unsigned char *out,
	_INOUT_ size_t *outlen
)
{
	if (inlen < EVP_CIPHER_CTX_block_size(self->ctx)) return NH_INVALID_ARG;
	if (!out)
	{
		*outlen = inlen;
		return NH_OK;
	}
	if (*outlen < inlen) return NH_BUF_TOO_SMALL;
	return update_cipher(self, in, inlen, out, outlen);
}

NH_UTILITY(NH_RV, NH_decrypt_final)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_OUT_ unsigned char *out,
	_INOUT_ size_t *outlen
)
{
	size_t block;

	block = EVP_CIPHER_CTX_block_size(self->ctx);
	if (!out)
	{
		*outlen = block;
		return NH_OK;
	}
	if (*outlen < block) return NH_BUF_TOO_SMALL;
	return final_cipher(self, out, outlen);
}

NH_UTILITY(NH_RV, NH_encrypt)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_IN_ unsigned char *in,
	_IN_ size_t inlen,
	_OUT_ unsigned char *out,
	_INOUT_ size_t *outlen
)
{
	NH_RV rv;
	size_t buflen, tmplen = NH_MAX_BLOCK_LENGTH;

	if (!in) return NH_INVALID_ARG;
	buflen = inlen + EVP_CIPHER_CTX_block_size(self->ctx);
	if (!out)
	{
		*outlen = buflen;
		return NH_OK;
	}
	if (*outlen < buflen) return NH_BUF_TOO_SMALL;
	if (NH_FAIL(rv = self->encrypt_update(self, in, inlen, out, &buflen))) return rv;
	rv = self->encrypt_final(self, out + buflen, &tmplen);
	if (NH_SUCCESS(rv)) *outlen = buflen + tmplen;
	return rv;
}

NH_UTILITY(NH_RV, NH_decrypt)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_IN_ unsigned char *in,
	_IN_ size_t inlen,
	_OUT_ unsigned char *out,
	_INOUT_ size_t *outlen
)
{
	NH_RV rv;
	size_t buflen, tmplen = NH_MAX_BLOCK_LENGTH;

	if (!in) return NH_INVALID_ARG;
	buflen = inlen;
	if (!out)
	{
		*outlen = buflen;
		return NH_OK;
	}
	if (*outlen < buflen) return NH_BUF_TOO_SMALL;
	if (NH_FAIL(rv = self->decrypt_update(self, in, inlen, out, &buflen))) return rv;
	rv = self->decrypt_final(self, out + buflen, &tmplen);
	if (NH_SUCCESS(rv)) *outlen = buflen + tmplen;
	return rv;
}

#define KEY_PLAIN_KNOWLEDGE_CHOICE		(NH_ASN1_OCTET_STRING | NH_ASN1_CHOICE_BIT)
#define KEY_CIPHER_KNOWLEDGE_CHOICE		(NH_ASN1_SEQUENCE | NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT)
NH_NODE_WAY symkey_map[] =
{
	{	/* SymKey */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* keygen */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* material/ secret */
		NH_SAIL_SKIP_EAST,
		KEY_PLAIN_KNOWLEDGE_CHOICE,
		NULL,
		0
	},
	{	/* code */
		NH_PARSE_ROOT,
		KEY_CIPHER_KNOWLEDGE_CHOICE,
		NULL,
		0
	}
};
NH_NODE_WAY cipher_text_map[] =
{
	{	/* code */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* cipher */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* iv */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* key */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, NH_encode_symkey)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_INOUT_ NH_SYMKEY_HANDLER_STR *hEncryption,
	_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder,
	_IN_ unsigned int path
)
{
	NH_RV rv;
	NH_ASN1_PNODE node;
	NH_IV *iv;
	unsigned char *buffer;
	size_t buflen;

	if (!self->key) return NH_INVALID_STATE_ERROR;
	if (!hEncoder) return NH_INVALID_ARG;
	if (!(node = hEncoder->sail(hEncoder->root, path))) return NH_CANNOT_SAIL;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hEncoder->put_little_integer(hEncoder, node, self->keygen))) return rv;

	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (!hEncryption)
	{
		node->knowledge = KEY_PLAIN_KNOWLEDGE_CHOICE;
		hEncoder->register_optional(node);
		if (NH_FAIL(rv = hEncoder->put_octet_string(hEncoder, node, self->key->data, self->key->length))) return rv;
	}
	else
	{
		if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, cipher_text_map, ASN_NODE_WAY_COUNT(cipher_text_map)))) return rv;
		if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hEncoder->put_little_integer(hEncoder, node, mechanism))) return rv;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hEncryption->new_iv(mechanism, &iv))) return rv;
		rv = hEncoder->put_octet_string(hEncoder, node, iv->data, iv->length);
		if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv)) rv = hEncryption->encrypt_init(hEncryption, mechanism, iv);
		if (NH_SUCCESS(rv))
		{
			rv = hEncryption->encrypt(hEncryption, self->key->data, self->key->length, NULL, &buflen);
			if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (buffer = (unsigned char*) malloc(buflen)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
			{
				rv = hEncryption->encrypt(hEncryption, self->key->data, self->key->length, buffer, &buflen);
				if (NH_SUCCESS(rv)) rv = hEncoder->put_octet_string(hEncoder, node, buffer, buflen);
				free(buffer);
			}
		}
		hEncryption->release_iv(iv);
	}
	return rv;
}

NH_UTILITY(NH_RV, NH_decode_symkey)
(
	_INOUT_ NH_SYMKEY_HANDLER_STR *self,
	_INOUT_ NH_SYMKEY_HANDLER_STR *hEncryption,
	_INOUT_ NH_ASN1_PARSER_HANDLE hParser,
	_IN_ unsigned int path
)
{
	NH_RV rv;
	NH_ASN1_PNODE node;
	CK_MECHANISM_TYPE mechanism;
	NH_IV iv;
	unsigned char *buffer;
	size_t buflen;
	NH_SYMKEY *key;

	if (self->key) return NH_INVALID_STATE_ERROR;
	if (!hParser) return NH_INVALID_ARG;
	if (!(node = hParser->sail(hParser->root, path))) return NH_CANNOT_SAIL;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hParser->parse_little_integer(hParser, node))) return rv;
	self->keygen = *(CK_MECHANISM_TYPE*) node->value;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (ASN_IS_TAG(node, KEY_PLAIN_KNOWLEDGE_CHOICE))
	{
		if (NH_FAIL(rv = hParser->parse_octetstring(hParser, node))) return rv;
		buflen = node->valuelen;
		if (!(buffer = (unsigned char*) malloc(buflen))) return NH_OUT_OF_MEMORY_ERROR;
		memcpy(buffer, node->value, buflen);
	}
	else
	{
		if (!hEncryption) return NH_INVALID_ARG;
		if (NH_FAIL(rv = hParser->map_from(hParser, node, cipher_text_map + 1, ASN_NODE_WAY_COUNT(cipher_text_map) - 1))) return rv;
		if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hParser->parse_little_integer(hParser, node))) return rv;
		mechanism = *(CK_MECHANISM_TYPE*) node->value;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hParser->parse_octetstring(hParser, node))) return rv;
		iv.data = (unsigned char*) node->value;
		iv.length = node->valuelen;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hParser->parse_octetstring(hParser, node))) return rv;
		if (NH_FAIL(rv = hEncryption->decrypt_init(hEncryption, mechanism, &iv))) return rv;
		if (NH_FAIL(rv = hEncryption->decrypt(hEncryption, (unsigned char*) node->value, node->valuelen, NULL, &buflen))) return rv;
		if (!(buffer = (unsigned char*) malloc(buflen))) return NH_OUT_OF_MEMORY_ERROR;
		rv = hEncryption->decrypt(hEncryption, (unsigned char*) node->value, node->valuelen, buffer, &buflen);
	}
	if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (key = (NH_SYMKEY*) malloc(sizeof(NH_SYMKEY))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		key->data = buffer;
		key->length = buflen;
		self->key = key;
	}
	else free(buffer);
	return rv;
}

NH_UTILITY(CK_KEY_TYPE, NH_key_type)(_IN_ NH_SYMKEY_HANDLER_STR *self)
{
	switch (self->keygen)
	{
	case CKM_DES3_KEY_GEN:
		return CKK_DES3;
	case CKM_RC2_KEY_GEN:
		return CKK_RC2;
	case CKM_AES_KEY_GEN:
		return CKK_AES;
	default: return CK_UNAVAILABLE_INFORMATION;
	}
}

NH_UTILITY(void, NH_set_key_gen)(_INOUT_ NH_SYMKEY_HANDLER_STR *self, _IN_ CK_KEY_TYPE keyType)
{
	switch (keyType)
	{
	case CKK_DES3:
		self->keygen = CKM_DES3_KEY_GEN;
		break;
	case CKK_RC2:
		self->keygen = CKM_RC2_KEY_GEN;
		break;
	case CKK_AES:
		self->keygen = CKM_AES_KEY_GEN;
		break;
	default: self->keygen = CK_UNAVAILABLE_INFORMATION;
	}
}

const static NH_SYMKEY_HANDLER_STR defSymHandler =
{
	UINT_MAX,
	NULL,
	NULL,
	NULL,
	NH_generate_key,
	NH_new_iv,
	NH_release_iv,
	NH_encrypt_init,
	NH_encrypt_update,
	NH_encrypt_final,
	NH_decrypt_init,
	NH_decrypt_update,
	NH_decrypt_final,
	NH_encrypt,
	NH_decrypt,
	NH_encode_symkey,
	NH_decode_symkey,
	NH_key_type,
	NH_set_key_gen
};

NH_FUNCTION(NH_RV, NH_new_symkey_handler)(_IN_ CK_MECHANISM_TYPE keygen, _OUT_ NH_SYMKEY_HANDLER *hHandler)
{
	EVP_CIPHER_CTX *ctx;
	NH_SYMKEY_HANDLER ret;
	NH_RV rv;

	seed();
	switch (keygen)
	{
	case CKM_DES3_KEY_GEN:
	case CKM_RC2_KEY_GEN:
	case CKM_AES_KEY_GEN:
	case CK_UNAVAILABLE_INFORMATION:
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
    #if OPENSSL_VERSION_NUMBER >= 0x10100001L
        if (!(ctx = EVP_CIPHER_CTX_new())) return NH_OUT_OF_MEMORY_ERROR;
    #else
        if (!(ctx = (EVP_CIPHER_CTX *) malloc(sizeof(EVP_CIPHER_CTX)))) return NH_OUT_OF_MEMORY_ERROR;
    #endif
	EVP_CIPHER_CTX_init(ctx);
	rv = (ret = (NH_SYMKEY_HANDLER) malloc(sizeof(NH_SYMKEY_HANDLER_STR))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv))
	{
		memcpy(ret, &defSymHandler, sizeof(NH_SYMKEY_HANDLER_STR));
		ret->keygen = keygen;
		ret->ctx = ctx;
		*hHandler = ret;
	}
	else free(ctx);
	return rv;
}

NH_FUNCTION(NH_RV, NH_release_symkey_handler)(_IN_ NH_SYMKEY_HANDLER hHandler)
{
	if (hHandler)
	{
		if (hHandler->ctx) EVP_CIPHER_CTX_free(hHandler->ctx);
		if (hHandler->key)
		{
			if (hHandler->key->data)
			{
				NH_safe_zeroize(hHandler->key->data, hHandler->key->length);
				free(hHandler->key->data);
			}
			free(hHandler->key);
		}
		free(hHandler);
	}
	return NH_OK;
}

/** **********************
 *  RSA key functions
 *  **********************/
NH_UTILITY(NH_RV, NH_RSA_pubkey_verify)
(
	_IN_ NH_RSA_PUBKEY_HANDLER_STR *hHandler,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ unsigned char *data,
	_IN_ size_t size,
	_IN_ unsigned char *signature,
	_IN_ size_t sigSize
)
{
	int nid;
	unsigned long e;
	char err[256];

	if (!data || !signature) return NH_INVALID_ARG;
	if (!hHandler->key) return NH_INVALID_STATE_ERROR;
	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		nid = NID_sha1;
		break;
	case CKM_SHA256_RSA_PKCS:
		nid = NID_sha256;
		break;
	case CKM_SHA384_RSA_PKCS:
		nid = NID_sha384;
		break;
	case CKM_SHA512_RSA_PKCS:
		nid = NID_sha512;
		break;
	case CKM_MD5_RSA_PKCS:
		nid = NID_md5;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if (!RSA_verify(nid, data, size, signature, sigSize, hHandler->key))
	{
		e = ERR_get_error();
		ERR_error_string(e, err);
		return S_SYSERROR(e) | NH_RSA_VERIFY_ERROR;;
	}
	return NH_OK;
	/*
	return RSA_verify(nid, data, size, signature, sigSize, hHandler->key) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_VERIFY_ERROR;
	*/
}

NH_UTILITY(NH_RV, NH_RSA_pubkey_encrypt)
(
	_IN_ NH_RSA_PUBKEY_HANDLER_STR *hHandler,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ unsigned char *data,
	_IN_ size_t size,
	_OUT_ unsigned char *ciphertext,
	_INOUT_ size_t *cipherSize
)
{
	int padding, flen;

	if (!data) return NH_INVALID_ARG;
	if (!hHandler->key) return NH_INVALID_STATE_ERROR;
	if (!ciphertext)
	{
		*cipherSize = RSA_size(hHandler->key);
		return NH_OK;
	}
	if (*cipherSize < RSA_size(hHandler->key)) return NH_BUF_TOO_SMALL;
	switch (mechanism)
	{
	case CKM_RSA_PKCS:
		padding = RSA_PKCS1_PADDING;
		flen = RSA_size(hHandler->key) - 11;
		break;
	case CKM_RSA_PKCS_OAEP:
		padding = RSA_PKCS1_OAEP_PADDING;
		flen = RSA_size(hHandler->key) - 41;
		break;
	case CKM_RSA_X_509:
		padding = RSA_NO_PADDING;
		flen = RSA_size(hHandler->key);
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	if (size > flen) return NH_INVALID_ARG;
	return RSA_public_encrypt(size, data, ciphertext, hHandler->key, padding) != -1 ? NH_OK :  S_SYSERROR(ERR_get_error()) | NH_RSA_ENCRYPT_ERROR;
}

NH_NODE_WAY rsa_pubkey_map[] =
{
	{
		/* RSAKey */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0,
		NULL,
		0
	},
	{	/* modulus */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* exponent */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* bits */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
NH_NODE_WAY pubkey_map[] =
{
	{	/* PubliCKey */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* keytype */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* key/RSAKey */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_CHOICE_BIT,
		NULL,
		0
	},
	{	/* key/DSAKey */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT,
		NULL,
		0
	}
};

NH_UTILITY(NH_RV, encode_bignum)(_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder, _INOUT_ NH_ASN1_PNODE node, _IN_ BIGNUM *n)
{
	NH_RV rv;
	unsigned char *buffer;
	size_t num_bytes, offset;

	num_bytes = BN_num_bytes(n);
	offset = (BN_num_bits(n) == num_bytes * 8) ? 1 : 0;
	if (!(buffer = (unsigned char*) malloc(num_bytes + offset))) return NH_OUT_OF_MEMORY_ERROR;
	memset(buffer, 0, num_bytes + offset);
	BN_bn2bin(n, buffer + offset);
	rv = hEncoder->put_integer(hEncoder, node, buffer, num_bytes + offset);
	free(buffer);
	return rv;
}

NH_UTILITY(NH_RV, NH_RSA_pubkey_encode)
(
	_IN_ NH_RSA_PUBKEY_HANDLER_STR *hHandler,
	_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder,
	_IN_ unsigned int path
)
{
	NH_RV rv;
	NH_ASN1_PNODE node;
	BIGNUM *e;
	BIGNUM *n;


	if (!hHandler->key) return NH_INVALID_STATE_ERROR;
	if (!hEncoder) return NH_INVALID_ARG;
	if (!(node = hEncoder->sail(hEncoder->root, path))) return NH_CANNOT_SAIL;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hEncoder->put_little_integer(hEncoder, node, CKK_RSA))) return rv;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, rsa_pubkey_map, ASN_NODE_WAY_COUNT(rsa_pubkey_map)))) return rv;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;

    #if OPENSSL_VERSION_NUMBER >= 0x10100001L
	RSA_get0_key((const RSA *)hHandler->key, (const BIGNUM **)&n, (const BIGNUM **)&e, NULL);
    #else
	n=hHandler->key->n;
	e=hHandler->key->e;
    #endif
	if (NH_FAIL(rv = encode_bignum(hEncoder, node, n))) return rv;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	return encode_bignum(hEncoder, node, e);
}

NH_UTILITY(NH_RV, decode_bignum)(_INOUT_ NH_ASN1_PARSER_HANDLE hParser, _INOUT_ NH_ASN1_PNODE node, _OUT_ NH_BIG_INTEGER *n)
{
	NH_RV rv;
	unsigned char *buffer;
	size_t buflen;

	if (NH_SUCCESS(rv = hParser->parse_integer(node)))
	{
		buffer = node->value;
		buflen = node->valuelen;;
		if (!buffer[0])
		{
			buffer++;
			buflen--;
		}
		n->data = buffer;
		n->length = buflen;
	}
	return rv;
}
NH_UTILITY(NH_RV, NH_RSA_pubkey_decode)
(
	_INOUT_ NH_RSA_PUBKEY_HANDLER_STR *hHandler,
	_INOUT_ NH_ASN1_PARSER_HANDLE hParser,
	_IN_ unsigned int path
)
{
	NH_RV rv;
	NH_ASN1_PNODE node;
	NH_BIG_INTEGER n, e;

	if (hHandler->key) return NH_INVALID_STATE_ERROR;
	if (!hParser) return NH_INVALID_ARG;
	if (!(node = hParser->sail(hParser->root, path))) return NH_CANNOT_SAIL;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hParser->parse_little_integer(hParser, node))) return rv;
	if (*(CK_KEY_TYPE*) node->value != CKK_RSA) return NH_INVALID_STATE_ERROR;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hParser->map_from(hParser, node, rsa_pubkey_map, ASN_NODE_WAY_COUNT(rsa_pubkey_map)))) return rv;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = decode_bignum(hParser, node, &n))) return rv;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = decode_bignum(hParser, node, &e))) return rv;
	return hHandler->create(hHandler, &n, &e);
}

NH_UTILITY(NH_RV, NH_RSA_pubkey_create)
(
	_INOUT_ NH_RSA_PUBKEY_HANDLER_STR *hHandler,
	_IN_ NH_BIG_INTEGER *n,
	_IN_ NH_BIG_INTEGER *e
)
{
	NH_RV rv;
	RSA *key;
    #if OPENSSL_VERSION_NUMBER >= 0x10100001L
	BIGNUM *_e;
	BIGNUM *_n;
    #endif

	if (!n || !e || !n->data || !e->data) return NH_INVALID_ARG;
	if (hHandler->key) return NH_INVALID_STATE_ERROR;
	if (!(key = RSA_new())) return S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;

    #if OPENSSL_VERSION_NUMBER >= 0x10100001L
	rv = (_n = BN_bin2bn(n->data, n->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv)) rv = (_e = BN_bin2bn(e->data, e->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv)) rv = RSA_set0_key(hHandler->key, _n, _e, NULL) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
    #else
	rv = (key->n = BN_bin2bn(n->data, n->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv)) rv = (key->e = BN_bin2bn(e->data, e->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
    #endif
	if (NH_SUCCESS(rv))
	{
		hHandler->key = key;
		hHandler->size = RSA_size(key);
	}
	else RSA_free(key);
	return rv;
}

NH_UTILITY(NH_RV, NH_RSA_pubkey_clone)(_IN_ NH_RSA_PUBKEY_HANDLER_STR *hHandler, _OUT_ NH_RSA_PUBKEY_HANDLER_STR **hDolly)
{
	NH_RV rv;
	RSA *dolly;
	NH_RSA_PUBKEY_HANDLER hNew;
	BIGNUM *e;
	BIGNUM *n;


	if (hHandler->key) return NH_INVALID_STATE_ERROR;

#if OPENSSL_VERSION_NUMBER >= 0x10100001L
	RSA_get0_key((const RSA *)hHandler->key,(const BIGNUM **)&n,(const BIGNUM **)&e,NULL);
#else
	e=hHandler->key->e;
	n=hHandler->key->n;
#endif

	if (!(dolly = RSA_new())) return S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv = (n = BN_dup(n)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR)) rv = (e = BN_dup(e)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;

#if OPENSSL_VERSION_NUMBER >= 0x10100001L
	rv = RSA_set0_key(hHandler->key,n,e,NULL) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
#endif

	if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_RSA_pubkey_handler(&hNew)))
	{
		hNew->key = dolly;
		hNew->size = RSA_size(dolly);
		*hDolly = hNew;
	}
	if (NH_FAIL(rv)) RSA_free(dolly);
	return rv;
}

NH_UTILITY(size_t, NH_rsa_pubkey_size)(_IN_ NH_RSA_PUBKEY_HANDLER_STR *hHandler)
{
	size_t size = sizeof(NH_RSA_PUBKEY_HANDLER_STR);
	BIGNUM *e=NULL;
	BIGNUM *n=NULL;


	if (hHandler->key)
	{
		#if OPENSSL_VERSION_NUMBER >= 0x10100001L
			RSA_get0_key((const RSA *)hHandler->key,(const BIGNUM **)&n,(const BIGNUM **)&e,NULL);
		#else
			e=hHandler->key->e;
			n=hHandler->key->n;
		#endif
		if (n) size += BN_num_bytes(n);
		if (e) size += BN_num_bytes(e);
	}
	return size;
}

static const NH_RSA_PUBKEY_HANDLER_STR defRSAPubKeyHandler =
{
	NULL,
	0,
	NH_RSA_pubkey_verify,
	NH_RSA_pubkey_encrypt,
	NH_RSA_pubkey_encode,
	NH_RSA_pubkey_decode,
	NH_RSA_pubkey_create,
	NH_RSA_pubkey_clone,
	NH_rsa_pubkey_size
};

NH_FUNCTION(NH_RV, NH_new_RSA_pubkey_handler)(_OUT_ NH_RSA_PUBKEY_HANDLER *hHandler)
{
	NH_RSA_PUBKEY_HANDLER out;

	if (!(out = (NH_RSA_PUBKEY_HANDLER) malloc((sizeof(NH_RSA_PUBKEY_HANDLER_STR))))) return NH_OUT_OF_MEMORY_ERROR;
	memcpy(out, &defRSAPubKeyHandler, sizeof(NH_RSA_PUBKEY_HANDLER_STR));
	*hHandler = out;
	return NH_OK;
}

NH_FUNCTION(NH_RV, NH_release_RSA_pubkey_handler)(_IN_ NH_RSA_PUBKEY_HANDLER hHandler)
{
	if (hHandler)
	{
		if (hHandler->key) RSA_free(hHandler->key);
		free(hHandler);
	}
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_RSA_privkey_sign)
(
	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ unsigned char *data,
	_IN_ size_t size,
	_OUT_ unsigned char *signature,
	_INOUT_ size_t *sigSize
)
{
	int rsa_size, nid;
	NH_RV rv;

	if (!data) return NH_INVALID_ARG;
	if (!hHandler->key) return NH_INVALID_STATE_ERROR;
	rsa_size = RSA_size(hHandler->key);
	if (!signature)
	{
		*sigSize = rsa_size;
		return NH_OK;
	}
	if (*sigSize < rsa_size) return NH_BUF_TOO_SMALL;
	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		nid = NID_sha1;
		break;
	case CKM_SHA256_RSA_PKCS:
		nid = NID_sha256;
		break;
	case CKM_SHA384_RSA_PKCS:
		nid = NID_sha384;
		break;
	case CKM_SHA512_RSA_PKCS:
		nid = NID_sha512;
		break;
	case CKM_MD5_RSA_PKCS:
		nid = NID_md5;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	rv = RSA_sign(nid, data, (unsigned int)size, signature, (unsigned int*)sigSize, hHandler->key) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_SIGN_ERROR;
	return rv;
}

NH_UTILITY(NH_RV, NH_RSA_privkey_decrypt)
(
	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ unsigned char *ciphertext,
	_IN_ size_t cipherSize,
	_OUT_ unsigned char *plaintext,
	_INOUT_ size_t *plainSize
)
{
	int rsa_size, padding, decoded;

	if (!ciphertext) return NH_INVALID_ARG;
	if (!hHandler->key) return NH_INVALID_STATE_ERROR;
	rsa_size = RSA_size(hHandler->key);
	if (!plaintext)
	{
		*plainSize = rsa_size;
		return NH_OK;
	}
	if (*plainSize < rsa_size) return NH_BUF_TOO_SMALL;
	switch (mechanism)
	{
	case CKM_RSA_PKCS:
		padding = RSA_PKCS1_PADDING;
		break;
	case CKM_RSA_PKCS_OAEP:
		padding = RSA_PKCS1_OAEP_PADDING;
		break;
	case CKM_RSA_X_509:
		padding = RSA_NO_PADDING;
		break;
	default: return NH_UNSUPPORTED_MECH_ERROR;
	}
	decoded = RSA_private_decrypt(cipherSize, ciphertext, plaintext, hHandler->key, padding);
	if (decoded != -1) *plainSize = decoded;
	return decoded != -1 ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_DECRYPT_ERROR;
}

NH_NODE_WAY privatekey_map[] =
{
	{	/* PrivateKey */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* keytype */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* key/RSAPrivKey */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_CHOICE_BIT,
		NULL,
		0
	},
	{	/* key/DSAPrivKey */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT,
		NULL,
		0
	}
};
NH_NODE_WAY rsa_privkey_map[] =
{
	{
		/* RSAPrivKey */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0,
		NULL,
		0
	},
	{	/* modulus */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* pubExponent */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	},
	{	/* sensitive/plain */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_CHOICE_BIT,
		NULL,
		0
	},
	{	/* sensitive/cipher */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_CHOICE_BIT | NH_ASN1_CHOICE_END_BIT,
		NULL,
		0
	}
};
NH_NODE_WAY rsa_keymaterial_map[] =
{
	{	/* sensitive/plain */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0,
		NULL,
		0
	},
	{	/* privExponent */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* prime1 */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0,
		NULL,
		0
	},
	{	/* prime2 */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1,
		NULL,
		0
	},
	{	/* exponent1 */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_2,
		NULL,
		0
	},
	{	/* exponent2 */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_3,
		NULL,
		0
	},
	{	/* coefficient */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_4,
		NULL,
		0
	}
};
NH_NODE_WAY rsa_encryptedmaterial_map[] =
{
	{	/* sensitive/cipher */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1,
		NULL,
		0
	},
	{	/* cipher */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* iv */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* privExponent */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* prime1 */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0,
		NULL,
		0
	},
	{	/* prime2 */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1,
		NULL,
		0
	},
	{	/* exponent1 */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_2,
		NULL,
		0
	},
	{	/* exponent2 */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_3,
		NULL,
		0
	},
	{	/* coefficient */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_4,
		NULL,
		0
	},
};
NH_UTILITY(NH_RV, encode_encrypted_bignum)
(
	_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder,
	NH_ASN1_PNODE node,
	_IN_ BIGNUM *n,
	_INOUT_ NH_SYMKEY_HANDLER hEncryption,
	_IN_ CK_MECHANISM_TYPE mechanism,
	NH_IV *iv
)
{
	NH_RV rv;
	unsigned char *big, *buffer;
	size_t num_bytes, buflen;

	num_bytes = BN_num_bytes(n);
	if (!(big = (unsigned char*) malloc(num_bytes))) return NH_OUT_OF_MEMORY_ERROR;
	memset(big, 0, num_bytes);
	num_bytes = BN_bn2bin(n, big);
	if (NH_SUCCESS(rv = hEncryption->encrypt_init(hEncryption, mechanism, iv)))
	{
		rv = hEncryption->encrypt(hEncryption, big, num_bytes, NULL, &buflen);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (buffer = (unsigned char*) malloc(buflen)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
		{
			rv = hEncryption->encrypt(hEncryption, big, num_bytes, buffer, &buflen);
			if (NH_SUCCESS(rv)) rv = hEncoder->put_octet_string(hEncoder, node, buffer, buflen);
			free(buffer);
		}
	}
	free(big);
	return rv;
}
NH_UTILITY(NH_RV, NH_RSA_privkey_encode)
(
	_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_INOUT_ NH_SYMKEY_HANDLER hEncryption,
	_INOUT_ NH_ASN1_ENCODER_HANDLE hEncoder,
	_IN_ unsigned int path
)
{
	NH_RV rv;
	NH_ASN1_PNODE node;
	NH_IV *iv;
	BIGNUM *e;
	BIGNUM *n;
	BIGNUM *d;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;


	if (!hHandler->key) return NH_INVALID_STATE_ERROR;
	if (!hEncoder) return NH_INVALID_ARG;
	if (!(node = hEncoder->sail(hEncoder->root, path))) return NH_CANNOT_SAIL;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hEncoder->put_little_integer(hEncoder, node, CKK_RSA))) return rv;

	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, rsa_privkey_map, ASN_NODE_WAY_COUNT(rsa_privkey_map)))) return rv;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;



#if OPENSSL_VERSION_NUMBER >= 0x10100001L
	RSA_get0_key((const RSA *)hHandler->key,(const BIGNUM **)&n,(const BIGNUM **)&e,(const BIGNUM **)&d);
	RSA_get0_factors((const RSA *)hHandler->key,(const BIGNUM **)&p,(const BIGNUM **)&q);
	RSA_get0_crt_params((const RSA *)hHandler->key,(const BIGNUM **)&dmp1,(const BIGNUM **)&dmq1,(const BIGNUM **)&iqmp);
#else
	e=hHandler->key->e;
	n=hHandler->key->n;
	d=hHandler->key->d;
	p=hHandler->key->p;
	q=hHandler->key->q;
	dmp1=hHandler->key->dmp1;
	dmq1=hHandler->key->dmq1;
	iqmp=hHandler->key->iqmp;
#endif

	if (NH_FAIL(rv = encode_bignum(hEncoder, node, n))) return rv;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (e)
	{
		node->knowledge = NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_OPTIONAL_BIT;
		hEncoder->register_optional(node);
		if (NH_FAIL(rv = encode_bignum(hEncoder, node, e))) return rv;
	}

	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (!hEncryption)
	{
		if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, rsa_keymaterial_map, ASN_NODE_WAY_COUNT(rsa_keymaterial_map)))) return rv;
		if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = encode_bignum(hEncoder, node, d))) return rv;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (p)
		{
			node->knowledge = NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0;
			hEncoder->register_optional(node);
			if (NH_FAIL(rv = encode_bignum(hEncoder, node, p))) return rv;
		}
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (q)
		{
			node->knowledge = NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1;
			hEncoder->register_optional(node);
			if (NH_FAIL(rv = encode_bignum(hEncoder, node, q))) return rv;
		}
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (dmp1)
		{
			node->knowledge = NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_2;
			hEncoder->register_optional(node);
			if (NH_FAIL(rv = encode_bignum(hEncoder, node, dmp1))) return rv;
		}
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (dmq1)
		{
			node->knowledge = NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_3;
			hEncoder->register_optional(node);
			if (NH_FAIL(rv = encode_bignum(hEncoder, node, dmq1))) return rv;
		}
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (iqmp)
		{
			node->knowledge = NH_ASN1_INTEGER | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_4;
			hEncoder->register_optional(node);
			if (NH_FAIL(rv = encode_bignum(hEncoder, node, iqmp))) return rv;
		}
	}

	else
	{
		if (NH_FAIL(rv = hEncoder->chart_from(hEncoder, node, rsa_encryptedmaterial_map, ASN_NODE_WAY_COUNT(rsa_encryptedmaterial_map)))) return rv;
		if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hEncoder->put_little_integer(hEncoder, node, mechanism))) return rv;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hEncryption->new_iv(mechanism, &iv))) return rv;
		rv = hEncoder->put_octet_string(hEncoder, node, iv->data, iv->length);
		if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv)) rv = encode_encrypted_bignum(hEncoder, node, d, hEncryption, mechanism, iv);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING) && p)  rv = encode_encrypted_bignum(hEncoder, node, p, hEncryption, mechanism, iv);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING) && q)  rv = encode_encrypted_bignum(hEncoder, node, q, hEncryption, mechanism, iv);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING) && dmp1)  rv = encode_encrypted_bignum(hEncoder, node, dmp1, hEncryption, mechanism, iv);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING) && dmq1)  rv = encode_encrypted_bignum(hEncoder, node, dmq1, hEncryption, mechanism, iv);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING) && iqmp)  rv = encode_encrypted_bignum(hEncoder, node, iqmp, hEncryption, mechanism, iv);
		hEncryption->release_iv(iv);
	}
	return rv;
}

NH_UTILITY(NH_RV, decode_encrypted_bignum)
(
	_INOUT_ NH_ASN1_PNODE node,
	_INOUT_ NH_SYMKEY_HANDLER hEncryption,
	_IN_ CK_MECHANISM_TYPE mechanism,
	_IN_ NH_IV *iv,
	_OUT_ NH_BIG_INTEGER *n
)
{
	NH_RV rv;
	unsigned char *buffer;
	size_t buflen;

	if (NH_FAIL(rv = hEncryption->decrypt_init(hEncryption, mechanism, iv))) return rv;
	if (NH_FAIL(rv = hEncryption->decrypt(hEncryption, (unsigned char*) node->value, node->valuelen, NULL, &buflen))) return rv;
	if (!(buffer = (unsigned char*) malloc(buflen))) return NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv = hEncryption->decrypt(hEncryption, (unsigned char*) node->value, node->valuelen, buffer, &buflen)))
	{
		n->data = buffer;
		n->length = buflen;
	}
	else free(buffer);
	return rv;
}
NH_UTILITY(NH_RV, NH_RSA_privkey_decode)
(
	_INOUT_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler,
	_INOUT_ NH_SYMKEY_HANDLER hEncryption,
	_INOUT_ NH_ASN1_PARSER_HANDLE hParser,
	_IN_ unsigned int path
)
{
	NH_RV rv;
	NH_ASN1_PNODE node;
	NH_BIG_INTEGER n, e, d, p, q, dmp, dmq, qmp;
	CK_MECHANISM_TYPE mechanism;
	NH_IV iv;
	CK_BBOOL clean = CK_FALSE;

	if (hHandler->key) return NH_INVALID_STATE_ERROR;
	if (!hParser) return NH_INVALID_ARG;
	d.data = NULL;
	e.data = NULL;
	p.data = NULL;
	q.data = NULL;
	dmp.data = NULL;
	dmq.data = NULL;
	qmp.data = NULL;
	if (!(node = hParser->sail(hParser->root, path))) return NH_CANNOT_SAIL;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hParser->parse_little_integer(hParser, node))) return rv;
	if (*(CK_KEY_TYPE*) node->value != CKK_RSA) return NH_INVALID_STATE_ERROR;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = hParser->map_from(hParser, node, rsa_privkey_map, ASN_NODE_WAY_COUNT(rsa_privkey_map)))) return rv;
	if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = decode_bignum(hParser, node, &n))) return rv;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (ASN_IS_PRESENT(node) && NH_FAIL(rv = decode_bignum(hParser, node, &e))) return rv;
	if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
	if (ASN_IS_CONSTRUCTED(*node->identifier) && ASN_IS_ON(NH_ASN1_CONTEXT, *node->identifier) && ((NH_ASN1_TAG_MASK & *node->identifier) == NH_ASN1_CT_TAG_0))
	{
		if (NH_FAIL(rv = hParser->map_from(hParser, node, rsa_keymaterial_map + 1, ASN_NODE_WAY_COUNT(rsa_keymaterial_map) - 1))) return rv;
		if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = decode_bignum(hParser, node, &d))) return rv;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (ASN_IS_PRESENT(node) && NH_FAIL(rv = decode_bignum(hParser, node, &p))) return rv;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (ASN_IS_PRESENT(node) && NH_FAIL(rv = decode_bignum(hParser, node, &q))) return rv;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (ASN_IS_PRESENT(node) && NH_FAIL(rv = decode_bignum(hParser, node, &dmp))) return rv;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (ASN_IS_PRESENT(node) && NH_FAIL(rv = decode_bignum(hParser, node, &dmq))) return rv;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (ASN_IS_PRESENT(node) && NH_FAIL(rv = decode_bignum(hParser, node, &qmp))) return rv;
	}
	else
	{
		if (!hEncryption) return NH_INVALID_ARG;
		if (NH_FAIL(rv = hParser->map_from(hParser, node, rsa_encryptedmaterial_map + 1, ASN_NODE_WAY_COUNT(rsa_encryptedmaterial_map) - 1))) return rv;
		if (!(node = node->child)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hParser->parse_little_integer(hParser, node))) return rv;
		mechanism = *(CK_MECHANISM_TYPE*) node->value;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hParser->parse_octetstring(hParser, node))) return rv;
		iv.data = (unsigned char*) node->value;
		iv.length = node->valuelen;
		if (!(node = node->next)) return NH_UNEXPECTED_ENCODING;
		if (NH_FAIL(rv = hParser->parse_octetstring(hParser, node))) return rv;
		rv = decode_encrypted_bignum(node, hEncryption, mechanism, &iv, &d);
		if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv) && ASN_IS_PRESENT(node))
		{
			rv = hParser->parse_octetstring(hParser, node);
			if (NH_SUCCESS(rv)) rv = decode_encrypted_bignum(node, hEncryption, mechanism, &iv, &p);
		}
		if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv) && ASN_IS_PRESENT(node))
		{
			rv = hParser->parse_octetstring(hParser, node);
			if (NH_SUCCESS(rv)) rv = decode_encrypted_bignum(node, hEncryption, mechanism, &iv, &q);
		}
		if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv) && ASN_IS_PRESENT(node))
		{
			rv = hParser->parse_octetstring(hParser, node);
			if (NH_SUCCESS(rv)) rv = decode_encrypted_bignum(node, hEncryption, mechanism, &iv, &dmp);
		}
		if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv) && ASN_IS_PRESENT(node))
		{
			rv = hParser->parse_octetstring(hParser, node);
			if (NH_SUCCESS(rv)) rv = decode_encrypted_bignum(node, hEncryption, mechanism, &iv, &dmq);
		}
		if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
		if (NH_SUCCESS(rv) && ASN_IS_PRESENT(node))
		{
			rv = hParser->parse_octetstring(hParser, node);
			if (NH_SUCCESS(rv)) rv = decode_encrypted_bignum(node, hEncryption, mechanism, &iv, &qmp);
		}
		clean = CK_TRUE;
	}
	if (NH_SUCCESS(rv)) rv = hHandler->create(hHandler, &n, e.data ? &e : NULL, &d, p.data ? &p : NULL, q.data ? &q : NULL, dmp.data ? &dmp : NULL, dmq.data ? &dmq : NULL, qmp.data ? &qmp : NULL);
	if (clean)
	{
		if (d.data) free(d.data);
		if (p.data) free(p.data);
		if (q.data) free(q.data);
		if (dmp.data) free(dmp.data);
		if (dmq.data) free(dmq.data);
		if (qmp.data) free(qmp.data);
	}
	return rv;
}

NH_UTILITY(NH_RV, NH_RSA_privkey_create)
(
	_INOUT_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler,
	_IN_ NH_BIG_INTEGER *n,
	_IN_ NH_BIG_INTEGER *e,
	_IN_ NH_BIG_INTEGER *d,
	_IN_ NH_BIG_INTEGER *p,
	_IN_ NH_BIG_INTEGER *q,
	_IN_ NH_BIG_INTEGER *dmp,
	_IN_ NH_BIG_INTEGER *dmq,
	_IN_ NH_BIG_INTEGER *qmp
)
{
	NH_RV rv;
	RSA *key;

	BIGNUM *_e;
	BIGNUM *_n;
	BIGNUM *_d;
	BIGNUM *_p;
	BIGNUM *_q;
	BIGNUM *_dmp1;
	BIGNUM *_dmq1;
	BIGNUM *_iqmp;



	if (!n || !n->data || !d || !d->data || (e && !e->data) || (p && !p->data) || (q && !q->data) || (dmp && !dmp->data) || (dmq && !dmq->data) || (qmp && !qmp->data)) return NH_INVALID_ARG;
	if (hHandler->key) return NH_INVALID_STATE_ERROR;
	if (!(key = RSA_new())) return S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	rv = (_n = BN_bin2bn(n->data, n->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv)) rv = (_d = BN_bin2bn(d->data, d->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv) && e) rv = (_e = BN_bin2bn(e->data, e->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv) && p) rv = (_p = BN_bin2bn(p->data, p->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv) && q) rv = (_q = BN_bin2bn(q->data, q->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv) && dmp) rv = (_dmp1 = BN_bin2bn(dmp->data, dmp->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv) && dmq) rv = (_dmq1 = BN_bin2bn(dmq->data, dmq->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv) && qmp) rv = (_iqmp = BN_bin2bn(qmp->data, qmp->length, NULL)) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;

#if OPENSSL_VERSION_NUMBER >= 0x10100001L

	if (NH_SUCCESS(rv)) rv = RSA_set0_key(key,_n,_e,_d) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv)) rv = RSA_set0_factors(key,_p,_q) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv)) rv = RSA_set0_crt_params(key,_dmp1,_dmq1,_iqmp) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_IMPORT_ERROR;
#else
	key->e=_e;
	key->n=_n;
	key->d=_d;
	key->p=_p;
	key->q=_q;
	key->dmp1=_dmp1;
	key->dmq1=_dmq1;
	key->iqmp=_iqmp;
#endif

	if (NH_SUCCESS(rv) && p && e && q) rv = RSA_check_key(key) == 1 ? NH_OK : NH_RSA_IMPORT_ERROR;
	if (NH_SUCCESS(rv)) hHandler->key = key;
	else RSA_free(key);
	return rv;
}

const static NH_NODE_WAY privkey_info_map[] =
{
	{	/* PrivateKeyInfo */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* Version */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* PrivateKeyAlgorithmIdentifier */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		pkix_algid_map,
		PKIX_ALGID_COUNT
	},
	{	/* PrivateKey */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	}
};
const static NH_NODE_WAY rsa_privkey_pkcs_map[] =
{
	{	/* RSAPrivateKey */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* Version */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* modulus n */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* publicExponent e */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* privateExponent d */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* prime1 p */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* prime2 q */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* exponent1 dmp */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* exponent2 dmq */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* coefficient qmp */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	}
};
NH_UTILITY(NH_RV, NH_RSA_from_privkey_info)(_INOUT_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler, _IN_ unsigned char *encoding, _IN_ size_t size)
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node, pkey;
	NH_BIG_INTEGER n, e, d, p, q, dmp, dmq, qmp;

	if (NH_FAIL(rv = NH_new_parser(encoding, size, 16, 128, &hParser))) return rv;
	rv = hParser->map(hParser, privkey_info_map, ASN_NODE_WAY_COUNT(privkey_info_map));
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 16) | (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_oid(hParser, node);
	if (NH_SUCCESS(rv)) rv = NH_match_oid(rsaEncryption_oid, NHC_RSA_ENCRYPTION_OID_COUNT, node->value, node->valuelen) ? NH_OK : NH_UNSUP_PKEY_ERROR;
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | (NH_PARSE_EAST | 2))) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_octetstring(hParser, node);
	if (NH_SUCCESS(rv)) rv = (pkey = hParser->add_child(hParser->container, node)) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv))
	{
		pkey->identifier = node->value;
		rv = hParser->map_from(hParser, pkey, rsa_privkey_pkcs_map, ASN_NODE_WAY_COUNT(rsa_privkey_pkcs_map));
	}
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(pkey, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_integer(node);	/* modulus */
	if (NH_SUCCESS(rv)) rv = decode_bignum(hParser, node, &n);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_integer(node);	/* publicExponent */
	if (NH_SUCCESS(rv)) rv = decode_bignum(hParser, node, &e);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_integer(node);	/* privateExponent */
	if (NH_SUCCESS(rv)) rv = decode_bignum(hParser, node, &d);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_integer(node);	/* prime1 */
	if (NH_SUCCESS(rv)) rv = decode_bignum(hParser, node, &p);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_integer(node);	/* prime2 */
	if (NH_SUCCESS(rv)) rv = decode_bignum(hParser, node, &q);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_integer(node);	/* exponent1 */
	if (NH_SUCCESS(rv)) rv = decode_bignum(hParser, node, &dmp);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_integer(node);	/* exponent2 */
	if (NH_SUCCESS(rv)) rv = decode_bignum(hParser, node, &dmq);
	if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_integer(node);	/* coefficient */
	if (NH_SUCCESS(rv)) rv = decode_bignum(hParser, node, &qmp);
	if (NH_SUCCESS(rv)) rv = hHandler->create(hHandler, &n, &e, &d, &p, &q, &dmp, &dmq, &qmp);
	NH_release_parser(hParser);
	return rv;
}

NH_UTILITY(NH_RV, NH_RSA_privkey_clone)(_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler, _OUT_ NH_RSA_PRIVKEY_HANDLER_STR **hDolly)
{
	NH_RV rv;
	RSA *dolly;
	NH_RSA_PRIVKEY_HANDLER hNew;
	BIGNUM *e;
	BIGNUM *n;
	BIGNUM *d;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;

	if (hHandler->key) return NH_INVALID_STATE_ERROR;
	if (!(dolly = RSA_new())) return S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;

#if OPENSSL_VERSION_NUMBER >= 0x10100001L
	RSA_get0_key((const RSA *)hHandler->key,(const BIGNUM **)&n,(const BIGNUM **)&e,(const BIGNUM **)&d);
	RSA_get0_factors((const RSA *)hHandler->key,(const BIGNUM **)&p,(const BIGNUM **)&q);
	RSA_get0_crt_params((const RSA *)hHandler->key,(const BIGNUM **)&dmp1,(const BIGNUM **)&dmq1,(const BIGNUM **)&iqmp);
#else
	e=hHandler->key->e;
	n=hHandler->key->n;
	d=hHandler->key->d;
	p=hHandler->key->p;
	q=hHandler->key->q;
	dmp1=hHandler->key->dmp1;
	dmq1=hHandler->key->dmq1;
	iqmp=hHandler->key->iqmp;
#endif

	rv = (n = BN_dup(n)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv) && e) rv = (e = BN_dup(e)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv)) rv = (d = BN_dup(d)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv) && p) rv = (p = BN_dup(p)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv) && q) rv = (q = BN_dup(q)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv) && dmp1) rv = (dmp1 = BN_dup(dmp1)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv) && dmq1) rv = (dmq1 = BN_dup(dmq1)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv) && iqmp) rv = (iqmp = BN_dup(iqmp)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;

#if OPENSSL_VERSION_NUMBER >= 0x10100001L
	if (NH_SUCCESS(rv)) rv = RSA_set0_key(dolly->key,n,e,d) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv)) rv = RSA_set0_factors(dolly->key,p,q) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
	if (NH_SUCCESS(rv)) rv = RSA_set0_crt_params(dolly->key,dmp1,dmq1,iqmp) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_CLONE_ERROR;
#else
	dolly->key->e=e;
	dolly->key->n=n;
	dolly->key->d=d;
	dolly->key->p=p;
	dolly->key->q=q;
	dolly->key->dmp1=dmp1;
	dolly->key->dmq1=dmq1;
	dolly->key->iqmp=iqmp;
#endif

	if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_RSA_privkey_handler(&hNew)))
	{
		hNew->key = dolly;
		*hDolly = hNew;
	}
	if (NH_FAIL(rv)) RSA_free(dolly);
	return rv;
}

NH_UTILITY(size_t, NH_rsa_privkey_size)(_IN_ NH_RSA_PRIVKEY_HANDLER_STR *hHandler)
{
	size_t size = sizeof(NH_RSA_PRIVKEY_HANDLER_STR);
	BIGNUM *e;
	BIGNUM *n;
	BIGNUM *d;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;


	if (hHandler->key) return NH_INVALID_STATE_ERROR;

#if OPENSSL_VERSION_NUMBER >= 0x10100001L
	RSA_get0_key((const RSA *)hHandler->key,(const BIGNUM **)&n,(const BIGNUM **)&e,(const BIGNUM **)&d);
	RSA_get0_factors((const RSA *)hHandler->key,(const BIGNUM **)&p,(const BIGNUM **)&q);
	RSA_get0_crt_params((const RSA *)hHandler->key,(const BIGNUM **)&dmp1,(const BIGNUM **)&dmq1,(const BIGNUM **)&iqmp);
#else
	e=hHandler->key->e;
	n=hHandler->key->n;
	d=hHandler->key->d;
	p=hHandler->key->p;
	q=hHandler->key->q;
	dmp1=hHandler->key->dmp1;
	dmq1=hHandler->key->dmq1;
	iqmp=hHandler->key->iqmp;
#endif

	if (hHandler->key)
	{
		if (n) size += BN_num_bytes(n);
		if (e) size += BN_num_bytes(e);
		if (d) size += BN_num_bytes(d);
		if (p) size += BN_num_bytes(p);
		if (q) size += BN_num_bytes(q);
		if (dmp1) size += BN_num_bytes(dmp1);
		if (dmq1) size += BN_num_bytes(dmq1);
		if (iqmp) size += BN_num_bytes(iqmp);
	}
	return size;
}

static const NH_RSA_PRIVKEY_HANDLER_STR defRSAPrivKeyHandler =
{
	NULL,
	NH_RSA_privkey_sign,
	NH_RSA_privkey_decrypt,
	NH_RSA_privkey_encode,
	NH_RSA_privkey_decode,
	NH_RSA_privkey_create,
	NH_RSA_privkey_clone,
	NH_rsa_privkey_size,
	NH_RSA_from_privkey_info
};

NH_FUNCTION(NH_RV, NH_new_RSA_privkey_handler)(_OUT_ NH_RSA_PRIVKEY_HANDLER *hHandler)
{
	NH_RSA_PRIVKEY_HANDLER out;

	if (!(out = (NH_RSA_PRIVKEY_HANDLER) malloc((sizeof(NH_RSA_PRIVKEY_HANDLER_STR))))) return NH_OUT_OF_MEMORY_ERROR;
	memcpy(out, &defRSAPrivKeyHandler, sizeof(NH_RSA_PRIVKEY_HANDLER_STR));
	*hHandler = out;
	return NH_OK;
}

NH_FUNCTION(NH_RV, NH_release_RSA_privkey_handler)(_IN_ NH_RSA_PRIVKEY_HANDLER hHandler)
{
	if (hHandler)
	{
		if (hHandler->key) RSA_free(hHandler->key);
		free(hHandler);
	}
	return NH_OK;
}

NH_FUNCTION(NH_RV, NH_generate_RSA_keys)
(
	_IN_ int bits,
	_IN_ unsigned long exponent,
	_OUT_ NH_RSA_PUBKEY_HANDLER *hPubKey,
	_OUT_ NH_RSA_PRIVKEY_HANDLER *hPrivKey
)
{
	NH_RV rv;
	BIGNUM *ex = NULL;
	RSA *key = NULL, *pub = NULL;
	NH_RSA_PUBKEY_HANDLER pubKey = NULL;
	NH_RSA_PRIVKEY_HANDLER privKey;
	BIGNUM *e;
	BIGNUM *n;


	if
	(
		NH_SUCCESS(rv = (ex = BN_new()) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_GEN_ERROR) &&
		NH_SUCCESS(rv = BN_set_word(ex, exponent) ? NH_OK : NH_RSA_GEN_ERROR) &&
		NH_SUCCESS(rv = (key = RSA_new()) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_GEN_ERROR) &&
		NH_SUCCESS(rv = RSA_generate_key_ex(key, bits, ex, NULL) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_GEN_ERROR) &&
		NH_SUCCESS(rv = (pub = RSA_new()) ? NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_GEN_ERROR)
	)
	{
	#if OPENSSL_VERSION_NUMBER >= 0x10100001L
		RSA_get0_key((const RSA *)key,(const BIGNUM **)&n,(const BIGNUM **)&e,NULL);
		if
		(
			NH_SUCCESS(rv = (n = BN_dup(n)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_GEN_ERROR) &&
			NH_SUCCESS(rv = (e = BN_dup(e)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_GEN_ERROR) &&
			NH_SUCCESS(rv = RSA_set0_key(key,n,e,NULL) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_GEN_ERROR) &&
	#else
		if
		(
			NH_SUCCESS(rv = (pub->n = BN_dup(key->n)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_GEN_ERROR) &&
			NH_SUCCESS(rv = (pub->e = BN_dup(key->e)) ?  NH_OK : S_SYSERROR(ERR_get_error()) | NH_RSA_GEN_ERROR) &&
	#endif
			NH_SUCCESS(rv = NH_new_RSA_pubkey_handler(&pubKey)) &&
			NH_SUCCESS(rv = NH_new_RSA_privkey_handler(&privKey))
		)
		{
			pubKey->key = pub;
			pubKey->size = bits;
			privKey->key = key;
			*hPubKey = pubKey;
			*hPrivKey = privKey;

		}
	}
	if (ex) BN_free(ex);
	if (NH_FAIL(rv))
	{
		if (key) RSA_free(key);
		if (pub) RSA_free(pub);
		if (pubKey) NH_release_RSA_pubkey_handler(pubKey);
	}
	return rv;
}


/** ****************************
 *  General utilities
 *  ****************************/
INLINE NH_UTILITY(CK_BBOOL, NH_match_oid)(_IN_ unsigned int *a, _IN_ size_t acount, _IN_ unsigned int *b, _IN_ size_t bcount)
{
	return (a && b && acount == bcount && memcmp(a, b, sizeof(unsigned int) * acount) == 0) ? CK_TRUE : CK_FALSE;
}

unsigned int rsaEncryption_oid[]		= { 1, 2, 840, 113549, 1, 1,  1 };
unsigned int rsaes_oaep_oid[]			= { 1, 2, 840, 113549, 1, 1,  7 };
unsigned int rsa_x509_oid[]			= { 2, 5,   8,      1, 1        };

unsigned int md5WithRSA_oid[]			= { 1, 3,  14,      3, 2, 3     };
unsigned int sha1WithRSAEncryption[]	= { 1, 2, 840, 113549, 1, 1,  5 };
unsigned int sha256WithRSAEncryption[]	= { 1, 2, 840, 113549, 1, 1, 11 };
unsigned int sha384WithRSAEncryption[]	= { 1, 2, 840, 113549, 1, 1, 12 };
unsigned int sha512WithRSAEncryption[]	= { 1, 2, 840, 113549, 1, 1, 13 };
unsigned int ecPublicKey_oid[]		= { 1, 2, 840,  10045, 2, 1     };
unsigned int dsa_oid[]				= { 1, 2, 840,  10040, 4, 1     };

unsigned int sha1_oid[]				= { 1,  3,  14,      3,   2, 26              };
unsigned int sha256_oid[]			= { 2, 16, 840,      1, 101,  3,    4, 2, 1  };
unsigned int sha384_oid[]			= { 2, 16, 840,      1, 101,  3,    4, 2, 2  };
unsigned int sha512_oid[]			= { 2, 16, 840,      1, 101,  3,    4, 2, 3  };
unsigned int md2_oid[]				= { 1,  2, 840, 113549,   2,  2              };
unsigned int md5_oid[]				= { 1,  2, 840, 113549,   2,  5              };


unsigned int rc2_cbc_oid[]			= { 1,  2, 840, 113549,   3, 2           };
unsigned int des3_cbc_oid[]			= { 1,  2, 840, 113549,   3, 7           };
unsigned int aes128_cbc_oid[]			= { 2, 16, 840,      1, 101, 3, 4, 1, 2  };
unsigned int aes192_cbc_oid[]			= { 2, 16, 840,      1, 101, 3, 4, 1, 22 };
unsigned int aes256_cbc_oid[]			= { 2, 16, 840,      1, 101, 3, 4, 1, 42 };

const static unsigned int* supported_mechanisms_oid[] =
{
	sha1WithRSAEncryption,
	sha256WithRSAEncryption,
	sha512WithRSAEncryption,
	sha384WithRSAEncryption,
	rsaEncryption_oid,
	md5WithRSA_oid,
	ecPublicKey_oid,
	sha1_oid,
	sha256_oid,
	sha384_oid,
	sha512_oid,
	md2_oid,
	md5_oid,
	des3_cbc_oid,
	rc2_cbc_oid,
	aes128_cbc_oid,
	aes192_cbc_oid,
	aes256_cbc_oid
};
const static size_t sizeof_oid[] =
{
	NHC_SHA1_WITH_RSA_OID_COUNT,
	NHC_SHA256_WITH_RSA_OID_COUNT,
	NHC_SHA512_WITH_RSA_OID_COUNT,
	NHC_SHA384_WITH_RSA_OID_COUNT,
	NHC_RSA_ENCRYPTION_OID_COUNT,
	NHC_MD5_WITH_RSA_OID_COUNT,
	NHC_ECDSA_PUBKEY_OID_COUNT,
	NHC_OID_COUNT(sha1_oid),
	NHC_OID_COUNT(sha256_oid),
	NHC_OID_COUNT(sha384_oid),
	NHC_OID_COUNT(sha512_oid),
	NHC_OID_COUNT(md2_oid),
	NHC_OID_COUNT(md5_oid),
	NHC_OID_COUNT(des3_cbc_oid),
	NHC_OID_COUNT(rc2_cbc_oid),
	NHC_OID_COUNT(aes128_cbc_oid),
	NHC_OID_COUNT(aes192_cbc_oid),
	NHC_OID_COUNT(aes256_cbc_oid)
};
const static CK_MECHANISM_TYPE supported_mechanisms_const[] =
{
	CKM_SHA1_RSA_PKCS,
	CKM_SHA256_RSA_PKCS,
	CKM_SHA512_RSA_PKCS,
	CKM_SHA384_RSA_PKCS,
	CKM_RSA_PKCS_KEY_PAIR_GEN,
	CKM_MD5_RSA_PKCS,
	CKM_ECDSA_KEY_PAIR_GEN,
	CKM_SHA_1,
	CKM_SHA256,
	CKM_SHA384,
	CKM_SHA512,
	CKM_MD2,
	CKM_MD5,
	CKM_DES3_CBC,
	CKM_RC2_CBC,
	CKM_AES_CBC,
	CKM_AES_CBC,
	CKM_AES_CBC
};
#define MECHANISM_CONST_COUNT(_a)		(sizeof(_a) / sizeof(CK_MECHANISM_TYPE))
#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(CK_MECHANISM_TYPE, NH_oid_to_mechanism)(_IN_ unsigned int *OID, _IN_ size_t count)
{
	int i;
	for(i = 0; i < MECHANISM_CONST_COUNT(supported_mechanisms_const); i++) if
	(
		NH_match_oid(OID, count, supported_mechanisms_oid[i], sizeof_oid[i])
	)	return supported_mechanisms_const[i];
	return CK_UNAVAILABLE_INFORMATION;
}
