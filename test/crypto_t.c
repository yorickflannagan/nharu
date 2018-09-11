#include "test.h"
#include "crypto.h"
#include <string.h>
#include <stdio.h>
#include <openssl/bn.h>

#define SECRET		"A secret to be shared"

NH_RV split(unsigned char k, unsigned char n, NH_SHARE **shares)
{
	NH_SHARE_HANDLER hHandler = NULL;
	NH_SHARE *out = NULL;
	unsigned char i = 0;
	NH_RV rv;

	rv = NH_new_secret_share(n, strlen(SECRET), &hHandler);
	if (NH_SUCCESS(rv)) rv = hHandler->split(hHandler, (unsigned char*)SECRET, strlen(SECRET), k, n);
	if (NH_SUCCESS(rv)) rv = (out = (NH_SHARE*)malloc(n * sizeof(NH_SHARE))) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv))
	{
		memset(out, 0, n * sizeof(NH_SHARE));
		while (NH_SUCCESS(rv) && i < n)
		{
			if (NH_SUCCESS(rv = NH_new_share(strlen(SECRET), &out[i]))) rv = hHandler->get(hHandler, i, out[i]);
			i++;
		}
		if (NH_SUCCESS(rv)) *shares = out;
		else
		{
			for (i = 0; i < n; i++) NH_release_share(out[i++]);
			free(out);
		}
	}
	if (hHandler) NH_release_secret_share(hHandler);
	return rv;
}

NH_RV join(unsigned char k, NH_SHARE *shares)
{
	NH_SHARE_HANDLER hHandler = NULL;
	NH_RV rv;
	char *secret = NULL;
	unsigned char i = 0;

	rv = NH_new_secret_share(k, strlen(SECRET), &hHandler);
	if (NH_SUCCESS(rv)) rv = (secret = (char*)malloc(strlen(SECRET) + 1)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv))
	{
		memset(secret, 0, strlen(SECRET) + 1);
		while (NH_SUCCESS(rv) && i < k)
		{
			rv = hHandler->set(hHandler, i, shares[i]);
			i++;
		}
		if (NH_SUCCESS(rv)) rv = hHandler->join(hHandler, (unsigned char*)secret);
		if (NH_SUCCESS(rv)) rv = (strcmp(secret, SECRET) == 0) ? NH_OK : NH_INVALID_ARG;
		free(secret);
	}
	if (hHandler) NH_release_secret_share(hHandler);
	return rv;
}

int test_secret_sharing()
{
	NH_RV rv;
	NH_SHARE *shares;
	unsigned char i;

	printf("%s", "Testing Shamir secret sharing scheme... ");
	if (NH_SUCCESS(rv = split(3, 6, &shares)))
	{
		rv = join(3, shares + 1);
		for (i = 0; i < 6; i++) NH_release_share(shares[i]);
		free(shares);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}


static char *SENSITIVE_DATA = "This data is sensitive and must be encrypted";
NH_RV encrypt_this(NH_SYMKEY_HANDLER hHandler, CK_MECHANISM_TYPE mechanism, NH_IV *iv)
{
	NH_RV rv;
	unsigned char *ciphertext = NULL, *plaintext = NULL;
	size_t cipherlen, plainlen;

	rv = hHandler->encrypt_init(hHandler, mechanism, iv);
	if (NH_SUCCESS(rv)) rv = hHandler->encrypt(hHandler, (unsigned char*) SENSITIVE_DATA, strlen(SENSITIVE_DATA), NULL, &cipherlen);
	if (NH_SUCCESS(rv)) rv = (ciphertext = (unsigned char*) malloc(cipherlen)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv)) rv = hHandler->encrypt(hHandler, (unsigned char*) SENSITIVE_DATA, strlen(SENSITIVE_DATA), ciphertext, &cipherlen);
	if (NH_SUCCESS(rv)) rv = hHandler->decrypt_init(hHandler, mechanism, iv);
	if (NH_SUCCESS(rv)) rv = hHandler->decrypt(hHandler, ciphertext, cipherlen, NULL, &plainlen);
	if (NH_SUCCESS(rv)) rv = (plaintext = (unsigned char*) malloc(plainlen)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
	if (NH_SUCCESS(rv))
	{
		memset(plaintext, 0, plainlen);
		rv = hHandler->decrypt(hHandler, ciphertext, cipherlen, plaintext, &plainlen);
	}
	if (NH_SUCCESS(rv)) rv = (plainlen == strlen(SENSITIVE_DATA) || memcmp(plaintext, SENSITIVE_DATA, plainlen) == 0) ? NH_OK : NH_CRYPTO_ERROR;
	if (ciphertext) free(ciphertext);
	if (plaintext) free(plaintext);
	return rv;

}

NH_RV test_encoding()
{
	NH_RV rv;
	NH_SYMKEY_HANDLER hHandler, hLoaded;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node;
	size_t eSize;
	unsigned char *eBuffer;

	if (NH_SUCCESS(rv = NH_new_symkey_handler(CKM_DES3_KEY_GEN, &hHandler)))
	{
		rv = hHandler->generate(hHandler, 24);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_encoder(SYMKEY_MAP_COUNT, 2048, &hEncoder)))
		{
			rv = hEncoder->chart(hEncoder, symkey_map, SYMKEY_MAP_COUNT, &node);
			if (NH_SUCCESS(rv)) rv = hHandler->encode(hHandler, CKM_AES_CBC, NULL, hEncoder, NH_PARSE_ROOT);
			if (NH_SUCCESS(rv))
			{
				eSize = hEncoder->encoded_size(hEncoder, node);
				if (NH_SUCCESS(rv = (eBuffer = (unsigned char*)malloc(eSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
				{
					rv = hEncoder->encode(hEncoder, node, eBuffer);
					if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_parser(eBuffer, eSize, SYMKEY_MAP_COUNT, 2048, &hParser)))
					{
						rv = hParser->map(hParser, symkey_map, SYMKEY_MAP_COUNT);
						if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_symkey_handler(CKM_DES3_KEY_GEN, &hLoaded)))
						{
							rv = hLoaded->decode(hLoaded, NULL, hParser, NH_PARSE_ROOT);
							if (NH_SUCCESS(rv)) rv = hHandler->key->length == hLoaded->key->length && memcmp(hHandler->key->data, hLoaded->key->data, hHandler->key->length) == 0 ? NH_OK : NH_CRYPTO_ERROR;
							NH_release_symkey_handler(hLoaded);
						}
						NH_release_parser(hParser);
					}
					free(eBuffer);
				}
			}
			NH_release_encoder(hEncoder);
		}
		NH_release_symkey_handler(hHandler);
	}
	return rv;
}

int test_encrypt()
{
	NH_RV rv;
	NH_SYMKEY_HANDLER hHandler;
	NH_IV *iv;

	printf("%s", "Testing CKM_DES3_CBC encryption... ");
	if (NH_SUCCESS(rv = NH_new_symkey_handler(CKM_DES3_KEY_GEN, &hHandler)))
	{
		rv = hHandler->generate(hHandler, 24);
		if (NH_SUCCESS(rv = hHandler->new_iv(CKM_DES3_CBC, &iv)))
		{
			rv = encrypt_this(hHandler, CKM_DES3_CBC, iv);
			hHandler->release_iv(iv);
		}
		NH_release_symkey_handler(hHandler);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);

	if (NH_SUCCESS(rv))
	{
		printf("%s", "Testing CKM_RC2_CBC encryption... ");
		if (NH_SUCCESS(rv = NH_new_symkey_handler(CKM_RC2_KEY_GEN, &hHandler)))
		{
			rv = hHandler->generate(hHandler, 128);
			if (NH_SUCCESS(rv = hHandler->new_iv(CKM_RC2_CBC, &iv)))
			{
				rv = encrypt_this(hHandler, CKM_RC2_CBC, iv);
				hHandler->release_iv(iv);
			}
			NH_release_symkey_handler(hHandler);
		}
		if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
		else printf("failed with error code %lu\n", rv);
	}

	if (NH_SUCCESS(rv))
	{
		printf("%s", "Testing CKM_AES_CBC encryption... ");
		if (NH_SUCCESS(rv = NH_new_symkey_handler(CKM_AES_KEY_GEN, &hHandler)))
		{
			rv = hHandler->generate(hHandler, 32);
			if (NH_SUCCESS(rv = hHandler->new_iv(CKM_AES_CBC, &iv)))
			{
				rv = encrypt_this(hHandler, CKM_AES_CBC, iv);
				hHandler->release_iv(iv);
			}
			NH_release_symkey_handler(hHandler);
		}
		if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
		else printf("failed with error code %lu\n", rv);
	}

	if (NH_SUCCESS(rv))
	{
		printf("%s", "Testing key encoding... ");
		if (NH_SUCCESS(rv = test_encoding())) printf("%s\n", "succeeded!");
		else printf("failed with error code %lu\n", rv);
	}
	return rv;
}


static char *CHALLENGE = "A data to be signed";
NH_RV test_signature(NH_RSA_PRIVKEY_HANDLER hPrivKey, NH_RSA_PUBKEY_HANDLER hPubKey)
{
	NH_RV rv;
	NH_HASH_HANDLER hHash;
	unsigned char *hash, *signature;
	size_t hashsize, sigSize;

	printf("%s", "Testing RSA signature... ");
	if (NH_SUCCESS(rv = NH_new_hash(&hHash)))
	{
		rv = hHash->init(hHash, CKM_SHA512);
		if (NH_SUCCESS(rv)) rv = hHash->digest(hHash, (unsigned char*)CHALLENGE, strlen(CHALLENGE), NULL, &hashsize);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (hash = (unsigned char*)malloc(hashsize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
		{
			rv = hHash->digest(hHash, (unsigned char*)CHALLENGE, strlen(CHALLENGE), hash, &hashsize);
			if (NH_SUCCESS(rv)) rv = hPrivKey->sign(hPrivKey, CKM_SHA512_RSA_PKCS, hash, hashsize, NULL, &sigSize);
			if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (signature = (unsigned char*)malloc(sigSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
			{
				rv = hPrivKey->sign(hPrivKey, CKM_SHA512_RSA_PKCS, hash, hashsize, signature, &sigSize);
				if (NH_SUCCESS(rv)) rv = hPubKey->verify(hPubKey, CKM_SHA512_RSA_PKCS, hash, hashsize, signature, sigSize);
				free(signature);
			}
			free(hash);
		}
		NH_release_hash(hHash);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}

NH_RV test_wrap_key( NH_RSA_PUBKEY_HANDLER hPubKey, NH_RSA_PRIVKEY_HANDLER hPrivKey)
{
	NH_RV rv;
	NH_SYMKEY_HANDLER hKey;
	size_t size, recsize;
	unsigned char *wrap, *recovered;

	printf("%s", "Testing key wrapping with RSA... ");
	if (NH_SUCCESS(rv = NH_new_symkey_handler(CKM_DES3_KEY_GEN, &hKey)))
	{
		rv = hKey->generate(hKey, 24);
		if (NH_SUCCESS(rv)) rv = hPubKey->encrypt(hPubKey, CKM_RSA_PKCS_OAEP, hKey->key->data, hKey->key->length, NULL, &size);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (wrap = (unsigned char*)malloc(size)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
		{
			rv = hPubKey->encrypt(hPubKey, CKM_RSA_PKCS_OAEP, hKey->key->data, hKey->key->length, wrap, &size);
			if (NH_SUCCESS(rv)) rv = hPrivKey->decrypt(hPrivKey, CKM_RSA_PKCS_OAEP, wrap, size, NULL, &recsize);
			if (NH_SUCCESS(rv) && NH_SUCCESS(rv = (recovered = (unsigned char*)malloc(recsize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
			{
				rv = hPrivKey->decrypt(hPrivKey, CKM_RSA_PKCS_OAEP, wrap, size, recovered, &recsize);
				if (NH_SUCCESS(rv)) rv = (hKey->key->length == recsize && memcmp(hKey->key->data, recovered, recsize) == 0) ? NH_OK : NH_BASE_ERROR;
				free(recovered);
			}
			free(wrap);
		}
		NH_release_symkey_handler(hKey);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}

NH_RV test_encode_pubkey(NH_RSA_PUBKEY_HANDLER hPubKey)
{
	NH_RV rv;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node;
	size_t eSize;
	unsigned char *eBuffer;
	NH_RSA_PUBKEY_HANDLER hLoaded;
	BIGNUM *e;
	BIGNUM *n;
	BIGNUM *_e;
	BIGNUM *_n;

	printf("%s", "Testing RSA public key encode... ");
	if (NH_SUCCESS(rv = NH_new_encoder(PUBKEY_MAP_COUNT, 2048, &hEncoder)))
	{
		rv = hEncoder->chart(hEncoder, pubkey_map, PUBKEY_MAP_COUNT, &node);
		if (NH_SUCCESS(rv)) rv = hPubKey->encode(hPubKey, hEncoder, NH_PARSE_ROOT);
		if (NH_SUCCESS(rv))
		{
			eSize = hEncoder->encoded_size(hEncoder, node);
			if NH_SUCCESS(rv = (eBuffer = (unsigned char*) malloc(eSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			{
				rv = hEncoder->encode(hEncoder, node, eBuffer);
				
				save_buffer(eBuffer, eSize, "pubkey.der");


				if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_parser(eBuffer, eSize, PUBKEY_MAP_COUNT, 2048, &hParser)))
				{
					rv = hParser->map(hParser, pubkey_map, PUBKEY_MAP_COUNT);
					if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_RSA_pubkey_handler(&hLoaded)))
					{
						if (NH_SUCCESS(rv = hLoaded->decode(hLoaded, hParser, NH_PARSE_ROOT)))
						{
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
							RSA_get0_key((const RSA *)hPubKey->key, (const BIGNUM **)&n, (const BIGNUM **)&e, NULL);
							RSA_get0_key((const RSA *)hLoaded->key, (const BIGNUM **)&_n, (const BIGNUM **)&_e, NULL);
#else
							n = hPubKey->key->n;
							e = hPubKey->key->e;
							_n = hLoaded->key->n;
							_e = hLoaded->key->e;
#endif
							rv = (BN_cmp(n, _n) == 0 && BN_cmp(e, _e) == 0) ? NH_OK : NH_BASE_ERROR;
						}
						NH_release_RSA_pubkey_handler(hLoaded);
					}
					NH_release_parser(hParser);
				}
				free(eBuffer);
			}
		}
		NH_release_encoder(hEncoder);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}

NH_RV test_encode_plainprivkey(NH_RSA_PRIVKEY_HANDLER hPrivKey)
{
	NH_RV rv;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node;
	size_t eSize;
	unsigned char *eBuffer;
	NH_RSA_PRIVKEY_HANDLER hLoaded;
	BIGNUM *d;
	BIGNUM *n;
	BIGNUM *_d;
	BIGNUM *_n;

	printf("%s", "Testing RSA private key encoding... ");
	if (NH_SUCCESS(rv = NH_new_encoder(PRIVKEY_MAP_COUNT, 2048, &hEncoder)))
	{
		rv = hEncoder->chart(hEncoder, privatekey_map, PRIVKEY_MAP_COUNT, &node);
		if (NH_SUCCESS(rv)) rv = hPrivKey->encode(hPrivKey, CK_UNAVAILABLE_INFORMATION, NULL, hEncoder, NH_PARSE_ROOT);
		if (NH_SUCCESS(rv))
		{
			eSize = hEncoder->encoded_size(hEncoder, node);
			if NH_SUCCESS(rv = (eBuffer = (unsigned char*) malloc(eSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
			{
				rv = hEncoder->encode(hEncoder, node, eBuffer);
				if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_parser(eBuffer, eSize, PRIVKEY_MAP_COUNT, 2048, &hParser)))
				{
					rv = hParser->map(hParser, privatekey_map, PRIVKEY_MAP_COUNT);
					if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_RSA_privkey_handler(&hLoaded)))
					{
						if (NH_SUCCESS(rv = hLoaded->decode(hLoaded, NULL, hParser, NH_PARSE_ROOT)))
						{
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
							RSA_get0_key((const RSA *)hPrivKey->key, (const BIGNUM **)&n, NULL, (const BIGNUM **)&d);
							RSA_get0_key((const RSA *)hLoaded->key, (const BIGNUM **)&_n, NULL, (const BIGNUM **)&_d);
#else
							n = hPrivKey->key->n;
							d = hPrivKey->key->d;
							_n = hLoaded->key->n;
							_d = hLoaded->key->d;
#endif
							rv = (BN_cmp(n, _n) == 0 && BN_cmp(d, _d) == 0) ? NH_OK : NH_BASE_ERROR;
						}
						NH_release_RSA_privkey_handler(hLoaded);
					}
					NH_release_parser(hParser);
				}
				free(eBuffer);
			}
		}
		NH_release_encoder(hEncoder);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}

NH_RV test_encode_encryptedprivkey(NH_RSA_PRIVKEY_HANDLER hPrivKey)
{
	NH_RV rv;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE node;
	size_t eSize;
	unsigned char *eBuffer;
	NH_RSA_PRIVKEY_HANDLER hLoaded;
	NH_SYMKEY_HANDLER hKey;
	BIGNUM *d = NULL;
	BIGNUM *n = NULL;
	BIGNUM *_d = NULL;
	BIGNUM *_n = NULL;

	printf("%s", "Testing RSA private key encrypted encoding... ");
	if (NH_SUCCESS(rv = NH_new_encoder(PRIVKEY_MAP_COUNT, 2048, &hEncoder)))
	{
		rv = hEncoder->chart(hEncoder, privatekey_map, PRIVKEY_MAP_COUNT, &node);
		if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_symkey_handler(CKM_DES3_KEY_GEN, &hKey)))
		{
			if (NH_SUCCESS(rv = hKey->generate(hKey, 24)) && NH_SUCCESS(rv = hPrivKey->encode(hPrivKey, CKM_DES3_CBC, hKey, hEncoder, NH_PARSE_ROOT)))
			{
				eSize = hEncoder->encoded_size(hEncoder, node);
				if NH_SUCCESS(rv = (eBuffer = (unsigned char*) malloc(eSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
				{
					rv = hEncoder->encode(hEncoder, node, eBuffer);
					if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_parser(eBuffer, eSize, PRIVKEY_MAP_COUNT, 2048, &hParser)))
					{
						rv = hParser->map(hParser, privatekey_map, PRIVKEY_MAP_COUNT);
						if (NH_SUCCESS(rv) && NH_SUCCESS(rv = NH_new_RSA_privkey_handler(&hLoaded)))
						{
							rv = hLoaded->decode(hLoaded, hKey, hParser, NH_PARSE_ROOT);
							if (NH_SUCCESS(rv))
							{
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
								RSA_get0_key((const RSA *)hPrivKey->key, (const BIGNUM **)&n, NULL, (const BIGNUM **)&d);
								RSA_get0_key((const RSA *)hLoaded->key, (const BIGNUM **)&_n, NULL, (const BIGNUM **)&_d);
#else
								n = hPrivKey->key->n;
								d = hPrivKey->key->d;
								_n = hLoaded->key->n;
								_d = hLoaded->key->d;
#endif
								rv = (BN_cmp(n, _n) == 0 && BN_cmp(d, _d) == 0) ? NH_OK : NH_BASE_ERROR;
							}
							NH_release_RSA_privkey_handler(hLoaded);
						}
						NH_release_parser(hParser);
					}
					free(eBuffer);
				}
			}
			NH_release_symkey_handler(hKey);
		}
		NH_release_encoder(hEncoder);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}
static int exponent = 65537;
int test_rsa()
{
	NH_RV rv;
	int bits = 2048;
	NH_RSA_PUBKEY_HANDLER hPubKey;
	NH_RSA_PRIVKEY_HANDLER hPrivKey;

	if (NH_SUCCESS(rv = NH_generate_RSA_keys(bits, exponent, &hPubKey, &hPrivKey)))
	{
		rv = test_signature(hPrivKey, hPubKey);
		if (NH_SUCCESS(rv)) rv = test_wrap_key(hPubKey, hPrivKey);
		/*
		if (NH_SUCCESS(rv)) rv = test_encode_pubkey(hPubKey);
		if (NH_SUCCESS(rv)) rv = test_encode_plainprivkey(hPrivKey);
		if (NH_SUCCESS(rv)) rv = test_encode_encryptedprivkey(hPrivKey);
*/		NH_release_RSA_pubkey_handler(hPubKey);
		NH_release_RSA_privkey_handler(hPrivKey);
	}
	if (NH_SUCCESS(rv)) rv = test_pkcs8();
	return rv;
}





static unsigned char pkcs8_key[] =
{
	0x30, 0x82, 0x04, 0xBC, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
	0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xA6, 0x30, 0x82, 0x04, 0xA2, 0x02, 0x01,
	0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xCE, 0x3E, 0x56, 0x18, 0x61, 0x37, 0x60, 0x17, 0x07, 0x58,
	0x4D, 0xEC, 0x88, 0xAE, 0x46, 0xC8, 0x3B, 0xE7, 0x07, 0x40, 0xA6, 0x42, 0x50, 0x0C, 0xD8, 0x48,
	0x73, 0x4C, 0xC0, 0x09, 0xF8, 0xD8, 0x2A, 0xBC, 0x2E, 0xD5, 0x33, 0x74, 0xB2, 0xA1, 0x65, 0xC2,
	0x04, 0x61, 0x0A, 0xFF, 0x7C, 0xD5, 0x97, 0xB1, 0x89, 0x09, 0x36, 0xCD, 0x88, 0x7D, 0xA8, 0x1A,
	0x32, 0xCA, 0x8C, 0xC9, 0xFB, 0x81, 0xB2, 0x07, 0xCE, 0xDD, 0x1D, 0x20, 0x24, 0x0B, 0xDF, 0xFE,
	0xA9, 0x31, 0xA2, 0x6C, 0x6E, 0x5D, 0x2F, 0x1D, 0xB5, 0x2D, 0xFE, 0x2F, 0xBE, 0x89, 0x6C, 0xBC,
	0x7A, 0xCA, 0x1B, 0x93, 0x15, 0xB5, 0x98, 0x88, 0x9C, 0x85, 0x61, 0x97, 0xFC, 0x9D, 0xA1, 0x47,
	0x38, 0x40, 0xCA, 0xA4, 0x2B, 0xB7, 0xEF, 0x37, 0x24, 0xE4, 0x62, 0x58, 0xBC, 0x39, 0x4D, 0x54,
	0xA8, 0xE4, 0xE3, 0x37, 0xDA, 0xBB, 0x24, 0x57, 0x3A, 0x47, 0xEC, 0x40, 0x40, 0xCB, 0x1F, 0x81,
	0x71, 0xA7, 0x19, 0x3A, 0xB6, 0x5F, 0x78, 0x3A, 0xC4, 0xC8, 0xFA, 0x91, 0x47, 0x1B, 0xA6, 0xD1,
	0x19, 0xE0, 0xB4, 0x0A, 0xFE, 0x13, 0x50, 0x70, 0x37, 0xA1, 0x5E, 0x3E, 0x33, 0x5D, 0x72, 0x9C,
	0xFD, 0xB2, 0xAE, 0x05, 0xAD, 0x16, 0x59, 0xE9, 0x02, 0x7D, 0xFD, 0xDD, 0x1A, 0x59, 0xEE, 0x02,
	0x57, 0x79, 0xC4, 0xE0, 0xB0, 0x5E, 0xA0, 0xF1, 0x09, 0xA4, 0x12, 0xEB, 0xDD, 0x0B, 0x39, 0x93,
	0xF1, 0x3F, 0xC8, 0xCB, 0x17, 0xB0, 0x50, 0x31, 0xB3, 0x58, 0x40, 0x7E, 0x5B, 0xF2, 0x69, 0x84,
	0x15, 0x55, 0x97, 0x38, 0x09, 0x22, 0x17, 0x59, 0x4E, 0x80, 0xC9, 0x4D, 0x03, 0x34, 0x57, 0x57,
	0x1F, 0x57, 0xC9, 0x0C, 0xDF, 0x87, 0x9D, 0x81, 0xB2, 0x98, 0xE0, 0xD4, 0x63, 0xC3, 0x60, 0x56,
	0x54, 0x97, 0x3F, 0x50, 0xDE, 0x97, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x48,
	0x48, 0x6E, 0xB2, 0x42, 0xB8, 0x3E, 0xB4, 0x33, 0x7D, 0xCE, 0x69, 0xBD, 0x09, 0x9F, 0x83, 0x24,
	0x03, 0x77, 0x76, 0x40, 0x0E, 0xF3, 0xB1, 0x5C, 0xC8, 0x1F, 0xA8, 0xE1, 0x91, 0x5D, 0x26, 0x9D,
	0xEB, 0xB0, 0x5A, 0x46, 0x9B, 0x7A, 0xD3, 0xB8, 0x2F, 0x44, 0x8B, 0xA2, 0x68, 0x22, 0x9F, 0x55,
	0x78, 0x02, 0x78, 0x39, 0x3D, 0xD5, 0xBD, 0x7C, 0x82, 0x1A, 0x15, 0x05, 0x3C, 0xF1, 0x29, 0xE6,
	0x74, 0x78, 0x1A, 0xE4, 0xCF, 0x53, 0xF2, 0xD9, 0x81, 0x8E, 0x58, 0xF7, 0xFD, 0x1A, 0xBD, 0x0B,
	0xFB, 0x54, 0x79, 0x97, 0x21, 0xB2, 0x9C, 0xC5, 0x80, 0x55, 0x64, 0xAA, 0x3F, 0x65, 0x97, 0x6C,
	0xAB, 0x4C, 0x78, 0x2E, 0xD9, 0x2E, 0xCF, 0x2C, 0x2C, 0x22, 0xDA, 0x0A, 0x6B, 0x79, 0x6B, 0x10,
	0xAA, 0xFA, 0x02, 0x15, 0x39, 0xD6, 0x56, 0x1A, 0xF5, 0x35, 0xF0, 0x6A, 0x76, 0x33, 0xF1, 0x4B,
	0xB2, 0x6C, 0x68, 0x9A, 0x78, 0x2D, 0x71, 0x1C, 0x31, 0xAC, 0xB9, 0xE6, 0x9B, 0x3C, 0x49, 0x7F,
	0x6A, 0x3D, 0xE7, 0x46, 0xE7, 0xAD, 0x1A, 0x90, 0xB1, 0xB4, 0xD7, 0x3E, 0x89, 0xB2, 0xA5, 0x41,
	0x34, 0x32, 0x55, 0xEE, 0x23, 0x79, 0xAB, 0x51, 0xAC, 0x0C, 0x64, 0x7C, 0xAA, 0x8B, 0x9D, 0x5F,
	0x1F, 0xD2, 0xB0, 0x51, 0x4D, 0xD6, 0x85, 0x7F, 0x71, 0xE7, 0x73, 0x1B, 0xAC, 0x7D, 0x6D, 0x1C,
	0xA2, 0x30, 0x30, 0xE7, 0x55, 0xC1, 0x75, 0x2F, 0xEC, 0x79, 0x37, 0x0D, 0x74, 0x48, 0x4B, 0xB4,
	0xCD, 0x8F, 0xBA, 0xE7, 0xA7, 0xFA, 0x97, 0x6E, 0xD1, 0xB2, 0x4C, 0x53, 0x82, 0x01, 0xCE, 0xAC,
	0xB4, 0x23, 0x80, 0x43, 0x66, 0x89, 0x37, 0x9E, 0x7D, 0x65, 0xC6, 0x05, 0x02, 0xAB, 0xB9, 0x44,
	0xB0, 0x54, 0x5C, 0x68, 0x02, 0x19, 0x90, 0xA0, 0xBC, 0x79, 0xEE, 0xD5, 0x08, 0x26, 0x09, 0x02,
	0x81, 0x81, 0x00, 0xF0, 0x87, 0xEF, 0xB3, 0xC0, 0x8B, 0x56, 0x2A, 0x74, 0x11, 0xE3, 0xBE, 0x37,
	0x96, 0x84, 0x6E, 0x1F, 0x10, 0x6A, 0xA5, 0xF2, 0xFA, 0xE1, 0xCE, 0x16, 0x78, 0xA3, 0x2D, 0x0A,
	0xE9, 0x27, 0x99, 0xBB, 0x5A, 0x9F, 0x78, 0xAF, 0x78, 0x54, 0x50, 0x58, 0x7A, 0x5C, 0xFC, 0xA7,
	0x1C, 0xDC, 0x51, 0xAA, 0x10, 0xDC, 0xF4, 0x5F, 0x44, 0x24, 0x54, 0x22, 0x13, 0x7C, 0xF6, 0xE1,
	0x95, 0x14, 0x0D, 0xB5, 0xFF, 0x60, 0xD2, 0x24, 0xF5, 0x48, 0x87, 0x84, 0x5A, 0xEF, 0xB7, 0xEA,
	0xB6, 0x22, 0x15, 0xD4, 0x0A, 0xD0, 0x32, 0x4B, 0xAA, 0xB0, 0x30, 0xBD, 0x3F, 0xDE, 0x2E, 0xF2,
	0xEA, 0x07, 0x66, 0x57, 0x76, 0x93, 0xF3, 0xE5, 0xD5, 0xA1, 0x8F, 0x76, 0x74, 0x36, 0x4C, 0x34,
	0x13, 0x13, 0xFD, 0x28, 0x1B, 0x45, 0x01, 0x62, 0x71, 0x1F, 0x14, 0xDD, 0x41, 0xD9, 0x0C, 0xF7,
	0x00, 0x60, 0x9B, 0x02, 0x81, 0x81, 0x00, 0xDB, 0x81, 0xE5, 0x66, 0x68, 0xA9, 0xE5, 0x07, 0x86,
	0x25, 0x3C, 0xC0, 0xD2, 0x28, 0xA8, 0xF7, 0xD3, 0xBE, 0xFE, 0xD9, 0x89, 0xE3, 0xB9, 0x09, 0x3E,
	0x94, 0x57, 0x9E, 0x1F, 0x99, 0x0F, 0x07, 0x0A, 0xCC, 0x32, 0x0D, 0xD1, 0x1E, 0x64, 0x01, 0xF3,
	0xEC, 0xAE, 0xDC, 0x1C, 0x40, 0xAC, 0x08, 0xA7, 0xA0, 0xC1, 0x7B, 0xB5, 0xC7, 0x40, 0x03, 0x7A,
	0x8E, 0x39, 0x3F, 0x5E, 0x08, 0x9A, 0x5E, 0xBC, 0xC9, 0x8C, 0x85, 0x4C, 0x75, 0x4B, 0x8E, 0x94,
	0xE4, 0xBB, 0xCF, 0x5E, 0x8A, 0x69, 0xBA, 0x64, 0xB0, 0x0F, 0x44, 0x97, 0x45, 0xEE, 0x6F, 0x6A,
	0x34, 0xB5, 0xF6, 0xB5, 0x16, 0x07, 0xE0, 0xCA, 0x96, 0x5E, 0x70, 0x97, 0x60, 0xE7, 0xC1, 0x6F,
	0xB7, 0x18, 0x38, 0x24, 0xD5, 0x68, 0x7B, 0x0F, 0xE7, 0x25, 0x7B, 0xCD, 0xE4, 0xD1, 0x12, 0xA9,
	0x68, 0x77, 0x9F, 0xEA, 0x8C, 0x43, 0xB5, 0x02, 0x81, 0x80, 0x01, 0xC0, 0x2B, 0x89, 0x76, 0x64,
	0x4D, 0x3B, 0x3F, 0xDF, 0x05, 0x76, 0x53, 0xF7, 0x3F, 0x7D, 0x81, 0xB2, 0x5F, 0xE4, 0x57, 0x51,
	0x66, 0x25, 0x56, 0xDA, 0x87, 0xED, 0x82, 0xFF, 0xD1, 0x6E, 0xF8, 0x03, 0x1F, 0xD8, 0x04, 0x06,
	0xEF, 0x2E, 0x2A, 0x86, 0xB1, 0x78, 0x91, 0x4A, 0xCF, 0x7B, 0xB4, 0xAE, 0x2C, 0xBD, 0x86, 0x97,
	0xFB, 0x5F, 0xB5, 0x63, 0xC8, 0xEC, 0x0F, 0x16, 0x43, 0xB0, 0x19, 0xDC, 0x02, 0xFB, 0x64, 0x93,
	0x78, 0x74, 0xAC, 0x0C, 0xF1, 0x63, 0xB8, 0x4C, 0x9D, 0x10, 0xE5, 0x9B, 0x32, 0x8A, 0xBB, 0x2C,
	0x41, 0xDE, 0x08, 0xF2, 0x97, 0x0E, 0x66, 0x6C, 0x37, 0xA3, 0x92, 0x0D, 0x65, 0xE4, 0x47, 0x8E,
	0xF7, 0x7F, 0x10, 0xD0, 0xA5, 0xB8, 0x86, 0x44, 0x81, 0x47, 0xBD, 0x6B, 0xFD, 0x63, 0x96, 0x30,
	0xD6, 0x96, 0x13, 0x4A, 0x30, 0x67, 0x3C, 0xC0, 0xFE, 0xF3, 0x02, 0x81, 0x80, 0x03, 0x85, 0x2A,
	0xC3, 0xA0, 0xAC, 0x10, 0xD3, 0x35, 0x10, 0x85, 0xCF, 0xE5, 0xCE, 0xE7, 0x1E, 0xCA, 0x53, 0x86,
	0xCC, 0xC0, 0x4C, 0x59, 0x9C, 0x4F, 0x57, 0x9B, 0xAC, 0x1A, 0x7F, 0x9E, 0xE1, 0x13, 0x08, 0x41,
	0x49, 0x3D, 0x70, 0x4A, 0x54, 0x49, 0xB0, 0x23, 0x01, 0xBE, 0xA6, 0x3E, 0xDC, 0x08, 0xAC, 0x28,
	0x4E, 0x2E, 0x95, 0x1A, 0x6E, 0xB3, 0xD9, 0x72, 0x0B, 0x95, 0x1B, 0x78, 0x36, 0x4A, 0xBA, 0xC4,
	0xB9, 0x22, 0x87, 0xC3, 0x05, 0x6F, 0x57, 0xD7, 0xB7, 0x34, 0xA1, 0xED, 0x9E, 0x22, 0x9D, 0x3C,
	0x31, 0x72, 0x67, 0x99, 0xB2, 0x49, 0xB6, 0xBC, 0xB0, 0x4F, 0x29, 0x22, 0x49, 0x35, 0x96, 0x81,
	0xBF, 0x36, 0x7E, 0x44, 0x59, 0x32, 0xCC, 0x71, 0xE3, 0xFC, 0x9B, 0x3B, 0x88, 0xB5, 0xB1, 0x94,
	0x45, 0x4F, 0x00, 0xFB, 0x65, 0x5C, 0x38, 0x23, 0xAA, 0xF9, 0xDC, 0xF3, 0xFD, 0x02, 0x81, 0x80,
	0x5C, 0x30, 0xC8, 0xD3, 0x51, 0x9B, 0x7D, 0x0D, 0x96, 0x48, 0x15, 0x10, 0xBB, 0xEC, 0x3C, 0x82,
	0x8A, 0x8A, 0x3F, 0x7A, 0x2E, 0xE3, 0xDC, 0x10, 0x2E, 0xE2, 0xB3, 0x47, 0xFE, 0x90, 0xCB, 0xC4,
	0xBF, 0xF9, 0xCF, 0x2C, 0x0B, 0x93, 0x56, 0x91, 0x60, 0x62, 0xAD, 0xB3, 0x75, 0x0B, 0xE6, 0xB8,
	0x0A, 0xC8, 0xB6, 0xFF, 0x3F, 0xD7, 0x0A, 0x52, 0x85, 0x36, 0x71, 0x91, 0x60, 0xA3, 0x11, 0xCF,
	0x2D, 0xE0, 0x5C, 0x7A, 0x4D, 0xCE, 0x1C, 0x9F, 0x73, 0x51, 0x1D, 0x82, 0x87, 0x22, 0x0A, 0x20,
	0xC6, 0xF5, 0x35, 0x65, 0xF6, 0xC0, 0x4F, 0x55, 0xB6, 0x35, 0x96, 0xBF, 0x2C, 0x02, 0x9B, 0x12,
	0x73, 0x2C, 0x56, 0x32, 0x34, 0xA8, 0x62, 0x24, 0x7F, 0xA9, 0xA0, 0xFF, 0x33, 0x0B, 0x05, 0x17,
	0x82, 0x09, 0x4D, 0xC6, 0xB0, 0xA1, 0xA0, 0x2D, 0x5B, 0x66, 0x08, 0xFF, 0x96, 0x63, 0x2D, 0x79
};
int test_pkcs8()
{
	NH_RV rv;
	NH_RSA_PRIVKEY_HANDLER hPrivKey;

	if (NH_SUCCESS(rv = NH_new_RSA_privkey_handler(&hPrivKey)))
	{
		rv = hPrivKey->from_privkey_info(hPrivKey, pkcs8_key, sizeof(pkcs8_key));
		NH_release_RSA_privkey_handler(hPrivKey);
	}
	return rv;
}
