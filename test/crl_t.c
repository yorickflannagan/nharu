#include "test.h"
#include <stdio.h>
#include <string.h>


unsigned char REVOKED[16] = { 0x02, 0xb9, 0xd4, 0xfb, 0x40, 0x30, 0xc3, 0x0c, 0x64, 0xc8, 0x16, 0xd4, 0x42, 0xd0, 0x3f, 0x76 };
int test_crl(char *szCRL, char *szCA)
{
	unsigned char *pCRL = NULL, *pCert = NULL;
	int crllen, certlen;

	NH_RV rv;
	NH_CRL_HANDLER hCRL = NULL;
	NH_CERTIFICATE_HANDLER hCA = NULL;
	NH_BIG_INTEGER revoked = { REVOKED, 16 };

	printf("%s", "Testing CRL parsing... ");
	if
	(
		NH_SUCCESS(rv = load_file(szCRL, &pCRL, &crllen)) &&
		NH_SUCCESS(rv = load_file(szCA, &pCert, &certlen)) &&
		NH_SUCCESS(rv = NH_parse_crl(pCRL, crllen, &hCRL)) &&
		NH_SUCCESS(rv = NH_parse_certificate(pCert, certlen, &hCA))
	)
	{
		rv = strcmp(hCA->subject->stringprep, hCRL->issuer->stringprep) == 0 ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = hCRL->verify(hCRL, hCA->pubkey);
		if (NH_SUCCESS(rv)) rv = hCRL->is_revoked(hCRL, &revoked) ? NH_OK : NH_PKIX_ERROR;
	}
	if (pCRL) free(pCRL);
	if (pCert) free(pCert);
	if (hCRL) NH_release_crl(hCRL);
	if (hCA) NH_release_certificate(hCA);
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}

NH_RV crlsign_callback(_IN_ NH_BLOB *data, _IN_ CK_MECHANISM_TYPE mechanism, _IN_ void *params, _OUT_ unsigned char *signature, _INOUT_ size_t *sigSize)
{
	NH_RSA_PRIVKEY_HANDLER hHandler = (NH_RSA_PRIVKEY_HANDLER) params;
	return hHandler->sign(hHandler, mechanism, data->data, data->length, signature, sigSize);
}
static unsigned char revoked[] = { 0x2B, 0x95, 0xB1, 0x1C, 0xD5, 0x11, 0xAC, 0x3F };
static char szRevocation[] = "20170623183148Z";
static unsigned int eReason = 1;
static unsigned char another[] = { 0x46, 0x82, 0x66, 0xDF, 0xF7, 0x0F, 0x4B, 0x94 };
static char szAnother[] = "20171027115356Z";
static unsigned int eAnother = 3;
static unsigned int _c_oid[] = { 2, 5, 4, 6 };
static unsigned int _o_oid[] = { 2, 5, 4, 10 };
static unsigned int _ou_oid[] = { 2, 5, 4, 11 };
static unsigned int _cn_oid[] = { 2, 5, 4, 3 };
static NH_OID_STR pC_OID = { _c_oid, NHC_OID_COUNT(_c_oid) };
static NH_OID_STR pO_OID = { _o_oid, NHC_OID_COUNT(_o_oid) };
static NH_OID_STR pOU_OID ={ _ou_oid, NHC_OID_COUNT(_ou_oid) };
static NH_OID_STR pCN_OID = { _cn_oid, NHC_OID_COUNT(_cn_oid) };
static NH_NAME_STR pC = { &pC_OID, "BR" };
static NH_NAME_STR pO = { &pO_OID, "PKI Brazil" };	
static NH_NAME_STR pOU = { &pOU_OID, "PKI Ruler for All Cats" };
static NH_NAME_STR pCN = { &pCN_OID, "Common Name for All Cats End User CA" };
static char szThis[] = "20190605154027Z";
static char szNext[] = "20190605214027Z";
static unsigned char __crlNumber[] = { 0x01 };
static unsigned char __aki[] = { 0x06, 0x06, 0x9A, 0x22, 0xC4, 0xA7, 0xC0, 0xF8, 0x55, 0xFE, 0x05, 0xEA, 0x86, 0x37, 0x0A, 0x8D, 0x2D, 0xC0, 0x17, 0xD3 };
int test_issue_crl()
{
	NH_RV rv;
	NH_CERTLIST_ENCODER hCRL;
	NH_BIG_INTEGER pSerial = { NULL, 0 };
	NH_NAME pIssuer[4];
	NH_OCTET_SRING aki = { __aki, sizeof(__aki) };
	NH_BIG_INTEGER number = { __crlNumber, sizeof(__crlNumber) };
	NH_RSA_PRIVKEY_HANDLER hPrivKey;
	size_t ulSize;
	unsigned char *pBuffer;
	NH_CERTIFICATE_HANDLER hCACert;
	NH_CRL_HANDLER hParser;

	printf("%s", "Testing CRL issuing... ");
	if (NH_SUCCESS(rv = NH_new_certlist_encoder(&hCRL)))
	{
		pSerial.data = revoked;
		pSerial.length = 8;
		if (NH_SUCCESS(rv = hCRL->add_cert(hCRL, &pSerial, szRevocation, eReason)))
		{
			pSerial.data = another;
			if (NH_SUCCESS(rv = hCRL->add_cert(hCRL, &pSerial, szAnother, eAnother)))
			{
				pIssuer[0] = &pC;
				pIssuer[1] = &pO;
				pIssuer[2] = &pOU;
				pIssuer[3] = &pCN;
				if
				(
					NH_SUCCESS(rv = hCRL->put_issuer(hCRL, pIssuer, 4)) &&
					NH_SUCCESS(rv = hCRL->put_this_update(hCRL, szThis)) &&
					NH_SUCCESS(rv = hCRL->put_next_update(hCRL, szNext)) &&
					NH_SUCCESS(rv = hCRL->put_aki(hCRL, &aki)) &&
					NH_SUCCESS(rv = hCRL->put_crl_number(hCRL, &number)) &&
					NH_SUCCESS(rv = NH_new_RSA_privkey_handler(&hPrivKey))
				)
				{
					if
					(
						NH_SUCCESS(rv = hPrivKey->from_privkey_info(hPrivKey, __ca_privkey, CA_PRIVKEY_SIZE)) &&
						NH_SUCCESS(rv = hCRL->sign(hCRL, CKM_SHA256_RSA_PKCS, crlsign_callback, hPrivKey)) &&
						NH_SUCCESS(rv = hCRL->encode(hCRL, NULL, &ulSize)) &&
						NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(ulSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
					)
					{
            				if
						(
							NH_SUCCESS(rv = hCRL->encode(hCRL, pBuffer, &ulSize)) &&
							NH_SUCCESS(rv = NH_parse_certificate(__ca_cert, CA_CERT_SIZE, &hCACert))
						)
						{
							if (NH_SUCCESS(rv = NH_parse_crl(pBuffer, ulSize, &hParser)))
							{
								if (NH_SUCCESS(rv = hParser->verify(hParser, hCACert->pubkey)))
								{
									pSerial.data = revoked;
									pSerial.length = 8;
									if (NH_SUCCESS(rv = hParser->is_revoked(hParser, &pSerial) ? NH_OK : NH_PKIX_ERROR))
									{
										pSerial.data = another;
										rv = hParser->is_revoked(hParser, &pSerial) ? NH_OK : NH_PKIX_ERROR;
									}
								}
								NH_release_crl(hParser);
							}
							NH_release_certificate(hCACert);
						}
            				free(pBuffer);
					}
					NH_release_RSA_privkey_handler(hPrivKey);
				}
			}
		}
		NH_delete_certilist_encoder(hCRL);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}

unsigned char __TLS_CHALLENGE[] = {
	0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x01, 0x04, 0x20, 0x95, 0x68, 0x22, 0x07, 0x72, 0xfc, 0x26,
	0x80, 0xbd, 0x7d, 0x04, 0x8a, 0xae, 0x27, 0xff, 0x34, 0xca, 0x3b, 0xe9,
	0xe4, 0x2c, 0xab, 0x7d, 0xdb, 0x2d, 0xef, 0xb6, 0x94, 0xc6, 0x13, 0xcf,
	0xc4
};
unsigned int __TLS_CHALLENGE_T = 49;
unsigned char __TLS_HASH[] =
{
	0x95, 0x68, 0x22, 0x07, 0x72, 0xFC, 0x26, 0x80,
	0xBD, 0x7D, 0x04, 0x8A, 0xAE, 0x27, 0xFF, 0x34,
	0xCA, 0x3B, 0xE9, 0xE4, 0x2C, 0xAB, 0x7D, 0xDB,
	0x2D, 0xEF, 0xB6, 0x94, 0xC6, 0x13, 0xCF, 0xC4
};
unsigned int __TLS_HASH_T = 32;
CK_MECHANISM_TYPE __HASH_ALG = CKM_SHA256;
int test_digest_info()
{
	NH_RV rv;
	NH_ASN1_PARSER_HANDLE hParser;
	NH_ASN1_PNODE pNode;
	CK_MECHANISM_TYPE hMechanism;
	NH_ASN1_ENCODER_HANDLE hEncoder;
	size_t cbEncode;
	unsigned char *pEncode;

	printf("%s", "Testing TLS DigestInfo parsing... ");
	if (NH_SUCCESS(rv = NH_parse_digest_info(__TLS_CHALLENGE, __TLS_CHALLENGE_T, &hParser)))
	{
		if
		(
			NH_SUCCESS(rv = (pNode = hParser->sail(hParser->root, NH_PARSE_SOUTH | 2)) ? NH_OK : NH_CANNOT_SAIL) &&
			NH_SUCCESS(rv = (hMechanism = NH_oid_to_mechanism((unsigned int*) pNode->value, pNode->valuelen)) == __HASH_ALG ? CKR_OK : NH_PARSER_ERROR) &&
			NH_SUCCESS(rv = (pNode = hParser->sail(hParser->root, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_CANNOT_SAIL) &&
			NH_SUCCESS(rv = pNode->valuelen == __TLS_HASH_T ? CKR_OK : NH_PARSER_ERROR)
		)	rv = memcmp(pNode->value, __TLS_HASH, pNode->valuelen) == 0 ? CKR_OK : NH_PARSER_ERROR;
		NH_release_digest_parser(hParser);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);

	printf("%s", "Testing TLS DigestInfo encoding... ");
	if (NH_SUCCESS(rv = NH_encode_digest_info(sha256_oid, NHC_SHA256_OID_COUNT, __TLS_HASH, __TLS_HASH_T, &hEncoder)))
	{
		cbEncode = hEncoder->encoded_size(hEncoder, hEncoder->root);
		if
		(
			NH_SUCCESS(rv = cbEncode == __TLS_CHALLENGE_T ? NH_OK : NH_PARSER_ERROR) &&
			NH_SUCCESS(rv = (pEncode = (unsigned char*) malloc(cbEncode)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
		)
		{
			if (NH_SUCCESS(rv = hEncoder->encode(hEncoder, hEncoder->root, pEncode))) rv = memcmp(pEncode, __TLS_CHALLENGE, cbEncode) == 0 ? NH_OK : NH_PARSER_ERROR;
			free(pEncode);
		}
		NH_release_digest_encoder(hEncoder);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}