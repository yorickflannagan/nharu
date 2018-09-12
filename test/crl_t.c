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
