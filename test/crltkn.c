#include "test.h"
#include <stdio.h>

unsigned char DUPLICATED[1] = { 0x03 };
int test_tkn_crl(char *szCRL)
{
	unsigned char *pCRL = NULL;
	int crllen;
	NH_RV rv;
	NH_CRL_HANDLER hCRL = NULL;
	NH_BIG_INTEGER revoked = { DUPLICATED, 1 };

	printf("%s", "Testing CRL with duplicated entries... ");
	if
	(
		NH_SUCCESS(rv = load_file(szCRL, &pCRL, &crllen)) &&
		NH_SUCCESS(rv = NH_parse_crl(pCRL, crllen, &hCRL))
	)
	{
		rv = hCRL->is_revoked(hCRL, &revoked) ? NH_OK : NH_PKIX_ERROR;
		NH_release_crl(hCRL);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return (int) rv;
}