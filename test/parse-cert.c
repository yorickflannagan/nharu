#include "parse-cert.h"
#include <stdio.h>

int main()
{
	NH_RV rv;
	NH_CERTIFICATE_HANDLER hCert;
	NH_ASN1_PNODE node;
	NH_PKIBR_EXTENSION hExt = NULL;

	rv = NH_parse_certificate(PROBLEM, sizeof(PROBLEM), &hCert);
	if (NH_SUCCESS(rv))
	{
		rv = hCert->subject_alt_names(hCert, &node);
		if (NH_SUCCESS(rv)) rv = NH_parse_pkibr_extension(node->identifier, node->size + node->contents - node->identifier, &hExt);
		if (NH_SUCCESS(rv)) NH_release_pkibr_extension(hExt);
		NH_release_certificate(hCert);
	}
	printf("Result code: %lu\n", rv);
	return (int) rv;
}