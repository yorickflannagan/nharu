#include "test.h"
#include <stdio.h>

int main(int argv, char **argc)
{
	int rv = NH_OK;
	printf("Testing Nharu Library...\n");
	rv = test_encoder();
	if (NH_SUCCESS(rv)) rv = test_secret_sharing();
	if (NH_SUCCESS(rv)) rv = test_encrypt();
	if (NH_SUCCESS(rv)) rv = test_rsa();
	if (NH_SUCCESS(rv)) rv = test_cert();
	if (NH_SUCCESS(rv)) rv = test_pkibr();
	if (NH_SUCCESS(rv)) rv = test_crl();
	if (NH_SUCCESS(rv)) rv = parse_openssl_cms_signed_data();
	if (NH_SUCCESS(rv)) rv = test_cms_signed_data();
	if (NH_SUCCESS(rv)) rv = test_openssl_cms_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_enveloped_data();
	return rv;
}
