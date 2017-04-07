#include "test.h"
#include <stdio.h>

int main(_UNUSED_ int argv, _UNUSED_ char **argc)
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
	if (NH_SUCCESS(rv)) rv = test_cms_signed_data_with_pubkey();
	if (NH_SUCCESS(rv)) rv = test_openssl_cms_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_fake_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_indefinite_length_form();
	return rv;
}
