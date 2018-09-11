#include "test.h"
#include <stdio.h>
#include <errno.h>

int main(_UNUSED_ int argv, _UNUSED_ char **argc)
{
	int rv;
	NH_NOISE_HANDLER hNoise;

	printf("%s\n", "Nharu library regression test");
	if (NH_SUCCESS(rv = NH_new_noise_device(&hNoise))) NH_release_noise_device(hNoise);
	if (NH_SUCCESS(rv)) rv = test_encoder();
	if (NH_SUCCESS(rv)) rv = test_indefinite_length_form();
	if (NH_SUCCESS(rv)) rv = test_secret_sharing();
	if (NH_SUCCESS(rv)) rv = test_encrypt();
	if (NH_SUCCESS(rv)) rv = test_rsa();

	/*
	 * TODO: Encoding RSA public and private key must be corrected
	 */
	printf("%s\n", "Test done");

/*	
	
	if (NH_SUCCESS(rv)) rv = test_cert();
	if (NH_SUCCESS(rv)) rv = test_pkibr();
	if (NH_SUCCESS(rv)) rv = test_crl();
	if (NH_SUCCESS(rv)) rv = parse_openssl_cms_signed_data();
	if (NH_SUCCESS(rv)) rv = test_cms_signed_data();
	if (NH_SUCCESS(rv)) rv = test_cms_signed_data_with_pubkey();
	if (NH_SUCCESS(rv)) rv = test_openssl_cms_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_fake_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_encoder();
	if (NH_SUCCESS(rv)) rv = test_cadest();

*/	return rv;
}


int save_buffer(unsigned char *buffer, size_t buflen, char *fname)
{
	FILE *p;
	if (!(p = fopen(fname, "w"))) return errno;
	fwrite(buffer, sizeof(unsigned char), buflen, p);
	fclose(p);
	return 0;
}