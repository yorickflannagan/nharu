#include "test.h"
#include <stdio.h>
#include <errno.h>


#define ARGC1		"C:\\Users\\developer\\dev\\nharu\\test\\repo\\pkibr-pf.cer"
#define ARGC2		"C:\\Users\\developer\\dev\\nharu\\test\\repo\\end-ca.cer"
#define ARGC3		"C:\\Users\\developer\\dev\\nharu\\test\\repo\\pkibr-ac.crl"
#define ARGC4		"C:\\Users\\developer\\dev\\nharu\\test\\repo\\pkibr-ac.cer"
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
	if (NH_SUCCESS(rv)) rv = test_certificate(ARGC1, ARGC2);
	if (NH_SUCCESS(rv)) rv = test_crl(ARGC3, ARGC4);

	/*
	 * TODO: Encoding RSA public and private key must be corrected
	 */
	printf("%s\n", "Test done");

/*	
	
	if (NH_SUCCESS(rv)) rv = parse_openssl_cms_signed_data();
	if (NH_SUCCESS(rv)) rv = test_cms_signed_data();
	if (NH_SUCCESS(rv)) rv = test_cms_signed_data_with_pubkey();
	if (NH_SUCCESS(rv)) rv = test_openssl_cms_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_fake_enveloped_data();
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

#define ROUNDUP(x)	(--(x), (x)|=(x)>>1, (x)|=(x)>>2, (x)|=(x)>>4, (x)|=(x)>>8, (x)|=(x)>>16, ++(x))
int load_file(char *szFilename, unsigned char **out, int *outlen)
{
	unsigned char buf[512], *data = NULL;
	int i, max = 0, len = 0, ret = 0;
	FILE *fp;

	if (!(fp = fopen(szFilename, "rb"))) return errno;
	while ((i = fread(buf, 1, 512, fp)))
	{
		if (len + i > max)
		{
			max = len + i;
			ROUNDUP(max);
			data = (unsigned char*) realloc(data, max);
		}
		memcpy(data + len, buf, i);
		len += i;
	}
	if (feof(fp))
	{
		*out = (unsigned char *) data;
		*outlen = len;
	}
	else
	{
		ret = ferror(fp);
		if (data) free(data);
	}
	fclose(fp);
	return ret;
}
