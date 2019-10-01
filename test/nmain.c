#include "test.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>


#ifdef _WIN32
#define PATH_SEPARATOR		"\\"
#else
#define PATH_SEPARATOR		"/"
#include <linux/limits.h>
#define MAX_PATH			PATH_MAX
#endif 


#define PKIBRPF		PATH_SEPARATOR"pkibr-pf.cer"
#define ENDCA		PATH_SEPARATOR"end-ca.cer"
#define PKIBRACRL		PATH_SEPARATOR"pkibr-ac.crl"
#define PKIBRAC		PATH_SEPARATOR"pkibr-ac.cer"
#define SIGNERCERT	PATH_SEPARATOR"signer.cer"

int main(_UNUSED_ int argv, _UNUSED_ char **argc)
{
	int rv = 0;
	NH_NOISE_HANDLER hNoise;
	char pkibrpf[MAX_PATH], endca[MAX_PATH], pkibrcrl[MAX_PATH], pkibrac[MAX_PATH], signer[MAX_PATH];
	
	memset(pkibrpf, 0, MAX_PATH);
	strcpy(pkibrpf, argc[1]);
	strcat(pkibrpf, PKIBRPF);
	memset(endca, 0, MAX_PATH);
	strcpy(endca, argc[1]);
	strcat(endca, ENDCA);
	memset(pkibrcrl, 0, MAX_PATH);
	strcpy(pkibrcrl, argc[1]);
	strcat(pkibrcrl, PKIBRACRL);
	memset(pkibrac, 0, MAX_PATH);
	strcpy(pkibrac, argc[1]);
	strcat(pkibrac, PKIBRAC);
	memset(signer, 0, MAX_PATH);
	strcpy(signer, argc[1]);
	strcat(signer, SIGNERCERT);

	printf("%s\n", "Nharu library regression test");
	if (NH_SUCCESS(rv = NH_new_noise_device(&hNoise))) NH_release_noise_device(hNoise);
	if (NH_SUCCESS(rv)) rv = check_crl_serpro();
	if (NH_SUCCESS(rv)) rv = test_encoder();
	if (NH_SUCCESS(rv)) rv = test_indefinite_length_form();
	if (NH_SUCCESS(rv)) rv = test_secret_sharing();
	if (NH_SUCCESS(rv)) rv = test_encrypt();
	if (NH_SUCCESS(rv)) rv = test_rsa();
	if (NH_SUCCESS(rv)) rv = test_certificate(pkibrpf, endca);
	if (NH_SUCCESS(rv)) rv = test_crl(pkibrcrl, pkibrac);
	if (NH_SUCCESS(rv)) rv = test_cms_signed_data(signer, endca);
	if (NH_SUCCESS(rv)) rv = test_cms_signed_data_with_pubkey(signer);
	if (NH_SUCCESS(rv)) rv = test_enveloped_data(signer);
	if (NH_SUCCESS(rv)) rv = test_fake_enveloped_data();
	if (NH_SUCCESS(rv)) rv = test_cadest();

	if (NH_SUCCESS(rv)) rv = test_parse_request();
	if (NH_SUCCESS(rv)) rv = test_parse_pubkey();
	if (NH_SUCCESS(rv)) rv = test_sign_certificate();
	if (NH_SUCCESS(rv)) rv = test_create_request();
	if (NH_SUCCESS(rv)) rv = test_encode_p8();
	if (NH_SUCCESS(rv)) rv = test_issue_crl();

	if (NH_SUCCESS(rv)) rv = test_digest_info();
	printf("%s\n", "Test done");
	return rv;
}


int save_buffer(unsigned char *buffer, size_t buflen, char *fname)
{
	FILE *p;
	if (!(p = fopen(fname, "w"))) return errno;
	fwrite(buffer, sizeof(unsigned char), buflen, p);
	fclose(p);
	return 0;
}

int load_file(char *szFilename, unsigned char **out, int *outlen)
{
	unsigned char buf[512], *data = NULL;
	int i, max = 0, len = 0, ret = 0;
	FILE *fp;

	if (!(fp = fopen(szFilename, "rb"))) return errno;
	while ((i = (int) fread(buf, 1, 512, fp)))
	{
		if (len + i > max)
		{
			max = len + i;
			max = ROUNDUP(max);
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
