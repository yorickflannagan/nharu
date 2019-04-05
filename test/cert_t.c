#include "test.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

int test_certificate(char *szCert, char *szCACert)
{
	NH_RV rv;
	unsigned char *pCert = NULL, *pCACert = NULL;
	int certlen, cacertlen;
	NH_CERTIFICATE_HANDLER hCert = NULL, hCA = NULL;
	NH_ASN1_PNODE node = NULL;
	unsigned int sig_OID[7] = { 1, 2, 840, 113549, 1, 1, 11 };
	unsigned int clientAuth_OID[9] = { 1, 3, 6, 1, 5, 5, 7, 3, 2 };
	unsigned int emailProctection_OID[9] = { 1, 3, 6, 1, 5, 5, 7, 3, 4 };
	time_t now;
	unsigned char SKI[20] = { 0x0D, 0xB5, 0x41, 0xE5, 0x20, 0xDA, 0x5D, 0xD1, 0x1D, 0x70, 0x01, 0x43, 0x6F, 0x99, 0xC1, 0x90, 0xAE, 0xCC, 0xA4, 0xE2 };
	unsigned char AKI[20] = { 0xBA, 0xD5, 0x56, 0x9B, 0xFA, 0xB7, 0x38, 0xEE, 0x63, 0xE1, 0x03, 0xB1, 0xF2, 0x07, 0x57, 0x29, 0x9B, 0x79, 0x4B, 0xA2 };
	NH_PKIBR_EXTENSION hExt = NULL;
	const char *SUBJECTID = "197504020000000000000000000000000000000000000DIKRJ";
	const char *SUBJECTTE = "0000000000001113333Rio de Janeiro RJ    ";
	const char *SUBJECTCEI = "000000000000";

	printf("Testing certificate parsing with [%s]... ", szCert);
	if 
	(
		NH_SUCCESS(rv = load_file(szCert, &pCert, &certlen)) &&
		NH_SUCCESS(rv = load_file(szCACert, &pCACert, &cacertlen)) &&
		NH_SUCCESS(rv = NH_parse_certificate(pCert, certlen, &hCert)) &&
		NH_SUCCESS(rv = NH_parse_certificate(pCACert, cacertlen, &hCA))
	)
	{
		time(&now);
		rv = hCert->check_validity(hCert, gmtime(&now));
		if (NH_SUCCESS(rv)) rv = hCert->verify(hCert, hCA->pubkey);
		if (NH_SUCCESS(rv)) rv = hCert->signature_mech(hCert, &node);
		if (NH_SUCCESS(rv)) rv = NH_match_oid(sig_OID, NHC_OID_COUNT(sig_OID), node->child->value, node->child->valuelen) ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = hCert->ext_key_usage(hCert, &node);
		if (NH_SUCCESS(rv)) rv = (node && (node = node->child)) ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = NH_match_oid(clientAuth_OID, NHC_OID_COUNT(clientAuth_OID), node->value, node->valuelen) ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = (node = node->next) ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = NH_match_oid(emailProctection_OID, NHC_OID_COUNT(emailProctection_OID), node->value, node->valuelen) ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = hCert->ski(hCert, &node);
		if (NH_SUCCESS(rv)) rv = (node && node->valuelen == sizeof(SKI) && memcmp(node->value, SKI, sizeof(SKI)) == 0) ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = hCert->aki(hCert, &node);
		if (NH_SUCCESS(rv)) rv = (node && node->child && node->child->valuelen == sizeof(AKI) && memcmp(node->child->value, AKI, sizeof(AKI)) == 0) ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = hCert->subject_alt_names(hCert, &node);
		if (NH_SUCCESS(rv)) rv = NH_parse_pkibr_extension(node->identifier, node->size + node->contents - node->identifier, &hExt);
		if (NH_SUCCESS(rv)) rv = strlen(SUBJECTID) == hExt->subject_id->valuelen && memcmp(SUBJECTID, hExt->subject_id->value, hExt->subject_id->valuelen) == 0 ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = strlen(SUBJECTTE) == hExt->subject_te->valuelen && memcmp(SUBJECTTE, hExt->subject_te->value, hExt->subject_te->valuelen) == 0 ? NH_OK : NH_PKIX_ERROR;
		if (NH_SUCCESS(rv)) rv = strlen(SUBJECTCEI) == hExt->subject_cei->valuelen && memcmp(SUBJECTCEI, hExt->subject_cei->value, hExt->subject_cei->valuelen) == 0 ? NH_OK : NH_PKIX_ERROR;
	}
	if (pCert) free(pCert);
	if (pCACert) free(pCACert);
	if (hCert) NH_release_certificate(hCert);
	if (hCA) NH_release_certificate(hCA);
	if (hExt) NH_release_pkibr_extension(hExt);
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return (int) rv;
}
