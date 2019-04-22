#include "test.h"
#include <stdio.h>
#include <string.h>

static unsigned char __request[] =
{
	0x30, 0x82, 0x02, 0x7f, 0x30, 0x82, 0x01, 0x67, 0x02, 0x01, 0x00, 0x30,
	0x3a, 0x31, 0x38, 0x30, 0x36, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x2f,
	0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x76, 0x61, 0x6c, 0x64, 0x6f,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x76, 0x61, 0x6c, 0x64, 0x6f, 0x20, 0x64,
	0x61, 0x73, 0x20, 0x54, 0x6f, 0x72, 0x72, 0x65, 0x73, 0x20, 0x31, 0x35,
	0x35, 0x34, 0x39, 0x32, 0x32, 0x31, 0x36, 0x33, 0x33, 0x30, 0x39, 0x30,
	0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
	0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
	0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb7, 0x92, 0x8b, 0xd8,
	0xcd, 0x77, 0x99, 0x7d, 0xf1, 0x9d, 0x53, 0x4f, 0xb1, 0xdb, 0xc6, 0x50,
	0x22, 0xd9, 0xab, 0xd7, 0xb0, 0x40, 0xa3, 0x0c, 0x05, 0xd5, 0xcb, 0xbb,
	0x69, 0x7d, 0xa4, 0xc3, 0xda, 0x92, 0xf1, 0xa9, 0x8c, 0x06, 0x14, 0x5a,
	0x2e, 0xf6, 0x1f, 0x4b, 0xad, 0x70, 0x9e, 0xa2, 0x84, 0xe7, 0x60, 0xbe,
	0x83, 0xda, 0xe0, 0x0a, 0xc0, 0x3c, 0xe5, 0x32, 0xe9, 0xf1, 0x5d, 0xb9,
	0xcc, 0xbc, 0x4c, 0xa2, 0x17, 0xab, 0x89, 0x13, 0xe8, 0x16, 0x88, 0x32,
	0xd5, 0x8f, 0xe2, 0xa3, 0x62, 0xe7, 0x2b, 0x1b, 0x0a, 0x12, 0x94, 0x7a,
	0x3a, 0xe8, 0x2d, 0x8c, 0x61, 0xce, 0xc2, 0x8f, 0x42, 0xec, 0x58, 0x20,
	0xa8, 0x9e, 0xe9, 0xec, 0x84, 0x66, 0xcf, 0xd3, 0x89, 0x94, 0xbb, 0xc1,
	0xeb, 0xf0, 0x6e, 0x27, 0xc9, 0xe9, 0xf8, 0x7d, 0x9d, 0x5d, 0x53, 0xc1,
	0xda, 0x18, 0x05, 0x5b, 0x7e, 0xe4, 0xbb, 0x78, 0x49, 0xac, 0xbe, 0x57,
	0xc9, 0x11, 0x45, 0x23, 0x32, 0xf6, 0x2b, 0x7d, 0xed, 0x8b, 0xdd, 0xe1,
	0x82, 0xdf, 0xdc, 0xe6, 0x93, 0xc8, 0x56, 0x02, 0x0c, 0x2f, 0x8b, 0x55,
	0x63, 0x99, 0x27, 0x87, 0xe4, 0xe7, 0x90, 0x2a, 0xaa, 0x42, 0xee, 0xca,
	0xcd, 0xcd, 0xd2, 0x75, 0x79, 0x94, 0x37, 0xea, 0xf7, 0x41, 0xef, 0xf0,
	0x90, 0xc3, 0x0a, 0x5f, 0x53, 0x67, 0x30, 0xe5, 0x28, 0x72, 0x16, 0x48,
	0xd7, 0x33, 0x49, 0x92, 0xde, 0x74, 0xc8, 0x05, 0xf3, 0x31, 0x36, 0x01,
	0x55, 0xa6, 0x63, 0x52, 0x2e, 0x0e, 0x12, 0xfd, 0x31, 0xbe, 0x26, 0x70,
	0x13, 0x3a, 0x68, 0x7d, 0x57, 0x80, 0xf4, 0xa6, 0x84, 0x3f, 0x00, 0x10,
	0xb4, 0x09, 0x2d, 0xcf, 0xc6, 0xdc, 0x6d, 0x79, 0x60, 0xa9, 0x55, 0x5b,
	0x1d, 0x6b, 0x4c, 0x92, 0x43, 0x30, 0x90, 0x42, 0x80, 0x59, 0x60, 0x7d,
	0x02, 0x03, 0x01, 0x00, 0x01, 0xa0, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
	0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
	0x01, 0x01, 0x00, 0x54, 0x08, 0x5c, 0xcb, 0x63, 0x17, 0x82, 0x4b, 0xff,
	0xbd, 0x03, 0x94, 0x45, 0xcb, 0xb0, 0xeb, 0xb0, 0x39, 0x5d, 0x7d, 0x35,
	0xc1, 0x2b, 0x2a, 0x17, 0xd4, 0xa0, 0xe6, 0x6b, 0x30, 0xc9, 0x5c, 0xfd,
	0xdb, 0x82, 0x50, 0x2b, 0x02, 0x08, 0x5e, 0x6d, 0xc5, 0xc0, 0x14, 0x54,
	0xea, 0xac, 0x74, 0xcd, 0xe3, 0x75, 0xf7, 0xaf, 0x48, 0xea, 0x42, 0xdb,
	0x0a, 0xef, 0x92, 0x53, 0x78, 0xb2, 0xa0, 0x84, 0x01, 0xec, 0x2a, 0xe6,
	0x5e, 0x38, 0x0c, 0x49, 0x85, 0x21, 0x8c, 0x1a, 0xd4, 0xbf, 0x6c, 0xff,
	0x17, 0x36, 0xda, 0x1f, 0x6f, 0x41, 0x59, 0x40, 0x96, 0x62, 0xeb, 0xd6,
	0x12, 0xa1, 0xd7, 0x1a, 0x20, 0xce, 0x9e, 0x55, 0x61, 0x4b, 0x6e, 0x11,
	0xa7, 0x33, 0x04, 0x95, 0xe6, 0x04, 0xa3, 0xdb, 0xf9, 0x8e, 0x78, 0xbf,
	0x86, 0x90, 0x64, 0x8d, 0xb7, 0xef, 0x40, 0x63, 0xe7, 0xdf, 0x86, 0xe8,
	0x95, 0xe7, 0x26, 0xec, 0x3e, 0xcd, 0x22, 0x24, 0x45, 0xaf, 0xd1, 0x9b,
	0x82, 0x5d, 0xb8, 0x72, 0x5d, 0x0f, 0x54, 0xb8, 0x72, 0x46, 0xe9, 0xe0,
	0x2f, 0x55, 0x4b, 0xff, 0x97, 0xd0, 0xa2, 0x4d, 0xd2, 0x46, 0x04, 0xd2,
	0x51, 0xa1, 0xb8, 0x02, 0xcf, 0x26, 0x8e, 0x6b, 0xab, 0xa1, 0x93, 0x5c,
	0xd6, 0x26, 0xde, 0xa1, 0x76, 0x91, 0x8b, 0xb4, 0x25, 0x3e, 0x30, 0xdc,
	0x09, 0x67, 0x74, 0xa7, 0x86, 0x6b, 0xce, 0x1f, 0x0f, 0xb0, 0xbb, 0x80,
	0xdf, 0xc9, 0x24, 0xc8, 0x4b, 0x8d, 0x2d, 0xc1, 0x48, 0x91, 0x28, 0xcf,
	0x15, 0x4f, 0x56, 0x87, 0xe3, 0x96, 0xf1, 0x72, 0x71, 0x07, 0xac, 0xa2,
	0x10, 0xdf, 0xee, 0x9b, 0x4b, 0x02, 0x8e, 0xbf, 0x65, 0x9e, 0x9a, 0x04,
	0x5e, 0xae, 0xcf, 0x7c, 0x4d, 0x42, 0x69, 0x81, 0x90, 0x65, 0x13, 0x07,
	0x64, 0x65, 0x04, 0xc1, 0x9b, 0xc6, 0xb1
};
static unsigned char __pubkey[] =
{
	0x30,  0x82,  0x01,  0x0a,  0x02,  0x82,  0x01,  0x01,  0x00,  0xb7,  0x92,  0x8b,  0xd8,  0xcd,  0x77,
	0x99,  0x7d,  0xf1,  0x9d,  0x53,  0x4f,  0xb1,  0xdb,  0xc6,  0x50,  0x22,  0xd9,  0xab,  0xd7,  0xb0,  0x40,
	0xa3,  0x0c,  0x05,  0xd5,  0xcb,  0xbb,  0x69,  0x7d,  0xa4,  0xc3,  0xda,  0x92,  0xf1,  0xa9,  0x8c,  0x06,
	0x14,  0x5a,  0x2e,  0xf6,  0x1f,  0x4b,  0xad,  0x70,  0x9e,  0xa2,  0x84,  0xe7,  0x60,  0xbe,  0x83,  0xda,
	0xe0,  0x0a,  0xc0,  0x3c,  0xe5,  0x32,  0xe9,  0xf1,  0x5d,  0xb9,  0xcc,  0xbc,  0x4c,  0xa2,  0x17,  0xab,
	0x89,  0x13,  0xe8,  0x16,  0x88,  0x32,  0xd5,  0x8f,  0xe2,  0xa3,  0x62,  0xe7,  0x2b,  0x1b,  0x0a,  0x12,
	0x94,  0x7a,  0x3a,  0xe8,  0x2d,  0x8c,  0x61,  0xce,  0xc2,  0x8f,  0x42,  0xec,  0x58,  0x20,  0xa8,  0x9e,
	0xe9,  0xec,  0x84,  0x66,  0xcf,  0xd3,  0x89,  0x94,  0xbb,  0xc1,  0xeb,  0xf0,  0x6e,  0x27,  0xc9,  0xe9,
	0xf8,  0x7d,  0x9d,  0x5d,  0x53,  0xc1,  0xda,  0x18,  0x05,  0x5b,  0x7e,  0xe4,  0xbb,  0x78,  0x49,  0xac,
	0xbe,  0x57,  0xc9,  0x11,  0x45,  0x23,  0x32,  0xf6,  0x2b,  0x7d,  0xed,  0x8b,  0xdd,  0xe1,  0x82,  0xdf,
	0xdc,  0xe6,  0x93,  0xc8,  0x56,  0x02,  0x0c,  0x2f,  0x8b,  0x55,  0x63,  0x99,  0x27,  0x87,  0xe4,  0xe7,
	0x90,  0x2a,  0xaa,  0x42,  0xee,  0xca,  0xcd,  0xcd,  0xd2,  0x75,  0x79,  0x94,  0x37,  0xea,  0xf7,  0x41,
	0xef,  0xf0,  0x90,  0xc3,  0x0a,  0x5f,  0x53,  0x67,  0x30,  0xe5,  0x28,  0x72,  0x16,  0x48,  0xd7,  0x33,
	0x49,  0x92,  0xde,  0x74,  0xc8,  0x05,  0xf3,  0x31,  0x36,  0x01,  0x55,  0xa6,  0x63,  0x52,  0x2e,  0x0e,
	0x12,  0xfd,  0x31,  0xbe,  0x26,  0x70,  0x13,  0x3a,  0x68,  0x7d,  0x57,  0x80,  0xf4,  0xa6,  0x84,  0x3f,
	0x00,  0x10,  0xb4,  0x09,  0x2d,  0xcf,  0xc6,  0xdc,  0x6d,  0x79,  0x60,  0xa9,  0x55,  0x5b,  0x1d,  0x6b,
	0x4c,  0x92,  0x43,  0x30,  0x90,  0x42,  0x80,  0x59,  0x60,  0x7d,  0x02,  0x03,  0x01,  0x00,  0x01
};
static char* __subject = " francisvaldo  genevaldo  das  torres  1554922163309 ";
int test_parse_request()
{
	NH_RV rv;
	NH_CREQUEST_PARSER hRequest;
	NH_ASN1_PNODE pPubKey = NULL;
	NH_PBITSTRING_VALUE pValue;

	printf("%s", "Testing PKCS#10 request parsing... ");
	if (NH_SUCCESS(rv = NH_parse_cert_request(__request, sizeof(__request), &hRequest)))
	{
		rv = strcmp(hRequest->subject->stringprep, __subject) == 0 ? NH_OK : NH_ISSUE_ERROR;
		if (NH_SUCCESS(rv)) rv = (pPubKey = hRequest->hParser->sail(hRequest->subjectPKInfo, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_ISSUE_ERROR;
		if (NH_SUCCESS(rv))
		{
			pValue = (NH_PBITSTRING_VALUE) pPubKey->value;
			rv = (pValue->len == sizeof(__pubkey)) ? NH_OK : NH_ISSUE_ERROR;
			if (NH_SUCCESS(rv)) rv = (memcmp(pValue->string, &__pubkey, pValue->len) == 0) ? NH_OK : NH_ISSUE_ERROR;
			if (NH_SUCCESS(rv)) rv = hRequest->verify(hRequest);
		}
		NH_release_cert_request(hRequest);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}
int test_parse_pubkey()
{
	NH_RV rv;
	NH_CREQUEST_PARSER hRequest;
	unsigned int ulSize;
	NHIX_PUBLIC_KEY hPubkey;
	NH_ASN1_PNODE node;
	NH_PBITSTRING_VALUE pValue, qValue;

	printf("%s", "Testing public key parser... ");
	if (NH_SUCCESS(rv = NH_parse_cert_request(__request, sizeof(__request), &hRequest)))
	{
		ulSize = hRequest->subjectPKInfo->contents - hRequest->subjectPKInfo->identifier + hRequest->subjectPKInfo->size;
		if (NH_SUCCESS(rv = NHIX_pubkey_parser(hRequest->subjectPKInfo->identifier, ulSize, &hPubkey)))
		{
			rv = (node = hRequest->hParser->sail(hRequest->subjectPKInfo, NH_PARSE_SOUTH | 2)) ? NH_OK : NH_ISSUE_ERROR;
			if (NH_SUCCESS(rv)) rv = NH_match_oid((unsigned int*) node->value, node->valuelen,(unsigned int*) hPubkey->algorithm->value, hPubkey->algorithm->valuelen) ? NH_OK : NH_ISSUE_ERROR;
			if (NH_SUCCESS(rv)) rv = (node = hRequest->hParser->sail(hRequest->subjectPKInfo, (NH_SAIL_SKIP_SOUTH << 8) | NH_SAIL_SKIP_EAST)) ? NH_OK : NH_ISSUE_ERROR;
			if (NH_SUCCESS(rv))
			{
				pValue = (NH_PBITSTRING_VALUE) node->value;
				qValue = (NH_PBITSTRING_VALUE) hPubkey->pubkey->value;
				rv = (pValue->len == qValue->len) ? NH_OK : NH_ISSUE_ERROR;
				if (NH_SUCCESS(rv)) rv = memcmp(pValue->string, qValue->string, pValue->len) == 0  ? NH_OK : NH_ISSUE_ERROR;
				if (NH_SUCCESS(rv)) rv = hRequest->verify(hRequest);
			}
			NHIX_release_pubkey(hPubkey);
		}
		NH_release_cert_request(hRequest);
	}
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return rv;
}


static unsigned char __ca_privkey[] =
{
  0x30, 0x82, 0x04, 0xbd, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
  0x04, 0xa7, 0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01,
  0x01, 0x00, 0xdf, 0xb1, 0x2a, 0x92, 0xa2, 0xea, 0x8e, 0x50, 0x43, 0x77,
  0xc1, 0xc4, 0x47, 0x47, 0xce, 0x01, 0x77, 0x76, 0xbb, 0x71, 0xb5, 0xff,
  0x5b, 0xbb, 0xed, 0xfa, 0xe5, 0xc0, 0x0e, 0xc9, 0x33, 0xd6, 0xf8, 0x62,
  0xef, 0xe5, 0x7f, 0xe3, 0xcc, 0xff, 0x61, 0x45, 0xdb, 0xb6, 0x8c, 0x0a,
  0xbf, 0x1e, 0x11, 0x5c, 0xa5, 0xdc, 0x3e, 0x74, 0x23, 0xd7, 0x04, 0x15,
  0x69, 0xa4, 0xbc, 0x9f, 0x0c, 0xfb, 0xf7, 0xd1, 0xc8, 0x2a, 0x25, 0x4d,
  0x34, 0x31, 0x5e, 0xa0, 0x95, 0x9f, 0x2d, 0xf7, 0xd7, 0x8a, 0xa3, 0xda,
  0x3e, 0x39, 0x4d, 0xa1, 0x98, 0x64, 0xae, 0xf9, 0x72, 0x79, 0xb8, 0xda,
  0xb3, 0x8d, 0x69, 0xd7, 0x4c, 0xe4, 0x6a, 0xa8, 0x48, 0xe3, 0xb9, 0x17,
  0xa7, 0xe7, 0x0b, 0x08, 0x85, 0x0b, 0x33, 0x0f, 0x52, 0xf9, 0xdc, 0xf3,
  0xdb, 0xa0, 0x3e, 0x70, 0x89, 0x58, 0x4e, 0xea, 0xa1, 0x6b, 0x87, 0xe7,
  0x5b, 0xc2, 0xbc, 0xc7, 0x7c, 0x4a, 0xd2, 0xb7, 0xe1, 0xce, 0x69, 0x63,
  0xb8, 0xd8, 0xec, 0xa8, 0xeb, 0xd7, 0x41, 0xef, 0xb9, 0xd6, 0xc4, 0xea,
  0xd6, 0xf3, 0x85, 0x40, 0x70, 0x5b, 0x2b, 0x20, 0xd7, 0xc5, 0xfe, 0xa6,
  0x1c, 0x58, 0x63, 0x0c, 0xda, 0xbc, 0x2d, 0xc8, 0x79, 0x15, 0x40, 0xc2,
  0x8f, 0xe8, 0x23, 0xbf, 0x22, 0xec, 0xab, 0x17, 0xc5, 0x02, 0xcb, 0x44,
  0x4a, 0x66, 0x7d, 0x7e, 0xf3, 0xdd, 0xa0, 0x8a, 0x31, 0xbe, 0xd8, 0x03,
  0xc1, 0x6f, 0x1a, 0x42, 0x4b, 0x4a, 0xab, 0xc3, 0xdc, 0x56, 0x35, 0x66,
  0x9a, 0x48, 0x69, 0xec, 0xe5, 0x76, 0xa1, 0x20, 0xd7, 0x29, 0x1c, 0xec,
  0xe5, 0x49, 0xd9, 0xe2, 0xcb, 0xac, 0x45, 0x63, 0xe0, 0x3f, 0xf3, 0x39,
  0x95, 0x2c, 0x22, 0x7b, 0xda, 0xd8, 0xc7, 0x03, 0x40, 0xd3, 0xdf, 0x47,
  0xa5, 0xaa, 0x14, 0x50, 0x7b, 0xa1, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
  0x82, 0x01, 0x00, 0x77, 0x80, 0xea, 0xc1, 0x94, 0x0f, 0xc3, 0x1f, 0xd6,
  0x2b, 0x70, 0x75, 0x2f, 0xaf, 0x88, 0xba, 0xf7, 0xdb, 0x92, 0xa0, 0x59,
  0x1e, 0xa7, 0x1f, 0x6b, 0x30, 0x12, 0xf5, 0xdb, 0xf0, 0x59, 0xa5, 0x8a,
  0xe5, 0x30, 0x4c, 0x67, 0x5a, 0x87, 0xf6, 0x17, 0x3d, 0x7e, 0xf7, 0xb3,
  0x31, 0x3a, 0x91, 0x11, 0xad, 0x71, 0x5e, 0x8c, 0x6e, 0xf7, 0x86, 0xb3,
  0x43, 0xcd, 0x40, 0x99, 0x14, 0x4f, 0x97, 0x7c, 0xf9, 0xb1, 0xf9, 0xf2,
  0x1b, 0xa0, 0xba, 0x8f, 0x57, 0x33, 0x17, 0xeb, 0x32, 0xf1, 0x0f, 0xbc,
  0x21, 0xa8, 0x04, 0x6d, 0x18, 0xdb, 0x95, 0x4e, 0x75, 0x2d, 0x57, 0x22,
  0x0e, 0x94, 0xc6, 0x03, 0xb9, 0x65, 0xf6, 0xd1, 0x94, 0x3d, 0xfc, 0x8a,
  0xb1, 0xbc, 0x9d, 0x8e, 0x23, 0x6b, 0x10, 0x64, 0xa2, 0xd7, 0x2d, 0x6d,
  0x81, 0x49, 0xdf, 0xfd, 0xfb, 0x99, 0x24, 0x78, 0x64, 0x98, 0xff, 0x1d,
  0xcc, 0xbc, 0x88, 0xd0, 0xc9, 0x9f, 0x90, 0x03, 0xf5, 0x49, 0x4e, 0x18,
  0xb0, 0xdd, 0x91, 0x26, 0x27, 0x85, 0xa4, 0x8e, 0x6a, 0xa4, 0x62, 0xf7,
  0x2b, 0x86, 0x67, 0x12, 0x28, 0xcf, 0xa6, 0x3f, 0x44, 0xa0, 0xe0, 0x4f,
  0xa5, 0x2e, 0x67, 0x1a, 0xb7, 0x20, 0x29, 0xff, 0x19, 0x01, 0x55, 0xe0,
  0xe9, 0x09, 0x4d, 0x58, 0x57, 0xf6, 0xbb, 0x4e, 0x7c, 0x2d, 0xa2, 0xfc,
  0x6c, 0xde, 0x29, 0xda, 0x74, 0xc7, 0x90, 0xdc, 0x7a, 0x1c, 0x56, 0x41,
  0x95, 0x3a, 0x24, 0x86, 0xaa, 0x76, 0x77, 0xa7, 0x5b, 0x23, 0x48, 0xcd,
  0xa0, 0x92, 0x46, 0x3c, 0x5e, 0x3d, 0xad, 0xcd, 0x8d, 0xdf, 0xe0, 0x2e,
  0x97, 0x24, 0x05, 0xae, 0x7c, 0x5b, 0x18, 0x2e, 0x7d, 0xf4, 0xb3, 0xde,
  0x2c, 0x41, 0xda, 0xca, 0xd3, 0x79, 0x32, 0x18, 0xe7, 0xe1, 0x95, 0x25,
  0x96, 0x32, 0x7f, 0x4e, 0x82, 0xb0, 0xc1, 0x02, 0x81, 0x81, 0x00, 0xf3,
  0xaa, 0x88, 0xd9, 0x2a, 0xb1, 0xc2, 0x5d, 0xe4, 0xa3, 0x2b, 0x77, 0xb8,
  0x17, 0xf5, 0x67, 0xce, 0x41, 0x35, 0xfa, 0xde, 0xd6, 0x94, 0xe8, 0x1f,
  0x6b, 0xad, 0xad, 0xf7, 0x31, 0xa0, 0xb8, 0x7a, 0x17, 0x7e, 0xbd, 0x88,
  0xb3, 0x63, 0x09, 0xa0, 0xd2, 0x25, 0xd7, 0x04, 0x0b, 0x8d, 0x62, 0x42,
  0xbc, 0xb9, 0x61, 0x10, 0x09, 0x4b, 0x30, 0xf7, 0x54, 0x46, 0x32, 0x23,
  0x7f, 0xb0, 0x7b, 0x43, 0xa9, 0x59, 0xa8, 0xf9, 0xc2, 0xeb, 0xb0, 0x1e,
  0xfe, 0x55, 0x1e, 0x99, 0x07, 0x7b, 0xb0, 0x57, 0x26, 0x2e, 0x99, 0x9b,
  0x64, 0x46, 0x54, 0xf4, 0x6b, 0xa8, 0xc9, 0x5b, 0x69, 0xd5, 0x03, 0x93,
  0xea, 0xd9, 0xd8, 0xce, 0xe6, 0x60, 0xa3, 0x22, 0x18, 0xe9, 0x7e, 0xc3,
  0xf1, 0x92, 0xb1, 0x4c, 0x7e, 0x17, 0x2f, 0x92, 0x53, 0x2c, 0xec, 0x3f,
  0x4a, 0xdf, 0xd9, 0x82, 0x28, 0x25, 0x95, 0x02, 0x81, 0x81, 0x00, 0xeb,
  0x03, 0xcd, 0xde, 0xdb, 0x45, 0xc6, 0xd7, 0x3b, 0x6e, 0x15, 0x0b, 0x99,
  0xc2, 0x76, 0x02, 0x91, 0x14, 0x01, 0xb2, 0xb5, 0xa3, 0xb2, 0x54, 0x8b,
  0xf2, 0x1e, 0xc0, 0xc4, 0xd6, 0xac, 0x31, 0xe4, 0xb1, 0xf4, 0xd3, 0x58,
  0x1a, 0xec, 0x75, 0x71, 0xc8, 0x90, 0x36, 0x09, 0x65, 0xe0, 0xcc, 0x55,
  0x46, 0x5e, 0xc5, 0xc5, 0x51, 0x88, 0x28, 0x3a, 0xb6, 0xaf, 0x2a, 0xa9,
  0xb3, 0x08, 0xb7, 0x5d, 0xc2, 0x84, 0xb9, 0xee, 0x26, 0x1d, 0xb9, 0x1a,
  0x36, 0x8f, 0x6d, 0x6c, 0x9e, 0x2f, 0x32, 0x3a, 0x0a, 0x05, 0x19, 0x29,
  0x7c, 0x42, 0x87, 0x48, 0xaa, 0x5f, 0x6c, 0x0e, 0x8e, 0xa3, 0x0c, 0x99,
  0x3e, 0xbe, 0x1b, 0x2f, 0x2d, 0xd5, 0x8c, 0xbd, 0x00, 0x02, 0x69, 0x30,
  0x37, 0x5e, 0x2d, 0x2e, 0x09, 0xaa, 0xef, 0x87, 0x9e, 0x3f, 0x81, 0x35,
  0x27, 0x08, 0xc0, 0x18, 0xf1, 0x62, 0xdd, 0x02, 0x81, 0x81, 0x00, 0xbd,
  0xe6, 0x76, 0x68, 0xe9, 0xc1, 0x47, 0xfd, 0xed, 0x26, 0xcd, 0xc5, 0xac,
  0x0f, 0xe0, 0x0e, 0x5a, 0xcc, 0xaf, 0xc9, 0x28, 0xca, 0x8b, 0x9a, 0xac,
  0x82, 0x3b, 0x05, 0x8d, 0xd5, 0x7b, 0xb0, 0xca, 0x56, 0x6d, 0x4c, 0x41,
  0xb1, 0xac, 0xc9, 0xe0, 0x30, 0x67, 0x95, 0x3f, 0x6d, 0xd1, 0x6e, 0x77,
  0x1c, 0xa6, 0x4d, 0x63, 0x36, 0x1b, 0x07, 0xba, 0x7a, 0x4f, 0x8a, 0xdb,
  0xe7, 0xb4, 0x1f, 0x1d, 0x08, 0x6a, 0xfc, 0x2a, 0x4b, 0x23, 0x6c, 0x4b,
  0x7b, 0x63, 0xd3, 0x48, 0xe8, 0x70, 0x19, 0x6a, 0x92, 0x33, 0x57, 0x3b,
  0xa7, 0xd6, 0xb8, 0x77, 0x15, 0x40, 0xa2, 0x4d, 0x40, 0x19, 0xe7, 0x83,
  0xec, 0x50, 0x83, 0x8c, 0x1c, 0x37, 0xcc, 0x6b, 0xd2, 0x86, 0x87, 0x69,
  0x26, 0x68, 0x71, 0x0d, 0x70, 0x67, 0x99, 0x87, 0xac, 0x93, 0x22, 0x3b,
  0xe1, 0x9a, 0xbb, 0xe5, 0x98, 0x6c, 0x51, 0x02, 0x81, 0x80, 0x01, 0x10,
  0xa6, 0x59, 0x31, 0x33, 0x32, 0xc0, 0x7c, 0xf3, 0x75, 0xc2, 0xf4, 0xb2,
  0x6d, 0xe8, 0x7b, 0x11, 0xd5, 0x24, 0x23, 0x30, 0x97, 0xb9, 0x4c, 0x5d,
  0x0f, 0x88, 0x9e, 0x1b, 0xbe, 0xf2, 0x06, 0xf0, 0x4b, 0x84, 0xbd, 0xac,
  0x79, 0x8f, 0xda, 0xb1, 0x26, 0xfe, 0x27, 0xb2, 0xbf, 0x7f, 0x0d, 0x8f,
  0xe1, 0x14, 0x12, 0x5d, 0xd9, 0x39, 0x1d, 0x73, 0x00, 0x7e, 0x38, 0x00,
  0xa8, 0xb4, 0x74, 0x07, 0x52, 0xa4, 0xa9, 0x10, 0xa1, 0x27, 0xda, 0x97,
  0x8e, 0xb4, 0xd7, 0x3e, 0x2c, 0x46, 0x94, 0xfe, 0xc0, 0xa1, 0x29, 0x8f,
  0xf7, 0x99, 0x37, 0x5a, 0x16, 0x4e, 0x9e, 0x0e, 0x45, 0x6c, 0xe4, 0x30,
  0xe5, 0x99, 0xa7, 0xf0, 0x14, 0x3c, 0xac, 0x0a, 0x98, 0xf8, 0x33, 0x10,
  0xbd, 0x2b, 0x85, 0x3e, 0xe3, 0xf8, 0x6b, 0xeb, 0xea, 0xab, 0xc2, 0x3a,
  0xe8, 0x0e, 0x3e, 0xce, 0xb1, 0x3d, 0x02, 0x81, 0x80, 0x4c, 0x31, 0x68,
  0x98, 0x9e, 0xea, 0x63, 0x4a, 0x20, 0xb5, 0xa3, 0xbc, 0xc8, 0xed, 0xe1,
  0x38, 0x6f, 0xe1, 0xea, 0x4b, 0x34, 0x53, 0x7e, 0x07, 0x48, 0x43, 0x67,
  0x11, 0xba, 0x24, 0xf9, 0x3c, 0x09, 0x01, 0xd7, 0xb1, 0x16, 0x1b, 0x00,
  0xd8, 0x7d, 0xc9, 0x86, 0x6f, 0x1a, 0x4e, 0x97, 0xa4, 0x0a, 0xf1, 0x38,
  0x87, 0x5c, 0x64, 0x4e, 0x8a, 0x91, 0xd8, 0xe6, 0xa4, 0xdc, 0xc2, 0x51,
  0x92, 0x75, 0xc8, 0xe3, 0x97, 0xd0, 0x1c, 0xbb, 0xd0, 0x33, 0xf4, 0xe2,
  0x62, 0x32, 0x17, 0x2a, 0x3b, 0x0c, 0xd3, 0xa4, 0xab, 0xef, 0xd3, 0x12,
  0x83, 0x96, 0xc7, 0xe6, 0x22, 0xec, 0x2b, 0x35, 0x1a, 0xae, 0x45, 0x7e,
  0xd7, 0x26, 0x1c, 0xbd, 0x0f, 0xe0, 0xde, 0xdf, 0x92, 0x75, 0x8e, 0x9b,
  0x49, 0x00, 0x7b, 0x99, 0x2f, 0xa6, 0x52, 0x7f, 0x0c, 0x5d, 0xb6, 0x2c,
  0xab, 0xd0, 0x8b, 0x1d, 0xd6
};
static unsigned int _uVersion = 2;
static unsigned char _pSerial[] = { 0x22, 0xDE };
static unsigned int _sha256WithRSAEncryption_oid[] = { 1, 2, 840, 113549, 1, 1, 11 };
static unsigned int _c_oid[] = { 2, 5, 4, 6 };
static unsigned int _o_oid[] = { 2, 5, 4, 10 };
static unsigned int _ou_oid[] = { 2, 5, 4, 11 };
static unsigned int _cn_oid[] = { 2, 5, 4, 3 };
static char *_cn_subject = "JOAQUIM JOSE DA SILVA XAVIER";
static char *_notBefore = "20190425173943Z";
static char *_notAfter = "20200425173943Z";
static unsigned char _aki[] = { 0x06, 0x06, 0x9A, 0x22, 0xC4, 0xA7, 0xC0, 0xF8, 0x55, 0xFE, 0x05, 0xEA, 0x86, 0x37, 0x0A, 0x8D, 0x2D, 0xC0, 0x17, 0xD3 };
static unsigned char _keyUsage[] = { 0x05, 0xE0 };
static unsigned int _microsoft_upn_oid[] = { 1, 3, 6, 1, 4, 1, 311, 20, 2, 3 };
static unsigned int _subject_id_oid[] = { 2, 16, 76, 1, 3, 1 };
static unsigned int _subject_te_id_oid[] = { 2, 16, 76, 1, 3, 5 };
static unsigned int _subject_cei_id_oid[] = { 2, 16, 76, 1, 3, 6 };
static unsigned int _clientAuth_oid[] = { 1, 3, 6, 1, 5, 5, 7, 3, 2 };
static unsigned int _emailProtection_oid[] = { 1, 3, 6, 1, 5, 5, 7, 3, 4  };
static char *_cdp = "http://www.caixa.gov.br/tkn/repo\0\0";
static NH_OID_STR pC_OID = { _c_oid, NHC_OID_COUNT(_c_oid) };
static NH_OID_STR pO_OID = { _o_oid, NHC_OID_COUNT(_o_oid) };
static NH_OID_STR pOU_OID ={ _ou_oid, NHC_OID_COUNT(_ou_oid) };
static NH_OID_STR pCN_OID = { _cn_oid, NHC_OID_COUNT(_cn_oid) };
static NH_OID_STR pUPN_OID =  { _microsoft_upn_oid, NHC_OID_COUNT(_microsoft_upn_oid) };
static NH_OID_STR pSubjectId_OID = { _subject_id_oid, NHC_OID_COUNT(_subject_id_oid) };
static NH_OID_STR pSubjectTE_OID = { _subject_te_id_oid, NHC_OID_COUNT(_subject_te_id_oid) };
static NH_OID_STR pSubjectCEI_OID = { _subject_cei_id_oid, NHC_OID_COUNT(_subject_cei_id_oid) };
static int __create_TBS( _OUT_ NH_TBSCERT_ENCODER *hOut)
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hTBSCert;
	NH_BIG_INTEGER iSerial = { _pSerial, 2 };
	NH_OID_STR pOID = { NULL, 0 };
	NH_NAME_STR pC = { &pC_OID, "BR" };
	NH_NAME_STR pO = { &pO_OID, "PKI Brazil" };	
	NH_NAME_STR pOU = { &pOU_OID, "PKI Ruler for All Cats" };
	NH_NAME_STR pCN = { &pCN_OID, "Common Name for All Cats End User CA" };
	NH_NAME pIssuer[4], pSubject[1];
	NH_CREQUEST_PARSER hRequest;
	NH_OCTET_SRING octetsValue = { NULL, 0 };
	NH_NAME_STR pUPN = { &pUPN_OID, "imyself@microsofot, com" };
	NH_NAME_STR pSubjectId = { &pSubjectId_OID, "000000000000000000000000000000000000000000000DETRANRJ" };
	NH_NAME_STR pSubjectTE = { &pSubjectTE_OID, "0000000000000000000Rio de Janeiro      RJ" };
	NH_NAME_STR pSubjectCEI = { &pSubjectCEI_OID, "000000000000" };
	NH_OTHER_NAME pAltName[4];
	NH_OID_STR pClientAuth = { _clientAuth_oid, NHC_OID_COUNT(_clientAuth_oid) };
	NH_OID_STR pEmailProtection = { _emailProtection_oid, NHC_OID_COUNT(_emailProtection_oid) };
	NH_OID pExtKey[2];

	if (NH_SUCCESS(rv = NH_new_tbscert_encoder(&hTBSCert)))
	{
		rv = hTBSCert->put_version(hTBSCert, _uVersion);
		if (NH_SUCCESS(rv)) rv = hTBSCert->put_serial(hTBSCert, &iSerial);
		if (NH_SUCCESS(rv))
		{
			pOID.pIdentifier = _sha256WithRSAEncryption_oid;
			pOID.uCount = NHC_OID_COUNT(_sha256WithRSAEncryption_oid);
			rv = hTBSCert->put_sign_alg(hTBSCert, &pOID);
		}
		if (NH_SUCCESS(rv))
		{
			pIssuer[0] = &pC;
			pIssuer[1] = &pO;
			pIssuer[2] = &pOU;
			pIssuer[3] = &pCN;
			rv = hTBSCert->put_issuer(hTBSCert, pIssuer, 4);
		}
		if (NH_SUCCESS(rv))
		{
			pCN.szValue = _cn_subject;
			pSubject[0] = &pCN;
			rv = hTBSCert->put_subject(hTBSCert, pSubject, 1);
		}
		if (NH_SUCCESS(rv)) rv = hTBSCert->put_validity(hTBSCert, _notBefore, _notAfter);
		if (NH_SUCCESS(rv))
		{
			if (NH_SUCCESS(rv = NH_parse_cert_request(__request, sizeof(__request), &hRequest)))
			{
				rv = hTBSCert->put_pubkey(hTBSCert, hRequest->subjectPKInfo);
				NH_release_cert_request(hRequest);
			}
		}
		if (NH_SUCCESS(rv))
		{
			octetsValue.data = _aki;
			octetsValue.length = sizeof(_aki);
			rv = hTBSCert->put_aki(hTBSCert, &octetsValue);
		}
		if (NH_SUCCESS(rv))
		{
			octetsValue.data = _keyUsage;
			octetsValue.length = sizeof(_keyUsage);
			rv = hTBSCert->put_key_usage(hTBSCert, &octetsValue);
		}
		if (NH_SUCCESS(rv))
		{
			pAltName[0] = &pUPN;
			pAltName[1] = &pSubjectId;
			pAltName[2] = &pSubjectTE;
			pAltName[3] = &pSubjectCEI;
			rv = hTBSCert->put_subject_altname(hTBSCert, pAltName, 4);
		}
		/* TODO: Check __put_basic_constraints */
		if (NH_SUCCESS(rv))
		{
			pExtKey[0] = &pClientAuth;
			pExtKey[1] = &pEmailProtection;
			rv = hTBSCert->put_extkey_usage(hTBSCert, pExtKey, 2);
		}
		if
		(
			NH_SUCCESS(rv) &&
			NH_SUCCESS(rv = hTBSCert->put_cdp(hTBSCert, _cdp))
		)	*hOut = hTBSCert;
	}
	return rv;
}
NH_RV __callback(_IN_ NH_BLOB *data, _IN_ CK_MECHANISM_TYPE mechanism, _IN_ void *params, _OUT_ unsigned char *signature, _INOUT_ size_t *sigSize)
{
	NH_RSA_PRIVKEY_HANDLER hHandler = (NH_RSA_PRIVKEY_HANDLER) params;
	return hHandler->sign(hHandler, mechanism, data->data, data->length, signature, sigSize);
}
int test_sign_certificate()
{
	NH_RV rv;
	NH_TBSCERT_ENCODER hTBSCert;
	NH_CERT_ENCODER hCertificate;
	NH_RSA_PRIVKEY_HANDLER hPrivKey;
	unsigned char *pBuffer;
	size_t uSize;

	if (NH_SUCCESS(__create_TBS(&hTBSCert)))
	{
		if (NH_SUCCESS(rv = NH_new_cert_encoder(&hCertificate)))
		{
			if (NH_SUCCESS(rv = NH_new_RSA_privkey_handler(&hPrivKey)))
			{
				if
				(
					NH_SUCCESS(rv = hPrivKey->from_privkey_info(hPrivKey, __ca_privkey, sizeof(__ca_privkey))) &&
					NH_SUCCESS(rv = hCertificate->sign(hCertificate, hTBSCert, CKM_SHA256_RSA_PKCS, __callback, hPrivKey)) &&
					NH_SUCCESS(rv = (uSize = hCertificate->hEncoder->encoded_size(hCertificate->hEncoder, hCertificate->hEncoder->root)) > 0 ? NH_OK : NH_ISSUE_ERROR) &&
					NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR)
				)
				{
					rv = hCertificate->hEncoder->encode(hCertificate->hEncoder, hCertificate->hEncoder->root, pBuffer);
					free(pBuffer);
				}
				NH_release_RSA_privkey_handler(hPrivKey);
			}
			NH_delete_cert_encoder(hCertificate);
		}
		NH_delete_tbscert_encoder(hTBSCert);
	}
	return rv;
}