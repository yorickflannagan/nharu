#include "test.h"
#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static NH_NODE_WAY supported_mechanisms_map[] =
{
	{	/* SupportedMechanisms */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* mechanism */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_INTEGER| NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* flags */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* minKeySize */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_0 | NH_ASN1_OPTIONAL_BIT | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* maxKeySize */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_INTEGER | NH_ASN1_CONTEXT_BIT | NH_ASN1_CT_TAG_1 | NH_ASN1_OPTIONAL_BIT,
		NULL,
		0
	}
};
static NH_NODE_WAY token_obj_map[] =
{
	{	/* TokenObj */
		NH_PARSE_ROOT,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* serial */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_PRINTABLE_STRING | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* TokenFeatures */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SEQUENCE,
		NULL,
		0
	},
	{	/* rng */
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_BOOLEAN | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* clock */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_BOOLEAN | NH_ASN1_HAS_NEXT_BIT,
		NULL,
		0
	},
	{	/* SupportedMechanisms */
		NH_SAIL_SKIP_EAST,
		NH_ASN1_SET,
		NULL,
		0
	},
	{
		NH_SAIL_SKIP_SOUTH,
		NH_ASN1_TWIN_BIT,
		supported_mechanisms_map,
		ASN_NODE_WAY_COUNT(supported_mechanisms_map)
	}
};
#define SERIAL_NUMBER		"122193169142    "


NH_RV encode_feature(NH_ASN1_ENCODER_HANDLE hHandle, NH_ASN1_PNODE set, unsigned int *feature)
{
	NH_ASN1_PNODE node;
	NH_RV rv;
	if (!(node = hHandle->add_to_set(hHandle->container, set))) return NH_OUT_OF_MEMORY_ERROR;
	if (NH_FAIL(rv = hHandle->chart_from(hHandle, node, supported_mechanisms_map, ASN_NODE_WAY_COUNT(supported_mechanisms_map)))) return rv;
	node = node->child;
	if (NH_FAIL(rv = hHandle->put_little_integer(hHandle, node, feature[0]))) return rv;
	node = node->next;
	if (NH_FAIL(rv = hHandle->put_little_integer(hHandle, node, feature[1]))) return rv;
	if (feature[2] > 0 && feature[3] > 0)
	{
		node = node->next;
		hHandle->register_optional(node);
		if (NH_FAIL(rv = hHandle->put_little_integer(hHandle, node, feature[2]))) return rv;
		node = node->next;
		hHandle->register_optional(node);
		if (NH_FAIL(rv = hHandle->put_little_integer(hHandle, node, feature[3]))) return rv;
	}
	return rv;
}
static unsigned int f1[] = {305, 32769, 24, 24};
static unsigned int f2[] = {256, 32769, 40, 128};
static unsigned int f3[] = {4224, 32769, 16, 32};
static unsigned int f4[] = {528, 1024, 0, 0};
static unsigned int f5[] = {544, 1024, 0, 0};
static unsigned int f6[] = {592, 1024, 0, 0};
static unsigned int f7[] = {5, 10241, 0, 0};
static unsigned int f8[] = {6, 10241, 0, 0};
static unsigned int f9[] = {64, 10241, 0, 0};
static unsigned int f10[] = {307, 393985, 0, 0};
static unsigned int f11[] = {258, 393985, 0, 0};
static unsigned int f12[] = {4226, 393985, 0, 0};
static unsigned int f13[] = {0, 65537, 512, 2048};
NH_RV encode_all_features(NH_ASN1_ENCODER_HANDLE hHandle, NH_ASN1_PNODE set)
{
	NH_RV rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f1))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f2))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f3))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f4))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f5))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f6))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f7))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f8))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f9))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f10))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f11))) return rv;
	if (NH_FAIL(rv = encode_feature(hHandle, set, f12))) return rv;
	return encode_feature(hHandle, set, f13);
}
int test_encoder()
{
	NH_RV rv;
	NH_ASN1_ENCODER_HANDLE hHandle = NULL;
	NH_ASN1_PARSER_HANDLE hParser = NULL;
	NH_ASN1_PNODE node = NULL;
	size_t len = 0;
	char *serial = SERIAL_NUMBER;
	unsigned char *buffer = NULL;

	printf("%s", "Testing ASN.1 encoding of a PKCS #11 token... ");
	rv = NH_new_encoder(72, 512, &hHandle);
	if (NH_SUCCESS(rv)) rv = hHandle->chart(hHandle, token_obj_map, ASN_NODE_WAY_COUNT(token_obj_map), &node);
	if (NH_SUCCESS(rv)) rv = (node = hHandle->sail(node, NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hHandle->put_printable_string(hHandle, node, (void*)serial, strlen(serial));
	if (NH_SUCCESS(rv)) rv = (node = hHandle->sail(node, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hHandle->put_boolean(hHandle, node, TRUE);
	if (NH_SUCCESS(rv)) rv = (node = hHandle->sail(node, NH_SAIL_SKIP_EAST)) ? NH_OK : NH_CANNOT_SAIL;
	if (NH_SUCCESS(rv)) rv = hHandle->put_boolean(hHandle, node, FALSE);
	if (NH_SUCCESS(rv)) rv = encode_all_features(hHandle, node->next);
	if (NH_SUCCESS(rv))
	{
		len = hHandle->encoded_size(hHandle, hHandle->root);
		rv = (buffer = (unsigned char*) malloc(len)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR;
		if (NH_SUCCESS(rv)) rv = hHandle->encode(hHandle, hHandle->root, buffer);
	}
	if (hHandle) NH_release_encoder(hHandle);

	if (NH_SUCCESS(rv)) rv = NH_new_parser(buffer, len, 72, 512, &hParser);
	if (NH_SUCCESS(rv)) rv = hParser->map(hParser, token_obj_map, ASN_NODE_WAY_COUNT(token_obj_map));
	if (NH_SUCCESS(rv)) rv = (node = hParser->sail(hParser->root, NH_SAIL_SKIP_SOUTH)) ? NH_OK : NH_UNEXPECTED_ENCODING;
	if (NH_SUCCESS(rv)) rv = hParser->parse_string(node);
	if (NH_SUCCESS(rv)) rv = node->valuelen == strlen(serial) && memcmp(node->value, serial, node->valuelen) == 0 ? NH_OK : 1;
	if (buffer) free(buffer);
	if (NH_SUCCESS(rv)) printf("%s\n", "succeeded!");
	else printf("failed with error code %lu\n", rv);
	return (int) rv;
}


static unsigned char indef_length[] =
{
	0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, 0xA0, 0x80, 0x30,
	0x80, 0x02, 0x01, 0x01, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05,
	0x00, 0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x00, 0x00,
	0x31, 0x82, 0x02, 0x29, 0x30, 0x82, 0x02, 0x25, 0x02, 0x01, 0x01, 0x30, 0x77, 0x30, 0x72, 0x31,
	0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x52, 0x31, 0x13, 0x30, 0x11,
	0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0A, 0x50, 0x4B, 0x49, 0x20, 0x42, 0x72, 0x61, 0x7A, 0x69,
	0x6C, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x16, 0x50, 0x4B, 0x49, 0x20,
	0x52, 0x75, 0x6C, 0x65, 0x72, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x41, 0x6C, 0x6C, 0x20, 0x43, 0x61,
	0x74, 0x73, 0x31, 0x2D, 0x30, 0x2B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x24, 0x43, 0x6F, 0x6D,
	0x6D, 0x6F, 0x6E, 0x20, 0x4E, 0x61, 0x6D, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x41, 0x6C, 0x6C,
	0x20, 0x43, 0x61, 0x74, 0x73, 0x20, 0x45, 0x6E, 0x64, 0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x43,
	0x41, 0x02, 0x01, 0x01, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0xA0,
	0x81, 0x88, 0x30, 0x18, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03, 0x31,
	0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x1C, 0x06, 0x09,
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05, 0x31, 0x0F, 0x17, 0x0D, 0x31, 0x36, 0x30,
	0x37, 0x32, 0x35, 0x31, 0x33, 0x33, 0x35, 0x33, 0x34, 0x5A, 0x30, 0x23, 0x06, 0x09, 0x2A, 0x86,
	0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x31, 0x16, 0x04, 0x14, 0x42, 0x1E, 0x6B, 0x3B, 0x38,
	0x06, 0xD1, 0xBA, 0xB2, 0xF4, 0x07, 0x5F, 0x59, 0xCD, 0x86, 0x09, 0xE5, 0xBD, 0x7C, 0x95, 0x30,
	0x29, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x34, 0x31, 0x1C, 0x30, 0x1A,
	0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0xA1, 0x0D, 0x06, 0x09, 0x2A,
	0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
	0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x01, 0x00, 0x2F, 0x15, 0x44,
	0x52, 0x9B, 0xE3, 0xBD, 0x2C, 0x1F, 0x9A, 0xD4, 0x62, 0x70, 0xB9, 0x71, 0x2F, 0xE9, 0x69, 0x5D,
	0x75, 0xD0, 0x24, 0xF3, 0x77, 0xA3, 0xB0, 0x3F, 0xDE, 0xF9, 0x0B, 0x17, 0x16, 0x31, 0x32, 0x03,
	0x86, 0x96, 0xC2, 0x20, 0x3D, 0x90, 0xE9, 0xF7, 0x07, 0xB5, 0x7C, 0x21, 0x24, 0xE1, 0xBF, 0xA0,
	0x73, 0xF3, 0xCF, 0xC3, 0xD8, 0xA2, 0x99, 0x25, 0x97, 0x58, 0xD1, 0x86, 0x3C, 0x93, 0x8A, 0x83,
	0xC1, 0x58, 0x50, 0x95, 0xDA, 0xE2, 0x92, 0x69, 0xC4, 0xB6, 0xBF, 0x9B, 0x70, 0x0B, 0x46, 0x68,
	0x79, 0x7B, 0x81, 0x51, 0x10, 0xA8, 0xA4, 0xCA, 0x29, 0xCD, 0x8C, 0x28, 0x95, 0x01, 0xF7, 0x2F,
	0xA9, 0x68, 0x48, 0x09, 0xCD, 0x1A, 0xAA, 0xA1, 0x38, 0x8F, 0x08, 0x92, 0x12, 0x73, 0xDE, 0x71,
	0x08, 0xDB, 0x5F, 0x0C, 0xDB, 0x71, 0xB2, 0x14, 0x52, 0x3E, 0x5E, 0x93, 0xA2, 0xA1, 0xBF, 0x37,
	0x23, 0x82, 0x21, 0x45, 0xF0, 0xF9, 0xB1, 0x8D, 0xB8, 0x36, 0xF2, 0x7A, 0x03, 0xCD, 0x7C, 0xDB,
	0x2C, 0x53, 0xD4, 0x83, 0x5B, 0x02, 0x3B, 0xF8, 0x99, 0xCC, 0x38, 0x4C, 0xEC, 0xAE, 0xB4, 0xBF,
	0xB2, 0x22, 0x4A, 0x89, 0x18, 0x26, 0x6C, 0xE5, 0x04, 0x83, 0x94, 0x09, 0xBC, 0x67, 0x3A, 0x1F,
	0xDB, 0x95, 0x37, 0x5C, 0x86, 0x74, 0x79, 0x51, 0x63, 0x3E, 0x82, 0x0A, 0x87, 0x92, 0x6F, 0xCF,
	0xFC, 0x4E, 0x5A, 0x19, 0x93, 0xBC, 0x41, 0x7B, 0x3A, 0x0D, 0x33, 0x79, 0x00, 0x99, 0xD5, 0xD2,
	0x9F, 0x0F, 0x2A, 0xCB, 0xA4, 0x98, 0x97, 0xF5, 0x60, 0xEB, 0x28, 0x5B, 0x75, 0x50, 0xDC, 0x3D,
	0xE7, 0x27, 0xD4, 0x87, 0xE2, 0x8E, 0x9E, 0x00, 0xAD, 0x25, 0x9D, 0x93, 0xB5, 0x70, 0x0E, 0x4B,
	0x0B, 0x51, 0x8D, 0x42, 0x1D, 0x7B, 0x99, 0x7A, 0x38, 0x9C, 0x17, 0x37, 0x90, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00
};

int test_indefinite_length_form()
{
	int rv;
	NH_CMS_SD_PARSER hCMS;

	printf("Checking indefinite length octets form implementation... ");
	if (NH_SUCCESS(rv = NH_cms_parse_signed_data(indef_length, sizeof(indef_length), &hCMS)))
	{
		NH_cms_release_sd_parser(hCMS);
	}
	if (NH_SUCCESS(rv)) printf("Done!\n");
	else printf("Failed with %d error code\n", rv);
	return rv;
}
