#include "test.h"
#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static unsigned char token[] =
{
	0x30, 0x81, 0xBA, 0x13, 0x10, 0x31, 0x32, 0x32, 0x31, 0x39, 0x33, 0x31, 0x36, 0x39, 0x31, 0x34,
	0x32, 0x20, 0x20, 0x20, 0x20, 0x30, 0x81, 0xA5, 0x01, 0x01, 0xFF, 0x01, 0x01, 0x00, 0x31, 0x81,
	0x9C, 0x30, 0x0E, 0x02, 0x02, 0x01, 0x31, 0x02, 0x02, 0x80, 0x01, 0x80, 0x01, 0x18, 0x81, 0x01,
	0x18, 0x30, 0x0E, 0x02, 0x02, 0x01, 0x00, 0x02, 0x02, 0x80, 0x01, 0x80, 0x01, 0x28, 0x81, 0x01,
	0x80, 0x30, 0x0E, 0x02, 0x02, 0x10, 0x80, 0x02, 0x02, 0x80, 0x01, 0x80, 0x01, 0x10, 0x81, 0x01,
	0x20, 0x30, 0x08, 0x02, 0x02, 0x02, 0x10, 0x02, 0x02, 0x04, 0x00, 0x30, 0x08, 0x02, 0x02, 0x02,
	0x20, 0x02, 0x02, 0x04, 0x00, 0x30, 0x08, 0x02, 0x02, 0x02, 0x50, 0x02, 0x02, 0x04, 0x00, 0x30,
	0x07, 0x02, 0x01, 0x05, 0x02, 0x02, 0x28, 0x01, 0x30, 0x07, 0x02, 0x01, 0x06, 0x02, 0x02, 0x28,
	0x01, 0x30, 0x07, 0x02, 0x01, 0x40, 0x02, 0x02, 0x28, 0x01, 0x30, 0x09, 0x02, 0x02, 0x01, 0x33,
	0x02, 0x03, 0x06, 0x03, 0x01, 0x30, 0x09, 0x02, 0x02, 0x01, 0x02, 0x02, 0x03, 0x06, 0x03, 0x01,
	0x30, 0x09, 0x02, 0x02, 0x10, 0x82, 0x02, 0x03, 0x06, 0x03, 0x01, 0x30, 0x10, 0x02, 0x01, 0x00,
	0x02, 0x03, 0x01, 0x00, 0x01, 0x80, 0x02, 0x02, 0x00, 0x81, 0x02, 0x08, 0x00
};

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

int test_parser()
{
	NH_ASN1_PARSER_HANDLE hHandle;
	NH_ASN1_PNODE node;
	NH_RV rv, frv;
	char serial[17];

	if (NH_SUCCESS(rv = NH_new_parser(token, sizeof(token), 72, 512, &hHandle)))
	{
		if (NH_SUCCESS(rv = hHandle->map(hHandle, token_obj_map, ASN_NODE_WAY_COUNT(token_obj_map))))
		{
			if ((node = hHandle->sail(hHandle->root, NH_SAIL_SKIP_SOUTH)))
			{
				if (NH_SUCCESS(rv = hHandle->parse_string(node)))
				{
                              memset(serial, 0, 17);
                              memcpy(serial, node->value, node->valuelen);
                              rv = strcmp(serial, SERIAL_NUMBER);
				}
			}
			else rv = NH_UNEXPECTED_ENCODING;
		}
		frv = NH_release_parser(hHandle);
	}
	printf("\nParsing test run with NH_RV %lu and NH_SYSRV %lu and %lu for NH_release_parser", G_ERROR(rv), G_SYSERROR(rv), frv);
	return (int) rv;
}


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
	NH_RV rv, frv;
	NH_ASN1_ENCODER_HANDLE hHandle;
	NH_ASN1_PNODE node;
	size_t len;
	char *serial = SERIAL_NUMBER;
	unsigned char *buffer;

	if (NH_SUCCESS(rv = NH_new_encoder(72, 512, &hHandle)))
	{
		if (NH_SUCCESS(rv = hHandle->chart(hHandle, token_obj_map, ASN_NODE_WAY_COUNT(token_obj_map), &node)))
		{
			if ((node = hHandle->sail(node, NH_SAIL_SKIP_SOUTH)))
			{
				if (NH_SUCCESS(rv = hHandle->put_printable_string(hHandle, node, (void*) serial, strlen(serial))))
				{
					if ((node = hHandle->sail(node, (NH_SAIL_SKIP_EAST << 8) | NH_SAIL_SKIP_SOUTH)))
					{
						if (NH_SUCCESS(rv = hHandle->put_boolean(hHandle, node, TRUE)))
						{
							if ((node = hHandle->sail(node, NH_SAIL_SKIP_EAST)))
							{
								if (NH_SUCCESS(rv = hHandle->put_boolean(hHandle, node, FALSE)))
								{
									if (NH_SUCCESS(rv = encode_all_features(hHandle, node->next)))
									{
										len = hHandle->encoded_size(hHandle, hHandle->root);
										if (!(buffer = (unsigned char*) malloc(len))) rv = NH_OUT_OF_MEMORY_ERROR;
										else
										{
											if (NH_SUCCESS(rv = hHandle->encode(hHandle, hHandle->root, buffer)))
											{
												if (NH_SUCCESS(rv = len == sizeof(token) ? 0 : 1)) rv = memcmp(buffer, token, len);
											}
											free(buffer);
										}
									}
								}
							}
							else rv = NH_CANNOT_SAIL;
						}
					}
					else rv = NH_CANNOT_SAIL;
				}
			}
			else rv = NH_CANNOT_SAIL;
		}
		frv = NH_release_encoder(hHandle);
	}
	printf("Encoding test run with NH_RV %lu and NH_SYSRV %lu and %lu for NH_release_parser\n", G_ERROR(rv), G_SYSERROR(rv), frv);
	return (int) rv;
}
