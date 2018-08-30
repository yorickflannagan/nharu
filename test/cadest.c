#include "cms.h"
#include <stdio.h>
#include <string.h>
#include "test.h"

static unsigned char sign_cert[] =
{
	0x30, 0x82, 0x04, 0xE6, 0x30, 0x82, 0x03, 0xCE, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00,
	0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30,
	0x72, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x52, 0x31, 0x13,
	0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0A, 0x50, 0x4B, 0x49, 0x20, 0x42, 0x72, 0x61,
	0x7A, 0x69, 0x6C, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x16, 0x50, 0x4B,
	0x49, 0x20, 0x52, 0x75, 0x6C, 0x65, 0x72, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x41, 0x6C, 0x6C, 0x20,
	0x43, 0x61, 0x74, 0x73, 0x31, 0x2D, 0x30, 0x2B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x24, 0x43,
	0x6F, 0x6D, 0x6D, 0x6F, 0x6E, 0x20, 0x4E, 0x61, 0x6D, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x41,
	0x6C, 0x6C, 0x20, 0x43, 0x61, 0x74, 0x73, 0x20, 0x45, 0x6E, 0x64, 0x20, 0x55, 0x73, 0x65, 0x72,
	0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 0x31, 0x32, 0x32, 0x31, 0x31, 0x36, 0x35,
	0x34, 0x34, 0x34, 0x5A, 0x17, 0x0D, 0x31, 0x36, 0x31, 0x32, 0x32, 0x30, 0x31, 0x36, 0x35, 0x34,
	0x34, 0x34, 0x5A, 0x30, 0x5B, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
	0x42, 0x52, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0A, 0x50, 0x4B, 0x49,
	0x20, 0x42, 0x72, 0x61, 0x7A, 0x69, 0x6C, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x0B,
	0x13, 0x16, 0x50, 0x4B, 0x49, 0x20, 0x52, 0x75, 0x6C, 0x65, 0x72, 0x20, 0x66, 0x6F, 0x72, 0x20,
	0x41, 0x6C, 0x6C, 0x20, 0x43, 0x61, 0x74, 0x73, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04,
	0x03, 0x13, 0x0D, 0x46, 0x75, 0x6C, 0x61, 0x6E, 0x6F, 0x20, 0x64, 0x65, 0x20, 0x54, 0x61, 0x6C,
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
	0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01,
	0x00, 0xCE, 0x3E, 0x56, 0x18, 0x61, 0x37, 0x60, 0x17, 0x07, 0x58, 0x4D, 0xEC, 0x88, 0xAE, 0x46,
	0xC8, 0x3B, 0xE7, 0x07, 0x40, 0xA6, 0x42, 0x50, 0x0C, 0xD8, 0x48, 0x73, 0x4C, 0xC0, 0x09, 0xF8,
	0xD8, 0x2A, 0xBC, 0x2E, 0xD5, 0x33, 0x74, 0xB2, 0xA1, 0x65, 0xC2, 0x04, 0x61, 0x0A, 0xFF, 0x7C,
	0xD5, 0x97, 0xB1, 0x89, 0x09, 0x36, 0xCD, 0x88, 0x7D, 0xA8, 0x1A, 0x32, 0xCA, 0x8C, 0xC9, 0xFB,
	0x81, 0xB2, 0x07, 0xCE, 0xDD, 0x1D, 0x20, 0x24, 0x0B, 0xDF, 0xFE, 0xA9, 0x31, 0xA2, 0x6C, 0x6E,
	0x5D, 0x2F, 0x1D, 0xB5, 0x2D, 0xFE, 0x2F, 0xBE, 0x89, 0x6C, 0xBC, 0x7A, 0xCA, 0x1B, 0x93, 0x15,
	0xB5, 0x98, 0x88, 0x9C, 0x85, 0x61, 0x97, 0xFC, 0x9D, 0xA1, 0x47, 0x38, 0x40, 0xCA, 0xA4, 0x2B,
	0xB7, 0xEF, 0x37, 0x24, 0xE4, 0x62, 0x58, 0xBC, 0x39, 0x4D, 0x54, 0xA8, 0xE4, 0xE3, 0x37, 0xDA,
	0xBB, 0x24, 0x57, 0x3A, 0x47, 0xEC, 0x40, 0x40, 0xCB, 0x1F, 0x81, 0x71, 0xA7, 0x19, 0x3A, 0xB6,
	0x5F, 0x78, 0x3A, 0xC4, 0xC8, 0xFA, 0x91, 0x47, 0x1B, 0xA6, 0xD1, 0x19, 0xE0, 0xB4, 0x0A, 0xFE,
	0x13, 0x50, 0x70, 0x37, 0xA1, 0x5E, 0x3E, 0x33, 0x5D, 0x72, 0x9C, 0xFD, 0xB2, 0xAE, 0x05, 0xAD,
	0x16, 0x59, 0xE9, 0x02, 0x7D, 0xFD, 0xDD, 0x1A, 0x59, 0xEE, 0x02, 0x57, 0x79, 0xC4, 0xE0, 0xB0,
	0x5E, 0xA0, 0xF1, 0x09, 0xA4, 0x12, 0xEB, 0xDD, 0x0B, 0x39, 0x93, 0xF1, 0x3F, 0xC8, 0xCB, 0x17,
	0xB0, 0x50, 0x31, 0xB3, 0x58, 0x40, 0x7E, 0x5B, 0xF2, 0x69, 0x84, 0x15, 0x55, 0x97, 0x38, 0x09,
	0x22, 0x17, 0x59, 0x4E, 0x80, 0xC9, 0x4D, 0x03, 0x34, 0x57, 0x57, 0x1F, 0x57, 0xC9, 0x0C, 0xDF,
	0x87, 0x9D, 0x81, 0xB2, 0x98, 0xE0, 0xD4, 0x63, 0xC3, 0x60, 0x56, 0x54, 0x97, 0x3F, 0x50, 0xDE,
	0x97, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x9C, 0x30, 0x82, 0x01, 0x98, 0x30, 0x09,
	0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E,
	0x04, 0x16, 0x04, 0x14, 0x87, 0xBA, 0x7D, 0xA1, 0xC5, 0xDC, 0x5A, 0x43, 0xBD, 0x03, 0x92, 0xD4,
	0xD2, 0xCB, 0xA4, 0xDE, 0xE8, 0xB9, 0x91, 0x40, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04,
	0x18, 0x30, 0x16, 0x80, 0x14, 0x5C, 0x26, 0xE7, 0xBC, 0x23, 0x3C, 0xB5, 0x32, 0xBF, 0x87, 0xC4,
	0xC3, 0x45, 0xA1, 0xAE, 0x6C, 0x11, 0x2A, 0x50, 0x08, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F,
	0x04, 0x04, 0x03, 0x02, 0x05, 0xE0, 0x30, 0x29, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x22, 0x30,
	0x20, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06, 0x01,
	0x05, 0x05, 0x07, 0x03, 0x04, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02,
	0x02, 0x30, 0x2C, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x25, 0x30, 0x23, 0x30, 0x21, 0xA0, 0x1F,
	0xA0, 0x1D, 0x86, 0x1B, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6C, 0x6F, 0x63, 0x61, 0x6C,
	0x68, 0x6F, 0x73, 0x74, 0x2F, 0x61, 0x63, 0x2F, 0x65, 0x6E, 0x64, 0x2E, 0x63, 0x72, 0x6C, 0x30,
	0x38, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x2C, 0x30, 0x2A, 0x30,
	0x28, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x1C, 0x68, 0x74, 0x74,
	0x70, 0x3A, 0x2F, 0x2F, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x2F, 0x61, 0x63,
	0x2F, 0x65, 0x6E, 0x64, 0x2E, 0x68, 0x74, 0x6D, 0x6C, 0x30, 0x75, 0x06, 0x03, 0x55, 0x1D, 0x11,
	0x04, 0x6E, 0x30, 0x6C, 0xA0, 0x38, 0x06, 0x05, 0x60, 0x4C, 0x01, 0x03, 0x01, 0xA0, 0x2F, 0x04,
	0x2D, 0x31, 0x31, 0x31, 0x31, 0x31, 0x39, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
	0x31, 0x31, 0x31, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0xA0, 0x17,
	0x06, 0x05, 0x60, 0x4C, 0x01, 0x03, 0x05, 0xA0, 0x0E, 0x04, 0x0C, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0xA0, 0x17, 0x06, 0x05, 0x60, 0x4C, 0x01, 0x03, 0x06,
	0xA0, 0x0E, 0x04, 0x0C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x34, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x2D, 0x30, 0x2B, 0x30, 0x29, 0x06, 0x03, 0x2B,
	0x05, 0x08, 0x30, 0x22, 0x30, 0x20, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
	0x16, 0x14, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6D, 0x79, 0x2E, 0x68, 0x6F, 0x73, 0x74,
	0x2E, 0x6E, 0x61, 0x6D, 0x65, 0x2F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
	0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x5E, 0xB4, 0x46, 0x72, 0x7E, 0xB6,
	0xE3, 0x6C, 0x0E, 0xD7, 0x78, 0x2E, 0xCB, 0x79, 0x20, 0x9F, 0x14, 0xA4, 0x73, 0x59, 0x6C, 0x5B,
	0x97, 0x1C, 0xC3, 0x7F, 0x31, 0x6E, 0x4B, 0x35, 0xD7, 0x91, 0xDB, 0x7F, 0x6E, 0x67, 0xD4, 0x13,
	0xD7, 0x5B, 0x7E, 0x5D, 0x3F, 0x4F, 0x1E, 0xBC, 0x09, 0xB6, 0x96, 0xA0, 0x63, 0x19, 0xFE, 0xE3,
	0x92, 0x12, 0x92, 0xC0, 0x4E, 0x2C, 0xC4, 0xBE, 0x51, 0x28, 0xAE, 0xB2, 0xFF, 0x2F, 0x3F, 0x0F,
	0x76, 0x33, 0xAF, 0x54, 0x73, 0x74, 0x3A, 0x8A, 0x60, 0xB7, 0x3D, 0x3E, 0x53, 0x9D, 0xA2, 0x62,
	0x12, 0xBE, 0x1B, 0x02, 0xE9, 0xE5, 0x19, 0xDA, 0x1D, 0xCB, 0x0A, 0x3B, 0x1C, 0x30, 0x2B, 0x17,
	0x38, 0x2B, 0x37, 0xA8, 0xF5, 0x58, 0x72, 0x39, 0xAB, 0x6A, 0x7E, 0xFA, 0x2D, 0x8E, 0x70, 0xCA,
	0x06, 0x66, 0x46, 0x64, 0xE8, 0x8E, 0x17, 0x33, 0x4C, 0xF9, 0x47, 0x12, 0xB8, 0xE7, 0x2B, 0xD5,
	0xCC, 0x7F, 0x49, 0x3F, 0x24, 0xCF, 0x72, 0x13, 0xCD, 0x6A, 0x96, 0x97, 0x8D, 0x89, 0x9A, 0x7F,
	0x8A, 0xE2, 0x26, 0x51, 0xF1, 0xA5, 0xC0, 0xC4, 0xA5, 0xAD, 0xCE, 0xAE, 0x30, 0xE4, 0x11, 0x70,
	0xD7, 0xA9, 0x92, 0xC5, 0x8B, 0x4D, 0x66, 0xB3, 0xF5, 0x25, 0x9D, 0x08, 0x4B, 0x90, 0x12, 0x83,
	0xA9, 0x9F, 0x95, 0x74, 0x6D, 0xE2, 0x82, 0xE1, 0x25, 0xAD, 0x7C, 0x54, 0xD5, 0xE4, 0x34, 0xC6,
	0x8C, 0xFF, 0x3B, 0x47, 0xE9, 0xB8, 0x3E, 0xDD, 0xB7, 0xCB, 0xF3, 0x43, 0x54, 0x0D, 0xD8, 0xFE,
	0xAD, 0x7A, 0x87, 0xCE, 0xCC, 0xDF, 0x36, 0x25, 0x2D, 0xEA, 0xC7, 0x52, 0x3F, 0x7A, 0x61, 0xD6,
	0x7E, 0xEC, 0x50, 0xDC, 0xD9, 0x6A, 0x93, 0x0A, 0x08, 0x1D, 0xB8, 0x35, 0x5A, 0x1A, 0x4A, 0x39,
	0x0F, 0x71, 0xCF, 0x22, 0xAC, 0xEB, 0x52, 0xC2, 0x13, 0xFB
};
#define SIGN_DATA           "Transaction to sign"
static unsigned char n_value[] =
{
	0xCE, 0x3E, 0x56, 0x18, 0x61, 0x37, 0x60, 0x17, 0x07, 0x58, 0x4D, 0xEC, 0x88, 0xAE, 0x46,
	0xC8, 0x3B, 0xE7, 0x07, 0x40, 0xA6, 0x42, 0x50, 0x0C, 0xD8, 0x48, 0x73, 0x4C, 0xC0, 0x09, 0xF8,
	0xD8, 0x2A, 0xBC, 0x2E, 0xD5, 0x33, 0x74, 0xB2, 0xA1, 0x65, 0xC2, 0x04, 0x61, 0x0A, 0xFF, 0x7C,
	0xD5, 0x97, 0xB1, 0x89, 0x09, 0x36, 0xCD, 0x88, 0x7D, 0xA8, 0x1A, 0x32, 0xCA, 0x8C, 0xC9, 0xFB,
	0x81, 0xB2, 0x07, 0xCE, 0xDD, 0x1D, 0x20, 0x24, 0x0B, 0xDF, 0xFE, 0xA9, 0x31, 0xA2, 0x6C, 0x6E,
	0x5D, 0x2F, 0x1D, 0xB5, 0x2D, 0xFE, 0x2F, 0xBE, 0x89, 0x6C, 0xBC, 0x7A, 0xCA, 0x1B, 0x93, 0x15,
	0xB5, 0x98, 0x88, 0x9C, 0x85, 0x61, 0x97, 0xFC, 0x9D, 0xA1, 0x47, 0x38, 0x40, 0xCA, 0xA4, 0x2B,
	0xB7, 0xEF, 0x37, 0x24, 0xE4, 0x62, 0x58, 0xBC, 0x39, 0x4D, 0x54, 0xA8, 0xE4, 0xE3, 0x37, 0xDA,
	0xBB, 0x24, 0x57, 0x3A, 0x47, 0xEC, 0x40, 0x40, 0xCB, 0x1F, 0x81, 0x71, 0xA7, 0x19, 0x3A, 0xB6,
	0x5F, 0x78, 0x3A, 0xC4, 0xC8, 0xFA, 0x91, 0x47, 0x1B, 0xA6, 0xD1, 0x19, 0xE0, 0xB4, 0x0A, 0xFE,
	0x13, 0x50, 0x70, 0x37, 0xA1, 0x5E, 0x3E, 0x33, 0x5D, 0x72, 0x9C, 0xFD, 0xB2, 0xAE, 0x05, 0xAD,
	0x16, 0x59, 0xE9, 0x02, 0x7D, 0xFD, 0xDD, 0x1A, 0x59, 0xEE, 0x02, 0x57, 0x79, 0xC4, 0xE0, 0xB0,
	0x5E, 0xA0, 0xF1, 0x09, 0xA4, 0x12, 0xEB, 0xDD, 0x0B, 0x39, 0x93, 0xF1, 0x3F, 0xC8, 0xCB, 0x17,
	0xB0, 0x50, 0x31, 0xB3, 0x58, 0x40, 0x7E, 0x5B, 0xF2, 0x69, 0x84, 0x15, 0x55, 0x97, 0x38, 0x09,
	0x22, 0x17, 0x59, 0x4E, 0x80, 0xC9, 0x4D, 0x03, 0x34, 0x57, 0x57, 0x1F, 0x57, 0xC9, 0x0C, 0xDF,
	0x87, 0x9D, 0x81, 0xB2, 0x98, 0xE0, 0xD4, 0x63, 0xC3, 0x60, 0x56, 0x54, 0x97, 0x3F, 0x50, 0xDE,
	0x97
};
const static NH_BLOB n = { n_value, sizeof(n_value) };
static unsigned char e_value[] = { 0x01, 0x00, 0x01 };
const static NH_BLOB e = { e_value, sizeof(e_value) };
static unsigned char d_value[] =
{
	0x48, 0x48, 0x6E, 0xB2, 0x42, 0xB8, 0x3E, 0xB4, 0x33, 0x7D, 0xCE, 0x69, 0xBD, 0x09, 0x9F, 0x83,
	0x24, 0x03, 0x77, 0x76, 0x40, 0x0E, 0xF3, 0xB1, 0x5C, 0xC8, 0x1F, 0xA8, 0xE1, 0x91, 0x5D, 0x26,
	0x9D, 0xEB, 0xB0, 0x5A, 0x46, 0x9B, 0x7A, 0xD3, 0xB8, 0x2F, 0x44, 0x8B, 0xA2, 0x68, 0x22, 0x9F,
	0x55, 0x78, 0x02, 0x78, 0x39, 0x3D, 0xD5, 0xBD, 0x7C, 0x82, 0x1A, 0x15, 0x05, 0x3C, 0xF1, 0x29,
	0xE6, 0x74, 0x78, 0x1A, 0xE4, 0xCF, 0x53, 0xF2, 0xD9, 0x81, 0x8E, 0x58, 0xF7, 0xFD, 0x1A, 0xBD,
	0x0B, 0xFB, 0x54, 0x79, 0x97, 0x21, 0xB2, 0x9C, 0xC5, 0x80, 0x55, 0x64, 0xAA, 0x3F, 0x65, 0x97,
	0x6C, 0xAB, 0x4C, 0x78, 0x2E, 0xD9, 0x2E, 0xCF, 0x2C, 0x2C, 0x22, 0xDA, 0x0A, 0x6B, 0x79, 0x6B,
	0x10, 0xAA, 0xFA, 0x02, 0x15, 0x39, 0xD6, 0x56, 0x1A, 0xF5, 0x35, 0xF0, 0x6A, 0x76, 0x33, 0xF1,
	0x4B, 0xB2, 0x6C, 0x68, 0x9A, 0x78, 0x2D, 0x71, 0x1C, 0x31, 0xAC, 0xB9, 0xE6, 0x9B, 0x3C, 0x49,
	0x7F, 0x6A, 0x3D, 0xE7, 0x46, 0xE7, 0xAD, 0x1A, 0x90, 0xB1, 0xB4, 0xD7, 0x3E, 0x89, 0xB2, 0xA5,
	0x41, 0x34, 0x32, 0x55, 0xEE, 0x23, 0x79, 0xAB, 0x51, 0xAC, 0x0C, 0x64, 0x7C, 0xAA, 0x8B, 0x9D,
	0x5F, 0x1F, 0xD2, 0xB0, 0x51, 0x4D, 0xD6, 0x85, 0x7F, 0x71, 0xE7, 0x73, 0x1B, 0xAC, 0x7D, 0x6D,
	0x1C, 0xA2, 0x30, 0x30, 0xE7, 0x55, 0xC1, 0x75, 0x2F, 0xEC, 0x79, 0x37, 0x0D, 0x74, 0x48, 0x4B,
	0xB4, 0xCD, 0x8F, 0xBA, 0xE7, 0xA7, 0xFA, 0x97, 0x6E, 0xD1, 0xB2, 0x4C, 0x53, 0x82, 0x01, 0xCE,
	0xAC, 0xB4, 0x23, 0x80, 0x43, 0x66, 0x89, 0x37, 0x9E, 0x7D, 0x65, 0xC6, 0x05, 0x02, 0xAB, 0xB9,
	0x44, 0xB0, 0x54, 0x5C, 0x68, 0x02, 0x19, 0x90, 0xA0, 0xBC, 0x79, 0xEE, 0xD5, 0x08, 0x26, 0x09
};
const static NH_BLOB d = { d_value, sizeof(d_value) };
static unsigned char p_value[] =
{
	0xF0, 0x87, 0xEF, 0xB3, 0xC0, 0x8B, 0x56, 0x2A, 0x74, 0x11, 0xE3, 0xBE, 0x37, 0x96, 0x84,
	0x6E, 0x1F, 0x10, 0x6A, 0xA5, 0xF2, 0xFA, 0xE1, 0xCE, 0x16, 0x78, 0xA3, 0x2D, 0x0A, 0xE9, 0x27,
	0x99, 0xBB, 0x5A, 0x9F, 0x78, 0xAF, 0x78, 0x54, 0x50, 0x58, 0x7A, 0x5C, 0xFC, 0xA7, 0x1C, 0xDC,
	0x51, 0xAA, 0x10, 0xDC, 0xF4, 0x5F, 0x44, 0x24, 0x54, 0x22, 0x13, 0x7C, 0xF6, 0xE1, 0x95, 0x14,
	0x0D, 0xB5, 0xFF, 0x60, 0xD2, 0x24, 0xF5, 0x48, 0x87, 0x84, 0x5A, 0xEF, 0xB7, 0xEA, 0xB6, 0x22,
	0x15, 0xD4, 0x0A, 0xD0, 0x32, 0x4B, 0xAA, 0xB0, 0x30, 0xBD, 0x3F, 0xDE, 0x2E, 0xF2, 0xEA, 0x07,
	0x66, 0x57, 0x76, 0x93, 0xF3, 0xE5, 0xD5, 0xA1, 0x8F, 0x76, 0x74, 0x36, 0x4C, 0x34, 0x13, 0x13,
	0xFD, 0x28, 0x1B, 0x45, 0x01, 0x62, 0x71, 0x1F, 0x14, 0xDD, 0x41, 0xD9, 0x0C, 0xF7, 0x00, 0x60,
	0x9B
};
const static NH_BLOB p = { p_value, sizeof(p_value) };
static unsigned char q_value[] =
{
	0xDB, 0x81, 0xE5, 0x66, 0x68, 0xA9, 0xE5, 0x07, 0x86, 0x25, 0x3C, 0xC0, 0xD2, 0x28, 0xA8,
	0xF7, 0xD3, 0xBE, 0xFE, 0xD9, 0x89, 0xE3, 0xB9, 0x09, 0x3E, 0x94, 0x57, 0x9E, 0x1F, 0x99, 0x0F,
	0x07, 0x0A, 0xCC, 0x32, 0x0D, 0xD1, 0x1E, 0x64, 0x01, 0xF3, 0xEC, 0xAE, 0xDC, 0x1C, 0x40, 0xAC,
	0x08, 0xA7, 0xA0, 0xC1, 0x7B, 0xB5, 0xC7, 0x40, 0x03, 0x7A, 0x8E, 0x39, 0x3F, 0x5E, 0x08, 0x9A,
	0x5E, 0xBC, 0xC9, 0x8C, 0x85, 0x4C, 0x75, 0x4B, 0x8E, 0x94, 0xE4, 0xBB, 0xCF, 0x5E, 0x8A, 0x69,
	0xBA, 0x64, 0xB0, 0x0F, 0x44, 0x97, 0x45, 0xEE, 0x6F, 0x6A, 0x34, 0xB5, 0xF6, 0xB5, 0x16, 0x07,
	0xE0, 0xCA, 0x96, 0x5E, 0x70, 0x97, 0x60, 0xE7, 0xC1, 0x6F, 0xB7, 0x18, 0x38, 0x24, 0xD5, 0x68,
	0x7B, 0x0F, 0xE7, 0x25, 0x7B, 0xCD, 0xE4, 0xD1, 0x12, 0xA9, 0x68, 0x77, 0x9F, 0xEA, 0x8C, 0x43,
	0xB5
};
const static NH_BLOB q = { q_value, sizeof(q_value) };
static unsigned char dmp_value[] =
{
	0x01, 0xC0, 0x2B, 0x89, 0x76, 0x64, 0x4D, 0x3B, 0x3F, 0xDF, 0x05, 0x76, 0x53, 0xF7, 0x3F, 0x7D,
	0x81, 0xB2, 0x5F, 0xE4, 0x57, 0x51, 0x66, 0x25, 0x56, 0xDA, 0x87, 0xED, 0x82, 0xFF, 0xD1, 0x6E,
	0xF8, 0x03, 0x1F, 0xD8, 0x04, 0x06, 0xEF, 0x2E, 0x2A, 0x86, 0xB1, 0x78, 0x91, 0x4A, 0xCF, 0x7B,
	0xB4, 0xAE, 0x2C, 0xBD, 0x86, 0x97, 0xFB, 0x5F, 0xB5, 0x63, 0xC8, 0xEC, 0x0F, 0x16, 0x43, 0xB0,
	0x19, 0xDC, 0x02, 0xFB, 0x64, 0x93, 0x78, 0x74, 0xAC, 0x0C, 0xF1, 0x63, 0xB8, 0x4C, 0x9D, 0x10,
	0xE5, 0x9B, 0x32, 0x8A, 0xBB, 0x2C, 0x41, 0xDE, 0x08, 0xF2, 0x97, 0x0E, 0x66, 0x6C, 0x37, 0xA3,
	0x92, 0x0D, 0x65, 0xE4, 0x47, 0x8E, 0xF7, 0x7F, 0x10, 0xD0, 0xA5, 0xB8, 0x86, 0x44, 0x81, 0x47,
	0xBD, 0x6B, 0xFD, 0x63, 0x96, 0x30, 0xD6, 0x96, 0x13, 0x4A, 0x30, 0x67, 0x3C, 0xC0, 0xFE, 0xF3
};
const static NH_BLOB dmp = { dmp_value, sizeof(dmp_value) };
static unsigned char dmq_value[] =
{
	0x03, 0x85, 0x2A, 0xC3, 0xA0, 0xAC, 0x10, 0xD3, 0x35, 0x10, 0x85, 0xCF, 0xE5, 0xCE, 0xE7, 0x1E,
	0xCA, 0x53, 0x86, 0xCC, 0xC0, 0x4C, 0x59, 0x9C, 0x4F, 0x57, 0x9B, 0xAC, 0x1A, 0x7F, 0x9E, 0xE1,
	0x13, 0x08, 0x41, 0x49, 0x3D, 0x70, 0x4A, 0x54, 0x49, 0xB0, 0x23, 0x01, 0xBE, 0xA6, 0x3E, 0xDC,
	0x08, 0xAC, 0x28, 0x4E, 0x2E, 0x95, 0x1A, 0x6E, 0xB3, 0xD9, 0x72, 0x0B, 0x95, 0x1B, 0x78, 0x36,
	0x4A, 0xBA, 0xC4, 0xB9, 0x22, 0x87, 0xC3, 0x05, 0x6F, 0x57, 0xD7, 0xB7, 0x34, 0xA1, 0xED, 0x9E,
	0x22, 0x9D, 0x3C, 0x31, 0x72, 0x67, 0x99, 0xB2, 0x49, 0xB6, 0xBC, 0xB0, 0x4F, 0x29, 0x22, 0x49,
	0x35, 0x96, 0x81, 0xBF, 0x36, 0x7E, 0x44, 0x59, 0x32, 0xCC, 0x71, 0xE3, 0xFC, 0x9B, 0x3B, 0x88,
	0xB5, 0xB1, 0x94, 0x45, 0x4F, 0x00, 0xFB, 0x65, 0x5C, 0x38, 0x23, 0xAA, 0xF9, 0xDC, 0xF3, 0xFD
};
const static NH_BLOB dmq = { dmq_value, sizeof(dmq_value) };
static unsigned char qmp_value[] =
{
	0x5C, 0x30, 0xC8, 0xD3, 0x51, 0x9B, 0x7D, 0x0D, 0x96, 0x48, 0x15, 0x10, 0xBB, 0xEC, 0x3C, 0x82,
	0x8A, 0x8A, 0x3F, 0x7A, 0x2E, 0xE3, 0xDC, 0x10, 0x2E, 0xE2, 0xB3, 0x47, 0xFE, 0x90, 0xCB, 0xC4,
	0xBF, 0xF9, 0xCF, 0x2C, 0x0B, 0x93, 0x56, 0x91, 0x60, 0x62, 0xAD, 0xB3, 0x75, 0x0B, 0xE6, 0xB8,
	0x0A, 0xC8, 0xB6, 0xFF, 0x3F, 0xD7, 0x0A, 0x52, 0x85, 0x36, 0x71, 0x91, 0x60, 0xA3, 0x11, 0xCF,
	0x2D, 0xE0, 0x5C, 0x7A, 0x4D, 0xCE, 0x1C, 0x9F, 0x73, 0x51, 0x1D, 0x82, 0x87, 0x22, 0x0A, 0x20,
	0xC6, 0xF5, 0x35, 0x65, 0xF6, 0xC0, 0x4F, 0x55, 0xB6, 0x35, 0x96, 0xBF, 0x2C, 0x02, 0x9B, 0x12,
	0x73, 0x2C, 0x56, 0x32, 0x34, 0xA8, 0x62, 0x24, 0x7F, 0xA9, 0xA0, 0xFF, 0x33, 0x0B, 0x05, 0x17,
	0x82, 0x09, 0x4D, 0xC6, 0xB0, 0xA1, 0xA0, 0x2D, 0x5B, 0x66, 0x08, 0xFF, 0x96, 0x63, 0x2D, 0x79
};
const static NH_BLOB qmp = { qmp_value, sizeof(qmp_value) };
NH_RV cadest_sign(_IN_ NH_BLOB *data, _IN_ CK_MECHANISM_TYPE mechanism, _UNUSED_ _IN_ void *params, _OUT_ unsigned char *signature, _INOUT_ size_t *sigSize)
{
	NH_RV rv;
	NH_RSA_PRIVKEY_HANDLER hHandler;

	if (NH_FAIL(rv = NH_new_RSA_privkey_handler(&hHandler))) return rv;
	if (NH_SUCCESS(rv = hHandler->create(hHandler, &n, &e, &d, &p, &q, &dmp, &dmq, &qmp))) rv = hHandler->sign(hHandler, mechanism, data->data, data->length, signature, sigSize);
	NH_release_RSA_privkey_handler(hHandler);
	return rv;
}
int test_cadest()
{
    NH_RV rv;
    NH_BLOB blob = { NULL, 0 };
    NH_CMS_SD_ENCODER hCMS = NULL;
    NH_CERTIFICATE_HANDLER hCert = NULL;
    blob.data = (unsigned char*)SIGN_DATA;
    blob.length = strlen(SIGN_DATA);
    
	printf("Testing CMS BES... ");
    rv = NH_cms_encode_signed_data(&blob, &hCMS);
    if (NH_SUCCESS(rv)) rv = hCMS->data_ctype(hCMS, CK_TRUE);
    if (NH_SUCCESS(rv)) rv = NH_parse_certificate(sign_cert, sizeof(sign_cert), &hCert);
    if (NH_SUCCESS(rv)) rv = hCMS->add_cert(hCMS, hCert);
    if (NH_SUCCESS(rv)) rv = hCMS->sign_cades_bes(hCMS, hCert, CKM_SHA256_RSA_PKCS, cadest_sign, NULL);
    if (hCMS) NH_cms_release_sd_encoder(hCMS);
    if (hCert) NH_release_certificate(hCert);
	if (NH_SUCCESS(rv)) printf("Done!\n");
	else printf("Failed\n");
    return (int)rv;
}
