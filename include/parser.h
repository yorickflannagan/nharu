/** **********************************************************
 ****h* Nharu library/DERParser
 *  **********************************************************
 * NAME
 *	DERParser
 *
 * AUTHOR
 *	Copyleft (C) 2015 by The Crypthing Initiative
 *
 * PURPOSE
 *	ASN.1 documents parsing and encoding
 *
 * NOTES
 *
 * SEE ALSO
 *
 ******
 *
 *  ***********************************************************
 */

#ifndef __PARSER_H__
#define __PARSER_H__

#include "sysservc.h"
#include <limits.h>

#if defined(_ALIGN_)
#pragma pack(push, _parser_align, 1)
#endif

/*
 *
 *	=================
 *	PARSING KNOWLEDGE
 *	=================
 *
 *	BYTE 4 | BIT 8    | BIT 7    | BIT 6    | BIT 5    | BIT 4      | BIT 3    | BIT 2    | BIT 1    |
 *	       | RESERVED                                                                                |
 *	BYTE 3 | BIT 8    | BIT 23   | BIT 22   | BIT 21   | BIT 20     | BIT 19   | BIT 18   | BIT 17   |
 *	         RESERVED | ECOV     | TWIN     | CHOICE   | CHOICE_END | HAS_NEXT | DEFAULT  | ANY      |
 *	BYTE 2 | BIT 16   | BIT 15   | BIT 14   | BIT 13   | BIT 12     | BIT 11   | BIT 10   | BIT 9    |
 *	       | CONTEXT  | OPTIONAL | EXPLICIT | TAG VALUES                                             |
 *	==================================== X-690 IDENTIFIER OCTET ======================================
 *	BYTE 1 | BIT 8    | BIT 7    | BIT 6    | BIT 5    | BIT 4      | BIT 3    | BIT 2    | BIT 1    |
 *	       | CLASS               | P/C      | TAG NUMBER                                             |
 *	==================================================================================================
 *
 *	UNIVERSAL 0 Reserved for use by the encoding rules
 *	UNIVERSAL 1 Boolean type
 *	UNIVERSAL 2 Integer type
 *	UNIVERSAL 3 Bitstring type
 *	UNIVERSAL 4 Octetstring type
 *	UNIVERSAL 5 Null type
 *	UNIVERSAL 6 Object identifier type
 *	UNIVERSAL 7 Object descriptor type
 *	UNIVERSAL 8 External type and Instance-of type
 *	UNIVERSAL 9 Real type
 *	UNIVERSAL 10 Enumerated type
 *	UNIVERSAL 11 Embedded-pdv type
 *	UNIVERSAL 12 UTF8String type
 *	UNIVERSAL 13 Relative object identifier type
 *	UNIVERSAL 14-15 Reserved for future editions of this Recommendation | International Standard
 *	UNIVERSAL 16 Sequence and Sequence-of types
 *	UNIVERSAL 17 Set and Set-of types
 *	UNIVERSAL 18-22, 25-30 Character string types
 *	UNIVERSAL 23-24 Time types
 *	UNIVERSAL 31-... Reserved for addenda to this Recommendation | International Standard
 */
#define NH_ASN1_BOOLEAN				0x01	/* X.680 universal types follows */
#define NH_ASN1_INTEGER				0x02
#define NH_ASN1_BIT_STRING			0x03
#define NH_ASN1_OCTET_STRING			0x04
#define NH_ASN1_NULL				0x05
#define NH_ASN1_OBJECT_ID			0x06
#define NH_ASN1_OBJECT_DESCRIPTOR		0x07
#define NH_ASN1_EXTERNAL_TYPE			0x28	/* NH_ASN1_CONSTRUCTED_BIT is implicitly on */
#define NH_ASN1_INSTANCE_OF			NH_ASN1_EXTERNAL_TYPE
#define NH_ASN1_REAL				0x09
#define NH_ASN1_ENUMERATED			0x0A
#define NH_ASN1_EMBEDDED_PDV			0x0B
#define NH_ASN1_UTF8_STRING			0x0C
#define NH_ASN1_RELATIVE_OID			0x0D
#define NH_ASN1_SEQUENCE			0x30	/* NH_ASN1_CONSTRUCTED_BIT is implicitly on */
#define NH_ASN1_SET				0x31	/* NH_ASN1_CONSTRUCTED_BIT is implicitly on */
#define NH_ASN1_NUMERIC_STRING		0x12
#define NH_ASN1_PRINTABLE_STRING		0x13
#define NH_ASN1_T61_STRING			0x14
#define NH_ASN1_VIDEOTEX_STRING		0x15
#define NH_ASN1_IA5_STRING			0x16
#define NH_ASN1_UTC_TIME			0x17
#define NH_ASN1_GENERALIZED_TIME		0x18
#define NH_ASN1_GRAPHIC_STRING		0x19
#define NH_ASN1_VISIBLE_STRING		0x1A
#define NH_ASN1_GENERAL_STRING		0x1B
#define NH_ASN1_UNIVERSAL_STRING		0x1C
#define NH_ASN1_BMP_STRING			0x1E
#define NH_ASN1_TELETEX_STRING 		NH_ASN1_T61_STRING
#define NH_NULL_TAG				0x00

#define NH_ASN1_CONSTRUCTED_BIT		0x00000020	/* Bit 6 of identifier octet (see X.690 8.1.2) */
#define NH_ASN1_UNIVERSAL			0x00000000	/* Universal type (bit 8 and bit 7 are off) */
#define NH_ASN1_APP				0x00000040	/* Application type (bit 8 off and bit 7 on) */
#define NH_ASN1_CONTEXT				0x00000080	/* Context-specific type (bit 8 on and bit 7 off ) */
#define NH_ASN1_PRIVATE				0x000000C0	/* Private type (bit 8 and bit 7 are on) */

#define NH_ASN1_CT_TAG_0			0x00000000	/* Tagged types [n] */
#define NH_ASN1_CT_TAG_1			0x00000100
#define NH_ASN1_CT_TAG_2			0x00000200
#define NH_ASN1_CT_TAG_3			0x00000300
#define NH_ASN1_CT_TAG_4			0x00000400
#define NH_ASN1_CT_TAG_5			0x00000500
#define NH_ASN1_CT_TAG_6			0x00000600
#define NH_ASN1_CT_TAG_7			0x00000700
#define NH_ASN1_CT_TAG_8			0x00000800

#define NH_ASN1_EXPLICIT_BIT			0x00002000 | NH_ASN1_CONSTRUCTED_BIT	/* Type must be EXPLICIT (it is implicitly constructed) */
#define NH_ASN1_OPTIONAL_BIT			0x00004000	/* Type should be OPTIONAL */
#define NH_ASN1_CONTEXT_BIT			0x00008000	/* Type is context specific (marked as [n]) */
#define NH_ASN1_ANY_TAG_BIT			0x00010000	/* Type should be ANY */
#define NH_ASN1_DEFAULT_BIT			0x00020000	/* Type has a DEFAULT value */
#define NH_ASN1_HAS_NEXT_BIT			0x00040000	/* Node has a brother */
#define NH_ASN1_CHOICE_END_BIT		0x00080000	/* Node type should be a CHOICE */
#define NH_ASN1_CHOICE_BIT			0x00100000	/* This type is the last CHOICE option */
#define NH_ASN1_TWIN_BIT			0x00200000	/* This node is the first element of a SET OF or a SEQUENCE OF */
#define NH_ASN1_EXP_CONSTRUCTED_BIT		0x00400000	/* alias ECOV: an EXPLICIT type is CONSTRUCTED? */
#define NH_ASN1_CT_TAG_MASK			0x00001F00
#define NH_ASN1_TAG_MASK			0x0000001F
#define NH_CLASS_MASK				NH_ASN1_PRIVATE


/* Path instructions */
#define NH_PARSE_NORTH				0x00	/* BIT 8 OFF BIT 7 OFF */
#define NH_PARSE_SOUTH				0x40	/* BIT 8 OFF BIT 7 ON */
#define NH_PARSE_EAST				0x80	/* BIT 8 ON BIT 7 OFF */
#define NH_PARSE_WEST				0xC0	/* BIT 8 ON BIT 7 ON */
#define NH_PARSE_WAY_MASK			0xC0	/* BIT 8 TO BIT 7 */
#define NH_PARSE_AMOUNT_MASK			0x3F	/* BIT 6 TO BIT 1 */
#define NH_PARSE_ROOT				0x00	/* Knowledge for root node parsing */

#define NH_SAIL_SKIP_NORTH			(NH_PARSE_NORTH | 1)
#define NH_SAIL_SKIP_SOUTH			(NH_PARSE_SOUTH | 1)
#define NH_SAIL_SKIP_EAST			(NH_PARSE_EAST  | 1)
#define NH_SAIL_SKIP_WEST			(NH_PARSE_WEST  | 1)


/* = = = = = = = = = = = = = = = = = = = = = = =
 * DER parsing/encoding utitilities functions
 * = = = = = = = = = = = = = = = = = = = = = = = */
typedef struct NH_ASN1_PARSER_STR		NH_ASN1_PARSER_STR;
typedef struct NH_NODE_WAY_STR		NH_NODE_WAY_STR;
typedef struct NH_ASN1_NODE_STR		NH_ASN1_NODE_STR;
typedef struct NH_ASN1_ENCODER_STR		NH_ASN1_ENCODER_STR;
typedef struct NH_BITSTRING_VALUE_STR	NH_BITSTRING_VALUE_STR;


/*
 ****f* NH_ASN1_PARSER_HANDLE/new_node
 *
 * NAME
 *	new_node
 *
 * PURPOSE
 *	Creates a new node for parsing and encoding.
 *
 * ARGUMENTS
 *	_IN_ NH_CARGO_CONTAINER hContainer: memory container handler.
 *	_OUT_ NH_ASN1_NODE_STR **node: the new node
 *
 * RESULT
 *	NH_CARGO_CONTAINER/bite_chunk return codes.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/new_node
 *
 * NAME
 *	new_node
 *
 * PURPOSE
 *	Creates a new node for parsing and encoding.
 *
 * ARGUMENTS
 *	_IN_ NH_CARGO_CONTAINER hContainer: memory container handler.
 *	_OUT_ NH_ASN1_NODE_STR **node: the new node
 *
 * RESULT
 *	NH_CARGO_CONTAINER/bite_chunk return codes.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_NEWNODE_FUNCTION)(_IN_ NH_CARGO_CONTAINER, _OUT_ NH_ASN1_NODE_STR **node);

/*
 ****f* NH_ASN1_PARSER_HANDLE/sail
 *
 * NAME
 *	sail
 *
 * PURPOSE
 *	Goto to required node using specified knowledge, if possibile
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_NODE_STR *current: current node from where to go
 *	_IN_ unsigned int path: knowledge.
 *
 * RESULT
 *	Return node, if the path is correct and the node is there... Otherwise, NULL.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/sail
 *
 * NAME
 *	sail
 *
 * PURPOSE
 *	Goto to required node using specified knowledge, if possibile
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_NODE_STR *current: current node from where to go
 *	_IN_ unsigned int path: knowledge.
 *
 * RESULT
 *	Return node, if the path is correct and the node is there... Otherwise, NULL.
 *
 ******
 *
 */
typedef NH_METHOD(NH_ASN1_NODE_STR*, NH_ASN1_SAIL_FUNCTION)(_IN_ NH_ASN1_NODE_STR*, _IN_ unsigned int);

/*
 ****f* NH_ASN1_PARSER_HANDLE/add_next
 *
 * NAME
 *	add_next
 *
 * PURPOSE
 *	Creates a node left to current, if possible.
 *
 * ARGUMENTS
 *	_IN_ NH_CARGO_CONTAINER hContainer: memory container handler.
 *	_INOUT_ NH_ASN1_NODE_STR *current): current node.
 *
 * RESULT
 *	A pointer to newly created NH_ASN1_NODE_STR or NULL.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/add_next
 *
 * NAME
 *	add_next
 *
 * PURPOSE
 *	Creates a node left to current, if possible.
 *
 * ARGUMENTS
 *	_IN_ NH_CARGO_CONTAINER hContainer: memory container handler.
 *	_INOUT_ NH_ASN1_NODE_STR *current): current node.
 *
 * RESULT
 *	A pointer to newly created NH_ASN1_NODE_STR or NULL.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/add_child
 *
 * NAME
 *	add_child
 *
 * PURPOSE
 *	Creates a child node of current, if possible.
 *
 * ARGUMENTS
 *	_IN_ NH_CARGO_CONTAINER hContainer: memory container handler.
 *	_INOUT_ NH_ASN1_NODE_STR *current): current node.
 *
 * RESULT
 *	A pointer to newly created NH_ASN1_NODE_STR or NULL.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/add_child
 *
 * NAME
 *	add_child
 *
 * PURPOSE
 *	Creates a node left to current, if possible.
 *
 * ARGUMENTS
 *	_IN_ NH_CARGO_CONTAINER hContainer: memory container handler.
 *	_INOUT_ NH_ASN1_NODE_STR *current): current node.
 *
 * RESULT
 *	A pointer to newly created NH_ASN1_NODE_STR or NULL.
 *
 ******
 *
 */
typedef NH_METHOD(NH_ASN1_NODE_STR*, NH_ASN1_ADDNODE_FUNCTION)(_IN_ NH_CARGO_CONTAINER, _INOUT_ NH_ASN1_NODE_STR*);


/* = = = = = = = = = = = = = = = = = = = = = = =
 * DER tree mapping functions
 * = = = = = = = = = = = = = = = = = = = = = = = */
/*
 ****f* NH_ASN1_PARSER_HANDLE/map
 *
 * NAME
 *	map
 *
 * PURPOSE
 *	Maps a DER document using specified knowledge.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_STR *self: handler to parser.
 *	_IN_ NH_NODE_WAY_STR *encyclopedia: knowldedge. Must not be NULL.
 *	_IN_ size_t count: length of encyclopedia array.
 *
 * RESULT
 *	NH_MUTEX_HANDLE lock() and unlock() return codes or NH_OUT_OF_MEMORY_ERROR.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1MAP_FUNCTION)(_INOUT_ NH_ASN1_PARSER_STR*, _IN_ NH_NODE_WAY_STR*, _IN_ size_t);

/*
 ****f* NH_ASN1_PARSER_HANDLE/map_set_of
 *
 * NAME
 *	map_set_of
 *
 * PURPOSE
 *	Maps a ASN.1 SET OF
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_STR *self: handler.
 *	_IN_ NH_ASN1_NODE_STR *current: node from where we should map
 *	IN_ NH_NODE_WAY_STR *encyclopedia: ASN.1 document knowledge
 *	_IN_ size_t count: encyclopedia array count.
 *
 * RESULT
 *	map_from() return codes.
 *
 * SEE ALSO
 *	map_from
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/map_from
 *
 * NAME
 *	map_from
 *
 * PURPOSE
 *	Maps a DER treee from specified node.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_STR *self: handler.
 *	_IN_ NH_ASN1_NODE_STR *current: node from where we should map
 *	IN_ NH_NODE_WAY_STR *encyclopedia: ASN.1 document knowledge
 *	_IN_ size_t count: encyclopedia array count.
 *
 * RESULT
 *	NH_WRONG_ASN1_KNOWLEDGE if encyclopedia has an invalid specification
 *	NH_OUT_OF_MEMORY_ERROR if no more memory is available.
 *	NH_CARGO_CONTAINER/bite_chunk() return codes.
 *	map_set_of() return codes.
 *	map_node() return codes.
 *
 * SEE ALSO
 *	map_set_of
 *	map_node
 *
 * NOTES
 *
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1MAP_FROM_FUNCTION)(_IN_ NH_ASN1_PARSER_STR*, _IN_ NH_ASN1_NODE_STR*, _IN_ NH_NODE_WAY_STR*, _IN_ size_t);

/*
 ****f* NH_ASN1_PARSER_HANDLE/map_node
 *
 * NAME
 *	map_node
 *
 * PURPOSE
 *	Maps specified node.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_STR *self: handler.
 *	_IN_ NH_ASN1_NODE_STR *parent: parent node, if there is one.
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to map.
 *	_IN_ unsigned int knowledge: knowledge to map the node.
 *
 * RESULT
 *	NH_SMALL_DER_ENCODING if buffer is too small to fit encoding data.
 *	read_size() return codes.
 *	map_node() return codes.
 *	new_node() return codes.
 *	NH_CARGO_CONTAINER/bite_chunk() return codes.
 *	NH_UNEXPECTED_ENCODING if an unexpected encoding octet is found.
 *
 * SEE ALSO
 *	read_size
 *	map_node
 *	new_node
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1MAP_NODE_FUNCTION)(_IN_ NH_ASN1_PARSER_STR*, _IN_ NH_ASN1_NODE_STR*, _INOUT_ NH_ASN1_NODE_STR*, _IN_ unsigned int);

/*
 ****f* NH_ASN1_PARSER_HANDLE/read_size
 *
 * NAME
 *	read_size
 *
 * PURPOSE
 *	Read DER contents size from encoding stream.
 *
 * ARGUMENTS
 *	_IN_ unsigned char *buffer: DER encoded buffer
 *	_IN_ unsigned char *last_byte: limit of DER encoded buffer.
 *	_OUT_ size_t *size: contents size.
 *	_OUT_ unsigned char **contents: pointer to contents begin.
 *	_OUT_ unsigned char **next: pointer to next DER encoding; NULL, if this is the last encoding.
 *
 * RESULT
 *	NH_SMALL_DER_ENCODING if the buffer is too small to be a valid DER encoding.
 *	NH_UNSUPPORTED_DER_LENGTH if the size is too big to be managed.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_READSIZE_FUNCTION)(_IN_ unsigned char*, _IN_ unsigned char*, _OUT_ size_t*, _OUT_ unsigned char**, _OUT_ unsigned char**);



/* = = = = = = = = = = = = = = = = = = = = = = =
 * DER parsing functions
 * = = = = = = = = = = = = = = = = = = = = = = = */
/*
 ****if* DERParser/register_optional
 *
 * NAME
 *	register_optional
 *
 * PURPOSE
 *	If node is NULL (i.e., optional), sets its identifier octet acording to its knowledge
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node to register
 *
 *******/
 typedef NH_METHOD(void, NH_ASN1_OPTREG_FUNCTION)(_INOUT_ NH_ASN1_NODE_STR*);


/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_boolean
 *
 * NAME
 *	parse_boolean
 *
 * PURPOSE
 *	Parses ASN.1 BOOLEAN type.
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not a BOOLEAN.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_integer
 *
 * NAME
 *	parse_integer
 *
 * PURPOSE
 *	Parses ASN.1 INTEGER type.
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not a INTEGER.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_real
 *
 * NAME
 *	parse_real
 *
 * PURPOSE
 *	Parses ASN.1 REAL type.
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not a REAL.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_octetstring
 *
 * NAME
 *	parse_octetstring
 *
 * PURPOSE
 *	Parses ASN.1 OCTET STRING type.
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not an OCTET STRING.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_string
 *
 * NAME
 *	parse_string
 *
 * PURPOSE
 *	Parses ASN.1 string of any type.
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not an ASN.1 string type.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_object_descriptor
 *
 * NAME
 *	parse_object_descriptor
 *
 * PURPOSE
 *	Parses ASN.1 ObjectDescriptor.
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not an ASN.1 ObjectDescriptor type.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_enumerated
 *
 * NAME
 *	parse_enumerated
 *
 * PURPOSE
 *	Parses ASN.1 ENUMERATED type.
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not an ASN.1 ENUMERATED type.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_embedded_pdv
 *
 * NAME
 *	parse_embedded_pdv
 *
 * PURPOSE
 *	Parses ASN.1 EMBEDDED PDV type.
 *
 * ARGUMENTS
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not an ASN.1 EMBEDDED PDV type.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_NODE_FUNCTION)(_INOUT_ NH_ASN1_NODE_STR*);


/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_little_integer
 *
 * NAME
 *	parse_little_integer
 *
 * PURPOSE
 *	Parses ASN.1 INTEGER type of four octets length
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not an INTEGER of four octets or less.
 *	NH_CARGO_CONTAINER/bite_chunk() return codes.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_bitstring
 *
 * NAME
 *	parse_bitstring
 *
 * PURPOSE
 *	Parses ASN.1 BIT STRING type.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not a BIT STRING.
 *	NH_CARGO_CONTAINER/bite_chunk() return codes.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_oid
 *
 * NAME
 *	parse_oid
 *
 * PURPOSE
 *	Parses ASN.1 OBJECT IDENTIFIER type.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not an OBJECT IDENTIFIER.
 *	NH_OUT_OF_MEMORY_ERROR if there is no memory available
 *	NH_CARGO_CONTAINER/bite_chunk() return codes.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_time
 *
 * NAME
 *	parse_time
 *
 * PURPOSE
 *	Parses ASN.1 time type.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not an ASN.1 UTCTime or GeneralizedTime type.
 *	NH_CARGO_CONTAINER/bite_chunk() return codes.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_PARSE_FUNCTION)(_IN_ NH_ASN1_PARSER_STR*, _INOUT_ NH_ASN1_NODE_STR*);

/*
 ****f* NH_ASN1_PARSER_HANDLE/parse_objectid
 *
 * NAME
 *	parse_objectid
 *
 * PURPOSE
 *	Parses ASN.1 OBJECT IDENTIFIER type. It supports relative OIDs.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: node to parse.
 *	_IN_ int relative: a non-zero value means it is a relative OID.
 *
 * RESULT
 *	NH_INVALID_DER_TYPE if identifier octet is not an OBJECT IDENTIFIER.
 *	NH_OUT_OF_MEMORY_ERROR if there is no memory available
 *	NH_CARGO_CONTAINER/bite_chunk return codes.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_PARSEOID_FUNCTION)(_IN_ NH_ASN1_PARSER_STR*, _INOUT_ NH_ASN1_NODE_STR*, _IN_ int);


/* = = = = = = = = = = = = = = = = = = = = = = =
 * DER tree charting functions
 * = = = = = = = = = = = = = = = = = = = = = = = */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/chart
 *
 * NAME
 *	chart
 *
 * PURPOSE
 *	Prepares an ASN.1 document for encoding
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_IN_ NH_NODE_WAY_STR *encyclopedia: document knowledge.
 *	IN_ size_t count: number of elements of encyclopedia array.
 *	_OUT_ NH_ASN1_NODE_STR **root: root element.
 *
 * RESULT
 *	NH_ASN1_ENCODER_HANDLE/new_node return codes.
 *	NH_ASN1_ENCODER_HANDLE/chart_from return codes.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_CHART_FUNCTION)(_INOUT_ NH_ASN1_ENCODER_STR*, _IN_ NH_NODE_WAY_STR*, _IN_ size_t, _OUT_ NH_ASN1_NODE_STR**);

/*
 ****f* NH_ASN1_ENCODER_HANDLE/chart_from
 *
 * NAME
 *	chart_from
 *
 * PURPOSE
 *	Prepares an ASN.1 node and its childs for encoding
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *current: node from where chart from.
 *	_IN_ NH_NODE_WAY_STR *encyclopedia: node tree knowledge.
 *	IN_ size_t count: number of elements of encyclopedia array.
 *
 * RESULT
 *	NH_ASN1_ENCODER_HANDLE/pave return codes.
 *	NH_CANNOT_SAIL if the knowledge is not suficient to go to a node.
 *	NH_CARGO_CONTAINER/bite_chunk return codes.
 *	NH_OUT_OF_MEMORY_ERROR.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_CHARTFROM_FUNCTION)(_IN_ NH_ASN1_ENCODER_STR*, _INOUT_ NH_ASN1_NODE_STR*, _IN_ NH_NODE_WAY_STR*, _IN_ size_t);

/*
 ****f* NH_ASN1_ENCODER_HANDLE/pave
 *
 * NAME
 *	pave
 *
 * PURPOSE
 *	Prepare a node for encoding
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *current: the node where to start searching for new node.
 *	_IN_ int path: knowledge: the way to node.
 *	_OUT_ NH_ASN1_NODE_STR **ret: the new node.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_PAVE_FUNCTION)(_IN_ NH_ASN1_ENCODER_STR*, _IN_ NH_ASN1_NODE_STR*, _IN_ int, _OUT_ NH_ASN1_NODE_STR**);


/* = = = = = = = = = = = = = = = = = = = = = = =
 * DER node data encoding functions
 * = = = = = = = = = = = = = = = = = = = = = = = */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_utc
 *
 * NAME
 *	put_utc
 *
 * PURPOSE
 *	Writes an ASN.1 UTCTime data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *utc: time value
 *	_IN_ size_t size: size of utc
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_generalized_time
 *
 * NAME
 *	put_generalized_time
 *
 * PURPOSE
 *	Writes an ASN.1 GeneralizedTime data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *gtime: time value.
 *	_IN_ size_t size: size of gtime
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_integer
 *
 * NAME
 *	put_integer
 *
 * PURPOSE
 *	Writes an ASN.1 INTEGER data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: integer value (in little endian)
 *	_IN_ size_t size: size of value
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_octet_string
 *
 * NAME
 *	put_octet_string
 *
 * PURPOSE
 *	Writes an ASN.1 OCTET STRING data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_object_descriptor
 *
 * NAME
 *	put_object_descriptor
 *
 * PURPOSE
 *	Writes an ASN.1 OBJECT DESCRIPTOR data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_real
 *
 * NAME
 *	put_real
 *
 * PURPOSE
 *	Writes an ASN.1 REAL data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_enumerated
 *
 * NAME
 *	put_enumerated
 *
 * PURPOSE
 *	Writes an ASN.1 ENUMERATED data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_embedded_pdv
 *
 * NAME
 *	put_embedded_pdv
 *
 * PURPOSE
 *	Writes an ASN.1 EMBEDDED PDV data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_utf8_string
 *
 * NAME
 *	put_utf8_string
 *
 * PURPOSE
 *	Writes an ASN.1 UTF8String data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_numeric_string
 *
 * NAME
 *	put_numeric_string
 *
 * PURPOSE
 *	Writes an ASN.1 NumericString data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_printable_string
 *
 * NAME
 *	put_printable_string
 *
 * PURPOSE
 *	Writes an ASN.1 PrintableString data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_videotex_string
 *
 * NAME
 *	put_videotex_string
 *
 * PURPOSE
 *	Writes an ASN.1 VideotexString data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_ia5_string
 *
 * NAME
 *	put_ia5_string
 *
 * PURPOSE
 *	Writes an ASN.1 IA5String data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_graphic_string
 *
 * NAME
 *	put_graphic_string
 *
 * PURPOSE
 *	Writes an ASN.1 GraphicString data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_visible_string
 *
 * NAME
 *	put_visible_string
 *
 * PURPOSE
 *	Writes an ASN.1 VisibleString data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_general_string
 *
 * NAME
 *	put_general_string
 *
 * PURPOSE
 *	Writes an ASN.1 GeneralString data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_universal_string
 *
 * NAME
 *	put_universal_string
 *
 * PURPOSE
 *	Writes an ASN.1 UniversalString data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_bmp_string
 *
 * NAME
 *	put_bmp_string
 *
 * PURPOSE
 *	Writes an ASN.1 BMPString data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_teletex_string
 *
 * NAME
 *	put_teletex_string
 *
 * PURPOSE
 *	Writes an ASN.1 TeletexString data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	__IN_ void *value: the binary data.
 *	_IN_ size_t size: size of value.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_PUT_FUNCTION)(_IN_ NH_ASN1_ENCODER_STR*, _INOUT_ NH_ASN1_NODE_STR*, _IN_ void*, _IN_ size_t);

/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_boolean
 *
 * NAME
 *	put_boolean
 *
 * PURPOSE
 *	Writes an ASN.1 BOOLEAN data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	_IN_ unsigned char: boolean value. Must be either TRUE or FALSE Nharu macros.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *	NH_TYPE_INCOMPATIBLE if value is not TRUE neither FALSE.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_PUTBOOL_FUNCTION)(_IN_ NH_ASN1_ENCODER_STR*, _INOUT_ NH_ASN1_NODE_STR*, _IN_ unsigned char);

/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_bitstring
 *
 * NAME
 *	put_bitstring
 *
 * PURPOSE
 *	Writes an ASN.1 BIT STRING data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	_IN_ NH_BITSTRING_VALUE_STR *value: the value itself.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_PUTBSTRING_FUNCTION)(_IN_ NH_ASN1_ENCODER_STR*, _INOUT_ NH_ASN1_NODE_STR*, _IN_ NH_BITSTRING_VALUE_STR*);

/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_objectid
 *
 * NAME
 *	put_objectid
 *
 * PURPOSE
 *	Writes an ASN.1 OBJECT IDENTIFIER data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	_IN_ unsigned int *value: OID as an array of int
 *	_IN_ size_t count: count of value array
 *	_IN_ int relative: TRUE if value is a relative OID; otherwise FALSE.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_PUTOID_FUNCTION)(_IN_ NH_ASN1_ENCODER_STR*, _INOUT_ NH_ASN1_NODE_STR*, _IN_ unsigned int*, _IN_ size_t, _IN_ int);

/*
 ****f* NH_ASN1_ENCODER_HANDLE/put_little_integer
 *
 * NAME
 *	put_little_integer
 *
 * PURPOSE
 *	Writes a platform dependent int as an ASN.1 INTEGER data
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to put value.
 *	_IN_ int value: the value itself.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR.
 *	NH_INVALID_DER_TYPE if node was incorrectly paved.
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_PUTINT_FUNCTION)(_IN_ NH_ASN1_ENCODER_STR*, _INOUT_ NH_ASN1_NODE_STR*, _IN_ int);

/*
 ****f* NH_ASN1_ENCODER_HANDLE/encoded_size
 *
 * NAME
 *	encoded_size
 *
 * PURPOSE
 *	Calculates the encoded size of a node.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_INOUT_ NH_ASN1_NODE_STR *node: the node where to begin the calculation.
 *
 * RESULT
 *	The encoding size (in octets).
 *
 * NOTES
 *	The calculation refers to specified node and all its childs. The node size member is setted.
 *
 ******
 *
 */
typedef NH_METHOD(size_t, NH_ASN1_DERSIZE_FUNCTION)(_IN_ NH_ASN1_ENCODER_STR*, _INOUT_ NH_ASN1_NODE_STR*);

/*
 ****f* NH_ASN1_ENCODER_HANDLE/encode
 *
 * NAME
 *	encode
 *
 * PURPOSE
 *	Encodes a buffer from the root node.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_STR *self: handler.
 *	_IN_ NH_ASN1_NODE_STR *root: the node where to begin the calculation.
 *	_OUT_ unsigned char *buffer: the output buffer
 *
 * RESULT
 *
 *
 * NOTES
 *	Ensures buffer fits the entire encoding using NH_ASN1_ENCODER_HANDLE/encded_size
 *
 ******
 *
 */
typedef NH_METHOD(NH_RV, NH_ASN1_ENCODE_FUNCTION)(_IN_ NH_ASN1_ENCODER_STR*, _IN_ NH_ASN1_NODE_STR*, _OUT_ unsigned char*);


/*
 ****f* NH_ASN1_ENCODER_HANDLE/encode_int
 *
 * NAME
 *	encode_int
 *
 * PURPOSE
 *	DER encodes a platform dependent int in len bytes.
 *
 * ARGUMENTS
 *	_OUT_ unsigned char *buffer: the buffer where to encodes the value
 *	_IN_ unsigned int value: value to be encoded.
 *	_IN_ size_t len: encode size
 *
 * NOTES
 *	Be sure that buffer fits the encoding using NH_ASN1_ENCODER_HANDLE/encoded_size method.
 *
 ******
 *
 */
typedef NH_METHOD(void, NH_ASN1_CODEINT_FUNCTION)(_OUT_ unsigned char*, _IN_ unsigned int, _IN_ size_t);


/*
 ****s* DERParser/NH_NODE_WAY
 *
 * NAME
 *	NH_NODE_WAY
 *
 * PURPOSE
 *	Stores the knowledge required to map a DER node.
 *
 * SYNOPSIS
 */
struct NH_NODE_WAY_STR
{
	unsigned int			path;			/* Instructions to navigate to node. The instruction is liliputian; so it must be interpreted from left to right */
	unsigned int			knowledge;		/* Knowledge required to parse node */
	struct NH_NODE_WAY_STR*		detour;		/* Detour in parsing. The mapper uses this member when it is not NULL. In this case, knowledge is ignored */
	unsigned int			count;		/* Detour nodes count */

};
/*
 ******* */

typedef NH_NODE_WAY_STR				NH_NODE_WAY;
typedef NH_NODE_WAY*				NH_PNODE_WAY;

/*
 ****s* DERParser/NH_ASN1_NODE
 *
 * NAME
 *	NH_ASN1_NODE - Any DER encoding node
 *
 * PURPOSE
 *	Maps a DER encoding and allows navigation in its tree.
 *
 * SYNOPSIS
 */
struct NH_ASN1_NODE_STR
{
	unsigned char*			identifier;		/* Identifier octet. Only for parsing; ignored during encoding */
	unsigned int			size;			/* Encoded contents size (in octets). During encoding size calculation, this member is updated */
	unsigned char*			contents;		/* Encoded contents offset. Only for parsing; ignored during encoding */
	void*					value;		/* Decoded node value */
	unsigned int			valuelen;		/* Decoded node value length */
	unsigned int			knowledge;		/* Knowledge associated to this node */
	struct NH_ASN1_NODE_STR*	parent;		/* Parent node; if NULL, this is the root node */
	struct NH_ASN1_NODE_STR*	child;		/* Child node (if any) */
	struct NH_ASN1_NODE_STR*	next;			/* Next node (if any) */
	struct NH_ASN1_NODE_STR*	previous;		/* Previous node (if any) */

};
/*
 ******* */

typedef NH_ASN1_NODE_STR			NH_ASN1_NODE;
typedef NH_ASN1_NODE*				NH_ASN1_PNODE;


/*
 ****s* DERParser/NH_ASN1_PARSER
 *
 * NAME
 *	NH_ASN1_PARSER - DER Encoded ASN.1 parser handler.
 *
 * PURPOSE
 *	Handle ASN.1 parsing
 *
 * SYNOPSIS
 */
struct NH_ASN1_PARSER_STR
{
	unsigned char*			encoding;			/* DER encoded buffer. Only for parsing */
	size_t				length;			/* Size of DER encoded buffer */
	NH_CARGO_CONTAINER		container;			/* Memory container handler */
	NH_ASN1_PNODE			root;				/* Shortcut for the first DER node (all navigation must start here) */

	/* Utilities methods */
	NH_ASN1_NEWNODE_FUNCTION	new_node;			/* Creates a new node */
	NH_ASN1_SAIL_FUNCTION		sail;				/* Goto to specified node, if possible */
	NH_ASN1_ADDNODE_FUNCTION	add_next;			/* Add a node next of current, if possible */
	NH_ASN1_ADDNODE_FUNCTION	add_child;			/* Add a child node  to current, if possible */
	NH_ASN1_READSIZE_FUNCTION	read_size;			/* Read DER contents size from the encoding buffer. */

	/* Mapping methods */
	NH_ASN1MAP_FUNCTION		map;				/* Maps DER document */
	NH_ASN1MAP_FROM_FUNCTION	map_from;			/* Maps a document from specified node */
	NH_ASN1MAP_NODE_FUNCTION	map_node;			/* Maps specified node */
	NH_ASN1MAP_FROM_FUNCTION	map_set_of;			/* Maps a SET OF ASN.1 elements from specified node */

	/* Parsing methods */
	NH_ASN1_NODE_FUNCTION		parse_boolean;		/* Parses a BOOLEAN ASN.1 type */
	NH_ASN1_PARSE_FUNCTION		parse_little_integer;	/* Parses a INTEGER ASN.1 type of four octets or less */
	NH_ASN1_NODE_FUNCTION		parse_integer;		/* Parses a INTEGER ASN.1 type */
	NH_ASN1_NODE_FUNCTION		parse_real;			/* Parses a REAL ASN.1 type */
	NH_ASN1_PARSE_FUNCTION		parse_bitstring;		/* Parses a BIT STRING ASN.1 type */
	NH_ASN1_NODE_FUNCTION		parse_octetstring;	/* Parses an OCTET STRING ASN.1 type */
	NH_ASN1_PARSE_FUNCTION		parse_oid;			/* Parses an OBJECT IDENTIFIER ASN.1 type  */
	NH_ASN1_PARSEOID_FUNCTION	parse_objectid;		/* Parses an OBJECT IDENTIFIER ASN.1 type  */
	NH_ASN1_NODE_FUNCTION		parse_string;		/* Parses an ASN.1 type of any string type */
	NH_ASN1_NODE_FUNCTION		parse_object_descriptor;/* Parses an ObjectDescriptor ASN.1 type */
	NH_ASN1_NODE_FUNCTION		parse_enumerated;		/* Parses an ASN.1 ENUMERATED type */
	NH_ASN1_NODE_FUNCTION		parse_embedded_pdv;	/* Parses an ASN.1 EMBEDDED PDV type */
	NH_ASN1_PARSE_FUNCTION		parse_time;			/* Parses an ASN.1 time type */

};
/*
 ******* */
typedef NH_ASN1_PARSER_STR		NH_ASN1_PARSER;
typedef NH_ASN1_PARSER*			NH_ASN1_PARSER_HANDLE;


/*
 ****s* DERParser/NH_ASN1_ENCODER_HANDLE
 *
 * NAME
 *	NH_ASN1_ENCODER_HANDLE - DER Encoded ASN.1 parser handler.
 *
 * PURPOSE
 *	Handle ASN.1 parsing
 *
 * SYNOPSIS
 */
struct NH_ASN1_ENCODER_STR
{
	NH_CARGO_CONTAINER		container;			/* Memory container handler */
	NH_ASN1_PNODE			root;				/* Shortcut for the first DER node (all navigation must start here) */

	/* Utilities methods */
	NH_ASN1_NEWNODE_FUNCTION	new_node;			/* Creates a new node */
	NH_ASN1_SAIL_FUNCTION		sail;				/* Goto to specified node, if possible */
	NH_ASN1_ADDNODE_FUNCTION	add_next;			/* Adds a node next of current, if possible */
	NH_ASN1_ADDNODE_FUNCTION	add_child;			/* Adds a child node  to current, if possible */
	NH_ASN1_ADDNODE_FUNCTION	add_to_set;			/* Adds a child node to current SET */
	NH_ASN1_READSIZE_FUNCTION	read_size;			/* Reads DER contents size from the encoding buffer. */
	NH_ASN1_CODEINT_FUNCTION	encode_int;			/* DER encodes a platform dependent int in len bytes. */
	NH_ASN1_OPTREG_FUNCTION		register_optional;	/* If node is NULL (i.e., optional), sets its identifier octet acording to its knowledge */

	/* Charting methods */
	NH_ASN1_CHART_FUNCTION		chart;			/* Prepares an ASN.1 document for encoding */
	NH_ASN1_CHARTFROM_FUNCTION	chart_from;			/* Prepares an ASN.1 node and its childs for encoding */
	NH_ASN1_PAVE_FUNCTION		pave;				/* Prepare a node for encoding */

	/* Encoding data methods */
	NH_ASN1_PUT_FUNCTION		put_utc;			/* Writes an ASN.1 UTCTime data */
	NH_ASN1_PUT_FUNCTION		put_generalized_time;	/* Writes an ASN.1 GeneralizedTime data */
	NH_ASN1_PUT_FUNCTION		put_integer;		/* Writes an ASN.1 INTEGER data */
	NH_ASN1_PUT_FUNCTION		put_octet_string;		/* Writes an ASN.1 OCTET STRING data */
	NH_ASN1_PUT_FUNCTION		put_object_descriptor;	/* Writes an ASN.1 OBJECT DESCRIPTOR data */
	NH_ASN1_PUT_FUNCTION		put_real;			/* Writes an ASN.1 REAL data */
	NH_ASN1_PUT_FUNCTION		put_enumerated;		/* Writes an ASN.1 ENUMERATED data */
	NH_ASN1_PUT_FUNCTION		put_embedded_pdv;		/* Writes an ASN.1 EMBEDDED PDV data */
	NH_ASN1_PUT_FUNCTION		put_utf8_string;		/* Writes an ASN.1 UTF8String data */
	NH_ASN1_PUT_FUNCTION		put_numeric_string;	/* Writes an ASN.1 NumericString data */
	NH_ASN1_PUT_FUNCTION		put_printable_string;	/* Writes an ASN.1 PrintableString data */
	NH_ASN1_PUT_FUNCTION		put_t61_string;		/* Writes an ASN.1 T61String data */
	NH_ASN1_PUT_FUNCTION		put_videotex_string;	/* Writes an ASN.1 VideotexString data */
	NH_ASN1_PUT_FUNCTION		put_ia5_string;		/* Writes an ASN.1 IA5String data */
	NH_ASN1_PUT_FUNCTION		put_graphic_string;	/* Writes an ASN.1 GraphicString data */
	NH_ASN1_PUT_FUNCTION		put_visible_string;	/* Writes an ASN.1 VisibleString data */
	NH_ASN1_PUT_FUNCTION		put_general_string;	/* Writes an ASN.1 GeneralString data */
	NH_ASN1_PUT_FUNCTION		put_universal_string;	/* Writes an ASN.1 UniversalString data */
	NH_ASN1_PUT_FUNCTION		put_bmp_string;		/* Writes an ASN.1 BMPString data */
	NH_ASN1_PUT_FUNCTION		put_teletex_string;	/* Writes an ASN.1 TeletexString data */
	NH_ASN1_PUTBOOL_FUNCTION	put_boolean;		/* Writes an ASN.1 BOOLEAN data */
	NH_ASN1_PUTBSTRING_FUNCTION	put_bitstring;		/* Writes an ASN.1 BIT STRING data */
	NH_ASN1_PUTOID_FUNCTION		put_objectid;		/* Writes an ASN.1 OBJECT IDENTIFIER data */
	NH_ASN1_PUTINT_FUNCTION		put_little_integer;	/* Writes a platform dependent int as an ASN.1 INTEGER data */

	/* Encoding document methods */
	NH_ASN1_DERSIZE_FUNCTION	encoded_size;		/* Calculates the encoded size of a node */
	NH_ASN1_ENCODE_FUNCTION		encode;			/* Encodes a buffer from the root node. */
};
/*
 ******* */
typedef NH_ASN1_ENCODER_STR		NH_ASN1_ENCODER;
typedef NH_ASN1_ENCODER*		NH_ASN1_ENCODER_HANDLE;


/*
 ****s* DERParser/NH_BITSTRING_VALUE_STR
 *
 * NAME
 *	NH_BITSTRING_VALUE
 *
 * PURPOSE
 *	ASN.1 BIT STRING representation.
 *
 * SYNOPSIS
 */
typedef struct NH_BITSTRING_VALUE_STR
{
	unsigned int			padding;	/* BIT STRING padding */
	unsigned char*			string;	/* BIT STRING itself */
	size_t				len;		/* BIT STRING (in octets) */

} NH_BITSTRING_VALUE, *NH_PBITSTRING_VALUE;
/*
 ******* */


#if defined(__cplusplus)
extern "C" {
#endif


/*
 ****f* DERParser/NH_new_parser
 *
 * NAME
 *	NH_new_parser
 *
 * PURPOSE
 *	Create a new ASN.1 parser handler.
 *
 * ARGUMENTS
 *	_IN_ unsigned char *encoding: DER encoded ASN.1 document
 *	_IN_ size_t len: sizeof of encoding
 *	_IN_ size_t nodes: estimated number of nodes do parse (for memory allocation purposes)
 *	_IN_ size_t datasize: estimated size of node value area (for memory allocation purposes)
 *	_OUT_ NH_ASN1_PARSER_HANDLE *hHandle: the handler itself.
 *
 * RESULT
 *	NH_INVALID_ARG if encoding is NULL
 *	NH_OUT_OF_MEMORY_ERROR on out of memory
 *	NH_freight_container() return codes
 *
 * SEE ALSO
 *	NH_freight_container
 *	NH_release_parser
 *
 * NOTES
 *	The parser is zero copy. Do NOT free encoding until NH_release_parser() is called.
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_new_parser)(_IN_ unsigned char*, _IN_ size_t, _IN_ size_t, _IN_ size_t, _OUT_ NH_ASN1_PARSER_HANDLE*);

/*
 ****f* DERParser/NH_release_parser
 *
 * NAME
 *	NH_release_parser
 *
 * PURPOSE
 *	Release ASN.1 parser handler.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_PARSER_HANDLE hHandle: the handler.
 *
 * RESULT
 *	NH_release_container() return codes.
 *
 * SEE ALSO
 *	NH_release_container
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_release_parser)(_IN_ NH_ASN1_PARSER_HANDLE);


/*
 ****f* DERParser/NH_new_encoder
 *
 * NAME
 *	NH_new_encoder
 *
 * PURPOSE
 *	Create a new ASN.1 encoder handler.
 *
 * ARGUMENTS
 *	_IN_ size_t nodes: estimated number of nodes do parse (for memory allocation purposes)
 *	_IN_ size_t datasize: estimated size of node value area (for memory allocation purposes)
 *	_OUT_ NH_ASN1_ENCODER_HANDLE *hHandle: the handler itself.
 *
 * RESULT
 *	NH_OUT_OF_MEMORY_ERROR on out of memory
 *	NH_freight_container() return codes
 *
 * SEE ALSO
 *	NH_freight_container
 *	NH_release_encoder
 *
 * NOTES
 *	The parser is zero copy. Do NOT free encoding until NH_release_parser() is called.
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_new_encoder)(_IN_ size_t, _IN_ size_t, _OUT_ NH_ASN1_ENCODER_HANDLE*);

/*
 ****f* DERParser/NH_release_encoder
 *
 * NAME
 *	NH_release_encoder
 *
 * PURPOSE
 *	Release ASN.1 encoder handler.
 *
 * ARGUMENTS
 *	_IN_ NH_ASN1_ENCODER_HANDLE hHandle: the handler.
 *
 * RESULT
 *	NH_release_container() return codes.
 *
 * SEE ALSO
 *	NH_release_container
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_release_encoder)(_IN_ NH_ASN1_ENCODER_HANDLE);


/*
 ****if* DERParser/NH_asn_get_tag
 *
 * NAME
 *	NH_asn_get_tag
 *
 * PURPOSE
 *	Return DER identifier octet based on specified knowledge
 *
 * ARGUMENTS
 *	_IN_ int knowledge: node knowledge
 *
 * RESULT
 *	the identifier octet.
 *
 *******/
INLINE NH_FUNCTION(unsigned char, NH_asn_get_tag)(_IN_ int);

NH_UTILITY(NH_RV, NH_asn_clone_node)(_INOUT_ NH_CARGO_CONTAINER, _IN_ NH_ASN1_PNODE, _INOUT_ NH_ASN1_PNODE*);


#if defined(__cplusplus)
}
#endif


/** ****************************
 *  Usefull macros
 *  ****************************/
/*
 ****if* DERParser/ASN_IS_VALUE
 *
 * NAME
 *	ASN_IS_VALUE
 *
 * PURPOSE
 *	Check if a knowledge has an expected _e value _v according to mask _m.
 *
 * USAGE
 *	ASN_IS_VALUE(_m, _v, _e)
 *
 *******/
#define ASN_IS_VALUE(_m, _v, _e)		(((_m) & (_v)) == (_e))

/*
 ****if* DERParser/ASN_GO_NORTH
 *
 * NAME
 *	ASN_GO_NORTH
 *
 * PURPOSE
 *	Check if can sail to north
 *
 * USAGE
 *	ASN_GO_NORTH(_v)
 *
 *******/
#define ASN_GO_NORTH(_v)			ASN_IS_VALUE(NH_PARSE_WAY_MASK, _v, NH_PARSE_NORTH)

/*
 ****if* DERParser/ASN_GO_SOUTH
 *
 * NAME
 *	ASN_GO_SOUTH
 *
 * PURPOSE
 *	Check if can sail to south
 *
 * USAGE
 *	ASN_GO_SOUTH(_v)
 *
 *******/
#define ASN_GO_SOUTH(_v)			ASN_IS_VALUE(NH_PARSE_WAY_MASK, _v, NH_PARSE_SOUTH)

/*
 ****if* DERParser/ASN_GO_EAST
 *
 * NAME
 *	ASN_GO_EAST
 *
 * PURPOSE
 *	Check if can sail to east
 *
 * USAGE
 *	ASN_GO_EAST(_v)
 *
 *******/
#define ASN_GO_EAST(_v)				ASN_IS_VALUE(NH_PARSE_WAY_MASK, _v, NH_PARSE_EAST)

/*
 ****if* DERParser/ASN_GO_WEST
 *
 * NAME
 *	ASN_GO_WEST
 *
 * PURPOSE
 *	Check if can sail to west
 *
 * USAGE
 *	ASN_GO_WEST(_v)
 *
 *******/
#define ASN_GO_WEST(_v)				ASN_IS_VALUE(NH_PARSE_WAY_MASK, _v, NH_PARSE_WEST)

/*
 ****if* DERParser/ASN_HAS_EXPECTED_TAG
 *
 * NAME
 *	ASN_HAS_EXPECTED_TAG
 *
 * PURPOSE
 *	Check if current _o has a tag according to its knowledge _k
 *
 * USAGE
 *	ASN_HAS_EXPECTED_TAG(_k, _o)
 *
 *******/
#define ASN_HAS_EXPECTED_TAG(_k, _o)	((((_k) & NH_ASN1_TAG_MASK) == ((_o) & NH_ASN1_TAG_MASK)) && !ASN_IS_ON(NH_ASN1_CONTEXT_BIT, _k))

/*
 ****if* DERParser/ASN_IS_TAG
 *
 * NAME
 *	ASN_IS_TAG
 *
 * PURPOSE
 *	Check if node _n knowledge is of _t type
 *
 * USAGE
 *	ASN_IS_TAG(_n, _t)
 *
 *******/
#define ASN_IS_TAG(_n, _t)			(((_n->knowledge) & NH_ASN1_TAG_MASK) == (NH_ASN1_TAG_MASK & _t))


/*
 ****if* DERParser/ASN_IS_ON
 *
 * NAME
 *	ASN_IS_ON
 *
 * PURPOSE
 *	Check if bit _b is turned on value _v
 *Ŕ
 * USAGE
 *	ASN_IS_ON(_b, _v)
 *
 *******/
#define ASN_IS_ON(_b, _v)			(((_b) & (_v)) == (_b))


/*
 ****if* DERParser/ASN_IS_OPTIONAL
 *
 * NAME
 *	ASN_IS_OPTIONAL
 *
 * PURPOSE
 *	Check if node specified by knowledge _k is optional
 *
 * USAGE
 *	ASN_IS_OPTIONAL(_k)
 *
 *******/
#define ASN_IS_OPTIONAL(_k)			(ASN_IS_ON(NH_ASN1_OPTIONAL_BIT, _k) || ASN_IS_ON(NH_ASN1_DEFAULT_BIT, _k))

/*
 ****if* DERParser/ASN_HAS_EXPECTED_CONTEXT
 *
 * NAME
 *	ASN_HAS_EXPECTED_CONTEXT
 *
 * PURPOSE
 *	Check if current octet _o has a tag according to its context knowledge _k
 *
 * USAGE
 *	 ASN_HAS_EXPECTED_CONTEXT(_k, _o)
 *
 *******/
#define ASN_HAS_EXPECTED_CONTEXT(_k, _o)	(ASN_IS_ON(NH_ASN1_CONTEXT_BIT, _k) && ASN_IS_ON(NH_ASN1_CONTEXT, _o) && ((((_k) & NH_ASN1_CT_TAG_MASK) >> 0x08) == ((_o) & NH_ASN1_TAG_MASK)))

/*
 ****if* DERParser/ASN_IS_OF_ANY_TYPE
 *
 * NAME
 *	ASN_IS_OF_ANY_TYPE
 *
 * PURPOSE
 *	Check if octet _o is of type ANY according to knowledge _k
 *
 * USAGE
 *	ASN_IS_OF_ANY_TYPE(_k, _o)
 *
 *******/
#define ASN_IS_OF_ANY_TYPE(_k, _o)		(ASN_IS_ON(NH_ASN1_ANY_TAG_BIT, _k) && ((_o) != NH_NULL_TAG))

/*
 ****if* DERParser/ASN_IS_EXPECTED_NULL
 *
 * NAME
 *	ASN_IS_EXPECTED_NULL
 *
 * PURPOSE
 *	Check if octet _o is NULL according to knowledge _k
 *
 * USAGE
 *	ASN_IS_EXPECTED_NULL(_k, _o)
 *
 *******/
#define ASN_IS_EXPECTED_NULL(_k, _o)	(ASN_IS_VALUE(NH_ASN1_TAG_MASK, _o,	NH_ASN1_NULL) && ASN_IS_OPTIONAL(_k))

/*
 ****if* DERParser/ASN_FOUND
 *
 * NAME
 *	ASN_FOUND
 *
 * PURPOSE
 *	Check if octet _o is according knowledge _k
 *
 * USAGE
 *	ASN_FOUND(_k, _o)
 *
 *******/
#define ASN_FOUND(_k, _o)			(ASN_HAS_EXPECTED_TAG(_k, _o) || ASN_HAS_EXPECTED_CONTEXT(_k, _o) || ASN_IS_OF_ANY_TYPE(_k, _o) || ASN_IS_EXPECTED_NULL(_k, _o))

/*
 ****if* DERParser/ASN_IS_CONSTRUCTED
 *
 * NAME
 *	ASN_IS_CONSTRUCTED
 *
 * PURPOSE
 *	Check if an ASN.1 node is constructed checking its octet _o
 *
 * USAGE
 *	ASN_IS_CONSTRUCTED(octet)
 *
 *******/
#define ASN_IS_CONSTRUCTED(_o)		ASN_IS_ON(NH_ASN1_CONSTRUCTED_BIT, (_o))

/*
 ****if* DERParser/ASN_IS_PRESENT
 *
 * NAME
 *	ASN_IS_PRESENT
 *
 * PURPOSE
 *	Check if an ASN.1 node _n has a non-null octet
 *
 * USAGE
 *	ASN_IS_PRESENT(node)
 *
 *******/
#define ASN_IS_PRESENT(_n)			((_n) && (*_n->identifier != NH_NULL_TAG) && (*_n->identifier != NH_ASN1_NULL))


/*
 ****if* DERParser/ASN_INT_SIZE
 *
 * NAME
 *	ASN_INT_SIZE
 *
 * PURPOSE
 *	Calculates the DER encoded size of an integer value _v
 *
 * USAGE
 *	ASN_INT_SIZE(_v)
 *
 *******/
#define ASN_INT_SIZE(_v)			((_v < 0x00000080) ? 1 : (_v < 0x00000100) ? 2 : (_v < 0x00010000) ? 3 : (_v < 0x01000000) ? 4 : 5)

/*
 ****if* DERParser/ASN_ENCODED_SIZE
 *
 * NAME
 *	ASN_ENCODED_SIZE
 *
 * PURPOSE
 *	Calculates the DER encoded size of any data of length _l
 *
 * USAGE
 *	ASN_ENCODED_SIZE(_L)
 *
 *******/
#define ASN_ENCODED_SIZE(_l)			(_l + ASN_INT_SIZE(_l) + 1)


/*
 ****if* DERParser/ASN_NODE_WAY_COUNT
 *
 * NAME
 *	ASN_NODE_WAY_COUNT
 *
 * PURPOSE
 *	Returns the number of elements of NH_NODE_WAY _a array
 *
 * USAGE
 *	ASN_NODE_WAY_COUNT(_a)
 *
 *******/
#define ASN_NODE_WAY_COUNT(_a)		(sizeof(_a) / sizeof(NH_NODE_WAY))


/*
 ****if* DERParser/ASN_TAG_IS_PRESENT
 *
 * NAME
 *	ASN_TAG_IS_PRESENT
 *
 * PURPOSE
 *	Check if tag _t is present in node _n
 *
 * USAGE
 *	ASN_TAG_IS_PRESENT(_n, _t)
 *
 *******/
#define ASN_TAG_IS_PRESENT(_n, _t)		((_n) && ((*_n->identifier & NH_ASN1_TAG_MASK) == (NH_ASN1_TAG_MASK & _t)))

/*
 ****if* DERParser/ASN_NODE_COUNT
 *
 * NAME
 *	ASN_NODE_COUNT
 *
 * PURPOSE
 *	Count the _c number of next nodes of this _n node.
 *
 * USAGE
 *	ASN_NODE_COUNT(_n, _c)
 *
 *******/
#define ASN_NODE_COUNT(_n, _c)		{ _c = 0; while (_n) { _c++; _n = _n->next; }}

/*
 ****if* DERParser/ASN_TAG_IS_STRING
 *
 * NAME
 *	ASN_TAG_IS_STRING
 *
 * PURPOSE
 *	Check if this node is a kind of string
 *
 * USAGE
 *	ASN_TAG_IS_STRING(_n)
 *
 *******/
#define ASN_TAG_IS_STRING(_n)			(ASN_TAG_IS_PRESENT(_n, NH_ASN1_TELETEX_STRING) || ASN_TAG_IS_PRESENT(_n, NH_ASN1_PRINTABLE_STRING) || ASN_TAG_IS_PRESENT(_n, NH_ASN1_UNIVERSAL_STRING) || ASN_TAG_IS_PRESENT(_n, NH_ASN1_UTF8_STRING) || ASN_TAG_IS_PRESENT(_n, NH_ASN1_BMP_STRING) || ASN_TAG_IS_PRESENT(_n, NH_ASN1_IA5_STRING))

/*
 ****if* DERParser/ASN_IS_PARSED
 *
 * NAME
 *	ASN_IS_PARSED
 *
 * PURPOSE
 *	Check if this node is parsed
 *
 * USAGE
 *	ASN_IS_PARSED(_n)
 *
 *******/
#define ASN_IS_PARSED(_n)			(_n && _n->value && _n->valuelen > 0)


#if defined(_ALIGN_)
#pragma pack(pop, _parser_align)
#endif

#endif	/* __PARSER_H__ */
