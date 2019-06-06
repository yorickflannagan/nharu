#include "parser.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 * ASN.1 utilities implementation
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
NH_UTILITY(NH_RV, NH_new_node)(_IN_ NH_CARGO_CONTAINER hContainer, _OUT_ NH_ASN1_NODE_STR **node)
{
	NH_ASN1_PNODE ret;
	NH_RV rv;

	if (NH_FAIL(rv = hContainer->bite_chunk(hContainer, sizeof(NH_ASN1_NODE), (void*) &ret))) return rv;
	memset(ret, 0, sizeof(NH_ASN1_NODE));
	ret->size = UINT_MAX;
	*node = ret;
	return NH_OK;
}

NH_UTILITY(NH_ASN1_NODE_STR*, NH_sail)(_IN_ NH_ASN1_NODE_STR *current, _IN_ unsigned int path)
{
	int j, jumps, i = 3;
	unsigned int instruction;
	NH_ASN1_PNODE node;

	node = (NH_ASN1_PNODE) current;
	while (i > -1 && node)
	{
		instruction = (path >> (i-- * 8)) & 0x000000FF;
		jumps = instruction & NH_PARSE_AMOUNT_MASK;
		j = 0;
		if		(ASN_GO_SOUTH(instruction))	while (j++ < jumps && node) node = node->child;
		else if	(ASN_GO_EAST(instruction))	while (j++ < jumps && node) node = node->next;
		else if	(ASN_GO_WEST(instruction))	while (j++ < jumps && node) node = node->previous;
		else							while (j++ < jumps && node) node = node->parent;
	}
	return node;
}

NH_UTILITY(NH_ASN1_NODE_STR*, NH_add_next)(_IN_ NH_CARGO_CONTAINER hContainer, _INOUT_ NH_ASN1_NODE_STR *current)
{
	NH_ASN1_PNODE node;

	if (!current || current->next) return NULL;
	if (NH_FAIL(NH_new_node(hContainer, &node))) return NULL;
	current->next = node;
	node->parent = current->parent;
	node->previous = current;
	return node;
}

NH_UTILITY(NH_ASN1_NODE_STR*, NH_add_child)(_IN_ NH_CARGO_CONTAINER hContainer, _INOUT_ NH_ASN1_NODE_STR *current)
{
	NH_ASN1_PNODE node;

	if (!current || current->child) return NULL;
	if (NH_FAIL(NH_new_node(hContainer, &node))) return NULL;
	node->parent = current;
	current->child = node;
	return node;
}

NH_UTILITY(NH_ASN1_NODE_STR*, NH_add_to_set)(_IN_ NH_CARGO_CONTAINER hContainer, _INOUT_ NH_ASN1_NODE_STR *set)
{
	NH_ASN1_PNODE node;
	if (set->child)
	{
		node = set->child;
		while (node->next) node = node->next;
		node = NH_add_next(hContainer, node);
	}
	else	node = NH_add_child(hContainer, set);
	return node;
}

#define UNDEFINITE_SIZE		-1
#define ERROR_SIZE		-2
INLINE NH_UTILITY(int, READ_SIZE)(_IN_ unsigned char *buffer, _IN_ unsigned char *limit, _OUT_ unsigned int *skip)
{
	unsigned int len_byte, roll = 0;
	int size = 0;

	*skip = 1;
	len_byte = *buffer;
	if (!(len_byte & 0x80)) return len_byte;
	len_byte &= 0x7F;
	if (buffer + len_byte > limit) return ERROR_SIZE;
	switch (len_byte)
	{
	case 4:
		size = *(buffer + 4) << roll;
		roll += 0x08;
		(*skip)++;
	case 3:
		size |= *(buffer + 3) << roll;
		roll += 0x08;
		(*skip)++;
	case 2:
		size |= *(buffer + 2) << roll;
		roll += 0x08;
		(*skip)++;
	case 1:
		size |= *(buffer + 1) << roll;
		(*skip)++;
		break;
	case 0: return UNDEFINITE_SIZE;
	default: return ERROR_SIZE;
	}
	return size;
}

NH_UTILITY(int, read_indefinite_size)(_IN_ unsigned char *buffer, _IN_ unsigned char *limit)
{
	int size, acc = 0;
	unsigned int skip;
	unsigned char *current = (unsigned char*) buffer;

	while (current < limit && (*current || *(current + 1)))
	{
		size = READ_SIZE(current + 1, limit, &skip);
		if (size == UNDEFINITE_SIZE && current < limit)
		{
			if (!ASN_IS_CONSTRUCTED(*(current))) return ERROR_SIZE;
			size = read_indefinite_size(current + 2, limit);
			skip = 3;
		}
		if (size == ERROR_SIZE) return size;
		acc += size + skip + 1;
		current += (skip + size + 1);
	}
	if (current == limit) return ERROR_SIZE;
	return acc;
}

NH_UTILITY(NH_RV, NH_read_size)
(
	_IN_ unsigned char *buffer,
	_IN_ unsigned char *last_byte,
	_OUT_ size_t *size,
	_OUT_ unsigned char **contents,
	_OUT_ unsigned char **next
)
{
	unsigned int skip, eoc = 0, msize;

	if (!(buffer && last_byte && size && contents && next)) return NH_INVALID_ARG;
	msize = READ_SIZE(buffer, last_byte, &skip);
	if (msize == UNDEFINITE_SIZE)
	{
		msize = read_indefinite_size(buffer + 1, last_byte);
		skip = 1;
		eoc = 2;
	}
	if (msize < 0) return NH_UNEXPECTED_ENCODING;
	*size = msize;
	*contents = (unsigned char*) buffer + skip;
	if (buffer + skip + msize + eoc < last_byte) *next = (unsigned char*) buffer + skip + msize + eoc;
	return NH_OK;
}

NH_UTILITY(void, NH_encode_int)(_OUT_ unsigned char *buffer, _IN_ unsigned int value, _IN_ size_t len)
{
	size_t length = len;
	unsigned int mask = 0xFF000000 >> (4 - length) * 8;
	while (length--)
	{
		*buffer++ = ((mask & value) >> (8 * length));
		mask >>= 8;
	}
}


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 * ASN.1 mapping implementation
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
NH_UTILITY(NH_RV, NH_map)(_INOUT_ NH_ASN1_PARSER_STR *self, _IN_ NH_NODE_WAY_STR *encyclopedia, _IN_ size_t count)
{
	NH_RV rv;
	NH_ASN1_PNODE node;

	if (!encyclopedia || encyclopedia[0].path != NH_PARSE_ROOT) return NH_INVALID_ARG;
	if (NH_FAIL(rv = self->new_node(self->container, &node))) return rv;
	self->root = node;
	node->identifier = self->encoding;
	if (NH_FAIL(rv = self->map_node(self, NULL, node, encyclopedia[0].knowledge))) return rv;
	return self->map_from(self, node, encyclopedia + 1, count - 1);
}

NH_UTILITY(NH_ASN1_PNODE, sail_to_sunset)(_IN_ NH_ASN1_PNODE current, _IN_ unsigned int path, _OUT_ unsigned int *direction)
{
	int j = 0, jumps = 0, i = 3;
	unsigned int instruction;
	NH_ASN1_PNODE node;

	node = current;
	while (i > -1 && node)
	{
		instruction = (path >> (i-- * 8)) & 0x000000FF;
		jumps = instruction & NH_PARSE_AMOUNT_MASK;
		j = 0;
		if (ASN_GO_SOUTH(instruction))
		{
			*direction = NH_PARSE_SOUTH;
			while (j++ < jumps && node->child) node = node->child;
		}
		else if (ASN_GO_EAST(instruction))
		{
			*direction = NH_PARSE_EAST;
			while (j++ < jumps && node->next) node = node->next;
		}
		else if (ASN_GO_WEST(instruction))
		{
			*direction = NH_PARSE_WEST;
			while (j++ < jumps && node->previous) node = node->previous;
		}
		else
		{
			*direction = NH_PARSE_NORTH;
			while (j++ < jumps && node->parent) node = node->parent;
		}
		if (j < jumps) node = NULL;
	}
	if (j != jumps) node = NULL;
	return node;
}

NH_UTILITY(NH_RV, NH_map_from)
(
	_IN_ NH_ASN1_PARSER_STR *self,
	_IN_ NH_ASN1_NODE_STR *current,
	_IN_ NH_NODE_WAY_STR *encyclopedia,
	_IN_ size_t count
)
{
	unsigned int i = 0, direction;
	NH_ASN1_PNODE next;
	NH_RV rv = NH_OK;

	while (i < count)
	{
		next = self->sail(current, encyclopedia[i].path);
		if (!next)
		{
			if (!(next = sail_to_sunset((NH_ASN1_PNODE) current, encyclopedia[i].path, &direction))) return NH_WRONG_ASN1_KNOWLEDGE;
			switch (direction)
			{
			case NH_PARSE_SOUTH:
				if (!ASN_IS_TAG(current, NH_NULL_TAG)) return NH_WRONG_ASN1_KNOWLEDGE;
				break;
			case NH_PARSE_EAST:
				if (!ASN_IS_OPTIONAL(encyclopedia[i].knowledge)) return NH_WRONG_ASN1_KNOWLEDGE;
				if (!(next = self->add_next(self->container, next))) return NH_OUT_OF_MEMORY_ERROR;
				if
				(
					NH_FAIL(rv = self->container->bite_chunk(self->container, sizeof(unsigned char *), (void*) &next->identifier))
				)	return rv;
				*next->identifier = NH_NULL_TAG;
				next->knowledge = encyclopedia[i].knowledge;
				next->size = 0;
				break;
			default: return NH_WRONG_ASN1_KNOWLEDGE;
			}
		}
		else
		{
			if (ASN_IS_ON(NH_ASN1_TWIN_BIT, encyclopedia[i].knowledge)) rv = self->map_set_of(self, next, encyclopedia[i].detour, encyclopedia[i].count);
			else if (encyclopedia[i].detour) rv = self->map_from(self, next, encyclopedia[i].detour, encyclopedia[i].count);
			else
			{
				if (next->size == UINT_MAX)
				{
					while (next->size == UINT_MAX && NH_SUCCESS(rv)) rv = self->map_node(self, next->parent, next, encyclopedia[i++].knowledge);
					i--;
				}
				while (NH_SUCCESS(rv) && ASN_IS_ON(NH_ASN1_CHOICE_BIT, encyclopedia[i].knowledge) && !ASN_IS_ON(NH_ASN1_CHOICE_END_BIT, encyclopedia[i].knowledge)) i++;
			}
			if (NH_FAIL(rv)) return rv;
		}
		current = next;
		i++;
	}
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_map_node)
(
	_IN_ NH_ASN1_PARSER_STR *self,
	_IN_ NH_ASN1_NODE_STR *parent,
	_INOUT_ NH_ASN1_NODE_STR *node,
	_IN_ unsigned int knowledge
)
{
	unsigned char *buffer, *next = NULL, *last_byte;
	NH_RV rv;

	if (!node) return NH_INVALID_ARG;
	if (node->size < UINT_MAX) return NH_OK;
	if (parent) last_byte = parent->contents + parent->size - 1;
	else last_byte = self->encoding + self->length - 1;
	if (ASN_FOUND(knowledge, *node->identifier))					/* Knowledge fits. So we map encoding. */
	{
		buffer = node->identifier;
		if (buffer == last_byte) return NH_SMALL_DER_ENCODING;
		buffer++;
		if (NH_FAIL(rv = self->read_size(buffer, last_byte, (size_t *) &node->size, &node->contents, &next))) return rv;
		node->knowledge = knowledge;
		if (ASN_IS_CONSTRUCTED(*node->identifier))	/* A constructed encoding MUST have a child node */
		{
			node->knowledge |= NH_ASN1_CONSTRUCTED_BIT;
			if (NH_FAIL(rv = self->new_node(self->container, &node->child))) return rv;
			if (node->contents) node->child->identifier = node->contents;
			else
			{
				if (NH_FAIL(rv = self->container->bite_chunk(self->container, sizeof(unsigned char*), (void*) &node->child->identifier))) return rv;
				*node->child->identifier = NH_NULL_TAG;
			}
			node->child->parent = node;
			if
			(	/* EXPLICT primitive types should be resolved early */
				ASN_IS_ON(NH_ASN1_EXPLICIT_BIT, node->knowledge) &&
				!ASN_IS_ON(NH_ASN1_EXP_CONSTRUCTED_BIT, node->knowledge) &&
				!ASN_IS_ON(NH_ASN1_ANY_TAG_BIT, node->knowledge) &&
				NH_FAIL(rv = self->map_node(self, node, node->child, node->knowledge & 0xDF))
			)	return rv;
		}

		if (next && ASN_IS_ON(NH_ASN1_HAS_NEXT_BIT, knowledge) && !node->next)	/* Create next node if it exists */
		{
			if (NH_FAIL(rv = self->new_node(self->container, &node->next))) return rv;
			node->next->identifier = next;
			node->next->parent = (NH_ASN1_PNODE) parent;
			node->next->previous = node;
		}
	}
	else if (ASN_IS_ON(NH_ASN1_CHOICE_BIT, knowledge) && !ASN_IS_ON(NH_ASN1_CHOICE_END_BIT, knowledge));	/* This is a choice. We need to continue searching. */
	else if (ASN_IS_OPTIONAL(knowledge)) 						/* Marks node as an absent optional encoding */
	{
		if (ASN_IS_ON(NH_ASN1_HAS_NEXT_BIT, knowledge) && !node->next)
		{
			if (NH_FAIL(rv = self->new_node(self->container, &node->next))) return rv;
			node->next->identifier = node->identifier;
			node->next->parent = (NH_ASN1_PNODE) parent;
			node->next->previous = node;
		}
		if (NH_FAIL(rv = self->container->bite_chunk(self->container, sizeof(unsigned char*), (void*) &node->identifier))) return rv;
		*node->identifier = NH_NULL_TAG;
		node->knowledge = knowledge;
		node->size = 0;
	}
	else  return NH_UNEXPECTED_ENCODING;
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_map_set_of)
(
	_IN_ NH_ASN1_PARSER_STR *self,
	_IN_ NH_ASN1_NODE_STR *current,
	_IN_ NH_NODE_WAY_STR *encyclopedia,
	_IN_ size_t count
)
{
	NH_RV rv = NH_OK;
	do rv = self->map_from(self, current, encyclopedia, count);
	while (NH_SUCCESS(rv) && (current = current->next));
	return rv;
}


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 * ASN.1 parsing implementation
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
INLINE NH_UTILITY(NH_RV, parse)(_INOUT_ NH_ASN1_PNODE node, _IN_ unsigned char octet)
{
	if (!(ASN_IS_CONSTRUCTED(*node->identifier) || ASN_IS_TAG(node, octet) || ASN_TAG_IS_PRESENT(node, octet))) return NH_INVALID_DER_TYPE;
	node->value = node->contents;
	node->value = node->contents;
	node->valuelen = node->size;
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_parse_boolean)(_INOUT_ NH_ASN1_NODE_STR *node)
{
	return parse(node, NH_ASN1_BOOLEAN);
}

NH_UTILITY(NH_RV, NH_parse_little_integer)(_IN_ NH_ASN1_PARSER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node)
{
	unsigned int roll = 0;
	long int value = 0;
	NH_RV rv;

	if (ASN_IS_CONSTRUCTED(*node->identifier) || !ASN_IS_TAG(node, NH_ASN1_INTEGER)) return NH_INVALID_DER_TYPE;
	switch (node->size)
	{
	case 4:
		value = *(node->contents + 3) << roll;
		roll += 0x08;
	case 3:
		value |= *(node->contents + 2) << roll;
		roll += 0x08;
	case 2:
		value |= *(node->contents + 1) << roll;
		roll += 0x08;
	case 1:
		value |= *node->contents << roll;
		break;
	default: return NH_INVALID_DER_TYPE;
	}
	if (NH_FAIL(rv = self->container->bite_chunk(self->container, sizeof(long int), &node->value))) return rv;
	*(long int*)node->value = value;
	node->valuelen = sizeof(long int);
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_parse_integer)(_INOUT_ NH_ASN1_NODE_STR *node)
{
	return parse(node, NH_ASN1_INTEGER);
}

NH_UTILITY(NH_RV, NH_parse_real)(_INOUT_ NH_ASN1_NODE_STR *node)
{
	return parse(node, NH_ASN1_REAL);
}

NH_UTILITY(NH_RV, NH_parse_bitstring)(_IN_ NH_ASN1_PARSER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node)
{
	NH_PBITSTRING_VALUE block;
	NH_RV rv;

	if (ASN_IS_CONSTRUCTED(*node->identifier) || !ASN_IS_TAG(node, NH_ASN1_BIT_STRING)) return NH_INVALID_DER_TYPE;
	if (NH_FAIL(rv = self->container->bite_chunk(self->container, sizeof(NH_BITSTRING_VALUE), (void*) &block))) return rv;

	if (node->size > 0)
	{
		block->padding = *node->contents;
		block->string = node->contents + 1;
		block->len = node->size - 1;
	}
	else memset(block, 0, sizeof(NH_BITSTRING_VALUE));
	node->value = block;
	node->valuelen = sizeof(NH_BITSTRING_VALUE);
	return NH_OK;
}

NH_UTILITY(NH_RV, parse_constructed_octetstring)(_IN_ NH_ASN1_PARSER_STR*, _INOUT_ NH_ASN1_NODE_STR*);
INLINE NH_UTILITY(NH_RV, parse_child_constructed_octetstring)(_IN_ NH_ASN1_PARSER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node)
{
	if (ASN_IS_CONSTRUCTED((*node->identifier))) return parse_constructed_octetstring(self, node);
	return parse(node, NH_ASN1_OCTET_STRING);
}
const static NH_NODE_WAY octet_maze[] = {{ NH_PARSE_ROOT, NH_ASN1_OCTET_STRING | NH_ASN1_HAS_NEXT_BIT, NULL, 0 }};
INLINE NH_UTILITY(NH_RV, parse_constructed_octetstring)(_IN_ NH_ASN1_PARSER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node)
{
	NH_RV rv;
	NH_ASN1_PNODE current;


	if (!(current = node->child)) return NH_TYPE_INCOMPATIBLE;
	rv = self->map_set_of(self, current, octet_maze, ASN_NODE_WAY_COUNT(octet_maze));
	while (NH_SUCCESS(rv) && current)
	{
		rv = parse_child_constructed_octetstring(self, current);
		current = current->next;
	}
	return rv;
}
INLINE NH_UTILITY(void, set_octetstring_value)(_INOUT_ NH_ASN1_NODE_STR *odin, _IN_ NH_ASN1_NODE_STR *thor)
{
	NH_ASN1_PNODE current = (NH_ASN1_PNODE) thor;

	while (current)
	{
		if (current->child) set_octetstring_value(odin, current->child);
		else
		{
			memcpy((unsigned char*) odin->value + odin->valuelen, current->value, current->valuelen);
			odin->valuelen += current->valuelen;
		}
		current = current->next;
	}

}
NH_UTILITY(NH_RV, NH_parse_octetstring)(_IN_ NH_ASN1_PARSER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node)
{
	NH_RV rv;

	if
	(
		ASN_IS_CONSTRUCTED(*node->identifier) &&
		NH_SUCCESS(rv = parse_constructed_octetstring(self, node)) &&
		NH_SUCCESS(rv = self->container->bite_chunk(self->container, node->size, (void*) &node->value))
	)
	{
		node->valuelen = 0;
		set_octetstring_value(node, node->child);
	}
	else rv = parse(node, NH_ASN1_OCTET_STRING);
	return rv;
}

NH_UTILITY(NH_RV, NH_parse_oid)(_IN_ NH_ASN1_PARSER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node)
{
	return self->parse_objectid(self, node, FALSE);
}

NH_UTILITY(NH_RV, NH_parse_objectid)(_IN_ NH_ASN1_PARSER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ int relative)
{
	unsigned int *temp, *value, octet, i = 0, j = 0, watermark = 0;
	unsigned char *contents;
	NH_RV rv;

	if (ASN_IS_CONSTRUCTED(*node->identifier) || !ASN_IS_TAG(node, NH_ASN1_OBJECT_ID)) return NH_INVALID_DER_TYPE;
	if (!(temp = (unsigned int*) malloc(node->size * sizeof(unsigned int)))) return NH_OUT_OF_MEMORY_ERROR;
	memset(temp, 0, node->size * sizeof(unsigned int));
	contents = node->contents;

	while (i < node->size)
	{
		do temp[watermark] = (temp[watermark] << 7) | (*contents & 0x7F);
		while (++i < node->size && (*contents++ & 0x80) == 0x80);
		watermark++;
	}
	if (NH_SUCCESS(rv = self->container->bite_chunk(self->container, (watermark + 1) * sizeof(unsigned int), (void*) &value)))
	{
		if (!relative)
		{
			octet = temp[0];
			if (octet < 0x50)
			{
				value[0] = octet / 0x28;
				value[1] = octet % 0x28;
			}
			else
			{
				value[0] = 0x02;
				value[1] = octet - 0x50;
			}
			j = 1;
		}
		for (i = j; i < watermark; i++) value[i + j] = temp[i];
		node->value = value;
		node->valuelen = watermark + 1;
	}
	free(temp);
	return rv;
}

NH_UTILITY(NH_RV, NH_parse_string)(_INOUT_ NH_ASN1_NODE_STR *node)
{
	if
	(
		ASN_IS_CONSTRUCTED(*node->identifier) ||
		(
			!ASN_IS_TAG(node, NH_ASN1_UTF8_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_NUMERIC_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_PRINTABLE_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_T61_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_VIDEOTEX_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_IA5_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_GRAPHIC_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_VISIBLE_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_GENERAL_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_UNIVERSAL_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_BMP_STRING) &&
			!ASN_IS_TAG(node, NH_ASN1_TELETEX_STRING)
		)
	)	return NH_INVALID_DER_TYPE;
	node->value = node->contents;
	node->valuelen = node->size;
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_parse_object_descriptor)(_INOUT_ NH_ASN1_NODE_STR *node)
{
	return parse(node, NH_ASN1_OBJECT_DESCRIPTOR);
}

NH_UTILITY(NH_RV, NH_parse_enumerated)(_INOUT_ NH_ASN1_NODE_STR *node)
{
	return parse(node, NH_ASN1_ENUMERATED);
}

NH_UTILITY(NH_RV, NH_parse_embedded_pdv)(_INOUT_ NH_ASN1_NODE_STR *node)
{
	return parse(node, NH_ASN1_EMBEDDED_PDV);
}

INLINE NH_UTILITY(int, asnyear_to_int)(_IN_ char *from, _IN_ size_t size)
{
	char year[] = { 0, 0, 0, 0, 0 };
	memcpy(year, from, size);
	return atoi(year);
}

NH_UTILITY(NH_RV, NH_parse_time)(_IN_ NH_ASN1_PARSER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node)
{
	NH_PTIME utctime;
	char *temp;
	int yearlen;
	NH_RV rv;

	if
	(
		ASN_IS_CONSTRUCTED(*node->identifier) ||
		(!ASN_IS_TAG(node, NH_ASN1_UTC_TIME) && !ASN_IS_TAG(node, NH_ASN1_GENERALIZED_TIME))
	)	return NH_INVALID_DER_TYPE;
	yearlen = ASN_IS_TAG(node, NH_ASN1_UTC_TIME) ? 2 : 4;
	if (node->size > (unsigned int) (11 + yearlen)) return NH_UNEXPECTED_ENCODING;
	if (NH_FAIL(rv = self->container->bite_chunk(self->container, sizeof(NH_TIME), (void*) &utctime))) return rv;
	memset(utctime, 0, sizeof(NH_TIME));
	temp = (char*) node->contents;

	utctime->tm_year = asnyear_to_int(temp, yearlen);
	utctime->tm_year += ASN_IS_TAG(node, NH_ASN1_UTC_TIME) ? 100 : -1900;
	temp += yearlen;
	utctime->tm_mon = asnyear_to_int(temp, 2);
	temp += 2;
	utctime->tm_mon--;
	utctime->tm_mday = asnyear_to_int(temp, 2);
	temp += 2;
	utctime->tm_hour = asnyear_to_int(temp, 2);
	temp += 2;
	utctime->tm_min = asnyear_to_int(temp, 2);
	temp += 2;
	utctime->tm_sec = asnyear_to_int(temp, 2);
	node->value = utctime;
	node->valuelen = sizeof(NH_TIME);
	return NH_OK;
}


static NH_ASN1_PARSER defParserHandler =
{
	NULL,
	0,
	NULL,
	NULL,
	NH_new_node,
	NH_sail,
	NH_add_next,
	NH_add_to_set,
	NH_read_size,
	NH_map,
	NH_map_from,
	NH_map_node,
	NH_map_set_of,
	NH_parse_boolean,
	NH_parse_little_integer,
	NH_parse_integer,
	NH_parse_real,
	NH_parse_bitstring,
	NH_parse_octetstring,
	NH_parse_oid,
	NH_parse_objectid,
	NH_parse_string,
	NH_parse_object_descriptor,
	NH_parse_enumerated,
	NH_parse_embedded_pdv,
	NH_parse_time
};

NH_FUNCTION(NH_RV, NH_new_parser)
(
	_IN_ unsigned char *encoding,
	_IN_ size_t len,
	_IN_ size_t nodes,
	_IN_ size_t datasize,
	_OUT_ NH_ASN1_PARSER_HANDLE *hHandle
)
{
	NH_ASN1_PARSER_HANDLE handler;
	NH_RV rv;

	if (!encoding) return NH_INVALID_ARG;
	if (!(handler = malloc(sizeof(NH_ASN1_PARSER)))) return NH_OUT_OF_MEMORY_ERROR;
	memcpy(handler, &defParserHandler, sizeof(NH_ASN1_PARSER));
	if (NH_SUCCESS(rv = NH_freight_container((nodes * sizeof(NH_ASN1_NODE)) + datasize, &handler->container)))
	{
		handler->encoding = (unsigned char *) encoding;
		handler->length = len;
		*hHandle = handler;
		return NH_OK;
	}
	free(handler);
	return rv;
}

NH_FUNCTION(NH_RV, NH_release_parser)(_IN_ NH_ASN1_PARSER_HANDLE hHandle)
{
	NH_RV rv;
	if (!hHandle) return NH_INVALID_ARG;
	rv = NH_release_container(hHandle->container);
	free(hHandle);
	return rv;
}


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 * ASN.1 encoding implementation
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
INLINE NH_FUNCTION(unsigned char, NH_asn_get_tag)(_IN_ int knowledge)
{
	unsigned char tag;
	if (ASN_IS_ON(NH_ASN1_CONTEXT_BIT, knowledge))
	{
		tag = ((knowledge & NH_ASN1_CT_TAG_MASK) >> 8) | NH_ASN1_CONTEXT;
		if (ASN_IS_ON(NH_ASN1_EXPLICIT_BIT, knowledge)) tag |= NH_ASN1_CONSTRUCTED_BIT;
		else tag |= (knowledge & NH_ASN1_CONSTRUCTED_BIT);
	}
	else tag = (knowledge & (NH_ASN1_TAG_MASK | NH_CLASS_MASK | NH_ASN1_CONSTRUCTED_BIT));
	return tag;
}

NH_UTILITY(void, NH_asn_register_optional)(_INOUT_ NH_ASN1_NODE_STR *node)
{
	if (*node->identifier == NH_NULL_TAG || *node->identifier == NH_ASN1_NULL) *node->identifier = NH_asn_get_tag(node->knowledge);
}

NH_UTILITY(NH_RV, NH_chart)
(
	_INOUT_ NH_ASN1_ENCODER_STR *self,
	_IN_ NH_NODE_WAY_STR *encyclopedia,
	_IN_ size_t count,
	_OUT_ NH_ASN1_NODE_STR **root
)
{
	NH_RV rv;

	if (!encyclopedia || encyclopedia[0].path != NH_PARSE_ROOT) return NH_INVALID_ARG;
	if (NH_FAIL(rv = self->new_node(self->container, root))) return rv;
	self->root = *root;
	return self->chart_from(self, *root, encyclopedia, count);
}

NH_UTILITY(NH_RV, NH_chart_from)
(
	_IN_ NH_ASN1_ENCODER_STR *self,
	_INOUT_ NH_ASN1_NODE_STR *current,
	_IN_ NH_NODE_WAY_STR *encyclopedia,
	_IN_ size_t count
)
{
	unsigned int i = 0;
	NH_RV rv;
	NH_ASN1_PNODE next;

	while (i < count)
	{
		if (NH_FAIL(rv = self->pave(self, current, encyclopedia[i].path, &next))) return rv;
		if (!next) return NH_CANNOT_SAIL;
		if (ASN_IS_ON(NH_ASN1_TWIN_BIT, encyclopedia[i].knowledge)) next->parent->child = NULL;
		else if (encyclopedia[i].detour && !ASN_IS_ON(NH_ASN1_PORTOLANI_BIT, encyclopedia[i].knowledge))
		{
			if (NH_FAIL(rv = self->chart_from(self, next, encyclopedia[i].detour, encyclopedia[i].count))) return rv;
		}
		else
		{
			next->knowledge = encyclopedia[i].knowledge;
			if
			(
				NH_FAIL(rv = self->container->bite_chunk(self->container, sizeof(unsigned char*), (void*) &next->identifier))
			)	return rv;
			if (ASN_IS_OPTIONAL(next->knowledge) || ASN_IS_ON(NH_ASN1_CHOICE_BIT, next->knowledge)) *next->identifier = NH_NULL_TAG;
			else
			{
				*next->identifier = NH_asn_get_tag(next->knowledge);
				if (ASN_IS_ON(NH_ASN1_EXPLICIT_BIT, next->knowledge))
				{
					if (!self->add_child(self->container, next)) return NH_OUT_OF_MEMORY_ERROR;
					if
					(	/* EXPLICT primitive types should be resolved early */
						!ASN_IS_ON(NH_ASN1_EXP_CONSTRUCTED_BIT, next->knowledge) &&
						!ASN_IS_ON(NH_ASN1_ANY_TAG_BIT, next->knowledge)
					)
					{
						if
						(
							NH_FAIL
							(
								rv = self->container->bite_chunk
								(
									self->container,
									sizeof(unsigned char*),
									(void*) &next->child->identifier
								)
							)
						)	return rv;
						*next->child->identifier = next->knowledge & NH_ASN1_TAG_MASK;
						next->child->knowledge = *next->child->identifier;
					}
				}
			}
			while (ASN_IS_ON(NH_ASN1_CHOICE_BIT, encyclopedia[i].knowledge) && !ASN_IS_ON(NH_ASN1_CHOICE_END_BIT, encyclopedia[i].knowledge)) i++;
		}
		current = next;
		i++;
	}
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_pave)
(
	_IN_ NH_ASN1_ENCODER_STR *self,
	_IN_ NH_ASN1_NODE_STR *current,
	_IN_ int path,
	_OUT_ NH_ASN1_NODE_STR **ret
)
{
	int j, jumps, i = 3;
	unsigned int instruction;
	NH_ASN1_PNODE node;

	node = (NH_ASN1_PNODE) current;
	while (i > -1 && node)
	{
		instruction = (path >> (i-- * 8)) & 0x000000FF;
		jumps = instruction & NH_PARSE_AMOUNT_MASK;
		j = 0;
		if (ASN_GO_SOUTH(instruction))
		{
			while (j++ < jumps && node)
			{
				if (!node->child && i == -1 && j == jumps)
				{
					if (!(node = self->add_child(self->container, node))) return NH_OUT_OF_MEMORY_ERROR;
					node->size = 0;
				}
				else	node = node->child;
			}
		}
		else if (ASN_GO_EAST(instruction))
		{
			while (j++ < jumps && node)
			{
				if (!node->next && i == -1 && j == jumps)
				{
					if (!(node = self->add_next(self->container, node))) return NH_OUT_OF_MEMORY_ERROR;
					node->size = 0;
				}
				else	node = node->next;
			}
		}
		else if (ASN_GO_WEST(instruction)) while (j++ < jumps && node) node = node->previous;
		else while (j++ < jumps && node) node = node->parent;
	}
	*ret = node;
	return NH_OK;
}

INLINE NH_UTILITY(NH_RV, asn_put_value)
(
	_IN_ NH_CARGO_CONTAINER hContainer,
	_INOUT_ NH_ASN1_PNODE node,
	_IN_ void *data,
	_IN_ size_t size,
	_IN_ unsigned char octet
)
{
	NH_RV rv;

	if (!ASN_IS_CONSTRUCTED(*node->identifier) && !ASN_IS_TAG(node, octet)) return NH_INVALID_DER_TYPE;
	if (NH_FAIL(rv = hContainer->bite_chunk(hContainer, size, &node->value))) return rv;
	memcpy(node->value, data, size);
	node->valuelen = size;
	return rv;
}

NH_UTILITY(NH_RV, NH_put_utc)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *utc, _IN_ size_t size)
{
	return asn_put_value(self->container, node, utc, size, NH_ASN1_UTC_TIME);
}

NH_UTILITY(NH_RV, NH_put_generalized_time)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *gtime, _IN_ size_t size)
{
	return asn_put_value(self->container, node, gtime, size, NH_ASN1_GENERALIZED_TIME);
}

NH_UTILITY(NH_RV, NH_put_integer)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_INTEGER);
}

NH_UTILITY(NH_RV, NH_put_octet_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_OCTET_STRING);
}

NH_UTILITY(NH_RV, NH_put_object_descriptor)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_OBJECT_DESCRIPTOR);
}

NH_UTILITY(NH_RV, NH_put_real)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_REAL);
}

NH_UTILITY(NH_RV, NH_put_enumerated)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	size_t isize;
	unsigned char buffer[sizeof(int)];
	int i = 0;

	if (size > sizeof(int)) return asn_put_value(self->container, node, value, size, NH_ASN1_ENUMERATED);
	memcpy(buffer, value, sizeof(int));
	NH_swap(buffer, sizeof(int));
	while (!buffer[i] && i < sizeof(int) - 1) i++;
	isize = sizeof(int) - i;
	return asn_put_value(self->container, node, (void*) &buffer[i], isize, NH_ASN1_ENUMERATED);
}

NH_UTILITY(NH_RV, NH_put_embedded_pdv)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_EMBEDDED_PDV);
}

NH_UTILITY(NH_RV, NH_put_utf8_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_UTF8_STRING);
}

NH_UTILITY(NH_RV, NH_put_numeric_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_NUMERIC_STRING);
}

NH_UTILITY(NH_RV, NH_put_printable_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_PRINTABLE_STRING);
}

NH_UTILITY(NH_RV, NH_put_t61_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_T61_STRING);
}

NH_UTILITY(NH_RV, NH_put_videotex_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_VIDEOTEX_STRING);
}

NH_UTILITY(NH_RV, NH_put_ia5_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_IA5_STRING);
}

NH_UTILITY(NH_RV, NH_put_graphic_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_GRAPHIC_STRING);
}

NH_UTILITY(NH_RV, NH_put_visible_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_VISIBLE_STRING);
}

NH_UTILITY(NH_RV, NH_put_general_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_GENERAL_STRING);
}

NH_UTILITY(NH_RV, NH_put_universal_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_UNIVERSAL_STRING);
}

NH_UTILITY(NH_RV, NH_put_bmp_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_BMP_STRING);
}

NH_UTILITY(NH_RV, NH_put_teletex_string)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ void *value, _IN_ size_t size)
{
	return asn_put_value(self->container, node, value, size, NH_ASN1_TELETEX_STRING);
}

NH_UTILITY(NH_RV, NH_put_boolean)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ unsigned char value)
{
	if (value != TRUE && value != FALSE) return NH_TYPE_INCOMPATIBLE;
	return asn_put_value(self->container, node, (void*) &value, sizeof(unsigned char), NH_ASN1_BOOLEAN);
}

NH_UTILITY(NH_RV, NH_put_bitstring)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ NH_BITSTRING_VALUE_STR *value)
{
	NH_RV rv;
	unsigned char *pBuffer;
	size_t uSize = value->len + 1;

	if (NH_SUCCESS(rv = (pBuffer = (unsigned char*) malloc(uSize)) ? NH_OK : NH_OUT_OF_MEMORY_ERROR))
	{
		pBuffer[0] = value->padding;
		memcpy(pBuffer + 1, value->string, value->len);
		rv = asn_put_value(self->container, node, pBuffer, uSize, NH_ASN1_BIT_STRING);
		free(pBuffer);
	}
	return rv;
}

NH_UTILITY(NH_RV, NH_put_objectid)
(
	_IN_ NH_ASN1_ENCODER_STR *self,
	_INOUT_ NH_ASN1_NODE_STR *node,
	_IN_ unsigned int *value,
	_IN_ size_t count,
	_IN_ int relative
)
{
	NH_RV rv;

	if (!relative)
	{
		if (count < 2 || value[0] > 2 || value[1] > 39) return NH_TYPE_INCOMPATIBLE;
	}
	if (NH_FAIL(rv = self->container->bite_chunk(self->container, sizeof(unsigned int) * count, &node->value))) return rv;
	memcpy(node->value, value, sizeof(unsigned int) * count);
	node->valuelen = count;
	return NH_OK;
}

NH_UTILITY(NH_RV, NH_put_little_integer)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node, _IN_ int value)
{
	size_t size;
	unsigned char buffer[sizeof(int) + 1];
	int i = 1;

	buffer[0] = 0;
	memcpy(buffer + 1, &value, sizeof(int));
	NH_swap(buffer, sizeof(int) + 1);
	while (!buffer[i] && i < sizeof(int)) i++;
	if (value > 0 && buffer[i] & 0x80) i--;
	size = sizeof(int) - i + 1;
	return asn_put_value(self->container, node, (void*) &buffer[i], size, NH_ASN1_INTEGER);
}

INLINE NH_UTILITY(size_t, oid_len)(_IN_ unsigned int value)
{
	unsigned int len = 5;
	if		(value < 0x00000080) len = 1;
	else if	(value < 0x00004000) len = 2;
	else if	(value < 0x00200000) len = 3;
	else if	(value < 0x10000000) len = 4;
	return len;
}

NH_UTILITY(size_t, NH_encoded_size)(_IN_ NH_ASN1_ENCODER_STR *self, _INOUT_ NH_ASN1_NODE_STR *node)
{
	size_t size = 0, len = 0, i = 0;
	unsigned int *octets;
	NH_ASN1_PNODE current = node;

	do
	{
		if (ASN_IS_OPTIONAL(current->knowledge) && *current->identifier == NH_NULL_TAG);
		else if (ASN_IS_CONSTRUCTED(current->knowledge))
		{
			if (current->child && current->child->knowledge ) current->size = self->encoded_size(self, current->child);
			size += ASN_ENCODED_SIZE(current->size);
		}

		else
		{
			if
			(
				current->value ||
				((current->knowledge & NH_ASN1_TAG_MASK) == NH_ASN1_NULL)
			)
			{

				switch (current->knowledge & NH_ASN1_TAG_MASK)
				{
				case NH_ASN1_BOOLEAN:
					len = 1;
					break;
				case NH_ASN1_NULL:
					len = 0;
					break;
				case NH_ASN1_OBJECT_ID:
					i = 2;
					len = 1;
				case NH_ASN1_RELATIVE_OID:
					octets = (unsigned int*) current->value;
					for (; i < current->valuelen; i++) len += oid_len(octets[i]);
					break;
				default:
					len = current->valuelen;
					break;
				}
				current->size = len;
			} else len = current->size;
			size += ASN_ENCODED_SIZE(len);
		}
	}
	while((current = current->next));
	return size;
}

INLINE NH_UTILITY(size_t, encode_oid_int)(_IN_ unsigned int value, _OUT_ unsigned char *buffer)
{
	unsigned int i = 0, len, mask = 0x7F;

	len = oid_len(value);
	buffer += len - 1;
	*buffer-- = (value & mask);

	while(++i < len) *buffer-- = ((value & (mask << (i * 7))) >> (i * 7)) | 0x80;
	return len;
}

INLINE NH_UTILITY(NH_RV, asn_recursive_encoding)
(
	_IN_ NH_ASN1_ENCODER_HANDLE self,
	_IN_ NH_ASN1_PNODE node,
	_OUT_ unsigned char *buffer,
	_OUT_ unsigned int *offset
)
{
	NH_RV rv = NH_OK;
	unsigned int len, i = 0, off = 0;
	NH_ASN1_PNODE current = node;
	unsigned char *init = buffer;

	do
	{
		if (*current->identifier != NH_NULL_TAG)
		{
			*buffer++ = *current->identifier;

			len = ASN_INT_SIZE(current->size);
			if (current->size > 0x7F) *buffer++ = (0x80 | --len);
			self->encode_int(buffer, current->size, len);
			buffer += len;

			if (ASN_IS_CONSTRUCTED(current->knowledge))
			{
				if (current->child && current->child->knowledge)
				{
					rv = asn_recursive_encoding(self, current->child, buffer, &off);
					buffer += off;
				}
				else
				{
					memcpy(buffer, current->contents, current->size);
					buffer += current->size;
				}
			}
			else
			{
				if (current->value || ASN_IS_TAG(current, NH_ASN1_NULL))
				{
					switch (current->knowledge & NH_ASN1_TAG_MASK)
					{
					case NH_ASN1_NULL:
						break;
					case NH_ASN1_OBJECT_ID:
						i = 2;
						if (current->valuelen < 2) rv = NH_TYPE_INCOMPATIBLE;
						else
						{
							buffer += encode_oid_int
							(
								((unsigned int*)current->value)[0] * 40 + ((unsigned int*)current->value)[1],
								buffer
							);
					case NH_ASN1_RELATIVE_OID:
							for
							(
								;
								i < current->valuelen;
								i++
							)	buffer += encode_oid_int(((unsigned int*)current->value)[i], buffer);
						}
						break;
					default:
						memcpy(buffer, current->value, current->valuelen);
						buffer += current->valuelen;
						break;
					}
				}
				else
				{
					memcpy(buffer, current->contents, current->size);
					buffer += current->size;
				}
			}
		}
	}
	while(NH_SUCCESS(rv) && (current = current->next));
	*offset = buffer - init;
	return rv;
}

NH_UTILITY(NH_RV, NH_encode)(_IN_ NH_ASN1_ENCODER_STR *self, _IN_ NH_ASN1_NODE_STR *root, _OUT_ unsigned char *buffer)
{
	unsigned int off = 0;
	return asn_recursive_encoding((NH_ASN1_ENCODER_HANDLE) self, (NH_ASN1_PNODE)root, buffer, &off);
}

static NH_ASN1_ENCODER defEncoderHandler =
{
	NULL,
	NULL,
	NH_new_node,
	NH_sail,
	NH_add_next,
	NH_add_child,
	NH_add_to_set,
	NH_read_size,
	NH_encode_int,
	NH_asn_register_optional,
	NH_chart,
	NH_chart_from,
	NH_pave,
	NH_put_utc,
	NH_put_generalized_time,
	NH_put_integer,
	NH_put_octet_string,
	NH_put_object_descriptor,
	NH_put_real,
	NH_put_enumerated,
	NH_put_embedded_pdv,
	NH_put_utf8_string,
	NH_put_numeric_string,
	NH_put_printable_string,
	NH_put_t61_string,
	NH_put_videotex_string,
	NH_put_ia5_string,
	NH_put_graphic_string,
	NH_put_visible_string,
	NH_put_general_string,
	NH_put_universal_string,
	NH_put_bmp_string,
	NH_put_teletex_string,
	NH_put_boolean,
	NH_put_bitstring,
	NH_put_objectid,
	NH_put_little_integer,
	NH_encoded_size,
	NH_encode
};

NH_FUNCTION(NH_RV, NH_new_encoder)(_IN_ size_t nodes, _IN_ size_t datasize, _OUT_ NH_ASN1_ENCODER_HANDLE *hHandle)
{
	NH_ASN1_ENCODER_HANDLE handler;
	NH_RV rv;

	if (!(handler = malloc(sizeof(NH_ASN1_ENCODER)))) return NH_OUT_OF_MEMORY_ERROR;
	memcpy(handler, &defEncoderHandler, sizeof(NH_ASN1_ENCODER));
	if (NH_SUCCESS(rv = NH_freight_container((nodes * sizeof(NH_ASN1_NODE)) + datasize, &handler->container)))
	{
		*hHandle = handler;
		return NH_OK;
	}
	free(handler);
	return rv;
}

NH_FUNCTION(NH_RV, NH_release_encoder)(_IN_ NH_ASN1_ENCODER_HANDLE hHandle)
{
	NH_RV rv;
	if (!hHandle) return NH_INVALID_ARG;
	rv = NH_release_container(hHandle->container);
	free(hHandle);
	return rv;
}


#if defined(_MSC_VER)
EXTERN
#endif
INLINE NH_UTILITY(NH_RV, NH_asn_clone_node)(_INOUT_ NH_CARGO_CONTAINER container, _IN_ NH_ASN1_PNODE from, _INOUT_ NH_ASN1_PNODE *to)
{
	NH_RV rv;
	NH_ASN1_PNODE node = *to;
	size_t size = from->size + from->contents - from->identifier;

	if (NH_FAIL(rv = container->bite_chunk(container, size, (void*) &node->identifier))) return rv;
	memcpy(node->identifier, from->identifier, size);
	node->size = from->size;
	node->knowledge = from->knowledge;
	node->contents = node->identifier + (from->contents - from->identifier);
	*to = node;
	return rv;
}


#ifdef _DEBUG_
#include <stdio.h>
#include <errno.h>
void printASNTree(NH_ASN1_PNODE node, int level)
{
	int i, optional, tag, id;
	while (node)
	{
		for (i = 0; i < level; i++) printf("  ");

		optional = ASN_IS_ON(NH_ASN1_OPTIONAL_BIT, node->knowledge) || ASN_IS_ON(NH_ASN1_DEFAULT_BIT, node->knowledge);
		tag = ((node->knowledge) & NH_ASN1_TAG_MASK);
		if (node->identifier) id = (int) *node->identifier;
		else id = 0;

		printf
		(
			"%p, identifier: 0x%X, tag %d, size: %d, knowledge: %d, valuelen: %d, optional: %d, value:[",
			(void*) node,
			id,
			tag,
			node->size,
			node->knowledge,
			node->valuelen,
			optional
		);
		for(i = 0; i < (int) node->valuelen; i++)
		{
			printf("%02X",*((char *)node->value + i));
		}
		printf("]\n");

		if (node->child) printASNTree(node->child, level + 1);
		node = node->next;
	}
	printf("\n");
}
int saveTo(unsigned char *buffer, size_t size, char *filename)
{
	FILE *stream;
	int err = 0;

	if ((stream = fopen(filename, "wb")))
	{
		if (fwrite(buffer, sizeof(unsigned char), size, stream) != size) err = ferror(stream);
		fclose(stream);
	}
	else err = errno;
	return err;
}
#endif
