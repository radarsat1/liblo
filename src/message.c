/*
 *  Copyright (C) 2004 Steve Harris
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  $Id$
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "lo_types_internal.h"
#include "lo/lo.h"

#define LO_DEF_TYPE_SIZE 8
#define LO_DEF_DATA_SIZE 8

static char lo_numerical_types[] = {
    LO_INT32,
    LO_FLOAT,
    LO_INT64,
    LO_DOUBLE,
    '\0'
};

static char lo_string_types[] = {
    LO_STRING,
    LO_SYMBOL,
    '\0'
};

static void lo_message_add_typechar(lo_message m, char t);
static void *lo_message_add_data(lo_message m, size_t s);
void lo_arg_pp_internal(lo_type type, void *data, int bigendian);

lo_message lo_message_new()
{
    lo_message m = malloc(sizeof(struct _lo_message));
    if (!m) {
	return m;
    }

    m->types = calloc(LO_DEF_TYPE_SIZE, sizeof(char));
    m->types[0] = ',';
    m->types[1] = '\0';
    m->typelen = 1;
    m->typesize = LO_DEF_TYPE_SIZE;
    m->data = calloc(1, LO_DEF_DATA_SIZE);
    m->datalen = 0;
    m->datasize = LO_DEF_DATA_SIZE;
    m->source = NULL;

    return m;
}

void lo_message_free(lo_message m)
{
    if (m) {
	free(m->types);
	free(m->data);
    }
    free(m);
}
	
void lo_message_add_int32(lo_message m, int32_t a)
{
    lo_pcast32 b;
    int32_t *nptr = lo_message_add_data(m, sizeof(a));
    b.i = a;

    lo_message_add_typechar(m, LO_INT32);
    *nptr = lo_htoo32(b.nl);
}
    
void lo_message_add_float(lo_message m, float a)
{
    lo_pcast32 b;
    int32_t *nptr = lo_message_add_data(m, sizeof(a));
    b.f = a;

    lo_message_add_typechar(m, LO_FLOAT);
    *nptr = lo_htoo32(b.nl);
}

void lo_message_add_string(lo_message m, char *a)
{
    const int size = lo_strsize(a);
    char *nptr = lo_message_add_data(m, size);

    lo_message_add_typechar(m, LO_STRING);
    strncpy(nptr, a, size);
}

void lo_message_add_blob(lo_message m, lo_blob a)
{
    const int size = lo_blobsize(a);
    const int32_t dsize = lo_htoo32(lo_blob_datasize(a));
    char *nptr = lo_message_add_data(m, size);

    lo_message_add_typechar(m, LO_BLOB);
    memset(nptr + size - 4, 0, 4);

    memcpy(nptr, &dsize, sizeof(dsize));
    memcpy(nptr + sizeof(int32_t), lo_blob_dataptr(a), lo_blob_datasize(a));
}

void lo_message_add_int64(lo_message m, int64_t a)
{
    lo_pcast64 b;
    uint64_t *nptr = lo_message_add_data(m, sizeof(a));
    b.i = a;

    lo_message_add_typechar(m, LO_INT64);
    *nptr = lo_htoo64(b.nl);
}

void lo_message_add_timetag(lo_message m, lo_timetag a)
{
    lo_pcast64 b;
    uint64_t *nptr = lo_message_add_data(m, sizeof(a));
    b.tt = a;

    lo_message_add_typechar(m, LO_TIMETAG);
    *nptr = lo_htoo64(b.nl);
}

void lo_message_add_double(lo_message m, double a)
{
    lo_pcast64 b;
    uint64_t *nptr = lo_message_add_data(m, sizeof(a));
    b.f = a;

    lo_message_add_typechar(m, LO_DOUBLE);
    *nptr = lo_htoo64(b.nl);
}

void lo_message_add_symbol(lo_message m, char *a)
{
    const int size = lo_strsize(a);
    char *nptr = lo_message_add_data(m, size);

    lo_message_add_typechar(m, LO_SYMBOL);
    strncpy(nptr, a, size);
}

void lo_message_add_char(lo_message m, char a)
{
    lo_pcast32 b;
    int32_t *nptr = lo_message_add_data(m, sizeof(int32_t));

    b.i = a;

    lo_message_add_typechar(m, LO_CHAR);
    *nptr = lo_htoo32(b.nl);
}

void lo_message_add_midi(lo_message m, uint8_t a[4])
{
    char *nptr = lo_message_add_data(m, sizeof(a));

    lo_message_add_typechar(m, LO_MIDI);

    memcpy(nptr, a, sizeof(a));
}

void lo_message_add_true(lo_message m)
{
    lo_message_add_typechar(m, LO_TRUE);
}

void lo_message_add_false(lo_message m)
{
    lo_message_add_typechar(m, LO_FALSE);
}

void lo_message_add_nil(lo_message m)
{
    lo_message_add_typechar(m, LO_NIL);
}

void lo_message_add_infinitum(lo_message m)
{
    lo_message_add_typechar(m, LO_INFINITUM);
}

static void lo_message_add_typechar(lo_message m, char t)
{
    if (m->typelen + 1 >= m->typesize) {
	m->typesize *= 2;
	m->types = realloc(m->types, m->typesize);
    }
    m->types[m->typelen] = t;
    m->typelen++;
    m->types[m->typelen] = '\0';
}

static void *lo_message_add_data(lo_message m, size_t s)
{
    int old_dlen = m->datalen;

    m->datalen += s;
    while (m->datalen > m->datasize) {
	m->datasize *= 2;
	m->data = realloc(m->data, m->datasize);
    }

    return m->data + old_dlen;
}

int lo_strsize(const char *s)
{
    return 4 * (strlen(s) / 4 + 1);
}

size_t lo_arg_size(lo_type type, void *data)
{
    switch (type) {
    case LO_TRUE:
    case LO_FALSE:
    case LO_NIL:
    case LO_INFINITUM:
	return 0;

    case LO_INT32:
    case LO_FLOAT:
    case LO_MIDI:
    case LO_CHAR:
	return 4;

    case LO_INT64:
    case LO_TIMETAG:
    case LO_DOUBLE:
	return 8;

    case LO_STRING:
    case LO_SYMBOL:
	return lo_strsize((char *)data);

    case LO_BLOB:
	return lo_blobsize((lo_blob)data);

    default:
	fprintf(stderr, "liblo warning: unhandled OSC type '%c' at %s:%d\n", type, __FILE__, __LINE__);
	return 0;
    }

    return 0;
}

/* convert endianness of arg pointed to by data from network to host */

void lo_arg_host_endian(lo_type type, void *data)
{
    switch (type) {
    case LO_INT32:
    case LO_FLOAT:
    case LO_BLOB:
    case LO_CHAR:
	*(int32_t *)data = lo_otoh32(*(int32_t *)data);
	break;

    case LO_INT64:
    case LO_TIMETAG:
    case LO_DOUBLE:
	*(int64_t *)data = lo_otoh64(*(int64_t *)data);
	break;

    case LO_STRING:
    case LO_SYMBOL:
    case LO_MIDI:
    case LO_TRUE:
    case LO_FALSE:
    case LO_NIL:
    case LO_INFINITUM:
	/* these are fine */
	break;

    default:
	fprintf(stderr, "liblo warning: unhandled OSC type '%c' at %s:%d\n",
		type, __FILE__, __LINE__);
	break;
    }
}

size_t lo_message_length(lo_message m, const char *path)
{
    return lo_strsize(path) + lo_strsize(m->types) + m->datalen;
}

void *lo_message_serialise(lo_message m, const char *path, void *to,
			   size_t *size)
{
    size_t s = lo_message_length(m, path);

    if (size) {
	*size = s;
    }

    if (!to) {
	to = calloc(1, s);
    }
    memcpy(to, path, strlen(path));
    memcpy(to + lo_strsize(path), m->types, m->typelen);
    memcpy(to + lo_strsize(path) + lo_strsize(m->types), m->data, m->datalen);

    return to;
}

void lo_message_pp(lo_message m)
{
    void *d = m->data;
    void *end = m->data + m->datalen;
    int i;

    printf("%s ", m->types);
    for (i = 1; m->types[i]; i++) {
	if (i > 1) {
	    printf(" ");
	}

	lo_arg_pp_internal(m->types[i], d, 1);
	d += lo_arg_size(m->types[i], d);
    }
    putchar('\n');
    if (d != end) {
	fprintf(stderr, "liblo warning: type and data do not match (off by %d) in message %p\n",
		abs(d - end), m);
    }
}

void lo_arg_pp(lo_type type, void *data)
{
    lo_arg_pp_internal(type, data, 0);
}

void lo_arg_pp_internal(lo_type type, void *data, int bigendian)
{
    lo_pcast32 val32;
    lo_pcast64 val64;
    int size;
    int i;

    size = lo_arg_size(type, data);
    if (size == 4 || type == LO_BLOB) {
	if (bigendian) {
	    val32.nl = lo_otoh32(*(int32_t *)data);
	} else {
	    val32.nl = *(int32_t *)data;
	}
    } else if (size == 8) {
	if (bigendian) {
	    val64.nl = lo_otoh64(*(int64_t *)data);
	} else {
	    val64.nl = *(int64_t *)data;
	}
    }

    switch (type) {
    case LO_INT32:
	printf("%d", val32.i);
	break;
    
    case LO_FLOAT:
	printf("%f", val32.f);
	break;

    case LO_STRING:
	printf("\"%s\"", (char *)data);
	break;

    case LO_BLOB:
	printf("[");
	if (val32.i > 12) {
	    printf("%d byte blob", val32.i);
	} else {
	    printf("%db ", val32.i);
	    for (i=0; i<val32.i; i++) {
		printf("0x%02x", *((char *)(data) + 4 + i));
		if (i+1 < val32.i) printf(" ");
	    }
	}
	printf("]");
	break;

    case LO_INT64:
	printf("%lld", val64.i);
	break;
    
    case LO_TIMETAG:
	printf("%08x.%08x", val64.tt.sec, val64.tt.frac);
	break;
    
    case LO_DOUBLE:
	printf("%f", val64.f);
	break;
    
    case LO_SYMBOL:
	printf("'%s", (char *)data);
	break;

    case LO_CHAR:
	printf("'%c'", (char)val32.i);
	break;

    case LO_MIDI:
	printf("MIDI [");
	for (i=0; i<4; i++) {
	    printf("0x%02x", *((uint8_t *)(data) + i));
	    if (i+1 < 4) printf(" ");
	}
	printf("]");
	break;

    case LO_TRUE:
	printf("#T");
	break;

    case LO_FALSE:
	printf("#F");
	break;

    case LO_NIL:
	printf("Nil");
	break;

    case LO_INFINITUM:
	printf("Infinitum");
	break;

    default:
	fprintf(stderr, "liblo warning: unhandled type: %c\n", type);
	break;
    }
}

int lo_is_numerical_type(lo_type a)
{
    return strchr(lo_numerical_types, a) != 0;
}

int lo_is_string_type(lo_type a)
{
    return strchr(lo_string_types, a) != 0;
}

int lo_coerce(lo_type type_to, lo_arg *to, lo_type type_from, lo_arg *from)
{
    if (type_to == type_from) {
	memcpy(to, from, lo_arg_size(type_from, from));

	return 1;
    }

    if (lo_is_string_type(type_to) && lo_is_string_type(type_from)) {
	strcpy((char *)to, (char *)from);

	return 1;
    }

    if (lo_is_numerical_type(type_to) && lo_is_numerical_type(type_from)) {
	switch (type_to) {
	case LO_INT32:
	    to->i = (uint32_t)lo_hires_val(type_from, from);
	    break;

	case LO_INT64:
	    to->i64 = (uint64_t)lo_hires_val(type_from, from);
	    break;

	case LO_FLOAT:
	    to->f = (float)lo_hires_val(type_from, from);
	    break;

	case LO_DOUBLE:
	    to->d = (double)lo_hires_val(type_from, from);
	    break;

	default:
	    fprintf(stderr, "liblo: bad coercion: %c -> %c\n", type_from,
		    type_to);
	    return 0;
	}
	return 1;
    }

    return 0;
}

lo_hires lo_hires_val(lo_type type, lo_arg *p)
{
    switch (type) {
    case LO_INT32:
	return p->i;
    case LO_INT64:
	return p->h;
    case LO_FLOAT:
	return p->f;
    case LO_DOUBLE:
	return p->d;
    default:
	fprintf(stderr, "liblo: hires val requested of non numerical type '%c' at %s:%d\n", type, __FILE__, __LINE__);
	break;
    }

    return 0.0l;
}

/* vi:set ts=8 sts=4 sw=4: */
