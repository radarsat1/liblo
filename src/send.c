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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include "lo_types_internal.h"
#include "lo/lo.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef WIN32
int initWSock();
#endif

#ifdef WIN32
#define geterror() WSAGetLastError()
#else
#define geterror() errno
#endif

static int resolve_address(lo_address a);
static int create_socket(lo_address a);
static int send_data(lo_address a, lo_server from, char *data, const size_t data_len);
static void add_varargs(lo_address t, lo_message m, va_list ap,
			const char *types, const char *file, int line);



/* Don't call lo_send_internal directly, use lo_send, a macro wrapping this
 * function with appropraite values for file and line */

int lo_send_internal(lo_address t, const char *file, const int line,
     const char *path, const char *types, ...)
{
    va_list ap;
    int ret;

    lo_message msg = lo_message_new();

    t->errnum = 0;
    t->errstr = NULL;

    va_start(ap, types);
    add_varargs(t, msg, ap, types, file, line);

    if (t->errnum) {
	lo_message_free(msg);
	return t->errnum;
    }

    ret = lo_send_message(t, path, msg);
    lo_message_free(msg);

    return ret;
}


/* Don't call lo_send_timestamped_internal directly, use lo_send_timestamped, a
 * macro wrapping this function with appropraite values for file and line */

int lo_send_timestamped_internal(lo_address t, const char *file,
                               	 const int line, lo_timetag ts,
				 const char *path, const char *types, ...)
{
    va_list ap;
    int ret;

    lo_message msg = lo_message_new();
    lo_bundle b = lo_bundle_new(ts);

    t->errnum = 0;
    t->errstr = NULL;

    va_start(ap, types);
    add_varargs(t, msg, ap, types, file, line);

    if (t->errnum) {
	lo_message_free(msg);
	return t->errnum;
    }

    lo_bundle_add_message(b, path, msg);
    ret = lo_send_bundle(t, b);
    lo_message_free(msg);
    lo_bundle_free(b);

    return ret;
}


/* Don't call lo_send_from_internal directly, us macros wrapping this 
 * function with appropraite values for file and line */

int lo_send_from_internal(lo_address to, lo_server from, const char *file,
                               	 const int line, lo_timetag ts,
				 const char *path, const char *types, ...)
{
    lo_bundle b = NULL;
    va_list ap;
    int ret;
    
    lo_message msg = lo_message_new();
    if (ts.sec || ts.frac) b = lo_bundle_new(ts);

    // Clear any previous errors
    to->errnum = 0;
    to->errstr = NULL;

    va_start(ap, types);
    add_varargs(to, msg, ap, types, file, line);

    if (to->errnum) {
	if (b) lo_bundle_free(b);
	lo_message_free(msg);
	return to->errnum;
    }

    if (b) {
	lo_bundle_add_message(b, path, msg);
	ret = lo_send_bundle_from(to, from, b);
    } else {
	ret = lo_send_message_from(to, from, path, msg);
    }
    
    // Free-up memory
    lo_message_free(msg);
    if (b) lo_bundle_free(b);

    return ret;
}


#if 0

This (incmplete) function converts from printf-style formats to OSC typetags,
but I think its dangerous and mislieading so its not available at the moment.

static char *format_to_types(const char *format);

static char *format_to_types(const char *format)
{
    const char *ptr;
    char *types = malloc(sizeof(format) + 1);
    char *out = types;
    int inspec = 0;
    int width = 0;
    int number = 0;

    if (!format) {
	return NULL;
    }

    for (ptr = format; *ptr; ptr++) {
	if (inspec) {
	    if (*ptr == 'l') {
		width++;
	    } else if (*ptr >= '0' && *ptr <= '9') {
		number *= 10;
		number += *ptr - '0';
	    } else if (*ptr == 'd') {
		if (width < 2 && number < 64) {
		    *out++ = LO_INT32;
		} else {
		    *out++ = LO_INT64;
		}
	    } else if (*ptr == 'f') {
		if (width < 2 && number < 64) {
		    *out++ = LO_FLOAT;
		} else {
		    *out++ = LO_DOUBLE;
		}
	    } else if (*ptr == '%') {
		fprintf(stderr, "liblo warning, unexpected '%%' in format\n");
		inspec = 1;
		width = 0;
		number = 0;
	    } else {
		fprintf(stderr, "liblo warning, unrecognised character '%c' "
			"in format\n", *ptr);
	    }
	} else {
	    if (*ptr == '%') {
		inspec = 1;
		width = 0;
		number = 0;
	    } else if (*ptr == LO_TRUE || *ptr == LO_FALSE || *ptr == LO_NIL ||
		       *ptr == LO_INFINITUM) {
		*out++ = *ptr;
	    } else {
		fprintf(stderr, "liblo warning, unrecognised character '%c' "
			"in format\n", *ptr);
	    }
	}
    }
    *out++ = '\0';

    return types;
}

#endif

static void add_varargs(lo_address t, lo_message msg, va_list ap,
			const char *types, const char *file, int line)
{
    int count = 0;
    int i;
    int64_t i64;
    float f;
    char *s;
    lo_blob b;
    uint8_t *m;
    lo_timetag tt;
    double d;

    while (types && *types) {
	count++;
	switch (*types++) {

	case LO_INT32:
	    i = va_arg(ap, int32_t);
	    lo_message_add_int32(msg, i);
	    break;

	case LO_FLOAT:
	    f = (float)va_arg(ap, double);
	    lo_message_add_float(msg, f);
	    break;

	case LO_STRING:
	    s = va_arg(ap, char *);
	    if (s == (char *)LO_MARKER_A) {
		fprintf(stderr, "liblo error: lo_send called with invalid "
			"string pointer for arg %d, probably arg mismatch\n"
		        "at %s:%d, exiting.\n", count, file, line);
		exit(1);
	    }
	    lo_message_add_string(msg, s);
	    break;

	case LO_BLOB:
	    b = va_arg(ap, lo_blob);
	    lo_message_add_blob(msg, b);
	    break;

	case LO_INT64:
	    i64 = va_arg(ap, int64_t);
	    lo_message_add_int64(msg, i64);
	    break;

	case LO_TIMETAG:
	    tt = va_arg(ap, lo_timetag);
	    lo_message_add_timetag(msg, tt);
	    break;

	case LO_DOUBLE:
	    d = va_arg(ap, double);
	    lo_message_add_double(msg, d);
	    break;

	case LO_SYMBOL:
	    s = va_arg(ap, char *);
	    if (s == (char *)LO_MARKER_A) {
		fprintf(stderr, "liblo error: lo_send called with invalid "
			"symbol pointer for arg %d, probably arg mismatch\n"
		        "at %s:%d, exiting.\n", count, file, line);
		exit(1);
	    }
	    lo_message_add_symbol(msg, s);
	    break;

	case LO_CHAR:
	    i = va_arg(ap, int);
	    lo_message_add_char(msg, i);
	    break;

	case LO_MIDI:
	    m = va_arg(ap, uint8_t *);
	    lo_message_add_midi(msg, m);
	    break;

	case LO_TRUE:
	    lo_message_add_true(msg);
	    break;

	case LO_FALSE:
	    lo_message_add_false(msg);
	    break;

	case LO_NIL:
	    lo_message_add_nil(msg);
	    break;

	case LO_INFINITUM:
	    lo_message_add_infinitum(msg);
	    break;

	default:
	    t->errnum = -1;
	    t->errstr = "unknown type";
	    fprintf(stderr, "liblo warning: unknown type '%c' at %s:%d\n",
		    *(types-1), file, line);
	    break;
	}
    }
    i = va_arg(ap, uint32_t);
    if (i != LO_MARKER_A) {
	t->errnum = -1;
	t->errstr = "bad format/args";
	fprintf(stderr, "liblo error: lo_send called with mismatching types "
	        "and data at\n%s:%d, exiting.\n", file, line);
    }
    i = va_arg(ap, uint32_t);
    if (i != LO_MARKER_B) {
	t->errnum = -1;
	t->errstr = "bad format/args";
	fprintf(stderr, "liblo error: lo_send called with mismatching types "
	        "and data at\n%s:%d, exiting.\n", file, line);
    }
    va_end(ap);
}


static int resolve_address(lo_address a)
{
    int ret;
    
    if (a->protocol == LO_UDP || a->protocol == LO_TCP) {
	struct addrinfo *ai;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
#ifdef ENABLE_IPV6
	hints.ai_family = PF_UNSPEC;
#else
	hints.ai_family = PF_INET;
#endif	
	hints.ai_socktype = a->protocol == LO_UDP ? SOCK_DGRAM : SOCK_STREAM;
	
	if ((ret = getaddrinfo(a->host, a->port, &hints, &ai))) {
	    a->errnum = ret;
	    a->errstr = gai_strerror(ret);
	    a->ai = NULL;
	    return -1;
	}
	
	a->ai = ai;
    }

    return 0;
}

static int create_socket(lo_address a)
{
    if (a->protocol == LO_UDP || a->protocol == LO_TCP) {

	a->socket = socket(a->ai->ai_family, a->ai->ai_socktype, 0);
	if (a->socket == -1) {
	    a->errnum = geterror();
	    a->errstr = NULL;
	    return -1;
	}

	if (a->protocol == LO_TCP) {
		// Only call connect() for TCP sockets - we use sendto() for UDP
		if ((connect(a->socket, a->ai->ai_addr, a->ai->ai_addrlen))) {
			a->errnum = geterror();
			a->errstr = NULL;
			close(a->socket);
			a->socket = -1;
			return -1;
		}
	}
	
    }
#ifndef WIN32
    else if (a->protocol == LO_UNIX) {
	struct sockaddr_un sa;

	a->socket = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (a->socket == -1) {
	    a->errnum = geterror();
	    a->errstr = NULL;
	    return -1;
	}

	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, a->port, sizeof(sa.sun_path)-1);

	if ((connect(a->socket, (struct sockaddr *)&sa, sizeof(sa))) < 0) {
	    a->errnum = geterror();
	    a->errstr = NULL;
	    close(a->socket);
	    a->socket = -1;
	    return -1;
	}
    } 
#endif
    else {
	/* unknown protocol */
	return -2;
    }

    return 0;
}

static int send_data(lo_address a, lo_server from, char *data, const size_t data_len)
{
    int ret=0;
    int sock=-1;

#ifdef WIN32
    if(!initWSock()) return -1;
#endif

    if (data_len > LO_MAX_MSG_SIZE) {
	a->errnum = 99;
	a->errstr = "Attempted to send message in excess of maximum "
		    "message size";
	return -1;
    }
    
    // Resolve the destination address, if not done already
    if (!a->ai) {
	ret = resolve_address( a );
	if (ret) return ret;
    }

    // Re-use existing socket?
    if (from) {
	sock = from->socket;
    } else if (a->protocol == LO_UDP && lo_client_sockets.udp!=-1) {
	sock = lo_client_sockets.udp;
    } else {
	if (a->socket==-1) {
	    ret = create_socket( a );
	    if (ret) return ret;
    	}
	sock = a->socket;
    }



    // Send Length of the following data
    if (a->protocol == LO_TCP) {
	int32_t size = htonl(data_len); 
	ret = send(sock, &size, sizeof(size), MSG_NOSIGNAL); 
    }
    
    // Send the data
    if (a->protocol == LO_UDP) {
  	ret = sendto(sock, data, data_len, MSG_NOSIGNAL,
	       a->ai->ai_addr, a->ai->ai_addrlen);
    } else {
	ret = send(sock, data, data_len, MSG_NOSIGNAL);
    }

    if (a->protocol == LO_TCP) {
    	//XXX not sure this is the right behviour
	close(a->socket);
	a->socket=-1;
    }

    if (ret == -1) {
	a->errnum = geterror();
	a->errstr = NULL;
    } else {
	a->errnum = 0;
	a->errstr = NULL;
    }

    return ret;
}


int lo_send_message(lo_address a, const char *path, lo_message msg)
{
    return lo_send_message_from( a, NULL, path, msg );
}

int lo_send_message_from(lo_address a, lo_server from, const char *path, lo_message msg)
{
    const size_t data_len = lo_message_length(msg, path);
    char *data = lo_message_serialise(msg, path, NULL, NULL);

    // Send the message
    int ret = send_data( a, from, data, data_len );

    // Free the memory allocated by lo_message_serialise
    if (data) free( data );

    return ret;
}


int lo_send_bundle(lo_address a, lo_bundle b)
{
    return lo_send_bundle_from( a, NULL, b );
}


int lo_send_bundle_from(lo_address a, lo_server from, lo_bundle b)
{
    const size_t data_len = lo_bundle_length(b);
    char *data = lo_bundle_serialise(b, NULL, NULL);

    // Send the bundle
    int ret = send_data( a, from, data, data_len );

    // Free the memory allocated by lo_bundle_serialise
    if (data) free( data );

    return ret;
}

/* vi:set ts=8 sts=4 sw=4: */
