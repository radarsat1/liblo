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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#endif

#include "lo_types_internal.h"
#include "lo/lo.h"
#include "config.h"

lo_address lo_address_new(const char *host, const char *port)
{
    lo_address a = calloc(1, sizeof(struct _lo_address));

    a->ai = NULL;
    a->proto = LO_UDP;
    if (host) {
	a->host = strdup(host);
    } else {
	a->host = strdup("localhost");
    }

    if (port) {
	a->port = strdup(port);
    } else {
	a->port = NULL;
    }

    return a;
}

lo_address lo_address_new_from_url(const char *url)
{
    lo_address a;
    char *protocol;

    if (!url || !*url) {
	return NULL;
    }

    a = calloc(1, sizeof(struct _lo_address));
    protocol = lo_url_get_protocol(url);
    if (!protocol) {
	return NULL;
    } else if (!strcmp(protocol, "udp")) {
	a->proto = LO_UDP;
	a->port = lo_url_get_port(url);
    } else if (!strcmp(protocol, "tcp")) {
	a->proto = LO_TCP;
	a->port = lo_url_get_port(url);
#ifndef WIN32
    } else if (!strcmp(protocol, "unix")) {
	a->proto = LO_UNIX;
	a->port = lo_url_get_path(url);
#endif
    } else {
	fprintf(stderr, PACKAGE_NAME ": protocol '%s' not supported by this "
	        "version\n", protocol);
	free(a);
	free(protocol);

	return NULL;
    }
    free(protocol);

    a->ai = NULL;
    a->host = lo_url_get_hostname(url);
    if (!a->host) {
	a->host = strdup("localhost");
    }

    return a;
}

const char *lo_address_get_hostname(lo_address a)
{
    return a->host;
}

const char *lo_address_get_port(lo_address a)
{
    return a->port;
}

char *lo_address_get_url(lo_address a)
{
    char *buf;
    int ret;
    int needquote = (int)(strchr(a->host, ':'));
    char *fmt;

    if (needquote) {
	fmt = "osc.%s://[%s]:%s/";
    } else {
	fmt = "osc.%s://%s:%s/";
    }
    ret = snprintf(NULL, 0, fmt, "udp", a->host, a->port);
    if (ret <= 0) {
	/* this libc is not C99 compliant, guess a size */
	ret = 1023;
    }
    buf = malloc((ret + 2) * sizeof(char));
    snprintf(buf, ret+1, fmt, "udp", a->host, a->port);

    return buf;
}

void lo_address_free(lo_address a)
{
    if (a) {
	free(a->host);
	free(a->port);
	if (a->ai && a->ai != (void *)1) {
	    freeaddrinfo(a->ai);
	}
	free(a);
    }
}

int lo_address_errno(lo_address a)
{
    return a->errnum;
}

const char *lo_address_errstr(lo_address a)
{
    char *msg;

    if (a->errstr) {
	return a->errstr;
    }

    msg = strerror(a->errnum);
    if (msg) {
	return msg;
    } else {
	return "unknown error";
    }

    return "unknown error";
}

char *lo_url_get_protocol(const char *url)
{
    char *protocol,*ret;


    if (!url) {
	return NULL;
    }

#ifdef WIN32
    protocol = malloc(strlen(url));
#else
    protocol = alloca(strlen(url));
#endif

    if (sscanf(url, "osc://%s", protocol)) {
	fprintf(stderr, PACKAGE_NAME " warning: no protocol specified in URL, "
		"assuming UDP.\n");
        ret = strdup("udp");
    }
    else if (sscanf(url, "osc.%[^:/]", protocol)) {
        ret = strdup(protocol);
    }
    else
        ret = NULL;

#ifdef WIN32
    free(protocol);
#endif
    return ret;
}

char *lo_url_get_hostname(const char *url)
{
    char *hostname = malloc(strlen(url));

    if (sscanf(url, "osc://%[^[:/]", hostname)) {
        return hostname;
    }
    if (sscanf(url, "osc.%*[^:/]://[%[^]/]]", hostname)) {
        return hostname;
    }
    if (sscanf(url, "osc.%*[^:/]://%[^[:/]", hostname)) {
        return hostname;
    }

    /* doesnt look like an OSC URL */
    free(hostname);

    return NULL;
}

char *lo_url_get_port(const char *url)
{
    char *port = malloc(strlen(url));

    if (sscanf(url, "osc://%*[^:]:%[0-9]", port)) {
        return port;
    }
    if (sscanf(url, "osc.%*[^:]://%*[^:]:%[0-9]", port)) {
        return port;
    }

    /* doesnt look like an OSC URL with port number */
    free(port);

    return NULL;
}

char *lo_url_get_path(const char *url)
{
    char *path = malloc(strlen(url));

    if (sscanf(url, "osc://%*[^:]:%*[0-9]%s", path)) {
        return path;
    }
    if (sscanf(url, "osc.%*[^:]://%*[^:]:%*[0-9]%s", path) == 1) {
        return path;
    }
    if (sscanf(url, "osc.%*[^:]://%s", path)) {
        return path;
    }

    /* doesnt look like an OSC URL with port number and path*/
    return NULL;
}

/* vi:set ts=8 sts=4 sw=4: */
