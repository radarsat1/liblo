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
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/un.h>

#include "lo_types_internal.h"
#include "lo/lo.h"
#include "lo/lo_throw.h"

#define LO_HOST_SIZE 1024

static int lo_can_coerce_spec(const char *a, const char *b);
static int lo_can_coerce(char a, char b);
static void dispatch_method(lo_server s, const char *path, char *types,
			    void *data);

lo_server lo_server_new(const char *port, lo_err_handler err_h)
{
    if (port && *port == '/') {
	return lo_server_new_with_proto(port, LO_UNIX, err_h);
    } else {
	return lo_server_new_with_proto(port, LO_UDP, err_h);
    }
}

lo_server lo_server_new_with_proto(const char *port, int proto,
				   lo_err_handler err_h)
{
    lo_server s = malloc(sizeof(struct _lo_server));
    struct addrinfo *ai = NULL, *it, *used;
    struct addrinfo hints;
    int ret = -1;
    int tries = 0;
    char pnum[16];
    const char *service;
    char hostname[LO_HOST_SIZE];

    s->err_h = err_h;
    s->first = NULL;
    s->ai = NULL;
    s->hostname = NULL;
    s->protocol = proto;
    s->port = 0;
    s->path = NULL;

    if (proto == LO_UDP) {
	hints.ai_socktype = SOCK_DGRAM;
    } else if (proto == LO_TCP) {
	hints.ai_socktype = SOCK_STREAM;
    } else if (proto == LO_UNIX) {
	struct sockaddr_un sa;

	s->socket = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s->socket == -1) {
	    used = NULL;
	    lo_throw(s, errno, strerror(errno), "socket()");
	    lo_server_free(s);

	    return NULL;
	}

	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, port, 107);

	if ((ret = bind(s->socket, (struct sockaddr *)&sa, sizeof(sa))) < 0) {
	    lo_throw(s, errno, strerror(errno), "bind()");

	    lo_server_free(s);
	    return NULL;
	}

	s->path = strdup(port);

	return s;
    } else {
	lo_throw(s, LO_UNKNOWNPROTO, "Unknown protocol", NULL);
	lo_server_free(s);

	return NULL;
    }

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;
    hints.ai_protocol = 0;
    hints.ai_addrlen = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    if (!port) {
	service = pnum;
    } else {
	service = port;
    }
    do {
	if (!port) {
	    /* not a good way to get random numbers, but its not critical */
	    snprintf(pnum, 15, "%d", 10000 + rand() % 10000);
	}

	if (ai) {
	    freeaddrinfo(ai);
	}

	if ((ret = getaddrinfo(NULL, service, &hints, &ai))) {
	    lo_throw(s, ret, gai_strerror(ret), NULL);
	    freeaddrinfo(ai);

	    return NULL;
	}

	used = NULL;
	s->ai = ai;
	s->socket = -1;
	s->port = 0;

	for (it = ai; it && s->socket == -1; it = it->ai_next) {
	    used = it;
	    s->socket = socket(it->ai_family, hints.ai_socktype, 0);
	}
	if (s->socket == -1) {
	    used = NULL;
	    lo_throw(s, errno, strerror(errno), "socket()");

	    lo_server_free(s);
	    return NULL;
	}

	if ((ret = bind(s->socket, used->ai_addr, used->ai_addrlen)) < 0) {
	    if (errno == EINVAL || errno == EADDRINUSE) {
		used = NULL;

		continue;
	    }
	    lo_throw(s, errno, strerror(errno), "bind()");

	    lo_server_free(s);
	    return NULL;
	}
    } while (!used && tries++ < 16);

    if (proto == LO_TCP) {
	listen(s->socket, 8);
    }

    if (!used) {
	lo_throw(s, LO_NOPORT, "cannot find free port", NULL);

	lo_server_free(s);
	return NULL;
    }

    /* Try it the IPV6 friendly way first */
    hostname[0] = '\0';
    for (it = ai; it; it = it->ai_next) {
	if (getnameinfo(it->ai_addr, it->ai_addrlen, hostname,
			sizeof(hostname), NULL, 0, NI_NAMEREQD) == 0) {
	    break;
	}
    }

    /* Fallback to the oldschool (i.e. reliable) way */
    if (!hostname[0]) {
	struct hostent *he;

	gethostname(hostname, sizeof(hostname));
	he = gethostbyname(hostname);
	strncpy(hostname, he->h_name, sizeof(hostname));
    }

    /* soethings gone really wrong, just hope its local only */
    if (!hostname[0]) {
	strcpy(hostname, "localhost");
    }
    s->hostname = strdup(hostname);

    if (used->ai_family == PF_INET6) {
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *)used->ai_addr;

	s->port = htons(addr->sin6_port);
    } else if (used->ai_family == PF_INET) {
	struct sockaddr_in *addr = (struct sockaddr_in *)used->ai_addr;

	s->port = htons(addr->sin_port);
    } else {
	lo_throw(s, LO_UNKNOWNPROTO, "unknown protocol family", NULL);
	s->port = atoi(port);
    }

    return s;
}

void lo_server_free(lo_server s)
{
    if (s) {
	lo_method it;
	lo_method next;

	freeaddrinfo(s->ai);
	free(s->hostname);
	free(s->path);
	for (it = s->first; it; it = next) {
	    next = it->next;
	    free((char *)it->path);
	    free((char *)it->typespec);
	    free(it);
	}
	free(s);
    }
}

void *lo_server_recv_raw(lo_server s, size_t *size)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    char buffer[LO_MAX_MSG_SIZE];
    int ret;
    void *data = NULL;

    ret = recvfrom(s->socket, buffer, LO_MAX_MSG_SIZE, 0,
		  (struct sockaddr *)&addr, &addr_len);
    if (ret <= 0) {
	return NULL;
    }
    data = malloc(ret);
    memcpy(data, buffer, ret);

    if (size) *size = ret;

    return data;
}

void *lo_server_recv_raw_stream(lo_server s, size_t *size)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    char buffer[LO_MAX_MSG_SIZE];
    int32_t read_size;
    int ret;
    void *data = NULL;
    struct pollfd ps;
    int sock;

    ps.fd = s->socket;
    ps.events = POLLIN | POLLPRI;
    ps.revents = 0;
    poll(&ps, 1, -1);
    sock = accept(s->socket, (struct sockaddr *)&addr, &addr_len);

    ret = recv(sock, &read_size, sizeof(read_size), 0);
    read_size = ntohl(read_size);
    if (read_size > LO_MAX_MSG_SIZE) {
	close(sock);
	lo_throw(s, LO_TOOBIG, "Message too large", "recv()");

	return NULL;
    }
    ret = recv(sock, buffer, read_size, 0);
    //close(sock);
    if (ret <= 0) {
	return NULL;
    }
    data = malloc(ret);
    memcpy(data, buffer, ret);

    if (size) *size = ret;

    return data;
}

int lo_server_recv_noblock(lo_server s, int timeout)
{
    struct pollfd ps;

    ps.fd = s->socket;
    ps.events = POLLIN | POLLPRI;
    ps.revents = 0;
    poll(&ps, 1, timeout);
    if (ps.revents) {
	return lo_server_recv(s);
    }

    return 0;
}

int lo_server_recv(lo_server s)
{
    void *data;
    size_t size;
    char *path;
    char *types;

    if (s->protocol == LO_TCP) {
	data = lo_server_recv_raw_stream(s, &size);
    } else {
	data = lo_server_recv_raw(s, &size);
    }

    if (!data) {
	return 0;
    }
    path = data;

    types = data + lo_strsize(path);
    if (!strcmp(path, "#bundle")) {
printf("bundle XXXXXXXXXXXX %s XXXXXXXXXXXXXXXXXXXX\n", types);
	free(data);

	return size;
    } else if (*types != ',') {
	lo_throw(s, LO_ENOTYPE, "Missing typetag", path);

	return -1;
    }

    dispatch_method(s, path, types+1, data);

    free(data);

    return size;
}

static void dispatch_method(lo_server s, const char *path, char *types,
			    void *data)
{
    int argc = strlen(types);
    lo_arg **argv = NULL;
    lo_method it;
    int ret = 1;
    int endian_fixed = 0;

    for (it = s->first; it; it = it->next) {
	/* If paths match or handler is wildcard */
	if (!it->path || !strcmp(path, it->path)) {
	    /* If types match or handler is wildcard */
	    if (!it->typespec || !strcmp(types, it->typespec)) {

		if (!argv && *types) {
		    int i;
		    char *ptr = types - 1 + lo_strsize(types - 1);

		    argv = calloc(argc+1, sizeof(lo_arg *));
		    if (!endian_fixed) {
			for (i=0; i<argc; i++) {
			    argv[i] = (lo_arg *)ptr;
			    lo_arg_host_endian(types[i], ptr);
			    ptr += lo_arg_size(types[i], ptr);
			}
			endian_fixed = 1;
		    }
		}

		ret = it->handler(path, types, argv, argc, data,
				      it->user_data);

	    } else if (lo_can_coerce_spec(types, it->typespec)) {
		int i;
		int opsize = 0;
		char *ptr = types - 1 + lo_strsize(types - 1);
		char *data_co, *data_co_ptr;

		argv = calloc(argc+1, sizeof(lo_arg *));
		for (i=0; i<argc; i++) {
		    opsize += lo_arg_size(it->typespec[i], ptr);
		    ptr += lo_arg_size(types[i], ptr);
		}

		data_co = malloc(opsize);
		data_co_ptr = data_co;
		ptr = types - 1 + lo_strsize(types - 1);
		for (i=0; i<argc; i++) {
		    argv[i] = (lo_arg *)data_co_ptr;
		    if (!endian_fixed) {
			lo_arg_host_endian(types[i], ptr);
		    }
		    lo_coerce(it->typespec[i], (lo_arg *)data_co_ptr,
			      types[i], (lo_arg *)ptr);
		    data_co_ptr += lo_arg_size(it->typespec[i], data_co_ptr);
		    ptr += lo_arg_size(types[i], ptr);
		}
		endian_fixed = 1;

		ret = it->handler(path, it->typespec, argv, argc, NULL,
				      it->user_data);
		free(argv);
		free(data_co);
		argv = NULL;
	    }
	    if (ret == 0) {
		break;
	    }
	}
    }
    free(argv);
}

lo_method lo_server_add_method(lo_server s, const char *path,
			       const char *typespec, lo_method_handler h,
			       void *user_data)
{
    lo_method m = calloc(1, sizeof(struct _lo_method));
    lo_method it;

    if (path) {
	m->path = strdup(path);
    } else {
	m->path = NULL;
    }

    if (typespec) {
	m->typespec = strdup(typespec);
    } else {
	m->typespec = NULL;
    }

    m->handler = h;
    m->user_data = user_data;
    m->next = NULL;

    /* append the new method to the list */
    if (!s->first) {
	s->first = m;
    } else {
	/* get to the last member of the list */
	for (it=s->first; it->next; it=it->next);
	it->next = m;
    }

    return m;
}

int lo_server_get_socket_fd(lo_server s)
{
    if (s->protocol != LO_UDP &&
        s->protocol != LO_TCP &&
        s->protocol != LO_UNIX) {
        return -1;  /* assume it is not supported */
    }
    return s->socket;
}

int lo_server_get_port(lo_server s)
{
    if (!s) {
	return 0;
    }

    return s->port;
}

char *lo_server_get_url(lo_server s)
{
    int ret;
    char *buf;

    if (!s) {
	return NULL;
    }

    if (s->protocol == LO_UDP || s->protocol == LO_TCP) {
	char *proto = s->protocol == LO_UDP ? "udp" : "tcp";

	ret = snprintf(NULL, 0, "osc.%s://%s:%d/", proto, s->hostname, s->port);
	if (ret <= 0) {
	    /* this libc is not C99 compliant, guess a size */
	    ret = 1023;
	}
	buf = malloc((ret + 2) * sizeof(char));
	snprintf(buf, ret+1, "osc.%s://%s:%d/", proto, s->hostname, s->port);

	return buf;
    } else if (s->protocol == LO_UNIX) {
	ret = snprintf(NULL, 0, "osc.unix:///%s", s->path);
	if (ret <= 0) {
	    /* this libc is not C99 compliant, guess a size */
	    ret = 1023;
	}
	buf = malloc((ret + 2) * sizeof(char));
	snprintf(buf, ret+1, "osc.unix:///%s", s->path);

	return buf;
    }

    return NULL;
}

void lo_throw(lo_server s, int errnum, const char *message, const char *path)
{
    if (s->err_h) {
	(*s->err_h)(errnum, message, path);
    }
}

void lo_server_pp(lo_server s)
{
    lo_method it;

    printf("socket: %d\n\n", s->socket);
    printf("Methods\n");
    for (it = s->first; it; it = it->next) {
	printf("\n");
	lo_method_pp_prefix(it, "   ");
    }
}

static int lo_can_coerce_spec(const char *a, const char *b)
{
    unsigned int i;

    if (strlen(a) != strlen(b)) {
	return 0;
    }

    for (i=0; a[i]; i++) {
	if (!lo_can_coerce(a[i], b[i])) {
	    return 0;
	}
    }

    return 1;
}

static int lo_can_coerce(char a, char b)
{
    return ((a == b) ||
           (lo_is_numerical_type(a) && lo_is_numerical_type(b)) ||
           (lo_is_string_type(a) && lo_is_string_type (b)));
}

/* vi:set ts=8 sts=4 sw=4: */
