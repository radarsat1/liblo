/*
 *  Copyright (C) 2004 Steve Harris
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <sys/types.h>

#ifdef _MSC_VER
#define _WINSOCKAPI_
#define snprintf _snprintf
#else
#include <unistd.h>
#endif

#if defined(WIN32) || defined(_MSC_VER)
#include <winsock2.h>
#include <ws2tcpip.h>
#define EADDRINUSE WSAEADDRINUSE
#else
#include <netdb.h>
#include <sys/socket.h>
#ifdef HAVE_POLL
#include <sys/poll.h>
#endif
#include <sys/un.h>
#include <arpa/inet.h>
#endif

#if defined(WIN32) || defined(_MSC_VER)
#define geterror() WSAGetLastError()
#else
#define geterror() errno
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#include "lo_types_internal.h"
#include "lo_internal.h"
#include "lo/lo.h"
#include "lo/lo_throw.h"

#define LO_HOST_SIZE 1024

typedef struct {
    lo_timetag ts;
    char *path;
    lo_message msg;
    int sock;
    void *next;
} queued_msg_list;

struct lo_cs lo_client_sockets = { -1, -1 };

static int lo_can_coerce_spec(const char *a, const char *b);
static int lo_can_coerce(char a, char b);
static void dispatch_method(lo_server s, const char *path,
                            lo_message msg, int sock);
static int dispatch_data(lo_server s, void *data,
                         size_t size, int sock);
static int dispatch_queued(lo_server s, int dispatch_all);
static void queue_data(lo_server s, lo_timetag ts, const char *path,
                       lo_message msg, int sock);
static lo_server lo_server_new_with_proto_internal(const char *group,
                                                   const char *port,
                                                   const char *iface,
                                                   const char *ip,
                                                   int proto,
                                                   lo_err_handler err_h);
static int lo_server_join_multicast_group(lo_server s, const char *group,
                                          int family,
                                          const char *iface, const char *ip);

#if defined(WIN32) || defined(_MSC_VER)
#ifndef gai_strerror
// Copied from the Win32 SDK 

// WARNING: The gai_strerror inline functions below use static buffers,
// and hence are not thread-safe.  We'll use buffers long enough to hold
// 1k characters.  Any system error messages longer than this will be
// returned as empty strings.  However 1k should work for the error codes
// used by getaddrinfo().
#define GAI_STRERROR_BUFFER_SIZE 1024

char *WSAAPI gai_strerrorA(int ecode)
{
    DWORD dwMsgLen;
    static char buff[GAI_STRERROR_BUFFER_SIZE + 1];

    dwMsgLen = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM
                              | FORMAT_MESSAGE_IGNORE_INSERTS
                              | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                              NULL,
                              ecode,
                              MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                              (LPSTR) buff,
                              GAI_STRERROR_BUFFER_SIZE, NULL);
    return buff;
}
#endif

static int stateWSock = -1;

int initWSock()
{
    WORD reqversion;
    WSADATA wsaData;
    if (stateWSock >= 0)
        return stateWSock;
    /* TODO - which version of Winsock do we actually need? */

    reqversion = MAKEWORD(2, 2);
    if (WSAStartup(reqversion, &wsaData) != 0) {
        /* Couldn't initialize Winsock */
        stateWSock = 0;
    } else if (LOBYTE(wsaData.wVersion) != LOBYTE(reqversion) ||
               HIBYTE(wsaData.wVersion) != HIBYTE(reqversion)) {
        /* wrong version */
        WSACleanup();
        stateWSock = 0;
    } else
        stateWSock = 1;

    return stateWSock;
}

static int detect_windows_server_2003_or_later()
{
    OSVERSIONINFOEX osvi;
    DWORDLONG dwlConditionMask = 0;
    int op=VER_GREATER_EQUAL;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    osvi.dwMajorVersion = 5;
    osvi.dwMinorVersion = 2;

    VER_SET_CONDITION( dwlConditionMask, VER_MAJORVERSION, op );
    VER_SET_CONDITION( dwlConditionMask, VER_MINORVERSION, op );

    return VerifyVersionInfo(
        &osvi, 
        VER_MAJORVERSION | VER_MINORVERSION | 
        VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR,
        dwlConditionMask);
}

#endif

#ifdef ENABLE_IPV6
static unsigned int get_family_PF(const char *ip, const char *port)
{
    struct addrinfo *ai=0;
    unsigned int fam=PF_UNSPEC;
    int ret = getaddrinfo(ip, port, 0, &ai);
    if (ai) {
        if (ret==0)
            fam = ai->ai_family;
        freeaddrinfo(ai);
    }
    return fam;
}
#endif

static int lo_server_setsock_reuseaddr(lo_server s)
{
    unsigned int yes = 1;
    if (setsockopt(s->sockets[0].fd, SOL_SOCKET, SO_REUSEADDR,
                   &yes, sizeof(yes)) < 0) {
        int err = geterror();
        lo_throw(s, err, strerror(err), "setsockopt(SO_REUSEADDR)");
        return err;
    }
#ifdef SO_REUSEPORT
    if (setsockopt(s->sockets[0].fd, SOL_SOCKET, SO_REUSEPORT,
                   &yes, sizeof(yes)) < 0) {
        int err = geterror();
        lo_throw(s, err, strerror(err), "setsockopt(SO_REUSEPORT)");
        return err;
    }
#endif
    return 0;
}

lo_server lo_server_new(const char *port, lo_err_handler err_h)
{
    return lo_server_new_with_proto(port, LO_DEFAULT, err_h);
}

lo_server lo_server_new_multicast(const char *group, const char *port,
                                  lo_err_handler err_h)
{
    return lo_server_new_with_proto_internal(group, port, 0, 0, LO_UDP, err_h);
}

#if defined(WIN32) || defined(_MSC_VER) || defined(HAVE_GETIFADDRS)
lo_server lo_server_new_multicast_iface(const char *group, const char *port,
                                        const char *iface, const char *ip,
                                        lo_err_handler err_h)
{
    return lo_server_new_with_proto_internal(group, port, iface, ip, LO_UDP, err_h);
}
#endif

lo_server lo_server_new_with_proto(const char *port, int proto,
                                   lo_err_handler err_h)
{
    return lo_server_new_with_proto_internal(NULL, port, 0, 0, proto, err_h);
}

lo_server lo_server_new_with_proto_internal(const char *group,
                                            const char *port,
                                            const char *iface,
                                            const char *ip,
                                            int proto,
                                            lo_err_handler err_h)
{
    lo_server s;
    struct addrinfo *ai = NULL, *it, *used;
    struct addrinfo hints;
    int tries = 0;
    char pnum[16];
    const char *service;
    char hostname[LO_HOST_SIZE];
    int err = 0;

#if defined(WIN32) || defined(_MSC_VER)
    /* Windows Server 2003 or later (Vista, 7, etc.) must join the
     * multicast group before bind(), but Windows XP must join
     * after bind(). */
    int wins2003_or_later = detect_windows_server_2003_or_later();
#endif

    // Set real protocol, if Default is requested
    if (proto == LO_DEFAULT) {
#if !defined(WIN32) && !defined(_MSC_VER)
        if (port && *port == '/')
            proto = LO_UNIX;
        else
#endif
            proto = LO_UDP;
    }
#if defined(WIN32) || defined(_MSC_VER)
    if (!initWSock())
        return NULL;
#endif

    s = calloc(1, sizeof(struct _lo_server));
    if (!s)
        return 0;

    s->err_h = err_h;
    s->first = NULL;
    s->ai = NULL;
    s->hostname = NULL;
    s->protocol = proto;
    s->port = 0;
    s->path = NULL;
    s->queued = NULL;
    s->queue_enabled = 1;
    s->sockets_len = 1;
    s->sockets_alloc = 2;
    s->sockets = calloc(2, sizeof(*(s->sockets)));
    s->sources = (lo_address)calloc(2, sizeof(struct _lo_address));
    s->sources_len = 2;
    s->bundle_start_handler = NULL;
    s->bundle_end_handler = NULL;
    s->bundle_handler_user_data = NULL;
    s->addr_if.iface = 0;
    s->addr_if.size = 0;

    if (!s->sockets) {
        free(s);
        return 0;
    }

    s->sockets[0].fd = -1;

    memset(&hints, 0, sizeof(hints));

    if (proto == LO_UDP) {
        hints.ai_socktype = SOCK_DGRAM;
    } else if (proto == LO_TCP) {
        hints.ai_socktype = SOCK_STREAM;
    }
#if !defined(WIN32) && !defined(_MSC_VER)
    else if (proto == LO_UNIX) {

        struct sockaddr_un sa;

        s->sockets[0].fd = socket(PF_UNIX, SOCK_DGRAM, 0);
        if (s->sockets[0].fd == -1) {
            err = geterror();
            used = NULL;
            lo_throw(s, err, strerror(err), "socket()");
            lo_server_free(s);

            return NULL;
        }

        sa.sun_family = AF_UNIX;
        strncpy(sa.sun_path, port, sizeof(sa.sun_path) - 1);

        if ((bind(s->sockets[0].fd,
                  (struct sockaddr *) &sa, sizeof(sa))) < 0) {
            err = geterror();
            lo_throw(s, err, strerror(err), "bind()");

            lo_server_free(s);
            return NULL;
        }

        s->path = strdup(port);

        return s;
    }
#endif
    else {
        lo_throw(s, LO_UNKNOWNPROTO, "Unknown protocol", NULL);
        lo_server_free(s);

        return NULL;
    }

#ifdef ENABLE_IPV6
    /* Determine the address family based on provided IP string or
       multicast group, if available, otherwise let the operating
       system decide. */
    hints.ai_family = PF_INET6;
    if (ip)
        hints.ai_family = get_family_PF(ip, port);
    else if (group)
        hints.ai_family = get_family_PF(group, port);
#else
    hints.ai_family = PF_INET;
#endif
    hints.ai_flags = AI_PASSIVE;

    if (!port) {
        service = pnum;
    } else {
        service = port;
    }
    do {
        int ret;
        if (!port) {
            /* not a good way to get random numbers, but its not critical */
            snprintf(pnum, 15, "%ld", 10000 + ((unsigned int) rand() +
                                               time(NULL)) % 10000);
        }

        ret = getaddrinfo(NULL, service, &hints, &ai);
        if (ret != 0) {
            lo_throw(s, ret, gai_strerror(ret), NULL);
            lo_server_free(s);
            return NULL;
        }

        used = NULL;
        s->ai = ai;
        s->sockets[0].fd = -1;
        s->port = 0;

        for (it = ai; it && s->sockets[0].fd == -1; it = it->ai_next) {
            used = it;
            s->sockets[0].fd = socket(it->ai_family, hints.ai_socktype, 0);

            if (s->sockets[0].fd != -1
                && it->ai_family == AF_INET
                && hints.ai_socktype == SOCK_DGRAM)
            {
                int opt = 1;
                setsockopt(s->sockets[0].fd, SOL_SOCKET, SO_BROADCAST, &opt,
                           sizeof(int));
            }
        }
        if (s->sockets[0].fd == -1) {
            err = geterror();
            used = NULL;
            lo_throw(s, err, strerror(err), "socket()");

            lo_server_free(s);
            return NULL;
        }

#ifdef ENABLE_IPV6
    unsigned int v6only_off = 0;
    if (setsockopt(s->sockets[0].fd, IPPROTO_IPV6, IPV6_V6ONLY,
                   &v6only_off, sizeof(v6only_off)) < 0) {
        err = geterror();
        /* Ignore the error if the option is simply not supported. */
        if (err!=ENOPROTOOPT) {
            lo_throw(s, err, strerror(err), "setsockopt(IPV6_V6ONLY)");
            lo_server_free(s);
            return NULL;
        }
    }
#endif

        if (group != NULL
            || proto == LO_TCP)
        {
            err = lo_server_setsock_reuseaddr(s);
            if (err) {
                lo_server_free(s);
                return NULL;
            }
        }

#if defined(WIN32) || defined(_MSC_VER)
        if (wins2003_or_later)
#endif
        /* Join multicast group if specified. */
        if (group != NULL)
            if (lo_server_join_multicast_group(s, group, used->ai_family,
                                               iface, ip))
                return NULL;

        if ((used != NULL) &&
            (bind(s->sockets[0].fd, used->ai_addr, used->ai_addrlen) <
             0)) {
            err = geterror();
            if (err == EINVAL || err == EADDRINUSE) {
                used = NULL;
                continue;
            }

            lo_throw(s, err, strerror(err), "bind()");
            lo_server_free(s);

            return NULL;
        }
    } while (!used && tries++ < 16);

    if (!used) {
        lo_throw(s, LO_NOPORT, "cannot find free port", NULL);

        lo_server_free(s);
        return NULL;
    }

#if defined(WIN32) || defined(_MSC_VER)
    if (!wins2003_or_later)
    /* Join multicast group if specified. */
    if (group != NULL)
        if (lo_server_join_multicast_group(s, group, used->ai_family,
                                           iface, ip))
            return NULL;
#endif

    if (proto == LO_TCP) {
        listen(s->sockets[0].fd, 8);
    }

    if (proto == LO_UDP) {
        lo_client_sockets.udp = s->sockets[0].fd;
    } else if (proto == LO_TCP) {
        lo_client_sockets.tcp = s->sockets[0].fd;
    }

    /* Set hostname to empty string */
    hostname[0] = '\0';

#ifdef ENABLE_IPV6
    /* Try it the IPV6 friendly way first */
    for (it = ai; it; it = it->ai_next) {
        if (getnameinfo(it->ai_addr, it->ai_addrlen, hostname,
                        sizeof(hostname), NULL, 0, NI_NAMEREQD) == 0) {
            break;
        }
    }

    /* check to make sure getnameinfo() didn't just set the hostname to "::".
       Needed on Darwin. */
    if (hostname[0] == ':') {
        hostname[0] = '\0';
    }
#endif


    /* Fallback to the oldschool (i.e. more reliable) way */
    if (!hostname[0]) {
        struct hostent *he;

        gethostname(hostname, sizeof(hostname));
        he = gethostbyname(hostname);
        if (he) {
            strncpy(hostname, he->h_name, sizeof(hostname));
        }
    }

    /* soethings gone really wrong, just hope its local only */
    if (!hostname[0]) {
        strcpy(hostname, "localhost");
    }
    s->hostname = strdup(hostname);

    if (used->ai_family == PF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) used->ai_addr;

        s->port = htons(addr->sin6_port);
    } else if (used->ai_family == PF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *) used->ai_addr;

        s->port = htons(addr->sin_port);
    } else {
        lo_throw(s, LO_UNKNOWNPROTO, "unknown protocol family", NULL);
        s->port = atoi(port);
    }

    return s;
}

#if defined(WIN32) || defined(_MSC_VER) || defined(HAVE_GETIFADDRS)

static int lo_server_set_iface(lo_server s, int fam, const char *iface, const char *ip)
{
    int err = lo_inaddr_find_iface(&s->addr_if, fam, iface, ip);
    if (err)
        return err;

    if (s->addr_if.size == sizeof(struct in_addr)) {
        if (setsockopt(s->sockets[0].fd, IPPROTO_IP, IP_MULTICAST_IF,
                       &s->addr_if.a.addr, s->addr_if.size) < 0) {
            err = geterror();
            lo_throw(s, err, strerror(err), "setsockopt(IP_MULTICAST_IF)");
            lo_server_free(s);
            return err;
        }
    }
#ifdef ENABLE_IPV6
    else if (s->addr_if.size == sizeof(struct in6_addr)) {
        if (setsockopt(s->sockets[0].fd, IPPROTO_IP, IPV6_MULTICAST_IF,
                       &s->addr_if.a.addr6, s->addr_if.size) < 0) {
            err = geterror();
            lo_throw(s, err, strerror(err), "setsockopt(IPV6_MULTICAST_IF)");
            lo_server_free(s);
            return err;
        }
    }
#endif
    return 0;
}

#endif // HAVE_GETIFADDRS

int lo_server_join_multicast_group(lo_server s, const char *group,
                                   int fam, const char *iface, const char *ip)
{
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));

    // TODO ipv6 support here

    if (fam==AF_INET) {
#ifdef HAVE_INET_PTON
        if (inet_pton(AF_INET, group, &mreq.imr_multiaddr) == 0) {
            int err = geterror();
            lo_throw(s, err, strerror(err), "inet_aton()");
            lo_server_free(s);
            return err;
        }
#else
        mreq.imr_multiaddr.s_addr = inet_addr(group);
        if (mreq.imr_multiaddr.s_addr == INADDR_ANY
            || mreq.imr_multiaddr.s_addr == INADDR_NONE) {
            int err = geterror();
            lo_throw(s, err, strerror(err), "inet_addr()");
            lo_server_free(s);
            return err;
        }
#endif
    }
#if defined(WIN32) || defined(_MSC_VER) || defined(HAVE_GETIFADDRS)
    if (iface || ip) {
        int err = lo_server_set_iface(s, fam, iface, ip);
        if (err) return err;

        mreq.imr_interface = s->addr_if.a.addr;
        // TODO: the above assignment is for an in_addr, which assumes IPv4
        //       how to specify group membership interface with IPv6?
    }
    else
#endif // HAVE_GETIFADDRS
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(s->sockets[0].fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        int err = geterror();
        lo_throw(s, err, strerror(err), "setsockopt(IP_ADD_MEMBERSHIP)");
        lo_server_free(s);
        return err;
    }

    return 0;
}

void lo_server_free(lo_server s)
{
    if (s) {
        lo_method it;
        lo_method next;
        int i;

        for (i = s->sockets_len - 1; i >= 0; i--) {
            if (s->sockets[i].fd != -1) {
                if (s->protocol == LO_UDP
                    && s->sockets[i].fd == lo_client_sockets.udp) {
                    lo_client_sockets.udp = -1;
                } else if (s->protocol == LO_TCP
                           && s->sockets[i].fd == lo_client_sockets.tcp) {
                    lo_client_sockets.tcp = -1;
                }

                closesocket(s->sockets[i].fd);
                s->sockets[i].fd = -1;
            }
        }
        if (s->ai) {
            freeaddrinfo(s->ai);
            s->ai = NULL;
        }
        if (s->hostname) {
            free(s->hostname);
            s->hostname = NULL;
        }
        if (s->path) {
            if (s->protocol == LO_UNIX)
                unlink(s->path);
            free(s->path);
            s->path = NULL;
        }
        while (s->queued) {
            queued_msg_list *q = s->queued;
            free(q->path);
            lo_message_free(q->msg);
            s->queued = q->next;
            free(q);
        }
        for (it = s->first; it; it = next) {
            next = it->next;
            free((char *) it->path);
            free((char *) it->typespec);
            free(it);
        }
        if (s->addr_if.iface)
            free(s->addr_if.iface);

        for (i=0; i < s->sockets_len; i++) {
            if (s->sockets[i].fd > -1) {
#ifdef SHUT_WR
                shutdown(s->sockets[i].fd, SHUT_WR);
#endif
                closesocket(s->sockets[i].fd);
            }
        }
        free(s->sockets);

        for (i=0; i < s->sources_len; i++) {
            if (s->sources[i].host)
                lo_address_free_mem(&s->sources[i]);
        }
        free(s->sources);

        free(s);
    }
}

int lo_server_enable_queue(lo_server s, int queue_enabled,
                           int dispatch_remaining)
{
    int prev = s->queue_enabled;
    s->queue_enabled = queue_enabled;

    if (!queue_enabled && dispatch_remaining && s->queued)
        dispatch_queued(s, 1);

    return prev;
}

void *lo_server_recv_raw(lo_server s, size_t * size)
{
    char buffer[LO_MAX_MSG_SIZE];
    int ret;
    void *data = NULL;

#if defined(WIN32) || defined(_MSC_VER)
    if (!initWSock())
        return NULL;
#endif

    s->addr_len = sizeof(s->addr);

    ret = recvfrom(s->sockets[0].fd, buffer, LO_MAX_MSG_SIZE, 0,
                   (struct sockaddr *) &s->addr, &s->addr_len);
    if (ret <= 0) {
        return NULL;
    }
    data = malloc(ret);
    memcpy(data, buffer, ret);

    if (size)
        *size = ret;

    return data;
}

// From http://tools.ietf.org/html/rfc1055
#define SLIP_END        0300    /* indicates end of packet */
#define SLIP_ESC        0333    /* indicates byte stuffing */
#define SLIP_ESC_END    0334    /* ESC ESC_END means END data byte */
#define SLIP_ESC_ESC    0335    /* ESC ESC_ESC means ESC data byte */

// buffer to write to
// buffer to read from
// size of buffer to read from
// state variable needed to maintain between calls broken on ESC boundary
// location to store count of bytes read from input buffer
static int slip_decode(unsigned char *buffer, unsigned char *from,
                       int size, int *state, int *bytesread)
{
    *bytesread = 0;
    while (size--) {
        (*bytesread)++;
        switch (*state) {
        case 0:
            switch (*from) {
            case SLIP_END:
                return 0;
            case SLIP_ESC:
                *state = 1;
                continue;
            default:
                *buffer++ = *from++;
            }
            break;

        case 1:
            switch (*from) {
            case SLIP_ESC_END:
                *buffer++ = SLIP_END;
                break;
            case SLIP_ESC_ESC:
                *buffer++ = SLIP_ESC;
                break;
            }
            *state = 0;
            break;
        }
    };
    return 1;
}

static int detect_slip(unsigned char *bytes)
{
    // If stream starts with SLIP_END or with a '/', assume we are
    // looking at a SLIP stream, otherwise, first four bytes probably
    // represent a message length and we are looking at a count-prefix
    // stream.  Note that several SLIP_ENDs in a row are supposed to
    // be ignored by the SLIP protocol, but here we only handle one
    // extra one, since it may exist e.g. at the beginning of a
    // stream.
    if (bytes[0]==SLIP_END && bytes[1]=='/'
        && (isprint(bytes[2])||bytes[2]==0)
        && (isprint(bytes[3])||bytes[3]==0))
        return 1;
    if (bytes[0]=='/'
        && (isprint(bytes[1])||bytes[1]==0)
        && (isprint(bytes[2])||bytes[2]==0)
        && (isprint(bytes[3])||bytes[3]==0))
        return 1;
    if (memcmp(bytes, "#bun", 4)==0)
        return 1;
    return 0;
}

void *lo_server_recv_raw_stream(lo_server s, size_t * size, int *psock)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    int ret = 0, i;
    int32_t read_size = 0;
    char buffer[LO_MAX_MSG_SIZE];
    int bytesleft, bytesread = 0;
    void *data = NULL;
    int sock = -1;
#ifdef HAVE_SELECT
#ifndef HAVE_POLL
    fd_set ps;
    int nfds = 0;
#endif
#endif

  again:

    /* check sockets in reverse order so that already-open sockets
     * have priority.  this allows checking for closed sockets even
     * when new connections are being requested.  it also allows to
     * continue looping through the list of sockets after closing and
     * deleting a socket, since deleting sockets doesn't affect the
     * order of the array to the left of the index. */

#ifdef HAVE_POLL
    for (i = 0; i < s->sockets_len; i++) {
        s->sockets[i].events = POLLIN | POLLPRI;
        s->sockets[i].revents = 0;
    }

    poll(s->sockets, s->sockets_len, -1);

    for (i = (s->sockets_len - 1); i >= 0; --i) {
        if (s->sockets[i].revents == POLLERR
            || s->sockets[i].revents == POLLHUP) {
            if (i > 0) {
                closesocket(s->sockets[i].fd);
                lo_server_del_socket(s, i, s->sockets[i].fd);
                continue;
            } else
                return NULL;
        }
        if (s->sockets[i].revents) {
            sock = s->sockets[i].fd;

#else
#ifdef HAVE_SELECT
#if defined(WIN32) || defined(_MSC_VER)
    if (!initWSock())
        return NULL;
#endif

    nfds = 0;
    FD_ZERO(&ps);
    for (i = (s->sockets_len - 1); i >= 0; --i) {
        FD_SET(s->sockets[i].fd, &ps);
        if (s->sockets[i].fd > nfds)
            nfds = s->sockets[i].fd;
    }

    if (select(nfds + 1, &ps, NULL, NULL, NULL) == SOCKET_ERROR)
        return NULL;

    for (i = 0; i < s->sockets_len; i++) {
        if (FD_ISSET(s->sockets[i].fd, &ps)) {
            sock = s->sockets[i].fd;

#endif
#endif

            if (sock == -1)
                return NULL;

            /* zeroeth socket is listening for new connections */
            if (sock == s->sockets[0].fd) {
                sock = accept(sock, (struct sockaddr *) &addr, &addr_len);
                lo_server_add_socket(s, sock, 0, &addr, addr_len);

                /* after adding a new socket, call select()/poll()
                 * again, since we are supposed to block until a
                 * message is received. */
                goto again;
            }

            if (i < 0) {
                closesocket(sock);
                return NULL;
            }

            bytesleft = sizeof(read_size);
            while (bytesleft > 0) {
                ret = recv(sock,
                           ((char*)&read_size)+sizeof(read_size)-bytesleft,
                           bytesleft, 0);
                if (ret <= 0) {
                    closesocket(sock);
                    lo_server_del_socket(s, i, sock);
                    break;
                } else
                    bytesleft -= ret;
            }
            if (ret <= 0)
                continue;

            read_size = ntohl(read_size);

            // detect SLIP based on first 4 bytes
            int32_t sizebytes = lo_swap32(read_size);
            int slip = detect_slip((unsigned char*)&sizebytes);

            if (slip) {
                int slipstate = 0;
                unsigned char slipchar = 0, *buf=0;
                if (!slip_decode((unsigned char*)buffer,
                                 (unsigned char*)&sizebytes,
                                 sizeof(int32_t), &slipstate, &bytesread))
                {
                    // returns zero for done, error?
                    printf("error? message too short?\n");
                    continue;
                }

                // TODO: Here we read one character at a time, so as
                // not to keep a buffer between reads for each open
                // socket.  It may be preferable to do so eventually,
                // also to help handle partial recv() success.

                ret = recv(sock, &slipchar, 1, 0);
                buf = (unsigned char*)(buffer+bytesread);
                while (ret==1 && slip_decode(buf, &slipchar, 1,
                                             &slipstate, &bytesread)
                       && (buf-(unsigned char*)buffer) < LO_MAX_MSG_SIZE)
                {
                    buf += bytesread;
                    ret = recv(sock, &slipchar, 1, 0);
                }

                if (ret <= 0) {
                    closesocket(sock);
                    lo_server_del_socket(s, i, sock);
                    continue;
                }

                bytesread = buf-(unsigned char*)buffer;
            } else {
                int bytesleft = 0;

                if (read_size > LO_MAX_MSG_SIZE || ret <= 0) {
                    closesocket(sock);
                    lo_server_del_socket(s, i, sock);
                    if (ret > 0)
                        lo_throw(s, LO_TOOBIG, "Message too large", "recv()");
                    continue;
                }

                bytesleft = read_size;
                while (bytesleft > 0) {
                    ret = recv(sock, buffer+read_size-bytesleft, bytesleft, 0);
                    if (ret <= 0) {
                        closesocket(sock);
                        lo_server_del_socket(s, i, sock);
                        break;
                    } else
                        bytesleft -= ret;
                }
                if (ret <= 0)
                    continue;
                bytesread = ret;
            }

            /* end of loop over sockets: successfully read data */
            break;
        }
    }

    /* it's possible for ret==0, in the case that one of the
     * connections has been closed */
    if (ret <= 0)
        return NULL;

    data = malloc(read_size);
    memcpy(data, buffer, read_size);

    if (read_size)
        *size = read_size;

    if (psock)
        *psock = sock;

    return data;
}

int lo_server_wait(lo_server s, int timeout)
{
    int sched_timeout = lo_server_next_event_delay(s) * 1000;
    int i;
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    lo_timetag now, then;
#ifdef HAVE_SELECT
#ifndef HAVE_POLL
    fd_set ps;
    struct timeval stimeout;
#endif
#endif

#ifdef HAVE_POLL
  again:
    for (i = 0; i < s->sockets_len; i++) {
        s->sockets[i].events = POLLIN | POLLPRI | POLLERR | POLLHUP;
        s->sockets[i].revents = 0;
    }

    lo_timetag_now(&then);

    poll(s->sockets, s->sockets_len,
         timeout > sched_timeout ? sched_timeout : timeout);

    if (s->sockets[0].revents == POLLERR
        || s->sockets[0].revents == POLLHUP)
        return 0;

    // If select() was reporting a new connection on the listening
    // socket rather than a ready message, accept it and check again.
    if (s->sockets[0].revents)
    {
        if (s->protocol == LO_TCP)
        {
            int sock = accept(s->sockets[0].fd,
                              (struct sockaddr *) &addr, &addr_len);

            i = lo_server_add_socket(s, sock, 0, &addr, addr_len);
            if (i < 0)
                closesocket(sock);

            lo_timetag_now(&now);

            double diff = lo_timetag_diff(now, then);

            sched_timeout = lo_server_next_event_delay(s) * 1000;
            timeout -= (int)(diff*1000);
            if (timeout < 0) timeout = 0;

            goto again;
        }
        else {
            return 1;
        }
    }

    for (i = 1; i < s->sockets_len; i++) {
        if (s->sockets[i].revents == POLLERR
            || s->sockets[i].revents == POLLHUP)
            return 0;
        if (s->sockets[i].revents)
            return 1;
    }

    if (lo_server_next_event_delay(s) < 0.01)
        return 1;
#else
#ifdef HAVE_SELECT
    int res, to, nfds = 0;

#if defined(WIN32) || defined(_MSC_VER)
    if (!initWSock())
        return 0;
#endif

    to = timeout > sched_timeout ? sched_timeout : timeout;
    stimeout.tv_sec = to / 1000;
    stimeout.tv_usec = (to % 1000) * 1000;

  again:
    FD_ZERO(&ps);
    for (i = 0; i < s->sockets_len; i++) {
        FD_SET(s->sockets[i].fd, &ps);
        if (s->sockets[i].fd > nfds)
            nfds = s->sockets[i].fd;
    }

    lo_timetag_now(&then);
    res = select(nfds + 1, &ps, NULL, NULL, &stimeout);

    if (res == SOCKET_ERROR)
        return 0;

    if (s->protocol == LO_TCP) {
        // If select() was reporting a new connection on the listening
        // socket rather than a ready message, accept it and check again.
        if (FD_ISSET(s->sockets[0].fd, &ps)) {
            int sock = accept(s->sockets[0].fd,
                              (struct sockaddr *) &addr, &addr_len);
            double diff;
            struct timeval tvdiff;

            i = lo_server_add_socket(s, sock, 0, &addr, addr_len);
            if (i < 0)
                closesocket(sock);

            lo_timetag_now(&now);

            // Subtract time waited from total timeout
            diff = lo_timetag_diff(now, then);
            tvdiff.tv_sec = stimeout.tv_sec - (int)diff;
            tvdiff.tv_usec = stimeout.tv_usec - (diff*1000000
                                                 -(int)diff*1000000);

            // Handle underflow
            if (tvdiff.tv_usec < 0) {
                tvdiff.tv_sec -= 1;
                tvdiff.tv_usec = 1000000 + tvdiff.tv_usec;
            }
            if (tvdiff.tv_sec < 0) {
                stimeout.tv_sec = 0;
                stimeout.tv_usec = 0;
            }
            else
                stimeout = tvdiff;

            goto again;
        }
    }

    if (res || lo_server_next_event_delay(s) < 0.01)
        return 1;
#endif
#endif

    return 0;
}

int lo_server_recv_noblock(lo_server s, int timeout)
{
    int result = lo_server_wait(s, timeout);
    if (result > 0) {
        return lo_server_recv(s);
    } else {
        return 0;
    }
}

int lo_server_recv(lo_server s)
{
    void *data;
    size_t size;
    double sched_time = lo_server_next_event_delay(s);
    int sock = -1;
    int i;
#ifdef HAVE_SELECT
#ifndef HAVE_POLL
    fd_set ps;
    struct timeval stimeout;
    int res, nfds = 0;
#endif
#endif

  again:
    if (sched_time > 0.01) {
        if (sched_time > 10.0) {
            sched_time = 10.0;
        }
#ifdef HAVE_POLL
        for (i = 0; i < s->sockets_len; i++) {
            s->sockets[i].events = POLLIN | POLLPRI | POLLERR | POLLHUP;
            s->sockets[i].revents = 0;
        }

        poll(s->sockets, s->sockets_len, (int) (sched_time * 1000.0));

        for (i = 0; i < s->sockets_len; i++) {
            if (s->sockets[i].revents == POLLERR
                || s->sockets[i].revents == POLLHUP)
                return 0;

            if (s->sockets[i].revents)
                break;
        }

        if (i >= s->sockets_len) {
            sched_time = lo_server_next_event_delay(s);

            if (sched_time > 0.01)
                goto again;

            return dispatch_queued(s, 0);
        }
#else
#ifdef HAVE_SELECT
#if defined(WIN32) || defined(_MSC_VER)
        if (!initWSock())
            return 0;
#endif

        FD_ZERO(&ps);
        for (i = 0; i < s->sockets_len; i++) {
            FD_SET(s->sockets[i].fd, &ps);
            if (s->sockets[i].fd > nfds)
                nfds = s->sockets[i].fd;
        }

        stimeout.tv_sec = sched_time;
        stimeout.tv_usec = (sched_time - stimeout.tv_sec) * 1.e6;
        res = select(nfds + 1, &ps, NULL, NULL, &stimeout);
        if (res == SOCKET_ERROR) {
            return 0;
        }

        if (!res) {
            sched_time = lo_server_next_event_delay(s);

            if (sched_time > 0.01)
                goto again;

            return dispatch_queued(s, 0);
        }
#endif
#endif
    } else {
        return dispatch_queued(s, 0);
    }
    if (s->protocol == LO_TCP) {
        data = lo_server_recv_raw_stream(s, &size, &sock);
    } else {
        data = lo_server_recv_raw(s, &size);
    }

    if (!data) {
        return 0;
    }
    if (dispatch_data(s, data, size, sock) < 0) {
        free(data);
        return -1;
    }
    free(data);
    return size;
}

int lo_server_add_socket(lo_server s, int socket, lo_address a,
                         struct sockaddr_storage *addr,
                         socklen_t addr_len)
{
    /* Update array of open sockets */
    if ((s->sockets_len + 1) > s->sockets_alloc) {
        void *sp = realloc(s->sockets,
                           sizeof(*(s->sockets)) * (s->sockets_alloc * 2));
        if (!sp)
            return -1;
        s->sockets = sp;
        s->sockets_alloc *= 2;
    }

    s->sockets[s->sockets_len].fd = socket;
    s->sockets_len++;

    /* Update socket-indexed array of sources */
    if (socket >= s->sources_len) {
        int L = socket * 2;
        s->sources = realloc(s->sources,
                             sizeof(struct _lo_address) * L);
        memset(s->sources + s->sources_len, 0,
               sizeof(struct _lo_address) * (L - s->sources_len));
        s->sources_len = L;
    }

    if (a)
        lo_address_copy(&s->sources[socket], a);
    else
        lo_address_init_with_sockaddr(&s->sources[socket],
                                      addr, addr_len,
                                      socket, LO_TCP);

    return s->sockets_len - 1;
}

void lo_server_del_socket(lo_server s, int index, int socket)
{
    int i;

    if (index < 0 && socket != -1) {
        for (index = 0; index < s->sockets_len; index++)
            if (s->sockets[index].fd == socket)
                break;
    }

    if (index < 0 || index >= s->sockets_len)
        return;

    lo_address_free_mem(&s->sources[s->sockets[index].fd]);

    for (i = index + 1; i < s->sockets_len; i++)
        s->sockets[i - 1] = s->sockets[i];
    s->sockets_len--;
}

static int dispatch_data(lo_server s, void *data,
                         size_t size, int sock)
{
    int result = 0;
    char *path = data;
    ssize_t len = lo_validate_string(data, size);
    if (len < 0) {
        lo_throw(s, -len, "Invalid message path", NULL);
        return len;
    }

    if (!strcmp(data, "#bundle")) {
        char *pos;
        int remain;
        uint32_t elem_len;
        lo_timetag ts, now;

        ssize_t bundle_result = lo_validate_bundle(data, size);
        if (bundle_result < 0) {
            lo_throw(s, -bundle_result, "Invalid bundle", NULL);
            return bundle_result;
        }
        pos = (char *) data + len;
        remain = size - len;

        lo_timetag_now(&now);
        ts.sec = lo_otoh32(*((uint32_t *) pos));
        pos += 4;
        ts.frac = lo_otoh32(*((uint32_t *) pos));
        pos += 4;
        remain -= 8;

        if (s->bundle_start_handler)
            s->bundle_start_handler(ts, s->bundle_handler_user_data);

        while (remain >= 4) {
            lo_message msg;
            elem_len = lo_otoh32(*((uint32_t *) pos));
            pos += 4;
            remain -= 4;

            if (!strcmp(pos, "#bundle")) {
                dispatch_data(s, pos, elem_len, sock);
            } else {
                msg = lo_message_deserialise(pos, elem_len, &result);
                if (!msg) {
                    lo_throw(s, result, "Invalid bundle element received",
                             path);
                    return -result;
                }
                // set timetag from bundle
                msg->ts = ts;

                // test for immediate dispatch
                if ((ts.sec == LO_TT_IMMEDIATE.sec
                     && ts.frac == LO_TT_IMMEDIATE.frac)
                    || lo_timetag_diff(ts, now) <= 0.0
                    || !s->queue_enabled)
                {
                    dispatch_method(s, pos, msg, sock);
                    lo_message_free(msg);
                } else {
                    queue_data(s, ts, pos, msg, sock);
                }
            }

            pos += elem_len;
            remain -= elem_len;
        }

        if (s->bundle_end_handler)
            s->bundle_end_handler(s->bundle_handler_user_data);

    } else {
        lo_message msg = lo_message_deserialise(data, size, &result);
        if (NULL == msg) {
            lo_throw(s, result, "Invalid message received", path);
            return -result;
        }
        dispatch_method(s, data, msg, sock);
        lo_message_free(msg);
    }
    return size;
}

int lo_server_dispatch_data(lo_server s, void *data, size_t size)
{
    return dispatch_data(s, data, size, -1);
}

/* returns the time in seconds until the next scheduled event */
double lo_server_next_event_delay(lo_server s)
{
    if (s->queued) {
        lo_timetag now;
        double delay;

        lo_timetag_now(&now);
        delay = lo_timetag_diff(((queued_msg_list *) s->queued)->ts, now);

        delay = delay > 100.0 ? 100.0 : delay;
        delay = delay < 0.0 ? 0.0 : delay;

        return delay;
    }

    return 100.0;
}

static void dispatch_method(lo_server s, const char *path,
                            lo_message msg, int sock)
{
    char *types = msg->types + 1;
    int argc = strlen(types);
    lo_method it;
    int ret = 1;
    int err;
    int pattern = strpbrk(path, " #*,?[]{}") != NULL;
    lo_address src = 0;
    char hostname[LO_HOST_SIZE];
    char portname[32];
    const char *pptr;

    //inet_ntop(s->addr.ss_family, &s->addr.padding, hostname, sizeof(hostname));
    if (s->protocol == LO_UDP && s->addr_len > 0) {
        err = getnameinfo((struct sockaddr *) &s->addr, s->addr_len,
                          hostname, sizeof(hostname), portname,
                          sizeof(portname),
                          NI_NUMERICHOST | NI_NUMERICSERV);
        if (err) {
            switch (err) {
            case EAI_AGAIN:
                lo_throw(s, err, "Try again", path);
                break;
            case EAI_BADFLAGS:
                lo_throw(s, err, "Bad flags", path);
                break;
            case EAI_FAIL:
                lo_throw(s, err, "Failed", path);
                break;
            case EAI_FAMILY:
                lo_throw(s, err, "Cannot resolve address family", path);
                break;
            case EAI_MEMORY:
                lo_throw(s, err, "Out of memory", path);
                break;
            case EAI_NONAME:
                lo_throw(s, err, "Cannot resolve", path);
                break;
#if !defined(WIN32) && !defined(_MSC_VER)
            case EAI_SYSTEM:
                lo_throw(s, err, strerror(err), path);
                break;
#endif
            default:
                lo_throw(s, err, "Unknown error", path);
                break;
            }

            return;
        }
    } else {
        hostname[0] = '\0';
        portname[0] = '\0';
    }


    // Store the source information in the lo_address
    if (s->protocol == LO_TCP && sock >= 0) {
        msg->source = &s->sources[sock];
    }
    else {
        src = lo_address_new(NULL, NULL);
        msg->source = src;
        if (src->host)
            free(src->host);
        if (src->host)
            free(src->port);
        src->host = strdup(hostname);
        src->port = strdup(portname);
        src->protocol = s->protocol;
    }

    for (it = s->first; it; it = it->next) {
        /* If paths match or handler is wildcard */
        if (!it->path || !strcmp(path, it->path) ||
            (pattern && lo_pattern_match(it->path, path))) {
            /* If types match or handler is wildcard */
            if (!it->typespec || !strcmp(types, it->typespec)) {
                /* Send wildcard path to generic handler, expanded path
                   to others.
                 */
                pptr = path;
                if (it->path)
                    pptr = it->path;
                ret = it->handler(pptr, types, msg->argv, argc, msg,
                                  it->user_data);

            } else if (lo_can_coerce_spec(types, it->typespec)) {
                int i;
                int opsize = 0;
                char *ptr = msg->data;
                char *data_co = NULL, *data_co_ptr = NULL;

                lo_arg **argv = calloc(argc, sizeof(lo_arg *));
                for (i = 0; i < argc; i++) {
                    opsize += lo_arg_size(it->typespec[i], ptr);
                    ptr += lo_arg_size(types[i], ptr);
                }

                if (opsize > 0) {
                    data_co = malloc(opsize);
                    data_co_ptr = data_co;
                    ptr = msg->data;
                }
                for (i = 0; i < argc; i++) {
                    argv[i] = (lo_arg *) data_co_ptr;
                    lo_coerce(it->typespec[i], (lo_arg *) data_co_ptr,
                              types[i], (lo_arg *) ptr);
                    data_co_ptr +=
                        lo_arg_size(it->typespec[i], data_co_ptr);
                    ptr += lo_arg_size(types[i], ptr);
                }

                /* Send wildcard path to generic handler, expanded path
                   to others.
                 */
                pptr = path;
                if (it->path)
                    pptr = it->path;
                ret = it->handler(pptr, it->typespec, argv, argc, msg,
                                  it->user_data);
                if (data_co) {
                    free(data_co);
                }
                free(argv);
                argv = NULL;
            }

            if (ret == 0 && !pattern) {
                break;
            }
        }
    }

    /* If we find no matching methods, check for protocol level stuff */
    if (ret == 1 && s->protocol == LO_UDP) {
        char *pos = strrchr(path, '/');

        /* if its a method enumeration call */
        if (pos && *(pos + 1) == '\0') {
            lo_message reply = lo_message_new();
            int len = strlen(path);
            lo_strlist *sl = NULL, *slit, *slnew, *slend;

            lo_arg **argv = msg->argv;
            if (!strcmp(types, "i") && argv != NULL) {
                lo_message_add_int32(reply, argv[0]->i);
            }
            lo_message_add_string(reply, path);

            for (it = s->first; it; it = it->next) {
                /* If paths match */
                if (it->path && !strncmp(path, it->path, len)) {
                    char *tmp;
                    char *sec;

                    tmp = malloc(strlen(it->path + len) + 1);
                    strcpy(tmp, it->path + len);
#if defined(WIN32) || defined(_MSC_VER)
                    sec = strchr(tmp, '/');
#else
                    sec = index(tmp, '/');
#endif
                    if (sec)
                        *sec = '\0';
                    slend = sl;
                    for (slit = sl; slit; slend = slit, slit = slit->next) {
                        if (!strcmp(slit->str, tmp)) {
                            free(tmp);
                            tmp = NULL;
                            break;
                        }
                    }
                    if (tmp) {
                        slnew = calloc(1, sizeof(lo_strlist));
                        slnew->str = tmp;
                        slnew->next = NULL;
                        if (!slend) {
                            sl = slnew;
                        } else {
                            slend->next = slnew;
                        }
                    }
                }
            }

            slit = sl;
            while (slit) {
                lo_message_add_string(reply, slit->str);
                slnew = slit;
                slit = slit->next;
                free(slnew->str);
                free(slnew);
            }
            lo_send_message(src, "#reply", reply);
            lo_message_free(reply);
        }
    }

    if (src) lo_address_free(src);
    msg->source = NULL;
}

int lo_server_events_pending(lo_server s)
{
    return s->queued != 0;
}

static void queue_data(lo_server s, lo_timetag ts, const char *path,
                       lo_message msg, int sock)
{
    /* insert blob into future dispatch queue */
    queued_msg_list *it = s->queued;
    queued_msg_list *prev = NULL;
    queued_msg_list *ins = calloc(1, sizeof(queued_msg_list));

    ins->ts = ts;
    ins->path = strdup(path);
    ins->msg = msg;
    ins->sock = sock;

    while (it) {
        if (lo_timetag_diff(it->ts, ts) > 0.0) {
            if (prev) {
                prev->next = ins;
            } else {
                s->queued = ins;
                ins->next = NULL;
            }
            ins->next = it;

            return;
        }
        prev = it;
        it = it->next;
    }

    /* fell through, so this event is last */
    if (prev) {
        prev->next = ins;
    } else {
        s->queued = ins;
    }
    ins->next = NULL;
}

static int dispatch_queued(lo_server s, int dispatch_all)
{
    queued_msg_list *head = s->queued;
    queued_msg_list *tailhead;
    lo_timetag disp_time;

    if (!head) {
        lo_throw(s, LO_INT_ERR, "attempted to dispatch with empty queue",
                 "timeout");
        return 1;
    }

    disp_time = head->ts;

    do {
        char *path;
        lo_message msg;
        int sock;
        tailhead = head->next;
        path = ((queued_msg_list *) s->queued)->path;
        msg = ((queued_msg_list *) s->queued)->msg;
        sock = ((queued_msg_list *) s->queued)->sock;
        dispatch_method(s, path, msg, sock);
        free(path);
        lo_message_free(msg);
        free((queued_msg_list *) s->queued);

        s->queued = tailhead;
        head = tailhead;
    } while ((head && lo_timetag_diff(head->ts, disp_time) < FLT_EPSILON)
             || dispatch_all);

    return 0;
}

lo_method lo_server_add_method(lo_server s, const char *path,
                               const char *typespec, lo_method_handler h,
                               void *user_data)
{
    lo_method m = calloc(1, sizeof(struct _lo_method));
    lo_method it;

    if (path && strpbrk(path, " #*,?[]{}")) {
        return NULL;
    }

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
        for (it = s->first; it->next; it = it->next);
        it->next = m;
    }

    return m;
}

void lo_server_del_method(lo_server s, const char *path,
                          const char *typespec)
{
    lo_method it, prev, next;
    int pattern = 0;

    if (!s->first)
        return;
    if (path)
        pattern = strpbrk(path, " #*,?[]{}") != NULL;

    it = s->first;
    prev = it;
    while (it) {
        /* incase we free it */
        next = it->next;

        /* If paths match or handler is wildcard */
        if ((it->path == path) ||
            (path && it->path && !strcmp(path, it->path)) ||
            (pattern && it->path && lo_pattern_match(it->path, path))) {
            /* If types match or handler is wildcard */
            if ((it->typespec == typespec) ||
                (typespec && it->typespec
                 && !strcmp(typespec, it->typespec))
                ) {
                /* Take care when removing the head. */
                if (it == s->first) {
                    s->first = it->next;
                } else {
                    prev->next = it->next;
                }
                next = it->next;
                free((void *) it->path);
                free((void *) it->typespec);
                free(it);
                it = prev;
            }
        }
        prev = it;
        if (it)
            it = next;
    }
}

int lo_server_add_bundle_handlers(lo_server s,
                                  lo_bundle_start_handler sh,
                                  lo_bundle_end_handler eh,
                                  void *user_data)
{
    s->bundle_start_handler = sh;
    s->bundle_end_handler = eh;
    s->bundle_handler_user_data = user_data;
    return 0;
}

int lo_server_get_socket_fd(lo_server s)
{
    if (s->protocol != LO_UDP && s->protocol != LO_TCP
#if !defined(WIN32) && !defined(_MSC_VER)
        && s->protocol != LO_UNIX
#endif
        ) {
        return -1;              /* assume it is not supported */
    }
    return s->sockets[0].fd;
}

int lo_server_get_port(lo_server s)
{
    if (!s) {
        return 0;
    }

    return s->port;
}

int lo_server_get_protocol(lo_server s)
{
    if (!s) {
        return -1;
    }

    return s->protocol;
}


char *lo_server_get_url(lo_server s)
{
    int ret = 0;
    char *buf;

    if (!s) {
        return NULL;
    }

    if (s->protocol == LO_UDP || s->protocol == LO_TCP) {
        const char *proto = s->protocol == LO_UDP ? "udp" : "tcp";

#ifndef _MSC_VER
        ret =
            snprintf(NULL, 0, "osc.%s://%s:%d/", proto, s->hostname,
                     s->port);
#endif
        if (ret <= 0) {
            /* this libc is not C99 compliant, guess a size */
            ret = 1023;
        }
        buf = malloc((ret + 2) * sizeof(char));
        snprintf(buf, ret + 1, "osc.%s://%s:%d/", proto, s->hostname,
                 s->port);

        return buf;
    }
#if !defined(WIN32) && !defined(_MSC_VER)
    else if (s->protocol == LO_UNIX) {
        ret = snprintf(NULL, 0, "osc.unix:///%s", s->path);
        if (ret <= 0) {
            /* this libc is not C99 compliant, guess a size */
            ret = 1023;
        }
        buf = malloc((ret + 2) * sizeof(char));
        snprintf(buf, ret + 1, "osc.unix:///%s", s->path);

        return buf;
    }
#endif
    return NULL;
}

void lo_server_pp(lo_server s)
{
    lo_method it;

    printf("socket: %d\n\n", s->sockets[0].fd);
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

    for (i = 0; a[i]; i++) {
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
            (lo_is_string_type(a) && lo_is_string_type(b)));
}

void lo_throw(lo_server s, int errnum, const char *message,
              const char *path)
{
    if (s->err_h) {
        (*s->err_h) (errnum, message, path);
    }
}

/* vi:set ts=8 sts=4 sw=4: */
