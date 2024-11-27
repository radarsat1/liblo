/*
 *  Copyright (C) 2014 Steve Harris et al. (see AUTHORS)
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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>

#ifdef _MSC_VER
#define _WINSOCKAPI_
#define snprintf _snprintf
#else
#include <unistd.h>
#include <sys/time.h>
#endif

#if defined(WIN32) || defined(_MSC_VER)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <malloc.h>
// TODO: Does this make sense on any platform? At least mingw defines
// both EADDRINUSE and WSAEADDRINUSE and the values differ. We need to
// check for WSAEADDRINUSE though on Windows.
#ifndef EADDRINUSE
#define EADDRINUSE WSAEADDRINUSE
#endif
#else
#include <netdb.h>
#include <sys/socket.h>
#ifdef HAVE_POLL
#include <poll.h>
#endif
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif
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
#include "lo/lo_lowlevel.h"
#include "lo/lo_throw.h"

typedef struct {
    lo_timetag ts;
    char *path;
    lo_message msg;
    int sock;
    void *next;
} queued_msg_list;

struct lo_cs lo_client_sockets = { -1, -1 };
static int reuseport_supported = 1;

static int lo_can_coerce_spec(const char *a, const char *b);
static int lo_can_coerce(char a, char b);
static int lo_servers_wait_internal(lo_server *s, int *recvd,
                                    int *queued, int num_servers,
                                    int timeout);
static int lo_server_recv_internal(lo_server s);
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
                                                   lo_err_handler err_h,
                                                   void *err_h_context);
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

static int lo_server_setsock_reuseaddr(lo_server s, int do_throw)
{
    unsigned int yes = 1;
    if (setsockopt(s->sockets[0].fd, SOL_SOCKET, SO_REUSEADDR,
                   (char*)&yes, sizeof(yes)) < 0) {
        int err = geterror();
		if (do_throw)
			lo_throw(s, err, strerror(err), "setsockopt(SO_REUSEADDR)");
        return err;
    }
    return 0;
}

static int lo_server_setsock_reuseport(lo_server s, int do_throw)
{
#ifdef SO_REUSEPORT
    unsigned int yes = 1;
    if (setsockopt(s->sockets[0].fd, SOL_SOCKET, SO_REUSEPORT,
                   &yes, sizeof(yes)) < 0) {
        int err = geterror();
		if (do_throw)
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
    return lo_server_new_with_proto_internal(group, port, 0, 0, LO_UDP, err_h, 0);
}

#if defined(WIN32) || defined(_MSC_VER) || defined(HAVE_GETIFADDRS)
lo_server lo_server_new_multicast_iface(const char *group, const char *port,
                                        const char *iface, const char *ip,
                                        lo_err_handler err_h)
{
    return lo_server_new_with_proto_internal(group, port, iface, ip, LO_UDP, err_h, 0);
}
#endif

lo_server lo_server_new_with_proto(const char *port, int proto,
                                   lo_err_handler err_h)
{
    return lo_server_new_with_proto_internal(NULL, port, 0, 0, proto, err_h, 0);
}

lo_server lo_server_new_from_url(const char *url,
                                 lo_err_handler err_h)
{
    lo_server s;
    int protocol;
    char *group, *port, *proto;

    if (!url || !*url) {
        return NULL;
    }

    protocol = lo_url_get_protocol_id(url);
    if (protocol == LO_UDP || protocol == LO_TCP) {
        group = lo_url_get_hostname(url);
        port = lo_url_get_port(url);
        s = lo_server_new_with_proto_internal(group, port, 0, 0,
                                              protocol, err_h, 0);
        if (group)
            free(group);
        if (port)
            free(port);
#if !defined(WIN32) && !defined(_MSC_VER)
    } else if (protocol == LO_UNIX) {
        port = lo_url_get_path(url);
        s = lo_server_new_with_proto_internal(0, port, 0, 0,
                                              LO_UNIX, err_h, 0);
        if (port)
            free(port);
#endif
    } else {
        proto = lo_url_get_protocol(url);
        fprintf(stderr,
                PACKAGE_NAME ": protocol '%s' not supported by this "
                "version\n", proto);
        if (proto)
            free(proto);

        return NULL;
    }

    return s;
}

lo_server lo_server_new_from_config(lo_server_config *config)
{
    if (config->size < sizeof(lo_server_config))
        return NULL;

    return lo_server_new_with_proto_internal(config->group,
                                             config->port,
                                             config->iface,
                                             config->ip,
                                             config->proto,
                                             config->err_handler,
                                             config->err_handler_context);
}

static
void lo_server_resolve_hostname(lo_server s)
{
    char hostname[LO_HOST_SIZE];

    /* Set hostname to empty string */
    hostname[0] = '\0';

#if defined(ENABLE_IPV6) && defined(HAVE_GETIFADDRS)
    /* Try it the IPV6 friendly way first */
    do {
        struct ifaddrs *ifa, *ifa_list;
        if (getifaddrs(&ifa_list))
            break;
        ifa = ifa_list;

        while (ifa) {
            if (!ifa->ifa_addr) {
                ifa = ifa->ifa_next;
                continue;
            }

            if (s->addr_if.iface) {
                if (s->addr_if.size == sizeof(struct in_addr)
                    && (ifa->ifa_addr->sa_family == AF_INET))
                {
                    struct sockaddr_in *sin = (struct sockaddr_in*)ifa->ifa_addr;
                    if (memcmp(&sin->sin_addr, &s->addr_if.a.addr, sizeof(struct in_addr))!=0
                        || (s->addr_if.iface && ifa->ifa_name
                            && strcmp(s->addr_if.iface, ifa->ifa_name)!=0))
                    {
                        ifa = ifa->ifa_next;
                        continue;
                    }
                }
                else if (s->addr_if.size == sizeof(struct in6_addr)
                         && (ifa->ifa_addr->sa_family == AF_INET6))
                {
                    struct sockaddr_in6 *sin = (struct sockaddr_in6*)ifa->ifa_addr;
                    if (memcmp(&sin->sin6_addr, &s->addr_if.a.addr6,
                               sizeof(struct in6_addr))!=0
                        || (s->addr_if.iface && ifa->ifa_name
                            && strcmp(s->addr_if.iface, ifa->ifa_name)!=0))
                    {
                        ifa = ifa->ifa_next;
                        continue;
                    }
                }
            }

            if ((ifa->ifa_addr->sa_family == AF_INET
                 && (!s->addr_if.iface || s->addr_if.size == sizeof(struct in_addr))
                 && (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), hostname,
                                 sizeof(hostname), NULL, 0, NI_NAMEREQD) == 0))
                || (ifa->ifa_addr->sa_family == AF_INET6
                    && (!s->addr_if.iface || s->addr_if.size == sizeof(struct in6_addr))
                    && (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), hostname,
                                    sizeof(hostname), NULL, 0, NI_NAMEREQD) == 0)))
            {
                /* check to make sure getnameinfo() didn't just set the hostname to "::".
                   Needed on Darwin. */
                if (hostname[0] == ':')
                    hostname[0] = '\0';
                else if (strcmp(hostname, "localhost")==0)
                    hostname[0] = '\0';
                else
                    break;
            }
            ifa = ifa->ifa_next;
        }

        freeifaddrs(ifa_list);
    }
    while (0);
#endif

    /* Fallback to the oldschool (i.e. more reliable) way */
    if (!hostname[0]) {
        struct hostent *he;

        gethostname(hostname, sizeof(hostname));
        he = gethostbyname(hostname);
        if (he) {
            strncpy(hostname, he->h_name, sizeof(hostname) - 1);
        }
    }

    /* somethings gone really wrong, just hope its local only */
    if (!hostname[0]) {
        strcpy(hostname, "localhost");
    }

    s->hostname = strdup(hostname);
}

#if defined(WIN32) || defined(_MSC_VER) || defined(HAVE_GETIFADDRS)

static int lo_server_set_iface(lo_server s, int fam, const char *iface, const char *ip)
{
    int err = lo_inaddr_find_iface(&s->addr_if, fam, iface, ip);
    if (err)
        return err;

    if (s->addr_if.size == sizeof(struct in_addr)) {
        if (setsockopt(s->sockets[0].fd, IPPROTO_IP, IP_MULTICAST_IF,
                       (const char*)&s->addr_if.a.addr, (socklen_t) s->addr_if.size) < 0)
		{
            err = geterror();
            lo_throw(s, err, strerror(err), "setsockopt(IP_MULTICAST_IF)");
            return err;
        }
    }
#ifdef ENABLE_IPV6 // TODO: this setsockopt fails on linux
    else if (s->addr_if.size == sizeof(struct in6_addr)) {
        if (setsockopt(s->sockets[0].fd, IPPROTO_IP, IPV6_MULTICAST_IF,
                       &s->addr_if.a.addr6, (socklen_t) s->addr_if.size) < 0) {
            err = geterror();
            lo_throw(s, err, strerror(err), "setsockopt(IPV6_MULTICAST_IF)");
            return err;
        }
    }
#endif
    return 0;
}

#endif // HAVE_GETIFADDRS

lo_server lo_server_new_with_proto_internal(const char *group,
                                            const char *port,
                                            const char *iface,
                                            const char *ip,
                                            int proto,
                                            lo_err_handler err_h,
                                            void *err_h_context)
{
    lo_server s;
    struct addrinfo *ai = NULL, *it, *used;
    struct addrinfo hints;
    int tries = 0;
    char pnum[16];
    const char *service;
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

    s = (lo_server) calloc(1, sizeof(struct _lo_server));
    if (!s)
        return 0;

    s->err_h = err_h;
    s->error_user_data = err_h_context;
    s->first = NULL;
    s->ai = NULL;
    s->hostname = NULL;
    s->protocol = proto;
    s->flags = (lo_server_flags) LO_SERVER_DEFAULT_FLAGS;
    s->port = 0;
    s->path = NULL;
    s->queued = NULL;
    s->sockets_len = 1;
    s->sockets_alloc = 2;
    s->sockets = (lo_server_fd_type *) calloc(2, sizeof(*(s->sockets)));
    s->contexts = (struct socket_context *) calloc(2, sizeof(*(s->contexts)));
    s->sources = (lo_address)calloc(2, sizeof(struct _lo_address));
    s->sources_len = 2;
    s->bundle_start_handler = NULL;
    s->bundle_end_handler = NULL;
    s->bundle_handler_user_data = NULL;
    s->addr_if.iface = 0;
    s->addr_if.size = 0;

    if (!(s->sockets && s->contexts && s->sources)) {
        free(s->sockets);
        free(s->contexts);
        free(s->sources);
        free(s);
        return 0;
    }

    s->sockets[0].fd = -1;
    s->max_msg_size = LO_DEFAULT_MAX_MSG_SIZE;

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
                                               (long int)time(NULL)) % 10000);
        }

        if (ai)
            freeaddrinfo(ai);

        ret = getaddrinfo(NULL, service, &hints, &ai);

        s->ai = ai;
        s->sockets[0].fd = -1;
        s->port = 0;

        if (ret != 0) {
            lo_throw(s, ret, gai_strerror(ret), NULL);
            lo_server_free(s);
            return NULL;
        }

        used = NULL;

        for (it = ai; it && s->sockets[0].fd == -1; it = it->ai_next) {
            used = it;
            s->sockets[0].fd = socket(it->ai_family, hints.ai_socktype, 0);

            if (s->sockets[0].fd != -1
                && it->ai_family == AF_INET
                && hints.ai_socktype == SOCK_DGRAM)
            {
                int opt = 1;
                setsockopt(s->sockets[0].fd, SOL_SOCKET, SO_BROADCAST,
						   (char*)&opt, sizeof(int));
                setsockopt(s->sockets[0].fd, IPPROTO_IP, IP_MULTICAST_LOOP,
                           (char*)&opt, sizeof(int));
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
            err = lo_server_setsock_reuseaddr(s, 1);
            if (err) {
                lo_server_free(s);
                return NULL;
            }
        }

        if (group != NULL && reuseport_supported)
        {
            /* Ignore the error if SO_REUSEPORT wasn't successful. */
            if (lo_server_setsock_reuseport(s, 0))
				reuseport_supported = 0;
        }

#if defined(WIN32) || defined(_MSC_VER)
        if (wins2003_or_later)
#endif
	{
        /* Join multicast group if specified. */
        if (group != NULL) {
            if (lo_server_join_multicast_group(s, group, used->ai_family,
                                               iface, ip))
                return NULL;
        } else {
#if defined(WIN32) || defined(_MSC_VER) || defined(HAVE_GETIFADDRS)
             if ((iface || ip)
                 && lo_inaddr_find_iface(&s->addr_if, used->ai_family, iface, ip))
             {
                 used = NULL;
                 continue;
             }
#endif
        }}

        if ((used != NULL) &&
            (bind(s->sockets[0].fd, used->ai_addr, used->ai_addrlen) <
             0)) {
            err = geterror();
#ifdef WIN32
            if (err == WSAEINVAL || err == WSAEADDRINUSE) {
#else
            if (err == EINVAL || err == EADDRINUSE) {
#endif
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

    if (used->ai_family == PF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) used->ai_addr;
        s->port = ntohs(addr->sin6_port);
    } else if (used->ai_family == PF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *) used->ai_addr;
        s->port = ntohs(addr->sin_port);
    } else {
        lo_throw(s, LO_UNKNOWNPROTO, "unknown protocol family", NULL);
        s->port = atoi(port);
    }

    return s;
}

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
            return err ? err : 1;
        }
#else
        mreq.imr_multiaddr.s_addr = inet_addr(group);
        if (mreq.imr_multiaddr.s_addr == INADDR_ANY
            || mreq.imr_multiaddr.s_addr == INADDR_NONE) {
            int err = geterror();
            lo_throw(s, err, strerror(err), "inet_addr()");
            lo_server_free(s);
            return err ? err : 1;
        }
#endif
    }
#if defined(WIN32) || defined(_MSC_VER) || defined(HAVE_GETIFADDRS)
    if (iface || ip) {
        int err = lo_server_set_iface(s, fam, iface, ip);
        if (err) {
          lo_server_free(s);
          return err;
        }

        mreq.imr_interface = s->addr_if.a.addr;
        // TODO: the above assignment is for an in_addr, which assumes IPv4
        //       how to specify group membership interface with IPv6?
    }
    else
#endif // HAVE_GETIFADDRS
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(s->sockets[0].fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (char*)&mreq, sizeof(mreq)) < 0) {
        int err = geterror();
        lo_throw(s, err, strerror(err), "setsockopt(IP_ADD_MEMBERSHIP)");
        lo_server_free(s);
        return err ? err : 1;
    }

    return 0;
}

int lo_server_enable_coercion(lo_server s, int enable)
{
    int r = (s->flags & LO_SERVER_COERCE) != 0;
    s->flags = (lo_server_flags)
        ((s->flags & ~LO_SERVER_COERCE)
         | (enable ? LO_SERVER_COERCE : 0));
    return r;
}

int lo_server_should_coerce_args(lo_server s)
{
    return (s->flags & LO_SERVER_COERCE) != 0;
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
            queued_msg_list *q = (queued_msg_list *) s->queued;
            free(q->path);
            lo_message_free(q->msg);
            s->queued = q->next;
            free(q);
        }
        for (it = s->first; it; it = next) {
            next = it->next;
            free((char*) it->path);
            free((char*) it->typespec);
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
            if (s->contexts[i].buffer)
                free(s->contexts[i].buffer);
        }
        free(s->sockets);
        free(s->contexts);

        for (i=0; i < s->sources_len; i++) {
            if (s->sources[i].host)
                lo_address_free_mem(&s->sources[i]);
        }
        free(s->sources);

        free(s);
    }
}

int lo_server_enable_queue(lo_server s, int enable,
                           int dispatch_remaining)
{
    int prev = (s->flags & LO_SERVER_ENQUEUE) != 0;
    s->flags = (lo_server_flags)
        ((s->flags & ~LO_SERVER_ENQUEUE)
         | (enable ? LO_SERVER_ENQUEUE : 0));

    if (!enable && dispatch_remaining && s->queued)
        dispatch_queued(s, 1);

    return prev;
}

static
void *lo_server_recv_raw(lo_server s, size_t * size)
{
    char *buffer = NULL;
    int ret, heap_buffer = 0;
    void *data = NULL;

#if defined(WIN32) || defined(_MSC_VER)
    if (!initWSock()) {
        return NULL;
    }
#endif

    if (s->max_msg_size<=0) {
        return NULL;
    }
    else if (s->max_msg_size > 4096) {
        // TODO: can we use a static buffer here instead?
        buffer = (char*) malloc(s->max_msg_size);
        heap_buffer = 1;
    }
    else {
        buffer = (char*) alloca(s->max_msg_size);
    }

    if (!buffer)
        return NULL;

    s->addr_len = sizeof(s->addr);

    ret = (int) recvfrom(s->sockets[0].fd, buffer, s->max_msg_size, 0,
                         (struct sockaddr *) &s->addr, &s->addr_len);
    if (ret <= 0) {
        if (heap_buffer) free(buffer);
        return NULL;
    }
    data = malloc(ret);
    memcpy(data, buffer, ret);

    if (size)
        *size = ret;

    if (heap_buffer) free(buffer);
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
static int slip_decode(unsigned char **buffer, unsigned char *from,
                       size_t size, int *state, size_t *bytesread)
{
    assert(from != NULL);
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
                from++;
                continue;
            default:
                *(*buffer)++ = *from++;
            }
            break;

        case 1:
            switch (*from) {
            case SLIP_ESC_END:
                *(*buffer)++ = SLIP_END;
                from++;
                break;
            case SLIP_ESC_ESC:
                *(*buffer)++ = SLIP_ESC;
                from++;
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

static
void init_context(struct socket_context *sc)
{
    sc->is_slip = -1;
    sc->buffer = 0;
    sc->buffer_size = 0;
    sc->buffer_msg_offset = 0;
    sc->buffer_read_offset = 0;
}

static
void cleanup_context(struct socket_context *sc)
{
    if (sc->buffer)
        free(sc->buffer);
    memset(sc, 0, sizeof(struct socket_context));
}

/*! \internal Return message length if a whole message is waiting in
 *  the socket's buffer, or 0 otherwise. */
static
uint32_t lo_server_buffer_contains_msg(lo_server s, int isock)
{
    struct socket_context *sc = &s->contexts[isock];
    if (sc->buffer_read_offset <= sizeof(uint32_t))
        return 0;

    uint32_t msg_len = ntohl(*(uint32_t*)sc->buffer);
    char *str = (char*)(sc->buffer + sizeof(uint32_t));
    if (str[0] != '/' && str[0] != '#')
    {
        // invalid message
        goto clear_buffer;
    }
    if (msg_len + sizeof(uint32_t) > sc->buffer_read_offset)
    {
        // still waiting for the rest of message
        return 0;
    }
    if (msg_len && lo_validate_string(str, msg_len) < 0)
        goto clear_buffer;
    return msg_len;

clear_buffer:
    sc->buffer_read_offset = sc->buffer_msg_offset = 0;
    return 0;
}

/*! \internal Copy received data into buffer, return pointer to
 *  message if buffer contains a complete message. */
static
void *lo_server_buffer_copy_for_dispatch(lo_server s, int isock, size_t *psize)
{
    void *data;
    struct socket_context *sc = &s->contexts[isock];
    uint32_t msg_len = lo_server_buffer_contains_msg(s, isock);
    if (msg_len == 0)
        return NULL;

    data = malloc(msg_len);
    memcpy(data, sc->buffer + sizeof(uint32_t), msg_len);
    *psize = msg_len;

    sc->buffer_read_offset -= msg_len + sizeof(uint32_t);
    sc->buffer_msg_offset -= msg_len + sizeof(uint32_t);

    // Move any left-over data to the beginning of the buffer to
    // make room for the next read.
    if (sc->buffer_read_offset > 0)
        memmove(sc->buffer,
                sc->buffer + msg_len + sizeof(uint32_t),
                sc->buffer_read_offset);

    return data;
}

/*! \internal This is called when a socket in the list is ready for
 *  recv'ing, previously checked by poll() or select(). */
static
int lo_server_recv_raw_stream_socket(lo_server s, int isock,
                                     size_t *psize, void **pdata)
{
    struct socket_context *sc = &s->contexts[isock];
    char *stack_buffer = 0, *read_into;
    uint32_t msg_len;
	int buffer_bytes_left, bytes_recv;
	ssize_t bytes_written, size;
    *pdata = 0;

  again:

    buffer_bytes_left = (int) (sc->buffer_size - sc->buffer_read_offset);

    // If we need more than half the buffer, double the buffer size.
    size = sc->buffer_size;
    if (size < 64)
        size = 64;
    while (buffer_bytes_left < size/2)
    {
        size *= 2;

        // Strictly speaking this is an arbitrary limit and could be
        // removed for TCP, since there is no upper limit on packet
        // size as in UDP, however we leave it for security
        // reasons--an unterminated SLIP stream would consume memory
        // indefinitely.
        if (s->max_msg_size != -1 && size > s->max_msg_size) {
            size = s->max_msg_size;
            break;
        }

        buffer_bytes_left = (int) (size - sc->buffer_read_offset);
    }

    if ((size_t)size > sc->buffer_size)
    {
        sc->buffer_size = size;
        sc->buffer = (char*) realloc(sc->buffer, sc->buffer_size);
        if (!sc->buffer) {
            // Out of memory
            return 0;
        }
    }

    // Read as much as we can into the remaining buffer memory.
    buffer_bytes_left = (int) (sc->buffer_size - sc->buffer_read_offset);

    read_into = sc->buffer + sc->buffer_read_offset;

    // In SLIP mode, we instead read into the local stack buffer
    if (sc->is_slip == 1)
    {
        stack_buffer = (char*) alloca(buffer_bytes_left - sizeof(uint32_t));
        read_into = stack_buffer;
    }

    bytes_recv = (int) recv(s->sockets[isock].fd,
                            read_into,
                            buffer_bytes_left, 0);

    if (bytes_recv <= 0)
    {
        if (errno == EAGAIN)
            return 0;

        // Error, or socket was closed.
        // Either way, we remove it from the server.
        closesocket(s->sockets[isock].fd);
        lo_server_del_socket(s, isock, s->sockets[isock].fd);
        return 0;
    }

    // If unknown, check whether we are in a SLIP stream.
    if (sc->is_slip == -1 && (sc->buffer_read_offset + bytes_recv) >= 4) {
        sc->is_slip = detect_slip((unsigned char*)(sc->buffer
												   + sc->buffer_msg_offset));
        sc->slip_state = 0;

        // Copy to stack if we just discovered we are in SLIP mode
        if (sc->is_slip)
        {
            stack_buffer = (char*) alloca(bytes_recv);
            memcpy(stack_buffer, read_into, bytes_recv);

            // Make room for size header
            *(uint32_t*)(sc->buffer + sc->buffer_read_offset) = 0;
            sc->buffer_read_offset += sizeof(uint32_t);
        }
    }

    if (sc->is_slip == 1)
    {
        // For SLIP, copy the read data into stack memory and decode
        // it back to the buffer.  We will leave enough room to
        // prepend a count prefix, and let the count-prefix code
        // handle it below.

        // Note for future: Actually we could dispatch it right here
        // instead of allocating and copying it to a buffer, but the
        // lo_server_recv() semantics require that we handle only 1
        // message at a time, so we are forced to leave undispatched
        // messages in the buffer for later.

        size_t bytes_read = 0;

        // Need to provide a mutable pointer to track how much memory
        // was written to the buffer by the SLIP decoder.
        char *buffer_after = sc->buffer + sc->buffer_read_offset;

        // As long as we find whole messages, dispatch them.
        while (slip_decode((unsigned char**)&buffer_after,
						   (unsigned char*)stack_buffer, bytes_recv,
                           &sc->slip_state, &bytes_read) == 0)
        {
            // We have a whole message in the buffer.
            size_t bytes_written = buffer_after - sc->buffer - sc->buffer_read_offset;

            sc->buffer_read_offset += bytes_written;

            msg_len = sc->buffer_read_offset - sc->buffer_msg_offset - sizeof(uint32_t);

            // Skip empty messages, for instance for when sender is double-ENDing SLIP
            if (msg_len)
            {
                // Store message length header
                *(uint32_t*)(sc->buffer + sc->buffer_msg_offset) = htonl(msg_len);

                // Advance to next message and zero the message length header
                sc->buffer_msg_offset += msg_len + sizeof(uint32_t);
                sc->buffer_read_offset += sizeof(uint32_t);
                buffer_after += sizeof(uint32_t);
                *(uint32_t*)(sc->buffer + sc->buffer_msg_offset) = 0;
            }

            // Update how much memory still needs decoding.
            bytes_recv -= bytes_read;
            stack_buffer += bytes_read;

            // We could exceed buffer due to prepending the count
            // prefix, so if we need more buffer room, allocate it.
            if (bytes_recv + sizeof(uint32_t) > sc->buffer_size - sc->buffer_read_offset)
            {
                sc->buffer_size *= 2;
                sc->buffer = (char*)  realloc(sc->buffer, sc->buffer_size);
                buffer_after = sc->buffer + sc->buffer_read_offset;
            }
        }

        // Any data left over is left in the buffer, so update the
        // read offset to indicate the end of it.
        bytes_written = buffer_after - sc->buffer - sc->buffer_read_offset;
        sc->buffer_read_offset += bytes_written;
    }
    else
    {
        sc->buffer_read_offset += bytes_recv;
    }

    *pdata = lo_server_buffer_copy_for_dispatch(s, isock, psize);

    if (!*pdata && bytes_recv == buffer_bytes_left)
    {
        // There could be more data, try recv() again.  This is okay
        // because we set the O_NONBLOCK flag.
        goto again;
    }

    // We need to inform the caller whether there may be data left
    // to read, which is true if we read exactly as much as we
    // asked for.
    return bytes_recv == buffer_bytes_left;
}

static
void *lo_server_recv_raw_stream(lo_server s, size_t * size, int *psock)
{
    int i;
    void *data = NULL;
    int sock = -1;

    assert(psock != NULL);

#ifndef HAVE_POLL
#ifdef HAVE_SELECT
#if defined(WIN32) || defined(_MSC_VER)
    if (!initWSock())
        return NULL;
#endif
#endif
#endif

    /* check sockets in reverse order so that already-open sockets
     * have priority.  this allows checking for closed sockets even
     * when new connections are being requested.  it also allows to
     * continue looping through the list of sockets after closing and
     * deleting a socket, since deleting sockets doesn't affect the
     * order of the array to the left of the index. */

    for (i = s->sockets_len - 1; i >= 0 && !data; i--) {
        if (s->sockets[i].revents) {
            sock = s->sockets[i].fd;
            if (sock == -1)
                return NULL;

            /* Handle incoming socket data */
            if (lo_server_recv_raw_stream_socket(s, i, size, &data)
                && !data)
            {
                // There could be more data waiting
                //*more = 1;
            }
            if (data)
                *psock = s->sockets[i].fd;
        }
    }

    *psock = sock;
    return data;
}

int lo_server_wait(lo_server s, int timeout)
{
    int recvd, queued;
    return lo_servers_wait_internal(&s, &recvd, &queued, 1, timeout);
}

int lo_servers_wait(lo_server *s, int *status, int num_servers, int timeout)
{
    int *recvd = status ? status : alloca(sizeof(int) * num_servers);
    int *queued = alloca(sizeof(int) * num_servers);
    int ret = lo_servers_wait_internal(s, recvd, queued, num_servers, timeout);
    if (status) {
        int i;
        for (i = 0; i < num_servers; i++)
            status[i] |= queued[i];
    }
    return ret;
}

static
int lo_servers_wait_internal(lo_server *s, int *recvd, int *queued, int num_servers, int timeout)
{
    int i, j, k, res, sched_timeout;
    assert(recvd && queued);

    for (i = 0; i < num_servers; i++)
        recvd[i] = queued[i] = 0;

    lo_timetag now, then;
#ifdef HAVE_SELECT
#ifndef HAVE_POLL
    fd_set ps;
    struct timeval stimeout;
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
#endif
#endif

    lo_timetag_now(&then);

#ifdef HAVE_POLL
    socklen_t addr_len = sizeof(struct sockaddr_storage);
    struct sockaddr_storage *addr = alloca (addr_len * num_servers);
    int num_sockets;

  again:
    num_sockets = 0;
    for (j = 0, k = 0; j < num_servers; j++) {
        for (i = 0; i < s[j]->sockets_len; i++) {
            if (lo_server_buffer_contains_msg(s[j], i)) {
                recvd[j] = 1;
                ++k;
                break;
            }
            ++num_sockets;
        }
    }

    // Return immediately if one or more servers already have messages waiting.
    if (k > 0) {
        return k;
    }

    struct pollfd *sockets = alloca(sizeof(struct pollfd) * num_sockets);

    sched_timeout = timeout;
    for (j = 0, k = 0; j < num_servers; j++) {
        for (i = 0; i < s[j]->sockets_len; i++) {
            sockets[k].fd = s[j]->sockets[i].fd;
            sockets[k].events = POLLIN | POLLPRI | POLLERR | POLLHUP;
            sockets[k].revents = s[j]->sockets[i].revents = 0;
            ++k;
        }
        int server_timeout = lo_server_next_event_delay(s[j]) * 1000;
        if (server_timeout < sched_timeout)
            sched_timeout = server_timeout;
    }

    res = poll(sockets, num_sockets, sched_timeout);

    if (res == -1)
        return -1;
    else if (res) {
        for (j = 0, k = 0; j < num_servers; j++) {
            if (s[j]->protocol == LO_TCP) {
                if (sockets[k].revents & (POLLIN | POLLPRI)) {
                    // If poll() was reporting a new connection on the listening
                    // socket rather than a ready message, accept it and check again.
                    int sock = accept(sockets[k].fd, (struct sockaddr *) &addr[j],
                                      &addr_len);

                    i = lo_server_add_socket(s[j], sock, 0, &addr[j], addr_len);
                    if (i < 0)
                        closesocket(sock);

                    lo_timetag_now(&now);

                    double diff = lo_timetag_diff(now, then);

                    timeout -= (int)(diff*1000);
                    if (timeout < 0)
                        timeout = 0;

                    goto again;
                }
                sockets[k].revents = 0;

                /* check sockets in reverse order so that already-open sockets
                 * have priority.  this allows checking for closed sockets even
                 * when new connections are being requested.  it also allows to
                 * continue looping through the list of sockets after closing and
                 * deleting a socket, since deleting sockets doesn't affect the
                 * order of the array to the left of the index. */

                for (i = s[j]->sockets_len - 1, k += i; i > 0; i--, k--) {
                    if (!sockets[k].revents)
                        continue;
                    if (sockets[k].revents & (POLLERR | POLLHUP)) {
                        closesocket(sockets[k].fd);
                        lo_server_del_socket(s[j], i, sockets[k].fd);
                        s[j]->sockets[i].revents = 0;
                    }
                    else {
                        s[j]->sockets[i].revents = POLLIN;
                        recvd[j] = 1;
                    }
                }
            }
            else {
                if (sockets[k].revents) {
                    s[j]->sockets[0].revents = POLLIN;
                    recvd[j] = 1;
                }
                ++k;
            }
        }
    }
#else
#ifdef HAVE_SELECT
    int to, num_fds;

#if defined(WIN32) || defined(_MSC_VER)
    if (!initWSock()) {
        return -1;
    }
#endif

  again:
    num_fds = 0;
    for (j = 0, k = 0; j < num_servers; j++) {
        for (i = 0; i < s[j]->sockets_len; i++) {
            if (lo_server_buffer_contains_msg(s[j], i)) {
                recvd[j] = 1;
                ++k;
                break;
            }
        }
    }

    // Return immediately if one or more servers already have messages waiting.
    if (k > 0)
        return k;

    sched_timeout = timeout;
    for (j = 0; j < num_servers; j++) {
        int server_timeout = lo_server_next_event_delay(s[j]) * 1000;
        if (server_timeout < sched_timeout)
            sched_timeout = server_timeout;
    }

    to = timeout > sched_timeout ? sched_timeout : timeout;
    stimeout.tv_sec = to / 1000;
    stimeout.tv_usec = (to % 1000) * 1000;

    FD_ZERO(&ps);
    for (j = 0; j < num_servers; j++) {
        for (i = 0; i < s[j]->sockets_len; i++) {
            s[j]->sockets[i].revents = 0;
            FD_SET(s[j]->sockets[i].fd, &ps);
#ifndef WIN32
            if (s[j]->sockets[i].fd > num_fds)
                num_fds = s[j]->sockets[i].fd;
#endif
        }
    }

    res = select(num_fds + 1, &ps, NULL, NULL, &stimeout);

    if (res == SOCKET_ERROR)
        return -1;
    else if (res) {
        for (j = 0; j < num_servers; j++) {
            if (FD_ISSET(s[j]->sockets[0].fd, &ps)) {
                // If select() was reporting a new connection on the listening
                // socket rather than a ready message, accept it and check again.
                if (s[j]->protocol == LO_TCP) {
                    int sock = accept(s[j]->sockets[0].fd,
                                      (struct sockaddr *) &addr, &addr_len);
                    double diff;
                    struct timeval tvdiff;

                    i = lo_server_add_socket(s[j], sock, 0, &addr, addr_len);
                    if (i < 0)
                        closesocket(sock);

                    lo_timetag_now(&now);

                    // Subtract time waited from total timeout
                    diff = lo_timetag_diff(now, then);
                    tvdiff.tv_sec = stimeout.tv_sec - (int)diff;
                    tvdiff.tv_usec = stimeout.tv_usec - (diff * 1000000
                                                         - (int)diff * 1000000);

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

                    timeout -= (int)(diff*1000);
                    if (timeout < 0)
                        timeout = 0;

                    goto again;
                }
                else {
                    s[j]->sockets[0].revents = POLLIN;
                    recvd[j] = 1;
                }
            }
            for (i = 1; i < s[j]->sockets_len; i++) {
                if (FD_ISSET(s[j]->sockets[i].fd, &ps)) {
                    s[j]->sockets[i].revents = POLLIN;
                    recvd[j] = 1;
                }
            }
        }
    }
#endif
#endif

    for (j = 0; j < num_servers; j++) {
        if (lo_server_next_event_delay(s[j]) < 0.01) {
            queued[j] = 1;
        }
    }

    for (i = 0, j = 0; i < num_servers; i++)
        j += (recvd[i] | queued[i]);

    return j;
}

int lo_servers_recv_noblock(lo_server *s, int *recvd, int num_servers,
                            int timeout)
{
    int i, total_bytes = 0;
    int *queued = alloca(sizeof(int) * num_servers);
    if (!recvd)
        recvd = alloca(sizeof(int) * num_servers);

    lo_timetag then;
    lo_timetag_now(&then);

again:
    if (lo_servers_wait_internal(s, recvd, queued, num_servers, timeout) > 0) {
        for (i = 0; i < num_servers; i++) {
            // a new message might be queued for future dispatch, in which case
            // any queued messages that are ready should take precedence
            if (recvd[i] && (recvd[i] = lo_server_recv_internal(s[i])) > 0) {
                // new message was received and dispatched
                total_bytes += recvd[i];
            }
            else if (queued[i]) {
                // queued message is ready for dispatch
                recvd[i] = dispatch_queued(s[i], 0);
                total_bytes += recvd[i];
            }
        }
        if (!total_bytes) {
            // we need to keep waiting if no received or queued messages are ready for dispatch
            lo_timetag now;
            lo_timetag_now(&now);
            double diff = lo_timetag_diff(now, then);
            timeout -= (int)(diff*1000);
            if (timeout > 2) {
                goto again;
            }
        }
    }
    return total_bytes;
}

int lo_server_recv_noblock(lo_server s, int timeout)
{
    return lo_servers_recv_noblock(&s, NULL, 1, timeout);
}

int lo_server_recv(lo_server s)
{
    int ret, recvd, queued;
    while ((ret = lo_servers_wait_internal(&s, &recvd, &queued, 1, 100)) == 0) {}
    if (ret > 0) {
        // new messages might be queued for future dispatch, in which case any queued msgs that are ready should take precedence
        if (recvd && (ret = lo_server_recv_internal(s))) {
            // new message was received and dispatched
            return ret;
        }
        else if (queued) {
            // queued message is ready for dispatch
            return dispatch_queued(s, 0);
        }
    }
    return 0;
}

// This function only handles incoming data, not previously queued messages
static
int lo_server_recv_internal(lo_server s)
{
    void *data;
    size_t size;
    int sock = -1;
    int i = 0;

    if (s->protocol == LO_TCP) {
        for (i = s->sockets_len - 1; i >= 0; i--) {
            // first check if there are additional messages in the buffer
            if ((data = lo_server_buffer_copy_for_dispatch(s, i, &size))) {
                sock = s->sockets[i].fd;
                goto got_data;
            }
            if (s->sockets[i].revents)
                break;
        }
        data = lo_server_recv_raw_stream(s, &size, &sock);
    }
    else {
        data = lo_server_recv_raw(s, &size);
    }

    if (!data) {
        return 0;
    }

  got_data:
    i = dispatch_data(s, data, size, sock);
    free(data);
    if (i < 0) {
        return -1;
    }
    return i ? (int) size : 0;
}

int lo_server_add_socket(lo_server s, int socket, lo_address a,
                         struct sockaddr_storage *addr,
                         socklen_t addr_len)
{
    /* We must ensure all stream sockets are non-blocking on recv()
     * since we are doing our blocking via select()/poll(). */
#ifdef WIN32
	unsigned long on=1;
	ioctlsocket(socket, FIONBIO, &on);
#else
    fcntl(socket, F_SETFL, O_NONBLOCK, 1);
#endif

    /* Update array of open sockets */
    if ((s->sockets_len + 1) > s->sockets_alloc) {
        void *sc;
        void *sp = realloc(s->sockets,
                           sizeof(*(s->sockets)) * (s->sockets_alloc * 2));
        if (!sp)
            return -1;
        s->sockets = (lo_server_fd_type *) sp;
        memset((char*)sp + s->sockets_alloc*sizeof(*s->sockets),
               0, s->sockets_alloc*sizeof(*s->sockets));

        sc = realloc(s->contexts,
                     sizeof(*(s->contexts))
                     * (s->sockets_alloc * 2));
        if (!sc)
            return -1;
        s->contexts = (struct socket_context *) sc;

        s->sockets_alloc *= 2;
    }

    /* Initialize new socket and context */
    s->sockets[s->sockets_len].fd = socket;
    init_context(&s->contexts[s->sockets_len]);

    s->sockets_len++;

    /* Update socket-indexed array of sources */
    if (socket >= s->sources_len) {
        int L = socket * 2;
        s->sources = (lo_address)
            realloc(s->sources,
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
    cleanup_context(&s->contexts[index]);

    for (i = index + 1; i < s->sockets_len; i++) {
        s->sockets[i - 1] = s->sockets[i];
        s->contexts[i - 1] = s->contexts[i];
    }
    s->sockets_len--;
}

static
int dispatch_data(lo_server s, void *data, size_t size, int sock)
{
    int result = 0;
    char *path = (char*) data;
    ssize_t len = lo_validate_string(data, size);
    if (len < 0) {
        lo_throw(s, (int) -len, "Invalid message path", NULL);
        return (int) len;
    }

    if (!strcmp((const char *) data, "#bundle")) {
        char *pos;
        int remain;
        uint32_t elem_len;
        lo_timetag ts, now;

        ssize_t bundle_result = lo_validate_bundle(data, size);
        if (bundle_result < 0) {
            lo_throw(s, (int) -bundle_result, "Invalid bundle", NULL);
            return (int) bundle_result;
        }
        pos = (char*) data + len;
        remain = (int) (size - len);

        lo_timetag_now(&now);
        ts.sec = lo_otoh32(*((uint32_t *) pos));
        pos += 4;
        ts.frac = lo_otoh32(*((uint32_t *) pos));
        pos += 4;
        remain -= 8;

        // TODO: surely the bundle start/stop handlers shouldn't be called here if the contents will be queued?!
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

                // bump the reference count so that it isn't
                // automatically released
                lo_message_incref(msg);

                // test for immediate dispatch
                if ((s->flags & LO_SERVER_ENQUEUE) == 0
                    || (   ts.sec == LO_TT_IMMEDIATE.sec
                        && ts.frac == LO_TT_IMMEDIATE.frac)
                    || lo_timetag_diff(ts, now) <= 0.0)
                {
                    dispatch_method(s, pos, msg, sock);
                    lo_message_free(msg);
                } else {
                    queue_data(s, ts, pos, msg, sock);
                    // set size to 0 for return
                    size = 0;
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
        lo_message_incref(msg);
        dispatch_method(s, (const char *)data, msg, sock);
        lo_message_free(msg);
    }
    return (int) size;
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
    int argc = (int) strlen(types);
    lo_method it;
    int ret = 1;
    int pattern = lo_string_contains_pattern(path);
    lo_address src = 0;
    const char *pptr;

    // Store the source information in the lo_address
    if (s->protocol == LO_TCP && sock >= 0) {
        msg->source = &s->sources[sock];
    }
    else {
        src = lo_address_new(NULL, NULL);

        // free up default host/port strings so they can be resolved
        // properly if requested
        if (src->host) {
            free(src->host);
            src->host = 0;
        }
        if (src->port) {
            free(src->port);
            src->port = 0;
        }
        src->source_server = s;
        src->source_path = path;
        src->protocol = s->protocol;
        msg->source = src;
    }

    for (it = s->first; it; it = it->next) {
        /* If paths match or handler is wildcard */
        if (!it->path || !strcmp(path, it->path) ||
            (pattern && lo_pattern_match(it->path, path)) ||
            (it->has_pattern && lo_pattern_match(path, it->path))) {
            /* If types match or handler is wildcard */
            if (!it->typespec || !strcmp(types, it->typespec)) {
                /* Send wildcard path to generic handler, expanded path
                   to others.
                 */
                pptr = path;
                if (it->path && !it->has_pattern)
                    pptr = it->path;
                ret = it->handler(pptr, types, msg->argv, argc, msg,
                                  it->user_data);

            } else if (lo_server_should_coerce_args(s) && lo_can_coerce_spec(types, it->typespec)) {
                lo_arg **argv = NULL;
                char *data_co = NULL;

                if (argc > 0) {
                    int i;
                    int opsize = 0;
                    char *ptr = (char*) msg->data, *data_co_ptr = NULL;

                    argv = (lo_arg **) calloc(argc, sizeof(lo_arg *));
                    for (i = 0; i < argc; i++) {
                        opsize += lo_arg_size((lo_type)it->typespec[i], ptr);
                        ptr += lo_arg_size((lo_type)types[i], ptr);
                    }

                    data_co = (char*) malloc(opsize);
                    data_co_ptr = data_co;
                    ptr = (char*) msg->data;
                    for (i = 0; i < argc; i++) {
                        argv[i] = (lo_arg *) data_co_ptr;
                        lo_coerce((lo_type)it->typespec[i], (lo_arg *) data_co_ptr,
                                  (lo_type)types[i], (lo_arg *) ptr);
                        data_co_ptr +=
                            lo_arg_size((lo_type)it->typespec[i], data_co_ptr);
                        ptr += lo_arg_size((lo_type)types[i], ptr);
                    }
                }

                /* Send wildcard path to generic handler, expanded path
                   to others.
                 */
                pptr = path;
                if (it->path)
                    pptr = it->path;
                ret = it->handler(pptr, it->typespec, argv, argc, msg,
                                  it->user_data);
                free(argv);
                free(data_co);
                argv = NULL;
            }

            if (ret == 0 && !pattern) {
                break;
            }
        }
    }

    /* If we find no matching methods, check for protocol level stuff */
    if (ret == 1 && s->protocol == LO_UDP) {
        char *pos = (char*) strrchr(path, '/');

        /* if its a method enumeration call */
        if (pos && *(pos + 1) == '\0') {
            lo_message reply = lo_message_new();
            int len = (int) strlen(path);
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

                    int tmplen = (int) strlen(it->path + len) + 1;
                    tmp = (char*) malloc(strlen(it->path + len) + 1);
                    strncpy(tmp, it->path + len, tmplen);
                    tmp[tmplen-1]=0;
                    sec = strchr(tmp, '/');
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
                        slnew = (lo_strlist *) calloc(1, sizeof(lo_strlist));
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
    queued_msg_list *it = (queued_msg_list *) s->queued;
    queued_msg_list *prev = NULL;
    queued_msg_list *ins = (queued_msg_list *)
        calloc(1, sizeof(queued_msg_list));

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
        it = (queued_msg_list *) it->next;
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
    queued_msg_list *head = (queued_msg_list *) s->queued;
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
        tailhead = (queued_msg_list *) head->next;
        path = ((queued_msg_list *) s->queued)->path;
        msg = ((queued_msg_list *) s->queued)->msg;
        sock = ((queued_msg_list *) s->queued)->sock;
        dispatch_method(s, path, msg, sock);
        free(path);
        lo_message_free(msg);
        free((queued_msg_list *) s->queued);

        s->queued = tailhead;
        head = tailhead;
    } while (head &&
             (lo_timetag_diff(head->ts, disp_time) < FLT_EPSILON || dispatch_all));

    return 0;
}

lo_method lo_server_add_method(lo_server s, const char *path,
                               const char *typespec, lo_method_handler h,
                               const void *user_data)
{
    lo_method m = (lo_method) calloc(1, sizeof(struct _lo_method));
    lo_method it;

    m->has_pattern = lo_string_contains_pattern(path);

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
    m->user_data = (char*) user_data;
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
        pattern = lo_string_contains_pattern(path);

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

int lo_server_del_lo_method(lo_server s, lo_method m)
{
    lo_method it, prev, next;

    if (!s->first)
        return 1;

    it = s->first;
    prev = it;
    while (it) {
        /* incase we free it */
        next = it->next;

        if (it == m) {
            /* Take care when removing the head. */
            if (it == s->first) {
                s->first = it->next;
            } else {
                prev->next = it->next;
            }
            free((void *) it->path);
            free((void *) it->typespec);
            free(it);
            return 0;
        }
        prev = it;
        if (it)
            it = next;
    }
    return 1;
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

        if (!s->hostname)
            lo_server_resolve_hostname(s);

#ifndef _MSC_VER
        ret =
            snprintf(NULL, 0, "osc.%s://%s:%d/", proto, s->hostname,
                     s->port);
#endif
        if (ret <= 0) {
            /* this libc is not C99 compliant, guess a size */
            ret = 1023;
        }
        buf = (char*) malloc((ret + 2) * sizeof(char));
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
        buf = (char*) malloc((ret + 2) * sizeof(char));
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
    return
        ((a == b) ||
         (lo_is_numerical_type((lo_type) a) &&
          lo_is_numerical_type((lo_type) b)) ||
         (lo_is_string_type((lo_type) a) &&
          lo_is_string_type((lo_type) b)));
}

// Context for error handler
void *lo_error_context;
#ifdef ENABLE_THREADS
#ifdef HAVE_LIBPTHREAD
    pthread_mutex_t lo_error_context_mutex = PTHREAD_MUTEX_INITIALIZER;
#else
#ifdef HAVE_WIN32_THREADS
    CRITICAL_SECTION lo_error_context_mutex = {(void*)-1,-1,0,0,0,0};
#endif
#endif
#endif

void lo_throw(lo_server s, int errnum, const char *message,
              const char *path)
{
    if (s->err_h) {
#ifdef ENABLE_THREADS
#ifdef HAVE_LIBPTHREAD
        pthread_mutex_lock(&lo_error_context_mutex);
#else
#ifdef HAVE_WIN32_THREADS
        EnterCriticalSection (&lo_error_context_mutex);
#endif
#endif
#endif
        lo_error_context = s->error_user_data;
        (*s->err_h) (errnum, message, path);
#ifdef ENABLE_THREADS
#ifdef HAVE_LIBPTHREAD
        pthread_mutex_unlock (&lo_error_context_mutex);
#else
#ifdef HAVE_WIN32_THREADS
        LeaveCriticalSection (&lo_error_context_mutex);
#endif
#endif
#endif
    }
}

void *lo_error_get_context()
{
    return lo_error_context;
}

void lo_server_set_error_context(lo_server s, void *user_data)
{
    s->error_user_data = user_data;
}

int lo_server_max_msg_size(lo_server s, int req_size)
{
    if (req_size == 0)
        return s->max_msg_size;

    if (s->protocol == LO_UDP) {
        if (req_size > 65535)
            req_size = 65535;

        if (req_size < 0)
            return s->max_msg_size;
    }
    else if (s->protocol == LO_TCP)
    {
        // TODO: We could potentially shrink the TCP buffers here
        // if req_size < buffer_size for any open sockets, but
        // care must be taken to clean up any data already in the
        // buffers.
    }

    s->max_msg_size = req_size;

    return s->max_msg_size;
}

/* vi:set ts=8 sts=4 sw=4: */
