#ifndef LO_TYPES_H
#define LO_TYPES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/types.h>
#include <sys/socket.h>
#endif

#ifdef HAVE_POLL
#include <poll.h>
#endif

#if defined(WIN32) || defined(_MSC_VER)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define closesocket close
#include <netdb.h>
#include <arpa/inet.h>
#endif

#ifdef _MSC_VER
typedef SSIZE_T ssize_t;
typedef unsigned __int64 uint64_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef __int32 int32_t;
#endif

#ifdef ENABLE_THREADS
#include <pthread.h>
#endif

#include "lo/lo_osc_types.h"

typedef void (*lo_err_handler) (int num, const char *msg,
                                const char *path);

struct _lo_method;

typedef struct _lo_inaddr {
    union {
        struct in_addr addr;
        struct in6_addr addr6;
    } a;
    size_t size;
    char *iface;
} *lo_inaddr;

typedef struct _lo_address {
    char *host;
    int socket;
    int ownsocket;
    char *port;
    int protocol;
    lo_proto_flags flags;
    struct addrinfo *ai;
    struct addrinfo *ai_first;
    int errnum;
    const char *errstr;
    int ttl;
    struct _lo_inaddr addr;
} *lo_address;

typedef struct _lo_blob {
    uint32_t size;
    char *data;
} *lo_blob;

typedef struct _lo_message {
    char *types;
    size_t typelen;
    size_t typesize;
    void *data;
    size_t datalen;
    size_t datasize;
    lo_address source;
    lo_arg **argv;
    /* timestamp from bundle (LO_TT_IMMEDIATE for unbundled messages) */
    lo_timetag ts;
} *lo_message;

typedef int (*lo_method_handler) (const char *path, const char *types,
                                  lo_arg ** argv, int argc,
                                  struct _lo_message * msg,
                                  void *user_data);

typedef int (*lo_bundle_start_handler) (lo_timetag time, void *user_data);
typedef int (*lo_bundle_end_handler) (void *user_data);

typedef struct _lo_method {
    const char *path;
    const char *typespec;
    lo_method_handler handler;
    char *user_data;
    struct _lo_method *next;
} *lo_method;

struct socket_context {
    char *buffer;
    size_t buffer_size;
    unsigned int buffer_msg_offset;
    unsigned int buffer_read_offset;
    int is_slip;                        //<! 1 if slip mode, 0 otherwise, -1 for unknown
    int slip_state;                     //<! state variable for slip decoding
};

typedef struct _lo_server {
    struct addrinfo *ai;
    lo_method first;
    lo_err_handler err_h;
    int port;
    char *hostname;
    char *path;
    int protocol;
    void *queued;
    int queue_enabled;
		int udp_resolve_enabled;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int sockets_len;
    int sockets_alloc;
#ifdef HAVE_POLL
    struct pollfd *sockets;
#else
    struct {
        int fd;
    } *sockets;
#endif

    // Some extra data needed per open socket.  Note that we don't put
    // it in the socket struct, because that layout is needed for
    // passing in the list of sockets to poll().
    struct socket_context *contexts;

    struct _lo_address *sources;
    int sources_len;
    lo_bundle_start_handler bundle_start_handler;
    lo_bundle_end_handler bundle_end_handler;
    void *bundle_handler_user_data;
    struct _lo_inaddr addr_if;
    void *error_user_data;
} *lo_server;

#ifdef ENABLE_THREADS
typedef struct _lo_server_thread {
    lo_server s;
    pthread_t thread;
    volatile int active;
    volatile int done;
} *lo_server_thread;
#else
typedef void *lo_server_thread;
#endif

typedef struct _lo_bundle {
    size_t size;
    size_t len;
    lo_timetag ts;
    lo_message *msgs;
    char **paths;
} *lo_bundle;

typedef struct _lo_strlist {
    char *str;
    struct _lo_strlist *next;
} lo_strlist;

typedef union {
    int32_t i;
    float f;
    char c;
    uint32_t nl;
} lo_pcast32;

typedef union {
    int64_t i;
    double f;
    uint64_t nl;
} lo_pcast64;

extern struct lo_cs {
    int udp;
    int tcp;
} lo_client_sockets;

#endif
