
#ifndef _LO_CPP_H_
#define _LO_CPP_H_

#include <lo/lo.h>
#include <lo/lo_throw.h>

#include <functional>
#include <vector>
#include <memory>


#define LO_ADD_METHOD_RT(s, argtypes, args, ht, rt, r, r1, r2)       \
    template <typename H>                                               \
    auto add_method(const char *path, const char *types, H&& h)         \
    -> rt const                                                         \
    {                                                                   \
        m_handlers.push_back(                                           \
            std::unique_ptr<handler>(new handler_##ht##_##r(h)));       \
        _add_method(path, types,                                        \
            [](const char *path, const char *types,                     \
               lo_arg **argv, int argc, void *msg,                      \
               void *data)->int                                         \
            {                                                           \
                r1 (*static_cast<handler_##ht##_##r*>(data)) args;      \
                r2;                                                     \
            }, m_handlers.back().get());                                \
    }

#define RT_INT(argtypes) \
    typename std::enable_if<std::is_same<decltype(h argtypes), int>::value, int>::type
#define RT_VOID(argtypes) \
    typename std::enable_if<std::is_same<decltype(h argtypes), void>::value, void>::type

#define LO_ADD_METHOD_RT_INT(s, argtypes, args, ht)                  \
    LO_ADD_METHOD_RT(s, argtypes, args, ht,                          \
                        RT_INT(argtypes), int, return,)
#define LO_ADD_METHOD_RT_VOID(s, argtypes, args, ht)                 \
    LO_ADD_METHOD_RT(s, argtypes, args, ht,                          \
                        RT_VOID(argtypes), void, , return 1)

#define LO_ADD_METHOD(s, argtypes, args, ht)                         \
    LO_ADD_METHOD_RT_INT(s, argtypes, args, ht)                      \
    LO_ADD_METHOD_RT_VOID(s, argtypes, args, ht)

namespace lo {

    class Server
    {
      public:
        Server() {}

        Server(lo_server s) : server(s) {
            lo_throw(server, LO_UNKNOWNPROTO, "test", "testhandler");
        }

        Server(const char *port, lo_err_handler err_h)
            : Server(lo_server_new(port, err_h)) {}

        template <typename E>
        Server(const char *port, E&& e)
            : Server(lo_server_new(port,
              [](int num, const char *msg, const char *where){
                auto h = static_cast<handler_error*>(lo_error_get_context());
                (*h)(num, msg, where);
              }))
        {
            if (server) {
                auto h = new handler_error(e);
                m_handlers.push_back(std::unique_ptr<handler>(h));
                lo_server_set_error_context(server, h);
            }
        }

        Server(const char *port, int proto=LO_UDP, lo_err_handler err_h=0)
            : Server(lo_server_new_with_proto(port, proto, err_h)) {}

        Server(const char *group, const char *port, const char *iface=0,
               const char *ip=0, lo_err_handler err_h=0)
            : Server((iface || ip)
                     ? lo_server_new_multicast_iface(group, port, iface, ip, err_h)
                     : lo_server_new_multicast(group, port, err_h)) {}

        virtual ~Server()
            { printf("~Server()\n");
                if (server) lo_server_free(server); }

        bool is_valid() { return server!=nullptr; }

        // Regular old liblo method handlers
        void add_method(const char *path, const char *types,
                        lo_method_handler h, void *data) const
        {
            _add_method(path, types, h, data);
        }

        // Alternative callback prototypes
        LO_ADD_METHOD(server,
            ((char*)0, (char*)0, (lo_arg**)0, (int)0),
            (path, types, argv, argc), pathtypesargs)
        LO_ADD_METHOD(server,
            ((char*)0, (lo_arg**)0, (int)0),
            (types, argv, argc), typesargs)
        LO_ADD_METHOD(server,
            ((char*)0, (lo_arg**)0, (int)0, (lo_message)0),
            (types, argv, argc, msg), typesargsmsg)
        LO_ADD_METHOD(server,
            ((lo_arg**)0, (int)0), (argv, argc), args)
        LO_ADD_METHOD(server,
            ((lo_arg**)0, (int)0, (lo_message)0),
            (argv, argc, msg), argsmsg)
        LO_ADD_METHOD(server,
            ((lo_message)0), (msg), msg)
        LO_ADD_METHOD(server, (), (),)

        void del_method(const char *path, const char *typespec)
        {
            // TODO
        }

        int dispatch_data(void *data, size_t size)
            { return lo_server_dispatch_data(server, data, size); }

        int wait(int timeout)
            { return lo_server_wait(server, timeout); }

        int recv()
            { return lo_server_recv(server); }

        int recv(int timeout)
            { return lo_server_recv_noblock(server, timeout); }

        int add_bundle_handlers(lo_bundle_start_handler sh,
                                lo_bundle_end_handler eh,
                                void *user_data)
        {
            // TODO, lambda versions
            return lo_server_add_bundle_handlers(server, sh, eh, user_data);
        }

        int socket_fd()
            { return lo_server_get_socket_fd(server); }

        int port()
            { return lo_server_get_port(server); }

        int protocol()
            { return lo_server_get_protocol(server); }

        std::string url()
            { return std::string(lo_server_get_url(server)); }

        int enable_queue(int queue_enabled,
                         int dispatch_remaining=1)
            { return lo_server_enable_queue(server,
                                            queue_enabled,
                                            dispatch_remaining); }

        int events_pending()
            { return lo_server_events_pending(server); }

        double next_event_delay()
            { return lo_server_next_event_delay(server); }

        operator lo_server() const
            { return server; }

      protected:
        lo_server server;

        class handler {
          public:
            virtual ~handler() { printf("handler::~handler\n"); };
        };
        template <typename T>
        class handler_type : public handler, public std::function<T> {
          public: template<typename H>handler_type(H&& h) : std::function<T>(h) {}
        };
        typedef handler_type<void()> handler__void;
        typedef handler_type<int()> handler__int;
        typedef handler_type<void(int, const char *, const char *)> handler_error;

        typedef handler_type<int(const char *,const char *,lo_arg**,int)> handler_pathtypesargs_int;
        typedef handler_type<int(const char *,lo_arg**,int)> handler_typesargs_int;
        typedef handler_type<int(const char *,lo_arg**,int,lo_message)> handler_typesargsmsg_int;
        typedef handler_type<int(lo_arg**,int,lo_message)> handler_argsmsg_int;
        typedef handler_type<int(lo_arg**,int)> handler_args_int;
        typedef handler_type<int(lo_message)> handler_msg_int;

        typedef handler_type<void(const char *,const char *,lo_arg**,int)> handler_pathtypesargs_void;
        typedef handler_type<void(const char *,lo_arg**,int)> handler_typesargs_void;
        typedef handler_type<void(const char *,lo_arg**,int,lo_message)> handler_typesargsmsg_void;
        typedef handler_type<void(lo_arg**,int,lo_message)> handler_argsmsg_void;
        typedef handler_type<void(lo_arg**,int)> handler_args_void;
        typedef handler_type<void(lo_message)> handler_msg_void;

        // Keep std::functions here so they are freed correctly
        std::vector<std::unique_ptr<handler>> m_handlers;

        virtual void _add_method(const char *path, const char *types,
                        lo_method_handler h, void *data) const
        {
            lo_server_add_method(server, path, types, h, data);
        }
    };

    class ServerThread : public Server
    {
      public:
        ServerThread(const char *port, lo_err_handler err_h)
            { server_thread = lo_server_thread_new(port, err_h); 
                printf("here1\n");
                lo_throw(lo_server_thread_get_server(server_thread), LO_UNKNOWNPROTO, "test2", "testhandler2");
                Server(lo_server_thread_get_server(server_thread));
            }

        template <typename E>
        ServerThread(const char *port, E&& e)
        {
          server_thread = lo_server_thread_new(port,
             [](int num, const char *msg, const char *where){
                 printf("wrapper: %d, %s, %s\n", num, msg, where);
                 auto h = static_cast<handler_error*>(lo_error_get_context());
                 (*h)(num, msg, where);
             });
          if (server_thread) {
              auto h = new handler_error(e);
              m_handlers.push_back(std::unique_ptr<handler>(h));
              lo_server_thread_set_error_context(server_thread, h);
              server = lo_server_thread_get_server(server_thread);
          }
          lo_throw(lo_server_thread_get_server(server_thread), LO_UNKNOWNPROTO, "test", "testhandler");
        }

        ServerThread(const char *port, int proto, lo_err_handler err_h)
            { server_thread = lo_server_thread_new_with_proto(port, proto, err_h); }

        virtual ~ServerThread()
            { printf("~ServerThread()\n");
              server = 0;
              if (server_thread) lo_server_thread_free(server_thread); }

        void start() { lo_server_thread_start(server_thread); }
        void stop() { lo_server_thread_stop(server_thread); }

        operator lo_server_thread() const
            { return server_thread; }

      protected:
        lo_server_thread server_thread;

        // Regular old liblo method handlers
        virtual void _add_method(const char *path, const char *types,
                        lo_method_handler h, void *data) const
        {
            lo_server_thread_add_method(server_thread, path, types, h, data);
        }
    };

    class Address
    {
      public:
        Address(const char *host, const char *port, int proto=LO_UDP)
          { address = lo_address_new_with_proto(proto, host, port); }

        Address(const char *url)
          { address = lo_address_new_from_url(url); }

        ~Address()
          { if (address)
              lo_address_free(address); }

        int ttl()
          { return lo_address_get_ttl(address); }

        void set_ttl(int ttl)
          { lo_address_set_ttl(address, ttl); }

        // In these functions we append "$$" to the type string, which
        // simply instructs lo_message_add_varargs() not to use
        // LO_MARKER checking at the end of the argument list.
        int send(const char *path, const char *type, ...)
        {
            va_list q;
            va_start(q, type);
            lo_message m = lo_message_new();
            std::string t = std::string(type) + "$$";
            lo_message_add_varargs(m, t.c_str(), q);
            int r = lo_send_message(address, path, m);
            lo_message_free(m);
            return r;
        }

        int send(lo_timetag ts, const char *path,
                 const char *type, ...)
        {
            va_list q;
            va_start(q, type);
            lo_message m = lo_message_new();
            std::string t = std::string(type) + "$$";
            lo_message_add_varargs(m, t.c_str(), q);
            lo_bundle b = lo_bundle_new(ts);
            lo_bundle_add_message(b, path, m);
            int r = lo_send_bundle(address, b);
            lo_bundle_free_messages(m);
            return r;
        }

        int send_from(lo_server from, const char *path,
                      const char *type, ...)
        {
            va_list q;
            va_start(q, type);
            lo_message m = lo_message_new();
            std::string t = std::string(type) + "$$";
            lo_message_add_varargs(m, t.c_str(), q);
            int r = lo_send_message_from(from, address, path, m);
            lo_message_free(m);
            return r;
        }

        int send_from(lo_server from, lo_timetag ts, 
                      const char *path, const char *type, ...)
        {
            va_list q;
            va_start(q, type);
            lo_message m = lo_message_new();
            std::string t = std::string(type) + "$$";
            lo_message_add_varargs(m, t.c_str(), q);
            lo_bundle b = lo_bundle_new(ts);
            lo_bundle_add_message(b, path, m);
            int r = lo_send_bundle_from(from, address, b);
            lo_bundle_free_messages(b);
        }

        int get_errno()
          { return lo_address_errno(address); }

        std::string errstr()
          { return std::string(lo_address_errstr(address)); }

        std::string hostname()
          { return std::string(lo_address_get_hostname(address)); }

        std::string port()
          { return std::string(lo_address_get_port(address)); }

        int protocol()
          { return lo_address_get_protocol(address); }

        std::string url()
          { return std::string(lo_address_get_url(address)); }

        std::string iface()
          { const char *s = lo_address_get_iface(address);
            return std::string(s ? s : ""); }

        void set_iface(const std::string &iface, const std::string &ip)
          { lo_address_set_iface(address,
                                 iface.empty() ? nullptr : iface.c_str(),
                                 ip.empty() ? nullptr : ip.c_str()); }

        void set_iface(const char *iface, const char *ip)
          { lo_address_set_iface(address, iface, ip); }

        operator lo_address() const
            { return address; }

      protected:
        lo_address address;
    };

};

#endif // _LO_CPP_H_
