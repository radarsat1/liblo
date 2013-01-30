
#ifndef _LO_CPP_H_
#define _LO_CPP_H_

#include <lo/lo.h>
#include <lo/lo_throw.h>

#include <functional>
#include <memory>
#include <list>
#include <unordered_map>
#include <string>
#include <sstream>
#include <initializer_list>

#define LO_ADD_METHOD_RT(s, argtypes, args, ht, rt, r, r1, r2)       \
    template <typename H>                                               \
    auto add_method(const string_type path, const string_type types, H&& h) \
    -> rt const                                                         \
    {                                                                   \
        std::string key = std::string(path._s?:"") + "," + (types._s?:""); \
        _handlers[key].push_front(                                      \
            std::unique_ptr<handler>(new handler_##ht##_##r(h)));       \
        _add_method(path, types,                                        \
            [](const char *path, const char *types,                     \
               lo_arg **argv, int argc, void *msg,                      \
               void *data)->int                                         \
            {                                                           \
                r1 (*static_cast<handler_##ht##_##r*>(data)) args;      \
                r2;                                                     \
            }, _handlers[key].front().get());                           \
    }

#define RT_INT(argtypes) \
    typename std::enable_if<std::is_same<decltype(h argtypes), int>::value, void>::type
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

    template <bool is_owner>
    class Message;

    // Helper classes to allow polymorphism on "const char *",
    // "std::string", and "int".
    class string_type {
      public:
        string_type(const char *s=0) { _s = s; }
        string_type(const std::string &s) { _s = s.c_str(); }
        operator const char*() const { return _s; }
        const char *_s;
    };

    class num_string_type : public string_type {
      public:
      num_string_type(const char *s) : string_type(s) {}
      num_string_type(const std::string &s) : string_type(s) {}
        num_string_type(int n) { std::ostringstream ss; ss << n;
            _p.reset(new std::string(ss.str())); _s = _p->c_str(); }
        std::unique_ptr<std::string> _p;
    };

    class Server
    {
      public:
        Server(lo_server s) : server(s) {}

        template <typename E>
        Server(const num_string_type &port, E&& e)
            : Server(lo_server_new(port,
              [](int num, const char *msg, const char *where){
                auto h = static_cast<handler_error*>(lo_error_get_context());
                (*h)(num, msg, where);
              }))
        {
            if (server) {
                lo_server_set_error_context(server,
                    _error_handler = std::unique_ptr<handler>(
                        new handler_error(e)));
            }
        }

        template <typename E>
        Server(const num_string_type &port, int proto, E&& e=0)
            : Server(lo_server_new_with_proto(port, proto,
              [](int num, const char *msg, const char *where){
                auto h = static_cast<handler_error*>(lo_error_get_context());
                (*h)(num, msg, where);
              }))
        {
            if (server) {
                lo_server_set_error_context(server,
                    _error_handler = std::unique_ptr<handler>(
                        new handler_error(e)));
            }
        }

        template <typename E>
        Server(const string_type &group, const num_string_type &port,
               const string_type &iface=0, const string_type &ip=0, E&& e=0)
            : Server((!iface._s || !ip._s)
                     ? lo_server_new_multicast_iface(group, port, iface, ip,
                           [](int num, const char *msg, const char *where){
                               auto h = static_cast<handler_error*>(lo_error_get_context());
                               (*h)(num, msg, where);
                           })
                     : lo_server_new_multicast(group, port,
                           [](int num, const char *msg, const char *where){
                               auto h = static_cast<handler_error*>(lo_error_get_context());
                               (*h)(num, msg, where);
                       }))
        {
            if (server) {
                lo_server_set_error_context(server,
                    _error_handler = std::unique_ptr<handler>(
                        new handler_error(e)));
            }
        }

        Server(const num_string_type &port, lo_err_handler err_h=0)
            : Server(lo_server_new(port, err_h)) {}

        Server(const num_string_type &port, int proto, lo_err_handler err_h=0)
            : Server(lo_server_new_with_proto(port, proto, err_h)) {}

        Server(const string_type &group, const num_string_type &port,
               const string_type &iface="", const string_type &ip="", lo_err_handler err_h=0)
            : Server((iface._s || ip._s)
                     ? lo_server_new_multicast_iface(group, port,
                                                     iface._s?:0,
                                                     ip._s?:0, err_h)
                     : lo_server_new_multicast(group, port, err_h)) {}

        virtual ~Server()
            { if (server) lo_server_free(server); }

        bool is_valid() { return server!=nullptr; }

        // Regular old liblo method handlers
        void add_method(const string_type &path, const string_type &types,
                        lo_method_handler h, void *data) const
            { _add_method(path, types, h, data); }

        // Alternative callback prototypes
        LO_ADD_METHOD(server,
            ((char*)0, (char*)0, (lo_arg**)0, (int)0),
            (path, types, argv, argc), pathtypesargs)
        LO_ADD_METHOD(server,
            ((char*)0, (lo_arg**)0, (int)0),
            (types, argv, argc), typesargs)
        LO_ADD_METHOD(server,
            ((char*)0, (lo_arg**)0, (int)0, Message<false>((lo_message)0)),
            (types, argv, argc, Message<false>(msg)), typesargsmsg)
        LO_ADD_METHOD(server,
            ((char*)0, Message<false>((lo_message)0)),
            (path, Message<false>(msg)), pathmsg)
        LO_ADD_METHOD(server,
            ((lo_arg**)0, (int)0), (argv, argc), args)
        LO_ADD_METHOD(server,
            ((lo_arg**)0, (int)0, Message<false>((lo_message)0)),
            (argv, argc, Message<false>(msg)), argsmsg)
        LO_ADD_METHOD(server,
            (Message<false>((lo_message)0)), (Message<false>(msg)), msg)
        LO_ADD_METHOD(server, (), (),)

        void del_method(const string_type &path, const string_type &typespec)
        {
            _handlers.erase(std::string(path._s?:"") + ","
                            + (typespec._s?:""));
            lo_server_del_method(server, path, typespec);
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
            return lo_server_add_bundle_handlers(server, sh, eh, user_data);
        }

        template <typename S, typename E>
        int add_bundle_handlers(S&& s, E&& e)
        {
            _bundle_handlers.reset(new std::pair<handler_bundle_start,
                                                 handler_bundle_end>(
                                       handler_bundle_start(s),
                                       handler_bundle_end(e)));
            return lo_server_add_bundle_handlers(
                server,
                [](lo_timetag time, void *user_data)->int{
                    auto h = (std::pair<handler_bundle_start,
                                        handler_bundle_end>*) user_data;
                    return h->first(time);
                },
                [](void *user_data)->int{
                    auto h = (std::pair<handler_bundle_start,
                                        handler_bundle_end>*) user_data;
                    return h->second();
                },
                _bundle_handlers.get());
        }

        int socket_fd()
            { return lo_server_get_socket_fd(server); }

        int port()
            { return lo_server_get_port(server); }

        int protocol()
            { return lo_server_get_protocol(server); }

        std::string url()
            { return std::string(lo_server_get_url(server)?:""); }

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

        class handler {};
        template <typename T>
        class handler_type : public handler, public std::function<T> {
          public: template<typename H>handler_type(H&& h) : std::function<T>(h) {}
        };
        typedef handler_type<void()> handler__void;
        typedef handler_type<int()> handler__int;
        typedef handler_type<void(int, const char *, const char *)> handler_error;
        typedef handler_type<void(int, const std::string&, const std::string&)> handler_error_s;
        typedef handler_type<int(lo_timetag)> handler_bundle_start;
        typedef handler_type<int()> handler_bundle_end;

        typedef handler_type<int(const char *,const char *,lo_arg**,int)> handler_pathtypesargs_int;
        typedef handler_type<int(const char *,lo_arg**,int)> handler_typesargs_int;
        typedef handler_type<int(const char *,lo_arg**,int,const Message<false>&)> handler_typesargsmsg_int;
        typedef handler_type<int(const char *,const Message<false>&)> handler_pathmsg_int;
        typedef handler_type<int(lo_arg**,int,const Message<false>&)> handler_argsmsg_int;
        typedef handler_type<int(lo_arg**,int)> handler_args_int;
        typedef handler_type<int(const Message<false>&)> handler_msg_int;

        typedef handler_type<void(const char *,const char *,lo_arg**,int)> handler_pathtypesargs_void;
        typedef handler_type<void(const char *,lo_arg**,int)> handler_typesargs_void;
        typedef handler_type<void(const char *,lo_arg**,int,const Message<false>&)> handler_typesargsmsg_void;
        typedef handler_type<void(const char *,const Message<false>&)> handler_pathmsg_void;
        typedef handler_type<void(lo_arg**,int,const Message<false>&)> handler_argsmsg_void;
        typedef handler_type<void(lo_arg**,int)> handler_args_void;
        typedef handler_type<void(const Message<false>&)> handler_msg_void;

        // Keep std::functions here so they are freed correctly
        std::unordered_map<std::string,
            std::list<std::unique_ptr<handler>>> _handlers;
        std::unique_ptr<handler> _error_handler;
        std::unique_ptr<std::pair<handler_bundle_start,
                                  handler_bundle_end>> _bundle_handlers;

        virtual void _add_method(const char *path, const char *types,
                        lo_method_handler h, void *data) const
        {
            lo_server_add_method(server, path, types, h, data);
        }
    };

    class ServerThread : public Server
    {
      public:
        ServerThread(const num_string_type &port, lo_err_handler err_h=0)
            : Server(lo_server_thread_get_server(
                  server_thread = lo_server_thread_new(port, err_h))) {}

        template <typename E>
        ServerThread(const num_string_type &port, E&& e)
            : Server(lo_server_thread_get_server(
                  server_thread = lo_server_thread_new(port,
                  [](int num, const char *msg, const char *where){
                      auto h = static_cast<handler_error*>(lo_error_get_context());
                      (*h)(num, msg, where);})))
            {
                if (server_thread) {
                    auto h = new handler_error(e);
                    _error_handler.reset(h);
                    lo_server_thread_set_error_context(server_thread, h);
                }
            }

        ServerThread(const num_string_type &port, int proto, lo_err_handler err_h)
            : Server(lo_server_thread_get_server(
                  server_thread = lo_server_thread_new_with_proto(port, proto, err_h))) {}

        virtual ~ServerThread()
            { server = 0;
              if (server_thread) lo_server_thread_free(server_thread); }

        void start() { lo_server_thread_start(server_thread); }
        void stop() { lo_server_thread_stop(server_thread); }

        operator lo_server_thread() const
            { return server_thread; }

      protected:
        lo_server_thread server_thread;

        // Regular old liblo method handlers
        virtual void _add_method(const string_type &path,
                                 const string_type &types,
                                 lo_method_handler h, void *data) const
        {
            lo_server_thread_add_method(server_thread, path, types, h, data);
        }
    };

    class Address
    {
      public:
        Address(const string_type &host, const num_string_type &port,
                int proto=LO_UDP)
          { address = lo_address_new_with_proto(proto, host, port); }

        Address(const string_type &url)
          { address = lo_address_new_from_url(url); }

        Address(lo_address a)
          { address = a; }

        ~Address()
          { if (address)
              lo_address_free(address); }

        int ttl()
          { return lo_address_get_ttl(address); }

        void set_ttl(int ttl)
          { lo_address_set_ttl(address, ttl); }

        int send(const string_type &path)
          { return lo_send(address, path, ""); }

        // In these functions we append "$$" to the type string, which
        // simply instructs lo_message_add_varargs() not to use
        // LO_MARKER checking at the end of the argument list.
        int send(const string_type &path, const string_type &type, ...)
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

        int send(lo_timetag ts, const string_type &path,
                 const string_type &type, ...)
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

        int send(const string_type &path, lo_message m)
            { return lo_send_message(address, path, m); }

        int send(lo_bundle b)
            { return lo_send_bundle(address, b); }

        int send_from(lo_server from, const string_type &path,
                      const string_type &type, ...)
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
                      const string_type &path,
                      const string_type &type, ...)
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
            return r;
        }

        int send_from(lo_server from, const string_type &path, lo_message m)
            { return lo_send_message_from(address, from, path, m); }

        int send(lo_server from, lo_bundle b)
            { return lo_send_bundle_from(address, from, b); }

        int get_errno()
          { return lo_address_errno(address); }

        std::string errstr()
          { return std::string(lo_address_errstr(address)?:""); }

        std::string hostname()
          { return std::string(lo_address_get_hostname(address)?:""); }

        std::string port()
          { return std::string(lo_address_get_port(address)?:""); }

        int protocol()
          { return lo_address_get_protocol(address); }

        std::string url()
          { return std::string(lo_address_get_url(address)?:""); }

        std::string iface()
          { return std::string(lo_address_get_iface(address)?:""); }

        void set_iface(const string_type &iface, const string_type &ip)
          { lo_address_set_iface(address, iface._s?:0, ip._s?:0); }

        operator lo_address() const
            { return address; }

      protected:
        lo_address address;
    };

    template <bool is_owner>
    class Message
    {
      public:
        Message()
            : message(lo_message_new()) {}

        Message(lo_message m)
            : message(m) {}

        Message(const Message &m)
            : message(m.message) {}

        Message(const string_type &types, ...)
        {
            message = lo_message_new();
            va_list q;
            va_start(q, types);
            std::string t(std::string(types)+"$$");
            add_varargs(t.c_str(), q);
        }

        virtual ~Message() {};

        int add(const string_type &types, ...)
        {
            va_list q;
            va_start(q, types);
            std::string t(std::string(types)+"$$");
            return add_varargs(t.c_str(), q);
        }

        int add_varargs(const string_type &types, va_list ap)
            { return lo_message_add_varargs(message, types, ap); }

        int add_int32(int32_t a)
            { return lo_message_add_int32(message, a); }

        int add_float(float a)
            { return lo_message_add_float(message, a); }

        int add_string(const string_type &a)
            { return lo_message_add_string(message, a); }

        int add_blob(lo_blob a)
            { return lo_message_add_blob(message, a); }

        int add_int64(int64_t a)
            { return lo_message_add_int64(message, a); }

        int add_timetag(lo_timetag a)
            { return lo_message_add_timetag(message, a); }

        int add_double(double a)
            { return lo_message_add_double(message, a); }

        int add_symbol(const string_type &a)
            { return lo_message_add_symbol(message, a); }

        int add_char(char a)
            { return lo_message_add_char(message, a); }

        int add_midi(uint8_t a[4])
            { return lo_message_add_midi(message, a); }

        int add_bool(bool b)
            { if (b)
                return lo_message_add_true(message);
              else
                return lo_message_add_false(message); }

        int add_true()
            { return lo_message_add_true(message); }

        int add_false()
            { return lo_message_add_false(message); }

        int add_nil()
            { return lo_message_add_nil(message); }

        int add_infinitum()
            { return lo_message_add_infinitum(message); }

        // Note, for polymorphic versions of "add", below, we can't do
        // this for "string" or "symbol" types, since it is ambiguous
        // with "add(types, ...)" above.

        int add(int32_t a)
            { return lo_message_add_int32(message, a); }

        int add(float a)
            { return lo_message_add_float(message, a); }

        int add(lo_blob a)
            { return lo_message_add_blob(message, a); }

        int add(int64_t a)
            { return lo_message_add_int64(message, a); }

        int add(lo_timetag a)
            { return lo_message_add_timetag(message, a); }

        int add(double a)
            { return lo_message_add_double(message, a); }

        int add(char a)
            { return lo_message_add_char(message, a); }

        int add(uint8_t a[4])
            { return lo_message_add_midi(message, a); }

        int add(bool b)
            { if (b)
                return lo_message_add_true(message);
              else
                return lo_message_add_false(message); }

        Address source()
            { return Address(lo_message_get_source(message)); }

        lo_timetag timestamp()
            { return lo_message_get_timestamp(message); }

        std::string types()
            { return std::string(lo_message_get_types(message)?:""); }

        int argc()
            { return lo_message_get_argc(message); }

        lo_arg **argv()
            { return lo_message_get_argv(message); }

        size_t length(const char *path)
            { return lo_message_length(message, path); }

        size_t length(const std::string &path)
            { return lo_message_length(message, path.c_str()); }

        void *serialise(const string_type &path, void *to, size_t *size)
            { return lo_message_serialise(message, path, to, size); }

        static
        Message *deserialise(void *data, size_t size, int *result=0)
            { lo_message m = lo_message_deserialise(data, size, result);
              return new Message(m); }

        void print() const
            { lo_message_pp(message); }

        operator lo_message() const
            { return message; }

      protected:
        lo_message message;
    };

    template<>
    Message<true>::~Message()
        { lo_message_free(message); }

    class Blob
    {
      public:
        Blob(int32_t size, const void *data=0)
            : blob(lo_blob_new(size, data)) {}

        template <typename T>
        Blob(const T &t)
            : blob(lo_blob_new(t.size()*sizeof(t[0]), &t[0])) {}

        virtual ~Blob()
            { lo_blob_free(blob); }

        uint32_t datasize()
            { return lo_blob_datasize(blob); }

        void *dataptr()
            { return lo_blob_dataptr(blob); }

        uint32_t size()
            { return lo_blobsize(blob); }

        operator lo_blob()
            { return blob; };

      protected:
        lo_blob blob;
    };

    template <bool is_owner>
    struct PathMsg
    {
        const string_type &path;
        Message<is_owner> msg;
    };

    template <bool is_owner>
    class Bundle
    {
      public:
        Bundle() { bundle = lo_bundle_new(LO_TT_IMMEDIATE); }

        Bundle(lo_timetag tt)
            : bundle(lo_bundle_new(tt)) {}

        Bundle(lo_bundle b)
            : bundle(b) {}

        Bundle(lo_timetag tt, const string_type &path, lo_message m)
            : bundle(lo_bundle_new(tt))
        {
            lo_bundle_add_message(bundle, path, m);
        }

        Bundle(const std::initializer_list<PathMsg<true>> &msgs);
        Bundle(const std::initializer_list<PathMsg<false>> &msgs);

        virtual ~Bundle() {}

        int add(const string_type &path, lo_message m)
            { return lo_bundle_add_message(bundle, path, m); }

        size_t length()
            { return lo_bundle_length(bundle); }

        unsigned int count()
            { return lo_bundle_count(bundle); }

        lo_message get_message(int index, const char **path)
            { return lo_bundle_get_message(bundle, index, path); }

        lo_message get_message(int index, std::string &path)
            { const char *p;
              int r=lo_bundle_get_message(bundle, index, &p);
              path = p?:0;
              return r; }

        void *serialise(void *to, size_t *size)
            { return lo_bundle_serialise(bundle, to, size); }

        operator lo_bundle()
            { return bundle; }

      protected:
        lo_bundle bundle;
    };

    template<>
    Bundle<true>::Bundle(const std::initializer_list<PathMsg<false>> &msgs)
        : bundle(lo_bundle_new(LO_TT_IMMEDIATE))
    {
        for (auto m : msgs) {
            lo_bundle_add_message(bundle, m.path, m.msg);
        }
    }

    template<>
    Bundle<false>::Bundle(const std::initializer_list<PathMsg<true>> &msgs)
        : bundle(lo_bundle_new(LO_TT_IMMEDIATE))
    {
        for (auto m : msgs) {
            lo_bundle_add_message(bundle, m.path, m.msg);
        }
    }

    template<>
    Bundle<false>::Bundle(const std::initializer_list<PathMsg<false>> &msgs)
        : bundle(lo_bundle_new(LO_TT_IMMEDIATE))
    {
        for (auto m : msgs) {
            lo_bundle_add_message(bundle, m.path, m.msg);
        }
    }

    template<> Bundle<true>::~Bundle()
        { lo_bundle_free_messages(bundle); }
};

#endif // _LO_CPP_H_