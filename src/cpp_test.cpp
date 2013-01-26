
#include <cstdio>
#include <string>
#include <iostream>

#include <array>
#include <vector>

#include <unistd.h>

#include <lo/lo.h>

int test1(const char *path, const char *types,
          lo_arg **argv, int argc, lo_message m,
          void *data)
{
    printf("path: %s\n", path);
    printf("types: %s\n", types);
    printf("i: %d\n", argv[0]->i);
    return 0;
}

int test2(lo_arg **argv, int argc)
{
    printf("in test2: %d\n", argv[0]->i);
    return 0;
}

int test3(lo_arg **argv, int argc, lo_message msg)
{
    printf("in test3\n");
    return 0;
}

void init(lo::Server &s)
{
    int j = 234;

    std::cout << "URL: " << s.url() << std::endl;

    class test3
    {
    public:
        test3(int j, std::string s) : _s(s), _j(j) {};
        int operator () (lo_arg **argv, int argc, lo_message msg)
        {
            std::cout << _s << ": " << _j << ", " << argv[0]->i << std::endl;
            return 0;
        }
    private:
        std::string _s;
        int _j;
    };

    s.add_method("test1", "i", test1, 0);
    s.add_method("test2", "i", test2);
    s.add_method("test3", "i", test3(j, "test3"));

    s.add_method("test4", "i",
                  [j](lo_arg **argv, int argc)
                  {
                      printf("test4: %d, %d\n", j, argv[0]->i);
                      return 0;
                  });

    j *= 2;
    s.add_method("test5", "i",
                  [j](lo_arg **argv, int argc, lo_message msg)
                  {
                      printf("test5: %d, %d -- ", j, argv[0]->i);
                      lo_message_pp(msg);
                      return 0;
                  });

    j *= 2;
    s.add_method("test6", "i",
                  [j](lo_message msg)
                  {
                      printf("test6: %d -- ", j);
                      lo_message_pp(msg);
                      return 0;
                  });

    j *= 2;
    s.add_method("test7", "i", [j](){printf("test7: %d\n", j); return 0;});
    j *= 2;
    s.add_method("test8", "i", [j](){printf("test8a: %d\n", j);});
    j *= 2;
    s.add_method("test8", "i", [j](){printf("test8b: %d\n", j);});

    j*=2;
    s.add_method("test9", "i", [j](const char *path, const char *types, lo_arg **argv, int argc)
                  {printf("test9: %d, %s, %s, %d\n", j, path, types, argv[0]->i); return 0;});
    j*=2;
    s.add_method("test10", "i", [j](const char *types, lo_arg **argv, int argc)
                  {printf("test10: %d, %s, %d\n", j, types, argv[0]->i); return 0;});
    j*=2;
    s.add_method("test11", "i", [j](const char *types, lo_arg **argv, int argc, lo_message msg)
                  {printf("test11: %d, %s, %d -- ", j, types, argv[0]->i); lo_message_pp(msg); return 0;});

    j*=2;
    s.add_method("test9", "i", [j](const char *path, const char *types, lo_arg **argv, int argc)
                  {printf("test9: %d, %s, %s, %d\n", j, path, types, argv[0]->i);});
    j*=2;
    s.add_method("test10", "i", [j](const char *types, lo_arg **argv, int argc)
                  {printf("test10: %d, %s, %d\n", j, types, argv[0]->i);});
    j*=2;
    s.add_method("test11", "is", [j](const char *types, lo_arg **argv, int argc, lo_message msg)
                 {printf("test11: %d, %s, %d, %s -- ", j, types, argv[0]->i, &argv[1]->s); lo_message_pp(msg);});

    s.add_method(0, 0, [](const char *path, lo_message m){printf("%s ", path); lo_message_pp(m);});
}

int main()
{
    int context = 999;
    lo::ServerThread st("9000",
                        [=](int num, const char *msg, const char *where)
                        {printf("error handler: %d\n", context);});
    if (!st.is_valid()) {
        printf("Nope.\n");
        return 1;
    }

    std::cout << "URL: " << st.url() << std::endl;

    init(st);

    st.start();

    lo::Address a("localhost", "9000");

    printf("address host %s, port %s\n", a.hostname().c_str(), a.port().c_str());
    printf("iface: %s\n", a.iface().c_str());
    a.set_iface(std::string(), std::string("127.0.0.1"));
    a.set_iface(0, "127.0.0.1");
    printf("iface: %s\n", a.iface().c_str());

    a.send_from(st, "test1", "i", 20);
    a.send("test2", "i", 40);
    a.send("test3", "i", 60);
    a.send("test4", "i", 80);
    a.send("test5", "i", 100);
    a.send("test6", "i", 120);
    a.send("test7", "i", 140);
    a.send("test8", "i", 160);
    a.send("test9", "i", 180);
    a.send("test10", "i", 200);

    lo::Message m;
    m.add("i", 220);
    m.add_string(std::string("blah"));
    a.send("test11", m);

    m.add(lo::Blob(4,"asdf"));
    m.add(lo::Blob(std::vector<char>(5, 'a')));
    m.add(lo::Blob(std::array<char,5>{"asdf"}));
    a.send("blobtest", m);

    printf("%s: %d\n", a.errstr().c_str(), a.get_errno());

    sleep(1);
}
