
#include <cstdio>
#include <string>
#include <iostream>

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

    std::cout << "URL: " << s.get_url() << std::endl;

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
    s.add_method("test11", "i", [j](const char *types, lo_arg **argv, int argc, lo_message msg)
                  {printf("test11: %d, %s, %d -- ", j, types, argv[0]->i); lo_message_pp(msg);});
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

    std::cout << "URL: " << st.get_url() << std::endl;

    init(st);

    st.start();

    lo_address a = lo_address_new("localhost", "9000");
    lo_send(a, "test1", "i", 20);
    lo_send(a, "test2", "i", 40);
    lo_send(a, "test3", "i", 60);
    lo_send(a, "test4", "i", 80);
    lo_send(a, "test5", "i", 100);
    lo_send(a, "test6", "i", 120);
    lo_send(a, "test7", "i", 140);
    lo_send(a, "test8", "i", 160);
    lo_send(a, "test9", "i", 180);
    lo_send(a, "test10", "i", 200);
    lo_send(a, "test11", "i", 220);
    lo_address_free(a);

    sleep(1);
}
