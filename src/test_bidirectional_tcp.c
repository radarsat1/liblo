
#include <stdio.h>
#include <lo/lo.h>
#include <pthread.h>
#include <stdlib.h>

int generic_handler(const char *path, const char *types, lo_arg ** argv,
                    int argc, lo_message data, void *user_data)
{
    lo_server s = (lo_server)user_data;
    lo_address a = lo_message_get_source(data);
    int prot = lo_address_get_protocol(a);

    printf("%p.%s, from %s:%s:%s\n", s, path,
           (prot==LO_UDP) ? "UDP"
           : (prot==LO_TCP) ? "TCP"
           : (prot==LO_UNIX) ? "UNIX" : "?",
           lo_address_get_hostname(a),
           lo_address_get_port(a));

    printf("%p.address fd: %d\n", s, ((int*)a)[1]);

    lo_send_from(a, s, LO_TT_IMMEDIATE, "/reply", 0);
    printf("%p.reply sent\n", s);

    return 0;
}

void *sendthread(void *arg)
{
    lo_server s = lo_server_new_with_proto("7772", LO_TCP, 0);
    if (!s) { printf("no server2\n"); exit(1); }

    printf("%p.sending thread\n", s);

    lo_server_add_method(s, 0, 0, generic_handler, s);

    lo_address a = lo_address_new_with_proto(LO_TCP, "localhost", "7771");

    lo_send_from(a, s, LO_TT_IMMEDIATE, "/test", 0);

    printf("%p.message sent\n", s);
    printf("%p.sending thread waiting\n", s);
    lo_server_recv(s);
    printf("%p.sending thread received\n", s);

    printf("%p.freeing address\n", s);
    lo_address_free(a);

    printf("%p.freeing\n", s);
    lo_server_free(s);

    return 0;
}

int main()
{
    /* start a new server on port 7770 */
    lo_server s = lo_server_new_with_proto("7771", LO_TCP, 0);
    if (!s) { printf("no server\n"); exit(1); }

    /* add method that will match any path and args */
    lo_server_add_method(s, 0, 0, generic_handler, s);

    printf("%p.server fd: %d\n", s, lo_server_get_socket_fd(s));

    pthread_t thr;
    pthread_create(&thr, 0, sendthread, s);

    printf("%p.receiving1..\n", s);
    lo_server_recv(s);
    printf("%p.done receiving1\n", s);

    printf("%p.receiving2..\n", s);
    lo_server_recv(s);
    printf("%p.done receiving2\n", s);

    pthread_join(thr, 0);

    printf("%p.freeing\n", s);
    lo_server_free(s);

    /* If it gets here without hanging we are good. */
    printf("TEST SUCCESSFUL\n");

    return 0;
}
