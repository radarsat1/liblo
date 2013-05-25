/*
 * oscdump - Receive and dump OpenSound Control messages.
 *
 * Copyright (C) 2008 Kentaro Fukuchi <kentaro@fukuchi.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <config.h>
#include <lo/lo.h>

void usage(void)
{
    printf("oscdump version %s\n"
           "Copyright (C) 2008 Kentaro Fukuchi\n\n"
           "Usage: oscdump <port>\n"
           "or     oscdump <url>\n"
           "Receive OpenSound Control messages and dump to standard output.\n\n"
           "Description\n"
           "port    : specifies the listening port number.\n"
           "url     : specifies the server parameters using a liblo URL.\n"
           "          e.g. UDP        \"osc.udp://:9000\"\n"
           "               Multicast  \"osc.udp://224.0.1.9:9000\"\n"
           "               TCP        \"osc.tcp://:9000\"\n\n", VERSION);
}

void errorHandler(int num, const char *msg, const char *where)
{
    printf("liblo server error %d in path %s: %s\n", num, where, msg);
}

int messageHandler(const char *path, const char *types, lo_arg ** argv,
                   int argc, lo_message msg, void *user_data)
{
    int i;

    printf("%s %s", path, types);

    for (i = 0; i < argc; i++) {
        printf(" ");
        lo_arg_pp((lo_type) types[i], argv[i]);
    }
    printf("\n");

    return 0;
}

int main(int argc, char **argv)
{
    lo_server server;
    char *port=0, *group=0;

    if (argc > 1) {
        port = argv[1];
    } else {
        usage();
        exit(1);
    }

    if (argc > 2) {
        group = argv[2];
    }

    if (group) {
        server = lo_server_new_multicast(group, port, errorHandler);
    } else if (isdigit(port[0])) {
        server = lo_server_new(port, errorHandler);
    } else {
        server = lo_server_new_from_url(port, errorHandler);
    }

    if (server == NULL) {
        printf("Could not start a server with port %s", port);
        if (group)
            printf(", multicast group %s\n", group);
        else
            printf("\n");
        exit(1);
    }

    lo_server_add_method(server, NULL, NULL, messageHandler, NULL);


    for (;;) {
        lo_server_recv(server);
    }

    return 0;
}
