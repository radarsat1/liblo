/*
 *  Copyright (C) 2005 Steve Harris
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

#include <stdio.h>
#include <stdlib.h>

#include "lo/lo.h"

int subtest_handler(const char *path, const char *types, lo_arg **argv,
                    int argc, lo_message data, void *user_data);

int main(int argc, char *argv[])
{
    lo_server st = lo_server_thread_new(NULL, NULL);
    lo_address t;
   
    if (argc != 2) {
	fprintf(stderr, "Usage: subtest <uri>\n");

	return 1;
    }

    lo_server_thread_add_method(st, NULL, "i", subtest_handler, NULL);
    lo_server_thread_start(st);

    t = lo_address_new_from_url(argv[1]);
    lo_send(t, "/subtest", "i", 0xf00);

    sleep(4);

    return 0;
}

int subtest_handler(const char *path, const char *types, lo_arg **argv,
                    int argc, lo_message data, void *user_data)
{
    lo_address a = lo_message_get_source(data);

    printf("subtest: got reply (%s)\n", path);
    lo_send(a, "/subtest-reply", "i", 0xbaa);
    if (lo_address_errno(a)) {
	fprintf(stderr, "subtest error %d: %s\n", lo_address_errno(a), lo_address_errstr(a));

	exit(1);
    }
}

/* vi:set ts=8 sts=4 sw=4: */
