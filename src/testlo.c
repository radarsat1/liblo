/*
 *  Copyright (C) 2004 Steve Harris
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

/*
 * This is some testcase code - it exercises the internals of liblo, so its not
 * a good example to learn from, see examples/ for example code
 */

#include <math.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "lo_types_internal.h"
#include "lo/lo.h"
#include "config.h"

#define TEST(cond) if (!(cond)) { fprintf(stderr, "FAILED " #cond \
					  " at %s:%d\n", __FILE__, __LINE__); \
				  exit(1); } \
		   else { printf("passed " #cond "\n"); }

union end_test32 {
    uint32_t i;
    char     c[4];
};

union end_test64 {
    uint64_t i;
    char     c[8];
};

static int done = 0;

char testdata[5] = "ABCDE";

void exitcheck(void);

void error(int num, const char *m, const char *path);
void rep_error(int num, const char *m, const char *path);

int generic_handler(const char *path, const char *types, lo_arg **argv,
		    int argc, lo_message data, void *user_data);

int foo_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int lots_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int coerce_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int quit_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int main()
{
    lo_blob btest = lo_blob_new(sizeof(testdata), testdata);
    lo_server_thread st, sta, stb;
    lo_server s = lo_server_new(NULL, error);
    lo_bundle b;
    lo_message m;
    char *server_url, *path, *protocol, *port;
    lo_address a;
    uint8_t midi_data[4] = {0xff, 0xf7, 0xAA, 0x00};
    union end_test32 et32;
    union end_test64 et64;
    lo_timetag tt = {0x1, 0x80000000};
    int count;

    /* leak check */
    st = lo_server_thread_new(NULL, error);
    lo_server_thread_start(st);
    usleep(4000);
    lo_server_thread_stop(st);
    lo_server_thread_free(st);
    st = lo_server_thread_new(NULL, error);
    lo_server_thread_start(st);
    lo_server_thread_stop(st);
    lo_server_thread_free(st);
    st = lo_server_thread_new(NULL, error);
    lo_server_thread_free(st);
    st = lo_server_thread_new(NULL, error);
    lo_server_thread_free(st);
    st = lo_server_thread_new(NULL, error);

    sta = lo_server_thread_new("7591", error);
    stb = lo_server_thread_new("7591", rep_error);
    if (stb) {
	fprintf(stderr, "FAILED: create bad server thread object!\n");
	exit(1);
    }
    lo_server_thread_free(sta);

    server_url = lo_server_thread_get_url(st);
    a = lo_address_new_from_url(server_url);
    printf("Server URL: %s\n", server_url);
    free(server_url);

    atexit(exitcheck);


    printf("type tests\n");
    TEST(sizeof(float) == sizeof(int32_t));
    TEST(sizeof(double) == sizeof(int64_t));

    et32.i = 0x23242526U;
    et32.i = lo_htoo32(et32.i);
    if (et32.c[0] != 0x23 || et32.c[1] != 0x24 || et32.c[2] != 0x25 ||
	et32.c[3] != 0x26) {
	fprintf(stderr, "failed 32bit endian conversion test\n");
	fprintf(stderr, "0x23242526 -> %X\n", et32.i);
	exit(1);
    } else {
	printf("passed 32bit endian conversion test\n");
    }

    et64.i = 0x232425262728292AULL;
    et64.i = lo_htoo64(et64.i);
    if (et64.c[0] != 0x23 || et64.c[1] != 0x24 || et64.c[2] != 0x25 ||
	et64.c[3] != 0x26 || et64.c[4] != 0x27 || et64.c[5] != 0x28 ||
	et64.c[6] != 0x29 || et64.c[7] != 0x2A) {
	fprintf(stderr, "failed 64bit endian conversion\n");
	fprintf(stderr, "0x232425262728292A -> %llX\n", et64.i);
	exit(1);
    } else {
	printf("passed 64bit endian conversion\n");
    }
    printf("\n");

    /* OSC URL tests */
    path = lo_url_get_path("osc.udp://localhost:9999/a/path/is/here");
    if (strcmp(path, "/a/path/is/here")) {
	printf("failed lo_url_get_path() test1\n");
	printf("'%s' != '/a/path/is/here'\n", path);
	exit(1);
    } else {
	printf("passed lo_url_get_path() test\n");
    }
    free(path);

    protocol = lo_url_get_protocol("osc.udp://localhost:9999/a/path/is/here");
    if (strcmp(protocol, "udp")) {
	printf("failed lo_url_get_protocol() test1\n");
	printf("'%s' != 'udp'\n", protocol);
	exit(1);
    } else {
	printf("passed lo_url_get_protocol() test\n");
    }
    free(protocol);

    port = lo_url_get_port("osc.udp://localhost:9999/a/path/is/here");
    if (strcmp(port, "9999")) {
	printf("failed lo_url_get_port() test1\n");
	printf("'%s' != '9999'\n", port);
	exit(1);
    } else {
	printf("passed lo_url_get_port() test\n");
    }
    free(port);
    printf("\n");


    if (lo_blob_datasize(btest) != 5 || lo_blobsize(btest) != 12) {
	printf("blob is %d (%d) bytes long, should be 5 (12)\n",
               lo_blob_datasize(btest), lo_blobsize(btest));
	lo_arg_pp(LO_BLOB, btest);
	printf(" <- blob\n");
	exit(1);
    }

    /* add method that will match the path /foo/bar, with two numbers, coerced
     * to float and int */
    lo_server_thread_add_method(st, "/foo/bar", "fi", foo_handler, NULL);

    lo_server_thread_add_method(st, "/lotsofformats", "fisbmhtdSccTFNI",
				lots_handler, NULL);

    lo_server_thread_add_method(st, "/coerce", "dfhiSs",
				coerce_handler, NULL);

    /* add method that will match any path and args */
    lo_server_thread_add_method(st, NULL, NULL, generic_handler, NULL);

    /* add method that will match the path /quit with no args */
    lo_server_thread_add_method(st, "/quit", "", quit_handler, NULL);

    /* check that the thread restarts */
    lo_server_thread_start(st);
    lo_server_thread_stop(st);
    lo_server_thread_start(st);

    if (lo_send(a, "/foo/bar", "ff", 0.12345678f, 23.0f) == -1) {
	printf("OSC error %d: %s\n", lo_address_errno(a), lo_address_errstr(a));
    }
    lo_send(a, "/bar", "ff", 0.12345678f, 1.0/0.0);
    lo_send(a, "/lotsofformats", "fisbmhtdSccTFNI", 0.12345678f, 123, "123",
	    btest, midi_data, 0x0123456789abcdefULL, tt, 0.9999, "sym",
	    'X', 'Y');
    lo_send(a, "/coerce", "fdihsS", 0.1f, 0.2, 123, 124LL, "aaa", "bbb");
    lo_send(a, "/coerce", "ffffss", 0.1f, 0.2f, 123.0, 124.0, "aaa", "bbb");
    lo_send(a, "/coerce", "ddddSS", 0.1, 0.2, 123.0, 124.0, "aaa", "bbb");
    lo_send(a, "/a/b/c/d", "sfsff", "one", 0.12345678f, "three",
	    -0.00000023001f, 1.0);
    lo_send(a, "/a/b/c/d", "b", btest);
    lo_blob_free(btest);

    b = lo_bundle_new((lo_timetag){1,2});
    m = lo_message_new();
    lo_message_add_int32(m, 23);
    lo_message_add_string(m, "23");
    lo_bundle_add_message(b, "/foo", m);
    TEST(lo_send_bundle(a, b) == 40);

    lo_address_free(a);
    
    server_url = lo_server_get_url(s);
    lo_server_add_method(s, NULL, NULL, generic_handler, NULL);
    a = lo_address_new_from_url(server_url);
    TEST(lo_server_recv_noblock(s, 0) == 0);
    printf("Testing noblock API on %s\n", server_url);
    lo_send(a, "/non-block-test", "f", 23.0);

    count = 0;
    while (!lo_server_recv_noblock(s, 10) && count++ < 1000) { }
    if (count >= 1000) {
	printf("lo_server_recv_noblock() test failed\n");

	exit(1);
    }

    lo_address_free(a);
    lo_server_free(s);
    free(server_url);

    { /* UNIX domain tests */
	lo_address ua;
	lo_server us;
	char *addr;

	unlink("/tmp/testlo.osc");
	us = lo_server_new_with_proto("/tmp/testlo.osc", LO_UNIX, error);
	ua = lo_address_new_from_url("osc.unix:///tmp/testlo.osc");
	TEST(lo_send(ua, "/unix", "f", 23.0) == 16);
	TEST(lo_server_recv(us) == 16);
	addr = lo_server_get_url(us);
	TEST(!strcmp("osc.unix:////tmp/testlo.osc", addr));
	free(addr);
	lo_server_free(us);
	lo_address_free(ua);
    }

    { /* TCP tests */
	lo_address ta;
	lo_server ts;
	char *addr;

	ts = lo_server_new_with_proto(NULL, LO_TCP, error);
	addr = lo_server_get_url(ts);
	ta = lo_address_new_from_url(addr);
	if (lo_address_errno(ta)) {
	    printf("err: %s\n", lo_address_errstr(ta));
	    exit(1);
	}
	if (lo_address_errno(ta)) {
	    printf("err: %s\n", lo_address_errstr(ta));
	    exit(1);
	}
	TEST(lo_send(ta, "/tcp", "f", 23.0) == 16);
	TEST(lo_send(ta, "/tcp", "f", 23.0) == 16);
	TEST(lo_server_recv(ts) == 16);
	TEST(lo_server_recv(ts) == 16);
	free(addr);
	lo_server_free(ts);
	lo_address_free(ta);
    }

    server_url = lo_server_thread_get_url(st);
    a = lo_address_new_from_url(server_url);
    /* exit */
    lo_send(a, "/quit", NULL);
    lo_address_free(a);

    while (!done) {
	usleep(1000);
    }

    lo_server_thread_free(st);
    free(server_url);

    return 0;
}

void exitcheck(void)
{
    if (!done) {
	fprintf(stderr, "\ntest run not completed\n" PACKAGE_NAME
		" test FAILED\n");
    } else {
	printf(PACKAGE_NAME " test PASSED\n");
    }
}

void error(int num, const char *msg, const char *path)
{
    printf("liblo server error %d in %s: %s\n", num, path, msg);
    exit(1);
}

void rep_error(int num, const char *msg, const char *path)
{
    if (num != 9904) {
	error(num, msg, path);
    }
}

int generic_handler(const char *path, const char *types, lo_arg **argv,
		    int argc, lo_message data, void *user_data)
{
    int i;

    printf("path: <%s>\n", path);
    for (i=0; i<argc; i++) {
	printf("arg %d '%c' ", i, types[i]);
	lo_arg_pp(types[i], argv[i]);
	printf("\n");
    }
    printf("\n");

    return 1;
}

int foo_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data)
{
    printf("%s <- f:%f, i:%d\n\n", path, argv[0]->f, argv[1]->i);

    return 0;
}

int lots_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data)
{
    lo_blob b;
    unsigned char *d;

    if (strcmp(path, "/lotsofformats")) {
	fprintf(stderr, "path != /lotsofformats\n");
	exit(1);
    }
    printf("path = %s\n", path);
    TEST(types[0] == 'f' && argv[0]->f == 0.12345678f);
    TEST(types[1] == 'i' && argv[1]->i == 123);
    TEST(types[2] == 's' && !strcmp(&argv[2]->s, "123"));
    b = (lo_blob)argv[3];
    d = lo_blob_dataptr(b);
    TEST(types[3] == 'b' && lo_blob_datasize(b) == 5);
    TEST(d[0] == 'A' && d[1] == 'B' && d[2] == 'C' && d[3] == 'D' &&
	 d[4] == 'E');
    d = argv[4]->m;
    TEST(d[0] == 0xff && d[1] == 0xf7 && d[2] == 0xaa && d[3] == 0x00);
    TEST(types[5] == 'h' && argv[5]->h == 0x0123456789ABCDEFULL);
    TEST(types[6] == 't' && argv[6]->t.sec == 1 && \
	 argv[6]->t.frac == 0x80000000);
    TEST(types[7] == 'd' && argv[7]->d == 0.9999);
    TEST(types[8] == 'S' && !strcmp(&argv[8]->S, "sym"));
    TEST(types[9] == 'c' && argv[9]->c == 'X');
    TEST(types[10] == 'c' && argv[10]->c == 'Y');
    TEST(types[11] == 'T');
    TEST(types[12] == 'F');
    TEST(types[13] == 'N');
    TEST(types[14] == 'I');

    printf("\n");

    return 0;
}

int coerce_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data)
{
    printf("path = %s\n", path);
    TEST(types[0] == 'd' && fabs(argv[0]->d - 0.1) < FLT_EPSILON);
    TEST(types[1] == 'f' && fabs(argv[1]->f - 0.2) < FLT_EPSILON);
    TEST(types[2] == 'h' && argv[2]->h == 123);
    TEST(types[3] == 'i' && argv[3]->i == 124);
    TEST(types[4] == 'S' && !strcmp(&argv[4]->S, "aaa"));
    TEST(types[5] == 's' && !strcmp(&argv[5]->s, "bbb"));
    printf("\n");

    return 0;
}

int quit_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data)
{
    done = 1;

    return 0;
}

/* vi:set ts=8 sts=4 sw=4: */
