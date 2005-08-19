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

#ifdef WIN32
#define PATHDELIM "\\"
#else
#define PATHDELIM "/"
#endif

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
static int bundle_count = 0;
static int pattern_count = 0;
static int reply_count = 0;
static int subtest_count = 0;
static int subtest_reply_count = 0;

char testdata[5] = "ABCDE";

static int jitter_count = 0;
static float jitter_total = 0.0f;
static float jitter_max = 0.0f;
static float jitter_min = 1000.0f;

void exitcheck(void);

void error(int num, const char *m, const char *path);
void rep_error(int num, const char *m, const char *path);

int generic_handler(const char *path, const char *types, lo_arg **argv,
		    int argc, lo_message data, void *user_data);

int foo_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int reply_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int lots_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int coerce_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int bundle_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int jitter_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int pattern_handler(const char *path, const char *types, lo_arg **argv,
	            int argc, lo_message data, void *user_data);

int subtest_handler(const char *path, const char *types, lo_arg **argv,
	            int argc, lo_message data, void *user_data);

int subtest_reply_handler(const char *path, const char *types, lo_arg **argv,
	            int argc, lo_message data, void *user_data);

int quit_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data);

int main()
{
    lo_blob btest = lo_blob_new(sizeof(testdata), testdata);
    lo_server_thread st, sta, stb;
    lo_server s = lo_server_new(NULL, error);
    lo_bundle b;
    lo_message m1, m2;
    char *server_url, *path, *protocol, *host, *port;
    lo_address a;
    uint8_t midi_data[4] = {0xff, 0xf7, 0xAA, 0x00};
    union end_test32 et32;
    union end_test64 et64;
    lo_timetag tt = {0x1, 0x80000000}, sched;
    int count;
    char cmd[256];

    sta = lo_server_thread_new("7591", error);
    stb = lo_server_thread_new("7591", rep_error);
    if (stb) {
	fprintf(stderr, "FAILED: create bad server thread object!\n");
	exit(1);
    }
    lo_server_thread_free(sta);

    /* leak check */
    st = lo_server_thread_new(NULL, error);
    lo_server_thread_start(st);
#ifdef WIN32
    Sleep(4);
#else
    usleep(4000);
#endif
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

    a = lo_address_new_from_url("osc://localhost/");
    TEST(a != NULL);
    lo_address_free(a);

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
    
    protocol = lo_url_get_protocol("osc.udp://[::ffff:localhost]:9999/a/path/is/here");
    if (strcmp(protocol, "udp")) {
	printf("failed lo_url_get_protocol() test1\n");
	printf("'%s' != 'udp'\n", protocol);
	exit(1);
    } else {
	printf("passed lo_url_get_protocol() test (IPv6)\n");
    }
    free(protocol);

    host = lo_url_get_hostname("osc.udp://foo.example.com:9999/a/path/is/here");
    if (strcmp(host, "foo.example.com")) {
	printf("failed lo_url_get_hostname() test1\n");
	printf("'%s' != 'foo.example.com'\n", host);
	exit(1);
    } else {
	printf("passed lo_url_get_hostname() test1\n");
    }
    free(host);

    host = lo_url_get_hostname("osc.udp://[0000::::0001]:9999/a/path/is/here");
    if (strcmp(host, "0000::::0001")) {
	printf("failed lo_url_get_hostname() test2\n");
	printf("'%s' != '0000::::0001'\n", host);
	exit(1);
    } else {
	printf("passed lo_url_get_hostname() test2\n");
    }
    free(host);

    port = lo_url_get_port("osc.udp://localhost:9999/a/path/is/here");
    if (strcmp(port, "9999")) {
	printf("failed lo_url_get_port() test1\n");
	printf("'%s' != '9999'\n", port);
	exit(1);
    } else {
	printf("passed lo_url_get_port() test\n");
    }
    free(port);
    
    port = lo_url_get_port("osc.udp://[::ffff:127.0.0.1]:9999/a/path/is/here");
    if (strcmp(port, "9999")) {
	printf("failed lo_url_get_port() test1\n");
	printf("'%s' != '9999'\n", port);
	exit(1);
    } else {
	printf("passed lo_url_get_port() test (IPv6)\n");
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

    lo_server_thread_add_method(st, "/reply", "s", reply_handler, NULL);

    lo_server_thread_add_method(st, "/lotsofformats", "fisbmhtdSccTFNI",
				lots_handler, NULL);

    lo_server_thread_add_method(st, "/coerce", "dfhiSs",
				coerce_handler, NULL);

    lo_server_thread_add_method(st, "/bundle", NULL,
				bundle_handler, NULL);
    lo_server_thread_add_method(st, "/jitter", "ti",
				jitter_handler, NULL);

    lo_server_thread_add_method(st, "/pattern/foo", NULL,
				pattern_handler, "foo");
    lo_server_thread_add_method(st, "/pattern/bar", NULL,
				pattern_handler, "bar");
    lo_server_thread_add_method(st, "/pattern/baz", NULL,
				pattern_handler, "baz");

    lo_server_thread_add_method(st, "/subtest", "i",
				subtest_handler, NULL);

    lo_server_thread_add_method(st, "/subtest-reply", "i",
				subtest_reply_handler, NULL);

    /* add method that will match any path and args */
    lo_server_thread_add_method(st, NULL, NULL, generic_handler, NULL);

    /* add method that will match the path /quit with no args */
    lo_server_thread_add_method(st, "/quit", "", quit_handler, NULL);

    /* check that the thread restarts */
    lo_server_thread_start(st);
    lo_server_thread_stop(st);
    lo_server_thread_start(st);

    if (lo_send(a, "/foo/bar", "ff", 0.12345678f, 23.0f) == -1) {
	printf("OSC error A %d: %s\n", lo_address_errno(a), lo_address_errstr(a));
	exit(1);
    }

    if (lo_send(a, "/foo/bar", "ff", 0.12345678f, 23.0f) == -1) {
	printf("OSC error B %d: %s\n", lo_address_errno(a), lo_address_errstr(a));
	exit(1);
    }

    lo_send(a, "/", "i", 242);
    lo_send(a, "/pattern/", "i", 243);

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

    lo_send(a, "/pattern/*", "s", "a");
    lo_send(a, "/pattern/ba[rz]", "s", "b");

    server_url = lo_server_thread_get_url(st);
    sprintf(cmd, "." PATHDELIM "subtest %s &", server_url);
    if (system(cmd) != 0) {
	fprintf(stderr, "Cannot execute subtest command\n");
	exit(1);
    }
    system(cmd);

#ifdef WIN32
    Sleep(2000);
#else
    sleep(2);
#endif
    TEST(reply_count == 2);
    TEST(pattern_count == 5);
    TEST(subtest_count == 2);
    TEST(subtest_reply_count == 22);
    printf("\n");

    b = lo_bundle_new((lo_timetag){10,0xFFFFFFFC});
    m1 = lo_message_new();
    lo_message_add_string(m1, "abcdefghijklmnopqrstuvwxyz");
    lo_message_add_string(m1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    lo_bundle_add_message(b, "/bundle", m1);
    lo_send_bundle(a, b);
    lo_message_free(m1);
    lo_bundle_free(b);

    b = lo_bundle_new((lo_timetag){1,2});
    m1 = lo_message_new();
    lo_message_add_int32(m1, 23);
    lo_message_add_string(m1, "23");
    lo_bundle_add_message(b, "/bundle", m1);
    m2 = lo_message_new();
    lo_message_add_string(m2, "24");
    lo_message_add_int32(m2, 24);
    lo_bundle_add_message(b, "/bundle", m2);

/* 
    lo_send_bundle(a, b);
    if (a->errnum) {
	printf("error %d: %s\n", a->errnum, a->errstr);
	exit(1);
    }
*/
    TEST(lo_send_bundle(a, b) == 64);

    lo_message_free(m1);
    lo_message_free(m2);
    lo_bundle_free(b);

    b = lo_bundle_new((lo_timetag){10,0xFFFFFFFE});
    m1 = lo_message_new();
    lo_message_add_string(m1, "abcdefghijklmnopqrstuvwxyz");
    lo_message_add_string(m1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    lo_bundle_add_message(b, "/bundle", m1);
    lo_send_bundle(a, b);
    lo_message_free(m1);
    lo_bundle_free(b);

    lo_timetag_now(&sched);

    sched.sec += 5;
    b = lo_bundle_new(sched);
    m1 = lo_message_new();
    lo_message_add_string(m1, "future");
    lo_message_add_string(m1, "time");
    lo_message_add_string(m1, "test");
    lo_bundle_add_message(b, "/bundle", m1);

    lo_send_bundle(a, b);
    lo_message_free(m1);
    lo_bundle_free(b);

    lo_send_timestamped(a, sched, "/bundle", "s", "lo_send_timestamped() test");

#define JITTER_ITS 25
    /* jitter tests */
    {
	lo_timetag stamps[JITTER_ITS];
	lo_timetag now;
	int i;

	for (i=0; i<JITTER_ITS; i++) {
	    lo_timetag_now(&now);
	    stamps[i] = now;
	    stamps[i].sec += 1;
	    stamps[i].frac = rand();
	    lo_send_timestamped(a, stamps[i], "/jitter", "ti", stamps[i], i);
	}
    }

#ifdef WIN32
    Sleep(2000);
#else
    sleep(2);
#endif

    lo_address_free(a);

    TEST(lo_server_thread_events_pending(st));

    while (lo_server_thread_events_pending(st)) {
	printf("pending events, wait...\n");
#ifdef WIN32
	fflush(stdout);
	Sleep(1000);
#else
	sleep(1);
#endif
    }
    
    TEST(bundle_count == 6);
    printf("\n");

    printf("bundle timing jitter results:\n"
	   "max jitter = %fs\n"
	   "avg jitter = %fs\n"
           "min jitter = %fs\n\n",
           jitter_max, jitter_total/(float)jitter_count, jitter_min);

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

    /* Delete methods */
    lo_server_thread_del_method(st, "/coerce", "dfhiSs");
    lo_server_del_method(s, NULL, NULL);

    lo_address_free(a);
    lo_server_free(s);
    free(server_url);

#ifndef WIN32
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
#endif

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
#ifdef WIN32
    Sleep(1);
#else
	usleep(1000);
#endif
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
    lo_address src = lo_message_get_source(data);
    char *url = lo_address_get_url(src);
    printf("%s <- f:%f, i:%d\n", path, argv[0]->f, argv[1]->i);
    if (lo_send(src, "/reply", "s", "a reply") == -1) {
	printf("OSC reply error %d: %s\nSending to %s\n", lo_address_errno(src), lo_address_errstr(src), url);
	exit(1);
    } else {
	printf("Reply sent to %s\n\n", url);
    }
    free(url);

    return 0;
}

int reply_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data)
{
    printf("Reply received\n");
    reply_count++;

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
printf("char: %d\n", argv[9]->c);
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

int bundle_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data)
{
    bundle_count++;
    printf("received bundle\n");

    return 0;
}

int jitter_handler(const char *path, const char *types, lo_arg **argv, int argc,
                 lo_message data, void *user_data)
{
    lo_timetag now;
    float jitter;

    lo_timetag_now(&now);
    jitter = fabs(lo_timetag_diff(now, argv[0]->t));
    jitter_count++;
    //printf("jitter: %f\n", jitter);
    printf("%d expected: %x:%x received %x:%x\n", argv[1]->i, argv[0]->t.sec,
	   argv[0]->t.frac, now.sec, now.frac);
    jitter_total += jitter;
    if (jitter > jitter_max) jitter_max = jitter;
    if (jitter < jitter_min) jitter_min = jitter;

    return 0;
}

int pattern_handler(const char *path, const char *types, lo_arg **argv,
		    int argc, lo_message data, void *user_data)
{
    pattern_count++;
    printf("pattern matched %s\n", (char *)user_data);

    return 0;
}

int subtest_handler(const char *path, const char *types, lo_arg **argv,
		    int argc, lo_message data, void *user_data)
{
    lo_address a = lo_message_get_source(data);

    subtest_count++;
    printf("got subtest message %d\n", subtest_count);
    lo_send(a, "/subtest", "i", subtest_count);

    return 0;
}

int subtest_reply_handler(const char *path, const char *types, lo_arg **argv,
		    int argc, lo_message data, void *user_data)
{
    subtest_reply_count++;
    //printf("got subtest reply message %d\n", subtest_reply_count);

    return 0;
}

int quit_handler(const char *path, const char *types, lo_arg **argv, int argc,
		 lo_message data, void *user_data)
{
    done = 1;

    return 0;
}

/* vi:set ts=8 sts=4 sw=4: */
