SUBDIRS = . tools

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = liblo.def.in

noinst_HEADERS = lo_types_internal.h lo_internal.h

SOURCE_FILES = address.c send.c message.c server.c method.c \
	blob.c bundle.c timetag.c pattern_match.c version.c

if ENABLE_THREADS
SOURCE_FILES += server_thread.c
endif

lib_LTLIBRARIES = liblo.la

if WINDOWS_DLL
lt_windows = -no-undefined -export-symbols liblo.def
endif

liblo_la_CFLAGS = -Wall -I$(top_srcdir)
liblo_la_SOURCES = $(SOURCE_FILES)
liblo_la_LDFLAGS  = $(lt_windows) -export-dynamic -version-info @LO_SO_VERSION@

# Test programs depend on server threads, so skip them if threads are
# disabled.
if ENABLE_THREADS
noinst_PROGRAMS = testlo subtest test_bidirectional_tcp
TESTS = testlo test_bidirectional_tcp
if HAVE_LAMBDA
noinst_PROGRAMS += cpp_test
TESTS += cpp_test
endif
endif

testlo_CFLAGS = -Wall -I$(top_srcdir)
testlo_SOURCES = testlo.c
testlo_LDADD = liblo.la

subtest_CFLAGS = -Wall -I$(top_srcdir)
subtest_SOURCES = subtest.c
subtest_LDADD = liblo.la

test_bidirectional_tcp_CFLAGS = -Wall -I$(top_srcdir)
test_bidirectional_tcp_SOURCES = test_bidirectional_tcp.c
test_bidirectional_tcp_LDADD = liblo.la

cpp_test_CXXFLAGS = -I$(top_srcdir)
cpp_test_SOURCES = cpp_test.cpp
cpp_test_LDADD = liblo.la

test: all
	for i in $(TESTS); do echo Running $$i; if ! ./$$i; then exit 1; fi; done

memtest: all
	LD_LIBRARY_PATH=.libs valgrind --tool=memcheck .libs/testlo
