MAINTAINERCLEANFILES = Makefile.in

noinst_HEADERS = lo_types_internal.h

SOURCE_FILES = address.c send.c message.c server.c method.c \
	server_thread.c blob.c bundle.c

lib_LTLIBRARIES = liblo.la

liblo_la_CFLAGS = -Wall -I$(top_srcdir)
liblo_la_SOURCES = $(SOURCE_FILES)
liblo_la_LIBADD = -lpthread
liblo_la_LDFLAGS  = -export-dynamic -version-info @LO_SO_VERSION@

noinst_PROGRAMS = testlo

testlo_CFLAGS = -Wall -I$(top_srcdir)
testlo_SOURCES = testlo.c
testlo_LDADD = liblo.la

test: all
	./testlo
