SUBDIRS = src examples lo build @DOXYGEN@

EXTRA_DIST = libtool ltmain.sh autogen.sh

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liblo.pc

test: all
	(cd src && make test)
