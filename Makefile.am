SUBDIRS = src examples lo @DOXYGEN@

EXTRA_DIST = libtool ltmain.sh autogen.sh

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liblo.pc

test: all
	./src/testlo
