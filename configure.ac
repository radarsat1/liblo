AC_PREREQ(2.57)

AC_INIT([liblo], [0.24], [liblo-devel@lists.sourceforge.net])

# libtool version: current:revision:age
#
# If the library source code has changed at all since the last update, then
# increment revision (`c:r:a' becomes `c:r+1:a').
#
# If any interfaces have been added, removed, or changed since the last update,
# increment current, and set revision to 0.
#
# If any interfaces have been added since the last public release, then
# increment age.
#
# If any interfaces have been removed since the last public release, then set
# age to 0.
LO_SO_VERSION=6:0:6

AC_CONFIG_SRCDIR([src/address.c])
AM_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE

AC_ENABLE_STATIC(no)
AC_ENABLE_SHARED(yes)
AC_SUBST(LO_SO_VERSION)

# disable support for ipv6.
AC_ARG_ENABLE(ipv6, [  --enable-ipv6           Enable ipv6 support],want_ipv6=yes,)
if test "$want_ipv6" = "yes"; then
	AC_DEFINE(ENABLE_IPV6, 1, Define this to enable ipv6.)
fi

# Checks for programs.
AC_PROG_CC
AM_PROG_LIBTOOL
AC_CHECK_PROG([DOXYGEN], [doxygen], [doc], [])
AC_SUBST(DOXYGEN)

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
AC_SEARCH_LIBS([recvfrom], [socket])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

AC_C_BIGENDIAN([LO_BIGENDIAN="1"], [LO_BIGENDIAN="0"])
AC_DEFINE_UNQUOTED(LO_BIGENDIAN, "$LO_BIGENDIAN", [If machine is bigendian])
AC_SUBST(LO_BIGENDIAN)

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	examples/Makefile
	lo/Makefile
	lo/lo_endian.h
	liblo.pc
	doc/Makefile
	doc/reference.doxygen
])
AC_OUTPUT()
