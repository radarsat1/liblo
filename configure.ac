AC_PREREQ(2.57)

AC_INIT([liblo], [0.27], [liblo-devel@lists.sourceforge.net])

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
LO_SO_VERSION=8:0:1

AC_CONFIG_SRCDIR([src/address.c])
AM_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_ENABLE_STATIC(no)
AC_ENABLE_SHARED(yes)
AC_SUBST(LO_SO_VERSION)

# disable support for ipv6.
AC_ARG_ENABLE(ipv6, [  --enable-ipv6           Enable ipv6 support],[want_ipv6=$enableval],)
if test "$want_ipv6" = "yes"; then
	AC_DEFINE(ENABLE_IPV6, 1, Define this to enable ipv6.)
fi

# Checks for programs.
AC_PROG_CC
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL
AM_PROG_CC_C_O
AC_CHECK_PROG([DOXYGEN], [doxygen], [doc], [])
AC_SUBST(DOXYGEN)

# Check if threads are wanted
AC_ARG_ENABLE(threads,
  [  --enable-threads        Enable server threads],
  [want_threads=$enableval],
  [want_threads=yes])

# Checks for libraries.
AC_SEARCH_LIBS([recvfrom], [socket])
AC_CHECK_FUNC([log], [], [AC_CHECK_LIB([m],[log])])
AC_CHECK_FUNCS([getifaddrs])

# Check for whether threads are wanted, and if so, did we find libpthread.
if test "x$want_threads" = "xyes"; then
  AC_SEARCH_LIBS([pthread_create], [c pthread],
    [AS_IF([! test "$ac_res" = "-lc" && ! test "$ac_res" = "none required"],
           [LIBPTHREAD="$ac_res"])
     have_threads=yes;
     AC_DEFINE(ENABLE_THREADS, 1, [Define this to enable threads.])],
    [AC_ERROR([pthread not found. Try option --disable-threads.])])
fi

AC_SUBST(LIBPTHREAD)
AC_SUBST(DEFTHREADS)
AM_CONDITIONAL([ENABLE_THREADS], [test "x$have_threads" = xyes])
AS_IF([test x"$have_threads" = xyes],
      [AC_SUBST(ENABLE_THREADS,1)
       AC_SUBST(DEFTHREADS,)],
      [AC_SUBST(ENABLE_THREADS,0)
       AC_SUBST(DEFTHREADS,[';;'])])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Check for features
AC_CHECK_FUNC([select], [AC_DEFINE(HAVE_SELECT, [1], [Define to 1 if select() is available.])], [
     AC_MSG_CHECKING([for select in ws2_32])
     extralibs="-lws2_32 -liphlpapi"
     LIBS="$LIBS $extralibs"
     # some winsock2 functions require XP, so WINNT=0x501
     CFLAGS="$CFLAGS -DWIN32 -D_WIN32_WINNT=0x501"
     AC_TRY_LINK([#include <winsock2.h>],
                 [select(0,0,0,0,0)],
                 [AC_MSG_RESULT(yes)
                 AC_DEFINE(HAVE_SELECT, [1], [Define to 1 if select() is available.])
                 is_windows=yes],
                 [AC_MSG_RESULT(no)])
])
AC_CHECK_FUNC([poll], [AC_DEFINE(HAVE_POLL, [1], [Define to 1 if poll() is available.])])
AC_CHECK_FUNC([inet_pton], [AC_DEFINE(HAVE_INET_PTON, [1], [Define to 1 if inet_pton() is available.])])

AM_CONDITIONAL(WINDOWS, test x$is_windows = xyes)
AM_CONDITIONAL(WINDOWS_DLL, test x$is_windows = xyes && test x$enable_shared = xyes)

AC_C_BIGENDIAN([LO_BIGENDIAN="1"], [LO_BIGENDIAN="0"])
AC_DEFINE_UNQUOTED(LO_BIGENDIAN, "$LO_BIGENDIAN", [If machine is bigendian])
AC_SUBST(LO_BIGENDIAN)

AC_SUBST(extralibs)

# Enable debug compiler flags.  Treat all warnings as errors.
# Necessary to do this here, since -Werror causes problems with some
# autoconf tests used above.
AC_ARG_ENABLE(debug, [  --enable-debug          Enable debug compiler flags])
if test x"$enable_debug" = "xyes"; then
    CF=""
    for i in $CFLAGS; do
        if ! ((test x"$i" = x-g) || (test x"$i" = x-O2)); then
            CF="$CF $i"
        fi
    done
	CFLAGS="$CF -O0 -g -Wall -Werror"
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/tools/Makefile
	src/liblo.def
	examples/Makefile
	lo/Makefile
	lo/lo.h
	lo/lo_endian.h
	liblo.pc
	doc/Makefile
	doc/reference.doxygen
	build/Makefile
])
AC_OUTPUT()

if ! test "x$have_threads" = "xyes"; then
    echo "[[liblo]] Building with server threads disabled."
fi

if ! test "x$ac_cv_func_getifaddrs" = xyes && ! test x$is_windows = xyes; then
    echo "[[liblo]] Warning: Building without interface selection for multicast."
    echo "        This is unusual on Linux, Windows, and OS X, so make sure you"
    echo "        know what you're doing!  May be needed e.g. on Android."
fi
