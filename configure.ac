
AC_INIT(locust, 0.1)
AM_INIT_AUTOMAKE(locust, 0.1)

AC_REVISION($Revision$)

AC_CONFIG_HEADER(include/locust/autoconfig.h)

LOCUST_VERSION=`(build_scripts/gen_version_h .)`
AC_SUBST(LOCUST_VERSION)

AC_CONFIG_FILES([include/locust/version.h locust.conf])

AC_GNU_SOURCE
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

AC_PROG_MAKE_SET

BUILD_PLATFORM=${build}
BUILD_CPU=${build_cpu}
BUILD_VENDOR=${build_vendor}
BUILD_OS=${build_os}

AC_SUBST(BUILD_PLATFORM)
AC_SUBST(BUILD_CPU)
AC_SUBST(BUILD_VENDOR)
AC_SUBST(BUILD_OS)

MODULES_INSTALL_PATH=`(cd $srcdir && pwd)`/bin/modules
AC_SUBST(MODULES_INSTALL_PATH)

AC_ARG_ENABLE([dev-mode],
	[AS_HELP_STRING([--enable-dev-mode],
		[Turn on locust developer mode])],
	[case "${enableval}" in
	y|ye|yes)
		DEVMODE_CFLAGS=" -Werror"
		DEVMODE_CFLAGS+=" -Wunused"
		DEVMODE_CFLAGS+=" -Wundef"
		DEVMODE_CFLAGS+=" -DLOCUST_DEBUG"
		;;
	n|no)
		DEVMODE_CFLAGS=""
		;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-dev-mode)  ;;
	esac])
AC_SUBST(DEVMODE_CFLAGS)

locust_srcdir=`(cd $srcdir && pwd)`
AC_SUBST(locust_srcdir)

SOLINK="-shared -Xlinker -x"
SLINK="-Wl,--export-dynamic -Wl,--no-as-needed"

case "${host_os}" in
	freebsd*)
	OSARCH=FREEBSD
	;;
	netbsd*)
	OSARCH=NETBSD
	;;
	openbsd*)
	OSARCH=OPENBSD
	SOLINK="-shared -fpic"
	;;
	solaris*)
	OSARCH=SUNOS
	SOLINK="-shared -fpic -L/usr/local/ssl/lib -lrt"
	;;
	linux*)
	OSARCH=LINUX
	SLINK+=" -fpic -ldl"
	;;
	darwin*)
	OSARCH=DARWIN
	SOLINK="-dynamic -bundle -undefined suppress -force_flat_namespace"
	SLINK="-rdynamic"
	;;
	*)
	OSARCH=${host_os}
	;;
esac

AC_SUBST(SOLINK)
AC_SUBST(SLINK)
AC_SUBST(OSARCH)

AH_TOP(
#ifndef LOCUST_AUTOCONFIG_H
#define LOCUST_AUTOCONFIG_H
)

AH_BOTTOM(
#endif
)


AC_PROG_CC
AC_PROG_INSTALL

AC_LANG(C)

AC_FUNC_ALLOCA
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

AC_CHECK_FUNCS([strlcat strlcpy])

AC_CHECK_LIB(pthread, pthread_create, [], [
	echo "Error! You need to have pthread in order to run locust."
	exit -1
	])

# LIBEDIT
AC_ARG_ENABLE(libedit-support,
	[AS_HELP_STRING([--disable-libedit-support], [Compile locust without libedit Support])], [enable_libedit_support="$enableval"], [enable_libedit_support="yes"])
if test "$enable_libedit_support" = "yes"; then
	AC_CHECK_LIB(ncurses, tgetent,,
	[AC_CHECK_LIB(curses, tgetent,,
	[AC_MSG_ERROR([libtermcap, libcurses or libncurses are required if you want libedit support!])] )] )
fi
AM_CONDITIONAL([ADD_LIBEDIT],[test "x$enable_libedit_support" != "xno"])
if test "$enable_libedit_support" = "yes"; then
	AC_CONFIG_SUBDIRS(libs/libedit)
fi

# LIBPCAP
AC_ARG_ENABLE(libpcap-support,
	[AS_HELP_STRING([--disable-libpcap-support], [Compile locust without libpcap support])], [enable_libpcap_support="$enableval"], [enable_libpcap_support="yes"])
if test "$enable_libpcap_support" = "yes"; then
	AC_CHECK_PROGS(BISON,bison,none)
	AC_CHECK_PROGS(FLEX,flex,none)
	if test "$BISON" = "none"; then
		AC_MSG_ERROR([no suitable bison found. Please install the 'bison' package in order to compile libpcap or run the configure script with --disable-libpcap-support.])
	fi
	if test "$FLEX" = "none"; then
		AC_MSG_ERROR([no suitable flex found. Please install the 'flex' package in order to compile libpcap or run the configure script with --disable-libpcap-support.])
	fi
	AC_CONFIG_SUBDIRS(libs/libpcap)
fi
AM_CONDITIONAL([ADD_LIBPCAP],[test "x$enable_libpcap_support" != "xno"])

AC_CONFIG_SUBDIRS(libs/libconfig)
AC_CONFIG_SUBDIRS(libs/libnet)

AC_CONFIG_FILES([Makefile
		main/Makefile
		modules/scanners/Makefile
		modules/wordlists/Makefile
		])

AC_OUTPUT

