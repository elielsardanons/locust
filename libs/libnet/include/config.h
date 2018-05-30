/* include/config.h.  Generated from config.h.in by configure.  */
/* include/config.h.in.  Generated from configure.in by autoheader.  */
/*
dnl $Id: acconfig.h,v 1.2 2004/01/03 20:31:00 mike Exp $
dnl
dnl Libnet autoconfiguration acconfig.h file
dnl Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
dnl All rights reserved.
dnl
dnl Process this file with autoheader to produce a config.h file.
dnl
*/

/* #undef LIBNET_BSDISH_OS */
/* #undef LIBNET_BSD_BYTE_SWAP */
/* #undef DLPI_DEV_PREFIX */
/* #undef HAVE_DEV_DLPI */
/* #undef HAVE_SOLARIS */
/* #undef HAVE_SOLARIS_IPV6 */
/* #undef HAVE_HPUX11 */
/* #undef HAVE_SOCKADDR_SA_LEN */
/* #undef HAVE_DLPI */
#define HAVE_PACKET_SOCKET 1
/* #undef HAVE_STRUCT_IP_CSUM */
/* #undef HAVE_LIB_PCAP */
/* #undef LBL_ALIGN */
/* #undef STUPID_SOLARIS_CHECKSUM_BUG */
#define _BSD_SOURCE 1
#define __BSD_SOURCE 1
#define __FAVOR_BSD 1
/* #undef LIBNET_BIG_ENDIAN */
#define LIBNET_LIL_ENDIAN 1
/* #undef NO_SNPRINTF */


/*
dnl EOF
*/

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `nsl' library (-lnsl). */
/* #undef HAVE_LIBNSL */

/* Define to 1 if you have the `packet' library (-lpacket). */
/* #undef HAVE_LIBPACKET */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the `wpcap' library (-lwpcap). */
/* #undef HAVE_LIBWPCAP */

/* Define if you have the Linux /proc filesystem. */
#define HAVE_LINUX_PROCFS 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <net/ethernet.h> header file. */
#define HAVE_NET_ETHERNET_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/bufmod.h> header file. */
/* #undef HAVE_SYS_BUFMOD_H */

/* Define to 1 if you have the <sys/dlpi_ext.h> header file. */
/* #undef HAVE_SYS_DLPI_EXT_H */

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Name of package */
#define PACKAGE "libnet"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "1.1.2.1"
