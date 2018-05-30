bin_PROGRAMS = locust
bindir = $(top_srcdir)/bin
locustdir=$(top_srcdir)/bin

LOCUST_SOURCE = locust.c \
		tcp.c \
		ip.c \
		icmp.c \
		ethernet.c \
		payload.c \
		logger.c \
		socket.c \
		string.c \
		cli.c \
		compat.c \
		netutils.c \
		loader.c \
		version.c \
		udp.c \
		thread.c \
		scanner.c \
		config.c \
		simclist.c \
		wordlist.c \
		sniffer.c \
		packet.c \
		route.c

locust_SOURCES = $(LOCUST_SOURCE)
locust_DATA = $(top_srcdir)/locust.conf

INCLUDES = -I../include
DEFAULT_INCLUDES = -I.

locust_CFLAGS = -Wall -std=c99 -g3 -ggdb $(DEVMODE_CFLAGS) -D__$(OSARCH)__
locust_LDFLAGS = $(SLINK)
locust_LDADD =
MAIN_LIBS =

# LIBEDIT
if ADD_LIBEDIT
locust_CFLAGS += -I$(top_srcdir)/libs/libedit/src -DHAVE_LIBEDIT 
locust_LDADD += $(top_srcdir)/libs/libedit/src/.libs/libedit.a
MAIN_LIBS += $(top_srcdir)/libs/libedit/src/.libs/libedit.a 
endif
$(top_srcdir)/libs/libedit/src/.libs/libedit.a:
	cd $(top_srcdir)/libs/libedit && $(MAKE)

# LIBCONFIG
locust_CFLAGS += -I$(top_srcdir)/libs/libconfig
locust_LDADD += $(top_srcdir)/libs/libconfig/.libs/libconfig.a
MAIN_LIBS += $(top_srcdir)/libs/libconfig/.libs/libconfig.a
$(top_srcdir)/libs/libconfig/.libs/libconfig.a:
	cd $(top_srcdir)/libs/libconfig && $(MAKE)

# LIBNET
locust_CFLAGS += -I$(top_srcdir)/libs/libnet/include
locust_LDADD += $(top_srcdir)/libs/libnet/src/libnet.a
MAIN_LIBS += $(top_srcdir)/libs/libnet/src/libnet.a
$(top_srcdir)/libs/libnet/src/libnet.a:
	cd $(top_srcdir)/libs/libnet && $(MAKE)

# LIBPCAP
if ADD_LIBPCAP
locust_CFLAGS += -I$(top_srcdir)/libs/libpcap -DHAVE_LIBPCAP
locust_LDADD += $(top_srcdir)/libs/libpcap/libpcap.a
MAIN_LIBS += $(top_srcdir)/libs/libpcap/libpcap.a
$(top_srcdir)/libs/libpcap/libpcap.a:
	cd $(top_srcdir)/libs/libpcap && $(MAKE)
endif

$(locust_SOURCE): $(MAIN_LIBS)

