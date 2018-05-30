/*
 * Locust - The Network security framework
 *
 * Copyright (C) 2009  Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*!
 * \file
 * \brief TCP abstraction layer.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>
#include <locust/config.h>
#include <locust/socket.h>
#include <locust/cli.h>
#include <locust/packet.h>
#include <locust/ip.h>

#define __FAVOR_BSD
#include <netinet/tcp.h>

#define FLAG_SET(value, flag) (((value & flag) != 0) ? 1 : 0)

/*!
 * \internal
 * \brief Max connection can connect to a socket binded to a port.
 */
static int max_bind_connections = 30;

/*!
 * \internal
 * \brief The accepted header modifiers.
 */
static const char *header_modifiers[] = { "src", "dst", "seq", "ack", "setflag", "unsetflag", "win", "offset", NULL };

/*!
 * \internal
 * \brief Fake header used to calculate TCP checksum using IPv4.
 */
struct tcp_checksum_header {
	/*! The IP source address. */
	unsigned long saddr;
	/*! The IP destination address. */
	unsigned long daddr;
	/*! 8bits Padding. */
	char dummy;
	/*! Protocol id (TCP). */
	unsigned char protocol;
	/*! The tcp header len. */
	unsigned short len;
	/*! The TCP header. */
	struct tcphdr tcp;
	/*! data */
	char payload[LCT_MAX_PACKET_SIZE];
};

/*!
 * \internal
 * \brief Fake header used to calculate TCP checksum using IPv6.
 */
struct tcp_checksum_header6 {
	/*! The IP source address. */
	unsigned long saddr[4];
	/*! The IP destination address. */
	unsigned long daddr[4];
	/*! TCP len */
	unsigned long len;
	/*! 8bits Padding. */
	unsigned char padding[3];
	/*! Protocol id (TCP). */
	unsigned char nextheader;
	/*! The TCP header. */
	struct tcphdr tcp;
	/*! data */
	char payload[LCT_MAX_PACKET_SIZE];
};

struct lct_socket *lct_tcp_simple_connect(const char *ip, unsigned short port, int timeout, void *(*owner)(void *))
{
	struct lct_socket *sock;
	int res, valopt;
	long opt;
	struct timeval tv;
	fd_set sckset;

	sock = lct_socket_create(ip, SOCK_STREAM, port);
	if (!sock) {
		return NULL;
	}

	/* Setting socket as non-blocking */
	if ((opt = fcntl(sock->sck, F_GETFL, NULL)) < 0) {
		lct_log(LCT_ERROR, "Error getting socket options (%s)\n", strerror(errno));
		lct_socket_release(sock);
		return NULL;
	}
	opt |= O_NONBLOCK;
	if (fcntl(sock->sck, F_SETFL, opt) < 0) {
		lct_log(LCT_ERROR, "Error setting socket as non-blocking (%s)\n", strerror(errno));
		lct_socket_release(sock);
		return NULL;
	}

	res = connect(sock->sck, sock->addr, sock->addrlen);
	if (res < 0 && errno == EINPROGRESS) {
		do {
			tv.tv_sec = timeout;
			tv.tv_usec = 0;
			FD_ZERO(&sckset);
			FD_SET(sock->sck, &sckset);
			/* If timeout < 0, then we won't timeout. */
			if (timeout < 0) {
				res = select(sock->sck + 1, NULL, &sckset, NULL, NULL);
			} else {
				res = select(sock->sck + 1, NULL, &sckset, NULL, &tv);
			}
			if (res < 0 && errno != EINTR) {
				lct_socket_release(sock);
				return NULL;
			} else if (res > 0) {
				socklen_t lon = sizeof(int);
				if (getsockopt(sock->sck, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon) < 0) {
					lct_socket_release(sock);
					return NULL;
				}
				if (valopt) {
					lct_socket_release(sock);
					return NULL;
				}
				break;
			} else {
				lct_socket_release(sock);
				return NULL;
			}
		} while (1);
	} else if (res < 0) {
		lct_log(LCT_DEBUG, "Error while connecting (%s) to %s\n", strerror(errno), lct_socket_ip(sock));
		lct_socket_release(sock);
		return NULL;
	}

	/* setting to blocking mode again */
	if ((opt = fcntl(sock->sck, F_GETFL, NULL)) < 0) {
		lct_log(LCT_ERROR, "Error getting socket options\n");
		lct_socket_release(sock);
		return NULL;
	}
	opt &= (~O_NONBLOCK);
	if (fcntl(sock->sck, F_SETFL, opt) < 0) {
		lct_log(LCT_ERROR, "Error setting socket to blocking: (%s)\n", strerror(errno));
		lct_socket_release(sock);
		return NULL;
	}

	sock->status = LCT_SOCKET_CONNECTED;

	if (owner) {
		/* attach thread if a function is specified. */
		lct_thread_detached(THREAD_CORE, &sock->owner, owner, sock);
	}

	return sock;
}

void lct_tcp_simple_close(struct lct_socket *sock)
{
	lct_socket_close(sock);
}

struct lct_socket *lct_tcp_simple_bind(const char *ip, int type, int port, void *(*listener)(void *))
{
	struct lct_socket *sock;

	sock = lct_socket_create(ip, type, port);
	if (!sock) {
		return NULL;
	}

	if (bind(sock->sck, sock->addr, sock->addrlen) < 0) {
		lct_log(LCT_ERROR, "Can't bind to port %d (%s)", port, strerror(errno));
		lct_socket_release(sock);
		return NULL;
	}

	if (listen(sock->sck, max_bind_connections)) {
		lct_log(LCT_ERROR, "Can't start listening to port %d (%s)\n", port, strerror(errno));
		lct_socket_release(sock);
		return NULL;
	}

	/* the socket is marked as listening. */
	sock->status = LCT_SOCKET_LISTEN;

	if (listener) {
		/* attach thread to the socket if one is specified. */
		lct_thread_detached(THREAD_CORE, &sock->owner, listener, sock);
	}

	return sock;
}

/*!
 * \internal
 * \brief Every socket must be careful with the release of the socket.
 */
static void tcp_dummy_exit(void *arg)
{
	struct lct_socket *sock = (struct lct_socket *)arg;

	close(sock->sck);
	/* release socket memory if refcount <= 0 */
	lct_socket_release(sock);
	/* decrease the thread counter. */
	lct_thread_decrease(THREAD_CORE);
}

/*!
 * \internal
 * \brief TCP simple dummy thread, only wait until the host is released.
 * \param data Connection structure.
 */
static void *tcp_dummy_loop(void *data)
{
	struct lct_socket *sock = (struct lct_socket *)data;
	int ret;
	fd_set sckset;
	struct timeval tv;

	if (!data) {
		lct_log(LCT_ERROR, "Trying to run dummy loop without a connection\n");
		lct_thread_exit(THREAD_CORE, NULL);
	}

	pthread_cleanup_push(tcp_dummy_exit, (void *)sock);

	do {
		FD_ZERO(&sckset);
		FD_SET(sock->sck, &sckset);
		tv.tv_sec = 0;
		tv.tv_usec = 500 * 1000;
		pthread_testcancel();
		ret = select(sock->sck + 1, &sckset, NULL, NULL, &tv);
	} while (ret >= 0);

	if (sock->sck > 0) {
		/* the socket was closed */
		close(sock->sck);
		sock->sck = -1;
		sock->status = LCT_SOCKET_RELEASED;
	}

	pthread_cleanup_pop(0);

	close(sock->sck);
	lct_socket_release(sock);

	lct_thread_exit(THREAD_CORE, NULL);
	return NULL;
}

/*!
 * \internal
 * \brief Handle CLI command 'tcp connect'.
 * \param args Structure with all the passed parameters.
 */
static enum lct_cli_result handle_command_tcp_connect(struct lct_cliargs *args)
{
	struct lct_socket *sock;
	int port, timeout = -1;

	if (args->argc < 4) {
		return CLI_USAGE;
	}

	port = atoi(args->argv[3]);
	if (!lct_valid_port(port)) {
		return CLI_USAGE;
	}

	if (args->argc == 5) {
		/* get timeout option */
		timeout = atoi(args->argv[4]);
		if (!timeout) {
			return CLI_FAILED;
		}
	}

	/* connect without timeout (-1) */
	sock = lct_tcp_simple_connect(args->argv[2], port, timeout, tcp_dummy_loop);
	if (!sock) {
		return CLI_FAILED;
	}

	lct_cli_output("Socket<id> = %d\n", sock->id);
	lct_cli_output("Host<id> = %d\n", sock->host_owner->id);

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief CLI command 'tcp connect' autocomplete.
 */
static char *handle_command_tcp_connect_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return lct_hosts_complete(word, state);
	}

	return NULL;
}

/*!
 * \internal
 * \brief Handle CLI command 'tcp close'.
 * \param args Structure with all the passed parameters from the CLI.
 */
static enum lct_cli_result handle_command_tcp_close(struct lct_cliargs *args)
{
	int sockid;
	struct lct_socket *sock;

	if (args->argc < 4) {
		return CLI_USAGE;
	}

	sockid = atoi(args->argv[3]);
	if (sockid < 0) {
		lct_cli_output("Invalid socket id\n");
		return CLI_USAGE;
	}

	sock = lct_socket_find(args->argv[2], sockid);
	if (!sock) {
		lct_cli_output("Couldn't find a socket in host '%s' with id '%d'\n", args->argv[2], sockid);
		return CLI_FAILED;
	}

	/* This command will only close TCP sockets. */
	if (lct_socket_type(sock) != SOCK_STREAM) {
		lct_cli_output("This is not a TCP socket\n");
		return CLI_FAILED;
	}

	lct_cli_output("Closing TCP socket on %s:%d\n", lct_socket_ip(sock), lct_socket_port(sock));
	lct_tcp_simple_close(sock);

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief CLI command 'tcp close' autocomplete
 */
static char *handle_command_tcp_close_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return lct_hosts_complete(word, state);
	}

	return NULL;
}

/*!
 * \internal
 * \brief Function executed if the thread is killed.
 * \see command_tcp_bind_listener
 */
static void command_tcp_bind_listener_exit(void *args)
{
	struct lct_socket *sock = (struct lct_socket *)args;
	lct_socket_release(sock);
	lct_thread_decrease(THREAD_CORE);
}

/*!
 * \internal
 * \brief Thread used to listen for incoming connections when binding to a TCP port.
 * \see command_tcp_bind_listener_exit
 */
static void *command_tcp_bind_listener(void *data)
{
	int sck, ret, n;
	socklen_t clientlen;
	struct lct_socket *sock;
	struct sockaddr *client;
	char buffer[512], hostname[NI_MAXHOST];
	struct timeval tv;
	fd_set sckset;

	if (!data) {
		lct_thread_exit(THREAD_CORE, NULL);
	}

	sock = (struct lct_socket *)data;
	clientlen = sock->addrlen;
	client = alloca(sock->addrlen);
	if (!client) {
		lct_log(LCT_ERROR, "Unable to allocate the client structure\n");
		lct_thread_exit(THREAD_CORE, NULL);
	}

	pthread_cleanup_push(command_tcp_bind_listener_exit, sock);	

	for (;;) {
		do {
			sck = lct_accept(sock, client, &clientlen, 500);
			pthread_testcancel();
		} while (sck == 0);

		if (sck < 0) {
			lct_cli_output("Accept connection error\n");
			lct_socket_release(sock);
			lct_thread_exit(THREAD_CORE, NULL);
		}
		getnameinfo(client, clientlen, hostname, sizeof(hostname), NULL, 0, NI_NUMERICHOST);
		lct_cli_output("\nConnection accepted from %s\n", hostname);

		for (;;) {
			FD_ZERO(&sckset);
			FD_SET(sck, &sckset);
			tv.tv_sec = 0;
			tv.tv_usec = 500 * 1000;

			ret = select(sck + 1, &sckset, NULL, NULL, &tv);
			if (ret > 0) {
				n = read(sck, buffer, sizeof(buffer));
				if (n <= 0) {
					break;
				}
				lct_cli_output("TCP [RX %s:%d] (%s) %s\n", lct_socket_ip(sock), lct_socket_port(sock), hostname, buffer);
			} else if (ret < 0) {
				break;
			}
			pthread_testcancel();
		}
	}

	pthread_cleanup_pop(0);

	lct_socket_release(sock);
	lct_thread_exit(THREAD_CORE, NULL);
}

/*!
 * \internal
 * \brief Handle CLI command 'tcp thread bind'.
 * \param args Structure with all the passed parameters from the CLI.
 */
static enum lct_cli_result handle_command_tcp_thread_bind(struct lct_cliargs *args)
{
	int port;
	struct lct_socket *sock;

	if (args->argc < 5) {
		return CLI_USAGE;
	}
	port = atoi(args->argv[4]);

	if (!lct_valid_port(port)) {
		lct_cli_output("Wrong port number.\n");
		return CLI_USAGE;
	}

	sock = lct_tcp_simple_bind(args->argv[3], SOCK_STREAM, port, command_tcp_bind_listener);
	if (!sock) {
		return CLI_FAILED;
	}

	lct_cli_output("Accepting connections on %s:%d\n", args->argv[3], lct_socket_port(sock));

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief Handle CLI command 'tcp bind'.
 * \param args Structure with all the passed parameters from the CLI.
 */
static enum lct_cli_result handle_command_tcp_bind(struct lct_cliargs *args)
{
	int port, ret, sck;
	struct lct_socket *sock;
	struct sockaddr *client;
	socklen_t clientlen;
	char buffer[1024], hostname[NI_MAXHOST];
	fd_set sckset;
	enum lct_cli_result retval;

	if (args->argc < 4) {
		return CLI_USAGE;
	}
	port = atoi(args->argv[3]);

	if (!lct_valid_port(port)) {
		lct_cli_output("Wrong port number.\n");
		return CLI_USAGE;
	}

	sock = lct_tcp_simple_bind(args->argv[2], SOCK_STREAM, port, NULL);
	if (!sock) {
		return CLI_FAILED;
	}

	client = alloca(sock->addrlen);
	if (!client) {
		lct_socket_release(sock);
		return CLI_FAILED;
	}
	clientlen = sock->addrlen;

	lct_cli_output("Waiting for a connection on %s:%d\n", args->argv[2], lct_socket_port(sock));

	sck = lct_accept(sock, client, &clientlen, -1);
	if (sck < 0) {
		lct_cli_output("Error while trying to accept a connection\n");
		lct_socket_release(sock);
		return CLI_FAILED;
	}
	getnameinfo(client, clientlen, hostname, sizeof(hostname), NULL, 0, NI_NUMERICHOST);
	lct_cli_output("Connection accepted from %s (type 'tcp close' to hangup the connection)\n", hostname);

	for (;;) {
		FD_ZERO(&sckset);
		FD_SET(sck, &sckset);
		FD_SET(0, &sckset);
		ret = select(sck + 1, &sckset, NULL, NULL, NULL);
		if (ret < 0) {
			retval = CLI_FAILED;
			break;
		}
		if (FD_ISSET(sck, &sckset)) {
			memset(buffer, 0, sizeof(buffer));
			ret = read(sck, buffer, sizeof(buffer));
			if (ret == 0) {
				retval = CLI_SUCCESS;
				break;
			} else if (ret < 0) {
				retval = CLI_FAILED;
				break;
			}
			lct_cli_output("%s", buffer);
		} else {
			/* read from stdin */
			memset(buffer, 0, sizeof(buffer));
			ret = read(0, buffer, sizeof(buffer));
			if (ret == 0) {
				retval = CLI_SUCCESS;
				break;
			} else if (ret < 0) {
				retval = CLI_FAILED;
				break;
			}
			if (!strncasecmp(buffer, "tcp close", strlen("tcp close"))) {
				retval = CLI_SUCCESS;
				break;
			}
			if (write(sck, buffer, strlen(buffer)) < 0) {
				retval = CLI_FAILED;
				break;
			}
		}
	}

	lct_socket_release(sock);
	return retval;
}

/*!
 * \internal
 * \brief Implement the TCP protocol injector for packet manipulation.
 * \param header The TCP header pointer to inject.
 * \param default_values set the tcp header default values or not.
 * \retval 0 on success.
 * \retval < 0 on error.
 */
static int tcp_protocol_injector(void *header, int default_values)
{

	if (default_values) {
		struct tcphdr *hdr = (struct tcphdr *)header;

		if (!header) {
			return -1;
		}

		/* Set default values. */
		hdr->th_sum = 0;
		hdr->th_off = 5;
		hdr->th_sport = 0;
		hdr->th_dport = 0;
		hdr->th_seq = random();
		hdr->th_win = htons(65535);
	}

	return 0;
}

/*!
 * \internal
 * \brief Implement the TCP header updater.
 * \param packet The packet pointer where the header to update is.
 * \param proto The TCP header pointer to update.
 * \retval 0 on success.
 * \retval < 0 on error.
 */
static int tcp_protocol_header_update(struct lct_packet *packet, struct lct_packet_protocol *proto)
{
	struct tcphdr *hdr = (struct tcphdr *)proto->ptr;
	struct tcp_checksum_header cksum;
	struct tcp_checksum_header6 cksum6;
	struct lct_packet_protocol *nextproto, *prevproto;
	unsigned long pktlen;

	pktlen = lct_packet_len(packet, proto);

	prevproto = lct_packet_protocol_next(packet, NULL);
	if (prevproto == proto) {
		lct_log(LCT_ERROR, "Malformed TCP packet, missing IP header\n");
		return -1;
	}

	/* find the previous protocol. */
	while ((nextproto = lct_packet_protocol_next(packet, prevproto)) != proto && prevproto) {
		prevproto = nextproto;
	}

	/* if no previous protocol, this is not a well formed TCP header. */
	if (!prevproto) {
		lct_log(LCT_WARNING, "Malformed TCP packet\n");
		return -1;
	}

	/* is the previous header an IP header? */
	if (prevproto->number != IPPROTO_IP && prevproto->number != IPPROTO_IPV6) {
		lct_log(LCT_WARNING, "Previous header must be an IP or IPv6 header in order to calculate the TCP checksum\n");
		return -1;
	}

	nextproto = lct_packet_protocol_next(packet, proto);

	if (prevproto->number == IPPROTO_IP) {
		memset(&cksum, 0, sizeof(cksum));
		lct_ip_get_saddr(&cksum.saddr, sizeof(cksum.saddr), prevproto);
		lct_ip_get_daddr(&cksum.daddr, sizeof(cksum.daddr), prevproto);
		cksum.len = htons(pktlen);
		cksum.protocol = IPPROTO_TCP;
		/* before calculating checksum, it must be zero. */
		hdr->th_sum = 0;
		memcpy(&cksum.tcp, proto->ptr, sizeof(cksum.tcp));
		if (nextproto) {
			memcpy(cksum.payload, nextproto->ptr, pktlen);
		}
		hdr->th_sum = lct_header_checksum((unsigned short *)&cksum, pktlen + sizeof(cksum) - sizeof(cksum.payload) - sizeof(cksum.tcp));
	} else {
		/* ipv6 */
		memset(&cksum6, 0, sizeof(cksum6));
		lct_ip_get_saddr(&cksum6.saddr, sizeof(cksum6.saddr), prevproto);
		lct_ip_get_daddr(&cksum6.daddr, sizeof(cksum6.daddr), prevproto);
		cksum6.len = htonl(pktlen);
		cksum6.nextheader = IPPROTO_TCP;
		memcpy(&cksum6.tcp, proto->ptr, sizeof(cksum6.tcp));
		if (nextproto) {
			memcpy(&cksum6.payload, nextproto->ptr, pktlen);
		}
		hdr->th_sum = lct_header_checksum((unsigned short *)&cksum6, pktlen + sizeof(cksum6) - sizeof(cksum6.payload) - sizeof(cksum.tcp));
	}

	return 0;
}

/*!
 * \internal
 * \brief Implement the getter function for the TCP protocol header.
 * \param proto
 * \param what
 * \param errcode
 * \retval NULL on error.
 * \retval The requested value.
 */
static void *tcp_protocol_header_getter(struct lct_packet_protocol *proto, const char *what, int *errcode)
{
	struct tcphdr *hdr = (struct tcphdr *)proto->ptr;

	*errcode = 0;

	if (!strcasecmp(what, "src") || !strcasecmp(what, "dst")) {
		unsigned short *port;
		port = calloc(1, sizeof(*port));
		if (!port) {
			*errcode = -1;
			return NULL;
		}
		if (!strcasecmp(what, "src")) {
			*port = ntohs(hdr->th_sport);
		} else {
			*port = ntohs(hdr->th_dport);
		}
		return port;
	} else if (!strcasecmp(what, "flags")) {
		unsigned char *flags;
		flags = calloc(1, sizeof(*flags));
		if (!flags) {
			*errcode = -1;
			return NULL;
		}
		*flags = hdr->th_flags;
		return flags;
	}

	*errcode = -1;
	return NULL;
}

/*!
 * \internal
 * \brief Dump the TCP header in a human readable form.
 * \param header The TCP header.
 * \retval The TCP header in a human readable form (dynamically allocated memory).
 */
static char *tcp_protocol_header_dump(void *header)
{
#define TCP_HEADER_FORMAT 	"+-+-+-+-+-+-+-+-+-+-+-+-+-TCP HEADER+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-31d|%-31d|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-63u|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-63u|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-7d|%-11s|%-1d|%-1d|%-1d|%-1d|%-1d|%-1d|%-31d|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-31d|%-31d|\n"

	struct tcphdr *hdr = (struct tcphdr *)header;
	char *ret;

	asprintf(&ret, TCP_HEADER_FORMAT,
					ntohs(hdr->th_sport), ntohs(hdr->th_dport),
					hdr->th_seq,
					hdr->th_ack,
					hdr->th_off, "unused",
					FLAG_SET(hdr->th_flags, TH_URG), FLAG_SET(hdr->th_flags, TH_ACK), FLAG_SET(hdr->th_flags, TH_PUSH),
					FLAG_SET(hdr->th_flags, TH_RST), FLAG_SET(hdr->th_flags, TH_SYN), FLAG_SET(hdr->th_flags, TH_FIN),
					hdr->th_win, hdr->th_sum, hdr->th_urp);

	return ret;
}

int lct_tcp_flag_byname(const char *name)
{
	if (!strcasecmp(name, "syn")) {
		return TH_SYN;
	} else if (!strcasecmp(name, "fin")) {
		return TH_FIN;
	} else if (!strcasecmp(name, "urg")) {
		return TH_URG;
	} else if (!strcasecmp(name, "rst")) {
		return TH_RST;
	} else if (!strcasecmp(name, "push") || !strcasecmp(name, "psh")) {
		return TH_PUSH;
	} else if (!strcasecmp(name, "ack")) {
		return TH_ACK;
	}

	return 0;
}

/*!
 * \internal
 * \brief Handler used to modify the TCP header parameters.
 * \param proto The tcp protocol structure to modify.
 * \param param The parameter name to modify.
 * \param arg The value to set.
 * \retval 0 on success.
 * \retval < 0 on error.
 */
static int tcp_protocol_header_modify(struct lct_packet_protocol *proto, const char *param, void *arg)
{
	struct tcphdr *hdr = (struct tcphdr *)proto->ptr;
	char *data = (char *)arg;
	unsigned short value = htons(atoi(data));

	if (!proto || !param) {
		return -1;
	}

	if (!strcasecmp(param, "src")) {
		hdr->th_sport = value;
	} else if (!strcasecmp(param, "dst")) {
		hdr->th_dport = value;
	} else if (!strcasecmp(param, "seq")) {
		hdr->th_seq = value;
	} else if (!strcasecmp(param, "ack")) {
		hdr->th_ack = value;
	} else if (!strcasecmp(param, "setflag")) {
		hdr->th_flags |= lct_tcp_flag_byname(data);
	} else if (!strcasecmp(param, "unsetflag")) {
		hdr->th_flags &= ~(lct_tcp_flag_byname(data));
	} else if (!strcasecmp(param, "offset")) {
		hdr->th_off = atoi(data);
	} else if (!strcasecmp(param, "win")) {
		hdr->th_win = value;
	}

	return 0;
}

int lct_tcp_finish(void)
{
	int res;

	res = lct_cli_command_unregister("tcp connect");
	res |= lct_cli_command_unregister("tcp close");
	res |= lct_cli_command_unregister("tcp thread bind");
	res |= lct_cli_command_unregister("tcp bind");
	res |= lct_packet_injector_unregister("tcp");

	return res;
}

/*!
 * \internal
 * \brief A TCP protocol header injector.
 */
static const struct lct_injector tcp_injector = {
	.name = "tcp",
	.number = IPPROTO_TCP,
	.struct_len = sizeof(struct tcphdr),
	.inject = tcp_protocol_injector,
	.update = tcp_protocol_header_update,
	.dump = tcp_protocol_header_dump,
	.modify = tcp_protocol_header_modify,
	.modifiers = header_modifiers,
	.getter = tcp_protocol_header_getter 
};

int lct_tcp_register_builtin_commands(void)
{
	int res, value;

	if ((value = lct_config_int(LCT_CONFIG_TCP_MAX_BIND_CONNECTIONS))) {
		max_bind_connections = value;
	}

	res = lct_packet_injector_register(&tcp_injector);

	res |= lct_cli_command_register("tcp connect", "Connect to a specified TCP port.", 
			"tcp connect <hostname> <port> [timeout]", handle_command_tcp_connect, handle_command_tcp_connect_complete);
	res |= lct_cli_command_register("tcp close", "Close an already created TCP socket.",
			"tcp close <hostname> <socket-id>", handle_command_tcp_close, handle_command_tcp_close_complete);
	res |= lct_cli_command_register("tcp thread bind", "Bind to a specified TCP port without blocking the console.", 
			"tcp thread bind <ipaddress> <port>", handle_command_tcp_thread_bind, NULL);
	res |= lct_cli_command_register("tcp bind", "Bind to a specified TCP port blocking the console.", 
			"tcp bind <ipaddress> <port>", handle_command_tcp_bind, NULL);
	return res;
}
