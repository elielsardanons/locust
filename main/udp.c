/*
 * Locust - The Network security framework
 *
 * Copyright (C) 2009  Gustavo Borgoni <gborgoni@voicemedia.com.ar>
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
 * \brief UDP abstraction layer.
 * \author Gustavo Borgoni <gborgoni@voicemedia.com.ar>
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>
#include <locust/socket.h>
#include <locust/cli.h>
#include <locust/packet.h>
#include <locust/ip.h>

#define __FAVOR_BSD
#include <netinet/udp.h>

/*!
 * \internal
 * \brief UDP header modifiers accepted.
 */
static const char *header_modifiers[] = { "src", "dst", NULL };

/*!
 * \internal
 * \brief Pseudo header used to calculate UDP checksum.
 */
struct udp_checksum_header {
	/*! IP Source address. */
	unsigned long saddr;
	/*! IP Destination address. */
	unsigned long daddr;
	/*! 8 bits padding. */
	unsigned char pad;
	/*! Protocol (UDP) */
	unsigned char protocol;
	/*! UDP header len */
	unsigned short len;
	/*! The UDP header. */
	struct udphdr udp;
};

struct lct_socket *lct_udp_simple_bind(const char *hostname, int port, void *(*listener)(void *))
{
	struct lct_socket *sock;
	socklen_t lenght;

	/* create the socket. */
	sock = lct_socket_create(hostname, SOCK_DGRAM, port);
	if (!sock) {
		return NULL;
	}

	/* bind the socket */
	if (bind(sock->sck, sock->addr, sock->addrlen) < 0) {
		lct_log(LCT_ERROR, "Can't bind to port %d (%s)", port, strerror(errno));
		lct_socket_release(sock);
		return NULL;
	}

	lenght = sock->addrlen;

	if (getsockname(sock->sck, sock->addr, &lenght) < 0) {
		lct_log(LCT_ERROR, "Error with getsockname");
		lct_socket_release(sock);
		return NULL;
	}

	/* This socket is marked as listening. */
	sock->status = LCT_SOCKET_LISTEN;

	if (listener) {
		/* attach thread to the socket if a function pointer is specified */
		lct_thread_detached(THREAD_CORE, &sock->owner, listener, sock);
	}

	return sock;
}

void lct_udp_simple_close(struct lct_socket *sock)
{
	lct_socket_close(sock);
}

struct lct_socket *lct_udp_simple_connect(const char *hostname, int port, void *(*listener)(void *))
{
	struct lct_socket *sock;
	int res;

	sock = lct_socket_create(hostname, SOCK_DGRAM, port);
	if (!sock) {
		return NULL;
	}

	/* this may look wrong but having a connect in a udp socket, we read icmp replies to check
	if there is a service running in the port we are trying to reach. */
	res = connect(sock->sck, sock->addr, sock->addrlen);
	if (res < 0) {
		lct_socket_release(sock);
		return NULL;
	}

	if (listener) {
		/* attach a thread */
		lct_thread_detached(THREAD_CORE, &sock->owner, listener, sock);
	}

	return sock;
}

/*!
 * \internal
 * \brief Exit function for thread.
 * \param arg A lct_socket Structure.
 * \see command_udp_bind_listener
 */
static void command_udp_thread_bind_listener_exit(void *arg)
{
	struct lct_socket *sock = (struct lct_socket *) arg;
	lct_socket_release(sock);
	lct_thread_decrease(THREAD_CORE);
}

/*!
 * \internal
 * \brief Thread to get UDP messages after a bind.
 * \param data A lct_socket structure.
 */
static void *command_udp_thread_bind_listener(void *data) 
{
	int n, ret;
	socklen_t clientlen;
	struct lct_socket *sock;
	struct sockaddr *client;
	char buffer[512], hostname[NI_MAXHOST];
	struct timeval tv;
	fd_set sckset;

	if (!data) {
		lct_thread_exit(THREAD_CORE, NULL);
	}

	sock = (struct lct_socket *) data;
	client = alloca(sock->addrlen);
	if (!client) {
		lct_thread_exit(THREAD_CORE, NULL);
	}
	clientlen = sock->addrlen;

	pthread_cleanup_push(command_udp_thread_bind_listener_exit, sock);

	memset(buffer, 0, sizeof(buffer));

	for (;;) {
		FD_ZERO(&sckset);
		FD_SET(sock->sck, &sckset);
		tv.tv_sec = 0;
		tv.tv_usec = 500 * 1000;
		ret = select(sock->sck + 1, &sckset, NULL, NULL, &tv);
		if (ret > 0) {
			n = recvfrom(sock->sck, buffer, sizeof(buffer), 0, client, &clientlen);
			buffer[n] = 0;
			getnameinfo(client, clientlen, hostname, sizeof(hostname), NULL, 0, NI_NUMERICHOST);
			lct_cli_output("UDP [RX %s:%d] (%s) %s\n", lct_socket_ip(sock), lct_socket_port(sock), hostname, buffer);
		} else if (ret < 0) {
			break;
		}
		pthread_testcancel();
	}

	pthread_cleanup_pop(0);

	lct_socket_release(sock);
	lct_thread_exit(THREAD_CORE, NULL);
	return NULL;
}

/*!
 * \internal
 * \brief Handle CLI command 'udp thread bind'.
 * \param args Command parameters.
 */
static enum lct_cli_result handle_command_udp_thread_bind(struct lct_cliargs *args)
{
	struct lct_socket *sock;
	int port = 0;

	if (args->argc < 4) {
		return CLI_USAGE;
	}

	if (args->argc > 4) {
		port = atoi(args->argv[4]);
		if (!lct_valid_port(port)) {
			lct_cli_output("Wrong port number.\n");
			return CLI_USAGE;
		}
	}

	sock = lct_udp_simple_bind(args->argv[3], port, command_udp_thread_bind_listener);
	if (!sock) {
		return CLI_FAILED;
	}

	lct_cli_output("Accepting connections on %s:%d\n",args->argv[3], lct_socket_port(sock));

	return CLI_SUCCESS;
}

int lct_udp_simple_send(const char *ip, int port, const char *data)
{
	struct lct_socket *sock;

	sock = lct_socket_create(ip, SOCK_DGRAM, port);
	if (!sock) {
		return -1;		
	}

	lct_socket_sendto(sock, data, strlen(data), 0);
	lct_socket_release(sock);

	return 0;
}

int lct_udp_connect_send(struct lct_socket *sock, const char *data)
{
	return write(sock->sck, data, strlen(data));
}

/*!
 * \internal
 * \brief Handle CLI command 'udp bind'.
 * \param args Command parameters.
 */
static enum lct_cli_result handle_command_udp_bind(struct lct_cliargs *args)
{
	struct lct_socket *sock;
	struct sockaddr *client;
	socklen_t clientlen;
	int port = 0, ret, n;
	fd_set sckset;
	char buffer[1024];

	if (args->argc < 3) {
		return CLI_USAGE;
	}

	if (args->argc > 3) {
		port = atoi(args->argv[3]);
		if (!lct_valid_port(port)) {
			lct_cli_output("Wrong port number.\n");
			return CLI_USAGE;
		}
	}

	sock = lct_udp_simple_bind(args->argv[2], port, NULL);
	if (!sock) {
		return CLI_FAILED;
	}
	client = alloca(sock->addrlen);
	if (!client) {
		lct_socket_release(sock);
		return CLI_FAILED;
	}
	clientlen = sock->addrlen;
	lct_cli_output("Accepting connections on %s:%d\n",args->argv[2], lct_socket_port(sock));


	for (;;) {
		memset(buffer, 0, sizeof(buffer));

		FD_ZERO(&sckset);
		FD_SET(sock->sck, &sckset);
		FD_SET(0, &sckset);

		ret = select(sock->sck + 1, &sckset, NULL, NULL, NULL);
		if (ret < 0) {
			lct_socket_release(sock);
			return CLI_FAILED;
		}
		if (FD_ISSET(sock->sck, &sckset)) {
			n = recvfrom(sock->sck, buffer, sizeof(buffer), 0, client, &clientlen);
			if (n < 0) {
				lct_socket_release(sock);
				return CLI_FAILED;
			} else if (ret == 0) {
				lct_socket_release(sock);
				return CLI_SUCCESS;
			}
			buffer[n] = 0;
			lct_cli_output("%s", buffer);
		} else {
			n = read(0, buffer, sizeof(buffer));
			if (n < 0) {
				lct_socket_release(sock);
				return CLI_FAILED;
			} else if (n == 0) {
				lct_socket_release(sock);
				return CLI_SUCCESS;
			}
			if (!strncasecmp("udp close", buffer, strlen("udp close"))) {
				lct_socket_release(sock);
				return CLI_SUCCESS;
			}
			sendto(sock->sck, buffer, strlen(buffer), 0, client, clientlen);
		}
	}

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief Handle CLI command 'udp send'
 */
static enum lct_cli_result handle_command_udp_send(struct lct_cliargs *args)
{
	int port;

	if (args->argc < 5) {
		return CLI_USAGE;
	}

	port = atoi(args->argv[3]);
	if (!lct_valid_port(port)) {
		lct_cli_output("Wrong port number.\n");
		return CLI_USAGE;
	}

	lct_udp_simple_send(args->argv[2], port, args->argv[4]);

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief CLI command 'udp send' autocomplete.
 */
static char *handle_command_udp_send_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return lct_hosts_complete(word, state);
	}

	return NULL;
}

/*!
 * \internal
 * \brief Handle CLI command 'udp close'.
 * \param args Structure with all the passed parameters from the CLI.
 */
static enum lct_cli_result handle_command_udp_close(struct lct_cliargs *args)
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

	if (lct_socket_type(sock) != SOCK_DGRAM) {
		lct_cli_output("This is not an UDP socket\n");
		return CLI_FAILED;
	}

	lct_cli_output("Closing UDP socket on %s:%d\n", lct_socket_ip(sock), lct_socket_port(sock));
	lct_udp_simple_close(sock);

        return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief CLI command 'udp close' autocomplete.
 */
static char *handle_command_udp_close_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return lct_hosts_complete(word, state);
	}

	return NULL;
}

/*!
 * \internal
 * \brief Implement the UDP protocol injector for packet manipulation.
 */
static int udp_protocol_injector(void *header, int default_values)
{
	if (default_values) {
		struct udphdr *hdr = (struct udphdr *)header;

		hdr->uh_ulen = 0;
		hdr->uh_sum = 0;
	}

	return 0;
}


/*!
 * \internal
 * \brief Implement the UDP header updater.
 */
static int udp_protocol_header_update(struct lct_packet *packet, struct lct_packet_protocol *proto)
{
	struct udphdr *hdr = (struct udphdr *)proto->ptr;
	struct udp_checksum_header cksum;
	struct lct_packet_protocol *nextproto, *prevproto;
	int pktlen;

        pktlen = proto->ptr_len;

	/* update the udp length. */
	nextproto = lct_packet_protocol_next(packet, proto);
	while (nextproto) {
		pktlen += nextproto->ptr_len;
		nextproto = lct_packet_protocol_next(packet, nextproto);
	}
	hdr->uh_ulen = htons(pktlen);

	prevproto = lct_packet_protocol_next(packet, NULL);
	if (prevproto == proto) {
		lct_log(LCT_ERROR, "Malformed UDP packet, missing IP header\n");
		return -1;
	}

	while ((nextproto = lct_packet_protocol_next(packet, prevproto)) != proto && prevproto) {
		prevproto = nextproto;
	}

	if (!prevproto) {
		lct_log(LCT_WARNING, "Malformed UDP packet\n");
		return -1;
	}

	/* is the previous header an IP header? */
	if (prevproto->number != IPPROTO_IP && prevproto->number != IPPROTO_IPV6) {
		lct_log(LCT_WARNING, "Previous header must be an IPv4 or IPv6 header in order to calculate the UDP checksum\n");
		return -1;
	}

	memset(&cksum, 0, sizeof(cksum));
	lct_ip_get_saddr(&cksum.saddr, sizeof(cksum.saddr), prevproto);
	lct_ip_get_daddr(&cksum.daddr, sizeof(cksum.daddr), prevproto);
	cksum.len = htons(sizeof(cksum.udp));
	cksum.protocol = IPPROTO_UDP;
	hdr->uh_sum = 0;
	memcpy(&cksum.udp, proto->ptr, sizeof(cksum.udp));
	hdr->uh_sum = lct_header_checksum((unsigned short *)&cksum, sizeof(cksum));

	return 0;
}

/*!
 * \internal
 * \brief Dump an UDP header in a human readable form.
 * \param header The UDP header pointer.
 * \retval The string with the UDP header dump (dynamically allocated memory).
 */
static char *udp_protocol_header_dump(void *header)
{
#define UDP_HEADER_FORMAT 	"+-+-+-+-+-+-+-+-+-+-+-+-+-UDP HEADER+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-31d|%-31d|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-31d|%-31d|\n"

	struct udphdr *hdr = (struct udphdr *)header;
	char *ret;

	asprintf(&ret, UDP_HEADER_FORMAT,
					ntohs(hdr->uh_sport), ntohs(hdr->uh_dport),
					hdr->uh_ulen, hdr->uh_sum);

	return ret;
}

/*!
 * \internal
 * \brief Handler to modify the UDP protocol.
 * \param proto The UDP protocol structure pointer.
 * \param param The parameter name to modify.
 * \param arg The value to set.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
static int udp_protocol_header_modify(struct lct_packet_protocol *proto, const char *param, void *arg)
{
	struct udphdr *hdr = (struct udphdr *)proto->ptr;
	char *data = (char *)arg;

	if (!proto || !param || !arg) {
		return -1;
	}

	if (!strcasecmp(param, "src")) {
		hdr->uh_sport = htons(atoi(data));
	} else if (!strcasecmp(param, "dst")) {
		hdr->uh_dport = htons(atoi(data));
	}

	return 0;
}

int lct_udp_finish(void)
{
	int res;

	res = lct_cli_command_unregister("udp thread bind");
	res |= lct_cli_command_unregister("udp bind");
	res |= lct_cli_command_unregister("udp send");
	res |= lct_cli_command_unregister("udp close");
	res |= lct_packet_injector_unregister("udp");

	return res;
}

/*!
 * \internal
 * \brief An UDP header injector.
 */
static const struct lct_injector udp_injector = {
	.name = "udp",
	.number = IPPROTO_UDP,
	.struct_len = sizeof(struct udphdr),
	.inject = udp_protocol_injector,
	.update = udp_protocol_header_update,
	.dump = udp_protocol_header_dump,
	.modify = udp_protocol_header_modify,
	.modifiers = header_modifiers,
	.getter = NULL
};

int lct_udp_register_builtin_commands(void)
{
	int res;

	res = lct_packet_injector_register(&udp_injector);

	res |= lct_cli_command_register("udp thread bind", "Bind to a specified UDP port, without blocking the console.",
		"udp thread bind <hostname> [port]", handle_command_udp_thread_bind, NULL);
	res |= lct_cli_command_register("udp bind", "Bind to a specified UDP port, blocking the console.",
		"udp bind <hostname> [port]", handle_command_udp_bind, NULL);
	res |= lct_cli_command_register("udp send", "Send data to a specified UDP port.",
		"udp send <hostname> <port> <data>", handle_command_udp_send, handle_command_udp_send_complete);
	res |= lct_cli_command_register("udp close", "Close an already created UDP socket.",
		"udp close <hostname> <socket-id>", handle_command_udp_close, handle_command_udp_close_complete);

	return res;
}

