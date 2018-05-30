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
 * \brief SYN TCP scan implementation.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/socket.h>
#include <locust/logger.h>
#include <locust/scanner.h>
#include <locust/packet.h>
#include <locust/cli.h>
#include <locust/tcp.h>
#include <locust/route.h>

#define SYN_SCAN_PRIORITY 5 
#define SYN_SCAN_TIMEOUT 4000 

/*!
 * \internal
 * \brief Check if a single port is open.
 * \param host Hostname to scan.
 * \param port Port to check.
 * \retval PORT_OPEN Port is open.
 * \retval PORT_CLOSED Port is closed.
 * \retval PORT_UNKNOWN Port status is unknown.
 * \retval PORT_FILTERED Port status is unknown.
 */
static enum lct_port_status scan_tcp_syn_port(const char *host, int port)
{
	struct lct_packet *syn_packet, *response_packet;
	struct lct_packet_protocol *ip_proto, *tcp_proto, *eth_proto;
	struct lct_socket *sock = NULL;
	char strport[10], dstip[NI_MAXHOST], srcip[NI_MAXHOST], devname[80];
	struct addrinfo *ai;
	int errcode;
	unsigned short srcport = rand() & 0xffff;
	time_t startscan, lastpacket;

	/* used to know if host will be resolved to an ipv4 or ipv6. */
	if (getaddrinfo(host, NULL, NULL, &ai)) {
		lct_log(LCT_WARNING, "getaddrinfo() %s\n", gai_strerror(errno));
		return PORT_CLOSED;
	}

	/* create the packet to send. */
	syn_packet = lct_packet_create();
	if (!syn_packet) {
		lct_log(LCT_ERROR, "Unable to create a packet!\n");
		return PORT_CLOSED;
	}

	/* set the ethernet header. */
	eth_proto = lct_packet_protocol_inject(syn_packet, "ethernet", 1);
	if (!eth_proto) {
		lct_log(LCT_ERROR, "Unable to inject an ethernet header\n");
		lct_packet_release(syn_packet->id);
		return PORT_CLOSED;
	}
	lct_packet_protocol_modify(syn_packet, 0, "dst", "0:1c:c0:9:86:c");
	lct_packet_protocol_modify(syn_packet, 0, "src", "00:23:32:bf:ac:ea");

	/* create the ip-tcp packet. */
	if (ai->ai_family == AF_INET) {
		ip_proto = lct_packet_protocol_inject(syn_packet, "ip", 1);
	} else {
		ip_proto = lct_packet_protocol_inject(syn_packet, "ipv6", 1);
	}
	if (!ip_proto) {
		lct_log(LCT_ERROR, "Unable to inject an ip header!\n");
		lct_packet_release(syn_packet->id);
		return PORT_CLOSED;
	}
	/* set the ip destination. */
	getnameinfo(ai->ai_addr, ai->ai_addrlen, dstip, sizeof(dstip), NULL, 0, NI_NUMERICHOST);
	lct_packet_protocol_modify(syn_packet, 1, "dst", dstip);
	lct_route_get_source_info(dstip, srcip, sizeof(srcip), devname, sizeof(devname));
	lct_packet_protocol_modify(syn_packet, 1, "src", srcip);

	/* inject the tcp protocol header. */
	tcp_proto = lct_packet_protocol_inject(syn_packet, "tcp", 1);
	if (!tcp_proto) {
		lct_log(LCT_ERROR, "Unable to inject a tcp header!\n");
		lct_packet_release(syn_packet->id);
		return PORT_CLOSED;
	}
	/* set the source and destination ports. */
	snprintf(strport, sizeof(strport), "%d", port);
	lct_packet_protocol_modify(syn_packet, 2, "dst", strport);
	snprintf(strport, sizeof(strport), "%d", srcport);
	lct_packet_protocol_modify(syn_packet, 2, "src", strport);
	/* set the syn flag on */
	lct_packet_protocol_modify(syn_packet, 2, "setflag", "syn");

	/* it is time to send the packet. */
	lct_packet_send(syn_packet->id, &sock);
	if (!sock) {
		return PORT_UNKNOWN;
	}

	lct_packet_release(syn_packet->id);

	time(&startscan);
	while (1) {
		if (response_packet = lct_packet_read(sock, SYN_SCAN_TIMEOUT)) {
			unsigned short *flags, *dstport;
			time(&lastpacket);
			if (difftime(lastpacket, startscan) > SYN_SCAN_TIMEOUT/1000) {
				lct_packet_release(response_packet->id);
				break;
			}
			/* a response packet was received. */
			tcp_proto = lct_packet_protocol_bypos(response_packet, 1);
			if (tcp_proto) {
				if (!(dstport = lct_packet_protocol_get(tcp_proto, "dst", &errcode))) {
					lct_packet_release(response_packet->id);
					continue;
				}
				if (*dstport != srcport) {
					lct_packet_release(response_packet->id);
					free(dstport);
					continue;
				}
				free(dstport);
				if (!(flags = lct_packet_protocol_get(tcp_proto, "flags", &errcode))) {
					lct_packet_release(response_packet->id);
					continue;
				}
				if ((lct_tcp_flag_byname("rst") & *flags)) {
					lct_packet_release(response_packet->id);
					free(flags);
					lct_socket_release(sock);
					return PORT_CLOSED;
				} else if ((lct_tcp_flag_byname("syn") & *flags) && (lct_tcp_flag_byname("ack") & *flags)) {
					lct_packet_release(response_packet->id);
					free(flags);
					lct_socket_release(sock);
					return PORT_OPEN;
				}
				free(flags);
			} else {
				lct_packet_release(response_packet->id);
			}
		} else {
			break;
		}
	}
	lct_socket_release(sock);

	return PORT_UNKNOWN;
}

/*!
 * \brief Handle CLI command 'scan tcp syn'.
 * \param args locust CLI passed arguments.
 * \retval CLI command return value.
 */
static enum lct_cli_result handle_command_scan_tcp_syn(struct lct_cliargs *args)
{
	int port_init, port_end;
	int ret;

	if (args->argc < 5) {
		return CLI_USAGE;
	}

	port_init = atoi(args->argv[4]);
	if (args->argc >= 6) {
		port_end = atoi(args->argv[5]);
	} else {
		port_end = port_init;
	}

	if (!lct_valid_port(port_init)) {
		lct_cli_output("Invalid initial port\n");
		return CLI_USAGE;
	}

	if (!lct_valid_port(port_end)) {
		lct_cli_output("Invalid final port\n");
		return CLI_USAGE;
	}

	lct_cli_output("Running a TCP SYN scan against %s\n", args->argv[3]);

	ret = lct_scan_host("synscan", args->argv[3], port_init, port_end, 0);

	if (ret < 0) {
		return CLI_FAILED;
	}

	return CLI_SUCCESS;
}

/*!
 * \brief Handle CLI command 'scan thread tcp syn'.
 * \param args locust CLI passed arguments.
 * \retval CLI command return value.
 */
static enum lct_cli_result handle_command_scan_thread_tcp_syn(struct lct_cliargs *args)
{
	int port_init, port_end;
	int ret;

	if (args->argc < 6) {
		return CLI_USAGE;
	}

	port_init = atoi(args->argv[5]);
	if (args->argc >= 7) {
		port_end = atoi(args->argv[6]);
	} else {
		port_end = port_init;
	}

	if (!lct_valid_port(port_init)) {
		lct_cli_output("Invalid initial port\n");
		return CLI_USAGE;
	}

	if (!lct_valid_port(port_end)) {
		lct_cli_output("Invalid final port\n");
		return CLI_USAGE;
	}

	lct_cli_output("Running a TCP SYN scan against %s\n", args->argv[4]);

	ret = lct_scan_host("synscan", args->argv[4], port_init, port_end, 1);

	if (ret < 0) {
		return CLI_FAILED;
	}

	return CLI_SUCCESS;
}

int module_load(void)
{
	int ret;

	if (!lct_running_as_root()) {
		lct_log(LCT_ERROR, "You must be root in order to have TCP SYN scan support\n");
		return 0;
	}

	ret = lct_scanner_register("synscan", SYN_SCAN_PRIORITY, PORT_TCP, scan_tcp_syn_port);

	if (ret >= 0) {
		ret |= lct_cli_command_register("scan tcp syn", "Run a tcp syn scan against a target hostname",
			"scan tcp syn <hostname> <port-init> [port-end]", handle_command_scan_tcp_syn, NULL);
		ret |= lct_cli_command_register("scan thread tcp syn", "Run a tcp syn scan against a target hostname using threads",
			"scan thread tcp syn <hostname> <port-init> [port-end]", handle_command_scan_thread_tcp_syn, NULL);
	}

	return ret;
}

int module_unload(void)
{
	int ret;

	if (!lct_running_as_root()) {
		return 0;
	}

	ret = lct_scanner_unregister("synscan");
	ret |= lct_cli_command_unregister("scan tcp syn");
	ret |= lct_cli_command_unregister("scan thread tcp syn");

	return ret;
}
