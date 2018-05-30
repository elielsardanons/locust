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
 * \brief UDP scanner implementation.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/socket.h>
#include <locust/logger.h>
#include <locust/scanner.h>
#include <locust/udp.h>
#include <locust/tcp.h>
#include <locust/cli.h>

#define UDP_SCAN_PRIORITY 10

#if defined(__LINUX__)
#define DUMMY_PORT 3
#define UDP_SCAN_TIMEOUT 6 
/*!
 * \internal
 * \brief Check if a single UDP port is open.
 * \note This implementation does not work on darwin (macosx) but doesn't need
 * root priviliged to run.
 * \param host Hostname to scan.
 * \param port Port to check.
 * \retval PORT_OPEN Port is open.
 * \retval PORT_CLOSE Port is closed.
 */
static enum lct_port_status scan_udp_port(const char *host, int port)
{
	struct lct_socket *sock, *timeoutsock;
	int ret;

	sock = lct_udp_simple_connect(host, port, NULL);
	if (!sock) {
		/* port is closed or we get a timeout */
		return PORT_CLOSED;
	}
	/* XXX send a random string */
	ret = lct_udp_connect_send(sock, "SOMETHING");
	/* wait the ICMP */
	timeoutsock = lct_tcp_simple_connect(host, DUMMY_PORT, -1, NULL);
	if (timeoutsock) {
		lct_socket_release(timeoutsock);
	}

	/* XXX send a random string */
	ret = lct_udp_connect_send(sock, "SOMETHING");
	lct_socket_release(sock);

	if (ret < 0) {
		return PORT_CLOSED;
	}
	return PORT_OPEN;
}
#endif

/*!
 * \brief Handle CLI command 'scan udp'.
 * \param args locust CLI passed arguments.
 * \retval CLI command return value.
 */
static enum lct_cli_result handle_command_scan_udp(struct lct_cliargs *args)
{
	int port_init, port_end;
#if defined(__LINUX__)
	int ret;
#endif

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

	lct_cli_output("Running an UDP scan against %s\n", args->argv[3]);

#if defined(__LINUX__)
	ret = lct_scan_host("simpleudpscan", args->argv[3], port_init, port_end, 0);

	if (ret < 0) {
		return CLI_FAILED;
	}
#else
	return CLI_FAILED;
#endif


	return CLI_SUCCESS;
}

/*!
 * \brief Handle CLI command 'scan thread udp'.
 * \param args locust CLI passed arguments.
 * \retval CLI command return value.
 */
static enum lct_cli_result handle_command_scan_thread_udp(struct lct_cliargs *args)
{
	int port_init, port_end;
#if defined(__LINUX__)
	int ret;
#endif

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

	lct_cli_output("Running UDP scan against %s\n", args->argv[4]);

#if defined(__LINUX__)
	ret = lct_scan_host("simpleudpscan", args->argv[4], port_init, port_end, 1);

	if (ret < 0) {
		return CLI_FAILED;
	}
#else
	return CLI_FAILED;
#endif

	return CLI_SUCCESS;
}

int module_load(void)
{
	int ret = 0;

#if defined(__LINUX__)
	ret = lct_scanner_register("simpleudpscan", UDP_SCAN_PRIORITY, PORT_UDP, scan_udp_port);
#endif

	if (ret >= 0) {
		ret |= lct_cli_command_register("scan udp passive", "Run a full scan against a target hostname",
			"scan udp passive <hostname> <port-init> [port-end]", handle_command_scan_udp, NULL);
		ret |= lct_cli_command_register("scan thread udp passive", "Run a full scan against a target hostname using threads",
			"scan thread udp passive <hostname> <port-init> [port-end]", handle_command_scan_thread_udp, NULL);
	}

	return ret;
}

int module_unload(void)
{
	int ret = 0;

#if defined(__LINUX__)
	ret = lct_scanner_unregister("simpleudpscan");
#endif
	ret |= lct_cli_command_unregister("scan udp passive");
	ret |= lct_cli_command_unregister("scan thread udp passive");

	return ret;
}
