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
 * \brief Connect() TCP scan implementation.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/socket.h>
#include <locust/logger.h>
#include <locust/scanner.h>
#include <locust/tcp.h>
#include <locust/cli.h>

#define CONNECT_SCAN_PRIORITY 10
#define CONNECT_SCAN_CONNECTION_TIMEOUT 3 

/*!
 * \internal
 * \brief Check if a single port is open.
 * \param host Hostname to scan.
 * \param port Port to check.
 * \retval 1 Port is open.
 * \retval 0 Port is closed.
 */
static enum lct_port_status scan_connect_port(const char *host, int port)
{
	struct lct_socket *sock;

	sock = lct_tcp_simple_connect(host, port, CONNECT_SCAN_CONNECTION_TIMEOUT, NULL); 
	if (!sock) {
		/* port is closed or we get a timeout */
		return PORT_CLOSED;
	}
	/* port is open */
	lct_socket_release(sock);
	return PORT_OPEN;
}

/*!
 * \brief Handle CLI command 'scan connect'.
 * \param args locust CLI passed arguments.
 * \retval CLI command return value.
 */
static enum lct_cli_result handle_command_scan_connect(struct lct_cliargs *args)
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

	lct_cli_output("Running connect() scan against %s\n", args->argv[3]);

	ret = lct_scan_host("connectscan", args->argv[3], port_init, port_end, 0);

	if (ret < 0) {
		return CLI_FAILED;
	}

	return CLI_SUCCESS;
}

/*!
 * \brief Handle CLI command 'scan thread connect'.
 * \param args locust CLI passed arguments.
 * \retval CLI command return value.
 */
static enum lct_cli_result handle_command_scan_thread_connect(struct lct_cliargs *args)
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

	lct_cli_output("Running connect() scan against %s\n", args->argv[4]);

	ret = lct_scan_host("connectscan", args->argv[4], port_init, port_end, 1);

	if (ret < 0) {
		return CLI_FAILED;
	}

	return CLI_SUCCESS;
}

int module_load(void)
{
	int ret;

	ret = lct_scanner_register("connectscan", CONNECT_SCAN_PRIORITY, PORT_TCP, scan_connect_port);

	if (ret >= 0) {
		ret |= lct_cli_command_register("scan tcp connect", "Run a tcp connect() scan against a target hostname",
			"scan tcp connect <hostname> <port-init> [port-end]", handle_command_scan_connect, NULL);
		ret |= lct_cli_command_register("scan thread tcp connect", "Run a tcp connect() scan against a target hostname using threads",
			"scan thread tcp connect <hostname> <port-init> [port-end]", handle_command_scan_thread_connect, NULL);
	}

	return ret;
}

int module_unload(void)
{
	int ret;

	ret = lct_scanner_unregister("connectscan");
	ret |= lct_cli_command_unregister("scan tcp connect");
	ret |= lct_cli_command_unregister("scan thread tcp connect");

	return ret;
}
