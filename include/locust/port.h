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
 * \brief Locust port definition.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_PORT_H
#define LOCUST_PORT_H

enum lct_port_protocol {
	PORT_TCP,
	PORT_UDP
};

enum lct_port_status {
	PORT_CLOSED,
	PORT_OPEN,
	PORT_FILTERED,
	PORT_UNKNOWN
};

/*! \brief Host ports */
struct lct_port {
	/*! Name of the service running in this port, NULL = unknown. */
	char *service;
	/*! Service version */
	char *version;
	/*! Port number. */
	int port;
	/*! Port protocol */
	enum lct_port_protocol protocol;
	/*! Port status (open, closed, etc) */
	enum lct_port_status status;
	/*! Next port in the list. */
	struct lct_port *next;
};

#endif /* LOCUST_PORT_H */
