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
 * \brief Scanner subsystem definitions.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_SCANNER_H
#define LOCUST_SCANNER_H

#include "locust/port.h"

/*! \brief Port scanner definition. */
struct lct_scanner {
	/*! Port scanner name. */
	char *name;
	/*! Port scanner priority. */
	int priority;
	/*! The protocol supported by this scanner */
	enum lct_port_protocol protocol;
	/*! Port scanner functionality. */
	enum lct_port_status (*scan)(const char *hostname, int port);
	/*! Reference counter (how many threads are using this scanner */
	int refcount;
};

/*!
 * \brief Register a port scanner.
 * \param name The name of the port scanner.
 * \param priority Every port scanner will have a priority to know
 * how to use if we don't say it explicitly.
 * \param protocol The protocol supported by the scanner.
 * \param scanner The scanner function pointer.
 * \retval 0 on success.
 * \retval < 0 on failure.
 */
int lct_scanner_register(const char *name, int priority, enum lct_port_protocol protocol,
	enum lct_port_status (*scanner)(const char *hostname, int port));

/*!
 * \brief Unregister a scanner.
 * \param name Name of the scanner to unregister.
 * \retval 0 on success.
 * \retval < 0 on failure.
 */
int lct_scanner_unregister(const char *name);

/*!
 * \brief Scan a specified host.
 * \param name Name of the scanner to use.
 * \param hostname Host target.
 * \param port_init Initial port to scan.
 * \param port_end Final port to scan.
 * \param use_threads If set, we will run one thread for each port we are trying to scan.
 * \retval 0 on success.
 * \retval < 0 on failure.
 */
int lct_scan_host(const char *name, const char *hostname, int port_init, int port_end, int use_threads);

#endif /* LOCUST_SCANNER_H */
