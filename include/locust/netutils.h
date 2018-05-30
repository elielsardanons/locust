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
 * \brief The network functions definitions.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_NETUTILS_H
#define LOCUST_NETUTILS_H

#include "locust/autoconfig.h"

#include <netdb.h>

/*!
 * \brief Check if a network port is valid or not.
 * \param port Port number to test.
 * \retval 0 The port is not valid.
 * \retval 1 The port is valid.
 */
int lct_valid_port(int port);

/*!
 * \brief Compare two addrinfo structure to check if we are talking
 * about the same host.
 * \param a1 First addrinfo to compare.
 * \param a2 Second addrinfo to compare.
 * \retval 0 The addrinfo are different.
 * \retval 1 The addrinfo are the same.
 */
int lct_addrinfocmp(struct addrinfo *a1, struct addrinfo *a2);

/*!
 * \brief Get the protocol number given its name.
 * \param proto_name The protocol name.
 * \retval < 0 on error.
 * \retval The protocol number.
 */
int lct_protocol_number(const char *proto_name);

/*!
 * \brief Get the protocol name given its number.
 * \param proto The protocol number.
 * \retval NULL on error.
 * \retval A dynamically allocated buffer with the protocol name.
 *         it is up to the caller to release this allocated memory.
 */
char *lct_protocol_name(int proto);

/*!
 * \brief Calculate the TCP/UDP header checksum.
 * \param addr The fake header pointer.
 * \param len The fake header len.
 * \retval The calculated TCP/UDP header checksum.
 */
unsigned short lct_header_checksum(unsigned short *addr, int len);

#endif /* LOCUST_NETUTILS_H */
