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
 * \brief TCP API definitions.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_TCP_H
#define LOCUST_TCP_H

/*!
 * \brief Connect to a host using TCP.
 * \param ip Host name to connect to.
 * \param port Port number.
 * \param timeout Connection timeout in seconds.
 * \param owner Thread owner.
 * \retval NULL on error.
 * \retval An allocated socket structure.
 */
struct lct_socket *lct_tcp_simple_connect(const char *ip, unsigned short port, int timeout, void *(*owner)(void *));

/*!
 * \brief Close the TCP socket.
 * \param sock Socket structure.
 */
void lct_tcp_simple_close(struct lct_socket *sock);

/*!
 * \brief Bind to a port and start listening
 * \param ip
 * \param type
 * \param port
 * \param listener
 * \retval NULL on error.
 * \retval The allocated socket structure.
 */
struct lct_socket *lct_tcp_simple_bind(const char *ip, int type, int port, void *(*listener)(void *));

/*!
 * \internal
 * \brief Get the TCP flag number given its name.
 * \param name The name of the flag.
 * \retval 0 if none found.
 * \retval The flag number.
 */
int lct_tcp_flag_byname(const char *name);

#endif /* LOCUST_TCP_H */
