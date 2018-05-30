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
 * \brief TCP API definitions.
 * \author Gustavo Borgoni <gborgoni@voicemedia.com.ar>
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_UDP_H
#define LOCUST_UDP_H

/*!
 * \brief Bind an UDP port and start listening on that port using the listener
 * thread.
 * \param ip The ip address where to start listening.
 * \param port The port number to listen.
 * \param listener If not NULL it will be run after binding and the lct_socket structure
 * allocated will be passed as a parameter to this thread. This thread must implement a cleanup
 * function to release the socket.
 * \retval NULL on error.
 * \retval Allocated lct_socket structure.
 */
struct lct_socket *lct_udp_simple_bind(const char *ip, int port, void *(*listener)(void *));

/*!
 * \brief Close an UDP socket.
 * \param sock The socket pointer.
 */
void lct_udp_simple_close(struct lct_socket *sock);

/*!
 * \brief Create an udp connected socket. This socket will check for ICMP replies.
 * \param hostname The hostname to "connect" to.
 * \param port The port to "connect" to.
 * \param listener If not null, we will run this function as a thread and attach it to the socket
 * structure.
 * \retval NULL on error.
 * \retval The allocated socket structure.
 */
struct lct_socket *lct_udp_simple_connect(const char *hostname, int port, void *(*listener)(void *));

/*!
 * \brief Send a message to an already connected udp socket.
 * \see lct_udp_simple_connect
 * \param sock The socket structure.
 * \param data The data to send.
 * \retval < 0 on error.
 * \retval >= 0 on success.
 */
int lct_udp_connect_send(struct lct_socket *sock, const char *data);

/*!
 * \brief Send an UDP packet to a host without checking for ICMP replies.
 * \param hostname The target hostname.
 * \param port The target port.
 * \param data The buffer to send.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_udp_simple_send(const char *hostname, int port, const char *data);

#endif /* LOCUST_UDP_H */
