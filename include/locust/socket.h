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
 * \brief socket definitions.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_SOCKET_H
#define LOCUST_SOCKET_H

#include <netdb.h>

#include "locust/port.h"
#include "locust/packet.h"

#include "locust/autoconfig.h"

/* libnet opaque definitions */
struct libnet_context;

/*! \brief All the socket status possible */
enum lct_socket_status {
	/*! The socket is listening for incoming connections. */
	LCT_SOCKET_LISTEN,
	/*! The socket is in a connected state. */
	LCT_SOCKET_CONNECTED,
	/*! The socket is initialized. */
	LCT_SOCKET_INITIALIZED,
	/*! The socket is no longer usable. */
	LCT_SOCKET_RELEASED
};

/*! \brief The Locust socket definition */
struct lct_socket {
	/*! socket uniqueid */
	unsigned int id;
	/*! sockaddr structure for this socket */
	struct sockaddr *addr;
	/*! sockaddr len */
	socklen_t addrlen;
	/*! socket type. */
	int type;
	/*! The actual socket. */
	int sck;
#ifdef HAVE_LIBPCAP
	/*! A libpcap open live device. */
	pcap_t *input;
#endif
	/*! output device supported by libnet. */
	struct libnet_context *output;
	/*! Connection owner */
	pthread_t owner;
	/*! Inbound sockets */
	int *inboundsck;
	/*! Inbound sockets counter. */
	int inboundcounter;
	/*! Is this owner a detached thread */
	int detached;
	/*! Host owner */
	struct lct_host *host_owner;
	/*! Socket status */
	enum lct_socket_status status;
	/*! Socket lock */
	struct lct_lock lock;
	/*! References counter */
	int refcount;
};

/*! \brief The Locust host entity definition. */
struct lct_host {
	/*! Unique host identifier */
	unsigned int id;
	/*! Host ip address. */
	char *ip;
	/*! addrinfo structure for subsequent socket calls. */
	struct addrinfo *addr_info;
	/*! Host active sockets. */
	list_t sockets;
	/*! Reference count used to destroy host entity when not
	    used anymore. */
	int refcount;
	/*! Connection last assigned id. */
	unsigned int lastid;
	/*! Head of the list of ports. */
	struct lct_port *ports;
	/*! Known ports counter. */
	int ports_counter;
	/*! Host lock */
	struct lct_lock lock;
};

/*!
 * \brief Get the socket port.
 * \param sock The socket structure.
 * \retval The port number assigned to this socket.
 */
int lct_socket_port(struct lct_socket *sock);

/*!
 * \brief Find a socket structure given the host structure and the
 * socket id.
 * \param ip The hostname.
 * \param id Connection id.
 * \retval NULL if no socket found with that id.
 * \retval The socket structure with the given socket id.
 */
struct lct_socket *lct_socket_find(const char *ip, int id);

/*!
 * \brief Allocate a socket structure.
 * \param ip The hostname.
 * \param type Socket type (SOCK_STREAM? SOCK_DGRAM?)
 * \param port Socket port number.
 * \retval NULL on error.
 * \retval The socket allocated.
 */
struct lct_socket *lct_socket_create(const char *ip, int type, int port);

/*!
 * \brief Allocate a raw socket structure.
 * \param hostname The hostname.
 * \retval NULL on error.
 * \retval The socket allocated.
 */
struct lct_socket *lct_socket_raw(const char *hostname);

/*!
 * \brief Close the socket and kill the associated thread.
 * \param sock Socket structure.
 * \see lct_socket_release
 */
void lct_socket_close(struct lct_socket *sock);

/*!
 * \brief Destroy the memory allocated for a socket.
 * \param sock Connection pointer.
 */
void lct_socket_release(struct lct_socket *sock);

/*!
 * \brief Get the IP assigned to this socket.
 * \param sock The socket pointer.
 * \retval The socket ip address.
 */
const char *lct_socket_ip(struct lct_socket *sock);

/*!
 * \brief Get the socket type.
 * \param sock The socket pointer.
 * \retval The socket type (SOCK_STREAM, SOCK_DGRAM, etc).
 */
int lct_socket_type(struct lct_socket *sock);

/*!
 * \brief Wrapper for standard 'accept' function, that adds the accepted socket to
 * a list inside lct_socket for future references to that socket.
 * \param sock The socket structure pointer from where we are going to receive connections.
 * \param addr The sockaddr to store the client data. 
 * \param addrlen The addrlen pointer to store the addr len when the function completes.
 * \param timeout accept() function timeout in milliseconds.
 * \retval The socket created for the accepted connection on success.
 * \retval < 0 on error.
 * \retval 0 on timeout.
 */
int lct_accept(struct lct_socket *sock, struct sockaddr *addr, socklen_t *addrlen, int timeout);

/*!
 * \brief Send a raw packet.
 * \param sock The socket structure.
 * \param datagram The packet data.
 * \param packetlen The packet data lenght.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_socket_sendraw(struct lct_socket *sock, const char *datagram, size_t packetlen);

/*!
 * \brief Send a packet.
 * \param sock The socket structure.
 * \param payload The data to send.
 * \param payloadlen The data lenght.
 * \param flags Extra flags (MSG_OOB, MSG_DONTROUTE).
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_socket_sendto(struct lct_socket *sock, const char *payload, size_t payloadlen, int flags);

/*!
 * \brief Read a packet from an open socket.
 * \param sock The locust socket structure.
 * \param buffer The output buffer.
 * \param buffer_len The output buffer len.
 * \param timeout Try to receive a packet until the passed timeout in ms. (-1 is no timeout).
 * \retval -1 on error.
 * \retval The number of bytes received.
 */
ssize_t lct_socket_read(struct lct_socket *sock, void *buffer, size_t buffer_len, int timeout);

/*!
 * \brief Report the status of a specified port (open, closed, etc)
 * \param hostname The host the port.
 * \param service The name of the service running in that port (NULL = unknown).
 * \param version The version of the service running in that port (NULL = unknown).
 * \param port_number The port number.
 * \param protocol The type of protocol of this port (TCP, UDP, etc).
 * \param status The actual status of the port (PORT_OPEN, PORT_CLOSED, etc..).
 */
void lct_port_status(const char *hostname, const char *service, const char *version, int port_number,
	enum lct_port_protocol protocol, enum lct_port_status status);

/*!
 * \brief CLI command autocomplete helper for the hosts list.
 * \param word The word to autocomplete.
 * \param state The number of responses.
 * \retval The next host in the list.
 * \retval NULL if no more hosts.
 */
char *lct_hosts_complete(const char *word, int state);

#endif /* LOCUST_SOCKET_H */
