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
 * \brief The locust packet API.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_PACKET_H
#define LOCUST_PACKET_H

#include <locust/simclist.h>

struct lct_socket;

#define LCT_MAX_PACKET_SIZE 1514 

/*! \brief A network packet. */
struct lct_packet {
	/*! The current packet id. */
	int id;
	/*! We need to bind this packet to an interface ? */
	char *device;
	/*! The packet content. */
	char datagram[LCT_MAX_PACKET_SIZE];
	/*! The protocols inside the datagram buffer. */
	list_t protocols;
	/*! packet locking mechanism. */
	struct lct_lock lock;
};

/*! \brief A protocol injected in a packet */
struct lct_packet_protocol {
	/*! Protocol number. */
	int number;
	/*! Pointer to the protocol structure. */
	void *ptr;
	/*! Protocol packet len */
	size_t ptr_len;
};

/*! \brief A protocol injector is the driver responsable of adding a header inside a packet. */
struct lct_injector {
	/*! Injector name. */
	char *name;
	/*! Protocol number. */
	int number;
	/*! Structure len. */
	size_t struct_len;
	/*! The injector implementation. */
	int (*inject)(void *header, int default_values);
	/*! update the needed values inside this header. */
	int (*update)(struct lct_packet *packet, struct lct_packet_protocol *proto);
	/*! Header dump */
	char *(*dump)(void *header);
	/*! injector modifier function. */
	int (*modify)(struct lct_packet_protocol *proto, const char *param, void *arg);
	/*! Get a part of a header. */
	void *(*getter)(struct lct_packet_protocol *proto, const char *what, int *errcode);
	/*! List of accepted modifiers NULL terminated. */
	const char **modifiers;
};

/*!
 * \brief Register a protocol injector.
 * \param in The injector structure to register.
 * \retval 0 on success.
 * \retval < 0 on error.
 */
int lct_packet_injector_register(const struct lct_injector *in);

/*!
 * \brief Unregister a protocol injector.
 * \param proto_name The protocol injector name.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_packet_injector_unregister(const char *proto_name);

/*!
 * \brief Create a packet structure an initialize the locking and lists inside it.
 * \retval NULL on error.
 * \retval The allocated packet structure.
 */
struct lct_packet *lct_packet_create();

/*!
 * \brief Release a packet from memory.
 * \param id The packet id.
 * \retval 0 on success.
 * \retval < 0 on error.
 */
int lct_packet_release(int id);

/*!
 * \brief Set the content of the packet.
 * \param packet The packet to modify.
 * \param payload The data to set.
 * \param payload_len The data lenght.
 */
void lct_packet_payload_set(struct lct_packet *packet, const unsigned char *payload, size_t payload_len);

/*!
 * \brief Get a packet by id with the lock held.
 * \param id The packet id we are trying to find.
 * \retval NULL on error.
 * \retval The packet structure with the lock held.
 */
struct lct_packet *lct_packet_get_byid_locked(int id);

/*!
 * \brief Get a packet protocol header by its position starting at 0.
 * \param packet The packet pointer.
 * \param position The header number to get.
 * \retval NULL on error.
 * \retval The packet protocol structure found in that position.
 */
struct lct_packet_protocol *lct_packet_protocol_bypos(struct lct_packet *packet, int position);

/*!
 * \brief Get the protocol number by name.
 * \param name The protocol name we are trying to find.
 * \retval < 0 on error.
 * \retval The protocol number.
 */
int lct_packet_protocol_number_byname(const char *name);

/*!
 * \brief Get a protocol header element.
 * \param proto The protocol structure header.
 * \param what Which part of the header to get.
 * \param errcode A pointer to an int used to check errors when running this function.
 * \returns the content of section of the header you request. 
 */
void *lct_packet_protocol_get(struct lct_packet_protocol *proto, const char *what, int *errcode);

/*!
 * \brief Inject a protocol inside a packet, this function must be called with
 *        the packet locked.
 * \param packet A pointer to the packet where to inject the protocol.
 * \param protocol_name The protocol name to inject.
 * \param default_values Setup the injected protocol header with default values.
 * \retval NULL on error.
 * \retval The packet protocol pointer.
 */
struct lct_packet_protocol *lct_packet_protocol_inject(struct lct_packet *packet, const char *protocol_name, int default_values);

/*!
 * \brief Iterate throw the list of protocols injected inside a packet.
 * \param packet The packet structure that we won't to iterate.
 * \param proto The packet protocol pointer. (if NULL get the first).
 * \retval NULL if no next element.
 * \retval The pointer to the next protocol in the list.
 */
struct lct_packet_protocol *lct_packet_protocol_next(struct lct_packet *packet, struct lct_packet_protocol *proto);

/*!
 * \brief Read a packet from an open socket.
 * \param sock The socket structure.
 * \param timeout Wait until timeout occurs.
 * \retval NULL if no packet was received.
 * \retval The received packet.
 */
struct lct_packet *lct_packet_read(struct lct_socket *sock, int timeout);

/*!
 * \brief Send a packet.
 * \param packet_id The packet to send.
 * \param retsock Set retsock to NULL if you want the socket being open inside
 *        this function to be closed before returning, or pass a pointer and avoid
 *        closing the socket for future use. 
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_packet_send(int packet_id, struct lct_socket **retsock);

/*!
 * \brief Modify an injected header parameter.
 * \param packet The packet pointer structure.
 * \param header The header number we want to modify.
 * \param param The parameter of the header we want to modify.
 * \param arg The value of the parameter we want to modify.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_packet_protocol_modify(struct lct_packet *packet, int header, const char *param, void *arg);

/*!
 * \brief Get the total packet len (the header len summatory).
 * \param packet The packet pointer.
 * \param initproto The initial protocol structure (if NULL start from the begining of the packet).
 * \retval The packet (len >= 0).
 */
int lct_packet_len(struct lct_packet *packet, struct lct_packet_protocol *initproto);

#endif /* LOCUST_PACKET_H */
