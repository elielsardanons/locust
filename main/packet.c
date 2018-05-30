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
 * \brief Locust packet implementation.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>
#include <locust/cli.h>
#include <locust/packet.h>
#include <locust/socket.h>
#include <locust/ip.h>
#include <locust/route.h>

/*! \brief All the created packets. */
static list_t packets;
/*! \brief The packets list locking mechanism. */
static struct lct_lock packets_lock;
/*! The unique packet id. */
static int packet_id = 0;

/*! \brief All the registered injectors. */
static list_t injectors;
/*! \brief The injectors list locking mechanism. */
static struct lct_lock injectors_lock;

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_packets_meter(const void *notused)
{
	return sizeof(struct lct_packet *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_packets_comparator(const void *a, const void *b)
{
	return (((struct lct_packet *)a)->id - ((struct lct_packet *)b)->id);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_packets_seeker(const void *a, const void *key)
{
	return (((struct lct_packet *)a)->id == *(int *)key);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_injectors_meter(const void *notused)
{
	return sizeof(struct lct_injector *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_injectors_seeker(const void *a, const void *key)
{
	return (((struct lct_injector *)a)->number == *(int *)key);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_packet_protocol_meter(const void *notused)
{
	return sizeof(struct lct_packet_protocol *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_packet_protocol_seeker(const void *a, const void *key)
{
	return (((struct lct_packet_protocol *)a)->number == *(int *)key);
}

struct lct_packet *lct_packet_create(void)
{
	struct lct_packet *p;

	p = calloc(1, sizeof(*p));
	if (!p) {
		lct_log(LCT_ERROR, "Unable to allocate the packet structure\n");
		return NULL;
	}

	lct_mutex_init(&p->lock, NULL);

	list_init(&p->protocols);
        list_attributes_copy(&p->protocols, list_packet_protocol_meter, 0);
        list_attributes_seeker(&p->protocols, list_packet_protocol_seeker);

	lct_mutex_lock(&packets_lock);
	p->id = (++packet_id);
	list_append(&packets, p);
	lct_mutex_unlock(&packets_lock);

	return p;
}

void lct_packet_payload_set(struct lct_packet *packet, const unsigned char *payload, size_t payload_len)
{
	if (payload_len > sizeof(packet->datagram)) {
		lct_log(LCT_WARNING, "Truncating packet\n");
		memcpy(packet->datagram, payload, sizeof(packet->datagram));
	} else {
		memcpy(packet->datagram, payload, payload_len);
	}
}

/*!
 * \internal 
 * \brief Release the memory allocate for a protocol injected in a packet.
 * \param proto The packet_protocol structure to release.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
static int packet_protocol_release(struct lct_packet_protocol *proto)
{
	if (!proto) {
		lct_log(LCT_ERROR, "Trying to free a null injected packet protocol\n");
		return -1;
	}
	free(proto);
	return 0;
}

int lct_packet_release(int id)
{
	struct lct_packet *p;
	struct lct_packet_protocol *proto;
	int pos;

	lct_mutex_lock(&packets_lock);
	p = list_seek(&packets, &id);
	if (!p) {
		/* no packet found with that id. */
		lct_mutex_unlock(&packets_lock);
		return -1;
	}
	lct_mutex_lock(&p->lock);

	pos = list_locate(&packets, p);
	p = list_extract_at(&packets, pos);

	list_iterator_start(&p->protocols);
	while (list_iterator_hasnext(&p->protocols)) {
		proto = list_iterator_next(&p->protocols);
		packet_protocol_release(proto);
	}
	list_iterator_stop(&p->protocols);
	list_destroy(&p->protocols);
	lct_mutex_destroy(&p->lock);
	if (p->device) {
		free(p->device);
	}
	free(p);

	lct_mutex_unlock(&packets_lock);

	return 0;
}

struct lct_packet *lct_packet_get_byid_locked(int id)
{
	struct lct_packet *p = NULL;
	int found = 0;

	lct_mutex_lock(&packets_lock);
	list_iterator_start(&packets);
	while (list_iterator_hasnext(&packets)) {
		p = list_iterator_next(&packets);
		lct_mutex_lock(&p->lock);
		if (p->id == id) {
			found = 1;
			break;
		}
		lct_mutex_unlock(&p->lock);
	}
	list_iterator_stop(&packets);
	lct_mutex_unlock(&packets_lock);

	return (found ? p : NULL);
}

struct lct_packet_protocol *lct_packet_protocol_next(struct lct_packet *packet, struct lct_packet_protocol *proto)
{
	struct lct_packet_protocol *next = NULL;
	int pos = -1;

	if (proto) {
		pos = list_locate(&packet->protocols, proto);
	}
	next = list_get_at(&packet->protocols, pos + 1);

	return next;
}

int lct_packet_protocol_number_byname(const char *name)
{
	struct lct_injector *in;
	int protocol_number = -1;

	if (!name) {
		return -1;
	}

	lct_mutex_lock(&injectors_lock);
	list_iterator_start(&injectors);
	while (list_iterator_hasnext(&injectors)) {
		in = list_iterator_next(&injectors);
		if (!strcasecmp(in->name, name)) {
			protocol_number = in->number;
			break;
		}
	}
	list_iterator_stop(&injectors);
	lct_mutex_unlock(&injectors_lock);

	return protocol_number;
}

/*!
 * \internal
 * \brief Run all the update handlers for the specified packet.
 * \param packet The packet pointer.
 */
static void run_packet_protocol_updates(struct lct_packet *packet)
{
	struct lct_injector *in;
	struct lct_packet_protocol *tmp;
	int proto_count;

	proto_count = list_size(&packet->protocols);
	/* After injecting run all the injector updates */
	while (proto_count) {
		tmp = list_get_at(&packet->protocols, --proto_count);
		lct_mutex_lock(&injectors_lock);
		in = list_seek(&injectors, &tmp->number);
		if (in && in->update) {
			in->update(packet, tmp);
		}
		lct_mutex_unlock(&injectors_lock);
	}
}

void *lct_packet_protocol_get(struct lct_packet_protocol *proto, const char *what, int *errcode)
{
	void *ret = NULL;
	int err;
	struct lct_injector *in;

	if (errcode) {
		*errcode = 0;
	}

	if (!proto || !what) {
		if (errcode) {
			*errcode = -1;
		}
		return NULL;
	}

	lct_mutex_lock(&injectors_lock);
	in = list_seek(&injectors, &proto->number);
	if (!in) {
		lct_mutex_unlock(&injectors_lock);
		if (errcode) {
			*errcode = -1;
		}
		return NULL;
	}

	if (in->getter) {
		ret = in->getter(proto, what, (errcode ? errcode : &err));
	} else {
		lct_mutex_unlock(&injectors_lock);
		if (errcode) {
			*errcode = -1;
		}
		return NULL;
	}
	lct_mutex_unlock(&injectors_lock);

	return ret;
}

struct lct_packet_protocol *lct_packet_protocol_inject(struct lct_packet *packet, const char *protocol_name, int default_values)
{
	struct lct_packet_protocol *proto, *tmp;
	struct lct_injector *in;
	int totlen = 0;
	int protocol_number;

	protocol_number = lct_packet_protocol_number_byname(protocol_name);
	if (protocol_number < 0) {
		return NULL;
	}

	lct_mutex_lock(&injectors_lock);
	in = list_seek(&injectors, &protocol_number);
	if (!in) {
		lct_mutex_unlock(&injectors_lock);
		return NULL;
	}

	list_iterator_start(&packet->protocols);
	while (list_iterator_hasnext(&packet->protocols)) {
		tmp = list_iterator_next(&packet->protocols);
		totlen += tmp->ptr_len;
	}
	list_iterator_stop(&packet->protocols);

	if (totlen + in->struct_len > LCT_MAX_PACKET_SIZE) {
		lct_log(LCT_ERROR, "Packet too long to continue adding headers\n");
		lct_mutex_unlock(&injectors_lock);
		return NULL;
	}

	proto = calloc(1, sizeof(*proto));
	if (!proto) {
		lct_log(LCT_ERROR, "Unable to allocate the protocol structure\n");
		lct_mutex_unlock(&injectors_lock);
		return NULL;
	}

	proto->number = protocol_number;
	proto->ptr_len = in->struct_len;

	proto->ptr = packet->datagram + totlen;
	list_append(&packet->protocols, proto);

	in->inject(proto->ptr, default_values);
	lct_mutex_unlock(&injectors_lock);

	run_packet_protocol_updates(packet);

	return proto;
}

struct lct_packet_protocol *lct_packet_protocol_bypos(struct lct_packet *packet, int position)
{
	struct lct_packet_protocol *proto;

	lct_mutex_lock(&packet->lock);

	proto = list_get_at(&packet->protocols, position);
	lct_mutex_unlock(&packet->lock);

	return proto;
}

int lct_packet_protocol_modify(struct lct_packet *packet, int header, const char *param, void *arg)
{
	struct lct_packet_protocol *proto;
	struct lct_injector *in;
	int ret = -1;

	proto = list_get_at(&packet->protocols, header);
	if (!proto) {
		return -1;
	}

	lct_mutex_lock(&injectors_lock);
	in = list_seek(&injectors, &proto->number);
	if (!in) {
		lct_mutex_unlock(&injectors_lock);
		return -1;
	}
	if (in->modify) {
		ret = in->modify(proto, param, arg);
	}
	lct_mutex_unlock(&injectors_lock);

	/* after modifying, run all the updates. */
	run_packet_protocol_updates(packet);

	return ret;
}

int lct_packet_injector_register(const struct lct_injector *in)
{
	if (!in) {
		lct_log(LCT_ERROR, "You are trying to register a non-existent injector\n");
		return -1;
	}

	lct_mutex_lock(&injectors_lock);
	list_append(&injectors, in);
	lct_mutex_unlock(&injectors_lock);

	return 0;
}

int lct_packet_injector_unregister(const char *proto_name)
{
	struct lct_injector *in;
	int pos, protocol_number;

	protocol_number = lct_protocol_number(proto_name);
	if (protocol_number < 0) {
		lct_log(LCT_DEBUG, "Unable to unregister packet injector '%s'\n", proto_name);
		return -1;
	}

	lct_mutex_lock(&injectors_lock);
	in = list_seek(&injectors, &protocol_number);
	if (!in) {
		lct_log(LCT_WARNING, "Trying to unregister a non-existent injector %d '%s'\n", protocol_number, proto_name);
		lct_mutex_unlock(&injectors_lock);
		return -1;
	}
	pos = list_locate(&injectors, in);
	in = list_extract_at(&injectors, pos);
	lct_mutex_unlock(&injectors_lock);

	return 0;
}

int lct_packet_len(struct lct_packet *packet, struct lct_packet_protocol *initproto)
{
	int len = 0, start = 0;
	struct lct_packet_protocol *proto;

	list_iterator_start(&packet->protocols);
	/* iterate throw all the protocols an calculate the packet len. */
	while (list_iterator_hasnext(&packet->protocols)) {
		proto = list_iterator_next(&packet->protocols);	
		if (initproto && proto == initproto) {
			start = 1;
		} else if (!initproto) {
			start = 1;
		}
		if (start) {
			len += proto->ptr_len;
		}
	}
	list_iterator_stop(&packet->protocols);

	return len;
}

struct lct_packet *lct_packet_read(struct lct_socket *sock, int timeout)
{
	struct lct_packet *packet;
	struct lct_packet_protocol *proto;
	unsigned char buffer[BUFSIZ];
	char *protoname;
	int res, errcode;
	
	if ((res = lct_socket_read(sock, buffer, sizeof(buffer), timeout)) <= 0) {
		return NULL;
	}

	packet = lct_packet_create();
	if (!packet) {
		lct_log(LCT_ERROR, "Unable to allocate the needed memory for the received packet\n");
		return NULL;
	}

	lct_packet_payload_set(packet, buffer, res);

	proto = lct_packet_protocol_inject(packet, "ethernet", 0);
	if (!proto) {
		lct_log(LCT_ERROR, "Unable to add an ethernet protocol header to the received packet\n");
		lct_packet_release(packet->id);
		return NULL;
	}

	proto = lct_packet_protocol_inject(packet, "ip", 0);
	if (!proto) {
		lct_log(LCT_ERROR, "Unable to add an ip protocol header to the received packet\n");
		lct_packet_release(packet->id);
		return NULL;
	}

	protoname = lct_packet_protocol_get(proto, "protocol", &errcode);
	if (errcode) {
		lct_log(LCT_ERROR, "Unable to get the IP header protocol value\n");
		lct_packet_release(packet->id);
		return NULL;
	}

	proto = lct_packet_protocol_inject(packet, protoname, 0);
	free(protoname);

	return packet;
}

int lct_packet_send(int packet_id, struct lct_socket **retsock)
{
	struct lct_packet *packet;
	struct lct_socket *sock;
	struct lct_packet_protocol *proto;
	int packetlen = 0;
	char hostname[NI_MAXHOST] = "";

	packet = lct_packet_get_byid_locked(packet_id);
	if (!packet) {
		return -1;
	}

	/* get the packet hostname */
	list_iterator_start(&packet->protocols);
	while (list_iterator_hasnext(&packet->protocols)) {
		proto = list_iterator_next(&packet->protocols);
		/* get the first ip protocol */
		if (proto->number == IPPROTO_IP || proto->number == IPPROTO_IPV6) {
			lct_ip_get_destination(hostname, sizeof(hostname), proto);
			break;
		}
	}
	list_iterator_stop(&packet->protocols);

	packetlen = lct_packet_len(packet, NULL);

	if (!packetlen) {
		lct_mutex_unlock(&packet->lock);
		return -1;
	}

	sock = lct_socket_raw(hostname);
	if (!sock) {
		lct_mutex_unlock(&packet->lock);
		return -1;
	}

	if (lct_socket_sendraw(sock, packet->datagram, packetlen) < 0) {
		lct_log(LCT_ERROR, "Error while writing packet %d to socket\n", packet_id);
		lct_mutex_unlock(&packet->lock);
		lct_socket_release(sock);
		return -1;
	}

	if (!retsock) {
		lct_socket_release(sock);
	} else {
		*retsock = sock;
	}
	lct_mutex_unlock(&packet->lock);

	return 0;
}

/*!
 * \internal
 * \brief Packet ID autocomplete helper.
 */
static char *packet_id_autocomplete(const char *word, int state)
{
	struct lct_packet *packet;
	char *ret, *options[128];
	int count = 0;

	lct_mutex_lock(&packets_lock);
	list_iterator_start(&packets);
	while (list_iterator_hasnext(&packets) && count < 128) {
		packet = list_iterator_next(&packets);
		asprintf(&options[count++], "%d", packet->id);
	}
	list_iterator_stop(&packets);
	lct_mutex_unlock(&packets_lock);
	options[count] = NULL;
	ret = lct_cli_command_complete((const char **)options, word, state);
	while (count > 0) {
		free(options[--count]);
	}

	return ret;
}

/*! \brief Handle CLI command 'packet show' */
static enum lct_cli_result handle_command_packet_show(struct lct_cliargs *args)
{
	struct lct_packet *packet;
	struct lct_packet_protocol *proto;
	struct lct_injector *in;
	char *protoheader;
	int count = 0, header_count;
	int id;

	if (args->argc > 2) {
		id = atoi(args->argv[2]);
		if (id <= 0) {
			lct_cli_output("Invalid packet id %d\n", id);
			return CLI_FAILED;
		}
		packet = lct_packet_get_byid_locked(id);
		if (!packet) {
			lct_cli_output("No packet found with id %d\n", id);
			return CLI_FAILED;
		}
		lct_cli_output("Packet ID: %d\nDatagram:\n", id);
		list_iterator_start(&packet->protocols);
		while (list_iterator_hasnext(&packet->protocols)) {
			proto = list_iterator_next(&packet->protocols);
			protoheader = NULL;
			lct_mutex_lock(&injectors_lock);
			in = list_seek(&injectors, &proto->number);
			if (in && in->dump) {
				protoheader = in->dump(proto->ptr);
			}
			lct_mutex_unlock(&injectors_lock);
			if (protoheader) {
				lct_cli_output("%s", protoheader);
				free(protoheader);
			}
			count++;
		}
		list_iterator_stop(&packet->protocols);
		lct_mutex_unlock(&packet->lock);
		if (count) {
			lct_cli_output("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
		}
		lct_cli_output("\n(%d header%s included)\n", count, (count == 1 ? "" : "s"));
	} else {
		lct_cli_output("%-5s %s\n", "id", "headers");
		lct_mutex_lock(&packets_lock);
		list_iterator_start(&packets);
		while (list_iterator_hasnext(&packets)) {
			packet = list_iterator_next(&packets);
			lct_cli_output("%-5d ", packet->id);
			header_count = 0;
			lct_mutex_lock(&packet->lock);
			list_iterator_start(&packet->protocols);
			while (list_iterator_hasnext(&packet->protocols)) {
				proto = list_iterator_next(&packet->protocols);
				lct_mutex_lock(&injectors_lock);
				in = list_seek(&injectors, &proto->number);
				if (in) {
					lct_cli_output("%s%s", (header_count ? "-" : ""), in->name);
				}
				lct_mutex_unlock(&injectors_lock);
				header_count++;
			}
			list_iterator_stop(&packet->protocols);
			lct_mutex_unlock(&packet->lock);
			lct_cli_output("\n");
			count++;
		}
		list_iterator_stop(&packets);
		lct_mutex_unlock(&packets_lock);
		lct_cli_output("%d packet%s\n", count, (count == 1 ? "" : "s"));
	}

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief Autocomplete for CLI command 'packet show'.
 */
static char *handle_command_packet_show_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return packet_id_autocomplete(word, state);
	}

	return NULL;
}

/*!
 * \internal
 * \brief Handle CLI command 'packet injector show'
 */
static enum lct_cli_result handle_command_packet_injector_show(struct lct_cliargs *args)
{
#define PACKET_INJECTOR_SHOW_TITLE_FORMAT "%-10s %-8s\n"
#define PACKET_INJECTOR_SHOW_FORMAT "%-10s %-8d\n"
	struct lct_injector *in;
	int count = 0;

	lct_cli_output(PACKET_INJECTOR_SHOW_TITLE_FORMAT, "name", "protocol");
	lct_mutex_lock(&injectors_lock);
	list_iterator_start(&injectors);
	while (list_iterator_hasnext(&injectors)) {
		in = list_iterator_next(&injectors);
		lct_cli_output(PACKET_INJECTOR_SHOW_FORMAT, in->name, in->number);
		count++;
	}
	list_iterator_stop(&injectors);
	lct_mutex_unlock(&injectors_lock);
	lct_cli_output("%d injector%s registered\n", count, (count == 1 ? "" : "s"));

	return CLI_SUCCESS;
#undef PACKET_INJECTOR_SHOW_TITLE_FORMAT
#undef PACKET_INJECTOR_SHOW_FORMAT
}

/*!
 * \internal
 * \brief Handle CLI command 'packet create'.
 */
static enum lct_cli_result handle_command_packet_create(struct lct_cliargs *args)
{
	struct lct_packet *packet;

	packet = lct_packet_create();
	if (!packet) {
		lct_cli_output("Failed creating an ethernet packet\n");
		return CLI_FAILED;
	}

	lct_cli_output("Packet created with id: %d\n", packet->id);

	return CLI_SUCCESS;
}

/*! \brief Handle CLI command 'packet release' */
static enum lct_cli_result handle_command_packet_release(struct lct_cliargs *args)
{
	int id;

	if (args->argc < 3) {
		return CLI_USAGE;
	}

	id = atoi(args->argv[2]);
	if (id <= 0) {
		lct_cli_output("Invalid packet id\n");
		return CLI_FAILED;
	}

	if (lct_packet_release(id)) {
		lct_cli_output("No packet with id %d was found\n", id);
		return CLI_FAILED;
	}

	lct_cli_output("Packet with id %d released\n", id);
	return CLI_SUCCESS;
}

/*! \brief Handle CLI command 'packet release' autocomplete. */
static char *handle_command_packet_release_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return packet_id_autocomplete(word, state);
	}

	return NULL;
}

/*! \brief Handle CLI command 'packet inject' */
static enum lct_cli_result handle_command_packet_inject(struct lct_cliargs *args)
{
	struct lct_packet *packet;
	int id, proto;

	if (args->argc < 4) {
		return CLI_USAGE;
	}

	id = atoi(args->argv[2]);
	if (id <= 0) {
		lct_cli_output("Invalid packet id\n");
		return CLI_FAILED;
	}

	packet = lct_packet_get_byid_locked(id);
	if (!packet) {
		lct_cli_output("No packet found with id %d\n", id);
		return CLI_FAILED;
	}

	proto = lct_packet_protocol_number_byname(args->argv[3]);
	if (proto < 0) {
		/* we couldn't find the protocol injector in the registered list. */
		proto = lct_protocol_number(args->argv[3]);
		if (proto < 0) {
			/* This is not a valid protocol */
			lct_cli_output("Unknown protocol %s\n", args->argv[3]);
		} else {
			lct_cli_output("No protocol injector found for the '%s' protocol\n", args->argv[3]);
		}
		lct_mutex_unlock(&packet->lock);
		return CLI_FAILED;
	}
	lct_packet_protocol_inject(packet, args->argv[3], 1);
	lct_mutex_unlock(&packet->lock);

	lct_cli_output("Protocol %s injected in packet %d\n", args->argv[3], id);

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief Autocomplete injectors
 */
static char *injectors_command_complete(const char *word, int state)
{
	char *options[128];
	struct lct_injector *in;
	int count = 0;
	char *ret = NULL;

	lct_mutex_lock(&injectors_lock);
	list_iterator_start(&injectors);
	while (list_iterator_hasnext(&injectors)) {
		in = list_iterator_next(&injectors);
		options[count++] = in->name;
	}	
	list_iterator_stop(&injectors);
	options[count] = NULL;
	ret = lct_cli_command_complete((const char **)options, word, state);
	lct_mutex_unlock(&injectors_lock);

	return ret;
}

static char *packet_inject_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return packet_id_autocomplete(word, state);
	} else if (pos == 4) {
		return injectors_command_complete(word, state);
	}

	return NULL;
}

/*! \brief Handle CLI command 'packet send' */
static enum lct_cli_result handle_command_packet_send(struct lct_cliargs *args)
{
	int packet_id;

	if (args->argc < 3) {
		return CLI_USAGE;
	}

	packet_id = atoi(args->argv[2]);
	if (packet_id <= 0) {
		lct_cli_output("Invalid packet id %d\n", packet_id);
		return CLI_FAILED;
	}

	if (lct_packet_send(packet_id, NULL) < 0) {
		lct_cli_output("Error while sending the packet id %d\n", packet_id);
		return CLI_FAILED;
	}

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief Handle CLI command 'packet send' autocomplete.
 */
static char *handle_command_packet_send_complete(const char **cmd, const char *word, int pos, int state)
{
	char *ret = NULL;

	if (pos == 3) {
		ret = packet_id_autocomplete(word, state);
	}

	return ret;
}

/*!
 * \internal
 * \brief Handle CLI command 'packet modify'
 */
static enum lct_cli_result handle_command_packet_modify(struct lct_cliargs *args)
{
	struct lct_packet *packet;
	int packetid, headerid;

	if (args->argc < 6) {
		return CLI_USAGE;
	}

	packetid = atoi(args->argv[2]);
	if (packetid <= 0) {
		lct_cli_output("Invalid packet id %d\n", packetid);
		return CLI_FAILED;
	}

	packet = lct_packet_get_byid_locked(packetid);
	if (!packet) {
		lct_cli_output("No packet found with id %d\n", packetid);
		return CLI_FAILED;
	}

	headerid = atoi(args->argv[3]);

	if (lct_packet_protocol_modify(packet, headerid, args->argv[4], args->argv[5]) < 0) {
		lct_mutex_unlock(&packet->lock);
		return CLI_FAILED;
	}

	lct_mutex_unlock(&packet->lock);

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief Handle CLI command 'packet modify' autocomplete.
 */
static char *handle_command_packet_modify_complete(const char **cmd, const char *word, int pos, int state)
{
	int packetid, headerid;
	struct lct_packet *packet;
	struct lct_packet_protocol *proto;
	struct lct_injector *in;
	char *ret = NULL, *options[128];
	int count = 0, i;

	if (pos == 3) {
		/* autocomplete packet id. */
		ret = packet_id_autocomplete(word, state);
		return ret;
	} else if (pos == 4) {
		/* autocomplete header pos */
		packetid = atoi(cmd[2]);
		packet = lct_packet_get_byid_locked(packetid);
		if (!packet) {
			return NULL;
		}
		count = list_size(&packet->protocols);
		for (i = 0; i < count && i < 128; i++) {
			asprintf(&options[i], "%d", i);
		}
		options[i] = NULL;
		ret = lct_cli_command_complete((const char **)options, word, state);
		for (i = 0; i < count; i++) {
			free(options[i]);
		}
		lct_mutex_unlock(&packet->lock);
		return ret;
	} else if (pos == 5) {
		/* autocomplete parameter name */
		packetid = atoi(cmd[2]);
		headerid = atoi(cmd[3]);
		packet = lct_packet_get_byid_locked(packetid);
		if (!packet) {
			return NULL;
		}
		proto = list_get_at(&packet->protocols, headerid);
		if (!proto) {
			lct_mutex_unlock(&packet->lock);
			return NULL;
		}
		lct_mutex_lock(&injectors_lock);
		in = list_seek(&injectors, &proto->number);
		if (!in) {
			lct_mutex_unlock(&packet->lock);
			lct_mutex_unlock(&injectors_lock);
			return NULL;
		}

		ret = lct_cli_command_complete(in->modifiers, word, state);

		lct_mutex_unlock(&injectors_lock);

		lct_mutex_unlock(&packet->lock);
		return ret;
	}

	return NULL;
}

int lct_packet_finish(void)
{
	lct_cli_command_unregister("packet show");
	lct_cli_command_unregister("packet create");
	lct_cli_command_unregister("packet release");
	lct_cli_command_unregister("packet injector show");
	lct_cli_command_unregister("packet inject");
	if (lct_running_as_root()) {
		lct_cli_command_unregister("packet send");
	}
	lct_cli_command_unregister("packet modify");

	lct_mutex_destroy(&packets_lock);
	list_destroy(&packets);

	lct_mutex_destroy(&injectors_lock);
	list_destroy(&injectors);

	return 0;
}

int lct_packet_initialize(void)
{
	/* initialize the packets list. */
	list_init(&packets);
	list_attributes_copy(&packets, list_packets_meter, 0);
	list_attributes_comparator(&packets, list_packets_comparator);
        list_attributes_seeker(&packets, list_packets_seeker);

	lct_mutex_init(&packets_lock, NULL);

	/* initialize the injectors list. */
	list_init(&injectors);
	list_attributes_copy(&injectors, list_injectors_meter, 0);
	list_attributes_seeker(&injectors, list_injectors_seeker);

	lct_mutex_init(&injectors_lock, NULL);

	/* register packet CLI commands */
	lct_cli_command_register("packet show", "Show every created packet.", "packet show [packet-id]", handle_command_packet_show,
			handle_command_packet_show_complete);
	lct_cli_command_register("packet create", "Create a new ethernet packet.", "packet create", handle_command_packet_create, NULL);
	lct_cli_command_register("packet release", "Destroy a created packet.", "packet release <packet-id>", handle_command_packet_release,
			handle_command_packet_release_complete);
	lct_cli_command_register("packet injector show", "Show the list of injectors.", "packet injector show", handle_command_packet_injector_show, NULL);
	lct_cli_command_register("packet inject", "Inject a protocol inside a packet", "packet inject <packet-id> <protocol>",
			handle_command_packet_inject, packet_inject_complete);
	if (lct_running_as_root()) {
		lct_cli_command_register("packet send", "Send a created packet", "packet send <packet-id>", handle_command_packet_send,
			handle_command_packet_send_complete);
	}
	lct_cli_command_register("packet modify", "Modify an injected header", "packet modify <packet-id> <header-pos> <param> <value>",
			handle_command_packet_modify, handle_command_packet_modify_complete);

	return 0;
}

