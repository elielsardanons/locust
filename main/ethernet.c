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
 * \brief Raw Ethernet API.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/socket.h>
#include <locust/packet.h>
#include <locust/logger.h>

#include <net/if.h>
#if defined(__LINUX__) || defined(__DARWIN__)
#include <net/ethernet.h>
#endif
#include <netinet/if_ether.h>
#ifdef __LINUX__
#include <netinet/ether.h>
#endif

#define ETHERNET_DEFAULT_MAC "00:00:00:00:00:00"

/*!
 * \internal
 * \brief Header modifiers accepted.
 */
static const char *header_modifiers[] = { "src", "dst", "type", NULL };

/*!
 * \internal
 * \brief The list of protocols supported by the ethernet frame.
 */
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif
static const struct ethertype {
	unsigned int proto_num;
	const char *name;
} ether_type[] =
{
	{ ETHERTYPE_PUP,	"PUP" },
	{ ETHERTYPE_IP,		"IP" },
	{ ETHERTYPE_ARP,	"ARP" },
	{ ETHERTYPE_REVARP,	"RARP" },
	{ ETHERTYPE_IPV6,	"IPv6" }
};

/*!
 * \internal
 * \brief Get the ethernet protocol type based on the number.
 * \param proto The protocol number.
 * \returns The protocol name or NULL if none found.
 */
static const char *ethernet_protocol_name(unsigned int proto)
{
	int i;

	for (i = 0; i < sizeof(ether_type); i++) {
		if (ether_type[i].proto_num == proto) {
			return ether_type[i].name;
		}
	}

	return NULL;
}

/*!
 * \internal
 * \brief Implement the Ethernet protocol injector for packet manipulation.
 */
static int ethernet_protocol_injector(void *header, int default_values)
{
	if (default_values) {
		struct ether_header *hdr = (struct ether_header *)header;

		memcpy(hdr->ether_dhost, (void *)ether_aton("00:00:00:00:00:00"), 6);
		memcpy(hdr->ether_shost, (void *)ether_aton("00:00:00:00:00:00"), 6);
		hdr->ether_type = htons(ETHERTYPE_IP);
	}

	return 0;
}

/*!
 * \internal
 * \brief Implement the Ethernet header updater.
 */
static int ethernet_protocol_header_update(struct lct_packet *packet, struct lct_packet_protocol *proto)
{
	struct ether_header *hdr = (struct ether_header *)proto->ptr;
	struct lct_packet_protocol *nextproto;

	/* update the next protocol number. */
	nextproto = lct_packet_protocol_next(packet, proto);
	if (nextproto) {
		switch (nextproto->number) {
			case IPPROTO_IP:
				hdr->ether_type = htons(ETHERTYPE_IP);
				break;
			case IPPROTO_IPV6:
				hdr->ether_type = htons(ETHERTYPE_IPV6);
				break;
			default:
				hdr->ether_type = 0x0000;
				break;
		}
	}

	return 0;
}

/*!
 * \internal
 * \brief Dump an Ethernet header in a human readable form.
 * \param header The header to dump.
 * \retval a dinamycally allocated string with the dump of the IP header.
 */
static char *ethernet_protocol_header_dump(void *header)
{
#define ETH_HEADER_FORMAT 	"+-+-+-+-+-+-+-+-+-+-+-+-+-+ETH HEADER-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-63s|\n" \
				"|%-31s|%-31s|\n" \
				"|%-63s|\n" \
				"|%-31s|%31s|\n" \

	struct ether_header *hdr = (struct ether_header *)header;
	char *ret;
	char *src, *dst;
	const char *protoname;

	protoname = ethernet_protocol_name(ntohs(hdr->ether_type));
	src = lct_strdupa(ether_ntoa((struct ether_addr *)hdr->ether_shost));
	dst = lct_strdupa(ether_ntoa((struct ether_addr *)hdr->ether_dhost));
	
	asprintf(&ret, ETH_HEADER_FORMAT, dst, "", "", src, protoname, "");

	return ret;
}

/*!
 * \internal
 * \brief Handler to modify the Ethernet protocol header.
 * \param proto The Ethernet protocol structure pointer.
 * \param param The parameter name to modify.
 * \param arg The value to set.
 * \retval 0 on success.
 * \retval < 0 on error.
 */
static int ethernet_protocol_header_modify(struct lct_packet_protocol *proto, const char *param, void *arg)
{
	char *data = (char *)arg;
	struct ether_header *hdr = (struct ether_header *)proto->ptr;
	struct ether_addr *mac;

	if (!proto || !param || !arg) {
		return -1;
	}

	if (!strcasecmp(param, "src")) {
		mac = ether_aton(data);
		if (!mac) {
			return -1;
		}
		memcpy(&hdr->ether_shost, mac, 6);
	} else if (!strcasecmp(param, "dst")) {
		mac = ether_aton(data);
		if (!mac) {
			return -1;
		}
		memcpy(&hdr->ether_dhost, mac, 6);
	} else if (!strcasecmp(param, "type")) {
		hdr->ether_type = htons(atoi(data));
	}

	return 0;
}

static void *ethernet_protocol_header_getter(struct lct_packet_protocol *proto, const char *what, int *errcode)
{
	struct ether_header *hdr = (struct ether_header *)proto->ptr;

	*errcode = 0;

	if (!strcasecmp(what, "src")) {
		char *mac;
		mac = calloc(1, 20);
		if (mac) { 
			strcpy(mac, ether_ntoa((struct ether_addr *)hdr->ether_shost));
			return mac;
		} else {
			*errcode = -1;
			return NULL;
		}
	} else if (!strcasecmp(what, "dst")) {
		char *mac;
		mac = calloc(1, 20);
		if (mac) {
			strcpy(mac, ether_ntoa((struct ether_addr *)hdr->ether_dhost));
			return mac;
		} else {
			*errcode = -1;
			return NULL;
		}
	} else if (!strcasecmp(what, "type")) {
		unsigned int *type;
		type = malloc(sizeof(unsigned int));
		if (type) {
			*type = ntohs(hdr->ether_type);
			return type;
		} else {
			*errcode = -1;
			return NULL;
		}
		return type;
	}

	*errcode = -1;
	return NULL;
}

static const struct lct_injector ethernet_injector = {
	.name = "ethernet",
	.number = ETHERNETPROTO,
	.struct_len = sizeof(struct ether_header),
	.inject = ethernet_protocol_injector,
	.update = ethernet_protocol_header_update,
	.dump = ethernet_protocol_header_dump,
	.modify = ethernet_protocol_header_modify,
	.modifiers = header_modifiers,
	.getter = ethernet_protocol_header_getter
};

int lct_ethernet_register_builtin_commands(void)
{
	int res;

	res = lct_packet_injector_register(&ethernet_injector);

	return res;
}
