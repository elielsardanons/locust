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
 * \brief Raw IP API.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/socket.h>
#include <locust/packet.h>
#include <locust/logger.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/*!
 * \internal
 * \brief Header modifiers accepted.
 */
static const char *header_modifiers[] = { "src", "dst", "ttl", "id", "protocol", NULL };

/*!
 * \internal
 * \brief Header modifiers accepted.
 */
static const char *header_modifiers6[] = { "src", "dst", "tclass", "flowlabel", "hoplimit", "nextheader", NULL };

/*!
 * \internal
 * \brief Implement the IP protocol injector for packet manipulation.
 */
static int ip_protocol_injector(void *header, int default_values)
{

	if (default_values) {
		struct ip *hdr = (struct ip *)header;

		hdr->ip_v = 4;
		hdr->ip_hl = 5;
		hdr->ip_sum = 0;
		hdr->ip_ttl = 64;
		hdr->ip_src.s_addr = inet_addr("127.0.0.1");
		hdr->ip_dst.s_addr = inet_addr("127.0.0.1");
	}

	return 0;
}

/*!
 * \internal
 * \brief Implement the IPv6 protocol injector for packet manipulation.
 */
static int ip6_protocol_injector(void *header, int default_values)
{
	if (default_values) {
		struct ip6_hdr *hdr = (struct ip6_hdr *)header;

		hdr->ip6_vfc = 0x60;
		hdr->ip6_nxt = IPPROTO_IPV6;
		hdr->ip6_plen = sizeof(*hdr);
		hdr->ip6_hlim = 60;
	}

	return 0;
}

/*!
 * \internal
 * \brief Implement the IP header updater.
 */
static int ip_protocol_header_update(struct lct_packet *packet, struct lct_packet_protocol *proto)
{
	struct ip *hdr = (struct ip *)proto->ptr;
	struct lct_packet_protocol *nextproto;
	int pktlen = 0;

	pktlen = proto->ptr_len; 

	/* update the next protocol number. */
	nextproto = lct_packet_protocol_next(packet, proto);
	if (nextproto) {
		hdr->ip_p = nextproto->number;
	}
	while (nextproto) {
		pktlen += nextproto->ptr_len;
		nextproto = lct_packet_protocol_next(packet, nextproto);
	}

	hdr->ip_len = htons(pktlen);
	hdr->ip_sum = 0;
	hdr->ip_sum = lct_header_checksum((unsigned short *)hdr, sizeof(struct ip));

	return 0;
}

/*!
 * \internal
 * \brief Implement the IPv6 header updater.
 */
static int ip6_protocol_header_update(struct lct_packet *packet, struct lct_packet_protocol *proto)
{
	struct ip6_hdr *hdr = (struct ip6_hdr *)proto->ptr;
	struct lct_packet_protocol *nextproto;
	int pktlen;

	/* update the next protocol number. */
	nextproto = lct_packet_protocol_next(packet, proto);
	if (nextproto) {
		hdr->ip6_nxt = nextproto->number;
	}

	pktlen = lct_packet_len(packet, proto);

	hdr->ip6_plen = htonl(pktlen);

	return 0;
}

/*!
 * \internal
 * \brief Implement the ipv4 protocol header getter.
 */
static void *ip_protocol_header_getter(struct lct_packet_protocol *proto, const char *what, int *errcode)
{
	*errcode = 0;

	struct ip *hdr = (struct ip *)proto->ptr;

	if (!strcasecmp(what, "src") || !strcasecmp(what, "dst")) {
		char *ip;
		ip = calloc(1, NI_MAXHOST + 1);
		if (!ip) {
			*errcode = -1;
			return NULL;
		} else {
			if (!strcasecmp(what, "src")) {
				strncpy(ip, inet_ntoa(hdr->ip_src), NI_MAXHOST);
			} else {
				strncpy(ip, inet_ntoa(hdr->ip_dst), NI_MAXHOST);
			}
			return ip;
		}
	} else if (!strcasecmp(what, "protocol")) {
		return lct_protocol_name(hdr->ip_p);
	}

	*errcode = -1;
	return NULL;
}

/*!
 * \internal
 * \brief Implement the ipv6 protocol header getter.
 */
static void *ip6_protocol_header_getter(struct lct_packet_protocol *proto, const char *what, int *errcode)
{
	*errcode = -1;
	return NULL;
}

/*!
 * \internal
 * \brief Dump an IP header in a human readable form.
 * \param header The header to dump.
 * \retval a dinamycally allocated string with the dump of the IP header.
 */
static char *ip_protocol_header_dump(void *header)
{
#define IP_HEADER_FORMAT 	"+-+-+-+-+-+-+-+-+-+-+-+-+-+IP HEADER+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-7u|%-7u|%-15u|%-31u|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-31u|%-1u|%-1u|%-1u|%-25u|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-15u|%-15s|%-31u|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-63s|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-63s|\n"

	struct ip *hdr = (struct ip *)header;
	char *ret;
	char *protoname;
	char src[NI_MAXHOST], dst[NI_MAXHOST];

	protoname = lct_protocol_name(hdr->ip_p);
	strncpy(src, inet_ntoa(hdr->ip_src), sizeof(src));
	strncpy(dst, inet_ntoa(hdr->ip_dst), sizeof(dst));

	asprintf(&ret, IP_HEADER_FORMAT,
				hdr->ip_v, hdr->ip_hl, hdr->ip_tos, ntohs(hdr->ip_len),
				hdr->ip_id, 0, 0, 0, hdr->ip_off,
				hdr->ip_ttl, protoname, hdr->ip_sum,
				src, dst);
	free(protoname);

	return ret;
}

/*!
 * \internal
 * \brief Get the ipv6 packet source address.
 * \param buffer The output buffer.
 * \param bufflen The output buffer size.
 * \param hdr The ipv6 header.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
static int ip6_source(char *buffer, size_t bufflen, struct ip6_hdr *hdr)
{
	int ret;
	struct sockaddr_in6 addr;

	memset(&addr, 0, sizeof(addr));
	memcpy(&addr.sin6_addr, &hdr->ip6_src, sizeof(addr.sin6_addr));
	addr.sin6_family = AF_INET6;
	ret = getnameinfo((struct sockaddr *)&addr, sizeof(addr), buffer, bufflen, NULL, 0, NI_NUMERICHOST);

	return ret;
}

/*!
 * \internal
 * \brief Get the ipv6 packet destination address.
 * \param buffer The output buffer.
 * \param bufflen The output buffer size.
 * \param hdr The ipv6 header.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
static int ip6_destination(char *buffer, size_t bufflen, struct ip6_hdr *hdr)
{
	int ret;
	struct sockaddr_in6 addr;

	memset(&addr, 0, sizeof(addr));
	memcpy(&addr.sin6_addr, &hdr->ip6_dst, sizeof(addr.sin6_addr));
	addr.sin6_family = AF_INET6;
	ret = getnameinfo((struct sockaddr *)&addr, sizeof(addr), buffer, bufflen, NULL, 0, NI_NUMERICHOST);

	return ret;
}

/*!
 * \internal
 * \brief Dump an IPv6 header in a human readable form.
 * \param header The header to dump.
 * \retval a dinamycally allocated string with the dump of the IPv6 header.
 */
static char *ip6_protocol_header_dump(void *header)
{
#define IPV6_HEADER_FORMAT 	"+-+-+-+-+-+-+-+-+-+-+-+-+-+IPv6 HEADER+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-7d|%-15d|%-39d|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-31d|%-15d|%-15d|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|                                                               |\n" \
				"|%-63s|\n" \
				"|                                                               |\n" \
				"|                                                               |\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|                                                               |\n" \
				"|%-63s|\n" \
				"|                                                               |\n" \
				"|                                                               |\n"

	struct ip6_hdr *hdr = (struct ip6_hdr *)header;
	char *ret = NULL;
	char src[NI_MAXHOST], dst[NI_MAXHOST];

	ip6_source(src, sizeof(src), hdr);
	ip6_destination(dst, sizeof(dst), hdr);

	asprintf(&ret, IPV6_HEADER_FORMAT, 6, 0, 0, 0, 0, 0, src, dst);

	return ret; 
}

/*!
 * \internal
 * \brief Handler to modify the IP protocol header.
 * \param proto The IP protocol structure pointer.
 * \param param The parameter name to modify.
 * \param arg The value to set.
 * \retval 0 on success.
 * \retval < 0 on error.
 */
static int ip_protocol_header_modify(struct lct_packet_protocol *proto, const char *param, void *arg)
{
	char *data = (char *)arg;
	struct ip *hdr = (struct ip *)proto->ptr;

	if (!proto || !param || !arg) {
		return -1;
	}

	if (!strcasecmp(param, "src")) {
		inet_aton(data, &hdr->ip_src);
	} else if (!strcasecmp(param, "dst")) {
		inet_aton(data, &hdr->ip_dst);
	} else if (!strcasecmp(param, "ttl")) {
		hdr->ip_ttl = htons(atoi(data));
	} else if (!strcasecmp(param, "id")) {
		hdr->ip_id = htons(atoi(data));
	} else if (!strcasecmp(param, "protocol")) {
		hdr->ip_p = htons(atoi(data));
	}

	return 0;
}

/*!
 * \internal
 * \brief Handler to modify the IPv6 protocol header.
 * \param proto The IP protocol structure pointer.
 * \param param The parameter name to modify.
 * \param arg The value to set.
 * \retval 0 on success.
 * \retval < 0 on error.
 */
static int ip6_protocol_header_modify(struct lct_packet_protocol *proto, const char *param, void *arg)
{
	return 0;
}

int lct_ip_get_source(char *buffer, size_t bufflen, struct lct_packet_protocol *proto)
{
	struct ip *hdr;
	struct ip6_hdr *hdr6;
	int res = 0;

	if (!proto) {
		lct_log(LCT_WARNING, "Passing an invalid ip protocol structure\n");
		return -1;
	}

	/* is this an IP protocol structure? */
	if (proto->number != IPPROTO_IP && proto->number != IPPROTO_IPV6) {
		lct_log(LCT_WARNING, "This is not an IP header protocol structure.\n");
		return -1;
	}


	if (proto->number == IPPROTO_IP) {
		/* ipv4 */
		hdr = (struct ip *)proto->ptr;
		strncpy(buffer, inet_ntoa(hdr->ip_src), bufflen);
	} else {
		/* ipv6 */
		struct sockaddr_in6 addr;
		hdr6 = (struct ip6_hdr *)proto->ptr;
		addr.sin6_addr = hdr6->ip6_src;
		addr.sin6_family = AF_INET6;
		res = getnameinfo((struct sockaddr *)&addr, sizeof(addr), buffer, bufflen, NULL, 0, NI_NUMERICHOST);
	}

	return res;
}

int lct_ip_get_destination(char *buffer, size_t bufflen, struct lct_packet_protocol *proto)
{
	int res = 0;

	if (!proto) {
		lct_log(LCT_WARNING, "Passing an invalid ip protocol structure\n");
		return -1;
	}

	/* is this an IP protocol structure? */
	if (proto->number != IPPROTO_IP && proto->number != IPPROTO_IPV6) {
		lct_log(LCT_WARNING, "This is not an IPv4 or IPv6 header protocol structure.\n");
		return -1;
	}

	if (proto->number == IPPROTO_IP) {
		/* ipv4 */
		struct ip *hdr = (struct ip *)proto->ptr;
		strncpy(buffer, inet_ntoa(hdr->ip_dst), bufflen);
	} else {
		/* ipv6 */
		struct sockaddr_in6 addr;
		struct ip6_hdr *hdr6 = (struct ip6_hdr *)proto->ptr;
		memcpy(&addr.sin6_addr, &hdr6->ip6_dst, sizeof(addr.sin6_addr));
		addr.sin6_family = AF_INET6;
		res = getnameinfo((struct sockaddr *)&addr, sizeof(addr), buffer, bufflen, NULL, 0, NI_NUMERICHOST);
	}

	return res;
}

int lct_ip_get_saddr(void *buff, size_t bufflen, struct lct_packet_protocol *proto)
{
	if (!proto) {
		lct_log(LCT_WARNING, "Passing an invalid ip protocol structure\n");
		return -1;
	}

	/* is this an IP protocol structure? */
	if (proto->number != IPPROTO_IP && proto->number != IPPROTO_IPV6) {
		lct_log(LCT_WARNING, "This is not an IP/IPv6 header protocol structure.\n");
		return -1;
	}

	if (proto->number == IPPROTO_IP) {
		struct ip *hdr = (struct ip *)proto->ptr;
		/* ipv4 result */
		if (bufflen < sizeof(hdr->ip_src.s_addr)) {
			lct_log(LCT_ERROR, "Truncating result buffer too short for the requested ip address\n");
		}
		memcpy(buff, &hdr->ip_src.s_addr, bufflen);
	} else {
		/* ipv6 result */
		struct ip6_hdr *hdr = (struct ip6_hdr *)proto->ptr;
		if (bufflen < sizeof(hdr->ip6_src.s6_addr)) {
			lct_log(LCT_ERROR, "Truncating result buffer too short for the requested ip address\n");
		}
		memcpy(buff, &hdr->ip6_src.s6_addr, bufflen);
	}

	return 0;
}

int lct_ip_get_daddr(void *buff, size_t bufflen, struct lct_packet_protocol *proto)
{
	if (!proto) {
		lct_log(LCT_WARNING, "Passing an invalid ip protocol structure\n");
		return -1;
	}

	/* is this an IP protocol structure? */
	if (proto->number != IPPROTO_IP && proto->number != IPPROTO_IPV6) {
		lct_log(LCT_WARNING, "This is not an IP/IPv6 header protocol structure.\n");
		return -1;
	}

	if (proto->number == IPPROTO_IP) {
		/* ipv4 result */
		struct ip *hdr = (struct ip *)proto->ptr;
		if (bufflen < sizeof(hdr->ip_dst.s_addr)) {
			lct_log(LCT_ERROR, "Truncating result buffer too short for the requested ip address\n");
		}
		memcpy(buff, &hdr->ip_dst.s_addr, bufflen);
	} else {
		/* ipv6 result */
		struct ip6_hdr *hdr = (struct ip6_hdr *)proto->ptr;
		if (bufflen < sizeof(hdr->ip6_dst.s6_addr)) {
			lct_log(LCT_ERROR, "Truncating result buffer too short for the requested ip address\n");
		}
		memcpy(buff, &hdr->ip6_dst.s6_addr, bufflen);
	}

	return 0;
}

unsigned short lct_ip_get_len(struct lct_packet_protocol *proto)
{
	if (!proto) {
		lct_log(LCT_WARNING, "Passing an invalid ip protocol structure\n");
		return 0;
	}

	/* is this an IP protocol structure? */
	if (proto->number != 0) {
		lct_log(LCT_WARNING, "This is not an IP header protocol structure.\n");
		return 0;
	}

	if (proto->number == IPPROTO_IP) {
		struct ip *hdr = (struct ip *)proto->ptr;
		return hdr->ip_len;
	} else { 
		struct ip6_hdr *hdr = (struct ip6_hdr *)proto->ptr;
		return hdr->ip6_plen;
	}
}

unsigned char lct_ip_get_protocol(struct lct_packet_protocol *proto)
{
	if (!proto) {
		lct_log(LCT_WARNING, "Passing an invalid ip protocol structure\n");
		return 0;
	}

	/* is this an IP protocol structure? */
	if (proto->number != IPPROTO_IP || proto->number != IPPROTO_IPV6) {
		lct_log(LCT_WARNING, "This is not an IP header protocol structure.\n");
		return 0;
	}

	if (proto->number == IPPROTO_IP) {
		struct ip *hdr = (struct ip *)proto->ptr;
		return hdr->ip_p;
	} else {
		struct ip6_hdr *hdr = (struct ip6_hdr *)proto->ptr;
		return hdr->ip6_nxt;
	}
}

/*!
 * \internal
 * \brief An IP protocol header injector.
 */
static const struct lct_injector ip_injector =
{
	.name = "ip",
	.number = IPPROTO_IP,
	.struct_len = sizeof(struct ip),
	.inject = ip_protocol_injector,
	.update = ip_protocol_header_update,
	.dump = ip_protocol_header_dump,
	.modify = ip_protocol_header_modify,
	.modifiers = header_modifiers,
	.getter = ip_protocol_header_getter
};

/*!
 * \internal
 * \brief An IPv6 protocol header injector.
 */
static const struct lct_injector ip6_injector =
{
	.name = "ipv6",
	.number = IPPROTO_IPV6, 
	.struct_len = sizeof(struct ip6_hdr),
	.inject = ip6_protocol_injector,
	.update = ip6_protocol_header_update,
	.dump = ip6_protocol_header_dump,
	.modify = ip6_protocol_header_modify,
	.modifiers = header_modifiers6,
	.getter = ip6_protocol_header_getter 
};

int lct_ip_register_builtin_commands(void)
{
	int res;

	res = lct_packet_injector_register(&ip_injector);
	res |= lct_packet_injector_register(&ip6_injector);

	return res;
}
