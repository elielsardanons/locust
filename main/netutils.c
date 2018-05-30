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
 * \brief The network function utilities.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>

int lct_valid_port(int port)
{
	if (port > 0 && port < 65536) {
		return 1;
	}
	return 0;
}

int lct_addrinfocmp(struct addrinfo *a1, struct addrinfo *a2)
{
	struct addrinfo *tmp1, *tmp2;
	char addr1[NI_MAXHOST], addr2[NI_MAXHOST];

	for (tmp1 = a1; tmp1; tmp1 = tmp1->ai_next) {
		getnameinfo(tmp1->ai_addr, tmp1->ai_addrlen, addr1, sizeof(addr1), NULL, 0, NI_NUMERICHOST);
		for (tmp2 = a2; tmp2; tmp2 = tmp2->ai_next) {
			getnameinfo(tmp2->ai_addr, tmp2->ai_addrlen, addr2, sizeof(addr2), NULL, 0, NI_NUMERICHOST);
			if (!strcasecmp(addr1, addr2)) {
				return 1;
			}
		}
	}
	return 0;
}

int lct_protocol_number(const char *proto_name)
{
	struct protoent *p;
	int proto_number = -1;

	/* special locust protocols. */
	if (!strcasecmp(proto_name, "ethernet")) {
		return ETHERNETPROTO;
	} else if (!strcasecmp(proto_name, "payload")) {
		return PAYLOADPROTO;
	}

	p = getprotobyname(proto_name);
	if (p) {
		proto_number = p->p_proto;
	}
	endprotoent();

	return proto_number;
}

char *lct_protocol_name(int proto)
{
	struct protoent *p;
	char *ret = NULL;

	if (proto == ETHERNETPROTO) {
		return strdup("etherip");
	} else if (proto == PAYLOADPROTO) {
		return strdup("payload");
	}

	p = getprotobynumber(proto);
	if (p) {
		ret = strdup(p->p_name);
	}
	endprotoent();

	return ret;
}

unsigned short lct_header_checksum(unsigned short *addr, int len)
{
	int nleft = len, sum = 0;
	unsigned short *w = addr;
	unsigned short ret = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&ret) = *(unsigned char *) w;
		sum += ret;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ret = ~sum;

	return ret;
}

