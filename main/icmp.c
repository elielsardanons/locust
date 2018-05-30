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
 * \brief Raw ICMP API.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/socket.h>
#include <locust/packet.h>

#include <netinet/in_systm.h>	/* n_short typedef */
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/*! \brief ICMP header modifiers accepted. */
static const char *header_modifiers[] = { "type", "code", "id", "seq", "mask", NULL };

/*! \brief Implement the ICMP protocol injector for packet manipulation. */
static int icmp_protocol_injector(void *header, int default_values)
{
	if (default_values) {
		struct icmp *hdr = (struct icmp *)header;

		hdr->icmp_type = ICMP_ECHO;
		hdr->icmp_code = 0;
		hdr->icmp_id = htons(0x42);
		hdr->icmp_seq = htons(0x42);
		hdr->icmp_mask = htonl(0);
	}

	return 0;
}

/*! \brief Implement the ICMP header updater. */
static int icmp_protocol_header_update(struct lct_packet *packet, struct lct_packet_protocol *proto)
{
	struct icmp *hdr = (struct icmp *)proto->ptr;

	/* update icmp protocol header checksum. */
	hdr->icmp_cksum = 0;
	hdr->icmp_cksum = lct_header_checksum((unsigned short *)hdr, lct_packet_len(packet, proto) + sizeof(struct icmp));

	return 0;
}

/*!
 * \internal
 * \brief Print in a human readable form the ICMP header.
 * \param header The ICMP header structure pointer.
 * \retval The header in a human readable form (dynamically allocated memory).
 */
static char *icmp_protocol_header_dump(void *header)
{
#define ICMP_HEADER_FORMAT 	"+-+-+-+-+-+-+-+-+-+-+-+-+ICMP HEADER+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-15d|%-15d|%-31d|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-31d|%-31d|\n" \
				"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-63d|\n"

	struct icmp *hdr = (struct icmp *)header;
	char *ret;

	asprintf(&ret, ICMP_HEADER_FORMAT,
			hdr->icmp_type,
			hdr->icmp_code,
			hdr->icmp_cksum,
			hdr->icmp_id,
			hdr->icmp_seq,
			hdr->icmp_mask);

	return ret;
}

/*!
 * \internal
 * \brief ICMP types.
 */
static const struct icmp_type {
	int value;
	const char *name;
} icmp_types[] =
{
	{ ICMP_ECHO,		"echo" },
	{ ICMP_ECHOREPLY,	"echoreply" },
	{ ICMP_UNREACH,		"unreachable" },
	{ ICMP_REDIRECT,	"redirect" },
	{ ICMP_SOURCEQUENCH,	"sourcequench" },
	{ ICMP_IREQ,		"inforequest" },
	{ ICMP_IREQREPLY,	"inforeply" },
	{ ICMP_TSTAMP,		"tstamprequest" },
	{ ICMP_TSTAMPREPLY,	"tstampreply" }
};

/*!
 * \internal
 * \todo Complete missing types. 
 * \brief Get the ICMP type number given its name.
 * \param name The ICMP type name.
 * \retval The type value
 * \retval -1 if none found.
 */
static int icmp_type_byname(const char *name)
{
	int i;

	for (i = 0; i < sizeof(icmp_types); i++) {
		if (!strcasecmp(icmp_types[i].name, name)) {
			return icmp_types[i].value;
		}
	}

	return -1;
}

/*!
 * \internal
 * \brief Return codes for each ICMP type.
 */
static const struct icmp_code {
	int value;
	const char *name;
} icmp_codes[] =
{
};

/*!
 * \internal
 * \brief Get the ICMP code number given its name.
 * \param name The ICMP code name.
 * \retval The code value
 * \retval -1 if none found.
 */
static int icmp_code_byname(const char *name)
{
	int i;

	for (i = 0; i < sizeof(icmp_codes); i++) {
		if (!strcasecmp(icmp_codes[i].name, name)) {
			return icmp_codes[i].value;
		}
	}

	return -1;
}

/*!
 * \internal
 * \brief Modify the UDP header values.
 * \param proto The protocol structure to modify.
 * \param param The parameter name to modify.
 * \param arg The value to set.
 */
static int icmp_protocol_header_modify(struct lct_packet_protocol *proto, const char *param, void *arg)
{
	struct icmp *hdr = (struct icmp *)proto->ptr;
	char *data = (char *)arg;

	if (!strcasecmp(param, "code")) {
		int code = icmp_code_byname(data);
		if (code < 0) {
			return -1;
		}
		hdr->icmp_code = code;
	} else if (!strcasecmp(param, "type")) {
		int type = icmp_type_byname(data);
		if (type < 0) {
			return -1;
		}
		hdr->icmp_type = type;
	} else if (!strcasecmp(param, "id")) {
		int id = atoi(data);
		hdr->icmp_id = htons(id);
	} else if (!strcasecmp(param, "seq")) {
		int seq = atoi(data);
		hdr->icmp_seq = htons(seq);
	} else if (!strcasecmp(param, "mask")) {
		memcpy(&hdr->icmp_mask, data, sizeof(hdr->icmp_mask));
	}

	return 0;
}

static const struct lct_injector icmp_injector = {
	.name = "icmp",
	.number = IPPROTO_ICMP,
	.struct_len = sizeof(struct icmp),
	.inject = icmp_protocol_injector,
	.update = icmp_protocol_header_update,
	.dump = icmp_protocol_header_dump,
	.modify = icmp_protocol_header_modify,
	.modifiers = header_modifiers,
	.getter = NULL
};

int lct_icmp_register_builtin_commands(void)
{
	int res;

	res = lct_packet_injector_register(&icmp_injector);

	return res;
}
