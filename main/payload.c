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
 * \brief Payload injector implementation.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/socket.h>
#include <locust/packet.h>

#define PAYLOAD_LEN 8

struct payload {
	unsigned char content[PAYLOAD_LEN];
};

/*! \brief ICMP header modifiers accepted. */
static const char *header_modifiers[] = { "content", NULL };

/*! \brief Implement the Payload protocol injector for packet manipulation. */
static int payload_protocol_injector(void *header, int default_values)
{
	return 0;
}

/*!
 * \internal
 * \brief Implement the payload header getter.
 */
static void *payload_protocol_header_getter(struct lct_packet_protocol *proto, const char *what, int *errcode)
{
	struct payload *hdr = (struct payload *)proto->ptr;
	char *res;

	if (!strcasecmp(what, "content")) {
		*errcode = 0;
		res = calloc(1, PAYLOAD_LEN + 1);
		if (!res) {
			*errcode = -1;
			return NULL;
		}
		memcpy(res, hdr->content, PAYLOAD_LEN);
		return res;
	}

	*errcode = -1;
	return NULL;
}

/*!
 * \internal
 * \brief Print in a human readable form the payload header.
 * \param header The payload header structure pointer.
 * \retval The header in a human readable form (dynamically allocated memory).
 */
static char *payload_protocol_header_dump(void *header)
{
#define PAYLOAD_HEADER_FORMAT 	"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+PAYLOAD+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
				"|%-63s|\n"

	char *ret;
	struct payload *hdr = (struct payload *)header;

	asprintf(&ret, PAYLOAD_HEADER_FORMAT, hdr->content);

	return ret;
}

/*!
 * \internal
 * \brief Modify the Payload header content.
 * \param proto The protocol structure to modify.
 * \param param The parameter name to modify.
 * \param arg The value to set.
 */
static int payload_protocol_header_modify(struct lct_packet_protocol *proto, const char *param, void *arg)
{
	struct payload *hdr = (struct payload *)proto->ptr;

	if (!strcasecmp(param, "content")) {
		memcpy(hdr->content, arg, sizeof(hdr->content));
	}

	return 0;
}

static const struct lct_injector payload_injector = {
	.name = "payload",
	.number = PAYLOADPROTO,
	.struct_len = sizeof(struct payload),
	.inject = payload_protocol_injector,
	.update = NULL,
	.dump = payload_protocol_header_dump,
	.modify = payload_protocol_header_modify,
	.modifiers = header_modifiers,
	.getter = payload_protocol_header_getter 
};

int lct_payload_register_builtin_commands(void)
{
	int res;

	res = lct_packet_injector_register(&payload_injector);

	return res;
}
