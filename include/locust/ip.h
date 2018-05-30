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
 * \brief IP Definitions.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_IP_H
#define LOCUST_IP_H

/*!
 * \brief Get the IP destination address from the header.
 * \param proto The IP protocol structure.
 * \param buff Output buffer.
 * \param bufflen Output buffer len.
 * \retval < 0 on error
 * \retval 0 on success.
 */
int lct_ip_get_daddr(void *buff, size_t bufflen, struct lct_packet_protocol *proto);

/*!
 * \brief Get the IP source address from the header.
 * \param proto The IP protocol structure.
 * \param buff Output buffer.
 * \param bufflen Output buffer len.
 * \retval < 0 on error
 * \retval 0 on success.
 */
int lct_ip_get_saddr(void *buff, size_t bufflen, struct lct_packet_protocol *proto);

/*!
 * \brief Get the IP source address from the header.
 * \param buffer The output buffer.
 * \param bufflen The output buffer lenght.
 * \param proto The IP protocol structure.
 */
void lct_ip_get_source(char *buffer, size_t bufflen, struct lct_packet_protocol *proto);

/*!
 * \brief Get the IP destination address from the header.
 * \param buffer The output buffer.
 * \param bufflen The output buffer lenght.
 * \param proto The IP protocol structure.
 */
void lct_ip_get_destination(char *buffer, size_t bufflen, struct lct_packet_protocol *proto);

/*!
 * \brief Get the IP length from the header.
 * \param proto The IP protocol structure.
 */
unsigned short lct_ip_get_len(struct lct_packet_protocol *proto);

/*!
 * \brief Get the IP protocol from the header.
 * \param proto The IP protocol structure.
 */
unsigned char lct_ip_get_protocol(struct lct_packet_protocol *proto);

#endif /* LOCUST_IP_H */
