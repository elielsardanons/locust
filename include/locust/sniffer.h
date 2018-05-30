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
 * \brief Locust sniffer API.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_SNIFFER_H
#define LOCUST_SNIFFER_H

#include "locust/autoconfig.h"

#ifdef HAVE_LIBPCAP

#include <locust.h>
#include <locust/packet.h>

struct sniffer_device;

/*! \brief A filter applied to a device. */
struct lct_sniffer_filter {
	/*! sniffer filter id. */
	unsigned int id;
	/*! \brief The file who register this filter. */
	const char *file;
	/*! \brief Line number. */
	int line;
	/*! \brief Function who register this filter. */
	const char *func;
	/*! \brief Save the received packets to a file. */
	char *save_file;
	/*! \brief Save packets in memory. */
	int save_packets;
	/*! \brief pcap dumper handler. */
	pcap_dumper_t *dumper;
	/*! \brief The filter for this event. */
	char *filter;
	/*! \brief The filter compiled. */
	struct bpf_program compiled_filter;
	/*! \brief The pointer to the device structure. */
	struct sniffer_device *device;
	/*! \brief The function to run if the packet pass 'filter' */
	int (*cb)(struct lct_packet *packet);
};

/*!
 * \brief Open a device for sniffing and register the callback function.
 * \param file The source filename.
 * \param line The source line number.
 * \param func The function name.
 * \param device The device name to open.
 * \param promisc Open it in promiscuos mode?
 * \param filter The filter string.
 * \param cb The callback function.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
struct lct_sniffer_filter *__lct_sniffer_open(const char *file, int line, const char *func, const char *device, int promisc, const char *filter,
	int (*cb)(struct lct_packet *packet));

#define lct_sniffer_open(device, promisc, filter, cb) __lct_sniffer_open(__FILE__, __LINE__, __PRETTY_FUNCTION__, device, promisc, filter, cb)

/*!
 * \brief Save the packets being sniffed to the specified filename.
 * \param filter The sniffer filter pointer.
 * \param filename The output filename.
 */
void lct_sniffer_save(struct lct_sniffer_filter *filter, const char *filename);

/*!
 * \brief Close an open sniffer.
 * \param sniff The sniffer pointer returned by a lct_sniffer_open call.
 * \see lct_sniffer_open
 */
void lct_sniffer_close(struct lct_sniffer_filter *sniff);

#endif /* HAVE_LIBPCAP */

#endif /* LOCUST_SNIFFER_H */
