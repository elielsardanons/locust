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
 * \brief Locust routing API.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>

#ifdef HAVE_LIBPCAP
static pcap_if_t *network_devices;
#endif

/*!
 * \internal
 * \brief Load the LIBPCAP list of devices.
 */
static int load_devices(void)
{
#ifdef HAVE_LIBPCAP
	char pcaperrbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&network_devices, pcaperrbuf) < 0) {
		lct_log(LCT_ERROR, "Error getting device names (%s)\n", pcaperrbuf);
		return -1;
	}
#endif
	return 0;
}

/*!
 * \internal
 * \brief Get a device name based on the destination ip address.
 * \param ip Target ip address.
 * \param devname A buffer to store the device name found.
 * \param devname_len The lenght of the devname buffer.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
static int devices_find_byip(const char *ip, char *devname, size_t devname_len)
{
#ifdef HAVE_LIBPCAP
	pcap_if_t *dev;
	pcap_addr_t *addr;
	char buf[INET6_ADDRSTRLEN], *tmp;
	socklen_t buf_size = sizeof(buf);

	for (dev = network_devices; dev; dev = dev->next) {
		for (addr = dev->addresses; addr; addr = addr->next) {
			if (addr->addr->sa_family == AF_INET) {
				/* compare ipv4 address. */
				tmp = inet_ntoa(((struct sockaddr_in *)(addr->addr))->sin_addr);
				if (!strcasecmp(ip, tmp)) {
					strncpy(devname, dev->name, devname_len);
					return 0;
				}
			} else {
				/* compare ipv6 address. */
				getnameinfo((struct sockaddr *)(addr->addr), sizeof(struct sockaddr_in6), buf, buf_size, NULL, 0, NI_NUMERICHOST);
				if (!strcasecmp(ip, buf)) { 
					strncpy(devname, dev->name, devname_len);
					return 0;
				}
			}
		}
	}
#endif
	return -1;
}

char *lct_devices_autocomplete(const char *word, int state)
{
	char *ret = NULL;
#ifdef HAVE_LIBPCAP
	pcap_if_t *dev;
	int i = 0;
#endif
	size_t wordlen;

	if (!word) {
		return NULL;
	}
	wordlen = strlen(word);

#ifdef HAVE_LIBPCAP
	/* search inside the list of network devices, then one that match best */
	for (dev = network_devices; dev; dev = dev->next) {
		if (!strncasecmp(word, dev->name, wordlen) && state <= i++) {
			ret = strdup(dev->name);
			break;
		}
	}
#endif
	return ret;
}

int lct_valid_network_device(const char *name)
{
#ifdef HAVE_LIBPCAP
	pcap_if_t *dev;

	for (dev = network_devices; dev; dev = dev->next) {
		if (!strcasecmp(dev->name, name)) {
			return 1;
		}
	}
#endif
	return 0;
}

int lct_route_get_source_info(const char *hostname, char *src, size_t src_len, char *devname, size_t devname_len)
{
	int fd, res;
        socklen_t n;
	struct addrinfo *ai;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	if ((res = getaddrinfo(hostname, "tftp", NULL, &ai))) {
		lct_log(LCT_WARNING, "getaddrinfo() %s\n", gai_strerror(res));
		return -1;
	}

	/* let the OS assign a source ip address :-) */
	if ((fd = socket(ai->ai_family, SOCK_DGRAM, 0)) < 0) {
		freeaddrinfo(ai);
		return -1;
	}

	if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
		close(fd);
		freeaddrinfo(ai);
		return -1;
	}

	if (ai->ai_family == AF_INET) {
		/* ipv4 */
		memset(&sin6, 0, sizeof(sin6));
		if (getsockname(fd, (struct sockaddr *)&sin, &n) < 0) {
			close(fd);
			freeaddrinfo(ai);
			return -1;
		}
		sin.sin_family = AF_INET;
		res = getnameinfo((struct sockaddr *)&sin, sizeof(sin), src, src_len, NULL, 0, NI_NUMERICHOST);
	} else {
		memset(&sin6, 0, sizeof(sin6));
		/* ipv6 */
		if (getsockname(fd, (struct sockaddr *)&sin6, &n) < 0) {
			close(fd);
			freeaddrinfo(ai);
			return -1;
		}
		sin6.sin6_family = AF_INET6;
		res = getnameinfo((struct sockaddr *)&sin6, sizeof(sin6), src, src_len, NULL, 0, NI_NUMERICHOST);
	}

	freeaddrinfo(ai);
	close(fd);

	if (res) {
		lct_log(LCT_ERROR, "Unable to find source ip based on destination ip address (%s)\n", gai_strerror(res));
		return -1;
	}

	/* find the device name based on the found source address */
	if (devices_find_byip(src, devname, devname_len)) {
		lct_log(LCT_ERROR, "Unable to get interface based on the ipaddress\n");
		return -1;
	}

	return 0;
}

int lct_route_finish(void)
{
	/* free the list of network devices */
	pcap_freealldevs(network_devices);

	return 0;
}

int lct_route_initialize(void)
{
	int res;

	/* initialize the list of network devices. */
	res = load_devices();

	return res;
}
