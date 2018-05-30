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
 * \brief Socket manipulation API.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>
#include <locust/socket.h>
#include <locust/cli.h>
#include <locust/packet.h>
#include <locust/route.h>

#include "libnet.h"

#include <net/if.h>
#include <sys/ioctl.h>

/*! \brief List of hosts that we know something. */
static list_t locust_hosts;
/*! \brief Locking mechanism for the list of hosts. */
static struct lct_lock locust_hosts_lock;

/*! \brief Every host has a unique id assigned, so we can reference it with that. */
static unsigned int last_hostid = 0;
/*! \brief Locking mechanism to access the unique host id. */
static struct lct_lock last_hostid_lock;

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_locust_hosts_meter(const void *notused)
{
	return sizeof(struct lct_host *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_locust_hosts_comparator(const void *a, const void *b)
{
	return strcmp(((struct lct_host *)a)->ip, ((struct lct_host *)b)->ip);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_locust_hosts_seeker(const void *a, const void *key)
{
	return lct_addrinfocmp(((struct lct_host *)a)->addr_info, (struct addrinfo *)key);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_sockets_meter(const void *notused)
{
	return sizeof(struct lct_socket *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_sockets_comparator(const void *a, const void *b)
{
	return (((struct lct_socket *)a)->sck - ((struct lct_socket *)b)->sck);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_sockets_seeker(const void *a, const void *key)
{
	return (((struct lct_socket *)a)->id == *(int *)key);
}

/*!
 * \internal
 * \brief Increment host reference counter, the host structure
 * will be released only if refcounter == 0.
 * \param host The target host.
 */
static void inc_host_ref(struct lct_host *host)
{
	host->refcount++;
}

/*!
 * \internal
 * \brief Decrement host reference counter, the host structure
 * will be released only if refcounter == 0.
 * \param host Target host.
 */
static void dec_host_ref(struct lct_host *host)
{
	host->refcount--;
}

/*!
 * \internal
 * \brief Increment socket references.
 * \param sck Socket structure.
 */
static void inc_socket_ref(struct lct_socket *sck)
{
	sck->refcount++;
}

/*!
 * \internal
 * \brief Decrement socket references.
 * \param sck Socket structure.
 */
static void dec_socket_ref(struct lct_socket *sck)
{
	sck->refcount--;
}

int lct_socket_port(struct lct_socket *sock)
{
	struct sockaddr_in *tmp;
	tmp = (struct sockaddr_in *)&sock->addr;
	return ntohs(tmp->sin_port);
}

const char *lct_socket_ip(struct lct_socket *sock)
{
	return sock->host_owner->ip;
}

int lct_socket_type(struct lct_socket *sock)
{
	return sock->type;
}

const char *lct_port_protocol2str(enum lct_port_protocol protocol)
{
	const char *ret;

	switch (protocol) {
		case PORT_TCP:
			ret = "tcp";
			break;
		case PORT_UDP:
			ret = "udp";
			break;
		default:
			ret = "UNKNOWN";
			break;
	}

	return ret;
}

/*!
 * \internal
 * \brief Create a 'host' entity
 * \param ip Host ip address.
 * \retval NULL on error.
 * \retval lct_host structure allocated on success.
 */
struct lct_host *host_create(const char *ip)
{
	struct lct_host *newhost, *hosttemp;
	struct addrinfo *ai;
	int res;

	if ((res = getaddrinfo(ip, NULL, NULL, &ai))) {
		lct_log(LCT_WARNING, "getaddrinfo() %s\n", gai_strerror(res));
		return NULL;
	}

	lct_mutex_lock(&locust_hosts_lock);
	hosttemp = (struct lct_host *)list_seek(&locust_hosts, ai);
	if (hosttemp) {
		/* already have a host with that ip? */
		inc_host_ref(hosttemp);
		lct_mutex_unlock(&locust_hosts_lock);
		freeaddrinfo(ai);
		return hosttemp;
	}

	/* allocate the lct_host structure. */
	newhost = calloc(1, sizeof(*newhost));
	if (!newhost) {
		lct_log(LCT_ERROR, "Unable to allocate a new host structure\n");
		lct_mutex_unlock(&locust_hosts_lock);
		freeaddrinfo(ai);
		return NULL;
	}

	newhost->addr_info = ai;
	newhost->ip = strdup(ip);

	/* initialize the sockets structure. */
	list_init(&newhost->sockets);
	list_attributes_copy(&newhost->sockets, list_sockets_meter, 0);
	list_attributes_comparator(&newhost->sockets, list_sockets_comparator);
	list_attributes_seeker(&newhost->sockets, list_sockets_seeker);

	/* initial reference count. */
	inc_host_ref(newhost);

	lct_mutex_lock(&last_hostid_lock);
	newhost->id = last_hostid + 1;
	/* increment last_hostid */
	last_hostid++;
	lct_mutex_unlock(&last_hostid_lock);

	lct_mutex_init(&newhost->lock, NULL);

	/* Insert the new host in the list. */
	list_append(&locust_hosts, newhost);

	lct_mutex_unlock(&locust_hosts_lock);

	return newhost;
}

/*!
 * \internal
 * \brief Get the name of the port status based on the
 * status enum.
 * \param status The current port status.
 * \retval The port status name (string).
 */
static const char *portstatus2str(enum lct_port_status status)
{
	const char *ret;

	switch (status) {
		case PORT_OPEN:
			ret = "open";
			break;
		case PORT_CLOSED:
			ret = "closed";
			break;
		case PORT_FILTERED:
			ret = "filtered";
			break;
		case PORT_UNKNOWN:
		default:
			ret = "unknown";
			break;
	}

	return ret;
}

/*!
 * \internal
 * \brief Get the port status enum based on the status name (string).
 * \param status The port status name.
 * \retval The port status enum (PORT_OPEN, PORT_CLOSED, etc).
 */
static enum lct_port_status portstatusstr2enum(const char *status)
{
	enum lct_port_status ret;

	if (!strcasecmp(status, "open")) {
		ret = PORT_OPEN;
	} else if (!strcasecmp(status, "closed")) {
		ret = PORT_CLOSED;
	} else if (!strcasecmp(status, "filtered")) {
		ret = PORT_FILTERED;
	} else {
		ret = PORT_UNKNOWN;
	}

	return ret;
}

/*!
 * \internal
 * \brief Get the socket status name based on the socket status enum.
 * \param status The current socket status.
 * \retval The socket status name (string).
 */
const char *socketstatus2str(enum lct_socket_status status)
{
	const char *ret;

	switch (status) {
		case LCT_SOCKET_LISTEN:
			ret = "listening";
			break;
		case LCT_SOCKET_CONNECTED:
			ret = "connected";
			break;
		case LCT_SOCKET_INITIALIZED:
			ret = "initialized";
			break;
		case LCT_SOCKET_RELEASED:
			ret = "released";
			break;
		default:
			ret = "unknown";
			break;
	}

	return ret;
}

/*!
 * \internal
 * \brief Free a the host ports.
 * \param host The host structure.
 */
static void free_ports(struct lct_host *host)
{
	struct lct_port *next, *tmp;

	if (!host->ports) {
		return;
	}

	for (tmp = host->ports; tmp; ) {
		next = tmp->next;
		free(tmp->service);
		free(tmp->version);
		free(tmp);
		tmp = next;
	}
}

/*!
 * \internal
 * \brief Free the lct_host structure.
 * \param h Host structure to free.
 */
static void free_host(struct lct_host *h)
{
	/* remove all the known ports of this host. */
	free_ports(h);
	freeaddrinfo(h->addr_info);
	free(h->ip);
	free(h);
}

/*!
 * \internal
 * \brief Remove a host structure from the list of hosts 
 * and free the memory allocated for this structure.
 * \param h lct_host structure to remove.
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int host_destroy(struct lct_host *h)
{
	struct lct_host *htemp;
	int pos;

	pos = list_locate(&locust_hosts, h);
	if (pos < 0) {
		lct_log(LCT_ERROR, "Trying to detroy a non-existent host\n");
		return -1;
	}
	htemp = list_extract_at(&locust_hosts, pos);
	free_host(htemp);

	return 0;
}

/*!
 * \internal
 * \brief Release a host structure. The memory allocated
 *        will be freed if not other thread is accesing this
 *        host.
 * \param h Host structure.
 */
void host_release(struct lct_host *h)
{
	lct_mutex_lock(&locust_hosts_lock);
	lct_mutex_lock(&h->lock);

	dec_host_ref(h);
	/* If the reference counter of the host is '0' then free
	 * all the allocated memory for this host */
	if (!h->refcount && !h->ports_counter) {
		if (!host_destroy(h)) {
			lct_mutex_unlock(&locust_hosts_lock);
			return;
		}
	}

	lct_mutex_unlock(&h->lock);
	lct_mutex_unlock(&locust_hosts_lock);
}

/*!
 * \internal
 * \brief Find a host structure with the given host ip.
 * \param hostname Host ip or hostname.
 * \retval NULL if no host is found with that ip/hostname.
 * \retval The host structure with the given host ip/hostname.
 */
static struct lct_host *host_find_byhostname(const char *hostname)
{
	struct lct_host *h;
	struct addrinfo *info;

	if (getaddrinfo(hostname, NULL, NULL, &info) < 0) {
		return NULL;
	}

	lct_mutex_lock(&locust_hosts_lock);
	h = list_seek(&locust_hosts, info);
	if (!h) {
		lct_mutex_unlock(&locust_hosts_lock);
		freeaddrinfo(info);
		return NULL;
	}

	inc_host_ref(h);
	lct_mutex_unlock(&locust_hosts_lock);
	freeaddrinfo(info);

	return h;
}

void lct_port_status(const char *hostname, const char *service, const char *version, int port_number,
	enum lct_port_protocol protocol, enum lct_port_status status)
{
	struct lct_host *host;
	struct lct_port *port = NULL, *tmp;

	host = host_create(hostname);
	if (!host) {
		return;
	}

	lct_mutex_lock(&host->lock);

	for (tmp = host->ports; tmp; tmp = tmp->next) {
		if (tmp->port == port_number && tmp->protocol == protocol) {
			port = tmp;
			break;
		}
	}

	if (!port) {
		port = calloc(1, sizeof(*port));
		if (!port) {
			host_release(host);
			lct_mutex_unlock(&host->lock);
			return;
		}

		/* insert the new port in the list (head) */
		port->next = host->ports;
		host->ports = port;
	}

	port->service = (service ? strdup(service) : NULL);
	if (service && !port->service) {
		host->ports = port->next;
		free(port);
		host_release(host);
		lct_mutex_unlock(&host->lock);
		return;
	}
	port->version = (version ? strdup(version) : NULL);
	if (version && !port->version) {
		host->ports = port->next;
		free(port);
		host_release(host);
		lct_mutex_unlock(&host->lock);
		return;
	}
	port->port = port_number;
	port->protocol = protocol;
	port->status = status;

	host->ports_counter++;
	lct_mutex_unlock(&host->lock);

	host_release(host);
}

struct lct_socket *lct_socket_find(const char *ip, int id)
{
	struct lct_socket *sock;
	struct lct_host *h;

	h = host_create(ip);
	if (!h) {
		return NULL;
	}

	lct_mutex_lock(&h->lock);
	sock = list_seek(&h->sockets, &id);
	lct_mutex_unlock(&h->lock);
	host_release(h);

	return sock;
}

/*!
 * \internal
 * \brief This is a way to track the sockets accepted for inbound connections.
 * \param sock The main socket receiving the connection.
 * \param sck The socket created for the accepted connection.
 */
static void socket_add_inbound(struct lct_socket *sock, int sck)
{
	lct_mutex_lock(&sock->lock);
	sock->inboundsck = realloc(sock->inboundsck, sizeof(int) * (sock->inboundcounter + 1));
	sock->inboundsck[sock->inboundcounter] = sck;
	sock->inboundcounter++;
	lct_mutex_unlock(&sock->lock);
}

int lct_accept(struct lct_socket *sock, struct sockaddr *addr, socklen_t *addrlen, int timeout)
{
	int sck, ret;
	struct timeval tv;
	fd_set sckset;

	FD_ZERO(&sckset);
	FD_SET(sock->sck, &sckset);

	/* if the passed timeout < 0, then block without timeout. */
	if (timeout >= 0) {
		tv.tv_sec = 0;
		tv.tv_usec = timeout * 1000;
		ret = select(sock->sck + 1, &sckset, NULL, NULL, &tv);
	} else {
		ret = select(sock->sck + 1, &sckset, NULL, NULL, NULL);
	}
	/* ret == 0 -> timeout, ret < 0 -> error, ret > 0 something to accept. */
	if (ret > 0) {
		sck = accept(sock->sck, addr, addrlen);
		if (sck > 0) {
			socket_add_inbound(sock, sck);
		}
		return sck;
	} else if (ret < 0) {
		return ret;
	}

	return 0;
}

int lct_socket_sendraw(struct lct_socket *sock, const char *datagram, size_t packetlen)
{
	int res = -1;

	if (sock->output) {
		res = libnet_write_link(sock->output, (unsigned char *)datagram, packetlen);
	}

	return res;
}

int lct_socket_sendto(struct lct_socket *sock, const char *payload, size_t payloadlen, int flags)
{
	int res = -1;

	if (sock->sck > 0) {
		res = sendto(sock->sck, payload, payloadlen, flags, sock->addr, sock->addrlen);
	}

	return res;
}

ssize_t lct_socket_read(struct lct_socket *sock, void *buffer, size_t buffer_len, int timeout)
{
	fd_set fds;
	struct timeval tv;
	struct pcap_pkthdr *pkt;
	const unsigned char *data;

	if (sock->type == SOCK_RAW) {
		pcap_set_timeout(sock->input, timeout);
		if (pcap_next_ex(sock->input, &pkt, &data) && pkt) {
			memcpy(buffer, data, (buffer_len > pkt->caplen ? pkt->caplen : buffer_len));
			return pkt->caplen;
		} else {
			return 0;
		}
	} else {
		if (timeout >= 0) {
			FD_ZERO(&fds);
			FD_SET(sock->sck, &fds);
			tv.tv_sec = 0;
			tv.tv_usec = timeout * 1000;

			if (select(sock->sck + 1, &fds, NULL, NULL, &tv) <= 0) {
				return -1;
			}
		}
		return read(sock->sck, buffer, buffer_len);
	}

	return -1;
}

struct lct_socket *lct_socket_raw(const char *hostname)
{
#ifdef HAVE_LIBPCAP
	struct lct_socket *sock;
	struct lct_host *h;
	pcap_t *pcapdev;
	char pcaperrbuf[PCAP_ERRBUF_SIZE] = "", libneterrbuf[LIBNET_ERRBUF_SIZE] = "";
	char device[80], srcip[NI_MAXHOST];

	if (!lct_running_as_root()) {
		lct_log(LCT_ERROR, "Permission denied, you must be root.\n");
		return NULL;
	}

	h = host_create(hostname);
	if (!h) {
		return NULL;
	}

	sock = calloc(1, sizeof(*sock));
	if (!sock) {
		lct_log(LCT_ERROR, "Unable to allocate raw socket structure\n");
		host_release(h);
		return NULL;
	}

	lct_mutex_lock(&h->lock);
	sock->host_owner = h;
	sock->id = (++h->lastid);
	sock->status = LCT_SOCKET_INITIALIZED;
	sock->type = SOCK_RAW;
	lct_mutex_init(&sock->lock, NULL);

	sock->addr = calloc(1, h->addr_info->ai_addrlen);
	if (!sock->addr) {
		lct_log(LCT_ERROR, "Unable to allocate sockaddr memory\n");
		free(sock);
		lct_mutex_unlock(&h->lock);
		host_release(h);
		return NULL;
	}

	memcpy(sock->addr, h->addr_info->ai_addr, h->addr_info->ai_addrlen);
	sock->addrlen = h->addr_info->ai_addrlen;

	/* select device to open based on the destination ip address. */
	if (lct_route_get_source_info(hostname, srcip, sizeof(srcip), device, sizeof(device)) < 0) {
		lct_log(LCT_ERROR, "Unable to open a device suitable to send this packet\n");
		free(sock);
		lct_mutex_unlock(&h->lock);
		host_release(h);
		return NULL;
	}

	sock->output = libnet_init(LIBNET_LINK_ADV, device, libneterrbuf);
	if (!sock->output) {
		lct_log(LCT_ERROR, "Unable to create raw socket (%s)\n", libneterrbuf);
		free(sock);
		lct_mutex_unlock(&h->lock);
		host_release(h);
		return NULL;
	}

	/* open the device for input packets. */
	pcapdev = pcap_open_live(device, BUFSIZ, 0, 5, pcaperrbuf);
	if (!pcapdev) {
		lct_log(LCT_ERROR, "%s\n", pcaperrbuf);
		free(sock);
		lct_mutex_unlock(&h->lock);
		host_release(h);
		return NULL;
	}
	if (strlen(pcaperrbuf) > 0) {
		lct_log(LCT_WARNING, "%s\n", pcaperrbuf);
	}
	sock->input = pcapdev;

	inc_socket_ref(sock);
	list_append(&h->sockets, sock);
	lct_mutex_unlock(&h->lock);

	return sock;
#else
	lct_log(LCT_ERROR, "RAW packets not supported if libpcap support is disabled\n");
	return NULL;
#endif
}

struct lct_socket *lct_socket_create(const char *ip, int type, int port)
{
	struct lct_socket *sock;
	struct lct_host *h;
	struct sockaddr_in *tmpsin;
	int sck;

	/* allocate a host structure. */
	h = host_create(ip);
	if (!h) {
		return NULL;
	}

	sock = calloc(1, sizeof(*sock));
	if (!sock) {
		lct_log(LCT_ERROR, "Unable to allocate socket structure\n");
		host_release(h);
		return NULL;
	}

	lct_mutex_lock(&h->lock);
	sock->host_owner = h;
	/* Assing an ID to this socket. */
	sock->id = (++h->lastid);
	sock->status = LCT_SOCKET_INITIALIZED;
	sock->type = type;
	lct_mutex_init(&sock->lock, NULL);

	/* create the socket sockaddr structure based on the host addrinfo structure. */
	sock->addr = calloc(1, h->addr_info->ai_addrlen);
	if (!sock->addr) {
		lct_log(LCT_ERROR, "sockaddr memory allocation failure\n");
		free(sock);
		lct_mutex_unlock(&h->lock);
		host_release(h);
		return NULL;
	}
	memcpy(sock->addr, h->addr_info->ai_addr, h->addr_info->ai_addrlen);
	tmpsin = (struct sockaddr_in *)sock->addr;
	tmpsin->sin_port = htons(port);
	sock->addrlen = h->addr_info->ai_addrlen;

	/* create the socket */
	sck = socket(h->addr_info->ai_family, type, 0);
	if (sck < 0) {
		lct_log(LCT_ERROR, "Unable to create internal socket\n");
		free(sock);
		lct_mutex_unlock(&h->lock);
		host_release(h);
		return NULL;
	}

	sock->sck = sck;
	inc_socket_ref(sock);
	/* add the allocated socket to the allocated host structure. */
	list_append(&h->sockets, sock);
	lct_mutex_unlock(&h->lock);

	return sock;
}

void lct_socket_close(struct lct_socket *sock)
{
	/* It is up to the owner, close the socket and release it. */
	pthread_cancel(sock->owner);
}

void lct_socket_release(struct lct_socket *sock)
{
	struct lct_host *h;
	int i, pos;

	if (!sock) {
		lct_log(LCT_ERROR, "No socket to be released\n");
		return;
	}

	h = sock->host_owner;
	lct_mutex_lock(&h->lock);

	/* we need to release this socket, or is someone using it? */
	lct_mutex_lock(&sock->lock);
	dec_socket_ref(sock);
	if (sock->refcount > 0) {
		lct_mutex_unlock(&sock->lock);
		return;
	}
	lct_mutex_unlock(&sock->lock);

	if (!sock->host_owner) {
		lct_log(LCT_ERROR, "No host owner for this socket\n");
		lct_mutex_unlock(&h->lock);
		return;
	}

	pos = list_locate(&h->sockets, sock);
	if (pos < 0) {
		lct_log(LCT_ERROR, "Internal error while trying to release a socket, we couldn't find it\n");
		lct_mutex_unlock(&h->lock);
		return;
	}

	sock = list_extract_at(&h->sockets, pos);
	lct_mutex_unlock(&h->lock);
	host_release(h);

#ifdef HAVE_LIBPCAP
	if (sock->type == SOCK_RAW && sock->input) {
		pcap_close(sock->input);
	} else
#endif
	if (sock->sck > 0) {
		close(sock->sck);
	}

	/* Close inbound sockets. */
	for (i = 0; i < sock->inboundcounter; i++) {
		close(sock->inboundsck[i]);
	}
	free(sock->inboundsck);
	free(sock->addr);
	free(sock);
}

/*!
 * \internal
 * \brief Count the number of allocated sockets for the specified host.
 * \param h Host structure to count sockets.
 * \retval Number of sockets allocated to this host. 
 */
static int host_sockets(struct lct_host *h)
{
	int count = 0;

	lct_mutex_lock(&h->lock);
	count = list_size(&h->sockets);
	lct_mutex_unlock(&h->lock);

	return count;
}

char *lct_hosts_complete(const char *word, int state)
{
	struct lct_host *host;
	int found = 0;
	size_t wordlen = strlen(word);
	char *ret = NULL;

	lct_mutex_lock(&locust_hosts_lock);
	list_iterator_start(&locust_hosts);
	while (list_iterator_hasnext(&locust_hosts)) {
		host = list_iterator_next(&locust_hosts);
		if (!strncasecmp(host->ip, word, wordlen)) {
			if (found >= state) {
				ret = strdup(host->ip);
				break;
			}
			found++;
		} 
	}
	list_iterator_stop(&locust_hosts);
	lct_mutex_unlock(&locust_hosts_lock);

	return ret;
}

/*!
 * \internal
 * \brief Handle CLI command 'host show' autocomplete.
 */
static char *host_show_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return lct_hosts_complete(word, state);
	}

	return NULL;
}

/*!
 * \internal
 * \brief Handle CLI command 'host show ports' autocomplete.
 */
static char *host_show_ports_complete(const char **cmd, const char *word, int pos, int state)
{
	const char *options[] = { "open", "closed", "filtered", "unknown", NULL };

	if (pos == 4) {
		return lct_hosts_complete(word, state);
	} else if (pos == 5) {
		return lct_cli_command_complete(options, word, state);
	}

	return NULL;
}

/*!
 * \internal
 * \brief Handle CLI command 'host show'.
 * \param args Structure with all the parameters being passed from the CLI.
 */
static enum lct_cli_result handle_command_host_show(struct lct_cliargs *args)
{
#define HOST_SHOW_FORMAT_TITLE "%-6s %-10s %-30s %-30s\n"
#define HOST_SHOW_FORMAT "%-6d %-10s %-30s %-30s\n"
	struct lct_host *h;
	struct lct_socket *sock;
	int sockets;
	int count = 0;

	if (args->argc < 3) {
		lct_cli_output("%-6s %-30s %-7s\n", "ID", "Hostname", "sockets");
		lct_mutex_lock(&locust_hosts_lock);
		list_iterator_start(&locust_hosts);
		while (list_iterator_hasnext(&locust_hosts)) {
			h = (struct lct_host *)list_iterator_next(&locust_hosts);
			sockets = host_sockets(h);
			lct_cli_output("%-6d %-30s %-7d\n", h->id, h->ip, sockets);
			count++;
		}
		list_iterator_stop(&locust_hosts);
		lct_mutex_unlock(&locust_hosts_lock);
		lct_cli_output("%d host%s\n", count, (count == 1 ? "" : "s"));
	} else {
		/* make report for a specific host. */
		h = host_find_byhostname(args->argv[2]);
		if (!h) {
			lct_cli_output("No such host '%s'\n", args->argv[2]);
			return CLI_FAILED;
		}
		lct_cli_output("Hostname: %s\n", h->ip);
		lct_mutex_lock(&h->lock);
		/* If we have sockets open for this host, show them. */
		list_iterator_start(&h->sockets);
		lct_cli_output("%-10s %-10s\n", "ID", "Status");
		while (list_iterator_hasnext(&h->sockets)) {
			sock = list_iterator_next(&h->sockets);
			lct_cli_output("%-10d %-10s\n", sock->id, socketstatus2str(sock->status));
			count++;
		}
		list_iterator_stop(&h->sockets);
		lct_mutex_unlock(&h->lock);
		host_release(h);
		lct_cli_output("%d socket%s\n", count, (count == 1 ? "" : "s"));
	}

	return CLI_SUCCESS;
#undef HOST_SHOW_FORMAT
#undef HOST_SHOW_FORMAT_TITLE
}

/*!
 * \internal
 * \brief Handle CLI command 'host show ports'.
 * \param args The cli command arguments.
 * \retval the cli_result enum (CLI_FAILED, CLI_SUCCESS, etc).
 */
static enum lct_cli_result handle_command_host_show_ports(struct lct_cliargs *args)
{
#define HOST_SHOW_FORMAT_TITLE "%-6s %-8s %-8s %-13s %-30s %-30s\n"
#define HOST_SHOW_FORMAT "%-6d %-8s %-8s %-13s %-30s %-30s\n"
	struct lct_host *host;
	struct lct_port *tmp;
	int filter = 0;
	enum lct_port_status status = PORT_OPEN;
	struct servent *service;
	int portscount = 0;

	if (args->argc < 4) {
		return CLI_USAGE;
	}

	if (args->argc >= 5) {
		filter = 1;
		status = portstatusstr2enum(args->argv[4]); 
		if (status == PORT_UNKNOWN && strcasecmp(args->argv[4], "unknown")) {
			lct_cli_output("Unknown port status\n");
			return CLI_FAILED;
		}
	}

	host = host_find_byhostname(args->argv[3]);
	if (!host) {
		lct_cli_output("No such host '%s'\n", args->argv[3]);
		return CLI_FAILED;
	}

	lct_mutex_lock(&host->lock);
	if (host->ports) {
		lct_cli_output(HOST_SHOW_FORMAT_TITLE, "Port", "Protocol", "Status", "StdService", "Service", "Version");
		for (tmp = host->ports; tmp; tmp = tmp->next) {
			if (filter && tmp->status != status) {
				continue;
			}
			service = getservbyport(htons(tmp->port), lct_port_protocol2str(tmp->protocol));
			lct_cli_output(HOST_SHOW_FORMAT, tmp->port,
						lct_port_protocol2str(tmp->protocol),
						portstatus2str(tmp->status), 
						(service && service->s_name ? service->s_name : "unknown"),
						(tmp->service ? tmp->service : "unknown"),
						(tmp->version ? tmp->version : "unknown"));
			portscount++;
		}
		lct_cli_output("%d port%s %s\n", portscount, (portscount == 1 ? "" : "s"), (args->argc >= 5 ? args->argv[4] : ""));
	}
	lct_mutex_unlock(&host->lock);
	host_release(host);

	return CLI_SUCCESS;
#undef HOST_SHOW_FORMAT
#undef HOST_SHOW_FORMAT_TITLE
}

int lct_host_register_builtin_commands(void)
{
	int res;

	res = lct_cli_command_register("host show", "List active hosts.", "host show [hostname]", handle_command_host_show, host_show_complete);
	res |= lct_cli_command_register("host show ports", "List known port status for the specified host.",
			"host show ports <hostname> [{open|closed|filtered|unknown}]", handle_command_host_show_ports, host_show_ports_complete);

	return res;
}

int lct_host_finish(void)
{
	int res;

	res = lct_cli_command_unregister("host show");
	res |= lct_cli_command_unregister("host show ports");

	lct_mutex_destroy(&locust_hosts_lock);
	lct_mutex_destroy(&last_hostid_lock);
	list_destroy(&locust_hosts);

	return res;
}

int lct_host_initialize(void)
{
	/* initialize the locust_hosts list. */
	list_init(&locust_hosts);
	list_attributes_copy(&locust_hosts, list_locust_hosts_meter, 0);
	list_attributes_comparator(&locust_hosts, list_locust_hosts_comparator);
	list_attributes_seeker(&locust_hosts, list_locust_hosts_seeker);

	lct_mutex_init(&locust_hosts_lock, NULL);
	lct_mutex_init(&last_hostid_lock, NULL);

	return 0;
}
