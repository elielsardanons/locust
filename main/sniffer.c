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

#include "locust.h"

#ifdef HAVE_LIBPCAP

#include <locust/logger.h>
#include <locust/cli.h>
#include <locust/sniffer.h>
#include <locust/packet.h>
#include <locust/route.h>

#ifdef __OPENBSD__
#include <net/ethertypes.h>
#else
#include <net/ethernet.h>
#endif

/*!
 * \internal
 * \brief All open devices.
 */
static list_t devices;
/*!
 * \internal
 * \brief Locking mechanism for the list of devices.
 */
static struct lct_lock devices_lck;

/*!
 * \internal
 * \brief Unique filter id.
 */
static unsigned int filter_id;
/*!
 * \internal
 * \brief filter id locking mechanism.
 */
static struct lct_lock filter_id_lock;

/*! \brief open device for sniffing. */
struct sniffer_device {
	/*! device name */
	char *name;
	/*! promiscuos mode? */
	int promisc;
	/*! The libpcap handler. */
	pcap_t *handler;
	/*! registered functions. */
	list_t filters;
	/*! \brief Thread receiving packets. */
	pthread_t thread;
	/*! structure reference counter. */
	int refcount;
	/*! locking mechanism. */
	struct lct_lock lock;
};

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_devices_meter(const void *notused)
{
	return sizeof(struct sniffer_device *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_devices_seeker(const void *a, const void *key)
{
	return !strncmp(((struct sniffer_device *)a)->name, (const char *)key, strlen((const char *)key));
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_filters_meter(const void *notused)
{
	return sizeof(struct lct_sniffer_filter *);
}

/*!
 * \brief Lock the list of open devices.
 */
static void devices_lock(void)
{
	lct_mutex_lock(&devices_lck);
}

/*!
 * \internal
 * \brief Unlock the list of open devices.
 */
static void devices_unlock(void)
{
	lct_mutex_unlock(&devices_lck);
}

/*!
 * \internal
 * \brief Release a sniffer_device from memory only if refcount == 0.
 * \param sd The sniffer_device structure to release.
 */
static void sniffer_device_release(struct sniffer_device *sd)
{
	int pos;

	devices_lock();
	lct_mutex_lock(&sd->lock);
	sd->refcount--;
	/* if this device is being used by another thread, just decrement
           the usage and return. */
	if (sd->refcount > 0) {
		lct_mutex_unlock(&sd->lock);
		devices_unlock();
		return;
	}

	/* this should never happen. */
	if (list_size(&sd->filters) > 0) {
		lct_log(LCT_WARNING, "Leaking memory while trying to destroy a sniffer with filters inside!\n");
	}

	/* remove from the list of open sniffer devices. */
	pos = list_locate(&devices, sd);
	list_extract_at(&devices, pos);
	/* now it is safe to unlock the list. */
	devices_unlock();

	/* stop sniffing packets. */
	pthread_cancel(sd->thread);
	lct_thread_join(sd->thread, NULL);

	/* close the libpcap handler. */
	pcap_close(sd->handler);
	free(sd->name);
	list_destroy(&sd->filters);
	lct_mutex_unlock(&sd->lock);
	free(sd);
}

/*!
 * \internal
 * \brief Release a sniffer_filter from memory.
 * \param sf
 * \note Call this function with sd locked.
 */
static void sniffer_filter_release(struct lct_sniffer_filter *sf)
{
	int pos;
	struct sniffer_device *sd;

	lct_mutex_lock(&sf->device->lock);
	pos = list_locate(&sf->device->filters, sf);
	list_extract_at(&sf->device->filters, pos);
	lct_mutex_unlock(&sf->device->lock);

	/* if we are saving the captured packets, close the
	   open file. */
	if (sf->dumper) {
		pcap_dump_close(sf->dumper);
	}

	/* did we allocate memory for the name of the file? */
	if (sf->save_file) {
		free(sf->save_file);
	}

	sd = sf->device;

	free(sf->filter);
	/* free the compiled filter. */
	pcap_freecode(&sf->compiled_filter);
	free(sf);
	/* try to release the sniffer device (decrement the usage) */
	sniffer_device_release(sd);
}

/*!
 * \internal
 * \brief Continue adding packet protocol headers based on the packet parsing.
 * \param packet The packet structure.
 */
static void sniffer_parse_packet_ip(struct lct_packet *packet)
{
	struct lct_packet_protocol *proto;
	char *protoname;
	int errcode;

	proto = lct_packet_protocol_inject(packet, "ip", 0);

	protoname = lct_packet_protocol_get(proto, "protocol", &errcode);
	if (errcode) {
		free(protoname);
		lct_log(LCT_ERROR, "Unable to get the IP header protocol value\n");
		return;
	}

	/* inject the next protocol based on the ip header without asking... */
	proto = lct_packet_protocol_inject(packet, protoname, 0);
	free(protoname);
}

/*!
 * \internal
 * \brief Continue adding packet protocol headers based on the packet parsing.
 * \param packet The packet structure.
 */
static void sniffer_parse_packet_ip6(struct lct_packet *packet)
{
	struct lct_packet_protocol *proto;
	char *protoname;
	int errcode;

	proto = lct_packet_protocol_inject(packet, "ipv6", 0);

	protoname = lct_packet_protocol_get(proto, "nextheader", &errcode);
	if (errcode) {
		free(protoname);
		lct_log(LCT_ERROR, "Unable to get the next header inside the IPV6 protocol header\n");
		return;
	}
	proto = lct_packet_protocol_inject(packet, protoname, 0);
	free(protoname);

}

/*!
 * \internal
 * \brief Parse a packet and populate a packet structure.
 * \param header A pcap header structure.
 * \param ptr The received packet pointer.
 * \retval NULL on error.
 * \retval The packet.
 */
static struct lct_packet *sniffer_parse_packet(const struct pcap_pkthdr *header, const unsigned char *ptr, struct sniffer_device *sd)
{
	struct lct_packet *packet;
	struct lct_packet_protocol *proto;
	int errcode;
	unsigned int *ethertype;

	packet = lct_packet_create();
	if (!packet) {
		return NULL;
	}

	/* setup the initial packet content. */
	lct_packet_payload_set(packet, ptr, header->len);

	/* start adding headers (we only support ethernet frames right now). */
	proto = lct_packet_protocol_inject(packet, "ethernet", 0);
	if (!proto) {
		lct_packet_release(packet->id);
		return NULL;
	}

	/* get the next type of protocol usually ip or ipv6 */
	ethertype = lct_packet_protocol_get(proto, "type", &errcode);
	if (errcode) {
		lct_log(LCT_ERROR, "Error getting ethernet packet type\n");
		lct_packet_release(packet->id);
		return NULL;
	}
	if (*ethertype == ETHERTYPE_IP) {
		sniffer_parse_packet_ip(packet);
	} else if (*ethertype == ETHERTYPE_IPV6) {
		sniffer_parse_packet_ip6(packet);
	} else {
		lct_log(LCT_ERROR, "Not supported packet\n");
	}
	free(ethertype);

	return packet;
}

/*!
 * \internal
 * \brief Receive a packet and execute the registered filters callback function.
 */
static void sniffer_get_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *data)
{
	struct sniffer_device *sd, *devpkt;
	struct lct_sniffer_filter *sf;
	struct lct_packet *packet;
	int save_packet = 0;

	devpkt = (struct sniffer_device *)args;

	/* parse the packet into the packet structure. */
	packet = sniffer_parse_packet(header, data, devpkt);

	/* call the callback functions registered. */
	devices_lock();
	list_iterator_start(&devices);
	while (list_iterator_hasnext(&devices)) {
		sd = list_iterator_next(&devices);
		lct_mutex_lock(&sd->lock);
		list_iterator_start(&sd->filters);
		while (list_iterator_hasnext(&sd->filters)) {
			sf = list_iterator_next(&sd->filters);
			if (bpf_filter(sf->compiled_filter.bf_insns, data, header->len, header->caplen)) {
				/* call each sniffer filter callback function passing the parsed packet. */
				sf->cb(packet);
				if (sf->dumper) {
					pcap_dump((unsigned char *)sf->dumper, header, data);
				}
				if (sf->save_packets) {
					save_packet = 1;
				}
			}
		}
		list_iterator_stop(&sd->filters);
		lct_mutex_unlock(&sd->lock);
	}
	list_iterator_stop(&devices);
	devices_unlock();

	if (!save_packet) {
		lct_packet_release(packet->id);
	}
}

/*!
 * \internal
 * \brief Thread receiving every packet.
 */
static void *sniffer_receive_packets(void *args)
{
	struct sniffer_device *sd = (struct sniffer_device *)args;

	while (1) {
		/* read a packet and run sniffer_get_packet if one was found. */
		pcap_dispatch(sd->handler, 0, sniffer_get_packet, (unsigned char *)sd);
		/* timeout 200ms */
		usleep(200);
		/* is someone trying to kill us? */
		pthread_testcancel();
	}

	lct_thread_exit(THREAD_CORE, NULL);
	return NULL;
}

/*!
 * \internal
 * \brief Create a sniffer (return the pointer locked).
 * \param device The device name.
 * \param promisc Open it in promiscuos mode?
 * \retval NULL on error.
 * \retval The created structure pointer.
 */
static struct sniffer_device *create_sniffer(const char *device, int promisc)
{
	struct sniffer_device *sd;
	char pcaperrbuf[PCAP_ERRBUF_SIZE] = "";
	pcap_t *handler;
	int res;

	/* if there is a sniffer device already allocated use it incrementing the use
	   count */
	devices_lock();
	sd = list_seek(&devices, device);
	if (sd) {
		lct_mutex_lock(&sd->lock);
		devices_unlock();
		sd->refcount++;
		return sd;
	}
	devices_unlock();

	/* open the device  to start receiving packets. */
	handler = pcap_open_live(device, BUFSIZ, promisc, 0, pcaperrbuf);
	if (!handler) {
		lct_log(LCT_ERROR, "Error opening device '%s' (%s)\n", device, pcaperrbuf);
		return NULL;
	} else if (strlen(pcaperrbuf) > 0) {
		lct_log(LCT_WARNING, "%s\n", pcaperrbuf);
	}
	if (pcap_setnonblock(handler, 1, pcaperrbuf) < 0) {
		lct_log(LCT_ERROR, "Couldn't set device %s as non-blocking (%s)\n", device, pcaperrbuf);
		pcap_close(handler);
		return NULL;
	}

	sd = calloc(1, sizeof(*sd));
	if (!sd) {
		lct_log(LCT_ERROR, "Unable to allocate the sniffer device structure\n");
		pcap_close(handler);
		return NULL;
	}

	/* create the list of filters. */
	list_init(&sd->filters);
	list_attributes_copy(&sd->filters, list_filters_meter, 0);

	sd->name = strdup(device);
	sd->promisc = promisc;
	sd->handler = handler;
	sd->refcount = 1;

	/* this is the thread that receives every packet */
	res = lct_thread(THREAD_CORE, &sd->thread, sniffer_receive_packets, sd);
	if (res) {
		lct_log(LCT_ERROR, "Error initializing the sniffer thread to receive packets\n");
	}

	lct_mutex_init(&sd->lock, NULL);
	lct_mutex_lock(&sd->lock);

	/* add the new sniffer device to the list. */
	devices_lock();
	list_append(&devices, sd);
	devices_unlock();

	return sd;
}

void lct_sniffer_save(struct lct_sniffer_filter *filter, const char *filename)
{
	if (!filename) {
		filter->save_packets = 1;
		return;
	}

	/* save the received packets in a file. */
	filter->save_file = strdup(filename);
	filter->dumper = pcap_dump_open(filter->device->handler, filename);
	if (!filter->dumper) {
		lct_log(LCT_ERROR, "Unable to save packets being sniffed %s\n", pcap_geterr(filter->device->handler));
	}
}

/*!
 * \internal
 * \brief Create a sniffer filter structure.
 * \param file The source filename of the one registering this filter.
 * \param line The source line number of the function creating this filter.
 * \param func The source function name creating this filter.
 * \param sd The sniffer device structure pointer to have access to the handler.
 * \param filter The filter string.
 * \param handler The callback function to execute when a packet is received.
 * \retval NULL on error.
 * \retval An allocated sniffer filter.
 */
static struct lct_sniffer_filter *create_filter(const char *file, int line, const char *func, struct sniffer_device *sd,
		const char *filter, int (*cb)(struct lct_packet *packet))
{
	struct lct_sniffer_filter *sf;
	int datalink, snaplen;

	if (!filter || !cb) {
		return NULL;
	}

	sf = calloc(1, sizeof(*sf));
	if (!sf) {
		return NULL;
	}

	/* type of datalink. */
	datalink = pcap_datalink(sd->handler);
	snaplen = pcap_snapshot(sd->handler);
	/* compile the filter. */
	if (pcap_compile_nopcap(snaplen, datalink, &sf->compiled_filter, filter, 0, 0) < 0) {
		lct_log(LCT_ERROR, "Invalid filter '%s'\n", filter);
		free(sf);
		return NULL;
	}

	lct_mutex_lock(&filter_id_lock);
	filter_id++;
	sf->id = filter_id;
	lct_mutex_unlock(&filter_id_lock);

	/* this is used for debugging purposes. */
	sf->file = file;
	sf->line = line;
	sf->func = func;

	/* save the filter. */
	sf->filter = strdup(filter);
	sf->device = sd;
	sf->cb = cb;

	return sf;
}

struct lct_sniffer_filter *__lct_sniffer_open(const char *file, int line, const char *func, const char *device, int promisc,
	const char *filter, int (*cb)(struct lct_packet *packet))
{
	struct sniffer_device *sd;
	struct lct_sniffer_filter *sf;

	sd = create_sniffer(device, promisc);
	if (!sd) {
		return NULL;
	}

	sf = create_filter(file, line, func, sd, filter, cb);
	if (!sf) {
		lct_mutex_unlock(&sd->lock);
		sniffer_device_release(sd);
		return NULL;
	}

	list_append(&sd->filters, sf);

	lct_mutex_unlock(&sd->lock);

	return sf;
}

void lct_sniffer_close(struct lct_sniffer_filter *sniff)
{
	sniffer_filter_release(sniff);
}

struct lct_sniffer_filter *lct_sniffer_filter_find(unsigned int id)
{
	struct lct_sniffer_filter *sf, *ret = NULL;
	struct sniffer_device *sd;

	devices_lock();
	list_iterator_start(&devices);
	while (list_iterator_hasnext(&devices)) {
		sd = list_iterator_next(&devices);
		list_iterator_start(&sd->filters);
		while (list_iterator_hasnext(&sd->filters)) {
			sf = list_iterator_next(&sd->filters);
			if (sf->id == id) {
				ret = sf;
				break;
			}
		}
		list_iterator_stop(&sd->filters);
		if (ret) {
			break;
		}
	}
	list_iterator_stop(&devices);
	devices_unlock();

	return ret;
}

/*!
 * \internal
 * \brief Sniffer ID autocomplete helper.
 */
static char *sniffer_id_autocomplete(const char *word, int state)
{
	struct sniffer_device *sd;
	struct lct_sniffer_filter *sf;
	char *ret, *options[600];
	int count = 0;

	devices_lock();
	list_iterator_start(&devices);
	while (list_iterator_hasnext(&devices) && count < 600) {
		sd = list_iterator_next(&devices);
		list_iterator_start(&sd->filters);
		while (list_iterator_hasnext(&sd->filters) && count < 600) {
			sf = list_iterator_next(&sd->filters);
			asprintf(&options[count++], "%d", sf->id);
		}
		list_iterator_stop(&sd->filters);
	}
	list_iterator_stop(&devices);
	devices_unlock();

	options[count] = NULL;
	ret = lct_cli_command_complete((const char **)options, word, state);
	while (count > 0) {
		free(options[--count]);
	}

	return ret;
}
/*!
 * \internal
 * \brief Handle CLI command 'sniffer show'.
 */
static enum lct_cli_result handle_command_sniffer_show(struct lct_cliargs *args)
{
#define SNIFFER_SHOW_TITLE_FORMAT "%-10s %-6s %-10s %-20s\n"
	struct sniffer_device *sd;
	struct lct_sniffer_filter *sf;

	lct_cli_output(SNIFFER_SHOW_TITLE_FORMAT, "ID", "Device", "File", "Filter");
	devices_lock();
	list_iterator_start(&devices);
	while (list_iterator_hasnext(&devices)) {
		sd = list_iterator_next(&devices);
		list_iterator_start(&sd->filters);
		while (list_iterator_hasnext(&sd->filters)) {
			sf = list_iterator_next(&sd->filters);
			lct_cli_output("%-10d %-6s %-10s %-20s\n", sf->id, sd->name, sf->file, (strlen(sf->filter) == 0 ? "any" : sf->filter));
		}
		list_iterator_stop(&sd->filters);
	}
	list_iterator_stop(&devices);
	devices_unlock();

	return CLI_SUCCESS;
#undef SNIFFER_SHOW_TITLE_FORMAT
}

/*!
 * \internal
 * \brief Callback function registered for raw sniffer (dump packets to stdout).
 */
static int sniffer_dump_raw(struct lct_packet *packet)
{
	return 0;
}

/*!
 * \internal
 * \brief Handle CLI command 'sniffer start raw'.
 */
static enum lct_cli_result handle_command_sniffer_start_raw(struct lct_cliargs *args)
{
	struct lct_sniffer_filter *sniff;
	int promisc = 0;
	char filter[LCT_MAX_COMPLETE_CMD] = "";

	if (args->argc < 4) {
		return CLI_USAGE;
	}

	if (args->argc > 4) {
		if (!strcasecmp(args->argv[4], "promisc")) {
			promisc = 1;
			lct_cli_join_args(filter, sizeof(filter), &args->argv[5]);
		} else {
			lct_cli_join_args(filter, sizeof(filter), &args->argv[4]);
		}
	}

	sniff = lct_sniffer_open(args->argv[3], promisc, filter, sniffer_dump_raw);
	if (!sniff) {
		return CLI_FAILED;
	}
	lct_cli_output("Sniffer id %d\n", sniff->id);

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief Handle CLI command 'sniffer start raw' autocomplete.
 */
static char *handle_command_sniffer_start_raw_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 4) {
		return lct_devices_autocomplete(word, state);
	}

	return NULL;
}

/*!
 * \internal
 * \brief Handle CLI command 'sniffer save'.
 */
static enum lct_cli_result handle_command_sniffer_save(struct lct_cliargs *args)
{
	int filter_id;
	struct lct_sniffer_filter *filter;

	if (args->argc < 4) {
		return CLI_USAGE;
	}

	filter_id = atoi(args->argv[2]);

	filter = lct_sniffer_filter_find(filter_id);
	if (!filter) {
		lct_cli_output("No matching filter with id '%d'\n", filter_id);
		return CLI_FAILED;
	}

	if (!strcasecmp(args->argv[3], "internal")) {
		lct_sniffer_save(filter, NULL);
	} else {
		lct_sniffer_save(filter, args->argv[3]);
	}

	return CLI_SUCCESS;
}

/*!
 * \internal
 * \brief Implements the autocomplete for the CLI command 'sniffer save'.
 */
static char *handle_command_sniffer_save_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return sniffer_id_autocomplete(word, state);
	}

	return NULL;
}

/*!
 * \internal
 * \brief Handle CLI command 'sniffer stop'.
 */
static enum lct_cli_result handle_command_sniffer_stop(struct lct_cliargs *args)
{
	unsigned int id;
	struct lct_sniffer_filter *sniff;

	if (args->argc < 3) {
		return CLI_USAGE;
	}

	id = atoi(args->argv[2]);
	if (id <= 0) {
		lct_cli_output("Invalid sniffer id\n");
		return CLI_FAILED;
	}

	sniff = lct_sniffer_filter_find(id);
	if (!sniff) {
		lct_cli_output("No sniffer found with id '%d'\n", id);
		return CLI_FAILED;
	}
	lct_sniffer_close(sniff);

	return CLI_SUCCESS;
}

static char *handle_command_sniffer_stop_complete(const char **cmd, const char *word, int pos, int state)
{
	if (pos == 3) {
		return sniffer_id_autocomplete(word, state);
	}

	return NULL;
}

int lct_sniffer_finish(void)
{
	int ret = 0;

	if (lct_running_as_root()) {
		ret = lct_cli_command_unregister("sniffer show");
		ret |= lct_cli_command_unregister("sniffer start raw");
		ret |= lct_cli_command_unregister("sniffer stop");
		ret |= lct_cli_command_unregister("sniffer save");
	}
	lct_mutex_destroy(&devices_lck);
	lct_mutex_destroy(&filter_id_lock);

	return ret;
}

int lct_sniffer_initialize(void)
{
	lct_mutex_init(&devices_lck, NULL);
	lct_mutex_init(&filter_id_lock, NULL);
	list_init(&devices);
	list_attributes_copy(&devices, list_devices_meter, 0);
	list_attributes_seeker(&devices, list_devices_seeker);

	if (lct_running_as_root()) {
		lct_cli_command_register("sniffer show", "Show registered filters to sniff packets.", "sniffer show", handle_command_sniffer_show, NULL); 
		lct_cli_command_register("sniffer start raw", "Initialize the raw packet sniffer.", "sniffer start raw <device> [promisc] [filter]",
				handle_command_sniffer_start_raw, handle_command_sniffer_start_raw_complete); 
		lct_cli_command_register("sniffer stop", "Stop a sniffer given its id.", "sniffer stop <id>", handle_command_sniffer_stop, handle_command_sniffer_stop_complete); 
		lct_cli_command_register("sniffer save", "Save the captured packets to a file or to memory if the 'internal' parameter is passed.",
				"sniffer save <id> <filename|internal>", handle_command_sniffer_save, handle_command_sniffer_save_complete); 
	} else {
		lct_log(LCT_INFO, "Sniffer is disabled, you need to be root to enable this feature.\n");
	}

	return 0;
}

#endif /* HAVE_LIBPCAP */

