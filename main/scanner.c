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
 * \brief Scanner subsystem implementation.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/socket.h>
#include <locust/scanner.h>
#include <locust/cli.h>
#include <locust/logger.h>

/*! \brief The list of registered scanners. */
static list_t scanners; 
/*! \brief The lock for the list of registered scanners. */
static struct lct_lock scanners_list_lock;

/*! \brief Pass the parameters to the scanner thread using this structure. */
struct scanner_thread_params {
	/*! The hostname of the target to scan. */
	char *hostname;
	/*! The port to check its status (scan) . */
	int port;
	/*! The scanner to use for this action. */
	struct lct_scanner *scanner;
};

/*! \brief Pass the parameters to the scanner loop thread using this structure. */
struct loop_scanner_thread_params {
	/*! The hostname of the target to scan. */
	char *hostname;
	/*! The initial port to scan. */
	int port_init;
	/*! The final port to scan. */
	int port_end;
	/*! The scanner driver to use. */
	struct lct_scanner *scanner;
};

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_scanners_meter(const void *notused)
{
	return sizeof(struct lct_scanner *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_scanners_seeker(const void *a, const void *key)
{
	struct lct_scanner *c = (struct lct_scanner *)a;
	const char *name = (const char *)key;

	return !strcmp(c->name, name);
}

/*!
 * \internal
 * \brief Lock the scanners structure.
 */
static void scanners_lock(void)
{
	lct_mutex_lock(&scanners_list_lock);
}

/*!
 * \internal
 * \brief Unlock the scanners structure.
 */
static void scanners_unlock(void)
{
	lct_mutex_unlock(&scanners_list_lock);
}

/*!
 * \internal
 * \brief Free the scanner structure.
 * \param scanner The scanner structure to be freed.
 */
static void free_scanner(struct lct_scanner *scanner)
{
	free(scanner->name);
	free(scanner);
}

int lct_scanner_register(const char *name, int priority, enum lct_port_protocol protocol,
		enum lct_port_status (*scanner)(const char *hostname, int port))
{
	struct lct_scanner *scan;

	scan = calloc(1, sizeof(*scan));
	if (!scan) {
		return -1;
	}

	scan->protocol = protocol;
	scan->name = strdup(name);
	scan->scan = scanner;

	/* insert the new scanner in the list. */
	scanners_lock();
	list_append(&scanners, scan);
	scanners_unlock();

	return 0;
}

int lct_scanner_unregister(const char *name)
{
	struct lct_scanner *tmp;
	int pos;

	scanners_lock();
	tmp = list_seek(&scanners, name);
	if (tmp) {
		if (tmp->refcount) {
			lct_log(LCT_ERROR, "The scanner is being used, we can't unregister it\n");
			scanners_unlock();
			return -1;
		}
		lct_log(LCT_DEBUG, "Unregistering scanner '%s'\n", name);
		pos = list_locate(&scanners, tmp);
		tmp = list_extract_at(&scanners, pos);	
		free_scanner(tmp);
	} else {
		lct_log(LCT_ERROR, "No such scanner '%s'\n", name);
	}
	scanners_unlock();

	return -1;
}

/*!
 * \internal
 * \brief Start using a scanner (increment the refcount for this scanner).
 * \param name Scanner name.
 * \retval NULL on error.
 * \retval The scanner we will use.
 */
static struct lct_scanner *scanner_use(const char *name)
{
	struct lct_scanner *tmp = NULL;

	scanners_lock();
	tmp = list_seek(&scanners, name);
	if (tmp) {
		tmp->refcount++;
	}
	scanners_unlock();

	return tmp;
}

/*!
 * \internal
 * \brief Stop using a scanner (release it, decrementing the refcount).
 * \param scanner The scanner structure.
 */
static void scanner_release(struct lct_scanner *scanner)
{
	scanners_lock();
	scanner->refcount--;
	if (scanner->refcount < 0) {
		lct_log(LCT_WARNING, "Trying to release a scanner more times that the ones we are using it.\n");
		scanner->refcount = 0;
	}
	scanners_unlock();
}

/*!
 * \internal
 * \brief Thread implementation to run a scan to a port.
 */
static void *scanner_thread(void *data)
{
	enum lct_port_status status;
	struct scanner_thread_params *params = (struct scanner_thread_params *)data;
	struct lct_scanner *scanner = params->scanner;

	status = scanner->scan(params->hostname, params->port);
	lct_port_status(params->hostname, NULL, NULL, params->port, scanner->protocol, status);

	free(params->hostname);
	free(params);

	lct_thread_exit(THREAD_SCANNER, NULL);
	return NULL;
}

/*!
 * \internal
 * \brief Run the scanner in this thread instead of blocking a call to the scanner.
 */
static void *loop_scanner_thread(void *data)
{
	struct loop_scanner_thread_params *p = (struct loop_scanner_thread_params *)data;
	struct scanner_thread_params *params;
	int port;
	pthread_t scan_thread;

	for (port = p->port_init; port <= p->port_end; port++) {
		/* Setup the parameter to be passed to the scanner driver. */
		params = malloc(sizeof(*params));
		if (!params) {
			continue;
		}
		params->scanner = p->scanner;
		params->hostname = strdup(p->hostname);
		params->port = port;
		/* If this is the last port to scan, create the thread as joinable to
 		call thread_join for this thread. */
		if (port == p->port_end) {
			lct_thread(THREAD_SCANNER, &scan_thread, scanner_thread, params);
		} else { 
			lct_thread_detached(THREAD_SCANNER, &scan_thread, scanner_thread, params);
		}
	}
	lct_thread_join(scan_thread, NULL);
	scanner_release(p->scanner);
	free(p->hostname);
	free(p);

	lct_thread_exit(THREAD_USER, NULL);
	return NULL;
}

int lct_scan_host(const char *name, const char *hostname, int port_init, int port_end, int use_threads)
{
	struct lct_scanner *scanner;
	struct loop_scanner_thread_params *loop_params;
	struct scanner_thread_params *params;
	int port;
	pthread_t loop_scan_thread;
	pthread_t scan_thread;

	scanner = scanner_use(name);
	if (!scanner) {
		lct_log(LCT_ERROR, "No scanner found with the name '%s'\n", name);
		return -1;
	}

	if (use_threads) {
		/* use threads (it is up to the scanner to release the "scanner". */
		loop_params = malloc(sizeof(*loop_params));
		if (!loop_params) {
			return -1;
		}
		/* Prepare the parameter to be passed to the loop thread. */
		loop_params->scanner = scanner;
		loop_params->hostname = strdup(hostname);
		loop_params->port_init = port_init;
		loop_params->port_end = port_end;
		lct_thread_detached(THREAD_USER, &loop_scan_thread, loop_scanner_thread, loop_params);
	} else {
		/* do not use threads. */
		for (port = port_init; port <= port_end; port++) {
			params = malloc(sizeof(*params));
			if (!params) {
				continue;
			}
			params->scanner = scanner;
			params->hostname = strdup(hostname);
			params->port = port;
			if (port == port_end) {
				lct_thread(THREAD_SCANNER, &scan_thread, scanner_thread, params);
			} else {
				lct_thread_detached(THREAD_SCANNER, &scan_thread, scanner_thread, params);
			}
		}
		lct_thread_join(scan_thread, NULL);
		/* Release this scanner */
		scanner_release(scanner);
	}

	return 0;
}

int lct_scanners_initialize(void)
{
	list_init(&scanners);
	list_attributes_copy(&scanners, list_scanners_meter, 0);
	list_attributes_seeker(&scanners, list_scanners_seeker);

	lct_mutex_init(&scanners_list_lock, NULL);

	return 0;
}

