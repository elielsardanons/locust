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
 * \brief The locust wordlist subsystem.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>
#include <locust/cli.h>
#include <locust/wordlist.h>

/*! \brief All the registered wordlists. */
static list_t wordlists;

/*! \brief The registered wordlists locking mechanism. */
static struct lct_lock wordlists_lock;

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_wordlists_meter(const void *notused)
{
	return sizeof(struct lct_wordlist *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_wordlists_comparator(const void *a, const void *b)
{
	struct lct_wordlist *w1 = (struct lct_wordlist *)a;
	struct lct_wordlist *w2 = (struct lct_wordlist *)b;

	return strcmp(w1->name, w2->name);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_wordlists_seeker(const void *a, const void *key)
{
	struct lct_wordlist *w = (struct lct_wordlist *)a;
	const char *name = (const char *)key;

	return !strcmp(w->name, name);
}

int lct_wordlist_register(struct lct_wordlist *driver)
{
	struct lct_wordlist *w;

	if (!driver) {
		lct_log(LCT_ERROR, "Trying to register a null wordlist driver\n");
		return -1;
	}

	lct_mutex_lock(&wordlists_lock);
	w = list_seek(&wordlists, driver->name);
	if (w) {
		lct_log(LCT_WARNING, "Wordlist driver '%s' already registered\n", driver->name);
		lct_mutex_unlock(&wordlists_lock);
		return -1;
	}

	list_append(&wordlists, driver);
	lct_mutex_unlock(&wordlists_lock);

	return 0;
}

int lct_wordlist_unregister(const char *name)
{
	struct lct_wordlist *w;
	int pos;

	if (!name) {
		lct_log(LCT_ERROR, "Unable to unregister null wordlist driver\n");
		return -1;
	}

	lct_mutex_lock(&wordlists_lock);
	w = list_seek(&wordlists, name);
	if (!w) {
		lct_log(LCT_ERROR, "Wordlist driver '%s' not registered, we are unable to unregister it\n", name);
		lct_mutex_unlock(&wordlists_lock);
		return 0;
	}
	if (w->refcount > 0) {
		lct_log(LCT_ERROR, "Wordlist driver '%s' is in use\n", name);
		lct_mutex_unlock(&wordlists_lock);
		return -1;
	}
	pos = list_locate(&wordlists, w);
	if (pos < 0) {
		lct_log(LCT_ERROR, "Wordlist internal error, unable to locate the wordlist\n");
		lct_mutex_unlock(&wordlists_lock);
		return -1;
	}
	w = list_extract_at(&wordlists, pos);
	lct_mutex_unlock(&wordlists_lock);

	return 0;
}

struct lct_wordlist_ptr *lct_wordlist_start(const char *name, void *arg)
{
	struct lct_wordlist_ptr *res;
	struct lct_wordlist *driver;

	lct_mutex_lock(&wordlists_lock);
	driver = list_seek(&wordlists, name);
	if (!driver) {
		lct_log(LCT_WARNING, "Wordlist '%s' not registered\n", name);
		lct_mutex_unlock(&wordlists_lock);
		return NULL;
	}

	res = calloc(1, sizeof(*res));
	if (!res) {
		lct_log(LCT_ERROR, "Unable to allocate the memory for the wordlist structure\n");
		lct_mutex_unlock(&wordlists_lock);
		return NULL;
	}

	driver->refcount++;
	res->internal = driver->init(arg);
	res->driver = driver;
	lct_mutex_unlock(&wordlists_lock);

	if (!res->internal) {
		free(res);
		return NULL;
	}

	return res;
}

char *lct_wordlist_next(struct lct_wordlist_ptr *ptr)
{
	struct lct_wordlist *w;
	char *res;

	if (!ptr) {
		lct_log(LCT_WARNING, "Trying to use a null wordlist ptr\n");
		return NULL;
	}

	w = ptr->driver;
	res = w->next(ptr->internal);

	return res;
}

int lct_wordlist_stop(struct lct_wordlist_ptr *ptr)
{
	struct lct_wordlist *w;
	int res;

	if (!ptr) {
		lct_log(LCT_WARNING, "Trying to use a null wordlist ptr\n");
		return -1;
	}

	lct_mutex_lock(&wordlists_lock);
	w = ptr->driver;
	res = w->finish(ptr->internal);
	w->refcount--;
	lct_mutex_unlock(&wordlists_lock);

	/* free the wordlist_ptr allocated memory. */
	free(ptr);

	return res;
}

/*! \brief Handle CLI command 'wordlist show'. */
static enum lct_cli_result handle_command_wordlist_show(struct lct_cliargs *args)
{
#define WORDLIST_SHOW_FORMAT_TITLE "%-20s\n"
#define WORDLIST_SHOW_FORMAT "%-20s\n"
	struct lct_wordlist *wl;
	int count = 0;

	lct_mutex_lock(&wordlists_lock);
	list_iterator_start(&wordlists);
	lct_cli_output(WORDLIST_SHOW_FORMAT_TITLE, "Name");
	while (list_iterator_hasnext(&wordlists)) {
		wl = list_iterator_next(&wordlists);
		lct_cli_output(WORDLIST_SHOW_FORMAT, wl->name);
		count++;
	}
	list_iterator_stop(&wordlists);
	lct_mutex_unlock(&wordlists_lock);
	lct_cli_output("%d wordlist%s registered\n", count, (count == 1 ? "" : "s"));

	return CLI_SUCCESS;
#undef WORDLIST_SHOW_FORMAT_TITLE
#undef WORDLIST_SHOW_FORMAT
}

int lct_wordlist_finish(void)
{
	int ret;

	ret = lct_cli_command_unregister("wordlist show");
	list_destroy(&wordlists);
	lct_mutex_destroy(&wordlists_lock);

	return 0;
}

int lct_wordlist_initialize(void)
{
	lct_mutex_init(&wordlists_lock, NULL);

	list_init(&wordlists);
	list_attributes_copy(&wordlists, list_wordlists_meter, 0);
	list_attributes_comparator(&wordlists, list_wordlists_comparator);
	list_attributes_seeker(&wordlists, list_wordlists_seeker);

	lct_cli_command_register("wordlist show", "Show the loaded wordlist drivers", "wordlist show", handle_command_wordlist_show, NULL);

	return 0;
}
