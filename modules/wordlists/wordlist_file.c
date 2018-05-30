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
 * \brief File wordlist implementation.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>
#include <locust/cli.h>
#include <locust/wordlist.h>

/*! The max lenght of a password inside the opened file. */
#define MAX_PASSWORD_LEN 60

/*! \brief All the requested files open. */
static list_t open_files;

/*! \brief Open files locking mechanism. */
static struct lct_lock open_files_lock;

/*! \brief The open file in memory. */
struct wordlistfile {
	/*! the wordlist filename */
	char *filename;
	/*! The file pointer. */
	FILE *ptr;
	/*! ref count. (how many are using this file). */
	int refcount;
	/*! locking mechanism for this open file */
	struct lct_lock lock;
};

/*! \brief All the "clients" using this driver. */
struct file_ptr {
	/*! A pointer to the internal wordlist driver pointer. */
	struct wordlistfile *file;
	/*! The position inside this file. */
	fpos_t pos;
};

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_open_files_meter(const void *notused)
{
	return sizeof(struct wordlistfile *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_open_files_comparator(const void *a, const void *b)
{
	struct wordlistfile *w1 = (struct wordlistfile *)a;
	struct wordlistfile *w2 = (struct wordlistfile *)b;

	return strcmp(w1->filename, w2->filename);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_open_files_seeker(const void *a, const void *key)
{
	struct wordlistfile *w = (struct wordlistfile *)a;
	const char *filename = (const char *)key;

	return !strcmp(w->filename, filename);
}

/*!
 * \internal
 * \brief Initialize this wordlist.
 * \param arg The wordlist filename. 
 * \retval The initial file_ptr structure to manager this wordlist.
 */
static void *file_init(void *arg)
{
	const char *filename = (const char *)arg;
	FILE *file;
	struct wordlistfile *wlf;
	struct file_ptr *fptr;

	if (!filename) {
		return NULL;
	}

	/* check if the file is already open. */
	lct_mutex_lock(&open_files_lock);
	wlf = list_seek(&open_files, filename);
	if (!wlf) {
		file = fopen(filename, "r");
		if (!file) {
			lct_mutex_unlock(&open_files_lock);
			return NULL;
		}
		wlf = calloc(1, sizeof(*wlf));
		if (!wlf) {
			fclose(file);
			lct_mutex_unlock(&open_files_lock);
			return NULL;
		}
		wlf->filename = strdup(filename);
		wlf->ptr = file;
		wlf->refcount = 1;
		lct_mutex_init(&wlf->lock, NULL);
		list_append(&open_files, wlf);
	} else {
		lct_mutex_lock(&wlf->lock);
		wlf->refcount++;
		lct_mutex_unlock(&wlf->lock);
	}
	lct_mutex_unlock(&open_files_lock);

	fptr = calloc(1, sizeof(*fptr));
	if (!fptr) {
		lct_mutex_lock(&wlf->lock);
		wlf->refcount--;
		lct_mutex_unlock(&wlf->lock);
		return NULL;
	}

	fptr->file = wlf;

	return fptr;
}

/*! \brief Get the next word from this wordlist. */
static char *file_next(void *ptr)
{
	struct file_ptr *fptr = (struct file_ptr *)ptr;
	struct wordlistfile *wlf;
	char *buff;

	if (!fptr) {
		return NULL;
	}

	lct_mutex_lock(&wlf->lock);
	wlf = fptr->file;
	fsetpos(wlf->ptr, &fptr->pos);
	buff = calloc(1, MAX_PASSWORD_LEN);
	if (!buff) {
		lct_mutex_unlock(&wlf->lock);
		return NULL;
	}
	if (!fgets(buff, MAX_PASSWORD_LEN, wlf->ptr)) {
		free(buff);
		lct_mutex_unlock(&wlf->lock);
		return NULL;
	}
	fgetpos(wlf->ptr, &fptr->pos);
	lct_mutex_unlock(&wlf->lock);

	return buff;
}

/*! \brief Finish using this wordlist. */
static int file_finish(void *ptr)
{
	struct file_ptr *fptr = (struct file_ptr *)ptr;
	struct wordlistfile *wlf;
	int pos;

	if (!fptr) {
		return -1;
	}

	lct_mutex_lock(&open_files_lock);
	wlf = fptr->file;
	lct_mutex_lock(&wlf->lock);
	wlf->refcount--;
	if (wlf->refcount == 0) {
		pos = list_locate(&open_files, wlf);
		wlf = list_extract_at(&open_files, pos);

		free(wlf->filename);
		if (wlf->ptr) {
			fclose(wlf->ptr);
		}
		lct_mutex_destroy(&wlf->lock);
		free(wlf);
		lct_mutex_unlock(&open_files_lock);
		return 0;
	}
	lct_mutex_unlock(&wlf->lock);
	lct_mutex_unlock(&open_files_lock);

	return 0;
}

static struct lct_wordlist wordlist_file = {
	.name = "file",
	.init = file_init,
	.next = file_next,
	.finish = file_finish
};

/*! Handle CLI command 'wordlist file' */
enum lct_cli_result handle_command_wordlist_file(struct lct_cliargs *args)
{
#define WORDLIST_FILE_TITLE_FORMAT "%-30s %-4s\n"
#define WORDLIST_FILE_FORMAT "%-30s %-4d\n"
	struct wordlistfile *wlf;
	int count = 0;
	
	lct_mutex_lock(&open_files_lock);
	list_iterator_start(&open_files);
	lct_cli_output(WORDLIST_FILE_TITLE_FORMAT, "Filename", "Usage");
	while (list_iterator_hasnext(&open_files)) {
		wlf = list_iterator_next(&open_files);
		lct_cli_output(WORDLIST_FILE_FORMAT, wlf->filename, wlf->refcount);
		count++;
	}
	list_iterator_stop(&open_files);
	lct_mutex_unlock(&open_files_lock);
	lct_cli_output("%d open file%s\n", count, (count == 1 ? "" : "s"));

	return CLI_SUCCESS;
#undef WORDLIST_FILE_TITLE_FORMAT
#undef WORDLIST_FILE_FORMAR
}

int module_load(void)
{
	/* initialize the open_files list */
	list_init(&open_files);
	list_attributes_copy(&open_files, list_open_files_meter, 0);
	list_attributes_comparator(&open_files, list_open_files_comparator);
	list_attributes_seeker(&open_files, list_open_files_seeker);

	lct_mutex_init(&open_files_lock, NULL);
	/* register this wordlist. */
	lct_wordlist_register(&wordlist_file);

	/* register cli command. */
	lct_cli_command_register("wordlist file", "Show the wordlist open files", "wordlist file", handle_command_wordlist_file, NULL); 
	return 0;
}

int module_unload(void)
{
	lct_cli_command_unregister("wordlist file");
	/* unregister the wordlist. */
	lct_wordlist_unregister("file");
	/* destroy the lock. */
	lct_mutex_destroy(&open_files_lock);
	/* destroy the open_files list. */
	list_destroy(&open_files);

	return 0;
}

