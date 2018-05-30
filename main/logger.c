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
 * \brief Logger functions implementation.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>

/*! \brief The structure definition of a logger. */
struct logger {
	char *name;
	void (*dolog)(const char *file, int line, const char *fun, int level, char *fmt, va_list ap);
};

/*! \brief The list of loggers registered. */
static list_t loggers;

/*! \brief The lock for the list of loggers.
 *  \see loggers
 */
static struct lct_lock loggers_list_lock;

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_loggers_meter(const void *notused)
{
	return sizeof(struct logger *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_loggers_seeker(const void *a, const void *key)
{
	struct logger *l = (struct logger *)a;
	const char *name = (const char *)key;

	return !strcmp(l->name, name);
}

/*! \brief Lock the loggers list. */
static void loggers_lock(void)
{
	lct_mutex_lock(&loggers_list_lock);
}

/*! \brief Unlock the loggers list. */
static void loggers_unlock(void)
{
	lct_mutex_unlock(&loggers_list_lock);
}

void __lct_log(const char *file, int line, const char *fun, int level, char *fmt, ...)
{
	struct logger *log;
	va_list ap;

	va_start(ap, fmt);

	loggers_lock();
	list_iterator_start(&loggers);
	/* log the message in every register engine. */
	while (list_iterator_hasnext(&loggers)) {
		log = list_iterator_next(&loggers);
		log->dolog(file, line, fun, level, fmt, ap);
	}
	list_iterator_stop(&loggers);
	loggers_unlock();

	va_end(ap);
}

/*!
 * \brief Free a 'logger' structure.
 * \param log Logger structure to destroy.
 */
static void free_logger(struct logger *log)
{
	free(log->name);
	free(log);
}

int lct_logger_register(const char *name, void (*func)(const char *file, int line, const char *fun, int level, char *fmt, va_list ap))
{
	struct logger *newlogger;

	/* allocate space for the new logger structure. */
	newlogger = calloc(1, sizeof(*newlogger));
	if (!newlogger) {
		return -1;
	}

	newlogger->name = strdup(name);
	newlogger->dolog = func;

	/* Insert the new logger inside the loggers list. */
	loggers_lock();
	list_append(&loggers, newlogger);
	loggers_unlock();

	return 0;
}

int lct_logger_unregister(const char *name)
{
	struct logger *log;
	int pos;

	loggers_lock();
	log = list_seek(&loggers, name);
	if (!log) {
		lct_log(LCT_WARNING, "Logger '%s' not registered\n", name);
		loggers_unlock();
		return 0;
	}
	pos = list_locate(&loggers, log);
	log = list_extract_at(&loggers, pos);
	free_logger(log);
	loggers_unlock();

	return 0;
}

const char *lct_logger_level2str(int level)
{
	const char *ret;

	switch (level) {
		case LCT_ERROR:
			ret = "ERROR";
			break;
		case LCT_WARNING:
			ret = "WARNING";
			break;
		case LCT_INFO:
			ret = "INFO";
			break;
		case LCT_DEBUG:
			ret = "DEBUG";
			break;
		default:
			ret = "UNKNOWN";
	}

	return ret;
}

int lct_logger_initialize(void)
{
	list_init(&loggers);
	list_attributes_copy(&loggers, list_loggers_meter, 0);
	list_attributes_seeker(&loggers, list_loggers_seeker);
	lct_mutex_init(&loggers_list_lock, NULL);

	return 0;
}
