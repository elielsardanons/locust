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
 * \brief Manage threads and syncronization inside locust.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>
#include <locust/config.h>
#include <locust/cli.h>

/*!
 * \internal
 * \brief Maximum number of threads that locust is allow to run.
 */
static int max_running_threads[LCT_THREADS_LEVELS];

/*!
 * \internal
 * \brief The number of actual running threads.
 */
static int running_threads[LCT_THREADS_LEVELS];

/*!
 * \internal
 * \brief Locking mechanism for the access to running_threads.
 * \see running_threads
 */
static struct lct_lock running_threads_lck;

void lct_thread_increase(enum lct_thread_level level)
{
	lct_mutex_lock(&running_threads_lck);
	/* wait until the other threads finish running. */
	while (running_threads[level] >= max_running_threads[level]) {
		lct_mutex_unlock(&running_threads_lck);
		/* delay execution of this thread for 500 milliseconds. */
		usleep(1000 * 500);
		lct_mutex_lock(&running_threads_lck);
	}
	running_threads[level]++;
	lct_mutex_unlock(&running_threads_lck);
}

void lct_thread_decrease(enum lct_thread_level level)
{
	lct_mutex_lock(&running_threads_lck);
	running_threads[level]--;
	lct_mutex_unlock(&running_threads_lck);
}

#ifdef DEBUG_MUTEX_LOCK
int __lct_mutex_lock(const char *file, int line, const char *func, struct lct_lock *mutex)
#else
int __lct_mutex_lock(struct lct_lock *mutex)
#endif
{
	int ret = 0;
#ifdef DEBUG_MUTEX_LOCK
	int count = 0;
#endif

#ifdef DEBUG_MUTEX_LOCK
	lct_log(LCT_DEBUG, "Locking from (%s,%d,%s)\n", file, line, func);
	while (pthread_mutex_trylock(&mutex->lock)) {
		usleep(2);
		count++;
		if (count > 300) {
			lct_log(LCT_DEBUG, "Avoiding deadlock in lock (%s,%d,%s)\n", file, line, func);
			lct_log(LCT_DEBUG, "Who has the lock: (%s,%d,%s)\n", mutex->file, mutex->line, mutex->func);
			count = 0;
		}
	}
	mutex->file = file;
	mutex->line = line;
	mutex->func = func;
#else
	pthread_mutex_lock(&mutex->lock);
#endif
	return ret;
}

#ifdef DEBUG_MUTEX_LOCK
int __lct_mutex_unlock(const char *file, int line, const char *func, struct lct_lock *mutex)
#else
int __lct_mutex_unlock(struct lct_lock *mutex)
#endif
{
	int ret;
#ifdef DEBUG_MUTEX_LOCK
	lct_log(LCT_DEBUG, "Unlocking %s from (%s,%d,%s)\n", file, line, func);
#endif
	ret = pthread_mutex_unlock(&mutex->lock);

	return ret;
}

#ifdef DEBUG_MUTEX_LOCK
int __lct_mutex_init(const char *file, int line, const char *func, struct lct_lock *mutex, const pthread_mutexattr_t *attr)
#else
int __lct_mutex_init(struct lct_lock *mutex, const pthread_mutexattr_t *attr)
#endif
{
	int ret;
#ifdef DEBUG_MUTEX_LOCK
	lct_log(LCT_DEBUG, "Initializing mutex from (%s,%d,%s)\n", file, line, func);
	mutex->name = name;
#endif
	ret = pthread_mutex_init(&mutex->lock, attr);

	return ret;
}

#ifdef DEBUG_MUTEX_LOCK
int __lct_mutex_destroy(const char *file, int line, const char *func, struct lct_lock *mutex)
#else
int __lct_mutex_destroy(struct lct_lock *mutex)
#endif
{
	int ret;
#ifdef DEBUG_MUTEX_LOCK
	lct_log(LCT_DEBUG, "Destroying mutex from (%s,%d,%s)\n", file, line, func);
	mutex->name = name;
#endif
	ret = pthread_mutex_destroy(&mutex->lock);

	return ret;
}

int __lct_thread_detached(const char *file, int line, const char *fun, enum lct_thread_level level, pthread_t *thread, void *(*start_routine)(void *), void *arg)
{
	int retval;
	pthread_attr_t attr;

	lct_thread_increase(level);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	retval = pthread_create(thread, &attr, start_routine, arg);
	pthread_attr_destroy(&attr);
#ifdef DEBUG_THREADS
	if (retval < 0) {
		lct_thread_decrease(level);
		lct_log(LCT_ERROR, "Error running thread_detached on (%s,%d,%s)\n", file, line, fun);
	}
#endif
	return retval;
}

int __lct_thread(const char *file, int line, const char *fun, enum lct_thread_level level, pthread_t *thread, void *(*start_routine)(void *), void *arg)
{
	int retval;

	lct_thread_increase(level);

	retval = pthread_create(thread, NULL, start_routine, arg);
#ifdef DEBUG_THREADS
	if (retval < 0) {
		lct_log(LCT_ERROR, "Error running thread on (%s,%d,%s)\n", file, line, fun);
	}
#endif
	return retval;
}

#ifdef DEBUG_THREADS
static enum lct_cli_result handle_command_threads_count(struct lct_cliargs *args)
{
	int i;
	for (i = 0; i < LCT_THREADS_LEVELS; i++) {
		lct_cli_output("Threads running in level %d: %d (max = %d)\n", i, running_threads[i], max_running_threads[i]);
	}

	return CLI_SUCCESS;
}
#endif

int lct_thread_initialize(void)
{
	int ret = 0;
	int value;

	/* setup default values. */
	max_running_threads[THREAD_CORE] = 50;
	max_running_threads[THREAD_SCANNER] = 200;
	max_running_threads[THREAD_USER] = 50;

	/* Get values from the main locust configuration file. */
	if ((value = lct_config_int(LCT_CONFIG_MAX_THREAD_CORE))) {
		max_running_threads[THREAD_CORE] = value;
	}
	if ((value = lct_config_int(LCT_CONFIG_MAX_THREAD_SCANNER))) {
		max_running_threads[THREAD_SCANNER] = value;
	}
	if ((value = lct_config_int(LCT_CONFIG_MAX_THREAD_USER))) {
		max_running_threads[THREAD_USER] = value;
	}

	memset(&running_threads, 0, sizeof(running_threads));

	lct_mutex_init(&running_threads_lck, NULL);
#ifdef DEBUG_THREADS
	ret = lct_cli_command_register("threads count", "Show the number of running threads",
			"threads count", handle_command_threads_count, NULL);
#endif

	return ret;
}

