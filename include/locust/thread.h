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
 * \brief Locust Thread Definitions.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_THREAD_H
#define LOCUST_THREAD_H

#include <pthread.h>

/*! Threads limits */
#define LCT_THREADS_LEVELS 3 

enum lct_thread_level {
	THREAD_CORE = 0,
	THREAD_SCANNER = 1,
	THREAD_USER = 2
};

/* uncomment this to debug locks. */
/* #define DEBUG_MUTEX_LOCK 1 */

/*!
 * \brief Decrease threads usage value.
 */
void lct_thread_decrease(enum lct_thread_level level);

/*!
 * \brief Increase threads usage value.
 */
void lct_thread_increase(enum lct_thread_level level);

/*!
 * \brief Create a detached thread.
 */
int __lct_thread_detached(const char *file, int line, const char *fun, enum lct_thread_level level, pthread_t *thread, void *(*start_routine)(void *), void *arg);

/*
 * \brief Create a joinable thread.
 */
int __lct_thread(const char *file, int line, const char *fun, enum lct_thread_level level, pthread_t *thread, void *(*start_routine)(void *), void *arg);

/*!
 * \brief Create a detached thread simplifying parameter passing.
 */
#define lct_thread_detached(__level, __thread, __func, __args) __lct_thread_detached(__FILE__, __LINE__, __PRETTY_FUNCTION__, __level, __thread, __func, __args)

/*!
 * \brief Create a joinable thread simplifying parameter passing.
 */
#define lct_thread(__level, __thread, __func, __args) __lct_thread(__FILE__, __LINE__, __PRETTY_FUNCTION__, __level, __thread, __func, __args)

/*!
 * \brief Exit a created thread.
 */
#define lct_thread_exit(__level, __resval) do { \
	lct_thread_decrease(__level);		\
	pthread_exit(__resval);			\
} while(0);

/*!
 * \brief Wait until the thread finish.
 */
#define lct_thread_join(__thread, __res) pthread_join(__thread, __res) 


/* Locking functions */

/*! \brief The locking function */
struct lct_lock {
	pthread_mutex_t lock;
#ifdef DEBUG_MUTEX_LOCK
	const char *name;
	/* who has the lock. */
	const char *file;
	int line;
	const char *func;
#endif
};

/*!
 * \brief Lock a mutex.
 */
#ifdef DEBUG_MUTEX_LOCK
int __lct_mutex_lock(const char *file, int line, const char *func, struct lct_lock *mutex);
#define lct_mutex_lock(__mutex) __lct_mutex_lock(__FILE__, __LINE__, __PRETTY_FUNCTION__, __mutex)
#else
int __lct_mutex_lock(struct lct_lock *mutex);
#define lct_mutex_lock(__mutex) __lct_mutex_lock(__mutex)
#endif

/*!
 * \brief Unlock a mutex.
 */
#ifdef DEBUG_MUTEX_LOCK
int __lct_mutex_unlock(const char *file, int line, const char *func, struct lct_lock *mutex);
#define lct_mutex_unlock(__mutex) __lct_mutex_unlock(__FILE__, __LINE__, __PRETTY_FUNCTION__, __mutex)
#else
int __lct_mutex_unlock(struct lct_lock *mutex);
#define lct_mutex_unlock(__mutex) __lct_mutex_unlock(__mutex)
#endif

/*!
 * \brief Initialize a mutex.
 */
#ifdef DEBUG_MUTEX_LOCK
int __lct_mutex_init(const char *file, int line, const char *func, struct lct_lock *mutex, const pthread_mutexattr_t *attr);
#define lct_mutex_init(__mutex, __attr) __lct_mutex_init(__FILE__, __LINE__, __PRETTY_FUNCTION__, __name, __mutex, __attr)
#else
int __lct_mutex_init(struct lct_lock *mutex, const pthread_mutexattr_t *attr);
#define lct_mutex_init(__mutex, __attr) __lct_mutex_init(__mutex, __attr)
#endif

/*!
 * \brief Destroy a mutex.
 */
#ifdef DEBUG_MUTEX_LOCK
int __lct_mutex_destroy(const char *file, int line, const char *func, struct lct_lock *mutex);
#define lct_mutex_destroy(__mutex) __lct_mutex_destroy(__FILE__, __LINE__, __PRETTY_FUNCTION__, __mutex)
#else
int __lct_mutex_destroy(struct lct_lock *mutex);
#define lct_mutex_destroy(__mutex) __lct_mutex_destroy(__mutex)
#endif

#endif /* LOCUST_THREAD_H */
