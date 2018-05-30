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
 * \brief Definitions for the wordlist subsystem.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_WORDLIST_H
#define LOCUST_WORDLIST_H

/*! \brief A driver wordlist ptr (for internal use of the driver). */
struct lct_wordlist_ptr {
	/*! internal driver pointer. */
	void *internal;
	/*! The driver owning this ptr. */
	struct lct_wordlist *driver;
};

/*! \brief A wordlist driver. */
struct lct_wordlist {
	/*! the wordlist driver name. */
	char *name;
	/*! the driver initialization function. */
	void *(*init)(void *arg);
	/*! the driver get next word function */
	char *(*next)(void *ptr);
	/*! finish using the driver. */
	int (*finish)(void *ptr);
	/*! Reference counter. */
	int refcount;
};

/*!
 * \brief Register a wordlist driver.
 * \param driver The driver structure.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_wordlist_register(struct lct_wordlist *driver);

/*!
 * \brief Unregister an already registered channel driver.
 * \param name The channel driver name.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_wordlist_unregister(const char *name);

/*!
 * \brief Initialize the wordlist driver.
 * \see lct_wordlist_init, lct_wordlist_finish
 * \param name The name of the driver to initialize.
 * \param arg The argument to this driver (depends on the driver).
 * \retval NULL on error.
 * \retval The pointer to get words.
 */
struct lct_wordlist_ptr *lct_wordlist_start(const char *name, void *arg);

/*!
 * \brief Get the next word from the driver.
 * \see lct_wordlist_init, lct_wordlist_finish
 * \param ptr The wordlist pointer.
 * \retval NULL if no more words in the list.
 * \retval The next word in the list.
 */
char *lct_wordlist_next(struct lct_wordlist_ptr *ptr);

/*!
 * \brief Finisg the initiated wordlist driver.
 * \see lct_wordlist_init, lct_wordlist_next
 * \param ptr The wordlist manipulation pointer.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_wordlist_stop(struct lct_wordlist_ptr *ptr);

#endif /* LOCUST_WORDLIST_H */
