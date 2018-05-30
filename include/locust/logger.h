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
 * \brief The Locust logging subsystem definitions.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_LOGGER_H
#define LOCUST_LOGGER_H

/*! Something was wrong and we couldn't execute the order. */
#define LCT_ERROR	0
/*! Something was wrong but we were able to execute the order. */
#define LCT_WARNING	10
/*! Just print information about what we are doing. */
#define LCT_INFO	20
/*! Debugging information for developers. */
#define LCT_DEBUG	30

#define lct_log(level, fmt, ...) __lct_log(__FILE__, __LINE__, __PRETTY_FUNCTION__, level, fmt, ##__VA_ARGS__)

/*!
 * \brief Output a message for logging.
 * \note You should use lct_log instead of this function.
 * \see lct_log
 */
void __attribute__((format(printf, 5, 6))) __lct_log(const char *file, int line, const char *fun, int level, char *fmt, ...);

/*!
 * \brief Register a logger backend.
 * \param name The name of the logger backend (for future references to this backend).
 * \param func The implementation of the logger backend.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_logger_register(const char *name, void (*func)(const char *file, int line, const char *fun, int level, char *fmt, va_list ap));

/*!
 * \brief Unregister a logger backend.
 * \param name The name of the logger backend to unregister.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_logger_unregister(const char *name);

/*!
 * \brief Get the logger level name from the number.
 * \param level The log level.
 * \retval The name of the log level.
 */
const char *lct_logger_level2str(int level);

#endif
