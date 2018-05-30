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
 * \brief Configuration subsystem definitions.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_CONFIG_H
#define LOCUST_CONFIG_H

#define LCT_MAIN_CONFIG_FILE "locust.conf"

#define LCT_CONFIG_MODULES_PATH			"locust.modules_path"
#define LCT_CONFIG_MAX_THREAD_CORE		"locust.max_core_threads"
#define LCT_CONFIG_MAX_THREAD_USER		"locust.max_user_threads"
#define LCT_CONFIG_MAX_THREAD_SCANNER		"locust.max_scanner_threads"
#define LCT_CONFIG_TCP_MAX_BIND_CONNECTIONS	"locust.tcp.max_bind_connections"
#define LCT_CONFIG_MAX_OPEN_FILES		"locust.max_files"

/*!
 * \brief Get a variable value (of type string) from the configuration file.
 * \param path The path to the value.
 * \retval NULL on error.
 * \retval The variable value.
 */
const char *lct_config_str(const char *path);

/*!
 * \brief Get a variable value (of type integer) from the configuration file.
 * \param path The path to the value.
 * \retval NULL on error.
 * \retval The variable value.
 */
int lct_config_int(const char *path);

/*!
 * \brief Load the main configuration file.
 * \param file Where the file 'locust.conf' is located.
 * \retval 0 on failure.
 * \retval 1 on success.
 */
int lct_config_load(const char *file);

#endif /* LOCUST_CONFIG_H */

