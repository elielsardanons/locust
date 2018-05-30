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
 * \brief Locust configuration subsystem.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/config.h>
#include <locust/logger.h>

#include "libconfig.h"

/*! \brief Locust main configuration file libconfig structure. */
static config_t main_locust_config;

const char *lct_config_str(const char *path)
{
	const char *ret;

	ret = config_lookup_string(&main_locust_config, path);
	return ret;
}

int lct_config_int(const char *path)
{
	int ret;

	ret = config_lookup_int(&main_locust_config, path);
	return ret;
}

int lct_config_load(const char *file)
{
	int ret;

	/* read the main locust configuration file. */
	ret = config_read_file(&main_locust_config, file);
	if (!ret) {
		lct_log(LCT_ERROR, "Error while reading config file %s (%s:%d)\n", file, config_error_text(&main_locust_config),
			config_error_line(&main_locust_config));
	}
	return ret;
}

int lct_config_initialize(void)
{
	/* initialize the libconfig structure. */
	config_init(&main_locust_config);
	return 0;
}

