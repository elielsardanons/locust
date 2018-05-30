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
 * \brief Locust routing API definitions 
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_ROUTE_H
#define LOCUST_ROUTE_H

/*!
 * \brief Get the source ip address based on the destination ip address.
 * \param hostname The target hostname.
 * \param src A buffer to store the source ip address.
 * \param src_len The lenght of the src buffer.
 * \param devname A buffer to store the found device name.
 * \param devname_len The lenght of the 'devname' buffer.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_route_get_source_info(const char *hostname, char *src, size_t src_len, char *devname, size_t devname_len);

/*!
 * \brief Helper function to autocomplete the list of netword devices.
 * \param word The word to autocomplete.
 * \param state The response number.
 * \retval The autocompleted word.
 * \retval NULL if nothing to autocomplete.
 */
char *lct_devices_autocomplete(const char *word, int state);

/*!
 * \brief Check if a network device name is valid.
 * \param name The network device name.
 * \retval 1 The device is valid.
 * \retval 0 The device is invalid.
 */
int lct_valid_network_device(const char *name);

#endif /* LOCUST_ROUTE_H */
