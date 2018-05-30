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
 * \brief Core private functions must only be run in the locust core.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_PRIVATE_H
#define LOCUST_PRIVATE_H

/*!
 * \brief Provided by main/cli.c to initialize builtin CLI commands.
 * \retval -1 On error.
 * \retval 0 on success.
 */
int lct_cli_register_builtin_commands(void);

/*!
 * \brief Provided by main/host.c to initialize builtin CLI commands.
 * \retval -1 on error.
 * \retval 0 on success.
 */
int lct_host_register_builtin_commands(void);

/*!
 * \brief Provided by main/ethernet.c to initialize builtin Ethernet helpers.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_ethernet_register_builtin_commands(void);

/*!
 * \brief Provided by main/ip.c to initialize builtin IP helpers.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_ip_register_builtin_commands(void);

/*!
 * \brief Provided by main/icmp.c to initialize builtin ICMP helpers.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_icmp_register_builtin_commands(void);

/*!
 * \brief Provided by main/tcp.c to initialize builtin TCP helpers.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_tcp_register_builtin_commands(void);

/*!
 * \brief Provided by main/udp.c to initialize builtin UDP helpers.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_udp_register_builtin_commands(void);

/*!
 * \brief Provided by main/paylaod.c to initialize builtin Payload helpers.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_payload_register_builtin_commands(void);

/*!
 * \brief Locust console thread (provided by main/cli.c).
 */
void *lct_cli_console(void *arg);

/*!
 * \brief Initialize the logger subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_logger_initialize(void);

/*!
 * \brief Initialize the host subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_host_initialize(void);

/*!
 * \brief Initialize the console subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_cli_initialize(void);

/*!
 * \brief Initialize the routing subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_route_initialize(void);

/*!
 * \brief Initialize the scanner subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_scanners_initialize(void);

/*!
 * \brief Initialize the loader subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_loader_initialize(void);

/*!
 * \brief Initialize the thread subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_thread_initialize(void);

/*!
 * \brief Initialize the configuration subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_config_initialize(void);

/*!
 * \brief Initialize the wordlist subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_wordlist_initialize(void);

/*!
 * \brief Initialize the packet subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_packet_initialize(void);

/*!
 * \brief Initialize the sniffer subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_sniffer_initialize(void);

/*!
 * \brief Close the packet subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_packet_finish(void);

/*!
 * \brief Close the wordlist subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_wordlist_finish(void);

/*!
 * \brief Closes the sniffer subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_sniffer_finish(void);

/*!
 * \brief Closes the cli subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_cli_finish(void);

/*!
 * \brief Closes the routing subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_route_finish(void);

/*!
 * \brief Closes the host subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_host_finish(void);

/*!
 * \brief Unload every loaded module.
 * \retval < 0 on error.
 * \retval 0 on succes.
 */
int lct_loader_finish(void);

/*!
 * \brief Close the tcp subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_tcp_finish(void);

/*!
 * \brief Close the udp subsystem.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_udp_finish(void);

#endif /* LOCUST_PRIVATE_H */
