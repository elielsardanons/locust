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
 * \brief General Locust definitions and includes.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_H
#define LOCUST_H

#include "locust/autoconfig.h"

#include "locust/netutils.h"

#include "locust/thread.h"

#include "locust/simclist.h"

#include <errno.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

/* va_list */
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/unistd.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef LOCUST_DEBUG
#define DEBUG_THREADS
#endif

#include <fcntl.h>

#include "locust/compat.h"

#ifdef HAVE_LIBPCAP
#include "pcap.h"
#endif

#include <pwd.h>
/*!
 * \brief Get the machines hostname.
 * \retval The hostname.
 */
char *lct_local_hostname(void);

/*!
 * \brief Is locust running as root?
 * \retval 1 We are running as root.
 * \retval 0 We are NOT running as root.
 */
int lct_running_as_root(void);

/*!
 * \brief Get the username as we are running.
 * \retval The username.
 */
char *lct_local_username(void);

#endif
