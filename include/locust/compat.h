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
 * \brief Definitions for compatibility.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_COMPAT_H
#define LOCUST_COMPAT_H

#include "locust/autoconfig.h"

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef lct_strdupa 
#define lct_strdupa(ptr)						\
	(__extension__							\
		({							\
			const char *__src = (ptr);			\
			size_t __len = strlen(__src) + 1;		\
			char *__dst = alloca(__len);			\
			memcpy (__dst, __src, __len);			\
			__dst;						\
		}))
#endif

/* glob compat stuff */
#if defined(__Darwin__)
#define GLOB_ABORTED GLOB_ABEND
#endif
#include <glob.h>
#ifdef SOLARIS
#define MY_GLOB_FLAGS   GLOB_NOCHECK
#else
#define MY_GLOB_FLAGS   (GLOB_NOMAGIC|GLOB_BRACE)
#endif

/* for internal use of locust. */
#define ETHERNETPROTO	97	/* the same as etherip. */
#define PAYLOADPROTO	152	/* not assigned protocol number. */

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

#endif /* LOCUST_COMPAT_H */
