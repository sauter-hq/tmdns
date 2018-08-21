/* $Id: getifaddrs.c,v 1.5 2004/02/06 19:46:00 andi Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  /* HAVE_CONFIG_H */

#ifndef HAVE_GETIFADDRS
/*	$OpenBSD: getifaddrs.c,v 1.3 2000/11/24 08:26:47 itojun Exp $	*/

/*
 * Copyright (c) 1995, 1999
 *	Berkeley Software Design, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED BY Berkeley Software Design, Inc. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Berkeley Software Design, Inc. BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	BSDI getifaddrs.c,v 2.12 2000/02/23 14:51:59 dab Exp
 */
/*
 * NOTE: SIOCGIFCONF case is not LP64 friendly.  it also does not perform
 * try-and-error for region size.
 */


#include <errno.h>
#include <memory.h>
#include <sys/ioctl.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <netinet/in.h>

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */

#ifdef HAVE_NETINET_IN6_VAR_H
#include <netinet/in6_var.h>
#endif /* HAVE_NETINET_IN6_VAR_H */

#ifdef	NET_RT_IFLIST
#include <sys/param.h>
#include <net/route.h>
#include <sys/sysctl.h>
#include <net/if_dl.h>
#endif

#include <errno.h>
#include "tm_ifaddrs.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*XXX IPv6*/
#if !HAVE_SOCKADDR_SA_LEN && !defined(SA_LEN)
#define	SA_LEN(sa)	sizeof(struct sockaddr)
#endif

#if !defined(SA_LEN)
#define	SA_LEN(sa)	(sa)->sa_len
#endif

#if HAVE_SOCKADDR_SA_LEN
#define	SALIGN	(sizeof(long) - 1)
#define	SA_RLEN(sa)	((sa)->sa_len ? (((sa)->sa_len + SALIGN) & ~SALIGN) : (SALIGN + 1))
#else
#define SA_RLEN(sa) (SA_LEN(sa)) /*XXX?*/
#endif /* HAVE_SOCKADDR_SA_LEN */

#ifndef	ALIGNBYTES
/*
 * On systems with a routing socket, ALIGNBYTES should match the value
 * that the kernel uses when building the messages.
 */
#define	ALIGNBYTES	XXX
#endif
#ifndef	ALIGN
#define	ALIGN(p)	(((u_long)(p) + ALIGNBYTES) &~ ALIGNBYTES)
#endif

int getifaddrs(struct ifaddrs **pif)
{
	int icnt = 1;
	int dcnt = 0;
	int ncnt = 0;
	char buf[8192];
	int sock;
	struct ifconf ifc;
	struct ifreq *ifr;
	struct ifreq *lifr;
	struct ifaddrs *ifa, *ift;
	int i;
	char *data;
	char *names;

	ifc.ifc_buf = buf;
	ifc.ifc_len = sizeof(buf);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return (-1);
	i = ioctl(sock, SIOCGIFCONF, (char *)&ifc);
	if (i == -1) {
		close(sock);
		return (-1);
	}

	ifr = ifc.ifc_req;
	lifr = (struct ifreq *)&ifc.ifc_buf[ifc.ifc_len];

	while (ifr < lifr) {
		struct sockaddr *sa;

		sa = &ifr->ifr_addr;
		++icnt;
		dcnt += SA_RLEN(sa);
		ncnt += sizeof(ifr->ifr_name) + 1;

		ifr = (struct ifreq *)(((char *)sa) + SA_LEN(sa));
	}

	if (icnt + dcnt + ncnt == 1) {
		*pif = NULL;
		close(sock);
		return (0);
	}
	data = malloc(sizeof(struct ifaddrs) * icnt + dcnt + ncnt);
	if (data == NULL) {
		close(sock);
		return(-1);
	}

	ifa = (struct ifaddrs *)data;
	data += sizeof(struct ifaddrs) * icnt;
	names = data + dcnt;

	memset(ifa, 0, sizeof(struct ifaddrs) * icnt);
	ift = ifa;

	ifr = ifc.ifc_req;
	lifr = (struct ifreq *)&ifc.ifc_buf[ifc.ifc_len];

	while (ifr < lifr) {
		struct sockaddr *sa;

		ift->ifa_name = names;
		names[sizeof(ifr->ifr_name)] = 0;
		strncpy(names, ifr->ifr_name, sizeof(ifr->ifr_name));
		while (*names++)
			;

		ift->ifa_addr = (struct sockaddr *)data;

		sa = &ifr->ifr_addr;
		memcpy(data, sa, SA_LEN(sa));
		data += SA_RLEN(sa);

		{
		    struct ifreq  freq;
		    memset (&freq, 0, sizeof(freq));
		    memcpy (freq.ifr_name, ifr->ifr_name, sizeof(ifa->ifa_name));
		    if( (ioctl(sock, SIOCGIFFLAGS, &freq) == 0 )) {
		        ift->ifa_flags = freq.ifr_flags;
		    }
		}

		ifr = (struct ifreq *)(((char *)sa) + SA_LEN(sa));
		ift = (ift->ifa_next = ift + 1);
	}

	if (--ift >= ifa) {
		ift->ifa_next = NULL;
		*pif = ifa;
	} else {
		*pif = NULL;
		free(ifa);
	}

	close(sock);
	return (0);
}
void
freeifaddrs(struct ifaddrs *ifp)
{
	free(ifp);
}

#endif  

