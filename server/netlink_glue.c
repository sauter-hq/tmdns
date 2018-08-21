/*
 *  Copyright 2004 Patrick McHardy, <kaber@coreworks.de>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

#include "config.h"

#ifdef WITH_NETLINK

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>

#include <linux/if.h>

/* can't include both, linux/if.h and net/if.h :-( */
extern char *if_indextoname (unsigned int ifidx, char * ifname);


#include <sys/ioctl.h>

#include "netlink_glue.h"
#include "libnetlink.h"
#include "debug.h"

static struct rtnl_handle rth;
static time_t network_change_time = 0;

enum link_state_changes
{
	LINK_STATE_AVAIL,
	LINK_STATE_UP,
	LINK_STATE_DOWN,
	LINK_STATE_GONE
};

static char *link_state_names[] =
{
	[LINK_STATE_AVAIL]	= "avail",
	[LINK_STATE_UP]		= "up",
	[LINK_STATE_DOWN]	= "down",
	[LINK_STATE_GONE]	= "gone",
};


/*
 * Apparently link up/down messages are sent twice,
 * catch the second one.
 */
static int duplicate_link_msg(char *ifname, int state)
{
	static char last_ifname[IFNAMSIZ];
	static unsigned int last_state;

	if (state != LINK_STATE_UP && state != LINK_STATE_DOWN)
		return 0;
	if (last_ifname[0] != '\0')
		goto save;
	if (strncmp(ifname, last_ifname, IFNAMSIZ))
		goto save;
	if (last_state == state)
		return 1;
save:
	strncpy(last_ifname, ifname, IFNAMSIZ);
	last_state  = state;
	return 0;
}

/*
 * Handle link state changed events from netlink
 *
 * Returns:
 *   always < 0 to make libnetlink terminate ist loop
 */
static int accept_link_msg(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct rtattr *tb[IFLA_MAX+1];
	int len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	char *ifname;
	int state = -1;

	if (len < 0)
		return -1;
	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	ifname = RTA_DATA(tb[IFLA_IFNAME]);
	
	switch (n->nlmsg_type) {
	case RTM_NEWLINK:
		if (ifi->ifi_change == ~0U)
			state = LINK_STATE_AVAIL;
		else if (ifi->ifi_change == (IFF_UP|IFF_RUNNING)) {
			if (ifi->ifi_flags & IFF_UP)
				state = LINK_STATE_UP;
			else
				state = LINK_STATE_DOWN;
		}
		break;
	case RTM_DELLINK:
		if (ifi->ifi_change == ~0U)
			state = LINK_STATE_GONE;
		break;
	}

	if (state != -1 && !duplicate_link_msg(ifname, state)) {
		debug("state change on interface %s -> status is %s now\n" , 
			ifname , link_state_names[state] );
		network_change_time = time(NULL);
	}

	return -1;
}

/*
 * Check if an interface is up.
 *    could do this with netlink, but ...
 *
 * Argument:
 *   ifidx  - interface index.
 *
 * Returns:
 *     1 - if is up,
 *     0 - if is down,
 *   < 0 - error
 */
static int is_if_up(int ifidx) {

	struct ifreq ifr;
	int sock = -1;
	int result = -1;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		                return (-1);

	memset( &ifr, 0 , sizeof(ifr) );

	if_indextoname( ifidx , ifr.ifr_name );

	if( (ioctl(sock, SIOCGIFFLAGS, &ifr ) == 0 )) {
		result = (ifr.ifr_flags & IFF_UP)?1:0;
	}
	
	close(sock);
	return result;
}

/*
 * Handle address change events from netlink
 *
 * Returns:
 *   always < 0 to make libnetlink terminate ist loop
 */
static int accept_addr_msg(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct ifaddrmsg *ifa = NLMSG_DATA(n);
	struct rtattr *tb[IFLA_MAX+1];
	int len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
	int is_up = -1;

	if (len < 0)
		return -1;
	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);

	debug("Address change on interface \n" );
	/*
	debug("Address change on interface %s\n" ,
			if_indextoname( ifa->ifa_index , NULL ) );
	*/
	if( !((ifa->ifa_family == AF_INET) || (ifa->ifa_family == AF_INET6)) )  {
		debug("Not IPv4 nor IPv6 address\n");
		return -1;
	}

	if( ( is_up = is_if_up(ifa->ifa_index) ) <= 0 ) {
		debug("Interface is down (?)\n");
		return -1;
	}

	network_change_time = time(NULL);

	/* was nice to print address here */
	return -1;

}

/*
 * Will be called from rtnl_listen when a interesting message have been 
 * received.
 *
 * We use it just to separate *ADDR and *LINK messages.
 */ 
static int accept_msg(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	if (n->nlmsg_type == RTM_NEWLINK || n->nlmsg_type == RTM_DELLINK)
		return accept_link_msg(who, n, arg);

	if (n->nlmsg_type == RTM_NEWADDR || n->nlmsg_type == RTM_DELADDR)
		return accept_addr_msg(who, n, arg);

	return -1;
}

/*
 * Initialize netlink related stuff. 
 *
 * Returns netlink sockets fd or < 0 on error.
 */
int init_netlink_glue() {
	if (rtnl_open(&rth, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR ) < 0) {
		return -1;
	}

	return rth.fd;
}

void stop_netlink_glue() {
	rtnl_close(&rth);
}

/*
 * To be called from the select loop to handle netlink messages.
 *
 * Returns: <0 on error.
 */
int handle_netlink_msg() {
	if( rth.fd < 0 ) {
		return -1;
	}

	if (rtnl_listen(&rth, accept_msg, NULL) < 0) {
	}

	return 0;
}

int network_changed() {
	if( network_change_time == 0 ) {
		return 0;
	}

	if( network_change_time + NOTIFY_DELAY > time(NULL) ) {
		return 0;
	}

	network_change_time = 0;
	return 1;
}


#endif /* WITH_NETLINK */

