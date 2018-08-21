/*
 * serv_udp.c
 *
 * Functions to send/recieve mDNS UDP packets.
 *
 * Part of the tmdns package by Andreas Hofmeister. 
 *
 * Copyright 1999 Matthew Pratt <mattpratt@yahoo.com>
 * Copyright 2003-2004 Andreas Hofmeister <andi@solutions.pyrmaid.de>
 *
 * This software is licensed under the terms of the GNU General 
 * Public License (GPL). Please see the file COPYING for details.
 * 
 *
*/

#include "config.h"

#include <net/if.h>

#include "tmdns.h"
#include "serv_udp.h"
#include "debug.h"

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#else
#include "tm_ifaddrs.h"
#endif

#include "conf.h"

#ifdef WITH_NETLINK
#include "netlink_glue.h"
#endif

#define MCAST_V4_ADDR "224.0.0.251"
#define UNICAST_LOCAL "127.0.0.1"

/* set of sockets for multicast send/receive */
static int * mcast_sockets = NULL;

/* all open sockets */
static int * listen_sockets = NULL;

/* our unicast dns socket */
static int bridge_sock = -1;

#ifdef WITH_NETLINK
/* our netlink socket */
static int netlink_sock = -1;
#endif

static struct sockaddr mcast_v4_sa;
#ifdef DEBUG
static const char * udp_answerdst2str(const dns_t * answer);
#endif
static int udp_sock_open( int mcast , 
		 	  const struct sockaddr * sock, 
			  const char * ifname );
static const char * udp_sockaddr_str( const struct sockaddr * addr );

static struct ifaddrs * interfaces = NULL;

/*****************************************************************************
 * open sockets we are interested in.
 *
 * We will open
 *  - one unicast listener on port 53, loopback device (if enabled)
 *  - one unicast listener per interface that is not loopback
 *  - one multicast listener for the IPv4 mDNS group.
 *  - one multicast sender per interface.
 *
 * for IPv6 we should also open a socket for the IPv6 multicast group
 *
 * Arguments:
 *   exclude_devs  :  device names to exclude when getting the addresses.
 *   		      not used yet.
 *   sockets       :  Array of integers where the file descriptors are
 *                    stored.
 *
 * Returns:
 *   number of fd's opened.
 *
 ****************************************************************************/
int udp_open_sockets(int * sockets[]) {

    struct ifaddrs * ifnow = NULL;

    struct sockaddr_in * sa_v4_p = (struct sockaddr_in *)&mcast_v4_sa;

    unsigned int sockidx = 0;
    unsigned int maxsockidx = 0;

    unsigned int n_mcast     = 0;	/* number of multicast addresses */
    unsigned int n_addresses = 0;

    debug("open sockets\n");
    if( interfaces != NULL ) {
        freeifaddrs(interfaces);
	interfaces = NULL;
    }

    if( getifaddrs(&interfaces) < 0 ) {
        debug("getifaddrs failed.");
        syslog(LOG_ERR,"getifaddrs failed.");
	return(-1);
    }

    /* count addresses and addresses on multicast capable interfaces */
    for(ifnow = interfaces; ifnow; ifnow = ifnow->ifa_next) {
      if (ifnow->ifa_addr == NULL) {
          /* we will exclude this one anyway */
	  continue;  
      }
      if( ! (ifnow->ifa_flags & IFF_UP) ) {
	  /* interface not up */
	  continue;
      }
      if( (ifnow->ifa_flags & IFF_MULTICAST) ) n_mcast ++;
      n_addresses ++;
    }

    /* 
     * allocate an integer array for all our listen sockets 
     * 
     * We need at least
     *
     * - one for the netlink socket.
     * - one for our bridge socket.
     * - one for each ipv4/ipv6 address for unicast listen/send.
     * - one fore each address on a multicast capable interface.
     *
     */
    if(listen_sockets != NULL) {
	debug("listen_sockets not NULL when initializing new set of sockets\n");
	free(listen_sockets);
	listen_sockets = NULL;
    } 

    maxsockidx = 2 + n_addresses + n_mcast;
    listen_sockets = malloc( (maxsockidx + 1) * sizeof(*listen_sockets) );

    if( listen_sockets == NULL ) {
	debug("can not get memory for file descriptors\n");
	return -1;
    }
    for( sockidx = 0; sockidx <= maxsockidx; sockidx ++ ) { 
	    listen_sockets[sockidx] = -1; 
    }
    sockidx = 0;

    debug("allocated space for %u listen sockets\n", maxsockidx);

#ifdef WITH_NETLINK
    /*
     * Setup netlink interface
     */
    if( (netlink_sock = init_netlink_glue()) >= 0 ) {
        listen_sockets[sockidx] = netlink_sock;
        sockidx ++;
    } else {
        debug("could not init netlink socket\n");
	syslog(LOG_ERR, "could not init netlink socket");
    }
#endif

    /*
     * initialize IPv4 multicast socket address. This is done once
     */
    memset( sa_v4_p , 0 , sizeof(struct sockaddr_in) );
    sa_v4_p->sin_family = AF_INET;
    sa_v4_p->sin_port = htons(config.port);
    inet_aton( MCAST_V4_ADDR , &(sa_v4_p->sin_addr) );

    /*
     * Setup the bridge socket.
     */
    if( config.dns_bridge ) {
	struct sockaddr bridge_sa;
	struct sockaddr_in * sock = (struct sockaddr_in *)&bridge_sa;

	memset( sock , 0 , sizeof(struct sockaddr_in) );
	sock->sin_family = AF_INET;
	sock->sin_port = htons(config.dns_port);

	inet_aton( UNICAST_LOCAL , &(sock->sin_addr) );
	listen_sockets[sockidx] = udp_sock_open( 0 , (struct sockaddr *)sock,NULL);

	if( listen_sockets[sockidx] >= 0 ) {
	    bridge_sock = listen_sockets[sockidx];
	    debug("bridge socket is index %d, fd = %d\n", sockidx , bridge_sock );
	    sockidx ++;
	} else {
	    debug_perror("can not create local dns listener socket");
	    syslog(LOG_ERR,"can not create local dns listener socket for %s", 
			    udp_sockaddr_str((struct sockaddr *)sock));
	}
    }

   /**
     * open a unicast send/receive socket for each interface address.
     *
     * We could get away with one for all interfaces, but we get 
     * a problem when we have multiple if addresses (e.g. one link-local
     * and one static).
     *
     * We also need to distinguish between mcast and unicast
     */
    for(ifnow = interfaces; ifnow; ifnow = ifnow->ifa_next) {
	
        if( ! (ifnow->ifa_flags & IFF_UP) ) {
	    /* interface not up */
	    continue;
        }

	if( is_excluded_interface( ifnow->ifa_name ) ) 
	    continue;

	if (ifnow->ifa_addr == NULL)
	    continue;

	switch( ifnow->ifa_addr->sa_family ) {
	    case AF_INET:
		{
		    struct sockaddr_in * addr = (struct sockaddr_in *)ifnow->ifa_addr;

		    struct sockaddr      sc;
		    struct sockaddr_in * sa = (struct sockaddr_in *)&sc;    

  		    sa->sin_family = AF_INET;
		    sa->sin_port = htons(config.port);
		    memcpy((void *)&(sa->sin_addr), 
			   (void *)&(addr->sin_addr), sizeof(struct in_addr));

		    listen_sockets[sockidx] = udp_sock_open( 0 , &sc , NULL);
		    if( listen_sockets[sockidx] >= 0 ) {
			sockidx ++;
		    } else {
			int err = errno;
			debug("can not open listener socket for %s : %s\n" , 
				udp_sockaddr_str(&sc), debug_errmsg(err) );
			syslog(LOG_ERR, "can not open listener socket for %s : %s\n" , 
				udp_sockaddr_str(&sc), debug_errmsg(err) );
		    }
		}
		break;
	
	    case AF_INET6:
            default:
		break;
	}

	if( sockidx > maxsockidx ) {
	    debug("number of allocated sockets reached\n");
	    /* FIXME: what to do ? Exit program ? Just return ? */
	    return sockidx;
	}
    }

    /**
     * open the ipv4 multicast sender sockets.
     *
     * There is no obvious way to make Linux to broadcast an outgoing
     * multicast packet to all interface on which we have joined our 
     * multicast group. 
     *
     * Therefore we have to broadcast the packets by hand.
     *
     * We open a mcast socket for each address on each interface, not 
     * just one per interface. This is because the sender address in 
     * mcast packets is not mcast. 
     * 
     */
    if(mcast_sockets != NULL) {
	debug("mcast_sockets not NULL when initializing new set of sockets\n");
	free(mcast_sockets);
	mcast_sockets = NULL;
    } 

    if( n_mcast > 0 ) {
      unsigned int i = 0;
      unsigned int mcastidx = 0;
      const char * seen = "";

      debug("need %d macast sockets\n" , n_mcast );

      mcast_sockets = (int *)malloc( (n_mcast+1) * sizeof(int));
      if( mcast_sockets == NULL ) {
	  /* at least try to yell */
	  debug_perror("can not get memory for mcast send sockets\n");
	  return sockidx;
      }

      for( i = 0; i < n_mcast + 1 ; i ++ )  mcast_sockets[i] = -1;

      for(ifnow = interfaces; ifnow; ifnow = ifnow->ifa_next) {

        if( ! (ifnow->ifa_flags & IFF_UP) ) {
	    /* interface not up */
	    continue;
        }

	if( ! (ifnow->ifa_flags & IFF_MULTICAST) ) {
	    /* not a multicast if */
	    continue;
	}

	if (ifnow->ifa_addr == NULL)
	    continue;

        if( (ifnow->ifa_addr->sa_family == AF_INET) && 
	    (strcmp(ifnow->ifa_name,seen) == 0 ) )
	{
	    /* already have seen this interface */
	    debug("seen interface %s/%s before (as %s)\n" , 
		    ifnow->ifa_name, udp_sockaddr_str(ifnow->ifa_addr),seen);
	    //continue;
	}
	debug("init sender for interface %s\n" , ifnow->ifa_name);
	
	if( is_excluded_interface( ifnow->ifa_name ) ) 
	    continue;

	switch( ifnow->ifa_addr->sa_family ) {
	    case AF_INET:
    		{
                    struct ip_mreqn mreq;

	            seen = ifnow->ifa_name;

                    mreq.imr_address.s_addr = ((struct sockaddr_in *)ifnow->ifa_addr)->sin_addr.s_addr;
		    mreq.imr_ifindex = if_nametoindex(ifnow->ifa_name);
                    inet_aton( MCAST_V4_ADDR , &(mreq.imr_multiaddr) );

		    listen_sockets[sockidx] = udp_sock_open( 1 , (struct sockaddr *)sa_v4_p,
				    		      ifnow->ifa_name );
		    
		    if( listen_sockets[sockidx] >= 0 ) {
		        mcast_sockets[mcastidx] = listen_sockets[sockidx];

	    	        debug("mcast socket for interface %s/%s is index %d, fd = %d\n", 
					ifnow->ifa_name , 
		  	        	udp_sockaddr_str((struct sockaddr *)sa_v4_p), 
					sockidx , listen_sockets[sockidx]);

                        if( setsockopt( listen_sockets[sockidx] ,
			   IPPROTO_IP, IP_ADD_MEMBERSHIP, 
			   &mreq, sizeof(mreq)) < 0 )
		        {
		            debug("add membership failed on interface %s: %s\n" ,
			           ifnow->ifa_name , debug_errmsg(errno) );
		            syslog(LOG_ERR, "add membership failed on interface %s: %s\n" ,
			           ifnow->ifa_name , debug_errmsg(errno) );
		        }

			/* Set IF for mcasts */
			if( setsockopt(listen_sockets[sockidx], IPPROTO_IP, IP_MULTICAST_IF, &mreq.imr_address, sizeof(mreq.imr_address)) < 0) {
				log_perror("when setting IP_MULTICAST_IF");
			}

			mcastidx ++;
	    	        sockidx ++;

		    } else {
	    	        int err = errno;
	    	        debug("can not crate multicast sender socket for %s/%s : %s\n" , 
				ifnow->ifa_name ,
		  	        udp_sockaddr_str((struct sockaddr *)sa_v4_p), 
				debug_errmsg(err) );
	    	        syslog(LOG_ERR, "can not open sender socket for %s/%s : %s\n" , 
				ifnow->ifa_name ,
		  	        udp_sockaddr_str((struct sockaddr *)sa_v4_p), 
				debug_errmsg(err) );
		    }

    	        }
		break;
	
	    case AF_INET6:
            default:
		break;
	}
      } /* foreach interface */
    }

    *sockets = listen_sockets;
    return sockidx ;
}
/*****************************************************************************
 * Actually open a single socket.
 *
 * Arguments are
 *  mcast   -  !=0 when this should be a multicast socket, else 0
 *  sock    -  sockaddr structure giving the address to listen on
 * 
 * Returns
 *   >= 0 if the socket has been opened, < 1 if an error occured.
 *
 ****************************************************************************/
static int udp_sock_open( int mcast , 
			  const struct sockaddr * sock , 
			  const char * ifname )
{
  int fd;
  unsigned int yes = 1;
  unsigned char ttl  = 255;
  
  fd = socket( sock->sa_family , SOCK_DGRAM, IPPROTO_UDP);

  /* Error */
  if( fd < 0 ){
      log_perror("Could not create socket");
      return -1;
  } 

  /* bind() the socket to the interface */
  if (bind(fd, sock , sizeof(struct sockaddr)) < 0){
      log_perror("Could not bind to port");
      close(fd);
      return -1;
  }

  if( ifname != NULL ) {
      struct ifreq interface;
      memset (&interface, 0, sizeof (struct ifreq));
      strncpy(interface.ifr_ifrn.ifrn_name, ifname, IFNAMSIZ);
      if( setsockopt(fd  , SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface)) < 0 )
      {  
          log_perror("can not bind to device");
      }
  }

  /* should allow other processes to open the mDNS mcast socket */
  if( setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0 ) {
      log_perror("when setting SO_REUSEADDR");
  }

  /* set ttl to 255 on all sockets */
  if( setsockopt(fd, IPPROTO_IP, IP_TTL , &ttl , sizeof(ttl)) < 0 ) {
      log_perror("when setting IP_TTL");
  }

  /* Tell me the TTL of incomming packets. */
  if( setsockopt(fd, IPPROTO_IP, IP_RECVTTL , &yes, sizeof(yes)) < 0 ) {
      log_perror("when setting IP_RECVTTL");
  }

  /* record interface from which the packet came */
  /* setsockopt(fd, IPPROTO_IP, IP_PKTINFO , &yes, sizeof(yes)); */

  if( mcast ) {

    if( sock->sa_family == AF_INET ) {
      unsigned char loop = 0;

      /* Do not loop back the query to myself. */
      if( setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
	  log_perror("when setting IP_MULTICAST_LOOP");
      }

      /* spec require a ttl of 255. */
      if( setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL , &ttl , sizeof(ttl)) < 0) {
	  log_perror("when setting IP_MULTICAST_TTL");
      }

    }
  }
             
  return(fd);
}
/*****************************************************************************/
void udp_close_sockets(void) {

    int i = 0;

    if( listen_sockets == NULL ) {
	debug("listen_sockets is NULL when attemp to close 'em\n");
	return;
    }

    for( i = 0; listen_sockets[i] >= 0 ; i ++ ) {
#ifdef WITH_NETLINK
	if( listen_sockets[i] == netlink_sock ) {
	    stop_netlink_glue();
	    continue;
	}
#endif
	close(listen_sockets[i]);
    }
    free(listen_sockets);
    listen_sockets = NULL;

    if( mcast_sockets == NULL ) {
        debug("mcast_sockets already NULL ?\n");
    } else {
        free(mcast_sockets);
        mcast_sockets = NULL;
    }
}

/*****************************************************************************/
int udp_packet_read(int sockfd, struct udp_packet *udp_pkt )
{
  int numread;
  struct sockaddr_in * sa;
  int * mcast_sock = NULL;

  struct ifaddrs * ifnow = NULL;

  struct msghdr  msg;
  struct iovec   iov;
  struct cmsghdr *ptr;
  char   adata[1024];

#ifdef WITH_NETLINK
  if( sockfd == netlink_sock ) {
    debug("netlink message\n");
    handle_netlink_msg();
    return -1;
  }
#endif

  udp_pkt->ttl = -1;

  /* Read in the actual packet */
  udp_pkt->src_len = sizeof(struct sockaddr);

  msg.msg_name       = (void *) &(udp_pkt->src_address);
  msg.msg_namelen    = udp_pkt->src_len;
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (void *) adata;
  msg.msg_controllen = sizeof(adata);
  iov.iov_base       = udp_pkt->buf;
  iov.iov_len        = sizeof(udp_pkt->buf);


  if( (numread = recvmsg(sockfd, &msg, 0)) < 0 ) {
    debug_perror("udp_packet_read: recvfrom");

    return -1;
  }

  udp_pkt->len = numread;

  for (ptr = CMSG_FIRSTHDR(&msg); ptr != NULL; ptr = CMSG_NXTHDR(&msg, ptr)) {
    if( (ptr->cmsg_level == SOL_IP) && (ptr->cmsg_type == IP_TTL) ) {
        udp_pkt->ttl = * ((int *)CMSG_DATA(ptr));
    }
    /*
    if( (ptr->cmsg_level == SOL_IP) && (ptr->cmsg_type == IP_PKTINFO) ) {
        memcpy( &(udp_pkt->pktinfo), CMSG_DATA(ptr) , sizeof(struct in_pktinfo));
    }
    */
  }

  debug("packet TTL is %d\n", udp_pkt->ttl );


  /* Then record where the packet came from */
  sa = (struct sockaddr_in *)&(udp_pkt->src_address);
  udp_pkt->src_port = ntohs(sa->sin_port);

  if( mcast_sockets != NULL ) {
    for( mcast_sock = mcast_sockets; *mcast_sock >= 0; mcast_sock ++ ) { 
      if( sockfd == *mcast_sock ) { 
        udp_pkt->from_mcast = 1; 
      };
    }
  }

  /* 
   * check if we got the message because of an external network loop.
   *
   * This loop check is needed because we now broadcast our answers to
   * all multicast interfaces. In case of an external net loop we must
   * avoid that tmdns fight with itself over its authorative records.
   *
   * The check is only done when the source port is the mDNS port, 
   * because we might have other mDNS clients running on this host. 
   *
   * Only packets with a ttl of 255 can be a looped packet, because we
   * always set the ip ttl to 255. If the answer packet was < 255 we
   * should ignore as answers anyway.
   *
   */
  if( (udp_pkt->ttl == 255) && 
      udp_pkt->from_mcast && 
      (udp_pkt->src_port == config.port ) ) 
  { 
    debug("packet from %s\n" , udp_sockaddr_str(&(udp_pkt->src_address)));

    for(ifnow = interfaces; ifnow; ifnow = ifnow->ifa_next) {

      if( ! (ifnow->ifa_flags & IFF_UP) ) {
	  /* interface not up */
	  continue;
      }

      debug("  loop check for %s/%s\n" ,
		      		ifnow->ifa_name ,
		  	        udp_sockaddr_str(ifnow->ifa_addr)); 

      switch( ifnow->ifa_addr->sa_family ) {
        case AF_INET:
	  {
	    struct sockaddr_in * srcaddr = (struct sockaddr_in *)&(udp_pkt->src_address);
	    struct sockaddr_in * ifaddr  = (struct sockaddr_in *)(ifnow->ifa_addr);

	    if( udp_pkt->src_address.sa_family != AF_INET ) {
	      debug("  not the same address family\n");
	      continue;
	    }

	    if( memcmp( &(srcaddr->sin_addr), &(ifaddr->sin_addr), 
			sizeof(struct in_addr)) == 0 ) 
	    {
	        debug(  "Loop detected\n");
		syslog(LOG_NOTICE,"got multicast packet from myself\n");
		udp_pkt->loop = 1;
	    }
	  }
	  break;
	case AF_INET6:
	default:
	  break;
      }
    }
  }

  udp_pkt->len = numread;

  return numread;
}
/*****************************************************************************
* Send packet to the multicast address. 
 *****************************************************************************/
void udp_send_mcast_dnsmsg( const dns_t * pkt ) {

  if( pkt->to_mcast ) {
      int i = 0;
      for( i = 0; mcast_sockets[i] >= 0; i++) {
          sendto( 
	      mcast_sockets[i], 
	      pkt->u.raw , dns_get_len(pkt), 
	      0 , 
	      &mcast_v4_sa , sizeof(mcast_v4_sa));

          debug("sent message of %d bytes to %s on fd %d\n" , 
	        dns_get_len(pkt) , udp_sockaddr_str(&mcast_v4_sa), mcast_sockets[i]  );
      }
  }

}

/*****************************************************************************
 * Send packet to an unicast address. 
 *****************************************************************************/
void udp_send_dnsmsg_to( 
		int sockfd, 
		const struct sockaddr * dst_address , socklen_t dst_len , 
		const dns_t * pkt ) 
{

  if( sockfd >= 0 ) {

      int bytes = 0;
      bytes = sendto(sockfd, pkt->u.raw , dns_get_len(pkt), 
	      0, dst_address, dst_len );

      debug("sent %d(of %d) bytes to %s\n" , 
	    bytes , dns_get_len(pkt) , udp_sockaddr_str(dst_address) );
  }

}
/*****************************************************************************
 * Send packet to an unicast address. (old)
 *****************************************************************************/
void udp_send_dnsmsg( int sockfd, const dns_t * pkt ) {

  if( sockfd >= 0 ) {

      int bytes = 0;
      bytes = sendto(sockfd, pkt->u.raw , dns_get_len(pkt), 
	      0, &(pkt->dst_address), pkt->dst_len );

      debug("sent %d(of %d) bytes to %s\n" , 
	    bytes , dns_get_len(pkt) , udp_answerdst2str(pkt) );
  }

}
/*****************************************************************************
 * return true if the given socket is the/a dns bridge socket.
 *
 *****************************************************************************/
int udp_is_bridgesock( int fd ) {
    if( fd == bridge_sock ) {
	return 1;
    }
    return 0;
}

/*****************************************************************************
 * Copy address from an incomming udp_packet to an answer packet.
 *
 *****************************************************************************/
void udp_copy_answer_address(dns_t * answer,const struct udp_packet * udp_pkt) {

    memcpy( (void *)&(answer->dst_address),
            (const void *)&(udp_pkt->src_address),
                      udp_pkt->src_len);
    answer->dst_len  = udp_pkt->src_len;

}

/*****************************************************************************
 * Take source address and port from a struct sockaddr and return a
 * string suitable for logging/debugging.
 *
 * The result of this function is a pointer to a static buffer that will be
 * re-used in the next call to this function.
 *
 *****************************************************************************/
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 256
#endif
#define PORT_LEN 7
static const char * udp_sockaddr_str( const struct sockaddr * addr ) {

    static char result[INET6_ADDRSTRLEN+PORT_LEN+2];
    int  addr_port;
    char port_s[PORT_LEN];

    switch( addr->sa_family ) {
#ifdef HAVE_INET_NTOP
        case AF_INET:
	case AF_INET6:
	    inet_ntop(addr->sa_family, 
                      &(((const struct sockaddr_in *)addr)->sin_addr),
                      result,INET6_ADDRSTRLEN);
#else
        case AF_INET:
	    strncpy(result,inet_ntoa((const struct sockaddr_in *)addr),
                    INET6_ADDRSTRLEN);
#endif
	    addr_port = htons(((const struct sockaddr_in *)addr)->sin_port);
	    snprintf(port_s,PORT_LEN,"#%d",addr_port);
	    strncat(result,port_s,INET6_ADDRSTRLEN+PORT_LEN+2);
	    return result;
	    break;
	default:
	    return "(unknown address family)";
    }

}

#ifdef DEBUG
static const char * udp_answerdst2str(const dns_t * answer) {
    return udp_sockaddr_str( &(answer->dst_address) );
}
#endif

const char * udp_pktsrc2str(const struct udp_packet * udp_pkt) {
    return udp_sockaddr_str( &(udp_pkt->src_address) );
}

