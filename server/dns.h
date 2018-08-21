/*
 *
 * dns.h
 *
 * Part of the tmdns package by Andreas Hofmeister. 
 *
 * Copyright 2003/2004 Andreas Hofmeister <andi.solutions.pyramid.de>
 *
 * This software is licensed under the terms of the GNU General 
 * Public License (GPL). Please see the file COPYING for details.
 * 
 *
*/
#ifndef DNS_H
#define DNS_H

#include <config.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <stdio.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>

#include "llist.h"
#include "tmdns.h"


/* maximum size of dns strings */
#define MAXDSTRING 255

/* maximum number of compressed domain labels */
#define MAXDOMAINS 128

/* 
 * draft-03 says a mDNS packet may not exceed 9000 bytes including
 * ip + udp headers. 
 */
#define DNSDATASIZE 9000


struct udp_packet {
  size_t	   len;			  /* size of this packet              */
  int		   ttl;                   /* ttl of recieved packet           */

  socklen_t        src_len;
  struct sockaddr  src_address;
  int              src_port;		  /* decoded port from src_addresss   */

  int		   loop;		  /* for external network loop detect */
  int              from_mcast;
  u_char buf[DNSDATASIZE];
};



typedef struct {
  u_int16_t query_type;      		  /* query type, usually T_A or T_PTR */
  u_int16_t query_class;     		  /* query_class, alway C_IN          */
  int       want_unicast;		  /* sender wanted unicast reply      */
  char      query_arg[MAXDNAME + 1];      /* object to search.                */
} dns_question;

typedef struct {

  socklen_t        dst_len;
  struct sockaddr  dst_address;

  int		from_mcast;            /* query came from multicast socket*/
  int           from_local;            /* query came from localhost       */
  int		to_mcast;	       /* answer goes to multicast        */
  int           fd;                    /* file descriptor on which we got */
  				       /* the query.                      */
  int           timeout;               /* time when to send back the answer*/

  unsigned int	bufsize;	       /* the size of the data buffer */
  u_char *	data;		       /* pointer to the first free byte in 
				          the buffer. */
  u_char *	last_dnptr;	       /* pointer to the last used entry in
				          dnptrs. For dn compression           */
  u_char *	dnptrs[MAXDOMAINS];    /* array of already compressed domains  */
  union dns_msg {
      HEADER	hdr;		       /* the DNS header */
      u_char 	raw[DNSDATASIZE];      /* data buffer    */
  } u;
} dns_t;

typedef struct {
  char * name_server;		       /* name server for the domain. */
  char * admin;		       	       /* mailbox of the administrator */
  u_int32_t serial;		       /* serial number for the data   */
  u_int32_t refresh;		       /* refresh time for zone data   */
  u_int32_t retry; 		       /* time to wait before a failed
					  refresh should be retried.   */
  u_int32_t expire;		       /* time until zone data expires */
  u_int32_t min_ttl;		       /* minimum ttl value for all RR's*/
} dns_soa_rr;

typedef struct {
  u_int16_t preference;			/* preference value for this mail host. */
  char * mail_host;			/* mail host. */
} dns_mx_rr;


typedef struct {
    char * cpu_type;			/* cpu type of this machine */
    char * os_name;			/* os of that machine       */
} dns_hinfo_rr;

typedef struct {
    list_t * strings;			/* list of text strings */
} dns_txt_rr;

typedef struct {
  u_int16_t priority;			/* priority for this svc */
  u_int16_t weight;			/* weight for this service */
  u_int16_t port;			/* port number */
  char * target;			/* target. */
} dns_srv_rr;

typedef struct _dns_rr_s {
    char  * domain;
    u_int16_t type;
    u_int16_t class;
    u_int32_t ttl;
    int       auth;
    void      (* freeFunc)(struct _dns_rr_s * rr);
    void      (* debugFunc)(const struct _dns_rr_s * rr);
    int	      (* cmpFunc)(const struct _dns_rr_s * a,const struct _dns_rr_s * b);
    struct _dns_rr_s * (* cloneFunc)(const struct _dns_rr_s * src);

    union {
	char *         dn;
	struct in_addr a;
	struct in6_addr aaaa;
	dns_soa_rr     soa;
	dns_mx_rr      mx;
	dns_hinfo_rr   hinfo;
	dns_txt_rr     txt;
	dns_srv_rr     srv;
    } rr ;
} dns_rr;


void dns_init( dns_t * );
int  dns_init_answer( dns_t * );

int  dns_add_ar( dns_t * pkt, dns_rr * rr );
int  dns_add_ns( dns_t * pkt, dns_rr * rr );
int  dns_add_rr( dns_t * pkt , dns_rr * rr );
int  dns_add_qr( dns_t * pkt , const char * domain,
		 u_int16_t type, u_int16_t class);

int dns_add_raw_rr( dns_t * pkt, const char * domain,
		    u_int16_t type , u_int16_t class, u_int32_t ttl ,
		    size_t rr_len, const u_char * rr_data );

size_t  dns_get_len(const dns_t *);

int udp_is_bridgesock( int fd );

typedef enum {
  IN_QUERY_SECT ,
  IN_ANSWER_SECT,
  IN_AUTHORITY_SECT,
  IN_EXTRA_SECT
} dns_sect;

typedef int (* dnswalk_cb)(dns_sect section, 
			   const char * domain, 
			   u_int16_t type, u_int16_t class, u_int32_t ttl,
			   size_t rr_len , const u_char * rr_data, 
			   void * user_data ,
			   const void * buf_start, const void * buf_end) ;

int dns_walk_buf   ( const u_char * buf , size_t len,
		      dnswalk_cb callback ,
		      void * userdata );

int dns_walk_packet( struct udp_packet *udp_pkt ,
		      dnswalk_cb callback ,
		      void * userdata );


#ifdef AF_INET6
#define HAVE_IP6
#endif

#endif
/* EOF */
