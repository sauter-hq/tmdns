/*
 * info.h - resource record storage, prototypes
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

#ifndef INFO_H
#define INFO_H 1

#include "llist.h"

typedef struct {
  const char * dname;
  short        type;
  dns_rr     * data;  /* pointer to the resource record */
  ll_entry_t * el;    /* where to continue the search   */
} search_state;

typedef struct {
  u_int16_t id;
  u_int16_t rcode;

  int			timeout;

  int			sock;
  struct sockaddr	dst_address;
  socklen_t 		dst_len;

  list_t * questions;
  list_t * answers;
  list_t * authority;
  list_t * additional;
} decoded_message_t;

int info_init(void);
void info_destroy(void);

void info_init_search( search_state * state, const char * query, int type );
int  info_search( search_state * state );
void info_drop_record(search_state * s);

void debug_rr( const dns_rr * src );
int info_compare_rr(dns_rr * a, dns_rr * b);
dns_rr * info_clone_rr( dns_rr * src );

decoded_message_t * info_new_message(void);
decoded_message_t * info_decode_packet( struct udp_packet *udp_pkt );

dns_question * info_new_question(const char * domain, u_int16_t type, 
                                 u_int16_t class);
void info_copy_questions( const decoded_message_t * src, 
                          const decoded_message_t * dst);

void info_debug_rr_list( const list_t * list );
void info_debug_message( const decoded_message_t * msg );
void info_free_decoded_message( decoded_message_t * message );


int info_is_local_domain( const char * domain );

#endif


