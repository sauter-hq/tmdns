/*
 * dns.c - dns packet handling.
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

#include "config.h"

#include "conf.h"
#include "tmdns.h"
#include "dns.h"
#include "debug.h"

#define BYTESLEFT(x) (x->bufsize - (x->data - x->u.raw) + sizeof(HEADER))

/****************************************************************************
 * get the length of the dns message.
 * 
 * @param pkt   a pointer to a dns package structure.
 ****************************************************************************/
size_t dns_get_len( const dns_t * pkt ) {
	return (pkt->data - pkt->u.raw);
}
/****************************************************************************
 * init a dns packet structure.
 * 
 * @param pkt   a pointer to a dns package structure.
 ****************************************************************************/
void dns_init( dns_t * pkg) {

    memset( pkg , 0 , sizeof(dns_t) );
    pkg->bufsize    = DNSDATASIZE;
    pkg->data       = pkg->u.raw + sizeof(HEADER);
    pkg->dnptrs[0]  = pkg->data;
    pkg->last_dnptr = pkg->dnptrs[MAXDOMAINS-1];
    pkg->to_mcast   = 0;


}
/****************************************************************************
 * init a dns answer.
 * 
 * @param pkg           a pointer to a dns package structure.
 * @param query         a pointer to a decoded query
 * @param include_query true when the query records should be put into the
 *                      new answer packet.
 ****************************************************************************/
int dns_init_answer( dns_t * pkt ) {

  pkt->u.hdr.opcode = QUERY;
  pkt->u.hdr.id     = 0;
  pkt->u.hdr.qr     = 1;       /* this is a response                   */
  pkt->u.hdr.aa     = 0;       /* never send authoritative answers     */
  pkt->u.hdr.tc     = 0;       /* not truncated, but we will see ...   */
  pkt->u.hdr.rd     = 0;       /* we never do recursion                */
  pkt->u.hdr.ra     = 0;       /* recursion is not available           */
#if __BIND >= 19960801
  pkt->u.hdr.ad     = 0;       /* bind says 0 here, so we'll do        */
#endif
  pkt->u.hdr.rcode  = NOERROR; /* message is ok.                       */

  pkt->u.hdr.qdcount = 0;
  pkt->u.hdr.ancount = 0;
  pkt->u.hdr.nscount = 0;
  pkt->u.hdr.arcount = 0;

  return 0;
}
/*****************************************************************************
 * compress a domain into a message
 *
 ****************************************************************************/
static int dns_compress_domain( dns_t * pkt , const char * domain ) {
    int count = 0;
    count = dn_comp( domain,
	             pkt->data   , BYTESLEFT(pkt) ,
		     //NULL, NULL );
		     pkt->dnptrs , &(pkt->last_dnptr) );
    if( count < 0 ) return -1;

    pkt->data += count;
    return count;
}
/*****************************************************************************
 * put a character string into a message
 *
 * character strings are at most 255 bytes long, all strings are
 * prefixed with a length byte. Strings are trucated if they exceed
 * the limit.
 ****************************************************************************/
static int dns_put_string( dns_t * pkt, const char * string ) {

    size_t slen = strlen(string);

    if( slen > MAXDSTRING ) slen = MAXDSTRING;
    if( BYTESLEFT(pkt) < slen + 1 ) return -1;

    *(pkt->data) = slen;
    pkt->data ++;
    memcpy( pkt->data , string , slen );
    pkt->data += slen;

    return slen + 1 ;
    
}
/*****************************************************************************
 * add a query record to a packet.
 *
 *  @param pkt     pointer to a dns packet structure.
 *  @param domian  domain for this RR
 *  @param type    type for this RR, currently T_A and T_PTR are supported.
 *  @param class   class for this RR, always set this to C_IN
 *
 *  @return length of this RR or -1 on error.
 ****************************************************************************/
int  dns_add_qr( dns_t * pkt , const char * domain,
		 u_int16_t type, u_int16_t class )
{
    int count = 0;
    u_char * old_data = pkt->data;

    count = dns_compress_domain(pkt,domain);
    if( count < 0 ) return -1;

    if( BYTESLEFT(pkt) < 4 ) return -1;

    PUTSHORT( type   , pkt->data );
    PUTSHORT( class  , pkt->data );

    pkt->u.hdr.qdcount = htons( ntohs(pkt->u.hdr.qdcount) + 1);
    return pkt->data - old_data ;
}
/*****************************************************************************
 * add a new resource record to a packet.
 *
 *  @param pkt     pointer to a dns packet structure.
 *  @param rr      pointer to the data for this RR.
 *
 *  @return length of this RR or -1 on error.
 ****************************************************************************/
int dns_add_raw_rr( dns_t * pkt, const char * domain, 
		u_int16_t type , u_int16_t class, u_int32_t ttl ,
		size_t rr_len, const u_char * rr_data ) 
{
    int count = 0;
    u_char * old_data = pkt->data;
    
    count = dns_compress_domain(pkt,domain);
    if( count < 0 ) return -1;
   
    if( BYTESLEFT(pkt) < 10 + rr_len ) return -1 ;

    PUTSHORT( type   , pkt->data );
    PUTSHORT( class  , pkt->data );
    PUTLONG ( ttl    , pkt->data );
    PUTSHORT( rr_len , pkt->data );
    memcpy(pkt->data,rr_data,rr_len);
    pkt->data += rr_len;

    pkt->u.hdr.ancount = htons( ntohs(pkt->u.hdr.ancount) + 1);
    return  pkt->data - old_data;
 
}
/*****************************************************************************
 * add a new resource record to a packet.
 *
 *  @param pkt     pointer to a dns packet structure.
 *  @param rr      pointer to the data for this RR.
 *
 *  @return length of this RR or -1 on error.
 ****************************************************************************/
static int dns_add_rr_flush( dns_t * pkt, dns_rr * rr , int allow_flush )
{
    int count = 0;
    u_char * old_data = pkt->data;
    u_char * lenptr;

    u_int16_t class;

    class = rr->class;

    /* flag authorative rr's by setting the high-bit in class */
    //debug("to_mcast=%d rr_auth=%d\n" , pkt->to_mcast , rr->auth );
    if( (allow_flush != 0) && (pkt->to_mcast != 0) && (rr->auth != 0) ) {
	class |= 0x8000;
    }
    
    count = dns_compress_domain(pkt,rr->domain);
    if( count < 0 ) return -1;
   
    if( BYTESLEFT(pkt) < 10 ) return -1 ;

    PUTSHORT( rr->type   , pkt->data );
    PUTSHORT( class      , pkt->data );
    PUTLONG ( rr->ttl    , pkt->data );
    lenptr = pkt->data;
    PUTSHORT( 0 , pkt->data );

    switch( rr->type ) {
	case T_A:
	    if( BYTESLEFT(pkt) < sizeof(struct in_addr) ) return - 1;
	    memcpy( pkt->data , &(rr->rr.a) , sizeof(struct in_addr));
	    pkt->data += sizeof(struct in_addr);
    	    PUTSHORT( sizeof(struct in_addr) , lenptr);
	    break;

	case T_AAAA:
	    if( BYTESLEFT(pkt) < sizeof(struct in6_addr) ) return - 1;
	    memcpy( pkt->data , &(rr->rr.aaaa) , sizeof(struct in6_addr));
	    pkt->data += sizeof(struct in6_addr);
    	    PUTSHORT( sizeof(struct in6_addr) , lenptr);
	    break;

	case T_NS:
	case T_MD:
	case T_MF:
	case T_CNAME:
	case T_MB:
	case T_MG:
	case T_MR:
	case T_PTR:
	    /* this are the standard RR's which returns a domain */
    	    count = dns_compress_domain(pkt,rr->rr.dn);
	    if( count < 0 ) {
	    	return -1;
	    }
    	    PUTSHORT( count , lenptr);
	    break;
	case T_SOA:
	    {
		u_int16_t octets = 0;
		dns_soa_rr * soarec = & rr->rr.soa;
    	    	count = dns_compress_domain(pkt,soarec->name_server);
	    	if( count < 0 ) return -1;
		octets += count;
    	    	count = dns_compress_domain(pkt,soarec->admin );
	    	if( count < 0 ) return -1;
		octets += count;
		if( BYTESLEFT(pkt) < 5 * 4 ) return -1;
		PUTLONG(soarec->serial ,pkt->data);
		PUTLONG(soarec->refresh,pkt->data);
		PUTLONG(soarec->retry  ,pkt->data);
		PUTLONG(soarec->expire ,pkt->data);
		PUTLONG(soarec->min_ttl,pkt->data);
    	        PUTSHORT( octets += 5*4 , lenptr);
	    }
	    break;
	case T_MX:
	    {
		dns_mx_rr * mxrec = & rr->rr.mx ;
		PUTSHORT( mxrec->preference, pkt->data);
    	    	count = dns_compress_domain(pkt,mxrec->mail_host);
	    	if( count < 0 ) return -1;
    	        PUTSHORT( 2 + count , lenptr);
	    }
	    break;
	case T_HINFO:
	    {
		u_int16_t datalen = 0;
		dns_hinfo_rr * hirec = & rr->rr.hinfo;
		count = dns_put_string(pkt,hirec->cpu_type);
		if( count < 0 ) return -1;
		datalen = count;
		
		count = dns_put_string(pkt,hirec->os_name);
		if( count < 0 ) return -1;
		datalen += count;

    	        PUTSHORT( datalen , lenptr);
	    }
	    break;
	case T_TXT:
	    {
		dns_txt_rr * txtrec = & rr->rr.txt;
		ll_entry_t * el;
		u_int16_t datalen = 0;

		for( el = ll_first(txtrec->strings) ; el != NULL ; el = ll_next(el) ) {
		    count = dns_put_string(pkt,el->data);
		    if( count < 0 ) return -1;
		    datalen += count;
		}
    	        PUTSHORT( datalen , lenptr);
	    }
	    break;
	case T_SRV:
	    {
		dns_srv_rr * srvrec = & rr->rr.srv;

    	        PUTSHORT( srvrec->priority, pkt->data );
    	        PUTSHORT( srvrec->weight,   pkt->data );
    	        PUTSHORT( srvrec->port,     pkt->data );

    	    	count = dns_compress_domain(pkt,srvrec->target);
		if( count < 0 ) {
		    return -1;
		}
    	        PUTSHORT( count + 6 , lenptr);
	    }
	    break;
	default:
	    debug("Unknown rr type %d\n" , rr->type);
	    return -1;
    }
    
    pkt->u.hdr.ancount = htons( ntohs(pkt->u.hdr.ancount) + 1);
    return pkt->data - old_data ;
}

/* external visible version */
int dns_add_rr( dns_t * pkt, dns_rr * rr ) {
    return dns_add_rr_flush(pkt,rr,1);
}

/*****************************************************************************
 * add an additional record to a packet.
 *
 *  @param pkt     pointer to a dns packet structure.
 *  @param rr      pointer to the data for this RR.
 *
 *  @return length of this RR or -1 on error.
 ****************************************************************************/
int dns_add_ar( dns_t * pkt, dns_rr * rr ) {

    int result = 0;

    result = dns_add_rr_flush(pkt,rr,0);
    if( result < 0 ) return result;

    pkt->u.hdr.ancount = htons( ntohs(pkt->u.hdr.ancount) - 1);
    pkt->u.hdr.arcount = htons( ntohs(pkt->u.hdr.arcount) + 1);

    return result;

}

/*****************************************************************************
 * add a autority (ns) record to a packet.
 *
 *  @param pkt     pointer to a dns packet structure.
 *  @param rr      pointer to the data for this RR.
 *
 *  @return length of this RR or -1 on error.
 ****************************************************************************/
int dns_add_ns( dns_t * pkt, dns_rr * rr ) {

    int result = 0;

    result = dns_add_rr_flush(pkt,rr,0);
    if( result < 0 ) return result;

    pkt->u.hdr.ancount = htons( ntohs(pkt->u.hdr.ancount) - 1);
    pkt->u.hdr.nscount = htons( ntohs(pkt->u.hdr.nscount) + 1);

    return result;

}
/*****************************************************************************
 * 
 * Walk over a dns message invoke a callback foreach RR found in the
 * answer section of the packet.
 *
 *****************************************************************************/
int dns_walk_packet( struct udp_packet *udp_pkt ,
		     dnswalk_cb callback ,
		     void * userdata )
{
     return dns_walk_buf(udp_pkt->buf,udp_pkt->len,callback,userdata);
}

typedef struct {
  const char * info;
  u_int16_t    count;
  dns_sect     section;
} psection_t;

int dns_walk_buf  ( const u_char * query , size_t querysize ,
		     dnswalk_cb callback ,
		     void * userdata )
{
    u_char * data                = (u_char *)query + sizeof(HEADER);
    const u_char * query_end     = query +  querysize;
    const HEADER * hdr           = (HEADER *)query;

    psection_t sections[] = { 
	         			{ "answer"     , 0 , IN_ANSWER_SECT    },
	         			{ "authority"  , 0 , IN_AUTHORITY_SECT },
		 			{ "additional" , 0 , IN_EXTRA_SECT     }, 
					{ NULL         , 0 , 0 } };
    psection_t * section_now = sections;

    u_int16_t  dtype;
    u_int16_t  dclass;
    u_int32_t  dttl;
    char       dname[MAXDNAME+1];

    if( query == NULL ) {
	return -1;
    }

    if( data >= query_end ) {
	debug("Message to short, need at least %d bytes\n", sizeof(HEADER));
	syslog(LOG_WARNING,"dns packet to short, need at least %d bytes\n", sizeof(HEADER));
	return -1;
    }

    sections[0].count = ntohs(hdr->ancount);
    sections[1].count = ntohs(hdr->nscount);
    sections[2].count = ntohs(hdr->arcount);

    {
      int qc = 0;
      int n  = 0;
      int count = 0;
    
      qc = ntohs(hdr->qdcount);

      debug("got %d queries\n",qc);

      for( n = 0; n < qc; n ++ ) { 

        count = dn_expand( query, query_end,
		           data,
		           dname , 
			   MAXDNAME);
        if( count < 0 ) {
	    debug("error in parsing question %d\n", n);
	    syslog(LOG_WARNING,"Error processing questions in dns packet\n");
  	    return -1 ;
        }

        data += count;

	if( data + 4 > query_end ) {
	    debug("size missmatch when processing question %d\n", n);
	    syslog(LOG_WARNING,"Error processing questions in dns packet\n");
  	    return -1;
	}

        GETSHORT(dtype, data );
        GETSHORT(dclass, data );

	callback(IN_QUERY_SECT, dname, dtype, dclass, 
		 0 , 0, NULL, 
		 userdata,
		 query,query_end);
      }
    }

    /**
     * process other sections
     */
    for( section_now = sections; section_now->info != NULL ; section_now ++ )
    {
	int n     = 0;
	int count = 0;
	unsigned int length = 0;
	u_char *  rr_data;

	debug("got %d %s\n", section_now->count, section_now->info);

        for( n = 0; n < section_now->count; n ++ ) { 
            count = dn_expand( query, query_end,
		               data,
		               dname , 
			       MAXDNAME);

            if( count < 0 ) {
	        debug("error in processing section %s, entry %d\n", section_now->info, n);
	        syslog(LOG_WARNING,"Error processing answers in dns packet\n");
  	        return -1;
            }

            data += count;
 
	    if( data + 10 > query_end ) {
	        debug("size missmatch when processing section %s, entry %d\n", 
				section_now->info, n);
	        syslog(LOG_WARNING,"Error processing %s section in dns packet\n",
				section_now->info);
  	        return -1;
	    }

            GETSHORT(dtype, data );
            GETSHORT(dclass, data );
            GETLONG (dttl  , data );
	    GETSHORT(length, data );
	    rr_data = data;

	    if( data + length > query_end ) {
	        debug("attemp to overflow buffer when processing section %s, entry %d\n", 
				section_now->info, n);

	        syslog(LOG_WARNING,"Error processing %s section in dns packet\n",
				section_now->info);
  	        return -1;
	    }

	    data += length;

	    callback(section_now->section, dname , dtype, dclass, dttl , 
		     length, rr_data , 
		     userdata,
		     query, query_end);
	}
    }

    return 0;
}

