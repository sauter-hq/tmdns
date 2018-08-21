/*
 * info.c - resource record storage.
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
#define _GNU_SOURCE 1 
#include <stdio.h>

#include <sys/utsname.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ctype.h>
#include <assert.h>

#include "conf.h"
#include "debug.h"
#include "tmdns.h"
#include "dns.h"
#include "llist.h"
#include "info.h"

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#else
#include "tm_ifaddrs.h"
#endif

static list_t * records;

static dns_rr * newLocalHinfoRec( const char * domain );
static dns_rr * newARec( const char * domain , const struct in_addr * ip );
static const char escaped_space[]="\\032";

/*****************************************************************************
 * Escape characters in domain labels.
 *
 * Returns a malloc'ed copy of the string with "." "\" and " " escaped.
 *
 *****************************************************************************/
static char * escapeDomainLabel(char * label) {
    unsigned int needed = 0;
    char * now = NULL;
    char * to  = NULL;
    char * result = NULL;

    /* count how many characters we will need */
    for( now = label; *now != 0; now ++ ) {
	switch( *now ) {
	    case '.':
	    case '\\':
		needed += 2;
		break;
	    case ' ':
		needed += strlen(escaped_space);
		break;
	    default:
		needed ++;
	}
    }

    result = (char *)malloc(needed + 1);
    if (result == NULL)
       return NULL;
    to = result;

    for( now = label; *now != 0; now ++ ) {
	*to = 0;
	switch( *now ) {
	    case '.':
	    case '\\':
		*to = '\\';
		to ++;
		*to = *now;
		break;
	    case ' ':
		strcat(to,escaped_space);
		to += strlen(escaped_space);
		break;
	    default:
		*to = *now;
		to ++;
	}
    }

    * to = 0;

    return result;

}

/*****************************************************************************
 * Constructor and destructor functions for basic resource records.
 *
 *****************************************************************************/
static void free_rr(dns_rr * rr) {
    if (rr->domain)
	free(rr->domain);
    free(rr);
}

void debug_rr(const dns_rr * rr) {
    debug("  domain=%s, type=%u, class=%u, ttl=%u, auth=%d\n",
	   rr->domain, rr->type, rr->class, rr->ttl, rr->auth );
}

static int cmpNone(const dns_rr * a, const dns_rr * b) {
    return 0;
}

static dns_rr * clone_rr( const dns_rr * src ) {
    dns_rr * copy = NULL;

    if( (copy = (dns_rr *)malloc( sizeof(dns_rr))) == NULL )
        return NULL;

    copy->domain   = strdup( src->domain );
    copy->type     = src->type;
    copy->class    = src->class;
    copy->ttl      = src->ttl;
    copy->auth     = src->auth;
    copy->freeFunc = src->freeFunc;
    copy->debugFunc= src->debugFunc;
    copy->cmpFunc  = src->cmpFunc;
    copy->cloneFunc= src->cloneFunc;

    return copy;
}

static void init_rr(dns_rr * rr,const char * domain, u_int16_t type ) {
  rr->domain   = strndup(domain,MAXDNAME);
  rr->type     = type;
  rr->class    = C_IN;
  rr->ttl      = config.default_ttl;
  rr->auth     = 0;
  rr->freeFunc = free_rr;
  rr->debugFunc= debug_rr;
  rr->cmpFunc  = cmpNone; /* dummy */
  rr->cloneFunc= clone_rr;
}

static int cmpUInt(u_int32_t a, u_int32_t b) {
  if( a > b ) return 1;
  if( a < b ) return -1;
  return 0;
}


/* extern visible compare function */
int info_compare_rr(dns_rr * a, dns_rr * b) {
    int result = 0;

    //debug("in info compare\n");
    assert(a != NULL);
    assert(b != NULL);
    assert(a->cmpFunc != NULL);

    if( (result = strncasecmp(a->domain,b->domain,MAXDNAME)) == 0 ) {
      //debug("  domain %s == %s\n" , a->domain,b->domain);
      if( (result = cmpUInt(a->type,b->type)) == 0) {
	//debug("  type %d == %d\n" , a->type,b->type);
        if( (result = cmpUInt(a->class,b->class)) == 0) {
	  //debug("  class %d == %d\n" , a->class,b->class);
	  result = a->cmpFunc(a,b);
        }
      }
    }

    //debug("compare result = %d\n" , result );
    return result;
}

/* extern visible clone function */
dns_rr * info_clone_rr( dns_rr * src ) {

    if( src == NULL ) {
	debug("attemp to clone a NULL pointer\n");
	return NULL;
    }

    return src->cloneFunc(src);
}

/*****************************************************************************
 * Constructor and destructor functions for hostinfo resource records.
 *
 *****************************************************************************/
static void freeHinfoRec(dns_rr * hinfo) {
   free(hinfo->rr.hinfo.cpu_type);
   free(hinfo->rr.hinfo.os_name);
   free_rr(hinfo);
}

static int compareHinfoRec(const dns_rr * a, const dns_rr * b) {
    int result = 0;

    debug("in compareHinfoRec\n");

    if((result = strncmp(a->rr.hinfo.cpu_type , b->rr.hinfo.cpu_type, MAXDSTRING)) == 0) {
	result = strncmp(a->rr.hinfo.os_name , b->rr.hinfo.os_name, MAXDSTRING);
    }

    return result;
}

static void debugHinfoRec(const dns_rr * hinfo) {
    debug_rr(hinfo);
    debug("    hinfo: cpu=%s, os=%s\n" , 
	  hinfo->rr.hinfo.cpu_type , hinfo->rr.hinfo.os_name );
}

static dns_rr * cloneHinfoRec(const dns_rr * src) {
    dns_rr * copy = NULL;

    if( (copy = clone_rr(src)) == NULL ) 
	return NULL;

    copy->rr.hinfo.cpu_type = strdup(src->rr.hinfo.cpu_type);
    if( copy->rr.hinfo.cpu_type == NULL ) {
	free(copy);
	return NULL;
    }
    copy->rr.hinfo.os_name  = strdup(src->rr.hinfo.os_name);
    if( copy->rr.hinfo.os_name == NULL ) {
	free(copy->rr.hinfo.cpu_type);
	free(copy);
	return NULL;
    }

    return copy;
}

static dns_rr * newHinfoRec(const char * domain , 
		            const char * cpu , const char * os ) {

    dns_rr * hinfo = NULL;

    hinfo = (dns_rr *)malloc( sizeof(dns_rr) );
    if (hinfo == NULL)
        return NULL;

    init_rr(hinfo,domain,T_HINFO);
    hinfo->rr.hinfo.cpu_type = strndup(cpu,MAXDSTRING);
    hinfo->rr.hinfo.os_name  = strndup(os,MAXDSTRING);

    hinfo->freeFunc  = freeHinfoRec;
    hinfo->debugFunc = debugHinfoRec;
    hinfo->cmpFunc   = compareHinfoRec;
    hinfo->cloneFunc = cloneHinfoRec;

    return hinfo;
}

static dns_rr * newLocalHinfoRec(const char * domain ) {

    struct utsname info;
    dns_rr * hinfo = NULL;

    char * os  = NULL;

    uname(&info);

    asprintf(&os, "%s %s" , info.sysname , info.release);

    hinfo = newHinfoRec(domain,info.machine,os);
    free(os);

    return hinfo;
}

/*****************************************************************************
 * Constructor function for ipv4 address resource records.
 *
 *****************************************************************************/
static int compareARec(const dns_rr * a, const dns_rr * b) {
    debug("in compareARec\n");
    return memcmp(&(a->rr.a), &(b->rr.a),sizeof(struct in_addr));
}

static dns_rr * cloneARec(const dns_rr * src) {
    dns_rr * copy = NULL;

    if( (copy = clone_rr(src)) == NULL ) 
	return NULL;

    memcpy( &(copy->rr.a), &(src->rr.a) , sizeof(struct in_addr));

    return copy;
}

static dns_rr * newARec( const char * domain , const struct in_addr * ip ) {
    dns_rr * aRec = NULL;
    
    aRec = (dns_rr *)malloc( sizeof(dns_rr) );
    if (aRec == NULL)
        return NULL;

    init_rr(aRec,domain,T_A);
    memcpy(&(aRec->rr.a),ip,sizeof(struct in_addr));

    aRec->freeFunc  = free_rr;
    aRec->cmpFunc   = compareARec;
    aRec->cloneFunc = cloneARec;

    return aRec;
}
/*****************************************************************************
 * Constructor function for ipv4 address resource records.
 *
 *****************************************************************************/
static int compareAAAARec(const dns_rr * a, const dns_rr * b) {
    debug("in compareARec\n");
    return memcmp(&(a->rr.aaaa), &(b->rr.aaaa),sizeof(struct in6_addr));
}

static dns_rr * cloneAAAARec(const dns_rr * src) {
    dns_rr * copy = NULL;

    if( (copy = clone_rr(src)) == NULL ) 
	return NULL;

    memcpy( &(copy->rr.aaaa), &(src->rr.aaaa) , sizeof(struct in6_addr));

    return copy;
}

static dns_rr * newAAAARec( const char * domain , const struct in6_addr * ip ) {
    dns_rr * aRec = NULL;
    
    aRec = (dns_rr *)malloc( sizeof(dns_rr) );
    if (aRec == NULL)
        return NULL;
    init_rr(aRec,domain,T_AAAA);
    memcpy(&(aRec->rr.aaaa),ip,sizeof(struct in6_addr));

    aRec->freeFunc  = free_rr;
    aRec->cmpFunc   = compareAAAARec;
    aRec->cloneFunc = cloneAAAARec;

    return aRec;
}
/*****************************************************************************
 * Constructor and destructor functions for pointer resource records.
 *
 *****************************************************************************/
static void freePtrRec(dns_rr * rr) {
    free(rr->rr.dn);
    free_rr(rr);
}

static int comparePtrRec(const dns_rr * a, const dns_rr * b) {
    debug("in comparePtrRec\n");
    return strncasecmp(a->rr.dn,b->rr.dn, MAXDNAME);
}

static void debugPtrRec(const dns_rr * ptrRec ) {
    const char * typeStr = "????";

    switch (ptrRec->type) {
	case T_NS:	typeStr = "ns"; break;
        case T_MD:	typeStr = "md"; break;
        case T_MF:	typeStr = "mf"; break;
        case T_CNAME:	typeStr = "cname"; break;
        case T_MB:	typeStr = "mb"; break;
        case T_MG:	typeStr = "mg"; break;
        case T_MR:	typeStr = "mr"; break;
        case T_PTR:	typeStr = "ptr"; break;
    }

    
    debug_rr(ptrRec);
    debug("    %s: %s\n" , typeStr, ptrRec->rr.dn );
}

static dns_rr * clonePtrRec(const dns_rr * src) {
    dns_rr * copy = NULL;

    if( (copy = clone_rr(src)) == NULL ) 
	return NULL;

    copy->rr.dn = strdup(src->rr.dn);
    if( copy->rr.dn == NULL ) {
	free(copy);
	return NULL;
    }

    return copy;
}


static dns_rr * newPtrRec( const char * domain , const char * dn ) {
    dns_rr * ptrRec = NULL;
    
    ptrRec = (dns_rr *)malloc( sizeof(dns_rr) );
    if (ptrRec == NULL)
        return NULL;

    init_rr(ptrRec,domain,T_PTR);
    ptrRec->rr.dn = strdup(dn);

    ptrRec->freeFunc  = freePtrRec;
    ptrRec->debugFunc = debugPtrRec;
    ptrRec->cmpFunc   = comparePtrRec;
    ptrRec->cloneFunc = clonePtrRec;

    return ptrRec;
}

/*****************************************************************************
 * Constructor and destructor functions for service resource records.
 *
 *****************************************************************************/
static void freeSrvRec(dns_rr * rr) {
    free(rr->rr.srv.target);
    free_rr(rr);
}

static int compareSrvRec(const dns_rr * a, const dns_rr * b) {

    int result = 0;

    debug("in compareSrvRec\n");

    if( (result = cmpUInt(a->rr.srv.priority , b->rr.srv.priority)) == 0 ) {
      if( (result = cmpUInt(a->rr.srv.weight , b->rr.srv.weight)) == 0 ) {
        if( (result = cmpUInt(a->rr.srv.port , b->rr.srv.port)) == 0 ) {
	  result = strncasecmp(a->rr.srv.target,b->rr.srv.target,MAXDNAME);
	}
      }
    }

    return result;
}

static void debugSrvRec(const dns_rr * rr) {
    debug_rr(rr);
    debug("    srv: prio=%u, weight=%u port=%u target=%s\n" , 
	  rr->rr.srv.priority , rr->rr.srv.weight, rr->rr.srv.port, rr->rr.srv.target);
}

static dns_rr * cloneSrvRec(const dns_rr * src) {
    dns_rr * copy = NULL;

    if( (copy = clone_rr(src)) == NULL ) 
	return NULL;

    copy->rr.srv.target = strdup(src->rr.srv.target);
    if( copy->rr.srv.target == NULL ) {
	free(copy);
	return NULL;
    }

    copy->rr.srv.priority = src->rr.srv.priority;
    copy->rr.srv.weight   = src->rr.srv.weight;
    copy->rr.srv.port     = src->rr.srv.port;

    return copy;
}

static dns_rr * newSrvRec( const char * domain,
                  u_int16_t  priority,
                  u_int16_t  weight,
                  u_int16_t  port,
                  const char * target )
{
    dns_rr * srvRec = NULL;

    srvRec = (dns_rr *)malloc( sizeof(dns_rr) );
    if (srvRec == NULL)
        return NULL;
    init_rr(srvRec,domain,T_SRV);

    srvRec->rr.srv.target   = strndup(target,MAXDNAME);
    srvRec->rr.srv.priority = priority;
    srvRec->rr.srv.weight   = weight;
    srvRec->rr.srv.port     = port;

    srvRec->freeFunc  = freeSrvRec;
    srvRec->debugFunc = debugSrvRec;
    srvRec->cmpFunc   = compareSrvRec;
    srvRec->cloneFunc = cloneSrvRec;

    return srvRec;
}
/*****************************************************************************
 * Constructor and destructor functions for txt resource records.
 *
 *****************************************************************************/
static void freeTxtRec(dns_rr * rr) {

    ll_entry_t * el;

    assert( rr->type == T_TXT );
    assert( rr->rr.txt.strings != NULL );

    foreach(el,rr->rr.txt.strings) {
        if( el->data != NULL ) {
	    free(el->data);
	    el->data = NULL;
	}
    }

    ll_delete( rr->rr.txt.strings );

    free_rr(rr);
}

static int compareTxtRec(const dns_rr * a, const dns_rr * b) {
    
    ll_entry_t * ela;
    ll_entry_t * elb;
    int result;

    debug("in compareTxtRec\n");

    ela = ll_first(a->rr.txt.strings);
    elb = ll_first(b->rr.txt.strings);

    while( (ela != NULL) && (elb != NULL) ) {
	
	if( (result = strncmp( ela->data , elb->data , MAXDNAME )) != 0 ) {
	    return result;
	}

	ela = ll_next(ela);
	elb = ll_next(elb);
    }

    if( ela != NULL ) {
	return 1;
    }

    if( elb != NULL ) {
	return -1;
    }

    return 0;
}

static void debugTxtRec(const dns_rr * rr) {
    ll_entry_t * el;
    debug_rr(rr);
    foreach(el,rr->rr.txt.strings) {
	debug("    string: %s\n" , (char *)el->data );
    }
}

static int txtRecAddString( const dns_rr * rr , const char * str ) {

    char * copy = NULL;

    assert( rr != NULL ) ;
    assert( rr->type == T_TXT );
    assert( rr->rr.txt.strings != NULL ) ;

    if( (copy = strndup(str,MAXDSTRING)) == NULL ) {
        return -1;
    }

    if( ll_add( rr->rr.txt.strings , copy ) < 0 ) {
	free(copy);
	return -1;
    }

    return 0;

}

static dns_rr * cloneTxtRec(const dns_rr * src) {
    dns_rr * copy = NULL;
    ll_entry_t * el;

    if( (copy = clone_rr(src)) == NULL ) 
	return NULL;

    if( (copy->rr.txt.strings = ll_new()) == NULL ) {
	free(copy);
        return NULL;
    }

    foreach(el,src->rr.txt.strings) {
	if(txtRecAddString(copy, (char *)el->data ) < 0 ) {
	    freeTxtRec(copy);
	    return NULL;
	}
    }

    return copy;
}

static dns_rr * newTxtRec( const char * domain )
{
    dns_rr * txtRec = NULL;

    txtRec = (dns_rr *)malloc( sizeof(dns_rr) );
    if (txtRec == NULL)
        return NULL;
    init_rr(txtRec,domain,T_TXT);

    if( (txtRec->rr.txt.strings = ll_new()) == NULL ) {
	free_rr(txtRec);
        return NULL;
    }

    txtRec->freeFunc  = freeTxtRec;
    txtRec->debugFunc = debugTxtRec;
    txtRec->cmpFunc   = compareTxtRec;
    txtRec->cloneFunc = cloneTxtRec;

    return txtRec;
}

/*****************************************************************************
 * Read a service registry and add a service record for each entry.
 *
 *****************************************************************************/
#define LINE_LEN 1024
static void info_read_serviceconf( char * service_file , const char * fqdn, 
                                   char * hostname) {

    FILE *fp;
    char line[LINE_LEN];
    int  lineno = 0;

    dns_rr * svc_rr = NULL;
    dns_rr * txt_rr = NULL;


    debug("read service config %s ...\n", service_file);

    fp = fopen (service_file, "r");
    if (!fp) {
      debug_perror("no service file");
      return;
    }

    memset(line,0,LINE_LEN);

    while (fgets(line, LINE_LEN - 1 , fp)) {

    	char * now  = line ;
	int fields  = 0;

        char proto[LINE_LEN];
	char service[LINE_LEN];
        int port     = -1;
        int prio     = -1;
        int weight   = -1;
        char * name  = NULL;
	int name_ofs = 0;

	char * serv_name = NULL;
	char * ptr_name  = NULL;

        memset(proto,0,LINE_LEN);
        memset(service,0,LINE_LEN);

	lineno ++;

	if( line[strlen(line) - 1] == '\n' ) {
            line[strlen(line) - 1] = 0; /* kill '\n' */
        }

	/* strip trailing blanks */
	now = &line[strlen(line) - 1];
	while( (now > line) && ( isblank(*now) ) ) {
	    *now = 0;
	    now --;
	}
	
	now = line;

        /* skip whitespace */
        while( isblank(*now) ) { now ++; }

        if ( *now =='#') { continue; } /* skip lines with comment */
        if ( *now == 0 ) { continue; } /* skip empty lines */

        // NOTE: if the sizeof proto changes, the 1023 needs to be updated.
	fields = sscanf(now,"%1023s %n", proto, &name_ofs);

	if( fields != 1 ) {
	    debug("syntax error in line %d\n",lineno);
	}

	if( name_ofs > 0 ) {
	    now = now + name_ofs;
	}

	if( strcasecmp( proto , "text") == 0 ) {

	    debug("found text\n");

	    if( svc_rr == NULL ) {
	        debug("Start text record before service record in line %d\n", lineno);
		continue;
	    }

	    if( txt_rr == NULL ) {
		debug("adding text record\n");
		txt_rr = newTxtRec( svc_rr->domain );
		ll_add(records,txt_rr);
	    }

	    debug("  adding string >%s< to last text record\n", now);
	    txtRecAddString( txt_rr , now );

	} else if( strcasecmp( proto , "ptr") == 0 ) {

    	    dns_rr * ptr_rr = NULL;

	    debug("found extra pointer\n");

	    if( svc_rr == NULL ) {
	        debug("Start ptr record before service record in line %d\n", lineno);
		continue;
	    }

	    ptr_rr = newPtrRec( now , svc_rr->domain );
	    ll_add(records,ptr_rr);

        } else {
            // NOTE: if the sizeof service changes, 1023 needs to be updated.
	    fields = sscanf(now,"%d %1023s %d %d %n", &port, service, &prio, &weight , &name_ofs );
	
	    if( ( fields < 4 ) && ( fields > 0 ) ) {
	        debug("syntax error in line %d\n",lineno);
	    }

	    if( name_ofs > 0 ) {
	        name = now + name_ofs;
	    }

	    debug("got %d fields, proto=%s port=%d service=%s prio=%d weight=%d name=%s (ofs=%d)\n",
		    fields, proto , port, service, prio, weight, name, name_ofs );

	    /* semantic check ... */

	    if(name && (*name != 0) ) {
	        char * escaped = NULL;
	        escaped = escapeDomainLabel(name);
	        if( strlen(escaped) > 63 ) {
		    debug("truncated service name because its longer than 63 chars.\n");
		    escaped[63] = 0;
	        }
	        asprintf(&serv_name, "%s._%s._%s.local",escaped,service,proto);
	        free(escaped);
	        asprintf(&ptr_name , "_%s._%s.local",service,proto);
	    } else {
	        asprintf(&serv_name, "%s._%s._%s.local",hostname,service,proto);
	        asprintf(&ptr_name , "_%s._%s.local",service,proto);
	    }

	    /* reset last text_rr, because we start a new scv rr */
	    txt_rr = NULL;

	    if( (svc_rr = newSrvRec(serv_name, prio, weight, port, fqdn )) != NULL ) {
                ll_add(records, svc_rr );
	        svc_rr->auth = 1;
	        if( ptr_name != NULL ) {
                    ll_add(records, newPtrRec(ptr_name,serv_name));
	        }
            }
	    free(serv_name);
	    if( ptr_name != NULL ) { free(ptr_name); }
        }
    }

    fclose(fp);
    return; 
}
/*****************************************************************************
 * initialize the resource database.
 *
 *  This function adds resource records we want to publish to the record 
 *  registry. It will perform the following steps :
 *
 *  - get the hostname from the config file or from utsname
 *  - get all interface addresses and add an A record for each address.
 *  - add a PTR rec for each address to allow reverse lookup.
 *  - add a HINFO record for hostname.local.
 *  - call info_read_serviceconf to add service records to the registry.
 *
 *****************************************************************************/

int info_init(void) {

    struct ifaddrs * ifs = NULL;
    struct ifaddrs * ifnow = NULL;

    struct utsname info;
    char * namebuf = NULL;
    char * raw_namebuf = NULL;
    char * dot_pos = NULL;

    debug("Initialize host data ...\n");

    uname(&info);

    if( config.hostname[0] != 0 ) {
        raw_namebuf = strdup(config.hostname);
    } else {
        raw_namebuf = strdup(info.nodename);
    }

    /* only first label */
    if( (dot_pos = index(raw_namebuf,'.')) != NULL ) {
	*dot_pos = 0;
    }

    asprintf(&namebuf,"%s.local", raw_namebuf );
    
    records = ll_new();

    /*
     * Find our ethernet interfaces and add A records for
     * each IPv4 address we have.
     * Also add PTR records for the reverse zone.
     */
    if (getifaddrs(&ifs) < 0) {
	syslog(LOG_ERR, "getifaddrs failed...exiting.");
	return -1;
    }

    for(ifnow = ifs; ifnow; ifnow = ifnow->ifa_next) {
	if( ifnow->ifa_flags & IFF_LOOPBACK ) continue;
	if( ! (ifnow->ifa_flags & IFF_UP) ) continue;

	if (ifnow->ifa_addr == NULL) {
	    debug("getifaddr returned an interface with NULL address");
	    continue;
	}

	if( is_excluded_interface( ifnow->ifa_name ) ) {
	    debug("exclude address from interface %s\n" , ifnow->ifa_name );
	    continue;
	}

	debug("got address on interface %s\n", ifnow->ifa_name );

	switch( ifnow->ifa_addr->sa_family ) {
	  case AF_INET:
		{
		    struct in_addr inaddr;
		    unsigned char * ib = (unsigned char *)&inaddr;
		    char * revname = NULL;
		    dns_rr * rr = NULL;

		    struct sockaddr_in * addr = 
			    (struct sockaddr_in *)ifnow->ifa_addr;

		    memcpy(&inaddr, &(addr->sin_addr) , sizeof(struct in_addr));
		    debug("  %s\n", inet_ntoa(inaddr) );

		    if( (rr = newARec(namebuf,&inaddr)) != NULL ) {
		      /* want to be authoratative for A records */
		      rr->auth = 1;
    		      ll_add(records , rr );

		      asprintf( &revname , "%d.%d.%d.%d.in-addr.arpa" ,
				    ib[3] , ib[2], ib[1], ib[0] );
		      debug("Reverse address is %s\n" , revname );
		      ll_add(records , newPtrRec(revname,namebuf));
		      free(revname);
		    }
		}
		break;

	  case AF_INET6:
		{
		    struct in6_addr inaddr;
		    dns_rr * rr = NULL;
		    /* reverse address needs:
                          (128/4) * 2 (for .) + ip6.arpa(8) + \0 chars */
		    char revname[73];
		    int n = 0;
		    int i = 0;

		    struct sockaddr_in6 * addr = 
			    (struct sockaddr_in6 *)ifnow->ifa_addr;

		    memcpy(&inaddr, &(addr->sin6_addr) , sizeof(struct in6_addr));

		    if( (rr = newAAAARec(namebuf,&inaddr)) != NULL ) {
		      /* want to be authoratative for AAAA records */
		      rr->auth = 1;
    		      ll_add(records , rr );

		      n = 0;
		      memset(revname,'.',65);
		      for( i = 15; i >= 0 ; i -- ) {
			  u_char h = inaddr.s6_addr[i] >> 4;
			  u_char l = inaddr.s6_addr[i] & 0x0F;
			  revname[n]   = (l<10) ? 0x30 + l : 0x57 + l;
			  revname[n+2] = (h<10) ? 0x30 + h : 0x57 + h;
			  n += 4;
		      }
		      strcpy(&revname[64],"ip6.arpa");
		      debug("Reverse address is %s\n" , revname );
		      ll_add(records , newPtrRec(revname,namebuf));
		    }
		}
		break;
	}
    }


    freeifaddrs(ifs);

    {
	dns_rr * rr = NULL;
        /* want to be authoratative for the HINFO record */
	if( (rr = newLocalHinfoRec(namebuf)) != NULL ) {
	  rr->auth = 1;
          ll_add(records , rr);
	}
    }

    if( config.service_file[0] != 0 ) {
        info_read_serviceconf(config.service_file, namebuf, raw_namebuf );
    }
    if( config.dynamic_service_file[0] != 0 ) {
        info_read_serviceconf(config.dynamic_service_file, namebuf, raw_namebuf );
    }

    free(raw_namebuf);
    free(namebuf);

    debug("will probe for this records:\n");
    info_debug_rr_list(records);

    return 0;
}

/*****************************************************************************
 * Destroy our RR registry.
 *
 * 
 *****************************************************************************/
void info_destroy(void) {
    ll_entry_t * el      = NULL;

    foreach(el,records) {
	dns_rr * rr = (dns_rr *)el->data;
	assert(rr != NULL );		/* FIXME: syslog and exit */
	if( rr->freeFunc != NULL ) {
	    rr->freeFunc(rr);
	} else {
	    free_rr(rr);
	}
    }

    ll_delete(records);
    records = NULL;
}

/*****************************************************************************
 * Init a search state structure.
 *
 *
 *****************************************************************************/
void info_init_search( search_state * state, const char * query, int type ) {
    
    assert(state != NULL);

    state->dname = query;
    state->type  = type;
    state->data  = NULL;
    state->el    = NULL;

}

/*****************************************************************************
 * search for an RR.
 *
 *   The search_state structure should must be filled out by the 
 *   info_init_search() function before calling this function. The 'el' member
 *   in the search stucture is updated to allow enumeration of all matching
 *   records.
 *   
 * Arguments:
 *   state  - state of this search.
 *
 * Note:
 *   A special case is state->dname == NULL. This is used to find all 
 *   resource records we want to be authorative for. These are the  A and AAAA 
 *   records for now.
 *
 * Result:
 *   1 if any record has been found, 0 otherwise. The search structure is 
 *   updated to reflect the position in the list where the record has been 
 *   found.
 *
 *****************************************************************************/
int info_search( search_state * state ) {

    ll_entry_t * startAt = NULL;
    ll_entry_t * el      = NULL;

    if( state->el == NULL ) {
	startAt = ll_first(records);
    } else {
	startAt = ll_next(state->el);
	if( startAt == NULL ) {
	    state->el = NULL;
	    state->data = NULL;
	    return 0;
	}
    }
    
    if( records == NULL ) {
	debug("Records array not initialized\n");
        return 0;
    }

    for( el = startAt ; el != NULL ; el = ll_next(el) ) {
	dns_rr * rr = el->data;

	/*debug("Search %s, have %s type %d\n", state->dname, rr->domain, rr->type ); */

	if( ( (state->type == T_ANY) || (rr->type == state->type) ) && 
	    ( (state->dname == NULL) || (strcmp(state->dname,rr->domain) == 0) ) ) 
	{
	
	    if( (state->dname == NULL) && ! rr->auth ) {
		continue;
	    }
	    
	    state->data = rr;
	    state->el   = el;
	    return 1;
	}
    }

    return 0;

}

/*****************************************************************************
 * Drop a record from our registry.
 *
 * After calling this function, the search_state does not point to a record
 * from the expected result set. The caller must call info_search again
 * to get the next value from the set.
 *
 *****************************************************************************/
void info_drop_record(search_state * s) {

    dns_rr * drop     = NULL;
    ll_entry_t * next = NULL;

    if( s == NULL ) {
	debug("search state is NULL\n");
	return;
    }

    if( s->el == NULL ) {
	debug("search state does not point to a record\n");
	return;
    }

    drop = s->el->data;

    if( (drop == NULL) || (drop->freeFunc == NULL)) {
	debug("invalid record to drop\n");
	return;
    }

    next = ll_next(s->el);
    drop->freeFunc(drop);
    ll_remove(s->el);

    s->el = next;
    if( s->el != NULL ) {
        s->data = (dns_rr *)s->el->data;
    } else {
        s->data = NULL;
    }
}

/*****************************************************************************
 * Callback to decode a single dns record from an dns packet.
 *
 * user_data is a pointer to the linked list where the packet should be 
 * appended.
 *
 * Unknown and malformed RR's are just ignored, so the packet as a whole 
 * would be processed. 
 *
 *****************************************************************************/
static int decode_packet_cb ( 
	      dns_sect section,
              const char * domain,
              u_int16_t type, u_int16_t class, u_int32_t ttl,
              size_t rr_len , const u_char * rr_data,
              void * user_data , 
	      const void * buf_start, const void * buf_end )
{

    decoded_message_t * msg = (decoded_message_t *)user_data;
    dns_rr * result_rr = NULL;
    int auth = 0;

    if( class & 0x8000 ) {
	auth = 1;
	class &= 0x7FFF;
    }

    if( class != 1 ) {
	debug("class not C_IN\n");
	syslog(LOG_WARNING,"dns rr class %d not supported, ignoring record\n", class);
	return 0;
    }

    if( section == IN_QUERY_SECT ) {
	dns_question * q = info_new_question(domain,type,class);
	q->want_unicast = auth;
	if( q != NULL ) {
	    ll_add(msg->questions,q);
	}
        return 0;
    }

    switch( type ) {
	case T_A:
	    if( rr_len == sizeof(struct in_addr) ) {
	      result_rr = newARec( domain, (const struct in_addr *)rr_data );
	    }
	    break;

	case T_AAAA:
	    if( rr_len == sizeof(struct in6_addr) ) {
	      result_rr = newAAAARec( domain, (const struct in6_addr *)rr_data );
	    }
	    break;

	case T_NS:
        case T_MD:
        case T_MF:
        case T_CNAME:
        case T_MB:
        case T_MG:
        case T_MR:
        case T_PTR:
	    {
		char decoded[MAXDNAME + 1];
		ssize_t count = 0;

		count = dn_expand( buf_start, buf_end , rr_data, decoded, MAXDNAME );

		if( count > 0 ) {
		    result_rr = newPtrRec( domain, decoded );
		}
		if( result_rr != NULL ) {
		  result_rr->type = type;
		}
	    }
	    break;

	case T_SOA:
	    break;

	case T_MX:
	    break;

	case T_HINFO:
	    {
		char cpu[MAXDSTRING + 1];
		char os[MAXDSTRING + 1 ];
		const u_char * now = (const u_char *)rr_data;

		memset(cpu,0,sizeof(cpu));
		memset(os,0,sizeof(os));

		if( (const void *)(now + 1 + *now) < buf_end ) {

		    memcpy(cpu, now + 1, *now );
		    now += *now;
		    now += 1;

		    if( (const void*)(now + 1 + *now) < buf_end) {
		        memcpy(os, now + 1, *now );

		        result_rr = newHinfoRec( domain, cpu, os );
		    }
		}
	    }
	    break;
	
	case T_TXT:
	    {
		char string[MAXDSTRING + 1];
		const u_char * now = (const u_char *)rr_data;
		const u_char * end = rr_data + rr_len;

		result_rr = newTxtRec(domain);

		while((now<end) && ((const void*)(now + 1 + *now) < buf_end)) {
		    
		    memset(string,0,sizeof(string));
		    memcpy(string, now + 1, *now);
		    now ++;
		    now += *now ;

		    txtRecAddString(result_rr,string);
		}
	    }
	    break;

	case T_SRV:
	    if( rr_len > 6 ) {

		u_int16_t prio   = 0;
		u_int16_t weight = 0;
		u_int16_t port   = 0;
		char decoded[MAXDNAME + 1];
		ssize_t count = 0;

		const u_char * now = (const u_char *)rr_data;

		GETSHORT(prio,now);
		GETSHORT(weight,now);
		GETSHORT(port,now);

		count = dn_expand( buf_start, buf_end , rr_data + 6, decoded, MAXDNAME );
		if( count >= 0 ) {
		    result_rr = newSrvRec( domain, prio, weight, port, decoded );
		}
	    }
	    break;

	default:
	    debug("unknown RR type %d, can not decode\n", type );
	    break;
    }

    if( result_rr != NULL ) {
	list_t * list = NULL;

	result_rr->ttl  = ttl;
	result_rr->auth = auth;

	switch( section ) {
	    case IN_QUERY_SECT:
		debug("Attempt to process question as answer\n");
		debug("Should have never get to this point !\n");
		break;
	    case IN_ANSWER_SECT:
		list = msg->answers;
		break;
	    case IN_AUTHORITY_SECT:
		list = msg->authority;
		break;
	    case IN_EXTRA_SECT:
		list = msg->additional;
		break;
	    default:
		debug("unknown section\n");
		list = NULL;
	}

	if( list != NULL ) {
	    ll_add(list,result_rr);
	} else {
	    result_rr->freeFunc(result_rr);
	}
    }

    return 0;
}

void info_debug_rr_list( const list_t * list ) {
    ll_entry_t * el;

    foreach(el,list) {
	if( el->data != NULL ) {
	  ((dns_rr *)el->data)->debugFunc((dns_rr *)el->data);
	} else {
	  debug("NULL\n");
	}
    }
}

dns_question * info_new_question(const char * domain, u_int16_t type, u_int16_t class) {

    dns_question * q = malloc(sizeof(*q));
    if( q != NULL ) {
        strncpy(q->query_arg,domain,MAXDNAME+1);
        q->query_type  = type;
        q->query_class = class;
    }

    return q;
}
#ifdef DEBUG
static void debug_question_list( const list_t * list ) {
    ll_entry_t * el = NULL;

    foreach(el,list) {
	if( el->data != NULL ) {
	    dns_question * q = (dns_question *)(el->data);
	    debug("    domain=%s type=%d class=%d\n" , 
		   q->query_arg , q->query_type , q->query_class );
	} else {
	    debug("NULL\n");
	}
    }
}
#else
#define debug_question_list(l)
#endif

void info_debug_message( const decoded_message_t * msg ) {
    debug("Questions:\n");
    debug_question_list(msg->questions);
    debug("Answers:\n");
    info_debug_rr_list(msg->answers);
    debug("Authority:\n");
    info_debug_rr_list(msg->authority);
    debug("Additional:\n");
    info_debug_rr_list(msg->additional);
}

static void free_rr_list( list_t * list ) {
    ll_entry_t * el = NULL;

    foreach(el,list) {
	if( el->data != NULL ) {
	  ((dns_rr *)el->data)->freeFunc(el->data);
	}
    }
    ll_delete(list);
}

static void free_question_list( list_t * list ) {
    ll_entry_t * el = NULL;

    foreach(el,list) {
	if( el->data != NULL ) {
	    free(el->data);
	}
    }
    ll_delete(list);
}

void info_free_decoded_message( decoded_message_t * message ) {

    if( message == NULL ) return;

    if( message->questions != NULL ) {
	free_question_list(message->questions);
    }
    if( message->answers != NULL ) {
	free_rr_list(message->answers);
    }
    if( message->authority != NULL ) {
	free_rr_list(message->authority);
    }
    if( message->additional != NULL ) {
	free_rr_list(message->additional);
    }

    free(message);
}

/*****************************************************************************
 * Decode a dns message into question, answer, authority and additional records.
 *
 *****************************************************************************/
decoded_message_t * info_new_message(void) {

    decoded_message_t * result = NULL;

    debug("alloc decoded_message\n");
    result = malloc( sizeof(*result) );
    if( result == NULL ) { 
        return NULL; 
    }

    memset(result,0,sizeof(*result));

    result->id = 0;
    result->rcode = 0;

    if( (result->questions = ll_new()) == NULL ) {
	info_free_decoded_message(result);
        return NULL; 
    }
    if( (result->answers = ll_new()) == NULL ) {
	info_free_decoded_message(result);
        return NULL; 
    }
    if( (result->authority = ll_new()) == NULL ) {
	info_free_decoded_message(result);
        return NULL; 
    }
    if( (result->additional = ll_new()) == NULL ) {
	info_free_decoded_message(result);
        return NULL; 
    }

    return result;
}

static decoded_message_t * info_decode_message( const u_char * buf, int len ) {
    decoded_message_t * result = info_new_message();
    const HEADER * hdr         = (const HEADER *)buf;

    if( result != NULL ) {
        if( dns_walk_buf( buf, len, decode_packet_cb, result ) < 0 ) {
	    info_free_decoded_message(result);
	    return NULL;
	}
    }

    result->id = hdr->id;

    return result;
}

void info_copy_questions( const decoded_message_t * src, 
                          const decoded_message_t * dst) {

    ll_entry_t * el;
    if( src == NULL ) return;
    if( dst == NULL ) return;

    el = NULL;
    foreach(el,src->questions) {
	dns_question * s = (dns_question *)el->data;
	dns_question * q = info_new_question(s->query_arg,s->query_type,s->query_class);
	if( q != NULL ) {
	    ll_add(dst->questions,q);
	}
    }
}

decoded_message_t * info_decode_packet( struct udp_packet *udp_pkt ) {
    return info_decode_message( udp_pkt->buf,udp_pkt->len );
}

static int info_compare_suffix(const char * suffix, const char * domain) {

    size_t  suflen = strlen(suffix);
    size_t  dlen   = strlen(domain);
    const char *  end    = domain + dlen - suflen;

    if( dlen < suflen ) {
	return 1;
    }

    debug("compare suffix %s with %s\n" , suffix, end );
    if ( strncasecmp( end , suffix, suflen ) == 0 ) {
	return 0;
    }

    return 1;
}

int info_is_local_domain( const char * domain ) {
    int didx = 0;

    for( didx = 0; config.also_local[didx] != NULL; didx ++ ) {
	if( info_compare_suffix(config.also_local[didx],domain) == 0 ) {
	    return 1;
	}
    }
    return 0;
}

