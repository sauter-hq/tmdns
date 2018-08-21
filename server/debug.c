/*
 *
 * debug.c 
 *
 * Part of the tmdns package by Andreas Hofmeister. 
 *
 * Copyright 1999 Matthew Pratt <mattpratt@yahoo.com>
 * Copyright 2003/2004 Andreas Hofmeister <andi.solutions.pyramid.de>
 *
 * This software is licensed under the terms of the GNU General 
 * Public License (GPL). Please see the file COPYING for details.
 * 
 *
*/
#include <config.h>
#include <string.h>

#include <stdio.h>
#include <errno.h>
#include "conf.h"
#include "debug.h"

#ifdef DEBUG

#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>


#undef debug

static FILE * open_log(void) {
     if( config.debug_file[0] ){
	 FILE *fp;
	 fp = fopen( config.debug_file, "a");
	 if(!fp){
		syslog( LOG_ERR, "could not open log file %m" );
		return NULL;
	 }
	 return fp;
    }

    return NULL;
}
/*****************************************************************************
 * same as perror but writes to debug output.
 ****************************************************************************/
void f_debug_perror( const char * msg ) {
	f_debug( "%s : %s\n" , msg , debug_errmsg(errno) );
}
/*****************************************************************************
 * same as printf but writes to debug output.
 ****************************************************************************/
void f_debug(const char *fmt, ...)
{
 	FILE * fp;
#define MAX_MESG_LEN 1024

	va_list args;
	char text[ MAX_MESG_LEN ];
	 
	sprintf( text, "[ %d ]: ", getpid());
	va_start (args, fmt);
	vsnprintf( &text[strlen(text)], MAX_MESG_LEN - strlen(text), fmt, args);
	va_end (args);
	 
     if((fp = open_log()) != NULL){
	 fprintf( fp, "%s", text);
	 fclose(fp);
     }

    /** if not in daemon-mode stderr was not closed, use it. */
    if( ! config.daemon_mode ) {
	 fprintf( stderr, "%s", text);
    }

}
/*****************************************************************************
 * dump a DNS packet to the debug output.
 * 
 * @param  msg     extra message for this packet.
 * @param  dnsdata pointer to a dns packet.
 ****************************************************************************/
void f_debug_dns(const char * msg , const void * dnsdata) {

    FILE * fp;
    if((fp = open_log()) != NULL){
	 fprintf( fp, "[ %d ]: %s :\n", getpid() , msg );
 	 __fp_query( dnsdata , fp);
	 fclose(fp);
    }

    if( config.daemon_mode == 0 ) {
	 fprintf( stderr, "[ %d ]: %s :\n", getpid() , msg );
	__fp_query( dnsdata, stderr );
    }
	  
}
#endif /* not def DEBUG */
/*****************************************************************************
 * return the error message for the error number 
 ****************************************************************************/
const char * debug_errmsg( int _errno ) {
#ifdef HAVE_STRERROR
    return strerror(_errno);
#else
    if( (_errno < sys_nerr) && (_errno >= 0) ) 
	return sys_errlist[_errno];
    return "unknown error";
#endif
}

/*****************************************************************************
 * Just like debug_perror and perror but
 * a) writes to the debug log
 * b) syslogs the error with LOG_WARNING
 ****************************************************************************/
void log_perror( const char * msg ) {
    int _errno = errno;
#ifdef DEBUG
    f_debug( "%s : %s\n" , msg , debug_errmsg(_errno) );
#endif
    syslog( LOG_WARNING, "%s : %s\n" , msg , debug_errmsg(_errno) );
}

