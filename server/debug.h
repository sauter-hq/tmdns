/*
 *
 * debug.c 
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

#ifndef DEBUG_H
#define DEBUG_H 1

#include <config.h>
#include <syslog.h>


#ifdef DEBUG

#define debug_perror(x) f_debug_perror(x)
#define debug f_debug
#define debug_dns(c,v) f_debug_dns((c),(v))
#define debug_cache_data(p) f_debug_cache_data(p)

extern void f_debug_perror(const char *);
extern void f_debug(const char * fmt, ... )
#ifdef __GNUC__
        __attribute__ ((format (printf, 1, 2)));
#else
 ;
#endif

extern void f_debug_dns(const char * , const void *);

#else

#define debug_perror(x)
#define debug(s...)
#define debug_dns(c,v)
#define debug_cache_data(p)
#endif

extern const char * debug_errmsg(int);
extern void log_perror( const char * msg );

#endif /* DEBUG_H */

