/*
  **
  ** dproxy.h
  **
  ** Part of the drpoxy package by Matthew Pratt. 
  **
  ** Copyright 1999 Matthew Pratt <mattpratt@yahoo.com>
  **
  ** This software is licensed under the terms of the GNU General 
  ** Public License (GPL). Please see the file COPYING for details.
  ** 
  **
*/

#ifndef TMDNS_H
#define TMDNS_H

#include <config.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <errno.h>

#include "dns.h"

#ifndef PORT
#define PORT 5353
#endif

#ifndef CONFIG_FILE_DEFAULT 
#define CONFIG_FILE_DEFAULT "/etc/tmdns.conf"
#endif
#ifndef DEBUG_FILE_DEFAULT 
#define DEBUG_FILE_DEFAULT "/var/log/tmdns.debug.log"
#endif
#ifndef PID_FILE_DEFAULT 
#define PID_FILE_DEFAULT "/var/run/tmdns.pid"
#endif

#define MAX_NS MAXNS  /* this is from resolv.h */
#ifndef MAX_IF
#define MAX_IF 16
#endif
#ifndef MAX_NETWORKS
#define MAX_NETWORKS 16
#endif

#ifndef NUM_PROBES
#define NUM_PROBES 3
#endif

#ifndef NUM_ANNOUNCEMENTS
#define NUM_ANNOUNCEMENTS 3
#endif

#endif
