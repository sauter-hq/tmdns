/*
 * conf.h - config handling routines fro tmdns
 *
 * Part of the tmdns package by Andreas Hofmeister.
 *
 * Copyright 2000 Jeroen Vreeken (pe1rxq@amsat.nl)
 * Copyright 2003-2004 Andreas Hofmeister <andi@solutions.pyrmaid,de> 
 *
 * This software is licensed under the terms of the GNU General
 * Public License (GPL). Please see the file COPYING for details.
 *
 *----------------------------------------------------------------------------
 *
 * How to add a config option :
 *   1. add a #define for a default value in 'config.h'. 
 *      
 *   2. add a field to 'struct config' in 'config.h'
 *
 *   3. add a default value to initialisation of 
 *      'config_defaults' below.
 *      
 *   4. add a entry to the config_params array below, if your
 *      option should be configurable by the config file.
 */ 

#include "config.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "conf.h"
#include "debug.h"

static int initialized = 0;

struct config config;  
static struct config config_defaults = {
  port:           5353,
  daemon_mode:    1 ,
  username:      "daemon" ,
  hostname:       "",
  config_file:    CONFIG_FILE_DEFAULT, 
  debug_file:     DEBUG_FILE_DEFAULT, 
  service_file:   SERVICE_FILE_DEFAULT, 
  ex_interfaces:  { NULL } ,
  default_ttl:    120 * 60 ,              /* TTL for local entries */
  default_unicast_ttl:    10 ,            /* TTL for resp. to unicast */
  pid_file:       PID_FILE_DEFAULT ,
  dns_bridge:     1,                      /* do not bridge dns queries */
  dns_port:       53,			  /* port to listen for unicast queries */
  gather_delay:   2,			  /* how long to delay answers */
  allow_nonlocal: 0,			  /* forward no-local unicast queries
					     to the mDNS group */ 
  also_local:     {
			".local" ,
			".254.169.in-addr.arpa" ,
			".0.8.e.f.ip6.arpa" ,
			NULL
		  },

  dynamic_service_file:   DYNAMIC_SERVICE_FILE_DEFAULT, 
};

static void conf_cmdparse(const char *cmd, const char *arg1);
static void copy_bool(const char *, void *);
static void print_bool(FILE * fd , const void * value ) ;
static void init_int(const char *, void *);
static void copy_int(const char *, void *);
static void print_int(FILE * fd , const void * value ) ;
static void copy_string(const char *, void *);
static void print_string(FILE * fd , const void * value ) ;

static void init_string_array(const char *, void *);
static void copy_string_array(const char *, char **, int);
static void print_string_array(FILE * fd , const void * value ) ;

static void copy_interfaces(const char *str, void * val) {
    copy_string_array(str,(char **)val, MAX_IF );
}

static void copy_also_local(const char *str, void * val) {
    copy_string_array(str,(char **)val, MAX_ALSO_LOCAL );
}

/* dummy functions */
static void copy_dummy(const char * str, void * val) {}
static void print_dummy(FILE * fd, const void * value ) {}


static config_param config_params[] = {
   { 
     "hostname" ,
     "# If you leave this empty, tmdns will announce the name from the system config\n"
     "# usually configured in '/etc/hostname'. You can use this parameter to change\n"
     "# the advertised name.\n"
     "# Note that only the part up to the first dot (if any) is used as hostname.\n"
     "#.\n",
     config.hostname,
     config_defaults.hostname,
     copy_string ,
     copy_string ,
     print_string
    } ,
    { 
     "username" ,
     "# if not empty, tmdns will run as this user.\n",
     config.username,
     config_defaults.username,
     copy_string ,
     copy_string ,
     print_string
   } ,
   { 
     "service_file" ,
     "# You can advertise services running on your machine in a static service\n" 
     "# definition file. This will allow other machines on your network to discover\n" 
     "# and use those services.\n" 
     "# \n" 
     "# Some distributions may support automatic service registration in the services\n" 
     "# 'init' scripts, in which case you can leave this setting (and the file) alone.\n" 
     "# \n" ,
     config.service_file,
     config_defaults.service_file,
     copy_string ,
     copy_string ,
     print_string
   } ,
   { 
     "pid_file" ,
     "# tmdns will save its pid in that file\n" ,
     config.pid_file,
     config_defaults.pid_file,
     copy_string ,
     copy_string ,
     print_string
  } ,
  { 
     "debug_file" ,
     "# Debug info log file\n" 
     "# If you want tmdns to log debug info, specify a file here.\n",
     config.debug_file,
     config_defaults.debug_file,
     copy_string ,
     copy_string ,
     print_string
   } ,
   { 
     "default_ttl" ,
     "# The time-to-live (in seconds) when we respond to multicast queries.\n"
     "# Mutlicast DNS clients will regard data we send as valid for this time.\n",
     &config.default_ttl,
     &config_defaults.default_ttl,
     init_int,
     copy_int ,
     print_int
   } ,
   { 
     "unicast_ttl" ,
     "# The time-to-live (in seconds) when we send data via the dns bridge.\n"
     "# We may respond to a caching dns server, so we should force it not \n"
     "# to cache our responses for too much time.\n" ,
     &config.default_unicast_ttl,
     &config_defaults.default_unicast_ttl,
     init_int,
     copy_int ,
     print_int
   } ,
   { 
     "dns_bridge" ,
     "# When set to true, dns unicast queries from the localhost will be.\n"
     "# forwarded as multicast queries to the local net. Multiple answers\n"
     "# will be gathered and passed back to the calling process as one\n"
     "# unicast dns answer.\n" ,
     &config.dns_bridge,
     &config_defaults.dns_bridge,
     init_int,
     copy_bool,
     print_bool
   } ,
   { 
     "allow_nonlocal" ,
     "# When set to true, dns unicast queries for names and addresses that\n"
     "# are not in the \".local.\" zone are forwarded to the multicast group.\n"
     "# This is insecure and also would require a unicast DNS server that \n"
     "# can answer such a question.\n"
     "# When set to \"no\", such a query will be answered with \"SERVFAIL\"\n" 
     "# what in turn should make your resolver ask the next DNS server in\n"
     "# your resolver conf.\n" ,
     &config.allow_nonlocal,
     &config_defaults.allow_nonlocal,
     init_int,
     copy_bool,
     print_bool
   } ,
   { 
     "local_domains" ,
     "# If you have set \"allow_nonlocal\" to \"no\", you may want additional names\n"
     "# to be queried by multicast dns, maybe because you also use one of the private\n"
     "# network address ranges in your network. \n"
     "# With this parameter, you can specify which domain suffixes also should be\n"
     "# searched by mDNS requests.\n"
     "# This parameter only has some effect when \"dns_bridge\" is set to \"yes\"\n"
     "# and \"allow_nonlocal\" is set to \"no\".\n"
     "# \n"
     "# Example: \n"
     "#   To allow to lookup the 192.168.9.0/24 network, add \"9.168.192.in-addr.arpa\"\n"
     "#   to the list.\n"
     "# \n"
     "# Note that you can not use both, unicast AND multicast DNS for the same domain.\n"
     "# Do not use this parameter if there is a real DNS for a domain and that nameserver\n"
     "# does not support multicast dns.\n"
     "# \n" ,
     config.also_local,
     config_defaults.also_local,
     init_string_array,
     copy_also_local,
     print_string_array
   } ,
   { 
     "dns_port" ,
     "# When dns_bridge above is enabled, on which port should tmdns listen\n"
     "# for unicast dns messages.\n" 
     "# You may want to change this if you have another dns server running\n"
     "# on your machine and want to forward the \".local.\" domain to tmdns.\n",
     &config.dns_port,
     &config_defaults.dns_port,
     init_int,
     copy_int ,
     print_int
   } ,
   { 
     "gather_delay" ,
     "# number of seconds to delay unicast dns answers to allow more answers\n" 
     "# to be gatered. Do not set this to something more then about 4 sec.\n"
     "# Only relevant if you also enabled dns_bridge above.\n",
     &config.gather_delay,
     &config_defaults.gather_delay,
     init_int,
     copy_int ,
     print_int
   } ,
   { 
     "dynamic_service_file" ,
     "# In addition to the above 'service_file', there is a second file that will\n" 
     "# be modified by the 'register-service' utility. You should not change this\n" 
     "# setting until you know what you're doing. If you like to change it here, \n" 
     "# anyway, you also need to modify the 'register-serviceÄ script to\n" 
     "# reflect the new path.\n" 
     "# \n" 
     "# You have been warned !\n" 
     "# \n" 
     "# \n" ,
     config.dynamic_service_file,
     config_defaults.dynamic_service_file,
     copy_string ,
     copy_string ,
     print_string
   } ,
  { 
     "exclude_interfaces" ,
     "# By default, tmdns accepts and sends multicast DNS packets on all network\n" 
     "# interfaces.\n" 
     "# \n" 
     "# It may be sensible to exclude some interfaces, for example the external\n" 
     "# interface of an internet router.\n" 
     "# \n" 
     "# Remember, that mDNS may give away some usefull informations to someone\n" 
     "# who want to attack your system.\n" 
     "# \n" ,
     config.ex_interfaces ,
     config_defaults.ex_interfaces,
     copy_interfaces,
     copy_interfaces,
     print_string_array
   } ,
 
  /*
   * end-of-array indicator, must be present and everything below
   * this line will be ignored.
   */
  { NULL , NULL , NULL, NULL, NULL , NULL, NULL }
};

/**************************************************************************
    Main function, called from tmdns.c
*/
int conf_load (const char *conf_file)
{
  FILE *fp;
  char line[1024], *cmd = NULL, *arg1 = NULL;
  
  conf_defaults();	/* load default settings first */
  
  fp = fopen (conf_file, "r");
  if (!fp) {	/* specified file does not exist... try default file */
      fp = fopen (config.config_file, "r");
      if (!fp) {	/* there is no config file.... use defaults */
          perror("no config file");
	  return 0;
      }
  } else if (config.config_file != conf_file) {
      strncpy(config.config_file, conf_file, sizeof(config.config_file));
      config.config_file[sizeof(config.config_file)-1] = 0;
  }
  while (fgets(line, 1024 , fp)) {
	 if (!(line[0]=='#')) {	/* skip lines with comment */
		size_t idx = 0;
		char * tmp = 0;

		line[strlen(line) - 1] = 0; /* kill '\n' */
		cmd = strtok( line, "=" );
		arg1 = strtok( NULL, "=");

		if(arg1 == NULL) continue;

		/* remove trailing whitespace from cmd */
		for( tmp = arg1 - 1; tmp > line; tmp -- ) {
		    if( (*tmp == ' ')  || ( *tmp == '\t' ) ) {
			*tmp = 0;
		    }
		}

		/* remove leading whitespaces */
		while( (*arg1 == ' ') || (*arg1 == '\t' ) ) 
		    arg1 ++;

		/* remove trailing whitespaces */
		for(idx = strlen(arg1) - 1 ; idx > 0; idx -- ) {
		    if( (arg1[idx] == ' ')  || ( arg1[idx] == '\t' ) ) {
			arg1[idx] = 0;
		    } else {
			break;
		    }
		}

		conf_cmdparse(cmd, arg1);
	 }
  }
  fclose(fp);
  return 0;
}
/*****************************************************************************/
static void conf_cmdparse(const char *cmd, const char *arg1)
{
  int i = 0;

  if( !cmd )return;
  if( !arg1 )return;
  
  while( config_params[i].param_name != NULL ) {
	if(!strncasecmp(cmd, config_params[i].param_name , 
			CONF_PATH_LEN + 50)) 
	{
	    if( config_params[i].copy != NULL ) {
	        config_params[i].copy( arg1, config_params[i].conf_value );
	    }
	    return;
	}
	i++;
  }

  fprintf( stderr, "Unknown config option: \"%s\"\n", cmd ); 
}

/************************************************************************
 * copy functions 
 *
 *   copy_bool   - convert a bool representation to int
 *   copy_int    - convert a string to int
 *   copy_string - just a string copy
 *   
 * @param str -   A char *, pointing to a string representation of the
 *                value.
 * @param value - points to the place where to store the value. 
************************************************************************/
static void copy_bool (const char *str, void * val)
{
	if ( !strcmp(str, "1") || 
	     !strcasecmp(str, "yes") || 
	     !strcasecmp(str,"on")) 
	{
		*((int *)val) = 1;
	} else {
		*((int *)val) = 0;
	}
}
static void copy_int(const char *str, void * val) {
	*((int *)val) = atoi(str);
}
static void copy_string(const char *str, void * val) {
	strncpy((char *)val, str , CONF_PATH_LEN );
}
static void init_int(const char *str, void * val) {
	*((int *)val) = *((const int *)str);
}


/************************************************************************
 * print functions  -
 *
 * Take a config value, convert it to human readable form 
 * and print it out.
 *
 *   print_bool   -  print a boolean value
 *   print_int    -  print a string
 *   print_string - print a string value
 *   
 * @param fd - File descriptor for output.
 * @param value - pointer to the config value.
************************************************************************/
static void print_bool(FILE * fd , const void * value ) {
  if( *((const int *)value) ) {
    fprintf(fd,"yes");
  } else {
    fprintf(fd,"no");
  }
}
static void print_int(FILE * fd , const void * value ) {
    fprintf(fd,"%d", *((const int *) value) );
}
static void print_string(FILE * fd, const void * value) {
    fprintf(fd,"%s", ((const char *)value) );
}

/************************************************************************
 * string array functions.
 * 
 * Memory for string arrays will be allocated dynamicaly. Do not
 * change the values in place !
 * 
 ***********************************************************************/
static void init_string_array(const char *str, void * val) {

    int idx = 0;
    while( ((const char **)str)[idx] != NULL ) {

	/* free old value */
	if( (((char **)val)[idx]) != NULL )
		free( ((char **)val)[idx] );

	((char **)val)[idx] = strdup(((const char **)str)[idx]);  
        idx ++;
    }

    /* place a end-of-array marker at the end. */
    if( (((char **)val)[idx]) != NULL ) {
	free( ((char **)val)[idx] );
	((char **)val)[idx] = NULL;
    }
}

/**
 * we can not give additional arguments to the initializer functions
 * i.e we can not pass an array size to it. You need to write a wrapper
 * for your array.
 */
static void copy_string_array(const char *str, char ** val, int size ) {
    char * now = NULL;
    char * copy= NULL;
    char * tok = NULL;
    int idx = 0;

    copy = strdup(str);
    now = copy;

    /* de-allocate old strings. */
    for( idx = 0; idx < size; idx ++ ) {
	if( val[idx] != NULL ) {
	    free(val[idx]);
	    val[idx] = NULL;
	}
    }

    idx = 0;
    /* break the string into words */
    while( (tok = strtok(now," \t")) != NULL ) {
	now = NULL;
	if( *tok == 0 ) continue;
	val[idx] = strdup(tok);
	idx ++;
	if( idx >= size ) break;
    }

    free(copy);
}

static void print_string_array(FILE * fd, const void * value) {
    int idx = 0;
    while( ((const char **)value)[idx] != NULL ) {
        fprintf(fd," %s", ((const char **)value)[idx] );
        idx ++;
    }
}

/************************************************************************
 * print the configuration on stdout.
************************************************************************/
void conf_print(void) {
   int i = 0;
   FILE * fd;

   fd = stdout;
   fprintf(fd,"#\n");
   fprintf(fd,"# config for %s version %s\n", PACKAGE, VERSION);
   fprintf(fd,"#\n");
   while( config_params[i].param_name != NULL ) {
     if( ((void *)config_params[i].print == NULL) ||
	 ((const void *)config_params[i].print == (const void *)print_dummy)) 
      {
	fprintf(fd, "%s", config_params[i].comment);
      } else {
	fprintf(fd,"# param %s \n" , config_params[i].param_name );
	fprintf(fd, "#\n");
	fprintf(fd, "%s", config_params[i].comment);
	fprintf(fd, "#\n");
	fprintf(fd, "# Default : " );
	config_params[i].print(fd,config_params[i].def_value );
	fprintf(fd, "\n#\n");
	fprintf(fd, "%s = " , config_params[i].param_name );
	config_params[i].print(fd,config_params[i].conf_value );
	fprintf(fd, "\n\n");
      }
	
	i++;
   }
}
/************************************************************************
    Load default settings first
*/
void conf_defaults (void)
{
  int i = 0;

  if( !initialized ) {
    memset(&config,0,sizeof(config));
    initialized = 1;
  }

  while( config_params[i].param_name != NULL ) {
     if( config_params[i].init != NULL ) {
	config_params[i].init( config_params[i].def_value,
			       config_params[i].conf_value );
     }
     i++;
  }

  config.daemon_mode = 1;
  config.debug_file[0] = 0;
  return;
}

/*****************************************************************************
 * check if the given interface is to be excluded from service.
 *
 * Arguments :
 *   ifname : interface to check.
 *
 * Returns:
 *   1 if the interface appears on the config exclude list,
 *   0 otherwise.
 *
 ****************************************************************************/
int is_excluded_interface( const char * ifname ) {

  char ** cfname = NULL;

  for( cfname = config.ex_interfaces; *cfname != NULL; cfname ++ ) {
    if( strcmp( *cfname , ifname ) == 0 ) {
      return 1;
    }
  }

  return 0;
}

