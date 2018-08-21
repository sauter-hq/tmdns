/*
 * conf.h - function prototypes for the config handling routines
 *
 * Part of the tmdns package by Andreas Hofmeister.
 *
 * Copyright 2000 Jeroen Vreeken (pe1rxq@amsat.nl)
 * Copyright 2003-2004 Andreas Hofmeister <andi@solutions.pyrmaid,de> 
 *
 * This software is licensed under the terms of the GNU General
 * Public License (GPL). Please see the file COPYING for details.
 *
 *
*/
#ifndef CONF_H 
#define CONF_H 1

#include "config.h"

#include "tmdns.h"

#define CONF_PATH_LEN 256

#define MAX_ALSO_LOCAL 32

/* 
    more parameters may be added later.
 */
struct config {
  int  port;
  int  daemon_mode;
  char service_file[CONF_PATH_LEN];
  char config_file[CONF_PATH_LEN];
  char debug_file[CONF_PATH_LEN];
  char * ex_interfaces[MAX_IF + 1]; 
  /* ttl stuff */
  u_int32_t default_ttl;
  u_int32_t default_unicast_ttl;
  char username[CONF_PATH_LEN];
  char hostname[CONF_PATH_LEN];
  char pid_file[CONF_PATH_LEN] ;
  int  dns_bridge;
  int  dns_port;
  int  gather_delay;
  int  allow_nonlocal;
  const char * also_local[MAX_ALSO_LOCAL + 1];
  char dynamic_service_file[CONF_PATH_LEN];
};

/** 
 * typedef for a param copy function. 
 */
typedef void (* conf_copy_func)(const char *, void *) ;
typedef void (* conf_print_func)(FILE * fp, const void *);

/**
 * description for parameters in the config file
 */
typedef struct {
  const char * param_name;         /* name for this parameter             */
  const char * comment;            /* a comment for this parameter        */
  void * conf_value;         /* pointer to a field in struct config */
  void * def_value;
  conf_copy_func  init;      /* a function to set the value in 'config'*/
  conf_copy_func  copy;      /* a function to set the value in 'config'*/
  conf_print_func print;     /* a function to print the value from 'config'*/
} config_param; 


extern struct config config;                      
extern int  conf_load (const char *conf_file);
extern void conf_defaults (void);

extern void conf_print(void);

extern int is_excluded_interface( const char * ifname );

#endif /* CONF_H */
