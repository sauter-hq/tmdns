
#include "config.h"

#include "tmdns.h"
#include "conf.h"
#include "serv_udp.h"
#include "debug.h"
#include "dns.h"
#include "info.h"

#include "llist.h"

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <pwd.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>

#include <assert.h>

#ifdef WITH_NETLINK
#include "netlink_glue.h"
#endif

/*****************************************************************************
 * Global variables and prototypes.
 *
 *****************************************************************************/

static int  handle_unicast_query(int sock, struct udp_packet * udp_pkt);
static int  handle_mcast_query( struct udp_packet *udp_pkt );
static void handle_mcast_reply(struct udp_packet * udp_pkt);

static int handle_bridge_query( int sock,  struct udp_packet *udp_pkt );
static int handle_timeout(void);

static int announce(void);
static int goodbye(void);
static int probe(void);

static volatile int go_down = 0;
static volatile int do_config = 0;

/* a list of domain name suffixes that may be queried per multicast 
static const char * dot_local_domains[] = {
    ".local" ,
    ".254.169.in-addr.arpa" ,
    "0.8.e.f.ip6.arpa" ,
    NULL
}; */

/* list of queries to answer. */
static list_t * query_list = NULL;

/*****************************************************************************
 * Signal handlers
 *
 *****************************************************************************/
static void sig_hup (int signo)
{
  signal(SIGHUP, sig_hup); /* set this for the next sighup */
  /* conf_load (config.config_file); */
  do_config = 1;
}

static void sig_term (int signo) {
  debug("signal %d, going down ...\n", signo);
  go_down = 1;
}

/*****************************************************************************
 * print usage informations to stderr.
 * 
 *****************************************************************************/
static void usage(const char * program , const char * message ) {
  fprintf(stderr,"%s\n" , message );
  fprintf(stderr,"%s ver. %s\n" , PACKAGE , VERSION );
  fprintf(stderr,"usage : %s [-c <config-file>] [-bdhPv] [-p <port>\n",program );
  fprintf(stderr,"\t-b \tdisable dns bridge mode for local queries\n");
  fprintf(stderr,"\t-c <config-file>\tread configuration from <config-file>\n");
  fprintf(stderr,"\t-d \t\tturn on debug (=non-daemon) mode.\n");
  fprintf(stderr,"\t-h \t\tthis message.\n");
  fprintf(stderr,"\t-p <port>\tlisten on port <port>.\n");
  fprintf(stderr,"\t-P \t\tprint configuration on stdout and exit.\n");
  fprintf(stderr,"\t-v \t\tprint version info on stderr and exit.\n");
}

/*****************************************************************************
 * get commandline options.
 * 
 * @return 0 on success, -1 on error, -2 if the progam should be terminated
 * with return code 0.
 *
 *****************************************************************************/
static int get_options( int argc, char * const argv[] ) {

  int c = 0;
  int dns_bridge = 0;
  int not_daemon = 0;
  int want_printout = 0;
  int want_version  = 0;
  int debug_port = 0;
  const char * progname = argv[0];
  const char * confname = NULL;

  conf_defaults();

  while( (c = getopt( argc, argv, "bc:dhp:Pv")) != EOF ) {
    switch(c) {
	case 'b':
		dns_bridge = 1;
		break;
	case 'c':
		confname = optarg;
		break;
	case 'd':
		not_daemon = 1;
		break;
	case 'h':
		usage(progname,"");
		return -2;
	case 'p':
		debug_port = atoi(optarg);
		break;
	case 'P':
		want_printout = 1;
		break;
	case 'v':
		want_version = 1;
		break;
	default:
		usage(progname,"");
		return -1;
    }
  }

  if( confname == NULL ) confname = CONFIG_FILE_DEFAULT;
  conf_load(confname);

  if( dns_bridge ) {
	config.dns_bridge = 0 ;
  }
  
  /** unset daemon-mode if -d was given. */
  if( not_daemon ) {
	config.daemon_mode = 0;
  } else {
	config.daemon_mode = 1;
  }

  if( debug_port > 0 ) {
	config.port = debug_port;
  } else {
	config.port = PORT;
  }

  if( want_printout ) {
	conf_print();
	return -2;
  }

  if( want_version ) {
	fprintf(stderr,"this is tmdns %s\n", VERSION );
#ifdef DEBUG
	fprintf(stderr,"    debug support is enabled\n");
	fprintf(stderr,"    default debug log is %s\n", DEBUG_FILE_DEFAULT );
#else
	fprintf(stderr,"    debug support is disabled\n");
#endif
	fprintf(stderr,"    default config file is %s\n", CONFIG_FILE_DEFAULT );
	return -2;
  };

  return 0;

}

/*****************************************************************************
 * change userid.
 *
 * Beside setting the uid of this process, we also change the owner of 
 * log- and pidfiles to allow writing when we are no longer root.
 * 
 *****************************************************************************/
static void change_id(void) {

    struct passwd * pw = NULL;

    if( config.username[0] == 0 ) {
	debug("no username given\n");
	syslog(LOG_NOTICE,"no username given in config"); 
	return;
    }

    pw = getpwnam( config.username );
    if( pw == NULL ) {
	debug("no user named %s\n", config.username );
	syslog(LOG_NOTICE,"no user %s found", config.username ); 
	return;
    }

    if( pw->pw_uid == 0 ) {
	debug("configured to run as root\n");
	syslog(LOG_INFO, "configured to run as root");
    }

    /* change ownership of the pid file so we can unlink it later */
    if( config.daemon_mode && (config.pid_file[0] != 0) ) {
	debug("set ownership of the pid file %s", config.pid_file );
	chown( config.pid_file , pw->pw_uid, pw->pw_gid );
    }

    /* change ownership of the log file */
    if( config.debug_file[0] != 0) {
	debug("set ownership of the debug file %s", config.debug_file );
	chown( config.debug_file , pw->pw_uid, pw->pw_gid );
    }

    debug("drop privileges: new uid = %d, new gid = %d\n",
	  pw->pw_uid, pw->pw_gid);

    setgid(pw->pw_gid);
    setgroups( 0, NULL );
    setuid(pw->pw_uid);
    return;
}

/*****************************************************************************/
int main(int argc, char ** argv ) {

  /* sockets to listen on. */
  int * sockfds = NULL;
  int usedifs = 0;

  /* count this down to check when we have sent all the probes that we should 
     have */
  int probing    = NUM_PROBES;	
  int announces  = NUM_ANNOUNCEMENTS;	

  /* when to answer the next outstanding answer */
  int next_outstanding_answer = 0;

  int i = 0;

  fd_set readfds ;

  int numread;
  struct udp_packet pkt;
  int optres = 0;

  memset( &pkt , 0, sizeof(pkt) );

  /* get commandline options, load config if needed. */
  if( (optres = get_options( argc, argv )) < 0 ) {
	if(optres == -2) exit(0);
  	exit(1);
  }

  openlog("tmdns", LOG_PID , LOG_DAEMON );

  /* initialize the RRs to announce */
  if (info_init() < 0)
      exit(1);

  debug("going to open sockets ...\n");
  usedifs = udp_open_sockets( &sockfds );

  if( usedifs < 1 ) {
	syslog(LOG_ERR, "no sockets to listen on.");
	debug("Sorry, no sockets to listen on.\n" );
	exit(2);
  }

  debug("have %d sockets\n", usedifs );

  /* initialize query backlog */
  query_list = ll_new();

  if (config.daemon_mode) {

    debug("running in daemon mode\n");

    /* Standard fork and background code */
    switch (fork()) {
	 case -1:	/* Oh shit, something went wrong */
		syslog(LOG_ERR, "Can not fork into background.");
		debug_perror("fork");
		exit(-1);
	 case 0:	/* Child: close off stdout, stdin and stderr */
		close(0);
		close(1);
		close(2);
		break;
	 default:	/* Parent: Just exit */
		exit(0);
    }

    /* create pid file */
  
    int pidfd;
    FILE * pidfp = NULL;

    pidfd = open(config.pid_file, O_EXCL|O_CREAT|O_WRONLY,
         S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (pidfd >= 0) 
        pidfp = fdopen( pidfd , "w" );
    
    if (pidfp == NULL) {
	syslog(LOG_ERR,"can't open pid file %s : %s\n",
		config.pid_file , debug_errmsg(errno) );
	debug("can not open pid file %s : %s\n",
		config.pid_file , debug_errmsg(errno) );

        // We must exit or the init scripts will not be able to
        // find us later.
        exit(1); 
    } else {
	 fprintf(pidfp,"%d\n", getpid());
         fclose(pidfp);
    }
  } else {
    /*
     * running in debug mode: check if there is a pidfile, 
     * exit if so
     */
    struct stat statbuf;

    debug("running in debug mode\n");

    if( (stat( config.pid_file , &statbuf )) == 0 ) {
	syslog(LOG_ERR,"pid file %s exists in debug mode\n", config.pid_file );
	debug("Another copy seems to be running - pid file %s exists\n", config.pid_file );
	udp_close_sockets();
	exit(1);
    }
  }

  /* drop su privilegs */
  setsid();
  change_id();

  signal(SIGHUP, sig_hup);
  signal(SIGTERM, sig_term);
  signal(SIGQUIT, sig_term);
  signal(SIGINT, sig_term);

  syslog(LOG_INFO,"enter main loop");


  while(go_down != 1){
    int numready = 0;
    int maxfd = 0;
    struct timeval tv;

#ifdef WITH_NETLINK
    if( network_changed() ) {
	debug("Network configuraton changed\n");

	/* do what needs to be done ... */
	if( getuid() == 0 ) {
	    debug("going to re-open sockets ...\n");
	    udp_close_sockets();
	    usedifs = udp_open_sockets( &sockfds );

	    if( usedifs < 1 ) {
		syslog(LOG_ERR, "no sockets to listen on.");
		debug("Sorry, no sockets to listen on.\n" );
		exit(2);
	    }

	    debug("have %d sockets\n", usedifs );

	} else {
	    debug("would re-open sockets but I'm not running as root\n");
	    syslog(LOG_NOTICE,"would re-open sockets but I'm not running as root\n");
	}

	/* tell other mcast clients that we give up the claimed names */
  	goodbye();

	/* re-initialize our registry */
	info_destroy();
	info_init();

	/* we are back in probing mode */
	probing    = NUM_PROBES;	
	announces  = NUM_ANNOUNCEMENTS;	

	continue;
    }
#endif

    FD_ZERO(&readfds);

    for( i = 0; i < usedifs; i ++ ) {
	if( sockfds[i] < 0 ) continue;
     	FD_SET( sockfds[i] , &readfds);
	if( maxfd < sockfds[i] ) maxfd = sockfds[i] ;
    }

    if( probing >= 0 ) {
      tv.tv_usec = 250000;
      tv.tv_sec  = 0;
    } else {
      tv.tv_usec = 0;
      tv.tv_sec  = 1;
    }

    //debug("select , timeout in %d.%6.6d sec.\n", tv.tv_sec, tv.tv_usec );
    numready = select( maxfd+1 , &readfds , NULL, NULL , &tv );

    if( numready <= 0 ) {
	
	if( do_config ) {
	    /*
	     * do_config would be set from the signal handler.
	     */
  	    conf_load (config.config_file);
	    info_destroy();
	    if (info_init() < 0) {
                unlink(config.pid_file);
                exit(1);
            }
	    do_config = 0;
  	    probing   = NUM_PROBES;	
  	    announces = NUM_ANNOUNCEMENTS;	
	    config.daemon_mode = 0;
	}

	if( numready != 0 ) {
#ifdef DEBUG
	    if( errno != EINTR )
	    	debug_perror("error on select !");
#endif
	    continue;
	}

	if( (probing < 0) && (announces > 0) ) {
	    announce();
	    announces --;
	}

	if( probing == 0 ) {
	    /*
	     * this is the first timeout after we have sent our last
	     * probe. Set probing to -1 to start normal
	     * operation.
	     */
	    announce();
	    announces --;
	    probing = -1;
	}

	if( probing > 0 ) {
	    /*
	     * still in probing mode - send another probe 
	     */
	    probe();
	    probing --;
	}

	if( ll_first(query_list) != NULL ) {
	    /*
	     * Check outstanding queries that should be answered now.
	     */
	     debug("handle outstanding queries ...\n");
	     next_outstanding_answer = handle_timeout();
	}

    } else {
	/* got some data ... */
 	for( i = 0; i < usedifs; i ++ ) {
  
	    int sockfd = -1;

	    debug("check socket idx %d, fd=%d\n", i , sockfds[i] );

	    if( sockfds[i] < 0 ) continue;
	    /* check if there is something to read */
	    if( ! FD_ISSET( sockfds[i] , &readfds) ) 
		continue;
	
	    sockfd = sockfds[i] ;

	    /* get the packet from the socket. */
  	    memset( &pkt , 0, sizeof(pkt) );
	    numread = udp_packet_read( sockfd, &pkt );	 
	    if( numread < 0 ) {
	        debug("no data ...\n");
	        continue;
	    }


	    debug("Message from %s , size %d bytes\n" , 
		      udp_pktsrc2str(&pkt), numread  );
	
	    if((size_t)numread < sizeof(HEADER)+1 ) {
	        debug("invalid size : %d < %d\n",numread,sizeof(HEADER)+1);
		syslog(LOG_NOTICE,"dns packet from %s has invalid size of %d bytes.\n",
			udp_pktsrc2str(&pkt), numread  );
	        continue;
	    }


	    if( ((HEADER *)pkt.buf)->qr == 0 ) {

	        /* packet is a query */

	        if( udp_is_bridgesock(sockfd)) {
	    	    debug("query from bridge socket\n");
  	            next_outstanding_answer = handle_bridge_query(sockfd, &pkt );
		} else {
		    if( pkt.src_port == config.port ) {
  	      	       handle_mcast_query( &pkt );
		    } else {
  	      	       handle_unicast_query(sockfd, &pkt );
		    }
		}

	    } else {

		/* packet is an answer */
		if( pkt.ttl != 255 ) {
		    debug("ttl in answer is not 255, ignore\n");
		    syslog(LOG_NOTICE,"answer packet from %s has invalid ttl of %d.\n",
		    udp_pktsrc2str(&pkt) , pkt.ttl );
		    continue;
		}


		if( pkt.loop ) {
		    debug("answer is looped back to myself, ignore\n");
		    syslog(LOG_NOTICE,"answer packet looped back to myself.\n");
		    continue;
		}

		handle_mcast_reply(&pkt);

	    }

        } /* for each ready fd */

	if( (next_outstanding_answer < time(NULL)) && ( ll_first(query_list) != NULL) ) {
	    /*
	     * Check outstanding queries that may should be answered now.
	     */
	     debug("handle outstanding queries ...\n");
	     next_outstanding_answer = handle_timeout();
	}


     } /* no error */
  } /* while not go down */

  goodbye();
  udp_close_sockets();
  
  if( config.daemon_mode ) {
      unlink( config.pid_file );
  }

  debug("normal exit\n");
  syslog(LOG_INFO,"normal exit");
  return 0;
}

/*****************************************************************************
 * Sleep for a random delay between 20-120 msec.
 *****************************************************************************/
static void random_sleep(void) {
    unsigned long rdelay = 0;
    rdelay = 20000 + (100000.0*rand()/(RAND_MAX+1.0));
    debug("random sleep for %lu usec\n" , rdelay );
    usleep(rdelay);
}

/*****************************************************************************
 * Take an encoded message and send it via multicast
 *****************************************************************************/
static void init_mcast_response(dns_t * answer) {
    dns_init(answer);
    dns_init_answer(answer);

    answer->to_mcast = 1;
    
    /* MUST set the query-id to 0 when we respond by mcast.  */
    answer->u.hdr.id = 0;

    /* it's an answer */
    answer->u.hdr.qr = 1;
}

static void send_mcast_response( const decoded_message_t * response ) {

    int answer_count  = 0;
    dns_t answer;
    ll_entry_t * el = NULL;

    debug("multicast answer\n");

    init_mcast_response(&answer);

    info_debug_message( response );

    foreach(el,response->answers) {
        answer_count ++;
        if( dns_add_rr( &answer, (dns_rr *)el->data ) < 0 ) {
	    udp_send_mcast_dnsmsg( &answer );
	    init_mcast_response(&answer);
	    dns_add_rr( &answer, (dns_rr *)el->data );
	}
    }

    if( answer_count > 0 ) {
        debug_dns("answer to client", answer.u.raw );
        udp_send_mcast_dnsmsg( &answer );
    }
}
/*****************************************************************************
 * Take an encoded message and send it as question via multicast
 *****************************************************************************/
static void init_mcast_query(dns_t * answer) {

    dns_init(answer);
    dns_init_answer(answer);

    answer->to_mcast = 1;
    
    /* SHOULD set the query-id to 0 when we query by mcast.  */
    answer->u.hdr.id = 0;

    /* it's a query */
    answer->u.hdr.qr = 0;
}

static void send_mcast_query( const decoded_message_t * response ) {

    dns_t answer;
    ll_entry_t * el = NULL;

    debug("multicast response\n");

    info_debug_message( response );

    init_mcast_query( &answer );

    foreach(el,response->questions) {
	dns_question * q = (dns_question *)el->data;
	if( dns_add_qr( &answer , q->query_arg , q->query_type , q->query_class ) < 0 ) {
    	    answer.u.hdr.tc = 1;
	    udp_send_mcast_dnsmsg( &answer );
    	    init_mcast_query( &answer );
	    dns_add_qr( &answer , q->query_arg , q->query_type , q->query_class );
	}
    }

    foreach(el,response->answers) {
        if( dns_add_rr( &answer, (dns_rr *)el->data ) < 1 ) {
    	    answer.u.hdr.tc = 1;
	    udp_send_mcast_dnsmsg( &answer );
    	    init_mcast_query( &answer );
	    dns_add_rr( &answer, (dns_rr *)el->data );
	}
    }

    foreach(el,response->authority) {
        if( dns_add_ns( &answer, (dns_rr *)el->data ) < 1 ) {
    	    answer.u.hdr.tc = 1;
	    udp_send_mcast_dnsmsg( &answer );
    	    init_mcast_query( &answer );
	    dns_add_ns( &answer, (dns_rr *)el->data );
	}
    }


    udp_send_mcast_dnsmsg( &answer );
}

/*****************************************************************************
 * Take an encoded message and send it via unicast 
 *
 * There is no truncated handling here, because we have not implemented
 * dns over tcp. 
 *
 *****************************************************************************/
static void send_ucast_response( 
		int sock ,
		const struct sockaddr * dst_address , socklen_t dst_len ,
		const decoded_message_t * response ) 
{

    int answer_count  = 0;
    dns_t answer;
    ll_entry_t * el = NULL;

    debug("unicast response\n");

    dns_init(&answer);
    dns_init_answer(&answer);

    answer.to_mcast = 0;
    answer.u.hdr.id = response->id;
    answer.u.hdr.rcode = response->rcode;

    /* it's an answer */
    answer.u.hdr.qr = 1;

    info_debug_message( response );

    foreach(el,response->questions) {
	dns_question * q = (dns_question *)el->data;
	dns_add_qr( &answer , q->query_arg , q->query_type , q->query_class );
    }

    foreach(el,response->answers) {
        answer_count ++;
        dns_add_rr( &answer, (dns_rr *)el->data );
    }

    foreach(el,response->authority) {
        answer_count ++;
        dns_add_ns( &answer, (dns_rr *)el->data );
    }

    foreach(el,response->additional) {
        answer_count ++;
        dns_add_ar( &answer, (dns_rr *)el->data );
    }

    if( (answer_count > 0) || (response->rcode != 0) ) {
        debug_dns("answer to client", answer.u.raw );
	udp_send_dnsmsg_to( sock , dst_address , dst_len , &answer );
    }
}
/*****************************************************************************
 * handle a multicast query that came from the multicast port.
 *
 * This indicates the sender is fully multicast capable.
 *
 * - decode the query
 * - send the answer.
 * 
 * @param sock     socket to send back the answer.
 * @param udp_pkt  data packet that contains the query.
 *
 * @return >=0 on success, < 0 on error.
 *****************************************************************************/
static int handle_mcast_query( struct udp_packet *udp_pkt ) {

    int answer_count  = 0;

    int added_auth = 1;

    decoded_message_t * query    = NULL;
    decoded_message_t * response = NULL;

    ll_entry_t * el = NULL;

    debug_dns("multicast query ", udp_pkt->buf);

    debug("decode query ...\n");
    
    debug("decode query ...\n");
    if( (query = info_decode_packet(udp_pkt)) == NULL ) {
	return 0;
    }
    info_debug_message( query );
    

    if( (response = info_new_message()) == NULL ) {
        info_free_decoded_message( query );
	return 0;
    }

    debug("look for answers...\n");
    foreach(el,query->questions) {
	search_state s;
	dns_question * question = (dns_question *)el->data;

	info_init_search(&s,question->query_arg,question->query_type);

	while( info_search(&s) >0 ) {
	    ll_entry_t * qael = NULL;
	    int known = 0;

    	    foreach(qael,query->answers) {
		dns_rr * q_answer = (dns_rr * )qael->data;

		if( info_compare_rr( q_answer , s.data ) == 0 ) {
		    debug("known answer supression\n");
		    known = 1;
		    break;
		}
	    }

	    if( ! known ) {
	        answer_count ++;
	        ll_add(response->answers, info_clone_rr(s.data));

		/* check if we added a record which are authoritativ for */
		if( s.data->auth ) {
		    added_auth = 1;
		}
	    }
	}
    }


    debug("conflict detetection in query\n");
    if( ll_first(query->authority) != NULL ) {
        search_state s;

        debug("have authority section in query\n");

        info_init_search(&s,NULL,T_ANY);
        while( info_search(&s) >0 ) {
    	    foreach(el,query->authority) {
		dns_rr * a = (dns_rr *)el->data;

		debug("look at %s and %s\n" , a->domain , s.data->domain);

	        if( strncasecmp(a->domain , s.data->domain, MAXDNAME) == 0 ) {
	            debug("**** CONFLICT IN AUTHORITY -> fight ****\n");
	            ll_add(response->answers, info_clone_rr(s.data));
		    added_auth = 1;
	            answer_count ++;
		    break;
	        }
            }
        }
    }

    if( answer_count > 0 ) {
      if( ! added_auth ) {
        random_sleep();
      }
      send_mcast_response( response );
    }

    info_free_decoded_message( query );
    info_free_decoded_message( response );

    return 0;
}

/*****************************************************************************
 * Add to a decoded response message any packet natching one of the queries.
 *
 * @return number of answers placed in the answer list.
 *****************************************************************************/
static int find_answers( const decoded_message_t * query , 
                         const decoded_message_t * response ) {

    ll_entry_t * el = NULL;
    dns_rr * srv_rr = NULL;
    int answer_count  = 0;

    debug("look for answers...\n");

    foreach(el,query->questions) {

	search_state s;
	dns_question * question = (dns_question *)el->data;

	info_init_search(&s,question->query_arg,question->query_type);

	debug("search : %s %d\n" , s.dname , s.type );

	while( info_search(&s) > 0 ) {
	
	    dns_rr * clone = NULL;
	    
	    debug("found\n");
	
	    clone = info_clone_rr(s.data);

	    if( clone != NULL ) {
	        clone->ttl = config.default_unicast_ttl;

	        answer_count ++;
	        if( s.data->type == T_SRV ) {
		    srv_rr = s.data;
	        }

	        ll_add(response->answers, clone );
	    }
	}
    }

    debug("add additional ...\n");

    /* 
     * add additional text- and address records 
     *
     * This is usefull for unicast queries only, because an mcast
     * querier would have asked for things it is interested in with
     * in multiple questions.
     *
     * Unicast queries only have a single question anyway
     */
    if( srv_rr != NULL ) {
	search_state s;

	info_init_search(&s, srv_rr->rr.srv.target , T_A);
	while( info_search(&s) >0 ) {
	    dns_rr * clone = info_clone_rr(s.data);
	    if( clone != NULL ) {
	        dns_rr * clone = info_clone_rr(s.data);
	        clone->ttl = config.default_unicast_ttl;
	        ll_add(response->additional, clone );
	    }
	}

	info_init_search(&s, srv_rr->rr.srv.target , T_AAAA);
	while( info_search(&s) >0 ) {
	    dns_rr * clone = info_clone_rr(s.data);
	    if( clone != NULL ) {
	        dns_rr * clone = info_clone_rr(s.data);
	        clone->ttl = config.default_unicast_ttl;
	        ll_add(response->additional, clone );
	    }
	}

	info_init_search(&s, srv_rr->domain , T_TXT);
	while( info_search(&s) >0 ) {
	    dns_rr * clone = info_clone_rr(s.data);
	    if( clone != NULL ) {
	        dns_rr * clone = info_clone_rr(s.data);
	        clone->ttl = config.default_unicast_ttl;
	        ll_add(response->additional, clone );
	    }
	}
    }

    return answer_count;
}
/*****************************************************************************
 * handle a multicast query from a client that did not use the mcast port
 * for sending its packet.
 *
 * Our answer will be a bit different from the answer to a pure mcast query:
 *
 *   - we preserve the transaction id
 *   - we add the queries to the response.
 *   - we may add additional records 
 * 
 * @param sock     socket to send back the answer.
 * @param udp_pkt  data packet that contains the query.
 *
 * @return >=0 on success, < 0 on error.
 *****************************************************************************/
static int handle_unicast_query( int sock,  struct udp_packet *udp_pkt ) {

    int answer_count  = 0;

    decoded_message_t * query    = NULL;
    decoded_message_t * response = NULL;

    debug_dns("unicast query from client", udp_pkt->buf);

    debug("decode query ...\n");
    if( (query = info_decode_packet(udp_pkt)) == NULL ) {
	return 0;
    }
    info_debug_message( query );

    if( (response = info_new_message()) == NULL ) {
        info_free_decoded_message( query );
	return 0;
    }

    debug("copy questions ...\n");
    info_copy_questions( query , response );

    response->id = query->id;

    answer_count = find_answers( query , response );

    debug("maybe answer ...\n");

    if( answer_count > 0 ) {
	send_ucast_response( sock, &(udp_pkt->src_address), udp_pkt->src_len, response );
    }

    info_free_decoded_message( query );
    info_free_decoded_message( response );

    return 0;
}

/*****************************************************************************
 * handle a unicast from the bridge socket.
 *
 * Our answer will be a bit different from the answer to multicast :
 *
 *   - we preserve the transaction id
 *   - we add the queries to the response.
 *   - we may add additional records 
 *   - we may respond with an error message.
 *   - a query is send out via multicast.
 *
 * Also the query is stored in a queue to allow for more answers to arrive
 * 
 * @param sock     socket to send back the answer.
 * @param udp_pkt  data packet that contains the query.
 *
 * @return >=0 on success, < 0 on error.
 *****************************************************************************/
static int handle_bridge_query( int sock,  struct udp_packet *udp_pkt ) {

    int answer_count  = 0;
    int failed = 0;

    decoded_message_t * query    = NULL;
    decoded_message_t * response = NULL;

    debug_dns("unicast query from client", udp_pkt->buf);

    debug("decode query ...\n");
    if( (query = info_decode_packet(udp_pkt)) == NULL ) {
	return 0;
    }
    info_debug_message( query );

    if( (response = info_new_message()) == NULL ) {
        info_free_decoded_message( query );
	return 0;
    }

    debug("copy questions ...\n");
    info_copy_questions( query , response );

    response->id = query->id;

    if( ! config.allow_nonlocal ) {
        ll_entry_t * el = NULL;

        foreach(el,query->questions) {
	    dns_question * question = (dns_question *)el->data;
	    if( ! info_is_local_domain(question->query_arg) ) {
	        debug("respond with SERVFAIL because query is not link-local\n");
	        response->rcode = SERVFAIL;
		failed = 1;
		break;
	    }
	}
    }

    if( failed != 0 ) {

	send_ucast_response( sock, &(udp_pkt->src_address), udp_pkt->src_len, response );
        info_free_decoded_message( query );
        info_free_decoded_message( response );
	
    } else {

	/* FIXME: this was the place to implement query suppression */
	 
	memcpy( &(response->dst_address), &(udp_pkt->src_address), udp_pkt->src_len);
	response->dst_len = udp_pkt->src_len;
	response->sock = sock;
	response->timeout = time(NULL) + config.gather_delay;

        // FIXME: answer_count is not used. delete ?
        answer_count = find_answers( query , response );
	ll_add(query_list, response);

	/* just re-use the bridge query to send the mcast query */

	send_mcast_query( query );

        info_free_decoded_message( query );
    }

    return 0;
}
/*****************************************************************************
 *
 * handle timeout:
 *
 *   - Send packets queued for delivery.
 *
 *****************************************************************************/
static int handle_timeout(void) {

    ll_entry_t * el = NULL;

    int now = time(NULL);

    el = ll_first(query_list); 
    while( el != NULL ) {
        ll_entry_t * el_now = el;
	decoded_message_t * response = (decoded_message_t *)el_now->data;
	el = ll_next(el);

	if( response->timeout > now ) {
	  /*
	   * Our list is kept in the order we've got the queries. Whenever
	   * we find a record that is not to be sent now, we can return.
	   */
	   return response->timeout ;
	}

	if( ll_first( response->answers ) == NULL ) {
	    response->rcode = NXDOMAIN;
	}

	send_ucast_response( response->sock, 
			     &(response->dst_address), 
			     response->dst_len, response );

        info_free_decoded_message( response );
	ll_remove(el_now);
    }

    return 0;
}
 
/*****************************************************************************
 *
 * handle multicast responses:
 *
 *   - if we have a multicast response to be answered, remove all RRs from
 *     our response that are also in the handled response.
 * 
 *   - Fill the RR's from the answer record we've got from multicast into the 
 *     bridge queries that may need them.
 *
 *   - check if an answer from the multicast response matches one of our
 *     own RRs. Remove them (?)
 *
 *
 *****************************************************************************/
static void handle_mcast_reply(struct udp_packet * udp_pkt) {

    decoded_message_t * response = NULL;
    ll_entry_t * el = NULL;
    search_state s;

    debug("handle multicast reply ...\n");

    debug("decode query ...\n");
    if( (response = info_decode_packet(udp_pkt)) == NULL ) {
	return ;
    }
    debug("response decoded\n");
    info_debug_message( response );

    /* foreach stored query ... */
    foreach(el,query_list) {

	ll_entry_t * qel = NULL;
	decoded_message_t * query = (decoded_message_t *)el->data;

        /* foreach question in stored query ... */
        foreach(qel,query->questions) {

	    ll_entry_t * rel = NULL;
	    dns_question * q = (dns_question *)qel->data;

            /* foreach answer in mcast response ... */
            foreach(rel,response->answers) {

		dns_rr * a = (dns_rr *)rel->data;

	        ll_entry_t * qael = NULL;
	        int known = 0;

		/* ... add a copy of answer if it matches the question */
                if( ( (q->query_type == T_ANY) || (q->query_type == a->type ) ) &&
	            ( q->query_class == a->class ) &&
                    ( strcasecmp(q->query_arg,a->domain) == 0) )
		{
                    foreach(qael,query->answers) {

		        dns_rr * q_answer = (dns_rr * )qael->data;

		        if( info_compare_rr( q_answer , a ) == 0 ) {
		            debug("known answer in stored query\n");
		            known = 1;
		            break;
		        }
	            }

	            if( ! known ) {
		        /* ... add a copy of answer if it matches the question */
		        dns_rr * clone = info_clone_rr(a);
		        clone->ttl = config.default_unicast_ttl;
	                ll_add(query->answers, clone);
		    }
		} /* match */
	    } /* each mcast response */
	} /* each question in query */
    } /* each stored query */


    /*
     * Check each answer if it is for a record we feel authorative for. If
     * there is one, check if they are different. If they are different,
     * there is a conflict and one party must drop its records.
     *
     * The tie-break algorithm from the specs doesn't feel right (binary
     * compare records), so we are polite and always drop our record instead.
     */
    debug("conflict detetection\n");

    info_init_search(&s,NULL,T_ANY);
    while( info_search(&s) >0 ) {
        foreach(el,response->answers) {
	    dns_rr * his = (dns_rr *)el->data;

	    if( (strncasecmp(his->domain , s.data->domain, MAXDNAME) == 0) &&
		(his->type == s.data->type) )
	    {
	        if( info_compare_rr( s.data , his ) != 0 ) {
	            debug("**** CONFLICT ****\n");
		    syslog(LOG_ERR, "conflict over name \"%s\" , type %d - drop my record\n",
			his->domain,his->type);
		    info_drop_record(&s);
		}
	    }
        }
    }

    info_free_decoded_message( response );
    debug("done with mcast response\n");
}

/*****************************************************************************
 * Send a probe packet to the multicast address.
 *
 * The packet contains questions for all of out RR's plus all
 * the RR's in the authority section. 
 *****************************************************************************/
static int probe(void) {
    search_state s;
    decoded_message_t * response = NULL;

    debug("Probe ...\n");

    if( (response = info_new_message()) == NULL ) {
	return 0;
    }


    /* add a question for each of my autorative records */
    info_init_search(&s,NULL,T_ANY);
    while( info_search(&s) >0 ) {
	ll_add( response->questions, 
	        info_new_question(s.data->domain, T_ANY , C_IN));
    }

    /* add an authorative record for each record we want register */
    info_init_search(&s,NULL,T_ANY);
    while( info_search(&s) >0 ) {
        ll_add(response->authority, info_clone_rr(s.data));
    }

    send_mcast_query( response );
    info_free_decoded_message( response );

    return 0;
}

/*****************************************************************************
 * Send announcement packet to the multicast address.
 *
 * An announcement is simply an answer to all of our RR's
 *
 *****************************************************************************/
static int announce(void) {
    search_state s;
    decoded_message_t * response = NULL;

    debug("Announce ...\n");

    if( (response = info_new_message()) == NULL ) {
	return 0;
    }

    /* add an answer record for each record we want to register */
    info_init_search(&s,NULL,T_ANY);
    while( info_search(&s) >0 ) {
        ll_add(response->answers, info_clone_rr(s.data));
	syslog(LOG_INFO,"claim name \"%s\", type %d\n" , s.data->domain , s.data->type );
    }

    send_mcast_response( response );
    info_free_decoded_message( response );

    return 0;

}

/*****************************************************************************
 * Send goodbye packet to the multicast address.
 *
 * Like an announcement that is simply an answer to all of our RR's but
 * with TTL set to 0. 
 *
 *****************************************************************************/
static int goodbye(void) {
    search_state s;
    decoded_message_t * response = NULL;

    debug("Goodbye ...\n");

    if( (response = info_new_message()) == NULL ) {
	return 0;
    }

    /* add an answer record with ttl=0 for each record we want to register */
    info_init_search(&s,NULL,T_ANY);
    while( info_search(&s) >0 ) {
        dns_rr * clone = info_clone_rr(s.data);
        clone->ttl = 0;
        ll_add(response->answers, clone);
	syslog(LOG_INFO,"goodbye for name\"%s\", type %d\n" , s.data->domain , s.data->type );
    }

    send_mcast_response( response );
    info_free_decoded_message( response );

    return 0;
}

