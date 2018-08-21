
tmdns_CFLAGS  = -Wall
sbin_PROGRAMS = tmdns
tmdns_SOURCES = \
		 conf.c          conf.h\
		 debug.c	 debug.h\
		 llist.c         llist.h\
		 dns.c           dns.h \
		 getifaddrs.c	 tm_ifaddrs.h \
		 info.c          info.h\
		 tmdns.c         tmdns.h \
		 serv_udp.c      serv_udp.h \
		 netlink_glue.c  netlink_glue.h \
		 libnetlink.c    libnetlink.h 

tmdns_LDADD=@BUILD_STATIC@

man_MANS = tmdns.8 tmdns.conf.5 tmdns.services.5
EXTRA_DIST = $(man_MANS) svc

