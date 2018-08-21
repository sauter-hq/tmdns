
#ifndef IF_ADDRS_H
#define IF_ADDRS_H 1

#include <sys/socket.h>

/*
 *  striped down version of struct ifaddrs, only that stuff,
 *  that our implementaion provides are included. 
 */
struct ifaddrs {
    struct ifaddrs     *ifa_next;
    char *		ifa_name;
    unsigned int        ifa_flags;
    struct sockaddr	*ifa_addr;
};

extern int getifaddrs(struct ifaddrs**);
extern void freeifaddrs(struct ifaddrs*);

#endif
