
#ifndef SERV_UDP_H
#define SERV_UDP_H 1

#include <config.h>

extern int udp_packet_read(int sockfd, struct udp_packet *udp_pkt);

extern int udp_open_sockets( int * sockets[] );
extern void udp_close_sockets(void);
extern void udp_send_dnsmsg(int, const dns_t * );

extern void udp_send_dnsmsg_to(
		int sockfd, 
		const struct sockaddr * dst_address , socklen_t dst_len ,
		const dns_t * pkt);

extern void udp_send_mcast_dnsmsg(const dns_t * );

void udp_copy_answer_address(dns_t * answer, const struct udp_packet * udp_pkt);

const char * udp_pktsrc2str(const struct udp_packet * udp_pkt);

#endif /*SERV_UDP_H*/

