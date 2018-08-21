
#ifndef NETLINK_GLUE_H

#define NOTIFY_DELAY	5

extern int init_netlink_glue(void);
extern void stop_netlink_glue(void);
extern int handle_netlink_msg(void);
extern int network_changed(void);

#define NETLINK_GLUE_H 1

#endif
