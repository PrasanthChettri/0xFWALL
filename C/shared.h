#ifndef EPBF_FIREWALL_SHARED_H
#define EPBF_FIREWALL_SHARED_H

#include <linux/types.h>

#define IPV4_RULE_MAP_ALIAS "ipv4_rule_table"
#define PORT_RULE_MAP_ALIAS "port_rule_table"
#define EVENT_LOG_MAP_ALIAS "events"
#define PROG_NAME "xdp_prog"
#define MAX_BLOCKED_IPV4 1024
#define MAX_BLOCKED_PORT 1024
#define RULE_ACTION_DROP 1
#define BLOCK_REASON_SRC_IPV4 1
#define BLOCK_REASON_SRC_PORT 2
#define INGRESS_BLOCKED_EVENT 1

struct rule_table {
    const __u32 *ipv4_list;
    const __u32 *ipv4_prefix_len;
    int ipv4_count;
    const __u16 *port_list;
    int port_count;
};

struct ipv4_rule_key {
    __u32 prefixlen;
    __u32 addr;
};

/*
struct ipv4_rule_key {
    __u32 addr;
};*/

struct rule_value {
    __u8 action;
};

struct port_rule_key {
    __u16 port;
};

struct event {
    __u64 id; 
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 reason;
    __u8 event_type;
    __u8 _pad;
};

#endif
