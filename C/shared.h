#ifndef EPBF_FIREWALL_SHARED_H
#define EPBF_FIREWALL_SHARED_H

#include <linux/types.h>
#include <linux/ipv6.h>

// Macro for stringification
#define _STR(x) #x
#define STR(x) _STR(x)

// Shared Constants
#define EVENT_LOG_MAP_ID events
#define EVENT_LOG_MAP_ALIAS STR(EVENT_LOG_MAP_ID)

#define MAX_BLOCKED_IPV4 1024
#define MAX_BLOCKED_IPV6 1024
#define MAX_BLOCKED_PORT 1024
#define RULE_ACTION_DROP 1

// Ingress (XDP) Constants
#define INGRESS_IPV4_RULE_MAP_ID ingress_ipv4_rule_table
#define INGRESS_PORT_RULE_MAP_ID ingress_port_rule_table
#define INGRESS_PROG_ID xdp_prog

#define INGRESS_IPV4_RULE_MAP_ALIAS STR(INGRESS_IPV4_RULE_MAP_ID)
#define INGRESS_PORT_RULE_MAP_ALIAS STR(INGRESS_PORT_RULE_MAP_ID)
#define INGRESS_PROG_NAME STR(INGRESS_PROG_ID)

#define INGRESS_BLOCK_REASON_SRC_IPV4 1
#define INGRESS_BLOCK_REASON_SRC_PORT 2
#define INGRESS_BLOCKED_EVENT 1

// Egress (TC) Constants
#define EGRESS_IPV4_RULE_MAP_ID egress_ipv4_rule_table
#define INGRESS_IPV6_RULE_MAP_ID egress_ipv6_rule_table
#define EGRESS_PORT_RULE_MAP_ID egress_port_rule_table
#define EGRESS_PROG_ID tc_prog

#define EGRESS_IPV4_RULE_MAP_ALIAS STR(EGRESS_IPV4_RULE_MAP_ID)
#define EGRESS_IPV6_RULE_MAP_ALIAS STR(EGRESS_IPV6_RULE_MAP_ID)
#define EGRESS_PORT_RULE_MAP_ALIAS STR(EGRESS_PORT_RULE_MAP_ID)
#define EGRESS_PROG_NAME STR(EGRESS_PROG_ID)

#define EGRESS_BLOCK_REASON_DST_IPV4 3
#define EGRESS_BLOCK_REASON_DST_PORT 4
#define EGRESS_BLOCKED_EVENT 2

#define IPTYPE_IPV6 1
#define IPTYPE_IPV4 0

#define MAX_IPV6_EXT_HDRS 6

typedef enum {
    RULE_ACTION_UPSERT = 0,
    RULE_ACTION_DELETE = 1,
} rule_action_t;

typedef enum {
    RULE_DIRECTION_INGRESS = 0,
    RULE_DIRECTION_EGRESS  = 1,
} rule_direction_t;

struct rule_table {
    const __u32 *ipv4_list;
    const __u32 *ipv4_prefix_len;
    int ipv4_count;
    const __u16 *port_list;
    int port_count;
};

struct ipv6_rule_key {
    __u32 prefixlen;
    struct in6_addr addr ; 
};

struct ipv4_rule_key {
    __u32 prefixlen;
    __u32 addr;
};

struct rule_value {
    __u8 action;
};

struct port_rule_key {
    __u16 port;
};

struct event {
    __u64 id; 
    __u32 src_ip[4];
    __u32 dst_ip[4];
    __u16 src_port;
    __u16 dst_port;
    __s8 protocol;
    __u8 reason;
    __u8 event_type;
    __u8 _pad;
};

#endif
