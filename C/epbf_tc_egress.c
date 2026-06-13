#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include "shared.h"

#include "shared_krings.h"
#include "epbf_helpers.h"

DEFINE_RULE_MAPS(EGRESS_IPV4_RULE_MAP_ID,
                 EGRESS_IPV6_RULE_MAP_ID,
                 EGRESS_PORT_RULE_MAP_ID);

SEC("tc/egress")
int EGRESS_PROG_ID(struct __sk_buff *skb) {
    struct event *event;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    void *ip = data + sizeof(*eth);
    struct parse_result pr = parse_ip(ip, data_end, eth->h_proto);
    struct conn_key ck ; 
    if(pr.protocol == -1) 
        return TC_ACT_OK ;  // change this 

    __u16 sport = 0, dport = 0;
    __u8 l4_proto = 0 ; 
    extract_transport_ports(ip, data_end, pr.ip_type, &sport, &dport, &l4_proto);
    make_conn_key(&ck, ip, ip, pr.ip_type, sport, dport, l4_proto) ; 
    void * status = bpf_map_lookup_elem(&CONNTRACK_MAP, &ck) ; 

    if(status && *((__u8*)status) == CONNTRACK_SEEN) {
        return TC_ACT_OK ; 
    }

    __u8 is_ip_blocked = CHECK_IP_BLOCKLIST(ip, pr.ip_type,
                                        EGRESS_IPV4_RULE_MAP_ID,
                                        EGRESS_IPV6_RULE_MAP_ID, daddr);
    __u8 is_port_blocked = CHECK_PORT_BLOCKLIST(EGRESS_PORT_RULE_MAP_ID, dport, l4_proto) ; 
    if (is_ip_blocked | is_port_blocked) {
        send_event(ip, pr.ip_type, sport, dport, l4_proto,
            is_ip_blocked, EGRESS_BLOCKED_EVENT);
        return TC_ACT_SHOT; // Drop packet in TC
    }

    return TC_ACT_OK; // Pass packet in TC
}
char LICENSE[] SEC("license") = "GPL";
