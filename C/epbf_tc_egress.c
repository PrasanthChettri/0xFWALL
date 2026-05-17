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

static __always_inline int check_ip4_blocklist(__u32 daddr) {
    struct ipv4_rule_key dst_key = { .prefixlen = 32, .addr = daddr };
    struct rule_value *dst_rule = bpf_map_lookup_elem(&EGRESS_IPV4_RULE_MAP_ID, &dst_key);
    if (dst_rule && dst_rule->action == RULE_ACTION_DROP)
        return 1;
    return 0; 
}

static __always_inline int extract_and_check_port_blocklist(struct iphdr *ip, void* data_end, __u16 *sport, __u16 *dport) {
    void *l4_start = (void *)ip + (ip->ihl * 4);
    *dport = 0;
    *sport = 0;
    void * cursor ; 
    __u8 protocol; 
    if (ip_type == IPTYPE_IPV4 ) {
        struct iphdr * ip = (struct iphdr *) ip_hdr  ; 
        cursor = ( (void * )ip ) + ip->ihl * 4;
        protocol = ip->protocol; 
    }
    else if (ip_type  == IPTYPE_IPV6) {
            struct ipv6hdr * ip = (struct ipv6hdr *) ip_hdr ; 
            protocol = ip->nexthdr ; 
            cursor = (void *)(ip_hdr + 1) ; 
            #pragma unroll
            for(int i = 0 ; i < MAX_IPV6_EXT_HDRS; i++) {
                if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
                    break ; 
                if (protocol == IPPROTO_HOPOPTS || 
                    protocol == IPPROTO_ROUTING || 
                    protocol == IPPROTO_DSTOPTS) {
                    struct ipv6_opt_hdr *exh_head = (struct ipv6_opt_hdr *)cursor ; 
                    if( (  void * ) (exh_head + 1)  > data_end ) goto port_pass ; 
                    protocol = exh_head->nexthdr ; 
                    cursor += (exh_head->hdrlen + 1) * 8 ; 
                } else if(protocol == IPPROTO_FRAGMENT) {
                    struct ipv6_opt_hdr *frag = (struct ipv6_opt_hdr *)cursor ; 
                    if ( (void *) (frag + 1)  > data_end)  goto port_pass ;
                    protocol = frag->nexthdr ; 
                    cursor += 8 ;
                } else goto port_pass ; 
        }
    }

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *) cursor;
        if ((void *)(tcp + 1) > data_end) goto port_pass ; 
        *dport = tcp->dest;
        *sport = tcp->source;
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *) cursor;
        if ((void *)(udp + 1) > data_end) goto port_pass ; 
        *dport = udp->dest;
        *sport = udp->source;
    }
    else goto port_pass ;

    struct port_rule_key key = { .port = *dport };
    struct rule_value *rule = bpf_map_lookup_elem(&EGRESS_PORT_RULE_MAP_ID, &key);
    return  (int) (rule && rule->action == RULE_ACTION_DROP) ; 

    port_pass : 
        return 0;
}

int _id; 
SEC("tc/egress")
int EGRESS_PROG_ID(struct __sk_buff *skb) {
    struct event *event;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    void *ip = data + sizeof(*eth);
    int ip_type = 0 ; 
    __s8 protocol = -1; 
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip4 = (struct iphdr *)ip;
        if ( (void *)(ip4 + 1) > data_end )  return TC_ACT_OK;
        protocol = ip4->protocol ; 
        ip_type = IPTYPE_IPV4 ; 
    }
    else if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr * ip6 = (struct ipv6hdr *)ip;
        if ( (void *)(ip6 + 1) > data_end )  return TC_ACT_OK;
        protocol = ip6->nexthdr ; 
        ip_type = IPTYPE_IPV6 ; 
    } else return TC_ACT_OK; 

    __u16 sport = 0, dport = 0;
    __u8 is_ip_blocked = 0 ; 
    if(ip_type == IPTYPE_IPV4)
        is_ip_blocked = check_ip4_blocklist(((struct iphdr *)ip)->daddr) ; 
    else if(ip_type == IPTYPE_IPV6)
        is_ip_blocked = check_ip6_blocklist(((struct ipv6hdr *)ip)->daddr) ; 

    __u8 is_port_blocked = extract_and_check_port_blocklist(ip, data_end, &sport, &dport, ip_type); 

    if (is_ip_blocked | is_port_blocked) {
        /*
        event = bpf_ringbuf_reserve(&EVENT_LOG_MAP_ID, sizeof(*event), 0);
        if (event) {
            event->id = ++_id; 
            event->ip_type = ip_type ; 
            if (ip_type == IPTYPE_IPV4) {
                struct iphdr *ip4 = (struct iphdr *)ip;
                event->src_ip[0] = ip4->saddr;
                event->src_ip[1] = 0;
                event->src_ip[2] = 0;
                event->src_ip[3] = 0;
                event->dst_ip[0] = ip4->daddr;
                event->dst_ip[1] = 0;
                event->dst_ip[2] = 0;
                event->dst_ip[3] = 0;
                event->reason = is_ip_blocked ? EGRESS_BLOCK_REASON_DST_IPV4 : EGRESS_BLOCK_REASON_DST_PORT;
            } else {
                struct ipv6hdr *ip6 = (struct ipv6hdr *)ip;
                #pragma unroll
                for(int i = 0 ; i < 4 ; i++) {
                    event->src_ip[i] = ip6->saddr.s6_addr32[i];
                    event->dst_ip[i] = ip6->daddr.s6_addr32[i];
                }
                event->reason = is_ip_blocked ? EGRESS_BLOCK_REASON_DST_IPV6 : EGRESS_BLOCK_REASON_DST_PORT;
            }
            event->src_port = sport;
            event->dst_port = dport;
            event->protocol = protocol;
            event->event_type = EGRESS_BLOCKED_EVENT;
            bpf_ringbuf_submit(event, 0);
        }
        */
        return TC_ACT_SHOT; // Drop packet in TC
    }

    return TC_ACT_OK; // Pass packet in TC
}
char LICENSE[] SEC("license") = "GPL";
