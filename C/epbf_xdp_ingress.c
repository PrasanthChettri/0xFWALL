#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include "shared.h"
#include "shared_krings.h"

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_BLOCKED_IPV4);
    __type(key, struct ipv4_rule_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} INGRESS_IPV4_RULE_MAP_ID SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_PORT);
    __type(key, struct port_rule_key);
    __type(value, struct rule_value);
} INGRESS_PORT_RULE_MAP_ID SEC(".maps");



static __always_inline int check_ip_blocklist(__u32 saddr) {
    struct ipv4_rule_key src_key = { .prefixlen = 32, .addr = saddr };
    struct rule_value *src_rule = bpf_map_lookup_elem(&INGRESS_IPV4_RULE_MAP_ID, &src_key);
    if (src_rule && src_rule->action == RULE_ACTION_DROP)
        return 1;
    return 0; 
}

static __always_inline int extract_and_check_port_blocklist(void *ip_hdr, void* data_end, __u16 *sport, __u16 *dport, int ip_type) {
    *dport = 0;
    *sport = 0;
    void * cursor ; 
    __u8 protocol; 
    if (ip_type == IPTYPE_IPV4 ) {
        struct iphdr * ip = (struct iphdr *) ip_hdr  ; 
        cursor = ip + ip->ihl * 4;
        protocol = ip->protocol; 
    }
    else if (ip_type  == IPTYPE_IPV6) {
        struct ipv6hdr * ip = (struct ipv6hdr *) ip_hdr ; 
        protocol = ip->nexthdr ; 
        cursor = void * (ip_hdr + 1) ; 
        #pragma unroll
        for(int i = 0 ; i < MAX_IPV6_EXT_HDRS; i++) {
            if(protocol == IPPROTO_TCP || protcol == IPPROTO_UDP)
                break ; 
            if (protocol == IPPROTO_HOPOPTS || 
                protocol == IPPROTO_ROUTING || 
                protocol == IPPROTO_DSTOPTS) {
                protocol =  ((struct ipv6_opt_hdr *) cursor)->nexthdr ; 
                cursor = cursor + sizeof(struct ipv6_opt_hdr) ; 
                if(cursor > data_end) goto port_pass ;
            } else if(
    }
    else goto port_pass ; 

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_start;
        if ((void *)(tcp + 1) > data_end) goto port_pass ; 
        *dport = tcp->dest;
        *sport = tcp->source;
        goto port_check ; 
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_start;
        if ((void *)(udp + 1) > data_end) goto port_pass ; 
        *dport = udp->dest;
        *sport = udp->source;
    } else goto port_pass ;

    struct ipv6hdr *ip  = (struct iphdr *) ip_hdr ; 
    if( (void *) (ip + 1) > data_end ) goto port_pass ; 


    struct port_rule_key key = { .port = *dport };
    struct rule_value *rule = bpf_map_lookup_elem(&INGRESS_PORT_RULE_MAP_ID, &key);
    return  (int) (rule && rule->action == RULE_ACTION_DROP) ; 

    port_pass : 
        return 0;
}

int _id ; 
SEC("xdp")
int INGRESS_PROG_ID(struct xdp_md *ctx)
{
    struct event *event;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        goto pass ;

    void *ip = data + sizeof(*eth);

    int ip_type = 0 ; 
    if (eth->h_proto == __constant_htons(ETH_P_IP))
        ip_type = IPTYPE_IPV4 ; 
    else if (eth->h_proto != __constant_htons(ETH_P_IPV6))
        ip_type = IPTYPE_IPV6 ; 
    else :
        goto pass ; 


    if ((void *)(ip + 1) > data_end)
        goto pass ; 

    __u16 sport = 0, dport = 0;
    __u8 is_ip_blocked = check_ip_blocklist(ip->saddr) ; 
    __u8 is_port_blocked = extract_and_check_port_blocklist(ip, data_end, &sport, &dport) ; 
    if(is_ip_blocked | is_port_blocked){
        event = bpf_ringbuf_reserve(&EVENT_LOG_MAP_ID, sizeof(*event), 0);
        if (event) {
            event->id = ++_id ; 
            event->src_ip = ip->saddr;
            event->dst_ip = ip->daddr;
            event->src_port = sport;
            event->dst_port = dport;
            event->protocol = ip->protocol;
            event->reason = is_ip_blocked ? INGRESS_BLOCK_REASON_SRC_IPV4 : INGRESS_BLOCK_REASON_SRC_PORT;
            event->event_type = INGRESS_BLOCKED_EVENT;
            bpf_ringbuf_submit(event, 0);
        }
        goto drop ; 
    }
    pass: 
        return XDP_PASS;
    drop: 
        return XDP_DROP;
}
char LICENSE[] SEC("license") = "GPL";
