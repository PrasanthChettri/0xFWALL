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

static __always_inline int extract_and_check_port_blocklist(struct iphdr *ip, void* data_end, __u16 *sport, __u16 *dport) {
    void *l4_start = (void *)ip + (ip->ihl * 4);
    *dport = 0;
    *sport = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_start;
        if ((void *)(tcp + 1) > data_end) return 0;
        *dport = tcp->dest;
        *sport = tcp->source;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_start;
        if ((void *)(udp + 1) > data_end) return 0;
        *dport = udp->dest;
        *sport = udp->source;
    } else {
        return 0;
    }

    struct port_rule_key key = { .port = *dport };
    struct rule_value *rule = bpf_map_lookup_elem(&INGRESS_PORT_RULE_MAP_ID, &key);
    return  (int) (rule && rule->action == RULE_ACTION_DROP) ; 
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
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 sport = 0, dport = 0;
    __u8 is_ip_blocked = check_ip_blocklist(ip->saddr) ; 
    __u8 is_port_blocked = extract_and_check_port_blocklist(ip, data_end, &sport, &dport) ; 
    if(is_ip_blocked | is_port_blocked){
        event = bpf_ringbuf_reserve(&EVENT_LOG_MAP_ID, sizeof(*event), 0);
        if (event) {
            event->id = ++_id ; 
            event->timestamp_ns = bpf_ktime_get_ns(); 
            event->src_ip = ip->saddr;
            event->dst_ip = ip->daddr;
            event->src_port = sport;
            event->dst_port = dport;
            event->protocol = ip->protocol;
            event->reason = is_ip_blocked ? INGRESS_BLOCK_REASON_SRC_IPV4 : INGRESS_BLOCK_REASON_SRC_PORT;
            event->event_type = INGRESS_BLOCKED_EVENT;
            bpf_ringbuf_submit(event, 0);
        }
        return XDP_DROP;
    }
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";