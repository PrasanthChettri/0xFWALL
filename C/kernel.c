#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include "shared.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPV4);
    __type(key, struct ipv4_rule_key);
    __type(value, struct rule_value);
} rule_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} blocked_ip_event  SEC(".maps");

int _id ; 
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    struct blocked_ip_event *event;
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

    struct rule_value *src_rule = bpf_map_lookup_elem(&rule_table, &ip->saddr);
    struct rule_value *dst_rule = bpf_map_lookup_elem(&rule_table, &ip->daddr);

    bpf_printk("xdp ip src=%x dst=%x src_rule=%p dst_rule=%p",
               ip->saddr, ip->daddr, src_rule, dst_rule);
    event = bpf_ringbuf_reserve(&blocked_ip_event, sizeof(*event), 0);
    if (!event) {
        return XDP_PASS ; 
    }
    event->id = ++_id ; 
    event->timestamp_ns = bpf_ktime_get_ns();
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->src_port = 0;
    event->dst_port = 0;
    event->protocol = ip->protocol;
    event->reason = 1;
    bpf_ringbuf_submit(event, 0);
    return XDP_PASS ; 

}

char LICENSE[] SEC("license") = "GPL";
