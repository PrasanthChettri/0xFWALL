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
} blocked_ip_events  SEC(".maps");

int _id ; 
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    struct blocked_ip_event *event;
    struct ipv4_rule_key src_key;
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

    src_key.addr = ip->saddr;
    struct rule_value *src_rule = bpf_map_lookup_elem(&rule_table, &src_key);

    if (!src_rule || src_rule->action != RULE_ACTION_DROP)
        return XDP_PASS;

    event = bpf_ringbuf_reserve(&blocked_ip_events, sizeof(*event), 0);
    if (!event) {
        return XDP_DROP;
    }
    event->id = ++_id ; 
    event->timestamp_ns = bpf_ktime_get_ns();
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->src_port = 0;
    event->dst_port = 0;
    event->protocol = ip->protocol;
    event->reason = BLOCK_REASON_SRC_IPV4;
    bpf_ringbuf_submit(event, 0);
    return XDP_DROP;

}

char LICENSE[] SEC("license") = "GPL";
