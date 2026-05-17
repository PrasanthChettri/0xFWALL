#ifndef EPBF_FILTER_HELPERS_H
#define EPBF_FILTER_HELPERS_H

#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "shared.h"
 
/* ── Map definition macro ───────────────────────────────────────────────────
 *
 * Both programs need three maps with the same shape but different names.
 * Declare them with a single macro call in each .c file:
 *
 *   DEFINE_RULE_MAPS(ingress_ipv4_rule_table,
 *                    ingress_ipv6_rule_table,
 *                    ingress_port_rule_table);
 */
#define DEFINE_RULE_MAPS(IPV4_MAP, IPV6_MAP, PORT_MAP)                        \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);                                  \
        __uint(max_entries, MAX_BLOCKED_IPV4);                                 \
        __type(key, struct ipv4_rule_key);                                     \
        __type(value, struct rule_value);                                      \
        __uint(map_flags, BPF_F_NO_PREALLOC);                                 \
    } IPV4_MAP SEC(".maps");                                                   \
                                                                               \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);                                  \
        __uint(max_entries, MAX_BLOCKED_IPV6);                                 \
        __type(key, struct ipv6_rule_key);                                     \
        __type(value, struct rule_value);                                      \
        __uint(map_flags, BPF_F_NO_PREALLOC);                                 \
    } IPV6_MAP SEC(".maps");                                                   \
                                                                               \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_HASH);                                       \
        __uint(max_entries, MAX_BLOCKED_PORT);                                 \
        __type(key, struct port_rule_key);                                     \
        __type(value, struct rule_value);                                      \
    } PORT_MAP SEC(".maps")
 
/* ── Map-dependent check macros ─────────────────────────────────────────────
 *
 * The verifier requires map references to appear literally in the compiled
 * unit, so these must be macros rather than functions.
 *
 * Usage:
 *   if (CHECK_IP4_BLOCKLIST(my_ipv4_map, addr)) { ... }
 */
#define CHECK_IP4_BLOCKLIST(map, _addr)                                        \
    ({                                                                         \
        struct ipv4_rule_key _k4 = { .prefixlen = 32, .addr = (_addr) };      \
        struct rule_value *_rv = bpf_map_lookup_elem(&(map), &_k4);          \
        (_rv && _rv->action == RULE_ACTION_DROP) ? 1 : 0;                    \
    })
 
#define CHECK_IP6_BLOCKLIST(map, _addr)                                        \
    ({                                                                         \
        struct ipv6_rule_key _k6 = { .prefixlen = 128, .addr = (_addr) };     \
        struct rule_value *_rv = bpf_map_lookup_elem(&(map), &_k6);          \
        (_rv && _rv->action == RULE_ACTION_DROP) ? 1 : 0;                    \
    })

#define CHECK_IP_BLOCKLIST(ip, ip_type, ipv4_map, ipv6_map)            \
({                                                                  \
    __u8 _blocked = 0;                                             \
    if ((ip_type) == IPTYPE_IPV4)                                  \
        _blocked = CHECK_IP4_BLOCKLIST(ipv4_map,                   \
                        ((struct iphdr *)(ip))->daddr);             \
    else if ((ip_type) == IPTYPE_IPV6)                             \
        _blocked = CHECK_IP6_BLOCKLIST(ipv6_map,                   \
                        ((struct ipv6hdr *)(ip))->daddr);           \
    _blocked;                                                       \
})
 
#define CHECK_PORT_BLOCKLIST(map, _port, l4_proto)                               \
    ({                                                                         \
        struct port_rule_key _kp = { .port = (_port) };                       \
        if (l4_proto == IPPROTO_TCP || l4_proto == IPPROTO_UDP ) {            \
            struct rule_value *_rv = bpf_map_lookup_elem(&(map), &_kp);          \
            (_rv && _rv->action == RULE_ACTION_DROP) ? 1 : 0;                   \
        }                                                                   \
        0;                                                                  \
    })

static __always_inline int
extract_transport_ports(void *ip_hdr, void *data_end, int ip_type,
                        __u16 *sport, __u16 *dport, __u8 *proto_out)
{
    *sport = 0;
    *dport = 0;
    void  *cursor;
    __u8   protocol;
 
    if (ip_type == IPTYPE_IPV4) {
        struct iphdr *ip = (struct iphdr *)ip_hdr;
        protocol = ip->protocol;
        cursor   = (void *)ip + ip->ihl * 4;
    } else if (ip_type == IPTYPE_IPV6) {
        struct ipv6hdr *ip = (struct ipv6hdr *)ip_hdr;
        protocol = ip->nexthdr;
        cursor   = (void *)(ip + 1);
 
        #pragma unroll
        for (int i = 0; i < MAX_IPV6_EXT_HDRS; i++) {
            if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
                break;
            if (protocol == IPPROTO_HOPOPTS ||
                protocol == IPPROTO_ROUTING ||
                protocol == IPPROTO_DSTOPTS) {
                struct ipv6_opt_hdr *exh = (struct ipv6_opt_hdr *)cursor;
                if ((void *)(exh + 1) > data_end) return 0;
                protocol = exh->nexthdr;
                cursor  += (exh->hdrlen + 1) * 8;
            } else if (protocol == IPPROTO_FRAGMENT) {
                /* ipv6_frag_hdr has the same first two bytes as ipv6_opt_hdr */
                struct ipv6_opt_hdr *frag = (struct ipv6_opt_hdr *)cursor;
                if ((void *)(frag + 1) > data_end) return 0;
                protocol = frag->nexthdr;
                cursor  += 8;
            } else {
                return 0;
            }
        }
    } else {
        return 0;
    }
 
    if (proto_out)
        *proto_out = protocol;
 
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)cursor;
        if ((void *)(tcp + 1) > data_end) return 0;
        *sport = tcp->source;
        *dport = tcp->dest;
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)cursor;
        if ((void *)(udp + 1) > data_end) return 0;
        *sport = udp->source;
        *dport = udp->dest;
    } else {
        return 0;
    }
 
    return 1;
}

static __always_inline void
fill_event(struct event *ev, 
           void *ip, int ip_type,
           __u16 sport, __u16 dport, __u8 protocol,
           __u8 is_ip_blocked, __u8 event_type)
{
    ev->id         = ev->id = bpf_ktime_get_ns();
    ev->ip_type    = ip_type;
    ev->src_port   = sport;
    ev->dst_port   = dport;
    ev->protocol   = protocol;
    ev->event_type = event_type;

    if (ip_type == IPTYPE_IPV4) {
        struct iphdr *ip4 = (struct iphdr *)ip;
        ev->src_ip[0] = ip4->saddr;
        ev->src_ip[1] = ev->src_ip[2] = ev->src_ip[3] = 0;
        ev->dst_ip[0] = ip4->daddr;
        ev->dst_ip[1] = ev->dst_ip[2] = ev->dst_ip[3] = 0;
        ev->reason = is_ip_blocked
            ? (event_type == EGRESS_BLOCKED_EVENT
                ? EGRESS_BLOCK_REASON_DST_IPV4
                : INGRESS_BLOCK_REASON_SRC_IPV4)
            : (event_type == EGRESS_BLOCKED_EVENT
                ? EGRESS_BLOCK_REASON_DST_PORT
                : INGRESS_BLOCK_REASON_SRC_PORT);
    } else {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)ip;
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            ev->src_ip[i] = ip6->saddr.s6_addr32[i];
            ev->dst_ip[i] = ip6->daddr.s6_addr32[i];
        }
        ev->reason = is_ip_blocked
            ? (event_type == EGRESS_BLOCKED_EVENT
                ? EGRESS_BLOCK_REASON_DST_IPV6
                : INGRESS_BLOCK_REASON_SRC_IPV6)
            : (event_type == EGRESS_BLOCKED_EVENT
                ? EGRESS_BLOCK_REASON_DST_PORT
                : INGRESS_BLOCK_REASON_SRC_PORT);
    }
}

#define send_event(ip, ip_type,                            \
                   sport, dport, protocol,                             \
                   is_ip_blocked, event_type)                          \
    do {                                                               \
        struct event *_ev = bpf_ringbuf_reserve(                       \
                &EVENT_LOG_MAP_ID, sizeof(*_ev), 0);                   \
        if (_ev) {                                                      \
            fill_event(_ev, ip, ip_type,                \
                       sport, dport, protocol,                         \
                       is_ip_blocked, event_type);                     \
            bpf_ringbuf_submit(_ev, 0);                                \
        }                                                              \
    } while (0)

struct parse_result {
    __s8  protocol;
    __u8  ip_type;
};

#define PARSE_RESULT_INVALID ((struct parse_result){ .protocol = -1, .ip_type = 0 })

static __always_inline struct parse_result
parse_ip(void *ip, void *data_end, __u16 h_proto)
{
    if (h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip4 = (struct iphdr *)ip;
        if ((void *)(ip4 + 1) > data_end) return PARSE_RESULT_INVALID;
        return (struct parse_result){
            .protocol = ip4->protocol,
            .ip_type  = IPTYPE_IPV4
        };
    } else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)ip;
        if ((void *)(ip6 + 1) > data_end) return PARSE_RESULT_INVALID;
        return (struct parse_result){
            .protocol = ip6->nexthdr,
            .ip_type  = IPTYPE_IPV6
        };
    }
    return PARSE_RESULT_INVALID;
}

#endif