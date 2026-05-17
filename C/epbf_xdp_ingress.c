#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include "shared.h"
#include "shared_krings.h"
#include "epbf_helpers.h"

DEFINE_RULE_MAPS(INGRESS_IPV4_RULE_MAP_ID,
                 INGRESS_IPV6_RULE_MAP_ID,
                 INGRESS_PORT_RULE_MAP_ID);

SEC("xdp")
int INGRESS_PROG_ID(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    void *ip = data + sizeof(*eth);
    struct parse_result pr = parse_ip(ip, data_end, eth->h_proto);
    if (pr.protocol == -1)
        return XDP_PASS;

    __u8 is_ip_blocked = CHECK_IP_BLOCKLIST(ip, pr.ip_type,
                                            INGRESS_IPV4_RULE_MAP_ID,
                                            INGRESS_IPV6_RULE_MAP_ID, saddr);

    __u16 sport = 0, dport = 0;
    __u8 l4_proto = 0;
    extract_transport_ports(ip, data_end, pr.ip_type, &sport, &dport, &l4_proto);
    __u8 is_port_blocked = CHECK_PORT_BLOCKLIST(INGRESS_PORT_RULE_MAP_ID, dport, l4_proto);

    if (is_ip_blocked | is_port_blocked) {
        send_event(ip, pr.ip_type, sport, dport, l4_proto,
                   is_ip_blocked, INGRESS_BLOCKED_EVENT);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
