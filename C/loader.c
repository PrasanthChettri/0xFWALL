#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include "shared.h"
#include "target/epbf_xdp_ingress.skel.h"
#include "target/epbf_tc_egress.skel.h"

struct bpf_metadata {
    struct epbf_xdp_ingress *ingress_skel;
    struct epbf_tc_egress *egress_skel;

    int ingress_ifindex, ingress_ipv4_rule_map_fd, ingress_ipv6_rule_map_fd, ingress_port_rule_map_fd;
    int egress_ifindex, egress_ipv4_rule_map_fd, egress_ipv6_rule_map_fd, egress_port_rule_map_fd;
    
    int log_map_fd;
    struct ring_buffer *log_rb;
    struct event *latest_event;
    pthread_mutex_t log_rb_lock;
};

struct bpf_metadata *bm;

struct bpf_metadata* get_bpf_obj(void) {
    if (!bm) { return NULL; }
    return bm;
}

void cleanup(void *);

int handle_log_rb(void *ctx, void *data, size_t len) {
    struct bpf_metadata *bpf_md = (struct bpf_metadata *)ctx;
    const struct event *event = (const struct event *)data;

    if (!bpf_md || !bpf_md->latest_event || !data) {
        return -1;
    }

    if (len != sizeof(struct event)) {
        return -1;
    }

    memcpy(bpf_md->latest_event, event, sizeof(*event));
    return 0;
}

int load_xdp(const char *obj_path, const char *ifname) {
    int err;

    bm->ingress_skel = epbf_xdp_ingress__open();
    if (!bm->ingress_skel) {
        return -1;
    }

    err = epbf_xdp_ingress__load(bm->ingress_skel);
    if (err) {
        return err;
    }

    bm->ingress_ipv4_rule_map_fd = bpf_map__fd(bm->ingress_skel->maps.ingress_ipv4_rule_table);
    bm->ingress_ipv6_rule_map_fd = bpf_map__fd(bm->ingress_skel->maps.ingress_ipv6_rule_table);
    bm->ingress_port_rule_map_fd = bpf_map__fd(bm->ingress_skel->maps.ingress_port_rule_table);
    bm->log_map_fd = bpf_map__fd(bm->ingress_skel->maps.events);
    
    bm->log_rb = ring_buffer__new(bm->log_map_fd, handle_log_rb, bm, NULL);
    if (bm->ingress_port_rule_map_fd < 0 || bm->ingress_ipv4_rule_map_fd < 0 || bm->ingress_ipv6_rule_map_fd < 0 || bm->log_map_fd < 0 || !bm->log_rb) {
        return -1;
    }

    bm->ingress_ifindex = if_nametoindex(ifname);
    if (!bm->ingress_ifindex) {
        return -1;
    }

    bm->ingress_skel->links.xdp_prog = bpf_program__attach_xdp(bm->ingress_skel->progs.xdp_prog, bm->ingress_ifindex);
    if (libbpf_get_error(bm->ingress_skel->links.xdp_prog)) {
        return -1;
    }
    return 0;
}

int load_tc(const char* obj_path, const char* ifname) {
    int err;

    bm->egress_skel = epbf_tc_egress__open();
    if (!bm->egress_skel) {
        return -1;
    }

    /* Reuse log map from XDP */
    if (bm->log_map_fd >= 0) {
        err = bpf_map__reuse_fd(bm->egress_skel->maps.events, bm->log_map_fd);
        if (err) {
            return err;
        }
    }

    err = epbf_tc_egress__load(bm->egress_skel);
    if (err) {
        return err;
    }

    bm->egress_ipv4_rule_map_fd = bpf_map__fd(bm->egress_skel->maps.egress_ipv4_rule_table);
    bm->egress_ipv6_rule_map_fd = bpf_map__fd(bm->egress_skel->maps.egress_ipv6_rule_table);
    bm->egress_port_rule_map_fd = bpf_map__fd(bm->egress_skel->maps.egress_port_rule_table);

    bm->egress_ifindex = if_nametoindex(ifname);
    if (!bm->egress_ifindex) {
        return -1;
    }
    
    bm->egress_skel->links.tc_prog = bpf_program__attach_tcx(bm->egress_skel->progs.tc_prog, bm->egress_ifindex, NULL); 
    if (libbpf_get_error(bm->egress_skel->links.tc_prog)) {
        return -1;
    }

    return 0;
}

int load_epbf(const char *xdp_path, const char *tc_path, const char *ifname) {
    int err;
    
    bm = malloc(sizeof(struct bpf_metadata));
    if (!bm) {
        return -1;
    }
    memset(bm, 0, sizeof(*bm));
    
    err = pthread_mutex_init(&bm->log_rb_lock, NULL);
    if (err != 0) {
        free(bm);
        bm = NULL;
        return -1;
    }

    err = load_xdp(xdp_path, ifname);
    if (err) {
        cleanup(bm);
        return err;
    }

    err = load_tc(tc_path, ifname);
    if (err) {
        cleanup(bm);
        return err;
    }

    return 0;
}

void cleanup(void *bpf_md) {
    struct bpf_metadata *bpf_md_s = (struct bpf_metadata *)bpf_md;
    if (!bpf_md_s) {
        return;
    }
    
    pthread_mutex_lock(&bpf_md_s->log_rb_lock);
    if (bpf_md_s->log_rb) {
        ring_buffer__free(bpf_md_s->log_rb);
        bpf_md_s->log_rb = NULL;
    }
    bpf_md_s->latest_event = NULL;
    pthread_mutex_unlock(&bpf_md_s->log_rb_lock);
    pthread_mutex_destroy(&bpf_md_s->log_rb_lock);

    if (bpf_md_s->ingress_skel) {
        epbf_xdp_ingress__destroy(bpf_md_s->ingress_skel);
    }
    if (bpf_md_s->egress_skel) {
        epbf_tc_egress__destroy(bpf_md_s->egress_skel);
    }
    
    free(bpf_md_s);
    bm = NULL;
}

int poll_logs(void *bpf_md, struct event *event, int ms) {
    struct bpf_metadata *bpf_md_s = (struct bpf_metadata *)bpf_md;
    int err;

    if (!bpf_md_s || !event || !bpf_md_s->log_rb) {
        return -1;
    }

    pthread_mutex_lock(&bpf_md_s->log_rb_lock);
    bpf_md_s->latest_event = event;
    err = ring_buffer__poll(bpf_md_s->log_rb, ms);
    bpf_md_s->latest_event = NULL;
    pthread_mutex_unlock(&bpf_md_s->log_rb_lock);
    return err;
}

struct rule_value rval = {
    .action = RULE_ACTION_DROP,
};


// TODO : Too many branches for updation, can optimize it with specific functions and less instructions and check overhead
// for now it is fine
int manage_ipv4_rule(const struct ipv4_rule_key *rk, rule_action_t action, rule_direction_t direction) {
    if (!bm || !rk) {
        return -1;
    }

    int fd = (direction == RULE_DIRECTION_INGRESS) ? bm->ingress_ipv4_rule_map_fd : bm->egress_ipv4_rule_map_fd;
    if (fd <= 0) {
        return -1;
    }

    int status;
    switch (action) {
        case RULE_ACTION_UPSERT:
            status = bpf_map_update_elem(fd, rk, &rval, BPF_ANY);
            break;
        case RULE_ACTION_DELETE:
            status = bpf_map_delete_elem(fd, rk);
            break;
        default:
            status = -2;
    }
    return status;
}

int manage_ipv6_rule(const struct ipv6_rule_key *rk, rule_action_t action, rule_direction_t direction) {
    if (!bm || !rk) {
        return -1;
    }

    int fd = (direction == RULE_DIRECTION_INGRESS) ? bm->ingress_ipv6_rule_map_fd : bm->egress_ipv6_rule_map_fd;
    if (fd <= 0) {
        return -1;
    }

    int status;
    switch (action) {
        case RULE_ACTION_UPSERT:
            status = bpf_map_update_elem(fd, rk, &rval, BPF_ANY);
            break;
        case RULE_ACTION_DELETE:
            status = bpf_map_delete_elem(fd, rk);
            break;
        default:
            status = -2;
    }
    return status;
}

int manage_port_rule(const struct port_rule_key *rk, rule_action_t action, rule_direction_t direction) {
    if (!bm || !rk) {
        return -1;
    }

    int fd = (direction == RULE_DIRECTION_INGRESS) ? bm->ingress_port_rule_map_fd : bm->egress_port_rule_map_fd;
    if (fd <= 0) {
        return -1;
    }
    int status;
    switch (action) {
        case RULE_ACTION_UPSERT:
            status = bpf_map_update_elem(fd, rk, &rval, BPF_ANY);
            break;
        case RULE_ACTION_DELETE:
            status = bpf_map_delete_elem(fd, rk);
            break;
        default:
            status = -2;
    }
    return status;
}
