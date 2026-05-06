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

struct bpf_metadata {
    struct bpf_object *ingress_obj;
    struct bpf_object *egress_obj;
    struct bpf_program *ingress_prog;
    struct bpf_program *egress_prog;

    int ingress_prog_fd, ingress_ifindex, ingress_ip_rule_map_fd, ingress_port_rule_map_fd;
    int egress_prog_fd, egress_ifindex, egress_ip_rule_map_fd, egress_port_rule_map_fd;

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
    struct bpf_map *ip_rule_map, *port_rule_map, *log_map;

    bm->ingress_obj = bpf_object__open(obj_path);
    if (libbpf_get_error(bm->ingress_obj)) {
        return -1;
    }

    err = bpf_object__load(bm->ingress_obj);
    if (err) {
        return err;
    }

    ip_rule_map = bpf_object__find_map_by_name(bm->ingress_obj, INGRESS_IPV4_RULE_MAP_ALIAS);
    port_rule_map = bpf_object__find_map_by_name(bm->ingress_obj, INGRESS_PORT_RULE_MAP_ALIAS);
    log_map = bpf_object__find_map_by_name(bm->ingress_obj, EVENT_LOG_MAP_ALIAS);

    if (!ip_rule_map || !log_map || !port_rule_map) {
        return -1;
    }

    bm->ingress_ip_rule_map_fd = bpf_map__fd(ip_rule_map);
    bm->ingress_port_rule_map_fd = bpf_map__fd(port_rule_map);
    bm->log_map_fd = bpf_map__fd(log_map);
    
    bm->log_rb = ring_buffer__new(bm->log_map_fd, handle_log_rb, bm, NULL);
    if (bm->ingress_port_rule_map_fd < 0 || bm->ingress_ip_rule_map_fd < 0 || bm->log_map_fd < 0 || !bm->log_rb) {
        return -1;
    }

    bm->ingress_prog = bpf_object__find_program_by_name(bm->ingress_obj, INGRESS_PROG_NAME);
    if (!bm->ingress_prog) {
        return -1;
    }
    bm->ingress_prog_fd = bpf_program__fd(bm->ingress_prog);

    bm->ingress_ifindex = if_nametoindex(ifname);
    if (!bm->ingress_ifindex) {
        return -1;
    }

    err = bpf_xdp_attach(bm->ingress_ifindex, bm->ingress_prog_fd, 0, NULL);
    return err;
}

int load_tc(const char* obj_path, const char* ifname) {
    int err;
    struct bpf_map *ip_rule_map, *port_rule_map, *log_map;

    bm->egress_obj = bpf_object__open(obj_path);
    if (libbpf_get_error(bm->egress_obj)) {
        return -1;
    }

    /* Reuse log map from XDP */
    log_map = bpf_object__find_map_by_name(bm->egress_obj, EVENT_LOG_MAP_ALIAS);
    if (log_map && bm->log_map_fd >= 0) {
        err = bpf_map__reuse_fd(log_map, bm->log_map_fd);
        if (err) {
            return err;
        }
    }

    err = bpf_object__load(bm->egress_obj);
    if (err) {
        return err;
    }

    ip_rule_map = bpf_object__find_map_by_name(bm->egress_obj, EGRESS_IPV4_RULE_MAP_ALIAS);
    port_rule_map = bpf_object__find_map_by_name(bm->egress_obj, EGRESS_PORT_RULE_MAP_ALIAS);
    
    if (!ip_rule_map || !port_rule_map) {
        return -1;
    }

    bm->egress_ip_rule_map_fd = bpf_map__fd(ip_rule_map);
    bm->egress_port_rule_map_fd = bpf_map__fd(port_rule_map);

    bm->egress_prog = bpf_object__find_program_by_name(bm->egress_obj, EGRESS_PROG_NAME);
    if (!bm->egress_prog) {
        return -1;
    }
    bm->egress_prog_fd = bpf_program__fd(bm->egress_prog);

    bm->egress_ifindex = if_nametoindex(ifname);
    if (!bm->egress_ifindex) {
        return -1;
    }

    // TC attachment logic
    struct bpf_tc_hook tc_hook;
    memset(&tc_hook, 0, sizeof(tc_hook));
    tc_hook.sz = sizeof(tc_hook);
    tc_hook.ifindex = bm->egress_ifindex;
    tc_hook.attach_point = BPF_TC_EGRESS;

    err = bpf_tc_hook_create(&tc_hook);
    if (err){
        return err;
    }

    struct bpf_tc_opts tc_opts;
    memset(&tc_opts, 0, sizeof(tc_opts));
    tc_opts.sz = sizeof(tc_opts);
    tc_opts.prog_fd = bm->egress_prog_fd;

    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        return err;
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

    if (bpf_md_s->ingress_ifindex > 0) {
        bpf_xdp_detach(bpf_md_s->ingress_ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    }
    if (bpf_md_s->egress_ifindex > 0 && bpf_md_s->egress_prog_fd > 0) {
        struct bpf_tc_hook tc_hook;
        memset(&tc_hook, 0, sizeof(tc_hook));
        tc_hook.sz = sizeof(tc_hook);
        tc_hook.ifindex = bpf_md_s->egress_ifindex;
        tc_hook.attach_point = BPF_TC_EGRESS;

        struct bpf_tc_opts tc_opts;
        memset(&tc_opts, 0, sizeof(tc_opts));
        tc_opts.sz = sizeof(tc_opts);
        tc_opts.prog_fd = bpf_md_s->egress_prog_fd;

        bpf_tc_detach(&tc_hook, &tc_opts);
    }

    if (bpf_md_s->ingress_obj) {
        bpf_object__close(bpf_md_s->ingress_obj);
    }
    if (bpf_md_s->egress_obj) {
        bpf_object__close(bpf_md_s->egress_obj);
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

    int fd = (direction == RULE_DIRECTION_INGRESS) ? bm->ingress_ip_rule_map_fd : bm->egress_ip_rule_map_fd;
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

int load_ingress_rules(const struct rule_table* rt) {
    if (!bm || !rt->ipv4_list || !rt->ipv4_prefix_len || !rt->port_list) {
        return -1;
    }
    
    struct rule_value value = {
        .action = RULE_ACTION_DROP,
    };
    
    for (int i = 0; i < rt->ipv4_count; i++) {
        struct ipv4_rule_key key = {
            .prefixlen = rt->ipv4_prefix_len[i],
            .addr = rt->ipv4_list[i],
        };
        if (bm->ingress_ip_rule_map_fd > 0) {
            bpf_map_update_elem(bm->ingress_ip_rule_map_fd, &key, &value, BPF_ANY);
        }
    }
    
    for (int i = 0; i < rt->port_count; i++) {
        struct port_rule_key p_key = {
            .port = rt->port_list[i],
        };
        if (bm->ingress_port_rule_map_fd > 0) {
            bpf_map_update_elem(bm->ingress_port_rule_map_fd, &p_key, &value, BPF_ANY);
        }
    }
    
    return 0;
}

int load_egress_rules(const struct rule_table* rt) {
    if (!bm || !rt->ipv4_list || !rt->ipv4_prefix_len || !rt->port_list) {
        return -1;
    }
    
    struct rule_value value = {
        .action = RULE_ACTION_DROP,
    };
    
    for (int i = 0; i < rt->ipv4_count; i++) {
        struct ipv4_rule_key key = {
            .prefixlen = rt->ipv4_prefix_len[i],
            .addr = rt->ipv4_list[i],
        };
        if (bm->egress_ip_rule_map_fd > 0) {
            bpf_map_update_elem(bm->egress_ip_rule_map_fd, &key, &value, BPF_ANY);
        }
    }
    
    for (int i = 0; i < rt->port_count; i++) {
        struct port_rule_key p_key = {
            .port = rt->port_list[i],
        };
        if (bm->egress_port_rule_map_fd > 0) {
            bpf_map_update_elem(bm->egress_port_rule_map_fd, &p_key, &value, BPF_ANY);
        }
    }
    
    return 0;
}
