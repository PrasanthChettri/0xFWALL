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
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, ifindex, ip_rule_map_fd, port_rule_map_fd, ip_log_map_fd;
    struct ring_buffer *ip_log_rb ; 
    struct blocked_ip_event *latest_bie ;
    struct blocked_port_event *latest_bpe ;
    pthread_mutex_t ip_log_rb_lock;
} ;

struct bpf_metadata *bm ; 

struct bpf_metadata* get_bpf_obj(void) {
    if (!bm) { return NULL; }
    return bm ; 
}

void cleanup(void *) ; 
int handle_ip_log_rb(void *ctx, void *data, size_t len) {
    struct bpf_metadata *bpf_md = (struct bpf_metadata *)ctx;
    const struct blocked_ip_event *event = (const struct blocked_ip_event *)data;

    if (!bpf_md || !bpf_md->latest_bie || !data) {
        return -1;
    }

    if (len != sizeof(struct blocked_ip_event)) {
        return -1;
    }

    memcpy(bpf_md->latest_bie, event, sizeof(*event));
    return 0;
}


int load_xdp(const char *obj_path, const char *ifname)
{
    int err;
    struct bpf_map *ip_rule_map, *port_rule_map, *log_map; // Pointer to hold the map object
    bm = malloc(sizeof(struct bpf_metadata)) ; 
    if (!bm) {
        return -1;
    }
    memset(bm, 0, sizeof(*bm));
    err = pthread_mutex_init(&bm->ip_log_rb_lock, NULL);
    if (err != 0) {
        free(bm);
        bm = NULL;
        return -1;
    }

    /* ── Step 1: Load ELF object into memory & run verifier ── */
    bm->obj = bpf_object__open(obj_path);          // parse ELF, resolve BTF
    if (libbpf_get_error(bm->obj))
        return -1;

    err = bpf_object__load(bm->obj);               // bpf(BPF_PROG_LOAD) syscall
    if (err) {                                   // verifier runs here 
        cleanup((void *)bm) ;
        return err ;
    }

    // IP_RULE_MAP INGRESS
    ip_rule_map = bpf_object__find_map_by_name(bm->obj, IPV4_RULE_MAP_ALIAS);
    // PORT RULE MAP INGRESS
    port_rule_map = bpf_object__find_map_by_name(bm->obj, PORT_RULE_MAP_ALIAS);
    // LOG MAP
    log_map = bpf_object__find_map_by_name(bm->obj, IP_LOG_MAP_ALIAS);
    if (!ip_rule_map || !log_map || !port_rule_map) {
        err = -1;
        cleanup((void *)bm);
        return err;
    }
    
    bm->ip_rule_map_fd = bpf_map__fd(ip_rule_map);
    bm->ip_log_map_fd = bpf_map__fd(log_map);
    bm->port_rule_map_fd = bpf_map__fd(port_rule_map);
    bm->ip_log_rb = ring_buffer__new(bm->ip_log_map_fd , handle_ip_log_rb, bm, NULL);
    if (bm->port_rule_map_fd < 0 || bm->ip_rule_map_fd < 0 || bm->ip_log_map_fd < 0) {
        err = -1;
        cleanup((void *)bm);
        return err;
    }

    bm->prog = bpf_object__find_program_by_name(bm->obj, PROG_NAME); // or by section
    if (!bm->prog) {
        err = -1;
        cleanup((void *) bm);
        return err ;
    }
    bm->prog_fd = bpf_program__fd(bm->prog);

    bm->ifindex = if_nametoindex(ifname);
    if (!bm->ifindex) {
        err = -1;
        cleanup((void *) bm) ; 
        return err ; 
    }

    err = bpf_xdp_attach(bm->ifindex, bm->prog_fd,
                          XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);

    if (err) {
        cleanup(bm) ; 
    }
    return err ;
}

void cleanup(void * bpf_md) {
    struct bpf_metadata *bpf_md_s = (struct bpf_metadata *) bpf_md ; 
    if (!bpf_md_s) {
        return;
    }
    pthread_mutex_lock(&bpf_md_s->ip_log_rb_lock);
    if (bpf_md_s->ip_log_rb) {
        ring_buffer__free(bpf_md_s->ip_log_rb);
        bpf_md_s->ip_log_rb = NULL;
    }
    bpf_md_s->latest_bie = NULL;
    pthread_mutex_unlock(&bpf_md_s->ip_log_rb_lock);
    pthread_mutex_destroy(&bpf_md_s->ip_log_rb_lock);
    bpf_xdp_detach(bpf_md_s->ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    bpf_object__close(bpf_md_s->obj);
    free(bpf_md_s) ; 
}

int poll_logs(void * bpf_md, struct blocked_ip_event *bie,  int ms) {
    struct bpf_metadata *bpf_md_s = (struct bpf_metadata *) bpf_md ; 
    int err;

    if (!bpf_md_s || !bie || !bpf_md_s->ip_log_rb) {
        return -1;
    }

    pthread_mutex_lock(&bpf_md_s->ip_log_rb_lock);
    bpf_md_s->latest_bie = bie;
    err = ring_buffer__poll(bpf_md_s->ip_log_rb, ms);
    bpf_md_s->latest_bie = NULL;
    pthread_mutex_unlock(&bpf_md_s->ip_log_rb_lock);
    return err ; 
}


int load_rules(const struct rule_table* rt) {
    if (!bm->ip_rule_map_fd || !rt->ipv4_list || !rt->port_list || !bm->prog_fd) {
        printf("EEE") ; 
        return -1 ;
    }
    struct rule_value value = {
        .action = RULE_ACTION_DROP,
    };
    for(int i = 0 ; i < rt->ipv4_count ; i++) {
        struct ipv4_rule_key key = {
            .addr = rt->ipv4_list[i],
        };
        int err = bpf_map_update_elem(bm->ip_rule_map_fd, &key, &value, BPF_ANY) ; 
        printf("FFF") ; 
        if (err != 0 ) {
            return err ; 
        }
    }
    for(int i = 0 ; i < rt->port_count ; i++) {
        struct port_rule_key p_key = {
            .port = rt->port_list[i],
        };
        printf("\n\n%d\n\n", rt->port_list[i]);
        int err = bpf_map_update_elem(bm->port_rule_map_fd, &p_key, &value, BPF_ANY) ; 
        printf("\n%d\n", err) ; 
        if (err != 0) {
            return err ; 
        }
        printf("GGGG") ; 
    }
    return 0 ;
}
