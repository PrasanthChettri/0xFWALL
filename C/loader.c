#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include "shared.h"

struct bpf_metadata {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, ifindex, rule_map_fd, ip_log_map_fd;
    struct ring_buffer *ip_log_rb ; 
    struct blocked_ip_event *latest_bie ;

} ;

struct bpf_metadata *bm ; 

struct bpf_metadata* get_bpf_obj(void) {
    if (!bm) { return NULL; }
    return bm ; 
}

void cleanup(void *) ; 
int handle_ip_log_rb(void *ctx, void *data, size_t len) {
    struct bpf_metadata *bpf_md = (struct bpf_metadata *)ctx;
    const struct blocked_ip_event *event = (const struct blocked_ip_event *)data  ;
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
    struct bpf_map *rule_map, *log_map; // Pointer to hold the map object
    bm = malloc(sizeof(struct bpf_metadata)) ; 

    /* ── Step 1: Load ELF object into memory & run verifier ── */
    bm->obj = bpf_object__open(obj_path);          // parse ELF, resolve BTF
    if (libbpf_get_error(bm->obj))
        return -1;

    err = bpf_object__load(bm->obj);               // bpf(BPF_PROG_LOAD) syscall
    if (err) {                                   // verifier runs here 
        cleanup((void *)bm) ;
        return err ;
    }

    rule_map = bpf_object__find_map_by_name(bm->obj, RULE_MAP_ALIAS);
    log_map = bpf_object__find_map_by_name(bm->obj, IP_LOG_MAP_ALIAS);
    if (!rule_map) {
        err = -1;
        cleanup((void *)bm);
        return err;
    }
    
    bm->rule_map_fd = bpf_map__fd(rule_map);
    bm->ip_log_map_fd = bpf_map__fd(log_map);
    bm->ip_log_rb = ring_buffer__new(bm->ip_log_map_fd , handle_ip_log_rb, bm, NULL);
    if (bm->rule_map_fd < 0 || bm->ip_log_map_fd < 0) {
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
    bpf_xdp_detach(bpf_md_s->ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    bpf_object__close(bpf_md_s->obj);
    free(bpf_md_s) ; 
}

int poll_logs(void * bpf_md, struct blocked_ip_event *bie,  int ms) {
    struct bpf_metadata *bpf_md_s = (struct bpf_metadata *) bpf_md ; 
    int err = ring_buffer__poll(bpf_md_s->ip_log_rb, ms);
    bie = bpf_md_s->latest_bie ; 
    return err ; 
}


int load_rules(const struct rule_table* rt) {
    if (!bm->rule_map_fd || !rt->ipv4_list || !bm->prog_fd) {
        return -1 ;
    }
    printf("\n%p\n%u\n", rt->ipv4_list, *(rt->ipv4_list)) ;
    __u8 SET = 1 ; 
    for(int i = 0 ; i < rt->ipv4_count ; i++) {
        int err = bpf_map_update_elem(bm->rule_map_fd, &(rt->ipv4_list[i]), &SET, BPF_ANY) ; 
        if (err != 0 ) {
            return err ; 
        }
    }
    return 0 ;
}
