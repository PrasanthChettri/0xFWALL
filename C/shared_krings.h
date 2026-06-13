#ifndef SHARED_KRINGS
#define SHARED_KRINGS
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024); // 8 MiB
} EVENT_LOG_MAP_ID SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH) ; 
    __uint(max_entries, 65536) ; 
    __type(key, struct conn_key) ; 
    __type(value, __u8) ; 
} CONNTRACK_MAP SEC(".maps") ; 
#endif
