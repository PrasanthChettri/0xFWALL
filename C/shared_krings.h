
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024); // 8 MiB
} EVENT_LOG_MAP_ID SEC(".maps");
