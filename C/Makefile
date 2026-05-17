# ── Config ───────────────────────────────────────────────────────────────────
TARGET  := ./target
CLANG   := clang
BPFTOOL := /usr/lib/linux-tools/6.8.0-117-generic/bpftool
AR      := ar
ARCH    := $(shell uname -m)

BPF_CFLAGS    := -O2 -g -target bpf -I$(TARGET) -I/usr/include/$(ARCH)-linux-gnu
LOADER_CFLAGS := -O2 -g -I$(TARGET)

# ── Deliverable ───────────────────────────────────────────────────────────────
.PHONY: all clean
all: $(TARGET)/libloader.a

# ── Stage 1: vmlinux.h ────────────────────────────────────────────────────────
$(TARGET)/vmlinux.h: | $(TARGET)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ── Stage 2: BPF objects ──────────────────────────────────────────────────────
$(TARGET)/epbf_xdp_ingress.o: epbf_xdp_ingress.c shared.h epbf_helpers.h shared_krings.h $(TARGET)/vmlinux.h | $(TARGET)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(TARGET)/epbf_tc_egress.o: epbf_tc_egress.c shared.h epbf_helpers.h shared_krings.h $(TARGET)/vmlinux.h | $(TARGET)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ── Stage 3: skeletons ────────────────────────────────────────────────────────
$(TARGET)/epbf_xdp_ingress.skel.h: $(TARGET)/epbf_xdp_ingress.o
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET)/epbf_tc_egress.skel.h: $(TARGET)/epbf_tc_egress.o
	$(BPFTOOL) gen skeleton $< > $@

# ── Stage 4: loader ───────────────────────────────────────────────────────────
$(TARGET)/loader.o: loader.c shared.h $(TARGET)/epbf_xdp_ingress.skel.h $(TARGET)/epbf_tc_egress.skel.h | $(TARGET)
	$(CLANG) $(LOADER_CFLAGS) -c $< -o $@

$(TARGET)/libloader.a: $(TARGET)/loader.o
	$(AR) rcs $@ $^

# ── Utility ───────────────────────────────────────────────────────────────────
$(TARGET):
	mkdir -p $@

clean:
	rm -rf $(TARGET)