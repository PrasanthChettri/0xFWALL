# Variables
CLANG := clang
BPFTOOL := bpftool
AR := ar
ARCH := $(shell uname -m)
CFLAGS_BPF := -O2 -g -target bpf -I/usr/include/$(ARCH)-linux-gnu
CFLAGS_LOADER := -O2 -g

# Directories
TARGET_DIR := ./target

# Files
BPF_OBJS := $(TARGET_DIR)/epbf_xdp_ingress.o $(TARGET_DIR)/epbf_tc_egress.o
SKELS := $(TARGET_DIR)/epbf_xdp_ingress.skel.h $(TARGET_DIR)/epbf_tc_egress.skel.h
LIBLOADER := $(TARGET_DIR)/libloader.a

# Default target
all: $(TARGET_DIR) $(SKELS) $(LIBLOADER)
	@echo "Build complete: eBPF objects, skeletons, and libloader.a stored in $(TARGET_DIR)"

# Create target directory
$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

# Rule for eBPF ingress
$(TARGET_DIR)/epbf_xdp_ingress.o: epbf_xdp_ingress.c shared.h epbf_helpers.h
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

# Rule for eBPF egress
$(TARGET_DIR)/epbf_tc_egress.o: epbf_tc_egress.c shared.h epbf_helpers.h
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

# Rule for generating skeletons
$(TARGET_DIR)/%.skel.h: $(TARGET_DIR)/%.o
	$(BPFTOOL) gen skeleton $< > $@

# Rule for the static library
$(LIBLOADER): loader.c shared.h $(SKELS)
	$(CLANG) $(CFLAGS_LOADER) -c $< -o $(TARGET_DIR)/loader.o
	$(AR) rcs $@ $(TARGET_DIR)/loader.o
	rm $(TARGET_DIR)/loader.o

# Clean target
clean:
	rm -rf $(TARGET_DIR)

.PHONY: all clean
