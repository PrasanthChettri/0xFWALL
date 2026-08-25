# 0xFWALL — Project Setup & Developer Environment Guide

This guide provides complete instructions for setting up the developer environment, installing required toolchains, compiling eBPF kernel hooks, and building/running the Rust userspace daemon.

---

## 1. System Requirements & Architecture

* **Operating System**: Linux (Kernel 5.8+ recommended for modern XDP, TCX, and ring buffer support).
* **Core Components**:
  * **C Kernel Hooks & Loader (`C/`)**:
    * `clang` (with BPF target support)
    * `bpftool` (with skeleton generation capability)
    * `libbpf-dev` headers & library
  * **Rust Userspace Daemon (`Rust_US/`)**:
    * `rustc` & `cargo` (Rust 2024 edition / latest stable)
  * **Runtime Requirements**:
    * Root access or capabilities (`CAP_BPF`, `CAP_NET_ADMIN`) to attach XDP and TC programs to network interfaces.

---

## 2. Toolchain Installation

### Option A: Standard System Package Installation (with sudo)

```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    libbpf1 \
    bpftool \
    libelf-dev \
    iproute2 \
    make \
    pkg-config

# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

---

### Option B: User-Local Installation (without sudo)

If developing in an unprivileged environment or container, the toolchains are installed into `~/.local` and `~/.cargo`:

```bash
# 1. Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# 2. Add Environment Variables to ~/.bashrc
cat << 'EOF' >> ~/.bashrc
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export C_INCLUDE_PATH="$HOME/.local/include:$HOME/.local/usr/include:$C_INCLUDE_PATH"
export LIBRARY_PATH="$HOME/.local/lib:$HOME/.local/usr/lib/x86_64-linux-gnu:$LIBRARY_PATH"
EOF
source ~/.bashrc
```

---

## 3. Building the Project

The build process involves two steps: compiling the C eBPF objects and static loader, then building the Rust daemon.

```
Step 1: make -C C
        ├── Compiles epbf_xdp_ingress.o (XDP Hook)
        ├── Compiles epbf_tc_egress.o (TC Hook)
        ├── Generates skeleton headers via bpftool
        └── Compiles loader.c into libloader.a
                 │
                 ▼
Step 2: cargo build (Rust_US/)
        ├── Links against C/target/libloader.a & libbpf
        └── Produces executable daemon: Rust_US
```

### Step 1: Compile C eBPF Bytecode & Loader Library
```bash
make -C C
```

**Expected output:**
```
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c epbf_xdp_ingress.c -o target/epbf_xdp_ingress.o
bpftool gen skeleton target/epbf_xdp_ingress.o > target/epbf_xdp_ingress.skel.h
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c epbf_tc_egress.c -o target/epbf_tc_egress.o
bpftool gen skeleton target/epbf_tc_egress.o > target/epbf_tc_egress.skel.h
clang -O2 -g -c loader.c -o ./target/loader.o
ar rcs target/libloader.a ./target/loader.o
Build complete: eBPF objects, skeletons, and libloader.a stored in ./target
```

### Step 2: Build the Rust Daemon
```bash
cd Rust_US
cargo build
```

---

## 4. Configuration

### 4.1 `Rust_US/config.yaml`
Configures filepaths, logging, and target network interface:

```yaml
epbf_path_ingress: "../C/target/epbf_xdp_ingress.o"
epbf_path_egress:  "../C/target/epbf_tc_egress.o"
rules_path: "rules.json"
log_path:   "blocked.log"
interface:  "eth0"   # Change to your target interface (e.g. ens33, wlan0, lo)
```

### 4.2 `Rust_US/rules.json`
Defines active blocking rules:

```json
{
  "ingress": {
    "blocked_ipv4": [
      "192.168.1.100/32",
      "10.0.0.0/8"
    ],
    "blocked_ipv6": [
      "2001:db8::/32"
    ],
    "blocked_ports": [
      22,
      23,
      8080
    ]
  },
  "egress": {
    "blocked_ipv4": [],
    "blocked_ipv6": [],
    "blocked_ports": []
  }
}
```

---

## 5. Running & Managing the Firewall

### Starting the Firewall
eBPF requires elevated privileges to attach hooks to network interfaces:

```bash
cd Rust_US
sudo ./target/debug/Rust_US
```

### Live Rule Reloading (Without Restarting)
When `rules.json` is modified, send a `SIGHUP` signal to the running daemon. The daemon calculates the exact rule diff (upserts/deletions) and pushes only modified entries to the kernel BPF maps:

```bash
# Using helper script
python3 reload_firewall.py

# Or via kill
sudo kill -HUP $(pgrep Rust_US)
```

### Stopping the Firewall
Press `Ctrl + C` or send `SIGINT`/`SIGTERM`:
```bash
sudo kill -INT $(pgrep Rust_US)
```
*Thanks to `bpf_link` usage, all attached XDP and TC hooks automatically detach from the network interface on exit.*

### Inspecting Blocked Packet Logs
```bash
tail -f Rust_US/blocked.log
```
Example log entry:
```text
[2026-08-25 14:30:00.123][EVENT] ID: 104   | TYPE: 1  | SRC: 192.168.1.100:44321 | DST: 192.168.1.1:80 | PROTO:   6 | REASON: IP_BLOCK_INGRESS_V4
```

---

## 6. Developer IDE (Neovim) Setup

A preconfigured Neovim environment (v0.12.5) with full LSP, autocompletion, and treesitter is available.

Launch Neovim:
```bash
nvim
```

### Included Features:
* **`rust-analyzer`**: Code completion, diagnostics, and inline hints for Rust.
* **`clangd`**: Code completion and type checking for C and eBPF files.
* **`nvim-tree`**: File explorer (`<Space> e` to toggle).
* **Key Shortcuts**:
  * `gd`: Go to definition
  * `K`: Hover documentation
  * `<Space> f`: Format file
  * `<Space> ca`: Code actions
  * `[d` / `]d`: Jump diagnostics
