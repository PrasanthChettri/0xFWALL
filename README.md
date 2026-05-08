# 0xFWALL

A Linux firewall built on eBPF. Packets are filtered at two kernel hooks before they ever reach userspace — **XDP** on ingress, **TC** on egress.

---

## Architecture

```
                        ┌─────────────────────────────────────────┐
                        │              Linux Kernel               │
                        │                                         │
  Incoming packet ──────►  [XDP hook]  epbf_xdp_ingress.o         │
                        │      │                                  │
                        │   XDP_DROP / XDP_PASS                   │
                        │      │                                  │
                        │  kernel network stack                   │
                        │                                         │
  Outgoing packet ◄─────  [TC hook]   epbf_tc_egress.o            │
                        │      │                                  │
                        │  TC_ACT_SHOT / TC_ACT_OK                │
                        │      │                                  │
                        │  BPF Maps (rules + event ring buffer)   │
                        └──────────────┬──────────────────────────┘
                                       │  libbpf
                                       │
                        ┌──────────────▼──────────────────────────┐
                        │           loader.c  (C userspace)       │
                        │                                         │
                        │  - Loads and attaches both BPF objects  │
                        │  - Reads/writes BPF maps                │
                        │  - Polls the ring buffer                │
                        │                                         │
                        │  Compiled to: libloader.a               │
                        └──────────────┬──────────────────────────┘
                                       │  Rust FFI (extern "C")
                                       │  linked via build.rs
                                       │
                        ┌──────────────▼──────────────────────────┐
                        │         Rust daemon  (Rust_US)          │
                        │                                         │
                        │  - Owns the EPBFProgram handle          │
                        │  - Loads rules from rules.json          │
                        │  - Hot-reloads on SIGHUP                │
                        │  - Writes events to blocked.log         │
                        └─────────────────────────────────────────┘
```

The C loader (`loader.c`) is compiled as a static library (`libloader.a`). The Rust daemon links against it at build time and calls into it via `extern "C"` declarations — no subprocess, no IPC, just a direct function call across the FFI boundary. `build.rs` tells Cargo where to find the library and which symbols to link.

---

## Features

- **Dual-hook filtering** — ingress via XDP, egress via TC
- **IPv4 and CIDR blocking** — block a single IP (`/32`) or an entire range (`/8`); uses an LPM trie so prefix matching is a single map lookup
- **Port blocking** — block by destination port on both ingress and egress
- **Live rule reload** — send `SIGHUP` to apply a new `rules.json` without restarting; only changed rules are pushed to the kernel
- **Event logging** — every blocked packet is written to a log file with timestamp, src/dst IP:port, protocol, and block reason
- **Automatic kernel cleanup** — programs are attached via `bpf_link`, so they detach from the interface automatically if the daemon exits for any reason

---


## Configuration

**`config.yaml`** — paths and interface:
```yaml
epbf_path_ingress: "../C/target/epbf_xdp_ingress.o"
epbf_path_egress:  "../C/target/epbf_tc_egress.o"
rules_path: "rules.json"
log_path:   "blocked.log"
interface:  "eth0"
```

**`rules.json`** — what to block:
```json
{
  "ingress": {
    "blocked_ipv4": ["192.168.1.100/32", "10.0.0.0/8"],
    "blocked_ports": [22, 23]
  },
  "egress": {
    "blocked_ipv4": [],
    "blocked_ports": []
  }
}
```

---

## Reloading rules

```bash
python3 reload_firewall.py
# or: kill -HUP $(pgrep Rust_US)
```

---

## Log format

```
[2025-05-08 14:32:01.443] [EVENT] ID: 1 | TYPE: 1 | SRC: 192.168.1.5:4821  | DST: 10.0.0.1:22  | PROTO: 6 | REASON: IP_BLOCK_INGRESS
[2025-05-08 14:32:10.887] [EVENT] ID: 2 | TYPE: 2 | SRC: 10.0.0.2:54231    | DST: 1.2.3.4:443  | PROTO: 6 | REASON: IP_BLOCK_EGRESS
```

Block reasons: `IP_BLOCK_INGRESS`, `PORT_BLOCK_INGRESS`, `IP_BLOCK_EGRESS`, `PORT_BLOCK_EGRESS`

---

## Current limitations

- IPv4 only — IPv6 traffic is not filtered
- TCP and UDP only — ICMP rules are not supported
- No stateful tracking — rules are purely per-packet
- Single interface per instance

---
