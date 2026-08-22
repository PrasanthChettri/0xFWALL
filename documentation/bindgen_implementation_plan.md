# 0xFWALL — Bindgen Architecture & Code Planning Guide

This document details the design, architecture, and step-by-step implementation plan for integrating **`bindgen`** into the 0xFWALL project. This setup establishes C headers as the **single source of truth** for all shared data structures, constants, enums, and loader function signatures, eliminating manual code duplication between C and Rust.

---

## 1. Overview & Motivation

### 1.1 The Problem
In dual-language eBPF architectures (C kernel/loader + Rust userspace daemon), data structures and constants must match bit-for-bit across language boundaries:
* **Memory Layouts**: Structs like `event`, `ipv4_rule_key`, `ipv6_rule_key`, and `port_rule_key` must have identical padding, alignment, and endianness.
* **Constants & Enums**: Action flags (`UPSERT`/`DELETE`), direction flags (`INGRESS`/`EGRESS`), reason codes (`INGRESS_BLOCK_REASON_*`), and map size limits.
* **FFI Declarations**: Function signatures for C loader functions (`load_epbf`, `manage_ipv4_rule`, `poll_logs`, `cleanup`).

Previously, these were manually defined twice: once in `C/shared.h` and again in `Rust_US/src/epbf.rs`. This duplication is error-prone: modifying a struct field or adding a reason code in C requires remembering to update Rust, risking silent memory corruption or mismatched enum values.

### 1.2 The Solution
Establish **`C/shared.h`** and **`C/loader.h`** as the authoritative single source of truth. At build time, Rust's `build.rs` runs `bindgen` to automatically generate `$OUT_DIR/bindings.rs`, exposing exact types, constants, enums, and FFI signatures directly to Rust.

---

## 2. Architecture & Data Flow

```
                                 ┌────────────────────────────────────────────────────────┐
                                 │                   Authoritative Source                 │
                                 │                                                        │
                                 │   C/shared.h  ───► Data types, constants, enums, maps  │
                                 │   C/loader.h  ───► C loader exported API signatures    │
                                 └───────────┬────────────────────────────────┬───────────┘
                                             │                                │
                     Direct #include         │                                │  bindgen (build.rs)
                                             ▼                                ▼
                     ┌────────────────────────────────┐              ┌────────────────────────────────┐
                     │          C / eBPF Side         │              │          Rust Side             │
                     │                                │              │                                │
                     │  - epbf_xdp_ingress.c (XDP)    │              │  - $OUT_DIR/bindings.rs        │
                     │  - epbf_tc_egress.c   (TC)     │              │    (Auto-generated types/FFI)  │
                     │  - loader.c -> libloader.a     │              │  - epbf.rs (Safe wrapper)      │
                     └────────────────────────────────┘              │  - main.rs / log_writer.rs     │
                                                                     └────────────────────────────────┘
```

### Separation of Concerns
| Component | What it Contains | File Location | Updated By |
| :--- | :--- | :--- | :--- |
| **Schema & Types** | Structs, enums, constants, memory layouts | `C/shared.h`, `C/loader.h` | Developer (C side only) |
| **Runtime Rules** | Active IPs, CIDRs, and ports to block | `Rust_US/rules.json` | Operator / User |
| **Daemon Config** | Network interfaces, log paths, rule paths | `Rust_US/config.yaml` | Operator / User |

---

## 3. Code Planning & File Changes

```
0xFWALL/
├── C/
│   ├── shared.h             # Authoritative structs, enums, and constants
│   ├── loader.h             # [NEW] Authoritative C loader API declarations
│   └── loader.c             # [MODIFY] Includes loader.h
├── Rust_US/
│   ├── Cargo.toml           # [MODIFY] Add bindgen to [build-dependencies]
│   ├── build.rs             # [MODIFY] Generate bindings.rs from loader.h
│   └── src/
│       └── epbf.rs          # [MODIFY] Use generated bindings, delete manual FFI
└── documentation/
    └── bindgen_implementation_plan.md
```

---

### Step 1: Create `C/loader.h`
Create `C/loader.h` to declare all userspace loader functions and metadata types.

```c
#ifndef EPBF_LOADER_H
#define EPBF_LOADER_H

#include "shared.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration of internal metadata struct */
struct bpf_metadata;

/* Lifecycle & Initialization */
struct bpf_metadata* get_bpf_obj(void);
int load_epbf(const char *ifname);
void cleanup(void *bpf_md);

/* Event Polling */
int poll_logs(void *bpf_md, struct event *event, int ms);

/* Rule Management */
int manage_ipv4_rule(const struct ipv4_rule_key *rk, rule_action_t action, rule_direction_t direction);
int manage_ipv6_rule(const struct ipv6_rule_key *rk, rule_action_t action, rule_direction_t direction);
int manage_port_rule(const struct port_rule_key *rk, rule_action_t action, rule_direction_t direction);

#ifdef __cplusplus
}
#endif

#endif /* EPBF_LOADER_H */
```

---

### Step 2: Update `C/loader.c`
Include `loader.h` inside `C/loader.c` to guarantee that the implementation matches the exported signatures.

```c
// At the top of C/loader.c
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
#include "loader.h"    /* <── Ensure signatures match */
#include "target/epbf_xdp_ingress.skel.h"
#include "target/epbf_tc_egress.skel.h"
```

---

### Step 3: Add `bindgen` to `Rust_US/Cargo.toml`
Add `bindgen` under `[build-dependencies]`.

```toml
[package]
name = "Rust_US"
version = "0.1.0"
edition = "2024"
build = "build.rs"

[dependencies]
libc = "0.2.0"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
tokio = { version = "1", features = ["full"] }
ipnet = { version = "2.9", features = ["serde"] }
chrono = "0.4.44"

[build-dependencies]
bindgen = "0.71"

[dev-dependencies]
assert_cmd = "2.2.1"
nix = { version = "0.31.2", features = ["signal", "process"] }
tempfile = "3.27.0"
```

---

### Step 4: Configure `Rust_US/build.rs`
Update `build.rs` to invoke `bindgen` targeting `C/loader.h`, with appropriate allowlists and derive macros.

```rust
use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let parent_dir = PathBuf::from(&manifest_dir)
        .parent()
        .unwrap()
        .to_path_buf();

    let c_dir = parent_dir.join("C");
    let c_lib_path = c_dir.join("target");
    let header_path = c_dir.join("loader.h");

    // Link against libloader.a and libbpf
    println!("cargo:rustc-link-search=native={}", c_lib_path.display());
    println!("cargo:rustc-link-lib=static=loader");
    println!("cargo:rustc-link-lib=bpf");

    // Rebuild when headers or library change
    println!("cargo:rerun-if-changed={}", header_path.display());
    println!("cargo:rerun-if-changed={}", c_dir.join("shared.h").display());
    println!("cargo:rerun-if-changed={}", c_lib_path.display());

    // Generate FFI bindings
    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().expect("Header path must be UTF-8"))
        .clang_arg(format!("-I{}", c_dir.display()))
        // Types to generate
        .allowlist_type("event")
        .allowlist_type("conn_key")
        .allowlist_type("ipv4_rule_key")
        .allowlist_type("ipv6_rule_key")
        .allowlist_type("port_rule_key")
        .allowlist_type("rule_value")
        .allowlist_type("rule_table")
        .allowlist_type("rule_action_t")
        .allowlist_type("rule_direction_t")
        // Functions to generate
        .allowlist_function("load_epbf")
        .allowlist_function("get_bpf_obj")
        .allowlist_function("cleanup")
        .allowlist_function("poll_logs")
        .allowlist_function("manage_ipv4_rule")
        .allowlist_function("manage_ipv6_rule")
        .allowlist_function("manage_port_rule")
        // Constants / Enums to generate
        .allowlist_var("INGRESS_.*")
        .allowlist_var("EGRESS_.*")
        .allowlist_var("MAX_BLOCKED_.*")
        .allowlist_var("IPTYPE_.*")
        .allowlist_var("CONNTRACK_.*")
        .allowlist_var("RULE_ACTION_.*")
        // Rust derives
        .derive_default(true)
        .derive_debug(true)
        .derive_copy(true)
        .generate()
        .expect("Unable to generate bindings from C/loader.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings to OUT_DIR/bindings.rs");
}
```

---

### Step 5: Refactor `Rust_US/src/epbf.rs`
1. Include the generated module:
   ```rust
   #[allow(non_upper_case_globals)]
   #[allow(non_camel_case_types)]
   #[allow(non_snake_case)]
   #[allow(unused)]
   pub mod bindings {
       include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
   }
   use bindings::*;
   pub use bindings::event as Event;
   ```
2. Remove manual definitions:
   - ❌ `RulesFfi`
   - ❌ `c_direction`
   - ❌ `c_action`
   - ❌ `c_ipv4_rule`
   - ❌ `c_ipv6_rule`
   - ❌ `c_port_rule`
   - ❌ manual `struct Event`
   - ❌ manual `extern "C"` block
3. Use generated constants in `fmt::Display for Event`:
   ```rust
   let reason_str = match self.reason as u32 {
       INGRESS_BLOCK_REASON_SRC_IPV4 => "IP_BLOCK_INGRESS_V4",
       INGRESS_BLOCK_REASON_SRC_IPV6 => "IP_BLOCK_INGRESS_V6",
       INGRESS_BLOCK_REASON_SRC_PORT => "PORT_BLOCK_INGRESS",
       EGRESS_BLOCK_REASON_DST_IPV4  => "IP_BLOCK_EGRESS_V4",
       EGRESS_BLOCK_REASON_DST_IPV6  => "IP_BLOCK_EGRESS_V6",
       EGRESS_BLOCK_REASON_DST_PORT  => "PORT_BLOCK_EGRESS",
       _ => "UNKNOWN",
   };
   ```
4. Use generated structs and functions in `upsert_rules` & `delete_rules`:
   ```rust
   // Ingress IPv4
   for ip_net in &rules.ingress.blocked_ipv4 {
       let c_rule = ipv4_rule_key {
           prefixlen: ip_net.prefix_len() as u32,
           addr: u32::from(ip_net.addr()).to_be(),
       };
       let ret = unsafe {
           manage_ipv4_rule(
               &c_rule,
               rule_action_t_RULE_ACTION_UPSERT,
               rule_direction_t_RULE_DIRECTION_INGRESS,
           )
       };
       if ret != 0 { return Err(ret); }
   }
   ```

---

## 4. Maintenance Workflow: Adding New Fields or Rules

Once bindgen is active, the development workflow for adding or updating features becomes streamlined:

```
1. Modify C/shared.h or C/loader.h
   (e.g., add new reason code #define INGRESS_BLOCK_REASON_PROTOCOL 7)
               │
               ▼
2. Build C library (make -C C)
               │
               ▼
3. Run cargo build / cargo check in Rust_US
   (bindgen automatically generates the new constant/struct in bindings.rs)
               │
               ▼
4. Use the new constant directly in Rust (e.g., INGRESS_BLOCK_REASON_PROTOCOL)
```

No manual Rust FFI struct edits or header translation required.

---

## 5. Build & Verification Commands

```bash
# 1. Build eBPF objects, skeletons, and static C loader library
make -C C

# 2. Verify C loader headers syntax
gcc -fsyntax-only -I/usr/include/x86_64-linux-gnu C/loader.h

# 3. Check and build Rust daemon with bindgen
cargo check --manifest-path Rust_US/Cargo.toml
cargo test --manifest-path Rust_US/Cargo.toml
```
