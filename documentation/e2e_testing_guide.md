# 0xFWALL — End-to-End (E2E) Testing Architecture & Guide

This guide details the design, structure, and execution of the **End-to-End (E2E) Testing Framework** for **0xFWALL**.

The framework tests the **complete running system** under real network conditions using **Python 3**, **Pytest**, **Scapy**, and **Linux Network Namespaces (`netns`)**.

---

## 1. Overview & Architecture

Unlike isolated unit tests, 0xFWALL's E2E test suite validates the entire eBPF data plane and userspace control plane together:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Pytest E2E Test Suite                           │
│                                                                        │
│  - Fixtures: Automatic NetNS & veth provisioning / cleanup             │
│  - Daemon Controller: Starts Rust_US, manages config, sends SIGHUP     │
│  - Scapy Engine: Crafts raw packets (IPv4/IPv6, TCP SYN, UDP, CIDRs)   │
│  - Log Parser: Validates blocked.log entries against sent packets      │
└───────────────────────────┬────────────────────────────────┬───────────┘
                            │                                │
                 Virtual Network Topology (veth pair)
                            │                                │
                            ▼                                ▼
              ┌───────────────────────────┐    ┌───────────────────────────┐
              │  Namespace: "ns_client"   │    │    Namespace: "ns_fw"     │
              │                           │    │                           │
              │  IP: 192.168.100.2/24     │    │  IP: 192.168.100.1/24     │
              │  IPv6: 2001:db8:100::2/64 │    │  IPv6: 2001:db8:100::1/64 │
              │  Interface: veth_c        ├────┤  Interface: veth_fw       │
              │                           │    │                           │
              │  (Injects forged packets) │    │  [XDP Hook] Ingress       │
              │                           │    │  [TC Hook]  Egress        │
              │                           │    │  0xFWALL Rust Daemon      │
              └───────────────────────────┘    └───────────────────────────┘
```

---

## 2. Directory Layout

```
0xFWALL/
├── tests/
│   ├── requirements.txt               # pytest, scapy, pyyaml
│   └── e2e/
│       ├── __init__.py
│       ├── conftest.py                # Pytest fixtures: Topology, Daemon lifecycle
│       ├── framework/
│       │   ├── __init__.py
│       │   ├── topology.py            # Linux Network Namespace & veth management
│       │   ├── daemon.py              # Daemon process manager, config & SIGHUP signaling
│       │   ├── traffic.py             # Scapy packet injection & sniffing engine
│       │   └── log_parser.py          # Real-time blocked.log parsing and assertions
│       ├── test_ingress_ipv4.py       # Ingress IPv4 (/32, /24, /16, /8) CIDR drops & allows
│       ├── test_ingress_ipv6.py       # Ingress IPv6 (/128, /64, /32) CIDR drops & allows
│       ├── test_ingress_ports.py      # TCP SYN, UDP, and allowed port filtering
│       ├── test_egress_filtering.py   # Egress TC IP and Port drop verification
│       ├── test_live_reload.py        # Live SIGHUP rule reload (adding/removing rules on the fly)
│       └── test_conntrack.py          # State tracking: outbound connection replies pass through XDP
└── documentation/
    └── e2e_testing_guide.md
```

---

## 3. Core Framework Components

### 3.1 Network Topology (`framework/topology.py`)
* Provisions two isolated network namespaces:
  * `ns_client`: Represents an external host or attacker.
  * `ns_fw`: Hosts the 0xFWALL firewall attached to `veth_fw`.
* Creates a virtual ethernet pair (`veth_c` <-> `veth_fw`).
* Guarantees teardown on test completion or failure.

### 3.2 Daemon Controller (`framework/daemon.py`)
* Automatically creates temporary isolated `config.yaml` and `rules.json` per test run.
* Spawns `Rust_US` inside `ns_fw`.
* Provides a `reload_rules(new_rules_dict)` method which writes updated JSON and sends `signal.SIGHUP` to the daemon.
* Ensures graceful shutdown with `SIGINT` on test exit.

### 3.3 Scapy Packet Engine (`framework/traffic.py`)
* Injects forged packets from `ns_client` with custom:
  * Source & Destination IPs (testing `/32`, `/24`, `/16`, `/8` CIDRs)
  * IPv6 Subnets (`/128`, `/64`, `/32`)
  * Transport protocols (TCP with specific flags like `SYN`, UDP, ICMP)
* Sniffs on `veth_fw` in `ns_fw` to assert whether the packet was dropped by XDP/TC or received by the kernel network stack.

### 3.4 Log Parser (`framework/log_parser.py`)
* Reads and parses `Rust_US/blocked.log` in real time.
* Asserts that dropped packets generate valid log records with exact fields:
  * `src_ip` / `dst_ip`
  * `src_port` / `dst_port`
  * `protocol` (6 for TCP, 17 for UDP, 1 for ICMP)
  * `reason` (`IP_BLOCK_INGRESS_V4`, `PORT_BLOCK_INGRESS`, `IP_BLOCK_EGRESS_V4`, etc.)

---

## 4. Test Matrix & Scenarios

### 4.1 Ingress IPv4 Filtering (`test_ingress_ipv4.py`)
* **Single Host Block (`/32`)**: Packets from `192.168.100.2` dropped; packets from `192.168.100.3` passed.
* **Subnet CIDR Block (`/24`)**: Packets from `192.168.1.0/24` dropped; outside subnet passed.
* **Broad CIDR Block (`/8`)**: Packets from `10.0.0.0/8` (e.g. `10.42.1.99`) dropped; other subnets passed.
* **Log Assertion**: Verifies `IP_BLOCK_INGRESS_V4` logged.

### 4.2 Ingress IPv6 Filtering (`test_ingress_ipv6.py`)
* **Exact Address (`/128`)**: Packets from `2001:db8:100::2` dropped.
* **Subnet (`/64`)**: Packets from `2001:db8:dead::/64` dropped.
* **Log Assertion**: Verifies `IP_BLOCK_INGRESS_V6` logged.

### 4.3 Ingress Port Filtering (`test_ingress_ports.py`)
* **TCP Port Blocking**: TCP SYN packets to blocked ports (e.g. 22, 23, 8080) dropped by XDP.
* **UDP Port Blocking**: UDP packets to blocked ports dropped by XDP.
* **Allowed Ports**: Packets to unblocked ports (e.g. 80, 443) pass through XDP.
* **Log Assertion**: Verifies `PORT_BLOCK_INGRESS` logged.

### 4.4 Egress Filtering (`test_egress_filtering.py`)
* **Destination IP Block**: Packets originating from `ns_fw` to blocked destination IPs dropped by TC (`TC_ACT_SHOT`).
* **Destination Port Block**: Outbound packets to blocked ports dropped by TC.
* **Log Assertion**: Verifies `IP_BLOCK_EGRESS_V4` and `PORT_BLOCK_EGRESS` logged.

### 4.5 Dynamic Rule Reload via SIGHUP (`test_live_reload.py`)
* Starts daemon with open rules ➔ verifies port 9000 passes.
* Modifies `rules.json` to block port 9000 and sends `SIGHUP` ➔ verifies port 9000 is immediately dropped by XDP.
* Modifies `rules.json` to remove port 9000 and sends `SIGHUP` ➔ verifies traffic flows again without restarting the daemon.

---

## 5. Running the E2E Test Suite

### Prerequisites
* Python 3.10+
* Root privileges (required for `ip netns`, `scapy`, and eBPF hook attachment)

### Setup & Run
```bash
# 1. Install Python test dependencies
pip install -r tests/requirements.txt

# 2. Compile eBPF objects and Rust daemon
make -C C
cd Rust_US && cargo build && cd ..

# 3. Run all E2E tests with pytest
sudo pytest tests/e2e/ -v --tb=short

# 4. Run a specific test suite with detailed output
sudo pytest tests/e2e/test_live_reload.py -v -s
```
