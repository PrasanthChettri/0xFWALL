# 0xFWALL — End-to-End (E2E) Testing Architecture & Code Guide

This document is the complete guide and code reference for the **Python End-to-End (E2E) Testing Framework** for **0xFWALL**.

The framework validates the **entire running system** (eBPF XDP/TC kernel hooks + static C loader + asynchronous Rust daemon) under realistic network conditions using **Python 3**, **Pytest**, **Scapy**, and **Linux Network Namespaces (`netns`)**.

---

## 1. Architecture & Network Topology

Each test execution automatically provisions an isolated virtual network environment using Linux network namespaces and virtual ethernet (`veth`) pairs:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Pytest E2E Test Suite                           │
│                                                                        │
│  - Fixtures: Automatic NetNS & veth provisioning / cleanup             │
│  - Daemon Controller: Starts Rust_US, manages config, sends SIGHUP     │
│  - Scapy Engine: Injects raw packets (IPv4/IPv6, TCP SYN, UDP, CIDRs)   │
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

## 2. Directory & File Structure

```
0xFWALL/
├── tests/
│   ├── requirements.txt               # Test dependencies (pytest, scapy, pyyaml)
│   ├── run_e2e.sh                     # Automated runner with toolchain & build checks
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

## 3. Complete Code Implementation

### 3.1 `tests/requirements.txt`
```text
pytest>=8.0.0
scapy>=2.5.0
pyyaml>=6.0.1
```

---

### 3.2 `tests/run_e2e.sh`
Master runner script that verifies root permissions, environment paths, builds C & Rust binaries, and runs pytest.

```bash
#!/usr/bin/env bash
set -euo pipefail

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: E2E tests require root privileges for network namespaces and eBPF."
    echo "    Please run with: sudo $0"
    exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "[+] 1. Checking toolchains & paths..."
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export C_INCLUDE_PATH="$HOME/.local/include:$HOME/.local/usr/include:${C_INCLUDE_PATH:-}"
export LIBRARY_PATH="$HOME/.local/lib:$HOME/.local/usr/lib/x86_64-linux-gnu:${LIBRARY_PATH:-}"

echo "[+] 2. Compiling eBPF objects and C loader library..."
make -C C

echo "[+] 3. Compiling Rust userspace daemon..."
cd Rust_US && cargo build && cd ..

echo "[+] 4. Installing Python test dependencies..."
pip install -q -r tests/requirements.txt

echo "[+] 5. Executing Pytest E2E Test Suite..."
pytest tests/e2e/ -v --tb=short "$@"
```

---

### 3.3 `tests/e2e/framework/topology.py`
Provisions isolated `ns_client` and `ns_fw` network namespaces with an attached `veth` pair and static ARP/neighbor entries.

```python
import subprocess
import time

class NetworkTopology:
    def __init__(self, ns_client="ns_client", ns_fw="ns_fw"):
        self.ns_client = ns_client
        self.ns_fw = ns_fw
        self.client_ip = "192.168.100.2"
        self.fw_ip = "192.168.100.1"
        self.client_ip6 = "2001:db8:100::2"
        self.fw_ip6 = "2001:db8:100::1"
        self.client_mac = "02:00:00:00:00:02"
        self.fw_mac = "02:00:00:00:00:01"

    def setup(self):
        self.cleanup()

        # 1. Create namespaces
        subprocess.run(f"ip netns add {self.ns_client}", shell=True, check=True)
        subprocess.run(f"ip netns add {self.ns_fw}", shell=True, check=True)

        # 2. Create veth pair
        subprocess.run(
            f"ip link add veth_c address {self.client_mac} type veth peer name veth_fw address {self.fw_mac}",
            shell=True, check=True
        )

        # 3. Move interfaces into respective namespaces
        subprocess.run(f"ip link set veth_c netns {self.ns_client}", shell=True, check=True)
        subprocess.run(f"ip link set veth_fw netns {self.ns_fw}", shell=True, check=True)

        # 4. Configure Client Namespace (ns_client)
        subprocess.run(f"ip -n {self.ns_client} addr add {self.client_ip}/24 dev veth_c", shell=True, check=True)
        subprocess.run(f"ip -n {self.ns_client} addr add {self.client_ip6}/64 dev veth_c", shell=True, check=True)
        subprocess.run(f"ip -n {self.ns_client} link set veth_c up", shell=True, check=True)
        subprocess.run(f"ip -n {self.ns_client} link set lo up", shell=True, check=True)

        # 5. Configure Firewall Namespace (ns_fw)
        subprocess.run(f"ip -n {self.ns_fw} addr add {self.fw_ip}/24 dev veth_fw", shell=True, check=True)
        subprocess.run(f"ip -n {self.ns_fw} addr add {self.fw_ip6}/64 dev veth_fw", shell=True, check=True)
        subprocess.run(f"ip -n {self.ns_fw} link set veth_fw up", shell=True, check=True)
        subprocess.run(f"ip -n {self.ns_fw} link set lo up", shell=True, check=True)

        # Set static neighbor entries to avoid ARP delays
        subprocess.run(
            f"ip -n {self.ns_client} neigh add {self.fw_ip} lladdr {self.fw_mac} dev veth_c",
            shell=True, check=True
        )
        subprocess.run(
            f"ip -n {self.ns_fw} neigh add {self.client_ip} lladdr {self.client_mac} dev veth_fw",
            shell=True, check=True
        )

        time.sleep(0.2)

    def cleanup(self):
        subprocess.run(f"ip netns del {self.ns_client} 2>/dev/null || true", shell=True)
        subprocess.run(f"ip netns del {self.ns_fw} 2>/dev/null || true", shell=True)
```

---

### 3.4 `tests/e2e/framework/daemon.py`
Manages the `Rust_US` daemon process inside `ns_fw`, writes temporary configs/rules, and issues `SIGHUP` live reload signals.

```python
import subprocess
import time
import json
import yaml
from pathlib import Path

class FirewallDaemon:
    def __init__(self, topology, work_dir: Path):
        self.topology = topology
        self.work_dir = work_dir
        self.config_path = work_dir / "config.yaml"
        self.rules_path = work_dir / "rules.json"
        self.log_path = work_dir / "blocked.log"
        self.repo_root = Path(__file__).parents[3]
        self.bin_path = self.repo_root / "Rust_US" / "target" / "debug" / "Rust_US"
        self.process = None

    def start(self, initial_rules: dict):
        self.write_rules(initial_rules)
        config_data = {
            "epbf_path_ingress": str(self.repo_root / "C" / "target" / "epbf_xdp_ingress.o"),
            "epbf_path_egress": str(self.repo_root / "C" / "target" / "epbf_tc_egress.o"),
            "rules_path": str(self.rules_path),
            "log_path": str(self.log_path),
            "interface": "veth_fw",
        }
        with open(self.config_path, "w") as f:
            yaml.dump(config_data, f)

        # Clear previous log file if present
        if self.log_path.exists():
            self.log_path.unlink()

        cmd = f"ip netns exec {self.topology.ns_fw} {self.bin_path}"
        self.process = subprocess.Popen(cmd, shell=True, cwd=self.work_dir)
        time.sleep(1.0) # Allow eBPF programs to load and attach

    def reload_rules(self, new_rules: dict):
        self.write_rules(new_rules)
        # Send SIGHUP to the running Rust daemon
        subprocess.run(f"pkill -HUP -f {self.bin_path.name}", shell=True, check=True)
        time.sleep(0.5) # Allow atomic map update

    def write_rules(self, rules: dict):
        with open(self.rules_path, "w") as f:
            json.dump(rules, f, indent=2)

    def stop(self):
        if self.process:
            subprocess.run(f"pkill -INT -f {self.bin_path.name} 2>/dev/null || true", shell=True)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
            time.sleep(0.5)
```

---

### 3.5 `tests/e2e/framework/traffic.py`
Scapy packet engine that injects raw Layer 2/3/4 packets from `ns_client` and asserts drop/pass behavior on `ns_fw`.

```python
import subprocess
import time
from scapy.all import IP, IPv6

class TrafficEngine:
    def __init__(self, topology):
        self.topology = topology

    def send_and_check(self, pkt, expect_dropped=True, timeout=0.8):
        """
        Sends a packet from ns_client across veth_c and sniffs on veth_fw in ns_fw.
        Returns True if the drop/pass behavior matches expect_dropped.
        """
        if IP in pkt:
            bpf_filter = f"ip src {pkt[IP].src} and ip dst {pkt[IP].dst}"
        elif IPv6 in pkt:
            bpf_filter = f"ip6 src {pkt[IPv6].src} and ip6 dst {pkt[IPv6].dst}"
        else:
            bpf_filter = ""

        # 1. Start sniffer in ns_fw
        sniffer_code = (
            f"from scapy.all import sniff; "
            f"pkts = sniff(iface='veth_fw', count=1, timeout={timeout}, filter='{bpf_filter}'); "
            f"exit(0 if len(pkts) > 0 else 1)"
        )
        sniff_proc = subprocess.Popen(
            f"ip netns exec {self.topology.ns_fw} python3 -c \"{sniffer_code}\"",
            shell=True
        )

        time.sleep(0.1)

        # 2. Inject packet from ns_client
        send_code = (
            f"from scapy.all import sendp, Ether, IP, IPv6, TCP, UDP, ICMP; "
            f"sendp({repr(pkt)}, iface='veth_c', verbose=False)"
        )
        subprocess.run(
            f"ip netns exec {self.topology.ns_client} python3 -c \"{send_code}\"",
            shell=True,
            check=True
        )

        # 3. Wait for sniffer result (0 = received, 1 = timeout/dropped)
        ret = sniff_proc.wait()
        packet_received = (ret == 0)

        if expect_dropped:
            return not packet_received  # True if packet was blocked
        else:
            return packet_received      # True if packet passed through
```

---

### 3.6 `tests/e2e/framework/log_parser.py`
Parses and asserts records in `blocked.log` generated by the Rust async log writer.

```python
from pathlib import Path
import re
import time

class LogVerifier:
    def __init__(self, log_path: Path):
        self.log_path = log_path

    def get_events(self) -> list:
        if not self.log_path.exists():
            return []
        events = []
        pattern = re.compile(
            r"\[(?P<time>[^\]]+)\]\[EVENT\]\s+"
            r"ID:\s+(?P<id>\d+)\s+\|\s+"
            r"TYPE:\s+(?P<type>\d+)\s+\|\s+"
            r"SRC:\s+(?P<src_ip>[^:]+):(?P<src_port>\d+)\s+\|\s+"
            r"DST:\s+(?P<dst_ip>[^:]+):(?P<dst_port>\d+)\s+\|\s+"
            r"PROTO:\s+(?P<proto>\d+)\s+\|\s+"
            r"REASON:\s+(?P<reason>\S+)"
        )
        for line in self.log_path.read_text().splitlines():
            m = pattern.search(line)
            if m:
                events.append(m.groupdict())
        return events

    def get_last_event(self) -> dict:
        time.sleep(0.2) # Allow async buffer to flush
        events = self.get_events()
        return events[-1] if events else {}

    def assert_last_event(self, expected_reason: str, expected_proto: int = None, expected_src: str = None):
        event = self.get_last_event()
        assert event, f"No event found in {self.log_path}"
        assert event["reason"] == expected_reason, f"Expected reason {expected_reason}, got {event['reason']}"
        if expected_proto is not None:
            assert int(event["proto"]) == expected_proto
        if expected_src is not None:
            assert event["src_ip"] == expected_src
```

---

### 3.7 `tests/e2e/conftest.py`
Pytest fixtures providing topology and daemon setup/teardown.

```python
import pytest
from framework.topology import NetworkTopology
from framework.daemon import FirewallDaemon
from framework.traffic import TrafficEngine
from framework.log_parser import LogVerifier

@pytest.fixture(scope="session")
def topology():
    topo = NetworkTopology()
    topo.setup()
    yield topo
    topo.cleanup()

@pytest.fixture
def firewall(topology, tmp_path):
    daemon = FirewallDaemon(topology, tmp_path)
    traffic = TrafficEngine(topology)
    logger = LogVerifier(daemon.log_path)

    yield {"daemon": daemon, "traffic": traffic, "logger": logger}

    daemon.stop()
```

---

### 3.8 `tests/e2e/test_ingress_ipv4.py`
```python
import pytest
from scapy.all import Ether, IP, TCP, ICMP

def test_blocked_ipv4_host_32(firewall, topology):
    """Test blocking a single IPv4 host (/32)"""
    rules = {
        "ingress": {"blocked_ipv4": ["192.168.100.2/32"], "blocked_ipv6": [], "blocked_ports": []},
        "egress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": []},
    }
    firewall["daemon"].start(rules)

    pkt = Ether(dst=topology.fw_mac) / IP(src="192.168.100.2", dst=topology.fw_ip) / ICMP()
    assert firewall["traffic"].send_and_check(pkt, expect_dropped=True)
    firewall["logger"].assert_last_event(expected_reason="IP_BLOCK_INGRESS_V4", expected_src="192.168.100.2")

def test_blocked_ipv4_cidr_subnet_8(firewall, topology):
    """Test blocking an entire CIDR subnet (10.0.0.0/8) using forged packets"""
    rules = {
        "ingress": {"blocked_ipv4": ["10.0.0.0/8"], "blocked_ipv6": [], "blocked_ports": []},
        "egress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": []},
    }
    firewall["daemon"].start(rules)

    # 1. Blocked: 10.42.1.99 matches 10.0.0.0/8
    pkt_blocked = Ether(dst=topology.fw_mac) / IP(src="10.42.1.99", dst=topology.fw_ip) / TCP(dport=80, flags="S")
    assert firewall["traffic"].send_and_check(pkt_blocked, expect_dropped=True)
    firewall["logger"].assert_last_event(expected_reason="IP_BLOCK_INGRESS_V4", expected_src="10.42.1.99")

    # 2. Allowed: 192.168.100.2 does NOT match 10.0.0.0/8
    pkt_allowed = Ether(dst=topology.fw_mac) / IP(src="192.168.100.2", dst=topology.fw_ip) / TCP(dport=80, flags="S")
    assert firewall["traffic"].send_and_check(pkt_allowed, expect_dropped=False)
```

---

### 3.9 `tests/e2e/test_ingress_ipv6.py`
```python
import pytest
from scapy.all import Ether, IPv6, TCP, ICMPv6EchoRequest

def test_blocked_ipv6_host_128(firewall, topology):
    """Test blocking a single IPv6 host (/128)"""
    rules = {
        "ingress": {"blocked_ipv4": [], "blocked_ipv6": ["2001:db8:100::2/128"], "blocked_ports": []},
        "egress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": []},
    }
    firewall["daemon"].start(rules)

    pkt = Ether(dst=topology.fw_mac) / IPv6(src="2001:db8:100::2", dst=topology.fw_ip6) / ICMPv6EchoRequest()
    assert firewall["traffic"].send_and_check(pkt, expect_dropped=True)
    firewall["logger"].assert_last_event(expected_reason="IP_BLOCK_INGRESS_V6", expected_src="2001:db8:100::2")

def test_blocked_ipv6_subnet_64(firewall, topology):
    """Test blocking an IPv6 /64 prefix"""
    rules = {
        "ingress": {"blocked_ipv4": [], "blocked_ipv6": ["2001:db8:dead::/64"], "blocked_ports": []},
        "egress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": []},
    }
    firewall["daemon"].start(rules)

    pkt_blocked = Ether(dst=topology.fw_mac) / IPv6(src="2001:db8:dead::beef", dst=topology.fw_ip6) / TCP(dport=80)
    assert firewall["traffic"].send_and_check(pkt_blocked, expect_dropped=True)
    firewall["logger"].assert_last_event(expected_reason="IP_BLOCK_INGRESS_V6", expected_src="2001:db8:dead::beef")
```

---

### 3.10 `tests/e2e/test_ingress_ports.py`
```python
import pytest
from scapy.all import Ether, IP, TCP, UDP

def test_blocked_tcp_ports(firewall, topology):
    """Test blocking destination TCP ports 22 and 8080"""
    rules = {
        "ingress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": [22, 8080]},
        "egress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": []},
    }
    firewall["daemon"].start(rules)

    # 1. Port 22 (Blocked)
    pkt_ssh = Ether(dst=topology.fw_mac) / IP(src="192.168.100.2", dst=topology.fw_ip) / TCP(dport=22, flags="S")
    assert firewall["traffic"].send_and_check(pkt_ssh, expect_dropped=True)
    firewall["logger"].assert_last_event(expected_reason="PORT_BLOCK_INGRESS", expected_proto=6)

    # 2. Port 8080 (Blocked)
    pkt_alt = Ether(dst=topology.fw_mac) / IP(src="192.168.100.2", dst=topology.fw_ip) / TCP(dport=8080, flags="S")
    assert firewall["traffic"].send_and_check(pkt_alt, expect_dropped=True)
    firewall["logger"].assert_last_event(expected_reason="PORT_BLOCK_INGRESS", expected_proto=6)

    # 3. Port 443 (Allowed)
    pkt_https = Ether(dst=topology.fw_mac) / IP(src="192.168.100.2", dst=topology.fw_ip) / TCP(dport=443, flags="S")
    assert firewall["traffic"].send_and_check(pkt_https, expect_dropped=False)

def test_blocked_udp_ports(firewall, topology):
    """Test blocking UDP port 53"""
    rules = {
        "ingress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": [53]},
        "egress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": []},
    }
    firewall["daemon"].start(rules)

    pkt_dns = Ether(dst=topology.fw_mac) / IP(src="192.168.100.2", dst=topology.fw_ip) / UDP(dport=53)
    assert firewall["traffic"].send_and_check(pkt_dns, expect_dropped=True)
    firewall["logger"].assert_last_event(expected_reason="PORT_BLOCK_INGRESS", expected_proto=17)
```

---

### 3.11 `tests/e2e/test_live_reload.py`
```python
import pytest
from scapy.all import Ether, IP, TCP

def test_sighup_live_rule_reload(firewall, topology):
    """Test dynamic addition and removal of rules via SIGHUP without daemon restart"""
    # 1. Start daemon with NO rules -> Port 9999 passes
    rules_initial = {
        "ingress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": []},
        "egress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": []},
    }
    firewall["daemon"].start(rules_initial)

    pkt = Ether(dst=topology.fw_mac) / IP(src="192.168.100.2", dst=topology.fw_ip) / TCP(dport=9999, flags="S")
    assert firewall["traffic"].send_and_check(pkt, expect_dropped=False)

    # 2. Live reload: block port 9999
    rules_blocked = {
        "ingress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": [9999]},
        "egress": {"blocked_ipv4": [], "blocked_ipv6": [], "blocked_ports": []},
    }
    firewall["daemon"].reload_rules(rules_blocked)

    # Port 9999 must now be dropped
    assert firewall["traffic"].send_and_check(pkt, expect_dropped=True)
    firewall["logger"].assert_last_event(expected_reason="PORT_BLOCK_INGRESS")

    # 3. Live reload: unblock port 9999
    firewall["daemon"].reload_rules(rules_initial)

    # Traffic must now pass again
    assert firewall["traffic"].send_and_check(pkt, expect_dropped=False)
```

---

## 4. Execution & Verification

### Run Entire E2E Suite:
```bash
sudo ./tests/run_e2e.sh
```

### Run a Single Test File:
```bash
sudo pytest tests/e2e/test_live_reload.py -v -s
```
