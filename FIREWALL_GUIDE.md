# 0xFWALL Development Guide & Roadmap

This document serves as the architectural foundation and learning guide for the 0xFWALL XDP Firewall project.

## 1. Core Implementation: Async Log Writer

We implemented a custom, high-performance logger that separates **Critical System Logs** (Blocking) from **High-Frequency Packet Logs** (Non-Blocking).

### `Rust_US/src/log_writer.rs`
```rust
use std::io;
use std::path::{Path, PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use chrono::Local;

use crate::xdp::Event;

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Info, Warn, Error, Debug,
}

/// The LogEntry enum allows the logger to handle both structured 
/// packet data and general status messages.
pub enum LogEntry {
    Event(Event),
    Message(LogLevel, String),
}

pub struct LogWriter {
    sender: mpsc::Sender<LogEntry>,
    task: JoinHandle<io::Result<()>>,
}

impl LogWriter {
    pub fn spawn<P: AsRef<Path>>(path: P, buffer_size: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel(buffer_size);
        let path = path.as_ref().to_path_buf();

        let task = tokio::spawn(async move {
            let file = OpenOptions::new().create(true).append(true).open(path).await?;
            let mut writer = BufWriter::new(file);

            while let Some(entry) = receiver.recv().await {
                let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                let output = match entry {
                    // Uses the Display trait from Event
                    LogEntry::Event(ev) => format!("[{}][EVENT] {}\n", now, ev),
                    LogEntry::Message(level, msg) => {
                        let lbl = match level {
                            LogLevel::Info => "INFO ",
                            LogLevel::Warn => "WARN ",
                            LogLevel::Error => "ERROR",
                            LogLevel::Debug => "DEBUG",
                        };
                        format!("[{}][{}] {}\n", now, lbl, msg)
                    }
                };
                writer.write_all(output.as_bytes()).await?;
                writer.flush().await?;
            }
            Ok(())
        });

        Self { sender, task }
    }

    /// BLOCKING: Guarantees delivery. Use for startup/errors.
    pub async fn log_blocking(&self, level: LogLevel, msg: impl Into<String>) {
        let _ = self.sender.send(LogEntry::Message(level, msg.into())).await;
    }

    /// NON-BLOCKING: Drops logs if buffer is full. Use for packet events.
    pub fn log_nblocking(&self, level: LogLevel, msg: impl Into<String>) {
        let _ = self.sender.try_send(LogEntry::Message(level, msg.into()));
    }

    pub fn event_nblocking(&self, ev: Event) {
        let _ = self.sender.try_send(LogEntry::Event(ev));
    }

    pub async fn shutdown(self) -> io::Result<()> {
        drop(self.sender);
        match self.task.await {
            Ok(result) => result,
            Err(err) => Err(io::Error::other(err)),
        }
    }
}
```

### Usage in `main.rs`
```rust
// Startup - Use Blocking (guarantees order and visibility)
log_writer.log_blocking(LogLevel::Info, "Starting 0xFWALL...").await;

// Packet Loop - Use Non-Blocking (prevents backpressure on XDP)
if let Some(event) = handler.poll_logs(100) {
    log_writer.event_nblocking(event); // No .await needed!
}
```

---

## 2. Async Rust Mental Models

1.  **Futures are Lazy:** Calling an `async` function does nothing until you `.await` it or spawn it.
2.  **Don't Block the Executor:** Never use `std::thread::sleep` or long-running synchronous loops inside `async`. It stops the entire runtime. Use `tokio::time::sleep` or `spawn_blocking`.
3.  **The "Async Infection":** To `.await` a function, your current function must also be `async`. We break this "infection" using `try_send` in the `LogWriter` for high-performance sections.
4.  **Ownership (Arc/Mutex):** Use `Arc` (Atomic Reference Counter) to share data across tasks. Use `Mutex` to safely mutate that data.
5.  **Task Cancellation:** In Rust, dropping a `Future` cancels the task. This makes cleanup extremely robust.

---

## 3. Project Roadmap

### Phase 1: Completing the Kernel (Next Steps)
*   **Port Filtering:** Update `kernel.c` to parse Layer 4 headers (TCP/UDP).
    *   *How:* Cast `data + sizeof(eth) + sizeof(ip)` to `tcphdr` or `udphdr` after verifying bounds.
*   **LPM (CIDR) Support:** Support blocking ranges like `192.168.1.0/24`.
    *   *How:* Change the BPF map type from `BPF_MAP_TYPE_HASH` to `BPF_MAP_TYPE_LPM_TRIE`.

### Phase 2: Dynamic Management
*   **Live Rule Reloading:** Update the blocklist without restarting the firewall.
    *   *How:* Use the `notify` crate in Rust to watch `rules.json` and call `bpf_map_update_elem` in the C loader.
*   **Statistics Map:** Track "Hits" per rule.
    *   *How:* Create a new `BPF_MAP_TYPE_ARRAY` in the kernel and increment counters for every dropped packet.

### Phase 3: Observability
*   **TUI Dashboard:** A real-time terminal interface showing dropped packets per second.
    *   *How:* Use the `ratatui` crate to build a UI that reads from the Statistics Map.
*   **Egress Filtering:** Block outgoing packets.
    *   *How:* Implement a TC (Traffic Control) BPF program, as XDP is ingress-only.
