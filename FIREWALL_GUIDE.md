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

✦ The error "libbpf: Kernel error message: Exclusivity flag on, cannot modify" is a classic "gotcha" when working with the Traffic Control (TC) subsystem in
  eBPF.

  Here is an educational breakdown of why this happens and how your current architecture is interacting with the Linux kernel.

  1. The Root Cause: TC Hook "Exclusivity"
  In Linux, for an eBPF program to run on the Egress path, it usually attaches to a specific "Queueing Discipline" (qdisc) called clsact.

  In your loader.c, you have this:

   1 err = bpf_tc_hook_create(&tc_hook);

  When libbpf calls the kernel to create this hook, it uses a Netlink flag called NLM_F_EXCL (Exclusivity). This tells the kernel: "Create this, but if it
  already exists, fail and tell me."

  If your program:
   1. Crashed previously.
   2. Was terminated without running cleanup.
   3. Or if you manually attached something to that interface.

  The clsact qdisc remains in the kernel. When you run cargo run again, bpf_tc_hook_create sees the existing hook, the kernel returns -EEXIST, and libbpf
  reports that "Exclusivity" error.

  Educational takeaway: Most production eBPF loaders check if err == -EEXIST and simply ignore it, because an existing hook is actually a "success" state
  for the loader.

  2. The "Leaky" Cleanup Logic
  Looking at your cleanup function, there are two issues affecting the lifecycle:

  A. TC Detach vs. Destroy

   1 bpf_tc_detach(&tc_hook, &tc_opts);
  bpf_tc_detach removes your program from the hook, but it leaves the hook (clsact qdisc) itself attached to the network interface. To fully "zero out" the
  interface, you would need bpf_tc_hook_destroy(&tc_hook).

  B. The XDP Detach Bug

   1 bpf_xdp_detach(bpf_md_s->ingress_ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
  This is a common typo. XDP_FLAGS_UPDATE_IF_NOEXIST is a flag meant for attachment. It tells the kernel "Only attach if there isn't a program there." Using
  it during detachment is logically contradictory and might cause the kernel to reject the command, leaving your XDP program "stuck" on the interface.

  3. Threading and the "Global Pointer" Trap
  This is likely where your Rust threading (tokio::task::spawn_blocking) meets C in a dangerous way.

  In loader.c, you define:
   1 struct bpf_metadata *bm; // Global variable

  In epbf.rs, your Rust struct holds a handle, but that handle is just a copy of the global bm pointer.

   1 let bpf_obj = unsafe { get_bpf_obj() };

  The Conflict:
   1. Rust's EPBFProgram implements Drop. When main finishes or a thread drops a handle, it calls cleanup(self.handle).
   2. Inside C's cleanup, you do free(bpf_md_s); bm = NULL;.
   3. If you have any other thread (like your polling task) still trying to use that pointer, or if you try to "Attach" again without a full process
      restart, you are dealing with a dangling pointer or a NULL global state.

  Even though you use Arc<Mutex<...>> in Rust to protect the object, the C side is using a single global variable (bm). If you ever created two instances of
  EPBFProgram, they would both be pointing to the exact same memory in C, and dropping one would crash the other.

  4. Why cargo run fails specifically
  When you use cargo run, you often stop the previous execution with Ctrl+C.
   - If your Shutdown logic in main.rs doesn't complete perfectly (e.g., the poll_task is still holding the lock when the process receives a signal), the
     cleanup function in C might never run.
   - The clsact qdisc (TC) and the XDP program stay alive in the Kernel.
   - On the next cargo run, the kernel sees the "Exclusivity" flag and blocks you.

  Summary of Lessons
   1. Idempotency is key: Loaders should be written to handle "already exists" errors gracefully.
   2. Kernel State != Process State: eBPF programs live in the kernel. If your UserSpace process dies, the Kernel programs stay behind unless explicitly
      torn down.
   3. Avoid C Globals in Rust Wrappers: When wrapping C in Rust, try to pass "Context" pointers back and forth rather than relying on a global static
      variable in C, especially when using async runtimes like Tokio.

 > the
        cleanup function in C might never run. what ? how do I make sure it runs regardless, discuss, don't implement

✦ Ensuring cleanup in an eBPF application is notoriously tricky because you are managing state outside your process (in the kernel). If your process
  disappears, the kernel doesn't automatically know that those XDP and TC programs should be removed.

  Here are the primary strategies to ensure cleanup happens, ranging from "Good Practice" to "Modern Kernel Solutions."

  1. Why Drop is not a Guarantee
  In Rust, the Drop trait is great for memory, but it's a "cooperative" cleanup.
   * The Problem: If your program receives a SIGKILL (kill -9), or if it segmentation faults (very possible when doing unsafe C interop), the Rust runtime
     doesn't get to run the Drop code. The memory is reclaimed by the OS, but the eBPF program stays "pinned" in the kernel.
   * The Result: You get the "Exclusivity" error on the next run because the previous "zombie" program is still there.

  2. Strategy: The "Double-Tap" Signal Handling
  Your current code handles Ctrl-C via a Tokio task. This is good for a clean exit, but for robustness, you want to handle signals at a lower level.

  Educational Concept: The "Graceful Exit" vs. "Forced Exit"
  You can use a crate like signal-hook or standard libc signal handling to register a handler that runs even if the async runtime is struggling. However,
  even this won't help with SIGKILL.

  3. Strategy: Modern Kernel "Links" (The Pro Way)
  The most robust way to solve this isn't in Rust or C logic—it's by using a kernel feature called bpf_link.

   * How it works: Instead of just "attaching" a program to an interface, you create a "Link" object.
   * The Magic: A bpf_link is tied to a File Descriptor (FD) in your process.
   * Auto-Cleanup: When your process dies (for any reason—crash, kill -9, normal exit), the Linux kernel automatically closes all FDs. When the FD for the
     bpf_link is closed, the kernel says, "Oh, the owner is gone," and automatically detaches the eBPF program for you.

  If you use bpf_program__attach_xdp (which returns a struct bpf_link*) instead of the older bpf_xdp_attach, you get this "auto-cleanup" for free from the
  kernel itself.

  4. Strategy: The "Clean Start" Pattern (Idempotency)
  Since you can never 100% guarantee that a process won't be killed mid-execution, the most "production-grade" approach is to make your Start logic clean up
  the Previous state.

  Instead of just trying to create the TC hook:
   1. Attempt a Destroy first: On startup, try to bpf_tc_hook_destroy. If it fails because nothing was there, ignore the error.
   2. Or use the "Replace" flag: When attaching, use flags that tell the kernel: "If a program is already here, just replace it with this new one."

  5. Strategy: The "PID File" or "Lock File"
  Some systems write their Process ID (PID) to a file (like /var/run/firewall.pid).
   - When the program starts, it checks if that PID is still running.
   - If not, but the eBPF programs are still loaded, it knows it's a "dirty" state and triggers a full cleanup before starting.

  Summary: Which should you use?
  If you want to be a "modern" eBPF developer, Strategy 3 (bpf_link) is the answer. It moves the responsibility of cleanup from your buggy Userspace code to
  the stable Linux Kernel.

  By holding a "Link" FD, you ensure that as long as your process is alive, the firewall is up; the moment your process vanishes (by choice or by crash),
  the firewall is cleared.

 > In Rust, the Drop trait is great for memory, but it's a "cooperative" cleanup.
      * The Problem: If your program receives a SIGKILL (kill -9), or if it segmentation faults (very possible when doing unsafe C interop), the Rust
   runtime
        doesn't get to run the Drop code. The memory is reclaimed by the OS, but the eBPF program stays "pinned" in the kernel.
      * The Result: You get the "Exclusivity" error on the next run because the previous "zombie" program is still there.But on ctrl+c, it should clean up
   right ? I mean if there are no seg faults and the program is running well

✦ You are exactly right: in a perfect world where the program is "well-behaved," Ctrl+C should trigger your cleanup.

  However, in your specific main.rs architecture, there is a "Reference Counting Trap" that can prevent cleanup from running, even if you think you're
  shutting down correctly.

  1. The Arc Reference Count Trap
  In your main.rs, you have this:

    1 let _handler: Arc<Mutex<EPBFProgram>> = ... // Reference count = 1
    2
    3 let handler_clone = _handler.clone();       // Reference count = 2
    4 let poll_task = tokio::task::spawn_blocking(move || {
    5     // This thread now "owns" one reference to the handler
    6     while r_read.load(Ordering::SeqCst) {
    7         let log = {
    8             let handler = handler_clone.lock().unwrap();
    9             handler.poll_logs(100) // Calling C code
   10         };
   11     }
   12 });

  The Drop trait for EPBFProgram (which calls your C cleanup) will only execute when the reference count reaches zero.

  The failure scenario:
   1. You hit Ctrl+C.
   2. The main loop receives AppEvent::Shutdown.
   3. It sets is_main_loop_running to false.
   4. It calls poll_task.await.unwrap().

  But what if the C code is stuck?
  If the C function poll_logs(100) hangs or takes longer than expected inside that spawn_blocking thread, the handler_clone (the 2nd reference) is still
  held by that thread.
   - The main thread is stuck waiting at poll_task.await.
   - Because the main thread is stuck, it hasn't dropped its own _handler reference yet.
   - Because the polling thread is stuck, it hasn't dropped its handler_clone reference yet.

  The result: The reference count is still 2. If you get impatient and hit Ctrl+C a second time (which many people do), the OS kills the process. The
  reference count never hit zero, and cleanup never runs.

  2. The "Mutex Deadlock" Risk during Shutdown
  There is another subtle way Ctrl+C can fail to clean up:

  In your handle_reload function:

   1 let mut h = handler.lock().unwrap();
   2 match h.reload_rules(rules) { ... }

  And in your poll_task:

   1 let handler = handler_clone.lock().unwrap();
   2 handler.poll_logs(100)

  If you hit Ctrl+C exactly while the program is reloading rules, and something goes wrong (like a panic or a hang in the C side of manage_ipv4_rule), the
  Mutex remains "poisoned" or locked.
  If the shutdown logic tries to acquire that same lock to perform a final cleanup, it will hang forever. Again, the user will eventually kill the process
  manually, skipping Drop.

  3. "Panic = Abort"
  By default, some Rust configurations (especially in embedded or high-performance contexts) use panic = 'abort' in Cargo.toml.
   - If your code panics (for example, .unwrap() on a failed lock or a failed file read), and it's set to abort, the process terminates immediately.
   - It does not unwind the stack.
   - It does not call Drop.

  Educational Takeaway: "Explicit is better than Implicit"
  Relying on Drop for system-wide resources (like eBPF programs, file locks, or shared memory) is often considered a "secondary" safety net.

  In high-reliability systems, engineers often do Explicit Cleanup:
  Instead of waiting for the object to go out of scope, they have an explicit shutdown() method:

   1 // Instead of just dropping, we call this in the Shutdown event
   2 handler.lock().unwrap().manual_shutdown();

  Why is this better?
  It allows you to see exactly where the cleanup fails. If your program hangs during manual_shutdown(), you know exactly which C function or which lock is
  the culprit, rather than just wondering why the "Exclusivity" error keeps appearing on the next run.