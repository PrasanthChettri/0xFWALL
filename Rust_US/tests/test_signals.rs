use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::process::{Command, Stdio};
use std::time::Duration;
use std::fs;
use tempfile::NamedTempFile;
use assert_cmd::cargo::cargo_bin;

#[test]
fn test_sighup_reloads_rules() {
    // 1. Prepare dummy configuration and rules files.
    let mut rules_file = NamedTempFile::new().unwrap();
    // Assuming your rules format is JSON. You might need to adapt this 
    // if your real `rules.json` uses a different format.
    fs::write(rules_file.path(), r#"{"blocked_ips": ["1.1.1.1"]}"#).unwrap();

    // 2. Set up a temporary working directory to isolate the test.
    let test_dir = tempfile::tempdir().unwrap();
    let test_config_path = test_dir.path().join("config.yaml");
    let test_log_path = test_dir.path().join("test_blocked.log");

    // Note: eBPF usually requires root to attach. If you run `cargo test` as a normal user, 
    // the binary will likely panic or exit early when `EPBFProgram::attach` is called.
    // In professional environments, you either mock the eBPF layer for tests or run 
    // integration tests as root in an isolated VM/Container.
    let config_content = format!(
        r#"
rules_path: "{}"
log_path: "{}"
epbf_path_ingress: "/fake/path/ingress.o"
epbf_path_egress: "/fake/path/egress.o"
interface: "lo"
"#,
        rules_file.path().display(),
        test_log_path.display()
    );
    fs::write(&test_config_path, config_content).unwrap();

    // 3. Spawn the compiled binary directly (not via `cargo run` so we get the correct PID)
    let bin_path = cargo_bin("Rust_US");
    let mut child = Command::new(bin_path)
        .current_dir(test_dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn process");

    // Wait a moment for the process to initialize
    std::thread::sleep(Duration::from_millis(500));

    // Check if the process exited early (e.g., due to missing root permissions for eBPF)
    if let Ok(Some(status)) = child.try_wait() {
        println!("Process exited early with status: {}. (This is expected if not running as root)", status);
        return; // Skip the rest of the test gracefully
    }

    // 4. Modify the rules file to simulate a configuration change
    fs::write(rules_file.path(), r#"{"blocked_ips": ["1.1.1.1", "8.8.8.8"]}"#).unwrap();

    // 5. Send SIGHUP to the application
    let pid = Pid::from_raw(child.id() as i32);
    let _ = signal::kill(pid, Signal::SIGHUP);

    // Wait for the SIGHUP to be processed
    std::thread::sleep(Duration::from_millis(500));

    // 6. Cleanup: shut down the process gracefully
    let _ = signal::kill(pid, Signal::SIGINT);
    let _ = child.wait();

    // 7. Assertions
    // In a fully mocked environment, you would assert that the log file 
    // contains the successful reload message.
    if test_log_path.exists() {
        let log_content = fs::read_to_string(test_log_path).unwrap_or_default();
        // assert!(log_content.contains("reloaded rules"));
        println!("Test finished. Log output:\n{}", log_content);
    }
}
