use std::sync::atomic::{AtomicBool, Ordering} ; 
use std::sync::Arc ; 
use std::sync::Mutex ; 

use config::AppConfig;
use log_writer::spawn_logger;
use tokio::signal ; 
use xdp::* ; 
mod config ;
mod xdp ;
use rules::* ; 
mod rules ;
mod log_writer ;


#[tokio::main]
async fn main() {
    let config = match AppConfig::load_from_file("config.yaml") {
        Ok(config) => config,
        Err(_) => {
            eprintln!("failed to load config.yaml");
            return;
        }
    };

    // 1. Spawn the logger, getting both halves.
    let (log_tx, log_worker) = log_writer::spawn_logger(&config.log_path, 1024);

    let is_main_loop_running = Arc::new(AtomicBool::new(true));
    let r = is_main_loop_running.clone();
    
    // Clone the sender for the Ctrl-C handler
    let ctrl_c_tx = log_tx.clone(); 
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen to kill signal");
        ctrl_c_tx.write(String::from("Stopping service"));
        r.store(false, Ordering::SeqCst);
        // ctrl_c_tx is safely dropped here when this task ends.
    });

    let rules = match Rules::load_from_file(&config.rules_path) {
        Ok(rules) => rules,
        Err(_) => {
            log_tx.write(String::from("failed to load rules, exiting"));
            drop(log_tx); 
            let _ = log_worker.shutdown().await;
            return;
        }
    };

    let _handler: Arc<Mutex<XdpProgram>> = match XdpProgram::attach(&config.kernel_path, &config.interface) {
        Ok(xdp) => xdp,
        Err(err) => {
            log_tx.write(format!("attach failed: {err}"));
            drop(log_tx);
            let _ = log_worker.shutdown().await;
            return;
        }
    };
    
    match _handler.lock().unwrap().load_rules(&rules.blocked_ipv4, &rules.blocked_ports) {
        Ok(_) => log_tx.write(String::from("loaded rules")), 
        Err(_) => {
            log_tx.write(String::from("failed to load rules"));
            drop(log_tx);
            let _ = log_worker.shutdown().await;
            return; 
        }
    }

    let r_read = is_main_loop_running.clone();
    let handler_clone = _handler.clone();
    
    // Clone the sender for the polling task
    let poll_tx = log_tx.clone(); 
    let poll_task = tokio::task::spawn_blocking(move || {
        let handler = handler_clone.lock().unwrap(); 
        while r_read.load(Ordering::SeqCst) {
            if let Some(log) = handler.poll_logs(100) {
                poll_tx.try_write(log);
            }
        }
        // No need to return anything here! poll_tx is dropped automatically.
    });

    // Wait for the polling loop to finish (which happens when r_read becomes false)
    poll_task.await.unwrap();

    // 2. CRITICAL: Drop the main thread's copy of the sender.
    // At this point, the ctrl-c sender is dropped, the poll sender is dropped.
    // Dropping this final sender closes the mpsc channel, telling the BufWriter to flush and exit.
    drop(log_tx);

    // 3. Await the worker to ensure all logs are flushed to disk.
    if let Err(err) = log_worker.shutdown().await {
        eprintln!("log writer shutdown failed: {err}");
    }
}
