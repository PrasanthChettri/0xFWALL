use std::sync::Mutex;

use config::AppConfig;
use tokio::signal;
use epbf::*;
mod config;
mod epbf;
use rules::*;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::signal::unix::SignalKind;
use std::sync::atomic::AtomicBool;
use tokio::signal::unix::signal;
use tokio::sync::mpsc;

mod rules;
mod log_writer;

pub enum AppEvent {
    ReloadConfig,
    Shutdown,
}

pub async fn handle_reload(config: &AppConfig, handler: &Mutex<EPBFProgram>, tx: &log_writer::LogSender) {
    let rules = match Rules::load_from_file(&config.rules_path) {
        Ok(rules) => rules,
        Err(_) => {
            tx.write(String::from("failed to reload rules")).await;
            return;
        }
    };
    let mut h = handler.lock().unwrap();
    match h.reload_rules(rules) {
        Ok(_) => tx.write(String::from("reloaded rules")).await, 
        Err(_) => tx.write(String::from("rule reload failed")).await, 
    } ;
}

#[tokio::main]
async fn main() {
    let config = match AppConfig::load_from_file("config.yaml") {
        Ok(config) => Arc::new(config),
        Err(_) => {
            eprintln!("failed to load config.yaml");
            return;
        }
    };

    // 1. Spawn the logger, getting both halves.
    let (log_tx, log_worker) = log_writer::spawn_logger(&config.log_path, 1024);

    let rules = match Rules::load_from_file(&config.rules_path) {
        Ok(rules) => rules,
        Err(_) => {
            log_tx.write(String::from("failed to load rules, exiting")).await;
            drop(log_tx); 
            let _ = log_worker.shutdown().await;
            return;
        }
    };

    let _handler: Arc<Mutex<EPBFProgram>> = match EPBFProgram::attach(
        &config.epbf_path_ingress, &config.epbf_path_egress, &config.interface
    ) {
        Ok(xdp) => xdp,
        Err(err) => {
            log_tx.write(format!("attach failed: {err}")).await;
            drop(log_tx);
            let _ = log_worker.shutdown().await;
            return;
        }
    };

    match _handler.lock().unwrap().load_rules(rules) {
        Ok(_) => log_tx.write(String::from("loaded rules")).await, 
        Err(_) => {
            log_tx.write(String::from("failed to load rules")).await;
            drop(log_tx);
            let _ = log_worker.shutdown().await;
            return; 
        }
    }

    let is_main_loop_running = Arc::new(AtomicBool::new(true));

    // The central event channel
    let (tx, mut rx) = mpsc::channel::<AppEvent>(32);

    // SIGHUP Task - ONLY sends event
    let tx_hup = tx.clone();
    tokio::spawn(async move {
        let mut sighup = signal(SignalKind::hangup()).expect("Failed to bind SIGHUP");
        loop {
            sighup.recv().await;
            if tx_hup.send(AppEvent::ReloadConfig).await.is_err() {
                break;
            }
        }
    });

    // Ctrl-C Task - ONLY sends event
    let tx_ctrlc = tx.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen to kill signal");
        let _ = tx_ctrlc.send(AppEvent::Shutdown).await;
    });

    let r_read = is_main_loop_running.clone();
    let handler_clone = _handler.clone();
    
    // Clone the sender for the polling task
    let poll_tx = log_tx.clone(); 
    let poll_task = tokio::task::spawn_blocking(move || {
        while r_read.load(Ordering::SeqCst) {
            let log = {
                let handler = handler_clone.lock().unwrap(); 
                handler.poll_logs(50)
            };
            if let Some(log) = log {
                poll_tx.try_write(log);
            }
        }
    });

    // Central Event Loop
    while let Some(event) = rx.recv().await {
        match event {
            AppEvent::ReloadConfig => {
                handle_reload(&config, &_handler, &log_tx).await;
            }
            AppEvent::Shutdown => {
                log_tx.write(String::from("Stopping service")).await;
                is_main_loop_running.store(false, Ordering::SeqCst);
                break;
            }
        }
    }

    // Wait for the polling loop to finish
    poll_task.await.unwrap();

    // CRITICAL: Drop the main thread's copies of senders
    drop(tx);
    drop(log_tx);

    if let Err(err) = log_worker.shutdown().await {
        eprintln!("log writer shutdown failed: {err}");
    }
}
