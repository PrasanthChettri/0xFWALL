use std::sync::atomic::{AtomicBool, Ordering} ; 
use std::sync::Arc ; 
use std::sync::Mutex ; 

use config::AppConfig;
use log_writer::LogWriter;
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

    let is_main_loop_running = Arc::new(AtomicBool::new(true)) ; 
    let r = is_main_loop_running.clone() ; 
    tokio::spawn(
        async move {
            signal::ctrl_c().await.expect("Failed to listen to kill signal") ; 
            println!("Stopping service") ;
            r.store(false, Ordering::SeqCst) ; 
        }
    ) ; 

    let rules = match  Rules::load_from_file(&config.rules_path) {
        Ok(rules) => rules ,
        Err(_) => panic!("F"), 
    } ;

    let _handler: Arc<Mutex<XdpProgram>> = match XdpProgram::attach(&config.kernel_path, &config.interface) {
        Ok(xdp) => xdp,
        Err(err) => {
            eprintln!("attach failed: {err}");
            return;
        }
    };
    
    match _handler.clone().lock().unwrap().load_rules(&rules.blocked_ipv4, &rules.blocked_ports) {
        Ok(_) => print!("YAY") , 
        Err(val) => print!("NAY{val}") 
    }

    let log_writer = LogWriter::spawn(&config.log_path, 1024);
    let r_read = is_main_loop_running.clone() ; 
    let handler_clone = _handler.clone() ; 
    let poll_task = tokio::spawn(async move {
        let handler = handler_clone.lock().unwrap() ; 
        while r_read.load(Ordering::SeqCst) {
            if let Some(log) = handler.poll_logs(100) {
                let _ = log_writer.try_write(log);
            }
        }
        drop(handler) ; 
        log_writer
    });

    let log_writer = poll_task.await.unwrap();
    if let Err(err) = log_writer.shutdown().await {
        eprintln!("log writer shutdown failed: {err}");
    }
}
