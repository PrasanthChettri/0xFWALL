use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering} ; 
use tokio::signal ; 
use std::sync::Arc ; 
use std::sync::Mutex ; 

use xdp::* ; 
mod xdp ;
use rules::* ; 
mod rules ;
use tokio ;
use serde::Deserialize;

#[tokio::main]
async fn main() {
    let k_path = "../C/target/kernel.o";
    let json_path = "rules.json" ; 
    let ifname = "ens33";

    let is_main_loop_running = Arc::new(AtomicBool::new(true)) ; 
    let r = is_main_loop_running.clone() ; 
    tokio::spawn(
        async move {
            signal::ctrl_c().await.expect("Failed to listen to kill signal") ; 
            println!("Stopping service") ;
            r.store(false, Ordering::SeqCst) ; 
        }
    ) ; 

    let rules = match  Rules::load_from_file(&json_path) {
        Ok(rules) => rules ,
        Err(_) => panic!("F"), 
    } ;

    let _handler: Arc<Mutex<XdpProgram>> = match XdpProgram::attach(k_path, ifname) {
        Ok(xdp) => xdp,
        Err(err) => {
            eprintln!("attach failed: {err}");
            return;
        }
    };
    
    match _handler.clone().lock().unwrap().load_rules(&rules.blocked_ipv4, &rules.blocked_ports) {
        Ok(r) => print!("YAY") , 
        Err(val) => print!("NAY{val}") 
    }

    let r_read = is_main_loop_running.clone() ; 
    let handler_clone = _handler.clone() ; 
    tokio::spawn(async move {
        let mut handler = handler_clone.lock().unwrap() ; 
        while(r_read.load(Ordering::SeqCst)) {
            let log = handler.poll_logs(100) ;
            dbg!(log) ;
        }
        drop(handler) ; 
    }).await.unwrap() ;
}
