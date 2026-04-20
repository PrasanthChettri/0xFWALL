use std::ffi::CString;
use std::os::raw::c_char;
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
    let ifname = "lo";

    let rules = match  Rules::load_from_file(&json_path) {
        Ok(rules) => rules ,
        Err(_) => panic!("F"), 
    } ;

    dbg!(&rules) ;
    tokio::spawn(async {
        print!("Hello") ; 
    }).await.unwrap() ;

    let _handler = match XdpProgram::attach(k_path, ifname) {
        Ok(xdp) => xdp,
        Err(err) => {
            eprintln!("attach failed: {err}");
            return;
        }
    };
    
    match XdpProgram::load_rules(&rules.blocked_ipv4, &rules.blocked_ports) {
        Ok(r) => print!("YAY") , 
        Err(val) => print!("NAY{val}") 
    }
    tokio::spawn(async {
        for i in [0 .. 100 ] {
            dbg!("_handler") ; 
        }
    }).await.unwrap() ;
}
