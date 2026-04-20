use std::fs;
use serde::Deserialize;
use std::net::Ipv4Addr ;

#[derive(Deserialize, Debug)]
pub struct Rules {
    pub blocked_ipv4: Vec<Ipv4Addr> ,
    pub blocked_ports: Vec<u16>
}

impl<'a> Rules {
    pub fn load_from_file(f_path : &'a str) -> Result<Self, i32> {
        let content =  fs::read_to_string("rules.json").map_err(|_|  -1)? ; 
        let rules: Rules = serde_json::from_str(&content).map_err(|_|  -1)? ; 
        return Ok(rules) ;
    }
}