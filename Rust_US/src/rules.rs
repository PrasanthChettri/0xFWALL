use std::fs;
use serde::Deserialize;
use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::HashSet ; 

#[derive(Deserialize, Debug)]
pub struct RuleSet {
    pub blocked_ipv4: Vec<Ipv4Net>,
    pub blocked_ipv6: Vec<Ipv6Net>,
    pub blocked_ports: Vec<u16>,
}

#[derive(Deserialize, Debug)]
pub struct Rules {
    pub ingress: RuleSet,
    pub egress: RuleSet,
}

impl Rules {
    pub fn load_from_file(f_path : &str) -> Result<Self, i32> {
        let content =  fs::read_to_string(f_path).map_err(|_|  -1)? ; 
        let rules: Rules = serde_json::from_str(&content).map_err(|_|  -1)? ; 
        return Ok(rules) ;
    }
}
