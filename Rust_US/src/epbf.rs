use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::net::Ipv4Addr;
use ipnet::Ipv4Net;
use std::sync::Arc ; 
use std::sync::Mutex ; 
use std::fmt;
use crate::rules::{Rules, RuleSet};
use std::time;
use std::time::UNIX_EPOCH;
use std::time::Duration;
use std::collections::HashSet ; 
use chrono::{DateTime, Local} ;



#[repr(C)]
struct RulesFfi {
    ipv4_list:  *const u32,
    ipv4_prefix_len:  *const u32,
    ipv4_count: c_int,
    port_list:  *const u16,
    port_count: c_int,
}

#[repr(C)]
enum c_direction {
    INGRESS = 0 , 
    EGRESS = 1
}

#[repr(C)]
enum c_action {
    UPSERT = 0 ,  
    DELETE = 1 ,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct c_ipv4_rule {
   prefix_len: u32 ,  
   addr: u32 ,  
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct c_port_rule {
   port: u16 ,  
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Event {
    pub id:           u64,
    pub timestamp_ns: u64,
    pub src_ip:       u32,
    pub dst_ip:       u32,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub protocol:     u8,
    pub reason:       u8,
    pub event_type:   u8,
    _pad:             u8,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let src_ip = Ipv4Addr::from(u32::from_be(self.src_ip));
        let dst_ip = Ipv4Addr::from(u32::from_be(self.dst_ip));
        let src_port = u16::from_be(self.src_port);
        let dst_port = u16::from_be(self.dst_port);
        let dt : DateTime<Local> = (UNIX_EPOCH + Duration::from_nanos(self.timestamp_ns)).into();
        let ts = dt.format("%Y-%m-%d %H:%M:%S%.3f");

        let reason_str = match self.reason {
            1 => "IP_BLOCK_INGRESS",
            2 => "PORT_BLOCK_INGRESS",
            3 => "IP_BLOCK_EGRESS",
            4 => "PORT_BLOCK_EGRESS" , 
            _ => "UNKNOWN"
        };

        write!(
            f,
            "[{}] ID: {:<5} | TYPE: {:<2} | SRC: {:<15}:{:>5} | DST: {:<15}:{:>5} | PROTO: {:>3} | REASON: {}",
            ts, 
            self.id,
            self.event_type,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            self.protocol,
            reason_str, 
        )
    }
}

impl Event {
    /// Return a zeroed-out value suitable for use as a C output buffer.
    pub fn new() -> Self {
        // SAFETY: every bit-pattern is valid for a repr(C) struct of
        // plain integer fields.
        unsafe { std::mem::zeroed() }   // ← fix 1: was `Self{}`
    }
}

unsafe extern "C" {
    //fn load_xdp(path: *const c_char, ifname: *const c_char) -> u32;
    //fn load_tc() -> u32;
    fn load_epbf(xdp_path: *const c_char, tc_path: *const c_char, ifname: *const c_char) -> u32; 
    fn get_bpf_obj() -> *mut c_void;
    fn cleanup(bpf_md: *mut c_void);

    fn manage_ipv4_rule(ipv4_rule: *const c_ipv4_rule, action: c_int, direction: c_int) -> c_int; 
    fn manage_port_rule(port_rule: *const c_port_rule, action: c_int, direction: c_int) -> c_int; 

    fn poll_logs(bpf_md: *mut c_void, event_ptr: *mut Event, ms: c_int) -> c_int;
}

pub struct EPBFProgram {
    handle: *mut c_void,
    current_rules: Option<Rules>
}

unsafe impl Send for EPBFProgram {}
unsafe impl Sync for EPBFProgram {}

impl Drop for EPBFProgram {
    fn drop(&mut self) {
        self.cleanup() ; 
    }
}

impl EPBFProgram {
    pub fn cleanup(&mut self) -> Result<(), i32> {
        if self.handle.is_null() {
            return Err(-1) ; 
        }
        unsafe { cleanup(self.handle) } ; 
        Ok(())
    }
    pub fn attach(ingress_obj_path: &str, egress_obj_path: &str, ifname: &str) -> Result<Arc<Mutex<Self>>, i32> {
        let iop_cpath   = CString::new(ingress_obj_path).map_err(|_| -1_i32)?;
        let eop_cpath   = CString::new(egress_obj_path).map_err(|_| -1_i32)?;
        let c_ifname = CString::new(ifname).map_err(|_| -1_i32)?;

        let err_epbf = unsafe { load_epbf(iop_cpath.as_ptr(), eop_cpath.as_ptr(), c_ifname.as_ptr()) };
        if err_epbf != 0 {
            return Err(err_epbf as i32);
        }
        let bpf_obj = unsafe { get_bpf_obj() };
        Ok(
            Arc::new(
                Mutex::new(Self { handle: bpf_obj, current_rules: None })
            )
        )
    }

    fn get_diff(&self, new_rules: &Rules) -> (Rules, Rules) {
        let current_unwrapped = self.current_rules.as_ref().unwrap();

        // Convert current rules to HashSets
        let c_ipv4_ingress_set: HashSet<_> = current_unwrapped.ingress.blocked_ipv4.iter().cloned().collect();
        let c_ipv4_egress_set: HashSet<_> = current_unwrapped.egress.blocked_ipv4.iter().cloned().collect();
        let c_port_ingress_set: HashSet<_> = current_unwrapped.ingress.blocked_ports.iter().cloned().collect();
        let c_port_egress_set: HashSet<_> = current_unwrapped.egress.blocked_ports.iter().cloned().collect();

        // Convert new rules to HashSets
        let n_ipv4_ingress_set: HashSet<_> = new_rules.ingress.blocked_ipv4.iter().cloned().collect();
        let n_ipv4_egress_set: HashSet<_> = new_rules.egress.blocked_ipv4.iter().cloned().collect();
        let n_port_ingress_set: HashSet<_> = new_rules.ingress.blocked_ports.iter().cloned().collect();
        let n_port_egress_set: HashSet<_> = new_rules.egress.blocked_ports.iter().cloned().collect();

        // Calculate "to delete"
        let ipv4_ingress_to_delete: Vec<_> = c_ipv4_ingress_set.difference(&n_ipv4_ingress_set).cloned().collect();
        let ipv4_egress_to_delete: Vec<_> = c_ipv4_egress_set.difference(&n_ipv4_egress_set).cloned().collect();
        let port_ingress_to_delete: Vec<_> = c_port_ingress_set.difference(&n_port_ingress_set).cloned().collect();
        let port_egress_to_delete: Vec<_> = c_port_egress_set.difference(&n_port_egress_set).cloned().collect();

        // Calculate "to add" (upsert)
        let ipv4_ingress_to_add: Vec<_> = n_ipv4_ingress_set.difference(&c_ipv4_ingress_set).cloned().collect();
        let ipv4_egress_to_add: Vec<_> = n_ipv4_egress_set.difference(&c_ipv4_egress_set).cloned().collect();
        let port_ingress_to_add: Vec<_> = n_port_ingress_set.difference(&c_port_ingress_set).cloned().collect();
        let port_egress_to_add: Vec<_> = n_port_egress_set.difference(&c_port_egress_set).cloned().collect();

        let to_delete_rules = Rules {
            ingress: RuleSet {
                blocked_ipv4: ipv4_ingress_to_delete,
                blocked_ports: port_ingress_to_delete,
            },
            egress: RuleSet {
                blocked_ipv4: ipv4_egress_to_delete,
                blocked_ports: port_egress_to_delete,
            },
        };
        let to_add_rules = Rules {
            ingress: RuleSet {
                blocked_ipv4: ipv4_ingress_to_add,
                blocked_ports: port_ingress_to_add,
            },
            egress: RuleSet {
                blocked_ipv4: ipv4_egress_to_add,
                blocked_ports: port_egress_to_add,
            },
        };
        (to_add_rules, to_delete_rules)
    }
    
    pub fn reload_rules(&mut self, rules: Rules) -> Result<(), i32> {
        match &self.current_rules {
            Some(_) => {
                let (to_add, to_delete) = self.get_diff(&rules) ; 
                self.load_rules(to_add)? ; 
                self.delete_rules(to_delete)?; 
                self.current_rules = Some(rules) ;
                Ok(())
            },
            None => self.load_rules(rules)
        } 
    }

    fn upsert_rules(&mut self, rules: &Rules) -> Result<(), i32> {
        // Ingress IPv4
        for ip_net in &rules.ingress.blocked_ipv4 {
            let c_rule = c_ipv4_rule {
                prefix_len: ip_net.prefix_len() as u32,
                addr: u32::from(ip_net.addr()).to_be(),
            };
            match unsafe { manage_ipv4_rule(&c_rule as *const c_ipv4_rule, c_action::UPSERT as i32, c_direction::INGRESS as i32) } {
                0 => {},
                err => return Err(err),
            }
        }

        // Ingress Ports
        for port in &rules.ingress.blocked_ports {
            let c_rule = c_port_rule { port: port.to_be() };
            match unsafe { manage_port_rule(&c_rule as *const c_port_rule, c_action::UPSERT as i32, c_direction::INGRESS as i32) } {
                0 => {},
                err => return Err(err),
            }
        }

        // Egress IPv4
        for ip_net in &rules.egress.blocked_ipv4 {
            let c_rule = c_ipv4_rule {
                prefix_len: ip_net.prefix_len() as u32,
                addr: u32::from(ip_net.addr()).to_be(),
            };
            match unsafe { manage_ipv4_rule(&c_rule as *const c_ipv4_rule, c_action::UPSERT as i32, c_direction::EGRESS as i32) } {
                0 => {},
                err => return Err(err),
            }
        }

        // Egress Ports
        for port in &rules.egress.blocked_ports {
            let c_rule = c_port_rule { port: port.to_be() };
            match unsafe { manage_port_rule(&c_rule as *const c_port_rule, c_action::UPSERT as i32, c_direction::EGRESS as i32) } {
                0 => {},
                err => return Err(err),
            }
        }
        Ok(())
    }

    fn delete_rules(&mut self, rules: Rules) -> Result<(), i32> {
        // Ingress IPv4
        for ip_net in &rules.ingress.blocked_ipv4 {
            let c_rule = c_ipv4_rule {
                prefix_len: ip_net.prefix_len() as u32,
                addr: u32::from(ip_net.addr()).to_be(),
            };
            match unsafe { manage_ipv4_rule(&c_rule as *const c_ipv4_rule, c_action::DELETE as i32, c_direction::INGRESS as i32) } {
                0 => {},
                err => return Err(err),
            }
        }

        // Ingress Ports
        for port in &rules.ingress.blocked_ports {
            let c_rule = c_port_rule { port: port.to_be() };
            match unsafe { manage_port_rule(&c_rule as *const c_port_rule, c_action::DELETE as i32, c_direction::INGRESS as i32) } {
                0 => {},
                err => return Err(err),
            }
        }

        // Egress IPv4
        for ip_net in &rules.egress.blocked_ipv4 {
            let c_rule = c_ipv4_rule {
                prefix_len: ip_net.prefix_len() as u32,
                addr: u32::from(ip_net.addr()).to_be(),
            };
            match unsafe { manage_ipv4_rule(&c_rule as *const c_ipv4_rule, c_action::DELETE as i32, c_direction::EGRESS as i32) } {
                0 => {},
                err => return Err(err),
            }
        }

        // Egress Ports
        for port in &rules.egress.blocked_ports {
            let c_rule = c_port_rule { port: port.to_be() };
            match unsafe { manage_port_rule(&c_rule as *const c_port_rule, c_action::DELETE as i32, c_direction::EGRESS as i32) } {
                0 => {},
                err => return Err(err),
            }
        }
        Ok(())
    }

    pub fn load_rules(&mut self, rules: Rules) -> Result<(), i32> {
        self.upsert_rules(&rules)?;
        self.current_rules = Some(rules);
        Ok(())
    }

    pub fn poll_logs(&self, ms: u16) -> Option<Event> {
        let mut event = Event::new();

        match unsafe { poll_logs(self.handle, &mut event as *mut Event, ms.into()) } {
            ret if ret > 0 => Some(event),
            0 => None,
            err => {dbg!(err); return None} ,
        }
    }
}
