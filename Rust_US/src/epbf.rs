use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::net::Ipv4Addr;
use ipnet::Ipv4Net;
use std::sync::Arc ; 
use std::sync::Mutex ; 
use std::fmt;
use crate::rules::Rules;
use std::time;
use std::time::UNIX_EPOCH;
use std::time::Duration;
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
            4 => "PORT_BLOCK_EGRESS"
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
    fn load_ingress_rules(rule_table: *const RulesFfi) -> c_int;
    fn load_egress_rules(rule_table: *const RulesFfi) -> c_int;
    fn poll_logs(bpf_md: *mut c_void, event_ptr: *mut Event, ms: c_int) -> c_int;
}

pub struct EPBFProgram {
    handle: *mut c_void,
}

unsafe impl Send for EPBFProgram {}
unsafe impl Sync for EPBFProgram {}

impl Drop for EPBFProgram {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { cleanup(self.handle) }
        }
    }
}

impl EPBFProgram {
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
                Mutex::new(Self { handle: bpf_obj })
            )
        )
    }

    pub fn load_rules_ingress(&self, ipv4_list: &[Ipv4Net], port_list: &[u16]) -> Result<(), i32> {
        let ipv4: Vec<u32> = ipv4_list.iter().map(|x| u32::from(x.addr()).to_be()).collect();
        let ipv4_prefix: Vec<u32> = ipv4_list.iter().map(|x| x.prefix_len() as u32).collect();
        let port: Vec<u16> = port_list.iter().map(|x| u16::from(*x).to_be()).collect();
        let rule_table = RulesFfi {
            ipv4_list:  ipv4.as_ptr(),
            ipv4_prefix_len: ipv4_prefix.as_ptr(),
            ipv4_count: ipv4.len() as c_int,
            port_list:  port.as_ptr(),
            port_count: port.len() as c_int,
        };

        match unsafe { load_ingress_rules(&rule_table as *const RulesFfi) } {
            0       => Ok(()),
            ret_val => Err(ret_val as i32),
        }
    }

    pub fn load_rules_egress(&self, ipv4_list: &[Ipv4Net], port_list: &[u16]) -> Result<(), i32> {
        let ipv4: Vec<u32> = ipv4_list.iter().map(|x| u32::from(x.addr()).to_be()).collect();
        let ipv4_prefix: Vec<u32> = ipv4_list.iter().map(|x| x.prefix_len() as u32).collect();
        let port: Vec<u16> = port_list.iter().map(|x| u16::from(*x).to_be()).collect();
        let rule_table = RulesFfi {
            ipv4_list:  ipv4.as_ptr(),
            ipv4_prefix_len: ipv4_prefix.as_ptr(),
            ipv4_count: ipv4.len() as c_int,
            port_list:  port.as_ptr(),
            port_count: port.len() as c_int,
        };

        match unsafe { load_egress_rules(&rule_table as *const RulesFfi) } {
            0       => Ok(()),
            ret_val => Err(ret_val as i32),
        }
    }

    pub fn load_rules(&self, rules: &Rules) -> Result<(), i32> {
        self.load_rules_ingress(&rules.ingress.blocked_ipv4, &rules.ingress.blocked_ports)?;
        self.load_rules_egress(&rules.egress.blocked_ipv4, &rules.egress.blocked_ports)?;
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
