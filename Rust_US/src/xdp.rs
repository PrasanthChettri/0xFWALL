use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::net::Ipv4Addr;
use std::sync::Arc ; 
use std::sync::Mutex ; 
use std::fmt;


#[repr(C)]
struct RulesFfi {
    ipv4_list:  *const u32,
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
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ID: {:<5} | SRC: {:<15}:{:>5} | DST: {:<15}:{:>5} | PROTO: {:>3} | REASON: {}",
            self.id,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
            self.reason
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
    fn load_xdp(path: *const c_char, ifname: *const c_char) -> u32;
    fn get_bpf_obj() -> *mut c_void;
    fn cleanup(bpf_md: *mut c_void);
    fn load_rules(rule_table: *const RulesFfi) -> c_int;
    fn poll_logs(bpf_md: *mut c_void, event_ptr: *mut Event, ms: c_int) -> c_int;
}

pub struct XdpProgram {
    handle: *mut c_void,
}

unsafe impl Send for XdpProgram {}
unsafe impl Sync for XdpProgram {}

impl Drop for XdpProgram {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { cleanup(self.handle) }
        }
    }
}

impl XdpProgram {
    pub fn attach(obj_path: &str, ifname: &str) -> Result<Arc<Mutex<Self>>, i32> {
        let c_path   = CString::new(obj_path).map_err(|_| -1_i32)?;
        let c_ifname = CString::new(ifname).map_err(|_| -1_i32)?;

        let err = unsafe { load_xdp(c_path.as_ptr(), c_ifname.as_ptr()) };
        if err != 0 {
            return Err(err as i32);
        }

        let bpf_obj = unsafe { get_bpf_obj() };
        Ok(
            Arc::new(
                Mutex::new(Self { handle: bpf_obj })
            )
        )
    }

    pub fn load_rules_ingress(&self, ipv4_list: &[Ipv4Addr], port_list: &[u16]) -> Result<(), i32> {
        let ipv4: Vec<u32> = ipv4_list.iter().copied().map(|x| u32::from(x).to_be()).collect();
        let port: Vec<u16> = port_list.iter().copied().map(|x| u16::from(x).to_be()).collect();
        let rule_table = RulesFfi {
            ipv4_list:  ipv4.as_ptr(),
            ipv4_count: ipv4.len() as c_int,
            port_list:  port.as_ptr(),
            port_count: port.len() as c_int,
        };

        match unsafe { load_rules(&rule_table as *const RulesFfi) } {
            0       => Ok(()),
            ret_val => Err(ret_val as i32),
        }
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
