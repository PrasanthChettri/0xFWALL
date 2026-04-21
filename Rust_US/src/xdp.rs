use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::net::Ipv4Addr;

#[repr(C)]
struct RulesFfi {
    ipv4_list:  *const u32,
    ipv4_count: c_int,
    port_list:  *const u16,
    port_count: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BlockedIpEvent {
    pub id:           u64,
    pub timestamp_ns: u64,
    pub src_ip:       u32,
    pub dst_ip:       u32,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub protocol:     u8,
    pub reason:       u8,
}

impl BlockedIpEvent {
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
    fn poll_logs(bpf_md: *mut c_void, ip_event_ptr: *mut BlockedIpEvent, ms: c_int) -> c_int;
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
    pub fn attach(obj_path: &str, ifname: &str) -> Result<Self, i32> {
        let c_path   = CString::new(obj_path).map_err(|_| -1_i32)?;
        let c_ifname = CString::new(ifname).map_err(|_| -1_i32)?;

        let err = unsafe { load_xdp(c_path.as_ptr(), c_ifname.as_ptr()) };
        if err != 0 {
            return Err(err as i32);
        }

        let bpf_obj = unsafe { get_bpf_obj() };
        Ok(Self { handle: bpf_obj })
    }

    pub fn load_rules(&self, ipv4_list: &[Ipv4Addr], port_list: &[u16]) -> Result<(), i32> {
        let ipv4: Vec<u32> = ipv4_list.iter().copied().map(u32::from).collect();
        let rule_table = RulesFfi {
            ipv4_list:  ipv4.as_ptr(),
            ipv4_count: ipv4.len() as c_int,
            port_list:  port_list.as_ptr(),
            port_count: port_list.len() as c_int,
        };

        dbg!(ipv4_list.first());

        match unsafe { load_rules(&rule_table as *const RulesFfi) } {
            0       => Ok(()),
            ret_val => Err(ret_val as i32),
        }
    }

    pub fn poll_logs(&self, ms: u16) -> Option<BlockedIpEvent> {
        let mut ip_event = BlockedIpEvent::new();

        match unsafe { poll_logs(self.handle, &mut ip_event as *mut BlockedIpEvent, ms.into()) } {
            ret if ret > 0 => Some(ip_event),
            _ => None,
        }
    }
}
