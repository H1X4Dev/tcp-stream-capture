use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use capture::ffi;
use util::SwapDebugAndDisplay;

mod capture;
mod util;

pub use capture::{
    MacAddress,
    TcpConnection,
    TcpStreamSide,
    TcpStreamEvent,
    OnTcpEvent,
    Context,
};

#[repr(transparent)]
pub struct LiveDevice(ffi::LiveDevice);

#[derive(Debug)]
pub struct Utf8Error;

impl LiveDevice {
    fn from_ffi(inner: ffi::LiveDevice) -> Option<Self>
    {
        if inner.is_null() {
            None
        } else {
            Some(Self(inner))
        }
    }

    pub fn find_by_name(name: &str) -> Option<Self>
    {
        Self::from_ffi(ffi::find_by_name(name))
    }

    pub fn find_by_ip(ip: &str) -> Option<Self>
    {
        Self::from_ffi(ffi::find_by_ip(ip))
    }

    pub fn find_by_ip_or_name(ip_or_name: &str) -> Option<Self>
    {
        Self::from_ffi(ffi::find_by_ip_or_name(ip_or_name))
    }

    pub fn name(&self) -> Result<String, Utf8Error>
    {
        self.0.name().map_err(|_e| Utf8Error)
    }

    pub fn mac_address(&self) -> Option<MacAddress>
    {
        self.0.mac_address().as_option()
    }

    pub fn ipv4_address(&self) -> Option<Ipv4Addr>
    {
        let addr: Ipv4Addr = self.0.ipv4_address().into();
        if addr.is_unspecified() {
            None
        } else {
            Some(addr)
        }
    }

    pub fn ipv6_address(&self) -> Option<Ipv6Addr>
    {
        let addr: Ipv6Addr = self.0.ipv6_address().into();
        if addr.is_unspecified() {
            None
        } else {
            Some(addr)
        }
    }

    pub fn ip_addresses(&self) -> Vec<IpAddr>
    {
        self.0.ip_addresses().into_iter().map(IpAddr::from).collect()
    }
}

pub fn get_live_devices() -> Vec<LiveDevice>
{
    let devices = ffi::get_live_devices();
    // ensure the original vector is not dropped
    let mut devices = std::mem::ManuallyDrop::new(devices);
    unsafe {
        // see https://doc.rust-lang.org/std/mem/fn.transmute.html
        Vec::from_raw_parts(devices.as_mut_ptr() as *mut LiveDevice, devices.len(), devices.capacity())
    }
}

impl Debug for LiveDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        f.debug_struct("LiveDevice")
            .field("name", &self.name())
            .field("mac_address", &self.mac_address().map(|x| SwapDebugAndDisplay(x)))
            .field("ipv4_address", &self.ipv4_address())
            .field("ipv6_address", &self.ipv6_address())
            .finish()
    }
}














// TODO: TCP stream capture with reassembly
