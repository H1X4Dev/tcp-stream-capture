use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use thiserror::Error;

use crate::capture::ffi;
use crate::util::SwapDebugAndDisplay;

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

#[derive(Debug, Error)]
#[error("bytes do not form a valid UTF-8 string")]
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


#[derive(Debug)]
pub struct SomeError;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("given string is not a valid BPF filter")]
    InvalidFilter,
    #[error("unable to set or clear device filter")]
    FilterUpdateFailed,
    #[error("unable to open device")]
    DeviceOpenFailed,
    #[error("unknown error")]
    Unknown,
}

impl From<ffi::CaptureResult> for Result<(), CaptureError> {
    fn from(value: ffi::CaptureResult) -> Self {
        use ffi::CaptureResult;
        match value {
            CaptureResult::Ok => Ok(()),
            CaptureResult::InvalidFilter => Err(CaptureError::InvalidFilter),
            CaptureResult::FilterUpdateFailed => Err(CaptureError::FilterUpdateFailed),
            CaptureResult::DeviceOpenFailed => Err(CaptureError::DeviceOpenFailed),
            _other => Err(CaptureError::Unknown),
        }
    }
}

pub struct TcpStreamCapture(cxx::UniquePtr<ffi::TcpStreamCapture>);

impl TcpStreamCapture {
    pub fn from_live(device: &LiveDevice, ctx: Context) -> Self
    {
        let inner = ffi::capture_from_live(&device.0, Box::new(ctx));
        Self(inner)
    }

    pub fn from_file(filename: &Path, ctx: Context) -> Self
    {
        let filename = filename.as_os_str().as_encoded_bytes();
        let inner = ffi::capture_from_file(filename, Box::new(ctx));
        Self(inner)
    }

    pub fn set_filter(&mut self, filter: &str) -> Result<(), CaptureError>
    {
        self.0.pin_mut().set_filter(filter).into()
    }

    pub fn clear_filter(&mut self) -> Result<(), SomeError>
    {
        let result = self.0.pin_mut().clear_filter();
        match result {
            true => Ok(()),
            false => Err(SomeError),
        }
    }

    pub fn start_capturing(&mut self) -> Result<(), SomeError>
    {
        let result = self.0.pin_mut().start_capturing();
        match result {
            true => Ok(()),
            false => Err(SomeError),
        }
    }

    pub fn stop_capturing(&mut self)
    {
        self.0.pin_mut().stop_capturing();
    }
}
