
use capture::ffi;

mod capture;


pub use self::ffi::MacAddress;
#[repr(transparent)]

pub struct LiveDevice(ffi::LiveDevice);

#[derive(Debug)]
pub struct Utf8Error;

impl LiveDevice {
    pub fn name(&self) -> Result<String, Utf8Error>
    {
        self.0.name().map_err(|_e| Utf8Error)
    }

    pub fn mac_address(&self) -> Option<MacAddress>
    {
        self.0.mac_address().as_option()
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







// TODO: TCP stream capture with reassembly
