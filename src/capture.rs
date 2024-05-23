use std::ffi::c_void;

use cxx::{type_id, ExternType};

#[repr(C)]
struct LiveDevice {
    _inner: *mut c_void,
}

unsafe impl ExternType for LiveDevice {
    type Id = type_id!("tcp_stream_capture::LiveDevice");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge(namespace = "tcp_stream_capture")]
mod ffi {
    unsafe extern "C++" {
        include!("tcp_stream_capture/src/capture.h");

        type LiveDevice = crate::capture::LiveDevice;
        fn name(self: &LiveDevice) -> Result<String>;

        type LiveDeviceList;
        fn new_live_device_list() -> UniquePtr<LiveDeviceList>;
        #[cxx_name = "size"]
        fn len(self: &LiveDeviceList) -> usize;
        fn get(self: &LiveDeviceList, i: usize) -> LiveDevice;
    }
}


pub fn test_device_list()
{
    let devices = ffi::new_live_device_list();
    println!("Found {} devices:", devices.len());
    for i in 0..devices.len() {
        let device = devices.get(i);
        match device.name() {
            Ok(name) => println!("{}. {}", i, name),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}
