use std::fmt::Display;

#[cxx::bridge(namespace = "tcp_stream_capture")]
pub(crate) mod ffi {
    pub(crate) struct LiveDevice {
        m_device: *mut PcapLiveDevice,
    }

    #[derive(Debug)]
    pub struct MacAddress {
        pub bytes: [u8; 6],
    }

    #[derive(Debug)]
    pub(crate) struct OptionMacAddress {
        value: MacAddress,
        valid: bool,
    }

    unsafe extern "C++" {
        include!("tcp_stream_capture/src/capture.h");

        #[namespace = "pcpp"]
        type PcapLiveDevice;

        fn get_live_devices() -> Vec<LiveDevice>;
        fn name(self: &LiveDevice) -> Result<String>;
        fn mac_address(self: &LiveDevice) -> OptionMacAddress;

        type LiveDeviceList;
        fn new_live_device_list() -> UniquePtr<LiveDeviceList>;
        #[cxx_name = "size"]
        fn len(self: &LiveDeviceList) -> usize;
        fn get(self: &LiveDeviceList, i: usize) -> LiveDevice;
    }
}

impl Display for ffi::MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5],
        )
    }
}

impl ffi::OptionMacAddress {
    pub(crate) fn as_option(self) -> Option<ffi::MacAddress>
    {
        if self.valid {
            Some(self.value)
        } else {
            None
        }
    }
}
