use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct Ipv4Address {
        pub(crate) bytes: [u8; 4],
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct Ipv6Address {
        pub(crate) bytes: [u8; 16],
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) enum IpAddressVersion {
        V4,
        V6,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct IpAddress {
        bytes: [u8; 16],
        version: IpAddressVersion,
    }

    // #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    // struct TcpConnection {
    //     src_addr: IpAddress,
    //     dst_addr: IpAddress,
    //     src_port: u16,
    //     dst_port: u16,
    //     flow_key: u32,
    //     start_time_s: i64,
    //     start_time_us: i64,
    //     end_time_s: i64,
    //     end_time_us: i64,
    // }

    unsafe extern "C++" {
        include!("tcp_stream_capture/src/capture.h");

        #[namespace = "pcpp"]
        type PcapLiveDevice;

        fn get_live_devices() -> Vec<LiveDevice>;

        /// Returns NULL if no such device exists.
        fn find_by_name(name: &str) -> LiveDevice;
        fn find_by_ip(ip: &str) -> LiveDevice;
        fn find_by_ip_or_name(ip_or_name: &str) -> LiveDevice;

        fn name(self: &LiveDevice) -> Result<String>;
        fn mac_address(self: &LiveDevice) -> OptionMacAddress;
        fn ipv4_address(self: &LiveDevice) -> Ipv4Address;
        fn ipv6_address(self: &LiveDevice) -> Ipv6Address;
        fn ip_addresses(self: &LiveDevice) -> Vec<IpAddress>;

        /*
        type LiveDeviceList;
        fn new_live_device_list() -> UniquePtr<LiveDeviceList>;
        #[cxx_name = "size"]
        fn len(self: &LiveDeviceList) -> usize;
        fn get(self: &LiveDeviceList, i: usize) -> LiveDevice;
        */

        #[namespace = "pcpp"]
        type ConnectionData;

        fn get_conn_src_addr(conn: &ConnectionData) -> IpAddress;
        fn get_conn_dst_addr(conn: &ConnectionData) -> IpAddress;
        fn get_conn_src_port(conn: &ConnectionData) -> u16;
        fn get_conn_dst_port(conn: &ConnectionData) -> u16;
        fn get_conn_flow_key(conn: &ConnectionData) -> u32;
        fn get_conn_start_time(conn: &ConnectionData) -> [i64; 2];
        fn get_conn_end_time(conn: &ConnectionData) -> [i64; 2];

    }
}


fn time_from_timeval(tv_sec: i64, tv_usec: i64) -> Option<SystemTime>
{
    if tv_sec == 0 && tv_usec == 0 {
        return None;
    }
    if tv_sec < 0 || tv_usec < 0 {
        // TODO: log_warn
        return None;
    }
    Some(
        UNIX_EPOCH
        + Duration::from_secs(tv_sec.try_into().unwrap())
        + Duration::from_micros(tv_usec.try_into().unwrap())
    )
}

pub struct TcpConnection<'a>(&'a ffi::ConnectionData);

impl<'a> TcpConnection<'a> {
    pub fn src_addr(&self) -> IpAddr
    {
        ffi::get_conn_src_addr(&self.0).into()
    }

    pub fn dst_addr(&self) -> IpAddr
    {
        ffi::get_conn_dst_addr(&self.0).into()
    }

    pub fn src_port(&self) -> u16
    {
        ffi::get_conn_src_port(&self.0)
    }

    pub fn dst_port(&self) -> u16
    {
        ffi::get_conn_dst_port(&self.0)
    }

    pub fn flow_key(&self) -> u32
    {
        ffi::get_conn_flow_key(&self.0)
    }

    pub fn start_time(&self) -> Option<SystemTime>
    {
        let [tv_sec, tv_usec] = ffi::get_conn_start_time(&self.0);
        time_from_timeval(tv_sec, tv_usec)
    }

    pub fn end_time(&self) -> Option<SystemTime>
    {
        let [tv_sec, tv_usec] = ffi::get_conn_end_time(&self.0);
        time_from_timeval(tv_sec, tv_usec)
    }
}


impl ffi::LiveDevice {
    pub(crate) fn is_null(&self) -> bool
    {
        self.m_device.is_null()
    }
}

impl Display for ffi::MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
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

impl From<ffi::Ipv4Address> for Ipv4Addr {
    fn from(value: ffi::Ipv4Address) -> Self {
        Ipv4Addr::from(value.bytes).into()
    }
}

impl From<ffi::Ipv6Address> for Ipv6Addr {
    fn from(value: ffi::Ipv6Address) -> Self {
        Ipv6Addr::from(value.bytes).into()
    }
}

impl From<ffi::IpAddress> for IpAddr {
    fn from(value: ffi::IpAddress) -> Self {
        match value.version {
            ffi::IpAddressVersion::V4 => {
                let bytes = <[u8; 4]>::try_from(&value.bytes[0..4]).unwrap();
                Ipv4Addr::from(bytes).into()
            }
            ffi::IpAddressVersion::V6 => Ipv6Addr::from(value.bytes).into(),
            _ => panic!("unexpected IpAddressVersion"),
        }
    }
}
