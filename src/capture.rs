use std::any::Any;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use ffi::MacAddress;

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct Timeval {
        tv_sec: i64,
        tv_usec: i64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) enum CaptureResult {
        Ok = 0,
        InvalidFilter,
        FilterUpdateFailed,
        DeviceOpenFailed,
        CaptureStartFailed,
    }

    extern "Rust" {
        type Context;

        fn on_tcp_message(ctx: &Context, conn: &ConnectionData, side: i8, payload: &[u8], missing_bytes: usize, timestamp: Timeval);
        fn on_tcp_connection_start(ctx: &Context, conn: &ConnectionData);
        fn on_tcp_connection_end(ctx: &Context, conn: &ConnectionData);

        fn log_error_enabled() -> bool;
        fn log_error(message: &CxxString);
        fn log_warn_enabled() -> bool;
        fn log_warn(message: &CxxString);
        fn log_info_enabled() -> bool;
        fn log_info(message: &CxxString);
        fn log_debug_enabled() -> bool;
        fn log_debug(message: &CxxString);
        fn log_trace_enabled() -> bool;
        fn log_trace(message: &CxxString);
    }

    unsafe extern "C++" {
        include!("tcp-stream-capture/src/capture.h");

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

        #[namespace = "pcpp"]
        type ConnectionData;

        fn get_conn_src_addr(conn: &ConnectionData) -> IpAddress;
        fn get_conn_dst_addr(conn: &ConnectionData) -> IpAddress;
        fn get_conn_src_port(conn: &ConnectionData) -> u16;
        fn get_conn_dst_port(conn: &ConnectionData) -> u16;
        fn get_conn_flow_key(conn: &ConnectionData) -> u32;
        fn get_conn_start_time(conn: &ConnectionData) -> Timeval;
        fn get_conn_end_time(conn: &ConnectionData) -> Timeval;

        type TcpStreamCapture;

        fn capture_from_live(device: &LiveDevice, ctx: Box<Context>) -> UniquePtr<TcpStreamCapture>;
        fn capture_from_file(filename: &[u8], ctx: Box<Context>) -> UniquePtr<TcpStreamCapture>;

        fn set_filter(self: Pin<&mut TcpStreamCapture>, filter: &str) -> CaptureResult;
        fn clear_filter(self: Pin<&mut TcpStreamCapture>) -> CaptureResult;

        fn start_capturing(self: Pin<&mut TcpStreamCapture>) -> CaptureResult;
        fn stop_capturing(self: Pin<&mut TcpStreamCapture>);
    }
}

fn log_error_enabled() -> bool { tracing::enabled!(tracing::Level::ERROR) }
fn log_warn_enabled()  -> bool { tracing::enabled!(tracing::Level::WARN) }
fn log_info_enabled()  -> bool { tracing::enabled!(tracing::Level::INFO) }
fn log_debug_enabled() -> bool { tracing::enabled!(tracing::Level::DEBUG) }
fn log_trace_enabled() -> bool { tracing::enabled!(tracing::Level::TRACE) }

fn log_error(message: &cxx::CxxString) { tracing::error!("{}", message); }
fn log_warn (message: &cxx::CxxString) { tracing::warn! ("{}", message); }
fn log_info (message: &cxx::CxxString) { tracing::info! ("{}", message); }
fn log_debug(message: &cxx::CxxString) { tracing::debug!("{}", message); }
fn log_trace(message: &cxx::CxxString) { tracing::trace!("{}", message); }

fn time_from_timeval(tv: ffi::Timeval) -> Option<SystemTime>
{
    if tv.tv_sec == 0 && tv.tv_usec == 0 {
        return None;
    }
    if tv.tv_sec < 0 || tv.tv_usec < 0 {
        tracing::warn!("got timeval before epoch: tv_sec={}, tv_usec={}", tv.tv_sec, tv.tv_usec);
        return None;
    }
    Some(
        UNIX_EPOCH
        + Duration::from_secs(tv.tv_sec.try_into().unwrap())
        + Duration::from_micros(tv.tv_usec.try_into().unwrap())
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
        time_from_timeval(ffi::get_conn_start_time(&self.0))
    }

    pub fn end_time(&self) -> Option<SystemTime>
    {
        time_from_timeval(ffi::get_conn_end_time(&self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpStreamSide {
    SideA = 0,
    SideB = 1,
}

impl TcpStreamSide {
    fn from_i8(side: i8) -> Self {
        if side == 0 {
            Self::SideA
        } else {
            Self::SideB
        }
    }
}

pub enum TcpStreamEvent<'a> {
    Message {
        conn: TcpConnection<'a>,
        side: TcpStreamSide,
        payload: &'a [u8],
        /// The number of missing bytes due to packet loss.
        missing_bytes: usize,
        /// When this packet was received.
        timestamp: Option<SystemTime>,
    },
    ConnectionStart(TcpConnection<'a>),
    ConnectionEnd(TcpConnection<'a>),
}

pub type OnTcpEvent = fn(event: TcpStreamEvent<'_>, user_cookie: &(dyn Any + Send));

pub struct Context {
    on_tcp_event: OnTcpEvent,
    user_cookie: Box<dyn Any + Send>,
}

impl Context {
    pub fn new(on_tcp_event: OnTcpEvent, user_cookie: Box<dyn Any + Send>) -> Self
    {
        Self { on_tcp_event, user_cookie }
    }

    fn handle_tcp_event(&self, event: TcpStreamEvent<'_>)
    {
        (self.on_tcp_event)(event, &self.user_cookie);

        fn is_send<T: Send>() -> bool { return true; }
        assert!(is_send::<Context>());
    }
}

fn on_tcp_message(ctx: &Context, conn: &ffi::ConnectionData, side: i8, payload: &[u8], missing_bytes: usize, timestamp: ffi::Timeval)
{
    let event = TcpStreamEvent::Message {
        conn: TcpConnection(conn),
        side: TcpStreamSide::from_i8(side),
        payload,
        missing_bytes,
        timestamp: time_from_timeval(timestamp),
    };
    ctx.handle_tcp_event(event);
}

fn on_tcp_connection_start(ctx: &Context, conn: &ffi::ConnectionData)
{
    let event = TcpStreamEvent::ConnectionStart(TcpConnection(conn));
    ctx.handle_tcp_event(event);
}

fn on_tcp_connection_end(ctx: &Context, conn: &ffi::ConnectionData)
{
    let event = TcpStreamEvent::ConnectionEnd(TcpConnection(conn));
    ctx.handle_tcp_event(event);
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
