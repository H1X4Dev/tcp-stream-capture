#pragma once

#include <array>
#include <memory>
#include "rust/cxx.h"

namespace pcpp {
    class PcapLiveDevice;
    class ConnectionData;
}

namespace tcp_stream_capture {
    struct LiveDevice;
    struct MacAddress;
    struct OptionMacAddress;
    struct Ipv4Address;
    struct Ipv6Address;
    struct IpAddress;
    struct Timeval;
    struct Context;
    class TcpStreamCapture;
}

#include "tcp-stream-capture/src/capture.rs.h"

namespace tcp_stream_capture {


rust::Vec<LiveDevice> get_live_devices();
LiveDevice find_by_name(rust::Str name);
LiveDevice find_by_ip(rust::Str ip);
LiveDevice find_by_ip_or_name(rust::Str ip_or_name);

IpAddress get_conn_src_addr(pcpp::ConnectionData const& conn) noexcept;
IpAddress get_conn_dst_addr(pcpp::ConnectionData const& conn) noexcept;
uint16_t get_conn_src_port(pcpp::ConnectionData const& conn) noexcept;
uint16_t get_conn_dst_port(pcpp::ConnectionData const& conn) noexcept;
uint32_t get_conn_flow_key(pcpp::ConnectionData const& conn) noexcept;
Timeval get_conn_start_time(pcpp::ConnectionData const& conn) noexcept;
Timeval get_conn_end_time(pcpp::ConnectionData const& conn) noexcept;

class TcpStreamCapture {
    class Impl;
    std::unique_ptr<Impl> m_impl;

public:
    TcpStreamCapture(std::unique_ptr<Impl> impl);
    ~TcpStreamCapture();

    CaptureResult set_filter(rust::Str filter);
    CaptureResult clear_filter();

    CaptureResult start_capturing();
    void stop_capturing();

    friend std::unique_ptr<TcpStreamCapture> capture_from_live(LiveDevice const& device, rust::Box<Context> ctx);
    friend std::unique_ptr<TcpStreamCapture> capture_from_file(rust::Slice<const uint8_t> filename, rust::Box<Context> ctx);
};

std::unique_ptr<TcpStreamCapture> capture_from_live(LiveDevice const& device, rust::Box<Context> ctx);
std::unique_ptr<TcpStreamCapture> capture_from_file(rust::Slice<const uint8_t> filename, rust::Box<Context> ctx);

}  // namespace
