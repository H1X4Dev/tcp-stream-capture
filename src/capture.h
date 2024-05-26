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

rust::Vec<LiveDevice> get_live_devices();
LiveDevice find_by_name(rust::Str name);
LiveDevice find_by_ip(rust::Str ip);
LiveDevice find_by_ip_or_name(rust::Str ip_or_name);

/*
class LiveDeviceList {
    std::vector<pcpp::PcapLiveDevice*> m_devices;
public:
    LiveDeviceList();
    std::vector<pcpp::PcapLiveDevice*> const& devices() const { return m_devices; }
    std::size_t size() const;
    LiveDevice get(std::size_t i) const;
};

std::unique_ptr<LiveDeviceList> new_live_device_list();
*/

IpAddress get_conn_src_addr(pcpp::ConnectionData const& conn) noexcept;
IpAddress get_conn_dst_addr(pcpp::ConnectionData const& conn) noexcept;
uint16_t get_conn_src_port(pcpp::ConnectionData const& conn) noexcept;
uint16_t get_conn_dst_port(pcpp::ConnectionData const& conn) noexcept;
uint32_t get_conn_flow_key(pcpp::ConnectionData const& conn) noexcept;
Timeval get_conn_start_time(pcpp::ConnectionData const& conn) noexcept;
Timeval get_conn_end_time(pcpp::ConnectionData const& conn) noexcept;

}  // namespace
