#include "tcp_stream_capture/src/capture.h"
#include "tcp_stream_capture/src/capture.rs.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/MacAddress.h"
#include <pcap/pcap.h>
#include <sys/time.h>
#include <cstring>
#include <iostream>
#include <sstream>

namespace tcp_stream_capture {



namespace logging {


struct None { };

template <typename List>
struct LogData {
    List list;
};

template <typename Init, typename Value>
constexpr LogData<std::pair<Init&&, Value&&>> operator<<(LogData<Init>&& init, Value&& value) noexcept
{
    return {{ std::forward<Init>(init.list), std::forward<Value>(value) }};
}

template <typename Init, size_t n>
constexpr LogData<std::pair<Init&&, char const*>> operator<<(LogData<Init>&& init, char const (&value)[n]) noexcept
{
  return {{ std::forward<Init>(init.list), value }};
}

inline void output(std::ostream&, None)
{ }

template <typename Init, typename Last>
void output(std::ostream& os, std::pair<Init, Last>&& data)
{
    output(os, std::move(data.first));
    os << data.second;
}

using LogFn = void(std::string const&) noexcept;
using IsLogEnabledFn = bool() noexcept;

template <typename List>
void log(LogFn* do_log, char const* file, int line, LogData<List>&& data)
{
    std::stringstream s;
    s << file << ":" << line << ": ";
    output(s, std::move(data.list));
    do_log(s.str());
}


}  // namespace logging

#define LOG(is_log_enabled, log_fn, x)               \
do                                                   \
{                                                    \
    if (is_log_enabled)                              \
    {                                                \
        logging::log(                                \
            log_fn,                                  \
            __FILE__,                                \
            __LINE__,                                \
            logging::LogData<logging::None>() << x); \
    }                                                \
} while (false)

#define LOG_ERROR(x) LOG(log_error_enabled(), log_error, x)
#define LOG_WARN(x)  LOG(log_warn_enabled(),  log_warn,  x)
#define LOG_INFO(x)  LOG(log_info_enabled(),  log_info,  x)
#define LOG_DEBUG(x) LOG(log_debug_enabled(), log_debug, x)
#define LOG_TRACE(x) LOG(log_trace_enabled(), log_trace, x)


Ipv4Address mk_ipv4_address(uint8_t const* addr_bytes) noexcept
{
    Ipv4Address result;
    std::copy(addr_bytes, addr_bytes + sizeof(result.bytes), result.bytes.data());
    return result;
}

Ipv4Address mk_ipv4_address(sockaddr_in const& addr) noexcept
{
    return mk_ipv4_address(reinterpret_cast<uint8_t const*>(&addr.sin_addr));
}

Ipv4Address mk_ipv4_address(pcpp::IPv4Address addr) noexcept
{
    return mk_ipv4_address(addr.toBytes());
}

Ipv6Address mk_ipv6_address(uint8_t const* addr_bytes) noexcept
{
    Ipv6Address result;
    std::copy(addr_bytes, addr_bytes + sizeof(result.bytes), result.bytes.data());
    return result;
}

Ipv6Address mk_ipv6_address(sockaddr_in6 const& addr) noexcept
{
    return mk_ipv6_address(reinterpret_cast<uint8_t const*>(&addr.sin6_addr));
}

Ipv6Address mk_ipv6_address(pcpp::IPv6Address addr) noexcept
{
    return mk_ipv6_address(addr.toBytes());
}

IpAddress mk_ip_address(Ipv4Address addr) noexcept
{
    IpAddress result;
    result.version = IpAddressVersion::V4;
    std::copy(addr.bytes.begin(), addr.bytes.end(), result.bytes.begin());
    return result;
}

IpAddress mk_ip_address(Ipv6Address addr) noexcept
{
    IpAddress result;
    result.version = IpAddressVersion::V6;
    std::copy(addr.bytes.begin(), addr.bytes.end(), result.bytes.begin());
    return result;
}

IpAddress mk_ip_address(pcpp::IPv4Address const& addr) noexcept
{
    return mk_ip_address(mk_ipv4_address(addr));
}

IpAddress mk_ip_address(pcpp::IPv6Address const& addr) noexcept
{
    return mk_ip_address(mk_ipv6_address(addr));
}

IpAddress mk_ip_address(pcpp::IPAddress const& addr) noexcept
{
    if (addr.isIPv4())
        return mk_ip_address(addr.getIPv4());
    assert(addr.isIPv6());
    return mk_ip_address(addr.getIPv6());
}

IpAddress get_conn_src_addr(pcpp::ConnectionData const& conn) noexcept
{
    return mk_ip_address(conn.srcIP);
}

IpAddress get_conn_dst_addr(pcpp::ConnectionData const& conn) noexcept
{
    return mk_ip_address(conn.dstIP);
}

uint16_t get_conn_src_port(pcpp::ConnectionData const& conn) noexcept
{
    return conn.srcPort;
}

uint16_t get_conn_dst_port(pcpp::ConnectionData const& conn) noexcept
{
    return conn.dstPort;
}

uint32_t get_conn_flow_key(pcpp::ConnectionData const& conn) noexcept
{
    return conn.flowKey;
}

std::array<int64_t, 2> get_conn_start_time(pcpp::ConnectionData const& conn) noexcept
{
    return { conn.startTime.tv_sec, conn.startTime.tv_usec };
}

std::array<int64_t, 2> get_conn_end_time(pcpp::ConnectionData const& conn) noexcept
{
    return { conn.endTime.tv_sec, conn.endTime.tv_usec };
}

rust::String LiveDevice::name() const
{
    return rust::String(m_device->getName());
}

OptionMacAddress LiveDevice::mac_address() const noexcept
{
    MacAddress result;
    pcpp::MacAddress addr = m_device->getMacAddress();
    if (addr.isValid()) {
        uint8_t const* addr_bytes = addr.getRawData();
        std::copy(addr_bytes, addr_bytes + sizeof(result.bytes), result.bytes.data());
        return { result, true };
    } else {
        std::fill(result.bytes.begin(), result.bytes.end(), 0);
        return { result, false };
    }
}

Ipv4Address LiveDevice::ipv4_address() const noexcept
{
    return mk_ipv4_address(m_device->getIPv4Address());
}

Ipv6Address LiveDevice::ipv6_address() const noexcept
{
    return mk_ipv6_address(m_device->getIPv6Address());
}

rust::Vec<IpAddress> LiveDevice::ip_addresses() const noexcept
{
    auto const& addresses = m_device->getAddresses();
    rust::Vec<IpAddress> out;
    // std::cerr << "AF_UNIX  = " << AF_UNIX << "\n";
    // std::cerr << "AF_INET  = " << AF_INET << "\n";
    // std::cerr << "AF_INET6 = " << AF_INET6 << "\n";
    // std::cerr << "AF_PACKET = " << AF_PACKET << "\n";
    for (pcap_addr_t const& p : addresses) {
        if (!p.addr)
            continue;
        if (p.addr->sa_family == AF_INET) {
            sockaddr_in s;
            std::memcpy(&s, p.addr, sizeof(s));
            out.push_back(mk_ip_address(mk_ipv4_address(s)));
        }
        if (p.addr->sa_family == AF_INET6) {
            sockaddr_in6 s;
            std::memcpy(&s, p.addr, sizeof(s));
            out.push_back(mk_ip_address(mk_ipv6_address(s)));
        }
        /*
        std::cerr << "addr: " << p.addr << "\n";
        std::cerr << "netm: " << p.netmask << "\n";
        std::cerr << "brod: " << p.broadaddr << "\n";
        std::cerr << "dsta: " << p.dstaddr << "\n";
        if (p.addr) {
            std::cerr << "addr family: " << p.addr->sa_family << "\n";
        }
        if (p.broadaddr) {
            std::cerr << "broadaddr family: " << p.broadaddr->sa_family << "\n";
        }
        */
    }
    return out;
}

LiveDevice find_by_name(rust::Str name)
{
    std::string str(name);
    pcpp::PcapLiveDevice* device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(str);
    return { device };
}

LiveDevice find_by_ip(rust::Str ip)
{
    std::string str(ip);
    pcpp::PcapLiveDevice* device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(str);
    return { device };
}

LiveDevice find_by_ip_or_name(rust::Str ip_or_name)
{
    std::string str(ip_or_name);
    pcpp::PcapLiveDevice* device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(str);
    return { device };
}

rust::Vec<LiveDevice> get_live_devices()
{
    std::vector<pcpp::PcapLiveDevice*> const& devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    rust::Vec<LiveDevice> out;
    out.reserve(devices.size());
    for (pcpp::PcapLiveDevice* device : devices) {
        out.push_back({ device });
    }
    return out;
}

/*
LiveDeviceList::LiveDeviceList()
{
    m_devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
}

std::unique_ptr<LiveDeviceList> new_live_device_list()
{
    return std::make_unique<LiveDeviceList>();
}

std::size_t LiveDeviceList::size() const
{
    return m_devices.size();
}

LiveDevice LiveDeviceList::get(std::size_t i) const
{
    return { m_devices[i] };
}
*/

}  // namespace
