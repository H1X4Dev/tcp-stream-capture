#include "tcp_stream_capture/src/capture.h"
#include "tcp_stream_capture/src/capture.rs.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/MacAddress.h"
#include <pcap/pcap.h>
#include <cstring>
#include <iostream>

namespace tcp_stream_capture {


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
