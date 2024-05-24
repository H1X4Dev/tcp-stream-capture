#include "tcp_stream_capture/src/capture.h"
#include "tcp_stream_capture/src/capture.rs.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/MacAddress.h"
#include <iostream>

namespace tcp_stream_capture {


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
    Ipv4Address result;
    pcpp::IPv4Address addr = m_device->getIPv4Address();
    uint8_t const* addr_bytes = addr.toBytes();
    std::copy(addr_bytes, addr_bytes + sizeof(result.bytes), result.bytes.data());
    return result;
}

Ipv6Address LiveDevice::ipv6_address() const noexcept
{
    Ipv6Address result;
    pcpp::IPv6Address addr = m_device->getIPv6Address();
    uint8_t const* addr_bytes = addr.toBytes();
    std::copy(addr_bytes, addr_bytes + sizeof(result.bytes), result.bytes.data());
    return result;
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
