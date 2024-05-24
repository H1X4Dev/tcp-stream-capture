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

}  // namespace
