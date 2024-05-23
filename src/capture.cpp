#include "tcp_stream_capture/src/capture.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include <iostream>

namespace tcp_stream_capture {


rust::String LiveDevice::name() const
{
    return rust::String(m_device->getName());
}

LiveDeviceList::LiveDeviceList()
{
    m_devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
}

std::unique_ptr<LiveDeviceList> new_live_device_list()
{
    return std::make_unique<LiveDeviceList>();
}

std::size_t live_device_list_size(LiveDeviceList const& list)
{
    return list.devices().size();
}


}  // namespace
