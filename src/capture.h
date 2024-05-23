#pragma once
#include "rust/cxx.h"
#include <memory>


namespace pcpp {
    class PcapLiveDevice;
}


namespace tcp_stream_capture {


class LiveDevice {
    pcpp::PcapLiveDevice* m_device;
public:
    LiveDevice(pcpp::PcapLiveDevice* device)
        : m_device(device)
    { }

    rust::String name() const;
};


class LiveDeviceList {
    std::vector<pcpp::PcapLiveDevice*> m_devices;
public:
    LiveDeviceList();
    std::vector<pcpp::PcapLiveDevice*> const& devices() const { return m_devices; }
    std::size_t size() const { return m_devices.size(); }
    LiveDevice get(std::size_t i) const { return m_devices[i]; }
};

std::unique_ptr<LiveDeviceList> new_live_device_list();


}  // namespace
