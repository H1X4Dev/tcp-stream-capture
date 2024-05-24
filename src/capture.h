#pragma once
#include "rust/cxx.h"
// #include "capture.rs.h"
// #include "tcp_stream_capture/src/capture.rs.h"
#include <memory>


namespace pcpp {
    class PcapLiveDevice;
}


namespace tcp_stream_capture {

struct MacAddress;
struct OptionMacAddress;
struct LiveDevice;

rust::Vec<LiveDevice> get_live_devices();

class LiveDeviceList {
    std::vector<pcpp::PcapLiveDevice*> m_devices;
public:
    LiveDeviceList();
    std::vector<pcpp::PcapLiveDevice*> const& devices() const { return m_devices; }
    std::size_t size() const;
    LiveDevice get(std::size_t i) const;
};

std::unique_ptr<LiveDeviceList> new_live_device_list();


}  // namespace
