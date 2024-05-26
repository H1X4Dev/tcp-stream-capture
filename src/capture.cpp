#include "tcp_stream_capture/src/capture.h"
#include "tcp_stream_capture/src/capture.rs.h"

#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapFilter.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/TcpReassembly.h"

#include <pcap/pcap.h>
#include <sys/time.h>

#include <atomic>
#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>
#include <thread>

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

Timeval mk_timeval(struct timeval t) noexcept
{
    Timeval result;
    result.tv_sec = t.tv_sec;
    result.tv_usec = t.tv_usec;
    return result;
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

Timeval get_conn_start_time(pcpp::ConnectionData const& conn) noexcept
{
    return mk_timeval(conn.startTime);
}

Timeval get_conn_end_time(pcpp::ConnectionData const& conn) noexcept
{
    return mk_timeval(conn.endTime);
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



class TcpStreamCapture::Impl {
    rust::Box<Context> m_ctx;

    pcpp::IPcapDevice* m_device = nullptr;
    std::unique_ptr<pcpp::IPcapDevice> m_device_storage;  // manages lifetime of m_device, if necessary

    std::unique_ptr<pcpp::GeneralFilter> m_filter;

    // Background thread for file reader devices
    std::thread m_file_reader_thread;
    std::atomic_bool m_keep_reading;

    bool m_is_capturing = false;

    pcpp::TcpReassembly m_assembler;

    // Background thread that reads packets from a pcap file.
    // We use a background thread for consistency with capturing from live devices.
    static void read_file_device(Impl* self, pcpp::IFileReaderDevice* file_device);

    // Called in a background thread by pcpp::PcapLiveDevice when a new packet arrives.
    static void device_on_packet_arrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* device, void* cookie);

    // Called by pcpp::TcpReassembly.
    static void assembler_on_tcp_message_ready(int8_t side, pcpp::TcpStreamData const& data, void* cookie);
    static void assembler_on_tcp_connection_start(pcpp::ConnectionData const& conn, void* cookie);
    static void assembler_on_tcp_connection_end(pcpp::ConnectionData const& conn, pcpp::TcpReassembly::ConnectionEndReason reason, void* cookie);

public:
    Impl(rust::Box<Context> ctx, pcpp::IPcapDevice* device, std::unique_ptr<pcpp::IPcapDevice> device_storage);
    ~Impl();

    CaptureResult set_filter(rust::Str filter);
    CaptureResult clear_filter();

    CaptureResult start_capturing();
    void stop_capturing();
};

TcpStreamCapture::Impl::Impl(rust::Box<Context> ctx, pcpp::IPcapDevice* device, std::unique_ptr<pcpp::IPcapDevice> device_storage)
    : m_ctx(std::move(ctx))
    , m_device(device)
    , m_device_storage(std::move(device_storage))
    , m_assembler(Impl::assembler_on_tcp_message_ready, this, Impl::assembler_on_tcp_connection_start, Impl::assembler_on_tcp_connection_end)
{
    LOG_TRACE("TcpStreamCapture::TcpStreamCapture()");
    assert(m_device);
}

TcpStreamCapture::Impl::~Impl()
{
    LOG_TRACE("TcpStreamCapture::~TcpStreamCapture()");
    if (m_is_capturing)
        stop_capturing();
}

CaptureResult TcpStreamCapture::Impl::set_filter(rust::Str filter)
{
    LOG_TRACE("TcpStreamCapture::set_filter: " << filter);
    std::string filter_str{filter};
    auto bpf_filter = std::make_unique<pcpp::BPFStringFilter>(std::move(filter_str));
    if (!bpf_filter->verifyFilter()) {
        LOG_ERROR("TcpStreamCapture::set_filter: invalid filter");
        return CaptureResult::InvalidFilter;
    }
    // If the device is opened, try to update the filter immediately.
    // Otherwise the filter will be set in 'start_capturing'.
    if (m_device->isOpened() && !m_device->setFilter(*bpf_filter)) {
        LOG_ERROR("TcpStreamCapture::set_filter: unable to set device filter");
        return CaptureResult::FilterUpdateFailed;
    }
    // Only update m_filter on success
    m_filter = std::move(bpf_filter);
    return CaptureResult::Ok;
}

CaptureResult TcpStreamCapture::Impl::clear_filter()
{
    LOG_TRACE("TcpStreamCapture::clear_filter");
    // If the device is opened, try to update the filter immediately.
    // Otherwise the filter will be set in 'start_capturing'.
    // If clearing fails, we keep m_filter alive.
    if (m_device->isOpened() && !m_device->clearFilter()) {
        LOG_ERROR("TcpStreamCapture::clear_filter: unable to clear device filter");
        return CaptureResult::FilterUpdateFailed;
    }
    m_filter = nullptr;
    return CaptureResult::Ok;
}

CaptureResult TcpStreamCapture::Impl::start_capturing()
{
    LOG_TRACE("TcpStreamCapture::start_capturing");
    if (m_is_capturing) {
        LOG_WARN("TcpStreamCapture::start_capturing: already started");
        return CaptureResult::Ok;
    }
    if (!m_device->open()) {
        LOG_ERROR("TcpStreamCapture::start_capturing: unable to open device");
        return CaptureResult::DeviceOpenFailed;
    }
    if (m_filter && !m_device->setFilter(*m_filter)) {
        LOG_ERROR("TcpStreamCapture::start_capturing: unable to set device filter");
        m_device->close();
        return CaptureResult::FilterUpdateFailed;
    }
    else if (!m_filter && !m_device->clearFilter()) {
        LOG_ERROR("TcpStreamCapture::start_capturing: unable to clear device filter");
        m_device->close();
        return CaptureResult::FilterUpdateFailed;
    }
    if (auto live_device = dynamic_cast<pcpp::PcapLiveDevice*>(m_device)) {
        // This starts a background thread where the capturing is done.
        // The callback will be called in the background thread.
        m_is_capturing = live_device->startCapture(Impl::device_on_packet_arrives, this);
    }
    if (auto file_device = dynamic_cast<pcpp::IFileReaderDevice*>(m_device)) {
        // Start background thread ourselves and read the file there.
        // This is simply done for API consistency. We do not mind performance
        // drawbacks in this case since our primary use case is capturing on a
        // live device.
        m_keep_reading.store(true);
        m_is_capturing = true;
        m_file_reader_thread = std::thread(Impl::read_file_device, this, file_device);
    }
    return m_is_capturing ? CaptureResult::Ok : CaptureResult::CaptureStartFailed;
}

void TcpStreamCapture::Impl::stop_capturing()
{
    LOG_TRACE("TcpStreamCapture::stop_capturing");
    if (!m_is_capturing)
        return;
    if (auto live_device = dynamic_cast<pcpp::PcapLiveDevice*>(m_device)) {
        live_device->stopCapture();
    }
    if (auto file_device = dynamic_cast<pcpp::IFileReaderDevice*>(m_device)) {
        (void)file_device;
        LOG_DEBUG("TcpStreamCapture::stop_capturing: about to join file reader thread");
        m_keep_reading.store(false);
        m_file_reader_thread.join();
        LOG_DEBUG("TcpStreamCapture::stop_capturing: joined file reader thread");
    }
    m_device->close();
    m_is_capturing = false;
}

void TcpStreamCapture::Impl::read_file_device(Impl* self, pcpp::IFileReaderDevice* file_device)
{
    LOG_TRACE("TcpStreamCapture::read_file_device thread: starting");
    pcpp::RawPacket rawPacket;
    while (true) {
        if (!self->m_keep_reading.load()) {
            LOG_DEBUG("TcpStreamCapture::read_file_device thread: stopping (reason: flag)");
            break;
        }
        if (!file_device->getNextPacket(rawPacket)) {
            LOG_DEBUG("TcpStreamCapture::read_file_device thread: stopping (reason: no more packets)");
            break;
        }
        LOG_DEBUG("TcpStreamCapture::read_file_device thread: got packet: " << rawPacket.getRawDataLen() << " bytes");
        self->m_assembler.reassemblePacket(&rawPacket);
    }
    LOG_TRACE("TcpStreamCapture::read_file_device thread: stopped");
}

void TcpStreamCapture::Impl::device_on_packet_arrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* device, void* cookie)
{
    LOG_TRACE("TcpStreamCapture::device_on_packet_arrives");
    (void)device;
    auto* self = reinterpret_cast<TcpStreamCapture::Impl*>(cookie);
    self->m_assembler.reassemblePacket(packet);
}

void TcpStreamCapture::Impl::assembler_on_tcp_message_ready(int8_t side, pcpp::TcpStreamData const& data, void* cookie)
{
    LOG_TRACE("TcpStreamCapture::assembler_on_tcp_message_ready");
    auto* self = reinterpret_cast<TcpStreamCapture::Impl*>(cookie);
    rust::Slice<const uint8_t> payload{data.getData(), data.getDataLength()};
    on_tcp_message(*self->m_ctx, data.getConnectionData(), side, payload, data.getMissingByteCount(), mk_timeval(data.getTimeStamp()));
}

void TcpStreamCapture::Impl::assembler_on_tcp_connection_start(pcpp::ConnectionData const& conn, void* cookie)
{
    LOG_TRACE("TcpStreamCapture::assembler_on_tcp_connection_start");
    auto* self = reinterpret_cast<TcpStreamCapture::Impl*>(cookie);
    on_tcp_connection_start(*self->m_ctx, conn);
}

void TcpStreamCapture::Impl::assembler_on_tcp_connection_end(pcpp::ConnectionData const& conn, pcpp::TcpReassembly::ConnectionEndReason reason, void* cookie)
{
    LOG_TRACE("TcpStreamCapture::assembler_on_tcp_connection_end");
    (void)reason;
    auto* self = reinterpret_cast<TcpStreamCapture::Impl*>(cookie);
    on_tcp_connection_end(*self->m_ctx, conn);
}



std::unique_ptr<TcpStreamCapture> capture_from_live(LiveDevice const& device, rust::Box<Context> ctx)
{
    auto impl = std::make_unique<TcpStreamCapture::Impl>(std::move(ctx), device.m_device, nullptr);
    return std::make_unique<TcpStreamCapture>(std::move(impl));
}

std::unique_ptr<TcpStreamCapture> capture_from_file(rust::Slice<const uint8_t> filename, rust::Box<Context> ctx)
{
    std::string filename_str{filename.data(), filename.data() + filename.size()};
    auto device = std::make_unique<pcpp::PcapFileReaderDevice>(filename_str);
    auto impl = std::make_unique<TcpStreamCapture::Impl>(std::move(ctx), device.get(), std::move(device));
    return std::make_unique<TcpStreamCapture>(std::move(impl));
}



TcpStreamCapture::TcpStreamCapture(std::unique_ptr<Impl> impl)
    : m_impl(std::move(impl))
{
    assert(m_impl);
}

TcpStreamCapture::~TcpStreamCapture()
{
}

CaptureResult TcpStreamCapture::set_filter(rust::Str filter)
{
    return m_impl->set_filter(std::move(filter));
}

CaptureResult TcpStreamCapture::clear_filter()
{
    return m_impl->clear_filter();
}

CaptureResult TcpStreamCapture::start_capturing()
{
    return m_impl->start_capturing();
}

void TcpStreamCapture::stop_capturing()
{
    return m_impl->stop_capturing();
}


}  // namespace
