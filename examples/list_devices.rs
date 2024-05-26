use tcp_stream_capture::*;

fn main()
{
    let format = tracing_subscriber::fmt::format()
        .with_thread_ids(true)
        .pretty();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .unwrap();
    tracing_subscriber::fmt()
        .event_format(format)
        .with_env_filter(filter)
        .init();

    let devices = get_live_devices();
    println!("Found {} live devices:", devices.len());
    for (i, device) in devices.iter().enumerate() {
        // let name = device.name()
        //     .unwrap_or_else(|e| format!("<error getting name: {:?}>", e));
        // println!("{}. {}", i, name);
        // if let Some(mac_addr) = device.mac_address() {
        //     println!("   MAC Address: {}", mac_addr);
        // }
        println!("{}. {:?}", i, device);
    }

    let queries = ["lo", "lo0", "stuff", "127.0.0.1", "::1"];
    for query in queries {
        println!("\nLooking for '{}':", query);
        println!("    by IP or name: {:?}", LiveDevice::find_by_ip_or_name(query));
        println!("    by name only:  {:?}", LiveDevice::find_by_name(query));
        println!("    by IP only:    {:?}", LiveDevice::find_by_ip(query));
    }

    let device = &devices[1];
    println!("\nDevice: {:?}", device);
    for ip_addr in device.ip_addresses() {
        println!("    {}", ip_addr);
    }
}
