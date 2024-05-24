use tcp_stream_capture::*;

fn main()
{
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
}
