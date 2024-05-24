use tcp_stream_capture::*;

fn main()
{
    let devices = get_live_devices();
    println!("Found {} live devices:", devices.len());
    for (i, device) in devices.iter().enumerate() {
        let name = device.name()
            .unwrap_or_else(|e| format!("<error getting name: {:?}>", e));
        println!("{}. {}", i, name);
        if let Some(mac_addr) = device.mac_address() {
            println!("   MAC Address: {}", mac_addr);
        }
    }
}
