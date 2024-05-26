use std::any::Any;
use std::time::Duration;

use anyhow::Result;
use tcp_stream_capture::*;

//
//  Run like this if there are permission errors:
//
//      cargo build --example cap_live && sudo setcap cap_net_raw,cap_net_admin=ep target/debug/examples/cap_live && target/debug/examples/cap_live
//

fn main() -> Result<()>
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

    let device = &devices[0];
    println!("Capturing from device: {}", device.name()?);

    let ctx = Context::new(on_tcp_event, Box::new(()));
    let mut cap = TcpStreamCapture::from_live(device, ctx);

    cap.start_capturing()?;

    std::thread::sleep(Duration::from_secs(5));

    cap.stop_capturing();

    Ok(())
}

fn on_tcp_event(event: TcpStreamEvent, _user_cookie: &(dyn Any + Send))
{
    match event {
        TcpStreamEvent::Message { conn, side, payload, missing_bytes, timestamp } => {
            let side = if side == TcpStreamSide::SideA { "A" } else { "B" };
            println!("Message: {}:{} -> {}:{} (flow {}): side {}, payload {} bytes, missing {} bytes, timestamp {:?}",
                conn.src_addr(), conn.src_port(), conn.dst_addr(), conn.dst_port(), conn.flow_key(),
                side, payload.len(), missing_bytes, timestamp
            );
        }
        TcpStreamEvent::ConnectionStart(conn) => {
            println!("New: {}:{} -> {}:{} (flow {})",
                conn.src_addr(), conn.src_port(), conn.dst_addr(), conn.dst_port(), conn.flow_key()
            );
        }
        TcpStreamEvent::ConnectionEnd(conn) => {
            println!("End: {}:{} -> {}:{} (flow {})",
                conn.src_addr(), conn.src_port(), conn.dst_addr(), conn.dst_port(), conn.flow_key()
            );
        }
    }
}
