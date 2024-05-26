# tcp_stream_capture

Capture TCP packets from libpcap and reassemble them into TCP streams.

To run example 1 (list available capture devices):

    cargo run --example list_devices

To run example 2 (capture from first available device):

    cargo build --example cap_live
    sudo setcap cap_net_raw,cap_net_admin=ep target/debug/examples/cap_live
    RUST_LOG=debug target/debug/examples/cap_live

References:
- [PcapPlusPlus 23.09 docs](<https://pcapplusplus.github.io/api-docs/v23.09/>)
- [Making a \*-sys crate](<https://kornel.ski/rust-sys-crate>)
- [cxx.rs](<https://cxx.rs/index.html>)
