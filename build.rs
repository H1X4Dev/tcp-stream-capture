use std::env;

fn main()
{
    let mut cpp = cxx_build::bridge("src/capture.rs");
    cpp.file("src/capture.cpp");
    cpp.std("c++14");

    // Set include path for PcapPlusPlus
    let pcpp_include = env::var_os("DEP_PCAPPLUSPLUS_INCLUDE")
        .expect("Environment variable DEP_PCAPPLUSPLUS_INCLUDE should have been set");
    cpp.include(pcpp_include);

    // Work around warnings about _FORTIFY_SOURCE on NixOS
    #[cfg(debug_assertions)]
    cpp.opt_level(1);

    cpp.compile("tcp_stream_capture_cpp");

    println!("cargo:rerun-if-changed=src/capture.rs");
    println!("cargo:rerun-if-changed=src/capture.cpp");
    println!("cargo:rerun-if-changed=src/capture.h");

    // Link to PcapPlusPlus libraries
    let pcpp_lib = env::var("DEP_PCAPPLUSPLUS_LIB")
        .expect("Environment variable DEP_PCAPPLUSPLUS_LIB should have been set");
    println!("cargo:rustc-link-search=native={}", pcpp_lib);
    println!("cargo:rustc-link-lib=static=Common++");
    println!("cargo:rustc-link-lib=static=Packet++");
    println!("cargo:rustc-link-lib=static=Pcap++");

    // Link to libpcap
    println!("cargo:rustc-link-lib=dylib=pcap");
}
