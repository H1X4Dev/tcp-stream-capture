# pcapplusplus-sys

Compile [PcapPlusPlus](<https://github.com/seladb/PcapPlusPlus>) and make its library and header files available.

Two environment variables will be made available to `build.rs` of dependent crates:
- `DEP_PCAPPLUSPLUS_INCLUDE` contains the path to PcapPlusPlus header files
- `DEP_PCAPPLUSPLUS_LIB` contains the path to the compiled PcapPlusPlus libraries

To use PcapPlusPlus with [cxx](<https://crates.io/crates/cxx>),
use something like this in your `build.rs`:

    let mut cpp = cxx_build::bridge("src/bridge.rs");

    // Set include path for PcapPlusPlus
    let pcpp_include = env::var_os("DEP_PCAPPLUSPLUS_INCLUDE")
        .expect("Environment variable DEP_PCAPPLUSPLUS_INCLUDE should have been set");
    cpp.include(pcpp_include);

    // ...

You also need to link to the PcapPlusPlus libraries and possibly libpcap:

    // Link to PcapPlusPlus libraries
    let pcpp_lib = env::var("DEP_PCAPPLUSPLUS_LIB")
        .expect("Environment variable DEP_PCAPPLUSPLUS_LIB should have been set");
    println!("cargo:rustc-link-search=native={}", pcpp_lib);
    println!("cargo:rustc-link-lib=static=Common++");
    println!("cargo:rustc-link-lib=static=Packet++");
    println!("cargo:rustc-link-lib=static=Pcap++");

    // Link to libpcap
    println!("cargo:rustc-link-lib=dylib=pcap");
