fn main()
{
    /* PcapPlusPlus */

    let pcpp = cmake::build("PcapPlusPlus");
    let pcpp_include = pcpp.join("include");
    let pcpp_lib = pcpp.join("lib64");
    println!("cargo:rustc-link-search=native={}", pcpp_lib.display());
    println!("cargo:rustc-link-lib=static=Common++");
    println!("cargo:rustc-link-lib=static=Packet++");
    println!("cargo:rustc-link-lib=static=Pcap++");

    /* tcp_stream_capture */

    // TODO: will need that for my cpp code
    let _ = pcpp_include;
}
