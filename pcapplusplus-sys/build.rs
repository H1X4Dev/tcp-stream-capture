fn main()
{
    let pcpp = cmake::Config::new("PcapPlusPlus")
        .define("PCAPPP_BUILD_EXAMPLES", "OFF")
        .define("PCAPPP_BUILD_TUTORIALS", "OFF")
        .define("PCAPPP_BUILD_TESTS", "OFF")
        .define("PCAPPP_BUILD_COVERAGE", "OFF")
        .define("PCAPPP_BUILD_FUZZERS", "OFF")
        .cxxflag("/EHsc")
        .build();
    let pcpp_include = pcpp.join("include");
    let pcpp_lib = pcpp.join("lib64");
    println!("cargo:include={}", pcpp_include.display());
    println!("cargo:lib={}", pcpp_lib.display());
}
