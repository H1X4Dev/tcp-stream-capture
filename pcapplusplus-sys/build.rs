fn main()
{
    let pcpp = cmake::build("PcapPlusPlus");
    let pcpp_include = pcpp.join("include");
    let pcpp_lib = pcpp.join("lib64");
    println!("cargo:include={}", pcpp_include.display());
    println!("cargo:lib={}", pcpp_lib.display());
}
