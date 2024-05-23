{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.cmake
    pkgs.libpcap
  ];

  hardeningDisable = [ "fortify" ];

  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
