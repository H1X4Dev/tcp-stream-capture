{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.cmake
    pkgs.libpcap
  ];

  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
