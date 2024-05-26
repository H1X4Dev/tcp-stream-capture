{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.cmake
    pkgs.libpcap
  ];

  hardeningDisable = [ "fortify" ];

  shellHook = ''
    export CC="clang"
    export CXX="clang++"
    export CXXFLAGS="-isystem ${pkgs.libpcap}/include/"$CXXFLAGS
  '';

  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
