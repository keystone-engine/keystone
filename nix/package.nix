{
  lib,
  stdenv,
  cmake,
  ninja,
}:
stdenv.mkDerivation {
  pname = "keystone-engine";
  inherit ((lib.importTOML ../Cargo.toml).workspace.package) version;

  src =
    let
      fs = lib.fileset;
      s = ../.;
    in
    fs.toSource {
      root = s;
      fileset = fs.unions [
        (s + /CMakeLists.txt)
        (s + /CMakeUninstall.in)
        (s + /LICENSE)
        (s + /pkg-config.pc.cmake)
        (s + /cmake)
        (s + /include)
        (s + /llvm/CMakeLists.txt)
        (s + /llvm/LICENSE.TXT)
        (s + /llvm/cmake)
        (s + /llvm/include)
        (s + /llvm/keystone)
        (s + /llvm/lib)
      ];
    };

  strictDeps = true;
  stripAllList = [ "lib/libkeystone.so" ];
  nativeBuildInputs = [
    cmake
    ninja
  ];

  meta = {
    description = "Multi-architecture assembler library built on LLVM's MC layer";
    homepage = "https://github.com/keystone-engine/keystone";
    license =
      with lib.licenses;
      AND [
        mpl20
        ncsa
        (WITH asl20 llvm-exception)
      ];
    maintainers = [ lib.maintainers.amaanq ];
    platforms = lib.platforms.all;
  };
}
