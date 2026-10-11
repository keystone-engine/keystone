{
  mkShell,
  clangStdenv,
  cmake,
  ninja,
  pkg-config,
  lldb,
  cargo,
  cargo-nextest,
  rustc,
  clippy,
  rustfmt,
  rust-analyzer,
  taplo,
  rustPlatform,
}:
(mkShell.override { stdenv = clangStdenv; }) {
  name = "keystone";

  strictDeps = true;
  nativeBuildInputs = [
    cmake
    ninja
    pkg-config
    lldb
    cargo
    cargo-nextest
    rustc
    clippy
    rustfmt
    rust-analyzer
    taplo
    rustPlatform.bindgenHook
  ];

  env = {
    CMAKE_EXPORT_COMPILE_COMMANDS = "1";
    RUST_SRC_PATH = "${rustPlatform.rustLibSrc}";
  };
}
