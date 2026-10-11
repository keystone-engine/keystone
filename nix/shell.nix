{
  mkShell,
  clangStdenv,
  clang-tools,
  cmake,
  ninja,
  pkg-config,
  python3,
  lldb,
  cargo,
  cargo-deny,
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
    clang-tools
    cmake
    ninja
    pkg-config
    (python3.withPackages (ps: [
      ps.build
      ps.mypy
      ps.scikit-build-core
    ]))
    lldb
    cargo
    cargo-deny
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
    PYTHONDONTWRITEBYTECODE = "1";
    RUST_SRC_PATH = "${rustPlatform.rustLibSrc}";
  };
}
