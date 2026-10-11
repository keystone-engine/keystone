{
  lib,
  rustPlatform,
  pkg-config,
  keystone,
}:
rustPlatform.buildRustPackage {
  pname = "keystone-engine-rust";
  inherit ((lib.importTOML ../Cargo.toml).workspace.package) version;

  src =
    let
      fs = lib.fileset;
      s = ../.;
    in
    fs.toSource {
      root = s;
      fileset = fs.unions [
        (s + /Cargo.toml)
        (s + /Cargo.lock)
        (s + /bindings)
        (s + /include/keystone/keystone.h)
        (s + /llvm/test)
      ];
    };

  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [
    "--package"
    "keystone-engine"
  ];
  cargoTestFlags = [
    "--package"
    "keystone-engine"
    "--features"
    "arch_all"
  ];
  useNextest = true;

  strictDeps = true;
  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
  ];
  buildInputs = [ keystone ];

  meta = {
    description = "Rust bindings for the Keystone assembler";
    homepage = "https://github.com/keystone-engine/keystone";
    license = lib.licenses.mpl20;
    maintainers = [ lib.maintainers.amaanq ];
    platforms = lib.platforms.unix;
  };
}
