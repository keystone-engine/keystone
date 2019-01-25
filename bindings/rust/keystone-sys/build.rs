#[cfg(feature = "build_keystone_cmake")]
extern crate cmake;
#[cfg(feature = "use_system_keystone")]
extern crate pkg_config;

#[cfg(feature = "build_keystone_cmake")]
use std::os::unix::fs;
#[cfg(feature = "build_keystone_cmake")]
use std::path::Path;

#[cfg(feature = "build_keystone_cmake")]
fn build_with_cmake() {
    if !Path::new("keystone").exists() {
        // This only happens when using the crate via a `git` reference as the
        // published version already embeds keystone's source.
        fs::symlink("../../..", "keystone").expect("failed to symlink keystone");
    }

    let dest = cmake::Config::new("keystone")
        .define("BUILD_LIBS_ONLY", "1")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("LLVM_TARGET_ARCH", "host")
        // Prevent python from leaving behind `.pyc` files which break `cargo package`
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dest.display());
    println!("cargo:rustc-link-lib=keystone");
}

fn main() {
    if cfg!(feature = "use_system_keystone") {
        #[cfg(feature = "use_system_keystone")]
        pkg_config::find_library("keystone").expect("Could not find system keystone");
    } else {
        #[cfg(feature = "build_keystone_cmake")]
        build_with_cmake();
    }
}
