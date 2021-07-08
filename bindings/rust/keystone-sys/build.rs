#[cfg(feature = "build_keystone_cmake")]
extern crate cmake;
#[cfg(feature = "use_system_keystone")]
extern crate pkg_config;

#[cfg(all(not(windows), feature = "build_keystone_cmake"))]
use std::os::unix::fs::symlink;
#[cfg(all(windows, feature = "build_keystone_cmake"))]
use std::os::windows::fs::symlink_dir as symlink;

#[cfg(feature = "build_keystone_cmake")]
use std::path::Path;

#[cfg(feature = "build_keystone_cmake")]
fn build_with_cmake() {
    if !Path::new("keystone").exists() {
        // This only happens when using the crate via a `git` reference as the
        // published version already embeds keystone's source.
        let pwd = std::env::current_dir().unwrap();
        let keystone_dir = pwd.ancestors().skip(3).next().unwrap();
        symlink(keystone_dir, "keystone").expect("failed to symlink keystone");
    }

    let dest = cmake::Config::new("keystone")
        .define("CMAKE_INSTALL_LIBDIR", "lib")
        .define("BUILD_LIBS_ONLY", "1")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("LLVM_TARGETS_TO_BUILD", "all")
        // Prevent python from leaving behind `.pyc` files which break `cargo package`
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dest.display());
    println!("cargo:rustc-link-lib=keystone");

    let target = std::env::var("TARGET").unwrap();
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else if target.contains("linux") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    } else if target.contains("windows") {
        println!("cargo:rustc-link-lib=dylib=shell32");
    }
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
