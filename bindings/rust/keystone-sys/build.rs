#[cfg(feature = "use_system_keystone")]
extern crate pkg_config;

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn build_with_cmake() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let cmake_dir = PathBuf::from("keystone");
    let build_dir = cmake_dir.join("build");

    if !cmake_dir.exists() {
        run(Command::new("ln").arg("-s").arg("../../..").arg("keystone"));
    }

    run(Command::new("mkdir")
        .current_dir(&cmake_dir)
        .arg("-p")
        .arg("build"));

    run(Command::new("../make-share.sh").current_dir(&build_dir));

    run(Command::new("cmake").current_dir(&build_dir).args(&[
        &format!("-DCMAKE_INSTALL_PREFIX={}", out_dir.display()),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_LIBS_ONLY=1",
        "-DCMAKE_OSX_ARCHITECTURES=",
        "-DBUILD_SHARED_LIBS=ON",
        "-DLLVM_TARGET_ARCH=host",
        "-G",
        "Unix Makefiles",
        "..",
    ]));

    run(Command::new("make").current_dir(&build_dir).arg("install"));

    println!("cargo:rustc-link-search=native={}/lib", out_dir.display());
    println!("cargo:rustc-link-lib=keystone");
}

fn main() {
    if cfg!(feature = "use_system_keystone") {
        #[cfg(feature = "use_system_keystone")]
        pkg_config::find_library("keystone").expect("Could not find system keystone");
    } else {
        build_with_cmake();
    }
}

fn run(cmd: &mut Command) {
    println!("run: {:?}", cmd);
    let status = match cmd.status() {
        Ok(s) => s,
        Err(ref e) => fail(&format!("failed to execute command: {}", e)),
    };
    if !status.success() {
        fail(&format!(
            "command did not execute successfully, got: {}",
            status
        ));
    }
}

fn fail(s: &str) -> ! {
    panic!("\n{}\n\nbuild script failed, must exit now", s);
}
