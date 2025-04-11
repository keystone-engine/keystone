#[cfg(all(feature = "use_system_keystone", feature = "build_keystone_cmake"))]
compile_error!("mutual exclusive features: use_system_keystone & build_with_cmake");

#[cfg(feature = "build_keystone_cmake")]
fn build_with_cmake() {
    #[cfg(not(windows))]
    use std::os::unix::fs::symlink;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir as symlink;
    use std::path::Path;
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
    #[cfg(feature = "use_system_keystone")]
    {
        pkg_config::find_library("keystone").expect("Could not find system keystone");
        return;
    }
    #[cfg(feature = "build_keystone_cmake")]
    {
        build_with_cmake();
        return;
    }
}
