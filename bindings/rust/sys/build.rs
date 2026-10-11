use std::{
   env,
   error::Error,
   path::{
      Path,
      PathBuf,
   },
   process::Command,
};

use bindgen::callbacks::{
   EnumVariantValue,
   ItemInfo,
   ParseCallbacks,
};

/// C type names and the Rust names the bindings expose them under.
const TYPE_NAMES: &[(&str, &str)] = &[
   ("ks_arch", "Arch"),
   ("ks_arch_variant", "ArchVariant"),
   ("ks_arm_it_mode", "ArmItMode"),
   ("ks_asm_result", "AsmResult"),
   ("ks_endian", "Endian"),
   ("ks_err", "KsErr"),
   ("ks_error_location", "ErrorLocation"),
   ("ks_radix", "Radix"),
   ("ks_sym_resolver", "SymbolResolver"),
   ("ks_width", "Width"),
   ("ks_x86_syntax", "X86Syntax"),
];

/// Enum variants whose casing `upper_camel` would get wrong.
const VARIANT_NAMES: &[(&str, &str)] = &[
   ("AARCH64", "AArch64"),
   ("LOONGARCH", "LoongArch"),
   ("ARM_V7", "ARMv7"),
   ("ARM_MCLASS", "ARMMClass"),
   ("ARM_EM", "ARMEM"),
   ("ARM_ONLY", "ARMOnly"),
   ("THUMB_V7", "Thumbv7"),
   ("THUMB_MCLASS", "ThumbMClass"),
   ("THUMB_EM", "ThumbEM"),
];

/// Enum variants kept in upper case.
const ACRONYMS: &[&str] = &[
   "ARM", "ATT", "AVR", "BPF", "CSKY", "EVM", "MIPS", "MSP430", "NASM", "PPC", "RISCV", "VE",
   "WASM",
];

/// Converts `SNAKE_CASE` to `UpperCamel`.
fn upper_camel(name: &str) -> String {
   name
      .split('_')
      .flat_map(|word| {
         let mut chars = word.chars();
         chars
            .next()
            .into_iter()
            .chain(chars.flat_map(char::to_lowercase))
      })
      .collect()
}

/// Maps the C header's names onto the Rust API's.
#[derive(Debug)]
struct Renamer;

impl ParseCallbacks for Renamer {
   fn item_name(&self, item: ItemInfo<'_>) -> Option<String> {
      TYPE_NAMES
         .iter()
         .find(|&&(from, _)| from == item.name)
         .map(|&(_, to)| to.to_owned())
   }

   fn enum_variant_name(
      &self,
      enum_name: Option<&str>,
      variant: &str,
      _value: EnumVariantValue,
   ) -> Option<String> {
      let suffix = enum_name?.trim_start_matches("enum ").strip_prefix("ks_")?;
      let prefix = match suffix {
         "arm_it_mode" => "KS_ARM_IT_".to_owned(),
         other => format!("KS_{}_", other.to_uppercase()),
      };
      let bare = variant.strip_prefix(&prefix)?;

      if let Some(&(_, to)) = VARIANT_NAMES.iter().find(|&&(from, _)| from == bare) {
         return Some(to.to_owned());
      }
      if ACRONYMS.contains(&bare) {
         return Some(bare.to_owned());
      }
      if bare.starts_with(|ch: char| ch.is_ascii_digit()) {
         return Some(format!("W{bare}"));
      }
      Some(upper_camel(bare))
   }
}

/// Writes the bindgen output for `keystone.h` into `OUT_DIR`.
fn generate_bindings(root: &Path) -> Result<(), Box<dyn Error>> {
   let header = root.join("include/keystone/keystone.h");
   println!("cargo:rerun-if-changed={}", header.display());

   let bindings = bindgen::Builder::default()
      .header(header.to_string_lossy())
      .layout_tests(false)
      .allowlist_type("^(ks|KS).*")
      .allowlist_function("^ks_.*")
      .allowlist_var("^(ks|KS).*")
      .rustified_enum("^(ks|KS).*")
      .bitfield_enum("ks_arch_variant")
      .prepend_enum_name(false)
      .parse_callbacks(Box::new(Renamer))
      .derive_ord(true)
      .derive_eq(true)
      .no_partialeq("ks_sym_resolver")
      .use_core()
      .formatter(bindgen::Formatter::None)
      .generate()?;

   let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("cargo did not set OUT_DIR")?);
   bindings.write_to_file(out.join("bindings.rs"))?;
   Ok(())
}

/// Lower-cased names of the enabled `arch_*` features.
fn enabled_archs() -> Vec<String> {
   let mut archs: Vec<String> = env::vars()
      .filter_map(|(key, _)| {
         key.strip_prefix("CARGO_FEATURE_ARCH_")
            .filter(|arch| *arch != "ALL")
            .map(str::to_lowercase)
      })
      .collect();
   archs.sort();
   archs
}

/// Builds the C++ library from source and returns its link directory.
fn build_from_source(root: &Path) -> PathBuf {
   let archs = enabled_archs();
   assert!(!archs.is_empty(), "enable at least one `arch_*` feature");

   let inputs = [
      "CMakeLists.txt",
      "cmake",
      "include",
      "llvm/CMakeLists.txt",
      "llvm/cmake",
      "llvm/include",
      "llvm/keystone",
      "llvm/lib",
   ];
   for input in inputs {
      println!("cargo:rerun-if-changed={}", root.join(input).display());
   }

   let mut config = cmake::Config::new(root);
   config.define("KEYSTONE_ARCH", archs.join(";"));
   config.no_build_target(true);

   let ninja = Command::new("ninja")
      .arg("--version")
      .output()
      .is_ok_and(|out| out.status.success());
   if env::var_os("CMAKE_GENERATOR").is_none() && ninja {
      config.generator("Ninja");
   }

   config.build().join("build")
}

fn main() -> Result<(), Box<dyn Error>> {
   let manifest = PathBuf::from(
      env::var_os("CARGO_MANIFEST_DIR").ok_or("cargo did not set CARGO_MANIFEST_DIR")?,
   );
   let root = manifest
      .ancestors()
      .nth(3)
      .ok_or("the sys crate must live at bindings/rust/sys")?;

   generate_bindings(root)?;

   let system = pkg_config::Config::new()
      .atleast_version("2")
      .cargo_metadata(false)
      .env_metadata(true)
      .probe("keystone");
   let search_dirs = match system {
      Ok(lib) => lib.link_paths,
      Err(_) => vec![build_from_source(root)],
   };
   for dir in search_dirs {
      println!("cargo:rustc-link-search=native={}", dir.display());
   }

   let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
   let msvc = env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|target_env| target_env == "msvc");

   if cfg!(feature = "dynamic_linkage") {
      let name = if msvc { "keystone-import" } else { "keystone" };
      println!("cargo:rustc-link-lib=dylib={name}");
      return Ok(());
   }

   println!("cargo:rustc-link-lib=static=keystone");
   if target_os == "windows" {
      println!("cargo:rustc-link-lib=dylib=shell32");
   }

   let default_stdlib = match target_os.as_str() {
      "macos" | "ios" | "freebsd" | "openbsd" => "c++",
      "windows" => "",
      _ => "stdc++",
   };
   let stdlib = cxx_stdlib().unwrap_or_else(|| default_stdlib.to_owned());
   if !stdlib.is_empty() {
      println!("cargo:rustc-link-lib=dylib={stdlib}");
   }
   Ok(())
}

/// The C++ standard library override, read like cc-rs: `CXXSTDLIB_<target>`
/// then `CXXSTDLIB`, where an empty value links nothing.
fn cxx_stdlib() -> Option<String> {
   let target = env::var("TARGET").unwrap_or_default();
   [
      format!("CXXSTDLIB_{target}"),
      format!("CXXSTDLIB_{}", target.replace('-', "_")),
      "CXXSTDLIB".to_owned(),
   ]
   .into_iter()
   .find_map(|key| {
      println!("cargo:rerun-if-env-changed={key}");
      env::var(key).ok()
   })
}
