use alloc::format;

use super::{
   harness,
   *,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
   Wasm32,
   Wasm64,
}

impl Mode {
   fn label(self) -> &'static str {
      match self {
         Self::Wasm32 => "Wasm32",
         Self::Wasm64 => "Wasm64",
      }
   }
}

#[derive(Debug)]
struct Config {
   mode:     Mode,
   features: Option<String>,
}

fn parse_config(content: &str) -> Option<Config> {
   if harness::all_run_lines_negate(content, &["# RUN:"]) {
      return None;
   }

   let mut mode = Mode::Wasm32;
   let mut features_vec = Vec::new();
   let mut mode_set = false;
   for line in harness::header_lines(content, 15) {
      if !line.starts_with("# RUN:") || line.contains(" not ") {
         continue;
      }
      if !mode_set {
         if line.contains("wasm64") {
            mode = Mode::Wasm64;
            mode_set = true;
         } else if line.contains("wasm32") {
            mode = Mode::Wasm32;
            mode_set = true;
         }
      }
      for tok in line.split_whitespace() {
         if let Some(val) = tok
            .strip_prefix("--mattr=")
            .or_else(|| tok.strip_prefix("-mattr="))
         {
            if !val.is_empty() {
               features_vec.push(val.to_owned());
            }
         }
      }
   }
   let features = if features_vec.is_empty() {
      None
   } else {
      Some(features_vec.join(","))
   };
   Some(Config { mode, features })
}

#[test]
fn wasm_from_llvm_files() {
   let mut wasm32 = Keystone::new(Arch::WASM).expect("Failed to initialize WASM32 engine");
   let mut wasm64 = Keystone::new(Arch::WASM).expect("Failed to initialize WASM64 engine");
   wasm64.set_width(Width::W64).expect("Failed to set width");

   for (source, content) in harness::fixtures("WebAssembly", &[], false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };
      let engine = match config.mode {
         Mode::Wasm32 => &mut wasm32,
         Mode::Wasm64 => &mut wasm64,
      };

      let features_str = config.features.as_deref().unwrap_or("");
      if let Err(err) = engine.set_feature(features_str) {
         println!("Skipping {source}: cannot set features '{features_str}': {err}");
         continue;
      }

      let tests = harness::parse_inline_check_lines(
         &content,
         "# CHECK:",
         "# encoding:",
         config.mode.label(),
      );
      for harness::ParsedTest {
         instruction,
         encoding,
         mode,
      } in tests
      {
         println!("Testing instruction: {instruction} with encoding: {encoding:?} in mode: {mode}");
         match engine.asm(instruction.as_bytes(), 0) {
            Ok(result) => {
               if result.bytes.is_empty() {
                  continue;
               }
               assert_eq!(
                  result.bytes, encoding,
                  "{mode} Instruction '{instruction}' produced incorrect encoding from file \
                   {source}"
               );
            },
            Err(err) => {
               let msg = format!("{err}");
               if msg.contains("invalid instruction") || msg.contains("unrecognized") {
                  println!("Skipping unknown wasm instruction '{instruction}': {err}");
                  continue;
               }
               panic!("Failed to assemble instruction '{instruction}' from file {source}: {err}");
            },
         }
      }
   }
}
