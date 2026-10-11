use super::{
   harness,
   *,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
   LoongArch32,
   LoongArch64,
}

impl Mode {
   fn label(self) -> &'static str {
      match self {
         Self::LoongArch32 => "LoongArch32",
         Self::LoongArch64 => "LoongArch64",
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
   if harness::has_mcpu_flag(content) {
      return None;
   }

   let mut mode = Mode::LoongArch32;
   let mut features = None;
   for line in harness::header_lines(content, 15) {
      if !line.starts_with("# RUN:") || line.contains(" not ") {
         continue;
      }
      if line.contains("loongarch64") || line.contains("--defsym=LA64=1") {
         mode = Mode::LoongArch64;
      } else if line.contains("loongarch32") {
         mode = Mode::LoongArch32;
      }
      if let Some(val) = harness::extract_flag(line, "-mattr=") {
         features = Some(val.to_owned());
      }
   }
   Some(Config { mode, features })
}

fn parse_tests(content: &str, default_mode: Mode) -> Vec<harness::ParsedTest<Mode>> {
   let lines: Vec<&str> = content.lines().collect();
   let mut out = Vec::new();
   let mut current_mode = default_mode;

   for (i, raw) in lines.iter().enumerate() {
      let line = raw.trim();
      if line == ".ifdef LA64" {
         current_mode = Mode::LoongArch64;
         continue;
      }
      if line == ".endif" {
         current_mode = default_mode;
         continue;
      }

      let is_check = line.contains("encoding:")
         && (line.starts_with("# CHECK-ASM:")
            || line.starts_with("# CHECK64-ASM:")
            || line.starts_with("# CHECK-ENCODING:"));
      if !is_check {
         continue;
      }

      let mut instruction = String::new();
      if i > 0 {
         let prev = lines[i - 1].trim();
         if !prev.starts_with('#') && !prev.is_empty() && !prev.starts_with('.') {
            instruction = prev.to_owned();
         } else if let Some(rest) = prev.strip_prefix("# CHECK-INST:") {
            instruction = rest.trim().to_owned();
         }
      }
      if instruction.is_empty() {
         for j in (0..i).rev() {
            let prev = lines[j].trim();
            if let Some(rest) = prev
               .strip_prefix("# CHECK-ASM-AND-OBJ:")
               .or_else(|| prev.strip_prefix("# CHECK64-ASM-AND-OBJ:"))
            {
               let intervening = lines[(j + 1)..i]
                  .iter()
                  .any(|text| text.trim().contains("encoding:"));
               if !intervening {
                  instruction = rest.trim().to_owned();
               }
               break;
            }
         }
      }
      if instruction.is_empty() {
         continue;
      }

      let Some(bytes) = harness::enc_of(line, harness::Enc::Bracket) else {
         continue;
      };

      out.push(harness::ParsedTest {
         instruction,
         encoding: bytes,
         mode: current_mode,
      });
   }

   out
}

#[test]
fn loongarch_from_llvm_files() {
   let mut la32 = Keystone::new(Arch::LoongArch).expect("Failed to initialize LoongArch32");
   la32.set_width(Width::W32).expect("Failed to set width");
   let mut la64 = Keystone::new(Arch::LoongArch).expect("Failed to initialize LoongArch64");

   for (source, content) in harness::fixtures("LoongArch", &["# RUN:"], false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };
      if let Some(features) = config.features.as_ref() {
         harness::reset_and_apply_features(&mut la32, Some(features), &source);
         harness::reset_and_apply_features(&mut la64, Some(features), &source);
      } else {
         harness::reset_and_apply_features(&mut la32, None, &source);
         harness::reset_and_apply_features(&mut la64, None, &source);
      }

      for harness::ParsedTest {
         instruction,
         encoding,
         mode,
      } in parse_tests(&content, config.mode)
      {
         let engine = match mode {
            Mode::LoongArch32 => &mut la32,
            Mode::LoongArch64 => &mut la64,
         };
         harness::assemble_and_assert(engine, &instruction, &encoding, &source, mode.label());
      }
   }
}
