use alloc::format;

use super::{
   harness,
   *,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
   clippy::upper_case_acronyms,
   reason = "keep architecture acronym variants"
)]
enum Mode {
   PPC,
   PPC64,
   PPC64LE,
}

impl Mode {
   fn label(self) -> &'static str {
      match self {
         Self::PPC => "PPC",
         Self::PPC64 => "PPC64",
         Self::PPC64LE => "PPC64LE",
      }
   }
}

#[derive(Debug)]
struct Config {
   default_mode: Mode,
   features:     Option<String>,
}

fn parse_config(content: &str) -> Option<Config> {
   if harness::all_run_lines_negate(content, &["# RUN:"]) {
      return None;
   }
   if harness::has_mcpu_flag(content) {
      return None;
   }

   let mut mode = Mode::PPC;
   let mut features = None;
   for line in harness::header_lines(content, 15) {
      if !line.starts_with("# RUN:") || line.contains(" not ") {
         continue;
      }
      if line.contains("powerpc64le") {
         mode = Mode::PPC64LE;
      } else if line.contains("powerpc64") {
         mode = Mode::PPC64;
      } else if line.contains("powerpc") {
         mode = Mode::PPC;
      }
      if let Some(val) = harness::extract_flag(line, "-mattr=") {
         features = Some(val.to_owned());
      }
   }

   Some(Config {
      default_mode: mode,
      features,
   })
}

fn parse_tests(content: &str, default_mode: Mode) -> Vec<harness::ParsedTest<Mode>> {
   let lines: Vec<&str> = content.lines().collect();
   let mut out = Vec::new();
   let mut i = 0;
   while i < lines.len() {
      let line = lines[i].trim();
      let (prefix, mode) = if line.starts_with("# CHECK-BE:") {
         ("# CHECK-BE:", Mode::PPC64)
      } else if line.starts_with("# CHECK-LE:") {
         ("# CHECK-LE:", Mode::PPC64LE)
      } else if line.starts_with("# CHECK:") {
         ("# CHECK:", default_mode)
      } else {
         i += 1;
         continue;
      };
      if !line.contains("# encoding:") {
         i += 1;
         continue;
      }

      let inst_part = line
         .trim_start_matches(prefix)
         .trim()
         .split('#')
         .next()
         .unwrap_or("")
         .trim()
         .to_owned();
      let mut full_encoding = line
         .split("# encoding:")
         .nth(1)
         .unwrap_or("")
         .trim()
         .to_owned();

      let same_prefix = format!(
         "# {}-SAME:",
         prefix.trim_start_matches("# ").trim_end_matches(':')
      );
      let mut j = i + 1;
      while j < lines.len() {
         let next = lines[j].trim();
         if let Some(rest) = next.strip_prefix(&same_prefix) {
            full_encoding.push(' ');
            full_encoding.push_str(rest.trim());
            j += 1;
         } else {
            break;
         }
      }

      if let Some(bytes) = harness::parse_encoding_bytes(&full_encoding) {
         if !inst_part.is_empty() {
            out.push(harness::ParsedTest {
               instruction: inst_part,
               encoding: bytes,
               mode,
            });
         }
      }

      i = j.max(i + 1);
   }
   out
}

fn make_engine(mode: Mode) -> Keystone {
   let mut engine = Keystone::new(Arch::PPC).expect("Failed to create PPC engine");
   let (width, endian) = match mode {
      Mode::PPC => (Width::W32, Endian::Big),
      Mode::PPC64 => (Width::W64, Endian::Big),
      Mode::PPC64LE => (Width::W64, Endian::Little),
   };
   engine.set_width(width).expect("Failed to set width");
   engine.set_endian(endian).expect("Failed to set endian");
   engine
}

#[test]
fn ppc_from_llvm_files() {
   for (source, content) in harness::fixtures("PowerPC", &["# RUN:"], false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };
      for harness::ParsedTest {
         instruction,
         encoding,
         mode,
      } in parse_tests(&content, config.default_mode)
      {
         let mut engine = make_engine(mode);
         harness::reset_and_apply_features(&mut engine, config.features.as_deref(), &source);
         harness::assemble_and_assert(&mut engine, &instruction, &encoding, &source, mode.label());
      }
   }
}

#[test]
fn crash() {
   let mut ks = Keystone::new(Arch::PPC).unwrap();
   ks.asm("sc c ", 0).unwrap_err();
}

#[test]
fn branch_with_pcrel_offset() {
   let mut ks = Keystone::new(Arch::PPC).unwrap();
   assert_eq!(ks.asm("b 0x2008", 0x2000).unwrap().bytes, [
      0x48, 0x00, 0x00, 0x08
   ]);
}

#[test]
fn negative_branch_target_not_hint() {
   let mut ks = Keystone::new(Arch::PPC).unwrap();
   assert_eq!(ks.asm("b -4", 0x100).unwrap().bytes, [
      0x4B, 0xFF, 0xFE, 0xFC
   ]);

   let asm = ks.asm("ble- 0", 0x100).unwrap();
   assert_eq!(asm.bytes.len(), 4);
}

#[test]
fn rewritten_instruction_keeps_address() {
   let mut ks = Keystone::new(Arch::PPC).unwrap();
   ks.set_endian(Endian::Big).unwrap();
   assert_eq!(ks.asm("dcbtt 0, 1\nb 0x1100", 0x1000).unwrap().bytes, [
      0x7E, 0x00, 0x0A, 0x2C, 0x48, 0x00, 0x00, 0xFC
   ]);
}
