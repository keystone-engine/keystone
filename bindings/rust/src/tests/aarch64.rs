use super::{
   harness,
   *,
};

const INCOMPLETE_CHECKS: &[(&str, &[u8])] = &[
   ("sqincd  x0, w0, all", &[0xE0, 0xF3, 0xEF, 0x04]),
   ("smstart", &[0x7F, 0x43, 0x03, 0xD5]),
   ("sp, x3, x7, lsl #4", &[0x7F, 0x70, 0x27, 0xCB]),
];

const RUN_PREFIXES: &[&str] = &["// RUN:", "//RUN:", "; RUN:", ";RUN:", "# RUN:", "#RUN:"];

#[derive(Debug, Default)]
struct Config {
   features: Option<String>,
}

fn parse_config(content: &str) -> Option<Config> {
   if harness::all_run_lines_negate(content, RUN_PREFIXES) {
      return None;
   }
   for line in harness::header_lines(content, 20) {
      let is_run = RUN_PREFIXES.iter().any(|prefix| line.starts_with(prefix));
      if is_run && line.contains("aarch64_be") {
         return None;
      }
      if is_run
         && (line.contains("-triple") || line.contains("--triple"))
         && !line.contains("aarch64")
         && !line.contains("arm64")
      {
         return None;
      }
   }

   Some(Config {
      features: harness::mattr(content, RUN_PREFIXES),
   })
}

fn parse_pairs(content: &str) -> Vec<harness::ParsedTest<&'static str>> {
   let mut out = harness::parse_inline_check_lines(content, "// CHECK:", "// encoding:", "AArch64");
   out.extend(harness::parse_split_check_lines(
      content,
      "// CHECK-INST:",
      "// CHECK-ENCODING:",
      "AArch64",
   ));
   out.retain(|case| {
      !case.instruction.contains("{{")
         && !case.instruction.contains("[[")
         && !INCOMPLETE_CHECKS.iter().any(|&(instruction, encoding)| {
            case.instruction == instruction && case.encoding == encoding
         })
   });
   out
}

#[test]
fn aarch64_from_llvm_files() {
   let mut ks = Keystone::new(Arch::AArch64).expect("Failed to initialize AArch64 engine");

   for (source, content) in harness::fixtures("AArch64", RUN_PREFIXES, false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };
      let pairs = parse_pairs(&content);
      if pairs.is_empty() {
         continue;
      }

      harness::reset_and_apply_features(&mut ks, config.features.as_deref(), &source);

      for pair in pairs {
         harness::assemble_and_assert(
            &mut ks,
            &pair.instruction,
            &pair.encoding,
            &source,
            pair.mode,
         );
      }
   }
}

#[test]
fn branch_with_large_relative_immediate() {
   let mut ks = Keystone::new(Arch::AArch64).unwrap();
   assert_eq!(
      ks.asm("bl #0x123456788", 0x0001_2345_6780).unwrap().bytes,
      [0x02, 0x00, 0x00, 0x94]
   );
}

#[test]
fn ldr_with_pcrel_offset() {
   let mut ks = Keystone::new(Arch::AArch64).unwrap();
   assert_eq!(ks.asm("ldr x0, #0x123c", 0x1234).unwrap().bytes, [
      0x40, 0x00, 0x00, 0x58
   ]);
}

#[test]
fn adr_after_first_instruction() {
   let mut ks = Keystone::new(Arch::AArch64).unwrap();
   assert_eq!(ks.asm("nop\nadr x0, #0x1000", 0x1000).unwrap().bytes, [
      0x1F, 0x20, 0x03, 0xD5, 0xE0, 0xFF, 0xFF, 0x10
   ]);
}

#[test]
fn adrp_after_first_instruction() {
   let mut ks = Keystone::new(Arch::AArch64).unwrap();
   assert_eq!(ks.asm("nop\nadrp x0, #0x2000", 0x1000).unwrap().bytes, [
      0x1F, 0x20, 0x03, 0xD5, 0x00, 0x00, 0x00, 0xB0
   ]);
}
