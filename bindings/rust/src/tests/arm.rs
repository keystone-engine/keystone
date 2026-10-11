use alloc::format;

use super::{
   harness,
   *,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
   Arm,
   Thumb,
   ThumbV7M,
   ThumbV7EM,
}

impl Mode {
   fn label(self) -> &'static str {
      match self {
         Self::Arm => "Arm",
         Self::Thumb => "Thumb",
         Self::ThumbV7M => "ThumbV7M",
         Self::ThumbV7EM => "ThumbV7EM",
      }
   }
}

#[derive(Debug)]
struct Config {
   mode:     Mode,
   features: Option<String>,
}

fn parse_config(content: &str) -> Option<Config> {
   let run_lines: Vec<&str> = content
      .lines()
      .filter(|line| line.trim().starts_with("@ RUN:") && line.contains("llvm-mc"))
      .collect();
   let any_runs = !run_lines.is_empty();
   let all_not = !run_lines.is_empty() && run_lines.iter().all(|line| line.contains(" not "));

   if all_not && any_runs {
      let first = run_lines[0];
      let mut mode = Mode::Arm;
      if let Some(triple) = harness::extract_flag(first, "-triple=") {
         if triple.starts_with("thumb") {
            mode = Mode::Thumb;
         }
      }
      let features = harness::extract_flag(first, "-mattr=").map(str::to_owned);
      return Some(Config { mode, features });
   }

   if harness::has_mcpu_flag(content) {
      return None;
   }
   if harness::header_lines(content, 15).any(|line| line.contains("gnu")) {
      return None;
   }

   let mut mode = Mode::Arm;
   let mut features = None;
   for line in harness::header_lines(content, 15) {
      if !line.starts_with("@ RUN:") || line.contains(" not ") {
         continue;
      }
      if line.contains("thumbv7em") {
         mode = Mode::ThumbV7EM;
      } else if line.contains("thumbv6m") || line.contains("thumbv7m") {
         mode = Mode::ThumbV7M;
      } else if line.contains("-triple=thumbv")
         || line.contains("-triple=thumb-")
         || line.contains("-triple thumbv")
         || line.contains("-triple thumb-")
      {
         mode = Mode::Thumb;
      }
      if let Some(val) = harness::extract_flag(line, "-mattr=") {
         features = Some(val.to_owned());
      }
   }
   Some(Config { mode, features })
}

struct ArmTest {
   instruction: String,
   encoding:    Vec<u8>,
   implicit_it: bool,
   mode:        Mode,
}

fn within_implicit_it(lines: &[&str], idx: usize) -> bool {
   let look_back = idx.saturating_sub(5);
   let cond_substrings = ["eq", "ne", "lt", "gt", "ge", "le", "vs"];
   for j in (look_back..idx).rev() {
      let line = lines[j].trim();
      let is_it = line.contains("itt") || line.contains("it ");
      if is_it && cond_substrings.iter().any(|cond| line.contains(cond)) {
         return true;
      }
   }
   false
}

fn parse_tests(content: &str, default_mode: Mode) -> Vec<ArmTest> {
   let lines: Vec<&str> = content.lines().collect();
   let mut out = Vec::new();
   let mut current_mode = default_mode;

   for (i, raw) in lines.iter().enumerate() {
      let line = raw.trim();
      if line == ".code 16" || line == ".thumb" {
         current_mode = Mode::Thumb;
         continue;
      }
      if line == ".code 32" || line == ".arm" {
         current_mode = Mode::Arm;
         continue;
      }
      let Some((instruction, encoding)) = harness::inline_check(line, "@ CHECK:", "@ encoding:")
      else {
         continue;
      };

      out.push(ArmTest {
         instruction: instruction.to_owned(),
         encoding,
         implicit_it: within_implicit_it(&lines, i),
         mode: current_mode,
      });
   }

   out
}

#[test]
fn arm_from_llvm_files() {
   let mut arm = Keystone::new(Arch::ARM).expect("Failed to initialize ARM Keystone engine");
   let mut thumb = Keystone::new(Arch::Thumb).expect("Failed to initialize Thumb Keystone engine");
   let mut thumbv7m = Keystone::new(Arch::Thumb).expect("Failed to initialize Thumbv7M engine");
   thumbv7m
      .set_arch_variant(ArchVariant::ThumbMClass)
      .expect("Failed to set ThumbMClass variant");
   let mut thumb_em_engine =
      Keystone::new(Arch::Thumb).expect("Failed to initialize Thumbv7EM engine");
   thumb_em_engine
      .set_arch_variant(ArchVariant::ThumbEM)
      .expect("Failed to set ThumbEM variant");

   for (source, content) in harness::fixtures("ARM", &[], false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };
      if let Some(features) = config.features.as_ref() {
         arm.set_feature(features).unwrap();
         thumb.set_feature(features).unwrap();
      }

      for ArmTest {
         mut instruction,
         encoding,
         implicit_it,
         mode,
      } in parse_tests(&content, config.mode)
      {
         println!(
            "Testing instruction: {instruction} with encoding: {encoding:?} in mode: {}, \
             implicit_it: {implicit_it}",
            mode.label()
         );

         let engine: &mut Keystone = match mode {
            Mode::Arm => &mut arm,
            Mode::Thumb => &mut thumb,
            Mode::ThumbV7M => &mut thumbv7m,
            Mode::ThumbV7EM => &mut thumb_em_engine,
         };

         engine
            .set_arm_it_mode(if implicit_it {
               ArmItMode::Always
            } else {
               ArmItMode::Never
            })
            .unwrap();

         let is_branch = instruction.trim_start().starts_with('b')
            && (instruction.contains(" #")
               || ["beq", "bne", "blt", "bgt"]
                  .iter()
                  .any(|prefix| instruction.starts_with(prefix)));
         let prefixed = is_branch && implicit_it && mode == Mode::Thumb;
         let mnemonic = instruction.split_whitespace().next().unwrap_or_default();
         let t2bcc = is_branch
            && mode != Mode::Arm
            && mnemonic
               .strip_suffix(".w")
               .is_some_and(|base| base != "b" && !(prefixed && base == "beq"));
         // LLVM counts t2Bcc from the PC, and the prefix moves the branch.
         let shift = 4 * (i64::from(t2bcc) + i64::from(prefixed));
         if shift != 0 {
            instruction = shift_branch_target(&instruction, shift);
         }
         if prefixed {
            instruction = format!("addeq r0, r1\n{instruction}");
         }

         let bytes = harness::assemble(engine, &instruction)
            .unwrap_or_else(|err| panic!("Failed to assemble instruction '{instruction}': {err}"));

         let is_conditional = ["eq", "ne", "lt", "gt", "ge", "le", "vs"]
            .iter()
            .any(|cond| instruction.contains(cond));
         if mode == Mode::Thumb && is_conditional && bytes.len() > encoding.len() {
            let suffix = &bytes[bytes.len() - encoding.len()..];
            assert_eq!(
               suffix,
               &*encoding,
               "{:?} Instruction '{instruction}' produced incorrect encoding suffix from file \
                {source}",
               mode.label()
            );
         } else {
            assert_eq!(
               bytes,
               encoding,
               "{:?} Instruction '{instruction}' produced incorrect encoding from file {source}",
               mode.label()
            );
         }
      }
   }
}

fn shift_branch_target(instruction: &str, by: i64) -> String {
   let Some((head, target)) = instruction.split_once('#') else {
      return instruction.to_owned();
   };
   let value = target.strip_prefix("0x").map_or_else(
      || target.parse::<i64>().ok(),
      |hex| i64::from_str_radix(hex, 16).ok(),
   );
   value.map_or_else(
      || instruction.to_owned(),
      |offset| format!("{head}#{}", offset + by),
   )
}

#[test]
fn blx_rel_thumb() {
   let mut ks = Keystone::new(Arch::Thumb).unwrap();
   assert_eq!(ks.asm("blx 0x86535200", 0x8653_51D4).unwrap().bytes, [
      0x00, 0xF0, 0x14, 0xE8
   ]);
}

#[test]
fn dollar_is_pc() {
   let mut arm = Keystone::new(Arch::ARM).unwrap();
   assert_eq!(arm.asm("b $", 0x1000).unwrap().bytes, [
      0xFE, 0xFF, 0xFF, 0xEA
   ]);

   let mut thumb = Keystone::new(Arch::Thumb).unwrap();
   assert_eq!(thumb.asm("b $", 0x1000).unwrap().bytes, [0xFE, 0xE7]);
}

#[test]
fn ldr_imm() {
   let mut ks = Keystone::new(Arch::ARM).unwrap();
   assert_eq!(ks.asm("ldr r0, =0x11223344", 0).unwrap().bytes, [
      0x04, 0x00, 0x1F, 0xE5, 0x44, 0x33, 0x22, 0x11
   ]);
}

#[test]
fn crash_on_arm_expression() {
   let mut ks = Keystone::new(Arch::ARM).unwrap();
   ks.asm("eor A1,.2", 0).unwrap_err();
}

#[test]
fn crash_on_invalid_size() {
   let mut ks = Keystone::new(Arch::ARM).unwrap();
   ks.asm(
      "LDr AH1I,=jHGQ,=2,=r,=GQ,=1111111111111112,=ey,=2,=eQ,=rQ',=r,=",
      0,
   )
   .unwrap_err();
}

#[test]
fn crash_on_invalid_access() {
   let mut ks = Keystone::new(Arch::ARM).unwrap();
   ks.asm("CpSQHK aSR C", 0).unwrap_err();
}

#[test]
fn crash_on_encoding_mcoperand() {
   let mut ks = Keystone::new(Arch::ARM).unwrap();
   ks.asm("CpS L,f", 0).unwrap_err();
}

#[test]
fn crash_on_arm_idx_lt_size() {
   let mut ks = Keystone::new(Arch::ARM).unwrap();
   ks.asm("ldrd", 0).unwrap_err();
}

#[test]
fn arm_symbol_resolver() {
   let mut ks = Keystone::new(Arch::ARM).unwrap();
   ks.set_symbol_resolver(|symbol, value| {
      match symbol {
         "symBackward" => {
            *value = 0;
            true
         },
         "symForward" => {
            *value = 0x20;
            true
         },
         _ => false,
      }
   })
   .unwrap();

   let asm = ks
      .asm("sub r0, r0, r0\nsub r1, r1, r1\nbl symBackward", 0)
      .unwrap();
   assert_eq!(asm.bytes[asm.bytes.len() - 4..], [0xFC, 0xFF, 0xFF, 0xEB]);

   assert_eq!(ks.asm("bl symForward", 0).unwrap().bytes, [
      0x06, 0x00, 0x00, 0xEB
   ]);
}

#[test]
fn thumb_symbol_resolver() {
   let mut ks = Keystone::new(Arch::Thumb).unwrap();
   ks.set_symbol_resolver(|symbol, value| {
      match symbol {
         "symBackward" => {
            *value = 0;
            true
         },
         "symForward" => {
            *value = 0x20;
            true
         },
         _ => false,
      }
   })
   .unwrap();

   let asm = ks
      .asm("sub r0, r0, r0\nsub r0, r0, r0\nbl symBackward", 0)
      .unwrap();
   assert_eq!(asm.bytes[asm.bytes.len() - 4..], [0xFF, 0xF7, 0xFA, 0xFF]);

   assert_eq!(ks.asm("bl symForward", 0).unwrap().bytes, [
      0x00, 0xF0, 0x0E, 0xF8
   ]);
}

#[test]
fn implicit_it_counts_toward_branch_address() {
   let mut ks = Keystone::new(Arch::Thumb).unwrap();
   ks.set_arm_it_mode(ArmItMode::Always).unwrap();
   assert_eq!(ks.asm("addeq r0, r1\nb 0x100", 0).unwrap().bytes, [
      0x08, 0xBF, 0x08, 0x44, 0x7C, 0xE0
   ]);
}

#[test]
fn data_directive_counts_toward_branch_address() {
   let mut ks = Keystone::new(Arch::ARM).unwrap();
   assert_eq!(ks.asm(".word 0\nb 0x1100", 0x1000).unwrap().bytes, [
      0x00, 0x00, 0x00, 0x00, 0x3D, 0x00, 0x00, 0xEA
   ]);
}

#[test]
fn wide_conditional_branch_target_is_absolute() {
   let mut ks = Keystone::new(Arch::Thumb).unwrap();
   assert_eq!(ks.asm("bgt.w 0x1100", 0x1000).unwrap().bytes, [
      0x00, 0xF3, 0x7E, 0x80
   ]);
}
