use alloc::format;

use super::{
   harness,
   *,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
   Mips32,
   Mips64,
}

impl Mode {
   fn label(self) -> &'static str {
      match self {
         Self::Mips32 => "Mips32",
         Self::Mips64 => "Mips64",
      }
   }
}

#[derive(Debug)]
struct Config {
   mode:     Mode,
   endian:   Endian,
   features: Option<String>,
   cpu:      Option<String>,
}

fn parse_config(content: &str) -> Option<Config> {
   if harness::all_run_lines_negate(content, &["# RUN:"]) {
      return None;
   }

   let mut mode = Mode::Mips32;
   let mut endian = Endian::Big;
   let mut features = None;
   let mut cpu = None;
   for line in harness::header_lines(content, 15) {
      if !line.starts_with("# RUN:") || line.contains(" not ") {
         continue;
      }
      if line.contains("mips64") || line.contains("-target mips64") {
         mode = Mode::Mips64;
      } else if line.contains("mips32") || line.contains("mips-") || line.contains("mipsel-") {
         mode = Mode::Mips32;
      }
      if line.contains("mipsel") || line.contains("mips64el") {
         endian = Endian::Little;
      }
      if let Some(val) = harness::extract_flag(line, "-mcpu=") {
         cpu = Some(val.to_owned());
      }
      if let Some(val) = harness::extract_flag(line, "-mattr=") {
         features = Some(val.to_owned());
      }
   }
   Some(Config {
      mode,
      endian,
      features,
      cpu,
   })
}

struct MipsTest {
   instruction:  String,
   encoding:     Vec<u8>,
   is_micromips: bool,
}

fn parse_tests(content: &str) -> Vec<MipsTest> {
   let lines: Vec<&str> = content.lines().collect();
   let mut out = Vec::new();
   let mut i = 0;

   while i < lines.len() {
      let line = lines[i].trim();

      let is_check = line.starts_with("# CHECK:");
      let is_micromips = line.starts_with("# MICROMIPS:");
      if !is_check && !is_micromips {
         i += 1;
         continue;
      }
      let prefix = if is_micromips {
         "# MICROMIPS:"
      } else {
         "# CHECK:"
      };

      if line.contains("# encoding:") {
         if let Some((inst, bytes)) = harness::inline_check(line, prefix, "# encoding:") {
            if !inst.starts_with('.') && !inst.starts_with('$') {
               out.push(MipsTest {
                  instruction: inst.to_owned(),
                  encoding: bytes,
                  is_micromips,
               });
            }
         }
         i += 1;
         continue;
      }

      let body = line.trim_start_matches(prefix).trim().to_owned();

      if body.is_empty()
         || body.starts_with('#')
         || body.contains("fixup")
         || body.starts_with("value:")
         || body.starts_with("kind:")
         || body.starts_with("offset:")
      {
         i += 1;
         continue;
      }

      if body.starts_with(".set ")
         && !body.contains("push")
         && !body.contains("pop")
         && !body.contains("nomacro")
         && !body.contains("macro")
         && !body.contains("noat")
         && !body.contains("noreorder")
         && !body.contains("reorder")
      {
         let consumed = consume_set_block(&lines, i, &body, &mut out);
         i = consumed;
         continue;
      }

      if body.starts_with('.') || body.starts_with('$') {
         i += 1;
         continue;
      }

      i += 1;
   }

   out
}

fn consume_set_block(
   lines: &[&str],
   start: usize,
   set_directive: &str,
   out: &mut Vec<MipsTest>,
) -> usize {
   let mut j = start + 1_usize;
   let mut emitted = 0_usize;
   while j < lines.len() {
      let next = lines[j].trim();
      if !next.starts_with('#') && !next.is_empty() {
         break;
      }
      if let Some(rest) = next.strip_prefix("# CHECK:") {
         let body = rest.trim();
         if body.starts_with(".set") {
            break;
         }
         if body.starts_with('.') || body.starts_with('$') {
            j += 1_usize;
            continue;
         }
         if next.contains("# encoding:") {
            if let Some((inst, bytes)) = harness::inline_check(next, "# CHECK:", "# encoding:") {
               out.push(MipsTest {
                  instruction:  format!("{set_directive}\n{inst}"),
                  encoding:     bytes,
                  is_micromips: false,
               });
               emitted += 1_usize;
            }
         } else if !body.is_empty() {
            let trailing = lines
               .iter()
               .enumerate()
               .skip(j + 1)
               .take_while(|&(_, cand)| {
                  !cand.trim().starts_with("# CHECK:") || cand.contains("# encoding:")
               })
               .find(|&(_, cand)| cand.contains("# encoding:"));
            if let Some((idx, cand)) = trailing {
               if let Some(bytes) = harness::enc_of(cand, harness::Enc::Bracket) {
                  out.push(MipsTest {
                     instruction:  format!("{set_directive}\n{body}"),
                     encoding:     bytes,
                     is_micromips: false,
                  });
                  emitted += 1_usize;
               }
               j = idx;
            }
         }
      }
      j += 1_usize;
   }
   if emitted > 0_usize {
      j
   } else {
      start + 1_usize
   }
}

#[test]
fn mips_from_llvm_files() {
   let mut mips32 = Keystone::new(Arch::MIPS).expect("Failed to initialize MIPS32 engine");
   let mut mips64 = Keystone::new(Arch::MIPS).expect("Failed to initialize MIPS64 engine");
   mips64.set_width(Width::W64).expect("Failed to set width");

   for (source, content) in harness::fixtures("Mips", &["# RUN:"], false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };
      let engine = match config.mode {
         Mode::Mips32 => &mut mips32,
         Mode::Mips64 => &mut mips64,
      };
      engine.set_endian(config.endian).unwrap();
      engine.set_feature("").unwrap();
      engine.set_cpu("").unwrap();
      if let Some(features) = config.features.as_ref() {
         println!("Setting features `{features}` for MIPS engine from file {source}");
         engine.set_feature(features).unwrap();
      }
      if let Some(cpu) = config.cpu.as_ref() {
         println!("Setting CPU `{cpu}` for MIPS engine from file {source}");
         engine.set_cpu(cpu).unwrap();
      }

      let tests = parse_tests(&content);
      let has_micromips = tests.iter().any(|item| item.is_micromips);

      for test in tests {
         run_test(engine, &test, has_micromips, &source, config.mode);
      }
   }
}

fn run_test(engine: &mut Keystone, test: &MipsTest, has_micromips: bool, source: &str, mode: Mode) {
   let instruction = &test.instruction;
   let encoding = &test.encoding;
   let is_micromips = &test.is_micromips;
   println!(
      "Testing instruction: {instruction} with encoding: {encoding:?} in mode: {}",
      mode.label()
   );
   if has_micromips {
      engine
         .set_feature(if *is_micromips {
            "+micromips"
         } else {
            "-micromips"
         })
         .unwrap();
   }

   let bytes = harness::assemble(engine, instruction).unwrap_or_else(|err| {
      panic!("Failed to assemble instruction '{instruction}' from file {source}: {err}")
   });

   let is_branch_or_jump =
      instruction.starts_with('b') || instruction.starts_with('j') || instruction.contains("jalr");

   if bytes.len() > encoding.len() && is_branch_or_jump && bytes.starts_with(encoding) {
      let extra = &bytes[encoding.len()..];
      let valid_nop = if *is_micromips {
         extra == [0x00, 0x00] || extra == [0x00, 0x00, 0x00, 0x00] || extra == [0x0C, 0x00]
      } else {
         extra == [0x00, 0x00, 0x00, 0x00]
      };
      assert!(
         valid_nop,
         "{:?} Instruction '{instruction}' produced unexpected delay slot bytes {extra:?} from \
          file {source}",
         mode.label()
      );
   } else {
      assert_eq!(
         bytes,
         *encoding,
         "{} Instruction '{instruction}' produced incorrect encoding from file {source}",
         mode.label()
      );
   }
}

#[test]
fn jal_imm() {
   let mut ks = Keystone::new(Arch::MIPS).unwrap();
   ks.set_width(Width::W64).unwrap();
   assert_eq!(ks.asm("jal 0xff0", 0).unwrap().bytes, [
      0x0C, 0x00, 0x03, 0xFC
   ]);
}

#[test]
fn branch_target_range_uses_pc() {
   let mut ks = Keystone::new(Arch::MIPS).unwrap();
   ks.set_endian(Endian::Big).unwrap();
   ks.set_width(Width::W64).unwrap();
   let first = ks.asm("beq $a1, $v1, 0x20000", 0x1FFFC).unwrap();
   assert_eq!(&first.bytes[..4], &[0x10, 0xA3, 0x00, 0x00]);
   let second = ks.asm("beq $a1, $v1, 0x20004", 0x20000).unwrap();
   assert_eq!(&second.bytes[..4], &[0x10, 0xA3, 0x00, 0x00]);
}

#[test]
fn macro_expansion_counts_toward_branch_address() {
   let mut ks = Keystone::new(Arch::MIPS).unwrap();
   ks.set_endian(Endian::Big).unwrap();
   assert_eq!(
      ks.asm("li $t0, 0x12345678\nb 0x1100", 0x1000)
         .unwrap()
         .bytes,
      [
         0x3C, 0x08, 0x12, 0x34, 0x35, 0x08, 0x56, 0x78, 0x10, 0x00, 0x00, 0x3D
      ]
   );
}

#[test]
fn pic_jump_rewrite_keeps_address() {
   let mut ks = Keystone::new(Arch::MIPS).unwrap();
   ks.set_endian(Endian::Big).unwrap();
   assert_eq!(ks.asm(".option pic2\nj 0x1100", 0x1000).unwrap().bytes, [
      0x10, 0x00, 0x00, 0x3F
   ]);
}
