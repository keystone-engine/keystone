use alloc::format;

use super::{
   harness,
   *,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
   Rv32,
   Rv64,
}

impl Mode {
   fn label(self) -> &'static str {
      match self {
         Self::Rv32 => "Rv32",
         Self::Rv64 => "Rv64",
      }
   }
}

#[derive(Debug)]
struct Config {
   mode:           Mode,
   features:       Option<String>,
   check_prefixes: Vec<String>,
}

fn join_continuations(content: &str) -> String {
   let lines: Vec<&str> = content.lines().collect();
   let mut out = Vec::new();
   let mut i = 0;
   while i < lines.len() {
      let line = lines[i];
      if !line.trim_end().ends_with('\\') {
         out.push(line.to_owned());
         i += 1;
         continue;
      }

      let mut joined = line.trim_end().trim_end_matches('\\').to_owned();
      i += 1;
      while i < lines.len() {
         let next = lines[i].trim();
         if let Some(rest) = next.strip_prefix("# RUN:") {
            joined.push(' ');
            joined.push_str(rest.trim());
         } else if let Some(rest) = next.strip_prefix('#') {
            if next.starts_with("# CHECK") {
               break;
            }
            joined.push(' ');
            joined.push_str(rest.trim());
         } else {
            break;
         }
         if !lines[i].trim_end().ends_with('\\') {
            i += 1;
            break;
         }
         i += 1;
      }
      out.push(joined);
   }
   out.join("\n")
}

fn parse_config(content: &str) -> Option<Config> {
   if harness::all_run_lines_negate(content, &["# RUN:"]) {
      return None;
   }
   if harness::has_mcpu_flag(content) {
      return None;
   }

   let mut mode = Mode::Rv32;
   let mut features = Vec::new();
   let mut check_prefixes = vec!["CHECK".to_owned()];

   for line in harness::header_lines(content, 15) {
      if !line.starts_with("# RUN:") || line.contains(" not ") {
         continue;
      }
      if line.contains("riscv64") {
         mode = Mode::Rv64;
      }
      for token in line.split_whitespace() {
         let attr = token
            .strip_prefix("--mattr=")
            .or_else(|| token.strip_prefix("-mattr="));
         if let Some(feature) = attr {
            features.push(feature.to_owned());
         }
      }
      if let Some(val) = harness::extract_flag(line, "-check-prefixes=") {
         check_prefixes = val
            .split(',')
            .map(|prefix| prefix.trim().to_owned())
            .filter(|prefix| !prefix.is_empty())
            .collect();
      }
   }

   Some(Config {
      mode,
      features: (!features.is_empty()).then(|| features.join(",")),
      check_prefixes,
   })
}

fn detect_source_above(lines: &[&str], check_prefixes: &[String]) -> bool {
   let mut inst_patterns = Vec::new();
   for prefix in check_prefixes {
      inst_patterns.push(format!("# {prefix}-INST:"));
      inst_patterns.push(format!("# {prefix}:"));
   }
   for (i, raw) in lines.iter().enumerate() {
      let line = raw.trim();
      if !inst_patterns.iter().any(|pat| line.starts_with(pat)) {
         continue;
      }
      for idx in (0..i).rev().take(3) {
         let prev = lines[idx].trim();
         if prev.is_empty() || prev.starts_with('#') || prev.starts_with('.') {
            continue;
         }
         return true;
      }
      return false;
   }
   false
}

#[expect(
   clippy::too_many_lines,
   reason = "one-pass state machine over the fixture lines"
)]
fn parse_tests(content: &str, check_prefixes: &[String]) -> Vec<harness::ParsedTest<Mode>> {
   let lines: Vec<&str> = content.lines().collect();
   let source_above = detect_source_above(&lines, check_prefixes);
   let mut out = Vec::new();
   let mut i = 0;

   while i < lines.len() {
      let line = lines[i].trim();

      let mut instruction = String::new();
      let mut found = false;
      for prefix in check_prefixes {
         let inst_pattern = format!("# {prefix}-INST:");
         let plain_pattern = format!("# {prefix}:");
         if let Some(rest) = line.strip_prefix(&inst_pattern) {
            instruction = rest.trim().to_owned();
            found = true;
            break;
         }
         if line.starts_with(&plain_pattern)
            && !line.contains("encoding:")
            && !line.contains(".option")
            && !line.contains('[')
         {
            instruction = line.trim_start_matches(&plain_pattern).trim().to_owned();
            found = true;
            break;
         }
      }

      if !found {
         i += 1;
         continue;
      }

      let mut parsed_bytes: Option<Vec<u8>> = None;
      let mut encoding_line_idx = None;
      for (j, raw) in lines.iter().enumerate().skip(i + 1) {
         let cand = raw.trim();

         let mut next_inst = false;
         for prefix in check_prefixes {
            let inst_pattern = format!("# {prefix}-INST:");
            if cand.starts_with(&inst_pattern) {
               next_inst = true;
               break;
            }
         }
         if next_inst {
            break;
         }

         let mut hit = false;
         for prefix in check_prefixes {
            let enc_pattern = format!("# {prefix}:");
            if !cand.starts_with(&enc_pattern) {
               continue;
            }
            if cand.contains("encoding:") {
               hit = true;
               break;
            }
            if prefix == "CHECK-ENC" && cand.contains('[') && cand.contains(']') {
               hit = true;
               break;
            }
         }
         if !hit {
            continue;
         }

         parsed_bytes = harness::enc_of(cand, harness::Enc::Bracket);
         encoding_line_idx = Some(j);
         break;
      }

      let Some(enc_idx) = encoding_line_idx else {
         i += 1;
         continue;
      };
      let Some(bytes) = parsed_bytes else {
         i += 1;
         continue;
      };

      let mut source_inst = instruction.clone();
      let mut found_above: Option<String> = None;
      for idx in (0..i).rev() {
         let prev = lines[idx].trim();
         if prev.is_empty() || prev.starts_with('#') || prev.starts_with('.') {
            continue;
         }
         found_above = Some(prev.to_owned());
         break;
      }
      let mut found_below: Option<String> = None;
      for raw in &lines[(enc_idx + 1)..] {
         let next = raw.trim();
         if next.is_empty() || next.starts_with('#') || next.starts_with('.') {
            continue;
         }
         found_below = Some(next.to_owned());
         break;
      }
      let mnemonic = instruction.split_whitespace().next().unwrap_or("");
      let overlaps = |cand: &str| {
         (cand.contains(&instruction) || instruction.contains(cand))
            && cand
               .split_whitespace()
               .next()
               .is_some_and(|mnem| !mnemonic.is_empty() && mnem == mnemonic)
      };
      let primary = if source_above {
         &found_above
      } else {
         &found_below
      };
      if let Some(primary_match) = primary.as_ref().filter(|text| overlaps(text)) {
         source_inst = primary_match.clone();
      }

      if source_inst.is_empty() {
         i += 1;
         continue;
      }

      out.push(harness::ParsedTest {
         instruction: source_inst,
         encoding:    bytes,
         mode:        Mode::Rv32, // placeholder, overwritten by caller
      });

      i = (enc_idx + 1).max(i + 1);
   }

   out
}

#[test]
fn riscv_from_llvm_files() {
   let mut rv32 = Keystone::new(Arch::RISCV).expect("Failed to initialize RISC-V engine");
   let mut rv64 = Keystone::new(Arch::RISCV).expect("Failed to initialize RISC-V engine");
   rv64
      .set_width(Width::W64)
      .expect("Failed to set width for RISC-V engine");

   for (source, raw) in harness::fixtures("RISCV", &[], false) {
      let content = join_continuations(&raw);
      let Some(config) = parse_config(&content) else {
         continue;
      };
      let engine = match config.mode {
         Mode::Rv32 => &mut rv32,
         Mode::Rv64 => &mut rv64,
      };

      harness::reset_and_apply_features(engine, config.features.as_deref(), &source);

      let mut tests = parse_tests(&content, &config.check_prefixes);
      if tests.is_empty() {
         continue;
      }
      for test in &mut tests {
         test.mode = config.mode;
      }

      for harness::ParsedTest {
         instruction,
         encoding,
         mode,
      } in tests
      {
         harness::assemble_and_assert(engine, &instruction, &encoding, &source, mode.label());
      }
   }
}
