use super::{
   harness,
   *,
};

#[derive(Debug, Default)]
struct Config {
   features: Option<String>,
   cpu:      Option<String>,
}

fn parse_config(content: &str) -> Option<Config> {
   if harness::all_run_lines_negate(content, &["; RUN:"]) {
      return None;
   }
   for line in harness::header_lines(content, 15) {
      if (line.contains("-mcpu=") || line.contains("-march=")) && !line.contains("m68k") {
         return None;
      }
   }

   let mut config = Config::default();
   for line in harness::header_lines(content, 15) {
      if !line.starts_with("; RUN:") || line.contains(" not ") {
         continue;
      }
      if let Some(val) = harness::extract_flag(line, "-mattr=") {
         config.features = Some(val.to_owned());
      }
      if let Some(val) = harness::extract_flag(line, "-mcpu=") {
         config.cpu = Some(val.to_owned());
      }
   }
   Some(config)
}

fn parse_encoding_with_placeholders(text: &str) -> Option<(Vec<u8>, bool)> {
   let inner = text.trim().trim_start_matches('[').trim_end_matches(']');
   if inner.is_empty() {
      return None;
   }
   let mut bytes = Vec::new();
   let mut has_placeholder = false;
   for tok in inner.split(',') {
      let trimmed = tok.trim();
      if trimmed == "A" || trimmed == "a" {
         bytes.push(0);
         has_placeholder = true;
         continue;
      }
      let body = trimmed.trim_start_matches("0x");
      match u8::from_str_radix(body, 16) {
         Ok(byte) => bytes.push(byte),
         Err(_) => return None,
      }
   }
   if bytes.is_empty() {
      None
   } else {
      Some((bytes, has_placeholder))
   }
}

struct Pair {
   instruction:     String,
   encoding:        Vec<u8>,
   has_placeholder: bool,
}

fn parse_pairs(content: &str) -> Vec<Pair> {
   let lines: Vec<&str> = content.lines().collect();
   let mut out = Vec::new();
   let mut i = 0;
   while i < lines.len() {
      let line = lines[i].trim();
      if !line.starts_with("; CHECK:") {
         i += 1;
         continue;
      }

      let mut instruction = String::new();
      for raw in &lines[(i + 1)..] {
         let cand = raw.trim();
         if cand.starts_with(';') || cand.is_empty() {
            continue;
         }
         instruction = cand.to_owned();
         break;
      }
      if instruction.is_empty() {
         i += 1;
         continue;
      }

      let mut parsed_encoding = None;
      let mut has_placeholder = false;
      for raw in &lines[i..(i + 3).min(lines.len())] {
         let cand = raw.trim();
         if !((cand.starts_with("; CHECK:") || cand.starts_with("; CHECK-SAME:"))
            && cand.contains("encoding:"))
         {
            continue;
         }
         let Some(after) = cand.split("encoding:").nth(1) else {
            continue;
         };
         if let Some((bytes, ph)) = parse_encoding_with_placeholders(after) {
            parsed_encoding = Some(bytes);
            has_placeholder = ph;
            break;
         }
      }

      if let Some(encoding) = parsed_encoding {
         out.push(Pair {
            instruction,
            encoding,
            has_placeholder,
         });
      }
      i += 1;
   }
   out
}

fn run_pair(ks: &mut Keystone, pair: Pair, source: &str) {
   let Pair {
      instruction,
      encoding,
      has_placeholder,
   } = pair;

   println!("Testing instruction: {instruction} with encoding: {encoding:?} in mode: M68k");
   let contains_label = instruction.contains(".LBB") || instruction.contains("label");
   let contains_pc_rel = instruction.contains("%pc")
      || instruction.contains("BACKWARD")
      || instruction.contains("FORWARD");

   let bytes = match harness::assemble(ks, &instruction) {
      Ok(bytes) => bytes,
      Err(err) => {
         if contains_label || contains_pc_rel {
            println!("Skipping instruction with label/PC-rel '{instruction}': {err}");
            return;
         }
         panic!("Failed to assemble instruction '{instruction}' from file {source}: {err}");
      },
   };

   if has_placeholder || contains_label || contains_pc_rel {
      let non_placeholder_count = encoding.iter().take_while(|&&byte| byte != 0).count();
      if non_placeholder_count == 0 {
         return;
      }
      let is_pc_rel_jump = (instruction.contains("jsr")
         || instruction.contains("jmp")
         || instruction.contains("bsr"))
         && (instruction.contains("%pc")
            || instruction.contains("BACKWARD")
            || instruction.contains("FORWARD"));
      if is_pc_rel_jump && bytes.len() >= 2 && encoding.len() >= 2 {
         assert_eq!(
            &bytes[..2],
            &encoding[..2],
            "PC-relative call/jump '{instruction}' produced incorrect opcode from file {source}"
         );
      } else {
         let cmp_len = non_placeholder_count.min(bytes.len());
         assert_eq!(
            &bytes[..cmp_len],
            &encoding[..non_placeholder_count],
            "Instruction with label '{instruction}' produced incorrect encoding prefix from file \
             {source}"
         );
      }
   } else {
      assert_eq!(
         bytes, encoding,
         "Instruction '{instruction}' produced incorrect encoding from file {source}"
      );
   }
}

#[test]
fn m68k_from_llvm_files() {
   let mut ks = Keystone::new(Arch::M68k).expect("Failed to initialize M68K Keystone engine");

   for (source, content) in harness::fixtures("M68k", &["; RUN:"], false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };
      let cpu = config.cpu.as_deref().unwrap_or("");
      ks.set_cpu(cpu)
         .unwrap_or_else(|_| panic!("Failed to set CPU `{cpu}` from file {source}"));
      let features = config.features.as_deref().unwrap_or("");
      ks.set_feature(features)
         .unwrap_or_else(|_| panic!("Failed to set features `{features}` from file {source}"));

      for pair in parse_pairs(&content) {
         run_pair(&mut ks, pair, &source);
      }
   }
}

#[test]
fn faddx() {
   let mut ks = Keystone::new(Arch::M68k).expect("Failed to initialize M68K Keystone engine");
   ks.set_feature("+isa-68881")
      .expect("Failed to enable M68881 FPU feature");
   let asm = ks
      .asm(b"fadd.x %fp0, %fp1", 0)
      .expect("Failed to assemble instruction");
   assert_eq!(asm.bytes, vec![0xF2, 0x00, 0x00, 0xA2]);
}
