use super::{
   harness,
   *,
};

fn parse_tests(content: &str) -> Vec<harness::ParsedTest<&'static str>> {
   let lines: Vec<&str> = content.lines().collect();

   let mut instructions = Vec::new();
   for raw_line in &lines {
      let line = raw_line.trim();
      if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
         continue;
      }
      instructions.push(line.to_owned());
   }

   let mut out = Vec::new();
   for instruction in instructions {
      let clean = instruction
         .split("//")
         .next()
         .unwrap_or(&instruction)
         .trim()
         .to_owned();

      for raw_line in &lines {
         let line = raw_line.trim();
         let Some(after) = line.strip_prefix("// CHECK:") else {
            continue;
         };
         if !line.contains(&clean) {
            continue;
         }

         let mut bytes = Vec::new();
         for token in after.split_whitespace() {
            match u8::from_str_radix(token, 16) {
               Ok(byte) => bytes.push(byte),
               Err(_) => break,
            }
         }
         if !bytes.is_empty() && !instruction.is_empty() {
            out.push(harness::ParsedTest {
               instruction,
               encoding: bytes,
               mode: "BPF",
            });
         }
         break;
      }
   }
   out
}

#[test]
fn bpf_from_llvm_files() {
   let mut ks = Keystone::new(Arch::BPF).expect("Failed to initialize BPF Keystone engine");
   for (source, content) in harness::fixtures("BPF", &["# RUN:"], true) {
      for case in parse_tests(&content) {
         harness::assemble_and_assert(
            &mut ks,
            &case.instruction,
            &case.encoding,
            &source,
            case.mode,
         );
      }
   }
}
