use super::{
   harness,
   *,
};

#[derive(Debug, Default)]
struct Config {
   features: Option<String>,
   cpu:      Option<String>,
}

fn parse_config(content: &str) -> Config {
   let mut config = Config::default();
   for line in harness::header_lines(content, 15) {
      if !line.starts_with("// RUN:") || line.contains(" not ") {
         continue;
      }
      if let Some(val) = harness::extract_flag(line, "-mcpu=") {
         config.cpu = Some(val.to_owned());
      }
      if let Some(val) = harness::extract_flag(line, "-mattr=") {
         config.features = Some(val.to_owned());
      }
   }
   config
}

#[test]
fn amdgpu_from_llvm_files() {
   let mut ks = Keystone::new(Arch::Amdgpu).expect("Failed to initialize AMDGPU Keystone engine");

   for (source, content) in harness::fixtures("AMDGPU", &["// RUN:"], false) {
      let config = parse_config(&content);
      if let Some(cpu) = config.cpu.as_ref() {
         println!("Setting CPU model `{cpu}` for AMDGPU engine from file {source}");
         ks.set_cpu(cpu)
            .expect("Failed to set CPU model for AMDGPU engine");
      }
      harness::reset_and_apply_features(&mut ks, config.features.as_deref(), &source);

      for harness::ParsedTest {
         instruction,
         encoding,
         mode,
      } in harness::parse_adjacent(
         &content,
         "// CHECK:",
         harness::Enc::Bracket,
         harness::Dir::BelowGuarded,
         |line| {
            !(line.is_empty()
               || line.starts_with("//")
               || line.starts_with("RUN")
               || line.starts_with('#'))
         },
         "Amdgpu",
      ) {
         harness::assemble_and_assert(&mut ks, &instruction, &encoding, &source, mode);
      }
   }
}
