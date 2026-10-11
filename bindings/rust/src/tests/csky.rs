use super::{
   harness,
   *,
};

#[derive(Debug, Default)]
struct Config {
   features:   Option<String>,
   compressed: bool,
}

fn parse_config(content: &str) -> Config {
   let mut features = Vec::new();
   let mut compressed = false;
   for line in harness::header_lines(content, 15) {
      for chunk in line.split("-mattr=").skip(1) {
         if let Some(val) = chunk.split_whitespace().next() {
            if !val.is_empty() {
               features.push(val.to_owned());
            }
         }
      }
      if let Some(val) = harness::extract_flag(line, "-enable-csky-asm-compressed-inst=") {
         compressed = val == "true";
      }
   }

   Config {
      features: (!features.is_empty()).then(|| features.join(",")),
      compressed,
   }
}

#[test]
fn csky_from_llvm_files() {
   let mut ks = Keystone::new(Arch::CSKY).expect("Failed to initialize CSKY Keystone engine");

   for (source, content) in harness::fixtures("CSKY", &["# RUN:"], false) {
      let config = parse_config(&content);

      harness::reset_and_apply_features(&mut ks, config.features.as_deref(), &source);
      ks.set_csky_compressed(config.compressed)
         .expect("Failed to set csky compressed");

      for harness::ParsedTest {
         instruction,
         encoding,
         mode,
      } in harness::parse_adjacent(
         &content,
         "# CHECK-ASM:",
         harness::Enc::Bracket,
         harness::Dir::Below,
         |line| !(line.is_empty() || line.starts_with('#') || line.starts_with("//")),
         "CSKY",
      ) {
         harness::assemble_and_assert(&mut ks, &instruction, &encoding, &source, mode);
      }
   }
}

#[test]
fn csky_fldmd() {
   let mut ks = Keystone::new(Arch::CSKY).expect("Failed to initialize CSKY Keystone engine");
   ks.set_feature("fpuv2_df")
      .expect("Failed to set feature 'fpuv2_df'");

   harness::assemble_and_assert(
      &mut ks,
      "fldmd  vr1-vr2, (a1)",
      &[0x21, 0xF4, 0x01, 0x31],
      "test_csky_fldmd",
      "Csky",
   );
}
