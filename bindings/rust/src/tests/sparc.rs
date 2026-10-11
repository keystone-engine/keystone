use super::{
   harness,
   *,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
   Sparc,
   SparcV9,
}

impl Mode {
   fn label(self) -> &'static str {
      match self {
         Self::Sparc => "Sparc",
         Self::SparcV9 => "SparcV9",
      }
   }
}

#[derive(Debug)]
struct Config {
   mode:     Mode,
   features: Option<String>,
   endian:   Endian,
}

fn parse_config(content: &str) -> Option<Config> {
   if harness::all_run_lines_negate(content, &["! RUN:"]) {
      return None;
   }
   if harness::has_mcpu_flag(content) {
      return None;
   }

   let mut mode = Mode::Sparc;
   let mut endian = Endian::Big;
   let mut features = None;

   for line in harness::header_lines(content, 15) {
      if !line.starts_with("! RUN:") || line.contains(" not ") {
         continue;
      }
      if line.contains("triple=sparcv9") || line.contains("triple=sparc64") {
         mode = Mode::SparcV9;
      }
      if line.contains("sparcel") {
         endian = Endian::Little;
      }
      if let Some(val) = harness::extract_flag(line, "-mattr=") {
         features = Some(val.to_owned());
      }
   }

   Some(Config {
      mode,
      features,
      endian,
   })
}

#[test]
fn sparc_from_llvm_files() {
   let mut sparc = Keystone::new(Arch::Sparc).expect("Failed to initialize SPARC Keystone engine");
   let mut sparcv9 =
      Keystone::new(Arch::Sparc).expect("Failed to initialize SPARCv9 Keystone engine");
   sparcv9.set_width(Width::W64).expect("Failed to set width");

   for (source, content) in harness::fixtures("Sparc", &["! RUN:"], false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };
      let engine: &mut Keystone = match config.mode {
         Mode::Sparc => &mut sparc,
         Mode::SparcV9 => &mut sparcv9,
      };

      if let Some(features) = config.features.as_ref() {
         harness::reset_and_apply_features(engine, Some(features), &source);
      } else {
         harness::reset_and_apply_features(engine, None, &source);
      }
      engine
         .set_endian(config.endian)
         .expect("Failed to set endian");

      let tests =
         harness::parse_inline_check_lines(&content, "! CHECK:", "encoding:", config.mode.label());
      for harness::ParsedTest {
         instruction,
         encoding,
         mode,
      } in tests
      {
         harness::assemble_and_assert(engine, &instruction, &encoding, &source, mode);
      }
   }
}

#[test]
fn bpr_immediate_divide_by_four() {
   let mut ks = Keystone::new(Arch::Sparc).unwrap();
   ks.set_endian(Endian::Big).unwrap();
   ks.set_width(Width::W64).unwrap();
   assert_eq!(ks.asm("brlez %g1, 0x400", 0).unwrap().bytes, [
      0x04, 0xC8, 0x41, 0x00
   ]);
}
