use super::{
   harness,
   *,
};

#[test]
fn crash_with_no_immediates() {
   let mut ks = Keystone::new(Arch::Hexagon).unwrap();
   let code = b".";
   assert_asm_error(
      ks.asm(code, 0),
      ErrorAssertion::simple(KsErr::AsmInvalidOperand),
   );
}

#[test]
fn crash_on_invalid_label() {
   let mut ks = Keystone::new(Arch::Hexagon).unwrap();
   let code = b"B://";
   assert_asm_error(
      ks.asm(code, 0),
      ErrorAssertion::at(KsErr::AsmLabelInvalid, (1, 1), "invalid label"),
   );
}

#[test]
fn crash_on_invalid_character_in_exponent_value() {
   let mut ks = Keystone::new(Arch::Hexagon).unwrap();
   let code = b"R#555D#55e5E";
   assert_asm_error(
      ks.asm(code, 0),
      ErrorAssertion::at(KsErr::AsmInvalidOperand, (1, 1), "unrecognized instruction"),
   );
}

#[test]
fn crash_on_mk_is_not_equal_to_symbolref() {
   let mut ks = Keystone::new(Arch::Hexagon).unwrap();
   let code = b"R19=\xff#R+R1oQ^+R";

   assert_asm_error(
      ks.asm(code, 0),
      ErrorAssertion::at(KsErr::AsmSyntax, (1, 5), "invalid character in input"),
   );
}

struct Config {
   cpu:      String,
   features: String,
}

fn parse_config(content: &str) -> Option<Config> {
   if harness::all_run_lines_negate(content, &["# RUN:", "#RUN:", "// RUN:"]) {
      return None;
   }
   let mut cpu = String::new();
   let mut features = String::new();
   for line in harness::header_lines(content, 10) {
      let is_run =
         line.starts_with("# RUN:") || line.starts_with("#RUN:") || line.starts_with("// RUN:");
      if !is_run || line.contains(" not ") {
         continue;
      }
      if let Some(val) = harness::extract_flag(line, "-mcpu=") {
         cpu = val.to_owned();
      }
      if line.contains("-mhvx") || line.contains("+hvx") {
         features = "+hvx".to_owned();
      }
      break;
   }
   Some(Config { cpu, features })
}

#[test]
fn hexagon_from_llvm_files() {
   let mut ks = Keystone::new(Arch::Hexagon).expect("Failed to initialize Hexagon engine");

   for (source, content) in harness::fixtures("Hexagon", &["# RUN:", "#RUN:", "// RUN:"], false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };
      let pairs = harness::parse_adjacent(
         &content,
         "# CHECK:",
         harness::Enc::Word,
         harness::Dir::Auto,
         |line| {
            !(line.is_empty()
               || line.starts_with('#')
               || line.starts_with("//")
               || line.starts_with('.')
               || line.ends_with(':')
               || line.contains('{')
               || line.contains('}'))
         },
         "Hexagon",
      );
      if pairs.is_empty() {
         continue;
      }

      ks.set_cpu(&config.cpu)
         .unwrap_or_else(|err| panic!("Failed to set cpu `{}` from {source}: {err}", config.cpu));
      harness::reset_and_apply_features(&mut ks, Some(&config.features), &source);

      for case in pairs {
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
