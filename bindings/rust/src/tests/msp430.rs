use super::{
   harness,
   *,
};

fn parse_tests(content: &str) -> Vec<harness::ParsedTest<&'static str>> {
   let (check_inline, check_inst, check_enc) = if content.contains("# CHECK:") {
      ("# CHECK:", "# CHECK-INST:", "# CHECK: encoding:")
   } else {
      ("; CHECK:", "; CHECK-INST:", "; CHECK: encoding:")
   };

   let mut split = harness::parse_split_check_lines(content, check_inst, check_enc, "MSP430");
   if !split.is_empty() {
      return split;
   }

   split.extend(harness::parse_inline_check_lines(
      content,
      check_inline,
      "encoding:",
      "MSP430",
   ));
   split
}

#[test]
fn msp430_from_llvm_files() {
   let mut ks = Keystone::new(Arch::MSP430).expect("Failed to initialize MSP430 Keystone engine");
   for (source, content) in harness::fixtures("MSP430", &["# RUN:", "; RUN:"], true) {
      harness::reset_and_apply_features(
         &mut ks,
         harness::mattr(&content, &["# RUN:", "; RUN:"]).as_deref(),
         &source,
      );
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
