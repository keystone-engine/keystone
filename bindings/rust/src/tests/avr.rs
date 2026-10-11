use super::{
   harness,
   harness::Shape::Inline,
   *,
};

#[test]
fn avr_from_llvm_files() {
   let mut ks = Keystone::new(Arch::AVR).expect("Failed to initialize AVR Keystone engine");
   for (source, content) in harness::fixtures("AVR", &["# RUN:", "; RUN:"], true) {
      harness::reset_and_apply_features(
         &mut ks,
         harness::mattr(&content, &["; RUN:"]).as_deref(),
         &source,
      );
      harness::run_cases(
         &mut ks,
         &content,
         &[Inline {
            check: "; CHECK:",
            enc:   "; encoding:",
         }],
         "Avr",
         &source,
      );
   }
}
