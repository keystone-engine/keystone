use super::{
   harness,
   harness::Shape::Split,
   *,
};

#[test]
fn xtensa_from_llvm_files() {
   let mut ks = Keystone::new(Arch::Xtensa).expect("Failed to initialize Xtensa Keystone engine");
   for (source, content) in harness::fixtures("Xtensa", &["# RUN:"], true) {
      harness::reset_and_apply_features(
         &mut ks,
         harness::mattr(&content, &["# RUN:"]).as_deref(),
         &source,
      );
      harness::run_cases(
         &mut ks,
         &content,
         &[Split {
            inst: "# CHECK-INST:",
            enc:  "# CHECK: encoding:",
         }],
         "Xtensa",
         &source,
      );
   }
}
