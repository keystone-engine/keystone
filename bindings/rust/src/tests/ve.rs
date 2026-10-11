use super::{
   harness,
   harness::Shape::Split,
   *,
};

#[test]
fn ve_from_llvm_files() {
   let mut ks = Keystone::new(Arch::VE).expect("Failed to initialize VE Keystone engine");
   for (source, content) in harness::fixtures("VE", &["# RUN:"], true) {
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
            enc:  "# CHECK-ENCODING: encoding:",
         }],
         "VE",
         &source,
      );
   }
}
