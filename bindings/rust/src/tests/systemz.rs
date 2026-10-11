use super::{
   harness,
   *,
};

#[test]
fn systemz_from_llvm_files() {
   let mut ks = Keystone::new(Arch::Systemz).expect("Failed to initialize SystemZ Keystone engine");
   for (source, content) in harness::fixtures("SystemZ", &["# RUN:"], true) {
      harness::reset_and_apply_features(
         &mut ks,
         harness::mattr(&content, &["# RUN:"]).as_deref(),
         &source,
      );
      harness::run_cases(
         &mut ks,
         &content,
         &[harness::Shape::Inline {
            check: "#CHECK:",
            enc:   "encoding:",
         }],
         "SystemZ",
         &source,
      );
   }
}

#[test]
fn crash_on_exponent_with_no_digits() {
   let mut ks = Keystone::new(Arch::Systemz).unwrap();
   assert_asm_error(
      ks.asm("}8e", 0),
      ErrorAssertion::at(
         KsErr::AsmSyntax,
         (1, 1),
         "unexpected token at start of statement",
      ),
   );

   assert_asm_error(
      ks.asm(b".08e+", 0),
      ErrorAssertion::at(
         KsErr::AsmSyntax,
         (1, 1),
         "unexpected token at start of statement",
      ),
   );
}

#[test]
fn crash_on_invalid_character_in_exponent_absexponent() {
   let mut ks = Keystone::new(Arch::Systemz).unwrap();
   assert_asm_error(
      ks.asm(b"J-9ee", 0),
      ErrorAssertion::at(KsErr::AsmInvalidOperand, (1, 2), "offset out of range"),
   );
}

#[test]
fn crash_on_elfobjectwriter() {
   let mut ks = Keystone::new(Arch::Systemz).unwrap();
   ks.asm(b"J-9-TI@h--9", 0).unwrap_err();
}

#[test]
fn crash_on_computing_fragment_size() {
   let mut ks = Keystone::new(Arch::Systemz).unwrap();
   assert_asm_error(
      ks.asm(b"=X;X:.]", 0),
      ErrorAssertion::with_locations(KsErr::AsmExprError, [
         ErrorLocation {
            point:   (1, 1),
            message: "unexpected token at start of statement",
         },
         ErrorLocation {
            point:   (1, 7),
            message: "unknown token in expression",
         },
      ]),
   );
}

#[test]
fn crash_on_doit() {
   let mut ks = Keystone::new(Arch::Systemz).unwrap();
   assert_asm_error(
      ks.asm(".org .-x^0\nx:'", 0),
      ErrorAssertion::simple(KsErr::AsmSyntax),
   );
}
