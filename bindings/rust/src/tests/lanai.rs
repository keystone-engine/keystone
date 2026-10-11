use super::{
   harness,
   *,
};

#[test]
fn lanai_from_llvm_files() {
   let mut ks = Keystone::new(Arch::Lanai).expect("Failed to initialize Lanai Keystone engine");
   for (source, content) in harness::fixtures("Lanai", &["! RUN:"], false) {
      for case in harness::parse_adjacent(
         &content,
         "! CHECK:",
         harness::Enc::Bracket,
         harness::Dir::Above,
         |line| {
            !(line.is_empty()
               || line.starts_with('!')
               || line.starts_with('.')
               || line.ends_with(':'))
         },
         "Lanai",
      ) {
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
