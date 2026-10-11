use super::*;

#[test]
fn evm_instructions() {
   let test_cases: &[(&str, &[u8])] = &[
      ("PUSH1", &[0x60]),
      ("PUSH2", &[0x61]),
      ("ADD", &[0x01]),
      ("MUL", &[0x02]),
      ("SUB", &[0x03]),
      ("DIV", &[0x04]),
      ("MOD", &[0x06]),
      ("EXP", &[0x0A]),
      ("AND", &[0x16]),
      ("OR", &[0x17]),
      ("XOR", &[0x18]),
      ("NOT", &[0x19]),
      ("LT", &[0x10]),
      ("GT", &[0x11]),
      ("EQ", &[0x14]),
   ];

   let mut ks = Keystone::new(Arch::EVM).expect("Failed to initialize EVM Keystone engine");
   for &(instruction, expected_encoding) in test_cases {
      let asm = ks
         .asm(instruction, 0)
         .expect("Failed to assemble EVM instruction");
      assert_eq!(
         asm.bytes, expected_encoding,
         "EVM instruction '{instruction}' produced incorrect encoding"
      );
   }
}
