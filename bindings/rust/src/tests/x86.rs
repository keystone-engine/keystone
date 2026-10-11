use alloc::vec::Vec;

use super::{
   harness,
   *,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
   X86_16,
   X86_32,
   X86_64,
}

impl Mode {
   fn label(self) -> &'static str {
      match self {
         Self::X86_16 => "X86_16",
         Self::X86_32 => "X86_32",
         Self::X86_64 => "X86_64",
      }
   }
}

#[derive(Debug)]
struct Config {
   mode:   Mode,
   syntax: X86Syntax,
}

const PRINTED_FORM_CHECKS: &[(&str, &[u8])] = &[
   ("addl    %ebx, %ecx", &[0x40, 0x01, 0xD9]),
   ("addl    %ebx, %ecx", &[0xD5, 0x00, 0x01, 0xD9]),
   ("popcntl %edi, %esi", &[0xF3, 0x40, 0x0F, 0xB8, 0xF7]),
   ("popcntl %edi, %esi", &[0xF3, 0xD5, 0x80, 0xB8, 0xF7]),
   ("rclb\t%al, %bl", &[0x62, 0xF4, 0x64, 0x18, 0xD0, 0xD0]),
   ("rcrb\t%al, %bl", &[0x62, 0xF4, 0x64, 0x18, 0xD0, 0xD8]),
   ("rolb\t%al, %bl", &[0x62, 0xF4, 0x64, 0x18, 0xD0, 0xC0]),
   ("{nf}\trolb\t%al, %bl", &[
      0x62, 0xF4, 0x64, 0x1C, 0xD0, 0xC0,
   ]),
   ("rorb\t%al, %bl", &[0x62, 0xF4, 0x64, 0x18, 0xD0, 0xC8]),
   ("{nf}\trorb\t%al, %bl", &[
      0x62, 0xF4, 0x64, 0x1C, 0xD0, 0xC8,
   ]),
   ("sarb\t%al, %bl", &[0x62, 0xF4, 0x64, 0x18, 0xD0, 0xF8]),
   ("{nf}\tsarb\t%al, %bl", &[
      0x62, 0xF4, 0x64, 0x1C, 0xD0, 0xF8,
   ]),
   ("shlb\t%al, %bl", &[0x62, 0xF4, 0x64, 0x18, 0xD0, 0xE0]),
   ("{nf}\tshlb\t%al, %bl", &[
      0x62, 0xF4, 0x64, 0x1C, 0xD0, 0xE0,
   ]),
   ("shrb\t%al, %bl", &[0x62, 0xF4, 0x64, 0x18, 0xD0, 0xE8]),
   ("{nf}\tshrb\t%al, %bl", &[
      0x62, 0xF4, 0x64, 0x1C, 0xD0, 0xE8,
   ]),
];

const RUN_PREFIXES: &[&str] = &["// RUN:", "# RUN:"];

fn parse_config(content: &str) -> Option<Config> {
   if harness::all_run_lines_negate(content, RUN_PREFIXES) {
      return None;
   }
   if content.contains(".code16gcc") {
      return None;
   }

   let mut mode = Mode::X86_32;
   let mut syntax = X86Syntax::ATT;
   for line in harness::header_lines(content, 15) {
      if !RUN_PREFIXES.iter().any(|prefix| line.starts_with(prefix)) || line.contains(" not ") {
         continue;
      }
      if line.contains("x86_64") || line.contains("x86-64") {
         mode = Mode::X86_64;
      } else if line.contains("code16") {
         mode = Mode::X86_16;
      } else if line.contains("i386") || line.contains("i686") || line.contains("x86-32") {
         mode = Mode::X86_32;
      }
      if line.contains("-x86-asm-syntax=intel") {
         syntax = X86Syntax::Intel;
      }
   }
   Some(Config { mode, syntax })
}

fn parse_tests(content: &str, mode: Mode) -> Vec<harness::ParsedTest<Mode>> {
   let mut out = harness::parse_inline_check_lines(content, "// CHECK:", "# encoding:", mode);
   out.extend(harness::parse_split_check_lines(
      content,
      "// CHECK:",
      "// CHECK: encoding:",
      mode,
   ));
   out.retain(|case| {
      !PRINTED_FORM_CHECKS.iter().any(|&(instruction, encoding)| {
         case.instruction == instruction && case.encoding == encoding
      })
   });
   out
}

#[test]
fn x86_from_llvm_files() {
   let mut x86_16 = Keystone::new(Arch::X86).expect("Failed to initialize X86_16 engine");
   x86_16.set_width(Width::W16).expect("Failed to set width");

   let mut x86_32 = Keystone::new(Arch::X86).expect("Failed to initialize X86_32 engine");
   let mut x86_64 = Keystone::new(Arch::X64).expect("Failed to initialize X86_64 engine");
   x86_16.set_x86_syntax(X86Syntax::ATT).unwrap();
   x86_32.set_x86_syntax(X86Syntax::ATT).unwrap();
   x86_64.set_x86_syntax(X86Syntax::ATT).unwrap();
   let mut last_syntax = X86Syntax::ATT;

   for (source, content) in harness::fixtures("X86", &[], false) {
      let Some(config) = parse_config(&content) else {
         continue;
      };

      if config.syntax != last_syntax {
         x86_16.set_x86_syntax(config.syntax).unwrap();
         x86_32.set_x86_syntax(config.syntax).unwrap();
         x86_64.set_x86_syntax(config.syntax).unwrap();
         last_syntax = config.syntax;
      }

      for harness::ParsedTest {
         instruction,
         encoding,
         mode,
      } in parse_tests(&content, config.mode)
      {
         let engine = match mode {
            Mode::X86_16 => &mut x86_16,
            Mode::X86_32 => &mut x86_32,
            Mode::X86_64 => &mut x86_64,
         };
         harness::assemble_and_assert(engine, &instruction, &encoding, &source, mode.label());
      }
   }
}

#[test]
fn x64_bigint() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   assert_eq!(ks.asm("mov rdi, 0x1122334455", 0).unwrap().bytes, [
      0x48, 0xBF, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00
   ]);

   assert_eq!(ks.asm("movabs rdi, 0x1122334455", 0).unwrap().bytes, [
      0x48, 0xBF, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00
   ]);
}

#[test]
fn jmp_imm() {
   let mut ks = Keystone::new(Arch::X86).unwrap();

   ks.set_x86_syntax(X86Syntax::ATT).unwrap();
   assert_eq!(ks.asm("jmp 0", 0).unwrap().bytes, [0xEB, 0xFE]);

   ks.set_x86_syntax(X86Syntax::Intel).unwrap();
   assert_eq!(ks.asm("jmp 0", 0).unwrap().bytes, [0xEB, 0xFE]);
}

#[test]
fn jmp_offset() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_x86_syntax(X86Syntax::ATT).unwrap();
   assert_eq!(ks.asm("jmpl *5", 0).unwrap().bytes, [
      0xFF, 0x25, 0x05, 0x00, 0x00, 0x00
   ]);

   ks.set_x86_syntax(X86Syntax::Intel).unwrap();
   assert_eq!(ks.asm("jmp dword ptr [5]", 0).unwrap().bytes, [
      0xFF, 0x25, 0x05, 0x00, 0x00, 0x00
   ]);
}

#[test]
fn nasm() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_x86_syntax(X86Syntax::NASM).unwrap();
   assert_eq!(ks.asm("mov dword [eax], 0x42424242", 0).unwrap().bytes, [
      0xC7, 0x00, 0x42, 0x42, 0x42, 0x42
   ]);

   assert_eq!(
      ks.asm("add eax, ebx; inc ecx this comment is ignored\ninc edx", 0)
         .unwrap()
         .bytes,
      [0x01, 0xD8, 0x42]
   );
}

#[test]
fn nasm_default_rel() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   ks.set_x86_syntax(X86Syntax::NASM).unwrap();
   assert_eq!(
      ks.asm(
         "
        default rel
        lea rax, [__data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]
   );

   assert_eq!(
      ks.asm(
         "
        default rel
        default abs
        lea rax, [__data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x48, 0x8D, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00]
   );

   assert_eq!(
      ks.asm(
         "
        default rel
        lea rax, ds:[__data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]
   );

   assert_eq!(
      ks.asm(
         "
        default rel
        lea rax, cs:[__data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x2E, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]
   );

   assert_eq!(
      ks.asm(
         "
        default rel
        lea rax, fs:[__data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x64, 0x48, 0x8D, 0x04, 0x25, 0x09, 0x00, 0x00, 0x00]
   );
}

#[test]
fn label_rel() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   ks.set_x86_syntax(X86Syntax::NASM).unwrap();
   assert_eq!(
      ks.asm(
         "
        lea rax, [rel __data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]
   );

   assert_eq!(
      ks.asm(
         "
        nop
        nop
        lea rax, [rel __data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x90, 0x90, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]
   );

   ks.set_x86_syntax(X86Syntax::ATT).unwrap();
   assert_eq!(
      ks.asm(
         "
        lea __data(%rip), %rax
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]
   );

   assert_eq!(
      ks.asm(
         "
        nop
        nop
        lea __data(%rip), %rax
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x90, 0x90, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]
   );

   ks.set_x86_syntax(X86Syntax::Intel).unwrap();
   assert_eq!(
      ks.asm(
         "
        lea rax, [rip + __data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]
   );

   assert_eq!(
      ks.asm(
         "
        nop
        nop
        lea rax, [rip + __data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x90, 0x90, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]
   );
}

#[test]
fn nasm_directives() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_x86_syntax(X86Syntax::NASM).unwrap();

   assert_eq!(
      ks.asm(
         "
        db 12, 13
        dw 14, 15
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x0C, 0x0D, 0x0E, 0x00, 0x0F, 0x00]
   );

   assert_eq!(
      ks.asm(
         "
        bits 32
        add eax, ebx
        bits 16
        add eax, ebx
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x01, 0xD8, 0x66, 0x01, 0xD8]
   );
}

#[test]
fn lea_label_nasm_abs() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   ks.set_x86_syntax(X86Syntax::NASM).unwrap();
   assert_eq!(
      ks.asm(
         "
        lea rax, [abs __data]
        __data:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x48, 0x8D, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00]
   );
}

#[test]
fn lea_label_addr() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   assert_eq!(
      ks.asm(
         "
        lea eax, [__data]
        __data:
    ",
         0x0048_0000
      )
      .unwrap()
      .bytes,
      [0x8D, 0x05, 0x06, 0x00, 0x48, 0x00]
   );
}

#[test]
fn lea_three() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_x86_syntax(X86Syntax::NASM).unwrap();
   assert_eq!(
      ks.asm(
         "
        a:
        lea eax, [eax + b - a]
        b:
    ",
         0
      )
      .unwrap()
      .bytes,
      [0x8D, 0x80, 0x06, 0x00, 0x00, 0x00]
   );
}

#[test]
fn rip_relative() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   assert_eq!(
      ks.asm("mov qword ptr [rip+0xF55AF], 0xFF", 0)
         .unwrap()
         .bytes,
      [
         0x48, 0xC7, 0x05, 0xAF, 0x55, 0x0F, 0x00, 0xFF, 0x00, 0x00, 0x00
      ]
   );

   assert_eq!(
      ks.asm("mov qword ptr [rip+0xF55AF], 0xFFFFFFFFFFFFFFFE", 0)
         .unwrap()
         .bytes,
      [
         0x48, 0xC7, 0x05, 0xAF, 0x55, 0x0F, 0x00, 0xFE, 0xFF, 0xFF, 0xFF
      ]
   );
}

#[test]
fn call() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   assert_eq!(ks.asm("call 0", 0).unwrap().bytes, [
      0xE8, 0xFB, 0xFF, 0xFF, 0xFF
   ]);

   // let code = "call 5";
   // let asm = ks.asm(code, 0x2000).unwrap();
   // assert_eq!(asm.bytes, [0xe8, 0x00, 0xe0, 0xff, 0xff]);
   //
   // ks.set_x86_syntax(X86Syntax::ATT).unwrap();
   // let asm = ks.asm(code, 0x2000).unwrap();
   // assert_eq!(asm.bytes, [0xe8, 0x00, 0xe0, 0xff, 0xff]);
}

#[test]
fn call_label() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   let code = "
        call label
        label:
    ";

   ks.set_x86_syntax(X86Syntax::NASM).unwrap();
   let asm_nasm = ks.asm(code, 0).unwrap();
   assert_eq!(asm_nasm.bytes, [0xE8, 0x00, 0x00, 0x00, 0x00]);

   ks.set_x86_syntax(X86Syntax::Intel).unwrap();
   let asm_intel = ks.asm(code, 0).unwrap();
   assert_eq!(asm_intel.bytes, [0xE8, 0x00, 0x00, 0x00, 0x00]);

   ks.set_x86_syntax(X86Syntax::ATT).unwrap();
   let asm_att = ks.asm(code, 0).unwrap();
   assert_eq!(asm_att.bytes, [0xE8, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn label_arith() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_x86_syntax(X86Syntax::NASM).unwrap();

   let code_sub = "
        sub eax, foo + 5
        foo:
    ";
   let asm_sub = ks.asm(code_sub, 0).unwrap();
   let valid_1: &[&[u8]] = &[
      &[0x2D, 0x0A, 0x00, 0x00, 0x00],
      &[0x81, 0xE8, 0x0B, 0x00, 0x00, 0x00],
      &[0x83, 0xE8, 0x08],
   ];
   assert!(
      valid_1.iter().any(|cand| *cand == asm_sub.bytes),
      "got {:?}, expected one of {:?}",
      asm_sub.bytes,
      valid_1
   );

   let code_diff = "
        sub eax, bar - foo
        foo:
            dq 0
        bar:
    ";
   let asm_diff = ks.asm(code_diff, 0).unwrap();
   let valid_2: &[&[u8]] = &[
      &[
         0x2D, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ],
      &[
         0x81, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ],
      &[
         0x83, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ],
   ];
   assert!(
      valid_2.iter().any(|cand| *cand == asm_diff.bytes),
      "got {:?}, expected one of {:?}",
      asm_diff.bytes,
      valid_2
   );
}

#[test]
fn int3() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   assert_eq!(ks.asm("int 3", 0).unwrap().bytes, [0xCD, 0x03]);
}

#[test]
fn ds_segment_prefix() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   assert_eq!(ks.asm("jmp dword ptr ds:[100]", 0).unwrap().bytes, [
      0xFF, 0x25, 0x64, 0x00, 0x00, 0x00
   ]);
}

#[test]
fn ss_default() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   assert_eq!(ks.asm("mov eax, dword ptr ss:[esp+8]", 0).unwrap().bytes, [
      0x8B, 0x44, 0x24, 0x08
   ]);

   assert_eq!(ks.asm("mov eax, dword ptr ss:[ebp+8]", 0).unwrap().bytes, [
      0x8B, 0x45, 0x08
   ]);
}

#[test]
fn x64_edge_cases() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   assert_eq!(
      ks.asm("movsx r12d, byte ptr [r15 + rbp * 1]", 0)
         .unwrap()
         .bytes,
      [0x45, 0x0F, 0xBE, 0x24, 0x2F]
   );

   assert_eq!(ks.asm("lea rdx, [rax]", 0).unwrap().bytes, [
      0x48, 0x8D, 0x10
   ]);

   assert_eq!(
      ks.asm("add qword ptr [0x7FF68481C8ED], 0x1", 0x7FF6_845C_B982)
         .unwrap()
         .bytes,
      [0x48, 0x83, 0x05, 0x63, 0x0F, 0x25, 0x00, 0x01]
   );

   assert_eq!(ks.asm("jmp [0x12345678]", 0).unwrap().bytes, [
      0xFF, 0x24, 0x25, 0x78, 0x56, 0x34, 0x12
   ]);

   assert_eq!(
      ks.asm("movabs rax, qword ptr ds:[0x1234567890]", 0x7FFC_A9FF_1977)
         .unwrap()
         .bytes,
      [0x48, 0xA1, 0x90, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00]
   );
}

#[test]
fn push_word() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   assert_eq!(ks.asm("push 0xd", 0).unwrap().bytes, [0x6A, 0x0D]);

   assert_eq!(ks.asm("push word ptr 0xd", 0).unwrap().bytes, [
      0x66, 0x6A, 0x0D
   ]);

   assert_eq!(ks.asm("push word 0x1234", 0).unwrap().bytes, [
      0x66, 0x68, 0x34, 0x12
   ]);

   assert_eq!(ks.asm("pushw 0x1234", 0).unwrap().bytes, [
      0x66, 0x68, 0x34, 0x12
   ]);
}

#[test]
fn bnd_prefix() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   assert_eq!(ks.asm("bnd ret", 0).unwrap().bytes, [0xF2, 0xC3]);
   assert_eq!(ks.asm("bnd jmp 0x100", 0).unwrap().bytes, [
      0xF2, 0xE9, 0xFA, 0x00, 0x00, 0x00
   ]);
   assert_eq!(ks.asm("bnd call 0x100", 0).unwrap().bytes, [
      0xF2, 0xE8, 0xFA, 0x00, 0x00, 0x00
   ]);
}

#[test]
fn dollar_is_pc() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   assert_eq!(ks.asm("jmp $", 0x1000).unwrap().bytes, [0xEB, 0xFE]);
}

#[test]
fn set_arch_same_arch_still_clears_resolver() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_symbol_resolver(|sym, val| {
      if sym == "tgt" {
         *val = 0x1000;
         true
      } else {
         false
      }
   })
   .unwrap();
   assert!(ks.has_symbol_resolver());

   let arch = ks.arch();
   ks.set_arch(arch).unwrap();
   assert!(!ks.has_symbol_resolver());

   assert_eq!(
      ks.asm("call tgt", 0).unwrap_err().code(),
      KsErr::AsmMissingSymbol
   );
}

#[test]
fn radix_before_first_asm() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   assert_eq!(ks.radix(), Radix::Decimal);
   ks.set_radix(Radix::Hexadecimal).unwrap();
   assert_eq!(ks.radix(), Radix::Hexadecimal);
   assert_eq!(ks.asm("mov eax, 1", 0).unwrap().bytes, [
      0xB8, 0x01, 0x00, 0x00, 0x00
   ]);
   assert_eq!(ks.radix(), Radix::Hexadecimal);
}

#[test]
#[cfg(feature = "arch_aarch64")]
fn set_arch_clears_resolver_and_state() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_symbol_resolver(|sym, val| {
      if sym == "x86_target" {
         *val = 0x1000;
         true
      } else {
         false
      }
   })
   .unwrap();
   assert!(ks.has_symbol_resolver());

   ks.set_arch(Arch::AArch64).unwrap();
   assert_eq!(ks.arch(), Arch::AArch64);
   assert!(!ks.has_symbol_resolver());

   assert_eq!(ks.asm("mov x0, #1", 0).unwrap().bytes, [
      0x20, 0x00, 0x80, 0xD2
   ]);
}

#[test]
fn keystone_is_send() {
   use std::thread;
   let mut ks = Keystone::new(Arch::X64).unwrap();
   ks.set_symbol_resolver(|sym, val| {
      if sym == "tgt" {
         *val = 0x1000;
         true
      } else {
         false
      }
   })
   .unwrap();
   let bytes = thread::spawn(move || {
      let mut engine = ks;
      engine.asm("call tgt", 0).unwrap().bytes
   })
   .join()
   .unwrap();
   assert_eq!(bytes, [0xE8, 0xFB, 0x0F, 0x00, 0x00]);
}

#[test]
fn resolver_survives_engine_move() {
   let mut engine = Keystone::new(Arch::X86).unwrap();
   engine
      .set_symbol_resolver(|sym, val| {
         if sym == "target" {
            *val = 0x1000;
            true
         } else {
            false
         }
      })
      .unwrap();
   let mut moved = Vec::from([engine]).pop().unwrap();
   assert_eq!(moved.asm("call target", 0).unwrap().bytes, [
      0xE8, 0xFB, 0x0F, 0x00, 0x00
   ]);
}

#[test]
fn at_in_symbol_name() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_symbol_resolver(|sym, val| {
      if sym == "_foo@4" {
         *val = 0x1234_5678;
         true
      } else {
         false
      }
   })
   .unwrap();
   assert_eq!(ks.asm("call _foo@4", 0x1000).unwrap().bytes, [
      0xE8, 0x73, 0x46, 0x34, 0x12
   ]);
}

#[test]
fn section_directives_noop() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   assert_eq!(
      ks.asm(".text\nmov rax, 1\n.data\n.long 0", 0)
         .unwrap()
         .bytes,
      [
         0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
      ]
   );
}

#[test]
fn globl_does_not_externalize_local_label() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   let plain = ks.asm("_foo:\nnop\njmp _foo", 0).unwrap();
   let withgl = ks.asm(".globl _foo\n_foo:\nnop\njmp _foo", 0).unwrap();
   assert_eq!(plain.bytes, withgl.bytes);
   assert_eq!(plain.bytes, [0x90, 0xEB, 0xFD]);
}

#[test]
fn dot_as_current_pc() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   assert_eq!(ks.asm("call .+5", 0).unwrap().bytes, [
      0xE8, 0x00, 0x00, 0x00, 0x00
   ]);
}

#[test]
fn unclosed_bracket_errors() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   ks.asm("lea rcx, [rdx", 0).unwrap_err();
   assert_eq!(ks.asm("lea rcx, [rdx]", 0).unwrap().bytes, [
      0x48, 0x8D, 0x0A
   ]);
}

#[test]
fn call_pcrel16_in_16bit_mode() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_width(Width::W16).unwrap();
   assert_eq!(ks.asm("call 0x100", 0).unwrap().bytes, [0xE8, 0xFD, 0x00]);
}

#[test]
fn lea_label_arithmetic() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   let asm = "L1:\nnop\nlea ecx, [eax + L2 - L1]\nL2:\n.byte 0x90";
   let result = ks.asm(asm, 0x100).unwrap();
   assert_eq!(result.bytes, [
      0x90, 0x8D, 0x88, 0x07, 0x00, 0x00, 0x00, 0x90
   ]);
}

#[test]
fn loop_instruction() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   assert_eq!(
      ks.asm("loop 0x7ff6bf912aad", 0x7FF6_BF91_2A84)
         .unwrap()
         .bytes,
      [0xE2, 0x27]
   );
}

#[test]
fn comiss() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   assert_eq!(
      ks.asm(
         "comiss xmm0, dword ptr [rip + 0x1ca568a]",
         0x0000_7FF6_BF90_CACF
      )
      .unwrap()
      .bytes,
      [0x0F, 0x2F, 0x05, 0x8A, 0x56, 0xCA, 0x01]
   );
}

#[test]
fn ljmp() {
   let mut ks = Keystone::new(Arch::X86).unwrap();
   ks.set_width(Width::W16).unwrap();
   assert_eq!(ks.asm("ljmp 0x33, 0x8", 0).unwrap().bytes, [
      0xEA, 0x08, 0x00, 0x33, 0x00
   ]);
}

#[test]
fn empty_tombstone_not_inserted_into_map() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "b 0777777776b";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_invalid_index() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "\"\"";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_unnamed_symbol() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "D\"\"";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_stringref_with_null_character() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "_{";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_setting_a_variable_twice() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "
        XX=Y/X
        Y/X
        XX=Y/a
        X=9/7
        XX=Y/a
        X=Y
    ";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_invalid_accessor() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "x=y--y;.=x-x";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_undefined_macro() {
   let mut ks = Keystone::new(Arch::X64).unwrap();

   let code_macro = b"\x12;\x12i;.iRp emiRp,\xca\xe9,I=";
   assert!(
      ks.asm(code_macro, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );

   let code_irp = ".irp x,y=";
   assert!(
      ks.asm(code_irp, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_absolute_expression() {
   let code = ".=_";
   let mut ks = Keystone::new(Arch::X64).unwrap();
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_non_immediate() {
   let mut ks = Keystone::new(Arch::X64).unwrap();

   let code_jmp = "jmp~_";
   assert_eq!(
      ks.asm(code_jmp, 0).unwrap_err().code(),
      KsErr::AsmMissingSymbol
   );

   let code_vaddpd = "vaddpd zmm1, zmm1, zmm1, x";
   assert!(
      ks.asm(code_vaddpd, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_value_too_large_for_fixup() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "loop 0x102";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_16bit_memory_operand() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "add [al+si+0x0], si";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_expecting_an_immediate_or_register() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "_-_*-_*AX";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_indexreg_already_set() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "_-*AL-_*AL";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_too_many_bits_for_uint64_t() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "mov rax, 0x20000000000000000000";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_inability_to_evaluate_offset_for_variable() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "x=y--y;.=x-x";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_invalid_scale() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "{[x*mm0";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_computing_fragment_before_predecessor() {
   let mut ks = Keystone::new(Arch::X64).unwrap();

   let code_predecessor = ".=x;.=x;1:";
   assert!(
      ks.asm(code_predecessor, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );

   let code_mul = ".=Y;jmp 0;mul qword ptr fs:[";
   assert!(
      ks.asm(code_mul, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_layout() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = ".=x;.=x";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_evaluating_relocatable() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "x:.=y;y:";
   ks.asm(code, 0).unwrap();
}

#[test]
fn crash_on_invalid_instruction() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "vaddpd zmm1, zmm1, zmm1, x";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_execution_aborted() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = "vaddpd zmm1, zmm1, zmm1:[";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_doit() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = ".=x;x:[eax - 0x1];jmp 0";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn crash_on_incompatible_ty_argument() {
   let mut ks = Keystone::new(Arch::X64).unwrap();
   let code = ".bss\n.int(0-a)";
   assert!(
      ks.asm(code, 0).is_err(),
      "Invalid assembly should return an error instead of crashing or succeeding"
   );
}

#[test]
fn x86_symbol_resolver() {
   let mut ks = Keystone::new(Arch::X86).unwrap();

   ks.set_symbol_resolver(|symbol, value| {
      println!("called with symbol: {symbol}");
      if symbol == "ZwQueryInformationProcess" {
         *value = 0x7FF9_8A05_0840;
         println!("sym_resolver called!");
         return true; // Handled the symbol
      }
      false // Not handled
   })
   .unwrap();

   let expected_bytes = [0xE8, 0x03, 0xEE, 0xFC, 0xFF];

   assert_eq!(
      ks.asm("call 0x7FF98A050840", 0x7FF9_8A08_1A38)
         .unwrap()
         .bytes,
      expected_bytes
   );

   assert_eq!(
      ks.asm("call ZwQueryInformationProcess", 0x7FF9_8A08_1A38)
         .unwrap()
         .bytes,
      expected_bytes
   );
}

#[test]
fn x64_symbol_resolver() {
   let mut ks = Keystone::new(Arch::X64).unwrap();

   ks.set_symbol_resolver(|symbol, value| {
      if symbol == "GetPhoneBuildString" {
         *value = 0x0041_B000;
         return true; // Handled the symbol
      }
      false // Not handled
   })
   .unwrap();

   let expected_bytes = [0xFF, 0x14, 0x25, 0x00, 0xB0, 0x41, 0x00];

   assert_eq!(
      ks.asm("call [GetPhoneBuildString]", 0).unwrap().bytes,
      expected_bytes
   );

   ks.set_x86_syntax(X86Syntax::Intel).unwrap();
   assert_eq!(
      ks.asm("call [GetPhoneBuildString]", 0).unwrap().bytes,
      expected_bytes
   );

   ks.set_x86_syntax(X86Syntax::ATT).unwrap();
   assert_eq!(
      ks.asm("call *GetPhoneBuildString", 0).unwrap().bytes,
      expected_bytes
   );
}

#[test]
fn detailed_error_information() {
   let mut ks = Keystone::new(Arch::X86).unwrap();

   let result = ks.asm("mov eax, !invalid", 0);
   assert!(result.is_err());
   let error = result.expect_err("Expected an error for invalid assembly");

   assert_eq!(
      error.code(),
      KsErr::AsmInvalidOperand,
      "Expected error code for invalid operand, got {:?}",
      error.code()
   );

   let locations = error.locations().expect("No locations found in error");
   assert_eq!(
      locations.len(),
      1,
      "Expected at least one location in error"
   );

   let location = &locations[0];
   assert_eq!(
      location.line, 1,
      "Expected error on line 1, got {}",
      location.line
   );

   assert_eq!(
      location.column, 10,
      "Expected error on column 10, got {}",
      location.column
   );

   assert_eq!(
      location.error_message, "unknown token in expression",
      "Expected error message about invalid token, got '{}'",
      location.error_message
   );
}
