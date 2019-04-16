#![allow(non_camel_case_types)]
// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [x86_const.rs]
use libc;
bitflags! {
#[repr(C)]
    pub struct Error: u32 {
        const ASM_X86_INVALIDOPERAND = 512;
        const ASM_X86_MISSINGFEATURE = 513;
        const ASM_X86_MNEMONICFAIL = 514;
    }
}
