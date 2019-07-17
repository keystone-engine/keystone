#![allow(non_camel_case_types)]
// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [sparc_const.rs]
use libc;
bitflags! {
#[repr(C)]
    pub struct Error: u32 {
        const ASM_SPARC_INVALIDOPERAND = 512;
        const ASM_SPARC_MISSINGFEATURE = 513;
        const ASM_SPARC_MNEMONICFAIL = 514;
    }
}
