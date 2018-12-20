#![allow(non_camel_case_types)]
// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [systemz_const.rs]
use libc;
bitflags! {
#[repr(C)]
    pub struct Error: u32 {
        const ASM_SYSTEMZ_INVALIDOPERAND = 512;
        const ASM_SYSTEMZ_MISSINGFEATURE = 513;
        const ASM_SYSTEMZ_MNEMONICFAIL = 514;
    }
}
