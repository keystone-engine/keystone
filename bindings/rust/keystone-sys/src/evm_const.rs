#![allow(non_camel_case_types)]
// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [evm_const.rs]
use libc;
bitflags! {
#[repr(C)]
    pub struct Error: u32 {
        const ASM_EVM_INVALIDOPERAND = 512;
        const ASM_EVM_MISSINGFEATURE = 513;
        const ASM_EVM_MNEMONICFAIL = 514;
    }
}
