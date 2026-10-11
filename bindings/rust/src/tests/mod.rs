extern crate alloc;
extern crate std;

use alloc::{
   borrow::ToOwned as _,
   string::String,
   vec,
   vec::Vec,
};
use std::println;

use asm_error::{
   ErrorAssertion,
   ErrorLocation,
   assert_asm_error,
};
use keystone_engine_sys::{
   Arch,
   ArchVariant,
   ArmItMode,
   Endian,
   KsErr,
   Radix,
   Width,
   X86Syntax,
};

use crate::Keystone;

mod asm_error;
mod harness;

#[cfg(feature = "arch_aarch64")] mod aarch64;
#[cfg(feature = "arch_amdgpu")] mod amdgpu;
#[cfg(feature = "arch_arm")] mod arm;
#[cfg(feature = "arch_avr")] mod avr;
#[cfg(feature = "arch_bpf")] mod bpf;
#[cfg(feature = "arch_csky")] mod csky;
#[cfg(feature = "arch_evm")] mod evm;
#[cfg(feature = "arch_hexagon")] mod hexagon;
#[cfg(feature = "arch_lanai")] mod lanai;
#[cfg(feature = "arch_loongarch")] mod loongarch;
#[cfg(feature = "arch_m68k")] mod m68k;
#[cfg(feature = "arch_mips")] mod mips;
#[cfg(feature = "arch_msp430")] mod msp430;
#[cfg(feature = "arch_ppc")] mod ppc;
#[cfg(feature = "arch_riscv")] mod riscv;
#[cfg(feature = "arch_sparc")] mod sparc;
#[cfg(feature = "arch_systemz")] mod systemz;
#[cfg(feature = "arch_ve")] mod ve;
#[cfg(feature = "arch_wasm")] mod wasm;
#[cfg(feature = "arch_x86")] mod x86;
#[cfg(feature = "arch_xtensa")] mod xtensa;
