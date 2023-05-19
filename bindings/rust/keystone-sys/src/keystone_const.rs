#![allow(non_camel_case_types)]
// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [keystone_const.rs]
use ::libc::*;

pub const API_MAJOR: c_uint = 0;
pub const API_MINOR: c_uint = 9;

bitflags! {
#[repr(C)]
    pub struct Mode: c_int {
        const LITTLE_ENDIAN = 0;
        const BIG_ENDIAN = 1073741824;
        const ARM = 1;
        const THUMB = 16;
        const V8 = 64;
        const MICRO = 16;
        const MIPS3 = 32;
        const MIPS32R6 = 64;
        const MIPS32 = 4;
        const MIPS64 = 8;
        const MODE_16 = 2;
        const MODE_32 = 4;
        const MODE_64 = 8;
        const PPC32 = 4;
        const PPC64 = 8;
        const QPX = 16;
        const RISCV32 = 4;
        const RISCV64 = 8;
        const SPARC32 = 4;
        const SPARC64 = 8;
        const V9 = 16;
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Arch {
    ARM = 1,
    ARM64 = 2,
    MIPS = 3,
    X86 = 4,
    PPC = 5,
    SPARC = 6,
    SYSTEMZ = 7,
    HEXAGON = 8,
    EVM = 9,
    RISCV = 10,
    MAX = 11,
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OptionType {
    SYNTAX = 1,
    SYM_RESOLVER = 2,
}

bitflags! {
#[repr(C)]
    pub struct OptionValue: size_t {
        const SYNTAX_INTEL = 1;
        const SYNTAX_ATT = 2;
        const SYNTAX_NASM = 4;
        const SYNTAX_MASM = 8;
        const SYNTAX_GAS = 16;
        const SYNTAX_RADIX16 = 32;
    }
}

bitflags! {
#[repr(C)]
    pub struct Error: c_int {
        const ASM = 128;
        const ASM_ARCH = 512;
        const OK = 0;
        const NOMEM = 1;
        const ARCH = 2;
        const HANDLE = 3;
        const MODE = 4;
        const VERSION = 5;
        const OPT_INVALID = 6;
        const ASM_EXPR_TOKEN = 128;
        const ASM_DIRECTIVE_VALUE_RANGE = 129;
        const ASM_DIRECTIVE_ID = 130;
        const ASM_DIRECTIVE_TOKEN = 131;
        const ASM_DIRECTIVE_STR = 132;
        const ASM_DIRECTIVE_COMMA = 133;
        const ASM_DIRECTIVE_RELOC_NAME = 134;
        const ASM_DIRECTIVE_RELOC_TOKEN = 135;
        const ASM_DIRECTIVE_FPOINT = 136;
        const ASM_DIRECTIVE_UNKNOWN = 137;
        const ASM_DIRECTIVE_EQU = 138;
        const ASM_DIRECTIVE_INVALID = 139;
        const ASM_VARIANT_INVALID = 140;
        const ASM_EXPR_BRACKET = 141;
        const ASM_SYMBOL_MODIFIER = 142;
        const ASM_SYMBOL_REDEFINED = 143;
        const ASM_SYMBOL_MISSING = 144;
        const ASM_RPAREN = 145;
        const ASM_STAT_TOKEN = 146;
        const ASM_UNSUPPORTED = 147;
        const ASM_MACRO_TOKEN = 148;
        const ASM_MACRO_PAREN = 149;
        const ASM_MACRO_EQU = 150;
        const ASM_MACRO_ARGS = 151;
        const ASM_MACRO_LEVELS_EXCEED = 152;
        const ASM_MACRO_STR = 153;
        const ASM_MACRO_INVALID = 154;
        const ASM_ESC_BACKSLASH = 155;
        const ASM_ESC_OCTAL = 156;
        const ASM_ESC_SEQUENCE = 157;
        const ASM_ESC_STR = 158;
        const ASM_TOKEN_INVALID = 159;
        const ASM_INSN_UNSUPPORTED = 160;
        const ASM_FIXUP_INVALID = 161;
        const ASM_LABEL_INVALID = 162;
        const ASM_FRAGMENT_INVALID = 163;
        const ASM_INVALIDOPERAND = 512;
        const ASM_MISSINGFEATURE = 513;
        const ASM_MNEMONICFAIL = 514;
    }
}
