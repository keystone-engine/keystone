// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [keystone_const.rs]
extern crate libc;


pub const KS_API_MAJOR : u32 = 0;
pub const KS_API_MINOR : u32 = 9;
pub const KS_ARCH_ARM : u32 = 1;
pub const KS_ARCH_ARM64 : u32 = 2;
pub const KS_ARCH_MIPS : u32 = 3;
pub const KS_ARCH_X86 : u32 = 4;
pub const KS_ARCH_PPC : u32 = 5;
pub const KS_ARCH_SPARC : u32 = 6;
pub const KS_ARCH_SYSTEMZ : u32 = 7;
pub const KS_ARCH_HEXAGON : u32 = 8;
pub const KS_ARCH_MAX : u32 = 9;


bitflags! {
	pub flags Mode : u32 {
		const MODE_LITTLE_ENDIAN = 0,
		const MODE_BIG_ENDIAN = 1073741824,
		const MODE_ARM = 1,
		const MODE_THUMB = 16,
		const MODE_V8 = 64,
		const MODE_MICRO = 16,
		const MODE_MIPS3 = 32,
		const MODE_MIPS32R6 = 64,
		const MODE_MIPS32 = 4,
		const MODE_MIPS64 = 8,
		const MODE_16 = 2,
		const MODE_32 = 4,
		const MODE_64 = 8,
		const MODE_PPC32 = 4,
		const MODE_PPC64 = 8,
		const MODE_QPX = 16,
		const MODE_SPARC32 = 4,
		const MODE_SPARC64 = 8,
		const MODE_V9 = 16,
	}
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Arch {
	ARM,
	ARM64,
	MIPS,
	X86,
	PPC,
	SPARC,
	SYSTEMZ,
	HEXAGON,
	MAX,
}


impl Arch {
	#[inline]
	pub fn val(&self) -> u32 {
		match *self {
			Arch::ARM => 1,
			Arch::ARM64 => 2,
			Arch::MIPS => 3,
			Arch::X86 => 4,
			Arch::PPC => 5,
			Arch::SPARC => 6,
			Arch::SYSTEMZ => 7,
			Arch::HEXAGON => 8,
			Arch::MAX => 9,
		}
	}
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OptionType {
	SYNTAX,
	MAX,
}

impl OptionType {
	#[inline]
	pub fn val(&self) -> u32 {
		match *self {
			OptionType::SYNTAX => 1,
			OptionType::MAX => 99
		}
	}
}

bitflags! {
	pub flags OptionValue : libc::size_t {
		const OPT_SYM_RESOLVER = 2,
		const OPT_SYNTAX_INTEL = 1,
		const OPT_SYNTAX_ATT = 2,
		const OPT_SYNTAX_NASM = 4,
		const OPT_SYNTAX_MASM = 8,
		const OPT_SYNTAX_GAS = 16,
		const OPT_SYNTAX_RADIX16 = 32,
	}
}

bitflags! {
	pub flags Error : u32 {
		const ERR_ASM = 128,
		const ERR_ASM_ARCH = 512,
		const ERR_OK = 0,
		const ERR_NOMEM = 1,
		const ERR_ARCH = 2,
		const ERR_HANDLE = 3,
		const ERR_MODE = 4,
		const ERR_VERSION = 5,
		const ERR_OPT_INVALID = 6,
		const ERR_ASM_EXPR_TOKEN = 128,
		const ERR_ASM_DIRECTIVE_VALUE_RANGE = 129,
		const ERR_ASM_DIRECTIVE_ID = 130,
		const ERR_ASM_DIRECTIVE_TOKEN = 131,
		const ERR_ASM_DIRECTIVE_STR = 132,
		const ERR_ASM_DIRECTIVE_COMMA = 133,
		const ERR_ASM_DIRECTIVE_RELOC_NAME = 134,
		const ERR_ASM_DIRECTIVE_RELOC_TOKEN = 135,
		const ERR_ASM_DIRECTIVE_FPOINT = 136,
		const ERR_ASM_DIRECTIVE_UNKNOWN = 137,
		const ERR_ASM_DIRECTIVE_EQU = 138,
		const ERR_ASM_DIRECTIVE_INVALID = 139,
		const ERR_ASM_VARIANT_INVALID = 140,
		const ERR_ASM_EXPR_BRACKET = 141,
		const ERR_ASM_SYMBOL_MODIFIER = 142,
		const ERR_ASM_SYMBOL_REDEFINED = 143,
		const ERR_ASM_SYMBOL_MISSING = 144,
		const ERR_ASM_RPAREN = 145,
		const ERR_ASM_STAT_TOKEN = 146,
		const ERR_ASM_UNSUPPORTED = 147,
		const ERR_ASM_MACRO_TOKEN = 148,
		const ERR_ASM_MACRO_PAREN = 149,
		const ERR_ASM_MACRO_EQU = 150,
		const ERR_ASM_MACRO_ARGS = 151,
		const ERR_ASM_MACRO_LEVELS_EXCEED = 152,
		const ERR_ASM_MACRO_STR = 153,
		const ERR_ASM_MACRO_INVALID = 154,
		const ERR_ASM_ESC_BACKSLASH = 155,
		const ERR_ASM_ESC_OCTAL = 156,
		const ERR_ASM_ESC_SEQUENCE = 157,
		const ERR_ASM_ESC_STR = 158,
		const ERR_ASM_TOKEN_INVALID = 159,
		const ERR_ASM_INSN_UNSUPPORTED = 160,
		const ERR_ASM_FIXUP_INVALID = 161,
		const ERR_ASM_LABEL_INVALID = 162,
		const ERR_ASM_FRAGMENT_INVALID = 163,
		const ERR_ASM_INVALIDOPERAND = 512,
		const ERR_ASM_MISSINGFEATURE = 513,
		const ERR_ASM_MNEMONICFAIL = 514,
	}
}

