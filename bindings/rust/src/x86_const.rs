// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]

pub const KS_ERR_ASM_X86_INVALIDOPERAND : u32 = 512;
pub const KS_ERR_ASM_X86_MISSINGFEATURE : u32 = 513;
pub const KS_ERR_ASM_X86_MNEMONICFAIL : u32 = 514;


// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Arch {
}


// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]
impl Arch {
	#[inline]
	pub fn val(&self) -> u32 {
		match *self {
		}
	}
}

// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OptionType {
	MAX,
}

// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]
impl OptionType {
	#[inline]
	pub fn val(&self) -> u32 {
		match *self {
			OptionType::MAX => 99
		}
	}
}

// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OptionValue {
}

// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]
impl OptionValue {
	#[inline]
	pub fn val(&self) -> u32 {
		match *self {
		}
	}
}

// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
	ASM_X86_INVALIDOPERAND,
	ASM_X86_MISSINGFEATURE,
	ASM_X86_MNEMONICFAIL,
	UNKNOWN,
}

// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]
impl Error {
	#[inline]
	pub fn from_val(v: u32) -> Error {
		match v {
			512 => Error::ASM_X86_INVALIDOPERAND,
			513 => Error::ASM_X86_MISSINGFEATURE,
			514 => Error::ASM_X86_MNEMONICFAIL,
			_ => Error::UNKNOWN,
		}
	}
}

// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]
impl Error {
	#[inline]
	pub fn to_val(&self) -> u32 {
		match *self {
			Error::ASM_X86_INVALIDOPERAND => 512,
			Error::ASM_X86_MISSINGFEATURE => 513,
			Error::ASM_X86_MNEMONICFAIL => 514,
		}
	}
}

