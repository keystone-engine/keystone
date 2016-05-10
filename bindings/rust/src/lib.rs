//! Bindings for the Keystone Engine.
//!
//! ```rust
//! extern crate keystone;
//! use keystone::{Keystone, Arch, Mode, Error, OptionType, OptionValue};
//!
//! fn main() {
//!     let engine = Keystone::new(Arch::X86, Mode::Mode32)
//!         .expect("Could not initialize Keystone engine");
//!     engine.option(OptionType::Syntax, OptionValue::SyntaxNASM)
//!         .expect("Could not set option to nasm syntax");
//!     let result = engine.asm("mov ah, 0x80".to_string(), 0)
//!         .expect("Could not assemble");
//! }
//! ```

extern crate libc;

pub mod ffi;
pub mod enums;
pub mod keystone_const;
pub mod arm64_const;
pub mod arm_const;
pub mod hexagon_const;
pub mod mips_const;
pub mod ppc_const;
pub mod sparc_const;
pub mod systemz_const;
pub mod x86_const;

use std::ffi::CStr;
use std::ffi::CString;

pub use enums::*;

#[allow(non_camel_case_types)]
pub type ks_handle = libc::size_t;

impl Error {
    pub fn msg(&self) -> String {
        error_msg(*self)
    }
}

#[derive(Debug, PartialEq)]
pub struct AsmResult {
    pub size: u32,
    pub stat_count: u32,
    pub bytes: Vec<u8>,
}

impl AsmResult {
}

pub fn bindings_version() -> (u32, u32) {
    (KS_API_MAJOR, KS_API_MINOR)
}

/// Return tuple `(major, minor)` API version numbers.
pub fn version() -> (u32, u32) {
    let mut major: u32 = 0;
    let mut minor: u32 = 0;

    unsafe {
        ffi::ks_version(&mut major, &mut minor);
    }
    (major, minor)
}

/// Return tuple `(major, minor)` API version numbers.
pub fn arch_supported(arch: Arch) -> bool {
    unsafe { ffi::ks_arch_supported(arch) }
}

/// Return a string describing given error code.
pub fn error_msg(error: Error) -> String {
    unsafe { CStr::from_ptr(ffi::ks_strerror(error)).to_string_lossy().into_owned() }
}

pub struct Keystone {
    handle: ks_handle, 
}

impl Keystone {
    /// Create new instance of Keystone engine.
    pub fn new(arch: Arch, mode: Mode) -> Result<Keystone, Error> {
        if version() != bindings_version() {
            return Err(Error::Version);
        }

        let mut handle: ks_handle = 0;

        let err = unsafe { ffi::ks_open(arch, mode, &mut handle) };
        if err == Error::Ok {
            Ok(Keystone { handle: handle })
        } else {
            Err(err)
        }
    }

    /// Report the last error number when some API function fail.
    pub fn error(&self) -> Result<(), Error> {
        let err = unsafe { ffi::ks_errno(self.handle) };
        if err == Error::Ok {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Set option for Keystone engine at runtime
    pub fn option(&self, type_: OptionType, value: OptionValue) -> Result<(), Error> {
        let err = unsafe { ffi::ks_option(self.handle, type_ as u32, value as libc::size_t) };
        if err == Error::Ok {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Assemble a string given its the buffer, size, start address and number
    /// of instructions to be decoded.
    /// 
    /// This API dynamically allocate memory to contain assembled instruction.
    /// Resulted array of bytes containing the machine code  is put into @*encoding
    pub fn asm(&self, str: String, address: u64) -> Result<AsmResult, Error> {
        let mut size: libc::size_t = 0;
        let mut stat_count: libc::size_t = 0;

        let s = CString::new(str).unwrap();
        let mut ptr: *mut libc::c_uchar = std::ptr::null_mut();

        let err = unsafe { ffi::ks_asm(self.handle, s.as_ptr(), address, &mut ptr, &mut size, &mut stat_count) };

        if err == Error::Ok {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, size) };

            unsafe{ 
                ffi::ks_free(ptr);
            };

            Ok( AsmResult {
                size: size as u32,
                stat_count: stat_count as u32,
                bytes: From::from(&bytes[..]),
            })
        } else {
            Err(unsafe { ffi::ks_errno(self.handle) })
        }
    }
}

impl Drop for Keystone {
    fn drop(&mut self) {
        unsafe { ffi::ks_close(self.handle) };
    }
}
