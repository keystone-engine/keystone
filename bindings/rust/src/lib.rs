//! Keystone Assembler Engine (www.keystone-engine.org) \
//! By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 \
//! Rust bindings by Remco Verhoef <remco@dutchcoders.io>, 2016
//!
//! ```rust
//! use keystone::{Keystone, Arch, Mode, OptionType, OptionValue};
//!
//! fn main() {
//!     let engine = Keystone::new(Arch::X86, Mode::MODE_32)
//!         .expect("Could not initialize Keystone engine");
//!     engine.option(OptionType::SYNTAX, OptionValue::SYNTAX_NASM)
//!         .expect("Could not set option to nasm syntax");
//!     let result = engine.asm("mov ah, 0x80".to_string(), 0)
//!         .expect("Could not assemble");
//! }
//! ```

extern crate keystone_sys as ffi;

use std::{convert::TryInto, ffi::CStr, fmt};

pub use crate::ffi::keystone_const::*;
pub use crate::ffi::ks_handle;

#[derive(Debug, PartialEq)]
pub struct AsmResult {
    pub stat_count: u32,
    size: u32,
    ptr: *mut libc::c_uchar,
}

impl AsmResult {
    pub fn as_bytes(&self) -> &[u8] {
        let bytes = unsafe { core::slice::from_raw_parts(self.ptr, self.size as _) };
        bytes
    }
}

impl Drop for AsmResult {
    fn drop(&mut self) {
        unsafe {
            ffi::ks_free(self.ptr);
        };
    }
}

impl fmt::Display for AsmResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.as_bytes() {
            f.write_fmt(format_args!("{:02x}", byte))?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum AsmError {
    NullPtr,
    SizeOverflow,
    Raw(Error),
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            Self::NullPtr => "got NULL ptr in allocation",
            Self::SizeOverflow => "u32 bigger than size_t",
            Self::Raw(err) => return fmt::Display::fmt(err, f),
        };
        f.write_str(msg)
    }
}

pub fn bindings_version() -> (u32, u32) {
    (API_MAJOR, API_MINOR)
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
    unsafe { ffi::ks_arch_supported(arch) != 0 }
}

pub fn error_msg(error: Error) -> String {
    unsafe {
        CStr::from_ptr(ffi::ks_strerror(error))
            .to_string_lossy()
            .into_owned()
    }
}

pub struct Keystone {
    handle: ks_handle,
}

impl Keystone {
    /// Create new instance of Keystone engine.
    pub fn new(arch: Arch, mode: Mode) -> Result<Keystone, Error> {
        if version() != bindings_version() {
            return Err(Error::VERSION);
        }

        let mut handle: Option<ks_handle> = None;

        let err = unsafe { ffi::ks_open(arch, mode, &mut handle) };
        if err == Error::OK {
            Ok(Keystone {
                // fixme: return err
                handle: handle.expect("Got NULL engine from ks_open()"),
            })
        } else {
            Err(err)
        }
    }

    /// Report the last error number when some API function fail.
    pub fn error(&self) -> Option<Error> {
        let err = unsafe { ffi::ks_errno(self.handle) };
        if err == Error::OK {
            None
        } else {
            Some(err)
        }
    }

    /// Set option for Keystone engine at runtime
    pub fn option(&self, option_type: OptionType, value: OptionValue) -> Result<(), Error> {
        let err = unsafe { ffi::ks_option(self.handle, option_type, value) };
        if err == Error::OK {
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
    pub fn asm(&self, str: &CStr, address: u64) -> Result<AsmResult, AsmError> {
        let mut size: libc::size_t = 0;
        let mut stat_count: libc::size_t = 0;

        let mut ptr: *mut libc::c_uchar = std::ptr::null_mut();

        let err = unsafe {
            ffi::ks_asm(
                self.handle,
                str.as_ptr(),
                address,
                &mut ptr,
                &mut size,
                &mut stat_count,
            )
        };

        if err != 0 {
            let err = unsafe { ffi::ks_errno(self.handle) };
            return Err(AsmError::Raw(err));
        }
        if ptr.is_null() {
            return Err(AsmError::NullPtr);
        }

        Ok(AsmResult {
            stat_count: stat_count.try_into().map_err(|_| AsmError::SizeOverflow)?,
            size: size.try_into().map_err(|_| AsmError::SizeOverflow)?,
            ptr,
        })
    }
}

impl Drop for Keystone {
    fn drop(&mut self) {
        unsafe { ffi::ks_close(self.handle) };
    }
}
