//! Keystone Assembler Engine (www.keystone-engine.org) */
//! By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
//! Rust bindings by Remco Verhoef <remco@dutchcoders.io>, 2016 */
//!
#![allow(bad_style)]

#[macro_use]
extern crate bitflags;
extern crate libc;

pub mod keystone_const;

use keystone_const::{Arch, Error, Mode, OptionType, OptionValue};
use ::std::{
    ffi::CStr,
    fmt,
    ptr,
};
use ::libc::{
    c_char,
    c_uchar,
    c_int,
    c_uint,
    size_t,
};

/// Opaque type representing the Keystone engine
#[repr(C)]
pub struct ks_engine {
    _private: [u8; 0],
}
pub type ks_handle = ptr::NonNull<ks_engine>;

extern "C" {
    pub fn ks_version(major: *mut c_uint, minor: *mut c_uint) -> c_uint;
    pub fn ks_arch_supported(arch: Arch) -> c_int;
    pub fn ks_open(arch: Arch, mode: Mode, engine: *mut Option<ks_handle>) -> Error;
    pub fn ks_asm(
        engine: ks_handle,
        string: *const c_char,
        address: u64,
        encoding: *mut *mut c_uchar,
        encoding_size: *mut size_t,
        stat_count: *mut size_t,
    ) -> c_int;
    pub fn ks_errno(engine: ks_handle) -> Error;
    pub fn ks_strerror(error_code: Error) -> *const c_char;
    pub fn ks_option(engine: ks_handle, opt_type: OptionType, value: OptionValue) -> Error;
    pub fn ks_close(engine: ks_handle);
    pub fn ks_free(encoding: *mut c_uchar);
}

impl Error {
    pub fn msg(self) -> String {
        error_msg(self)
    }
}

/// Return a string describing given error code.
pub fn error_msg(error: Error) -> String {
    unsafe {
        CStr::from_ptr(ks_strerror(error))
            .to_string_lossy()
            .into_owned()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg())
    }
}
