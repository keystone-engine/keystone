use libc;
use std::os::raw::c_char;
use enums::{Arch, Mode, Error};

use {ks_handle};

#[link(name = "keystone")]
extern "C" {
    pub fn ks_version(major: *const u32, minor: *const u32) -> u32;
    pub fn ks_arch_supported(arch: Arch) -> bool;
    pub fn ks_open(arch: Arch, mode: Mode, engine: *mut ks_handle) -> Error;
    pub fn ks_asm(engine: ks_handle, string: *const c_char, address: u64, encoding:*mut *mut libc::c_uchar, encoding_size: *mut libc::size_t, stat_count: *mut libc::size_t ) -> Error;
    pub fn ks_errno(engine: ks_handle) -> Error;
    pub fn ks_strerror(error_code: Error) -> *const c_char;
    pub fn ks_option(engine: ks_handle, type_: u32, value: libc::size_t) -> Error;
    pub fn ks_close(engine: ks_handle);
    pub fn ks_free(encoding: *mut libc::c_uchar);
}
