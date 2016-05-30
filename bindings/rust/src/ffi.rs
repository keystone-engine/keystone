//! Keystone Assembler Engine (www.keystone-engine.org) */
//! By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
//! Rust bindings by Remco Verhoef <remco@dutchcoders.io>, 2016 */
//!

use libc;
use std::os::raw::c_char;

use ks_handle;

#[link(name = "keystone")]
extern "C" {
    pub fn ks_version(major: *const u32, minor: *const u32) -> u32;
    pub fn ks_arch_supported(arch: u32) -> bool;
    pub fn ks_open(arch: u32, mode: u32, engine: *mut ks_handle) -> u32;
    pub fn ks_asm(engine: ks_handle,
                  string: *const c_char,
                  address: u64,
                  encoding: *mut *mut libc::c_uchar,
                  encoding_size: *mut libc::size_t,
                  stat_count: *mut libc::size_t)
                  -> u32;
    pub fn ks_errno(engine: ks_handle) -> u32;
    pub fn ks_strerror(error_code: u32) -> *const c_char;
    pub fn ks_option(engine: ks_handle, type_: u32, value: libc::size_t) -> u32;
    pub fn ks_close(engine: ks_handle);
    pub fn ks_free(encoding: *mut libc::c_uchar);
}
