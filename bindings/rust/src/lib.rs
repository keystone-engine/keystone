//! Keystone Assembler Engine (www.keystone-engine.org) \
//! By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 \
//! By Amaan Qureshi <git@amaanq.com>, 2025.
//!
//! ```rust
//! use keystone_engine::{
//!    Arch,
//!    Keystone,
//!    X86Syntax,
//! };
//!
//! let mut engine = Keystone::new(Arch::X86).expect("Could not initialize Keystone engine");
//! engine
//!    .set_x86_syntax(X86Syntax::NASM)
//!    .expect("Could not set option to nasm syntax");
//! let asm = engine.asm("mov ah, 0x80", 0).expect("Could not assemble");
//! assert_eq!(asm.bytes, vec![0xB4, 0x80]);
//! assert_eq!(asm.len(), 2);
//! ```

#![no_std]
#![expect(
   clippy::pub_use,
   reason = "the safe API is built on the generated enums"
)]

extern crate alloc;

use alloc::{
   boxed::Box,
   ffi::CString,
   string::String,
   vec::Vec,
};
use core::{
   error,
   ffi::{
      CStr,
      c_char,
      c_void,
   },
   fmt,
   mem,
   ptr,
   result,
   slice,
};

pub use keystone_engine_sys::*;

#[cfg(test)] mod tests;

/// Get the Keystone API version.
///
/// Returns a tuple of the major and minor version numbers.
#[inline]
#[must_use = "the version is only returned, not recorded"]
pub fn version() -> (u32, u32) {
   let mut major: u32 = 0;
   let mut minor: u32 = 0;

   // SAFETY: both out-pointers are valid for writes for the whole call.
   unsafe { ks_version(&raw mut major, &raw mut minor) };
   (major, minor)
}

/// Check if the given architecture is supported.
#[inline]
#[must_use = "the support check has no side effects"]
pub fn arch_supported(arch: Arch) -> bool {
   // SAFETY: `ks_arch_supported` only inspects its by-value argument.
   unsafe { ks_arch_supported(arch) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Assembly {
   pub bytes:      Vec<u8>,
   pub stat_count: usize,
}

impl Assembly {
   /// Number of bytes in the assembled output.
   #[inline]
   #[must_use = "the length has no side effects"]
   pub fn len(&self) -> usize {
      self.bytes.len()
   }

   /// Whether the assembled output is empty.
   #[inline]
   #[must_use = "the emptiness check has no side effects"]
   pub fn is_empty(&self) -> bool {
      self.bytes.is_empty()
   }
}

impl AsRef<[u8]> for Assembly {
   #[inline]
   fn as_ref(&self) -> &[u8] {
      &self.bytes
   }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorLocation {
   pub line:          u64,
   pub column:        u64,
   pub error_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
   /// The engine's error code.
   code:      KsErr,
   /// Source locations, empty when the engine reported none.
   locations: Vec<ErrorLocation>,
}

impl Error {
   /// Get the underlying keystone error code.
   #[inline]
   #[must_use = "the error code has no side effects"]
   pub const fn code(&self) -> KsErr {
      self.code
   }

   /// Get assembly error locations if available.
   #[inline]
   #[must_use = "the locations have no side effects"]
   pub fn locations(&self) -> Option<&[ErrorLocation]> {
      (!self.locations.is_empty()).then_some(self.locations.as_slice())
   }

   /// Create a basic error from a keystone error code.
   #[inline]
   #[must_use = "constructing an error has no side effects"]
   pub const fn keystone(code: KsErr) -> Self {
      Self {
         code,
         locations: Vec::new(),
      }
   }

   /// Create a rich assembly error with locations.
   #[inline]
   #[must_use = "constructing an error has no side effects"]
   pub const fn detailed(code: KsErr, locations: Vec<ErrorLocation>) -> Self {
      Self { code, locations }
   }
}

impl fmt::Display for Error {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      if self.locations.is_empty() {
         return write!(f, "{}", self.code);
      }

      writeln!(f, "Keystone error: {}", self.code)?;
      for (index, location) in self.locations.iter().enumerate() {
         if index > 0 {
            writeln!(f)?;
         }
         write!(
            f,
            "at line {}, column {}: {}",
            location.line, location.column, location.error_message
         )?;
      }
      Ok(())
   }
}

impl error::Error for Error {}

impl From<KsErr> for Error {
   #[inline]
   fn from(err: KsErr) -> Self {
      Self::keystone(err)
   }
}

pub type Result<T> = result::Result<T, Error>;

impl fmt::Display for Assembly {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      for &byte in &self.bytes {
         f.write_fmt(format_args!("{byte:02x}"))?;
      }

      Ok(())
   }
}

/// Boxed resolver closure owned by the engine.
type ResolverBox = Box<dyn FnMut(&str, &mut u64) -> bool + Send + 'static>;

/// Converts a C string the engine owns into an owned Rust string.
///
/// # Safety
///
/// `ptr` must point to a NUL-terminated string that stays valid for the call.
unsafe fn owned_string(ptr: *const c_char) -> String {
   // SAFETY: guaranteed by the caller.
   unsafe { CStr::from_ptr(ptr) }
      .to_string_lossy()
      .into_owned()
}

/// The Keystone engine.
///
/// `Send` and `Sync`. Mutation (`asm`, `set_*`) requires `&mut self`, so
/// the borrow checker keeps a single thread in any mutating call at a
/// time; multiple threads may share `&Keystone` to read configuration.
pub struct Keystone {
   /// Engine created by `ks_new` and released only in `Drop`.
   handle:   *mut ks_engine,
   /// `Box::into_raw`ed `Box<ResolverBox>`. The double box collapses
   /// the fat-pointer closure to a thin, heap-stable address for the C
   /// `void*` payload that survives moves of `Keystone`.
   resolver: *mut ResolverBox,
}

// SAFETY: ks_engine and the resolver box are heap-allocated and don't
// pin to a thread; the C side performs no TLS lookups. The resolver
// bound forces `Send` captures.
unsafe impl Send for Keystone {}
// SAFETY: mutation requires `&mut self`, so the borrow checker prevents
// the only races that would matter for `Sync`.
unsafe impl Sync for Keystone {}

impl Keystone {
   /// Create a new engine for the given architecture.
   ///
   /// # Errors
   ///
   /// Returns the engine's error when `arch` is not compiled in or the
   /// engine cannot be created.
   #[inline]
   pub fn new(arch: Arch) -> Result<Self> {
      let mut handle = ptr::null_mut();
      // SAFETY: `handle` is a valid out-pointer for the new engine.
      unsafe { ks_new(&raw mut handle, arch) }.and_then_with(|| {
         Ok(Self {
            handle,
            resolver: ptr::null_mut(),
         })
      })
   }

   /// Whether the given architecture was compiled into this build.
   #[inline]
   #[must_use = "the support check has no side effects"]
   pub fn supports(arch: Arch) -> bool {
      arch_supported(arch)
   }

   /// `(major, minor)` API version of the underlying C library.
   #[inline]
   #[must_use = "the version is only returned, not recorded"]
   pub fn version() -> (u32, u32) {
      version()
   }

   /// Get the architecture.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub fn arch(&self) -> Arch {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_get_arch(self.handle) }
   }

   /// Switch the architecture. Resets endian, width, syntax, variant,
   /// features, CPU, symbol resolver, and error state to the new arch's
   /// defaults; downstream LLVM objects are rebuilt on the next
   /// [`asm`](Self::asm) call. The owned resolver `Box` is reclaimed.
   ///
   /// # Errors
   ///
   /// Returns the engine's error when `arch` is not compiled in.
   #[inline]
   pub fn set_arch(&mut self, arch: Arch) -> Result<()> {
      // SAFETY: `self.handle` is a live engine.
      let rc = unsafe { ks_set_arch(self.handle, arch) };
      if rc == KsErr::Ok && !self.resolver.is_null() {
         // SAFETY: `ks_set_arch` dropped the engine's reference to the
         // resolver, and the pointer came from `Box::into_raw`.
         drop(unsafe { Box::from_raw(self.resolver) });
         self.resolver = ptr::null_mut();
      }
      rc.and_then_with(|| Ok(()))
   }

   /// Get the endianness.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub fn endian(&self) -> Endian {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_get_endian(self.handle) }
   }

   /// Set the endianness.
   ///
   /// # Errors
   ///
   /// Returns the engine's error when the architecture rejects `endian`.
   #[inline]
   pub fn set_endian(&mut self, endian: Endian) -> Result<()> {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_set_endian(self.handle, endian) }.and_then_with(|| Ok(()))
   }

   /// Get the CPU bit width.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub fn width(&self) -> Width {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_get_width(self.handle) }
   }

   /// Set the CPU bit width.
   ///
   /// # Errors
   ///
   /// Returns the engine's error when the architecture rejects `width`.
   #[inline]
   pub fn set_width(&mut self, width: Width) -> Result<()> {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_set_width(self.handle, width) }.and_then_with(|| Ok(()))
   }

   /// Get the architecture variant.
   #[inline]
   #[must_use = "the getter has no side effects"]
   #[expect(
      clippy::as_conversions,
      clippy::cast_sign_loss,
      reason = "the C API returns the non-negative variant bitmask as an int"
   )]
   pub fn arch_variant(&self) -> ArchVariant {
      // SAFETY: `self.handle` is a live engine.
      let variant = unsafe { ks_get_arch_variant(self.handle) };
      ArchVariant(variant as u32)
   }

   /// Set the architecture variant.
   ///
   /// # Errors
   ///
   /// Returns [`KsErr::OptInvalid`] when `variant` does not fit the C API's
   /// `int`, otherwise the engine's error when the architecture rejects it.
   #[inline]
   pub fn set_arch_variant(&mut self, variant: ArchVariant) -> Result<()> {
      let Ok(raw) = i32::try_from(variant.0) else {
         return Err(KsErr::OptInvalid.into());
      };
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_set_arch_variant(self.handle, raw) }.and_then_with(|| Ok(()))
   }

   /// Get the x86 syntax.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub fn x86_syntax(&self) -> X86Syntax {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_get_x86_syntax(self.handle) }
   }

   /// Set the X86 syntax.
   ///
   /// # Errors
   ///
   /// Returns the engine's error when the architecture is not x86.
   #[inline]
   pub fn set_x86_syntax(&mut self, syntax: X86Syntax) -> Result<()> {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_set_x86_syntax(self.handle, syntax) }.and_then_with(|| Ok(()))
   }

   /// Get the radix.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub fn radix(&self) -> Radix {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_get_radix(self.handle) }
   }

   /// Set the radix of unprefixed integer literals. `0x` and `0b` prefixes
   /// still apply.
   ///
   /// # Errors
   ///
   /// Returns the engine's error when it rejects `radix`.
   #[inline]
   pub fn set_radix(&mut self, radix: Radix) -> Result<()> {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_set_radix(self.handle, radix) }.and_then_with(|| Ok(()))
   }

   /// Get the ARM Implicit IT (If-Then) mode.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub fn arm_it_mode(&self) -> ArmItMode {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_get_arm_it_mode(self.handle) }
   }

   /// Set the ARM Implicit IT (If-Then) mode.
   ///
   /// # Errors
   ///
   /// Returns the engine's error when the architecture is not ARM.
   #[inline]
   pub fn set_arm_it_mode(&mut self, mode: ArmItMode) -> Result<()> {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_set_arm_it_mode(self.handle, mode) }.and_then_with(|| Ok(()))
   }

   /// Get whether or not CSKY compressed instructions are enabled.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub fn csky_compressed(&self) -> bool {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_get_csky_compressed(self.handle) }
   }

   /// Set whether or not CSKY compressed instructions are enabled.
   ///
   /// # Errors
   ///
   /// Returns the engine's error when the architecture is not CSKY.
   #[inline]
   pub fn set_csky_compressed(&mut self, compressed: bool) -> Result<()> {
      // SAFETY: `self.handle` is a live engine.
      unsafe { ks_set_csky_compressed(self.handle, compressed) }.and_then_with(|| Ok(()))
   }

   /// Get the feature.
   ///
   /// Features can be a single feature or a comma-separated list of features.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub fn feature(&self) -> String {
      // SAFETY: `self.handle` is a live engine.
      let raw = unsafe { ks_get_feature(self.handle) };
      // SAFETY: the engine owns a NUL-terminated string until the next setter
      // call.
      unsafe { owned_string(raw) }
   }

   /// Set the feature.
   ///
   /// Features can be a single feature or a comma-separated list of features.
   /// [`Arch::AArch64`] enables every extension (`all`) until a list replaces
   /// it.
   ///
   /// # Errors
   ///
   /// Returns [`KsErr::Feature`] when `features` contains a NUL byte.
   #[inline]
   pub fn set_feature<S>(&mut self, features: S) -> Result<()>
   where
      S: AsRef<str>,
   {
      let Ok(raw) = CString::new(features.as_ref()) else {
         return Err(KsErr::Feature.into());
      };
      // SAFETY: `self.handle` is a live engine and `raw` outlives the call.
      unsafe { ks_set_feature(self.handle, raw.as_ptr()) }.and_then_with(|| Ok(()))
   }

   /// Get the CPU model.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub fn cpu(&self) -> String {
      // SAFETY: `self.handle` is a live engine.
      let raw = unsafe { ks_get_cpu(self.handle) };
      // SAFETY: the engine owns a NUL-terminated string until the next setter
      // call.
      unsafe { owned_string(raw) }
   }

   /// Set the CPU model.
   ///
   /// # Errors
   ///
   /// Returns [`KsErr::Cpu`] when `cpu` contains a NUL byte.
   #[inline]
   pub fn set_cpu<S>(&mut self, cpu: S) -> Result<()>
   where
      S: AsRef<str>,
   {
      let Ok(raw) = CString::new(cpu.as_ref()) else {
         return Err(KsErr::Cpu.into());
      };
      // SAFETY: `self.handle` is a live engine and `raw` outlives the call.
      unsafe { ks_set_cpu(self.handle, raw.as_ptr()) }.and_then_with(|| Ok(()))
   }

   /// Returns whether a symbol resolver is currently installed.
   #[inline]
   #[must_use = "the getter has no side effects"]
   pub const fn has_symbol_resolver(&self) -> bool {
      !self.resolver.is_null()
   }

   /// Install a symbol resolver. The closure receives each unresolved
   /// symbol's name and a mutable value slot; return `true` after
   /// writing the value, `false` to leave the symbol unresolved. The
   /// engine owns the closure for its lifetime; replacing drops the
   /// previous one. Use [`Self::clear_symbol_resolver`] to remove.
   ///
   /// # Errors
   ///
   /// Returns the engine's error when it rejects the resolver.
   #[inline]
   pub fn set_symbol_resolver<F>(&mut self, callback: F) -> Result<()>
   where
      F: FnMut(&str, &mut u64) -> bool + Send + 'static,
   {
      /// Trampoline the engine calls with the payload installed below.
      unsafe extern "C" fn resolve(
         payload: *mut c_void,
         symbol: *const c_char,
         value: *mut u64,
      ) -> bool {
         // SAFETY: the payload is the `Box<ResolverBox>` installed below,
         // and the engine never calls the resolver concurrently.
         let callback = unsafe { &mut *payload.cast::<ResolverBox>() };
         // SAFETY: the engine passes a NUL-terminated symbol name.
         let Ok(symbol_str) = unsafe { CStr::from_ptr(symbol) }.to_str() else {
            return false;
         };
         // SAFETY: the engine passes either null or a valid value slot.
         let Some(value_ref) = (unsafe { value.as_mut() }) else {
            return false;
         };
         callback(symbol_str, value_ref)
      }

      // Outer Box gives a thin, heap-stable address; inner Box owns
      // the dyn-FnMut fat pointer. The C `void*` payload survives
      // moves of `Keystone`.
      let inner: ResolverBox = Box::new(callback);
      let new_payload = Box::into_raw(Box::new(inner));

      if !self.resolver.is_null() {
         // SAFETY: the old pointer came from `Box::into_raw`, and the engine
         // is re-pointed at the new payload below before it can run again.
         drop(unsafe { Box::from_raw(self.resolver) });
      }
      self.resolver = new_payload;

      let resolver = SymbolResolver {
         payload: new_payload.cast::<c_void>(),
         resolve: Some(resolve),
      };

      // SAFETY: `self.handle` is a live engine, and the payload lives until
      // the resolver is replaced, cleared, or the engine is dropped.
      unsafe { ks_set_symbol_resolver(self.handle, resolver) }.and_then_with(|| Ok(()))
   }

   /// Remove any installed symbol resolver. Undefined symbols then fail
   /// assembly with [`KsErr::AsmMissingSymbol`].
   ///
   /// # Errors
   ///
   /// Returns the engine's error when it rejects the cleared resolver.
   #[inline]
   pub fn clear_symbol_resolver(&mut self) -> Result<()> {
      let cleared = SymbolResolver {
         payload: ptr::null_mut(),
         resolve: None,
      };
      // SAFETY: `self.handle` is a live engine.
      let rc = unsafe { ks_set_symbol_resolver(self.handle, cleared) };
      if !self.resolver.is_null() {
         // SAFETY: the engine no longer references the payload, which came
         // from `Box::into_raw`.
         drop(unsafe { Box::from_raw(self.resolver) });
         self.resolver = ptr::null_mut();
      }
      rc.and_then_with(|| Ok(()))
   }

   /// Assemble a string at the given start address. Errors carry
   /// source-location detail via [`Error::locations`]. An interior NUL
   /// byte in the input returns [`KsErr::AsmSyntax`] rather than
   /// panicking.
   ///
   /// # Errors
   ///
   /// Returns the engine's error, with source locations when it reports
   /// them, when the input fails to assemble.
   #[inline]
   pub fn asm<S>(&mut self, source: S, address: u64) -> Result<Assembly>
   where
      S: Into<Vec<u8>>,
   {
      let Ok(text) = CString::new(source) else {
         return Err(KsErr::AsmSyntax.into());
      };

      // SAFETY: `AsmResult` is a plain C struct for which all-zero is the
      // documented empty state.
      let mut raw: AsmResult = unsafe { mem::zeroed() };
      // SAFETY: `self.handle` is a live engine, `text` outlives the call, and
      // `raw` is a valid out-pointer.
      let code = unsafe { ks_assemble(self.handle, text.as_ptr(), address, &raw mut raw) };

      let result = if code == KsErr::Ok {
         let bytes = if raw.size > 0 && !raw.bytes.is_null() {
            // SAFETY: on success `bytes` points to `size` initialized bytes.
            unsafe { slice::from_raw_parts(raw.bytes, raw.size) }.to_vec()
         } else {
            Vec::new()
         };
         Ok(Assembly {
            bytes,
            stat_count: raw.stat_count,
         })
      } else if raw.error_count > 0 && !raw.errors.is_null() {
         // SAFETY: on failure `errors` points to `error_count` entries.
         let errors_slice = unsafe { slice::from_raw_parts(raw.errors, raw.error_count) };
         let locations = errors_slice
            .iter()
            .map(|entry| {
               ErrorLocation {
                  line:          entry.line_number,
                  column:        entry.column_number,
                  error_message: if entry.error_message.is_null() {
                     String::new()
                  } else {
                     // SAFETY: a non-null message is NUL-terminated and owned
                     // by `raw` until it is freed below.
                     unsafe { owned_string(entry.error_message) }
                  },
               }
            })
            .collect();
         Err(Error::detailed(code, locations))
      } else {
         Err(Error::keystone(code))
      };

      // SAFETY: `raw` was filled by `ks_assemble` and is freed exactly once.
      unsafe { ks_asm_result_free(&raw mut raw) };
      result
   }
}

impl Drop for Keystone {
   #[inline]
   fn drop(&mut self) {
      // Engine first so the trampoline can't fire again, then the box.
      // SAFETY: `self.handle` is a live engine that is never used again.
      unsafe { ks_delete(self.handle) };
      if !self.resolver.is_null() {
         // SAFETY: the engine is gone, and the pointer came from
         // `Box::into_raw`.
         drop(unsafe { Box::from_raw(self.resolver) });
      }
   }
}
