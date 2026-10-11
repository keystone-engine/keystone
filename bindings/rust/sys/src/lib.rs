#![no_std]
#![expect(
   clippy::pub_use,
   reason = "this crate exists to expose the generated bindings"
)]

use core::{
   error::Error,
   ffi::CStr,
   fmt::{
      self,
      Display,
      Formatter,
   },
};

/// Items `bindgen` generates from `keystone.h` into `$OUT_DIR` at build time.
#[cfg_attr(
   not(test),
   expect(clippy::missing_docs_in_private_items, reason = "bindgen output")
)]
#[expect(
   non_upper_case_globals,
   clippy::absolute_paths,
   clippy::multiple_inherent_impl,
   clippy::renamed_function_params,
   clippy::use_self,
   reason = "bindgen output"
)]
#[expect(
   clippy::inline_modules,
   reason = "the module only wraps the generated include"
)]
mod bindings {
   include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*;

impl KsErr {
   /// Calls `op` if the result is Ok, otherwise returns the [`Err`] value of
   /// `self`.
   ///
   /// # Errors
   ///
   /// Returns `self` when it is not [`KsErr::Ok`], otherwise whatever `op`
   /// returns.
   #[inline]
   pub fn and_then<U, F>(self, op: F) -> Result<U, Self>
   where
      F: FnOnce() -> Result<U, Self>,
   {
      if self == Self::Ok { op() } else { Err(self) }
   }

   /// Generalized `and_then` for any error type that can be created from
   /// `KsErr`.
   ///
   /// # Errors
   ///
   /// Returns `self` converted into `E` when it is not [`KsErr::Ok`],
   /// otherwise whatever `op` returns.
   #[inline]
   pub fn and_then_with<T, E, F>(self, op: F) -> Result<T, E>
   where
      F: FnOnce() -> Result<T, E>,
      E: From<Self>,
   {
      if self == Self::Ok {
         op()
      } else {
         Err(self.into())
      }
   }

   /// Returns `res` if the result is Ok, otherwise returns the [`Err`] value of
   /// `self`. Arguments passed to this are eagerly evaluated; if you are
   /// passing the result of a function call, it is recommended to use
   /// [`KsErr::and_then`] instead, as it's lazily evaluated.
   ///
   /// # Errors
   ///
   /// Returns `self` when it is not [`KsErr::Ok`], otherwise `res`.
   #[inline]
   pub fn and<U>(self, res: Result<U, Self>) -> Result<U, Self> {
      if self == Self::Ok { res } else { Err(self) }
   }
}

impl From<KsErr> for Result<(), KsErr> {
   #[inline]
   fn from(value: KsErr) -> Self {
      if value == KsErr::Ok {
         Ok(())
      } else {
         Err(value)
      }
   }
}

impl ArchVariant {
   /// Returns `true` when every flag bit set in `other` is also set in
   /// `self`. Convenient for testing combinations after `|`-ing
   /// variants together (e.g. `(v & MASK).contains(EXPECTED)`).
   #[inline]
   #[must_use = "the containment check has no side effects"]
   pub const fn contains(self, other: Self) -> bool {
      (self.0 & other.0) == other.0
   }

   /// Returns `true` when no flag bits are set.
   #[inline]
   #[must_use = "the emptiness check has no side effects"]
   pub const fn is_empty(self) -> bool {
      self.0 == 0
   }
}

impl Display for KsErr {
   #[inline]
   fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
      // SAFETY: `ks_strerror` accepts every `ks_err` value.
      let ptr = unsafe { ks_strerror(*self) };
      // SAFETY: `ks_strerror` returns a static NUL-terminated string.
      let raw = unsafe { CStr::from_ptr(ptr) };
      let Ok(message) = raw.to_str() else {
         return Err(fmt::Error);
      };
      f.write_str(message)
   }
}

impl Error for KsErr {}
