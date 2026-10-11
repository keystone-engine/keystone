use alloc::{
   vec,
   vec::Vec,
};

use keystone_engine_sys::KsErr;

use crate::{
   Assembly,
   Error,
};

pub struct ErrorLocation {
   pub point:   (u64, u64),
   pub message: &'static str,
}

pub enum ErrorAssertion {
   Simple(KsErr),
   WithLocations(KsErr, Vec<ErrorLocation>),
}

impl ErrorAssertion {
   pub const fn simple(code: KsErr) -> Self {
      Self::Simple(code)
   }

   pub fn at(code: KsErr, point: (u64, u64), message: &'static str) -> Self {
      Self::WithLocations(code, vec![ErrorLocation { point, message }])
   }

   pub fn with_locations<L>(code: KsErr, locations: L) -> Self
   where
      L: Into<Vec<ErrorLocation>>,
   {
      Self::WithLocations(code, locations.into())
   }
}

pub fn assert_asm_error(result: Result<Assembly, Error>, expected: ErrorAssertion) {
   let error = result.expect_err("Expected an error for invalid assembly");

   let (expected_code, maybe_wanted) = match expected {
      ErrorAssertion::Simple(code) => (code, None),
      ErrorAssertion::WithLocations(code, locs) => (code, Some(locs)),
   };

   assert_eq!(
      error.code(),
      expected_code,
      "Expected error code {expected_code:?}, got {:?}",
      error.code()
   );

   let Some(wanted) = maybe_wanted else {
      return;
   };

   let locations = error
      .locations()
      .expect("Expected locations but found none");

   assert_eq!(
      locations.len(),
      wanted.len(),
      "Expected {} location(s) in error, got {}",
      wanted.len(),
      locations.len()
   );

   for (location, want) in locations.iter().zip(&wanted) {
      let (expected_line, expected_column) = want.point;

      assert_eq!(
         location.line, expected_line,
         "Expected error on line {expected_line}, got {}",
         location.line
      );
      assert_eq!(
         location.column, expected_column,
         "Expected error on column {expected_column}, got {}",
         location.column
      );
      assert_eq!(
         location.error_message, want.message,
         "Expected error message '{}', got '{}'",
         want.message, location.error_message
      );
   }
}
