{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.CPU.Sparc
Description : Definitions for the SPARC architecture.
Copyright   : (C) Adrian Herrera, 2016
License     : GPL-2

Definitions for the SPARC architecture.
-}
module Keystone.CPU.Sparc
    (
      Error(..)
    ) where

{# context lib = "keystone" #}

#include <keystone/sparc.h>

-- | SPARC errors.
{# enum ks_err_asm_sparc as Error
   { underscoreToCase }
   with prefix = "KS_ERR_ASM_SPARC_"
   deriving (Show, Eq, Bounded) #}
