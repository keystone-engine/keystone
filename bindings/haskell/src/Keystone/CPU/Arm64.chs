{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.CPU.Arm64
Description : Definitions for the ARM64 architecture.
Copyright   : (C) Adrian Herrera, 2016
License     : GPL-2

Definitions for the ARM64 architecture.
-}
module Keystone.CPU.Arm64
    (
      Error(..)
    ) where

{# context lib = "keystone" #}

#include <keystone/arm64.h>

-- | ARM64 errors.
{# enum ks_err_asm_arm64 as Error
   { underscoreToCase }
   with prefix = "KS_ERR_ASM_ARM64_"
   deriving (Show, Eq, Bounded)
#}
