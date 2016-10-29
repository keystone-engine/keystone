{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.CPU.Arm
Description : Definitions for the ARM architecture.
Copyright   : (C) Adrian Herrera, 2016
License     : GPL-2

Definitions for the ARM architecture.
-}
module Keystone.CPU.Arm
    (
      Error(..)
    ) where

{# context lib = "keystone" #}

#include <keystone/arm.h>

-- | ARM errors.
{# enum ks_err_asm_arm as Error
   { underscoreToCase }
   with prefix = "KS_ERR_ASM_ARM_"
   deriving (Show, Eq, Bounded)
#}
