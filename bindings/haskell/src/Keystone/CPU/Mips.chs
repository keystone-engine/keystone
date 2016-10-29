{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.CPU.Mips
Description : Definitions for the MIPS architecture.
Copyright   : (C) Adrian Herrera, 2016
License     : GPL-2

Definitions for the MIPS architecture.
-}
module Keystone.CPU.Mips
    (
      Error(..)
    ) where

{# context lib = "keystone" #}

#include <keystone/mips.h>

-- | MIPS errors.
{# enum ks_err_asm_mips as Error
   { underscoreToCase }
   with prefix = "KS_ERR_ASM_MIPS_"
   deriving (Show, Eq, Bounded)
#}
