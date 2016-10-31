{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.CPU.X86
Description : Definitions for the X86 architecture.
Copyright   : (C) Adrian Herrera, 2016
License     : GPL-2

Definitions for the X86 architecture.
-}
module Keystone.CPU.X86
    (
      Error(..)
    ) where

{# context lib = "keystone" #}

#include <keystone/x86.h>

-- | X86 errors.
{# enum ks_err_asm_x86 as Error
   { underscoreToCase }
   with prefix = "KS_ERR_ASM_X86_"
   deriving (Show, Eq, Bounded)
#}
