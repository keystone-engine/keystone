{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.CPU.Msp430
Description : Definitions for the Msp430 architecture.
Copyright   : (C) Trey Keown, 2018
License     : GPL-2

Definitions for the Msp430 architecture.
-}
module Keystone.CPU.Msp430
    (
      Error(..)
    ) where

{# context lib = "keystone" #}

#include <keystone/msp430.h>

-- | Msp430 errors.
{# enum ks_err_asm_msp430 as Error
   { underscoreToCase }
   with prefix = "KS_ERR_ASM_MSP430_"
   deriving (Show, Eq, Bounded)
#}
