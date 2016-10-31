{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.CPU.Ppc
Description : Definitions for the PPC architecture.
Copyright   : (C) Adrian Herrera, 2016
License     : GPL-2

Definitions for the PPC architecture.
-}
module Keystone.CPU.Ppc
    (
      Error(..)
    ) where

{# context lib = "keystone" #}

#include <keystone/ppc.h>

-- | PPC errors.
{# enum ks_err_asm_ppc as Error
   { underscoreToCase }
   with prefix = "KS_ERR_ASM_PPC_"
   deriving (Show, Eq, Bounded)
#}
