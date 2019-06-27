{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.CPU.SystemZ
Description : Definitions for the SystemZ architecture.
Copyright   : (C) Adrian Herrera, 2016
License     : GPL-2

Definitions for the SystemZ architecture.
-}
module Keystone.CPU.SystemZ
    (
      Error(..)
    ) where

{# context lib = "keystone" #}

#include <keystone/systemz.h>

-- | SystemZ errors.
{# enum ks_err_asm_systemz as Error
   { underscoreToCase }
   with prefix = "KS_ERR_ASM_SYSTEMZ_"
   deriving (Show, Eq, Bounded)
#}
