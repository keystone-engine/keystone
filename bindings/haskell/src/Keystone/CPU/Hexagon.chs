{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.CPU.Hexagon
Description : Definitions for the Hexagon architecture.
Copyright   : (C) Adrian Herrera, 2016
License     : GPL-2

Definitions for the Hexagon architecture.
-}
module Keystone.CPU.Hexagon
    (
      Error(..)
    ) where

{# context lib = "keystone" #}

#include <keystone/hexagon.h>

-- | Hexagon errors.
{# enum ks_err_asm_hexagon as Error
   { underscoreToCase }
   with prefix = "KS_ERR_ASM_HEXAGON_"
   deriving (Show, Eq, Bounded)
#}
