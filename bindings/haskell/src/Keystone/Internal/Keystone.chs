{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Keystone.Internal.Keystone
Description : The Keystone assembler engine.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Low-level bindings for the Keystone assembler engine.

This module should not be directly imported; it is only exposed because of the
way cabal handles ordering of chs files.
-}
module Keystone.Internal.Keystone
    ( -- * Types
      Architecture(..)
    , Mode(..)
    , OptionType(..)
    , OptionValue(..)

      -- * Function bindings
    , ksOpen
    , ksOption
    , ksFree
    , ksAsm
    , ksVersion
    , ksErrno
    , ksStrerror
    ) where

import Foreign
import Foreign.C

import Keystone.Internal.Util

{# import Keystone.Internal.Core #}

{# context lib = "keystone" #}

#include <keystone/keystone.h>

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

-- | CPU architecture.
{# enum ks_arch as Architecture
   { underscoreToCase }
   with prefix = "KS_"
   deriving (Show, Eq, Bounded)
#}

-- | CPU hardware mode.
{# enum ks_mode as Mode
   { underscoreToCase }
   with prefix = "KS_"
   deriving (Show, Eq, Bounded)
#}

-- | Runtime option types.
{# enum ks_opt_type as OptionType
   { underscoreToCase }
   with prefix = "KS_"
   deriving (Show, Eq, Bounded)
#}

-- | Runtime option values.
{# enum ks_opt_value as OptionValue
   { underscoreToCase }
   with prefix = "KS_OPT_"
   deriving (Show, Eq, Bounded)
#}

-------------------------------------------------------------------------------
-- Assembler control
-------------------------------------------------------------------------------

{# fun ks_open as ^
   { `Architecture'
   , combineEnums `[Mode]'
   , alloca- `EnginePtr' peek*
   } -> `Error'
#}

{# fun ks_option as ^
   { `Engine'
   , `OptionType'
   , `OptionValue'
   } -> `Error'
#}

{# fun ks_asm as ^
   { `Engine'
   ,  `String'
   ,  `Word64'
   ,  alloca- `Ptr CUChar' peek*
   ,  alloca- `Int' peekToInt*
   ,  alloca- `Int' peekToInt*
   } -> `Int'
#}

{# fun ks_free as ^
   { castPtr `Ptr CUChar'
   } -> `()'
#}

-------------------------------------------------------------------------------
-- Misc.
-------------------------------------------------------------------------------

{# fun pure unsafe ks_version as ^
   { id `Ptr CUInt'
   , id `Ptr CUInt'
   } -> `Int'
#}

{# fun unsafe ks_errno as ^
   { `Engine'
   } -> `Error'
#}

{# fun pure unsafe ks_strerror as ^
   { `Error'
   } -> `String'
#}

-------------------------------------------------------------------------------
-- Helper functions
-------------------------------------------------------------------------------

peekToInt :: (Storable a, Integral a, Num b)
          => Ptr a
          -> IO b
peekToInt ptr =
    peek ptr >>= (return . fromIntegral)
