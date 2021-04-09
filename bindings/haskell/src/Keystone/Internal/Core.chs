{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module
Description : Core Keystone components.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Defines core Keystone components.

This module should not be directly imported; it is only exposed because of the
way cabal handles ordering of chs files.
-}
module Keystone.Internal.Core where

import Control.Monad
import Control.Monad.Trans.Except (ExceptT)
import Foreign

{# context lib = "keystone" #}

#include <keystone/keystone.h>
#include "keystone_wrapper.h"

-- | The Keystone engine.
{# pointer *ks_engine as Engine
   foreign finalizer ks_close_wrapper as close
   newtype
#}

-- | A pointer to the Keystone engine.
{# pointer *ks_engine as EnginePtr -> Engine #}

-- | Make a new Keystone engine out of an engine pointer. The returned Keystone
-- engine will automatically call 'ks_close_wrapper' when it goes out of scope.
mkEngine :: EnginePtr
         -> IO Engine
mkEngine ptr =
    liftM Engine (newForeignPtr close ptr)

-- | Errors encountered by the Keystone API. These values are returned by
-- 'errno'.
{# enum ks_err as Error
   { underscoreToCase }
   with prefix = "KS_"
   deriving (Show, Eq, Bounded)
#}

-- | The assembler runs in the IO monad and allows for the handling of errors
-- "under the hood".
type Assembler a = ExceptT Error IO a
