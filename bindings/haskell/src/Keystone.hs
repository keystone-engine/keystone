{-|
Module      : Keystone
Description : The Keystone assembler engine.
Copyright   : (c) Adrian Herrera, 2016
License     :  GPL-2

Keystone is a lightweight multi-platform, multi-architecture assembler
framework.

Further information is available at <http://www.keystone-engine.org>.
-}
module Keystone
    ( -- * Assembler control
      Assembler
    , Engine
    , Architecture(..)
    , Mode(..)
    , OptionType(..)
    , OptionValue(..)
    , runAssembler
    , open
    , option
    , assemble

      -- * Error handling
    , Error(..)
    , errno
    , strerror

      -- * Misc.
    , version
    ) where

import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Data.ByteString (ByteString, packCStringLen)
import Data.List (intercalate)
import Foreign

import Keystone.Internal.Core
import Keystone.Internal.Keystone

-------------------------------------------------------------------------------
-- Assembler control
-------------------------------------------------------------------------------

-- | Run the Keystone assembler and return a result on success, or an 'Error'
-- on failure.
runAssembler :: Assembler a         -- ^ The assembler code to execute
             -> IO (Either Error a) -- ^ A result on success, or an 'Error' on
                                    -- failure
runAssembler =
    runExceptT

-- | Create a new instance of the Keystone assembler.
open :: Architecture        -- ^ CPU architecture
     -> [Mode]              -- ^ CPU hardware mode
     -> Assembler Engine    -- ^ A 'Keystone' engine on success, or an 'Error'
                            -- on failure
open arch mode = do
    (err, ksPtr) <- lift $ ksOpen arch mode
    if err == ErrOk then
        -- Return a pointer to the Keystone engine if ksOpen completed
        -- successfully
        lift $ mkEngine ksPtr
    else
        -- Otherwise return an error
        throwE err

option :: Engine        -- ^ 'Keystone' engine handle
       -> OptionType    -- ^ Type of option to set
       -> OptionValue   -- ^ Option value corresponding with the type
       -> Assembler ()  -- ^ An 'Error' on failure
option ks optType optValue = do
    err <- lift $ ksOption ks optType optValue
    if err == ErrOk then
        return ()
    else
        throwE err

-- | Assemble a list of statements.
assemble :: Engine                      -- ^ 'Keystone' engine handle
         -> [String]                    -- ^ List of statements to assemble.
         -> Maybe Word64                -- ^ Optional address of the first
                                        -- assembly instruction
         -> Assembler (ByteString, Int) -- ^ Returns the encoded input assembly
                                        -- string and the number of statements
                                        -- successfully processed. Returns an
                                        -- 'Error' on failure
assemble ks stmts addr = do
    let string = intercalate ";" stmts
    (res, encPtr, encSize, statCount) <- lift $ ksAsm ks string (maybeZ addr)
    if res == 0 then do
        -- If ksAsm completed successfully, pack the encoded bytes into a
        -- ByteString. Once the encoded bytes have been packed the original
        -- encoded bytes can be freed. The ByteString is returned with the
        -- statement count
        bs <- lift $ packCStringLen (castPtr encPtr, encSize)
        lift $ ksFree encPtr
        return (bs, statCount)
    else do
        -- On failure, call errno for error code
        err <- errno ks
        throwE err
    where maybeZ = maybe 0 id

-------------------------------------------------------------------------------
-- Misc.
-------------------------------------------------------------------------------

-- | Combined API version & major and minor version numbers. Returns a
-- hexadecimal number as (major << 8 | minor), which encodes both major and
-- minor versions.
version :: Int
version =
    ksVersion nullPtr nullPtr

-- | Report the 'Error' number when some API function failed.
errno :: Engine             -- ^ 'Keystone' engine handle
      -> Assembler Error    -- ^ The last 'Error' code
errno =
    lift . ksErrno

-- | Return a string describing the given 'Error'.
strerror :: Error   -- ^ The 'Error' code
         -> String  -- ^ Description of the error code
strerror =
    ksStrerror
