{-|
Module      : Keystone.Internal.Util
Description : Utility (aka helper) functions for the Keystone assembler.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2
-}
module Keystone.Internal.Util where

import Data.Bits
import Foreign

-- | Combine a list of Enums by performing a bitwise-OR.
combineEnums :: (Enum a, Num b, Bits b) => [a] -> b
combineEnums =
    foldr ((.|.) <$> enumToNum) 0

-- | Cast a pointer and then peek inside it.
castPtrAndPeek :: Storable a => Ptr b -> IO a
castPtrAndPeek =
    peek . castPtr

-- | Convert an 'Eum' to a 'Num'.
enumToNum :: (Enum a, Num b) => a -> b
enumToNum =
    fromIntegral . fromEnum
