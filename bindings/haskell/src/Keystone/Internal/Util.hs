{-|
Module      : Keystone.Internal.Util
Description : Utility (aka helper) functions for the Keystone assembler.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2
-}
module Keystone.Internal.Util where

import Control.Applicative ((<$>))
import Data.Bits

-- | Combine a list of Enums by performing a bitwise-OR.
combineEnums :: (Enum a, Num b, Bits b)
             => [a]
             -> b
combineEnums =
    foldr ((.|.) <$> enumToNum) 0

-- | Convert an 'Eum' to a 'Num'.
enumToNum :: (Enum a, Num b)
          => a
          -> b
enumToNum =
    fromIntegral . fromEnum
