-- Sample code for Keystone Assembler Engine.

import Keystone

import qualified Data.ByteString as BS
import Data.List (intercalate)
import qualified Numeric as N (showHex)

-- Pretty-print byte string as hex.
showHexBS :: BS.ByteString
          -> String
showHexBS =
    concatMap (flip N.showHex " ") . BS.unpack

testKs :: Architecture
       -> [Mode]
       -> [String]
       -> Maybe OptionValue
       -> IO ()
testKs arch mode assembly maybeSyntax = do
    result <- runAssembler $ do
        ks <- open arch mode
        case maybeSyntax of
            Just syntax -> option ks OptSyntax syntax
            Nothing     -> return ()
        (encode, count) <- assemble ks assembly Nothing
        return (encode, count)
    case result of
        Right (encode, count) -> let size = BS.length encode in do
            putStr   $ intercalate ";" assembly ++ " = "
            putStrLn $ showHexBS encode
            putStrLn $ "Assembled: " ++ show size ++ " bytes, " ++
                       show count ++ " statements\n"
        Left err -> putStrLn $ "Failed with error: " ++ show err ++ " (" ++
                               strerror err ++ ")"

main :: IO ()
main = do
    -- X86
    testKs ArchX86 [Mode16] ["add eax, ecx"]   Nothing
    testKs ArchX86 [Mode32] ["add eax, ecx"]   Nothing
    testKs ArchX86 [Mode64] ["add rax, rcx"]   Nothing
    testKs ArchX86 [Mode32] ["add %ecx, %eax"] (Just SyntaxAtt)
    testKs ArchX86 [Mode64] ["add %rcx, %rax"] (Just SyntaxAtt)

    -- ARM
    testKs ArchArm [ModeArm]                ["sub r1, r2, r5"]   Nothing
    testKs ArchArm [ModeArm, ModeBigEndian] ["sub r1, r2, r5"]   Nothing
    testKs ArchArm [ModeThumb]              ["movs r4, #0xf0"]   Nothing
    testKs ArchArm [ModeThumb, ModeBigEndian] ["movs r4, #0xf0"] Nothing

    -- ARM64
    testKs ArchArm64 [ModeLittleEndian] ["ldr w1, [sp, #0x8]"] Nothing

    -- Hexagon
    testKs ArchHexagon [ModeBigEndian] ["v23.w=vavg(v11.w,v2.w):rnd"] Nothing

    -- MIPS
    testKs ArchMips [ModeMips32]                ["and $9, $6, $7"] Nothing
    testKs ArchMips [ModeMips32, ModeBigEndian] ["and $9, $6, $7"] Nothing
    testKs ArchMips [ModeMips64]                ["and $9, $6, $7"] Nothing
    testKs ArchMips [ModeMips64, ModeBigEndian] ["and $9, $6, $7"] Nothing

    -- PowerPC
    testKs ArchPpc [ModePpc32, ModeBigEndian] ["add 1, 2, 3"] Nothing
    testKs ArchPpc [ModePpc64]                ["add 1, 2, 3"] Nothing
    testKs ArchPpc [ModePpc64, ModeBigEndian] ["add 1, 2, 3"] Nothing

    -- SPARC
    testKs ArchSparc [ModeSparc32, ModeLittleEndian] ["add %g1, %g2, %g3"] Nothing
    testKs ArchSparc [ModeSparc32, ModeBigEndian]    ["add %g1, %g2, %g3"] Nothing

    -- SystemZ
    testKs ArchSystemz [ModeBigEndian] ["a %r0, 4095(%r15,%r1)"] Nothing
