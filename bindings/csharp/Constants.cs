using System.Runtime.InteropServices;

namespace Keystone
{
    public class Constants
    {
        // Keystone API version
        public const int KS_API_MAJOR = 0;
        public const int KS_API_MINOR = 9;

        // Package version
        public const int KS_VERSION_MAJOR = KS_API_MAJOR;
        public const int KS_VERSION_MINOR = KS_API_MINOR;
        public const int KS_VERSION_EXTRA = 1;

        public enum ks_arch : int
        {
            KS_ARCH_ARM = 1,    // ARM architecture (including Thumb, Thumb-2)
            KS_ARCH_ARM64,      // ARM-64, also called AArch64
            KS_ARCH_MIPS,       // Mips architecture
            KS_ARCH_X86,        // X86 architecture (including x86 & x86-64)
            KS_ARCH_PPC,        // PowerPC architecture (currently unsupported)
            KS_ARCH_SPARC,      // Sparc architecture
            KS_ARCH_SYSTEMZ,    // SystemZ architecture (S390X)
            KS_ARCH_HEXAGON,    // Hexagon architecture
            KS_ARCH_MAX,
        }

        public enum ks_mode : int
        {
            KS_MODE_LITTLE_ENDIAN = 0,    // little-endian mode (default mode)
            KS_MODE_BIG_ENDIAN = 1 << 30, // big-endian mode
                                          // arm / arm64
            KS_MODE_ARM = 1 << 0,              // ARM mode
            KS_MODE_THUMB = 1 << 4,       // THUMB mode (including Thumb-2)
            KS_MODE_V8 = 1 << 6,          // ARMv8 A32 encodings for ARM
                                          // mips
            KS_MODE_MICRO = 1 << 4,       // MicroMips mode
            KS_MODE_MIPS3 = 1 << 5,       // Mips III ISA
            KS_MODE_MIPS32R6 = 1 << 6,    // Mips32r6 ISA
            KS_MODE_MIPS32 = 1 << 2,      // Mips32 ISA
            KS_MODE_MIPS64 = 1 << 3,      // Mips64 ISA
                                          // x86 / x64
            KS_MODE_16 = 1 << 1,          // 16-bit mode
            KS_MODE_32 = 1 << 2,          // 32-bit mode
            KS_MODE_64 = 1 << 3,          // 64-bit mode
                                          // ppc 
            KS_MODE_PPC32 = 1 << 2,       // 32-bit mode
            KS_MODE_PPC64 = 1 << 3,       // 64-bit mode
            KS_MODE_QPX = 1 << 4,         // Quad Processing eXtensions mode
                                          // sparc
            KS_MODE_SPARC32 = 1 << 2,     // 32-bit mode
            KS_MODE_SPARC64 = 1 << 3,     // 64-bit mode
            KS_MODE_V9 = 1 << 4,          // SparcV9 mode
        }

        // All generic errors related to input assembly >= KS_ERR_ASM
        public const int KS_ERR_ASM = 128;

        // All architecture-specific errors related to input assembly >= KS_ERR_ASM_ARCH
        public const int KS_ERR_ASM_ARCH = 512;

        public enum ks_err : int
        {
            KS_ERR_OK = 0,   // No error: everything was fine
            KS_ERR_NOMEM,      // Out-Of-Memory error: ks_open(), ks_emulate()
            KS_ERR_ARCH,     // Unsupported architecture: ks_open()
            KS_ERR_HANDLE,   // Invalid handle
            KS_ERR_MODE,     // Invalid/unsupported mode: ks_open()
            KS_ERR_VERSION,  // Unsupported version (bindings)
            KS_ERR_OPT_INVALID,  // Unsupported option

            // generic input assembly errors - parser specific
            KS_ERR_ASM_EXPR_TOKEN = KS_ERR_ASM,    // unknown token in expression
            KS_ERR_ASM_DIRECTIVE_VALUE_RANGE,   // literal value out of range for directive
            KS_ERR_ASM_DIRECTIVE_ID,    // expected identifier in directive
            KS_ERR_ASM_DIRECTIVE_TOKEN, // unexpected token in directive
            KS_ERR_ASM_DIRECTIVE_STR,   // expected string in directive
            KS_ERR_ASM_DIRECTIVE_COMMA, // expected comma in directive
            KS_ERR_ASM_DIRECTIVE_RELOC_NAME, // expected relocation name in directive
            KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN, // unexpected token in .reloc directive
            KS_ERR_ASM_DIRECTIVE_FPOINT,    // invalid floating point in directive
            KS_ERR_ASM_DIRECTIVE_UNKNOWN,    // unknown directive
            KS_ERR_ASM_DIRECTIVE_EQU,   // invalid equal directive
            KS_ERR_ASM_DIRECTIVE_INVALID,   // (generic) invalid directive
            KS_ERR_ASM_VARIANT_INVALID, // invalid variant
            KS_ERR_ASM_EXPR_BRACKET,    // brackets expression not supported on this target
            KS_ERR_ASM_SYMBOL_MODIFIER, // unexpected symbol modifier following '@'
            KS_ERR_ASM_SYMBOL_REDEFINED, // invalid symbol redefinition
            KS_ERR_ASM_SYMBOL_MISSING,  // cannot find a symbol
            KS_ERR_ASM_RPAREN,          // expected ')' in parentheses expression
            KS_ERR_ASM_STAT_TOKEN,      // unexpected token at start of statement
            KS_ERR_ASM_UNSUPPORTED,     // unsupported token yet
            KS_ERR_ASM_MACRO_TOKEN,     // unexpected token in macro instantiation
            KS_ERR_ASM_MACRO_PAREN,     // unbalanced parentheses in macro argument
            KS_ERR_ASM_MACRO_EQU,       // expected '=' after formal parameter identifier
            KS_ERR_ASM_MACRO_ARGS,      // too many positional arguments
            KS_ERR_ASM_MACRO_LEVELS_EXCEED, // macros cannot be nested more than 20 levels deep
            KS_ERR_ASM_MACRO_STR,    // invalid macro string
            KS_ERR_ASM_MACRO_INVALID,    // invalid macro (generic error)
            KS_ERR_ASM_ESC_BACKSLASH,   // unexpected backslash at end of escaped string
            KS_ERR_ASM_ESC_OCTAL,       // invalid octal escape sequence  (out of range)
            KS_ERR_ASM_ESC_SEQUENCE,         // invalid escape sequence (unrecognized character)
            KS_ERR_ASM_ESC_STR,         // broken escape string
            KS_ERR_ASM_TOKEN_INVALID,   // invalid token
            KS_ERR_ASM_INSN_UNSUPPORTED,   // this instruction is unsupported in this mode
            KS_ERR_ASM_FIXUP_INVALID,   // invalid fixup
            KS_ERR_ASM_LABEL_INVALID,   // invalid label
            KS_ERR_ASM_FRAGMENT_INVALID,   // invalid fragment

            // generic input assembly errors - architecture specific
            KS_ERR_ASM_INVALIDOPERAND = KS_ERR_ASM_ARCH,
            KS_ERR_ASM_MISSINGFEATURE,
            KS_ERR_ASM_MNEMONICFAIL,
        }

        // To register the resolver, pass its function address to ks_option(), using
        // option KS_OPT_SYM_RESOLVER. For example, see samples/sample.c.
        // typedef bool (*ks_sym_resolver)(const char* symbol, uint64_t *value);

        // Runtime option for the Keystone engine
        public enum ks_opt_type : int
        {
            KS_OPT_SYNTAX = 1,    // Choose syntax for input assembly
            KS_OPT_SYM_RESOLVER,  // Set symbol resolver callback
        }

        // Runtime option value (associated with ks_opt_type above)
        public enum ks_opt_value : int
        {
            KS_OPT_SYNTAX_INTEL = 1 << 0, // X86 Intel syntax - default on X86 (KS_OPT_SYNTAX).
            KS_OPT_SYNTAX_ATT = 1 << 1, // X86 ATT asm syntax (KS_OPT_SYNTAX).
            KS_OPT_SYNTAX_NASM = 1 << 2, // X86 Nasm syntax (KS_OPT_SYNTAX).
            KS_OPT_SYNTAX_MASM = 1 << 3, // X86 Masm syntax (KS_OPT_SYNTAX) - unsupported yet.
            KS_OPT_SYNTAX_GAS = 1 << 4, // X86 GNU GAS syntax (KS_OPT_SYNTAX).
            KS_OPT_SYNTAX_RADIX16 = 1 << 5, // All immediates are in hex format (i.e 12 is 0x12)
        }

        public enum ks_err_asm_arm64 : int
        {
            KS_ERR_ASM_ARM64_INVALIDOPERAND = KS_ERR_ASM_ARCH,
            KS_ERR_ASM_ARM64_MISSINGFEATURE,
            KS_ERR_ASM_ARM64_MNEMONICFAIL,
        }

        public enum ks_err_asm_arm : int
        {
            KS_ERR_ASM_ARM_INVALIDOPERAND = KS_ERR_ASM_ARCH,
            KS_ERR_ASM_ARM_MISSINGFEATURE,
            KS_ERR_ASM_ARM_MNEMONICFAIL,
        }

        public enum ks_err_asm_hexagon : int
        {
            KS_ERR_ASM_HEXAGON_INVALIDOPERAND = KS_ERR_ASM_ARCH,
            KS_ERR_ASM_HEXAGON_MISSINGFEATURE,
            KS_ERR_ASM_HEXAGON_MNEMONICFAIL,
        }

        public enum ks_err_asm_mips : int
        {
            KS_ERR_ASM_MIPS_INVALIDOPERAND = KS_ERR_ASM_ARCH,
            KS_ERR_ASM_MIPS_MISSINGFEATURE,
            KS_ERR_ASM_MIPS_MNEMONICFAIL,
        }

        public enum ks_err_asm_ppc : int
        {
            KS_ERR_ASM_PPC_INVALIDOPERAND = KS_ERR_ASM_ARCH,
            KS_ERR_ASM_PPC_MISSINGFEATURE,
            KS_ERR_ASM_PPC_MNEMONICFAIL,
        }

        public enum ks_err_asm_sparc : int
        {
            KS_ERR_ASM_SPARC_INVALIDOPERAND = KS_ERR_ASM_ARCH,
            KS_ERR_ASM_SPARC_MISSINGFEATURE,
            KS_ERR_ASM_SPARC_MNEMONICFAIL,
        }

        public enum ks_err_asm_systemz : int
        {
            KS_ERR_ASM_SYSTEMZ_INVALIDOPERAND = KS_ERR_ASM_ARCH,
            KS_ERR_ASM_SYSTEMZ_MISSINGFEATURE,
            KS_ERR_ASM_SYSTEMZ_MNEMONICFAIL,
        }

        public enum ks_err_asm_x86 : int
        {
            KS_ERR_ASM_X86_INVALIDOPERAND = KS_ERR_ASM_ARCH,
            KS_ERR_ASM_X86_MISSINGFEATURE,
            KS_ERR_ASM_X86_MNEMONICFAIL,
        }

        // Delegate
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool ks_sym_resolver([In, MarshalAs(UnmanagedType.LPStr)] string symbol, ref ulong value);
    }
}