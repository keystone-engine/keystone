using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeystoneNET
{
    public enum KeystoneError : short
    {
        KS_ERR_OK = 0,   // No error: everything was fine
        KS_ERR_NOMEM,      // Out-Of-Memory error: ks_open(), ks_emulate()
        KS_ERR_ARCH,     // Unsupported architecture: ks_open()
        KS_ERR_HANDLE,   // Invalid handle
        KS_ERR_MODE,     // Invalid/unsupported mode: ks_open()
        KS_ERR_VERSION,  // Unsupported version (bindings)
        KS_ERR_OPT_INVALID,  // Unsupported option

        // generic input assembly errors - parser specific
        KS_ERR_ASM_EXPR_TOKEN = 128,    // unknown token in expression
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
        KS_ERR_ASM_INVALIDOPERAND = 512,
        KS_ERR_ASM_MISSINGFEATURE,
        KS_ERR_ASM_MNEMONICFAIL,
    };
}
