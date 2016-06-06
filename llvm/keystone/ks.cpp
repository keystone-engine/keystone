/* Keystone Assembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */

#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)
#pragma warning(disable:4996)
#endif
#if defined(KEYSTONE_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stdio.h>
#endif

#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCCodeEmitter.h"

// DEBUG
//#include <iostream>

#include "ks_priv.h"

using namespace llvm;


KEYSTONE_EXPORT
unsigned int ks_version(unsigned int *major, unsigned int *minor)
{
    if (major != NULL && minor != NULL) {
        *major = KS_API_MAJOR;
        *minor = KS_API_MINOR;
    }

    return (KS_API_MAJOR << 8) + KS_API_MINOR;
}


KEYSTONE_EXPORT
ks_err ks_errno(ks_engine *ks)
{
    return (ks_err)ks->errnum;
}


KEYSTONE_EXPORT
const char *ks_strerror(ks_err code)
{
    switch(code) {
        default:
            return "Unknow error";  // FIXME
        case KS_ERR_OK:
            return "OK (KS_ERR_OK)";
        case KS_ERR_NOMEM:
            return "No memory available or memory not present (KS_ERR_NOMEM)";
        case KS_ERR_ARCH:
            return "Invalid/unsupported architecture (KS_ERR_ARCH)";
        case KS_ERR_HANDLE:
            return "Invalid handle (KS_ERR_HANDLE)";
        case KS_ERR_MODE:
            return "Invalid mode (KS_ERR_MODE)";
        case KS_ERR_VERSION:
            return "Different API version between core & binding (KS_ERR_VERSION)";
        case KS_ERR_OPT_INVALID:
            return "Invalid option (KS_ERR_OPT_INVALID)";
        case KS_ERR_ASM_INVALIDOPERAND:
            return "Invalid operand (KS_ERR_ASM_INVALIDOPERAND)";
        case KS_ERR_ASM_MISSINGFEATURE:
            return "Missing CPU feature (KS_ERR_ASM_MISSINGFEATURE)";
        case KS_ERR_ASM_MNEMONICFAIL:
            return "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)";

        // generic input assembly errors - parser specific
        case KS_ERR_ASM_EXPR_TOKEN:    // unknown token in expression
            return "Unknown token in expression (KS_ERR_ASM_EXPR_TOKEN)";
        case KS_ERR_ASM_DIRECTIVE_VALUE_RANGE:   // literal value out of range for directive
            return "Literal value out of range for directive (KS_ERR_ASM_DIRECTIVE_VALUE_RANGE)";
        case KS_ERR_ASM_DIRECTIVE_ID:    // expected identifier in directive
            return "Expected identifier in directive (KS_ERR_ASM_DIRECTIVE_ID)";
        case KS_ERR_ASM_DIRECTIVE_TOKEN: // unexpected token in directive
            return "Unexpected token in directive (KS_ERR_ASM_DIRECTIVE_TOKEN)";
        case KS_ERR_ASM_DIRECTIVE_STR:   // expected string in directive
            return "Expected string in directive (KS_ERR_ASM_DIRECTIVE_STR)";
        case KS_ERR_ASM_DIRECTIVE_COMMA: // expected comma in directive
            return "Expected comma in directive (KS_ERR_ASM_DIRECTIVE_COMMA)";
        //case KS_ERR_ASM_DIRECTIVE_RELOC_NAME: // expected relocation name in directive
        //    return "Expected relocation name in directive (KS_ERR_ASM_DIRECTIVE_RELOC_NAME)";
        //case KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN: // unexpected token in .reloc directive
        //    return "Unexpected token in .reloc directive (KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN)";
        case KS_ERR_ASM_DIRECTIVE_FPOINT:    // invalid floating point in directive
            return "Invalid floating point in directive (KS_ERR_ASM_DIRECTIVE_FPOINT)";
        case KS_ERR_ASM_VARIANT_INVALID: // invalid variant
            return "Invalid variant (KS_ERR_ASM_VARIANT_INVALID)";
        case KS_ERR_ASM_DIRECTIVE_EQU:
            return "Invalid equal directive (KS_ERR_ASM_DIRECTIVE_EQU)";
        case KS_ERR_ASM_EXPR_BRACKET:    // brackets expression not supported on this target
            return "Brackets expression not supported (KS_ERR_ASM_EXPR_BRACKET)";
        case KS_ERR_ASM_SYMBOL_MODIFIER: // unexpected symbol modifier following '@'
            return "Unexpected symbol modifier following '@' (KS_ERR_ASM_SYMBOL_MODIFIER)";
        case KS_ERR_ASM_SYMBOL_REDEFINED:
            return "Invalid symbol redefined (KS_ERR_ASM_SYMBOL_REDEFINED)";
        case KS_ERR_ASM_SYMBOL_MISSING:
            return "Cannot find a symbol (KS_ERR_ASM_SYMBOL_MISSING)";
        case KS_ERR_ASM_RPAREN:          // expected ')' in parentheses expression
            return "Expected ')' (KS_ERR_ASM_RPAREN)";
        case KS_ERR_ASM_STAT_TOKEN:      // unexpected token at start of statement
            return "Unexpected token at start of statement (KS_ERR_ASM_STAT_TOKEN)";
        case KS_ERR_ASM_UNSUPPORTED:     // unsupported token yet
            return "Unsupported token yet (KS_ERR_ASM_UNSUPPORTED)";
        case KS_ERR_ASM_MACRO_TOKEN:     // unexpected token in macro instantiation
            return "Unexpected token in macro instantiation (KS_ERR_ASM_MACRO_TOKEN)";
        case KS_ERR_ASM_MACRO_PAREN:     // unbalanced parentheses in macro argument
            return "Unbalanced parentheses in macro argument (KS_ERR_ASM_MACRO_PAREN)";
        case KS_ERR_ASM_MACRO_EQU:       // expected '=' after formal parameter identifier
            return "Expected '=' after formal parameter identifier (KS_ERR_ASM_MACRO_EQU)";
        case KS_ERR_ASM_MACRO_ARGS:      // too many positional arguments
            return "Too many positional arguments (KS_ERR_ASM_MACRO_ARGS)";
        case KS_ERR_ASM_MACRO_LEVELS_EXCEED: // macros cannot be nested more than 20 levels deep
            return "Macros cannot be nested more than 20 levels deep (KS_ERR_ASM_MACRO_LEVELS_EXCEED)";
        case KS_ERR_ASM_MACRO_STR:         // invalid macro string
            return "Invalid macro string (KS_ERR_ASM_MACRO_STR)";
        case KS_ERR_ASM_MACRO_INVALID:         // invalid macro string
            return "Invalid macro (KS_ERR_ASM_MACRO_INVALID)";
        case KS_ERR_ASM_ESC_BACKSLASH:   // unexpected backslash at end of escaped string
            return "Unexpected backslash at end of escaped string (KS_ERR_ASM_ESC_BACKSLASH)";
        case KS_ERR_ASM_ESC_OCTAL:       // invalid octal escape sequence (out of range)
            return "Invalid octal escape sequence (KS_ERR_ASM_ESC_OCTAL)";
        case KS_ERR_ASM_ESC_SEQUENCE:         // invalid escape sequence (unrecognized character)
            return "Invalid escape sequence (KS_ERR_ASM_ESC_SEQUENCE)";
        case KS_ERR_ASM_ESC_STR:         // broken escape string
            return "Invalid escape string (KS_ERR_ASM_ESC_STR)";
        case KS_ERR_ASM_TOKEN_INVALID:   // invalid token from input assembly
            return "Invalid input token (KS_ERR_ASM_TOKEN_INVALID)";
        case KS_ERR_ASM_INSN_UNSUPPORTED:
            return "Instruction is unsupported in this mode (KS_ERR_ASM_INSN_UNSUPPORTED)";
        case KS_ERR_ASM_DIRECTIVE_UNKNOWN:
            return "Unknown directive (KS_ERR_ASM_DIRECTIVE_UNKNOWN)";
        case KS_ERR_ASM_FIXUP_INVALID:
            return "Invalid fixup (KS_ERR_ASM_FIXUP_INVALID)";
        case KS_ERR_ASM_LABEL_INVALID:
            return "Invalid label (KS_ERR_ASM_LABEL_INVALID)";
        case KS_ERR_ASM_FRAGMENT_INVALID:
            return "Invalid fragment (KS_ERR_ASM_FRAGMENT_INVALID)";
        case KS_ERR_ASM_DIRECTIVE_INVALID:
            return "Invalid directive (KS_ERR_ASM_DIRECTIVE_INVALID)";
    }
}


KEYSTONE_EXPORT
bool ks_arch_supported(ks_arch arch)
{
    switch (arch) {
#ifdef LLVM_ENABLE_ARCH_ARM
        case KS_ARCH_ARM:   return true;
#endif
#ifdef LLVM_ENABLE_ARCH_AArch64
        case KS_ARCH_ARM64: return true;
#endif
#ifdef LLVM_ENABLE_ARCH_Mips
        case KS_ARCH_MIPS:  return true;
#endif
#ifdef LLVM_ENABLE_ARCH_PowerPC
        case KS_ARCH_PPC:   return true;
#endif
#ifdef LLVM_ENABLE_ARCH_Sparc
        case KS_ARCH_SPARC: return true;
#endif
#ifdef LLVM_ENABLE_ARCH_X86
        case KS_ARCH_X86:   return true;
#endif
#ifdef LLVM_ENABLE_ARCH_Hexagon
        case KS_ARCH_HEXAGON:   return true;
#endif
#ifdef LLVM_ENABLE_ARCH_SystemZ
        case KS_ARCH_SYSTEMZ:   return true;
#endif
        /* Invalid or disabled arch */
        default:            return false;
    }
}


static const Target *GetTarget(std::string TripleName)
{
    // Figure out the target triple.
    Triple TheTriple(TripleName);

    // Get the target specific parser.
    std::string Error;

    return TargetRegistry::lookupTarget("", TheTriple, Error);
}


static ks_err InitKs(int arch, ks_engine *ks, std::string TripleName)
{
    static bool initialized = false;
    std::string MCPU = "";

    if (!initialized) {
        initialized = true;
        // Initialize targets and assembly parsers.
        llvm::InitializeAllTargetInfos();
        llvm::InitializeAllTargetMCs();
        llvm::InitializeAllAsmParsers();
    }

    ks->TripleName = Triple::normalize(TripleName);
    ks->TheTarget = GetTarget(ks->TripleName);
    if (!ks->TheTarget)
        return KS_ERR_MODE;   // FIXME

    // Now that GetTarget() has (potentially) replaced TripleName, it's safe to
    // construct the Triple object.
    Triple TheTriple(ks->TripleName);

    ks->MRI = ks->TheTarget->createMCRegInfo(ks->TripleName);
    assert(ks->MRI && "Unable to create target register info!");

    // Package up features to be passed to target/subtarget
#if 0
    if (MAttrs.size()) {
        SubtargetFeatures Features;
        for (unsigned i = 0; i != MAttrs.size(); ++i)
            Features.AddFeature(MAttrs[i]);
        ks->FeaturesStr = Features.getString();
    }
#endif

    ks->MAI = ks->TheTarget->createMCAsmInfo(*ks->MRI, ks->TripleName);
    assert(ks->MAI && "Unable to create target asm info!");

    // enable Knights Landing architecture for X86
    if (ks->arch == KS_ARCH_X86)
        MCPU = "knl";

    ks->MCII = ks->TheTarget->createMCInstrInfo();
    ks->STI = ks->TheTarget->createMCSubtargetInfo(ks->TripleName, MCPU, ks->FeaturesStr);
    ks->MAB = ks->TheTarget->createMCAsmBackend(*ks->MRI, ks->TripleName, MCPU);
    ks->MAB->setArch(arch);
    ks->MCOptions = InitMCTargetOptionsFromFlags();

    return KS_ERR_OK;
}


KEYSTONE_EXPORT
ks_err ks_open(ks_arch arch, int mode, ks_engine **result)
{
    struct ks_struct *ks;
    std::string TripleName = "";

    if (arch < KS_ARCH_MAX) {
        ks = new (std::nothrow) ks_struct();
        ks->TheTarget = NULL;
        ks->MAB = NULL;
        ks->MRI = NULL;
        ks->MAI = NULL;
        ks->MCII = NULL;
        ks->STI = NULL;

        if (!ks) {
            // memory insufficient
            return KS_ERR_NOMEM;
        }

        ks->errnum = KS_ERR_OK;
        ks->arch = arch;
        ks->mode = mode;

        switch(arch) {
            default: break;

#ifdef LLVM_ENABLE_ARCH_ARM
            case KS_ARCH_ARM:
                if (mode & ~KS_MODE_ARM_MASK) {
                    delete ks;
                    return KS_ERR_MODE;
                }

                if (mode & KS_MODE_THUMB) {
                    if (mode & KS_MODE_BIG_ENDIAN)
                        TripleName = "thumbebv7";
                    else
                        TripleName = "thumbv7";
                } else {
                    if (mode & KS_MODE_BIG_ENDIAN)
                        TripleName = "armv7eb";
                    else
                        TripleName = "armv7";
                }

                InitKs(arch, ks, TripleName);

                //ks->init_arch = arm_ks_init;
                break;
#endif

#ifdef LLVM_ENABLE_ARCH_AArch64
            case KS_ARCH_ARM64:
                if (mode != KS_MODE_LITTLE_ENDIAN) {
                    delete ks;
                    return KS_ERR_MODE;
                }

                TripleName = "aarch64";
                InitKs(arch, ks, TripleName);

                //ks->init_arch = arm64_ks_init;
                break;
#endif

#ifdef LLVM_ENABLE_ARCH_Hexagon
            case KS_ARCH_HEXAGON:
                if (mode & ~KS_MODE_HEXAGON_MASK) {
                    delete ks;
                    return KS_ERR_MODE;
                }

                TripleName = "hexagon";

                InitKs(arch, ks, TripleName);

                //ks->init_arch = arm_ks_init;
                break;
#endif

#ifdef LLVM_ENABLE_ARCH_SystemZ
            case KS_ARCH_SYSTEMZ:
                if (mode & ~KS_MODE_SYSTEMZ_MASK) {
                    delete ks;
                    return KS_ERR_MODE;
                }

                TripleName = "s390x";

                InitKs(arch, ks, TripleName);

                //ks->init_arch = arm_ks_init;
                break;
#endif

#ifdef LLVM_ENABLE_ARCH_Sparc
            case KS_ARCH_SPARC:
                if ((mode & ~KS_MODE_SPARC_MASK) ||
                        !(mode & (KS_MODE_SPARC32|KS_MODE_SPARC64))) {
                    delete ks;
                    return KS_ERR_MODE;
                }
                if (mode & KS_MODE_BIG_ENDIAN) {
                    // big endian
                    if (mode & KS_MODE_SPARC64)
                        TripleName = "sparc64";
                    else
                        TripleName = "sparc";
                } else {
                    // little endian
                    if (mode & KS_MODE_SPARC64) {
                        // TripleName = "sparc64el";
                        // FIXME
                        delete ks;
                        return KS_ERR_MODE;
                    } else
                        TripleName = "sparcel";
                }

                InitKs(arch, ks, TripleName);

                break;
#endif

#ifdef LLVM_ENABLE_ARCH_Mips
            case KS_ARCH_MIPS:
                if ((mode & ~KS_MODE_MIPS_MASK) ||
                        !(mode & (KS_MODE_MIPS32|KS_MODE_MIPS64))) {
                    delete ks;
                    return KS_ERR_MODE;
                }
                if (mode & KS_MODE_BIG_ENDIAN) {
                    // big endian
                    if (mode & KS_MODE_MIPS32)
                        TripleName = "mips";
                    if (mode & KS_MODE_MIPS64)
                        TripleName = "mips64";
                } else {    // little endian
                    if (mode & KS_MODE_MIPS32)
                        TripleName = "mipsel";
                    if (mode & KS_MODE_MIPS64)
                        TripleName = "mips64el";
                }

                InitKs(arch, ks, TripleName);

                break;
#endif

#ifdef LLVM_ENABLE_ARCH_PowerPC
            case KS_ARCH_PPC:
                if ((mode & ~KS_MODE_PPC_MASK) ||
                        !(mode & (KS_MODE_PPC32|KS_MODE_PPC64))) {
                    delete ks;
                    return KS_ERR_MODE;
                }

                if (mode & KS_MODE_BIG_ENDIAN) {
                    // big endian
                    if (mode & KS_MODE_PPC32)
                        TripleName = "ppc32";
                    if (mode & KS_MODE_PPC64)
                        TripleName = "ppc64";
                } else {    // little endian
                    if (mode & KS_MODE_PPC32) {
                        // do not support this mode
                        delete ks;
                        return KS_ERR_MODE;
                    }
                    if (mode & KS_MODE_MIPS64)
                        TripleName = "ppc64le";
                }

                InitKs(arch, ks, TripleName);

                //ks->init_arch = ppc_ks_init;
                break;
#endif

#ifdef LLVM_ENABLE_ARCH_X86
            case KS_ARCH_X86: {
                if ((mode & ~KS_MODE_X86_MASK) ||
                        (mode & KS_MODE_BIG_ENDIAN) ||
                        !(mode & (KS_MODE_16|KS_MODE_32|KS_MODE_64))) {
                    delete ks;
                    return KS_ERR_MODE;
                }

                switch(mode) {
                    default: break;
                    case KS_MODE_16:
                        // FIXME
                        TripleName = "i386-unknown-unknown-code16";
                        break;
                    case KS_MODE_32:
                        // FIXME
                        TripleName = "i386";
                        break;
                    case KS_MODE_64:
                        // FIXME
                        TripleName = "x86_64";
                        break;
                }

                InitKs(arch, ks, TripleName);

                //ks->init_arch = x86_ks_init;
                break;
            }
#endif
        }

        if (TripleName.empty()) {
            // this arch is not supported
            delete ks;
            return KS_ERR_ARCH;
        }

        *result = ks;

        return KS_ERR_OK;
    } else
        return KS_ERR_ARCH;
}


KEYSTONE_EXPORT
ks_err ks_close(ks_engine *ks)
{
    delete ks->STI;
    delete ks->MCII;
    delete ks->MAI;
    delete ks->MRI;
    delete ks->MAB;

    // finally, free ks itself.
    delete ks;

    return KS_ERR_OK;
}


KEYSTONE_EXPORT
ks_err ks_option(ks_engine *ks, ks_opt_type type, size_t value)
{
    switch(type) {
        case KS_OPT_SYNTAX:
            if (ks->arch != KS_ARCH_X86)
                return KS_ERR_OPT_INVALID;
            switch(value) {
                default:
                    return KS_ERR_OPT_INVALID;
                case KS_OPT_SYNTAX_NASM:
                case KS_OPT_SYNTAX_INTEL:
                    ks->syntax = (ks_opt_value)value;
                    ks->MAI->setAssemblerDialect(1);
                    break;
                case KS_OPT_SYNTAX_GAS:
                case KS_OPT_SYNTAX_ATT:
                    ks->syntax = (ks_opt_value)value;
                    ks->MAI->setAssemblerDialect(0);
                    break;
            }

            return KS_ERR_OK;
    }

    return KS_ERR_OPT_INVALID;
}


KEYSTONE_EXPORT
void ks_free(unsigned char *p)
{
    free(p);
}

KEYSTONE_EXPORT
int ks_asm(ks_engine *ks,
        const char *assembly,
        uint64_t address,
        unsigned char **insn, size_t *insn_size,
        size_t *stat_count)
{
    MCCodeEmitter *CE;
    MCStreamer *Streamer;
    unsigned char *encoding;
    SmallString<1024> Msg;
    raw_svector_ostream OS(Msg);

    *insn = NULL;
    *insn_size = 0;

    MCContext Ctx(ks->MAI, ks->MRI, &ks->MOFI, &ks->SrcMgr, true, address);
    ks->MOFI.InitMCObjectFileInfo(Triple(ks->TripleName), Ctx);
    CE = ks->TheTarget->createMCCodeEmitter(*ks->MCII, *ks->MRI, Ctx);

    Streamer = ks->TheTarget->createMCObjectStreamer(
            Triple(ks->TripleName), Ctx, *ks->MAB, OS, CE, *ks->STI, ks->MCOptions.MCRelaxAll,
            /*DWARFMustBeAtTheEnd*/ false);

    // Tell SrcMgr about this buffer, which is what the parser will pick up.
    ErrorOr<std::unique_ptr<MemoryBuffer>> BufferPtr = MemoryBuffer::getMemBuffer(assembly);
    if (BufferPtr.getError()) {
        // TODO: set error
        return -1;
    }

    ks->SrcMgr.clearBuffers();
    ks->SrcMgr.AddNewSourceBuffer(std::move(*BufferPtr), SMLoc());

    MCAsmParser *Parser = createMCAsmParser(ks->SrcMgr, Ctx, *Streamer, *ks->MAI);
    MCTargetAsmParser *TAP = ks->TheTarget->createMCAsmParser(*ks->STI, *Parser, *ks->MCII, ks->MCOptions);
    TAP->KsSyntax = ks->syntax;

    Parser->setTargetParser(*TAP);

    // TODO: optimize this to avoid setting up NASM every time we call ks_asm()
    if (ks->arch == KS_ARCH_X86 && ks->syntax == KS_OPT_SYNTAX_NASM) {
        Parser->initializeDirectiveKindMap(KS_OPT_SYNTAX_NASM);
        ks->MAI->setCommentString(";");
    }

    *stat_count = Parser->Run(false, address);

    // PPC counts empty statement
    if (ks->arch == KS_ARCH_PPC)
        *stat_count = *stat_count / 2;

    ks->errnum = Parser->KsError;

    delete TAP;
    delete Parser;
    delete CE;
    delete Streamer;

    if (ks->errnum >= KS_ERR_ASM)
        return -1;
    else {
        *insn_size = Msg.size();
        encoding = (unsigned char *)malloc(*insn_size);
        memcpy(encoding, Msg.data(), *insn_size);
        *insn = encoding;
        return 0;
    }
}
