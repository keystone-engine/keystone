/* Keystone Assembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
/* By Amaan Qureshi <git@amaanq.com>, 2025 */

#ifndef KS_PRIV_H
#define KS_PRIV_H

#include "../../include/keystone/keystone.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include <mutex>
#include <optional>
#include <string>

using namespace llvm_ks;

#define KS_VARIANT_ARM_MASK                                                    \
  (KS_ARCH_VARIANT_ARM_V7 | KS_ARCH_VARIANT_ARM_MCLASS | KS_ARCH_VARIANT_ARM_EM)

/**
 * The internal structure of the Keystone engine.
 */
struct ks_engine {
  ks_arch Arch;
  ks_endian Endian;
  ks_width Width;
  int ArchVariant = KS_ARCH_VARIANT_NONE;
  ks_err Errnum = KS_ERR_OK;
  ks_x86_syntax Syntax = KS_X86_SYNTAX_INTEL;
  ks_radix Radix = KS_RADIX_DECIMAL;
  ks_sym_resolver SymbolResolver = {};
  size_t ErrorCount = 0;
  ks_error_location *Errors = nullptr;
  SmallVector<MCAsmParser::MCPendingError, 0> StoredErrors;
  bool NeedsInitialization =
      true; // If a property such as the endian, width, architecture variant,
            // or features has changed, we need to reinitialize the engine

  std::string TripleName;
  std::string FeaturesStr;
  std::string CPU;
  const Target *TheTarget = nullptr;
  Triple TheTriple;
  SourceMgr SrcMgr;
  MCTargetOptions MCOptions;
  MCRegisterInfo *MRI = nullptr;
  MCAsmInfo *MAI = nullptr;
  MCInstrInfo *MCII = nullptr;
  MCSubtargetInfo *MSTI = nullptr;
  MCObjectFileInfo *MOFI = nullptr;

  ks_engine(ks_arch Arch, ks_endian Endian, ks_width Width)
      : Arch(Arch), Endian(Endian), Width(Width) {}
};

struct ks_arch_desc {
  unsigned Endians;
  unsigned Widths;
  ks_endian DefaultEndian;
  ks_width DefaultWidth;
};

static inline std::optional<ks_arch_desc> ks_describe_arch(ks_arch arch) {
  constexpr ks_endian LE = KS_ENDIAN_LITTLE, BE = KS_ENDIAN_BIG;
  constexpr ks_width W16 = KS_WIDTH_16, W32 = KS_WIDTH_32, W64 = KS_WIDTH_64;

  switch (arch) {
#ifdef KEYSTONE_HAS_AARCH64
  case KS_ARCH_AARCH64:
    return ks_arch_desc{LE | BE, W64, LE, W64};
#endif
#ifdef KEYSTONE_HAS_AMDGPU
  case KS_ARCH_AMDGPU:
    return ks_arch_desc{LE, W64, LE, W64};
#endif
#ifdef KEYSTONE_HAS_ARM
  case KS_ARCH_ARM:
  case KS_ARCH_THUMB:
    return ks_arch_desc{LE | BE, W32, LE, W32};
#endif
#ifdef KEYSTONE_HAS_AVR
  case KS_ARCH_AVR:
    return ks_arch_desc{LE, W16, LE, W16};
#endif
#ifdef KEYSTONE_HAS_BPF
  case KS_ARCH_BPF:
    return ks_arch_desc{LE | BE, W64, LE, W64};
#endif
#ifdef KEYSTONE_HAS_CSKY
  case KS_ARCH_CSKY:
    return ks_arch_desc{LE, W32, LE, W32};
#endif
#ifdef KEYSTONE_HAS_EVM
  // EVM is 256-bit, but the width is never used in Keystone.
  case KS_ARCH_EVM:
    return ks_arch_desc{BE, W16 | W32 | W64, BE, W32};
#endif
#ifdef KEYSTONE_HAS_HEXAGON
  case KS_ARCH_HEXAGON:
    return ks_arch_desc{LE, W32, LE, W32};
#endif
#ifdef KEYSTONE_HAS_LANAI
  case KS_ARCH_LANAI:
    return ks_arch_desc{BE, W32, BE, W32};
#endif
#ifdef KEYSTONE_HAS_LOONGARCH
  case KS_ARCH_LOONGARCH:
    return ks_arch_desc{LE, W32 | W64, LE, W64};
#endif
#ifdef KEYSTONE_HAS_M68K
  case KS_ARCH_M68K:
    return ks_arch_desc{BE, W32, BE, W32};
#endif
#ifdef KEYSTONE_HAS_MIPS
  case KS_ARCH_MIPS:
    return ks_arch_desc{LE | BE, W32 | W64, BE, W32};
#endif
#ifdef KEYSTONE_HAS_MSP430
  case KS_ARCH_MSP430:
    return ks_arch_desc{LE, W16, LE, W16};
#endif
#ifdef KEYSTONE_HAS_PPC
  case KS_ARCH_PPC:
    return ks_arch_desc{LE | BE, W32 | W64, BE, W32};
#endif
#ifdef KEYSTONE_HAS_RISCV
  case KS_ARCH_RISCV:
    return ks_arch_desc{LE, W32 | W64, LE, W32};
#endif
#ifdef KEYSTONE_HAS_SPARC
  case KS_ARCH_SPARC:
    return ks_arch_desc{LE | BE, W32 | W64, BE, W32};
#endif
#ifdef KEYSTONE_HAS_SYSTEMZ
  case KS_ARCH_SYSTEMZ:
    return ks_arch_desc{BE, W64, BE, W64};
#endif
#ifdef KEYSTONE_HAS_VE
  case KS_ARCH_VE:
    return ks_arch_desc{LE, W64, LE, W64};
#endif
#ifdef KEYSTONE_HAS_WASM
  case KS_ARCH_WASM:
    return ks_arch_desc{LE, W32 | W64, LE, W32};
#endif
#ifdef KEYSTONE_HAS_X86
  case KS_ARCH_X86:
    return ks_arch_desc{LE, W16 | W32 | W64, LE, W32};
  case KS_ARCH_X64:
    return ks_arch_desc{LE, W64, LE, W64};
#endif
#ifdef KEYSTONE_HAS_XTENSA
  case KS_ARCH_XTENSA:
    return ks_arch_desc{LE, W32, LE, W32};
#endif
  default:
    return std::nullopt;
  }
}

static inline bool ks_endian_is_valid(ks_arch arch, ks_endian endian) {
  std::optional<ks_arch_desc> desc = ks_describe_arch(arch);
  return desc && (desc->Endians & endian);
}

static inline bool ks_width_is_valid(ks_arch arch, ks_width width) {
  std::optional<ks_arch_desc> desc = ks_describe_arch(arch);
  return desc && (desc->Widths & width);
}

/**
 * Compute the triple name based on the architecture, endianness, and width of
 * the Keystone engine.
 */
static inline ks_err ks_compute_triple(ks_engine *ks) {
  if (!ks)
    return KS_ERR_HANDLE;

  if (!ks_endian_is_valid(ks->Arch, ks->Endian)) {
    return KS_ERR_ENDIAN;
  }

  if (!ks_width_is_valid(ks->Arch, ks->Width)) {
    return KS_ERR_WIDTH;
  }

  std::string tripleName;

  switch (ks->Arch) {
#ifdef KEYSTONE_HAS_ARM
  case KS_ARCH_ARM:
    if (ks->Endian == KS_ENDIAN_LITTLE) {
      switch (ks->ArchVariant) {
      case KS_ARCH_VARIANT_ARM_V7:
        tripleName = "armv7";
        break;
      case KS_ARCH_VARIANT_ARM_MCLASS:
        tripleName = "armv7m";
        break;
      case KS_ARCH_VARIANT_ARM_EM:
        tripleName = "armv7em";
        break;
      default:
        tripleName = "armv8";
        break;
      }
    } else { // KS_ENDIAN_BIG
      switch (ks->ArchVariant) {
      case KS_ARCH_VARIANT_ARM_V7:
        tripleName = "armv7eb";
        break;
      case KS_ARCH_VARIANT_ARM_MCLASS:
        tripleName = "armv7meb";
        break;
      case KS_ARCH_VARIANT_ARM_EM:
        tripleName = "armv7emeb";
        break;
      default:
        tripleName = "armv8eb";
        break;
      }
    }
    break;
#endif

#ifdef KEYSTONE_HAS_AARCH64
  case KS_ARCH_AARCH64:
    if (ks->Endian == KS_ENDIAN_LITTLE) {
      tripleName = "aarch64";
    } else { // KS_ENDIAN_BIG
      tripleName = "aarch64_be";
    }
    break;
#endif

#ifdef KEYSTONE_HAS_AMDGPU
  case KS_ARCH_AMDGPU:
    tripleName = "amdgcn";
    break;
#endif

#ifdef KEYSTONE_HAS_AVR
  case KS_ARCH_AVR:
    tripleName = "avr";
    break;
#endif

#ifdef KEYSTONE_HAS_BPF
  case KS_ARCH_BPF:
    if (ks->Endian == KS_ENDIAN_LITTLE) {
      tripleName = "bpfel";
    } else { // KS_ENDIAN_BIG
      tripleName = "bpfeb";
    }
    break;
#endif

#ifdef KEYSTONE_HAS_CSKY
  case KS_ARCH_CSKY:
    tripleName = "csky";
    break;
#endif

#ifdef KEYSTONE_HAS_EVM
  case KS_ARCH_EVM:
    // EVM does not have a triple, so we can skip this case.
    break;
#endif

#ifdef KEYSTONE_HAS_HEXAGON
  case KS_ARCH_HEXAGON:
    tripleName = "hexagon";
    break;
#endif

#ifdef KEYSTONE_HAS_LANAI
  case KS_ARCH_LANAI:
    tripleName = "lanai";
    break;
#endif

#ifdef KEYSTONE_HAS_LOONGARCH
  case KS_ARCH_LOONGARCH:
    if (ks->Width == KS_WIDTH_64) {
      tripleName = "loongarch64";
    } else { // KS_WIDTH_32
      tripleName = "loongarch32";
    }
    break;
#endif

#ifdef KEYSTONE_HAS_M68K
  case KS_ARCH_M68K:
    tripleName = "m68k";
    break;
#endif

#ifdef KEYSTONE_HAS_MIPS
  case KS_ARCH_MIPS:
    if (ks->Endian == KS_ENDIAN_BIG) {
      if (ks->Width == KS_WIDTH_32) {
        tripleName = "mipseb";
      } else { // KS_WIDTH_64
        tripleName = "mips64eb";
      }
    } else { // KS_ENDIAN_LITTLE
      if (ks->Width == KS_WIDTH_32) {
        tripleName = "mipsel";
      } else { // KS_WIDTH_64
        tripleName = "mips64el";
      }
    }
    break;
#endif

#ifdef KEYSTONE_HAS_MSP430
  case KS_ARCH_MSP430:
    tripleName = "msp430";
    break;
#endif

#ifdef KEYSTONE_HAS_PPC
  case KS_ARCH_PPC:
    if (ks->Endian == KS_ENDIAN_BIG) {
      if (ks->Width == KS_WIDTH_32) {
        tripleName = "ppc";
      } else { // KS_WIDTH_64
        tripleName = "ppc64";
      }
    } else { // KS_ENDIAN_LITTLE
      if (ks->Width == KS_WIDTH_32) {
        tripleName = "ppcle";
      } else { // KS_WIDTH_64
        tripleName = "ppc64le";
      }
    }
    break;
#endif

#ifdef KEYSTONE_HAS_RISCV
  case KS_ARCH_RISCV:
    if (ks->Width == KS_WIDTH_32) {
      tripleName = "riscv32";
    } else { // KS_WIDTH_64
      tripleName = "riscv64";
    }
    break;
#endif

#ifdef KEYSTONE_HAS_SPARC
  case KS_ARCH_SPARC:
    if (ks->Endian == KS_ENDIAN_BIG) {
      if (ks->Width == KS_WIDTH_32) {
        tripleName = "sparc";
      } else { // KS_WIDTH_64
        tripleName = "sparcv9";
      }
    } else { // KS_ENDIAN_LITTLE
      if (ks->Width == KS_WIDTH_32) {
        tripleName = "sparcel";
      } else {
        // The per-arch ks_endian/ks_width validators are permissive about
        // SPARC (mask allows both endians at both widths) so that callers
        // can set the two fields independently. The combination LE-64 has
        // no LLVM triple though; reject it here, which `ks_init` now
        // propagates back through `ks_assemble`.
        return KS_ERR_WIDTH;
      }
    }
    break;
#endif

#ifdef KEYSTONE_HAS_SYSTEMZ
  case KS_ARCH_SYSTEMZ:
    tripleName = "s390x";
    break;
#endif

#ifdef KEYSTONE_HAS_VE
  case KS_ARCH_VE:
    tripleName = "ve";
    break;
#endif

#ifdef KEYSTONE_HAS_ARM
  case KS_ARCH_THUMB:
    if (ks->Endian == KS_ENDIAN_LITTLE) {
      switch (ks->ArchVariant) {
      case KS_ARCH_VARIANT_THUMB_MCLASS:
        tripleName = "thumbv8m.main";
        break;
      case KS_ARCH_VARIANT_THUMB_V7 | KS_ARCH_VARIANT_THUMB_MCLASS:
        tripleName = "thumbv7m";
        break;
      case KS_ARCH_VARIANT_THUMB_V7:
        tripleName = "thumbv7";
        break;
      case KS_ARCH_VARIANT_THUMB_EM:
        tripleName = "thumbv7em";
        break;
      default:
        tripleName = "thumbv8";
        break;
      }
    } else { // KS_ENDIAN_BIG
      switch (ks->ArchVariant) {
      case KS_ARCH_VARIANT_THUMB_V7 | KS_ARCH_VARIANT_THUMB_MCLASS:
        tripleName = "thumbv7meb";
        break;
      case KS_ARCH_VARIANT_THUMB_MCLASS:
        tripleName = "thumbv8m.main";
        break;
      case KS_ARCH_VARIANT_THUMB_V7:
        tripleName = "thumbv7eb";
        break;
      case KS_ARCH_VARIANT_THUMB_EM:
        tripleName = "thumbv7emeb";
        break;
      default:
        tripleName = "thumbv8eb";
        break;
      }
    }
    break;
#endif

#ifdef KEYSTONE_HAS_X86
  case KS_ARCH_X86:
    switch (ks->Width) {
    case KS_WIDTH_16:
      tripleName = "i386-unknown-unknown-code16";
      break;
    case KS_WIDTH_32:
      tripleName = "i386";
      break;
    case KS_WIDTH_64:
      tripleName = "x86_64";
      break;
    }
    break;
  case KS_ARCH_X64:
    tripleName = "x86_64";
    break;
#endif

#ifdef KEYSTONE_HAS_XTENSA
  case KS_ARCH_XTENSA:
    tripleName = "xtensa";
    break;
#endif

#ifdef KEYSTONE_HAS_WASM
  case KS_ARCH_WASM:
    if (ks->Width == KS_WIDTH_64) {
      tripleName = "wasm64";
    } else { // KS_WIDTH_32
      tripleName = "wasm32";
    }
    break;
#endif

  default:
    return KS_ERR_ARCH;
  }

  ks->TripleName = tripleName;

  return KS_ERR_OK;
}

/**
 * Initialize the Keystone engine's internal structures.
 */
static inline ks_err ks_init(ks_engine *ks) {
  static std::once_flag GlobalInitFlag;
  std::call_once(GlobalInitFlag, []() {
    InitializeAllTargetInfos();
    InitializeAllTargetMCs();
    InitializeAllAsmParsers();
  });

  if (ks_err triple_err = ks_compute_triple(ks); triple_err != KS_ERR_OK) {
    return triple_err;
  }
  ks->TheTriple = Triple(ks->TripleName);

  // Reinitialization path: release the previous MC objects before
  // overwriting their slots. `ks_delete` only frees whatever is current,
  // so anything reachable here would otherwise leak.
  delete ks->MRI;
  ks->MRI = nullptr;
  delete ks->MAI;
  ks->MAI = nullptr;
  delete ks->MCII;
  ks->MCII = nullptr;
  delete ks->MSTI;
  ks->MSTI = nullptr;

  std::string Error;
  ks->TheTarget = TargetRegistry::lookupTarget("", ks->TheTriple, Error);
  if (!ks->TheTarget) {
    return KS_ERR_ARCH;
  }

  ks->MRI = ks->TheTarget->createMCRegInfo(ks->TheTriple);
  assert(ks->MRI && "Unable to create target register info!");

  ks->MAI =
      ks->TheTarget->createMCAsmInfo(*ks->MRI, ks->TheTriple, ks->MCOptions);
  assert(ks->MAI && "Unable to create target asm info!");

  // NASM/MASM convention: `$` denotes the current location counter. LLVM's
  // MCAsmInfo defaults this off; turn it on for all keystone targets so
  // `b $` (issue #412) and `jmp $` Just Work.
  ks->MAI->setDollarIsPC(true);

  // Win32 stdcall mangles names like `_foo@4` (decoration suffix is the
  // argument byte count). Without this, the parser sees `@4` as an unknown
  // relocation specifier and rejects the symbol (issue #573). Letting `@`
  // sit inside the identifier means the symbol resolver receives the full
  // mangled name; known specifiers (`@PLT`, `@GOT`, ...) still match first.
  ks->MAI->setAllowAtInName(true);

  if (ks->Arch == KS_ARCH_X86 || ks->Arch == KS_ARCH_X64) {
    ks->MAI->setAssemblerDialect(ks->Syntax != KS_X86_SYNTAX_ATT);
  }

  // Propagate the engine-side Radix to MAI so getters/setters can run
  // before the first ks_assemble without dereferencing a null MAI.
  ks->MAI->setRadix(ks->Radix);

  ks->MCII = ks->TheTarget->createMCInstrInfo();
  assert(ks->MCII && "Unable to create target instr info!");

  std::string Features = ks->FeaturesStr;
  if (Features.empty() && ks->Arch == KS_ARCH_AARCH64)
    Features = "+all";
  ks->MSTI = ks->TheTarget->createMCSubtargetInfo(ks->TheTriple, ks->CPU,
                                                  Features);
  if (!ks->MSTI)
    return KS_ERR_FEATURE;

  return KS_ERR_OK;
}

#endif
