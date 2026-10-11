/* Keystone Assembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
/* By Amaan Qureshi <git@amaanq.com>, 2025 */

#include "ks.h"
#include <cerrno>
#include <cstdlib>
#include <cstring>
#ifdef KEYSTONE_HAS_EVM
#include "evm.h"
#endif
#include "keystone/keystone.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include <sstream>

using namespace llvm_ks;

/**
 * Get the Keystone API version.
 *
 * @major: major number of the API version
 * @minor: minor number of the API version
 *
 * @return: a hexical number encoding both major & minor versions. The returned
 * value is represented as `(major << 8 | minor)`.
 *
 * For example, if the major version is 1, and the minor version is 2, then the
 * return value would be 0x0102.
 *
 * NOTE: if you only care about the return value, you may set both @major &
 * @minor to NULL.
 */
KEYSTONE_EXPORT
unsigned int ks_version(unsigned int *major, unsigned int *minor) {
  if (major) {
    *major = KS_VERSION_MAJOR;
  }

  if (minor) {
    *minor = KS_VERSION_MINOR;
  }

  return KS_MAKE_VERSION(KS_VERSION_MAJOR, KS_VERSION_MINOR);
}

/**
 * Determine if the given architecture is supported by this library.
 *
 * @arch: architecture type (see `ks_arch`)
 *
 * @return: `true` if this library supports the given arch, `false` otherwise.
 */
KEYSTONE_EXPORT
bool ks_arch_supported(ks_arch arch) {
  return ks_describe_arch(arch).has_value();
}

/**
 * Create a new Keystone engine instance.
 *
 * The endianness and bit width are automatically determined based on the
 * architecture. To set a specific endianness or bit width, use
 * `ks_set_endian()` or `ks_set_width()` after creating the engine.
 *
 * @ks: pointer to an uninitialized `ks_engine`, which will be updated.
 * @arch: architecture type (see `ks_arch`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_new(ks_engine **ks, ks_arch arch) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }
  std::optional<ks_arch_desc> desc = ks_describe_arch(arch);
  if (!desc) {
    return KS_ERR_ARCH;
  }

  ks_engine *engine = new (std::nothrow)
      ks_engine(arch, desc->DefaultEndian, desc->DefaultWidth);
  if (engine == nullptr) {
    return KS_ERR_MEM;
  }

  *ks = engine;

  return KS_ERR_OK;
}

/**
 * Delete the Keystone engine instance.
 *
 * @ks: Keystone engine handle
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_delete(ks_engine *ks) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  // The MC objects are allocated by `ks_init` for every non-EVM target,
  // even on engines that later switch to EVM via `ks_set_arch`. Free
  // them unconditionally here.
  if (ks->Errors) {
    free(ks->Errors);
  }

  delete ks->MRI;
  delete ks->MAI;
  delete ks->MCII;
  delete ks->MSTI;
  delete ks;
  return KS_ERR_OK;
}

/**
 * Get the string representation of a Keystone error code.
 *
 * @code: error code (see `ks_err`)
 *
 * @return: string representation of the error code. The string is statically
 * allocated and should not be freed by the caller.
 */
KEYSTONE_EXPORT
const char *ks_strerror(ks_err code) {
  switch (code) {
  case KS_ERR_OK:
    return "OK (KS_ERR_OK)";
  case KS_ERR_MEM:
    return "No memory available or memory not present (KS_ERR_MEM)";
  case KS_ERR_HANDLE:
    return "Invalid handle (KS_ERR_HANDLE)";
  case KS_ERR_ARCH:
    return "Invalid/unsupported architecture (KS_ERR_ARCH)";
  case KS_ERR_ENDIAN:
    return "Invalid/unsupported endianness (KS_ERR_ENDIAN)";
  case KS_ERR_WIDTH:
    return "Invalid/unsupported CPU width (KS_ERR_WIDTH)";
  case KS_ERR_FEATURE:
    return "Unsupported CPU feature (KS_ERR_FEATURE)";
  case KS_ERR_CPU:
    return "Invalid CPU model (KS_ERR_CPU)";
  case KS_ERR_VERSION:
    return "Different API version between core & binding (KS_ERR_VERSION)";
  case KS_ERR_OPT_INVALID:
    return "Invalid option (KS_ERR_OPT_INVALID)";

  // generic input assembly errors - parser specific
  case KS_ERR_ASM_SYNTAX:
    return "General syntax error in assembly (KS_ERR_ASM_SYNTAX)";
  case KS_ERR_ASM_INVALID_TOKEN:
    return "Invalid token or unexpected token (KS_ERR_ASM_INVALID_TOKEN)";
  case KS_ERR_ASM_INVALID_DIRECTIVE:
    return "Unknown or invalid directive (KS_ERR_ASM_INVALID_DIRECTIVE)";
  case KS_ERR_ASM_MISSING_SYMBOL:
    return "Referenced symbol not found (KS_ERR_ASM_MISSING_SYMBOL)";
  case KS_ERR_ASM_INVALID_SYMBOL:
    return "Symbol is invalid or redefined (KS_ERR_ASM_INVALID_SYMBOL)";
  case KS_ERR_ASM_MACRO_ERROR:
    return "Error in macro definition or usage (KS_ERR_ASM_MACRO_ERROR)";
  case KS_ERR_ASM_INSN_UNSUPPORTED:
    return "Instruction not supported in current mode "
           "(KS_ERR_ASM_INSN_UNSUPPORTED)";
  case KS_ERR_ASM_EXPR_ERROR:
    return "Error in expression parsing (KS_ERR_ASM_EXPR_ERROR)";
  case KS_ERR_ASM_FIXUP_INVALID:
    return "Invalid fixup/relocation (KS_ERR_ASM_FIXUP_INVALID)";
  case KS_ERR_ASM_LABEL_INVALID:
    return "Invalid label (KS_ERR_ASM_LABEL_INVALID)";

  // generic input assembly errors - architecture specific
  case KS_ERR_ASM_INVALID_OPERAND:
    return "Invalid instruction operand (KS_ERR_ASM_INVALID_OPERAND)";
  case KS_ERR_ASM_MISSING_FEATURE:
    return "Required CPU feature is missing (KS_ERR_ASM_MISSING_FEATURE)";
  case KS_ERR_ASM_MNEMONIC_FAIL:
    return "Unrecognized instruction mnemonic (KS_ERR_ASM_MNEMONIC_FAIL)";

  default:
    return "Unknown error code";
  }
}

/**
 * Get the architecture for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 *
 * @return: architecture type (see `ks_arch`).
 */
KEYSTONE_EXPORT
ks_arch ks_get_arch(ks_engine *ks) {
  if (!ks) {
    return KS_ARCH_X86; // Default to X86 if handle is NULL
  }

  return ks->Arch;
}

/**
 * Set the architecture. Note that this resets the engine to a blank slate,
 * cross-arch-meaningless errors, resolver, syntax, variant, features, and CPU
 * are cleared here. See keystone.h for the binding-side contract.
 */
KEYSTONE_EXPORT
ks_err ks_set_arch(ks_engine *ks, ks_arch arch) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }
  std::optional<ks_arch_desc> desc = ks_describe_arch(arch);
  if (!desc) {
    return KS_ERR_ARCH;
  }
  // No early-out for same-arch: the documented contract is that this
  // call resets the resolver / errors / features / etc., and bindings
  // (in particular the Rust wrapper) reclaim heap-owned state on
  // KS_ERR_OK regardless of whether the architecture actually changed.

  ks->Errnum = KS_ERR_OK;
  ks->ErrorCount = 0;
  if (ks->Errors) {
    free(ks->Errors);
    ks->Errors = nullptr;
  }
  ks->StoredErrors.clear();
  ks->SymbolResolver = {};
  ks->Syntax = KS_X86_SYNTAX_INTEL;
  ks->ArchVariant = KS_ARCH_VARIANT_NONE;
  ks->FeaturesStr.clear();
  ks->CPU.clear();

  ks->Arch = arch;
  ks->Endian = desc->DefaultEndian;
  ks->Width = desc->DefaultWidth;
  ks->NeedsInitialization = true;

  return KS_ERR_OK;
}

/**
 * Get the endianness for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 * @endian: endianness value (see `ks_endian`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_endian ks_get_endian(ks_engine *ks) {
  if (!ks) {
    return KS_ENDIAN_LITTLE; // Default to little-endian if handle is NULL
  }

  return ks->Endian;
}

/**
 * Set the endianness for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 * @endian: endianness value (see `ks_endian`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_endian(ks_engine *ks, ks_endian endian) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  if (!ks_endian_is_valid(ks->Arch, endian)) {
    return KS_ERR_ENDIAN;
  }

  if (ks->Endian == endian) {
    return KS_ERR_OK;
  }

  ks->Endian = endian;
  ks->NeedsInitialization = true;

  return KS_ERR_OK;
}

/**
 * Get the CPU bit width for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 *
 * @return: CPU width value (see `ks_width`).
 */
KEYSTONE_EXPORT
ks_width ks_get_width(ks_engine *ks) {
  if (!ks) {
    return KS_WIDTH_32; // Default to 32-bit width if handle is NULL
  }

  return ks->Width;
}

/**
 * Set the CPU bit width for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 * @width: CPU width value (see `ks_width`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_width(ks_engine *ks, ks_width width) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  if (!ks_width_is_valid(ks->Arch, width)) {
    return KS_ERR_WIDTH;
  }

  if (ks->Width == width) {
    return KS_ERR_OK;
  }

  ks->Width = width;
  ks->NeedsInitialization = true;

  return KS_ERR_OK;
}

/**
 * Get architecture variant for an existing Keystone engine instance.
 * This can be used to specify ARM-specific variants like V8, MCLASS, and EM.
 *
 * @ks: Keystone engine handle
 *
 * @return: architecture variant (see `ks_arch_variant`).
 */
KEYSTONE_EXPORT
int ks_get_arch_variant(ks_engine *ks) {
  if (!ks) {
    return KS_ARCH_VARIANT_NONE; // Default to no variant if handle is NULL
  }

  return ks->ArchVariant;
}

/**
 * Set architecture variant for an existing Keystone engine instance.
 * This can be used to specify ARM-specific variants like V8, MCLASS, and EM.
 *
 * @ks: Keystone engine handle
 * @variant: ARM architecture variant (see `ks_arch_variant`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_arch_variant(ks_engine *ks, int variant) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  if (ks->Arch != KS_ARCH_ARM && ks->Arch != KS_ARCH_THUMB) {
    return KS_ERR_ARCH;
  }

  if ((variant & ~KS_VARIANT_ARM_MASK) != 0) {
    return KS_ERR_ARCH;
  }

  ks->ArchVariant = variant;
  ks->NeedsInitialization = true;

  return KS_ERR_OK;
}

/**
 * Get the X86 assembly syntax for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: current X86 syntax value (see `ks_x86_syntax`).
 */
KEYSTONE_EXPORT
ks_x86_syntax ks_get_x86_syntax(ks_engine *ks) {
  if (!ks) {
    return KS_X86_SYNTAX_INTEL; // Default to Intel syntax if handle is NULL
  }

  return ks->Syntax;
}

/**
 * Set the X86 assembly syntax for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @syntax: X86 syntax value (see `ks_x86_syntax`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT ks_err ks_set_x86_syntax(ks_engine *ks, ks_x86_syntax syntax) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  if (ks->Arch != KS_ARCH_X86 && ks->Arch != KS_ARCH_X64) {
    return KS_ERR_OPT_INVALID;
  }

  switch (syntax) {
  case KS_X86_SYNTAX_ATT:
  case KS_X86_SYNTAX_NASM:
  case KS_X86_SYNTAX_INTEL:
    ks->Syntax = syntax;
    // If the engine is already initialized, set the dialect in MAI directly.
    if (!ks->NeedsInitialization) {
      ks->MAI->setAssemblerDialect(ks->Syntax != KS_X86_SYNTAX_ATT);
    }
    break;
  default:
    return KS_ERR_OPT_INVALID;
  }

  return KS_ERR_OK;
}

/**
 * Get the radix for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: current radix value (see `ks_radix`).
 */
KEYSTONE_EXPORT
ks_radix ks_get_radix(ks_engine *ks) {
  if (!ks) {
    return KS_RADIX_HEXADECIMAL; // Default to hexadecimal if handle is NULL
  }

  // Source of truth is the engine field; MAI may not be live yet.
  return ks->Radix;
}

/**
 * Set the radix for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @radix: radix value (see `ks_radix`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_radix(ks_engine *ks, ks_radix radix) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  switch (radix) {
  case KS_RADIX_BINARY:
  case KS_RADIX_OCTAL:
  case KS_RADIX_DECIMAL:
  case KS_RADIX_HEXADECIMAL:
  case KS_RADIX_BASE36:
    ks->Radix = radix;
    // Mirror into MAI when it already exists, otherwise ks_init will
    // pick the value up the first time it builds the asm info.
    if (ks->MAI) {
      ks->MAI->setRadix(radix);
    }
    break;
  default:
    return KS_ERR_OPT_INVALID;
  }

  return KS_ERR_OK;
}

/**
 * Get the ARM implicit IT mode for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @mode: IT mode value (see `ks_arm_it_mode`)
 */
KEYSTONE_EXPORT
ks_arm_it_mode ks_get_arm_it_mode(ks_engine *ks) {
  if (!ks) {
    return KS_ARM_IT_ALWAYS; // Default to always if handle is NULL
  }

  return (ks_arm_it_mode)ks->MCOptions.getImplicitIT();
}

/**
 * Set the ARM implicit IT mode for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @mode: IT mode value (see `ks_arm_it_mode`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_arm_it_mode(ks_engine *ks, ks_arm_it_mode mode) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  if (ks->Arch != KS_ARCH_ARM && ks->Arch != KS_ARCH_THUMB) {
    return KS_ERR_ARCH;
  }

  switch (mode) {
  case KS_ARM_IT_ALWAYS:
  case KS_ARM_IT_NEVER:
  case KS_ARM_IT_ARM_ONLY:
  case KS_ARM_IT_THUMB_ONLY:
    ks->MCOptions.setImplicitIT(mode);
    return KS_ERR_OK;
  default:
    return KS_ERR_OPT_INVALID;
  }
}

/**
 * Get the CSKY compressed instruction mode for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: true if compressed instructions are enabled, false otherwise.
 */
KEYSTONE_EXPORT
bool ks_get_csky_compressed(ks_engine *ks) {
  if (!ks) {
    return false; // Default to false if handle is NULL
  }

  return ks->MCOptions.isCSKYCompressed();
}

/**
 * Set the CSKY compressed instruction mode for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @enable: true to enable compressed instructions, false to disable
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_csky_compressed(ks_engine *ks, bool compressed) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  if (ks->Arch != KS_ARCH_CSKY) {
    return KS_ERR_ARCH;
  }

  ks->MCOptions.setCSKYCompressed(compressed);
  return KS_ERR_OK;
}

/**
 * Get CPU features for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: string representation of the features enabled in the engine. The
 * string is a comma-separated list of features, with each feature prefixed by
 * `+` or `-` to indicate whether it is enabled or disabled. The caller should
 * not free the returned string, as it is owned by the Keystone instance. The
 * string will be invalidated when the engine is reset or deleted, or when
 * `ks_set_feature()` is called again.
 */
KEYSTONE_EXPORT
const char *ks_get_feature(ks_engine *ks) {
  if (!ks) {
    return ""; // Return empty string if handle is NULL
  }

  return ks->FeaturesStr.c_str();
}

/**
 * Set CPU features for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @feature_str: string representation of the features to enable. This string
 * should be a comma-separated list of features supported by the architecture.
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_feature(ks_engine *ks, const char *features) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  std::string OldFeatures = ks->FeaturesStr;

  ks->FeaturesStr = "";

  if (features && *features != '\0') {
    std::string input(features);
    std::stringstream ss(input);
    std::string feature;
    bool first = true;

    while (std::getline(ss, feature, ',')) {
      // Trim whitespace
      feature.erase(0, feature.find_first_not_of(" \t"));
      feature.erase(feature.find_last_not_of(" \t") + 1);

      if (!feature.empty()) {
        if (!first) {
          ks->FeaturesStr += ",";
        }

        // Add + prefix if not already present
        if (feature[0] != '+' && feature[0] != '-') {
          ks->FeaturesStr += "+";
        }
        ks->FeaturesStr += feature;
        first = false;
      }
    }
  }

  ks->NeedsInitialization |= OldFeatures != ks->FeaturesStr;
  return KS_ERR_OK;
}

/**
 * Get CPU model for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: string representation of the CPU model. The caller should not free
 * the returned string, as it is owned by the Keystone instance. The string
 * will be invalidated when the engine is reset or deleted, or when
 * `ks_set_cpu()` is called again.
 */
KEYSTONE_EXPORT
const char *ks_get_cpu(ks_engine *ks) {
  if (!ks) {
    return ""; // Return empty string if handle is NULL
  }

  return ks->CPU.c_str();
}

/**
 * Set CPU model for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @cpu: CPU model
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_cpu(ks_engine *ks, const char *cpu) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  std::string OldCPU = ks->CPU;
  ks->CPU = cpu ? cpu : "";
  ks->NeedsInitialization |= OldCPU != ks->CPU;
  return KS_ERR_OK;
}

/**
 * Get the symbol resolver callback for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: pointer to the current symbol resolver, or NULL if not set.
 */
KEYSTONE_EXPORT
ks_sym_resolver ks_get_symbol_resolver(ks_engine *ks) {
  if (!ks) {
    return {}; // Return an empty resolver if handle is NULL
  }

  return ks->SymbolResolver;
}

/**
 * Set the symbol resolver callback for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @resolver: function pointer to the symbol resolver callback
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_symbol_resolver(ks_engine *ks, ks_sym_resolver resolver) {
  if (!ks) {
    return KS_ERR_HANDLE;
  }

  ks->SymbolResolver = resolver;
  return KS_ERR_OK;
}

/**
 * Assemble a string given its buffer and size.
 *
 * @ks: Keystone engine handle
 * @str: NULL-terminated assembly string. Use semicolons or newlines to
 * separate statements.
 * @address: address of the first assembly instruction, or 0 to ignore.
 * @encoding: array of bytes to contain the encoding.
 * @encoding_size: pointer to size of encoding array as an input parameter,
 * and actual size of encoding data as an output parameter.
 * @stat_count: pointer to number of statements as an output parameter.
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
static ks_err ks_asm_impl(ks_engine *ks, const char *str, uint64_t address,
                          unsigned char **encoding, size_t *encoding_size,
                          size_t *stat_count) {
  std::string ErrorMsg;
  std::string TripleName;

  if (!ks) {
    return KS_ERR_HANDLE;
  }

  if (!str) {
    return KS_ERR_ASM_SYNTAX;
  }

  // Clear errors from previous call
  ks->ErrorCount = 0;
  ks->Errnum = KS_ERR_OK;
  if (ks->Errors) {
    free(ks->Errors);
    ks->Errors = nullptr;
  }
  ks->StoredErrors.clear();

#ifdef KEYSTONE_HAS_EVM
  if (ks->Arch == KS_ARCH_EVM) {
    // Parse multiple EVM instructions
    std::string input(str);
    std::vector<unsigned char> bytecode;
    std::istringstream iss(input);
    std::string line;

    auto parse_uint = [](const std::string &s, unsigned base,
                         unsigned long &out) -> bool {
      if (s.empty()) {
        return false;
      }
      const char *first = s.c_str();
      char *end = nullptr;
      errno = 0;
      unsigned long v = std::strtoul(first, &end, base);
      if (errno != 0 || end == first ||
          static_cast<size_t>(end - first) != s.size()) {
        return false;
      }
      out = v;
      return true;
    };

    size_t parsed_statements = 0;
    while (std::getline(iss, line)) {
      // Trim whitespace
      line.erase(0, line.find_first_not_of(" \t\r\n"));
      line.erase(line.find_last_not_of(" \t\r\n") + 1);

      if (line.empty() || line[0] == ';' || line[0] == '#') {
        continue; // Skip empty lines and comments
      }

      // Split instruction and operands
      std::istringstream line_stream(line);
      std::string mnemonic;
      line_stream >> mnemonic;

      unsigned short opcode = evm_opcode(mnemonic);
      if (opcode == EVM_INS_INVALID) {
        return KS_ERR_ASM_MNEMONIC_FAIL;
      }

      bytecode.push_back((unsigned char)opcode);

      // Handle PUSH instructions with immediate data
      if (mnemonic.substr(0, 4) == "push" && mnemonic.length() > 4) {
        unsigned long push_size_ul = 0;
        if (!parse_uint(mnemonic.substr(4), 10, push_size_ul) ||
            push_size_ul == 0 || push_size_ul > 32) {
          return KS_ERR_ASM_MNEMONIC_FAIL;
        }
        size_t push_size = static_cast<size_t>(push_size_ul);
        std::string operand;

        if (!(line_stream >> operand)) {
          return KS_ERR_ASM_INVALID_OPERAND;
        }
        // Reject trailing junk: no extra tokens after the PUSH immediate.
        std::string trailing;
        if (line_stream >> trailing) {
          return KS_ERR_ASM_INVALID_OPERAND;
        }
        if (operand.size() >= 2 && operand[0] == '0' &&
            (operand[1] == 'x' || operand[1] == 'X')) {
          operand = operand.substr(2);
        }
        if (operand.empty() || operand.size() > push_size * 2) {
          return KS_ERR_ASM_INVALID_OPERAND;
        }
        operand =
            std::string(push_size * 2 - operand.size(), '0') + operand;

        for (size_t i = 0; i < operand.size(); i += 2) {
          unsigned long byte_val = 0;
          if (!parse_uint(operand.substr(i, 2), 16, byte_val) ||
              byte_val > 0xFF) {
            return KS_ERR_ASM_INVALID_OPERAND;
          }
          bytecode.push_back(static_cast<unsigned char>(byte_val));
        }
      }
      ++parsed_statements;
    }

    if (bytecode.empty()) {
      return KS_ERR_ASM_MNEMONIC_FAIL;
    }

    *encoding_size = bytecode.size();
    *stat_count = parsed_statements;
    *encoding = (unsigned char *)malloc(*encoding_size);
    if (!*encoding) {
      return KS_ERR_MEM;
    }

    for (size_t i = 0; i < bytecode.size(); i++) {
      (*encoding)[i] = bytecode[i];
    }

    return KS_ERR_OK;
  }
#endif // KEYSTONE_HAS_EVM

  if (ks->NeedsInitialization) {
    ks_err err = ks_init(ks);
    if (err != KS_ERR_OK) {
      return err;
    }
    ks->NeedsInitialization = false;
  }

  MCObjectFileInfo MOFI;
  MCContext Ctx(ks->TheTriple, *ks->MAI, *ks->MRI, *ks->MSTI, &ks->SrcMgr,
                true);
  Ctx.setBaseAddress(address);

  MOFI.initMCObjectFileInfo(Ctx, false, false);
  Ctx.setObjectFileInfo(&MOFI);

  std::unique_ptr<MCCodeEmitter> CE(
      ks->TheTarget->createMCCodeEmitter(*ks->MCII, Ctx));

  std::unique_ptr<MemoryBuffer> Buffer = MemoryBuffer::getMemBuffer(str);

  ks->SrcMgr.clearBuffers();
  ks->SrcMgr.AddNewSourceBuffer(std::move(Buffer), SMLoc());

  SmallString<1024> OutputBuffer;
  raw_svector_ostream OS(OutputBuffer);

  std::unique_ptr<MCAsmBackend> MAB(
      ks->TheTarget->createMCAsmBackend(*ks->MSTI, *ks->MRI, ks->MCOptions));
  MAB->setArch(ks->Arch);

  std::unique_ptr<MCObjectWriter> OW = MAB->createObjectWriter(OS);

  std::unique_ptr<MCStreamer> Streamer(ks->TheTarget->createMCObjectStreamer(
      ks->TheTriple, Ctx, std::move(MAB), std::move(OW), std::move(CE),
      *ks->MSTI));

  Streamer->setSymbolResolver(ks->SymbolResolver);
  Ctx.setSymbolResolver(ks->SymbolResolver);

  std::unique_ptr<MCAsmParser> Parser(
      createMCAsmParser(ks->SrcMgr, Ctx, *Streamer, *ks->MAI));

  std::unique_ptr<MCTargetAsmParser> TAP(
      ks->TheTarget->createMCAsmParser(*ks->MSTI, *Parser, *ks->MCII));

  if (!TAP) {
    return KS_ERR_MEM;
  }

  TAP->setKsSyntax(ks->Syntax);

  Parser->setTargetParser(*TAP);

  if ((ks->Arch == KS_ARCH_X86 || ks->Arch == KS_ARCH_X64) &&
      ks->Syntax == KS_X86_SYNTAX_NASM) {
    Parser->initializeDirectiveKindMap(KS_X86_SYNTAX_NASM);
    ks->MAI->setCommentString(";");
  }

  // Parse the input and handle any errors
  *stat_count = Parser->Run(false, address);

  // Drain any remaining per-statement pending errors into the accumulator,
  // then take everything legitimate that was reported during parsing.
  Parser->printPendingErrors();
  ks->StoredErrors = std::move(Parser->KsAccumulatedErrors);
  Parser->KsAccumulatedErrors.clear();
  // Append errors raised through MCContext::reportError (e.g. fixup-time).
  for (auto &E : Ctx.KsErrors) {
    MCAsmParser::MCPendingError P;
    P.Loc = E.Loc;
    P.Msg = E.Msg;
    P.Range = E.Range;
    ks->StoredErrors.push_back(std::move(P));
  }
  // If the parser flagged an error but didn't push anything legitimate
  // (e.g. lexer failed before producing a real diagnostic), still surface
  // a syntax error to the caller instead of a silent empty success.
  bool ParserHadError = Parser->hasHadError();
  if (!ks->StoredErrors.empty()) {
    ks->ErrorCount = ks->StoredErrors.size();
    ks->Errors = (ks_error_location *)calloc(ks->StoredErrors.size(),
                                             sizeof(ks_error_location));

    for (size_t i = 0; i < ks->StoredErrors.size(); ++i) {
      if (ks->StoredErrors[i].Loc.isValid()) {
        std::pair<unsigned int, unsigned int> LineAndCol =
            ks->SrcMgr.getLineAndColumn(ks->StoredErrors[i].Loc);
        ks->Errors[i].line_number = LineAndCol.first;
        ks->Errors[i].column_number = LineAndCol.second;
      }
      ks->Errors[i].error_message = ks->StoredErrors[i].Msg.c_str();
    }
  }

  ks->Errnum = Parser->getKsError();
  if (ks->Errnum != KS_ERR_OK) {
    return ks->Errnum;
  }

  // Pending errors collected during parsing should turn into a top-level
  // failure, not a silent KS_ERR_OK with empty output. Use the message text
  // to pick a more specific error code; fall back to KS_ERR_ASM_SYNTAX.
  if (!ks->StoredErrors.empty()) {
    // Pick the most specific error code by scanning every captured message;
    // some inputs produce a generic syntax message followed by a more
    // descriptive one (e.g. "unknown token in expression").
    auto pick = [&]() -> ks_err {
      for (const auto &E : ks->StoredErrors) {
        StringRef M = E.Msg;
        if (M.contains("invalid label"))
          return KS_ERR_ASM_LABEL_INVALID;
        if (M.contains("unrecognized instruction") ||
            M.contains("unknown instruction") || M.contains("unknown mnemonic"))
          return KS_ERR_ASM_MNEMONIC_FAIL;
        if (M.contains("unknown token in expression") ||
            M.contains("expected expression"))
          return KS_ERR_ASM_EXPR_ERROR;
        if (M.contains("invalid operand"))
          return KS_ERR_ASM_INVALID_OPERAND;
        if (M.contains("undefined symbol") || M.contains("symbol not found"))
          return KS_ERR_ASM_MISSING_SYMBOL;
        if (M.contains("macro"))
          return KS_ERR_ASM_MACRO_ERROR;
        if (M.contains("unknown directive") || M.contains("invalid directive"))
          return KS_ERR_ASM_INVALID_DIRECTIVE;
      }
      return KS_ERR_ASM_SYNTAX;
    };
    ks->Errnum = pick();
    return ks->Errnum;
  }
  if (ParserHadError || Ctx.hadError()) {
    ks->Errnum = KS_ERR_ASM_SYNTAX;
    return ks->Errnum;
  }

  // The OutputBuffer contains a full ELF object file; extract the .text
  // section contents (the raw machine code) for the caller.
  const unsigned char *Buf = (const unsigned char *)OutputBuffer.data();
  size_t BufSize = OutputBuffer.size();
  size_t TextOff = 0, TextSize = 0;

  // Wasm: output is a wasm module, magic 00 61 73 6d 01 00 00 00.
  // Walk sections, find the Code section (id=10), and extract the raw
  // instruction bytes of its single function body (without the body-size
  // / locals prefix and without the trailing 0x0B `end` marker).
  if (BufSize >= 8 && Buf[0] == 0x00 && Buf[1] == 0x61 && Buf[2] == 0x73 &&
      Buf[3] == 0x6D) {
    size_t P = 8;
    auto readLeb = [&](size_t &Pos) -> uint64_t {
      uint64_t V = 0;
      unsigned Shift = 0;
      while (Pos < BufSize) {
        uint8_t B = Buf[Pos++];
        V |= (uint64_t)(B & 0x7F) << Shift;
        if ((B & 0x80) == 0)
          break;
        Shift += 7;
      }
      return V;
    };
    while (P < BufSize) {
      uint8_t SecId = Buf[P++];
      uint64_t SecSize = readLeb(P);
      size_t SecStart = P;
      if (SecId == 10 /* Code */) {
        // Code section: vec of function bodies.
        size_t Cur = SecStart;
        uint64_t NumBodies = readLeb(Cur);
        if (NumBodies >= 1) {
          readLeb(Cur); // body size
          uint64_t LocalEntries = readLeb(Cur);
          for (uint64_t i = 0; i < LocalEntries; ++i) {
            readLeb(Cur); // count
            if (Cur < BufSize)
              ++Cur; // value type
          }
          // Body ends right before the trailing 0x0B end marker.
          // Compute body-payload end precisely: after the leading body-size
          // LEB, the next BodySize bytes are the body, ending with 0x0B.
          size_t BodyEndPrecise = 0;
          {
            size_t Q = SecStart;
            readLeb(Q); // num bodies
            size_t BodyLenStart = Q;
            uint64_t BS = readLeb(Q);
            BodyEndPrecise = Q + BS;
            (void)BodyLenStart;
          }
          if (BodyEndPrecise <= BufSize && BodyEndPrecise > 0 &&
              Buf[BodyEndPrecise - 1] == 0x0B) {
            TextOff = Cur;
            TextSize = BodyEndPrecise - 1 - Cur;
          }
        }
        break;
      }
      P = SecStart + SecSize;
    }
  }

  // Minimal ELF header parsing (handles ELFCLASS32 / ELFCLASS64, both endians)
  if (BufSize >= 64 && Buf[0] == 0x7F && Buf[1] == 'E' && Buf[2] == 'L' &&
      Buf[3] == 'F') {
    bool Is64 = Buf[4] == 2;
    bool IsLE = Buf[5] == 1;
    auto rd16 = [&](size_t o) -> uint16_t {
      return IsLE ? (uint16_t)(Buf[o] | (Buf[o + 1] << 8))
                  : (uint16_t)((Buf[o] << 8) | Buf[o + 1]);
    };
    auto rd32 = [&](size_t o) -> uint32_t {
      return IsLE ? (uint32_t)(Buf[o] | (Buf[o + 1] << 8) | (Buf[o + 2] << 16) |
                               ((uint32_t)Buf[o + 3] << 24))
                  : (uint32_t)(((uint32_t)Buf[o] << 24) |
                               ((uint32_t)Buf[o + 1] << 16) |
                               ((uint32_t)Buf[o + 2] << 8) | Buf[o + 3]);
    };
    auto rd64 = [&](size_t o) -> uint64_t {
      uint64_t a = rd32(o), b = rd32(o + 4);
      return IsLE ? (a | (b << 32)) : ((a << 32) | b);
    };

    uint64_t e_shoff = Is64 ? rd64(0x28) : rd32(0x20);
    uint16_t e_shentsize = rd16(Is64 ? 0x3A : 0x2E);
    uint16_t e_shnum = rd16(Is64 ? 0x3C : 0x30);

    if (e_shentsize && e_shnum &&
        e_shoff + (size_t)e_shentsize * e_shnum <= BufSize) {
      // Find the first SHT_PROGBITS (type=1) section with executable flag
      // (SHF_EXECINSTR=0x4). Keystone's ELFObjectWriter doesn't always emit
      // a usable section header string table, so we identify .text by
      // its type/flags rather than its name.
      for (unsigned i = 0; i < e_shnum; ++i) {
        size_t sh_off = e_shoff + (size_t)i * e_shentsize;
        uint32_t sh_type = rd32(sh_off + 4);
        uint64_t sh_flags = Is64 ? rd64(sh_off + 8) : rd32(sh_off + 8);
        size_t Off = Is64 ? rd64(sh_off + 0x18) : rd32(sh_off + 0x10);
        size_t Sz = Is64 ? rd64(sh_off + 0x20) : rd32(sh_off + 0x14);
        if (sh_type == 1 /* SHT_PROGBITS */ &&
            (sh_flags & 0x4) /* SHF_EXECINSTR */) {
          TextOff = Off;
          TextSize = Sz;
          break;
        }
      }
    }
  }

  if (TextOff == 0 || TextOff + TextSize > BufSize)
    TextSize = 0;

  *encoding_size = TextSize;
  // Always return a non-null pointer on success so callers can rely on it
  // even when the input legitimately produced zero bytes (e.g. directives
  // only). The allocation has at least 1 byte so free() works.
  *encoding = (unsigned char *)malloc(TextSize ? TextSize : 1);
  if (!*encoding)
    return KS_ERR_MEM;
  if (TextSize)
    memcpy(*encoding, Buf + TextOff, TextSize);

  return KS_ERR_OK;
}

/**
 * Public entry point: assemble a string and return both the encoded bytes
 * and any source-location errors in a single, caller-owned result.
 */
KEYSTONE_EXPORT
ks_err ks_assemble(ks_engine *ks, const char *str, uint64_t address,
                   ks_asm_result *out) {
  if (!out) {
    return KS_ERR_HANDLE;
  }

  // Zero the result upfront so partial fills don't leave dangling
  // pointers from previous calls visible to the caller.
  memset(out, 0, sizeof(*out));

  if (!ks) {
    out->code = KS_ERR_HANDLE;
    return KS_ERR_HANDLE;
  }

  unsigned char *encoding = nullptr;
  size_t encoding_size = 0;
  size_t stat_count = 0;

  ks_err code =
      ks_asm_impl(ks, str, address, &encoding, &encoding_size, &stat_count);

  out->code = code;
  out->bytes = encoding;
  out->size = encoding_size;
  out->stat_count = stat_count;

  // Deep-copy the engine-owned error array so the caller is free of
  // engine lifetime entanglement. Strings get strdup'd into the result.
  if (ks->ErrorCount > 0 && ks->Errors) {
    ks_error_location *copy = static_cast<ks_error_location *>(
        calloc(ks->ErrorCount, sizeof(ks_error_location)));
    if (copy) {
      for (size_t i = 0; i < ks->ErrorCount; ++i) {
        copy[i].line_number = ks->Errors[i].line_number;
        copy[i].column_number = ks->Errors[i].column_number;
        copy[i].error_message = ks->Errors[i].error_message
                                    ? strdup(ks->Errors[i].error_message)
                                    : nullptr;
      }
      out->errors = copy;
      out->error_count = ks->ErrorCount;
    }
  }

  return code;
}

/**
 * Release memory owned by `*r`. Safe to call on a zero-initialized result.
 */
KEYSTONE_EXPORT
void ks_asm_result_free(ks_asm_result *r) {
  if (!r) {
    return;
  }
  if (r->bytes) {
    free(r->bytes);
  }
  if (r->errors) {
    for (size_t i = 0; i < r->error_count; ++i) {
      // strdup'd copies in ks_assemble; cast away const for free().
      if (r->errors[i].error_message) {
        free(const_cast<char *>(r->errors[i].error_message));
      }
    }
    free(r->errors);
  }
  memset(r, 0, sizeof(*r));
}
