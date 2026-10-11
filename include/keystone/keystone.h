/* Keystone Assembler Engine (www.keystone-engine.org) */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
/* By Amaan Qureshi <git@amaanq.com>, 2025 */

#ifndef KEYSTONE_ENGINE_H
#define KEYSTONE_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _MSC_VER // MSVC compiler
#pragma warning(disable : 4201)
#pragma warning(disable : 4100)
#ifndef KEYSTONE_STATIC
#define KEYSTONE_EXPORT __declspec(dllexport)
#else
#define KEYSTONE_EXPORT
#endif
#else
#ifdef __GNUC__
#ifndef KEYSTONE_STATIC
#define KEYSTONE_EXPORT __attribute__((visibility("default")))
#else
#define KEYSTONE_EXPORT
#endif
#else
#define KEYSTONE_EXPORT
#endif
#endif

// Keystone API version
#define KS_API_MAJOR 1
#define KS_API_MINOR 0

// Keystone package version
#define KS_VERSION_MAJOR KS_API_MAJOR
#define KS_VERSION_MINOR KS_API_MINOR
#define KS_VERSION_EXTRA 0

// Pack major and minor into a single comparable integer. Major occupies
// the upper 16 bits so the encoding leaves headroom for >255 minor
// versions without colliding with major bumps.
#define KS_MAKE_VERSION(major, minor) (((major) << 16) | (minor))

/**
 * Keystone engine handle
 */
typedef struct ks_engine ks_engine;

/**
 * Error location structure containing information about where an error
 * occurred. Strings are owned by the surrounding `ks_asm_result`; do not
 * free them individually — call `ks_asm_result_free` instead.
 */
typedef struct ks_error_location {
  uint64_t line_number;      // 1-based line number
  uint64_t column_number;    // 1-based column number
  const char *error_message; // Error message (owned by ks_asm_result)
} ks_error_location;

/**
 * Symbol resolver structure for handling undefined symbols during assembly.
 *
 * When Keystone encounters undefined symbols while assembling code, it invokes
 * the provided resolver function to dynamically resolve these symbols to
 * values.
 *
 * The resolver structure contains:
 * - A user-defined payload, `payload`, that is passed to the resolver callback
 * - A function pointer, `resolve`, to the resolver callback
 *
 * The resolver callback receives:
 * @symbol: Name of the undefined symbol that needs resolution
 * @value: Pointer to a 64-bit integer where the symbol's value should be stored
 * @payload: The user-defined data provided in this structure
 *
 * The callback should:
 * 1. Return `true` if the symbol was resolved successfully, or `false` if not.
 * 2. Set the symbol's value by writing to the @value pointer if the symbol is
 * resolved.
 *
 * If a symbol cannot be resolved, the callback should return `false`,
 * which will cause `ks_assemble()` to fail with error `KS_ERR_ASM_SYMBOL_MISSING`.
 *
 * To register a symbol resolver, use the `ks_set_symbol_resolver()` function.
 */
typedef struct ks_sym_resolver {
  void *payload;
  bool (*resolve)(void *payload, const char *symbol, uint64_t *value);
} ks_sym_resolver;

/**
 * Keystone architectures
 */
typedef enum ks_arch {
  KS_ARCH_AARCH64 = 1, // AArch64 architecture
  KS_ARCH_AMDGPU,      // AMDGPU architecture
  KS_ARCH_ARM,         // ARM architecture
  KS_ARCH_AVR,         // AVR architecture
  KS_ARCH_BPF,         // BPF (Berkeley Packet Filter) architecture
  KS_ARCH_CSKY,        // CSKY architecture
  KS_ARCH_EVM,         // Ethernet Virtual Machine architecture
  KS_ARCH_LANAI,       // Lanai architecture
  KS_ARCH_LOONGARCH,   // LoongArch architecture
  KS_ARCH_HEXAGON,     // Hexagon architecture
  KS_ARCH_M68K,        // M68K architecture
  KS_ARCH_MIPS,        // Mips architecture
  KS_ARCH_MSP430,      // MSP430 architecture
  KS_ARCH_PPC,         // PowerPC architecture
  KS_ARCH_RISCV,       // RISC-V architecture
  KS_ARCH_SPARC,       // Sparc architecture
  KS_ARCH_SYSTEMZ,     // SystemZ architecture (S390X)
  KS_ARCH_THUMB,       // Thumb architecture
  KS_ARCH_VE,          // VE (Vector Engine) architecture
  KS_ARCH_WASM,        // WebAssembly architecture
  KS_ARCH_X86,         // X86 architecture
  KS_ARCH_X64,         // X86-64 architecture
  KS_ARCH_XTENSA,      // Xtensa architecture
} ks_arch;

/**
 * Keystone architecture bit widths
 */
typedef enum ks_width {
  KS_WIDTH_16 = 16, // 16-bit architecture
  KS_WIDTH_32 = 32, // 32-bit architecture
  KS_WIDTH_64 = 64, // 64-bit architecture
} ks_width;

/**
 * Keystone architecture variants
 *
 * Used to specify architecture-specific variants that are neither
 * CPU models nor optional features, but fundamental target properties.
 *
 * Note: the `THUMB_*` values intentionally alias the `ARM_*` values
 * (Thumb is a sub-encoding of ARM, so the same internal variant flags
 * apply). Only one variant family should be used per engine — the one
 * matching its `ks_arch`.
 */
typedef enum ks_arch_variant {
  KS_ARCH_VARIANT_NONE,

  // ARM
  KS_ARCH_VARIANT_ARM_V7 = 1 << 0,     // ARMv7 A32 encodings for ARM
  KS_ARCH_VARIANT_ARM_MCLASS = 1 << 1, // ARM Cortex-M class
  KS_ARCH_VARIANT_ARM_EM = 1 << 2,     // ARM Cortex-M class

  // Thumb — alias the ARM values; same internal flags
  KS_ARCH_VARIANT_THUMB_V7 = KS_ARCH_VARIANT_ARM_V7,
  KS_ARCH_VARIANT_THUMB_MCLASS = KS_ARCH_VARIANT_ARM_MCLASS,
  KS_ARCH_VARIANT_THUMB_EM = KS_ARCH_VARIANT_ARM_EM,
} ks_arch_variant;

typedef enum ks_endian {
  KS_ENDIAN_LITTLE = 1, // Little-endian
  KS_ENDIAN_BIG = 2,    // Big-endian
} ks_endian;

/**
 * Keystone error codes
 */
typedef enum ks_err {
  KS_ERR_OK = 0,      // No error
  KS_ERR_MEM,         // Out-Of-Memory (OOM) error
  KS_ERR_HANDLE,      // Invalid handle
  KS_ERR_ARCH,        // Invalid/unsupported architecture
  KS_ERR_ENDIAN,      // Invalid/unsupported endianness
  KS_ERR_WIDTH,       // Invalid/unsupported CPU width
  KS_ERR_FEATURE,     // Invalid/unsupported feature
  KS_ERR_CPU,         // Invalid/unsupported CPU
  KS_ERR_VERSION,     // Invalid/unsupported version
  KS_ERR_OPT_INVALID, // Invalid/unsupported option

  // Assembly errors
  KS_ERR_ASM_SYNTAX,            // General syntax error in assembly
  KS_ERR_ASM_INVALID_TOKEN,     // Invalid token or unexpected token
  KS_ERR_ASM_INVALID_DIRECTIVE, // Unknown or invalid directive
  KS_ERR_ASM_MISSING_SYMBOL,    // Referenced symbol not found
  KS_ERR_ASM_INVALID_SYMBOL,    // Symbol is invalid or redefined
  KS_ERR_ASM_MACRO_ERROR,       // Error in macro definition or usage
  KS_ERR_ASM_INSN_UNSUPPORTED,  // Instruction not supported in current mode
  KS_ERR_ASM_EXPR_ERROR,        // Error in expression parsing
  KS_ERR_ASM_FIXUP_INVALID,     // Invalid fixup/relocation
  KS_ERR_ASM_LABEL_INVALID,     // Invalid label
  KS_ERR_ASM_INVALID_OPERAND,   // Invalid instruction operand
  KS_ERR_ASM_MISSING_FEATURE,   // Required CPU feature is missing
  KS_ERR_ASM_MNEMONIC_FAIL,     // Unrecognized instruction mnemonic
} ks_err;

/**
 * Result of `ks_assemble`. Carries both the encoded bytes (on success)
 * and any rich source-location error messages (on failure or partial
 * success). All allocated members are owned by the result and freed by a
 * single `ks_asm_result_free` call.
 *
 * Typical usage:
 *
 * ```c
 * ks_asm_result r = {0};
 * ks_err code = ks_assemble(ks, "mov rax, 1", 0, &r);
 * if (code == KS_ERR_OK) {
 *     // r.bytes / r.size hold the encoding
 * } else {
 *     for (size_t i = 0; i < r.error_count; i++) {
 *         // r.errors[i].line_number, .column_number, .error_message
 *     }
 * }
 * ks_asm_result_free(&r);
 * ```
 */
typedef struct ks_asm_result {
  ks_err code;                // Same as ks_assemble's return value
  unsigned char *bytes;       // Encoded bytes (NULL if none)
  size_t size;                // Number of bytes in `bytes`
  size_t stat_count;          // Number of statements parsed
  ks_error_location *errors;  // Error array (NULL if none)
  size_t error_count;         // Number of entries in `errors`
} ks_asm_result;

/**
 * Keystone syntax options
 */
typedef enum ks_x86_syntax {
  KS_X86_SYNTAX_ATT,   // AT&T syntax
  KS_X86_SYNTAX_INTEL, // Intel syntax
  KS_X86_SYNTAX_NASM,  // NASM syntax
} ks_x86_syntax;

/**
 * Keystone radix options
 */
typedef enum ks_radix {
  KS_RADIX_BINARY = 2,       // Binary radix (2)
  KS_RADIX_OCTAL = 8,        // Octal radix (8)
  KS_RADIX_DECIMAL = 10,     // Decimal radix (10)
  KS_RADIX_HEXADECIMAL = 16, // Hexadecimal radix (16)
  KS_RADIX_BASE36 = 36,      // Base 36 radix (36)
} ks_radix;

/**
 * Keystone ARM Implicit IT (If-Then) block options
 */
typedef enum ks_arm_it_mode {
  KS_ARM_IT_ALWAYS,     // Always enable implicit IT blocks
  KS_ARM_IT_NEVER,      // Never enable implicit IT blocks
  KS_ARM_IT_ARM_ONLY,   // Enable implicit IT blocks for ARM only
  KS_ARM_IT_THUMB_ONLY, // Enable implicit IT blocks for THUMB only
} ks_arm_it_mode;

/**
 * Get the Keystone API version.
 *
 * @major: major number of the API version (may be NULL)
 * @minor: minor number of the API version (may be NULL)
 *
 * @return: a packed integer with major in the upper 16 bits and minor in
 * the lower 16 bits, i.e. `KS_MAKE_VERSION(major, minor)`. For major 1
 * and minor 2 the return value would be `0x00010002`.
 */
KEYSTONE_EXPORT
unsigned int ks_version(unsigned int *major, unsigned int *minor);

/**
 * Determine if the given architecture is supported by this library.
 *
 * @arch: architecture type (see `ks_arch`)
 *
 * @return: `true` if this library supports the given arch, `false` otherwise.
 */
KEYSTONE_EXPORT
bool ks_arch_supported(ks_arch arch);

/**
 * Create a new Keystone engine instance.
 *
 * @ks: pointer to an uninitialized `ks_engine`, which will be updated.
 * @arch: architecture type (see `ks_arch`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_new(ks_engine **ks, ks_arch arch);

/**
 * Delete the Keystone engine instance.
 *
 * @ks: Keystone engine handle
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_delete(ks_engine *ks);

/**
 * Get the string representation of a Keystone error code.
 *
 * @code: error code (see `ks_err`)
 *
 * @return: string representation of the error code. The string is statically
 * allocated and should not be freed by the caller.
 */
KEYSTONE_EXPORT
const char *ks_strerror(ks_err code);

/**
 * Get the architecture for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 *
 * @return: architecture type (see `ks_arch`).
 */
KEYSTONE_EXPORT
ks_arch ks_get_arch(ks_engine *ks);

/**
 * Switch an engine's architecture. Resets endian, width, variant,
 * X86 syntax, features, CPU, symbol resolver, and error state to the
 * new arch's defaults; downstream LLVM objects are rebuilt on the next
 * `ks_assemble` call. Bindings owning extra heap state attached to the
 * engine must release it on success.
 *
 * @return: `KS_ERR_OK` on success.
 */
KEYSTONE_EXPORT
ks_err ks_set_arch(ks_engine *ks, ks_arch arch);

/**
 * Get the endianness for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 *
 * @return: endianness value (see `ks_endian`).
 */
KEYSTONE_EXPORT
ks_endian ks_get_endian(ks_engine *ks);

/**
 * Set the endianness for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 * @endian: endianness value (see `ks_endian`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_endian(ks_engine *ks, ks_endian endian);

/**
 * Get the CPU bit width for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 *
 * @return: CPU width value (see `ks_width`).
 */
KEYSTONE_EXPORT
ks_width ks_get_width(ks_engine *ks);

/**
 * Set the CPU bit width for an existing Keystone engine instance.
 *
 * @ks: Keystone engine handle
 * @width: CPU width value (see `ks_width`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_width(ks_engine *ks, ks_width width);

/**
 * Get architecture variant for an existing Keystone engine instance.
 * This can be used to specify ARM-specific variants like V8, MCLASS, and EM.
 *
 * @ks: Keystone engine handle
 *
 * @return: architecture variant (see `ks_arch_variant`).
 */
KEYSTONE_EXPORT
int ks_get_arch_variant(ks_engine *ks);

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
ks_err ks_set_arch_variant(ks_engine *ks, int variant);

/**
 * Get the X86 assembly syntax for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: current X86 syntax value (see `ks_x86_syntax`).
 */
KEYSTONE_EXPORT
ks_x86_syntax ks_get_x86_syntax(ks_engine *ks);

/**
 * Set the X86 assembly syntax for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @syntax: X86 syntax value (see `ks_x86_syntax`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_x86_syntax(ks_engine *ks, ks_x86_syntax syntax);

/**
 * Get the radix for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: current radix value (see `ks_radix`).
 */
KEYSTONE_EXPORT
ks_radix ks_get_radix(ks_engine *ks);

/**
 * Set the radix of unprefixed integer literals. `0x` and `0b` prefixes
 * still apply.
 *
 * @ks: Keystone engine handle
 * @radix: radix value (see `ks_radix`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_radix(ks_engine *ks, ks_radix radix);

/**
 * Get the ARM implicit IT mode for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @mode: IT mode value (see `ks_arm_it_mode`)
 */
KEYSTONE_EXPORT
ks_arm_it_mode ks_get_arm_it_mode(ks_engine *ks);

/**
 * Set the ARM implicit IT mode for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @mode: IT mode value (see `ks_arm_it_mode`)
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_arm_it_mode(ks_engine *ks, ks_arm_it_mode mode);

/**
 * Get the CSKY compressed instruction mode for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: true if compressed instructions are enabled, false otherwise.
 */
KEYSTONE_EXPORT
bool ks_get_csky_compressed(ks_engine *ks);

/**
 * Set the CSKY compressed instruction mode for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @enable: true to enable compressed instructions, false to disable
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_csky_compressed(ks_engine *ks, bool compressed);

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
const char *ks_get_feature(ks_engine *ks);

/**
 * Set CPU features for the Keystone engine.
 *
 * The value is stored on the engine and applied to the subtarget during
 * the next assembly call. Validation is deferred to that point — an
 * unknown feature name surfaces there (typically as
 * `KS_ERR_ASM_MISSING_FEATURE` or no-op), not from this setter.
 *
 * `KS_ARCH_AARCH64` enables every extension (`all`) until a list replaces it.
 *
 * @ks: Keystone engine handle
 * @features: comma-separated list of feature names with `+`/`-` prefixes.
 *
 * @return: `KS_ERR_OK` on success, `KS_ERR_HANDLE` if `ks` is NULL.
 */
KEYSTONE_EXPORT
ks_err ks_set_feature(ks_engine *ks, const char *features);

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
const char *ks_get_cpu(ks_engine *ks);

/**
 * Set CPU model for the Keystone engine.
 *
 * The value is stored on the engine and applied to the subtarget during
 * the next assembly call. Validation is deferred to that point — an
 * unknown CPU surfaces there, not from this setter.
 *
 * @ks: Keystone engine handle
 * @cpu: CPU model
 *
 * @return: `KS_ERR_OK` on success, `KS_ERR_HANDLE` if `ks` is NULL.
 */
KEYSTONE_EXPORT
ks_err ks_set_cpu(ks_engine *ks, const char *cpu);

/**
 * Get the symbol resolver callback for the Keystone engine.
 *
 * @ks: Keystone engine handle
 *
 * @return: the current symbol resolver, with a NULL `resolve` if none is set.
 */
KEYSTONE_EXPORT
ks_sym_resolver ks_get_symbol_resolver(ks_engine *ks);

/**
 * Set the symbol resolver callback for the Keystone engine.
 *
 * @ks: Keystone engine handle
 * @resolver: the resolver callback and its payload
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure.
 */
KEYSTONE_EXPORT
ks_err ks_set_symbol_resolver(ks_engine *ks, ks_sym_resolver resolver);

/**
 * Assemble a string and return both the encoded bytes and any source
 * location errors in a single result.
 *
 * @ks: Keystone engine handle
 * @str: NULL-terminated assembly string. Use semicolons or newlines to
 * separate statements.
 * @address: address of the first assembly instruction, or 0 to ignore.
 * @out: pointer to a caller-allocated `ks_asm_result` that will be
 * filled in. On entry it may be zero-initialized; on return the caller
 * owns its contents and must call `ks_asm_result_free` to release them.
 *
 * @return: `KS_ERR_OK` on success, or any other value on failure. The
 * same code is also written into `out->code` for convenience.
 *
 * Compared to the older `ks_asm` + `ks_get_error_details` pair this
 * keeps each call's output self-contained (no engine-owned state shared
 * across calls), simplifies binding code, and matches the lifetime
 * model that idiomatic Rust / Go / Python bindings already expect.
 */
KEYSTONE_EXPORT
ks_err ks_assemble(ks_engine *ks, const char *str, uint64_t address,
                   ks_asm_result *out);

/**
 * Release memory owned by `*r`. Safe to call on a zero-initialized
 * result. After the call `*r` is zeroed.
 */
KEYSTONE_EXPORT
void ks_asm_result_free(ks_asm_result *r);

#ifdef __cplusplus
}
#endif

#endif
