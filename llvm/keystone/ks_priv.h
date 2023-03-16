/* Keystone Assembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */

#ifndef KS_PRIV_H
#define KS_PRIV_H

#include <stdint.h>

#include "../../include/keystone/keystone.h"

#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCTargetOptionsCommandFlags.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"

// These are masks of supported modes for each cpu/arch.
// They should be updated when changes are made to the ks_mode enum typedef.
#define KS_MODE_ARM_MASK    (KS_MODE_ARM|KS_MODE_THUMB|KS_MODE_LITTLE_ENDIAN|KS_MODE_BIG_ENDIAN|KS_MODE_V8)
#define KS_MODE_MIPS_MASK   (KS_MODE_MIPS32|KS_MODE_MIPS64|KS_MODE_LITTLE_ENDIAN|KS_MODE_BIG_ENDIAN)
#define KS_MODE_X86_MASK    (KS_MODE_16|KS_MODE_32|KS_MODE_64|KS_MODE_LITTLE_ENDIAN)
#define KS_MODE_PPC_MASK    (KS_MODE_PPC32|KS_MODE_PPC64|KS_MODE_LITTLE_ENDIAN|KS_MODE_BIG_ENDIAN)
#define KS_MODE_SPARC_MASK  (KS_MODE_V9|KS_MODE_SPARC32|KS_MODE_SPARC64|KS_MODE_LITTLE_ENDIAN|KS_MODE_BIG_ENDIAN)
#define KS_MODE_HEXAGON_MASK  (KS_MODE_BIG_ENDIAN)
#define KS_MODE_SYSTEMZ_MASK  (KS_MODE_BIG_ENDIAN)
#define KS_MODE_ARM64_MASK  (KS_MODE_LITTLE_ENDIAN)
#define KS_MODE_M68K_MASK   (KS_MODE_BIG_ENDIAN)
#define KS_MODE_RISCV_MASK (KS_MODE_RISCV32|KS_MODE_RISCV64|KS_MODE_LITTLE_ENDIAN)


#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))

struct ks_struct;

// return 0 on success, -1 on failure
typedef void (*ks_args_ks_t)(struct ks_struct*);

struct ks_struct {
    ks_arch arch;
    int mode;
    unsigned int errnum;
    ks_opt_value syntax;

    ks_args_ks_t init_arch = nullptr;
    const Target *TheTarget = nullptr;
    std::string TripleName;
    SourceMgr SrcMgr;
    MCAsmBackend *MAB = nullptr;
    MCTargetOptions MCOptions;
    MCRegisterInfo *MRI = nullptr;
    MCAsmInfo *MAI = nullptr;
    MCInstrInfo *MCII = nullptr;
    std::string FeaturesStr;
    MCSubtargetInfo *STI = nullptr;
    MCObjectFileInfo MOFI;
    ks_sym_resolver sym_resolver = nullptr;

    ks_struct(ks_arch arch, int mode, unsigned int errnum, ks_opt_value syntax)
        : arch(arch), mode(mode), errnum(errnum), syntax(syntax) { }
};


#endif
