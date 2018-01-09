/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Subtarget Enumeration Source Fragment                                      *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_SUBTARGETINFO_ENUM
#undef GET_SUBTARGETINFO_ENUM
namespace llvm_ks {
namespace PPC {
enum : uint64_t {
  DeprecatedDST = 0,
  Directive32 = 1,
  Directive64 = 2,
  Directive440 = 3,
  Directive601 = 4,
  Directive602 = 5,
  Directive603 = 6,
  Directive604 = 7,
  Directive620 = 8,
  Directive750 = 9,
  Directive970 = 10,
  Directive7400 = 11,
  DirectiveA2 = 12,
  DirectiveE500mc = 13,
  DirectiveE5500 = 14,
  DirectivePwr3 = 15,
  DirectivePwr4 = 16,
  DirectivePwr5 = 17,
  DirectivePwr5x = 18,
  DirectivePwr6 = 19,
  DirectivePwr6x = 20,
  DirectivePwr7 = 21,
  DirectivePwr8 = 22,
  Feature64Bit = 23,
  Feature64BitRegs = 24,
  FeatureAltivec = 25,
  FeatureBPERMD = 26,
  FeatureBookE = 27,
  FeatureCMPB = 28,
  FeatureCRBits = 29,
  FeatureDirectMove = 30,
  FeatureE500 = 31,
  FeatureExtDiv = 32,
  FeatureFCPSGN = 33,
  FeatureFPCVT = 34,
  FeatureFPRND = 35,
  FeatureFRE = 36,
  FeatureFRES = 37,
  FeatureFRSQRTE = 38,
  FeatureFRSQRTES = 39,
  FeatureFSqrt = 40,
  FeatureFloat128 = 41,
  FeatureFusion = 42,
  FeatureHTM = 43,
  FeatureICBT = 44,
  FeatureISEL = 45,
  FeatureInvariantFunctionDescriptors = 46,
  FeatureLDBRX = 47,
  FeatureLFIWAX = 48,
  FeatureMFOCRF = 49,
  FeatureMFTB = 50,
  FeatureMSYNC = 51,
  FeatureP8Altivec = 52,
  FeatureP8Crypto = 53,
  FeatureP8Vector = 54,
  FeaturePOPCNTD = 55,
  FeaturePPC4xx = 56,
  FeaturePPC6xx = 57,
  FeaturePartwordAtomic = 58,
  FeatureQPX = 59,
  FeatureRecipPrec = 60,
  FeatureSPE = 61,
  FeatureSTFIWX = 62,
  FeatureSoftFloat = 63,
  FeatureVSX = 64
};
}
} // end llvm namespace
#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC
namespace llvm_ks {
// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKV PPCFeatureKV[] = {
  { "64bit", "Enable 64-bit instructions", { PPC::Feature64Bit }, { } },
  { "64bitregs", "Enable 64-bit registers usage for ppc32 [beta]", { PPC::Feature64BitRegs }, { } },
  { "altivec", "Enable Altivec instructions", { PPC::FeatureAltivec }, { } },
  { "booke", "Enable Book E instructions", { PPC::FeatureBookE }, { PPC::FeatureICBT } },
  { "bpermd", "Enable the bpermd instruction", { PPC::FeatureBPERMD }, { } },
  { "cmpb", "Enable the cmpb instruction", { PPC::FeatureCMPB }, { } },
  { "crbits", "Use condition-register bits individually", { PPC::FeatureCRBits }, { } },
  { "crypto", "Enable POWER8 Crypto instructions", { PPC::FeatureP8Crypto }, { PPC::FeatureP8Altivec } },
  { "direct-move", "Enable Power8 direct move instructions", { PPC::FeatureDirectMove }, { PPC::FeatureVSX } },
  { "e500", "Enable E500/E500mc instructions", { PPC::FeatureE500 }, { } },
  { "extdiv", "Enable extended divide instructions", { PPC::FeatureExtDiv }, { } },
  { "fcpsgn", "Enable the fcpsgn instruction", { PPC::FeatureFCPSGN }, { } },
  { "float128", "Enable the __float128 data type for IEEE-754R Binary128.", { PPC::FeatureFloat128 }, { PPC::FeatureVSX } },
  { "fpcvt", "Enable fc[ft]* (unsigned and single-precision) and lfiwzx instructions", { PPC::FeatureFPCVT }, { } },
  { "fprnd", "Enable the fri[mnpz] instructions", { PPC::FeatureFPRND }, { } },
  { "fre", "Enable the fre instruction", { PPC::FeatureFRE }, { } },
  { "fres", "Enable the fres instruction", { PPC::FeatureFRES }, { } },
  { "frsqrte", "Enable the frsqrte instruction", { PPC::FeatureFRSQRTE }, { } },
  { "frsqrtes", "Enable the frsqrtes instruction", { PPC::FeatureFRSQRTES }, { } },
  { "fsqrt", "Enable the fsqrt instruction", { PPC::FeatureFSqrt }, { } },
  { "fusion", "Target supports add/load integer fusion.", { PPC::FeatureFusion }, { } },
  { "htm", "Enable Hardware Transactional Memory instructions", { PPC::FeatureHTM }, { } },
  { "icbt", "Enable icbt instruction", { PPC::FeatureICBT }, { } },
  { "invariant-function-descriptors", "Assume function descriptors are invariant", { PPC::FeatureInvariantFunctionDescriptors }, { } },
  { "isel", "Enable the isel instruction", { PPC::FeatureISEL }, { } },
  { "ldbrx", "Enable the ldbrx instruction", { PPC::FeatureLDBRX }, { } },
  { "lfiwax", "Enable the lfiwax instruction", { PPC::FeatureLFIWAX }, { } },
  { "mfocrf", "Enable the MFOCRF instruction", { PPC::FeatureMFOCRF }, { } },
  { "msync", "Has only the msync instruction instead of sync", { PPC::FeatureMSYNC }, { PPC::FeatureBookE } },
  { "partword-atomics", "Enable l[bh]arx and st[bh]cx.", { PPC::FeaturePartwordAtomic }, { } },
  { "popcntd", "Enable the popcnt[dw] instructions", { PPC::FeaturePOPCNTD }, { } },
  { "power8-altivec", "Enable POWER8 Altivec instructions", { PPC::FeatureP8Altivec }, { PPC::FeatureAltivec } },
  { "power8-vector", "Enable POWER8 vector instructions", { PPC::FeatureP8Vector }, { PPC::FeatureVSX, PPC::FeatureP8Altivec } },
  { "ppc4xx", "Enable PPC 4xx instructions", { PPC::FeaturePPC4xx }, { } },
  { "ppc6xx", "Enable PPC 6xx instructions", { PPC::FeaturePPC6xx }, { } },
  { "qpx", "Enable QPX instructions", { PPC::FeatureQPX }, { } },
  { "recipprec", "Assume higher precision reciprocal estimates", { PPC::FeatureRecipPrec }, { } },
  { "soft-float", "Use software emulation for floating point", { PPC::FeatureSoftFloat }, { } },
  { "spe", "Enable SPE instructions", { PPC::FeatureSPE }, { } },
  { "stfiwx", "Enable the stfiwx instruction", { PPC::FeatureSTFIWX }, { } },
  { "vsx", "Enable VSX instructions", { PPC::FeatureVSX }, { PPC::FeatureAltivec } }
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetFeatureKV PPCSubTypeKV[] = {
  { "440", "Select the 440 processor", { PPC::Directive440, PPC::FeatureISEL, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureICBT, PPC::FeatureBookE, PPC::FeatureMSYNC, PPC::FeatureMFTB }, { } },
  { "450", "Select the 450 processor", { PPC::Directive440, PPC::FeatureISEL, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureICBT, PPC::FeatureBookE, PPC::FeatureMSYNC, PPC::FeatureMFTB }, { } },
  { "601", "Select the 601 processor", { PPC::Directive601 }, { } },
  { "602", "Select the 602 processor", { PPC::Directive602, PPC::FeatureMFTB }, { } },
  { "603", "Select the 603 processor", { PPC::Directive603, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "603e", "Select the 603e processor", { PPC::Directive603, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "603ev", "Select the 603ev processor", { PPC::Directive603, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "604", "Select the 604 processor", { PPC::Directive604, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "604e", "Select the 604e processor", { PPC::Directive604, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "620", "Select the 620 processor", { PPC::Directive620, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "7400", "Select the 7400 processor", { PPC::Directive7400, PPC::FeatureAltivec, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "7450", "Select the 7450 processor", { PPC::Directive7400, PPC::FeatureAltivec, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "750", "Select the 750 processor", { PPC::Directive750, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "970", "Select the 970 processor", { PPC::Directive970, PPC::FeatureAltivec, PPC::FeatureMFOCRF, PPC::FeatureFSqrt, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureSTFIWX, PPC::Feature64Bit, PPC::FeatureMFTB }, { } },
  { "a2", "Select the a2 processor", { PPC::DirectiveA2, PPC::FeatureICBT, PPC::FeatureBookE, PPC::FeatureMFOCRF, PPC::FeatureFCPSGN, PPC::FeatureFSqrt, PPC::FeatureFRE, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureFRSQRTES, PPC::FeatureRecipPrec, PPC::FeatureSTFIWX, PPC::FeatureLFIWAX, PPC::FeatureFPRND, PPC::FeatureFPCVT, PPC::FeatureISEL, PPC::FeaturePOPCNTD, PPC::FeatureCMPB, PPC::FeatureLDBRX, PPC::Feature64Bit, PPC::FeatureMFTB }, { } },
  { "a2q", "Select the a2q processor", { PPC::DirectiveA2, PPC::FeatureICBT, PPC::FeatureBookE, PPC::FeatureMFOCRF, PPC::FeatureFCPSGN, PPC::FeatureFSqrt, PPC::FeatureFRE, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureFRSQRTES, PPC::FeatureRecipPrec, PPC::FeatureSTFIWX, PPC::FeatureLFIWAX, PPC::FeatureFPRND, PPC::FeatureFPCVT, PPC::FeatureISEL, PPC::FeaturePOPCNTD, PPC::FeatureCMPB, PPC::FeatureLDBRX, PPC::Feature64Bit, PPC::FeatureQPX, PPC::FeatureMFTB }, { } },
  { "e500mc", "Select the e500mc processor", { PPC::DirectiveE500mc, PPC::FeatureSTFIWX, PPC::FeatureICBT, PPC::FeatureBookE, PPC::FeatureISEL, PPC::FeatureMFTB }, { } },
  { "e5500", "Select the e5500 processor", { PPC::DirectiveE5500, PPC::FeatureMFOCRF, PPC::Feature64Bit, PPC::FeatureSTFIWX, PPC::FeatureICBT, PPC::FeatureBookE, PPC::FeatureISEL, PPC::FeatureMFTB }, { } },
  { "g3", "Select the g3 processor", { PPC::Directive750, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "g4", "Select the g4 processor", { PPC::Directive7400, PPC::FeatureAltivec, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "g4+", "Select the g4+ processor", { PPC::Directive7400, PPC::FeatureAltivec, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFTB }, { } },
  { "g5", "Select the g5 processor", { PPC::Directive970, PPC::FeatureAltivec, PPC::FeatureMFOCRF, PPC::FeatureFSqrt, PPC::FeatureSTFIWX, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::Feature64Bit, PPC::FeatureMFTB, PPC::DeprecatedDST }, { } },
  { "generic", "Select the generic processor", { PPC::Directive32, PPC::FeatureMFTB }, { } },
  { "ppc", "Select the ppc processor", { PPC::Directive32, PPC::FeatureMFTB }, { } },
  { "ppc64", "Select the ppc64 processor", { PPC::Directive64, PPC::FeatureAltivec, PPC::FeatureMFOCRF, PPC::FeatureFSqrt, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureSTFIWX, PPC::Feature64Bit, PPC::FeatureMFTB }, { } },
  { "ppc64le", "Select the ppc64le processor", { PPC::DirectivePwr7, PPC::FeatureAltivec, PPC::FeatureVSX, PPC::FeatureMFOCRF, PPC::FeatureFCPSGN, PPC::FeatureFSqrt, PPC::FeatureFRE, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureFRSQRTES, PPC::FeatureRecipPrec, PPC::FeatureSTFIWX, PPC::FeatureLFIWAX, PPC::FeatureFPRND, PPC::FeatureFPCVT, PPC::FeatureISEL, PPC::FeaturePOPCNTD, PPC::FeatureCMPB, PPC::FeatureLDBRX, PPC::Feature64Bit, PPC::FeatureBPERMD, PPC::FeatureExtDiv, PPC::FeatureMFTB, PPC::DeprecatedDST, PPC::DirectivePwr8, PPC::FeatureP8Altivec, PPC::FeatureP8Vector, PPC::FeatureP8Crypto, PPC::FeatureHTM, PPC::FeatureDirectMove, PPC::FeatureICBT, PPC::FeaturePartwordAtomic, PPC::FeatureFusion }, { } },
  { "pwr3", "Select the pwr3 processor", { PPC::DirectivePwr3, PPC::FeatureAltivec, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureMFOCRF, PPC::FeatureSTFIWX, PPC::Feature64Bit }, { } },
  { "pwr4", "Select the pwr4 processor", { PPC::DirectivePwr4, PPC::FeatureAltivec, PPC::FeatureMFOCRF, PPC::FeatureFSqrt, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureSTFIWX, PPC::Feature64Bit, PPC::FeatureMFTB }, { } },
  { "pwr5", "Select the pwr5 processor", { PPC::DirectivePwr5, PPC::FeatureAltivec, PPC::FeatureMFOCRF, PPC::FeatureFSqrt, PPC::FeatureFRE, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureFRSQRTES, PPC::FeatureSTFIWX, PPC::Feature64Bit, PPC::FeatureMFTB, PPC::DeprecatedDST }, { } },
  { "pwr5x", "Select the pwr5x processor", { PPC::DirectivePwr5x, PPC::FeatureAltivec, PPC::FeatureMFOCRF, PPC::FeatureFSqrt, PPC::FeatureFRE, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureFRSQRTES, PPC::FeatureSTFIWX, PPC::FeatureFPRND, PPC::Feature64Bit, PPC::FeatureMFTB, PPC::DeprecatedDST }, { } },
  { "pwr6", "Select the pwr6 processor", { PPC::DirectivePwr6, PPC::FeatureAltivec, PPC::FeatureMFOCRF, PPC::FeatureFCPSGN, PPC::FeatureFSqrt, PPC::FeatureFRE, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureFRSQRTES, PPC::FeatureRecipPrec, PPC::FeatureSTFIWX, PPC::FeatureLFIWAX, PPC::FeatureCMPB, PPC::FeatureFPRND, PPC::Feature64Bit, PPC::FeatureMFTB, PPC::DeprecatedDST }, { } },
  { "pwr6x", "Select the pwr6x processor", { PPC::DirectivePwr5x, PPC::FeatureAltivec, PPC::FeatureMFOCRF, PPC::FeatureFCPSGN, PPC::FeatureFSqrt, PPC::FeatureFRE, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureFRSQRTES, PPC::FeatureRecipPrec, PPC::FeatureSTFIWX, PPC::FeatureLFIWAX, PPC::FeatureCMPB, PPC::FeatureFPRND, PPC::Feature64Bit, PPC::FeatureMFTB, PPC::DeprecatedDST }, { } },
  { "pwr7", "Select the pwr7 processor", { PPC::DirectivePwr7, PPC::FeatureAltivec, PPC::FeatureVSX, PPC::FeatureMFOCRF, PPC::FeatureFCPSGN, PPC::FeatureFSqrt, PPC::FeatureFRE, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureFRSQRTES, PPC::FeatureRecipPrec, PPC::FeatureSTFIWX, PPC::FeatureLFIWAX, PPC::FeatureFPRND, PPC::FeatureFPCVT, PPC::FeatureISEL, PPC::FeaturePOPCNTD, PPC::FeatureCMPB, PPC::FeatureLDBRX, PPC::Feature64Bit, PPC::FeatureBPERMD, PPC::FeatureExtDiv, PPC::FeatureMFTB, PPC::DeprecatedDST }, { } },
  { "pwr8", "Select the pwr8 processor", { PPC::DirectivePwr7, PPC::FeatureAltivec, PPC::FeatureVSX, PPC::FeatureMFOCRF, PPC::FeatureFCPSGN, PPC::FeatureFSqrt, PPC::FeatureFRE, PPC::FeatureFRES, PPC::FeatureFRSQRTE, PPC::FeatureFRSQRTES, PPC::FeatureRecipPrec, PPC::FeatureSTFIWX, PPC::FeatureLFIWAX, PPC::FeatureFPRND, PPC::FeatureFPCVT, PPC::FeatureISEL, PPC::FeaturePOPCNTD, PPC::FeatureCMPB, PPC::FeatureLDBRX, PPC::Feature64Bit, PPC::FeatureBPERMD, PPC::FeatureExtDiv, PPC::FeatureMFTB, PPC::DeprecatedDST, PPC::DirectivePwr8, PPC::FeatureP8Altivec, PPC::FeatureP8Vector, PPC::FeatureP8Crypto, PPC::FeatureHTM, PPC::FeatureDirectMove, PPC::FeatureICBT, PPC::FeaturePartwordAtomic, PPC::FeatureFusion }, { } }
};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#ifndef NDEBUG
#define DBGFIELD(x) x,
#else
#define DBGFIELD(x)
#endif

#undef DBGFIELD
static inline MCSubtargetInfo *createPPCMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, PPCFeatureKV, PPCSubTypeKV, NULL);
}

} // end llvm namespace
#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::PPCSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
  if (Bits[PPC::DeprecatedDST]) DeprecatedDST = true;
  if (Bits[PPC::Directive32] && DarwinDirective < PPC::DIR_32) DarwinDirective = PPC::DIR_32;
  if (Bits[PPC::Directive64] && DarwinDirective < PPC::DIR_64) DarwinDirective = PPC::DIR_64;
  if (Bits[PPC::Directive440] && DarwinDirective < PPC::DIR_440) DarwinDirective = PPC::DIR_440;
  if (Bits[PPC::Directive601] && DarwinDirective < PPC::DIR_601) DarwinDirective = PPC::DIR_601;
  if (Bits[PPC::Directive602] && DarwinDirective < PPC::DIR_602) DarwinDirective = PPC::DIR_602;
  if (Bits[PPC::Directive603] && DarwinDirective < PPC::DIR_603) DarwinDirective = PPC::DIR_603;
  if (Bits[PPC::Directive604] && DarwinDirective < PPC::DIR_603) DarwinDirective = PPC::DIR_603;
  if (Bits[PPC::Directive620] && DarwinDirective < PPC::DIR_603) DarwinDirective = PPC::DIR_603;
  if (Bits[PPC::Directive750] && DarwinDirective < PPC::DIR_750) DarwinDirective = PPC::DIR_750;
  if (Bits[PPC::Directive970] && DarwinDirective < PPC::DIR_970) DarwinDirective = PPC::DIR_970;
  if (Bits[PPC::Directive7400] && DarwinDirective < PPC::DIR_7400) DarwinDirective = PPC::DIR_7400;
  if (Bits[PPC::DirectiveA2] && DarwinDirective < PPC::DIR_A2) DarwinDirective = PPC::DIR_A2;
  if (Bits[PPC::DirectiveE500mc] && DarwinDirective < PPC::DIR_E500mc) DarwinDirective = PPC::DIR_E500mc;
  if (Bits[PPC::DirectiveE5500] && DarwinDirective < PPC::DIR_E5500) DarwinDirective = PPC::DIR_E5500;
  if (Bits[PPC::DirectivePwr3] && DarwinDirective < PPC::DIR_PWR3) DarwinDirective = PPC::DIR_PWR3;
  if (Bits[PPC::DirectivePwr4] && DarwinDirective < PPC::DIR_PWR4) DarwinDirective = PPC::DIR_PWR4;
  if (Bits[PPC::DirectivePwr5] && DarwinDirective < PPC::DIR_PWR5) DarwinDirective = PPC::DIR_PWR5;
  if (Bits[PPC::DirectivePwr5x] && DarwinDirective < PPC::DIR_PWR5X) DarwinDirective = PPC::DIR_PWR5X;
  if (Bits[PPC::DirectivePwr6] && DarwinDirective < PPC::DIR_PWR6) DarwinDirective = PPC::DIR_PWR6;
  if (Bits[PPC::DirectivePwr6x] && DarwinDirective < PPC::DIR_PWR6X) DarwinDirective = PPC::DIR_PWR6X;
  if (Bits[PPC::DirectivePwr7] && DarwinDirective < PPC::DIR_PWR7) DarwinDirective = PPC::DIR_PWR7;
  if (Bits[PPC::DirectivePwr8] && DarwinDirective < PPC::DIR_PWR8) DarwinDirective = PPC::DIR_PWR8;
  if (Bits[PPC::Feature64Bit]) Has64BitSupport = true;
  if (Bits[PPC::Feature64BitRegs]) Use64BitRegs = true;
  if (Bits[PPC::FeatureAltivec]) HasAltivec = true;
  if (Bits[PPC::FeatureBPERMD]) HasBPERMD = true;
  if (Bits[PPC::FeatureBookE]) IsBookE = true;
  if (Bits[PPC::FeatureCMPB]) HasCMPB = true;
  if (Bits[PPC::FeatureCRBits]) UseCRBits = true;
  if (Bits[PPC::FeatureDirectMove]) HasDirectMove = true;
  if (Bits[PPC::FeatureE500]) IsE500 = true;
  if (Bits[PPC::FeatureExtDiv]) HasExtDiv = true;
  if (Bits[PPC::FeatureFCPSGN]) HasFCPSGN = true;
  if (Bits[PPC::FeatureFPCVT]) HasFPCVT = true;
  if (Bits[PPC::FeatureFPRND]) HasFPRND = true;
  if (Bits[PPC::FeatureFRE]) HasFRE = true;
  if (Bits[PPC::FeatureFRES]) HasFRES = true;
  if (Bits[PPC::FeatureFRSQRTE]) HasFRSQRTE = true;
  if (Bits[PPC::FeatureFRSQRTES]) HasFRSQRTES = true;
  if (Bits[PPC::FeatureFSqrt]) HasFSQRT = true;
  if (Bits[PPC::FeatureFloat128]) HasFloat128 = true;
  if (Bits[PPC::FeatureFusion]) HasFusion = true;
  if (Bits[PPC::FeatureHTM]) HasHTM = true;
  if (Bits[PPC::FeatureICBT]) HasICBT = true;
  if (Bits[PPC::FeatureISEL]) HasISEL = true;
  if (Bits[PPC::FeatureInvariantFunctionDescriptors]) HasInvariantFunctionDescriptors = true;
  if (Bits[PPC::FeatureLDBRX]) HasLDBRX = true;
  if (Bits[PPC::FeatureLFIWAX]) HasLFIWAX = true;
  if (Bits[PPC::FeatureMFOCRF]) HasMFOCRF = true;
  if (Bits[PPC::FeatureMFTB]) FeatureMFTB = true;
  if (Bits[PPC::FeatureMSYNC]) HasOnlyMSYNC = true;
  if (Bits[PPC::FeatureP8Altivec]) HasP8Altivec = true;
  if (Bits[PPC::FeatureP8Crypto]) HasP8Crypto = true;
  if (Bits[PPC::FeatureP8Vector]) HasP8Vector = true;
  if (Bits[PPC::FeaturePOPCNTD]) HasPOPCNTD = true;
  if (Bits[PPC::FeaturePPC4xx]) IsPPC4xx = true;
  if (Bits[PPC::FeaturePPC6xx]) IsPPC6xx = true;
  if (Bits[PPC::FeaturePartwordAtomic]) HasPartwordAtomics = true;
  if (Bits[PPC::FeatureQPX]) HasQPX = true;
  if (Bits[PPC::FeatureRecipPrec]) HasRecipPrec = true;
  if (Bits[PPC::FeatureSPE]) HasSPE = true;
  if (Bits[PPC::FeatureSTFIWX]) HasSTFIWX = true;
  if (Bits[PPC::FeatureSoftFloat]) UseSoftFloat = true;
  if (Bits[PPC::FeatureVSX]) HasVSX = true;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC
