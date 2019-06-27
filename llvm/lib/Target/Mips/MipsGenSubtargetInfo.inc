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
namespace Mips {
enum : uint64_t {
  FeatureCnMips = 0,
  FeatureDSP = 1,
  FeatureDSPR2 = 2,
  FeatureDSPR3 = 3,
  FeatureEVA = 4,
  FeatureFP64Bit = 5,
  FeatureFPXX = 6,
  FeatureGP64Bit = 7,
  FeatureMSA = 8,
  FeatureMicroMips = 9,
  FeatureMips1 = 10,
  FeatureMips2 = 11,
  FeatureMips3 = 12,
  FeatureMips3_32 = 13,
  FeatureMips3_32r2 = 14,
  FeatureMips4 = 15,
  FeatureMips4_32 = 16,
  FeatureMips4_32r2 = 17,
  FeatureMips5 = 18,
  FeatureMips5_32r2 = 19,
  FeatureMips16 = 20,
  FeatureMips32 = 21,
  FeatureMips32r2 = 22,
  FeatureMips32r3 = 23,
  FeatureMips32r5 = 24,
  FeatureMips32r6 = 25,
  FeatureMips64 = 26,
  FeatureMips64r2 = 27,
  FeatureMips64r3 = 28,
  FeatureMips64r5 = 29,
  FeatureMips64r6 = 30,
  FeatureNaN2008 = 31,
  FeatureNoABICalls = 32,
  FeatureNoOddSPReg = 33,
  FeatureSingleFloat = 34,
  FeatureSoftFloat = 35,
  FeatureUseTCCInDIV = 36,
  FeatureVFPU = 37,
  ImplP5600 = 38
};
}
} // end llvm namespace
#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC
namespace llvm_ks {
// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKV MipsFeatureKV[] = {
  { "cnmips", "Octeon cnMIPS Support", { Mips::FeatureCnMips }, { Mips::FeatureMips64r2 } },
  { "dsp", "Mips DSP ASE", { Mips::FeatureDSP }, { } },
  { "dspr2", "Mips DSP-R2 ASE", { Mips::FeatureDSPR2 }, { Mips::FeatureDSP } },
  { "dspr3", "Mips DSP-R3 ASE", { Mips::FeatureDSPR3 }, { Mips::FeatureDSP, Mips::FeatureDSPR2 } },
  { "eva", "Mips EVA ASE", { Mips::FeatureEVA }, { } },
  { "fp64", "Support 64-bit FP registers", { Mips::FeatureFP64Bit }, { } },
  { "fpxx", "Support for FPXX", { Mips::FeatureFPXX }, { } },
  { "gp64", "General Purpose Registers are 64-bit wide", { Mips::FeatureGP64Bit }, { } },
  { "micromips", "microMips mode", { Mips::FeatureMicroMips }, { } },
  { "mips1", "Mips I ISA Support [highly experimental]", { Mips::FeatureMips1 }, { } },
  { "mips16", "Mips16 mode", { Mips::FeatureMips16 }, { } },
  { "mips2", "Mips II ISA Support [highly experimental]", { Mips::FeatureMips2 }, { Mips::FeatureMips1 } },
  { "mips3", "MIPS III ISA Support [highly experimental]", { Mips::FeatureMips3 }, { Mips::FeatureMips2, Mips::FeatureMips3_32, Mips::FeatureMips3_32r2, Mips::FeatureGP64Bit, Mips::FeatureFP64Bit } },
  { "mips32", "Mips32 ISA Support", { Mips::FeatureMips32 }, { Mips::FeatureMips2, Mips::FeatureMips3_32, Mips::FeatureMips4_32 } },
  { "mips32r2", "Mips32r2 ISA Support", { Mips::FeatureMips32r2 }, { Mips::FeatureMips3_32r2, Mips::FeatureMips4_32r2, Mips::FeatureMips5_32r2, Mips::FeatureMips32 } },
  { "mips32r3", "Mips32r3 ISA Support", { Mips::FeatureMips32r3 }, { Mips::FeatureMips32r2 } },
  { "mips32r5", "Mips32r5 ISA Support", { Mips::FeatureMips32r5 }, { Mips::FeatureMips32r3 } },
  { "mips32r6", "Mips32r6 ISA Support [experimental]", { Mips::FeatureMips32r6 }, { Mips::FeatureMips32r5, Mips::FeatureFP64Bit, Mips::FeatureNaN2008 } },
  { "mips3_32", "Subset of MIPS-III that is also in MIPS32 [highly experimental]", { Mips::FeatureMips3_32 }, { } },
  { "mips3_32r2", "Subset of MIPS-III that is also in MIPS32r2 [highly experimental]", { Mips::FeatureMips3_32r2 }, { } },
  { "mips4", "MIPS IV ISA Support", { Mips::FeatureMips4 }, { Mips::FeatureMips3, Mips::FeatureMips4_32, Mips::FeatureMips4_32r2 } },
  { "mips4_32", "Subset of MIPS-IV that is also in MIPS32 [highly experimental]", { Mips::FeatureMips4_32 }, { } },
  { "mips4_32r2", "Subset of MIPS-IV that is also in MIPS32r2 [highly experimental]", { Mips::FeatureMips4_32r2 }, { } },
  { "mips5", "MIPS V ISA Support [highly experimental]", { Mips::FeatureMips5 }, { Mips::FeatureMips4, Mips::FeatureMips5_32r2 } },
  { "mips5_32r2", "Subset of MIPS-V that is also in MIPS32r2 [highly experimental]", { Mips::FeatureMips5_32r2 }, { } },
  { "mips64", "Mips64 ISA Support", { Mips::FeatureMips64 }, { Mips::FeatureMips5, Mips::FeatureMips32 } },
  { "mips64r2", "Mips64r2 ISA Support", { Mips::FeatureMips64r2 }, { Mips::FeatureMips64, Mips::FeatureMips32r2 } },
  { "mips64r3", "Mips64r3 ISA Support", { Mips::FeatureMips64r3 }, { Mips::FeatureMips64r2, Mips::FeatureMips32r3 } },
  { "mips64r5", "Mips64r5 ISA Support", { Mips::FeatureMips64r5 }, { Mips::FeatureMips64r3, Mips::FeatureMips32r5 } },
  { "mips64r6", "Mips64r6 ISA Support [experimental]", { Mips::FeatureMips64r6 }, { Mips::FeatureMips32r6, Mips::FeatureMips64r5, Mips::FeatureNaN2008 } },
  { "msa", "Mips MSA ASE", { Mips::FeatureMSA }, { } },
  { "nan2008", "IEEE 754-2008 NaN encoding", { Mips::FeatureNaN2008 }, { } },
  { "noabicalls", "Disable SVR4-style position-independent code", { Mips::FeatureNoABICalls }, { } },
  { "nooddspreg", "Disable odd numbered single-precision registers", { Mips::FeatureNoOddSPReg }, { } },
  { "p5600", "The P5600 Processor", { Mips::ImplP5600 }, { Mips::FeatureMips32r5 } },
  { "single-float", "Only supports single precision float", { Mips::FeatureSingleFloat }, { } },
  { "soft-float", "Does not support floating point instructions", { Mips::FeatureSoftFloat }, { } },
  { "use-tcc-in-div", "Force the assembler to use trapping", { Mips::FeatureUseTCCInDIV }, { } },
  { "vfpu", "Enable vector FPU instructions", { Mips::FeatureVFPU }, { } }
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetFeatureKV MipsSubTypeKV[] = {
  { "mips1", "Select the mips1 processor", { Mips::FeatureMips1 }, { } },
  { "mips2", "Select the mips2 processor", { Mips::FeatureMips2 }, { } },
  { "mips3", "Select the mips3 processor", { Mips::FeatureMips3 }, { } },
  { "mips32", "Select the mips32 processor", { Mips::FeatureMips32 }, { } },
  { "mips32r2", "Select the mips32r2 processor", { Mips::FeatureMips32r2 }, { } },
  { "mips32r3", "Select the mips32r3 processor", { Mips::FeatureMips32r3 }, { } },
  { "mips32r5", "Select the mips32r5 processor", { Mips::FeatureMips32r5 }, { } },
  { "mips32r6", "Select the mips32r6 processor", { Mips::FeatureMips32r6 }, { } },
  { "mips4", "Select the mips4 processor", { Mips::FeatureMips4 }, { } },
  { "mips5", "Select the mips5 processor", { Mips::FeatureMips5 }, { } },
  { "mips64", "Select the mips64 processor", { Mips::FeatureMips64 }, { } },
  { "mips64r2", "Select the mips64r2 processor", { Mips::FeatureMips64r2 }, { } },
  { "mips64r3", "Select the mips64r3 processor", { Mips::FeatureMips64r3 }, { } },
  { "mips64r5", "Select the mips64r5 processor", { Mips::FeatureMips64r5 }, { } },
  { "mips64r6", "Select the mips64r6 processor", { Mips::FeatureMips64r6 }, { } },
  { "octeon", "Select the octeon processor", { Mips::FeatureMips64r2, Mips::FeatureCnMips }, { } },
  { "p5600", "Select the p5600 processor", { Mips::ImplP5600 }, { } }
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
static inline MCSubtargetInfo *createMipsMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, MipsFeatureKV, MipsSubTypeKV, NULL);
}

} // end llvm namespace
#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::MipsSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
  if (Bits[Mips::FeatureCnMips]) HasCnMips = true;
  if (Bits[Mips::FeatureDSP]) HasDSP = true;
  if (Bits[Mips::FeatureDSPR2]) HasDSPR2 = true;
  if (Bits[Mips::FeatureDSPR3]) HasDSPR3 = true;
  if (Bits[Mips::FeatureEVA]) HasEVA = true;
  if (Bits[Mips::FeatureFP64Bit]) IsFP64bit = true;
  if (Bits[Mips::FeatureFPXX]) IsFPXX = true;
  if (Bits[Mips::FeatureGP64Bit]) IsGP64bit = true;
  if (Bits[Mips::FeatureMSA]) HasMSA = true;
  if (Bits[Mips::FeatureMicroMips]) InMicroMipsMode = true;
  if (Bits[Mips::FeatureMips1] && MipsArchVersion < Mips1) MipsArchVersion = Mips1;
  if (Bits[Mips::FeatureMips2] && MipsArchVersion < Mips2) MipsArchVersion = Mips2;
  if (Bits[Mips::FeatureMips3] && MipsArchVersion < Mips3) MipsArchVersion = Mips3;
  if (Bits[Mips::FeatureMips3_32]) HasMips3_32 = true;
  if (Bits[Mips::FeatureMips3_32r2]) HasMips3_32r2 = true;
  if (Bits[Mips::FeatureMips4] && MipsArchVersion < Mips4) MipsArchVersion = Mips4;
  if (Bits[Mips::FeatureMips4_32]) HasMips4_32 = true;
  if (Bits[Mips::FeatureMips4_32r2]) HasMips4_32r2 = true;
  if (Bits[Mips::FeatureMips5] && MipsArchVersion < Mips5) MipsArchVersion = Mips5;
  if (Bits[Mips::FeatureMips5_32r2]) HasMips5_32r2 = true;
  if (Bits[Mips::FeatureMips16]) InMips16Mode = true;
  if (Bits[Mips::FeatureMips32] && MipsArchVersion < Mips32) MipsArchVersion = Mips32;
  if (Bits[Mips::FeatureMips32r2] && MipsArchVersion < Mips32r2) MipsArchVersion = Mips32r2;
  if (Bits[Mips::FeatureMips32r3] && MipsArchVersion < Mips32r3) MipsArchVersion = Mips32r3;
  if (Bits[Mips::FeatureMips32r5] && MipsArchVersion < Mips32r5) MipsArchVersion = Mips32r5;
  if (Bits[Mips::FeatureMips32r6] && MipsArchVersion < Mips32r6) MipsArchVersion = Mips32r6;
  if (Bits[Mips::FeatureMips64] && MipsArchVersion < Mips64) MipsArchVersion = Mips64;
  if (Bits[Mips::FeatureMips64r2] && MipsArchVersion < Mips64r2) MipsArchVersion = Mips64r2;
  if (Bits[Mips::FeatureMips64r3] && MipsArchVersion < Mips64r3) MipsArchVersion = Mips64r3;
  if (Bits[Mips::FeatureMips64r5] && MipsArchVersion < Mips64r5) MipsArchVersion = Mips64r5;
  if (Bits[Mips::FeatureMips64r6] && MipsArchVersion < Mips64r6) MipsArchVersion = Mips64r6;
  if (Bits[Mips::FeatureNaN2008]) IsNaN2008bit = true;
  if (Bits[Mips::FeatureNoABICalls]) NoABICalls = true;
  if (Bits[Mips::FeatureNoOddSPReg]) UseOddSPReg = false;
  if (Bits[Mips::FeatureSingleFloat]) IsSingleFloat = true;
  if (Bits[Mips::FeatureSoftFloat]) IsSoftFloat = true;
  if (Bits[Mips::FeatureUseTCCInDIV]) UseTCCInDIV = false;
  if (Bits[Mips::FeatureVFPU]) HasVFPU = true;
  if (Bits[Mips::ImplP5600] && ProcImpl < MipsSubtarget::CPU::P5600) ProcImpl = MipsSubtarget::CPU::P5600;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC
