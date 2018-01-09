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
namespace AArch64 {
enum : uint64_t {
  FeatureCRC = 0,
  FeatureCrypto = 1,
  FeatureFPARMv8 = 2,
  FeatureFullFP16 = 3,
  FeatureNEON = 4,
  FeaturePerfMon = 5,
  FeatureReserveX18 = 6,
  FeatureSPE = 7,
  FeatureStrictAlign = 8,
  FeatureZCRegMove = 9,
  FeatureZCZeroing = 10,
  HasV8_1aOps = 11,
  HasV8_2aOps = 12,
  ProcA35 = 13,
  ProcA53 = 14,
  ProcA57 = 15,
  ProcCyclone = 16,
  ProcExynosM1 = 17
};
}
} // end llvm namespace
#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC
namespace llvm_ks {
// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKV AArch64FeatureKV[] = {
  { "a35", "Cortex-A35 ARM processors", { AArch64::ProcA35 }, { AArch64::FeatureFPARMv8, AArch64::FeatureNEON, AArch64::FeatureCrypto, AArch64::FeatureCRC, AArch64::FeaturePerfMon } },
  { "a53", "Cortex-A53 ARM processors", { AArch64::ProcA53 }, { AArch64::FeatureFPARMv8, AArch64::FeatureNEON, AArch64::FeatureCrypto, AArch64::FeatureCRC, AArch64::FeaturePerfMon } },
  { "a57", "Cortex-A57 ARM processors", { AArch64::ProcA57 }, { AArch64::FeatureFPARMv8, AArch64::FeatureNEON, AArch64::FeatureCrypto, AArch64::FeatureCRC, AArch64::FeaturePerfMon } },
  { "crc", "Enable ARMv8 CRC-32 checksum instructions", { AArch64::FeatureCRC }, { } },
  { "crypto", "Enable cryptographic instructions", { AArch64::FeatureCrypto }, { } },
  { "cyclone", "Cyclone", { AArch64::ProcCyclone }, { AArch64::FeatureFPARMv8, AArch64::FeatureNEON, AArch64::FeatureCrypto, AArch64::FeatureCRC, AArch64::FeaturePerfMon, AArch64::FeatureZCRegMove, AArch64::FeatureZCZeroing } },
  { "exynosm1", "Samsung Exynos-M1 processors", { AArch64::ProcExynosM1 }, { AArch64::FeatureFPARMv8, AArch64::FeatureNEON, AArch64::FeatureCrypto, AArch64::FeatureCRC, AArch64::FeaturePerfMon } },
  { "fp-armv8", "Enable ARMv8 FP", { AArch64::FeatureFPARMv8 }, { } },
  { "fullfp16", "Full FP16", { AArch64::FeatureFullFP16 }, { AArch64::FeatureFPARMv8 } },
  { "neon", "Enable Advanced SIMD instructions", { AArch64::FeatureNEON }, { AArch64::FeatureFPARMv8 } },
  { "perfmon", "Enable ARMv8 PMUv3 Performance Monitors extension", { AArch64::FeaturePerfMon }, { } },
  { "reserve-x18", "Reserve X18, making it unavailable as a GPR", { AArch64::FeatureReserveX18 }, { } },
  { "spe", "Enable Statistical Profiling extension", { AArch64::FeatureSPE }, { } },
  { "strict-align", "Disallow all unaligned memory access", { AArch64::FeatureStrictAlign }, { } },
  { "v8.1a", "Support ARM v8.1a instructions", { AArch64::HasV8_1aOps }, { AArch64::FeatureCRC } },
  { "v8.2a", "Support ARM v8.2a instructions", { AArch64::HasV8_2aOps }, { AArch64::HasV8_1aOps } },
  { "zcm", "Has zero-cycle register moves", { AArch64::FeatureZCRegMove }, { } },
  { "zcz", "Has zero-cycle zeroing instructions", { AArch64::FeatureZCZeroing }, { } }
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetFeatureKV AArch64SubTypeKV[] = {
  { "cortex-a35", "Select the cortex-a35 processor", { AArch64::ProcA35 }, { } },
  { "cortex-a53", "Select the cortex-a53 processor", { AArch64::ProcA53 }, { } },
  { "cortex-a57", "Select the cortex-a57 processor", { AArch64::ProcA57 }, { } },
  { "cortex-a72", "Select the cortex-a72 processor", { AArch64::ProcA57 }, { } },
  { "cyclone", "Select the cyclone processor", { AArch64::ProcCyclone }, { } },
  { "exynos-m1", "Select the exynos-m1 processor", { AArch64::ProcExynosM1 }, { } },
  { "generic", "Select the generic processor", { AArch64::FeatureFPARMv8, AArch64::FeatureNEON, AArch64::FeatureCRC, AArch64::FeaturePerfMon }, { } }
};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#ifndef NDEBUG
#define DBGFIELD(x) x,
#else
#define DBGFIELD(x)
#endif

// ===============================================================
// Data tables for the new per-operand machine model.

#undef DBGFIELD
static inline MCSubtargetInfo *createAArch64MCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, AArch64FeatureKV, AArch64SubTypeKV, NULL);
}

} // end llvm namespace
#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::AArch64Subtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
  if (Bits[AArch64::FeatureCRC]) HasCRC = true;
  if (Bits[AArch64::FeatureCrypto]) HasCrypto = true;
  if (Bits[AArch64::FeatureFPARMv8]) HasFPARMv8 = true;
  if (Bits[AArch64::FeatureFullFP16]) HasFullFP16 = true;
  if (Bits[AArch64::FeatureNEON]) HasNEON = true;
  if (Bits[AArch64::FeaturePerfMon]) HasPerfMon = true;
  if (Bits[AArch64::FeatureReserveX18]) ReserveX18 = true;
  if (Bits[AArch64::FeatureSPE]) HasSPE = true;
  if (Bits[AArch64::FeatureStrictAlign]) StrictAlign = true;
  if (Bits[AArch64::FeatureZCRegMove]) HasZeroCycleRegMove = true;
  if (Bits[AArch64::FeatureZCZeroing]) HasZeroCycleZeroing = true;
  if (Bits[AArch64::HasV8_1aOps]) HasV8_1aOps = true;
  if (Bits[AArch64::HasV8_2aOps]) HasV8_2aOps = true;
  if (Bits[AArch64::ProcA35] && ARMProcFamily < CortexA35) ARMProcFamily = CortexA35;
  if (Bits[AArch64::ProcA53] && ARMProcFamily < CortexA53) ARMProcFamily = CortexA53;
  if (Bits[AArch64::ProcA57] && ARMProcFamily < CortexA57) ARMProcFamily = CortexA57;
  if (Bits[AArch64::ProcCyclone] && ARMProcFamily < Cyclone) ARMProcFamily = Cyclone;
  if (Bits[AArch64::ProcExynosM1] && ARMProcFamily < ExynosM1) ARMProcFamily = ExynosM1;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC
