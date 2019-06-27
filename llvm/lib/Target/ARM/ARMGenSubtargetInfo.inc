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
namespace ARM {
enum : uint64_t {
  ARMv2 = 0,
  ARMv2a = 1,
  ARMv3 = 2,
  ARMv3m = 3,
  ARMv4 = 4,
  ARMv4t = 5,
  ARMv5t = 6,
  ARMv5te = 7,
  ARMv5tej = 8,
  ARMv6 = 9,
  ARMv6j = 10,
  ARMv6k = 11,
  ARMv6kz = 12,
  ARMv6m = 13,
  ARMv6sm = 14,
  ARMv6t2 = 15,
  ARMv7a = 16,
  ARMv7em = 17,
  ARMv7k = 18,
  ARMv7m = 19,
  ARMv7r = 20,
  ARMv7s = 21,
  ARMv8a = 22,
  ARMv8mBaseline = 23,
  ARMv8mMainline = 24,
  ARMv81a = 25,
  ARMv82a = 26,
  Feature8MSecExt = 27,
  FeatureAClass = 28,
  FeatureAcquireRelease = 29,
  FeatureAvoidMOVsShOp = 30,
  FeatureAvoidPartialCPSR = 31,
  FeatureCRC = 32,
  FeatureCrypto = 33,
  FeatureD16 = 34,
  FeatureDB = 35,
  FeatureDSP = 36,
  FeatureFP16 = 37,
  FeatureFPARMv8 = 38,
  FeatureFullFP16 = 39,
  FeatureHWDiv = 40,
  FeatureHWDivARM = 41,
  FeatureHasRAS = 42,
  FeatureHasSlowFPVMLx = 43,
  FeatureLongCalls = 44,
  FeatureMClass = 45,
  FeatureMP = 46,
  FeatureNEON = 47,
  FeatureNEONForFP = 48,
  FeatureNaClTrap = 49,
  FeatureNoARM = 50,
  FeatureNoMovt = 51,
  FeaturePerfMon = 52,
  FeaturePref32BitThumb = 53,
  FeatureRClass = 54,
  FeatureReserveR9 = 55,
  FeatureSlowFPBrcc = 56,
  FeatureStrictAlign = 57,
  FeatureT2XtPk = 58,
  FeatureThumb2 = 59,
  FeatureTrustZone = 60,
  FeatureV7Clrex = 61,
  FeatureVFP2 = 62,
  FeatureVFP3 = 63,
  FeatureVFP4 = 64,
  FeatureVFPOnlySP = 65,
  FeatureVMLxForwarding = 66,
  FeatureVirtualization = 67,
  FeatureZCZeroing = 68,
  HasV4TOps = 69,
  HasV5TEOps = 70,
  HasV5TOps = 71,
  HasV6KOps = 72,
  HasV6MOps = 73,
  HasV6Ops = 74,
  HasV6T2Ops = 75,
  HasV7Ops = 76,
  HasV8MBaselineOps = 77,
  HasV8MMainlineOps = 78,
  HasV8Ops = 79,
  HasV8_1aOps = 80,
  HasV8_2aOps = 81,
  IWMMXT = 82,
  IWMMXT2 = 83,
  ModeSoftFloat = 84,
  ModeThumb = 85,
  ProcA5 = 86,
  ProcA7 = 87,
  ProcA8 = 88,
  ProcA9 = 89,
  ProcA12 = 90,
  ProcA15 = 91,
  ProcA17 = 92,
  ProcA35 = 93,
  ProcA53 = 94,
  ProcA57 = 95,
  ProcA72 = 96,
  ProcExynosM1 = 97,
  ProcKrait = 98,
  ProcR4 = 99,
  ProcR5 = 100,
  ProcR7 = 101,
  ProcSwift = 102,
  XScale = 103
};
}
} // end llvm namespace
#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC
namespace llvm_ks {
// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKV ARMFeatureKV[] = {
  { "32bit", "Prefer 32-bit Thumb instrs", { ARM::FeaturePref32BitThumb }, { } },
  { "8msecext", "Enable support for ARMv8-M Security Extensions", { ARM::Feature8MSecExt }, { } },
  { "a12", "Cortex-A12 ARM processors", { ARM::ProcA12 }, { } },
  { "a15", "Cortex-A15 ARM processors", { ARM::ProcA15 }, { } },
  { "a17", "Cortex-A17 ARM processors", { ARM::ProcA17 }, { } },
  { "a35", "Cortex-A35 ARM processors", { ARM::ProcA35 }, { } },
  { "a5", "Cortex-A5 ARM processors", { ARM::ProcA5 }, { } },
  { "a53", "Cortex-A53 ARM processors", { ARM::ProcA53 }, { } },
  { "a57", "Cortex-A57 ARM processors", { ARM::ProcA57 }, { } },
  { "a7", "Cortex-A7 ARM processors", { ARM::ProcA7 }, { } },
  { "a72", "Cortex-A72 ARM processors", { ARM::ProcA72 }, { } },
  { "a8", "Cortex-A8 ARM processors", { ARM::ProcA8 }, { } },
  { "a9", "Cortex-A9 ARM processors", { ARM::ProcA9 }, { } },
  { "aclass", "Is application profile ('A' series)", { ARM::FeatureAClass }, { } },
  { "acquire-release", "Has v8 acquire/release (lda/ldaex etc) instructions", { ARM::FeatureAcquireRelease }, { } },
  { "armv2", "ARMv2 architecture", { ARM::ARMv2 }, { } },
  { "armv2a", "ARMv2a architecture", { ARM::ARMv2a }, { } },
  { "armv3", "ARMv3 architecture", { ARM::ARMv3 }, { } },
  { "armv3m", "ARMv3m architecture", { ARM::ARMv3m }, { } },
  { "armv4", "ARMv4 architecture", { ARM::ARMv4 }, { } },
  { "armv4t", "ARMv4t architecture", { ARM::ARMv4t }, { ARM::HasV4TOps } },
  { "armv5t", "ARMv5t architecture", { ARM::ARMv5t }, { ARM::HasV5TOps } },
  { "armv5te", "ARMv5te architecture", { ARM::ARMv5te }, { ARM::HasV5TEOps } },
  { "armv5tej", "ARMv5tej architecture", { ARM::ARMv5tej }, { ARM::HasV5TEOps } },
  { "armv6", "ARMv6 architecture", { ARM::ARMv6 }, { ARM::HasV6Ops } },
  { "armv6-m", "ARMv6m architecture", { ARM::ARMv6m }, { ARM::HasV6MOps, ARM::FeatureNoARM, ARM::FeatureDB, ARM::FeatureMClass } },
  { "armv6j", "ARMv7a architecture", { ARM::ARMv6j }, { ARM::ARMv6 } },
  { "armv6k", "ARMv6k architecture", { ARM::ARMv6k }, { ARM::HasV6KOps } },
  { "armv6kz", "ARMv6kz architecture", { ARM::ARMv6kz }, { ARM::HasV6KOps, ARM::FeatureTrustZone } },
  { "armv6s-m", "ARMv6sm architecture", { ARM::ARMv6sm }, { ARM::HasV6MOps, ARM::FeatureNoARM, ARM::FeatureDB, ARM::FeatureMClass } },
  { "armv6t2", "ARMv6t2 architecture", { ARM::ARMv6t2 }, { ARM::HasV6T2Ops, ARM::FeatureDSP } },
  { "armv7-a", "ARMv7a architecture", { ARM::ARMv7a }, { ARM::HasV7Ops, ARM::FeatureNEON, ARM::FeatureDB, ARM::FeatureDSP, ARM::FeatureAClass } },
  { "armv7-m", "ARMv7m architecture", { ARM::ARMv7m }, { ARM::HasV7Ops, ARM::FeatureThumb2, ARM::FeatureNoARM, ARM::FeatureDB, ARM::FeatureHWDiv, ARM::FeatureMClass } },
  { "armv7-r", "ARMv7r architecture", { ARM::ARMv7r }, { ARM::HasV7Ops, ARM::FeatureDB, ARM::FeatureDSP, ARM::FeatureHWDiv, ARM::FeatureRClass } },
  { "armv7e-m", "ARMv7em architecture", { ARM::ARMv7em }, { ARM::HasV7Ops, ARM::FeatureThumb2, ARM::FeatureNoARM, ARM::FeatureDB, ARM::FeatureHWDiv, ARM::FeatureMClass, ARM::FeatureDSP, ARM::FeatureT2XtPk } },
  { "armv7k", "ARMv7a architecture", { ARM::ARMv7k }, { ARM::ARMv7a } },
  { "armv7s", "ARMv7a architecture", { ARM::ARMv7s }, { ARM::ARMv7a } },
  { "armv8-a", "ARMv8a architecture", { ARM::ARMv8a }, { ARM::HasV8Ops, ARM::FeatureAClass, ARM::FeatureDB, ARM::FeatureFPARMv8, ARM::FeatureNEON, ARM::FeatureDSP, ARM::FeatureTrustZone, ARM::FeatureMP, ARM::FeatureVirtualization, ARM::FeatureCrypto, ARM::FeatureCRC } },
  { "armv8-m.base", "ARMv8mBaseline architecture", { ARM::ARMv8mBaseline }, { ARM::HasV8MBaselineOps, ARM::FeatureNoARM, ARM::FeatureDB, ARM::FeatureHWDiv, ARM::FeatureV7Clrex, ARM::Feature8MSecExt, ARM::FeatureAcquireRelease, ARM::FeatureMClass } },
  { "armv8-m.main", "ARMv8mMainline architecture", { ARM::ARMv8mMainline }, { ARM::HasV8MMainlineOps, ARM::FeatureNoARM, ARM::FeatureDB, ARM::FeatureHWDiv, ARM::Feature8MSecExt, ARM::FeatureAcquireRelease, ARM::FeatureMClass } },
  { "armv8.1-a", "ARMv81a architecture", { ARM::ARMv81a }, { ARM::HasV8_1aOps, ARM::FeatureAClass, ARM::FeatureDB, ARM::FeatureFPARMv8, ARM::FeatureNEON, ARM::FeatureDSP, ARM::FeatureTrustZone, ARM::FeatureMP, ARM::FeatureVirtualization, ARM::FeatureCrypto, ARM::FeatureCRC } },
  { "armv8.2-a", "ARMv82a architecture", { ARM::ARMv82a }, { ARM::HasV8_2aOps, ARM::FeatureAClass, ARM::FeatureDB, ARM::FeatureFPARMv8, ARM::FeatureNEON, ARM::FeatureDSP, ARM::FeatureTrustZone, ARM::FeatureMP, ARM::FeatureVirtualization, ARM::FeatureCrypto, ARM::FeatureCRC } },
  { "avoid-movs-shop", "Avoid movs instructions with shifter operand", { ARM::FeatureAvoidMOVsShOp }, { } },
  { "avoid-partial-cpsr", "Avoid CPSR partial update for OOO execution", { ARM::FeatureAvoidPartialCPSR }, { } },
  { "crc", "Enable support for CRC instructions", { ARM::FeatureCRC }, { } },
  { "crypto", "Enable support for Cryptography extensions", { ARM::FeatureCrypto }, { ARM::FeatureNEON } },
  { "d16", "Restrict FP to 16 double registers", { ARM::FeatureD16 }, { } },
  { "db", "Has data barrier (dmb / dsb) instructions", { ARM::FeatureDB }, { } },
  { "dsp", "Supports DSP instructions in ARM and/or Thumb2", { ARM::FeatureDSP }, { } },
  { "exynosm1", "Samsung Exynos-M1 processors", { ARM::ProcExynosM1 }, { } },
  { "fp-armv8", "Enable ARMv8 FP", { ARM::FeatureFPARMv8 }, { ARM::FeatureVFP4 } },
  { "fp-only-sp", "Floating point unit supports single precision only", { ARM::FeatureVFPOnlySP }, { } },
  { "fp16", "Enable half-precision floating point", { ARM::FeatureFP16 }, { } },
  { "fullfp16", "Enable full half-precision floating point", { ARM::FeatureFullFP16 }, { ARM::FeatureFPARMv8 } },
  { "hwdiv", "Enable divide instructions", { ARM::FeatureHWDiv }, { } },
  { "hwdiv-arm", "Enable divide instructions in ARM mode", { ARM::FeatureHWDivARM }, { } },
  { "iwmmxt", "ARMv5te architecture", { ARM::IWMMXT }, { ARM::ARMv5te } },
  { "iwmmxt2", "ARMv5te architecture", { ARM::IWMMXT2 }, { ARM::ARMv5te } },
  { "krait", "Qualcomm ARM processors", { ARM::ProcKrait }, { } },
  { "long-calls", "Generate calls via indirect call instructions", { ARM::FeatureLongCalls }, { } },
  { "mclass", "Is microcontroller profile ('M' series)", { ARM::FeatureMClass }, { } },
  { "mp", "Supports Multiprocessing extension", { ARM::FeatureMP }, { } },
  { "nacl-trap", "NaCl trap", { ARM::FeatureNaClTrap }, { } },
  { "neon", "Enable NEON instructions", { ARM::FeatureNEON }, { ARM::FeatureVFP3 } },
  { "neonfp", "Use NEON for single precision FP", { ARM::FeatureNEONForFP }, { } },
  { "no-movt", "Don't use movt/movw pairs for 32-bit imms", { ARM::FeatureNoMovt }, { } },
  { "noarm", "Does not support ARM mode execution", { ARM::FeatureNoARM }, { ARM::ModeThumb } },
  { "perfmon", "Enable support for Performance Monitor extensions", { ARM::FeaturePerfMon }, { } },
  { "r4", "Cortex-R4 ARM processors", { ARM::ProcR4 }, { } },
  { "r5", "Cortex-R5 ARM processors", { ARM::ProcR5 }, { } },
  { "r7", "Cortex-R7 ARM processors", { ARM::ProcR7 }, { } },
  { "ras", "Has return address stack", { ARM::FeatureHasRAS }, { } },
  { "rclass", "Is realtime profile ('R' series)", { ARM::FeatureRClass }, { } },
  { "reserve-r9", "Reserve R9, making it unavailable as GPR", { ARM::FeatureReserveR9 }, { } },
  { "slow-fp-brcc", "FP compare + branch is slow", { ARM::FeatureSlowFPBrcc }, { } },
  { "slowfpvmlx", "Disable VFP / NEON MAC instructions", { ARM::FeatureHasSlowFPVMLx }, { } },
  { "soft-float", "Use software floating point features.", { ARM::ModeSoftFloat }, { } },
  { "strict-align", "Disallow all unaligned memory access", { ARM::FeatureStrictAlign }, { } },
  { "swift", "Swift ARM processors", { ARM::ProcSwift }, { } },
  { "t2xtpk", "Enable Thumb2 extract and pack instructions", { ARM::FeatureT2XtPk }, { } },
  { "thumb-mode", "Thumb mode", { ARM::ModeThumb }, { } },
  { "thumb2", "Enable Thumb2 instructions", { ARM::FeatureThumb2 }, { } },
  { "trustzone", "Enable support for TrustZone security extensions", { ARM::FeatureTrustZone }, { } },
  { "v4t", "Support ARM v4T instructions", { ARM::HasV4TOps }, { } },
  { "v5t", "Support ARM v5T instructions", { ARM::HasV5TOps }, { ARM::HasV4TOps } },
  { "v5te", "Support ARM v5TE, v5TEj, and v5TExp instructions", { ARM::HasV5TEOps }, { ARM::HasV5TOps } },
  { "v6", "Support ARM v6 instructions", { ARM::HasV6Ops }, { ARM::HasV5TEOps } },
  { "v6k", "Support ARM v6k instructions", { ARM::HasV6KOps }, { ARM::HasV6Ops } },
  { "v6m", "Support ARM v6M instructions", { ARM::HasV6MOps }, { ARM::HasV6Ops } },
  { "v6t2", "Support ARM v6t2 instructions", { ARM::HasV6T2Ops }, { ARM::HasV8MBaselineOps, ARM::HasV6KOps, ARM::FeatureThumb2 } },
  { "v7", "Support ARM v7 instructions", { ARM::HasV7Ops }, { ARM::HasV6T2Ops, ARM::FeaturePerfMon, ARM::FeatureV7Clrex } },
  { "v7clrex", "Has v7 clrex instruction", { ARM::FeatureV7Clrex }, { } },
  { "v8", "Support ARM v8 instructions", { ARM::HasV8Ops }, { ARM::HasV7Ops, ARM::FeatureAcquireRelease } },
  { "v8.1a", "Support ARM v8.1a instructions", { ARM::HasV8_1aOps }, { ARM::HasV8Ops } },
  { "v8.2a", "Support ARM v8.2a instructions", { ARM::HasV8_2aOps }, { ARM::HasV8_1aOps } },
  { "v8m", "Support ARM v8M Baseline instructions", { ARM::HasV8MBaselineOps }, { ARM::HasV6MOps } },
  { "v8m.main", "Support ARM v8M Mainline instructions", { ARM::HasV8MMainlineOps }, { ARM::HasV7Ops } },
  { "vfp2", "Enable VFP2 instructions", { ARM::FeatureVFP2 }, { } },
  { "vfp3", "Enable VFP3 instructions", { ARM::FeatureVFP3 }, { ARM::FeatureVFP2 } },
  { "vfp4", "Enable VFP4 instructions", { ARM::FeatureVFP4 }, { ARM::FeatureVFP3, ARM::FeatureFP16 } },
  { "virtualization", "Supports Virtualization extension", { ARM::FeatureVirtualization }, { ARM::FeatureHWDiv, ARM::FeatureHWDivARM } },
  { "vmlx-forwarding", "Has multiplier accumulator forwarding", { ARM::FeatureVMLxForwarding }, { } },
  { "xscale", "ARMv5te architecture", { ARM::XScale }, { ARM::ARMv5te } },
  { "zcz", "Has zero-cycle zeroing instructions", { ARM::FeatureZCZeroing }, { } }
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetFeatureKV ARMSubTypeKV[] = {
  { "arm1020e", "Select the arm1020e processor", { ARM::ARMv5te }, { } },
  { "arm1020t", "Select the arm1020t processor", { ARM::ARMv5t }, { } },
  { "arm1022e", "Select the arm1022e processor", { ARM::ARMv5te }, { } },
  { "arm10e", "Select the arm10e processor", { ARM::ARMv5te }, { } },
  { "arm10tdmi", "Select the arm10tdmi processor", { ARM::ARMv5t }, { } },
  { "arm1136j-s", "Select the arm1136j-s processor", { ARM::ARMv6 }, { } },
  { "arm1136jf-s", "Select the arm1136jf-s processor", { ARM::ARMv6, ARM::FeatureVFP2, ARM::FeatureHasSlowFPVMLx }, { } },
  { "arm1156t2-s", "Select the arm1156t2-s processor", { ARM::ARMv6t2 }, { } },
  { "arm1156t2f-s", "Select the arm1156t2f-s processor", { ARM::ARMv6t2, ARM::FeatureVFP2, ARM::FeatureHasSlowFPVMLx }, { } },
  { "arm1176jz-s", "Select the arm1176jz-s processor", { ARM::ARMv6kz }, { } },
  { "arm1176jzf-s", "Select the arm1176jzf-s processor", { ARM::ARMv6kz, ARM::FeatureVFP2, ARM::FeatureHasSlowFPVMLx }, { } },
  { "arm710t", "Select the arm710t processor", { ARM::ARMv4t }, { } },
  { "arm720t", "Select the arm720t processor", { ARM::ARMv4t }, { } },
  { "arm7tdmi", "Select the arm7tdmi processor", { ARM::ARMv4t }, { } },
  { "arm7tdmi-s", "Select the arm7tdmi-s processor", { ARM::ARMv4t }, { } },
  { "arm8", "Select the arm8 processor", { ARM::ARMv4 }, { } },
  { "arm810", "Select the arm810 processor", { ARM::ARMv4 }, { } },
  { "arm9", "Select the arm9 processor", { ARM::ARMv4t }, { } },
  { "arm920", "Select the arm920 processor", { ARM::ARMv4t }, { } },
  { "arm920t", "Select the arm920t processor", { ARM::ARMv4t }, { } },
  { "arm922t", "Select the arm922t processor", { ARM::ARMv4t }, { } },
  { "arm926ej-s", "Select the arm926ej-s processor", { ARM::ARMv5te }, { } },
  { "arm940t", "Select the arm940t processor", { ARM::ARMv4t }, { } },
  { "arm946e-s", "Select the arm946e-s processor", { ARM::ARMv5te }, { } },
  { "arm966e-s", "Select the arm966e-s processor", { ARM::ARMv5te }, { } },
  { "arm968e-s", "Select the arm968e-s processor", { ARM::ARMv5te }, { } },
  { "arm9e", "Select the arm9e processor", { ARM::ARMv5te }, { } },
  { "arm9tdmi", "Select the arm9tdmi processor", { ARM::ARMv4t }, { } },
  { "cortex-a12", "Select the cortex-a12 processor", { ARM::ARMv7a, ARM::ProcA12, ARM::FeatureHasRAS, ARM::FeatureTrustZone, ARM::FeatureVMLxForwarding, ARM::FeatureT2XtPk, ARM::FeatureVFP4, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureAvoidPartialCPSR, ARM::FeatureVirtualization, ARM::FeatureMP }, { } },
  { "cortex-a15", "Select the cortex-a15 processor", { ARM::ARMv7a, ARM::ProcA15, ARM::FeatureHasRAS, ARM::FeatureTrustZone, ARM::FeatureT2XtPk, ARM::FeatureVFP4, ARM::FeatureMP, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureAvoidPartialCPSR, ARM::FeatureVirtualization }, { } },
  { "cortex-a17", "Select the cortex-a17 processor", { ARM::ARMv7a, ARM::ProcA17, ARM::FeatureHasRAS, ARM::FeatureTrustZone, ARM::FeatureMP, ARM::FeatureVMLxForwarding, ARM::FeatureT2XtPk, ARM::FeatureVFP4, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureAvoidPartialCPSR, ARM::FeatureVirtualization }, { } },
  { "cortex-a35", "Select the cortex-a35 processor", { ARM::ARMv8a, ARM::ProcA35, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureT2XtPk, ARM::FeatureCrypto, ARM::FeatureCRC }, { } },
  { "cortex-a5", "Select the cortex-a5 processor", { ARM::ARMv7a, ARM::ProcA5, ARM::FeatureHasRAS, ARM::FeatureTrustZone, ARM::FeatureSlowFPBrcc, ARM::FeatureHasSlowFPVMLx, ARM::FeatureVMLxForwarding, ARM::FeatureT2XtPk, ARM::FeatureMP, ARM::FeatureVFP4 }, { } },
  { "cortex-a53", "Select the cortex-a53 processor", { ARM::ARMv8a, ARM::ProcA53, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureT2XtPk, ARM::FeatureCrypto, ARM::FeatureCRC }, { } },
  { "cortex-a57", "Select the cortex-a57 processor", { ARM::ARMv8a, ARM::ProcA57, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureT2XtPk, ARM::FeatureCrypto, ARM::FeatureCRC }, { } },
  { "cortex-a7", "Select the cortex-a7 processor", { ARM::ARMv7a, ARM::ProcA7, ARM::FeatureHasRAS, ARM::FeatureTrustZone, ARM::FeatureSlowFPBrcc, ARM::FeatureHasSlowFPVMLx, ARM::FeatureVMLxForwarding, ARM::FeatureT2XtPk, ARM::FeatureMP, ARM::FeatureVFP4, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureVirtualization }, { } },
  { "cortex-a72", "Select the cortex-a72 processor", { ARM::ARMv8a, ARM::ProcA72, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureT2XtPk, ARM::FeatureCrypto, ARM::FeatureCRC }, { } },
  { "cortex-a8", "Select the cortex-a8 processor", { ARM::ARMv7a, ARM::ProcA8, ARM::FeatureHasRAS, ARM::FeatureTrustZone, ARM::FeatureSlowFPBrcc, ARM::FeatureHasSlowFPVMLx, ARM::FeatureVMLxForwarding, ARM::FeatureT2XtPk }, { } },
  { "cortex-a9", "Select the cortex-a9 processor", { ARM::ARMv7a, ARM::ProcA9, ARM::FeatureHasRAS, ARM::FeatureTrustZone, ARM::FeatureVMLxForwarding, ARM::FeatureT2XtPk, ARM::FeatureFP16, ARM::FeatureAvoidPartialCPSR, ARM::FeatureMP }, { } },
  { "cortex-m0", "Select the cortex-m0 processor", { ARM::ARMv6m }, { } },
  { "cortex-m0plus", "Select the cortex-m0plus processor", { ARM::ARMv6m }, { } },
  { "cortex-m1", "Select the cortex-m1 processor", { ARM::ARMv6m }, { } },
  { "cortex-m3", "Select the cortex-m3 processor", { ARM::ARMv7m }, { } },
  { "cortex-m4", "Select the cortex-m4 processor", { ARM::ARMv7em, ARM::FeatureVFP4, ARM::FeatureVFPOnlySP, ARM::FeatureD16 }, { } },
  { "cortex-m7", "Select the cortex-m7 processor", { ARM::ARMv7em, ARM::FeatureFPARMv8, ARM::FeatureD16 }, { } },
  { "cortex-r4", "Select the cortex-r4 processor", { ARM::ARMv7r, ARM::ProcR4, ARM::FeatureHasRAS, ARM::FeatureAvoidPartialCPSR, ARM::FeatureT2XtPk }, { } },
  { "cortex-r4f", "Select the cortex-r4f processor", { ARM::ARMv7r, ARM::ProcR4, ARM::FeatureHasRAS, ARM::FeatureSlowFPBrcc, ARM::FeatureHasSlowFPVMLx, ARM::FeatureVFP3, ARM::FeatureD16, ARM::FeatureAvoidPartialCPSR, ARM::FeatureT2XtPk }, { } },
  { "cortex-r5", "Select the cortex-r5 processor", { ARM::ARMv7r, ARM::ProcR5, ARM::FeatureHasRAS, ARM::FeatureVFP3, ARM::FeatureD16, ARM::FeatureSlowFPBrcc, ARM::FeatureHWDivARM, ARM::FeatureHasSlowFPVMLx, ARM::FeatureAvoidPartialCPSR, ARM::FeatureT2XtPk }, { } },
  { "cortex-r7", "Select the cortex-r7 processor", { ARM::ARMv7r, ARM::ProcR7, ARM::FeatureHasRAS, ARM::FeatureVFP3, ARM::FeatureD16, ARM::FeatureFP16, ARM::FeatureMP, ARM::FeatureSlowFPBrcc, ARM::FeatureHWDivARM, ARM::FeatureHasSlowFPVMLx, ARM::FeatureAvoidPartialCPSR, ARM::FeatureT2XtPk }, { } },
  { "cyclone", "Select the cyclone processor", { ARM::ARMv8a, ARM::ProcSwift, ARM::FeatureHasRAS, ARM::FeatureNEONForFP, ARM::FeatureT2XtPk, ARM::FeatureVFP4, ARM::FeatureMP, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureAvoidPartialCPSR, ARM::FeatureAvoidMOVsShOp, ARM::FeatureHasSlowFPVMLx, ARM::FeatureCrypto, ARM::FeatureZCZeroing }, { } },
  { "ep9312", "Select the ep9312 processor", { ARM::ARMv4t }, { } },
  { "exynos-m1", "Select the exynos-m1 processor", { ARM::ARMv8a, ARM::ProcExynosM1, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureT2XtPk, ARM::FeatureCrypto, ARM::FeatureCRC }, { } },
  { "generic", "Select the generic processor", { }, { } },
  { "iwmmxt", "Select the iwmmxt processor", { ARM::ARMv5te }, { } },
  { "krait", "Select the krait processor", { ARM::ARMv7a, ARM::ProcKrait, ARM::FeatureHasRAS, ARM::FeatureVMLxForwarding, ARM::FeatureT2XtPk, ARM::FeatureFP16, ARM::FeatureAvoidPartialCPSR, ARM::FeatureVFP4, ARM::FeatureHWDiv, ARM::FeatureHWDivARM }, { } },
  { "mpcore", "Select the mpcore processor", { ARM::ARMv6k, ARM::FeatureVFP2, ARM::FeatureHasSlowFPVMLx }, { } },
  { "mpcorenovfp", "Select the mpcorenovfp processor", { ARM::ARMv6k }, { } },
  { "sc000", "Select the sc000 processor", { ARM::ARMv6m }, { } },
  { "sc300", "Select the sc300 processor", { ARM::ARMv7m }, { } },
  { "strongarm", "Select the strongarm processor", { ARM::ARMv4 }, { } },
  { "strongarm110", "Select the strongarm110 processor", { ARM::ARMv4 }, { } },
  { "strongarm1100", "Select the strongarm1100 processor", { ARM::ARMv4 }, { } },
  { "strongarm1110", "Select the strongarm1110 processor", { ARM::ARMv4 }, { } },
  { "swift", "Select the swift processor", { ARM::ARMv7a, ARM::ProcSwift, ARM::FeatureHasRAS, ARM::FeatureNEONForFP, ARM::FeatureT2XtPk, ARM::FeatureVFP4, ARM::FeatureMP, ARM::FeatureHWDiv, ARM::FeatureHWDivARM, ARM::FeatureAvoidPartialCPSR, ARM::FeatureAvoidMOVsShOp, ARM::FeatureHasSlowFPVMLx }, { } },
  { "xscale", "Select the xscale processor", { ARM::ARMv5te }, { } }
};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#ifndef NDEBUG
#define DBGFIELD(x) x,
#else
#define DBGFIELD(x)
#endif

// Functional units for "ARMV6Itineraries"
namespace ARMV6ItinerariesFU {
  const unsigned V6_Pipe = 1 << 0;
}

// Functional units for "CortexA9Itineraries"
namespace CortexA9ItinerariesFU {
  const unsigned A9_Issue0 = 1 << 0;
  const unsigned A9_Issue1 = 1 << 1;
  const unsigned A9_Branch = 1 << 2;
  const unsigned A9_ALU0 = 1 << 3;
  const unsigned A9_ALU1 = 1 << 4;
  const unsigned A9_AGU = 1 << 5;
  const unsigned A9_NPipe = 1 << 6;
  const unsigned A9_MUX0 = 1 << 7;
  const unsigned A9_LSUnit = 1 << 8;
  const unsigned A9_DRegsVFP = 1 << 9;
  const unsigned A9_DRegsN = 1 << 10;
}

// ===============================================================
// Data tables for the new per-operand machine model.


#undef DBGFIELD
static inline MCSubtargetInfo *createARMMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, ARMFeatureKV, ARMSubTypeKV, NULL);
}

} // end llvm namespace
#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::ARMSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
  if (Bits[ARM::ARMv2] && ARMArch < ARMv2) ARMArch = ARMv2;
  if (Bits[ARM::ARMv2a] && ARMArch < ARMv2a) ARMArch = ARMv2a;
  if (Bits[ARM::ARMv3] && ARMArch < ARMv3) ARMArch = ARMv3;
  if (Bits[ARM::ARMv3m] && ARMArch < ARMv3m) ARMArch = ARMv3m;
  if (Bits[ARM::ARMv4] && ARMArch < ARMv4) ARMArch = ARMv4;
  if (Bits[ARM::ARMv4t] && ARMArch < ARMv4t) ARMArch = ARMv4t;
  if (Bits[ARM::ARMv5t] && ARMArch < ARMv5t) ARMArch = ARMv5t;
  if (Bits[ARM::ARMv5te] && ARMArch < ARMv5te) ARMArch = ARMv5te;
  if (Bits[ARM::ARMv5tej] && ARMArch < ARMv5tej) ARMArch = ARMv5tej;
  if (Bits[ARM::ARMv6] && ARMArch < ARMv6) ARMArch = ARMv6;
  if (Bits[ARM::ARMv6j] && ARMArch < ARMv7a) ARMArch = ARMv7a;
  if (Bits[ARM::ARMv6k] && ARMArch < ARMv6k) ARMArch = ARMv6k;
  if (Bits[ARM::ARMv6kz] && ARMArch < ARMv6kz) ARMArch = ARMv6kz;
  if (Bits[ARM::ARMv6m] && ARMArch < ARMv6m) ARMArch = ARMv6m;
  if (Bits[ARM::ARMv6sm] && ARMArch < ARMv6sm) ARMArch = ARMv6sm;
  if (Bits[ARM::ARMv6t2] && ARMArch < ARMv6t2) ARMArch = ARMv6t2;
  if (Bits[ARM::ARMv7a] && ARMArch < ARMv7a) ARMArch = ARMv7a;
  if (Bits[ARM::ARMv7em] && ARMArch < ARMv7em) ARMArch = ARMv7em;
  if (Bits[ARM::ARMv7k] && ARMArch < ARMv7a) ARMArch = ARMv7a;
  if (Bits[ARM::ARMv7m] && ARMArch < ARMv7m) ARMArch = ARMv7m;
  if (Bits[ARM::ARMv7r] && ARMArch < ARMv7r) ARMArch = ARMv7r;
  if (Bits[ARM::ARMv7s] && ARMArch < ARMv7a) ARMArch = ARMv7a;
  if (Bits[ARM::ARMv8a] && ARMArch < ARMv8a) ARMArch = ARMv8a;
  if (Bits[ARM::ARMv8mBaseline] && ARMArch < ARMv8mBaseline) ARMArch = ARMv8mBaseline;
  if (Bits[ARM::ARMv8mMainline] && ARMArch < ARMv8mMainline) ARMArch = ARMv8mMainline;
  if (Bits[ARM::ARMv81a] && ARMArch < ARMv81a) ARMArch = ARMv81a;
  if (Bits[ARM::ARMv82a] && ARMArch < ARMv82a) ARMArch = ARMv82a;
  if (Bits[ARM::Feature8MSecExt]) Has8MSecExt = true;
  if (Bits[ARM::FeatureAClass] && ARMProcClass < AClass) ARMProcClass = AClass;
  if (Bits[ARM::FeatureAcquireRelease]) HasAcquireRelease = true;
  if (Bits[ARM::FeatureAvoidMOVsShOp]) AvoidMOVsShifterOperand = true;
  if (Bits[ARM::FeatureAvoidPartialCPSR]) AvoidCPSRPartialUpdate = true;
  if (Bits[ARM::FeatureCRC]) HasCRC = true;
  if (Bits[ARM::FeatureCrypto]) HasCrypto = true;
  if (Bits[ARM::FeatureD16]) HasD16 = true;
  if (Bits[ARM::FeatureDB]) HasDataBarrier = true;
  if (Bits[ARM::FeatureDSP]) HasDSP = true;
  if (Bits[ARM::FeatureFP16]) HasFP16 = true;
  if (Bits[ARM::FeatureFPARMv8]) HasFPARMv8 = true;
  if (Bits[ARM::FeatureFullFP16]) HasFullFP16 = true;
  if (Bits[ARM::FeatureHWDiv]) HasHardwareDivide = true;
  if (Bits[ARM::FeatureHWDivARM]) HasHardwareDivideInARM = true;
  if (Bits[ARM::FeatureHasRAS]) HasRAS = true;
  if (Bits[ARM::FeatureHasSlowFPVMLx]) SlowFPVMLx = true;
  if (Bits[ARM::FeatureLongCalls]) GenLongCalls = true;
  if (Bits[ARM::FeatureMClass] && ARMProcClass < MClass) ARMProcClass = MClass;
  if (Bits[ARM::FeatureMP]) HasMPExtension = true;
  if (Bits[ARM::FeatureNEON]) HasNEON = true;
  if (Bits[ARM::FeatureNEONForFP]) UseNEONForSinglePrecisionFP = true;
  if (Bits[ARM::FeatureNaClTrap]) UseNaClTrap = true;
  if (Bits[ARM::FeatureNoARM]) NoARM = true;
  if (Bits[ARM::FeatureNoMovt]) NoMovt = true;
  if (Bits[ARM::FeaturePerfMon]) HasPerfMon = true;
  if (Bits[ARM::FeaturePref32BitThumb]) Pref32BitThumb = true;
  if (Bits[ARM::FeatureRClass] && ARMProcClass < RClass) ARMProcClass = RClass;
  if (Bits[ARM::FeatureReserveR9]) ReserveR9 = true;
  if (Bits[ARM::FeatureSlowFPBrcc]) SlowFPBrcc = true;
  if (Bits[ARM::FeatureStrictAlign]) StrictAlign = true;
  if (Bits[ARM::FeatureT2XtPk]) HasT2ExtractPack = true;
  if (Bits[ARM::FeatureThumb2]) HasThumb2 = true;
  if (Bits[ARM::FeatureTrustZone]) HasTrustZone = true;
  if (Bits[ARM::FeatureV7Clrex]) HasV7Clrex = true;
  if (Bits[ARM::FeatureVFP2]) HasVFPv2 = true;
  if (Bits[ARM::FeatureVFP3]) HasVFPv3 = true;
  if (Bits[ARM::FeatureVFP4]) HasVFPv4 = true;
  if (Bits[ARM::FeatureVFPOnlySP]) FPOnlySP = true;
  if (Bits[ARM::FeatureVMLxForwarding]) HasVMLxForwarding = true;
  if (Bits[ARM::FeatureVirtualization]) HasVirtualization = true;
  if (Bits[ARM::FeatureZCZeroing]) HasZeroCycleZeroing = true;
  if (Bits[ARM::HasV4TOps]) HasV4TOps = true;
  if (Bits[ARM::HasV5TEOps]) HasV5TEOps = true;
  if (Bits[ARM::HasV5TOps]) HasV5TOps = true;
  if (Bits[ARM::HasV6KOps]) HasV6KOps = true;
  if (Bits[ARM::HasV6MOps]) HasV6MOps = true;
  if (Bits[ARM::HasV6Ops]) HasV6Ops = true;
  if (Bits[ARM::HasV6T2Ops]) HasV6T2Ops = true;
  if (Bits[ARM::HasV7Ops]) HasV7Ops = true;
  if (Bits[ARM::HasV8MBaselineOps]) HasV8MBaselineOps = true;
  if (Bits[ARM::HasV8MMainlineOps]) HasV8MMainlineOps = true;
  if (Bits[ARM::HasV8Ops]) HasV8Ops = true;
  if (Bits[ARM::HasV8_1aOps]) HasV8_1aOps = true;
  if (Bits[ARM::HasV8_2aOps]) HasV8_2aOps = true;
  if (Bits[ARM::IWMMXT] && ARMArch < ARMv5te) ARMArch = ARMv5te;
  if (Bits[ARM::IWMMXT2] && ARMArch < ARMv5te) ARMArch = ARMv5te;
  if (Bits[ARM::ModeSoftFloat]) UseSoftFloat = true;
  if (Bits[ARM::ModeThumb]) InThumbMode = true;
  if (Bits[ARM::ProcA5] && ARMProcFamily < CortexA5) ARMProcFamily = CortexA5;
  if (Bits[ARM::ProcA7] && ARMProcFamily < CortexA7) ARMProcFamily = CortexA7;
  if (Bits[ARM::ProcA8] && ARMProcFamily < CortexA8) ARMProcFamily = CortexA8;
  if (Bits[ARM::ProcA9] && ARMProcFamily < CortexA9) ARMProcFamily = CortexA9;
  if (Bits[ARM::ProcA12] && ARMProcFamily < CortexA12) ARMProcFamily = CortexA12;
  if (Bits[ARM::ProcA15] && ARMProcFamily < CortexA15) ARMProcFamily = CortexA15;
  if (Bits[ARM::ProcA17] && ARMProcFamily < CortexA17) ARMProcFamily = CortexA17;
  if (Bits[ARM::ProcA35] && ARMProcFamily < CortexA35) ARMProcFamily = CortexA35;
  if (Bits[ARM::ProcA53] && ARMProcFamily < CortexA53) ARMProcFamily = CortexA53;
  if (Bits[ARM::ProcA57] && ARMProcFamily < CortexA57) ARMProcFamily = CortexA57;
  if (Bits[ARM::ProcA72] && ARMProcFamily < CortexA72) ARMProcFamily = CortexA72;
  if (Bits[ARM::ProcExynosM1] && ARMProcFamily < ExynosM1) ARMProcFamily = ExynosM1;
  if (Bits[ARM::ProcKrait] && ARMProcFamily < Krait) ARMProcFamily = Krait;
  if (Bits[ARM::ProcR4] && ARMProcFamily < CortexR4) ARMProcFamily = CortexR4;
  if (Bits[ARM::ProcR5] && ARMProcFamily < CortexR5) ARMProcFamily = CortexR5;
  if (Bits[ARM::ProcR7] && ARMProcFamily < CortexR7) ARMProcFamily = CortexR7;
  if (Bits[ARM::ProcSwift] && ARMProcFamily < Swift) ARMProcFamily = Swift;
  if (Bits[ARM::XScale] && ARMArch < ARMv5te) ARMArch = ARMv5te;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC
