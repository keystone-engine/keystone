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

enum {
  FeatureAbs2008 = 0,
  FeatureCRC = 1,
  FeatureCnMips = 2,
  FeatureCnMipsP = 3,
  FeatureDSP = 4,
  FeatureDSPR2 = 5,
  FeatureDSPR3 = 6,
  FeatureEVA = 7,
  FeatureFP64Bit = 8,
  FeatureFPXX = 9,
  FeatureFixR5900 = 10,
  FeatureGINV = 11,
  FeatureGP64Bit = 12,
  FeatureLongCalls = 13,
  FeatureMSA = 14,
  FeatureMT = 15,
  FeatureMicroMips = 16,
  FeatureMips1 = 17,
  FeatureMips2 = 18,
  FeatureMips3 = 19,
  FeatureMips3D = 20,
  FeatureMips3_32 = 21,
  FeatureMips3_32r2 = 22,
  FeatureMips4 = 23,
  FeatureMips4_32 = 24,
  FeatureMips4_32r2 = 25,
  FeatureMips5 = 26,
  FeatureMips5_32r2 = 27,
  FeatureMips16 = 28,
  FeatureMips32 = 29,
  FeatureMips32r2 = 30,
  FeatureMips32r3 = 31,
  FeatureMips32r5 = 32,
  FeatureMips32r6 = 33,
  FeatureMips64 = 34,
  FeatureMips64r2 = 35,
  FeatureMips64r3 = 36,
  FeatureMips64r5 = 37,
  FeatureMips64r6 = 38,
  FeatureNaN2008 = 39,
  FeatureNoABICalls = 40,
  FeatureNoMadd4 = 41,
  FeatureNoOddSPReg = 42,
  FeaturePTR64Bit = 43,
  FeatureR5900 = 44,
  FeatureSingleFloat = 45,
  FeatureSoftFloat = 46,
  FeatureStrictAlign = 47,
  FeatureSym32 = 48,
  FeatureUseCompactBranches = 49,
  FeatureUseIndirectJumpsHazard = 50,
  FeatureUseTCCInDIV = 51,
  FeatureVFPU = 52,
  FeatureVirt = 53,
  FeatureXGOT = 54,
  ImplI6400 = 55,
  ImplI6500 = 56,
  ImplP5600 = 57,
  NumSubtargetFeatures = 58
};

} // namespace Mips

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(Abs2008, false, abs2008)
GET_SUBTARGETINFO_MACRO(DisableMadd4, false, disableMadd4)
GET_SUBTARGETINFO_MACRO(FixR5900, false, fixR5900)
GET_SUBTARGETINFO_MACRO(Has3D, false, has3D)
GET_SUBTARGETINFO_MACRO(HasCRC, false, hasCRC)
GET_SUBTARGETINFO_MACRO(HasCnMips, false, hasCnMips)
GET_SUBTARGETINFO_MACRO(HasCnMipsP, false, hasCnMipsP)
GET_SUBTARGETINFO_MACRO(HasDSP, false, hasDSP)
GET_SUBTARGETINFO_MACRO(HasDSPR2, false, hasDSPR2)
GET_SUBTARGETINFO_MACRO(HasDSPR3, false, hasDSPR3)
GET_SUBTARGETINFO_MACRO(HasEVA, false, hasEVA)
GET_SUBTARGETINFO_MACRO(HasGINV, false, hasGINV)
GET_SUBTARGETINFO_MACRO(HasMSA, false, hasMSA)
GET_SUBTARGETINFO_MACRO(HasMT, false, hasMT)
GET_SUBTARGETINFO_MACRO(HasMips3_32, false, hasMips3_32)
GET_SUBTARGETINFO_MACRO(HasMips3_32r2, false, hasMips3_32r2)
GET_SUBTARGETINFO_MACRO(HasMips4_32, false, hasMips4_32)
GET_SUBTARGETINFO_MACRO(HasMips4_32r2, false, hasMips4_32r2)
GET_SUBTARGETINFO_MACRO(HasMips5_32r2, false, hasMips5_32r2)
GET_SUBTARGETINFO_MACRO(HasSym32, false, hasSym32)
GET_SUBTARGETINFO_MACRO(HasVFPU, false, hasVFPU)
GET_SUBTARGETINFO_MACRO(HasVirt, false, hasVirt)
GET_SUBTARGETINFO_MACRO(InMicroMipsMode, false, inMicroMipsMode)
GET_SUBTARGETINFO_MACRO(InMips16Mode, false, inMips16Mode)
GET_SUBTARGETINFO_MACRO(IsFP64bit, false, isFP64bit)
GET_SUBTARGETINFO_MACRO(IsFPXX, false, isFPXX)
GET_SUBTARGETINFO_MACRO(IsGP64bit, false, isGP64bit)
GET_SUBTARGETINFO_MACRO(IsNaN2008bit, false, isNaN2008bit)
GET_SUBTARGETINFO_MACRO(IsPTR64bit, false, isPTR64bit)
GET_SUBTARGETINFO_MACRO(IsR5900, false, isR5900)
GET_SUBTARGETINFO_MACRO(IsSingleFloat, false, isSingleFloat)
GET_SUBTARGETINFO_MACRO(IsSoftFloat, false, isSoftFloat)
GET_SUBTARGETINFO_MACRO(NoABICalls, false, noABICalls)
GET_SUBTARGETINFO_MACRO(StrictAlign, false, strictAlign)
GET_SUBTARGETINFO_MACRO(UseCompactBranches, false, useCompactBranches)
GET_SUBTARGETINFO_MACRO(UseIndirectJumpsHazard, false, useIndirectJumpsHazard)
GET_SUBTARGETINFO_MACRO(UseLongCalls, false, useLongCalls)
GET_SUBTARGETINFO_MACRO(UseOddSPReg, true, useOddSPReg)
GET_SUBTARGETINFO_MACRO(UseTCCInDIV, true, useTCCInDIV)
GET_SUBTARGETINFO_MACRO(UseXGOT, false, useXGOT)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 58, 2297> MipsFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 58 + 1, sizeof(SubtargetFeatureKV) * 58 + 9, Mips::FeatureAbs2008, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 57 + 44, sizeof(SubtargetFeatureKV) * 57 + 51, Mips::FeatureCnMips, { { { 0x800000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 56 + 73, sizeof(SubtargetFeatureKV) * 56 + 81, Mips::FeatureCnMipsP, { { { 0x4ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 55 + 104, sizeof(SubtargetFeatureKV) * 55 + 108, Mips::FeatureCRC, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 54 + 124, sizeof(SubtargetFeatureKV) * 54 + 128, Mips::FeatureDSP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 53 + 141, sizeof(SubtargetFeatureKV) * 53 + 147, Mips::FeatureDSPR2, { { { 0x10ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 52 + 163, sizeof(SubtargetFeatureKV) * 52 + 169, Mips::FeatureDSPR3, { { { 0x30ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 51 + 185, sizeof(SubtargetFeatureKV) * 51 + 189, Mips::FeatureEVA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 50 + 202, sizeof(SubtargetFeatureKV) * 50 + 212, Mips::FeatureFixR5900, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 49 + 248, sizeof(SubtargetFeatureKV) * 49 + 253, Mips::FeatureFP64Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 48 + 281, sizeof(SubtargetFeatureKV) * 48 + 286, Mips::FeatureFPXX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 47 + 303, sizeof(SubtargetFeatureKV) * 47 + 308, Mips::FeatureGINV, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 46 + 335, sizeof(SubtargetFeatureKV) * 46 + 340, Mips::FeatureGP64Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 45 + 382, sizeof(SubtargetFeatureKV) * 45 + 388, Mips::ImplI6400, { { { 0x4000004000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 44 + 409, sizeof(SubtargetFeatureKV) * 44 + 415, Mips::ImplI6500, { { { 0x4000004000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 43 + 436, sizeof(SubtargetFeatureKV) * 43 + 447, Mips::FeatureLongCalls, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 42 + 482, sizeof(SubtargetFeatureKV) * 42 + 492, Mips::FeatureMicroMips, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 41 + 507, sizeof(SubtargetFeatureKV) * 41 + 513, Mips::FeatureMips1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 40 + 554, sizeof(SubtargetFeatureKV) * 40 + 561, Mips::FeatureMips16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 39 + 573, sizeof(SubtargetFeatureKV) * 39 + 579, Mips::FeatureMips2, { { { 0x20000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 38 + 621, sizeof(SubtargetFeatureKV) * 38 + 627, Mips::FeatureMips3, { { { 0x641100ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 670, sizeof(SubtargetFeatureKV) * 37 + 677, Mips::FeatureMips32, { { { 0x1240000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 696, sizeof(SubtargetFeatureKV) * 36 + 705, Mips::FeatureMips32r2, { { { 0x2a400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 726, sizeof(SubtargetFeatureKV) * 35 + 735, Mips::FeatureMips32r3, { { { 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 756, sizeof(SubtargetFeatureKV) * 34 + 765, Mips::FeatureMips32r5, { { { 0x80000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 786, sizeof(SubtargetFeatureKV) * 33 + 795, Mips::FeatureMips32r6, { { { 0x8100000101ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 831, sizeof(SubtargetFeatureKV) * 32 + 840, Mips::FeatureMips3_32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 904, sizeof(SubtargetFeatureKV) * 31 + 915, Mips::FeatureMips3_32r2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 981, sizeof(SubtargetFeatureKV) * 30 + 988, Mips::FeatureMips3D, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 1000, sizeof(SubtargetFeatureKV) * 29 + 1006, Mips::FeatureMips4, { { { 0x3080000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 1026, sizeof(SubtargetFeatureKV) * 28 + 1035, Mips::FeatureMips4_32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 1098, sizeof(SubtargetFeatureKV) * 27 + 1109, Mips::FeatureMips4_32r2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 1174, sizeof(SubtargetFeatureKV) * 26 + 1180, Mips::FeatureMips5, { { { 0x8800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 1221, sizeof(SubtargetFeatureKV) * 25 + 1232, Mips::FeatureMips5_32r2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 1296, sizeof(SubtargetFeatureKV) * 24 + 1303, Mips::FeatureMips64, { { { 0x24000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 1322, sizeof(SubtargetFeatureKV) * 23 + 1331, Mips::FeatureMips64r2, { { { 0x440000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 1352, sizeof(SubtargetFeatureKV) * 22 + 1361, Mips::FeatureMips64r3, { { { 0x880000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 1382, sizeof(SubtargetFeatureKV) * 21 + 1391, Mips::FeatureMips64r5, { { { 0x1100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 1412, sizeof(SubtargetFeatureKV) * 20 + 1421, Mips::FeatureMips64r6, { { { 0xa200000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 1457, sizeof(SubtargetFeatureKV) * 19 + 1461, Mips::FeatureMSA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 1474, sizeof(SubtargetFeatureKV) * 18 + 1477, Mips::FeatureMT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 1489, sizeof(SubtargetFeatureKV) * 17 + 1497, Mips::FeatureNaN2008, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 1524, sizeof(SubtargetFeatureKV) * 16 + 1535, Mips::FeatureNoABICalls, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 1580, sizeof(SubtargetFeatureKV) * 15 + 1588, Mips::FeatureNoMadd4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 1640, sizeof(SubtargetFeatureKV) * 14 + 1651, Mips::FeatureNoOddSPReg, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 1699, sizeof(SubtargetFeatureKV) * 13 + 1705, Mips::ImplP5600, { { { 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 1725, sizeof(SubtargetFeatureKV) * 12 + 1731, Mips::FeaturePTR64Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 1756, sizeof(SubtargetFeatureKV) * 11 + 1762, Mips::FeatureR5900, { { { 0x200000080400ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 1797, sizeof(SubtargetFeatureKV) * 10 + 1810, Mips::FeatureSingleFloat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 1847, sizeof(SubtargetFeatureKV) * 9 + 1858, Mips::FeatureSoftFloat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 1903, sizeof(SubtargetFeatureKV) * 8 + 1916, Mips::FeatureStrictAlign, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 1952, sizeof(SubtargetFeatureKV) * 7 + 1958, Mips::FeatureSym32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 1987, sizeof(SubtargetFeatureKV) * 6 + 2008, Mips::FeatureUseCompactBranches, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 2062, sizeof(SubtargetFeatureKV) * 5 + 2087, Mips::FeatureUseIndirectJumpsHazard, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 2157, sizeof(SubtargetFeatureKV) * 4 + 2172, Mips::FeatureUseTCCInDIV, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 2208, sizeof(SubtargetFeatureKV) * 3 + 2213, Mips::FeatureVFPU, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 2244, sizeof(SubtargetFeatureKV) * 2 + 2249, Mips::FeatureVirt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 2273, sizeof(SubtargetFeatureKV) * 1 + 2278, Mips::FeatureXGOT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000abs2008\000Disable IEEE 754-2008 abs.fmt mode\000cnmips\000Octeon c"
    "nMIPS Support\000cnmipsp\000Octeon+ cnMIPS Support\000crc\000Mips R6 CR"
    "C ASE\000dsp\000Mips DSP ASE\000dspr2\000Mips DSP-R2 ASE\000dspr3\000Mi"
    "ps DSP-R3 ASE\000eva\000Mips EVA ASE\000fix-r5900\000Enable R5900 short"
    " loop erratum fix\000fp64\000Support 64-bit FP registers\000fpxx\000Sup"
    "port for FPXX\000ginv\000Mips Global Invalidate ASE\000gp64\000General "
    "Purpose Registers are 64-bit wide\000i6400\000MIPS I6400 Processor\000i"
    "6500\000MIPS I6500 Processor\000long-calls\000Disable use of the jal in"
    "struction\000micromips\000microMips mode\000mips1\000Mips I ISA Support"
    " [highly experimental]\000mips16\000Mips16 mode\000mips2\000Mips II ISA"
    " Support [highly experimental]\000mips3\000MIPS III ISA Support [highly"
    " experimental]\000mips32\000Mips32 ISA Support\000mips32r2\000Mips32r2 "
    "ISA Support\000mips32r3\000Mips32r3 ISA Support\000mips32r5\000Mips32r5"
    " ISA Support\000mips32r6\000Mips32r6 ISA Support [experimental]\000mips"
    "3_32\000Subset of MIPS-III that is also in MIPS32 [highly experimental]"
    "\000mips3_32r2\000Subset of MIPS-III that is also in MIPS32r2 [highly e"
    "xperimental]\000mips3d\000Mips 3D ASE\000mips4\000MIPS IV ISA Support\000"
    "mips4_32\000Subset of MIPS-IV that is also in MIPS32 [highly experiment"
    "al]\000mips4_32r2\000Subset of MIPS-IV that is also in MIPS32r2 [highly"
    " experimental]\000mips5\000MIPS V ISA Support [highly experimental]\000"
    "mips5_32r2\000Subset of MIPS-V that is also in MIPS32r2 [highly experim"
    "ental]\000mips64\000Mips64 ISA Support\000mips64r2\000Mips64r2 ISA Supp"
    "ort\000mips64r3\000Mips64r3 ISA Support\000mips64r5\000Mips64r5 ISA Sup"
    "port\000mips64r6\000Mips64r6 ISA Support [experimental]\000msa\000Mips "
    "MSA ASE\000mt\000Mips MT ASE\000nan2008\000IEEE 754-2008 NaN encoding\000"
    "noabicalls\000Disable SVR4-style position-independent code\000nomadd4\000"
    "Disable 4-operand madd.fmt and related instructions\000nooddspreg\000Di"
    "sable odd numbered single-precision registers\000p5600\000The P5600 Pro"
    "cessor\000ptr64\000Pointers are 64-bit wide\000r5900\000R5900 (PS2 Emot"
    "ion Engine) Support\000single-float\000Only supports single precision f"
    "loat\000soft-float\000Does not support floating point instructions\000s"
    "trict-align\000Disable unaligned load store for r6\000sym32\000Symbols "
    "are 32 bit on Mips64\000use-compact-branches\000Use compact branch inst"
    "ructions for MIPS32R6/MIPS64R6\000use-indirect-jump-hazard\000Use indir"
    "ect jump guards to prevent certain speculation based attacks\000use-tcc"
    "-in-div\000Force the assembler to use trapping\000vfpu\000Enable vector"
    " FPU instructions\000virt\000Mips Virtualization ASE\000xgot\000Assume "
    "32-bit GOT\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 22, 165> MipsSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 22 + 1, { { { 0x20000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 21 + 9, { { { 0x80000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 20 + 15, { { { 0x100000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 19 + 21, { { { 0x20000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 18 + 27, { { { 0x40000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 17 + 33, { { { 0x80000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 16 + 39, { { { 0x20000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 15 + 46, { { { 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 14 + 55, { { { 0x80000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 13 + 64, { { { 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 12 + 73, { { { 0x200000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 11 + 82, { { { 0x800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 10 + 88, { { { 0x4000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 9 + 94, { { { 0x400000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 8 + 101, { { { 0x800000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 7 + 110, { { { 0x1000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 6 + 119, { { { 0x2000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 5 + 128, { { { 0x4000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 4 + 137, { { { 0x800000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 3 + 144, { { { 0x80000000cULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 2 + 152, { { { 0x200000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 1 + 158, { { { 0x100000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
  },
    "\000generic\000i6400\000i6500\000mips1\000mips2\000mips3\000mips32\000m"
    "ips32r2\000mips32r3\000mips32r5\000mips32r6\000mips4\000mips5\000mips64"
    "\000mips64r2\000mips64r3\000mips64r5\000mips64r6\000octeon\000octeon+\000"
    "p5600\000r5900\000"};

namespace Mips_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace Mips_MC
struct MipsGenMCSubtargetInfo : public MCSubtargetInfo {
  MipsGenMCSubtargetInfo(const Triple &TT,
    StringRef CPU, StringRef TuneCPU, StringRef FS,
    StringTable PN,
    ArrayRef<SubtargetFeatureKV> PF,
    ArrayRef<SubtargetSubTypeKV> PD,
    const MCSchedModel *PSM,
    const MCWriteProcResEntry *WPR,
    const MCWriteLatencyEntry *WL,
    const MCReadAdvanceEntry *RA, const InstrStage *IS,
    const unsigned *OC, const unsigned *FP) :
      MCSubtargetInfo(TT, CPU, TuneCPU, FS, PN, PF, PD, PSM,
                      WPR, WL, RA, IS, OC, FP) { }

  unsigned resolveVariantSchedClass(unsigned SchedClass,
      const MCInst *MI, const MCInstrInfo *MCII,
      unsigned CPUID) const final {
    return Mips_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned MipsGenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (FB[Mips::FeaturePTR64Bit]) Modes |= (1 << 0);
  return Modes;
}
unsigned MipsGenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    // No HwMode for ValueType.
    return 0;
  case HwMode_RegInfo:
    Modes &= 1;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for RegInfo were found!");
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_EncodingInfo:
    // No HwMode for EncodingInfo.
    return 0;
  }
  llvm_unreachable("unexpected HwModeType");
  return 0; // should not get here
}

static inline MCSubtargetInfo *createMipsMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new MipsGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(MipsSubTypeKVStorage.Strings), MipsFeatureKVStorage.Features, MipsSubTypeKVStorage.SubTypes, nullptr, 
                      nullptr, nullptr, nullptr, 
                      nullptr, nullptr, nullptr);
}


} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_MC_DESC

#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC

#include "llvm/ADT/BitmaskEnum.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::MipsSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[Mips::FeatureAbs2008]) Abs2008 = true;
  if (Bits[Mips::FeatureCRC]) HasCRC = true;
  if (Bits[Mips::FeatureCnMips]) HasCnMips = true;
  if (Bits[Mips::FeatureCnMipsP]) HasCnMipsP = true;
  if (Bits[Mips::FeatureDSP]) HasDSP = true;
  if (Bits[Mips::FeatureDSPR2]) HasDSPR2 = true;
  if (Bits[Mips::FeatureDSPR3]) HasDSPR3 = true;
  if (Bits[Mips::FeatureEVA]) HasEVA = true;
  if (Bits[Mips::FeatureFP64Bit]) IsFP64bit = true;
  if (Bits[Mips::FeatureFPXX]) IsFPXX = true;
  if (Bits[Mips::FeatureFixR5900]) FixR5900 = true;
  if (Bits[Mips::FeatureGINV]) HasGINV = true;
  if (Bits[Mips::FeatureGP64Bit]) IsGP64bit = true;
  if (Bits[Mips::FeatureLongCalls]) UseLongCalls = true;
  if (Bits[Mips::FeatureMSA]) HasMSA = true;
  if (Bits[Mips::FeatureMT]) HasMT = true;
  if (Bits[Mips::FeatureMicroMips]) InMicroMipsMode = true;
  if (Bits[Mips::FeatureMips1] && MipsArchVersion < Mips1) MipsArchVersion = Mips1;
  if (Bits[Mips::FeatureMips2] && MipsArchVersion < Mips2) MipsArchVersion = Mips2;
  if (Bits[Mips::FeatureMips3] && MipsArchVersion < Mips3) MipsArchVersion = Mips3;
  if (Bits[Mips::FeatureMips3D]) Has3D = true;
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
  if (Bits[Mips::FeatureNoMadd4]) DisableMadd4 = true;
  if (Bits[Mips::FeatureNoOddSPReg]) UseOddSPReg = false;
  if (Bits[Mips::FeaturePTR64Bit]) IsPTR64bit = true;
  if (Bits[Mips::FeatureR5900]) IsR5900 = true;
  if (Bits[Mips::FeatureSingleFloat]) IsSingleFloat = true;
  if (Bits[Mips::FeatureSoftFloat]) IsSoftFloat = true;
  if (Bits[Mips::FeatureStrictAlign]) StrictAlign = true;
  if (Bits[Mips::FeatureSym32]) HasSym32 = true;
  if (Bits[Mips::FeatureUseCompactBranches]) UseCompactBranches = true;
  if (Bits[Mips::FeatureUseIndirectJumpsHazard]) UseIndirectJumpsHazard = true;
  if (Bits[Mips::FeatureUseTCCInDIV]) UseTCCInDIV = false;
  if (Bits[Mips::FeatureVFPU]) HasVFPU = true;
  if (Bits[Mips::FeatureVirt]) HasVirt = true;
  if (Bits[Mips::FeatureXGOT]) UseXGOT = true;
  if (Bits[Mips::ImplI6400] && ProcImpl < MipsSubtarget::CPU::I6400) ProcImpl = MipsSubtarget::CPU::I6400;
  if (Bits[Mips::ImplI6500] && ProcImpl < MipsSubtarget::CPU::I6500) ProcImpl = MipsSubtarget::CPU::I6500;
  if (Bits[Mips::ImplP5600] && ProcImpl < MipsSubtarget::CPU::P5600) ProcImpl = MipsSubtarget::CPU::P5600;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace Mips_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace Mips_MC
struct MipsGenSubtargetInfo : public TargetSubtargetInfo {
  explicit MipsGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class MipsHwModeBits : unsigned {
    DefaultMode = 0,
    MIPS64 = (1 << 0),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/MIPS64),
  };
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
  const FeatureBitset &getInlineIgnoreFeatures() const override;
  const FeatureBitset &getInlineInverseFeatures() const override;
  const FeatureBitset &getInlineMustMatchFeatures() const override;
};

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_HEADER

#ifdef GET_SUBTARGETINFO_CTOR
#undef GET_SUBTARGETINFO_CTOR

#include "llvm/CodeGen/TargetSchedule.h"

namespace llvm_ks {

extern const llvm_ks::StringRef MipsNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<58, 2297> MipsFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<22, 165> MipsSubTypeKVStorage;
extern const llvm_ks::MCSchedModel MipsSchedModels[];
extern const llvm_ks::MCWriteProcResEntry MipsWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry MipsWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry MipsReadAdvanceTable[];
MipsGenSubtargetInfo::MipsGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(MipsSubTypeKVStorage.Strings), ArrayRef(MipsFeatureKVStorage.Features), ArrayRef(MipsSubTypeKVStorage.SubTypes), MipsSchedModels, 
                        MipsWriteProcResTable, MipsWriteLatencyTable, MipsReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned MipsGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  switch (SchedClass) {
  case 111: // ADD_ADDiu_ANDi_ORi_ROTR_SEB_SEH_SLT_SLTu_SLL_SRA_SRL_XORi_ADDu_SLLV_SRAV_SRLV_LSA_COPY
    if (SchedModel->getProcessorID() == 3) { // MipsP5600Model
      if (1)
        return 750; // P5600WriteALU
      if (0)
        return 751; // P5600WriteAL2
    }
    break;
  case 112: // ADDi
    if (SchedModel->getProcessorID() == 3) { // MipsP5600Model
      if (1)
        return 750; // P5600WriteALU
      if (0)
        return 751; // P5600WriteAL2
    }
    break;
  case 227: // ROTRV
    if (SchedModel->getProcessorID() == 3) { // MipsP5600Model
      if (1)
        return 750; // P5600WriteALU
      if (0)
        return 751; // P5600WriteAL2
    }
    break;
  case 228: // ADD_ADDiu_ADDu_ANDi_ORi_ROTR_SEB_SEH_SLL_SLLV_SLT_SLTu_SRA_SRAV_SRL_SRLV_XORi
    if (SchedModel->getProcessorID() == 3) { // MipsP5600Model
      if (1)
        return 750; // P5600WriteALU
      if (0)
        return 751; // P5600WriteAL2
    }
    break;
  case 232: // COPY
    if (SchedModel->getProcessorID() == 3) { // MipsP5600Model
      if (1)
        return 750; // P5600WriteALU
      if (0)
        return 751; // P5600WriteAL2
    }
    break;
  };
  report_fatal_error("Expected a variant SchedClass");
} // MipsGenSubtargetInfo::resolveSchedClass

unsigned MipsGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return Mips_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // MipsGenSubtargetInfo::resolveVariantSchedClass

unsigned MipsGenSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const auto *Subtarget =
      static_cast<const MipsSubtarget *>(this);
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((Subtarget->isABI_N64())) Modes |= (1 << 0);
  return Modes;
}
unsigned MipsGenSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    // No HwMode for ValueType.
    return 0;
  case HwMode_RegInfo:
    Modes &= 1;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for RegInfo were found!");
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_EncodingInfo:
    // No HwMode for EncodingInfo.
    return 0;
  }
  llvm_unreachable("unexpected HwModeType");
  return 0; // should not get here
}
const FeatureBitset &MipsGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &MipsGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &MipsGenSubtargetInfo::getInlineMustMatchFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}


} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_CTOR

#ifdef GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS
#undef GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS


#endif // GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS

#ifdef GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS
#undef GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS


#endif // GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS

