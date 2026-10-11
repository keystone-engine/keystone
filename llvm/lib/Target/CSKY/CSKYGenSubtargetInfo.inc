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

namespace CSKY {

enum {
  FeatureBTST16 = 0,
  FeatureCCRT = 1,
  FeatureCache = 2,
  FeatureConstPool = 3,
  FeatureDSP = 4,
  FeatureDSPV2 = 5,
  FeatureDSP_Silan = 6,
  FeatureDoloop = 7,
  FeatureExtendLrw = 8,
  FeatureFPUV2_DF = 9,
  FeatureFPUV2_SF = 10,
  FeatureFPUV3_DF = 11,
  FeatureFPUV3_HF = 12,
  FeatureFPUV3_HI = 13,
  FeatureFPUV3_SF = 14,
  FeatureFdivdu = 15,
  FeatureHWDiv = 16,
  FeatureHardTP = 17,
  FeatureHighreg = 18,
  FeatureIstack = 19,
  FeatureJAVA = 20,
  FeatureNVIC = 21,
  FeaturePushPop = 22,
  FeatureSTM = 23,
  FeatureSmart = 24,
  FeatureSoftTP = 25,
  FeatureStackSize = 26,
  FeatureTrust = 27,
  FeatureVDSPV1_128 = 28,
  FeatureVDSPV2 = 29,
  Has2E3 = 30,
  Has3E3r1 = 31,
  Has3E7 = 32,
  Has3r1E3r2 = 33,
  Has3r2E3r3 = 34,
  Has7E10 = 35,
  Has10E60 = 36,
  HasDSP1E2 = 37,
  HasDSPE60 = 38,
  HasE1 = 39,
  HasE2 = 40,
  HasFLOAT1E2 = 41,
  HasFLOAT1E3 = 42,
  HasFLOAT3E4 = 43,
  HasFLOAT7E60 = 44,
  HasFLOATE1 = 45,
  HasMP = 46,
  HasMP1E2 = 47,
  HasVDSP2E3 = 48,
  HasVDSP2E60F = 49,
  ModeHardFloat = 50,
  ModeHardFloatABI = 51,
  ProcCK801 = 52,
  ProcCK802 = 53,
  ProcCK803 = 54,
  ProcCK803S = 55,
  ProcCK804 = 56,
  ProcCK805 = 57,
  ProcCK807 = 58,
  ProcCK810 = 59,
  ProcCK810V = 60,
  ProcCK860 = 61,
  ProcCK860V = 62,
  NumSubtargetFeatures = 63
};

} // namespace CSKY

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(DumpConstPool, false, dumpConstPool)
GET_SUBTARGETINFO_MACRO(EnableInterruptAttribute, false, enableInterruptAttribute)
GET_SUBTARGETINFO_MACRO(EnableStackSize, false, enableStackSize)
GET_SUBTARGETINFO_MACRO(Has10E60, false, has10E60)
GET_SUBTARGETINFO_MACRO(Has2E3, false, has2E3)
GET_SUBTARGETINFO_MACRO(Has3E3r1, false, has3E3r1)
GET_SUBTARGETINFO_MACRO(Has3E7, false, has3E7)
GET_SUBTARGETINFO_MACRO(Has3r1E3r2, false, has3r1E3r2)
GET_SUBTARGETINFO_MACRO(Has3r2E3r3, false, has3r2E3r3)
GET_SUBTARGETINFO_MACRO(Has7E10, false, has7E10)
GET_SUBTARGETINFO_MACRO(HasBTST16, false, hasBTST16)
GET_SUBTARGETINFO_MACRO(HasCache, false, hasCache)
GET_SUBTARGETINFO_MACRO(HasDSP, false, hasDSP)
GET_SUBTARGETINFO_MACRO(HasDSP1E2, false, hasDSP1E2)
GET_SUBTARGETINFO_MACRO(HasDSPE60, false, hasDSPE60)
GET_SUBTARGETINFO_MACRO(HasDSPV2, false, hasDSPV2)
GET_SUBTARGETINFO_MACRO(HasDSP_Silan, false, hasDSP_Silan)
GET_SUBTARGETINFO_MACRO(HasDoloop, false, hasDoloop)
GET_SUBTARGETINFO_MACRO(HasE1, false, hasE1)
GET_SUBTARGETINFO_MACRO(HasE2, false, hasE2)
GET_SUBTARGETINFO_MACRO(HasExtendLrw, false, hasExtendLrw)
GET_SUBTARGETINFO_MACRO(HasFLOAT1E2, false, hasFLOAT1E2)
GET_SUBTARGETINFO_MACRO(HasFLOAT1E3, false, hasFLOAT1E3)
GET_SUBTARGETINFO_MACRO(HasFLOAT3E4, false, hasFLOAT3E4)
GET_SUBTARGETINFO_MACRO(HasFLOAT7E60, false, hasFLOAT7E60)
GET_SUBTARGETINFO_MACRO(HasFLOATE1, false, hasFLOATE1)
GET_SUBTARGETINFO_MACRO(HasFPUv2DoubleFloat, false, hasFPUv2DoubleFloat)
GET_SUBTARGETINFO_MACRO(HasFPUv2SingleFloat, false, hasFPUv2SingleFloat)
GET_SUBTARGETINFO_MACRO(HasFPUv3DoubleFloat, false, hasFPUv3DoubleFloat)
GET_SUBTARGETINFO_MACRO(HasFPUv3HalfFloat, false, hasFPUv3HalfFloat)
GET_SUBTARGETINFO_MACRO(HasFPUv3HalfWord, false, hasFPUv3HalfWord)
GET_SUBTARGETINFO_MACRO(HasFPUv3SingleFloat, false, hasFPUv3SingleFloat)
GET_SUBTARGETINFO_MACRO(HasFdivdu, false, hasFdivdu)
GET_SUBTARGETINFO_MACRO(HasHardwareDivide, false, hasHardwareDivide)
GET_SUBTARGETINFO_MACRO(HasHighRegisters, false, hasHighRegisters)
GET_SUBTARGETINFO_MACRO(HasJAVA, false, hasJAVA)
GET_SUBTARGETINFO_MACRO(HasMP, false, hasMP)
GET_SUBTARGETINFO_MACRO(HasMP1E2, false, hasMP1E2)
GET_SUBTARGETINFO_MACRO(HasNVIC, false, hasNVIC)
GET_SUBTARGETINFO_MACRO(HasPushPop, false, hasPushPop)
GET_SUBTARGETINFO_MACRO(HasSTM, false, hasSTM)
GET_SUBTARGETINFO_MACRO(HasTrust, false, hasTrust)
GET_SUBTARGETINFO_MACRO(HasVDSP2E3, false, hasVDSP2E3)
GET_SUBTARGETINFO_MACRO(HasVDSP2E60F, false, hasVDSP2E60F)
GET_SUBTARGETINFO_MACRO(HasVDSPV1_128, false, hasVDSPV1_128)
GET_SUBTARGETINFO_MACRO(HasVDSPV2, false, hasVDSPV2)
GET_SUBTARGETINFO_MACRO(ReadTPHard, true, readTPHard)
GET_SUBTARGETINFO_MACRO(ReadTPHard, false, readTPHard)
GET_SUBTARGETINFO_MACRO(SmartMode, false, smartMode)
GET_SUBTARGETINFO_MACRO(UseCCRT, false, useCCRT)
GET_SUBTARGETINFO_MACRO(UseHardFloat, false, useHardFloat)
GET_SUBTARGETINFO_MACRO(UseHardFloatABI, false, useHardFloatABI)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 63, 2350> CSKYFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 63 + 1, sizeof(SubtargetFeatureKV) * 63 + 7, CSKY::Has10E60, { { { 0x800000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 62 + 39, sizeof(SubtargetFeatureKV) * 62 + 43, CSKY::Has2E3, { { { 0x10000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 61 + 73, sizeof(SubtargetFeatureKV) * 61 + 79, CSKY::Has3E3r1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 60 + 111, sizeof(SubtargetFeatureKV) * 60 + 117, CSKY::Has3r1E3r2, { { { 0x80000080ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 59 + 149, sizeof(SubtargetFeatureKV) * 59 + 155, CSKY::Has3r2E3r3, { { { 0x80ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 58 + 187, sizeof(SubtargetFeatureKV) * 58 + 191, CSKY::Has3E7, { { { 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 57 + 221, sizeof(SubtargetFeatureKV) * 57 + 226, CSKY::Has7E10, { { { 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 56 + 257, sizeof(SubtargetFeatureKV) * 56 + 264, CSKY::FeatureBTST16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 55 + 297, sizeof(SubtargetFeatureKV) * 55 + 303, CSKY::FeatureCache, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 54 + 316, sizeof(SubtargetFeatureKV) * 54 + 321, CSKY::FeatureCCRT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 53 + 347, sizeof(SubtargetFeatureKV) * 53 + 353, CSKY::ProcCK801, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 52 + 375, sizeof(SubtargetFeatureKV) * 52 + 381, CSKY::ProcCK802, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 51 + 403, sizeof(SubtargetFeatureKV) * 51 + 409, CSKY::ProcCK803, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 50 + 431, sizeof(SubtargetFeatureKV) * 50 + 438, CSKY::ProcCK803S, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 49 + 461, sizeof(SubtargetFeatureKV) * 49 + 467, CSKY::ProcCK804, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 48 + 489, sizeof(SubtargetFeatureKV) * 48 + 495, CSKY::ProcCK805, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 47 + 517, sizeof(SubtargetFeatureKV) * 47 + 523, CSKY::ProcCK807, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 46 + 545, sizeof(SubtargetFeatureKV) * 46 + 551, CSKY::ProcCK810, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 45 + 573, sizeof(SubtargetFeatureKV) * 45 + 580, CSKY::ProcCK810V, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 44 + 603, sizeof(SubtargetFeatureKV) * 44 + 609, CSKY::ProcCK860, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 43 + 631, sizeof(SubtargetFeatureKV) * 43 + 638, CSKY::ProcCK860V, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 42 + 661, sizeof(SubtargetFeatureKV) * 42 + 671, CSKY::FeatureConstPool, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 41 + 706, sizeof(SubtargetFeatureKV) * 41 + 713, CSKY::FeatureDoloop, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 40 + 740, sizeof(SubtargetFeatureKV) * 40 + 747, CSKY::HasDSP1E2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 39 + 780, sizeof(SubtargetFeatureKV) * 39 + 790, CSKY::FeatureDSP_Silan, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 38 + 820, sizeof(SubtargetFeatureKV) * 38 + 827, CSKY::HasDSPE60, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 860, sizeof(SubtargetFeatureKV) * 37 + 866, CSKY::FeatureDSPV2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 895, sizeof(SubtargetFeatureKV) * 36 + 898, CSKY::HasE1, { { { 0x100ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 927, sizeof(SubtargetFeatureKV) * 35 + 930, CSKY::HasE2, { { { 0x8000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 959, sizeof(SubtargetFeatureKV) * 34 + 964, CSKY::FeatureDSP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 988, sizeof(SubtargetFeatureKV) * 33 + 993, CSKY::FeatureExtendLrw, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 1024, sizeof(SubtargetFeatureKV) * 32 + 1031, CSKY::FeatureFdivdu, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 1064, sizeof(SubtargetFeatureKV) * 31 + 1073, CSKY::HasFLOAT1E2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 1108, sizeof(SubtargetFeatureKV) * 30 + 1117, CSKY::HasFLOAT1E3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 1152, sizeof(SubtargetFeatureKV) * 29 + 1161, CSKY::HasFLOAT3E4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 1196, sizeof(SubtargetFeatureKV) * 28 + 1206, CSKY::HasFLOAT7E60, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 1242, sizeof(SubtargetFeatureKV) * 27 + 1250, CSKY::HasFLOATE1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 1284, sizeof(SubtargetFeatureKV) * 26 + 1293, CSKY::FeatureFPUV2_DF, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 1332, sizeof(SubtargetFeatureKV) * 25 + 1341, CSKY::FeatureFPUV2_SF, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 1380, sizeof(SubtargetFeatureKV) * 24 + 1389, CSKY::FeatureFPUV3_DF, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 1428, sizeof(SubtargetFeatureKV) * 23 + 1437, CSKY::FeatureFPUV3_HF, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 1486, sizeof(SubtargetFeatureKV) * 22 + 1495, CSKY::FeatureFPUV3_HI, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 1542, sizeof(SubtargetFeatureKV) * 21 + 1551, CSKY::FeatureFPUV3_SF, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 1590, sizeof(SubtargetFeatureKV) * 20 + 1601, CSKY::ModeHardFloat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 1634, sizeof(SubtargetFeatureKV) * 19 + 1649, CSKY::ModeHardFloatABI, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 1690, sizeof(SubtargetFeatureKV) * 18 + 1698, CSKY::FeatureHardTP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 1726, sizeof(SubtargetFeatureKV) * 17 + 1741, CSKY::FeatureHighreg, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 1766, sizeof(SubtargetFeatureKV) * 16 + 1772, CSKY::FeatureHWDiv, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 1799, sizeof(SubtargetFeatureKV) * 15 + 1806, CSKY::FeatureIstack, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 1833, sizeof(SubtargetFeatureKV) * 14 + 1838, CSKY::FeatureJAVA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 1863, sizeof(SubtargetFeatureKV) * 13 + 1866, CSKY::HasMP, { { { 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 1895, sizeof(SubtargetFeatureKV) * 12 + 1901, CSKY::HasMP1E2, { { { 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 1933, sizeof(SubtargetFeatureKV) * 11 + 1947, CSKY::FeatureSTM, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 1987, sizeof(SubtargetFeatureKV) * 10 + 1992, CSKY::FeatureNVIC, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 2004, sizeof(SubtargetFeatureKV) * 9 + 2012, CSKY::FeaturePushPop, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 2041, sizeof(SubtargetFeatureKV) * 8 + 2047, CSKY::FeatureSmart, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 2074, sizeof(SubtargetFeatureKV) * 7 + 2082, CSKY::FeatureSoftTP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 2111, sizeof(SubtargetFeatureKV) * 6 + 2122, CSKY::FeatureStackSize, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 2152, sizeof(SubtargetFeatureKV) * 5 + 2158, CSKY::FeatureTrust, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 2184, sizeof(SubtargetFeatureKV) * 4 + 2192, CSKY::HasVDSP2E3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 2226, sizeof(SubtargetFeatureKV) * 3 + 2236, CSKY::HasVDSP2E60F, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 2272, sizeof(SubtargetFeatureKV) * 2 + 2279, CSKY::FeatureVDSPV1_128, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 2314, sizeof(SubtargetFeatureKV) * 1 + 2321, CSKY::FeatureVDSPV2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000" "10e60\000Support CSKY 10e60 instructions\000" "2e3\000Support CS"
    "KY 2e3 instructions\000" "3e3r1\000Support CSKY 3e3r1 instructions\000" ""
    "3e3r2\000Support CSKY 3e3r2 instructions\000" "3e3r3\000Support CSKY 3e"
    "3r3 instructions\000" "3e7\000Support CSKY 3e7 instructions\000" "7e10\000"
    "Support CSKY 7e10 instructions\000btst16\000Use the 16-bit btsti instru"
    "ction\000cache\000Enable cache\000ccrt\000Use CSKY compiler runtime\000"
    "ck801\000CSKY ck801 processors\000ck802\000CSKY ck802 processors\000ck8"
    "03\000CSKY ck803 processors\000ck803s\000CSKY ck803s processors\000ck80"
    "4\000CSKY ck804 processors\000ck805\000CSKY ck805 processors\000ck807\000"
    "CSKY ck807 processors\000ck810\000CSKY ck810 processors\000ck810v\000CS"
    "KY ck810v processors\000ck860\000CSKY ck860 processors\000ck860v\000CSK"
    "Y ck860v processors\000constpool\000Dump the constant pool by compiler\000"
    "doloop\000Enable doloop instructions\000dsp1e2\000Support CSKY dsp1e2 i"
    "nstructions\000dsp_silan\000Enable DSP Silan instructions\000dspe60\000"
    "Support CSKY dspe60 instructions\000dspv2\000Enable DSP V2.0 instructio"
    "ns\000e1\000Support CSKY e1 instructions\000e2\000Support CSKY e2 instr"
    "uctions\000edsp\000Enable DSP instructions\000elrw\000Use the extend LR"
    "W instruction\000fdivdu\000Enable float divide instructions\000float1e2"
    "\000Support CSKY float1e2 instructions\000float1e3\000Support CSKY floa"
    "t1e3 instructions\000float3e4\000Support CSKY float3e4 instructions\000"
    "float7e60\000Support CSKY float7e60 instructions\000floate1\000Support "
    "CSKY floate1 instructions\000fpuv2_df\000Enable FPUv2 double float inst"
    "ructions\000fpuv2_sf\000Enable FPUv2 single float instructions\000fpuv3"
    "_df\000Enable FPUv3 double float instructions\000fpuv3_hf\000Enable FPU"
    "v3 half precision operate instructions\000fpuv3_hi\000Enable FPUv3 half"
    " word converting instructions\000fpuv3_sf\000Enable FPUv3 single float "
    "instructions\000hard-float\000Use hard floating point features\000hard-"
    "float-abi\000Use hard floating point ABI to pass args\000hard-tp\000Ena"
    "ble TLS Pointer register\000high-registers\000Enable r16-r31 registers\000"
    "hwdiv\000Enable divide instructions\000istack\000Enable interrupt attri"
    "bute\000java\000Enable java instructions\000mp\000Support CSKY mp instr"
    "uctions\000mp1e2\000Support CSKY mp1e2 instructions\000multiple_stld\000"
    "Enable multiple load/store instructions\000nvic\000Enable NVIC\000pushp"
    "op\000Enable push/pop instructions\000smart\000Let CPU work in Smart Mo"
    "de\000soft-tp\000Disable TLS Pointer register\000stack-size\000Output s"
    "tack size information\000trust\000Enable trust instructions\000vdsp2e3\000"
    "Support CSKY vdsp2e3 instructions\000vdsp2e60f\000Support CSKY vdsp2e60"
    "f instructions\000vdspv1\000Enable 128bit vdsp-v1 instructions\000vdspv"
    "2\000Enable vdsp-v2 instructions\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 152, 1236> CSKYSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 152 + 1, { { { 0x400c06108270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 151 + 6, { { { 0x400ee6108278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 150 + 12, { { { 0x800e26808278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 149 + 17, { { { 0x800e26808278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 148 + 23, { { { 0x1800e26818278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 147 + 30, { { { 0x1800e26818278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 146 + 36, { { { 0x2000d05608277805ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 145 + 41, { { { 0x6002d05628277805ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 144 + 47, { { { 0x10008008000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 143 + 53, { { { 0x10008008000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 142 + 60, { { { 0x20010008200001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 141 + 66, { { { 0x20010008300001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 140 + 73, { { { 0x20010008200001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 139 + 80, { { { 0x40400048210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 138 + 86, { { { 0x40406048210011ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 137 + 93, { { { 0x40646048210411ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 136 + 101, { { { 0x40646048210411ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 135 + 110, { { { 0x406460c8250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 134 + 121, { { { 0x40646648250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 133 + 132, { { { 0x40646648250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 132 + 143, { { { 0x40646048210411ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 131 + 153, { { { 0x406460c8250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 130 + 165, { { { 0x40646648250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 129 + 177, { { { 0x40646648250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 128 + 189, { { { 0x406460c8250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 127 + 199, { { { 0x40646648250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 126 + 209, { { { 0x40646648250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 125 + 219, { { { 0x40646048210411ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 124 + 228, { { { 0x406460c8250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 123 + 239, { { { 0x40646648250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 122 + 250, { { { 0x40646648250431ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 121 + 261, { { { 0x40406048210011ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 120 + 269, { { { 0x404064c8250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 119 + 279, { { { 0x40406648250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 118 + 289, { { { 0x40406648250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 117 + 299, { { { 0x40406048210011ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 116 + 308, { { { 0x404064c8250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 115 + 319, { { { 0x40406648250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 114 + 330, { { { 0x40406648250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 113 + 341, { { { 0x404064c8250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 112 + 350, { { { 0x40406648250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 111 + 359, { { { 0x40406648250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 110 + 368, { { { 0x40406048210011ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 109 + 376, { { { 0x404064c8250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 108 + 386, { { { 0x40406648250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 107 + 396, { { { 0x40406648250031ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 106 + 406, { { { 0x40640048210401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 105 + 413, { { { 0x40640048210401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 104 + 421, { { { 0x406404c8210421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 103 + 431, { { { 0x40640648210421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 102 + 441, { { { 0x40640648210421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 101 + 451, { { { 0x406404c8210421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 100 + 460, { { { 0x40640648210421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 99 + 469, { { { 0x40640648210421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 98 + 478, { { { 0x40640048210401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 97 + 486, { { { 0x406400c8210421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 96 + 496, { { { 0x40640648210421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 95 + 506, { { { 0x40640648210421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 94 + 516, { { { 0x40400048210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 93 + 523, { { { 0x404004c8210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 92 + 532, { { { 0x40400648210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 91 + 541, { { { 0x40400648210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 90 + 550, { { { 0x40400048210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 89 + 558, { { { 0x404004c8210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 88 + 568, { { { 0x40400648210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 87 + 578, { { { 0x40400648210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 86 + 588, { { { 0x404004c8210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 85 + 596, { { { 0x40400648210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 84 + 604, { { { 0x40400648210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 83 + 612, { { { 0xc04000c8210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 82 + 619, { { { 0xc04060c8210011ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 81 + 627, { { { 0xc06460c8210411ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 80 + 636, { { { 0xc06460c8210451ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 79 + 646, { { { 0xc06460c8210451ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 78 + 657, { { { 0xc06460c8210411ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 77 + 667, { { { 0xc04060c8210051ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 76 + 676, { { { 0xc06400c8210401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 75 + 684, { { { 0xc06400c8210441ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 74 + 693, { { { 0xc04000c8210041ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 73 + 701, { { { 0xc04000c8210041ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 72 + 710, { { { 0xc04000c8210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 71 + 718, { { { 0x40400048210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 70 + 725, { { { 0x404004c8210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 69 + 734, { { { 0x40400648210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 68 + 743, { { { 0x40400648210021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 67 + 752, { { { 0x140400648210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 66 + 758, { { { 0x140400648250021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 65 + 765, { { { 0x140640648250421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 64 + 773, { { { 0x140640648250421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 63 + 782, { { { 0x140640648250421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 62 + 792, { { { 0x140640648250421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 61 + 801, { { { 0x140400648250021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 60 + 809, { { { 0x140400648250021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 59 + 818, { { { 0x140400648250021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 58 + 826, { { { 0x140640648210401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 57 + 833, { { { 0x140640648210401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 56 + 841, { { { 0x140640648210401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 55 + 849, { { { 0x140400648210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 54 + 856, { { { 0x140400648210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 53 + 864, { { { 0x140400648210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 52 + 871, { { { 0x241400668250001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 51 + 877, { { { 0x241400668250021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 50 + 884, { { { 0x241640668250421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 49 + 892, { { { 0x241640668250421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 48 + 901, { { { 0x241400668250021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 47 + 909, { { { 0x241640668250401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 46 + 916, { { { 0x241640668250401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 45 + 924, { { { 0x241400668250001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 44 + 931, { { { 0x400c06108270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 43 + 937, { { { 0x400c06108270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 42 + 944, { { { 0x400ee6108278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 41 + 952, { { { 0x400ee6108278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 40 + 959, { { { 0x800c06808270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 39 + 965, { { { 0x800c06808270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 38 + 972, { { { 0x800e26808278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 37 + 980, { { { 0x800e26808278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 36 + 989, { { { 0x1800e26818278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 35 + 999, { { { 0x1800e26818278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 34 + 1008, { { { 0x800c06808270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 33 + 1016, { { { 0x1800c06818270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 32 + 1025, { { { 0x1800c06818270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 31 + 1033, { { { 0x800e26808278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 30 + 1040, { { { 0x800e26808278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 29 + 1048, { { { 0x1800e26818278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 28 + 1057, { { { 0x1800e26818278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 27 + 1065, { { { 0x800c06808270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 26 + 1072, { { { 0x1800c06818270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 25 + 1080, { { { 0x1800c06818270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 24 + 1087, { { { 0x2000c05608270005ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 23 + 1093, { { { 0x2000d05608277805ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 22 + 1100, { { { 0x6002d05628277805ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 21 + 1108, { { { 0x6002c05628270005ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 20 + 1115, { { { 0x10008008000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 19 + 1120, { { { 0x20010008200001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 18 + 1125, { { { 0x20010008200001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 17 + 1131, { { { 0x40400648210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 16 + 1136, { { { 0x40400648210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 15 + 1142, { { { 0x140400648250021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 14 + 1148, { { { 0x140640648250421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 13 + 1155, { { { 0x140640648250421ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 12 + 1163, { { { 0x140400648250021ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 11 + 1170, { { { 0x140640648210401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 10 + 1176, { { { 0x140640648210401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 9 + 1183, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 8 + 1191, { { { 0x241400668250001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 7 + 1196, { { { 0x241640668250401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 6 + 1202, { { { 0x400c06108270014ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 5 + 1207, { { { 0x400ee6108278614ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 4 + 1213, { { { 0x20010008200001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 3 + 1218, { { { 0x20010008200001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 2 + 1224, { { { 0x40400648210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 1 + 1229, { { { 0x40400648210001ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
  },
    "\000c807\000c807f\000c810\000c810t\000c810tv\000c810v\000c860\000c860v\000"
    "ck801\000ck801t\000ck802\000ck802j\000ck802t\000ck803\000ck803e\000ck80"
    "3ef\000ck803efh\000ck803efhr1\000ck803efhr2\000ck803efhr3\000ck803efht\000"
    "ck803efhtr1\000ck803efhtr2\000ck803efhtr3\000ck803efr1\000ck803efr2\000"
    "ck803efr3\000ck803eft\000ck803eftr1\000ck803eftr2\000ck803eftr3\000ck80"
    "3eh\000ck803ehr1\000ck803ehr2\000ck803ehr3\000ck803eht\000ck803ehtr1\000"
    "ck803ehtr2\000ck803ehtr3\000ck803er1\000ck803er2\000ck803er3\000ck803et"
    "\000ck803etr1\000ck803etr2\000ck803etr3\000ck803f\000ck803fh\000ck803fh"
    "r1\000ck803fhr2\000ck803fhr3\000ck803fr1\000ck803fr2\000ck803fr3\000ck8"
    "03ft\000ck803ftr1\000ck803ftr2\000ck803ftr3\000ck803h\000ck803hr1\000ck"
    "803hr2\000ck803hr3\000ck803ht\000ck803htr1\000ck803htr2\000ck803htr3\000"
    "ck803r1\000ck803r2\000ck803r3\000ck803s\000ck803se\000ck803sef\000ck803"
    "sefn\000ck803sefnt\000ck803seft\000ck803sen\000ck803sf\000ck803sfn\000c"
    "k803sn\000ck803snt\000ck803st\000ck803t\000ck803tr1\000ck803tr2\000ck80"
    "3tr3\000ck804\000ck804e\000ck804ef\000ck804efh\000ck804efht\000ck804eft"
    "\000ck804eh\000ck804eht\000ck804et\000ck804f\000ck804fh\000ck804ft\000c"
    "k804h\000ck804ht\000ck804t\000ck805\000ck805e\000ck805ef\000ck805eft\000"
    "ck805et\000ck805f\000ck805ft\000ck805t\000ck807\000ck807e\000ck807ef\000"
    "ck807f\000ck810\000ck810e\000ck810ef\000ck810eft\000ck810eftv\000ck810e"
    "fv\000ck810et\000ck810etv\000ck810ev\000ck810f\000ck810ft\000ck810ftv\000"
    "ck810fv\000ck810t\000ck810tv\000ck810v\000ck860\000ck860f\000ck860fv\000"
    "ck860v\000e801\000e802\000e802t\000e803\000e803t\000e804d\000e804df\000"
    "e804dft\000e804dt\000e804f\000e804ft\000generic\000i805\000i805f\000r80"
    "7\000r807f\000s802\000s802t\000s803\000s803t\000"};

namespace CSKY_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace CSKY_MC
struct CSKYGenMCSubtargetInfo : public MCSubtargetInfo {
  CSKYGenMCSubtargetInfo(const Triple &TT,
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
    return CSKY_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
};

static inline MCSubtargetInfo *createCSKYMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new CSKYGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(CSKYSubTypeKVStorage.Strings), CSKYFeatureKVStorage.Features, CSKYSubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::CSKYSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[CSKY::FeatureBTST16]) HasBTST16 = true;
  if (Bits[CSKY::FeatureCCRT]) UseCCRT = true;
  if (Bits[CSKY::FeatureCache]) HasCache = true;
  if (Bits[CSKY::FeatureConstPool]) DumpConstPool = true;
  if (Bits[CSKY::FeatureDSP]) HasDSP = true;
  if (Bits[CSKY::FeatureDSPV2]) HasDSPV2 = true;
  if (Bits[CSKY::FeatureDSP_Silan]) HasDSP_Silan = true;
  if (Bits[CSKY::FeatureDoloop]) HasDoloop = true;
  if (Bits[CSKY::FeatureExtendLrw]) HasExtendLrw = true;
  if (Bits[CSKY::FeatureFPUV2_DF]) HasFPUv2DoubleFloat = true;
  if (Bits[CSKY::FeatureFPUV2_SF]) HasFPUv2SingleFloat = true;
  if (Bits[CSKY::FeatureFPUV3_DF]) HasFPUv3DoubleFloat = true;
  if (Bits[CSKY::FeatureFPUV3_HF]) HasFPUv3HalfFloat = true;
  if (Bits[CSKY::FeatureFPUV3_HI]) HasFPUv3HalfWord = true;
  if (Bits[CSKY::FeatureFPUV3_SF]) HasFPUv3SingleFloat = true;
  if (Bits[CSKY::FeatureFdivdu]) HasFdivdu = true;
  if (Bits[CSKY::FeatureHWDiv]) HasHardwareDivide = true;
  if (Bits[CSKY::FeatureHardTP]) ReadTPHard = true;
  if (Bits[CSKY::FeatureHighreg]) HasHighRegisters = true;
  if (Bits[CSKY::FeatureIstack]) EnableInterruptAttribute = true;
  if (Bits[CSKY::FeatureJAVA]) HasJAVA = true;
  if (Bits[CSKY::FeatureNVIC]) HasNVIC = true;
  if (Bits[CSKY::FeaturePushPop]) HasPushPop = true;
  if (Bits[CSKY::FeatureSTM]) HasSTM = true;
  if (Bits[CSKY::FeatureSmart]) SmartMode = true;
  if (Bits[CSKY::FeatureSoftTP]) ReadTPHard = false;
  if (Bits[CSKY::FeatureStackSize]) EnableStackSize = true;
  if (Bits[CSKY::FeatureTrust]) HasTrust = true;
  if (Bits[CSKY::FeatureVDSPV1_128]) HasVDSPV1_128 = true;
  if (Bits[CSKY::FeatureVDSPV2]) HasVDSPV2 = true;
  if (Bits[CSKY::Has2E3]) Has2E3 = true;
  if (Bits[CSKY::Has3E3r1]) Has3E3r1 = true;
  if (Bits[CSKY::Has3E7]) Has3E7 = true;
  if (Bits[CSKY::Has3r1E3r2]) Has3r1E3r2 = true;
  if (Bits[CSKY::Has3r2E3r3]) Has3r2E3r3 = true;
  if (Bits[CSKY::Has7E10]) Has7E10 = true;
  if (Bits[CSKY::Has10E60]) Has10E60 = true;
  if (Bits[CSKY::HasDSP1E2]) HasDSP1E2 = true;
  if (Bits[CSKY::HasDSPE60]) HasDSPE60 = true;
  if (Bits[CSKY::HasE1]) HasE1 = true;
  if (Bits[CSKY::HasE2]) HasE2 = true;
  if (Bits[CSKY::HasFLOAT1E2]) HasFLOAT1E2 = true;
  if (Bits[CSKY::HasFLOAT1E3]) HasFLOAT1E3 = true;
  if (Bits[CSKY::HasFLOAT3E4]) HasFLOAT3E4 = true;
  if (Bits[CSKY::HasFLOAT7E60]) HasFLOAT7E60 = true;
  if (Bits[CSKY::HasFLOATE1]) HasFLOATE1 = true;
  if (Bits[CSKY::HasMP]) HasMP = true;
  if (Bits[CSKY::HasMP1E2]) HasMP1E2 = true;
  if (Bits[CSKY::HasVDSP2E3]) HasVDSP2E3 = true;
  if (Bits[CSKY::HasVDSP2E60F]) HasVDSP2E60F = true;
  if (Bits[CSKY::ModeHardFloat]) UseHardFloat = true;
  if (Bits[CSKY::ModeHardFloatABI]) UseHardFloatABI = true;
  if (Bits[CSKY::ProcCK801] && CSKYProcFamily < CK801) CSKYProcFamily = CK801;
  if (Bits[CSKY::ProcCK802] && CSKYProcFamily < CK802) CSKYProcFamily = CK802;
  if (Bits[CSKY::ProcCK803] && CSKYProcFamily < CK803) CSKYProcFamily = CK803;
  if (Bits[CSKY::ProcCK803S] && CSKYProcFamily < CK803S) CSKYProcFamily = CK803S;
  if (Bits[CSKY::ProcCK804] && CSKYProcFamily < CK804) CSKYProcFamily = CK804;
  if (Bits[CSKY::ProcCK805] && CSKYProcFamily < CK805) CSKYProcFamily = CK805;
  if (Bits[CSKY::ProcCK807] && CSKYProcFamily < CK807) CSKYProcFamily = CK807;
  if (Bits[CSKY::ProcCK810] && CSKYProcFamily < CK810) CSKYProcFamily = CK810;
  if (Bits[CSKY::ProcCK810V] && CSKYProcFamily < CK810V) CSKYProcFamily = CK810V;
  if (Bits[CSKY::ProcCK860] && CSKYProcFamily < CK860) CSKYProcFamily = CK860;
  if (Bits[CSKY::ProcCK860V] && CSKYProcFamily < CK860V) CSKYProcFamily = CK860V;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace CSKY_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace CSKY_MC
struct CSKYGenSubtargetInfo : public TargetSubtargetInfo {
  explicit CSKYGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
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

extern const llvm_ks::StringRef CSKYNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<63, 2350> CSKYFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<152, 1236> CSKYSubTypeKVStorage;
extern const llvm_ks::MCSchedModel CSKYSchedModels[];
extern const llvm_ks::MCWriteProcResEntry CSKYWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry CSKYWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry CSKYReadAdvanceTable[];
CSKYGenSubtargetInfo::CSKYGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(CSKYSubTypeKVStorage.Strings), ArrayRef(CSKYFeatureKVStorage.Features), ArrayRef(CSKYSubTypeKVStorage.SubTypes), CSKYSchedModels, 
                        CSKYWriteProcResTable, CSKYWriteLatencyTable, CSKYReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned CSKYGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // CSKYGenSubtargetInfo::resolveSchedClass

unsigned CSKYGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return CSKY_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // CSKYGenSubtargetInfo::resolveVariantSchedClass

const FeatureBitset &CSKYGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &CSKYGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &CSKYGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

