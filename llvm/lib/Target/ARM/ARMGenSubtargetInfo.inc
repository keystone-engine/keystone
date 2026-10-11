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

enum {
  ARMv4 = 0,
  ARMv4t = 1,
  ARMv5t = 2,
  ARMv5te = 3,
  ARMv5tej = 4,
  ARMv6 = 5,
  ARMv6j = 6,
  ARMv6k = 7,
  ARMv6kz = 8,
  ARMv6m = 9,
  ARMv6sm = 10,
  ARMv6t2 = 11,
  ARMv7a = 12,
  ARMv7em = 13,
  ARMv7k = 14,
  ARMv7m = 15,
  ARMv7r = 16,
  ARMv7s = 17,
  ARMv7ve = 18,
  ARMv8a = 19,
  ARMv8mBaseline = 20,
  ARMv8mMainline = 21,
  ARMv8r = 22,
  ARMv9a = 23,
  ARMv81a = 24,
  ARMv81mMainline = 25,
  ARMv82a = 26,
  ARMv83a = 27,
  ARMv84a = 28,
  ARMv85a = 29,
  ARMv86a = 30,
  ARMv87a = 31,
  ARMv88a = 32,
  ARMv89a = 33,
  ARMv91a = 34,
  ARMv92a = 35,
  ARMv93a = 36,
  ARMv94a = 37,
  ARMv95a = 38,
  ARMv96a = 39,
  ARMv97a = 40,
  Feature8MSecExt = 41,
  FeatureAAPCSFrameChain = 42,
  FeatureAClass = 43,
  FeatureAES = 44,
  FeatureAcquireRelease = 45,
  FeatureAtomics32 = 46,
  FeatureAvoidMOVsShOp = 47,
  FeatureAvoidMULS = 48,
  FeatureAvoidPartialCPSR = 49,
  FeatureBF16 = 50,
  FeatureCLRBHB = 51,
  FeatureCRC = 52,
  FeatureCheapPredicableCPSR = 53,
  FeatureCheckVLDnAlign = 54,
  FeatureCoprocCDE0 = 55,
  FeatureCoprocCDE1 = 56,
  FeatureCoprocCDE2 = 57,
  FeatureCoprocCDE3 = 58,
  FeatureCoprocCDE4 = 59,
  FeatureCoprocCDE5 = 60,
  FeatureCoprocCDE6 = 61,
  FeatureCoprocCDE7 = 62,
  FeatureCrypto = 63,
  FeatureD32 = 64,
  FeatureDB = 65,
  FeatureDFB = 66,
  FeatureDSP = 67,
  FeatureDontWidenVMOVS = 68,
  FeatureDotProd = 69,
  FeatureExecuteOnly = 70,
  FeatureExpandMLx = 71,
  FeatureFP16 = 72,
  FeatureFP16FML = 73,
  FeatureFP64 = 74,
  FeatureFPAO = 75,
  FeatureFPARMv8 = 76,
  FeatureFPARMv8_D16 = 77,
  FeatureFPARMv8_D16_SP = 78,
  FeatureFPARMv8_SP = 79,
  FeatureFPRegs = 80,
  FeatureFPRegs16 = 81,
  FeatureFPRegs64 = 82,
  FeatureFixCMSE_CVE_2021_35465 = 83,
  FeatureFixCortexA57AES1742098 = 84,
  FeatureFullFP16 = 85,
  FeatureFuseAES = 86,
  FeatureFuseLiterals = 87,
  FeatureHWDivARM = 88,
  FeatureHWDivThumb = 89,
  FeatureHardenSlsBlr = 90,
  FeatureHardenSlsNoComdat = 91,
  FeatureHardenSlsRetBr = 92,
  FeatureHasNoBranchPredictor = 93,
  FeatureHasRetAddrStack = 94,
  FeatureHasSlowFPVFMx = 95,
  FeatureHasSlowFPVMLx = 96,
  FeatureHasVMLxHazards = 97,
  FeatureLOB = 98,
  FeatureLongCalls = 99,
  FeatureMClass = 100,
  FeatureMP = 101,
  FeatureMVEVectorCostFactor1 = 102,
  FeatureMVEVectorCostFactor2 = 103,
  FeatureMVEVectorCostFactor4 = 104,
  FeatureMatMulInt8 = 105,
  FeatureMuxedUnits = 106,
  FeatureNEON = 107,
  FeatureNEONForFP = 108,
  FeatureNEONForFPMovs = 109,
  FeatureNoARM = 110,
  FeatureNoBTIAtReturnTwice = 111,
  FeatureNoMovt = 112,
  FeatureNoNegativeImmediates = 113,
  FeatureNoPostRASched = 114,
  FeatureNonpipelinedVFP = 115,
  FeaturePACBTI = 116,
  FeaturePerfMon = 117,
  FeaturePref32BitThumb = 118,
  FeaturePrefISHSTBarrier = 119,
  FeaturePreferBranchAlign32 = 120,
  FeaturePreferBranchAlign64 = 121,
  FeaturePreferVMOVSR = 122,
  FeatureProfUnpredicate = 123,
  FeatureRAS = 124,
  FeatureRClass = 125,
  FeatureReadTpTPIDRPRW = 126,
  FeatureReadTpTPIDRURO = 127,
  FeatureReadTpTPIDRURW = 128,
  FeatureReserveR9 = 129,
  FeatureSB = 130,
  FeatureSHA2 = 131,
  FeatureSlowFPBrcc = 132,
  FeatureSlowLoadDSubreg = 133,
  FeatureSlowOddRegister = 134,
  FeatureSlowVDUP32 = 135,
  FeatureSlowVGETLNi32 = 136,
  FeatureSplatVFPToNeon = 137,
  FeatureStrictAlign = 138,
  FeatureThumb2 = 139,
  FeatureTrustZone = 140,
  FeatureUseMIPipeliner = 141,
  FeatureUseMISched = 142,
  FeatureUseWideStrideVFP = 143,
  FeatureV7Clrex = 144,
  FeatureVFP2 = 145,
  FeatureVFP2_SP = 146,
  FeatureVFP3 = 147,
  FeatureVFP3_D16 = 148,
  FeatureVFP3_D16_SP = 149,
  FeatureVFP3_SP = 150,
  FeatureVFP4 = 151,
  FeatureVFP4_D16 = 152,
  FeatureVFP4_D16_SP = 153,
  FeatureVFP4_SP = 154,
  FeatureVMLxForwarding = 155,
  FeatureVirtualization = 156,
  FeatureZCZeroing = 157,
  HasCDEOps = 158,
  HasMVEFloatOps = 159,
  HasMVEIntegerOps = 160,
  HasV4TOps = 161,
  HasV5TEOps = 162,
  HasV5TOps = 163,
  HasV6KOps = 164,
  HasV6MOps = 165,
  HasV6Ops = 166,
  HasV6T2Ops = 167,
  HasV7Ops = 168,
  HasV8MBaselineOps = 169,
  HasV8MMainlineOps = 170,
  HasV8Ops = 171,
  HasV8_1MMainlineOps = 172,
  HasV8_1aOps = 173,
  HasV8_2aOps = 174,
  HasV8_3aOps = 175,
  HasV8_4aOps = 176,
  HasV8_5aOps = 177,
  HasV8_6aOps = 178,
  HasV8_7aOps = 179,
  HasV8_8aOps = 180,
  HasV8_9aOps = 181,
  HasV9_0aOps = 182,
  HasV9_1aOps = 183,
  HasV9_2aOps = 184,
  HasV9_3aOps = 185,
  HasV9_4aOps = 186,
  HasV9_5aOps = 187,
  HasV9_6aOps = 188,
  HasV9_7aOps = 189,
  IWMMXT = 190,
  IWMMXT2 = 191,
  ModeBigEndianInstructions = 192,
  ModeSoftFloat = 193,
  ModeThumb = 194,
  ProcA5 = 195,
  ProcA7 = 196,
  ProcA8 = 197,
  ProcA9 = 198,
  ProcA12 = 199,
  ProcA15 = 200,
  ProcA17 = 201,
  ProcA32 = 202,
  ProcA35 = 203,
  ProcA53 = 204,
  ProcA55 = 205,
  ProcA57 = 206,
  ProcA72 = 207,
  ProcA73 = 208,
  ProcA75 = 209,
  ProcA76 = 210,
  ProcA77 = 211,
  ProcA78 = 212,
  ProcA78AE = 213,
  ProcA78C = 214,
  ProcA510 = 215,
  ProcA710 = 216,
  ProcExynos = 217,
  ProcKrait = 218,
  ProcKryo = 219,
  ProcM3 = 220,
  ProcM7 = 221,
  ProcM55 = 222,
  ProcM85 = 223,
  ProcR4 = 224,
  ProcR5 = 225,
  ProcR7 = 226,
  ProcR52 = 227,
  ProcR52plus = 228,
  ProcSwift = 229,
  ProcV1 = 230,
  ProcX1 = 231,
  ProcX1C = 232,
  XScale = 233,
  NumSubtargetFeatures = 234
};

} // namespace ARM

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(AvoidCPSRPartialUpdate, false, avoidCPSRPartialUpdate)
GET_SUBTARGETINFO_MACRO(AvoidMOVsShifterOperand, false, avoidMOVsShifterOperand)
GET_SUBTARGETINFO_MACRO(AvoidMULS, false, avoidMULS)
GET_SUBTARGETINFO_MACRO(BigEndianInstructions, false, bigEndianInstructions)
GET_SUBTARGETINFO_MACRO(CheapPredicableCPSRDef, false, cheapPredicableCPSRDef)
GET_SUBTARGETINFO_MACRO(CheckVLDnAccessAlignment, false, checkVLDnAccessAlignment)
GET_SUBTARGETINFO_MACRO(CreateAAPCSFrameChain, false, createAAPCSFrameChain)
GET_SUBTARGETINFO_MACRO(DisablePostRAScheduler, false, disablePostRAScheduler)
GET_SUBTARGETINFO_MACRO(DontWidenVMOVS, false, dontWidenVMOVS)
GET_SUBTARGETINFO_MACRO(ExpandMLx, false, expandMLx)
GET_SUBTARGETINFO_MACRO(FixCMSE_CVE_2021_35465, false, fixCMSE_CVE_2021_35465)
GET_SUBTARGETINFO_MACRO(FixCortexA57AES1742098, false, fixCortexA57AES1742098)
GET_SUBTARGETINFO_MACRO(GenExecuteOnly, false, genExecuteOnly)
GET_SUBTARGETINFO_MACRO(GenLongCalls, false, genLongCalls)
GET_SUBTARGETINFO_MACRO(HardenSlsBlr, false, hardenSlsBlr)
GET_SUBTARGETINFO_MACRO(HardenSlsNoComdat, false, hardenSlsNoComdat)
GET_SUBTARGETINFO_MACRO(HardenSlsRetBr, false, hardenSlsRetBr)
GET_SUBTARGETINFO_MACRO(Has8MSecExt, false, has8MSecExt)
GET_SUBTARGETINFO_MACRO(HasAES, false, hasAES)
GET_SUBTARGETINFO_MACRO(HasAcquireRelease, false, hasAcquireRelease)
GET_SUBTARGETINFO_MACRO(HasBF16, false, hasBF16)
GET_SUBTARGETINFO_MACRO(HasBranchPredictor, true, hasBranchPredictor)
GET_SUBTARGETINFO_MACRO(HasCDEOps, false, hasCDEOps)
GET_SUBTARGETINFO_MACRO(HasCLRBHB, false, hasCLRBHB)
GET_SUBTARGETINFO_MACRO(HasCRC, false, hasCRC)
GET_SUBTARGETINFO_MACRO(HasCrypto, false, hasCrypto)
GET_SUBTARGETINFO_MACRO(HasD32, false, hasD32)
GET_SUBTARGETINFO_MACRO(HasDSP, false, hasDSP)
GET_SUBTARGETINFO_MACRO(HasDataBarrier, false, hasDataBarrier)
GET_SUBTARGETINFO_MACRO(HasDivideInARMMode, false, hasDivideInARMMode)
GET_SUBTARGETINFO_MACRO(HasDivideInThumbMode, false, hasDivideInThumbMode)
GET_SUBTARGETINFO_MACRO(HasDotProd, false, hasDotProd)
GET_SUBTARGETINFO_MACRO(HasFP16, false, hasFP16)
GET_SUBTARGETINFO_MACRO(HasFP16FML, false, hasFP16FML)
GET_SUBTARGETINFO_MACRO(HasFP64, false, hasFP64)
GET_SUBTARGETINFO_MACRO(HasFPAO, false, hasFPAO)
GET_SUBTARGETINFO_MACRO(HasFPARMv8, false, hasFPARMv8)
GET_SUBTARGETINFO_MACRO(HasFPARMv8D16, false, hasFPARMv8D16)
GET_SUBTARGETINFO_MACRO(HasFPARMv8D16SP, false, hasFPARMv8D16SP)
GET_SUBTARGETINFO_MACRO(HasFPARMv8SP, false, hasFPARMv8SP)
GET_SUBTARGETINFO_MACRO(HasFPRegs, false, hasFPRegs)
GET_SUBTARGETINFO_MACRO(HasFPRegs16, false, hasFPRegs16)
GET_SUBTARGETINFO_MACRO(HasFPRegs64, false, hasFPRegs64)
GET_SUBTARGETINFO_MACRO(HasForced32BitAtomics, false, hasForced32BitAtomics)
GET_SUBTARGETINFO_MACRO(HasFullDataBarrier, false, hasFullDataBarrier)
GET_SUBTARGETINFO_MACRO(HasFullFP16, false, hasFullFP16)
GET_SUBTARGETINFO_MACRO(HasFuseAES, false, hasFuseAES)
GET_SUBTARGETINFO_MACRO(HasFuseLiterals, false, hasFuseLiterals)
GET_SUBTARGETINFO_MACRO(HasLOB, false, hasLOB)
GET_SUBTARGETINFO_MACRO(HasMPExtension, false, hasMPExtension)
GET_SUBTARGETINFO_MACRO(HasMVEFloatOps, false, hasMVEFloatOps)
GET_SUBTARGETINFO_MACRO(HasMVEIntegerOps, false, hasMVEIntegerOps)
GET_SUBTARGETINFO_MACRO(HasMatMulInt8, false, hasMatMulInt8)
GET_SUBTARGETINFO_MACRO(HasMuxedUnits, false, hasMuxedUnits)
GET_SUBTARGETINFO_MACRO(HasNEON, false, hasNEON)
GET_SUBTARGETINFO_MACRO(HasNEONForFP, false, hasNEONForFP)
GET_SUBTARGETINFO_MACRO(HasPACBTI, false, hasPACBTI)
GET_SUBTARGETINFO_MACRO(HasPerfMon, false, hasPerfMon)
GET_SUBTARGETINFO_MACRO(HasRAS, false, hasRAS)
GET_SUBTARGETINFO_MACRO(HasRetAddrStack, false, hasRetAddrStack)
GET_SUBTARGETINFO_MACRO(HasSB, false, hasSB)
GET_SUBTARGETINFO_MACRO(HasSHA2, false, hasSHA2)
GET_SUBTARGETINFO_MACRO(HasSlowLoadDSubregister, false, hasSlowLoadDSubregister)
GET_SUBTARGETINFO_MACRO(HasSlowOddRegister, false, hasSlowOddRegister)
GET_SUBTARGETINFO_MACRO(HasSlowVDUP32, false, hasSlowVDUP32)
GET_SUBTARGETINFO_MACRO(HasSlowVGETLNi32, false, hasSlowVGETLNi32)
GET_SUBTARGETINFO_MACRO(HasThumb2, false, hasThumb2)
GET_SUBTARGETINFO_MACRO(HasTrustZone, false, hasTrustZone)
GET_SUBTARGETINFO_MACRO(HasV4TOps, false, hasV4TOps)
GET_SUBTARGETINFO_MACRO(HasV5TEOps, false, hasV5TEOps)
GET_SUBTARGETINFO_MACRO(HasV5TOps, false, hasV5TOps)
GET_SUBTARGETINFO_MACRO(HasV6KOps, false, hasV6KOps)
GET_SUBTARGETINFO_MACRO(HasV6MOps, false, hasV6MOps)
GET_SUBTARGETINFO_MACRO(HasV6Ops, false, hasV6Ops)
GET_SUBTARGETINFO_MACRO(HasV6T2Ops, false, hasV6T2Ops)
GET_SUBTARGETINFO_MACRO(HasV7Clrex, false, hasV7Clrex)
GET_SUBTARGETINFO_MACRO(HasV7Ops, false, hasV7Ops)
GET_SUBTARGETINFO_MACRO(HasV8MBaselineOps, false, hasV8MBaselineOps)
GET_SUBTARGETINFO_MACRO(HasV8MMainlineOps, false, hasV8MMainlineOps)
GET_SUBTARGETINFO_MACRO(HasV8Ops, false, hasV8Ops)
GET_SUBTARGETINFO_MACRO(HasV8_1MMainlineOps, false, hasV8_1MMainlineOps)
GET_SUBTARGETINFO_MACRO(HasV8_1aOps, false, hasV8_1aOps)
GET_SUBTARGETINFO_MACRO(HasV8_2aOps, false, hasV8_2aOps)
GET_SUBTARGETINFO_MACRO(HasV8_3aOps, false, hasV8_3aOps)
GET_SUBTARGETINFO_MACRO(HasV8_4aOps, false, hasV8_4aOps)
GET_SUBTARGETINFO_MACRO(HasV8_5aOps, false, hasV8_5aOps)
GET_SUBTARGETINFO_MACRO(HasV8_6aOps, false, hasV8_6aOps)
GET_SUBTARGETINFO_MACRO(HasV8_7aOps, false, hasV8_7aOps)
GET_SUBTARGETINFO_MACRO(HasV8_8aOps, false, hasV8_8aOps)
GET_SUBTARGETINFO_MACRO(HasV8_9aOps, false, hasV8_9aOps)
GET_SUBTARGETINFO_MACRO(HasV9_0aOps, false, hasV9_0aOps)
GET_SUBTARGETINFO_MACRO(HasV9_1aOps, false, hasV9_1aOps)
GET_SUBTARGETINFO_MACRO(HasV9_2aOps, false, hasV9_2aOps)
GET_SUBTARGETINFO_MACRO(HasV9_3aOps, false, hasV9_3aOps)
GET_SUBTARGETINFO_MACRO(HasV9_4aOps, false, hasV9_4aOps)
GET_SUBTARGETINFO_MACRO(HasV9_5aOps, false, hasV9_5aOps)
GET_SUBTARGETINFO_MACRO(HasV9_6aOps, false, hasV9_6aOps)
GET_SUBTARGETINFO_MACRO(HasV9_7aOps, false, hasV9_7aOps)
GET_SUBTARGETINFO_MACRO(HasVFPv2, false, hasVFPv2)
GET_SUBTARGETINFO_MACRO(HasVFPv2SP, false, hasVFPv2SP)
GET_SUBTARGETINFO_MACRO(HasVFPv3, false, hasVFPv3)
GET_SUBTARGETINFO_MACRO(HasVFPv3D16, false, hasVFPv3D16)
GET_SUBTARGETINFO_MACRO(HasVFPv3D16SP, false, hasVFPv3D16SP)
GET_SUBTARGETINFO_MACRO(HasVFPv3SP, false, hasVFPv3SP)
GET_SUBTARGETINFO_MACRO(HasVFPv4, false, hasVFPv4)
GET_SUBTARGETINFO_MACRO(HasVFPv4D16, false, hasVFPv4D16)
GET_SUBTARGETINFO_MACRO(HasVFPv4D16SP, false, hasVFPv4D16SP)
GET_SUBTARGETINFO_MACRO(HasVFPv4SP, false, hasVFPv4SP)
GET_SUBTARGETINFO_MACRO(HasVMLxForwarding, false, hasVMLxForwarding)
GET_SUBTARGETINFO_MACRO(HasVMLxHazards, false, hasVMLxHazards)
GET_SUBTARGETINFO_MACRO(HasVirtualization, false, hasVirtualization)
GET_SUBTARGETINFO_MACRO(HasZeroCycleZeroing, false, hasZeroCycleZeroing)
GET_SUBTARGETINFO_MACRO(IsFPBrccSlow, false, isFPBrccSlow)
GET_SUBTARGETINFO_MACRO(IsProfitableToUnpredicate, false, isProfitableToUnpredicate)
GET_SUBTARGETINFO_MACRO(IsReadTPTPIDRPRW, false, isReadTPTPIDRPRW)
GET_SUBTARGETINFO_MACRO(IsReadTPTPIDRURO, false, isReadTPTPIDRURO)
GET_SUBTARGETINFO_MACRO(IsReadTPTPIDRURW, false, isReadTPTPIDRURW)
GET_SUBTARGETINFO_MACRO(IsThumb, false, isThumb)
GET_SUBTARGETINFO_MACRO(NegativeImmediates, true, negativeImmediates)
GET_SUBTARGETINFO_MACRO(NoARM, false, noARM)
GET_SUBTARGETINFO_MACRO(NoBTIAtReturnTwice, false, noBTIAtReturnTwice)
GET_SUBTARGETINFO_MACRO(NoMovt, false, noMovt)
GET_SUBTARGETINFO_MACRO(NonpipelinedVFP, false, nonpipelinedVFP)
GET_SUBTARGETINFO_MACRO(PreferISHSTBarriers, false, preferISHSTBarriers)
GET_SUBTARGETINFO_MACRO(PreferVMOVSR, false, preferVMOVSR)
GET_SUBTARGETINFO_MACRO(Prefers32BitThumb, false, prefers32BitThumb)
GET_SUBTARGETINFO_MACRO(ReserveR9, false, reserveR9)
GET_SUBTARGETINFO_MACRO(SlowFPVFMx, false, slowFPVFMx)
GET_SUBTARGETINFO_MACRO(SlowFPVMLx, false, slowFPVMLx)
GET_SUBTARGETINFO_MACRO(StrictAlign, false, strictAlign)
GET_SUBTARGETINFO_MACRO(UseMIPipeliner, false, useMIPipeliner)
GET_SUBTARGETINFO_MACRO(UseMISched, false, useMISched)
GET_SUBTARGETINFO_MACRO(UseNEONForFPMovs, false, useNEONForFPMovs)
GET_SUBTARGETINFO_MACRO(UseSoftFloat, false, useSoftFloat)
GET_SUBTARGETINFO_MACRO(UseSplatVFPToNeon, false, useSplatVFPToNeon)
GET_SUBTARGETINFO_MACRO(UseWideStrideVFP, false, useWideStrideVFP)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 234, 9733> ARMFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 234 + 1, sizeof(SubtargetFeatureKV) * 234 + 7, ARM::FeaturePref32BitThumb, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 233 + 34, sizeof(SubtargetFeatureKV) * 233 + 43, ARM::Feature8MSecExt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 232 + 90, sizeof(SubtargetFeatureKV) * 232 + 94, ARM::ProcA12, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 231 + 120, sizeof(SubtargetFeatureKV) * 231 + 124, ARM::ProcA15, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 230 + 150, sizeof(SubtargetFeatureKV) * 230 + 154, ARM::ProcA17, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 229 + 180, sizeof(SubtargetFeatureKV) * 229 + 184, ARM::ProcA32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 228 + 210, sizeof(SubtargetFeatureKV) * 228 + 214, ARM::ProcA35, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 227 + 240, sizeof(SubtargetFeatureKV) * 227 + 243, ARM::ProcA5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 226 + 268, sizeof(SubtargetFeatureKV) * 226 + 272, ARM::ProcA53, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 225 + 298, sizeof(SubtargetFeatureKV) * 225 + 302, ARM::ProcA55, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 224 + 328, sizeof(SubtargetFeatureKV) * 224 + 332, ARM::ProcA57, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 223 + 358, sizeof(SubtargetFeatureKV) * 223 + 361, ARM::ProcA7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 222 + 386, sizeof(SubtargetFeatureKV) * 222 + 390, ARM::ProcA72, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 221 + 416, sizeof(SubtargetFeatureKV) * 221 + 420, ARM::ProcA73, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 220 + 446, sizeof(SubtargetFeatureKV) * 220 + 450, ARM::ProcA75, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 219 + 476, sizeof(SubtargetFeatureKV) * 219 + 480, ARM::ProcA76, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 218 + 506, sizeof(SubtargetFeatureKV) * 218 + 510, ARM::ProcA77, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 217 + 536, sizeof(SubtargetFeatureKV) * 217 + 541, ARM::ProcA78C, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 216 + 568, sizeof(SubtargetFeatureKV) * 216 + 571, ARM::ProcA8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 215 + 596, sizeof(SubtargetFeatureKV) * 215 + 599, ARM::ProcA9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 214 + 624, sizeof(SubtargetFeatureKV) * 214 + 642, ARM::FeatureAAPCSFrameChain, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 213 + 680, sizeof(SubtargetFeatureKV) * 213 + 687, ARM::FeatureAClass, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 212 + 723, sizeof(SubtargetFeatureKV) * 212 + 739, ARM::FeatureAcquireRelease, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 211 + 792, sizeof(SubtargetFeatureKV) * 211 + 796, ARM::FeatureAES, { { { 0x0ULL, 0x80000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 210 + 815, sizeof(SubtargetFeatureKV) * 210 + 821, ARM::ARMv4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 209 + 840, sizeof(SubtargetFeatureKV) * 209 + 847, ARM::ARMv4t, { { { 0x0ULL, 0x0ULL, 0x200000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 208 + 867, sizeof(SubtargetFeatureKV) * 208 + 874, ARM::ARMv5t, { { { 0x0ULL, 0x0ULL, 0x800000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 207 + 894, sizeof(SubtargetFeatureKV) * 207 + 902, ARM::ARMv5te, { { { 0x0ULL, 0x0ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 206 + 923, sizeof(SubtargetFeatureKV) * 206 + 932, ARM::ARMv5tej, { { { 0x0ULL, 0x0ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 205 + 954, sizeof(SubtargetFeatureKV) * 205 + 960, ARM::ARMv6, { { { 0x0ULL, 0x8ULL, 0x4000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 204 + 979, sizeof(SubtargetFeatureKV) * 204 + 987, ARM::ARMv6m, { { { 0x0ULL, 0x401000000002ULL, 0x2000000400ULL, 0x4ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 203 + 1007, sizeof(SubtargetFeatureKV) * 203 + 1014, ARM::ARMv6j, { { { 0x20ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 202 + 1034, sizeof(SubtargetFeatureKV) * 202 + 1041, ARM::ARMv6k, { { { 0x0ULL, 0x0ULL, 0x1000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 201 + 1061, sizeof(SubtargetFeatureKV) * 201 + 1069, ARM::ARMv6kz, { { { 0x0ULL, 0x0ULL, 0x1000001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 200 + 1090, sizeof(SubtargetFeatureKV) * 200 + 1099, ARM::ARMv6sm, { { { 0x0ULL, 0x401000000002ULL, 0x2000000400ULL, 0x4ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 199 + 1120, sizeof(SubtargetFeatureKV) * 199 + 1128, ARM::ARMv6t2, { { { 0x0ULL, 0x8ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 198 + 1149, sizeof(SubtargetFeatureKV) * 198 + 1014, ARM::ARMv7a, { { { 0x80000000000ULL, 0x2008000000000aULL, 0x10000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 197 + 1157, sizeof(SubtargetFeatureKV) * 197 + 1165, ARM::ARMv7m, { { { 0x0ULL, 0x401002000002ULL, 0x10000000800ULL, 0x4ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 196 + 1185, sizeof(SubtargetFeatureKV) * 196 + 1193, ARM::ARMv7r, { { { 0x0ULL, 0x202000000200000aULL, 0x10000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 195 + 1213, sizeof(SubtargetFeatureKV) * 195 + 1222, ARM::ARMv7em, { { { 0x0ULL, 0x40100200000aULL, 0x10000000800ULL, 0x4ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 194 + 1243, sizeof(SubtargetFeatureKV) * 194 + 1014, ARM::ARMv7k, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 193 + 1250, sizeof(SubtargetFeatureKV) * 193 + 1014, ARM::ARMv7s, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 192 + 1257, sizeof(SubtargetFeatureKV) * 192 + 1265, ARM::ARMv7ve, { { { 0x80000000000ULL, 0x2008200000000aULL, 0x10010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 191 + 1286, sizeof(SubtargetFeatureKV) * 191 + 1294, ARM::ARMv8a, { { { 0x8010080000000000ULL, 0x8200000100aULL, 0x80010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 190 + 1314, sizeof(SubtargetFeatureKV) * 190 + 1327, ARM::ARMv8mBaseline, { { { 0x220000000000ULL, 0x401002000002ULL, 0x20000010400ULL, 0x4ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 189 + 1355, sizeof(SubtargetFeatureKV) * 189 + 1368, ARM::ARMv8mMainline, { { { 0x220000000000ULL, 0x401002000002ULL, 0x40000000000ULL, 0x4ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 188 + 1396, sizeof(SubtargetFeatureKV) * 188 + 1404, ARM::ARMv8r, { { { 0x10000000000000ULL, 0x200000200000400eULL, 0x80010000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 187 + 1424, sizeof(SubtargetFeatureKV) * 187 + 1434, ARM::ARMv81a, { { { 0x8010080000000000ULL, 0x8200000100aULL, 0x200010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 186 + 1455, sizeof(SubtargetFeatureKV) * 186 + 1470, ARM::ARMv81mMainline, { { { 0x220000000000ULL, 0x1000401402000002ULL, 0x100000000000ULL, 0x4ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 185 + 1499, sizeof(SubtargetFeatureKV) * 185 + 1509, ARM::ARMv82a, { { { 0x8010080000000000ULL, 0x100008200000100aULL, 0x400010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 184 + 1530, sizeof(SubtargetFeatureKV) * 184 + 1540, ARM::ARMv83a, { { { 0x8010080000000000ULL, 0x100008200000100aULL, 0x800010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 183 + 1561, sizeof(SubtargetFeatureKV) * 183 + 1571, ARM::ARMv84a, { { { 0x8010080000000000ULL, 0x100008200000102aULL, 0x1000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 182 + 1592, sizeof(SubtargetFeatureKV) * 182 + 1602, ARM::ARMv85a, { { { 0x8010080000000000ULL, 0x100008200000102aULL, 0x2000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 181 + 1623, sizeof(SubtargetFeatureKV) * 181 + 1633, ARM::ARMv86a, { { { 0x8010080000000000ULL, 0x100008200000102aULL, 0x4000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 180 + 1654, sizeof(SubtargetFeatureKV) * 180 + 1664, ARM::ARMv87a, { { { 0x8010080000000000ULL, 0x100008200000102aULL, 0x8000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 179 + 1685, sizeof(SubtargetFeatureKV) * 179 + 1695, ARM::ARMv88a, { { { 0x8010080000000000ULL, 0x100008200000102aULL, 0x10000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 178 + 1716, sizeof(SubtargetFeatureKV) * 178 + 1726, ARM::ARMv89a, { { { 0x8010080000000000ULL, 0x100008200000102aULL, 0x20000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 177 + 1747, sizeof(SubtargetFeatureKV) * 177 + 1755, ARM::ARMv9a, { { { 0x10080000000000ULL, 0x100008200000102aULL, 0x40000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 176 + 1775, sizeof(SubtargetFeatureKV) * 176 + 1785, ARM::ARMv91a, { { { 0x10080000000000ULL, 0x100008200000102aULL, 0x80000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 175 + 1806, sizeof(SubtargetFeatureKV) * 175 + 1816, ARM::ARMv92a, { { { 0x10080000000000ULL, 0x100008200000102aULL, 0x100000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 174 + 1837, sizeof(SubtargetFeatureKV) * 174 + 1847, ARM::ARMv93a, { { { 0x8010080000000000ULL, 0x100008200000102aULL, 0x200000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 173 + 1868, sizeof(SubtargetFeatureKV) * 173 + 1878, ARM::ARMv94a, { { { 0x10080000000000ULL, 0x100008200000102aULL, 0x400000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 172 + 1899, sizeof(SubtargetFeatureKV) * 172 + 1909, ARM::ARMv95a, { { { 0x10080000000000ULL, 0x100008200000102aULL, 0x800000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 171 + 1930, sizeof(SubtargetFeatureKV) * 171 + 1940, ARM::ARMv96a, { { { 0x10080000000000ULL, 0x100008200000102aULL, 0x1000000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 170 + 1961, sizeof(SubtargetFeatureKV) * 170 + 1971, ARM::ARMv97a, { { { 0x10080000000000ULL, 0x100008200000102aULL, 0x2000000010001000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 169 + 1992, sizeof(SubtargetFeatureKV) * 169 + 2003, ARM::FeatureAtomics32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 168 + 2054, sizeof(SubtargetFeatureKV) * 168 + 2070, ARM::FeatureAvoidMOVsShOp, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 167 + 2115, sizeof(SubtargetFeatureKV) * 167 + 2126, ARM::FeatureAvoidMULS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 166 + 2168, sizeof(SubtargetFeatureKV) * 166 + 2187, ARM::FeatureAvoidPartialCPSR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 165 + 2231, sizeof(SubtargetFeatureKV) * 165 + 2236, ARM::FeatureBF16, { { { 0x0ULL, 0x80000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 164 + 2277, sizeof(SubtargetFeatureKV) * 164 + 2301, ARM::ModeBigEndianInstructions, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 163 + 2346, sizeof(SubtargetFeatureKV) * 163 + 2362, ARM::FeaturePreferBranchAlign64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 162 + 2405, sizeof(SubtargetFeatureKV) * 162 + 2409, ARM::HasCDEOps, { { { 0x0ULL, 0x0ULL, 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 161 + 2434, sizeof(SubtargetFeatureKV) * 161 + 2441, ARM::FeatureCoprocCDE0, { { { 0x0ULL, 0x0ULL, 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 160 + 2468, sizeof(SubtargetFeatureKV) * 160 + 2475, ARM::FeatureCoprocCDE1, { { { 0x0ULL, 0x0ULL, 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 159 + 2502, sizeof(SubtargetFeatureKV) * 159 + 2509, ARM::FeatureCoprocCDE2, { { { 0x0ULL, 0x0ULL, 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 158 + 2536, sizeof(SubtargetFeatureKV) * 158 + 2543, ARM::FeatureCoprocCDE3, { { { 0x0ULL, 0x0ULL, 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 157 + 2570, sizeof(SubtargetFeatureKV) * 157 + 2577, ARM::FeatureCoprocCDE4, { { { 0x0ULL, 0x0ULL, 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 156 + 2604, sizeof(SubtargetFeatureKV) * 156 + 2611, ARM::FeatureCoprocCDE5, { { { 0x0ULL, 0x0ULL, 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 155 + 2638, sizeof(SubtargetFeatureKV) * 155 + 2645, ARM::FeatureCoprocCDE6, { { { 0x0ULL, 0x0ULL, 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 154 + 2672, sizeof(SubtargetFeatureKV) * 154 + 2679, ARM::FeatureCoprocCDE7, { { { 0x0ULL, 0x0ULL, 0x40000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 153 + 2706, sizeof(SubtargetFeatureKV) * 153 + 2728, ARM::FeatureCheapPredicableCPSR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 152 + 2787, sizeof(SubtargetFeatureKV) * 152 + 2794, ARM::FeatureCLRBHB, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 151 + 2823, sizeof(SubtargetFeatureKV) * 151 + 2835, ARM::ProcA510, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 150 + 2862, sizeof(SubtargetFeatureKV) * 150 + 2874, ARM::ProcA710, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 149 + 2901, sizeof(SubtargetFeatureKV) * 149 + 2912, ARM::ProcA78, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 148 + 2938, sizeof(SubtargetFeatureKV) * 148 + 2951, ARM::ProcA78AE, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 147 + 2979, sizeof(SubtargetFeatureKV) * 147 + 2989, ARM::ProcX1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 146 + 3014, sizeof(SubtargetFeatureKV) * 146 + 3025, ARM::ProcX1C, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 145 + 3051, sizeof(SubtargetFeatureKV) * 145 + 3055, ARM::FeatureCRC, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 144 + 3091, sizeof(SubtargetFeatureKV) * 144 + 3098, ARM::FeatureCrypto, { { { 0x100000000000ULL, 0x80000000000ULL, 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 143 + 3141, sizeof(SubtargetFeatureKV) * 143 + 3145, ARM::FeatureD32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 142 + 3178, sizeof(SubtargetFeatureKV) * 142 + 3181, ARM::FeatureDB, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 141 + 3221, sizeof(SubtargetFeatureKV) * 141 + 3225, ARM::FeatureDFB, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 140 + 3265, sizeof(SubtargetFeatureKV) * 140 + 3290, ARM::FeatureNoPostRASched, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 139 + 3337, sizeof(SubtargetFeatureKV) * 139 + 3354, ARM::FeatureDontWidenVMOVS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 138 + 3381, sizeof(SubtargetFeatureKV) * 138 + 3389, ARM::FeatureDotProd, { { { 0x0ULL, 0x80000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 137 + 3433, sizeof(SubtargetFeatureKV) * 137 + 3437, ARM::FeatureDSP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 136 + 3484, sizeof(SubtargetFeatureKV) * 136 + 3497, ARM::FeatureExecuteOnly, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 135 + 3541, sizeof(SubtargetFeatureKV) * 135 + 3555, ARM::FeatureExpandMLx, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 134 + 3592, sizeof(SubtargetFeatureKV) * 134 + 3599, ARM::ProcExynos, { { { 0x8010000000000000ULL, 0x8000001c3c00080ULL, 0x20008390ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 133 + 3625, sizeof(SubtargetFeatureKV) * 133 + 3649, ARM::FeatureFixCMSE_CVE_2021_35465, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 132 + 3708, sizeof(SubtargetFeatureKV) * 132 + 3735, ARM::FeatureFixCortexA57AES1742098, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 131 + 3809, sizeof(SubtargetFeatureKV) * 131 + 3818, ARM::FeatureFPARMv8, { { { 0x0ULL, 0xa000ULL, 0x800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 130 + 3834, sizeof(SubtargetFeatureKV) * 130 + 3846, ARM::FeatureFPARMv8_D16, { { { 0x0ULL, 0x4400ULL, 0x1000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 129 + 3887, sizeof(SubtargetFeatureKV) * 129 + 3901, ARM::FeatureFPARMv8_D16_SP, { { { 0x0ULL, 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 128 + 3966, sizeof(SubtargetFeatureKV) * 128 + 3977, ARM::FeatureFPARMv8_SP, { { { 0x0ULL, 0x4001ULL, 0x4000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 127 + 4018, sizeof(SubtargetFeatureKV) * 127 + 4023, ARM::FeatureFP16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 126 + 4060, sizeof(SubtargetFeatureKV) * 126 + 4068, ARM::FeatureFP16FML, { { { 0x0ULL, 0x200000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 125 + 4127, sizeof(SubtargetFeatureKV) * 125 + 4132, ARM::FeatureFP64, { { { 0x0ULL, 0x40000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 124 + 4178, sizeof(SubtargetFeatureKV) * 124 + 4183, ARM::FeatureFPAO, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 123 + 4235, sizeof(SubtargetFeatureKV) * 123 + 4242, ARM::FeatureFPRegs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 122 + 4262, sizeof(SubtargetFeatureKV) * 122 + 4271, ARM::FeatureFPRegs16, { { { 0x0ULL, 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 121 + 4298, sizeof(SubtargetFeatureKV) * 121 + 4307, ARM::FeatureFPRegs64, { { { 0x0ULL, 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 120 + 4334, sizeof(SubtargetFeatureKV) * 120 + 4343, ARM::FeatureFullFP16, { { { 0x0ULL, 0x24000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 119 + 4385, sizeof(SubtargetFeatureKV) * 119 + 4394, ARM::FeatureFuseAES, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 118 + 4426, sizeof(SubtargetFeatureKV) * 118 + 4440, ARM::FeatureFuseLiterals, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 117 + 4480, sizeof(SubtargetFeatureKV) * 117 + 4495, ARM::FeatureHardenSlsBlr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 116 + 4558, sizeof(SubtargetFeatureKV) * 116 + 4578, ARM::FeatureHardenSlsNoComdat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 115 + 4644, sizeof(SubtargetFeatureKV) * 115 + 4661, ARM::FeatureHardenSlsRetBr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 114 + 4748, sizeof(SubtargetFeatureKV) * 114 + 4754, ARM::FeatureHWDivThumb, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 113 + 4790, sizeof(SubtargetFeatureKV) * 113 + 4800, ARM::FeatureHWDivARM, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 112 + 4839, sizeof(SubtargetFeatureKV) * 112 + 4844, ARM::FeatureMatMulInt8, { { { 0x0ULL, 0x80000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 111 + 4882, sizeof(SubtargetFeatureKV) * 111 + 902, ARM::IWMMXT, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 110 + 4889, sizeof(SubtargetFeatureKV) * 110 + 902, ARM::IWMMXT2, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 109 + 4897, sizeof(SubtargetFeatureKV) * 109 + 4903, ARM::ProcKrait, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 108 + 4929, sizeof(SubtargetFeatureKV) * 108 + 4934, ARM::ProcKryo, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 107 + 4959, sizeof(SubtargetFeatureKV) * 107 + 4963, ARM::FeatureLOB, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 106 + 5001, sizeof(SubtargetFeatureKV) * 106 + 5012, ARM::FeatureLongCalls, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 105 + 5058, sizeof(SubtargetFeatureKV) * 105 + 5069, ARM::FeaturePreferBranchAlign32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 104 + 5112, sizeof(SubtargetFeatureKV) * 104 + 5115, ARM::ProcM3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 103 + 5140, sizeof(SubtargetFeatureKV) * 103 + 5144, ARM::ProcM55, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 102 + 5170, sizeof(SubtargetFeatureKV) * 102 + 5173, ARM::ProcM7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 101 + 5198, sizeof(SubtargetFeatureKV) * 101 + 5202, ARM::ProcM85, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 100 + 5228, sizeof(SubtargetFeatureKV) * 100 + 5235, ARM::FeatureMClass, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 99 + 5275, sizeof(SubtargetFeatureKV) * 99 + 5278, ARM::FeatureMP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 98 + 5313, sizeof(SubtargetFeatureKV) * 98 + 5325, ARM::FeatureMuxedUnits, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 97 + 5352, sizeof(SubtargetFeatureKV) * 97 + 5356, ARM::HasMVEIntegerOps, { { { 0x0ULL, 0x60008ULL, 0x100000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 96 + 5406, sizeof(SubtargetFeatureKV) * 96 + 5413, ARM::HasMVEFloatOps, { { { 0x0ULL, 0x204000ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 95 + 5476, sizeof(SubtargetFeatureKV) * 95 + 5485, ARM::FeatureMVEVectorCostFactor1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 94 + 5542, sizeof(SubtargetFeatureKV) * 94 + 5551, ARM::FeatureMVEVectorCostFactor2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 93 + 5609, sizeof(SubtargetFeatureKV) * 93 + 5618, ARM::FeatureMVEVectorCostFactor4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 92 + 5676, sizeof(SubtargetFeatureKV) * 92 + 5681, ARM::FeatureNEON, { { { 0x0ULL, 0x0ULL, 0x80000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 91 + 5706, sizeof(SubtargetFeatureKV) * 91 + 5718, ARM::FeatureNEONForFPMovs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 90 + 5756, sizeof(SubtargetFeatureKV) * 90 + 5763, ARM::FeatureNEONForFP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 89 + 5796, sizeof(SubtargetFeatureKV) * 89 + 5808, ARM::ProcV1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 88 + 5835, sizeof(SubtargetFeatureKV) * 88 + 5855, ARM::FeatureHasNoBranchPredictor, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 87 + 5879, sizeof(SubtargetFeatureKV) * 87 + 5902, ARM::FeatureNoBTIAtReturnTwice, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 86 + 5953, sizeof(SubtargetFeatureKV) * 86 + 5961, ARM::FeatureNoMovt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 85 + 6003, sizeof(SubtargetFeatureKV) * 85 + 6021, ARM::FeatureNoNegativeImmediates, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 84 + 6150, sizeof(SubtargetFeatureKV) * 84 + 6156, ARM::FeatureNoARM, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 83 + 6192, sizeof(SubtargetFeatureKV) * 83 + 6209, ARM::FeatureNonpipelinedVFP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 82 + 6244, sizeof(SubtargetFeatureKV) * 82 + 6251, ARM::FeaturePACBTI, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 81 + 6314, sizeof(SubtargetFeatureKV) * 81 + 6322, ARM::FeaturePerfMon, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 80 + 6372, sizeof(SubtargetFeatureKV) * 80 + 6385, ARM::FeaturePrefISHSTBarrier, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 79 + 6407, sizeof(SubtargetFeatureKV) * 79 + 6421, ARM::FeaturePreferVMOVSR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 78 + 6435, sizeof(SubtargetFeatureKV) * 78 + 6445, ARM::FeatureProfUnpredicate, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 77 + 6474, sizeof(SubtargetFeatureKV) * 77 + 6477, ARM::ProcR4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 76 + 6502, sizeof(SubtargetFeatureKV) * 76 + 6505, ARM::ProcR5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 75 + 6530, sizeof(SubtargetFeatureKV) * 75 + 6534, ARM::ProcR52, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 74 + 6560, sizeof(SubtargetFeatureKV) * 74 + 6568, ARM::ProcR52plus, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 73 + 6598, sizeof(SubtargetFeatureKV) * 73 + 6601, ARM::ProcR7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 72 + 6626, sizeof(SubtargetFeatureKV) * 72 + 6630, ARM::FeatureRAS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 71 + 6693, sizeof(SubtargetFeatureKV) * 71 + 6700, ARM::FeatureRClass, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 70 + 6733, sizeof(SubtargetFeatureKV) * 70 + 6750, ARM::FeatureReadTpTPIDRPRW, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 69 + 6796, sizeof(SubtargetFeatureKV) * 69 + 6813, ARM::FeatureReadTpTPIDRURO, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 68 + 6859, sizeof(SubtargetFeatureKV) * 68 + 6876, ARM::FeatureReadTpTPIDRURW, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 67 + 6922, sizeof(SubtargetFeatureKV) * 67 + 6933, ARM::FeatureReserveR9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 66 + 6974, sizeof(SubtargetFeatureKV) * 66 + 6989, ARM::FeatureHasRetAddrStack, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 65 + 7014, sizeof(SubtargetFeatureKV) * 65 + 7017, ARM::FeatureSB, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 64 + 7050, sizeof(SubtargetFeatureKV) * 64 + 7055, ARM::FeatureSHA2, { { { 0x0ULL, 0x80000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 63 + 7086, sizeof(SubtargetFeatureKV) * 63 + 7099, ARM::FeatureSlowFPBrcc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 62 + 7127, sizeof(SubtargetFeatureKV) * 62 + 7146, ARM::FeatureSlowLoadDSubreg, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 61 + 7177, sizeof(SubtargetFeatureKV) * 61 + 7190, ARM::FeatureSlowOddRegister, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 60 + 7238, sizeof(SubtargetFeatureKV) * 60 + 7250, ARM::FeatureSlowVDUP32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 59 + 7280, sizeof(SubtargetFeatureKV) * 59 + 7295, ARM::FeatureSlowVGETLNi32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 58 + 7328, sizeof(SubtargetFeatureKV) * 58 + 7339, ARM::FeatureHasSlowFPVFMx, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 57 + 7375, sizeof(SubtargetFeatureKV) * 57 + 7386, ARM::FeatureHasSlowFPVMLx, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 56 + 7422, sizeof(SubtargetFeatureKV) * 56 + 7433, ARM::ModeSoftFloat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 55 + 7471, sizeof(SubtargetFeatureKV) * 55 + 7486, ARM::FeatureSplatVFPToNeon, { { { 0x0ULL, 0x10ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 54 + 7518, sizeof(SubtargetFeatureKV) * 54 + 7531, ARM::FeatureStrictAlign, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 53 + 7568, sizeof(SubtargetFeatureKV) * 53 + 7574, ARM::ProcSwift, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 52 + 7595, sizeof(SubtargetFeatureKV) * 52 + 7606, ARM::ModeThumb, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 51 + 7617, sizeof(SubtargetFeatureKV) * 51 + 7624, ARM::FeatureThumb2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 50 + 7651, sizeof(SubtargetFeatureKV) * 50 + 7661, ARM::FeatureTrustZone, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 49 + 7710, sizeof(SubtargetFeatureKV) * 49 + 7726, ARM::FeatureUseMIPipeliner, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 48 + 7751, sizeof(SubtargetFeatureKV) * 48 + 7763, ARM::FeatureUseMISched, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 47 + 7788, sizeof(SubtargetFeatureKV) * 47 + 7792, ARM::HasV4TOps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 46 + 7821, sizeof(SubtargetFeatureKV) * 46 + 7825, ARM::HasV5TOps, { { { 0x0ULL, 0x0ULL, 0x200000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 45 + 7854, sizeof(SubtargetFeatureKV) * 45 + 7859, ARM::HasV5TEOps, { { { 0x0ULL, 0x0ULL, 0x800000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 44 + 7908, sizeof(SubtargetFeatureKV) * 44 + 7911, ARM::HasV6Ops, { { { 0x0ULL, 0x0ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 43 + 7939, sizeof(SubtargetFeatureKV) * 43 + 7943, ARM::HasV6KOps, { { { 0x0ULL, 0x0ULL, 0x4000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 42 + 7972, sizeof(SubtargetFeatureKV) * 42 + 7976, ARM::HasV6MOps, { { { 0x0ULL, 0x0ULL, 0x4000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 41 + 8005, sizeof(SubtargetFeatureKV) * 41 + 8010, ARM::HasV6T2Ops, { { { 0x0ULL, 0x0ULL, 0x21000000800ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 40 + 8040, sizeof(SubtargetFeatureKV) * 40 + 8043, ARM::HasV7Ops, { { { 0x0ULL, 0x0ULL, 0x8000010000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 39 + 8071, sizeof(SubtargetFeatureKV) * 39 + 8079, ARM::FeatureV7Clrex, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 38 + 8104, sizeof(SubtargetFeatureKV) * 38 + 8107, ARM::HasV8Ops, { { { 0x200000000000ULL, 0x20000000000000ULL, 0x10000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 8135, sizeof(SubtargetFeatureKV) * 37 + 8141, ARM::HasV8_1aOps, { { { 0x0ULL, 0x0ULL, 0x80000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 8172, sizeof(SubtargetFeatureKV) * 36 + 8183, ARM::HasV8_1MMainlineOps, { { { 0x0ULL, 0x0ULL, 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 8223, sizeof(SubtargetFeatureKV) * 35 + 8229, ARM::HasV8_2aOps, { { { 0x0ULL, 0x0ULL, 0x200000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 8260, sizeof(SubtargetFeatureKV) * 34 + 8266, ARM::HasV8_3aOps, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 8297, sizeof(SubtargetFeatureKV) * 33 + 8303, ARM::HasV8_4aOps, { { { 0x0ULL, 0x20ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 8334, sizeof(SubtargetFeatureKV) * 32 + 8340, ARM::HasV8_5aOps, { { { 0x0ULL, 0x0ULL, 0x1000000000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 8371, sizeof(SubtargetFeatureKV) * 31 + 8377, ARM::HasV8_6aOps, { { { 0x4000000000000ULL, 0x20000000000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 8408, sizeof(SubtargetFeatureKV) * 30 + 8414, ARM::HasV8_7aOps, { { { 0x0ULL, 0x0ULL, 0x4000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 8445, sizeof(SubtargetFeatureKV) * 29 + 8451, ARM::HasV8_8aOps, { { { 0x0ULL, 0x0ULL, 0x8000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 8482, sizeof(SubtargetFeatureKV) * 28 + 8488, ARM::HasV8_9aOps, { { { 0x8000000000000ULL, 0x0ULL, 0x10000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 8519, sizeof(SubtargetFeatureKV) * 27 + 8523, ARM::HasV8MBaselineOps, { { { 0x0ULL, 0x0ULL, 0x2000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 8561, sizeof(SubtargetFeatureKV) * 26 + 8570, ARM::HasV8MMainlineOps, { { { 0x0ULL, 0x0ULL, 0x10000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 8608, sizeof(SubtargetFeatureKV) * 25 + 8614, ARM::HasV9_1aOps, { { { 0x0ULL, 0x0ULL, 0x44000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 8645, sizeof(SubtargetFeatureKV) * 24 + 8651, ARM::HasV9_2aOps, { { { 0x0ULL, 0x0ULL, 0x88000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 8682, sizeof(SubtargetFeatureKV) * 23 + 8688, ARM::HasV9_3aOps, { { { 0x0ULL, 0x0ULL, 0x110000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 8719, sizeof(SubtargetFeatureKV) * 22 + 8725, ARM::HasV9_4aOps, { { { 0x0ULL, 0x0ULL, 0x220000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 8756, sizeof(SubtargetFeatureKV) * 21 + 8762, ARM::HasV9_5aOps, { { { 0x0ULL, 0x0ULL, 0x400000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 8793, sizeof(SubtargetFeatureKV) * 20 + 8799, ARM::HasV9_6aOps, { { { 0x0ULL, 0x0ULL, 0x800000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 8830, sizeof(SubtargetFeatureKV) * 19 + 8836, ARM::HasV9_7aOps, { { { 0x0ULL, 0x0ULL, 0x1000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 8867, sizeof(SubtargetFeatureKV) * 18 + 8871, ARM::HasV9_0aOps, { { { 0x0ULL, 0x0ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 8900, sizeof(SubtargetFeatureKV) * 17 + 8905, ARM::FeatureVFP2, { { { 0x0ULL, 0x400ULL, 0x40000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 8930, sizeof(SubtargetFeatureKV) * 16 + 8937, ARM::FeatureVFP2_SP, { { { 0x0ULL, 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 8987, sizeof(SubtargetFeatureKV) * 15 + 8992, ARM::FeatureVFP3, { { { 0x0ULL, 0x0ULL, 0x500000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 9017, sizeof(SubtargetFeatureKV) * 14 + 9025, ARM::FeatureVFP3_D16, { { { 0x0ULL, 0x400ULL, 0x220000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 9075, sizeof(SubtargetFeatureKV) * 13 + 9085, ARM::FeatureVFP3_D16_SP, { { { 0x0ULL, 0x0ULL, 0x40000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 9159, sizeof(SubtargetFeatureKV) * 12 + 9166, ARM::FeatureVFP3_SP, { { { 0x0ULL, 0x1ULL, 0x200000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 9216, sizeof(SubtargetFeatureKV) * 11 + 9221, ARM::FeatureVFP4, { { { 0x0ULL, 0x100ULL, 0x5080000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 9246, sizeof(SubtargetFeatureKV) * 10 + 9254, ARM::FeatureVFP4_D16, { { { 0x0ULL, 0x500ULL, 0x2100000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 9304, sizeof(SubtargetFeatureKV) * 9 + 9314, ARM::FeatureVFP4_D16_SP, { { { 0x0ULL, 0x100ULL, 0x200000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 9388, sizeof(SubtargetFeatureKV) * 8 + 9395, ARM::FeatureVFP4_SP, { { { 0x0ULL, 0x101ULL, 0x2400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 9445, sizeof(SubtargetFeatureKV) * 7 + 9460, ARM::FeatureVirtualization, { { { 0x0ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 9494, sizeof(SubtargetFeatureKV) * 6 + 9505, ARM::FeatureCheckVLDnAlign, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 9537, sizeof(SubtargetFeatureKV) * 5 + 9553, ARM::FeatureVMLxForwarding, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 9591, sizeof(SubtargetFeatureKV) * 4 + 9604, ARM::FeatureHasVMLxHazards, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 9621, sizeof(SubtargetFeatureKV) * 3 + 9637, ARM::FeatureUseWideStrideVFP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 9685, sizeof(SubtargetFeatureKV) * 2 + 902, ARM::XScale, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 9692, sizeof(SubtargetFeatureKV) * 1 + 9696, ARM::FeatureZCZeroing, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000" "32bit\000Prefer 32-bit Thumb instrs\000" "8msecext\000Enable sup"
    "port for ARMv8-M Security Extensions\000a12\000Cortex-A12 ARM processor"
    "s\000a15\000Cortex-A15 ARM processors\000a17\000Cortex-A17 ARM processo"
    "rs\000a32\000Cortex-A32 ARM processors\000a35\000Cortex-A35 ARM process"
    "ors\000a5\000Cortex-A5 ARM processors\000a53\000Cortex-A53 ARM processo"
    "rs\000a55\000Cortex-A55 ARM processors\000a57\000Cortex-A57 ARM process"
    "ors\000a7\000Cortex-A7 ARM processors\000a72\000Cortex-A72 ARM processo"
    "rs\000a73\000Cortex-A73 ARM processors\000a75\000Cortex-A75 ARM process"
    "ors\000a76\000Cortex-A76 ARM processors\000a77\000Cortex-A77 ARM proces"
    "sors\000a78c\000Cortex-A78C ARM processors\000a8\000Cortex-A8 ARM proce"
    "ssors\000a9\000Cortex-A9 ARM processors\000aapcs-frame-chain\000Create "
    "an AAPCS compliant frame chain\000aclass\000Is application profile ('A'"
    " series)\000acquire-release\000Has v8 acquire/release (lda/ldaex  etc) "
    "instructions\000aes\000Enable AES support\000armv4\000ARMv4 architectur"
    "e\000armv4t\000ARMv4t architecture\000armv5t\000ARMv5t architecture\000"
    "armv5te\000ARMv5te architecture\000armv5tej\000ARMv5tej architecture\000"
    "armv6\000ARMv6 architecture\000armv6-m\000ARMv6m architecture\000armv6j"
    "\000ARMv7a architecture\000armv6k\000ARMv6k architecture\000armv6kz\000"
    "ARMv6kz architecture\000armv6s-m\000ARMv6sm architecture\000armv6t2\000"
    "ARMv6t2 architecture\000armv7-a\000armv7-m\000ARMv7m architecture\000ar"
    "mv7-r\000ARMv7r architecture\000armv7e-m\000ARMv7em architecture\000arm"
    "v7k\000armv7s\000armv7ve\000ARMv7ve architecture\000armv8-a\000ARMv8a a"
    "rchitecture\000armv8-m.base\000ARMv8mBaseline architecture\000armv8-m.m"
    "ain\000ARMv8mMainline architecture\000armv8-r\000ARMv8r architecture\000"
    "armv8.1-a\000ARMv81a architecture\000armv8.1-m.main\000ARMv81mMainline "
    "architecture\000armv8.2-a\000ARMv82a architecture\000armv8.3-a\000ARMv8"
    "3a architecture\000armv8.4-a\000ARMv84a architecture\000armv8.5-a\000AR"
    "Mv85a architecture\000armv8.6-a\000ARMv86a architecture\000armv8.7-a\000"
    "ARMv87a architecture\000armv8.8-a\000ARMv88a architecture\000armv8.9-a\000"
    "ARMv89a architecture\000armv9-a\000ARMv9a architecture\000armv9.1-a\000"
    "ARMv91a architecture\000armv9.2-a\000ARMv92a architecture\000armv9.3-a\000"
    "ARMv93a architecture\000armv9.4-a\000ARMv94a architecture\000armv9.5-a\000"
    "ARMv95a architecture\000armv9.6-a\000ARMv96a architecture\000armv9.7-a\000"
    "ARMv97a architecture\000atomics-32\000Assume that lock-free 32-bit atom"
    "ics are available\000avoid-movs-shop\000Avoid movs instructions with sh"
    "ifter operand\000avoid-muls\000Avoid MULS instructions for M class core"
    "s\000avoid-partial-cpsr\000Avoid CPSR partial update for OOO execution\000"
    "bf16\000Enable support for BFloat16 instructions\000big-endian-instruct"
    "ions\000Expect instructions to be stored big-endian.\000branch-align-64"
    "\000Prefer 64-bit alignment for branch targets\000cde\000Support CDE in"
    "structions\000cdecp0\000Coprocessor 0 ISA is CDEv1\000cdecp1\000Coproce"
    "ssor 1 ISA is CDEv1\000cdecp2\000Coprocessor 2 ISA is CDEv1\000cdecp3\000"
    "Coprocessor 3 ISA is CDEv1\000cdecp4\000Coprocessor 4 ISA is CDEv1\000c"
    "decp5\000Coprocessor 5 ISA is CDEv1\000cdecp6\000Coprocessor 6 ISA is C"
    "DEv1\000cdecp7\000Coprocessor 7 ISA is CDEv1\000cheap-predicable-cpsr\000"
    "Disable +1 predication cost for instructions updating CPSR\000clrbhb\000"
    "Enable Clear BHB instruction\000cortex-a510\000Cortex-A510 ARM processo"
    "rs\000cortex-a710\000Cortex-A710 ARM processors\000cortex-a78\000Cortex"
    "-A78 ARM processors\000cortex-a78ae\000Cortex-A78AE ARM processors\000c"
    "ortex-x1\000Cortex-X1 ARM processors\000cortex-x1c\000Cortex-X1C ARM pr"
    "ocessors\000crc\000Enable support for CRC instructions\000crypto\000Ena"
    "ble support for Cryptography extensions\000d32\000Extend FP to 32 doubl"
    "e registers\000db\000Has data barrier (dmb/dsb) instructions\000dfb\000"
    "Has full data barrier (dfb) instruction\000disable-postra-scheduler\000"
    "Don't schedule again after register allocation\000dont-widen-vmovs\000D"
    "on't widen VMOVS to VMOVD\000dotprod\000Enable support for dot product "
    "instructions\000dsp\000Supports DSP instructions in ARM and/or Thumb2\000"
    "execute-only\000Enable the generation of execute only code.\000expand-f"
    "p-mlx\000Expand VFP/NEON MLA/MLS instructions\000exynos\000Samsung Exyn"
    "os processors\000fix-cmse-cve-2021-35465\000Mitigate against the cve-20"
    "21-35465 security vulnurability\000fix-cortex-a57-aes-1742098\000Work a"
    "round Cortex-A57 Erratum 1742098 / Cortex-A72 Erratum 1655431 (AES)\000"
    "fp-armv8\000Enable ARMv8 FP\000fp-armv8d16\000Enable ARMv8 FP with only"
    " 16 d-registers\000fp-armv8d16sp\000Enable ARMv8 FP with only 16 d-regi"
    "sters and no double precision\000fp-armv8sp\000Enable ARMv8 FP with no "
    "double precision\000fp16\000Enable half-precision floating point\000fp1"
    "6fml\000Enable full half-precision floating point fml instructions\000f"
    "p64\000Floating point unit supports double precision\000fpao\000Enable "
    "fast computation of positive address offsets\000fpregs\000Enable FP reg"
    "isters\000fpregs16\000Enable 16-bit FP registers\000fpregs64\000Enable "
    "64-bit FP registers\000fullfp16\000Enable full half-precision floating "
    "point\000fuse-aes\000CPU fuses AES crypto operations\000fuse-literals\000"
    "CPU fuses literal generation operations\000harden-sls-blr\000Harden aga"
    "inst straight line speculation across indirect calls\000harden-sls-noco"
    "mdat\000Generate thunk code for SLS mitigation in the normal text secti"
    "on\000harden-sls-retbr\000Harden against straight line speculation acro"
    "ss RETurn and BranchRegister instructions\000hwdiv\000Enable divide ins"
    "tructions in Thumb\000hwdiv-arm\000Enable divide instructions in ARM mo"
    "de\000i8mm\000Enable Matrix Multiply Int8 Extension\000iwmmxt\000iwmmxt"
    "2\000krait\000Qualcomm Krait processors\000kryo\000Qualcomm Kryo proces"
    "sors\000lob\000Enable Low Overhead Branch extensions\000long-calls\000G"
    "enerate calls via indirect call instructions\000loop-align\000Prefer 32"
    "-bit alignment for branch targets\000m3\000Cortex-M3 ARM processors\000"
    "m55\000Cortex-M55 ARM processors\000m7\000Cortex-M7 ARM processors\000m"
    "85\000Cortex-M85 ARM processors\000mclass\000Is microcontroller profile"
    " ('M' series)\000mp\000Supports Multiprocessing extension\000muxed-unit"
    "s\000Has muxed AGU and NEON/FPU\000mve\000Support M-Class Vector Extens"
    "ion with integer ops\000mve.fp\000Support M-Class Vector Extension with"
    " integer and floating ops\000mve1beat\000Model MVE instructions as a 1 "
    "beat per tick architecture\000mve2beat\000Model MVE instructions as a 2"
    " beats per tick architecture\000mve4beat\000Model MVE instructions as a"
    " 4 beats per tick architecture\000neon\000Enable NEON instructions\000n"
    "eon-fpmovs\000Convert VMOVSR, VMOVRS, VMOVS to NEON\000neonfp\000Use NE"
    "ON for single precision FP\000neoverse-v1\000Neoverse-V1 ARM processors"
    "\000no-branch-predictor\000Has no branch predictor\000no-bti-at-return-"
    "twice\000Don't place a BTI instruction after a return-twice\000no-movt\000"
    "Don't use movt/movw pairs for 32-bit imms\000no-neg-immediates\000Conve"
    "rt immediates and instructions to their negated or complemented equival"
    "ent when the immediate does not fit in the encoding.\000noarm\000Does n"
    "ot support ARM mode execution\000nonpipelined-vfp\000VFP instructions a"
    "re not pipelined\000pacbti\000Enable Pointer Authentication and Branch "
    "Target Identification\000perfmon\000Enable support for Performance Moni"
    "tor extensions\000prefer-ishst\000Prefer ISHST barriers\000prefer-vmovs"
    "r\000Prefer VMOVSR\000prof-unpr\000Is profitable to unpredicate\000r4\000"
    "Cortex-R4 ARM processors\000r5\000Cortex-R5 ARM processors\000r52\000Co"
    "rtex-R52 ARM processors\000r52plus\000Cortex-R52plus ARM processors\000"
    "r7\000Cortex-R7 ARM processors\000ras\000Enable Reliability, Availabili"
    "ty and Serviceability extensions\000rclass\000Is realtime profile ('R' "
    "series)\000read-tp-tpidrprw\000Reading thread pointer from TPIDRPRW reg"
    "ister\000read-tp-tpidruro\000Reading thread pointer from TPIDRURO regis"
    "ter\000read-tp-tpidrurw\000Reading thread pointer from TPIDRURW registe"
    "r\000reserve-r9\000Reserve R9, making it unavailable as GPR\000ret-addr"
    "-stack\000Has return address stack\000sb\000Enable v8.5a Speculation Ba"
    "rrier\000sha2\000Enable SHA1 and SHA256 support\000slow-fp-brcc\000FP c"
    "ompare + branch is slow\000slow-load-D-subreg\000Loading into D subregs"
    " is slow\000slow-odd-reg\000VLDM/VSTM starting with an odd register is "
    "slow\000slow-vdup32\000Has slow VDUP32 - prefer VMOV\000slow-vgetlni32\000"
    "Has slow VGETLNi32 - prefer VMOV\000slowfpvfmx\000Disable VFP / NEON FM"
    "A instructions\000slowfpvmlx\000Disable VFP / NEON MAC instructions\000"
    "soft-float\000Use software floating point features.\000splat-vfp-neon\000"
    "Splat register from VFP to NEON\000strict-align\000Disallow all unalign"
    "ed memory access\000swift\000Swift ARM processors\000thumb-mode\000Thum"
    "b mode\000thumb2\000Enable Thumb2 instructions\000trustzone\000Enable s"
    "upport for TrustZone security extensions\000use-mipipeliner\000Use the "
    "MachinePipeliner\000use-misched\000Use the MachineScheduler\000v4t\000S"
    "upport ARM v4T instructions\000v5t\000Support ARM v5T instructions\000v"
    "5te\000Support ARM v5TE, v5TEj, and v5TExp instructions\000v6\000Suppor"
    "t ARM v6 instructions\000v6k\000Support ARM v6k instructions\000v6m\000"
    "Support ARM v6M instructions\000v6t2\000Support ARM v6t2 instructions\000"
    "v7\000Support ARM v7 instructions\000v7clrex\000Has v7 clrex instructio"
    "n\000v8\000Support ARM v8 instructions\000v8.1a\000Support ARM v8.1a in"
    "structions\000v8.1m.main\000Support ARM v8-1M Mainline instructions\000"
    "v8.2a\000Support ARM v8.2a instructions\000v8.3a\000Support ARM v8.3a i"
    "nstructions\000v8.4a\000Support ARM v8.4a instructions\000v8.5a\000Supp"
    "ort ARM v8.5a instructions\000v8.6a\000Support ARM v8.6a instructions\000"
    "v8.7a\000Support ARM v8.7a instructions\000v8.8a\000Support ARM v8.8a i"
    "nstructions\000v8.9a\000Support ARM v8.9a instructions\000v8m\000Suppor"
    "t ARM v8M Baseline instructions\000v8m.main\000Support ARM v8M Mainline"
    " instructions\000v9.1a\000Support ARM v9.1a instructions\000v9.2a\000Su"
    "pport ARM v9.2a instructions\000v9.3a\000Support ARM v9.3a instructions"
    "\000v9.4a\000Support ARM v9.4a instructions\000v9.5a\000Support ARM v9."
    "5a instructions\000v9.6a\000Support ARM v9.6a instructions\000v9.7a\000"
    "Support ARM v9.7a instructions\000v9a\000Support ARM v9a instructions\000"
    "vfp2\000Enable VFP2 instructions\000vfp2sp\000Enable VFP2 instructions "
    "with no double precision\000vfp3\000Enable VFP3 instructions\000vfp3d16"
    "\000Enable VFP3 instructions with only 16 d-registers\000vfp3d16sp\000E"
    "nable VFP3 instructions with only 16 d-registers and no double precisio"
    "n\000vfp3sp\000Enable VFP3 instructions with no double precision\000vfp"
    "4\000Enable VFP4 instructions\000vfp4d16\000Enable VFP4 instructions wi"
    "th only 16 d-registers\000vfp4d16sp\000Enable VFP4 instructions with on"
    "ly 16 d-registers and no double precision\000vfp4sp\000Enable VFP4 inst"
    "ructions with no double precision\000virtualization\000Supports Virtual"
    "ization extension\000vldn-align\000Check for VLDn unaligned access\000v"
    "mlx-forwarding\000Has multiplier accumulator forwarding\000vmlx-hazards"
    "\000Has VMLx hazards\000wide-stride-vfp\000Use a wide stride when alloc"
    "ating VFP registers\000xscale\000zcz\000Has zero-cycle zeroing instruct"
    "ions\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 96, 964> ARMSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 96 + 1, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 95 + 10, { { { 0x4ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 94 + 19, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 93 + 28, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 92 + 35, { { { 0x4ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 91 + 45, { { { 0x20ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 90 + 56, { { { 0x20ULL, 0x100000000ULL, 0x20000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 89 + 68, { { { 0x800ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 88 + 80, { { { 0x800ULL, 0x100000000ULL, 0x20000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 87 + 93, { { { 0x100ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 86 + 105, { { { 0x100ULL, 0x100000000ULL, 0x20000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 85 + 118, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 84 + 126, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 83 + 134, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 82 + 143, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 81 + 154, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 80 + 159, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 79 + 166, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 78 + 171, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 77 + 178, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 76 + 186, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 75 + 194, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 74 + 205, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 73 + 213, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 72 + 223, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 71 + 233, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 70 + 243, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 69 + 249, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 68 + 258, { { { 0x2000000001000ULL, 0x2040000000ULL, 0x18801000ULL, 0x80ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 67 + 269, { { { 0x42000000001000ULL, 0x42040000010ULL, 0x10801200ULL, 0x100ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 66 + 280, { { { 0x2000000001000ULL, 0x2040000000ULL, 0x18801000ULL, 0x200ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 65 + 291, { { { 0x8010000000080000ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 64 + 302, { { { 0x8010000000080000ULL, 0x3000000ULL, 0x0ULL, 0x800ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 63 + 313, { { { 0x1000ULL, 0x21c0000000ULL, 0x8801010ULL, 0x8ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 62 + 323, { { { 0x4000000800000ULL, 0x20003000200ULL, 0x4ULL, 0x1000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 61 + 335, { { { 0x8010000000080000ULL, 0x3000800ULL, 0x0ULL, 0x1000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 60 + 346, { { { 0x4000000ULL, 0x3000020ULL, 0x0ULL, 0x2000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 59 + 357, { { { 0x8032000000080000ULL, 0x3100800ULL, 0x0ULL, 0x4000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 58 + 368, { { { 0x1000ULL, 0x23c0000000ULL, 0x18801010ULL, 0x10ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 57 + 378, { { { 0x4000000800000ULL, 0x20003000200ULL, 0x4ULL, 0x1000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 56 + 390, { { { 0x8010000000080000ULL, 0x3100000ULL, 0x0ULL, 0x8000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 55 + 401, { { { 0x8010000000080000ULL, 0x3000000ULL, 0x0ULL, 0x10000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 54 + 412, { { { 0x4000000ULL, 0x3000020ULL, 0x0ULL, 0x20000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 53 + 423, { { { 0x8010000004000000ULL, 0x3200020ULL, 0x0ULL, 0x40000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 52 + 434, { { { 0x8010000004000000ULL, 0x3200020ULL, 0x0ULL, 0x40000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 51 + 447, { { { 0x8010000004000000ULL, 0x3200020ULL, 0x0ULL, 0x80000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 50 + 458, { { { 0x8010000004000000ULL, 0x3200020ULL, 0x0ULL, 0x100000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 49 + 469, { { { 0x8010000004000000ULL, 0x3200020ULL, 0x0ULL, 0x200000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 48 + 482, { { { 0x8010000004000000ULL, 0x3200020ULL, 0x0ULL, 0x400000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 47 + 494, { { { 0x1000ULL, 0x80003c0000000ULL, 0x8001010ULL, 0x20ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 46 + 504, { { { 0x42000000001000ULL, 0x400242240000180ULL, 0x8001000ULL, 0x40ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 45 + 514, { { { 0x200ULL, 0x20000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 44 + 524, { { { 0x200ULL, 0x20000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 43 + 538, { { { 0x200ULL, 0x20000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 42 + 548, { { { 0x100000ULL, 0x1000020000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 41 + 559, { { { 0x8000ULL, 0x100000020000000ULL, 0x4000ULL, 0x10000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 40 + 569, { { { 0x1000000200000ULL, 0x1000001a0084008ULL, 0x4000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 39 + 580, { { { 0x200000ULL, 0x1000001a0084008ULL, 0x4000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 38 + 592, { { { 0x2000ULL, 0x1000001a0000000ULL, 0x2004000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 37 + 602, { { { 0x2000000ULL, 0x110004120002008ULL, 0x80004000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 36 + 613, { { { 0x2000000ULL, 0x100000120082008ULL, 0x80004000ULL, 0x40000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 35 + 624, { { { 0x2000ULL, 0x200000000002000ULL, 0x6000ULL, 0x20000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 34 + 634, { { { 0x2000000ULL, 0x210000000002008ULL, 0x80004000ULL, 0x80000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 8 },
   { sizeof(SubtargetSubTypeKV) * 33 + 645, { { { 0x2000000010000ULL, 0x40000000ULL, 0x0ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 32 + 655, { { { 0x2000000010000ULL, 0x1c0000000ULL, 0x100010ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 31 + 666, { { { 0x2000000010000ULL, 0x1c1000000ULL, 0x100010ULL, 0x200000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 30 + 676, { { { 0x400000ULL, 0x80000001800ULL, 0x4000ULL, 0x800000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 9 },
   { sizeof(SubtargetSubTypeKV) * 29 + 687, { { { 0x400000ULL, 0x80000001800ULL, 0x4000ULL, 0x1000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 9 },
   { sizeof(SubtargetSubTypeKV) * 28 + 702, { { { 0x2000000010000ULL, 0x21c1000100ULL, 0x100010ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 27 + 712, { { { 0x2000000010000ULL, 0x21c1000100ULL, 0x100010ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 26 + 722, { { { 0x8010000004000000ULL, 0x3200020ULL, 0x0ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 25 + 732, { { { 0x8010000004000000ULL, 0x3200020ULL, 0x0ULL, 0x10000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 24 + 743, { { { 0x8002800000080000ULL, 0x41021c3000000ULL, 0x20804000ULL, 0x2000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 10 },
   { sizeof(SubtargetSubTypeKV) * 23 + 751, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 22 + 758, { { { 0x80000ULL, 0x0ULL, 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 21 + 768, { { { 0x4000000ULL, 0x200020ULL, 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 20 + 778, { { { 0x4000000ULL, 0x200020ULL, 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 19 + 788, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 18 + 796, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 17 + 803, { { { 0x42000000001000ULL, 0x40043000100ULL, 0x8800000ULL, 0x4000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 16 + 809, { { { 0x8010000000080000ULL, 0x3000000ULL, 0x0ULL, 0x8000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 15 + 814, { { { 0x80ULL, 0x100000000ULL, 0x20000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 14 + 821, { { { 0x80ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 13 + 833, { { { 0x8010000004000000ULL, 0x3000020ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 12 + 845, { { { 0x4000000800000ULL, 0x20000000200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 11 + 857, { { { 0x8014000010000000ULL, 0x20003200000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 10 + 869, { { { 0x200ULL, 0x20000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 9 + 875, { { { 0x8000ULL, 0x20000000ULL, 0x4000ULL, 0x10000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 8 + 881, { { { 0x1000000200000ULL, 0x1000001a0084008ULL, 0x4000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 7 + 890, { { { 0x2000000ULL, 0x110004120002008ULL, 0x80004000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 6 + 899, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 5 + 909, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 4 + 922, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 3 + 936, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 2 + 950, { { { 0x2800000001000ULL, 0x8841023c3000000ULL, 0x80c1e0ULL, 0x2000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 10 },
   { sizeof(SubtargetSubTypeKV) * 1 + 956, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
  },
    "\000arm1020e\000arm1020t\000arm1022e\000arm10e\000arm10tdmi\000arm1136j"
    "-s\000arm1136jf-s\000arm1156t2-s\000arm1156t2f-s\000arm1176jz-s\000arm1"
    "176jzf-s\000arm710t\000arm720t\000arm7tdmi\000arm7tdmi-s\000arm8\000arm"
    "810\000arm9\000arm920\000arm920t\000arm922t\000arm926ej-s\000arm940t\000"
    "arm946e-s\000arm966e-s\000arm968e-s\000arm9e\000arm9tdmi\000cortex-a12\000"
    "cortex-a15\000cortex-a17\000cortex-a32\000cortex-a35\000cortex-a5\000co"
    "rtex-a510\000cortex-a53\000cortex-a55\000cortex-a57\000cortex-a7\000cor"
    "tex-a710\000cortex-a72\000cortex-a73\000cortex-a75\000cortex-a76\000cor"
    "tex-a76ae\000cortex-a77\000cortex-a78\000cortex-a78ae\000cortex-a78c\000"
    "cortex-a8\000cortex-a9\000cortex-m0\000cortex-m0plus\000cortex-m1\000co"
    "rtex-m23\000cortex-m3\000cortex-m33\000cortex-m35p\000cortex-m4\000cort"
    "ex-m52\000cortex-m55\000cortex-m7\000cortex-m85\000cortex-r4\000cortex-"
    "r4f\000cortex-r5\000cortex-r52\000cortex-r52plus\000cortex-r7\000cortex"
    "-r8\000cortex-x1\000cortex-x1c\000cyclone\000ep9312\000exynos-m3\000exy"
    "nos-m4\000exynos-m5\000generic\000iwmmxt\000krait\000kryo\000mpcore\000"
    "mpcorenovfp\000neoverse-n1\000neoverse-n2\000neoverse-v1\000sc000\000sc"
    "300\000star-mc1\000star-mc3\000strongarm\000strongarm110\000strongarm11"
    "00\000strongarm1110\000swift\000xscale\000"};

namespace ARM_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  switch (SchedClass) {
  case 1: // IIC_iALUi_WriteALU_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 2: // IIC_iALUr_WriteALU_ReadALU_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 3: // IIC_iALUsr_WriteALUsi_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 4: // IIC_iALUsr_WriteALUSsr_ReadALUsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1336; // SwiftWriteP0ThreeCycleThreeUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 5: // IIC_iMOVsi_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 13: // IIC_iMAC32_WriteMAC32_ReadMUL_ReadMUL_ReadMAC
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1349; // SwiftWriteP0P01FiveCycleTwoUops_ReadMUL_ReadMUL_anonymous_20158
      return 1350; // SwiftWriteP0FourCycle_ReadMUL_ReadMUL_ReadALU
    }
    break;
  case 14: // IIC_iCMOVi_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 15: // IIC_iMOVi_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 17: // IIC_iCMOVr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 18: // IIC_iCMOVsr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 23: // IIC_iALUr_WriteALU_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 28: // IIC_iMAC64_WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1353; // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_anonymous_20158_anonymous_20158
      return 1354; // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_ReadALU_ReadALU
    }
    break;
  case 37: // IIC_iALUsi_WriteALUsi_ReadALUsr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC
          && ARM_MC::isPredicated(*MI, MCII))
        return 1334; // anonymous_20746_ReadDefault
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1335; // A57Write_2cyc_1M_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1356; // WriteALU_anonymous_20127
      return 1357; // WriteALU_NoReadAdvance
    }
    break;
  case 38: // IIC_iCMOVsi_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 39: // IIC_iALUsi_WriteALUsi_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 41: // IIC_iALUr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 42: // IIC_iALUi_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 45: // IIC_iALUsr_WriteALUsr_ReadALUsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1367; // SwiftWriteP01ThreeCycleTwoUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 46: // IIC_iBITi_WriteALU_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 47: // IIC_iBITr_WriteALU_ReadALU_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 48: // IIC_iBITsr_WriteALUsi_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 49: // IIC_iBITsr_WriteALUsr_ReadALUsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1367; // SwiftWriteP01ThreeCycleTwoUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 54: // IIC_iUNAr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 57: // IIC_iCMPsr_WriteCMPsi_ReadALU
    if (CPUID == 10) { // SwiftModel
  return 1330; // SwiftWriteP01TwoCycle_ReadALU
    }
    break;
  case 58: // IIC_iCMPsr_WriteCMPsr_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1369; // A57Write_2cyc_1I_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    break;
  case 68: // IIC_iMOVr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 69: // IIC_iMOVsr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 70: // IIC_iMVNi_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 71: // IIC_iMVNr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 72: // IIC_iMVNsr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 73: // IIC_iBITsi_WriteALUsi_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 76: // IIC_iMAC16_WriteMAC16_ReadMUL_ReadMUL_ReadMAC
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1349; // SwiftWriteP0P01FiveCycleTwoUops_ReadMUL_ReadMUL_anonymous_20158
      return 1350; // SwiftWriteP0FourCycle_ReadMUL_ReadMUL_ReadALU
    }
    break;
  case 77: // WriteMAC32_ReadMUL_ReadMUL_ReadMAC
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1349; // SwiftWriteP0P01FiveCycleTwoUops_ReadMUL_ReadMUL_anonymous_20158
      return 1350; // SwiftWriteP0FourCycle_ReadMUL_ReadMUL_ReadALU
    }
    break;
  case 78: // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1353; // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_anonymous_20158_anonymous_20158
      return 1354; // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_ReadALU_ReadALU
    }
    break;
  case 90: // IIC_iEXTAr_WriteALUsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1379; // anonymous_20739
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1381; // anonymous_20746
      return 1382; // A57Write_2cyc_1M
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 91: // IIC_iEXTr_WriteALUsi
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1381; // anonymous_20746
      return 1382; // A57Write_2cyc_1M
    }
    if (CPUID == 10) { // SwiftModel
      return 1385; // WriteALU
    }
    break;
  case 94: // IIC_iTSTsr_WriteCMPsi_ReadALU
    if (CPUID == 10) { // SwiftModel
  return 1330; // SwiftWriteP01TwoCycle_ReadALU
    }
    break;
  case 95: // IIC_iTSTsr_WriteCMPsr_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1369; // A57Write_2cyc_1I_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    break;
  case 96: // IIC_iMUL64_WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1386; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL
      return 1387; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL
    }
    break;
  case 97: // WriteALU_ReadALU_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 278: // IIC_iUNAsi_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 279: // IIC_iBITi_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 280: // IIC_iCMPsi_WriteCMPsi_ReadALU_ReadALU
    if (CPUID == 10) { // SwiftModel
  return 1423; // SwiftWriteP01TwoCycle_ReadALU_ReadALU
    }
    break;
  case 283: // IIC_iCMPsi_WriteCMPsi
    if (CPUID == 10) { // SwiftModel
  return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 294: // IIC_iMVNsi_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 295: // IIC_iALUsir_WriteALUsi_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 296: // IIC_iMUL16_WriteMAC16_ReadMUL_ReadMUL_ReadMAC
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1349; // SwiftWriteP0P01FiveCycleTwoUops_ReadMUL_ReadMUL_anonymous_20158
      return 1350; // SwiftWriteP0FourCycle_ReadMUL_ReadMUL_ReadALU
    }
    break;
  case 298: // WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 308: // IIC_iEXTAsr_WriteALU_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 309: // IIC_iEXTr_WriteALU_ReadALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 312: // IIC_iTSTsi_WriteCMPsi
    if (CPUID == 10) { // SwiftModel
  return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 313: // IIC_iBITr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 320: // IIC_iTSTr_WriteALU
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 321: // ANDri_ORRri_EORri_BICri
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 322: // ANDrr_ORRrr_EORrr_BICrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 323: // ANDrsi_ORRrsi_EORrsi_BICrsi
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 324: // ANDrsr_ORRrsr_EORrsr_BICrsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1367; // SwiftWriteP01ThreeCycleTwoUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 325: // MOVsr_MOVsi
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 326: // MVNsr
    if (CPUID == 4) { // CortexA57Model
      if ((
            ARM_MC::isCPSRDefined(*MI, MCII)
            && ARM_MC::isPredicated(*MI, MCII)
          ))
        return 1380; // A57Write_2cyc_1I
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 327: // MOVCCsi_MOVCCsr
    if (CPUID == 4) { // CortexA57Model
      if ((
            ARM_MC::isCPSRDefined(*MI, MCII)
            && ARM_MC::isPredicated(*MI, MCII)
          ))
        return 1380; // A57Write_2cyc_1I
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 333: // SEL
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1425; // (SwiftWriteP0OneCycle_SwiftWriteP0OneCycle)
      return 1426; // SwiftWriteP0OneCycle
    }
    break;
  case 336: // MLAv5_MLA_MLS_SMMLA_SMMLAR_SMMLS_SMMLSR
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 338: // UMULL
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1386; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL
      return 1387; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL
    }
    break;
  case 339: // SMLAL_UMLALv5_UMLAL_UMAAL_SMLALv5_SMLALBB_SMLALBT_SMLALTB_SMLALTT
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    break;
  case 340: // SMLAD_SMLADX_SMLSD_SMLSDX
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1429; // SwiftWriteP0P01FiveCycleTwoUops
      return 1430; // SwiftWriteP0FourCycle
    }
    break;
  case 341: // SMLALD_SMLSLD
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    break;
  case 345: // SMLABB_SMLABT_SMLATB_SMLATT_SMLAWB_SMLAWT
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 347: // LDRrs
    if (CPUID == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(3).getImm()) == 2
            )
          ))
        return 1431; // A57Write_5cyc_1I_1L
      if (ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::sub)
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 348: // LDRBi12_PICLDRH_PICLDRB_PICLDRSH_PICLDRSB_LDRH_LDRSH_LDRSB
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getOperand(2).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(3).getImm()) == ARM_AM::sub
          ))
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 351: // SXTB_SXTB16_SXTH_UXTB_UXTB16_UXTH
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1381; // anonymous_20746
      return 1382; // A57Write_2cyc_1M
    }
    break;
  case 352: // t2SXTB_t2SXTB16_t2SXTH_t2UXTB_t2UXTB16_t2UXTH
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 353: // t2MOVCCi32imm
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 354: // t2MOVi32imm
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 355: // t2MOV_ga_pcrel
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 356: // t2MOVi16_ga_pcrel
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 357: // t2SEL
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1425; // (SwiftWriteP0OneCycle_SwiftWriteP0OneCycle)
      return 1426; // SwiftWriteP0OneCycle
    }
    break;
  case 363: // SADD8_SADD16_SSUB8_SSUB16_SASX_SSAX_UADD8_UADD16_USUB8_USUB16_UASX_USAX
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1433; // A57Write_5cyc_1I_1M
      return 1434; // A57Write_3cyc_1I_1M
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 364: // t2SADD8_t2SADD16_t2SSUB8_t2SSUB16_t2SASX_t2SSAX_t2UADD8_t2UADD16_t2USUB8_t2USUB16_t2UASX_t2USAX
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1433; // A57Write_5cyc_1I_1M
      return 1434; // A57Write_3cyc_1I_1M
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 375: // t2MLA_t2MLS_t2SMMLA_t2SMMLAR_t2SMMLS_t2SMMLSR
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 377: // SMLSD_SMLSDX
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 378: // t2SMLABB_t2SMLABT_t2SMLATB_t2SMLATT_t2SMLAWB_t2SMLAWT
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 379: // t2SMLSD_t2SMLSDX
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 380: // t2SMLAD_t2SMLADX
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1429; // SwiftWriteP0P01FiveCycleTwoUops
      return 1430; // SwiftWriteP0FourCycle
    }
    break;
  case 383: // t2SMLAL_t2SMLALBB_t2SMLALBT_t2SMLALD_t2SMLALDX_t2SMLALTB_t2SMLALTT_t2UMLAL_t2SMLSLD_t2SMLSLDX_t2UMAAL
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    break;
  case 387: // LDRBrs
    if (CPUID == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(3).getImm()) == 2
            )
          ))
        return 1431; // A57Write_5cyc_1I_1L
      if (ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::sub)
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 396: // LDRH_PICLDRB_PICLDRH
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getOperand(2).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(3).getImm()) == ARM_AM::sub
          ))
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 402: // LDRBT_POST_IMM_LDRBT_POST_REG_LDRB_POST_REG_LDRB_PRE_REG
    if (CPUID == 4) { // CortexA57Model
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift)
        return 1435; // A57Write_4cyc_1I_1L_1M_A57WrBackThree
      return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
    }
    break;
  case 404: // LDRT_POST_IMM_LDRT_POST_REG_LDR_POST_REG_LDR_PRE_REG
    if (CPUID == 4) { // CortexA57Model
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift)
        return 1435; // A57Write_4cyc_1I_1L_1M_A57WrBackThree
      return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
    }
    break;
  case 417: // LDRD
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getOperand(3).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(4).getImm()) == ARM_AM::sub
          ))
        return 1437; // A57Write_5cyc_1I_1L_A57Write_5cyc_1I_1L
      return 1438; // A57Write_4cyc_1L_A57Write_4cyc_1L
    }
    break;
  case 418: // LDRD_POST_LDRD_PRE
    if (CPUID == 4) { // CortexA57Model
      if (!MI->getOperand(4).getReg().isValid())
        return 1439; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57WrBackTwo
      return 1440; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57WrBackOne
    }
    break;
  case 420: // LDMDA_LDMDB_LDMIA_LDMIB_t2LDMDB_t2LDMIA_sysLDMDA_sysLDMDB_sysLDMIA_sysLDMIB_tLDMIA
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1473; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1474; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1475; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1476; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1477; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1478; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1479; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1481; // A57Write_3cyc_1L_A57Write_3cyc_1L
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1482; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1483; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1484; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1485; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1486; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1487; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
      return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
    }
    if (CPUID == 9) { // CortexR52Model
      return 1472; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1456; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLDMAddrNoWB
    }
    break;
  case 421: // LDMDA_UPD_LDMDB_UPD_LDMIA_UPD_LDMIB_UPD_tLDMIA_UPD_sysLDMDA_UPD_sysLDMDB_UPD_sysLDMIA_UPD_sysLDMIB_UPD_t2LDMDB_UPD_t2LDMIA_UPD
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1504; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo
    }
    break;
  case 422: // LDMIA_RET_t2LDMIA_RET
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1544; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteP1TwoCycle
    }
    break;
  case 423: // tPOP_RET
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1544; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteP1TwoCycle
    }
    break;
  case 424: // tPOP
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1544; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteP1TwoCycle
    }
    break;
  case 426: // PICSTRB_PICSTRH_STRBi12_STRH
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getOperand(2).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(3).getImm()) == ARM_AM::sub
          ))
        return 1545; // A57Write_3cyc_1I_1S
      return 1546; // A57Write_1cyc_1S
    }
    break;
  case 427: // STRrs
    if (CPUID == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(3).getImm()) == 2
            )
          ))
        return 1545; // A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::sub)
        return 1545; // A57Write_3cyc_1I_1S
      return 1546; // A57Write_1cyc_1S
    }
    break;
  case 428: // STRBrs
    if (CPUID == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(3).getImm()) == 2
            )
          ))
        return 1545; // A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::sub)
        return 1545; // A57Write_3cyc_1I_1S
      return 1546; // A57Write_1cyc_1S
    }
    break;
  case 446: // STRD
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getOperand(3).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(4).getImm()) == ARM_AM::sub
          ))
        return 1545; // A57Write_3cyc_1I_1S
      return 1546; // A57Write_1cyc_1S
    }
    break;
  case 450: // STMDA_STMDB_STMIA_STMIB_sysSTMDA_sysSTMDB_sysSTMIA_sysSTMIB_t2STMDB_t2STMIA
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1546; // A57Write_1cyc_1S
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1577; // A57Write_2cyc_1S
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1578; // A57Write_3cyc_1S
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1579; // A57Write_4cyc_1S
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1580; // A57Write_5cyc_1S
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1581; // A57Write_6cyc_1S
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1582; // A57Write_7cyc_1S
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1583; // A57Write_8cyc_1S
      return 1577; // A57Write_2cyc_1S
    }
    if (CPUID == 9) { // CortexR52Model
      return 1562; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
    }
    if (CPUID == 10) { // SwiftModel
      return 1547; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 451: // STMDA_UPD_STMDB_UPD_STMIA_UPD_STMIB_UPD_sysSTMDA_UPD_sysSTMDB_UPD_sysSTMIA_UPD_sysSTMIB_UPD_t2STMDB_UPD_t2STMIA_UPD_tSTMIA_UPD
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
    }
    if (CPUID == 10) { // SwiftModel
      return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 452: // tPUSH
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
    }
    if (CPUID == 10) { // SwiftModel
      return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 518: // VCMPD_VCMPZD_VCMPED_VCMPEZD
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 519: // VCMPS_VCMPZS_VCMPES_VCMPEZS
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 536: // VMULslv2i32_VMULv2i32_VQDMULHslv2i32_VQDMULHv2i32_VQRDMULHslv2i32_VQRDMULHv2i32_VMULLsv2i64_VMULLuv2i64_VQDMULLv2i64
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 537: // VMULslv4i32_VMULv4i32_VQDMULHslv4i32_VQDMULHv4i32_VQRDMULHslv4i32_VQRDMULHv4i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1625; // A57Write_5cyc_1W
      return 1626; // A57Write_6cyc_1W
    }
    break;
  case 541: // VMLALslsv2i32_VMLALsluv2i32_VMLALsv2i64_VMLALuv2i64_VMLAslv2i32_VMLAv2i32_VMLSLslsv2i32_VMLSLsluv2i32_VMLSLsv2i64_VMLSLuv2i64_VMLSslv2i32_VMLSv2i32_VQDMLALslv2i32_VQDMLALv2i64_VQDMLSLslv2i32_VQDMLSLv2i64
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1627; // A57Write_4cyc_1W_anonymous_21079
      return 1628; // A57Write_5cyc_1W_anonymous_21081
    }
    break;
  case 542: // VMLALslsv4i16_VMLALsluv4i16_VMLALsv4i32_VMLALsv8i16_VMLALuv4i32_VMLALuv8i16_VMLAslv4i16_VMLAv4i16_VMLAv8i8_VMLSLslsv4i16_VMLSLsluv4i16_VMLSLsv4i32_VMLSLsv8i16_VMLSLuv4i32_VMLSLuv8i16_VMLSslv4i16_VMLSv4i16_VMLSv8i8_VQDMLALslv4i16_VQDMLALv4i32_VQDMLSLslv4i16_VQDMLSLv4i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1627; // A57Write_4cyc_1W_anonymous_21079
      return 1628; // A57Write_5cyc_1W_anonymous_21081
    }
    break;
  case 546: // VMLAslv4i32_VMLAv4i32_VMLSslv4i32_VMLSv4i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1629; // A57Write_5cyc_1W_anonymous_21074
      return 1630; // A57Write_6cyc_1W_anonymous_21076
    }
    break;
  case 547: // VMLAslv8i16_VMLAv16i8_VMLAv8i16_VMLSslv8i16_VMLSv16i8_VMLSv8i16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1629; // A57Write_5cyc_1W_anonymous_21074
      return 1630; // A57Write_6cyc_1W_anonymous_21076
    }
    break;
  case 594: // VLDMDIA_VLDMSIA
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1658; // A57Write_5cyc_1L_A57Write_6cyc_1L
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1659; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1660; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1661; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1662; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_13cyc_1L_A57Write_14cyc_1L
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1663; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_13cyc_1L_A57Write_14cyc_1L_A57Write_15cyc_1L_A57Write_16cyc_1L
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1664; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_13cyc_1L_A57Write_14cyc_1L_A57Write_15cyc_1L_A57Write_16cyc_1L_A57Write_17cyc_1L_A57Write_18cyc_1L
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1665; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_13cyc_1L_A57Write_14cyc_1L_A57Write_15cyc_1L_A57Write_16cyc_1L_A57Write_17cyc_1L_A57Write_18cyc_1L_A57Write_19cyc_1L_A57Write_20cyc_1L
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1666; // A57Write_5cyc_1L_A57Write_5cyc_1L
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1667; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1668; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1669; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1670; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1671; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1672; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_11cyc_1L
      return 1673; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_12cyc_1L
    }
    if (CPUID == 9) { // CortexR52Model
      return 1657; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52WriteLM10Cy_R52WriteLM11Cy_R52WriteLM12Cy_R52ReserveLd5Cy
    }
    if (CPUID == 10) { // SwiftModel
      return 1647; // SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM13Cy_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm2
    }
    break;
  case 595: // VLDMDDB_UPD_VLDMDIA_UPD_VLDMSDB_UPD_VLDMSIA_UPD
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1691; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1692; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1693; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1694; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1695; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_13cyc_1L_1I_A57Write_14cyc_1L_1I
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1696; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_13cyc_1L_1I_A57Write_14cyc_1L_1I_A57Write_15cyc_1L_1I_A57Write_16cyc_1L_1I
      if (ARM_MC::isPredicated(*MI, MCII)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1697; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_13cyc_1L_1I_A57Write_14cyc_1L_1I_A57Write_15cyc_1L_1I_A57Write_16cyc_1L_1I_A57Write_17cyc_1L_1I_A57Write_18cyc_1L_1I
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1698; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_13cyc_1L_1I_A57Write_14cyc_1L_1I_A57Write_15cyc_1L_1I_A57Write_16cyc_1L_1I_A57Write_17cyc_1L_1I_A57Write_18cyc_1L_1I_A57Write_19cyc_1L_1I_A57Write_20cyc_1L_1I
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1699; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1700; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1701; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1702; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1703; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1704; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1705; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      return 1706; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_12cyc_1L_1I
    }
    if (CPUID == 10) { // SwiftModel
      return 1690; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM13Cy_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm2
    }
    break;
  case 596: // VSTMDIA_VSTMSIA
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1577; // A57Write_2cyc_1S
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1579; // A57Write_4cyc_1S
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1581; // A57Write_6cyc_1S
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1583; // A57Write_8cyc_1S
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1708; // A57Write_10cyc_1S
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1709; // A57Write_12cyc_1S
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1710; // A57Write_14cyc_1S
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1711; // A57Write_16cyc_1S
      return 1579; // A57Write_4cyc_1S
    }
    if (CPUID == 10) { // SwiftModel
      return 1548; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 597: // VSTMDDB_UPD_VSTMDIA_UPD_VSTMSDB_UPD_VSTMSIA_UPD
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1722; // A57WrBackOne_A57Write_10cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1723; // A57WrBackOne_A57Write_12cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1724; // A57WrBackOne_A57Write_14cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1725; // A57WrBackOne_A57Write_16cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (CPUID == 10) { // SwiftModel
      return 1716; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 680: // t2MOVCCi_t2MOVCCi16
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 681: // t2MOVi_t2MOVi16
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 687: // MOVsr
    if (CPUID == 4) { // CortexA57Model
      if ((
            ARM_MC::isCPSRDefined(*MI, MCII)
            && ARM_MC::isPredicated(*MI, MCII)
          ))
        return 1380; // A57Write_2cyc_1I
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 688: // t2MOVSsr_t2MOVsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 689: // MOVTi16_ga_pcrel_MOVTi16_t2MOVTi16_ga_pcrel_t2MOVTi16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1339; // A57Write_1cyc_1I
      return 1382; // A57Write_2cyc_1M
    }
    break;
  case 690: // ADDSri_ADCri_ADDri_RSBSri_RSBri_RSCri_SBCri_t2ADDSri_t2ADCri_t2ADDri_t2ADDri12_t2RSBSri_t2RSBri_t2SBCri
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 691: // CLZ_t2CLZ
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 692: // t2ANDri_t2BICri_t2EORri_t2ORRri
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 695: // t2MVNr
    if (CPUID == 8) { // CortexM85Model
  return 1726; // M85NonsmallShiftWrite_M85Read_ISS
    }
    break;
  case 696: // t2MVNs
    if (CPUID == 4) { // CortexA57Model
      if ((
            ARM_MC::isCPSRDefined(*MI, MCII)
            && ARM_MC::isPredicated(*MI, MCII)
          ))
        return 1380; // A57Write_2cyc_1I
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    if (CPUID == 8) { // CortexM85Model
      return 1726; // M85NonsmallShiftWrite_M85Read_ISS
    }
    break;
  case 697: // ADDSrr_ADCrr_ADDrr_RSBrr_RSCrr_SBCrr_t2ADDSrr_t2ADCrr_t2ADDrr_t2SBCrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 699: // t2ANDrr_t2BICrr_t2EORrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 700: // ADDSrsi_ADCrsi_ADDrsi_RSBrsi_RSCrsi_SBCrsi
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 701: // t2ADDSrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC
          && ARM_MC::isPredicated(*MI, MCII))
        return 1334; // anonymous_20746_ReadDefault
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1335; // A57Write_2cyc_1M_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1356; // WriteALU_anonymous_20127
      return 1357; // WriteALU_NoReadAdvance
    }
    break;
  case 702: // t2ADCrs_t2ADDrs_t2SBCrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1728; // M85NonsmallShiftWrite_M85Read_ISS_M85Read_ISS
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1728; // M85NonsmallShiftWrite_M85Read_ISS_M85Read_ISS
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 703: // t2ANDrs_t2BICrs_t2EORrs_t2ORRrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 704: // t2RSBrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 705: // ADDSrsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1336; // SwiftWriteP0ThreeCycleThreeUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 706: // ADCrsr_ADDrsr_RSBrsr_RSCrsr_SBCrsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1367; // SwiftWriteP01ThreeCycleTwoUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 707: // ADR
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 709: // MVNsi
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 710: // t2MOVSsi_t2MOVsi
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 711: // ASRi_RORi
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 712: // ASRr_RORr_LSRi_LSRr_LSLi_LSLr
    if (CPUID == 4) { // CortexA57Model
      if ((
            ARM_MC::isCPSRDefined(*MI, MCII)
            && ARM_MC::isPredicated(*MI, MCII)
          ))
        return 1380; // A57Write_2cyc_1I
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 713: // LSRs1
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 716: // CMPrsi_CMNrsi
    if (CPUID == 10) { // SwiftModel
  return 1330; // SwiftWriteP01TwoCycle_ReadALU
    }
    break;
  case 717: // CMPrsr_CMNrsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1369; // A57Write_2cyc_1I_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    break;
  case 718: // t2LDC2L_OFFSET_t2LDC2L_OPTION_t2LDC2L_POST_t2LDC2L_PRE_t2LDC2_OFFSET_t2LDC2_OPTION_t2LDC2_POST_t2LDC2_PRE_t2LDCL_OFFSET_t2LDCL_OPTION_t2LDCL_POST_t2LDCL_PRE_t2LDC_OFFSET_t2LDC_OPTION_t2LDC_POST_t2LDC_PRE_RRXi
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 719: // RBIT_REV_REV16_REVSH
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 720: // RRX
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 723: // TSTrsi
    if (CPUID == 10) { // SwiftModel
  return 1330; // SwiftWriteP01TwoCycle_ReadALU
    }
    break;
  case 724: // TSTrsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1369; // A57Write_2cyc_1I_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    break;
  case 767: // VCMPEH_VCMPEZH_VCMPH_VCMPZH
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 786: // VQDMLALslv2i32_VQDMLALv2i64_VQDMLSLslv2i32_VQDMLSLv2i64
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 787: // VQDMLALslv4i16_VQDMLALv4i32_VQDMLSLslv4i16_VQDMLSLv4i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 788: // VQDMULHslv2i32_VQDMULHv2i32_VQDMULLv2i64_VQRDMULHslv2i32_VQRDMULHv2i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 789: // VQDMULHslv4i16_VQDMULHv4i16_VQDMULLslv2i32_VQDMULLslv4i16_VQDMULLv4i32_VQRDMULHslv4i16_VQRDMULHv4i16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 790: // VQDMULHslv4i32_VQDMULHv4i32_VQRDMULHslv4i32_VQRDMULHv4i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1625; // A57Write_5cyc_1W
      return 1626; // A57Write_6cyc_1W
    }
    break;
  case 791: // VQDMULHslv8i16_VQDMULHv8i16_VQRDMULHslv8i16_VQRDMULHv8i16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1625; // A57Write_5cyc_1W
      return 1626; // A57Write_6cyc_1W
    }
    break;
  case 871: // MOVCCsi
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 872: // t2ASRri_tASRri_t2LSRri_tLSRri_t2LSLri_tLSLri_t2RORri_t2RRX
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 873: // LSRi_LSLi
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 874: // t2MOVCCasr_t2MOVCClsl_t2MOVCClsr_t2MOVCCror
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 875: // t2MOVCCr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 876: // t2MOVTi16_ga_pcrel_t2MOVTi16
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 877: // t2MOVr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 878: // tROR
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 879: // t2ASRrr_tASRrr_t2LSRrr_tLSRrr_t2LSLrr_tLSLrr_t2RORrr
    if (CPUID == 4) { // CortexA57Model
      if ((
            ARM_MC::isCPSRDefined(*MI, MCII)
            && ARM_MC::isPredicated(*MI, MCII)
          ))
        return 1380; // A57Write_2cyc_1I
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 882: // SADD16_SADD8_SSUB16_SSUB8_UADD16_UADD8_USUB16_USUB8
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1733; // A57Write_4cyc_1I_1M
      return 1734; // A57Write_2cyc_1I_1M
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 883: // t2SADD16_t2SADD8_t2SSUB16_t2SSUB8_t2UADD16_t2UADD8_t2USUB16_t2USUB8
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1733; // A57Write_4cyc_1I_1M
      return 1734; // A57Write_2cyc_1I_1M
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 910: // LDR_PRE_REG
    if (CPUID == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1735; // A57Write_5cyc_1I_1L_A57WrBackTwo
      return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
    }
    break;
  case 911: // LDRB_PRE_REG
    if (CPUID == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1735; // A57Write_5cyc_1I_1L_A57WrBackTwo
      return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
    }
    break;
  case 912: // LDRH_PRE
    if (CPUID == 4) { // CortexA57Model
      if (!MI->getOperand(3).getReg().isValid())
        return 1736; // A57Write_4cyc_1L_A57WrBackTwo
      return 1737; // A57Write_4cyc_1L_A57WrBackOne
    }
    break;
  case 913: // LDRSB_PRE_LDRSH_PRE
    if (CPUID == 4) { // CortexA57Model
      if (!MI->getOperand(3).getReg().isValid())
        return 1736; // A57Write_4cyc_1L_A57WrBackTwo
      return 1737; // A57Write_4cyc_1L_A57WrBackOne
    }
    break;
  case 919: // LDRD_PRE
    if (CPUID == 4) { // CortexA57Model
      if (!MI->getOperand(4).getReg().isValid())
        return 1738; // A57Write_5cyc_1I_1L_A57Write_5cyc_1I_1L_A57WrBackTwo
      return 1440; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57WrBackOne
    }
    break;
  case 927: // LDRH_POST
    if (CPUID == 4) { // CortexA57Model
      if (!MI->getOperand(2).getReg().isValid())
        return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
      return 1739; // A57Write_4cyc_1L_1I_A57WrBackOne
    }
    break;
  case 928: // LDRSB_POST_LDRSH_POST
    if (CPUID == 4) { // CortexA57Model
      if (!MI->getOperand(2).getReg().isValid())
        return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
      return 1739; // A57Write_4cyc_1L_1I_A57WrBackOne
    }
    break;
  case 933: // PLDrs_PLDWrs
    if (CPUID == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(2).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(2).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(2).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(2).getImm()) == 2
            )
          ))
        return 1431; // A57Write_5cyc_1I_1L
      if (ARM_AM::getAM2Op(MI->getOperand(2).getImm()) == ARM_AM::sub)
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 945: // STR_PRE_REG
    if (CPUID == 4) { // CortexA57Model
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift
          && !(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::sub
          && !(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1741; // A57WrBackOne_A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift)
        return 1742; // A57WrBackTwo_A57Write_1cyc_1S_1M
      if (ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::sub)
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
    }
    break;
  case 946: // STRB_PRE_REG
    if (CPUID == 4) { // CortexA57Model
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift
          && !(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::sub
          && !(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1741; // A57WrBackOne_A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift)
        return 1742; // A57WrBackTwo_A57Write_1cyc_1S_1M
      if (ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::sub)
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
    }
    break;
  case 947: // STRD_PRE
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getOperand(4).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(5).getImm()) == ARM_AM::sub
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
    }
    break;
  case 967: // VSTMSIA
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1546; // A57Write_1cyc_1S
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1577; // A57Write_2cyc_1S
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1578; // A57Write_3cyc_1S
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1579; // A57Write_4cyc_1S
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1580; // A57Write_5cyc_1S
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1581; // A57Write_6cyc_1S
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1582; // A57Write_7cyc_1S
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1583; // A57Write_8cyc_1S
      return 1577; // A57Write_2cyc_1S
    }
    if (CPUID == 10) { // SwiftModel
      return 1548; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 968: // VSTMSDB_UPD_VSTMSIA_UPD
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (CPUID == 10) { // SwiftModel
      return 1716; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 972: // VMULpd_VMULv4i16_VMULv8i8_VMULslv4i16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 973: // VMULv2i32_VMULslv2i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 974: // VQDMULHslv2i32_VQDMULHv2i32_VQRDMULHslv2i32_VQRDMULHv2i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 975: // VQDMULHslv4i16_VQDMULHv4i16_VQRDMULHslv4i16_VQRDMULHv4i16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 976: // VMULpq_VMULv16i8_VMULv8i16_VMULslv8i16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1625; // A57Write_5cyc_1W
      return 1626; // A57Write_6cyc_1W
    }
    break;
  case 977: // VMLAslv2i32_VMLAv2i32_VMLSslv2i32_VMLSv2i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1743; // A57Write_4cyc_1W_anonymous_21069
      return 1744; // A57Write_5cyc_1W_anonymous_21071
    }
    break;
  case 978: // VMLAslv4i16_VMLAv4i16_VMLAv8i8_VMLSslv4i16_VMLSv4i16_VMLSv8i8
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1743; // A57Write_4cyc_1W_anonymous_21069
      return 1744; // A57Write_5cyc_1W_anonymous_21071
    }
    break;
  case 979: // VQRDMLAHslv2i32_VQRDMLAHv2i32_VQRDMLSHslv2i32_VQRDMLSHv2i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 980: // VQRDMLAHslv4i16_VQRDMLAHv4i16_VQRDMLSHslv4i16_VQRDMLSHv4i16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 981: // VQRDMLAHslv4i32_VQRDMLAHv4i32_VQRDMLSHslv4i32_VQRDMLSHv4i32
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 982: // VQRDMLAHslv8i16_VQRDMLAHv8i16_VQRDMLSHslv8i16_VQRDMLSHv8i16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 983: // VMULLp8_VMULLslsv2i32_VMULLslsv4i16_VMULLsluv2i32_VMULLsluv4i16_VMULLsv4i32_VMULLsv8i16_VMULLuv4i32_VMULLuv8i16
    if (CPUID == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 1014: // t2LDMIA_RET
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1544; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteP1TwoCycle
    }
    break;
  case 1015: // tLDMIA_UPD_t2LDMDB_UPD_t2LDMIA_UPD
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1504; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo
    }
    break;
  case 1016: // t2LDMDB_t2LDMIA_tLDMIA
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1473; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1474; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1475; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1476; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1477; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1478; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1479; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1481; // A57Write_3cyc_1L_A57Write_3cyc_1L
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1482; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1483; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1484; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1485; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1486; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1487; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
      return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
    }
    if (CPUID == 9) { // CortexR52Model
      return 1472; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1456; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLDMAddrNoWB
    }
    break;
  case 1023: // t2STMDB_t2STMIA
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1546; // A57Write_1cyc_1S
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1577; // A57Write_2cyc_1S
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1578; // A57Write_3cyc_1S
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1579; // A57Write_4cyc_1S
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1580; // A57Write_5cyc_1S
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1581; // A57Write_6cyc_1S
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1582; // A57Write_7cyc_1S
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1583; // A57Write_8cyc_1S
      return 1577; // A57Write_2cyc_1S
    }
    if (CPUID == 9) { // CortexR52Model
      return 1562; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
    }
    if (CPUID == 10) { // SwiftModel
      return 1547; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 1024: // t2STMDB_UPD_t2STMIA_UPD_tSTMIA_UPD
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
    }
    if (CPUID == 10) { // SwiftModel
      return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 1025: // tMOVSr_tMOVr
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1029: // t2SMLAL_t2SMLALBB_t2SMLALBT_t2SMLALD_t2SMLALDX_t2SMLALTB_t2SMLALTT_t2SMLSLD_t2SMLSLDX
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    break;
  case 1030: // t2REV_t2REV16_t2REVSH_tREV_tREV16_tREVSH
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1061: // t2ADDrr_t2ADDSrr_t2SBCrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 1062: // t2ASRri_t2LSLri_t2LSRri
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1063: // t2ASRrr_t2LSLrr_t2LSRrr_t2RORrr
    if (CPUID == 4) { // CortexA57Model
      if ((
            ARM_MC::isCPSRDefined(*MI, MCII)
            && ARM_MC::isPredicated(*MI, MCII)
          ))
        return 1380; // A57Write_2cyc_1I
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1064: // t2CMNrr
    if (CPUID == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1066: // t2CMPrr
    if (CPUID == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1067: // t2ORRrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1068: // t2REV_t2REV16_t2REVSH
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1069: // t2RSBri_t2RSBSri
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 1070: // t2RSBrr_t2SUBSrr_t2SUBrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 1071: // t2TEQrr_t2TSTrr
    if (CPUID == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1074: // t2STMIA_UPD_t2STMDB_UPD
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
    }
    if (CPUID == 10) { // SwiftModel
      return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 1076: // tADC_tADDhirr_tADDrSP_tADDrr_tADDspr_tPICADD_tSBC_tSUBrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1077: // tADDrSPi_tADDspi_tADR_tRSB_tSUBspi
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1078: // tAND_tBIC_tEOR_tORR
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1079: // tASRri_tLSLri_tLSRri
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1088: // tTST
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1094: // t2MOVSsi
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1095: // t2MOVSsr
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1097: // t2SMMLA_t2SMMLAR_t2SMMLS_t2SMMLSR
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 1105: // t2LDMDB_t2LDMIA
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1473; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1474; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1475; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1476; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1477; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1478; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1479; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1481; // A57Write_3cyc_1L_A57Write_3cyc_1L
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1482; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1483; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1484; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1485; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1486; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1487; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
      return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
    }
    if (CPUID == 9) { // CortexR52Model
      return 1472; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1456; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLDMAddrNoWB
    }
    break;
  case 1106: // t2LDMDB_UPD_t2LDMIA_UPD
    if (CPUID == 2) { // CortexA9Model
    }
    if (CPUID == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (CPUID == 9) { // CortexR52Model
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1504; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo
    }
    break;
  case 1107: // tADDi3_tADDi8_tSUBi3_tSUBi8
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1108: // t2ADDSri_t2ADDri
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 1109: // t2SUBSri_t2SUBri
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 1234: // t2RSBSrs_t2SUBrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1728; // M85NonsmallShiftWrite_M85Read_ISS_M85Read_ISS
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1728; // M85NonsmallShiftWrite_M85Read_ISS_M85Read_ISS
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1235: // t2SUBSrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC
          && ARM_MC::isPredicated(*MI, MCII))
        return 1334; // anonymous_20746_ReadDefault
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1335; // A57Write_2cyc_1M_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1356; // WriteALU_anonymous_20127
      return 1357; // WriteALU_NoReadAdvance
    }
    break;
  case 1236: // t2BICrs_t2EORrs_t2ORRrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1237: // t2ORNrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1238: // t2CMNrs
    if (CPUID == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
  return 1423; // SwiftWriteP01TwoCycle_ReadALU_ReadALU
    }
    break;
  case 1239: // t2CMPrs
    if (CPUID == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
  return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 1240: // t2TEQrs_t2TSTrs
    if (CPUID == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
  return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 1241: // t2ASRs1_t2LSRs1
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1242: // t2RRX
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isCPSRDefined(*MI, MCII))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1243: // t2CLZ
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1245: // t2RBIT
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1246: // t2PKHBT_t2PKHTB
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1254: // VCMPS
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 1255: // VCMPD
    if (CPUID == 4) { // CortexA57Model
      if (ARM_MC::isPredicated(*MI, MCII))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 1265: // t2RSBSrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1266: // t2ADCrs_t2SBCrs
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (CPUID == 10) { // SwiftModel
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1267: // t2ADDSrr_t2SBCrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1268: // t2SUBSrr_t2RSBrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1269: // t2ADCrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1270: // t2BICrr_t2EORrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1271: // t2ORNrr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1272: // tLSLSri
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1273: // tADDspi_tSUBspi
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1274: // t2ADDri
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1275: // t2ADDri12
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1276: // t2SUBri
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1277: // t2SUBri12
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1278: // tADDrSP_tADDspr_tADDhirr
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1745; // WriteALU_M85Read_ISS_M85Read_ISS
      return 1746; // WriteALU_M85Read_EX1_M85Read_EX1
    }
    break;
  case 1279: // tADDrSPi
    if (CPUID == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    if (CPUID == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1745; // WriteALU_M85Read_ISS_M85Read_ISS
      return 1746; // WriteALU_M85Read_EX1_M85Read_EX1
    }
    break;
  case 1291: // VMRS
    if (CPUID == 8) { // CortexM85Model
      if ((
            MI->getOperand(0).isReg() 
            && MI->getOperand(0).getReg() == ARM::PC
          ))
        return 1747; // M85VMRSEarly
      return 1748; // M85VMRSLate
    }
    break;
  };
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace ARM_MC
struct ARMGenMCSubtargetInfo : public MCSubtargetInfo {
  ARMGenMCSubtargetInfo(const Triple &TT,
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
    return ARM_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned ARMGenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (false) Modes |= (1 << 0);
  return Modes;
}
unsigned ARMGenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
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

static inline MCSubtargetInfo *createARMMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new ARMGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(ARMSubTypeKVStorage.Strings), ARMFeatureKVStorage.Features, ARMSubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::ARMSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
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
  if (Bits[ARM::ARMv7ve] && ARMArch < ARMv7ve) ARMArch = ARMv7ve;
  if (Bits[ARM::ARMv8a] && ARMArch < ARMv8a) ARMArch = ARMv8a;
  if (Bits[ARM::ARMv8mBaseline] && ARMArch < ARMv8mBaseline) ARMArch = ARMv8mBaseline;
  if (Bits[ARM::ARMv8mMainline] && ARMArch < ARMv8mMainline) ARMArch = ARMv8mMainline;
  if (Bits[ARM::ARMv8r] && ARMArch < ARMv8r) ARMArch = ARMv8r;
  if (Bits[ARM::ARMv9a] && ARMArch < ARMv9a) ARMArch = ARMv9a;
  if (Bits[ARM::ARMv81a] && ARMArch < ARMv81a) ARMArch = ARMv81a;
  if (Bits[ARM::ARMv81mMainline] && ARMArch < ARMv81mMainline) ARMArch = ARMv81mMainline;
  if (Bits[ARM::ARMv82a] && ARMArch < ARMv82a) ARMArch = ARMv82a;
  if (Bits[ARM::ARMv83a] && ARMArch < ARMv83a) ARMArch = ARMv83a;
  if (Bits[ARM::ARMv84a] && ARMArch < ARMv84a) ARMArch = ARMv84a;
  if (Bits[ARM::ARMv85a] && ARMArch < ARMv85a) ARMArch = ARMv85a;
  if (Bits[ARM::ARMv86a] && ARMArch < ARMv86a) ARMArch = ARMv86a;
  if (Bits[ARM::ARMv87a] && ARMArch < ARMv87a) ARMArch = ARMv87a;
  if (Bits[ARM::ARMv88a] && ARMArch < ARMv88a) ARMArch = ARMv88a;
  if (Bits[ARM::ARMv89a] && ARMArch < ARMv89a) ARMArch = ARMv89a;
  if (Bits[ARM::ARMv91a] && ARMArch < ARMv91a) ARMArch = ARMv91a;
  if (Bits[ARM::ARMv92a] && ARMArch < ARMv92a) ARMArch = ARMv92a;
  if (Bits[ARM::ARMv93a] && ARMArch < ARMv93a) ARMArch = ARMv93a;
  if (Bits[ARM::ARMv94a] && ARMArch < ARMv94a) ARMArch = ARMv94a;
  if (Bits[ARM::ARMv95a] && ARMArch < ARMv95a) ARMArch = ARMv95a;
  if (Bits[ARM::ARMv96a] && ARMArch < ARMv96a) ARMArch = ARMv96a;
  if (Bits[ARM::ARMv97a] && ARMArch < ARMv97a) ARMArch = ARMv97a;
  if (Bits[ARM::Feature8MSecExt]) Has8MSecExt = true;
  if (Bits[ARM::FeatureAAPCSFrameChain]) CreateAAPCSFrameChain = true;
  if (Bits[ARM::FeatureAClass] && ARMProcClass < AClass) ARMProcClass = AClass;
  if (Bits[ARM::FeatureAES]) HasAES = true;
  if (Bits[ARM::FeatureAcquireRelease]) HasAcquireRelease = true;
  if (Bits[ARM::FeatureAtomics32]) HasForced32BitAtomics = true;
  if (Bits[ARM::FeatureAvoidMOVsShOp]) AvoidMOVsShifterOperand = true;
  if (Bits[ARM::FeatureAvoidMULS]) AvoidMULS = true;
  if (Bits[ARM::FeatureAvoidPartialCPSR]) AvoidCPSRPartialUpdate = true;
  if (Bits[ARM::FeatureBF16]) HasBF16 = true;
  if (Bits[ARM::FeatureCLRBHB]) HasCLRBHB = true;
  if (Bits[ARM::FeatureCRC]) HasCRC = true;
  if (Bits[ARM::FeatureCheapPredicableCPSR]) CheapPredicableCPSRDef = true;
  if (Bits[ARM::FeatureCheckVLDnAlign]) CheckVLDnAccessAlignment = true;
  if (Bits[ARM::FeatureCoprocCDE0]) CoprocCDE[0] = true;
  if (Bits[ARM::FeatureCoprocCDE1]) CoprocCDE[1] = true;
  if (Bits[ARM::FeatureCoprocCDE2]) CoprocCDE[2] = true;
  if (Bits[ARM::FeatureCoprocCDE3]) CoprocCDE[3] = true;
  if (Bits[ARM::FeatureCoprocCDE4]) CoprocCDE[4] = true;
  if (Bits[ARM::FeatureCoprocCDE5]) CoprocCDE[5] = true;
  if (Bits[ARM::FeatureCoprocCDE6]) CoprocCDE[6] = true;
  if (Bits[ARM::FeatureCoprocCDE7]) CoprocCDE[7] = true;
  if (Bits[ARM::FeatureCrypto]) HasCrypto = true;
  if (Bits[ARM::FeatureD32]) HasD32 = true;
  if (Bits[ARM::FeatureDB]) HasDataBarrier = true;
  if (Bits[ARM::FeatureDFB]) HasFullDataBarrier = true;
  if (Bits[ARM::FeatureDSP]) HasDSP = true;
  if (Bits[ARM::FeatureDontWidenVMOVS]) DontWidenVMOVS = true;
  if (Bits[ARM::FeatureDotProd]) HasDotProd = true;
  if (Bits[ARM::FeatureExecuteOnly]) GenExecuteOnly = true;
  if (Bits[ARM::FeatureExpandMLx]) ExpandMLx = true;
  if (Bits[ARM::FeatureFP16]) HasFP16 = true;
  if (Bits[ARM::FeatureFP16FML]) HasFP16FML = true;
  if (Bits[ARM::FeatureFP64]) HasFP64 = true;
  if (Bits[ARM::FeatureFPAO]) HasFPAO = true;
  if (Bits[ARM::FeatureFPARMv8]) HasFPARMv8 = true;
  if (Bits[ARM::FeatureFPARMv8_D16]) HasFPARMv8D16 = true;
  if (Bits[ARM::FeatureFPARMv8_D16_SP]) HasFPARMv8D16SP = true;
  if (Bits[ARM::FeatureFPARMv8_SP]) HasFPARMv8SP = true;
  if (Bits[ARM::FeatureFPRegs]) HasFPRegs = true;
  if (Bits[ARM::FeatureFPRegs16]) HasFPRegs16 = true;
  if (Bits[ARM::FeatureFPRegs64]) HasFPRegs64 = true;
  if (Bits[ARM::FeatureFixCMSE_CVE_2021_35465]) FixCMSE_CVE_2021_35465 = true;
  if (Bits[ARM::FeatureFixCortexA57AES1742098]) FixCortexA57AES1742098 = true;
  if (Bits[ARM::FeatureFullFP16]) HasFullFP16 = true;
  if (Bits[ARM::FeatureFuseAES]) HasFuseAES = true;
  if (Bits[ARM::FeatureFuseLiterals]) HasFuseLiterals = true;
  if (Bits[ARM::FeatureHWDivARM]) HasDivideInARMMode = true;
  if (Bits[ARM::FeatureHWDivThumb]) HasDivideInThumbMode = true;
  if (Bits[ARM::FeatureHardenSlsBlr]) HardenSlsBlr = true;
  if (Bits[ARM::FeatureHardenSlsNoComdat]) HardenSlsNoComdat = true;
  if (Bits[ARM::FeatureHardenSlsRetBr]) HardenSlsRetBr = true;
  if (Bits[ARM::FeatureHasNoBranchPredictor]) HasBranchPredictor = false;
  if (Bits[ARM::FeatureHasRetAddrStack]) HasRetAddrStack = true;
  if (Bits[ARM::FeatureHasSlowFPVFMx]) SlowFPVFMx = true;
  if (Bits[ARM::FeatureHasSlowFPVMLx]) SlowFPVMLx = true;
  if (Bits[ARM::FeatureHasVMLxHazards]) HasVMLxHazards = true;
  if (Bits[ARM::FeatureLOB]) HasLOB = true;
  if (Bits[ARM::FeatureLongCalls]) GenLongCalls = true;
  if (Bits[ARM::FeatureMClass] && ARMProcClass < MClass) ARMProcClass = MClass;
  if (Bits[ARM::FeatureMP]) HasMPExtension = true;
  if (Bits[ARM::FeatureMVEVectorCostFactor1] && MVEVectorCostFactor < 4) MVEVectorCostFactor = 4;
  if (Bits[ARM::FeatureMVEVectorCostFactor2] && MVEVectorCostFactor < 2) MVEVectorCostFactor = 2;
  if (Bits[ARM::FeatureMVEVectorCostFactor4] && MVEVectorCostFactor < 1) MVEVectorCostFactor = 1;
  if (Bits[ARM::FeatureMatMulInt8]) HasMatMulInt8 = true;
  if (Bits[ARM::FeatureMuxedUnits]) HasMuxedUnits = true;
  if (Bits[ARM::FeatureNEON]) HasNEON = true;
  if (Bits[ARM::FeatureNEONForFP]) HasNEONForFP = true;
  if (Bits[ARM::FeatureNEONForFPMovs]) UseNEONForFPMovs = true;
  if (Bits[ARM::FeatureNoARM]) NoARM = true;
  if (Bits[ARM::FeatureNoBTIAtReturnTwice]) NoBTIAtReturnTwice = true;
  if (Bits[ARM::FeatureNoMovt]) NoMovt = true;
  if (Bits[ARM::FeatureNoNegativeImmediates]) NegativeImmediates = false;
  if (Bits[ARM::FeatureNoPostRASched]) DisablePostRAScheduler = true;
  if (Bits[ARM::FeatureNonpipelinedVFP]) NonpipelinedVFP = true;
  if (Bits[ARM::FeaturePACBTI]) HasPACBTI = true;
  if (Bits[ARM::FeaturePerfMon]) HasPerfMon = true;
  if (Bits[ARM::FeaturePref32BitThumb]) Prefers32BitThumb = true;
  if (Bits[ARM::FeaturePrefISHSTBarrier]) PreferISHSTBarriers = true;
  if (Bits[ARM::FeaturePreferBranchAlign32] && PreferBranchLogAlignment < 2) PreferBranchLogAlignment = 2;
  if (Bits[ARM::FeaturePreferBranchAlign64] && PreferBranchLogAlignment < 3) PreferBranchLogAlignment = 3;
  if (Bits[ARM::FeaturePreferVMOVSR]) PreferVMOVSR = true;
  if (Bits[ARM::FeatureProfUnpredicate]) IsProfitableToUnpredicate = true;
  if (Bits[ARM::FeatureRAS]) HasRAS = true;
  if (Bits[ARM::FeatureRClass] && ARMProcClass < RClass) ARMProcClass = RClass;
  if (Bits[ARM::FeatureReadTpTPIDRPRW]) IsReadTPTPIDRPRW = true;
  if (Bits[ARM::FeatureReadTpTPIDRURO]) IsReadTPTPIDRURO = true;
  if (Bits[ARM::FeatureReadTpTPIDRURW]) IsReadTPTPIDRURW = true;
  if (Bits[ARM::FeatureReserveR9]) ReserveR9 = true;
  if (Bits[ARM::FeatureSB]) HasSB = true;
  if (Bits[ARM::FeatureSHA2]) HasSHA2 = true;
  if (Bits[ARM::FeatureSlowFPBrcc]) IsFPBrccSlow = true;
  if (Bits[ARM::FeatureSlowLoadDSubreg]) HasSlowLoadDSubregister = true;
  if (Bits[ARM::FeatureSlowOddRegister]) HasSlowOddRegister = true;
  if (Bits[ARM::FeatureSlowVDUP32]) HasSlowVDUP32 = true;
  if (Bits[ARM::FeatureSlowVGETLNi32]) HasSlowVGETLNi32 = true;
  if (Bits[ARM::FeatureSplatVFPToNeon]) UseSplatVFPToNeon = true;
  if (Bits[ARM::FeatureStrictAlign]) StrictAlign = true;
  if (Bits[ARM::FeatureThumb2]) HasThumb2 = true;
  if (Bits[ARM::FeatureTrustZone]) HasTrustZone = true;
  if (Bits[ARM::FeatureUseMIPipeliner]) UseMIPipeliner = true;
  if (Bits[ARM::FeatureUseMISched]) UseMISched = true;
  if (Bits[ARM::FeatureUseWideStrideVFP]) UseWideStrideVFP = true;
  if (Bits[ARM::FeatureV7Clrex]) HasV7Clrex = true;
  if (Bits[ARM::FeatureVFP2]) HasVFPv2 = true;
  if (Bits[ARM::FeatureVFP2_SP]) HasVFPv2SP = true;
  if (Bits[ARM::FeatureVFP3]) HasVFPv3 = true;
  if (Bits[ARM::FeatureVFP3_D16]) HasVFPv3D16 = true;
  if (Bits[ARM::FeatureVFP3_D16_SP]) HasVFPv3D16SP = true;
  if (Bits[ARM::FeatureVFP3_SP]) HasVFPv3SP = true;
  if (Bits[ARM::FeatureVFP4]) HasVFPv4 = true;
  if (Bits[ARM::FeatureVFP4_D16]) HasVFPv4D16 = true;
  if (Bits[ARM::FeatureVFP4_D16_SP]) HasVFPv4D16SP = true;
  if (Bits[ARM::FeatureVFP4_SP]) HasVFPv4SP = true;
  if (Bits[ARM::FeatureVMLxForwarding]) HasVMLxForwarding = true;
  if (Bits[ARM::FeatureVirtualization]) HasVirtualization = true;
  if (Bits[ARM::FeatureZCZeroing]) HasZeroCycleZeroing = true;
  if (Bits[ARM::HasCDEOps]) HasCDEOps = true;
  if (Bits[ARM::HasMVEFloatOps]) HasMVEFloatOps = true;
  if (Bits[ARM::HasMVEIntegerOps]) HasMVEIntegerOps = true;
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
  if (Bits[ARM::HasV8_1MMainlineOps]) HasV8_1MMainlineOps = true;
  if (Bits[ARM::HasV8_1aOps]) HasV8_1aOps = true;
  if (Bits[ARM::HasV8_2aOps]) HasV8_2aOps = true;
  if (Bits[ARM::HasV8_3aOps]) HasV8_3aOps = true;
  if (Bits[ARM::HasV8_4aOps]) HasV8_4aOps = true;
  if (Bits[ARM::HasV8_5aOps]) HasV8_5aOps = true;
  if (Bits[ARM::HasV8_6aOps]) HasV8_6aOps = true;
  if (Bits[ARM::HasV8_7aOps]) HasV8_7aOps = true;
  if (Bits[ARM::HasV8_8aOps]) HasV8_8aOps = true;
  if (Bits[ARM::HasV8_9aOps]) HasV8_9aOps = true;
  if (Bits[ARM::HasV9_0aOps]) HasV9_0aOps = true;
  if (Bits[ARM::HasV9_1aOps]) HasV9_1aOps = true;
  if (Bits[ARM::HasV9_2aOps]) HasV9_2aOps = true;
  if (Bits[ARM::HasV9_3aOps]) HasV9_3aOps = true;
  if (Bits[ARM::HasV9_4aOps]) HasV9_4aOps = true;
  if (Bits[ARM::HasV9_5aOps]) HasV9_5aOps = true;
  if (Bits[ARM::HasV9_6aOps]) HasV9_6aOps = true;
  if (Bits[ARM::HasV9_7aOps]) HasV9_7aOps = true;
  if (Bits[ARM::IWMMXT] && ARMArch < ARMv5te) ARMArch = ARMv5te;
  if (Bits[ARM::IWMMXT2] && ARMArch < ARMv5te) ARMArch = ARMv5te;
  if (Bits[ARM::ModeBigEndianInstructions]) BigEndianInstructions = true;
  if (Bits[ARM::ModeSoftFloat]) UseSoftFloat = true;
  if (Bits[ARM::ModeThumb]) IsThumb = true;
  if (Bits[ARM::ProcA5] && ARMProcFamily < CortexA5) ARMProcFamily = CortexA5;
  if (Bits[ARM::ProcA7] && ARMProcFamily < CortexA7) ARMProcFamily = CortexA7;
  if (Bits[ARM::ProcA8] && ARMProcFamily < CortexA8) ARMProcFamily = CortexA8;
  if (Bits[ARM::ProcA9] && ARMProcFamily < CortexA9) ARMProcFamily = CortexA9;
  if (Bits[ARM::ProcA12] && ARMProcFamily < CortexA12) ARMProcFamily = CortexA12;
  if (Bits[ARM::ProcA15] && ARMProcFamily < CortexA15) ARMProcFamily = CortexA15;
  if (Bits[ARM::ProcA17] && ARMProcFamily < CortexA17) ARMProcFamily = CortexA17;
  if (Bits[ARM::ProcA32] && ARMProcFamily < CortexA32) ARMProcFamily = CortexA32;
  if (Bits[ARM::ProcA35] && ARMProcFamily < CortexA35) ARMProcFamily = CortexA35;
  if (Bits[ARM::ProcA53] && ARMProcFamily < CortexA53) ARMProcFamily = CortexA53;
  if (Bits[ARM::ProcA55] && ARMProcFamily < CortexA55) ARMProcFamily = CortexA55;
  if (Bits[ARM::ProcA57] && ARMProcFamily < CortexA57) ARMProcFamily = CortexA57;
  if (Bits[ARM::ProcA72] && ARMProcFamily < CortexA72) ARMProcFamily = CortexA72;
  if (Bits[ARM::ProcA73] && ARMProcFamily < CortexA73) ARMProcFamily = CortexA73;
  if (Bits[ARM::ProcA75] && ARMProcFamily < CortexA75) ARMProcFamily = CortexA75;
  if (Bits[ARM::ProcA76] && ARMProcFamily < CortexA76) ARMProcFamily = CortexA76;
  if (Bits[ARM::ProcA77] && ARMProcFamily < CortexA77) ARMProcFamily = CortexA77;
  if (Bits[ARM::ProcA78] && ARMProcFamily < CortexA78) ARMProcFamily = CortexA78;
  if (Bits[ARM::ProcA78AE] && ARMProcFamily < CortexA78AE) ARMProcFamily = CortexA78AE;
  if (Bits[ARM::ProcA78C] && ARMProcFamily < CortexA78C) ARMProcFamily = CortexA78C;
  if (Bits[ARM::ProcA510] && ARMProcFamily < CortexA510) ARMProcFamily = CortexA510;
  if (Bits[ARM::ProcA710] && ARMProcFamily < CortexA710) ARMProcFamily = CortexA710;
  if (Bits[ARM::ProcExynos] && ARMProcFamily < Exynos) ARMProcFamily = Exynos;
  if (Bits[ARM::ProcKrait] && ARMProcFamily < Krait) ARMProcFamily = Krait;
  if (Bits[ARM::ProcKryo] && ARMProcFamily < Kryo) ARMProcFamily = Kryo;
  if (Bits[ARM::ProcM3] && ARMProcFamily < CortexM3) ARMProcFamily = CortexM3;
  if (Bits[ARM::ProcM7] && ARMProcFamily < CortexM7) ARMProcFamily = CortexM7;
  if (Bits[ARM::ProcM55] && ARMProcFamily < CortexM55) ARMProcFamily = CortexM55;
  if (Bits[ARM::ProcM85] && ARMProcFamily < CortexM85) ARMProcFamily = CortexM85;
  if (Bits[ARM::ProcR4] && ARMProcFamily < CortexR4) ARMProcFamily = CortexR4;
  if (Bits[ARM::ProcR5] && ARMProcFamily < CortexR5) ARMProcFamily = CortexR5;
  if (Bits[ARM::ProcR7] && ARMProcFamily < CortexR7) ARMProcFamily = CortexR7;
  if (Bits[ARM::ProcR52] && ARMProcFamily < CortexR52) ARMProcFamily = CortexR52;
  if (Bits[ARM::ProcR52plus] && ARMProcFamily < CortexR52plus) ARMProcFamily = CortexR52plus;
  if (Bits[ARM::ProcSwift] && ARMProcFamily < Swift) ARMProcFamily = Swift;
  if (Bits[ARM::ProcV1] && ARMProcFamily < NeoverseV1) ARMProcFamily = NeoverseV1;
  if (Bits[ARM::ProcX1] && ARMProcFamily < CortexX1) ARMProcFamily = CortexX1;
  if (Bits[ARM::ProcX1C] && ARMProcFamily < CortexX1C) ARMProcFamily = CortexX1C;
  if (Bits[ARM::XScale] && ARMArch < ARMv5te) ARMArch = ARMv5te;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace ARM_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace ARM_MC
struct ARMGenSubtargetInfo : public TargetSubtargetInfo {
  explicit ARMGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class ARMHwModeBits : unsigned {
    DefaultMode = 0,
    Thumb1OnlyMode = (1 << 0),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/Thumb1OnlyMode),
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

extern const llvm_ks::StringRef ARMNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<234, 9733> ARMFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<96, 964> ARMSubTypeKVStorage;
extern const llvm_ks::MCSchedModel ARMSchedModels[];
extern const llvm_ks::MCWriteProcResEntry ARMWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry ARMWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry ARMReadAdvanceTable[];
extern const llvm_ks::InstrStage ARMStages[];
extern const unsigned ARMOperandCycles[];
extern const unsigned ARMForwardingPaths[];
ARMGenSubtargetInfo::ARMGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(ARMSubTypeKVStorage.Strings), ArrayRef(ARMFeatureKVStorage.Features), ArrayRef(ARMSubTypeKVStorage.SubTypes), ARMSchedModels, 
                        ARMWriteProcResTable, ARMWriteLatencyTable, ARMReadAdvanceTable, 
                        ARMStages, ARMOperandCycles, ARMForwardingPaths) {}

unsigned ARMGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {

  const ARMBaseInstrInfo *TII =
    static_cast<const ARMBaseInstrInfo*>(SchedModel->getInstrInfo());
  (void)TII;
  const ARMSubtarget *STI =
    static_cast<const ARMSubtarget*>(SchedModel->getSubtargetInfo());
  (void)STI;

  switch (SchedClass) {
  case 1: // IIC_iALUi_WriteALU_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 2: // IIC_iALUr_WriteALU_ReadALU_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 3: // IIC_iALUsr_WriteALUsi_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 4: // IIC_iALUsr_WriteALUSsr_ReadALUsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (TII->isPredicated(*MI))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1336; // SwiftWriteP0ThreeCycleThreeUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 5: // IIC_iMOVsi_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 9: // IIC_iLoad_mBr
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1340; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1341; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1342; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1343; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1344; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1345; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1346; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1347; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1348; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
    }
    break;
  case 13: // IIC_iMAC32_WriteMAC32_ReadMUL_ReadMUL_ReadMAC
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1349; // SwiftWriteP0P01FiveCycleTwoUops_ReadMUL_ReadMUL_anonymous_20158
      return 1350; // SwiftWriteP0FourCycle_ReadMUL_ReadMUL_ReadALU
    }
    break;
  case 14: // IIC_iCMOVi_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 15: // IIC_iMOVi_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 17: // IIC_iCMOVr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 18: // IIC_iCMOVsr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 23: // IIC_iALUr_WriteALU_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 28: // IIC_iMAC64_WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1353; // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_anonymous_20158_anonymous_20158
      return 1354; // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_ReadALU_ReadALU
    }
    break;
  case 37: // IIC_iALUsi_WriteALUsi_ReadALUsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC
          && TII->isPredicated(*MI))
        return 1334; // anonymous_20746_ReadDefault
      if (TII->isPredicated(*MI))
        return 1335; // A57Write_2cyc_1M_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if ((TII->isSwiftFastImmShift(MI))
          && TII->isPredicated(*MI))
        return 1355; // SwiftWriteP01TwoCycle_anonymous_20127
      if (TII->isPredicated(*MI))
        return 1356; // WriteALU_anonymous_20127
      if (TII->isSwiftFastImmShift(MI))
        return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
      return 1357; // WriteALU_NoReadAdvance
    }
    break;
  case 38: // IIC_iCMOVsi_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 39: // IIC_iALUsi_WriteALUsi_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 41: // IIC_iALUr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 42: // IIC_iALUi_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 43: // IIC_iLoad_mu
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    break;
  case 44: // IIC_iPop_Br_WriteBrL
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1340; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1341; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1342; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1343; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1344; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1345; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1346; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1347; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1348; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
    }
    break;
  case 45: // IIC_iALUsr_WriteALUsr_ReadALUsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (TII->isPredicated(*MI))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1367; // SwiftWriteP01ThreeCycleTwoUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 46: // IIC_iBITi_WriteALU_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 47: // IIC_iBITr_WriteALU_ReadALU_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 48: // IIC_iBITsr_WriteALUsi_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 49: // IIC_iBITsr_WriteALUsr_ReadALUsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (TII->isPredicated(*MI))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1367; // SwiftWriteP01ThreeCycleTwoUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 54: // IIC_iUNAr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 57: // IIC_iCMPsr_WriteCMPsi_ReadALU
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1368; // SwiftWriteP01OneCycle_ReadALU
      return 1330; // SwiftWriteP01TwoCycle_ReadALU
    }
    break;
  case 58: // IIC_iCMPsr_WriteCMPsr_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1369; // A57Write_2cyc_1I_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    break;
  case 60: // IIC_iLoad_m
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1370; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1371; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1372; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1373; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1374; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1375; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1376; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1377; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1378; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
    }
    break;
  case 68: // IIC_iMOVr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 69: // IIC_iMOVsr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 70: // IIC_iMVNi_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 71: // IIC_iMVNr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 72: // IIC_iMVNsr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 73: // IIC_iBITsi_WriteALUsi_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 76: // IIC_iMAC16_WriteMAC16_ReadMUL_ReadMUL_ReadMAC
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1349; // SwiftWriteP0P01FiveCycleTwoUops_ReadMUL_ReadMUL_anonymous_20158
      return 1350; // SwiftWriteP0FourCycle_ReadMUL_ReadMUL_ReadALU
    }
    break;
  case 77: // WriteMAC32_ReadMUL_ReadMUL_ReadMAC
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1349; // SwiftWriteP0P01FiveCycleTwoUops_ReadMUL_ReadMUL_anonymous_20158
      return 1350; // SwiftWriteP0FourCycle_ReadMUL_ReadMUL_ReadALU
    }
    break;
  case 78: // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1353; // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_anonymous_20158_anonymous_20158
      return 1354; // WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL_ReadALU_ReadALU
    }
    break;
  case 82: // IIC_iStore_m
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    break;
  case 83: // IIC_iStore_mu
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    break;
  case 90: // IIC_iEXTAr_WriteALUsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1379; // anonymous_20739
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1381; // anonymous_20746
      return 1382; // A57Write_2cyc_1M
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 91: // IIC_iEXTr_WriteALUsi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1381; // anonymous_20746
      return 1382; // A57Write_2cyc_1M
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1384; // SwiftWriteP01TwoCycle
      return 1385; // WriteALU
    }
    break;
  case 94: // IIC_iTSTsr_WriteCMPsi_ReadALU
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1368; // SwiftWriteP01OneCycle_ReadALU
      return 1330; // SwiftWriteP01TwoCycle_ReadALU
    }
    break;
  case 95: // IIC_iTSTsr_WriteCMPsr_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1369; // A57Write_2cyc_1I_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    break;
  case 96: // IIC_iMUL64_WriteMAC64Lo_WriteMAC64Hi_ReadMUL_ReadMUL
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1386; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL
      return 1387; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL
    }
    break;
  case 97: // WriteALU_ReadALU_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 183: // IIC_fpLoad_mu
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1388; // A9WriteAdr_(A9WriteIssue_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1389; // (A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1390; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1391; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1392; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1393; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1394; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1395; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if ((TII->getNumLDMAddresses(*MI) == 0)
          && (MI->getOperand(0).getReg().isVirtual())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1389; // (A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1396; // A9WriteAdr_A9WriteLMfp1_A9WriteL1Hi
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1397; // (A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1398; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1399; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1400; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1401; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1402; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1403; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if ((TII->getNumLDMAddresses(*MI) == 0)
          && (MI->getOperand(0).getReg().isPhysical())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1404; // (A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
    }
    break;
  case 184: // IIC_fpLoad_m
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1405; // (A9WriteIssue_A9WriteLfpOp)_A9WriteAdr
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1406; // A9WriteLMfp1_A9WriteL1Hi_A9WriteAdr
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1407; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1408; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1409; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1410; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1411; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1412; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1413; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1407; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1414; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1415; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1416; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1417; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1418; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1419; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1420; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1421; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)
    }
    break;
  case 278: // IIC_iUNAsi_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 279: // IIC_iBITi_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 280: // IIC_iCMPsi_WriteCMPsi_ReadALU_ReadALU
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1422; // SwiftWriteP01OneCycle_ReadALU_ReadALU
      return 1423; // SwiftWriteP01TwoCycle_ReadALU_ReadALU
    }
    break;
  case 283: // IIC_iCMPsi_WriteCMPsi
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1424; // SwiftWriteP01OneCycle
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 294: // IIC_iMVNsi_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 295: // IIC_iALUsir_WriteALUsi_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 296: // IIC_iMUL16_WriteMAC16_ReadMUL_ReadMUL_ReadMAC
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1349; // SwiftWriteP0P01FiveCycleTwoUops_ReadMUL_ReadMUL_anonymous_20158
      return 1350; // SwiftWriteP0FourCycle_ReadMUL_ReadMUL_ReadALU
    }
    break;
  case 298: // WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 308: // IIC_iEXTAsr_WriteALU_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 309: // IIC_iEXTr_WriteALU_ReadALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 312: // IIC_iTSTsi_WriteCMPsi
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1424; // SwiftWriteP01OneCycle
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 313: // IIC_iBITr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 316: // IIC_iPop_WriteLd
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1370; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1371; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1372; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1373; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1374; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1375; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1376; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1377; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1378; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
    }
    break;
  case 317: // IIC_iStore_m_WriteST
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    break;
  case 320: // IIC_iTSTr_WriteALU
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 321: // ANDri_ORRri_EORri_BICri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 322: // ANDrr_ORRrr_EORrr_BICrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 323: // ANDrsi_ORRrsi_EORrsi_BICrsi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 324: // ANDrsr_ORRrsr_EORrsr_BICrsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (TII->isPredicated(*MI))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1367; // SwiftWriteP01ThreeCycleTwoUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 325: // MOVsr_MOVsi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 326: // MVNsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            TII->ARMBaseInstrInfo::isCPSRDefined(*MI)
            && TII->isPredicated(*MI)
          ))
        return 1380; // A57Write_2cyc_1I
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 327: // MOVCCsi_MOVCCsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            TII->ARMBaseInstrInfo::isCPSRDefined(*MI)
            && TII->isPredicated(*MI)
          ))
        return 1380; // A57Write_2cyc_1I
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 333: // SEL
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1425; // (SwiftWriteP0OneCycle_SwiftWriteP0OneCycle)
      return 1426; // SwiftWriteP0OneCycle
    }
    break;
  case 336: // MLAv5_MLA_MLS_SMMLA_SMMLAR_SMMLS_SMMLSR
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 338: // UMULL
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1386; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL
      return 1387; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL
    }
    break;
  case 339: // SMLAL_UMLALv5_UMLAL_UMAAL_SMLALv5_SMLALBB_SMLALBT_SMLALTB_SMLALTT
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    break;
  case 340: // SMLAD_SMLADX_SMLSD_SMLSDX
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1429; // SwiftWriteP0P01FiveCycleTwoUops
      return 1430; // SwiftWriteP0FourCycle
    }
    break;
  case 341: // SMLALD_SMLSLD
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    break;
  case 345: // SMLABB_SMLABT_SMLATB_SMLATT_SMLAWB_SMLAWT
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 347: // LDRrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(3).getImm()) == 2
            )
          ))
        return 1431; // A57Write_5cyc_1I_1L
      if (ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::sub)
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 348: // LDRBi12_PICLDRH_PICLDRB_PICLDRSH_PICLDRSB_LDRH_LDRSH_LDRSB
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getOperand(2).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(3).getImm()) == ARM_AM::sub
          ))
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 351: // SXTB_SXTB16_SXTH_UXTB_UXTB16_UXTH
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1381; // anonymous_20746
      return 1382; // A57Write_2cyc_1M
    }
    break;
  case 352: // t2SXTB_t2SXTB16_t2SXTH_t2UXTB_t2UXTB16_t2UXTH
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 353: // t2MOVCCi32imm
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 354: // t2MOVi32imm
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 355: // t2MOV_ga_pcrel
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 356: // t2MOVi16_ga_pcrel
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 357: // t2SEL
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1425; // (SwiftWriteP0OneCycle_SwiftWriteP0OneCycle)
      return 1426; // SwiftWriteP0OneCycle
    }
    break;
  case 363: // SADD8_SADD16_SSUB8_SSUB16_SASX_SSAX_UADD8_UADD16_USUB8_USUB16_UASX_USAX
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1433; // A57Write_5cyc_1I_1M
      return 1434; // A57Write_3cyc_1I_1M
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 364: // t2SADD8_t2SADD16_t2SSUB8_t2SSUB16_t2SASX_t2SSAX_t2UADD8_t2UADD16_t2USUB8_t2USUB16_t2UASX_t2USAX
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1433; // A57Write_5cyc_1I_1M
      return 1434; // A57Write_3cyc_1I_1M
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 375: // t2MLA_t2MLS_t2SMMLA_t2SMMLAR_t2SMMLS_t2SMMLSR
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 377: // SMLSD_SMLSDX
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 378: // t2SMLABB_t2SMLABT_t2SMLATB_t2SMLATT_t2SMLAWB_t2SMLAWT
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 379: // t2SMLSD_t2SMLSDX
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 380: // t2SMLAD_t2SMLADX
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1429; // SwiftWriteP0P01FiveCycleTwoUops
      return 1430; // SwiftWriteP0FourCycle
    }
    break;
  case 383: // t2SMLAL_t2SMLALBB_t2SMLALBT_t2SMLALD_t2SMLALDX_t2SMLALTB_t2SMLALTT_t2UMLAL_t2SMLSLD_t2SMLSLDX_t2UMAAL
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    break;
  case 387: // LDRBrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(3).getImm()) == 2
            )
          ))
        return 1431; // A57Write_5cyc_1I_1L
      if (ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::sub)
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 396: // LDRH_PICLDRB_PICLDRH
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getOperand(2).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(3).getImm()) == ARM_AM::sub
          ))
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 402: // LDRBT_POST_IMM_LDRBT_POST_REG_LDRB_POST_REG_LDRB_PRE_REG
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift)
        return 1435; // A57Write_4cyc_1I_1L_1M_A57WrBackThree
      return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
    }
    break;
  case 404: // LDRT_POST_IMM_LDRT_POST_REG_LDR_POST_REG_LDR_PRE_REG
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift)
        return 1435; // A57Write_4cyc_1I_1L_1M_A57WrBackThree
      return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
    }
    break;
  case 417: // LDRD
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getOperand(3).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(4).getImm()) == ARM_AM::sub
          ))
        return 1437; // A57Write_5cyc_1I_1L_A57Write_5cyc_1I_1L
      return 1438; // A57Write_4cyc_1L_A57Write_4cyc_1L
    }
    break;
  case 418: // LDRD_POST_LDRD_PRE
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!MI->getOperand(4).getReg().isValid())
        return 1439; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57WrBackTwo
      return 1440; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57WrBackOne
    }
    break;
  case 420: // LDMDA_LDMDB_LDMIA_LDMIB_t2LDMDB_t2LDMIA_sysLDMDA_sysLDMDB_sysLDMIA_sysLDMIB_tLDMIA
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1370; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1371; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1372; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1373; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1374; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1375; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1376; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1377; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1378; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1473; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1474; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1475; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1476; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1477; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1478; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1479; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1481; // A57Write_3cyc_1L_A57Write_3cyc_1L
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1482; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1483; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1484; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1485; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1486; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1487; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
      return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1457; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1458; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1459; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1460; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1461; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1462; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1463; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1464; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1465; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1466; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1467; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1468; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1469; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1470; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1471; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52Read_ISS
      return 1472; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1441; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1442; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1443; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1444; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1445; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1446; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1447; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1448; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1449; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1450; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1451; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1452; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1453; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1454; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1455; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy_SwiftWriteLDMAddrNoWB
      return 1456; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLDMAddrNoWB
    }
    break;
  case 421: // LDMDA_UPD_LDMDB_UPD_LDMIA_UPD_LDMIB_UPD_tLDMIA_UPD_sysLDMDA_UPD_sysLDMDB_UPD_sysLDMIA_UPD_sysLDMIB_UPD_t2LDMDB_UPD_t2LDMIA_UPD
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1505; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1506; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1507; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1508; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1509; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1510; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1511; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1512; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1513; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1514; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1515; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1516; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1517; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1518; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1519; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1489; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1490; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1491; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1492; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1493; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1494; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1495; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1496; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1497; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1498; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1499; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1500; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1501; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1502; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1503; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy
      return 1504; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo
    }
    break;
  case 422: // LDMIA_RET_t2LDMIA_RET
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1340; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1341; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1342; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1343; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1344; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1345; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1346; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1347; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1348; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1505; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1506; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1507; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1508; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1509; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1510; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1511; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1512; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1513; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1514; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1515; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1516; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1517; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1518; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1519; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1529; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1530; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1531; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1532; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1533; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1534; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1535; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1536; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1537; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1538; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1539; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1540; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1541; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1542; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1543; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy_SwiftWriteP1TwoCycle
      return 1544; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteP1TwoCycle
    }
    break;
  case 423: // tPOP_RET
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1340; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1341; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1342; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1343; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1344; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1345; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1346; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1347; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1348; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1505; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1506; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1507; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1508; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1509; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1510; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1511; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1512; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1513; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1514; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1515; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1516; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1517; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1518; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1519; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1529; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1530; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1531; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1532; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1533; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1534; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1535; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1536; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1537; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1538; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1539; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1540; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1541; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1542; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1543; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy_SwiftWriteP1TwoCycle
      return 1544; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteP1TwoCycle
    }
    break;
  case 424: // tPOP
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1370; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1371; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1372; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1373; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1374; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1375; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1376; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1377; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1378; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1505; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1506; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1507; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1508; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1509; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1510; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1511; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1512; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1513; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1514; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1515; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1516; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1517; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1518; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1519; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1529; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1530; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1531; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1532; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1533; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1534; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1535; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1536; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1537; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1538; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1539; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1540; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1541; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1542; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1543; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy_SwiftWriteP1TwoCycle
      return 1544; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteP1TwoCycle
    }
    break;
  case 426: // PICSTRB_PICSTRH_STRBi12_STRH
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getOperand(2).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(3).getImm()) == ARM_AM::sub
          ))
        return 1545; // A57Write_3cyc_1I_1S
      return 1546; // A57Write_1cyc_1S
    }
    break;
  case 427: // STRrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(3).getImm()) == 2
            )
          ))
        return 1545; // A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::sub)
        return 1545; // A57Write_3cyc_1I_1S
      return 1546; // A57Write_1cyc_1S
    }
    break;
  case 428: // STRBrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(3).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(3).getImm()) == 2
            )
          ))
        return 1545; // A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2Op(MI->getOperand(3).getImm()) == ARM_AM::sub)
        return 1545; // A57Write_3cyc_1I_1S
      return 1546; // A57Write_1cyc_1S
    }
    break;
  case 446: // STRD
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getOperand(3).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(4).getImm()) == ARM_AM::sub
          ))
        return 1545; // A57Write_3cyc_1I_1S
      return 1546; // A57Write_1cyc_1S
    }
    break;
  case 450: // STMDA_STMDB_STMIA_STMIB_sysSTMDA_sysSTMDB_sysSTMIA_sysSTMIB_t2STMDB_t2STMIA
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1546; // A57Write_1cyc_1S
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1577; // A57Write_2cyc_1S
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1578; // A57Write_3cyc_1S
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1579; // A57Write_4cyc_1S
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1580; // A57Write_5cyc_1S
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1581; // A57Write_6cyc_1S
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1582; // A57Write_7cyc_1S
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1583; // A57Write_8cyc_1S
      return 1577; // A57Write_2cyc_1S
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1562; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1563; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1564; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1565; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1566; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1567; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1568; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1569; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1570; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1571; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1572; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1573; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1574; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1575; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1576; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      return 1562; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1547; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1548; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1549; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1550; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1551; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1552; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1553; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1554; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1555; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1556; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1557; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1558; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1559; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1560; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1561; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1547; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 451: // STMDA_UPD_STMDB_UPD_STMIA_UPD_STMIB_UPD_sysSTMDA_UPD_sysSTMDB_UPD_sysSTMIA_UPD_sysSTMIB_UPD_t2STMDB_UPD_t2STMIA_UPD_tSTMIA_UPD
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1600; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1601; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1602; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1603; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1604; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1605; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1606; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1607; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1608; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1609; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1610; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1611; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1612; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1613; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1585; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1586; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1587; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1588; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1589; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1590; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1591; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1592; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1593; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1594; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1595; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1596; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1597; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1598; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 452: // tPUSH
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1600; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1601; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1602; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1603; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1604; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1605; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1606; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1607; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1608; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1609; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1610; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1611; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1612; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1613; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1585; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1586; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1587; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1588; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1589; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1590; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1591; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1592; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1593; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1594; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1595; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1596; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1597; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1598; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 518: // VCMPD_VCMPZD_VCMPED_VCMPEZD
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 519: // VCMPS_VCMPZS_VCMPES_VCMPEZS
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 536: // VMULslv2i32_VMULv2i32_VQDMULHslv2i32_VQDMULHv2i32_VQRDMULHslv2i32_VQRDMULHv2i32_VMULLsv2i64_VMULLuv2i64_VQDMULLv2i64
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 537: // VMULslv4i32_VMULv4i32_VQDMULHslv4i32_VQDMULHv4i32_VQRDMULHslv4i32_VQRDMULHv4i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1625; // A57Write_5cyc_1W
      return 1626; // A57Write_6cyc_1W
    }
    break;
  case 541: // VMLALslsv2i32_VMLALsluv2i32_VMLALsv2i64_VMLALuv2i64_VMLAslv2i32_VMLAv2i32_VMLSLslsv2i32_VMLSLsluv2i32_VMLSLsv2i64_VMLSLuv2i64_VMLSslv2i32_VMLSv2i32_VQDMLALslv2i32_VQDMLALv2i64_VQDMLSLslv2i32_VQDMLSLv2i64
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1627; // A57Write_4cyc_1W_anonymous_21079
      return 1628; // A57Write_5cyc_1W_anonymous_21081
    }
    break;
  case 542: // VMLALslsv4i16_VMLALsluv4i16_VMLALsv4i32_VMLALsv8i16_VMLALuv4i32_VMLALuv8i16_VMLAslv4i16_VMLAv4i16_VMLAv8i8_VMLSLslsv4i16_VMLSLsluv4i16_VMLSLsv4i32_VMLSLsv8i16_VMLSLuv4i32_VMLSLuv8i16_VMLSslv4i16_VMLSv4i16_VMLSv8i8_VQDMLALslv4i16_VQDMLALv4i32_VQDMLSLslv4i16_VQDMLSLv4i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1627; // A57Write_4cyc_1W_anonymous_21079
      return 1628; // A57Write_5cyc_1W_anonymous_21081
    }
    break;
  case 546: // VMLAslv4i32_VMLAv4i32_VMLSslv4i32_VMLSv4i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1629; // A57Write_5cyc_1W_anonymous_21074
      return 1630; // A57Write_6cyc_1W_anonymous_21076
    }
    break;
  case 547: // VMLAslv8i16_VMLAv16i8_VMLAv8i16_VMLSslv8i16_VMLSv16i8_VMLSv8i16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1629; // A57Write_5cyc_1W_anonymous_21074
      return 1630; // A57Write_6cyc_1W_anonymous_21076
    }
    break;
  case 592: // VLDMQIA
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1405; // (A9WriteIssue_A9WriteLfpOp)_A9WriteAdr
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1406; // A9WriteLMfp1_A9WriteL1Hi_A9WriteAdr
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1407; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1408; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1409; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1410; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1411; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1412; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1413; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1407; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1414; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1415; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1416; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1417; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1418; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1419; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1420; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1421; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)
    }
    break;
  case 594: // VLDMDIA_VLDMSIA
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1405; // (A9WriteIssue_A9WriteLfpOp)_A9WriteAdr
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1406; // A9WriteLMfp1_A9WriteL1Hi_A9WriteAdr
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1407; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1408; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1409; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1410; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1411; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1412; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1413; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isVirtual())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1407; // (A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)_(A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1414; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1415; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1416; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1417; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1418; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1419; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1420; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)
      if ((MI->getOperand(0).getReg().isPhysical())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1421; // A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1658; // A57Write_5cyc_1L_A57Write_6cyc_1L
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1659; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1660; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1661; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1662; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_13cyc_1L_A57Write_14cyc_1L
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1663; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_13cyc_1L_A57Write_14cyc_1L_A57Write_15cyc_1L_A57Write_16cyc_1L
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1664; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_13cyc_1L_A57Write_14cyc_1L_A57Write_15cyc_1L_A57Write_16cyc_1L_A57Write_17cyc_1L_A57Write_18cyc_1L
      if (TII->isPredicated(*MI))
        return 1665; // A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_13cyc_1L_A57Write_14cyc_1L_A57Write_15cyc_1L_A57Write_16cyc_1L_A57Write_17cyc_1L_A57Write_18cyc_1L_A57Write_19cyc_1L_A57Write_20cyc_1L
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1666; // A57Write_5cyc_1L_A57Write_5cyc_1L
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1667; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1668; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1669; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1670; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1671; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1672; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_11cyc_1L
      return 1673; // A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L_A57Write_11cyc_1L_A57Write_11cyc_1L_A57Write_12cyc_1L_A57Write_12cyc_1L
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (MI->getNumOperands() == 1)
        return 1648; // R52WriteLM5Cy_R52ReserveLd5Cy
      if (MI->getNumOperands() == 2)
        return 1648; // R52WriteLM5Cy_R52ReserveLd5Cy
      if (MI->getNumOperands() == 3)
        return 1649; // R52WriteLM5Cy_R52WriteLM6Cy_R52ReserveLd6Cy
      if (MI->getNumOperands() == 4)
        return 1649; // R52WriteLM5Cy_R52WriteLM6Cy_R52ReserveLd6Cy
      if (MI->getNumOperands() == 5)
        return 1650; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52ReserveLd4Cy
      if (MI->getNumOperands() == 6)
        return 1651; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52ReserveLd7Cy
      if (MI->getNumOperands() == 7)
        return 1652; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52ReserveLd8Cy
      if (MI->getNumOperands() == 8)
        return 1652; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52ReserveLd8Cy
      if (MI->getNumOperands() == 9)
        return 1653; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52ReserveLd9Cy
      if (MI->getNumOperands() == 10)
        return 1653; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52ReserveLd9Cy
      if (MI->getNumOperands() == 11)
        return 1654; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52WriteLM10Cy_R52ReserveLd10Cy
      if (MI->getNumOperands() == 12)
        return 1654; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52WriteLM10Cy_R52ReserveLd10Cy
      if (MI->getNumOperands() == 13)
        return 1655; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52WriteLM10Cy_R52WriteLM11Cy_R52ReserveLd11Cy
      if (MI->getNumOperands() == 14)
        return 1655; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52WriteLM10Cy_R52WriteLM11Cy_R52ReserveLd11Cy
      if (MI->getNumOperands() == 14)
        return 1656; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52WriteLM10Cy_R52WriteLM11Cy_R52WriteLM12Cy_R52ReserveLd12Cy
      if (MI->getNumOperands() == 15)
        return 1656; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52WriteLM10Cy_R52WriteLM11Cy_R52WriteLM12Cy_R52ReserveLd12Cy
      return 1657; // R52WriteLM5Cy_R52WriteLM6Cy_R52WriteLM7Cy_R52WriteLM8Cy_R52WriteLM9Cy_R52WriteLM10Cy_R52WriteLM11Cy_R52WriteLM12Cy_R52ReserveLd5Cy
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 1)
        return 1631; // SwiftWriteLM4Cy
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1632; // SwiftWriteLM4Cy_SwiftWriteLM4CyNo
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1633; // SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm3
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1634; // SwiftWriteLM4Cy_SwiftWriteLM4CyNo_SwiftWriteLM4CyNo_SwiftWriteLM4CyNo
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1635; // SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm5
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1636; // SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM10Cy_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm5
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1637; // SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm7
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1638; // SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM13Cy_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm2
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1639; // SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM25CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm9
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1640; // SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM10Cy_SwiftWriteLM14Cy_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm5
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1641; // SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM25CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm9
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1642; // SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM11Cy_SwiftWriteLM11Cy_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm3
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1643; // SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM25CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm9
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1644; // SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM10Cy_SwiftWriteLM14Cy_SwiftWriteLM14Cy_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm7
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1645; // SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM17Cy_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM25CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm9
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1646; // SwiftWriteLM7Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM18CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm4
      return 1647; // SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM13Cy_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm2
    }
    break;
  case 595: // VLDMDDB_UPD_VLDMDIA_UPD_VLDMSDB_UPD_VLDMSIA_UPD
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1388; // A9WriteAdr_(A9WriteIssue_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1389; // (A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1390; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1391; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1392; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1393; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1394; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
          && (MI->getOperand(0).getReg().isVirtual())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1395; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp_A9WriteLfpOp)
      if ((TII->getNumLDMAddresses(*MI) == 0)
          && (MI->getOperand(0).getReg().isVirtual())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1389; // (A9WriteAdr_A9WriteAdr)_(A9WriteIssue_A9WriteLfpOp_A9WriteLfpOp)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 1))
        return 1396; // A9WriteAdr_A9WriteLMfp1_A9WriteL1Hi
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 2))
        return 1397; // (A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 3))
        return 1398; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 4))
        return 1399; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 5))
        return 1400; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 6))
        return 1401; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 7))
        return 1402; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if (((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
          && (MI->getOperand(0).getReg().isPhysical())
          && ((TII->getNumLDMAddresses(*MI)+1)/2 == 8))
        return 1403; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
      if ((TII->getNumLDMAddresses(*MI) == 0)
          && (MI->getOperand(0).getReg().isPhysical())
          && (TII->getNumLDMAddresses(*MI) == 0))
        return 1404; // (A9WriteAdr_A9WriteAdr)_A9WriteLMfp1_(A9WriteLMfpLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1691; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1692; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1693; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1694; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1695; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_13cyc_1L_1I_A57Write_14cyc_1L_1I
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1696; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_13cyc_1L_1I_A57Write_14cyc_1L_1I_A57Write_15cyc_1L_1I_A57Write_16cyc_1L_1I
      if (TII->isPredicated(*MI)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1697; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_13cyc_1L_1I_A57Write_14cyc_1L_1I_A57Write_15cyc_1L_1I_A57Write_16cyc_1L_1I_A57Write_17cyc_1L_1I_A57Write_18cyc_1L_1I
      if (TII->isPredicated(*MI))
        return 1698; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_13cyc_1L_1I_A57Write_14cyc_1L_1I_A57Write_15cyc_1L_1I_A57Write_16cyc_1L_1I_A57Write_17cyc_1L_1I_A57Write_18cyc_1L_1I_A57Write_19cyc_1L_1I_A57Write_20cyc_1L_1I
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1699; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1700; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1701; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1702; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1703; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1704; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1705; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      return 1706; // A57WrBackOne_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_12cyc_1L_1I_A57Write_12cyc_1L_1I
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 1)
        return 1674; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM4Cy
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1675; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM4Cy_SwiftWriteLM4CyNo
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1676; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm3
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1677; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM4Cy_SwiftWriteLM4CyNo_SwiftWriteLM4CyNo_SwiftWriteLM4CyNo
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1678; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm5
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1679; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM10Cy_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm5
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1680; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm7
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1681; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM13Cy_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm2
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1682; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM25CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm9
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1683; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM10Cy_SwiftWriteLM14Cy_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm5
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1684; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM25CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm9
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1685; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM11Cy_SwiftWriteLM11Cy_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteLM11CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm3
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1686; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM25CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm9
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1687; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM10Cy_SwiftWriteLM14Cy_SwiftWriteLM14Cy_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteLM14CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm7
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1688; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM17Cy_SwiftWriteLM18CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM21CyNo_SwiftWriteLM22CyNo_SwiftWriteLM25CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm9
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1689; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM7Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM18CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteLM19CyNo_SwiftWriteLM22CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm4
      return 1690; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM13Cy_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteLM13CyNo_SwiftWriteP01OneCycle_SwiftVLDMPerm2
    }
    break;
  case 596: // VSTMDIA_VSTMSIA
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1577; // A57Write_2cyc_1S
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1579; // A57Write_4cyc_1S
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1581; // A57Write_6cyc_1S
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1583; // A57Write_8cyc_1S
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1708; // A57Write_10cyc_1S
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1709; // A57Write_12cyc_1S
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1710; // A57Write_14cyc_1S
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1711; // A57Write_16cyc_1S
      return 1579; // A57Write_4cyc_1S
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 1)
        return 1707; // SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1707; // SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1549; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1707; // SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1551; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1549; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1553; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1548; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1555; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1551; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1557; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1549; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1559; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1553; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1561; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1550; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1548; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 597: // VSTMDDB_UPD_VSTMDIA_UPD_VSTMSDB_UPD_VSTMSIA_UPD
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1722; // A57WrBackOne_A57Write_10cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1723; // A57WrBackOne_A57Write_12cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1724; // A57WrBackOne_A57Write_14cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1725; // A57WrBackOne_A57Write_16cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 1)
        return 1712; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1712; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1713; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1712; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1714; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1713; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1715; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1716; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1717; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1714; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1718; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1713; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1719; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1715; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1720; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1721; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1716; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 680: // t2MOVCCi_t2MOVCCi16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 681: // t2MOVi_t2MOVi16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 687: // MOVsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            TII->ARMBaseInstrInfo::isCPSRDefined(*MI)
            && TII->isPredicated(*MI)
          ))
        return 1380; // A57Write_2cyc_1I
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 688: // t2MOVSsr_t2MOVsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 689: // MOVTi16_ga_pcrel_MOVTi16_t2MOVTi16_ga_pcrel_t2MOVTi16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1339; // A57Write_1cyc_1I
      return 1382; // A57Write_2cyc_1M
    }
    break;
  case 690: // ADDSri_ADCri_ADDri_RSBSri_RSBri_RSCri_SBCri_t2ADDSri_t2ADCri_t2ADDri_t2ADDri12_t2RSBSri_t2RSBri_t2SBCri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 691: // CLZ_t2CLZ
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 692: // t2ANDri_t2BICri_t2EORri_t2ORRri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 695: // t2MVNr
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
  return 1726; // M85NonsmallShiftWrite_M85Read_ISS
    }
    break;
  case 696: // t2MVNs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            TII->ARMBaseInstrInfo::isCPSRDefined(*MI)
            && TII->isPredicated(*MI)
          ))
        return 1380; // A57Write_2cyc_1I
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1726; // M85NonsmallShiftWrite_M85Read_ISS
    }
    break;
  case 697: // ADDSrr_ADCrr_ADDrr_RSBrr_RSCrr_SBCrr_t2ADDSrr_t2ADCrr_t2ADDrr_t2SBCrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 699: // t2ANDrr_t2BICrr_t2EORrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 700: // ADDSrsi_ADCrsi_ADDrsi_RSBrsi_RSCrsi_SBCrsi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 701: // t2ADDSrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC
          && TII->isPredicated(*MI))
        return 1334; // anonymous_20746_ReadDefault
      if (TII->isPredicated(*MI))
        return 1335; // A57Write_2cyc_1M_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if ((TII->isSwiftFastImmShift(MI))
          && TII->isPredicated(*MI))
        return 1355; // SwiftWriteP01TwoCycle_anonymous_20127
      if (TII->isPredicated(*MI))
        return 1356; // WriteALU_anonymous_20127
      if (TII->isSwiftFastImmShift(MI))
        return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
      return 1357; // WriteALU_NoReadAdvance
    }
    break;
  case 702: // t2ADCrs_t2ADDrs_t2SBCrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1728; // M85NonsmallShiftWrite_M85Read_ISS_M85Read_ISS
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1728; // M85NonsmallShiftWrite_M85Read_ISS_M85Read_ISS
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 703: // t2ANDrs_t2BICrs_t2EORrs_t2ORRrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 704: // t2RSBrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 705: // ADDSrsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (TII->isPredicated(*MI))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1336; // SwiftWriteP0ThreeCycleThreeUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 706: // ADCrsr_ADDrsr_RSBrsr_RSCrsr_SBCrsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI)
          && MI->getOperand(0).getReg() == ARM::PC)
        return 1332; // anonymous_20739_ReadDefault
      if (TII->isPredicated(*MI))
        return 1333; // A57Write_2cyc_1I_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1367; // SwiftWriteP01ThreeCycleTwoUops_anonymous_20127
      return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
    }
    break;
  case 707: // ADR
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 709: // MVNsi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 710: // t2MOVSsi_t2MOVsi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 711: // ASRi_RORi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 712: // ASRr_RORr_LSRi_LSRr_LSLi_LSLr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            TII->ARMBaseInstrInfo::isCPSRDefined(*MI)
            && TII->isPredicated(*MI)
          ))
        return 1380; // A57Write_2cyc_1I
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 713: // LSRs1
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 716: // CMPrsi_CMNrsi
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1368; // SwiftWriteP01OneCycle_ReadALU
      return 1330; // SwiftWriteP01TwoCycle_ReadALU
    }
    break;
  case 717: // CMPrsr_CMNrsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1369; // A57Write_2cyc_1I_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    break;
  case 718: // t2LDC2L_OFFSET_t2LDC2L_OPTION_t2LDC2L_POST_t2LDC2L_PRE_t2LDC2_OFFSET_t2LDC2_OPTION_t2LDC2_POST_t2LDC2_PRE_t2LDCL_OFFSET_t2LDCL_OPTION_t2LDCL_POST_t2LDCL_PRE_t2LDC_OFFSET_t2LDC_OPTION_t2LDC_POST_t2LDC_PRE_RRXi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 719: // RBIT_REV_REV16_REVSH
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 720: // RRX
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 723: // TSTrsi
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1368; // SwiftWriteP01OneCycle_ReadALU
      return 1330; // SwiftWriteP01TwoCycle_ReadALU
    }
    break;
  case 724: // TSTrsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1369; // A57Write_2cyc_1I_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    break;
  case 767: // VCMPEH_VCMPEZH_VCMPH_VCMPZH
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 786: // VQDMLALslv2i32_VQDMLALv2i64_VQDMLSLslv2i32_VQDMLSLv2i64
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 787: // VQDMLALslv4i16_VQDMLALv4i32_VQDMLSLslv4i16_VQDMLSLv4i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 788: // VQDMULHslv2i32_VQDMULHv2i32_VQDMULLv2i64_VQRDMULHslv2i32_VQRDMULHv2i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 789: // VQDMULHslv4i16_VQDMULHv4i16_VQDMULLslv2i32_VQDMULLslv4i16_VQDMULLv4i32_VQRDMULHslv4i16_VQRDMULHv4i16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 790: // VQDMULHslv4i32_VQDMULHv4i32_VQRDMULHslv4i32_VQRDMULHv4i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1625; // A57Write_5cyc_1W
      return 1626; // A57Write_6cyc_1W
    }
    break;
  case 791: // VQDMULHslv8i16_VQDMULHv8i16_VQRDMULHslv8i16_VQRDMULHv8i16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1625; // A57Write_5cyc_1W
      return 1626; // A57Write_6cyc_1W
    }
    break;
  case 871: // MOVCCsi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 872: // t2ASRri_tASRri_t2LSRri_tLSRri_t2LSLri_tLSLri_t2RORri_t2RRX
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 873: // LSRi_LSLi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 874: // t2MOVCCasr_t2MOVCClsl_t2MOVCClsr_t2MOVCCror
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 875: // t2MOVCCr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 876: // t2MOVTi16_ga_pcrel_t2MOVTi16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 877: // t2MOVr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 878: // tROR
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 879: // t2ASRrr_tASRrr_t2LSRrr_tLSRrr_t2LSLrr_tLSLrr_t2RORrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            TII->ARMBaseInstrInfo::isCPSRDefined(*MI)
            && TII->isPredicated(*MI)
          ))
        return 1380; // A57Write_2cyc_1I
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 882: // SADD16_SADD8_SSUB16_SSUB8_UADD16_UADD8_USUB16_USUB8
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1733; // A57Write_4cyc_1I_1M
      return 1734; // A57Write_2cyc_1I_1M
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 883: // t2SADD16_t2SADD8_t2SSUB16_t2SSUB8_t2UADD16_t2UADD8_t2USUB16_t2USUB8
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1733; // A57Write_4cyc_1I_1M
      return 1734; // A57Write_2cyc_1I_1M
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1383; // SwiftWriteP01ThreeCycleTwoUops
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 910: // LDR_PRE_REG
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1735; // A57Write_5cyc_1I_1L_A57WrBackTwo
      return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
    }
    break;
  case 911: // LDRB_PRE_REG
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1735; // A57Write_5cyc_1I_1L_A57WrBackTwo
      return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
    }
    break;
  case 912: // LDRH_PRE
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!MI->getOperand(3).getReg().isValid())
        return 1736; // A57Write_4cyc_1L_A57WrBackTwo
      return 1737; // A57Write_4cyc_1L_A57WrBackOne
    }
    break;
  case 913: // LDRSB_PRE_LDRSH_PRE
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!MI->getOperand(3).getReg().isValid())
        return 1736; // A57Write_4cyc_1L_A57WrBackTwo
      return 1737; // A57Write_4cyc_1L_A57WrBackOne
    }
    break;
  case 919: // LDRD_PRE
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!MI->getOperand(4).getReg().isValid())
        return 1738; // A57Write_5cyc_1I_1L_A57Write_5cyc_1I_1L_A57WrBackTwo
      return 1440; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57WrBackOne
    }
    break;
  case 927: // LDRH_POST
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!MI->getOperand(2).getReg().isValid())
        return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
      return 1739; // A57Write_4cyc_1L_1I_A57WrBackOne
    }
    break;
  case 928: // LDRSB_POST_LDRSH_POST
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!MI->getOperand(2).getReg().isValid())
        return 1436; // A57Write_4cyc_1L_1I_A57WrBackTwo
      return 1739; // A57Write_4cyc_1L_1I_A57WrBackOne
    }
    break;
  case 933: // PLDrs_PLDWrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(2).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(2).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(2).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(2).getImm()) == 2
            )
          ))
        return 1431; // A57Write_5cyc_1I_1L
      if (ARM_AM::getAM2Op(MI->getOperand(2).getImm()) == ARM_AM::sub)
        return 1431; // A57Write_5cyc_1I_1L
      return 1432; // A57Write_4cyc_1L
    }
    break;
  case 945: // STR_PRE_REG
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift
          && !(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::sub
          && !(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1741; // A57WrBackOne_A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift)
        return 1742; // A57WrBackTwo_A57Write_1cyc_1S_1M
      if (ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::sub)
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
    }
    break;
  case 946: // STRB_PRE_REG
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift
          && !(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::sub
          && !(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      if (!(
            ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::no_shift
            || (
              ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::add
              && ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) == ARM_AM::lsl
              && ARM_AM::getAM2Offset(MI->getOperand(4).getImm()) == 2
            )
          ))
        return 1741; // A57WrBackOne_A57Write_3cyc_1I_1S
      if (ARM_AM::getAM2ShiftOpc(MI->getOperand(4).getImm()) != ARM_AM::no_shift)
        return 1742; // A57WrBackTwo_A57Write_1cyc_1S_1M
      if (ARM_AM::getAM2Op(MI->getOperand(4).getImm()) == ARM_AM::sub)
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
    }
    break;
  case 947: // STRD_PRE
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getOperand(4).getReg().isValid()
            && ARM_AM::getAM3Op(MI->getOperand(5).getImm()) == ARM_AM::sub
          ))
        return 1740; // A57WrBackTwo_A57Write_3cyc_1I_1S
      return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
    }
    break;
  case 967: // VSTMSIA
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1546; // A57Write_1cyc_1S
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1577; // A57Write_2cyc_1S
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1578; // A57Write_3cyc_1S
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1579; // A57Write_4cyc_1S
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1580; // A57Write_5cyc_1S
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1581; // A57Write_6cyc_1S
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1582; // A57Write_7cyc_1S
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1583; // A57Write_8cyc_1S
      return 1577; // A57Write_2cyc_1S
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 1)
        return 1707; // SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1707; // SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1549; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1707; // SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1551; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1549; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1553; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1548; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1555; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1551; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1557; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1549; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1559; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1553; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1561; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1550; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1548; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 968: // VSTMSDB_UPD_VSTMSIA_UPD
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 1)
        return 1712; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1712; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1713; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1712; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_SwiftWriteStIncAddr
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1714; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1713; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1715; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1716; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1717; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1714; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1718; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1713; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1719; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1715; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1720; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1721; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1716; // (SwiftWriteP01OneCycle_SwiftWriteP01OneCycle)_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 972: // VMULpd_VMULv4i16_VMULv8i8_VMULslv4i16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 973: // VMULv2i32_VMULslv2i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 974: // VQDMULHslv2i32_VQDMULHv2i32_VQRDMULHslv2i32_VQRDMULHv2i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 975: // VQDMULHslv4i16_VQDMULHv4i16_VQRDMULHslv4i16_VQRDMULHv4i16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 976: // VMULpq_VMULv16i8_VMULv8i16_VMULslv8i16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1625; // A57Write_5cyc_1W
      return 1626; // A57Write_6cyc_1W
    }
    break;
  case 977: // VMLAslv2i32_VMLAv2i32_VMLSslv2i32_VMLSv2i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1743; // A57Write_4cyc_1W_anonymous_21069
      return 1744; // A57Write_5cyc_1W_anonymous_21071
    }
    break;
  case 978: // VMLAslv4i16_VMLAv4i16_VMLAv8i8_VMLSslv4i16_VMLSv4i16_VMLSv8i8
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1743; // A57Write_4cyc_1W_anonymous_21069
      return 1744; // A57Write_5cyc_1W_anonymous_21071
    }
    break;
  case 979: // VQRDMLAHslv2i32_VQRDMLAHv2i32_VQRDMLSHslv2i32_VQRDMLSHv2i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 980: // VQRDMLAHslv4i16_VQRDMLAHv4i16_VQRDMLSHslv4i16_VQRDMLSHv4i16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 981: // VQRDMLAHslv4i32_VQRDMLAHv4i32_VQRDMLSHslv4i32_VQRDMLSHv4i32
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 982: // VQRDMLAHslv8i16_VQRDMLAHv8i16_VQRDMLSHslv8i16_VQRDMLSHv8i16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1729; // A57Write_4cyc_1W_anonymous_21084
      return 1730; // A57Write_5cyc_1W_anonymous_21086
    }
    break;
  case 983: // VMULLp8_VMULLslsv2i32_VMULLslsv4i16_VMULLsluv2i32_VMULLsluv4i16_VMULLsv4i32_VMULLsv8i16_VMULLuv4i32_VMULLuv8i16
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (false)
        return 1624; // A57Write_4cyc_1W
      return 1625; // A57Write_5cyc_1W
    }
    break;
  case 1014: // t2LDMIA_RET
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1340; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1341; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1342; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1343; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1344; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1345; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1346; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1347; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteB
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1348; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteB
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1505; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1506; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1507; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1508; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1509; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1510; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1511; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1512; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1513; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1514; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1515; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1516; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1517; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1518; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1519; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1529; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1530; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1531; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1532; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1533; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1534; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1535; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1536; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1537; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1538; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1539; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1540; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1541; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1542; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteP1TwoCycle
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1543; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy_SwiftWriteP1TwoCycle
      return 1544; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteP1TwoCycle
    }
    break;
  case 1015: // tLDMIA_UPD_t2LDMDB_UPD_t2LDMIA_UPD
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1505; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1506; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1507; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1508; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1509; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1510; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1511; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1512; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1513; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1514; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1515; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1516; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1517; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1518; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1519; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1489; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1490; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1491; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1492; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1493; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1494; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1495; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1496; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1497; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1498; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1499; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1500; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1501; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1502; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1503; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy
      return 1504; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo
    }
    break;
  case 1016: // t2LDMDB_t2LDMIA_tLDMIA
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1370; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1371; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1372; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1373; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1374; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1375; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1376; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1377; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1378; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1473; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1474; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1475; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1476; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1477; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1478; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1479; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1481; // A57Write_3cyc_1L_A57Write_3cyc_1L
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1482; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1483; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1484; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1485; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1486; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1487; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
      return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1457; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1458; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1459; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1460; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1461; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1462; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1463; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1464; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1465; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1466; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1467; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1468; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1469; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1470; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1471; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52Read_ISS
      return 1472; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1441; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1442; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1443; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1444; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1445; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1446; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1447; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1448; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1449; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1450; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1451; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1452; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1453; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1454; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1455; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy_SwiftWriteLDMAddrNoWB
      return 1456; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLDMAddrNoWB
    }
    break;
  case 1023: // t2STMDB_t2STMIA
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1546; // A57Write_1cyc_1S
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1577; // A57Write_2cyc_1S
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1578; // A57Write_3cyc_1S
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1579; // A57Write_4cyc_1S
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1580; // A57Write_5cyc_1S
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1581; // A57Write_6cyc_1S
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1582; // A57Write_7cyc_1S
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1583; // A57Write_8cyc_1S
      return 1577; // A57Write_2cyc_1S
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1562; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1563; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1564; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1565; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1566; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1567; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1568; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1569; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1570; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1571; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1572; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1573; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1574; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1575; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1576; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
      return 1562; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52Read_ISS_R52Read_EX2
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1547; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1548; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1549; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1550; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1551; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1552; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1553; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1554; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1555; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1556; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1557; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1558; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1559; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1560; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1561; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1547; // (SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 1024: // t2STMDB_UPD_t2STMIA_UPD_tSTMIA_UPD
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1600; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1601; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1602; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1603; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1604; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1605; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1606; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1607; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1608; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1609; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1610; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1611; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1612; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1613; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1585; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1586; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1587; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1588; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1589; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1590; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1591; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1592; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1593; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1594; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1595; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1596; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1597; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1598; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 1025: // tMOVSr_tMOVr
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1029: // t2SMLAL_t2SMLALBB_t2SMLALBT_t2SMLALD_t2SMLALDX_t2SMLALTB_t2SMLALTT_t2SMLSLD_t2SMLSLDX
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1351; // A57Write_5cyc_1I_1M_A57Write_5cyc_1I_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
      return 1352; // A57Write_4cyc_1M_A57Write_4cyc_1M_ReadMUL_ReadMUL_ReadMAC_ReadMAC
    }
    break;
  case 1030: // t2REV_t2REV16_t2REVSH_tREV_tREV16_tREVSH
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1061: // t2ADDrr_t2ADDSrr_t2SBCrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 1062: // t2ASRri_t2LSLri_t2LSRri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1063: // t2ASRrr_t2LSLrr_t2LSRrr_t2RORrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            TII->ARMBaseInstrInfo::isCPSRDefined(*MI)
            && TII->isPredicated(*MI)
          ))
        return 1380; // A57Write_2cyc_1I
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      if (TII->isPredicated(*MI))
        return 1380; // A57Write_2cyc_1I
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1064: // t2CMNrr
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1066: // t2CMPrr
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1067: // t2ORRrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1068: // t2REV_t2REV16_t2REVSH
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1069: // t2RSBri_t2RSBSri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 1070: // t2RSBrr_t2SUBSrr_t2SUBrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    break;
  case 1071: // t2TEQrr_t2TSTrr
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1074: // t2STMIA_UPD_t2STMDB_UPD
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1614; // A57WrBackOne_A57Write_1cyc_1S_1I
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1616; // A57WrBackOne_A57Write_3cyc_1S_1I
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1617; // A57WrBackOne_A57Write_4cyc_1S_1I
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1618; // A57WrBackOne_A57Write_5cyc_1S_1I
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1619; // A57WrBackOne_A57Write_6cyc_1S_1I
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1620; // A57WrBackOne_A57Write_7cyc_1S_1I
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1621; // A57WrBackOne_A57Write_8cyc_1S_1I
      return 1615; // A57WrBackOne_A57Write_2cyc_1S_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1600; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1601; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1602; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1603; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1604; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1605; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1606; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1607; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1608; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1609; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1610; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1611; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1612; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1613; // (R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
      return 1599; // (R52WriteIStIncAddr_R52WriteIStIncAddr)_R52WriteAdr_R52Read_ISS_R52Read_EX2
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1585; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1586; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1587; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1588; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1589; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1590; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1591; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1592; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1593; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1594; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1595; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1596; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1597; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1598; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr_SwiftWriteStIncAddr)
      return 1584; // SwiftWriteP01OneCycle_(SwiftWriteStIncAddr_SwiftWriteStIncAddr)
    }
    break;
  case 1076: // tADC_tADDhirr_tADDrSP_tADDrr_tADDspr_tPICADD_tSBC_tSUBrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1077: // tADDrSPi_tADDspi_tADR_tRSB_tSUBspi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1078: // tAND_tBIC_tEOR_tORR
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1079: // tASRri_tLSLri_tLSRri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1088: // tTST
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1094: // t2MOVSsi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1095: // t2MOVSsr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1097: // t2SMMLA_t2SMMLAR_t2SMMLS_t2SMMLSR
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isPredicated(*MI))
        return 1427; // SwiftWriteP0P01FiveCycleTwoUops_ReadALU_ReadALU_anonymous_20158
      return 1428; // SwiftWriteP0FourCycle_ReadALU_ReadALU_ReadALU
    }
    break;
  case 1105: // t2LDMDB_t2LDMIA
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1370; // A9WriteL1_A9WriteL1Hi_A9WriteAdr_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1371; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1372; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1373; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1374; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1375; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1376; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1377; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1378; // A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteAdr_A9WriteAdr)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1473; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1474; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1475; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1476; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1477; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1478; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1479; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI)
          && (
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if (ARM_MC::isLDMBaseRegInList(*MI))
        return 1480; // A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_11cyc_1L_1I_A57Write_11cyc_1L_1I
      if ((
            MI->getNumOperands() == 4
            || MI->getNumOperands() == 5
          ))
        return 1481; // A57Write_3cyc_1L_A57Write_3cyc_1L
      if ((
            MI->getNumOperands() == 6
            || MI->getNumOperands() == 7
          ))
        return 1482; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L
      if ((
            MI->getNumOperands() == 8
            || MI->getNumOperands() == 9
          ))
        return 1483; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L
      if ((
            MI->getNumOperands() == 10
            || MI->getNumOperands() == 11
          ))
        return 1484; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L
      if ((
            MI->getNumOperands() == 12
            || MI->getNumOperands() == 13
          ))
        return 1485; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L
      if ((
            MI->getNumOperands() == 14
            || MI->getNumOperands() == 15
          ))
        return 1486; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L
      if ((
            MI->getNumOperands() == 16
            || MI->getNumOperands() == 17
          ))
        return 1487; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L
      if ((
            MI->getNumOperands() == 18
            || MI->getNumOperands() == 19
          ))
        return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
      return 1488; // A57Write_3cyc_1L_A57Write_3cyc_1L_A57Write_4cyc_1L_A57Write_4cyc_1L_A57Write_5cyc_1L_A57Write_5cyc_1L_A57Write_6cyc_1L_A57Write_6cyc_1L_A57Write_7cyc_1L_A57Write_7cyc_1L_A57Write_8cyc_1L_A57Write_8cyc_1L_A57Write_9cyc_1L_A57Write_9cyc_1L_A57Write_10cyc_1L_A57Write_10cyc_1L
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1457; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1458; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1459; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1460; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1461; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1462; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1463; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1464; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1465; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1466; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1467; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1468; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1469; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1470; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1471; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52Read_ISS
      return 1472; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1441; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1442; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1443; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1444; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1445; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1446; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1447; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1448; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1449; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1450; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1451; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1452; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1453; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1454; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLDMAddrNoWB
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1455; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy_SwiftWriteLDMAddrNoWB
      return 1456; // SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo_SwiftWriteLDMAddrNoWB
    }
    break;
  case 1106: // t2LDMDB_UPD_t2LDMIA_UPD
    if (SchedModel->getProcessorID() == 2) { // CortexA9Model
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 1)
        return 1358; // A9WriteAdr_A9WriteL1_A9WriteL1Hi_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 2)
        return 1359; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 3)
        return 1360; // (A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 4)
        return 1361; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 5)
        return 1362; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 6)
        return 1363; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 7)
        return 1364; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if ((TII->getNumLDMAddresses(*MI)+1)/2 == 8)
        return 1365; // (A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
      if (TII->getNumLDMAddresses(*MI) == 0)
        return 1366; // (A9WriteAdr_A9WriteAdr)_A9WriteL1_A9WriteL1Hi_(A9WriteLMLo_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_(A9WriteLMHi_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1_A9WriteCycle1)_A9WriteIssue
    }
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if ((
            MI->getNumOperands() == 5
            || MI->getNumOperands() == 6
          ))
        return 1521; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I
      if ((
            MI->getNumOperands() == 7
            || MI->getNumOperands() == 8
          ))
        return 1522; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I
      if ((
            MI->getNumOperands() == 9
            || MI->getNumOperands() == 10
          ))
        return 1523; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I
      if ((
            MI->getNumOperands() == 11
            || MI->getNumOperands() == 12
          ))
        return 1524; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I
      if ((
            MI->getNumOperands() == 13
            || MI->getNumOperands() == 14
          ))
        return 1525; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I
      if ((
            MI->getNumOperands() == 15
            || MI->getNumOperands() == 16
          ))
        return 1526; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I
      if ((
            MI->getNumOperands() == 17
            || MI->getNumOperands() == 18
          ))
        return 1527; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I
      if ((
            MI->getNumOperands() == 19
            || MI->getNumOperands() == 20
          ))
        return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
      return 1528; // A57WrBackOne_A57Write_3cyc_1L_1I_A57Write_3cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_4cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_5cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_6cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_7cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_8cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_9cyc_1L_1I_A57Write_10cyc_1L_1I_A57Write_10cyc_1L_1I
    }
    if (SchedModel->getProcessorID() == 9) { // CortexR52Model
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1505; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1506; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1507; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1508; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1509; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1510; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1511; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1512; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1513; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1514; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1515; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1516; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1517; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1518; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteAdr_R52Read_ISS
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1519; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6Cy_R52WriteILDM7Cy_R52WriteILDM8Cy_R52WriteILDM9Cy_R52WriteILDM10Cy_R52WriteILDM11Cy_R52WriteILDM12Cy_R52WriteILDM13Cy_R52WriteILDM14Cy_R52WriteILDM15Cy_R52WriteILDM16Cy_R52WriteILDM17Cy_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
      return 1520; // R52WriteILDM4Cy_R52WriteILDM5Cy_R52WriteILDM6CyNo_R52WriteILDM7CyNo_R52WriteILDM8CyNo_R52WriteILDM9CyNo_R52WriteILDM10CyNo_R52WriteILDM11CyNo_R52WriteILDM12CyNo_R52WriteILDM13CyNo_R52WriteILDM14CyNo_R52WriteILDM15CyNo_R52WriteILDM16CyNo_R52WriteILDM17CyNo_R52WriteILDM18Cy_R52WriteILDM19Cy_R52WriteAdr_R52Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->getNumLDMAddresses(*MI) == 2)
        return 1489; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy
      if (TII->getNumLDMAddresses(*MI) == 3)
        return 1490; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy
      if (TII->getNumLDMAddresses(*MI) == 4)
        return 1491; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy
      if (TII->getNumLDMAddresses(*MI) == 5)
        return 1492; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy
      if (TII->getNumLDMAddresses(*MI) == 6)
        return 1493; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy
      if (TII->getNumLDMAddresses(*MI) == 7)
        return 1494; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy
      if (TII->getNumLDMAddresses(*MI) == 8)
        return 1495; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy
      if (TII->getNumLDMAddresses(*MI) == 9)
        return 1496; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy
      if (TII->getNumLDMAddresses(*MI) == 10)
        return 1497; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy
      if (TII->getNumLDMAddresses(*MI) == 11)
        return 1498; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy
      if (TII->getNumLDMAddresses(*MI) == 12)
        return 1499; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy
      if (TII->getNumLDMAddresses(*MI) == 13)
        return 1500; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy
      if (TII->getNumLDMAddresses(*MI) == 14)
        return 1501; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy
      if (TII->getNumLDMAddresses(*MI) == 15)
        return 1502; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy
      if (TII->getNumLDMAddresses(*MI) == 16)
        return 1503; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5Cy_SwiftWriteLM6Cy_SwiftWriteLM7Cy_SwiftWriteLM8Cy_SwiftWriteLM9Cy_SwiftWriteLM10Cy_SwiftWriteLM11Cy_SwiftWriteLM12Cy_SwiftWriteLM13Cy_SwiftWriteLM14Cy_SwiftWriteLM15Cy_SwiftWriteLM16Cy_SwiftWriteLM17Cy_SwiftWriteLM18Cy
      return 1504; // SwiftWriteLDMAddrWB_SwiftWriteLM3Cy_SwiftWriteLM4Cy_SwiftWriteLM5CyNo_SwiftWriteLM6CyNo_SwiftWriteLM7CyNo_SwiftWriteLM8CyNo_SwiftWriteLM9CyNo_SwiftWriteLM10CyNo_SwiftWriteLM11CyNo_SwiftWriteLM12CyNo_SwiftWriteLM13CyNo_SwiftWriteLM14CyNo_SwiftWriteLM15CyNo_SwiftWriteLM16CyNo_SwiftWriteLM17CyNo_SwiftWriteLM18CyNo
    }
    break;
  case 1107: // tADDi3_tADDi8_tSUBi3_tSUBi8
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1108: // t2ADDSri_t2ADDri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 1109: // t2SUBSri_t2SUBri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    break;
  case 1234: // t2RSBSrs_t2SUBrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1728; // M85NonsmallShiftWrite_M85Read_ISS_M85Read_ISS
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1728; // M85NonsmallShiftWrite_M85Read_ISS_M85Read_ISS
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1235: // t2SUBSrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC
          && TII->isPredicated(*MI))
        return 1334; // anonymous_20746_ReadDefault
      if (TII->isPredicated(*MI))
        return 1335; // A57Write_2cyc_1M_ReadDefault
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1334; // anonymous_20746_ReadDefault
      return 1335; // A57Write_2cyc_1M_ReadDefault
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if ((TII->isSwiftFastImmShift(MI))
          && TII->isPredicated(*MI))
        return 1355; // SwiftWriteP01TwoCycle_anonymous_20127
      if (TII->isPredicated(*MI))
        return 1356; // WriteALU_anonymous_20127
      if (TII->isSwiftFastImmShift(MI))
        return 1337; // SwiftWriteP01TwoCycle_NoReadAdvance
      return 1357; // WriteALU_NoReadAdvance
    }
    break;
  case 1236: // t2BICrs_t2EORrs_t2ORRrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1237: // t2ORNrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1238: // t2CMNrs
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1422; // SwiftWriteP01OneCycle_ReadALU_ReadALU
      return 1423; // SwiftWriteP01TwoCycle_ReadALU_ReadALU
    }
    break;
  case 1239: // t2CMPrs
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1424; // SwiftWriteP01OneCycle
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 1240: // t2TEQrs_t2TSTrs
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
  return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1424; // SwiftWriteP01OneCycle
      return 1384; // SwiftWriteP01TwoCycle
    }
    break;
  case 1241: // t2ASRs1_t2LSRs1
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1242: // t2RRX
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->ARMBaseInstrInfo::isCPSRDefined(*MI))
        return 1382; // A57Write_2cyc_1M
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1243: // t2CLZ
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1245: // t2RBIT
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1246: // t2PKHBT_t2PKHTB
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1254: // VCMPS
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 1255: // VCMPD
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (TII->isPredicated(*MI))
        return 1622; // A57Write_6cyc_1V_1X
      return 1623; // A57Write_3cyc_1X
    }
    break;
  case 1265: // t2RSBSrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1266: // t2ADCrs_t2SBCrs
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1328; // anonymous_20746_ReadALU
      return 1329; // A57Write_2cyc_1M_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    if (SchedModel->getProcessorID() == 10) { // SwiftModel
      if (TII->isSwiftFastImmShift(MI))
        return 1330; // SwiftWriteP01TwoCycle_ReadALU
      return 1331; // WriteALU_ReadALU
    }
    break;
  case 1267: // t2ADDSrr_t2SBCrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1268: // t2SUBSrr_t2RSBrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1269: // t2ADCrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1270: // t2BICrr_t2EORrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1271: // t2ORNrr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1326; // anonymous_21210_ReadALU_ReadALU
      return 1327; // A57Write_1cyc_1I_ReadALU_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      return 1727; // M85NonsmallShiftWrite_M85Read_EX1_M85Read_ISS
    }
    break;
  case 1272: // tLSLSri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1273: // tADDspi_tSUBspi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    break;
  case 1274: // t2ADDri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1275: // t2ADDri12
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1276: // t2SUBri
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1277: // t2SUBri12
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1324; // anonymous_21210_ReadALU
      return 1325; // A57Write_1cyc_1I_ReadALU
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1731; // WriteALU_M85Read_ISS
      return 1732; // WriteALU_M85Read_EX1
    }
    break;
  case 1278: // tADDrSP_tADDspr_tADDhirr
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1745; // WriteALU_M85Read_ISS_M85Read_ISS
      return 1746; // WriteALU_M85Read_EX1_M85Read_EX1
    }
    break;
  case 1279: // tADDrSPi
    if (SchedModel->getProcessorID() == 4) { // CortexA57Model
      if (MI->getOperand(0).getReg() == ARM::PC)
        return 1338; // anonymous_21210
      return 1339; // A57Write_1cyc_1I
    }
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if (MI->getOperand(0).getReg() == ARM::SP)
        return 1745; // WriteALU_M85Read_ISS_M85Read_ISS
      return 1746; // WriteALU_M85Read_EX1_M85Read_EX1
    }
    break;
  case 1291: // VMRS
    if (SchedModel->getProcessorID() == 8) { // CortexM85Model
      if ((
            MI->getOperand(0).isReg() 
            && MI->getOperand(0).getReg() == ARM::PC
          ))
        return 1747; // M85VMRSEarly
      return 1748; // M85VMRSLate
    }
    break;
  };
  report_fatal_error("Expected a variant SchedClass");
} // ARMGenSubtargetInfo::resolveSchedClass

unsigned ARMGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return ARM_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // ARMGenSubtargetInfo::resolveVariantSchedClass

unsigned ARMGenSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const auto *Subtarget =
      static_cast<const ARMSubtarget *>(this);
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((Subtarget->isThumb1Only())) Modes |= (1 << 0);
  return Modes;
}
unsigned ARMGenSubtargetInfo::getHwMode(enum HwModeType type) const {
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
const FeatureBitset &ARMGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
ARM::ARMv89a,
ARM::ARMv9a,
ARM::ARMv81a,
ARM::ARMv81mMainline,
ARM::ARMv82a,
ARM::ARMv83a,
ARM::ARMv84a,
ARM::ARMv85a,
ARM::ARMv86a,
ARM::ARMv87a,
ARM::ARMv88a,
ARM::ARMv4t,
ARM::ARMv91a,
ARM::ARMv92a,
ARM::ARMv93a,
ARM::ARMv94a,
ARM::ARMv95a,
ARM::ARMv96a,
ARM::ARMv97a,
ARM::IWMMXT,
ARM::IWMMXT2,
ARM::XScale,
ARM::ARMv8mMainline,
ARM::ARMv4,
ARM::ARMv5t,
ARM::ARMv5te,
ARM::ARMv5tej,
ARM::ARMv6,
ARM::ARMv6j,
ARM::ARMv6k,
ARM::ARMv6kz,
ARM::ARMv6m,
ARM::ARMv6sm,
ARM::ARMv7a,
ARM::ARMv8r,
ARM::ARMv8mBaseline,
ARM::ARMv8a,
ARM::ARMv7ve,
ARM::ARMv7s,
ARM::ARMv7m,
ARM::ARMv6t2,
ARM::ARMv7em,
ARM::ARMv7k,
ARM::ARMv7r,
ARM::FeatureAvoidPartialCPSR,
ARM::FeatureAvoidMOVsShOp,
ARM::FeatureAvoidMULS,
ARM::FeatureCheapPredicableCPSR,
ARM::FeatureCheckVLDnAlign,
ARM::FeatureNoPostRASched,
ARM::FeatureDontWidenVMOVS,
ARM::FeatureExpandMLx,
ARM::FeatureHasNoBranchPredictor,
ARM::FeatureFPAO,
ARM::FeatureFuseAES,
ARM::FeatureFuseLiterals,
ARM::FeatureMuxedUnits,
ARM::FeatureHasRetAddrStack,
ARM::FeatureSlowLoadDSubreg,
ARM::FeatureSlowOddRegister,
ARM::FeatureSlowVDUP32,
ARM::FeatureSlowVGETLNi32,
ARM::FeatureVMLxForwarding,
ARM::FeatureHasVMLxHazards,
ARM::FeatureZCZeroing,
ARM::FeatureSlowFPBrcc,
ARM::FeatureProfUnpredicate,
ARM::FeatureMVEVectorCostFactor1,
ARM::FeatureMVEVectorCostFactor2,
ARM::FeatureMVEVectorCostFactor4,
ARM::FeatureNoNegativeImmediates,
ARM::FeatureNoMovt,
ARM::FeatureNonpipelinedVFP,
ARM::FeaturePreferBranchAlign64,
ARM::FeaturePreferBranchAlign32,
ARM::FeaturePrefISHSTBarrier,
ARM::FeaturePreferVMOVSR,
ARM::FeaturePref32BitThumb,
ARM::FeatureHasSlowFPVFMx,
ARM::FeatureHasSlowFPVMLx,
ARM::FeatureUseMIPipeliner,
ARM::FeatureUseMISched,
ARM::FeatureNEONForFPMovs,
ARM::FeatureSplatVFPToNeon,
ARM::FeatureUseWideStrideVFP,
  };
  return Features;
}

const FeatureBitset &ARMGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
ARM::FeatureExecuteOnly,
  };
  return Features;
}

const FeatureBitset &ARMGenSubtargetInfo::getInlineMustMatchFeatures() const {
  static constexpr FeatureBitset Features = {
ARM::ModeBigEndianInstructions,
ARM::FeatureCoprocCDE0,
ARM::FeatureCoprocCDE1,
ARM::FeatureCoprocCDE2,
ARM::FeatureCoprocCDE3,
ARM::FeatureCoprocCDE4,
ARM::FeatureCoprocCDE5,
ARM::FeatureCoprocCDE6,
ARM::FeatureCoprocCDE7,
ARM::FeatureAAPCSFrameChain,
ARM::HasCDEOps,
ARM::FeatureAtomics32,
ARM::FeatureReadTpTPIDRPRW,
ARM::FeatureReadTpTPIDRURO,
ARM::FeatureReadTpTPIDRURW,
ARM::ModeThumb,
ARM::FeatureNoARM,
ARM::FeatureNoBTIAtReturnTwice,
ARM::ModeSoftFloat,
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

