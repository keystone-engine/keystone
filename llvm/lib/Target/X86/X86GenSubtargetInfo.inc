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

namespace X86 {

enum {
  FeatureADX = 0,
  FeatureAES = 1,
  FeatureAMXAVX512 = 2,
  FeatureAMXBF16 = 3,
  FeatureAMXCOMPLEX = 4,
  FeatureAMXFP8 = 5,
  FeatureAMXFP16 = 6,
  FeatureAMXINT8 = 7,
  FeatureAMXMOVRS = 8,
  FeatureAMXTILE = 9,
  FeatureAVX = 10,
  FeatureAVX2 = 11,
  FeatureAVX10_1 = 12,
  FeatureAVX10_1_512 = 13,
  FeatureAVX10_2 = 14,
  FeatureAVX10_2_512 = 15,
  FeatureAVX512 = 16,
  FeatureAVXIFMA = 17,
  FeatureAVXNECONVERT = 18,
  FeatureAVXVNNI = 19,
  FeatureAVXVNNIINT8 = 20,
  FeatureAVXVNNIINT16 = 21,
  FeatureBF16 = 22,
  FeatureBITALG = 23,
  FeatureBMI = 24,
  FeatureBMI2 = 25,
  FeatureBMM = 26,
  FeatureBWI = 27,
  FeatureCCMP = 28,
  FeatureCDI = 29,
  FeatureCF = 30,
  FeatureCLDEMOTE = 31,
  FeatureCLFLUSHOPT = 32,
  FeatureCLWB = 33,
  FeatureCLZERO = 34,
  FeatureCMOV = 35,
  FeatureCMPCCXADD = 36,
  FeatureCRC32 = 37,
  FeatureCX8 = 38,
  FeatureCX16 = 39,
  FeatureDQI = 40,
  FeatureEGPR = 41,
  FeatureENQCMD = 42,
  FeatureERMSB = 43,
  FeatureEVEX512 = 44,
  FeatureF16C = 45,
  FeatureFMA = 46,
  FeatureFMA4 = 47,
  FeatureFP16 = 48,
  FeatureFSGSBase = 49,
  FeatureFSRM = 50,
  FeatureFXSR = 51,
  FeatureGFNI = 52,
  FeatureHRESET = 53,
  FeatureHardenSlsIJmp = 54,
  FeatureHardenSlsRet = 55,
  FeatureIFMA = 56,
  FeatureINVPCID = 57,
  FeatureJMPABS = 58,
  FeatureKL = 59,
  FeatureLAHFSAHF64 = 60,
  FeatureLVIControlFlowIntegrity = 61,
  FeatureLVILoadHardening = 62,
  FeatureLWP = 63,
  FeatureLZCNT = 64,
  FeatureMMX = 65,
  FeatureMOVBE = 66,
  FeatureMOVDIR64B = 67,
  FeatureMOVDIRI = 68,
  FeatureMOVRS = 69,
  FeatureMWAITX = 70,
  FeatureNDD = 71,
  FeatureNF = 72,
  FeatureNOPL = 73,
  FeaturePCLMUL = 74,
  FeaturePCONFIG = 75,
  FeaturePKU = 76,
  FeaturePOPCNT = 77,
  FeaturePPX = 78,
  FeaturePREFETCHI = 79,
  FeaturePRFCHW = 80,
  FeaturePTWRITE = 81,
  FeaturePush2Pop2 = 82,
  FeatureRAOINT = 83,
  FeatureRDPID = 84,
  FeatureRDPRU = 85,
  FeatureRDRAND = 86,
  FeatureRDSEED = 87,
  FeatureRTM = 88,
  FeatureReserveEDI = 89,
  FeatureReserveR8 = 90,
  FeatureReserveR9 = 91,
  FeatureReserveR10 = 92,
  FeatureReserveR11 = 93,
  FeatureReserveR12 = 94,
  FeatureReserveR13 = 95,
  FeatureReserveR14 = 96,
  FeatureReserveR15 = 97,
  FeatureReserveR16 = 98,
  FeatureReserveR17 = 99,
  FeatureReserveR18 = 100,
  FeatureReserveR19 = 101,
  FeatureReserveR20 = 102,
  FeatureReserveR21 = 103,
  FeatureReserveR22 = 104,
  FeatureReserveR23 = 105,
  FeatureReserveR24 = 106,
  FeatureReserveR25 = 107,
  FeatureReserveR26 = 108,
  FeatureReserveR27 = 109,
  FeatureReserveR28 = 110,
  FeatureReserveR29 = 111,
  FeatureReserveR30 = 112,
  FeatureReserveR31 = 113,
  FeatureRetpoline = 114,
  FeatureRetpolineExternalThunk = 115,
  FeatureRetpolineIndirectBranches = 116,
  FeatureRetpolineIndirectCalls = 117,
  FeatureSERIALIZE = 118,
  FeatureSGX = 119,
  FeatureSHA = 120,
  FeatureSHA512 = 121,
  FeatureSHSTK = 122,
  FeatureSM3 = 123,
  FeatureSM4 = 124,
  FeatureSSE1 = 125,
  FeatureSSE2 = 126,
  FeatureSSE3 = 127,
  FeatureSSE4A = 128,
  FeatureSSE41 = 129,
  FeatureSSE42 = 130,
  FeatureSSEUnalignedMem = 131,
  FeatureSSSE3 = 132,
  FeatureSoftFloat = 133,
  FeatureSpeculativeExecutionSideEffectSuppression = 134,
  FeatureTBM = 135,
  FeatureTSXLDTRK = 136,
  FeatureTaggedGlobals = 137,
  FeatureUINTR = 138,
  FeatureUSERMSR = 139,
  FeatureUseGPR32InInlineAsm = 140,
  FeatureVAES = 141,
  FeatureVBMI = 142,
  FeatureVBMI2 = 143,
  FeatureVLX = 144,
  FeatureVNNI = 145,
  FeatureVP2INTERSECT = 146,
  FeatureVPCLMULQDQ = 147,
  FeatureVPOPCNTDQ = 148,
  FeatureWAITPKG = 149,
  FeatureWBNOINVD = 150,
  FeatureWIDEKL = 151,
  FeatureX86_64 = 152,
  FeatureX87 = 153,
  FeatureXOP = 154,
  FeatureXSAVE = 155,
  FeatureXSAVEC = 156,
  FeatureXSAVEOPT = 157,
  FeatureXSAVES = 158,
  FeatureZU = 159,
  Is16Bit = 160,
  Is32Bit = 161,
  Is64Bit = 162,
  IsX32 = 163,
  ProcIntelAtom = 164,
  TuningAllowLight256Bit = 165,
  TuningBLSFalseDeps = 166,
  TuningBranchFusion = 167,
  TuningBranchHint = 168,
  TuningCOMPRESSFalseDeps = 169,
  TuningEXPANDFalseDeps = 170,
  TuningFast7ByteNOP = 171,
  TuningFast11ByteNOP = 172,
  TuningFast15ByteNOP = 173,
  TuningFastBEXTR = 174,
  TuningFastDPWSSD = 175,
  TuningFastGather = 176,
  TuningFastHorizontalOps = 177,
  TuningFastImm16 = 178,
  TuningFastImmVectorShift = 179,
  TuningFastLZCNT = 180,
  TuningFastMOVBE = 181,
  TuningFastSHLDRotate = 182,
  TuningFastScalarFSQRT = 183,
  TuningFastScalarShiftMasks = 184,
  TuningFastVariableCrossLaneShuffle = 185,
  TuningFastVariablePerLaneShuffle = 186,
  TuningFastVectorFSQRT = 187,
  TuningFastVectorShiftMasks = 188,
  TuningGETMANTFalseDeps = 189,
  TuningInsertVZEROUPPER = 190,
  TuningLEAForSP = 191,
  TuningLEAUsesAG = 192,
  TuningLZCNTFalseDeps = 193,
  TuningMULCFalseDeps = 194,
  TuningMULLQFalseDeps = 195,
  TuningMacroFusion = 196,
  TuningNDDMem = 197,
  TuningNoDomainDelay = 198,
  TuningNoDomainDelayBlend = 199,
  TuningNoDomainDelayMov = 200,
  TuningNoDomainDelayShuffle = 201,
  TuningPERMFalseDeps = 202,
  TuningPOPCNTFalseDeps = 203,
  TuningPadShortFunctions = 204,
  TuningPrefer128Bit = 205,
  TuningPrefer256Bit = 206,
  TuningPreferLegacySetCC = 207,
  TuningPreferMaskRegisters = 208,
  TuningPreferMovmskOverVTest = 209,
  TuningPreferNoGather = 210,
  TuningPreferNoScatter = 211,
  TuningPreferShiftShuffle = 212,
  TuningRANGEFalseDeps = 213,
  TuningSBBDepBreaking = 214,
  TuningSlow3OpsLEA = 215,
  TuningSlowDivide32 = 216,
  TuningSlowDivide64 = 217,
  TuningSlowIncDec = 218,
  TuningSlowIndirectCall = 219,
  TuningSlowLEA = 220,
  TuningSlowPMADDWD = 221,
  TuningSlowPMULLD = 222,
  TuningSlowPMULLQ = 223,
  TuningSlowSHLD = 224,
  TuningSlowTwoMemOps = 225,
  TuningSlowUAMem16 = 226,
  TuningSlowUAMem32 = 227,
  TuningTZCNTFalseDeps = 228,
  TuningUseGLMDivSqrtCosts = 229,
  TuningUseSLMArithCosts = 230,
  NumSubtargetFeatures = 231
};

} // namespace X86

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(AllowLight256Bit, false, allowLight256Bit)
GET_SUBTARGETINFO_MACRO(AllowTaggedGlobals, false, allowTaggedGlobals)
GET_SUBTARGETINFO_MACRO(DeprecatedUseRetpoline, false, deprecatedUseRetpoline)
GET_SUBTARGETINFO_MACRO(FastImmVectorShift, false, fastImmVectorShift)
GET_SUBTARGETINFO_MACRO(HardenSlsIJmp, false, hardenSlsIJmp)
GET_SUBTARGETINFO_MACRO(HardenSlsRet, false, hardenSlsRet)
GET_SUBTARGETINFO_MACRO(HasADX, false, hasADX)
GET_SUBTARGETINFO_MACRO(HasAES, false, hasAES)
GET_SUBTARGETINFO_MACRO(HasAMXAVX512, false, hasAMXAVX512)
GET_SUBTARGETINFO_MACRO(HasAMXBF16, false, hasAMXBF16)
GET_SUBTARGETINFO_MACRO(HasAMXCOMPLEX, false, hasAMXCOMPLEX)
GET_SUBTARGETINFO_MACRO(HasAMXFP16, false, hasAMXFP16)
GET_SUBTARGETINFO_MACRO(HasAMXFP8, false, hasAMXFP8)
GET_SUBTARGETINFO_MACRO(HasAMXINT8, false, hasAMXINT8)
GET_SUBTARGETINFO_MACRO(HasAMXMOVRS, false, hasAMXMOVRS)
GET_SUBTARGETINFO_MACRO(HasAMXTILE, false, hasAMXTILE)
GET_SUBTARGETINFO_MACRO(HasAVX10_1, false, hasAVX10_1)
GET_SUBTARGETINFO_MACRO(HasAVX10_1_512, false, hasAVX10_1_512)
GET_SUBTARGETINFO_MACRO(HasAVX10_2, false, hasAVX10_2)
GET_SUBTARGETINFO_MACRO(HasAVX10_2_512, false, hasAVX10_2_512)
GET_SUBTARGETINFO_MACRO(HasAVXIFMA, false, hasAVXIFMA)
GET_SUBTARGETINFO_MACRO(HasAVXNECONVERT, false, hasAVXNECONVERT)
GET_SUBTARGETINFO_MACRO(HasAVXVNNI, false, hasAVXVNNI)
GET_SUBTARGETINFO_MACRO(HasAVXVNNIINT16, false, hasAVXVNNIINT16)
GET_SUBTARGETINFO_MACRO(HasAVXVNNIINT8, false, hasAVXVNNIINT8)
GET_SUBTARGETINFO_MACRO(HasBF16, false, hasBF16)
GET_SUBTARGETINFO_MACRO(HasBITALG, false, hasBITALG)
GET_SUBTARGETINFO_MACRO(HasBLSFalseDeps, false, hasBLSFalseDeps)
GET_SUBTARGETINFO_MACRO(HasBMI, false, hasBMI)
GET_SUBTARGETINFO_MACRO(HasBMI2, false, hasBMI2)
GET_SUBTARGETINFO_MACRO(HasBMM, false, hasBMM)
GET_SUBTARGETINFO_MACRO(HasBWI, false, hasBWI)
GET_SUBTARGETINFO_MACRO(HasBranchFusion, false, hasBranchFusion)
GET_SUBTARGETINFO_MACRO(HasBranchHint, false, hasBranchHint)
GET_SUBTARGETINFO_MACRO(HasCCMP, false, hasCCMP)
GET_SUBTARGETINFO_MACRO(HasCDI, false, hasCDI)
GET_SUBTARGETINFO_MACRO(HasCF, false, hasCF)
GET_SUBTARGETINFO_MACRO(HasCLDEMOTE, false, hasCLDEMOTE)
GET_SUBTARGETINFO_MACRO(HasCLFLUSHOPT, false, hasCLFLUSHOPT)
GET_SUBTARGETINFO_MACRO(HasCLWB, false, hasCLWB)
GET_SUBTARGETINFO_MACRO(HasCLZERO, false, hasCLZERO)
GET_SUBTARGETINFO_MACRO(HasCMOV, false, hasCMOV)
GET_SUBTARGETINFO_MACRO(HasCMPCCXADD, false, hasCMPCCXADD)
GET_SUBTARGETINFO_MACRO(HasCOMPRESSFalseDeps, false, hasCOMPRESSFalseDeps)
GET_SUBTARGETINFO_MACRO(HasCRC32, false, hasCRC32)
GET_SUBTARGETINFO_MACRO(HasCX16, false, hasCX16)
GET_SUBTARGETINFO_MACRO(HasCX8, false, hasCX8)
GET_SUBTARGETINFO_MACRO(HasDQI, false, hasDQI)
GET_SUBTARGETINFO_MACRO(HasEGPR, false, hasEGPR)
GET_SUBTARGETINFO_MACRO(HasENQCMD, false, hasENQCMD)
GET_SUBTARGETINFO_MACRO(HasERMSB, false, hasERMSB)
GET_SUBTARGETINFO_MACRO(HasEVEX512, false, hasEVEX512)
GET_SUBTARGETINFO_MACRO(HasEXPANDFalseDeps, false, hasEXPANDFalseDeps)
GET_SUBTARGETINFO_MACRO(HasF16C, false, hasF16C)
GET_SUBTARGETINFO_MACRO(HasFMA, false, hasFMA)
GET_SUBTARGETINFO_MACRO(HasFMA4, false, hasFMA4)
GET_SUBTARGETINFO_MACRO(HasFP16, false, hasFP16)
GET_SUBTARGETINFO_MACRO(HasFSGSBase, false, hasFSGSBase)
GET_SUBTARGETINFO_MACRO(HasFSRM, false, hasFSRM)
GET_SUBTARGETINFO_MACRO(HasFXSR, false, hasFXSR)
GET_SUBTARGETINFO_MACRO(HasFast11ByteNOP, false, hasFast11ByteNOP)
GET_SUBTARGETINFO_MACRO(HasFast15ByteNOP, false, hasFast15ByteNOP)
GET_SUBTARGETINFO_MACRO(HasFast7ByteNOP, false, hasFast7ByteNOP)
GET_SUBTARGETINFO_MACRO(HasFastBEXTR, false, hasFastBEXTR)
GET_SUBTARGETINFO_MACRO(HasFastDPWSSD, false, hasFastDPWSSD)
GET_SUBTARGETINFO_MACRO(HasFastGather, false, hasFastGather)
GET_SUBTARGETINFO_MACRO(HasFastHorizontalOps, false, hasFastHorizontalOps)
GET_SUBTARGETINFO_MACRO(HasFastImm16, false, hasFastImm16)
GET_SUBTARGETINFO_MACRO(HasFastLZCNT, false, hasFastLZCNT)
GET_SUBTARGETINFO_MACRO(HasFastMOVBE, false, hasFastMOVBE)
GET_SUBTARGETINFO_MACRO(HasFastSHLDRotate, false, hasFastSHLDRotate)
GET_SUBTARGETINFO_MACRO(HasFastScalarFSQRT, false, hasFastScalarFSQRT)
GET_SUBTARGETINFO_MACRO(HasFastScalarShiftMasks, false, hasFastScalarShiftMasks)
GET_SUBTARGETINFO_MACRO(HasFastVariableCrossLaneShuffle, false, hasFastVariableCrossLaneShuffle)
GET_SUBTARGETINFO_MACRO(HasFastVariablePerLaneShuffle, false, hasFastVariablePerLaneShuffle)
GET_SUBTARGETINFO_MACRO(HasFastVectorFSQRT, false, hasFastVectorFSQRT)
GET_SUBTARGETINFO_MACRO(HasFastVectorShiftMasks, false, hasFastVectorShiftMasks)
GET_SUBTARGETINFO_MACRO(HasGETMANTFalseDeps, false, hasGETMANTFalseDeps)
GET_SUBTARGETINFO_MACRO(HasGFNI, false, hasGFNI)
GET_SUBTARGETINFO_MACRO(HasHRESET, false, hasHRESET)
GET_SUBTARGETINFO_MACRO(HasIFMA, false, hasIFMA)
GET_SUBTARGETINFO_MACRO(HasINVPCID, false, hasINVPCID)
GET_SUBTARGETINFO_MACRO(HasJMPABS, false, hasJMPABS)
GET_SUBTARGETINFO_MACRO(HasKL, false, hasKL)
GET_SUBTARGETINFO_MACRO(HasLAHFSAHF64, false, hasLAHFSAHF64)
GET_SUBTARGETINFO_MACRO(HasLWP, false, hasLWP)
GET_SUBTARGETINFO_MACRO(HasLZCNT, false, hasLZCNT)
GET_SUBTARGETINFO_MACRO(HasLZCNTFalseDeps, false, hasLZCNTFalseDeps)
GET_SUBTARGETINFO_MACRO(HasMMX, false, hasMMX)
GET_SUBTARGETINFO_MACRO(HasMOVBE, false, hasMOVBE)
GET_SUBTARGETINFO_MACRO(HasMOVDIR64B, false, hasMOVDIR64B)
GET_SUBTARGETINFO_MACRO(HasMOVDIRI, false, hasMOVDIRI)
GET_SUBTARGETINFO_MACRO(HasMOVRS, false, hasMOVRS)
GET_SUBTARGETINFO_MACRO(HasMULCFalseDeps, false, hasMULCFalseDeps)
GET_SUBTARGETINFO_MACRO(HasMULLQFalseDeps, false, hasMULLQFalseDeps)
GET_SUBTARGETINFO_MACRO(HasMWAITX, false, hasMWAITX)
GET_SUBTARGETINFO_MACRO(HasMacroFusion, false, hasMacroFusion)
GET_SUBTARGETINFO_MACRO(HasNDD, false, hasNDD)
GET_SUBTARGETINFO_MACRO(HasNDDM, false, hasNDDM)
GET_SUBTARGETINFO_MACRO(HasNF, false, hasNF)
GET_SUBTARGETINFO_MACRO(HasNOPL, false, hasNOPL)
GET_SUBTARGETINFO_MACRO(HasPCLMUL, false, hasPCLMUL)
GET_SUBTARGETINFO_MACRO(HasPCONFIG, false, hasPCONFIG)
GET_SUBTARGETINFO_MACRO(HasPERMFalseDeps, false, hasPERMFalseDeps)
GET_SUBTARGETINFO_MACRO(HasPKU, false, hasPKU)
GET_SUBTARGETINFO_MACRO(HasPOPCNT, false, hasPOPCNT)
GET_SUBTARGETINFO_MACRO(HasPOPCNTFalseDeps, false, hasPOPCNTFalseDeps)
GET_SUBTARGETINFO_MACRO(HasPPX, false, hasPPX)
GET_SUBTARGETINFO_MACRO(HasPREFETCHI, false, hasPREFETCHI)
GET_SUBTARGETINFO_MACRO(HasPRFCHW, false, hasPRFCHW)
GET_SUBTARGETINFO_MACRO(HasPTWRITE, false, hasPTWRITE)
GET_SUBTARGETINFO_MACRO(HasPush2Pop2, false, hasPush2Pop2)
GET_SUBTARGETINFO_MACRO(HasRANGEFalseDeps, false, hasRANGEFalseDeps)
GET_SUBTARGETINFO_MACRO(HasRAOINT, false, hasRAOINT)
GET_SUBTARGETINFO_MACRO(HasRDPID, false, hasRDPID)
GET_SUBTARGETINFO_MACRO(HasRDPRU, false, hasRDPRU)
GET_SUBTARGETINFO_MACRO(HasRDRAND, false, hasRDRAND)
GET_SUBTARGETINFO_MACRO(HasRDSEED, false, hasRDSEED)
GET_SUBTARGETINFO_MACRO(HasRTM, false, hasRTM)
GET_SUBTARGETINFO_MACRO(HasSBBDepBreaking, false, hasSBBDepBreaking)
GET_SUBTARGETINFO_MACRO(HasSERIALIZE, false, hasSERIALIZE)
GET_SUBTARGETINFO_MACRO(HasSGX, false, hasSGX)
GET_SUBTARGETINFO_MACRO(HasSHA, false, hasSHA)
GET_SUBTARGETINFO_MACRO(HasSHA512, false, hasSHA512)
GET_SUBTARGETINFO_MACRO(HasSHSTK, false, hasSHSTK)
GET_SUBTARGETINFO_MACRO(HasSM3, false, hasSM3)
GET_SUBTARGETINFO_MACRO(HasSM4, false, hasSM4)
GET_SUBTARGETINFO_MACRO(HasSSE4A, false, hasSSE4A)
GET_SUBTARGETINFO_MACRO(HasSSEUnalignedMem, false, hasSSEUnalignedMem)
GET_SUBTARGETINFO_MACRO(HasSlowDivide32, false, hasSlowDivide32)
GET_SUBTARGETINFO_MACRO(HasSlowDivide64, false, hasSlowDivide64)
GET_SUBTARGETINFO_MACRO(HasTBM, false, hasTBM)
GET_SUBTARGETINFO_MACRO(HasTSXLDTRK, false, hasTSXLDTRK)
GET_SUBTARGETINFO_MACRO(HasTZCNTFalseDeps, false, hasTZCNTFalseDeps)
GET_SUBTARGETINFO_MACRO(HasUINTR, false, hasUINTR)
GET_SUBTARGETINFO_MACRO(HasUSERMSR, false, hasUSERMSR)
GET_SUBTARGETINFO_MACRO(HasVAES, false, hasVAES)
GET_SUBTARGETINFO_MACRO(HasVBMI, false, hasVBMI)
GET_SUBTARGETINFO_MACRO(HasVBMI2, false, hasVBMI2)
GET_SUBTARGETINFO_MACRO(HasVLX, false, hasVLX)
GET_SUBTARGETINFO_MACRO(HasVNNI, false, hasVNNI)
GET_SUBTARGETINFO_MACRO(HasVP2INTERSECT, false, hasVP2INTERSECT)
GET_SUBTARGETINFO_MACRO(HasVPCLMULQDQ, false, hasVPCLMULQDQ)
GET_SUBTARGETINFO_MACRO(HasVPOPCNTDQ, false, hasVPOPCNTDQ)
GET_SUBTARGETINFO_MACRO(HasWAITPKG, false, hasWAITPKG)
GET_SUBTARGETINFO_MACRO(HasWBNOINVD, false, hasWBNOINVD)
GET_SUBTARGETINFO_MACRO(HasWIDEKL, false, hasWIDEKL)
GET_SUBTARGETINFO_MACRO(HasX86_64, false, hasX86_64)
GET_SUBTARGETINFO_MACRO(HasX87, false, hasX87)
GET_SUBTARGETINFO_MACRO(HasXOP, false, hasXOP)
GET_SUBTARGETINFO_MACRO(HasXSAVE, false, hasXSAVE)
GET_SUBTARGETINFO_MACRO(HasXSAVEC, false, hasXSAVEC)
GET_SUBTARGETINFO_MACRO(HasXSAVEOPT, false, hasXSAVEOPT)
GET_SUBTARGETINFO_MACRO(HasXSAVES, false, hasXSAVES)
GET_SUBTARGETINFO_MACRO(HasZU, false, hasZU)
GET_SUBTARGETINFO_MACRO(InsertVZEROUPPER, false, insertVZEROUPPER)
GET_SUBTARGETINFO_MACRO(Is16Bit, false, is16Bit)
GET_SUBTARGETINFO_MACRO(Is32Bit, false, is32Bit)
GET_SUBTARGETINFO_MACRO(Is64Bit, false, is64Bit)
GET_SUBTARGETINFO_MACRO(IsAtom, false, isAtom)
GET_SUBTARGETINFO_MACRO(IsPMADDWDSlow, false, isPMADDWDSlow)
GET_SUBTARGETINFO_MACRO(IsPMULLDSlow, false, isPMULLDSlow)
GET_SUBTARGETINFO_MACRO(IsPMULLQSlow, false, isPMULLQSlow)
GET_SUBTARGETINFO_MACRO(IsSHLDSlow, false, isSHLDSlow)
GET_SUBTARGETINFO_MACRO(IsUnalignedMem16Slow, false, isUnalignedMem16Slow)
GET_SUBTARGETINFO_MACRO(IsUnalignedMem32Slow, false, isUnalignedMem32Slow)
GET_SUBTARGETINFO_MACRO(IsX32, false, isX32)
GET_SUBTARGETINFO_MACRO(LeaUsesAG, false, leaUsesAG)
GET_SUBTARGETINFO_MACRO(NoDomainDelay, false, noDomainDelay)
GET_SUBTARGETINFO_MACRO(NoDomainDelayBlend, false, noDomainDelayBlend)
GET_SUBTARGETINFO_MACRO(NoDomainDelayMov, false, noDomainDelayMov)
GET_SUBTARGETINFO_MACRO(NoDomainDelayShuffle, false, noDomainDelayShuffle)
GET_SUBTARGETINFO_MACRO(PadShortFunctions, false, padShortFunctions)
GET_SUBTARGETINFO_MACRO(Prefer128Bit, false, prefer128Bit)
GET_SUBTARGETINFO_MACRO(Prefer256Bit, false, prefer256Bit)
GET_SUBTARGETINFO_MACRO(PreferGather, true, preferGather)
GET_SUBTARGETINFO_MACRO(PreferLegacySetCC, false, preferLegacySetCC)
GET_SUBTARGETINFO_MACRO(PreferLowerShuffleAsShift, false, preferLowerShuffleAsShift)
GET_SUBTARGETINFO_MACRO(PreferMaskRegisters, false, preferMaskRegisters)
GET_SUBTARGETINFO_MACRO(PreferMovmskOverVTest, false, preferMovmskOverVTest)
GET_SUBTARGETINFO_MACRO(PreferScatter, true, preferScatter)
GET_SUBTARGETINFO_MACRO(Slow3OpsLEA, false, slow3OpsLEA)
GET_SUBTARGETINFO_MACRO(SlowIncDec, false, slowIncDec)
GET_SUBTARGETINFO_MACRO(SlowIndirectCall, false, slowIndirectCall)
GET_SUBTARGETINFO_MACRO(SlowLEA, false, slowLEA)
GET_SUBTARGETINFO_MACRO(SlowTwoMemOps, false, slowTwoMemOps)
GET_SUBTARGETINFO_MACRO(UseGLMDivSqrtCosts, false, useGLMDivSqrtCosts)
GET_SUBTARGETINFO_MACRO(UseInlineAsmGPR32, false, useInlineAsmGPR32)
GET_SUBTARGETINFO_MACRO(UseLVIControlFlowIntegrity, false, useLVIControlFlowIntegrity)
GET_SUBTARGETINFO_MACRO(UseLVILoadHardening, false, useLVILoadHardening)
GET_SUBTARGETINFO_MACRO(UseLeaForSP, false, useLeaForSP)
GET_SUBTARGETINFO_MACRO(UseRetpolineExternalThunk, false, useRetpolineExternalThunk)
GET_SUBTARGETINFO_MACRO(UseRetpolineIndirectBranches, false, useRetpolineIndirectBranches)
GET_SUBTARGETINFO_MACRO(UseRetpolineIndirectCalls, false, useRetpolineIndirectCalls)
GET_SUBTARGETINFO_MACRO(UseSLMArithCosts, false, useSLMArithCosts)
GET_SUBTARGETINFO_MACRO(UseSoftFloat, false, useSoftFloat)
GET_SUBTARGETINFO_MACRO(UseSpeculativeExecutionSideEffectSuppression, false, useSpeculativeExecutionSideEffectSuppression)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 230, 12651> X86FeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 230 + 1, sizeof(SubtargetFeatureKV) * 230 + 12, X86::Is16Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 229 + 32, sizeof(SubtargetFeatureKV) * 229 + 43, X86::Is32Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 228 + 63, sizeof(SubtargetFeatureKV) * 228 + 69, X86::FeatureX86_64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 227 + 97, sizeof(SubtargetFeatureKV) * 227 + 108, X86::Is64Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 226 + 129, sizeof(SubtargetFeatureKV) * 226 + 133, X86::FeatureADX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 225 + 158, sizeof(SubtargetFeatureKV) * 225 + 162, X86::FeatureAES, { { { 0x0ULL, 0x4000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 224 + 186, sizeof(SubtargetFeatureKV) * 224 + 206, X86::TuningAllowLight256Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 223 + 273, sizeof(SubtargetFeatureKV) * 223 + 284, X86::FeatureAMXAVX512, { { { 0x200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 222 + 316, sizeof(SubtargetFeatureKV) * 222 + 325, X86::FeatureAMXBF16, { { { 0x200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 221 + 355, sizeof(SubtargetFeatureKV) * 221 + 367, X86::FeatureAMXCOMPLEX, { { { 0x200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 220 + 400, sizeof(SubtargetFeatureKV) * 220 + 409, X86::FeatureAMXFP16, { { { 0x200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 219 + 443, sizeof(SubtargetFeatureKV) * 219 + 451, X86::FeatureAMXFP8, { { { 0x200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 218 + 480, sizeof(SubtargetFeatureKV) * 218 + 489, X86::FeatureAMXINT8, { { { 0x200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 217 + 519, sizeof(SubtargetFeatureKV) * 217 + 529, X86::FeatureAMXMOVRS, { { { 0x200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 216 + 560, sizeof(SubtargetFeatureKV) * 216 + 569, X86::FeatureAMXTILE, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 215 + 599, sizeof(SubtargetFeatureKV) * 215 + 603, X86::FeatureAVX, { { { 0x0ULL, 0x0ULL, 0x4ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 214 + 627, sizeof(SubtargetFeatureKV) * 214 + 635, X86::FeatureAVX10_1, { { { 0x101010020c00000ULL, 0x0ULL, 0x13c000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 213 + 663, sizeof(SubtargetFeatureKV) * 213 + 635, X86::FeatureAVX10_1_512, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 212 + 675, sizeof(SubtargetFeatureKV) * 212 + 683, X86::FeatureAVX10_2, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 211 + 711, sizeof(SubtargetFeatureKV) * 211 + 683, X86::FeatureAVX10_2_512, { { { 0x4000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 210 + 723, sizeof(SubtargetFeatureKV) * 210 + 728, X86::FeatureAVX2, { { { 0x400ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 209 + 753, sizeof(SubtargetFeatureKV) * 209 + 764, X86::FeatureBF16, { { { 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 208 + 796, sizeof(SubtargetFeatureKV) * 208 + 809, X86::FeatureBITALG, { { { 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 207 + 839, sizeof(SubtargetFeatureKV) * 207 + 849, X86::FeatureBMM, { { { 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 206 + 883, sizeof(SubtargetFeatureKV) * 206 + 892, X86::FeatureBWI, { { { 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 205 + 934, sizeof(SubtargetFeatureKV) * 205 + 943, X86::FeatureCDI, { { { 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 204 + 990, sizeof(SubtargetFeatureKV) * 204 + 999, X86::FeatureDQI, { { { 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 203 + 1051, sizeof(SubtargetFeatureKV) * 203 + 1059, X86::FeatureAVX512, { { { 0x600000000800ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 202 + 1087, sizeof(SubtargetFeatureKV) * 202 + 1098, X86::FeatureFP16, { { { 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 201 + 1128, sizeof(SubtargetFeatureKV) * 201 + 1139, X86::FeatureIFMA, { { { 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 200 + 1181, sizeof(SubtargetFeatureKV) * 200 + 1192, X86::FeatureVBMI, { { { 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 199 + 1245, sizeof(SubtargetFeatureKV) * 199 + 1257, X86::FeatureVBMI2, { { { 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 198 + 1318, sizeof(SubtargetFeatureKV) * 198 + 1327, X86::FeatureVLX, { { { 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 197 + 1367, sizeof(SubtargetFeatureKV) * 197 + 1378, X86::FeatureVNNI, { { { 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 196 + 1428, sizeof(SubtargetFeatureKV) * 196 + 1447, X86::FeatureVP2INTERSECT, { { { 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 195 + 1475, sizeof(SubtargetFeatureKV) * 195 + 1491, X86::FeatureVPOPCNTDQ, { { { 0x10000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 194 + 1536, sizeof(SubtargetFeatureKV) * 194 + 1544, X86::FeatureAVXIFMA, { { { 0x800ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 193 + 1560, sizeof(SubtargetFeatureKV) * 193 + 1573, X86::FeatureAVXNECONVERT, { { { 0x800ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 192 + 1609, sizeof(SubtargetFeatureKV) * 192 + 1617, X86::FeatureAVXVNNI, { { { 0x800ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 191 + 1643, sizeof(SubtargetFeatureKV) * 191 + 1656, X86::FeatureAVXVNNIINT16, { { { 0x800ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 190 + 1678, sizeof(SubtargetFeatureKV) * 190 + 1690, X86::FeatureAVXVNNIINT8, { { { 0x800ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 189 + 1711, sizeof(SubtargetFeatureKV) * 189 + 1715, X86::FeatureBMI, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 188 + 1740, sizeof(SubtargetFeatureKV) * 188 + 1745, X86::FeatureBMI2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 187 + 1771, sizeof(SubtargetFeatureKV) * 187 + 1783, X86::TuningBranchHint, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 186 + 1814, sizeof(SubtargetFeatureKV) * 186 + 1827, X86::TuningBranchFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 185 + 1875, sizeof(SubtargetFeatureKV) * 185 + 1880, X86::FeatureCCMP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 184 + 1924, sizeof(SubtargetFeatureKV) * 184 + 1927, X86::FeatureCF, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 183 + 1956, sizeof(SubtargetFeatureKV) * 183 + 1965, X86::FeatureCLDEMOTE, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 182 + 1990, sizeof(SubtargetFeatureKV) * 182 + 2001, X86::FeatureCLFLUSHOPT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 181 + 2030, sizeof(SubtargetFeatureKV) * 181 + 2035, X86::FeatureCLWB, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 180 + 2057, sizeof(SubtargetFeatureKV) * 180 + 2064, X86::FeatureCLZERO, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 179 + 2087, sizeof(SubtargetFeatureKV) * 179 + 2092, X86::FeatureCMOV, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 178 + 2129, sizeof(SubtargetFeatureKV) * 178 + 2139, X86::FeatureCMPCCXADD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 177 + 2170, sizeof(SubtargetFeatureKV) * 177 + 2176, X86::FeatureCRC32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 176 + 2266, sizeof(SubtargetFeatureKV) * 176 + 2271, X86::FeatureCX16, { { { 0x4000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 175 + 2360, sizeof(SubtargetFeatureKV) * 175 + 2364, X86::FeatureCX8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 174 + 2395, sizeof(SubtargetFeatureKV) * 174 + 2400, X86::FeatureEGPR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 173 + 2442, sizeof(SubtargetFeatureKV) * 173 + 2449, X86::FeatureENQCMD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 172 + 2473, sizeof(SubtargetFeatureKV) * 172 + 2479, X86::FeatureERMSB, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 171 + 2502, sizeof(SubtargetFeatureKV) * 171 + 2510, X86::FeatureEVEX512, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 170 + 2551, sizeof(SubtargetFeatureKV) * 170 + 2556, X86::FeatureF16C, { { { 0x400ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 169 + 2610, sizeof(SubtargetFeatureKV) * 169 + 2625, X86::TuningBLSFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 168 + 2683, sizeof(SubtargetFeatureKV) * 168 + 2703, X86::TuningCOMPRESSFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 167 + 2787, sizeof(SubtargetFeatureKV) * 167 + 2805, X86::TuningEXPANDFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 166 + 2887, sizeof(SubtargetFeatureKV) * 166 + 2906, X86::TuningGETMANTFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 165 + 2997, sizeof(SubtargetFeatureKV) * 165 + 3014, X86::TuningLZCNTFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 164 + 3060, sizeof(SubtargetFeatureKV) * 164 + 3076, X86::TuningMULCFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 163 + 3131, sizeof(SubtargetFeatureKV) * 163 + 3148, X86::TuningMULLQFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 162 + 3196, sizeof(SubtargetFeatureKV) * 162 + 3212, X86::TuningPERMFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 161 + 3267, sizeof(SubtargetFeatureKV) * 161 + 3285, X86::TuningPOPCNTFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 160 + 3332, sizeof(SubtargetFeatureKV) * 160 + 3349, X86::TuningRANGEFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 159 + 3407, sizeof(SubtargetFeatureKV) * 159 + 3424, X86::TuningTZCNTFalseDeps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 158 + 3470, sizeof(SubtargetFeatureKV) * 158 + 3485, X86::TuningFast11ByteNOP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 157 + 3530, sizeof(SubtargetFeatureKV) * 157 + 3545, X86::TuningFast15ByteNOP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 156 + 3590, sizeof(SubtargetFeatureKV) * 156 + 3604, X86::TuningFast7ByteNOP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 155 + 3648, sizeof(SubtargetFeatureKV) * 155 + 3659, X86::TuningFastBEXTR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 154 + 3748, sizeof(SubtargetFeatureKV) * 154 + 3760, X86::TuningFastDPWSSD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 153 + 3830, sizeof(SubtargetFeatureKV) * 153 + 3842, X86::TuningFastGather, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 152 + 3936, sizeof(SubtargetFeatureKV) * 152 + 3946, X86::TuningFastHorizontalOps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 151 + 4056, sizeof(SubtargetFeatureKV) * 151 + 4067, X86::TuningFastImm16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 150 + 4133, sizeof(SubtargetFeatureKV) * 150 + 4144, X86::TuningFastLZCNT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 149 + 4202, sizeof(SubtargetFeatureKV) * 149 + 4213, X86::TuningFastMOVBE, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 148 + 4286, sizeof(SubtargetFeatureKV) * 148 + 4304, X86::TuningFastScalarFSQRT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 147 + 4349, sizeof(SubtargetFeatureKV) * 147 + 4373, X86::TuningFastScalarShiftMasks, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 146 + 4441, sizeof(SubtargetFeatureKV) * 146 + 4458, X86::TuningFastSHLDRotate, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 145 + 4494, sizeof(SubtargetFeatureKV) * 145 + 4526, X86::TuningFastVariableCrossLaneShuffle, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 144 + 4575, sizeof(SubtargetFeatureKV) * 144 + 4605, X86::TuningFastVariablePerLaneShuffle, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 143 + 4652, sizeof(SubtargetFeatureKV) * 143 + 4670, X86::TuningFastVectorFSQRT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 142 + 4715, sizeof(SubtargetFeatureKV) * 142 + 4739, X86::TuningFastVectorShiftMasks, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 141 + 4807, sizeof(SubtargetFeatureKV) * 141 + 4833, X86::TuningPreferShiftShuffle, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 140 + 4875, sizeof(SubtargetFeatureKV) * 140 + 4879, X86::FeatureFMA, { { { 0x400ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 139 + 4919, sizeof(SubtargetFeatureKV) * 139 + 4924, X86::FeatureFMA4, { { { 0x400ULL, 0x0ULL, 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 138 + 4963, sizeof(SubtargetFeatureKV) * 138 + 4972, X86::FeatureFSGSBase, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 137 + 5004, sizeof(SubtargetFeatureKV) * 137 + 5009, X86::FeatureFSRM, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 136 + 5046, sizeof(SubtargetFeatureKV) * 136 + 5051, X86::FeatureFXSR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 135 + 5089, sizeof(SubtargetFeatureKV) * 135 + 5094, X86::FeatureGFNI, { { { 0x0ULL, 0x4000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 134 + 5138, sizeof(SubtargetFeatureKV) * 134 + 5154, X86::FeatureHardenSlsIJmp, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 133 + 5229, sizeof(SubtargetFeatureKV) * 133 + 5244, X86::FeatureHardenSlsRet, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 132 + 5310, sizeof(SubtargetFeatureKV) * 132 + 5317, X86::FeatureHRESET, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 131 + 5340, sizeof(SubtargetFeatureKV) * 131 + 5354, X86::TuningSlowDivide32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 130 + 5405, sizeof(SubtargetFeatureKV) * 130 + 5419, X86::TuningSlowDivide64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 129 + 5472, sizeof(SubtargetFeatureKV) * 129 + 5493, X86::FeatureUseGPR32InInlineAsm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 128 + 5540, sizeof(SubtargetFeatureKV) * 128 + 5548, X86::FeatureINVPCID, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 127 + 5586, sizeof(SubtargetFeatureKV) * 127 + 5593, X86::FeatureJMPABS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 126 + 5621, sizeof(SubtargetFeatureKV) * 126 + 5624, X86::FeatureKL, { { { 0x0ULL, 0x4000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 125 + 5659, sizeof(SubtargetFeatureKV) * 125 + 5666, X86::TuningLEAForSP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 124 + 5758, sizeof(SubtargetFeatureKV) * 124 + 5770, X86::TuningLEAUsesAG, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 123 + 5811, sizeof(SubtargetFeatureKV) * 123 + 5819, X86::FeatureLVIControlFlowIntegrity, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 122 + 6054, sizeof(SubtargetFeatureKV) * 122 + 6073, X86::FeatureLVILoadHardening, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 121 + 6179, sizeof(SubtargetFeatureKV) * 121 + 6183, X86::FeatureLWP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 120 + 6207, sizeof(SubtargetFeatureKV) * 120 + 6213, X86::FeatureLZCNT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 119 + 6239, sizeof(SubtargetFeatureKV) * 119 + 6251, X86::TuningMacroFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 118 + 6311, sizeof(SubtargetFeatureKV) * 118 + 6315, X86::FeatureMMX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 117 + 6339, sizeof(SubtargetFeatureKV) * 117 + 6345, X86::FeatureMOVBE, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 116 + 6371, sizeof(SubtargetFeatureKV) * 116 + 6381, X86::FeatureMOVDIR64B, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 115 + 6435, sizeof(SubtargetFeatureKV) * 115 + 6443, X86::FeatureMOVDIRI, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 114 + 6494, sizeof(SubtargetFeatureKV) * 114 + 6500, X86::FeatureMOVRS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 113 + 6513, sizeof(SubtargetFeatureKV) * 113 + 6520, X86::FeatureMWAITX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 112 + 6563, sizeof(SubtargetFeatureKV) * 112 + 6567, X86::FeatureNDD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 111 + 6603, sizeof(SubtargetFeatureKV) * 111 + 6606, X86::FeatureNF, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 110 + 6646, sizeof(SubtargetFeatureKV) * 110 + 6662, X86::TuningNoDomainDelay, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 109 + 6712, sizeof(SubtargetFeatureKV) * 109 + 6734, X86::TuningNoDomainDelayBlend, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 108 + 6788, sizeof(SubtargetFeatureKV) * 108 + 6808, X86::TuningNoDomainDelayMov, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 107 + 6860, sizeof(SubtargetFeatureKV) * 107 + 6884, X86::TuningNoDomainDelayShuffle, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 106 + 6940, sizeof(SubtargetFeatureKV) * 106 + 6945, X86::FeatureNOPL, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 105 + 6994, sizeof(SubtargetFeatureKV) * 105 + 7014, X86::TuningPadShortFunctions, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 104 + 7080, sizeof(SubtargetFeatureKV) * 104 + 7087, X86::FeaturePCLMUL, { { { 0x0ULL, 0x4000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 103 + 7140, sizeof(SubtargetFeatureKV) * 103 + 7148, X86::FeaturePCONFIG, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 102 + 7183, sizeof(SubtargetFeatureKV) * 102 + 7187, X86::FeaturePKU, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 101 + 7210, sizeof(SubtargetFeatureKV) * 101 + 7217, X86::FeaturePOPCNT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 100 + 7244, sizeof(SubtargetFeatureKV) * 100 + 7248, X86::FeaturePPX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 99 + 7278, sizeof(SubtargetFeatureKV) * 99 + 7293, X86::TuningPrefer128Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 98 + 7325, sizeof(SubtargetFeatureKV) * 98 + 7340, X86::TuningPrefer256Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 97 + 7372, sizeof(SubtargetFeatureKV) * 97 + 7392, X86::TuningPreferLegacySetCC, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 96 + 7421, sizeof(SubtargetFeatureKV) * 96 + 7443, X86::TuningPreferMaskRegisters, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 95 + 7490, sizeof(SubtargetFeatureKV) * 95 + 7515, X86::TuningPreferMovmskOverVTest, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 94 + 7552, sizeof(SubtargetFeatureKV) * 94 + 7567, X86::TuningNDDMem, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 93 + 7596, sizeof(SubtargetFeatureKV) * 93 + 7613, X86::TuningPreferNoGather, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 92 + 7643, sizeof(SubtargetFeatureKV) * 92 + 7661, X86::TuningPreferNoScatter, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 91 + 7692, sizeof(SubtargetFeatureKV) * 91 + 7702, X86::FeaturePREFETCHI, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 90 + 7742, sizeof(SubtargetFeatureKV) * 90 + 7749, X86::FeaturePRFCHW, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 89 + 7777, sizeof(SubtargetFeatureKV) * 89 + 7785, X86::FeaturePTWRITE, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 88 + 7813, sizeof(SubtargetFeatureKV) * 88 + 7823, X86::FeaturePush2Pop2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 87 + 7855, sizeof(SubtargetFeatureKV) * 87 + 7862, X86::FeatureRAOINT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 86 + 7891, sizeof(SubtargetFeatureKV) * 86 + 7897, X86::FeatureRDPID, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 85 + 7924, sizeof(SubtargetFeatureKV) * 85 + 7930, X86::FeatureRDPRU, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 84 + 7957, sizeof(SubtargetFeatureKV) * 84 + 7963, X86::FeatureRDRAND, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 83 + 7990, sizeof(SubtargetFeatureKV) * 83 + 7997, X86::FeatureRDSEED, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 82 + 8024, sizeof(SubtargetFeatureKV) * 82 + 8036, X86::FeatureReserveEDI, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 81 + 8080, sizeof(SubtargetFeatureKV) * 81 + 8092, X86::FeatureReserveR10, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 80 + 8136, sizeof(SubtargetFeatureKV) * 80 + 8148, X86::FeatureReserveR11, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 79 + 8192, sizeof(SubtargetFeatureKV) * 79 + 8204, X86::FeatureReserveR12, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 78 + 8248, sizeof(SubtargetFeatureKV) * 78 + 8260, X86::FeatureReserveR13, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 77 + 8304, sizeof(SubtargetFeatureKV) * 77 + 8316, X86::FeatureReserveR14, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 76 + 8360, sizeof(SubtargetFeatureKV) * 76 + 8372, X86::FeatureReserveR15, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 75 + 8416, sizeof(SubtargetFeatureKV) * 75 + 8428, X86::FeatureReserveR16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 74 + 8472, sizeof(SubtargetFeatureKV) * 74 + 8484, X86::FeatureReserveR17, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 73 + 8528, sizeof(SubtargetFeatureKV) * 73 + 8540, X86::FeatureReserveR18, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 72 + 8584, sizeof(SubtargetFeatureKV) * 72 + 8596, X86::FeatureReserveR19, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 71 + 8640, sizeof(SubtargetFeatureKV) * 71 + 8652, X86::FeatureReserveR20, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 70 + 8696, sizeof(SubtargetFeatureKV) * 70 + 8708, X86::FeatureReserveR21, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 69 + 8752, sizeof(SubtargetFeatureKV) * 69 + 8764, X86::FeatureReserveR22, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 68 + 8808, sizeof(SubtargetFeatureKV) * 68 + 8820, X86::FeatureReserveR23, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 67 + 8864, sizeof(SubtargetFeatureKV) * 67 + 8876, X86::FeatureReserveR24, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 66 + 8920, sizeof(SubtargetFeatureKV) * 66 + 8932, X86::FeatureReserveR25, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 65 + 8976, sizeof(SubtargetFeatureKV) * 65 + 8988, X86::FeatureReserveR26, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 64 + 9032, sizeof(SubtargetFeatureKV) * 64 + 9044, X86::FeatureReserveR27, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 63 + 9088, sizeof(SubtargetFeatureKV) * 63 + 9100, X86::FeatureReserveR28, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 62 + 9144, sizeof(SubtargetFeatureKV) * 62 + 9156, X86::FeatureReserveR29, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 61 + 9200, sizeof(SubtargetFeatureKV) * 61 + 9212, X86::FeatureReserveR30, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 60 + 9256, sizeof(SubtargetFeatureKV) * 60 + 9268, X86::FeatureReserveR31, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 59 + 9312, sizeof(SubtargetFeatureKV) * 59 + 9323, X86::FeatureReserveR8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 58 + 9366, sizeof(SubtargetFeatureKV) * 58 + 9377, X86::FeatureReserveR9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 57 + 9420, sizeof(SubtargetFeatureKV) * 57 + 9430, X86::FeatureRetpoline, { { { 0x0ULL, 0x30000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 56 + 9583, sizeof(SubtargetFeatureKV) * 56 + 9608, X86::FeatureRetpolineExternalThunk, { { { 0x0ULL, 0x20000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 55 + 9812, sizeof(SubtargetFeatureKV) * 55 + 9840, X86::FeatureRetpolineIndirectBranches, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 54 + 9904, sizeof(SubtargetFeatureKV) * 54 + 9929, X86::FeatureRetpolineIndirectCalls, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 53 + 9990, sizeof(SubtargetFeatureKV) * 53 + 9994, X86::FeatureRTM, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 52 + 10019, sizeof(SubtargetFeatureKV) * 52 + 10024, X86::FeatureLAHFSAHF64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 51 + 10074, sizeof(SubtargetFeatureKV) * 51 + 10091, X86::TuningSBBDepBreaking, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 50 + 10139, sizeof(SubtargetFeatureKV) * 50 + 10149, X86::FeatureSERIALIZE, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 49 + 10175, sizeof(SubtargetFeatureKV) * 49 + 10181, X86::FeatureSpeculativeExecutionSideEffectSuppression, { { { 0x2000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 48 + 10372, sizeof(SubtargetFeatureKV) * 48 + 10376, X86::FeatureSGX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 47 + 10409, sizeof(SubtargetFeatureKV) * 47 + 10413, X86::FeatureSHA, { { { 0x0ULL, 0x4000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 46 + 10437, sizeof(SubtargetFeatureKV) * 46 + 10444, X86::FeatureSHA512, { { { 0x800ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 45 + 10472, sizeof(SubtargetFeatureKV) * 45 + 10478, X86::FeatureSHSTK, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 44 + 10516, sizeof(SubtargetFeatureKV) * 44 + 10530, X86::TuningSlow3OpsLEA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 43 + 10586, sizeof(SubtargetFeatureKV) * 43 + 10598, X86::TuningSlowIncDec, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 42 + 10651, sizeof(SubtargetFeatureKV) * 42 + 10670, X86::TuningSlowIndirectCall, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 41 + 10706, sizeof(SubtargetFeatureKV) * 41 + 10715, X86::TuningSlowLEA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 40 + 10762, sizeof(SubtargetFeatureKV) * 40 + 10775, X86::TuningSlowPMADDWD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 39 + 10805, sizeof(SubtargetFeatureKV) * 39 + 10817, X86::TuningSlowPMULLD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 38 + 10884, sizeof(SubtargetFeatureKV) * 38 + 10896, X86::TuningSlowPMULLQ, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 10923, sizeof(SubtargetFeatureKV) * 37 + 10933, X86::TuningSlowSHLD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 10958, sizeof(SubtargetFeatureKV) * 36 + 10975, X86::TuningSlowTwoMemOps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 11016, sizeof(SubtargetFeatureKV) * 35 + 11038, X86::TuningSlowUAMem16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 11075, sizeof(SubtargetFeatureKV) * 34 + 11097, X86::TuningSlowUAMem32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 11134, sizeof(SubtargetFeatureKV) * 33 + 11138, X86::FeatureSM3, { { { 0x400ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 11163, sizeof(SubtargetFeatureKV) * 32 + 11167, X86::FeatureSM4, { { { 0x800ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 11192, sizeof(SubtargetFeatureKV) * 31 + 11203, X86::FeatureSoftFloat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 11240, sizeof(SubtargetFeatureKV) * 30 + 11244, X86::FeatureSSE1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 11268, sizeof(SubtargetFeatureKV) * 29 + 11286, X86::FeatureSSEUnalignedMem, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 11404, sizeof(SubtargetFeatureKV) * 28 + 11409, X86::FeatureSSE2, { { { 0x0ULL, 0x2000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 11434, sizeof(SubtargetFeatureKV) * 27 + 11439, X86::FeatureSSE3, { { { 0x0ULL, 0x4000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 11464, sizeof(SubtargetFeatureKV) * 26 + 11471, X86::FeatureSSE41, { { { 0x0ULL, 0x0ULL, 0x10ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 11499, sizeof(SubtargetFeatureKV) * 25 + 11506, X86::FeatureSSE42, { { { 0x0ULL, 0x0ULL, 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 11534, sizeof(SubtargetFeatureKV) * 24 + 11540, X86::FeatureSSE4A, { { { 0x0ULL, 0x8000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 11568, sizeof(SubtargetFeatureKV) * 23 + 11574, X86::FeatureSSSE3, { { { 0x0ULL, 0x8000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 11600, sizeof(SubtargetFeatureKV) * 22 + 11615, X86::FeatureTaggedGlobals, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 11730, sizeof(SubtargetFeatureKV) * 21 + 11734, X86::FeatureTBM, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 11758, sizeof(SubtargetFeatureKV) * 20 + 11767, X86::FeatureTSXLDTRK, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 11797, sizeof(SubtargetFeatureKV) * 19 + 11826, X86::TuningFastImmVectorShift, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 11888, sizeof(SubtargetFeatureKV) * 18 + 11894, X86::FeatureUINTR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 11917, sizeof(SubtargetFeatureKV) * 17 + 11940, X86::TuningUseGLMDivSqrtCosts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 11992, sizeof(SubtargetFeatureKV) * 16 + 12012, X86::TuningUseSLMArithCosts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 12053, sizeof(SubtargetFeatureKV) * 15 + 12061, X86::FeatureUSERMSR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 12090, sizeof(SubtargetFeatureKV) * 14 + 12095, X86::FeatureVAES, { { { 0x802ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 12153, sizeof(SubtargetFeatureKV) * 13 + 12164, X86::FeatureVPCLMULQDQ, { { { 0x400ULL, 0x400ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 12195, sizeof(SubtargetFeatureKV) * 12 + 12206, X86::TuningInsertVZEROUPPER, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 12244, sizeof(SubtargetFeatureKV) * 11 + 12252, X86::FeatureWAITPKG, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 12280, sizeof(SubtargetFeatureKV) * 10 + 12289, X86::FeatureWBNOINVD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 12314, sizeof(SubtargetFeatureKV) * 9 + 12321, X86::FeatureWIDEKL, { { { 0x800000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 12358, sizeof(SubtargetFeatureKV) * 8 + 12362, X86::IsX32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 12413, sizeof(SubtargetFeatureKV) * 7 + 12417, X86::FeatureX87, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 12447, sizeof(SubtargetFeatureKV) * 6 + 12451, X86::FeatureXOP, { { { 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 12475, sizeof(SubtargetFeatureKV) * 5 + 12481, X86::FeatureXSAVE, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 12508, sizeof(SubtargetFeatureKV) * 4 + 12515, X86::FeatureXSAVEC, { { { 0x0ULL, 0x0ULL, 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 12543, sizeof(SubtargetFeatureKV) * 3 + 12552, X86::FeatureXSAVEOPT, { { { 0x0ULL, 0x0ULL, 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 12582, sizeof(SubtargetFeatureKV) * 2 + 12589, X86::FeatureXSAVES, { { { 0x0ULL, 0x0ULL, 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 12617, sizeof(SubtargetFeatureKV) * 1 + 12620, X86::FeatureZU, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000" "16bit-mode\000" "16-bit mode (i8086)\000" "32bit-mode\000" "32-b"
    "it mode (80386)\000" "64bit\000Support 64-bit instructions\000" "64bit-"
    "mode\000" "64-bit mode (x86_64)\000adx\000Support ADX instructions\000a"
    "es\000Enable AES instructions\000allow-light-256-bit\000Enable generati"
    "on of 256-bit load/stores even if we prefer 128-bit\000amx-avx512\000Su"
    "pport AMX-AVX512 instructions\000amx-bf16\000Support AMX-BF16 instructi"
    "ons\000amx-complex\000Support AMX-COMPLEX instructions\000amx-fp16\000S"
    "upport AMX amx-fp16 instructions\000amx-fp8\000Support AMX-FP8 instruct"
    "ions\000amx-int8\000Support AMX-INT8 instructions\000amx-movrs\000Suppo"
    "rt AMX-MOVRS instructions\000amx-tile\000Support AMX-TILE instructions\000"
    "avx\000Enable AVX instructions\000avx10.1\000Support AVX10.1 instructio"
    "n\000avx10.1-512\000avx10.2\000Support AVX10.2 instruction\000avx10.2-5"
    "12\000avx2\000Enable AVX2 instructions\000avx512bf16\000Support bfloat1"
    "6 floating point\000avx512bitalg\000Enable AVX-512 Bit Algorithms\000av"
    "x512bmm\000Enable AVX512 Bit Matrix Multiply\000avx512bw\000Enable AVX-"
    "512 Byte and Word Instructions\000avx512cd\000Enable AVX-512 Conflict D"
    "etection Instructions\000avx512dq\000Enable AVX-512 Doubleword and Quad"
    "word Instructions\000avx512f\000Enable AVX-512 instructions\000avx512fp"
    "16\000Support 16-bit floating point\000avx512ifma\000Enable AVX-512 Int"
    "eger Fused Multiple-Add\000avx512vbmi\000Enable AVX-512 Vector Byte Man"
    "ipulation Instructions\000avx512vbmi2\000Enable AVX-512 further Vector "
    "Byte Manipulation Instructions\000avx512vl\000Enable AVX-512 Vector Len"
    "gth eXtensions\000avx512vnni\000Enable AVX-512 Vector Neural Network In"
    "structions\000avx512vp2intersect\000Enable AVX-512 vp2intersect\000avx5"
    "12vpopcntdq\000Enable AVX-512 Population Count Instructions\000avxifma\000"
    "Enable AVX-IFMA\000avxneconvert\000Support AVX-NE-CONVERT instructions\000"
    "avxvnni\000Support AVX_VNNI encoding\000avxvnniint16\000Enable AVX-VNNI"
    "-INT16\000avxvnniint8\000Enable AVX-VNNI-INT8\000bmi\000Support BMI ins"
    "tructions\000bmi2\000Support BMI2 instructions\000branch-hint\000Target"
    " has branch hint feature\000branchfusion\000CMP/TEST can be fused with "
    "conditional branches\000ccmp\000Support conditional cmp & test instruct"
    "ions\000cf\000Support conditional faulting\000cldemote\000Enable Cache "
    "Line Demote\000clflushopt\000Flush A Cache Line Optimized\000clwb\000Ca"
    "che Line Write Back\000clzero\000Enable Cache Line Zero\000cmov\000Enab"
    "le conditional move instructions\000cmpccxadd\000Support CMPCCXADD inst"
    "ructions\000crc32\000Enable SSE 4.2 CRC32 instruction (used when SSE4.2"
    " is supported but function is GPR only)\000cx16\000" "64-bit with cmpxc"
    "hg16b (this is true for most x86-64 chips, but not the first AMD chips)"
    "\000cx8\000Support CMPXCHG8B instructions\000egpr\000Support extended g"
    "eneral purpose register\000enqcmd\000Has ENQCMD instructions\000ermsb\000"
    "REP MOVS/STOS are fast\000evex512\000Support ZMM and 64-bit mask instru"
    "ctions\000f16c\000Support 16-bit floating point conversion instructions"
    "\000false-deps-bls\000BLSR/BLSI/BLSMSK have a false dependency on dest "
    "register\000false-deps-compress\000V[P]COMPRESSPD/PS/Q/D/W/B with zero-"
    "masking has a false dependency on dest register\000false-deps-expand\000"
    "V[P]EXPANDPD/PS/Q/D/W/B with zero-masking has a false dependency on des"
    "t register\000false-deps-getmant\000VGETMANTSS/SD/SH and VGETMANDPS/PD("
    "memory version) has a false dependency on dest register\000false-deps-l"
    "zcnt\000LZCNT has a false dependency on dest register\000false-deps-mul"
    "c\000VF[C]MULCPH/SH has a false dependency on dest register\000false-de"
    "ps-mullq\000VPMULLQ has a false dependency on dest register\000false-de"
    "ps-perm\000VPERMD/Q/PS/PD has a false dependency on dest register\000fa"
    "lse-deps-popcnt\000POPCNT has a false dependency on dest register\000fa"
    "lse-deps-range\000VRANGEPD/PS/SD/SS has a false dependency on dest regi"
    "ster\000false-deps-tzcnt\000TZCNT has a false dependency on dest regist"
    "er\000fast-11bytenop\000Target can quickly decode up to 11 byte NOPs\000"
    "fast-15bytenop\000Target can quickly decode up to 15 byte NOPs\000fast-"
    "7bytenop\000Target can quickly decode up to 7 byte NOPs\000fast-bextr\000"
    "Indicates that the BEXTR instruction is implemented as a single uop wit"
    "h good throughput\000fast-dpwssd\000Prefer vpdpwssd instruction over vp"
    "maddwd+vpaddd instruction sequence\000fast-gather\000Indicates if gathe"
    "r is reasonably fast (this is true for Skylake client and all AVX-512 C"
    "PUs)\000fast-hops\000Prefer horizontal vector math instructions (haddp,"
    " phsub, etc.) over normal vector instructions with shuffles\000fast-imm"
    "16\000Prefer a i16 instruction with i16 immediate over extension to i32"
    "\000fast-lzcnt\000LZCNT instructions are as fast as most simple integer"
    " ops\000fast-movbe\000Prefer a movbe over a single-use load + bswap / s"
    "ingle-use bswap + store\000fast-scalar-fsqrt\000Scalar SQRT is fast (di"
    "sable Newton-Raphson)\000fast-scalar-shift-masks\000Prefer a left/right"
    " scalar logical shift pair over a shift+and pair\000fast-shld-rotate\000"
    "SHLD can be used as a faster rotate\000fast-variable-crosslane-shuffle\000"
    "Cross-lane shuffles with variable masks are fast\000fast-variable-perla"
    "ne-shuffle\000Per-lane shuffles with variable masks are fast\000fast-ve"
    "ctor-fsqrt\000Vector SQRT is fast (disable Newton-Raphson)\000fast-vect"
    "or-shift-masks\000Prefer a left/right vector logical shift pair over a "
    "shift+and pair\000faster-shift-than-shuffle\000Shifts are faster (or as"
    " fast) as shuffle\000fma\000Enable three-operand fused multiple-add\000"
    "fma4\000Enable four-operand fused multiple-add\000fsgsbase\000Support F"
    "S/GS Base instructions\000fsrm\000REP MOVSB of short lengths is faster\000"
    "fxsr\000Support fxsave/fxrestore instructions\000gfni\000Enable Galois "
    "Field Arithmetic Instructions\000harden-sls-ijmp\000Harden against stra"
    "ight line speculation across indirect JMP instructions.\000harden-sls-r"
    "et\000Harden against straight line speculation across RET instructions."
    "\000hreset\000Has hreset instruction\000idivl-to-divb\000Use 8-bit divi"
    "de for positive values less than 256\000idivq-to-divl\000Use 32-bit div"
    "ide for positive values less than 2^32\000inline-asm-use-gpr32\000Enabl"
    "e use of GPR32 in inline assembly for APX\000invpcid\000Invalidate Proc"
    "ess-Context Identifier\000jmpabs\000Support 64-bit absolute JMP\000kl\000"
    "Support Key Locker kl Instructions\000lea-sp\000Use LEA for adjusting t"
    "he stack pointer (this is an optimization for Intel Atom processors)\000"
    "lea-uses-ag\000LEA instruction needs inputs at AG stage\000lvi-cfi\000P"
    "revent indirect calls/branches from using a memory operand, and precede"
    " all indirect calls/branches from a register with an LFENCE instruction"
    " to serialize control flow. Also decompose RET instructions into a POP+"
    "LFENCE+JMP sequence.\000lvi-load-hardening\000Insert LFENCE instruction"
    "s to prevent data speculatively injected into loads from being used mal"
    "iciously.\000lwp\000Enable LWP instructions\000lzcnt\000Support LZCNT i"
    "nstruction\000macrofusion\000Various instructions can be fused with con"
    "ditional branches\000mmx\000Enable MMX instructions\000movbe\000Support"
    " MOVBE instruction\000movdir64b\000Support movdir64b instruction (direc"
    "t store 64 bytes)\000movdiri\000Support movdiri instruction (direct sto"
    "re integer)\000movrs\000Enable MOVRS\000mwaitx\000Enable MONITORX/MWAIT"
    "X timer functionality\000ndd\000Support non-destructive destination\000"
    "nf\000Support status flags update suppression\000no-bypass-delay\000Has"
    " no bypass delay when using the 'wrong' domain\000no-bypass-delay-blend"
    "\000Has no bypass delay when using the 'wrong' blend type\000no-bypass-"
    "delay-mov\000Has no bypass delay when using the 'wrong' mov type\000no-"
    "bypass-delay-shuffle\000Has no bypass delay when using the 'wrong' shuf"
    "fle type\000nopl\000Enable NOPL instruction (generally pentium pro+)\000"
    "pad-short-functions\000Pad short functions (to prevent a stall when ret"
    "urning too early)\000pclmul\000Enable packed carry-less multiplication "
    "instructions\000pconfig\000platform configuration instruction\000pku\000"
    "Enable protection keys\000popcnt\000Support POPCNT instruction\000ppx\000"
    "Support Push-Pop Acceleration\000prefer-128-bit\000Prefer 128-bit AVX i"
    "nstructions\000prefer-256-bit\000Prefer 256-bit AVX instructions\000pre"
    "fer-legacy-setcc\000Prefer to emit legacy SetCC.\000prefer-mask-registe"
    "rs\000Prefer AVX512 mask registers over PTEST/MOVMSK\000prefer-movmsk-o"
    "ver-vtest\000Prefer movmsk over vtest instruction\000prefer-ndd-mem\000"
    "Prefer NDD memory addressing\000prefer-no-gather\000Prefer no gather in"
    "structions\000prefer-no-scatter\000Prefer no scatter instructions\000pr"
    "efetchi\000Prefetch instruction with T0 or T1 Hint\000prfchw\000Support"
    " PRFCHW instructions\000ptwrite\000Support ptwrite instruction\000push2"
    "pop2\000Support PUSH2/POP2 instructions\000raoint\000Support RAO-INT in"
    "structions\000rdpid\000Support RDPID instructions\000rdpru\000Support R"
    "DPRU instructions\000rdrnd\000Support RDRAND instruction\000rdseed\000S"
    "upport RDSEED instruction\000reserve-edi\000Reserve EDI, making it unav"
    "ailable as a GPR\000reserve-r10\000Reserve R10, making it unavailable a"
    "s a GPR\000reserve-r11\000Reserve R11, making it unavailable as a GPR\000"
    "reserve-r12\000Reserve R12, making it unavailable as a GPR\000reserve-r"
    "13\000Reserve R13, making it unavailable as a GPR\000reserve-r14\000Res"
    "erve R14, making it unavailable as a GPR\000reserve-r15\000Reserve R15,"
    " making it unavailable as a GPR\000reserve-r16\000Reserve R16, making i"
    "t unavailable as a GPR\000reserve-r17\000Reserve R17, making it unavail"
    "able as a GPR\000reserve-r18\000Reserve R18, making it unavailable as a"
    " GPR\000reserve-r19\000Reserve R19, making it unavailable as a GPR\000r"
    "eserve-r20\000Reserve R20, making it unavailable as a GPR\000reserve-r2"
    "1\000Reserve R21, making it unavailable as a GPR\000reserve-r22\000Rese"
    "rve R22, making it unavailable as a GPR\000reserve-r23\000Reserve R23, "
    "making it unavailable as a GPR\000reserve-r24\000Reserve R24, making it"
    " unavailable as a GPR\000reserve-r25\000Reserve R25, making it unavaila"
    "ble as a GPR\000reserve-r26\000Reserve R26, making it unavailable as a "
    "GPR\000reserve-r27\000Reserve R27, making it unavailable as a GPR\000re"
    "serve-r28\000Reserve R28, making it unavailable as a GPR\000reserve-r29"
    "\000Reserve R29, making it unavailable as a GPR\000reserve-r30\000Reser"
    "ve R30, making it unavailable as a GPR\000reserve-r31\000Reserve R31, m"
    "aking it unavailable as a GPR\000reserve-r8\000Reserve R8, making it un"
    "available as a GPR\000reserve-r9\000Reserve R9, making it unavailable a"
    "s a GPR\000retpoline\000Remove speculation of indirect branches from th"
    "e generated code, either by avoiding them entirely or lowering them wit"
    "h a speculation blocking construct\000retpoline-external-thunk\000When "
    "lowering an indirect call or branch using a `retpoline`, rely on the sp"
    "ecified user provided thunk rather than emitting one ourselves. Only ha"
    "s effect when combined with some other retpoline feature\000retpoline-i"
    "ndirect-branches\000Remove speculation of indirect branches from the ge"
    "nerated code\000retpoline-indirect-calls\000Remove speculation of indir"
    "ect calls from the generated code\000rtm\000Support RTM instructions\000"
    "sahf\000Support LAHF and SAHF instructions in 64-bit mode\000sbb-dep-br"
    "eaking\000SBB with same register has no source dependency\000serialize\000"
    "Has serialize instruction\000seses\000Prevent speculative execution sid"
    "e channel timing attacks by inserting a speculation barrier before memo"
    "ry reads, memory writes, and conditional branches. Implies LVI Control "
    "Flow integrity.\000sgx\000Enable Software Guard Extensions\000sha\000En"
    "able SHA instructions\000sha512\000Support SHA512 instructions\000shstk"
    "\000Support CET Shadow-Stack instructions\000slow-3ops-lea\000LEA instr"
    "uction with 3 ops or certain registers is slow\000slow-incdec\000INC an"
    "d DEC instructions are slower than ADD and SUB\000slow-indirect-call\000"
    "Indirect calls from memory are slow\000slow-lea\000LEA instruction with"
    " certain arguments is slow\000slow-pmaddwd\000PMADDWD is slower than PM"
    "ULLD\000slow-pmulld\000PMULLD instruction is slow (compared to PMULLW/P"
    "MULHW and PMULUDQ)\000slow-pmullq\000PMULLQ instruction is slow\000slow"
    "-shld\000SHLD instruction is slow\000slow-two-mem-ops\000Two memory ope"
    "rand instructions are slow\000slow-unaligned-mem-16\000Slow unaligned 1"
    "6-byte memory access\000slow-unaligned-mem-32\000Slow unaligned 32-byte"
    " memory access\000sm3\000Support SM3 instructions\000sm4\000Support SM4"
    " instructions\000soft-float\000Use software floating point features\000"
    "sse\000Enable SSE instructions\000sse-unaligned-mem\000Allow unaligned "
    "memory operands with SSE instructions (this may require setting a confi"
    "guration bit in the processor)\000sse2\000Enable SSE2 instructions\000s"
    "se3\000Enable SSE3 instructions\000sse4.1\000Enable SSE 4.1 instruction"
    "s\000sse4.2\000Enable SSE 4.2 instructions\000sse4a\000Support SSE 4a i"
    "nstructions\000ssse3\000Enable SSSE3 instructions\000tagged-globals\000"
    "Use an instruction sequence for taking the address of a global that all"
    "ows a memory tag in the upper address bits.\000tbm\000Enable TBM instru"
    "ctions\000tsxldtrk\000Support TSXLDTRK instructions\000tuning-fast-imm-"
    "vector-shift\000Vector shifts are fast (2/cycle) as opposed to slow (1/"
    "cycle)\000uintr\000Has UINTR Instructions\000use-glm-div-sqrt-costs\000"
    "Use Goldmont specific floating point div/sqrt costs\000use-slm-arith-co"
    "sts\000Use Silvermont specific arithmetic costs\000usermsr\000Support U"
    "SERMSR instructions\000vaes\000Promote selected AES instructions to AVX"
    "512/AVX registers\000vpclmulqdq\000Enable vpclmulqdq instructions\000vz"
    "eroupper\000Should insert vzeroupper instructions\000waitpkg\000Wait an"
    "d pause enhancements\000wbnoinvd\000Write Back No Invalidate\000widekl\000"
    "Support Key Locker wide Instructions\000x32\000" "64-bit with ILP32 pro"
    "gramming model (e.g. x32 ABI)\000x87\000Enable X87 float instructions\000"
    "xop\000Enable XOP instructions\000xsave\000Support xsave instructions\000"
    "xsavec\000Support xsavec instructions\000xsaveopt\000Support xsaveopt i"
    "nstructions\000xsaves\000Support xsaves instructions\000zu\000Support z"
    "ero-upper SETcc/IMUL\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 136, 1412> X86SubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 136 + 1, { { { 0x123a60eb03080003ULL, 0x540000000d33e1fULL, 0x7ba82014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 135 + 11, { { { 0x100800c800000000ULL, 0x12201ULL, 0x3000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100000000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 134 + 20, { { { 0x123a64fb031e0003ULL, 0x540000000d33e1fULL, 0x7ba82414ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 133 + 30, { { { 0x123a64fb033e0003ULL, 0x1f40000000d33e1fULL, 0x7ba82414ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 132 + 42, { { { 0x123a64fb033e0003ULL, 0x1f40000000d33e1fULL, 0x7ba82414ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 131 + 54, { { { 0x4800000000ULL, 0x10202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x500000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 130 + 61, { { { 0x8004800000000ULL, 0x2000000000010202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x500000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 129 + 70, { { { 0x8004800000000ULL, 0x4000000000010202ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100000000000000ULL, 0x500400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 128 + 80, { { { 0x8004800000000ULL, 0x2000000000010202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x500000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 127 + 90, { { { 0x4800000000ULL, 0x10202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x500000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 126 + 103, { { { 0x8004800000000ULL, 0x2000000000010202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x500000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 125 + 113, { { { 0x8004800000000ULL, 0x4000000000010202ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100000000000000ULL, 0x500400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 124 + 122, { { { 0x800c800000000ULL, 0x8000000000010202ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100000000000000ULL, 0x500400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 123 + 136, { { { 0x100800c800000000ULL, 0x206ULL, 0x3000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0xc004001000000000ULL, 0x603001041ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 122 + 141, { { { 0x100800e800000000ULL, 0x412606ULL, 0x3000014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4024080000000000ULL, 0x4256000840ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 121 + 153, { { { 0x100a00e900000002ULL, 0x100000000c12606ULL, 0x7b000014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4024080000000000ULL, 0x4256000840ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 120 + 171, { { { 0x100800c800000000ULL, 0x12201ULL, 0x3000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100000000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 119 + 181, { { { 0x900800e800000002ULL, 0x12603ULL, 0xf000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100108000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 118 + 188, { { { 0x900860e801000002ULL, 0x12603ULL, 0xf000080ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4120508000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 117 + 195, { { { 0x900a60e801000002ULL, 0x12603ULL, 0x2f000080ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4120508000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 116 + 202, { { { 0x900a60e803000802ULL, 0x412647ULL, 0x2f000080ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4120508000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 115 + 209, { { { 0x100800c800000000ULL, 0x206ULL, 0x3000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0xc004001000000000ULL, 0x603001041ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 114 + 217, { { { 0x120a68e803000c01ULL, 0x4000000000c12607ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x46c0202000000000ULL, 0x1002800b12ULL, 0x0ULL, 0x0ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 113 + 227, { { { 0x100800c800000000ULL, 0x12203ULL, 0x3000011ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x5104200000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 112 + 234, { { { 0x100820e801000402ULL, 0x12607ULL, 0x2b000011ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x1136600000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 8 },
   { sizeof(SubtargetSubTypeKV) * 111 + 241, { { { 0x0ULL, 0x10002ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 110 + 244, { { { 0x8004800000000ULL, 0x2000000000000002ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 109 + 249, { { { 0x100a60ad03000803ULL, 0x100000000c12647ULL, 0x7b000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db4602000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 9 },
   { sizeof(SubtargetSubTypeKV) * 108 + 259, { { { 0x100a60ad03000803ULL, 0x100000000c12647ULL, 0x7b000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db4602000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 9 },
   { sizeof(SubtargetSubTypeKV) * 107 + 269, { { { 0x111a61af2bc10803ULL, 0x100000000c12647ULL, 0x7b5be001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db460a000000000ULL, 0x1024c4000ULL, 0x0ULL, 0x0ULL, } } }, 10 },
   { sizeof(SubtargetSubTypeKV) * 106 + 279, { { { 0x111a61af2bc10803ULL, 0x500000000c12647ULL, 0x7b5be001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db460a000000000ULL, 0x1024c4000ULL, 0x0ULL, 0x0ULL, } } }, 11 },
   { sizeof(SubtargetSubTypeKV) * 105 + 289, { { { 0x130a69e92b010c03ULL, 0x4100000000c13607ULL, 0x7b014004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82804390ULL, 0x0ULL, 0x0ULL, } } }, 12 },
   { sizeof(SubtargetSubTypeKV) * 104 + 300, { { { 0x120a69eb2b010c03ULL, 0x4000000000c13607ULL, 0x7b030004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x2904b90ULL, 0x0ULL, 0x0ULL, } } }, 12 },
   { sizeof(SubtargetSubTypeKV) * 103 + 312, { { { 0x123a64fb833e0003ULL, 0x1f40000000d3be1fULL, 0x7b282c14ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 102 + 329, { { { 0x120a69eb2b410c03ULL, 0x4000000000c13607ULL, 0x7b030004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x2904b90ULL, 0x0ULL, 0x0ULL, } } }, 12 },
   { sizeof(SubtargetSubTypeKV) * 101 + 340, { { { 0x100a20e800000400ULL, 0x4000000000402602ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x40c0200000000000ULL, 0x802800910ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 100 + 351, { { { 0x120a68e803000c00ULL, 0x4000000000402607ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x46c0202000000000ULL, 0x1002800b12ULL, 0x0ULL, 0x0ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 99 + 361, { { { 0x100800c800000000ULL, 0x202ULL, 0x3000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000010ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 98 + 367, { { { 0x100800c800000000ULL, 0x202ULL, 0x3000002ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000010ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 97 + 385, { { { 0x100800c800000000ULL, 0x202ULL, 0x3000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000010ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 96 + 402, { { { 0x100800e800000400ULL, 0x4000000000002602ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x40c0200000000000ULL, 0x802800910ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 95 + 419, { { { 0x100a20e800000400ULL, 0x4000000000402602ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x40c0200000000000ULL, 0x802800910ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 94 + 436, { { { 0x120a68e803000c00ULL, 0x4000000000402607ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x46c0202000000000ULL, 0x1002800b12ULL, 0x0ULL, 0x0ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 93 + 453, { { { 0x120a68e803000c00ULL, 0x4000000000402607ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x46c0202000000000ULL, 0x1002800b12ULL, 0x0ULL, 0x0ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 92 + 474, { { { 0x120a68e803000c01ULL, 0x4000000000c12607ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x46c0202000000000ULL, 0x1002800b12ULL, 0x0ULL, 0x0ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 91 + 491, { { { 0x120a68e803000c01ULL, 0x4000000000c12607ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x46c0202000000000ULL, 0x1002800b12ULL, 0x0ULL, 0x0ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 90 + 512, { { { 0x100800e800000000ULL, 0x4000000000002602ULL, 0x3000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x2000110ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 89 + 531, { { { 0x100800e800000000ULL, 0x4000000000002202ULL, 0x3000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x2000110ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 88 + 546, { { { 0x100800e800000000ULL, 0x4000000000002202ULL, 0x3000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x2000110ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 87 + 553, { { { 0x100800e800000400ULL, 0x4000000000002602ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x40c0200000000000ULL, 0x802800910ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 86 + 564, { { { 0x171f6ffbbbff4fffULL, 0x5f40000000d7ffbfULL, 0xfb7be504ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x6ec9212000000000ULL, 0x8220c79cULL, 0x0ULL, 0x0ULL, } } }, 15 },
   { sizeof(SubtargetSubTypeKV) * 85 + 578, { { { 0x131f6debabc90e8bULL, 0x4540000000d33e1fULL, 0x7b7be504ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x6ec9202000000000ULL, 0x8220479cULL, 0x0ULL, 0x0ULL, } } }, 15 },
   { sizeof(SubtargetSubTypeKV) * 84 + 592, { { { 0x4000000000ULL, 0x0ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4080200000000000ULL, 0x2800010ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 83 + 600, { { { 0x4000000000ULL, 0x10002ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 82 + 606, { { { 0x100a00e900000002ULL, 0x100000000c12606ULL, 0x7b000014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4024000000000000ULL, 0x2214000840ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 81 + 615, { { { 0x100a00e900000002ULL, 0x100000000d32606ULL, 0x7b000014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4024000000000000ULL, 0x2214000040ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 80 + 629, { { { 0x100a00e900000002ULL, 0x100000000d32606ULL, 0x7b000014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4024000000000000ULL, 0x2214000040ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 79 + 643, { { { 0x123a60eb03080003ULL, 0x540000000d33e1fULL, 0x7ba82014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4c80200000000000ULL, 0x800810ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 78 + 653, { { { 0x123a64fb831e0003ULL, 0x540000000d33e1fULL, 0x7ba82414ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4c80200000000000ULL, 0x800810ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 77 + 664, { { { 0x131f6debabc90ecbULL, 0x4540000000d3be1fULL, 0x7b7be504ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x6ec9212000000000ULL, 0x8220479cULL, 0x0ULL, 0x0ULL, } } }, 15 },
   { sizeof(SubtargetSubTypeKV) * 76 + 678, { { { 0x131f6debabc90edbULL, 0x4540000000d3be1fULL, 0x7b7be504ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x6ec9212000000000ULL, 0x8220479cULL, 0x0ULL, 0x0ULL, } } }, 15 },
   { sizeof(SubtargetSubTypeKV) * 75 + 694, { { { 0x131f6debabc90edbULL, 0x4540000000d3be1fULL, 0x7b7be504ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x6ec9212000000000ULL, 0x8220479cULL, 0x0ULL, 0x0ULL, } } }, 15 },
   { sizeof(SubtargetSubTypeKV) * 74 + 710, { { { 0x120a68e803000c00ULL, 0x4000000000402607ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x46c0202000000000ULL, 0x1002800b12ULL, 0x0ULL, 0x0ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 73 + 718, { { { 0x0ULL, 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 72 + 723, { { { 0x0ULL, 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 71 + 728, { { { 0x4000000000ULL, 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 70 + 733, { { { 0x4800000000ULL, 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 69 + 738, { { { 0x131e69e92b810c03ULL, 0x4100000000d13607ULL, 0x7b1be004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82004390ULL, 0x0ULL, 0x0ULL, } } }, 16 },
   { sizeof(SubtargetSubTypeKV) * 68 + 753, { { { 0x131e69eb2b810c03ULL, 0x4100000000d13e07ULL, 0x7b5be004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82004390ULL, 0x0ULL, 0x0ULL, } } }, 16 },
   { sizeof(SubtargetSubTypeKV) * 67 + 768, { { { 0x131e69e92b810c03ULL, 0x4100000000d13607ULL, 0x7b1be004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82004390ULL, 0x0ULL, 0x0ULL, } } }, 16 },
   { sizeof(SubtargetSubTypeKV) * 66 + 783, { { { 0x131e69eb2b810c03ULL, 0x4100000000d13e07ULL, 0x7b5be004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82004390ULL, 0x0ULL, 0x0ULL, } } }, 16 },
   { sizeof(SubtargetSubTypeKV) * 65 + 798, { { { 0x100a20e800000400ULL, 0x4000000000402602ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x40c0200000000000ULL, 0x802800910ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 64 + 808, { { { 0x4000000000ULL, 0x2ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 63 + 811, { { { 0x4000000000ULL, 0x10002ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 62 + 816, { { { 0x4000000000ULL, 0x10002ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 61 + 821, { { { 0x8004800000000ULL, 0x4000000000010202ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100000000000000ULL, 0x500400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 60 + 824, { { { 0x800c800000000ULL, 0x8000000000010202ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100000000000000ULL, 0x500400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 59 + 832, { { { 0x100a60e823010003ULL, 0xc12607ULL, 0x2b000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x25000000000000ULL, 0x226810000ULL, 0x0ULL, 0x0ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 58 + 836, { { { 0x100a60e823010003ULL, 0xc12607ULL, 0x2b100000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x25000000000000ULL, 0x226810000ULL, 0x0ULL, 0x0ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 57 + 840, { { { 0x4000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 56 + 849, { { { 0x123a64fb033e0003ULL, 0x1f40000000d33e1fULL, 0x7ba82414ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 17 },
   { sizeof(SubtargetSubTypeKV) * 55 + 859, { { { 0x123a60eb03080003ULL, 0x540000000d33e1fULL, 0x7ba82014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 54 + 870, { { { 0x100a60e823010003ULL, 0xc12607ULL, 0x2b000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x25000000000000ULL, 0x226810000ULL, 0x0ULL, 0x0ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 53 + 881, { { { 0x100800e800000000ULL, 0x4000000000002202ULL, 0x3000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x2000110ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 52 + 889, { { { 0x800c800000000ULL, 0x8000000000000202ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 18 },
   { sizeof(SubtargetSubTypeKV) * 51 + 896, { { { 0x163a66fb133e4003ULL, 0x1f40000000d7ffbfULL, 0xfb282414ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82828790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 50 + 905, { { { 0x8004800000000ULL, 0x4000000000010202ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100000000000000ULL, 0x500400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 49 + 913, { { { 0x800c800000000ULL, 0x8000000000010202ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4100000000000000ULL, 0x500400000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 48 + 926, { { { 0x123a64fb033e0003ULL, 0x1f40000000d33e1fULL, 0x7b282414ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 47 + 938, { { { 0x100800c800000000ULL, 0x202ULL, 0x3000002ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000010ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 46 + 945, { { { 0x4000000000ULL, 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 45 + 953, { { { 0x8004800000000ULL, 0x4000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 18 },
   { sizeof(SubtargetSubTypeKV) * 44 + 963, { { { 0x4000000000ULL, 0x2ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 43 + 975, { { { 0x8004800000000ULL, 0x202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 42 + 984, { { { 0x8004800000000ULL, 0x2000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 41 + 993, { { { 0x8004800000000ULL, 0x2000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 40 + 1003, { { { 0x8004800000000ULL, 0x4000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 18 },
   { sizeof(SubtargetSubTypeKV) * 39 + 1012, { { { 0x8004800000000ULL, 0x4000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 18 },
   { sizeof(SubtargetSubTypeKV) * 38 + 1022, { { { 0x8004800000000ULL, 0x4000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 18 },
   { sizeof(SubtargetSubTypeKV) * 37 + 1032, { { { 0x8004800000000ULL, 0x8000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 18 },
   { sizeof(SubtargetSubTypeKV) * 36 + 1047, { { { 0x8004800000000ULL, 0x202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 35 + 1058, { { { 0x8004800000000ULL, 0x2000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 34 + 1070, { { { 0x8004800000000ULL, 0x2000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 33 + 1094, { { { 0x8004800000000ULL, 0x4000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 18 },
   { sizeof(SubtargetSubTypeKV) * 32 + 1104, { { { 0x4000000000ULL, 0x2ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 31 + 1116, { { { 0x4800000000ULL, 0x200ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 30 + 1128, { { { 0x4800000000ULL, 0x200ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 29 + 1139, { { { 0x8004800000000ULL, 0x8000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 18 },
   { sizeof(SubtargetSubTypeKV) * 28 + 1148, { { { 0x123a60eb03080003ULL, 0x540000000d33e1fULL, 0x7ba82014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 27 + 1159, { { { 0x131e69e92b810c03ULL, 0x4100000000d13607ULL, 0x7b1be004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82004390ULL, 0x0ULL, 0x0ULL, } } }, 16 },
   { sizeof(SubtargetSubTypeKV) * 26 + 1170, { { { 0x100800e800000400ULL, 0x4000000000002602ULL, 0x2b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x40c0200000000000ULL, 0x802800910ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 25 + 1182, { { { 0x131f6debabc90e8bULL, 0x4540000000d33e1fULL, 0x7b7be504ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x6ec9202000000000ULL, 0x8220479cULL, 0x0ULL, 0x0ULL, } } }, 15 },
   { sizeof(SubtargetSubTypeKV) * 24 + 1197, { { { 0x123a64fb831e0003ULL, 0x540000000d33e1fULL, 0x7ba82414ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4c80200000000000ULL, 0x800810ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 23 + 1210, { { { 0x100800e800000000ULL, 0x412606ULL, 0x3000014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4024080000000000ULL, 0x4256000840ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 22 + 1221, { { { 0x120a69eb2b010c03ULL, 0x4000000000c13607ULL, 0x7b010004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x2904b90ULL, 0x0ULL, 0x0ULL, } } }, 12 },
   { sizeof(SubtargetSubTypeKV) * 21 + 1225, { { { 0x120a68e903000c03ULL, 0x4000000000c12607ULL, 0x7b000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec1202000000000ULL, 0x2800b90ULL, 0x0ULL, 0x0ULL, } } }, 19 },
   { sizeof(SubtargetSubTypeKV) * 20 + 1233, { { { 0x120a69eb2b010c03ULL, 0x4000000000c13607ULL, 0x7b010004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x2904b90ULL, 0x0ULL, 0x0ULL, } } }, 12 },
   { sizeof(SubtargetSubTypeKV) * 19 + 1248, { { { 0x120a69eb2b010c03ULL, 0x4000000000c13607ULL, 0x7b010004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x2904b90ULL, 0x0ULL, 0x0ULL, } } }, 12 },
   { sizeof(SubtargetSubTypeKV) * 18 + 1263, { { { 0x100800e800000000ULL, 0x412606ULL, 0x3000014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4024080000000000ULL, 0x4256000840ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 17 + 1267, { { { 0x131e69eb2b810c03ULL, 0x4500000000d1361fULL, 0x7b1fe004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82004390ULL, 0x0ULL, 0x0ULL, } } }, 16 },
   { sizeof(SubtargetSubTypeKV) * 16 + 1277, { { { 0x101a00eb00000002ULL, 0x100000000d32606ULL, 0x7b000014ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4024000000000000ULL, 0x2214000040ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 15 + 1285, { { { 0x100800e800000000ULL, 0x4000000000002602ULL, 0x3000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x2000110ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 14 + 1294, { { { 0x123a64fb033e0003ULL, 0x1f40000000d33e1fULL, 0x7b282414ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec9202000000000ULL, 0x82820790ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 13 + 1306, { { { 0x0ULL, 0x2ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 12 + 1317, { { { 0x0ULL, 0x10002ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 11 + 1326, { { { 0x8004800000000ULL, 0x4000000000000202ULL, 0x3000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x6800010ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 10 + 1333, { { { 0x100800e800000000ULL, 0x4000000000002202ULL, 0x3000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x40c0200000000000ULL, 0x802800810ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 9 + 1343, { { { 0x100860e803000800ULL, 0x4000000000002207ULL, 0xb000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x46c0202000000000ULL, 0x1002800812ULL, 0x0ULL, 0x0ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 8 + 1353, { { { 0x100861e82b000800ULL, 0x4000000000002207ULL, 0xb010004ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4ec1202000000000ULL, 0x2804810ULL, 0x0ULL, 0x0ULL, } } }, 12 },
   { sizeof(SubtargetSubTypeKV) * 7 + 1363, { { { 0x8004800000000ULL, 0x8000000000000202ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x400000000ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 6 + 1369, { { { 0x100a60ad03000803ULL, 0x100000000c12647ULL, 0x7b000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db460a000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 5 + 1376, { { { 0x100a60af03000803ULL, 0x100000000f12647ULL, 0x7b400001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db460a000000000ULL, 0x102400000ULL, 0x0ULL, 0x0ULL, } } }, 20 },
   { sizeof(SubtargetSubTypeKV) * 4 + 1383, { { { 0x120e60af03000803ULL, 0x100000000f13647ULL, 0x7b482001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db460a000000000ULL, 0x2400010ULL, 0x0ULL, 0x0ULL, } } }, 21 },
   { sizeof(SubtargetSubTypeKV) * 3 + 1390, { { { 0x131e61af2bc10803ULL, 0x500000000f13647ULL, 0x7b5be001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db4e6a000000000ULL, 0x2400010ULL, 0x0ULL, 0x0ULL, } } }, 22 },
   { sizeof(SubtargetSubTypeKV) * 2 + 1397, { { { 0x131e61af2bc90803ULL, 0x500000000f1b65fULL, 0x7b5fe001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db4e6e000000000ULL, 0x100a400010ULL, 0x0ULL, 0x0ULL, } } }, 22 },
   { sizeof(SubtargetSubTypeKV) * 1 + 1404, { { { 0x131f61af2fdf0803ULL, 0x500000000f1b65fULL, 0x7b5fe001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x4db4e0a000000000ULL, 0x2400010ULL, 0x0ULL, 0x0ULL, } } }, 22 },
  },
    "\000alderlake\000amdfam10\000arrowlake\000arrowlake-s\000arrowlake_s\000"
    "athlon\000athlon-4\000athlon-fx\000athlon-mp\000athlon-tbird\000athlon-"
    "xp\000athlon64\000athlon64-sse3\000atom\000atom_sse4_2\000atom_sse4_2_m"
    "ovbe\000barcelona\000bdver1\000bdver2\000bdver3\000bdver4\000bonnell\000"
    "broadwell\000btver1\000btver2\000c3\000c3-2\000c86-4g-m4\000c86-4g-m6\000"
    "c86-4g-m7\000c86-4g-m8\000cannonlake\000cascadelake\000clearwaterforest"
    "\000cooperlake\000core-avx-i\000core-avx2\000core2\000core_2_duo_sse4_1"
    "\000core_2_duo_ssse3\000core_2nd_gen_avx\000core_3rd_gen_avx\000core_4t"
    "h_gen_avx\000core_4th_gen_avx_tsx\000core_5th_gen_avx\000core_5th_gen_a"
    "vx_tsx\000core_aes_pclmulqdq\000core_i7_sse4_2\000corei7\000corei7-avx\000"
    "diamondrapids\000emeraldrapids\000generic\000geode\000goldmont\000goldm"
    "ont-plus\000goldmont_plus\000gracemont\000grandridge\000graniterapids\000"
    "graniterapids-d\000graniterapids_d\000haswell\000i386\000i486\000i586\000"
    "i686\000icelake-client\000icelake-server\000icelake_client\000icelake_s"
    "erver\000ivybridge\000k6\000k6-2\000k6-3\000k8\000k8-sse3\000knl\000knm"
    "\000lakemont\000lunarlake\000meteorlake\000mic_avx512\000nehalem\000noc"
    "ona\000novalake\000opteron\000opteron-sse3\000pantherlake\000penryn\000"
    "pentium\000pentium-m\000pentium-mmx\000pentium2\000pentium3\000pentium3"
    "m\000pentium4\000pentium4m\000pentium_4\000pentium_4_sse3\000pentium_ii"
    "\000pentium_iii\000pentium_iii_no_xmm_regs\000pentium_m\000pentium_mmx\000"
    "pentium_pro\000pentiumpro\000prescott\000raptorlake\000rocketlake\000sa"
    "ndybridge\000sapphirerapids\000sierraforest\000silvermont\000skx\000sky"
    "lake\000skylake-avx512\000skylake_avx512\000slm\000tigerlake\000tremont"
    "\000westmere\000wildcatlake\000winchip-c6\000winchip2\000x86-64\000x86-"
    "64-v2\000x86-64-v3\000x86-64-v4\000yonah\000znver1\000znver2\000znver3\000"
    "znver4\000znver5\000znver6\000"};

namespace X86_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  switch (SchedClass) {
  case 668: // CMPXCHG8rm
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3066; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3067; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3068; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3069; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3070; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3071; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3072; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3073; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3074; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      return 3075; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
    }
    break;
  case 687: // CMPXCHG8rr
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3076; // JWriteLOCK_CMPXCHG8B
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3077; // JWriteLOCK_CMPXCHG16B
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3078; // JWriteLOCK_CMPXCHG8rm
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3079; // JWriteLOCK_CMPXCHGrm
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3080; // JWriteCMPXCHG8B
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3081; // JWriteCMPXCHG16B
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3082; // JWriteCMPXCHG8rm
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3083; // WriteCMPXCHGRMW
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3084; // JWriteCMPXCHG8rr
      return 3085; // WriteCMPXCHG
    }
    break;
  case 691: // CMPXCHG16rm_CMPXCHG32rm_CMPXCHG64rm
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3066; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3067; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3068; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3069; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3070; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3071; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3072; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3073; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3074; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      return 3075; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
    }
    break;
  case 694: // CMPXCHG8B
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3086; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3087; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3088; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3089; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3090; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3091; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3092; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3093; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3094; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      return 3095; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
    }
    break;
  case 700: // CMPXCHG16B
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3086; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3087; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3088; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3089; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3090; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3091; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3092; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3093; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3094; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      return 3095; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
    }
    break;
  case 790: // XADD16rm_XADD32rm_XADD64rm_XADD8rm
    if (CPUID == 8) { // BtVer2Model
      if (X86_MC::hasLockPrefix(*MI))
        return 3096; // JWriteLOCK_XADDrm_XCHG_Part_JWriteXCHGrm_LdSt_Part_ReadAfterLd
      return 3097; // JWriteXADDrm_XCHG_Part_JWriteXADDrm_LdSt_Part_ReadAfterLd
    }
    break;
  case 807: // SUB32rr_SUB64rr_XOR32rr_XOR64rr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 808: // XORPSrr_VXORPSrr_XORPDrr_VXORPDrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 809: // VXORPSYrr_VXORPDYrr
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3114; // JWriteZeroIdiomYmm
      return 3113; // WriteFLogicY
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    break;
  case 810: // PXORrr_VPXORrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 811: // PSUBBrr_VPSUBBrr_PSUBDrr_VPSUBDrr_VPSUBQrr_PSUBWrr_VPSUBWrr_PCMPGTBrr_VPCMPGTBrr_PCMPGTDrr_VPCMPGTDrr_PCMPGTWrr_VPCMPGTWrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3117; // SKLWritePSUB
    }
    break;
  case 812: // PSUBQrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3117; // SKLWritePSUB
    }
    break;
  case 813: // PCMPGTQrr_VPCMPGTQrr
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3122; // BWWritePCMPGTQ
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3124; // SKXWritePCMPGTQ
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3120; // SBWritePCMPGTQ
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3121; // HWWritePCMPGTQ
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3125; // ICXWritePCMPGTQ
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3123; // SKLWritePCMPGTQ
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 814: // CMOV16rr_CMOV32rr_CMOV64rr
    if (CPUID == 7) { // BroadwellModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3129; // BWWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (CPUID == 12) { // SkylakeServerModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3131; // SKXWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (CPUID == 13) { // SandyBridgeModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3126; // SBWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (CPUID == 14) { // HaswellModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3128; // HWWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (CPUID == 16) { // IceLakeModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3132; // ICXWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (CPUID == 19) { // SkylakeClientModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3130; // SKLWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    break;
  case 815: // CMOV16rm_CMOV32rm_CMOV64rm
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(7).getImm() == X86::COND_BE)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_A)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_L)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_GE)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_LE)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_G)
        return 3137; // PdWriteCMOVm
      return 3134; // WriteCMOVLd
    }
    if (CPUID == 7) { // BroadwellModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3136; // BWWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (CPUID == 12) { // SkylakeServerModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3139; // SKXWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (CPUID == 13) { // SandyBridgeModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3133; // SBWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (CPUID == 14) { // HaswellModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3135; // HWWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (CPUID == 16) { // IceLakeModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3140; // ICXWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (CPUID == 19) { // SkylakeClientModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3138; // SKLWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    break;
  case 816: // SETCCr
    if (CPUID == 7) { // BroadwellModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3144; // BWWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (CPUID == 12) { // SkylakeServerModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3146; // SKXWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (CPUID == 13) { // SandyBridgeModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3141; // SBWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (CPUID == 14) { // HaswellModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3143; // HWWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (CPUID == 16) { // IceLakeModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3147; // ICXWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (CPUID == 19) { // SkylakeClientModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3145; // SKLWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    break;
  case 817: // SETCCm
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(5).getImm() == X86::COND_GE)
        return 3152; // PdWriteSETGEmSETGmSETLEmSETLm
      if (MI->getOperand(5).getImm() == X86::COND_G)
        return 3152; // PdWriteSETGEmSETGmSETLEmSETLm
      if (MI->getOperand(5).getImm() == X86::COND_LE)
        return 3152; // PdWriteSETGEmSETGmSETLEmSETLm
      if (MI->getOperand(5).getImm() == X86::COND_L)
        return 3152; // PdWriteSETGEmSETGmSETLEmSETLm
      return 3149; // WriteSETCCStore
    }
    if (CPUID == 7) { // BroadwellModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3151; // BWWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (CPUID == 12) { // SkylakeServerModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3154; // SKXWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (CPUID == 13) { // SandyBridgeModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3148; // SBWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (CPUID == 14) { // HaswellModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3150; // HWWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (CPUID == 16) { // IceLakeModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3155; // ICXWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (CPUID == 19) { // SkylakeClientModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3153; // SKLWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    break;
  case 900: // VPXORYrr
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    break;
  case 901: // VPSUBBYrr_VPSUBDYrr_VPSUBQYrr_VPSUBWYrr_VPCMPGTBYrr_VPCMPGTDYrr_VPCMPGTWYrr
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3117; // SKLWritePSUB
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 902: // VPCMPGTQYrr
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3122; // BWWritePCMPGTQ
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3124; // SKXWritePCMPGTQ
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3121; // HWWritePCMPGTQ
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3125; // ICXWritePCMPGTQ
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3123; // SKLWritePCMPGTQ
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 903: // ADC16ri8_ADC32ri8_ADC64ri8_SBB16ri8_SBB32ri8_SBB64ri8
    if (CPUID == 14) { // HaswellModel
      if ((
            MI->getOperand(2).getImm() == 0
            && MI->getOperand(1).getReg() != X86::AX
            && MI->getOperand(1).getReg() != X86::EAX
            && MI->getOperand(1).getReg() != X86::RAX
          ))
        return 3158; // HWWriteADC0
      return 3159; // WriteADC
    }
    break;
  case 911: // PCMPGTQrr
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3122; // BWWritePCMPGTQ
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3124; // SKXWritePCMPGTQ
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3120; // SBWritePCMPGTQ
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3121; // HWWritePCMPGTQ
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3125; // ICXWritePCMPGTQ
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3123; // SKLWritePCMPGTQ
    }
    break;
  case 955: // VPERM2F128rri
    if (CPUID == 8) { // BtVer2Model
      if ((
            MI->getOperand(1).getReg() == MI->getOperand(2).getReg()
            && MI->getOperand(3).getImm() == 136
          ))
        return 3114; // JWriteZeroIdiomYmm
      return 3160; // WriteFShuffle256
    }
    break;
  case 1010: // LEA32r_LEA64r_LEA64_32r
    if (CPUID == 5) { // BdVer2Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3164; // PdWrite3OpsLEA
      return 3162; // WriteLEA
    }
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3165; // JWrite3OpsLEA
      return 3162; // WriteLEA
    }
    if (CPUID == 21) { // Znver3Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3161; // Zn3Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (CPUID == 22) { // Znver4Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3163; // Zn4Write3OpsLEA
      return 3162; // WriteLEA
    }
    break;
  case 1012: // LCMPXCHG8
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3066; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3067; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3068; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3069; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3070; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3071; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3072; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3073; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3074; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      return 3075; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
    }
    break;
  case 1013: // LCMPXCHG16B
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3086; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3087; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3088; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3089; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3090; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3091; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3092; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3093; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3094; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      return 3095; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
    }
    break;
  case 1047: // XOR32rr_REV_XOR64rr_REV_SUB32rr_REV_SUB64rr_REV
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 1048: // CMP8rr_CMP8rr_REV_CMP16rr_CMP16rr_REV_CMP32rr_CMP32rr_REV_CMP64rr_CMP64rr_REV
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 1049: // VXORPSrr_VXORPDrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1050: // VANDNPSrr_VANDNPDrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1051: // VANDNPSYrr_VANDNPDYrr
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3114; // JWriteZeroIdiomYmm
      return 3113; // WriteFLogicY
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    break;
  case 1052: // VPXORrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1053: // VPANDNrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1054: // VPANDNYrr
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    break;
  case 1055: // VPSUBBrr_VPSUBWrr_VPSUBDrr_VPSUBQrr_VPCMPGTBrr_VPCMPGTWrr_VPCMPGTDrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3117; // SKLWritePSUB
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1143: // VXORPSZ128rr_VXORPDZ128rr_VANDNPSZ128rr_VANDNPDZ128rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1144: // VXORPSZ256rr_VXORPDZ256rr_VANDNPSZ256rr_VANDNPDZ256rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    break;
  case 1145: // VXORPSZrr_VXORPDZrr_VANDNPSZrr_VANDNPDZrr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    break;
  case 1146: // VPXORDZ128rr_VPXORQZ128rr_VPANDNDZ128rr_VPANDNQZ128rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1147: // VPXORDZ256rr_VPXORQZ256rr_VPANDNDZ256rr_VPANDNQZ256rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    break;
  case 1148: // VPXORDZrr_VPXORQZrr_VPANDNDZrr_VPANDNQZrr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    break;
  case 1149: // VPSUBBZ128rr_VPSUBWZ128rr_VPSUBDZ128rr_VPSUBQZ128rr_VPCMPGTBZ128rr_VPCMPGTWZ128rr_VPCMPGTDZ128rr_VPCMPGTQZ128rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1150: // VPSUBBZ256rr_VPSUBWZ256rr_VPSUBDZ256rr_VPSUBQZ256rr_VPCMPGTBZ256rr_VPCMPGTWZ256rr_VPCMPGTDZ256rr_VPCMPGTQZ256rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1151: // VPSUBBZrr_VPSUBWZrr_VPSUBDZrr_VPSUBQZrr_VPCMPGTBZrr_VPCMPGTWZrr_VPCMPGTDZrr_VPCMPGTQZrr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1153: // LXADD8_LXADD16_LXADD32_LXADD64
    if (CPUID == 8) { // BtVer2Model
      if (X86_MC::hasLockPrefix(*MI))
        return 3096; // JWriteLOCK_XADDrm_XCHG_Part_JWriteXCHGrm_LdSt_Part_ReadAfterLd
      return 3097; // JWriteXADDrm_XCHG_Part_JWriteXADDrm_LdSt_Part_ReadAfterLd
    }
    break;
  case 1191: // ANDNPSrr_ANDNPDrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1192: // MMX_PXORrr_MMX_PANDNrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3168; // WriteVecLogic
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3168; // WriteVecLogic
    }
    break;
  case 1193: // PANDNrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1194: // MMX_PSUBBrr_MMX_PSUBDrr_MMX_PSUBWrr_MMX_PCMPGTBrr_MMX_PCMPGTDrr_MMX_PCMPGTWrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3169; // WriteVecALU
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3169; // WriteVecALU
    }
    break;
  case 1195: // MMX_PSUBQrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3169; // WriteVecALU
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3169; // WriteVecALU
    }
    break;
  case 1196: // LCMPXCHG16_LCMPXCHG32_LCMPXCHG64
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3066; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3067; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3068; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3069; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3070; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3071; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3072; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3073; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3074; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      return 3075; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
    }
    break;
  case 1197: // CMPXCHG16rr_CMPXCHG32rr_CMPXCHG64rr
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3076; // JWriteLOCK_CMPXCHG8B
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3077; // JWriteLOCK_CMPXCHG16B
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3078; // JWriteLOCK_CMPXCHG8rm
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3079; // JWriteLOCK_CMPXCHGrm
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3080; // JWriteCMPXCHG8B
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3081; // JWriteCMPXCHG16B
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3082; // JWriteCMPXCHG8rm
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3083; // WriteCMPXCHGRMW
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3084; // JWriteCMPXCHG8rr
      return 3085; // WriteCMPXCHG
    }
    break;
  case 1198: // LCMPXCHG8B
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3086; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3087; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3088; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86_MC::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3089; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3090; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3091; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3092; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3093; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3094; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      return 3095; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
    }
    break;
  case 1199: // INC8m_INC16m_INC32m_INC64m_DEC8m_DEC16m_DEC32m_DEC64m_NOT8m_NOT16m_NOT32m_NOT64m_NEG8m_NEG16m_NEG32m_NEG64m
    if (CPUID == 8) { // BtVer2Model
      if (X86_MC::hasLockPrefix(*MI))
        return 3170; // JWriteLOCK_ALURMW
      return 3171; // WriteALURMW
    }
    break;
  case 1201: // MMX_PSUBSBrr_MMX_PSUBSWrr_MMX_PSUBUSBrr_MMX_PSUBUSWrr
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3169; // WriteVecALU
    }
    break;
  case 1202: // PSUBSBrr_VPSUBSBrr_PSUBSWrr_VPSUBSWrr_PSUBUSBrr_VPSUBUSBrr_PSUBUSWrr_VPSUBUSWrr
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1204: // MMX_PCMPGTBrr_MMX_PCMPGTDrr_MMX_PCMPGTWrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3169; // WriteVecALU
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3169; // WriteVecALU
    }
    break;
  case 1221: // PCMPGTBrr_PCMPGTDrr_PCMPGTWrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1222: // VPCMPGTBrr_VPCMPGTDrr_VPCMPGTWrr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1223: // VPCMPGTBYrr_VPCMPGTDYrr_VPCMPGTWYrr
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1251: // VPCMPGTBZ128rr_VPCMPGTDZ128rr_VPCMPGTQZ128rr_VPCMPGTWZ128rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1252: // VPCMPGTBZ256rr_VPCMPGTDZ256rr_VPCMPGTQZ256rr_VPCMPGTWZ256rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1253: // VPCMPGTBZrr_VPCMPGTDZrr_VPCMPGTQZrr_VPCMPGTWZrr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1407: // VXORPSZ128rr_VXORPDZ128rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1408: // VXORPSZ256rr_VXORPDZ256rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    break;
  case 1409: // VXORPSZrr_VXORPDZrr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    break;
  case 1410: // VPXORDZ128rr_VPXORQZ128rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1411: // VPXORDZ256rr_VPXORQZ256rr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    break;
  case 1412: // VPXORDZrr_VPXORQZrr
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    break;
  case 1452: // DEC8m_INC8m_NEG8m_NOT8m
    if (CPUID == 8) { // BtVer2Model
      if (X86_MC::hasLockPrefix(*MI))
        return 3170; // JWriteLOCK_ALURMW
      return 3171; // WriteALURMW
    }
    break;
  case 1459: // XOR32rr_XOR64rr
    if (CPUID == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 1460: // XOR32rr_REV_XOR64rr_REV
    if (CPUID == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (CPUID == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 1647: // XADD16rm_XADD32rm_XADD64rm
    if (CPUID == 8) { // BtVer2Model
      if (X86_MC::hasLockPrefix(*MI))
        return 3096; // JWriteLOCK_XADDrm_XCHG_Part_JWriteXCHGrm_LdSt_Part_ReadAfterLd
      return 3097; // JWriteXADDrm_XCHG_Part_JWriteXADDrm_LdSt_Part_ReadAfterLd
    }
    break;
  case 2442: // LEA64r_LEA64_32r
    if (CPUID == 5) { // BdVer2Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3164; // PdWrite3OpsLEA
      return 3162; // WriteLEA
    }
    if (CPUID == 8) { // BtVer2Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3165; // JWrite3OpsLEA
      return 3162; // WriteLEA
    }
    if (CPUID == 9) { // C864GM4Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3172; // C4GM4Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (CPUID == 10) { // C864GM7Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3173; // C4GM7Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (CPUID == 11) { // C864GM8Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3174; // C4GM8Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (CPUID == 21) { // Znver3Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3161; // Zn3Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (CPUID == 22) { // Znver4Model
      if ((
            X86_MC::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3163; // Zn4Write3OpsLEA
      return 3162; // WriteLEA
    }
    break;
  };
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace X86_MC
struct X86GenMCSubtargetInfo : public MCSubtargetInfo {
  X86GenMCSubtargetInfo(const Triple &TT,
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
    return X86_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned X86GenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (FB[X86::Is64Bit] && !FB[X86::IsX32]) Modes |= (1 << 0);
  if (FB[X86::IsX32]) Modes |= (1 << 1);
  return Modes;
}
unsigned X86GenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
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
    Modes &= 3;
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

static inline MCSubtargetInfo *createX86MCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new X86GenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(X86SubTypeKVStorage.Strings), X86FeatureKVStorage.Features, X86SubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::X86Subtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[X86::FeatureADX]) HasADX = true;
  if (Bits[X86::FeatureAES]) HasAES = true;
  if (Bits[X86::FeatureAMXAVX512]) HasAMXAVX512 = true;
  if (Bits[X86::FeatureAMXBF16]) HasAMXBF16 = true;
  if (Bits[X86::FeatureAMXCOMPLEX]) HasAMXCOMPLEX = true;
  if (Bits[X86::FeatureAMXFP8]) HasAMXFP8 = true;
  if (Bits[X86::FeatureAMXFP16]) HasAMXFP16 = true;
  if (Bits[X86::FeatureAMXINT8]) HasAMXINT8 = true;
  if (Bits[X86::FeatureAMXMOVRS]) HasAMXMOVRS = true;
  if (Bits[X86::FeatureAMXTILE]) HasAMXTILE = true;
  if (Bits[X86::FeatureAVX] && X86SSELevel < AVX) X86SSELevel = AVX;
  if (Bits[X86::FeatureAVX2] && X86SSELevel < AVX2) X86SSELevel = AVX2;
  if (Bits[X86::FeatureAVX10_1]) HasAVX10_1 = true;
  if (Bits[X86::FeatureAVX10_1_512]) HasAVX10_1_512 = true;
  if (Bits[X86::FeatureAVX10_2]) HasAVX10_2 = true;
  if (Bits[X86::FeatureAVX10_2_512]) HasAVX10_2_512 = true;
  if (Bits[X86::FeatureAVX512] && X86SSELevel < AVX512) X86SSELevel = AVX512;
  if (Bits[X86::FeatureAVXIFMA]) HasAVXIFMA = true;
  if (Bits[X86::FeatureAVXNECONVERT]) HasAVXNECONVERT = true;
  if (Bits[X86::FeatureAVXVNNI]) HasAVXVNNI = true;
  if (Bits[X86::FeatureAVXVNNIINT8]) HasAVXVNNIINT8 = true;
  if (Bits[X86::FeatureAVXVNNIINT16]) HasAVXVNNIINT16 = true;
  if (Bits[X86::FeatureBF16]) HasBF16 = true;
  if (Bits[X86::FeatureBITALG]) HasBITALG = true;
  if (Bits[X86::FeatureBMI]) HasBMI = true;
  if (Bits[X86::FeatureBMI2]) HasBMI2 = true;
  if (Bits[X86::FeatureBMM]) HasBMM = true;
  if (Bits[X86::FeatureBWI]) HasBWI = true;
  if (Bits[X86::FeatureCCMP]) HasCCMP = true;
  if (Bits[X86::FeatureCDI]) HasCDI = true;
  if (Bits[X86::FeatureCF]) HasCF = true;
  if (Bits[X86::FeatureCLDEMOTE]) HasCLDEMOTE = true;
  if (Bits[X86::FeatureCLFLUSHOPT]) HasCLFLUSHOPT = true;
  if (Bits[X86::FeatureCLWB]) HasCLWB = true;
  if (Bits[X86::FeatureCLZERO]) HasCLZERO = true;
  if (Bits[X86::FeatureCMOV]) HasCMOV = true;
  if (Bits[X86::FeatureCMPCCXADD]) HasCMPCCXADD = true;
  if (Bits[X86::FeatureCRC32]) HasCRC32 = true;
  if (Bits[X86::FeatureCX8]) HasCX8 = true;
  if (Bits[X86::FeatureCX16]) HasCX16 = true;
  if (Bits[X86::FeatureDQI]) HasDQI = true;
  if (Bits[X86::FeatureEGPR]) HasEGPR = true;
  if (Bits[X86::FeatureENQCMD]) HasENQCMD = true;
  if (Bits[X86::FeatureERMSB]) HasERMSB = true;
  if (Bits[X86::FeatureEVEX512]) HasEVEX512 = true;
  if (Bits[X86::FeatureF16C]) HasF16C = true;
  if (Bits[X86::FeatureFMA]) HasFMA = true;
  if (Bits[X86::FeatureFMA4]) HasFMA4 = true;
  if (Bits[X86::FeatureFP16]) HasFP16 = true;
  if (Bits[X86::FeatureFSGSBase]) HasFSGSBase = true;
  if (Bits[X86::FeatureFSRM]) HasFSRM = true;
  if (Bits[X86::FeatureFXSR]) HasFXSR = true;
  if (Bits[X86::FeatureGFNI]) HasGFNI = true;
  if (Bits[X86::FeatureHRESET]) HasHRESET = true;
  if (Bits[X86::FeatureHardenSlsIJmp]) HardenSlsIJmp = true;
  if (Bits[X86::FeatureHardenSlsRet]) HardenSlsRet = true;
  if (Bits[X86::FeatureIFMA]) HasIFMA = true;
  if (Bits[X86::FeatureINVPCID]) HasINVPCID = true;
  if (Bits[X86::FeatureJMPABS]) HasJMPABS = true;
  if (Bits[X86::FeatureKL]) HasKL = true;
  if (Bits[X86::FeatureLAHFSAHF64]) HasLAHFSAHF64 = true;
  if (Bits[X86::FeatureLVIControlFlowIntegrity]) UseLVIControlFlowIntegrity = true;
  if (Bits[X86::FeatureLVILoadHardening]) UseLVILoadHardening = true;
  if (Bits[X86::FeatureLWP]) HasLWP = true;
  if (Bits[X86::FeatureLZCNT]) HasLZCNT = true;
  if (Bits[X86::FeatureMMX]) HasMMX = true;
  if (Bits[X86::FeatureMOVBE]) HasMOVBE = true;
  if (Bits[X86::FeatureMOVDIR64B]) HasMOVDIR64B = true;
  if (Bits[X86::FeatureMOVDIRI]) HasMOVDIRI = true;
  if (Bits[X86::FeatureMOVRS]) HasMOVRS = true;
  if (Bits[X86::FeatureMWAITX]) HasMWAITX = true;
  if (Bits[X86::FeatureNDD]) HasNDD = true;
  if (Bits[X86::FeatureNF]) HasNF = true;
  if (Bits[X86::FeatureNOPL]) HasNOPL = true;
  if (Bits[X86::FeaturePCLMUL]) HasPCLMUL = true;
  if (Bits[X86::FeaturePCONFIG]) HasPCONFIG = true;
  if (Bits[X86::FeaturePKU]) HasPKU = true;
  if (Bits[X86::FeaturePOPCNT]) HasPOPCNT = true;
  if (Bits[X86::FeaturePPX]) HasPPX = true;
  if (Bits[X86::FeaturePREFETCHI]) HasPREFETCHI = true;
  if (Bits[X86::FeaturePRFCHW]) HasPRFCHW = true;
  if (Bits[X86::FeaturePTWRITE]) HasPTWRITE = true;
  if (Bits[X86::FeaturePush2Pop2]) HasPush2Pop2 = true;
  if (Bits[X86::FeatureRAOINT]) HasRAOINT = true;
  if (Bits[X86::FeatureRDPID]) HasRDPID = true;
  if (Bits[X86::FeatureRDPRU]) HasRDPRU = true;
  if (Bits[X86::FeatureRDRAND]) HasRDRAND = true;
  if (Bits[X86::FeatureRDSEED]) HasRDSEED = true;
  if (Bits[X86::FeatureRTM]) HasRTM = true;
  if (Bits[X86::FeatureReserveEDI]) ReservedRReg[X86::EDI] = true;
  if (Bits[X86::FeatureReserveR8]) ReservedRReg[X86::R8] = true;
  if (Bits[X86::FeatureReserveR9]) ReservedRReg[X86::R9] = true;
  if (Bits[X86::FeatureReserveR10]) ReservedRReg[X86::R10] = true;
  if (Bits[X86::FeatureReserveR11]) ReservedRReg[X86::R11] = true;
  if (Bits[X86::FeatureReserveR12]) ReservedRReg[X86::R12] = true;
  if (Bits[X86::FeatureReserveR13]) ReservedRReg[X86::R13] = true;
  if (Bits[X86::FeatureReserveR14]) ReservedRReg[X86::R14] = true;
  if (Bits[X86::FeatureReserveR15]) ReservedRReg[X86::R15] = true;
  if (Bits[X86::FeatureReserveR16]) ReservedRReg[X86::R16] = true;
  if (Bits[X86::FeatureReserveR17]) ReservedRReg[X86::R17] = true;
  if (Bits[X86::FeatureReserveR18]) ReservedRReg[X86::R18] = true;
  if (Bits[X86::FeatureReserveR19]) ReservedRReg[X86::R19] = true;
  if (Bits[X86::FeatureReserveR20]) ReservedRReg[X86::R20] = true;
  if (Bits[X86::FeatureReserveR21]) ReservedRReg[X86::R21] = true;
  if (Bits[X86::FeatureReserveR22]) ReservedRReg[X86::R22] = true;
  if (Bits[X86::FeatureReserveR23]) ReservedRReg[X86::R23] = true;
  if (Bits[X86::FeatureReserveR24]) ReservedRReg[X86::R24] = true;
  if (Bits[X86::FeatureReserveR25]) ReservedRReg[X86::R25] = true;
  if (Bits[X86::FeatureReserveR26]) ReservedRReg[X86::R26] = true;
  if (Bits[X86::FeatureReserveR27]) ReservedRReg[X86::R27] = true;
  if (Bits[X86::FeatureReserveR28]) ReservedRReg[X86::R28] = true;
  if (Bits[X86::FeatureReserveR29]) ReservedRReg[X86::R29] = true;
  if (Bits[X86::FeatureReserveR30]) ReservedRReg[X86::R30] = true;
  if (Bits[X86::FeatureReserveR31]) ReservedRReg[X86::R31] = true;
  if (Bits[X86::FeatureRetpoline]) DeprecatedUseRetpoline = true;
  if (Bits[X86::FeatureRetpolineExternalThunk]) UseRetpolineExternalThunk = true;
  if (Bits[X86::FeatureRetpolineIndirectBranches]) UseRetpolineIndirectBranches = true;
  if (Bits[X86::FeatureRetpolineIndirectCalls]) UseRetpolineIndirectCalls = true;
  if (Bits[X86::FeatureSERIALIZE]) HasSERIALIZE = true;
  if (Bits[X86::FeatureSGX]) HasSGX = true;
  if (Bits[X86::FeatureSHA]) HasSHA = true;
  if (Bits[X86::FeatureSHA512]) HasSHA512 = true;
  if (Bits[X86::FeatureSHSTK]) HasSHSTK = true;
  if (Bits[X86::FeatureSM3]) HasSM3 = true;
  if (Bits[X86::FeatureSM4]) HasSM4 = true;
  if (Bits[X86::FeatureSSE1] && X86SSELevel < SSE1) X86SSELevel = SSE1;
  if (Bits[X86::FeatureSSE2] && X86SSELevel < SSE2) X86SSELevel = SSE2;
  if (Bits[X86::FeatureSSE3] && X86SSELevel < SSE3) X86SSELevel = SSE3;
  if (Bits[X86::FeatureSSE4A]) HasSSE4A = true;
  if (Bits[X86::FeatureSSE41] && X86SSELevel < SSE41) X86SSELevel = SSE41;
  if (Bits[X86::FeatureSSE42] && X86SSELevel < SSE42) X86SSELevel = SSE42;
  if (Bits[X86::FeatureSSEUnalignedMem]) HasSSEUnalignedMem = true;
  if (Bits[X86::FeatureSSSE3] && X86SSELevel < SSSE3) X86SSELevel = SSSE3;
  if (Bits[X86::FeatureSoftFloat]) UseSoftFloat = true;
  if (Bits[X86::FeatureSpeculativeExecutionSideEffectSuppression]) UseSpeculativeExecutionSideEffectSuppression = true;
  if (Bits[X86::FeatureTBM]) HasTBM = true;
  if (Bits[X86::FeatureTSXLDTRK]) HasTSXLDTRK = true;
  if (Bits[X86::FeatureTaggedGlobals]) AllowTaggedGlobals = true;
  if (Bits[X86::FeatureUINTR]) HasUINTR = true;
  if (Bits[X86::FeatureUSERMSR]) HasUSERMSR = true;
  if (Bits[X86::FeatureUseGPR32InInlineAsm]) UseInlineAsmGPR32 = true;
  if (Bits[X86::FeatureVAES]) HasVAES = true;
  if (Bits[X86::FeatureVBMI]) HasVBMI = true;
  if (Bits[X86::FeatureVBMI2]) HasVBMI2 = true;
  if (Bits[X86::FeatureVLX]) HasVLX = true;
  if (Bits[X86::FeatureVNNI]) HasVNNI = true;
  if (Bits[X86::FeatureVP2INTERSECT]) HasVP2INTERSECT = true;
  if (Bits[X86::FeatureVPCLMULQDQ]) HasVPCLMULQDQ = true;
  if (Bits[X86::FeatureVPOPCNTDQ]) HasVPOPCNTDQ = true;
  if (Bits[X86::FeatureWAITPKG]) HasWAITPKG = true;
  if (Bits[X86::FeatureWBNOINVD]) HasWBNOINVD = true;
  if (Bits[X86::FeatureWIDEKL]) HasWIDEKL = true;
  if (Bits[X86::FeatureX86_64]) HasX86_64 = true;
  if (Bits[X86::FeatureX87]) HasX87 = true;
  if (Bits[X86::FeatureXOP]) HasXOP = true;
  if (Bits[X86::FeatureXSAVE]) HasXSAVE = true;
  if (Bits[X86::FeatureXSAVEC]) HasXSAVEC = true;
  if (Bits[X86::FeatureXSAVEOPT]) HasXSAVEOPT = true;
  if (Bits[X86::FeatureXSAVES]) HasXSAVES = true;
  if (Bits[X86::FeatureZU]) HasZU = true;
  if (Bits[X86::Is16Bit]) Is16Bit = true;
  if (Bits[X86::Is32Bit]) Is32Bit = true;
  if (Bits[X86::Is64Bit]) Is64Bit = true;
  if (Bits[X86::IsX32]) IsX32 = true;
  if (Bits[X86::ProcIntelAtom]) IsAtom = true;
  if (Bits[X86::TuningAllowLight256Bit]) AllowLight256Bit = true;
  if (Bits[X86::TuningBLSFalseDeps]) HasBLSFalseDeps = true;
  if (Bits[X86::TuningBranchFusion]) HasBranchFusion = true;
  if (Bits[X86::TuningBranchHint]) HasBranchHint = true;
  if (Bits[X86::TuningCOMPRESSFalseDeps]) HasCOMPRESSFalseDeps = true;
  if (Bits[X86::TuningEXPANDFalseDeps]) HasEXPANDFalseDeps = true;
  if (Bits[X86::TuningFast7ByteNOP]) HasFast7ByteNOP = true;
  if (Bits[X86::TuningFast11ByteNOP]) HasFast11ByteNOP = true;
  if (Bits[X86::TuningFast15ByteNOP]) HasFast15ByteNOP = true;
  if (Bits[X86::TuningFastBEXTR]) HasFastBEXTR = true;
  if (Bits[X86::TuningFastDPWSSD]) HasFastDPWSSD = true;
  if (Bits[X86::TuningFastGather]) HasFastGather = true;
  if (Bits[X86::TuningFastHorizontalOps]) HasFastHorizontalOps = true;
  if (Bits[X86::TuningFastImm16]) HasFastImm16 = true;
  if (Bits[X86::TuningFastImmVectorShift]) FastImmVectorShift = true;
  if (Bits[X86::TuningFastLZCNT]) HasFastLZCNT = true;
  if (Bits[X86::TuningFastMOVBE]) HasFastMOVBE = true;
  if (Bits[X86::TuningFastSHLDRotate]) HasFastSHLDRotate = true;
  if (Bits[X86::TuningFastScalarFSQRT]) HasFastScalarFSQRT = true;
  if (Bits[X86::TuningFastScalarShiftMasks]) HasFastScalarShiftMasks = true;
  if (Bits[X86::TuningFastVariableCrossLaneShuffle]) HasFastVariableCrossLaneShuffle = true;
  if (Bits[X86::TuningFastVariablePerLaneShuffle]) HasFastVariablePerLaneShuffle = true;
  if (Bits[X86::TuningFastVectorFSQRT]) HasFastVectorFSQRT = true;
  if (Bits[X86::TuningFastVectorShiftMasks]) HasFastVectorShiftMasks = true;
  if (Bits[X86::TuningGETMANTFalseDeps]) HasGETMANTFalseDeps = true;
  if (Bits[X86::TuningInsertVZEROUPPER]) InsertVZEROUPPER = true;
  if (Bits[X86::TuningLEAForSP]) UseLeaForSP = true;
  if (Bits[X86::TuningLEAUsesAG]) LeaUsesAG = true;
  if (Bits[X86::TuningLZCNTFalseDeps]) HasLZCNTFalseDeps = true;
  if (Bits[X86::TuningMULCFalseDeps]) HasMULCFalseDeps = true;
  if (Bits[X86::TuningMULLQFalseDeps]) HasMULLQFalseDeps = true;
  if (Bits[X86::TuningMacroFusion]) HasMacroFusion = true;
  if (Bits[X86::TuningNDDMem]) HasNDDM = true;
  if (Bits[X86::TuningNoDomainDelay]) NoDomainDelay = true;
  if (Bits[X86::TuningNoDomainDelayBlend]) NoDomainDelayBlend = true;
  if (Bits[X86::TuningNoDomainDelayMov]) NoDomainDelayMov = true;
  if (Bits[X86::TuningNoDomainDelayShuffle]) NoDomainDelayShuffle = true;
  if (Bits[X86::TuningPERMFalseDeps]) HasPERMFalseDeps = true;
  if (Bits[X86::TuningPOPCNTFalseDeps]) HasPOPCNTFalseDeps = true;
  if (Bits[X86::TuningPadShortFunctions]) PadShortFunctions = true;
  if (Bits[X86::TuningPrefer128Bit]) Prefer128Bit = true;
  if (Bits[X86::TuningPrefer256Bit]) Prefer256Bit = true;
  if (Bits[X86::TuningPreferLegacySetCC]) PreferLegacySetCC = true;
  if (Bits[X86::TuningPreferMaskRegisters]) PreferMaskRegisters = true;
  if (Bits[X86::TuningPreferMovmskOverVTest]) PreferMovmskOverVTest = true;
  if (Bits[X86::TuningPreferNoGather]) PreferGather = false;
  if (Bits[X86::TuningPreferNoScatter]) PreferScatter = false;
  if (Bits[X86::TuningPreferShiftShuffle]) PreferLowerShuffleAsShift = true;
  if (Bits[X86::TuningRANGEFalseDeps]) HasRANGEFalseDeps = true;
  if (Bits[X86::TuningSBBDepBreaking]) HasSBBDepBreaking = true;
  if (Bits[X86::TuningSlow3OpsLEA]) Slow3OpsLEA = true;
  if (Bits[X86::TuningSlowDivide32]) HasSlowDivide32 = true;
  if (Bits[X86::TuningSlowDivide64]) HasSlowDivide64 = true;
  if (Bits[X86::TuningSlowIncDec]) SlowIncDec = true;
  if (Bits[X86::TuningSlowIndirectCall]) SlowIndirectCall = true;
  if (Bits[X86::TuningSlowLEA]) SlowLEA = true;
  if (Bits[X86::TuningSlowPMADDWD]) IsPMADDWDSlow = true;
  if (Bits[X86::TuningSlowPMULLD]) IsPMULLDSlow = true;
  if (Bits[X86::TuningSlowPMULLQ]) IsPMULLQSlow = true;
  if (Bits[X86::TuningSlowSHLD]) IsSHLDSlow = true;
  if (Bits[X86::TuningSlowTwoMemOps]) SlowTwoMemOps = true;
  if (Bits[X86::TuningSlowUAMem16]) IsUnalignedMem16Slow = true;
  if (Bits[X86::TuningSlowUAMem32]) IsUnalignedMem32Slow = true;
  if (Bits[X86::TuningTZCNTFalseDeps]) HasTZCNTFalseDeps = true;
  if (Bits[X86::TuningUseGLMDivSqrtCosts]) UseGLMDivSqrtCosts = true;
  if (Bits[X86::TuningUseSLMArithCosts]) UseSLMArithCosts = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace X86_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace X86_MC
struct X86GenSubtargetInfo : public TargetSubtargetInfo {
  explicit X86GenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class X86HwModeBits : unsigned {
    DefaultMode = 0,
    X86_64 = (1 << 0),
    X86_64_X32 = (1 << 1),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/X86_64_X32),
  };
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
  const FeatureBitset &getInlineIgnoreFeatures() const override;
  const FeatureBitset &getInlineInverseFeatures() const override;
  const FeatureBitset &getInlineMustMatchFeatures() const override;
  bool isZeroIdiom(const MachineInstr *MI, APInt &Mask) const override;
  bool isDependencyBreaking(const MachineInstr *MI, APInt &Mask) const override;
  bool isOptimizableRegisterMove(const MachineInstr *MI) const override;
};

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_HEADER

#ifdef GET_SUBTARGETINFO_CTOR
#undef GET_SUBTARGETINFO_CTOR

#include "llvm/CodeGen/TargetSchedule.h"

namespace llvm_ks {

extern const llvm_ks::StringRef X86Names[];
extern const llvm_ks::SubtargetFeatureKVStorage<230, 12651> X86FeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<136, 1412> X86SubTypeKVStorage;
extern const llvm_ks::MCSchedModel X86SchedModels[];
extern const llvm_ks::MCWriteProcResEntry X86WriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry X86WriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry X86ReadAdvanceTable[];
X86GenSubtargetInfo::X86GenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(X86SubTypeKVStorage.Strings), ArrayRef(X86FeatureKVStorage.Features), ArrayRef(X86SubTypeKVStorage.SubTypes), X86SchedModels, 
                        X86WriteProcResTable, X86WriteLatencyTable, X86ReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned X86GenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  switch (SchedClass) {
  case 668: // CMPXCHG8rm
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3066; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3067; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3068; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3069; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3070; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3071; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3072; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3073; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3074; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      return 3075; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
    }
    break;
  case 687: // CMPXCHG8rr
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3076; // JWriteLOCK_CMPXCHG8B
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3077; // JWriteLOCK_CMPXCHG16B
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3078; // JWriteLOCK_CMPXCHG8rm
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3079; // JWriteLOCK_CMPXCHGrm
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3080; // JWriteCMPXCHG8B
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3081; // JWriteCMPXCHG16B
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3082; // JWriteCMPXCHG8rm
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3083; // WriteCMPXCHGRMW
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3084; // JWriteCMPXCHG8rr
      return 3085; // WriteCMPXCHG
    }
    break;
  case 691: // CMPXCHG16rm_CMPXCHG32rm_CMPXCHG64rm
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3066; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3067; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3068; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3069; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3070; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3071; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3072; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3073; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3074; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      return 3075; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
    }
    break;
  case 694: // CMPXCHG8B
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3086; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3087; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3088; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3089; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3090; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3091; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3092; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3093; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3094; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      return 3095; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
    }
    break;
  case 700: // CMPXCHG16B
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3086; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3087; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3088; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3089; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3090; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3091; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3092; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3093; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3094; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      return 3095; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
    }
    break;
  case 790: // XADD16rm_XADD32rm_XADD64rm_XADD8rm
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (X86InstrInfo::hasLockPrefix(*MI))
        return 3096; // JWriteLOCK_XADDrm_XCHG_Part_JWriteXCHGrm_LdSt_Part_ReadAfterLd
      return 3097; // JWriteXADDrm_XCHG_Part_JWriteXADDrm_LdSt_Part_ReadAfterLd
    }
    break;
  case 807: // SUB32rr_SUB64rr_XOR32rr_XOR64rr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 808: // XORPSrr_VXORPSrr_XORPDrr_VXORPDrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 809: // VXORPSYrr_VXORPDYrr
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3114; // JWriteZeroIdiomYmm
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    break;
  case 810: // PXORrr_VPXORrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 811: // PSUBBrr_VPSUBBrr_PSUBDrr_VPSUBDrr_VPSUBQrr_PSUBWrr_VPSUBWrr_PCMPGTBrr_VPCMPGTBrr_PCMPGTDrr_VPCMPGTDrr_PCMPGTWrr_VPCMPGTWrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3117; // SKLWritePSUB
    }
    break;
  case 812: // PSUBQrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3117; // SKLWritePSUB
    }
    break;
  case 813: // PCMPGTQrr_VPCMPGTQrr
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3122; // BWWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3124; // SKXWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3120; // SBWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3121; // HWWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3125; // ICXWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3123; // SKLWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 814: // CMOV16rr_CMOV32rr_CMOV64rr
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3129; // BWWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3131; // SKXWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3126; // SBWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3128; // HWWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3132; // ICXWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if ((
            MI->getOperand(3).getImm() == X86::COND_A
            || MI->getOperand(3).getImm() == X86::COND_BE
          ))
        return 3130; // SKLWriteCMOVA_CMOVBErr
      return 3127; // WriteCMOV
    }
    break;
  case 815: // CMOV16rm_CMOV32rm_CMOV64rm
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(7).getImm() == X86::COND_BE)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_A)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_L)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_GE)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_LE)
        return 3137; // PdWriteCMOVm
      if (MI->getOperand(7).getImm() == X86::COND_G)
        return 3137; // PdWriteCMOVm
      return 3134; // WriteCMOVLd
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3136; // BWWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3139; // SKXWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3133; // SBWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3135; // HWWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3140; // ICXWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if ((
            MI->getOperand(7).getImm() == X86::COND_A
            || MI->getOperand(7).getImm() == X86::COND_BE
          ))
        return 3138; // SKLWriteCMOVA_CMOVBErm
      return 3134; // WriteCMOVLd
    }
    break;
  case 816: // SETCCr
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3144; // BWWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3146; // SKXWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3141; // SBWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3143; // HWWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3147; // ICXWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if ((
            MI->getOperand(1).getImm() == X86::COND_A
            || MI->getOperand(1).getImm() == X86::COND_BE
          ))
        return 3145; // SKLWriteSETA_SETBEr
      return 3142; // WriteSETCC
    }
    break;
  case 817: // SETCCm
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(5).getImm() == X86::COND_GE)
        return 3152; // PdWriteSETGEmSETGmSETLEmSETLm
      if (MI->getOperand(5).getImm() == X86::COND_G)
        return 3152; // PdWriteSETGEmSETGmSETLEmSETLm
      if (MI->getOperand(5).getImm() == X86::COND_LE)
        return 3152; // PdWriteSETGEmSETGmSETLEmSETLm
      if (MI->getOperand(5).getImm() == X86::COND_L)
        return 3152; // PdWriteSETGEmSETGmSETLEmSETLm
      return 3149; // WriteSETCCStore
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3151; // BWWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3154; // SKXWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3148; // SBWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3150; // HWWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3155; // ICXWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if ((
            MI->getOperand(5).getImm() == X86::COND_A
            || MI->getOperand(5).getImm() == X86::COND_BE
          ))
        return 3153; // SKLWriteSETA_SETBEm
      return 3149; // WriteSETCCStore
    }
    break;
  case 900: // VPXORYrr
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    break;
  case 901: // VPSUBBYrr_VPSUBDYrr_VPSUBQYrr_VPSUBWYrr_VPCMPGTBYrr_VPCMPGTDYrr_VPCMPGTWYrr
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3117; // SKLWritePSUB
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 902: // VPCMPGTQYrr
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3122; // BWWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3124; // SKXWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3121; // HWWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3125; // ICXWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3123; // SKLWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 903: // ADC16ri8_ADC32ri8_ADC64ri8_SBB16ri8_SBB32ri8_SBB64ri8
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if ((
            MI->getOperand(2).getImm() == 0
            && MI->getOperand(1).getReg() != X86::AX
            && MI->getOperand(1).getReg() != X86::EAX
            && MI->getOperand(1).getReg() != X86::RAX
          ))
        return 3158; // HWWriteADC0
      return 3159; // WriteADC
    }
    break;
  case 911: // PCMPGTQrr
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3122; // BWWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3124; // SKXWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3120; // SBWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3121; // HWWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3125; // ICXWritePCMPGTQ
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3123; // SKLWritePCMPGTQ
    }
    break;
  case 955: // VPERM2F128rri
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            MI->getOperand(1).getReg() == MI->getOperand(2).getReg()
            && MI->getOperand(3).getImm() == 136
          ))
        return 3114; // JWriteZeroIdiomYmm
      return 3160; // WriteFShuffle256
    }
    break;
  case 1010: // LEA32r_LEA64r_LEA64_32r
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3164; // PdWrite3OpsLEA
      return 3162; // WriteLEA
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3165; // JWrite3OpsLEA
      return 3162; // WriteLEA
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3161; // Zn3Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3163; // Zn4Write3OpsLEA
      return 3162; // WriteLEA
    }
    break;
  case 1012: // LCMPXCHG8
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3066; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3067; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3068; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3069; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3070; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3071; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3072; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3073; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3074; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      return 3075; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
    }
    break;
  case 1013: // LCMPXCHG16B
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3086; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3087; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3088; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3089; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3090; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3091; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3092; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3093; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3094; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      return 3095; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
    }
    break;
  case 1047: // XOR32rr_REV_XOR64rr_REV_SUB32rr_REV_SUB64rr_REV
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 1048: // CMP8rr_CMP8rr_REV_CMP16rr_CMP16rr_REV_CMP32rr_CMP32rr_REV_CMP64rr_CMP64rr_REV
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(0).getReg() == MI->getOperand(1).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 1049: // VXORPSrr_VXORPDrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1050: // VANDNPSrr_VANDNPDrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1051: // VANDNPSYrr_VANDNPDYrr
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3114; // JWriteZeroIdiomYmm
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    break;
  case 1052: // VPXORrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1053: // VPANDNrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1054: // VPANDNYrr
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    break;
  case 1055: // VPSUBBrr_VPSUBWrr_VPSUBDrr_VPSUBQrr_VPCMPGTBrr_VPCMPGTWrr_VPCMPGTDrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3117; // SKLWritePSUB
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1143: // VXORPSZ128rr_VXORPDZ128rr_VANDNPSZ128rr_VANDNPDZ128rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1144: // VXORPSZ256rr_VXORPDZ256rr_VANDNPSZ256rr_VANDNPDZ256rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    break;
  case 1145: // VXORPSZrr_VXORPDZrr_VANDNPSZrr_VANDNPDZrr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    break;
  case 1146: // VPXORDZ128rr_VPXORQZ128rr_VPANDNDZ128rr_VPANDNQZ128rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1147: // VPXORDZ256rr_VPXORQZ256rr_VPANDNDZ256rr_VPANDNQZ256rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    break;
  case 1148: // VPXORDZrr_VPXORQZrr_VPANDNDZrr_VPANDNQZrr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    break;
  case 1149: // VPSUBBZ128rr_VPSUBWZ128rr_VPSUBDZ128rr_VPSUBQZ128rr_VPCMPGTBZ128rr_VPCMPGTWZ128rr_VPCMPGTDZ128rr_VPCMPGTQZ128rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1150: // VPSUBBZ256rr_VPSUBWZ256rr_VPSUBDZ256rr_VPSUBQZ256rr_VPCMPGTBZ256rr_VPCMPGTWZ256rr_VPCMPGTDZ256rr_VPCMPGTQZ256rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1151: // VPSUBBZrr_VPSUBWZrr_VPSUBDZrr_VPSUBQZrr_VPCMPGTBZrr_VPCMPGTWZrr_VPCMPGTDZrr_VPCMPGTQZrr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3118; // SKXWritePSUB
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3119; // ICXWritePSUB
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1153: // LXADD8_LXADD16_LXADD32_LXADD64
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (X86InstrInfo::hasLockPrefix(*MI))
        return 3096; // JWriteLOCK_XADDrm_XCHG_Part_JWriteXCHGrm_LdSt_Part_ReadAfterLd
      return 3097; // JWriteXADDrm_XCHG_Part_JWriteXADDrm_LdSt_Part_ReadAfterLd
    }
    break;
  case 1191: // ANDNPSrr_ANDNPDrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1192: // MMX_PXORrr_MMX_PANDNrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3168; // WriteVecLogic
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3168; // WriteVecLogic
    }
    break;
  case 1193: // PANDNrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1194: // MMX_PSUBBrr_MMX_PSUBDrr_MMX_PSUBWrr_MMX_PCMPGTBrr_MMX_PCMPGTDrr_MMX_PCMPGTWrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3169; // WriteVecALU
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3169; // WriteVecALU
    }
    break;
  case 1195: // MMX_PSUBQrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3169; // WriteVecALU
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3169; // WriteVecALU
    }
    break;
  case 1196: // LCMPXCHG16_LCMPXCHG32_LCMPXCHG64
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3066; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3067; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3068; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3069; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3070; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3071; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3072; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3073; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3074; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
      return 3075; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd
    }
    break;
  case 1197: // CMPXCHG16rr_CMPXCHG32rr_CMPXCHG64rr
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3076; // JWriteLOCK_CMPXCHG8B
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3077; // JWriteLOCK_CMPXCHG16B
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3078; // JWriteLOCK_CMPXCHG8rm
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3079; // JWriteLOCK_CMPXCHGrm
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3080; // JWriteCMPXCHG8B
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3081; // JWriteCMPXCHG16B
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3082; // JWriteCMPXCHG8rm
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3083; // WriteCMPXCHGRMW
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3084; // JWriteCMPXCHG8rr
      return 3085; // WriteCMPXCHG
    }
    break;
  case 1198: // LCMPXCHG8B
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode())
          ))
        return 3086; // JWriteLOCK_CMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3087; // JWriteLOCK_CMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode())
          ))
        return 3088; // JWriteLOCK_CMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if ((
            X86InstrInfo::hasLockPrefix(*MI)
            && llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode())
          ))
        return 3089; // JWriteLOCK_CMPXCHGrm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG8B, X86::LCMPXCHG8B}, MI->getOpcode()))
        return 3090; // JWriteCMPXCHG8B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::CMPXCHG16B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3091; // JWriteCMPXCHG16B_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm}, MI->getOpcode()))
        return 3092; // JWriteCMPXCHG8rm_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (llvm_ks::is_contained({X86::LCMPXCHG8, X86::CMPXCHG8rm, X86::CMPXCHG16rm, X86::CMPXCHG32rm, X86::CMPXCHG64rm, X86::LCMPXCHG16, X86::LCMPXCHG32, X86::LCMPXCHG64, X86::LCMPXCHG8B, X86::LCMPXCHG16B}, MI->getOpcode()))
        return 3093; // WriteCMPXCHGRMW_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      if (( MI->getOpcode() == X86::CMPXCHG8rr ))
        return 3094; // JWriteCMPXCHG8rr_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
      return 3095; // WriteCMPXCHG_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadDefault_ReadAfterLd_ReadAfterLd_ReadAfterLd_ReadAfterLd
    }
    break;
  case 1199: // INC8m_INC16m_INC32m_INC64m_DEC8m_DEC16m_DEC32m_DEC64m_NOT8m_NOT16m_NOT32m_NOT64m_NEG8m_NEG16m_NEG32m_NEG64m
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (X86InstrInfo::hasLockPrefix(*MI))
        return 3170; // JWriteLOCK_ALURMW
      return 3171; // WriteALURMW
    }
    break;
  case 1201: // MMX_PSUBSBrr_MMX_PSUBSWrr_MMX_PSUBUSBrr_MMX_PSUBUSWrr
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3169; // WriteVecALU
    }
    break;
  case 1202: // PSUBSBrr_VPSUBSBrr_PSUBSWrr_VPSUBSWrr_PSUBUSBrr_VPSUBUSBrr_PSUBUSWrr_VPSUBUSWrr
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1204: // MMX_PCMPGTBrr_MMX_PCMPGTDrr_MMX_PCMPGTWrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3169; // WriteVecALU
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3169; // WriteVecALU
    }
    break;
  case 1221: // PCMPGTBrr_PCMPGTDrr_PCMPGTWrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1222: // VPCMPGTBrr_VPCMPGTDrr_VPCMPGTWrr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1223: // VPCMPGTBYrr_VPCMPGTDYrr_VPCMPGTWYrr
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1251: // VPCMPGTBZ128rr_VPCMPGTDZ128rr_VPCMPGTQZ128rr_VPCMPGTWZ128rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3116; // WriteVecALUX
    }
    break;
  case 1252: // VPCMPGTBZ256rr_VPCMPGTDZ256rr_VPCMPGTQZ256rr_VPCMPGTWZ256rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1253: // VPCMPGTBZrr_VPCMPGTDZrr_VPCMPGTQZrr_VPCMPGTWZrr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3157; // WriteVecALUY
    }
    break;
  case 1407: // VXORPSZ128rr_VXORPDZ128rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3112; // WriteFLogic
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3112; // WriteFLogic
    }
    break;
  case 1408: // VXORPSZ256rr_VXORPDZ256rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3113; // WriteFLogicY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3113; // WriteFLogicY
    }
    break;
  case 1409: // VXORPSZrr_VXORPDZrr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3166; // WriteFLogicZ
    }
    break;
  case 1410: // VPXORDZ128rr_VPXORQZ128rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3115; // WriteVecLogicX
    }
    break;
  case 1411: // VPXORDZ256rr_VPXORQZ256rr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3156; // WriteVecLogicY
    }
    break;
  case 1412: // VPXORDZrr_VPXORQZrr
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3167; // WriteVecLogicZ
    }
    break;
  case 1452: // DEC8m_INC8m_NEG8m_NOT8m
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (X86InstrInfo::hasLockPrefix(*MI))
        return 3170; // JWriteLOCK_ALURMW
      return 3171; // WriteALURMW
    }
    break;
  case 1459: // XOR32rr_XOR64rr
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3104; // PdWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 7) { // BroadwellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3101; // BWWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3105; // JWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 12) { // SkylakeServerModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3107; // SKXWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 13) { // SandyBridgeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3098; // SBWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 14) { // HaswellModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3100; // HWWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 16) { // IceLakeModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3108; // ICXWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 19) { // SkylakeClientModel
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3106; // SKLWriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 1460: // XOR32rr_REV_XOR64rr_REV
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3109; // C4GM4WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3110; // C4GM7WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3111; // C4GM8WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3102; // Zn3WriteZeroLatency
      return 3099; // WriteALU
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
        return 3103; // Zn4WriteZeroLatency
      return 3099; // WriteALU
    }
    break;
  case 1647: // XADD16rm_XADD32rm_XADD64rm
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if (X86InstrInfo::hasLockPrefix(*MI))
        return 3096; // JWriteLOCK_XADDrm_XCHG_Part_JWriteXCHGrm_LdSt_Part_ReadAfterLd
      return 3097; // JWriteXADDrm_XCHG_Part_JWriteXADDrm_LdSt_Part_ReadAfterLd
    }
    break;
  case 2442: // LEA64r_LEA64_32r
    if (SchedModel->getProcessorID() == 5) { // BdVer2Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3164; // PdWrite3OpsLEA
      return 3162; // WriteLEA
    }
    if (SchedModel->getProcessorID() == 8) { // BtVer2Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3165; // JWrite3OpsLEA
      return 3162; // WriteLEA
    }
    if (SchedModel->getProcessorID() == 9) { // C864GM4Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3172; // C4GM4Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (SchedModel->getProcessorID() == 10) { // C864GM7Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3173; // C4GM7Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (SchedModel->getProcessorID() == 11) { // C864GM8Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3174; // C4GM8Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (SchedModel->getProcessorID() == 21) { // Znver3Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3161; // Zn3Write3OpsLEA
      return 3162; // WriteLEA
    }
    if (SchedModel->getProcessorID() == 22) { // Znver4Model
      if ((
            X86InstrInfo::isThreeOperandsLEA(*MI)
            || (
              MI->getOperand(2).isImm() 
              && MI->getOperand(2).getImm() != 1
            )
          ))
        return 3163; // Zn4Write3OpsLEA
      return 3162; // WriteLEA
    }
    break;
  };
  report_fatal_error("Expected a variant SchedClass");
} // X86GenSubtargetInfo::resolveSchedClass

unsigned X86GenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return X86_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // X86GenSubtargetInfo::resolveVariantSchedClass

bool X86GenSubtargetInfo::isZeroIdiom(const MachineInstr *MI, APInt &Mask) const {
  unsigned ProcessorID = getSchedModel().getProcessorID();
  switch(MI->getOpcode()) {
  default:
    break;
  case X86::VPERM2F128rri:
    if (ProcessorID == 8) {
      Mask.clearAllBits();
      return (
        MI->getOperand(1).getReg() == MI->getOperand(2).getReg()
        && MI->getOperand(3).getImm() == 136
      );
    }
    break;

  case X86::VANDNPSZrr:
  case X86::VANDNPDZrr:
  case X86::VANDNPSZ128rr:
  case X86::VANDNPDZ128rr:
  case X86::VANDNPSZ256rr:
  case X86::VANDNPDZ256rr:
  case X86::VPCMPGTBZrr:
  case X86::VPCMPGTWZrr:
  case X86::VPCMPGTDZrr:
  case X86::VPCMPGTQZrr:
  case X86::VPCMPGTBZ128rr:
  case X86::VPCMPGTWZ128rr:
  case X86::VPCMPGTDZ128rr:
  case X86::VPCMPGTQZ128rr:
  case X86::VPCMPGTBZ256rr:
  case X86::VPCMPGTWZ256rr:
  case X86::VPCMPGTDZ256rr:
  case X86::VPCMPGTQZ256rr:
  case X86::VPANDNDZrr:
  case X86::VPANDNQZrr:
  case X86::VPANDNDZ128rr:
  case X86::VPANDNQZ128rr:
  case X86::VPANDNDZ256rr:
  case X86::VPANDNQZ256rr:
    if (ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::MMX_PXORrr:
  case X86::MMX_PANDNrr:
  case X86::MMX_PSUBBrr:
  case X86::MMX_PSUBDrr:
  case X86::MMX_PSUBQrr:
  case X86::MMX_PSUBWrr:
  case X86::MMX_PSUBSBrr:
  case X86::MMX_PSUBSWrr:
  case X86::MMX_PSUBUSBrr:
  case X86::MMX_PSUBUSWrr:
  case X86::MMX_PCMPGTBrr:
  case X86::MMX_PCMPGTDrr:
  case X86::MMX_PCMPGTWrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 20) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::XOR32rr_REV:
  case X86::XOR64rr_REV:
  case X86::SUB32rr_REV:
  case X86::SUB64rr_REV:
  case X86::VPSUBSBYrr:
  case X86::VPSUBSWYrr:
  case X86::VPSUBUSBYrr:
  case X86::VPSUBUSWYrr:
    if (ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::VXORPSZrr:
  case X86::VXORPDZrr:
  case X86::VXORPSZ128rr:
  case X86::VXORPDZ128rr:
  case X86::VXORPSZ256rr:
  case X86::VXORPDZ256rr:
  case X86::VPXORDZrr:
  case X86::VPXORQZrr:
  case X86::VPXORDZ128rr:
  case X86::VPXORQZ128rr:
  case X86::VPXORDZ256rr:
  case X86::VPXORQZ256rr:
  case X86::VPSUBBZrr:
  case X86::VPSUBWZrr:
  case X86::VPSUBDZrr:
  case X86::VPSUBQZrr:
  case X86::VPSUBBZ128rr:
  case X86::VPSUBWZ128rr:
  case X86::VPSUBDZ128rr:
  case X86::VPSUBQZ128rr:
  case X86::VPSUBBZ256rr:
  case X86::VPSUBWZ256rr:
  case X86::VPSUBDZ256rr:
  case X86::VPSUBQZ256rr:
    if (ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 16 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::VPANDNYrr:
    if (ProcessorID == 6 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::PSUBSBrr:
  case X86::PSUBSWrr:
  case X86::PSUBUSBrr:
  case X86::PSUBUSWrr:
  case X86::VPSUBSBrr:
  case X86::VPSUBSWrr:
  case X86::VPSUBUSBrr:
  case X86::VPSUBUSWrr:
    if (ProcessorID == 5 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::ANDNPSrr:
  case X86::ANDNPDrr:
  case X86::PANDNrr:
  case X86::VANDNPSrr:
  case X86::VANDNPDrr:
  case X86::VPANDNrr:
  case X86::VANDNPSYrr:
  case X86::VANDNPDYrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::VPCMPGTQYrr:
    if (ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::VPXORYrr:
  case X86::VPSUBBYrr:
  case X86::VPSUBWYrr:
  case X86::VPSUBDYrr:
  case X86::VPSUBQYrr:
  case X86::VPCMPGTBYrr:
  case X86::VPCMPGTWYrr:
  case X86::VPCMPGTDYrr:
    if (ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::PCMPGTQrr:
    if (ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 13 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::VXORPSYrr:
  case X86::VXORPDYrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::SUB32rr:
  case X86::SUB64rr:
  case X86::XOR64rr:
  case X86::PSUBBrr:
  case X86::PSUBWrr:
  case X86::PSUBDrr:
  case X86::PSUBQrr:
  case X86::PCMPGTBrr:
  case X86::PCMPGTDrr:
  case X86::PCMPGTWrr:
  case X86::VXORPSrr:
  case X86::VXORPDrr:
  case X86::VPXORrr:
  case X86::VPSUBBrr:
  case X86::VPSUBWrr:
  case X86::VPSUBDrr:
  case X86::VPSUBQrr:
  case X86::VPCMPGTBrr:
  case X86::VPCMPGTWrr:
  case X86::VPCMPGTDrr:
  case X86::VPCMPGTQrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 13 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::XOR32rr:
  case X86::XORPSrr:
  case X86::XORPDrr:
  case X86::PXORrr:
    if (ProcessorID == 4 || ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 13 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;
  }

  return false;
} // X86GenSubtargetInfo::isZeroIdiom

bool X86GenSubtargetInfo::isDependencyBreaking(const MachineInstr *MI, APInt &Mask) const {
  if (isZeroIdiom(MI, Mask))
    return true;

  unsigned ProcessorID = getSchedModel().getProcessorID();
  switch(MI->getOpcode()) {
  default:
    break;
  case X86::SBB32rr_REV:
  case X86::SBB64rr_REV:
    if (ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::CMP8rr:
  case X86::CMP8rr_REV:
  case X86::CMP16rr:
  case X86::CMP16rr_REV:
  case X86::CMP32rr_REV:
  case X86::CMP64rr_REV:
    if (ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(0).getReg() == MI->getOperand(1).getReg();
    }
    break;

  case X86::MMX_PCMPEQBrr:
  case X86::MMX_PCMPEQWrr:
  case X86::MMX_PCMPEQDrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 20 || ProcessorID == 21) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::VPCMPEQBYrr:
  case X86::VPCMPEQWYrr:
  case X86::VPCMPEQDYrr:
  case X86::VPCMPEQQYrr:
    if (ProcessorID == 6 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::PCMPEQQrr:
  case X86::VPCMPEQQrr:
    if (ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::SBB32rr:
  case X86::SBB64rr:
  case X86::PCMPEQBrr:
  case X86::PCMPEQWrr:
  case X86::PCMPEQDrr:
  case X86::VPCMPEQBrr:
  case X86::VPCMPEQWrr:
  case X86::VPCMPEQDrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(1).getReg() == MI->getOperand(2).getReg();
    }
    break;

  case X86::CMP32rr:
  case X86::CMP64rr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI->getOperand(0).getReg() == MI->getOperand(1).getReg();
    }
    break;
  }

  return false;
} // X86GenSubtargetInfo::isDependencyBreaking

bool X86GenSubtargetInfo::isOptimizableRegisterMove(const MachineInstr *MI) const {
  unsigned ProcessorID = getSchedModel().getProcessorID();
  switch(MI->getOpcode()) {
  default:
    break;
  case X86::MMX_MOVQ64rr:
    if (ProcessorID == 8) {
      return true;
    }
    break;

  case X86::MOV32rr_REV:
  case X86::MOV64rr_REV:
  case X86::MOVSX32rr32:
  case X86::XCHG32rr:
  case X86::XCHG32ar:
  case X86::XCHG64rr:
  case X86::XCHG64ar:
  case X86::MOVAPSrr_REV:
  case X86::MOVUPSrr_REV:
  case X86::MOVAPDrr_REV:
  case X86::MOVUPDrr_REV:
  case X86::MOVDQArr_REV:
  case X86::MOVDQUrr_REV:
  case X86::VMOVAPSrr_REV:
  case X86::VMOVUPSrr_REV:
  case X86::VMOVAPDrr_REV:
  case X86::VMOVUPDrr_REV:
  case X86::VMOVDQArr_REV:
  case X86::VMOVDQUrr_REV:
  case X86::VMOVAPSYrr:
  case X86::VMOVAPSYrr_REV:
  case X86::VMOVUPSYrr:
  case X86::VMOVUPSYrr_REV:
  case X86::VMOVAPDYrr:
  case X86::VMOVAPDYrr_REV:
  case X86::VMOVUPDYrr:
  case X86::VMOVUPDYrr_REV:
  case X86::VMOVDQAYrr:
  case X86::VMOVDQAYrr_REV:
  case X86::VMOVDQUYrr:
  case X86::VMOVDQUYrr_REV:
    if (ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      return true;
    }
    break;

  case X86::MOV32rr:
  case X86::MOV64rr:
  case X86::MOVAPSrr:
  case X86::MOVUPSrr:
  case X86::MOVAPDrr:
  case X86::MOVUPDrr:
  case X86::MOVDQArr:
  case X86::MOVDQUrr:
  case X86::VMOVAPSrr:
  case X86::VMOVUPSrr:
  case X86::VMOVAPDrr:
  case X86::VMOVUPDrr:
  case X86::VMOVDQArr:
  case X86::VMOVDQUrr:
    if (ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      return true;
    }
    break;
  }

  return false;
} // X86GenSubtargetInfo::isOptimizableRegisterMove

unsigned X86GenSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const auto *Subtarget =
      static_cast<const X86Subtarget *>(this);
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((Subtarget->is64Bit()) && (!Subtarget->getTargetTriple().isX32())) Modes |= (1 << 0);
  if ((Subtarget->getTargetTriple().isX32())) Modes |= (1 << 1);
  return Modes;
}
unsigned X86GenSubtargetInfo::getHwMode(enum HwModeType type) const {
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
    Modes &= 3;
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
const FeatureBitset &X86GenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
X86::TuningAllowLight256Bit,
X86::TuningFastImmVectorShift,
X86::TuningBLSFalseDeps,
X86::TuningBranchFusion,
X86::TuningBranchHint,
X86::TuningCOMPRESSFalseDeps,
X86::TuningEXPANDFalseDeps,
X86::TuningFast11ByteNOP,
X86::TuningFast15ByteNOP,
X86::TuningFast7ByteNOP,
X86::TuningFastBEXTR,
X86::TuningFastDPWSSD,
X86::TuningFastGather,
X86::TuningFastHorizontalOps,
X86::TuningFastImm16,
X86::TuningFastLZCNT,
X86::TuningFastMOVBE,
X86::TuningFastSHLDRotate,
X86::TuningFastScalarFSQRT,
X86::TuningFastScalarShiftMasks,
X86::TuningFastVariableCrossLaneShuffle,
X86::TuningFastVariablePerLaneShuffle,
X86::TuningFastVectorFSQRT,
X86::TuningFastVectorShiftMasks,
X86::TuningGETMANTFalseDeps,
X86::FeatureLAHFSAHF64,
X86::TuningLZCNTFalseDeps,
X86::TuningMULCFalseDeps,
X86::TuningMULLQFalseDeps,
X86::TuningMacroFusion,
X86::TuningNDDMem,
X86::FeatureNOPL,
X86::TuningPERMFalseDeps,
X86::TuningPOPCNTFalseDeps,
X86::TuningRANGEFalseDeps,
X86::TuningSBBDepBreaking,
X86::FeatureSSEUnalignedMem,
X86::TuningSlowDivide32,
X86::TuningSlowDivide64,
X86::TuningTZCNTFalseDeps,
X86::FeatureX86_64,
X86::TuningInsertVZEROUPPER,
X86::ProcIntelAtom,
X86::TuningSlowPMADDWD,
X86::TuningSlowPMULLD,
X86::TuningSlowPMULLQ,
X86::TuningSlowSHLD,
X86::TuningSlowUAMem16,
X86::TuningSlowUAMem32,
X86::TuningLEAUsesAG,
X86::TuningNoDomainDelay,
X86::TuningNoDomainDelayBlend,
X86::TuningNoDomainDelayMov,
X86::TuningNoDomainDelayShuffle,
X86::TuningPadShortFunctions,
X86::TuningPrefer128Bit,
X86::TuningPrefer256Bit,
X86::TuningPreferNoGather,
X86::TuningPreferLegacySetCC,
X86::TuningPreferShiftShuffle,
X86::TuningPreferMaskRegisters,
X86::TuningPreferMovmskOverVTest,
X86::TuningPreferNoScatter,
X86::TuningSlow3OpsLEA,
X86::TuningSlowIncDec,
X86::TuningSlowIndirectCall,
X86::TuningSlowLEA,
X86::TuningSlowTwoMemOps,
X86::TuningUseGLMDivSqrtCosts,
X86::TuningLEAForSP,
X86::TuningUseSLMArithCosts,
  };
  return Features;
}

const FeatureBitset &X86GenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &X86GenSubtargetInfo::getInlineMustMatchFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}


} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_CTOR

#ifdef GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS
#undef GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS

bool isZeroIdiom(const MCInst &MI, APInt &Mask, unsigned ProcessorID) const override;
bool isDependencyBreaking(const MCInst &MI, APInt &Mask, unsigned ProcessorID) const override;
bool isOptimizableRegisterMove(const MCInst &MI, unsigned ProcessorID) const override;

#endif // GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS

#ifdef GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS
#undef GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS

bool X86MCInstrAnalysis::isZeroIdiom(const MCInst &MI, APInt &Mask, unsigned ProcessorID) const {
  switch(MI.getOpcode()) {
  default:
    break;
  case X86::VPERM2F128rri:
    if (ProcessorID == 8) {
      Mask.clearAllBits();
      return (
        MI.getOperand(1).getReg() == MI.getOperand(2).getReg()
        && MI.getOperand(3).getImm() == 136
      );
    }
    break;

  case X86::VANDNPSZrr:
  case X86::VANDNPDZrr:
  case X86::VANDNPSZ128rr:
  case X86::VANDNPDZ128rr:
  case X86::VANDNPSZ256rr:
  case X86::VANDNPDZ256rr:
  case X86::VPCMPGTBZrr:
  case X86::VPCMPGTWZrr:
  case X86::VPCMPGTDZrr:
  case X86::VPCMPGTQZrr:
  case X86::VPCMPGTBZ128rr:
  case X86::VPCMPGTWZ128rr:
  case X86::VPCMPGTDZ128rr:
  case X86::VPCMPGTQZ128rr:
  case X86::VPCMPGTBZ256rr:
  case X86::VPCMPGTWZ256rr:
  case X86::VPCMPGTDZ256rr:
  case X86::VPCMPGTQZ256rr:
  case X86::VPANDNDZrr:
  case X86::VPANDNQZrr:
  case X86::VPANDNDZ128rr:
  case X86::VPANDNQZ128rr:
  case X86::VPANDNDZ256rr:
  case X86::VPANDNQZ256rr:
    if (ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::MMX_PXORrr:
  case X86::MMX_PANDNrr:
  case X86::MMX_PSUBBrr:
  case X86::MMX_PSUBDrr:
  case X86::MMX_PSUBQrr:
  case X86::MMX_PSUBWrr:
  case X86::MMX_PSUBSBrr:
  case X86::MMX_PSUBSWrr:
  case X86::MMX_PSUBUSBrr:
  case X86::MMX_PSUBUSWrr:
  case X86::MMX_PCMPGTBrr:
  case X86::MMX_PCMPGTDrr:
  case X86::MMX_PCMPGTWrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 20) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::XOR32rr_REV:
  case X86::XOR64rr_REV:
  case X86::SUB32rr_REV:
  case X86::SUB64rr_REV:
  case X86::VPSUBSBYrr:
  case X86::VPSUBSWYrr:
  case X86::VPSUBUSBYrr:
  case X86::VPSUBUSWYrr:
    if (ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::VXORPSZrr:
  case X86::VXORPDZrr:
  case X86::VXORPSZ128rr:
  case X86::VXORPDZ128rr:
  case X86::VXORPSZ256rr:
  case X86::VXORPDZ256rr:
  case X86::VPXORDZrr:
  case X86::VPXORQZrr:
  case X86::VPXORDZ128rr:
  case X86::VPXORQZ128rr:
  case X86::VPXORDZ256rr:
  case X86::VPXORQZ256rr:
  case X86::VPSUBBZrr:
  case X86::VPSUBWZrr:
  case X86::VPSUBDZrr:
  case X86::VPSUBQZrr:
  case X86::VPSUBBZ128rr:
  case X86::VPSUBWZ128rr:
  case X86::VPSUBDZ128rr:
  case X86::VPSUBQZ128rr:
  case X86::VPSUBBZ256rr:
  case X86::VPSUBWZ256rr:
  case X86::VPSUBDZ256rr:
  case X86::VPSUBQZ256rr:
    if (ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 16 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::VPANDNYrr:
    if (ProcessorID == 6 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::PSUBSBrr:
  case X86::PSUBSWrr:
  case X86::PSUBUSBrr:
  case X86::PSUBUSWrr:
  case X86::VPSUBSBrr:
  case X86::VPSUBSWrr:
  case X86::VPSUBUSBrr:
  case X86::VPSUBUSWrr:
    if (ProcessorID == 5 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::ANDNPSrr:
  case X86::ANDNPDrr:
  case X86::PANDNrr:
  case X86::VANDNPSrr:
  case X86::VANDNPDrr:
  case X86::VPANDNrr:
  case X86::VANDNPSYrr:
  case X86::VANDNPDYrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::VPCMPGTQYrr:
    if (ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::VPXORYrr:
  case X86::VPSUBBYrr:
  case X86::VPSUBWYrr:
  case X86::VPSUBDYrr:
  case X86::VPSUBQYrr:
  case X86::VPCMPGTBYrr:
  case X86::VPCMPGTWYrr:
  case X86::VPCMPGTDYrr:
    if (ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::PCMPGTQrr:
    if (ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 13 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::VXORPSYrr:
  case X86::VXORPDYrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::SUB32rr:
  case X86::SUB64rr:
  case X86::XOR64rr:
  case X86::PSUBBrr:
  case X86::PSUBWrr:
  case X86::PSUBDrr:
  case X86::PSUBQrr:
  case X86::PCMPGTBrr:
  case X86::PCMPGTDrr:
  case X86::PCMPGTWrr:
  case X86::VXORPSrr:
  case X86::VXORPDrr:
  case X86::VPXORrr:
  case X86::VPSUBBrr:
  case X86::VPSUBWrr:
  case X86::VPSUBDrr:
  case X86::VPSUBQrr:
  case X86::VPCMPGTBrr:
  case X86::VPCMPGTWrr:
  case X86::VPCMPGTDrr:
  case X86::VPCMPGTQrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 13 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::XOR32rr:
  case X86::XORPSrr:
  case X86::XORPDrr:
  case X86::PXORrr:
    if (ProcessorID == 4 || ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 7 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 12 || ProcessorID == 13 || ProcessorID == 14 || ProcessorID == 16 || ProcessorID == 19 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;
  }

  return false;
} // X86MCInstrAnalysis::isZeroIdiom

bool X86MCInstrAnalysis::isDependencyBreaking(const MCInst &MI, APInt &Mask, unsigned ProcessorID) const {
  if (isZeroIdiom(MI, Mask, ProcessorID))
    return true;

  switch(MI.getOpcode()) {
  default:
    break;
  case X86::SBB32rr_REV:
  case X86::SBB64rr_REV:
    if (ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::CMP8rr:
  case X86::CMP8rr_REV:
  case X86::CMP16rr:
  case X86::CMP16rr_REV:
  case X86::CMP32rr_REV:
  case X86::CMP64rr_REV:
    if (ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(0).getReg() == MI.getOperand(1).getReg();
    }
    break;

  case X86::MMX_PCMPEQBrr:
  case X86::MMX_PCMPEQWrr:
  case X86::MMX_PCMPEQDrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 20 || ProcessorID == 21) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::VPCMPEQBYrr:
  case X86::VPCMPEQWYrr:
  case X86::VPCMPEQDYrr:
  case X86::VPCMPEQQYrr:
    if (ProcessorID == 6 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::PCMPEQQrr:
  case X86::VPCMPEQQrr:
    if (ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::SBB32rr:
  case X86::SBB64rr:
  case X86::PCMPEQBrr:
  case X86::PCMPEQWrr:
  case X86::PCMPEQDrr:
  case X86::VPCMPEQBrr:
  case X86::VPCMPEQWrr:
  case X86::VPCMPEQDrr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(1).getReg() == MI.getOperand(2).getReg();
    }
    break;

  case X86::CMP32rr:
  case X86::CMP64rr:
    if (ProcessorID == 5 || ProcessorID == 6 || ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 20 || ProcessorID == 21 || ProcessorID == 22) {
      Mask.clearAllBits();
      return MI.getOperand(0).getReg() == MI.getOperand(1).getReg();
    }
    break;
  }

  return false;
} // X86MCInstrAnalysis::isDependencyBreaking

bool X86MCInstrAnalysis::isOptimizableRegisterMove(const MCInst &MI, unsigned ProcessorID) const {
  switch(MI.getOpcode()) {
  default:
    break;
  case X86::MMX_MOVQ64rr:
    if (ProcessorID == 8) {
      return true;
    }
    break;

  case X86::MOV32rr_REV:
  case X86::MOV64rr_REV:
  case X86::MOVSX32rr32:
  case X86::XCHG32rr:
  case X86::XCHG32ar:
  case X86::XCHG64rr:
  case X86::XCHG64ar:
  case X86::MOVAPSrr_REV:
  case X86::MOVUPSrr_REV:
  case X86::MOVAPDrr_REV:
  case X86::MOVUPDrr_REV:
  case X86::MOVDQArr_REV:
  case X86::MOVDQUrr_REV:
  case X86::VMOVAPSrr_REV:
  case X86::VMOVUPSrr_REV:
  case X86::VMOVAPDrr_REV:
  case X86::VMOVUPDrr_REV:
  case X86::VMOVDQArr_REV:
  case X86::VMOVDQUrr_REV:
  case X86::VMOVAPSYrr:
  case X86::VMOVAPSYrr_REV:
  case X86::VMOVUPSYrr:
  case X86::VMOVUPSYrr_REV:
  case X86::VMOVAPDYrr:
  case X86::VMOVAPDYrr_REV:
  case X86::VMOVUPDYrr:
  case X86::VMOVUPDYrr_REV:
  case X86::VMOVDQAYrr:
  case X86::VMOVDQAYrr_REV:
  case X86::VMOVDQUYrr:
  case X86::VMOVDQUYrr_REV:
    if (ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      return true;
    }
    break;

  case X86::MOV32rr:
  case X86::MOV64rr:
  case X86::MOVAPSrr:
  case X86::MOVUPSrr:
  case X86::MOVAPDrr:
  case X86::MOVUPDrr:
  case X86::MOVDQArr:
  case X86::MOVDQUrr:
  case X86::VMOVAPSrr:
  case X86::VMOVUPSrr:
  case X86::VMOVAPDrr:
  case X86::VMOVUPDrr:
  case X86::VMOVDQArr:
  case X86::VMOVDQUrr:
    if (ProcessorID == 8 || ProcessorID == 9 || ProcessorID == 10 || ProcessorID == 11 || ProcessorID == 21 || ProcessorID == 22) {
      return true;
    }
    break;
  }

  return false;
} // X86MCInstrAnalysis::isOptimizableRegisterMove


#endif // GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS

