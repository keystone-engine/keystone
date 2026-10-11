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

namespace AMDGPU {

enum {
  Feature16BitInsts = 0,
  Feature45BitNumRecordsBufferResource = 1,
  Feature64BitLiterals = 2,
  Feature1024AddressableVGPRs = 3,
  Feature1536VGPRs = 4,
  FeatureA16 = 5,
  FeatureAddMinMaxInsts = 6,
  FeatureAddNoCarryInsts = 7,
  FeatureAddSubU64Insts = 8,
  FeatureAddressableLocalMemorySize32768 = 9,
  FeatureAddressableLocalMemorySize65536 = 10,
  FeatureAddressableLocalMemorySize163840 = 11,
  FeatureAddressableLocalMemorySize327680 = 12,
  FeatureAgentScopeFineGrainedRemoteMemoryAtomics = 13,
  FeatureApertureRegs = 14,
  FeatureArchitectedFlatScratch = 15,
  FeatureArchitectedSGPRs = 16,
  FeatureAshrPkInsts = 17,
  FeatureAssemblerPermissiveWavesize = 18,
  FeatureAsynccnt = 19,
  FeatureAtomicBufferGlobalPkAddF16Insts = 20,
  FeatureAtomicBufferGlobalPkAddF16NoRtnInsts = 21,
  FeatureAtomicBufferPkAddBF16Inst = 22,
  FeatureAtomicCSubNoRtnInsts = 23,
  FeatureAtomicDsPkAdd16Insts = 24,
  FeatureAtomicFMinFMaxF32FlatInsts = 25,
  FeatureAtomicFMinFMaxF32GlobalInsts = 26,
  FeatureAtomicFMinFMaxF64FlatInsts = 27,
  FeatureAtomicFMinFMaxF64GlobalInsts = 28,
  FeatureAtomicFaddNoRtnInsts = 29,
  FeatureAtomicFaddRtnInsts = 30,
  FeatureAtomicFlatPkAdd16Insts = 31,
  FeatureAtomicGlobalPkAddBF16Inst = 32,
  FeatureAutoWaitcntBeforeBarrier = 33,
  FeatureBF8ConversionScaleInsts = 34,
  FeatureBF16ConversionInsts = 35,
  FeatureBF16PackedInsts = 36,
  FeatureBF16TransInsts = 37,
  FeatureBVHDualAndBVH8Insts = 38,
  FeatureBackOffBarrier = 39,
  FeatureBitOp3Insts = 40,
  FeatureCIInsts = 41,
  FeatureClusters = 42,
  FeatureCuMode = 43,
  FeatureCubeInsts = 44,
  FeatureCvtFP8VOP1Bug = 45,
  FeatureCvtNormInsts = 46,
  FeatureCvtPkF16F32Inst = 47,
  FeatureCvtPkNormVOP2Insts = 48,
  FeatureCvtPkNormVOP3Insts = 49,
  FeatureD16Writes32BitVgpr = 50,
  FeatureDLInsts = 51,
  FeatureDPALU_DPP = 52,
  FeatureDPP = 53,
  FeatureDPP8 = 54,
  FeatureDPPBroadcasts = 55,
  FeatureDPPSrc1SGPR = 56,
  FeatureDPPWavefrontShifts = 57,
  FeatureDX10ClampAndIEEEMode = 58,
  FeatureDefaultComponentBroadcast = 59,
  FeatureDefaultComponentZero = 60,
  FeatureDot1Insts = 61,
  FeatureDot2Insts = 62,
  FeatureDot3Insts = 63,
  FeatureDot4Insts = 64,
  FeatureDot5Insts = 65,
  FeatureDot6Insts = 66,
  FeatureDot7Insts = 67,
  FeatureDot8Insts = 68,
  FeatureDot9Insts = 69,
  FeatureDot10Insts = 70,
  FeatureDot11Insts = 71,
  FeatureDot12Insts = 72,
  FeatureDot13Insts = 73,
  FeatureDsSrc2Insts = 74,
  FeatureDumpCodeLower = 75,
  FeatureEmulatedSystemScopeAtomics = 76,
  FeatureEnableDS128 = 77,
  FeatureEnableFlatScratch = 78,
  FeatureEnableLoadStoreOpt = 79,
  FeatureEnablePRTStrictNull = 80,
  FeatureEnableSIScheduler = 81,
  FeatureEnableUnsafeDSOffsetFolding = 82,
  FeatureExtendedImageInsts = 83,
  FeatureF16BF16ToFP6BF6ConversionScaleInsts = 84,
  FeatureF32ToF16BF16ConversionSRInsts = 85,
  FeatureFMA = 86,
  FeatureFP4ConversionScaleInsts = 87,
  FeatureFP6BF6ConversionScaleInsts = 88,
  FeatureFP8ConversionInsts = 89,
  FeatureFP8ConversionScaleInsts = 90,
  FeatureFP8E5M3Insts = 91,
  FeatureFP8Insts = 92,
  FeatureFP64 = 93,
  FeatureFastDenormalF32 = 94,
  FeatureFastFMAF32 = 95,
  FeatureFlatAddressSpace = 96,
  FeatureFlatAtomicFaddF32Inst = 97,
  FeatureFlatBufferGlobalAtomicFaddF64Inst = 98,
  FeatureFlatGVSMode = 99,
  FeatureFlatGlobalInsts = 100,
  FeatureFlatInstOffsets = 101,
  FeatureFlatOffsetBits12 = 102,
  FeatureFlatOffsetBits24 = 103,
  FeatureFlatScratchInsts = 104,
  FeatureFlatSegmentOffsetBug = 105,
  FeatureFlatSignedOffset = 106,
  FeatureFmaMixBF16Insts = 107,
  FeatureFmaMixInsts = 108,
  FeatureFmacF64Inst = 109,
  FeatureFormattedMUBUFInsts = 110,
  FeatureFullRate64Ops = 111,
  FeatureG16 = 112,
  FeatureGCN3Encoding = 113,
  FeatureGDS = 114,
  FeatureGFX7GFX8GFX9Insts = 115,
  FeatureGFX8Insts = 116,
  FeatureGFX9 = 117,
  FeatureGFX9Insts = 118,
  FeatureGFX10 = 119,
  FeatureGFX10Insts = 120,
  FeatureGFX10_3Insts = 121,
  FeatureGFX10_AEncoding = 122,
  FeatureGFX10_BEncoding = 123,
  FeatureGFX11 = 124,
  FeatureGFX11Insts = 125,
  FeatureGFX11_7Insts = 126,
  FeatureGFX12 = 127,
  FeatureGFX12Insts = 128,
  FeatureGFX13 = 129,
  FeatureGFX13Insts = 130,
  FeatureGFX90AInsts = 131,
  FeatureGFX125xLowestRateWMMA = 132,
  FeatureGFX940Insts = 133,
  FeatureGFX950Insts = 134,
  FeatureGFX1250Insts = 135,
  FeatureGFX1251GEMMInsts = 136,
  FeatureGWS = 137,
  FeatureGetWaveIdInst = 138,
  FeatureGloballyAddressableScratch = 139,
  FeatureHalfRate64Ops = 140,
  FeatureIEEEMinimumMaximumInsts = 141,
  FeatureImageGather4D16Bug = 142,
  FeatureImageInsts = 143,
  FeatureImageStoreD16Bug = 144,
  FeatureInstCacheLineSize64 = 145,
  FeatureInstCacheLineSize128 = 146,
  FeatureInstFwdPrefetchBug = 147,
  FeatureIntClamp = 148,
  FeatureInv2PiInlineImm = 149,
  FeatureKernargPreload = 150,
  FeatureLDSBankCount16 = 151,
  FeatureLDSBankCount32 = 152,
  FeatureLDSMisalignedBug = 153,
  FeatureLdsBarrierArriveAtomic = 154,
  FeatureLdsBranchVmemWARHazard = 155,
  FeatureLerpInst = 156,
  FeatureLshlAddU64Inst = 157,
  FeatureMADIntraFwdBug = 158,
  FeatureMAIInsts = 159,
  FeatureMFMAInlineLiteralBug = 160,
  FeatureMIMG_R128 = 161,
  FeatureMSAALoadDstSelBug = 162,
  FeatureMTBUFInsts = 163,
  FeatureMadMacF32Insts = 164,
  FeatureMadMixInsts = 165,
  FeatureMadNC64_32Insts = 166,
  FeatureMadU32Inst = 167,
  FeatureMaxHardClauseLength32 = 168,
  FeatureMaxHardClauseLength63 = 169,
  FeatureMaxPrivateElementSize4 = 170,
  FeatureMaxPrivateElementSize8 = 171,
  FeatureMaxPrivateElementSize16 = 172,
  FeatureMcastLoadInsts = 173,
  FeatureMemoryAtomicFAddF32DenormalSupport = 174,
  FeatureMin3Max3PKF16 = 175,
  FeatureMinMaxI64Insts = 176,
  FeatureMinimum3Maximum3F16 = 177,
  FeatureMinimum3Maximum3F32 = 178,
  FeatureMinimum3Maximum3PKF16 = 179,
  FeatureMovrel = 180,
  FeatureMqsadInsts = 181,
  FeatureMqsadPkInsts = 182,
  FeatureMsadInsts = 183,
  FeatureNSAClauseBug = 184,
  FeatureNSAEncoding = 185,
  FeatureNSAtoVMEMBug = 186,
  FeatureNegativeScratchOffsetBug = 187,
  FeatureNegativeUnalignedScratchOffsetBug = 188,
  FeatureNoDataDepHazard = 189,
  FeatureNoF16PseudoScalarTransInlineConstants = 190,
  FeatureNoSdstCMPX = 191,
  FeatureOffset3fBug = 192,
  FeaturePackedFP32Ops = 193,
  FeaturePackedFP64Ops = 194,
  FeaturePackedTID = 195,
  FeaturePackedU64Ops = 196,
  FeaturePartialNSAEncoding = 197,
  FeaturePermlane16Insts = 198,
  FeaturePermlane16Swap = 199,
  FeaturePermlane32Swap = 200,
  FeaturePkAddMinMaxInsts = 201,
  FeaturePkFmacF16Inst = 202,
  FeaturePointSampleAccel = 203,
  FeaturePreciseMemory = 204,
  FeaturePrivEnabledTrap2NopBug = 205,
  FeaturePrngInst = 206,
  FeaturePseudoScalarTrans = 207,
  FeatureQsadInsts = 208,
  FeatureR128A16 = 209,
  FeatureRealTrue16Insts = 210,
  FeatureRequiredExportPriority = 211,
  FeatureRequiresAlignedVGPRs = 212,
  FeatureRequiresCOV6 = 213,
  FeatureRequiresInitialUnclausedVmem = 214,
  FeatureRestrictedSOffset = 215,
  FeatureSALUFloatInsts = 216,
  FeatureSALUMinimumMaximumInsts = 217,
  FeatureSBarrierLeaveImm = 218,
  FeatureSDWA = 219,
  FeatureSDWAMac = 220,
  FeatureSDWAOmod = 221,
  FeatureSDWAOutModsVOPC = 222,
  FeatureSDWAScalar = 223,
  FeatureSDWASdst = 224,
  FeatureSGPRInitBug = 225,
  FeatureSMEMtoVectorWriteHazard = 226,
  FeatureSMemRealTime = 227,
  FeatureSMemTimeInst = 228,
  FeatureSRAMECC = 229,
  FeatureSWMMACGfx1200Insts = 230,
  FeatureSWMMACGfx1250Insts = 231,
  FeatureSWakeupBarrier = 232,
  FeatureSWakeupImm = 233,
  FeatureSadInsts = 234,
  FeatureSafeCUPrefetch = 235,
  FeatureSafeSmemPrefetch = 236,
  FeatureScalarAtomics = 237,
  FeatureScalarDwordx3Loads = 238,
  FeatureScalarFlatScratchInsts = 239,
  FeatureScalarStores = 240,
  FeatureSeaIslands = 241,
  FeatureSetPrioIncWgInst = 242,
  FeatureSetregVGPRMSBFixup = 243,
  FeatureShaderCyclesHiLoRegisters = 244,
  FeatureShaderCyclesRegister = 245,
  FeatureSmemPrefetchInsts = 246,
  FeatureSouthernIslands = 247,
  FeatureSupportsSRAMECC = 248,
  FeatureSupportsXNACK = 249,
  FeatureTanhInsts = 250,
  FeatureTensorCvtLutInsts = 251,
  FeatureTgSplitSupport = 252,
  FeatureTransCoexecutionHazard = 253,
  FeatureTransposeLoadF4F6Insts = 254,
  FeatureTrapHandler = 255,
  FeatureTrigReducedRange = 256,
  FeatureTrue16BitInsts = 257,
  FeatureUnalignedAccessMode = 258,
  FeatureUnalignedBufferAccess = 259,
  FeatureUnalignedDSAccess = 260,
  FeatureUnalignedScratchAccess = 261,
  FeatureUnpackedD16VMem = 262,
  FeatureUseAddPC64Inst = 263,
  FeatureUseBlockVGPROpsForCSR = 264,
  FeatureUseFlatForGlobal = 265,
  FeatureUserSGPRInit16Bug = 266,
  FeatureVALUTransUseHazard = 267,
  FeatureVGPRIndexMode = 268,
  FeatureVMEMtoScalarWriteHazard = 269,
  FeatureVMemToLDSLoad = 270,
  FeatureVMovB64Inst = 271,
  FeatureVMulU64Inst = 272,
  FeatureVOP3Literal = 273,
  FeatureVOP3PInsts = 274,
  FeatureVOP3PX2IncrementsVaVdstTwice = 275,
  FeatureVOPDInsts = 276,
  FeatureVcmpxExecWARHazard = 277,
  FeatureVcmpxPermlaneHazard = 278,
  FeatureVmemPrefInsts = 279,
  FeatureVmemWriteVgprInOrder = 280,
  FeatureVolcanicIslands = 281,
  FeatureVscnt = 282,
  FeatureWMMA128bInsts = 283,
  FeatureWMMA256bInsts = 284,
  FeatureWMMACoexecutionHazards = 285,
  FeatureWaitXcnt = 286,
  FeatureWaitsBeforeSystemScopeStores = 287,
  FeatureWavefrontSize16 = 288,
  FeatureWavefrontSize32 = 289,
  FeatureWavefrontSize64 = 290,
  FeatureXF32Insts = 291,
  FeatureXNACK = 292,
  FeatureXNACKOnOffModes = 293,
  NumSubtargetFeatures = 294
};

} // namespace AMDGPU

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(DumpCode, false, dumpCode)
GET_SUBTARGETINFO_MACRO(EnableCuMode, false, enableCuMode)
GET_SUBTARGETINFO_MACRO(EnableDS128, false, enableDS128)
GET_SUBTARGETINFO_MACRO(EnableFlatScratch, false, enableFlatScratch)
GET_SUBTARGETINFO_MACRO(EnableLoadStoreOpt, false, enableLoadStoreOpt)
GET_SUBTARGETINFO_MACRO(EnablePRTStrictNull, false, enablePRTStrictNull)
GET_SUBTARGETINFO_MACRO(EnablePreciseMemory, false, enablePreciseMemory)
GET_SUBTARGETINFO_MACRO(EnableRealTrue16Insts, false, enableRealTrue16Insts)
GET_SUBTARGETINFO_MACRO(EnableSIScheduler, false, enableSIScheduler)
GET_SUBTARGETINFO_MACRO(EnableSRAMECC, false, enableSRAMECC)
GET_SUBTARGETINFO_MACRO(EnableUnsafeDSOffsetFolding, false, enableUnsafeDSOffsetFolding)
GET_SUBTARGETINFO_MACRO(EnableXNACK, false, enableXNACK)
GET_SUBTARGETINFO_MACRO(Has1024AddressableVGPRs, false, has1024AddressableVGPRs)
GET_SUBTARGETINFO_MACRO(Has1536VGPRs, false, has1536VGPRs)
GET_SUBTARGETINFO_MACRO(Has16BitInsts, false, has16BitInsts)
GET_SUBTARGETINFO_MACRO(Has45BitNumRecordsBufferResource, false, has45BitNumRecordsBufferResource)
GET_SUBTARGETINFO_MACRO(Has64BitLiterals, false, has64BitLiterals)
GET_SUBTARGETINFO_MACRO(HasA16, false, hasA16)
GET_SUBTARGETINFO_MACRO(HasAddMinMaxInsts, false, hasAddMinMaxInsts)
GET_SUBTARGETINFO_MACRO(HasAddNoCarryInsts, false, hasAddNoCarryInsts)
GET_SUBTARGETINFO_MACRO(HasAddSubU64Insts, false, hasAddSubU64Insts)
GET_SUBTARGETINFO_MACRO(HasAgentScopeFineGrainedRemoteMemoryAtomics, false, hasAgentScopeFineGrainedRemoteMemoryAtomics)
GET_SUBTARGETINFO_MACRO(HasApertureRegs, false, hasApertureRegs)
GET_SUBTARGETINFO_MACRO(HasArchitectedFlatScratch, false, hasArchitectedFlatScratch)
GET_SUBTARGETINFO_MACRO(HasArchitectedSGPRs, false, hasArchitectedSGPRs)
GET_SUBTARGETINFO_MACRO(HasAshrPkInsts, false, hasAshrPkInsts)
GET_SUBTARGETINFO_MACRO(HasAssemblerPermissiveWavesize, false, hasAssemblerPermissiveWavesize)
GET_SUBTARGETINFO_MACRO(HasAsynccnt, false, hasAsynccnt)
GET_SUBTARGETINFO_MACRO(HasAtomicBufferGlobalPkAddF16Insts, false, hasAtomicBufferGlobalPkAddF16Insts)
GET_SUBTARGETINFO_MACRO(HasAtomicBufferGlobalPkAddF16NoRtnInsts, false, hasAtomicBufferGlobalPkAddF16NoRtnInsts)
GET_SUBTARGETINFO_MACRO(HasAtomicBufferPkAddBF16Inst, false, hasAtomicBufferPkAddBF16Inst)
GET_SUBTARGETINFO_MACRO(HasAtomicCSubNoRtnInsts, false, hasAtomicCSubNoRtnInsts)
GET_SUBTARGETINFO_MACRO(HasAtomicDsPkAdd16Insts, false, hasAtomicDsPkAdd16Insts)
GET_SUBTARGETINFO_MACRO(HasAtomicFMinFMaxF32FlatInsts, false, hasAtomicFMinFMaxF32FlatInsts)
GET_SUBTARGETINFO_MACRO(HasAtomicFMinFMaxF32GlobalInsts, false, hasAtomicFMinFMaxF32GlobalInsts)
GET_SUBTARGETINFO_MACRO(HasAtomicFMinFMaxF64FlatInsts, false, hasAtomicFMinFMaxF64FlatInsts)
GET_SUBTARGETINFO_MACRO(HasAtomicFMinFMaxF64GlobalInsts, false, hasAtomicFMinFMaxF64GlobalInsts)
GET_SUBTARGETINFO_MACRO(HasAtomicFaddNoRtnInsts, false, hasAtomicFaddNoRtnInsts)
GET_SUBTARGETINFO_MACRO(HasAtomicFaddRtnInsts, false, hasAtomicFaddRtnInsts)
GET_SUBTARGETINFO_MACRO(HasAtomicFlatPkAdd16Insts, false, hasAtomicFlatPkAdd16Insts)
GET_SUBTARGETINFO_MACRO(HasAtomicGlobalPkAddBF16Inst, false, hasAtomicGlobalPkAddBF16Inst)
GET_SUBTARGETINFO_MACRO(HasAutoWaitcntBeforeBarrier, false, hasAutoWaitcntBeforeBarrier)
GET_SUBTARGETINFO_MACRO(HasBF16ConversionInsts, false, hasBF16ConversionInsts)
GET_SUBTARGETINFO_MACRO(HasBF16PackedInsts, false, hasBF16PackedInsts)
GET_SUBTARGETINFO_MACRO(HasBF16TransInsts, false, hasBF16TransInsts)
GET_SUBTARGETINFO_MACRO(HasBF8ConversionScaleInsts, false, hasBF8ConversionScaleInsts)
GET_SUBTARGETINFO_MACRO(HasBVHDualAndBVH8Insts, false, hasBVHDualAndBVH8Insts)
GET_SUBTARGETINFO_MACRO(HasBackOffBarrier, false, hasBackOffBarrier)
GET_SUBTARGETINFO_MACRO(HasBitOp3Insts, false, hasBitOp3Insts)
GET_SUBTARGETINFO_MACRO(HasCIInsts, false, hasCIInsts)
GET_SUBTARGETINFO_MACRO(HasClusters, false, hasClusters)
GET_SUBTARGETINFO_MACRO(HasCubeInsts, false, hasCubeInsts)
GET_SUBTARGETINFO_MACRO(HasCvtFP8VOP1Bug, false, hasCvtFP8VOP1Bug)
GET_SUBTARGETINFO_MACRO(HasCvtNormInsts, false, hasCvtNormInsts)
GET_SUBTARGETINFO_MACRO(HasCvtPkF16F32Inst, false, hasCvtPkF16F32Inst)
GET_SUBTARGETINFO_MACRO(HasCvtPkNormVOP2Insts, false, hasCvtPkNormVOP2Insts)
GET_SUBTARGETINFO_MACRO(HasCvtPkNormVOP3Insts, false, hasCvtPkNormVOP3Insts)
GET_SUBTARGETINFO_MACRO(HasD16Writes32BitVgpr, false, hasD16Writes32BitVgpr)
GET_SUBTARGETINFO_MACRO(HasDLInsts, false, hasDLInsts)
GET_SUBTARGETINFO_MACRO(HasDPALU_DPP, false, hasDPALU_DPP)
GET_SUBTARGETINFO_MACRO(HasDPP, false, hasDPP)
GET_SUBTARGETINFO_MACRO(HasDPP8, false, hasDPP8)
GET_SUBTARGETINFO_MACRO(HasDPPBroadcasts, false, hasDPPBroadcasts)
GET_SUBTARGETINFO_MACRO(HasDPPSrc1SGPR, false, hasDPPSrc1SGPR)
GET_SUBTARGETINFO_MACRO(HasDPPWavefrontShifts, false, hasDPPWavefrontShifts)
GET_SUBTARGETINFO_MACRO(HasDX10ClampAndIEEEMode, false, hasDX10ClampAndIEEEMode)
GET_SUBTARGETINFO_MACRO(HasDefaultComponentBroadcast, false, hasDefaultComponentBroadcast)
GET_SUBTARGETINFO_MACRO(HasDefaultComponentZero, false, hasDefaultComponentZero)
GET_SUBTARGETINFO_MACRO(HasDot10Insts, false, hasDot10Insts)
GET_SUBTARGETINFO_MACRO(HasDot11Insts, false, hasDot11Insts)
GET_SUBTARGETINFO_MACRO(HasDot12Insts, false, hasDot12Insts)
GET_SUBTARGETINFO_MACRO(HasDot13Insts, false, hasDot13Insts)
GET_SUBTARGETINFO_MACRO(HasDot1Insts, false, hasDot1Insts)
GET_SUBTARGETINFO_MACRO(HasDot2Insts, false, hasDot2Insts)
GET_SUBTARGETINFO_MACRO(HasDot3Insts, false, hasDot3Insts)
GET_SUBTARGETINFO_MACRO(HasDot4Insts, false, hasDot4Insts)
GET_SUBTARGETINFO_MACRO(HasDot5Insts, false, hasDot5Insts)
GET_SUBTARGETINFO_MACRO(HasDot6Insts, false, hasDot6Insts)
GET_SUBTARGETINFO_MACRO(HasDot7Insts, false, hasDot7Insts)
GET_SUBTARGETINFO_MACRO(HasDot8Insts, false, hasDot8Insts)
GET_SUBTARGETINFO_MACRO(HasDot9Insts, false, hasDot9Insts)
GET_SUBTARGETINFO_MACRO(HasDsSrc2Insts, false, hasDsSrc2Insts)
GET_SUBTARGETINFO_MACRO(HasEmulatedSystemScopeAtomics, false, hasEmulatedSystemScopeAtomics)
GET_SUBTARGETINFO_MACRO(HasExtendedImageInsts, false, hasExtendedImageInsts)
GET_SUBTARGETINFO_MACRO(HasF16BF16ToFP6BF6ConversionScaleInsts, false, hasF16BF16ToFP6BF6ConversionScaleInsts)
GET_SUBTARGETINFO_MACRO(HasF32ToF16BF16ConversionSRInsts, false, hasF32ToF16BF16ConversionSRInsts)
GET_SUBTARGETINFO_MACRO(HasFMA, false, hasFMA)
GET_SUBTARGETINFO_MACRO(HasFP4ConversionScaleInsts, false, hasFP4ConversionScaleInsts)
GET_SUBTARGETINFO_MACRO(HasFP64, false, hasFP64)
GET_SUBTARGETINFO_MACRO(HasFP6BF6ConversionScaleInsts, false, hasFP6BF6ConversionScaleInsts)
GET_SUBTARGETINFO_MACRO(HasFP8ConversionInsts, false, hasFP8ConversionInsts)
GET_SUBTARGETINFO_MACRO(HasFP8ConversionScaleInsts, false, hasFP8ConversionScaleInsts)
GET_SUBTARGETINFO_MACRO(HasFP8E5M3Insts, false, hasFP8E5M3Insts)
GET_SUBTARGETINFO_MACRO(HasFP8Insts, false, hasFP8Insts)
GET_SUBTARGETINFO_MACRO(HasFastDenormalF32, false, hasFastDenormalF32)
GET_SUBTARGETINFO_MACRO(HasFastFMAF32, false, hasFastFMAF32)
GET_SUBTARGETINFO_MACRO(HasFlatAddressSpace, false, hasFlatAddressSpace)
GET_SUBTARGETINFO_MACRO(HasFlatAtomicFaddF32Inst, false, hasFlatAtomicFaddF32Inst)
GET_SUBTARGETINFO_MACRO(HasFlatBufferGlobalAtomicFaddF64Inst, false, hasFlatBufferGlobalAtomicFaddF64Inst)
GET_SUBTARGETINFO_MACRO(HasFlatGVSMode, false, hasFlatGVSMode)
GET_SUBTARGETINFO_MACRO(HasFlatGlobalInsts, false, hasFlatGlobalInsts)
GET_SUBTARGETINFO_MACRO(HasFlatInstOffsets, false, hasFlatInstOffsets)
GET_SUBTARGETINFO_MACRO(HasFlatScratchInsts, false, hasFlatScratchInsts)
GET_SUBTARGETINFO_MACRO(HasFlatSegmentOffsetBug, false, hasFlatSegmentOffsetBug)
GET_SUBTARGETINFO_MACRO(HasFlatSignedOffset, false, hasFlatSignedOffset)
GET_SUBTARGETINFO_MACRO(HasFmaMixBF16Insts, false, hasFmaMixBF16Insts)
GET_SUBTARGETINFO_MACRO(HasFmaMixInsts, false, hasFmaMixInsts)
GET_SUBTARGETINFO_MACRO(HasFmacF64Inst, false, hasFmacF64Inst)
GET_SUBTARGETINFO_MACRO(HasFormattedMUBUFInsts, false, hasFormattedMUBUFInsts)
GET_SUBTARGETINFO_MACRO(HasFullRate64Ops, false, hasFullRate64Ops)
GET_SUBTARGETINFO_MACRO(HasG16, false, hasG16)
GET_SUBTARGETINFO_MACRO(HasGCN3Encoding, false, hasGCN3Encoding)
GET_SUBTARGETINFO_MACRO(HasGDS, false, hasGDS)
GET_SUBTARGETINFO_MACRO(HasGFX10Insts, false, hasGFX10Insts)
GET_SUBTARGETINFO_MACRO(HasGFX10_3Insts, false, hasGFX10_3Insts)
GET_SUBTARGETINFO_MACRO(HasGFX10_AEncoding, false, hasGFX10_AEncoding)
GET_SUBTARGETINFO_MACRO(HasGFX10_BEncoding, false, hasGFX10_BEncoding)
GET_SUBTARGETINFO_MACRO(HasGFX11Insts, false, hasGFX11Insts)
GET_SUBTARGETINFO_MACRO(HasGFX11_7Insts, false, hasGFX11_7Insts)
GET_SUBTARGETINFO_MACRO(HasGFX1250Insts, false, hasGFX1250Insts)
GET_SUBTARGETINFO_MACRO(HasGFX1251GEMMInsts, false, hasGFX1251GEMMInsts)
GET_SUBTARGETINFO_MACRO(HasGFX125xLowestRateWMMA, false, hasGFX125xLowestRateWMMA)
GET_SUBTARGETINFO_MACRO(HasGFX12Insts, false, hasGFX12Insts)
GET_SUBTARGETINFO_MACRO(HasGFX13Insts, false, hasGFX13Insts)
GET_SUBTARGETINFO_MACRO(HasGFX7GFX8GFX9Insts, false, hasGFX7GFX8GFX9Insts)
GET_SUBTARGETINFO_MACRO(HasGFX8Insts, false, hasGFX8Insts)
GET_SUBTARGETINFO_MACRO(HasGFX90AInsts, false, hasGFX90AInsts)
GET_SUBTARGETINFO_MACRO(HasGFX940Insts, false, hasGFX940Insts)
GET_SUBTARGETINFO_MACRO(HasGFX950Insts, false, hasGFX950Insts)
GET_SUBTARGETINFO_MACRO(HasGFX9Insts, false, hasGFX9Insts)
GET_SUBTARGETINFO_MACRO(HasGWS, false, hasGWS)
GET_SUBTARGETINFO_MACRO(HasGetWaveIdInst, false, hasGetWaveIdInst)
GET_SUBTARGETINFO_MACRO(HasGloballyAddressableScratch, false, hasGloballyAddressableScratch)
GET_SUBTARGETINFO_MACRO(HasHalfRate64Ops, false, hasHalfRate64Ops)
GET_SUBTARGETINFO_MACRO(HasIEEEMinimumMaximumInsts, false, hasIEEEMinimumMaximumInsts)
GET_SUBTARGETINFO_MACRO(HasImageGather4D16Bug, false, hasImageGather4D16Bug)
GET_SUBTARGETINFO_MACRO(HasImageInsts, false, hasImageInsts)
GET_SUBTARGETINFO_MACRO(HasImageStoreD16Bug, false, hasImageStoreD16Bug)
GET_SUBTARGETINFO_MACRO(HasInstFwdPrefetchBug, false, hasInstFwdPrefetchBug)
GET_SUBTARGETINFO_MACRO(HasIntClamp, false, hasIntClamp)
GET_SUBTARGETINFO_MACRO(HasInv2PiInlineImm, false, hasInv2PiInlineImm)
GET_SUBTARGETINFO_MACRO(HasKernargPreload, false, hasKernargPreload)
GET_SUBTARGETINFO_MACRO(HasLDSMisalignedBug, false, hasLDSMisalignedBug)
GET_SUBTARGETINFO_MACRO(HasLdsBarrierArriveAtomic, false, hasLdsBarrierArriveAtomic)
GET_SUBTARGETINFO_MACRO(HasLdsBranchVmemWARHazard, false, hasLdsBranchVmemWARHazard)
GET_SUBTARGETINFO_MACRO(HasLerpInst, false, hasLerpInst)
GET_SUBTARGETINFO_MACRO(HasLshlAddU64Inst, false, hasLshlAddU64Inst)
GET_SUBTARGETINFO_MACRO(HasMADIntraFwdBug, false, hasMADIntraFwdBug)
GET_SUBTARGETINFO_MACRO(HasMAIInsts, false, hasMAIInsts)
GET_SUBTARGETINFO_MACRO(HasMFMAInlineLiteralBug, false, hasMFMAInlineLiteralBug)
GET_SUBTARGETINFO_MACRO(HasMIMG_R128, false, hasMIMG_R128)
GET_SUBTARGETINFO_MACRO(HasMSAALoadDstSelBug, false, hasMSAALoadDstSelBug)
GET_SUBTARGETINFO_MACRO(HasMTBUFInsts, false, hasMTBUFInsts)
GET_SUBTARGETINFO_MACRO(HasMadMacF32Insts, false, hasMadMacF32Insts)
GET_SUBTARGETINFO_MACRO(HasMadMixInsts, false, hasMadMixInsts)
GET_SUBTARGETINFO_MACRO(HasMadNC64_32Insts, false, hasMadNC64_32Insts)
GET_SUBTARGETINFO_MACRO(HasMadU32Inst, false, hasMadU32Inst)
GET_SUBTARGETINFO_MACRO(HasMcastLoadInsts, false, hasMcastLoadInsts)
GET_SUBTARGETINFO_MACRO(HasMemoryAtomicFaddF32DenormalSupport, false, hasMemoryAtomicFaddF32DenormalSupport)
GET_SUBTARGETINFO_MACRO(HasMin3Max3PKF16, false, hasMin3Max3PKF16)
GET_SUBTARGETINFO_MACRO(HasMinMaxI64Insts, false, hasMinMaxI64Insts)
GET_SUBTARGETINFO_MACRO(HasMinimum3Maximum3F16, false, hasMinimum3Maximum3F16)
GET_SUBTARGETINFO_MACRO(HasMinimum3Maximum3F32, false, hasMinimum3Maximum3F32)
GET_SUBTARGETINFO_MACRO(HasMinimum3Maximum3PKF16, false, hasMinimum3Maximum3PKF16)
GET_SUBTARGETINFO_MACRO(HasMovrel, false, hasMovrel)
GET_SUBTARGETINFO_MACRO(HasMqsadInsts, false, hasMqsadInsts)
GET_SUBTARGETINFO_MACRO(HasMqsadPkInsts, false, hasMqsadPkInsts)
GET_SUBTARGETINFO_MACRO(HasMsadInsts, false, hasMsadInsts)
GET_SUBTARGETINFO_MACRO(HasNSAClauseBug, false, hasNSAClauseBug)
GET_SUBTARGETINFO_MACRO(HasNSAEncoding, false, hasNSAEncoding)
GET_SUBTARGETINFO_MACRO(HasNSAtoVMEMBug, false, hasNSAtoVMEMBug)
GET_SUBTARGETINFO_MACRO(HasNegativeScratchOffsetBug, false, hasNegativeScratchOffsetBug)
GET_SUBTARGETINFO_MACRO(HasNegativeUnalignedScratchOffsetBug, false, hasNegativeUnalignedScratchOffsetBug)
GET_SUBTARGETINFO_MACRO(HasNoDataDepHazard, false, hasNoDataDepHazard)
GET_SUBTARGETINFO_MACRO(HasNoF16PseudoScalarTransInlineConstants, false, hasNoF16PseudoScalarTransInlineConstants)
GET_SUBTARGETINFO_MACRO(HasNoSdstCMPX, false, hasNoSdstCMPX)
GET_SUBTARGETINFO_MACRO(HasOffset3fBug, false, hasOffset3fBug)
GET_SUBTARGETINFO_MACRO(HasPackedFP32Ops, false, hasPackedFP32Ops)
GET_SUBTARGETINFO_MACRO(HasPackedFP64Ops, false, hasPackedFP64Ops)
GET_SUBTARGETINFO_MACRO(HasPackedTID, false, hasPackedTID)
GET_SUBTARGETINFO_MACRO(HasPackedU64Ops, false, hasPackedU64Ops)
GET_SUBTARGETINFO_MACRO(HasPartialNSAEncoding, false, hasPartialNSAEncoding)
GET_SUBTARGETINFO_MACRO(HasPermlane16Insts, false, hasPermlane16Insts)
GET_SUBTARGETINFO_MACRO(HasPermlane16Swap, false, hasPermlane16Swap)
GET_SUBTARGETINFO_MACRO(HasPermlane32Swap, false, hasPermlane32Swap)
GET_SUBTARGETINFO_MACRO(HasPkAddMinMaxInsts, false, hasPkAddMinMaxInsts)
GET_SUBTARGETINFO_MACRO(HasPkFmacF16Inst, false, hasPkFmacF16Inst)
GET_SUBTARGETINFO_MACRO(HasPointSampleAccel, false, hasPointSampleAccel)
GET_SUBTARGETINFO_MACRO(HasPrivEnabledTrap2NopBug, false, hasPrivEnabledTrap2NopBug)
GET_SUBTARGETINFO_MACRO(HasPrngInst, false, hasPrngInst)
GET_SUBTARGETINFO_MACRO(HasPseudoScalarTrans, false, hasPseudoScalarTrans)
GET_SUBTARGETINFO_MACRO(HasQsadInsts, false, hasQsadInsts)
GET_SUBTARGETINFO_MACRO(HasR128A16, false, hasR128A16)
GET_SUBTARGETINFO_MACRO(HasRequiredExportPriority, false, hasRequiredExportPriority)
GET_SUBTARGETINFO_MACRO(HasRequiresInitialUnclausedVmem, false, hasRequiresInitialUnclausedVmem)
GET_SUBTARGETINFO_MACRO(HasRestrictedSOffset, false, hasRestrictedSOffset)
GET_SUBTARGETINFO_MACRO(HasSALUFloatInsts, false, hasSALUFloatInsts)
GET_SUBTARGETINFO_MACRO(HasSALUMinimumMaximumInsts, false, hasSALUMinimumMaximumInsts)
GET_SUBTARGETINFO_MACRO(HasSBarrierLeaveImm, false, hasSBarrierLeaveImm)
GET_SUBTARGETINFO_MACRO(HasSDWA, false, hasSDWA)
GET_SUBTARGETINFO_MACRO(HasSDWAMac, false, hasSDWAMac)
GET_SUBTARGETINFO_MACRO(HasSDWAOmod, false, hasSDWAOmod)
GET_SUBTARGETINFO_MACRO(HasSDWAOutModsVOPC, false, hasSDWAOutModsVOPC)
GET_SUBTARGETINFO_MACRO(HasSDWAScalar, false, hasSDWAScalar)
GET_SUBTARGETINFO_MACRO(HasSDWASdst, false, hasSDWASdst)
GET_SUBTARGETINFO_MACRO(HasSGPRInitBug, false, hasSGPRInitBug)
GET_SUBTARGETINFO_MACRO(HasSMEMtoVectorWriteHazard, false, hasSMEMtoVectorWriteHazard)
GET_SUBTARGETINFO_MACRO(HasSMemRealTime, false, hasSMemRealTime)
GET_SUBTARGETINFO_MACRO(HasSMemTimeInst, false, hasSMemTimeInst)
GET_SUBTARGETINFO_MACRO(HasSWMMACGfx1200Insts, false, hasSWMMACGfx1200Insts)
GET_SUBTARGETINFO_MACRO(HasSWMMACGfx1250Insts, false, hasSWMMACGfx1250Insts)
GET_SUBTARGETINFO_MACRO(HasSWakeupBarrier, false, hasSWakeupBarrier)
GET_SUBTARGETINFO_MACRO(HasSWakeupImm, false, hasSWakeupImm)
GET_SUBTARGETINFO_MACRO(HasSadInsts, false, hasSadInsts)
GET_SUBTARGETINFO_MACRO(HasSafeCUPrefetch, false, hasSafeCUPrefetch)
GET_SUBTARGETINFO_MACRO(HasSafeSmemPrefetch, false, hasSafeSmemPrefetch)
GET_SUBTARGETINFO_MACRO(HasScalarAtomics, false, hasScalarAtomics)
GET_SUBTARGETINFO_MACRO(HasScalarDwordx3Loads, false, hasScalarDwordx3Loads)
GET_SUBTARGETINFO_MACRO(HasScalarFlatScratchInsts, false, hasScalarFlatScratchInsts)
GET_SUBTARGETINFO_MACRO(HasScalarStores, false, hasScalarStores)
GET_SUBTARGETINFO_MACRO(HasSetPrioIncWgInst, false, hasSetPrioIncWgInst)
GET_SUBTARGETINFO_MACRO(HasSetregVGPRMSBFixup, false, hasSetregVGPRMSBFixup)
GET_SUBTARGETINFO_MACRO(HasShaderCyclesHiLoRegisters, false, hasShaderCyclesHiLoRegisters)
GET_SUBTARGETINFO_MACRO(HasShaderCyclesRegister, false, hasShaderCyclesRegister)
GET_SUBTARGETINFO_MACRO(HasSmemPrefetchInsts, false, hasSmemPrefetchInsts)
GET_SUBTARGETINFO_MACRO(HasTanhInsts, false, hasTanhInsts)
GET_SUBTARGETINFO_MACRO(HasTensorCvtLutInsts, false, hasTensorCvtLutInsts)
GET_SUBTARGETINFO_MACRO(HasTgSplitSupport, false, hasTgSplitSupport)
GET_SUBTARGETINFO_MACRO(HasTransCoexecutionHazard, false, hasTransCoexecutionHazard)
GET_SUBTARGETINFO_MACRO(HasTransposeLoadF4F6Insts, false, hasTransposeLoadF4F6Insts)
GET_SUBTARGETINFO_MACRO(HasTrapHandler, false, hasTrapHandler)
GET_SUBTARGETINFO_MACRO(HasTrigReducedRange, false, hasTrigReducedRange)
GET_SUBTARGETINFO_MACRO(HasTrue16BitInsts, false, hasTrue16BitInsts)
GET_SUBTARGETINFO_MACRO(HasUnalignedAccessMode, false, hasUnalignedAccessMode)
GET_SUBTARGETINFO_MACRO(HasUnalignedBufferAccess, false, hasUnalignedBufferAccess)
GET_SUBTARGETINFO_MACRO(HasUnalignedDSAccess, false, hasUnalignedDSAccess)
GET_SUBTARGETINFO_MACRO(HasUnalignedScratchAccess, false, hasUnalignedScratchAccess)
GET_SUBTARGETINFO_MACRO(HasUnpackedD16VMem, false, hasUnpackedD16VMem)
GET_SUBTARGETINFO_MACRO(HasUserSGPRInit16Bug, false, hasUserSGPRInit16Bug)
GET_SUBTARGETINFO_MACRO(HasVALUTransUseHazard, false, hasVALUTransUseHazard)
GET_SUBTARGETINFO_MACRO(HasVGPRIndexMode, false, hasVGPRIndexMode)
GET_SUBTARGETINFO_MACRO(HasVMEMtoScalarWriteHazard, false, hasVMEMtoScalarWriteHazard)
GET_SUBTARGETINFO_MACRO(HasVMemToLDSLoad, false, hasVMemToLDSLoad)
GET_SUBTARGETINFO_MACRO(HasVMovB64Inst, false, hasVMovB64Inst)
GET_SUBTARGETINFO_MACRO(HasVMulU64Inst, false, hasVMulU64Inst)
GET_SUBTARGETINFO_MACRO(HasVOP3Literal, false, hasVOP3Literal)
GET_SUBTARGETINFO_MACRO(HasVOP3PInsts, false, hasVOP3PInsts)
GET_SUBTARGETINFO_MACRO(HasVOP3PX2IncrementsVaVdstTwice, false, hasVOP3PX2IncrementsVaVdstTwice)
GET_SUBTARGETINFO_MACRO(HasVOPDInsts, false, hasVOPDInsts)
GET_SUBTARGETINFO_MACRO(HasVcmpxExecWARHazard, false, hasVcmpxExecWARHazard)
GET_SUBTARGETINFO_MACRO(HasVcmpxPermlaneHazard, false, hasVcmpxPermlaneHazard)
GET_SUBTARGETINFO_MACRO(HasVmemPrefInsts, false, hasVmemPrefInsts)
GET_SUBTARGETINFO_MACRO(HasVmemWriteVgprInOrder, false, hasVmemWriteVgprInOrder)
GET_SUBTARGETINFO_MACRO(HasVscnt, false, hasVscnt)
GET_SUBTARGETINFO_MACRO(HasWMMA128bInsts, false, hasWMMA128bInsts)
GET_SUBTARGETINFO_MACRO(HasWMMA256bInsts, false, hasWMMA256bInsts)
GET_SUBTARGETINFO_MACRO(HasWMMACoexecutionHazards, false, hasWMMACoexecutionHazards)
GET_SUBTARGETINFO_MACRO(HasWaitXcnt, false, hasWaitXcnt)
GET_SUBTARGETINFO_MACRO(HasXF32Insts, false, hasXF32Insts)
GET_SUBTARGETINFO_MACRO(HasXNACKOnOffModes, false, hasXNACKOnOffModes)
GET_SUBTARGETINFO_MACRO(RequiresAlignVGPR, false, requiresAlignVGPR)
GET_SUBTARGETINFO_MACRO(RequiresCOV6, false, requiresCOV6)
GET_SUBTARGETINFO_MACRO(RequiresWaitsBeforeSystemScopeStores, false, requiresWaitsBeforeSystemScopeStores)
GET_SUBTARGETINFO_MACRO(SupportsSRAMECC, false, supportsSRAMECC)
GET_SUBTARGETINFO_MACRO(SupportsXNACK, false, supportsXNACK)
GET_SUBTARGETINFO_MACRO(UseAddPC64Inst, false, useAddPC64Inst)
GET_SUBTARGETINFO_MACRO(UseBlockVGPROpsForCSR, false, useBlockVGPROpsForCSR)
GET_SUBTARGETINFO_MACRO(UseFlatForGlobal, false, useFlatForGlobal)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 294, 18809> AMDGPUFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 294 + 1, sizeof(SubtargetFeatureKV) * 294 + 24, AMDGPU::Feature1024AddressableVGPRs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 293 + 51, sizeof(SubtargetFeatureKV) * 293 + 71, AMDGPU::Feature1536VGPRs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 292 + 104, sizeof(SubtargetFeatureKV) * 292 + 117, AMDGPU::Feature16BitInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 291 + 142, sizeof(SubtargetFeatureKV) * 291 + 177, AMDGPU::Feature45BitNumRecordsBufferResource, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 290 + 230, sizeof(SubtargetFeatureKV) * 290 + 246, AMDGPU::Feature64BitLiterals, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 289 + 301, sizeof(SubtargetFeatureKV) * 289 + 305, AMDGPU::FeatureA16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 288 + 379, sizeof(SubtargetFeatureKV) * 288 + 397, AMDGPU::FeatureAddMinMaxInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 287 + 438, sizeof(SubtargetFeatureKV) * 287 + 457, AMDGPU::FeatureAddNoCarryInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 286 + 506, sizeof(SubtargetFeatureKV) * 286 + 524, AMDGPU::FeatureAddSubU64Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 285 + 565, sizeof(SubtargetFeatureKV) * 285 + 598, AMDGPU::FeatureAddressableLocalMemorySize163840, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 284 + 632, sizeof(SubtargetFeatureKV) * 284 + 598, AMDGPU::FeatureAddressableLocalMemorySize32768, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 283 + 664, sizeof(SubtargetFeatureKV) * 283 + 598, AMDGPU::FeatureAddressableLocalMemorySize327680, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 282 + 697, sizeof(SubtargetFeatureKV) * 282 + 598, AMDGPU::FeatureAddressableLocalMemorySize65536, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 281 + 729, sizeof(SubtargetFeatureKV) * 281 + 776, AMDGPU::FeatureAgentScopeFineGrainedRemoteMemoryAtomics, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 280 + 981, sizeof(SubtargetFeatureKV) * 280 + 995, AMDGPU::FeatureApertureRegs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 279 + 1039, sizeof(SubtargetFeatureKV) * 279 + 1064, AMDGPU::FeatureArchitectedFlatScratch, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 278 + 1137, sizeof(SubtargetFeatureKV) * 278 + 1155, AMDGPU::FeatureArchitectedSGPRs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 277 + 1184, sizeof(SubtargetFeatureKV) * 277 + 1198, AMDGPU::FeatureAshrPkInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 276 + 1237, sizeof(SubtargetFeatureKV) * 276 + 1267, AMDGPU::FeatureAssemblerPermissiveWavesize, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 275 + 1324, sizeof(SubtargetFeatureKV) * 275 + 1333, AMDGPU::FeatureAsynccnt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 274 + 1363, sizeof(SubtargetFeatureKV) * 274 + 1401, AMDGPU::FeatureAtomicBufferGlobalPkAddF16Insts, { { { 0x0ULL, 0x1000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 273 + 1503, sizeof(SubtargetFeatureKV) * 273 + 1548, AMDGPU::FeatureAtomicBufferGlobalPkAddF16NoRtnInsts, { { { 0x0ULL, 0x1000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 272 + 1652, sizeof(SubtargetFeatureKV) * 272 + 1683, AMDGPU::FeatureAtomicBufferPkAddBF16Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 271 + 1725, sizeof(SubtargetFeatureKV) * 271 + 1750, AMDGPU::FeatureAtomicCSubNoRtnInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 270 + 1842, sizeof(SubtargetFeatureKV) * 270 + 1868, AMDGPU::FeatureAtomicDsPkAdd16Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 269 + 1954, sizeof(SubtargetFeatureKV) * 269 + 1979, AMDGPU::FeatureAtomicFaddNoRtnInsts, { { { 0x0ULL, 0x1000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 268 + 2077, sizeof(SubtargetFeatureKV) * 268 + 2099, AMDGPU::FeatureAtomicFaddRtnInsts, { { { 0x0ULL, 0x1000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 267 + 2191, sizeof(SubtargetFeatureKV) * 267 + 2219, AMDGPU::FeatureAtomicFlatPkAdd16Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 266 + 2287, sizeof(SubtargetFeatureKV) * 266 + 2313, AMDGPU::FeatureAtomicFMinFMaxF32FlatInsts, { { { 0x0ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 265 + 2376, sizeof(SubtargetFeatureKV) * 265 + 2402, AMDGPU::FeatureAtomicFMinFMaxF64FlatInsts, { { { 0x0ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 264 + 2466, sizeof(SubtargetFeatureKV) * 264 + 2494, AMDGPU::FeatureAtomicFMinFMaxF32GlobalInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 263 + 2559, sizeof(SubtargetFeatureKV) * 263 + 2494, AMDGPU::FeatureAtomicFMinFMaxF64GlobalInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 262 + 2587, sizeof(SubtargetFeatureKV) * 262 + 2618, AMDGPU::FeatureAtomicGlobalPkAddBF16Inst, { { { 0x0ULL, 0x1000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 261 + 2660, sizeof(SubtargetFeatureKV) * 261 + 2688, AMDGPU::FeatureAutoWaitcntBeforeBarrier, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 260 + 2742, sizeof(SubtargetFeatureKV) * 260 + 2759, AMDGPU::FeatureBackOffBarrier, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 259 + 2822, sizeof(SubtargetFeatureKV) * 259 + 2837, AMDGPU::FeatureBF16ConversionInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 258 + 2870, sizeof(SubtargetFeatureKV) * 258 + 2884, AMDGPU::FeatureBF16PackedInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 257 + 2939, sizeof(SubtargetFeatureKV) * 257 + 2956, AMDGPU::FeatureBF16TransInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 256 + 2993, sizeof(SubtargetFeatureKV) * 256 + 3013, AMDGPU::FeatureBF8ConversionScaleInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 255 + 3051, sizeof(SubtargetFeatureKV) * 255 + 3064, AMDGPU::FeatureBitOp3Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 254 + 3107, sizeof(SubtargetFeatureKV) * 254 + 3122, AMDGPU::FeatureUseBlockVGPROpsForCSR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 253 + 3175, sizeof(SubtargetFeatureKV) * 253 + 3196, AMDGPU::FeatureBVHDualAndBVH8Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 252 + 3271, sizeof(SubtargetFeatureKV) * 252 + 3280, AMDGPU::FeatureCIInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 251 + 3312, sizeof(SubtargetFeatureKV) * 251 + 3321, AMDGPU::FeatureClusters, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 250 + 3356, sizeof(SubtargetFeatureKV) * 250 + 3367, AMDGPU::FeatureCubeInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 249 + 3392, sizeof(SubtargetFeatureKV) * 249 + 3399, AMDGPU::FeatureCuMode, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 248 + 3434, sizeof(SubtargetFeatureKV) * 248 + 3451, AMDGPU::FeatureCvtFP8VOP1Bug, { { { 0x0ULL, 0x2000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 247 + 3504, sizeof(SubtargetFeatureKV) * 247 + 3519, AMDGPU::FeatureCvtNormInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 246 + 3548, sizeof(SubtargetFeatureKV) * 246 + 3568, AMDGPU::FeatureCvtPkF16F32Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 245 + 3599, sizeof(SubtargetFeatureKV) * 245 + 3621, AMDGPU::FeatureCvtPkNormVOP2Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 244 + 3694, sizeof(SubtargetFeatureKV) * 244 + 3621, AMDGPU::FeatureCvtPkNormVOP3Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 243 + 3716, sizeof(SubtargetFeatureKV) * 243 + 3733, AMDGPU::FeatureD16Writes32BitVgpr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 242 + 3792, sizeof(SubtargetFeatureKV) * 242 + 3820, AMDGPU::FeatureDefaultComponentBroadcast, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 241 + 3902, sizeof(SubtargetFeatureKV) * 241 + 3925, AMDGPU::FeatureDefaultComponentZero, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 240 + 4007, sizeof(SubtargetFeatureKV) * 240 + 4016, AMDGPU::FeatureDLInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 239 + 4059, sizeof(SubtargetFeatureKV) * 239 + 4070, AMDGPU::FeatureDot1Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 238 + 4119, sizeof(SubtargetFeatureKV) * 238 + 4131, AMDGPU::FeatureDot10Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 237 + 4162, sizeof(SubtargetFeatureKV) * 237 + 4174, AMDGPU::FeatureDot11Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 236 + 4270, sizeof(SubtargetFeatureKV) * 236 + 4282, AMDGPU::FeatureDot12Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 235 + 4315, sizeof(SubtargetFeatureKV) * 235 + 4327, AMDGPU::FeatureDot13Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 234 + 4361, sizeof(SubtargetFeatureKV) * 234 + 4372, AMDGPU::FeatureDot2Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 233 + 4420, sizeof(SubtargetFeatureKV) * 233 + 4431, AMDGPU::FeatureDot3Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 232 + 4462, sizeof(SubtargetFeatureKV) * 232 + 4473, AMDGPU::FeatureDot4Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 231 + 4505, sizeof(SubtargetFeatureKV) * 231 + 4516, AMDGPU::FeatureDot5Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 230 + 4548, sizeof(SubtargetFeatureKV) * 230 + 4559, AMDGPU::FeatureDot6Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 229 + 4590, sizeof(SubtargetFeatureKV) * 229 + 4601, AMDGPU::FeatureDot7Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 228 + 4647, sizeof(SubtargetFeatureKV) * 228 + 4658, AMDGPU::FeatureDot8Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 227 + 4706, sizeof(SubtargetFeatureKV) * 227 + 4717, AMDGPU::FeatureDot9Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 226 + 4767, sizeof(SubtargetFeatureKV) * 226 + 4771, AMDGPU::FeatureDPP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 225 + 4820, sizeof(SubtargetFeatureKV) * 225 + 4830, AMDGPU::FeatureDPALU_DPP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 224 + 4889, sizeof(SubtargetFeatureKV) * 224 + 4903, AMDGPU::FeatureDPPBroadcasts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 223 + 4939, sizeof(SubtargetFeatureKV) * 223 + 4953, AMDGPU::FeatureDPPSrc1SGPR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 222 + 4995, sizeof(SubtargetFeatureKV) * 222 + 5016, AMDGPU::FeatureDPPWavefrontShifts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 221 + 5064, sizeof(SubtargetFeatureKV) * 221 + 5069, AMDGPU::FeatureDPP8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 220 + 5119, sizeof(SubtargetFeatureKV) * 220 + 5133, AMDGPU::FeatureDsSrc2Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 219 + 5160, sizeof(SubtargetFeatureKV) * 219 + 5169, AMDGPU::FeatureDumpCodeLower, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 218 + 5207, sizeof(SubtargetFeatureKV) * 218 + 5232, AMDGPU::FeatureDX10ClampAndIEEEMode, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 217 + 5291, sizeof(SubtargetFeatureKV) * 217 + 5321, AMDGPU::FeatureEmulatedSystemScopeAtomics, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 216 + 5415, sizeof(SubtargetFeatureKV) * 216 + 5428, AMDGPU::FeatureEnableDS128, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 215 + 5453, sizeof(SubtargetFeatureKV) * 215 + 5473, AMDGPU::FeatureEnableFlatScratch, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 214 + 5530, sizeof(SubtargetFeatureKV) * 214 + 5553, AMDGPU::FeatureEnablePRTStrictNull, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 213 + 5615, sizeof(SubtargetFeatureKV) * 213 + 5636, AMDGPU::FeatureExtendedImageInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 212 + 5686, sizeof(SubtargetFeatureKV) * 212 + 5720, AMDGPU::FeatureF16BF16ToFP6BF6ConversionScaleInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 211 + 5772, sizeof(SubtargetFeatureKV) * 211 + 5800, AMDGPU::FeatureF32ToF16BF16ConversionSRInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 210 + 5849, sizeof(SubtargetFeatureKV) * 210 + 5867, AMDGPU::FeatureFastDenormalF32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 209 + 5938, sizeof(SubtargetFeatureKV) * 209 + 5948, AMDGPU::FeatureFastFMAF32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 208 + 5998, sizeof(SubtargetFeatureKV) * 208 + 6017, AMDGPU::FeatureFlatAddressSpace, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 207 + 6044, sizeof(SubtargetFeatureKV) * 207 + 6070, AMDGPU::FeatureFlatAtomicFaddF32Inst, { { { 0x0ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 206 + 6106, sizeof(SubtargetFeatureKV) * 206 + 6139, AMDGPU::FeatureFlatBufferGlobalAtomicFaddF64Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 205 + 6201, sizeof(SubtargetFeatureKV) * 205 + 6217, AMDGPU::FeatureUseFlatForGlobal, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 204 + 6263, sizeof(SubtargetFeatureKV) * 204 + 6281, AMDGPU::FeatureFlatGlobalInsts, { { { 0x0ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 203 + 6320, sizeof(SubtargetFeatureKV) * 203 + 6334, AMDGPU::FeatureFlatGVSMode, { { { 0x0ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 202 + 6384, sizeof(SubtargetFeatureKV) * 202 + 6402, AMDGPU::FeatureFlatInstOffsets, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 201 + 6458, sizeof(SubtargetFeatureKV) * 201 + 6478, AMDGPU::FeatureFlatOffsetBits12, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 200 + 6518, sizeof(SubtargetFeatureKV) * 200 + 6478, AMDGPU::FeatureFlatOffsetBits24, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 199 + 6538, sizeof(SubtargetFeatureKV) * 199 + 6557, AMDGPU::FeatureFlatScratchInsts, { { { 0x0ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 198 + 6597, sizeof(SubtargetFeatureKV) * 198 + 6621, AMDGPU::FeatureFlatSegmentOffsetBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 197 + 6704, sizeof(SubtargetFeatureKV) * 197 + 6723, AMDGPU::FeatureFlatSignedOffset, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 196 + 6779, sizeof(SubtargetFeatureKV) * 196 + 6798, AMDGPU::FeatureFmaMixBF16Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 195 + 6870, sizeof(SubtargetFeatureKV) * 195 + 6884, AMDGPU::FeatureFmaMixInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 194 + 6949, sizeof(SubtargetFeatureKV) * 194 + 6962, AMDGPU::FeatureFmacF64Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 193 + 6989, sizeof(SubtargetFeatureKV) * 193 + 6994, AMDGPU::FeatureFMA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 192 + 7058, sizeof(SubtargetFeatureKV) * 192 + 7080, AMDGPU::FeatureFormattedMUBUFInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 191 + 7130, sizeof(SubtargetFeatureKV) * 191 + 7150, AMDGPU::FeatureFP4ConversionScaleInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 190 + 7188, sizeof(SubtargetFeatureKV) * 190 + 7193, AMDGPU::FeatureFP64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 189 + 7228, sizeof(SubtargetFeatureKV) * 189 + 7251, AMDGPU::FeatureFP6BF6ConversionScaleInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 188 + 7297, sizeof(SubtargetFeatureKV) * 188 + 7318, AMDGPU::FeatureFP8ConversionInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 187 + 7358, sizeof(SubtargetFeatureKV) * 187 + 7378, AMDGPU::FeatureFP8ConversionScaleInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 186 + 7416, sizeof(SubtargetFeatureKV) * 186 + 7426, AMDGPU::FeatureFP8Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 185 + 7455, sizeof(SubtargetFeatureKV) * 185 + 7469, AMDGPU::FeatureFP8E5M3Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 184 + 7497, sizeof(SubtargetFeatureKV) * 184 + 7514, AMDGPU::FeatureFullRate64Ops, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 183 + 7551, sizeof(SubtargetFeatureKV) * 183 + 7555, AMDGPU::FeatureG16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 182 + 7602, sizeof(SubtargetFeatureKV) * 182 + 7616, AMDGPU::FeatureGCN3Encoding, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 181 + 7639, sizeof(SubtargetFeatureKV) * 181 + 7643, AMDGPU::FeatureGDS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 180 + 7665, sizeof(SubtargetFeatureKV) * 180 + 7682, AMDGPU::FeatureGetWaveIdInst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 179 + 7724, sizeof(SubtargetFeatureKV) * 179 + 7730, AMDGPU::FeatureGFX10, { { { 0x146352001e0044a1ULL, 0x1555171e0080000ULL, 0xa0f0020a10328200ULL, 0x419a8010440ULL, 0x5064038ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 178 + 7751, sizeof(SubtargetFeatureKV) * 178 + 7765, AMDGPU::FeatureGFX10_3Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 177 + 7801, sizeof(SubtargetFeatureKV) * 177 + 7813, AMDGPU::FeatureGFX10Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 176 + 7848, sizeof(SubtargetFeatureKV) * 176 + 7865, AMDGPU::FeatureGFX10_AEncoding, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 175 + 7898, sizeof(SubtargetFeatureKV) * 175 + 7915, AMDGPU::FeatureGFX10_BEncoding, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 174 + 7939, sizeof(SubtargetFeatureKV) * 174 + 7945, AMDGPU::FeatureGFX11, { { { 0x10635200060044a1ULL, 0x2f555131e0080000ULL, 0xa0f0010a10340200ULL, 0x40000010440ULL, 0x516003aULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 173 + 7966, sizeof(SubtargetFeatureKV) * 173 + 7980, AMDGPU::FeatureGFX11_7Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 172 + 8016, sizeof(SubtargetFeatureKV) * 172 + 8028, AMDGPU::FeatureGFX11Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 171 + 8063, sizeof(SubtargetFeatureKV) * 171 + 8069, AMDGPU::FeatureGFX12, { { { 0x8600200060060a1ULL, 0x2f5115b1e0000000ULL, 0xa016010200342001ULL, 0x2000440ULL, 0x416003aULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 170 + 8090, sizeof(SubtargetFeatureKV) * 170 + 8102, AMDGPU::FeatureGFX12Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 169 + 8137, sizeof(SubtargetFeatureKV) * 169 + 8151, AMDGPU::FeatureGFX1250Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 168 + 8188, sizeof(SubtargetFeatureKV) * 168 + 8207, AMDGPU::FeatureGFX1251GEMMInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 167 + 8249, sizeof(SubtargetFeatureKV) * 167 + 8274, AMDGPU::FeatureGFX125xLowestRateWMMA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 166 + 8353, sizeof(SubtargetFeatureKV) * 166 + 8359, AMDGPU::FeatureGFX13, { { { 0x8600200060060a1ULL, 0x2f5155b1e0080000ULL, 0xa016010a0034a005ULL, 0x2000440ULL, 0x416003aULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 165 + 8380, sizeof(SubtargetFeatureKV) * 165 + 8392, AMDGPU::FeatureGFX13Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x20004000000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 164 + 8427, sizeof(SubtargetFeatureKV) * 164 + 8448, AMDGPU::FeatureGFX7GFX8GFX9Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 163 + 8488, sizeof(SubtargetFeatureKV) * 163 + 8499, AMDGPU::FeatureGFX8Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 162 + 8533, sizeof(SubtargetFeatureKV) * 162 + 8538, AMDGPU::FeatureGFX9, { { { 0x16a35200000040a1ULL, 0x5a4131e0000000ULL, 0x8e0000810320200ULL, 0x1a419a8030000ULL, 0x2401045038ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 161 + 8558, sizeof(SubtargetFeatureKV) * 161 + 8569, AMDGPU::FeatureGFX9Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 160 + 8603, sizeof(SubtargetFeatureKV) * 160 + 8616, AMDGPU::FeatureGFX90AInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 159 + 8652, sizeof(SubtargetFeatureKV) * 159 + 8665, AMDGPU::FeatureGFX940Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 158 + 8701, sizeof(SubtargetFeatureKV) * 158 + 8714, AMDGPU::FeatureGFX950Insts, { { { 0x800400020000ULL, 0x5b00000ULL, 0xc000000000000ULL, 0x180ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 157 + 8750, sizeof(SubtargetFeatureKV) * 157 + 8779, AMDGPU::FeatureGloballyAddressableScratch, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 156 + 8850, sizeof(SubtargetFeatureKV) * 156 + 8854, AMDGPU::FeatureGWS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 155 + 8875, sizeof(SubtargetFeatureKV) * 155 + 8892, AMDGPU::FeatureHalfRate64Ops, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 154 + 8948, sizeof(SubtargetFeatureKV) * 154 + 8975, AMDGPU::FeatureIEEEMinimumMaximumInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 153 + 9091, sizeof(SubtargetFeatureKV) * 153 + 9113, AMDGPU::FeatureImageGather4D16Bug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 152 + 9144, sizeof(SubtargetFeatureKV) * 152 + 9156, AMDGPU::FeatureImageInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 151 + 9183, sizeof(SubtargetFeatureKV) * 151 + 9203, AMDGPU::FeatureImageStoreD16Bug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 150 + 9232, sizeof(SubtargetFeatureKV) * 150 + 9254, AMDGPU::FeatureInstFwdPrefetchBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 149 + 9304, sizeof(SubtargetFeatureKV) * 149 + 9325, AMDGPU::FeatureInstCacheLineSize128, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 148 + 9363, sizeof(SubtargetFeatureKV) * 148 + 9325, AMDGPU::FeatureInstCacheLineSize64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 147 + 9383, sizeof(SubtargetFeatureKV) * 147 + 9399, AMDGPU::FeatureIntClamp, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 146 + 9437, sizeof(SubtargetFeatureKV) * 146 + 9456, AMDGPU::FeatureInv2PiInlineImm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 145 + 9493, sizeof(SubtargetFeatureKV) * 145 + 9509, AMDGPU::FeatureKernargPreload, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 144 + 9573, sizeof(SubtargetFeatureKV) * 144 + 9599, AMDGPU::FeatureLdsBarrierArriveAtomic, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 143 + 9642, sizeof(SubtargetFeatureKV) * 143 + 9669, AMDGPU::FeatureLdsBranchVmemWARHazard, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 142 + 9726, sizeof(SubtargetFeatureKV) * 142 + 9745, AMDGPU::FeatureLDSMisalignedBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 141 + 9839, sizeof(SubtargetFeatureKV) * 141 + 9854, AMDGPU::FeatureLDSBankCount16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 140 + 9896, sizeof(SubtargetFeatureKV) * 140 + 9854, AMDGPU::FeatureLDSBankCount32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 139 + 9911, sizeof(SubtargetFeatureKV) * 139 + 9921, AMDGPU::FeatureLerpInst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 138 + 9947, sizeof(SubtargetFeatureKV) * 138 + 9962, AMDGPU::FeatureEnableLoadStoreOpt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 137 + 9998, sizeof(SubtargetFeatureKV) * 137 + 10016, AMDGPU::FeatureLshlAddU64Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 136 + 10047, sizeof(SubtargetFeatureKV) * 136 + 10065, AMDGPU::FeatureMADIntraFwdBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 135 + 10110, sizeof(SubtargetFeatureKV) * 135 + 10128, AMDGPU::FeatureMadMacF32Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 134 + 10189, sizeof(SubtargetFeatureKV) * 134 + 10203, AMDGPU::FeatureMadMixInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 133 + 10268, sizeof(SubtargetFeatureKV) * 133 + 10287, AMDGPU::FeatureMadNC64_32Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 132 + 10331, sizeof(SubtargetFeatureKV) * 132 + 10344, AMDGPU::FeatureMadU32Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 131 + 10370, sizeof(SubtargetFeatureKV) * 131 + 10380, AMDGPU::FeatureMAIInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 130 + 10401, sizeof(SubtargetFeatureKV) * 130 + 10427, AMDGPU::FeatureMaxHardClauseLength32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 129 + 10488, sizeof(SubtargetFeatureKV) * 129 + 10514, AMDGPU::FeatureMaxHardClauseLength63, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 128 + 10575, sizeof(SubtargetFeatureKV) * 128 + 10603, AMDGPU::FeatureMaxPrivateElementSize16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 127 + 10641, sizeof(SubtargetFeatureKV) * 127 + 10668, AMDGPU::FeatureMaxPrivateElementSize4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 126 + 10705, sizeof(SubtargetFeatureKV) * 126 + 10732, AMDGPU::FeatureMaxPrivateElementSize8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 125 + 10769, sizeof(SubtargetFeatureKV) * 125 + 10786, AMDGPU::FeatureMcastLoadInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 124 + 10818, sizeof(SubtargetFeatureKV) * 124 + 10858, AMDGPU::FeatureMemoryAtomicFAddF32DenormalSupport, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 123 + 10926, sizeof(SubtargetFeatureKV) * 123 + 10950, AMDGPU::FeatureMFMAInlineLiteralBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 122 + 10989, sizeof(SubtargetFeatureKV) * 122 + 10999, AMDGPU::FeatureMIMG_R128, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 121 + 11033, sizeof(SubtargetFeatureKV) * 121 + 11051, AMDGPU::FeatureMinMaxI64Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 120 + 11088, sizeof(SubtargetFeatureKV) * 120 + 11104, AMDGPU::FeatureMin3Max3PKF16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 119 + 11161, sizeof(SubtargetFeatureKV) * 119 + 11183, AMDGPU::FeatureMinimum3Maximum3F16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 118 + 11234, sizeof(SubtargetFeatureKV) * 118 + 11256, AMDGPU::FeatureMinimum3Maximum3F32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 117 + 11307, sizeof(SubtargetFeatureKV) * 117 + 11331, AMDGPU::FeatureMinimum3Maximum3PKF16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 116 + 11388, sizeof(SubtargetFeatureKV) * 116 + 11395, AMDGPU::FeatureMovrel, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 115 + 11426, sizeof(SubtargetFeatureKV) * 115 + 11438, AMDGPU::FeatureMqsadInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 114 + 11469, sizeof(SubtargetFeatureKV) * 114 + 11484, AMDGPU::FeatureMqsadPkInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 113 + 11518, sizeof(SubtargetFeatureKV) * 113 + 11540, AMDGPU::FeatureMSAALoadDstSelBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 112 + 11576, sizeof(SubtargetFeatureKV) * 112 + 11587, AMDGPU::FeatureMsadInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 111 + 11613, sizeof(SubtargetFeatureKV) * 111 + 11625, AMDGPU::FeatureMTBUFInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 110 + 11663, sizeof(SubtargetFeatureKV) * 110 + 11691, AMDGPU::FeatureNegativeScratchOffsetBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 109 + 11781, sizeof(SubtargetFeatureKV) * 109 + 11819, AMDGPU::FeatureNegativeUnalignedScratchOffsetBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 108 + 11945, sizeof(SubtargetFeatureKV) * 108 + 11964, AMDGPU::FeatureNoDataDepHazard, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 107 + 11992, sizeof(SubtargetFeatureKV) * 107 + 12036, AMDGPU::FeatureNoF16PseudoScalarTransInlineConstants, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 106 + 12109, sizeof(SubtargetFeatureKV) * 106 + 12122, AMDGPU::FeatureNoSdstCMPX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 105 + 12173, sizeof(SubtargetFeatureKV) * 105 + 12188, AMDGPU::FeatureNSAClauseBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 104 + 12251, sizeof(SubtargetFeatureKV) * 104 + 12264, AMDGPU::FeatureNSAEncoding, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 103 + 12308, sizeof(SubtargetFeatureKV) * 103 + 12324, AMDGPU::FeatureNSAtoVMEMBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 102 + 12389, sizeof(SubtargetFeatureKV) * 102 + 12403, AMDGPU::FeatureOffset3fBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 101 + 12436, sizeof(SubtargetFeatureKV) * 101 + 12452, AMDGPU::FeaturePackedFP32Ops, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 100 + 12485, sizeof(SubtargetFeatureKV) * 100 + 12501, AMDGPU::FeaturePackedFP64Ops, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 99 + 12534, sizeof(SubtargetFeatureKV) * 99 + 12545, AMDGPU::FeaturePackedTID, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 98 + 12594, sizeof(SubtargetFeatureKV) * 98 + 12609, AMDGPU::FeaturePackedU64Ops, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 97 + 12644, sizeof(SubtargetFeatureKV) * 97 + 12665, AMDGPU::FeaturePartialNSAEncoding, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 96 + 12717, sizeof(SubtargetFeatureKV) * 96 + 12734, AMDGPU::FeaturePermlane16Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 95 + 12786, sizeof(SubtargetFeatureKV) * 95 + 12802, AMDGPU::FeaturePermlane16Swap, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 94 + 12841, sizeof(SubtargetFeatureKV) * 94 + 12857, AMDGPU::FeaturePermlane32Swap, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 93 + 12896, sizeof(SubtargetFeatureKV) * 93 + 12917, AMDGPU::FeaturePkAddMinMaxInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 92 + 12961, sizeof(SubtargetFeatureKV) * 92 + 12978, AMDGPU::FeaturePkFmacF16Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 91 + 13008, sizeof(SubtargetFeatureKV) * 91 + 13027, AMDGPU::FeaturePointSampleAccel, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 90 + 13065, sizeof(SubtargetFeatureKV) * 90 + 13080, AMDGPU::FeaturePreciseMemory, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 89 + 13107, sizeof(SubtargetFeatureKV) * 89 + 13134, AMDGPU::FeaturePrivEnabledTrap2NopBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 88 + 13202, sizeof(SubtargetFeatureKV) * 88 + 13212, AMDGPU::FeaturePrngInst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 87 + 13239, sizeof(SubtargetFeatureKV) * 87 + 13259, AMDGPU::FeaturePseudoScalarTrans, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 86 + 13305, sizeof(SubtargetFeatureKV) * 86 + 13316, AMDGPU::FeatureQsadInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 85 + 13341, sizeof(SubtargetFeatureKV) * 85 + 13350, AMDGPU::FeatureR128A16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 84 + 13467, sizeof(SubtargetFeatureKV) * 84 + 13479, AMDGPU::FeatureRealTrue16Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 83 + 13505, sizeof(SubtargetFeatureKV) * 83 + 13530, AMDGPU::FeatureRequiredExportPriority, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 82 + 13588, sizeof(SubtargetFeatureKV) * 82 + 13602, AMDGPU::FeatureRequiresCOV6, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 81 + 13633, sizeof(SubtargetFeatureKV) * 81 + 13664, AMDGPU::FeatureRequiresInitialUnclausedVmem, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 80 + 13732, sizeof(SubtargetFeatureKV) * 80 + 13751, AMDGPU::FeatureRestrictedSOffset, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 79 + 13801, sizeof(SubtargetFeatureKV) * 79 + 13821, AMDGPU::FeatureSBarrierLeaveImm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 78 + 13864, sizeof(SubtargetFeatureKV) * 78 + 13878, AMDGPU::FeatureSMemRealTime, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 77 + 13908, sizeof(SubtargetFeatureKV) * 77 + 13923, AMDGPU::FeatureSMemTimeInst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 76 + 13949, sizeof(SubtargetFeatureKV) * 76 + 13971, AMDGPU::FeatureSWakeupBarrier, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 75 + 14005, sizeof(SubtargetFeatureKV) * 75 + 14018, AMDGPU::FeatureSWakeupImm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 74 + 14054, sizeof(SubtargetFeatureKV) * 74 + 14064, AMDGPU::FeatureSadInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 73 + 14088, sizeof(SubtargetFeatureKV) * 73 + 14105, AMDGPU::FeatureSafeCUPrefetch, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 72 + 14161, sizeof(SubtargetFeatureKV) * 72 + 14180, AMDGPU::FeatureSafeSmemPrefetch, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 71 + 14227, sizeof(SubtargetFeatureKV) * 71 + 14238, AMDGPU::FeatureSALUFloatInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 70 + 14275, sizeof(SubtargetFeatureKV) * 70 + 14302, AMDGPU::FeatureSALUMinimumMaximumInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 69 + 14345, sizeof(SubtargetFeatureKV) * 69 + 14360, AMDGPU::FeatureScalarAtomics, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 68 + 14398, sizeof(SubtargetFeatureKV) * 68 + 14419, AMDGPU::FeatureScalarDwordx3Loads, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 67 + 14455, sizeof(SubtargetFeatureKV) * 67 + 14481, AMDGPU::FeatureScalarFlatScratchInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 66 + 14523, sizeof(SubtargetFeatureKV) * 66 + 14537, AMDGPU::FeatureScalarStores, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 65 + 14574, sizeof(SubtargetFeatureKV) * 65 + 14579, AMDGPU::FeatureSDWA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 64 + 14625, sizeof(SubtargetFeatureKV) * 64 + 14634, AMDGPU::FeatureSDWAMac, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 63 + 14699, sizeof(SubtargetFeatureKV) * 63 + 14709, AMDGPU::FeatureSDWAOmod, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 62 + 14765, sizeof(SubtargetFeatureKV) * 62 + 14784, AMDGPU::FeatureSDWAOutModsVOPC, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 61 + 14850, sizeof(SubtargetFeatureKV) * 61 + 14862, AMDGPU::FeatureSDWAScalar, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 60 + 14929, sizeof(SubtargetFeatureKV) * 60 + 14939, AMDGPU::FeatureSDWASdst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 59 + 15010, sizeof(SubtargetFeatureKV) * 59 + 15022, AMDGPU::FeatureSeaIslands, { { { 0x140112001e000400ULL, 0xc400120080400ULL, 0xf0001a10028200ULL, 0x41000010000ULL, 0x401000009ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 58 + 15049, sizeof(SubtargetFeatureKV) * 58 + 15069, AMDGPU::FeatureSetPrioIncWgInst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 57 + 15103, sizeof(SubtargetFeatureKV) * 57 + 15125, AMDGPU::FeatureSetregVGPRMSBFixup, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 56 + 15181, sizeof(SubtargetFeatureKV) * 56 + 15195, AMDGPU::FeatureSGPRInitBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 55 + 15261, sizeof(SubtargetFeatureKV) * 55 + 15291, AMDGPU::FeatureShaderCyclesHiLoRegisters, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 54 + 15334, sizeof(SubtargetFeatureKV) * 54 + 15357, AMDGPU::FeatureShaderCyclesRegister, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 53 + 15393, sizeof(SubtargetFeatureKV) * 53 + 15406, AMDGPU::FeatureEnableSIScheduler, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 52 + 15434, sizeof(SubtargetFeatureKV) * 52 + 15454, AMDGPU::FeatureSmemPrefetchInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 51 + 15555, sizeof(SubtargetFeatureKV) * 51 + 15583, AMDGPU::FeatureSMEMtoVectorWriteHazard, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 50 + 15626, sizeof(SubtargetFeatureKV) * 50 + 15643, AMDGPU::FeatureSouthernIslands, { { { 0x1401100014000200ULL, 0x4400020080400ULL, 0xd0001a11028200ULL, 0x41000000000ULL, 0x401000001ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 49 + 15675, sizeof(SubtargetFeatureKV) * 49 + 15683, AMDGPU::FeatureSRAMECC, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 48 + 15698, sizeof(SubtargetFeatureKV) * 48 + 15714, AMDGPU::FeatureSupportsSRAMECC, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 47 + 15740, sizeof(SubtargetFeatureKV) * 47 + 15761, AMDGPU::FeatureSWMMACGfx1200Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 46 + 15793, sizeof(SubtargetFeatureKV) * 46 + 15814, AMDGPU::FeatureSWMMACGfx1250Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 45 + 15846, sizeof(SubtargetFeatureKV) * 45 + 15857, AMDGPU::FeatureTanhInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 44 + 15889, sizeof(SubtargetFeatureKV) * 44 + 15910, AMDGPU::FeatureTensorCvtLutInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 43 + 15940, sizeof(SubtargetFeatureKV) * 43 + 15956, AMDGPU::FeatureTgSplitSupport, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 42 + 16010, sizeof(SubtargetFeatureKV) * 42 + 16035, AMDGPU::FeatureTransCoexecutionHazard, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 41 + 16093, sizeof(SubtargetFeatureKV) * 41 + 16119, AMDGPU::FeatureTransposeLoadF4F6Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 40 + 16176, sizeof(SubtargetFeatureKV) * 40 + 16189, AMDGPU::FeatureTrapHandler, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 39 + 16210, sizeof(SubtargetFeatureKV) * 39 + 16229, AMDGPU::FeatureTrigReducedRange, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 38 + 16285, sizeof(SubtargetFeatureKV) * 38 + 16292, AMDGPU::FeatureTrue16BitInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 16325, sizeof(SubtargetFeatureKV) * 37 + 16347, AMDGPU::FeatureUnalignedAccessMode, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 16434, sizeof(SubtargetFeatureKV) * 36 + 16458, AMDGPU::FeatureUnalignedBufferAccess, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 16510, sizeof(SubtargetFeatureKV) * 35 + 16530, AMDGPU::FeatureUnalignedDSAccess, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 16592, sizeof(SubtargetFeatureKV) * 34 + 16617, AMDGPU::FeatureUnalignedScratchAccess, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 16660, sizeof(SubtargetFeatureKV) * 33 + 16678, AMDGPU::FeatureUnpackedD16VMem, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 16713, sizeof(SubtargetFeatureKV) * 32 + 16738, AMDGPU::FeatureEnableUnsafeDSOffsetFolding, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 16789, sizeof(SubtargetFeatureKV) * 31 + 16807, AMDGPU::FeatureUseAddPC64Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 16837, sizeof(SubtargetFeatureKV) * 30 + 16858, AMDGPU::FeatureUserSGPRInit16Bug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 16916, sizeof(SubtargetFeatureKV) * 29 + 16931, AMDGPU::FeatureVMovB64Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 16957, sizeof(SubtargetFeatureKV) * 28 + 16972, AMDGPU::FeatureVMulU64Inst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 16999, sizeof(SubtargetFeatureKV) * 27 + 17021, AMDGPU::FeatureVALUTransUseHazard, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 17096, sizeof(SubtargetFeatureKV) * 26 + 17118, AMDGPU::FeatureVcmpxExecWARHazard, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 17164, sizeof(SubtargetFeatureKV) * 25 + 17186, AMDGPU::FeatureVcmpxPermlaneHazard, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 17204, sizeof(SubtargetFeatureKV) * 24 + 17216, AMDGPU::FeatureRequiresAlignedVGPRs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 17268, sizeof(SubtargetFeatureKV) * 23 + 17284, AMDGPU::FeatureVGPRIndexMode, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 17316, sizeof(SubtargetFeatureKV) * 22 + 17332, AMDGPU::FeatureVmemPrefInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 17388, sizeof(SubtargetFeatureKV) * 21 + 17411, AMDGPU::FeatureVMemToLDSLoad, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 17568, sizeof(SubtargetFeatureKV) * 20 + 17596, AMDGPU::FeatureVMEMtoScalarWriteHazard, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 17695, sizeof(SubtargetFeatureKV) * 19 + 17720, AMDGPU::FeatureVmemWriteVgprInOrder, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 17783, sizeof(SubtargetFeatureKV) * 18 + 17800, AMDGPU::FeatureVolcanicIslands, { { { 0x16a1120000000401ULL, 0x1e400160080400ULL, 0xf0001a10328200ULL, 0x1041858010000ULL, 0x401001009ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 17832, sizeof(SubtargetFeatureKV) * 17 + 17845, AMDGPU::FeatureVOP3Literal, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 17873, sizeof(SubtargetFeatureKV) * 16 + 17879, AMDGPU::FeatureVOP3PInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 17909, sizeof(SubtargetFeatureKV) * 15 + 17942, AMDGPU::FeatureVOP3PX2IncrementsVaVdstTwice, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 18006, sizeof(SubtargetFeatureKV) * 14 + 18011, AMDGPU::FeatureVOPDInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 18051, sizeof(SubtargetFeatureKV) * 13 + 18057, AMDGPU::FeatureVscnt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 18090, sizeof(SubtargetFeatureKV) * 12 + 18100, AMDGPU::FeatureWaitXcnt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 18128, sizeof(SubtargetFeatureKV) * 11 + 18161, AMDGPU::FeatureWaitsBeforeSystemScopeStores, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 18232, sizeof(SubtargetFeatureKV) * 10 + 18248, AMDGPU::FeatureWavefrontSize16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 18284, sizeof(SubtargetFeatureKV) * 9 + 18248, AMDGPU::FeatureWavefrontSize32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 18300, sizeof(SubtargetFeatureKV) * 8 + 18248, AMDGPU::FeatureWavefrontSize64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 18316, sizeof(SubtargetFeatureKV) * 7 + 18332, AMDGPU::FeatureWMMA128bInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 18405, sizeof(SubtargetFeatureKV) * 6 + 18421, AMDGPU::FeatureWMMA256bInsts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 18487, sizeof(SubtargetFeatureKV) * 5 + 18512, AMDGPU::FeatureWMMACoexecutionHazards, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 18575, sizeof(SubtargetFeatureKV) * 4 + 18586, AMDGPU::FeatureXF32Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 18689, sizeof(SubtargetFeatureKV) * 3 + 18695, AMDGPU::FeatureXNACK, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x200000000000000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 18716, sizeof(SubtargetFeatureKV) * 2 + 18735, AMDGPU::FeatureXNACKOnOffModes, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x200000000000000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 18770, sizeof(SubtargetFeatureKV) * 1 + 18784, AMDGPU::FeatureSupportsXNACK, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000" "1024-addressable-vgprs\000Has 1024 addressable VGPRs\000" "1536-"
    "physical-vgprs\000Has 1536 physical VGPRs per SIMD\000" "16-bit-insts\000"
    "Has i16/f16 instructions\000" "45-bit-num-records-buffer-resource\000Th"
    "e buffer resource (V#) supports 45-bit num_records\000" "64-bit-literal"
    "s\000Can use 64-bit literals with single DWORD instructions\000a16\000S"
    "upport A16 for 16-bit coordinates/gradients/lod/clamp/mip image operand"
    "s\000add-min-max-insts\000Has v_add_{min|max}_{i|u}32 instructions\000a"
    "dd-no-carry-insts\000Have VALU add/sub instructions without carry out\000"
    "add-sub-u64-insts\000Has v_add_u64 and v_sub_u64 instructions\000addres"
    "sablelocalmemorysize163840\000The size of local memory in bytes\000addr"
    "essablelocalmemorysize32768\000addressablelocalmemorysize327680\000addr"
    "essablelocalmemorysize65536\000agent-scope-fine-grained-remote-memory-a"
    "tomics\000Agent (device) scoped atomic operations, excluding those dire"
    "ctly supported by PCIe (i.e. integer atomic add, exchange, and compare-"
    "and-swap), are functional for allocations in host or peer device memory"
    ".\000aperture-regs\000Has Memory Aperture Base and Size Registers\000ar"
    "chitected-flat-scratch\000Flat Scratch register is a readonly SPI initi"
    "alized architected register\000architected-sgprs\000Enable the architec"
    "ted SGPRs\000ashr-pk-insts\000Has Arithmetic Shift Pack instructions\000"
    "assembler-permissive-wavesize\000Allow parsing wave32 and wave64 varian"
    "ts of instructions\000asynccnt\000Has separate asynccnt counter\000atom"
    "ic-buffer-global-pk-add-f16-insts\000Has buffer_atomic_pk_add_f16 and g"
    "lobal_atomic_pk_add_f16 instructions that can return original value\000"
    "atomic-buffer-global-pk-add-f16-no-rtn-insts\000Has buffer_atomic_pk_ad"
    "d_f16 and global_atomic_pk_add_f16 instructions that don't return origi"
    "nal value\000atomic-buffer-pk-add-bf16-inst\000Has buffer_atomic_pk_add"
    "_bf16 instruction\000atomic-csub-no-rtn-insts\000Has buffer_atomic_csub"
    " and global_atomic_csub instructions that don't return original value\000"
    "atomic-ds-pk-add-16-insts\000Has ds_pk_add_bf16, ds_pk_add_f16, ds_pk_a"
    "dd_rtn_bf16, ds_pk_add_rtn_f16 instructions\000atomic-fadd-no-rtn-insts"
    "\000Has buffer_atomic_add_f32 and global_atomic_add_f32 instructions th"
    "at don't return original value\000atomic-fadd-rtn-insts\000Has buffer_a"
    "tomic_add_f32 and global_atomic_add_f32 instructions that return origin"
    "al value\000atomic-flat-pk-add-16-insts\000Has flat_atomic_pk_add_f16 a"
    "nd flat_atomic_pk_add_bf16 instructions\000atomic-fmin-fmax-flat-f32\000"
    "Has flat memory instructions for atomicrmw fmin/fmax for float\000atomi"
    "c-fmin-fmax-flat-f64\000Has flat memory instructions for atomicrmw fmin"
    "/fmax for double\000atomic-fmin-fmax-global-f32\000Has global/buffer in"
    "structions for atomicrmw fmin/fmax for float\000atomic-fmin-fmax-global"
    "-f64\000atomic-global-pk-add-bf16-inst\000Has global_atomic_pk_add_bf16"
    " instruction\000auto-waitcnt-before-barrier\000Hardware automatically i"
    "nserts waitcnt before barrier\000back-off-barrier\000Hardware supports "
    "backing off s_barrier if an exception occurs\000bf16-cvt-insts\000Has b"
    "f16 conversion instructions\000bf16-pk-insts\000Has bf16 packed instruc"
    "tions (fma, add, mul, max, min)\000bf16-trans-insts\000Has bf16 transce"
    "ndental instructions\000bf8-cvt-scale-insts\000Has bf8 conversion scale"
    " instructions\000bitop3-insts\000Has v_bitop3_b32/v_bitop3_b16 instruct"
    "ions\000block-vgpr-csr\000Use block load/store for VGPR callee saved re"
    "gisters\000bvh-dual-bvh-8-insts\000Has image_bvh_dual_intersect_ray and"
    " image_bvh8_intersect_ray instructions\000ci-insts\000Additional instru"
    "ctions for CI+\000clusters\000Has clusters of workgroups support\000cub"
    "e-insts\000Has v_cube* instructions\000cumode\000Enable CU wavefront ex"
    "ecution mode\000cvt-fp8-vop1-bug\000FP8/BF8 VOP1 form of conversion to "
    "F32 is unreliable\000cvt-norm-insts\000Has v_cvt_norm* instructions\000"
    "cvt-pk-f16-f32-inst\000Has cvt_pk_f16_f32 instruction\000cvt-pknorm-vop"
    "2-insts\000Has v_cvt_pk_norm_*f32 instructions/Has v_cvt_pk_norm_*_f16 "
    "instructions\000cvt-pknorm-vop3-insts\000d16-write-vgpr32\000D16 instru"
    "ctions potentially have 32-bit data dependencies\000default-component-b"
    "roadcast\000BUFFER/IMAGE store instructions set unspecified components "
    "to x component (GFX12)\000default-component-zero\000BUFFER/IMAGE store "
    "instructions set unspecified components to zero (before GFX12)\000dl-in"
    "sts\000Has v_fmac_f32 and v_xnor_b32 instructions\000dot1-insts\000Has "
    "v_dot4_i32_i8 and v_dot8_i32_i4 instructions\000dot10-insts\000Has v_do"
    "t2_f32_f16 instruction\000dot11-insts\000Has v_dot4_f32_fp8_fp8, v_dot4"
    "_f32_fp8_bf8, v_dot4_f32_bf8_fp8, v_dot4_f32_bf8_bf8 instructions\000do"
    "t12-insts\000Has v_dot2_f32_bf16 instructions\000dot13-insts\000Has v_d"
    "ot2c_f32_bf16 instructions\000dot2-insts\000Has v_dot2_i32_i16, v_dot2_"
    "u32_u16 instructions\000dot3-insts\000Has v_dot8c_i32_i4 instruction\000"
    "dot4-insts\000Has v_dot2c_i32_i16 instruction\000dot5-insts\000Has v_do"
    "t2c_f32_f16 instruction\000dot6-insts\000Has v_dot4c_i32_i8 instruction"
    "\000dot7-insts\000Has v_dot4_u32_u8, v_dot8_u32_u4 instructions\000dot8"
    "-insts\000Has v_dot4_i32_iu8, v_dot8_i32_iu4 instructions\000dot9-insts"
    "\000Has v_dot2_f16_f16, v_dot2_bf16_bf16 instructions\000dpp\000Support"
    " DPP (Data Parallel Primitives) extension\000dpp-64bit\000Support DPP ("
    "Data Parallel Primitives) extension in DP ALU\000dpp-row-bcast\000Suppo"
    "rt DPP row_bcast15/row_bcast31\000dpp-src1-sgpr\000Support SGPR for Src"
    "1 of DPP instructions\000dpp-wavefront-shifts\000Support DPP wave_shl/w"
    "ave_rol/wave_shr/wave_ror\000dpp8\000Support DPP8 (Data Parallel Primit"
    "ives) extension\000ds-src2-insts\000Has ds_*_src2 instructions\000dumpc"
    "ode\000Dump MachineInstrs in the CodeEmitter\000dx10-clamp-and-ieee-mod"
    "e\000Target has DX10_CLAMP and IEEE_MODE kernel descriptor bits\000emul"
    "ated-system-scope-atomics\000System scope atomics unsupported by the PC"
    "I-e are emulated in HW via CAS loop and functional.\000enable-ds128\000"
    "Use ds_{read|write}_b128\000enable-flat-scratch\000Use scratch_* flat m"
    "emory instructions to access scratch\000enable-prt-strict-null\000Enabl"
    "e zeroing of result registers for sparse texture fetches\000extended-im"
    "age-insts\000Support mips != 0, lod != 0, gather4, and get_lod\000f16bf"
    "16-to-fp6bf6-cvt-scale-insts\000Has f16bf16 to fp6bf6 conversion scale "
    "instructions\000f32-to-f16bf16-cvt-sr-insts\000Has f32 to f16bf16 conve"
    "rsion scale instructions\000fast-denormal-f32\000Enabling denormals doe"
    "s not cause f32 instructions to run at f64 rates\000fast-fmaf\000Assumi"
    "ng f32 fma is at least as fast as mul + add\000flat-address-space\000Su"
    "pport flat address space\000flat-atomic-fadd-f32-inst\000Has flat_atomi"
    "c_add_f32 instruction\000flat-buffer-global-fadd-f64-inst\000Has flat, "
    "buffer, and global instructions for f64 atomic fadd\000flat-for-global\000"
    "Force to generate flat instruction for global\000flat-global-insts\000H"
    "ave global_* flat memory instructions\000flat-gvs-mode\000Have GVS addr"
    "essing mode with flat_* instructions\000flat-inst-offsets\000Flat instr"
    "uctions have immediate offset addressing mode\000flat-offset-bits-12\000"
    "Number of bits for flat offset encoding\000flat-offset-bits-24\000flat-"
    "scratch-insts\000Have scratch_* flat memory instructions\000flat-segmen"
    "t-offset-bug\000GFX10 bug where inst_offset is ignored when flat instru"
    "ctions access global memory\000flat-signed-offset\000Immediate offset o"
    "f FLAT instructions are always signed\000fma-mix-bf16-insts\000Has v_fm"
    "a_mix_f32_bf16, v_fma_mixlo_bf16, v_fma_mixhi_bf16 instructions\000fma-"
    "mix-insts\000Has v_fma_mix_f32, v_fma_mixlo_f16, v_fma_mixhi_f16 instru"
    "ctions\000fmacf64-inst\000Has v_fmac_f64 instruction\000fmaf\000Enable "
    "single precision FMA (not as fast as mul+add, but fused)\000formatted-m"
    "ubuf-insts\000Has formatted memory untyped buffer instructions.\000fp4-"
    "cvt-scale-insts\000Has fp4 conversion scale instructions\000fp64\000Ena"
    "ble double precision operations\000fp6bf6-cvt-scale-insts\000Has fp6 an"
    "d bf6 conversion scale instructions\000fp8-conversion-insts\000Has fp8 "
    "and bf8 conversion instructions\000fp8-cvt-scale-insts\000Has fp8 conve"
    "rsion scale instructions\000fp8-insts\000Has fp8 and bf8 instructions\000"
    "fp8e5m3-insts\000Has fp8 e5m3 format support\000full-rate-64-ops\000Mos"
    "t fp64 instructions are full rate\000g16\000Support G16 for 16-bit grad"
    "ient image operands\000gcn3-encoding\000Encoding format for VI\000gds\000"
    "Has Global Data Share\000get-wave-id-inst\000Has s_get_waveid_in_workgr"
    "oup instruction\000gfx10\000GFX10 GPU generation\000gfx10-3-insts\000Ad"
    "ditional instructions for GFX10.3\000gfx10-insts\000Additional instruct"
    "ions for GFX10+\000gfx10_a-encoding\000Has BVH ray tracing instructions"
    "\000gfx10_b-encoding\000Encoding format GFX10_B\000gfx11\000GFX11 GPU g"
    "eneration\000gfx11-7-insts\000Additional instructions for GFX11.7\000gf"
    "x11-insts\000Additional instructions for GFX11+\000gfx12\000GFX12 GPU g"
    "eneration\000gfx12-insts\000Additional instructions for GFX12+\000gfx12"
    "50-insts\000Additional instructions for GFX1250+\000gfx1251-gemm-insts\000"
    "Has additional gfx1251 DGEMM instructions\000gfx125x-lowest-rate-wmma\000"
    "Has the lowest rate wmma in the gfx125x family, mainly for the gfx12-5-"
    "generic\000gfx13\000GFX13 GPU generation\000gfx13-insts\000Additional i"
    "nstructions for GFX13+\000gfx7-gfx8-gfx9-insts\000Instructions shared i"
    "n GFX7, GFX8, GFX9\000gfx8-insts\000Additional instructions for GFX8+\000"
    "gfx9\000GFX9 GPU generation\000gfx9-insts\000Additional instructions fo"
    "r GFX9+\000gfx90a-insts\000Additional instructions for GFX90A+\000gfx94"
    "0-insts\000Additional instructions for GFX940+\000gfx950-insts\000Addit"
    "ional instructions for GFX950+\000globally-addressable-scratch\000FLAT "
    "instructions can access scratch memory for any thread in any wave\000gw"
    "s\000Has Global Wave Sync\000half-rate-64-ops\000Most fp64 instructions"
    " are half rate instead of quarter\000ieee-minimum-maximum-insts\000Has "
    "v_minimum/maximum_f16/f32/f64, v_minimummaximum/maximumminimum_f16/f32 "
    "andv_pk_minimum/maximum_f16 instructions\000image-gather4-d16-bug\000Im"
    "age Gather4 D16 hardware bug\000image-insts\000Support image instructio"
    "ns\000image-store-d16-bug\000Image Store D16 hardware bug\000inst-fwd-p"
    "refetch-bug\000S_INST_PREFETCH instruction causes shader to hang\000ins"
    "tcachelinesize128\000Instruction cache line size in bytes.\000instcache"
    "linesize64\000int-clamp-insts\000Support clamp for integer destination\000"
    "inv-2pi-inline-imm\000Has 1 / (2 * pi) as inline immediate\000kernarg-p"
    "reload\000Hardware supports preloading of kernel arguments in user SGPR"
    "s.\000lds-barrier-arrive-atomic\000Has LDS barrier-arrive atomic instru"
    "ctions\000lds-branch-vmem-war-hazard\000Switching between LDS and VMEM-"
    "tex not waiting VM_VSRC=0\000lds-misaligned-bug\000Some GFX10 bug with "
    "multi-dword LDS and flat access that is not naturally aligned in WGP mo"
    "de\000ldsbankcount16\000The number of LDS banks per compute unit.\000ld"
    "sbankcount32\000lerp-inst\000Has v_lerp_u8 instruction\000load-store-op"
    "t\000Enable SI load/store optimizer pass\000lshl-add-u64-inst\000Has v_"
    "lshl_add_u64 instruction\000mad-intra-fwd-bug\000MAD_U64/I64 intra inst"
    "ruction forwarding bug\000mad-mac-f32-insts\000Has v_mad_f32/v_mac_f32/"
    "v_madak_f32/v_madmk_f32 instructions\000mad-mix-insts\000Has v_mad_mix_"
    "f32, v_mad_mixlo_f16, v_mad_mixhi_f16 instructions\000mad-nc-64-32-inst"
    "s\000Has v_mad_nc_{u64_u32|i64_i32} instructions\000mad-u32-inst\000Has"
    " v_mad_u32 instruction\000mai-insts\000Has mAI instructions\000max-hard"
    "-clause-length-32\000Maximum number of instructions in an explicit S_CL"
    "AUSE is 32\000max-hard-clause-length-63\000Maximum number of instructio"
    "ns in an explicit S_CLAUSE is 63\000max-private-element-size-16\000Maxi"
    "mum private access size may be 16\000max-private-element-size-4\000Maxi"
    "mum private access size may be 4\000max-private-element-size-8\000Maxim"
    "um private access size may be 8\000mcast-load-insts\000Has multicast lo"
    "ad instructions\000memory-atomic-fadd-f32-denormal-support\000global/fl"
    "at/buffer atomic fadd for float supports denormal handling\000mfma-inli"
    "ne-literal-bug\000MFMA cannot use inline literal as SrcC\000mimg-r128\000"
    "Support 128-bit texture resources\000min-max-i64-insts\000Has v_{min|ma"
    "x}_{i|u}64 instructions\000min3-max3-pkf16\000Has v_pk_min3_num_f16 and"
    " v_pk_max3_num_f16 instructions\000minimum3-maximum3-f16\000Has v_minim"
    "um3_f16 and v_maximum3_f16 instructions\000minimum3-maximum3-f32\000Has"
    " v_minimum3_f32 and v_maximum3_f32 instructions\000minimum3-maximum3-pk"
    "f16\000Has v_pk_minimum3_f16 and v_pk_maximum3_f16 instructions\000movr"
    "el\000Has v_movrel*_b32 instructions\000mqsad-insts\000Has v_mqsad_u32_"
    "u8 instruction\000mqsad-pk-insts\000Has v_mqsad_pk_u16_u8 instruction\000"
    "msaa-load-dst-sel-bug\000MSAA loads not honoring dst_sel bug\000msad-in"
    "sts\000Has v_msad_u8 instruction\000mtbuf-insts\000Has memory typed buf"
    "fer instructions.\000negative-scratch-offset-bug\000Negative immediate "
    "offsets in scratch instructions with an SGPR offset page fault on GFX9\000"
    "negative-unaligned-scratch-offset-bug\000Scratch instructions with a VG"
    "PR offset and a negative immediate offset thatis not a multiple of 4 re"
    "ad wrong memory on GFX10\000no-data-dep-hazard\000Does not need SW wait"
    "states\000no-f16-pseudo-scalar-trans-inline-constants\000Inline constan"
    "ts are not supported for F16 pseudo scalar transcendentals\000no-sdst-c"
    "mpx\000V_CMPX does not write VCC/SGPR in addition to EXEC\000nsa-clause"
    "-bug\000MIMG-NSA in a hard clause has unpredictable results on GFX10.1\000"
    "nsa-encoding\000Support NSA encoding for image instructions\000nsa-to-v"
    "mem-bug\000MIMG-NSA followed by VMEM fail if EXEC_LO or EXEC_HI equals "
    "zero\000offset-3f-bug\000Branch offset of 3f hardware bug\000packed-fp3"
    "2-ops\000Support packed fp32 instructions\000packed-fp64-ops\000Support"
    " packed fp64 instructions\000packed-tid\000Workitem IDs are packed into"
    " v0 at kernel launch\000packed-u64-ops\000Support packed uint64 instruc"
    "tions\000partial-nsa-encoding\000Support partial NSA encoding for image"
    " instructions\000permlane16-insts\000Has v_permlane16_b32/v_permlanex16"
    "_b32 instructions\000permlane16-swap\000Has v_permlane16_swap_b32 instr"
    "uctions\000permlane32-swap\000Has v_permlane32_swap_b32 instructions\000"
    "pk-add-min-max-insts\000Has v_pk_add_{min|max}_{i|u}16 instructions\000"
    "pk-fmac-f16-inst\000Has v_pk_fmac_f16 instruction\000point-sample-accel"
    "\000Has point sample acceleration feature\000precise-memory\000Enable p"
    "recise memory mode\000priv-enabled-trap2-nop-bug\000Hardware that runs "
    "with PRIV=1 interpreting 's_trap 2' as a nop bug\000prng-inst\000Has v_"
    "prng_b32 instruction\000pseudo-scalar-trans\000Has Pseudo Scalar Transc"
    "endental instructions\000qsad-insts\000Has v_qsad* instructions\000r128"
    "-a16\000Support gfx9-style A16 for 16-bit coordinates/gradients/lod/cla"
    "mp/mip image operands, where a16 is aliased with r128\000real-true16\000"
    "Use true 16-bit registers\000required-export-priority\000Export priorit"
    "y must be explicitly manipulated on GFX11.5\000requires-cov6\000Target "
    "Requires Code Object V6\000requires-initial-unclause-vmem\000Hardware e"
    "ntrypoints require first VMEM instruction to be unclaused\000restricted"
    "-soffset\000Has restricted SOffset (immediate not supported).\000s-barr"
    "ier-leave-imm\000s_barrier_leave takes an immediate operand\000s-memrea"
    "ltime\000Has s_memrealtime instruction\000s-memtime-inst\000Has s_memti"
    "me instruction\000s-wakeup-barrier-inst\000Has s_wakeup_barrier instruc"
    "tion.\000s-wakeup-imm\000s_wakeup takes an immediate operand\000sad-ins"
    "ts\000Has v_sad* instructions\000safe-cu-prefetch\000VMEM CU scope pref"
    "etches do not fail on illegal address\000safe-smem-prefetch\000SMEM pre"
    "fetches do not fail on illegal address\000salu-float\000Has SALU floati"
    "ng point instructions\000salu-minimum-maximum-insts\000Has s_minimum/ma"
    "ximum_f16/f32 instructions\000scalar-atomics\000Has atomic scalar memor"
    "y instructions\000scalar-dwordx3-loads\000Has 96-bit scalar load instru"
    "ctions\000scalar-flat-scratch-insts\000Have s_scratch_* flat memory ins"
    "tructions\000scalar-stores\000Has store scalar memory instructions\000s"
    "dwa\000Support SDWA (Sub-DWORD Addressing) extension\000sdwa-mav\000Sup"
    "port v_mac_f32/f16 with SDWA (Sub-DWORD Addressing) extension\000sdwa-o"
    "mod\000Support OMod with SDWA (Sub-DWORD Addressing) extension\000sdwa-"
    "out-mods-vopc\000Support clamp for VOPC with SDWA (Sub-DWORD Addressing"
    ") extension\000sdwa-scalar\000Support scalar register with SDWA (Sub-DW"
    "ORD Addressing) extension\000sdwa-sdst\000Support scalar dst for VOPC w"
    "ith SDWA (Sub-DWORD Addressing) extension\000sea-islands\000SEA_ISLANDS"
    " GPU generation\000setprio-inc-wg-inst\000Has s_setprio_inc_wg instruct"
    "ion.\000setreg-vgpr-msb-fixup\000S_SETREG to MODE clobbers VGPR MSB bit"
    "s, requires fixup\000sgpr-init-bug\000VI SGPR initialization bug requir"
    "ing a fixed SGPR allocation size\000shader-cycles-hi-lo-registers\000Ha"
    "s SHADER_CYCLES_HI/LO hardware registers\000shader-cycles-register\000H"
    "as SHADER_CYCLES hardware register\000si-scheduler\000Enable SI Machine"
    " Scheduler\000smem-prefetch-insts\000Has s_prefetch_inst, s_prefetch_in"
    "st_pc_rel, s_prefetch_data and s_prefetch_data_pc_rel instructions\000s"
    "mem-to-vector-write-hazard\000s_load_dword followed by v_cmp page fault"
    "s\000southern-islands\000SOUTHERN_ISLANDS GPU generation\000sramecc\000"
    "Enable SRAMECC\000sramecc-support\000Hardware supports SRAMECC\000swmma"
    "c-gfx1200-insts\000Has GFX1200 SWMMAC instructions\000swmmac-gfx1250-in"
    "sts\000Has GFX1250 SWMMAC instructions\000tanh-insts\000Has v_tanh_f32/"
    "f16 instructions\000tensor-cvt-lut-insts\000Has v_perm_pk16* instructio"
    "ns\000tgsplit-support\000Hardware support for threadgroup split executi"
    "on mode\000trans-coexecution-hazard\000Hazard when TRANS co-executes wi"
    "th other VALU instruction\000transpose-load-f4f6-insts\000Has ds_load_t"
    "r4/tr6 and global_load_tr4/tr6 instructions\000trap-handler\000Trap han"
    "dler support\000trig-reduced-range\000Requires use of fract on argument"
    "s to trig instructions\000true16\000True 16-bit operand instructions\000"
    "unaligned-access-mode\000Enable unaligned global, local and region load"
    "s and stores if the hardware supports it\000unaligned-buffer-access\000"
    "Hardware supports unaligned global loads and stores\000unaligned-ds-acc"
    "ess\000Hardware supports unaligned local and region loads and stores\000"
    "unaligned-scratch-access\000Support unaligned scratch loads and stores\000"
    "unpacked-d16-vmem\000Has unpacked d16 vmem instructions\000unsafe-ds-of"
    "fset-folding\000Force using DS instruction immediate offsets on SI\000u"
    "se-add-pc64-inst\000Use s_add_pc_i64 instruction.\000user-sgpr-init16-b"
    "ug\000Bug requiring at least 16 user+system SGPRs to be enabled\000v-mo"
    "v-b64-inst\000Has v_mov_b64 instruction\000v-mul-u64-inst\000Has v_mul_"
    "u64 instruction.\000valu-trans-use-hazard\000Hazard when TRANS instruct"
    "ions are closely followed by a use of the result\000vcmpx-exec-war-haza"
    "rd\000V_CMPX WAR hazard on EXEC (V_CMPX issue ONLY)\000vcmpx-permlane-h"
    "azard\000TODO: describe me\000vgpr-align2\000VGPR and AGPR tuple operan"
    "ds require even alignment\000vgpr-index-mode\000Has VGPR mode register "
    "indexing\000vmem-pref-insts\000Has flat_prefect_b8 and global_prefetch_"
    "b8 instructions\000vmem-to-lds-load-insts\000The platform has memory to"
    " lds instructions (global_load w/lds bit set, buffer_loadw/lds bit set "
    "or global_load_lds. This does not include scratch_load_lds.\000vmem-to-"
    "scalar-write-hazard\000VMEM instruction followed by scalar writing to E"
    "XEC mask, M0 or SGPR leads to incorrect execution.\000vmem-write-vgpr-i"
    "n-order\000VMEM instructions of the same type write VGPR results in ord"
    "er\000volcanic-islands\000VOLCANIC_ISLANDS GPU generation\000vop3-liter"
    "al\000Can use one literal in VOP3\000vop3p\000Has VOP3P packed instruct"
    "ions\000vop3px2-increments-va-vdst-twice\000VOP3PX2 encoded instruction"
    "s increment the VaVdst counter twice\000vopd\000Has VOPD dual issue wav"
    "e32 instructions\000vscnt\000Has separate store vscnt counter\000wait-x"
    "cnt\000Has s_wait_xcnt instruction\000waits-before-system-scope-stores\000"
    "Target requires waits for loads and atomics before system scope stores\000"
    "wavefrontsize16\000The number of threads per wavefront\000wavefrontsize"
    "32\000wavefrontsize64\000wmma-128b-insts\000Has WMMA instructions where"
    " A and B matrices do not have duplicated data\000wmma-256b-insts\000Has"
    " WMMA instructions where A and B matrices have duplicated data\000wmma-"
    "coexecution-hazards\000Hazards when WMMA co-executes with other WMMA/VA"
    "LU instruction\000xf32-insts\000Has instructions that support xf32 form"
    "at, such as v_mfma_f32_16x16x8_xf32 and v_mfma_f32_32x32x4_xf32\000xnac"
    "k\000Enable XNACK support\000xnack-on-off-modes\000Target supports XNAC"
    "K on/off modes\000xnack-support\000Hardware supports XNACK\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 81, 683> AMDGPUSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 81 + 1, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 80 + 9, { { { 0x0ULL, 0x80000000ULL, 0x1001000ULL, 0x0ULL, 0x2002000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 79 + 17, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x0ULL, 0x2000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 78 + 22, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 77 + 30, { { { 0x0ULL, 0x100000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 76 + 42, { { { 0x8008000000000ULL, 0x80020000000400ULL, 0x17e000100b080400ULL, 0x1a00400200001ULL, 0x2000602000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 75 + 58, { { { 0x6008008000000000ULL, 0xe8000000000004eULL, 0x2e0000001000000ULL, 0x20000000200000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 74 + 74, { { { 0x8008000000000ULL, 0x80020000000400ULL, 0x17e000100b080400ULL, 0x1a00400000001ULL, 0x2000602000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 73 + 82, { { { 0x6008008000000000ULL, 0x8002000000044eULL, 0x17e000100b080400ULL, 0x1a00400000001ULL, 0x2000602000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 72 + 90, { { { 0x6008008000000000ULL, 0x8002000000044eULL, 0x17e000100b080400ULL, 0x1a00400000001ULL, 0x2000602000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 71 + 98, { { { 0x8008000000000ULL, 0x480020000000400ULL, 0x17e000100b080400ULL, 0x1a00400000001ULL, 0x2000602000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 70 + 106, { { { 0x6008008000000000ULL, 0xe8000000000004eULL, 0x2e0000001000000ULL, 0x20000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 69 + 114, { { { 0x6008008000000000ULL, 0xe8000000000004eULL, 0x2e0000001000000ULL, 0x20000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 68 + 122, { { { 0x6008008000000000ULL, 0xe8000000000004eULL, 0x2e0000001000000ULL, 0x20000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 67 + 130, { { { 0x6008008000000000ULL, 0xe8000000000004eULL, 0x2e0000001000000ULL, 0x20000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 66 + 138, { { { 0x6008008000000000ULL, 0xe8000000000004eULL, 0x2e0000001000000ULL, 0x20000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 65 + 146, { { { 0x6008008000000000ULL, 0xe8000000000004eULL, 0x2e0000001000000ULL, 0x20000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 64 + 154, { { { 0x6008008000000000ULL, 0xe8000000000004eULL, 0x2e0000001000000ULL, 0x20000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 63 + 162, { { { 0x10c008060008000ULL, 0x50000002020001f8ULL, 0x42e640000100a000ULL, 0x20004001240028ULL, 0x8400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 62 + 178, { { { 0x40c008060008000ULL, 0x100000020000017aULL, 0x2e0400441008000ULL, 0x200000002c2028ULL, 0x10400c00ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 61 + 192, { { { 0x40c008060008010ULL, 0x100000020000017aULL, 0x2e0400441008000ULL, 0x20000000042028ULL, 0x10400c00ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 60 + 200, { { { 0x40c008060008010ULL, 0x100000020000017aULL, 0x2e0400441008000ULL, 0x20000000042028ULL, 0x10400800ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 59 + 208, { { { 0x40c008060008000ULL, 0x100000020000017aULL, 0x2e0400441008000ULL, 0x20000000042028ULL, 0x10400c00ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 58 + 216, { { { 0x40c008060008000ULL, 0x100000020000017aULL, 0x2e0400441008000ULL, 0x20000000042028ULL, 0x10400800ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 57 + 224, { { { 0x50c008060008000ULL, 0x100000020000017aULL, 0x2e0400001008000ULL, 0x200000010c0828ULL, 0x10400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 56 + 232, { { { 0x50c008060008010ULL, 0x100000020000017aULL, 0x2e0400001008000ULL, 0x200000010c0828ULL, 0x10400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 55 + 240, { { { 0x50c008060008000ULL, 0x100000020000017aULL, 0x2e0400001008000ULL, 0x200000010c0828ULL, 0x10400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 54 + 248, { { { 0x50c008060008000ULL, 0x100000020000017aULL, 0x2e0400001008000ULL, 0x200000010c0028ULL, 0x10400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 53 + 256, { { { 0x50c008060008000ULL, 0x100000020000017aULL, 0x2e0400001008000ULL, 0x200000010c0028ULL, 0x10400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 52 + 264, { { { 0x10c008060008000ULL, 0x50000002020001f8ULL, 0x42e640000100a000ULL, 0x20004001040028ULL, 0x8400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 51 + 272, { { { 0x10c008060008000ULL, 0x50000002020001f8ULL, 0x42e640000100a000ULL, 0x20004001040028ULL, 0x8400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 50 + 280, { { { 0x10c008060008000ULL, 0x50000002020001f8ULL, 0x42e640000100a000ULL, 0x20004001040028ULL, 0x8400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 49 + 288, { { { 0x10c8db9f95b914eULL, 0x8000280e0a001018ULL, 0x4009e2c025400890ULL, 0x6f5c410001f4c28aULL, 0x1260c18000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 48 + 304, { { { 0x10f50c1e1518410ULL, 0x80004002020801f8ULL, 0x42e041081100a000ULL, 0x50444001a58028ULL, 0x88400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 47 + 318, { { { 0x10f50c1e1518410ULL, 0x80004002020801f8ULL, 0x42e041081100a000ULL, 0x50444001858028ULL, 0x88400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 46 + 326, { { { 0x10f50c1e1518410ULL, 0x80004002020801f8ULL, 0x42e041081100a000ULL, 0x50444001858028ULL, 0x88400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 45 + 334, { { { 0x10fddb9f95b914eULL, 0x8000280e0a001018ULL, 0x40e9e2c035400880ULL, 0x6d5c45c001d5c28aULL, 0x1260c98000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 44 + 342, { { { 0x11fddb9f95b914eULL, 0x8000a80e0a001018ULL, 0x40e9e2c035400990ULL, 0x6d5445c001d5c29eULL, 0x1260c98080ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 43 + 350, { { { 0x10bd539f9538414ULL, 0x280a02100018ULL, 0x2e0000011002882ULL, 0x4c60450001a1c0a8ULL, 0x400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 42 + 364, { { { 0x10bd539f9538414ULL, 0x280a02100018ULL, 0x2e0000011002882ULL, 0x4c6045000181c0a8ULL, 0x400000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 41 + 372, { { { 0x0ULL, 0x80000000ULL, 0x1001000ULL, 0x80000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 8 },
   { sizeof(SubtargetSubTypeKV) * 40 + 379, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x80000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 39 + 386, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x80000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 38 + 393, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 37 + 400, { { { 0x0ULL, 0x80000000ULL, 0x1001000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 8 },
   { sizeof(SubtargetSubTypeKV) * 36 + 407, { { { 0x0ULL, 0x80000000ULL, 0x800000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 35 + 414, { { { 0x0ULL, 0x0ULL, 0x800000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 34 + 421, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 33 + 428, { { { 0x0ULL, 0x0ULL, 0x800000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 32 + 435, { { { 0x0ULL, 0x80000000ULL, 0x1001000ULL, 0x0ULL, 0x2002000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 31 + 442, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x200000000ULL, 0x2000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 30 + 449, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x0ULL, 0x2000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 29 + 456, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x200000000ULL, 0x2000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 28 + 463, { { { 0x0ULL, 0x0ULL, 0x814000ULL, 0x0ULL, 0x2002000000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 27 + 470, { { { 0xe0180081f910a400ULL, 0x20b0060000004fULL, 0x4000a1400028ULL, 0x110000000030040aULL, 0x8000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 9 },
   { sizeof(SubtargetSubTypeKV) * 26 + 485, { { { 0x400ULL, 0x24000000080400ULL, 0x100100c000ULL, 0x200000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 25 + 498, { { { 0x400ULL, 0x24000000080400ULL, 0x300100c000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 24 + 505, { { { 0x400ULL, 0x24000000080400ULL, 0x300100c000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 23 + 512, { { { 0x400ULL, 0x24100000080400ULL, 0x100100c000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 22 + 519, { { { 0x6008000000000400ULL, 0x24100000080448ULL, 0x100100d000ULL, 0x100000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 21 + 526, { { { 0xe008000020200400ULL, 0x2410000008044fULL, 0x118100d000ULL, 0x100000000000400ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 20 + 533, { { { 0x400ULL, 0x24000000080400ULL, 0x300100c000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 19 + 540, { { { 0xe018008078100400ULL, 0x20b0040000004fULL, 0x1081408008ULL, 0x110000000010040aULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 10 },
   { sizeof(SubtargetSubTypeKV) * 18 + 547, { { { 0x400ULL, 0x24000000080400ULL, 0x300100c000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 17 + 554, { { { 0xe0182081f910a400ULL, 0x20b0061200004fULL, 0x4000a1400028ULL, 0x110000000010040aULL, 0x800008000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 9 },
   { sizeof(SubtargetSubTypeKV) * 16 + 561, { { { 0xe018018df950a800ULL, 0x20b0061780034fULL, 0x4000a1400068ULL, 0x110000000010440aULL, 0x8000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 11 },
   { sizeof(SubtargetSubTypeKV) * 15 + 568, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x80000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 14 + 575, { { { 0x0ULL, 0x80000000ULL, 0x1001000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 8 },
   { sizeof(SubtargetSubTypeKV) * 13 + 582, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x200000000ULL, 0x2000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 12 + 590, { { { 0x0ULL, 0x0ULL, 0x800000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 11 + 597, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 10 + 604, { { { 0x0ULL, 0x0ULL, 0x800000ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 9 + 612, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x80000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 8 + 618, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x80000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 7 + 627, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x0ULL, 0x2000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 6 + 637, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x0ULL, 0x2000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 5 + 647, { { { 0x0ULL, 0x0ULL, 0x814000ULL, 0x0ULL, 0x2002000000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 4 + 654, { { { 0x0ULL, 0x80000000ULL, 0x1001000ULL, 0x80000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 8 },
   { sizeof(SubtargetSubTypeKV) * 3 + 661, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x200000000ULL, 0x2000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 2 + 667, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x200000000ULL, 0x2000040ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 1 + 676, { { { 0x0ULL, 0x0ULL, 0x1000000ULL, 0x80000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
  },
    "\000bonaire\000carrizo\000fiji\000generic\000generic-hsa\000gfx10-1-gen"
    "eric\000gfx10-3-generic\000gfx1010\000gfx1011\000gfx1012\000gfx1013\000"
    "gfx1030\000gfx1031\000gfx1032\000gfx1033\000gfx1034\000gfx1035\000gfx10"
    "36\000gfx11-7-generic\000gfx11-generic\000gfx1100\000gfx1101\000gfx1102"
    "\000gfx1103\000gfx1150\000gfx1151\000gfx1152\000gfx1153\000gfx1154\000g"
    "fx1170\000gfx1171\000gfx1172\000gfx12-5-generic\000gfx12-generic\000gfx"
    "1200\000gfx1201\000gfx1250\000gfx1251\000gfx13-generic\000gfx1310\000gf"
    "x600\000gfx601\000gfx602\000gfx700\000gfx701\000gfx702\000gfx703\000gfx"
    "704\000gfx705\000gfx801\000gfx802\000gfx803\000gfx805\000gfx810\000gfx9"
    "-4-generic\000gfx9-generic\000gfx900\000gfx902\000gfx904\000gfx906\000g"
    "fx908\000gfx909\000gfx90a\000gfx90c\000gfx942\000gfx950\000hainan\000ha"
    "waii\000iceland\000kabini\000kaveri\000mullins\000oland\000pitcairn\000"
    "polaris10\000polaris11\000stoney\000tahiti\000tonga\000tongapro\000verd"
    "e\000"};

namespace AMDGPU_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  switch (SchedClass) {
  case 35: // COPY
    if (CPUID == 1) { // SIQuarterSpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 2) { // GFX10SpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 3) { // GFX11SpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 4) { // GFX125xGenericSpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 5) { // GFX12SpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 6) { // GFX1250SpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 7) { // GFX1251SpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 8) { // SIFullSpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 9) { // SIDPGFX942FullSpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 10) { // SIDPFullSpeedModel
  return 78; // WriteSALU
    }
    if (CPUID == 11) { // SIDPGFX950FullSpeedModel
  return 78; // WriteSALU
    }
    break;
  case 36: // V_ACCVGPR_WRITE_B32_e64
    if (CPUID == 1) { // SIQuarterSpeedModel
  return 80; // Write64Bit_ReadDefault
    }
    break;
  case 39: // V_MFMA_F32_32X32X16_BF16_e64_V_MFMA_F32_32X32X16_BF16_mac_e64_V_MFMA_F32_32X32X16_BF16_mac_vgprcd_e64_V_MFMA_F32_32X32X16_BF16_vgprcd_e64_V_MFMA_F32_32X32X16_BF8_BF8_e64_V_MFMA_F32_32X32X16_BF8_BF8_mac_e64_V_MFMA_F32_32X32X16_BF8_BF8_mac_vgprcd_e64_V_MFMA_F32_32X32X16_BF8_BF8_vgprcd_e64_V_MFMA_F32_32X32X16_BF8_FP8_e64_V_MFMA_F32_32X32X16_BF8_FP8_mac_e64_V_MFMA_F32_32X32X16_BF8_FP8_mac_vgprcd_e64_V_MFMA_F32_32X32X16_BF8_FP8_vgprcd_e64_V_MFMA_F32_32X32X16_F16_e64_V_MFMA_F32_32X32X16_F16_mac_e64_V_MFMA_F32_32X32X16_F16_mac_vgprcd_e64_V_MFMA_F32_32X32X16_F16_vgprcd_e64_V_MFMA_F32_32X32X16_FP8_BF8_e64_V_MFMA_F32_32X32X16_FP8_BF8_mac_e64_V_MFMA_F32_32X32X16_FP8_BF8_mac_vgprcd_e64_V_MFMA_F32_32X32X16_FP8_BF8_vgprcd_e64_V_MFMA_F32_32X32X16_FP8_FP8_e64_V_MFMA_F32_32X32X16_FP8_FP8_mac_e64_V_MFMA_F32_32X32X16_FP8_FP8_mac_vgprcd_e64_V_MFMA_F32_32X32X16_FP8_FP8_vgprcd_e64_V_MFMA_F32_32X32X1F32_e64_V_MFMA_F32_32X32X1F32_mac_e64_V_MFMA_F32_32X32X1F32_mac_vgprcd_e64_V_MFMA_F32_32X32X1F32_vgprcd_e64_V_MFMA_F32_32X32X2BF16_e64_V_MFMA_F32_32X32X2BF16_mac_e64_V_MFMA_F32_32X32X2BF16_mac_vgprcd_e64_V_MFMA_F32_32X32X2BF16_vgprcd_e64_V_MFMA_F32_32X32X2F32_e64_V_MFMA_F32_32X32X2F32_mac_e64_V_MFMA_F32_32X32X2F32_mac_vgprcd_e64_V_MFMA_F32_32X32X2F32_vgprcd_e64_V_MFMA_F32_32X32X4BF16_1K_e64_V_MFMA_F32_32X32X4BF16_1K_mac_e64_V_MFMA_F32_32X32X4BF16_1K_mac_vgprcd_e64_V_MFMA_F32_32X32X4BF16_1K_vgprcd_e64_V_MFMA_F32_32X32X4BF16_e64_V_MFMA_F32_32X32X4BF16_mac_e64_V_MFMA_F32_32X32X4BF16_mac_vgprcd_e64_V_MFMA_F32_32X32X4BF16_vgprcd_e64_V_MFMA_F32_32X32X4F16_e64_V_MFMA_F32_32X32X4F16_mac_e64_V_MFMA_F32_32X32X4F16_mac_vgprcd_e64_V_MFMA_F32_32X32X4F16_vgprcd_e64_V_MFMA_F32_32X32X4XF32_e64_V_MFMA_F32_32X32X4XF32_mac_e64_V_MFMA_F32_32X32X4XF32_mac_vgprcd_e64_V_MFMA_F32_32X32X4XF32_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_vgprcd_e64_V_MFMA_F32_32X32X8BF16_1K_e64_V_MFMA_F32_32X32X8BF16_1K_mac_e64_V_MFMA_F32_32X32X8BF16_1K_mac_vgprcd_e64_V_MFMA_F32_32X32X8BF16_1K_vgprcd_e64_V_MFMA_F32_32X32X8F16_e64_V_MFMA_F32_32X32X8F16_mac_e64_V_MFMA_F32_32X32X8F16_mac_vgprcd_e64_V_MFMA_F32_32X32X8F16_vgprcd_e64_V_MFMA_I32_32X32X16I8_e64_V_MFMA_I32_32X32X16I8_mac_e64_V_MFMA_I32_32X32X16I8_mac_vgprcd_e64_V_MFMA_I32_32X32X16I8_vgprcd_e64_V_MFMA_I32_32X32X32_I8_e64_V_MFMA_I32_32X32X32_I8_mac_e64_V_MFMA_I32_32X32X32_I8_mac_vgprcd_e64_V_MFMA_I32_32X32X32_I8_vgprcd_e64_V_MFMA_I32_32X32X4I8_e64_V_MFMA_I32_32X32X4I8_mac_e64_V_MFMA_I32_32X32X4I8_mac_vgprcd_e64_V_MFMA_I32_32X32X4I8_vgprcd_e64_V_MFMA_I32_32X32X8I8_e64_V_MFMA_I32_32X32X8I8_mac_e64_V_MFMA_I32_32X32X8I8_mac_vgprcd_e64_V_MFMA_I32_32X32X8I8_vgprcd_e64_V_MFMA_F32_32X32X16_BF16_gfx940_acd_V_MFMA_F32_32X32X16_BF16_gfx940_vcd_V_MFMA_F32_32X32X16_BF8_BF8_gfx940_acd_V_MFMA_F32_32X32X16_BF8_BF8_gfx940_vcd_V_MFMA_F32_32X32X16_BF8_FP8_gfx940_acd_V_MFMA_F32_32X32X16_BF8_FP8_gfx940_vcd_V_MFMA_F32_32X32X16_F16_gfx940_acd_V_MFMA_F32_32X32X16_F16_gfx940_vcd_V_MFMA_F32_32X32X16_FP8_BF8_gfx940_acd_V_MFMA_F32_32X32X16_FP8_BF8_gfx940_vcd_V_MFMA_F32_32X32X16_FP8_FP8_gfx940_acd_V_MFMA_F32_32X32X16_FP8_FP8_gfx940_vcd_V_MFMA_F32_32X32X1F32_gfx90a_acd_V_MFMA_F32_32X32X1F32_gfx90a_vcd_V_MFMA_F32_32X32X1F32_gfx940_acd_V_MFMA_F32_32X32X1F32_gfx940_vcd_V_MFMA_F32_32X32X1F32_vi_V_MFMA_F32_32X32X2BF16_gfx90a_acd_V_MFMA_F32_32X32X2BF16_gfx90a_vcd_V_MFMA_F32_32X32X2BF16_vi_V_MFMA_F32_32X32X2F32_gfx90a_acd_V_MFMA_F32_32X32X2F32_gfx90a_vcd_V_MFMA_F32_32X32X2F32_gfx940_acd_V_MFMA_F32_32X32X2F32_gfx940_vcd_V_MFMA_F32_32X32X2F32_vi_V_MFMA_F32_32X32X4BF16_1K_gfx90a_acd_V_MFMA_F32_32X32X4BF16_1K_gfx90a_vcd_V_MFMA_F32_32X32X4BF16_1K_gfx940_acd_V_MFMA_F32_32X32X4BF16_1K_gfx940_vcd_V_MFMA_F32_32X32X4BF16_gfx90a_acd_V_MFMA_F32_32X32X4BF16_gfx90a_vcd_V_MFMA_F32_32X32X4BF16_vi_V_MFMA_F32_32X32X4F16_gfx90a_acd_V_MFMA_F32_32X32X4F16_gfx90a_vcd_V_MFMA_F32_32X32X4F16_gfx940_acd_V_MFMA_F32_32X32X4F16_gfx940_vcd_V_MFMA_F32_32X32X4F16_vi_V_MFMA_F32_32X32X4XF32_gfx940_acd_V_MFMA_F32_32X32X4XF32_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_gfx940_vcd_V_MFMA_F32_32X32X8BF16_1K_gfx90a_acd_V_MFMA_F32_32X32X8BF16_1K_gfx90a_vcd_V_MFMA_F32_32X32X8BF16_1K_gfx940_acd_V_MFMA_F32_32X32X8BF16_1K_gfx940_vcd_V_MFMA_F32_32X32X8F16_gfx90a_acd_V_MFMA_F32_32X32X8F16_gfx90a_vcd_V_MFMA_F32_32X32X8F16_gfx940_acd_V_MFMA_F32_32X32X8F16_gfx940_vcd_V_MFMA_F32_32X32X8F16_vi_V_MFMA_I32_32X32X16I8_gfx940_acd_V_MFMA_I32_32X32X16I8_gfx940_vcd_V_MFMA_I32_32X32X32_I8_gfx940_acd_V_MFMA_I32_32X32X32_I8_gfx940_vcd_V_MFMA_I32_32X32X4I8_gfx90a_acd_V_MFMA_I32_32X32X4I8_gfx90a_vcd_V_MFMA_I32_32X32X4I8_gfx940_acd_V_MFMA_I32_32X32X4I8_gfx940_vcd_V_MFMA_I32_32X32X4I8_vi_V_MFMA_I32_32X32X8I8_gfx90a_acd_V_MFMA_I32_32X32X8I8_gfx90a_vcd_V_MFMA_I32_32X32X8I8_vi
    if (CPUID == 11) { // SIDPGFX950FullSpeedModel
  return 82; // Write8PassMAI_MIMFMARead
    }
    break;
  case 54: // V_MFMA_F32_16X16X128_F8F6F4_f4_f4_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f4_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f6_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f6_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f8_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f8_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f4_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f4_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f6_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f6_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f8_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f8_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f4_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f4_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f6_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f6_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f8_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f8_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f4_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f4_f4_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f4_f6_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f4_f6_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f4_f8_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f4_f8_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f6_f4_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f6_f4_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f6_f6_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f6_f6_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f6_f8_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f6_f8_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f8_f4_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f8_f4_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f8_f6_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f8_f6_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f8_f8_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f8_f8_gfx940_vcd
    if (CPUID == 11) { // SIDPGFX950FullSpeedModel
  return 83; // Write4PassMAI_MIMFMARead
    }
    break;
  case 55: // V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_gfx940_vcd
    if (CPUID == 11) { // SIDPGFX950FullSpeedModel
  return 83; // Write4PassMAI_MIMFMARead
    }
    break;
  case 56: // V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_gfx940_vcd
    if (CPUID == 11) { // SIDPGFX950FullSpeedModel
  return 82; // Write8PassMAI_MIMFMARead
    }
    break;
  case 63: // V_WMMA_F32_16X16X128_F8F6F4_f4_f4_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f6_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f8_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f4_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f6_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f8_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f4_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f6_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f8_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f4_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f6_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f8_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f4_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f6_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f8_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f4_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f6_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f8_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_w32_threeaddr
    if (CPUID == 4) { // GFX125xGenericSpeedModel
  return 86; // WriteXDL8PassWMMA
    }
    if (CPUID == 6) { // GFX1250SpeedModel
  return 85; // WriteXDL2PassWMMA
    }
    if (CPUID == 7) { // GFX1251SpeedModel
  return 86; // WriteXDL8PassWMMA
    }
    break;
  case 64: // V_WMMA_F32_16X16X128_F8F6F4_f4_f4_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f6_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f8_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f4_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f6_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f8_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f4_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f6_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f8_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f4_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f6_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f8_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f4_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f6_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f8_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f4_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f6_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f8_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f4_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f4_f6_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f4_f8_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f6_f4_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f6_f6_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f6_f8_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f8_f4_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f8_f6_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f8_f8_w32_twoaddr_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f4_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f6_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f8_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f4_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f6_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f8_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f4_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f6_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f8_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_w32_gfx1250
    if (CPUID == 4) { // GFX125xGenericSpeedModel
  return 86; // WriteXDL8PassWMMA
    }
    if (CPUID == 6) { // GFX1250SpeedModel
  return 85; // WriteXDL2PassWMMA
    }
    if (CPUID == 7) { // GFX1251SpeedModel
  return 86; // WriteXDL8PassWMMA
    }
    break;
  };
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace AMDGPU_MC
struct AMDGPUGenMCSubtargetInfo : public MCSubtargetInfo {
  AMDGPUGenMCSubtargetInfo(const Triple &TT,
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
    return AMDGPU_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned AMDGPUGenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (FB[AMDGPU::FeatureMAIInsts] && FB[AMDGPU::FeatureRequiresAlignedVGPRs]) Modes |= (1 << 0);
  if (!FB[AMDGPU::FeatureMAIInsts] && FB[AMDGPU::FeatureRequiresAlignedVGPRs] && FB[AMDGPU::FeatureWavefrontSize32]) Modes |= (1 << 1);
  if (!FB[AMDGPU::FeatureMAIInsts] && FB[AMDGPU::FeatureRequiresAlignedVGPRs] && FB[AMDGPU::FeatureWavefrontSize64]) Modes |= (1 << 2);
  if ((FB[AMDGPU::FeatureWavefrontSize32] || FB[AMDGPU::FeatureAssemblerPermissiveWavesize]) && !FB[AMDGPU::FeatureRequiresAlignedVGPRs]) Modes |= (1 << 3);
  return Modes;
}
unsigned AMDGPUGenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    Modes &= 15;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for ValueType were found!");
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_RegInfo:
    Modes &= 15;
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

static inline MCSubtargetInfo *createAMDGPUMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new AMDGPUGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(AMDGPUSubTypeKVStorage.Strings), AMDGPUFeatureKVStorage.Features, AMDGPUSubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::AMDGPUSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[AMDGPU::Feature16BitInsts]) Has16BitInsts = true;
  if (Bits[AMDGPU::Feature45BitNumRecordsBufferResource]) Has45BitNumRecordsBufferResource = true;
  if (Bits[AMDGPU::Feature64BitLiterals]) Has64BitLiterals = true;
  if (Bits[AMDGPU::Feature1024AddressableVGPRs]) Has1024AddressableVGPRs = true;
  if (Bits[AMDGPU::Feature1536VGPRs]) Has1536VGPRs = true;
  if (Bits[AMDGPU::FeatureA16]) HasA16 = true;
  if (Bits[AMDGPU::FeatureAddMinMaxInsts]) HasAddMinMaxInsts = true;
  if (Bits[AMDGPU::FeatureAddNoCarryInsts]) HasAddNoCarryInsts = true;
  if (Bits[AMDGPU::FeatureAddSubU64Insts]) HasAddSubU64Insts = true;
  if (Bits[AMDGPU::FeatureAddressableLocalMemorySize32768] && AddressableLocalMemorySize < 32768) AddressableLocalMemorySize = 32768;
  if (Bits[AMDGPU::FeatureAddressableLocalMemorySize65536] && AddressableLocalMemorySize < 65536) AddressableLocalMemorySize = 65536;
  if (Bits[AMDGPU::FeatureAddressableLocalMemorySize163840] && AddressableLocalMemorySize < 163840) AddressableLocalMemorySize = 163840;
  if (Bits[AMDGPU::FeatureAddressableLocalMemorySize327680] && AddressableLocalMemorySize < 327680) AddressableLocalMemorySize = 327680;
  if (Bits[AMDGPU::FeatureAgentScopeFineGrainedRemoteMemoryAtomics]) HasAgentScopeFineGrainedRemoteMemoryAtomics = true;
  if (Bits[AMDGPU::FeatureApertureRegs]) HasApertureRegs = true;
  if (Bits[AMDGPU::FeatureArchitectedFlatScratch]) HasArchitectedFlatScratch = true;
  if (Bits[AMDGPU::FeatureArchitectedSGPRs]) HasArchitectedSGPRs = true;
  if (Bits[AMDGPU::FeatureAshrPkInsts]) HasAshrPkInsts = true;
  if (Bits[AMDGPU::FeatureAssemblerPermissiveWavesize]) HasAssemblerPermissiveWavesize = true;
  if (Bits[AMDGPU::FeatureAsynccnt]) HasAsynccnt = true;
  if (Bits[AMDGPU::FeatureAtomicBufferGlobalPkAddF16Insts]) HasAtomicBufferGlobalPkAddF16Insts = true;
  if (Bits[AMDGPU::FeatureAtomicBufferGlobalPkAddF16NoRtnInsts]) HasAtomicBufferGlobalPkAddF16NoRtnInsts = true;
  if (Bits[AMDGPU::FeatureAtomicBufferPkAddBF16Inst]) HasAtomicBufferPkAddBF16Inst = true;
  if (Bits[AMDGPU::FeatureAtomicCSubNoRtnInsts]) HasAtomicCSubNoRtnInsts = true;
  if (Bits[AMDGPU::FeatureAtomicDsPkAdd16Insts]) HasAtomicDsPkAdd16Insts = true;
  if (Bits[AMDGPU::FeatureAtomicFMinFMaxF32FlatInsts]) HasAtomicFMinFMaxF32FlatInsts = true;
  if (Bits[AMDGPU::FeatureAtomicFMinFMaxF32GlobalInsts]) HasAtomicFMinFMaxF32GlobalInsts = true;
  if (Bits[AMDGPU::FeatureAtomicFMinFMaxF64FlatInsts]) HasAtomicFMinFMaxF64FlatInsts = true;
  if (Bits[AMDGPU::FeatureAtomicFMinFMaxF64GlobalInsts]) HasAtomicFMinFMaxF64GlobalInsts = true;
  if (Bits[AMDGPU::FeatureAtomicFaddNoRtnInsts]) HasAtomicFaddNoRtnInsts = true;
  if (Bits[AMDGPU::FeatureAtomicFaddRtnInsts]) HasAtomicFaddRtnInsts = true;
  if (Bits[AMDGPU::FeatureAtomicFlatPkAdd16Insts]) HasAtomicFlatPkAdd16Insts = true;
  if (Bits[AMDGPU::FeatureAtomicGlobalPkAddBF16Inst]) HasAtomicGlobalPkAddBF16Inst = true;
  if (Bits[AMDGPU::FeatureAutoWaitcntBeforeBarrier]) HasAutoWaitcntBeforeBarrier = true;
  if (Bits[AMDGPU::FeatureBF8ConversionScaleInsts]) HasBF8ConversionScaleInsts = true;
  if (Bits[AMDGPU::FeatureBF16ConversionInsts]) HasBF16ConversionInsts = true;
  if (Bits[AMDGPU::FeatureBF16PackedInsts]) HasBF16PackedInsts = true;
  if (Bits[AMDGPU::FeatureBF16TransInsts]) HasBF16TransInsts = true;
  if (Bits[AMDGPU::FeatureBVHDualAndBVH8Insts]) HasBVHDualAndBVH8Insts = true;
  if (Bits[AMDGPU::FeatureBackOffBarrier]) HasBackOffBarrier = true;
  if (Bits[AMDGPU::FeatureBitOp3Insts]) HasBitOp3Insts = true;
  if (Bits[AMDGPU::FeatureCIInsts]) HasCIInsts = true;
  if (Bits[AMDGPU::FeatureClusters]) HasClusters = true;
  if (Bits[AMDGPU::FeatureCuMode]) EnableCuMode = true;
  if (Bits[AMDGPU::FeatureCubeInsts]) HasCubeInsts = true;
  if (Bits[AMDGPU::FeatureCvtFP8VOP1Bug]) HasCvtFP8VOP1Bug = true;
  if (Bits[AMDGPU::FeatureCvtNormInsts]) HasCvtNormInsts = true;
  if (Bits[AMDGPU::FeatureCvtPkF16F32Inst]) HasCvtPkF16F32Inst = true;
  if (Bits[AMDGPU::FeatureCvtPkNormVOP2Insts]) HasCvtPkNormVOP2Insts = true;
  if (Bits[AMDGPU::FeatureCvtPkNormVOP3Insts]) HasCvtPkNormVOP3Insts = true;
  if (Bits[AMDGPU::FeatureD16Writes32BitVgpr]) HasD16Writes32BitVgpr = true;
  if (Bits[AMDGPU::FeatureDLInsts]) HasDLInsts = true;
  if (Bits[AMDGPU::FeatureDPALU_DPP]) HasDPALU_DPP = true;
  if (Bits[AMDGPU::FeatureDPP]) HasDPP = true;
  if (Bits[AMDGPU::FeatureDPP8]) HasDPP8 = true;
  if (Bits[AMDGPU::FeatureDPPBroadcasts]) HasDPPBroadcasts = true;
  if (Bits[AMDGPU::FeatureDPPSrc1SGPR]) HasDPPSrc1SGPR = true;
  if (Bits[AMDGPU::FeatureDPPWavefrontShifts]) HasDPPWavefrontShifts = true;
  if (Bits[AMDGPU::FeatureDX10ClampAndIEEEMode]) HasDX10ClampAndIEEEMode = true;
  if (Bits[AMDGPU::FeatureDefaultComponentBroadcast]) HasDefaultComponentBroadcast = true;
  if (Bits[AMDGPU::FeatureDefaultComponentZero]) HasDefaultComponentZero = true;
  if (Bits[AMDGPU::FeatureDot1Insts]) HasDot1Insts = true;
  if (Bits[AMDGPU::FeatureDot2Insts]) HasDot2Insts = true;
  if (Bits[AMDGPU::FeatureDot3Insts]) HasDot3Insts = true;
  if (Bits[AMDGPU::FeatureDot4Insts]) HasDot4Insts = true;
  if (Bits[AMDGPU::FeatureDot5Insts]) HasDot5Insts = true;
  if (Bits[AMDGPU::FeatureDot6Insts]) HasDot6Insts = true;
  if (Bits[AMDGPU::FeatureDot7Insts]) HasDot7Insts = true;
  if (Bits[AMDGPU::FeatureDot8Insts]) HasDot8Insts = true;
  if (Bits[AMDGPU::FeatureDot9Insts]) HasDot9Insts = true;
  if (Bits[AMDGPU::FeatureDot10Insts]) HasDot10Insts = true;
  if (Bits[AMDGPU::FeatureDot11Insts]) HasDot11Insts = true;
  if (Bits[AMDGPU::FeatureDot12Insts]) HasDot12Insts = true;
  if (Bits[AMDGPU::FeatureDot13Insts]) HasDot13Insts = true;
  if (Bits[AMDGPU::FeatureDsSrc2Insts]) HasDsSrc2Insts = true;
  if (Bits[AMDGPU::FeatureDumpCodeLower]) DumpCode = true;
  if (Bits[AMDGPU::FeatureEmulatedSystemScopeAtomics]) HasEmulatedSystemScopeAtomics = true;
  if (Bits[AMDGPU::FeatureEnableDS128]) EnableDS128 = true;
  if (Bits[AMDGPU::FeatureEnableFlatScratch]) EnableFlatScratch = true;
  if (Bits[AMDGPU::FeatureEnableLoadStoreOpt]) EnableLoadStoreOpt = true;
  if (Bits[AMDGPU::FeatureEnablePRTStrictNull]) EnablePRTStrictNull = true;
  if (Bits[AMDGPU::FeatureEnableSIScheduler]) EnableSIScheduler = true;
  if (Bits[AMDGPU::FeatureEnableUnsafeDSOffsetFolding]) EnableUnsafeDSOffsetFolding = true;
  if (Bits[AMDGPU::FeatureExtendedImageInsts]) HasExtendedImageInsts = true;
  if (Bits[AMDGPU::FeatureF16BF16ToFP6BF6ConversionScaleInsts]) HasF16BF16ToFP6BF6ConversionScaleInsts = true;
  if (Bits[AMDGPU::FeatureF32ToF16BF16ConversionSRInsts]) HasF32ToF16BF16ConversionSRInsts = true;
  if (Bits[AMDGPU::FeatureFMA]) HasFMA = true;
  if (Bits[AMDGPU::FeatureFP4ConversionScaleInsts]) HasFP4ConversionScaleInsts = true;
  if (Bits[AMDGPU::FeatureFP6BF6ConversionScaleInsts]) HasFP6BF6ConversionScaleInsts = true;
  if (Bits[AMDGPU::FeatureFP8ConversionInsts]) HasFP8ConversionInsts = true;
  if (Bits[AMDGPU::FeatureFP8ConversionScaleInsts]) HasFP8ConversionScaleInsts = true;
  if (Bits[AMDGPU::FeatureFP8E5M3Insts]) HasFP8E5M3Insts = true;
  if (Bits[AMDGPU::FeatureFP8Insts]) HasFP8Insts = true;
  if (Bits[AMDGPU::FeatureFP64]) HasFP64 = true;
  if (Bits[AMDGPU::FeatureFastDenormalF32]) HasFastDenormalF32 = true;
  if (Bits[AMDGPU::FeatureFastFMAF32]) HasFastFMAF32 = true;
  if (Bits[AMDGPU::FeatureFlatAddressSpace]) HasFlatAddressSpace = true;
  if (Bits[AMDGPU::FeatureFlatAtomicFaddF32Inst]) HasFlatAtomicFaddF32Inst = true;
  if (Bits[AMDGPU::FeatureFlatBufferGlobalAtomicFaddF64Inst]) HasFlatBufferGlobalAtomicFaddF64Inst = true;
  if (Bits[AMDGPU::FeatureFlatGVSMode]) HasFlatGVSMode = true;
  if (Bits[AMDGPU::FeatureFlatGlobalInsts]) HasFlatGlobalInsts = true;
  if (Bits[AMDGPU::FeatureFlatInstOffsets]) HasFlatInstOffsets = true;
  if (Bits[AMDGPU::FeatureFlatOffsetBits12] && FlatOffsetBitWidth < 12) FlatOffsetBitWidth = 12;
  if (Bits[AMDGPU::FeatureFlatOffsetBits24] && FlatOffsetBitWidth < 24) FlatOffsetBitWidth = 24;
  if (Bits[AMDGPU::FeatureFlatScratchInsts]) HasFlatScratchInsts = true;
  if (Bits[AMDGPU::FeatureFlatSegmentOffsetBug]) HasFlatSegmentOffsetBug = true;
  if (Bits[AMDGPU::FeatureFlatSignedOffset]) HasFlatSignedOffset = true;
  if (Bits[AMDGPU::FeatureFmaMixBF16Insts]) HasFmaMixBF16Insts = true;
  if (Bits[AMDGPU::FeatureFmaMixInsts]) HasFmaMixInsts = true;
  if (Bits[AMDGPU::FeatureFmacF64Inst]) HasFmacF64Inst = true;
  if (Bits[AMDGPU::FeatureFormattedMUBUFInsts]) HasFormattedMUBUFInsts = true;
  if (Bits[AMDGPU::FeatureFullRate64Ops]) HasFullRate64Ops = true;
  if (Bits[AMDGPU::FeatureG16]) HasG16 = true;
  if (Bits[AMDGPU::FeatureGCN3Encoding]) HasGCN3Encoding = true;
  if (Bits[AMDGPU::FeatureGDS]) HasGDS = true;
  if (Bits[AMDGPU::FeatureGFX7GFX8GFX9Insts]) HasGFX7GFX8GFX9Insts = true;
  if (Bits[AMDGPU::FeatureGFX8Insts]) HasGFX8Insts = true;
  if (Bits[AMDGPU::FeatureGFX9] && Gen < GCNSubtarget::GFX9) Gen = GCNSubtarget::GFX9;
  if (Bits[AMDGPU::FeatureGFX9Insts]) HasGFX9Insts = true;
  if (Bits[AMDGPU::FeatureGFX10] && Gen < GCNSubtarget::GFX10) Gen = GCNSubtarget::GFX10;
  if (Bits[AMDGPU::FeatureGFX10Insts]) HasGFX10Insts = true;
  if (Bits[AMDGPU::FeatureGFX10_3Insts]) HasGFX10_3Insts = true;
  if (Bits[AMDGPU::FeatureGFX10_AEncoding]) HasGFX10_AEncoding = true;
  if (Bits[AMDGPU::FeatureGFX10_BEncoding]) HasGFX10_BEncoding = true;
  if (Bits[AMDGPU::FeatureGFX11] && Gen < GCNSubtarget::GFX11) Gen = GCNSubtarget::GFX11;
  if (Bits[AMDGPU::FeatureGFX11Insts]) HasGFX11Insts = true;
  if (Bits[AMDGPU::FeatureGFX11_7Insts]) HasGFX11_7Insts = true;
  if (Bits[AMDGPU::FeatureGFX12] && Gen < GCNSubtarget::GFX12) Gen = GCNSubtarget::GFX12;
  if (Bits[AMDGPU::FeatureGFX12Insts]) HasGFX12Insts = true;
  if (Bits[AMDGPU::FeatureGFX13] && Gen < GCNSubtarget::GFX13) Gen = GCNSubtarget::GFX13;
  if (Bits[AMDGPU::FeatureGFX13Insts]) HasGFX13Insts = true;
  if (Bits[AMDGPU::FeatureGFX90AInsts]) HasGFX90AInsts = true;
  if (Bits[AMDGPU::FeatureGFX125xLowestRateWMMA]) HasGFX125xLowestRateWMMA = true;
  if (Bits[AMDGPU::FeatureGFX940Insts]) HasGFX940Insts = true;
  if (Bits[AMDGPU::FeatureGFX950Insts]) HasGFX950Insts = true;
  if (Bits[AMDGPU::FeatureGFX1250Insts]) HasGFX1250Insts = true;
  if (Bits[AMDGPU::FeatureGFX1251GEMMInsts]) HasGFX1251GEMMInsts = true;
  if (Bits[AMDGPU::FeatureGWS]) HasGWS = true;
  if (Bits[AMDGPU::FeatureGetWaveIdInst]) HasGetWaveIdInst = true;
  if (Bits[AMDGPU::FeatureGloballyAddressableScratch]) HasGloballyAddressableScratch = true;
  if (Bits[AMDGPU::FeatureHalfRate64Ops]) HasHalfRate64Ops = true;
  if (Bits[AMDGPU::FeatureIEEEMinimumMaximumInsts]) HasIEEEMinimumMaximumInsts = true;
  if (Bits[AMDGPU::FeatureImageGather4D16Bug]) HasImageGather4D16Bug = true;
  if (Bits[AMDGPU::FeatureImageInsts]) HasImageInsts = true;
  if (Bits[AMDGPU::FeatureImageStoreD16Bug]) HasImageStoreD16Bug = true;
  if (Bits[AMDGPU::FeatureInstCacheLineSize64] && InstCacheLineSize < 64) InstCacheLineSize = 64;
  if (Bits[AMDGPU::FeatureInstCacheLineSize128] && InstCacheLineSize < 128) InstCacheLineSize = 128;
  if (Bits[AMDGPU::FeatureInstFwdPrefetchBug]) HasInstFwdPrefetchBug = true;
  if (Bits[AMDGPU::FeatureIntClamp]) HasIntClamp = true;
  if (Bits[AMDGPU::FeatureInv2PiInlineImm]) HasInv2PiInlineImm = true;
  if (Bits[AMDGPU::FeatureKernargPreload]) HasKernargPreload = true;
  if (Bits[AMDGPU::FeatureLDSBankCount16] && LDSBankCount < 16) LDSBankCount = 16;
  if (Bits[AMDGPU::FeatureLDSBankCount32] && LDSBankCount < 32) LDSBankCount = 32;
  if (Bits[AMDGPU::FeatureLDSMisalignedBug]) HasLDSMisalignedBug = true;
  if (Bits[AMDGPU::FeatureLdsBarrierArriveAtomic]) HasLdsBarrierArriveAtomic = true;
  if (Bits[AMDGPU::FeatureLdsBranchVmemWARHazard]) HasLdsBranchVmemWARHazard = true;
  if (Bits[AMDGPU::FeatureLerpInst]) HasLerpInst = true;
  if (Bits[AMDGPU::FeatureLshlAddU64Inst]) HasLshlAddU64Inst = true;
  if (Bits[AMDGPU::FeatureMADIntraFwdBug]) HasMADIntraFwdBug = true;
  if (Bits[AMDGPU::FeatureMAIInsts]) HasMAIInsts = true;
  if (Bits[AMDGPU::FeatureMFMAInlineLiteralBug]) HasMFMAInlineLiteralBug = true;
  if (Bits[AMDGPU::FeatureMIMG_R128]) HasMIMG_R128 = true;
  if (Bits[AMDGPU::FeatureMSAALoadDstSelBug]) HasMSAALoadDstSelBug = true;
  if (Bits[AMDGPU::FeatureMTBUFInsts]) HasMTBUFInsts = true;
  if (Bits[AMDGPU::FeatureMadMacF32Insts]) HasMadMacF32Insts = true;
  if (Bits[AMDGPU::FeatureMadMixInsts]) HasMadMixInsts = true;
  if (Bits[AMDGPU::FeatureMadNC64_32Insts]) HasMadNC64_32Insts = true;
  if (Bits[AMDGPU::FeatureMadU32Inst]) HasMadU32Inst = true;
  if (Bits[AMDGPU::FeatureMaxHardClauseLength32] && MaxHardClauseLength < 32) MaxHardClauseLength = 32;
  if (Bits[AMDGPU::FeatureMaxHardClauseLength63] && MaxHardClauseLength < 63) MaxHardClauseLength = 63;
  if (Bits[AMDGPU::FeatureMaxPrivateElementSize4] && MaxPrivateElementSize < 4) MaxPrivateElementSize = 4;
  if (Bits[AMDGPU::FeatureMaxPrivateElementSize8] && MaxPrivateElementSize < 8) MaxPrivateElementSize = 8;
  if (Bits[AMDGPU::FeatureMaxPrivateElementSize16] && MaxPrivateElementSize < 16) MaxPrivateElementSize = 16;
  if (Bits[AMDGPU::FeatureMcastLoadInsts]) HasMcastLoadInsts = true;
  if (Bits[AMDGPU::FeatureMemoryAtomicFAddF32DenormalSupport]) HasMemoryAtomicFaddF32DenormalSupport = true;
  if (Bits[AMDGPU::FeatureMin3Max3PKF16]) HasMin3Max3PKF16 = true;
  if (Bits[AMDGPU::FeatureMinMaxI64Insts]) HasMinMaxI64Insts = true;
  if (Bits[AMDGPU::FeatureMinimum3Maximum3F16]) HasMinimum3Maximum3F16 = true;
  if (Bits[AMDGPU::FeatureMinimum3Maximum3F32]) HasMinimum3Maximum3F32 = true;
  if (Bits[AMDGPU::FeatureMinimum3Maximum3PKF16]) HasMinimum3Maximum3PKF16 = true;
  if (Bits[AMDGPU::FeatureMovrel]) HasMovrel = true;
  if (Bits[AMDGPU::FeatureMqsadInsts]) HasMqsadInsts = true;
  if (Bits[AMDGPU::FeatureMqsadPkInsts]) HasMqsadPkInsts = true;
  if (Bits[AMDGPU::FeatureMsadInsts]) HasMsadInsts = true;
  if (Bits[AMDGPU::FeatureNSAClauseBug]) HasNSAClauseBug = true;
  if (Bits[AMDGPU::FeatureNSAEncoding]) HasNSAEncoding = true;
  if (Bits[AMDGPU::FeatureNSAtoVMEMBug]) HasNSAtoVMEMBug = true;
  if (Bits[AMDGPU::FeatureNegativeScratchOffsetBug]) HasNegativeScratchOffsetBug = true;
  if (Bits[AMDGPU::FeatureNegativeUnalignedScratchOffsetBug]) HasNegativeUnalignedScratchOffsetBug = true;
  if (Bits[AMDGPU::FeatureNoDataDepHazard]) HasNoDataDepHazard = true;
  if (Bits[AMDGPU::FeatureNoF16PseudoScalarTransInlineConstants]) HasNoF16PseudoScalarTransInlineConstants = true;
  if (Bits[AMDGPU::FeatureNoSdstCMPX]) HasNoSdstCMPX = true;
  if (Bits[AMDGPU::FeatureOffset3fBug]) HasOffset3fBug = true;
  if (Bits[AMDGPU::FeaturePackedFP32Ops]) HasPackedFP32Ops = true;
  if (Bits[AMDGPU::FeaturePackedFP64Ops]) HasPackedFP64Ops = true;
  if (Bits[AMDGPU::FeaturePackedTID]) HasPackedTID = true;
  if (Bits[AMDGPU::FeaturePackedU64Ops]) HasPackedU64Ops = true;
  if (Bits[AMDGPU::FeaturePartialNSAEncoding]) HasPartialNSAEncoding = true;
  if (Bits[AMDGPU::FeaturePermlane16Insts]) HasPermlane16Insts = true;
  if (Bits[AMDGPU::FeaturePermlane16Swap]) HasPermlane16Swap = true;
  if (Bits[AMDGPU::FeaturePermlane32Swap]) HasPermlane32Swap = true;
  if (Bits[AMDGPU::FeaturePkAddMinMaxInsts]) HasPkAddMinMaxInsts = true;
  if (Bits[AMDGPU::FeaturePkFmacF16Inst]) HasPkFmacF16Inst = true;
  if (Bits[AMDGPU::FeaturePointSampleAccel]) HasPointSampleAccel = true;
  if (Bits[AMDGPU::FeaturePreciseMemory]) EnablePreciseMemory = true;
  if (Bits[AMDGPU::FeaturePrivEnabledTrap2NopBug]) HasPrivEnabledTrap2NopBug = true;
  if (Bits[AMDGPU::FeaturePrngInst]) HasPrngInst = true;
  if (Bits[AMDGPU::FeaturePseudoScalarTrans]) HasPseudoScalarTrans = true;
  if (Bits[AMDGPU::FeatureQsadInsts]) HasQsadInsts = true;
  if (Bits[AMDGPU::FeatureR128A16]) HasR128A16 = true;
  if (Bits[AMDGPU::FeatureRealTrue16Insts]) EnableRealTrue16Insts = true;
  if (Bits[AMDGPU::FeatureRequiredExportPriority]) HasRequiredExportPriority = true;
  if (Bits[AMDGPU::FeatureRequiresAlignedVGPRs]) RequiresAlignVGPR = true;
  if (Bits[AMDGPU::FeatureRequiresCOV6]) RequiresCOV6 = true;
  if (Bits[AMDGPU::FeatureRequiresInitialUnclausedVmem]) HasRequiresInitialUnclausedVmem = true;
  if (Bits[AMDGPU::FeatureRestrictedSOffset]) HasRestrictedSOffset = true;
  if (Bits[AMDGPU::FeatureSALUFloatInsts]) HasSALUFloatInsts = true;
  if (Bits[AMDGPU::FeatureSALUMinimumMaximumInsts]) HasSALUMinimumMaximumInsts = true;
  if (Bits[AMDGPU::FeatureSBarrierLeaveImm]) HasSBarrierLeaveImm = true;
  if (Bits[AMDGPU::FeatureSDWA]) HasSDWA = true;
  if (Bits[AMDGPU::FeatureSDWAMac]) HasSDWAMac = true;
  if (Bits[AMDGPU::FeatureSDWAOmod]) HasSDWAOmod = true;
  if (Bits[AMDGPU::FeatureSDWAOutModsVOPC]) HasSDWAOutModsVOPC = true;
  if (Bits[AMDGPU::FeatureSDWAScalar]) HasSDWAScalar = true;
  if (Bits[AMDGPU::FeatureSDWASdst]) HasSDWASdst = true;
  if (Bits[AMDGPU::FeatureSGPRInitBug]) HasSGPRInitBug = true;
  if (Bits[AMDGPU::FeatureSMEMtoVectorWriteHazard]) HasSMEMtoVectorWriteHazard = true;
  if (Bits[AMDGPU::FeatureSMemRealTime]) HasSMemRealTime = true;
  if (Bits[AMDGPU::FeatureSMemTimeInst]) HasSMemTimeInst = true;
  if (Bits[AMDGPU::FeatureSRAMECC]) EnableSRAMECC = true;
  if (Bits[AMDGPU::FeatureSWMMACGfx1200Insts]) HasSWMMACGfx1200Insts = true;
  if (Bits[AMDGPU::FeatureSWMMACGfx1250Insts]) HasSWMMACGfx1250Insts = true;
  if (Bits[AMDGPU::FeatureSWakeupBarrier]) HasSWakeupBarrier = true;
  if (Bits[AMDGPU::FeatureSWakeupImm]) HasSWakeupImm = true;
  if (Bits[AMDGPU::FeatureSadInsts]) HasSadInsts = true;
  if (Bits[AMDGPU::FeatureSafeCUPrefetch]) HasSafeCUPrefetch = true;
  if (Bits[AMDGPU::FeatureSafeSmemPrefetch]) HasSafeSmemPrefetch = true;
  if (Bits[AMDGPU::FeatureScalarAtomics]) HasScalarAtomics = true;
  if (Bits[AMDGPU::FeatureScalarDwordx3Loads]) HasScalarDwordx3Loads = true;
  if (Bits[AMDGPU::FeatureScalarFlatScratchInsts]) HasScalarFlatScratchInsts = true;
  if (Bits[AMDGPU::FeatureScalarStores]) HasScalarStores = true;
  if (Bits[AMDGPU::FeatureSeaIslands] && Gen < GCNSubtarget::SEA_ISLANDS) Gen = GCNSubtarget::SEA_ISLANDS;
  if (Bits[AMDGPU::FeatureSetPrioIncWgInst]) HasSetPrioIncWgInst = true;
  if (Bits[AMDGPU::FeatureSetregVGPRMSBFixup]) HasSetregVGPRMSBFixup = true;
  if (Bits[AMDGPU::FeatureShaderCyclesHiLoRegisters]) HasShaderCyclesHiLoRegisters = true;
  if (Bits[AMDGPU::FeatureShaderCyclesRegister]) HasShaderCyclesRegister = true;
  if (Bits[AMDGPU::FeatureSmemPrefetchInsts]) HasSmemPrefetchInsts = true;
  if (Bits[AMDGPU::FeatureSouthernIslands] && Gen < GCNSubtarget::SOUTHERN_ISLANDS) Gen = GCNSubtarget::SOUTHERN_ISLANDS;
  if (Bits[AMDGPU::FeatureSupportsSRAMECC]) SupportsSRAMECC = true;
  if (Bits[AMDGPU::FeatureSupportsXNACK]) SupportsXNACK = true;
  if (Bits[AMDGPU::FeatureTanhInsts]) HasTanhInsts = true;
  if (Bits[AMDGPU::FeatureTensorCvtLutInsts]) HasTensorCvtLutInsts = true;
  if (Bits[AMDGPU::FeatureTgSplitSupport]) HasTgSplitSupport = true;
  if (Bits[AMDGPU::FeatureTransCoexecutionHazard]) HasTransCoexecutionHazard = true;
  if (Bits[AMDGPU::FeatureTransposeLoadF4F6Insts]) HasTransposeLoadF4F6Insts = true;
  if (Bits[AMDGPU::FeatureTrapHandler]) HasTrapHandler = true;
  if (Bits[AMDGPU::FeatureTrigReducedRange]) HasTrigReducedRange = true;
  if (Bits[AMDGPU::FeatureTrue16BitInsts]) HasTrue16BitInsts = true;
  if (Bits[AMDGPU::FeatureUnalignedAccessMode]) HasUnalignedAccessMode = true;
  if (Bits[AMDGPU::FeatureUnalignedBufferAccess]) HasUnalignedBufferAccess = true;
  if (Bits[AMDGPU::FeatureUnalignedDSAccess]) HasUnalignedDSAccess = true;
  if (Bits[AMDGPU::FeatureUnalignedScratchAccess]) HasUnalignedScratchAccess = true;
  if (Bits[AMDGPU::FeatureUnpackedD16VMem]) HasUnpackedD16VMem = true;
  if (Bits[AMDGPU::FeatureUseAddPC64Inst]) UseAddPC64Inst = true;
  if (Bits[AMDGPU::FeatureUseBlockVGPROpsForCSR]) UseBlockVGPROpsForCSR = true;
  if (Bits[AMDGPU::FeatureUseFlatForGlobal]) UseFlatForGlobal = true;
  if (Bits[AMDGPU::FeatureUserSGPRInit16Bug]) HasUserSGPRInit16Bug = true;
  if (Bits[AMDGPU::FeatureVALUTransUseHazard]) HasVALUTransUseHazard = true;
  if (Bits[AMDGPU::FeatureVGPRIndexMode]) HasVGPRIndexMode = true;
  if (Bits[AMDGPU::FeatureVMEMtoScalarWriteHazard]) HasVMEMtoScalarWriteHazard = true;
  if (Bits[AMDGPU::FeatureVMemToLDSLoad]) HasVMemToLDSLoad = true;
  if (Bits[AMDGPU::FeatureVMovB64Inst]) HasVMovB64Inst = true;
  if (Bits[AMDGPU::FeatureVMulU64Inst]) HasVMulU64Inst = true;
  if (Bits[AMDGPU::FeatureVOP3Literal]) HasVOP3Literal = true;
  if (Bits[AMDGPU::FeatureVOP3PInsts]) HasVOP3PInsts = true;
  if (Bits[AMDGPU::FeatureVOP3PX2IncrementsVaVdstTwice]) HasVOP3PX2IncrementsVaVdstTwice = true;
  if (Bits[AMDGPU::FeatureVOPDInsts]) HasVOPDInsts = true;
  if (Bits[AMDGPU::FeatureVcmpxExecWARHazard]) HasVcmpxExecWARHazard = true;
  if (Bits[AMDGPU::FeatureVcmpxPermlaneHazard]) HasVcmpxPermlaneHazard = true;
  if (Bits[AMDGPU::FeatureVmemPrefInsts]) HasVmemPrefInsts = true;
  if (Bits[AMDGPU::FeatureVmemWriteVgprInOrder]) HasVmemWriteVgprInOrder = true;
  if (Bits[AMDGPU::FeatureVolcanicIslands] && Gen < GCNSubtarget::VOLCANIC_ISLANDS) Gen = GCNSubtarget::VOLCANIC_ISLANDS;
  if (Bits[AMDGPU::FeatureVscnt]) HasVscnt = true;
  if (Bits[AMDGPU::FeatureWMMA128bInsts]) HasWMMA128bInsts = true;
  if (Bits[AMDGPU::FeatureWMMA256bInsts]) HasWMMA256bInsts = true;
  if (Bits[AMDGPU::FeatureWMMACoexecutionHazards]) HasWMMACoexecutionHazards = true;
  if (Bits[AMDGPU::FeatureWaitXcnt]) HasWaitXcnt = true;
  if (Bits[AMDGPU::FeatureWaitsBeforeSystemScopeStores]) RequiresWaitsBeforeSystemScopeStores = true;
  if (Bits[AMDGPU::FeatureWavefrontSize16] && WavefrontSizeLog2 < 4) WavefrontSizeLog2 = 4;
  if (Bits[AMDGPU::FeatureWavefrontSize32] && WavefrontSizeLog2 < 5) WavefrontSizeLog2 = 5;
  if (Bits[AMDGPU::FeatureWavefrontSize64] && WavefrontSizeLog2 < 6) WavefrontSizeLog2 = 6;
  if (Bits[AMDGPU::FeatureXF32Insts]) HasXF32Insts = true;
  if (Bits[AMDGPU::FeatureXNACK]) EnableXNACK = true;
  if (Bits[AMDGPU::FeatureXNACKOnOffModes]) HasXNACKOnOffModes = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace AMDGPU_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace AMDGPU_MC
struct AMDGPUGenSubtargetInfo : public TargetSubtargetInfo {
  explicit AMDGPUGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class AMDGPUHwModeBits : unsigned {
    DefaultMode = 0,
    AVAlign2LoadStoreMode = (1 << 0),
    AlignedVGPRNoAGPRMode_Wave32 = (1 << 1),
    AlignedVGPRNoAGPRMode_Wave64 = (1 << 2),
    anonymous_13853 = (1 << 3),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/anonymous_13853),
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

extern const llvm_ks::StringRef AMDGPUNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<294, 18809> AMDGPUFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<81, 683> AMDGPUSubTypeKVStorage;
extern const llvm_ks::MCSchedModel AMDGPUSchedModels[];
extern const llvm_ks::MCWriteProcResEntry AMDGPUWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry AMDGPUWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry AMDGPUReadAdvanceTable[];
AMDGPUGenSubtargetInfo::AMDGPUGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(AMDGPUSubTypeKVStorage.Strings), ArrayRef(AMDGPUFeatureKVStorage.Features), ArrayRef(AMDGPUSubTypeKVStorage.SubTypes), AMDGPUSchedModels, 
                        AMDGPUWriteProcResTable, AMDGPUWriteLatencyTable, AMDGPUReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned AMDGPUGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {

  const SIInstrInfo *TII =
    static_cast<const SIInstrInfo*>(SchedModel->getInstrInfo());
  (void)TII;

  switch (SchedClass) {
  case 35: // COPY
    if (SchedModel->getProcessorID() == 1) { // SIQuarterSpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 2) { // GFX10SpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 3) { // GFX11SpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 4) { // GFX125xGenericSpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 5) { // GFX12SpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 6) { // GFX1250SpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 7) { // GFX1251SpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 8) { // SIFullSpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 9) { // SIDPGFX942FullSpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 10) { // SIDPFullSpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    if (SchedModel->getProcessorID() == 11) { // SIDPGFX950FullSpeedModel
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) <= 32)
        return 76; // Write32Bit
      if (TII->isVGPRCopy(*MI) && TII->getOpSize(*MI, 0) > 32)
        return 77; // Write64Bit
      return 78; // WriteSALU
    }
    break;
  case 36: // V_ACCVGPR_WRITE_B32_e64
    if (SchedModel->getProcessorID() == 1) { // SIQuarterSpeedModel
      if (TII->hasVGPRUses(*MI))
        return 79; // Write64Bit_MIVGPRRead
      return 80; // Write64Bit_ReadDefault
    }
    break;
  case 39: // V_MFMA_F32_32X32X16_BF16_e64_V_MFMA_F32_32X32X16_BF16_mac_e64_V_MFMA_F32_32X32X16_BF16_mac_vgprcd_e64_V_MFMA_F32_32X32X16_BF16_vgprcd_e64_V_MFMA_F32_32X32X16_BF8_BF8_e64_V_MFMA_F32_32X32X16_BF8_BF8_mac_e64_V_MFMA_F32_32X32X16_BF8_BF8_mac_vgprcd_e64_V_MFMA_F32_32X32X16_BF8_BF8_vgprcd_e64_V_MFMA_F32_32X32X16_BF8_FP8_e64_V_MFMA_F32_32X32X16_BF8_FP8_mac_e64_V_MFMA_F32_32X32X16_BF8_FP8_mac_vgprcd_e64_V_MFMA_F32_32X32X16_BF8_FP8_vgprcd_e64_V_MFMA_F32_32X32X16_F16_e64_V_MFMA_F32_32X32X16_F16_mac_e64_V_MFMA_F32_32X32X16_F16_mac_vgprcd_e64_V_MFMA_F32_32X32X16_F16_vgprcd_e64_V_MFMA_F32_32X32X16_FP8_BF8_e64_V_MFMA_F32_32X32X16_FP8_BF8_mac_e64_V_MFMA_F32_32X32X16_FP8_BF8_mac_vgprcd_e64_V_MFMA_F32_32X32X16_FP8_BF8_vgprcd_e64_V_MFMA_F32_32X32X16_FP8_FP8_e64_V_MFMA_F32_32X32X16_FP8_FP8_mac_e64_V_MFMA_F32_32X32X16_FP8_FP8_mac_vgprcd_e64_V_MFMA_F32_32X32X16_FP8_FP8_vgprcd_e64_V_MFMA_F32_32X32X1F32_e64_V_MFMA_F32_32X32X1F32_mac_e64_V_MFMA_F32_32X32X1F32_mac_vgprcd_e64_V_MFMA_F32_32X32X1F32_vgprcd_e64_V_MFMA_F32_32X32X2BF16_e64_V_MFMA_F32_32X32X2BF16_mac_e64_V_MFMA_F32_32X32X2BF16_mac_vgprcd_e64_V_MFMA_F32_32X32X2BF16_vgprcd_e64_V_MFMA_F32_32X32X2F32_e64_V_MFMA_F32_32X32X2F32_mac_e64_V_MFMA_F32_32X32X2F32_mac_vgprcd_e64_V_MFMA_F32_32X32X2F32_vgprcd_e64_V_MFMA_F32_32X32X4BF16_1K_e64_V_MFMA_F32_32X32X4BF16_1K_mac_e64_V_MFMA_F32_32X32X4BF16_1K_mac_vgprcd_e64_V_MFMA_F32_32X32X4BF16_1K_vgprcd_e64_V_MFMA_F32_32X32X4BF16_e64_V_MFMA_F32_32X32X4BF16_mac_e64_V_MFMA_F32_32X32X4BF16_mac_vgprcd_e64_V_MFMA_F32_32X32X4BF16_vgprcd_e64_V_MFMA_F32_32X32X4F16_e64_V_MFMA_F32_32X32X4F16_mac_e64_V_MFMA_F32_32X32X4F16_mac_vgprcd_e64_V_MFMA_F32_32X32X4F16_vgprcd_e64_V_MFMA_F32_32X32X4XF32_e64_V_MFMA_F32_32X32X4XF32_mac_e64_V_MFMA_F32_32X32X4XF32_mac_vgprcd_e64_V_MFMA_F32_32X32X4XF32_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_mac_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_mac_vgprcd_e64_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_vgprcd_e64_V_MFMA_F32_32X32X8BF16_1K_e64_V_MFMA_F32_32X32X8BF16_1K_mac_e64_V_MFMA_F32_32X32X8BF16_1K_mac_vgprcd_e64_V_MFMA_F32_32X32X8BF16_1K_vgprcd_e64_V_MFMA_F32_32X32X8F16_e64_V_MFMA_F32_32X32X8F16_mac_e64_V_MFMA_F32_32X32X8F16_mac_vgprcd_e64_V_MFMA_F32_32X32X8F16_vgprcd_e64_V_MFMA_I32_32X32X16I8_e64_V_MFMA_I32_32X32X16I8_mac_e64_V_MFMA_I32_32X32X16I8_mac_vgprcd_e64_V_MFMA_I32_32X32X16I8_vgprcd_e64_V_MFMA_I32_32X32X32_I8_e64_V_MFMA_I32_32X32X32_I8_mac_e64_V_MFMA_I32_32X32X32_I8_mac_vgprcd_e64_V_MFMA_I32_32X32X32_I8_vgprcd_e64_V_MFMA_I32_32X32X4I8_e64_V_MFMA_I32_32X32X4I8_mac_e64_V_MFMA_I32_32X32X4I8_mac_vgprcd_e64_V_MFMA_I32_32X32X4I8_vgprcd_e64_V_MFMA_I32_32X32X8I8_e64_V_MFMA_I32_32X32X8I8_mac_e64_V_MFMA_I32_32X32X8I8_mac_vgprcd_e64_V_MFMA_I32_32X32X8I8_vgprcd_e64_V_MFMA_F32_32X32X16_BF16_gfx940_acd_V_MFMA_F32_32X32X16_BF16_gfx940_vcd_V_MFMA_F32_32X32X16_BF8_BF8_gfx940_acd_V_MFMA_F32_32X32X16_BF8_BF8_gfx940_vcd_V_MFMA_F32_32X32X16_BF8_FP8_gfx940_acd_V_MFMA_F32_32X32X16_BF8_FP8_gfx940_vcd_V_MFMA_F32_32X32X16_F16_gfx940_acd_V_MFMA_F32_32X32X16_F16_gfx940_vcd_V_MFMA_F32_32X32X16_FP8_BF8_gfx940_acd_V_MFMA_F32_32X32X16_FP8_BF8_gfx940_vcd_V_MFMA_F32_32X32X16_FP8_FP8_gfx940_acd_V_MFMA_F32_32X32X16_FP8_FP8_gfx940_vcd_V_MFMA_F32_32X32X1F32_gfx90a_acd_V_MFMA_F32_32X32X1F32_gfx90a_vcd_V_MFMA_F32_32X32X1F32_gfx940_acd_V_MFMA_F32_32X32X1F32_gfx940_vcd_V_MFMA_F32_32X32X1F32_vi_V_MFMA_F32_32X32X2BF16_gfx90a_acd_V_MFMA_F32_32X32X2BF16_gfx90a_vcd_V_MFMA_F32_32X32X2BF16_vi_V_MFMA_F32_32X32X2F32_gfx90a_acd_V_MFMA_F32_32X32X2F32_gfx90a_vcd_V_MFMA_F32_32X32X2F32_gfx940_acd_V_MFMA_F32_32X32X2F32_gfx940_vcd_V_MFMA_F32_32X32X2F32_vi_V_MFMA_F32_32X32X4BF16_1K_gfx90a_acd_V_MFMA_F32_32X32X4BF16_1K_gfx90a_vcd_V_MFMA_F32_32X32X4BF16_1K_gfx940_acd_V_MFMA_F32_32X32X4BF16_1K_gfx940_vcd_V_MFMA_F32_32X32X4BF16_gfx90a_acd_V_MFMA_F32_32X32X4BF16_gfx90a_vcd_V_MFMA_F32_32X32X4BF16_vi_V_MFMA_F32_32X32X4F16_gfx90a_acd_V_MFMA_F32_32X32X4F16_gfx90a_vcd_V_MFMA_F32_32X32X4F16_gfx940_acd_V_MFMA_F32_32X32X4F16_gfx940_vcd_V_MFMA_F32_32X32X4F16_vi_V_MFMA_F32_32X32X4XF32_gfx940_acd_V_MFMA_F32_32X32X4XF32_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f4_f4_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f4_f6_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f4_f8_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f6_f4_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f6_f6_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f6_f8_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f8_f4_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f8_f6_gfx940_vcd_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_gfx940_acd_V_MFMA_F32_32X32X64_F8F6F4_f8_f8_gfx940_vcd_V_MFMA_F32_32X32X8BF16_1K_gfx90a_acd_V_MFMA_F32_32X32X8BF16_1K_gfx90a_vcd_V_MFMA_F32_32X32X8BF16_1K_gfx940_acd_V_MFMA_F32_32X32X8BF16_1K_gfx940_vcd_V_MFMA_F32_32X32X8F16_gfx90a_acd_V_MFMA_F32_32X32X8F16_gfx90a_vcd_V_MFMA_F32_32X32X8F16_gfx940_acd_V_MFMA_F32_32X32X8F16_gfx940_vcd_V_MFMA_F32_32X32X8F16_vi_V_MFMA_I32_32X32X16I8_gfx940_acd_V_MFMA_I32_32X32X16I8_gfx940_vcd_V_MFMA_I32_32X32X32_I8_gfx940_acd_V_MFMA_I32_32X32X32_I8_gfx940_vcd_V_MFMA_I32_32X32X4I8_gfx90a_acd_V_MFMA_I32_32X32X4I8_gfx90a_vcd_V_MFMA_I32_32X32X4I8_gfx940_acd_V_MFMA_I32_32X32X4I8_gfx940_vcd_V_MFMA_I32_32X32X4I8_vi_V_MFMA_I32_32X32X8I8_gfx90a_acd_V_MFMA_I32_32X32X8I8_gfx90a_vcd_V_MFMA_I32_32X32X8I8_vi
    if (SchedModel->getProcessorID() == 11) { // SIDPGFX950FullSpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::cbsz)->getImm() <= AMDGPU::MFMAScaleFormats::FP8_E5M2 ||
  TII->getNamedOperand(*MI, AMDGPU::OpName::blgp)->getImm() <= AMDGPU::MFMAScaleFormats::FP8_E5M2
)
        return 81; // Write16PassMAI_MIMFMARead
      return 82; // Write8PassMAI_MIMFMARead
    }
    break;
  case 54: // V_MFMA_F32_16X16X128_F8F6F4_f4_f4_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f4_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f6_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f6_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f8_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f8_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f4_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f4_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f6_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f6_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f8_e64_V_MFMA_F32_16X16X128_F8F6F4_f6_f8_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f4_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f4_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f6_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f6_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f8_e64_V_MFMA_F32_16X16X128_F8F6F4_f8_f8_vgprcd_e64_V_MFMA_F32_16X16X128_F8F6F4_f4_f4_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f4_f4_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f4_f6_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f4_f6_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f4_f8_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f4_f8_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f6_f4_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f6_f4_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f6_f6_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f6_f6_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f6_f8_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f6_f8_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f8_f4_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f8_f4_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f8_f6_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f8_f6_gfx940_vcd_V_MFMA_F32_16X16X128_F8F6F4_f8_f8_gfx940_acd_V_MFMA_F32_16X16X128_F8F6F4_f8_f8_gfx940_vcd
    if (SchedModel->getProcessorID() == 11) { // SIDPGFX950FullSpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::cbsz)->getImm() <= AMDGPU::MFMAScaleFormats::FP8_E5M2 ||
  TII->getNamedOperand(*MI, AMDGPU::OpName::blgp)->getImm() <= AMDGPU::MFMAScaleFormats::FP8_E5M2
)
        return 82; // Write8PassMAI_MIMFMARead
      return 83; // Write4PassMAI_MIMFMARead
    }
    break;
  case 55: // V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_vgprcd_e64_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_gfx940_vcd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_gfx940_acd_V_MFMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_gfx940_vcd
    if (SchedModel->getProcessorID() == 11) { // SIDPGFX950FullSpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::cbsz)->getImm() <= AMDGPU::MFMAScaleFormats::FP8_E5M2 ||
  TII->getNamedOperand(*MI, AMDGPU::OpName::blgp)->getImm() <= AMDGPU::MFMAScaleFormats::FP8_E5M2
)
        return 82; // Write8PassMAI_MIMFMARead
      return 83; // Write4PassMAI_MIMFMARead
    }
    break;
  case 56: // V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_mac_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_mac_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_vgprcd_e64_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f4_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f6_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f4_f8_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f4_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f6_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f6_f8_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f4_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f6_gfx940_vcd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_gfx940_acd_V_MFMA_SCALE_F32_32X32X64_F8F6F4_f8_f8_gfx940_vcd
    if (SchedModel->getProcessorID() == 11) { // SIDPGFX950FullSpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::cbsz)->getImm() <= AMDGPU::MFMAScaleFormats::FP8_E5M2 ||
  TII->getNamedOperand(*MI, AMDGPU::OpName::blgp)->getImm() <= AMDGPU::MFMAScaleFormats::FP8_E5M2
)
        return 81; // Write16PassMAI_MIMFMARead
      return 82; // Write8PassMAI_MIMFMARead
    }
    break;
  case 63: // V_WMMA_F32_16X16X128_F8F6F4_f4_f4_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f6_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f8_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f4_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f6_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f8_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f4_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f6_w32_threeaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f8_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f4_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f6_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f8_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f4_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f6_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f8_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f4_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f6_w32_threeaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f8_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_w32_threeaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_w32_threeaddr
    if (SchedModel->getProcessorID() == 4) { // GFX125xGenericSpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_a_fmt)->getImm() == AMDGPU::WMMA::MATRIX_FMT_FP4 &&
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_b_fmt)->getImm() <= AMDGPU::WMMA::MATRIX_FMT_FP4
)
        return 84; // WriteXDL4PassWMMA
      return 86; // WriteXDL8PassWMMA
    }
    if (SchedModel->getProcessorID() == 6) { // GFX1250SpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_a_fmt)->getImm() <= AMDGPU::WMMA::MATRIX_FMT_BF8 ||
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_b_fmt)->getImm() <= AMDGPU::WMMA::MATRIX_FMT_BF8
)
        return 84; // WriteXDL4PassWMMA
      return 85; // WriteXDL2PassWMMA
    }
    if (SchedModel->getProcessorID() == 7) { // GFX1251SpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_a_fmt)->getImm() == AMDGPU::WMMA::MATRIX_FMT_FP4 &&
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_b_fmt)->getImm() <= AMDGPU::WMMA::MATRIX_FMT_FP4
)
        return 84; // WriteXDL4PassWMMA
      return 86; // WriteXDL8PassWMMA
    }
    break;
  case 64: // V_WMMA_F32_16X16X128_F8F6F4_f4_f4_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f6_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f8_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f4_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f6_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f6_f8_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f4_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f6_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f8_f8_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f4_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f6_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f8_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f4_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f6_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f8_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f4_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f6_w32_twoaddr_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f8_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_w32_twoaddr_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_w32_twoaddr_V_WMMA_F32_16X16X128_F8F6F4_f4_f4_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f4_f6_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f4_f8_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f6_f4_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f6_f6_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f6_f8_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f8_f4_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f8_f6_w32_twoaddr_gfx1250_V_WMMA_F32_16X16X128_F8F6F4_f8_f8_w32_twoaddr_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f4_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f6_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f4_f8_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f4_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f6_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f6_f8_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f4_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f6_w32_gfx1250_V_WMMA_SCALE16_F32_16X16X128_F8F6F4_f8_f8_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f4_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f6_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f4_f8_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f4_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f6_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f6_f8_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f4_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f6_w32_gfx1250_V_WMMA_SCALE_F32_16X16X128_F8F6F4_f8_f8_w32_gfx1250
    if (SchedModel->getProcessorID() == 4) { // GFX125xGenericSpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_a_fmt)->getImm() == AMDGPU::WMMA::MATRIX_FMT_FP4 &&
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_b_fmt)->getImm() <= AMDGPU::WMMA::MATRIX_FMT_FP4
)
        return 84; // WriteXDL4PassWMMA
      return 86; // WriteXDL8PassWMMA
    }
    if (SchedModel->getProcessorID() == 6) { // GFX1250SpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_a_fmt)->getImm() <= AMDGPU::WMMA::MATRIX_FMT_BF8 ||
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_b_fmt)->getImm() <= AMDGPU::WMMA::MATRIX_FMT_BF8
)
        return 84; // WriteXDL4PassWMMA
      return 85; // WriteXDL2PassWMMA
    }
    if (SchedModel->getProcessorID() == 7) { // GFX1251SpeedModel
      if (
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_a_fmt)->getImm() == AMDGPU::WMMA::MATRIX_FMT_FP4 &&
  TII->getNamedOperand(*MI, AMDGPU::OpName::matrix_b_fmt)->getImm() <= AMDGPU::WMMA::MATRIX_FMT_FP4
)
        return 84; // WriteXDL4PassWMMA
      return 86; // WriteXDL8PassWMMA
    }
    break;
  };
  report_fatal_error("Expected a variant SchedClass");
} // AMDGPUGenSubtargetInfo::resolveSchedClass

unsigned AMDGPUGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return AMDGPU_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // AMDGPUGenSubtargetInfo::resolveVariantSchedClass

unsigned AMDGPUGenSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const auto *Subtarget =
      static_cast<const AMDGPUSubtarget *>(this);
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((Subtarget->hasMAIInsts()) && (Subtarget->needsAlignedVGPRs())) Modes |= (1 << 0);
  if ((!Subtarget->hasMAIInsts()) && (Subtarget->needsAlignedVGPRs()) && (Subtarget->isWave32())) Modes |= (1 << 1);
  if ((!Subtarget->hasMAIInsts()) && (Subtarget->needsAlignedVGPRs()) && (Subtarget->isWave64())) Modes |= (1 << 2);
  if ((Subtarget->isWave32()) && (!Subtarget->needsAlignedVGPRs())) Modes |= (1 << 3);
  return Modes;
}
unsigned AMDGPUGenSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    Modes &= 15;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for ValueType were found!");
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_RegInfo:
    Modes &= 15;
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
const FeatureBitset &AMDGPUGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
AMDGPU::FeatureEnableLoadStoreOpt,
AMDGPU::FeatureEnableSIScheduler,
AMDGPU::FeatureEnableUnsafeDSOffsetFolding,
AMDGPU::FeatureXNACK,
AMDGPU::FeatureAutoWaitcntBeforeBarrier,
AMDGPU::FeatureFastFMAF32,
AMDGPU::FeatureHalfRate64Ops,
AMDGPU::FeatureSGPRInitBug,
AMDGPU::FeatureTrapHandler,
AMDGPU::FeatureUnalignedAccessMode,
AMDGPU::FeatureUnalignedScratchAccess,
AMDGPU::FeatureXNACKOnOffModes,
AMDGPU::FeatureSupportsSRAMECC,
AMDGPU::FeatureSupportsXNACK,
AMDGPU::FeatureUseFlatForGlobal,
  };
  return Features;
}

const FeatureBitset &AMDGPUGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &AMDGPUGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

