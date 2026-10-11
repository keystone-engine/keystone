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

namespace SystemZ {

enum {
  FeatureBEAREnhancement = 0,
  FeatureBackChain = 1,
  FeatureConcurrentFunctions = 2,
  FeatureDFPPackedConversion = 3,
  FeatureDFPZonedConversion = 4,
  FeatureDeflateConversion = 5,
  FeatureDistinctOps = 6,
  FeatureEnhancedDAT2 = 7,
  FeatureEnhancedSort = 8,
  FeatureExecutionHint = 9,
  FeatureFPExtension = 10,
  FeatureFastSerialization = 11,
  FeatureGuardedStorage = 12,
  FeatureHighWord = 13,
  FeatureInsertReferenceBitsMultiple = 14,
  FeatureInterlockedAccess1 = 15,
  FeatureLoadAndTrap = 16,
  FeatureLoadAndZeroRightmostByte = 17,
  FeatureLoadStoreOnCond = 18,
  FeatureLoadStoreOnCond2 = 19,
  FeatureMessageSecurityAssist3 = 20,
  FeatureMessageSecurityAssist4 = 21,
  FeatureMessageSecurityAssist5 = 22,
  FeatureMessageSecurityAssist7 = 23,
  FeatureMessageSecurityAssist8 = 24,
  FeatureMessageSecurityAssist9 = 25,
  FeatureMessageSecurityAssist12 = 26,
  FeatureMiscellaneousExtensions = 27,
  FeatureMiscellaneousExtensions2 = 28,
  FeatureMiscellaneousExtensions3 = 29,
  FeatureMiscellaneousExtensions4 = 30,
  FeatureNNPAssist = 31,
  FeaturePopulationCount = 32,
  FeatureProcessorActivityInstrumentation = 33,
  FeatureProcessorAssist = 34,
  FeatureResetDATProtection = 35,
  FeatureResetReferenceBitsMultiple = 36,
  FeatureSoftFloat = 37,
  FeatureTestPendingExternalInterruption = 38,
  FeatureTransactionalExecution = 39,
  FeatureUnalignedSymbols = 40,
  FeatureVector = 41,
  FeatureVectorEnhancements1 = 42,
  FeatureVectorEnhancements2 = 43,
  FeatureVectorEnhancements3 = 44,
  FeatureVectorPackedDecimal = 45,
  FeatureVectorPackedDecimalEnhancement = 46,
  FeatureVectorPackedDecimalEnhancement2 = 47,
  FeatureVectorPackedDecimalEnhancement3 = 48,
  NumSubtargetFeatures = 49
};

} // namespace SystemZ

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(HasBEAREnhancement, false, hasBEAREnhancement)
GET_SUBTARGETINFO_MACRO(HasBackChain, false, hasBackChain)
GET_SUBTARGETINFO_MACRO(HasConcurrentFunctions, false, hasConcurrentFunctions)
GET_SUBTARGETINFO_MACRO(HasDFPPackedConversion, false, hasDFPPackedConversion)
GET_SUBTARGETINFO_MACRO(HasDFPZonedConversion, false, hasDFPZonedConversion)
GET_SUBTARGETINFO_MACRO(HasDeflateConversion, false, hasDeflateConversion)
GET_SUBTARGETINFO_MACRO(HasDistinctOps, false, hasDistinctOps)
GET_SUBTARGETINFO_MACRO(HasEnhancedDAT2, false, hasEnhancedDAT2)
GET_SUBTARGETINFO_MACRO(HasEnhancedSort, false, hasEnhancedSort)
GET_SUBTARGETINFO_MACRO(HasExecutionHint, false, hasExecutionHint)
GET_SUBTARGETINFO_MACRO(HasFPExtension, false, hasFPExtension)
GET_SUBTARGETINFO_MACRO(HasFastSerialization, false, hasFastSerialization)
GET_SUBTARGETINFO_MACRO(HasGuardedStorage, false, hasGuardedStorage)
GET_SUBTARGETINFO_MACRO(HasHighWord, false, hasHighWord)
GET_SUBTARGETINFO_MACRO(HasInsertReferenceBitsMultiple, false, hasInsertReferenceBitsMultiple)
GET_SUBTARGETINFO_MACRO(HasInterlockedAccess1, false, hasInterlockedAccess1)
GET_SUBTARGETINFO_MACRO(HasLoadAndTrap, false, hasLoadAndTrap)
GET_SUBTARGETINFO_MACRO(HasLoadAndZeroRightmostByte, false, hasLoadAndZeroRightmostByte)
GET_SUBTARGETINFO_MACRO(HasLoadStoreOnCond, false, hasLoadStoreOnCond)
GET_SUBTARGETINFO_MACRO(HasLoadStoreOnCond2, false, hasLoadStoreOnCond2)
GET_SUBTARGETINFO_MACRO(HasMessageSecurityAssist12, false, hasMessageSecurityAssist12)
GET_SUBTARGETINFO_MACRO(HasMessageSecurityAssist3, false, hasMessageSecurityAssist3)
GET_SUBTARGETINFO_MACRO(HasMessageSecurityAssist4, false, hasMessageSecurityAssist4)
GET_SUBTARGETINFO_MACRO(HasMessageSecurityAssist5, false, hasMessageSecurityAssist5)
GET_SUBTARGETINFO_MACRO(HasMessageSecurityAssist7, false, hasMessageSecurityAssist7)
GET_SUBTARGETINFO_MACRO(HasMessageSecurityAssist8, false, hasMessageSecurityAssist8)
GET_SUBTARGETINFO_MACRO(HasMessageSecurityAssist9, false, hasMessageSecurityAssist9)
GET_SUBTARGETINFO_MACRO(HasMiscellaneousExtensions, false, hasMiscellaneousExtensions)
GET_SUBTARGETINFO_MACRO(HasMiscellaneousExtensions2, false, hasMiscellaneousExtensions2)
GET_SUBTARGETINFO_MACRO(HasMiscellaneousExtensions3, false, hasMiscellaneousExtensions3)
GET_SUBTARGETINFO_MACRO(HasMiscellaneousExtensions4, false, hasMiscellaneousExtensions4)
GET_SUBTARGETINFO_MACRO(HasNNPAssist, false, hasNNPAssist)
GET_SUBTARGETINFO_MACRO(HasPopulationCount, false, hasPopulationCount)
GET_SUBTARGETINFO_MACRO(HasProcessorActivityInstrumentation, false, hasProcessorActivityInstrumentation)
GET_SUBTARGETINFO_MACRO(HasProcessorAssist, false, hasProcessorAssist)
GET_SUBTARGETINFO_MACRO(HasResetDATProtection, false, hasResetDATProtection)
GET_SUBTARGETINFO_MACRO(HasResetReferenceBitsMultiple, false, hasResetReferenceBitsMultiple)
GET_SUBTARGETINFO_MACRO(HasSoftFloat, false, hasSoftFloat)
GET_SUBTARGETINFO_MACRO(HasTestPendingExternalInterruption, false, hasTestPendingExternalInterruption)
GET_SUBTARGETINFO_MACRO(HasTransactionalExecution, false, hasTransactionalExecution)
GET_SUBTARGETINFO_MACRO(HasUnalignedSymbols, false, hasUnalignedSymbols)
GET_SUBTARGETINFO_MACRO(HasVector, false, hasVector)
GET_SUBTARGETINFO_MACRO(HasVectorEnhancements1, false, hasVectorEnhancements1)
GET_SUBTARGETINFO_MACRO(HasVectorEnhancements2, false, hasVectorEnhancements2)
GET_SUBTARGETINFO_MACRO(HasVectorEnhancements3, false, hasVectorEnhancements3)
GET_SUBTARGETINFO_MACRO(HasVectorPackedDecimal, false, hasVectorPackedDecimal)
GET_SUBTARGETINFO_MACRO(HasVectorPackedDecimalEnhancement, false, hasVectorPackedDecimalEnhancement)
GET_SUBTARGETINFO_MACRO(HasVectorPackedDecimalEnhancement2, false, hasVectorPackedDecimalEnhancement2)
GET_SUBTARGETINFO_MACRO(HasVectorPackedDecimalEnhancement3, false, hasVectorPackedDecimalEnhancement3)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 49, 4176> SystemZFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 49 + 1, sizeof(SubtargetFeatureKV) * 49 + 11, SystemZ::FeatureBackChain, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 48 + 81, sizeof(SubtargetFeatureKV) * 48 + 98, SystemZ::FeatureBEAREnhancement, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 47 + 153, sizeof(SubtargetFeatureKV) * 47 + 174, SystemZ::FeatureConcurrentFunctions, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 46 + 233, sizeof(SubtargetFeatureKV) * 46 + 252, SystemZ::FeatureDeflateConversion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 45 + 309, sizeof(SubtargetFeatureKV) * 45 + 331, SystemZ::FeatureDFPPackedConversion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 44 + 391, sizeof(SubtargetFeatureKV) * 44 + 412, SystemZ::FeatureDFPZonedConversion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 43 + 471, sizeof(SubtargetFeatureKV) * 43 + 484, SystemZ::FeatureDistinctOps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 42 + 540, sizeof(SubtargetFeatureKV) * 42 + 555, SystemZ::FeatureEnhancedDAT2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 41 + 608, sizeof(SubtargetFeatureKV) * 41 + 622, SystemZ::FeatureEnhancedSort, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 40 + 674, sizeof(SubtargetFeatureKV) * 40 + 689, SystemZ::FeatureExecutionHint, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 39 + 742, sizeof(SubtargetFeatureKV) * 39 + 761, SystemZ::FeatureFastSerialization, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 38 + 818, sizeof(SubtargetFeatureKV) * 38 + 831, SystemZ::FeatureFPExtension, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 894, sizeof(SubtargetFeatureKV) * 37 + 910, SystemZ::FeatureGuardedStorage, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 964, sizeof(SubtargetFeatureKV) * 36 + 974, SystemZ::FeatureHighWord, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 1022, sizeof(SubtargetFeatureKV) * 35 + 1053, SystemZ::FeatureInsertReferenceBitsMultiple, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 1122, sizeof(SubtargetFeatureKV) * 34 + 1142, SystemZ::FeatureInterlockedAccess1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 1197, sizeof(SubtargetFeatureKV) * 33 + 1211, SystemZ::FeatureLoadAndTrap, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 1263, sizeof(SubtargetFeatureKV) * 32 + 1292, SystemZ::FeatureLoadAndZeroRightmostByte, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 1359, sizeof(SubtargetFeatureKV) * 31 + 1378, SystemZ::FeatureLoadStoreOnCond, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 1440, sizeof(SubtargetFeatureKV) * 30 + 1461, SystemZ::FeatureLoadStoreOnCond2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 1525, sizeof(SubtargetFeatureKV) * 29 + 1561, SystemZ::FeatureMessageSecurityAssist12, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 1636, sizeof(SubtargetFeatureKV) * 28 + 1671, SystemZ::FeatureMessageSecurityAssist3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 1745, sizeof(SubtargetFeatureKV) * 27 + 1780, SystemZ::FeatureMessageSecurityAssist4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 1854, sizeof(SubtargetFeatureKV) * 26 + 1889, SystemZ::FeatureMessageSecurityAssist5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 1963, sizeof(SubtargetFeatureKV) * 25 + 1998, SystemZ::FeatureMessageSecurityAssist7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 2072, sizeof(SubtargetFeatureKV) * 24 + 2107, SystemZ::FeatureMessageSecurityAssist8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 2181, sizeof(SubtargetFeatureKV) * 23 + 2216, SystemZ::FeatureMessageSecurityAssist9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 2290, sizeof(SubtargetFeatureKV) * 22 + 2315, SystemZ::FeatureMiscellaneousExtensions, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 2378, sizeof(SubtargetFeatureKV) * 21 + 2405, SystemZ::FeatureMiscellaneousExtensions2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 2470, sizeof(SubtargetFeatureKV) * 20 + 2497, SystemZ::FeatureMiscellaneousExtensions3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 2562, sizeof(SubtargetFeatureKV) * 19 + 2589, SystemZ::FeatureMiscellaneousExtensions4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 2654, sizeof(SubtargetFeatureKV) * 18 + 2665, SystemZ::FeatureNNPAssist, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 2714, sizeof(SubtargetFeatureKV) * 17 + 2731, SystemZ::FeaturePopulationCount, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 2786, sizeof(SubtargetFeatureKV) * 16 + 2821, SystemZ::FeatureProcessorActivityInstrumentation, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 2894, sizeof(SubtargetFeatureKV) * 15 + 2911, SystemZ::FeatureProcessorAssist, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 2966, sizeof(SubtargetFeatureKV) * 14 + 2987, SystemZ::FeatureResetDATProtection, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 3046, sizeof(SubtargetFeatureKV) * 13 + 3076, SystemZ::FeatureResetReferenceBitsMultiple, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 3144, sizeof(SubtargetFeatureKV) * 12 + 3155, SystemZ::FeatureSoftFloat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 3197, sizeof(SubtargetFeatureKV) * 11 + 3232, SystemZ::FeatureTestPendingExternalInterruption, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 3305, sizeof(SubtargetFeatureKV) * 10 + 3329, SystemZ::FeatureTransactionalExecution, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 3391, sizeof(SubtargetFeatureKV) * 9 + 3409, SystemZ::FeatureUnalignedSymbols, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 3468, sizeof(SubtargetFeatureKV) * 8 + 3475, SystemZ::FeatureVector, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 3521, sizeof(SubtargetFeatureKV) * 7 + 3543, SystemZ::FeatureVectorEnhancements1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 3603, sizeof(SubtargetFeatureKV) * 6 + 3625, SystemZ::FeatureVectorEnhancements2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 3685, sizeof(SubtargetFeatureKV) * 5 + 3707, SystemZ::FeatureVectorEnhancements3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 3767, sizeof(SubtargetFeatureKV) * 4 + 3789, SystemZ::FeatureVectorPackedDecimal, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 3849, sizeof(SubtargetFeatureKV) * 3 + 3883, SystemZ::FeatureVectorPackedDecimalEnhancement, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 3955, sizeof(SubtargetFeatureKV) * 2 + 3991, SystemZ::FeatureVectorPackedDecimalEnhancement2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 4065, sizeof(SubtargetFeatureKV) * 1 + 4101, SystemZ::FeatureVectorPackedDecimalEnhancement3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000backchain\000Store the address of the caller's frame into the calle"
    "e's stack frame\000bear-enhancement\000Assume that the BEAR-enhancement"
    " facility is installed\000concurrent-functions\000Assume that the concu"
    "rrent-functions facility is installed\000deflate-conversion\000Assume t"
    "hat the deflate-conversion facility is installed\000dfp-packed-conversi"
    "on\000Assume that the DFP packed-conversion facility is installed\000df"
    "p-zoned-conversion\000Assume that the DFP zoned-conversion facility is "
    "installed\000distinct-ops\000Assume that the distinct-operands facility"
    " is installed\000enhanced-dat-2\000Assume that the enhanced-DAT facilit"
    "y 2 is installed\000enhanced-sort\000Assume that the enhanced-sort faci"
    "lity is installed\000execution-hint\000Assume that the execution-hint f"
    "acility is installed\000fast-serialization\000Assume that the fast-seri"
    "alization facility is installed\000fp-extension\000Assume that the floa"
    "ting-point extension facility is installed\000guarded-storage\000Assume"
    " that the guarded-storage facility is installed\000high-word\000Assume "
    "that the high-word facility is installed\000insert-reference-bits-multi"
    "ple\000Assume that the insert-reference-bits-multiple facility is insta"
    "lled\000interlocked-access1\000Assume that interlocked-access facility "
    "1 is installed\000load-and-trap\000Assume that the load-and-trap facili"
    "ty is installed\000load-and-zero-rightmost-byte\000Assume that the load"
    "-and-zero-rightmost-byte facility is installed\000load-store-on-cond\000"
    "Assume that the load/store-on-condition facility is installed\000load-s"
    "tore-on-cond-2\000Assume that the load/store-on-condition facility 2 is"
    " installed\000message-security-assist-extension12\000Assume that the me"
    "ssage-security-assist extension facility 12 is installed\000message-sec"
    "urity-assist-extension3\000Assume that the message-security-assist exte"
    "nsion facility 3 is installed\000message-security-assist-extension4\000"
    "Assume that the message-security-assist extension facility 4 is install"
    "ed\000message-security-assist-extension5\000Assume that the message-sec"
    "urity-assist extension facility 5 is installed\000message-security-assi"
    "st-extension7\000Assume that the message-security-assist extension faci"
    "lity 7 is installed\000message-security-assist-extension8\000Assume tha"
    "t the message-security-assist extension facility 8 is installed\000mess"
    "age-security-assist-extension9\000Assume that the message-security-assi"
    "st extension facility 9 is installed\000miscellaneous-extensions\000Ass"
    "ume that the miscellaneous-extensions facility is installed\000miscella"
    "neous-extensions-2\000Assume that the miscellaneous-extensions facility"
    " 2 is installed\000miscellaneous-extensions-3\000Assume that the miscel"
    "laneous-extensions facility 3 is installed\000miscellaneous-extensions-"
    "4\000Assume that the miscellaneous-extensions facility 4 is installed\000"
    "nnp-assist\000Assume that the NNP-assist facility is installed\000popul"
    "ation-count\000Assume that the population-count facility is installed\000"
    "processor-activity-instrumentation\000Assume that the processor-activit"
    "y-instrumentation facility is installed\000processor-assist\000Assume t"
    "hat the processor-assist facility is installed\000reset-dat-protection\000"
    "Assume that the reset-DAT-protection facility is installed\000reset-ref"
    "erence-bits-multiple\000Assume that the reset-reference-bits-multiple f"
    "acility is installed\000soft-float\000Use software emulation for floati"
    "ng point\000test-pending-external-interruption\000Assume that the test-"
    "pending-external-interruption facility is installed\000transactional-ex"
    "ecution\000Assume that the transactional-execution facility is installe"
    "d\000unaligned-symbols\000Don't apply the ABI minimum alignment to exte"
    "rnal symbols.\000vector\000Assume that the vectory facility is installe"
    "d\000vector-enhancements-1\000Assume that the vector enhancements facil"
    "ity 1 is installed\000vector-enhancements-2\000Assume that the vector e"
    "nhancements facility 2 is installed\000vector-enhancements-3\000Assume "
    "that the vector enhancements facility 3 is installed\000vector-packed-d"
    "ecimal\000Assume that the vector packed decimal facility is installed\000"
    "vector-packed-decimal-enhancement\000Assume that the vector packed deci"
    "mal enhancement facility is installed\000vector-packed-decimal-enhancem"
    "ent-2\000Assume that the vector packed decimal enhancement facility 2 i"
    "s installed\000vector-packed-decimal-enhancement-3\000Assume that the v"
    "ector packed decimal enhancement facility 3 is installed\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 17, 99> SystemZSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 17 + 1, { { { 0x950835aed0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 16 + 8, { { { 0x295087faed8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 15 + 15, { { { 0x26d519fffed8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 14 + 22, { { { 0x6ed53bfffff8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 13 + 29, { { { 0xeedfbbfffff9ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 12 + 36, { { { 0x1fedffffffffdULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 11 + 43, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 10 + 49, { { { 0x110034ac40ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 9 + 55, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 8 + 63, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 7 + 67, { { { 0x295087faed8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 6 + 71, { { { 0x26d519fffed8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 5 + 75, { { { 0x6ed53bfffff8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 4 + 79, { { { 0xeedfbbfffff9ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 3 + 83, { { { 0x1fedffffffffdULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 2 + 87, { { { 0x110034ac40ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 1 + 92, { { { 0x950835aed0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
  },
    "\000arch10\000arch11\000arch12\000arch13\000arch14\000arch15\000arch8\000"
    "arch9\000generic\000z10\000z13\000z14\000z15\000z16\000z17\000z196\000z"
    "EC12\000"};

namespace SystemZ_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace SystemZ_MC
struct SystemZGenMCSubtargetInfo : public MCSubtargetInfo {
  SystemZGenMCSubtargetInfo(const Triple &TT,
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
    return SystemZ_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned SystemZGenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (false) Modes |= (1 << 0);
  return Modes;
}
unsigned SystemZGenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
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

static inline MCSubtargetInfo *createSystemZMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new SystemZGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(SystemZSubTypeKVStorage.Strings), SystemZFeatureKVStorage.Features, SystemZSubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::SystemZSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[SystemZ::FeatureBEAREnhancement]) HasBEAREnhancement = true;
  if (Bits[SystemZ::FeatureBackChain]) HasBackChain = true;
  if (Bits[SystemZ::FeatureConcurrentFunctions]) HasConcurrentFunctions = true;
  if (Bits[SystemZ::FeatureDFPPackedConversion]) HasDFPPackedConversion = true;
  if (Bits[SystemZ::FeatureDFPZonedConversion]) HasDFPZonedConversion = true;
  if (Bits[SystemZ::FeatureDeflateConversion]) HasDeflateConversion = true;
  if (Bits[SystemZ::FeatureDistinctOps]) HasDistinctOps = true;
  if (Bits[SystemZ::FeatureEnhancedDAT2]) HasEnhancedDAT2 = true;
  if (Bits[SystemZ::FeatureEnhancedSort]) HasEnhancedSort = true;
  if (Bits[SystemZ::FeatureExecutionHint]) HasExecutionHint = true;
  if (Bits[SystemZ::FeatureFPExtension]) HasFPExtension = true;
  if (Bits[SystemZ::FeatureFastSerialization]) HasFastSerialization = true;
  if (Bits[SystemZ::FeatureGuardedStorage]) HasGuardedStorage = true;
  if (Bits[SystemZ::FeatureHighWord]) HasHighWord = true;
  if (Bits[SystemZ::FeatureInsertReferenceBitsMultiple]) HasInsertReferenceBitsMultiple = true;
  if (Bits[SystemZ::FeatureInterlockedAccess1]) HasInterlockedAccess1 = true;
  if (Bits[SystemZ::FeatureLoadAndTrap]) HasLoadAndTrap = true;
  if (Bits[SystemZ::FeatureLoadAndZeroRightmostByte]) HasLoadAndZeroRightmostByte = true;
  if (Bits[SystemZ::FeatureLoadStoreOnCond]) HasLoadStoreOnCond = true;
  if (Bits[SystemZ::FeatureLoadStoreOnCond2]) HasLoadStoreOnCond2 = true;
  if (Bits[SystemZ::FeatureMessageSecurityAssist3]) HasMessageSecurityAssist3 = true;
  if (Bits[SystemZ::FeatureMessageSecurityAssist4]) HasMessageSecurityAssist4 = true;
  if (Bits[SystemZ::FeatureMessageSecurityAssist5]) HasMessageSecurityAssist5 = true;
  if (Bits[SystemZ::FeatureMessageSecurityAssist7]) HasMessageSecurityAssist7 = true;
  if (Bits[SystemZ::FeatureMessageSecurityAssist8]) HasMessageSecurityAssist8 = true;
  if (Bits[SystemZ::FeatureMessageSecurityAssist9]) HasMessageSecurityAssist9 = true;
  if (Bits[SystemZ::FeatureMessageSecurityAssist12]) HasMessageSecurityAssist12 = true;
  if (Bits[SystemZ::FeatureMiscellaneousExtensions]) HasMiscellaneousExtensions = true;
  if (Bits[SystemZ::FeatureMiscellaneousExtensions2]) HasMiscellaneousExtensions2 = true;
  if (Bits[SystemZ::FeatureMiscellaneousExtensions3]) HasMiscellaneousExtensions3 = true;
  if (Bits[SystemZ::FeatureMiscellaneousExtensions4]) HasMiscellaneousExtensions4 = true;
  if (Bits[SystemZ::FeatureNNPAssist]) HasNNPAssist = true;
  if (Bits[SystemZ::FeaturePopulationCount]) HasPopulationCount = true;
  if (Bits[SystemZ::FeatureProcessorActivityInstrumentation]) HasProcessorActivityInstrumentation = true;
  if (Bits[SystemZ::FeatureProcessorAssist]) HasProcessorAssist = true;
  if (Bits[SystemZ::FeatureResetDATProtection]) HasResetDATProtection = true;
  if (Bits[SystemZ::FeatureResetReferenceBitsMultiple]) HasResetReferenceBitsMultiple = true;
  if (Bits[SystemZ::FeatureSoftFloat]) HasSoftFloat = true;
  if (Bits[SystemZ::FeatureTestPendingExternalInterruption]) HasTestPendingExternalInterruption = true;
  if (Bits[SystemZ::FeatureTransactionalExecution]) HasTransactionalExecution = true;
  if (Bits[SystemZ::FeatureUnalignedSymbols]) HasUnalignedSymbols = true;
  if (Bits[SystemZ::FeatureVector]) HasVector = true;
  if (Bits[SystemZ::FeatureVectorEnhancements1]) HasVectorEnhancements1 = true;
  if (Bits[SystemZ::FeatureVectorEnhancements2]) HasVectorEnhancements2 = true;
  if (Bits[SystemZ::FeatureVectorEnhancements3]) HasVectorEnhancements3 = true;
  if (Bits[SystemZ::FeatureVectorPackedDecimal]) HasVectorPackedDecimal = true;
  if (Bits[SystemZ::FeatureVectorPackedDecimalEnhancement]) HasVectorPackedDecimalEnhancement = true;
  if (Bits[SystemZ::FeatureVectorPackedDecimalEnhancement2]) HasVectorPackedDecimalEnhancement2 = true;
  if (Bits[SystemZ::FeatureVectorPackedDecimalEnhancement3]) HasVectorPackedDecimalEnhancement3 = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace SystemZ_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace SystemZ_MC
struct SystemZGenSubtargetInfo : public TargetSubtargetInfo {
  explicit SystemZGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class SystemZHwModeBits : unsigned {
    DefaultMode = 0,
    NoVecHwMode = (1 << 0),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/NoVecHwMode),
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

extern const llvm_ks::StringRef SystemZNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<49, 4176> SystemZFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<17, 99> SystemZSubTypeKVStorage;
extern const llvm_ks::MCSchedModel SystemZSchedModels[];
extern const llvm_ks::MCWriteProcResEntry SystemZWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry SystemZWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry SystemZReadAdvanceTable[];
SystemZGenSubtargetInfo::SystemZGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(SystemZSubTypeKVStorage.Strings), ArrayRef(SystemZFeatureKVStorage.Features), ArrayRef(SystemZSubTypeKVStorage.SubTypes), SystemZSchedModels, 
                        SystemZWriteProcResTable, SystemZWriteLatencyTable, SystemZReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned SystemZGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // SystemZGenSubtargetInfo::resolveSchedClass

unsigned SystemZGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return SystemZ_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // SystemZGenSubtargetInfo::resolveVariantSchedClass

unsigned SystemZGenSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const auto *Subtarget =
      static_cast<const SystemZSubtarget *>(this);
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((!Subtarget->hasVector())) Modes |= (1 << 0);
  return Modes;
}
unsigned SystemZGenSubtargetInfo::getHwMode(enum HwModeType type) const {
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
const FeatureBitset &SystemZGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &SystemZGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &SystemZGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

