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

namespace Sparc {

enum {
  DetectRoundChange = 0,
  Feature64Bit = 1,
  FeatureCrypto = 2,
  FeatureHardQuad = 3,
  FeatureLeon = 4,
  FeatureNoFMULS = 5,
  FeatureNoFSMULD = 6,
  FeatureOSA2011 = 7,
  FeaturePWRPSR = 8,
  FeatureReserveG1 = 9,
  FeatureReserveG2 = 10,
  FeatureReserveG3 = 11,
  FeatureReserveG4 = 12,
  FeatureReserveG5 = 13,
  FeatureReserveG6 = 14,
  FeatureReserveG7 = 15,
  FeatureReserveI0 = 16,
  FeatureReserveI1 = 17,
  FeatureReserveI2 = 18,
  FeatureReserveI3 = 19,
  FeatureReserveI4 = 20,
  FeatureReserveI5 = 21,
  FeatureReserveL0 = 22,
  FeatureReserveL1 = 23,
  FeatureReserveL2 = 24,
  FeatureReserveL3 = 25,
  FeatureReserveL4 = 26,
  FeatureReserveL5 = 27,
  FeatureReserveL6 = 28,
  FeatureReserveL7 = 29,
  FeatureReserveO0 = 30,
  FeatureReserveO1 = 31,
  FeatureReserveO2 = 32,
  FeatureReserveO3 = 33,
  FeatureReserveO4 = 34,
  FeatureReserveO5 = 35,
  FeatureSoftFloat = 36,
  FeatureSoftMulDiv = 37,
  FeatureUA2005 = 38,
  FeatureUA2007 = 39,
  FeatureV8Deprecated = 40,
  FeatureV8Plus = 41,
  FeatureV9 = 42,
  FeatureVIS = 43,
  FeatureVIS2 = 44,
  FeatureVIS3 = 45,
  FixAllFDIVSQRT = 46,
  FixTN0009 = 47,
  FixTN0010 = 48,
  FixTN0011 = 49,
  FixTN0012 = 50,
  FixTN0013 = 51,
  InsertNOPLoad = 52,
  LeonCASA = 53,
  LeonCycleCounter = 54,
  TuneNoPredictor = 55,
  TuneSlowRDPC = 56,
  UMACSMACSupport = 57,
  UsePopc = 58,
  NumSubtargetFeatures = 59
};

} // namespace Sparc

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(DetectRoundChange, false, detectRoundChange)
GET_SUBTARGETINFO_MACRO(FixAllFDIVSQRT, false, fixAllFDIVSQRT)
GET_SUBTARGETINFO_MACRO(FixTN0009, false, fixTN0009)
GET_SUBTARGETINFO_MACRO(FixTN0010, false, fixTN0010)
GET_SUBTARGETINFO_MACRO(FixTN0011, false, fixTN0011)
GET_SUBTARGETINFO_MACRO(FixTN0012, false, fixTN0012)
GET_SUBTARGETINFO_MACRO(FixTN0013, false, fixTN0013)
GET_SUBTARGETINFO_MACRO(HasHardQuad, false, hasHardQuad)
GET_SUBTARGETINFO_MACRO(HasLeonCasa, false, hasLeonCasa)
GET_SUBTARGETINFO_MACRO(HasLeonCycleCounter, false, hasLeonCycleCounter)
GET_SUBTARGETINFO_MACRO(HasNoFMULS, false, hasNoFMULS)
GET_SUBTARGETINFO_MACRO(HasNoFSMULD, false, hasNoFSMULD)
GET_SUBTARGETINFO_MACRO(HasNoPredictor, false, hasNoPredictor)
GET_SUBTARGETINFO_MACRO(HasPWRPSR, false, hasPWRPSR)
GET_SUBTARGETINFO_MACRO(HasSlowRDPC, false, hasSlowRDPC)
GET_SUBTARGETINFO_MACRO(HasUmacSmac, false, hasUmacSmac)
GET_SUBTARGETINFO_MACRO(InsertNOPLoad, false, insertNOPLoad)
GET_SUBTARGETINFO_MACRO(Is64Bit, false, is64Bit)
GET_SUBTARGETINFO_MACRO(IsCrypto, false, isCrypto)
GET_SUBTARGETINFO_MACRO(IsLeon, false, isLeon)
GET_SUBTARGETINFO_MACRO(IsOSA2011, false, isOSA2011)
GET_SUBTARGETINFO_MACRO(IsUA2005, false, isUA2005)
GET_SUBTARGETINFO_MACRO(IsUA2007, false, isUA2007)
GET_SUBTARGETINFO_MACRO(IsV8Plus, false, isV8Plus)
GET_SUBTARGETINFO_MACRO(IsV9, false, isV9)
GET_SUBTARGETINFO_MACRO(IsVIS, false, isVIS)
GET_SUBTARGETINFO_MACRO(IsVIS2, false, isVIS2)
GET_SUBTARGETINFO_MACRO(IsVIS3, false, isVIS3)
GET_SUBTARGETINFO_MACRO(UsePopc, false, usePopc)
GET_SUBTARGETINFO_MACRO(UseSoftFloat, false, useSoftFloat)
GET_SUBTARGETINFO_MACRO(UseSoftMulDiv, false, useSoftMulDiv)
GET_SUBTARGETINFO_MACRO(UseV8DeprecatedInsts, false, useV8DeprecatedInsts)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 59, 3417> SparcFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 59 + 1, sizeof(SubtargetFeatureKV) * 59 + 7, Sparc::Feature64Bit, { { { 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 58 + 26, sizeof(SubtargetFeatureKV) * 58 + 33, Sparc::FeatureCrypto, { { { 0x80ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 57 + 65, sizeof(SubtargetFeatureKV) * 57 + 79, Sparc::FeatureV8Deprecated, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 56 + 124, sizeof(SubtargetFeatureKV) * 56 + 142, Sparc::DetectRoundChange, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 55 + 253, sizeof(SubtargetFeatureKV) * 55 + 264, Sparc::FixTN0009, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 54 + 320, sizeof(SubtargetFeatureKV) * 54 + 331, Sparc::FixTN0010, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 53 + 387, sizeof(SubtargetFeatureKV) * 53 + 398, Sparc::FixTN0011, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 52 + 454, sizeof(SubtargetFeatureKV) * 52 + 465, Sparc::FixTN0012, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 51 + 521, sizeof(SubtargetFeatureKV) * 51 + 532, Sparc::FixTN0013, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 50 + 588, sizeof(SubtargetFeatureKV) * 50 + 603, Sparc::FixAllFDIVSQRT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 49 + 699, sizeof(SubtargetFeatureKV) * 49 + 715, Sparc::FeatureHardQuad, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 48 + 760, sizeof(SubtargetFeatureKV) * 48 + 772, Sparc::LeonCASA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 47 + 827, sizeof(SubtargetFeatureKV) * 47 + 839, Sparc::UMACSMACSupport, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 46 + 891, sizeof(SubtargetFeatureKV) * 46 + 905, Sparc::InsertNOPLoad, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 45 + 1051, sizeof(SubtargetFeatureKV) * 45 + 1056, Sparc::FeatureLeon, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 44 + 1079, sizeof(SubtargetFeatureKV) * 44 + 1096, Sparc::LeonCycleCounter, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 43 + 1132, sizeof(SubtargetFeatureKV) * 43 + 1143, Sparc::FeaturePWRPSR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 42 + 1173, sizeof(SubtargetFeatureKV) * 42 + 1182, Sparc::FeatureNoFMULS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 41 + 1213, sizeof(SubtargetFeatureKV) * 41 + 1223, Sparc::FeatureNoFSMULD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 40 + 1255, sizeof(SubtargetFeatureKV) * 40 + 1268, Sparc::TuneNoPredictor, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 39 + 1328, sizeof(SubtargetFeatureKV) * 39 + 1336, Sparc::FeatureOSA2011, { { { 0x3c0000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 38 + 1385, sizeof(SubtargetFeatureKV) * 38 + 1390, Sparc::UsePopc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 1434, sizeof(SubtargetFeatureKV) * 37 + 1445, Sparc::FeatureReserveG1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 1488, sizeof(SubtargetFeatureKV) * 36 + 1499, Sparc::FeatureReserveG2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 1542, sizeof(SubtargetFeatureKV) * 35 + 1553, Sparc::FeatureReserveG3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 1596, sizeof(SubtargetFeatureKV) * 34 + 1607, Sparc::FeatureReserveG4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 1650, sizeof(SubtargetFeatureKV) * 33 + 1661, Sparc::FeatureReserveG5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 1704, sizeof(SubtargetFeatureKV) * 32 + 1715, Sparc::FeatureReserveG6, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 1758, sizeof(SubtargetFeatureKV) * 31 + 1769, Sparc::FeatureReserveG7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 1812, sizeof(SubtargetFeatureKV) * 30 + 1823, Sparc::FeatureReserveI0, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 1866, sizeof(SubtargetFeatureKV) * 29 + 1877, Sparc::FeatureReserveI1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 1920, sizeof(SubtargetFeatureKV) * 28 + 1931, Sparc::FeatureReserveI2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 1974, sizeof(SubtargetFeatureKV) * 27 + 1985, Sparc::FeatureReserveI3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 2028, sizeof(SubtargetFeatureKV) * 26 + 2039, Sparc::FeatureReserveI4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 2082, sizeof(SubtargetFeatureKV) * 25 + 2093, Sparc::FeatureReserveI5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 2136, sizeof(SubtargetFeatureKV) * 24 + 2147, Sparc::FeatureReserveL0, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 2190, sizeof(SubtargetFeatureKV) * 23 + 2201, Sparc::FeatureReserveL1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 2244, sizeof(SubtargetFeatureKV) * 22 + 2255, Sparc::FeatureReserveL2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 2298, sizeof(SubtargetFeatureKV) * 21 + 2309, Sparc::FeatureReserveL3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 2352, sizeof(SubtargetFeatureKV) * 20 + 2363, Sparc::FeatureReserveL4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 2406, sizeof(SubtargetFeatureKV) * 19 + 2417, Sparc::FeatureReserveL5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 2460, sizeof(SubtargetFeatureKV) * 18 + 2471, Sparc::FeatureReserveL6, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 2514, sizeof(SubtargetFeatureKV) * 17 + 2525, Sparc::FeatureReserveL7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 2568, sizeof(SubtargetFeatureKV) * 16 + 2579, Sparc::FeatureReserveO0, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 2622, sizeof(SubtargetFeatureKV) * 15 + 2633, Sparc::FeatureReserveO1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 2676, sizeof(SubtargetFeatureKV) * 14 + 2687, Sparc::FeatureReserveO2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 2730, sizeof(SubtargetFeatureKV) * 13 + 2741, Sparc::FeatureReserveO3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 2784, sizeof(SubtargetFeatureKV) * 12 + 2795, Sparc::FeatureReserveO4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 2838, sizeof(SubtargetFeatureKV) * 11 + 2849, Sparc::FeatureReserveO5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 2892, sizeof(SubtargetFeatureKV) * 10 + 2902, Sparc::TuneSlowRDPC, { { { 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 2922, sizeof(SubtargetFeatureKV) * 9 + 2933, Sparc::FeatureSoftFloat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 2975, sizeof(SubtargetFeatureKV) * 8 + 2988, Sparc::FeatureSoftMulDiv, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 3043, sizeof(SubtargetFeatureKV) * 7 + 3050, Sparc::FeatureUA2005, { { { 0x1c0000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 3097, sizeof(SubtargetFeatureKV) * 6 + 3104, Sparc::FeatureUA2007, { { { 0x1c0000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 3151, sizeof(SubtargetFeatureKV) * 5 + 3158, Sparc::FeatureV8Plus, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 3229, sizeof(SubtargetFeatureKV) * 4 + 3232, Sparc::FeatureV9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 3261, sizeof(SubtargetFeatureKV) * 3 + 3265, Sparc::FeatureVIS, { { { 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 3317, sizeof(SubtargetFeatureKV) * 2 + 3322, Sparc::FeatureVIS2, { { { 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 3366, sizeof(SubtargetFeatureKV) * 1 + 3371, Sparc::FeatureVIS3, { { { 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000" "64bit\000Enable 64-bit mode\000crypto\000Enable cryptographic ex"
    "tensions\000deprecated-v8\000Enable deprecated V8 instructions in V9 mo"
    "de\000detectroundchange\000LEON3 erratum detection: Detects any roundin"
    "g mode change request: use only the round-to-nearest rounding mode\000f"
    "ix-tn0009\000Enable workaround for errata described in GRLIB-TN-0009\000"
    "fix-tn0010\000Enable workaround for errata described in GRLIB-TN-0010\000"
    "fix-tn0011\000Enable workaround for errata described in GRLIB-TN-0011\000"
    "fix-tn0012\000Enable workaround for errata described in GRLIB-TN-0012\000"
    "fix-tn0013\000Enable workaround for errata described in GRLIB-TN-0013\000"
    "fixallfdivsqrt\000LEON erratum fix: Fix FDIVS/FDIVD/FSQRTS/FSQRTD instr"
    "uctions with NOPs and floating-point store\000hard-quad-float\000Enable"
    " quad-word floating point instructions\000hasleoncasa\000Enable CASA in"
    "struction for LEON3 and LEON4 processors\000hasumacsmac\000Enable UMAC "
    "and SMAC for LEON3 and LEON4 processors\000insertnopload\000LEON3 errat"
    "um fix: Insert a NOP instruction after every single-cycle load instruct"
    "ion when the next instruction is another load/store instruction\000leon"
    "\000Enable LEON extensions\000leoncyclecounter\000Use the Leon cycle co"
    "unter register\000leonpwrpsr\000Enable the PWRPSR instruction\000no-fmu"
    "ls\000Disable the fmuls instruction.\000no-fsmuld\000Disable the fsmuld"
    " instruction.\000no-predictor\000Processor has no branch predictor, bra"
    "nches stall execution\000osa2011\000Enable Oracle SPARC Architecture 20"
    "11 extensions\000popc\000Use the popc (population count) instruction\000"
    "reserve-g1\000Reserve G1, making it unavailable as a GPR\000reserve-g2\000"
    "Reserve G2, making it unavailable as a GPR\000reserve-g3\000Reserve G3,"
    " making it unavailable as a GPR\000reserve-g4\000Reserve G4, making it "
    "unavailable as a GPR\000reserve-g5\000Reserve G5, making it unavailable"
    " as a GPR\000reserve-g6\000Reserve G6, making it unavailable as a GPR\000"
    "reserve-g7\000Reserve G7, making it unavailable as a GPR\000reserve-i0\000"
    "Reserve I0, making it unavailable as a GPR\000reserve-i1\000Reserve I1,"
    " making it unavailable as a GPR\000reserve-i2\000Reserve I2, making it "
    "unavailable as a GPR\000reserve-i3\000Reserve I3, making it unavailable"
    " as a GPR\000reserve-i4\000Reserve I4, making it unavailable as a GPR\000"
    "reserve-i5\000Reserve I5, making it unavailable as a GPR\000reserve-l0\000"
    "Reserve L0, making it unavailable as a GPR\000reserve-l1\000Reserve L1,"
    " making it unavailable as a GPR\000reserve-l2\000Reserve L2, making it "
    "unavailable as a GPR\000reserve-l3\000Reserve L3, making it unavailable"
    " as a GPR\000reserve-l4\000Reserve L4, making it unavailable as a GPR\000"
    "reserve-l5\000Reserve L5, making it unavailable as a GPR\000reserve-l6\000"
    "Reserve L6, making it unavailable as a GPR\000reserve-l7\000Reserve L7,"
    " making it unavailable as a GPR\000reserve-o0\000Reserve O0, making it "
    "unavailable as a GPR\000reserve-o1\000Reserve O1, making it unavailable"
    " as a GPR\000reserve-o2\000Reserve O2, making it unavailable as a GPR\000"
    "reserve-o3\000Reserve O3, making it unavailable as a GPR\000reserve-o4\000"
    "Reserve O4, making it unavailable as a GPR\000reserve-o5\000Reserve O5,"
    " making it unavailable as a GPR\000slow-rdpc\000rd %pc, %XX is slow\000"
    "soft-float\000Use software emulation for floating point\000soft-mul-div"
    "\000Use software emulation for integer multiply and divide\000ua2005\000"
    "Enable UltraSPARC Architecture 2005 extensions\000ua2007\000Enable Ultr"
    "aSPARC Architecture 2007 extensions\000v8plus\000Enable V8+ mode, allow"
    "ing use of 64-bit V9 instructions in 32-bit code\000v9\000Enable SPARC-"
    "V9 instructions\000vis\000Enable UltraSPARC Visual Instruction Set exte"
    "nsions\000vis2\000Enable Visual Instruction Set extensions II\000vis3\000"
    "Enable Visual Instruction Set extensions III\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 40, 310> SparcSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 40 + 1, { { { 0x10000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 39 + 8, { { { 0x10000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 38 + 15, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 37 + 20, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 36 + 28, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 35 + 36, { { { 0x260000000000110ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 34 + 42, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 33 + 53, { { { 0x10ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 32 + 59, { { { 0x220000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 31 + 65, { { { 0x220000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 30 + 71, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 29 + 78, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 28 + 85, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 27 + 92, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 26 + 99, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 25 + 106, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 24 + 113, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 23 + 120, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 22 + 127, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 21 + 134, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 20 + 141, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 19 + 148, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 18 + 156, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 17 + 166, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 16 + 176, { { { 0x20000000000010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 15 + 186, { { { 0x1d4000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x80000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 14 + 194, { { { 0x4001d4000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x80000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 13 + 203, { { { 0x4003dc000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x80000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 12 + 212, { { { 0x4003dc000000084ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 11 + 221, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 10 + 230, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 9 + 240, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 8 + 253, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 7 + 264, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 6 + 271, { { { 0xd0000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x100000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 5 + 282, { { { 0x1d0000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x100000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 4 + 294, { { { 0x10400000000070ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 3 + 300, { { { 0x2000000040ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 2 + 303, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 1 + 306, { { { 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
  },
    "\000at697e\000at697f\000f934\000generic\000gr712rc\000gr740\000hyperspa"
    "rc\000leon2\000leon3\000leon4\000ma2080\000ma2085\000ma2100\000ma2150\000"
    "ma2155\000ma2450\000ma2455\000ma2480\000ma2485\000ma2x5x\000ma2x8x\000m"
    "yriad2\000myriad2.1\000myriad2.2\000myriad2.3\000niagara\000niagara2\000"
    "niagara3\000niagara4\000sparclet\000sparclite\000sparclite86x\000supers"
    "parc\000tsc701\000ultrasparc\000ultrasparc3\000ut699\000v7\000v8\000v9\000"};

namespace Sparc_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace Sparc_MC
struct SparcGenMCSubtargetInfo : public MCSubtargetInfo {
  SparcGenMCSubtargetInfo(const Triple &TT,
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
    return Sparc_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned SparcGenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (FB[Sparc::Feature64Bit]) Modes |= (1 << 0);
  return Modes;
}
unsigned SparcGenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
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

static inline MCSubtargetInfo *createSparcMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new SparcGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(SparcSubTypeKVStorage.Strings), SparcFeatureKVStorage.Features, SparcSubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::SparcSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[Sparc::DetectRoundChange]) DetectRoundChange = true;
  if (Bits[Sparc::Feature64Bit]) Is64Bit = true;
  if (Bits[Sparc::FeatureCrypto]) IsCrypto = true;
  if (Bits[Sparc::FeatureHardQuad]) HasHardQuad = true;
  if (Bits[Sparc::FeatureLeon]) IsLeon = true;
  if (Bits[Sparc::FeatureNoFMULS]) HasNoFMULS = true;
  if (Bits[Sparc::FeatureNoFSMULD]) HasNoFSMULD = true;
  if (Bits[Sparc::FeatureOSA2011]) IsOSA2011 = true;
  if (Bits[Sparc::FeaturePWRPSR]) HasPWRPSR = true;
  if (Bits[Sparc::FeatureReserveG1]) ReserveRegister[1 + SP::G0] = true;
  if (Bits[Sparc::FeatureReserveG2]) ReserveRegister[2 + SP::G0] = true;
  if (Bits[Sparc::FeatureReserveG3]) ReserveRegister[3 + SP::G0] = true;
  if (Bits[Sparc::FeatureReserveG4]) ReserveRegister[4 + SP::G0] = true;
  if (Bits[Sparc::FeatureReserveG5]) ReserveRegister[5 + SP::G0] = true;
  if (Bits[Sparc::FeatureReserveG6]) ReserveRegister[6 + SP::G0] = true;
  if (Bits[Sparc::FeatureReserveG7]) ReserveRegister[7 + SP::G0] = true;
  if (Bits[Sparc::FeatureReserveI0]) ReserveRegister[0 + SP::I0] = true;
  if (Bits[Sparc::FeatureReserveI1]) ReserveRegister[1 + SP::I0] = true;
  if (Bits[Sparc::FeatureReserveI2]) ReserveRegister[2 + SP::I0] = true;
  if (Bits[Sparc::FeatureReserveI3]) ReserveRegister[3 + SP::I0] = true;
  if (Bits[Sparc::FeatureReserveI4]) ReserveRegister[4 + SP::I0] = true;
  if (Bits[Sparc::FeatureReserveI5]) ReserveRegister[5 + SP::I0] = true;
  if (Bits[Sparc::FeatureReserveL0]) ReserveRegister[0 + SP::L0] = true;
  if (Bits[Sparc::FeatureReserveL1]) ReserveRegister[1 + SP::L0] = true;
  if (Bits[Sparc::FeatureReserveL2]) ReserveRegister[2 + SP::L0] = true;
  if (Bits[Sparc::FeatureReserveL3]) ReserveRegister[3 + SP::L0] = true;
  if (Bits[Sparc::FeatureReserveL4]) ReserveRegister[4 + SP::L0] = true;
  if (Bits[Sparc::FeatureReserveL5]) ReserveRegister[5 + SP::L0] = true;
  if (Bits[Sparc::FeatureReserveL6]) ReserveRegister[6 + SP::L0] = true;
  if (Bits[Sparc::FeatureReserveL7]) ReserveRegister[7 + SP::L0] = true;
  if (Bits[Sparc::FeatureReserveO0]) ReserveRegister[0 + SP::O0] = true;
  if (Bits[Sparc::FeatureReserveO1]) ReserveRegister[1 + SP::O0] = true;
  if (Bits[Sparc::FeatureReserveO2]) ReserveRegister[2 + SP::O0] = true;
  if (Bits[Sparc::FeatureReserveO3]) ReserveRegister[3 + SP::O0] = true;
  if (Bits[Sparc::FeatureReserveO4]) ReserveRegister[4 + SP::O0] = true;
  if (Bits[Sparc::FeatureReserveO5]) ReserveRegister[5 + SP::O0] = true;
  if (Bits[Sparc::FeatureSoftFloat]) UseSoftFloat = true;
  if (Bits[Sparc::FeatureSoftMulDiv]) UseSoftMulDiv = true;
  if (Bits[Sparc::FeatureUA2005]) IsUA2005 = true;
  if (Bits[Sparc::FeatureUA2007]) IsUA2007 = true;
  if (Bits[Sparc::FeatureV8Deprecated]) UseV8DeprecatedInsts = true;
  if (Bits[Sparc::FeatureV8Plus]) IsV8Plus = true;
  if (Bits[Sparc::FeatureV9]) IsV9 = true;
  if (Bits[Sparc::FeatureVIS]) IsVIS = true;
  if (Bits[Sparc::FeatureVIS2]) IsVIS2 = true;
  if (Bits[Sparc::FeatureVIS3]) IsVIS3 = true;
  if (Bits[Sparc::FixAllFDIVSQRT]) FixAllFDIVSQRT = true;
  if (Bits[Sparc::FixTN0009]) FixTN0009 = true;
  if (Bits[Sparc::FixTN0010]) FixTN0010 = true;
  if (Bits[Sparc::FixTN0011]) FixTN0011 = true;
  if (Bits[Sparc::FixTN0012]) FixTN0012 = true;
  if (Bits[Sparc::FixTN0013]) FixTN0013 = true;
  if (Bits[Sparc::InsertNOPLoad]) InsertNOPLoad = true;
  if (Bits[Sparc::LeonCASA]) HasLeonCasa = true;
  if (Bits[Sparc::LeonCycleCounter]) HasLeonCycleCounter = true;
  if (Bits[Sparc::TuneNoPredictor]) HasNoPredictor = true;
  if (Bits[Sparc::TuneSlowRDPC]) HasSlowRDPC = true;
  if (Bits[Sparc::UMACSMACSupport]) HasUmacSmac = true;
  if (Bits[Sparc::UsePopc]) UsePopc = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace Sparc_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace Sparc_MC
struct SparcGenSubtargetInfo : public TargetSubtargetInfo {
  explicit SparcGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class SparcHwModeBits : unsigned {
    DefaultMode = 0,
    SPARC64 = (1 << 0),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/SPARC64),
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

extern const llvm_ks::StringRef SparcNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<59, 3417> SparcFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<40, 310> SparcSubTypeKVStorage;
extern const llvm_ks::MCSchedModel SparcSchedModels[];
extern const llvm_ks::MCWriteProcResEntry SparcWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry SparcWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry SparcReadAdvanceTable[];
extern const llvm_ks::InstrStage SparcStages[];
extern const unsigned SparcOperandCycles[];
extern const unsigned SparcForwardingPaths[];
SparcGenSubtargetInfo::SparcGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(SparcSubTypeKVStorage.Strings), ArrayRef(SparcFeatureKVStorage.Features), ArrayRef(SparcSubTypeKVStorage.SubTypes), SparcSchedModels, 
                        SparcWriteProcResTable, SparcWriteLatencyTable, SparcReadAdvanceTable, 
                        SparcStages, SparcOperandCycles, SparcForwardingPaths) {}

unsigned SparcGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // SparcGenSubtargetInfo::resolveSchedClass

unsigned SparcGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return Sparc_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // SparcGenSubtargetInfo::resolveVariantSchedClass

unsigned SparcGenSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const auto *Subtarget =
      static_cast<const SparcSubtarget *>(this);
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((Subtarget->is64Bit())) Modes |= (1 << 0);
  return Modes;
}
unsigned SparcGenSubtargetInfo::getHwMode(enum HwModeType type) const {
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
const FeatureBitset &SparcGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &SparcGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &SparcGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

