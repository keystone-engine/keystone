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

namespace Hexagon {

enum {
  ArchV5 = 0,
  ArchV55 = 1,
  ArchV60 = 2,
  ArchV62 = 3,
  ArchV65 = 4,
  ArchV66 = 5,
  ArchV67 = 6,
  ArchV68 = 7,
  ArchV69 = 8,
  ArchV71 = 9,
  ArchV73 = 10,
  ArchV75 = 11,
  ArchV79 = 12,
  ArchV81 = 13,
  ExtensionAudio = 14,
  ExtensionHVX = 15,
  ExtensionHVX64B = 16,
  ExtensionHVX128B = 17,
  ExtensionHVXIEEEFP = 18,
  ExtensionHVXQFloat = 19,
  ExtensionHVXV60 = 20,
  ExtensionHVXV62 = 21,
  ExtensionHVXV65 = 22,
  ExtensionHVXV66 = 23,
  ExtensionHVXV67 = 24,
  ExtensionHVXV68 = 25,
  ExtensionHVXV69 = 26,
  ExtensionHVXV71 = 27,
  ExtensionHVXV73 = 28,
  ExtensionHVXV75 = 29,
  ExtensionHVXV79 = 30,
  ExtensionHVXV81 = 31,
  ExtensionZReg = 32,
  FeatureCabac = 33,
  FeatureCompound = 34,
  FeatureDuplex = 35,
  FeatureLongCalls = 36,
  FeatureMemNoShuf = 37,
  FeatureMemops = 38,
  FeatureNVJ = 39,
  FeatureNVS = 40,
  FeatureNoreturnStackElim = 41,
  FeaturePackets = 42,
  FeaturePreV65 = 43,
  FeatureReservedR6 = 44,
  FeatureReservedR7 = 45,
  FeatureReservedR8 = 46,
  FeatureReservedR9 = 47,
  FeatureReservedR10 = 48,
  FeatureReservedR11 = 49,
  FeatureReservedR12 = 50,
  FeatureReservedR13 = 51,
  FeatureReservedR14 = 52,
  FeatureReservedR15 = 53,
  FeatureReservedR16 = 54,
  FeatureReservedR17 = 55,
  FeatureReservedR18 = 56,
  FeatureReservedR19 = 57,
  FeatureReservedR20 = 58,
  FeatureReservedR21 = 59,
  FeatureReservedR22 = 60,
  FeatureReservedR23 = 61,
  FeatureReservedR24 = 62,
  FeatureReservedR25 = 63,
  FeatureReservedR26 = 64,
  FeatureReservedR27 = 65,
  FeatureReservedR28 = 66,
  FeatureSCSRegR16 = 67,
  FeatureSCSRegR17 = 68,
  FeatureSCSRegR18 = 69,
  FeatureSCSRegR19 = 70,
  FeatureSCSRegR20 = 71,
  FeatureSCSRegR21 = 72,
  FeatureSCSRegR22 = 73,
  FeatureSCSRegR23 = 74,
  FeatureSCSRegR24 = 75,
  FeatureSCSRegR25 = 76,
  FeatureSCSRegR26 = 77,
  FeatureSCSRegR27 = 78,
  FeatureSmallData = 79,
  ProcTinyCore = 80,
  NumSubtargetFeatures = 81
};

} // namespace Hexagon

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(EnableDuplex, false, enableDuplex)
GET_SUBTARGETINFO_MACRO(HasMemNoShuf, true, hasMemNoShuf)
GET_SUBTARGETINFO_MACRO(HasPreV65, false, hasPreV65)
GET_SUBTARGETINFO_MACRO(NoreturnStackElim, false, noreturnStackElim)
GET_SUBTARGETINFO_MACRO(UseAudioOps, false, useAudioOps)
GET_SUBTARGETINFO_MACRO(UseCabac, true, useCabac)
GET_SUBTARGETINFO_MACRO(UseCompound, false, useCompound)
GET_SUBTARGETINFO_MACRO(UseHVX128BOps, false, useHVX128BOps)
GET_SUBTARGETINFO_MACRO(UseHVX64BOps, false, useHVX64BOps)
GET_SUBTARGETINFO_MACRO(UseHVXIEEEFPOps, false, useHVXIEEEFPOps)
GET_SUBTARGETINFO_MACRO(UseHVXQFloatOps, false, useHVXQFloatOps)
GET_SUBTARGETINFO_MACRO(UseLongCalls, false, useLongCalls)
GET_SUBTARGETINFO_MACRO(UseMemops, false, useMemops)
GET_SUBTARGETINFO_MACRO(UseNewValueJumps, false, useNewValueJumps)
GET_SUBTARGETINFO_MACRO(UseNewValueStores, false, useNewValueStores)
GET_SUBTARGETINFO_MACRO(UsePackets, false, usePackets)
GET_SUBTARGETINFO_MACRO(UseSmallData, false, useSmallData)
GET_SUBTARGETINFO_MACRO(UseZRegOps, false, useZRegOps)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 81, 2957> HexagonFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 81 + 1, sizeof(SubtargetFeatureKV) * 81 + 7, Hexagon::ExtensionAudio, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 80 + 44, sizeof(SubtargetFeatureKV) * 80 + 50, Hexagon::FeatureCabac, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 79 + 77, sizeof(SubtargetFeatureKV) * 79 + 86, Hexagon::FeatureCompound, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 78 + 112, sizeof(SubtargetFeatureKV) * 78 + 119, Hexagon::FeatureDuplex, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 77 + 159, sizeof(SubtargetFeatureKV) * 77 + 163, Hexagon::ExtensionHVX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 76 + 188, sizeof(SubtargetFeatureKV) * 76 + 200, Hexagon::ExtensionHVXIEEEFP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 75 + 245, sizeof(SubtargetFeatureKV) * 75 + 260, Hexagon::ExtensionHVX128B, { { { 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 74 + 290, sizeof(SubtargetFeatureKV) * 74 + 304, Hexagon::ExtensionHVX64B, { { { 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 73 + 333, sizeof(SubtargetFeatureKV) * 73 + 344, Hexagon::ExtensionHVXQFloat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 72 + 385, sizeof(SubtargetFeatureKV) * 72 + 163, Hexagon::ExtensionHVXV60, { { { 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 71 + 392, sizeof(SubtargetFeatureKV) * 71 + 163, Hexagon::ExtensionHVXV62, { { { 0x108000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 70 + 399, sizeof(SubtargetFeatureKV) * 70 + 163, Hexagon::ExtensionHVXV65, { { { 0x308000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 69 + 406, sizeof(SubtargetFeatureKV) * 69 + 163, Hexagon::ExtensionHVXV66, { { { 0x100708000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 68 + 413, sizeof(SubtargetFeatureKV) * 68 + 163, Hexagon::ExtensionHVXV67, { { { 0xf00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 67 + 420, sizeof(SubtargetFeatureKV) * 67 + 163, Hexagon::ExtensionHVXV68, { { { 0x1f00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 66 + 427, sizeof(SubtargetFeatureKV) * 66 + 163, Hexagon::ExtensionHVXV69, { { { 0x3f00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 65 + 434, sizeof(SubtargetFeatureKV) * 65 + 163, Hexagon::ExtensionHVXV71, { { { 0x7f00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 64 + 441, sizeof(SubtargetFeatureKV) * 64 + 163, Hexagon::ExtensionHVXV73, { { { 0xff00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 63 + 448, sizeof(SubtargetFeatureKV) * 63 + 163, Hexagon::ExtensionHVXV75, { { { 0x1ff00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 62 + 455, sizeof(SubtargetFeatureKV) * 62 + 163, Hexagon::ExtensionHVXV79, { { { 0x3ff00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 61 + 462, sizeof(SubtargetFeatureKV) * 61 + 163, Hexagon::ExtensionHVXV81, { { { 0x7fc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 60 + 469, sizeof(SubtargetFeatureKV) * 60 + 480, Hexagon::FeatureLongCalls, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 59 + 508, sizeof(SubtargetFeatureKV) * 59 + 519, Hexagon::FeatureMemNoShuf, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 58 + 547, sizeof(SubtargetFeatureKV) * 58 + 554, Hexagon::FeatureMemops, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 57 + 577, sizeof(SubtargetFeatureKV) * 57 + 597, Hexagon::FeatureNoreturnStackElim, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 56 + 661, sizeof(SubtargetFeatureKV) * 56 + 665, Hexagon::FeatureNVJ, { { { 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 55 + 693, sizeof(SubtargetFeatureKV) * 55 + 697, Hexagon::FeatureNVS, { { { 0x40000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 54 + 726, sizeof(SubtargetFeatureKV) * 54 + 734, Hexagon::FeaturePackets, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 53 + 766, sizeof(SubtargetFeatureKV) * 53 + 773, Hexagon::FeaturePreV65, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 52 + 808, sizeof(SubtargetFeatureKV) * 52 + 821, Hexagon::FeatureReservedR10, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 51 + 842, sizeof(SubtargetFeatureKV) * 51 + 855, Hexagon::FeatureReservedR11, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 50 + 876, sizeof(SubtargetFeatureKV) * 50 + 889, Hexagon::FeatureReservedR12, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 49 + 910, sizeof(SubtargetFeatureKV) * 49 + 923, Hexagon::FeatureReservedR13, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 48 + 944, sizeof(SubtargetFeatureKV) * 48 + 957, Hexagon::FeatureReservedR14, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 47 + 978, sizeof(SubtargetFeatureKV) * 47 + 991, Hexagon::FeatureReservedR15, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 46 + 1012, sizeof(SubtargetFeatureKV) * 46 + 1025, Hexagon::FeatureReservedR16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 45 + 1046, sizeof(SubtargetFeatureKV) * 45 + 1059, Hexagon::FeatureReservedR17, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 44 + 1080, sizeof(SubtargetFeatureKV) * 44 + 1093, Hexagon::FeatureReservedR18, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 43 + 1114, sizeof(SubtargetFeatureKV) * 43 + 1127, Hexagon::FeatureReservedR19, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 42 + 1148, sizeof(SubtargetFeatureKV) * 42 + 1161, Hexagon::FeatureReservedR20, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 41 + 1182, sizeof(SubtargetFeatureKV) * 41 + 1195, Hexagon::FeatureReservedR21, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 40 + 1216, sizeof(SubtargetFeatureKV) * 40 + 1229, Hexagon::FeatureReservedR22, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 39 + 1250, sizeof(SubtargetFeatureKV) * 39 + 1263, Hexagon::FeatureReservedR23, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 38 + 1284, sizeof(SubtargetFeatureKV) * 38 + 1297, Hexagon::FeatureReservedR24, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 1318, sizeof(SubtargetFeatureKV) * 37 + 1331, Hexagon::FeatureReservedR25, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 1352, sizeof(SubtargetFeatureKV) * 36 + 1365, Hexagon::FeatureReservedR26, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 1386, sizeof(SubtargetFeatureKV) * 35 + 1399, Hexagon::FeatureReservedR27, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 1420, sizeof(SubtargetFeatureKV) * 34 + 1433, Hexagon::FeatureReservedR28, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 1454, sizeof(SubtargetFeatureKV) * 33 + 1466, Hexagon::FeatureReservedR6, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 1486, sizeof(SubtargetFeatureKV) * 32 + 1498, Hexagon::FeatureReservedR7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 1518, sizeof(SubtargetFeatureKV) * 31 + 1530, Hexagon::FeatureReservedR8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 1550, sizeof(SubtargetFeatureKV) * 30 + 1562, Hexagon::FeatureReservedR9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 1582, sizeof(SubtargetFeatureKV) * 29 + 1594, Hexagon::FeatureSCSRegR16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 1644, sizeof(SubtargetFeatureKV) * 28 + 1656, Hexagon::FeatureSCSRegR17, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 1706, sizeof(SubtargetFeatureKV) * 27 + 1718, Hexagon::FeatureSCSRegR18, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 1768, sizeof(SubtargetFeatureKV) * 26 + 1780, Hexagon::FeatureSCSRegR19, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 1830, sizeof(SubtargetFeatureKV) * 25 + 1842, Hexagon::FeatureSCSRegR20, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 1892, sizeof(SubtargetFeatureKV) * 24 + 1904, Hexagon::FeatureSCSRegR21, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 1954, sizeof(SubtargetFeatureKV) * 23 + 1966, Hexagon::FeatureSCSRegR22, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 2016, sizeof(SubtargetFeatureKV) * 22 + 2028, Hexagon::FeatureSCSRegR23, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 2078, sizeof(SubtargetFeatureKV) * 21 + 2090, Hexagon::FeatureSCSRegR24, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 2140, sizeof(SubtargetFeatureKV) * 20 + 2152, Hexagon::FeatureSCSRegR25, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 2202, sizeof(SubtargetFeatureKV) * 19 + 2214, Hexagon::FeatureSCSRegR26, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 2264, sizeof(SubtargetFeatureKV) * 18 + 2276, Hexagon::FeatureSCSRegR27, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 2326, sizeof(SubtargetFeatureKV) * 17 + 2337, Hexagon::FeatureSmallData, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 2386, sizeof(SubtargetFeatureKV) * 16 + 2395, Hexagon::ProcTinyCore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 2413, sizeof(SubtargetFeatureKV) * 15 + 2416, Hexagon::ArchV5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 2447, sizeof(SubtargetFeatureKV) * 14 + 2451, Hexagon::ArchV55, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 2483, sizeof(SubtargetFeatureKV) * 13 + 2487, Hexagon::ArchV60, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 2519, sizeof(SubtargetFeatureKV) * 12 + 2523, Hexagon::ArchV62, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 2555, sizeof(SubtargetFeatureKV) * 11 + 2559, Hexagon::ArchV65, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 2591, sizeof(SubtargetFeatureKV) * 10 + 2595, Hexagon::ArchV66, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 2627, sizeof(SubtargetFeatureKV) * 9 + 2631, Hexagon::ArchV67, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 2663, sizeof(SubtargetFeatureKV) * 8 + 2667, Hexagon::ArchV68, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 2699, sizeof(SubtargetFeatureKV) * 7 + 2703, Hexagon::ArchV69, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 2735, sizeof(SubtargetFeatureKV) * 6 + 2739, Hexagon::ArchV71, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 2771, sizeof(SubtargetFeatureKV) * 5 + 2775, Hexagon::ArchV73, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 2807, sizeof(SubtargetFeatureKV) * 4 + 2811, Hexagon::ArchV75, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 2843, sizeof(SubtargetFeatureKV) * 3 + 2847, Hexagon::ArchV79, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 2879, sizeof(SubtargetFeatureKV) * 2 + 2883, Hexagon::ArchV81, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 2915, sizeof(SubtargetFeatureKV) * 1 + 2920, Hexagon::ExtensionZReg, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000audio\000Hexagon Audio extension instructions\000cabac\000Emit the "
    "CABAC instruction\000compound\000Use compound instructions\000duplex\000"
    "Enable generation of duplex instruction\000hvx\000Hexagon HVX instructi"
    "ons\000hvx-ieee-fp\000Hexagon HVX IEEE floating point instructions\000h"
    "vx-length128b\000Hexagon HVX 128B instructions\000hvx-length64b\000Hexa"
    "gon HVX 64B instructions\000hvx-qfloat\000Hexagon HVX QFloating point i"
    "nstructions\000hvxv60\000hvxv62\000hvxv65\000hvxv66\000hvxv67\000hvxv68"
    "\000hvxv69\000hvxv71\000hvxv73\000hvxv75\000hvxv79\000hvxv81\000long-ca"
    "lls\000Use constant-extended calls\000mem_noshuf\000Supports mem_noshuf"
    " feature\000memops\000Use memop instructions\000noreturn-stack-elim\000"
    "Eliminate stack allocation in a noreturn function when possible\000nvj\000"
    "Support for new-value jumps\000nvs\000Support for new-value stores\000p"
    "ackets\000Support for instruction packets\000prev65\000Support features"
    " deprecated in v65\000reserved-r10\000Reserve register R10\000reserved-"
    "r11\000Reserve register R11\000reserved-r12\000Reserve register R12\000"
    "reserved-r13\000Reserve register R13\000reserved-r14\000Reserve registe"
    "r R14\000reserved-r15\000Reserve register R15\000reserved-r16\000Reserv"
    "e register R16\000reserved-r17\000Reserve register R17\000reserved-r18\000"
    "Reserve register R18\000reserved-r19\000Reserve register R19\000reserve"
    "d-r20\000Reserve register R20\000reserved-r21\000Reserve register R21\000"
    "reserved-r22\000Reserve register R22\000reserved-r23\000Reserve registe"
    "r R23\000reserved-r24\000Reserve register R24\000reserved-r25\000Reserv"
    "e register R25\000reserved-r26\000Reserve register R26\000reserved-r27\000"
    "Reserve register R27\000reserved-r28\000Reserve register R28\000reserve"
    "d-r6\000Reserve register R6\000reserved-r7\000Reserve register R7\000re"
    "served-r8\000Reserve register R8\000reserved-r9\000Reserve register R9\000"
    "scs-reg-r16\000Use register R16 as the shadow call stack pointer\000scs"
    "-reg-r17\000Use register R17 as the shadow call stack pointer\000scs-re"
    "g-r18\000Use register R18 as the shadow call stack pointer\000scs-reg-r"
    "19\000Use register R19 as the shadow call stack pointer\000scs-reg-r20\000"
    "Use register R20 as the shadow call stack pointer\000scs-reg-r21\000Use"
    " register R21 as the shadow call stack pointer\000scs-reg-r22\000Use re"
    "gister R22 as the shadow call stack pointer\000scs-reg-r23\000Use regis"
    "ter R23 as the shadow call stack pointer\000scs-reg-r24\000Use register"
    " R24 as the shadow call stack pointer\000scs-reg-r25\000Use register R2"
    "5 as the shadow call stack pointer\000scs-reg-r26\000Use register R26 a"
    "s the shadow call stack pointer\000scs-reg-r27\000Use register R27 as t"
    "he shadow call stack pointer\000small-data\000Allow GP-relative address"
    "ing of global variables\000tinycore\000Hexagon Tiny Core\000v5\000Enabl"
    "e Hexagon V5 architecture\000v55\000Enable Hexagon V55 architecture\000"
    "v60\000Enable Hexagon V60 architecture\000v62\000Enable Hexagon V62 arc"
    "hitecture\000v65\000Enable Hexagon V65 architecture\000v66\000Enable He"
    "xagon V66 architecture\000v67\000Enable Hexagon V67 architecture\000v68"
    "\000Enable Hexagon V68 architecture\000v69\000Enable Hexagon V69 archit"
    "ecture\000v71\000Enable Hexagon V71 architecture\000v73\000Enable Hexag"
    "on V73 architecture\000v75\000Enable Hexagon V75 architecture\000v79\000"
    "Enable Hexagon V79 architecture\000v81\000Enable Hexagon V81 architectu"
    "re\000zreg\000Hexagon ZReg extension instructions\000"};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
#define DBGFIELD(x) x,
#define DBGVAL_OR_NULLPTR(x) x
#else
#define DBGFIELD(x)
#define DBGVAL_OR_NULLPTR(x) nullptr
#endif

// Functional units for "HexagonItinerariesV60"
namespace HexagonItinerariesV60FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV60FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV60"
namespace HexagonItinerariesV60Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV60Bypass

// Functional units for "HexagonItinerariesV5"
namespace HexagonItinerariesV5FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;

} // namespace HexagonItinerariesV5FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV5"
namespace HexagonItinerariesV5Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;

} // namespace HexagonItinerariesV5Bypass

// Functional units for "HexagonItinerariesV55"
namespace HexagonItinerariesV55FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;

} // namespace HexagonItinerariesV55FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV55"
namespace HexagonItinerariesV55Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;

} // namespace HexagonItinerariesV55Bypass

// Functional units for "HexagonItinerariesV62"
namespace HexagonItinerariesV62FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV62FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV62"
namespace HexagonItinerariesV62Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV62Bypass

// Functional units for "HexagonItinerariesV65"
namespace HexagonItinerariesV65FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV65FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV65"
namespace HexagonItinerariesV65Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV65Bypass

// Functional units for "HexagonItinerariesV66"
namespace HexagonItinerariesV66FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV66FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV66"
namespace HexagonItinerariesV66Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV66Bypass

// Functional units for "HexagonItinerariesV67"
namespace HexagonItinerariesV67FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV67FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV67"
namespace HexagonItinerariesV67Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV67Bypass

// Functional units for "HexagonItinerariesV67T"
namespace HexagonItinerariesV67TFU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV67TFU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV67T"
namespace HexagonItinerariesV67TBypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV67TBypass

// Functional units for "HexagonItinerariesV68"
namespace HexagonItinerariesV68FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV68FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV68"
namespace HexagonItinerariesV68Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV68Bypass

// Functional units for "HexagonItinerariesV69"
namespace HexagonItinerariesV69FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV69FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV69"
namespace HexagonItinerariesV69Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV69Bypass

// Functional units for "HexagonItinerariesV71"
namespace HexagonItinerariesV71FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV71FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV71"
namespace HexagonItinerariesV71Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV71Bypass

// Functional units for "HexagonItinerariesV71T"
namespace HexagonItinerariesV71TFU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV71TFU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV71T"
namespace HexagonItinerariesV71TBypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV71TBypass

// Functional units for "HexagonItinerariesV73"
namespace HexagonItinerariesV73FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV73FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV73"
namespace HexagonItinerariesV73Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV73Bypass

// Functional units for "HexagonItinerariesV75"
namespace HexagonItinerariesV75FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV75FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV75"
namespace HexagonItinerariesV75Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV75Bypass

// Functional units for "HexagonItinerariesV79"
namespace HexagonItinerariesV79FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV79FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV79"
namespace HexagonItinerariesV79Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV79Bypass

// Functional units for "HexagonItinerariesV81"
namespace HexagonItinerariesV81FU {

  const InstrStage::FuncUnits SLOT0 = 1ULL << 0;
  const InstrStage::FuncUnits SLOT1 = 1ULL << 1;
  const InstrStage::FuncUnits SLOT2 = 1ULL << 2;
  const InstrStage::FuncUnits SLOT3 = 1ULL << 3;
  const InstrStage::FuncUnits SLOT_ENDLOOP = 1ULL << 4;
  const InstrStage::FuncUnits CVI_ST = 1ULL << 5;
  const InstrStage::FuncUnits CVI_XLANE = 1ULL << 6;
  const InstrStage::FuncUnits CVI_SHIFT = 1ULL << 7;
  const InstrStage::FuncUnits CVI_MPY0 = 1ULL << 8;
  const InstrStage::FuncUnits CVI_MPY1 = 1ULL << 9;
  const InstrStage::FuncUnits CVI_LD = 1ULL << 10;
  const InstrStage::FuncUnits CVI_XLSHF = 1ULL << 11;
  const InstrStage::FuncUnits CVI_MPY01 = 1ULL << 12;
  const InstrStage::FuncUnits CVI_ALL = 1ULL << 13;
  const InstrStage::FuncUnits CVI_ALL_NOMEM = 1ULL << 14;
  const InstrStage::FuncUnits CVI_ZW = 1ULL << 15;

} // namespace HexagonItinerariesV81FU

// Pipeline forwarding paths for itineraries "HexagonItinerariesV81"
namespace HexagonItinerariesV81Bypass {

  const unsigned NoBypass = 0;
  const unsigned Hex_FWD = 1 << 0;
  const unsigned HVX_FWD = 1 << 1;

} // namespace HexagonItinerariesV81Bypass

extern const llvm_ks::InstrStage HexagonStages[] = {
  { 0, 0, 0, llvm_ks::InstrStage::Required }, // No itinerary
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 1
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 2
  { 1, HexagonItinerariesV60FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 3
  { 1, HexagonItinerariesV60FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 4
  { 1, HexagonItinerariesV60FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 5
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 6
  { 1, HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 7
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1 | HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 8-9
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY01 | HexagonItinerariesV60FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 10-11
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1 | HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 12-14
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 15-16
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 17-18
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1 | HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 19-21
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE | HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 22-23
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY01 | HexagonItinerariesV60FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 24-27
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1 | HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 28-29
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 30-31
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 32-33
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 34-37
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 38-39
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 40-43
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 44-45
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 46-47
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 48-49
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 50-51
  { 1, HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1 | HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 52-54
  { 1, HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY01 | HexagonItinerariesV60FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 55-57
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 58-59
  { 1, HexagonItinerariesV60FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 60-61
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 62-64
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 65-66
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY01 | HexagonItinerariesV60FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 67-69
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 70-71
  { 1, HexagonItinerariesV5FU::SLOT2 | HexagonItinerariesV5FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 72
  { 1, HexagonItinerariesV5FU::SLOT0 | HexagonItinerariesV5FU::SLOT1 | HexagonItinerariesV5FU::SLOT2 | HexagonItinerariesV5FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 73
  { 1, HexagonItinerariesV5FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 74
  { 1, HexagonItinerariesV5FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 75
  { 1, HexagonItinerariesV5FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 76
  { 1, HexagonItinerariesV5FU::SLOT0 | HexagonItinerariesV5FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 77
  { 1, HexagonItinerariesV5FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 78
  { 1, HexagonItinerariesV5FU::SLOT2 | HexagonItinerariesV5FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV5FU::SLOT2 | HexagonItinerariesV5FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 79-80
  { 1, HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 81
  { 1, HexagonItinerariesV55FU::SLOT0 | HexagonItinerariesV55FU::SLOT1 | HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 82
  { 1, HexagonItinerariesV55FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 83
  { 1, HexagonItinerariesV55FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 84
  { 1, HexagonItinerariesV55FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 85
  { 1, HexagonItinerariesV55FU::SLOT0 | HexagonItinerariesV55FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 86
  { 1, HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 87
  { 1, HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 88-89
  { 1, HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 90
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1 | HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 91
  { 1, HexagonItinerariesV62FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 92
  { 1, HexagonItinerariesV62FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 93
  { 1, HexagonItinerariesV62FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 94
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 95
  { 1, HexagonItinerariesV62FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 96
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1 | HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY0 | HexagonItinerariesV62FU::CVI_MPY1 | HexagonItinerariesV62FU::CVI_SHIFT | HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 97-98
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1 | HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY01 | HexagonItinerariesV62FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 99-100
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY0 | HexagonItinerariesV62FU::CVI_MPY1 | HexagonItinerariesV62FU::CVI_SHIFT | HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 101-103
  { 1, HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 104-105
  { 1, HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY0 | HexagonItinerariesV62FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 106-107
  { 1, HexagonItinerariesV62FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY0 | HexagonItinerariesV62FU::CVI_MPY1 | HexagonItinerariesV62FU::CVI_SHIFT | HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 108-110
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1 | HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_XLANE | HexagonItinerariesV62FU::CVI_SHIFT | HexagonItinerariesV62FU::CVI_MPY0 | HexagonItinerariesV62FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 111-112
  { 1, HexagonItinerariesV62FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY01 | HexagonItinerariesV62FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 113-116
  { 1, HexagonItinerariesV62FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY0 | HexagonItinerariesV62FU::CVI_MPY1 | HexagonItinerariesV62FU::CVI_SHIFT | HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 117-118
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1 | HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 119-120
  { 1, HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 121-122
  { 1, HexagonItinerariesV62FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 123-126
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 127-128
  { 1, HexagonItinerariesV62FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 129-132
  { 1, HexagonItinerariesV62FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 133-134
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1 | HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_SHIFT | HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 135-136
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1 | HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 137-138
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1 | HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 139-140
  { 1, HexagonItinerariesV62FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY0 | HexagonItinerariesV62FU::CVI_MPY1 | HexagonItinerariesV62FU::CVI_SHIFT | HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 141-143
  { 1, HexagonItinerariesV62FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY01 | HexagonItinerariesV62FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 144-146
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1 | HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 147-148
  { 1, HexagonItinerariesV62FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 149-150
  { 1, HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY0 | HexagonItinerariesV62FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_SHIFT | HexagonItinerariesV62FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 151-153
  { 1, HexagonItinerariesV62FU::SLOT2 | HexagonItinerariesV62FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 154-155
  { 1, HexagonItinerariesV62FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_MPY01 | HexagonItinerariesV62FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 156-158
  { 1, HexagonItinerariesV62FU::SLOT0 | HexagonItinerariesV62FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV62FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 159-160
  { 1, HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 161
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1 | HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 162
  { 1, HexagonItinerariesV65FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 163
  { 1, HexagonItinerariesV65FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 164
  { 1, HexagonItinerariesV65FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 165
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 166
  { 1, HexagonItinerariesV65FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 167
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1 | HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY0 | HexagonItinerariesV65FU::CVI_MPY1 | HexagonItinerariesV65FU::CVI_SHIFT | HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 168-169
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1 | HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY01 | HexagonItinerariesV65FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 170-171
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY0 | HexagonItinerariesV65FU::CVI_MPY1 | HexagonItinerariesV65FU::CVI_SHIFT | HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 172-174
  { 1, HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 175-176
  { 1, HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY0 | HexagonItinerariesV65FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 177-178
  { 1, HexagonItinerariesV65FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY0 | HexagonItinerariesV65FU::CVI_MPY1 | HexagonItinerariesV65FU::CVI_SHIFT | HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 179-181
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1 | HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_XLANE | HexagonItinerariesV65FU::CVI_SHIFT | HexagonItinerariesV65FU::CVI_MPY0 | HexagonItinerariesV65FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 182-183
  { 1, HexagonItinerariesV65FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY01 | HexagonItinerariesV65FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 184-187
  { 1, HexagonItinerariesV65FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY0 | HexagonItinerariesV65FU::CVI_MPY1 | HexagonItinerariesV65FU::CVI_SHIFT | HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 188-189
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1 | HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 190-191
  { 1, HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 192-193
  { 1, HexagonItinerariesV65FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 194-197
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 198-199
  { 1, HexagonItinerariesV65FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 200-203
  { 1, HexagonItinerariesV65FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 204-205
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1 | HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_SHIFT | HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 206-207
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1 | HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 208-209
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1 | HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 210-211
  { 1, HexagonItinerariesV65FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY0 | HexagonItinerariesV65FU::CVI_MPY1 | HexagonItinerariesV65FU::CVI_SHIFT | HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 212-214
  { 1, HexagonItinerariesV65FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY01 | HexagonItinerariesV65FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 215-217
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1 | HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 218-219
  { 1, HexagonItinerariesV65FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 220-221
  { 1, HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY0 | HexagonItinerariesV65FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_SHIFT | HexagonItinerariesV65FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 222-224
  { 1, HexagonItinerariesV65FU::SLOT2 | HexagonItinerariesV65FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 225-226
  { 1, HexagonItinerariesV65FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_MPY01 | HexagonItinerariesV65FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 227-229
  { 1, HexagonItinerariesV65FU::SLOT0 | HexagonItinerariesV65FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV65FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 230-231
  { 1, HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 232
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1 | HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 233
  { 1, HexagonItinerariesV66FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 234
  { 1, HexagonItinerariesV66FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 235
  { 1, HexagonItinerariesV66FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 236
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 237
  { 1, HexagonItinerariesV66FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 238
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1 | HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY0 | HexagonItinerariesV66FU::CVI_MPY1 | HexagonItinerariesV66FU::CVI_SHIFT | HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 239-240
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1 | HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY01 | HexagonItinerariesV66FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 241-242
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY0 | HexagonItinerariesV66FU::CVI_MPY1 | HexagonItinerariesV66FU::CVI_SHIFT | HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 243-245
  { 1, HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 246-247
  { 1, HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY0 | HexagonItinerariesV66FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 248-249
  { 1, HexagonItinerariesV66FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY0 | HexagonItinerariesV66FU::CVI_MPY1 | HexagonItinerariesV66FU::CVI_SHIFT | HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 250-252
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1 | HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_XLANE | HexagonItinerariesV66FU::CVI_SHIFT | HexagonItinerariesV66FU::CVI_MPY0 | HexagonItinerariesV66FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 253-254
  { 1, HexagonItinerariesV66FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY01 | HexagonItinerariesV66FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 255-258
  { 1, HexagonItinerariesV66FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY0 | HexagonItinerariesV66FU::CVI_MPY1 | HexagonItinerariesV66FU::CVI_SHIFT | HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 259-260
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1 | HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 261-262
  { 1, HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 263-264
  { 1, HexagonItinerariesV66FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 265-268
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 269-270
  { 1, HexagonItinerariesV66FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 271-274
  { 1, HexagonItinerariesV66FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 275-276
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1 | HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_SHIFT | HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 277-278
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1 | HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 279-280
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1 | HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 281-282
  { 1, HexagonItinerariesV66FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY0 | HexagonItinerariesV66FU::CVI_MPY1 | HexagonItinerariesV66FU::CVI_SHIFT | HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 283-285
  { 1, HexagonItinerariesV66FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY01 | HexagonItinerariesV66FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 286-288
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1 | HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 289-290
  { 1, HexagonItinerariesV66FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 291-292
  { 1, HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY0 | HexagonItinerariesV66FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_SHIFT | HexagonItinerariesV66FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 293-295
  { 1, HexagonItinerariesV66FU::SLOT2 | HexagonItinerariesV66FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 296-297
  { 1, HexagonItinerariesV66FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_MPY01 | HexagonItinerariesV66FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 298-300
  { 1, HexagonItinerariesV66FU::SLOT0 | HexagonItinerariesV66FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV66FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 301-302
  { 1, HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 303
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1 | HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 304
  { 1, HexagonItinerariesV67FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 305
  { 1, HexagonItinerariesV67FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 306
  { 1, HexagonItinerariesV67FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 307
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 308
  { 1, HexagonItinerariesV67FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 309
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1 | HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY0 | HexagonItinerariesV67FU::CVI_MPY1 | HexagonItinerariesV67FU::CVI_SHIFT | HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 310-311
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1 | HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY01 | HexagonItinerariesV67FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 312-313
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY0 | HexagonItinerariesV67FU::CVI_MPY1 | HexagonItinerariesV67FU::CVI_SHIFT | HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 314-316
  { 1, HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 317-318
  { 1, HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY0 | HexagonItinerariesV67FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 319-320
  { 1, HexagonItinerariesV67FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY0 | HexagonItinerariesV67FU::CVI_MPY1 | HexagonItinerariesV67FU::CVI_SHIFT | HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 321-323
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1 | HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_XLANE | HexagonItinerariesV67FU::CVI_SHIFT | HexagonItinerariesV67FU::CVI_MPY0 | HexagonItinerariesV67FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 324-325
  { 1, HexagonItinerariesV67FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY01 | HexagonItinerariesV67FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 326-329
  { 1, HexagonItinerariesV67FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY0 | HexagonItinerariesV67FU::CVI_MPY1 | HexagonItinerariesV67FU::CVI_SHIFT | HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 330-331
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1 | HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 332-333
  { 1, HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 334-335
  { 1, HexagonItinerariesV67FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 336-339
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 340-341
  { 1, HexagonItinerariesV67FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 342-345
  { 1, HexagonItinerariesV67FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 346-347
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1 | HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_SHIFT | HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 348-349
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1 | HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 350-351
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1 | HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 352-353
  { 1, HexagonItinerariesV67FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY0 | HexagonItinerariesV67FU::CVI_MPY1 | HexagonItinerariesV67FU::CVI_SHIFT | HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 354-356
  { 1, HexagonItinerariesV67FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY01 | HexagonItinerariesV67FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 357-359
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1 | HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 360-361
  { 1, HexagonItinerariesV67FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 362-363
  { 1, HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY0 | HexagonItinerariesV67FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_SHIFT | HexagonItinerariesV67FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 364-366
  { 1, HexagonItinerariesV67FU::SLOT2 | HexagonItinerariesV67FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 367-368
  { 1, HexagonItinerariesV67FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_MPY01 | HexagonItinerariesV67FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 369-371
  { 1, HexagonItinerariesV67FU::SLOT0 | HexagonItinerariesV67FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 372-373
  { 1, HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 374
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 375
  { 1, HexagonItinerariesV67TFU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 376
  { 1, HexagonItinerariesV67TFU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 377
  { 1, HexagonItinerariesV67TFU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 378
  { 1, HexagonItinerariesV67TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 379
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY0 | HexagonItinerariesV67TFU::CVI_MPY1 | HexagonItinerariesV67TFU::CVI_SHIFT | HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 380-381
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY01 | HexagonItinerariesV67TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 382-383
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY0 | HexagonItinerariesV67TFU::CVI_MPY1 | HexagonItinerariesV67TFU::CVI_SHIFT | HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 384-386
  { 1, HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 387-388
  { 1, HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY0 | HexagonItinerariesV67TFU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 389-390
  { 1, HexagonItinerariesV67TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY0 | HexagonItinerariesV67TFU::CVI_MPY1 | HexagonItinerariesV67TFU::CVI_SHIFT | HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 391-393
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_XLANE | HexagonItinerariesV67TFU::CVI_SHIFT | HexagonItinerariesV67TFU::CVI_MPY0 | HexagonItinerariesV67TFU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 394-395
  { 1, HexagonItinerariesV67TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY01 | HexagonItinerariesV67TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 396-399
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 400
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 401
  { 1, HexagonItinerariesV67TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY0 | HexagonItinerariesV67TFU::CVI_MPY1 | HexagonItinerariesV67TFU::CVI_SHIFT | HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 402-403
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 404-405
  { 1, HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 406-407
  { 1, HexagonItinerariesV67TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 408-411
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 412-413
  { 1, HexagonItinerariesV67TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 414-417
  { 1, HexagonItinerariesV67TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 418-419
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_SHIFT | HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 420-421
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 422-423
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 424-425
  { 1, HexagonItinerariesV67TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY0 | HexagonItinerariesV67TFU::CVI_MPY1 | HexagonItinerariesV67TFU::CVI_SHIFT | HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 426-428
  { 1, HexagonItinerariesV67TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY01 | HexagonItinerariesV67TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 429-431
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1 | HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 432-433
  { 1, HexagonItinerariesV67TFU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 434-435
  { 1, HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY0 | HexagonItinerariesV67TFU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_SHIFT | HexagonItinerariesV67TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 436-438
  { 1, HexagonItinerariesV67TFU::SLOT2 | HexagonItinerariesV67TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 439-440
  { 1, HexagonItinerariesV67TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_MPY01 | HexagonItinerariesV67TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 441-443
  { 1, HexagonItinerariesV67TFU::SLOT0 | HexagonItinerariesV67TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV67TFU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 444-445
  { 1, HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 446
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1 | HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 447
  { 1, HexagonItinerariesV68FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 448
  { 1, HexagonItinerariesV68FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 449
  { 1, HexagonItinerariesV68FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 450
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 451
  { 1, HexagonItinerariesV68FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 452
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1 | HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY0 | HexagonItinerariesV68FU::CVI_MPY1 | HexagonItinerariesV68FU::CVI_SHIFT | HexagonItinerariesV68FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 453-454
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1 | HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY01 | HexagonItinerariesV68FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 455-456
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY0 | HexagonItinerariesV68FU::CVI_MPY1 | HexagonItinerariesV68FU::CVI_SHIFT | HexagonItinerariesV68FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 457-459
  { 1, HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 460-461
  { 1, HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY0 | HexagonItinerariesV68FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 462-463
  { 1, HexagonItinerariesV68FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY0 | HexagonItinerariesV68FU::CVI_MPY1 | HexagonItinerariesV68FU::CVI_SHIFT | HexagonItinerariesV68FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 464-466
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1 | HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_XLANE | HexagonItinerariesV68FU::CVI_SHIFT | HexagonItinerariesV68FU::CVI_MPY0 | HexagonItinerariesV68FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 467-468
  { 1, HexagonItinerariesV68FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY01 | HexagonItinerariesV68FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 469-472
  { 1, HexagonItinerariesV68FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY0 | HexagonItinerariesV68FU::CVI_MPY1 | HexagonItinerariesV68FU::CVI_SHIFT | HexagonItinerariesV68FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 473-474
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1 | HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 475-476
  { 1, HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 477-478
  { 1, HexagonItinerariesV68FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 479-482
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 483-484
  { 1, HexagonItinerariesV68FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 485-488
  { 1, HexagonItinerariesV68FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 489-490
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1 | HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_SHIFT | HexagonItinerariesV68FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 491-492
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1 | HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 493-494
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1 | HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 495-496
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY01 | HexagonItinerariesV68FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 497-499
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1 | HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 500-501
  { 1, HexagonItinerariesV68FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 502-503
  { 1, HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY0 | HexagonItinerariesV68FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_SHIFT | HexagonItinerariesV68FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 504-506
  { 1, HexagonItinerariesV68FU::SLOT2 | HexagonItinerariesV68FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 507-508
  { 1, HexagonItinerariesV68FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_MPY01 | HexagonItinerariesV68FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 509-511
  { 1, HexagonItinerariesV68FU::SLOT0 | HexagonItinerariesV68FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV68FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 512-513
  { 1, HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 514
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1 | HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 515
  { 1, HexagonItinerariesV69FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 516
  { 1, HexagonItinerariesV69FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 517
  { 1, HexagonItinerariesV69FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 518
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 519
  { 1, HexagonItinerariesV69FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 520
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1 | HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY0 | HexagonItinerariesV69FU::CVI_MPY1 | HexagonItinerariesV69FU::CVI_SHIFT | HexagonItinerariesV69FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 521-522
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1 | HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY01 | HexagonItinerariesV69FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 523-524
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY0 | HexagonItinerariesV69FU::CVI_MPY1 | HexagonItinerariesV69FU::CVI_SHIFT | HexagonItinerariesV69FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 525-527
  { 1, HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 528-529
  { 1, HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY0 | HexagonItinerariesV69FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 530-531
  { 1, HexagonItinerariesV69FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY0 | HexagonItinerariesV69FU::CVI_MPY1 | HexagonItinerariesV69FU::CVI_SHIFT | HexagonItinerariesV69FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 532-534
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1 | HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_XLANE | HexagonItinerariesV69FU::CVI_SHIFT | HexagonItinerariesV69FU::CVI_MPY0 | HexagonItinerariesV69FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 535-536
  { 1, HexagonItinerariesV69FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY01 | HexagonItinerariesV69FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 537-540
  { 1, HexagonItinerariesV69FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY0 | HexagonItinerariesV69FU::CVI_MPY1 | HexagonItinerariesV69FU::CVI_SHIFT | HexagonItinerariesV69FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 541-542
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1 | HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 543-544
  { 1, HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 545-546
  { 1, HexagonItinerariesV69FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 547-550
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 551-552
  { 1, HexagonItinerariesV69FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 553-556
  { 1, HexagonItinerariesV69FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 557-558
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1 | HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_SHIFT | HexagonItinerariesV69FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 559-560
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1 | HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 561-562
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1 | HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 563-564
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY01 | HexagonItinerariesV69FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 565-567
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1 | HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 568-569
  { 1, HexagonItinerariesV69FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 570-571
  { 1, HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY0 | HexagonItinerariesV69FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_SHIFT | HexagonItinerariesV69FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 572-574
  { 1, HexagonItinerariesV69FU::SLOT2 | HexagonItinerariesV69FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 575-576
  { 1, HexagonItinerariesV69FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_MPY01 | HexagonItinerariesV69FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 577-579
  { 1, HexagonItinerariesV69FU::SLOT0 | HexagonItinerariesV69FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV69FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 580-581
  { 1, HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 582
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1 | HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 583
  { 1, HexagonItinerariesV71FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 584
  { 1, HexagonItinerariesV71FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 585
  { 1, HexagonItinerariesV71FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 586
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 587
  { 1, HexagonItinerariesV71FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 588
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1 | HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY0 | HexagonItinerariesV71FU::CVI_MPY1 | HexagonItinerariesV71FU::CVI_SHIFT | HexagonItinerariesV71FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 589-590
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1 | HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY01 | HexagonItinerariesV71FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 591-592
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY0 | HexagonItinerariesV71FU::CVI_MPY1 | HexagonItinerariesV71FU::CVI_SHIFT | HexagonItinerariesV71FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 593-595
  { 1, HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 596-597
  { 1, HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY0 | HexagonItinerariesV71FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 598-599
  { 1, HexagonItinerariesV71FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY0 | HexagonItinerariesV71FU::CVI_MPY1 | HexagonItinerariesV71FU::CVI_SHIFT | HexagonItinerariesV71FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 600-602
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1 | HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_XLANE | HexagonItinerariesV71FU::CVI_SHIFT | HexagonItinerariesV71FU::CVI_MPY0 | HexagonItinerariesV71FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 603-604
  { 1, HexagonItinerariesV71FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY01 | HexagonItinerariesV71FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 605-608
  { 1, HexagonItinerariesV71FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY0 | HexagonItinerariesV71FU::CVI_MPY1 | HexagonItinerariesV71FU::CVI_SHIFT | HexagonItinerariesV71FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 609-610
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1 | HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 611-612
  { 1, HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 613-614
  { 1, HexagonItinerariesV71FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 615-618
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 619-620
  { 1, HexagonItinerariesV71FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 621-624
  { 1, HexagonItinerariesV71FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 625-626
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1 | HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_SHIFT | HexagonItinerariesV71FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 627-628
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1 | HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 629-630
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1 | HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 631-632
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY01 | HexagonItinerariesV71FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 633-635
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1 | HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 636-637
  { 1, HexagonItinerariesV71FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 638-639
  { 1, HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY0 | HexagonItinerariesV71FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_SHIFT | HexagonItinerariesV71FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 640-642
  { 1, HexagonItinerariesV71FU::SLOT2 | HexagonItinerariesV71FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 643-644
  { 1, HexagonItinerariesV71FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_MPY01 | HexagonItinerariesV71FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 645-647
  { 1, HexagonItinerariesV71FU::SLOT0 | HexagonItinerariesV71FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 648-649
  { 1, HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 650
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 651
  { 1, HexagonItinerariesV71TFU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 652
  { 1, HexagonItinerariesV71TFU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 653
  { 1, HexagonItinerariesV71TFU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 654
  { 1, HexagonItinerariesV71TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 655
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY0 | HexagonItinerariesV71TFU::CVI_MPY1 | HexagonItinerariesV71TFU::CVI_SHIFT | HexagonItinerariesV71TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 656-657
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY01 | HexagonItinerariesV71TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 658-659
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY0 | HexagonItinerariesV71TFU::CVI_MPY1 | HexagonItinerariesV71TFU::CVI_SHIFT | HexagonItinerariesV71TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 660-662
  { 1, HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 663-664
  { 1, HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY0 | HexagonItinerariesV71TFU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 665-666
  { 1, HexagonItinerariesV71TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY0 | HexagonItinerariesV71TFU::CVI_MPY1 | HexagonItinerariesV71TFU::CVI_SHIFT | HexagonItinerariesV71TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 667-669
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_XLANE | HexagonItinerariesV71TFU::CVI_SHIFT | HexagonItinerariesV71TFU::CVI_MPY0 | HexagonItinerariesV71TFU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 670-671
  { 1, HexagonItinerariesV71TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY01 | HexagonItinerariesV71TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 672-675
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 676
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 677
  { 1, HexagonItinerariesV71TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY0 | HexagonItinerariesV71TFU::CVI_MPY1 | HexagonItinerariesV71TFU::CVI_SHIFT | HexagonItinerariesV71TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 678-679
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 680-681
  { 1, HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 682-683
  { 1, HexagonItinerariesV71TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 684-687
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 688-689
  { 1, HexagonItinerariesV71TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 690-693
  { 1, HexagonItinerariesV71TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 694-695
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_SHIFT | HexagonItinerariesV71TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 696-697
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 698-699
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 700-701
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY01 | HexagonItinerariesV71TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 702-704
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1 | HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 705-706
  { 1, HexagonItinerariesV71TFU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 707-708
  { 1, HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY0 | HexagonItinerariesV71TFU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_SHIFT | HexagonItinerariesV71TFU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 709-711
  { 1, HexagonItinerariesV71TFU::SLOT2 | HexagonItinerariesV71TFU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 712-713
  { 1, HexagonItinerariesV71TFU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_MPY01 | HexagonItinerariesV71TFU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 714-716
  { 1, HexagonItinerariesV71TFU::SLOT0 | HexagonItinerariesV71TFU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV71TFU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 717-718
  { 1, HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 719
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1 | HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 720
  { 1, HexagonItinerariesV73FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 721
  { 1, HexagonItinerariesV73FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 722
  { 1, HexagonItinerariesV73FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 723
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 724
  { 1, HexagonItinerariesV73FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 725
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1 | HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY0 | HexagonItinerariesV73FU::CVI_MPY1 | HexagonItinerariesV73FU::CVI_SHIFT | HexagonItinerariesV73FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 726-727
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1 | HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY01 | HexagonItinerariesV73FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 728-729
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY0 | HexagonItinerariesV73FU::CVI_MPY1 | HexagonItinerariesV73FU::CVI_SHIFT | HexagonItinerariesV73FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 730-732
  { 1, HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 733-734
  { 1, HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY0 | HexagonItinerariesV73FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 735-736
  { 1, HexagonItinerariesV73FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY0 | HexagonItinerariesV73FU::CVI_MPY1 | HexagonItinerariesV73FU::CVI_SHIFT | HexagonItinerariesV73FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 737-739
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1 | HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_XLANE | HexagonItinerariesV73FU::CVI_SHIFT | HexagonItinerariesV73FU::CVI_MPY0 | HexagonItinerariesV73FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 740-741
  { 1, HexagonItinerariesV73FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY01 | HexagonItinerariesV73FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 742-745
  { 1, HexagonItinerariesV73FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY0 | HexagonItinerariesV73FU::CVI_MPY1 | HexagonItinerariesV73FU::CVI_SHIFT | HexagonItinerariesV73FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 746-747
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1 | HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 748-749
  { 1, HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 750-751
  { 1, HexagonItinerariesV73FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 752-755
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 756-757
  { 1, HexagonItinerariesV73FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 758-761
  { 1, HexagonItinerariesV73FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 762-763
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1 | HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_SHIFT | HexagonItinerariesV73FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 764-765
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1 | HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 766-767
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1 | HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 768-769
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY01 | HexagonItinerariesV73FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 770-772
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1 | HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 773-774
  { 1, HexagonItinerariesV73FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 775-776
  { 1, HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY0 | HexagonItinerariesV73FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_SHIFT | HexagonItinerariesV73FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 777-779
  { 1, HexagonItinerariesV73FU::SLOT2 | HexagonItinerariesV73FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 780-781
  { 1, HexagonItinerariesV73FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_MPY01 | HexagonItinerariesV73FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 782-784
  { 1, HexagonItinerariesV73FU::SLOT0 | HexagonItinerariesV73FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV73FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 785-786
  { 1, HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 787
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1 | HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 788
  { 1, HexagonItinerariesV75FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 789
  { 1, HexagonItinerariesV75FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 790
  { 1, HexagonItinerariesV75FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 791
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 792
  { 1, HexagonItinerariesV75FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 793
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1 | HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY0 | HexagonItinerariesV75FU::CVI_MPY1 | HexagonItinerariesV75FU::CVI_SHIFT | HexagonItinerariesV75FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 794-795
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1 | HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY01 | HexagonItinerariesV75FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 796-797
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY0 | HexagonItinerariesV75FU::CVI_MPY1 | HexagonItinerariesV75FU::CVI_SHIFT | HexagonItinerariesV75FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 798-800
  { 1, HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 801-802
  { 1, HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY0 | HexagonItinerariesV75FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 803-804
  { 1, HexagonItinerariesV75FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY0 | HexagonItinerariesV75FU::CVI_MPY1 | HexagonItinerariesV75FU::CVI_SHIFT | HexagonItinerariesV75FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 805-807
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1 | HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_XLANE | HexagonItinerariesV75FU::CVI_SHIFT | HexagonItinerariesV75FU::CVI_MPY0 | HexagonItinerariesV75FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 808-809
  { 1, HexagonItinerariesV75FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY01 | HexagonItinerariesV75FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 810-813
  { 1, HexagonItinerariesV75FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY0 | HexagonItinerariesV75FU::CVI_MPY1 | HexagonItinerariesV75FU::CVI_SHIFT | HexagonItinerariesV75FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 814-815
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1 | HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 816-817
  { 1, HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 818-819
  { 1, HexagonItinerariesV75FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 820-823
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 824-825
  { 1, HexagonItinerariesV75FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 826-829
  { 1, HexagonItinerariesV75FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 830-831
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1 | HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_SHIFT | HexagonItinerariesV75FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 832-833
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1 | HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 834-835
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1 | HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 836-837
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY01 | HexagonItinerariesV75FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 838-840
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1 | HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 841-842
  { 1, HexagonItinerariesV75FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 843-844
  { 1, HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY0 | HexagonItinerariesV75FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_SHIFT | HexagonItinerariesV75FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 845-847
  { 1, HexagonItinerariesV75FU::SLOT2 | HexagonItinerariesV75FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 848-849
  { 1, HexagonItinerariesV75FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_MPY01 | HexagonItinerariesV75FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 850-852
  { 1, HexagonItinerariesV75FU::SLOT0 | HexagonItinerariesV75FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV75FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 853-854
  { 1, HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 855
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1 | HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 856
  { 1, HexagonItinerariesV79FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 857
  { 1, HexagonItinerariesV79FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 858
  { 1, HexagonItinerariesV79FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 859
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 860
  { 1, HexagonItinerariesV79FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 861
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1 | HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY0 | HexagonItinerariesV79FU::CVI_MPY1 | HexagonItinerariesV79FU::CVI_SHIFT | HexagonItinerariesV79FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 862-863
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1 | HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY01 | HexagonItinerariesV79FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 864-865
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY0 | HexagonItinerariesV79FU::CVI_MPY1 | HexagonItinerariesV79FU::CVI_SHIFT | HexagonItinerariesV79FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 866-868
  { 1, HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 869-870
  { 1, HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY0 | HexagonItinerariesV79FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 871-872
  { 1, HexagonItinerariesV79FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY0 | HexagonItinerariesV79FU::CVI_MPY1 | HexagonItinerariesV79FU::CVI_SHIFT | HexagonItinerariesV79FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 873-875
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1 | HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_XLANE | HexagonItinerariesV79FU::CVI_SHIFT | HexagonItinerariesV79FU::CVI_MPY0 | HexagonItinerariesV79FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 876-877
  { 1, HexagonItinerariesV79FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY01 | HexagonItinerariesV79FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 878-881
  { 1, HexagonItinerariesV79FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY0 | HexagonItinerariesV79FU::CVI_MPY1 | HexagonItinerariesV79FU::CVI_SHIFT | HexagonItinerariesV79FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 882-883
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1 | HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 884-885
  { 1, HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 886-887
  { 1, HexagonItinerariesV79FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 888-891
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 892-893
  { 1, HexagonItinerariesV79FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 894-897
  { 1, HexagonItinerariesV79FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 898-899
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1 | HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_SHIFT | HexagonItinerariesV79FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 900-901
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1 | HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 902-903
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1 | HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 904-905
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY01 | HexagonItinerariesV79FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 906-908
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1 | HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 909-910
  { 1, HexagonItinerariesV79FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 911-912
  { 1, HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY0 | HexagonItinerariesV79FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_SHIFT | HexagonItinerariesV79FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 913-915
  { 1, HexagonItinerariesV79FU::SLOT2 | HexagonItinerariesV79FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 916-917
  { 1, HexagonItinerariesV79FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_MPY01 | HexagonItinerariesV79FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 918-920
  { 1, HexagonItinerariesV79FU::SLOT0 | HexagonItinerariesV79FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV79FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 921-922
  { 1, HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 923
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1 | HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 924
  { 1, HexagonItinerariesV81FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 925
  { 1, HexagonItinerariesV81FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 926
  { 1, HexagonItinerariesV81FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 927
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 928
  { 1, HexagonItinerariesV81FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 929
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1 | HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY0 | HexagonItinerariesV81FU::CVI_MPY1 | HexagonItinerariesV81FU::CVI_SHIFT | HexagonItinerariesV81FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 930-931
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1 | HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY01 | HexagonItinerariesV81FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 932-933
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY0 | HexagonItinerariesV81FU::CVI_MPY1 | HexagonItinerariesV81FU::CVI_SHIFT | HexagonItinerariesV81FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 934-936
  { 1, HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 937-938
  { 1, HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY0 | HexagonItinerariesV81FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 939-940
  { 1, HexagonItinerariesV81FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY0 | HexagonItinerariesV81FU::CVI_MPY1 | HexagonItinerariesV81FU::CVI_SHIFT | HexagonItinerariesV81FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 941-943
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1 | HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_XLANE | HexagonItinerariesV81FU::CVI_SHIFT | HexagonItinerariesV81FU::CVI_MPY0 | HexagonItinerariesV81FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 944-945
  { 1, HexagonItinerariesV81FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY01 | HexagonItinerariesV81FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 946-949
  { 1, HexagonItinerariesV81FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY0 | HexagonItinerariesV81FU::CVI_MPY1 | HexagonItinerariesV81FU::CVI_SHIFT | HexagonItinerariesV81FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 950-951
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1 | HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 952-953
  { 1, HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 954-955
  { 1, HexagonItinerariesV81FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 956-959
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 960-961
  { 1, HexagonItinerariesV81FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 962-965
  { 1, HexagonItinerariesV81FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 966-967
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1 | HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_SHIFT | HexagonItinerariesV81FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 968-969
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1 | HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 970-971
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1 | HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 972-973
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY01 | HexagonItinerariesV81FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 974-976
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1 | HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 977-978
  { 1, HexagonItinerariesV81FU::SLOT2, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 979-980
  { 1, HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY0 | HexagonItinerariesV81FU::CVI_MPY1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_SHIFT | HexagonItinerariesV81FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 981-983
  { 1, HexagonItinerariesV81FU::SLOT2 | HexagonItinerariesV81FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_ALL_NOMEM, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 984-985
  { 1, HexagonItinerariesV81FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_MPY01 | HexagonItinerariesV81FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 986-988
  { 1, HexagonItinerariesV81FU::SLOT0 | HexagonItinerariesV81FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV81FU::CVI_ZW, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 989-990
  { 0, 0, 0, llvm_ks::InstrStage::Required } // End stages
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV60[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 1, 2, 1, 4 }, // 1 tc_01d44cb2
  { 1, 2, 3, 4, 7 }, // 2 PSEUDO
  { 1, 2, 3, 7, 9 }, // 3 tc_c57d9f39
  { 1, 2, 3, 9, 13 }, // 4 tc_1c2c7a4a
  { 1, 2, 3, 13, 17 }, // 5 tc_442395f3
  { 1, 2, 3, 17, 20 }, // 6 tc_713b66bf
  { 1, 2, 3, 20, 23 }, // 7 tc_86173609
  { 1, 1, 2, 23, 26 }, // 8 tc_5da50c4b
  { 1, 1, 2, 26, 29 }, // 9 tc_4a55d03c
  { 1, 2, 3, 29, 32 }, // 10 tc_d33e5eee
  { 1, 1, 2, 32, 35 }, // 11 tc_651cbe02
  { 1, 3, 4, 35, 38 }, // 12 DUPLEX
  { 1, 4, 5, 38, 39 }, // 13 tc_ENDLOOP
  { 1, 2, 3, 0, 0 }, // 14 tc_23708a21
  { 1, 1, 2, 39, 41 }, // 15 tc_56a124a7
  { 1, 5, 6, 41, 43 }, // 16 tc_2f573607
  { 1, 5, 6, 43, 46 }, // 17 tc_53c851ab
  { 1, 6, 7, 46, 50 }, // 18 tc_fedb7e19
  { 1, 6, 7, 50, 53 }, // 19 tc_4222e6bf
  { 1, 6, 7, 53, 57 }, // 20 tc_075c8dd8
  { 1, 3, 4, 57, 60 }, // 21 tc_9bcfb2ee
  { 1, 3, 4, 60, 63 }, // 22 tc_158aa3f7
  { 1, 3, 4, 63, 66 }, // 23 tc_df5d53f9
  { 1, 3, 4, 66, 69 }, // 24 tc_14ab4f41
  { 1, 3, 4, 69, 70 }, // 25 tc_f38f92e1
  { 1, 3, 4, 70, 71 }, // 26 tc_1981450d
  { 1, 6, 7, 71, 73 }, // 27 tc_e9170fb7
  { 1, 3, 4, 73, 75 }, // 28 tc_40d64c94
  { 1, 6, 7, 75, 77 }, // 29 LD_tc_ld_SLOT01
  { 1, 1, 2, 77, 80 }, // 30 tc_38382228
  { 1, 1, 2, 80, 83 }, // 31 tc_c21d7447
  { 1, 1, 2, 83, 87 }, // 32 tc_7f8ae742
  { 1, 7, 8, 87, 90 }, // 33 tc_5a4b5e58
  { 1, 7, 8, 90, 94 }, // 34 tc_197dce51
  { 1, 1, 2, 94, 95 }, // 35 tc_44fffc58
  { 1, 6, 7, 95, 100 }, // 36 tc_5ceb2f9e
  { 1, 8, 10, 100, 103 }, // 37 tc_56c4f9fe
  { 1, 7, 8, 103, 105 }, // 38 tc_7476d766
  { 1, 6, 7, 105, 110 }, // 39 tc_b4dc7630
  { 1, 6, 7, 110, 114 }, // 40 tc_a2b365d2
  { 1, 5, 6, 114, 115 }, // 41 tc_60e324ff
  { 1, 10, 12, 115, 118 }, // 42 tc_db5555f3
  { 1, 12, 15, 118, 121 }, // 43 tc_c0749f3c
  { 1, 15, 17, 121, 124 }, // 44 PSEUDOM
  { 1, 8, 10, 124, 127 }, // 45 tc_3aacf4a8
  { 1, 17, 19, 127, 129 }, // 46 tc_c4edf264
  { 1, 19, 22, 129, 132 }, // 47 tc_c5dba46e
  { 1, 10, 12, 132, 136 }, // 48 tc_af25efd9
  { 1, 1, 2, 136, 139 }, // 49 tc_0dfac0a7
  { 1, 6, 7, 139, 143 }, // 50 tc_8035e91f
  { 1, 3, 4, 143, 147 }, // 51 tc_011e0e9d
  { 1, 6, 7, 147, 150 }, // 52 tc_ae5babd7
  { 1, 3, 4, 150, 153 }, // 53 tc_5deb5e47
  { 1, 1, 2, 153, 158 }, // 54 tc_bb831a7c
  { 1, 3, 4, 158, 162 }, // 55 tc_92240447
  { 1, 6, 7, 162, 165 }, // 56 tc_7c31e19a
  { 1, 6, 7, 165, 169 }, // 57 tc_d03278fd
  { 1, 6, 7, 169, 173 }, // 58 tc_65cbd974
  { 1, 3, 4, 173, 176 }, // 59 tc_934753bb
  { 1, 6, 7, 176, 179 }, // 60 ST_tc_st_SLOT01
  { 1, 22, 24, 179, 183 }, // 61 CVI_VA
  { 1, 17, 19, 183, 187 }, // 62 tc_f175e046
  { 1, 17, 19, 187, 192 }, // 63 tc_4942646a
  { 1, 8, 10, 192, 194 }, // 64 tc_0ec46cf9
  { 1, 10, 12, 194, 195 }, // 65 tc_718b5c53
  { 1, 24, 28, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 7, 8, 195, 197 }, // 67 tc_7dc63b5c
  { 1, 3, 4, 197, 198 }, // 68 tc_d45ba9cd
  { 1, 2, 3, 198, 201 }, // 69 tc_388f9897
  { 1, 2, 3, 201, 203 }, // 70 tc_9124c04f
  { 1, 2, 3, 203, 206 }, // 71 tc_4ac61d92
  { 1, 6, 7, 206, 208 }, // 72 tc_aee6250c
  { 1, 6, 7, 208, 211 }, // 73 tc_eed07714
  { 1, 6, 7, 211, 214 }, // 74 tc_74a42bda
  { 1, 6, 7, 214, 217 }, // 75 tc_a9edeffa
  { 1, 6, 7, 217, 220 }, // 76 tc_838c4d7a
  { 1, 1, 2, 220, 222 }, // 77 tc_d61dfdc3
  { 1, 1, 2, 222, 225 }, // 78 tc_8a825db2
  { 1, 1, 2, 225, 228 }, // 79 tc_f34c1c21
  { 1, 2, 3, 228, 231 }, // 80 tc_95a33176
  { 1, 1, 2, 231, 233 }, // 81 tc_9f6cd987
  { 1, 2, 3, 0, 0 }, // 82 tc_b837298f
  { 1, 2, 3, 233, 236 }, // 83 tc_8b5bd4f5
  { 1, 2, 3, 236, 239 }, // 84 tc_84a7500d
  { 1, 7, 8, 239, 241 }, // 85 tc_49fdfd4b
  { 1, 1, 2, 241, 244 }, // 86 tc_f098b237
  { 1, 1, 2, 244, 247 }, // 87 tc_20131976
  { 1, 1, 2, 247, 252 }, // 88 tc_1d41f8b7
  { 1, 1, 2, 252, 255 }, // 89 tc_a1297125
  { 1, 2, 3, 255, 256 }, // 90 tc_112d30d6
  { 1, 1, 2, 256, 259 }, // 91 tc_d68dca5c
  { 1, 1, 2, 259, 263 }, // 92 tc_788b1d09
  { 1, 1, 2, 263, 268 }, // 93 tc_38e0bae9
  { 1, 1, 2, 268, 271 }, // 94 tc_407e96f9
  { 1, 1, 2, 271, 275 }, // 95 tc_7401744f
  { 1, 1, 2, 275, 278 }, // 96 tc_9b3c0462
  { 1, 1, 2, 278, 280 }, // 97 tc_151bf368
  { 1, 2, 3, 280, 283 }, // 98 tc_9c52f549
  { 1, 1, 2, 283, 285 }, // 99 tc_55b33fda
  { 1, 1, 2, 285, 289 }, // 100 tc_6fc5dbea
  { 1, 7, 8, 289, 291 }, // 101 tc_3edca78f
  { 1, 1, 2, 291, 295 }, // 102 tc_a7a13fac
  { 1, 1, 2, 295, 297 }, // 103 tc_9783714b
  { 1, 1, 2, 297, 300 }, // 104 tc_f0e8e832
  { 1, 1, 2, 300, 302 }, // 105 tc_65279839
  { 1, 1, 2, 302, 306 }, // 106 tc_0a195f2c
  { 1, 1, 2, 306, 310 }, // 107 tc_01e1be3b
  { 1, 1, 2, 310, 313 }, // 108 tc_556f6577
  { 1, 1, 2, 313, 316 }, // 109 tc_02fe1c65
  { 1, 1, 2, 316, 320 }, // 110 tc_9e72dc89
  { 1, 1, 2, 320, 325 }, // 111 tc_9edb7c77
  { 1, 1, 2, 325, 328 }, // 112 tc_7f7f45f5
  { 1, 1, 2, 328, 331 }, // 113 tc_c20701f0
  { 1, 1, 2, 331, 335 }, // 114 tc_f7569068
  { 1, 7, 8, 335, 337 }, // 115 tc_fae9dfa5
  { 1, 7, 8, 337, 339 }, // 116 tc_6ae3426b
  { 1, 1, 2, 339, 341 }, // 117 tc_69bfb303
  { 1, 5, 6, 341, 342 }, // 118 tc_362b0be2
  { 1, 5, 6, 342, 344 }, // 119 tc_dc51281d
  { 1, 5, 6, 344, 345 }, // 120 tc_95f43c5e
  { 1, 1, 2, 345, 346 }, // 121 tc_decdde8a
  { 1, 1, 2, 346, 348 }, // 122 tc_eeda4109
  { 1, 1, 2, 348, 350 }, // 123 tc_711c805f
  { 1, 5, 6, 350, 352 }, // 124 tc_ed03645c
  { 1, 5, 6, 352, 354 }, // 125 tc_42ff66ba
  { 1, 7, 8, 354, 356 }, // 126 tc_57a55b54
  { 1, 5, 6, 356, 357 }, // 127 tc_f97707c1
  { 1, 7, 8, 357, 359 }, // 128 tc_1248597c
  { 1, 7, 8, 359, 361 }, // 129 tc_9406230a
  { 1, 5, 6, 361, 362 }, // 130 tc_d57d649c
  { 1, 7, 8, 362, 364 }, // 131 tc_4abdbdc6
  { 1, 7, 8, 364, 366 }, // 132 tc_6d861a95
  { 1, 5, 6, 0, 0 }, // 133 tc_b9bec29e
  { 1, 5, 6, 366, 367 }, // 134 tc_45f9d1be
  { 1, 5, 6, 0, 0 }, // 135 tc_33e7e673
  { 1, 3, 4, 367, 370 }, // 136 tc_24e109c7
  { 1, 1, 2, 370, 373 }, // 137 tc_9e27f2f9
  { 1, 3, 4, 373, 376 }, // 138 tc_f6e2aff9
  { 1, 1, 2, 376, 379 }, // 139 tc_24f426ab
  { 1, 3, 4, 379, 382 }, // 140 tc_975a4e54
  { 1, 5, 6, 382, 383 }, // 141 tc_e60def48
  { 1, 1, 2, 383, 386 }, // 142 tc_5502c366
  { 1, 3, 4, 386, 388 }, // 143 tc_7b9187d3
  { 1, 1, 2, 388, 390 }, // 144 tc_f999c66e
  { 1, 6, 7, 390, 395 }, // 145 tc_1c7522a8
  { 1, 6, 7, 395, 401 }, // 146 tc_76bb5435
  { 1, 6, 7, 401, 403 }, // 147 tc_8a6d0d94
  { 1, 3, 4, 403, 405 }, // 148 tc_2471c1c8
  { 1, 3, 4, 405, 407 }, // 149 tc_64b00d8a
  { 1, 6, 7, 407, 412 }, // 150 tc_5f2afaf7
  { 1, 6, 7, 412, 416 }, // 151 tc_ac65613f
  { 1, 6, 7, 416, 421 }, // 152 tc_a32e03e7
  { 1, 6, 7, 421, 424 }, // 153 tc_822c3c68
  { 1, 6, 7, 424, 428 }, // 154 tc_abfd9a6d
  { 1, 6, 7, 428, 432 }, // 155 tc_bf2ffc0f
  { 0, 0, 0, 0, 0 }, // 156 tc_ed3f8d2a
  { 1, 6, 7, 432, 435 }, // 157 tc_7c6d32e4
  { 1, 6, 7, 435, 440 }, // 158 tc_45791fb8
  { 1, 6, 7, 440, 445 }, // 159 tc_b7c4062a
  { 1, 6, 7, 445, 448 }, // 160 tc_5944960d
  { 1, 1, 2, 448, 452 }, // 161 tc_2c13e7f5
  { 1, 1, 2, 452, 456 }, // 162 tc_a154b476
  { 1, 1, 2, 456, 460 }, // 163 tc_a4e22bbd
  { 1, 1, 2, 460, 464 }, // 164 tc_503ce0f3
  { 1, 6, 7, 464, 466 }, // 165 tc_0655b949
  { 1, 3, 4, 466, 468 }, // 166 tc_6e20402a
  { 1, 3, 4, 468, 469 }, // 167 tc_db96aa6b
  { 1, 1, 2, 469, 471 }, // 168 tc_a7bdb22c
  { 1, 1, 2, 471, 474 }, // 169 tc_db596beb
  { 1, 1, 2, 474, 477 }, // 170 tc_a08b630b
  { 1, 1, 2, 477, 480 }, // 171 tc_1fcb8495
  { 1, 6, 7, 480, 485 }, // 172 tc_9edefe01
  { 1, 6, 7, 485, 490 }, // 173 tc_449acf79
  { 1, 3, 4, 490, 495 }, // 174 tc_ce59038e
  { 1, 3, 4, 495, 500 }, // 175 tc_f529831b
  { 1, 3, 4, 500, 505 }, // 176 tc_addc37a8
  { 1, 3, 4, 505, 508 }, // 177 tc_6f42bc60
  { 1, 3, 4, 508, 510 }, // 178 tc_7af3a37e
  { 1, 1, 2, 510, 512 }, // 179 tc_e3d699e3
  { 1, 6, 7, 512, 515 }, // 180 tc_ba9255a6
  { 1, 6, 7, 515, 520 }, // 181 tc_1fe4ab69
  { 1, 6, 7, 520, 523 }, // 182 tc_bb07f2c5
  { 1, 6, 7, 523, 528 }, // 183 tc_8e82e8ca
  { 1, 3, 4, 528, 531 }, // 184 tc_cfa0e29b
  { 1, 3, 4, 531, 536 }, // 185 tc_0a6c20ae
  { 1, 3, 4, 536, 539 }, // 186 tc_0fac1eb8
  { 1, 3, 4, 539, 544 }, // 187 tc_829d8a86
  { 1, 6, 7, 544, 548 }, // 188 tc_280f7fe1
  { 1, 6, 7, 548, 552 }, // 189 tc_887d1bb7
  { 1, 3, 4, 552, 556 }, // 190 tc_96ef76ef
  { 1, 3, 4, 556, 560 }, // 191 tc_55a9a350
  { 1, 1, 2, 560, 564 }, // 192 tc_f0cdeccf
  { 1, 1, 2, 564, 569 }, // 193 tc_a38c45dc
  { 1, 1, 2, 569, 571 }, // 194 tc_d3632d88
  { 1, 1, 2, 571, 575 }, // 195 tc_5e4cf0e8
  { 1, 1, 2, 575, 577 }, // 196 tc_ef921005
  { 1, 6, 7, 577, 580 }, // 197 tc_5b347363
  { 1, 6, 7, 580, 582 }, // 198 tc_3d14a17b
  { 1, 6, 7, 582, 583 }, // 199 tc_3fbf1042
  { 1, 6, 7, 583, 584 }, // 200 tc_63567288
  { 1, 6, 7, 584, 586 }, // 201 tc_59a7822c
  { 1, 6, 7, 0, 0 }, // 202 tc_937dd41c
  { 1, 3, 4, 0, 0 }, // 203 tc_a4ee89db
  { 1, 3, 4, 0, 0 }, // 204 tc_c818ff7f
  { 1, 3, 4, 586, 587 }, // 205 tc_1242dc2a
  { 1, 6, 7, 587, 589 }, // 206 tc_44d5a428
  { 1, 28, 30, 589, 592 }, // 207 tc_540c3da3
  { 1, 17, 19, 592, 596 }, // 208 tc_b091f1c6
  { 1, 30, 32, 596, 598 }, // 209 tc_5bf8afbb
  { 1, 32, 34, 598, 602 }, // 210 tc_2b4c548e
  { 1, 32, 34, 602, 607 }, // 211 tc_bb599486
  { 1, 34, 38, 607, 610 }, // 212 tc_a7e6707d
  { 1, 34, 38, 610, 614 }, // 213 tc_3c56e5ce
  { 1, 12, 15, 614, 618 }, // 214 tc_abe8c3b2
  { 1, 12, 15, 618, 623 }, // 215 tc_453fe68d
  { 1, 12, 15, 623, 627 }, // 216 tc_1ba8a0cd
  { 1, 38, 40, 627, 630 }, // 217 tc_52447ecc
  { 1, 38, 40, 630, 634 }, // 218 tc_3904b926
  { 1, 38, 40, 634, 639 }, // 219 tc_b9db8205
  { 1, 38, 40, 639, 643 }, // 220 tc_663c80a7
  { 1, 40, 44, 643, 646 }, // 221 tc_f21e8abb
  { 1, 40, 44, 646, 650 }, // 222 tc_131f1c81
  { 1, 40, 44, 650, 655 }, // 223 tc_c7039829
  { 1, 40, 44, 655, 659 }, // 224 tc_e2d2e9e5
  { 1, 44, 46, 659, 662 }, // 225 tc_ab23f776
  { 1, 44, 46, 662, 666 }, // 226 tc_7177e272
  { 1, 44, 46, 666, 671 }, // 227 tc_e99d4c2e
  { 1, 44, 46, 671, 675 }, // 228 tc_6942b6e0
  { 1, 19, 22, 675, 679 }, // 229 tc_a02a10a8
  { 1, 19, 22, 679, 684 }, // 230 tc_54a0dc47
  { 1, 19, 22, 684, 688 }, // 231 tc_447d9895
  { 1, 19, 22, 688, 693 }, // 232 tc_191381c1
  { 1, 19, 22, 693, 697 }, // 233 tc_3e2aaafc
  { 1, 44, 46, 697, 699 }, // 234 tc_3ce09744
  { 1, 44, 46, 699, 702 }, // 235 tc_20a4bbec
  { 1, 17, 19, 702, 704 }, // 236 tc_5cdf8c84
  { 1, 46, 48, 704, 706 }, // 237 tc_2a698a03
  { 1, 17, 19, 706, 709 }, // 238 tc_c127de3a
  { 1, 48, 50, 709, 712 }, // 239 tc_05ca8cfd
  { 1, 32, 34, 712, 715 }, // 240 tc_d8287c14
  { 1, 8, 10, 715, 719 }, // 241 tc_257f6f7c
  { 1, 8, 10, 719, 724 }, // 242 tc_7e6a3e89
  { 1, 8, 10, 724, 728 }, // 243 tc_e35c1e93
  { 1, 32, 34, 728, 732 }, // 244 tc_08a4f1b6
  { 1, 8, 10, 732, 736 }, // 245 tc_57a4709c
  { 1, 30, 32, 736, 740 }, // 246 tc_56e64202
  { 1, 17, 19, 740, 743 }, // 247 tc_ac4046bc
  { 1, 17, 19, 743, 747 }, // 248 tc_2e8f5f6e
  { 1, 48, 50, 747, 750 }, // 249 tc_7417e785
  { 1, 48, 50, 750, 754 }, // 250 tc_309dbb4f
  { 1, 50, 52, 754, 758 }, // 251 tc_df80eeb0
  { 1, 48, 50, 758, 762 }, // 252 tc_16ff9ef8
  { 1, 2, 3, 762, 764 }, // 253 tc_e2fdd6e6
  { 1, 48, 50, 764, 766 }, // 254 tc_51d0ecc3
  { 1, 2, 3, 766, 769 }, // 255 tc_531b383c
  { 1, 50, 52, 769, 771 }, // 256 tc_04da405a
  { 1, 17, 19, 771, 773 }, // 257 tc_3c8c15d0
  { 1, 32, 34, 773, 775 }, // 258 tc_0afc8be9
  { 1, 50, 52, 775, 780 }, // 259 tc_561aaa58
  { 1, 30, 32, 780, 782 }, // 260 tc_946013d8
  { 1, 30, 32, 782, 785 }, // 261 tc_46d6c3e0
  { 1, 50, 52, 785, 789 }, // 262 tc_87adc037
  { 1, 17, 19, 789, 793 }, // 263 tc_a19b9305
  { 1, 17, 19, 793, 796 }, // 264 tc_649072c2
  { 1, 32, 34, 796, 799 }, // 265 tc_0b04c6c7
  { 1, 32, 34, 799, 803 }, // 266 tc_660769f1
  { 1, 32, 34, 803, 806 }, // 267 tc_dcca380f
  { 1, 32, 34, 806, 810 }, // 268 tc_72e2b393
  { 1, 32, 34, 810, 813 }, // 269 tc_73efe966
  { 1, 17, 19, 813, 816 }, // 270 tc_cda936da
  { 1, 52, 55, 816, 819 }, // 271 tc_a28f32b5
  { 1, 52, 55, 819, 823 }, // 272 tc_7d68d5c2
  { 1, 55, 58, 823, 826 }, // 273 tc_7095ecba
  { 1, 55, 58, 826, 830 }, // 274 tc_a69eeee1
  { 1, 58, 60, 0, 0 }, // 275 tc_1381a97c
  { 1, 58, 60, 830, 831 }, // 276 tc_e3f68a46
  { 1, 60, 62, 831, 834 }, // 277 tc_f1de44ef
  { 1, 50, 52, 834, 839 }, // 278 tc_9d1dc972
  { 1, 60, 62, 839, 843 }, // 279 tc_90bcc1db
  { 1, 62, 65, 843, 846 }, // 280 tc_cd94bfe0
  { 1, 62, 65, 846, 850 }, // 281 tc_15fdf750
  { 1, 32, 34, 850, 854 }, // 282 tc_1ad8a370
  { 1, 32, 34, 854, 859 }, // 283 tc_e675c45a
  { 1, 32, 34, 859, 863 }, // 284 tc_37820f4c
  { 1, 65, 67, 863, 866 }, // 285 tc_61bf7c03
  { 1, 65, 67, 866, 870 }, // 286 tc_933f2b39
  { 1, 65, 67, 870, 874 }, // 287 tc_26a377fe
  { 1, 65, 67, 874, 879 }, // 288 tc_2d4051cd
  { 1, 30, 32, 879, 882 }, // 289 tc_6e7fa133
  { 1, 48, 50, 882, 885 }, // 290 tc_8772086c
  { 1, 10, 12, 885, 887 }, // 291 tc_b4416217
  { 1, 19, 22, 887, 891 }, // 292 tc_9f363d21
  { 1, 19, 22, 891, 896 }, // 293 tc_8e420e4d
  { 1, 67, 70, 896, 900 }, // 294 tc_7273323b
  { 1, 67, 70, 900, 905 }, // 295 tc_58d21193
  { 1, 10, 12, 905, 909 }, // 296 tc_71646d06
  { 1, 50, 52, 909, 912 }, // 297 tc_2c745bb8
  { 1, 58, 60, 912, 913 }, // 298 tc_b28e51aa
  { 1, 58, 60, 913, 915 }, // 299 tc_767c4e9d
  { 1, 70, 72, 915, 917 }, // 300 tc_e699ae41
  { 1, 70, 72, 917, 920 }, // 301 tc_a0dbea28
  { 1, 70, 72, 920, 923 }, // 302 tc_dd5b0695
  { 1, 70, 72, 923, 927 }, // 303 tc_3ad719fb
  { 1, 3, 4, 0, 0 }, // 304 tc_77f94a5e
  { 1, 7, 8, 0, 0 }, // 305 tc_55255f2b
  { 0, 0, 0, 0, 0 }, // 306 tc_0a43be35
  { 1, 3, 4, 927, 928 }, // 307 tc_b1ae5f67
  { 1, 3, 4, 928, 929 }, // 308 tc_d234b61a
  { 1, 3, 4, 929, 931 }, // 309 tc_2237d952
  { 1, 3, 4, 0, 0 }, // 310 tc_78f87ed3
  { 1, 3, 4, 931, 933 }, // 311 tc_a724463d
  { 1, 3, 4, 933, 935 }, // 312 tc_6fb52018
  { 1, 7, 8, 935, 937 }, // 313 tc_46c18ecf
  { 1, 5, 6, 937, 939 }, // 314 tc_9b20a062
  { 1, 5, 6, 939, 941 }, // 315 tc_5a222e89
  { 1, 5, 6, 941, 942 }, // 316 tc_0ba0d5da
  { 1, 5, 6, 942, 943 }, // 317 tc_7d6a2568
  { 1, 5, 6, 943, 945 }, // 318 tc_759e57be
  { 1, 5, 6, 945, 947 }, // 319 tc_139ef484
  { 1, 5, 6, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 7, 8, 0, 0 }, // 321 tc_7f58404a
  { 0, 0, 0, 0, 0 }, // 322 tc_b3d46584
  { 1, 7, 8, 947, 949 }, // 323 tc_d71ea8fa
  { 1, 7, 8, 949, 951 }, // 324 tc_6aa823ab
  { 0, 0, 0, 0, 0 }, // 325 tc_b2196a3f
  { 1, 7, 8, 951, 952 }, // 326 tc_2c3e17fc
  { 1, 7, 8, 952, 955 }, // 327 tc_27106296
  { 1, 3, 4, 955, 957 }, // 328 tc_a3070909
  { 1, 3, 4, 957, 959 }, // 329 tc_512b1653
  { 1, 7, 8, 959, 960 }, // 330 tc_d7718fbe
  { 1, 7, 8, 960, 963 }, // 331 tc_bb78483e
  { 1, 7, 8, 963, 964 }, // 332 tc_54f0cee2
  { 1, 7, 8, 964, 966 }, // 333 tc_28e55c6f
  { 1, 3, 4, 966, 967 }, // 334 tc_4bf903b0
  { 1, 3, 4, 967, 968 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV5[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 72, 73, 0, 0 }, // 1 tc_01d44cb2
  { 1, 73, 74, 0, 0 }, // 2 PSEUDO
  { 1, 73, 74, 0, 0 }, // 3 tc_c57d9f39
  { 1, 73, 74, 0, 0 }, // 4 tc_1c2c7a4a
  { 1, 73, 74, 0, 0 }, // 5 tc_442395f3
  { 1, 73, 74, 0, 0 }, // 6 tc_713b66bf
  { 1, 73, 74, 0, 0 }, // 7 tc_86173609
  { 1, 72, 73, 0, 0 }, // 8 tc_5da50c4b
  { 1, 72, 73, 0, 0 }, // 9 tc_4a55d03c
  { 1, 73, 74, 0, 0 }, // 10 tc_d33e5eee
  { 1, 72, 73, 0, 0 }, // 11 tc_651cbe02
  { 1, 74, 75, 0, 0 }, // 12 DUPLEX
  { 1, 75, 76, 0, 0 }, // 13 tc_ENDLOOP
  { 1, 73, 74, 0, 0 }, // 14 tc_23708a21
  { 1, 72, 73, 0, 0 }, // 15 tc_56a124a7
  { 1, 76, 77, 0, 0 }, // 16 tc_2f573607
  { 1, 76, 77, 0, 0 }, // 17 tc_53c851ab
  { 1, 77, 78, 0, 0 }, // 18 tc_fedb7e19
  { 1, 77, 78, 0, 0 }, // 19 tc_4222e6bf
  { 1, 77, 78, 0, 0 }, // 20 tc_075c8dd8
  { 1, 74, 75, 0, 0 }, // 21 tc_9bcfb2ee
  { 1, 74, 75, 0, 0 }, // 22 tc_158aa3f7
  { 1, 74, 75, 0, 0 }, // 23 tc_df5d53f9
  { 1, 74, 75, 0, 0 }, // 24 tc_14ab4f41
  { 1, 74, 75, 0, 0 }, // 25 tc_f38f92e1
  { 1, 74, 75, 0, 0 }, // 26 tc_1981450d
  { 1, 77, 78, 0, 0 }, // 27 tc_e9170fb7
  { 1, 74, 75, 0, 0 }, // 28 tc_40d64c94
  { 1, 77, 78, 0, 0 }, // 29 LD_tc_ld_SLOT01
  { 1, 72, 73, 0, 0 }, // 30 tc_38382228
  { 1, 72, 73, 0, 0 }, // 31 tc_c21d7447
  { 1, 72, 73, 0, 0 }, // 32 tc_7f8ae742
  { 1, 78, 79, 0, 0 }, // 33 tc_5a4b5e58
  { 1, 78, 79, 0, 0 }, // 34 tc_197dce51
  { 1, 72, 73, 0, 0 }, // 35 tc_44fffc58
  { 1, 77, 78, 0, 0 }, // 36 tc_5ceb2f9e
  { 0, 0, 0, 0, 0 }, // 37 tc_56c4f9fe
  { 1, 78, 79, 0, 0 }, // 38 tc_7476d766
  { 1, 77, 78, 0, 0 }, // 39 tc_b4dc7630
  { 1, 77, 78, 0, 0 }, // 40 tc_a2b365d2
  { 1, 76, 77, 0, 0 }, // 41 tc_60e324ff
  { 0, 0, 0, 0, 0 }, // 42 tc_db5555f3
  { 0, 0, 0, 0, 0 }, // 43 tc_c0749f3c
  { 1, 79, 81, 0, 0 }, // 44 PSEUDOM
  { 0, 0, 0, 0, 0 }, // 45 tc_3aacf4a8
  { 0, 0, 0, 0, 0 }, // 46 tc_c4edf264
  { 0, 0, 0, 0, 0 }, // 47 tc_c5dba46e
  { 0, 0, 0, 0, 0 }, // 48 tc_af25efd9
  { 1, 72, 73, 0, 0 }, // 49 tc_0dfac0a7
  { 1, 77, 78, 0, 0 }, // 50 tc_8035e91f
  { 1, 74, 75, 0, 0 }, // 51 tc_011e0e9d
  { 1, 77, 78, 0, 0 }, // 52 tc_ae5babd7
  { 1, 74, 75, 0, 0 }, // 53 tc_5deb5e47
  { 1, 72, 73, 0, 0 }, // 54 tc_bb831a7c
  { 1, 74, 75, 0, 0 }, // 55 tc_92240447
  { 1, 77, 78, 0, 0 }, // 56 tc_7c31e19a
  { 1, 77, 78, 0, 0 }, // 57 tc_d03278fd
  { 1, 77, 78, 0, 0 }, // 58 tc_65cbd974
  { 1, 74, 75, 0, 0 }, // 59 tc_934753bb
  { 1, 77, 78, 0, 0 }, // 60 ST_tc_st_SLOT01
  { 0, 0, 0, 0, 0 }, // 61 CVI_VA
  { 0, 0, 0, 0, 0 }, // 62 tc_f175e046
  { 0, 0, 0, 0, 0 }, // 63 tc_4942646a
  { 0, 0, 0, 0, 0 }, // 64 tc_0ec46cf9
  { 0, 0, 0, 0, 0 }, // 65 tc_718b5c53
  { 0, 0, 0, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 78, 79, 0, 0 }, // 67 tc_7dc63b5c
  { 1, 74, 75, 0, 0 }, // 68 tc_d45ba9cd
  { 1, 73, 74, 0, 0 }, // 69 tc_388f9897
  { 1, 73, 74, 0, 0 }, // 70 tc_9124c04f
  { 1, 73, 74, 0, 0 }, // 71 tc_4ac61d92
  { 1, 77, 78, 0, 0 }, // 72 tc_aee6250c
  { 1, 77, 78, 0, 0 }, // 73 tc_eed07714
  { 1, 77, 78, 0, 0 }, // 74 tc_74a42bda
  { 1, 77, 78, 0, 0 }, // 75 tc_a9edeffa
  { 1, 77, 78, 0, 0 }, // 76 tc_838c4d7a
  { 1, 72, 73, 0, 0 }, // 77 tc_d61dfdc3
  { 1, 72, 73, 0, 0 }, // 78 tc_8a825db2
  { 1, 72, 73, 0, 0 }, // 79 tc_f34c1c21
  { 1, 73, 74, 0, 0 }, // 80 tc_95a33176
  { 1, 72, 73, 0, 0 }, // 81 tc_9f6cd987
  { 1, 73, 74, 0, 0 }, // 82 tc_b837298f
  { 1, 73, 74, 0, 0 }, // 83 tc_8b5bd4f5
  { 1, 73, 74, 0, 0 }, // 84 tc_84a7500d
  { 1, 78, 79, 0, 0 }, // 85 tc_49fdfd4b
  { 1, 72, 73, 0, 0 }, // 86 tc_f098b237
  { 1, 72, 73, 0, 0 }, // 87 tc_20131976
  { 1, 72, 73, 0, 0 }, // 88 tc_1d41f8b7
  { 1, 72, 73, 0, 0 }, // 89 tc_a1297125
  { 1, 73, 74, 0, 0 }, // 90 tc_112d30d6
  { 1, 72, 73, 0, 0 }, // 91 tc_d68dca5c
  { 1, 72, 73, 0, 0 }, // 92 tc_788b1d09
  { 1, 72, 73, 0, 0 }, // 93 tc_38e0bae9
  { 1, 72, 73, 0, 0 }, // 94 tc_407e96f9
  { 1, 72, 73, 0, 0 }, // 95 tc_7401744f
  { 1, 72, 73, 0, 0 }, // 96 tc_9b3c0462
  { 1, 72, 73, 0, 0 }, // 97 tc_151bf368
  { 1, 73, 74, 0, 0 }, // 98 tc_9c52f549
  { 1, 72, 73, 0, 0 }, // 99 tc_55b33fda
  { 1, 72, 73, 0, 0 }, // 100 tc_6fc5dbea
  { 1, 78, 79, 0, 0 }, // 101 tc_3edca78f
  { 1, 72, 73, 0, 0 }, // 102 tc_a7a13fac
  { 1, 72, 73, 0, 0 }, // 103 tc_9783714b
  { 1, 72, 73, 0, 0 }, // 104 tc_f0e8e832
  { 1, 72, 73, 0, 0 }, // 105 tc_65279839
  { 1, 72, 73, 0, 0 }, // 106 tc_0a195f2c
  { 1, 72, 73, 0, 0 }, // 107 tc_01e1be3b
  { 1, 72, 73, 0, 0 }, // 108 tc_556f6577
  { 1, 72, 73, 0, 0 }, // 109 tc_02fe1c65
  { 1, 72, 73, 0, 0 }, // 110 tc_9e72dc89
  { 1, 72, 73, 0, 0 }, // 111 tc_9edb7c77
  { 1, 72, 73, 0, 0 }, // 112 tc_7f7f45f5
  { 1, 72, 73, 0, 0 }, // 113 tc_c20701f0
  { 1, 72, 73, 0, 0 }, // 114 tc_f7569068
  { 1, 78, 79, 0, 0 }, // 115 tc_fae9dfa5
  { 1, 78, 79, 0, 0 }, // 116 tc_6ae3426b
  { 1, 72, 73, 0, 0 }, // 117 tc_69bfb303
  { 1, 76, 77, 0, 0 }, // 118 tc_362b0be2
  { 1, 76, 77, 0, 0 }, // 119 tc_dc51281d
  { 1, 76, 77, 0, 0 }, // 120 tc_95f43c5e
  { 1, 72, 73, 0, 0 }, // 121 tc_decdde8a
  { 1, 72, 73, 0, 0 }, // 122 tc_eeda4109
  { 1, 72, 73, 0, 0 }, // 123 tc_711c805f
  { 1, 76, 77, 0, 0 }, // 124 tc_ed03645c
  { 1, 76, 77, 0, 0 }, // 125 tc_42ff66ba
  { 1, 78, 79, 0, 0 }, // 126 tc_57a55b54
  { 1, 76, 77, 0, 0 }, // 127 tc_f97707c1
  { 1, 78, 79, 0, 0 }, // 128 tc_1248597c
  { 1, 78, 79, 0, 0 }, // 129 tc_9406230a
  { 1, 76, 77, 0, 0 }, // 130 tc_d57d649c
  { 1, 78, 79, 0, 0 }, // 131 tc_4abdbdc6
  { 1, 78, 79, 0, 0 }, // 132 tc_6d861a95
  { 0, 0, 0, 0, 0 }, // 133 tc_b9bec29e
  { 1, 76, 77, 0, 0 }, // 134 tc_45f9d1be
  { 1, 76, 77, 0, 0 }, // 135 tc_33e7e673
  { 1, 74, 75, 0, 0 }, // 136 tc_24e109c7
  { 1, 72, 73, 0, 0 }, // 137 tc_9e27f2f9
  { 1, 74, 75, 0, 0 }, // 138 tc_f6e2aff9
  { 1, 72, 73, 0, 0 }, // 139 tc_24f426ab
  { 1, 74, 75, 0, 0 }, // 140 tc_975a4e54
  { 1, 76, 77, 0, 0 }, // 141 tc_e60def48
  { 1, 72, 73, 0, 0 }, // 142 tc_5502c366
  { 1, 74, 75, 0, 0 }, // 143 tc_7b9187d3
  { 1, 72, 73, 0, 0 }, // 144 tc_f999c66e
  { 1, 77, 78, 0, 0 }, // 145 tc_1c7522a8
  { 1, 77, 78, 0, 0 }, // 146 tc_76bb5435
  { 1, 77, 78, 0, 0 }, // 147 tc_8a6d0d94
  { 1, 74, 75, 0, 0 }, // 148 tc_2471c1c8
  { 1, 74, 75, 0, 0 }, // 149 tc_64b00d8a
  { 1, 77, 78, 0, 0 }, // 150 tc_5f2afaf7
  { 1, 77, 78, 0, 0 }, // 151 tc_ac65613f
  { 1, 77, 78, 0, 0 }, // 152 tc_a32e03e7
  { 1, 77, 78, 0, 0 }, // 153 tc_822c3c68
  { 1, 77, 78, 0, 0 }, // 154 tc_abfd9a6d
  { 1, 77, 78, 0, 0 }, // 155 tc_bf2ffc0f
  { 0, 0, 0, 0, 0 }, // 156 tc_ed3f8d2a
  { 1, 77, 78, 0, 0 }, // 157 tc_7c6d32e4
  { 1, 77, 78, 0, 0 }, // 158 tc_45791fb8
  { 1, 77, 78, 0, 0 }, // 159 tc_b7c4062a
  { 1, 77, 78, 0, 0 }, // 160 tc_5944960d
  { 1, 72, 73, 0, 0 }, // 161 tc_2c13e7f5
  { 1, 72, 73, 0, 0 }, // 162 tc_a154b476
  { 1, 72, 73, 0, 0 }, // 163 tc_a4e22bbd
  { 1, 72, 73, 0, 0 }, // 164 tc_503ce0f3
  { 1, 77, 78, 0, 0 }, // 165 tc_0655b949
  { 1, 74, 75, 0, 0 }, // 166 tc_6e20402a
  { 1, 74, 75, 0, 0 }, // 167 tc_db96aa6b
  { 1, 72, 73, 0, 0 }, // 168 tc_a7bdb22c
  { 1, 72, 73, 0, 0 }, // 169 tc_db596beb
  { 1, 72, 73, 0, 0 }, // 170 tc_a08b630b
  { 1, 72, 73, 0, 0 }, // 171 tc_1fcb8495
  { 1, 77, 78, 0, 0 }, // 172 tc_9edefe01
  { 1, 77, 78, 0, 0 }, // 173 tc_449acf79
  { 1, 74, 75, 0, 0 }, // 174 tc_ce59038e
  { 1, 74, 75, 0, 0 }, // 175 tc_f529831b
  { 1, 74, 75, 0, 0 }, // 176 tc_addc37a8
  { 1, 74, 75, 0, 0 }, // 177 tc_6f42bc60
  { 1, 74, 75, 0, 0 }, // 178 tc_7af3a37e
  { 1, 72, 73, 0, 0 }, // 179 tc_e3d699e3
  { 1, 77, 78, 0, 0 }, // 180 tc_ba9255a6
  { 1, 77, 78, 0, 0 }, // 181 tc_1fe4ab69
  { 1, 77, 78, 0, 0 }, // 182 tc_bb07f2c5
  { 1, 77, 78, 0, 0 }, // 183 tc_8e82e8ca
  { 1, 74, 75, 0, 0 }, // 184 tc_cfa0e29b
  { 1, 74, 75, 0, 0 }, // 185 tc_0a6c20ae
  { 1, 74, 75, 0, 0 }, // 186 tc_0fac1eb8
  { 1, 74, 75, 0, 0 }, // 187 tc_829d8a86
  { 1, 77, 78, 0, 0 }, // 188 tc_280f7fe1
  { 1, 77, 78, 0, 0 }, // 189 tc_887d1bb7
  { 1, 74, 75, 0, 0 }, // 190 tc_96ef76ef
  { 1, 74, 75, 0, 0 }, // 191 tc_55a9a350
  { 1, 72, 73, 0, 0 }, // 192 tc_f0cdeccf
  { 1, 72, 73, 0, 0 }, // 193 tc_a38c45dc
  { 1, 72, 73, 0, 0 }, // 194 tc_d3632d88
  { 1, 72, 73, 0, 0 }, // 195 tc_5e4cf0e8
  { 1, 72, 73, 0, 0 }, // 196 tc_ef921005
  { 1, 77, 78, 0, 0 }, // 197 tc_5b347363
  { 1, 77, 78, 0, 0 }, // 198 tc_3d14a17b
  { 1, 77, 78, 0, 0 }, // 199 tc_3fbf1042
  { 1, 77, 78, 0, 0 }, // 200 tc_63567288
  { 1, 77, 78, 0, 0 }, // 201 tc_59a7822c
  { 1, 77, 78, 0, 0 }, // 202 tc_937dd41c
  { 1, 74, 75, 0, 0 }, // 203 tc_a4ee89db
  { 1, 74, 75, 0, 0 }, // 204 tc_c818ff7f
  { 1, 74, 75, 0, 0 }, // 205 tc_1242dc2a
  { 1, 77, 78, 0, 0 }, // 206 tc_44d5a428
  { 0, 0, 0, 0, 0 }, // 207 tc_540c3da3
  { 0, 0, 0, 0, 0 }, // 208 tc_b091f1c6
  { 0, 0, 0, 0, 0 }, // 209 tc_5bf8afbb
  { 0, 0, 0, 0, 0 }, // 210 tc_2b4c548e
  { 0, 0, 0, 0, 0 }, // 211 tc_bb599486
  { 0, 0, 0, 0, 0 }, // 212 tc_a7e6707d
  { 0, 0, 0, 0, 0 }, // 213 tc_3c56e5ce
  { 0, 0, 0, 0, 0 }, // 214 tc_abe8c3b2
  { 0, 0, 0, 0, 0 }, // 215 tc_453fe68d
  { 0, 0, 0, 0, 0 }, // 216 tc_1ba8a0cd
  { 0, 0, 0, 0, 0 }, // 217 tc_52447ecc
  { 0, 0, 0, 0, 0 }, // 218 tc_3904b926
  { 0, 0, 0, 0, 0 }, // 219 tc_b9db8205
  { 0, 0, 0, 0, 0 }, // 220 tc_663c80a7
  { 0, 0, 0, 0, 0 }, // 221 tc_f21e8abb
  { 0, 0, 0, 0, 0 }, // 222 tc_131f1c81
  { 0, 0, 0, 0, 0 }, // 223 tc_c7039829
  { 0, 0, 0, 0, 0 }, // 224 tc_e2d2e9e5
  { 0, 0, 0, 0, 0 }, // 225 tc_ab23f776
  { 0, 0, 0, 0, 0 }, // 226 tc_7177e272
  { 0, 0, 0, 0, 0 }, // 227 tc_e99d4c2e
  { 0, 0, 0, 0, 0 }, // 228 tc_6942b6e0
  { 0, 0, 0, 0, 0 }, // 229 tc_a02a10a8
  { 0, 0, 0, 0, 0 }, // 230 tc_54a0dc47
  { 0, 0, 0, 0, 0 }, // 231 tc_447d9895
  { 0, 0, 0, 0, 0 }, // 232 tc_191381c1
  { 0, 0, 0, 0, 0 }, // 233 tc_3e2aaafc
  { 0, 0, 0, 0, 0 }, // 234 tc_3ce09744
  { 0, 0, 0, 0, 0 }, // 235 tc_20a4bbec
  { 0, 0, 0, 0, 0 }, // 236 tc_5cdf8c84
  { 0, 0, 0, 0, 0 }, // 237 tc_2a698a03
  { 0, 0, 0, 0, 0 }, // 238 tc_c127de3a
  { 0, 0, 0, 0, 0 }, // 239 tc_05ca8cfd
  { 0, 0, 0, 0, 0 }, // 240 tc_d8287c14
  { 0, 0, 0, 0, 0 }, // 241 tc_257f6f7c
  { 0, 0, 0, 0, 0 }, // 242 tc_7e6a3e89
  { 0, 0, 0, 0, 0 }, // 243 tc_e35c1e93
  { 0, 0, 0, 0, 0 }, // 244 tc_08a4f1b6
  { 0, 0, 0, 0, 0 }, // 245 tc_57a4709c
  { 0, 0, 0, 0, 0 }, // 246 tc_56e64202
  { 0, 0, 0, 0, 0 }, // 247 tc_ac4046bc
  { 0, 0, 0, 0, 0 }, // 248 tc_2e8f5f6e
  { 0, 0, 0, 0, 0 }, // 249 tc_7417e785
  { 0, 0, 0, 0, 0 }, // 250 tc_309dbb4f
  { 0, 0, 0, 0, 0 }, // 251 tc_df80eeb0
  { 0, 0, 0, 0, 0 }, // 252 tc_16ff9ef8
  { 0, 0, 0, 0, 0 }, // 253 tc_e2fdd6e6
  { 0, 0, 0, 0, 0 }, // 254 tc_51d0ecc3
  { 0, 0, 0, 0, 0 }, // 255 tc_531b383c
  { 0, 0, 0, 0, 0 }, // 256 tc_04da405a
  { 0, 0, 0, 0, 0 }, // 257 tc_3c8c15d0
  { 0, 0, 0, 0, 0 }, // 258 tc_0afc8be9
  { 0, 0, 0, 0, 0 }, // 259 tc_561aaa58
  { 0, 0, 0, 0, 0 }, // 260 tc_946013d8
  { 0, 0, 0, 0, 0 }, // 261 tc_46d6c3e0
  { 0, 0, 0, 0, 0 }, // 262 tc_87adc037
  { 0, 0, 0, 0, 0 }, // 263 tc_a19b9305
  { 0, 0, 0, 0, 0 }, // 264 tc_649072c2
  { 0, 0, 0, 0, 0 }, // 265 tc_0b04c6c7
  { 0, 0, 0, 0, 0 }, // 266 tc_660769f1
  { 0, 0, 0, 0, 0 }, // 267 tc_dcca380f
  { 0, 0, 0, 0, 0 }, // 268 tc_72e2b393
  { 0, 0, 0, 0, 0 }, // 269 tc_73efe966
  { 0, 0, 0, 0, 0 }, // 270 tc_cda936da
  { 0, 0, 0, 0, 0 }, // 271 tc_a28f32b5
  { 0, 0, 0, 0, 0 }, // 272 tc_7d68d5c2
  { 0, 0, 0, 0, 0 }, // 273 tc_7095ecba
  { 0, 0, 0, 0, 0 }, // 274 tc_a69eeee1
  { 0, 0, 0, 0, 0 }, // 275 tc_1381a97c
  { 0, 0, 0, 0, 0 }, // 276 tc_e3f68a46
  { 0, 0, 0, 0, 0 }, // 277 tc_f1de44ef
  { 0, 0, 0, 0, 0 }, // 278 tc_9d1dc972
  { 0, 0, 0, 0, 0 }, // 279 tc_90bcc1db
  { 0, 0, 0, 0, 0 }, // 280 tc_cd94bfe0
  { 0, 0, 0, 0, 0 }, // 281 tc_15fdf750
  { 0, 0, 0, 0, 0 }, // 282 tc_1ad8a370
  { 0, 0, 0, 0, 0 }, // 283 tc_e675c45a
  { 0, 0, 0, 0, 0 }, // 284 tc_37820f4c
  { 0, 0, 0, 0, 0 }, // 285 tc_61bf7c03
  { 0, 0, 0, 0, 0 }, // 286 tc_933f2b39
  { 0, 0, 0, 0, 0 }, // 287 tc_26a377fe
  { 0, 0, 0, 0, 0 }, // 288 tc_2d4051cd
  { 0, 0, 0, 0, 0 }, // 289 tc_6e7fa133
  { 0, 0, 0, 0, 0 }, // 290 tc_8772086c
  { 0, 0, 0, 0, 0 }, // 291 tc_b4416217
  { 0, 0, 0, 0, 0 }, // 292 tc_9f363d21
  { 0, 0, 0, 0, 0 }, // 293 tc_8e420e4d
  { 0, 0, 0, 0, 0 }, // 294 tc_7273323b
  { 0, 0, 0, 0, 0 }, // 295 tc_58d21193
  { 0, 0, 0, 0, 0 }, // 296 tc_71646d06
  { 0, 0, 0, 0, 0 }, // 297 tc_2c745bb8
  { 0, 0, 0, 0, 0 }, // 298 tc_b28e51aa
  { 0, 0, 0, 0, 0 }, // 299 tc_767c4e9d
  { 0, 0, 0, 0, 0 }, // 300 tc_e699ae41
  { 0, 0, 0, 0, 0 }, // 301 tc_a0dbea28
  { 0, 0, 0, 0, 0 }, // 302 tc_dd5b0695
  { 0, 0, 0, 0, 0 }, // 303 tc_3ad719fb
  { 1, 74, 75, 0, 0 }, // 304 tc_77f94a5e
  { 1, 78, 79, 0, 0 }, // 305 tc_55255f2b
  { 0, 0, 0, 0, 0 }, // 306 tc_0a43be35
  { 1, 74, 75, 0, 0 }, // 307 tc_b1ae5f67
  { 0, 0, 0, 0, 0 }, // 308 tc_d234b61a
  { 1, 74, 75, 0, 0 }, // 309 tc_2237d952
  { 0, 0, 0, 0, 0 }, // 310 tc_78f87ed3
  { 0, 0, 0, 0, 0 }, // 311 tc_a724463d
  { 0, 0, 0, 0, 0 }, // 312 tc_6fb52018
  { 0, 0, 0, 0, 0 }, // 313 tc_46c18ecf
  { 0, 0, 0, 0, 0 }, // 314 tc_9b20a062
  { 0, 0, 0, 0, 0 }, // 315 tc_5a222e89
  { 1, 76, 77, 0, 0 }, // 316 tc_0ba0d5da
  { 0, 0, 0, 0, 0 }, // 317 tc_7d6a2568
  { 0, 0, 0, 0, 0 }, // 318 tc_759e57be
  { 0, 0, 0, 0, 0 }, // 319 tc_139ef484
  { 1, 76, 77, 0, 0 }, // 320 tc_9b34f5e0
  { 0, 0, 0, 0, 0 }, // 321 tc_7f58404a
  { 0, 0, 0, 0, 0 }, // 322 tc_b3d46584
  { 0, 0, 0, 0, 0 }, // 323 tc_d71ea8fa
  { 0, 0, 0, 0, 0 }, // 324 tc_6aa823ab
  { 0, 0, 0, 0, 0 }, // 325 tc_b2196a3f
  { 1, 78, 79, 0, 0 }, // 326 tc_2c3e17fc
  { 1, 78, 79, 0, 0 }, // 327 tc_27106296
  { 1, 74, 75, 0, 0 }, // 328 tc_a3070909
  { 0, 0, 0, 0, 0 }, // 329 tc_512b1653
  { 1, 78, 79, 0, 0 }, // 330 tc_d7718fbe
  { 0, 0, 0, 0, 0 }, // 331 tc_bb78483e
  { 0, 0, 0, 0, 0 }, // 332 tc_54f0cee2
  { 1, 78, 79, 0, 0 }, // 333 tc_28e55c6f
  { 1, 74, 75, 0, 0 }, // 334 tc_4bf903b0
  { 0, 0, 0, 0, 0 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV55[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 81, 82, 968, 971 }, // 1 tc_01d44cb2
  { 1, 82, 83, 971, 974 }, // 2 PSEUDO
  { 1, 82, 83, 974, 976 }, // 3 tc_c57d9f39
  { 1, 82, 83, 976, 980 }, // 4 tc_1c2c7a4a
  { 1, 82, 83, 980, 984 }, // 5 tc_442395f3
  { 1, 82, 83, 984, 987 }, // 6 tc_713b66bf
  { 1, 82, 83, 987, 990 }, // 7 tc_86173609
  { 1, 81, 82, 990, 993 }, // 8 tc_5da50c4b
  { 1, 81, 82, 993, 996 }, // 9 tc_4a55d03c
  { 1, 82, 83, 996, 999 }, // 10 tc_d33e5eee
  { 1, 81, 82, 999, 1002 }, // 11 tc_651cbe02
  { 1, 83, 84, 1002, 1005 }, // 12 DUPLEX
  { 1, 84, 85, 1005, 1006 }, // 13 tc_ENDLOOP
  { 1, 82, 83, 0, 0 }, // 14 tc_23708a21
  { 1, 81, 82, 1006, 1008 }, // 15 tc_56a124a7
  { 1, 85, 86, 1008, 1010 }, // 16 tc_2f573607
  { 1, 85, 86, 1010, 1013 }, // 17 tc_53c851ab
  { 1, 86, 87, 1013, 1017 }, // 18 tc_fedb7e19
  { 1, 86, 87, 1017, 1020 }, // 19 tc_4222e6bf
  { 1, 86, 87, 1020, 1024 }, // 20 tc_075c8dd8
  { 1, 83, 84, 1024, 1027 }, // 21 tc_9bcfb2ee
  { 1, 83, 84, 1027, 1030 }, // 22 tc_158aa3f7
  { 1, 83, 84, 1030, 1033 }, // 23 tc_df5d53f9
  { 1, 83, 84, 1033, 1036 }, // 24 tc_14ab4f41
  { 1, 83, 84, 1036, 1037 }, // 25 tc_f38f92e1
  { 1, 83, 84, 1037, 1038 }, // 26 tc_1981450d
  { 1, 86, 87, 1038, 1040 }, // 27 tc_e9170fb7
  { 1, 83, 84, 1040, 1042 }, // 28 tc_40d64c94
  { 1, 86, 87, 1042, 1044 }, // 29 LD_tc_ld_SLOT01
  { 1, 81, 82, 1044, 1047 }, // 30 tc_38382228
  { 1, 81, 82, 1047, 1050 }, // 31 tc_c21d7447
  { 1, 81, 82, 1050, 1054 }, // 32 tc_7f8ae742
  { 1, 87, 88, 1054, 1057 }, // 33 tc_5a4b5e58
  { 1, 87, 88, 1057, 1061 }, // 34 tc_197dce51
  { 1, 81, 82, 1061, 1062 }, // 35 tc_44fffc58
  { 1, 86, 87, 1062, 1067 }, // 36 tc_5ceb2f9e
  { 0, 0, 0, 0, 0 }, // 37 tc_56c4f9fe
  { 1, 87, 88, 1067, 1069 }, // 38 tc_7476d766
  { 1, 86, 87, 1069, 1074 }, // 39 tc_b4dc7630
  { 1, 86, 87, 1074, 1078 }, // 40 tc_a2b365d2
  { 1, 85, 86, 1078, 1079 }, // 41 tc_60e324ff
  { 0, 0, 0, 0, 0 }, // 42 tc_db5555f3
  { 0, 0, 0, 0, 0 }, // 43 tc_c0749f3c
  { 1, 88, 90, 1079, 1082 }, // 44 PSEUDOM
  { 0, 0, 0, 0, 0 }, // 45 tc_3aacf4a8
  { 0, 0, 0, 0, 0 }, // 46 tc_c4edf264
  { 0, 0, 0, 0, 0 }, // 47 tc_c5dba46e
  { 0, 0, 0, 0, 0 }, // 48 tc_af25efd9
  { 1, 81, 82, 1082, 1085 }, // 49 tc_0dfac0a7
  { 1, 86, 87, 1085, 1089 }, // 50 tc_8035e91f
  { 1, 83, 84, 1089, 1093 }, // 51 tc_011e0e9d
  { 1, 86, 87, 1093, 1096 }, // 52 tc_ae5babd7
  { 1, 83, 84, 1096, 1099 }, // 53 tc_5deb5e47
  { 1, 81, 82, 1099, 1104 }, // 54 tc_bb831a7c
  { 1, 83, 84, 1104, 1108 }, // 55 tc_92240447
  { 1, 86, 87, 1108, 1111 }, // 56 tc_7c31e19a
  { 1, 86, 87, 1111, 1115 }, // 57 tc_d03278fd
  { 1, 86, 87, 1115, 1119 }, // 58 tc_65cbd974
  { 1, 83, 84, 1119, 1122 }, // 59 tc_934753bb
  { 1, 86, 87, 1122, 1125 }, // 60 ST_tc_st_SLOT01
  { 0, 0, 0, 0, 0 }, // 61 CVI_VA
  { 0, 0, 0, 0, 0 }, // 62 tc_f175e046
  { 0, 0, 0, 0, 0 }, // 63 tc_4942646a
  { 0, 0, 0, 0, 0 }, // 64 tc_0ec46cf9
  { 0, 0, 0, 0, 0 }, // 65 tc_718b5c53
  { 0, 0, 0, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 87, 88, 1125, 1127 }, // 67 tc_7dc63b5c
  { 1, 83, 84, 1127, 1128 }, // 68 tc_d45ba9cd
  { 1, 82, 83, 1128, 1131 }, // 69 tc_388f9897
  { 1, 82, 83, 1131, 1133 }, // 70 tc_9124c04f
  { 1, 82, 83, 1133, 1136 }, // 71 tc_4ac61d92
  { 1, 86, 87, 1136, 1138 }, // 72 tc_aee6250c
  { 1, 86, 87, 1138, 1141 }, // 73 tc_eed07714
  { 1, 86, 87, 1141, 1144 }, // 74 tc_74a42bda
  { 1, 86, 87, 1144, 1147 }, // 75 tc_a9edeffa
  { 1, 86, 87, 1147, 1150 }, // 76 tc_838c4d7a
  { 1, 81, 82, 1150, 1152 }, // 77 tc_d61dfdc3
  { 1, 81, 82, 1152, 1155 }, // 78 tc_8a825db2
  { 1, 81, 82, 1155, 1158 }, // 79 tc_f34c1c21
  { 1, 82, 83, 1158, 1161 }, // 80 tc_95a33176
  { 1, 81, 82, 1161, 1163 }, // 81 tc_9f6cd987
  { 1, 82, 83, 0, 0 }, // 82 tc_b837298f
  { 1, 82, 83, 1163, 1166 }, // 83 tc_8b5bd4f5
  { 1, 82, 83, 1166, 1169 }, // 84 tc_84a7500d
  { 1, 87, 88, 1169, 1171 }, // 85 tc_49fdfd4b
  { 1, 81, 82, 1171, 1174 }, // 86 tc_f098b237
  { 1, 81, 82, 1174, 1177 }, // 87 tc_20131976
  { 1, 81, 82, 1177, 1182 }, // 88 tc_1d41f8b7
  { 1, 81, 82, 1182, 1185 }, // 89 tc_a1297125
  { 1, 82, 83, 1185, 1186 }, // 90 tc_112d30d6
  { 1, 81, 82, 1186, 1189 }, // 91 tc_d68dca5c
  { 1, 81, 82, 1189, 1193 }, // 92 tc_788b1d09
  { 1, 81, 82, 1193, 1198 }, // 93 tc_38e0bae9
  { 1, 81, 82, 1198, 1201 }, // 94 tc_407e96f9
  { 1, 81, 82, 1201, 1205 }, // 95 tc_7401744f
  { 1, 81, 82, 1205, 1208 }, // 96 tc_9b3c0462
  { 1, 81, 82, 1208, 1210 }, // 97 tc_151bf368
  { 1, 82, 83, 1210, 1213 }, // 98 tc_9c52f549
  { 1, 81, 82, 1213, 1215 }, // 99 tc_55b33fda
  { 1, 81, 82, 1215, 1219 }, // 100 tc_6fc5dbea
  { 1, 87, 88, 1219, 1221 }, // 101 tc_3edca78f
  { 1, 81, 82, 1221, 1225 }, // 102 tc_a7a13fac
  { 1, 81, 82, 1225, 1227 }, // 103 tc_9783714b
  { 1, 81, 82, 1227, 1230 }, // 104 tc_f0e8e832
  { 1, 81, 82, 1230, 1232 }, // 105 tc_65279839
  { 1, 81, 82, 1232, 1236 }, // 106 tc_0a195f2c
  { 1, 81, 82, 1236, 1240 }, // 107 tc_01e1be3b
  { 1, 81, 82, 1240, 1243 }, // 108 tc_556f6577
  { 1, 81, 82, 1243, 1246 }, // 109 tc_02fe1c65
  { 1, 81, 82, 1246, 1250 }, // 110 tc_9e72dc89
  { 1, 81, 82, 1250, 1255 }, // 111 tc_9edb7c77
  { 1, 81, 82, 1255, 1258 }, // 112 tc_7f7f45f5
  { 1, 81, 82, 1258, 1261 }, // 113 tc_c20701f0
  { 1, 81, 82, 1261, 1265 }, // 114 tc_f7569068
  { 1, 87, 88, 1265, 1267 }, // 115 tc_fae9dfa5
  { 1, 87, 88, 1267, 1269 }, // 116 tc_6ae3426b
  { 1, 81, 82, 1269, 1271 }, // 117 tc_69bfb303
  { 1, 85, 86, 1271, 1272 }, // 118 tc_362b0be2
  { 1, 85, 86, 1272, 1274 }, // 119 tc_dc51281d
  { 1, 85, 86, 1274, 1275 }, // 120 tc_95f43c5e
  { 1, 81, 82, 1275, 1276 }, // 121 tc_decdde8a
  { 1, 81, 82, 1276, 1278 }, // 122 tc_eeda4109
  { 1, 81, 82, 1278, 1280 }, // 123 tc_711c805f
  { 1, 85, 86, 1280, 1282 }, // 124 tc_ed03645c
  { 1, 85, 86, 1282, 1284 }, // 125 tc_42ff66ba
  { 1, 87, 88, 1284, 1286 }, // 126 tc_57a55b54
  { 1, 85, 86, 1286, 1287 }, // 127 tc_f97707c1
  { 1, 87, 88, 1287, 1289 }, // 128 tc_1248597c
  { 1, 87, 88, 1289, 1291 }, // 129 tc_9406230a
  { 1, 85, 86, 1291, 1292 }, // 130 tc_d57d649c
  { 1, 87, 88, 1292, 1294 }, // 131 tc_4abdbdc6
  { 1, 87, 88, 1294, 1296 }, // 132 tc_6d861a95
  { 1, 85, 86, 0, 0 }, // 133 tc_b9bec29e
  { 1, 85, 86, 1296, 1297 }, // 134 tc_45f9d1be
  { 1, 85, 86, 0, 0 }, // 135 tc_33e7e673
  { 1, 83, 84, 1297, 1300 }, // 136 tc_24e109c7
  { 1, 81, 82, 1300, 1303 }, // 137 tc_9e27f2f9
  { 1, 83, 84, 1303, 1306 }, // 138 tc_f6e2aff9
  { 1, 81, 82, 1306, 1309 }, // 139 tc_24f426ab
  { 1, 83, 84, 1309, 1312 }, // 140 tc_975a4e54
  { 1, 85, 86, 1312, 1313 }, // 141 tc_e60def48
  { 1, 81, 82, 1313, 1316 }, // 142 tc_5502c366
  { 1, 83, 84, 1316, 1318 }, // 143 tc_7b9187d3
  { 1, 81, 82, 1318, 1320 }, // 144 tc_f999c66e
  { 1, 86, 87, 1320, 1325 }, // 145 tc_1c7522a8
  { 1, 86, 87, 1325, 1331 }, // 146 tc_76bb5435
  { 1, 86, 87, 1331, 1333 }, // 147 tc_8a6d0d94
  { 1, 83, 84, 1333, 1335 }, // 148 tc_2471c1c8
  { 1, 83, 84, 1335, 1337 }, // 149 tc_64b00d8a
  { 1, 86, 87, 1337, 1342 }, // 150 tc_5f2afaf7
  { 1, 86, 87, 1342, 1346 }, // 151 tc_ac65613f
  { 1, 86, 87, 1346, 1351 }, // 152 tc_a32e03e7
  { 1, 86, 87, 1351, 1354 }, // 153 tc_822c3c68
  { 1, 86, 87, 1354, 1358 }, // 154 tc_abfd9a6d
  { 1, 86, 87, 1358, 1362 }, // 155 tc_bf2ffc0f
  { 1, 83, 84, 1362, 1365 }, // 156 tc_ed3f8d2a
  { 1, 86, 87, 1365, 1368 }, // 157 tc_7c6d32e4
  { 1, 86, 87, 1368, 1373 }, // 158 tc_45791fb8
  { 1, 86, 87, 1373, 1378 }, // 159 tc_b7c4062a
  { 1, 86, 87, 1378, 1381 }, // 160 tc_5944960d
  { 1, 81, 82, 1381, 1385 }, // 161 tc_2c13e7f5
  { 1, 81, 82, 1385, 1389 }, // 162 tc_a154b476
  { 1, 81, 82, 1389, 1393 }, // 163 tc_a4e22bbd
  { 1, 81, 82, 1393, 1397 }, // 164 tc_503ce0f3
  { 1, 86, 87, 1397, 1399 }, // 165 tc_0655b949
  { 1, 83, 84, 1399, 1401 }, // 166 tc_6e20402a
  { 1, 83, 84, 1401, 1402 }, // 167 tc_db96aa6b
  { 1, 81, 82, 1402, 1404 }, // 168 tc_a7bdb22c
  { 1, 81, 82, 1404, 1407 }, // 169 tc_db596beb
  { 1, 81, 82, 1407, 1410 }, // 170 tc_a08b630b
  { 1, 81, 82, 1410, 1413 }, // 171 tc_1fcb8495
  { 1, 86, 87, 1413, 1418 }, // 172 tc_9edefe01
  { 1, 86, 87, 1418, 1423 }, // 173 tc_449acf79
  { 1, 83, 84, 1423, 1428 }, // 174 tc_ce59038e
  { 1, 83, 84, 1428, 1433 }, // 175 tc_f529831b
  { 1, 83, 84, 1433, 1438 }, // 176 tc_addc37a8
  { 1, 83, 84, 1438, 1441 }, // 177 tc_6f42bc60
  { 1, 83, 84, 1441, 1443 }, // 178 tc_7af3a37e
  { 1, 81, 82, 1443, 1445 }, // 179 tc_e3d699e3
  { 1, 86, 87, 1445, 1448 }, // 180 tc_ba9255a6
  { 1, 86, 87, 1448, 1453 }, // 181 tc_1fe4ab69
  { 1, 86, 87, 1453, 1456 }, // 182 tc_bb07f2c5
  { 1, 86, 87, 1456, 1461 }, // 183 tc_8e82e8ca
  { 1, 83, 84, 1461, 1464 }, // 184 tc_cfa0e29b
  { 1, 83, 84, 1464, 1469 }, // 185 tc_0a6c20ae
  { 1, 83, 84, 1469, 1472 }, // 186 tc_0fac1eb8
  { 1, 83, 84, 1472, 1477 }, // 187 tc_829d8a86
  { 1, 86, 87, 1477, 1481 }, // 188 tc_280f7fe1
  { 1, 86, 87, 1481, 1485 }, // 189 tc_887d1bb7
  { 1, 83, 84, 1485, 1489 }, // 190 tc_96ef76ef
  { 1, 83, 84, 1489, 1493 }, // 191 tc_55a9a350
  { 1, 81, 82, 1493, 1497 }, // 192 tc_f0cdeccf
  { 1, 81, 82, 1497, 1502 }, // 193 tc_a38c45dc
  { 1, 81, 82, 1502, 1504 }, // 194 tc_d3632d88
  { 1, 81, 82, 1504, 1508 }, // 195 tc_5e4cf0e8
  { 1, 81, 82, 1508, 1510 }, // 196 tc_ef921005
  { 1, 86, 87, 1510, 1513 }, // 197 tc_5b347363
  { 1, 86, 87, 1513, 1515 }, // 198 tc_3d14a17b
  { 1, 86, 87, 1515, 1516 }, // 199 tc_3fbf1042
  { 1, 86, 87, 1516, 1517 }, // 200 tc_63567288
  { 1, 86, 87, 1517, 1519 }, // 201 tc_59a7822c
  { 1, 86, 87, 0, 0 }, // 202 tc_937dd41c
  { 1, 83, 84, 0, 0 }, // 203 tc_a4ee89db
  { 1, 83, 84, 0, 0 }, // 204 tc_c818ff7f
  { 1, 83, 84, 1519, 1520 }, // 205 tc_1242dc2a
  { 1, 86, 87, 1520, 1522 }, // 206 tc_44d5a428
  { 0, 0, 0, 0, 0 }, // 207 tc_540c3da3
  { 0, 0, 0, 0, 0 }, // 208 tc_b091f1c6
  { 0, 0, 0, 0, 0 }, // 209 tc_5bf8afbb
  { 0, 0, 0, 0, 0 }, // 210 tc_2b4c548e
  { 0, 0, 0, 0, 0 }, // 211 tc_bb599486
  { 0, 0, 0, 0, 0 }, // 212 tc_a7e6707d
  { 0, 0, 0, 0, 0 }, // 213 tc_3c56e5ce
  { 0, 0, 0, 0, 0 }, // 214 tc_abe8c3b2
  { 0, 0, 0, 0, 0 }, // 215 tc_453fe68d
  { 0, 0, 0, 0, 0 }, // 216 tc_1ba8a0cd
  { 0, 0, 0, 0, 0 }, // 217 tc_52447ecc
  { 0, 0, 0, 0, 0 }, // 218 tc_3904b926
  { 0, 0, 0, 0, 0 }, // 219 tc_b9db8205
  { 0, 0, 0, 0, 0 }, // 220 tc_663c80a7
  { 0, 0, 0, 0, 0 }, // 221 tc_f21e8abb
  { 0, 0, 0, 0, 0 }, // 222 tc_131f1c81
  { 0, 0, 0, 0, 0 }, // 223 tc_c7039829
  { 0, 0, 0, 0, 0 }, // 224 tc_e2d2e9e5
  { 0, 0, 0, 0, 0 }, // 225 tc_ab23f776
  { 0, 0, 0, 0, 0 }, // 226 tc_7177e272
  { 0, 0, 0, 0, 0 }, // 227 tc_e99d4c2e
  { 0, 0, 0, 0, 0 }, // 228 tc_6942b6e0
  { 0, 0, 0, 0, 0 }, // 229 tc_a02a10a8
  { 0, 0, 0, 0, 0 }, // 230 tc_54a0dc47
  { 0, 0, 0, 0, 0 }, // 231 tc_447d9895
  { 0, 0, 0, 0, 0 }, // 232 tc_191381c1
  { 0, 0, 0, 0, 0 }, // 233 tc_3e2aaafc
  { 0, 0, 0, 0, 0 }, // 234 tc_3ce09744
  { 0, 0, 0, 0, 0 }, // 235 tc_20a4bbec
  { 0, 0, 0, 0, 0 }, // 236 tc_5cdf8c84
  { 0, 0, 0, 0, 0 }, // 237 tc_2a698a03
  { 0, 0, 0, 0, 0 }, // 238 tc_c127de3a
  { 0, 0, 0, 0, 0 }, // 239 tc_05ca8cfd
  { 0, 0, 0, 0, 0 }, // 240 tc_d8287c14
  { 0, 0, 0, 0, 0 }, // 241 tc_257f6f7c
  { 0, 0, 0, 0, 0 }, // 242 tc_7e6a3e89
  { 0, 0, 0, 0, 0 }, // 243 tc_e35c1e93
  { 0, 0, 0, 0, 0 }, // 244 tc_08a4f1b6
  { 0, 0, 0, 0, 0 }, // 245 tc_57a4709c
  { 0, 0, 0, 0, 0 }, // 246 tc_56e64202
  { 0, 0, 0, 0, 0 }, // 247 tc_ac4046bc
  { 0, 0, 0, 0, 0 }, // 248 tc_2e8f5f6e
  { 0, 0, 0, 0, 0 }, // 249 tc_7417e785
  { 0, 0, 0, 0, 0 }, // 250 tc_309dbb4f
  { 0, 0, 0, 0, 0 }, // 251 tc_df80eeb0
  { 0, 0, 0, 0, 0 }, // 252 tc_16ff9ef8
  { 0, 0, 0, 0, 0 }, // 253 tc_e2fdd6e6
  { 0, 0, 0, 0, 0 }, // 254 tc_51d0ecc3
  { 0, 0, 0, 0, 0 }, // 255 tc_531b383c
  { 0, 0, 0, 0, 0 }, // 256 tc_04da405a
  { 0, 0, 0, 0, 0 }, // 257 tc_3c8c15d0
  { 0, 0, 0, 0, 0 }, // 258 tc_0afc8be9
  { 0, 0, 0, 0, 0 }, // 259 tc_561aaa58
  { 0, 0, 0, 0, 0 }, // 260 tc_946013d8
  { 0, 0, 0, 0, 0 }, // 261 tc_46d6c3e0
  { 0, 0, 0, 0, 0 }, // 262 tc_87adc037
  { 0, 0, 0, 0, 0 }, // 263 tc_a19b9305
  { 0, 0, 0, 0, 0 }, // 264 tc_649072c2
  { 0, 0, 0, 0, 0 }, // 265 tc_0b04c6c7
  { 0, 0, 0, 0, 0 }, // 266 tc_660769f1
  { 0, 0, 0, 0, 0 }, // 267 tc_dcca380f
  { 0, 0, 0, 0, 0 }, // 268 tc_72e2b393
  { 0, 0, 0, 0, 0 }, // 269 tc_73efe966
  { 0, 0, 0, 0, 0 }, // 270 tc_cda936da
  { 0, 0, 0, 0, 0 }, // 271 tc_a28f32b5
  { 0, 0, 0, 0, 0 }, // 272 tc_7d68d5c2
  { 0, 0, 0, 0, 0 }, // 273 tc_7095ecba
  { 0, 0, 0, 0, 0 }, // 274 tc_a69eeee1
  { 0, 0, 0, 0, 0 }, // 275 tc_1381a97c
  { 0, 0, 0, 0, 0 }, // 276 tc_e3f68a46
  { 0, 0, 0, 0, 0 }, // 277 tc_f1de44ef
  { 0, 0, 0, 0, 0 }, // 278 tc_9d1dc972
  { 0, 0, 0, 0, 0 }, // 279 tc_90bcc1db
  { 0, 0, 0, 0, 0 }, // 280 tc_cd94bfe0
  { 0, 0, 0, 0, 0 }, // 281 tc_15fdf750
  { 0, 0, 0, 0, 0 }, // 282 tc_1ad8a370
  { 0, 0, 0, 0, 0 }, // 283 tc_e675c45a
  { 0, 0, 0, 0, 0 }, // 284 tc_37820f4c
  { 0, 0, 0, 0, 0 }, // 285 tc_61bf7c03
  { 0, 0, 0, 0, 0 }, // 286 tc_933f2b39
  { 0, 0, 0, 0, 0 }, // 287 tc_26a377fe
  { 0, 0, 0, 0, 0 }, // 288 tc_2d4051cd
  { 0, 0, 0, 0, 0 }, // 289 tc_6e7fa133
  { 0, 0, 0, 0, 0 }, // 290 tc_8772086c
  { 0, 0, 0, 0, 0 }, // 291 tc_b4416217
  { 0, 0, 0, 0, 0 }, // 292 tc_9f363d21
  { 0, 0, 0, 0, 0 }, // 293 tc_8e420e4d
  { 0, 0, 0, 0, 0 }, // 294 tc_7273323b
  { 0, 0, 0, 0, 0 }, // 295 tc_58d21193
  { 0, 0, 0, 0, 0 }, // 296 tc_71646d06
  { 0, 0, 0, 0, 0 }, // 297 tc_2c745bb8
  { 0, 0, 0, 0, 0 }, // 298 tc_b28e51aa
  { 0, 0, 0, 0, 0 }, // 299 tc_767c4e9d
  { 0, 0, 0, 0, 0 }, // 300 tc_e699ae41
  { 0, 0, 0, 0, 0 }, // 301 tc_a0dbea28
  { 0, 0, 0, 0, 0 }, // 302 tc_dd5b0695
  { 0, 0, 0, 0, 0 }, // 303 tc_3ad719fb
  { 1, 83, 84, 0, 0 }, // 304 tc_77f94a5e
  { 1, 87, 88, 0, 0 }, // 305 tc_55255f2b
  { 0, 0, 0, 0, 0 }, // 306 tc_0a43be35
  { 1, 83, 84, 1522, 1523 }, // 307 tc_b1ae5f67
  { 1, 83, 84, 1523, 1524 }, // 308 tc_d234b61a
  { 1, 83, 84, 1524, 1526 }, // 309 tc_2237d952
  { 1, 83, 84, 0, 0 }, // 310 tc_78f87ed3
  { 1, 83, 84, 1526, 1528 }, // 311 tc_a724463d
  { 1, 83, 84, 1528, 1530 }, // 312 tc_6fb52018
  { 1, 87, 88, 1530, 1532 }, // 313 tc_46c18ecf
  { 1, 85, 86, 1532, 1534 }, // 314 tc_9b20a062
  { 1, 85, 86, 1534, 1536 }, // 315 tc_5a222e89
  { 1, 85, 86, 1536, 1537 }, // 316 tc_0ba0d5da
  { 1, 85, 86, 1537, 1538 }, // 317 tc_7d6a2568
  { 1, 85, 86, 1538, 1540 }, // 318 tc_759e57be
  { 1, 85, 86, 1540, 1542 }, // 319 tc_139ef484
  { 1, 85, 86, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 87, 88, 0, 0 }, // 321 tc_7f58404a
  { 0, 0, 0, 0, 0 }, // 322 tc_b3d46584
  { 1, 87, 88, 1542, 1544 }, // 323 tc_d71ea8fa
  { 1, 87, 88, 1544, 1546 }, // 324 tc_6aa823ab
  { 0, 0, 0, 0, 0 }, // 325 tc_b2196a3f
  { 1, 87, 88, 1546, 1547 }, // 326 tc_2c3e17fc
  { 1, 87, 88, 1547, 1550 }, // 327 tc_27106296
  { 1, 83, 84, 1550, 1552 }, // 328 tc_a3070909
  { 1, 83, 84, 1552, 1554 }, // 329 tc_512b1653
  { 1, 87, 88, 1554, 1555 }, // 330 tc_d7718fbe
  { 1, 87, 88, 1555, 1558 }, // 331 tc_bb78483e
  { 1, 87, 88, 1558, 1559 }, // 332 tc_54f0cee2
  { 1, 87, 88, 1559, 1561 }, // 333 tc_28e55c6f
  { 1, 83, 84, 1561, 1562 }, // 334 tc_4bf903b0
  { 1, 83, 84, 1562, 1563 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV62[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 90, 91, 1563, 1566 }, // 1 tc_01d44cb2
  { 1, 91, 92, 1566, 1569 }, // 2 PSEUDO
  { 1, 91, 92, 1569, 1571 }, // 3 tc_c57d9f39
  { 1, 91, 92, 1571, 1575 }, // 4 tc_1c2c7a4a
  { 1, 91, 92, 1575, 1579 }, // 5 tc_442395f3
  { 1, 91, 92, 1579, 1582 }, // 6 tc_713b66bf
  { 1, 91, 92, 1582, 1585 }, // 7 tc_86173609
  { 1, 90, 91, 1585, 1588 }, // 8 tc_5da50c4b
  { 1, 90, 91, 1588, 1591 }, // 9 tc_4a55d03c
  { 1, 91, 92, 1591, 1594 }, // 10 tc_d33e5eee
  { 1, 90, 91, 1594, 1597 }, // 11 tc_651cbe02
  { 1, 92, 93, 1597, 1600 }, // 12 DUPLEX
  { 1, 93, 94, 1600, 1601 }, // 13 tc_ENDLOOP
  { 1, 91, 92, 0, 0 }, // 14 tc_23708a21
  { 1, 91, 92, 1601, 1603 }, // 15 tc_56a124a7
  { 1, 94, 95, 1603, 1605 }, // 16 tc_2f573607
  { 1, 94, 95, 1605, 1608 }, // 17 tc_53c851ab
  { 1, 95, 96, 1608, 1612 }, // 18 tc_fedb7e19
  { 1, 95, 96, 1612, 1615 }, // 19 tc_4222e6bf
  { 1, 95, 96, 1615, 1619 }, // 20 tc_075c8dd8
  { 1, 92, 93, 1619, 1622 }, // 21 tc_9bcfb2ee
  { 1, 92, 93, 1622, 1625 }, // 22 tc_158aa3f7
  { 1, 92, 93, 1625, 1628 }, // 23 tc_df5d53f9
  { 1, 92, 93, 1628, 1631 }, // 24 tc_14ab4f41
  { 1, 92, 93, 1631, 1632 }, // 25 tc_f38f92e1
  { 1, 92, 93, 1632, 1633 }, // 26 tc_1981450d
  { 1, 95, 96, 1633, 1635 }, // 27 tc_e9170fb7
  { 1, 92, 93, 1635, 1637 }, // 28 tc_40d64c94
  { 1, 95, 96, 1637, 1639 }, // 29 LD_tc_ld_SLOT01
  { 1, 90, 91, 1639, 1642 }, // 30 tc_38382228
  { 1, 90, 91, 1642, 1645 }, // 31 tc_c21d7447
  { 1, 90, 91, 1645, 1649 }, // 32 tc_7f8ae742
  { 1, 96, 97, 1649, 1652 }, // 33 tc_5a4b5e58
  { 1, 96, 97, 1652, 1656 }, // 34 tc_197dce51
  { 1, 90, 91, 1656, 1657 }, // 35 tc_44fffc58
  { 1, 95, 96, 1657, 1662 }, // 36 tc_5ceb2f9e
  { 1, 97, 99, 1662, 1665 }, // 37 tc_56c4f9fe
  { 1, 96, 97, 1665, 1667 }, // 38 tc_7476d766
  { 1, 95, 96, 1667, 1672 }, // 39 tc_b4dc7630
  { 1, 95, 96, 1672, 1676 }, // 40 tc_a2b365d2
  { 1, 94, 95, 1676, 1677 }, // 41 tc_60e324ff
  { 1, 99, 101, 1677, 1680 }, // 42 tc_db5555f3
  { 1, 101, 104, 1680, 1683 }, // 43 tc_c0749f3c
  { 1, 104, 106, 1683, 1686 }, // 44 PSEUDOM
  { 1, 97, 99, 1686, 1689 }, // 45 tc_3aacf4a8
  { 1, 106, 108, 1689, 1691 }, // 46 tc_c4edf264
  { 1, 108, 111, 1691, 1694 }, // 47 tc_c5dba46e
  { 1, 99, 101, 1694, 1698 }, // 48 tc_af25efd9
  { 1, 90, 91, 1698, 1701 }, // 49 tc_0dfac0a7
  { 1, 95, 96, 1701, 1705 }, // 50 tc_8035e91f
  { 1, 92, 93, 1705, 1709 }, // 51 tc_011e0e9d
  { 1, 95, 96, 1709, 1712 }, // 52 tc_ae5babd7
  { 1, 92, 93, 1712, 1715 }, // 53 tc_5deb5e47
  { 1, 90, 91, 1715, 1720 }, // 54 tc_bb831a7c
  { 1, 92, 93, 1720, 1724 }, // 55 tc_92240447
  { 1, 95, 96, 1724, 1727 }, // 56 tc_7c31e19a
  { 1, 95, 96, 1727, 1731 }, // 57 tc_d03278fd
  { 1, 95, 96, 1731, 1735 }, // 58 tc_65cbd974
  { 1, 92, 93, 1735, 1738 }, // 59 tc_934753bb
  { 1, 95, 96, 1738, 1741 }, // 60 ST_tc_st_SLOT01
  { 1, 111, 113, 1741, 1745 }, // 61 CVI_VA
  { 1, 106, 108, 1745, 1749 }, // 62 tc_f175e046
  { 1, 106, 108, 1749, 1754 }, // 63 tc_4942646a
  { 1, 97, 99, 1754, 1756 }, // 64 tc_0ec46cf9
  { 1, 99, 101, 1756, 1757 }, // 65 tc_718b5c53
  { 1, 113, 117, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 96, 97, 1757, 1759 }, // 67 tc_7dc63b5c
  { 1, 92, 93, 1759, 1760 }, // 68 tc_d45ba9cd
  { 1, 91, 92, 1760, 1763 }, // 69 tc_388f9897
  { 1, 91, 92, 1763, 1765 }, // 70 tc_9124c04f
  { 1, 91, 92, 1765, 1768 }, // 71 tc_4ac61d92
  { 1, 95, 96, 1768, 1770 }, // 72 tc_aee6250c
  { 1, 95, 96, 1770, 1773 }, // 73 tc_eed07714
  { 1, 95, 96, 1773, 1776 }, // 74 tc_74a42bda
  { 1, 95, 96, 1776, 1779 }, // 75 tc_a9edeffa
  { 1, 95, 96, 1779, 1782 }, // 76 tc_838c4d7a
  { 1, 90, 91, 1782, 1784 }, // 77 tc_d61dfdc3
  { 1, 90, 91, 1784, 1787 }, // 78 tc_8a825db2
  { 1, 90, 91, 1787, 1790 }, // 79 tc_f34c1c21
  { 1, 91, 92, 1790, 1793 }, // 80 tc_95a33176
  { 1, 90, 91, 1793, 1795 }, // 81 tc_9f6cd987
  { 1, 91, 92, 0, 0 }, // 82 tc_b837298f
  { 1, 91, 92, 1795, 1798 }, // 83 tc_8b5bd4f5
  { 1, 91, 92, 1798, 1801 }, // 84 tc_84a7500d
  { 1, 96, 97, 1801, 1803 }, // 85 tc_49fdfd4b
  { 1, 90, 91, 1803, 1806 }, // 86 tc_f098b237
  { 1, 90, 91, 1806, 1809 }, // 87 tc_20131976
  { 1, 90, 91, 1809, 1814 }, // 88 tc_1d41f8b7
  { 1, 90, 91, 1814, 1817 }, // 89 tc_a1297125
  { 1, 91, 92, 1817, 1818 }, // 90 tc_112d30d6
  { 1, 90, 91, 1818, 1821 }, // 91 tc_d68dca5c
  { 1, 90, 91, 1821, 1825 }, // 92 tc_788b1d09
  { 1, 90, 91, 1825, 1830 }, // 93 tc_38e0bae9
  { 1, 90, 91, 1830, 1833 }, // 94 tc_407e96f9
  { 1, 90, 91, 1833, 1837 }, // 95 tc_7401744f
  { 1, 90, 91, 1837, 1840 }, // 96 tc_9b3c0462
  { 1, 90, 91, 1840, 1842 }, // 97 tc_151bf368
  { 1, 91, 92, 1842, 1845 }, // 98 tc_9c52f549
  { 1, 90, 91, 1845, 1847 }, // 99 tc_55b33fda
  { 1, 90, 91, 1847, 1851 }, // 100 tc_6fc5dbea
  { 1, 96, 97, 1851, 1853 }, // 101 tc_3edca78f
  { 1, 90, 91, 1853, 1857 }, // 102 tc_a7a13fac
  { 1, 90, 91, 1857, 1859 }, // 103 tc_9783714b
  { 1, 90, 91, 1859, 1862 }, // 104 tc_f0e8e832
  { 1, 90, 91, 1862, 1864 }, // 105 tc_65279839
  { 1, 90, 91, 1864, 1868 }, // 106 tc_0a195f2c
  { 1, 90, 91, 1868, 1872 }, // 107 tc_01e1be3b
  { 1, 90, 91, 1872, 1875 }, // 108 tc_556f6577
  { 1, 90, 91, 1875, 1878 }, // 109 tc_02fe1c65
  { 1, 90, 91, 1878, 1882 }, // 110 tc_9e72dc89
  { 1, 90, 91, 1882, 1887 }, // 111 tc_9edb7c77
  { 1, 90, 91, 1887, 1890 }, // 112 tc_7f7f45f5
  { 1, 90, 91, 1890, 1893 }, // 113 tc_c20701f0
  { 1, 90, 91, 1893, 1897 }, // 114 tc_f7569068
  { 1, 96, 97, 1897, 1899 }, // 115 tc_fae9dfa5
  { 1, 96, 97, 1899, 1901 }, // 116 tc_6ae3426b
  { 1, 90, 91, 1901, 1903 }, // 117 tc_69bfb303
  { 1, 94, 95, 1903, 1904 }, // 118 tc_362b0be2
  { 1, 94, 95, 1904, 1906 }, // 119 tc_dc51281d
  { 1, 94, 95, 1906, 1907 }, // 120 tc_95f43c5e
  { 1, 91, 92, 1907, 1908 }, // 121 tc_decdde8a
  { 1, 91, 92, 1908, 1910 }, // 122 tc_eeda4109
  { 1, 91, 92, 1910, 1912 }, // 123 tc_711c805f
  { 1, 94, 95, 1912, 1914 }, // 124 tc_ed03645c
  { 1, 94, 95, 1914, 1916 }, // 125 tc_42ff66ba
  { 1, 96, 97, 1916, 1918 }, // 126 tc_57a55b54
  { 1, 94, 95, 1918, 1919 }, // 127 tc_f97707c1
  { 1, 96, 97, 1919, 1921 }, // 128 tc_1248597c
  { 1, 96, 97, 1921, 1923 }, // 129 tc_9406230a
  { 1, 94, 95, 1923, 1924 }, // 130 tc_d57d649c
  { 1, 96, 97, 1924, 1926 }, // 131 tc_4abdbdc6
  { 1, 96, 97, 1926, 1928 }, // 132 tc_6d861a95
  { 1, 94, 95, 0, 0 }, // 133 tc_b9bec29e
  { 1, 94, 95, 1928, 1929 }, // 134 tc_45f9d1be
  { 1, 94, 95, 0, 0 }, // 135 tc_33e7e673
  { 1, 92, 93, 1929, 1932 }, // 136 tc_24e109c7
  { 1, 91, 92, 1932, 1935 }, // 137 tc_9e27f2f9
  { 1, 92, 93, 1935, 1938 }, // 138 tc_f6e2aff9
  { 1, 91, 92, 1938, 1941 }, // 139 tc_24f426ab
  { 1, 92, 93, 1941, 1944 }, // 140 tc_975a4e54
  { 1, 94, 95, 1944, 1945 }, // 141 tc_e60def48
  { 1, 90, 91, 1945, 1948 }, // 142 tc_5502c366
  { 1, 92, 93, 1948, 1950 }, // 143 tc_7b9187d3
  { 1, 91, 92, 1950, 1952 }, // 144 tc_f999c66e
  { 1, 95, 96, 1952, 1957 }, // 145 tc_1c7522a8
  { 1, 95, 96, 1957, 1963 }, // 146 tc_76bb5435
  { 1, 95, 96, 1963, 1965 }, // 147 tc_8a6d0d94
  { 1, 92, 93, 1965, 1967 }, // 148 tc_2471c1c8
  { 1, 92, 93, 1967, 1969 }, // 149 tc_64b00d8a
  { 1, 95, 96, 1969, 1974 }, // 150 tc_5f2afaf7
  { 1, 95, 96, 1974, 1978 }, // 151 tc_ac65613f
  { 1, 95, 96, 1978, 1983 }, // 152 tc_a32e03e7
  { 1, 95, 96, 1983, 1986 }, // 153 tc_822c3c68
  { 1, 95, 96, 1986, 1990 }, // 154 tc_abfd9a6d
  { 1, 95, 96, 1990, 1994 }, // 155 tc_bf2ffc0f
  { 1, 92, 93, 1994, 1997 }, // 156 tc_ed3f8d2a
  { 1, 95, 96, 1997, 2000 }, // 157 tc_7c6d32e4
  { 1, 95, 96, 2000, 2005 }, // 158 tc_45791fb8
  { 1, 95, 96, 2005, 2010 }, // 159 tc_b7c4062a
  { 1, 95, 96, 2010, 2013 }, // 160 tc_5944960d
  { 1, 90, 91, 2013, 2017 }, // 161 tc_2c13e7f5
  { 1, 90, 91, 2017, 2021 }, // 162 tc_a154b476
  { 1, 90, 91, 2021, 2025 }, // 163 tc_a4e22bbd
  { 1, 90, 91, 2025, 2029 }, // 164 tc_503ce0f3
  { 1, 95, 96, 2029, 2031 }, // 165 tc_0655b949
  { 1, 92, 93, 2031, 2033 }, // 166 tc_6e20402a
  { 1, 92, 93, 2033, 2034 }, // 167 tc_db96aa6b
  { 1, 90, 91, 2034, 2036 }, // 168 tc_a7bdb22c
  { 1, 90, 91, 2036, 2039 }, // 169 tc_db596beb
  { 1, 90, 91, 2039, 2042 }, // 170 tc_a08b630b
  { 1, 90, 91, 2042, 2045 }, // 171 tc_1fcb8495
  { 1, 95, 96, 2045, 2050 }, // 172 tc_9edefe01
  { 1, 95, 96, 2050, 2055 }, // 173 tc_449acf79
  { 1, 92, 93, 2055, 2060 }, // 174 tc_ce59038e
  { 1, 92, 93, 2060, 2065 }, // 175 tc_f529831b
  { 1, 92, 93, 2065, 2070 }, // 176 tc_addc37a8
  { 1, 92, 93, 2070, 2073 }, // 177 tc_6f42bc60
  { 1, 92, 93, 2073, 2075 }, // 178 tc_7af3a37e
  { 1, 90, 91, 2075, 2077 }, // 179 tc_e3d699e3
  { 1, 95, 96, 2077, 2080 }, // 180 tc_ba9255a6
  { 1, 95, 96, 2080, 2085 }, // 181 tc_1fe4ab69
  { 1, 95, 96, 2085, 2088 }, // 182 tc_bb07f2c5
  { 1, 95, 96, 2088, 2093 }, // 183 tc_8e82e8ca
  { 1, 92, 93, 2093, 2096 }, // 184 tc_cfa0e29b
  { 1, 92, 93, 2096, 2101 }, // 185 tc_0a6c20ae
  { 1, 92, 93, 2101, 2104 }, // 186 tc_0fac1eb8
  { 1, 92, 93, 2104, 2109 }, // 187 tc_829d8a86
  { 1, 95, 96, 2109, 2113 }, // 188 tc_280f7fe1
  { 1, 95, 96, 2113, 2117 }, // 189 tc_887d1bb7
  { 1, 92, 93, 2117, 2121 }, // 190 tc_96ef76ef
  { 1, 92, 93, 2121, 2125 }, // 191 tc_55a9a350
  { 1, 90, 91, 2125, 2129 }, // 192 tc_f0cdeccf
  { 1, 90, 91, 2129, 2134 }, // 193 tc_a38c45dc
  { 1, 90, 91, 2134, 2136 }, // 194 tc_d3632d88
  { 1, 90, 91, 2136, 2140 }, // 195 tc_5e4cf0e8
  { 1, 90, 91, 2140, 2142 }, // 196 tc_ef921005
  { 1, 95, 96, 2142, 2145 }, // 197 tc_5b347363
  { 1, 95, 96, 2145, 2147 }, // 198 tc_3d14a17b
  { 1, 95, 96, 2147, 2148 }, // 199 tc_3fbf1042
  { 1, 95, 96, 2148, 2149 }, // 200 tc_63567288
  { 1, 95, 96, 2149, 2151 }, // 201 tc_59a7822c
  { 1, 95, 96, 0, 0 }, // 202 tc_937dd41c
  { 1, 92, 93, 0, 0 }, // 203 tc_a4ee89db
  { 1, 92, 93, 0, 0 }, // 204 tc_c818ff7f
  { 1, 92, 93, 2151, 2152 }, // 205 tc_1242dc2a
  { 1, 95, 96, 2152, 2154 }, // 206 tc_44d5a428
  { 1, 117, 119, 2154, 2157 }, // 207 tc_540c3da3
  { 1, 106, 108, 2157, 2161 }, // 208 tc_b091f1c6
  { 1, 119, 121, 2161, 2163 }, // 209 tc_5bf8afbb
  { 1, 121, 123, 2163, 2167 }, // 210 tc_2b4c548e
  { 1, 121, 123, 2167, 2172 }, // 211 tc_bb599486
  { 1, 123, 127, 2172, 2175 }, // 212 tc_a7e6707d
  { 1, 123, 127, 2175, 2179 }, // 213 tc_3c56e5ce
  { 1, 101, 104, 2179, 2183 }, // 214 tc_abe8c3b2
  { 1, 101, 104, 2183, 2188 }, // 215 tc_453fe68d
  { 1, 101, 104, 2188, 2192 }, // 216 tc_1ba8a0cd
  { 1, 127, 129, 2192, 2195 }, // 217 tc_52447ecc
  { 1, 127, 129, 2195, 2199 }, // 218 tc_3904b926
  { 1, 127, 129, 2199, 2204 }, // 219 tc_b9db8205
  { 1, 127, 129, 2204, 2208 }, // 220 tc_663c80a7
  { 1, 129, 133, 2208, 2211 }, // 221 tc_f21e8abb
  { 1, 129, 133, 2211, 2215 }, // 222 tc_131f1c81
  { 1, 129, 133, 2215, 2220 }, // 223 tc_c7039829
  { 1, 129, 133, 2220, 2224 }, // 224 tc_e2d2e9e5
  { 1, 133, 135, 2224, 2227 }, // 225 tc_ab23f776
  { 1, 133, 135, 2227, 2231 }, // 226 tc_7177e272
  { 1, 133, 135, 2231, 2236 }, // 227 tc_e99d4c2e
  { 1, 133, 135, 2236, 2240 }, // 228 tc_6942b6e0
  { 1, 108, 111, 2240, 2244 }, // 229 tc_a02a10a8
  { 1, 108, 111, 2244, 2249 }, // 230 tc_54a0dc47
  { 1, 108, 111, 2249, 2253 }, // 231 tc_447d9895
  { 1, 108, 111, 2253, 2258 }, // 232 tc_191381c1
  { 1, 108, 111, 2258, 2262 }, // 233 tc_3e2aaafc
  { 1, 133, 135, 2262, 2264 }, // 234 tc_3ce09744
  { 1, 133, 135, 2264, 2267 }, // 235 tc_20a4bbec
  { 1, 106, 108, 2267, 2269 }, // 236 tc_5cdf8c84
  { 1, 135, 137, 2269, 2271 }, // 237 tc_2a698a03
  { 1, 106, 108, 2271, 2274 }, // 238 tc_c127de3a
  { 1, 137, 139, 2274, 2277 }, // 239 tc_05ca8cfd
  { 1, 121, 123, 2277, 2280 }, // 240 tc_d8287c14
  { 1, 97, 99, 2280, 2284 }, // 241 tc_257f6f7c
  { 1, 97, 99, 2284, 2289 }, // 242 tc_7e6a3e89
  { 1, 97, 99, 2289, 2293 }, // 243 tc_e35c1e93
  { 1, 121, 123, 2293, 2297 }, // 244 tc_08a4f1b6
  { 1, 97, 99, 2297, 2301 }, // 245 tc_57a4709c
  { 1, 119, 121, 2301, 2305 }, // 246 tc_56e64202
  { 1, 106, 108, 2305, 2308 }, // 247 tc_ac4046bc
  { 1, 106, 108, 2308, 2312 }, // 248 tc_2e8f5f6e
  { 1, 137, 139, 2312, 2315 }, // 249 tc_7417e785
  { 1, 137, 139, 2315, 2319 }, // 250 tc_309dbb4f
  { 1, 139, 141, 2319, 2323 }, // 251 tc_df80eeb0
  { 1, 137, 139, 2323, 2327 }, // 252 tc_16ff9ef8
  { 1, 91, 92, 2327, 2329 }, // 253 tc_e2fdd6e6
  { 1, 137, 139, 2329, 2331 }, // 254 tc_51d0ecc3
  { 1, 91, 92, 2331, 2334 }, // 255 tc_531b383c
  { 1, 139, 141, 2334, 2336 }, // 256 tc_04da405a
  { 1, 106, 108, 2336, 2338 }, // 257 tc_3c8c15d0
  { 1, 121, 123, 2338, 2340 }, // 258 tc_0afc8be9
  { 1, 139, 141, 2340, 2345 }, // 259 tc_561aaa58
  { 1, 119, 121, 2345, 2347 }, // 260 tc_946013d8
  { 1, 119, 121, 2347, 2350 }, // 261 tc_46d6c3e0
  { 1, 139, 141, 2350, 2354 }, // 262 tc_87adc037
  { 1, 106, 108, 2354, 2358 }, // 263 tc_a19b9305
  { 1, 106, 108, 2358, 2361 }, // 264 tc_649072c2
  { 1, 121, 123, 2361, 2364 }, // 265 tc_0b04c6c7
  { 1, 121, 123, 2364, 2368 }, // 266 tc_660769f1
  { 1, 121, 123, 2368, 2371 }, // 267 tc_dcca380f
  { 1, 121, 123, 2371, 2375 }, // 268 tc_72e2b393
  { 1, 121, 123, 2375, 2378 }, // 269 tc_73efe966
  { 1, 106, 108, 2378, 2381 }, // 270 tc_cda936da
  { 1, 141, 144, 2381, 2384 }, // 271 tc_a28f32b5
  { 1, 141, 144, 2384, 2388 }, // 272 tc_7d68d5c2
  { 1, 144, 147, 2388, 2391 }, // 273 tc_7095ecba
  { 1, 144, 147, 2391, 2395 }, // 274 tc_a69eeee1
  { 1, 147, 149, 0, 0 }, // 275 tc_1381a97c
  { 1, 147, 149, 2395, 2396 }, // 276 tc_e3f68a46
  { 1, 149, 151, 2396, 2399 }, // 277 tc_f1de44ef
  { 1, 139, 141, 2399, 2404 }, // 278 tc_9d1dc972
  { 1, 149, 151, 2404, 2408 }, // 279 tc_90bcc1db
  { 1, 151, 154, 2408, 2411 }, // 280 tc_cd94bfe0
  { 1, 151, 154, 2411, 2415 }, // 281 tc_15fdf750
  { 1, 121, 123, 2415, 2419 }, // 282 tc_1ad8a370
  { 1, 121, 123, 2419, 2424 }, // 283 tc_e675c45a
  { 1, 121, 123, 2424, 2428 }, // 284 tc_37820f4c
  { 1, 154, 156, 2428, 2431 }, // 285 tc_61bf7c03
  { 1, 154, 156, 2431, 2435 }, // 286 tc_933f2b39
  { 1, 154, 156, 2435, 2439 }, // 287 tc_26a377fe
  { 1, 154, 156, 2439, 2444 }, // 288 tc_2d4051cd
  { 1, 119, 121, 2444, 2447 }, // 289 tc_6e7fa133
  { 1, 97, 99, 2447, 2450 }, // 290 tc_8772086c
  { 1, 99, 101, 2450, 2452 }, // 291 tc_b4416217
  { 1, 108, 111, 2452, 2456 }, // 292 tc_9f363d21
  { 1, 108, 111, 2456, 2461 }, // 293 tc_8e420e4d
  { 1, 156, 159, 2461, 2465 }, // 294 tc_7273323b
  { 1, 156, 159, 2465, 2470 }, // 295 tc_58d21193
  { 1, 99, 101, 2470, 2474 }, // 296 tc_71646d06
  { 1, 139, 141, 2474, 2477 }, // 297 tc_2c745bb8
  { 1, 147, 149, 2477, 2478 }, // 298 tc_b28e51aa
  { 1, 147, 149, 2478, 2480 }, // 299 tc_767c4e9d
  { 1, 159, 161, 2480, 2482 }, // 300 tc_e699ae41
  { 1, 159, 161, 2482, 2485 }, // 301 tc_a0dbea28
  { 1, 159, 161, 2485, 2488 }, // 302 tc_dd5b0695
  { 1, 159, 161, 2488, 2492 }, // 303 tc_3ad719fb
  { 1, 92, 93, 0, 0 }, // 304 tc_77f94a5e
  { 1, 96, 97, 0, 0 }, // 305 tc_55255f2b
  { 0, 0, 0, 0, 0 }, // 306 tc_0a43be35
  { 1, 92, 93, 2492, 2493 }, // 307 tc_b1ae5f67
  { 1, 92, 93, 2493, 2494 }, // 308 tc_d234b61a
  { 1, 92, 93, 2494, 2496 }, // 309 tc_2237d952
  { 1, 92, 93, 0, 0 }, // 310 tc_78f87ed3
  { 1, 92, 93, 2496, 2498 }, // 311 tc_a724463d
  { 1, 92, 93, 2498, 2500 }, // 312 tc_6fb52018
  { 1, 96, 97, 2500, 2502 }, // 313 tc_46c18ecf
  { 1, 94, 95, 2502, 2504 }, // 314 tc_9b20a062
  { 1, 94, 95, 2504, 2506 }, // 315 tc_5a222e89
  { 1, 94, 95, 2506, 2507 }, // 316 tc_0ba0d5da
  { 1, 94, 95, 2507, 2508 }, // 317 tc_7d6a2568
  { 1, 94, 95, 2508, 2510 }, // 318 tc_759e57be
  { 1, 94, 95, 2510, 2512 }, // 319 tc_139ef484
  { 1, 94, 95, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 96, 97, 0, 0 }, // 321 tc_7f58404a
  { 0, 0, 0, 0, 0 }, // 322 tc_b3d46584
  { 1, 96, 97, 2512, 2514 }, // 323 tc_d71ea8fa
  { 1, 96, 97, 2514, 2516 }, // 324 tc_6aa823ab
  { 0, 0, 0, 0, 0 }, // 325 tc_b2196a3f
  { 1, 96, 97, 2516, 2517 }, // 326 tc_2c3e17fc
  { 1, 96, 97, 2517, 2520 }, // 327 tc_27106296
  { 1, 92, 93, 2520, 2522 }, // 328 tc_a3070909
  { 1, 92, 93, 2522, 2524 }, // 329 tc_512b1653
  { 1, 96, 97, 2524, 2525 }, // 330 tc_d7718fbe
  { 1, 96, 97, 2525, 2528 }, // 331 tc_bb78483e
  { 1, 96, 97, 2528, 2529 }, // 332 tc_54f0cee2
  { 1, 96, 97, 2529, 2531 }, // 333 tc_28e55c6f
  { 1, 92, 93, 2531, 2532 }, // 334 tc_4bf903b0
  { 1, 92, 93, 2532, 2533 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV65[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 161, 162, 2533, 2536 }, // 1 tc_01d44cb2
  { 1, 162, 163, 2536, 2539 }, // 2 PSEUDO
  { 1, 162, 163, 2539, 2541 }, // 3 tc_c57d9f39
  { 1, 162, 163, 2541, 2545 }, // 4 tc_1c2c7a4a
  { 1, 162, 163, 2545, 2549 }, // 5 tc_442395f3
  { 1, 162, 163, 2549, 2552 }, // 6 tc_713b66bf
  { 1, 162, 163, 2552, 2555 }, // 7 tc_86173609
  { 1, 161, 162, 2555, 2558 }, // 8 tc_5da50c4b
  { 1, 161, 162, 2558, 2561 }, // 9 tc_4a55d03c
  { 1, 162, 163, 2561, 2564 }, // 10 tc_d33e5eee
  { 1, 161, 162, 2564, 2567 }, // 11 tc_651cbe02
  { 1, 163, 164, 2567, 2570 }, // 12 DUPLEX
  { 1, 164, 165, 2570, 2571 }, // 13 tc_ENDLOOP
  { 1, 162, 163, 0, 0 }, // 14 tc_23708a21
  { 1, 162, 163, 2571, 2573 }, // 15 tc_56a124a7
  { 1, 165, 166, 2573, 2575 }, // 16 tc_2f573607
  { 1, 165, 166, 2575, 2578 }, // 17 tc_53c851ab
  { 1, 166, 167, 2578, 2582 }, // 18 tc_fedb7e19
  { 1, 166, 167, 2582, 2585 }, // 19 tc_4222e6bf
  { 1, 166, 167, 2585, 2589 }, // 20 tc_075c8dd8
  { 1, 163, 164, 2589, 2592 }, // 21 tc_9bcfb2ee
  { 1, 163, 164, 2592, 2595 }, // 22 tc_158aa3f7
  { 1, 163, 164, 2595, 2598 }, // 23 tc_df5d53f9
  { 1, 163, 164, 2598, 2601 }, // 24 tc_14ab4f41
  { 1, 163, 164, 2601, 2602 }, // 25 tc_f38f92e1
  { 1, 163, 164, 2602, 2603 }, // 26 tc_1981450d
  { 1, 166, 167, 2603, 2605 }, // 27 tc_e9170fb7
  { 1, 163, 164, 2605, 2607 }, // 28 tc_40d64c94
  { 1, 166, 167, 2607, 2609 }, // 29 LD_tc_ld_SLOT01
  { 1, 161, 162, 2609, 2612 }, // 30 tc_38382228
  { 1, 161, 162, 2612, 2615 }, // 31 tc_c21d7447
  { 1, 161, 162, 2615, 2619 }, // 32 tc_7f8ae742
  { 1, 167, 168, 2619, 2622 }, // 33 tc_5a4b5e58
  { 1, 167, 168, 2622, 2626 }, // 34 tc_197dce51
  { 1, 161, 162, 2626, 2627 }, // 35 tc_44fffc58
  { 1, 166, 167, 2627, 2632 }, // 36 tc_5ceb2f9e
  { 1, 168, 170, 2632, 2635 }, // 37 tc_56c4f9fe
  { 1, 167, 168, 2635, 2637 }, // 38 tc_7476d766
  { 1, 166, 167, 2637, 2642 }, // 39 tc_b4dc7630
  { 1, 166, 167, 2642, 2646 }, // 40 tc_a2b365d2
  { 1, 165, 166, 2646, 2647 }, // 41 tc_60e324ff
  { 1, 170, 172, 2647, 2650 }, // 42 tc_db5555f3
  { 1, 172, 175, 2650, 2653 }, // 43 tc_c0749f3c
  { 1, 175, 177, 2653, 2656 }, // 44 PSEUDOM
  { 1, 168, 170, 2656, 2659 }, // 45 tc_3aacf4a8
  { 1, 177, 179, 2659, 2661 }, // 46 tc_c4edf264
  { 1, 179, 182, 2661, 2664 }, // 47 tc_c5dba46e
  { 1, 170, 172, 2664, 2668 }, // 48 tc_af25efd9
  { 1, 161, 162, 2668, 2671 }, // 49 tc_0dfac0a7
  { 1, 166, 167, 2671, 2675 }, // 50 tc_8035e91f
  { 1, 163, 164, 2675, 2679 }, // 51 tc_011e0e9d
  { 1, 166, 167, 2679, 2682 }, // 52 tc_ae5babd7
  { 1, 163, 164, 2682, 2685 }, // 53 tc_5deb5e47
  { 1, 161, 162, 2685, 2690 }, // 54 tc_bb831a7c
  { 1, 163, 164, 2690, 2694 }, // 55 tc_92240447
  { 1, 166, 167, 2694, 2697 }, // 56 tc_7c31e19a
  { 1, 166, 167, 2697, 2701 }, // 57 tc_d03278fd
  { 1, 166, 167, 2701, 2705 }, // 58 tc_65cbd974
  { 1, 163, 164, 2705, 2708 }, // 59 tc_934753bb
  { 1, 166, 167, 2708, 2711 }, // 60 ST_tc_st_SLOT01
  { 1, 182, 184, 2711, 2715 }, // 61 CVI_VA
  { 1, 177, 179, 2715, 2719 }, // 62 tc_f175e046
  { 1, 177, 179, 2719, 2724 }, // 63 tc_4942646a
  { 1, 168, 170, 2724, 2726 }, // 64 tc_0ec46cf9
  { 1, 170, 172, 2726, 2727 }, // 65 tc_718b5c53
  { 1, 184, 188, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 167, 168, 2727, 2729 }, // 67 tc_7dc63b5c
  { 1, 163, 164, 2729, 2730 }, // 68 tc_d45ba9cd
  { 1, 162, 163, 2730, 2733 }, // 69 tc_388f9897
  { 1, 162, 163, 2733, 2735 }, // 70 tc_9124c04f
  { 1, 162, 163, 2735, 2738 }, // 71 tc_4ac61d92
  { 1, 166, 167, 2738, 2740 }, // 72 tc_aee6250c
  { 1, 166, 167, 2740, 2743 }, // 73 tc_eed07714
  { 1, 166, 167, 2743, 2746 }, // 74 tc_74a42bda
  { 1, 166, 167, 2746, 2749 }, // 75 tc_a9edeffa
  { 1, 166, 167, 2749, 2752 }, // 76 tc_838c4d7a
  { 1, 161, 162, 2752, 2754 }, // 77 tc_d61dfdc3
  { 1, 161, 162, 2754, 2757 }, // 78 tc_8a825db2
  { 1, 161, 162, 2757, 2760 }, // 79 tc_f34c1c21
  { 1, 162, 163, 2760, 2763 }, // 80 tc_95a33176
  { 1, 161, 162, 2763, 2765 }, // 81 tc_9f6cd987
  { 1, 162, 163, 0, 0 }, // 82 tc_b837298f
  { 1, 162, 163, 2765, 2768 }, // 83 tc_8b5bd4f5
  { 1, 162, 163, 2768, 2771 }, // 84 tc_84a7500d
  { 1, 167, 168, 2771, 2773 }, // 85 tc_49fdfd4b
  { 1, 161, 162, 2773, 2776 }, // 86 tc_f098b237
  { 1, 161, 162, 2776, 2779 }, // 87 tc_20131976
  { 1, 161, 162, 2779, 2784 }, // 88 tc_1d41f8b7
  { 1, 161, 162, 2784, 2787 }, // 89 tc_a1297125
  { 1, 162, 163, 2787, 2788 }, // 90 tc_112d30d6
  { 1, 161, 162, 2788, 2791 }, // 91 tc_d68dca5c
  { 1, 161, 162, 2791, 2795 }, // 92 tc_788b1d09
  { 1, 161, 162, 2795, 2800 }, // 93 tc_38e0bae9
  { 1, 161, 162, 2800, 2803 }, // 94 tc_407e96f9
  { 1, 161, 162, 2803, 2807 }, // 95 tc_7401744f
  { 1, 161, 162, 2807, 2810 }, // 96 tc_9b3c0462
  { 1, 161, 162, 2810, 2812 }, // 97 tc_151bf368
  { 1, 162, 163, 2812, 2815 }, // 98 tc_9c52f549
  { 1, 161, 162, 2815, 2817 }, // 99 tc_55b33fda
  { 1, 161, 162, 2817, 2821 }, // 100 tc_6fc5dbea
  { 1, 167, 168, 2821, 2823 }, // 101 tc_3edca78f
  { 1, 161, 162, 2823, 2827 }, // 102 tc_a7a13fac
  { 1, 161, 162, 2827, 2829 }, // 103 tc_9783714b
  { 1, 161, 162, 2829, 2832 }, // 104 tc_f0e8e832
  { 1, 161, 162, 2832, 2834 }, // 105 tc_65279839
  { 1, 161, 162, 2834, 2838 }, // 106 tc_0a195f2c
  { 1, 161, 162, 2838, 2842 }, // 107 tc_01e1be3b
  { 1, 161, 162, 2842, 2845 }, // 108 tc_556f6577
  { 1, 161, 162, 2845, 2848 }, // 109 tc_02fe1c65
  { 1, 161, 162, 2848, 2852 }, // 110 tc_9e72dc89
  { 1, 161, 162, 2852, 2857 }, // 111 tc_9edb7c77
  { 1, 161, 162, 2857, 2860 }, // 112 tc_7f7f45f5
  { 1, 161, 162, 2860, 2863 }, // 113 tc_c20701f0
  { 1, 161, 162, 2863, 2867 }, // 114 tc_f7569068
  { 1, 167, 168, 2867, 2869 }, // 115 tc_fae9dfa5
  { 1, 167, 168, 2869, 2871 }, // 116 tc_6ae3426b
  { 1, 161, 162, 2871, 2873 }, // 117 tc_69bfb303
  { 1, 165, 166, 2873, 2874 }, // 118 tc_362b0be2
  { 1, 165, 166, 2874, 2876 }, // 119 tc_dc51281d
  { 1, 165, 166, 2876, 2877 }, // 120 tc_95f43c5e
  { 1, 162, 163, 2877, 2878 }, // 121 tc_decdde8a
  { 1, 162, 163, 2878, 2880 }, // 122 tc_eeda4109
  { 1, 162, 163, 2880, 2882 }, // 123 tc_711c805f
  { 1, 165, 166, 2882, 2884 }, // 124 tc_ed03645c
  { 1, 165, 166, 2884, 2886 }, // 125 tc_42ff66ba
  { 1, 167, 168, 2886, 2888 }, // 126 tc_57a55b54
  { 1, 165, 166, 2888, 2889 }, // 127 tc_f97707c1
  { 1, 167, 168, 2889, 2891 }, // 128 tc_1248597c
  { 1, 167, 168, 2891, 2893 }, // 129 tc_9406230a
  { 1, 165, 166, 2893, 2894 }, // 130 tc_d57d649c
  { 1, 167, 168, 2894, 2896 }, // 131 tc_4abdbdc6
  { 1, 167, 168, 2896, 2898 }, // 132 tc_6d861a95
  { 1, 165, 166, 0, 0 }, // 133 tc_b9bec29e
  { 1, 165, 166, 2898, 2899 }, // 134 tc_45f9d1be
  { 1, 165, 166, 0, 0 }, // 135 tc_33e7e673
  { 1, 163, 164, 2899, 2902 }, // 136 tc_24e109c7
  { 1, 162, 163, 2902, 2905 }, // 137 tc_9e27f2f9
  { 1, 163, 164, 2905, 2908 }, // 138 tc_f6e2aff9
  { 1, 162, 163, 2908, 2911 }, // 139 tc_24f426ab
  { 1, 163, 164, 2911, 2914 }, // 140 tc_975a4e54
  { 1, 165, 166, 2914, 2915 }, // 141 tc_e60def48
  { 1, 161, 162, 2915, 2918 }, // 142 tc_5502c366
  { 1, 163, 164, 2918, 2920 }, // 143 tc_7b9187d3
  { 1, 162, 163, 2920, 2922 }, // 144 tc_f999c66e
  { 1, 166, 167, 2922, 2927 }, // 145 tc_1c7522a8
  { 1, 166, 167, 2927, 2933 }, // 146 tc_76bb5435
  { 1, 166, 167, 2933, 2935 }, // 147 tc_8a6d0d94
  { 1, 163, 164, 2935, 2937 }, // 148 tc_2471c1c8
  { 1, 163, 164, 2937, 2939 }, // 149 tc_64b00d8a
  { 1, 166, 167, 2939, 2944 }, // 150 tc_5f2afaf7
  { 1, 166, 167, 2944, 2948 }, // 151 tc_ac65613f
  { 1, 166, 167, 2948, 2953 }, // 152 tc_a32e03e7
  { 1, 166, 167, 2953, 2956 }, // 153 tc_822c3c68
  { 1, 166, 167, 2956, 2960 }, // 154 tc_abfd9a6d
  { 1, 166, 167, 2960, 2964 }, // 155 tc_bf2ffc0f
  { 1, 163, 164, 2964, 2967 }, // 156 tc_ed3f8d2a
  { 1, 166, 167, 2967, 2970 }, // 157 tc_7c6d32e4
  { 1, 166, 167, 2970, 2975 }, // 158 tc_45791fb8
  { 1, 166, 167, 2975, 2980 }, // 159 tc_b7c4062a
  { 1, 166, 167, 2980, 2983 }, // 160 tc_5944960d
  { 1, 161, 162, 2983, 2987 }, // 161 tc_2c13e7f5
  { 1, 161, 162, 2987, 2991 }, // 162 tc_a154b476
  { 1, 161, 162, 2991, 2995 }, // 163 tc_a4e22bbd
  { 1, 161, 162, 2995, 2999 }, // 164 tc_503ce0f3
  { 1, 166, 167, 2999, 3001 }, // 165 tc_0655b949
  { 1, 163, 164, 3001, 3003 }, // 166 tc_6e20402a
  { 1, 163, 164, 3003, 3004 }, // 167 tc_db96aa6b
  { 1, 161, 162, 3004, 3006 }, // 168 tc_a7bdb22c
  { 1, 161, 162, 3006, 3009 }, // 169 tc_db596beb
  { 1, 161, 162, 3009, 3012 }, // 170 tc_a08b630b
  { 1, 161, 162, 3012, 3015 }, // 171 tc_1fcb8495
  { 1, 166, 167, 3015, 3020 }, // 172 tc_9edefe01
  { 1, 166, 167, 3020, 3025 }, // 173 tc_449acf79
  { 1, 163, 164, 3025, 3030 }, // 174 tc_ce59038e
  { 1, 163, 164, 3030, 3035 }, // 175 tc_f529831b
  { 1, 163, 164, 3035, 3040 }, // 176 tc_addc37a8
  { 1, 163, 164, 3040, 3043 }, // 177 tc_6f42bc60
  { 1, 163, 164, 3043, 3045 }, // 178 tc_7af3a37e
  { 1, 161, 162, 3045, 3047 }, // 179 tc_e3d699e3
  { 1, 166, 167, 3047, 3050 }, // 180 tc_ba9255a6
  { 1, 166, 167, 3050, 3055 }, // 181 tc_1fe4ab69
  { 1, 166, 167, 3055, 3058 }, // 182 tc_bb07f2c5
  { 1, 166, 167, 3058, 3063 }, // 183 tc_8e82e8ca
  { 1, 163, 164, 3063, 3066 }, // 184 tc_cfa0e29b
  { 1, 163, 164, 3066, 3071 }, // 185 tc_0a6c20ae
  { 1, 163, 164, 3071, 3074 }, // 186 tc_0fac1eb8
  { 1, 163, 164, 3074, 3079 }, // 187 tc_829d8a86
  { 1, 166, 167, 3079, 3083 }, // 188 tc_280f7fe1
  { 1, 166, 167, 3083, 3087 }, // 189 tc_887d1bb7
  { 1, 163, 164, 3087, 3091 }, // 190 tc_96ef76ef
  { 1, 163, 164, 3091, 3095 }, // 191 tc_55a9a350
  { 1, 161, 162, 3095, 3099 }, // 192 tc_f0cdeccf
  { 1, 161, 162, 3099, 3104 }, // 193 tc_a38c45dc
  { 1, 161, 162, 3104, 3106 }, // 194 tc_d3632d88
  { 1, 161, 162, 3106, 3110 }, // 195 tc_5e4cf0e8
  { 1, 161, 162, 3110, 3112 }, // 196 tc_ef921005
  { 1, 166, 167, 3112, 3115 }, // 197 tc_5b347363
  { 1, 166, 167, 3115, 3117 }, // 198 tc_3d14a17b
  { 1, 166, 167, 3117, 3118 }, // 199 tc_3fbf1042
  { 1, 166, 167, 3118, 3119 }, // 200 tc_63567288
  { 1, 166, 167, 3119, 3121 }, // 201 tc_59a7822c
  { 1, 166, 167, 0, 0 }, // 202 tc_937dd41c
  { 1, 163, 164, 0, 0 }, // 203 tc_a4ee89db
  { 1, 163, 164, 0, 0 }, // 204 tc_c818ff7f
  { 1, 163, 164, 3121, 3122 }, // 205 tc_1242dc2a
  { 1, 166, 167, 3122, 3124 }, // 206 tc_44d5a428
  { 1, 188, 190, 3124, 3127 }, // 207 tc_540c3da3
  { 1, 177, 179, 3127, 3131 }, // 208 tc_b091f1c6
  { 1, 190, 192, 3131, 3133 }, // 209 tc_5bf8afbb
  { 1, 192, 194, 3133, 3137 }, // 210 tc_2b4c548e
  { 1, 192, 194, 3137, 3142 }, // 211 tc_bb599486
  { 1, 194, 198, 3142, 3145 }, // 212 tc_a7e6707d
  { 1, 194, 198, 3145, 3149 }, // 213 tc_3c56e5ce
  { 1, 172, 175, 3149, 3153 }, // 214 tc_abe8c3b2
  { 1, 172, 175, 3153, 3158 }, // 215 tc_453fe68d
  { 1, 172, 175, 3158, 3162 }, // 216 tc_1ba8a0cd
  { 1, 198, 200, 3162, 3165 }, // 217 tc_52447ecc
  { 1, 198, 200, 3165, 3169 }, // 218 tc_3904b926
  { 1, 198, 200, 3169, 3174 }, // 219 tc_b9db8205
  { 1, 198, 200, 3174, 3178 }, // 220 tc_663c80a7
  { 1, 200, 204, 3178, 3181 }, // 221 tc_f21e8abb
  { 1, 200, 204, 3181, 3185 }, // 222 tc_131f1c81
  { 1, 200, 204, 3185, 3190 }, // 223 tc_c7039829
  { 1, 200, 204, 3190, 3194 }, // 224 tc_e2d2e9e5
  { 1, 204, 206, 3194, 3197 }, // 225 tc_ab23f776
  { 1, 204, 206, 3197, 3201 }, // 226 tc_7177e272
  { 1, 204, 206, 3201, 3206 }, // 227 tc_e99d4c2e
  { 1, 204, 206, 3206, 3210 }, // 228 tc_6942b6e0
  { 1, 179, 182, 3210, 3214 }, // 229 tc_a02a10a8
  { 1, 179, 182, 3214, 3219 }, // 230 tc_54a0dc47
  { 1, 179, 182, 3219, 3223 }, // 231 tc_447d9895
  { 1, 179, 182, 3223, 3228 }, // 232 tc_191381c1
  { 1, 179, 182, 3228, 3232 }, // 233 tc_3e2aaafc
  { 1, 204, 206, 3232, 3234 }, // 234 tc_3ce09744
  { 1, 204, 206, 3234, 3237 }, // 235 tc_20a4bbec
  { 1, 177, 179, 3237, 3239 }, // 236 tc_5cdf8c84
  { 1, 206, 208, 3239, 3241 }, // 237 tc_2a698a03
  { 1, 177, 179, 3241, 3244 }, // 238 tc_c127de3a
  { 1, 208, 210, 3244, 3247 }, // 239 tc_05ca8cfd
  { 1, 192, 194, 3247, 3250 }, // 240 tc_d8287c14
  { 1, 168, 170, 3250, 3254 }, // 241 tc_257f6f7c
  { 1, 168, 170, 3254, 3259 }, // 242 tc_7e6a3e89
  { 1, 168, 170, 3259, 3263 }, // 243 tc_e35c1e93
  { 1, 192, 194, 3263, 3267 }, // 244 tc_08a4f1b6
  { 1, 168, 170, 3267, 3271 }, // 245 tc_57a4709c
  { 1, 190, 192, 3271, 3275 }, // 246 tc_56e64202
  { 1, 177, 179, 3275, 3278 }, // 247 tc_ac4046bc
  { 1, 177, 179, 3278, 3282 }, // 248 tc_2e8f5f6e
  { 1, 208, 210, 3282, 3285 }, // 249 tc_7417e785
  { 1, 208, 210, 3285, 3289 }, // 250 tc_309dbb4f
  { 1, 210, 212, 3289, 3293 }, // 251 tc_df80eeb0
  { 1, 208, 210, 3293, 3297 }, // 252 tc_16ff9ef8
  { 1, 162, 163, 3297, 3299 }, // 253 tc_e2fdd6e6
  { 1, 208, 210, 3299, 3301 }, // 254 tc_51d0ecc3
  { 1, 162, 163, 3301, 3304 }, // 255 tc_531b383c
  { 1, 210, 212, 3304, 3306 }, // 256 tc_04da405a
  { 1, 177, 179, 3306, 3308 }, // 257 tc_3c8c15d0
  { 1, 192, 194, 3308, 3310 }, // 258 tc_0afc8be9
  { 1, 210, 212, 3310, 3315 }, // 259 tc_561aaa58
  { 1, 190, 192, 3315, 3317 }, // 260 tc_946013d8
  { 1, 190, 192, 3317, 3320 }, // 261 tc_46d6c3e0
  { 1, 210, 212, 3320, 3324 }, // 262 tc_87adc037
  { 1, 177, 179, 3324, 3328 }, // 263 tc_a19b9305
  { 1, 177, 179, 3328, 3331 }, // 264 tc_649072c2
  { 1, 192, 194, 3331, 3334 }, // 265 tc_0b04c6c7
  { 1, 192, 194, 3334, 3338 }, // 266 tc_660769f1
  { 1, 192, 194, 3338, 3341 }, // 267 tc_dcca380f
  { 1, 192, 194, 3341, 3345 }, // 268 tc_72e2b393
  { 1, 192, 194, 3345, 3348 }, // 269 tc_73efe966
  { 1, 177, 179, 3348, 3351 }, // 270 tc_cda936da
  { 1, 212, 215, 3351, 3354 }, // 271 tc_a28f32b5
  { 1, 212, 215, 3354, 3358 }, // 272 tc_7d68d5c2
  { 1, 215, 218, 3358, 3361 }, // 273 tc_7095ecba
  { 1, 215, 218, 3361, 3365 }, // 274 tc_a69eeee1
  { 1, 218, 220, 0, 0 }, // 275 tc_1381a97c
  { 1, 218, 220, 3365, 3366 }, // 276 tc_e3f68a46
  { 1, 220, 222, 3366, 3369 }, // 277 tc_f1de44ef
  { 1, 210, 212, 3369, 3374 }, // 278 tc_9d1dc972
  { 1, 220, 222, 3374, 3378 }, // 279 tc_90bcc1db
  { 1, 222, 225, 3378, 3381 }, // 280 tc_cd94bfe0
  { 1, 222, 225, 3381, 3385 }, // 281 tc_15fdf750
  { 1, 192, 194, 3385, 3389 }, // 282 tc_1ad8a370
  { 1, 192, 194, 3389, 3394 }, // 283 tc_e675c45a
  { 1, 192, 194, 3394, 3398 }, // 284 tc_37820f4c
  { 1, 225, 227, 3398, 3401 }, // 285 tc_61bf7c03
  { 1, 225, 227, 3401, 3405 }, // 286 tc_933f2b39
  { 1, 225, 227, 3405, 3409 }, // 287 tc_26a377fe
  { 1, 225, 227, 3409, 3414 }, // 288 tc_2d4051cd
  { 1, 190, 192, 3414, 3417 }, // 289 tc_6e7fa133
  { 1, 168, 170, 3417, 3420 }, // 290 tc_8772086c
  { 1, 170, 172, 3420, 3422 }, // 291 tc_b4416217
  { 1, 179, 182, 3422, 3426 }, // 292 tc_9f363d21
  { 1, 179, 182, 3426, 3431 }, // 293 tc_8e420e4d
  { 1, 227, 230, 3431, 3435 }, // 294 tc_7273323b
  { 1, 227, 230, 3435, 3440 }, // 295 tc_58d21193
  { 1, 170, 172, 3440, 3444 }, // 296 tc_71646d06
  { 1, 210, 212, 3444, 3447 }, // 297 tc_2c745bb8
  { 1, 218, 220, 3447, 3448 }, // 298 tc_b28e51aa
  { 1, 218, 220, 3448, 3450 }, // 299 tc_767c4e9d
  { 1, 230, 232, 3450, 3452 }, // 300 tc_e699ae41
  { 1, 230, 232, 3452, 3455 }, // 301 tc_a0dbea28
  { 1, 230, 232, 3455, 3458 }, // 302 tc_dd5b0695
  { 1, 230, 232, 3458, 3462 }, // 303 tc_3ad719fb
  { 1, 163, 164, 0, 0 }, // 304 tc_77f94a5e
  { 1, 167, 168, 0, 0 }, // 305 tc_55255f2b
  { 1, 167, 168, 3462, 3463 }, // 306 tc_0a43be35
  { 1, 163, 164, 3463, 3464 }, // 307 tc_b1ae5f67
  { 1, 163, 164, 3464, 3465 }, // 308 tc_d234b61a
  { 1, 163, 164, 3465, 3467 }, // 309 tc_2237d952
  { 1, 163, 164, 0, 0 }, // 310 tc_78f87ed3
  { 1, 163, 164, 3467, 3469 }, // 311 tc_a724463d
  { 1, 163, 164, 3469, 3471 }, // 312 tc_6fb52018
  { 1, 167, 168, 3471, 3473 }, // 313 tc_46c18ecf
  { 1, 165, 166, 3473, 3475 }, // 314 tc_9b20a062
  { 1, 165, 166, 3475, 3477 }, // 315 tc_5a222e89
  { 1, 165, 166, 3477, 3478 }, // 316 tc_0ba0d5da
  { 1, 165, 166, 3478, 3479 }, // 317 tc_7d6a2568
  { 1, 165, 166, 3479, 3481 }, // 318 tc_759e57be
  { 1, 165, 166, 3481, 3483 }, // 319 tc_139ef484
  { 1, 165, 166, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 167, 168, 0, 0 }, // 321 tc_7f58404a
  { 1, 163, 164, 0, 0 }, // 322 tc_b3d46584
  { 1, 167, 168, 3483, 3485 }, // 323 tc_d71ea8fa
  { 1, 167, 168, 3485, 3487 }, // 324 tc_6aa823ab
  { 1, 167, 168, 3487, 3489 }, // 325 tc_b2196a3f
  { 1, 167, 168, 3489, 3490 }, // 326 tc_2c3e17fc
  { 1, 167, 168, 3490, 3493 }, // 327 tc_27106296
  { 1, 163, 164, 3493, 3495 }, // 328 tc_a3070909
  { 1, 163, 164, 3495, 3497 }, // 329 tc_512b1653
  { 1, 167, 168, 3497, 3498 }, // 330 tc_d7718fbe
  { 1, 167, 168, 3498, 3501 }, // 331 tc_bb78483e
  { 1, 167, 168, 3501, 3502 }, // 332 tc_54f0cee2
  { 1, 167, 168, 3502, 3504 }, // 333 tc_28e55c6f
  { 1, 163, 164, 3504, 3505 }, // 334 tc_4bf903b0
  { 1, 163, 164, 3505, 3506 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV66[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 232, 233, 3506, 3509 }, // 1 tc_01d44cb2
  { 1, 233, 234, 3509, 3512 }, // 2 PSEUDO
  { 1, 233, 234, 3512, 3514 }, // 3 tc_c57d9f39
  { 1, 233, 234, 3514, 3518 }, // 4 tc_1c2c7a4a
  { 1, 233, 234, 3518, 3522 }, // 5 tc_442395f3
  { 1, 233, 234, 3522, 3525 }, // 6 tc_713b66bf
  { 1, 233, 234, 3525, 3528 }, // 7 tc_86173609
  { 1, 232, 233, 3528, 3531 }, // 8 tc_5da50c4b
  { 1, 232, 233, 3531, 3534 }, // 9 tc_4a55d03c
  { 1, 233, 234, 3534, 3537 }, // 10 tc_d33e5eee
  { 1, 232, 233, 3537, 3540 }, // 11 tc_651cbe02
  { 1, 234, 235, 3540, 3543 }, // 12 DUPLEX
  { 1, 235, 236, 3543, 3544 }, // 13 tc_ENDLOOP
  { 1, 233, 234, 0, 0 }, // 14 tc_23708a21
  { 1, 233, 234, 3544, 3546 }, // 15 tc_56a124a7
  { 1, 236, 237, 3546, 3548 }, // 16 tc_2f573607
  { 1, 236, 237, 3548, 3551 }, // 17 tc_53c851ab
  { 1, 237, 238, 3551, 3555 }, // 18 tc_fedb7e19
  { 1, 237, 238, 3555, 3558 }, // 19 tc_4222e6bf
  { 1, 237, 238, 3558, 3562 }, // 20 tc_075c8dd8
  { 1, 234, 235, 3562, 3565 }, // 21 tc_9bcfb2ee
  { 1, 234, 235, 3565, 3568 }, // 22 tc_158aa3f7
  { 1, 234, 235, 3568, 3571 }, // 23 tc_df5d53f9
  { 1, 234, 235, 3571, 3574 }, // 24 tc_14ab4f41
  { 1, 234, 235, 3574, 3575 }, // 25 tc_f38f92e1
  { 1, 234, 235, 3575, 3576 }, // 26 tc_1981450d
  { 1, 237, 238, 3576, 3578 }, // 27 tc_e9170fb7
  { 1, 234, 235, 3578, 3580 }, // 28 tc_40d64c94
  { 1, 237, 238, 3580, 3582 }, // 29 LD_tc_ld_SLOT01
  { 1, 232, 233, 3582, 3585 }, // 30 tc_38382228
  { 1, 232, 233, 3585, 3588 }, // 31 tc_c21d7447
  { 1, 232, 233, 3588, 3592 }, // 32 tc_7f8ae742
  { 1, 238, 239, 3592, 3595 }, // 33 tc_5a4b5e58
  { 1, 238, 239, 3595, 3599 }, // 34 tc_197dce51
  { 1, 232, 233, 3599, 3600 }, // 35 tc_44fffc58
  { 1, 237, 238, 3600, 3605 }, // 36 tc_5ceb2f9e
  { 1, 239, 241, 3605, 3608 }, // 37 tc_56c4f9fe
  { 1, 238, 239, 3608, 3610 }, // 38 tc_7476d766
  { 1, 237, 238, 3610, 3615 }, // 39 tc_b4dc7630
  { 1, 237, 238, 3615, 3619 }, // 40 tc_a2b365d2
  { 1, 236, 237, 3619, 3620 }, // 41 tc_60e324ff
  { 1, 241, 243, 3620, 3623 }, // 42 tc_db5555f3
  { 1, 243, 246, 3623, 3626 }, // 43 tc_c0749f3c
  { 1, 246, 248, 3626, 3629 }, // 44 PSEUDOM
  { 1, 239, 241, 3629, 3632 }, // 45 tc_3aacf4a8
  { 1, 248, 250, 3632, 3634 }, // 46 tc_c4edf264
  { 1, 250, 253, 3634, 3637 }, // 47 tc_c5dba46e
  { 1, 241, 243, 3637, 3641 }, // 48 tc_af25efd9
  { 1, 232, 233, 3641, 3644 }, // 49 tc_0dfac0a7
  { 1, 237, 238, 3644, 3648 }, // 50 tc_8035e91f
  { 1, 234, 235, 3648, 3652 }, // 51 tc_011e0e9d
  { 1, 237, 238, 3652, 3655 }, // 52 tc_ae5babd7
  { 1, 234, 235, 3655, 3658 }, // 53 tc_5deb5e47
  { 1, 232, 233, 3658, 3663 }, // 54 tc_bb831a7c
  { 1, 234, 235, 3663, 3667 }, // 55 tc_92240447
  { 1, 237, 238, 3667, 3670 }, // 56 tc_7c31e19a
  { 1, 237, 238, 3670, 3674 }, // 57 tc_d03278fd
  { 1, 237, 238, 3674, 3678 }, // 58 tc_65cbd974
  { 1, 234, 235, 3678, 3681 }, // 59 tc_934753bb
  { 1, 237, 238, 3681, 3684 }, // 60 ST_tc_st_SLOT01
  { 1, 253, 255, 3684, 3688 }, // 61 CVI_VA
  { 1, 248, 250, 3688, 3692 }, // 62 tc_f175e046
  { 1, 248, 250, 3692, 3697 }, // 63 tc_4942646a
  { 1, 239, 241, 3697, 3699 }, // 64 tc_0ec46cf9
  { 1, 241, 243, 3699, 3700 }, // 65 tc_718b5c53
  { 1, 255, 259, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 238, 239, 3700, 3702 }, // 67 tc_7dc63b5c
  { 1, 234, 235, 3702, 3703 }, // 68 tc_d45ba9cd
  { 1, 233, 234, 3703, 3706 }, // 69 tc_388f9897
  { 1, 233, 234, 3706, 3708 }, // 70 tc_9124c04f
  { 1, 233, 234, 3708, 3711 }, // 71 tc_4ac61d92
  { 1, 237, 238, 3711, 3713 }, // 72 tc_aee6250c
  { 1, 237, 238, 3713, 3716 }, // 73 tc_eed07714
  { 1, 237, 238, 3716, 3719 }, // 74 tc_74a42bda
  { 1, 237, 238, 3719, 3722 }, // 75 tc_a9edeffa
  { 1, 237, 238, 3722, 3725 }, // 76 tc_838c4d7a
  { 1, 232, 233, 3725, 3727 }, // 77 tc_d61dfdc3
  { 1, 232, 233, 3727, 3730 }, // 78 tc_8a825db2
  { 1, 232, 233, 3730, 3733 }, // 79 tc_f34c1c21
  { 1, 233, 234, 3733, 3736 }, // 80 tc_95a33176
  { 1, 232, 233, 3736, 3738 }, // 81 tc_9f6cd987
  { 1, 233, 234, 0, 0 }, // 82 tc_b837298f
  { 1, 233, 234, 3738, 3741 }, // 83 tc_8b5bd4f5
  { 1, 233, 234, 3741, 3744 }, // 84 tc_84a7500d
  { 1, 238, 239, 3744, 3746 }, // 85 tc_49fdfd4b
  { 1, 232, 233, 3746, 3749 }, // 86 tc_f098b237
  { 1, 232, 233, 3749, 3752 }, // 87 tc_20131976
  { 1, 232, 233, 3752, 3757 }, // 88 tc_1d41f8b7
  { 1, 232, 233, 3757, 3760 }, // 89 tc_a1297125
  { 1, 233, 234, 3760, 3761 }, // 90 tc_112d30d6
  { 1, 232, 233, 3761, 3764 }, // 91 tc_d68dca5c
  { 1, 232, 233, 3764, 3768 }, // 92 tc_788b1d09
  { 1, 232, 233, 3768, 3773 }, // 93 tc_38e0bae9
  { 1, 232, 233, 3773, 3776 }, // 94 tc_407e96f9
  { 1, 232, 233, 3776, 3780 }, // 95 tc_7401744f
  { 1, 232, 233, 3780, 3783 }, // 96 tc_9b3c0462
  { 1, 232, 233, 3783, 3785 }, // 97 tc_151bf368
  { 1, 233, 234, 3785, 3788 }, // 98 tc_9c52f549
  { 1, 232, 233, 3788, 3790 }, // 99 tc_55b33fda
  { 1, 232, 233, 3790, 3794 }, // 100 tc_6fc5dbea
  { 1, 238, 239, 3794, 3796 }, // 101 tc_3edca78f
  { 1, 232, 233, 3796, 3800 }, // 102 tc_a7a13fac
  { 1, 232, 233, 3800, 3802 }, // 103 tc_9783714b
  { 1, 232, 233, 3802, 3805 }, // 104 tc_f0e8e832
  { 1, 232, 233, 3805, 3807 }, // 105 tc_65279839
  { 1, 232, 233, 3807, 3811 }, // 106 tc_0a195f2c
  { 1, 232, 233, 3811, 3815 }, // 107 tc_01e1be3b
  { 1, 232, 233, 3815, 3818 }, // 108 tc_556f6577
  { 1, 232, 233, 3818, 3821 }, // 109 tc_02fe1c65
  { 1, 232, 233, 3821, 3825 }, // 110 tc_9e72dc89
  { 1, 232, 233, 3825, 3830 }, // 111 tc_9edb7c77
  { 1, 232, 233, 3830, 3833 }, // 112 tc_7f7f45f5
  { 1, 232, 233, 3833, 3836 }, // 113 tc_c20701f0
  { 1, 232, 233, 3836, 3840 }, // 114 tc_f7569068
  { 1, 238, 239, 3840, 3842 }, // 115 tc_fae9dfa5
  { 1, 238, 239, 3842, 3844 }, // 116 tc_6ae3426b
  { 1, 232, 233, 3844, 3846 }, // 117 tc_69bfb303
  { 1, 236, 237, 3846, 3847 }, // 118 tc_362b0be2
  { 1, 236, 237, 3847, 3849 }, // 119 tc_dc51281d
  { 1, 236, 237, 3849, 3850 }, // 120 tc_95f43c5e
  { 1, 233, 234, 3850, 3851 }, // 121 tc_decdde8a
  { 1, 233, 234, 3851, 3853 }, // 122 tc_eeda4109
  { 1, 233, 234, 3853, 3855 }, // 123 tc_711c805f
  { 1, 236, 237, 3855, 3857 }, // 124 tc_ed03645c
  { 1, 236, 237, 3857, 3859 }, // 125 tc_42ff66ba
  { 1, 238, 239, 3859, 3861 }, // 126 tc_57a55b54
  { 1, 236, 237, 3861, 3862 }, // 127 tc_f97707c1
  { 1, 238, 239, 3862, 3864 }, // 128 tc_1248597c
  { 1, 238, 239, 3864, 3866 }, // 129 tc_9406230a
  { 1, 236, 237, 3866, 3867 }, // 130 tc_d57d649c
  { 1, 238, 239, 3867, 3869 }, // 131 tc_4abdbdc6
  { 1, 238, 239, 3869, 3871 }, // 132 tc_6d861a95
  { 1, 236, 237, 0, 0 }, // 133 tc_b9bec29e
  { 1, 236, 237, 3871, 3872 }, // 134 tc_45f9d1be
  { 1, 236, 237, 0, 0 }, // 135 tc_33e7e673
  { 1, 234, 235, 3872, 3875 }, // 136 tc_24e109c7
  { 1, 233, 234, 3875, 3878 }, // 137 tc_9e27f2f9
  { 1, 234, 235, 3878, 3881 }, // 138 tc_f6e2aff9
  { 1, 233, 234, 3881, 3884 }, // 139 tc_24f426ab
  { 1, 234, 235, 3884, 3887 }, // 140 tc_975a4e54
  { 1, 236, 237, 3887, 3888 }, // 141 tc_e60def48
  { 1, 232, 233, 3888, 3891 }, // 142 tc_5502c366
  { 1, 234, 235, 3891, 3893 }, // 143 tc_7b9187d3
  { 1, 233, 234, 3893, 3895 }, // 144 tc_f999c66e
  { 1, 237, 238, 3895, 3900 }, // 145 tc_1c7522a8
  { 1, 237, 238, 3900, 3906 }, // 146 tc_76bb5435
  { 1, 237, 238, 3906, 3908 }, // 147 tc_8a6d0d94
  { 1, 234, 235, 3908, 3910 }, // 148 tc_2471c1c8
  { 1, 234, 235, 3910, 3912 }, // 149 tc_64b00d8a
  { 1, 237, 238, 3912, 3917 }, // 150 tc_5f2afaf7
  { 1, 237, 238, 3917, 3921 }, // 151 tc_ac65613f
  { 1, 237, 238, 3921, 3926 }, // 152 tc_a32e03e7
  { 1, 237, 238, 3926, 3929 }, // 153 tc_822c3c68
  { 1, 237, 238, 3929, 3933 }, // 154 tc_abfd9a6d
  { 1, 237, 238, 3933, 3937 }, // 155 tc_bf2ffc0f
  { 1, 234, 235, 3937, 3940 }, // 156 tc_ed3f8d2a
  { 1, 237, 238, 3940, 3943 }, // 157 tc_7c6d32e4
  { 1, 237, 238, 3943, 3948 }, // 158 tc_45791fb8
  { 1, 237, 238, 3948, 3953 }, // 159 tc_b7c4062a
  { 1, 237, 238, 3953, 3956 }, // 160 tc_5944960d
  { 1, 232, 233, 3956, 3960 }, // 161 tc_2c13e7f5
  { 1, 232, 233, 3960, 3964 }, // 162 tc_a154b476
  { 1, 232, 233, 3964, 3968 }, // 163 tc_a4e22bbd
  { 1, 232, 233, 3968, 3972 }, // 164 tc_503ce0f3
  { 1, 237, 238, 3972, 3974 }, // 165 tc_0655b949
  { 1, 234, 235, 3974, 3976 }, // 166 tc_6e20402a
  { 1, 234, 235, 3976, 3977 }, // 167 tc_db96aa6b
  { 1, 232, 233, 3977, 3979 }, // 168 tc_a7bdb22c
  { 1, 232, 233, 3979, 3982 }, // 169 tc_db596beb
  { 1, 232, 233, 3982, 3985 }, // 170 tc_a08b630b
  { 1, 232, 233, 3985, 3988 }, // 171 tc_1fcb8495
  { 1, 237, 238, 3988, 3993 }, // 172 tc_9edefe01
  { 1, 237, 238, 3993, 3998 }, // 173 tc_449acf79
  { 1, 234, 235, 3998, 4003 }, // 174 tc_ce59038e
  { 1, 234, 235, 4003, 4008 }, // 175 tc_f529831b
  { 1, 234, 235, 4008, 4013 }, // 176 tc_addc37a8
  { 1, 234, 235, 4013, 4016 }, // 177 tc_6f42bc60
  { 1, 234, 235, 4016, 4018 }, // 178 tc_7af3a37e
  { 1, 232, 233, 4018, 4020 }, // 179 tc_e3d699e3
  { 1, 237, 238, 4020, 4023 }, // 180 tc_ba9255a6
  { 1, 237, 238, 4023, 4028 }, // 181 tc_1fe4ab69
  { 1, 237, 238, 4028, 4031 }, // 182 tc_bb07f2c5
  { 1, 237, 238, 4031, 4036 }, // 183 tc_8e82e8ca
  { 1, 234, 235, 4036, 4039 }, // 184 tc_cfa0e29b
  { 1, 234, 235, 4039, 4044 }, // 185 tc_0a6c20ae
  { 1, 234, 235, 4044, 4047 }, // 186 tc_0fac1eb8
  { 1, 234, 235, 4047, 4052 }, // 187 tc_829d8a86
  { 1, 237, 238, 4052, 4056 }, // 188 tc_280f7fe1
  { 1, 237, 238, 4056, 4060 }, // 189 tc_887d1bb7
  { 1, 234, 235, 4060, 4064 }, // 190 tc_96ef76ef
  { 1, 234, 235, 4064, 4068 }, // 191 tc_55a9a350
  { 1, 232, 233, 4068, 4072 }, // 192 tc_f0cdeccf
  { 1, 232, 233, 4072, 4077 }, // 193 tc_a38c45dc
  { 1, 232, 233, 4077, 4079 }, // 194 tc_d3632d88
  { 1, 232, 233, 4079, 4083 }, // 195 tc_5e4cf0e8
  { 1, 232, 233, 4083, 4085 }, // 196 tc_ef921005
  { 1, 237, 238, 4085, 4088 }, // 197 tc_5b347363
  { 1, 237, 238, 4088, 4090 }, // 198 tc_3d14a17b
  { 1, 237, 238, 4090, 4091 }, // 199 tc_3fbf1042
  { 1, 237, 238, 4091, 4092 }, // 200 tc_63567288
  { 1, 237, 238, 4092, 4094 }, // 201 tc_59a7822c
  { 1, 237, 238, 0, 0 }, // 202 tc_937dd41c
  { 1, 234, 235, 0, 0 }, // 203 tc_a4ee89db
  { 1, 234, 235, 0, 0 }, // 204 tc_c818ff7f
  { 1, 234, 235, 4094, 4095 }, // 205 tc_1242dc2a
  { 1, 237, 238, 4095, 4097 }, // 206 tc_44d5a428
  { 1, 259, 261, 4097, 4100 }, // 207 tc_540c3da3
  { 1, 248, 250, 4100, 4104 }, // 208 tc_b091f1c6
  { 1, 261, 263, 4104, 4106 }, // 209 tc_5bf8afbb
  { 1, 263, 265, 4106, 4110 }, // 210 tc_2b4c548e
  { 1, 263, 265, 4110, 4115 }, // 211 tc_bb599486
  { 1, 265, 269, 4115, 4118 }, // 212 tc_a7e6707d
  { 1, 265, 269, 4118, 4122 }, // 213 tc_3c56e5ce
  { 1, 243, 246, 4122, 4126 }, // 214 tc_abe8c3b2
  { 1, 243, 246, 4126, 4131 }, // 215 tc_453fe68d
  { 1, 243, 246, 4131, 4135 }, // 216 tc_1ba8a0cd
  { 1, 269, 271, 4135, 4138 }, // 217 tc_52447ecc
  { 1, 269, 271, 4138, 4142 }, // 218 tc_3904b926
  { 1, 269, 271, 4142, 4147 }, // 219 tc_b9db8205
  { 1, 269, 271, 4147, 4151 }, // 220 tc_663c80a7
  { 1, 271, 275, 4151, 4154 }, // 221 tc_f21e8abb
  { 1, 271, 275, 4154, 4158 }, // 222 tc_131f1c81
  { 1, 271, 275, 4158, 4163 }, // 223 tc_c7039829
  { 1, 271, 275, 4163, 4167 }, // 224 tc_e2d2e9e5
  { 1, 275, 277, 4167, 4170 }, // 225 tc_ab23f776
  { 1, 275, 277, 4170, 4174 }, // 226 tc_7177e272
  { 1, 275, 277, 4174, 4179 }, // 227 tc_e99d4c2e
  { 1, 275, 277, 4179, 4183 }, // 228 tc_6942b6e0
  { 1, 250, 253, 4183, 4187 }, // 229 tc_a02a10a8
  { 1, 250, 253, 4187, 4192 }, // 230 tc_54a0dc47
  { 1, 250, 253, 4192, 4196 }, // 231 tc_447d9895
  { 1, 250, 253, 4196, 4201 }, // 232 tc_191381c1
  { 1, 250, 253, 4201, 4205 }, // 233 tc_3e2aaafc
  { 1, 275, 277, 4205, 4207 }, // 234 tc_3ce09744
  { 1, 275, 277, 4207, 4210 }, // 235 tc_20a4bbec
  { 1, 248, 250, 4210, 4212 }, // 236 tc_5cdf8c84
  { 1, 277, 279, 4212, 4214 }, // 237 tc_2a698a03
  { 1, 248, 250, 4214, 4217 }, // 238 tc_c127de3a
  { 1, 279, 281, 4217, 4220 }, // 239 tc_05ca8cfd
  { 1, 263, 265, 4220, 4223 }, // 240 tc_d8287c14
  { 1, 239, 241, 4223, 4227 }, // 241 tc_257f6f7c
  { 1, 239, 241, 4227, 4232 }, // 242 tc_7e6a3e89
  { 1, 239, 241, 4232, 4236 }, // 243 tc_e35c1e93
  { 1, 263, 265, 4236, 4240 }, // 244 tc_08a4f1b6
  { 1, 239, 241, 4240, 4244 }, // 245 tc_57a4709c
  { 1, 261, 263, 4244, 4248 }, // 246 tc_56e64202
  { 1, 248, 250, 4248, 4251 }, // 247 tc_ac4046bc
  { 1, 248, 250, 4251, 4255 }, // 248 tc_2e8f5f6e
  { 1, 279, 281, 4255, 4258 }, // 249 tc_7417e785
  { 1, 279, 281, 4258, 4262 }, // 250 tc_309dbb4f
  { 1, 281, 283, 4262, 4266 }, // 251 tc_df80eeb0
  { 1, 279, 281, 4266, 4270 }, // 252 tc_16ff9ef8
  { 1, 233, 234, 4270, 4272 }, // 253 tc_e2fdd6e6
  { 1, 279, 281, 4272, 4274 }, // 254 tc_51d0ecc3
  { 1, 233, 234, 4274, 4277 }, // 255 tc_531b383c
  { 1, 281, 283, 4277, 4279 }, // 256 tc_04da405a
  { 1, 248, 250, 4279, 4281 }, // 257 tc_3c8c15d0
  { 1, 263, 265, 4281, 4283 }, // 258 tc_0afc8be9
  { 1, 281, 283, 4283, 4288 }, // 259 tc_561aaa58
  { 1, 261, 263, 4288, 4290 }, // 260 tc_946013d8
  { 1, 261, 263, 4290, 4293 }, // 261 tc_46d6c3e0
  { 1, 281, 283, 4293, 4297 }, // 262 tc_87adc037
  { 1, 248, 250, 4297, 4301 }, // 263 tc_a19b9305
  { 1, 248, 250, 4301, 4304 }, // 264 tc_649072c2
  { 1, 263, 265, 4304, 4307 }, // 265 tc_0b04c6c7
  { 1, 263, 265, 4307, 4311 }, // 266 tc_660769f1
  { 1, 263, 265, 4311, 4314 }, // 267 tc_dcca380f
  { 1, 263, 265, 4314, 4318 }, // 268 tc_72e2b393
  { 1, 263, 265, 4318, 4321 }, // 269 tc_73efe966
  { 1, 248, 250, 4321, 4324 }, // 270 tc_cda936da
  { 1, 283, 286, 4324, 4327 }, // 271 tc_a28f32b5
  { 1, 283, 286, 4327, 4331 }, // 272 tc_7d68d5c2
  { 1, 286, 289, 4331, 4334 }, // 273 tc_7095ecba
  { 1, 286, 289, 4334, 4338 }, // 274 tc_a69eeee1
  { 1, 289, 291, 0, 0 }, // 275 tc_1381a97c
  { 1, 289, 291, 4338, 4339 }, // 276 tc_e3f68a46
  { 1, 291, 293, 4339, 4342 }, // 277 tc_f1de44ef
  { 1, 281, 283, 4342, 4347 }, // 278 tc_9d1dc972
  { 1, 291, 293, 4347, 4351 }, // 279 tc_90bcc1db
  { 1, 293, 296, 4351, 4354 }, // 280 tc_cd94bfe0
  { 1, 293, 296, 4354, 4358 }, // 281 tc_15fdf750
  { 1, 263, 265, 4358, 4362 }, // 282 tc_1ad8a370
  { 1, 263, 265, 4362, 4367 }, // 283 tc_e675c45a
  { 1, 263, 265, 4367, 4371 }, // 284 tc_37820f4c
  { 1, 296, 298, 4371, 4374 }, // 285 tc_61bf7c03
  { 1, 296, 298, 4374, 4378 }, // 286 tc_933f2b39
  { 1, 296, 298, 4378, 4382 }, // 287 tc_26a377fe
  { 1, 296, 298, 4382, 4387 }, // 288 tc_2d4051cd
  { 1, 261, 263, 4387, 4390 }, // 289 tc_6e7fa133
  { 1, 239, 241, 4390, 4393 }, // 290 tc_8772086c
  { 1, 241, 243, 4393, 4395 }, // 291 tc_b4416217
  { 1, 250, 253, 4395, 4399 }, // 292 tc_9f363d21
  { 1, 250, 253, 4399, 4404 }, // 293 tc_8e420e4d
  { 1, 298, 301, 4404, 4408 }, // 294 tc_7273323b
  { 1, 298, 301, 4408, 4413 }, // 295 tc_58d21193
  { 1, 241, 243, 4413, 4417 }, // 296 tc_71646d06
  { 1, 281, 283, 4417, 4420 }, // 297 tc_2c745bb8
  { 1, 289, 291, 4420, 4421 }, // 298 tc_b28e51aa
  { 1, 289, 291, 4421, 4423 }, // 299 tc_767c4e9d
  { 1, 301, 303, 4423, 4425 }, // 300 tc_e699ae41
  { 1, 301, 303, 4425, 4428 }, // 301 tc_a0dbea28
  { 1, 301, 303, 4428, 4431 }, // 302 tc_dd5b0695
  { 1, 301, 303, 4431, 4435 }, // 303 tc_3ad719fb
  { 1, 234, 235, 0, 0 }, // 304 tc_77f94a5e
  { 1, 238, 239, 0, 0 }, // 305 tc_55255f2b
  { 1, 238, 239, 4435, 4436 }, // 306 tc_0a43be35
  { 1, 234, 235, 4436, 4437 }, // 307 tc_b1ae5f67
  { 1, 234, 235, 4437, 4438 }, // 308 tc_d234b61a
  { 1, 234, 235, 4438, 4440 }, // 309 tc_2237d952
  { 1, 234, 235, 0, 0 }, // 310 tc_78f87ed3
  { 1, 234, 235, 4440, 4442 }, // 311 tc_a724463d
  { 1, 234, 235, 4442, 4444 }, // 312 tc_6fb52018
  { 1, 238, 239, 4444, 4446 }, // 313 tc_46c18ecf
  { 1, 236, 237, 4446, 4448 }, // 314 tc_9b20a062
  { 1, 236, 237, 4448, 4450 }, // 315 tc_5a222e89
  { 1, 236, 237, 4450, 4451 }, // 316 tc_0ba0d5da
  { 1, 236, 237, 4451, 4452 }, // 317 tc_7d6a2568
  { 1, 236, 237, 4452, 4454 }, // 318 tc_759e57be
  { 1, 236, 237, 4454, 4456 }, // 319 tc_139ef484
  { 1, 236, 237, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 238, 239, 0, 0 }, // 321 tc_7f58404a
  { 1, 234, 235, 0, 0 }, // 322 tc_b3d46584
  { 1, 238, 239, 4456, 4458 }, // 323 tc_d71ea8fa
  { 1, 238, 239, 4458, 4460 }, // 324 tc_6aa823ab
  { 1, 238, 239, 4460, 4462 }, // 325 tc_b2196a3f
  { 1, 238, 239, 4462, 4463 }, // 326 tc_2c3e17fc
  { 1, 238, 239, 4463, 4466 }, // 327 tc_27106296
  { 1, 234, 235, 4466, 4468 }, // 328 tc_a3070909
  { 1, 234, 235, 4468, 4470 }, // 329 tc_512b1653
  { 1, 238, 239, 4470, 4471 }, // 330 tc_d7718fbe
  { 1, 238, 239, 4471, 4474 }, // 331 tc_bb78483e
  { 1, 238, 239, 4474, 4475 }, // 332 tc_54f0cee2
  { 1, 238, 239, 4475, 4477 }, // 333 tc_28e55c6f
  { 1, 234, 235, 4477, 4478 }, // 334 tc_4bf903b0
  { 1, 234, 235, 4478, 4479 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV67[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 303, 304, 4479, 4482 }, // 1 tc_01d44cb2
  { 1, 304, 305, 4482, 4485 }, // 2 PSEUDO
  { 1, 304, 305, 4485, 4487 }, // 3 tc_c57d9f39
  { 1, 304, 305, 4487, 4491 }, // 4 tc_1c2c7a4a
  { 1, 304, 305, 4491, 4495 }, // 5 tc_442395f3
  { 1, 304, 305, 4495, 4498 }, // 6 tc_713b66bf
  { 1, 304, 305, 4498, 4501 }, // 7 tc_86173609
  { 1, 303, 304, 4501, 4504 }, // 8 tc_5da50c4b
  { 1, 303, 304, 4504, 4507 }, // 9 tc_4a55d03c
  { 1, 304, 305, 4507, 4510 }, // 10 tc_d33e5eee
  { 1, 303, 304, 4510, 4513 }, // 11 tc_651cbe02
  { 1, 305, 306, 4513, 4516 }, // 12 DUPLEX
  { 1, 306, 307, 4516, 4517 }, // 13 tc_ENDLOOP
  { 1, 304, 305, 0, 0 }, // 14 tc_23708a21
  { 1, 304, 305, 4517, 4519 }, // 15 tc_56a124a7
  { 1, 307, 308, 4519, 4521 }, // 16 tc_2f573607
  { 1, 307, 308, 4521, 4524 }, // 17 tc_53c851ab
  { 1, 308, 309, 4524, 4528 }, // 18 tc_fedb7e19
  { 1, 308, 309, 4528, 4531 }, // 19 tc_4222e6bf
  { 1, 308, 309, 4531, 4535 }, // 20 tc_075c8dd8
  { 1, 305, 306, 4535, 4538 }, // 21 tc_9bcfb2ee
  { 1, 305, 306, 4538, 4541 }, // 22 tc_158aa3f7
  { 1, 305, 306, 4541, 4544 }, // 23 tc_df5d53f9
  { 1, 305, 306, 4544, 4547 }, // 24 tc_14ab4f41
  { 1, 305, 306, 4547, 4548 }, // 25 tc_f38f92e1
  { 1, 305, 306, 4548, 4549 }, // 26 tc_1981450d
  { 1, 308, 309, 4549, 4551 }, // 27 tc_e9170fb7
  { 1, 305, 306, 4551, 4553 }, // 28 tc_40d64c94
  { 1, 308, 309, 4553, 4555 }, // 29 LD_tc_ld_SLOT01
  { 1, 303, 304, 4555, 4558 }, // 30 tc_38382228
  { 1, 303, 304, 4558, 4561 }, // 31 tc_c21d7447
  { 1, 303, 304, 4561, 4565 }, // 32 tc_7f8ae742
  { 1, 309, 310, 4565, 4568 }, // 33 tc_5a4b5e58
  { 1, 309, 310, 4568, 4572 }, // 34 tc_197dce51
  { 1, 303, 304, 4572, 4573 }, // 35 tc_44fffc58
  { 1, 308, 309, 4573, 4578 }, // 36 tc_5ceb2f9e
  { 1, 310, 312, 4578, 4581 }, // 37 tc_56c4f9fe
  { 1, 309, 310, 4581, 4583 }, // 38 tc_7476d766
  { 1, 308, 309, 4583, 4588 }, // 39 tc_b4dc7630
  { 1, 308, 309, 4588, 4592 }, // 40 tc_a2b365d2
  { 1, 307, 308, 4592, 4593 }, // 41 tc_60e324ff
  { 1, 312, 314, 4593, 4596 }, // 42 tc_db5555f3
  { 1, 314, 317, 4596, 4599 }, // 43 tc_c0749f3c
  { 1, 317, 319, 4599, 4602 }, // 44 PSEUDOM
  { 1, 310, 312, 4602, 4605 }, // 45 tc_3aacf4a8
  { 1, 319, 321, 4605, 4607 }, // 46 tc_c4edf264
  { 1, 321, 324, 4607, 4610 }, // 47 tc_c5dba46e
  { 1, 312, 314, 4610, 4614 }, // 48 tc_af25efd9
  { 1, 303, 304, 4614, 4617 }, // 49 tc_0dfac0a7
  { 1, 308, 309, 4617, 4621 }, // 50 tc_8035e91f
  { 1, 305, 306, 4621, 4625 }, // 51 tc_011e0e9d
  { 1, 308, 309, 4625, 4628 }, // 52 tc_ae5babd7
  { 1, 305, 306, 4628, 4631 }, // 53 tc_5deb5e47
  { 1, 303, 304, 4631, 4636 }, // 54 tc_bb831a7c
  { 1, 305, 306, 4636, 4640 }, // 55 tc_92240447
  { 1, 308, 309, 4640, 4643 }, // 56 tc_7c31e19a
  { 1, 308, 309, 4643, 4647 }, // 57 tc_d03278fd
  { 1, 308, 309, 4647, 4651 }, // 58 tc_65cbd974
  { 1, 305, 306, 4651, 4654 }, // 59 tc_934753bb
  { 1, 308, 309, 4654, 4657 }, // 60 ST_tc_st_SLOT01
  { 1, 324, 326, 4657, 4661 }, // 61 CVI_VA
  { 1, 319, 321, 4661, 4665 }, // 62 tc_f175e046
  { 1, 319, 321, 4665, 4670 }, // 63 tc_4942646a
  { 1, 310, 312, 4670, 4672 }, // 64 tc_0ec46cf9
  { 1, 312, 314, 4672, 4673 }, // 65 tc_718b5c53
  { 1, 326, 330, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 309, 310, 4673, 4675 }, // 67 tc_7dc63b5c
  { 1, 305, 306, 4675, 4676 }, // 68 tc_d45ba9cd
  { 1, 304, 305, 4676, 4679 }, // 69 tc_388f9897
  { 1, 304, 305, 4679, 4681 }, // 70 tc_9124c04f
  { 1, 304, 305, 4681, 4684 }, // 71 tc_4ac61d92
  { 1, 308, 309, 4684, 4686 }, // 72 tc_aee6250c
  { 1, 308, 309, 4686, 4689 }, // 73 tc_eed07714
  { 1, 308, 309, 4689, 4692 }, // 74 tc_74a42bda
  { 1, 308, 309, 4692, 4695 }, // 75 tc_a9edeffa
  { 1, 308, 309, 4695, 4698 }, // 76 tc_838c4d7a
  { 1, 303, 304, 4698, 4700 }, // 77 tc_d61dfdc3
  { 1, 303, 304, 4700, 4703 }, // 78 tc_8a825db2
  { 1, 303, 304, 4703, 4706 }, // 79 tc_f34c1c21
  { 1, 304, 305, 4706, 4709 }, // 80 tc_95a33176
  { 1, 303, 304, 4709, 4711 }, // 81 tc_9f6cd987
  { 1, 304, 305, 0, 0 }, // 82 tc_b837298f
  { 1, 304, 305, 4711, 4714 }, // 83 tc_8b5bd4f5
  { 1, 304, 305, 4714, 4717 }, // 84 tc_84a7500d
  { 1, 309, 310, 4717, 4719 }, // 85 tc_49fdfd4b
  { 1, 303, 304, 4719, 4722 }, // 86 tc_f098b237
  { 1, 303, 304, 4722, 4725 }, // 87 tc_20131976
  { 1, 303, 304, 4725, 4730 }, // 88 tc_1d41f8b7
  { 1, 303, 304, 4730, 4733 }, // 89 tc_a1297125
  { 1, 304, 305, 4733, 4734 }, // 90 tc_112d30d6
  { 1, 303, 304, 4734, 4737 }, // 91 tc_d68dca5c
  { 1, 303, 304, 4737, 4741 }, // 92 tc_788b1d09
  { 1, 303, 304, 4741, 4746 }, // 93 tc_38e0bae9
  { 1, 303, 304, 4746, 4749 }, // 94 tc_407e96f9
  { 1, 303, 304, 4749, 4753 }, // 95 tc_7401744f
  { 1, 303, 304, 4753, 4756 }, // 96 tc_9b3c0462
  { 1, 303, 304, 4756, 4758 }, // 97 tc_151bf368
  { 1, 304, 305, 4758, 4761 }, // 98 tc_9c52f549
  { 1, 303, 304, 4761, 4763 }, // 99 tc_55b33fda
  { 1, 303, 304, 4763, 4767 }, // 100 tc_6fc5dbea
  { 1, 309, 310, 4767, 4769 }, // 101 tc_3edca78f
  { 1, 303, 304, 4769, 4773 }, // 102 tc_a7a13fac
  { 1, 303, 304, 4773, 4775 }, // 103 tc_9783714b
  { 1, 303, 304, 4775, 4778 }, // 104 tc_f0e8e832
  { 1, 303, 304, 4778, 4780 }, // 105 tc_65279839
  { 1, 303, 304, 4780, 4784 }, // 106 tc_0a195f2c
  { 1, 303, 304, 4784, 4788 }, // 107 tc_01e1be3b
  { 1, 303, 304, 4788, 4791 }, // 108 tc_556f6577
  { 1, 303, 304, 4791, 4794 }, // 109 tc_02fe1c65
  { 1, 303, 304, 4794, 4798 }, // 110 tc_9e72dc89
  { 1, 303, 304, 4798, 4803 }, // 111 tc_9edb7c77
  { 1, 303, 304, 4803, 4806 }, // 112 tc_7f7f45f5
  { 1, 303, 304, 4806, 4809 }, // 113 tc_c20701f0
  { 1, 303, 304, 4809, 4813 }, // 114 tc_f7569068
  { 1, 309, 310, 4813, 4815 }, // 115 tc_fae9dfa5
  { 1, 309, 310, 4815, 4817 }, // 116 tc_6ae3426b
  { 1, 303, 304, 4817, 4819 }, // 117 tc_69bfb303
  { 1, 307, 308, 4819, 4820 }, // 118 tc_362b0be2
  { 1, 307, 308, 4820, 4822 }, // 119 tc_dc51281d
  { 1, 307, 308, 4822, 4823 }, // 120 tc_95f43c5e
  { 1, 304, 305, 4823, 4824 }, // 121 tc_decdde8a
  { 1, 304, 305, 4824, 4826 }, // 122 tc_eeda4109
  { 1, 304, 305, 4826, 4828 }, // 123 tc_711c805f
  { 1, 307, 308, 4828, 4830 }, // 124 tc_ed03645c
  { 1, 307, 308, 4830, 4832 }, // 125 tc_42ff66ba
  { 1, 309, 310, 4832, 4834 }, // 126 tc_57a55b54
  { 1, 307, 308, 4834, 4835 }, // 127 tc_f97707c1
  { 1, 309, 310, 4835, 4837 }, // 128 tc_1248597c
  { 1, 309, 310, 4837, 4839 }, // 129 tc_9406230a
  { 1, 307, 308, 4839, 4840 }, // 130 tc_d57d649c
  { 1, 309, 310, 4840, 4842 }, // 131 tc_4abdbdc6
  { 1, 309, 310, 4842, 4844 }, // 132 tc_6d861a95
  { 1, 307, 308, 0, 0 }, // 133 tc_b9bec29e
  { 1, 307, 308, 4844, 4845 }, // 134 tc_45f9d1be
  { 1, 307, 308, 0, 0 }, // 135 tc_33e7e673
  { 1, 305, 306, 4845, 4848 }, // 136 tc_24e109c7
  { 1, 304, 305, 4848, 4851 }, // 137 tc_9e27f2f9
  { 1, 305, 306, 4851, 4854 }, // 138 tc_f6e2aff9
  { 1, 304, 305, 4854, 4857 }, // 139 tc_24f426ab
  { 1, 305, 306, 4857, 4860 }, // 140 tc_975a4e54
  { 1, 307, 308, 4860, 4861 }, // 141 tc_e60def48
  { 1, 303, 304, 4861, 4864 }, // 142 tc_5502c366
  { 1, 305, 306, 4864, 4866 }, // 143 tc_7b9187d3
  { 1, 304, 305, 4866, 4868 }, // 144 tc_f999c66e
  { 1, 308, 309, 4868, 4873 }, // 145 tc_1c7522a8
  { 1, 308, 309, 4873, 4879 }, // 146 tc_76bb5435
  { 1, 308, 309, 4879, 4881 }, // 147 tc_8a6d0d94
  { 1, 305, 306, 4881, 4883 }, // 148 tc_2471c1c8
  { 1, 305, 306, 4883, 4885 }, // 149 tc_64b00d8a
  { 1, 308, 309, 4885, 4890 }, // 150 tc_5f2afaf7
  { 1, 308, 309, 4890, 4894 }, // 151 tc_ac65613f
  { 1, 308, 309, 4894, 4899 }, // 152 tc_a32e03e7
  { 1, 308, 309, 4899, 4902 }, // 153 tc_822c3c68
  { 1, 308, 309, 4902, 4906 }, // 154 tc_abfd9a6d
  { 1, 308, 309, 4906, 4910 }, // 155 tc_bf2ffc0f
  { 1, 305, 306, 4910, 4913 }, // 156 tc_ed3f8d2a
  { 1, 308, 309, 4913, 4916 }, // 157 tc_7c6d32e4
  { 1, 308, 309, 4916, 4921 }, // 158 tc_45791fb8
  { 1, 308, 309, 4921, 4926 }, // 159 tc_b7c4062a
  { 1, 308, 309, 4926, 4929 }, // 160 tc_5944960d
  { 1, 303, 304, 4929, 4933 }, // 161 tc_2c13e7f5
  { 1, 303, 304, 4933, 4937 }, // 162 tc_a154b476
  { 1, 303, 304, 4937, 4941 }, // 163 tc_a4e22bbd
  { 1, 303, 304, 4941, 4945 }, // 164 tc_503ce0f3
  { 1, 308, 309, 4945, 4947 }, // 165 tc_0655b949
  { 1, 305, 306, 4947, 4949 }, // 166 tc_6e20402a
  { 1, 305, 306, 4949, 4950 }, // 167 tc_db96aa6b
  { 1, 303, 304, 4950, 4952 }, // 168 tc_a7bdb22c
  { 1, 303, 304, 4952, 4955 }, // 169 tc_db596beb
  { 1, 303, 304, 4955, 4958 }, // 170 tc_a08b630b
  { 1, 303, 304, 4958, 4961 }, // 171 tc_1fcb8495
  { 1, 308, 309, 4961, 4966 }, // 172 tc_9edefe01
  { 1, 308, 309, 4966, 4971 }, // 173 tc_449acf79
  { 1, 305, 306, 4971, 4976 }, // 174 tc_ce59038e
  { 1, 305, 306, 4976, 4981 }, // 175 tc_f529831b
  { 1, 305, 306, 4981, 4986 }, // 176 tc_addc37a8
  { 1, 305, 306, 4986, 4989 }, // 177 tc_6f42bc60
  { 1, 305, 306, 4989, 4991 }, // 178 tc_7af3a37e
  { 1, 303, 304, 4991, 4993 }, // 179 tc_e3d699e3
  { 1, 308, 309, 4993, 4996 }, // 180 tc_ba9255a6
  { 1, 308, 309, 4996, 5001 }, // 181 tc_1fe4ab69
  { 1, 308, 309, 5001, 5004 }, // 182 tc_bb07f2c5
  { 1, 308, 309, 5004, 5009 }, // 183 tc_8e82e8ca
  { 1, 305, 306, 5009, 5012 }, // 184 tc_cfa0e29b
  { 1, 305, 306, 5012, 5017 }, // 185 tc_0a6c20ae
  { 1, 305, 306, 5017, 5020 }, // 186 tc_0fac1eb8
  { 1, 305, 306, 5020, 5025 }, // 187 tc_829d8a86
  { 1, 308, 309, 5025, 5029 }, // 188 tc_280f7fe1
  { 1, 308, 309, 5029, 5033 }, // 189 tc_887d1bb7
  { 1, 305, 306, 5033, 5037 }, // 190 tc_96ef76ef
  { 1, 305, 306, 5037, 5041 }, // 191 tc_55a9a350
  { 1, 303, 304, 5041, 5045 }, // 192 tc_f0cdeccf
  { 1, 303, 304, 5045, 5050 }, // 193 tc_a38c45dc
  { 1, 303, 304, 5050, 5052 }, // 194 tc_d3632d88
  { 1, 303, 304, 5052, 5056 }, // 195 tc_5e4cf0e8
  { 1, 303, 304, 5056, 5058 }, // 196 tc_ef921005
  { 1, 308, 309, 5058, 5061 }, // 197 tc_5b347363
  { 1, 308, 309, 5061, 5063 }, // 198 tc_3d14a17b
  { 1, 308, 309, 5063, 5064 }, // 199 tc_3fbf1042
  { 1, 308, 309, 5064, 5065 }, // 200 tc_63567288
  { 1, 308, 309, 5065, 5067 }, // 201 tc_59a7822c
  { 1, 308, 309, 0, 0 }, // 202 tc_937dd41c
  { 1, 305, 306, 0, 0 }, // 203 tc_a4ee89db
  { 1, 305, 306, 0, 0 }, // 204 tc_c818ff7f
  { 1, 305, 306, 5067, 5068 }, // 205 tc_1242dc2a
  { 1, 308, 309, 5068, 5070 }, // 206 tc_44d5a428
  { 1, 330, 332, 5070, 5073 }, // 207 tc_540c3da3
  { 1, 319, 321, 5073, 5077 }, // 208 tc_b091f1c6
  { 1, 332, 334, 5077, 5079 }, // 209 tc_5bf8afbb
  { 1, 334, 336, 5079, 5083 }, // 210 tc_2b4c548e
  { 1, 334, 336, 5083, 5088 }, // 211 tc_bb599486
  { 1, 336, 340, 5088, 5091 }, // 212 tc_a7e6707d
  { 1, 336, 340, 5091, 5095 }, // 213 tc_3c56e5ce
  { 1, 314, 317, 5095, 5099 }, // 214 tc_abe8c3b2
  { 1, 314, 317, 5099, 5104 }, // 215 tc_453fe68d
  { 1, 314, 317, 5104, 5108 }, // 216 tc_1ba8a0cd
  { 1, 340, 342, 5108, 5111 }, // 217 tc_52447ecc
  { 1, 340, 342, 5111, 5115 }, // 218 tc_3904b926
  { 1, 340, 342, 5115, 5120 }, // 219 tc_b9db8205
  { 1, 340, 342, 5120, 5124 }, // 220 tc_663c80a7
  { 1, 342, 346, 5124, 5127 }, // 221 tc_f21e8abb
  { 1, 342, 346, 5127, 5131 }, // 222 tc_131f1c81
  { 1, 342, 346, 5131, 5136 }, // 223 tc_c7039829
  { 1, 342, 346, 5136, 5140 }, // 224 tc_e2d2e9e5
  { 1, 346, 348, 5140, 5143 }, // 225 tc_ab23f776
  { 1, 346, 348, 5143, 5147 }, // 226 tc_7177e272
  { 1, 346, 348, 5147, 5152 }, // 227 tc_e99d4c2e
  { 1, 346, 348, 5152, 5156 }, // 228 tc_6942b6e0
  { 1, 321, 324, 5156, 5160 }, // 229 tc_a02a10a8
  { 1, 321, 324, 5160, 5165 }, // 230 tc_54a0dc47
  { 1, 321, 324, 5165, 5169 }, // 231 tc_447d9895
  { 1, 321, 324, 5169, 5174 }, // 232 tc_191381c1
  { 1, 321, 324, 5174, 5178 }, // 233 tc_3e2aaafc
  { 1, 346, 348, 5178, 5180 }, // 234 tc_3ce09744
  { 1, 346, 348, 5180, 5183 }, // 235 tc_20a4bbec
  { 1, 319, 321, 5183, 5185 }, // 236 tc_5cdf8c84
  { 1, 348, 350, 5185, 5187 }, // 237 tc_2a698a03
  { 1, 319, 321, 5187, 5190 }, // 238 tc_c127de3a
  { 1, 350, 352, 5190, 5193 }, // 239 tc_05ca8cfd
  { 1, 334, 336, 5193, 5196 }, // 240 tc_d8287c14
  { 1, 310, 312, 5196, 5200 }, // 241 tc_257f6f7c
  { 1, 310, 312, 5200, 5205 }, // 242 tc_7e6a3e89
  { 1, 310, 312, 5205, 5209 }, // 243 tc_e35c1e93
  { 1, 334, 336, 5209, 5213 }, // 244 tc_08a4f1b6
  { 1, 310, 312, 5213, 5217 }, // 245 tc_57a4709c
  { 1, 332, 334, 5217, 5221 }, // 246 tc_56e64202
  { 1, 319, 321, 5221, 5224 }, // 247 tc_ac4046bc
  { 1, 319, 321, 5224, 5228 }, // 248 tc_2e8f5f6e
  { 1, 350, 352, 5228, 5231 }, // 249 tc_7417e785
  { 1, 350, 352, 5231, 5235 }, // 250 tc_309dbb4f
  { 1, 352, 354, 5235, 5239 }, // 251 tc_df80eeb0
  { 1, 350, 352, 5239, 5243 }, // 252 tc_16ff9ef8
  { 1, 304, 305, 5243, 5245 }, // 253 tc_e2fdd6e6
  { 1, 350, 352, 5245, 5247 }, // 254 tc_51d0ecc3
  { 1, 304, 305, 5247, 5250 }, // 255 tc_531b383c
  { 1, 352, 354, 5250, 5252 }, // 256 tc_04da405a
  { 1, 319, 321, 5252, 5254 }, // 257 tc_3c8c15d0
  { 1, 334, 336, 5254, 5256 }, // 258 tc_0afc8be9
  { 1, 352, 354, 5256, 5261 }, // 259 tc_561aaa58
  { 1, 332, 334, 5261, 5263 }, // 260 tc_946013d8
  { 1, 332, 334, 5263, 5266 }, // 261 tc_46d6c3e0
  { 1, 352, 354, 5266, 5270 }, // 262 tc_87adc037
  { 1, 319, 321, 5270, 5274 }, // 263 tc_a19b9305
  { 1, 319, 321, 5274, 5277 }, // 264 tc_649072c2
  { 1, 334, 336, 5277, 5280 }, // 265 tc_0b04c6c7
  { 1, 334, 336, 5280, 5284 }, // 266 tc_660769f1
  { 1, 334, 336, 5284, 5287 }, // 267 tc_dcca380f
  { 1, 334, 336, 5287, 5291 }, // 268 tc_72e2b393
  { 1, 334, 336, 5291, 5294 }, // 269 tc_73efe966
  { 1, 319, 321, 5294, 5297 }, // 270 tc_cda936da
  { 1, 354, 357, 5297, 5300 }, // 271 tc_a28f32b5
  { 1, 354, 357, 5300, 5304 }, // 272 tc_7d68d5c2
  { 1, 357, 360, 5304, 5307 }, // 273 tc_7095ecba
  { 1, 357, 360, 5307, 5311 }, // 274 tc_a69eeee1
  { 1, 360, 362, 0, 0 }, // 275 tc_1381a97c
  { 1, 360, 362, 5311, 5312 }, // 276 tc_e3f68a46
  { 1, 362, 364, 5312, 5315 }, // 277 tc_f1de44ef
  { 1, 352, 354, 5315, 5320 }, // 278 tc_9d1dc972
  { 1, 362, 364, 5320, 5324 }, // 279 tc_90bcc1db
  { 1, 364, 367, 5324, 5327 }, // 280 tc_cd94bfe0
  { 1, 364, 367, 5327, 5331 }, // 281 tc_15fdf750
  { 1, 334, 336, 5331, 5335 }, // 282 tc_1ad8a370
  { 1, 334, 336, 5335, 5340 }, // 283 tc_e675c45a
  { 1, 334, 336, 5340, 5344 }, // 284 tc_37820f4c
  { 1, 367, 369, 5344, 5347 }, // 285 tc_61bf7c03
  { 1, 367, 369, 5347, 5351 }, // 286 tc_933f2b39
  { 1, 367, 369, 5351, 5355 }, // 287 tc_26a377fe
  { 1, 367, 369, 5355, 5360 }, // 288 tc_2d4051cd
  { 1, 332, 334, 5360, 5363 }, // 289 tc_6e7fa133
  { 1, 310, 312, 5363, 5366 }, // 290 tc_8772086c
  { 1, 312, 314, 5366, 5368 }, // 291 tc_b4416217
  { 1, 321, 324, 5368, 5372 }, // 292 tc_9f363d21
  { 1, 321, 324, 5372, 5377 }, // 293 tc_8e420e4d
  { 1, 369, 372, 5377, 5381 }, // 294 tc_7273323b
  { 1, 369, 372, 5381, 5386 }, // 295 tc_58d21193
  { 1, 312, 314, 5386, 5390 }, // 296 tc_71646d06
  { 1, 352, 354, 5390, 5393 }, // 297 tc_2c745bb8
  { 1, 360, 362, 5393, 5394 }, // 298 tc_b28e51aa
  { 1, 360, 362, 5394, 5396 }, // 299 tc_767c4e9d
  { 1, 372, 374, 5396, 5398 }, // 300 tc_e699ae41
  { 1, 372, 374, 5398, 5401 }, // 301 tc_a0dbea28
  { 1, 372, 374, 5401, 5404 }, // 302 tc_dd5b0695
  { 1, 372, 374, 5404, 5408 }, // 303 tc_3ad719fb
  { 1, 305, 306, 0, 0 }, // 304 tc_77f94a5e
  { 1, 309, 310, 0, 0 }, // 305 tc_55255f2b
  { 1, 309, 310, 5408, 5409 }, // 306 tc_0a43be35
  { 1, 305, 306, 5409, 5410 }, // 307 tc_b1ae5f67
  { 1, 305, 306, 5410, 5411 }, // 308 tc_d234b61a
  { 1, 305, 306, 5411, 5413 }, // 309 tc_2237d952
  { 1, 305, 306, 0, 0 }, // 310 tc_78f87ed3
  { 1, 305, 306, 5413, 5415 }, // 311 tc_a724463d
  { 1, 305, 306, 5415, 5417 }, // 312 tc_6fb52018
  { 1, 309, 310, 5417, 5419 }, // 313 tc_46c18ecf
  { 1, 307, 308, 5419, 5421 }, // 314 tc_9b20a062
  { 1, 307, 308, 5421, 5423 }, // 315 tc_5a222e89
  { 1, 307, 308, 5423, 5424 }, // 316 tc_0ba0d5da
  { 1, 307, 308, 5424, 5425 }, // 317 tc_7d6a2568
  { 1, 307, 308, 5425, 5427 }, // 318 tc_759e57be
  { 1, 307, 308, 5427, 5429 }, // 319 tc_139ef484
  { 1, 307, 308, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 309, 310, 0, 0 }, // 321 tc_7f58404a
  { 1, 305, 306, 0, 0 }, // 322 tc_b3d46584
  { 1, 309, 310, 5429, 5431 }, // 323 tc_d71ea8fa
  { 1, 309, 310, 5431, 5433 }, // 324 tc_6aa823ab
  { 1, 309, 310, 5433, 5435 }, // 325 tc_b2196a3f
  { 1, 309, 310, 5435, 5436 }, // 326 tc_2c3e17fc
  { 1, 309, 310, 5436, 5439 }, // 327 tc_27106296
  { 1, 305, 306, 5439, 5441 }, // 328 tc_a3070909
  { 1, 305, 306, 5441, 5443 }, // 329 tc_512b1653
  { 1, 309, 310, 5443, 5444 }, // 330 tc_d7718fbe
  { 1, 309, 310, 5444, 5447 }, // 331 tc_bb78483e
  { 1, 309, 310, 5447, 5448 }, // 332 tc_54f0cee2
  { 1, 309, 310, 5448, 5450 }, // 333 tc_28e55c6f
  { 1, 305, 306, 5450, 5451 }, // 334 tc_4bf903b0
  { 1, 305, 306, 5451, 5452 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV67T[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 374, 375, 5452, 5455 }, // 1 tc_01d44cb2
  { 1, 375, 376, 5455, 5458 }, // 2 PSEUDO
  { 1, 375, 376, 5458, 5460 }, // 3 tc_c57d9f39
  { 1, 375, 376, 5460, 5464 }, // 4 tc_1c2c7a4a
  { 1, 375, 376, 5464, 5468 }, // 5 tc_442395f3
  { 1, 375, 376, 5468, 5471 }, // 6 tc_713b66bf
  { 1, 375, 376, 5471, 5474 }, // 7 tc_86173609
  { 1, 374, 375, 5474, 5477 }, // 8 tc_5da50c4b
  { 1, 374, 375, 5477, 5480 }, // 9 tc_4a55d03c
  { 1, 375, 376, 5480, 5483 }, // 10 tc_d33e5eee
  { 1, 374, 375, 5483, 5486 }, // 11 tc_651cbe02
  { 1, 376, 377, 5486, 5489 }, // 12 DUPLEX
  { 1, 377, 378, 5489, 5490 }, // 13 tc_ENDLOOP
  { 1, 375, 376, 0, 0 }, // 14 tc_23708a21
  { 1, 375, 376, 5490, 5492 }, // 15 tc_56a124a7
  { 1, 378, 379, 5492, 5494 }, // 16 tc_2f573607
  { 1, 378, 379, 5494, 5497 }, // 17 tc_53c851ab
  { 1, 376, 377, 5497, 5501 }, // 18 tc_fedb7e19
  { 1, 376, 377, 5501, 5504 }, // 19 tc_4222e6bf
  { 1, 376, 377, 5504, 5508 }, // 20 tc_075c8dd8
  { 1, 376, 377, 5508, 5511 }, // 21 tc_9bcfb2ee
  { 1, 376, 377, 5511, 5514 }, // 22 tc_158aa3f7
  { 1, 376, 377, 5514, 5517 }, // 23 tc_df5d53f9
  { 1, 376, 377, 5517, 5520 }, // 24 tc_14ab4f41
  { 1, 376, 377, 5520, 5521 }, // 25 tc_f38f92e1
  { 1, 376, 377, 5521, 5522 }, // 26 tc_1981450d
  { 1, 376, 377, 5522, 5524 }, // 27 tc_e9170fb7
  { 1, 376, 377, 5524, 5526 }, // 28 tc_40d64c94
  { 1, 376, 377, 5526, 5529 }, // 29 LD_tc_ld_SLOT01
  { 1, 379, 380, 5529, 5532 }, // 30 tc_38382228
  { 1, 379, 380, 5532, 5535 }, // 31 tc_c21d7447
  { 1, 379, 380, 5535, 5539 }, // 32 tc_7f8ae742
  { 1, 379, 380, 5539, 5542 }, // 33 tc_5a4b5e58
  { 1, 379, 380, 5542, 5546 }, // 34 tc_197dce51
  { 1, 374, 375, 5546, 5547 }, // 35 tc_44fffc58
  { 1, 376, 377, 5547, 5552 }, // 36 tc_5ceb2f9e
  { 1, 380, 382, 5552, 5555 }, // 37 tc_56c4f9fe
  { 1, 379, 380, 5555, 5557 }, // 38 tc_7476d766
  { 1, 376, 377, 5557, 5562 }, // 39 tc_b4dc7630
  { 1, 376, 377, 5562, 5566 }, // 40 tc_a2b365d2
  { 1, 378, 379, 5566, 5567 }, // 41 tc_60e324ff
  { 1, 382, 384, 5567, 5570 }, // 42 tc_db5555f3
  { 1, 384, 387, 5570, 5573 }, // 43 tc_c0749f3c
  { 1, 387, 389, 5573, 5576 }, // 44 PSEUDOM
  { 1, 380, 382, 5576, 5579 }, // 45 tc_3aacf4a8
  { 1, 389, 391, 5579, 5581 }, // 46 tc_c4edf264
  { 1, 391, 394, 5581, 5584 }, // 47 tc_c5dba46e
  { 1, 382, 384, 5584, 5588 }, // 48 tc_af25efd9
  { 1, 374, 375, 5588, 5591 }, // 49 tc_0dfac0a7
  { 1, 376, 377, 5591, 5595 }, // 50 tc_8035e91f
  { 1, 376, 377, 5595, 5599 }, // 51 tc_011e0e9d
  { 1, 376, 377, 5599, 5602 }, // 52 tc_ae5babd7
  { 1, 376, 377, 5602, 5605 }, // 53 tc_5deb5e47
  { 1, 379, 380, 5605, 5610 }, // 54 tc_bb831a7c
  { 1, 376, 377, 5610, 5614 }, // 55 tc_92240447
  { 1, 376, 377, 5614, 5617 }, // 56 tc_7c31e19a
  { 1, 376, 377, 5617, 5621 }, // 57 tc_d03278fd
  { 1, 376, 377, 5621, 5625 }, // 58 tc_65cbd974
  { 1, 376, 377, 5625, 5628 }, // 59 tc_934753bb
  { 1, 376, 377, 5628, 5632 }, // 60 ST_tc_st_SLOT01
  { 1, 394, 396, 5632, 5636 }, // 61 CVI_VA
  { 1, 389, 391, 5636, 5640 }, // 62 tc_f175e046
  { 1, 389, 391, 5640, 5645 }, // 63 tc_4942646a
  { 1, 380, 382, 5645, 5647 }, // 64 tc_0ec46cf9
  { 1, 382, 384, 5647, 5648 }, // 65 tc_718b5c53
  { 1, 396, 400, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 379, 380, 5648, 5650 }, // 67 tc_7dc63b5c
  { 1, 376, 377, 5650, 5651 }, // 68 tc_d45ba9cd
  { 1, 400, 401, 5651, 5654 }, // 69 tc_388f9897
  { 1, 400, 401, 5654, 5656 }, // 70 tc_9124c04f
  { 1, 400, 401, 5656, 5659 }, // 71 tc_4ac61d92
  { 1, 401, 402, 5659, 5661 }, // 72 tc_aee6250c
  { 1, 401, 402, 5661, 5664 }, // 73 tc_eed07714
  { 1, 401, 402, 5664, 5667 }, // 74 tc_74a42bda
  { 1, 401, 402, 5667, 5670 }, // 75 tc_a9edeffa
  { 1, 401, 402, 5670, 5673 }, // 76 tc_838c4d7a
  { 1, 374, 375, 5673, 5675 }, // 77 tc_d61dfdc3
  { 1, 374, 375, 5675, 5678 }, // 78 tc_8a825db2
  { 1, 374, 375, 5678, 5681 }, // 79 tc_f34c1c21
  { 1, 375, 376, 5681, 5684 }, // 80 tc_95a33176
  { 1, 374, 375, 5684, 5686 }, // 81 tc_9f6cd987
  { 1, 375, 376, 0, 0 }, // 82 tc_b837298f
  { 1, 375, 376, 5686, 5689 }, // 83 tc_8b5bd4f5
  { 1, 375, 376, 5689, 5692 }, // 84 tc_84a7500d
  { 1, 379, 380, 5692, 5694 }, // 85 tc_49fdfd4b
  { 1, 374, 375, 5694, 5697 }, // 86 tc_f098b237
  { 1, 374, 375, 5697, 5700 }, // 87 tc_20131976
  { 1, 374, 375, 5700, 5705 }, // 88 tc_1d41f8b7
  { 1, 374, 375, 5705, 5708 }, // 89 tc_a1297125
  { 1, 375, 376, 5708, 5709 }, // 90 tc_112d30d6
  { 1, 379, 380, 5709, 5712 }, // 91 tc_d68dca5c
  { 1, 379, 380, 5712, 5716 }, // 92 tc_788b1d09
  { 1, 379, 380, 5716, 5721 }, // 93 tc_38e0bae9
  { 1, 374, 375, 5721, 5724 }, // 94 tc_407e96f9
  { 1, 379, 380, 5724, 5728 }, // 95 tc_7401744f
  { 1, 374, 375, 5728, 5731 }, // 96 tc_9b3c0462
  { 1, 374, 375, 5731, 5733 }, // 97 tc_151bf368
  { 1, 375, 376, 5733, 5736 }, // 98 tc_9c52f549
  { 1, 374, 375, 5736, 5738 }, // 99 tc_55b33fda
  { 1, 374, 375, 5738, 5742 }, // 100 tc_6fc5dbea
  { 1, 379, 380, 5742, 5744 }, // 101 tc_3edca78f
  { 1, 374, 375, 5744, 5748 }, // 102 tc_a7a13fac
  { 1, 379, 380, 5748, 5750 }, // 103 tc_9783714b
  { 1, 379, 380, 5750, 5753 }, // 104 tc_f0e8e832
  { 1, 374, 375, 5753, 5755 }, // 105 tc_65279839
  { 1, 379, 380, 5755, 5759 }, // 106 tc_0a195f2c
  { 1, 379, 380, 5759, 5763 }, // 107 tc_01e1be3b
  { 1, 379, 380, 5763, 5766 }, // 108 tc_556f6577
  { 1, 379, 380, 5766, 5769 }, // 109 tc_02fe1c65
  { 1, 379, 380, 5769, 5773 }, // 110 tc_9e72dc89
  { 1, 379, 380, 5773, 5778 }, // 111 tc_9edb7c77
  { 1, 379, 380, 5778, 5781 }, // 112 tc_7f7f45f5
  { 1, 374, 375, 5781, 5784 }, // 113 tc_c20701f0
  { 1, 379, 380, 5784, 5788 }, // 114 tc_f7569068
  { 1, 379, 380, 5788, 5790 }, // 115 tc_fae9dfa5
  { 1, 379, 380, 5790, 5792 }, // 116 tc_6ae3426b
  { 1, 374, 375, 5792, 5794 }, // 117 tc_69bfb303
  { 1, 378, 379, 5794, 5795 }, // 118 tc_362b0be2
  { 1, 378, 379, 5795, 5797 }, // 119 tc_dc51281d
  { 1, 378, 379, 5797, 5798 }, // 120 tc_95f43c5e
  { 1, 375, 376, 5798, 5799 }, // 121 tc_decdde8a
  { 1, 375, 376, 5799, 5801 }, // 122 tc_eeda4109
  { 1, 375, 376, 5801, 5803 }, // 123 tc_711c805f
  { 1, 378, 379, 5803, 5805 }, // 124 tc_ed03645c
  { 1, 378, 379, 5805, 5807 }, // 125 tc_42ff66ba
  { 1, 379, 380, 5807, 5809 }, // 126 tc_57a55b54
  { 1, 378, 379, 5809, 5810 }, // 127 tc_f97707c1
  { 1, 379, 380, 5810, 5812 }, // 128 tc_1248597c
  { 1, 379, 380, 5812, 5814 }, // 129 tc_9406230a
  { 1, 378, 379, 5814, 5815 }, // 130 tc_d57d649c
  { 1, 379, 380, 5815, 5817 }, // 131 tc_4abdbdc6
  { 1, 379, 380, 5817, 5819 }, // 132 tc_6d861a95
  { 1, 378, 379, 0, 0 }, // 133 tc_b9bec29e
  { 1, 378, 379, 5819, 5820 }, // 134 tc_45f9d1be
  { 1, 378, 379, 0, 0 }, // 135 tc_33e7e673
  { 1, 376, 377, 5820, 5823 }, // 136 tc_24e109c7
  { 1, 375, 376, 5823, 5826 }, // 137 tc_9e27f2f9
  { 1, 376, 377, 5826, 5829 }, // 138 tc_f6e2aff9
  { 1, 375, 376, 5829, 5832 }, // 139 tc_24f426ab
  { 1, 376, 377, 5832, 5835 }, // 140 tc_975a4e54
  { 1, 378, 379, 5835, 5836 }, // 141 tc_e60def48
  { 1, 374, 375, 5836, 5839 }, // 142 tc_5502c366
  { 1, 376, 377, 5839, 5841 }, // 143 tc_7b9187d3
  { 1, 375, 376, 5841, 5843 }, // 144 tc_f999c66e
  { 1, 376, 377, 5843, 5848 }, // 145 tc_1c7522a8
  { 1, 376, 377, 5848, 5854 }, // 146 tc_76bb5435
  { 1, 376, 377, 5854, 5856 }, // 147 tc_8a6d0d94
  { 1, 376, 377, 5856, 5858 }, // 148 tc_2471c1c8
  { 1, 376, 377, 5858, 5860 }, // 149 tc_64b00d8a
  { 1, 376, 377, 5860, 5865 }, // 150 tc_5f2afaf7
  { 1, 376, 377, 5865, 5869 }, // 151 tc_ac65613f
  { 1, 376, 377, 5869, 5874 }, // 152 tc_a32e03e7
  { 1, 376, 377, 5874, 5877 }, // 153 tc_822c3c68
  { 1, 376, 377, 5877, 5881 }, // 154 tc_abfd9a6d
  { 1, 376, 377, 5881, 5885 }, // 155 tc_bf2ffc0f
  { 1, 376, 377, 5885, 5888 }, // 156 tc_ed3f8d2a
  { 1, 376, 377, 5888, 5891 }, // 157 tc_7c6d32e4
  { 1, 376, 377, 5891, 5896 }, // 158 tc_45791fb8
  { 1, 376, 377, 5896, 5901 }, // 159 tc_b7c4062a
  { 1, 376, 377, 5901, 5904 }, // 160 tc_5944960d
  { 1, 379, 380, 5904, 5908 }, // 161 tc_2c13e7f5
  { 1, 379, 380, 5908, 5912 }, // 162 tc_a154b476
  { 1, 379, 380, 5912, 5916 }, // 163 tc_a4e22bbd
  { 1, 379, 380, 5916, 5920 }, // 164 tc_503ce0f3
  { 1, 376, 377, 5920, 5922 }, // 165 tc_0655b949
  { 1, 376, 377, 5922, 5924 }, // 166 tc_6e20402a
  { 1, 376, 377, 5924, 5925 }, // 167 tc_db96aa6b
  { 1, 379, 380, 5925, 5927 }, // 168 tc_a7bdb22c
  { 1, 379, 380, 5927, 5930 }, // 169 tc_db596beb
  { 1, 379, 380, 5930, 5933 }, // 170 tc_a08b630b
  { 1, 379, 380, 5933, 5936 }, // 171 tc_1fcb8495
  { 1, 376, 377, 5936, 5941 }, // 172 tc_9edefe01
  { 1, 376, 377, 5941, 5946 }, // 173 tc_449acf79
  { 1, 376, 377, 5946, 5951 }, // 174 tc_ce59038e
  { 1, 376, 377, 5951, 5956 }, // 175 tc_f529831b
  { 1, 376, 377, 5956, 5961 }, // 176 tc_addc37a8
  { 1, 376, 377, 5961, 5964 }, // 177 tc_6f42bc60
  { 1, 376, 377, 5964, 5966 }, // 178 tc_7af3a37e
  { 1, 374, 375, 5966, 5968 }, // 179 tc_e3d699e3
  { 1, 376, 377, 5968, 5971 }, // 180 tc_ba9255a6
  { 1, 376, 377, 5971, 5976 }, // 181 tc_1fe4ab69
  { 1, 376, 377, 5976, 5979 }, // 182 tc_bb07f2c5
  { 1, 376, 377, 5979, 5984 }, // 183 tc_8e82e8ca
  { 1, 376, 377, 5984, 5987 }, // 184 tc_cfa0e29b
  { 1, 376, 377, 5987, 5992 }, // 185 tc_0a6c20ae
  { 1, 376, 377, 5992, 5995 }, // 186 tc_0fac1eb8
  { 1, 376, 377, 5995, 6000 }, // 187 tc_829d8a86
  { 1, 376, 377, 6000, 6004 }, // 188 tc_280f7fe1
  { 1, 376, 377, 6004, 6008 }, // 189 tc_887d1bb7
  { 1, 376, 377, 6008, 6012 }, // 190 tc_96ef76ef
  { 1, 376, 377, 6012, 6016 }, // 191 tc_55a9a350
  { 1, 379, 380, 6016, 6020 }, // 192 tc_f0cdeccf
  { 1, 379, 380, 6020, 6025 }, // 193 tc_a38c45dc
  { 1, 379, 380, 6025, 6027 }, // 194 tc_d3632d88
  { 1, 379, 380, 6027, 6031 }, // 195 tc_5e4cf0e8
  { 1, 374, 375, 6031, 6033 }, // 196 tc_ef921005
  { 1, 376, 377, 6033, 6036 }, // 197 tc_5b347363
  { 1, 376, 377, 6036, 6038 }, // 198 tc_3d14a17b
  { 1, 376, 377, 6038, 6039 }, // 199 tc_3fbf1042
  { 1, 376, 377, 6039, 6040 }, // 200 tc_63567288
  { 1, 376, 377, 6040, 6042 }, // 201 tc_59a7822c
  { 1, 376, 377, 0, 0 }, // 202 tc_937dd41c
  { 1, 376, 377, 0, 0 }, // 203 tc_a4ee89db
  { 1, 376, 377, 0, 0 }, // 204 tc_c818ff7f
  { 1, 376, 377, 6042, 6043 }, // 205 tc_1242dc2a
  { 1, 376, 377, 6043, 6045 }, // 206 tc_44d5a428
  { 1, 402, 404, 6045, 6048 }, // 207 tc_540c3da3
  { 1, 389, 391, 6048, 6052 }, // 208 tc_b091f1c6
  { 1, 404, 406, 6052, 6054 }, // 209 tc_5bf8afbb
  { 1, 406, 408, 6054, 6058 }, // 210 tc_2b4c548e
  { 1, 406, 408, 6058, 6063 }, // 211 tc_bb599486
  { 1, 408, 412, 6063, 6066 }, // 212 tc_a7e6707d
  { 1, 408, 412, 6066, 6070 }, // 213 tc_3c56e5ce
  { 1, 384, 387, 6070, 6074 }, // 214 tc_abe8c3b2
  { 1, 384, 387, 6074, 6079 }, // 215 tc_453fe68d
  { 1, 384, 387, 6079, 6083 }, // 216 tc_1ba8a0cd
  { 1, 412, 414, 6083, 6086 }, // 217 tc_52447ecc
  { 1, 412, 414, 6086, 6090 }, // 218 tc_3904b926
  { 1, 412, 414, 6090, 6095 }, // 219 tc_b9db8205
  { 1, 412, 414, 6095, 6099 }, // 220 tc_663c80a7
  { 1, 414, 418, 6099, 6102 }, // 221 tc_f21e8abb
  { 1, 414, 418, 6102, 6106 }, // 222 tc_131f1c81
  { 1, 414, 418, 6106, 6111 }, // 223 tc_c7039829
  { 1, 414, 418, 6111, 6115 }, // 224 tc_e2d2e9e5
  { 1, 418, 420, 6115, 6118 }, // 225 tc_ab23f776
  { 1, 418, 420, 6118, 6122 }, // 226 tc_7177e272
  { 1, 418, 420, 6122, 6127 }, // 227 tc_e99d4c2e
  { 1, 418, 420, 6127, 6131 }, // 228 tc_6942b6e0
  { 1, 391, 394, 6131, 6135 }, // 229 tc_a02a10a8
  { 1, 391, 394, 6135, 6140 }, // 230 tc_54a0dc47
  { 1, 391, 394, 6140, 6144 }, // 231 tc_447d9895
  { 1, 391, 394, 6144, 6149 }, // 232 tc_191381c1
  { 1, 391, 394, 6149, 6153 }, // 233 tc_3e2aaafc
  { 1, 418, 420, 6153, 6155 }, // 234 tc_3ce09744
  { 1, 418, 420, 6155, 6158 }, // 235 tc_20a4bbec
  { 1, 389, 391, 6158, 6160 }, // 236 tc_5cdf8c84
  { 1, 420, 422, 6160, 6162 }, // 237 tc_2a698a03
  { 1, 389, 391, 6162, 6165 }, // 238 tc_c127de3a
  { 1, 422, 424, 6165, 6168 }, // 239 tc_05ca8cfd
  { 1, 406, 408, 6168, 6171 }, // 240 tc_d8287c14
  { 1, 380, 382, 6171, 6175 }, // 241 tc_257f6f7c
  { 1, 380, 382, 6175, 6180 }, // 242 tc_7e6a3e89
  { 1, 380, 382, 6180, 6184 }, // 243 tc_e35c1e93
  { 1, 406, 408, 6184, 6188 }, // 244 tc_08a4f1b6
  { 1, 380, 382, 6188, 6192 }, // 245 tc_57a4709c
  { 1, 404, 406, 6192, 6196 }, // 246 tc_56e64202
  { 1, 389, 391, 6196, 6199 }, // 247 tc_ac4046bc
  { 1, 389, 391, 6199, 6203 }, // 248 tc_2e8f5f6e
  { 1, 422, 424, 6203, 6206 }, // 249 tc_7417e785
  { 1, 422, 424, 6206, 6210 }, // 250 tc_309dbb4f
  { 1, 424, 426, 6210, 6214 }, // 251 tc_df80eeb0
  { 1, 422, 424, 6214, 6218 }, // 252 tc_16ff9ef8
  { 1, 400, 401, 6218, 6220 }, // 253 tc_e2fdd6e6
  { 1, 422, 424, 6220, 6222 }, // 254 tc_51d0ecc3
  { 1, 400, 401, 6222, 6225 }, // 255 tc_531b383c
  { 1, 424, 426, 6225, 6227 }, // 256 tc_04da405a
  { 1, 389, 391, 6227, 6229 }, // 257 tc_3c8c15d0
  { 1, 406, 408, 6229, 6231 }, // 258 tc_0afc8be9
  { 1, 424, 426, 6231, 6236 }, // 259 tc_561aaa58
  { 1, 404, 406, 6236, 6238 }, // 260 tc_946013d8
  { 1, 404, 406, 6238, 6241 }, // 261 tc_46d6c3e0
  { 1, 424, 426, 6241, 6245 }, // 262 tc_87adc037
  { 1, 389, 391, 6245, 6249 }, // 263 tc_a19b9305
  { 1, 389, 391, 6249, 6252 }, // 264 tc_649072c2
  { 1, 406, 408, 6252, 6255 }, // 265 tc_0b04c6c7
  { 1, 406, 408, 6255, 6259 }, // 266 tc_660769f1
  { 1, 406, 408, 6259, 6262 }, // 267 tc_dcca380f
  { 1, 406, 408, 6262, 6266 }, // 268 tc_72e2b393
  { 1, 406, 408, 6266, 6269 }, // 269 tc_73efe966
  { 1, 389, 391, 6269, 6272 }, // 270 tc_cda936da
  { 1, 426, 429, 6272, 6275 }, // 271 tc_a28f32b5
  { 1, 426, 429, 6275, 6279 }, // 272 tc_7d68d5c2
  { 1, 429, 432, 6279, 6282 }, // 273 tc_7095ecba
  { 1, 429, 432, 6282, 6286 }, // 274 tc_a69eeee1
  { 1, 432, 434, 0, 0 }, // 275 tc_1381a97c
  { 1, 432, 434, 6286, 6287 }, // 276 tc_e3f68a46
  { 1, 434, 436, 6287, 6290 }, // 277 tc_f1de44ef
  { 1, 424, 426, 6290, 6295 }, // 278 tc_9d1dc972
  { 1, 434, 436, 6295, 6299 }, // 279 tc_90bcc1db
  { 1, 436, 439, 6299, 6302 }, // 280 tc_cd94bfe0
  { 1, 436, 439, 6302, 6306 }, // 281 tc_15fdf750
  { 1, 406, 408, 6306, 6310 }, // 282 tc_1ad8a370
  { 1, 406, 408, 6310, 6315 }, // 283 tc_e675c45a
  { 1, 406, 408, 6315, 6319 }, // 284 tc_37820f4c
  { 1, 439, 441, 6319, 6322 }, // 285 tc_61bf7c03
  { 1, 439, 441, 6322, 6326 }, // 286 tc_933f2b39
  { 1, 439, 441, 6326, 6330 }, // 287 tc_26a377fe
  { 1, 439, 441, 6330, 6335 }, // 288 tc_2d4051cd
  { 1, 404, 406, 6335, 6338 }, // 289 tc_6e7fa133
  { 1, 380, 382, 6338, 6341 }, // 290 tc_8772086c
  { 1, 382, 384, 6341, 6343 }, // 291 tc_b4416217
  { 1, 391, 394, 6343, 6347 }, // 292 tc_9f363d21
  { 1, 391, 394, 6347, 6352 }, // 293 tc_8e420e4d
  { 1, 441, 444, 6352, 6356 }, // 294 tc_7273323b
  { 1, 441, 444, 6356, 6361 }, // 295 tc_58d21193
  { 1, 382, 384, 6361, 6365 }, // 296 tc_71646d06
  { 1, 424, 426, 6365, 6368 }, // 297 tc_2c745bb8
  { 1, 432, 434, 6368, 6369 }, // 298 tc_b28e51aa
  { 1, 432, 434, 6369, 6371 }, // 299 tc_767c4e9d
  { 1, 444, 446, 6371, 6373 }, // 300 tc_e699ae41
  { 1, 444, 446, 6373, 6376 }, // 301 tc_a0dbea28
  { 1, 444, 446, 6376, 6379 }, // 302 tc_dd5b0695
  { 1, 444, 446, 6379, 6383 }, // 303 tc_3ad719fb
  { 1, 376, 377, 0, 0 }, // 304 tc_77f94a5e
  { 1, 379, 380, 0, 0 }, // 305 tc_55255f2b
  { 1, 379, 380, 6383, 6384 }, // 306 tc_0a43be35
  { 1, 376, 377, 6384, 6385 }, // 307 tc_b1ae5f67
  { 1, 376, 377, 6385, 6386 }, // 308 tc_d234b61a
  { 1, 376, 377, 6386, 6388 }, // 309 tc_2237d952
  { 1, 376, 377, 0, 0 }, // 310 tc_78f87ed3
  { 1, 376, 377, 6388, 6390 }, // 311 tc_a724463d
  { 1, 376, 377, 6390, 6392 }, // 312 tc_6fb52018
  { 1, 379, 380, 6392, 6394 }, // 313 tc_46c18ecf
  { 1, 378, 379, 6394, 6396 }, // 314 tc_9b20a062
  { 1, 378, 379, 6396, 6398 }, // 315 tc_5a222e89
  { 1, 378, 379, 6398, 6399 }, // 316 tc_0ba0d5da
  { 1, 378, 379, 6399, 6400 }, // 317 tc_7d6a2568
  { 1, 378, 379, 6400, 6402 }, // 318 tc_759e57be
  { 1, 378, 379, 6402, 6404 }, // 319 tc_139ef484
  { 1, 378, 379, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 379, 380, 0, 0 }, // 321 tc_7f58404a
  { 1, 376, 377, 0, 0 }, // 322 tc_b3d46584
  { 1, 379, 380, 6404, 6406 }, // 323 tc_d71ea8fa
  { 1, 379, 380, 6406, 6408 }, // 324 tc_6aa823ab
  { 1, 379, 380, 6408, 6410 }, // 325 tc_b2196a3f
  { 1, 379, 380, 6410, 6411 }, // 326 tc_2c3e17fc
  { 1, 379, 380, 6411, 6414 }, // 327 tc_27106296
  { 1, 376, 377, 6414, 6416 }, // 328 tc_a3070909
  { 1, 376, 377, 6416, 6418 }, // 329 tc_512b1653
  { 1, 379, 380, 6418, 6419 }, // 330 tc_d7718fbe
  { 1, 379, 380, 6419, 6422 }, // 331 tc_bb78483e
  { 1, 379, 380, 6422, 6423 }, // 332 tc_54f0cee2
  { 1, 379, 380, 6423, 6425 }, // 333 tc_28e55c6f
  { 1, 376, 377, 6425, 6426 }, // 334 tc_4bf903b0
  { 1, 376, 377, 6426, 6427 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV68[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 446, 447, 6427, 6430 }, // 1 tc_01d44cb2
  { 1, 447, 448, 6430, 6433 }, // 2 PSEUDO
  { 1, 447, 448, 6433, 6435 }, // 3 tc_c57d9f39
  { 1, 447, 448, 6435, 6439 }, // 4 tc_1c2c7a4a
  { 1, 447, 448, 6439, 6443 }, // 5 tc_442395f3
  { 1, 447, 448, 6443, 6446 }, // 6 tc_713b66bf
  { 1, 447, 448, 6446, 6449 }, // 7 tc_86173609
  { 1, 446, 447, 6449, 6452 }, // 8 tc_5da50c4b
  { 1, 446, 447, 6452, 6455 }, // 9 tc_4a55d03c
  { 1, 447, 448, 6455, 6458 }, // 10 tc_d33e5eee
  { 1, 446, 447, 6458, 6461 }, // 11 tc_651cbe02
  { 1, 448, 449, 6461, 6464 }, // 12 DUPLEX
  { 1, 449, 450, 6464, 6465 }, // 13 tc_ENDLOOP
  { 1, 447, 448, 0, 0 }, // 14 tc_23708a21
  { 1, 447, 448, 6465, 6467 }, // 15 tc_56a124a7
  { 1, 450, 451, 6467, 6469 }, // 16 tc_2f573607
  { 1, 450, 451, 6469, 6472 }, // 17 tc_53c851ab
  { 1, 451, 452, 6472, 6476 }, // 18 tc_fedb7e19
  { 1, 451, 452, 6476, 6479 }, // 19 tc_4222e6bf
  { 1, 451, 452, 6479, 6483 }, // 20 tc_075c8dd8
  { 1, 448, 449, 6483, 6486 }, // 21 tc_9bcfb2ee
  { 1, 448, 449, 6486, 6489 }, // 22 tc_158aa3f7
  { 1, 448, 449, 6489, 6492 }, // 23 tc_df5d53f9
  { 1, 448, 449, 6492, 6495 }, // 24 tc_14ab4f41
  { 1, 448, 449, 6495, 6496 }, // 25 tc_f38f92e1
  { 1, 448, 449, 6496, 6497 }, // 26 tc_1981450d
  { 1, 451, 452, 6497, 6499 }, // 27 tc_e9170fb7
  { 1, 448, 449, 6499, 6501 }, // 28 tc_40d64c94
  { 1, 451, 452, 6501, 6503 }, // 29 LD_tc_ld_SLOT01
  { 1, 446, 447, 6503, 6506 }, // 30 tc_38382228
  { 1, 446, 447, 6506, 6509 }, // 31 tc_c21d7447
  { 1, 446, 447, 6509, 6513 }, // 32 tc_7f8ae742
  { 1, 452, 453, 6513, 6516 }, // 33 tc_5a4b5e58
  { 1, 452, 453, 6516, 6520 }, // 34 tc_197dce51
  { 1, 446, 447, 6520, 6521 }, // 35 tc_44fffc58
  { 1, 451, 452, 6521, 6526 }, // 36 tc_5ceb2f9e
  { 1, 453, 455, 6526, 6529 }, // 37 tc_56c4f9fe
  { 1, 452, 453, 6529, 6531 }, // 38 tc_7476d766
  { 1, 451, 452, 6531, 6536 }, // 39 tc_b4dc7630
  { 1, 451, 452, 6536, 6540 }, // 40 tc_a2b365d2
  { 1, 450, 451, 6540, 6541 }, // 41 tc_60e324ff
  { 1, 455, 457, 6541, 6544 }, // 42 tc_db5555f3
  { 1, 457, 460, 6544, 6547 }, // 43 tc_c0749f3c
  { 1, 460, 462, 6547, 6550 }, // 44 PSEUDOM
  { 1, 453, 455, 6550, 6553 }, // 45 tc_3aacf4a8
  { 1, 462, 464, 6553, 6555 }, // 46 tc_c4edf264
  { 1, 464, 467, 6555, 6558 }, // 47 tc_c5dba46e
  { 1, 455, 457, 6558, 6562 }, // 48 tc_af25efd9
  { 1, 446, 447, 6562, 6565 }, // 49 tc_0dfac0a7
  { 1, 451, 452, 6565, 6569 }, // 50 tc_8035e91f
  { 1, 448, 449, 6569, 6573 }, // 51 tc_011e0e9d
  { 1, 451, 452, 6573, 6576 }, // 52 tc_ae5babd7
  { 1, 448, 449, 6576, 6579 }, // 53 tc_5deb5e47
  { 1, 446, 447, 6579, 6584 }, // 54 tc_bb831a7c
  { 1, 448, 449, 6584, 6588 }, // 55 tc_92240447
  { 1, 451, 452, 6588, 6591 }, // 56 tc_7c31e19a
  { 1, 451, 452, 6591, 6595 }, // 57 tc_d03278fd
  { 1, 451, 452, 6595, 6599 }, // 58 tc_65cbd974
  { 1, 448, 449, 6599, 6602 }, // 59 tc_934753bb
  { 1, 451, 452, 6602, 6605 }, // 60 ST_tc_st_SLOT01
  { 1, 467, 469, 6605, 6609 }, // 61 CVI_VA
  { 1, 462, 464, 6609, 6613 }, // 62 tc_f175e046
  { 1, 462, 464, 6613, 6618 }, // 63 tc_4942646a
  { 1, 453, 455, 6618, 6620 }, // 64 tc_0ec46cf9
  { 1, 455, 457, 6620, 6621 }, // 65 tc_718b5c53
  { 1, 469, 473, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 452, 453, 6621, 6623 }, // 67 tc_7dc63b5c
  { 1, 448, 449, 6623, 6624 }, // 68 tc_d45ba9cd
  { 1, 447, 448, 6624, 6627 }, // 69 tc_388f9897
  { 1, 447, 448, 6627, 6629 }, // 70 tc_9124c04f
  { 1, 447, 448, 6629, 6632 }, // 71 tc_4ac61d92
  { 1, 451, 452, 6632, 6634 }, // 72 tc_aee6250c
  { 1, 451, 452, 6634, 6637 }, // 73 tc_eed07714
  { 1, 451, 452, 6637, 6640 }, // 74 tc_74a42bda
  { 1, 451, 452, 6640, 6643 }, // 75 tc_a9edeffa
  { 1, 451, 452, 6643, 6646 }, // 76 tc_838c4d7a
  { 1, 446, 447, 6646, 6648 }, // 77 tc_d61dfdc3
  { 1, 446, 447, 6648, 6651 }, // 78 tc_8a825db2
  { 1, 446, 447, 6651, 6654 }, // 79 tc_f34c1c21
  { 1, 447, 448, 6654, 6657 }, // 80 tc_95a33176
  { 1, 446, 447, 6657, 6659 }, // 81 tc_9f6cd987
  { 1, 447, 448, 0, 0 }, // 82 tc_b837298f
  { 1, 447, 448, 6659, 6662 }, // 83 tc_8b5bd4f5
  { 1, 447, 448, 6662, 6665 }, // 84 tc_84a7500d
  { 1, 452, 453, 6665, 6667 }, // 85 tc_49fdfd4b
  { 1, 446, 447, 6667, 6670 }, // 86 tc_f098b237
  { 1, 446, 447, 6670, 6673 }, // 87 tc_20131976
  { 1, 446, 447, 6673, 6678 }, // 88 tc_1d41f8b7
  { 1, 446, 447, 6678, 6681 }, // 89 tc_a1297125
  { 1, 447, 448, 6681, 6682 }, // 90 tc_112d30d6
  { 1, 446, 447, 6682, 6685 }, // 91 tc_d68dca5c
  { 1, 446, 447, 6685, 6689 }, // 92 tc_788b1d09
  { 1, 446, 447, 6689, 6694 }, // 93 tc_38e0bae9
  { 1, 446, 447, 6694, 6697 }, // 94 tc_407e96f9
  { 1, 446, 447, 6697, 6701 }, // 95 tc_7401744f
  { 1, 446, 447, 6701, 6704 }, // 96 tc_9b3c0462
  { 1, 446, 447, 6704, 6706 }, // 97 tc_151bf368
  { 1, 447, 448, 6706, 6709 }, // 98 tc_9c52f549
  { 1, 446, 447, 6709, 6711 }, // 99 tc_55b33fda
  { 1, 446, 447, 6711, 6715 }, // 100 tc_6fc5dbea
  { 1, 452, 453, 6715, 6717 }, // 101 tc_3edca78f
  { 1, 446, 447, 6717, 6721 }, // 102 tc_a7a13fac
  { 1, 446, 447, 6721, 6723 }, // 103 tc_9783714b
  { 1, 446, 447, 6723, 6726 }, // 104 tc_f0e8e832
  { 1, 446, 447, 6726, 6728 }, // 105 tc_65279839
  { 1, 446, 447, 6728, 6732 }, // 106 tc_0a195f2c
  { 1, 446, 447, 6732, 6736 }, // 107 tc_01e1be3b
  { 1, 446, 447, 6736, 6739 }, // 108 tc_556f6577
  { 1, 446, 447, 6739, 6742 }, // 109 tc_02fe1c65
  { 1, 446, 447, 6742, 6746 }, // 110 tc_9e72dc89
  { 1, 446, 447, 6746, 6751 }, // 111 tc_9edb7c77
  { 1, 446, 447, 6751, 6754 }, // 112 tc_7f7f45f5
  { 1, 446, 447, 6754, 6757 }, // 113 tc_c20701f0
  { 1, 446, 447, 6757, 6761 }, // 114 tc_f7569068
  { 1, 452, 453, 6761, 6763 }, // 115 tc_fae9dfa5
  { 1, 452, 453, 6763, 6765 }, // 116 tc_6ae3426b
  { 1, 446, 447, 6765, 6767 }, // 117 tc_69bfb303
  { 1, 450, 451, 6767, 6768 }, // 118 tc_362b0be2
  { 1, 450, 451, 6768, 6770 }, // 119 tc_dc51281d
  { 1, 450, 451, 6770, 6771 }, // 120 tc_95f43c5e
  { 1, 447, 448, 6771, 6772 }, // 121 tc_decdde8a
  { 1, 447, 448, 6772, 6774 }, // 122 tc_eeda4109
  { 1, 447, 448, 6774, 6776 }, // 123 tc_711c805f
  { 1, 450, 451, 6776, 6778 }, // 124 tc_ed03645c
  { 1, 450, 451, 6778, 6780 }, // 125 tc_42ff66ba
  { 1, 452, 453, 6780, 6782 }, // 126 tc_57a55b54
  { 1, 450, 451, 6782, 6783 }, // 127 tc_f97707c1
  { 1, 452, 453, 6783, 6785 }, // 128 tc_1248597c
  { 1, 452, 453, 6785, 6787 }, // 129 tc_9406230a
  { 1, 450, 451, 6787, 6788 }, // 130 tc_d57d649c
  { 1, 452, 453, 6788, 6790 }, // 131 tc_4abdbdc6
  { 1, 452, 453, 6790, 6792 }, // 132 tc_6d861a95
  { 1, 450, 451, 0, 0 }, // 133 tc_b9bec29e
  { 1, 450, 451, 6792, 6793 }, // 134 tc_45f9d1be
  { 1, 450, 451, 0, 0 }, // 135 tc_33e7e673
  { 1, 448, 449, 6793, 6796 }, // 136 tc_24e109c7
  { 1, 447, 448, 6796, 6799 }, // 137 tc_9e27f2f9
  { 1, 448, 449, 6799, 6802 }, // 138 tc_f6e2aff9
  { 1, 447, 448, 6802, 6805 }, // 139 tc_24f426ab
  { 1, 448, 449, 6805, 6808 }, // 140 tc_975a4e54
  { 1, 450, 451, 6808, 6809 }, // 141 tc_e60def48
  { 1, 446, 447, 6809, 6812 }, // 142 tc_5502c366
  { 1, 448, 449, 6812, 6814 }, // 143 tc_7b9187d3
  { 1, 447, 448, 6814, 6816 }, // 144 tc_f999c66e
  { 1, 451, 452, 6816, 6821 }, // 145 tc_1c7522a8
  { 1, 451, 452, 6821, 6827 }, // 146 tc_76bb5435
  { 1, 451, 452, 6827, 6829 }, // 147 tc_8a6d0d94
  { 1, 448, 449, 6829, 6831 }, // 148 tc_2471c1c8
  { 1, 448, 449, 6831, 6833 }, // 149 tc_64b00d8a
  { 1, 451, 452, 6833, 6838 }, // 150 tc_5f2afaf7
  { 1, 451, 452, 6838, 6842 }, // 151 tc_ac65613f
  { 1, 451, 452, 6842, 6847 }, // 152 tc_a32e03e7
  { 1, 451, 452, 6847, 6850 }, // 153 tc_822c3c68
  { 1, 451, 452, 6850, 6854 }, // 154 tc_abfd9a6d
  { 1, 451, 452, 6854, 6858 }, // 155 tc_bf2ffc0f
  { 1, 448, 449, 6858, 6861 }, // 156 tc_ed3f8d2a
  { 1, 451, 452, 6861, 6864 }, // 157 tc_7c6d32e4
  { 1, 451, 452, 6864, 6869 }, // 158 tc_45791fb8
  { 1, 451, 452, 6869, 6874 }, // 159 tc_b7c4062a
  { 1, 451, 452, 6874, 6877 }, // 160 tc_5944960d
  { 1, 446, 447, 6877, 6881 }, // 161 tc_2c13e7f5
  { 1, 446, 447, 6881, 6885 }, // 162 tc_a154b476
  { 1, 446, 447, 6885, 6889 }, // 163 tc_a4e22bbd
  { 1, 446, 447, 6889, 6893 }, // 164 tc_503ce0f3
  { 1, 451, 452, 6893, 6895 }, // 165 tc_0655b949
  { 1, 448, 449, 6895, 6897 }, // 166 tc_6e20402a
  { 1, 448, 449, 6897, 6898 }, // 167 tc_db96aa6b
  { 1, 446, 447, 6898, 6900 }, // 168 tc_a7bdb22c
  { 1, 446, 447, 6900, 6903 }, // 169 tc_db596beb
  { 1, 446, 447, 6903, 6906 }, // 170 tc_a08b630b
  { 1, 446, 447, 6906, 6909 }, // 171 tc_1fcb8495
  { 1, 451, 452, 6909, 6914 }, // 172 tc_9edefe01
  { 1, 451, 452, 6914, 6919 }, // 173 tc_449acf79
  { 1, 448, 449, 6919, 6924 }, // 174 tc_ce59038e
  { 1, 448, 449, 6924, 6929 }, // 175 tc_f529831b
  { 1, 448, 449, 6929, 6934 }, // 176 tc_addc37a8
  { 1, 448, 449, 6934, 6937 }, // 177 tc_6f42bc60
  { 1, 448, 449, 6937, 6939 }, // 178 tc_7af3a37e
  { 1, 446, 447, 6939, 6941 }, // 179 tc_e3d699e3
  { 1, 451, 452, 6941, 6944 }, // 180 tc_ba9255a6
  { 1, 451, 452, 6944, 6949 }, // 181 tc_1fe4ab69
  { 1, 451, 452, 6949, 6952 }, // 182 tc_bb07f2c5
  { 1, 451, 452, 6952, 6957 }, // 183 tc_8e82e8ca
  { 1, 448, 449, 6957, 6960 }, // 184 tc_cfa0e29b
  { 1, 448, 449, 6960, 6965 }, // 185 tc_0a6c20ae
  { 1, 448, 449, 6965, 6968 }, // 186 tc_0fac1eb8
  { 1, 448, 449, 6968, 6973 }, // 187 tc_829d8a86
  { 1, 451, 452, 6973, 6977 }, // 188 tc_280f7fe1
  { 1, 451, 452, 6977, 6981 }, // 189 tc_887d1bb7
  { 1, 448, 449, 6981, 6985 }, // 190 tc_96ef76ef
  { 1, 448, 449, 6985, 6989 }, // 191 tc_55a9a350
  { 1, 446, 447, 6989, 6993 }, // 192 tc_f0cdeccf
  { 1, 446, 447, 6993, 6998 }, // 193 tc_a38c45dc
  { 1, 446, 447, 6998, 7000 }, // 194 tc_d3632d88
  { 1, 446, 447, 7000, 7004 }, // 195 tc_5e4cf0e8
  { 1, 446, 447, 7004, 7006 }, // 196 tc_ef921005
  { 1, 451, 452, 7006, 7009 }, // 197 tc_5b347363
  { 1, 451, 452, 7009, 7011 }, // 198 tc_3d14a17b
  { 1, 451, 452, 7011, 7012 }, // 199 tc_3fbf1042
  { 1, 451, 452, 7012, 7013 }, // 200 tc_63567288
  { 1, 451, 452, 7013, 7015 }, // 201 tc_59a7822c
  { 1, 451, 452, 0, 0 }, // 202 tc_937dd41c
  { 1, 448, 449, 0, 0 }, // 203 tc_a4ee89db
  { 1, 448, 449, 0, 0 }, // 204 tc_c818ff7f
  { 1, 448, 449, 7015, 7016 }, // 205 tc_1242dc2a
  { 1, 451, 452, 7016, 7018 }, // 206 tc_44d5a428
  { 1, 473, 475, 7018, 7021 }, // 207 tc_540c3da3
  { 1, 462, 464, 7021, 7025 }, // 208 tc_b091f1c6
  { 1, 475, 477, 7025, 7027 }, // 209 tc_5bf8afbb
  { 1, 477, 479, 7027, 7031 }, // 210 tc_2b4c548e
  { 1, 477, 479, 7031, 7036 }, // 211 tc_bb599486
  { 1, 479, 483, 7036, 7039 }, // 212 tc_a7e6707d
  { 1, 479, 483, 7039, 7043 }, // 213 tc_3c56e5ce
  { 1, 457, 460, 7043, 7047 }, // 214 tc_abe8c3b2
  { 1, 457, 460, 7047, 7052 }, // 215 tc_453fe68d
  { 1, 457, 460, 7052, 7056 }, // 216 tc_1ba8a0cd
  { 1, 483, 485, 7056, 7059 }, // 217 tc_52447ecc
  { 1, 483, 485, 7059, 7063 }, // 218 tc_3904b926
  { 1, 483, 485, 7063, 7068 }, // 219 tc_b9db8205
  { 1, 483, 485, 7068, 7072 }, // 220 tc_663c80a7
  { 1, 485, 489, 7072, 7075 }, // 221 tc_f21e8abb
  { 1, 485, 489, 7075, 7079 }, // 222 tc_131f1c81
  { 1, 485, 489, 7079, 7084 }, // 223 tc_c7039829
  { 1, 485, 489, 7084, 7088 }, // 224 tc_e2d2e9e5
  { 1, 489, 491, 7088, 7091 }, // 225 tc_ab23f776
  { 1, 489, 491, 7091, 7095 }, // 226 tc_7177e272
  { 1, 489, 491, 7095, 7100 }, // 227 tc_e99d4c2e
  { 1, 489, 491, 7100, 7104 }, // 228 tc_6942b6e0
  { 1, 464, 467, 7104, 7108 }, // 229 tc_a02a10a8
  { 1, 464, 467, 7108, 7113 }, // 230 tc_54a0dc47
  { 1, 464, 467, 7113, 7117 }, // 231 tc_447d9895
  { 1, 464, 467, 7117, 7122 }, // 232 tc_191381c1
  { 1, 464, 467, 7122, 7126 }, // 233 tc_3e2aaafc
  { 1, 489, 491, 7126, 7128 }, // 234 tc_3ce09744
  { 1, 489, 491, 7128, 7131 }, // 235 tc_20a4bbec
  { 1, 462, 464, 7131, 7133 }, // 236 tc_5cdf8c84
  { 1, 491, 493, 7133, 7135 }, // 237 tc_2a698a03
  { 1, 462, 464, 7135, 7138 }, // 238 tc_c127de3a
  { 1, 493, 495, 7138, 7141 }, // 239 tc_05ca8cfd
  { 1, 477, 479, 7141, 7144 }, // 240 tc_d8287c14
  { 1, 453, 455, 7144, 7148 }, // 241 tc_257f6f7c
  { 1, 453, 455, 7148, 7153 }, // 242 tc_7e6a3e89
  { 1, 453, 455, 7153, 7157 }, // 243 tc_e35c1e93
  { 1, 477, 479, 7157, 7161 }, // 244 tc_08a4f1b6
  { 1, 453, 455, 7161, 7165 }, // 245 tc_57a4709c
  { 1, 475, 477, 7165, 7169 }, // 246 tc_56e64202
  { 1, 462, 464, 7169, 7172 }, // 247 tc_ac4046bc
  { 1, 462, 464, 7172, 7176 }, // 248 tc_2e8f5f6e
  { 1, 493, 495, 7176, 7179 }, // 249 tc_7417e785
  { 1, 493, 495, 7179, 7183 }, // 250 tc_309dbb4f
  { 1, 495, 497, 7183, 7187 }, // 251 tc_df80eeb0
  { 1, 493, 495, 7187, 7191 }, // 252 tc_16ff9ef8
  { 1, 447, 448, 7191, 7193 }, // 253 tc_e2fdd6e6
  { 1, 493, 495, 7193, 7195 }, // 254 tc_51d0ecc3
  { 1, 447, 448, 7195, 7198 }, // 255 tc_531b383c
  { 1, 495, 497, 7198, 7200 }, // 256 tc_04da405a
  { 1, 462, 464, 7200, 7202 }, // 257 tc_3c8c15d0
  { 1, 477, 479, 7202, 7204 }, // 258 tc_0afc8be9
  { 1, 495, 497, 7204, 7209 }, // 259 tc_561aaa58
  { 1, 475, 477, 7209, 7211 }, // 260 tc_946013d8
  { 1, 475, 477, 7211, 7214 }, // 261 tc_46d6c3e0
  { 1, 495, 497, 7214, 7218 }, // 262 tc_87adc037
  { 1, 462, 464, 7218, 7222 }, // 263 tc_a19b9305
  { 1, 462, 464, 7222, 7225 }, // 264 tc_649072c2
  { 1, 477, 479, 7225, 7228 }, // 265 tc_0b04c6c7
  { 1, 477, 479, 7228, 7232 }, // 266 tc_660769f1
  { 1, 477, 479, 7232, 7235 }, // 267 tc_dcca380f
  { 1, 477, 479, 7235, 7239 }, // 268 tc_72e2b393
  { 1, 477, 479, 7239, 7242 }, // 269 tc_73efe966
  { 1, 462, 464, 7242, 7245 }, // 270 tc_cda936da
  { 1, 457, 460, 7245, 7248 }, // 271 tc_a28f32b5
  { 1, 457, 460, 7248, 7252 }, // 272 tc_7d68d5c2
  { 1, 497, 500, 7252, 7255 }, // 273 tc_7095ecba
  { 1, 497, 500, 7255, 7259 }, // 274 tc_a69eeee1
  { 1, 500, 502, 0, 0 }, // 275 tc_1381a97c
  { 1, 500, 502, 7259, 7260 }, // 276 tc_e3f68a46
  { 1, 502, 504, 7260, 7263 }, // 277 tc_f1de44ef
  { 1, 495, 497, 7263, 7268 }, // 278 tc_9d1dc972
  { 1, 502, 504, 7268, 7272 }, // 279 tc_90bcc1db
  { 1, 504, 507, 7272, 7275 }, // 280 tc_cd94bfe0
  { 1, 504, 507, 7275, 7279 }, // 281 tc_15fdf750
  { 1, 477, 479, 7279, 7283 }, // 282 tc_1ad8a370
  { 1, 477, 479, 7283, 7288 }, // 283 tc_e675c45a
  { 1, 477, 479, 7288, 7292 }, // 284 tc_37820f4c
  { 1, 507, 509, 7292, 7295 }, // 285 tc_61bf7c03
  { 1, 507, 509, 7295, 7299 }, // 286 tc_933f2b39
  { 1, 507, 509, 7299, 7303 }, // 287 tc_26a377fe
  { 1, 507, 509, 7303, 7308 }, // 288 tc_2d4051cd
  { 1, 475, 477, 7308, 7311 }, // 289 tc_6e7fa133
  { 1, 453, 455, 7311, 7314 }, // 290 tc_8772086c
  { 1, 455, 457, 7314, 7316 }, // 291 tc_b4416217
  { 1, 464, 467, 7316, 7320 }, // 292 tc_9f363d21
  { 1, 464, 467, 7320, 7325 }, // 293 tc_8e420e4d
  { 1, 509, 512, 7325, 7329 }, // 294 tc_7273323b
  { 1, 509, 512, 7329, 7334 }, // 295 tc_58d21193
  { 1, 455, 457, 7334, 7338 }, // 296 tc_71646d06
  { 1, 495, 497, 7338, 7341 }, // 297 tc_2c745bb8
  { 1, 500, 502, 7341, 7342 }, // 298 tc_b28e51aa
  { 1, 500, 502, 7342, 7344 }, // 299 tc_767c4e9d
  { 1, 512, 514, 7344, 7346 }, // 300 tc_e699ae41
  { 1, 512, 514, 7346, 7349 }, // 301 tc_a0dbea28
  { 1, 512, 514, 7349, 7352 }, // 302 tc_dd5b0695
  { 1, 512, 514, 7352, 7356 }, // 303 tc_3ad719fb
  { 1, 448, 449, 0, 0 }, // 304 tc_77f94a5e
  { 1, 452, 453, 0, 0 }, // 305 tc_55255f2b
  { 1, 452, 453, 7356, 7357 }, // 306 tc_0a43be35
  { 1, 448, 449, 7357, 7358 }, // 307 tc_b1ae5f67
  { 1, 448, 449, 7358, 7359 }, // 308 tc_d234b61a
  { 1, 448, 449, 7359, 7361 }, // 309 tc_2237d952
  { 1, 448, 449, 0, 0 }, // 310 tc_78f87ed3
  { 1, 448, 449, 7361, 7363 }, // 311 tc_a724463d
  { 1, 448, 449, 7363, 7365 }, // 312 tc_6fb52018
  { 1, 452, 453, 7365, 7367 }, // 313 tc_46c18ecf
  { 1, 450, 451, 7367, 7369 }, // 314 tc_9b20a062
  { 1, 450, 451, 7369, 7371 }, // 315 tc_5a222e89
  { 1, 450, 451, 7371, 7372 }, // 316 tc_0ba0d5da
  { 1, 450, 451, 7372, 7373 }, // 317 tc_7d6a2568
  { 1, 450, 451, 7373, 7375 }, // 318 tc_759e57be
  { 1, 450, 451, 7375, 7377 }, // 319 tc_139ef484
  { 1, 450, 451, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 452, 453, 0, 0 }, // 321 tc_7f58404a
  { 1, 448, 449, 0, 0 }, // 322 tc_b3d46584
  { 1, 452, 453, 7377, 7379 }, // 323 tc_d71ea8fa
  { 1, 452, 453, 7379, 7381 }, // 324 tc_6aa823ab
  { 1, 452, 453, 7381, 7383 }, // 325 tc_b2196a3f
  { 1, 452, 453, 7383, 7384 }, // 326 tc_2c3e17fc
  { 1, 452, 453, 7384, 7387 }, // 327 tc_27106296
  { 1, 448, 449, 7387, 7389 }, // 328 tc_a3070909
  { 1, 448, 449, 7389, 7391 }, // 329 tc_512b1653
  { 1, 452, 453, 7391, 7392 }, // 330 tc_d7718fbe
  { 1, 452, 453, 7392, 7395 }, // 331 tc_bb78483e
  { 1, 452, 453, 7395, 7396 }, // 332 tc_54f0cee2
  { 1, 452, 453, 7396, 7398 }, // 333 tc_28e55c6f
  { 1, 448, 449, 7398, 7399 }, // 334 tc_4bf903b0
  { 1, 448, 449, 7399, 7400 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV69[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 514, 515, 7400, 7403 }, // 1 tc_01d44cb2
  { 1, 515, 516, 7403, 7406 }, // 2 PSEUDO
  { 1, 515, 516, 7406, 7408 }, // 3 tc_c57d9f39
  { 1, 515, 516, 7408, 7412 }, // 4 tc_1c2c7a4a
  { 1, 515, 516, 7412, 7416 }, // 5 tc_442395f3
  { 1, 515, 516, 7416, 7419 }, // 6 tc_713b66bf
  { 1, 515, 516, 7419, 7422 }, // 7 tc_86173609
  { 1, 514, 515, 7422, 7425 }, // 8 tc_5da50c4b
  { 1, 514, 515, 7425, 7428 }, // 9 tc_4a55d03c
  { 1, 515, 516, 7428, 7431 }, // 10 tc_d33e5eee
  { 1, 514, 515, 7431, 7434 }, // 11 tc_651cbe02
  { 1, 516, 517, 7434, 7437 }, // 12 DUPLEX
  { 1, 517, 518, 7437, 7438 }, // 13 tc_ENDLOOP
  { 1, 515, 516, 0, 0 }, // 14 tc_23708a21
  { 1, 515, 516, 7438, 7440 }, // 15 tc_56a124a7
  { 1, 518, 519, 7440, 7442 }, // 16 tc_2f573607
  { 1, 518, 519, 7442, 7445 }, // 17 tc_53c851ab
  { 1, 519, 520, 7445, 7449 }, // 18 tc_fedb7e19
  { 1, 519, 520, 7449, 7452 }, // 19 tc_4222e6bf
  { 1, 519, 520, 7452, 7456 }, // 20 tc_075c8dd8
  { 1, 516, 517, 7456, 7459 }, // 21 tc_9bcfb2ee
  { 1, 516, 517, 7459, 7462 }, // 22 tc_158aa3f7
  { 1, 516, 517, 7462, 7465 }, // 23 tc_df5d53f9
  { 1, 516, 517, 7465, 7468 }, // 24 tc_14ab4f41
  { 1, 516, 517, 7468, 7469 }, // 25 tc_f38f92e1
  { 1, 516, 517, 7469, 7470 }, // 26 tc_1981450d
  { 1, 519, 520, 7470, 7472 }, // 27 tc_e9170fb7
  { 1, 516, 517, 7472, 7474 }, // 28 tc_40d64c94
  { 1, 519, 520, 7474, 7476 }, // 29 LD_tc_ld_SLOT01
  { 1, 514, 515, 7476, 7479 }, // 30 tc_38382228
  { 1, 514, 515, 7479, 7482 }, // 31 tc_c21d7447
  { 1, 514, 515, 7482, 7486 }, // 32 tc_7f8ae742
  { 1, 520, 521, 7486, 7489 }, // 33 tc_5a4b5e58
  { 1, 520, 521, 7489, 7493 }, // 34 tc_197dce51
  { 1, 514, 515, 7493, 7494 }, // 35 tc_44fffc58
  { 1, 519, 520, 7494, 7499 }, // 36 tc_5ceb2f9e
  { 1, 521, 523, 7499, 7502 }, // 37 tc_56c4f9fe
  { 1, 520, 521, 7502, 7504 }, // 38 tc_7476d766
  { 1, 519, 520, 7504, 7509 }, // 39 tc_b4dc7630
  { 1, 519, 520, 7509, 7513 }, // 40 tc_a2b365d2
  { 1, 518, 519, 7513, 7514 }, // 41 tc_60e324ff
  { 1, 523, 525, 7514, 7517 }, // 42 tc_db5555f3
  { 1, 525, 528, 7517, 7520 }, // 43 tc_c0749f3c
  { 1, 528, 530, 7520, 7523 }, // 44 PSEUDOM
  { 1, 521, 523, 7523, 7526 }, // 45 tc_3aacf4a8
  { 1, 530, 532, 7526, 7528 }, // 46 tc_c4edf264
  { 1, 532, 535, 7528, 7531 }, // 47 tc_c5dba46e
  { 1, 523, 525, 7531, 7535 }, // 48 tc_af25efd9
  { 1, 514, 515, 7535, 7538 }, // 49 tc_0dfac0a7
  { 1, 519, 520, 7538, 7542 }, // 50 tc_8035e91f
  { 1, 516, 517, 7542, 7546 }, // 51 tc_011e0e9d
  { 1, 519, 520, 7546, 7549 }, // 52 tc_ae5babd7
  { 1, 516, 517, 7549, 7552 }, // 53 tc_5deb5e47
  { 1, 514, 515, 7552, 7557 }, // 54 tc_bb831a7c
  { 1, 516, 517, 7557, 7561 }, // 55 tc_92240447
  { 1, 519, 520, 7561, 7564 }, // 56 tc_7c31e19a
  { 1, 519, 520, 7564, 7568 }, // 57 tc_d03278fd
  { 1, 519, 520, 7568, 7572 }, // 58 tc_65cbd974
  { 1, 516, 517, 7572, 7575 }, // 59 tc_934753bb
  { 1, 519, 520, 7575, 7578 }, // 60 ST_tc_st_SLOT01
  { 1, 535, 537, 7578, 7582 }, // 61 CVI_VA
  { 1, 530, 532, 7582, 7586 }, // 62 tc_f175e046
  { 1, 530, 532, 7586, 7591 }, // 63 tc_4942646a
  { 1, 521, 523, 7591, 7593 }, // 64 tc_0ec46cf9
  { 1, 523, 525, 7593, 7594 }, // 65 tc_718b5c53
  { 1, 537, 541, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 520, 521, 7594, 7596 }, // 67 tc_7dc63b5c
  { 1, 516, 517, 7596, 7597 }, // 68 tc_d45ba9cd
  { 1, 515, 516, 7597, 7600 }, // 69 tc_388f9897
  { 1, 515, 516, 7600, 7602 }, // 70 tc_9124c04f
  { 1, 515, 516, 7602, 7605 }, // 71 tc_4ac61d92
  { 1, 519, 520, 7605, 7607 }, // 72 tc_aee6250c
  { 1, 519, 520, 7607, 7610 }, // 73 tc_eed07714
  { 1, 519, 520, 7610, 7613 }, // 74 tc_74a42bda
  { 1, 519, 520, 7613, 7616 }, // 75 tc_a9edeffa
  { 1, 519, 520, 7616, 7619 }, // 76 tc_838c4d7a
  { 1, 514, 515, 7619, 7621 }, // 77 tc_d61dfdc3
  { 1, 514, 515, 7621, 7624 }, // 78 tc_8a825db2
  { 1, 514, 515, 7624, 7627 }, // 79 tc_f34c1c21
  { 1, 515, 516, 7627, 7630 }, // 80 tc_95a33176
  { 1, 514, 515, 7630, 7632 }, // 81 tc_9f6cd987
  { 1, 515, 516, 0, 0 }, // 82 tc_b837298f
  { 1, 515, 516, 7632, 7635 }, // 83 tc_8b5bd4f5
  { 1, 515, 516, 7635, 7638 }, // 84 tc_84a7500d
  { 1, 520, 521, 7638, 7640 }, // 85 tc_49fdfd4b
  { 1, 514, 515, 7640, 7643 }, // 86 tc_f098b237
  { 1, 514, 515, 7643, 7646 }, // 87 tc_20131976
  { 1, 514, 515, 7646, 7651 }, // 88 tc_1d41f8b7
  { 1, 514, 515, 7651, 7654 }, // 89 tc_a1297125
  { 1, 515, 516, 7654, 7655 }, // 90 tc_112d30d6
  { 1, 514, 515, 7655, 7658 }, // 91 tc_d68dca5c
  { 1, 514, 515, 7658, 7662 }, // 92 tc_788b1d09
  { 1, 514, 515, 7662, 7667 }, // 93 tc_38e0bae9
  { 1, 514, 515, 7667, 7670 }, // 94 tc_407e96f9
  { 1, 514, 515, 7670, 7674 }, // 95 tc_7401744f
  { 1, 514, 515, 7674, 7677 }, // 96 tc_9b3c0462
  { 1, 514, 515, 7677, 7679 }, // 97 tc_151bf368
  { 1, 515, 516, 7679, 7682 }, // 98 tc_9c52f549
  { 1, 514, 515, 7682, 7684 }, // 99 tc_55b33fda
  { 1, 514, 515, 7684, 7688 }, // 100 tc_6fc5dbea
  { 1, 520, 521, 7688, 7690 }, // 101 tc_3edca78f
  { 1, 514, 515, 7690, 7694 }, // 102 tc_a7a13fac
  { 1, 514, 515, 7694, 7696 }, // 103 tc_9783714b
  { 1, 514, 515, 7696, 7699 }, // 104 tc_f0e8e832
  { 1, 514, 515, 7699, 7701 }, // 105 tc_65279839
  { 1, 514, 515, 7701, 7705 }, // 106 tc_0a195f2c
  { 1, 514, 515, 7705, 7709 }, // 107 tc_01e1be3b
  { 1, 514, 515, 7709, 7712 }, // 108 tc_556f6577
  { 1, 514, 515, 7712, 7715 }, // 109 tc_02fe1c65
  { 1, 514, 515, 7715, 7719 }, // 110 tc_9e72dc89
  { 1, 514, 515, 7719, 7724 }, // 111 tc_9edb7c77
  { 1, 514, 515, 7724, 7727 }, // 112 tc_7f7f45f5
  { 1, 514, 515, 7727, 7730 }, // 113 tc_c20701f0
  { 1, 514, 515, 7730, 7734 }, // 114 tc_f7569068
  { 1, 520, 521, 7734, 7736 }, // 115 tc_fae9dfa5
  { 1, 520, 521, 7736, 7738 }, // 116 tc_6ae3426b
  { 1, 514, 515, 7738, 7740 }, // 117 tc_69bfb303
  { 1, 518, 519, 7740, 7741 }, // 118 tc_362b0be2
  { 1, 518, 519, 7741, 7743 }, // 119 tc_dc51281d
  { 1, 518, 519, 7743, 7744 }, // 120 tc_95f43c5e
  { 1, 515, 516, 7744, 7745 }, // 121 tc_decdde8a
  { 1, 515, 516, 7745, 7747 }, // 122 tc_eeda4109
  { 1, 515, 516, 7747, 7749 }, // 123 tc_711c805f
  { 1, 518, 519, 7749, 7751 }, // 124 tc_ed03645c
  { 1, 518, 519, 7751, 7753 }, // 125 tc_42ff66ba
  { 1, 520, 521, 7753, 7755 }, // 126 tc_57a55b54
  { 1, 518, 519, 7755, 7756 }, // 127 tc_f97707c1
  { 1, 520, 521, 7756, 7758 }, // 128 tc_1248597c
  { 1, 520, 521, 7758, 7760 }, // 129 tc_9406230a
  { 1, 518, 519, 7760, 7761 }, // 130 tc_d57d649c
  { 1, 520, 521, 7761, 7763 }, // 131 tc_4abdbdc6
  { 1, 520, 521, 7763, 7765 }, // 132 tc_6d861a95
  { 1, 518, 519, 0, 0 }, // 133 tc_b9bec29e
  { 1, 518, 519, 7765, 7766 }, // 134 tc_45f9d1be
  { 1, 518, 519, 0, 0 }, // 135 tc_33e7e673
  { 1, 516, 517, 7766, 7769 }, // 136 tc_24e109c7
  { 1, 515, 516, 7769, 7772 }, // 137 tc_9e27f2f9
  { 1, 516, 517, 7772, 7775 }, // 138 tc_f6e2aff9
  { 1, 515, 516, 7775, 7778 }, // 139 tc_24f426ab
  { 1, 516, 517, 7778, 7781 }, // 140 tc_975a4e54
  { 1, 518, 519, 7781, 7782 }, // 141 tc_e60def48
  { 1, 514, 515, 7782, 7785 }, // 142 tc_5502c366
  { 1, 516, 517, 7785, 7787 }, // 143 tc_7b9187d3
  { 1, 515, 516, 7787, 7789 }, // 144 tc_f999c66e
  { 1, 519, 520, 7789, 7794 }, // 145 tc_1c7522a8
  { 1, 519, 520, 7794, 7800 }, // 146 tc_76bb5435
  { 1, 519, 520, 7800, 7802 }, // 147 tc_8a6d0d94
  { 1, 516, 517, 7802, 7804 }, // 148 tc_2471c1c8
  { 1, 516, 517, 7804, 7806 }, // 149 tc_64b00d8a
  { 1, 519, 520, 7806, 7811 }, // 150 tc_5f2afaf7
  { 1, 519, 520, 7811, 7815 }, // 151 tc_ac65613f
  { 1, 519, 520, 7815, 7820 }, // 152 tc_a32e03e7
  { 1, 519, 520, 7820, 7823 }, // 153 tc_822c3c68
  { 1, 519, 520, 7823, 7827 }, // 154 tc_abfd9a6d
  { 1, 519, 520, 7827, 7831 }, // 155 tc_bf2ffc0f
  { 1, 516, 517, 7831, 7834 }, // 156 tc_ed3f8d2a
  { 1, 519, 520, 7834, 7837 }, // 157 tc_7c6d32e4
  { 1, 519, 520, 7837, 7842 }, // 158 tc_45791fb8
  { 1, 519, 520, 7842, 7847 }, // 159 tc_b7c4062a
  { 1, 519, 520, 7847, 7850 }, // 160 tc_5944960d
  { 1, 514, 515, 7850, 7854 }, // 161 tc_2c13e7f5
  { 1, 514, 515, 7854, 7858 }, // 162 tc_a154b476
  { 1, 514, 515, 7858, 7862 }, // 163 tc_a4e22bbd
  { 1, 514, 515, 7862, 7866 }, // 164 tc_503ce0f3
  { 1, 519, 520, 7866, 7868 }, // 165 tc_0655b949
  { 1, 516, 517, 7868, 7870 }, // 166 tc_6e20402a
  { 1, 516, 517, 7870, 7871 }, // 167 tc_db96aa6b
  { 1, 514, 515, 7871, 7873 }, // 168 tc_a7bdb22c
  { 1, 514, 515, 7873, 7876 }, // 169 tc_db596beb
  { 1, 514, 515, 7876, 7879 }, // 170 tc_a08b630b
  { 1, 514, 515, 7879, 7882 }, // 171 tc_1fcb8495
  { 1, 519, 520, 7882, 7887 }, // 172 tc_9edefe01
  { 1, 519, 520, 7887, 7892 }, // 173 tc_449acf79
  { 1, 516, 517, 7892, 7897 }, // 174 tc_ce59038e
  { 1, 516, 517, 7897, 7902 }, // 175 tc_f529831b
  { 1, 516, 517, 7902, 7907 }, // 176 tc_addc37a8
  { 1, 516, 517, 7907, 7910 }, // 177 tc_6f42bc60
  { 1, 516, 517, 7910, 7912 }, // 178 tc_7af3a37e
  { 1, 514, 515, 7912, 7914 }, // 179 tc_e3d699e3
  { 1, 519, 520, 7914, 7917 }, // 180 tc_ba9255a6
  { 1, 519, 520, 7917, 7922 }, // 181 tc_1fe4ab69
  { 1, 519, 520, 7922, 7925 }, // 182 tc_bb07f2c5
  { 1, 519, 520, 7925, 7930 }, // 183 tc_8e82e8ca
  { 1, 516, 517, 7930, 7933 }, // 184 tc_cfa0e29b
  { 1, 516, 517, 7933, 7938 }, // 185 tc_0a6c20ae
  { 1, 516, 517, 7938, 7941 }, // 186 tc_0fac1eb8
  { 1, 516, 517, 7941, 7946 }, // 187 tc_829d8a86
  { 1, 519, 520, 7946, 7950 }, // 188 tc_280f7fe1
  { 1, 519, 520, 7950, 7954 }, // 189 tc_887d1bb7
  { 1, 516, 517, 7954, 7958 }, // 190 tc_96ef76ef
  { 1, 516, 517, 7958, 7962 }, // 191 tc_55a9a350
  { 1, 514, 515, 7962, 7966 }, // 192 tc_f0cdeccf
  { 1, 514, 515, 7966, 7971 }, // 193 tc_a38c45dc
  { 1, 514, 515, 7971, 7973 }, // 194 tc_d3632d88
  { 1, 514, 515, 7973, 7977 }, // 195 tc_5e4cf0e8
  { 1, 514, 515, 7977, 7979 }, // 196 tc_ef921005
  { 1, 519, 520, 7979, 7982 }, // 197 tc_5b347363
  { 1, 519, 520, 7982, 7984 }, // 198 tc_3d14a17b
  { 1, 519, 520, 7984, 7985 }, // 199 tc_3fbf1042
  { 1, 519, 520, 7985, 7986 }, // 200 tc_63567288
  { 1, 519, 520, 7986, 7988 }, // 201 tc_59a7822c
  { 1, 519, 520, 0, 0 }, // 202 tc_937dd41c
  { 1, 516, 517, 0, 0 }, // 203 tc_a4ee89db
  { 1, 516, 517, 0, 0 }, // 204 tc_c818ff7f
  { 1, 516, 517, 7988, 7989 }, // 205 tc_1242dc2a
  { 1, 519, 520, 7989, 7991 }, // 206 tc_44d5a428
  { 1, 541, 543, 7991, 7994 }, // 207 tc_540c3da3
  { 1, 530, 532, 7994, 7998 }, // 208 tc_b091f1c6
  { 1, 543, 545, 7998, 8000 }, // 209 tc_5bf8afbb
  { 1, 545, 547, 8000, 8004 }, // 210 tc_2b4c548e
  { 1, 545, 547, 8004, 8009 }, // 211 tc_bb599486
  { 1, 547, 551, 8009, 8012 }, // 212 tc_a7e6707d
  { 1, 547, 551, 8012, 8016 }, // 213 tc_3c56e5ce
  { 1, 525, 528, 8016, 8020 }, // 214 tc_abe8c3b2
  { 1, 525, 528, 8020, 8025 }, // 215 tc_453fe68d
  { 1, 525, 528, 8025, 8029 }, // 216 tc_1ba8a0cd
  { 1, 551, 553, 8029, 8032 }, // 217 tc_52447ecc
  { 1, 551, 553, 8032, 8036 }, // 218 tc_3904b926
  { 1, 551, 553, 8036, 8041 }, // 219 tc_b9db8205
  { 1, 551, 553, 8041, 8045 }, // 220 tc_663c80a7
  { 1, 553, 557, 8045, 8048 }, // 221 tc_f21e8abb
  { 1, 553, 557, 8048, 8052 }, // 222 tc_131f1c81
  { 1, 553, 557, 8052, 8057 }, // 223 tc_c7039829
  { 1, 553, 557, 8057, 8061 }, // 224 tc_e2d2e9e5
  { 1, 557, 559, 8061, 8064 }, // 225 tc_ab23f776
  { 1, 557, 559, 8064, 8068 }, // 226 tc_7177e272
  { 1, 557, 559, 8068, 8073 }, // 227 tc_e99d4c2e
  { 1, 557, 559, 8073, 8077 }, // 228 tc_6942b6e0
  { 1, 532, 535, 8077, 8081 }, // 229 tc_a02a10a8
  { 1, 532, 535, 8081, 8086 }, // 230 tc_54a0dc47
  { 1, 532, 535, 8086, 8090 }, // 231 tc_447d9895
  { 1, 532, 535, 8090, 8095 }, // 232 tc_191381c1
  { 1, 532, 535, 8095, 8099 }, // 233 tc_3e2aaafc
  { 1, 557, 559, 8099, 8101 }, // 234 tc_3ce09744
  { 1, 557, 559, 8101, 8104 }, // 235 tc_20a4bbec
  { 1, 530, 532, 8104, 8106 }, // 236 tc_5cdf8c84
  { 1, 559, 561, 8106, 8108 }, // 237 tc_2a698a03
  { 1, 530, 532, 8108, 8111 }, // 238 tc_c127de3a
  { 1, 561, 563, 8111, 8114 }, // 239 tc_05ca8cfd
  { 1, 545, 547, 8114, 8117 }, // 240 tc_d8287c14
  { 1, 521, 523, 8117, 8121 }, // 241 tc_257f6f7c
  { 1, 521, 523, 8121, 8126 }, // 242 tc_7e6a3e89
  { 1, 521, 523, 8126, 8130 }, // 243 tc_e35c1e93
  { 1, 545, 547, 8130, 8134 }, // 244 tc_08a4f1b6
  { 1, 521, 523, 8134, 8138 }, // 245 tc_57a4709c
  { 1, 543, 545, 8138, 8142 }, // 246 tc_56e64202
  { 1, 530, 532, 8142, 8145 }, // 247 tc_ac4046bc
  { 1, 530, 532, 8145, 8149 }, // 248 tc_2e8f5f6e
  { 1, 561, 563, 8149, 8152 }, // 249 tc_7417e785
  { 1, 561, 563, 8152, 8156 }, // 250 tc_309dbb4f
  { 1, 563, 565, 8156, 8160 }, // 251 tc_df80eeb0
  { 1, 561, 563, 8160, 8164 }, // 252 tc_16ff9ef8
  { 1, 515, 516, 8164, 8166 }, // 253 tc_e2fdd6e6
  { 1, 561, 563, 8166, 8168 }, // 254 tc_51d0ecc3
  { 1, 515, 516, 8168, 8171 }, // 255 tc_531b383c
  { 1, 563, 565, 8171, 8173 }, // 256 tc_04da405a
  { 1, 530, 532, 8173, 8175 }, // 257 tc_3c8c15d0
  { 1, 545, 547, 8175, 8177 }, // 258 tc_0afc8be9
  { 1, 563, 565, 8177, 8182 }, // 259 tc_561aaa58
  { 1, 543, 545, 8182, 8184 }, // 260 tc_946013d8
  { 1, 543, 545, 8184, 8187 }, // 261 tc_46d6c3e0
  { 1, 563, 565, 8187, 8191 }, // 262 tc_87adc037
  { 1, 530, 532, 8191, 8195 }, // 263 tc_a19b9305
  { 1, 530, 532, 8195, 8198 }, // 264 tc_649072c2
  { 1, 545, 547, 8198, 8201 }, // 265 tc_0b04c6c7
  { 1, 545, 547, 8201, 8205 }, // 266 tc_660769f1
  { 1, 530, 532, 8205, 8208 }, // 267 tc_dcca380f
  { 1, 530, 532, 8208, 8212 }, // 268 tc_72e2b393
  { 1, 530, 532, 8212, 8215 }, // 269 tc_73efe966
  { 1, 530, 532, 8215, 8218 }, // 270 tc_cda936da
  { 1, 525, 528, 8218, 8221 }, // 271 tc_a28f32b5
  { 1, 525, 528, 8221, 8225 }, // 272 tc_7d68d5c2
  { 1, 565, 568, 8225, 8228 }, // 273 tc_7095ecba
  { 1, 565, 568, 8228, 8232 }, // 274 tc_a69eeee1
  { 1, 568, 570, 0, 0 }, // 275 tc_1381a97c
  { 1, 568, 570, 8232, 8233 }, // 276 tc_e3f68a46
  { 1, 570, 572, 8233, 8236 }, // 277 tc_f1de44ef
  { 1, 563, 565, 8236, 8241 }, // 278 tc_9d1dc972
  { 1, 570, 572, 8241, 8245 }, // 279 tc_90bcc1db
  { 1, 572, 575, 8245, 8248 }, // 280 tc_cd94bfe0
  { 1, 572, 575, 8248, 8252 }, // 281 tc_15fdf750
  { 1, 545, 547, 8252, 8256 }, // 282 tc_1ad8a370
  { 1, 545, 547, 8256, 8261 }, // 283 tc_e675c45a
  { 1, 530, 532, 8261, 8265 }, // 284 tc_37820f4c
  { 1, 575, 577, 8265, 8268 }, // 285 tc_61bf7c03
  { 1, 575, 577, 8268, 8272 }, // 286 tc_933f2b39
  { 1, 575, 577, 8272, 8276 }, // 287 tc_26a377fe
  { 1, 575, 577, 8276, 8281 }, // 288 tc_2d4051cd
  { 1, 543, 545, 8281, 8284 }, // 289 tc_6e7fa133
  { 1, 521, 523, 8284, 8287 }, // 290 tc_8772086c
  { 1, 523, 525, 8287, 8289 }, // 291 tc_b4416217
  { 1, 532, 535, 8289, 8293 }, // 292 tc_9f363d21
  { 1, 532, 535, 8293, 8298 }, // 293 tc_8e420e4d
  { 1, 577, 580, 8298, 8302 }, // 294 tc_7273323b
  { 1, 577, 580, 8302, 8307 }, // 295 tc_58d21193
  { 1, 523, 525, 8307, 8311 }, // 296 tc_71646d06
  { 1, 563, 565, 8311, 8314 }, // 297 tc_2c745bb8
  { 1, 568, 570, 8314, 8315 }, // 298 tc_b28e51aa
  { 1, 568, 570, 8315, 8317 }, // 299 tc_767c4e9d
  { 1, 580, 582, 8317, 8319 }, // 300 tc_e699ae41
  { 1, 580, 582, 8319, 8322 }, // 301 tc_a0dbea28
  { 1, 580, 582, 8322, 8325 }, // 302 tc_dd5b0695
  { 1, 580, 582, 8325, 8329 }, // 303 tc_3ad719fb
  { 1, 516, 517, 0, 0 }, // 304 tc_77f94a5e
  { 1, 520, 521, 0, 0 }, // 305 tc_55255f2b
  { 1, 520, 521, 8329, 8330 }, // 306 tc_0a43be35
  { 1, 516, 517, 8330, 8331 }, // 307 tc_b1ae5f67
  { 1, 516, 517, 8331, 8332 }, // 308 tc_d234b61a
  { 1, 516, 517, 8332, 8334 }, // 309 tc_2237d952
  { 1, 516, 517, 0, 0 }, // 310 tc_78f87ed3
  { 1, 516, 517, 8334, 8336 }, // 311 tc_a724463d
  { 1, 516, 517, 8336, 8338 }, // 312 tc_6fb52018
  { 1, 520, 521, 8338, 8340 }, // 313 tc_46c18ecf
  { 1, 518, 519, 8340, 8342 }, // 314 tc_9b20a062
  { 1, 518, 519, 8342, 8344 }, // 315 tc_5a222e89
  { 1, 518, 519, 8344, 8345 }, // 316 tc_0ba0d5da
  { 1, 518, 519, 8345, 8346 }, // 317 tc_7d6a2568
  { 1, 518, 519, 8346, 8348 }, // 318 tc_759e57be
  { 1, 518, 519, 8348, 8350 }, // 319 tc_139ef484
  { 1, 518, 519, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 520, 521, 0, 0 }, // 321 tc_7f58404a
  { 1, 516, 517, 0, 0 }, // 322 tc_b3d46584
  { 1, 520, 521, 8350, 8352 }, // 323 tc_d71ea8fa
  { 1, 520, 521, 8352, 8354 }, // 324 tc_6aa823ab
  { 1, 520, 521, 8354, 8356 }, // 325 tc_b2196a3f
  { 1, 520, 521, 8356, 8357 }, // 326 tc_2c3e17fc
  { 1, 520, 521, 8357, 8360 }, // 327 tc_27106296
  { 1, 516, 517, 8360, 8362 }, // 328 tc_a3070909
  { 1, 516, 517, 8362, 8364 }, // 329 tc_512b1653
  { 1, 520, 521, 8364, 8365 }, // 330 tc_d7718fbe
  { 1, 520, 521, 8365, 8368 }, // 331 tc_bb78483e
  { 1, 520, 521, 8368, 8369 }, // 332 tc_54f0cee2
  { 1, 520, 521, 8369, 8371 }, // 333 tc_28e55c6f
  { 1, 516, 517, 8371, 8372 }, // 334 tc_4bf903b0
  { 1, 516, 517, 8372, 8373 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV71[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 582, 583, 8373, 8376 }, // 1 tc_01d44cb2
  { 1, 583, 584, 8376, 8379 }, // 2 PSEUDO
  { 1, 583, 584, 8379, 8381 }, // 3 tc_c57d9f39
  { 1, 583, 584, 8381, 8385 }, // 4 tc_1c2c7a4a
  { 1, 583, 584, 8385, 8389 }, // 5 tc_442395f3
  { 1, 583, 584, 8389, 8392 }, // 6 tc_713b66bf
  { 1, 583, 584, 8392, 8395 }, // 7 tc_86173609
  { 1, 582, 583, 8395, 8398 }, // 8 tc_5da50c4b
  { 1, 582, 583, 8398, 8401 }, // 9 tc_4a55d03c
  { 1, 583, 584, 8401, 8404 }, // 10 tc_d33e5eee
  { 1, 582, 583, 8404, 8407 }, // 11 tc_651cbe02
  { 1, 584, 585, 8407, 8410 }, // 12 DUPLEX
  { 1, 585, 586, 8410, 8411 }, // 13 tc_ENDLOOP
  { 1, 583, 584, 0, 0 }, // 14 tc_23708a21
  { 1, 583, 584, 8411, 8413 }, // 15 tc_56a124a7
  { 1, 586, 587, 8413, 8415 }, // 16 tc_2f573607
  { 1, 586, 587, 8415, 8418 }, // 17 tc_53c851ab
  { 1, 587, 588, 8418, 8422 }, // 18 tc_fedb7e19
  { 1, 587, 588, 8422, 8425 }, // 19 tc_4222e6bf
  { 1, 587, 588, 8425, 8429 }, // 20 tc_075c8dd8
  { 1, 584, 585, 8429, 8432 }, // 21 tc_9bcfb2ee
  { 1, 584, 585, 8432, 8435 }, // 22 tc_158aa3f7
  { 1, 584, 585, 8435, 8438 }, // 23 tc_df5d53f9
  { 1, 584, 585, 8438, 8441 }, // 24 tc_14ab4f41
  { 1, 584, 585, 8441, 8442 }, // 25 tc_f38f92e1
  { 1, 584, 585, 8442, 8443 }, // 26 tc_1981450d
  { 1, 587, 588, 8443, 8445 }, // 27 tc_e9170fb7
  { 1, 584, 585, 8445, 8447 }, // 28 tc_40d64c94
  { 1, 587, 588, 8447, 8449 }, // 29 LD_tc_ld_SLOT01
  { 1, 582, 583, 8449, 8452 }, // 30 tc_38382228
  { 1, 582, 583, 8452, 8455 }, // 31 tc_c21d7447
  { 1, 582, 583, 8455, 8459 }, // 32 tc_7f8ae742
  { 1, 588, 589, 8459, 8462 }, // 33 tc_5a4b5e58
  { 1, 588, 589, 8462, 8466 }, // 34 tc_197dce51
  { 1, 582, 583, 8466, 8467 }, // 35 tc_44fffc58
  { 1, 587, 588, 8467, 8472 }, // 36 tc_5ceb2f9e
  { 1, 589, 591, 8472, 8475 }, // 37 tc_56c4f9fe
  { 1, 588, 589, 8475, 8477 }, // 38 tc_7476d766
  { 1, 587, 588, 8477, 8482 }, // 39 tc_b4dc7630
  { 1, 587, 588, 8482, 8486 }, // 40 tc_a2b365d2
  { 1, 586, 587, 8486, 8487 }, // 41 tc_60e324ff
  { 1, 591, 593, 8487, 8490 }, // 42 tc_db5555f3
  { 1, 593, 596, 8490, 8493 }, // 43 tc_c0749f3c
  { 1, 596, 598, 8493, 8496 }, // 44 PSEUDOM
  { 1, 589, 591, 8496, 8499 }, // 45 tc_3aacf4a8
  { 1, 598, 600, 8499, 8501 }, // 46 tc_c4edf264
  { 1, 600, 603, 8501, 8504 }, // 47 tc_c5dba46e
  { 1, 591, 593, 8504, 8508 }, // 48 tc_af25efd9
  { 1, 582, 583, 8508, 8511 }, // 49 tc_0dfac0a7
  { 1, 587, 588, 8511, 8515 }, // 50 tc_8035e91f
  { 1, 584, 585, 8515, 8519 }, // 51 tc_011e0e9d
  { 1, 587, 588, 8519, 8522 }, // 52 tc_ae5babd7
  { 1, 584, 585, 8522, 8525 }, // 53 tc_5deb5e47
  { 1, 582, 583, 8525, 8530 }, // 54 tc_bb831a7c
  { 1, 584, 585, 8530, 8534 }, // 55 tc_92240447
  { 1, 587, 588, 8534, 8537 }, // 56 tc_7c31e19a
  { 1, 587, 588, 8537, 8541 }, // 57 tc_d03278fd
  { 1, 587, 588, 8541, 8545 }, // 58 tc_65cbd974
  { 1, 584, 585, 8545, 8548 }, // 59 tc_934753bb
  { 1, 587, 588, 8548, 8551 }, // 60 ST_tc_st_SLOT01
  { 1, 603, 605, 8551, 8555 }, // 61 CVI_VA
  { 1, 598, 600, 8555, 8559 }, // 62 tc_f175e046
  { 1, 598, 600, 8559, 8564 }, // 63 tc_4942646a
  { 1, 589, 591, 8564, 8566 }, // 64 tc_0ec46cf9
  { 1, 591, 593, 8566, 8567 }, // 65 tc_718b5c53
  { 1, 605, 609, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 588, 589, 8567, 8569 }, // 67 tc_7dc63b5c
  { 1, 584, 585, 8569, 8570 }, // 68 tc_d45ba9cd
  { 1, 583, 584, 8570, 8573 }, // 69 tc_388f9897
  { 1, 583, 584, 8573, 8575 }, // 70 tc_9124c04f
  { 1, 583, 584, 8575, 8578 }, // 71 tc_4ac61d92
  { 1, 587, 588, 8578, 8580 }, // 72 tc_aee6250c
  { 1, 587, 588, 8580, 8583 }, // 73 tc_eed07714
  { 1, 587, 588, 8583, 8586 }, // 74 tc_74a42bda
  { 1, 587, 588, 8586, 8589 }, // 75 tc_a9edeffa
  { 1, 587, 588, 8589, 8592 }, // 76 tc_838c4d7a
  { 1, 582, 583, 8592, 8594 }, // 77 tc_d61dfdc3
  { 1, 582, 583, 8594, 8597 }, // 78 tc_8a825db2
  { 1, 582, 583, 8597, 8600 }, // 79 tc_f34c1c21
  { 1, 583, 584, 8600, 8603 }, // 80 tc_95a33176
  { 1, 582, 583, 8603, 8605 }, // 81 tc_9f6cd987
  { 1, 583, 584, 0, 0 }, // 82 tc_b837298f
  { 1, 583, 584, 8605, 8608 }, // 83 tc_8b5bd4f5
  { 1, 583, 584, 8608, 8611 }, // 84 tc_84a7500d
  { 1, 588, 589, 8611, 8613 }, // 85 tc_49fdfd4b
  { 1, 582, 583, 8613, 8616 }, // 86 tc_f098b237
  { 1, 582, 583, 8616, 8619 }, // 87 tc_20131976
  { 1, 582, 583, 8619, 8624 }, // 88 tc_1d41f8b7
  { 1, 582, 583, 8624, 8627 }, // 89 tc_a1297125
  { 1, 583, 584, 8627, 8628 }, // 90 tc_112d30d6
  { 1, 582, 583, 8628, 8631 }, // 91 tc_d68dca5c
  { 1, 582, 583, 8631, 8635 }, // 92 tc_788b1d09
  { 1, 582, 583, 8635, 8640 }, // 93 tc_38e0bae9
  { 1, 582, 583, 8640, 8643 }, // 94 tc_407e96f9
  { 1, 582, 583, 8643, 8647 }, // 95 tc_7401744f
  { 1, 582, 583, 8647, 8650 }, // 96 tc_9b3c0462
  { 1, 582, 583, 8650, 8652 }, // 97 tc_151bf368
  { 1, 583, 584, 8652, 8655 }, // 98 tc_9c52f549
  { 1, 582, 583, 8655, 8657 }, // 99 tc_55b33fda
  { 1, 582, 583, 8657, 8661 }, // 100 tc_6fc5dbea
  { 1, 588, 589, 8661, 8663 }, // 101 tc_3edca78f
  { 1, 582, 583, 8663, 8667 }, // 102 tc_a7a13fac
  { 1, 582, 583, 8667, 8669 }, // 103 tc_9783714b
  { 1, 582, 583, 8669, 8672 }, // 104 tc_f0e8e832
  { 1, 582, 583, 8672, 8674 }, // 105 tc_65279839
  { 1, 582, 583, 8674, 8678 }, // 106 tc_0a195f2c
  { 1, 582, 583, 8678, 8682 }, // 107 tc_01e1be3b
  { 1, 582, 583, 8682, 8685 }, // 108 tc_556f6577
  { 1, 582, 583, 8685, 8688 }, // 109 tc_02fe1c65
  { 1, 582, 583, 8688, 8692 }, // 110 tc_9e72dc89
  { 1, 582, 583, 8692, 8697 }, // 111 tc_9edb7c77
  { 1, 582, 583, 8697, 8700 }, // 112 tc_7f7f45f5
  { 1, 582, 583, 8700, 8703 }, // 113 tc_c20701f0
  { 1, 582, 583, 8703, 8707 }, // 114 tc_f7569068
  { 1, 588, 589, 8707, 8709 }, // 115 tc_fae9dfa5
  { 1, 588, 589, 8709, 8711 }, // 116 tc_6ae3426b
  { 1, 582, 583, 8711, 8713 }, // 117 tc_69bfb303
  { 1, 586, 587, 8713, 8714 }, // 118 tc_362b0be2
  { 1, 586, 587, 8714, 8716 }, // 119 tc_dc51281d
  { 1, 586, 587, 8716, 8717 }, // 120 tc_95f43c5e
  { 1, 583, 584, 8717, 8718 }, // 121 tc_decdde8a
  { 1, 583, 584, 8718, 8720 }, // 122 tc_eeda4109
  { 1, 583, 584, 8720, 8722 }, // 123 tc_711c805f
  { 1, 586, 587, 8722, 8724 }, // 124 tc_ed03645c
  { 1, 586, 587, 8724, 8726 }, // 125 tc_42ff66ba
  { 1, 588, 589, 8726, 8728 }, // 126 tc_57a55b54
  { 1, 586, 587, 8728, 8729 }, // 127 tc_f97707c1
  { 1, 588, 589, 8729, 8731 }, // 128 tc_1248597c
  { 1, 588, 589, 8731, 8733 }, // 129 tc_9406230a
  { 1, 586, 587, 8733, 8734 }, // 130 tc_d57d649c
  { 1, 588, 589, 8734, 8736 }, // 131 tc_4abdbdc6
  { 1, 588, 589, 8736, 8738 }, // 132 tc_6d861a95
  { 1, 586, 587, 0, 0 }, // 133 tc_b9bec29e
  { 1, 586, 587, 8738, 8739 }, // 134 tc_45f9d1be
  { 1, 586, 587, 0, 0 }, // 135 tc_33e7e673
  { 1, 584, 585, 8739, 8742 }, // 136 tc_24e109c7
  { 1, 583, 584, 8742, 8745 }, // 137 tc_9e27f2f9
  { 1, 584, 585, 8745, 8748 }, // 138 tc_f6e2aff9
  { 1, 583, 584, 8748, 8751 }, // 139 tc_24f426ab
  { 1, 584, 585, 8751, 8754 }, // 140 tc_975a4e54
  { 1, 586, 587, 8754, 8755 }, // 141 tc_e60def48
  { 1, 582, 583, 8755, 8758 }, // 142 tc_5502c366
  { 1, 584, 585, 8758, 8760 }, // 143 tc_7b9187d3
  { 1, 583, 584, 8760, 8762 }, // 144 tc_f999c66e
  { 1, 587, 588, 8762, 8767 }, // 145 tc_1c7522a8
  { 1, 587, 588, 8767, 8773 }, // 146 tc_76bb5435
  { 1, 587, 588, 8773, 8775 }, // 147 tc_8a6d0d94
  { 1, 584, 585, 8775, 8777 }, // 148 tc_2471c1c8
  { 1, 584, 585, 8777, 8779 }, // 149 tc_64b00d8a
  { 1, 587, 588, 8779, 8784 }, // 150 tc_5f2afaf7
  { 1, 587, 588, 8784, 8788 }, // 151 tc_ac65613f
  { 1, 587, 588, 8788, 8793 }, // 152 tc_a32e03e7
  { 1, 587, 588, 8793, 8796 }, // 153 tc_822c3c68
  { 1, 587, 588, 8796, 8800 }, // 154 tc_abfd9a6d
  { 1, 587, 588, 8800, 8804 }, // 155 tc_bf2ffc0f
  { 1, 584, 585, 8804, 8807 }, // 156 tc_ed3f8d2a
  { 1, 587, 588, 8807, 8810 }, // 157 tc_7c6d32e4
  { 1, 587, 588, 8810, 8815 }, // 158 tc_45791fb8
  { 1, 587, 588, 8815, 8820 }, // 159 tc_b7c4062a
  { 1, 587, 588, 8820, 8823 }, // 160 tc_5944960d
  { 1, 582, 583, 8823, 8827 }, // 161 tc_2c13e7f5
  { 1, 582, 583, 8827, 8831 }, // 162 tc_a154b476
  { 1, 582, 583, 8831, 8835 }, // 163 tc_a4e22bbd
  { 1, 582, 583, 8835, 8839 }, // 164 tc_503ce0f3
  { 1, 587, 588, 8839, 8841 }, // 165 tc_0655b949
  { 1, 584, 585, 8841, 8843 }, // 166 tc_6e20402a
  { 1, 584, 585, 8843, 8844 }, // 167 tc_db96aa6b
  { 1, 582, 583, 8844, 8846 }, // 168 tc_a7bdb22c
  { 1, 582, 583, 8846, 8849 }, // 169 tc_db596beb
  { 1, 582, 583, 8849, 8852 }, // 170 tc_a08b630b
  { 1, 582, 583, 8852, 8855 }, // 171 tc_1fcb8495
  { 1, 587, 588, 8855, 8860 }, // 172 tc_9edefe01
  { 1, 587, 588, 8860, 8865 }, // 173 tc_449acf79
  { 1, 584, 585, 8865, 8870 }, // 174 tc_ce59038e
  { 1, 584, 585, 8870, 8875 }, // 175 tc_f529831b
  { 1, 584, 585, 8875, 8880 }, // 176 tc_addc37a8
  { 1, 584, 585, 8880, 8883 }, // 177 tc_6f42bc60
  { 1, 584, 585, 8883, 8885 }, // 178 tc_7af3a37e
  { 1, 582, 583, 8885, 8887 }, // 179 tc_e3d699e3
  { 1, 587, 588, 8887, 8890 }, // 180 tc_ba9255a6
  { 1, 587, 588, 8890, 8895 }, // 181 tc_1fe4ab69
  { 1, 587, 588, 8895, 8898 }, // 182 tc_bb07f2c5
  { 1, 587, 588, 8898, 8903 }, // 183 tc_8e82e8ca
  { 1, 584, 585, 8903, 8906 }, // 184 tc_cfa0e29b
  { 1, 584, 585, 8906, 8911 }, // 185 tc_0a6c20ae
  { 1, 584, 585, 8911, 8914 }, // 186 tc_0fac1eb8
  { 1, 584, 585, 8914, 8919 }, // 187 tc_829d8a86
  { 1, 587, 588, 8919, 8923 }, // 188 tc_280f7fe1
  { 1, 587, 588, 8923, 8927 }, // 189 tc_887d1bb7
  { 1, 584, 585, 8927, 8931 }, // 190 tc_96ef76ef
  { 1, 584, 585, 8931, 8935 }, // 191 tc_55a9a350
  { 1, 582, 583, 8935, 8939 }, // 192 tc_f0cdeccf
  { 1, 582, 583, 8939, 8944 }, // 193 tc_a38c45dc
  { 1, 582, 583, 8944, 8946 }, // 194 tc_d3632d88
  { 1, 582, 583, 8946, 8950 }, // 195 tc_5e4cf0e8
  { 1, 582, 583, 8950, 8952 }, // 196 tc_ef921005
  { 1, 587, 588, 8952, 8955 }, // 197 tc_5b347363
  { 1, 587, 588, 8955, 8957 }, // 198 tc_3d14a17b
  { 1, 587, 588, 8957, 8958 }, // 199 tc_3fbf1042
  { 1, 587, 588, 8958, 8959 }, // 200 tc_63567288
  { 1, 587, 588, 8959, 8961 }, // 201 tc_59a7822c
  { 1, 587, 588, 0, 0 }, // 202 tc_937dd41c
  { 1, 584, 585, 0, 0 }, // 203 tc_a4ee89db
  { 1, 584, 585, 0, 0 }, // 204 tc_c818ff7f
  { 1, 584, 585, 8961, 8962 }, // 205 tc_1242dc2a
  { 1, 587, 588, 8962, 8964 }, // 206 tc_44d5a428
  { 1, 609, 611, 8964, 8967 }, // 207 tc_540c3da3
  { 1, 598, 600, 8967, 8971 }, // 208 tc_b091f1c6
  { 1, 611, 613, 8971, 8973 }, // 209 tc_5bf8afbb
  { 1, 613, 615, 8973, 8977 }, // 210 tc_2b4c548e
  { 1, 613, 615, 8977, 8982 }, // 211 tc_bb599486
  { 1, 615, 619, 8982, 8985 }, // 212 tc_a7e6707d
  { 1, 615, 619, 8985, 8989 }, // 213 tc_3c56e5ce
  { 1, 593, 596, 8989, 8993 }, // 214 tc_abe8c3b2
  { 1, 593, 596, 8993, 8998 }, // 215 tc_453fe68d
  { 1, 593, 596, 8998, 9002 }, // 216 tc_1ba8a0cd
  { 1, 619, 621, 9002, 9005 }, // 217 tc_52447ecc
  { 1, 619, 621, 9005, 9009 }, // 218 tc_3904b926
  { 1, 619, 621, 9009, 9014 }, // 219 tc_b9db8205
  { 1, 619, 621, 9014, 9018 }, // 220 tc_663c80a7
  { 1, 621, 625, 9018, 9021 }, // 221 tc_f21e8abb
  { 1, 621, 625, 9021, 9025 }, // 222 tc_131f1c81
  { 1, 621, 625, 9025, 9030 }, // 223 tc_c7039829
  { 1, 621, 625, 9030, 9034 }, // 224 tc_e2d2e9e5
  { 1, 625, 627, 9034, 9037 }, // 225 tc_ab23f776
  { 1, 625, 627, 9037, 9041 }, // 226 tc_7177e272
  { 1, 625, 627, 9041, 9046 }, // 227 tc_e99d4c2e
  { 1, 625, 627, 9046, 9050 }, // 228 tc_6942b6e0
  { 1, 600, 603, 9050, 9054 }, // 229 tc_a02a10a8
  { 1, 600, 603, 9054, 9059 }, // 230 tc_54a0dc47
  { 1, 600, 603, 9059, 9063 }, // 231 tc_447d9895
  { 1, 600, 603, 9063, 9068 }, // 232 tc_191381c1
  { 1, 600, 603, 9068, 9072 }, // 233 tc_3e2aaafc
  { 1, 625, 627, 9072, 9074 }, // 234 tc_3ce09744
  { 1, 625, 627, 9074, 9077 }, // 235 tc_20a4bbec
  { 1, 598, 600, 9077, 9079 }, // 236 tc_5cdf8c84
  { 1, 627, 629, 9079, 9081 }, // 237 tc_2a698a03
  { 1, 598, 600, 9081, 9084 }, // 238 tc_c127de3a
  { 1, 629, 631, 9084, 9087 }, // 239 tc_05ca8cfd
  { 1, 613, 615, 9087, 9090 }, // 240 tc_d8287c14
  { 1, 589, 591, 9090, 9094 }, // 241 tc_257f6f7c
  { 1, 589, 591, 9094, 9099 }, // 242 tc_7e6a3e89
  { 1, 589, 591, 9099, 9103 }, // 243 tc_e35c1e93
  { 1, 613, 615, 9103, 9107 }, // 244 tc_08a4f1b6
  { 1, 589, 591, 9107, 9111 }, // 245 tc_57a4709c
  { 1, 611, 613, 9111, 9115 }, // 246 tc_56e64202
  { 1, 598, 600, 9115, 9118 }, // 247 tc_ac4046bc
  { 1, 598, 600, 9118, 9122 }, // 248 tc_2e8f5f6e
  { 1, 629, 631, 9122, 9125 }, // 249 tc_7417e785
  { 1, 629, 631, 9125, 9129 }, // 250 tc_309dbb4f
  { 1, 631, 633, 9129, 9133 }, // 251 tc_df80eeb0
  { 1, 629, 631, 9133, 9137 }, // 252 tc_16ff9ef8
  { 1, 583, 584, 9137, 9139 }, // 253 tc_e2fdd6e6
  { 1, 629, 631, 9139, 9141 }, // 254 tc_51d0ecc3
  { 1, 583, 584, 9141, 9144 }, // 255 tc_531b383c
  { 1, 631, 633, 9144, 9146 }, // 256 tc_04da405a
  { 1, 598, 600, 9146, 9148 }, // 257 tc_3c8c15d0
  { 1, 613, 615, 9148, 9150 }, // 258 tc_0afc8be9
  { 1, 631, 633, 9150, 9155 }, // 259 tc_561aaa58
  { 1, 611, 613, 9155, 9157 }, // 260 tc_946013d8
  { 1, 611, 613, 9157, 9160 }, // 261 tc_46d6c3e0
  { 1, 631, 633, 9160, 9164 }, // 262 tc_87adc037
  { 1, 598, 600, 9164, 9168 }, // 263 tc_a19b9305
  { 1, 598, 600, 9168, 9171 }, // 264 tc_649072c2
  { 1, 613, 615, 9171, 9174 }, // 265 tc_0b04c6c7
  { 1, 613, 615, 9174, 9178 }, // 266 tc_660769f1
  { 1, 598, 600, 9178, 9181 }, // 267 tc_dcca380f
  { 1, 598, 600, 9181, 9185 }, // 268 tc_72e2b393
  { 1, 598, 600, 9185, 9188 }, // 269 tc_73efe966
  { 1, 598, 600, 9188, 9191 }, // 270 tc_cda936da
  { 1, 593, 596, 9191, 9194 }, // 271 tc_a28f32b5
  { 1, 593, 596, 9194, 9198 }, // 272 tc_7d68d5c2
  { 1, 633, 636, 9198, 9201 }, // 273 tc_7095ecba
  { 1, 633, 636, 9201, 9205 }, // 274 tc_a69eeee1
  { 1, 636, 638, 0, 0 }, // 275 tc_1381a97c
  { 1, 636, 638, 9205, 9206 }, // 276 tc_e3f68a46
  { 1, 638, 640, 9206, 9209 }, // 277 tc_f1de44ef
  { 1, 631, 633, 9209, 9214 }, // 278 tc_9d1dc972
  { 1, 638, 640, 9214, 9218 }, // 279 tc_90bcc1db
  { 1, 640, 643, 9218, 9221 }, // 280 tc_cd94bfe0
  { 1, 640, 643, 9221, 9225 }, // 281 tc_15fdf750
  { 1, 613, 615, 9225, 9229 }, // 282 tc_1ad8a370
  { 1, 613, 615, 9229, 9234 }, // 283 tc_e675c45a
  { 1, 598, 600, 9234, 9238 }, // 284 tc_37820f4c
  { 1, 643, 645, 9238, 9241 }, // 285 tc_61bf7c03
  { 1, 643, 645, 9241, 9245 }, // 286 tc_933f2b39
  { 1, 643, 645, 9245, 9249 }, // 287 tc_26a377fe
  { 1, 643, 645, 9249, 9254 }, // 288 tc_2d4051cd
  { 1, 611, 613, 9254, 9257 }, // 289 tc_6e7fa133
  { 1, 589, 591, 9257, 9260 }, // 290 tc_8772086c
  { 1, 591, 593, 9260, 9262 }, // 291 tc_b4416217
  { 1, 600, 603, 9262, 9266 }, // 292 tc_9f363d21
  { 1, 600, 603, 9266, 9271 }, // 293 tc_8e420e4d
  { 1, 645, 648, 9271, 9275 }, // 294 tc_7273323b
  { 1, 645, 648, 9275, 9280 }, // 295 tc_58d21193
  { 1, 591, 593, 9280, 9284 }, // 296 tc_71646d06
  { 1, 631, 633, 9284, 9287 }, // 297 tc_2c745bb8
  { 1, 636, 638, 9287, 9288 }, // 298 tc_b28e51aa
  { 1, 636, 638, 9288, 9290 }, // 299 tc_767c4e9d
  { 1, 648, 650, 9290, 9292 }, // 300 tc_e699ae41
  { 1, 648, 650, 9292, 9295 }, // 301 tc_a0dbea28
  { 1, 648, 650, 9295, 9298 }, // 302 tc_dd5b0695
  { 1, 648, 650, 9298, 9302 }, // 303 tc_3ad719fb
  { 1, 584, 585, 0, 0 }, // 304 tc_77f94a5e
  { 1, 588, 589, 0, 0 }, // 305 tc_55255f2b
  { 1, 588, 589, 9302, 9303 }, // 306 tc_0a43be35
  { 1, 584, 585, 9303, 9304 }, // 307 tc_b1ae5f67
  { 1, 584, 585, 9304, 9305 }, // 308 tc_d234b61a
  { 1, 584, 585, 9305, 9307 }, // 309 tc_2237d952
  { 1, 584, 585, 0, 0 }, // 310 tc_78f87ed3
  { 1, 584, 585, 9307, 9309 }, // 311 tc_a724463d
  { 1, 584, 585, 9309, 9311 }, // 312 tc_6fb52018
  { 1, 588, 589, 9311, 9313 }, // 313 tc_46c18ecf
  { 1, 586, 587, 9313, 9315 }, // 314 tc_9b20a062
  { 1, 586, 587, 9315, 9317 }, // 315 tc_5a222e89
  { 1, 586, 587, 9317, 9318 }, // 316 tc_0ba0d5da
  { 1, 586, 587, 9318, 9319 }, // 317 tc_7d6a2568
  { 1, 586, 587, 9319, 9321 }, // 318 tc_759e57be
  { 1, 586, 587, 9321, 9323 }, // 319 tc_139ef484
  { 1, 586, 587, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 588, 589, 0, 0 }, // 321 tc_7f58404a
  { 1, 584, 585, 0, 0 }, // 322 tc_b3d46584
  { 1, 588, 589, 9323, 9325 }, // 323 tc_d71ea8fa
  { 1, 588, 589, 9325, 9327 }, // 324 tc_6aa823ab
  { 1, 588, 589, 9327, 9329 }, // 325 tc_b2196a3f
  { 1, 588, 589, 9329, 9330 }, // 326 tc_2c3e17fc
  { 1, 588, 589, 9330, 9333 }, // 327 tc_27106296
  { 1, 584, 585, 9333, 9335 }, // 328 tc_a3070909
  { 1, 584, 585, 9335, 9337 }, // 329 tc_512b1653
  { 1, 588, 589, 9337, 9338 }, // 330 tc_d7718fbe
  { 1, 588, 589, 9338, 9341 }, // 331 tc_bb78483e
  { 1, 588, 589, 9341, 9342 }, // 332 tc_54f0cee2
  { 1, 588, 589, 9342, 9344 }, // 333 tc_28e55c6f
  { 1, 584, 585, 9344, 9345 }, // 334 tc_4bf903b0
  { 1, 584, 585, 9345, 9346 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV71T[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 650, 651, 9346, 9349 }, // 1 tc_01d44cb2
  { 1, 651, 652, 9349, 9352 }, // 2 PSEUDO
  { 1, 651, 652, 9352, 9354 }, // 3 tc_c57d9f39
  { 1, 651, 652, 9354, 9358 }, // 4 tc_1c2c7a4a
  { 1, 651, 652, 9358, 9362 }, // 5 tc_442395f3
  { 1, 651, 652, 9362, 9365 }, // 6 tc_713b66bf
  { 1, 651, 652, 9365, 9368 }, // 7 tc_86173609
  { 1, 650, 651, 9368, 9371 }, // 8 tc_5da50c4b
  { 1, 650, 651, 9371, 9374 }, // 9 tc_4a55d03c
  { 1, 651, 652, 9374, 9377 }, // 10 tc_d33e5eee
  { 1, 650, 651, 9377, 9380 }, // 11 tc_651cbe02
  { 1, 652, 653, 9380, 9383 }, // 12 DUPLEX
  { 1, 653, 654, 9383, 9384 }, // 13 tc_ENDLOOP
  { 1, 651, 652, 0, 0 }, // 14 tc_23708a21
  { 1, 651, 652, 9384, 9386 }, // 15 tc_56a124a7
  { 1, 654, 655, 9386, 9388 }, // 16 tc_2f573607
  { 1, 654, 655, 9388, 9391 }, // 17 tc_53c851ab
  { 1, 652, 653, 9391, 9395 }, // 18 tc_fedb7e19
  { 1, 652, 653, 9395, 9398 }, // 19 tc_4222e6bf
  { 1, 652, 653, 9398, 9402 }, // 20 tc_075c8dd8
  { 1, 652, 653, 9402, 9405 }, // 21 tc_9bcfb2ee
  { 1, 652, 653, 9405, 9408 }, // 22 tc_158aa3f7
  { 1, 652, 653, 9408, 9411 }, // 23 tc_df5d53f9
  { 1, 652, 653, 9411, 9414 }, // 24 tc_14ab4f41
  { 1, 652, 653, 9414, 9415 }, // 25 tc_f38f92e1
  { 1, 652, 653, 9415, 9416 }, // 26 tc_1981450d
  { 1, 652, 653, 9416, 9418 }, // 27 tc_e9170fb7
  { 1, 652, 653, 9418, 9420 }, // 28 tc_40d64c94
  { 1, 652, 653, 9420, 9423 }, // 29 LD_tc_ld_SLOT01
  { 1, 655, 656, 9423, 9426 }, // 30 tc_38382228
  { 1, 655, 656, 9426, 9429 }, // 31 tc_c21d7447
  { 1, 655, 656, 9429, 9433 }, // 32 tc_7f8ae742
  { 1, 655, 656, 9433, 9436 }, // 33 tc_5a4b5e58
  { 1, 655, 656, 9436, 9440 }, // 34 tc_197dce51
  { 1, 650, 651, 9440, 9441 }, // 35 tc_44fffc58
  { 1, 652, 653, 9441, 9446 }, // 36 tc_5ceb2f9e
  { 1, 656, 658, 9446, 9449 }, // 37 tc_56c4f9fe
  { 1, 655, 656, 9449, 9451 }, // 38 tc_7476d766
  { 1, 652, 653, 9451, 9456 }, // 39 tc_b4dc7630
  { 1, 652, 653, 9456, 9460 }, // 40 tc_a2b365d2
  { 1, 654, 655, 9460, 9461 }, // 41 tc_60e324ff
  { 1, 658, 660, 9461, 9464 }, // 42 tc_db5555f3
  { 1, 660, 663, 9464, 9467 }, // 43 tc_c0749f3c
  { 1, 663, 665, 9467, 9470 }, // 44 PSEUDOM
  { 1, 656, 658, 9470, 9473 }, // 45 tc_3aacf4a8
  { 1, 665, 667, 9473, 9475 }, // 46 tc_c4edf264
  { 1, 667, 670, 9475, 9478 }, // 47 tc_c5dba46e
  { 1, 658, 660, 9478, 9482 }, // 48 tc_af25efd9
  { 1, 650, 651, 9482, 9485 }, // 49 tc_0dfac0a7
  { 1, 652, 653, 9485, 9489 }, // 50 tc_8035e91f
  { 1, 652, 653, 9489, 9493 }, // 51 tc_011e0e9d
  { 1, 652, 653, 9493, 9496 }, // 52 tc_ae5babd7
  { 1, 652, 653, 9496, 9499 }, // 53 tc_5deb5e47
  { 1, 655, 656, 9499, 9504 }, // 54 tc_bb831a7c
  { 1, 652, 653, 9504, 9508 }, // 55 tc_92240447
  { 1, 652, 653, 9508, 9511 }, // 56 tc_7c31e19a
  { 1, 652, 653, 9511, 9515 }, // 57 tc_d03278fd
  { 1, 652, 653, 9515, 9519 }, // 58 tc_65cbd974
  { 1, 652, 653, 9519, 9522 }, // 59 tc_934753bb
  { 1, 652, 653, 9522, 9526 }, // 60 ST_tc_st_SLOT01
  { 1, 670, 672, 9526, 9530 }, // 61 CVI_VA
  { 1, 665, 667, 9530, 9534 }, // 62 tc_f175e046
  { 1, 665, 667, 9534, 9539 }, // 63 tc_4942646a
  { 1, 656, 658, 9539, 9541 }, // 64 tc_0ec46cf9
  { 1, 658, 660, 9541, 9542 }, // 65 tc_718b5c53
  { 1, 672, 676, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 655, 656, 9542, 9544 }, // 67 tc_7dc63b5c
  { 1, 652, 653, 9544, 9545 }, // 68 tc_d45ba9cd
  { 1, 676, 677, 9545, 9548 }, // 69 tc_388f9897
  { 1, 676, 677, 9548, 9550 }, // 70 tc_9124c04f
  { 1, 676, 677, 9550, 9553 }, // 71 tc_4ac61d92
  { 1, 677, 678, 9553, 9555 }, // 72 tc_aee6250c
  { 1, 677, 678, 9555, 9558 }, // 73 tc_eed07714
  { 1, 677, 678, 9558, 9561 }, // 74 tc_74a42bda
  { 1, 677, 678, 9561, 9564 }, // 75 tc_a9edeffa
  { 1, 677, 678, 9564, 9567 }, // 76 tc_838c4d7a
  { 1, 650, 651, 9567, 9569 }, // 77 tc_d61dfdc3
  { 1, 650, 651, 9569, 9572 }, // 78 tc_8a825db2
  { 1, 650, 651, 9572, 9575 }, // 79 tc_f34c1c21
  { 1, 651, 652, 9575, 9578 }, // 80 tc_95a33176
  { 1, 650, 651, 9578, 9580 }, // 81 tc_9f6cd987
  { 1, 651, 652, 0, 0 }, // 82 tc_b837298f
  { 1, 651, 652, 9580, 9583 }, // 83 tc_8b5bd4f5
  { 1, 651, 652, 9583, 9586 }, // 84 tc_84a7500d
  { 1, 655, 656, 9586, 9588 }, // 85 tc_49fdfd4b
  { 1, 650, 651, 9588, 9591 }, // 86 tc_f098b237
  { 1, 650, 651, 9591, 9594 }, // 87 tc_20131976
  { 1, 650, 651, 9594, 9599 }, // 88 tc_1d41f8b7
  { 1, 650, 651, 9599, 9602 }, // 89 tc_a1297125
  { 1, 651, 652, 9602, 9603 }, // 90 tc_112d30d6
  { 1, 655, 656, 9603, 9606 }, // 91 tc_d68dca5c
  { 1, 655, 656, 9606, 9610 }, // 92 tc_788b1d09
  { 1, 655, 656, 9610, 9615 }, // 93 tc_38e0bae9
  { 1, 650, 651, 9615, 9618 }, // 94 tc_407e96f9
  { 1, 655, 656, 9618, 9622 }, // 95 tc_7401744f
  { 1, 650, 651, 9622, 9625 }, // 96 tc_9b3c0462
  { 1, 650, 651, 9625, 9627 }, // 97 tc_151bf368
  { 1, 651, 652, 9627, 9630 }, // 98 tc_9c52f549
  { 1, 650, 651, 9630, 9632 }, // 99 tc_55b33fda
  { 1, 650, 651, 9632, 9636 }, // 100 tc_6fc5dbea
  { 1, 655, 656, 9636, 9638 }, // 101 tc_3edca78f
  { 1, 650, 651, 9638, 9642 }, // 102 tc_a7a13fac
  { 1, 655, 656, 9642, 9644 }, // 103 tc_9783714b
  { 1, 655, 656, 9644, 9647 }, // 104 tc_f0e8e832
  { 1, 650, 651, 9647, 9649 }, // 105 tc_65279839
  { 1, 655, 656, 9649, 9653 }, // 106 tc_0a195f2c
  { 1, 655, 656, 9653, 9657 }, // 107 tc_01e1be3b
  { 1, 655, 656, 9657, 9660 }, // 108 tc_556f6577
  { 1, 655, 656, 9660, 9663 }, // 109 tc_02fe1c65
  { 1, 655, 656, 9663, 9667 }, // 110 tc_9e72dc89
  { 1, 655, 656, 9667, 9672 }, // 111 tc_9edb7c77
  { 1, 655, 656, 9672, 9675 }, // 112 tc_7f7f45f5
  { 1, 650, 651, 9675, 9678 }, // 113 tc_c20701f0
  { 1, 655, 656, 9678, 9682 }, // 114 tc_f7569068
  { 1, 655, 656, 9682, 9684 }, // 115 tc_fae9dfa5
  { 1, 655, 656, 9684, 9686 }, // 116 tc_6ae3426b
  { 1, 650, 651, 9686, 9688 }, // 117 tc_69bfb303
  { 1, 654, 655, 9688, 9689 }, // 118 tc_362b0be2
  { 1, 654, 655, 9689, 9691 }, // 119 tc_dc51281d
  { 1, 654, 655, 9691, 9692 }, // 120 tc_95f43c5e
  { 1, 651, 652, 9692, 9693 }, // 121 tc_decdde8a
  { 1, 651, 652, 9693, 9695 }, // 122 tc_eeda4109
  { 1, 651, 652, 9695, 9697 }, // 123 tc_711c805f
  { 1, 654, 655, 9697, 9699 }, // 124 tc_ed03645c
  { 1, 654, 655, 9699, 9701 }, // 125 tc_42ff66ba
  { 1, 655, 656, 9701, 9703 }, // 126 tc_57a55b54
  { 1, 654, 655, 9703, 9704 }, // 127 tc_f97707c1
  { 1, 655, 656, 9704, 9706 }, // 128 tc_1248597c
  { 1, 655, 656, 9706, 9708 }, // 129 tc_9406230a
  { 1, 654, 655, 9708, 9709 }, // 130 tc_d57d649c
  { 1, 655, 656, 9709, 9711 }, // 131 tc_4abdbdc6
  { 1, 655, 656, 9711, 9713 }, // 132 tc_6d861a95
  { 1, 654, 655, 0, 0 }, // 133 tc_b9bec29e
  { 1, 654, 655, 9713, 9714 }, // 134 tc_45f9d1be
  { 1, 654, 655, 0, 0 }, // 135 tc_33e7e673
  { 1, 652, 653, 9714, 9717 }, // 136 tc_24e109c7
  { 1, 651, 652, 9717, 9720 }, // 137 tc_9e27f2f9
  { 1, 652, 653, 9720, 9723 }, // 138 tc_f6e2aff9
  { 1, 651, 652, 9723, 9726 }, // 139 tc_24f426ab
  { 1, 652, 653, 9726, 9729 }, // 140 tc_975a4e54
  { 1, 654, 655, 9729, 9730 }, // 141 tc_e60def48
  { 1, 650, 651, 9730, 9733 }, // 142 tc_5502c366
  { 1, 652, 653, 9733, 9735 }, // 143 tc_7b9187d3
  { 1, 651, 652, 9735, 9737 }, // 144 tc_f999c66e
  { 1, 652, 653, 9737, 9742 }, // 145 tc_1c7522a8
  { 1, 652, 653, 9742, 9748 }, // 146 tc_76bb5435
  { 1, 652, 653, 9748, 9750 }, // 147 tc_8a6d0d94
  { 1, 652, 653, 9750, 9752 }, // 148 tc_2471c1c8
  { 1, 652, 653, 9752, 9754 }, // 149 tc_64b00d8a
  { 1, 652, 653, 9754, 9759 }, // 150 tc_5f2afaf7
  { 1, 652, 653, 9759, 9763 }, // 151 tc_ac65613f
  { 1, 652, 653, 9763, 9768 }, // 152 tc_a32e03e7
  { 1, 652, 653, 9768, 9771 }, // 153 tc_822c3c68
  { 1, 652, 653, 9771, 9775 }, // 154 tc_abfd9a6d
  { 1, 652, 653, 9775, 9779 }, // 155 tc_bf2ffc0f
  { 1, 652, 653, 9779, 9782 }, // 156 tc_ed3f8d2a
  { 1, 652, 653, 9782, 9785 }, // 157 tc_7c6d32e4
  { 1, 652, 653, 9785, 9790 }, // 158 tc_45791fb8
  { 1, 652, 653, 9790, 9795 }, // 159 tc_b7c4062a
  { 1, 652, 653, 9795, 9798 }, // 160 tc_5944960d
  { 1, 655, 656, 9798, 9802 }, // 161 tc_2c13e7f5
  { 1, 655, 656, 9802, 9806 }, // 162 tc_a154b476
  { 1, 655, 656, 9806, 9810 }, // 163 tc_a4e22bbd
  { 1, 655, 656, 9810, 9814 }, // 164 tc_503ce0f3
  { 1, 652, 653, 9814, 9816 }, // 165 tc_0655b949
  { 1, 652, 653, 9816, 9818 }, // 166 tc_6e20402a
  { 1, 652, 653, 9818, 9819 }, // 167 tc_db96aa6b
  { 1, 655, 656, 9819, 9821 }, // 168 tc_a7bdb22c
  { 1, 655, 656, 9821, 9824 }, // 169 tc_db596beb
  { 1, 655, 656, 9824, 9827 }, // 170 tc_a08b630b
  { 1, 655, 656, 9827, 9830 }, // 171 tc_1fcb8495
  { 1, 652, 653, 9830, 9835 }, // 172 tc_9edefe01
  { 1, 652, 653, 9835, 9840 }, // 173 tc_449acf79
  { 1, 652, 653, 9840, 9845 }, // 174 tc_ce59038e
  { 1, 652, 653, 9845, 9850 }, // 175 tc_f529831b
  { 1, 652, 653, 9850, 9855 }, // 176 tc_addc37a8
  { 1, 652, 653, 9855, 9858 }, // 177 tc_6f42bc60
  { 1, 652, 653, 9858, 9860 }, // 178 tc_7af3a37e
  { 1, 650, 651, 9860, 9862 }, // 179 tc_e3d699e3
  { 1, 652, 653, 9862, 9865 }, // 180 tc_ba9255a6
  { 1, 652, 653, 9865, 9870 }, // 181 tc_1fe4ab69
  { 1, 652, 653, 9870, 9873 }, // 182 tc_bb07f2c5
  { 1, 652, 653, 9873, 9878 }, // 183 tc_8e82e8ca
  { 1, 652, 653, 9878, 9881 }, // 184 tc_cfa0e29b
  { 1, 652, 653, 9881, 9886 }, // 185 tc_0a6c20ae
  { 1, 652, 653, 9886, 9889 }, // 186 tc_0fac1eb8
  { 1, 652, 653, 9889, 9894 }, // 187 tc_829d8a86
  { 1, 652, 653, 9894, 9898 }, // 188 tc_280f7fe1
  { 1, 652, 653, 9898, 9902 }, // 189 tc_887d1bb7
  { 1, 652, 653, 9902, 9906 }, // 190 tc_96ef76ef
  { 1, 652, 653, 9906, 9910 }, // 191 tc_55a9a350
  { 1, 655, 656, 9910, 9914 }, // 192 tc_f0cdeccf
  { 1, 655, 656, 9914, 9919 }, // 193 tc_a38c45dc
  { 1, 655, 656, 9919, 9921 }, // 194 tc_d3632d88
  { 1, 655, 656, 9921, 9925 }, // 195 tc_5e4cf0e8
  { 1, 650, 651, 9925, 9927 }, // 196 tc_ef921005
  { 1, 652, 653, 9927, 9930 }, // 197 tc_5b347363
  { 1, 652, 653, 9930, 9932 }, // 198 tc_3d14a17b
  { 1, 652, 653, 9932, 9933 }, // 199 tc_3fbf1042
  { 1, 652, 653, 9933, 9934 }, // 200 tc_63567288
  { 1, 652, 653, 9934, 9936 }, // 201 tc_59a7822c
  { 1, 652, 653, 0, 0 }, // 202 tc_937dd41c
  { 1, 652, 653, 0, 0 }, // 203 tc_a4ee89db
  { 1, 652, 653, 0, 0 }, // 204 tc_c818ff7f
  { 1, 652, 653, 9936, 9937 }, // 205 tc_1242dc2a
  { 1, 652, 653, 9937, 9939 }, // 206 tc_44d5a428
  { 1, 678, 680, 9939, 9942 }, // 207 tc_540c3da3
  { 1, 665, 667, 9942, 9946 }, // 208 tc_b091f1c6
  { 1, 680, 682, 9946, 9948 }, // 209 tc_5bf8afbb
  { 1, 682, 684, 9948, 9952 }, // 210 tc_2b4c548e
  { 1, 682, 684, 9952, 9957 }, // 211 tc_bb599486
  { 1, 684, 688, 9957, 9960 }, // 212 tc_a7e6707d
  { 1, 684, 688, 9960, 9964 }, // 213 tc_3c56e5ce
  { 1, 660, 663, 9964, 9968 }, // 214 tc_abe8c3b2
  { 1, 660, 663, 9968, 9973 }, // 215 tc_453fe68d
  { 1, 660, 663, 9973, 9977 }, // 216 tc_1ba8a0cd
  { 1, 688, 690, 9977, 9980 }, // 217 tc_52447ecc
  { 1, 688, 690, 9980, 9984 }, // 218 tc_3904b926
  { 1, 688, 690, 9984, 9989 }, // 219 tc_b9db8205
  { 1, 688, 690, 9989, 9993 }, // 220 tc_663c80a7
  { 1, 690, 694, 9993, 9996 }, // 221 tc_f21e8abb
  { 1, 690, 694, 9996, 10000 }, // 222 tc_131f1c81
  { 1, 690, 694, 10000, 10005 }, // 223 tc_c7039829
  { 1, 690, 694, 10005, 10009 }, // 224 tc_e2d2e9e5
  { 1, 694, 696, 10009, 10012 }, // 225 tc_ab23f776
  { 1, 694, 696, 10012, 10016 }, // 226 tc_7177e272
  { 1, 694, 696, 10016, 10021 }, // 227 tc_e99d4c2e
  { 1, 694, 696, 10021, 10025 }, // 228 tc_6942b6e0
  { 1, 667, 670, 10025, 10029 }, // 229 tc_a02a10a8
  { 1, 667, 670, 10029, 10034 }, // 230 tc_54a0dc47
  { 1, 667, 670, 10034, 10038 }, // 231 tc_447d9895
  { 1, 667, 670, 10038, 10043 }, // 232 tc_191381c1
  { 1, 667, 670, 10043, 10047 }, // 233 tc_3e2aaafc
  { 1, 694, 696, 10047, 10049 }, // 234 tc_3ce09744
  { 1, 694, 696, 10049, 10052 }, // 235 tc_20a4bbec
  { 1, 665, 667, 10052, 10054 }, // 236 tc_5cdf8c84
  { 1, 696, 698, 10054, 10056 }, // 237 tc_2a698a03
  { 1, 665, 667, 10056, 10059 }, // 238 tc_c127de3a
  { 1, 698, 700, 10059, 10062 }, // 239 tc_05ca8cfd
  { 1, 682, 684, 10062, 10065 }, // 240 tc_d8287c14
  { 1, 656, 658, 10065, 10069 }, // 241 tc_257f6f7c
  { 1, 656, 658, 10069, 10074 }, // 242 tc_7e6a3e89
  { 1, 656, 658, 10074, 10078 }, // 243 tc_e35c1e93
  { 1, 682, 684, 10078, 10082 }, // 244 tc_08a4f1b6
  { 1, 656, 658, 10082, 10086 }, // 245 tc_57a4709c
  { 1, 680, 682, 10086, 10090 }, // 246 tc_56e64202
  { 1, 665, 667, 10090, 10093 }, // 247 tc_ac4046bc
  { 1, 665, 667, 10093, 10097 }, // 248 tc_2e8f5f6e
  { 1, 698, 700, 10097, 10100 }, // 249 tc_7417e785
  { 1, 698, 700, 10100, 10104 }, // 250 tc_309dbb4f
  { 1, 700, 702, 10104, 10108 }, // 251 tc_df80eeb0
  { 1, 698, 700, 10108, 10112 }, // 252 tc_16ff9ef8
  { 1, 676, 677, 10112, 10114 }, // 253 tc_e2fdd6e6
  { 1, 698, 700, 10114, 10116 }, // 254 tc_51d0ecc3
  { 1, 676, 677, 10116, 10119 }, // 255 tc_531b383c
  { 1, 700, 702, 10119, 10121 }, // 256 tc_04da405a
  { 1, 665, 667, 10121, 10123 }, // 257 tc_3c8c15d0
  { 1, 682, 684, 10123, 10125 }, // 258 tc_0afc8be9
  { 1, 700, 702, 10125, 10130 }, // 259 tc_561aaa58
  { 1, 680, 682, 10130, 10132 }, // 260 tc_946013d8
  { 1, 680, 682, 10132, 10135 }, // 261 tc_46d6c3e0
  { 1, 700, 702, 10135, 10139 }, // 262 tc_87adc037
  { 1, 665, 667, 10139, 10143 }, // 263 tc_a19b9305
  { 1, 665, 667, 10143, 10146 }, // 264 tc_649072c2
  { 1, 682, 684, 10146, 10149 }, // 265 tc_0b04c6c7
  { 1, 682, 684, 10149, 10153 }, // 266 tc_660769f1
  { 1, 665, 667, 10153, 10156 }, // 267 tc_dcca380f
  { 1, 665, 667, 10156, 10160 }, // 268 tc_72e2b393
  { 1, 665, 667, 10160, 10163 }, // 269 tc_73efe966
  { 1, 665, 667, 10163, 10166 }, // 270 tc_cda936da
  { 1, 660, 663, 10166, 10169 }, // 271 tc_a28f32b5
  { 1, 660, 663, 10169, 10173 }, // 272 tc_7d68d5c2
  { 1, 702, 705, 10173, 10176 }, // 273 tc_7095ecba
  { 1, 702, 705, 10176, 10180 }, // 274 tc_a69eeee1
  { 1, 705, 707, 0, 0 }, // 275 tc_1381a97c
  { 1, 705, 707, 10180, 10181 }, // 276 tc_e3f68a46
  { 1, 707, 709, 10181, 10184 }, // 277 tc_f1de44ef
  { 1, 700, 702, 10184, 10189 }, // 278 tc_9d1dc972
  { 1, 707, 709, 10189, 10193 }, // 279 tc_90bcc1db
  { 1, 709, 712, 10193, 10196 }, // 280 tc_cd94bfe0
  { 1, 709, 712, 10196, 10200 }, // 281 tc_15fdf750
  { 1, 682, 684, 10200, 10204 }, // 282 tc_1ad8a370
  { 1, 682, 684, 10204, 10209 }, // 283 tc_e675c45a
  { 1, 665, 667, 10209, 10213 }, // 284 tc_37820f4c
  { 1, 712, 714, 10213, 10216 }, // 285 tc_61bf7c03
  { 1, 712, 714, 10216, 10220 }, // 286 tc_933f2b39
  { 1, 712, 714, 10220, 10224 }, // 287 tc_26a377fe
  { 1, 712, 714, 10224, 10229 }, // 288 tc_2d4051cd
  { 1, 680, 682, 10229, 10232 }, // 289 tc_6e7fa133
  { 1, 656, 658, 10232, 10235 }, // 290 tc_8772086c
  { 1, 658, 660, 10235, 10237 }, // 291 tc_b4416217
  { 1, 667, 670, 10237, 10241 }, // 292 tc_9f363d21
  { 1, 667, 670, 10241, 10246 }, // 293 tc_8e420e4d
  { 1, 714, 717, 10246, 10250 }, // 294 tc_7273323b
  { 1, 714, 717, 10250, 10255 }, // 295 tc_58d21193
  { 1, 658, 660, 10255, 10259 }, // 296 tc_71646d06
  { 1, 700, 702, 10259, 10262 }, // 297 tc_2c745bb8
  { 1, 705, 707, 10262, 10263 }, // 298 tc_b28e51aa
  { 1, 705, 707, 10263, 10265 }, // 299 tc_767c4e9d
  { 1, 717, 719, 10265, 10267 }, // 300 tc_e699ae41
  { 1, 717, 719, 10267, 10270 }, // 301 tc_a0dbea28
  { 1, 717, 719, 10270, 10273 }, // 302 tc_dd5b0695
  { 1, 717, 719, 10273, 10277 }, // 303 tc_3ad719fb
  { 1, 652, 653, 0, 0 }, // 304 tc_77f94a5e
  { 1, 655, 656, 0, 0 }, // 305 tc_55255f2b
  { 1, 655, 656, 10277, 10278 }, // 306 tc_0a43be35
  { 1, 652, 653, 10278, 10279 }, // 307 tc_b1ae5f67
  { 1, 652, 653, 10279, 10280 }, // 308 tc_d234b61a
  { 1, 652, 653, 10280, 10282 }, // 309 tc_2237d952
  { 1, 652, 653, 0, 0 }, // 310 tc_78f87ed3
  { 1, 652, 653, 10282, 10284 }, // 311 tc_a724463d
  { 1, 652, 653, 10284, 10286 }, // 312 tc_6fb52018
  { 1, 655, 656, 10286, 10288 }, // 313 tc_46c18ecf
  { 1, 654, 655, 10288, 10290 }, // 314 tc_9b20a062
  { 1, 654, 655, 10290, 10292 }, // 315 tc_5a222e89
  { 1, 654, 655, 10292, 10293 }, // 316 tc_0ba0d5da
  { 1, 654, 655, 10293, 10294 }, // 317 tc_7d6a2568
  { 1, 654, 655, 10294, 10296 }, // 318 tc_759e57be
  { 1, 654, 655, 10296, 10298 }, // 319 tc_139ef484
  { 1, 654, 655, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 655, 656, 0, 0 }, // 321 tc_7f58404a
  { 1, 652, 653, 0, 0 }, // 322 tc_b3d46584
  { 1, 655, 656, 10298, 10300 }, // 323 tc_d71ea8fa
  { 1, 655, 656, 10300, 10302 }, // 324 tc_6aa823ab
  { 1, 655, 656, 10302, 10304 }, // 325 tc_b2196a3f
  { 1, 655, 656, 10304, 10305 }, // 326 tc_2c3e17fc
  { 1, 655, 656, 10305, 10308 }, // 327 tc_27106296
  { 1, 652, 653, 10308, 10310 }, // 328 tc_a3070909
  { 1, 652, 653, 10310, 10312 }, // 329 tc_512b1653
  { 1, 655, 656, 10312, 10313 }, // 330 tc_d7718fbe
  { 1, 655, 656, 10313, 10316 }, // 331 tc_bb78483e
  { 1, 655, 656, 10316, 10317 }, // 332 tc_54f0cee2
  { 1, 655, 656, 10317, 10319 }, // 333 tc_28e55c6f
  { 1, 652, 653, 10319, 10320 }, // 334 tc_4bf903b0
  { 1, 652, 653, 10320, 10321 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV73[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 719, 720, 10321, 10324 }, // 1 tc_01d44cb2
  { 1, 720, 721, 10324, 10327 }, // 2 PSEUDO
  { 1, 720, 721, 10327, 10329 }, // 3 tc_c57d9f39
  { 1, 720, 721, 10329, 10333 }, // 4 tc_1c2c7a4a
  { 1, 720, 721, 10333, 10337 }, // 5 tc_442395f3
  { 1, 720, 721, 10337, 10340 }, // 6 tc_713b66bf
  { 1, 720, 721, 10340, 10343 }, // 7 tc_86173609
  { 1, 719, 720, 10343, 10346 }, // 8 tc_5da50c4b
  { 1, 719, 720, 10346, 10349 }, // 9 tc_4a55d03c
  { 1, 720, 721, 10349, 10352 }, // 10 tc_d33e5eee
  { 1, 719, 720, 10352, 10355 }, // 11 tc_651cbe02
  { 1, 721, 722, 10355, 10358 }, // 12 DUPLEX
  { 1, 722, 723, 10358, 10359 }, // 13 tc_ENDLOOP
  { 1, 720, 721, 0, 0 }, // 14 tc_23708a21
  { 1, 720, 721, 10359, 10361 }, // 15 tc_56a124a7
  { 1, 723, 724, 10361, 10363 }, // 16 tc_2f573607
  { 1, 723, 724, 10363, 10366 }, // 17 tc_53c851ab
  { 1, 724, 725, 10366, 10370 }, // 18 tc_fedb7e19
  { 1, 724, 725, 10370, 10373 }, // 19 tc_4222e6bf
  { 1, 724, 725, 10373, 10377 }, // 20 tc_075c8dd8
  { 1, 721, 722, 10377, 10380 }, // 21 tc_9bcfb2ee
  { 1, 721, 722, 10380, 10383 }, // 22 tc_158aa3f7
  { 1, 721, 722, 10383, 10386 }, // 23 tc_df5d53f9
  { 1, 721, 722, 10386, 10389 }, // 24 tc_14ab4f41
  { 1, 721, 722, 10389, 10390 }, // 25 tc_f38f92e1
  { 1, 721, 722, 10390, 10391 }, // 26 tc_1981450d
  { 1, 724, 725, 10391, 10393 }, // 27 tc_e9170fb7
  { 1, 721, 722, 10393, 10395 }, // 28 tc_40d64c94
  { 1, 724, 725, 10395, 10397 }, // 29 LD_tc_ld_SLOT01
  { 1, 719, 720, 10397, 10400 }, // 30 tc_38382228
  { 1, 719, 720, 10400, 10403 }, // 31 tc_c21d7447
  { 1, 719, 720, 10403, 10407 }, // 32 tc_7f8ae742
  { 1, 725, 726, 10407, 10410 }, // 33 tc_5a4b5e58
  { 1, 725, 726, 10410, 10414 }, // 34 tc_197dce51
  { 1, 719, 720, 10414, 10415 }, // 35 tc_44fffc58
  { 1, 724, 725, 10415, 10420 }, // 36 tc_5ceb2f9e
  { 1, 726, 728, 10420, 10423 }, // 37 tc_56c4f9fe
  { 1, 725, 726, 10423, 10425 }, // 38 tc_7476d766
  { 1, 724, 725, 10425, 10430 }, // 39 tc_b4dc7630
  { 1, 724, 725, 10430, 10434 }, // 40 tc_a2b365d2
  { 1, 723, 724, 10434, 10435 }, // 41 tc_60e324ff
  { 1, 728, 730, 10435, 10438 }, // 42 tc_db5555f3
  { 1, 730, 733, 10438, 10441 }, // 43 tc_c0749f3c
  { 1, 733, 735, 10441, 10444 }, // 44 PSEUDOM
  { 1, 726, 728, 10444, 10447 }, // 45 tc_3aacf4a8
  { 1, 735, 737, 10447, 10449 }, // 46 tc_c4edf264
  { 1, 737, 740, 10449, 10452 }, // 47 tc_c5dba46e
  { 1, 728, 730, 10452, 10456 }, // 48 tc_af25efd9
  { 1, 719, 720, 10456, 10459 }, // 49 tc_0dfac0a7
  { 1, 724, 725, 10459, 10463 }, // 50 tc_8035e91f
  { 1, 721, 722, 10463, 10467 }, // 51 tc_011e0e9d
  { 1, 724, 725, 10467, 10470 }, // 52 tc_ae5babd7
  { 1, 721, 722, 10470, 10473 }, // 53 tc_5deb5e47
  { 1, 719, 720, 10473, 10478 }, // 54 tc_bb831a7c
  { 1, 721, 722, 10478, 10482 }, // 55 tc_92240447
  { 1, 724, 725, 10482, 10485 }, // 56 tc_7c31e19a
  { 1, 724, 725, 10485, 10489 }, // 57 tc_d03278fd
  { 1, 724, 725, 10489, 10493 }, // 58 tc_65cbd974
  { 1, 721, 722, 10493, 10496 }, // 59 tc_934753bb
  { 1, 724, 725, 10496, 10499 }, // 60 ST_tc_st_SLOT01
  { 1, 740, 742, 10499, 10503 }, // 61 CVI_VA
  { 1, 735, 737, 10503, 10507 }, // 62 tc_f175e046
  { 1, 735, 737, 10507, 10512 }, // 63 tc_4942646a
  { 1, 726, 728, 10512, 10514 }, // 64 tc_0ec46cf9
  { 1, 728, 730, 10514, 10515 }, // 65 tc_718b5c53
  { 1, 742, 746, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 725, 726, 10515, 10517 }, // 67 tc_7dc63b5c
  { 1, 721, 722, 10517, 10518 }, // 68 tc_d45ba9cd
  { 1, 720, 721, 10518, 10521 }, // 69 tc_388f9897
  { 1, 720, 721, 10521, 10523 }, // 70 tc_9124c04f
  { 1, 720, 721, 10523, 10526 }, // 71 tc_4ac61d92
  { 1, 724, 725, 10526, 10528 }, // 72 tc_aee6250c
  { 1, 724, 725, 10528, 10531 }, // 73 tc_eed07714
  { 1, 724, 725, 10531, 10534 }, // 74 tc_74a42bda
  { 1, 724, 725, 10534, 10537 }, // 75 tc_a9edeffa
  { 1, 724, 725, 10537, 10540 }, // 76 tc_838c4d7a
  { 1, 719, 720, 10540, 10542 }, // 77 tc_d61dfdc3
  { 1, 719, 720, 10542, 10545 }, // 78 tc_8a825db2
  { 1, 719, 720, 10545, 10548 }, // 79 tc_f34c1c21
  { 1, 720, 721, 10548, 10551 }, // 80 tc_95a33176
  { 1, 719, 720, 10551, 10553 }, // 81 tc_9f6cd987
  { 1, 720, 721, 0, 0 }, // 82 tc_b837298f
  { 1, 720, 721, 10553, 10556 }, // 83 tc_8b5bd4f5
  { 1, 720, 721, 10556, 10559 }, // 84 tc_84a7500d
  { 1, 725, 726, 10559, 10561 }, // 85 tc_49fdfd4b
  { 1, 719, 720, 10561, 10564 }, // 86 tc_f098b237
  { 1, 719, 720, 10564, 10567 }, // 87 tc_20131976
  { 1, 719, 720, 10567, 10572 }, // 88 tc_1d41f8b7
  { 1, 719, 720, 10572, 10575 }, // 89 tc_a1297125
  { 1, 720, 721, 10575, 10576 }, // 90 tc_112d30d6
  { 1, 719, 720, 10576, 10579 }, // 91 tc_d68dca5c
  { 1, 719, 720, 10579, 10583 }, // 92 tc_788b1d09
  { 1, 719, 720, 10583, 10588 }, // 93 tc_38e0bae9
  { 1, 719, 720, 10588, 10591 }, // 94 tc_407e96f9
  { 1, 719, 720, 10591, 10595 }, // 95 tc_7401744f
  { 1, 719, 720, 10595, 10598 }, // 96 tc_9b3c0462
  { 1, 719, 720, 10598, 10600 }, // 97 tc_151bf368
  { 1, 720, 721, 10600, 10603 }, // 98 tc_9c52f549
  { 1, 719, 720, 10603, 10605 }, // 99 tc_55b33fda
  { 1, 719, 720, 10605, 10609 }, // 100 tc_6fc5dbea
  { 1, 725, 726, 10609, 10611 }, // 101 tc_3edca78f
  { 1, 719, 720, 10611, 10615 }, // 102 tc_a7a13fac
  { 1, 719, 720, 10615, 10617 }, // 103 tc_9783714b
  { 1, 719, 720, 10617, 10620 }, // 104 tc_f0e8e832
  { 1, 719, 720, 10620, 10622 }, // 105 tc_65279839
  { 1, 719, 720, 10622, 10626 }, // 106 tc_0a195f2c
  { 1, 719, 720, 10626, 10630 }, // 107 tc_01e1be3b
  { 1, 719, 720, 10630, 10633 }, // 108 tc_556f6577
  { 1, 719, 720, 10633, 10636 }, // 109 tc_02fe1c65
  { 1, 719, 720, 10636, 10640 }, // 110 tc_9e72dc89
  { 1, 719, 720, 10640, 10645 }, // 111 tc_9edb7c77
  { 1, 719, 720, 10645, 10648 }, // 112 tc_7f7f45f5
  { 1, 719, 720, 10648, 10651 }, // 113 tc_c20701f0
  { 1, 719, 720, 10651, 10655 }, // 114 tc_f7569068
  { 1, 725, 726, 10655, 10657 }, // 115 tc_fae9dfa5
  { 1, 725, 726, 10657, 10659 }, // 116 tc_6ae3426b
  { 1, 719, 720, 10659, 10661 }, // 117 tc_69bfb303
  { 1, 723, 724, 10661, 10662 }, // 118 tc_362b0be2
  { 1, 723, 724, 10662, 10664 }, // 119 tc_dc51281d
  { 1, 723, 724, 10664, 10665 }, // 120 tc_95f43c5e
  { 1, 720, 721, 10665, 10666 }, // 121 tc_decdde8a
  { 1, 720, 721, 10666, 10668 }, // 122 tc_eeda4109
  { 1, 720, 721, 10668, 10670 }, // 123 tc_711c805f
  { 1, 723, 724, 10670, 10672 }, // 124 tc_ed03645c
  { 1, 723, 724, 10672, 10674 }, // 125 tc_42ff66ba
  { 1, 725, 726, 10674, 10676 }, // 126 tc_57a55b54
  { 1, 723, 724, 10676, 10677 }, // 127 tc_f97707c1
  { 1, 725, 726, 10677, 10679 }, // 128 tc_1248597c
  { 1, 725, 726, 10679, 10681 }, // 129 tc_9406230a
  { 1, 723, 724, 10681, 10682 }, // 130 tc_d57d649c
  { 1, 725, 726, 10682, 10684 }, // 131 tc_4abdbdc6
  { 1, 725, 726, 10684, 10686 }, // 132 tc_6d861a95
  { 1, 723, 724, 0, 0 }, // 133 tc_b9bec29e
  { 1, 723, 724, 10686, 10687 }, // 134 tc_45f9d1be
  { 1, 723, 724, 0, 0 }, // 135 tc_33e7e673
  { 1, 721, 722, 10687, 10690 }, // 136 tc_24e109c7
  { 1, 720, 721, 10690, 10693 }, // 137 tc_9e27f2f9
  { 1, 721, 722, 10693, 10696 }, // 138 tc_f6e2aff9
  { 1, 720, 721, 10696, 10699 }, // 139 tc_24f426ab
  { 1, 721, 722, 10699, 10702 }, // 140 tc_975a4e54
  { 1, 719, 720, 10702, 10703 }, // 141 tc_e60def48
  { 1, 719, 720, 10703, 10706 }, // 142 tc_5502c366
  { 1, 721, 722, 10706, 10708 }, // 143 tc_7b9187d3
  { 1, 720, 721, 10708, 10710 }, // 144 tc_f999c66e
  { 1, 724, 725, 10710, 10715 }, // 145 tc_1c7522a8
  { 1, 724, 725, 10715, 10721 }, // 146 tc_76bb5435
  { 1, 724, 725, 10721, 10723 }, // 147 tc_8a6d0d94
  { 1, 721, 722, 10723, 10725 }, // 148 tc_2471c1c8
  { 1, 721, 722, 10725, 10727 }, // 149 tc_64b00d8a
  { 1, 724, 725, 10727, 10732 }, // 150 tc_5f2afaf7
  { 1, 724, 725, 10732, 10736 }, // 151 tc_ac65613f
  { 1, 724, 725, 10736, 10741 }, // 152 tc_a32e03e7
  { 1, 724, 725, 10741, 10744 }, // 153 tc_822c3c68
  { 1, 724, 725, 10744, 10748 }, // 154 tc_abfd9a6d
  { 1, 724, 725, 10748, 10752 }, // 155 tc_bf2ffc0f
  { 1, 721, 722, 10752, 10755 }, // 156 tc_ed3f8d2a
  { 1, 724, 725, 10755, 10758 }, // 157 tc_7c6d32e4
  { 1, 724, 725, 10758, 10763 }, // 158 tc_45791fb8
  { 1, 724, 725, 10763, 10768 }, // 159 tc_b7c4062a
  { 1, 724, 725, 10768, 10771 }, // 160 tc_5944960d
  { 1, 719, 720, 10771, 10775 }, // 161 tc_2c13e7f5
  { 1, 719, 720, 10775, 10779 }, // 162 tc_a154b476
  { 1, 719, 720, 10779, 10783 }, // 163 tc_a4e22bbd
  { 1, 719, 720, 10783, 10787 }, // 164 tc_503ce0f3
  { 1, 724, 725, 10787, 10789 }, // 165 tc_0655b949
  { 1, 721, 722, 10789, 10791 }, // 166 tc_6e20402a
  { 1, 721, 722, 10791, 10792 }, // 167 tc_db96aa6b
  { 1, 719, 720, 10792, 10794 }, // 168 tc_a7bdb22c
  { 1, 719, 720, 10794, 10797 }, // 169 tc_db596beb
  { 1, 719, 720, 10797, 10800 }, // 170 tc_a08b630b
  { 1, 719, 720, 10800, 10803 }, // 171 tc_1fcb8495
  { 1, 724, 725, 10803, 10808 }, // 172 tc_9edefe01
  { 1, 724, 725, 10808, 10813 }, // 173 tc_449acf79
  { 1, 721, 722, 10813, 10818 }, // 174 tc_ce59038e
  { 1, 721, 722, 10818, 10823 }, // 175 tc_f529831b
  { 1, 721, 722, 10823, 10828 }, // 176 tc_addc37a8
  { 1, 721, 722, 10828, 10831 }, // 177 tc_6f42bc60
  { 1, 721, 722, 10831, 10833 }, // 178 tc_7af3a37e
  { 1, 719, 720, 10833, 10835 }, // 179 tc_e3d699e3
  { 1, 724, 725, 10835, 10838 }, // 180 tc_ba9255a6
  { 1, 724, 725, 10838, 10843 }, // 181 tc_1fe4ab69
  { 1, 724, 725, 10843, 10846 }, // 182 tc_bb07f2c5
  { 1, 724, 725, 10846, 10851 }, // 183 tc_8e82e8ca
  { 1, 721, 722, 10851, 10854 }, // 184 tc_cfa0e29b
  { 1, 721, 722, 10854, 10859 }, // 185 tc_0a6c20ae
  { 1, 721, 722, 10859, 10862 }, // 186 tc_0fac1eb8
  { 1, 721, 722, 10862, 10867 }, // 187 tc_829d8a86
  { 1, 724, 725, 10867, 10871 }, // 188 tc_280f7fe1
  { 1, 724, 725, 10871, 10875 }, // 189 tc_887d1bb7
  { 1, 721, 722, 10875, 10879 }, // 190 tc_96ef76ef
  { 1, 721, 722, 10879, 10883 }, // 191 tc_55a9a350
  { 1, 719, 720, 10883, 10887 }, // 192 tc_f0cdeccf
  { 1, 719, 720, 10887, 10892 }, // 193 tc_a38c45dc
  { 1, 719, 720, 10892, 10894 }, // 194 tc_d3632d88
  { 1, 719, 720, 10894, 10898 }, // 195 tc_5e4cf0e8
  { 1, 719, 720, 10898, 10900 }, // 196 tc_ef921005
  { 1, 724, 725, 10900, 10903 }, // 197 tc_5b347363
  { 1, 724, 725, 10903, 10905 }, // 198 tc_3d14a17b
  { 1, 724, 725, 10905, 10906 }, // 199 tc_3fbf1042
  { 1, 724, 725, 10906, 10907 }, // 200 tc_63567288
  { 1, 724, 725, 10907, 10909 }, // 201 tc_59a7822c
  { 1, 724, 725, 0, 0 }, // 202 tc_937dd41c
  { 1, 721, 722, 0, 0 }, // 203 tc_a4ee89db
  { 1, 721, 722, 0, 0 }, // 204 tc_c818ff7f
  { 1, 721, 722, 10909, 10910 }, // 205 tc_1242dc2a
  { 1, 724, 725, 10910, 10912 }, // 206 tc_44d5a428
  { 1, 746, 748, 10912, 10915 }, // 207 tc_540c3da3
  { 1, 735, 737, 10915, 10919 }, // 208 tc_b091f1c6
  { 1, 748, 750, 10919, 10921 }, // 209 tc_5bf8afbb
  { 1, 750, 752, 10921, 10925 }, // 210 tc_2b4c548e
  { 1, 750, 752, 10925, 10930 }, // 211 tc_bb599486
  { 1, 752, 756, 10930, 10933 }, // 212 tc_a7e6707d
  { 1, 752, 756, 10933, 10937 }, // 213 tc_3c56e5ce
  { 1, 730, 733, 10937, 10941 }, // 214 tc_abe8c3b2
  { 1, 730, 733, 10941, 10946 }, // 215 tc_453fe68d
  { 1, 730, 733, 10946, 10950 }, // 216 tc_1ba8a0cd
  { 1, 756, 758, 10950, 10953 }, // 217 tc_52447ecc
  { 1, 756, 758, 10953, 10957 }, // 218 tc_3904b926
  { 1, 756, 758, 10957, 10962 }, // 219 tc_b9db8205
  { 1, 756, 758, 10962, 10966 }, // 220 tc_663c80a7
  { 1, 758, 762, 10966, 10969 }, // 221 tc_f21e8abb
  { 1, 758, 762, 10969, 10973 }, // 222 tc_131f1c81
  { 1, 758, 762, 10973, 10978 }, // 223 tc_c7039829
  { 1, 758, 762, 10978, 10982 }, // 224 tc_e2d2e9e5
  { 1, 762, 764, 10982, 10985 }, // 225 tc_ab23f776
  { 1, 762, 764, 10985, 10989 }, // 226 tc_7177e272
  { 1, 762, 764, 10989, 10994 }, // 227 tc_e99d4c2e
  { 1, 762, 764, 10994, 10998 }, // 228 tc_6942b6e0
  { 1, 737, 740, 10998, 11002 }, // 229 tc_a02a10a8
  { 1, 737, 740, 11002, 11007 }, // 230 tc_54a0dc47
  { 1, 737, 740, 11007, 11011 }, // 231 tc_447d9895
  { 1, 737, 740, 11011, 11016 }, // 232 tc_191381c1
  { 1, 737, 740, 11016, 11020 }, // 233 tc_3e2aaafc
  { 1, 762, 764, 11020, 11022 }, // 234 tc_3ce09744
  { 1, 762, 764, 11022, 11025 }, // 235 tc_20a4bbec
  { 1, 735, 737, 11025, 11027 }, // 236 tc_5cdf8c84
  { 1, 764, 766, 11027, 11029 }, // 237 tc_2a698a03
  { 1, 735, 737, 11029, 11032 }, // 238 tc_c127de3a
  { 1, 766, 768, 11032, 11035 }, // 239 tc_05ca8cfd
  { 1, 750, 752, 11035, 11038 }, // 240 tc_d8287c14
  { 1, 726, 728, 11038, 11042 }, // 241 tc_257f6f7c
  { 1, 726, 728, 11042, 11047 }, // 242 tc_7e6a3e89
  { 1, 726, 728, 11047, 11051 }, // 243 tc_e35c1e93
  { 1, 750, 752, 11051, 11055 }, // 244 tc_08a4f1b6
  { 1, 726, 728, 11055, 11059 }, // 245 tc_57a4709c
  { 1, 748, 750, 11059, 11063 }, // 246 tc_56e64202
  { 1, 735, 737, 11063, 11066 }, // 247 tc_ac4046bc
  { 1, 735, 737, 11066, 11070 }, // 248 tc_2e8f5f6e
  { 1, 766, 768, 11070, 11073 }, // 249 tc_7417e785
  { 1, 766, 768, 11073, 11077 }, // 250 tc_309dbb4f
  { 1, 768, 770, 11077, 11081 }, // 251 tc_df80eeb0
  { 1, 766, 768, 11081, 11085 }, // 252 tc_16ff9ef8
  { 1, 720, 721, 11085, 11087 }, // 253 tc_e2fdd6e6
  { 1, 766, 768, 11087, 11089 }, // 254 tc_51d0ecc3
  { 1, 720, 721, 11089, 11092 }, // 255 tc_531b383c
  { 1, 768, 770, 11092, 11094 }, // 256 tc_04da405a
  { 1, 735, 737, 11094, 11096 }, // 257 tc_3c8c15d0
  { 1, 750, 752, 11096, 11098 }, // 258 tc_0afc8be9
  { 1, 768, 770, 11098, 11103 }, // 259 tc_561aaa58
  { 1, 748, 750, 11103, 11105 }, // 260 tc_946013d8
  { 1, 748, 750, 11105, 11108 }, // 261 tc_46d6c3e0
  { 1, 768, 770, 11108, 11112 }, // 262 tc_87adc037
  { 1, 735, 737, 11112, 11116 }, // 263 tc_a19b9305
  { 1, 735, 737, 11116, 11119 }, // 264 tc_649072c2
  { 1, 750, 752, 11119, 11122 }, // 265 tc_0b04c6c7
  { 1, 750, 752, 11122, 11126 }, // 266 tc_660769f1
  { 1, 735, 737, 11126, 11129 }, // 267 tc_dcca380f
  { 1, 735, 737, 11129, 11133 }, // 268 tc_72e2b393
  { 1, 735, 737, 11133, 11136 }, // 269 tc_73efe966
  { 1, 735, 737, 11136, 11139 }, // 270 tc_cda936da
  { 1, 730, 733, 11139, 11142 }, // 271 tc_a28f32b5
  { 1, 730, 733, 11142, 11146 }, // 272 tc_7d68d5c2
  { 1, 770, 773, 11146, 11149 }, // 273 tc_7095ecba
  { 1, 770, 773, 11149, 11153 }, // 274 tc_a69eeee1
  { 1, 773, 775, 0, 0 }, // 275 tc_1381a97c
  { 1, 773, 775, 11153, 11154 }, // 276 tc_e3f68a46
  { 1, 775, 777, 11154, 11157 }, // 277 tc_f1de44ef
  { 1, 768, 770, 11157, 11162 }, // 278 tc_9d1dc972
  { 1, 775, 777, 11162, 11166 }, // 279 tc_90bcc1db
  { 1, 777, 780, 11166, 11169 }, // 280 tc_cd94bfe0
  { 1, 777, 780, 11169, 11173 }, // 281 tc_15fdf750
  { 1, 750, 752, 11173, 11177 }, // 282 tc_1ad8a370
  { 1, 750, 752, 11177, 11182 }, // 283 tc_e675c45a
  { 1, 735, 737, 11182, 11186 }, // 284 tc_37820f4c
  { 1, 780, 782, 11186, 11189 }, // 285 tc_61bf7c03
  { 1, 780, 782, 11189, 11193 }, // 286 tc_933f2b39
  { 1, 780, 782, 11193, 11197 }, // 287 tc_26a377fe
  { 1, 780, 782, 11197, 11202 }, // 288 tc_2d4051cd
  { 1, 748, 750, 11202, 11205 }, // 289 tc_6e7fa133
  { 1, 726, 728, 11205, 11208 }, // 290 tc_8772086c
  { 1, 728, 730, 11208, 11210 }, // 291 tc_b4416217
  { 1, 737, 740, 11210, 11214 }, // 292 tc_9f363d21
  { 1, 737, 740, 11214, 11219 }, // 293 tc_8e420e4d
  { 1, 782, 785, 11219, 11223 }, // 294 tc_7273323b
  { 1, 782, 785, 11223, 11228 }, // 295 tc_58d21193
  { 1, 728, 730, 11228, 11232 }, // 296 tc_71646d06
  { 1, 768, 770, 11232, 11235 }, // 297 tc_2c745bb8
  { 1, 773, 775, 11235, 11236 }, // 298 tc_b28e51aa
  { 1, 773, 775, 11236, 11238 }, // 299 tc_767c4e9d
  { 1, 785, 787, 11238, 11240 }, // 300 tc_e699ae41
  { 1, 785, 787, 11240, 11243 }, // 301 tc_a0dbea28
  { 1, 785, 787, 11243, 11246 }, // 302 tc_dd5b0695
  { 1, 785, 787, 11246, 11250 }, // 303 tc_3ad719fb
  { 1, 721, 722, 0, 0 }, // 304 tc_77f94a5e
  { 1, 725, 726, 0, 0 }, // 305 tc_55255f2b
  { 1, 725, 726, 11250, 11251 }, // 306 tc_0a43be35
  { 1, 721, 722, 11251, 11252 }, // 307 tc_b1ae5f67
  { 1, 721, 722, 11252, 11253 }, // 308 tc_d234b61a
  { 1, 721, 722, 11253, 11255 }, // 309 tc_2237d952
  { 1, 721, 722, 0, 0 }, // 310 tc_78f87ed3
  { 1, 721, 722, 11255, 11257 }, // 311 tc_a724463d
  { 1, 721, 722, 11257, 11259 }, // 312 tc_6fb52018
  { 1, 725, 726, 11259, 11261 }, // 313 tc_46c18ecf
  { 1, 723, 724, 11261, 11263 }, // 314 tc_9b20a062
  { 1, 723, 724, 11263, 11265 }, // 315 tc_5a222e89
  { 1, 723, 724, 11265, 11266 }, // 316 tc_0ba0d5da
  { 1, 723, 724, 11266, 11267 }, // 317 tc_7d6a2568
  { 1, 723, 724, 11267, 11269 }, // 318 tc_759e57be
  { 1, 723, 724, 11269, 11271 }, // 319 tc_139ef484
  { 1, 723, 724, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 725, 726, 0, 0 }, // 321 tc_7f58404a
  { 1, 721, 722, 0, 0 }, // 322 tc_b3d46584
  { 1, 725, 726, 11271, 11273 }, // 323 tc_d71ea8fa
  { 1, 725, 726, 11273, 11275 }, // 324 tc_6aa823ab
  { 1, 725, 726, 11275, 11277 }, // 325 tc_b2196a3f
  { 1, 725, 726, 11277, 11278 }, // 326 tc_2c3e17fc
  { 1, 725, 726, 11278, 11281 }, // 327 tc_27106296
  { 1, 721, 722, 11281, 11283 }, // 328 tc_a3070909
  { 1, 721, 722, 11283, 11285 }, // 329 tc_512b1653
  { 1, 725, 726, 11285, 11286 }, // 330 tc_d7718fbe
  { 1, 725, 726, 11286, 11289 }, // 331 tc_bb78483e
  { 1, 725, 726, 11289, 11290 }, // 332 tc_54f0cee2
  { 1, 725, 726, 11290, 11292 }, // 333 tc_28e55c6f
  { 1, 721, 722, 11292, 11293 }, // 334 tc_4bf903b0
  { 1, 721, 722, 11293, 11294 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV75[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 787, 788, 11294, 11297 }, // 1 tc_01d44cb2
  { 1, 788, 789, 11297, 11300 }, // 2 PSEUDO
  { 1, 788, 789, 11300, 11302 }, // 3 tc_c57d9f39
  { 1, 788, 789, 11302, 11306 }, // 4 tc_1c2c7a4a
  { 1, 788, 789, 11306, 11310 }, // 5 tc_442395f3
  { 1, 788, 789, 11310, 11313 }, // 6 tc_713b66bf
  { 1, 788, 789, 11313, 11316 }, // 7 tc_86173609
  { 1, 787, 788, 11316, 11319 }, // 8 tc_5da50c4b
  { 1, 787, 788, 11319, 11322 }, // 9 tc_4a55d03c
  { 1, 788, 789, 11322, 11325 }, // 10 tc_d33e5eee
  { 1, 787, 788, 11325, 11328 }, // 11 tc_651cbe02
  { 1, 789, 790, 11328, 11331 }, // 12 DUPLEX
  { 1, 790, 791, 11331, 11332 }, // 13 tc_ENDLOOP
  { 1, 788, 789, 0, 0 }, // 14 tc_23708a21
  { 1, 788, 789, 11332, 11334 }, // 15 tc_56a124a7
  { 1, 791, 792, 11334, 11336 }, // 16 tc_2f573607
  { 1, 791, 792, 11336, 11339 }, // 17 tc_53c851ab
  { 1, 792, 793, 11339, 11343 }, // 18 tc_fedb7e19
  { 1, 792, 793, 11343, 11346 }, // 19 tc_4222e6bf
  { 1, 792, 793, 11346, 11350 }, // 20 tc_075c8dd8
  { 1, 789, 790, 11350, 11353 }, // 21 tc_9bcfb2ee
  { 1, 789, 790, 11353, 11356 }, // 22 tc_158aa3f7
  { 1, 789, 790, 11356, 11359 }, // 23 tc_df5d53f9
  { 1, 789, 790, 11359, 11362 }, // 24 tc_14ab4f41
  { 1, 789, 790, 11362, 11363 }, // 25 tc_f38f92e1
  { 1, 789, 790, 11363, 11364 }, // 26 tc_1981450d
  { 1, 792, 793, 11364, 11366 }, // 27 tc_e9170fb7
  { 1, 789, 790, 11366, 11368 }, // 28 tc_40d64c94
  { 1, 792, 793, 11368, 11370 }, // 29 LD_tc_ld_SLOT01
  { 1, 787, 788, 11370, 11373 }, // 30 tc_38382228
  { 1, 787, 788, 11373, 11376 }, // 31 tc_c21d7447
  { 1, 787, 788, 11376, 11380 }, // 32 tc_7f8ae742
  { 1, 793, 794, 11380, 11383 }, // 33 tc_5a4b5e58
  { 1, 793, 794, 11383, 11387 }, // 34 tc_197dce51
  { 1, 787, 788, 11387, 11388 }, // 35 tc_44fffc58
  { 1, 792, 793, 11388, 11393 }, // 36 tc_5ceb2f9e
  { 1, 794, 796, 11393, 11396 }, // 37 tc_56c4f9fe
  { 1, 793, 794, 11396, 11398 }, // 38 tc_7476d766
  { 1, 792, 793, 11398, 11403 }, // 39 tc_b4dc7630
  { 1, 792, 793, 11403, 11407 }, // 40 tc_a2b365d2
  { 1, 791, 792, 11407, 11408 }, // 41 tc_60e324ff
  { 1, 796, 798, 11408, 11411 }, // 42 tc_db5555f3
  { 1, 798, 801, 11411, 11414 }, // 43 tc_c0749f3c
  { 1, 801, 803, 11414, 11417 }, // 44 PSEUDOM
  { 1, 794, 796, 11417, 11420 }, // 45 tc_3aacf4a8
  { 1, 803, 805, 11420, 11422 }, // 46 tc_c4edf264
  { 1, 805, 808, 11422, 11425 }, // 47 tc_c5dba46e
  { 1, 796, 798, 11425, 11429 }, // 48 tc_af25efd9
  { 1, 787, 788, 11429, 11432 }, // 49 tc_0dfac0a7
  { 1, 792, 793, 11432, 11436 }, // 50 tc_8035e91f
  { 1, 789, 790, 11436, 11440 }, // 51 tc_011e0e9d
  { 1, 792, 793, 11440, 11443 }, // 52 tc_ae5babd7
  { 1, 789, 790, 11443, 11446 }, // 53 tc_5deb5e47
  { 1, 787, 788, 11446, 11451 }, // 54 tc_bb831a7c
  { 1, 789, 790, 11451, 11455 }, // 55 tc_92240447
  { 1, 792, 793, 11455, 11458 }, // 56 tc_7c31e19a
  { 1, 792, 793, 11458, 11462 }, // 57 tc_d03278fd
  { 1, 792, 793, 11462, 11466 }, // 58 tc_65cbd974
  { 1, 789, 790, 11466, 11469 }, // 59 tc_934753bb
  { 1, 792, 793, 11469, 11472 }, // 60 ST_tc_st_SLOT01
  { 1, 808, 810, 11472, 11476 }, // 61 CVI_VA
  { 1, 803, 805, 11476, 11480 }, // 62 tc_f175e046
  { 1, 803, 805, 11480, 11485 }, // 63 tc_4942646a
  { 1, 794, 796, 11485, 11487 }, // 64 tc_0ec46cf9
  { 1, 796, 798, 11487, 11488 }, // 65 tc_718b5c53
  { 1, 810, 814, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 793, 794, 11488, 11490 }, // 67 tc_7dc63b5c
  { 1, 789, 790, 11490, 11491 }, // 68 tc_d45ba9cd
  { 1, 788, 789, 11491, 11494 }, // 69 tc_388f9897
  { 1, 788, 789, 11494, 11496 }, // 70 tc_9124c04f
  { 1, 788, 789, 11496, 11499 }, // 71 tc_4ac61d92
  { 1, 792, 793, 11499, 11501 }, // 72 tc_aee6250c
  { 1, 792, 793, 11501, 11504 }, // 73 tc_eed07714
  { 1, 792, 793, 11504, 11507 }, // 74 tc_74a42bda
  { 1, 792, 793, 11507, 11510 }, // 75 tc_a9edeffa
  { 1, 792, 793, 11510, 11513 }, // 76 tc_838c4d7a
  { 1, 787, 788, 11513, 11515 }, // 77 tc_d61dfdc3
  { 1, 787, 788, 11515, 11518 }, // 78 tc_8a825db2
  { 1, 787, 788, 11518, 11521 }, // 79 tc_f34c1c21
  { 1, 788, 789, 11521, 11524 }, // 80 tc_95a33176
  { 1, 787, 788, 11524, 11526 }, // 81 tc_9f6cd987
  { 1, 788, 789, 0, 0 }, // 82 tc_b837298f
  { 1, 788, 789, 11526, 11529 }, // 83 tc_8b5bd4f5
  { 1, 788, 789, 11529, 11532 }, // 84 tc_84a7500d
  { 1, 793, 794, 11532, 11534 }, // 85 tc_49fdfd4b
  { 1, 787, 788, 11534, 11537 }, // 86 tc_f098b237
  { 1, 787, 788, 11537, 11540 }, // 87 tc_20131976
  { 1, 787, 788, 11540, 11545 }, // 88 tc_1d41f8b7
  { 1, 787, 788, 11545, 11548 }, // 89 tc_a1297125
  { 1, 788, 789, 11548, 11549 }, // 90 tc_112d30d6
  { 1, 787, 788, 11549, 11552 }, // 91 tc_d68dca5c
  { 1, 787, 788, 11552, 11556 }, // 92 tc_788b1d09
  { 1, 787, 788, 11556, 11561 }, // 93 tc_38e0bae9
  { 1, 787, 788, 11561, 11564 }, // 94 tc_407e96f9
  { 1, 787, 788, 11564, 11568 }, // 95 tc_7401744f
  { 1, 787, 788, 11568, 11571 }, // 96 tc_9b3c0462
  { 1, 787, 788, 11571, 11573 }, // 97 tc_151bf368
  { 1, 788, 789, 11573, 11576 }, // 98 tc_9c52f549
  { 1, 787, 788, 11576, 11578 }, // 99 tc_55b33fda
  { 1, 787, 788, 11578, 11582 }, // 100 tc_6fc5dbea
  { 1, 793, 794, 11582, 11584 }, // 101 tc_3edca78f
  { 1, 787, 788, 11584, 11588 }, // 102 tc_a7a13fac
  { 1, 787, 788, 11588, 11590 }, // 103 tc_9783714b
  { 1, 787, 788, 11590, 11593 }, // 104 tc_f0e8e832
  { 1, 787, 788, 11593, 11595 }, // 105 tc_65279839
  { 1, 787, 788, 11595, 11599 }, // 106 tc_0a195f2c
  { 1, 787, 788, 11599, 11603 }, // 107 tc_01e1be3b
  { 1, 787, 788, 11603, 11606 }, // 108 tc_556f6577
  { 1, 787, 788, 11606, 11609 }, // 109 tc_02fe1c65
  { 1, 787, 788, 11609, 11613 }, // 110 tc_9e72dc89
  { 1, 787, 788, 11613, 11618 }, // 111 tc_9edb7c77
  { 1, 787, 788, 11618, 11621 }, // 112 tc_7f7f45f5
  { 1, 787, 788, 11621, 11624 }, // 113 tc_c20701f0
  { 1, 787, 788, 11624, 11628 }, // 114 tc_f7569068
  { 1, 793, 794, 11628, 11630 }, // 115 tc_fae9dfa5
  { 1, 793, 794, 11630, 11632 }, // 116 tc_6ae3426b
  { 1, 787, 788, 11632, 11634 }, // 117 tc_69bfb303
  { 1, 791, 792, 11634, 11635 }, // 118 tc_362b0be2
  { 1, 791, 792, 11635, 11637 }, // 119 tc_dc51281d
  { 1, 791, 792, 11637, 11638 }, // 120 tc_95f43c5e
  { 1, 788, 789, 11638, 11639 }, // 121 tc_decdde8a
  { 1, 788, 789, 11639, 11641 }, // 122 tc_eeda4109
  { 1, 788, 789, 11641, 11643 }, // 123 tc_711c805f
  { 1, 791, 792, 11643, 11645 }, // 124 tc_ed03645c
  { 1, 791, 792, 11645, 11647 }, // 125 tc_42ff66ba
  { 1, 793, 794, 11647, 11649 }, // 126 tc_57a55b54
  { 1, 791, 792, 11649, 11650 }, // 127 tc_f97707c1
  { 1, 793, 794, 11650, 11652 }, // 128 tc_1248597c
  { 1, 793, 794, 11652, 11654 }, // 129 tc_9406230a
  { 1, 791, 792, 11654, 11655 }, // 130 tc_d57d649c
  { 1, 793, 794, 11655, 11657 }, // 131 tc_4abdbdc6
  { 1, 793, 794, 11657, 11659 }, // 132 tc_6d861a95
  { 1, 791, 792, 0, 0 }, // 133 tc_b9bec29e
  { 1, 791, 792, 11659, 11660 }, // 134 tc_45f9d1be
  { 1, 791, 792, 0, 0 }, // 135 tc_33e7e673
  { 1, 789, 790, 11660, 11663 }, // 136 tc_24e109c7
  { 1, 788, 789, 11663, 11666 }, // 137 tc_9e27f2f9
  { 1, 789, 790, 11666, 11669 }, // 138 tc_f6e2aff9
  { 1, 788, 789, 11669, 11672 }, // 139 tc_24f426ab
  { 1, 789, 790, 11672, 11675 }, // 140 tc_975a4e54
  { 1, 787, 788, 11675, 11676 }, // 141 tc_e60def48
  { 1, 787, 788, 11676, 11679 }, // 142 tc_5502c366
  { 1, 789, 790, 11679, 11681 }, // 143 tc_7b9187d3
  { 1, 788, 789, 11681, 11683 }, // 144 tc_f999c66e
  { 1, 792, 793, 11683, 11688 }, // 145 tc_1c7522a8
  { 1, 792, 793, 11688, 11694 }, // 146 tc_76bb5435
  { 1, 792, 793, 11694, 11696 }, // 147 tc_8a6d0d94
  { 1, 789, 790, 11696, 11698 }, // 148 tc_2471c1c8
  { 1, 789, 790, 11698, 11700 }, // 149 tc_64b00d8a
  { 1, 792, 793, 11700, 11705 }, // 150 tc_5f2afaf7
  { 1, 792, 793, 11705, 11709 }, // 151 tc_ac65613f
  { 1, 792, 793, 11709, 11714 }, // 152 tc_a32e03e7
  { 1, 792, 793, 11714, 11717 }, // 153 tc_822c3c68
  { 1, 792, 793, 11717, 11721 }, // 154 tc_abfd9a6d
  { 1, 792, 793, 11721, 11725 }, // 155 tc_bf2ffc0f
  { 1, 789, 790, 11725, 11728 }, // 156 tc_ed3f8d2a
  { 1, 792, 793, 11728, 11731 }, // 157 tc_7c6d32e4
  { 1, 792, 793, 11731, 11736 }, // 158 tc_45791fb8
  { 1, 792, 793, 11736, 11741 }, // 159 tc_b7c4062a
  { 1, 792, 793, 11741, 11744 }, // 160 tc_5944960d
  { 1, 787, 788, 11744, 11748 }, // 161 tc_2c13e7f5
  { 1, 787, 788, 11748, 11752 }, // 162 tc_a154b476
  { 1, 787, 788, 11752, 11756 }, // 163 tc_a4e22bbd
  { 1, 787, 788, 11756, 11760 }, // 164 tc_503ce0f3
  { 1, 792, 793, 11760, 11762 }, // 165 tc_0655b949
  { 1, 789, 790, 11762, 11764 }, // 166 tc_6e20402a
  { 1, 789, 790, 11764, 11765 }, // 167 tc_db96aa6b
  { 1, 787, 788, 11765, 11767 }, // 168 tc_a7bdb22c
  { 1, 787, 788, 11767, 11770 }, // 169 tc_db596beb
  { 1, 787, 788, 11770, 11773 }, // 170 tc_a08b630b
  { 1, 787, 788, 11773, 11776 }, // 171 tc_1fcb8495
  { 1, 792, 793, 11776, 11781 }, // 172 tc_9edefe01
  { 1, 792, 793, 11781, 11786 }, // 173 tc_449acf79
  { 1, 789, 790, 11786, 11791 }, // 174 tc_ce59038e
  { 1, 789, 790, 11791, 11796 }, // 175 tc_f529831b
  { 1, 789, 790, 11796, 11801 }, // 176 tc_addc37a8
  { 1, 789, 790, 11801, 11804 }, // 177 tc_6f42bc60
  { 1, 789, 790, 11804, 11806 }, // 178 tc_7af3a37e
  { 1, 787, 788, 11806, 11808 }, // 179 tc_e3d699e3
  { 1, 792, 793, 11808, 11811 }, // 180 tc_ba9255a6
  { 1, 792, 793, 11811, 11816 }, // 181 tc_1fe4ab69
  { 1, 792, 793, 11816, 11819 }, // 182 tc_bb07f2c5
  { 1, 792, 793, 11819, 11824 }, // 183 tc_8e82e8ca
  { 1, 789, 790, 11824, 11827 }, // 184 tc_cfa0e29b
  { 1, 789, 790, 11827, 11832 }, // 185 tc_0a6c20ae
  { 1, 789, 790, 11832, 11835 }, // 186 tc_0fac1eb8
  { 1, 789, 790, 11835, 11840 }, // 187 tc_829d8a86
  { 1, 792, 793, 11840, 11844 }, // 188 tc_280f7fe1
  { 1, 792, 793, 11844, 11848 }, // 189 tc_887d1bb7
  { 1, 789, 790, 11848, 11852 }, // 190 tc_96ef76ef
  { 1, 789, 790, 11852, 11856 }, // 191 tc_55a9a350
  { 1, 787, 788, 11856, 11860 }, // 192 tc_f0cdeccf
  { 1, 787, 788, 11860, 11865 }, // 193 tc_a38c45dc
  { 1, 787, 788, 11865, 11867 }, // 194 tc_d3632d88
  { 1, 787, 788, 11867, 11871 }, // 195 tc_5e4cf0e8
  { 1, 787, 788, 11871, 11873 }, // 196 tc_ef921005
  { 1, 792, 793, 11873, 11876 }, // 197 tc_5b347363
  { 1, 792, 793, 11876, 11878 }, // 198 tc_3d14a17b
  { 1, 792, 793, 11878, 11879 }, // 199 tc_3fbf1042
  { 1, 792, 793, 11879, 11880 }, // 200 tc_63567288
  { 1, 792, 793, 11880, 11882 }, // 201 tc_59a7822c
  { 1, 792, 793, 0, 0 }, // 202 tc_937dd41c
  { 1, 789, 790, 0, 0 }, // 203 tc_a4ee89db
  { 1, 789, 790, 0, 0 }, // 204 tc_c818ff7f
  { 1, 789, 790, 11882, 11883 }, // 205 tc_1242dc2a
  { 1, 792, 793, 11883, 11885 }, // 206 tc_44d5a428
  { 1, 814, 816, 11885, 11888 }, // 207 tc_540c3da3
  { 1, 803, 805, 11888, 11892 }, // 208 tc_b091f1c6
  { 1, 816, 818, 11892, 11894 }, // 209 tc_5bf8afbb
  { 1, 818, 820, 11894, 11898 }, // 210 tc_2b4c548e
  { 1, 818, 820, 11898, 11903 }, // 211 tc_bb599486
  { 1, 820, 824, 11903, 11906 }, // 212 tc_a7e6707d
  { 1, 820, 824, 11906, 11910 }, // 213 tc_3c56e5ce
  { 1, 798, 801, 11910, 11914 }, // 214 tc_abe8c3b2
  { 1, 798, 801, 11914, 11919 }, // 215 tc_453fe68d
  { 1, 798, 801, 11919, 11923 }, // 216 tc_1ba8a0cd
  { 1, 824, 826, 11923, 11926 }, // 217 tc_52447ecc
  { 1, 824, 826, 11926, 11930 }, // 218 tc_3904b926
  { 1, 824, 826, 11930, 11935 }, // 219 tc_b9db8205
  { 1, 824, 826, 11935, 11939 }, // 220 tc_663c80a7
  { 1, 826, 830, 11939, 11942 }, // 221 tc_f21e8abb
  { 1, 826, 830, 11942, 11946 }, // 222 tc_131f1c81
  { 1, 826, 830, 11946, 11951 }, // 223 tc_c7039829
  { 1, 826, 830, 11951, 11955 }, // 224 tc_e2d2e9e5
  { 1, 830, 832, 11955, 11958 }, // 225 tc_ab23f776
  { 1, 830, 832, 11958, 11962 }, // 226 tc_7177e272
  { 1, 830, 832, 11962, 11967 }, // 227 tc_e99d4c2e
  { 1, 830, 832, 11967, 11971 }, // 228 tc_6942b6e0
  { 1, 805, 808, 11971, 11975 }, // 229 tc_a02a10a8
  { 1, 805, 808, 11975, 11980 }, // 230 tc_54a0dc47
  { 1, 805, 808, 11980, 11984 }, // 231 tc_447d9895
  { 1, 805, 808, 11984, 11989 }, // 232 tc_191381c1
  { 1, 805, 808, 11989, 11993 }, // 233 tc_3e2aaafc
  { 1, 830, 832, 11993, 11995 }, // 234 tc_3ce09744
  { 1, 830, 832, 11995, 11998 }, // 235 tc_20a4bbec
  { 1, 803, 805, 11998, 12000 }, // 236 tc_5cdf8c84
  { 1, 832, 834, 12000, 12002 }, // 237 tc_2a698a03
  { 1, 803, 805, 12002, 12005 }, // 238 tc_c127de3a
  { 1, 834, 836, 12005, 12008 }, // 239 tc_05ca8cfd
  { 1, 818, 820, 12008, 12011 }, // 240 tc_d8287c14
  { 1, 794, 796, 12011, 12015 }, // 241 tc_257f6f7c
  { 1, 794, 796, 12015, 12020 }, // 242 tc_7e6a3e89
  { 1, 794, 796, 12020, 12024 }, // 243 tc_e35c1e93
  { 1, 818, 820, 12024, 12028 }, // 244 tc_08a4f1b6
  { 1, 794, 796, 12028, 12032 }, // 245 tc_57a4709c
  { 1, 816, 818, 12032, 12036 }, // 246 tc_56e64202
  { 1, 803, 805, 12036, 12039 }, // 247 tc_ac4046bc
  { 1, 803, 805, 12039, 12043 }, // 248 tc_2e8f5f6e
  { 1, 834, 836, 12043, 12046 }, // 249 tc_7417e785
  { 1, 834, 836, 12046, 12050 }, // 250 tc_309dbb4f
  { 1, 836, 838, 12050, 12054 }, // 251 tc_df80eeb0
  { 1, 834, 836, 12054, 12058 }, // 252 tc_16ff9ef8
  { 1, 788, 789, 12058, 12060 }, // 253 tc_e2fdd6e6
  { 1, 834, 836, 12060, 12062 }, // 254 tc_51d0ecc3
  { 1, 788, 789, 12062, 12065 }, // 255 tc_531b383c
  { 1, 836, 838, 12065, 12067 }, // 256 tc_04da405a
  { 1, 803, 805, 12067, 12069 }, // 257 tc_3c8c15d0
  { 1, 818, 820, 12069, 12071 }, // 258 tc_0afc8be9
  { 1, 836, 838, 12071, 12076 }, // 259 tc_561aaa58
  { 1, 816, 818, 12076, 12078 }, // 260 tc_946013d8
  { 1, 816, 818, 12078, 12081 }, // 261 tc_46d6c3e0
  { 1, 836, 838, 12081, 12085 }, // 262 tc_87adc037
  { 1, 803, 805, 12085, 12089 }, // 263 tc_a19b9305
  { 1, 803, 805, 12089, 12092 }, // 264 tc_649072c2
  { 1, 818, 820, 12092, 12095 }, // 265 tc_0b04c6c7
  { 1, 818, 820, 12095, 12099 }, // 266 tc_660769f1
  { 1, 803, 805, 12099, 12102 }, // 267 tc_dcca380f
  { 1, 803, 805, 12102, 12106 }, // 268 tc_72e2b393
  { 1, 803, 805, 12106, 12109 }, // 269 tc_73efe966
  { 1, 803, 805, 12109, 12112 }, // 270 tc_cda936da
  { 1, 798, 801, 12112, 12115 }, // 271 tc_a28f32b5
  { 1, 798, 801, 12115, 12119 }, // 272 tc_7d68d5c2
  { 1, 838, 841, 12119, 12122 }, // 273 tc_7095ecba
  { 1, 838, 841, 12122, 12126 }, // 274 tc_a69eeee1
  { 1, 841, 843, 0, 0 }, // 275 tc_1381a97c
  { 1, 841, 843, 12126, 12127 }, // 276 tc_e3f68a46
  { 1, 843, 845, 12127, 12130 }, // 277 tc_f1de44ef
  { 1, 836, 838, 12130, 12135 }, // 278 tc_9d1dc972
  { 1, 843, 845, 12135, 12139 }, // 279 tc_90bcc1db
  { 1, 845, 848, 12139, 12142 }, // 280 tc_cd94bfe0
  { 1, 845, 848, 12142, 12146 }, // 281 tc_15fdf750
  { 1, 818, 820, 12146, 12150 }, // 282 tc_1ad8a370
  { 1, 818, 820, 12150, 12155 }, // 283 tc_e675c45a
  { 1, 803, 805, 12155, 12159 }, // 284 tc_37820f4c
  { 1, 848, 850, 12159, 12162 }, // 285 tc_61bf7c03
  { 1, 848, 850, 12162, 12166 }, // 286 tc_933f2b39
  { 1, 848, 850, 12166, 12170 }, // 287 tc_26a377fe
  { 1, 848, 850, 12170, 12175 }, // 288 tc_2d4051cd
  { 1, 816, 818, 12175, 12178 }, // 289 tc_6e7fa133
  { 1, 794, 796, 12178, 12181 }, // 290 tc_8772086c
  { 1, 796, 798, 12181, 12183 }, // 291 tc_b4416217
  { 1, 805, 808, 12183, 12187 }, // 292 tc_9f363d21
  { 1, 805, 808, 12187, 12192 }, // 293 tc_8e420e4d
  { 1, 850, 853, 12192, 12196 }, // 294 tc_7273323b
  { 1, 850, 853, 12196, 12201 }, // 295 tc_58d21193
  { 1, 796, 798, 12201, 12205 }, // 296 tc_71646d06
  { 1, 836, 838, 12205, 12208 }, // 297 tc_2c745bb8
  { 1, 841, 843, 12208, 12209 }, // 298 tc_b28e51aa
  { 1, 841, 843, 12209, 12211 }, // 299 tc_767c4e9d
  { 1, 853, 855, 12211, 12213 }, // 300 tc_e699ae41
  { 1, 853, 855, 12213, 12216 }, // 301 tc_a0dbea28
  { 1, 853, 855, 12216, 12219 }, // 302 tc_dd5b0695
  { 1, 853, 855, 12219, 12223 }, // 303 tc_3ad719fb
  { 1, 789, 790, 0, 0 }, // 304 tc_77f94a5e
  { 1, 793, 794, 0, 0 }, // 305 tc_55255f2b
  { 1, 793, 794, 12223, 12224 }, // 306 tc_0a43be35
  { 1, 789, 790, 12224, 12225 }, // 307 tc_b1ae5f67
  { 1, 789, 790, 12225, 12226 }, // 308 tc_d234b61a
  { 1, 789, 790, 12226, 12228 }, // 309 tc_2237d952
  { 1, 789, 790, 0, 0 }, // 310 tc_78f87ed3
  { 1, 789, 790, 12228, 12230 }, // 311 tc_a724463d
  { 1, 789, 790, 12230, 12232 }, // 312 tc_6fb52018
  { 1, 793, 794, 12232, 12234 }, // 313 tc_46c18ecf
  { 1, 791, 792, 12234, 12236 }, // 314 tc_9b20a062
  { 1, 791, 792, 12236, 12238 }, // 315 tc_5a222e89
  { 1, 791, 792, 12238, 12239 }, // 316 tc_0ba0d5da
  { 1, 791, 792, 12239, 12240 }, // 317 tc_7d6a2568
  { 1, 791, 792, 12240, 12242 }, // 318 tc_759e57be
  { 1, 791, 792, 12242, 12244 }, // 319 tc_139ef484
  { 1, 791, 792, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 793, 794, 0, 0 }, // 321 tc_7f58404a
  { 1, 789, 790, 0, 0 }, // 322 tc_b3d46584
  { 1, 793, 794, 12244, 12246 }, // 323 tc_d71ea8fa
  { 1, 793, 794, 12246, 12248 }, // 324 tc_6aa823ab
  { 1, 793, 794, 12248, 12250 }, // 325 tc_b2196a3f
  { 1, 793, 794, 12250, 12251 }, // 326 tc_2c3e17fc
  { 1, 793, 794, 12251, 12254 }, // 327 tc_27106296
  { 1, 789, 790, 12254, 12256 }, // 328 tc_a3070909
  { 1, 789, 790, 12256, 12258 }, // 329 tc_512b1653
  { 1, 793, 794, 12258, 12259 }, // 330 tc_d7718fbe
  { 1, 793, 794, 12259, 12262 }, // 331 tc_bb78483e
  { 1, 793, 794, 12262, 12263 }, // 332 tc_54f0cee2
  { 1, 793, 794, 12263, 12265 }, // 333 tc_28e55c6f
  { 1, 789, 790, 12265, 12266 }, // 334 tc_4bf903b0
  { 1, 789, 790, 12266, 12267 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV79[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 855, 856, 12267, 12270 }, // 1 tc_01d44cb2
  { 1, 856, 857, 12270, 12273 }, // 2 PSEUDO
  { 1, 856, 857, 12273, 12275 }, // 3 tc_c57d9f39
  { 1, 856, 857, 12275, 12279 }, // 4 tc_1c2c7a4a
  { 1, 856, 857, 12279, 12283 }, // 5 tc_442395f3
  { 1, 856, 857, 12283, 12286 }, // 6 tc_713b66bf
  { 1, 856, 857, 12286, 12289 }, // 7 tc_86173609
  { 1, 855, 856, 12289, 12292 }, // 8 tc_5da50c4b
  { 1, 855, 856, 12292, 12295 }, // 9 tc_4a55d03c
  { 1, 856, 857, 12295, 12298 }, // 10 tc_d33e5eee
  { 1, 855, 856, 12298, 12301 }, // 11 tc_651cbe02
  { 1, 857, 858, 12301, 12304 }, // 12 DUPLEX
  { 1, 858, 859, 12304, 12305 }, // 13 tc_ENDLOOP
  { 1, 856, 857, 0, 0 }, // 14 tc_23708a21
  { 1, 856, 857, 12305, 12307 }, // 15 tc_56a124a7
  { 1, 859, 860, 12307, 12309 }, // 16 tc_2f573607
  { 1, 859, 860, 12309, 12312 }, // 17 tc_53c851ab
  { 1, 860, 861, 12312, 12316 }, // 18 tc_fedb7e19
  { 1, 860, 861, 12316, 12319 }, // 19 tc_4222e6bf
  { 1, 860, 861, 12319, 12323 }, // 20 tc_075c8dd8
  { 1, 857, 858, 12323, 12326 }, // 21 tc_9bcfb2ee
  { 1, 857, 858, 12326, 12329 }, // 22 tc_158aa3f7
  { 1, 857, 858, 12329, 12332 }, // 23 tc_df5d53f9
  { 1, 857, 858, 12332, 12335 }, // 24 tc_14ab4f41
  { 1, 857, 858, 12335, 12336 }, // 25 tc_f38f92e1
  { 1, 857, 858, 12336, 12337 }, // 26 tc_1981450d
  { 1, 860, 861, 12337, 12339 }, // 27 tc_e9170fb7
  { 1, 857, 858, 12339, 12341 }, // 28 tc_40d64c94
  { 1, 860, 861, 12341, 12343 }, // 29 LD_tc_ld_SLOT01
  { 1, 855, 856, 12343, 12346 }, // 30 tc_38382228
  { 1, 855, 856, 12346, 12349 }, // 31 tc_c21d7447
  { 1, 855, 856, 12349, 12353 }, // 32 tc_7f8ae742
  { 1, 861, 862, 12353, 12356 }, // 33 tc_5a4b5e58
  { 1, 861, 862, 12356, 12360 }, // 34 tc_197dce51
  { 1, 855, 856, 12360, 12361 }, // 35 tc_44fffc58
  { 1, 860, 861, 12361, 12366 }, // 36 tc_5ceb2f9e
  { 1, 862, 864, 12366, 12369 }, // 37 tc_56c4f9fe
  { 1, 861, 862, 12369, 12371 }, // 38 tc_7476d766
  { 1, 860, 861, 12371, 12376 }, // 39 tc_b4dc7630
  { 1, 860, 861, 12376, 12380 }, // 40 tc_a2b365d2
  { 1, 859, 860, 12380, 12381 }, // 41 tc_60e324ff
  { 1, 864, 866, 12381, 12384 }, // 42 tc_db5555f3
  { 1, 866, 869, 12384, 12387 }, // 43 tc_c0749f3c
  { 1, 869, 871, 12387, 12390 }, // 44 PSEUDOM
  { 1, 862, 864, 12390, 12393 }, // 45 tc_3aacf4a8
  { 1, 871, 873, 12393, 12395 }, // 46 tc_c4edf264
  { 1, 873, 876, 12395, 12398 }, // 47 tc_c5dba46e
  { 1, 864, 866, 12398, 12402 }, // 48 tc_af25efd9
  { 1, 855, 856, 12402, 12405 }, // 49 tc_0dfac0a7
  { 1, 860, 861, 12405, 12409 }, // 50 tc_8035e91f
  { 1, 857, 858, 12409, 12413 }, // 51 tc_011e0e9d
  { 1, 860, 861, 12413, 12416 }, // 52 tc_ae5babd7
  { 1, 857, 858, 12416, 12419 }, // 53 tc_5deb5e47
  { 1, 855, 856, 12419, 12424 }, // 54 tc_bb831a7c
  { 1, 857, 858, 12424, 12428 }, // 55 tc_92240447
  { 1, 860, 861, 12428, 12431 }, // 56 tc_7c31e19a
  { 1, 860, 861, 12431, 12435 }, // 57 tc_d03278fd
  { 1, 860, 861, 12435, 12439 }, // 58 tc_65cbd974
  { 1, 857, 858, 12439, 12442 }, // 59 tc_934753bb
  { 1, 860, 861, 12442, 12445 }, // 60 ST_tc_st_SLOT01
  { 1, 876, 878, 12445, 12449 }, // 61 CVI_VA
  { 1, 871, 873, 12449, 12453 }, // 62 tc_f175e046
  { 1, 871, 873, 12453, 12458 }, // 63 tc_4942646a
  { 1, 862, 864, 12458, 12460 }, // 64 tc_0ec46cf9
  { 1, 864, 866, 12460, 12461 }, // 65 tc_718b5c53
  { 1, 878, 882, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 861, 862, 12461, 12463 }, // 67 tc_7dc63b5c
  { 1, 857, 858, 12463, 12464 }, // 68 tc_d45ba9cd
  { 1, 856, 857, 12464, 12467 }, // 69 tc_388f9897
  { 1, 856, 857, 12467, 12469 }, // 70 tc_9124c04f
  { 1, 856, 857, 12469, 12472 }, // 71 tc_4ac61d92
  { 1, 860, 861, 12472, 12474 }, // 72 tc_aee6250c
  { 1, 860, 861, 12474, 12477 }, // 73 tc_eed07714
  { 1, 860, 861, 12477, 12480 }, // 74 tc_74a42bda
  { 1, 860, 861, 12480, 12483 }, // 75 tc_a9edeffa
  { 1, 860, 861, 12483, 12486 }, // 76 tc_838c4d7a
  { 1, 855, 856, 12486, 12488 }, // 77 tc_d61dfdc3
  { 1, 855, 856, 12488, 12491 }, // 78 tc_8a825db2
  { 1, 855, 856, 12491, 12494 }, // 79 tc_f34c1c21
  { 1, 856, 857, 12494, 12497 }, // 80 tc_95a33176
  { 1, 855, 856, 12497, 12499 }, // 81 tc_9f6cd987
  { 1, 856, 857, 0, 0 }, // 82 tc_b837298f
  { 1, 856, 857, 12499, 12502 }, // 83 tc_8b5bd4f5
  { 1, 856, 857, 12502, 12505 }, // 84 tc_84a7500d
  { 1, 861, 862, 12505, 12507 }, // 85 tc_49fdfd4b
  { 1, 855, 856, 12507, 12510 }, // 86 tc_f098b237
  { 1, 855, 856, 12510, 12513 }, // 87 tc_20131976
  { 1, 855, 856, 12513, 12518 }, // 88 tc_1d41f8b7
  { 1, 855, 856, 12518, 12521 }, // 89 tc_a1297125
  { 1, 856, 857, 12521, 12522 }, // 90 tc_112d30d6
  { 1, 855, 856, 12522, 12525 }, // 91 tc_d68dca5c
  { 1, 855, 856, 12525, 12529 }, // 92 tc_788b1d09
  { 1, 855, 856, 12529, 12534 }, // 93 tc_38e0bae9
  { 1, 855, 856, 12534, 12537 }, // 94 tc_407e96f9
  { 1, 855, 856, 12537, 12541 }, // 95 tc_7401744f
  { 1, 855, 856, 12541, 12544 }, // 96 tc_9b3c0462
  { 1, 855, 856, 12544, 12546 }, // 97 tc_151bf368
  { 1, 856, 857, 12546, 12549 }, // 98 tc_9c52f549
  { 1, 855, 856, 12549, 12551 }, // 99 tc_55b33fda
  { 1, 855, 856, 12551, 12555 }, // 100 tc_6fc5dbea
  { 1, 861, 862, 12555, 12557 }, // 101 tc_3edca78f
  { 1, 855, 856, 12557, 12561 }, // 102 tc_a7a13fac
  { 1, 855, 856, 12561, 12563 }, // 103 tc_9783714b
  { 1, 855, 856, 12563, 12566 }, // 104 tc_f0e8e832
  { 1, 855, 856, 12566, 12568 }, // 105 tc_65279839
  { 1, 855, 856, 12568, 12572 }, // 106 tc_0a195f2c
  { 1, 855, 856, 12572, 12576 }, // 107 tc_01e1be3b
  { 1, 855, 856, 12576, 12579 }, // 108 tc_556f6577
  { 1, 855, 856, 12579, 12582 }, // 109 tc_02fe1c65
  { 1, 855, 856, 12582, 12586 }, // 110 tc_9e72dc89
  { 1, 855, 856, 12586, 12591 }, // 111 tc_9edb7c77
  { 1, 855, 856, 12591, 12594 }, // 112 tc_7f7f45f5
  { 1, 855, 856, 12594, 12597 }, // 113 tc_c20701f0
  { 1, 855, 856, 12597, 12601 }, // 114 tc_f7569068
  { 1, 861, 862, 12601, 12603 }, // 115 tc_fae9dfa5
  { 1, 861, 862, 12603, 12605 }, // 116 tc_6ae3426b
  { 1, 855, 856, 12605, 12607 }, // 117 tc_69bfb303
  { 1, 859, 860, 12607, 12608 }, // 118 tc_362b0be2
  { 1, 859, 860, 12608, 12610 }, // 119 tc_dc51281d
  { 1, 859, 860, 12610, 12611 }, // 120 tc_95f43c5e
  { 1, 856, 857, 12611, 12612 }, // 121 tc_decdde8a
  { 1, 856, 857, 12612, 12614 }, // 122 tc_eeda4109
  { 1, 856, 857, 12614, 12616 }, // 123 tc_711c805f
  { 1, 859, 860, 12616, 12618 }, // 124 tc_ed03645c
  { 1, 859, 860, 12618, 12620 }, // 125 tc_42ff66ba
  { 1, 861, 862, 12620, 12622 }, // 126 tc_57a55b54
  { 1, 859, 860, 12622, 12623 }, // 127 tc_f97707c1
  { 1, 861, 862, 12623, 12625 }, // 128 tc_1248597c
  { 1, 861, 862, 12625, 12627 }, // 129 tc_9406230a
  { 1, 859, 860, 12627, 12628 }, // 130 tc_d57d649c
  { 1, 861, 862, 12628, 12630 }, // 131 tc_4abdbdc6
  { 1, 861, 862, 12630, 12632 }, // 132 tc_6d861a95
  { 1, 859, 860, 0, 0 }, // 133 tc_b9bec29e
  { 1, 859, 860, 12632, 12633 }, // 134 tc_45f9d1be
  { 1, 859, 860, 0, 0 }, // 135 tc_33e7e673
  { 1, 857, 858, 12633, 12636 }, // 136 tc_24e109c7
  { 1, 856, 857, 12636, 12639 }, // 137 tc_9e27f2f9
  { 1, 857, 858, 12639, 12642 }, // 138 tc_f6e2aff9
  { 1, 856, 857, 12642, 12645 }, // 139 tc_24f426ab
  { 1, 857, 858, 12645, 12648 }, // 140 tc_975a4e54
  { 1, 855, 856, 12648, 12649 }, // 141 tc_e60def48
  { 1, 855, 856, 12649, 12652 }, // 142 tc_5502c366
  { 1, 857, 858, 12652, 12654 }, // 143 tc_7b9187d3
  { 1, 856, 857, 12654, 12656 }, // 144 tc_f999c66e
  { 1, 860, 861, 12656, 12661 }, // 145 tc_1c7522a8
  { 1, 860, 861, 12661, 12667 }, // 146 tc_76bb5435
  { 1, 860, 861, 12667, 12669 }, // 147 tc_8a6d0d94
  { 1, 857, 858, 12669, 12671 }, // 148 tc_2471c1c8
  { 1, 857, 858, 12671, 12673 }, // 149 tc_64b00d8a
  { 1, 860, 861, 12673, 12678 }, // 150 tc_5f2afaf7
  { 1, 860, 861, 12678, 12682 }, // 151 tc_ac65613f
  { 1, 860, 861, 12682, 12687 }, // 152 tc_a32e03e7
  { 1, 860, 861, 12687, 12690 }, // 153 tc_822c3c68
  { 1, 860, 861, 12690, 12694 }, // 154 tc_abfd9a6d
  { 1, 860, 861, 12694, 12698 }, // 155 tc_bf2ffc0f
  { 1, 857, 858, 12698, 12701 }, // 156 tc_ed3f8d2a
  { 1, 860, 861, 12701, 12704 }, // 157 tc_7c6d32e4
  { 1, 860, 861, 12704, 12709 }, // 158 tc_45791fb8
  { 1, 860, 861, 12709, 12714 }, // 159 tc_b7c4062a
  { 1, 860, 861, 12714, 12717 }, // 160 tc_5944960d
  { 1, 855, 856, 12717, 12721 }, // 161 tc_2c13e7f5
  { 1, 855, 856, 12721, 12725 }, // 162 tc_a154b476
  { 1, 855, 856, 12725, 12729 }, // 163 tc_a4e22bbd
  { 1, 855, 856, 12729, 12733 }, // 164 tc_503ce0f3
  { 1, 860, 861, 12733, 12735 }, // 165 tc_0655b949
  { 1, 857, 858, 12735, 12737 }, // 166 tc_6e20402a
  { 1, 857, 858, 12737, 12738 }, // 167 tc_db96aa6b
  { 1, 855, 856, 12738, 12740 }, // 168 tc_a7bdb22c
  { 1, 855, 856, 12740, 12743 }, // 169 tc_db596beb
  { 1, 855, 856, 12743, 12746 }, // 170 tc_a08b630b
  { 1, 855, 856, 12746, 12749 }, // 171 tc_1fcb8495
  { 1, 860, 861, 12749, 12754 }, // 172 tc_9edefe01
  { 1, 860, 861, 12754, 12759 }, // 173 tc_449acf79
  { 1, 857, 858, 12759, 12764 }, // 174 tc_ce59038e
  { 1, 857, 858, 12764, 12769 }, // 175 tc_f529831b
  { 1, 857, 858, 12769, 12774 }, // 176 tc_addc37a8
  { 1, 857, 858, 12774, 12777 }, // 177 tc_6f42bc60
  { 1, 857, 858, 12777, 12779 }, // 178 tc_7af3a37e
  { 1, 855, 856, 12779, 12781 }, // 179 tc_e3d699e3
  { 1, 860, 861, 12781, 12784 }, // 180 tc_ba9255a6
  { 1, 860, 861, 12784, 12789 }, // 181 tc_1fe4ab69
  { 1, 860, 861, 12789, 12792 }, // 182 tc_bb07f2c5
  { 1, 860, 861, 12792, 12797 }, // 183 tc_8e82e8ca
  { 1, 857, 858, 12797, 12800 }, // 184 tc_cfa0e29b
  { 1, 857, 858, 12800, 12805 }, // 185 tc_0a6c20ae
  { 1, 857, 858, 12805, 12808 }, // 186 tc_0fac1eb8
  { 1, 857, 858, 12808, 12813 }, // 187 tc_829d8a86
  { 1, 860, 861, 12813, 12817 }, // 188 tc_280f7fe1
  { 1, 860, 861, 12817, 12821 }, // 189 tc_887d1bb7
  { 1, 857, 858, 12821, 12825 }, // 190 tc_96ef76ef
  { 1, 857, 858, 12825, 12829 }, // 191 tc_55a9a350
  { 1, 855, 856, 12829, 12833 }, // 192 tc_f0cdeccf
  { 1, 855, 856, 12833, 12838 }, // 193 tc_a38c45dc
  { 1, 855, 856, 12838, 12840 }, // 194 tc_d3632d88
  { 1, 855, 856, 12840, 12844 }, // 195 tc_5e4cf0e8
  { 1, 855, 856, 12844, 12846 }, // 196 tc_ef921005
  { 1, 860, 861, 12846, 12849 }, // 197 tc_5b347363
  { 1, 860, 861, 12849, 12851 }, // 198 tc_3d14a17b
  { 1, 860, 861, 12851, 12852 }, // 199 tc_3fbf1042
  { 1, 860, 861, 12852, 12853 }, // 200 tc_63567288
  { 1, 860, 861, 12853, 12855 }, // 201 tc_59a7822c
  { 1, 860, 861, 0, 0 }, // 202 tc_937dd41c
  { 1, 857, 858, 0, 0 }, // 203 tc_a4ee89db
  { 1, 857, 858, 0, 0 }, // 204 tc_c818ff7f
  { 1, 857, 858, 12855, 12856 }, // 205 tc_1242dc2a
  { 1, 860, 861, 12856, 12858 }, // 206 tc_44d5a428
  { 1, 882, 884, 12858, 12861 }, // 207 tc_540c3da3
  { 1, 871, 873, 12861, 12865 }, // 208 tc_b091f1c6
  { 1, 884, 886, 12865, 12867 }, // 209 tc_5bf8afbb
  { 1, 886, 888, 12867, 12871 }, // 210 tc_2b4c548e
  { 1, 886, 888, 12871, 12876 }, // 211 tc_bb599486
  { 1, 888, 892, 12876, 12879 }, // 212 tc_a7e6707d
  { 1, 888, 892, 12879, 12883 }, // 213 tc_3c56e5ce
  { 1, 866, 869, 12883, 12887 }, // 214 tc_abe8c3b2
  { 1, 866, 869, 12887, 12892 }, // 215 tc_453fe68d
  { 1, 866, 869, 12892, 12896 }, // 216 tc_1ba8a0cd
  { 1, 892, 894, 12896, 12899 }, // 217 tc_52447ecc
  { 1, 892, 894, 12899, 12903 }, // 218 tc_3904b926
  { 1, 892, 894, 12903, 12908 }, // 219 tc_b9db8205
  { 1, 892, 894, 12908, 12912 }, // 220 tc_663c80a7
  { 1, 894, 898, 12912, 12915 }, // 221 tc_f21e8abb
  { 1, 894, 898, 12915, 12919 }, // 222 tc_131f1c81
  { 1, 894, 898, 12919, 12924 }, // 223 tc_c7039829
  { 1, 894, 898, 12924, 12928 }, // 224 tc_e2d2e9e5
  { 1, 898, 900, 12928, 12931 }, // 225 tc_ab23f776
  { 1, 898, 900, 12931, 12935 }, // 226 tc_7177e272
  { 1, 898, 900, 12935, 12940 }, // 227 tc_e99d4c2e
  { 1, 898, 900, 12940, 12944 }, // 228 tc_6942b6e0
  { 1, 873, 876, 12944, 12948 }, // 229 tc_a02a10a8
  { 1, 873, 876, 12948, 12953 }, // 230 tc_54a0dc47
  { 1, 873, 876, 12953, 12957 }, // 231 tc_447d9895
  { 1, 873, 876, 12957, 12962 }, // 232 tc_191381c1
  { 1, 873, 876, 12962, 12966 }, // 233 tc_3e2aaafc
  { 1, 898, 900, 12966, 12968 }, // 234 tc_3ce09744
  { 1, 898, 900, 12968, 12971 }, // 235 tc_20a4bbec
  { 1, 871, 873, 12971, 12973 }, // 236 tc_5cdf8c84
  { 1, 900, 902, 12973, 12975 }, // 237 tc_2a698a03
  { 1, 871, 873, 12975, 12978 }, // 238 tc_c127de3a
  { 1, 902, 904, 12978, 12981 }, // 239 tc_05ca8cfd
  { 1, 886, 888, 12981, 12984 }, // 240 tc_d8287c14
  { 1, 862, 864, 12984, 12988 }, // 241 tc_257f6f7c
  { 1, 862, 864, 12988, 12993 }, // 242 tc_7e6a3e89
  { 1, 862, 864, 12993, 12997 }, // 243 tc_e35c1e93
  { 1, 886, 888, 12997, 13001 }, // 244 tc_08a4f1b6
  { 1, 862, 864, 13001, 13005 }, // 245 tc_57a4709c
  { 1, 884, 886, 13005, 13009 }, // 246 tc_56e64202
  { 1, 871, 873, 13009, 13012 }, // 247 tc_ac4046bc
  { 1, 871, 873, 13012, 13016 }, // 248 tc_2e8f5f6e
  { 1, 902, 904, 13016, 13019 }, // 249 tc_7417e785
  { 1, 902, 904, 13019, 13023 }, // 250 tc_309dbb4f
  { 1, 904, 906, 13023, 13027 }, // 251 tc_df80eeb0
  { 1, 902, 904, 13027, 13031 }, // 252 tc_16ff9ef8
  { 1, 856, 857, 13031, 13033 }, // 253 tc_e2fdd6e6
  { 1, 902, 904, 13033, 13035 }, // 254 tc_51d0ecc3
  { 1, 856, 857, 13035, 13038 }, // 255 tc_531b383c
  { 1, 904, 906, 13038, 13040 }, // 256 tc_04da405a
  { 1, 871, 873, 13040, 13042 }, // 257 tc_3c8c15d0
  { 1, 886, 888, 13042, 13044 }, // 258 tc_0afc8be9
  { 1, 904, 906, 13044, 13049 }, // 259 tc_561aaa58
  { 1, 884, 886, 13049, 13051 }, // 260 tc_946013d8
  { 1, 884, 886, 13051, 13054 }, // 261 tc_46d6c3e0
  { 1, 904, 906, 13054, 13058 }, // 262 tc_87adc037
  { 1, 871, 873, 13058, 13062 }, // 263 tc_a19b9305
  { 1, 871, 873, 13062, 13065 }, // 264 tc_649072c2
  { 1, 886, 888, 13065, 13068 }, // 265 tc_0b04c6c7
  { 1, 886, 888, 13068, 13072 }, // 266 tc_660769f1
  { 1, 871, 873, 13072, 13075 }, // 267 tc_dcca380f
  { 1, 871, 873, 13075, 13079 }, // 268 tc_72e2b393
  { 1, 871, 873, 13079, 13082 }, // 269 tc_73efe966
  { 1, 871, 873, 13082, 13085 }, // 270 tc_cda936da
  { 1, 866, 869, 13085, 13088 }, // 271 tc_a28f32b5
  { 1, 866, 869, 13088, 13092 }, // 272 tc_7d68d5c2
  { 1, 906, 909, 13092, 13095 }, // 273 tc_7095ecba
  { 1, 906, 909, 13095, 13099 }, // 274 tc_a69eeee1
  { 1, 909, 911, 0, 0 }, // 275 tc_1381a97c
  { 1, 909, 911, 13099, 13100 }, // 276 tc_e3f68a46
  { 1, 911, 913, 13100, 13103 }, // 277 tc_f1de44ef
  { 1, 904, 906, 13103, 13108 }, // 278 tc_9d1dc972
  { 1, 911, 913, 13108, 13112 }, // 279 tc_90bcc1db
  { 1, 913, 916, 13112, 13115 }, // 280 tc_cd94bfe0
  { 1, 913, 916, 13115, 13119 }, // 281 tc_15fdf750
  { 1, 886, 888, 13119, 13123 }, // 282 tc_1ad8a370
  { 1, 886, 888, 13123, 13128 }, // 283 tc_e675c45a
  { 1, 871, 873, 13128, 13132 }, // 284 tc_37820f4c
  { 1, 916, 918, 13132, 13135 }, // 285 tc_61bf7c03
  { 1, 916, 918, 13135, 13139 }, // 286 tc_933f2b39
  { 1, 916, 918, 13139, 13143 }, // 287 tc_26a377fe
  { 1, 916, 918, 13143, 13148 }, // 288 tc_2d4051cd
  { 1, 884, 886, 13148, 13151 }, // 289 tc_6e7fa133
  { 1, 862, 864, 13151, 13154 }, // 290 tc_8772086c
  { 1, 864, 866, 13154, 13156 }, // 291 tc_b4416217
  { 1, 873, 876, 13156, 13160 }, // 292 tc_9f363d21
  { 1, 873, 876, 13160, 13165 }, // 293 tc_8e420e4d
  { 1, 918, 921, 13165, 13169 }, // 294 tc_7273323b
  { 1, 918, 921, 13169, 13174 }, // 295 tc_58d21193
  { 1, 864, 866, 13174, 13178 }, // 296 tc_71646d06
  { 1, 904, 906, 13178, 13181 }, // 297 tc_2c745bb8
  { 1, 909, 911, 13181, 13182 }, // 298 tc_b28e51aa
  { 1, 909, 911, 13182, 13184 }, // 299 tc_767c4e9d
  { 1, 921, 923, 13184, 13186 }, // 300 tc_e699ae41
  { 1, 921, 923, 13186, 13189 }, // 301 tc_a0dbea28
  { 1, 921, 923, 13189, 13192 }, // 302 tc_dd5b0695
  { 1, 921, 923, 13192, 13196 }, // 303 tc_3ad719fb
  { 1, 857, 858, 0, 0 }, // 304 tc_77f94a5e
  { 1, 861, 862, 0, 0 }, // 305 tc_55255f2b
  { 1, 861, 862, 13196, 13197 }, // 306 tc_0a43be35
  { 1, 857, 858, 13197, 13198 }, // 307 tc_b1ae5f67
  { 1, 857, 858, 13198, 13199 }, // 308 tc_d234b61a
  { 1, 857, 858, 13199, 13201 }, // 309 tc_2237d952
  { 1, 857, 858, 0, 0 }, // 310 tc_78f87ed3
  { 1, 857, 858, 13201, 13203 }, // 311 tc_a724463d
  { 1, 857, 858, 13203, 13205 }, // 312 tc_6fb52018
  { 1, 861, 862, 13205, 13207 }, // 313 tc_46c18ecf
  { 1, 859, 860, 13207, 13209 }, // 314 tc_9b20a062
  { 1, 859, 860, 13209, 13211 }, // 315 tc_5a222e89
  { 1, 859, 860, 13211, 13212 }, // 316 tc_0ba0d5da
  { 1, 859, 860, 13212, 13213 }, // 317 tc_7d6a2568
  { 1, 859, 860, 13213, 13215 }, // 318 tc_759e57be
  { 1, 859, 860, 13215, 13217 }, // 319 tc_139ef484
  { 1, 859, 860, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 861, 862, 0, 0 }, // 321 tc_7f58404a
  { 1, 857, 858, 0, 0 }, // 322 tc_b3d46584
  { 1, 861, 862, 13217, 13219 }, // 323 tc_d71ea8fa
  { 1, 861, 862, 13219, 13221 }, // 324 tc_6aa823ab
  { 1, 861, 862, 13221, 13223 }, // 325 tc_b2196a3f
  { 1, 861, 862, 13223, 13224 }, // 326 tc_2c3e17fc
  { 1, 861, 862, 13224, 13227 }, // 327 tc_27106296
  { 1, 857, 858, 13227, 13229 }, // 328 tc_a3070909
  { 1, 857, 858, 13229, 13231 }, // 329 tc_512b1653
  { 1, 861, 862, 13231, 13232 }, // 330 tc_d7718fbe
  { 1, 861, 862, 13232, 13235 }, // 331 tc_bb78483e
  { 1, 861, 862, 13235, 13236 }, // 332 tc_54f0cee2
  { 1, 861, 862, 13236, 13238 }, // 333 tc_28e55c6f
  { 1, 857, 858, 13238, 13239 }, // 334 tc_4bf903b0
  { 1, 857, 858, 13239, 13240 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

static constexpr llvm_ks::InstrItinerary HexagonItinerariesV81[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 923, 924, 13240, 13243 }, // 1 tc_01d44cb2
  { 1, 924, 925, 13243, 13246 }, // 2 PSEUDO
  { 1, 924, 925, 13246, 13248 }, // 3 tc_c57d9f39
  { 1, 924, 925, 13248, 13252 }, // 4 tc_1c2c7a4a
  { 1, 924, 925, 13252, 13256 }, // 5 tc_442395f3
  { 1, 924, 925, 13256, 13259 }, // 6 tc_713b66bf
  { 1, 924, 925, 13259, 13262 }, // 7 tc_86173609
  { 1, 923, 924, 13262, 13265 }, // 8 tc_5da50c4b
  { 1, 923, 924, 13265, 13268 }, // 9 tc_4a55d03c
  { 1, 924, 925, 13268, 13271 }, // 10 tc_d33e5eee
  { 1, 923, 924, 13271, 13274 }, // 11 tc_651cbe02
  { 1, 925, 926, 13274, 13277 }, // 12 DUPLEX
  { 1, 926, 927, 13277, 13278 }, // 13 tc_ENDLOOP
  { 1, 924, 925, 0, 0 }, // 14 tc_23708a21
  { 1, 924, 925, 13278, 13280 }, // 15 tc_56a124a7
  { 1, 927, 928, 13280, 13282 }, // 16 tc_2f573607
  { 1, 927, 928, 13282, 13285 }, // 17 tc_53c851ab
  { 1, 928, 929, 13285, 13289 }, // 18 tc_fedb7e19
  { 1, 928, 929, 13289, 13292 }, // 19 tc_4222e6bf
  { 1, 928, 929, 13292, 13296 }, // 20 tc_075c8dd8
  { 1, 925, 926, 13296, 13299 }, // 21 tc_9bcfb2ee
  { 1, 925, 926, 13299, 13302 }, // 22 tc_158aa3f7
  { 1, 925, 926, 13302, 13305 }, // 23 tc_df5d53f9
  { 1, 925, 926, 13305, 13308 }, // 24 tc_14ab4f41
  { 1, 925, 926, 13308, 13309 }, // 25 tc_f38f92e1
  { 1, 925, 926, 13309, 13310 }, // 26 tc_1981450d
  { 1, 928, 929, 13310, 13312 }, // 27 tc_e9170fb7
  { 1, 925, 926, 13312, 13314 }, // 28 tc_40d64c94
  { 1, 928, 929, 13314, 13316 }, // 29 LD_tc_ld_SLOT01
  { 1, 923, 924, 13316, 13319 }, // 30 tc_38382228
  { 1, 923, 924, 13319, 13322 }, // 31 tc_c21d7447
  { 1, 923, 924, 13322, 13326 }, // 32 tc_7f8ae742
  { 1, 929, 930, 13326, 13329 }, // 33 tc_5a4b5e58
  { 1, 929, 930, 13329, 13333 }, // 34 tc_197dce51
  { 1, 923, 924, 13333, 13334 }, // 35 tc_44fffc58
  { 1, 928, 929, 13334, 13339 }, // 36 tc_5ceb2f9e
  { 1, 930, 932, 13339, 13342 }, // 37 tc_56c4f9fe
  { 1, 929, 930, 13342, 13344 }, // 38 tc_7476d766
  { 1, 928, 929, 13344, 13349 }, // 39 tc_b4dc7630
  { 1, 928, 929, 13349, 13353 }, // 40 tc_a2b365d2
  { 1, 927, 928, 13353, 13354 }, // 41 tc_60e324ff
  { 1, 932, 934, 13354, 13357 }, // 42 tc_db5555f3
  { 1, 934, 937, 13357, 13360 }, // 43 tc_c0749f3c
  { 1, 937, 939, 13360, 13363 }, // 44 PSEUDOM
  { 1, 930, 932, 13363, 13366 }, // 45 tc_3aacf4a8
  { 1, 939, 941, 13366, 13368 }, // 46 tc_c4edf264
  { 1, 941, 944, 13368, 13371 }, // 47 tc_c5dba46e
  { 1, 932, 934, 13371, 13375 }, // 48 tc_af25efd9
  { 1, 923, 924, 13375, 13378 }, // 49 tc_0dfac0a7
  { 1, 928, 929, 13378, 13382 }, // 50 tc_8035e91f
  { 1, 925, 926, 13382, 13386 }, // 51 tc_011e0e9d
  { 1, 928, 929, 13386, 13389 }, // 52 tc_ae5babd7
  { 1, 925, 926, 13389, 13392 }, // 53 tc_5deb5e47
  { 1, 923, 924, 13392, 13397 }, // 54 tc_bb831a7c
  { 1, 925, 926, 13397, 13401 }, // 55 tc_92240447
  { 1, 928, 929, 13401, 13404 }, // 56 tc_7c31e19a
  { 1, 928, 929, 13404, 13408 }, // 57 tc_d03278fd
  { 1, 928, 929, 13408, 13412 }, // 58 tc_65cbd974
  { 1, 925, 926, 13412, 13415 }, // 59 tc_934753bb
  { 1, 928, 929, 13415, 13418 }, // 60 ST_tc_st_SLOT01
  { 1, 944, 946, 13418, 13422 }, // 61 CVI_VA
  { 1, 939, 941, 13422, 13426 }, // 62 tc_f175e046
  { 1, 939, 941, 13426, 13431 }, // 63 tc_4942646a
  { 1, 930, 932, 13431, 13433 }, // 64 tc_0ec46cf9
  { 1, 932, 934, 13433, 13434 }, // 65 tc_718b5c53
  { 1, 946, 950, 0, 0 }, // 66 CVI_GATHER_PSEUDO
  { 1, 929, 930, 13434, 13436 }, // 67 tc_7dc63b5c
  { 1, 925, 926, 13436, 13437 }, // 68 tc_d45ba9cd
  { 1, 924, 925, 13437, 13440 }, // 69 tc_388f9897
  { 1, 924, 925, 13440, 13442 }, // 70 tc_9124c04f
  { 1, 924, 925, 13442, 13445 }, // 71 tc_4ac61d92
  { 1, 928, 929, 13445, 13447 }, // 72 tc_aee6250c
  { 1, 928, 929, 13447, 13450 }, // 73 tc_eed07714
  { 1, 928, 929, 13450, 13453 }, // 74 tc_74a42bda
  { 1, 928, 929, 13453, 13456 }, // 75 tc_a9edeffa
  { 1, 928, 929, 13456, 13459 }, // 76 tc_838c4d7a
  { 1, 923, 924, 13459, 13461 }, // 77 tc_d61dfdc3
  { 1, 923, 924, 13461, 13464 }, // 78 tc_8a825db2
  { 1, 923, 924, 13464, 13467 }, // 79 tc_f34c1c21
  { 1, 924, 925, 13467, 13470 }, // 80 tc_95a33176
  { 1, 923, 924, 13470, 13472 }, // 81 tc_9f6cd987
  { 1, 924, 925, 0, 0 }, // 82 tc_b837298f
  { 1, 924, 925, 13472, 13475 }, // 83 tc_8b5bd4f5
  { 1, 924, 925, 13475, 13478 }, // 84 tc_84a7500d
  { 1, 929, 930, 13478, 13480 }, // 85 tc_49fdfd4b
  { 1, 923, 924, 13480, 13483 }, // 86 tc_f098b237
  { 1, 923, 924, 13483, 13486 }, // 87 tc_20131976
  { 1, 923, 924, 13486, 13491 }, // 88 tc_1d41f8b7
  { 1, 923, 924, 13491, 13494 }, // 89 tc_a1297125
  { 1, 924, 925, 13494, 13495 }, // 90 tc_112d30d6
  { 1, 923, 924, 13495, 13498 }, // 91 tc_d68dca5c
  { 1, 923, 924, 13498, 13502 }, // 92 tc_788b1d09
  { 1, 923, 924, 13502, 13507 }, // 93 tc_38e0bae9
  { 1, 923, 924, 13507, 13510 }, // 94 tc_407e96f9
  { 1, 923, 924, 13510, 13514 }, // 95 tc_7401744f
  { 1, 923, 924, 13514, 13517 }, // 96 tc_9b3c0462
  { 1, 923, 924, 13517, 13519 }, // 97 tc_151bf368
  { 1, 924, 925, 13519, 13522 }, // 98 tc_9c52f549
  { 1, 923, 924, 13522, 13524 }, // 99 tc_55b33fda
  { 1, 923, 924, 13524, 13528 }, // 100 tc_6fc5dbea
  { 1, 929, 930, 13528, 13530 }, // 101 tc_3edca78f
  { 1, 923, 924, 13530, 13534 }, // 102 tc_a7a13fac
  { 1, 923, 924, 13534, 13536 }, // 103 tc_9783714b
  { 1, 923, 924, 13536, 13539 }, // 104 tc_f0e8e832
  { 1, 923, 924, 13539, 13541 }, // 105 tc_65279839
  { 1, 923, 924, 13541, 13545 }, // 106 tc_0a195f2c
  { 1, 923, 924, 13545, 13549 }, // 107 tc_01e1be3b
  { 1, 923, 924, 13549, 13552 }, // 108 tc_556f6577
  { 1, 923, 924, 13552, 13555 }, // 109 tc_02fe1c65
  { 1, 923, 924, 13555, 13559 }, // 110 tc_9e72dc89
  { 1, 923, 924, 13559, 13564 }, // 111 tc_9edb7c77
  { 1, 923, 924, 13564, 13567 }, // 112 tc_7f7f45f5
  { 1, 923, 924, 13567, 13570 }, // 113 tc_c20701f0
  { 1, 923, 924, 13570, 13574 }, // 114 tc_f7569068
  { 1, 929, 930, 13574, 13576 }, // 115 tc_fae9dfa5
  { 1, 929, 930, 13576, 13578 }, // 116 tc_6ae3426b
  { 1, 923, 924, 13578, 13580 }, // 117 tc_69bfb303
  { 1, 927, 928, 13580, 13581 }, // 118 tc_362b0be2
  { 1, 927, 928, 13581, 13583 }, // 119 tc_dc51281d
  { 1, 927, 928, 13583, 13584 }, // 120 tc_95f43c5e
  { 1, 924, 925, 13584, 13585 }, // 121 tc_decdde8a
  { 1, 924, 925, 13585, 13587 }, // 122 tc_eeda4109
  { 1, 924, 925, 13587, 13589 }, // 123 tc_711c805f
  { 1, 927, 928, 13589, 13591 }, // 124 tc_ed03645c
  { 1, 927, 928, 13591, 13593 }, // 125 tc_42ff66ba
  { 1, 929, 930, 13593, 13595 }, // 126 tc_57a55b54
  { 1, 927, 928, 13595, 13596 }, // 127 tc_f97707c1
  { 1, 929, 930, 13596, 13598 }, // 128 tc_1248597c
  { 1, 929, 930, 13598, 13600 }, // 129 tc_9406230a
  { 1, 927, 928, 13600, 13601 }, // 130 tc_d57d649c
  { 1, 929, 930, 13601, 13603 }, // 131 tc_4abdbdc6
  { 1, 929, 930, 13603, 13605 }, // 132 tc_6d861a95
  { 1, 927, 928, 0, 0 }, // 133 tc_b9bec29e
  { 1, 927, 928, 13605, 13606 }, // 134 tc_45f9d1be
  { 1, 927, 928, 0, 0 }, // 135 tc_33e7e673
  { 1, 925, 926, 13606, 13609 }, // 136 tc_24e109c7
  { 1, 924, 925, 13609, 13612 }, // 137 tc_9e27f2f9
  { 1, 925, 926, 13612, 13615 }, // 138 tc_f6e2aff9
  { 1, 924, 925, 13615, 13618 }, // 139 tc_24f426ab
  { 1, 925, 926, 13618, 13621 }, // 140 tc_975a4e54
  { 1, 923, 924, 13621, 13622 }, // 141 tc_e60def48
  { 1, 923, 924, 13622, 13625 }, // 142 tc_5502c366
  { 1, 925, 926, 13625, 13627 }, // 143 tc_7b9187d3
  { 1, 924, 925, 13627, 13629 }, // 144 tc_f999c66e
  { 1, 928, 929, 13629, 13634 }, // 145 tc_1c7522a8
  { 1, 928, 929, 13634, 13640 }, // 146 tc_76bb5435
  { 1, 928, 929, 13640, 13642 }, // 147 tc_8a6d0d94
  { 1, 925, 926, 13642, 13644 }, // 148 tc_2471c1c8
  { 1, 925, 926, 13644, 13646 }, // 149 tc_64b00d8a
  { 1, 928, 929, 13646, 13651 }, // 150 tc_5f2afaf7
  { 1, 928, 929, 13651, 13655 }, // 151 tc_ac65613f
  { 1, 928, 929, 13655, 13660 }, // 152 tc_a32e03e7
  { 1, 928, 929, 13660, 13663 }, // 153 tc_822c3c68
  { 1, 928, 929, 13663, 13667 }, // 154 tc_abfd9a6d
  { 1, 928, 929, 13667, 13671 }, // 155 tc_bf2ffc0f
  { 1, 925, 926, 13671, 13674 }, // 156 tc_ed3f8d2a
  { 1, 928, 929, 13674, 13677 }, // 157 tc_7c6d32e4
  { 1, 928, 929, 13677, 13682 }, // 158 tc_45791fb8
  { 1, 928, 929, 13682, 13687 }, // 159 tc_b7c4062a
  { 1, 928, 929, 13687, 13690 }, // 160 tc_5944960d
  { 1, 923, 924, 13690, 13694 }, // 161 tc_2c13e7f5
  { 1, 923, 924, 13694, 13698 }, // 162 tc_a154b476
  { 1, 923, 924, 13698, 13702 }, // 163 tc_a4e22bbd
  { 1, 923, 924, 13702, 13706 }, // 164 tc_503ce0f3
  { 1, 928, 929, 13706, 13708 }, // 165 tc_0655b949
  { 1, 925, 926, 13708, 13710 }, // 166 tc_6e20402a
  { 1, 925, 926, 13710, 13711 }, // 167 tc_db96aa6b
  { 1, 923, 924, 13711, 13713 }, // 168 tc_a7bdb22c
  { 1, 923, 924, 13713, 13716 }, // 169 tc_db596beb
  { 1, 923, 924, 13716, 13719 }, // 170 tc_a08b630b
  { 1, 923, 924, 13719, 13722 }, // 171 tc_1fcb8495
  { 1, 928, 929, 13722, 13727 }, // 172 tc_9edefe01
  { 1, 928, 929, 13727, 13732 }, // 173 tc_449acf79
  { 1, 925, 926, 13732, 13737 }, // 174 tc_ce59038e
  { 1, 925, 926, 13737, 13742 }, // 175 tc_f529831b
  { 1, 925, 926, 13742, 13747 }, // 176 tc_addc37a8
  { 1, 925, 926, 13747, 13750 }, // 177 tc_6f42bc60
  { 1, 925, 926, 13750, 13752 }, // 178 tc_7af3a37e
  { 1, 923, 924, 13752, 13754 }, // 179 tc_e3d699e3
  { 1, 928, 929, 13754, 13757 }, // 180 tc_ba9255a6
  { 1, 928, 929, 13757, 13762 }, // 181 tc_1fe4ab69
  { 1, 928, 929, 13762, 13765 }, // 182 tc_bb07f2c5
  { 1, 928, 929, 13765, 13770 }, // 183 tc_8e82e8ca
  { 1, 925, 926, 13770, 13773 }, // 184 tc_cfa0e29b
  { 1, 925, 926, 13773, 13778 }, // 185 tc_0a6c20ae
  { 1, 925, 926, 13778, 13781 }, // 186 tc_0fac1eb8
  { 1, 925, 926, 13781, 13786 }, // 187 tc_829d8a86
  { 1, 928, 929, 13786, 13790 }, // 188 tc_280f7fe1
  { 1, 928, 929, 13790, 13794 }, // 189 tc_887d1bb7
  { 1, 925, 926, 13794, 13798 }, // 190 tc_96ef76ef
  { 1, 925, 926, 13798, 13802 }, // 191 tc_55a9a350
  { 1, 923, 924, 13802, 13806 }, // 192 tc_f0cdeccf
  { 1, 923, 924, 13806, 13811 }, // 193 tc_a38c45dc
  { 1, 923, 924, 13811, 13813 }, // 194 tc_d3632d88
  { 1, 923, 924, 13813, 13817 }, // 195 tc_5e4cf0e8
  { 1, 923, 924, 13817, 13819 }, // 196 tc_ef921005
  { 1, 928, 929, 13819, 13822 }, // 197 tc_5b347363
  { 1, 928, 929, 13822, 13824 }, // 198 tc_3d14a17b
  { 1, 928, 929, 13824, 13825 }, // 199 tc_3fbf1042
  { 1, 928, 929, 13825, 13826 }, // 200 tc_63567288
  { 1, 928, 929, 13826, 13828 }, // 201 tc_59a7822c
  { 1, 928, 929, 0, 0 }, // 202 tc_937dd41c
  { 1, 925, 926, 0, 0 }, // 203 tc_a4ee89db
  { 1, 925, 926, 0, 0 }, // 204 tc_c818ff7f
  { 1, 925, 926, 13828, 13829 }, // 205 tc_1242dc2a
  { 1, 928, 929, 13829, 13831 }, // 206 tc_44d5a428
  { 1, 950, 952, 13831, 13834 }, // 207 tc_540c3da3
  { 1, 939, 941, 13834, 13838 }, // 208 tc_b091f1c6
  { 1, 952, 954, 13838, 13840 }, // 209 tc_5bf8afbb
  { 1, 954, 956, 13840, 13844 }, // 210 tc_2b4c548e
  { 1, 954, 956, 13844, 13849 }, // 211 tc_bb599486
  { 1, 956, 960, 13849, 13852 }, // 212 tc_a7e6707d
  { 1, 956, 960, 13852, 13856 }, // 213 tc_3c56e5ce
  { 1, 934, 937, 13856, 13860 }, // 214 tc_abe8c3b2
  { 1, 934, 937, 13860, 13865 }, // 215 tc_453fe68d
  { 1, 934, 937, 13865, 13869 }, // 216 tc_1ba8a0cd
  { 1, 960, 962, 13869, 13872 }, // 217 tc_52447ecc
  { 1, 960, 962, 13872, 13876 }, // 218 tc_3904b926
  { 1, 960, 962, 13876, 13881 }, // 219 tc_b9db8205
  { 1, 960, 962, 13881, 13885 }, // 220 tc_663c80a7
  { 1, 962, 966, 13885, 13888 }, // 221 tc_f21e8abb
  { 1, 962, 966, 13888, 13892 }, // 222 tc_131f1c81
  { 1, 962, 966, 13892, 13897 }, // 223 tc_c7039829
  { 1, 962, 966, 13897, 13901 }, // 224 tc_e2d2e9e5
  { 1, 966, 968, 13901, 13904 }, // 225 tc_ab23f776
  { 1, 966, 968, 13904, 13908 }, // 226 tc_7177e272
  { 1, 966, 968, 13908, 13913 }, // 227 tc_e99d4c2e
  { 1, 966, 968, 13913, 13917 }, // 228 tc_6942b6e0
  { 1, 941, 944, 13917, 13921 }, // 229 tc_a02a10a8
  { 1, 941, 944, 13921, 13926 }, // 230 tc_54a0dc47
  { 1, 941, 944, 13926, 13930 }, // 231 tc_447d9895
  { 1, 941, 944, 13930, 13935 }, // 232 tc_191381c1
  { 1, 941, 944, 13935, 13939 }, // 233 tc_3e2aaafc
  { 1, 966, 968, 13939, 13941 }, // 234 tc_3ce09744
  { 1, 966, 968, 13941, 13944 }, // 235 tc_20a4bbec
  { 1, 939, 941, 13944, 13946 }, // 236 tc_5cdf8c84
  { 1, 968, 970, 13946, 13948 }, // 237 tc_2a698a03
  { 1, 939, 941, 13948, 13951 }, // 238 tc_c127de3a
  { 1, 970, 972, 13951, 13954 }, // 239 tc_05ca8cfd
  { 1, 954, 956, 13954, 13957 }, // 240 tc_d8287c14
  { 1, 930, 932, 13957, 13961 }, // 241 tc_257f6f7c
  { 1, 930, 932, 13961, 13966 }, // 242 tc_7e6a3e89
  { 1, 930, 932, 13966, 13970 }, // 243 tc_e35c1e93
  { 1, 954, 956, 13970, 13974 }, // 244 tc_08a4f1b6
  { 1, 930, 932, 13974, 13978 }, // 245 tc_57a4709c
  { 1, 952, 954, 13978, 13982 }, // 246 tc_56e64202
  { 1, 939, 941, 13982, 13985 }, // 247 tc_ac4046bc
  { 1, 939, 941, 13985, 13989 }, // 248 tc_2e8f5f6e
  { 1, 970, 972, 13989, 13992 }, // 249 tc_7417e785
  { 1, 970, 972, 13992, 13996 }, // 250 tc_309dbb4f
  { 1, 972, 974, 13996, 14000 }, // 251 tc_df80eeb0
  { 1, 970, 972, 14000, 14004 }, // 252 tc_16ff9ef8
  { 1, 924, 925, 14004, 14006 }, // 253 tc_e2fdd6e6
  { 1, 970, 972, 14006, 14008 }, // 254 tc_51d0ecc3
  { 1, 924, 925, 14008, 14011 }, // 255 tc_531b383c
  { 1, 972, 974, 14011, 14013 }, // 256 tc_04da405a
  { 1, 939, 941, 14013, 14015 }, // 257 tc_3c8c15d0
  { 1, 954, 956, 14015, 14017 }, // 258 tc_0afc8be9
  { 1, 972, 974, 14017, 14022 }, // 259 tc_561aaa58
  { 1, 952, 954, 14022, 14024 }, // 260 tc_946013d8
  { 1, 952, 954, 14024, 14027 }, // 261 tc_46d6c3e0
  { 1, 972, 974, 14027, 14031 }, // 262 tc_87adc037
  { 1, 939, 941, 14031, 14035 }, // 263 tc_a19b9305
  { 1, 939, 941, 14035, 14038 }, // 264 tc_649072c2
  { 1, 954, 956, 14038, 14041 }, // 265 tc_0b04c6c7
  { 1, 954, 956, 14041, 14045 }, // 266 tc_660769f1
  { 1, 939, 941, 14045, 14048 }, // 267 tc_dcca380f
  { 1, 939, 941, 14048, 14052 }, // 268 tc_72e2b393
  { 1, 939, 941, 14052, 14055 }, // 269 tc_73efe966
  { 1, 939, 941, 14055, 14058 }, // 270 tc_cda936da
  { 1, 934, 937, 14058, 14061 }, // 271 tc_a28f32b5
  { 1, 934, 937, 14061, 14065 }, // 272 tc_7d68d5c2
  { 1, 974, 977, 14065, 14068 }, // 273 tc_7095ecba
  { 1, 974, 977, 14068, 14072 }, // 274 tc_a69eeee1
  { 1, 977, 979, 0, 0 }, // 275 tc_1381a97c
  { 1, 977, 979, 14072, 14073 }, // 276 tc_e3f68a46
  { 1, 979, 981, 14073, 14076 }, // 277 tc_f1de44ef
  { 1, 972, 974, 14076, 14081 }, // 278 tc_9d1dc972
  { 1, 979, 981, 14081, 14085 }, // 279 tc_90bcc1db
  { 1, 981, 984, 14085, 14088 }, // 280 tc_cd94bfe0
  { 1, 981, 984, 14088, 14092 }, // 281 tc_15fdf750
  { 1, 954, 956, 14092, 14096 }, // 282 tc_1ad8a370
  { 1, 954, 956, 14096, 14101 }, // 283 tc_e675c45a
  { 1, 939, 941, 14101, 14105 }, // 284 tc_37820f4c
  { 1, 984, 986, 14105, 14108 }, // 285 tc_61bf7c03
  { 1, 984, 986, 14108, 14112 }, // 286 tc_933f2b39
  { 1, 984, 986, 14112, 14116 }, // 287 tc_26a377fe
  { 1, 984, 986, 14116, 14121 }, // 288 tc_2d4051cd
  { 1, 952, 954, 14121, 14124 }, // 289 tc_6e7fa133
  { 1, 930, 932, 14124, 14127 }, // 290 tc_8772086c
  { 1, 932, 934, 14127, 14129 }, // 291 tc_b4416217
  { 1, 941, 944, 14129, 14133 }, // 292 tc_9f363d21
  { 1, 941, 944, 14133, 14138 }, // 293 tc_8e420e4d
  { 1, 986, 989, 14138, 14142 }, // 294 tc_7273323b
  { 1, 986, 989, 14142, 14147 }, // 295 tc_58d21193
  { 1, 932, 934, 14147, 14151 }, // 296 tc_71646d06
  { 1, 972, 974, 14151, 14154 }, // 297 tc_2c745bb8
  { 1, 977, 979, 14154, 14155 }, // 298 tc_b28e51aa
  { 1, 977, 979, 14155, 14157 }, // 299 tc_767c4e9d
  { 1, 989, 991, 14157, 14159 }, // 300 tc_e699ae41
  { 1, 989, 991, 14159, 14162 }, // 301 tc_a0dbea28
  { 1, 989, 991, 14162, 14165 }, // 302 tc_dd5b0695
  { 1, 989, 991, 14165, 14169 }, // 303 tc_3ad719fb
  { 1, 925, 926, 0, 0 }, // 304 tc_77f94a5e
  { 1, 929, 930, 0, 0 }, // 305 tc_55255f2b
  { 1, 929, 930, 14169, 14170 }, // 306 tc_0a43be35
  { 1, 925, 926, 14170, 14171 }, // 307 tc_b1ae5f67
  { 1, 925, 926, 14171, 14172 }, // 308 tc_d234b61a
  { 1, 925, 926, 14172, 14174 }, // 309 tc_2237d952
  { 1, 925, 926, 0, 0 }, // 310 tc_78f87ed3
  { 1, 925, 926, 14174, 14176 }, // 311 tc_a724463d
  { 1, 925, 926, 14176, 14178 }, // 312 tc_6fb52018
  { 1, 929, 930, 14178, 14180 }, // 313 tc_46c18ecf
  { 1, 927, 928, 14180, 14182 }, // 314 tc_9b20a062
  { 1, 927, 928, 14182, 14184 }, // 315 tc_5a222e89
  { 1, 927, 928, 14184, 14185 }, // 316 tc_0ba0d5da
  { 1, 927, 928, 14185, 14186 }, // 317 tc_7d6a2568
  { 1, 927, 928, 14186, 14188 }, // 318 tc_759e57be
  { 1, 927, 928, 14188, 14190 }, // 319 tc_139ef484
  { 1, 927, 928, 0, 0 }, // 320 tc_9b34f5e0
  { 1, 929, 930, 0, 0 }, // 321 tc_7f58404a
  { 1, 925, 926, 0, 0 }, // 322 tc_b3d46584
  { 1, 929, 930, 14190, 14192 }, // 323 tc_d71ea8fa
  { 1, 929, 930, 14192, 14194 }, // 324 tc_6aa823ab
  { 1, 929, 930, 14194, 14196 }, // 325 tc_b2196a3f
  { 1, 929, 930, 14196, 14197 }, // 326 tc_2c3e17fc
  { 1, 929, 930, 14197, 14200 }, // 327 tc_27106296
  { 1, 925, 926, 14200, 14202 }, // 328 tc_a3070909
  { 1, 925, 926, 14202, 14204 }, // 329 tc_512b1653
  { 1, 929, 930, 14204, 14205 }, // 330 tc_d7718fbe
  { 1, 929, 930, 14205, 14208 }, // 331 tc_bb78483e
  { 1, 929, 930, 14208, 14209 }, // 332 tc_54f0cee2
  { 1, 929, 930, 14209, 14211 }, // 333 tc_28e55c6f
  { 1, 925, 926, 14211, 14212 }, // 334 tc_4bf903b0
  { 1, 925, 926, 14212, 14213 }, // 335 tc_7c28bd7e
  { 0, 0, 0, 0, 0 }, // 336 tc_invalid
  { 0, uint16_t(~0U), uint16_t(~0U), uint16_t(~0U), uint16_t(~0U) }// end marker
};

// ===============================================================
// Data tables for the new per-operand machine model.

// {ProcResourceIdx, ReleaseAtCycle, AcquireAtCycle}
extern const llvm_ks::MCWriteProcResEntry HexagonWriteProcResTable[] = {
  { 0,  0,  0 }, // Invalid
}; // HexagonWriteProcResTable

// {Cycles, WriteResourceID}
extern const llvm_ks::MCWriteLatencyEntry HexagonWriteLatencyTable[] = {
  { 0,  0}, // Invalid
}; // HexagonWriteLatencyTable

// {UseIdx, WriteResourceID, Cycles}
extern const llvm_ks::MCReadAdvanceEntry HexagonReadAdvanceTable[] = {
  {0,  0,  0}, // Invalid
}; // HexagonReadAdvanceTable

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
static constexpr char HexagonSchedClassNamesStorage[] =
  "\0"
  "InvalidSchedClass\0"
  ;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static constexpr llvm_ks::StringTable
HexagonSchedClassNames = HexagonSchedClassNamesStorage;

extern const llvm_ks::MCSchedModel HexagonSchedModels[] = {
{ // NoSchedModel
  MCSchedModel::DefaultIssueWidth,
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  MCSchedModel::DefaultLoadLatency,
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  0, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  nullptr, // No Itinerary
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV60
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  1, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV60,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV5
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  2, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV5,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV55
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  3, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV55,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV62
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  4, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV62,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV65
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  5, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV65,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV66
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  6, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV66,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV67
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  7, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV67,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV67T
  3, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  8, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV67T,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV68
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  9, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV68,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV69
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  10, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV69,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV71
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  11, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV71,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV71T
  3, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  12, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV71T,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV73
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  13, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV73,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV75
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  14, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV75,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV79
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  15, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV79,
  nullptr // No extra processor descriptor
  },
{ // HexagonModelV81
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  false, // EnableIntervals
  16, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  DBGVAL_OR_NULLPTR(&HexagonSchedClassNames), // SchedClassNames
  HexagonItinerariesV81,
  nullptr // No extra processor descriptor
  },
};

#undef DBGFIELD

#undef DBGVAL_OR_NULLPTR

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 17, 187> HexagonSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 17 + 1, { { { 0xdce00000007ULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 16 + 9, { { { 0xdce00000001ULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 15 + 19, { { { 0xdce00000003ULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 14 + 30, { { { 0xdce00000007ULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 13 + 41, { { { 0xdce0000000fULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 12 + 52, { { { 0x5ee0000001fULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 11 + 63, { { { 0x5ee0000003fULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 10 + 74, { { { 0x5ee0000007fULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 9 + 85, { { { 0x5640000407fULL, 0x18000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 8 },
   { sizeof(SubtargetSubTypeKV) * 8 + 97, { { { 0x5ee000000ffULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 9 },
   { sizeof(SubtargetSubTypeKV) * 7 + 108, { { { 0x5ee000001ffULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 10 },
   { sizeof(SubtargetSubTypeKV) * 6 + 119, { { { 0x5ee000003ffULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 11 },
   { sizeof(SubtargetSubTypeKV) * 5 + 130, { { { 0x564000043ffULL, 0x18000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 12 },
   { sizeof(SubtargetSubTypeKV) * 4 + 142, { { { 0x5ec000007ffULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 3 + 153, { { { 0x5ec00000fffULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 2 + 164, { { { 0x5ec00001fffULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 15 },
   { sizeof(SubtargetSubTypeKV) * 1 + 175, { { { 0x5ec00003fffULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 16 },
  },
    "\000generic\000hexagonv5\000hexagonv55\000hexagonv60\000hexagonv62\000h"
    "exagonv65\000hexagonv66\000hexagonv67\000hexagonv67t\000hexagonv68\000h"
    "exagonv69\000hexagonv71\000hexagonv71t\000hexagonv73\000hexagonv75\000h"
    "exagonv79\000hexagonv81\000"};

namespace Hexagon_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace Hexagon_MC
struct HexagonGenMCSubtargetInfo : public MCSubtargetInfo {
  HexagonGenMCSubtargetInfo(const Triple &TT,
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
    return Hexagon_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned HexagonGenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (FB[Hexagon::ExtensionHVX64B]) Modes |= (1 << 0);
  if (FB[Hexagon::ExtensionHVX128B]) Modes |= (1 << 1);
  return Modes;
}
unsigned HexagonGenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    Modes &= 3;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for ValueType were found!");
    return llvm_ks::countr_zero(Modes) + 1;
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

static inline MCSubtargetInfo *createHexagonMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new HexagonGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(HexagonSubTypeKVStorage.Strings), HexagonFeatureKVStorage.Features, HexagonSubTypeKVStorage.SubTypes, HexagonSchedModels, 
                      HexagonWriteProcResTable, HexagonWriteLatencyTable, HexagonReadAdvanceTable, 
                      HexagonStages, nullptr, nullptr);
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
void llvm_ks::HexagonSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[Hexagon::ArchV5] && HexagonArchVersion < Hexagon::ArchEnum::V5) HexagonArchVersion = Hexagon::ArchEnum::V5;
  if (Bits[Hexagon::ArchV55] && HexagonArchVersion < Hexagon::ArchEnum::V55) HexagonArchVersion = Hexagon::ArchEnum::V55;
  if (Bits[Hexagon::ArchV60] && HexagonArchVersion < Hexagon::ArchEnum::V60) HexagonArchVersion = Hexagon::ArchEnum::V60;
  if (Bits[Hexagon::ArchV62] && HexagonArchVersion < Hexagon::ArchEnum::V62) HexagonArchVersion = Hexagon::ArchEnum::V62;
  if (Bits[Hexagon::ArchV65] && HexagonArchVersion < Hexagon::ArchEnum::V65) HexagonArchVersion = Hexagon::ArchEnum::V65;
  if (Bits[Hexagon::ArchV66] && HexagonArchVersion < Hexagon::ArchEnum::V66) HexagonArchVersion = Hexagon::ArchEnum::V66;
  if (Bits[Hexagon::ArchV67] && HexagonArchVersion < Hexagon::ArchEnum::V67) HexagonArchVersion = Hexagon::ArchEnum::V67;
  if (Bits[Hexagon::ArchV68] && HexagonArchVersion < Hexagon::ArchEnum::V68) HexagonArchVersion = Hexagon::ArchEnum::V68;
  if (Bits[Hexagon::ArchV69] && HexagonArchVersion < Hexagon::ArchEnum::V69) HexagonArchVersion = Hexagon::ArchEnum::V69;
  if (Bits[Hexagon::ArchV71] && HexagonArchVersion < Hexagon::ArchEnum::V71) HexagonArchVersion = Hexagon::ArchEnum::V71;
  if (Bits[Hexagon::ArchV73] && HexagonArchVersion < Hexagon::ArchEnum::V73) HexagonArchVersion = Hexagon::ArchEnum::V73;
  if (Bits[Hexagon::ArchV75] && HexagonArchVersion < Hexagon::ArchEnum::V75) HexagonArchVersion = Hexagon::ArchEnum::V75;
  if (Bits[Hexagon::ArchV79] && HexagonArchVersion < Hexagon::ArchEnum::V79) HexagonArchVersion = Hexagon::ArchEnum::V79;
  if (Bits[Hexagon::ArchV81] && HexagonArchVersion < Hexagon::ArchEnum::V81) HexagonArchVersion = Hexagon::ArchEnum::V81;
  if (Bits[Hexagon::ExtensionAudio]) UseAudioOps = true;
  if (Bits[Hexagon::ExtensionHVX] && HexagonHVXVersion < Hexagon::ArchEnum::V60) HexagonHVXVersion = Hexagon::ArchEnum::V60;
  if (Bits[Hexagon::ExtensionHVX64B]) UseHVX64BOps = true;
  if (Bits[Hexagon::ExtensionHVX128B]) UseHVX128BOps = true;
  if (Bits[Hexagon::ExtensionHVXIEEEFP]) UseHVXIEEEFPOps = true;
  if (Bits[Hexagon::ExtensionHVXQFloat]) UseHVXQFloatOps = true;
  if (Bits[Hexagon::ExtensionHVXV60] && HexagonHVXVersion < Hexagon::ArchEnum::V60) HexagonHVXVersion = Hexagon::ArchEnum::V60;
  if (Bits[Hexagon::ExtensionHVXV62] && HexagonHVXVersion < Hexagon::ArchEnum::V62) HexagonHVXVersion = Hexagon::ArchEnum::V62;
  if (Bits[Hexagon::ExtensionHVXV65] && HexagonHVXVersion < Hexagon::ArchEnum::V65) HexagonHVXVersion = Hexagon::ArchEnum::V65;
  if (Bits[Hexagon::ExtensionHVXV66] && HexagonHVXVersion < Hexagon::ArchEnum::V66) HexagonHVXVersion = Hexagon::ArchEnum::V66;
  if (Bits[Hexagon::ExtensionHVXV67] && HexagonHVXVersion < Hexagon::ArchEnum::V67) HexagonHVXVersion = Hexagon::ArchEnum::V67;
  if (Bits[Hexagon::ExtensionHVXV68] && HexagonHVXVersion < Hexagon::ArchEnum::V68) HexagonHVXVersion = Hexagon::ArchEnum::V68;
  if (Bits[Hexagon::ExtensionHVXV69] && HexagonHVXVersion < Hexagon::ArchEnum::V69) HexagonHVXVersion = Hexagon::ArchEnum::V69;
  if (Bits[Hexagon::ExtensionHVXV71] && HexagonHVXVersion < Hexagon::ArchEnum::V71) HexagonHVXVersion = Hexagon::ArchEnum::V71;
  if (Bits[Hexagon::ExtensionHVXV73] && HexagonHVXVersion < Hexagon::ArchEnum::V73) HexagonHVXVersion = Hexagon::ArchEnum::V73;
  if (Bits[Hexagon::ExtensionHVXV75] && HexagonHVXVersion < Hexagon::ArchEnum::V75) HexagonHVXVersion = Hexagon::ArchEnum::V75;
  if (Bits[Hexagon::ExtensionHVXV79] && HexagonHVXVersion < Hexagon::ArchEnum::V79) HexagonHVXVersion = Hexagon::ArchEnum::V79;
  if (Bits[Hexagon::ExtensionHVXV81] && HexagonHVXVersion < Hexagon::ArchEnum::V81) HexagonHVXVersion = Hexagon::ArchEnum::V81;
  if (Bits[Hexagon::ExtensionZReg]) UseZRegOps = true;
  if (Bits[Hexagon::FeatureCabac]) UseCabac = false;
  if (Bits[Hexagon::FeatureCompound]) UseCompound = true;
  if (Bits[Hexagon::FeatureDuplex]) EnableDuplex = true;
  if (Bits[Hexagon::FeatureLongCalls]) UseLongCalls = true;
  if (Bits[Hexagon::FeatureMemNoShuf]) HasMemNoShuf = false;
  if (Bits[Hexagon::FeatureMemops]) UseMemops = true;
  if (Bits[Hexagon::FeatureNVJ]) UseNewValueJumps = true;
  if (Bits[Hexagon::FeatureNVS]) UseNewValueStores = true;
  if (Bits[Hexagon::FeatureNoreturnStackElim]) NoreturnStackElim = true;
  if (Bits[Hexagon::FeaturePackets]) UsePackets = true;
  if (Bits[Hexagon::FeaturePreV65]) HasPreV65 = true;
  if (Bits[Hexagon::FeatureReservedR6]) UserReservedRegister[Hexagon::R6] = true;
  if (Bits[Hexagon::FeatureReservedR7]) UserReservedRegister[Hexagon::R7] = true;
  if (Bits[Hexagon::FeatureReservedR8]) UserReservedRegister[Hexagon::R8] = true;
  if (Bits[Hexagon::FeatureReservedR9]) UserReservedRegister[Hexagon::R9] = true;
  if (Bits[Hexagon::FeatureReservedR10]) UserReservedRegister[Hexagon::R10] = true;
  if (Bits[Hexagon::FeatureReservedR11]) UserReservedRegister[Hexagon::R11] = true;
  if (Bits[Hexagon::FeatureReservedR12]) UserReservedRegister[Hexagon::R12] = true;
  if (Bits[Hexagon::FeatureReservedR13]) UserReservedRegister[Hexagon::R13] = true;
  if (Bits[Hexagon::FeatureReservedR14]) UserReservedRegister[Hexagon::R14] = true;
  if (Bits[Hexagon::FeatureReservedR15]) UserReservedRegister[Hexagon::R15] = true;
  if (Bits[Hexagon::FeatureReservedR16]) UserReservedRegister[Hexagon::R16] = true;
  if (Bits[Hexagon::FeatureReservedR17]) UserReservedRegister[Hexagon::R17] = true;
  if (Bits[Hexagon::FeatureReservedR18]) UserReservedRegister[Hexagon::R18] = true;
  if (Bits[Hexagon::FeatureReservedR19]) UserReservedRegister[Hexagon::R19] = true;
  if (Bits[Hexagon::FeatureReservedR20]) UserReservedRegister[Hexagon::R20] = true;
  if (Bits[Hexagon::FeatureReservedR21]) UserReservedRegister[Hexagon::R21] = true;
  if (Bits[Hexagon::FeatureReservedR22]) UserReservedRegister[Hexagon::R22] = true;
  if (Bits[Hexagon::FeatureReservedR23]) UserReservedRegister[Hexagon::R23] = true;
  if (Bits[Hexagon::FeatureReservedR24]) UserReservedRegister[Hexagon::R24] = true;
  if (Bits[Hexagon::FeatureReservedR25]) UserReservedRegister[Hexagon::R25] = true;
  if (Bits[Hexagon::FeatureReservedR26]) UserReservedRegister[Hexagon::R26] = true;
  if (Bits[Hexagon::FeatureReservedR27]) UserReservedRegister[Hexagon::R27] = true;
  if (Bits[Hexagon::FeatureReservedR28]) UserReservedRegister[Hexagon::R28] = true;
  if (Bits[Hexagon::FeatureSCSRegR16]) SCSPointerRegister[Hexagon::R16] = true;
  if (Bits[Hexagon::FeatureSCSRegR17]) SCSPointerRegister[Hexagon::R17] = true;
  if (Bits[Hexagon::FeatureSCSRegR18]) SCSPointerRegister[Hexagon::R18] = true;
  if (Bits[Hexagon::FeatureSCSRegR19]) SCSPointerRegister[Hexagon::R19] = true;
  if (Bits[Hexagon::FeatureSCSRegR20]) SCSPointerRegister[Hexagon::R20] = true;
  if (Bits[Hexagon::FeatureSCSRegR21]) SCSPointerRegister[Hexagon::R21] = true;
  if (Bits[Hexagon::FeatureSCSRegR22]) SCSPointerRegister[Hexagon::R22] = true;
  if (Bits[Hexagon::FeatureSCSRegR23]) SCSPointerRegister[Hexagon::R23] = true;
  if (Bits[Hexagon::FeatureSCSRegR24]) SCSPointerRegister[Hexagon::R24] = true;
  if (Bits[Hexagon::FeatureSCSRegR25]) SCSPointerRegister[Hexagon::R25] = true;
  if (Bits[Hexagon::FeatureSCSRegR26]) SCSPointerRegister[Hexagon::R26] = true;
  if (Bits[Hexagon::FeatureSCSRegR27]) SCSPointerRegister[Hexagon::R27] = true;
  if (Bits[Hexagon::FeatureSmallData]) UseSmallData = true;
  if (Bits[Hexagon::ProcTinyCore] && HexagonProcFamily < TinyCore) HexagonProcFamily = TinyCore;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace Hexagon_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace Hexagon_MC
struct HexagonGenSubtargetInfo : public TargetSubtargetInfo {
  explicit HexagonGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class HexagonHwModeBits : unsigned {
    DefaultMode = 0,
    Hvx64 = (1 << 0),
    Hvx128 = (1 << 1),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/Hvx128),
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

extern const llvm_ks::StringRef HexagonNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<81, 2957> HexagonFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<17, 187> HexagonSubTypeKVStorage;
extern const llvm_ks::MCSchedModel HexagonSchedModels[];
extern const llvm_ks::MCWriteProcResEntry HexagonWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry HexagonWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry HexagonReadAdvanceTable[];
extern const llvm_ks::InstrStage HexagonStages[];
HexagonGenSubtargetInfo::HexagonGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(HexagonSubTypeKVStorage.Strings), ArrayRef(HexagonFeatureKVStorage.Features), ArrayRef(HexagonSubTypeKVStorage.SubTypes), HexagonSchedModels, 
                        HexagonWriteProcResTable, HexagonWriteLatencyTable, HexagonReadAdvanceTable, 
                        HexagonStages, nullptr, nullptr) {}

unsigned HexagonGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // HexagonGenSubtargetInfo::resolveSchedClass

unsigned HexagonGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return Hexagon_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // HexagonGenSubtargetInfo::resolveVariantSchedClass

unsigned HexagonGenSubtargetInfo::getHwModeSet() const {

  const auto *HST = static_cast<const HexagonSubtarget *>(this);

  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((HST->useHVX64BOps())) Modes |= (1 << 0);
  if ((HST->useHVX128BOps())) Modes |= (1 << 1);
  return Modes;
}
unsigned HexagonGenSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    Modes &= 3;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for ValueType were found!");
    return llvm_ks::countr_zero(Modes) + 1;
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
const FeatureBitset &HexagonGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &HexagonGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &HexagonGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

