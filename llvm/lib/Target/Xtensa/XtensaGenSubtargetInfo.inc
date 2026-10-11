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

namespace Xtensa {

enum {
  FeatureBoolean = 0,
  FeatureCLAMPS = 1,
  FeatureCoprocessor = 2,
  FeatureDFPAccel = 3,
  FeatureDataCache = 4,
  FeatureDebug = 5,
  FeatureDensity = 6,
  FeatureDiv32 = 7,
  FeatureESP32S2Ops = 8,
  FeatureException = 9,
  FeatureExtendedL32R = 10,
  FeatureForcedAtomics = 11,
  FeatureHighPriInterrupts = 12,
  FeatureHighPriInterruptsLevel3 = 13,
  FeatureHighPriInterruptsLevel4 = 14,
  FeatureHighPriInterruptsLevel5 = 15,
  FeatureHighPriInterruptsLevel6 = 16,
  FeatureHighPriInterruptsLevel7 = 17,
  FeatureInterrupt = 18,
  FeatureLoop = 19,
  FeatureMAC16 = 20,
  FeatureMINMAX = 21,
  FeatureMiscSR = 22,
  FeatureMul16 = 23,
  FeatureMul32 = 24,
  FeatureMul32High = 25,
  FeatureNSA = 26,
  FeaturePRID = 27,
  FeatureRegionProtection = 28,
  FeatureRelocatableVector = 29,
  FeatureS32C1I = 30,
  FeatureSEXT = 31,
  FeatureSingleFloat = 32,
  FeatureTHREADPTR = 33,
  FeatureTimers1 = 34,
  FeatureTimers2 = 35,
  FeatureTimers3 = 36,
  FeatureWindowed = 37,
  NumSubtargetFeatures = 38
};

} // namespace Xtensa

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(HasBoolean, false, hasBoolean)
GET_SUBTARGETINFO_MACRO(HasCLAMPS, false, hasCLAMPS)
GET_SUBTARGETINFO_MACRO(HasCoprocessor, false, hasCoprocessor)
GET_SUBTARGETINFO_MACRO(HasDFPAccel, false, hasDFPAccel)
GET_SUBTARGETINFO_MACRO(HasDataCache, false, hasDataCache)
GET_SUBTARGETINFO_MACRO(HasDebug, false, hasDebug)
GET_SUBTARGETINFO_MACRO(HasDensity, false, hasDensity)
GET_SUBTARGETINFO_MACRO(HasDiv32, false, hasDiv32)
GET_SUBTARGETINFO_MACRO(HasESP32S2Ops, false, hasESP32S2Ops)
GET_SUBTARGETINFO_MACRO(HasException, false, hasException)
GET_SUBTARGETINFO_MACRO(HasExtendedL32R, false, hasExtendedL32R)
GET_SUBTARGETINFO_MACRO(HasForcedAtomics, false, hasForcedAtomics)
GET_SUBTARGETINFO_MACRO(HasHighPriInterrupts, false, hasHighPriInterrupts)
GET_SUBTARGETINFO_MACRO(HasHighPriInterruptsLevel3, false, hasHighPriInterruptsLevel3)
GET_SUBTARGETINFO_MACRO(HasHighPriInterruptsLevel4, false, hasHighPriInterruptsLevel4)
GET_SUBTARGETINFO_MACRO(HasHighPriInterruptsLevel5, false, hasHighPriInterruptsLevel5)
GET_SUBTARGETINFO_MACRO(HasHighPriInterruptsLevel6, false, hasHighPriInterruptsLevel6)
GET_SUBTARGETINFO_MACRO(HasHighPriInterruptsLevel7, false, hasHighPriInterruptsLevel7)
GET_SUBTARGETINFO_MACRO(HasInterrupt, false, hasInterrupt)
GET_SUBTARGETINFO_MACRO(HasLoop, false, hasLoop)
GET_SUBTARGETINFO_MACRO(HasMAC16, false, hasMAC16)
GET_SUBTARGETINFO_MACRO(HasMINMAX, false, hasMINMAX)
GET_SUBTARGETINFO_MACRO(HasMiscSR, false, hasMiscSR)
GET_SUBTARGETINFO_MACRO(HasMul16, false, hasMul16)
GET_SUBTARGETINFO_MACRO(HasMul32, false, hasMul32)
GET_SUBTARGETINFO_MACRO(HasMul32High, false, hasMul32High)
GET_SUBTARGETINFO_MACRO(HasNSA, false, hasNSA)
GET_SUBTARGETINFO_MACRO(HasPRID, false, hasPRID)
GET_SUBTARGETINFO_MACRO(HasRegionProtection, false, hasRegionProtection)
GET_SUBTARGETINFO_MACRO(HasRelocatableVector, false, hasRelocatableVector)
GET_SUBTARGETINFO_MACRO(HasS32C1I, false, hasS32C1I)
GET_SUBTARGETINFO_MACRO(HasSEXT, false, hasSEXT)
GET_SUBTARGETINFO_MACRO(HasSingleFloat, false, hasSingleFloat)
GET_SUBTARGETINFO_MACRO(HasTHREADPTR, false, hasTHREADPTR)
GET_SUBTARGETINFO_MACRO(HasTimers1, false, hasTimers1)
GET_SUBTARGETINFO_MACRO(HasTimers2, false, hasTimers2)
GET_SUBTARGETINFO_MACRO(HasTimers3, false, hasTimers3)
GET_SUBTARGETINFO_MACRO(HasWindowed, false, hasWindowed)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 38, 1665> XtensaFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 38 + 1, sizeof(SubtargetFeatureKV) * 38 + 6, Xtensa::FeatureBoolean, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 38, sizeof(SubtargetFeatureKV) * 37 + 45, Xtensa::FeatureCLAMPS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 73, sizeof(SubtargetFeatureKV) * 36 + 85, Xtensa::FeatureCoprocessor, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 118, sizeof(SubtargetFeatureKV) * 35 + 125, Xtensa::FeatureDataCache, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 157, sizeof(SubtargetFeatureKV) * 34 + 163, Xtensa::FeatureDebug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 190, sizeof(SubtargetFeatureKV) * 33 + 198, Xtensa::FeatureDensity, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 226, sizeof(SubtargetFeatureKV) * 32 + 235, Xtensa::FeatureDFPAccel, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 282, sizeof(SubtargetFeatureKV) * 31 + 288, Xtensa::FeatureDiv32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 315, sizeof(SubtargetFeatureKV) * 30 + 326, Xtensa::FeatureESP32S2Ops, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 364, sizeof(SubtargetFeatureKV) * 29 + 374, Xtensa::FeatureException, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 405, sizeof(SubtargetFeatureKV) * 28 + 418, Xtensa::FeatureExtendedL32R, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 453, sizeof(SubtargetFeatureKV) * 27 + 468, Xtensa::FeatureForcedAtomics, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 525, sizeof(SubtargetFeatureKV) * 26 + 528, Xtensa::FeatureSingleFloat, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 565, sizeof(SubtargetFeatureKV) * 25 + 583, Xtensa::FeatureHighPriInterrupts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 622, sizeof(SubtargetFeatureKV) * 24 + 647, Xtensa::FeatureHighPriInterruptsLevel3, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 686, sizeof(SubtargetFeatureKV) * 23 + 711, Xtensa::FeatureHighPriInterruptsLevel4, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 750, sizeof(SubtargetFeatureKV) * 22 + 775, Xtensa::FeatureHighPriInterruptsLevel5, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 814, sizeof(SubtargetFeatureKV) * 21 + 839, Xtensa::FeatureHighPriInterruptsLevel6, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 878, sizeof(SubtargetFeatureKV) * 20 + 903, Xtensa::FeatureHighPriInterruptsLevel7, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 942, sizeof(SubtargetFeatureKV) * 19 + 952, Xtensa::FeatureInterrupt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 983, sizeof(SubtargetFeatureKV) * 18 + 988, Xtensa::FeatureLoop, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 1017, sizeof(SubtargetFeatureKV) * 17 + 1023, Xtensa::FeatureMAC16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 1056, sizeof(SubtargetFeatureKV) * 16 + 1063, Xtensa::FeatureMINMAX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 1091, sizeof(SubtargetFeatureKV) * 15 + 1098, Xtensa::FeatureMiscSR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 1136, sizeof(SubtargetFeatureKV) * 14 + 1142, Xtensa::FeatureMul16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 1169, sizeof(SubtargetFeatureKV) * 13 + 1175, Xtensa::FeatureMul32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 1202, sizeof(SubtargetFeatureKV) * 12 + 1212, Xtensa::FeatureMul32High, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 1243, sizeof(SubtargetFeatureKV) * 11 + 1247, Xtensa::FeatureNSA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 1272, sizeof(SubtargetFeatureKV) * 10 + 1277, Xtensa::FeaturePRID, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 1311, sizeof(SubtargetFeatureKV) * 9 + 1322, Xtensa::FeatureRegionProtection, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 1361, sizeof(SubtargetFeatureKV) * 8 + 1369, Xtensa::FeatureRelocatableVector, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 1409, sizeof(SubtargetFeatureKV) * 7 + 1416, Xtensa::FeatureS32C1I, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 1444, sizeof(SubtargetFeatureKV) * 6 + 1449, Xtensa::FeatureSEXT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 1482, sizeof(SubtargetFeatureKV) * 5 + 1492, Xtensa::FeatureTHREADPTR, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 1523, sizeof(SubtargetFeatureKV) * 4 + 1531, Xtensa::FeatureTimers1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 1554, sizeof(SubtargetFeatureKV) * 3 + 1562, Xtensa::FeatureTimers2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 1585, sizeof(SubtargetFeatureKV) * 2 + 1593, Xtensa::FeatureTimers3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 1616, sizeof(SubtargetFeatureKV) * 1 + 1625, Xtensa::FeatureWindowed, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000bool\000Enable Xtensa Boolean extension\000clamps\000Enable Xtensa "
    "CLAMPS option\000coprocessor\000Enable Xtensa Coprocessor option\000dca"
    "che\000Enable Xtensa Data Cache option\000debug\000Enable Xtensa Debug "
    "option\000density\000Enable Density instructions\000dfpaccel\000Enable "
    "Xtensa Double Precision FP acceleration\000div32\000Enable Xtensa Div32"
    " option\000esp32s2ops\000Support Xtensa esp32-s2 ISA extension\000excep"
    "tion\000Enable Xtensa Exception option\000extendedl32r\000Enable Xtensa"
    " Extended L32R option\000forced-atomics\000Assume that lock-free native"
    "-width atomics are available\000fp\000Enable Xtensa Single FP instructi"
    "ons\000highpriinterrupts\000Enable Xtensa HighPriInterrupts option\000h"
    "ighpriinterrupts-level3\000Enable Xtensa HighPriInterrupts Level3\000hi"
    "ghpriinterrupts-level4\000Enable Xtensa HighPriInterrupts Level4\000hig"
    "hpriinterrupts-level5\000Enable Xtensa HighPriInterrupts Level5\000high"
    "priinterrupts-level6\000Enable Xtensa HighPriInterrupts Level6\000highp"
    "riinterrupts-level7\000Enable Xtensa HighPriInterrupts Level7\000interr"
    "upt\000Enable Xtensa Interrupt option\000loop\000Enable Xtensa Loop ext"
    "ension\000mac16\000Enable Xtensa MAC16 instructions\000minmax\000Enable"
    " Xtensa MINMAX option\000miscsr\000Enable Xtensa Miscellaneous SR optio"
    "n\000mul16\000Enable Xtensa Mul16 option\000mul32\000Enable Xtensa Mul3"
    "2 option\000mul32high\000Enable Xtensa Mul32High option\000nsa\000Enabl"
    "e Xtensa NSA option\000prid\000Enable Xtensa Processor ID option\000reg"
    "protect\000Enable Xtensa Region Protection option\000rvector\000Enable "
    "Xtensa Relocatable Vector option\000s32c1i\000Enable Xtensa S32C1I opti"
    "on\000sext\000Enable Xtensa Sign Extend option\000threadptr\000Enable X"
    "tensa THREADPTR option\000timers1\000Enable Xtensa Timers 1\000timers2\000"
    "Enable Xtensa Timers 2\000timers3\000Enable Xtensa Timers 3\000windowed"
    "\000Enable Xtensa Windowed Register option\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 4, 32> XtensaSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 4 + 1, { { { 0x33fffe12ffULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 3 + 7, { { { 0x32bfe613f6ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 2 + 15, { { { 0x43d843660ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 1 + 23, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
  },
    "\000esp32\000esp32s2\000esp8266\000generic\000"};

namespace Xtensa_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace Xtensa_MC
struct XtensaGenMCSubtargetInfo : public MCSubtargetInfo {
  XtensaGenMCSubtargetInfo(const Triple &TT,
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
    return Xtensa_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
};

static inline MCSubtargetInfo *createXtensaMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new XtensaGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(XtensaSubTypeKVStorage.Strings), XtensaFeatureKVStorage.Features, XtensaSubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::XtensaSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[Xtensa::FeatureBoolean]) HasBoolean = true;
  if (Bits[Xtensa::FeatureCLAMPS]) HasCLAMPS = true;
  if (Bits[Xtensa::FeatureCoprocessor]) HasCoprocessor = true;
  if (Bits[Xtensa::FeatureDFPAccel]) HasDFPAccel = true;
  if (Bits[Xtensa::FeatureDataCache]) HasDataCache = true;
  if (Bits[Xtensa::FeatureDebug]) HasDebug = true;
  if (Bits[Xtensa::FeatureDensity]) HasDensity = true;
  if (Bits[Xtensa::FeatureDiv32]) HasDiv32 = true;
  if (Bits[Xtensa::FeatureESP32S2Ops]) HasESP32S2Ops = true;
  if (Bits[Xtensa::FeatureException]) HasException = true;
  if (Bits[Xtensa::FeatureExtendedL32R]) HasExtendedL32R = true;
  if (Bits[Xtensa::FeatureForcedAtomics]) HasForcedAtomics = true;
  if (Bits[Xtensa::FeatureHighPriInterrupts]) HasHighPriInterrupts = true;
  if (Bits[Xtensa::FeatureHighPriInterruptsLevel3]) HasHighPriInterruptsLevel3 = true;
  if (Bits[Xtensa::FeatureHighPriInterruptsLevel4]) HasHighPriInterruptsLevel4 = true;
  if (Bits[Xtensa::FeatureHighPriInterruptsLevel5]) HasHighPriInterruptsLevel5 = true;
  if (Bits[Xtensa::FeatureHighPriInterruptsLevel6]) HasHighPriInterruptsLevel6 = true;
  if (Bits[Xtensa::FeatureHighPriInterruptsLevel7]) HasHighPriInterruptsLevel7 = true;
  if (Bits[Xtensa::FeatureInterrupt]) HasInterrupt = true;
  if (Bits[Xtensa::FeatureLoop]) HasLoop = true;
  if (Bits[Xtensa::FeatureMAC16]) HasMAC16 = true;
  if (Bits[Xtensa::FeatureMINMAX]) HasMINMAX = true;
  if (Bits[Xtensa::FeatureMiscSR]) HasMiscSR = true;
  if (Bits[Xtensa::FeatureMul16]) HasMul16 = true;
  if (Bits[Xtensa::FeatureMul32]) HasMul32 = true;
  if (Bits[Xtensa::FeatureMul32High]) HasMul32High = true;
  if (Bits[Xtensa::FeatureNSA]) HasNSA = true;
  if (Bits[Xtensa::FeaturePRID]) HasPRID = true;
  if (Bits[Xtensa::FeatureRegionProtection]) HasRegionProtection = true;
  if (Bits[Xtensa::FeatureRelocatableVector]) HasRelocatableVector = true;
  if (Bits[Xtensa::FeatureS32C1I]) HasS32C1I = true;
  if (Bits[Xtensa::FeatureSEXT]) HasSEXT = true;
  if (Bits[Xtensa::FeatureSingleFloat]) HasSingleFloat = true;
  if (Bits[Xtensa::FeatureTHREADPTR]) HasTHREADPTR = true;
  if (Bits[Xtensa::FeatureTimers1]) HasTimers1 = true;
  if (Bits[Xtensa::FeatureTimers2]) HasTimers2 = true;
  if (Bits[Xtensa::FeatureTimers3]) HasTimers3 = true;
  if (Bits[Xtensa::FeatureWindowed]) HasWindowed = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace Xtensa_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace Xtensa_MC
struct XtensaGenSubtargetInfo : public TargetSubtargetInfo {
  explicit XtensaGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
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

extern const llvm_ks::StringRef XtensaNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<38, 1665> XtensaFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<4, 32> XtensaSubTypeKVStorage;
extern const llvm_ks::MCSchedModel XtensaSchedModels[];
extern const llvm_ks::MCWriteProcResEntry XtensaWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry XtensaWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry XtensaReadAdvanceTable[];
XtensaGenSubtargetInfo::XtensaGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(XtensaSubTypeKVStorage.Strings), ArrayRef(XtensaFeatureKVStorage.Features), ArrayRef(XtensaSubTypeKVStorage.SubTypes), XtensaSchedModels, 
                        XtensaWriteProcResTable, XtensaWriteLatencyTable, XtensaReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned XtensaGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // XtensaGenSubtargetInfo::resolveSchedClass

unsigned XtensaGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return Xtensa_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // XtensaGenSubtargetInfo::resolveVariantSchedClass

const FeatureBitset &XtensaGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &XtensaGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &XtensaGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

