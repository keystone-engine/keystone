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

namespace MSP430 {

enum {
  FeatureHWMult16 = 0,
  FeatureHWMult32 = 1,
  FeatureHWMultF5 = 2,
  FeatureX = 3,
  NumSubtargetFeatures = 4
};

} // namespace MSP430

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(ExtendedInsts, false, extendedInsts)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 4, 165> MSP430FeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 4 + 1, sizeof(SubtargetFeatureKV) * 4 + 5, MSP430::FeatureX, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 32, sizeof(SubtargetFeatureKV) * 3 + 41, MSP430::FeatureHWMult16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 75, sizeof(SubtargetFeatureKV) * 2 + 84, MSP430::FeatureHWMult32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 118, sizeof(SubtargetFeatureKV) * 1 + 127, MSP430::FeatureHWMultF5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000ext\000Enable MSP430-X extensions\000hwmult16\000Enable 16-bit hard"
    "ware multiplier\000hwmult32\000Enable 32-bit hardware multiplier\000hwm"
    "ultf5\000Enable F5 series hardware multiplier\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 3, 25> MSP430SubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 3 + 1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 2 + 9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 1 + 16, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
  },
    "\000generic\000msp430\000msp430x\000"};

namespace MSP430_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace MSP430_MC
struct MSP430GenMCSubtargetInfo : public MCSubtargetInfo {
  MSP430GenMCSubtargetInfo(const Triple &TT,
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
    return MSP430_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
};

static inline MCSubtargetInfo *createMSP430MCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new MSP430GenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(MSP430SubTypeKVStorage.Strings), MSP430FeatureKVStorage.Features, MSP430SubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::MSP430Subtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[MSP430::FeatureHWMult16] && HWMultMode < HWMult16) HWMultMode = HWMult16;
  if (Bits[MSP430::FeatureHWMult32] && HWMultMode < HWMult32) HWMultMode = HWMult32;
  if (Bits[MSP430::FeatureHWMultF5] && HWMultMode < HWMultF5) HWMultMode = HWMultF5;
  if (Bits[MSP430::FeatureX]) ExtendedInsts = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace MSP430_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace MSP430_MC
struct MSP430GenSubtargetInfo : public TargetSubtargetInfo {
  explicit MSP430GenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
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

extern const llvm_ks::StringRef MSP430Names[];
extern const llvm_ks::SubtargetFeatureKVStorage<4, 165> MSP430FeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<3, 25> MSP430SubTypeKVStorage;
extern const llvm_ks::MCSchedModel MSP430SchedModels[];
extern const llvm_ks::MCWriteProcResEntry MSP430WriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry MSP430WriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry MSP430ReadAdvanceTable[];
MSP430GenSubtargetInfo::MSP430GenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(MSP430SubTypeKVStorage.Strings), ArrayRef(MSP430FeatureKVStorage.Features), ArrayRef(MSP430SubTypeKVStorage.SubTypes), MSP430SchedModels, 
                        MSP430WriteProcResTable, MSP430WriteLatencyTable, MSP430ReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned MSP430GenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // MSP430GenSubtargetInfo::resolveSchedClass

unsigned MSP430GenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return MSP430_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // MSP430GenSubtargetInfo::resolveVariantSchedClass

const FeatureBitset &MSP430GenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &MSP430GenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &MSP430GenSubtargetInfo::getInlineMustMatchFeatures() const {
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

