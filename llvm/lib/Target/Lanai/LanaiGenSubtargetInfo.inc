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


} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO


#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {


// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 2, 14> LanaiSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 2 + 1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 1 + 9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
  },
    "\000generic\000v11\000"};

namespace Lanai_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace Lanai_MC
struct LanaiGenMCSubtargetInfo : public MCSubtargetInfo {
  LanaiGenMCSubtargetInfo(const Triple &TT,
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
    return Lanai_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
};

static inline MCSubtargetInfo *createLanaiMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new LanaiGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(LanaiSubTypeKVStorage.Strings), {}, LanaiSubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::LanaiSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace Lanai_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace Lanai_MC
struct LanaiGenSubtargetInfo : public TargetSubtargetInfo {
  explicit LanaiGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
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

extern const llvm_ks::StringRef LanaiNames[];
extern const llvm_ks::SubtargetSubTypeKVStorage<2, 14> LanaiSubTypeKVStorage;
extern const llvm_ks::MCSchedModel LanaiSchedModels[];
extern const llvm_ks::MCWriteProcResEntry LanaiWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry LanaiWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry LanaiReadAdvanceTable[];
extern const llvm_ks::InstrStage LanaiStages[];
extern const unsigned LanaiOperandCycles[];
extern const unsigned LanaiForwardingPaths[];
LanaiGenSubtargetInfo::LanaiGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(LanaiSubTypeKVStorage.Strings), {}, ArrayRef(LanaiSubTypeKVStorage.SubTypes), LanaiSchedModels, 
                        LanaiWriteProcResTable, LanaiWriteLatencyTable, LanaiReadAdvanceTable, 
                        LanaiStages, LanaiOperandCycles, LanaiForwardingPaths) {}

unsigned LanaiGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // LanaiGenSubtargetInfo::resolveSchedClass

unsigned LanaiGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return Lanai_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // LanaiGenSubtargetInfo::resolveVariantSchedClass

const FeatureBitset &LanaiGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &LanaiGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &LanaiGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

