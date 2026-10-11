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

namespace LoongArch {

enum {
  Feature32Bit = 0,
  Feature32S = 1,
  Feature64Bit = 2,
  FeatureBasicD = 3,
  FeatureBasicF = 4,
  FeatureDiv32 = 5,
  FeatureExtLASX = 6,
  FeatureExtLBT = 7,
  FeatureExtLSX = 8,
  FeatureExtLVZ = 9,
  FeatureFrecipe = 10,
  FeatureLAMCAS = 11,
  FeatureLAM_BH = 12,
  FeatureLD_SEQ_SA = 13,
  FeatureRelax = 14,
  FeatureSCQ = 15,
  FeatureUAL = 16,
  LaGlobalWithAbs = 17,
  LaGlobalWithPcrel = 18,
  LaLocalWithAbs = 19,
  TunePreferWInst = 20,
  NumSubtargetFeatures = 21
};

} // namespace LoongArch

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(Has32S, false, has32S)
GET_SUBTARGETINFO_MACRO(HasBasicD, false, hasBasicD)
GET_SUBTARGETINFO_MACRO(HasBasicF, false, hasBasicF)
GET_SUBTARGETINFO_MACRO(HasDiv32, false, hasDiv32)
GET_SUBTARGETINFO_MACRO(HasExtLASX, false, hasExtLASX)
GET_SUBTARGETINFO_MACRO(HasExtLBT, false, hasExtLBT)
GET_SUBTARGETINFO_MACRO(HasExtLSX, false, hasExtLSX)
GET_SUBTARGETINFO_MACRO(HasExtLVZ, false, hasExtLVZ)
GET_SUBTARGETINFO_MACRO(HasFrecipe, false, hasFrecipe)
GET_SUBTARGETINFO_MACRO(HasLA32, false, hasLA32)
GET_SUBTARGETINFO_MACRO(HasLA64, false, hasLA64)
GET_SUBTARGETINFO_MACRO(HasLAMCAS, false, hasLAMCAS)
GET_SUBTARGETINFO_MACRO(HasLAM_BH, false, hasLAM_BH)
GET_SUBTARGETINFO_MACRO(HasLD_SEQ_SA, false, hasLD_SEQ_SA)
GET_SUBTARGETINFO_MACRO(HasLaGlobalWithAbs, false, hasLaGlobalWithAbs)
GET_SUBTARGETINFO_MACRO(HasLaGlobalWithPcrel, false, hasLaGlobalWithPcrel)
GET_SUBTARGETINFO_MACRO(HasLaLocalWithAbs, false, hasLaLocalWithAbs)
GET_SUBTARGETINFO_MACRO(HasLinkerRelax, false, hasLinkerRelax)
GET_SUBTARGETINFO_MACRO(HasSCQ, false, hasSCQ)
GET_SUBTARGETINFO_MACRO(HasUAL, false, hasUAL)
GET_SUBTARGETINFO_MACRO(PreferWInst, false, preferWInst)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 21, 1017> LoongArchFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 21 + 1, sizeof(SubtargetFeatureKV) * 21 + 7, LoongArch::Feature32Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 56, sizeof(SubtargetFeatureKV) * 20 + 60, LoongArch::Feature32S, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 102, sizeof(SubtargetFeatureKV) * 19 + 108, LoongArch::Feature64Bit, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 157, sizeof(SubtargetFeatureKV) * 18 + 159, LoongArch::FeatureBasicD, { { { 0x10ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 197, sizeof(SubtargetFeatureKV) * 17 + 203, LoongArch::FeatureDiv32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 277, sizeof(SubtargetFeatureKV) * 16 + 279, LoongArch::FeatureBasicF, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 317, sizeof(SubtargetFeatureKV) * 15 + 325, LoongArch::FeatureFrecipe, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 378, sizeof(SubtargetFeatureKV) * 14 + 397, LoongArch::LaGlobalWithAbs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 424, sizeof(SubtargetFeatureKV) * 13 + 445, LoongArch::LaGlobalWithPcrel, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 474, sizeof(SubtargetFeatureKV) * 12 + 492, LoongArch::LaLocalWithAbs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 518, sizeof(SubtargetFeatureKV) * 11 + 525, LoongArch::FeatureLAM_BH, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 585, sizeof(SubtargetFeatureKV) * 10 + 592, LoongArch::FeatureLAMCAS, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 621, sizeof(SubtargetFeatureKV) * 9 + 626, LoongArch::FeatureExtLASX, { { { 0x100ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 668, sizeof(SubtargetFeatureKV) * 8 + 672, LoongArch::FeatureExtLBT, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 718, sizeof(SubtargetFeatureKV) * 7 + 728, LoongArch::FeatureLD_SEQ_SA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 784, sizeof(SubtargetFeatureKV) * 6 + 788, LoongArch::FeatureExtLSX, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 820, sizeof(SubtargetFeatureKV) * 5 + 824, LoongArch::FeatureExtLVZ, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 866, sizeof(SubtargetFeatureKV) * 4 + 880, LoongArch::TunePreferWInst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 914, sizeof(SubtargetFeatureKV) * 3 + 920, LoongArch::FeatureRelax, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 945, sizeof(SubtargetFeatureKV) * 2 + 949, LoongArch::FeatureSCQ, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 974, sizeof(SubtargetFeatureKV) * 1 + 978, LoongArch::FeatureUAL, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000" "32bit\000LA32 Basic Integer and Privilege Instruction Set\000" ""
    "32s\000LA32 Standard Basic Instruction Extension\000" "64bit\000LA64 Ba"
    "sic Integer and Privilege Instruction Set\000d\000'D' (Double-Precision"
    " Floating-Point)\000div32\000Assume div.w[u] and mod.w[u] can handle in"
    "puts that are not sign-extended\000f\000'F' (Single-Precision Floating-"
    "Point)\000frecipe\000Support frecipe.{s/d} and frsqrte.{s/d} instructio"
    "ns\000la-global-with-abs\000Expand la.global as la.abs\000la-global-wit"
    "h-pcrel\000Expand la.global as la.pcrel\000la-local-with-abs\000Expand "
    "la.local as la.abs\000lam-bh\000Support amswap[_db].{b/h} and amadd[_db"
    "].{b/h} instructions\000lamcas\000Support amcas[_db].{b/h/w/d}\000lasx\000"
    "'LASX' (Loongson Advanced SIMD Extension)\000lbt\000'LBT' (Loongson Bin"
    "ary Translation Extension)\000ld-seq-sa\000Don't use a same-address loa"
    "d-load barrier (dbar 0x700)\000lsx\000'LSX' (Loongson SIMD Extension)\000"
    "lvz\000'LVZ' (Loongson Virtualization Extension)\000prefer-w-inst\000Pr"
    "efer instructions with W suffix\000relax\000Enable Linker relaxation\000"
    "scq\000Support sc.q instruction\000ual\000Allow memory accesses to be u"
    "naligned\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 7, 72> LoongArchSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 7 + 1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 6 + 9, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 5 + 22, { { { 0x10104ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 4 + 35, { { { 0x102c4ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 3 + 41, { { { 0x1bee4ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 2 + 47, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 1 + 59, { { { 0x1000cULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
  },
    "\000generic\000generic-la32\000generic-la64\000la464\000la664\000loonga"
    "rch32\000loongarch64\000"};

namespace LoongArch_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace LoongArch_MC
struct LoongArchGenMCSubtargetInfo : public MCSubtargetInfo {
  LoongArchGenMCSubtargetInfo(const Triple &TT,
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
    return LoongArch_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned LoongArchGenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (FB[LoongArch::Feature64Bit]) Modes |= (1 << 0);
  return Modes;
}
unsigned LoongArchGenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    Modes &= 1;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for ValueType were found!");
    return llvm_ks::countr_zero(Modes) + 1;
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

static inline MCSubtargetInfo *createLoongArchMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new LoongArchGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(LoongArchSubTypeKVStorage.Strings), LoongArchFeatureKVStorage.Features, LoongArchSubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::LoongArchSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[LoongArch::Feature32Bit]) HasLA32 = true;
  if (Bits[LoongArch::Feature32S]) Has32S = true;
  if (Bits[LoongArch::Feature64Bit]) HasLA64 = true;
  if (Bits[LoongArch::FeatureBasicD]) HasBasicD = true;
  if (Bits[LoongArch::FeatureBasicF]) HasBasicF = true;
  if (Bits[LoongArch::FeatureDiv32]) HasDiv32 = true;
  if (Bits[LoongArch::FeatureExtLASX]) HasExtLASX = true;
  if (Bits[LoongArch::FeatureExtLBT]) HasExtLBT = true;
  if (Bits[LoongArch::FeatureExtLSX]) HasExtLSX = true;
  if (Bits[LoongArch::FeatureExtLVZ]) HasExtLVZ = true;
  if (Bits[LoongArch::FeatureFrecipe]) HasFrecipe = true;
  if (Bits[LoongArch::FeatureLAMCAS]) HasLAMCAS = true;
  if (Bits[LoongArch::FeatureLAM_BH]) HasLAM_BH = true;
  if (Bits[LoongArch::FeatureLD_SEQ_SA]) HasLD_SEQ_SA = true;
  if (Bits[LoongArch::FeatureRelax]) HasLinkerRelax = true;
  if (Bits[LoongArch::FeatureSCQ]) HasSCQ = true;
  if (Bits[LoongArch::FeatureUAL]) HasUAL = true;
  if (Bits[LoongArch::LaGlobalWithAbs]) HasLaGlobalWithAbs = true;
  if (Bits[LoongArch::LaGlobalWithPcrel]) HasLaGlobalWithPcrel = true;
  if (Bits[LoongArch::LaLocalWithAbs]) HasLaLocalWithAbs = true;
  if (Bits[LoongArch::TunePreferWInst]) PreferWInst = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace LoongArch_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace LoongArch_MC
struct LoongArchGenSubtargetInfo : public TargetSubtargetInfo {
  explicit LoongArchGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class LoongArchHwModeBits : unsigned {
    DefaultMode = 0,
    LA64 = (1 << 0),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/LA64),
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

extern const llvm_ks::StringRef LoongArchNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<21, 1017> LoongArchFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<7, 72> LoongArchSubTypeKVStorage;
extern const llvm_ks::MCSchedModel LoongArchSchedModels[];
extern const llvm_ks::MCWriteProcResEntry LoongArchWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry LoongArchWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry LoongArchReadAdvanceTable[];
LoongArchGenSubtargetInfo::LoongArchGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(LoongArchSubTypeKVStorage.Strings), ArrayRef(LoongArchFeatureKVStorage.Features), ArrayRef(LoongArchSubTypeKVStorage.SubTypes), LoongArchSchedModels, 
                        LoongArchWriteProcResTable, LoongArchWriteLatencyTable, LoongArchReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned LoongArchGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // LoongArchGenSubtargetInfo::resolveSchedClass

unsigned LoongArchGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return LoongArch_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // LoongArchGenSubtargetInfo::resolveVariantSchedClass

unsigned LoongArchGenSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const auto *Subtarget =
      static_cast<const LoongArchSubtarget *>(this);
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((Subtarget->is64Bit())) Modes |= (1 << 0);
  return Modes;
}
unsigned LoongArchGenSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    Modes &= 1;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for ValueType were found!");
    return llvm_ks::countr_zero(Modes) + 1;
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
const FeatureBitset &LoongArchGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &LoongArchGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &LoongArchGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

