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

namespace M68k {

enum {
  FeatureISA00 = 0,
  FeatureISA10 = 1,
  FeatureISA20 = 2,
  FeatureISA30 = 3,
  FeatureISA40 = 4,
  FeatureISA60 = 5,
  FeatureISA881 = 6,
  FeatureISA882 = 7,
  FeatureReserveA0 = 8,
  FeatureReserveA1 = 9,
  FeatureReserveA2 = 10,
  FeatureReserveA3 = 11,
  FeatureReserveA4 = 12,
  FeatureReserveA5 = 13,
  FeatureReserveA6 = 14,
  FeatureReserveD0 = 15,
  FeatureReserveD1 = 16,
  FeatureReserveD2 = 17,
  FeatureReserveD3 = 18,
  FeatureReserveD4 = 19,
  FeatureReserveD5 = 20,
  FeatureReserveD6 = 21,
  FeatureReserveD7 = 22,
  NumSubtargetFeatures = 23
};

} // namespace M68k

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO


#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 23, 751> M68kFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 23 + 1, sizeof(SubtargetFeatureKV) * 23 + 11, M68k::FeatureISA00, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 35, sizeof(SubtargetFeatureKV) * 22 + 45, M68k::FeatureISA10, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 69, sizeof(SubtargetFeatureKV) * 21 + 79, M68k::FeatureISA20, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 103, sizeof(SubtargetFeatureKV) * 20 + 113, M68k::FeatureISA30, { { { 0x4ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 137, sizeof(SubtargetFeatureKV) * 19 + 147, M68k::FeatureISA40, { { { 0x88ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 171, sizeof(SubtargetFeatureKV) * 18 + 181, M68k::FeatureISA60, { { { 0x10ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 205, sizeof(SubtargetFeatureKV) * 17 + 215, M68k::FeatureISA881, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 245, sizeof(SubtargetFeatureKV) * 16 + 255, M68k::FeatureISA882, { { { 0x40ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 285, sizeof(SubtargetFeatureKV) * 15 + 296, M68k::FeatureReserveA0, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 316, sizeof(SubtargetFeatureKV) * 14 + 327, M68k::FeatureReserveA1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 347, sizeof(SubtargetFeatureKV) * 13 + 358, M68k::FeatureReserveA2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 378, sizeof(SubtargetFeatureKV) * 12 + 389, M68k::FeatureReserveA3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 409, sizeof(SubtargetFeatureKV) * 11 + 420, M68k::FeatureReserveA4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 440, sizeof(SubtargetFeatureKV) * 10 + 451, M68k::FeatureReserveA5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 471, sizeof(SubtargetFeatureKV) * 9 + 482, M68k::FeatureReserveA6, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 502, sizeof(SubtargetFeatureKV) * 8 + 513, M68k::FeatureReserveD0, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 533, sizeof(SubtargetFeatureKV) * 7 + 544, M68k::FeatureReserveD1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 564, sizeof(SubtargetFeatureKV) * 6 + 575, M68k::FeatureReserveD2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 595, sizeof(SubtargetFeatureKV) * 5 + 606, M68k::FeatureReserveD3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 626, sizeof(SubtargetFeatureKV) * 4 + 637, M68k::FeatureReserveD4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 657, sizeof(SubtargetFeatureKV) * 3 + 668, M68k::FeatureReserveD5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 688, sizeof(SubtargetFeatureKV) * 2 + 699, M68k::FeatureReserveD6, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 719, sizeof(SubtargetFeatureKV) * 1 + 730, M68k::FeatureReserveD7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000isa-68000\000Is M68000 ISA supported\000isa-68010\000Is M68010 ISA "
    "supported\000isa-68020\000Is M68020 ISA supported\000isa-68030\000Is M6"
    "8030 ISA supported\000isa-68040\000Is M68040 ISA supported\000isa-68060"
    "\000Is M68060 ISA supported\000isa-68881\000Is M68881 (FPU) ISA support"
    "ed\000isa-68882\000Is M68882 (FPU) ISA supported\000reserve-a0\000Reser"
    "ve A0 register\000reserve-a1\000Reserve A1 register\000reserve-a2\000Re"
    "serve A2 register\000reserve-a3\000Reserve A3 register\000reserve-a4\000"
    "Reserve A4 register\000reserve-a5\000Reserve A5 register\000reserve-a6\000"
    "Reserve A6 register\000reserve-d0\000Reserve D0 register\000reserve-d1\000"
    "Reserve D1 register\000reserve-d2\000Reserve D2 register\000reserve-d3\000"
    "Reserve D3 register\000reserve-d4\000Reserve D4 register\000reserve-d5\000"
    "Reserve D5 register\000reserve-d6\000Reserve D6 register\000reserve-d7\000"
    "Reserve D7 register\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 7, 52> M68kSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 7 + 1, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 6 + 8, { { { 0x2ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 5 + 15, { { { 0x4ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 4 + 22, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 3 + 29, { { { 0x10ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 2 + 36, { { { 0x20ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 1 + 43, { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
  },
    "\000M68000\000M68010\000M68020\000M68030\000M68040\000M68060\000generic"
    "\000"};

namespace M68k_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace M68k_MC
struct M68kGenMCSubtargetInfo : public MCSubtargetInfo {
  M68kGenMCSubtargetInfo(const Triple &TT,
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
    return M68k_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
};

static inline MCSubtargetInfo *createM68kMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new M68kGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(M68kSubTypeKVStorage.Strings), M68kFeatureKVStorage.Features, M68kSubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::M68kSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[M68k::FeatureISA00] && SubtargetKind < M00) SubtargetKind = M00;
  if (Bits[M68k::FeatureISA10] && SubtargetKind < M10) SubtargetKind = M10;
  if (Bits[M68k::FeatureISA20] && SubtargetKind < M20) SubtargetKind = M20;
  if (Bits[M68k::FeatureISA30] && SubtargetKind < M30) SubtargetKind = M30;
  if (Bits[M68k::FeatureISA40] && SubtargetKind < M40) SubtargetKind = M40;
  if (Bits[M68k::FeatureISA60] && SubtargetKind < M60) SubtargetKind = M60;
  if (Bits[M68k::FeatureISA881] && FPUKind < M881) FPUKind = M881;
  if (Bits[M68k::FeatureISA882] && FPUKind < M882) FPUKind = M882;
  if (Bits[M68k::FeatureReserveA0]) UserReservedRegister[M68k::A0] = true;
  if (Bits[M68k::FeatureReserveA1]) UserReservedRegister[M68k::A1] = true;
  if (Bits[M68k::FeatureReserveA2]) UserReservedRegister[M68k::A2] = true;
  if (Bits[M68k::FeatureReserveA3]) UserReservedRegister[M68k::A3] = true;
  if (Bits[M68k::FeatureReserveA4]) UserReservedRegister[M68k::A4] = true;
  if (Bits[M68k::FeatureReserveA5]) UserReservedRegister[M68k::A5] = true;
  if (Bits[M68k::FeatureReserveA6]) UserReservedRegister[M68k::A6] = true;
  if (Bits[M68k::FeatureReserveD0]) UserReservedRegister[M68k::D0] = true;
  if (Bits[M68k::FeatureReserveD1]) UserReservedRegister[M68k::D1] = true;
  if (Bits[M68k::FeatureReserveD2]) UserReservedRegister[M68k::D2] = true;
  if (Bits[M68k::FeatureReserveD3]) UserReservedRegister[M68k::D3] = true;
  if (Bits[M68k::FeatureReserveD4]) UserReservedRegister[M68k::D4] = true;
  if (Bits[M68k::FeatureReserveD5]) UserReservedRegister[M68k::D5] = true;
  if (Bits[M68k::FeatureReserveD6]) UserReservedRegister[M68k::D6] = true;
  if (Bits[M68k::FeatureReserveD7]) UserReservedRegister[M68k::D7] = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace M68k_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace M68k_MC
struct M68kGenSubtargetInfo : public TargetSubtargetInfo {
  explicit M68kGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
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

extern const llvm_ks::StringRef M68kNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<23, 751> M68kFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<7, 52> M68kSubTypeKVStorage;
extern const llvm_ks::MCSchedModel M68kSchedModels[];
extern const llvm_ks::MCWriteProcResEntry M68kWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry M68kWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry M68kReadAdvanceTable[];
M68kGenSubtargetInfo::M68kGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(M68kSubTypeKVStorage.Strings), ArrayRef(M68kFeatureKVStorage.Features), ArrayRef(M68kSubTypeKVStorage.SubTypes), M68kSchedModels, 
                        M68kWriteProcResTable, M68kWriteLatencyTable, M68kReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned M68kGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // M68kGenSubtargetInfo::resolveSchedClass

unsigned M68kGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return M68k_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // M68kGenSubtargetInfo::resolveVariantSchedClass

const FeatureBitset &M68kGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &M68kGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &M68kGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

