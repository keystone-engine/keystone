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

namespace WebAssembly {

enum {
  FeatureAtomics = 0,
  FeatureBulkMemory = 1,
  FeatureBulkMemoryOpt = 2,
  FeatureCallIndirectOverlong = 3,
  FeatureExceptionHandling = 4,
  FeatureExtendedConst = 5,
  FeatureFP16 = 6,
  FeatureGC = 7,
  FeatureMultiMemory = 8,
  FeatureMultivalue = 9,
  FeatureMutableGlobals = 10,
  FeatureNontrappingFPToInt = 11,
  FeatureReferenceTypes = 12,
  FeatureRelaxedAtomics = 13,
  FeatureRelaxedSIMD = 14,
  FeatureSIMD128 = 15,
  FeatureSignExt = 16,
  FeatureTailCall = 17,
  FeatureWideArithmetic = 18,
  NumSubtargetFeatures = 19
};

} // namespace WebAssembly

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(HasAtomics, false, hasAtomics)
GET_SUBTARGETINFO_MACRO(HasBulkMemory, false, hasBulkMemory)
GET_SUBTARGETINFO_MACRO(HasBulkMemoryOpt, false, hasBulkMemoryOpt)
GET_SUBTARGETINFO_MACRO(HasCallIndirectOverlong, false, hasCallIndirectOverlong)
GET_SUBTARGETINFO_MACRO(HasExceptionHandling, false, hasExceptionHandling)
GET_SUBTARGETINFO_MACRO(HasExtendedConst, false, hasExtendedConst)
GET_SUBTARGETINFO_MACRO(HasFP16, false, hasFP16)
GET_SUBTARGETINFO_MACRO(HasGC, false, hasGC)
GET_SUBTARGETINFO_MACRO(HasMultiMemory, false, hasMultiMemory)
GET_SUBTARGETINFO_MACRO(HasMultivalue, false, hasMultivalue)
GET_SUBTARGETINFO_MACRO(HasMutableGlobals, false, hasMutableGlobals)
GET_SUBTARGETINFO_MACRO(HasNontrappingFPToInt, false, hasNontrappingFPToInt)
GET_SUBTARGETINFO_MACRO(HasReferenceTypes, false, hasReferenceTypes)
GET_SUBTARGETINFO_MACRO(HasRelaxedAtomics, false, hasRelaxedAtomics)
GET_SUBTARGETINFO_MACRO(HasSignExt, false, hasSignExt)
GET_SUBTARGETINFO_MACRO(HasTailCall, false, hasTailCall)
GET_SUBTARGETINFO_MACRO(HasWideArithmetic, false, hasWideArithmetic)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 19, 859> WebAssemblyFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 19 + 1, sizeof(SubtargetFeatureKV) * 19 + 9, WebAssembly::FeatureAtomics, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 24, sizeof(SubtargetFeatureKV) * 18 + 36, WebAssembly::FeatureBulkMemory, { { { 0x4ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 66, sizeof(SubtargetFeatureKV) * 17 + 82, WebAssembly::FeatureBulkMemoryOpt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 125, sizeof(SubtargetFeatureKV) * 16 + 148, WebAssembly::FeatureCallIndirectOverlong, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 202, sizeof(SubtargetFeatureKV) * 15 + 221, WebAssembly::FeatureExceptionHandling, { { { 0x1200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 252, sizeof(SubtargetFeatureKV) * 14 + 267, WebAssembly::FeatureExtendedConst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 301, sizeof(SubtargetFeatureKV) * 13 + 306, WebAssembly::FeatureFP16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 331, sizeof(SubtargetFeatureKV) * 12 + 334, WebAssembly::FeatureGC, { { { 0x1000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 349, sizeof(SubtargetFeatureKV) * 11 + 361, WebAssembly::FeatureMultiMemory, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 386, sizeof(SubtargetFeatureKV) * 10 + 397, WebAssembly::FeatureMultivalue, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 451, sizeof(SubtargetFeatureKV) * 9 + 467, WebAssembly::FeatureMutableGlobals, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 490, sizeof(SubtargetFeatureKV) * 8 + 510, WebAssembly::FeatureNontrappingFPToInt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 564, sizeof(SubtargetFeatureKV) * 7 + 580, WebAssembly::FeatureReferenceTypes, { { { 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 603, sizeof(SubtargetFeatureKV) * 6 + 619, WebAssembly::FeatureRelaxedAtomics, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 651, sizeof(SubtargetFeatureKV) * 5 + 664, WebAssembly::FeatureRelaxedSIMD, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 697, sizeof(SubtargetFeatureKV) * 4 + 706, WebAssembly::FeatureSignExt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 738, sizeof(SubtargetFeatureKV) * 3 + 746, WebAssembly::FeatureSIMD128, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 766, sizeof(SubtargetFeatureKV) * 2 + 776, WebAssembly::FeatureTailCall, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 806, sizeof(SubtargetFeatureKV) * 1 + 822, WebAssembly::FeatureWideArithmetic, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000atomics\000Enable Atomics\000bulk-memory\000Enable bulk memory oper"
    "ations\000bulk-memory-opt\000Enable bulk memory optimization operations"
    "\000call-indirect-overlong\000Enable overlong encoding for call_indirec"
    "t immediates\000exception-handling\000Enable Wasm exception handling\000"
    "extended-const\000Enable extended const expressions\000fp16\000Enable F"
    "P16 instructions\000gc\000Enable wasm gc\000multimemory\000Enable multi"
    "ple memories\000multivalue\000Enable multivalue blocks, instructions, a"
    "nd functions\000mutable-globals\000Enable mutable globals\000nontrappin"
    "g-fptoint\000Enable non-trapping float-to-int conversion operators\000r"
    "eference-types\000Enable reference types\000relaxed-atomics\000Enable r"
    "elaxed-atomics proposal\000relaxed-simd\000Enable relaxed-simd instruct"
    "ions\000sign-ext\000Enable sign extension operators\000simd128\000Enabl"
    "e 128-bit SIMD\000tail-call\000Enable tail call instructions\000wide-ar"
    "ithmetic\000Enable wide-arithmetic instructions\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 4, 34> WebAssemblySubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 4 + 1, { { { 0x3dfffULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 3 + 15, { { { 0x11e0eULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 2 + 23, { { { 0x10e2cULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 1 + 29, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
  },
    "\000bleeding-edge\000generic\000lime1\000mvp\000"};

namespace WebAssembly_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace WebAssembly_MC
struct WebAssemblyGenMCSubtargetInfo : public MCSubtargetInfo {
  WebAssemblyGenMCSubtargetInfo(const Triple &TT,
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
    return WebAssembly_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned WebAssemblyGenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (false) Modes |= (1 << 0);
  return Modes;
}
unsigned WebAssemblyGenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
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

static inline MCSubtargetInfo *createWebAssemblyMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new WebAssemblyGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(WebAssemblySubTypeKVStorage.Strings), WebAssemblyFeatureKVStorage.Features, WebAssemblySubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::WebAssemblySubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[WebAssembly::FeatureAtomics]) HasAtomics = true;
  if (Bits[WebAssembly::FeatureBulkMemory]) HasBulkMemory = true;
  if (Bits[WebAssembly::FeatureBulkMemoryOpt]) HasBulkMemoryOpt = true;
  if (Bits[WebAssembly::FeatureCallIndirectOverlong]) HasCallIndirectOverlong = true;
  if (Bits[WebAssembly::FeatureExceptionHandling]) HasExceptionHandling = true;
  if (Bits[WebAssembly::FeatureExtendedConst]) HasExtendedConst = true;
  if (Bits[WebAssembly::FeatureFP16]) HasFP16 = true;
  if (Bits[WebAssembly::FeatureGC]) HasGC = true;
  if (Bits[WebAssembly::FeatureMultiMemory]) HasMultiMemory = true;
  if (Bits[WebAssembly::FeatureMultivalue]) HasMultivalue = true;
  if (Bits[WebAssembly::FeatureMutableGlobals]) HasMutableGlobals = true;
  if (Bits[WebAssembly::FeatureNontrappingFPToInt]) HasNontrappingFPToInt = true;
  if (Bits[WebAssembly::FeatureReferenceTypes]) HasReferenceTypes = true;
  if (Bits[WebAssembly::FeatureRelaxedAtomics]) HasRelaxedAtomics = true;
  if (Bits[WebAssembly::FeatureRelaxedSIMD] && SIMDLevel < RelaxedSIMD) SIMDLevel = RelaxedSIMD;
  if (Bits[WebAssembly::FeatureSIMD128] && SIMDLevel < SIMD128) SIMDLevel = SIMD128;
  if (Bits[WebAssembly::FeatureSignExt]) HasSignExt = true;
  if (Bits[WebAssembly::FeatureTailCall]) HasTailCall = true;
  if (Bits[WebAssembly::FeatureWideArithmetic]) HasWideArithmetic = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace WebAssembly_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace WebAssembly_MC
struct WebAssemblyGenSubtargetInfo : public TargetSubtargetInfo {
  explicit WebAssemblyGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class WebAssemblyHwModeBits : unsigned {
    DefaultMode = 0,
    WASM64 = (1 << 0),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/WASM64),
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

extern const llvm_ks::StringRef WebAssemblyNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<19, 859> WebAssemblyFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<4, 34> WebAssemblySubTypeKVStorage;
extern const llvm_ks::MCSchedModel WebAssemblySchedModels[];
extern const llvm_ks::MCWriteProcResEntry WebAssemblyWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry WebAssemblyWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry WebAssemblyReadAdvanceTable[];
WebAssemblyGenSubtargetInfo::WebAssemblyGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(WebAssemblySubTypeKVStorage.Strings), ArrayRef(WebAssemblyFeatureKVStorage.Features), ArrayRef(WebAssemblySubTypeKVStorage.SubTypes), WebAssemblySchedModels, 
                        WebAssemblyWriteProcResTable, WebAssemblyWriteLatencyTable, WebAssemblyReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned WebAssemblyGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // WebAssemblyGenSubtargetInfo::resolveSchedClass

unsigned WebAssemblyGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return WebAssembly_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // WebAssemblyGenSubtargetInfo::resolveVariantSchedClass

unsigned WebAssemblyGenSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const auto *Subtarget =
      static_cast<const WebAssemblySubtarget *>(this);
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((Subtarget->hasAddr64())) Modes |= (1 << 0);
  return Modes;
}
unsigned WebAssemblyGenSubtargetInfo::getHwMode(enum HwModeType type) const {
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
const FeatureBitset &WebAssemblyGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &WebAssemblyGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &WebAssemblyGenSubtargetInfo::getInlineMustMatchFeatures() const {
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

