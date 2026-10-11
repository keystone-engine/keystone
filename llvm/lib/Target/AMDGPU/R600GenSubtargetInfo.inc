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

namespace R600 {

enum {
  FeatureAddressableLocalMemorySize32768 = 0,
  FeatureAddressableLocalMemorySize65536 = 1,
  FeatureAddressableLocalMemorySize163840 = 2,
  FeatureAddressableLocalMemorySize327680 = 3,
  FeatureCFALUBug = 4,
  FeatureCaymanISA = 5,
  FeatureEvergreen = 6,
  FeatureFMA = 7,
  FeatureFP64 = 8,
  FeatureFetchLimit8 = 9,
  FeatureFetchLimit16 = 10,
  FeatureFlatOffsetBits12 = 11,
  FeatureFlatOffsetBits24 = 12,
  FeatureMadMacF32Insts = 13,
  FeatureNorthernIslands = 14,
  FeatureR600 = 15,
  FeatureR600ALUInst = 16,
  FeatureR700 = 17,
  FeatureVertexCache = 18,
  FeatureWavefrontSize16 = 19,
  FeatureWavefrontSize32 = 20,
  FeatureWavefrontSize64 = 21,
  NumSubtargetFeatures = 22
};

} // namespace R600

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(HasCFALUBug, false, hasCFALUBug)
GET_SUBTARGETINFO_MACRO(HasCaymanISA, false, hasCaymanISA)
GET_SUBTARGETINFO_MACRO(HasFMA, false, hasFMA)
GET_SUBTARGETINFO_MACRO(HasFP64, false, hasFP64)
GET_SUBTARGETINFO_MACRO(HasMadMacF32Insts, false, hasMadMacF32Insts)
GET_SUBTARGETINFO_MACRO(HasR600ALUInst, true, hasR600ALUInst)
GET_SUBTARGETINFO_MACRO(HasVertexCache, false, hasVertexCache)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 22, 935> R600FeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 22 + 1, sizeof(SubtargetFeatureKV) * 22 + 16, R600::FeatureVertexCache, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 54, sizeof(SubtargetFeatureKV) * 21 + 66, R600::FeatureR600ALUInst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 109, sizeof(SubtargetFeatureKV) * 20 + 142, R600::FeatureAddressableLocalMemorySize163840, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 176, sizeof(SubtargetFeatureKV) * 19 + 142, R600::FeatureAddressableLocalMemorySize32768, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 208, sizeof(SubtargetFeatureKV) * 18 + 142, R600::FeatureAddressableLocalMemorySize327680, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 241, sizeof(SubtargetFeatureKV) * 17 + 142, R600::FeatureAddressableLocalMemorySize65536, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 273, sizeof(SubtargetFeatureKV) * 16 + 283, R600::FeatureCaymanISA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 298, sizeof(SubtargetFeatureKV) * 15 + 307, R600::FeatureCFALUBug, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 326, sizeof(SubtargetFeatureKV) * 14 + 336, R600::FeatureEvergreen, { { { 0x2401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 361, sizeof(SubtargetFeatureKV) * 13 + 369, R600::FeatureFetchLimit16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 423, sizeof(SubtargetFeatureKV) * 12 + 430, R600::FeatureFetchLimit8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 483, sizeof(SubtargetFeatureKV) * 11 + 503, R600::FeatureFlatOffsetBits12, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 543, sizeof(SubtargetFeatureKV) * 10 + 503, R600::FeatureFlatOffsetBits24, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 563, sizeof(SubtargetFeatureKV) * 9 + 568, R600::FeatureFMA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 632, sizeof(SubtargetFeatureKV) * 8 + 637, R600::FeatureFP64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 672, sizeof(SubtargetFeatureKV) * 7 + 690, R600::FeatureMadMacF32Insts, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 751, sizeof(SubtargetFeatureKV) * 6 + 768, R600::FeatureNorthernIslands, { { { 0x202401ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 800, sizeof(SubtargetFeatureKV) * 5 + 805, R600::FeatureR600, { { { 0x12200ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 825, sizeof(SubtargetFeatureKV) * 4 + 830, R600::FeatureR700, { { { 0x2400ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 850, sizeof(SubtargetFeatureKV) * 3 + 866, R600::FeatureWavefrontSize16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 902, sizeof(SubtargetFeatureKV) * 2 + 866, R600::FeatureWavefrontSize32, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 918, sizeof(SubtargetFeatureKV) * 1 + 866, R600::FeatureWavefrontSize64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000HasVertexCache\000Specify use of dedicated vertex cache\000R600ALUI"
    "nst\000Older version of ALU instructions encoding\000addressablelocalme"
    "morysize163840\000The size of local memory in bytes\000addressablelocal"
    "memorysize32768\000addressablelocalmemorysize327680\000addressablelocal"
    "memorysize65536\000caymanISA\000Use Cayman ISA\000cfalubug\000GPU has C"
    "F_ALU bug\000evergreen\000EVERGREEN GPU generation\000fetch16\000Limit "
    "the maximum number of fetches in a clause to 16\000fetch8\000Limit the "
    "maximum number of fetches in a clause to 8\000flat-offset-bits-12\000Nu"
    "mber of bits for flat offset encoding\000flat-offset-bits-24\000fmaf\000"
    "Enable single precision FMA (not as fast as mul+add, but fused)\000fp64"
    "\000Enable double precision operations\000mad-mac-f32-insts\000Has v_ma"
    "d_f32/v_mac_f32/v_madak_f32/v_madmk_f32 instructions\000northern-island"
    "s\000NORTHERN_ISLANDS GPU generation\000r600\000R600 GPU generation\000"
    "r700\000R700 GPU generation\000wavefrontsize16\000The number of threads"
    " per wavefront\000wavefrontsize32\000wavefrontsize64\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 16, 103> R600SubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 16 + 1, { { { 0x44010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 15 + 7, { { { 0x4010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 14 + 14, { { { 0x40a0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 13 + 21, { { { 0x140050ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 12 + 27, { { { 0x2400c0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 11 + 35, { { { 0x240040ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 10 + 43, { { { 0x248000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 9 + 48, { { { 0x148000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 8 + 53, { { { 0x240050ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 7 + 61, { { { 0x88000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 6 + 67, { { { 0x248000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 5 + 73, { { { 0x160000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 4 + 79, { { { 0x160000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 3 + 85, { { { 0x260000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 2 + 91, { { { 0x200050ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 1 + 96, { { { 0x44010ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 1 },
  },
    "\000barts\000caicos\000cayman\000cedar\000cypress\000juniper\000r600\000"
    "r630\000redwood\000rs880\000rv670\000rv710\000rv730\000rv770\000sumo\000"
    "turks\000"};

namespace R600_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace R600_MC
struct R600GenMCSubtargetInfo : public MCSubtargetInfo {
  R600GenMCSubtargetInfo(const Triple &TT,
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
    return R600_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
};

static inline MCSubtargetInfo *createR600MCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new R600GenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(R600SubTypeKVStorage.Strings), R600FeatureKVStorage.Features, R600SubTypeKVStorage.SubTypes, nullptr, 
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
void llvm_ks::R600Subtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[R600::FeatureAddressableLocalMemorySize32768] && AddressableLocalMemorySize < 32768) AddressableLocalMemorySize = 32768;
  if (Bits[R600::FeatureAddressableLocalMemorySize65536] && AddressableLocalMemorySize < 65536) AddressableLocalMemorySize = 65536;
  if (Bits[R600::FeatureAddressableLocalMemorySize163840] && AddressableLocalMemorySize < 163840) AddressableLocalMemorySize = 163840;
  if (Bits[R600::FeatureAddressableLocalMemorySize327680] && AddressableLocalMemorySize < 327680) AddressableLocalMemorySize = 327680;
  if (Bits[R600::FeatureCFALUBug]) HasCFALUBug = true;
  if (Bits[R600::FeatureCaymanISA]) HasCaymanISA = true;
  if (Bits[R600::FeatureEvergreen] && Gen < R600Subtarget::EVERGREEN) Gen = R600Subtarget::EVERGREEN;
  if (Bits[R600::FeatureFMA]) HasFMA = true;
  if (Bits[R600::FeatureFP64]) HasFP64 = true;
  if (Bits[R600::FeatureFetchLimit8] && TexVTXClauseSize < 8) TexVTXClauseSize = 8;
  if (Bits[R600::FeatureFetchLimit16] && TexVTXClauseSize < 16) TexVTXClauseSize = 16;
  if (Bits[R600::FeatureFlatOffsetBits12] && FlatOffsetBitWidth < 12) FlatOffsetBitWidth = 12;
  if (Bits[R600::FeatureFlatOffsetBits24] && FlatOffsetBitWidth < 24) FlatOffsetBitWidth = 24;
  if (Bits[R600::FeatureMadMacF32Insts]) HasMadMacF32Insts = true;
  if (Bits[R600::FeatureNorthernIslands] && Gen < R600Subtarget::NORTHERN_ISLANDS) Gen = R600Subtarget::NORTHERN_ISLANDS;
  if (Bits[R600::FeatureR600] && Gen < R600Subtarget::R600) Gen = R600Subtarget::R600;
  if (Bits[R600::FeatureR600ALUInst]) HasR600ALUInst = false;
  if (Bits[R600::FeatureR700] && Gen < R600Subtarget::R700) Gen = R600Subtarget::R700;
  if (Bits[R600::FeatureVertexCache]) HasVertexCache = true;
  if (Bits[R600::FeatureWavefrontSize16] && WavefrontSizeLog2 < 4) WavefrontSizeLog2 = 4;
  if (Bits[R600::FeatureWavefrontSize32] && WavefrontSizeLog2 < 5) WavefrontSizeLog2 = 5;
  if (Bits[R600::FeatureWavefrontSize64] && WavefrontSizeLog2 < 6) WavefrontSizeLog2 = 6;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace R600_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace R600_MC
struct R600GenSubtargetInfo : public TargetSubtargetInfo {
  explicit R600GenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
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

extern const llvm_ks::StringRef R600Names[];
extern const llvm_ks::SubtargetFeatureKVStorage<22, 935> R600FeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<16, 103> R600SubTypeKVStorage;
extern const llvm_ks::MCSchedModel R600SchedModels[];
extern const llvm_ks::MCWriteProcResEntry R600WriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry R600WriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry R600ReadAdvanceTable[];
extern const llvm_ks::InstrStage R600Stages[];
extern const unsigned R600OperandCycles[];
extern const unsigned R600ForwardingPaths[];
R600GenSubtargetInfo::R600GenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(R600SubTypeKVStorage.Strings), ArrayRef(R600FeatureKVStorage.Features), ArrayRef(R600SubTypeKVStorage.SubTypes), R600SchedModels, 
                        R600WriteProcResTable, R600WriteLatencyTable, R600ReadAdvanceTable, 
                        R600Stages, R600OperandCycles, R600ForwardingPaths) {}

unsigned R600GenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // R600GenSubtargetInfo::resolveSchedClass

unsigned R600GenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return R600_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // R600GenSubtargetInfo::resolveVariantSchedClass

const FeatureBitset &R600GenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &R600GenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &R600GenSubtargetInfo::getInlineMustMatchFeatures() const {
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

