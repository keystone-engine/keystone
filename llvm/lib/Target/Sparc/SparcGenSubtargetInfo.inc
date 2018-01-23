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
enum : uint64_t {
  FeatureHardQuad = 0,
  FeatureV8Deprecated = 1,
  FeatureV9 = 2,
  FeatureVIS = 3,
  FeatureVIS2 = 4,
  FeatureVIS3 = 5,
  UsePopc = 6
};
}
} // end llvm namespace
#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC
namespace llvm_ks {
// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKV SparcFeatureKV[] = {
  { "deprecated-v8", "Enable deprecated V8 instructions in V9 mode", { Sparc::FeatureV8Deprecated }, { } },
  { "hard-quad-float", "Enable quad-word floating point instructions", { Sparc::FeatureHardQuad }, { } },
  { "popc", "Use the popc (population count) instruction", { Sparc::UsePopc }, { } },
  { "v9", "Enable SPARC-V9 instructions", { Sparc::FeatureV9 }, { } },
  { "vis", "Enable UltraSPARC Visual Instruction Set extensions", { Sparc::FeatureVIS }, { } },
  { "vis2", "Enable Visual Instruction Set extensions II", { Sparc::FeatureVIS2 }, { } },
  { "vis3", "Enable Visual Instruction Set extensions III", { Sparc::FeatureVIS3 }, { } }
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetFeatureKV SparcSubTypeKV[] = {
  { "f934", "Select the f934 processor", { }, { } },
  { "generic", "Select the generic processor", { }, { } },
  { "hypersparc", "Select the hypersparc processor", { }, { } },
  { "niagara", "Select the niagara processor", { Sparc::FeatureV9, Sparc::FeatureV8Deprecated, Sparc::FeatureVIS, Sparc::FeatureVIS2 }, { } },
  { "niagara2", "Select the niagara2 processor", { Sparc::FeatureV9, Sparc::FeatureV8Deprecated, Sparc::UsePopc, Sparc::FeatureVIS, Sparc::FeatureVIS2 }, { } },
  { "niagara3", "Select the niagara3 processor", { Sparc::FeatureV9, Sparc::FeatureV8Deprecated, Sparc::UsePopc, Sparc::FeatureVIS, Sparc::FeatureVIS2 }, { } },
  { "niagara4", "Select the niagara4 processor", { Sparc::FeatureV9, Sparc::FeatureV8Deprecated, Sparc::UsePopc, Sparc::FeatureVIS, Sparc::FeatureVIS2, Sparc::FeatureVIS3 }, { } },
  { "sparclet", "Select the sparclet processor", { }, { } },
  { "sparclite", "Select the sparclite processor", { }, { } },
  { "sparclite86x", "Select the sparclite86x processor", { }, { } },
  { "supersparc", "Select the supersparc processor", { }, { } },
  { "tsc701", "Select the tsc701 processor", { }, { } },
  { "ultrasparc", "Select the ultrasparc processor", { Sparc::FeatureV9, Sparc::FeatureV8Deprecated, Sparc::FeatureVIS }, { } },
  { "ultrasparc3", "Select the ultrasparc3 processor", { Sparc::FeatureV9, Sparc::FeatureV8Deprecated, Sparc::FeatureVIS, Sparc::FeatureVIS2 }, { } },
  { "v7", "Select the v7 processor", { }, { } },
  { "v8", "Select the v8 processor", { }, { } },
  { "v9", "Select the v9 processor", { Sparc::FeatureV9 }, { } }
};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#ifndef NDEBUG
#define DBGFIELD(x) x,
#else
#define DBGFIELD(x)
#endif

// ===============================================================
// Data tables for the new per-operand machine model.

#undef DBGFIELD
static inline MCSubtargetInfo *createSparcMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, SparcFeatureKV, SparcSubTypeKV, NULL);
}

} // end llvm namespace
#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::SparcSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
  if (Bits[Sparc::FeatureHardQuad]) HasHardQuad = true;
  if (Bits[Sparc::FeatureV8Deprecated]) V8DeprecatedInsts = true;
  if (Bits[Sparc::FeatureV9]) IsV9 = true;
  if (Bits[Sparc::FeatureVIS]) IsVIS = true;
  if (Bits[Sparc::FeatureVIS2]) IsVIS2 = true;
  if (Bits[Sparc::FeatureVIS3]) IsVIS3 = true;
  if (Bits[Sparc::UsePopc]) UsePopc = true;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC
