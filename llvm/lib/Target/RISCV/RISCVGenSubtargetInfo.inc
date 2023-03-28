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
namespace RISCV {
enum : uint64_t {
  Feature64Bit = 0,
  FeatureRV32E = 1,
  FeatureRelax = 2,
  FeatureStdExtA = 3,
  FeatureStdExtC = 4,
  FeatureStdExtD = 5,
  FeatureStdExtF = 6,
  FeatureStdExtM = 7,
  NumSubtargetFeatures = 8
};
} // end namespace RISCV
} // end namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {
// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKV RISCVFeatureKV[] = {
  { "64bit", "Implements RV64", {RISCV::Feature64Bit}, { } },
  { "a", "'A' (Atomic Instructions)", {RISCV::FeatureStdExtA,}, { } },
  { "c", "'C' (Compressed Instructions)", {RISCV::FeatureStdExtC,}, { } },
  { "d", "'D' (Double-Precision Floating-Point)", {RISCV::FeatureStdExtD,}, {RISCV::FeatureStdExtF} },
  { "e", "Implements RV32E (provides 16 rather than 32 GPRs)", {RISCV::FeatureRV32E}, { } },
  { "f", "'F' (Single-Precision Floating-Point)", {RISCV::FeatureStdExtF,}, { } },
  { "m", "'M' (Integer Multiplication and Division)", {RISCV::FeatureStdExtM,}, { } },
  { "relax", "Enable Linker relaxation.", {RISCV::FeatureRelax,}, { } },
};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
#define DBGFIELD(x) x,
#else
#define DBGFIELD(x)
#endif

// ===============================================================
// Data tables for the new per-operand machine model.

// {ProcResourceIdx, Cycles}
extern const llvm_ks::MCWriteProcResEntry RISCVWriteProcResTable[] = {
  { 0,  0}, // Invalid
}; // RISCVWriteProcResTable

// {Cycles, WriteResourceID}
extern const llvm_ks::MCWriteLatencyEntry RISCVWriteLatencyTable[] = {
  { 0,  0}, // Invalid
}; // RISCVWriteLatencyTable

// {UseIdx, WriteResourceID, Cycles}
extern const llvm_ks::MCReadAdvanceEntry RISCVReadAdvanceTable[] = {
  {0,  0,  0}, // Invalid
}; // RISCVReadAdvanceTable

#undef DBGFIELD

static const llvm_ks::MCSchedModel NoSchedModel = {
  MCSchedModel::DefaultIssueWidth,
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  MCSchedModel::DefaultLoadLatency,
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  0, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  nullptr, // No Itinerary
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetFeatureKV RISCVSubTypeKV[] = { 
 { "generic-rv32", "select rv32 CPU", {RISCV::FeatureStdExtA,RISCV::FeatureStdExtC,RISCV::FeatureStdExtD,RISCV::FeatureStdExtF,RISCV::FeatureStdExtM,RISCV::FeatureRelax,}, {}},
 { "generic-rv64", "select rv64 CPU", {RISCV::Feature64Bit,RISCV::FeatureStdExtA,RISCV::FeatureStdExtC,RISCV::FeatureStdExtD,RISCV::FeatureStdExtF,RISCV::FeatureStdExtM,RISCV::FeatureRelax,}, {}},
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetInfoKV RISCVProcSchedKV[] = {
 { "generic-rv32",  (const void *)&NoSchedModel },
 { "generic-rv64",  (const void *)&NoSchedModel },
};

namespace RISCV_MC {
unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}
} // end of namespace RISCV_MC


static inline MCSubtargetInfo *createRISCVMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, RISCVFeatureKV, RISCVSubTypeKV,/*  
                      RISCVWriteProcResTable, RISCVWriteLatencyTable, RISCVReadAdvanceTable, 
                      nullptr, nullptr, nullptr */RISCVProcSchedKV);
}

} // end namespace llvm_ks

#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC

#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::RISCVSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
  if (Bits[RISCV::Feature64Bit]) HasRV64 = true;
  if (Bits[RISCV::FeatureRV32E]) IsRV32E = true;
  if (Bits[RISCV::FeatureRelax]) EnableLinkerRelax = true;
  if (Bits[RISCV::FeatureStdExtA]) HasStdExtA = true;
  if (Bits[RISCV::FeatureStdExtC]) HasStdExtC = true;
  if (Bits[RISCV::FeatureStdExtD]) HasStdExtD = true;
  if (Bits[RISCV::FeatureStdExtF]) HasStdExtF = true;
  if (Bits[RISCV::FeatureStdExtM]) HasStdExtM = true;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC