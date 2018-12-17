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
  FeatureX = 3
};
} // end namespace MSP430
} // end namespace llvm

#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {
// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKV MSP430FeatureKV[] = {
  { "ext", "Enable MSP430-X extensions", { MSP430::FeatureX }, { } },
  { "hwmult16", "Enable 16-bit hardware multiplier", { MSP430::FeatureHWMult16 }, { } },
  { "hwmult32", "Enable 32-bit hardware multiplier", { MSP430::FeatureHWMult32 }, { } },
  { "hwmultf5", "Enable F5 series hardware multiplier", { MSP430::FeatureHWMultF5 }, { } }
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetFeatureKV MSP430SubTypeKV[] = {
  { "generic", "Select the generic processor", { }, { } },
  { "msp430", "Select the msp430 processor", { }, { } },
  { "msp430x", "Select the msp430x processor", { MSP430::FeatureX }, { } }
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

// {ProcResourceIdx, Cycles}
extern const llvm_ks::MCWriteProcResEntry MSP430WriteProcResTable[] = {
  { 0,  0}, // Invalid
}; // MSP430WriteProcResTable

// {Cycles, WriteResourceID}
extern const llvm_ks::MCWriteLatencyEntry MSP430WriteLatencyTable[] = {
  { 0,  0}, // Invalid
}; // MSP430WriteLatencyTable

// {UseIdx, WriteResourceID, Cycles}
extern const llvm_ks::MCReadAdvanceEntry MSP430ReadAdvanceTable[] = {
  {0,  0,  0}, // Invalid
}; // MSP430ReadAdvanceTable

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
  nullptr}; // No Itinerary

// Sorted (by key) array of itineraries for CPU subtype.
extern const llvm_ks::SubtargetInfoKV MSP430ProcSchedKV[] = {
  { "generic", (const void *)&NoSchedModel },
  { "msp430", (const void *)&NoSchedModel },
  { "msp430x", (const void *)&NoSchedModel }
};
#undef DBGFIELD
static inline MCSubtargetInfo *createMSP430MCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, MSP430FeatureKV, MSP430SubTypeKV, NULL);
}

} // end namespace llvm

#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC

#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::MSP430Subtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
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
struct MSP430GenSubtargetInfo : public TargetSubtargetInfo {
  explicit MSP430GenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const override;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
};
} // end namespace llvm

#endif // GET_SUBTARGETINFO_HEADER


#ifdef GET_SUBTARGETINFO_CTOR
#undef GET_SUBTARGETINFO_CTOR

#include "llvm/CodeGen/TargetSchedule.h"

namespace llvm_ks {
extern const llvm_ks::SubtargetFeatureKV MSP430FeatureKV[];
extern const llvm_ks::SubtargetFeatureKV MSP430SubTypeKV[];
extern const llvm_ks::SubtargetInfoKV MSP430ProcSchedKV[];
extern const llvm_ks::MCWriteProcResEntry MSP430WriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry MSP430WriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry MSP430ReadAdvanceTable[];
MSP430GenSubtargetInfo::MSP430GenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, FS, makeArrayRef(MSP430FeatureKV, 4), makeArrayRef(MSP430SubTypeKV, 3), 
                        MSP430ProcSchedKV, MSP430WriteProcResTable, MSP430WriteLatencyTable, MSP430ReadAdvanceTable, 
                        0, 0, 0) {}

unsigned MSP430GenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // MSP430GenSubtargetInfo::resolveSchedClass
} // end namespace llvm

#endif // GET_SUBTARGETINFO_CTOR

