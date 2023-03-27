//==-- llvm/MC/MCSubtargetInfo.h - Subtarget Information ---------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file describes the subtarget options of a Target machine.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCSUBTARGETINFO_H
#define LLVM_MC_MCSUBTARGETINFO_H

#include "llvm/MC/MCInstrItineraries.h"
#include "llvm/MC/MCSchedule.h"
#include "llvm/MC/SubtargetFeature.h"
#include <string>

namespace llvm_ks {

class StringRef;

//===----------------------------------------------------------------------===//
///
/// MCSubtargetInfo - Generic base class for all target subtargets.
///
class MCSubtargetInfo {
  Triple TargetTriple;                        // Target triple
  std::string CPU; // CPU being targeted.
  ArrayRef<SubtargetFeatureKV> ProcFeatures;  // Processor feature list
  ArrayRef<SubtargetFeatureKV> ProcDesc;  // Processor descriptions

  FeatureBitset FeatureBits;           // Feature bits for current CPU + FS

  // Scheduler machine model
  const SubtargetInfoKV *ProcSchedModels;
  const MCSchedModel *CPUSchedModel;

  MCSubtargetInfo() = delete;
  MCSubtargetInfo &operator=(MCSubtargetInfo &&) = delete;
  MCSubtargetInfo &operator=(const MCSubtargetInfo &) = delete;

public:
  MCSubtargetInfo(const MCSubtargetInfo &) = default;
  MCSubtargetInfo(const Triple &TT, StringRef CPU, StringRef FS,
                  ArrayRef<SubtargetFeatureKV> PF,
                  ArrayRef<SubtargetFeatureKV> PD,
                  const SubtargetInfoKV *ProcSched);

  /// getTargetTriple - Return the target triple string.
  const Triple &getTargetTriple() const { return TargetTriple; }

  /// getCPU - Return the CPU string.
  StringRef getCPU() const {
    return CPU;
  }

  /// getFeatureBits - Return the feature bits.
  ///
  const FeatureBitset& getFeatureBits() const {
    return FeatureBits;
  }

  /// setFeatureBits - Set the feature bits.
  ///
  void setFeatureBits(const FeatureBitset &FeatureBits_) {
    FeatureBits = FeatureBits_;
  }

  bool hasFeature(unsigned Feature) const {
    return FeatureBits[Feature];
  }

protected:
  /// Initialize the scheduling model and feature bits.
  ///
  /// FIXME: Find a way to stick this in the constructor, since it should only
  /// be called during initialization.
  void InitMCProcessorInfo(StringRef CPU, StringRef FS);

public:
  /// Set the features to the default for the given CPU with an appended feature
  /// string.
  void setDefaultFeatures(StringRef CPU, StringRef FS);

  /// ToggleFeature - Toggle a feature and returns the re-computed feature
  /// bits. This version does not change the implied bits.
  FeatureBitset ToggleFeature(uint64_t FB);

  /// ToggleFeature - Toggle a feature and returns the re-computed feature
  /// bits. This version does not change the implied bits.
  FeatureBitset ToggleFeature(const FeatureBitset& FB);

  /// ToggleFeature - Toggle a set of features and returns the re-computed
  /// feature bits. This version will also change all implied bits.
  FeatureBitset ToggleFeature(StringRef FS);

  /// Apply a feature flag and return the re-computed feature bits, including
  /// all feature bits implied by the flag.
  FeatureBitset ApplyFeatureFlag(StringRef FS);

  /// getSchedModelForCPU - Get the machine model of a CPU.
  const MCSchedModel &getSchedModelForCPU(StringRef CPU) const;

  /// Get the machine model for this subtarget's CPU.
  const MCSchedModel &getSchedModel() const { return *CPUSchedModel; }

  /// Check whether the CPU string is valid.
  bool isCPUStringValid(StringRef CPU) const {
    auto Found = std::lower_bound(ProcDesc.begin(), ProcDesc.end(), CPU);
    return Found != ProcDesc.end() && StringRef(Found->Key) == CPU;
  }
};

} // End llvm namespace

#endif
