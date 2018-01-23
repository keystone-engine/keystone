//===-- llvm/MC/MCInstrItineraries.h - Scheduling ---------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file describes the structures used for instruction
// itineraries, stages, and operand reads/writes.  This is used by
// schedulers to determine instruction stages and latencies.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCINSTRITINERARIES_H
#define LLVM_MC_MCINSTRITINERARIES_H

#include "llvm/MC/MCSchedule.h"
#include <algorithm>

namespace llvm_ks {

//===----------------------------------------------------------------------===//
/// These values represent a non-pipelined step in
/// the execution of an instruction.  Cycles represents the number of
/// discrete time slots needed to complete the stage.  Units represent
/// the choice of functional units that can be used to complete the
/// stage.  Eg. IntUnit1, IntUnit2. NextCycles indicates how many
/// cycles should elapse from the start of this stage to the start of
/// the next stage in the itinerary. A value of -1 indicates that the
/// next stage should start immediately after the current one.
/// For example:
///
///   { 1, x, -1 }
///      indicates that the stage occupies FU x for 1 cycle and that
///      the next stage starts immediately after this one.
///
///   { 2, x|y, 1 }
///      indicates that the stage occupies either FU x or FU y for 2
///      consecutive cycles and that the next stage starts one cycle
///      after this stage starts. That is, the stage requirements
///      overlap in time.
///
///   { 1, x, 0 }
///      indicates that the stage occupies FU x for 1 cycle and that
///      the next stage starts in this same cycle. This can be used to
///      indicate that the instruction requires multiple stages at the
///      same time.
///
/// FU reservation can be of two different kinds:
///  - FUs which instruction actually requires
///  - FUs which instruction just reserves. Reserved unit is not available for
///    execution of other instruction. However, several instructions can reserve
///    the same unit several times.
/// Such two types of units reservation is used to model instruction domain
/// change stalls, FUs using the same resource (e.g. same register file), etc.

struct InstrStage {
  enum ReservationKinds {
    Required = 0,
    Reserved = 1
  };

  unsigned Cycles_;  ///< Length of stage in machine cycles
  unsigned Units_;   ///< Choice of functional units
  int NextCycles_;   ///< Number of machine cycles to next stage
  ReservationKinds Kind_; ///< Kind of the FU reservation

  /// \brief Returns the choice of FUs.
  unsigned getUnits() const {
    return Units_;
  }
};


//===----------------------------------------------------------------------===//
/// An itinerary represents the scheduling information for an instruction.
/// This includes a set of stages occupied by the instruction and the pipeline
/// cycle in which operands are read and written.
///
struct InstrItinerary {
  int      NumMicroOps;        ///< # of micro-ops, -1 means it's variable
  unsigned FirstStage;         ///< Index of first stage in itinerary
  unsigned LastStage;          ///< Index of last + 1 stage in itinerary
  unsigned FirstOperandCycle;  ///< Index of first operand rd/wr
  unsigned LastOperandCycle;   ///< Index of last + 1 operand rd/wr
};


//===----------------------------------------------------------------------===//
/// Itinerary data supplied by a subtarget to be used by a target.
///
class InstrItineraryData {
public:
  MCSchedModel          SchedModel;     ///< Basic machine properties.
  const InstrStage     *Stages;         ///< Array of stages selected
  const InstrItinerary *Itineraries;    ///< Array of itineraries selected
};

} // End llvm namespace

#endif
