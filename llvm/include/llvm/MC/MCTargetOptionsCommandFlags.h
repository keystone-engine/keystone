//===-- MCTargetOptionsCommandFlags.h --------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains machine code-specific flags that are shared between
// different command line tools.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCTARGETOPTIONSCOMMANDFLAGS_H
#define LLVM_MC_MCTARGETOPTIONSCOMMANDFLAGS_H

#include "llvm/MC/MCTargetOptions.h"

using namespace llvm_ks;

bool RelaxAll;

int DwarfVersion = 0;

bool FatalWarnings;

bool NoWarn;

//cl::alias NoWarnW("W", cl::desc("Alias for --no-warn"), cl::aliasopt(NoWarn));

std::string ABIName = "";

static inline MCTargetOptions InitMCTargetOptionsFromFlags() {
  MCTargetOptions Options;
  Options.MCRelaxAll = RelaxAll;
  Options.DwarfVersion = DwarfVersion;
  Options.ABIName = ABIName;
  Options.MCFatalWarnings = FatalWarnings;
  Options.MCNoWarn = NoWarn;
  return Options;
}

#endif
