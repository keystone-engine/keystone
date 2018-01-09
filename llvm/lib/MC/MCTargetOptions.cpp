//===- lib/MC/MCTargetOptions.cpp - MC Target Options --------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCTargetOptions.h"

namespace llvm_ks {

MCTargetOptions::MCTargetOptions()
    : MCRelaxAll(false),
      MCFatalWarnings(false), MCNoWarn(false),
      DwarfVersion(0), ABIName() {}

StringRef MCTargetOptions::getABIName() const {
  return ABIName;
}

} // end namespace llvm_ks
