//===-- SparcTargetInfo.cpp - Sparc Target Implementation -----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/SparcMCTargetDesc.h"
#include "llvm/Support/TargetRegistry.h"
using namespace llvm;

Target llvm::TheSparcTarget;
Target llvm::TheSparcV9Target;
Target llvm::TheSparcelTarget;

extern "C" void LLVMInitializeSparcTargetInfo() {
  RegisterTarget<Triple::sparc> X(TheSparcTarget, "sparc",
                                                   "Sparc");
  RegisterTarget<Triple::sparcv9> Y(TheSparcV9Target,
                                                     "sparcv9", "Sparc V9");
  RegisterTarget<Triple::sparcel> Z(TheSparcelTarget,
                                                     "sparcel", "Sparc LE");
}
