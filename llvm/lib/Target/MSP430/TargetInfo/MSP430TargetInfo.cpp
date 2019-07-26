//===-- MSP430TargetInfo.cpp - MSP430 Target Implementation ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "../MCTargetDesc/MSP430MCTargetDesc.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm_ks;

Target llvm_ks::TheMSP430Target;

extern "C" void LLVMInitializeMSP430TargetInfo() {
  RegisterTarget<Triple::msp430>
          X(TheMSP430Target, "msp430", "MSP430");
}
