//===-- SystemZTargetInfo.cpp - SystemZ target implementation -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/SystemZMCTargetDesc.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm_ks;

Target llvm_ks::TheSystemZTarget;

extern "C" void LLVMInitializeSystemZTargetInfo() {
  RegisterTarget<Triple::systemz>
    X(TheSystemZTarget, "systemz", "SystemZ");
}
