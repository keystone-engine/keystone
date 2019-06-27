//===-- ARMTargetInfo.cpp - ARM Target Implementation ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/ARMMCTargetDesc.h"
#include "llvm/Support/TargetRegistry.h"
using namespace llvm_ks;

Target llvm_ks::TheARMLETarget,   llvm_ks::TheARMBETarget;
Target llvm_ks::TheThumbLETarget, llvm_ks::TheThumbBETarget;

extern "C" void LLVMInitializeARMTargetInfo() {
  RegisterTarget<Triple::arm>
    X(TheARMLETarget, "arm", "ARM");
  RegisterTarget<Triple::armeb>
    Y(TheARMBETarget, "armeb", "ARM (big endian)");

  RegisterTarget<Triple::thumb>
    A(TheThumbLETarget, "thumb", "Thumb");
  RegisterTarget<Triple::thumbeb>
    B(TheThumbBETarget, "thumbeb", "Thumb (big endian)");
}
