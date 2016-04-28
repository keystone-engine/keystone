//===-- MipsTargetInfo.cpp - Mips Target Implementation -------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/MipsMCTargetDesc.h"
#include "llvm/Support/TargetRegistry.h"
using namespace llvm;

Target llvm::TheMipsTarget, llvm::TheMipselTarget;
Target llvm::TheMips64Target, llvm::TheMips64elTarget;

extern "C" void LLVMInitializeMipsTargetInfo() {
  RegisterTarget<Triple::mips> X(TheMipsTarget, "mips", "Mips");

  RegisterTarget<Triple::mipsel> Y(TheMipselTarget, "mipsel", "Mipsel");

  RegisterTarget<Triple::mips64> A(TheMips64Target, "mips64", "Mips64 [experimental]");

  RegisterTarget<Triple::mips64el> B(TheMips64elTarget,
                            "mips64el", "Mips64el [experimental]");
}
