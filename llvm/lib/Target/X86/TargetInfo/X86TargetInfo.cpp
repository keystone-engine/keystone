//===-- X86TargetInfo.cpp - X86 Target Implementation ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/X86MCTargetDesc.h"
#include "llvm/Support/TargetRegistry.h"
using namespace llvm_ks;

Target llvm_ks::TheX86_32Target, llvm_ks::TheX86_64Target;

extern "C" void LLVMInitializeX86TargetInfo() {
  RegisterTarget<Triple::x86>
    X(TheX86_32Target, "x86", "32-bit X86: Pentium-Pro and above");

  RegisterTarget<Triple::x86_64>
    Y(TheX86_64Target, "x86-64", "64-bit X86: EM64T and AMD64");
}
