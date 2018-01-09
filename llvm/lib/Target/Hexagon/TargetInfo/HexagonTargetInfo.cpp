//===-- HexagonTargetInfo.cpp - Hexagon Target Implementation ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Hexagon.h"
#include "llvm/Support/TargetRegistry.h"
using namespace llvm_ks;

Target llvm_ks::TheHexagonTarget;

extern "C" void LLVMInitializeHexagonTargetInfo() {
  RegisterTarget<Triple::hexagon>  X(TheHexagonTarget, "hexagon", "Hexagon");
}
