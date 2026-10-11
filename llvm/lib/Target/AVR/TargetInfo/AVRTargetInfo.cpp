//===-- AVRTargetInfo.cpp - AVR Target Implementation ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "TargetInfo/AVRTargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Compiler.h"
namespace llvm_ks {
Target &getTheAVRTarget() {
  static Target TheAVRTarget;
  return TheAVRTarget;
}
} // namespace llvm_ks

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeAVRTargetInfo() {
  llvm_ks::RegisterTarget<llvm_ks::Triple::avr> X(llvm_ks::getTheAVRTarget(), "avr",
                                            "Atmel AVR Microcontroller", "AVR");
}
