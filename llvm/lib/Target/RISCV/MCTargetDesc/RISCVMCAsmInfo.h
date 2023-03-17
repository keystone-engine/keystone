//===-- RISCVMCAsmInfo.h - RISCV Asm Info ----------------------*- C++ -*--===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the RISCVMCAsmInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RISCV_MCTARGETDESC_RISCVMCASMINFO_H
#define LLVM_LIB_TARGET_RISCV_MCTARGETDESC_RISCVMCASMINFO_H

#include "llvm/MC/MCAsmInfoELF.h"

namespace llvm_ks {
class Triple;

class RISCVMCAsmInfo : public MCAsmInfoELF {
public:
  explicit RISCVMCAsmInfo(const Triple &TargetTriple);
};

} // namespace llvm_ks

#endif
