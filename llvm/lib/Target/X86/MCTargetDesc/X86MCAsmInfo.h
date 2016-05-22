//===-- X86MCAsmInfo.h - X86 asm properties --------------------*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the X86MCAsmInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_X86_MCTARGETDESC_X86MCASMINFO_H
#define LLVM_LIB_TARGET_X86_MCTARGETDESC_X86MCASMINFO_H

#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCAsmInfoELF.h"

namespace llvm {
class Triple;

class X86ELFMCAsmInfo : public MCAsmInfoELF {
public:
  explicit X86ELFMCAsmInfo(const Triple &Triple);
};
} // namespace llvm

#endif
