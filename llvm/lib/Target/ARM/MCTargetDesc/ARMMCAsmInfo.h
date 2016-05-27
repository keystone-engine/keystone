//===-- ARMMCAsmInfo.h - ARM asm properties --------------------*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the ARMMCAsmInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_ARM_MCTARGETDESC_ARMMCASMINFO_H
#define LLVM_LIB_TARGET_ARM_MCTARGETDESC_ARMMCASMINFO_H

#include "llvm/MC/MCAsmInfoELF.h"

namespace llvm {
class Triple;

class ARMELFMCAsmInfo : public MCAsmInfoELF {
public:
  explicit ARMELFMCAsmInfo(const Triple &TT);

  void setUseIntegratedAssembler(bool Value) override;
};

} // namespace llvm

#endif
