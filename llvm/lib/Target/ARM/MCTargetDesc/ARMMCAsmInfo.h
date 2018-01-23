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

#include "llvm/MC/MCAsmInfoCOFF.h"
#include "llvm/MC/MCAsmInfoDarwin.h"
#include "llvm/MC/MCAsmInfoELF.h"

namespace llvm_ks {
class Triple;

class ARMMCAsmInfoDarwin : public MCAsmInfoDarwin {
public:
  explicit ARMMCAsmInfoDarwin(const Triple &TheTriple);
};

class ARMELFMCAsmInfo : public MCAsmInfoELF {
public:
  explicit ARMELFMCAsmInfo(const Triple &TT);

  void setUseIntegratedAssembler(bool Value) override;
};

class ARMCOFFMCAsmInfoMicrosoft : public MCAsmInfoMicrosoft {
public:
  explicit ARMCOFFMCAsmInfoMicrosoft();
};

class ARMCOFFMCAsmInfoGNU : public MCAsmInfoGNUCOFF {
public:
  explicit ARMCOFFMCAsmInfoGNU();
};

} // namespace llvm_ks

#endif
