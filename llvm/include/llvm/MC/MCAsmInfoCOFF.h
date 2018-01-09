//===-- MCAsmInfoCOFF.h - COFF asm properties -------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCASMINFOCOFF_H
#define LLVM_MC_MCASMINFOCOFF_H

#include "llvm/MC/MCAsmInfo.h"

namespace llvm_ks {
  class MCAsmInfoCOFF : public MCAsmInfo {
  protected:
    explicit MCAsmInfoCOFF();
  };

  class MCAsmInfoMicrosoft : public MCAsmInfoCOFF {
  protected:
    explicit MCAsmInfoMicrosoft();
  };

  class MCAsmInfoGNUCOFF : public MCAsmInfoCOFF {
  protected:
    explicit MCAsmInfoGNUCOFF();
  };
}


#endif // LLVM_MC_MCASMINFOCOFF_H
