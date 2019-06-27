//===-- HexagonTargetAsmInfo.h - Hexagon asm properties --------*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the HexagonMCAsmInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_HEXAGON_MCTARGETDESC_HEXAGONMCASMINFO_H
#define LLVM_LIB_TARGET_HEXAGON_MCTARGETDESC_HEXAGONMCASMINFO_H

#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCAsmInfoELF.h"

namespace llvm_ks {
class Triple;

class HexagonMCAsmInfo : public MCAsmInfoELF {
public:
  explicit HexagonMCAsmInfo(const Triple &TT);
};

} // namespace llvm_ks

#endif
