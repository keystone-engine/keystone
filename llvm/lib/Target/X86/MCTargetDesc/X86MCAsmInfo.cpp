//===-- X86MCAsmInfo.cpp - X86 asm properties -----------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declarations of the X86MCAsmInfo properties.
//
//===----------------------------------------------------------------------===//

#include "X86MCAsmInfo.h"
#include "llvm/ADT/Triple.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/Support/ELF.h"
using namespace llvm;

//#include <iostream>
enum AsmWriterFlavorTy {
  // Note: This numbering has to match the GCC assembler dialects for inline
  // asm alternatives to work right.
  ATT = 0, Intel = 1
};

static AsmWriterFlavorTy AsmWriterFlavor = Intel; // ATT

X86ELFMCAsmInfo::X86ELFMCAsmInfo(const Triple &T) {
  bool is64Bit = T.getArch() == Triple::x86_64;
  bool isX32 = T.getEnvironment() == Triple::GNUX32;

  // For ELF, x86-64 pointer size depends on the ABI.
  // For x86-64 without the x32 ABI, pointer size is 8. For x86 and for x86-64
  // with the x32 ABI, pointer size remains the default 4.
  PointerSize = (is64Bit && !isX32) ? 8 : 4;

  // OTOH, stack slot size is always 8 for x86-64, even with the x32 ABI.
  CalleeSaveStackSlotSize = is64Bit ? 8 : 4;

  AssemblerDialect = AsmWriterFlavor;

  TextAlignFillValue = 0x90;

  // Debug Information
  SupportsDebugInformation = true;

  // Exceptions handling
  ExceptionsType = ExceptionHandling::DwarfCFI;

  // Always enable the integrated assembler by default.
  // Clang also enabled it when the OS is Solaris but that is redundant here.
  UseIntegratedAssembler = true;
}
