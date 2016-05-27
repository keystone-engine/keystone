//===-- AArch64MCAsmInfo.cpp - AArch64 asm properties ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declarations of the AArch64MCAsmInfo properties.
//
//===----------------------------------------------------------------------===//

#include "AArch64MCAsmInfo.h"
#include "llvm/ADT/Triple.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCStreamer.h"

using namespace llvm;

enum AsmWriterVariantTy {
  Default = -1,
  Generic = 0,
  Apple = 1
};

static AsmWriterVariantTy AsmWriterVariant = Default;

AArch64MCAsmInfoELF::AArch64MCAsmInfoELF(const Triple &T) {
  if (T.getArch() == Triple::aarch64_be)
    IsLittleEndian = false;

  // We prefer NEON instructions to be printed in the short form.
  AssemblerDialect = AsmWriterVariant == Default ? 0 : AsmWriterVariant;

  PointerSize = 8;

  // ".comm align is in bytes but .align is pow-2."
  AlignmentIsInBytes = false;

  CommentString = "//";
  PrivateGlobalPrefix = ".L";
  PrivateLabelPrefix = ".L";
  Code32Directive = ".code\t32";

  Data16bitsDirective = "\t.hword\t";
  Data32bitsDirective = "\t.word\t";
  Data64bitsDirective = "\t.xword\t";

  UseDataRegionDirectives = false;

  WeakRefDirective = "\t.weak\t";

  SupportsDebugInformation = true;

  // Exceptions handling
  ExceptionsType = ExceptionHandling::DwarfCFI;

  UseIntegratedAssembler = true;

  HasIdentDirective = true;
}
