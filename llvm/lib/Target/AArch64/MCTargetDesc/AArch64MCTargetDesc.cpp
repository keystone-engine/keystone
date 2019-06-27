//===-- AArch64MCTargetDesc.cpp - AArch64 Target Descriptions ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides AArch64 specific target descriptions.
//
//===----------------------------------------------------------------------===//

#include "AArch64MCTargetDesc.h"
#include "AArch64ELFStreamer.h"
#include "AArch64MCAsmInfo.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm_ks;

#define GET_INSTRINFO_MC_DESC
#include "AArch64GenInstrInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "AArch64GenSubtargetInfo.inc"

#define GET_REGINFO_MC_DESC
#include "AArch64GenRegisterInfo.inc"

static MCInstrInfo *createAArch64MCInstrInfo() {
  MCInstrInfo *X = new MCInstrInfo();
  InitAArch64MCInstrInfo(X);
  return X;
}

static MCSubtargetInfo *
createAArch64MCSubtargetInfo(const Triple &TT, StringRef CPU, StringRef FS) {
  if (CPU.empty())
    CPU = "generic";

  return createAArch64MCSubtargetInfoImpl(TT, CPU, FS);
}

static MCRegisterInfo *createAArch64MCRegisterInfo(const Triple &Triple) {
  MCRegisterInfo *X = new MCRegisterInfo();
  InitAArch64MCRegisterInfo(X, AArch64::LR);
  return X;
}

static MCAsmInfo *createAArch64MCAsmInfo(const MCRegisterInfo &MRI,
                                         const Triple &TheTriple) {
  MCAsmInfo *MAI;
  if (TheTriple.isOSBinFormatMachO())
    MAI = new AArch64MCAsmInfoDarwin();
  else {
    assert(TheTriple.isOSBinFormatELF() && "Only expect Darwin or ELF");
    MAI = new AArch64MCAsmInfoELF(TheTriple);
  }

  // Initial state of the frame pointer is SP.
  unsigned Reg = MRI.getDwarfRegNum(AArch64::SP, true);
  MCCFIInstruction Inst = MCCFIInstruction::createDefCfa(nullptr, Reg, 0);
  MAI->addInitialFrameState(Inst);

  return MAI;
}

// Force static initialization.
extern "C" void LLVMInitializeAArch64TargetMC() {
  for (Target *T :
       {&TheAArch64leTarget, &TheAArch64beTarget, &TheARM64Target}) {
    // Register the MC asm info.
    RegisterMCAsmInfoFn X(*T, createAArch64MCAsmInfo);

    // Register the MC instruction info.
    TargetRegistry::RegisterMCInstrInfo(*T, createAArch64MCInstrInfo);

    // Register the MC register info.
    TargetRegistry::RegisterMCRegInfo(*T, createAArch64MCRegisterInfo);

    // Register the MC subtarget info.
    TargetRegistry::RegisterMCSubtargetInfo(*T, createAArch64MCSubtargetInfo);

    // Register the MC Code Emitter
    TargetRegistry::RegisterMCCodeEmitter(*T, createAArch64MCCodeEmitter);
  }

  // Register the asm backend.
  for (Target *T : {&TheAArch64leTarget, &TheARM64Target})
    TargetRegistry::RegisterMCAsmBackend(*T, createAArch64leAsmBackend);
  TargetRegistry::RegisterMCAsmBackend(TheAArch64beTarget,
                                       createAArch64beAsmBackend);
}
