//===-- MipsMCTargetDesc.cpp - Mips Target Descriptions -------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides Mips specific target descriptions.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/STLExtras.h"
#include "MipsELFStreamer.h"
#include "MipsMCAsmInfo.h"
#include "MipsMCNaCl.h"
#include "MipsMCTargetDesc.h"
#include "MipsTargetStreamer.h"
#include "llvm/ADT/Triple.h"
#include "llvm/MC/MCELFStreamer.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MachineLocation.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm_ks;

#define GET_INSTRINFO_MC_DESC
#include "MipsGenInstrInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "MipsGenSubtargetInfo.inc"

#define GET_REGINFO_MC_DESC
#include "MipsGenRegisterInfo.inc"

/// Select the Mips CPU for the given triple and cpu name.
/// FIXME: Merge with the copy in MipsSubtarget.cpp
StringRef MIPS_MC::selectMipsCPU(const Triple &TT, StringRef CPU) {
  if (CPU.empty() || CPU == "generic") {
    if (TT.getArch() == Triple::mips || TT.getArch() == Triple::mipsel)
      CPU = "mips32";
    else
      CPU = "mips64";
  }
  return CPU;
}

static MCInstrInfo *createMipsMCInstrInfo() {
  MCInstrInfo *X = new MCInstrInfo();
  InitMipsMCInstrInfo(X);
  return X;
}

static MCRegisterInfo *createMipsMCRegisterInfo(const Triple &TT) {
  MCRegisterInfo *X = new MCRegisterInfo();
  InitMipsMCRegisterInfo(X, Mips::RA);
  return X;
}

static MCSubtargetInfo *createMipsMCSubtargetInfo(const Triple &TT,
                                                  StringRef CPU, StringRef FS) {
  CPU = MIPS_MC::selectMipsCPU(TT, CPU);
  return createMipsMCSubtargetInfoImpl(TT, CPU, FS);
}

static MCAsmInfo *createMipsMCAsmInfo(const MCRegisterInfo &MRI,
                                      const Triple &TT) {
  MCAsmInfo *MAI = new MipsMCAsmInfo(TT);

  unsigned SP = MRI.getDwarfRegNum(Mips::SP, true);
  MCCFIInstruction Inst = MCCFIInstruction::createDefCfa(nullptr, SP, 0);
  MAI->addInitialFrameState(Inst);

  return MAI;
}

extern "C" void LLVMInitializeMipsTargetMC() {
  for (Target *T : {&TheMipsTarget, &TheMipselTarget, &TheMips64Target,
                    &TheMips64elTarget}) {
    // Register the MC asm info.
    RegisterMCAsmInfoFn X(*T, createMipsMCAsmInfo);

    // Register the MC instruction info.
    TargetRegistry::RegisterMCInstrInfo(*T, createMipsMCInstrInfo);

    // Register the MC register info.
    TargetRegistry::RegisterMCRegInfo(*T, createMipsMCRegisterInfo);

    // Register the MC subtarget info.
    TargetRegistry::RegisterMCSubtargetInfo(*T, createMipsMCSubtargetInfo);
  }

  // Register the MC Code Emitter
  for (Target *T : {&TheMipsTarget, &TheMips64Target})
    TargetRegistry::RegisterMCCodeEmitter(*T, createMipsMCCodeEmitterEB);

  for (Target *T : {&TheMipselTarget, &TheMips64elTarget})
    TargetRegistry::RegisterMCCodeEmitter(*T, createMipsMCCodeEmitterEL);

  // Register the asm backend.
  TargetRegistry::RegisterMCAsmBackend(TheMipsTarget,
                                       createMipsAsmBackendEB32);
  TargetRegistry::RegisterMCAsmBackend(TheMipselTarget,
                                       createMipsAsmBackendEL32);
  TargetRegistry::RegisterMCAsmBackend(TheMips64Target,
                                       createMipsAsmBackendEB64);
  TargetRegistry::RegisterMCAsmBackend(TheMips64elTarget,
                                       createMipsAsmBackendEL64);

}
