//===-- MSP430MCTargetDesc.cpp - MSP430 Target Descriptions ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides MSP430 specific target descriptions.
//
//===----------------------------------------------------------------------===//

#include "MSP430MCTargetDesc.h"
#include "MSP430MCAsmInfo.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm_ks;

#define GET_INSTRINFO_MC_DESC
#include "../MSP430GenInstrInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "../MSP430GenSubtargetInfo.inc"

#define GET_REGINFO_MC_DESC
#include "../MSP430GenRegisterInfo.inc"
#include "../MSP430.h"

static MCAsmInfo *createMSP430MCAsmInfo(const MCRegisterInfo &MRI,
                                         const Triple &TT) {
  return new MSP430MCAsmInfo(TT);
}

static MCInstrInfo *createMSP430MCInstrInfo() {
  MCInstrInfo *X = new MCInstrInfo();
  InitMSP430MCInstrInfo(X);
  return X;
}

static MCRegisterInfo *createMSP430MCRegisterInfo(const Triple &TT) {
  MCRegisterInfo *X = new MCRegisterInfo();
  InitMSP430MCRegisterInfo(X, MSP430::PC);
  return X;
}

static MCSubtargetInfo *
createMSP430MCSubtargetInfo(const Triple &TT, StringRef CPU, StringRef FS) {
  return createMSP430MCSubtargetInfoImpl(TT, CPU, FS);
}

extern "C" void LLVMInitializeMSP430TargetMC() {
  TargetRegistry::RegisterMCInstrInfo(TheMSP430Target,
                                      createMSP430MCInstrInfo);

  TargetRegistry::RegisterMCRegInfo(TheMSP430Target,
                                    createMSP430MCRegisterInfo);

  TargetRegistry::RegisterMCSubtargetInfo(TheMSP430Target,
                                          createMSP430MCSubtargetInfo);

  TargetRegistry::RegisterMCCodeEmitter(TheMSP430Target,
                                        createMSP430MCCodeEmitter);

  TargetRegistry::RegisterMCAsmBackend(TheMSP430Target,
                                       createMSP430MCAsmBackend);

  TargetRegistry::RegisterMCAsmInfo(TheMSP430Target,
                                    createMSP430MCAsmInfo);
}
