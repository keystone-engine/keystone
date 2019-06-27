//===-- HexagonMCTargetDesc.cpp - Hexagon Target Descriptions -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides Hexagon specific target descriptions.
//
//===----------------------------------------------------------------------===//

#include "HexagonMCTargetDesc.h"
#include "Hexagon.h"
#include "HexagonMCAsmInfo.h"
#include "HexagonMCELFStreamer.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCELFStreamer.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectStreamer.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MachineLocation.h"
#include "llvm/Support/ELF.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm_ks;

#define GET_INSTRINFO_MC_DESC
#include "HexagonGenInstrInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "HexagonGenSubtargetInfo.inc"

#define GET_REGINFO_MC_DESC
#include "HexagonGenRegisterInfo.inc"

bool llvm_ks::HexagonDisableCompound;

bool llvm_ks::HexagonDisableDuplex;

StringRef HEXAGON_MC::selectHexagonCPU(const Triple &TT, StringRef CPU) {
  if (CPU.empty())
    CPU = "hexagonv60";
  return CPU;
}

MCInstrInfo *llvm_ks::createHexagonMCInstrInfo() {
  MCInstrInfo *X = new MCInstrInfo();
  InitHexagonMCInstrInfo(X);
  return X;
}

static MCRegisterInfo *createHexagonMCRegisterInfo(const Triple &TT) {
  MCRegisterInfo *X = new MCRegisterInfo();
  InitHexagonMCRegisterInfo(X, Hexagon::R0);
  return X;
}

static MCSubtargetInfo *
createHexagonMCSubtargetInfo(const Triple &TT, StringRef CPU, StringRef FS) {
  CPU = HEXAGON_MC::selectHexagonCPU(TT, CPU);
  return createHexagonMCSubtargetInfoImpl(TT, CPU, FS);
}

namespace {
class HexagonTargetELFStreamer : public HexagonTargetStreamer {
public:
  MCELFStreamer &getStreamer() {
    return static_cast<MCELFStreamer &>(Streamer);
  }
  HexagonTargetELFStreamer(MCStreamer &S, MCSubtargetInfo const &STI)
      : HexagonTargetStreamer(S) {
    auto Bits = STI.getFeatureBits();
    unsigned Flags;
    if (Bits.to_ullong() & llvm_ks::Hexagon::ArchV5)
      Flags = ELF::EF_HEXAGON_MACH_V5;
    else
      Flags = ELF::EF_HEXAGON_MACH_V4;
    getStreamer().getAssembler().setELFHeaderEFlags(Flags);
  }
  void EmitCommonSymbolSorted(MCSymbol *Symbol, uint64_t Size,
                              unsigned ByteAlignment,
                              unsigned AccessSize) override {
    HexagonMCELFStreamer &HexagonELFStreamer =
        static_cast<HexagonMCELFStreamer &>(getStreamer());
    HexagonELFStreamer.HexagonMCEmitCommonSymbol(Symbol, Size, ByteAlignment,
                                                 AccessSize);
  }
  void EmitLocalCommonSymbolSorted(MCSymbol *Symbol, uint64_t Size,
                                   unsigned ByteAlignment,
                                   unsigned AccessSize) override {
    HexagonMCELFStreamer &HexagonELFStreamer =
        static_cast<HexagonMCELFStreamer &>(getStreamer());
    HexagonELFStreamer.HexagonMCEmitLocalCommonSymbol(
        Symbol, Size, ByteAlignment, AccessSize);
  }
};
}

static MCAsmInfo *createHexagonMCAsmInfo(const MCRegisterInfo &MRI,
                                         const Triple &TT) {
  MCAsmInfo *MAI = new HexagonMCAsmInfo(TT);

  // VirtualFP = (R30 + #0).
  MCCFIInstruction Inst =
      MCCFIInstruction::createDefCfa(nullptr, Hexagon::R30, 0);
  MAI->addInitialFrameState(Inst);

  return MAI;
}

// Force static initialization.
extern "C" void LLVMInitializeHexagonTargetMC() {
  // Register the MC asm info.
  RegisterMCAsmInfoFn X(TheHexagonTarget, createHexagonMCAsmInfo);

  // Register the MC instruction info.
  TargetRegistry::RegisterMCInstrInfo(TheHexagonTarget,
                                      createHexagonMCInstrInfo);

  // Register the MC register info.
  TargetRegistry::RegisterMCRegInfo(TheHexagonTarget,
                                    createHexagonMCRegisterInfo);

  // Register the MC subtarget info.
  TargetRegistry::RegisterMCSubtargetInfo(TheHexagonTarget,
                                          createHexagonMCSubtargetInfo);

  // Register the MC Code Emitter
  TargetRegistry::RegisterMCCodeEmitter(TheHexagonTarget,
                                        createHexagonMCCodeEmitter);

  // Register the asm backend
  TargetRegistry::RegisterMCAsmBackend(TheHexagonTarget,
                                       createHexagonAsmBackend);
}
