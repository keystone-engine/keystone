//===-- MSP430ELFStreamer.cpp - MSP430 ELF Target Streamer Methods --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides MSP430 specific target streamer methods.
//
//===----------------------------------------------------------------------===//

#include "MSP430ELFBackport.h"
#include "MSP430MCTargetDesc.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCELFStreamer.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"

using namespace llvm_ks;

namespace llvm_ks {

class MSP430TargetELFStreamer : public MCTargetStreamer {
public:
  MCELFStreamer &getStreamer();
  MSP430TargetELFStreamer(MCStreamer &S, const MCSubtargetInfo &STI);
};

// This part is for ELF object output.
MSP430TargetELFStreamer::MSP430TargetELFStreamer(MCStreamer &S,
                                                 const MCSubtargetInfo &STI)
    : MCTargetStreamer(S) {
  MCAssembler &MCA = getStreamer().getAssembler();
  unsigned EFlags = MCA.getELFHeaderEFlags();
  MCA.setELFHeaderEFlags(EFlags);

  // Emit build attributes section according to
  // MSP430 EABI (slaa534.pdf, part 13).
  MCSection *AttributeSection = getStreamer().getContext().getELFSection(
      ".MSP430.attributes", SHT_MSP430_ATTRIBUTES, 0);
  Streamer.SwitchSection(AttributeSection);

  bool Error;
  // Format version.
  Streamer.EmitIntValue(0x41, 1, Error);
  // Subsection length.
  Streamer.EmitIntValue(22, 4, Error);
  // Vendor name string, zero-terminated.
  Streamer.EmitBytes("mspabi");
  Streamer.EmitIntValue(0, 1, Error);

  // Attribute vector scope tag. 1 stands for the entire file.
  Streamer.EmitIntValue(1, 1, Error);
  // Attribute vector length.
  Streamer.EmitIntValue(11, 4, Error);
  // OFBA_MSPABI_Tag_ISA(4) = 1, MSP430
  Streamer.EmitIntValue(4, 1, Error);
  Streamer.EmitIntValue(1, 1, Error);
  // OFBA_MSPABI_Tag_Code_Model(6) = 1, Small
  Streamer.EmitIntValue(6, 1, Error);
  Streamer.EmitIntValue(1, 1, Error);
  // OFBA_MSPABI_Tag_Data_Model(8) = 1, Small
  Streamer.EmitIntValue(8, 1, Error);
  Streamer.EmitIntValue(1, 1, Error);
}

MCELFStreamer &MSP430TargetELFStreamer::getStreamer() {
  return static_cast<MCELFStreamer &>(Streamer);
}

} // namespace llvm
