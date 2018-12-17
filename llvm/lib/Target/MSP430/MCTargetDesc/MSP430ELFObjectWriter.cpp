//===-- MSP430ELFObjectWriter.cpp - MSP430 ELF Writer ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MSP430ELFBackport.h"
#include "MSP430FixupKinds.h"
#include "MSP430MCTargetDesc.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCFixup.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCValue.h"
#include "llvm/Support/ErrorHandling.h"

using namespace llvm_ks;

namespace {
class MSP430ELFObjectWriter : public MCELFObjectTargetWriter {
public:
  MSP430ELFObjectWriter(uint8_t OSABI)
    : MCELFObjectTargetWriter(false, OSABI, ELF::EM_MSP430,
                              /*HasRelocationAddend*/ true) {}

  ~MSP430ELFObjectWriter() override {}

protected:
  unsigned getRelocType(MCContext &Ctx, const MCValue &Target,
                        const MCFixup &Fixup, bool IsPCRel) const override {
    // Translate fixup kind to ELF relocation type.
    switch ((unsigned)Fixup.getKind()) {
    case FK_Data_1:                   return R_MSP430_8;
    case FK_Data_2:                   return R_MSP430_16_BYTE;
    case FK_Data_4:                   return R_MSP430_32;
    case MSP430::fixup_32:            return R_MSP430_32;
    case MSP430::fixup_10_pcrel:      return R_MSP430_10_PCREL;
    case MSP430::fixup_16:            return R_MSP430_16;
    case MSP430::fixup_16_pcrel:      return R_MSP430_16_PCREL;
    case MSP430::fixup_16_byte:       return R_MSP430_16_BYTE;
    case MSP430::fixup_16_pcrel_byte: return R_MSP430_16_PCREL_BYTE;
    case MSP430::fixup_2x_pcrel:      return R_MSP430_2X_PCREL;
    case MSP430::fixup_rl_pcrel:      return R_MSP430_RL_PCREL;
    case MSP430::fixup_8:             return R_MSP430_8;
    case MSP430::fixup_sym_diff:      return R_MSP430_SYM_DIFF;
    default:
      llvm_unreachable("Invalid fixup kind");
    }
  }
};
} // end of anonymous namespace

MCObjectWriter *llvm_ks::createMSP430ObjectWriter(raw_pwrite_stream &OS,
                                                   uint8_t OSABI) {
    MCELFObjectTargetWriter *MOTW = new MSP430ELFObjectWriter(OSABI);
    return createELFObjectWriter(MOTW, OS, /*IsLittleEndian=*/false);
}