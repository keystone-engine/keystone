//===-- MSP430AsmBackend.cpp - MSP430 Assembler Backend -------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MSP430FixupKinds.h"
#include "MSP430MCTargetDesc.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAssembler.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDirectives.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixupKindInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm_ks;

namespace {
class MSP430AsmBackend : public MCAsmBackend {
    uint8_t OSABI;
public:
    MSP430AsmBackend(uint8_t osABI)
            : OSABI(osABI) {}

    // Override MCAsmBackend
    unsigned getNumFixupKinds() const override {
      return MSP430::NumTargetFixupKinds;
    }
    const MCFixupKindInfo &getFixupKindInfo(MCFixupKind Kind) const override {
        const static MCFixupKindInfo Infos[MSP430::NumTargetFixupKinds] = {
                // This table must be in the same order of enum in MSP430FixupKinds.h.
                //
                // name            offset bits flags
                {"fixup_32",            0, 32, 0},
                {"fixup_10_pcrel",      0, 10, MCFixupKindInfo::FKF_IsPCRel},
                {"fixup_16",            0, 16, 0},
                {"fixup_16_pcrel",      0, 16, MCFixupKindInfo::FKF_IsPCRel},
                {"fixup_16_byte",       0, 16, 0},
                {"fixup_16_pcrel_byte", 0, 16, MCFixupKindInfo::FKF_IsPCRel},
                {"fixup_2x_pcrel",      0, 10, MCFixupKindInfo::FKF_IsPCRel},
                {"fixup_rl_pcrel",      0, 16, MCFixupKindInfo::FKF_IsPCRel},
                {"fixup_8",             0,  8, 0},
                {"fixup_sym_diff",      0, 32, 0},
        };
        static_assert((array_lengthof(Infos)) == MSP430::NumTargetFixupKinds,
                      "Not all fixup kinds added to Infos array");

        if (Kind < FirstTargetFixupKind)
            return MCAsmBackend::getFixupKindInfo(Kind);

        return Infos[Kind - FirstTargetFixupKind];
    }
    void applyFixup(const MCFixup &Fixup, char *Data, unsigned DataSize,
                    uint64_t Value, bool IsPCRel, unsigned int &KsError) const override;
    bool mayNeedRelaxation(const MCInst &Inst) const override {
      return false;
    }
    bool fixupNeedsRelaxation(const MCFixup &Fixup, uint64_t Value,
                              const MCRelaxableFragment *Fragment,
                              const MCAsmLayout &Layout, unsigned &KsError) const override {
      return false;
    }
    void relaxInstruction(const MCInst &Inst, MCInst &Res) const override {
      llvm_unreachable("MSP430 does do not have assembler relaxation");
    }
    bool writeNopData(uint64_t Count, MCObjectWriter *OW) const override {
      if ((Count % 2) != 0)
        return false;

      // The canonical nop on MSP430 is mov #0, r3
      uint64_t NopCount = Count / 2;
      while (NopCount--)
        OW->write16(0x0343);

      return true;
    }

    MCObjectWriter *createObjectWriter(raw_pwrite_stream &OS) const override {
      return createMSP430ObjectWriter(OS, OSABI);
    }

    uint64_t adjustFixupValue(const MCFixup &Fixup, uint64_t Value, unsigned int &KsError) const {
      unsigned Kind = Fixup.getKind();
      switch (Kind) {
        case MSP430::fixup_10_pcrel: {
          if (Value & 0x1) KsError = KS_ERR_ASM;

          // Offset is signed
          int16_t Offset = Value;
          // Jumps are in words
          Offset >>= 1;
          // PC points to the next instruction so decrement by one
          --Offset;

          if (Offset < -512 || Offset > 511) KsError = KS_ERR_ASM;

          // Mask 10 bits
          Offset &= 0x3ff;

          return Offset;
        }
        default:
          return Value;
      }
    };
};

void MSP430AsmBackend::applyFixup(const MCFixup &Fixup,
                                  char *Data,
                                  unsigned DataSize,
                                  uint64_t Value, bool IsPCRel,
                                  unsigned int &KsError) const {
  Value = adjustFixupValue(Fixup, Value, KsError);
  MCFixupKindInfo Info = getFixupKindInfo(Fixup.getKind());
  if (!Value)
    return; // Doesn't change encoding.

  // Shift the value into position.
  Value <<= Info.TargetOffset;

  unsigned Offset = Fixup.getOffset();
  unsigned NumBytes = alignTo(Info.TargetSize + Info.TargetOffset, 8) / 8;

  assert(Offset + NumBytes <= DataSize && "Invalid fixup offset!");

  // For each byte of the fragment that the fixup touches, mask in the
  // bits from the fixup value.
  for (unsigned i = 0; i != NumBytes; ++i) {
    Data[Offset + i] |= uint8_t((Value >> (i * 8)) & 0xff);
  }
}

} // end anonymous namespace

MCAsmBackend *llvm_ks::createMSP430MCAsmBackend(const Target &T,
                                                const MCRegisterInfo &MRI,
                                                const Triple &TT,
                                                StringRef CPU) {
  return new MSP430AsmBackend(ELF::ELFOSABI_STANDALONE);
}
