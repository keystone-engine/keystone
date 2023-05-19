//===-- RISCVAsmBackend.h - RISCV Assembler Backend -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RISCV_MCTARGETDESC_RISCVASMBACKEND_H
#define LLVM_LIB_TARGET_RISCV_MCTARGETDESC_RISCVASMBACKEND_H

#include "MCTargetDesc/RISCVFixupKinds.h"
#include "MCTargetDesc/RISCVMCTargetDesc.h"
#include "Utils/RISCVBaseInfo.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCFixupKindInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/ADT/STLExtras.h"


namespace llvm_ks {
class MCAssembler;
class MCObjectWriter;
class raw_ostream;

class RISCVAsmBackend : public MCAsmBackend {
  

  Triple::OSType OSType;
  bool IsLittle; // Big or little endian
  bool Is64Bit;  // 32 or 64 bit words
  bool ForceRelocs = false;
  RISCVABI::ABI TargetABI = RISCVABI::ABI_Unknown;
  const MCSubtargetInfo &STI;
  const MCTargetOptions &TargetOptions;
  uint8_t OSABI;

public:
  RISCVAsmBackend(const Target &T, Triple::OSType OSType, bool IsLittle,
                 bool Is64Bit, const MCSubtargetInfo &STI, const MCTargetOptions &Options)
      : MCAsmBackend(), OSType(OSType), IsLittle(IsLittle), Is64Bit(Is64Bit),STI(STI), TargetOptions(Options){
    TargetABI = RISCVABI::computeTargetABI(
        STI.getTargetTriple(), STI.getFeatureBits(), Options.getABIName());
    RISCVFeatures::validate(STI.getTargetTriple(), STI.getFeatureBits());
    
  }
  ~RISCVAsmBackend() override {}

  void setForceRelocs() { ForceRelocs = true; }

  // Returns true if relocations will be forced for shouldForceRelocation by
  // default. This will be true if relaxation is enabled or had previously
  // been enabled.
  bool willForceRelocations() const {
    return ForceRelocs || STI.getFeatureBits()[RISCV::FeatureRelax];
  }

  // Generate diff expression relocations if the relax feature is enabled or had
  // previously been enabled, otherwise it is safe for the assembler to
  // calculate these internally.
  bool requiresDiffExpressionRelocations() const {
    return willForceRelocations();
  }

  // Return Size with extra Nop Bytes for alignment directive in code section.
  bool shouldInsertExtraNopBytesForCodeAlign(const MCAlignFragment &AF,
                                             unsigned &Size);

  // Insert target specific fixup type for alignment directive in code section.
  bool shouldInsertFixupForCodeAlign(MCAssembler &Asm,
                                     const MCAsmLayout &Layout,
                                     MCAlignFragment &AF);

  void applyFixup(const MCFixup &Fixup, char *Data, unsigned DataSize,
                          uint64_t Value, bool IsPCRel, unsigned int &KsError) const override;

  MCObjectWriter *createObjectWriter(raw_pwrite_stream &OS) const override;

  bool shouldForceRelocation(const MCAssembler &Asm, const MCFixup &Fixup,
                             const MCValue &Target);

  bool fixupNeedsRelaxation(const MCFixup &Fixup, uint64_t Value,
                            const MCRelaxableFragment *DF,
                            const MCAsmLayout &Layout, unsigned &KsError) const override {
    llvm_unreachable("Handled by fixupNeedsRelaxationAdvanced");
  }

  bool fixupNeedsRelaxationAdvanced(const MCFixup &Fixup, bool Resolved,
                                    uint64_t Value,
                                    const MCRelaxableFragment *DF,
                                    const MCAsmLayout &Layout) const override;

  unsigned getNumFixupKinds() const override {
    return RISCV::NumTargetFixupKinds;
  }

  const MCFixupKindInfo &getFixupKindInfo(MCFixupKind Kind) const override {
    const static MCFixupKindInfo Infos[] = {
      // This table *must* be in the order that the fixup_* kinds are defined in
      // RISCVFixupKinds.h.
      //
      // name                      offset bits  flags
      { "fixup_riscv_hi20",         12,     20,  0 },
      { "fixup_riscv_lo12_i",       20,     12,  0 },
      { "fixup_riscv_lo12_s",        0,     32,  0 },
      { "fixup_riscv_pcrel_hi20",   12,     20,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_pcrel_lo12_i", 20,     12,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_pcrel_lo12_s",  0,     32,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_got_hi20",     12,     20,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_tprel_hi20",   12,     20,  0 },
      { "fixup_riscv_tprel_lo12_i", 20,     12,  0 },
      { "fixup_riscv_tprel_lo12_s",  0,     32,  0 },
      { "fixup_riscv_tprel_add",     0,      0,  0 },
      { "fixup_riscv_tls_got_hi20", 12,     20,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_tls_gd_hi20",  12,     20,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_jal",          12,     20,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_branch",        0,     32,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_rvc_jump",      2,     11,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_rvc_branch",    0,     16,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_call",          0,     64,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_call_plt",      0,     64,  MCFixupKindInfo::FKF_IsPCRel },
      { "fixup_riscv_relax",         0,      0,  0 },
      { "fixup_riscv_align",         0,      0,  0 }
    };
    static_assert((array_lengthof(Infos)) == RISCV::NumTargetFixupKinds,
                  "Not all fixup kinds added to Infos array");

    if (Kind < FirstTargetFixupKind)
      return MCAsmBackend::getFixupKindInfo(Kind);

    assert(unsigned(Kind - FirstTargetFixupKind) < getNumFixupKinds() &&
           "Invalid kind!");
    return Infos[Kind - FirstTargetFixupKind];
  }

  bool mayNeedRelaxation(const MCInst &Inst) const override;
  unsigned getRelaxedOpcode(unsigned Op) const;

  void relaxInstruction(const MCInst &Inst,
                        MCInst &Res) const override;


  bool writeNopData(uint64_t Count, MCObjectWriter * OW) const override;

  const MCTargetOptions &getTargetOptions() const { return TargetOptions; }
  RISCVABI::ABI getTargetABI() const { return TargetABI; }
};
}

#endif
