//===-- X86AsmBackend.cpp - X86 Assembler Backend -------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/X86BaseInfo.h"
#include "MCTargetDesc/X86FixupKinds.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixupKindInfo.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/Support/ELF.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

static unsigned getFixupKindLog2Size(unsigned Kind) {
  switch (Kind) {
  default:
    llvm_unreachable("invalid fixup kind!");
  case FK_PCRel_1:
  case FK_SecRel_1:
  case FK_Data_1:
    return 0;
  case FK_PCRel_2:
  case FK_SecRel_2:
  case FK_Data_2:
    return 1;
  case FK_PCRel_4:
  case X86::reloc_riprel_4byte:
  case X86::reloc_riprel_4byte_movq_load:
  case X86::reloc_signed_4byte:
  case X86::reloc_global_offset_table:
  case FK_SecRel_4:
  case FK_Data_4:
    return 2;
  case FK_PCRel_8:
  case FK_SecRel_8:
  case FK_Data_8:
  case X86::reloc_global_offset_table8:
    return 3;
  }
}

namespace {

class X86ELFObjectWriter : public MCELFObjectTargetWriter {
public:
  X86ELFObjectWriter(bool is64Bit, uint8_t OSABI, uint16_t EMachine,
                     bool HasRelocationAddend, bool foobar)
    : MCELFObjectTargetWriter(is64Bit, OSABI, EMachine, HasRelocationAddend) {}
};

class X86AsmBackend : public MCAsmBackend {
  const StringRef CPU;
  bool HasNopl;
  uint64_t MaxNopLength;
public:
  X86AsmBackend(const Target &T, StringRef CPU) : MCAsmBackend(), CPU(CPU) {
    HasNopl = CPU != "generic" && CPU != "i386" && CPU != "i486" &&
              CPU != "i586" && CPU != "pentium" && CPU != "pentium-mmx" &&
              CPU != "i686" && CPU != "k6" && CPU != "k6-2" && CPU != "k6-3" &&
              CPU != "geode" && CPU != "winchip-c6" && CPU != "winchip2" &&
              CPU != "c3" && CPU != "c3-2";
    // Max length of true long nop instruction is 15 bytes.
    // Max length of long nop replacement instruction is 7 bytes.
    // Taking into account SilverMont architecture features max length of nops
    // is reduced for it to achieve better performance.
    MaxNopLength = (!HasNopl || CPU == "slm") ? 7 : 15;
  }

  unsigned getNumFixupKinds() const override {
    return X86::NumTargetFixupKinds;
  }

  const MCFixupKindInfo &getFixupKindInfo(MCFixupKind Kind) const override {
    const static MCFixupKindInfo Infos[X86::NumTargetFixupKinds] = {
      { "reloc_riprel_4byte", 0, 4 * 8, MCFixupKindInfo::FKF_IsPCRel, },
      { "reloc_riprel_4byte_movq_load", 0, 4 * 8, MCFixupKindInfo::FKF_IsPCRel,},
      { "reloc_signed_4byte", 0, 4 * 8, 0},
      { "reloc_global_offset_table", 0, 4 * 8, 0},
      { "reloc_global_offset_table8", 0, 8 * 8, 0},
    };

    if (Kind < FirstTargetFixupKind)
      return MCAsmBackend::getFixupKindInfo(Kind);

    assert(unsigned(Kind - FirstTargetFixupKind) < getNumFixupKinds() &&
           "Invalid kind!");
    return Infos[Kind - FirstTargetFixupKind];
  }

  void applyFixup(const MCFixup &Fixup, char *Data, unsigned DataSize,
                  uint64_t Value, bool IsPCRel) const override {
    unsigned Size = 1 << getFixupKindLog2Size(Fixup.getKind());

    assert(Fixup.getOffset() + Size <= DataSize &&
           "Invalid fixup offset!");

    // Check that uppper bits are either all zeros or all ones.
    // Specifically ignore overflow/underflow as long as the leakage is
    // limited to the lower bits. This is to remain compatible with
    // other assemblers.
    assert(isIntN(Size * 8 + 1, Value) &&
           "Value does not fit in the Fixup field");

    for (unsigned i = 0; i != Size; ++i)
      Data[Fixup.getOffset() + i] = uint8_t(Value >> (i * 8));
  }

  bool mayNeedRelaxation(const MCInst &Inst) const override;

  bool fixupNeedsRelaxation(const MCFixup &Fixup, uint64_t Value,
                            const MCRelaxableFragment *DF,
                            const MCAsmLayout &Layout) const override;

  void relaxInstruction(const MCInst &Inst, MCInst &Res) const override;

  bool writeNopData(uint64_t Count, MCObjectWriter *OW) const override;
};
} // end anonymous namespace

static unsigned getRelaxedOpcodeBranch(unsigned Op) {
  switch (Op) {
  default:
    return Op;

  case X86::JAE_1: return X86::JAE_4;
  case X86::JA_1:  return X86::JA_4;
  case X86::JBE_1: return X86::JBE_4;
  case X86::JB_1:  return X86::JB_4;
  case X86::JE_1:  return X86::JE_4;
  case X86::JGE_1: return X86::JGE_4;
  case X86::JG_1:  return X86::JG_4;
  case X86::JLE_1: return X86::JLE_4;
  case X86::JL_1:  return X86::JL_4;
  case X86::JMP_1: return X86::JMP_4;
  case X86::JNE_1: return X86::JNE_4;
  case X86::JNO_1: return X86::JNO_4;
  case X86::JNP_1: return X86::JNP_4;
  case X86::JNS_1: return X86::JNS_4;
  case X86::JO_1:  return X86::JO_4;
  case X86::JP_1:  return X86::JP_4;
  case X86::JS_1:  return X86::JS_4;
  }
}

static unsigned getRelaxedOpcodeArith(unsigned Op) {
  switch (Op) {
  default:
    return Op;

    // IMUL
  case X86::IMUL16rri8: return X86::IMUL16rri;
  case X86::IMUL16rmi8: return X86::IMUL16rmi;
  case X86::IMUL32rri8: return X86::IMUL32rri;
  case X86::IMUL32rmi8: return X86::IMUL32rmi;
  case X86::IMUL64rri8: return X86::IMUL64rri32;
  case X86::IMUL64rmi8: return X86::IMUL64rmi32;

    // AND
  case X86::AND16ri8: return X86::AND16ri;
  case X86::AND16mi8: return X86::AND16mi;
  case X86::AND32ri8: return X86::AND32ri;
  case X86::AND32mi8: return X86::AND32mi;
  case X86::AND64ri8: return X86::AND64ri32;
  case X86::AND64mi8: return X86::AND64mi32;

    // OR
  case X86::OR16ri8: return X86::OR16ri;
  case X86::OR16mi8: return X86::OR16mi;
  case X86::OR32ri8: return X86::OR32ri;
  case X86::OR32mi8: return X86::OR32mi;
  case X86::OR64ri8: return X86::OR64ri32;
  case X86::OR64mi8: return X86::OR64mi32;

    // XOR
  case X86::XOR16ri8: return X86::XOR16ri;
  case X86::XOR16mi8: return X86::XOR16mi;
  case X86::XOR32ri8: return X86::XOR32ri;
  case X86::XOR32mi8: return X86::XOR32mi;
  case X86::XOR64ri8: return X86::XOR64ri32;
  case X86::XOR64mi8: return X86::XOR64mi32;

    // ADD
  case X86::ADD16ri8: return X86::ADD16ri;
  case X86::ADD16mi8: return X86::ADD16mi;
  case X86::ADD32ri8: return X86::ADD32ri;
  case X86::ADD32mi8: return X86::ADD32mi;
  case X86::ADD64ri8: return X86::ADD64ri32;
  case X86::ADD64mi8: return X86::ADD64mi32;

   // ADC
  case X86::ADC16ri8: return X86::ADC16ri;
  case X86::ADC16mi8: return X86::ADC16mi;
  case X86::ADC32ri8: return X86::ADC32ri;
  case X86::ADC32mi8: return X86::ADC32mi;
  case X86::ADC64ri8: return X86::ADC64ri32;
  case X86::ADC64mi8: return X86::ADC64mi32;

    // SUB
  case X86::SUB16ri8: return X86::SUB16ri;
  case X86::SUB16mi8: return X86::SUB16mi;
  case X86::SUB32ri8: return X86::SUB32ri;
  case X86::SUB32mi8: return X86::SUB32mi;
  case X86::SUB64ri8: return X86::SUB64ri32;
  case X86::SUB64mi8: return X86::SUB64mi32;

   // SBB
  case X86::SBB16ri8: return X86::SBB16ri;
  case X86::SBB16mi8: return X86::SBB16mi;
  case X86::SBB32ri8: return X86::SBB32ri;
  case X86::SBB32mi8: return X86::SBB32mi;
  case X86::SBB64ri8: return X86::SBB64ri32;
  case X86::SBB64mi8: return X86::SBB64mi32;

    // CMP
  case X86::CMP16ri8: return X86::CMP16ri;
  case X86::CMP16mi8: return X86::CMP16mi;
  case X86::CMP32ri8: return X86::CMP32ri;
  case X86::CMP32mi8: return X86::CMP32mi;
  case X86::CMP64ri8: return X86::CMP64ri32;
  case X86::CMP64mi8: return X86::CMP64mi32;

    // PUSH
  case X86::PUSH32i8:  return X86::PUSHi32;
  case X86::PUSH16i8:  return X86::PUSHi16;
  case X86::PUSH64i8:  return X86::PUSH64i32;
  }
}

static unsigned getRelaxedOpcode(unsigned Op) {
  unsigned R = getRelaxedOpcodeArith(Op);
  if (R != Op)
    return R;
  return getRelaxedOpcodeBranch(Op);
}

bool X86AsmBackend::mayNeedRelaxation(const MCInst &Inst) const {
  // Branches can always be relaxed.
  if (getRelaxedOpcodeBranch(Inst.getOpcode()) != Inst.getOpcode())
    return true;

  // Check if this instruction is ever relaxable.
  if (getRelaxedOpcodeArith(Inst.getOpcode()) == Inst.getOpcode())
    return false;


  // Check if the relaxable operand has an expression. For the current set of
  // relaxable instructions, the relaxable operand is always the last operand.
  unsigned RelaxableOp = Inst.getNumOperands() - 1;
  if (Inst.getOperand(RelaxableOp).isExpr())
    return true;

  return false;
}

bool X86AsmBackend::fixupNeedsRelaxation(const MCFixup &Fixup,
                                         uint64_t Value,
                                         const MCRelaxableFragment *DF,
                                         const MCAsmLayout &Layout) const {
  // Relax if the value is too big for a (signed) i8.
  return int64_t(Value) != int64_t(int8_t(Value));
}

// FIXME: Can tblgen help at all here to verify there aren't other instructions
// we can relax?
void X86AsmBackend::relaxInstruction(const MCInst &Inst, MCInst &Res) const {
  // The only relaxations X86 does is from a 1byte pcrel to a 4byte pcrel.
  unsigned RelaxedOp = getRelaxedOpcode(Inst.getOpcode());

  if (RelaxedOp == Inst.getOpcode()) {
    SmallString<256> Tmp;
    raw_svector_ostream OS(Tmp);
    OS << "\n";
    report_fatal_error("unexpected instruction to relax: " + OS.str());
  }

  Res = Inst;
  Res.setOpcode(RelaxedOp);
}

/// \brief Write a sequence of optimal nops to the output, covering \p Count
/// bytes.
/// \return - true on success, false on failure
bool X86AsmBackend::writeNopData(uint64_t Count, MCObjectWriter *OW) const {
  static const uint8_t TrueNops[10][10] = {
    // nop
    {0x90},
    // xchg %ax,%ax
    {0x66, 0x90},
    // nopl (%[re]ax)
    {0x0f, 0x1f, 0x00},
    // nopl 0(%[re]ax)
    {0x0f, 0x1f, 0x40, 0x00},
    // nopl 0(%[re]ax,%[re]ax,1)
    {0x0f, 0x1f, 0x44, 0x00, 0x00},
    // nopw 0(%[re]ax,%[re]ax,1)
    {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},
    // nopl 0L(%[re]ax)
    {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},
    // nopl 0L(%[re]ax,%[re]ax,1)
    {0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
    // nopw 0L(%[re]ax,%[re]ax,1)
    {0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
    // nopw %cs:0L(%[re]ax,%[re]ax,1)
    {0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
  };

  // Alternative nop instructions for CPUs which don't support long nops.
  static const uint8_t AltNops[7][10] = {
      // nop
      {0x90},
      // xchg %ax,%ax
      {0x66, 0x90},
      // lea 0x0(%esi),%esi
      {0x8d, 0x76, 0x00},
      // lea 0x0(%esi),%esi
      {0x8d, 0x74, 0x26, 0x00},
      // nop + lea 0x0(%esi),%esi
      {0x90, 0x8d, 0x74, 0x26, 0x00},
      // lea 0x0(%esi),%esi
      {0x8d, 0xb6, 0x00, 0x00, 0x00, 0x00 },
      // lea 0x0(%esi),%esi
      {0x8d, 0xb4, 0x26, 0x00, 0x00, 0x00, 0x00},
  };

  // Select the right NOP table.
  // FIXME: Can we get if CPU supports long nops from the subtarget somehow?
  const uint8_t (*Nops)[10] = HasNopl ? TrueNops : AltNops;
  assert(HasNopl || MaxNopLength <= 7);

  // Emit as many largest nops as needed, then emit a nop of the remaining
  // length.
  do {
    const uint8_t ThisNopLength = (uint8_t) std::min(Count, MaxNopLength);
    const uint8_t Prefixes = ThisNopLength <= 10 ? 0 : ThisNopLength - 10;
    for (uint8_t i = 0; i < Prefixes; i++)
      OW->write8(0x66);
    const uint8_t Rest = ThisNopLength - Prefixes;
    for (uint8_t i = 0; i < Rest; i++)
      OW->write8(Nops[Rest - 1][i]);
    Count -= ThisNopLength;
  } while (Count != 0);

  return true;
}

/* *** */

namespace {

class ELFX86AsmBackend : public X86AsmBackend {
public:
  uint8_t OSABI;
  ELFX86AsmBackend(const Target &T, uint8_t OSABI, StringRef CPU)
      : X86AsmBackend(T, CPU), OSABI(OSABI) {}
};

class ELFX86_32AsmBackend : public ELFX86AsmBackend {
public:
  ELFX86_32AsmBackend(const Target &T, uint8_t OSABI, StringRef CPU)
    : ELFX86AsmBackend(T, OSABI, CPU) {}

  MCObjectWriter *createObjectWriter(raw_pwrite_stream &OS) const override {
    return createX86ELFObjectWriter(OS, /*IsELF64*/ false, OSABI, ELF::EM_386);
  }
};

class ELFX86_X32AsmBackend : public ELFX86AsmBackend {
public:
  ELFX86_X32AsmBackend(const Target &T, uint8_t OSABI, StringRef CPU)
      : ELFX86AsmBackend(T, OSABI, CPU) {}

  MCObjectWriter *createObjectWriter(raw_pwrite_stream &OS) const override {
    return createX86ELFObjectWriter(OS, /*IsELF64*/ false, OSABI,
                                    ELF::EM_X86_64);
  }
};

class ELFX86_IAMCUAsmBackend : public ELFX86AsmBackend {
public:
  ELFX86_IAMCUAsmBackend(const Target &T, uint8_t OSABI, StringRef CPU)
      : ELFX86AsmBackend(T, OSABI, CPU) {}

  MCObjectWriter *createObjectWriter(raw_pwrite_stream &OS) const override {
    return createX86ELFObjectWriter(OS, /*IsELF64*/ false, OSABI,
                                    ELF::EM_IAMCU);
  }
};

class ELFX86_64AsmBackend : public ELFX86AsmBackend {
public:
  ELFX86_64AsmBackend(const Target &T, uint8_t OSABI, StringRef CPU)
    : ELFX86AsmBackend(T, OSABI, CPU) {}

  MCObjectWriter *createObjectWriter(raw_pwrite_stream &OS) const override {
    return createX86ELFObjectWriter(OS, /*IsELF64*/ true, OSABI, ELF::EM_X86_64);
  }
};

namespace CU {

  /// Compact unwind encoding values.
  enum CompactUnwindEncodings {
    /// [RE]BP based frame where [RE]BP is pused on the stack immediately after
    /// the return address, then [RE]SP is moved to [RE]BP.
    UNWIND_MODE_BP_FRAME                   = 0x01000000,

    /// A frameless function with a small constant stack size.
    UNWIND_MODE_STACK_IMMD                 = 0x02000000,

    /// A frameless function with a large constant stack size.
    UNWIND_MODE_STACK_IND                  = 0x03000000,

    /// No compact unwind encoding is available.
    UNWIND_MODE_DWARF                      = 0x04000000,

    /// Mask for encoding the frame registers.
    UNWIND_BP_FRAME_REGISTERS              = 0x00007FFF,

    /// Mask for encoding the frameless registers.
    UNWIND_FRAMELESS_STACK_REG_PERMUTATION = 0x000003FF
  };

} // end CU namespace
} // end anonymous namespace

MCAsmBackend *llvm::createX86_32AsmBackend(const Target &T,
                                           const MCRegisterInfo &MRI,
                                           const Triple &TheTriple,
                                           StringRef CPU) {
  uint8_t OSABI = MCELFObjectTargetWriter::getOSABI(TheTriple.getOS());

  if (TheTriple.isOSIAMCU())
    return new ELFX86_IAMCUAsmBackend(T, OSABI, CPU);

  return new ELFX86_32AsmBackend(T, OSABI, CPU);
}

MCAsmBackend *llvm::createX86_64AsmBackend(const Target &T,
                                           const MCRegisterInfo &MRI,
                                           const Triple &TheTriple,
                                           StringRef CPU) {
  uint8_t OSABI = MCELFObjectTargetWriter::getOSABI(TheTriple.getOS());

  if (TheTriple.getEnvironment() == Triple::GNUX32)
    return new ELFX86_X32AsmBackend(T, OSABI, CPU);
  return new ELFX86_64AsmBackend(T, OSABI, CPU);
}
