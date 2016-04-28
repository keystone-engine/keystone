//===-- X86AsmInstrumentation.cpp - Instrument X86 inline assembly C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "X86AsmInstrumentation.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "X86Operand.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Triple.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstBuilder.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include <algorithm>
#include <cassert>
#include <vector>

//#include <iostream>

// Following comment describes how assembly instrumentation works.
// Currently we have only AddressSanitizer instrumentation, but we're
// planning to implement MemorySanitizer for inline assembly too. If
// you're not familiar with AddressSanitizer algorithm, please, read
// https://code.google.com/p/address-sanitizer/wiki/AddressSanitizerAlgorithm.
//
// When inline assembly is parsed by an instance of X86AsmParser, all
// instructions are emitted via EmitInstruction method. That's the
// place where X86AsmInstrumentation analyzes an instruction and
// decides, whether the instruction should be emitted as is or
// instrumentation is required. The latter case happens when an
// instruction reads from or writes to memory. Now instruction opcode
// is explicitly checked, and if an instruction has a memory operand
// (for instance, movq (%rsi, %rcx, 8), %rax) - it should be
// instrumented.  There're also exist instructions that modify
// memory but don't have an explicit memory operands, for instance,
// movs.
//
// Let's consider at first 8-byte memory accesses when an instruction
// has an explicit memory operand. In this case we need two registers -
// AddressReg to compute address of a memory cells which are accessed
// and ShadowReg to compute corresponding shadow address. So, we need
// to spill both registers before instrumentation code and restore them
// after instrumentation. Thus, in general, instrumentation code will
// look like this:
// PUSHF  # Store flags, otherwise they will be overwritten
// PUSH AddressReg  # spill AddressReg
// PUSH ShadowReg   # spill ShadowReg
// LEA MemOp, AddressReg  # compute address of the memory operand
// MOV AddressReg, ShadowReg
// SHR ShadowReg, 3
// # ShadowOffset(AddressReg >> 3) contains address of a shadow
// # corresponding to MemOp.
// CMP ShadowOffset(ShadowReg), 0  # test shadow value
// JZ .Done  # when shadow equals to zero, everything is fine
// MOV AddressReg, RDI
// # Call __asan_report function with AddressReg as an argument
// CALL __asan_report
// .Done:
// POP ShadowReg  # Restore ShadowReg
// POP AddressReg  # Restore AddressReg
// POPF  # Restore flags
//
// Memory accesses with different size (1-, 2-, 4- and 16-byte) are
// handled in a similar manner, but small memory accesses (less than 8
// byte) require an additional ScratchReg, which is used for shadow value.
//
// If, suppose, we're instrumenting an instruction like movs, only
// contents of RDI, RDI + AccessSize * RCX, RSI, RSI + AccessSize *
// RCX are checked.  In this case there're no need to spill and restore
// AddressReg , ShadowReg or flags four times, they're saved on stack
// just once, before instrumentation of these four addresses, and restored
// at the end of the instrumentation.
//
// There exist several things which complicate this simple algorithm.
// * Instrumented memory operand can have RSP as a base or an index
//   register.  So we need to add a constant offset before computation
//   of memory address, since flags, AddressReg, ShadowReg, etc. were
//   already stored on stack and RSP was modified.
// * Debug info (usually, DWARF) should be adjusted, because sometimes
//   RSP is used as a frame register. So, we need to select some
//   register as a frame register and temprorary override current CFA
//   register.

namespace llvm {
namespace {

const int64_t MinAllowedDisplacement = std::numeric_limits<int32_t>::min();
const int64_t MaxAllowedDisplacement = std::numeric_limits<int32_t>::max();

int64_t ApplyDisplacementBounds(int64_t Displacement) {
  return std::max(std::min(MaxAllowedDisplacement, Displacement),
                  MinAllowedDisplacement);
}

void CheckDisplacementBounds(int64_t Displacement) {
  assert(Displacement >= MinAllowedDisplacement &&
         Displacement <= MaxAllowedDisplacement);
}

bool IsStackReg(unsigned Reg) { return Reg == X86::RSP || Reg == X86::ESP; }

bool IsSmallMemAccess(unsigned AccessSize) { return AccessSize < 8; }

class X86AddressSanitizer : public X86AsmInstrumentation {
public:
  struct RegisterContext {
  private:
    enum RegOffset {
      REG_OFFSET_ADDRESS = 0,
      REG_OFFSET_SHADOW,
      REG_OFFSET_SCRATCH
    };

  public:
    RegisterContext(unsigned AddressReg, unsigned ShadowReg,
                    unsigned ScratchReg) {
      BusyRegs.push_back(convReg(AddressReg, 64));
      BusyRegs.push_back(convReg(ShadowReg, 64));
      BusyRegs.push_back(convReg(ScratchReg, 64));
    }

    unsigned AddressReg(unsigned Size) const {
      return convReg(BusyRegs[REG_OFFSET_ADDRESS], Size);
    }

    unsigned ShadowReg(unsigned Size) const {
      return convReg(BusyRegs[REG_OFFSET_SHADOW], Size);
    }

    unsigned ScratchReg(unsigned Size) const {
      return convReg(BusyRegs[REG_OFFSET_SCRATCH], Size);
    }

    void AddBusyReg(unsigned Reg) {
      if (Reg != X86::NoRegister)
        BusyRegs.push_back(convReg(Reg, 64));
    }

    void AddBusyRegs(const X86Operand &Op) {
      AddBusyReg(Op.getMemBaseReg());
      AddBusyReg(Op.getMemIndexReg());
    }

    unsigned ChooseFrameReg(unsigned Size) const {
      static const MCPhysReg Candidates[] = { X86::RBP, X86::RAX, X86::RBX,
                                              X86::RCX, X86::RDX, X86::RDI,
                                              X86::RSI };
      for (unsigned Reg : Candidates) {
        if (!std::count(BusyRegs.begin(), BusyRegs.end(), Reg))
          return convReg(Reg, Size);
      }
      return X86::NoRegister;
    }

  private:
    unsigned convReg(unsigned Reg, unsigned Size) const {
      return Reg == X86::NoRegister ? Reg : getX86SubSuperRegister(Reg, Size);
    }

    std::vector<unsigned> BusyRegs;
  };

  X86AddressSanitizer(const MCSubtargetInfo *&STI)
      : X86AsmInstrumentation(STI), RepPrefix(false), OrigSPOffset(0) {}

  ~X86AddressSanitizer() override {}

  // X86AsmInstrumentation implementation:
  void InstrumentAndEmitInstruction(MCInst &Inst,
                                    OperandVector &Operands,
                                    MCContext &Ctx,
                                    const MCInstrInfo &MII,
                                    MCStreamer &Out) override {
    InstrumentMOVS(Inst, Operands, Ctx, MII, Out);
    if (RepPrefix)
      EmitInstruction(Out, MCInstBuilder(X86::REP_PREFIX));

    InstrumentMOV(Inst, Operands, Ctx, MII, Out);

    RepPrefix = (Inst.getOpcode() == X86::REP_PREFIX);
    if (!RepPrefix)
      EmitInstruction(Out, Inst);
  }

  // Adjusts up stack and saves all registers used in instrumentation.
  virtual void InstrumentMemOperandPrologue(const RegisterContext &RegCtx,
                                            MCContext &Ctx,
                                            MCStreamer &Out) = 0;

  // Restores all registers used in instrumentation and adjusts stack.
  virtual void InstrumentMemOperandEpilogue(const RegisterContext &RegCtx,
                                            MCContext &Ctx,
                                            MCStreamer &Out) = 0;

  virtual void InstrumentMemOperandSmall(X86Operand &Op, unsigned AccessSize,
                                         bool IsWrite,
                                         const RegisterContext &RegCtx,
                                         MCContext &Ctx, MCStreamer &Out) = 0;
  virtual void InstrumentMemOperandLarge(X86Operand &Op, unsigned AccessSize,
                                         bool IsWrite,
                                         const RegisterContext &RegCtx,
                                         MCContext &Ctx, MCStreamer &Out) = 0;

  virtual void InstrumentMOVSImpl(unsigned AccessSize, MCContext &Ctx,
                                  MCStreamer &Out) = 0;

  void InstrumentMemOperand(X86Operand &Op, unsigned AccessSize, bool IsWrite,
                            const RegisterContext &RegCtx, MCContext &Ctx,
                            MCStreamer &Out);
  void InstrumentMOVSBase(unsigned DstReg, unsigned SrcReg, unsigned CntReg,
                          unsigned AccessSize, MCContext &Ctx, MCStreamer &Out);

  void InstrumentMOVS(const MCInst &Inst, OperandVector &Operands,
                      MCContext &Ctx, const MCInstrInfo &MII, MCStreamer &Out);
  void InstrumentMOV(const MCInst &Inst, OperandVector &Operands,
                     MCContext &Ctx, const MCInstrInfo &MII, MCStreamer &Out);

protected:
  void EmitLabel(MCStreamer &Out, MCSymbol *Label) { Out.EmitLabel(Label); }

  void EmitLEA(X86Operand &Op, unsigned Size, unsigned Reg, MCStreamer &Out) {
    assert(Size == 32 || Size == 64);
    MCInst Inst;
    Inst.setOpcode(Size == 32 ? X86::LEA32r : X86::LEA64r);
    Inst.addOperand(MCOperand::createReg(getX86SubSuperRegister(Reg, Size)));
    Op.addMemOperands(Inst, 5);
    EmitInstruction(Out, Inst);
  }

  void ComputeMemOperandAddress(X86Operand &Op, unsigned Size,
                                unsigned Reg, MCContext &Ctx, MCStreamer &Out);

  // Creates new memory operand with Displacement added to an original
  // displacement. Residue will contain a residue which could happen when the
  // total displacement exceeds 32-bit limitation.
  std::unique_ptr<X86Operand> AddDisplacement(X86Operand &Op,
                                              int64_t Displacement,
                                              MCContext &Ctx, int64_t *Residue);

  bool is64BitMode() const {
    return STI->getFeatureBits()[X86::Mode64Bit];
  }
  bool is32BitMode() const {
    return STI->getFeatureBits()[X86::Mode32Bit];
  }
  bool is16BitMode() const {
    return STI->getFeatureBits()[X86::Mode16Bit];
  }

  unsigned getPointerWidth() {
    if (is16BitMode()) return 16;
    if (is32BitMode()) return 32;
    if (is64BitMode()) return 64;
    llvm_unreachable("invalid mode");
  }

  // True when previous instruction was actually REP prefix.
  bool RepPrefix;

  // Offset from the original SP register.
  int64_t OrigSPOffset;
};

void X86AddressSanitizer::InstrumentMemOperand(
    X86Operand &Op, unsigned AccessSize, bool IsWrite,
    const RegisterContext &RegCtx, MCContext &Ctx, MCStreamer &Out) {
  assert(Op.isMem() && "Op should be a memory operand.");
  assert((AccessSize & (AccessSize - 1)) == 0 && AccessSize <= 16 &&
         "AccessSize should be a power of two, less or equal than 16.");
  // FIXME: take into account load/store alignment.
  if (IsSmallMemAccess(AccessSize))
    InstrumentMemOperandSmall(Op, AccessSize, IsWrite, RegCtx, Ctx, Out);
  else
    InstrumentMemOperandLarge(Op, AccessSize, IsWrite, RegCtx, Ctx, Out);
}

void X86AddressSanitizer::InstrumentMOVSBase(unsigned DstReg, unsigned SrcReg,
                                             unsigned CntReg,
                                             unsigned AccessSize,
                                             MCContext &Ctx, MCStreamer &Out) {
  // FIXME: check whole ranges [DstReg .. DstReg + AccessSize * (CntReg - 1)]
  // and [SrcReg .. SrcReg + AccessSize * (CntReg - 1)].
  RegisterContext RegCtx(X86::RDX /* AddressReg */, X86::RAX /* ShadowReg */,
                         IsSmallMemAccess(AccessSize)
                             ? X86::RBX
                             : X86::NoRegister /* ScratchReg */);
  RegCtx.AddBusyReg(DstReg);
  RegCtx.AddBusyReg(SrcReg);
  RegCtx.AddBusyReg(CntReg);

  InstrumentMemOperandPrologue(RegCtx, Ctx, Out);

  // Test (%SrcReg)
  {
    const MCExpr *Disp = MCConstantExpr::create(0, Ctx);
    std::unique_ptr<X86Operand> Op(X86Operand::CreateMem(
        getPointerWidth(), 0, Disp, SrcReg, 0, AccessSize, SMLoc(), SMLoc()));
    InstrumentMemOperand(*Op, AccessSize, false /* IsWrite */, RegCtx, Ctx,
                         Out);
  }

  // Test -1(%SrcReg, %CntReg, AccessSize)
  {
    const MCExpr *Disp = MCConstantExpr::create(-1, Ctx);
    std::unique_ptr<X86Operand> Op(X86Operand::CreateMem(
        getPointerWidth(), 0, Disp, SrcReg, CntReg, AccessSize, SMLoc(),
        SMLoc()));
    InstrumentMemOperand(*Op, AccessSize, false /* IsWrite */, RegCtx, Ctx,
                         Out);
  }

  // Test (%DstReg)
  {
    const MCExpr *Disp = MCConstantExpr::create(0, Ctx);
    std::unique_ptr<X86Operand> Op(X86Operand::CreateMem(
        getPointerWidth(), 0, Disp, DstReg, 0, AccessSize, SMLoc(), SMLoc()));
    InstrumentMemOperand(*Op, AccessSize, true /* IsWrite */, RegCtx, Ctx, Out);
  }

  // Test -1(%DstReg, %CntReg, AccessSize)
  {
    const MCExpr *Disp = MCConstantExpr::create(-1, Ctx);
    std::unique_ptr<X86Operand> Op(X86Operand::CreateMem(
        getPointerWidth(), 0, Disp, DstReg, CntReg, AccessSize, SMLoc(),
        SMLoc()));
    InstrumentMemOperand(*Op, AccessSize, true /* IsWrite */, RegCtx, Ctx, Out);
  }

  InstrumentMemOperandEpilogue(RegCtx, Ctx, Out);
}

void X86AddressSanitizer::InstrumentMOVS(const MCInst &Inst,
                                         OperandVector &Operands,
                                         MCContext &Ctx, const MCInstrInfo &MII,
                                         MCStreamer &Out) {
  // Access size in bytes.
  unsigned AccessSize = 0;

  switch (Inst.getOpcode()) {
  case X86::MOVSB:
    AccessSize = 1;
    break;
  case X86::MOVSW:
    AccessSize = 2;
    break;
  case X86::MOVSL:
    AccessSize = 4;
    break;
  case X86::MOVSQ:
    AccessSize = 8;
    break;
  default:
    return;
  }

  InstrumentMOVSImpl(AccessSize, Ctx, Out);
}

void X86AddressSanitizer::InstrumentMOV(const MCInst &Inst,
                                        OperandVector &Operands, MCContext &Ctx,
                                        const MCInstrInfo &MII,
                                        MCStreamer &Out) {
  // Access size in bytes.
  unsigned AccessSize = 0;

  switch (Inst.getOpcode()) {
  case X86::MOV8mi:
  case X86::MOV8mr:
  case X86::MOV8rm:
    AccessSize = 1;
    break;
  case X86::MOV16mi:
  case X86::MOV16mr:
  case X86::MOV16rm:
    AccessSize = 2;
    break;
  case X86::MOV32mi:
  case X86::MOV32mr:
  case X86::MOV32rm:
    AccessSize = 4;
    break;
  case X86::MOV64mi32:
  case X86::MOV64mr:
  case X86::MOV64rm:
    AccessSize = 8;
    break;
  case X86::MOVAPDmr:
  case X86::MOVAPSmr:
  case X86::MOVAPDrm:
  case X86::MOVAPSrm:
    AccessSize = 16;
    break;
  default:
    return;
  }

  const bool IsWrite = MII.get(Inst.getOpcode()).mayStore();

  for (unsigned Ix = 0; Ix < Operands.size(); ++Ix) {
    assert(Operands[Ix]);
    MCParsedAsmOperand &Op = *Operands[Ix];
    if (Op.isMem()) {
      X86Operand &MemOp = static_cast<X86Operand &>(Op);
      RegisterContext RegCtx(
          X86::RDI /* AddressReg */, X86::RAX /* ShadowReg */,
          IsSmallMemAccess(AccessSize) ? X86::RCX
                                       : X86::NoRegister /* ScratchReg */);
      RegCtx.AddBusyRegs(MemOp);
      InstrumentMemOperandPrologue(RegCtx, Ctx, Out);
      InstrumentMemOperand(MemOp, AccessSize, IsWrite, RegCtx, Ctx, Out);
      InstrumentMemOperandEpilogue(RegCtx, Ctx, Out);
    }
  }
}

void X86AddressSanitizer::ComputeMemOperandAddress(X86Operand &Op,
                                                   unsigned Size,
                                                   unsigned Reg, MCContext &Ctx,
                                                   MCStreamer &Out) {
  int64_t Displacement = 0;
  if (IsStackReg(Op.getMemBaseReg()))
    Displacement -= OrigSPOffset;
  if (IsStackReg(Op.getMemIndexReg()))
    Displacement -= OrigSPOffset * Op.getMemScale();

  assert(Displacement >= 0);

  // Emit Op as is.
  if (Displacement == 0) {
    EmitLEA(Op, Size, Reg, Out);
    return;
  }

  int64_t Residue;
  std::unique_ptr<X86Operand> NewOp =
      AddDisplacement(Op, Displacement, Ctx, &Residue);
  EmitLEA(*NewOp, Size, Reg, Out);

  while (Residue != 0) {
    const MCConstantExpr *Disp =
        MCConstantExpr::create(ApplyDisplacementBounds(Residue), Ctx);
    std::unique_ptr<X86Operand> DispOp =
        X86Operand::CreateMem(getPointerWidth(), 0, Disp, Reg, 0, 1, SMLoc(),
                              SMLoc());
    EmitLEA(*DispOp, Size, Reg, Out);
    Residue -= Disp->getValue();
  }
}

std::unique_ptr<X86Operand>
X86AddressSanitizer::AddDisplacement(X86Operand &Op, int64_t Displacement,
                                     MCContext &Ctx, int64_t *Residue) {
  assert(Displacement >= 0);

  if (Displacement == 0 ||
      (Op.getMemDisp() && Op.getMemDisp()->getKind() != MCExpr::Constant)) {
    *Residue = Displacement;
    return X86Operand::CreateMem(Op.getMemModeSize(), Op.getMemSegReg(),
                                 Op.getMemDisp(), Op.getMemBaseReg(),
                                 Op.getMemIndexReg(), Op.getMemScale(),
                                 SMLoc(), SMLoc());
  }

  int64_t OrigDisplacement =
      static_cast<const MCConstantExpr *>(Op.getMemDisp())->getValue();
  CheckDisplacementBounds(OrigDisplacement);
  Displacement += OrigDisplacement;

  int64_t NewDisplacement = ApplyDisplacementBounds(Displacement);
  CheckDisplacementBounds(NewDisplacement);

  *Residue = Displacement - NewDisplacement;
  const MCExpr *Disp = MCConstantExpr::create(NewDisplacement, Ctx);
  return X86Operand::CreateMem(Op.getMemModeSize(), Op.getMemSegReg(), Disp,
                               Op.getMemBaseReg(), Op.getMemIndexReg(),
                               Op.getMemScale(), SMLoc(), SMLoc());
}

} // End anonymous namespace

X86AsmInstrumentation::X86AsmInstrumentation(const MCSubtargetInfo *&STI)
    : STI(STI), InitialFrameReg(0) {}

X86AsmInstrumentation::~X86AsmInstrumentation() {}

void X86AsmInstrumentation::InstrumentAndEmitInstruction(
    MCInst &Inst, OperandVector &Operands, MCContext &Ctx,
    const MCInstrInfo &MII, MCStreamer &Out) {
  EmitInstruction(Out, Inst);
}

void X86AsmInstrumentation::EmitInstruction(MCStreamer &Out,
                                            MCInst &Inst) {
  Out.EmitInstruction(Inst, *STI);
}

unsigned X86AsmInstrumentation::GetFrameRegGeneric(const MCContext &Ctx,
                                                   MCStreamer &Out) {
  if (!Out.getNumFrameInfos()) // No active dwarf frame
    return X86::NoRegister;
  const MCDwarfFrameInfo &Frame = Out.getDwarfFrameInfos().back();
  if (Frame.End) // Active dwarf frame is closed
    return X86::NoRegister;
  const MCRegisterInfo *MRI = Ctx.getRegisterInfo();
  if (!MRI) // No register info
    return X86::NoRegister;

  if (InitialFrameReg) {
    // FrameReg is set explicitly, we're instrumenting a MachineFunction.
    return InitialFrameReg;
  }

  return MRI->getLLVMRegNum(Frame.CurrentCfaRegister, true /* IsEH */);
}

X86AsmInstrumentation *
CreateX86AsmInstrumentation(const MCTargetOptions &MCOptions,
                            const MCContext &Ctx, const MCSubtargetInfo *&STI) {
  return new X86AsmInstrumentation(STI);
}

} // end llvm namespace
