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

namespace llvm_ks {

X86AsmInstrumentation::X86AsmInstrumentation(const MCSubtargetInfo *&STI)
    : STI(STI), InitialFrameReg(0) {}

X86AsmInstrumentation::~X86AsmInstrumentation() {}

void X86AsmInstrumentation::InstrumentAndEmitInstruction(
    MCInst &Inst, OperandVector &Operands, MCContext &Ctx,
    const MCInstrInfo &MII, MCStreamer &Out, unsigned int &KsError) {
  EmitInstruction(Out, Inst, KsError);
}

void X86AsmInstrumentation::EmitInstruction(MCStreamer &Out,
                                            MCInst &Inst,
                                            unsigned int &KsError) {
  Out.EmitInstruction(Inst, *STI, KsError);
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
