//===-- HexagonMCCodeEmitter.h - Hexagon Target Descriptions ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// \brief Definition for classes that emit Hexagon machine code from MCInsts
///
//===----------------------------------------------------------------------===//

#ifndef HEXAGONMCCODEEMITTER_H
#define HEXAGONMCCODEEMITTER_H

#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/raw_ostream.h"

namespace llvm_ks {

class HexagonMCCodeEmitter : public MCCodeEmitter {
  MCContext &MCT;
  MCInstrInfo const &MCII;
  std::unique_ptr<unsigned> Addend;
  std::unique_ptr<bool> Extended;
  std::unique_ptr<MCInst const *> CurrentBundle;
  mutable unsigned KsError;

  // helper routine for getMachineOpValue()
  unsigned getExprOpValue(const MCInst &MI, const MCOperand &MO,
                          const MCExpr *ME, SmallVectorImpl<MCFixup> &Fixups,
                          const MCSubtargetInfo &STI) const;

public:
  HexagonMCCodeEmitter(MCInstrInfo const &aMII, MCContext &aMCT);

  void setError(unsigned E) const { KsError = E; }
  unsigned getError() const { return KsError; }

  // Return parse bits for instruction `MCI' inside bundle `MCB'
  uint32_t parseBits(size_t Instruction, size_t Last, MCInst const &MCB,
                    MCInst const &MCI) const;

  void encodeInstruction(MCInst &MI, raw_ostream &OS,
                         SmallVectorImpl<MCFixup> &Fixups,
                         MCSubtargetInfo const &STI,
                         unsigned int &KsError) const override;

  void EncodeSingleInstruction(const MCInst &MI, raw_ostream &OS,
                               SmallVectorImpl<MCFixup> &Fixups,
                               const MCSubtargetInfo &STI,
                               uint32_t Parse, size_t Index) const;

  // \brief TableGen'erated function for getting the
  // binary encoding for an instruction.
  uint64_t getBinaryCodeForInstr(MCInst const &MI,
                                 SmallVectorImpl<MCFixup> &Fixups,
                                 MCSubtargetInfo const &STI) const;

  /// \brief Return binary encoding of operand.
  unsigned getMachineOpValue(MCInst const &MI, MCOperand const &MO,
                             SmallVectorImpl<MCFixup> &Fixups,
                             MCSubtargetInfo const &STI) const;
}; // class HexagonMCCodeEmitter

} // namespace llvm_ks

#endif /* HEXAGONMCCODEEMITTER_H */
