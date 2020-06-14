//===-- MCAsmParser.cpp - Abstract Asm Parser Interface -------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/ADT/Twine.h"
#include "llvm/MC/MCParser/MCAsmLexer.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm_ks;

MCAsmParser::MCAsmParser() : TargetParser(nullptr), KsError(0) {
}

MCAsmParser::~MCAsmParser() {
}

void MCAsmParser::setTargetParser(MCTargetAsmParser &P) {
  assert(!TargetParser && "Target parser is already initialized!");
  TargetParser = &P;
  TargetParser->Initialize(*this);
}

const AsmToken &MCAsmParser::getTok() const {
  return getLexer().getTok();
}

bool MCAsmParser::TokError(const Twine &Msg, ArrayRef<SMRange> Ranges) {
  Error(getLexer().getLoc(), Msg, Ranges);
  return true;
}

bool MCAsmParser::parseExpression(const MCExpr *&Res) {
  SMLoc L;
  return parseExpression(Res, L);
}

bool MCAsmParser::parseEOL(const Twine &Msg) {
  if (getTok().getKind() != AsmToken::EndOfStatement)
    return Error(getTok().getLoc(), Msg);
  Lex();
  return false;
}

bool MCAsmParser::parseToken(AsmToken::TokenKind T, const Twine &Msg = "unexpected token") {
  if (T == AsmToken::EndOfStatement)
    return parseEOL(Msg);
  if (getTok().getKind() != T)
    return Error(getTok().getLoc(), Msg);
  Lex();
  return false;
}

bool MCAsmParser::parseOptionalToken(AsmToken::TokenKind T) {
  bool Present = (getTok().getKind() == T);
  if (Present)
    parseToken(T);
  return Present;
}

bool MCAsmParser::parseMany(function_ref<bool()> parseOne, bool hasComma) {
  if (parseOptionalToken(AsmToken::EndOfStatement))
    return false;
  while (true) {
    if (parseOne())
      return true;
    if (parseOptionalToken(AsmToken::EndOfStatement))
      return false;
    if (hasComma && parseToken(AsmToken::Comma))
      return true;
  }
  return false;
}

LLVM_DUMP_METHOD void MCParsedAsmOperand::dump() const {
}
