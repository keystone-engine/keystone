//===-- llvm/MC/MCTargetAsmParser.h - Target Assembly Parser ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCPARSER_MCTARGETASMPARSER_H
#define LLVM_MC_MCPARSER_MCTARGETASMPARSER_H

#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCParser/MCAsmParserExtension.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/SubtargetFeature.h"
#include <memory>

namespace llvm_ks {
class AsmToken;
class MCInst;
class MCParsedAsmOperand;
class MCStreamer;
class MCSubtargetInfo;
class SMLoc;
class StringRef;
template <typename T> class SmallVectorImpl;

typedef SmallVectorImpl<std::unique_ptr<MCParsedAsmOperand>> OperandVector;

enum AsmRewriteKind {
  AOK_Delete = 0,     // Rewrite should be ignored.
  AOK_Align,          // Rewrite align as .align.
  AOK_EVEN,           // Rewrite even as .even.
  AOK_DotOperator,    // Rewrite a dot operator expression as an immediate.
                      // E.g., [eax].foo.bar -> [eax].8
  AOK_Emit,           // Rewrite _emit as .byte.
  AOK_Imm,            // Rewrite as $$N.
  AOK_ImmPrefix,      // Add $$ before a parsed Imm.
  AOK_Input,          // Rewrite in terms of $N.
  AOK_Output,         // Rewrite in terms of $N.
  AOK_SizeDirective,  // Add a sizing directive (e.g., dword ptr).
  AOK_Label,          // Rewrite local labels.
  AOK_Skip            // Skip emission (e.g., offset/type operators).
};

const char AsmRewritePrecedence [] = {
  0, // AOK_Delete
  2, // AOK_Align
  2, // AOK_EVEN
  2, // AOK_DotOperator
  2, // AOK_Emit
  4, // AOK_Imm
  4, // AOK_ImmPrefix
  3, // AOK_Input
  3, // AOK_Output
  5, // AOK_SizeDirective
  1, // AOK_Label
  2  // AOK_Skip
};

struct AsmRewrite {
  AsmRewriteKind Kind;
  SMLoc Loc;
  unsigned Len;
  unsigned Val;
  StringRef Label;
public:
  AsmRewrite(AsmRewriteKind kind, SMLoc loc, unsigned len = 0, unsigned val = 0)
    : Kind(kind), Loc(loc), Len(len), Val(val) {}
  AsmRewrite(AsmRewriteKind kind, SMLoc loc, unsigned len, StringRef label)
    : Kind(kind), Loc(loc), Len(len), Val(0), Label(label) {}
};

struct ParseInstructionInfo {

  SmallVectorImpl<AsmRewrite> *AsmRewrites;

  ParseInstructionInfo() : AsmRewrites(nullptr) {}
  ParseInstructionInfo(SmallVectorImpl<AsmRewrite> *rewrites)
    : AsmRewrites(rewrites) {}
};

/// MCTargetAsmParser - Generic interface to target specific assembly parsers.
class MCTargetAsmParser : public MCAsmParserExtension {
public:
  enum MatchResultTy {
    Match_Success = 1,
    Match_InvalidOperand = 512, // KS_ERR_ASM_ARCH
    Match_MissingFeature,
    Match_MnemonicFail,
    FIRST_TARGET_MATCH_RESULT_TY
  };

private:
  MCTargetAsmParser(const MCTargetAsmParser &) = delete;
  void operator=(const MCTargetAsmParser &) = delete;
protected: // Can only create subclasses.
  MCTargetAsmParser(MCTargetOptions const &, const MCSubtargetInfo &STI);

  /// Create a copy of STI and return a non-const reference to it.
  MCSubtargetInfo &copySTI();

  /// AvailableFeatures - The current set of available features.
  uint64_t AvailableFeatures;
  FeatureBitset AvailableFeaturesFB;

  /// ParsingInlineAsm - Are we parsing ms-style inline assembly?
  bool ParsingInlineAsm;

  /// SemaCallback - The Sema callback implementation.  Must be set when parsing
  /// ms-style inline assembly.
  MCAsmParserSemaCallback *SemaCallback;

  /// Set of options which affects instrumentation of inline assembly.
  MCTargetOptions MCOptions;

  /// Current STI.
  const MCSubtargetInfo *STI;

public:
  // save Keystone syntax
  int KsSyntax;

  ~MCTargetAsmParser() override;

  const MCSubtargetInfo &getSTI() const;

  uint64_t getAvailableFeatures() const { return AvailableFeatures; }
  FeatureBitset getAvailableFeaturesFB() const { return AvailableFeaturesFB; }
  void setAvailableFeatures(uint64_t Value) { AvailableFeatures = Value; }
  void setAvailableFeaturesFB(FeatureBitset Value) { AvailableFeaturesFB = Value; }

  bool isParsingInlineAsm () { return ParsingInlineAsm; }
  void setParsingInlineAsm (bool Value) { ParsingInlineAsm = Value; }

  MCTargetOptions getTargetOptions() const { return MCOptions; }

  void setSemaCallback(MCAsmParserSemaCallback *Callback) {
    SemaCallback = Callback;
  }

  virtual bool ParseRegister(unsigned &RegNo, SMLoc &StartLoc,
                             SMLoc &EndLoc, unsigned int &ErrorCode) = 0;

  /// Sets frame register corresponding to the current MachineFunction.
  virtual void SetFrameRegister(unsigned RegNo) {}

  /// ParseInstruction - Parse one assembly instruction.
  ///
  /// The parser is positioned following the instruction name. The target
  /// specific instruction parser should parse the entire instruction and
  /// construct the appropriate MCInst, or emit an error. On success, the entire
  /// line should be parsed up to and including the end-of-statement token. On
  /// failure, the parser is not required to read to the end of the line.
  //
  /// \param Name - The instruction name.
  /// \param NameLoc - The source location of the name.
  /// \param Operands [out] - The list of parsed operands, this returns
  ///        ownership of them to the caller.
  /// \return True on failure.
  virtual bool ParseInstruction(ParseInstructionInfo &Info, StringRef Name,
                                SMLoc NameLoc, OperandVector &Operands, unsigned int &ErrorCode) = 0;
  virtual bool ParseInstruction(ParseInstructionInfo &Info, StringRef Name,
                                AsmToken Token, OperandVector &Operands, unsigned int &ErrorCode) {
    return ParseInstruction(Info, Name, Token.getLoc(), Operands, ErrorCode);
  }

  /// ParseDirective - Parse a target specific assembler directive
  ///
  /// The parser is positioned following the directive name.  The target
  /// specific directive parser should parse the entire directive doing or
  /// recording any target specific work, or return true and do nothing if the
  /// directive is not target specific. If the directive is specific for
  /// the target, the entire line is parsed up to and including the
  /// end-of-statement token and false is returned.
  ///
  /// \param DirectiveID - the identifier token of the directive.
  virtual bool ParseDirective(AsmToken DirectiveID) = 0;

  /// MatchAndEmitInstruction - Recognize a series of operands of a parsed
  /// instruction as an actual MCInst and emit it to the specified MCStreamer.
  /// This returns false on success and returns true on failure to match.
  ///
  /// On failure, the target parser is responsible for emitting a diagnostic
  /// explaining the match failure.
  virtual bool MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                                       OperandVector &Operands, MCStreamer &Out,
                                       uint64_t &ErrorInfo,
                                       bool MatchingInlineAsm, unsigned int &ErrorCode, uint64_t &Address) = 0;

  /// Allows targets to let registers opt out of clobber lists.
  virtual bool OmitRegisterFromClobberLists(unsigned RegNo) { return false; }

  /// Allow a target to add special case operand matching for things that
  /// tblgen doesn't/can't handle effectively. For example, literal
  /// immediates on ARM. TableGen expects a token operand, but the parser
  /// will recognize them as immediates.
  virtual unsigned validateTargetOperandClass(MCParsedAsmOperand &Op,
                                              unsigned Kind) {
    return Match_InvalidOperand;
  }

  /// checkTargetMatchPredicate - Validate the instruction match against
  /// any complex target predicates not expressible via match classes.
  virtual unsigned checkTargetMatchPredicate(MCInst &Inst) {
    return Match_Success;
  }

  virtual void convertToMapAndConstraints(unsigned Kind,
                                          const OperandVector &Operands) = 0;

  // Return whether this parser uses assignment statements with equals tokens
  virtual bool equalIsAsmAssignment() { return true; };
  // Return whether this start of statement identifier is a label
  virtual bool isLabel(AsmToken &Token, bool &valid) { valid = true; return true; };

  virtual const MCExpr *applyModifierToExpr(const MCExpr *E,
                                            MCSymbolRefExpr::VariantKind,
                                            MCContext &Ctx) {
    return nullptr;
  }

  virtual void onLabelParsed(MCSymbol *Symbol) { }
};

enum OperandMatchResultTy {
  MatchOperand_Success,  // operand matched successfully
  MatchOperand_NoMatch,  // operand did not match
  MatchOperand_ParseFail // operand matched but had errors
};

enum class DiagnosticPredicateTy {
  Match,
  NearMatch,
  NoMatch,
};

// When an operand is parsed, the assembler will try to iterate through a set of
// possible operand classes that the operand might match and call the
// corresponding PredicateMethod to determine that.
//
// If there are two AsmOperands that would give a specific diagnostic if there
// is no match, there is currently no mechanism to distinguish which operand is
// a closer match. The DiagnosticPredicate distinguishes between 'completely
// no match' and 'near match', so the assembler can decide whether to give a
// specific diagnostic, or use 'InvalidOperand' and continue to find a
// 'better matching' diagnostic.
//
// For example:
//    opcode opnd0, onpd1, opnd2
//
// where:
//    opnd2 could be an 'immediate of range [-8, 7]'
//    opnd2 could be a  'register + shift/extend'.
//
// If opnd2 is a valid register, but with a wrong shift/extend suffix, it makes
// little sense to give a diagnostic that the operand should be an immediate
// in range [-8, 7].
//
// This is a light-weight alternative to the 'NearMissInfo' approach
// below which collects *all* possible diagnostics. This alternative
// is optional and fully backward compatible with existing
// PredicateMethods that return a 'bool' (match or no match).
struct DiagnosticPredicate {
  DiagnosticPredicateTy Type;

  explicit DiagnosticPredicate(bool Match)
      : Type(Match ? DiagnosticPredicateTy::Match
                   : DiagnosticPredicateTy::NearMatch) {}
  DiagnosticPredicate(DiagnosticPredicateTy T) : Type(T) {}
  DiagnosticPredicate(const DiagnosticPredicate &) = default;

  operator bool() const { return Type == DiagnosticPredicateTy::Match; }
  bool isMatch() const { return Type == DiagnosticPredicateTy::Match; }
  bool isNearMatch() const { return Type == DiagnosticPredicateTy::NearMatch; }
  bool isNoMatch() const { return Type == DiagnosticPredicateTy::NoMatch; }
};
} // End llvm namespace

#endif
