/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_ASSEMBLER_HEADER
#undef GET_ASSEMBLER_HEADER
  // This should be included into the middle of the declaration of
  // your subclasses implementation of MCTargetAsmParser.
  uint64_t ComputeAvailableFeatures(const FeatureBitset& FB) const;
  void convertToMCInst(unsigned Kind, MCInst &Inst, unsigned Opcode,
                       const OperandVector &Operands);
  void convertToMapAndConstraints(unsigned Kind,
                           const OperandVector &Operands) override;
  bool mnemonicIsValid(StringRef Mnemonic, unsigned VariantID);
  unsigned MatchInstructionImpl(const OperandVector &Operands,
                                MCInst &Inst,
                                uint64_t &ErrorInfo, bool matchingInlineAsm,
                                unsigned VariantID = 0);
#endif // GET_ASSEMBLER_HEADER_INFO


#ifdef GET_OPERAND_DIAGNOSTIC_TYPES
#undef GET_OPERAND_DIAGNOSTIC_TYPES

#endif // GET_OPERAND_DIAGNOSTIC_TYPES


#ifdef GET_REGISTER_MATCHER
#undef GET_REGISTER_MATCHER

// Flags for subtarget features that participate in instruction matching.
enum SubtargetFeatureFlag : uint8_t {
  Feature_None = 0
};

static unsigned MatchRegisterName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 10 strings to match.
    if (Name[0] != 'r')
      break;
    switch (Name[1]) {
    default: break;
    case '0':	 // 1 string to match.
      return 5;	 // "r0"
    case '1':	 // 1 string to match.
      return 7;	 // "r1"
    case '2':	 // 1 string to match.
      return 9;	 // "r2"
    case '3':	 // 1 string to match.
      return 1;	 // "r3"
    case '4':	 // 1 string to match.
      return 3;	 // "r4"
    case '5':	 // 1 string to match.
      return 11;	 // "r5"
    case '6':	 // 1 string to match.
      return 12;	 // "r6"
    case '7':	 // 1 string to match.
      return 13;	 // "r7"
    case '8':	 // 1 string to match.
      return 14;	 // "r8"
    case '9':	 // 1 string to match.
      return 15;	 // "r9"
    }
    break;
  case 3:	 // 16 strings to match.
    if (Name[0] != 'r')
      break;
    switch (Name[1]) {
    default: break;
    case '0':	 // 1 string to match.
      if (Name[2] != 'b')
        break;
      return 6;	 // "r0b"
    case '1':	 // 7 strings to match.
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        return 16;	 // "r10"
      case '1':	 // 1 string to match.
        return 17;	 // "r11"
      case '2':	 // 1 string to match.
        return 18;	 // "r12"
      case '3':	 // 1 string to match.
        return 19;	 // "r13"
      case '4':	 // 1 string to match.
        return 20;	 // "r14"
      case '5':	 // 1 string to match.
        return 21;	 // "r15"
      case 'b':	 // 1 string to match.
        return 8;	 // "r1b"
      }
      break;
    case '2':	 // 1 string to match.
      if (Name[2] != 'b')
        break;
      return 10;	 // "r2b"
    case '3':	 // 1 string to match.
      if (Name[2] != 'b')
        break;
      return 2;	 // "r3b"
    case '4':	 // 1 string to match.
      if (Name[2] != 'b')
        break;
      return 4;	 // "r4b"
    case '5':	 // 1 string to match.
      if (Name[2] != 'b')
        break;
      return 22;	 // "r5b"
    case '6':	 // 1 string to match.
      if (Name[2] != 'b')
        break;
      return 23;	 // "r6b"
    case '7':	 // 1 string to match.
      if (Name[2] != 'b')
        break;
      return 24;	 // "r7b"
    case '8':	 // 1 string to match.
      if (Name[2] != 'b')
        break;
      return 25;	 // "r8b"
    case '9':	 // 1 string to match.
      if (Name[2] != 'b')
        break;
      return 26;	 // "r9b"
    }
    break;
  case 4:	 // 6 strings to match.
    if (memcmp(Name.data()+0, "r1", 2))
      break;
    switch (Name[2]) {
    default: break;
    case '0':	 // 1 string to match.
      if (Name[3] != 'b')
        break;
      return 27;	 // "r10b"
    case '1':	 // 1 string to match.
      if (Name[3] != 'b')
        break;
      return 28;	 // "r11b"
    case '2':	 // 1 string to match.
      if (Name[3] != 'b')
        break;
      return 29;	 // "r12b"
    case '3':	 // 1 string to match.
      if (Name[3] != 'b')
        break;
      return 30;	 // "r13b"
    case '4':	 // 1 string to match.
      if (Name[3] != 'b')
        break;
      return 31;	 // "r14b"
    case '5':	 // 1 string to match.
      if (Name[3] != 'b')
        break;
      return 32;	 // "r15b"
    }
    break;
  }
  return 0;
}

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  return "(unknown)";
}

#endif // GET_SUBTARGET_FEATURE_NAME


#ifdef GET_MATCHER_IMPLEMENTATION
#undef GET_MATCHER_IMPLEMENTATION

namespace {
enum OperatorConversionKind {
  CVT_Done,
  CVT_Reg,
  CVT_Tied,
  CVT_95_Reg,
  CVT_imm_95_0,
  CVT_95_addMemOperands,
  CVT_95_addImmOperands,
  CVT_95_addRegOperands,
  CVT_regSR,
  CVT_imm_95_1,
  CVT_imm_95_4,
  CVT_imm_95_2,
  CVT_imm_95_8,
  CVT_imm_95__MINUS_1,
  CVT_regCG,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Reg1_0__Tie0__imm_95_0,
  Convert__Mem2_0__imm_95_0,
  Convert__Reg1_1__Tie0__Reg1_0,
  Convert__Mem2_1__Reg1_0,
  Convert__Reg1_1__Tie0__CGImm1_0,
  Convert__Mem2_1__CGImm1_0,
  Convert__Reg1_1__Tie0__Imm1_0,
  Convert__Mem2_1__Imm1_0,
  Convert__Reg1_1__Tie0__IndReg1_0,
  Convert__Mem2_1__IndReg1_0,
  Convert__Reg1_1__Tie0__Mem2_0,
  Convert__Mem2_1__Mem2_0,
  Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1,
  Convert__Mem2_1__PostIndReg1_0,
  Convert__Reg1_1__Reg1_0,
  Convert__Reg1_1__CGImm1_0,
  Convert__Reg1_1__Imm1_0,
  Convert__Reg1_1__Mem2_0,
  Convert__Reg1_0,
  Convert__Imm1_0,
  Convert__Mem2_0,
  Convert__Reg1_0__imm_95_0,
  Convert__regSR__Tie0__imm_95_1,
  Convert__regSR__Tie0__imm_95_4,
  Convert__regSR__Tie0__imm_95_2,
  Convert__Reg1_0__Tie0__imm_95_1,
  Convert__Mem2_0__imm_95_1,
  Convert__Reg1_0__Tie0__imm_95_2,
  Convert__Mem2_0__imm_95_2,
  Convert__regSR__Tie0__imm_95_8,
  Convert__Reg1_0__Tie0__imm_95__MINUS_1,
  Convert__Mem2_0__imm_95__MINUS_1,
  Convert__Imm1_1__Imm1_0,
  Convert__Reg1_1__IndReg1_0,
  Convert__Reg1_1__PostIndReg1_0__Tie1,
  Convert__regCG__imm_95_0,
  Convert__CGImm1_0,
  Convert_NoOperands,
  Convert__Reg1_0__Tie0__Reg1_0,
  Convert__Mem2_0__Mem2_0,
  Convert__Reg1_0__Tie0,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][9] = {
  // Convert__Reg1_0__Tie0__imm_95_0
  { CVT_95_Reg, 1, CVT_Tied, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Mem2_0__imm_95_0
  { CVT_95_addMemOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_1__Tie0__Reg1_0
  { CVT_95_Reg, 2, CVT_Tied, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Mem2_1__Reg1_0
  { CVT_95_addMemOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__Tie0__CGImm1_0
  { CVT_95_Reg, 2, CVT_Tied, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Mem2_1__CGImm1_0
  { CVT_95_addMemOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Tie0__Imm1_0
  { CVT_95_Reg, 2, CVT_Tied, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Mem2_1__Imm1_0
  { CVT_95_addMemOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Tie0__IndReg1_0
  { CVT_95_Reg, 2, CVT_Tied, 0, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Mem2_1__IndReg1_0
  { CVT_95_addMemOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_1__Tie0__Mem2_0
  { CVT_95_Reg, 2, CVT_Tied, 0, CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__Mem2_1__Mem2_0
  { CVT_95_addMemOperands, 2, CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1
  { CVT_95_Reg, 2, CVT_95_addRegOperands, 1, CVT_Tied, 0, CVT_Tied, 1, CVT_Done },
  // Convert__Mem2_1__PostIndReg1_0
  { CVT_95_addMemOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__CGImm1_0
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Imm1_0
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Mem2_0
  { CVT_95_Reg, 2, CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Mem2_0
  { CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__Reg1_0__imm_95_0
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__regSR__Tie0__imm_95_1
  { CVT_regSR, 0, CVT_Tied, 0, CVT_imm_95_1, 0, CVT_Done },
  // Convert__regSR__Tie0__imm_95_4
  { CVT_regSR, 0, CVT_Tied, 0, CVT_imm_95_4, 0, CVT_Done },
  // Convert__regSR__Tie0__imm_95_2
  { CVT_regSR, 0, CVT_Tied, 0, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_0__Tie0__imm_95_1
  { CVT_95_Reg, 1, CVT_Tied, 0, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Mem2_0__imm_95_1
  { CVT_95_addMemOperands, 1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_0__Tie0__imm_95_2
  { CVT_95_Reg, 1, CVT_Tied, 0, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Mem2_0__imm_95_2
  { CVT_95_addMemOperands, 1, CVT_imm_95_2, 0, CVT_Done },
  // Convert__regSR__Tie0__imm_95_8
  { CVT_regSR, 0, CVT_Tied, 0, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_0__Tie0__imm_95__MINUS_1
  { CVT_95_Reg, 1, CVT_Tied, 0, CVT_imm_95__MINUS_1, 0, CVT_Done },
  // Convert__Mem2_0__imm_95__MINUS_1
  { CVT_95_addMemOperands, 1, CVT_imm_95__MINUS_1, 0, CVT_Done },
  // Convert__Imm1_1__Imm1_0
  { CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__IndReg1_0
  { CVT_95_Reg, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_1__PostIndReg1_0__Tie1
  { CVT_95_Reg, 2, CVT_95_addRegOperands, 1, CVT_Tied, 1, CVT_Done },
  // Convert__regCG__imm_95_0
  { CVT_regCG, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__CGImm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__Reg1_0__Tie0__Reg1_0
  { CVT_95_Reg, 1, CVT_Tied, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Mem2_0__Mem2_0
  { CVT_95_addMemOperands, 1, CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__Reg1_0__Tie0
  { CVT_95_Reg, 1, CVT_Tied, 0, CVT_Done },
};

void MSP430AsmParser::
convertToMCInst(unsigned Kind, MCInst &Inst, unsigned Opcode,
                const OperandVector &Operands) {
  assert(Kind < CVT_NUM_SIGNATURES && "Invalid signature!");
  const uint8_t *Converter = ConversionTable[Kind];
  unsigned OpIdx;
  Inst.setOpcode(Opcode);
  for (const uint8_t *p = Converter; *p; p+= 2) {
    OpIdx = *(p + 1);
    switch (*p) {
    default: llvm_unreachable("invalid conversion entry!");
    case CVT_Reg:
      static_cast<MSP430Operand&>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_Tied:
      Inst.addOperand(Inst.getOperand(OpIdx));
      break;
    case CVT_95_Reg:
      static_cast<MSP430Operand&>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_95_addMemOperands:
      static_cast<MSP430Operand&>(*Operands[OpIdx]).addMemOperands(Inst, 2);
      break;
    case CVT_95_addImmOperands:
      static_cast<MSP430Operand&>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_addRegOperands:
      static_cast<MSP430Operand&>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_regSR:
      Inst.addOperand(MCOperand::createReg(MSP430::SR));
      break;
    case CVT_imm_95_1:
      Inst.addOperand(MCOperand::createImm(1));
      break;
    case CVT_imm_95_4:
      Inst.addOperand(MCOperand::createImm(4));
      break;
    case CVT_imm_95_2:
      Inst.addOperand(MCOperand::createImm(2));
      break;
    case CVT_imm_95_8:
      Inst.addOperand(MCOperand::createImm(8));
      break;
    case CVT_imm_95__MINUS_1:
      Inst.addOperand(MCOperand::createImm(-1));
      break;
    case CVT_regCG:
      Inst.addOperand(MCOperand::createReg(MSP430::CG));
      break;
    }
  }
}

void MSP430AsmParser::
convertToMapAndConstraints(unsigned Kind,
                           const OperandVector &Operands) {
  assert(Kind < CVT_NUM_SIGNATURES && "Invalid signature!");
  unsigned NumMCOperands = 0;
  const uint8_t *Converter = ConversionTable[Kind];
  for (const uint8_t *p = Converter; *p; p+= 2) {
    switch (*p) {
    default: llvm_unreachable("invalid conversion entry!");
    case CVT_Reg:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("r");
      ++NumMCOperands;
      break;
    case CVT_Tied:
      ++NumMCOperands;
      break;
    case CVT_95_Reg:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("r");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addMemOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 2;
      break;
    case CVT_95_addImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_regSR:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_imm_95_1:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_4:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_2:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_8:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95__MINUS_1:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_regCG:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    }
  }
}

namespace {

/// MatchClassKind - The kinds of classes which participate in
/// instruction matching.
enum MatchClassKind {
  InvalidMatchClass = 0,
  OptionalMatchClass = 1,
  MCK_GR16, // register class 'GR16'
  MCK_GR8, // register class 'GR8'
  MCK_CGImm, // user defined class 'CGImmAsmOperand'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_IndReg, // user defined class 'IndRegAsmOperand'
  MCK_Mem, // user defined class 'MemAsmOperand'
  MCK_PostIndReg, // user defined class 'PostIndRegAsmOperand'
  NumMatchClassKinds
};

}

static MatchClassKind matchTokenString(StringRef Name) {
  return InvalidMatchClass;
}

/// isSubclass - Compute whether \p A is a subclass of \p B.
static bool isSubclass(MatchClassKind A, MatchClassKind B) {
  if (A == B)
    return true;

  return false;
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind) {
  MSP430Operand &Operand = (MSP430Operand&)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken())
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  // 'CGImm' class
  case MCK_CGImm:
    if (Operand.isCGImm())
      return MCTargetAsmParser::Match_Success;
    break;
  // 'Imm' class
  case MCK_Imm:
    if (Operand.isImm())
      return MCTargetAsmParser::Match_Success;
    break;
  // 'IndReg' class
  case MCK_IndReg:
    if (Operand.isIndReg())
      return MCTargetAsmParser::Match_Success;
    break;
  // 'Mem' class
  case MCK_Mem:
    if (Operand.isMem())
      return MCTargetAsmParser::Match_Success;
    break;
  // 'PostIndReg' class
  case MCK_PostIndReg:
    if (Operand.isPostIndReg())
      return MCTargetAsmParser::Match_Success;
    break;
  } // end switch (Kind)

  if (Operand.isReg()) {
    MatchClassKind OpKind;
    switch (Operand.getReg()) {
    default: OpKind = InvalidMatchClass; break;
    case MSP430::PCB: OpKind = MCK_GR8; break;
    case MSP430::SPB: OpKind = MCK_GR8; break;
    case MSP430::SRB: OpKind = MCK_GR8; break;
    case MSP430::CGB: OpKind = MCK_GR8; break;
    case MSP430::FPB: OpKind = MCK_GR8; break;
    case MSP430::R5B: OpKind = MCK_GR8; break;
    case MSP430::R6B: OpKind = MCK_GR8; break;
    case MSP430::R7B: OpKind = MCK_GR8; break;
    case MSP430::R8B: OpKind = MCK_GR8; break;
    case MSP430::R9B: OpKind = MCK_GR8; break;
    case MSP430::R10B: OpKind = MCK_GR8; break;
    case MSP430::R11B: OpKind = MCK_GR8; break;
    case MSP430::R12B: OpKind = MCK_GR8; break;
    case MSP430::R13B: OpKind = MCK_GR8; break;
    case MSP430::R14B: OpKind = MCK_GR8; break;
    case MSP430::R15B: OpKind = MCK_GR8; break;
    case MSP430::PC: OpKind = MCK_GR16; break;
    case MSP430::SP: OpKind = MCK_GR16; break;
    case MSP430::SR: OpKind = MCK_GR16; break;
    case MSP430::CG: OpKind = MCK_GR16; break;
    case MSP430::FP: OpKind = MCK_GR16; break;
    case MSP430::R5: OpKind = MCK_GR16; break;
    case MSP430::R6: OpKind = MCK_GR16; break;
    case MSP430::R7: OpKind = MCK_GR16; break;
    case MSP430::R8: OpKind = MCK_GR16; break;
    case MSP430::R9: OpKind = MCK_GR16; break;
    case MSP430::R10: OpKind = MCK_GR16; break;
    case MSP430::R11: OpKind = MCK_GR16; break;
    case MSP430::R12: OpKind = MCK_GR16; break;
    case MSP430::R13: OpKind = MCK_GR16; break;
    case MSP430::R14: OpKind = MCK_GR16; break;
    case MSP430::R15: OpKind = MCK_GR16; break;
    }
    return isSubclass(OpKind, Kind) ? MCTargetAsmParser::Match_Success :
                                      MCTargetAsmParser::Match_InvalidOperand;
  }

  return MCTargetAsmParser::Match_InvalidOperand;
}

uint64_t MSP430AsmParser::
ComputeAvailableFeatures(const FeatureBitset& FB) const {
  uint64_t Features = 0;
  return Features;
}

static const char *const MnemonicTable =
    "\003adc\005adc.b\003add\005add.b\004addc\006addc.b\003and\005and.b\003b"
    "ic\005bic.b\003bis\005bis.b\003bit\005bit.b\002br\004call\003clr\005clr"
    ".b\004clrc\004clrn\004clrz\003cmp\005cmp.b\004dadc\006dadc.b\004dadd\006"
    "dadd.b\003dec\005dec.b\004decd\006decd.b\004dint\004eint\003inc\005inc."
    "b\004incd\006incd.b\003inv\005inv.b\001j\003jmp\003mov\005mov.b\003nop\003"
    "pop\004push\006push.b\003ret\004reti\003rla\005rla.b\003rlc\005rlc.b\003"
    "rra\005rra.b\003rrc\005rrc.b\003sbc\005sbc.b\004setc\004setn\004setz\003"
    "sub\005sub.b\004subc\006subc.b\004swpb\003sxt\003tst\005tst.b\003xor\005"
    "xor.b";

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
    uint16_t Opcode;
    uint16_t ConvertFn;
    uint8_t RequiredFeatures;
    uint8_t Classes[2];
    StringRef getMnemonic() const {
      return StringRef(MnemonicTable + Mnemonic + 1,
                       MnemonicTable[Mnemonic]);
    }
  };

  // Predicate for searching for an opcode.
  struct LessOpcode {
    bool operator()(const MatchEntry &LHS, StringRef RHS) {
      return LHS.getMnemonic() < RHS;
    }
    bool operator()(StringRef LHS, const MatchEntry &RHS) {
      return LHS < RHS.getMnemonic();
    }
    bool operator()(const MatchEntry &LHS, const MatchEntry &RHS) {
      return LHS.getMnemonic() < RHS.getMnemonic();
    }
  };
} // end anonymous namespace.

static const MatchEntry MatchTable0[] = {
  { 0 /* adc */, MSP430::ADDC16rc, Convert__Reg1_0__Tie0__imm_95_0, 0, { MCK_GR16 }, },
  { 0 /* adc */, MSP430::ADDC16mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 4 /* adc.b */, MSP430::ADDC8rc, Convert__Reg1_0__Tie0__imm_95_0, 0, { MCK_GR8 }, },
  { 4 /* adc.b */, MSP430::ADDC8mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16rr, Convert__Reg1_1__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16rc, Convert__Reg1_1__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16ri, Convert__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16mc, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16rm, Convert__Reg1_1__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8rr, Convert__Reg1_1__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8rc, Convert__Reg1_1__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8ri, Convert__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8rm, Convert__Reg1_1__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 72 /* br */, MSP430::Br, Convert__Reg1_0, 0, { MCK_GR16 }, },
  { 72 /* br */, MSP430::Bi, Convert__Imm1_0, 0, { MCK_Imm }, },
  { 72 /* br */, MSP430::Bm, Convert__Mem2_0, 0, { MCK_Mem }, },
  { 75 /* call */, MSP430::CALLr, Convert__Reg1_0, 0, { MCK_GR16 }, },
  { 75 /* call */, MSP430::CALLi, Convert__Imm1_0, 0, { MCK_Imm }, },
  { 75 /* call */, MSP430::CALLm, Convert__Mem2_0, 0, { MCK_Mem }, },
  { 80 /* clr */, MSP430::MOV16rc, Convert__Reg1_0__imm_95_0, 0, { MCK_GR16 }, },
  { 80 /* clr */, MSP430::MOV16mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 84 /* clr.b */, MSP430::MOV8rc, Convert__Reg1_0__imm_95_0, 0, { MCK_GR8 }, },
  { 84 /* clr.b */, MSP430::MOV8mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 90 /* clrc */, MSP430::BIC16rc, Convert__regSR__Tie0__imm_95_1, 0, {  }, },
  { 95 /* clrn */, MSP430::BIC16rc, Convert__regSR__Tie0__imm_95_4, 0, {  }, },
  { 100 /* clrz */, MSP430::BIC16rc, Convert__regSR__Tie0__imm_95_2, 0, {  }, },
  { 105 /* cmp */, MSP430::CMP16rr, Convert__Reg1_1__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 105 /* cmp */, MSP430::CMP16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 105 /* cmp */, MSP430::CMP16rc, Convert__Reg1_1__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 105 /* cmp */, MSP430::CMP16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 105 /* cmp */, MSP430::CMP16ri, Convert__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 105 /* cmp */, MSP430::CMP16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 105 /* cmp */, MSP430::CMP16rm, Convert__Reg1_1__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 109 /* cmp.b */, MSP430::CMP8rr, Convert__Reg1_1__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 109 /* cmp.b */, MSP430::CMP8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 109 /* cmp.b */, MSP430::CMP8rc, Convert__Reg1_1__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 109 /* cmp.b */, MSP430::CMP8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 109 /* cmp.b */, MSP430::CMP8ri, Convert__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 109 /* cmp.b */, MSP430::CMP8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 109 /* cmp.b */, MSP430::CMP8rm, Convert__Reg1_1__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 115 /* dadc */, MSP430::DADD16rc, Convert__Reg1_0__Tie0__imm_95_0, 0, { MCK_GR16 }, },
  { 115 /* dadc */, MSP430::DADD16mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 120 /* dadc.b */, MSP430::DADD8rc, Convert__Reg1_0__Tie0__imm_95_0, 0, { MCK_GR8 }, },
  { 120 /* dadc.b */, MSP430::DADD8mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 139 /* dec */, MSP430::SUB16rc, Convert__Reg1_0__Tie0__imm_95_1, 0, { MCK_GR16 }, },
  { 139 /* dec */, MSP430::SUB16mc, Convert__Mem2_0__imm_95_1, 0, { MCK_Mem }, },
  { 143 /* dec.b */, MSP430::SUB8rc, Convert__Reg1_0__Tie0__imm_95_1, 0, { MCK_GR8 }, },
  { 143 /* dec.b */, MSP430::SUB8mc, Convert__Mem2_0__imm_95_1, 0, { MCK_Mem }, },
  { 149 /* decd */, MSP430::SUB16rc, Convert__Reg1_0__Tie0__imm_95_2, 0, { MCK_GR16 }, },
  { 149 /* decd */, MSP430::SUB16mc, Convert__Mem2_0__imm_95_2, 0, { MCK_Mem }, },
  { 154 /* decd.b */, MSP430::SUB8rc, Convert__Reg1_0__Tie0__imm_95_2, 0, { MCK_GR8 }, },
  { 154 /* decd.b */, MSP430::SUB8mc, Convert__Mem2_0__imm_95_2, 0, { MCK_Mem }, },
  { 161 /* dint */, MSP430::BIC16rc, Convert__regSR__Tie0__imm_95_8, 0, {  }, },
  { 166 /* eint */, MSP430::BIS16rc, Convert__regSR__Tie0__imm_95_8, 0, {  }, },
  { 171 /* inc */, MSP430::ADD16rc, Convert__Reg1_0__Tie0__imm_95_1, 0, { MCK_GR16 }, },
  { 171 /* inc */, MSP430::ADD16mc, Convert__Mem2_0__imm_95_1, 0, { MCK_Mem }, },
  { 175 /* inc.b */, MSP430::ADD8rc, Convert__Reg1_0__Tie0__imm_95_1, 0, { MCK_GR8 }, },
  { 175 /* inc.b */, MSP430::ADD8mc, Convert__Mem2_0__imm_95_1, 0, { MCK_Mem }, },
  { 181 /* incd */, MSP430::ADD16rc, Convert__Reg1_0__Tie0__imm_95_2, 0, { MCK_GR16 }, },
  { 181 /* incd */, MSP430::ADD16mc, Convert__Mem2_0__imm_95_2, 0, { MCK_Mem }, },
  { 186 /* incd.b */, MSP430::ADD8rc, Convert__Reg1_0__Tie0__imm_95_2, 0, { MCK_GR8 }, },
  { 186 /* incd.b */, MSP430::ADD8mc, Convert__Mem2_0__imm_95_2, 0, { MCK_Mem }, },
  { 193 /* inv */, MSP430::XOR16rc, Convert__Reg1_0__Tie0__imm_95__MINUS_1, 0, { MCK_GR16 }, },
  { 193 /* inv */, MSP430::XOR16mc, Convert__Mem2_0__imm_95__MINUS_1, 0, { MCK_Mem }, },
  { 197 /* inv.b */, MSP430::XOR8rc, Convert__Reg1_0__Tie0__imm_95__MINUS_1, 0, { MCK_GR8 }, },
  { 197 /* inv.b */, MSP430::XOR8mc, Convert__Mem2_0__imm_95__MINUS_1, 0, { MCK_Mem }, },
  { 203 /* j */, MSP430::JCC, Convert__Imm1_1__Imm1_0, 0, { MCK_Imm, MCK_Imm }, },
  { 205 /* jmp */, MSP430::JMP, Convert__Imm1_0, 0, { MCK_Imm }, },
  { 209 /* mov */, MSP430::MOV16rr, Convert__Reg1_1__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 209 /* mov */, MSP430::MOV16rc, Convert__Reg1_1__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 209 /* mov */, MSP430::MOV16ri, Convert__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 209 /* mov */, MSP430::MOV16rn, Convert__Reg1_1__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16rm, Convert__Reg1_1__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 209 /* mov */, MSP430::MOV16rp, Convert__Reg1_1__PostIndReg1_0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 213 /* mov.b */, MSP430::MOV8rr, Convert__Reg1_1__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 213 /* mov.b */, MSP430::MOV8rc, Convert__Reg1_1__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 213 /* mov.b */, MSP430::MOV8ri, Convert__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 213 /* mov.b */, MSP430::MOV8rn, Convert__Reg1_1__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8rm, Convert__Reg1_1__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 213 /* mov.b */, MSP430::MOV8rp, Convert__Reg1_1__PostIndReg1_0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 219 /* nop */, MSP430::MOV16rc, Convert__regCG__imm_95_0, 0, {  }, },
  { 223 /* pop */, MSP430::POP16r, Convert__Reg1_0, 0, { MCK_GR16 }, },
  { 227 /* push */, MSP430::PUSH16r, Convert__Reg1_0, 0, { MCK_GR16 }, },
  { 227 /* push */, MSP430::PUSH16c, Convert__CGImm1_0, 0, { MCK_CGImm }, },
  { 227 /* push */, MSP430::PUSH16i, Convert__Imm1_0, 0, { MCK_Imm }, },
  { 232 /* push.b */, MSP430::PUSH8r, Convert__Reg1_0, 0, { MCK_GR8 }, },
  { 239 /* ret */, MSP430::RET, Convert_NoOperands, 0, {  }, },
  { 243 /* reti */, MSP430::RETI, Convert_NoOperands, 0, {  }, },
  { 248 /* rla */, MSP430::ADD16rr, Convert__Reg1_0__Tie0__Reg1_0, 0, { MCK_GR16 }, },
  { 248 /* rla */, MSP430::ADD16mm, Convert__Mem2_0__Mem2_0, 0, { MCK_Mem }, },
  { 252 /* rla.b */, MSP430::ADD8rr, Convert__Reg1_0__Tie0__Reg1_0, 0, { MCK_GR8 }, },
  { 252 /* rla.b */, MSP430::ADD8mm, Convert__Mem2_0__Mem2_0, 0, { MCK_Mem }, },
  { 258 /* rlc */, MSP430::ADDC16rr, Convert__Reg1_0__Tie0__Reg1_0, 0, { MCK_GR16 }, },
  { 258 /* rlc */, MSP430::ADDC16mm, Convert__Mem2_0__Mem2_0, 0, { MCK_Mem }, },
  { 262 /* rlc.b */, MSP430::ADDC8rr, Convert__Reg1_0__Tie0__Reg1_0, 0, { MCK_GR8 }, },
  { 262 /* rlc.b */, MSP430::ADDC8mm, Convert__Mem2_0__Mem2_0, 0, { MCK_Mem }, },
  { 268 /* rra */, MSP430::RRA16r, Convert__Reg1_0__Tie0, 0, { MCK_GR16 }, },
  { 272 /* rra.b */, MSP430::RRA8r, Convert__Reg1_0__Tie0, 0, { MCK_GR8 }, },
  { 278 /* rrc */, MSP430::RRC16r, Convert__Reg1_0__Tie0, 0, { MCK_GR16 }, },
  { 282 /* rrc.b */, MSP430::RRC8r, Convert__Reg1_0__Tie0, 0, { MCK_GR8 }, },
  { 288 /* sbc */, MSP430::SUBC16rc, Convert__Reg1_0__Tie0__imm_95_0, 0, { MCK_GR16 }, },
  { 288 /* sbc */, MSP430::SUBC16mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 292 /* sbc.b */, MSP430::SUBC8rc, Convert__Reg1_0__Tie0__imm_95_0, 0, { MCK_GR8 }, },
  { 292 /* sbc.b */, MSP430::SUBC8mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 298 /* setc */, MSP430::BIS16rc, Convert__regSR__Tie0__imm_95_1, 0, {  }, },
  { 303 /* setn */, MSP430::BIS16rc, Convert__regSR__Tie0__imm_95_4, 0, {  }, },
  { 308 /* setz */, MSP430::BIS16rc, Convert__regSR__Tie0__imm_95_2, 0, {  }, },
  { 313 /* sub */, MSP430::SUB16rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 335 /* swpb */, MSP430::SWPB16r, Convert__Reg1_0__Tie0, 0, { MCK_GR16 }, },
  { 340 /* sxt */, MSP430::SEXT16r, Convert__Reg1_0__Tie0, 0, { MCK_GR16 }, },
  { 344 /* tst */, MSP430::CMP16rc, Convert__Reg1_0__imm_95_0, 0, { MCK_GR16 }, },
  { 344 /* tst */, MSP430::CMP16mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 348 /* tst.b */, MSP430::CMP8rc, Convert__Reg1_0__imm_95_0, 0, { MCK_GR8 }, },
  { 348 /* tst.b */, MSP430::CMP8mc, Convert__Mem2_0__imm_95_0, 0, { MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR16, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR16, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rr, Convert__Reg1_1__Tie0__Reg1_0, 0, { MCK_GR8, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mr, Convert__Mem2_1__Reg1_0, 0, { MCK_GR8, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rc, Convert__Reg1_1__Tie0__CGImm1_0, 0, { MCK_CGImm, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mc, Convert__Mem2_1__CGImm1_0, 0, { MCK_CGImm, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8ri, Convert__Reg1_1__Tie0__Imm1_0, 0, { MCK_Imm, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mi, Convert__Mem2_1__Imm1_0, 0, { MCK_Imm, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rn, Convert__Reg1_1__Tie0__IndReg1_0, 0, { MCK_IndReg, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mn, Convert__Mem2_1__IndReg1_0, 0, { MCK_IndReg, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rm, Convert__Reg1_1__Tie0__Mem2_0, 0, { MCK_Mem, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mm, Convert__Mem2_1__Mem2_0, 0, { MCK_Mem, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rp, Convert__Reg1_1__PostIndReg1_0__Tie0__Tie1, 0, { MCK_PostIndReg, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mp, Convert__Mem2_1__PostIndReg1_0, 0, { MCK_PostIndReg, MCK_Mem }, },
};

bool MSP430AsmParser::
mnemonicIsValid(StringRef Mnemonic, unsigned VariantID) {
  // Find the appropriate table for this asm variant.
  const MatchEntry *Start, *End;
  switch (VariantID) {
  default: llvm_unreachable("invalid variant!");
  case 0: Start = std::begin(MatchTable0); End = std::end(MatchTable0); break;
  }
  // Search the table.
  auto MnemonicRange = std::equal_range(Start, End, Mnemonic, LessOpcode());
  return MnemonicRange.first != MnemonicRange.second;
}

unsigned MSP430AsmParser::
MatchInstructionImpl(const OperandVector &Operands,
                     MCInst &Inst, uint64_t &ErrorInfo,
                     bool matchingInlineAsm, unsigned VariantID) {
  // Eliminate obvious mismatches.
  if (Operands.size() > 3) {
    ErrorInfo = 3;
    return Match_InvalidOperand;
  }

  // Get the current feature set.
  uint64_t AvailableFeatures = getAvailableFeatures();

  // Get the instruction mnemonic, which is the first token.
  StringRef Mnemonic = ((MSP430Operand&)*Operands[0]).getToken();

  // Some state to try to produce better error messages.
  bool HadMatchOtherThanFeatures = false;
  bool HadMatchOtherThanPredicate = false;
  unsigned RetCode = Match_InvalidOperand;
  uint64_t MissingFeatures = ~0ULL;
  // Set ErrorInfo to the operand that mismatches if it is
  // wrong for all instances of the instruction.
  ErrorInfo = ~0ULL;
  // Find the appropriate table for this asm variant.
  const MatchEntry *Start, *End;
  switch (VariantID) {
  default: llvm_unreachable("invalid variant!");
  case 0: Start = std::begin(MatchTable0); End = std::end(MatchTable0); break;
  }
  // Search the table.
  auto MnemonicRange = std::equal_range(Start, End, Mnemonic, LessOpcode());

  // Return a more specific error code if no mnemonics match.
  if (MnemonicRange.first == MnemonicRange.second)
    return Match_MnemonicFail;

  for (const MatchEntry *it = MnemonicRange.first, *ie = MnemonicRange.second;
       it != ie; ++it) {
    // equal_range guarantees that instruction mnemonic matches.
    assert(Mnemonic == it->getMnemonic());
    bool OperandsValid = true;
    for (unsigned FormalIdx = 0, ActualIdx = 1; FormalIdx != 2; ++FormalIdx) {
      auto Formal = static_cast<MatchClassKind>(it->Classes[FormalIdx]);
      if (ActualIdx >= Operands.size()) {
        OperandsValid = (Formal == InvalidMatchClass) || isSubclass(Formal, OptionalMatchClass);
        if (!OperandsValid) ErrorInfo = ActualIdx;
        break;
      }
      MCParsedAsmOperand &Actual = *Operands[ActualIdx];
      unsigned Diag = validateOperandClass(Actual, Formal);
      if (Diag == Match_Success) {
        ++ActualIdx;
        continue;
      }
      // If the generic handler indicates an invalid operand
      // failure, check for a special case.
      if (Diag == Match_InvalidOperand) {
        Diag = validateTargetOperandClass(Actual, Formal);
        if (Diag == Match_Success) {
          ++ActualIdx;
          continue;
        }
      }
      // If current formal operand wasn't matched and it is optional
      // then try to match next formal operand
      if (Diag == Match_InvalidOperand && isSubclass(Formal, OptionalMatchClass)) {
        continue;
      }
      // If this operand is broken for all of the instances of this
      // mnemonic, keep track of it so we can report loc info.
      // If we already had a match that only failed due to a
      // target predicate, that diagnostic is preferred.
      if (!HadMatchOtherThanPredicate &&
          (it == MnemonicRange.first || ErrorInfo <= ActualIdx)) {
        ErrorInfo = ActualIdx;
        // InvalidOperand is the default. Prefer specificity.
        if (Diag != Match_InvalidOperand)
          RetCode = Diag;
      }
      // Otherwise, just reject this instance of the mnemonic.
      OperandsValid = false;
      break;
    }

    if (!OperandsValid) continue;
    if ((AvailableFeatures & it->RequiredFeatures) != it->RequiredFeatures) {
      HadMatchOtherThanFeatures = true;
      uint64_t NewMissingFeatures = it->RequiredFeatures & ~AvailableFeatures;
      if (countPopulation(NewMissingFeatures) <=
          countPopulation(MissingFeatures))
        MissingFeatures = NewMissingFeatures;
      continue;
    }

    Inst.clear();

    if (matchingInlineAsm) {
      Inst.setOpcode(it->Opcode);
      convertToMapAndConstraints(it->ConvertFn, Operands);
      return Match_Success;
    }

    // We have selected a definite instruction, convert the parsed
    // operands into the appropriate MCInst.
    convertToMCInst(it->ConvertFn, Inst, it->Opcode, Operands);

    // We have a potential match. Check the target predicate to
    // handle any context sensitive constraints.
    unsigned MatchResult;
    if ((MatchResult = checkTargetMatchPredicate(Inst)) != Match_Success) {
      Inst.clear();
      RetCode = MatchResult;
      HadMatchOtherThanPredicate = true;
      continue;
    }

    return Match_Success;
  }

  // Okay, we had no match.  Try to return a useful error code.
  if (HadMatchOtherThanPredicate || !HadMatchOtherThanFeatures)
    return RetCode;

  // Missing feature matches return which features were missing
  ErrorInfo = MissingFeatures;
  return Match_MissingFeature;
}

#endif // GET_MATCHER_IMPLEMENTATION

