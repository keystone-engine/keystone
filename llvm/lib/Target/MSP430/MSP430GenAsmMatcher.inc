/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: MSP430.td                                                            *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_ASSEMBLER_HEADER
#undef GET_ASSEMBLER_HEADER
  // This should be included into the middle of the declaration of
  // your subclasses implementation of MCTargetAsmParser.
  FeatureBitset ComputeAvailableFeatures(const FeatureBitset &FB) const;
  void convertToMCInst(unsigned Kind, MCInst &Inst, unsigned Opcode,
                       const OperandVector &Operands);
  void convertToMapAndConstraints(unsigned Kind,
                           const OperandVector &Operands) override;
  unsigned MatchInstructionImpl(const OperandVector &Operands,
                                MCInst &Inst,
                                uint64_t &ErrorInfo,
                                FeatureBitset &MissingFeatures,
                                bool matchingInlineAsm,
                                unsigned VariantID = 0);
  unsigned MatchInstructionImpl(const OperandVector &Operands,
                                MCInst &Inst,
                                uint64_t &ErrorInfo,
                                bool matchingInlineAsm,
                                unsigned VariantID = 0) {
    FeatureBitset MissingFeatures;
    return MatchInstructionImpl(Operands, Inst, ErrorInfo, MissingFeatures,
                                matchingInlineAsm, VariantID);
  }

#endif // GET_ASSEMBLER_HEADER


#ifdef GET_OPERAND_DIAGNOSTIC_TYPES
#undef GET_OPERAND_DIAGNOSTIC_TYPES

#endif // GET_OPERAND_DIAGNOSTIC_TYPES


#ifdef GET_REGISTER_MATCHER
#undef GET_REGISTER_MATCHER

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
};

static MCRegister MatchRegisterName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 20 strings to match.
    if (Name[0] != 'r')
      break;
    switch (Name[1]) {
    default: break;
    case '0':	 // 2 strings to match.
      return MSP430::PC;	 // "r0"
    case '1':	 // 2 strings to match.
      return MSP430::SP;	 // "r1"
    case '2':	 // 2 strings to match.
      return MSP430::SR;	 // "r2"
    case '3':	 // 2 strings to match.
      return MSP430::CG;	 // "r3"
    case '4':	 // 2 strings to match.
      return MSP430::R4;	 // "r4"
    case '5':	 // 2 strings to match.
      return MSP430::R5;	 // "r5"
    case '6':	 // 2 strings to match.
      return MSP430::R6;	 // "r6"
    case '7':	 // 2 strings to match.
      return MSP430::R7;	 // "r7"
    case '8':	 // 2 strings to match.
      return MSP430::R8;	 // "r8"
    case '9':	 // 2 strings to match.
      return MSP430::R9;	 // "r9"
    }
    break;
  case 3:	 // 12 strings to match.
    if (memcmp(Name.data()+0, "r1", 2) != 0)
      break;
    switch (Name[2]) {
    default: break;
    case '0':	 // 2 strings to match.
      return MSP430::R10;	 // "r10"
    case '1':	 // 2 strings to match.
      return MSP430::R11;	 // "r11"
    case '2':	 // 2 strings to match.
      return MSP430::R12;	 // "r12"
    case '3':	 // 2 strings to match.
      return MSP430::R13;	 // "r13"
    case '4':	 // 2 strings to match.
      return MSP430::R14;	 // "r14"
    case '5':	 // 2 strings to match.
      return MSP430::R15;	 // "r15"
    }
    break;
  }
  return MSP430::NoRegister;
}

static MCRegister MatchRegisterAltName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 10 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 2 strings to match.
      if (Name[1] != 'g')
        break;
      return MSP430::CG;	 // "cg"
    case 'f':	 // 2 strings to match.
      if (Name[1] != 'p')
        break;
      return MSP430::R4;	 // "fp"
    case 'p':	 // 2 strings to match.
      if (Name[1] != 'c')
        break;
      return MSP430::PC;	 // "pc"
    case 's':	 // 4 strings to match.
      switch (Name[1]) {
      default: break;
      case 'p':	 // 2 strings to match.
        return MSP430::SP;	 // "sp"
      case 'r':	 // 2 strings to match.
        return MSP430::SR;	 // "sr"
      }
      break;
    }
    break;
  }
  return MSP430::NoRegister;
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

enum {
  Tie0_1_1,
  Tie1_1_1,
};

static const uint8_t TiedAsmOperandTable[][3] = {
  /* Tie0_1_1 */ { 0, 1, 1 },
  /* Tie1_1_1 */ { 1, 1, 1 },
};

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
  Convert__Reg1_0__Tie0_1_1__imm_95_0,
  Convert__Mem2_0__imm_95_0,
  Convert__Reg1_1__Tie0_1_1__Reg1_0,
  Convert__Mem2_1__Reg1_0,
  Convert__Reg1_1__Tie0_1_1__CGImm1_0,
  Convert__Mem2_1__CGImm1_0,
  Convert__Reg1_1__Tie0_1_1__Imm1_0,
  Convert__Mem2_1__Imm1_0,
  Convert__Reg1_1__Tie0_1_1__IndReg1_0,
  Convert__Mem2_1__IndReg1_0,
  Convert__Reg1_1__Tie0_1_1__Mem2_0,
  Convert__Mem2_1__Mem2_0,
  Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1,
  Convert__Mem2_1__PostIndReg1_0,
  Convert__Reg1_1__Reg1_0,
  Convert__Reg1_1__CGImm1_0,
  Convert__Reg1_1__Imm1_0,
  Convert__Reg1_1__IndReg1_0,
  Convert__Reg1_1__Mem2_0,
  Convert__Reg1_1__PostIndReg1_0,
  Convert__Reg1_0,
  Convert__Imm1_0,
  Convert__Mem2_0,
  Convert__IndReg1_0,
  Convert__PostIndReg1_0,
  Convert__Reg1_0__imm_95_0,
  Convert__regSR__Tie0_1_1__imm_95_1,
  Convert__regSR__Tie0_1_1__imm_95_4,
  Convert__regSR__Tie0_1_1__imm_95_2,
  Convert__Reg1_0__Tie0_1_1__imm_95_1,
  Convert__Mem2_0__imm_95_1,
  Convert__Reg1_0__Tie0_1_1__imm_95_2,
  Convert__Mem2_0__imm_95_2,
  Convert__regSR__Tie0_1_1__imm_95_8,
  Convert__Reg1_0__Tie0_1_1__imm_95__MINUS_1,
  Convert__Mem2_0__imm_95__MINUS_1,
  Convert__Imm1_1__Imm1_0,
  Convert__Reg1_1__PostIndReg1_0__Tie1_1_1,
  Convert__regCG__imm_95_0,
  Convert__CGImm1_0,
  Convert_NoOperands,
  Convert__Reg1_0__Tie0_1_1__Reg1_0,
  Convert__Mem2_0__Mem2_0,
  Convert__Reg1_0__Tie0_1_1,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][9] = {
  // Convert__Reg1_0__Tie0_1_1__imm_95_0
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Mem2_0__imm_95_0
  { CVT_95_addMemOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_1__Tie0_1_1__Reg1_0
  { CVT_95_Reg, 2, CVT_Tied, Tie0_1_1, CVT_95_Reg, 1, CVT_Done },
  // Convert__Mem2_1__Reg1_0
  { CVT_95_addMemOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__Tie0_1_1__CGImm1_0
  { CVT_95_Reg, 2, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Mem2_1__CGImm1_0
  { CVT_95_addMemOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Tie0_1_1__Imm1_0
  { CVT_95_Reg, 2, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Mem2_1__Imm1_0
  { CVT_95_addMemOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Tie0_1_1__IndReg1_0
  { CVT_95_Reg, 2, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Mem2_1__IndReg1_0
  { CVT_95_addMemOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_1__Tie0_1_1__Mem2_0
  { CVT_95_Reg, 2, CVT_Tied, Tie0_1_1, CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__Mem2_1__Mem2_0
  { CVT_95_addMemOperands, 2, CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1
  { CVT_95_Reg, 2, CVT_95_addRegOperands, 1, CVT_Tied, Tie0_1_1, CVT_Tied, Tie1_1_1, CVT_Done },
  // Convert__Mem2_1__PostIndReg1_0
  { CVT_95_addMemOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__CGImm1_0
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Imm1_0
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__IndReg1_0
  { CVT_95_Reg, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_1__Mem2_0
  { CVT_95_Reg, 2, CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__Reg1_1__PostIndReg1_0
  { CVT_95_Reg, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Mem2_0
  { CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__IndReg1_0
  { CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__PostIndReg1_0
  { CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_0__imm_95_0
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__regSR__Tie0_1_1__imm_95_1
  { CVT_regSR, 0, CVT_Tied, Tie0_1_1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__regSR__Tie0_1_1__imm_95_4
  { CVT_regSR, 0, CVT_Tied, Tie0_1_1, CVT_imm_95_4, 0, CVT_Done },
  // Convert__regSR__Tie0_1_1__imm_95_2
  { CVT_regSR, 0, CVT_Tied, Tie0_1_1, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__imm_95_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Mem2_0__imm_95_1
  { CVT_95_addMemOperands, 1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__imm_95_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Mem2_0__imm_95_2
  { CVT_95_addMemOperands, 1, CVT_imm_95_2, 0, CVT_Done },
  // Convert__regSR__Tie0_1_1__imm_95_8
  { CVT_regSR, 0, CVT_Tied, Tie0_1_1, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__imm_95__MINUS_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_imm_95__MINUS_1, 0, CVT_Done },
  // Convert__Mem2_0__imm_95__MINUS_1
  { CVT_95_addMemOperands, 1, CVT_imm_95__MINUS_1, 0, CVT_Done },
  // Convert__Imm1_1__Imm1_0
  { CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__PostIndReg1_0__Tie1_1_1
  { CVT_95_Reg, 2, CVT_95_addRegOperands, 1, CVT_Tied, Tie1_1_1, CVT_Done },
  // Convert__regCG__imm_95_0
  { CVT_regCG, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__CGImm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_0
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 1, CVT_Done },
  // Convert__Mem2_0__Mem2_0
  { CVT_95_addMemOperands, 1, CVT_95_addMemOperands, 1, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_Done },
};

void MSP430AsmParser::
convertToMCInst(unsigned Kind, MCInst &Inst, unsigned Opcode,
                const OperandVector &Operands) {
  assert(Kind < CVT_NUM_SIGNATURES && "Invalid signature!");
  const uint8_t *Converter = ConversionTable[Kind];
  Inst.setOpcode(Opcode);
  for (const uint8_t *p = Converter; *p; p += 2) {
    unsigned OpIdx = *(p + 1);
    switch (*p) {
    default: llvm_unreachable("invalid conversion entry!");
    case CVT_Reg:
      static_cast<MSP430Operand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_Tied: {
      assert(*(p + 1) < (size_t)(std::end(TiedAsmOperandTable) -
                              std::begin(TiedAsmOperandTable)) &&
             "Tied operand not found");
      unsigned TiedResOpnd = TiedAsmOperandTable[*(p + 1)][0];
      if (TiedResOpnd != (uint8_t)-1)
        Inst.addOperand(Inst.getOperand(TiedResOpnd));
      break;
    }
    case CVT_95_Reg:
      static_cast<MSP430Operand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_95_addMemOperands:
      static_cast<MSP430Operand &>(*Operands[OpIdx]).addMemOperands(Inst, 2);
      break;
    case CVT_95_addImmOperands:
      static_cast<MSP430Operand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_addRegOperands:
      static_cast<MSP430Operand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
  for (const uint8_t *p = Converter; *p; p += 2) {
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
  MCK_LAST_TOKEN = OptionalMatchClass,
  MCK_GR16, // register class 'GR16'
  MCK_GR8, // register class 'GR8'
  MCK_LAST_REGISTER = MCK_GR8,
  MCK_CGImm, // user defined class 'CGImmAsmOperand'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_IndReg, // user defined class 'IndRegAsmOperand'
  MCK_Mem, // user defined class 'MemAsmOperand'
  MCK_PostIndReg, // user defined class 'PostIndRegAsmOperand'
  NumMatchClassKinds
};

} // end anonymous namespace

static unsigned getDiagKindFromRegisterClass(MatchClassKind RegisterClass) {
  return MCTargetAsmParser::Match_InvalidOperand;
}

static MatchClassKind matchTokenString(StringRef Name) {
  return InvalidMatchClass;
}

/// isSubclass - Compute whether \p A is a subclass of \p B.
static bool isSubclass(MatchClassKind A, MatchClassKind B) {
  if (A == B)
    return true;

  [[maybe_unused]] static constexpr struct {
    uint32_t Offset;
    uint16_t Start;
    uint16_t Length;
  } Table[] = {
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
  };

  return false;
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind, const MCSubtargetInfo &STI) {
  MSP430Operand &Operand = (MSP430Operand &)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  case MCK_CGImm: {
    DiagnosticPredicate DP(Operand.isCGImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Imm: {
    DiagnosticPredicate DP(Operand.isImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_IndReg: {
    DiagnosticPredicate DP(Operand.isIndReg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Mem: {
    DiagnosticPredicate DP(Operand.isMem());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_PostIndReg: {
    DiagnosticPredicate DP(Operand.isPostIndReg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg()) {
    static constexpr uint16_t Table[MSP430::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      MCK_GR16,
      MCK_GR8,
      MCK_GR16,
      MCK_GR8,
      MCK_GR16,
      MCK_GR8,
      MCK_GR16,
      MCK_GR8,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR16,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
      MCK_GR8,
    };

    MCRegister Reg = Operand.getReg();
    MatchClassKind OpKind = Reg.isPhysical() ? (MatchClassKind)Table[Reg.id()] : InvalidMatchClass;
    return isSubclass(OpKind, Kind) ? (unsigned)MCTargetAsmParser::Match_Success :
                                      getDiagKindFromRegisterClass(Kind);
  }

  if (Kind > MCK_LAST_TOKEN && Kind <= MCK_LAST_REGISTER)
    return getDiagKindFromRegisterClass(Kind);

  return MCTargetAsmParser::Match_InvalidOperand;
}

#ifndef NDEBUG
const char *getMatchClassName(MatchClassKind Kind) {
  switch (Kind) {
  case InvalidMatchClass: return "InvalidMatchClass";
  case OptionalMatchClass: return "OptionalMatchClass";
  case MCK_GR16: return "MCK_GR16";
  case MCK_GR8: return "MCK_GR8";
  case MCK_CGImm: return "MCK_CGImm";
  case MCK_Imm: return "MCK_Imm";
  case MCK_IndReg: return "MCK_IndReg";
  case MCK_Mem: return "MCK_Mem";
  case MCK_PostIndReg: return "MCK_PostIndReg";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset MSP430AsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  return Features;
}

static bool checkAsmTiedOperandConstraints(const MSP430AsmParser&AsmParser,
                               unsigned Kind, const OperandVector &Operands,
                               uint64_t &ErrorInfo) {
  assert(Kind < CVT_NUM_SIGNATURES && "Invalid signature!");
  const uint8_t *Converter = ConversionTable[Kind];
  for (const uint8_t *p = Converter; *p; p += 2) {
    switch (*p) {
    case CVT_Tied: {
      unsigned OpIdx = *(p + 1);
      assert(OpIdx < (size_t)(std::end(TiedAsmOperandTable) -
                              std::begin(TiedAsmOperandTable)) &&
             "Tied operand not found");
      unsigned OpndNum1 = TiedAsmOperandTable[OpIdx][1];
      unsigned OpndNum2 = TiedAsmOperandTable[OpIdx][2];
      if (OpndNum1 != OpndNum2) {
        auto &SrcOp1 = Operands[OpndNum1];
        auto &SrcOp2 = Operands[OpndNum2];
        if (!AsmParser.areEqualRegs(*SrcOp1, *SrcOp2)) {
          ErrorInfo = OpndNum2;
          return false;
        }
      }
      break;
    }
    default:
      break;
    }
  }
  return true;
}

static const char MnemonicTable[] =
    "\003adc\005adc.b\003add\005add.b\004addc\006addc.b\003and\005and.b\003b"
    "ic\005bic.b\003bis\005bis.b\003bit\005bit.b\002br\004call\003clr\005clr"
    ".b\004clrc\004clrn\004clrz\003cmp\005cmp.b\004dadc\006dadc.b\004dadd\006"
    "dadd.b\003dec\005dec.b\004decd\006decd.b\004dint\004eint\003inc\005inc."
    "b\004incd\006incd.b\003inv\005inv.b\001j\003jmp\003mov\005mov.b\003nop\003"
    "pop\004push\006push.b\003ret\004reti\003rla\005rla.b\003rlc\005rlc.b\003"
    "rra\005rra.b\003rrc\005rrc.b\003sbc\005sbc.b\004setc\004setn\004setz\003"
    "sub\005sub.b\004subc\006subc.b\004swpb\003sxt\003tst\005tst.b\003xor\005"
    "xor.b";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
};

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
    uint32_t Opcode;
    uint8_t ConvertFn;
    uint8_t RequiredFeaturesIdx;
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
} // end anonymous namespace

static const MatchEntry MatchTable0[] = {
  { 0 /* adc */, MSP430::ADDC16rc, Convert__Reg1_0__Tie0_1_1__imm_95_0, AMFBS_None, { MCK_GR16 }, },
  { 0 /* adc */, MSP430::ADDC16mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 4 /* adc.b */, MSP430::ADDC8rc, Convert__Reg1_0__Tie0_1_1__imm_95_0, AMFBS_None, { MCK_GR8 }, },
  { 4 /* adc.b */, MSP430::ADDC8mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 10 /* add */, MSP430::ADD16rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 10 /* add */, MSP430::ADD16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 14 /* add.b */, MSP430::ADD8rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 14 /* add.b */, MSP430::ADD8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 20 /* addc */, MSP430::ADDC16rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 20 /* addc */, MSP430::ADDC16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 25 /* addc.b */, MSP430::ADDC8rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 25 /* addc.b */, MSP430::ADDC8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 32 /* and */, MSP430::AND16rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 32 /* and */, MSP430::AND16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 36 /* and.b */, MSP430::AND8rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 36 /* and.b */, MSP430::AND8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 42 /* bic */, MSP430::BIC16rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 42 /* bic */, MSP430::BIC16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 46 /* bic.b */, MSP430::BIC8rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 46 /* bic.b */, MSP430::BIC8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 52 /* bis */, MSP430::BIS16rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 52 /* bis */, MSP430::BIS16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 56 /* bis.b */, MSP430::BIS8rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 56 /* bis.b */, MSP430::BIS8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16rr, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16rc, Convert__Reg1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16ri, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16rn, Convert__Reg1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16rm, Convert__Reg1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 62 /* bit */, MSP430::BIT16rp, Convert__Reg1_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 62 /* bit */, MSP430::BIT16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8rr, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8rc, Convert__Reg1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8ri, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8rn, Convert__Reg1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8rm, Convert__Reg1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 66 /* bit.b */, MSP430::BIT8rp, Convert__Reg1_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 66 /* bit.b */, MSP430::BIT8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 72 /* br */, MSP430::Br, Convert__Reg1_0, AMFBS_None, { MCK_GR16 }, },
  { 72 /* br */, MSP430::Bi, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 72 /* br */, MSP430::Bm, Convert__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 75 /* call */, MSP430::CALLr, Convert__Reg1_0, AMFBS_None, { MCK_GR16 }, },
  { 75 /* call */, MSP430::CALLi, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 75 /* call */, MSP430::CALLn, Convert__IndReg1_0, AMFBS_None, { MCK_IndReg }, },
  { 75 /* call */, MSP430::CALLm, Convert__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 75 /* call */, MSP430::CALLp, Convert__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg }, },
  { 80 /* clr */, MSP430::MOV16rc, Convert__Reg1_0__imm_95_0, AMFBS_None, { MCK_GR16 }, },
  { 80 /* clr */, MSP430::MOV16mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 84 /* clr.b */, MSP430::MOV8rc, Convert__Reg1_0__imm_95_0, AMFBS_None, { MCK_GR8 }, },
  { 84 /* clr.b */, MSP430::MOV8mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 90 /* clrc */, MSP430::BIC16rc, Convert__regSR__Tie0_1_1__imm_95_1, AMFBS_None, {  }, },
  { 95 /* clrn */, MSP430::BIC16rc, Convert__regSR__Tie0_1_1__imm_95_4, AMFBS_None, {  }, },
  { 100 /* clrz */, MSP430::BIC16rc, Convert__regSR__Tie0_1_1__imm_95_2, AMFBS_None, {  }, },
  { 105 /* cmp */, MSP430::CMP16rr, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 105 /* cmp */, MSP430::CMP16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 105 /* cmp */, MSP430::CMP16rc, Convert__Reg1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 105 /* cmp */, MSP430::CMP16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 105 /* cmp */, MSP430::CMP16ri, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 105 /* cmp */, MSP430::CMP16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 105 /* cmp */, MSP430::CMP16rn, Convert__Reg1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 105 /* cmp */, MSP430::CMP16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 105 /* cmp */, MSP430::CMP16rm, Convert__Reg1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 105 /* cmp */, MSP430::CMP16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 105 /* cmp */, MSP430::CMP16rp, Convert__Reg1_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 105 /* cmp */, MSP430::CMP16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 109 /* cmp.b */, MSP430::CMP8rr, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 109 /* cmp.b */, MSP430::CMP8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 109 /* cmp.b */, MSP430::CMP8rc, Convert__Reg1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 109 /* cmp.b */, MSP430::CMP8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 109 /* cmp.b */, MSP430::CMP8ri, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 109 /* cmp.b */, MSP430::CMP8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 109 /* cmp.b */, MSP430::CMP8rn, Convert__Reg1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 109 /* cmp.b */, MSP430::CMP8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 109 /* cmp.b */, MSP430::CMP8rm, Convert__Reg1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 109 /* cmp.b */, MSP430::CMP8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 109 /* cmp.b */, MSP430::CMP8rp, Convert__Reg1_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 109 /* cmp.b */, MSP430::CMP8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 115 /* dadc */, MSP430::DADD16rc, Convert__Reg1_0__Tie0_1_1__imm_95_0, AMFBS_None, { MCK_GR16 }, },
  { 115 /* dadc */, MSP430::DADD16mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 120 /* dadc.b */, MSP430::DADD8rc, Convert__Reg1_0__Tie0_1_1__imm_95_0, AMFBS_None, { MCK_GR8 }, },
  { 120 /* dadc.b */, MSP430::DADD8mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 127 /* dadd */, MSP430::DADD16rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 127 /* dadd */, MSP430::DADD16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 132 /* dadd.b */, MSP430::DADD8rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 132 /* dadd.b */, MSP430::DADD8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 139 /* dec */, MSP430::SUB16rc, Convert__Reg1_0__Tie0_1_1__imm_95_1, AMFBS_None, { MCK_GR16 }, },
  { 139 /* dec */, MSP430::SUB16mc, Convert__Mem2_0__imm_95_1, AMFBS_None, { MCK_Mem }, },
  { 143 /* dec.b */, MSP430::SUB8rc, Convert__Reg1_0__Tie0_1_1__imm_95_1, AMFBS_None, { MCK_GR8 }, },
  { 143 /* dec.b */, MSP430::SUB8mc, Convert__Mem2_0__imm_95_1, AMFBS_None, { MCK_Mem }, },
  { 149 /* decd */, MSP430::SUB16rc, Convert__Reg1_0__Tie0_1_1__imm_95_2, AMFBS_None, { MCK_GR16 }, },
  { 149 /* decd */, MSP430::SUB16mc, Convert__Mem2_0__imm_95_2, AMFBS_None, { MCK_Mem }, },
  { 154 /* decd.b */, MSP430::SUB8rc, Convert__Reg1_0__Tie0_1_1__imm_95_2, AMFBS_None, { MCK_GR8 }, },
  { 154 /* decd.b */, MSP430::SUB8mc, Convert__Mem2_0__imm_95_2, AMFBS_None, { MCK_Mem }, },
  { 161 /* dint */, MSP430::BIC16rc, Convert__regSR__Tie0_1_1__imm_95_8, AMFBS_None, {  }, },
  { 166 /* eint */, MSP430::BIS16rc, Convert__regSR__Tie0_1_1__imm_95_8, AMFBS_None, {  }, },
  { 171 /* inc */, MSP430::ADD16rc, Convert__Reg1_0__Tie0_1_1__imm_95_1, AMFBS_None, { MCK_GR16 }, },
  { 171 /* inc */, MSP430::ADD16mc, Convert__Mem2_0__imm_95_1, AMFBS_None, { MCK_Mem }, },
  { 175 /* inc.b */, MSP430::ADD8rc, Convert__Reg1_0__Tie0_1_1__imm_95_1, AMFBS_None, { MCK_GR8 }, },
  { 175 /* inc.b */, MSP430::ADD8mc, Convert__Mem2_0__imm_95_1, AMFBS_None, { MCK_Mem }, },
  { 181 /* incd */, MSP430::ADD16rc, Convert__Reg1_0__Tie0_1_1__imm_95_2, AMFBS_None, { MCK_GR16 }, },
  { 181 /* incd */, MSP430::ADD16mc, Convert__Mem2_0__imm_95_2, AMFBS_None, { MCK_Mem }, },
  { 186 /* incd.b */, MSP430::ADD8rc, Convert__Reg1_0__Tie0_1_1__imm_95_2, AMFBS_None, { MCK_GR8 }, },
  { 186 /* incd.b */, MSP430::ADD8mc, Convert__Mem2_0__imm_95_2, AMFBS_None, { MCK_Mem }, },
  { 193 /* inv */, MSP430::XOR16rc, Convert__Reg1_0__Tie0_1_1__imm_95__MINUS_1, AMFBS_None, { MCK_GR16 }, },
  { 193 /* inv */, MSP430::XOR16mc, Convert__Mem2_0__imm_95__MINUS_1, AMFBS_None, { MCK_Mem }, },
  { 197 /* inv.b */, MSP430::XOR8rc, Convert__Reg1_0__Tie0_1_1__imm_95__MINUS_1, AMFBS_None, { MCK_GR8 }, },
  { 197 /* inv.b */, MSP430::XOR8mc, Convert__Mem2_0__imm_95__MINUS_1, AMFBS_None, { MCK_Mem }, },
  { 203 /* j */, MSP430::JCC, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 205 /* jmp */, MSP430::JMP, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 209 /* mov */, MSP430::MOV16rr, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 209 /* mov */, MSP430::MOV16rc, Convert__Reg1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 209 /* mov */, MSP430::MOV16ri, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 209 /* mov */, MSP430::MOV16rn, Convert__Reg1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 209 /* mov */, MSP430::MOV16rm, Convert__Reg1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 209 /* mov */, MSP430::MOV16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 209 /* mov */, MSP430::MOV16rp, Convert__Reg1_1__PostIndReg1_0__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 213 /* mov.b */, MSP430::MOV8rr, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 213 /* mov.b */, MSP430::MOV8rc, Convert__Reg1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 213 /* mov.b */, MSP430::MOV8ri, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 213 /* mov.b */, MSP430::MOV8rn, Convert__Reg1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 213 /* mov.b */, MSP430::MOV8rm, Convert__Reg1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 213 /* mov.b */, MSP430::MOV8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 213 /* mov.b */, MSP430::MOV8rp, Convert__Reg1_1__PostIndReg1_0__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 219 /* nop */, MSP430::MOV16rc, Convert__regCG__imm_95_0, AMFBS_None, {  }, },
  { 223 /* pop */, MSP430::POP16r, Convert__Reg1_0, AMFBS_None, { MCK_GR16 }, },
  { 227 /* push */, MSP430::PUSH16r, Convert__Reg1_0, AMFBS_None, { MCK_GR16 }, },
  { 227 /* push */, MSP430::PUSH16c, Convert__CGImm1_0, AMFBS_None, { MCK_CGImm }, },
  { 227 /* push */, MSP430::PUSH16i, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 232 /* push.b */, MSP430::PUSH8r, Convert__Reg1_0, AMFBS_None, { MCK_GR8 }, },
  { 239 /* ret */, MSP430::RET, Convert_NoOperands, AMFBS_None, {  }, },
  { 243 /* reti */, MSP430::RETI, Convert_NoOperands, AMFBS_None, {  }, },
  { 248 /* rla */, MSP430::ADD16rr, Convert__Reg1_0__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16 }, },
  { 248 /* rla */, MSP430::ADD16mm, Convert__Mem2_0__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 252 /* rla.b */, MSP430::ADD8rr, Convert__Reg1_0__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8 }, },
  { 252 /* rla.b */, MSP430::ADD8mm, Convert__Mem2_0__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 258 /* rlc */, MSP430::ADDC16rr, Convert__Reg1_0__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16 }, },
  { 258 /* rlc */, MSP430::ADDC16mm, Convert__Mem2_0__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 262 /* rlc.b */, MSP430::ADDC8rr, Convert__Reg1_0__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8 }, },
  { 262 /* rlc.b */, MSP430::ADDC8mm, Convert__Mem2_0__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 268 /* rra */, MSP430::RRA16r, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GR16 }, },
  { 268 /* rra */, MSP430::RRA16n, Convert__IndReg1_0, AMFBS_None, { MCK_IndReg }, },
  { 268 /* rra */, MSP430::RRA16m, Convert__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 268 /* rra */, MSP430::RRA16p, Convert__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg }, },
  { 272 /* rra.b */, MSP430::RRA8r, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GR8 }, },
  { 272 /* rra.b */, MSP430::RRA8n, Convert__IndReg1_0, AMFBS_None, { MCK_IndReg }, },
  { 272 /* rra.b */, MSP430::RRA8m, Convert__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 272 /* rra.b */, MSP430::RRA8p, Convert__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg }, },
  { 278 /* rrc */, MSP430::RRC16r, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GR16 }, },
  { 278 /* rrc */, MSP430::RRC16n, Convert__IndReg1_0, AMFBS_None, { MCK_IndReg }, },
  { 278 /* rrc */, MSP430::RRC16m, Convert__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 278 /* rrc */, MSP430::RRC16p, Convert__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg }, },
  { 282 /* rrc.b */, MSP430::RRC8r, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GR8 }, },
  { 282 /* rrc.b */, MSP430::RRC8n, Convert__IndReg1_0, AMFBS_None, { MCK_IndReg }, },
  { 282 /* rrc.b */, MSP430::RRC8m, Convert__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 282 /* rrc.b */, MSP430::RRC8p, Convert__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg }, },
  { 288 /* sbc */, MSP430::SUBC16rc, Convert__Reg1_0__Tie0_1_1__imm_95_0, AMFBS_None, { MCK_GR16 }, },
  { 288 /* sbc */, MSP430::SUBC16mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 292 /* sbc.b */, MSP430::SUBC8rc, Convert__Reg1_0__Tie0_1_1__imm_95_0, AMFBS_None, { MCK_GR8 }, },
  { 292 /* sbc.b */, MSP430::SUBC8mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 298 /* setc */, MSP430::BIS16rc, Convert__regSR__Tie0_1_1__imm_95_1, AMFBS_None, {  }, },
  { 303 /* setn */, MSP430::BIS16rc, Convert__regSR__Tie0_1_1__imm_95_4, AMFBS_None, {  }, },
  { 308 /* setz */, MSP430::BIS16rc, Convert__regSR__Tie0_1_1__imm_95_2, AMFBS_None, {  }, },
  { 313 /* sub */, MSP430::SUB16rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 313 /* sub */, MSP430::SUB16rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 313 /* sub */, MSP430::SUB16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 317 /* sub.b */, MSP430::SUB8rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 317 /* sub.b */, MSP430::SUB8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 323 /* subc */, MSP430::SUBC16rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 323 /* subc */, MSP430::SUBC16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 328 /* subc.b */, MSP430::SUBC8rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 328 /* subc.b */, MSP430::SUBC8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 335 /* swpb */, MSP430::SWPB16r, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GR16 }, },
  { 335 /* swpb */, MSP430::SWPB16n, Convert__IndReg1_0, AMFBS_None, { MCK_IndReg }, },
  { 335 /* swpb */, MSP430::SWPB16m, Convert__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 335 /* swpb */, MSP430::SWPB16p, Convert__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg }, },
  { 340 /* sxt */, MSP430::SEXT16r, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GR16 }, },
  { 340 /* sxt */, MSP430::SEXT16n, Convert__IndReg1_0, AMFBS_None, { MCK_IndReg }, },
  { 340 /* sxt */, MSP430::SEXT16m, Convert__Mem2_0, AMFBS_None, { MCK_Mem }, },
  { 340 /* sxt */, MSP430::SEXT16p, Convert__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg }, },
  { 344 /* tst */, MSP430::CMP16rc, Convert__Reg1_0__imm_95_0, AMFBS_None, { MCK_GR16 }, },
  { 344 /* tst */, MSP430::CMP16mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 348 /* tst.b */, MSP430::CMP8rc, Convert__Reg1_0__imm_95_0, AMFBS_None, { MCK_GR8 }, },
  { 348 /* tst.b */, MSP430::CMP8mc, Convert__Mem2_0__imm_95_0, AMFBS_None, { MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR16, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 354 /* xor */, MSP430::XOR16rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR16 }, },
  { 354 /* xor */, MSP430::XOR16mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rr, Convert__Reg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mr, Convert__Mem2_1__Reg1_0, AMFBS_None, { MCK_GR8, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rc, Convert__Reg1_1__Tie0_1_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mc, Convert__Mem2_1__CGImm1_0, AMFBS_None, { MCK_CGImm, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8ri, Convert__Reg1_1__Tie0_1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mi, Convert__Mem2_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rn, Convert__Reg1_1__Tie0_1_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mn, Convert__Mem2_1__IndReg1_0, AMFBS_None, { MCK_IndReg, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rm, Convert__Reg1_1__Tie0_1_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mm, Convert__Mem2_1__Mem2_0, AMFBS_None, { MCK_Mem, MCK_Mem }, },
  { 358 /* xor.b */, MSP430::XOR8rp, Convert__Reg1_1__PostIndReg1_0__Tie0_1_1__Tie1_1_1, AMFBS_None, { MCK_PostIndReg, MCK_GR8 }, },
  { 358 /* xor.b */, MSP430::XOR8mp, Convert__Mem2_1__PostIndReg1_0, AMFBS_None, { MCK_PostIndReg, MCK_Mem }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned MSP430AsmParser::
MatchInstructionImpl(const OperandVector &Operands,
                     MCInst &Inst,
                     uint64_t &ErrorInfo,
                     FeatureBitset &MissingFeatures,
                     bool matchingInlineAsm, unsigned VariantID) {
  // Eliminate obvious mismatches.
  if (Operands.size() > 3) {
    ErrorInfo = 3;
    return Match_InvalidOperand;
  }

  // Get the current feature set.
  const FeatureBitset &AvailableFeatures = getAvailableFeatures();

  // Get the instruction mnemonic, which is the first token.
  StringRef Mnemonic = ((MSP430Operand &)*Operands[0]).getToken();

  // Some state to try to produce better error messages.
  bool HadMatchOtherThanFeatures = false;
  bool HadMatchOtherThanPredicate = false;
  unsigned RetCode = Match_InvalidOperand;
  MissingFeatures.set();
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

  DEBUG_WITH_TYPE("asm-matcher", dbgs() << "AsmMatcher: found " <<
  std::distance(MnemonicRange.first, MnemonicRange.second) <<
  " encodings with mnemonic '" << Mnemonic << "'\n");

  // Return a more specific error code if no mnemonics match.
  if (MnemonicRange.first == MnemonicRange.second)
    return Match_MnemonicFail;

  for (const MatchEntry *it = MnemonicRange.first, *ie = MnemonicRange.second;
       it != ie; ++it) {
    const FeatureBitset &RequiredFeatures = FeatureBitsets[it->RequiredFeaturesIdx];
    bool HasRequiredFeatures =
      (AvailableFeatures & RequiredFeatures) == RequiredFeatures;
    DEBUG_WITH_TYPE("asm-matcher", dbgs() << "Trying to match opcode "
                                          << MII.getName(it->Opcode) << "\n");
    // equal_range guarantees that instruction mnemonic matches.
    assert(Mnemonic == it->getMnemonic());
    bool OperandsValid = true;
    unsigned ActualIdx = 1;
    for (unsigned FormalIdx = 0; FormalIdx != 2; ++FormalIdx) {
      auto Formal = static_cast<MatchClassKind>(it->Classes[FormalIdx]);
      DEBUG_WITH_TYPE("asm-matcher",
                      dbgs() << "  Matching formal operand class " << getMatchClassName(Formal)
                             << " against actual operand at index " << ActualIdx);
      if (ActualIdx < Operands.size())
        DEBUG_WITH_TYPE("asm-matcher", dbgs() << " (";
                        Operands[ActualIdx]->print(dbgs(), getContext().getAsmInfo()); dbgs() << "): ");
      else
        DEBUG_WITH_TYPE("asm-matcher", dbgs() << ": ");
      if (ActualIdx >= Operands.size()) {
        DEBUG_WITH_TYPE("asm-matcher", dbgs() << "actual operand index out of range\n");
        if (Formal == InvalidMatchClass) {
          break;
        }
        if (isSubclass(Formal, OptionalMatchClass)) {
          continue;
        }
        OperandsValid = false;
        ErrorInfo = ActualIdx;
        break;
      }
      MCParsedAsmOperand &Actual = *Operands[ActualIdx];
      unsigned Diag = validateOperandClass(Actual, Formal, *STI);
      if (Diag == Match_Success) {
        DEBUG_WITH_TYPE("asm-matcher",
                        dbgs() << "match success using generic matcher\n");
        ++ActualIdx;
        continue;
      }
      // If the generic handler indicates an invalid operand
      // failure, check for a special case.
      if (Diag != Match_Success) {
        unsigned TargetDiag = validateTargetOperandClass(Actual, Formal);
        if (TargetDiag == Match_Success) {
          DEBUG_WITH_TYPE("asm-matcher",
                          dbgs() << "match success using target matcher\n");
          ++ActualIdx;
          continue;
        }
        // If the target matcher returned a specific error code use
        // that, else use the one from the generic matcher.
        if (TargetDiag != Match_InvalidOperand && HasRequiredFeatures)
          Diag = TargetDiag;
      }
      // If current formal operand wasn't matched and it is optional
      // then try to match next formal operand
      if (Diag == Match_InvalidOperand && isSubclass(Formal, OptionalMatchClass)) {
        DEBUG_WITH_TYPE("asm-matcher", dbgs() << "ignoring optional operand\n");
        continue;
      }
      // If this operand is broken for all of the instances of this
      // mnemonic, keep track of it so we can report loc info.
      // If we already had a match that only failed due to a
      // target predicate, that diagnostic is preferred.
      if (!HadMatchOtherThanPredicate &&
          (it == MnemonicRange.first || ErrorInfo <= ActualIdx)) {
        if (HasRequiredFeatures && (ErrorInfo != ActualIdx || Diag != Match_InvalidOperand))
          RetCode = Diag;
        ErrorInfo = ActualIdx;
      }
      // Otherwise, just reject this instance of the mnemonic.
      OperandsValid = false;
      break;
    }

    if (!OperandsValid) {
      DEBUG_WITH_TYPE("asm-matcher", dbgs() << "Opcode result: multiple "
                                               "operand mismatches, ignoring "
                                               "this opcode\n");
      continue;
    }
    if (!HasRequiredFeatures) {
      HadMatchOtherThanFeatures = true;
      FeatureBitset NewMissingFeatures = RequiredFeatures & ~AvailableFeatures;
      DEBUG_WITH_TYPE("asm-matcher", dbgs() << "Missing target features:";
                      for (unsigned I = 0, E = NewMissingFeatures.size(); I != E; ++I)
                        if (NewMissingFeatures[I])
                          dbgs() << ' ' << I;
                      dbgs() << "\n");
      if (NewMissingFeatures.count() <=
          MissingFeatures.count())
        MissingFeatures = NewMissingFeatures;
      continue;
    }

    Inst.clear();

    Inst.setOpcode(it->Opcode);
    // We have a potential match but have not rendered the operands.
    // Check the target predicate to handle any context sensitive
    // constraints.
    // For example, Ties that are referenced multiple times must be
    // checked here to ensure the input is the same for each match
    // constraints. If we leave it any later the ties will have been
    // canonicalized
    unsigned MatchResult;
    if ((MatchResult = checkEarlyTargetMatchPredicate(Inst, Operands)) != Match_Success) {
      Inst.clear();
      DEBUG_WITH_TYPE(
          "asm-matcher",
          dbgs() << "Early target match predicate failed with diag code "
                 << MatchResult << "\n");
      RetCode = MatchResult;
      HadMatchOtherThanPredicate = true;
      continue;
    }

    if (matchingInlineAsm) {
      convertToMapAndConstraints(it->ConvertFn, Operands);
      if (!checkAsmTiedOperandConstraints(*this, it->ConvertFn, Operands,
                                          ErrorInfo))
        return Match_InvalidTiedOperand;

      return Match_Success;
    }

    // We have selected a definite instruction, convert the parsed
    // operands into the appropriate MCInst.
    convertToMCInst(it->ConvertFn, Inst, it->Opcode, Operands);

    // We have a potential match. Check the target predicate to
    // handle any context sensitive constraints.
    if ((MatchResult = checkTargetMatchPredicate(Inst)) != Match_Success) {
      DEBUG_WITH_TYPE("asm-matcher",
                      dbgs() << "Target match predicate failed with diag code "
                             << MatchResult << "\n");
      Inst.clear();
      RetCode = MatchResult;
      HadMatchOtherThanPredicate = true;
      continue;
    }

    if (!checkAsmTiedOperandConstraints(*this, it->ConvertFn, Operands,
                                         ErrorInfo))
      return Match_InvalidTiedOperand;

    DEBUG_WITH_TYPE(
        "asm-matcher",
        dbgs() << "Opcode result: complete match, selecting this opcode\n");
    return Match_Success;
  }

  // Okay, we had no match.  Try to return a useful error code.
  if (HadMatchOtherThanPredicate || !HadMatchOtherThanFeatures)
    return RetCode;

  ErrorInfo = 0;
  return Match_MissingFeature;
}

#endif // GET_MATCHER_IMPLEMENTATION


#ifdef GET_MNEMONIC_SPELL_CHECKER
#undef GET_MNEMONIC_SPELL_CHECKER

static std::string MSP430MnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
  const unsigned MaxEditDist = 2;
  std::vector<StringRef> Candidates;
  StringRef Prev = "";

  // Find the appropriate table for this asm variant.
  const MatchEntry *Start, *End;
  switch (VariantID) {
  default: llvm_unreachable("invalid variant!");
  case 0: Start = std::begin(MatchTable0); End = std::end(MatchTable0); break;
  }

  for (auto I = Start; I < End; I++) {
    // Ignore unsupported instructions.
    const FeatureBitset &RequiredFeatures = FeatureBitsets[I->RequiredFeaturesIdx];
    if ((FBS & RequiredFeatures) != RequiredFeatures)
      continue;

    StringRef T = I->getMnemonic();
    // Avoid recomputing the edit distance for the same string.
    if (T == Prev)
      continue;

    Prev = T;
    unsigned Dist = S.edit_distance(T, false, MaxEditDist);
    if (Dist <= MaxEditDist)
      Candidates.push_back(T);
  }

  if (Candidates.empty())
    return "";

  std::string Res = ", did you mean: ";
  unsigned i = 0;
  for (; i < Candidates.size() - 1; i++)
    Res += Candidates[i].str() + ", ";
  return Res + Candidates[i].str() + "?";
}

#endif // GET_MNEMONIC_SPELL_CHECKER


#ifdef GET_MNEMONIC_CHECKER
#undef GET_MNEMONIC_CHECKER

static bool MSP430CheckMnemonic(StringRef Mnemonic,
                                const FeatureBitset &AvailableFeatures,
                                unsigned VariantID) {
  // Find the appropriate table for this asm variant.
  const MatchEntry *Start, *End;
  switch (VariantID) {
  default: llvm_unreachable("invalid variant!");
  case 0: Start = std::begin(MatchTable0); End = std::end(MatchTable0); break;
  }

  // Search the table.
  auto MnemonicRange = std::equal_range(Start, End, Mnemonic, LessOpcode());

  if (MnemonicRange.first == MnemonicRange.second)
    return false;

  for (const MatchEntry *it = MnemonicRange.first, *ie = MnemonicRange.second;
       it != ie; ++it) {
    const FeatureBitset &RequiredFeatures =
      FeatureBitsets[it->RequiredFeaturesIdx];
    if ((AvailableFeatures & RequiredFeatures) == RequiredFeatures)
      return true;
  }
  return false;
}

#endif // GET_MNEMONIC_CHECKER

