/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: Lanai.td                                                             *|
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

  ParseStatus MatchOperandParserImpl(
    OperandVector &Operands,
    StringRef Mnemonic,
    bool ParseForAllFeatures = false);
  ParseStatus tryCustomParseOperand(
    OperandVector &Operands,
    unsigned MCK);

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
  case 2:	 // 15 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 1 string to match.
      if (Name[1] != 'p')
        break;
      return Lanai::FP;	 // "fp"
    case 'p':	 // 1 string to match.
      if (Name[1] != 'c')
        break;
      return Lanai::PC;	 // "pc"
    case 'r':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return Lanai::R0;	 // "r0"
      case '1':	 // 1 string to match.
        return Lanai::R1;	 // "r1"
      case '2':	 // 1 string to match.
        return Lanai::R2;	 // "r2"
      case '3':	 // 1 string to match.
        return Lanai::R3;	 // "r3"
      case '4':	 // 1 string to match.
        return Lanai::R4;	 // "r4"
      case '5':	 // 1 string to match.
        return Lanai::R5;	 // "r5"
      case '6':	 // 1 string to match.
        return Lanai::R6;	 // "r6"
      case '7':	 // 1 string to match.
        return Lanai::R7;	 // "r7"
      case '8':	 // 1 string to match.
        return Lanai::R8;	 // "r8"
      case '9':	 // 1 string to match.
        return Lanai::R9;	 // "r9"
      case 'v':	 // 1 string to match.
        return Lanai::RV;	 // "rv"
      }
      break;
    case 's':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'p':	 // 1 string to match.
        return Lanai::SP;	 // "sp"
      case 'w':	 // 1 string to match.
        return Lanai::SR;	 // "sw"
      }
      break;
    }
    break;
  case 3:	 // 25 strings to match.
    if (Name[0] != 'r')
      break;
    switch (Name[1]) {
    default: break;
    case '1':	 // 10 strings to match.
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        return Lanai::R10;	 // "r10"
      case '1':	 // 1 string to match.
        return Lanai::R11;	 // "r11"
      case '2':	 // 1 string to match.
        return Lanai::R12;	 // "r12"
      case '3':	 // 1 string to match.
        return Lanai::R13;	 // "r13"
      case '4':	 // 1 string to match.
        return Lanai::R14;	 // "r14"
      case '5':	 // 1 string to match.
        return Lanai::R15;	 // "r15"
      case '6':	 // 1 string to match.
        return Lanai::R16;	 // "r16"
      case '7':	 // 1 string to match.
        return Lanai::R17;	 // "r17"
      case '8':	 // 1 string to match.
        return Lanai::R18;	 // "r18"
      case '9':	 // 1 string to match.
        return Lanai::R19;	 // "r19"
      }
      break;
    case '2':	 // 10 strings to match.
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        return Lanai::R20;	 // "r20"
      case '1':	 // 1 string to match.
        return Lanai::R21;	 // "r21"
      case '2':	 // 1 string to match.
        return Lanai::R22;	 // "r22"
      case '3':	 // 1 string to match.
        return Lanai::R23;	 // "r23"
      case '4':	 // 1 string to match.
        return Lanai::R24;	 // "r24"
      case '5':	 // 1 string to match.
        return Lanai::R25;	 // "r25"
      case '6':	 // 1 string to match.
        return Lanai::R26;	 // "r26"
      case '7':	 // 1 string to match.
        return Lanai::R27;	 // "r27"
      case '8':	 // 1 string to match.
        return Lanai::R28;	 // "r28"
      case '9':	 // 1 string to match.
        return Lanai::R29;	 // "r29"
      }
      break;
    case '3':	 // 2 strings to match.
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        return Lanai::R30;	 // "r30"
      case '1':	 // 1 string to match.
        return Lanai::R31;	 // "r31"
      }
      break;
    case 'c':	 // 1 string to match.
      if (Name[2] != 'a')
        break;
      return Lanai::RCA;	 // "rca"
    case 'r':	 // 2 strings to match.
      switch (Name[2]) {
      default: break;
      case '1':	 // 1 string to match.
        return Lanai::RR1;	 // "rr1"
      case '2':	 // 1 string to match.
        return Lanai::RR2;	 // "rr2"
      }
      break;
    }
    break;
  }
  return Lanai::NoRegister;
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

static const uint8_t TiedAsmOperandTable[][3] = { /* empty  */ {0, 0, 0} };

namespace {
enum OperatorConversionKind {
  CVT_Done,
  CVT_Reg,
  CVT_Tied,
  CVT_95_addImmOperands,
  CVT_95_Reg,
  CVT_95_addHiImm16Operands,
  CVT_95_addLoImm16Operands,
  CVT_95_addCondCodeOperands,
  CVT_95_addHiImm16AndOperands,
  CVT_95_addLoImm16AndOperands,
  CVT_95_addBrTargetOperands,
  CVT_95_addMemImmOperands,
  CVT_95_addMemRegImmOperands,
  CVT_95_addMemRegRegOperands,
  CVT_95_addMemSplsOperands,
  CVT_regR0,
  CVT_imm_95_0,
  CVT_regR1,
  CVT_95_addLoImm21Operands,
  CVT_95_addImmShiftOperands,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Imm1_0__Imm1_1,
  Convert__Reg1_0__Reg1_1,
  Convert__Reg1_2__Reg1_0__HiImm161_1,
  Convert__Reg1_2__Reg1_0__LoImm161_1,
  Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0,
  Convert__Reg1_2__Reg1_0__HiImm16And1_1,
  Convert__Reg1_2__Reg1_0__LoImm16And1_1,
  Convert__Reg1_1__Imm1_0,
  Convert__BrTarget1_1__Imm1_0,
  Convert__Imm1_2__Imm1_0,
  Convert__Reg1_1__Reg1_3__Imm1_0,
  Convert__Reg1_0,
  Convert__BrTarget1_0,
  Convert__Reg1_1__MemImm1_0,
  Convert__Reg1_1__MemRegImm3_0,
  Convert__Reg1_1__MemRegReg3_0,
  Convert_NoOperands,
  Convert__Reg1_1__MemSpls3_0,
  Convert__Reg1_1__Reg1_0,
  Convert__Reg1_1__Reg1_0__regR0__imm_95_0,
  Convert__Reg1_1__regR1__HiImm16And1_0,
  Convert__Reg1_1__regR0__HiImm161_0,
  Convert__Reg1_1__regR1__LoImm16And1_0,
  Convert__Reg1_1__regR0__LoImm161_0,
  Convert__Reg1_1__LoImm211_0,
  Convert__Reg1_3__Reg1_1__Reg1_2__Imm1_0,
  Convert__Reg1_2__Reg1_0__ImmShift1_1,
  Convert__Reg1_0__MemImm1_1,
  Convert__Reg1_0__MemRegImm3_1,
  Convert__Reg1_0__MemRegReg3_1,
  Convert__Reg1_0__MemSpls3_1,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][9] = {
  // Convert__Imm1_0__Imm1_1
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_2__Reg1_0__HiImm161_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addHiImm16Operands, 2, CVT_Done },
  // Convert__Reg1_2__Reg1_0__LoImm161_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addLoImm16Operands, 2, CVT_Done },
  // Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0
  { CVT_95_Reg, 4, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addCondCodeOperands, 1, CVT_Done },
  // Convert__Reg1_2__Reg1_0__HiImm16And1_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addHiImm16AndOperands, 2, CVT_Done },
  // Convert__Reg1_2__Reg1_0__LoImm16And1_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addLoImm16AndOperands, 2, CVT_Done },
  // Convert__Reg1_1__Imm1_0
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__BrTarget1_1__Imm1_0
  { CVT_95_addBrTargetOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Imm1_2__Imm1_0
  { CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_3__Imm1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__BrTarget1_0
  { CVT_95_addBrTargetOperands, 1, CVT_Done },
  // Convert__Reg1_1__MemImm1_0
  { CVT_95_Reg, 2, CVT_95_addMemImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__MemRegImm3_0
  { CVT_95_Reg, 2, CVT_95_addMemRegImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__MemRegReg3_0
  { CVT_95_Reg, 2, CVT_95_addMemRegRegOperands, 1, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__Reg1_1__MemSpls3_0
  { CVT_95_Reg, 2, CVT_95_addMemSplsOperands, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_0__regR0__imm_95_0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_regR0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_1__regR1__HiImm16And1_0
  { CVT_95_Reg, 2, CVT_regR1, 0, CVT_95_addHiImm16AndOperands, 1, CVT_Done },
  // Convert__Reg1_1__regR0__HiImm161_0
  { CVT_95_Reg, 2, CVT_regR0, 0, CVT_95_addHiImm16Operands, 1, CVT_Done },
  // Convert__Reg1_1__regR1__LoImm16And1_0
  { CVT_95_Reg, 2, CVT_regR1, 0, CVT_95_addLoImm16AndOperands, 1, CVT_Done },
  // Convert__Reg1_1__regR0__LoImm161_0
  { CVT_95_Reg, 2, CVT_regR0, 0, CVT_95_addLoImm16Operands, 1, CVT_Done },
  // Convert__Reg1_1__LoImm211_0
  { CVT_95_Reg, 2, CVT_95_addLoImm21Operands, 1, CVT_Done },
  // Convert__Reg1_3__Reg1_1__Reg1_2__Imm1_0
  { CVT_95_Reg, 4, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_2__Reg1_0__ImmShift1_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmShiftOperands, 2, CVT_Done },
  // Convert__Reg1_0__MemImm1_1
  { CVT_95_Reg, 1, CVT_95_addMemImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__MemRegImm3_1
  { CVT_95_Reg, 1, CVT_95_addMemRegImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__MemRegReg3_1
  { CVT_95_Reg, 1, CVT_95_addMemRegRegOperands, 2, CVT_Done },
  // Convert__Reg1_0__MemSpls3_1
  { CVT_95_Reg, 1, CVT_95_addMemSplsOperands, 2, CVT_Done },
};

void LanaiAsmParser::
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
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
    case CVT_95_addImmOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_Reg:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addHiImm16Operands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addHiImm16Operands(Inst, 1);
      break;
    case CVT_95_addLoImm16Operands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addLoImm16Operands(Inst, 1);
      break;
    case CVT_95_addCondCodeOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addCondCodeOperands(Inst, 1);
      break;
    case CVT_95_addHiImm16AndOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addHiImm16AndOperands(Inst, 1);
      break;
    case CVT_95_addLoImm16AndOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addLoImm16AndOperands(Inst, 1);
      break;
    case CVT_95_addBrTargetOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addBrTargetOperands(Inst, 1);
      break;
    case CVT_95_addMemImmOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addMemImmOperands(Inst, 1);
      break;
    case CVT_95_addMemRegImmOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addMemRegImmOperands(Inst, 3);
      break;
    case CVT_95_addMemRegRegOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addMemRegRegOperands(Inst, 3);
      break;
    case CVT_95_addMemSplsOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addMemSplsOperands(Inst, 3);
      break;
    case CVT_regR0:
      Inst.addOperand(MCOperand::createReg(Lanai::R0));
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_regR1:
      Inst.addOperand(MCOperand::createReg(Lanai::R1));
      break;
    case CVT_95_addLoImm21Operands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addLoImm21Operands(Inst, 1);
      break;
    case CVT_95_addImmShiftOperands:
      static_cast<LanaiOperand &>(*Operands[OpIdx]).addImmShiftOperands(Inst, 1);
      break;
    }
  }
}

void LanaiAsmParser::
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
    case CVT_95_addImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_Reg:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("r");
      NumMCOperands += 1;
      break;
    case CVT_95_addHiImm16Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addLoImm16Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addCondCodeOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addHiImm16AndOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addLoImm16AndOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addBrTargetOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addMemImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addMemRegImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 3;
      break;
    case CVT_95_addMemRegRegOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 3;
      break;
    case CVT_95_addMemSplsOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 3;
      break;
    case CVT_regR0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_imm_95_0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_regR1:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addLoImm21Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addImmShiftOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
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
  MCK__EXCLAIM_, // '!'
  MCK__PCT_fp, // '%fp'
  MCK__PCT_pc, // '%pc'
  MCK__MINUS_4, // '-4'
  MCK__DOT_r, // '.r'
  MCK__91_, // '['
  MCK__93_, // ']'
  MCK_add, // 'add'
  MCK_return, // 'return'
  MCK_LAST_TOKEN = MCK_return,
  MCK_CCR, // register class 'CCR'
  MCK_Reg1, // derived register class
  MCK_GPR, // register class 'GPR'
  MCK_LAST_REGISTER = MCK_GPR,
  MCK_BrTarget, // user defined class 'BrTargetAsmOperand'
  MCK_CallTarget, // user defined class 'CallTargetAsmOperand'
  MCK_CondCode, // user defined class 'CondCodeOperand'
  MCK_HiImm16And, // user defined class 'HiImm16AndAsmOperand'
  MCK_HiImm16, // user defined class 'HiImm16AsmOperand'
  MCK_Imm10, // user defined class 'Imm10AsmOperand'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_ImmShift, // user defined class 'ImmShiftAsmOperand'
  MCK_LoImm16And, // user defined class 'LoImm16AndAsmOperand'
  MCK_LoImm16, // user defined class 'LoImm16AsmOperand'
  MCK_LoImm21, // user defined class 'LoImm21AsmOperand'
  MCK_MemImm, // user defined class 'MemImmAsmOperand'
  MCK_MemRegImm, // user defined class 'MemRegImmAsmOperand'
  MCK_MemRegReg, // user defined class 'MemRegRegAsmOperand'
  MCK_MemSpls, // user defined class 'MemSplsAsmOperand'
  NumMatchClassKinds
};

} // end anonymous namespace

static unsigned getDiagKindFromRegisterClass(MatchClassKind RegisterClass) {
  return MCTargetAsmParser::Match_InvalidOperand;
}

static MatchClassKind matchTokenString(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 3 strings to match.
    switch (Name[0]) {
    default: break;
    case '!':	 // 1 string to match.
      return MCK__EXCLAIM_;	 // "!"
    case '[':	 // 1 string to match.
      return MCK__91_;	 // "["
    case ']':	 // 1 string to match.
      return MCK__93_;	 // "]"
    }
    break;
  case 2:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case '-':	 // 1 string to match.
      if (Name[1] != '4')
        break;
      return MCK__MINUS_4;	 // "-4"
    case '.':	 // 1 string to match.
      if (Name[1] != 'r')
        break;
      return MCK__DOT_r;	 // ".r"
    }
    break;
  case 3:	 // 3 strings to match.
    switch (Name[0]) {
    default: break;
    case '%':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'f':	 // 1 string to match.
        if (Name[2] != 'p')
          break;
        return MCK__PCT_fp;	 // "%fp"
      case 'p':	 // 1 string to match.
        if (Name[2] != 'c')
          break;
        return MCK__PCT_pc;	 // "%pc"
      }
      break;
    case 'a':	 // 1 string to match.
      if (memcmp(Name.data()+1, "dd", 2) != 0)
        break;
      return MCK_add;	 // "add"
    }
    break;
  case 6:	 // 1 string to match.
    if (memcmp(Name.data()+0, "return", 6) != 0)
      break;
    return MCK_return;	 // "return"
  }
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
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 13, 1},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
    {1, 0, 0},
  };

  static constexpr uint8_t Data[] = {
    0x01,
  };

  auto &Entry = Table[A];
  unsigned Idx = B - Entry.Start;
  if (Idx >= Entry.Length)
    return false;
  Idx += Entry.Offset;
  return (Data[Idx / 8] >> (Idx % 8)) & 1;
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind, const MCSubtargetInfo &STI) {
  LanaiOperand &Operand = (LanaiOperand &)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  case MCK_BrTarget: {
    DiagnosticPredicate DP(Operand.isBrTarget());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_CallTarget: {
    DiagnosticPredicate DP(Operand.isCallTarget());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_CondCode: {
    DiagnosticPredicate DP(Operand.isCondCode());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_HiImm16And: {
    DiagnosticPredicate DP(Operand.isHiImm16And());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_HiImm16: {
    DiagnosticPredicate DP(Operand.isHiImm16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Imm10: {
    DiagnosticPredicate DP(Operand.isImm10());
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
  case MCK_ImmShift: {
    DiagnosticPredicate DP(Operand.isImmShift());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_LoImm16And: {
    DiagnosticPredicate DP(Operand.isLoImm16And());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_LoImm16: {
    DiagnosticPredicate DP(Operand.isLoImm16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_LoImm21: {
    DiagnosticPredicate DP(Operand.isLoImm21());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MemImm: {
    DiagnosticPredicate DP(Operand.isMemImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MemRegImm: {
    DiagnosticPredicate DP(Operand.isMemRegImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MemRegReg: {
    DiagnosticPredicate DP(Operand.isMemRegReg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MemSpls: {
    DiagnosticPredicate DP(Operand.isMemSpls());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg()) {
    static constexpr uint16_t Table[Lanai::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      MCK_Reg1,
      MCK_Reg1,
      MCK_Reg1,
      MCK_Reg1,
      MCK_Reg1,
      MCK_CCR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_GPR,
      MCK_Reg1,
      MCK_Reg1,
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
  case MCK__EXCLAIM_: return "MCK__EXCLAIM_";
  case MCK__PCT_fp: return "MCK__PCT_fp";
  case MCK__PCT_pc: return "MCK__PCT_pc";
  case MCK__MINUS_4: return "MCK__MINUS_4";
  case MCK__DOT_r: return "MCK__DOT_r";
  case MCK__91_: return "MCK__91_";
  case MCK__93_: return "MCK__93_";
  case MCK_add: return "MCK_add";
  case MCK_return: return "MCK_return";
  case MCK_CCR: return "MCK_CCR";
  case MCK_Reg1: return "MCK_Reg1";
  case MCK_GPR: return "MCK_GPR";
  case MCK_BrTarget: return "MCK_BrTarget";
  case MCK_CallTarget: return "MCK_CallTarget";
  case MCK_CondCode: return "MCK_CondCode";
  case MCK_HiImm16And: return "MCK_HiImm16And";
  case MCK_HiImm16: return "MCK_HiImm16";
  case MCK_Imm10: return "MCK_Imm10";
  case MCK_Imm: return "MCK_Imm";
  case MCK_ImmShift: return "MCK_ImmShift";
  case MCK_LoImm16And: return "MCK_LoImm16And";
  case MCK_LoImm16: return "MCK_LoImm16";
  case MCK_LoImm21: return "MCK_LoImm21";
  case MCK_MemImm: return "MCK_MemImm";
  case MCK_MemRegImm: return "MCK_MemRegImm";
  case MCK_MemRegReg: return "MCK_MemRegReg";
  case MCK_MemSpls: return "MCK_MemSpls";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset LanaiAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  return Features;
}

static bool checkAsmTiedOperandConstraints(const LanaiAsmParser&AsmParser,
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
    "\021#adjcallstackdown\017#adjcallstackup\014#adjdynalloc\003add\005add."
    "f\004addc\006addc.f\003and\005and.f\001b\002bt\002ld\004ld.b\004ld.h\005"
    "leadz\005log_0\005log_1\005log_2\005log_3\005log_4\003mov\003nop\002or\004"
    "or.f\004popc\001s\004sel.\002sh\004sh.f\003sha\005sha.f\002st\004st.b\004"
    "st.h\003sub\005sub.f\004subb\006subb.f\006trailz\003uld\005uld.b\005uld"
    ".h\003xor\005xor.f";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
};

namespace {
  struct MatchEntry {
    uint8_t Mnemonic;
    uint32_t Opcode;
    uint8_t ConvertFn;
    uint8_t RequiredFeaturesIdx;
    uint8_t Classes[7];
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
  { 0 /* #ADJCALLSTACKDOWN */, Lanai::ADJCALLSTACKDOWN, Convert__Imm1_0__Imm1_1, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 18 /* #ADJCALLSTACKUP */, Lanai::ADJCALLSTACKUP, Convert__Imm1_0__Imm1_1, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 34 /* #ADJDYNALLOC */, Lanai::ADJDYNALLOC, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 47 /* add */, Lanai::ADD_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 47 /* add */, Lanai::ADD_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 47 /* add */, Lanai::ADD_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 51 /* add.f */, Lanai::ADD_F_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 51 /* add.f */, Lanai::ADD_F_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 51 /* add.f */, Lanai::ADD_F_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 57 /* addc */, Lanai::ADDC_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 57 /* addc */, Lanai::ADDC_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 57 /* addc */, Lanai::ADDC_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 62 /* addc.f */, Lanai::ADDC_F_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 62 /* addc.f */, Lanai::ADDC_F_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 62 /* addc.f */, Lanai::ADDC_F_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 69 /* and */, Lanai::AND_I_HI, Convert__Reg1_2__Reg1_0__HiImm16And1_1, AMFBS_None, { MCK_GPR, MCK_HiImm16And, MCK_GPR }, },
  { 69 /* and */, Lanai::AND_I_LO, Convert__Reg1_2__Reg1_0__LoImm16And1_1, AMFBS_None, { MCK_GPR, MCK_LoImm16And, MCK_GPR }, },
  { 69 /* and */, Lanai::AND_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 73 /* and.f */, Lanai::AND_F_I_HI, Convert__Reg1_2__Reg1_0__HiImm16And1_1, AMFBS_None, { MCK_GPR, MCK_HiImm16And, MCK_GPR }, },
  { 73 /* and.f */, Lanai::AND_F_I_LO, Convert__Reg1_2__Reg1_0__LoImm16And1_1, AMFBS_None, { MCK_GPR, MCK_LoImm16And, MCK_GPR }, },
  { 73 /* and.f */, Lanai::AND_F_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 79 /* b */, Lanai::BRIND_CC, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GPR }, },
  { 79 /* b */, Lanai::BRCC, Convert__BrTarget1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_BrTarget }, },
  { 79 /* b */, Lanai::BRR, Convert__Imm1_2__Imm1_0, AMFBS_None, { MCK_Imm, MCK__DOT_r, MCK_Imm }, },
  { 79 /* b */, Lanai::BRIND_CCA, Convert__Reg1_1__Reg1_3__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GPR, MCK_add, MCK_GPR }, },
  { 81 /* bt */, Lanai::JR, Convert__Reg1_0, AMFBS_None, { MCK_GPR }, },
  { 81 /* bt */, Lanai::BT, Convert__BrTarget1_0, AMFBS_None, { MCK_BrTarget }, },
  { 84 /* ld */, Lanai::LDADDR, Convert__Reg1_1__MemImm1_0, AMFBS_None, { MCK_MemImm, MCK_GPR }, },
  { 84 /* ld */, Lanai::LDW_RI, Convert__Reg1_1__MemRegImm3_0, AMFBS_None, { MCK_MemRegImm, MCK_GPR }, },
  { 84 /* ld */, Lanai::LDW_RR, Convert__Reg1_1__MemRegReg3_0, AMFBS_None, { MCK_MemRegReg, MCK_GPR }, },
  { 84 /* ld */, Lanai::RET, Convert_NoOperands, AMFBS_None, { MCK__MINUS_4, MCK__91_, MCK__PCT_fp, MCK__93_, MCK__PCT_pc, MCK__EXCLAIM_, MCK_return }, },
  { 87 /* ld.b */, Lanai::LDBs_RR, Convert__Reg1_1__MemRegReg3_0, AMFBS_None, { MCK_MemRegReg, MCK_GPR }, },
  { 87 /* ld.b */, Lanai::LDBs_RI, Convert__Reg1_1__MemSpls3_0, AMFBS_None, { MCK_MemSpls, MCK_GPR }, },
  { 92 /* ld.h */, Lanai::LDHs_RR, Convert__Reg1_1__MemRegReg3_0, AMFBS_None, { MCK_MemRegReg, MCK_GPR }, },
  { 92 /* ld.h */, Lanai::LDHs_RI, Convert__Reg1_1__MemSpls3_0, AMFBS_None, { MCK_MemSpls, MCK_GPR }, },
  { 97 /* leadz */, Lanai::LEADZ, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 103 /* log_0 */, Lanai::LOG0, Convert_NoOperands, AMFBS_None, {  }, },
  { 109 /* log_1 */, Lanai::LOG1, Convert_NoOperands, AMFBS_None, {  }, },
  { 115 /* log_2 */, Lanai::LOG2, Convert_NoOperands, AMFBS_None, {  }, },
  { 121 /* log_3 */, Lanai::LOG3, Convert_NoOperands, AMFBS_None, {  }, },
  { 127 /* log_4 */, Lanai::LOG4, Convert_NoOperands, AMFBS_None, {  }, },
  { 133 /* mov */, Lanai::ADD_R, Convert__Reg1_1__Reg1_0__regR0__imm_95_0, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 133 /* mov */, Lanai::AND_I_HI, Convert__Reg1_1__regR1__HiImm16And1_0, AMFBS_None, { MCK_HiImm16And, MCK_GPR }, },
  { 133 /* mov */, Lanai::ADD_I_HI, Convert__Reg1_1__regR0__HiImm161_0, AMFBS_None, { MCK_HiImm16, MCK_GPR }, },
  { 133 /* mov */, Lanai::AND_I_LO, Convert__Reg1_1__regR1__LoImm16And1_0, AMFBS_None, { MCK_LoImm16And, MCK_GPR }, },
  { 133 /* mov */, Lanai::ADD_I_LO, Convert__Reg1_1__regR0__LoImm161_0, AMFBS_None, { MCK_LoImm16, MCK_GPR }, },
  { 133 /* mov */, Lanai::SLI, Convert__Reg1_1__LoImm211_0, AMFBS_None, { MCK_LoImm21, MCK_GPR }, },
  { 137 /* nop */, Lanai::NOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 141 /* or */, Lanai::OR_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 141 /* or */, Lanai::OR_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 141 /* or */, Lanai::OR_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 144 /* or.f */, Lanai::OR_F_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 144 /* or.f */, Lanai::OR_F_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 144 /* or.f */, Lanai::OR_F_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 149 /* popc */, Lanai::POPC, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 154 /* s */, Lanai::SCC, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GPR }, },
  { 156 /* sel. */, Lanai::SELECT, Convert__Reg1_3__Reg1_1__Reg1_2__Imm1_0, AMFBS_None, { MCK_Imm, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 161 /* sh */, Lanai::SL_I, Convert__Reg1_2__Reg1_0__ImmShift1_1, AMFBS_None, { MCK_GPR, MCK_ImmShift, MCK_GPR }, },
  { 161 /* sh */, Lanai::SHL_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 164 /* sh.f */, Lanai::SL_F_I, Convert__Reg1_2__Reg1_0__ImmShift1_1, AMFBS_None, { MCK_GPR, MCK_ImmShift, MCK_GPR }, },
  { 164 /* sh.f */, Lanai::SHL_F_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 169 /* sha */, Lanai::SA_I, Convert__Reg1_2__Reg1_0__ImmShift1_1, AMFBS_None, { MCK_GPR, MCK_ImmShift, MCK_GPR }, },
  { 169 /* sha */, Lanai::SRA_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 173 /* sha.f */, Lanai::SA_F_I, Convert__Reg1_2__Reg1_0__ImmShift1_1, AMFBS_None, { MCK_GPR, MCK_ImmShift, MCK_GPR }, },
  { 173 /* sha.f */, Lanai::SRA_F_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 179 /* st */, Lanai::STADDR, Convert__Reg1_0__MemImm1_1, AMFBS_None, { MCK_GPR, MCK_MemImm }, },
  { 179 /* st */, Lanai::SW_RI, Convert__Reg1_0__MemRegImm3_1, AMFBS_None, { MCK_GPR, MCK_MemRegImm }, },
  { 179 /* st */, Lanai::SW_RR, Convert__Reg1_0__MemRegReg3_1, AMFBS_None, { MCK_GPR, MCK_MemRegReg }, },
  { 182 /* st.b */, Lanai::STB_RR, Convert__Reg1_0__MemRegReg3_1, AMFBS_None, { MCK_GPR, MCK_MemRegReg }, },
  { 182 /* st.b */, Lanai::STB_RI, Convert__Reg1_0__MemSpls3_1, AMFBS_None, { MCK_GPR, MCK_MemSpls }, },
  { 187 /* st.h */, Lanai::STH_RR, Convert__Reg1_0__MemRegReg3_1, AMFBS_None, { MCK_GPR, MCK_MemRegReg }, },
  { 187 /* st.h */, Lanai::STH_RI, Convert__Reg1_0__MemSpls3_1, AMFBS_None, { MCK_GPR, MCK_MemSpls }, },
  { 192 /* sub */, Lanai::SUB_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 192 /* sub */, Lanai::SUB_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 192 /* sub */, Lanai::SUB_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 196 /* sub.f */, Lanai::SUB_F_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 196 /* sub.f */, Lanai::SUB_F_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 196 /* sub.f */, Lanai::SUB_F_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 202 /* subb */, Lanai::SUBB_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 202 /* subb */, Lanai::SUBB_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 202 /* subb */, Lanai::SUBB_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 207 /* subb.f */, Lanai::SUBB_F_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 207 /* subb.f */, Lanai::SUBB_F_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 207 /* subb.f */, Lanai::SUBB_F_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 214 /* trailz */, Lanai::TRAILZ, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 221 /* uld */, Lanai::LDW_RI, Convert__Reg1_1__MemRegImm3_0, AMFBS_None, { MCK_MemRegImm, MCK_GPR }, },
  { 221 /* uld */, Lanai::LDWz_RR, Convert__Reg1_1__MemRegReg3_0, AMFBS_None, { MCK_MemRegReg, MCK_GPR }, },
  { 225 /* uld.b */, Lanai::LDBz_RR, Convert__Reg1_1__MemRegReg3_0, AMFBS_None, { MCK_MemRegReg, MCK_GPR }, },
  { 225 /* uld.b */, Lanai::LDBz_RI, Convert__Reg1_1__MemSpls3_0, AMFBS_None, { MCK_MemSpls, MCK_GPR }, },
  { 231 /* uld.h */, Lanai::LDHz_RR, Convert__Reg1_1__MemRegReg3_0, AMFBS_None, { MCK_MemRegReg, MCK_GPR }, },
  { 231 /* uld.h */, Lanai::LDHz_RI, Convert__Reg1_1__MemSpls3_0, AMFBS_None, { MCK_MemSpls, MCK_GPR }, },
  { 237 /* xor */, Lanai::XOR_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 237 /* xor */, Lanai::XOR_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 237 /* xor */, Lanai::XOR_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 241 /* xor.f */, Lanai::XOR_F_I_HI, Convert__Reg1_2__Reg1_0__HiImm161_1, AMFBS_None, { MCK_GPR, MCK_HiImm16, MCK_GPR }, },
  { 241 /* xor.f */, Lanai::XOR_F_I_LO, Convert__Reg1_2__Reg1_0__LoImm161_1, AMFBS_None, { MCK_GPR, MCK_LoImm16, MCK_GPR }, },
  { 241 /* xor.f */, Lanai::XOR_F_R, Convert__Reg1_3__Reg1_1__Reg1_2__CondCode1_0, AMFBS_None, { MCK_CondCode, MCK_GPR, MCK_GPR, MCK_GPR }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned LanaiAsmParser::
MatchInstructionImpl(const OperandVector &Operands,
                     MCInst &Inst,
                     uint64_t &ErrorInfo,
                     FeatureBitset &MissingFeatures,
                     bool matchingInlineAsm, unsigned VariantID) {
  // Eliminate obvious mismatches.
  if (Operands.size() > 8) {
    ErrorInfo = 8;
    return Match_InvalidOperand;
  }

  // Get the current feature set.
  const FeatureBitset &AvailableFeatures = getAvailableFeatures();

  // Get the instruction mnemonic, which is the first token.
  StringRef Mnemonic = ((LanaiOperand &)*Operands[0]).getToken();

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
    for (unsigned FormalIdx = 0; FormalIdx != 7; ++FormalIdx) {
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

namespace {
  struct OperandMatchEntry {
    uint8_t Mnemonic;
    uint8_t OperandMask;
    uint8_t Class;
    uint8_t RequiredFeaturesIdx;

    StringRef getMnemonic() const {
      return StringRef(MnemonicTable + Mnemonic + 1,
                       MnemonicTable[Mnemonic]);
    }
  };

  // Predicate for searching for an opcode.
  struct LessOpcodeOperand {
    bool operator()(const OperandMatchEntry &LHS, StringRef RHS) {
      return LHS.getMnemonic()  < RHS;
    }
    bool operator()(StringRef LHS, const OperandMatchEntry &RHS) {
      return LHS < RHS.getMnemonic();
    }
    bool operator()(const OperandMatchEntry &LHS, const OperandMatchEntry &RHS) {
      return LHS.getMnemonic() < RHS.getMnemonic();
    }
  };
} // end anonymous namespace

static const OperandMatchEntry OperandMatchTable[20] = {
  /* Operand List Mnemonic, Mask, Operand Class, Features */
  { 84 /* ld */, 1 /* 0 */, MCK_MemImm, AMFBS_None },
  { 84 /* ld */, 1 /* 0 */, MCK_MemRegImm, AMFBS_None },
  { 84 /* ld */, 1 /* 0 */, MCK_MemRegReg, AMFBS_None },
  { 87 /* ld.b */, 1 /* 0 */, MCK_MemRegReg, AMFBS_None },
  { 87 /* ld.b */, 1 /* 0 */, MCK_MemSpls, AMFBS_None },
  { 92 /* ld.h */, 1 /* 0 */, MCK_MemRegReg, AMFBS_None },
  { 92 /* ld.h */, 1 /* 0 */, MCK_MemSpls, AMFBS_None },
  { 179 /* st */, 2 /* 1 */, MCK_MemImm, AMFBS_None },
  { 179 /* st */, 2 /* 1 */, MCK_MemRegImm, AMFBS_None },
  { 179 /* st */, 2 /* 1 */, MCK_MemRegReg, AMFBS_None },
  { 182 /* st.b */, 2 /* 1 */, MCK_MemRegReg, AMFBS_None },
  { 182 /* st.b */, 2 /* 1 */, MCK_MemSpls, AMFBS_None },
  { 187 /* st.h */, 2 /* 1 */, MCK_MemRegReg, AMFBS_None },
  { 187 /* st.h */, 2 /* 1 */, MCK_MemSpls, AMFBS_None },
  { 221 /* uld */, 1 /* 0 */, MCK_MemRegImm, AMFBS_None },
  { 221 /* uld */, 1 /* 0 */, MCK_MemRegReg, AMFBS_None },
  { 225 /* uld.b */, 1 /* 0 */, MCK_MemRegReg, AMFBS_None },
  { 225 /* uld.b */, 1 /* 0 */, MCK_MemSpls, AMFBS_None },
  { 231 /* uld.h */, 1 /* 0 */, MCK_MemRegReg, AMFBS_None },
  { 231 /* uld.h */, 1 /* 0 */, MCK_MemSpls, AMFBS_None },
};

ParseStatus LanaiAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_MemImm:
    return parseMemoryOperand(Operands);
  case MCK_MemRegImm:
    return parseMemoryOperand(Operands);
  case MCK_MemRegReg:
    return parseMemoryOperand(Operands);
  case MCK_MemSpls:
    return parseMemoryOperand(Operands);
  default:
    return ParseStatus::NoMatch;
  }
  return ParseStatus::NoMatch;
}

ParseStatus LanaiAsmParser::
MatchOperandParserImpl(OperandVector &Operands,
                       StringRef Mnemonic,
                       bool ParseForAllFeatures) {
  // Get the current feature set.
  const FeatureBitset &AvailableFeatures = getAvailableFeatures();

  // Get the next operand index.
  unsigned NextOpNum = Operands.size() - 1;
  // Search the table.
  auto MnemonicRange =
    std::equal_range(std::begin(OperandMatchTable), std::end(OperandMatchTable),
                     Mnemonic, LessOpcodeOperand());

  if (MnemonicRange.first == MnemonicRange.second)
    return ParseStatus::NoMatch;

  for (const OperandMatchEntry *it = MnemonicRange.first,
       *ie = MnemonicRange.second; it != ie; ++it) {
    // equal_range guarantees that instruction mnemonic matches.
    assert(Mnemonic == it->getMnemonic());

    // check if the available features match
    const FeatureBitset &RequiredFeatures = FeatureBitsets[it->RequiredFeaturesIdx];
    if (!ParseForAllFeatures && (AvailableFeatures & RequiredFeatures) != RequiredFeatures)
      continue;

    // check if the operand in question has a custom parser.
    if (!(it->OperandMask & (1 << NextOpNum)))
      continue;

    // call custom parse method to handle the operand
    ParseStatus Result = tryCustomParseOperand(Operands, it->Class);
    if (!Result.isNoMatch())
      return Result;
  }

  // Okay, we had no match.
  return ParseStatus::NoMatch;
}

#endif // GET_MATCHER_IMPLEMENTATION


#ifdef GET_MNEMONIC_SPELL_CHECKER
#undef GET_MNEMONIC_SPELL_CHECKER

static std::string LanaiMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool LanaiCheckMnemonic(StringRef Mnemonic,
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

