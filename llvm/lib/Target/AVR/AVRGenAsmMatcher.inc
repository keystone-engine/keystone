/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: AVR.td                                                               *|
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
  Feature_HasSRAMBit = 14,
  Feature_HasJMPCALLBit = 7,
  Feature_HasIJMPCALLBit = 6,
  Feature_HasEIJMPCALLBit = 3,
  Feature_HasADDSUBIWBit = 0,
  Feature_HasSmallStackBit = 15,
  Feature_HasMOVWBit = 10,
  Feature_HasLPMBit = 8,
  Feature_HasLPMXBit = 9,
  Feature_HasELPMBit = 4,
  Feature_HasELPMXBit = 5,
  Feature_HasSPMBit = 12,
  Feature_HasSPMXBit = 13,
  Feature_HasDESBit = 2,
  Feature_SupportsRMWBit = 18,
  Feature_SupportsMultiplicationBit = 17,
  Feature_HasBREAKBit = 1,
  Feature_HasTinyEncodingBit = 16,
  Feature_HasNonTinyEncodingBit = 11,
};

static MCRegister MatchRegisterName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 11 strings to match.
    switch (Name[0]) {
    default: break;
    case 'S':	 // 1 string to match.
      if (Name[1] != 'P')
        break;
      return AVR::SP;	 // "SP"
    case 'r':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return AVR::R0;	 // "r0"
      case '1':	 // 1 string to match.
        return AVR::R1;	 // "r1"
      case '2':	 // 1 string to match.
        return AVR::R2;	 // "r2"
      case '3':	 // 1 string to match.
        return AVR::R3;	 // "r3"
      case '4':	 // 1 string to match.
        return AVR::R4;	 // "r4"
      case '5':	 // 1 string to match.
        return AVR::R5;	 // "r5"
      case '6':	 // 1 string to match.
        return AVR::R6;	 // "r6"
      case '7':	 // 1 string to match.
        return AVR::R7;	 // "r7"
      case '8':	 // 1 string to match.
        return AVR::R8;	 // "r8"
      case '9':	 // 1 string to match.
        return AVR::R9;	 // "r9"
      }
      break;
    }
    break;
  case 3:	 // 24 strings to match.
    switch (Name[0]) {
    default: break;
    case 'S':	 // 2 strings to match.
      if (Name[1] != 'P')
        break;
      switch (Name[2]) {
      default: break;
      case 'H':	 // 1 string to match.
        return AVR::SPH;	 // "SPH"
      case 'L':	 // 1 string to match.
        return AVR::SPL;	 // "SPL"
      }
      break;
    case 'r':	 // 22 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return AVR::R10;	 // "r10"
        case '1':	 // 1 string to match.
          return AVR::R11;	 // "r11"
        case '2':	 // 1 string to match.
          return AVR::R12;	 // "r12"
        case '3':	 // 1 string to match.
          return AVR::R13;	 // "r13"
        case '4':	 // 1 string to match.
          return AVR::R14;	 // "r14"
        case '5':	 // 1 string to match.
          return AVR::R15;	 // "r15"
        case '6':	 // 1 string to match.
          return AVR::R16;	 // "r16"
        case '7':	 // 1 string to match.
          return AVR::R17;	 // "r17"
        case '8':	 // 1 string to match.
          return AVR::R18;	 // "r18"
        case '9':	 // 1 string to match.
          return AVR::R19;	 // "r19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return AVR::R20;	 // "r20"
        case '1':	 // 1 string to match.
          return AVR::R21;	 // "r21"
        case '2':	 // 1 string to match.
          return AVR::R22;	 // "r22"
        case '3':	 // 1 string to match.
          return AVR::R23;	 // "r23"
        case '4':	 // 1 string to match.
          return AVR::R24;	 // "r24"
        case '5':	 // 1 string to match.
          return AVR::R25;	 // "r25"
        case '6':	 // 1 string to match.
          return AVR::R26;	 // "r26"
        case '7':	 // 1 string to match.
          return AVR::R27;	 // "r27"
        case '8':	 // 1 string to match.
          return AVR::R28;	 // "r28"
        case '9':	 // 1 string to match.
          return AVR::R29;	 // "r29"
        }
        break;
      case '3':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return AVR::R30;	 // "r30"
        case '1':	 // 1 string to match.
          return AVR::R31;	 // "r31"
        }
        break;
      }
      break;
    }
    break;
  case 5:	 // 6 strings to match.
    switch (Name[0]) {
    default: break;
    case 'F':	 // 1 string to match.
      if (memcmp(Name.data()+1, "LAGS", 4) != 0)
        break;
      return AVR::SREG;	 // "FLAGS"
    case 'r':	 // 5 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 1 string to match.
        if (memcmp(Name.data()+2, ":r0", 3) != 0)
          break;
        return AVR::R1R0;	 // "r1:r0"
      case '3':	 // 1 string to match.
        if (memcmp(Name.data()+2, ":r2", 3) != 0)
          break;
        return AVR::R3R2;	 // "r3:r2"
      case '5':	 // 1 string to match.
        if (memcmp(Name.data()+2, ":r4", 3) != 0)
          break;
        return AVR::R5R4;	 // "r5:r4"
      case '7':	 // 1 string to match.
        if (memcmp(Name.data()+2, ":r6", 3) != 0)
          break;
        return AVR::R7R6;	 // "r7:r6"
      case '9':	 // 1 string to match.
        if (memcmp(Name.data()+2, ":r8", 3) != 0)
          break;
        return AVR::R9R8;	 // "r9:r8"
      }
      break;
    }
    break;
  case 6:	 // 1 string to match.
    if (memcmp(Name.data()+0, "r10:r9", 6) != 0)
      break;
    return AVR::R10R9;	 // "r10:r9"
  case 7:	 // 19 strings to match.
    if (Name[0] != 'r')
      break;
    switch (Name[1]) {
    default: break;
    case '1':	 // 9 strings to match.
      switch (Name[2]) {
      default: break;
      case '1':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r10", 4) != 0)
          break;
        return AVR::R11R10;	 // "r11:r10"
      case '2':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r11", 4) != 0)
          break;
        return AVR::R12R11;	 // "r12:r11"
      case '3':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r12", 4) != 0)
          break;
        return AVR::R13R12;	 // "r13:r12"
      case '4':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r13", 4) != 0)
          break;
        return AVR::R14R13;	 // "r14:r13"
      case '5':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r14", 4) != 0)
          break;
        return AVR::R15R14;	 // "r15:r14"
      case '6':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r15", 4) != 0)
          break;
        return AVR::R16R15;	 // "r16:r15"
      case '7':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r16", 4) != 0)
          break;
        return AVR::R17R16;	 // "r17:r16"
      case '8':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r17", 4) != 0)
          break;
        return AVR::R18R17;	 // "r18:r17"
      case '9':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r18", 4) != 0)
          break;
        return AVR::R19R18;	 // "r19:r18"
      }
      break;
    case '2':	 // 9 strings to match.
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r19", 4) != 0)
          break;
        return AVR::R20R19;	 // "r20:r19"
      case '1':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r20", 4) != 0)
          break;
        return AVR::R21R20;	 // "r21:r20"
      case '2':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r21", 4) != 0)
          break;
        return AVR::R22R21;	 // "r22:r21"
      case '3':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r22", 4) != 0)
          break;
        return AVR::R23R22;	 // "r23:r22"
      case '4':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r23", 4) != 0)
          break;
        return AVR::R24R23;	 // "r24:r23"
      case '5':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r24", 4) != 0)
          break;
        return AVR::R25R24;	 // "r25:r24"
      case '6':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r25", 4) != 0)
          break;
        return AVR::R26R25;	 // "r26:r25"
      case '7':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r26", 4) != 0)
          break;
        return AVR::R27R26;	 // "r27:r26"
      case '9':	 // 1 string to match.
        if (memcmp(Name.data()+3, ":r28", 4) != 0)
          break;
        return AVR::R29R28;	 // "r29:r28"
      }
      break;
    case '3':	 // 1 string to match.
      if (memcmp(Name.data()+2, "1:r30", 5) != 0)
        break;
      return AVR::R31R30;	 // "r31:r30"
    }
    break;
  }
  return AVR::NoRegister;
}

static MCRegister MatchRegisterAltName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 3 strings to match.
    switch (Name[0]) {
    default: break;
    case 'X':	 // 1 string to match.
      return AVR::R27R26;	 // "X"
    case 'Y':	 // 1 string to match.
      return AVR::R29R28;	 // "Y"
    case 'Z':	 // 1 string to match.
      return AVR::R31R30;	 // "Z"
    }
    break;
  case 2:	 // 6 strings to match.
    switch (Name[0]) {
    default: break;
    case 'x':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'h':	 // 1 string to match.
        return AVR::R27;	 // "xh"
      case 'l':	 // 1 string to match.
        return AVR::R26;	 // "xl"
      }
      break;
    case 'y':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'h':	 // 1 string to match.
        return AVR::R29;	 // "yh"
      case 'l':	 // 1 string to match.
        return AVR::R28;	 // "yl"
      }
      break;
    case 'z':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'h':	 // 1 string to match.
        return AVR::R31;	 // "zh"
      case 'l':	 // 1 string to match.
        return AVR::R30;	 // "zl"
      }
      break;
    }
    break;
  }
  return AVR::NoRegister;
}

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_HasSRAMBit: return "";
  case Feature_HasJMPCALLBit: return "";
  case Feature_HasIJMPCALLBit: return "";
  case Feature_HasEIJMPCALLBit: return "";
  case Feature_HasADDSUBIWBit: return "";
  case Feature_HasSmallStackBit: return "";
  case Feature_HasMOVWBit: return "";
  case Feature_HasLPMBit: return "";
  case Feature_HasLPMXBit: return "";
  case Feature_HasELPMBit: return "";
  case Feature_HasELPMXBit: return "";
  case Feature_HasSPMBit: return "";
  case Feature_HasSPMXBit: return "";
  case Feature_HasDESBit: return "";
  case Feature_SupportsRMWBit: return "";
  case Feature_SupportsMultiplicationBit: return "";
  case Feature_HasBREAKBit: return "";
  case Feature_HasTinyEncodingBit: return "";
  case Feature_HasNonTinyEncodingBit: return "";
  default: return "(unknown)";
  }
}

#endif // GET_SUBTARGET_FEATURE_NAME


#ifdef GET_MATCHER_IMPLEMENTATION
#undef GET_MATCHER_IMPLEMENTATION

enum {
  Tie0_1_1,
  Tie0_2_2,
  Tie1_2_2,
  Tie1_3_3,
};

static const uint8_t TiedAsmOperandTable[][3] = {
  /* Tie0_1_1 */ { 0, 1, 1 },
  /* Tie0_2_2 */ { 0, 2, 2 },
  /* Tie1_2_2 */ { 1, 2, 2 },
  /* Tie1_3_3 */ { 1, 3, 3 },
};

namespace {
enum OperatorConversionKind {
  CVT_Done,
  CVT_Reg,
  CVT_Tied,
  CVT_95_Reg,
  CVT_95_addImmOperands,
  CVT_imm_95_0,
  CVT_imm_95_5,
  CVT_imm_95_7,
  CVT_imm_95_6,
  CVT_imm_95_3,
  CVT_95_addImmCom8Operands,
  CVT_imm_95_2,
  CVT_imm_95_4,
  CVT_imm_95_1,
  CVT_95_addMemriOperands,
  CVT_imm_95_255,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Reg1_0__Tie0_1_1__Reg1_1,
  Convert__Reg1_0__Tie0_1_1__Imm1_1,
  Convert__Reg1_0__Tie0_1_1,
  Convert__Imm1_0,
  Convert__Imm1_0__Imm1_1,
  Convert__imm_95_0__Imm1_0,
  Convert_NoOperands,
  Convert__imm_95_5__Imm1_0,
  Convert__imm_95_7__Imm1_0,
  Convert__imm_95_6__Imm1_0,
  Convert__imm_95_3__Imm1_0,
  Convert__Reg1_0__Imm1_1,
  Convert__Reg1_0__Tie0_1_1__ImmCom81_1,
  Convert__imm_95_0,
  Convert__imm_95_5,
  Convert__imm_95_7,
  Convert__imm_95_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_0,
  Convert__imm_95_4,
  Convert__imm_95_6,
  Convert__imm_95_3,
  Convert__imm_95_1,
  Convert__Reg1_0__Reg1_1,
  Convert__Reg1_1__Reg1_0,
  Convert__Reg1_0__Reg1_2__Tie1_3_3,
  Convert__Reg1_0__Reg1_1__Tie1_2_2,
  Convert__Reg1_0__Memri2_1,
  Convert__Imm1_0__Reg1_1,
  Convert__Reg1_0,
  Convert__Reg1_0__imm_95_255,
  Convert__Reg1_1__Tie0_2_2__Reg1_2__imm_95_0,
  Convert__Reg1_0__Tie0_1_1__Reg1_2__imm_95_0,
  Convert__Memri2_0__Reg1_1,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][9] = {
  // Convert__Reg1_0__Tie0_1_1__Reg1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Imm1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Imm1_0__Imm1_1
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__imm_95_0__Imm1_0
  { CVT_imm_95_0, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__imm_95_5__Imm1_0
  { CVT_imm_95_5, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__imm_95_7__Imm1_0
  { CVT_imm_95_7, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__imm_95_6__Imm1_0
  { CVT_imm_95_6, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__imm_95_3__Imm1_0
  { CVT_imm_95_3, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__Imm1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__ImmCom81_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmCom8Operands, 2, CVT_Done },
  // Convert__imm_95_0
  { CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_5
  { CVT_imm_95_5, 0, CVT_Done },
  // Convert__imm_95_7
  { CVT_imm_95_7, 0, CVT_Done },
  // Convert__imm_95_2
  { CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_0
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 1, CVT_Done },
  // Convert__imm_95_4
  { CVT_imm_95_4, 0, CVT_Done },
  // Convert__imm_95_6
  { CVT_imm_95_6, 0, CVT_Done },
  // Convert__imm_95_3
  { CVT_imm_95_3, 0, CVT_Done },
  // Convert__imm_95_1
  { CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_1__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_2__Tie1_3_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_Tied, Tie1_3_3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Tie1_2_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie1_2_2, CVT_Done },
  // Convert__Reg1_0__Memri2_1
  { CVT_95_Reg, 1, CVT_95_addMemriOperands, 2, CVT_Done },
  // Convert__Imm1_0__Reg1_1
  { CVT_95_addImmOperands, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__imm_95_255
  { CVT_95_Reg, 1, CVT_imm_95_255, 0, CVT_Done },
  // Convert__Reg1_1__Tie0_2_2__Reg1_2__imm_95_0
  { CVT_95_Reg, 2, CVT_Tied, Tie0_2_2, CVT_95_Reg, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_2__imm_95_0
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Memri2_0__Reg1_1
  { CVT_95_addMemriOperands, 1, CVT_95_Reg, 2, CVT_Done },
};

void AVRAsmParser::
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
      static_cast<AVROperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
      static_cast<AVROperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addImmOperands:
      static_cast<AVROperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_imm_95_5:
      Inst.addOperand(MCOperand::createImm(5));
      break;
    case CVT_imm_95_7:
      Inst.addOperand(MCOperand::createImm(7));
      break;
    case CVT_imm_95_6:
      Inst.addOperand(MCOperand::createImm(6));
      break;
    case CVT_imm_95_3:
      Inst.addOperand(MCOperand::createImm(3));
      break;
    case CVT_95_addImmCom8Operands:
      static_cast<AVROperand &>(*Operands[OpIdx]).addImmCom8Operands(Inst, 1);
      break;
    case CVT_imm_95_2:
      Inst.addOperand(MCOperand::createImm(2));
      break;
    case CVT_imm_95_4:
      Inst.addOperand(MCOperand::createImm(4));
      break;
    case CVT_imm_95_1:
      Inst.addOperand(MCOperand::createImm(1));
      break;
    case CVT_95_addMemriOperands:
      static_cast<AVROperand &>(*Operands[OpIdx]).addMemriOperands(Inst, 2);
      break;
    case CVT_imm_95_255:
      Inst.addOperand(MCOperand::createImm(255));
      break;
    }
  }
}

void AVRAsmParser::
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
    case CVT_95_addImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_5:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_7:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_6:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_3:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addImmCom8Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_2:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_4:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_1:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addMemriOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 2;
      break;
    case CVT_imm_95_255:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
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
  MCK__43_, // '+'
  MCK__MINUS_, // '-'
  MCK_LAST_TOKEN = MCK__MINUS_,
  MCK_Reg31, // derived register class
  MCK_Reg16, // derived register class
  MCK_CCR, // register class 'CCR'
  MCK_GPRSP, // register class 'GPRSP'
  MCK_ZREG, // register class 'ZREG'
  MCK_Reg17, // derived register class
  MCK_PTRDISPREGS, // register class 'PTRDISPREGS'
  MCK_Reg18, // derived register class
  MCK_PTRREGS, // register class 'PTRREGS'
  MCK_DREGSLD8lo, // register class 'DREGSLD8lo'
  MCK_IWREGS, // register class 'IWREGS'
  MCK_Reg26, // derived register class
  MCK_Reg19, // derived register class
  MCK_Reg27, // derived register class
  MCK_Reg25, // derived register class
  MCK_DLDREGS, // register class 'DLDREGS'
  MCK_DREGSlo, // register class 'DREGSlo'
  MCK_LD8lo, // register class 'LD8lo'
  MCK_Reg30, // derived register class
  MCK_Reg29, // derived register class
  MCK_Reg22, // derived register class
  MCK_Reg23, // derived register class
  MCK_Reg14, // derived register class
  MCK_Reg15, // derived register class
  MCK_Reg4, // derived register class
  MCK_Reg20, // derived register class
  MCK_DREGSMOVW, // register class 'DREGSMOVW'
  MCK_GPR8lo, // register class 'GPR8lo'
  MCK_LD8, // register class 'LD8'
  MCK_DREGSNOZ, // register class 'DREGSNOZ'
  MCK_DREGS, // register class 'DREGS'
  MCK_GPR8NOZ, // register class 'GPR8NOZ'
  MCK_GPR8, // register class 'GPR8'
  MCK_LAST_REGISTER = MCK_GPR8,
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_Memri, // user defined class 'MemriAsmOperand'
  MCK_ImmCom8, // user defined class 'imm_com8_asmoperand'
  NumMatchClassKinds
};

} // end anonymous namespace

static unsigned getDiagKindFromRegisterClass(MatchClassKind RegisterClass) {
  return MCTargetAsmParser::Match_InvalidOperand;
}

static MatchClassKind matchTokenString(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case '+':	 // 1 string to match.
      return MCK__43_;	 // "+"
    case '-':	 // 1 string to match.
      return MCK__MINUS_;	 // "-"
    }
    break;
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
    {0, 17, 18},
    {18, 9, 26},
    {44, 0, 0},
    {44, 0, 0},
    {44, 10, 25},
    {69, 11, 24},
    {93, 12, 23},
    {116, 14, 21},
    {137, 14, 21},
    {158, 15, 20},
    {178, 19, 16},
    {194, 17, 18},
    {212, 19, 16},
    {228, 25, 10},
    {238, 24, 11},
    {249, 26, 9},
    {258, 22, 13},
    {271, 28, 9},
    {280, 23, 12},
    {292, 33, 2},
    {294, 25, 10},
    {304, 27, 8},
    {312, 27, 8},
    {320, 34, 1},
    {321, 32, 5},
    {326, 30, 5},
    {331, 34, 1},
    {332, 35, 2},
    {334, 36, 1},
    {335, 34, 1},
    {336, 0, 0},
    {336, 36, 1},
    {337, 0, 0},
    {337, 0, 0},
    {337, 0, 0},
    {337, 0, 0},
  };

  static constexpr uint8_t Data[] = {
    0x41,
    0x05,
    0xBF,
    0x12,
    0xDE,
    0x5C,
    0x21,
    0x30,
    0x71,
    0x25,
    0xBC,
    0xB9,
    0x10,
    0x98,
    0x58,
    0xC2,
    0x9B,
    0x43,
    0x60,
    0xE2,
    0x87,
    0x37,
    0x07,
    0x26,
    0x0E,
    0x1E,
    0x1C,
    0xDE,
    0x5C,
    0xF0,
    0x83,
    0x27,
    0x0E,
    0xE6,
    0xC8,
    0x01,
    0xFC,
    0xC1,
    0xC1,
    0x81,
    0x73,
    0xFE,
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
  AVROperand &Operand = (AVROperand &)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  case MCK_Imm: {
    DiagnosticPredicate DP(Operand.isImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Memri: {
    DiagnosticPredicate DP(Operand.isMemri());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_ImmCom8: {
    DiagnosticPredicate DP(Operand.isImmCom8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg()) {
    static constexpr uint16_t Table[AVR::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      MCK_GPRSP,
      InvalidMatchClass,
      InvalidMatchClass,
      MCK_CCR,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_GPR8lo,
      MCK_LD8lo,
      MCK_LD8lo,
      MCK_LD8lo,
      MCK_LD8lo,
      MCK_LD8lo,
      MCK_LD8lo,
      MCK_LD8lo,
      MCK_LD8lo,
      MCK_Reg4,
      MCK_Reg4,
      MCK_Reg4,
      MCK_Reg4,
      MCK_Reg4,
      MCK_Reg4,
      MCK_LD8,
      MCK_LD8,
      MCK_DREGSlo,
      MCK_DREGSlo,
      MCK_DREGSlo,
      MCK_DREGSlo,
      MCK_DREGSlo,
      MCK_Reg30,
      MCK_DREGSlo,
      MCK_Reg30,
      MCK_DREGSlo,
      MCK_Reg30,
      MCK_DREGSlo,
      MCK_Reg31,
      MCK_DREGSLD8lo,
      MCK_Reg26,
      MCK_DREGSLD8lo,
      MCK_Reg26,
      MCK_DREGSLD8lo,
      MCK_Reg26,
      MCK_DREGSLD8lo,
      MCK_Reg25,
      MCK_Reg18,
      MCK_Reg22,
      MCK_Reg17,
      MCK_Reg16,
      MCK_ZREG,
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
  case MCK__43_: return "MCK__43_";
  case MCK__MINUS_: return "MCK__MINUS_";
  case MCK_Reg31: return "MCK_Reg31";
  case MCK_Reg16: return "MCK_Reg16";
  case MCK_CCR: return "MCK_CCR";
  case MCK_GPRSP: return "MCK_GPRSP";
  case MCK_ZREG: return "MCK_ZREG";
  case MCK_Reg17: return "MCK_Reg17";
  case MCK_PTRDISPREGS: return "MCK_PTRDISPREGS";
  case MCK_Reg18: return "MCK_Reg18";
  case MCK_PTRREGS: return "MCK_PTRREGS";
  case MCK_DREGSLD8lo: return "MCK_DREGSLD8lo";
  case MCK_IWREGS: return "MCK_IWREGS";
  case MCK_Reg26: return "MCK_Reg26";
  case MCK_Reg19: return "MCK_Reg19";
  case MCK_Reg27: return "MCK_Reg27";
  case MCK_Reg25: return "MCK_Reg25";
  case MCK_DLDREGS: return "MCK_DLDREGS";
  case MCK_DREGSlo: return "MCK_DREGSlo";
  case MCK_LD8lo: return "MCK_LD8lo";
  case MCK_Reg30: return "MCK_Reg30";
  case MCK_Reg29: return "MCK_Reg29";
  case MCK_Reg22: return "MCK_Reg22";
  case MCK_Reg23: return "MCK_Reg23";
  case MCK_Reg14: return "MCK_Reg14";
  case MCK_Reg15: return "MCK_Reg15";
  case MCK_Reg4: return "MCK_Reg4";
  case MCK_Reg20: return "MCK_Reg20";
  case MCK_DREGSMOVW: return "MCK_DREGSMOVW";
  case MCK_GPR8lo: return "MCK_GPR8lo";
  case MCK_LD8: return "MCK_LD8";
  case MCK_DREGSNOZ: return "MCK_DREGSNOZ";
  case MCK_DREGS: return "MCK_DREGS";
  case MCK_GPR8NOZ: return "MCK_GPR8NOZ";
  case MCK_GPR8: return "MCK_GPR8";
  case MCK_Imm: return "MCK_Imm";
  case MCK_Memri: return "MCK_Memri";
  case MCK_ImmCom8: return "MCK_ImmCom8";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset AVRAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  if (FB[AVR::FeatureSRAM])
    Features.set(Feature_HasSRAMBit);
  if (FB[AVR::FeatureJMPCALL])
    Features.set(Feature_HasJMPCALLBit);
  if (FB[AVR::FeatureIJMPCALL])
    Features.set(Feature_HasIJMPCALLBit);
  if (FB[AVR::FeatureEIJMPCALL])
    Features.set(Feature_HasEIJMPCALLBit);
  if (FB[AVR::FeatureADDSUBIW])
    Features.set(Feature_HasADDSUBIWBit);
  if (FB[AVR::FeatureSmallStack])
    Features.set(Feature_HasSmallStackBit);
  if (FB[AVR::FeatureMOVW])
    Features.set(Feature_HasMOVWBit);
  if (FB[AVR::FeatureLPM])
    Features.set(Feature_HasLPMBit);
  if (FB[AVR::FeatureLPMX])
    Features.set(Feature_HasLPMXBit);
  if (FB[AVR::FeatureELPM])
    Features.set(Feature_HasELPMBit);
  if (FB[AVR::FeatureELPMX])
    Features.set(Feature_HasELPMXBit);
  if (FB[AVR::FeatureSPM])
    Features.set(Feature_HasSPMBit);
  if (FB[AVR::FeatureSPMX])
    Features.set(Feature_HasSPMXBit);
  if (FB[AVR::FeatureDES])
    Features.set(Feature_HasDESBit);
  if (FB[AVR::FeatureRMW])
    Features.set(Feature_SupportsRMWBit);
  if (FB[AVR::FeatureMultiplication])
    Features.set(Feature_SupportsMultiplicationBit);
  if (FB[AVR::FeatureBREAK])
    Features.set(Feature_HasBREAKBit);
  if (FB[AVR::FeatureTinyEncoding])
    Features.set(Feature_HasTinyEncodingBit);
  if (!FB[AVR::FeatureTinyEncoding])
    Features.set(Feature_HasNonTinyEncodingBit);
  return Features;
}

static bool checkAsmTiedOperandConstraints(const AVRAsmParser&AsmParser,
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
    "\003adc\003add\004adiw\003and\004andi\003asr\004bclr\003bld\004brbc\004"
    "brbs\004brcc\004brcs\005break\004breq\004brge\004brhc\004brhs\004brid\004"
    "brie\004brlo\004brlt\004brmi\004brne\004brpl\004brsh\004brtc\004brts\004"
    "brvc\004brvs\004bset\003bst\004call\003cbi\003cbr\003clc\003clh\003cli\003"
    "cln\003clr\003cls\003clt\003clv\003clz\003com\002cp\003cpc\003cpi\004cp"
    "se\003dec\003des\006eicall\005eijmp\004elpm\003eor\004fmul\005fmuls\006"
    "fmulsu\005icall\004ijmp\002in\003inc\003jmp\003lac\003las\003lat\002ld\003"
    "ldd\003ldi\003lds\003lpm\003lsl\003lsr\003mov\004movw\003mul\004muls\005"
    "mulsu\003neg\003nop\002or\003ori\003out\003pop\004push\005rcall\003ret\004"
    "reti\004rjmp\003rol\003ror\003sbc\004sbci\003sbi\004sbic\004sbis\004sbi"
    "w\003sbr\004sbrc\004sbrs\003sec\003seh\003sei\003sen\003ser\003ses\003s"
    "et\003sev\003sez\005sleep\003spm\002st\003std\003sts\003sub\004subi\004"
    "swap\003tst\003wdr\003xch";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
  AMFBS_HasADDSUBIW,
  AMFBS_HasBREAK,
  AMFBS_HasDES,
  AMFBS_HasEIJMPCALL,
  AMFBS_HasELPM,
  AMFBS_HasELPMX,
  AMFBS_HasIJMPCALL,
  AMFBS_HasJMPCALL,
  AMFBS_HasLPM,
  AMFBS_HasLPMX,
  AMFBS_HasMOVW,
  AMFBS_HasSPM,
  AMFBS_HasSPMX,
  AMFBS_HasSRAM,
  AMFBS_SupportsMultiplication,
  AMFBS_SupportsRMW,
  AMFBS_HasSRAM_HasNonTinyEncoding,
  AMFBS_HasSRAM_HasTinyEncoding,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
  {Feature_HasADDSUBIWBit, }, // AMFBS_HasADDSUBIW
  {Feature_HasBREAKBit, }, // AMFBS_HasBREAK
  {Feature_HasDESBit, }, // AMFBS_HasDES
  {Feature_HasEIJMPCALLBit, }, // AMFBS_HasEIJMPCALL
  {Feature_HasELPMBit, }, // AMFBS_HasELPM
  {Feature_HasELPMXBit, }, // AMFBS_HasELPMX
  {Feature_HasIJMPCALLBit, }, // AMFBS_HasIJMPCALL
  {Feature_HasJMPCALLBit, }, // AMFBS_HasJMPCALL
  {Feature_HasLPMBit, }, // AMFBS_HasLPM
  {Feature_HasLPMXBit, }, // AMFBS_HasLPMX
  {Feature_HasMOVWBit, }, // AMFBS_HasMOVW
  {Feature_HasSPMBit, }, // AMFBS_HasSPM
  {Feature_HasSPMXBit, }, // AMFBS_HasSPMX
  {Feature_HasSRAMBit, }, // AMFBS_HasSRAM
  {Feature_SupportsMultiplicationBit, }, // AMFBS_SupportsMultiplication
  {Feature_SupportsRMWBit, }, // AMFBS_SupportsRMW
  {Feature_HasSRAMBit, Feature_HasNonTinyEncodingBit, }, // AMFBS_HasSRAM_HasNonTinyEncoding
  {Feature_HasSRAMBit, Feature_HasTinyEncodingBit, }, // AMFBS_HasSRAM_HasTinyEncoding
};

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
    uint32_t Opcode;
    uint8_t ConvertFn;
    uint8_t RequiredFeaturesIdx;
    uint8_t Classes[3];
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
  { 0 /* adc */, AVR::ADCRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 4 /* add */, AVR::ADDRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 8 /* adiw */, AVR::ADIWRdK, Convert__Reg1_0__Tie0_1_1__Imm1_1, AMFBS_HasADDSUBIW, { MCK_IWREGS, MCK_Imm }, },
  { 13 /* and */, AVR::ANDRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 17 /* andi */, AVR::ANDIRdK, Convert__Reg1_0__Tie0_1_1__Imm1_1, AMFBS_None, { MCK_LD8, MCK_Imm }, },
  { 22 /* asr */, AVR::ASRRd, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GPR8 }, },
  { 26 /* bclr */, AVR::BCLRs, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 31 /* bld */, AVR::BLD, Convert__Reg1_0__Tie0_1_1__Imm1_1, AMFBS_None, { MCK_GPR8, MCK_Imm }, },
  { 35 /* brbc */, AVR::BRBCsk, Convert__Imm1_0__Imm1_1, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 40 /* brbs */, AVR::BRBSsk, Convert__Imm1_0__Imm1_1, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 45 /* brcc */, AVR::BRBCsk, Convert__imm_95_0__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 50 /* brcs */, AVR::BRBSsk, Convert__imm_95_0__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 55 /* break */, AVR::BREAK, Convert_NoOperands, AMFBS_HasBREAK, {  }, },
  { 61 /* breq */, AVR::BREQk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 66 /* brge */, AVR::BRGEk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 71 /* brhc */, AVR::BRBCsk, Convert__imm_95_5__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 76 /* brhs */, AVR::BRBSsk, Convert__imm_95_5__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 81 /* brid */, AVR::BRBCsk, Convert__imm_95_7__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 86 /* brie */, AVR::BRBSsk, Convert__imm_95_7__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 91 /* brlo */, AVR::BRLOk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 96 /* brlt */, AVR::BRLTk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 101 /* brmi */, AVR::BRMIk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 106 /* brne */, AVR::BRNEk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 111 /* brpl */, AVR::BRPLk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 116 /* brsh */, AVR::BRSHk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 121 /* brtc */, AVR::BRBCsk, Convert__imm_95_6__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 126 /* brts */, AVR::BRBSsk, Convert__imm_95_6__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 131 /* brvc */, AVR::BRBCsk, Convert__imm_95_3__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 136 /* brvs */, AVR::BRBSsk, Convert__imm_95_3__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 141 /* bset */, AVR::BSETs, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 146 /* bst */, AVR::BST, Convert__Reg1_0__Imm1_1, AMFBS_None, { MCK_GPR8, MCK_Imm }, },
  { 150 /* call */, AVR::CALLk, Convert__Imm1_0, AMFBS_HasJMPCALL, { MCK_Imm }, },
  { 155 /* cbi */, AVR::CBIAb, Convert__Imm1_0__Imm1_1, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 159 /* cbr */, AVR::ANDIRdK, Convert__Reg1_0__Tie0_1_1__ImmCom81_1, AMFBS_None, { MCK_LD8, MCK_ImmCom8 }, },
  { 163 /* clc */, AVR::BCLRs, Convert__imm_95_0, AMFBS_None, {  }, },
  { 167 /* clh */, AVR::BCLRs, Convert__imm_95_5, AMFBS_None, {  }, },
  { 171 /* cli */, AVR::BCLRs, Convert__imm_95_7, AMFBS_None, {  }, },
  { 175 /* cln */, AVR::BCLRs, Convert__imm_95_2, AMFBS_None, {  }, },
  { 179 /* clr */, AVR::EORRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GPR8 }, },
  { 183 /* cls */, AVR::BCLRs, Convert__imm_95_4, AMFBS_None, {  }, },
  { 187 /* clt */, AVR::BCLRs, Convert__imm_95_6, AMFBS_None, {  }, },
  { 191 /* clv */, AVR::BCLRs, Convert__imm_95_3, AMFBS_None, {  }, },
  { 195 /* clz */, AVR::BCLRs, Convert__imm_95_1, AMFBS_None, {  }, },
  { 199 /* com */, AVR::COMRd, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GPR8 }, },
  { 203 /* cp */, AVR::CPRdRr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 206 /* cpc */, AVR::CPCRdRr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 210 /* cpi */, AVR::CPIRdK, Convert__Reg1_0__Imm1_1, AMFBS_None, { MCK_LD8, MCK_Imm }, },
  { 214 /* cpse */, AVR::CPSE, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 219 /* dec */, AVR::DECRd, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GPR8 }, },
  { 223 /* des */, AVR::DESK, Convert__Imm1_0, AMFBS_HasDES, { MCK_Imm }, },
  { 227 /* eicall */, AVR::EICALL, Convert_NoOperands, AMFBS_HasEIJMPCALL, {  }, },
  { 234 /* eijmp */, AVR::EIJMP, Convert_NoOperands, AMFBS_HasEIJMPCALL, {  }, },
  { 240 /* elpm */, AVR::ELPM, Convert_NoOperands, AMFBS_HasELPM, {  }, },
  { 240 /* elpm */, AVR::ELPMRdZ, Convert__Reg1_0__Reg1_1, AMFBS_HasELPMX, { MCK_GPR8, MCK_ZREG }, },
  { 240 /* elpm */, AVR::ELPMRdZPi, Convert__Reg1_0__Reg1_1, AMFBS_HasELPMX, { MCK_GPR8, MCK_ZREG, MCK__43_ }, },
  { 245 /* eor */, AVR::EORRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 249 /* fmul */, AVR::FMUL, Convert__Reg1_0__Reg1_1, AMFBS_SupportsMultiplication, { MCK_LD8lo, MCK_LD8lo }, },
  { 254 /* fmuls */, AVR::FMULS, Convert__Reg1_0__Reg1_1, AMFBS_SupportsMultiplication, { MCK_LD8lo, MCK_LD8lo }, },
  { 260 /* fmulsu */, AVR::FMULSU, Convert__Reg1_0__Reg1_1, AMFBS_SupportsMultiplication, { MCK_LD8lo, MCK_LD8lo }, },
  { 267 /* icall */, AVR::ICALL, Convert_NoOperands, AMFBS_HasIJMPCALL, {  }, },
  { 273 /* ijmp */, AVR::IJMP, Convert_NoOperands, AMFBS_HasIJMPCALL, {  }, },
  { 278 /* in */, AVR::INRdA, Convert__Reg1_0__Imm1_1, AMFBS_None, { MCK_GPR8, MCK_Imm }, },
  { 281 /* inc */, AVR::INCRd, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GPR8 }, },
  { 285 /* jmp */, AVR::JMPk, Convert__Imm1_0, AMFBS_HasJMPCALL, { MCK_Imm }, },
  { 289 /* lac */, AVR::LACZRd, Convert__Reg1_1__Reg1_0, AMFBS_SupportsRMW, { MCK_ZREG, MCK_GPR8 }, },
  { 293 /* las */, AVR::LASZRd, Convert__Reg1_1__Reg1_0, AMFBS_SupportsRMW, { MCK_ZREG, MCK_GPR8 }, },
  { 297 /* lat */, AVR::LATZRd, Convert__Reg1_1__Reg1_0, AMFBS_SupportsRMW, { MCK_ZREG, MCK_GPR8 }, },
  { 301 /* ld */, AVR::LDRdPtr, Convert__Reg1_0__Reg1_1, AMFBS_HasSRAM, { MCK_GPR8, MCK_PTRREGS }, },
  { 301 /* ld */, AVR::LDRdPtrPd, Convert__Reg1_0__Reg1_2__Tie1_3_3, AMFBS_HasSRAM, { MCK_GPR8, MCK__MINUS_, MCK_PTRREGS }, },
  { 301 /* ld */, AVR::LDRdPtrPi, Convert__Reg1_0__Reg1_1__Tie1_2_2, AMFBS_HasSRAM, { MCK_GPR8, MCK_PTRREGS, MCK__43_ }, },
  { 304 /* ldd */, AVR::LDDRdPtrQ, Convert__Reg1_0__Memri2_1, AMFBS_HasSRAM_HasNonTinyEncoding, { MCK_GPR8, MCK_Memri }, },
  { 308 /* ldi */, AVR::LDIRdK, Convert__Reg1_0__Imm1_1, AMFBS_None, { MCK_LD8, MCK_Imm }, },
  { 312 /* lds */, AVR::LDSRdKTiny, Convert__Reg1_0__Imm1_1, AMFBS_HasSRAM_HasTinyEncoding, { MCK_LD8, MCK_Imm }, },
  { 312 /* lds */, AVR::LDSRdK, Convert__Reg1_0__Imm1_1, AMFBS_HasSRAM_HasNonTinyEncoding, { MCK_GPR8, MCK_Imm }, },
  { 316 /* lpm */, AVR::LPM, Convert_NoOperands, AMFBS_HasLPM, {  }, },
  { 316 /* lpm */, AVR::LPMRdZ, Convert__Reg1_0__Reg1_1, AMFBS_HasLPMX, { MCK_GPR8, MCK_ZREG }, },
  { 316 /* lpm */, AVR::LPMRdZPi, Convert__Reg1_0__Reg1_1, AMFBS_HasLPMX, { MCK_GPR8, MCK_ZREG, MCK__43_ }, },
  { 320 /* lsl */, AVR::ADDRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GPR8 }, },
  { 324 /* lsr */, AVR::LSRRd, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GPR8 }, },
  { 328 /* mov */, AVR::MOVRdRr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 332 /* movw */, AVR::MOVWRdRr, Convert__Reg1_0__Reg1_1, AMFBS_HasMOVW, { MCK_DREGS, MCK_DREGS }, },
  { 337 /* mul */, AVR::MULRdRr, Convert__Reg1_0__Reg1_1, AMFBS_SupportsMultiplication, { MCK_GPR8, MCK_GPR8 }, },
  { 341 /* muls */, AVR::MULSRdRr, Convert__Reg1_0__Reg1_1, AMFBS_SupportsMultiplication, { MCK_LD8, MCK_LD8 }, },
  { 346 /* mulsu */, AVR::MULSURdRr, Convert__Reg1_0__Reg1_1, AMFBS_SupportsMultiplication, { MCK_LD8lo, MCK_LD8lo }, },
  { 352 /* neg */, AVR::NEGRd, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GPR8 }, },
  { 356 /* nop */, AVR::NOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 360 /* or */, AVR::ORRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 363 /* ori */, AVR::ORIRdK, Convert__Reg1_0__Tie0_1_1__Imm1_1, AMFBS_None, { MCK_LD8, MCK_Imm }, },
  { 367 /* out */, AVR::OUTARr, Convert__Imm1_0__Reg1_1, AMFBS_None, { MCK_Imm, MCK_GPR8 }, },
  { 371 /* pop */, AVR::POPRd, Convert__Reg1_0, AMFBS_HasSRAM, { MCK_GPR8 }, },
  { 375 /* push */, AVR::PUSHRr, Convert__Reg1_0, AMFBS_HasSRAM, { MCK_GPR8 }, },
  { 380 /* rcall */, AVR::RCALLk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 386 /* ret */, AVR::RET, Convert_NoOperands, AMFBS_None, {  }, },
  { 390 /* reti */, AVR::RETI, Convert_NoOperands, AMFBS_None, {  }, },
  { 395 /* rjmp */, AVR::RJMPk, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 400 /* rol */, AVR::ADCRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GPR8 }, },
  { 404 /* ror */, AVR::RORRd, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GPR8 }, },
  { 408 /* sbc */, AVR::SBCRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 412 /* sbci */, AVR::SBCIRdK, Convert__Reg1_0__Tie0_1_1__Imm1_1, AMFBS_None, { MCK_LD8, MCK_Imm }, },
  { 417 /* sbi */, AVR::SBIAb, Convert__Imm1_0__Imm1_1, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 421 /* sbic */, AVR::SBICAb, Convert__Imm1_0__Imm1_1, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 426 /* sbis */, AVR::SBISAb, Convert__Imm1_0__Imm1_1, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 431 /* sbiw */, AVR::SBIWRdK, Convert__Reg1_0__Tie0_1_1__Imm1_1, AMFBS_HasADDSUBIW, { MCK_IWREGS, MCK_Imm }, },
  { 436 /* sbr */, AVR::ORIRdK, Convert__Reg1_0__Tie0_1_1__Imm1_1, AMFBS_None, { MCK_LD8, MCK_Imm }, },
  { 440 /* sbrc */, AVR::SBRCRrB, Convert__Reg1_0__Imm1_1, AMFBS_None, { MCK_GPR8, MCK_Imm }, },
  { 445 /* sbrs */, AVR::SBRSRrB, Convert__Reg1_0__Imm1_1, AMFBS_None, { MCK_GPR8, MCK_Imm }, },
  { 450 /* sec */, AVR::BSETs, Convert__imm_95_0, AMFBS_None, {  }, },
  { 454 /* seh */, AVR::BSETs, Convert__imm_95_5, AMFBS_None, {  }, },
  { 458 /* sei */, AVR::BSETs, Convert__imm_95_7, AMFBS_None, {  }, },
  { 462 /* sen */, AVR::BSETs, Convert__imm_95_2, AMFBS_None, {  }, },
  { 466 /* ser */, AVR::LDIRdK, Convert__Reg1_0__imm_95_255, AMFBS_None, { MCK_LD8 }, },
  { 470 /* ses */, AVR::BSETs, Convert__imm_95_4, AMFBS_None, {  }, },
  { 474 /* set */, AVR::BSETs, Convert__imm_95_6, AMFBS_None, {  }, },
  { 478 /* sev */, AVR::BSETs, Convert__imm_95_3, AMFBS_None, {  }, },
  { 482 /* sez */, AVR::BSETs, Convert__imm_95_1, AMFBS_None, {  }, },
  { 486 /* sleep */, AVR::SLEEP, Convert_NoOperands, AMFBS_None, {  }, },
  { 492 /* spm */, AVR::SPM, Convert_NoOperands, AMFBS_HasSPM, {  }, },
  { 492 /* spm */, AVR::SPMZPi, Convert__Reg1_0, AMFBS_HasSPMX, { MCK_ZREG, MCK__43_ }, },
  { 496 /* st */, AVR::STPtrRr, Convert__Reg1_0__Reg1_1, AMFBS_HasSRAM, { MCK_PTRREGS, MCK_GPR8 }, },
  { 496 /* st */, AVR::STPtrPdRr, Convert__Reg1_1__Tie0_2_2__Reg1_2__imm_95_0, AMFBS_HasSRAM, { MCK__MINUS_, MCK_PTRREGS, MCK_GPR8 }, },
  { 496 /* st */, AVR::STPtrPiRr, Convert__Reg1_0__Tie0_1_1__Reg1_2__imm_95_0, AMFBS_HasSRAM, { MCK_PTRREGS, MCK__43_, MCK_GPR8 }, },
  { 499 /* std */, AVR::STDPtrQRr, Convert__Memri2_0__Reg1_1, AMFBS_HasSRAM_HasNonTinyEncoding, { MCK_Memri, MCK_GPR8 }, },
  { 503 /* sts */, AVR::STSKRrTiny, Convert__Imm1_0__Reg1_1, AMFBS_HasSRAM_HasTinyEncoding, { MCK_Imm, MCK_LD8 }, },
  { 503 /* sts */, AVR::STSKRr, Convert__Imm1_0__Reg1_1, AMFBS_HasSRAM_HasNonTinyEncoding, { MCK_Imm, MCK_GPR8 }, },
  { 507 /* sub */, AVR::SUBRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_GPR8, MCK_GPR8 }, },
  { 511 /* subi */, AVR::SUBIRdK, Convert__Reg1_0__Tie0_1_1__Imm1_1, AMFBS_None, { MCK_LD8, MCK_Imm }, },
  { 516 /* swap */, AVR::SWAPRd, Convert__Reg1_0__Tie0_1_1, AMFBS_None, { MCK_GPR8 }, },
  { 521 /* tst */, AVR::ANDRdRr, Convert__Reg1_0__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_GPR8 }, },
  { 525 /* wdr */, AVR::WDR, Convert_NoOperands, AMFBS_None, {  }, },
  { 529 /* xch */, AVR::XCHZRd, Convert__Reg1_1__Reg1_0, AMFBS_SupportsRMW, { MCK_ZREG, MCK_GPR8 }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned AVRAsmParser::
MatchInstructionImpl(const OperandVector &Operands,
                     MCInst &Inst,
                     uint64_t &ErrorInfo,
                     FeatureBitset &MissingFeatures,
                     bool matchingInlineAsm, unsigned VariantID) {
  // Eliminate obvious mismatches.
  if (Operands.size() > 4) {
    ErrorInfo = 4;
    return Match_InvalidOperand;
  }

  // Get the current feature set.
  const FeatureBitset &AvailableFeatures = getAvailableFeatures();

  // Get the instruction mnemonic, which is the first token.
  StringRef Mnemonic = ((AVROperand &)*Operands[0]).getToken();

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
    for (unsigned FormalIdx = 0; FormalIdx != 3; ++FormalIdx) {
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
    uint16_t Mnemonic;
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

static const OperandMatchEntry OperandMatchTable[2] = {
  /* Operand List Mnemonic, Mask, Operand Class, Features */
  { 304 /* ldd */, 2 /* 1 */, MCK_Memri, AMFBS_HasSRAM_HasNonTinyEncoding },
  { 499 /* std */, 1 /* 0 */, MCK_Memri, AMFBS_HasSRAM_HasNonTinyEncoding },
};

ParseStatus AVRAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_Memri:
    return parseMemriOperand(Operands);
  default:
    return ParseStatus::NoMatch;
  }
  return ParseStatus::NoMatch;
}

ParseStatus AVRAsmParser::
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

static std::string AVRMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool AVRCheckMnemonic(StringRef Mnemonic,
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

