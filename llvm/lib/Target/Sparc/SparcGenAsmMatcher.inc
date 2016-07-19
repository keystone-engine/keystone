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
  unsigned MatchInstructionImpl(const OperandVector &Operands,
                                MCInst &Inst,
                                uint64_t &ErrorInfo, bool matchingInlineAsm,
                                unsigned VariantID = 0);

  enum OperandMatchResultTy {
    MatchOperand_Success,    // operand matched successfully
    MatchOperand_NoMatch,    // operand did not match
    MatchOperand_ParseFail   // operand matched but had errors
  };
  OperandMatchResultTy MatchOperandParserImpl(
    OperandVector &Operands,
    StringRef Mnemonic);
  OperandMatchResultTy tryCustomParseOperand(
    OperandVector &Operands,
    unsigned MCK);

#endif // GET_ASSEMBLER_HEADER_INFO


#ifdef GET_OPERAND_DIAGNOSTIC_TYPES
#undef GET_OPERAND_DIAGNOSTIC_TYPES

#endif // GET_OPERAND_DIAGNOSTIC_TYPES


#ifdef GET_REGISTER_MATCHER
#undef GET_REGISTER_MATCHER

// Flags for subtarget features that participate in instruction matching.
enum SubtargetFeatureFlag : uint8_t {
  Feature_HasV9 = (1ULL << 0),
  Feature_HasVIS = (1ULL << 1),
  Feature_HasVIS2 = (1ULL << 2),
  Feature_HasVIS3 = (1ULL << 3),
  Feature_None = 0
};

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_HasV9: return "";
  case Feature_HasVIS: return "";
  case Feature_HasVIS2: return "";
  case Feature_HasVIS3: return "";
  default: return "(unknown)";
  }
}

#endif // GET_SUBTARGET_FEATURE_NAME


#ifdef GET_MATCHER_IMPLEMENTATION
#undef GET_MATCHER_IMPLEMENTATION

static void applyMnemonicAliases(StringRef &Mnemonic, uint64_t Features, unsigned VariantID) {
  switch (VariantID) {
    case 0:
      switch (Mnemonic.size()) {
      default: break;
      case 4:	 // 3 strings to match.
        switch (Mnemonic[0]) {
        default: break;
        case 'a':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+1, "ddc", 3))
            break;
          if ((Features & Feature_HasV9) == Feature_HasV9)	 // "addc"
            Mnemonic = "addx";
          return;
        case 'l':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+1, "duw", 3))
            break;
          if ((Features & Feature_HasV9) == Feature_HasV9)	 // "lduw"
            Mnemonic = "ld";
          return;
        case 's':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+1, "ubc", 3))
            break;
          if ((Features & Feature_HasV9) == Feature_HasV9)	 // "subc"
            Mnemonic = "subx";
          return;
        }
        break;
      case 5:	 // 1 string to match.
        if (memcmp(Mnemonic.data()+0, "lduwa", 5))
          break;
        if ((Features & Feature_HasV9) == Feature_HasV9)	 // "lduwa"
          Mnemonic = "lda";
        return;
      case 6:	 // 3 strings to match.
        switch (Mnemonic[0]) {
        default: break;
        case 'a':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+1, "ddccc", 5))
            break;
          if ((Features & Feature_HasV9) == Feature_HasV9)	 // "addccc"
            Mnemonic = "addxcc";
          return;
        case 'r':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+1, "eturn", 5))
            break;
          if ((Features & Feature_HasV9) == Feature_HasV9)	 // "return"
            Mnemonic = "rett";
          return;
        case 's':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+1, "ubccc", 5))
            break;
          if ((Features & Feature_HasV9) == Feature_HasV9)	 // "subccc"
            Mnemonic = "subxcc";
          return;
        }
        break;
      }
    break;
  }
  switch (Mnemonic.size()) {
  default: break;
  case 4:	 // 3 strings to match.
    switch (Mnemonic[0]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "ddc", 3))
        break;
      if ((Features & Feature_HasV9) == Feature_HasV9)	 // "addc"
        Mnemonic = "addx";
      return;
    case 'l':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "duw", 3))
        break;
      if ((Features & Feature_HasV9) == Feature_HasV9)	 // "lduw"
        Mnemonic = "ld";
      return;
    case 's':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "ubc", 3))
        break;
      if ((Features & Feature_HasV9) == Feature_HasV9)	 // "subc"
        Mnemonic = "subx";
      return;
    }
    break;
  case 5:	 // 1 string to match.
    if (memcmp(Mnemonic.data()+0, "lduwa", 5))
      break;
    if ((Features & Feature_HasV9) == Feature_HasV9)	 // "lduwa"
      Mnemonic = "lda";
    return;
  case 6:	 // 3 strings to match.
    switch (Mnemonic[0]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "ddccc", 5))
        break;
      if ((Features & Feature_HasV9) == Feature_HasV9)	 // "addccc"
        Mnemonic = "addxcc";
      return;
    case 'r':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "eturn", 5))
        break;
      if ((Features & Feature_HasV9) == Feature_HasV9)	 // "return"
        Mnemonic = "rett";
      return;
    case 's':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "ubccc", 5))
        break;
      if ((Features & Feature_HasV9) == Feature_HasV9)	 // "subccc"
        Mnemonic = "subxcc";
      return;
    }
    break;
  }
}

namespace {
enum OperatorConversionKind {
  CVT_Done,
  CVT_Reg,
  CVT_Tied,
  CVT_95_Reg,
  CVT_95_addImmOperands,
  CVT_imm_95_8,
  CVT_imm_95_13,
  CVT_imm_95_5,
  CVT_imm_95_1,
  CVT_imm_95_10,
  CVT_imm_95_11,
  CVT_imm_95_12,
  CVT_imm_95_3,
  CVT_imm_95_2,
  CVT_imm_95_4,
  CVT_imm_95_0,
  CVT_imm_95_9,
  CVT_imm_95_6,
  CVT_imm_95_14,
  CVT_regG0,
  CVT_imm_95_15,
  CVT_imm_95_7,
  CVT_regO7,
  CVT_95_addMEMriOperands,
  CVT_95_addMEMrrOperands,
  CVT_regFCC0,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Reg1_2__Reg1_0__Reg1_1,
  Convert__Reg1_2__Reg1_0__Imm1_1,
  Convert__Imm1_0__imm_95_8,
  Convert__Imm1_1__imm_95_8,
  Convert__Imm1_1__Imm1_0,
  Convert__Imm1_2__imm_95_8,
  Convert__Imm1_2__Imm1_0,
  Convert__Imm1_3__imm_95_8,
  Convert__Imm1_3__Imm1_0,
  Convert__Imm1_4__Imm1_0,
  Convert__Imm1_0,
  Convert__Imm1_0__imm_95_13,
  Convert__Imm1_1__imm_95_13,
  Convert__Imm1_2__imm_95_13,
  Convert__Imm1_3__imm_95_13,
  Convert__Reg1_1__Reg1_1__Reg1_0,
  Convert__Reg1_1__Reg1_1__Imm1_0,
  Convert__Imm1_0__imm_95_5,
  Convert__Imm1_1__imm_95_5,
  Convert__Imm1_2__imm_95_5,
  Convert__Imm1_3__imm_95_5,
  Convert__Imm1_0__imm_95_1,
  Convert__Imm1_1__imm_95_1,
  Convert__Imm1_2__imm_95_1,
  Convert__Imm1_3__imm_95_1,
  Convert__Imm1_0__imm_95_10,
  Convert__Imm1_1__imm_95_10,
  Convert__Imm1_2__imm_95_10,
  Convert__Imm1_3__imm_95_10,
  Convert__Imm1_0__imm_95_11,
  Convert__Imm1_1__imm_95_11,
  Convert__Imm1_2__imm_95_11,
  Convert__Imm1_3__imm_95_11,
  Convert__Imm1_0__imm_95_12,
  Convert__Imm1_1__imm_95_12,
  Convert__Imm1_2__imm_95_12,
  Convert__Imm1_3__imm_95_12,
  Convert__Imm1_0__imm_95_3,
  Convert__Imm1_1__imm_95_3,
  Convert__Imm1_2__imm_95_3,
  Convert__Imm1_3__imm_95_3,
  Convert__Imm1_0__imm_95_2,
  Convert__Imm1_1__imm_95_2,
  Convert__Imm1_2__imm_95_2,
  Convert__Imm1_3__imm_95_2,
  Convert__Imm1_0__imm_95_4,
  Convert__Imm1_1__imm_95_4,
  Convert__Imm1_2__imm_95_4,
  Convert__Imm1_3__imm_95_4,
  Convert__Imm1_0__imm_95_0,
  Convert__Imm1_1__imm_95_0,
  Convert__Imm1_2__imm_95_0,
  Convert__Imm1_3__imm_95_0,
  Convert__Imm1_0__imm_95_9,
  Convert__Imm1_1__imm_95_9,
  Convert__Imm1_2__imm_95_9,
  Convert__Imm1_3__imm_95_9,
  Convert__Imm1_0__imm_95_6,
  Convert__Imm1_1__imm_95_6,
  Convert__Imm1_2__imm_95_6,
  Convert__Imm1_3__imm_95_6,
  Convert__Imm1_0__imm_95_14,
  Convert__Imm1_1__imm_95_14,
  Convert__Imm1_2__imm_95_14,
  Convert__Imm1_3__imm_95_14,
  Convert__Reg1_0__Imm1_1,
  Convert__Reg1_1__Imm1_2,
  Convert__Reg1_2__Imm1_3,
  Convert__regG0__Reg1_1__Reg1_0,
  Convert__regG0__Reg1_1__Imm1_0,
  Convert__Imm1_0__imm_95_15,
  Convert__Imm1_1__imm_95_15,
  Convert__Imm1_2__imm_95_15,
  Convert__Imm1_3__imm_95_15,
  Convert__Imm1_0__imm_95_7,
  Convert__Imm1_1__imm_95_7,
  Convert__Imm1_2__imm_95_7,
  Convert__Imm1_3__imm_95_7,
  Convert__regO7__MEMri2_0,
  Convert__regO7__MEMrr2_0,
  Convert__Reg1_4__Reg1_1__Reg1_3__Tie0,
  Convert__Reg1_0__regG0__regG0,
  Convert__MEMri2_1__regG0,
  Convert__MEMrr2_1__regG0,
  Convert__Reg1_0,
  Convert__Reg1_0__Reg1_1,
  Convert__Reg1_0__Reg1_0__imm_95_1,
  Convert__Reg1_1__Reg1_0,
  Convert__Imm1_1__imm_95_0__Reg1_0,
  Convert__Imm1_2__imm_95_0__Reg1_1,
  Convert__Imm1_2__Imm1_0__Reg1_1,
  Convert__Imm1_3__imm_95_0__Reg1_2,
  Convert__Imm1_3__Imm1_0__Reg1_2,
  Convert__Imm1_4__Imm1_0__Reg1_3,
  Convert__Imm1_1__imm_95_9__Reg1_0,
  Convert__Imm1_2__imm_95_9__Reg1_1,
  Convert__Imm1_3__imm_95_9__Reg1_2,
  Convert__Imm1_1__imm_95_6__Reg1_0,
  Convert__Imm1_2__imm_95_6__Reg1_1,
  Convert__Imm1_3__imm_95_6__Reg1_2,
  Convert__Imm1_1__imm_95_11__Reg1_0,
  Convert__Imm1_2__imm_95_11__Reg1_1,
  Convert__Imm1_3__imm_95_11__Reg1_2,
  Convert__Imm1_1__imm_95_4__Reg1_0,
  Convert__Imm1_2__imm_95_4__Reg1_1,
  Convert__Imm1_3__imm_95_4__Reg1_2,
  Convert__Imm1_1__imm_95_13__Reg1_0,
  Convert__Imm1_2__imm_95_13__Reg1_1,
  Convert__Imm1_3__imm_95_13__Reg1_2,
  Convert__Imm1_1__imm_95_2__Reg1_0,
  Convert__Imm1_2__imm_95_2__Reg1_1,
  Convert__Imm1_3__imm_95_2__Reg1_2,
  Convert__Imm1_1__imm_95_8__Reg1_0,
  Convert__Imm1_2__imm_95_8__Reg1_1,
  Convert__Imm1_3__imm_95_8__Reg1_2,
  Convert__Imm1_1__imm_95_1__Reg1_0,
  Convert__Imm1_2__imm_95_1__Reg1_1,
  Convert__Imm1_3__imm_95_1__Reg1_2,
  Convert__Imm1_1__imm_95_15__Reg1_0,
  Convert__Imm1_2__imm_95_15__Reg1_1,
  Convert__Imm1_3__imm_95_15__Reg1_2,
  Convert__Imm1_1__imm_95_7__Reg1_0,
  Convert__Imm1_2__imm_95_7__Reg1_1,
  Convert__Imm1_3__imm_95_7__Reg1_2,
  Convert__Imm1_1__imm_95_10__Reg1_0,
  Convert__Imm1_2__imm_95_10__Reg1_1,
  Convert__Imm1_3__imm_95_10__Reg1_2,
  Convert__Imm1_1__imm_95_5__Reg1_0,
  Convert__Imm1_2__imm_95_5__Reg1_1,
  Convert__Imm1_3__imm_95_5__Reg1_2,
  Convert__Imm1_1__imm_95_12__Reg1_0,
  Convert__Imm1_2__imm_95_12__Reg1_1,
  Convert__Imm1_3__imm_95_12__Reg1_2,
  Convert__Imm1_1__imm_95_3__Reg1_0,
  Convert__Imm1_2__imm_95_3__Reg1_1,
  Convert__Imm1_3__imm_95_3__Reg1_2,
  Convert__Imm1_1__imm_95_14__Reg1_0,
  Convert__Imm1_2__imm_95_14__Reg1_1,
  Convert__Imm1_3__imm_95_14__Reg1_2,
  Convert__regFCC0__Reg1_0__Reg1_1,
  Convert__Reg1_0__Reg1_1__Reg1_2,
  Convert_NoOperands,
  Convert__MEMri2_0,
  Convert__MEMrr2_0,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_8,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0,
  Convert__Reg1_3__Reg1_2__Tie0__Imm1_0,
  Convert__Reg1_3__Reg1_1__Reg1_2__Tie0__Imm1_0,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_13,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_5,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_1,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_10,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_6,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_11,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_11,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_12,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_3,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_4,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_2,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_13,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_4,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_2,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_0,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_8,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_9,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_6,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_15,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_14,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_7,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_10,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_5,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_12,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_3,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_14,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_15,
  Convert__Reg1_2__Reg1_1__Tie0__imm_95_7,
  Convert__Reg1_0__Tie0,
  Convert__regG0__MEMri2_0,
  Convert__regG0__MEMrr2_0,
  Convert__Reg1_1__MEMri2_0,
  Convert__Reg1_1__MEMrr2_0,
  Convert__MEMri2_1,
  Convert__Reg1_3__MEMri2_1,
  Convert__MEMrr2_1,
  Convert__Reg1_3__MEMrr2_1,
  Convert__Reg1_4__MEMrr2_1__Imm1_3,
  Convert__Reg1_1,
  Convert__regG0__Reg1_0,
  Convert__Reg1_1__regG0__Reg1_0,
  Convert__regG0__Imm1_0,
  Convert__Reg1_1__regG0__Imm1_0,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_8,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_0,
  Convert__Reg1_3__Imm1_2__Tie0__Imm1_0,
  Convert__Reg1_3__Reg1_1__Imm1_2__Tie0__Imm1_0,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_13,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_5,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_1,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_9,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_10,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_6,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_11,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_11,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_12,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_3,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_4,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_2,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_13,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_4,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_2,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_0,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_8,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_9,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_1,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_6,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_15,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_14,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_7,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_10,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_5,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_12,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_3,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_14,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_15,
  Convert__Reg1_2__Imm1_1__Tie0__imm_95_7,
  Convert__Reg1_0__regG0__Reg1_0,
  Convert__Reg1_0__Reg1_0__regG0,
  Convert__Reg1_1__Reg1_0__regG0,
  Convert__regG0__regG0__regG0,
  Convert__imm_95_8,
  Convert__Reg1_1__Imm1_0,
  Convert__MEMri2_2,
  Convert__MEMrr2_2,
  Convert__MEMri2_2__Reg1_0,
  Convert__MEMrr2_2__Reg1_0,
  Convert__MEMrr2_2__Reg1_0__Imm1_4,
  Convert__Reg1_3__MEMri2_1__Tie0,
  Convert__Reg1_3__MEMrr2_1__Tie0,
  Convert__Reg1_4__MEMrr2_1__Imm1_3__Tie0,
  Convert__regG0__Reg1_0__imm_95_8,
  Convert__regG0__Imm1_0__imm_95_8,
  Convert__regG0__Reg1_1__imm_95_8,
  Convert__regG0__Imm1_1__imm_95_8,
  Convert__Reg1_0__Reg1_2__imm_95_8,
  Convert__Reg1_0__Imm1_2__imm_95_8,
  Convert__Reg1_1__Reg1_3__imm_95_8,
  Convert__Reg1_1__Imm1_3__imm_95_8,
  Convert__Reg1_2__Reg1_4__Imm1_0,
  Convert__Reg1_2__Imm1_4__Imm1_0,
  Convert__regG0__Reg1_0__imm_95_13,
  Convert__regG0__Imm1_0__imm_95_13,
  Convert__regG0__Reg1_1__imm_95_13,
  Convert__regG0__Imm1_1__imm_95_13,
  Convert__Reg1_0__Reg1_2__imm_95_13,
  Convert__Reg1_0__Imm1_2__imm_95_13,
  Convert__Reg1_1__Reg1_3__imm_95_13,
  Convert__Reg1_1__Imm1_3__imm_95_13,
  Convert__regG0__Reg1_0__imm_95_5,
  Convert__regG0__Imm1_0__imm_95_5,
  Convert__regG0__Reg1_1__imm_95_5,
  Convert__regG0__Imm1_1__imm_95_5,
  Convert__Reg1_0__Reg1_2__imm_95_5,
  Convert__Reg1_0__Imm1_2__imm_95_5,
  Convert__Reg1_1__Reg1_3__imm_95_5,
  Convert__Reg1_1__Imm1_3__imm_95_5,
  Convert__regG0__Reg1_0__imm_95_1,
  Convert__regG0__Imm1_0__imm_95_1,
  Convert__regG0__Reg1_1__imm_95_1,
  Convert__regG0__Imm1_1__imm_95_1,
  Convert__Reg1_0__Reg1_2__imm_95_1,
  Convert__Reg1_0__Imm1_2__imm_95_1,
  Convert__Reg1_1__Reg1_3__imm_95_1,
  Convert__Reg1_1__Imm1_3__imm_95_1,
  Convert__regG0__Reg1_0__imm_95_10,
  Convert__regG0__Imm1_0__imm_95_10,
  Convert__regG0__Reg1_1__imm_95_10,
  Convert__regG0__Imm1_1__imm_95_10,
  Convert__Reg1_0__Reg1_2__imm_95_10,
  Convert__Reg1_0__Imm1_2__imm_95_10,
  Convert__Reg1_1__Reg1_3__imm_95_10,
  Convert__Reg1_1__Imm1_3__imm_95_10,
  Convert__regG0__Reg1_0__imm_95_11,
  Convert__regG0__Imm1_0__imm_95_11,
  Convert__regG0__Reg1_1__imm_95_11,
  Convert__regG0__Imm1_1__imm_95_11,
  Convert__Reg1_0__Reg1_2__imm_95_11,
  Convert__Reg1_0__Imm1_2__imm_95_11,
  Convert__Reg1_1__Reg1_3__imm_95_11,
  Convert__Reg1_1__Imm1_3__imm_95_11,
  Convert__regG0__Reg1_0__imm_95_12,
  Convert__regG0__Imm1_0__imm_95_12,
  Convert__regG0__Reg1_1__imm_95_12,
  Convert__regG0__Imm1_1__imm_95_12,
  Convert__Reg1_0__Reg1_2__imm_95_12,
  Convert__Reg1_0__Imm1_2__imm_95_12,
  Convert__Reg1_1__Reg1_3__imm_95_12,
  Convert__Reg1_1__Imm1_3__imm_95_12,
  Convert__regG0__Reg1_0__imm_95_3,
  Convert__regG0__Imm1_0__imm_95_3,
  Convert__regG0__Reg1_1__imm_95_3,
  Convert__regG0__Imm1_1__imm_95_3,
  Convert__Reg1_0__Reg1_2__imm_95_3,
  Convert__Reg1_0__Imm1_2__imm_95_3,
  Convert__Reg1_1__Reg1_3__imm_95_3,
  Convert__Reg1_1__Imm1_3__imm_95_3,
  Convert__regG0__Reg1_0__imm_95_2,
  Convert__regG0__Imm1_0__imm_95_2,
  Convert__regG0__Reg1_1__imm_95_2,
  Convert__regG0__Imm1_1__imm_95_2,
  Convert__Reg1_0__Reg1_2__imm_95_2,
  Convert__Reg1_0__Imm1_2__imm_95_2,
  Convert__Reg1_1__Reg1_3__imm_95_2,
  Convert__Reg1_1__Imm1_3__imm_95_2,
  Convert__regG0__Reg1_0__imm_95_4,
  Convert__regG0__Imm1_0__imm_95_4,
  Convert__regG0__Reg1_1__imm_95_4,
  Convert__regG0__Imm1_1__imm_95_4,
  Convert__Reg1_0__Reg1_2__imm_95_4,
  Convert__Reg1_0__Imm1_2__imm_95_4,
  Convert__Reg1_1__Reg1_3__imm_95_4,
  Convert__Reg1_1__Imm1_3__imm_95_4,
  Convert__regG0__Reg1_0__imm_95_0,
  Convert__regG0__Imm1_0__imm_95_0,
  Convert__regG0__Reg1_1__imm_95_0,
  Convert__regG0__Imm1_1__imm_95_0,
  Convert__Reg1_0__Reg1_2__imm_95_0,
  Convert__Reg1_0__Imm1_2__imm_95_0,
  Convert__Reg1_1__Reg1_3__imm_95_0,
  Convert__Reg1_1__Imm1_3__imm_95_0,
  Convert__regG0__Reg1_0__imm_95_9,
  Convert__regG0__Imm1_0__imm_95_9,
  Convert__regG0__Reg1_1__imm_95_9,
  Convert__regG0__Imm1_1__imm_95_9,
  Convert__Reg1_0__Reg1_2__imm_95_9,
  Convert__Reg1_0__Imm1_2__imm_95_9,
  Convert__Reg1_1__Reg1_3__imm_95_9,
  Convert__Reg1_1__Imm1_3__imm_95_9,
  Convert__regG0__Reg1_0__imm_95_6,
  Convert__regG0__Imm1_0__imm_95_6,
  Convert__regG0__Reg1_1__imm_95_6,
  Convert__regG0__Imm1_1__imm_95_6,
  Convert__Reg1_0__Reg1_2__imm_95_6,
  Convert__Reg1_0__Imm1_2__imm_95_6,
  Convert__Reg1_1__Reg1_3__imm_95_6,
  Convert__Reg1_1__Imm1_3__imm_95_6,
  Convert__regG0__Reg1_0__imm_95_14,
  Convert__regG0__Imm1_0__imm_95_14,
  Convert__regG0__Reg1_1__imm_95_14,
  Convert__regG0__Imm1_1__imm_95_14,
  Convert__Reg1_0__Reg1_2__imm_95_14,
  Convert__Reg1_0__Imm1_2__imm_95_14,
  Convert__Reg1_1__Reg1_3__imm_95_14,
  Convert__Reg1_1__Imm1_3__imm_95_14,
  Convert__regG0__Reg1_0__regG0,
  Convert__regG0__Reg1_0__imm_95_15,
  Convert__regG0__Imm1_0__imm_95_15,
  Convert__regG0__Reg1_1__imm_95_15,
  Convert__regG0__Imm1_1__imm_95_15,
  Convert__Reg1_0__Reg1_2__imm_95_15,
  Convert__Reg1_0__Imm1_2__imm_95_15,
  Convert__Reg1_1__Reg1_3__imm_95_15,
  Convert__Reg1_1__Imm1_3__imm_95_15,
  Convert__regG0__Reg1_0__imm_95_7,
  Convert__regG0__Imm1_0__imm_95_7,
  Convert__regG0__Reg1_1__imm_95_7,
  Convert__regG0__Imm1_1__imm_95_7,
  Convert__Reg1_0__Reg1_2__imm_95_7,
  Convert__Reg1_0__Imm1_2__imm_95_7,
  Convert__Reg1_1__Reg1_3__imm_95_7,
  Convert__Reg1_1__Imm1_3__imm_95_7,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][11] = {
  // Convert__Reg1_2__Reg1_0__Reg1_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_0__imm_95_8
  { CVT_95_addImmOperands, 1, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_8
  { CVT_95_addImmOperands, 2, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Imm1_1__Imm1_0
  { CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_8
  { CVT_95_addImmOperands, 3, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Imm1_2__Imm1_0
  { CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Imm1_3__imm_95_8
  { CVT_95_addImmOperands, 4, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Imm1_3__Imm1_0
  { CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Imm1_4__Imm1_0
  { CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Imm1_0__imm_95_13
  { CVT_95_addImmOperands, 1, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_13
  { CVT_95_addImmOperands, 2, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_13
  { CVT_95_addImmOperands, 3, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_13
  { CVT_95_addImmOperands, 4, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_1__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_1__Imm1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Imm1_0__imm_95_5
  { CVT_95_addImmOperands, 1, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_5
  { CVT_95_addImmOperands, 2, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_5
  { CVT_95_addImmOperands, 3, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_5
  { CVT_95_addImmOperands, 4, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_1
  { CVT_95_addImmOperands, 1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_1
  { CVT_95_addImmOperands, 2, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_1
  { CVT_95_addImmOperands, 4, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_10
  { CVT_95_addImmOperands, 1, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_10
  { CVT_95_addImmOperands, 2, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_10
  { CVT_95_addImmOperands, 3, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_10
  { CVT_95_addImmOperands, 4, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_11
  { CVT_95_addImmOperands, 1, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_11
  { CVT_95_addImmOperands, 2, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_11
  { CVT_95_addImmOperands, 3, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_11
  { CVT_95_addImmOperands, 4, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_12
  { CVT_95_addImmOperands, 1, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_12
  { CVT_95_addImmOperands, 2, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_12
  { CVT_95_addImmOperands, 3, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_12
  { CVT_95_addImmOperands, 4, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_3
  { CVT_95_addImmOperands, 1, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_3
  { CVT_95_addImmOperands, 2, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_3
  { CVT_95_addImmOperands, 3, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_3
  { CVT_95_addImmOperands, 4, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_2
  { CVT_95_addImmOperands, 1, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_2
  { CVT_95_addImmOperands, 2, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_2
  { CVT_95_addImmOperands, 3, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_4
  { CVT_95_addImmOperands, 1, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_4
  { CVT_95_addImmOperands, 2, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_4
  { CVT_95_addImmOperands, 3, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_4
  { CVT_95_addImmOperands, 4, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_0
  { CVT_95_addImmOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_0
  { CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_0
  { CVT_95_addImmOperands, 4, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_9
  { CVT_95_addImmOperands, 1, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_9
  { CVT_95_addImmOperands, 2, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_9
  { CVT_95_addImmOperands, 3, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_9
  { CVT_95_addImmOperands, 4, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_6
  { CVT_95_addImmOperands, 1, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_6
  { CVT_95_addImmOperands, 2, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_6
  { CVT_95_addImmOperands, 3, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_6
  { CVT_95_addImmOperands, 4, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_14
  { CVT_95_addImmOperands, 1, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_14
  { CVT_95_addImmOperands, 2, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_14
  { CVT_95_addImmOperands, 3, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_14
  { CVT_95_addImmOperands, 4, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_1__Imm1_2
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_2__Imm1_3
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__regG0__Reg1_1__Reg1_0
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__regG0__Reg1_1__Imm1_0
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Imm1_0__imm_95_15
  { CVT_95_addImmOperands, 1, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_15
  { CVT_95_addImmOperands, 2, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_15
  { CVT_95_addImmOperands, 3, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_15
  { CVT_95_addImmOperands, 4, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Imm1_0__imm_95_7
  { CVT_95_addImmOperands, 1, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Imm1_1__imm_95_7
  { CVT_95_addImmOperands, 2, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Imm1_2__imm_95_7
  { CVT_95_addImmOperands, 3, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Imm1_3__imm_95_7
  { CVT_95_addImmOperands, 4, CVT_imm_95_7, 0, CVT_Done },
  // Convert__regO7__MEMri2_0
  { CVT_regO7, 0, CVT_95_addMEMriOperands, 1, CVT_Done },
  // Convert__regO7__MEMrr2_0
  { CVT_regO7, 0, CVT_95_addMEMrrOperands, 1, CVT_Done },
  // Convert__Reg1_4__Reg1_1__Reg1_3__Tie0
  { CVT_95_Reg, 5, CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_Tied, 0, CVT_Done },
  // Convert__Reg1_0__regG0__regG0
  { CVT_95_Reg, 1, CVT_regG0, 0, CVT_regG0, 0, CVT_Done },
  // Convert__MEMri2_1__regG0
  { CVT_95_addMEMriOperands, 2, CVT_regG0, 0, CVT_Done },
  // Convert__MEMrr2_1__regG0
  { CVT_95_addMEMrrOperands, 2, CVT_regG0, 0, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_0__imm_95_1
  { CVT_95_Reg, 1, CVT_95_Reg, 1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_1__imm_95_0__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_0, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__Imm1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_0__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_0, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_3__Imm1_0__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 1, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_4__Imm1_0__Reg1_3
  { CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 1, CVT_95_Reg, 4, CVT_Done },
  // Convert__Imm1_1__imm_95_9__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_9, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_9__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_9, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_9__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_9, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_6__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_6, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_6__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_6, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_6__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_6, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_11__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_11, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_11__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_11, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_11__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_11, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_4__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_4, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_4__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_4, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_4__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_4, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_13__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_13, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_13__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_13, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_13__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_13, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_2__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_2, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_2__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_2, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_2__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_2, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_8__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_8, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_8__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_8, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_8__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_8, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_1__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_1, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_1__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_1, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_1__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_1, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_15__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_15, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_15__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_15, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_15__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_15, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_7__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_7, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_7__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_7, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_7__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_7, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_10__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_10, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_10__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_10, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_10__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_10, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_5__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_5, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_5__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_5, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_5__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_5, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_12__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_12, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_12__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_12, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_12__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_12, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_3__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_3, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_3__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_3, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_3__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_3, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_14__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_14, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_14__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_14, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_14__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_14, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__regFCC0__Reg1_0__Reg1_1
  { CVT_regFCC0, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__MEMri2_0
  { CVT_95_addMEMriOperands, 1, CVT_Done },
  // Convert__MEMrr2_0
  { CVT_95_addMEMrrOperands, 1, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_8
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_3__Reg1_2__Tie0__Imm1_0
  { CVT_95_Reg, 4, CVT_95_Reg, 3, CVT_Tied, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_3__Reg1_1__Reg1_2__Tie0__Imm1_0
  { CVT_95_Reg, 4, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Tied, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_13
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_5
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_1
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_10
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_6
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_11
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_11
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_12
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_3
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_4
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_2
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_13
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_4
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_2
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_0
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_8
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_9
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_6
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_15
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_14
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_7
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_10
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_5
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_12
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_3
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_14
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_15
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0__imm_95_7
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, 0, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_0__Tie0
  { CVT_95_Reg, 1, CVT_Tied, 0, CVT_Done },
  // Convert__regG0__MEMri2_0
  { CVT_regG0, 0, CVT_95_addMEMriOperands, 1, CVT_Done },
  // Convert__regG0__MEMrr2_0
  { CVT_regG0, 0, CVT_95_addMEMrrOperands, 1, CVT_Done },
  // Convert__Reg1_1__MEMri2_0
  { CVT_95_Reg, 2, CVT_95_addMEMriOperands, 1, CVT_Done },
  // Convert__Reg1_1__MEMrr2_0
  { CVT_95_Reg, 2, CVT_95_addMEMrrOperands, 1, CVT_Done },
  // Convert__MEMri2_1
  { CVT_95_addMEMriOperands, 2, CVT_Done },
  // Convert__Reg1_3__MEMri2_1
  { CVT_95_Reg, 4, CVT_95_addMEMriOperands, 2, CVT_Done },
  // Convert__MEMrr2_1
  { CVT_95_addMEMrrOperands, 2, CVT_Done },
  // Convert__Reg1_3__MEMrr2_1
  { CVT_95_Reg, 4, CVT_95_addMEMrrOperands, 2, CVT_Done },
  // Convert__Reg1_4__MEMrr2_1__Imm1_3
  { CVT_95_Reg, 5, CVT_95_addMEMrrOperands, 2, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_1
  { CVT_95_Reg, 2, CVT_Done },
  // Convert__regG0__Reg1_0
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__regG0__Reg1_0
  { CVT_95_Reg, 2, CVT_regG0, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__regG0__Imm1_0
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__regG0__Imm1_0
  { CVT_95_Reg, 2, CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_8
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_0
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_3__Imm1_2__Tie0__Imm1_0
  { CVT_95_Reg, 4, CVT_95_addImmOperands, 3, CVT_Tied, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_3__Reg1_1__Imm1_2__Tie0__Imm1_0
  { CVT_95_Reg, 4, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Tied, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_13
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_5
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_1
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_9
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_10
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_6
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_11
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_11
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_12
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_3
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_4
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_2
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_13
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_4
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_2
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_0
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_8
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_9
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_6
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_15
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_14
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_7
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_10
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_5
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_12
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_3
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_14
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_15
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0__imm_95_7
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, 0, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_0__regG0__Reg1_0
  { CVT_95_Reg, 1, CVT_regG0, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_0__regG0
  { CVT_95_Reg, 1, CVT_95_Reg, 1, CVT_regG0, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_0__regG0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_regG0, 0, CVT_Done },
  // Convert__regG0__regG0__regG0
  { CVT_regG0, 0, CVT_regG0, 0, CVT_regG0, 0, CVT_Done },
  // Convert__imm_95_8
  { CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_0
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__MEMri2_2
  { CVT_95_addMEMriOperands, 3, CVT_Done },
  // Convert__MEMrr2_2
  { CVT_95_addMEMrrOperands, 3, CVT_Done },
  // Convert__MEMri2_2__Reg1_0
  { CVT_95_addMEMriOperands, 3, CVT_95_Reg, 1, CVT_Done },
  // Convert__MEMrr2_2__Reg1_0
  { CVT_95_addMEMrrOperands, 3, CVT_95_Reg, 1, CVT_Done },
  // Convert__MEMrr2_2__Reg1_0__Imm1_4
  { CVT_95_addMEMrrOperands, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__Reg1_3__MEMri2_1__Tie0
  { CVT_95_Reg, 4, CVT_95_addMEMriOperands, 2, CVT_Tied, 0, CVT_Done },
  // Convert__Reg1_3__MEMrr2_1__Tie0
  { CVT_95_Reg, 4, CVT_95_addMEMrrOperands, 2, CVT_Tied, 0, CVT_Done },
  // Convert__Reg1_4__MEMrr2_1__Imm1_3__Tie0
  { CVT_95_Reg, 5, CVT_95_addMEMrrOperands, 2, CVT_95_addImmOperands, 4, CVT_Tied, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_8
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_8, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_8
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_8, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_8
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_8, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_8
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_8
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_8
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_8
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_8
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_4__Imm1_0
  { CVT_95_Reg, 3, CVT_95_Reg, 5, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_2__Imm1_4__Imm1_0
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_13
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_13, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_13
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_13, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_13
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_13, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_13
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_13
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_13
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_13
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_13
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_13, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_5
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_5, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_5
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_5, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_5
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_5, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_5
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_5
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_5
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_5
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_5
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_5, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_1
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_1
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_1
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_1, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_1
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_1
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_1
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_1
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_1, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_10
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_10, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_10
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_10, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_10
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_10, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_10
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_10
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_10
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_10
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_10
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_10, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_11
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_11, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_11
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_11, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_11
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_11, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_11
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_11
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_11
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_11
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_11
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_11, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_12
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_12, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_12
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_12, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_12
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_12, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_12
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_12
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_12
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_12
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_12
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_12, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_3
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_3, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_3
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_3, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_3
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_3, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_3
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_3
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_3
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_3
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_3, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_2
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_2, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_2
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_2, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_2
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_2, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_2
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_2
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_2
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_2
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_2
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_2, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_4
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_4, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_4
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_4, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_4
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_4, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_4
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_4
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_4
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_4
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_4
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_4, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_0
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_0
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_0
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_0
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_0
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_0
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_0
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_0
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_0, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_9
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_9, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_9
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_9, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_9
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_9, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_9
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_9
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_9
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_9
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_9
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_9, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_6
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_6, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_6
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_6, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_6
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_6, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_6
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_6
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_6
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_6
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_6
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_6, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_14
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_14, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_14
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_14, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_14
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_14, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_14
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_14
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_14
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_14
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_14
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_14, 0, CVT_Done },
  // Convert__regG0__Reg1_0__regG0
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_regG0, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_15
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_15, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_15
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_15, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_15
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_15, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_15
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_15
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_15
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_15
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_15
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_15, 0, CVT_Done },
  // Convert__regG0__Reg1_0__imm_95_7
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_imm_95_7, 0, CVT_Done },
  // Convert__regG0__Imm1_0__imm_95_7
  { CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_imm_95_7, 0, CVT_Done },
  // Convert__regG0__Reg1_1__imm_95_7
  { CVT_regG0, 0, CVT_95_Reg, 2, CVT_imm_95_7, 0, CVT_Done },
  // Convert__regG0__Imm1_1__imm_95_7
  { CVT_regG0, 0, CVT_95_addImmOperands, 2, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_2__imm_95_7
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_0__Imm1_2__imm_95_7
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_3__imm_95_7
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_3__imm_95_7
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_imm_95_7, 0, CVT_Done },
};

void SparcAsmParser::
convertToMCInst(unsigned Kind, MCInst &Inst, unsigned Opcode,
                const OperandVector &Operands) {
  assert(Kind < CVT_NUM_SIGNATURES && "Invalid signature!");
  const uint8_t *Converter = ConversionTable[Kind];
  Inst.setOpcode(Opcode);
  for (const uint8_t *p = Converter; *p; p+= 2) {
    switch (*p) {
    default: llvm_unreachable("invalid conversion entry!");
    case CVT_Reg:
      static_cast<SparcOperand&>(*Operands[*(p + 1)]).addRegOperands(Inst, 1);
      break;
    case CVT_Tied:
      Inst.addOperand(Inst.getOperand(*(p + 1)));
      break;
    case CVT_95_Reg:
      static_cast<SparcOperand&>(*Operands[*(p + 1)]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addImmOperands:
      static_cast<SparcOperand&>(*Operands[*(p + 1)]).addImmOperands(Inst, 1);
      break;
    case CVT_imm_95_8:
      Inst.addOperand(MCOperand::createImm(8));
      break;
    case CVT_imm_95_13:
      Inst.addOperand(MCOperand::createImm(13));
      break;
    case CVT_imm_95_5:
      Inst.addOperand(MCOperand::createImm(5));
      break;
    case CVT_imm_95_1:
      Inst.addOperand(MCOperand::createImm(1));
      break;
    case CVT_imm_95_10:
      Inst.addOperand(MCOperand::createImm(10));
      break;
    case CVT_imm_95_11:
      Inst.addOperand(MCOperand::createImm(11));
      break;
    case CVT_imm_95_12:
      Inst.addOperand(MCOperand::createImm(12));
      break;
    case CVT_imm_95_3:
      Inst.addOperand(MCOperand::createImm(3));
      break;
    case CVT_imm_95_2:
      Inst.addOperand(MCOperand::createImm(2));
      break;
    case CVT_imm_95_4:
      Inst.addOperand(MCOperand::createImm(4));
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_imm_95_9:
      Inst.addOperand(MCOperand::createImm(9));
      break;
    case CVT_imm_95_6:
      Inst.addOperand(MCOperand::createImm(6));
      break;
    case CVT_imm_95_14:
      Inst.addOperand(MCOperand::createImm(14));
      break;
    case CVT_regG0:
      Inst.addOperand(MCOperand::createReg(SP::G0));
      break;
    case CVT_imm_95_15:
      Inst.addOperand(MCOperand::createImm(15));
      break;
    case CVT_imm_95_7:
      Inst.addOperand(MCOperand::createImm(7));
      break;
    case CVT_regO7:
      Inst.addOperand(MCOperand::createReg(SP::O7));
      break;
    case CVT_95_addMEMriOperands:
      static_cast<SparcOperand&>(*Operands[*(p + 1)]).addMEMriOperands(Inst, 2);
      break;
    case CVT_95_addMEMrrOperands:
      static_cast<SparcOperand&>(*Operands[*(p + 1)]).addMEMrrOperands(Inst, 2);
      break;
    case CVT_regFCC0:
      Inst.addOperand(MCOperand::createReg(SP::FCC0));
      break;
    }
  }
}

void SparcAsmParser::
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
    case CVT_95_addImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_8:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_13:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_5:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_1:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_10:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_11:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_12:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_3:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
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
    case CVT_imm_95_0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_9:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_6:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_14:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_regG0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_imm_95_15:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_7:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_regO7:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addMEMriOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 2;
      break;
    case CVT_95_addMEMrrOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 2;
      break;
    case CVT_regFCC0:
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
  MCK__PCT_fcc0, // '%fcc0'
  MCK__PCT_fsr, // '%fsr'
  MCK__PCT_g0, // '%g0'
  MCK__PCT_icc, // '%icc'
  MCK__PCT_psr, // '%psr'
  MCK__PCT_tbr, // '%tbr'
  MCK__PCT_wim, // '%wim'
  MCK__PCT_xcc, // '%xcc'
  MCK__43_, // '+'
  MCK_3, // '3'
  MCK_5, // '5'
  MCK__91_, // '['
  MCK__93_, // ']'
  MCK_a, // 'a'
  MCK_pn, // 'pn'
  MCK_pt, // 'pt'
  MCK_FCCRegs, // register class 'FCCRegs'
  MCK_Reg7, // derived register class
  MCK_PRRegs, // register class 'PRRegs'
  MCK_Reg5, // derived register class
  MCK_IntPair, // register class 'IntPair'
  MCK_QFPRegs, // register class 'QFPRegs'
  MCK_ASRRegs, // register class 'ASRRegs'
  MCK_DFPRegs, // register class 'DFPRegs'
  MCK_FPRegs, // register class 'FPRegs'
  MCK_IntRegs, // register class 'IntRegs,I64Regs'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_MEMri, // user defined class 'SparcMEMriAsmOperand'
  MCK_MEMrr, // user defined class 'SparcMEMrrAsmOperand'
  NumMatchClassKinds
};

}

static MatchClassKind matchTokenString(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 6 strings to match.
    switch (Name[0]) {
    default: break;
    case '+':	 // 1 string to match.
      return MCK__43_;	 // "+"
    case '3':	 // 1 string to match.
      return MCK_3;	 // "3"
    case '5':	 // 1 string to match.
      return MCK_5;	 // "5"
    case '[':	 // 1 string to match.
      return MCK__91_;	 // "["
    case ']':	 // 1 string to match.
      return MCK__93_;	 // "]"
    case 'a':	 // 1 string to match.
      return MCK_a;	 // "a"
    }
    break;
  case 2:	 // 2 strings to match.
    if (Name[0] != 'p')
      break;
    switch (Name[1]) {
    default: break;
    case 'n':	 // 1 string to match.
      return MCK_pn;	 // "pn"
    case 't':	 // 1 string to match.
      return MCK_pt;	 // "pt"
    }
    break;
  case 3:	 // 1 string to match.
    if (memcmp(Name.data()+0, "%g0", 3))
      break;
    return MCK__PCT_g0;	 // "%g0"
  case 4:	 // 6 strings to match.
    if (Name[0] != '%')
      break;
    switch (Name[1]) {
    default: break;
    case 'f':	 // 1 string to match.
      if (memcmp(Name.data()+2, "sr", 2))
        break;
      return MCK__PCT_fsr;	 // "%fsr"
    case 'i':	 // 1 string to match.
      if (memcmp(Name.data()+2, "cc", 2))
        break;
      return MCK__PCT_icc;	 // "%icc"
    case 'p':	 // 1 string to match.
      if (memcmp(Name.data()+2, "sr", 2))
        break;
      return MCK__PCT_psr;	 // "%psr"
    case 't':	 // 1 string to match.
      if (memcmp(Name.data()+2, "br", 2))
        break;
      return MCK__PCT_tbr;	 // "%tbr"
    case 'w':	 // 1 string to match.
      if (memcmp(Name.data()+2, "im", 2))
        break;
      return MCK__PCT_wim;	 // "%wim"
    case 'x':	 // 1 string to match.
      if (memcmp(Name.data()+2, "cc", 2))
        break;
      return MCK__PCT_xcc;	 // "%xcc"
    }
    break;
  case 5:	 // 1 string to match.
    if (memcmp(Name.data()+0, "%fcc0", 5))
      break;
    return MCK__PCT_fcc0;	 // "%fcc0"
  }
  return InvalidMatchClass;
}

/// isSubclass - Compute whether \p A is a subclass of \p B.
static bool isSubclass(MatchClassKind A, MatchClassKind B) {
  if (A == B)
    return true;

  switch (A) {
  default:
    return false;

  case MCK_Reg7:
    return B == MCK_QFPRegs;

  case MCK_Reg5:
    return B == MCK_DFPRegs;
  }
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind) {
  SparcOperand &Operand = (SparcOperand&)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken())
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  // 'Imm' class
  if (Kind == MCK_Imm) {
    if (Operand.isImm())
      return MCTargetAsmParser::Match_Success;
  }

  // 'MEMri' class
  if (Kind == MCK_MEMri) {
    if (Operand.isMEMri())
      return MCTargetAsmParser::Match_Success;
  }

  // 'MEMrr' class
  if (Kind == MCK_MEMrr) {
    if (Operand.isMEMrr())
      return MCTargetAsmParser::Match_Success;
  }

  if (Operand.isReg()) {
    MatchClassKind OpKind;
    switch (Operand.getReg()) {
    default: OpKind = InvalidMatchClass; break;
    case Sparc::FCC0: OpKind = MCK_FCCRegs; break;
    case Sparc::FCC1: OpKind = MCK_FCCRegs; break;
    case Sparc::FCC2: OpKind = MCK_FCCRegs; break;
    case Sparc::FCC3: OpKind = MCK_FCCRegs; break;
    case Sparc::Y: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR1: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR2: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR3: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR4: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR5: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR6: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR7: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR8: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR9: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR10: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR11: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR12: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR13: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR14: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR15: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR16: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR17: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR18: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR19: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR20: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR21: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR22: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR23: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR24: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR25: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR26: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR27: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR28: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR29: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR30: OpKind = MCK_ASRRegs; break;
    case Sparc::ASR31: OpKind = MCK_ASRRegs; break;
    case Sparc::TPC: OpKind = MCK_PRRegs; break;
    case Sparc::TNPC: OpKind = MCK_PRRegs; break;
    case Sparc::TSTATE: OpKind = MCK_PRRegs; break;
    case Sparc::TT: OpKind = MCK_PRRegs; break;
    case Sparc::TICK: OpKind = MCK_PRRegs; break;
    case Sparc::TBA: OpKind = MCK_PRRegs; break;
    case Sparc::PSTATE: OpKind = MCK_PRRegs; break;
    case Sparc::TL: OpKind = MCK_PRRegs; break;
    case Sparc::PIL: OpKind = MCK_PRRegs; break;
    case Sparc::CWP: OpKind = MCK_PRRegs; break;
    case Sparc::CANSAVE: OpKind = MCK_PRRegs; break;
    case Sparc::CANRESTORE: OpKind = MCK_PRRegs; break;
    case Sparc::CLEANWIN: OpKind = MCK_PRRegs; break;
    case Sparc::OTHERWIN: OpKind = MCK_PRRegs; break;
    case Sparc::WSTATE: OpKind = MCK_PRRegs; break;
    case Sparc::G0: OpKind = MCK_IntRegs; break;
    case Sparc::G1: OpKind = MCK_IntRegs; break;
    case Sparc::G2: OpKind = MCK_IntRegs; break;
    case Sparc::G3: OpKind = MCK_IntRegs; break;
    case Sparc::G4: OpKind = MCK_IntRegs; break;
    case Sparc::G5: OpKind = MCK_IntRegs; break;
    case Sparc::G6: OpKind = MCK_IntRegs; break;
    case Sparc::G7: OpKind = MCK_IntRegs; break;
    case Sparc::O0: OpKind = MCK_IntRegs; break;
    case Sparc::O1: OpKind = MCK_IntRegs; break;
    case Sparc::O2: OpKind = MCK_IntRegs; break;
    case Sparc::O3: OpKind = MCK_IntRegs; break;
    case Sparc::O4: OpKind = MCK_IntRegs; break;
    case Sparc::O5: OpKind = MCK_IntRegs; break;
    case Sparc::O6: OpKind = MCK_IntRegs; break;
    case Sparc::O7: OpKind = MCK_IntRegs; break;
    case Sparc::L0: OpKind = MCK_IntRegs; break;
    case Sparc::L1: OpKind = MCK_IntRegs; break;
    case Sparc::L2: OpKind = MCK_IntRegs; break;
    case Sparc::L3: OpKind = MCK_IntRegs; break;
    case Sparc::L4: OpKind = MCK_IntRegs; break;
    case Sparc::L5: OpKind = MCK_IntRegs; break;
    case Sparc::L6: OpKind = MCK_IntRegs; break;
    case Sparc::L7: OpKind = MCK_IntRegs; break;
    case Sparc::I0: OpKind = MCK_IntRegs; break;
    case Sparc::I1: OpKind = MCK_IntRegs; break;
    case Sparc::I2: OpKind = MCK_IntRegs; break;
    case Sparc::I3: OpKind = MCK_IntRegs; break;
    case Sparc::I4: OpKind = MCK_IntRegs; break;
    case Sparc::I5: OpKind = MCK_IntRegs; break;
    case Sparc::I6: OpKind = MCK_IntRegs; break;
    case Sparc::I7: OpKind = MCK_IntRegs; break;
    case Sparc::F0: OpKind = MCK_FPRegs; break;
    case Sparc::F1: OpKind = MCK_FPRegs; break;
    case Sparc::F2: OpKind = MCK_FPRegs; break;
    case Sparc::F3: OpKind = MCK_FPRegs; break;
    case Sparc::F4: OpKind = MCK_FPRegs; break;
    case Sparc::F5: OpKind = MCK_FPRegs; break;
    case Sparc::F6: OpKind = MCK_FPRegs; break;
    case Sparc::F7: OpKind = MCK_FPRegs; break;
    case Sparc::F8: OpKind = MCK_FPRegs; break;
    case Sparc::F9: OpKind = MCK_FPRegs; break;
    case Sparc::F10: OpKind = MCK_FPRegs; break;
    case Sparc::F11: OpKind = MCK_FPRegs; break;
    case Sparc::F12: OpKind = MCK_FPRegs; break;
    case Sparc::F13: OpKind = MCK_FPRegs; break;
    case Sparc::F14: OpKind = MCK_FPRegs; break;
    case Sparc::F15: OpKind = MCK_FPRegs; break;
    case Sparc::F16: OpKind = MCK_FPRegs; break;
    case Sparc::F17: OpKind = MCK_FPRegs; break;
    case Sparc::F18: OpKind = MCK_FPRegs; break;
    case Sparc::F19: OpKind = MCK_FPRegs; break;
    case Sparc::F20: OpKind = MCK_FPRegs; break;
    case Sparc::F21: OpKind = MCK_FPRegs; break;
    case Sparc::F22: OpKind = MCK_FPRegs; break;
    case Sparc::F23: OpKind = MCK_FPRegs; break;
    case Sparc::F24: OpKind = MCK_FPRegs; break;
    case Sparc::F25: OpKind = MCK_FPRegs; break;
    case Sparc::F26: OpKind = MCK_FPRegs; break;
    case Sparc::F27: OpKind = MCK_FPRegs; break;
    case Sparc::F28: OpKind = MCK_FPRegs; break;
    case Sparc::F29: OpKind = MCK_FPRegs; break;
    case Sparc::F30: OpKind = MCK_FPRegs; break;
    case Sparc::F31: OpKind = MCK_FPRegs; break;
    case Sparc::D0: OpKind = MCK_Reg5; break;
    case Sparc::D1: OpKind = MCK_Reg5; break;
    case Sparc::D2: OpKind = MCK_Reg5; break;
    case Sparc::D3: OpKind = MCK_Reg5; break;
    case Sparc::D4: OpKind = MCK_Reg5; break;
    case Sparc::D5: OpKind = MCK_Reg5; break;
    case Sparc::D6: OpKind = MCK_Reg5; break;
    case Sparc::D7: OpKind = MCK_Reg5; break;
    case Sparc::D8: OpKind = MCK_Reg5; break;
    case Sparc::D9: OpKind = MCK_Reg5; break;
    case Sparc::D10: OpKind = MCK_Reg5; break;
    case Sparc::D11: OpKind = MCK_Reg5; break;
    case Sparc::D12: OpKind = MCK_Reg5; break;
    case Sparc::D13: OpKind = MCK_Reg5; break;
    case Sparc::D14: OpKind = MCK_Reg5; break;
    case Sparc::D15: OpKind = MCK_Reg5; break;
    case Sparc::D16: OpKind = MCK_DFPRegs; break;
    case Sparc::D17: OpKind = MCK_DFPRegs; break;
    case Sparc::D18: OpKind = MCK_DFPRegs; break;
    case Sparc::D19: OpKind = MCK_DFPRegs; break;
    case Sparc::D20: OpKind = MCK_DFPRegs; break;
    case Sparc::D21: OpKind = MCK_DFPRegs; break;
    case Sparc::D22: OpKind = MCK_DFPRegs; break;
    case Sparc::D23: OpKind = MCK_DFPRegs; break;
    case Sparc::D24: OpKind = MCK_DFPRegs; break;
    case Sparc::D25: OpKind = MCK_DFPRegs; break;
    case Sparc::D26: OpKind = MCK_DFPRegs; break;
    case Sparc::D27: OpKind = MCK_DFPRegs; break;
    case Sparc::D28: OpKind = MCK_DFPRegs; break;
    case Sparc::D29: OpKind = MCK_DFPRegs; break;
    case Sparc::D30: OpKind = MCK_DFPRegs; break;
    case Sparc::D31: OpKind = MCK_DFPRegs; break;
    case Sparc::Q0: OpKind = MCK_Reg7; break;
    case Sparc::Q1: OpKind = MCK_Reg7; break;
    case Sparc::Q2: OpKind = MCK_Reg7; break;
    case Sparc::Q3: OpKind = MCK_Reg7; break;
    case Sparc::Q4: OpKind = MCK_Reg7; break;
    case Sparc::Q5: OpKind = MCK_Reg7; break;
    case Sparc::Q6: OpKind = MCK_Reg7; break;
    case Sparc::Q7: OpKind = MCK_Reg7; break;
    case Sparc::Q8: OpKind = MCK_QFPRegs; break;
    case Sparc::Q9: OpKind = MCK_QFPRegs; break;
    case Sparc::Q10: OpKind = MCK_QFPRegs; break;
    case Sparc::Q11: OpKind = MCK_QFPRegs; break;
    case Sparc::Q12: OpKind = MCK_QFPRegs; break;
    case Sparc::Q13: OpKind = MCK_QFPRegs; break;
    case Sparc::Q14: OpKind = MCK_QFPRegs; break;
    case Sparc::Q15: OpKind = MCK_QFPRegs; break;
    case Sparc::G0_G1: OpKind = MCK_IntPair; break;
    case Sparc::G2_G3: OpKind = MCK_IntPair; break;
    case Sparc::G4_G5: OpKind = MCK_IntPair; break;
    case Sparc::G6_G7: OpKind = MCK_IntPair; break;
    case Sparc::O0_O1: OpKind = MCK_IntPair; break;
    case Sparc::O2_O3: OpKind = MCK_IntPair; break;
    case Sparc::O4_O5: OpKind = MCK_IntPair; break;
    case Sparc::O6_O7: OpKind = MCK_IntPair; break;
    case Sparc::L0_L1: OpKind = MCK_IntPair; break;
    case Sparc::L2_L3: OpKind = MCK_IntPair; break;
    case Sparc::L4_L5: OpKind = MCK_IntPair; break;
    case Sparc::L6_L7: OpKind = MCK_IntPair; break;
    case Sparc::I0_I1: OpKind = MCK_IntPair; break;
    case Sparc::I2_I3: OpKind = MCK_IntPair; break;
    case Sparc::I4_I5: OpKind = MCK_IntPair; break;
    case Sparc::I6_I7: OpKind = MCK_IntPair; break;
    }
    return isSubclass(OpKind, Kind) ? MCTargetAsmParser::Match_Success :
                                      MCTargetAsmParser::Match_InvalidOperand;
  }

  return MCTargetAsmParser::Match_InvalidOperand;
}

uint64_t SparcAsmParser::
ComputeAvailableFeatures(const FeatureBitset& FB) const {
  uint64_t Features = 0;
  if ((FB[Sparc::FeatureV9]))
    Features |= Feature_HasV9;
  if ((FB[Sparc::FeatureVIS]))
    Features |= Feature_HasVIS;
  if ((FB[Sparc::FeatureVIS2]))
    Features |= Feature_HasVIS2;
  if ((FB[Sparc::FeatureVIS3]))
    Features |= Feature_HasVIS3;
  return Features;
}

static const char *const MnemonicTable =
    "\003add\005addcc\004addx\005addxc\006addxcc\007addxccc\talignaddr\nalig"
    "naddrl\003and\005andcc\004andn\006andncc\007array16\007array32\006array"
    "8\001b\002ba\003bcc\004bclr\003bcs\002be\003beq\002bg\003bge\004bgeu\003"
    "bgu\002bl\003ble\004bleu\003blu\005bmask\002bn\003bne\004bneg\003bnz\004"
    "bpos\005brgez\004brgz\005brlez\004brlz\004brnz\003brz\004bset\010bshuff"
    "le\004btog\004btst\003bvc\003bvs\002bz\004call\003cas\004casx\003clr\004"
    "clrb\004clrh\007cmask16\007cmask32\006cmask8\003cmp\003dec\005deccc\006"
    "edge16\007edge16l\010edge16ln\007edge16n\006edge32\007edge32l\010edge32"
    "ln\007edge32n\005edge8\006edge8l\007edge8ln\006edge8n\005fabsd\005fabsq"
    "\005fabss\005faddd\005faddq\005fadds\nfaligndata\004fand\010fandnot1\tf"
    "andnot1s\010fandnot2\tfandnot2s\005fands\002fb\003fba\003fbe\003fbg\004"
    "fbge\003fbl\004fble\004fblg\003fbn\004fbne\004fbnz\003fbo\003fbu\004fbu"
    "e\004fbug\005fbuge\004fbul\005fbule\003fbz\010fchksm16\005fcmpd\006fcmp"
    "ed\006fcmpeq\010fcmpeq16\010fcmpeq32\006fcmpes\010fcmpgt16\010fcmpgt32\010"
    "fcmple16\010fcmple32\010fcmpne16\010fcmpne32\005fcmpq\005fcmps\005fdivd"
    "\005fdivq\005fdivs\006fdmulq\005fdtoi\005fdtoq\005fdtos\005fdtox\007fex"
    "pand\006fhaddd\006fhadds\006fhsubd\006fhsubs\005fitod\005fitoq\005fitos"
    "\006flcmpd\006flcmps\005flush\006flushw\007fmean16\005fmovd\006fmovda\007"
    "fmovdcc\007fmovdcs\006fmovde\007fmovdeq\006fmovdg\007fmovdge\010fmovdge"
    "u\007fmovdgu\006fmovdl\007fmovdle\010fmovdleu\007fmovdlg\007fmovdlu\006"
    "fmovdn\007fmovdne\010fmovdneg\007fmovdnz\006fmovdo\010fmovdpos\006fmovd"
    "u\007fmovdue\007fmovdug\010fmovduge\007fmovdul\010fmovdule\007fmovdvc\007"
    "fmovdvs\006fmovdz\005fmovq\006fmovqa\007fmovqcc\007fmovqcs\006fmovqe\007"
    "fmovqeq\006fmovqg\007fmovqge\010fmovqgeu\007fmovqgu\006fmovql\007fmovql"
    "e\010fmovqleu\007fmovqlg\007fmovqlu\006fmovqn\007fmovqne\010fmovqneg\007"
    "fmovqnz\006fmovqo\010fmovqpos\006fmovqu\007fmovque\007fmovqug\010fmovqu"
    "ge\007fmovqul\010fmovqule\007fmovqvc\007fmovqvs\006fmovqz\tfmovrdgez\010"
    "fmovrdgz\tfmovrdlez\010fmovrdlz\010fmovrdnz\007fmovrdz\tfmovrqgez\010fm"
    "ovrqgz\tfmovrqlez\010fmovrqlz\010fmovrqnz\007fmovrqz\tfmovrsgez\010fmov"
    "rsgz\tfmovrslez\010fmovrslz\010fmovrsnz\007fmovrsz\005fmovs\006fmovsa\007"
    "fmovscc\007fmovscs\006fmovse\007fmovseq\006fmovsg\007fmovsge\010fmovsge"
    "u\007fmovsgu\006fmovsl\007fmovsle\010fmovsleu\007fmovslg\007fmovslu\006"
    "fmovsn\007fmovsne\010fmovsneg\007fmovsnz\006fmovso\010fmovspos\006fmovs"
    "u\007fmovsue\007fmovsug\010fmovsuge\007fmovsul\010fmovsule\007fmovsvc\007"
    "fmovsvs\006fmovsz\nfmul8sux16\nfmul8ulx16\010fmul8x16\nfmul8x16al\nfmul"
    "8x16au\005fmuld\013fmuld8sux16\013fmuld8ulx16\005fmulq\005fmuls\006fnad"
    "dd\006fnadds\005fnand\006fnands\005fnegd\005fnegq\005fnegs\007fnhaddd\007"
    "fnhadds\004fnor\005fnors\005fnot1\006fnot1s\005fnot2\006fnot2s\004fone\005"
    "fones\003for\007fornot1\010fornot1s\007fornot2\010fornot2s\004fors\007f"
    "pack16\007fpack32\010fpackfix\007fpadd16\010fpadd16s\007fpadd32\010fpad"
    "d32s\007fpadd64\007fpmerge\007fpsub16\010fpsub16S\007fpsub32\010fpsub32"
    "S\005fqtod\005fqtoi\005fqtos\005fqtox\007fslas16\007fslas32\006fsll16\006"
    "fsll32\006fsmuld\006fsqrtd\006fsqrtq\006fsqrts\006fsra16\006fsra32\005f"
    "src1\006fsrc1s\005fsrc2\006fsrc2s\006fsrl16\006fsrl32\005fstod\005fstoi"
    "\005fstoq\005fstox\005fsubd\005fsubq\005fsubs\005fxnor\006fxnors\004fxo"
    "r\005fxors\005fxtod\005fxtoq\005fxtos\005fzero\006fzeros\003inc\005incc"
    "c\003jmp\004jmpl\002ld\003lda\003ldd\004ldda\003ldq\004ldqa\004ldsb\005"
    "ldsba\004ldsh\005ldsha\006ldstub\007ldstuba\004ldsw\004ldub\005lduba\004"
    "lduh\005lduha\003ldx\005lzcnt\006membar\003mov\004mova\005movcc\005movc"
    "s\007movdtox\004move\005moveq\004movg\005movge\006movgeu\005movgu\004mo"
    "vl\005movle\006movleu\005movlg\005movlu\004movn\005movne\006movneg\005m"
    "ovnz\004movo\006movpos\007movrgez\006movrgz\007movrlez\006movrlz\006mov"
    "rnz\005movrz\010movstosw\010movstouw\004movu\005movue\005movug\006movug"
    "e\005movul\006movule\005movvc\005movvs\004movz\006mulscc\004mulx\003neg"
    "\003nop\003not\002or\004orcc\003orn\005orncc\005pdist\006pdistn\004popc"
    "\002rd\004rdpr\007restore\003ret\004retl\004rett\004save\004sdiv\006sdi"
    "vcc\005sdivx\003set\005sethi\010shutdown\004siam\005signx\003sll\004sll"
    "x\004smul\006smulcc\003sra\004srax\003srl\004srlx\002st\003sta\003stb\004"
    "stba\005stbar\003std\004stda\003sth\004stha\003stq\004stqa\003stx\003su"
    "b\005subcc\004subx\006subxcc\004swap\005swapa\001t\002ta\006taddcc\010t"
    "addcctv\003tcc\003tcs\002te\003teq\002tg\003tge\004tgeu\003tgu\002tl\003"
    "tle\004tleu\003tlu\002tn\003tne\004tneg\003tnz\004tpos\003tst\006tsubcc"
    "\010tsubcctv\003tvc\003tvs\002tz\004udiv\006udivcc\005udivx\004umul\006"
    "umulcc\007umulxhi\005unimp\002wr\004wrpr\005xmulx\007xmulxhi\004xnor\006"
    "xnorcc\003xor\005xorcc";

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
    uint16_t Opcode;
    uint16_t ConvertFn;
    uint8_t RequiredFeatures;
    uint8_t Classes[5];
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
  { 0 /* add */, Sparc::ADDrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 0 /* add */, Sparc::ADDri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4 /* addcc */, Sparc::ADDCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4 /* addcc */, Sparc::ADDCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 10 /* addx */, Sparc::ADDCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 10 /* addx */, Sparc::ADDCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 15 /* addxc */, Sparc::ADDXC, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 21 /* addxcc */, Sparc::ADDErr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 21 /* addxcc */, Sparc::ADDEri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 28 /* addxccc */, Sparc::ADDXCCC, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 36 /* alignaddr */, Sparc::ALIGNADDR, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 46 /* alignaddrl */, Sparc::ALIGNADDRL, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 57 /* and */, Sparc::ANDrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 57 /* and */, Sparc::ANDri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 61 /* andcc */, Sparc::ANDCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 61 /* andcc */, Sparc::ANDCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 67 /* andn */, Sparc::ANDNrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 67 /* andn */, Sparc::ANDNri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 72 /* andncc */, Sparc::ANDNCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 72 /* andncc */, Sparc::ANDNCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 79 /* array16 */, Sparc::ARRAY16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 87 /* array32 */, Sparc::ARRAY32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 95 /* array8 */, Sparc::ARRAY8, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 102 /* b */, Sparc::BCOND, Convert__Imm1_0__imm_95_8, 0, { MCK_Imm }, },
  { 102 /* b */, Sparc::BPICC, Convert__Imm1_1__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCC, Convert__Imm1_1__imm_95_8, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 102 /* b */, Sparc::BCONDA, Convert__Imm1_1__imm_95_8, 0, { MCK_a, MCK_Imm }, },
  { 102 /* b */, Sparc::BCOND, Convert__Imm1_1__Imm1_0, 0, { MCK_Imm, MCK_Imm }, },
  { 102 /* b */, Sparc::BPICCA, Convert__Imm1_2__imm_95_8, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_8, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_8, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_8, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPICC, Convert__Imm1_2__imm_95_8, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCC, Convert__Imm1_2__imm_95_8, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPICC, Convert__Imm1_2__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCC, Convert__Imm1_2__Imm1_0, 0, { MCK_Imm, MCK__PCT_xcc, MCK_Imm }, },
  { 102 /* b */, Sparc::BCONDA, Convert__Imm1_2__Imm1_0, 0, { MCK_Imm, MCK_a, MCK_Imm }, },
  { 102 /* b */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_8, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_8, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPICCA, Convert__Imm1_3__imm_95_8, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_8, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPICCA, Convert__Imm1_3__Imm1_0, Feature_HasV9, { MCK_Imm, MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCCA, Convert__Imm1_3__Imm1_0, 0, { MCK_Imm, MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPICCNT, Convert__Imm1_3__Imm1_0, Feature_HasV9, { MCK_Imm, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCCNT, Convert__Imm1_3__Imm1_0, 0, { MCK_Imm, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPICCANT, Convert__Imm1_4__Imm1_0, Feature_HasV9, { MCK_Imm, MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 102 /* b */, Sparc::BPXCCANT, Convert__Imm1_4__Imm1_0, 0, { MCK_Imm, MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BA, Convert__Imm1_0, 0, { MCK_Imm }, },
  { 104 /* ba */, Sparc::BCOND, Convert__Imm1_0__imm_95_8, 0, { MCK_Imm }, },
  { 104 /* ba */, Sparc::BPICC, Convert__Imm1_1__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPXCC, Convert__Imm1_1__imm_95_8, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BCONDA, Convert__Imm1_1__imm_95_8, 0, { MCK_a, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPICCA, Convert__Imm1_2__imm_95_8, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_8, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_8, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_8, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPICC, Convert__Imm1_2__imm_95_8, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPXCC, Convert__Imm1_2__imm_95_8, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_8, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_8, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPICCA, Convert__Imm1_3__imm_95_8, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 104 /* ba */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_8, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BCOND, Convert__Imm1_0__imm_95_13, 0, { MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPICC, Convert__Imm1_1__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPXCC, Convert__Imm1_1__imm_95_13, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BCONDA, Convert__Imm1_1__imm_95_13, 0, { MCK_a, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPICCA, Convert__Imm1_2__imm_95_13, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_13, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_13, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_13, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPICC, Convert__Imm1_2__imm_95_13, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPXCC, Convert__Imm1_2__imm_95_13, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_13, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_13, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPICCA, Convert__Imm1_3__imm_95_13, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 107 /* bcc */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_13, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 111 /* bclr */, Sparc::ANDNrr, Convert__Reg1_1__Reg1_1__Reg1_0, 0, { MCK_IntRegs, MCK_IntRegs }, },
  { 111 /* bclr */, Sparc::ANDNri, Convert__Reg1_1__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 116 /* bcs */, Sparc::BCOND, Convert__Imm1_0__imm_95_5, 0, { MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPICC, Convert__Imm1_1__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPXCC, Convert__Imm1_1__imm_95_5, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BCONDA, Convert__Imm1_1__imm_95_5, 0, { MCK_a, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPICCA, Convert__Imm1_2__imm_95_5, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_5, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_5, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_5, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPICC, Convert__Imm1_2__imm_95_5, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPXCC, Convert__Imm1_2__imm_95_5, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_5, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_5, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPICCA, Convert__Imm1_3__imm_95_5, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 116 /* bcs */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_5, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 120 /* be */, Sparc::BCOND, Convert__Imm1_0__imm_95_1, 0, { MCK_Imm }, },
  { 120 /* be */, Sparc::BPICC, Convert__Imm1_1__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPXCC, Convert__Imm1_1__imm_95_1, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 120 /* be */, Sparc::BCONDA, Convert__Imm1_1__imm_95_1, 0, { MCK_a, MCK_Imm }, },
  { 120 /* be */, Sparc::BPICCA, Convert__Imm1_2__imm_95_1, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_1, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_1, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_1, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPICC, Convert__Imm1_2__imm_95_1, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPXCC, Convert__Imm1_2__imm_95_1, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_1, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_1, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPICCA, Convert__Imm1_3__imm_95_1, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 120 /* be */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_1, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BCOND, Convert__Imm1_0__imm_95_1, 0, { MCK_Imm }, },
  { 123 /* beq */, Sparc::BPICC, Convert__Imm1_1__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPXCC, Convert__Imm1_1__imm_95_1, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BCONDA, Convert__Imm1_1__imm_95_1, 0, { MCK_a, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPICCA, Convert__Imm1_2__imm_95_1, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_1, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_1, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_1, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPICC, Convert__Imm1_2__imm_95_1, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPXCC, Convert__Imm1_2__imm_95_1, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_1, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_1, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPICCA, Convert__Imm1_3__imm_95_1, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 123 /* beq */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_1, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BCOND, Convert__Imm1_0__imm_95_10, 0, { MCK_Imm }, },
  { 127 /* bg */, Sparc::BPICC, Convert__Imm1_1__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPXCC, Convert__Imm1_1__imm_95_10, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BCONDA, Convert__Imm1_1__imm_95_10, 0, { MCK_a, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPICCA, Convert__Imm1_2__imm_95_10, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_10, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_10, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_10, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPICC, Convert__Imm1_2__imm_95_10, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPXCC, Convert__Imm1_2__imm_95_10, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_10, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_10, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPICCA, Convert__Imm1_3__imm_95_10, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 127 /* bg */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_10, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BCOND, Convert__Imm1_0__imm_95_11, 0, { MCK_Imm }, },
  { 130 /* bge */, Sparc::BPICC, Convert__Imm1_1__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPXCC, Convert__Imm1_1__imm_95_11, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BCONDA, Convert__Imm1_1__imm_95_11, 0, { MCK_a, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPICCA, Convert__Imm1_2__imm_95_11, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_11, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_11, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_11, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPICC, Convert__Imm1_2__imm_95_11, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPXCC, Convert__Imm1_2__imm_95_11, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_11, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_11, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPICCA, Convert__Imm1_3__imm_95_11, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 130 /* bge */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_11, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BCOND, Convert__Imm1_0__imm_95_13, 0, { MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPICC, Convert__Imm1_1__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPXCC, Convert__Imm1_1__imm_95_13, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BCONDA, Convert__Imm1_1__imm_95_13, 0, { MCK_a, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPICCA, Convert__Imm1_2__imm_95_13, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_13, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_13, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_13, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPICC, Convert__Imm1_2__imm_95_13, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPXCC, Convert__Imm1_2__imm_95_13, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_13, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_13, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPICCA, Convert__Imm1_3__imm_95_13, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 134 /* bgeu */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_13, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BCOND, Convert__Imm1_0__imm_95_12, 0, { MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPICC, Convert__Imm1_1__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPXCC, Convert__Imm1_1__imm_95_12, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BCONDA, Convert__Imm1_1__imm_95_12, 0, { MCK_a, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPICCA, Convert__Imm1_2__imm_95_12, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_12, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_12, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_12, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPICC, Convert__Imm1_2__imm_95_12, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPXCC, Convert__Imm1_2__imm_95_12, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_12, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_12, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPICCA, Convert__Imm1_3__imm_95_12, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 139 /* bgu */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_12, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BCOND, Convert__Imm1_0__imm_95_3, 0, { MCK_Imm }, },
  { 143 /* bl */, Sparc::BPICC, Convert__Imm1_1__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPXCC, Convert__Imm1_1__imm_95_3, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BCONDA, Convert__Imm1_1__imm_95_3, 0, { MCK_a, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPICCA, Convert__Imm1_2__imm_95_3, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_3, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_3, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_3, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPICC, Convert__Imm1_2__imm_95_3, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPXCC, Convert__Imm1_2__imm_95_3, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_3, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_3, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPICCA, Convert__Imm1_3__imm_95_3, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 143 /* bl */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_3, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BCOND, Convert__Imm1_0__imm_95_2, 0, { MCK_Imm }, },
  { 146 /* ble */, Sparc::BPICC, Convert__Imm1_1__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPXCC, Convert__Imm1_1__imm_95_2, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BCONDA, Convert__Imm1_1__imm_95_2, 0, { MCK_a, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPICCA, Convert__Imm1_2__imm_95_2, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_2, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_2, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_2, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPICC, Convert__Imm1_2__imm_95_2, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPXCC, Convert__Imm1_2__imm_95_2, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_2, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_2, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPICCA, Convert__Imm1_3__imm_95_2, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 146 /* ble */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_2, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BCOND, Convert__Imm1_0__imm_95_4, 0, { MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPICC, Convert__Imm1_1__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPXCC, Convert__Imm1_1__imm_95_4, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BCONDA, Convert__Imm1_1__imm_95_4, 0, { MCK_a, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPICCA, Convert__Imm1_2__imm_95_4, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_4, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_4, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_4, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPICC, Convert__Imm1_2__imm_95_4, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPXCC, Convert__Imm1_2__imm_95_4, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_4, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_4, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPICCA, Convert__Imm1_3__imm_95_4, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 150 /* bleu */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_4, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BCOND, Convert__Imm1_0__imm_95_5, 0, { MCK_Imm }, },
  { 155 /* blu */, Sparc::BPICC, Convert__Imm1_1__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPXCC, Convert__Imm1_1__imm_95_5, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BCONDA, Convert__Imm1_1__imm_95_5, 0, { MCK_a, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPICCA, Convert__Imm1_2__imm_95_5, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_5, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_5, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_5, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPICC, Convert__Imm1_2__imm_95_5, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPXCC, Convert__Imm1_2__imm_95_5, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_5, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_5, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPICCA, Convert__Imm1_3__imm_95_5, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 155 /* blu */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_5, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 159 /* bmask */, Sparc::BMASK, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 165 /* bn */, Sparc::BCOND, Convert__Imm1_0__imm_95_0, 0, { MCK_Imm }, },
  { 165 /* bn */, Sparc::BPICC, Convert__Imm1_1__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPXCC, Convert__Imm1_1__imm_95_0, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BCONDA, Convert__Imm1_1__imm_95_0, 0, { MCK_a, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPICCA, Convert__Imm1_2__imm_95_0, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_0, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_0, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_0, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPICC, Convert__Imm1_2__imm_95_0, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPXCC, Convert__Imm1_2__imm_95_0, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_0, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_0, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPICCA, Convert__Imm1_3__imm_95_0, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 165 /* bn */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_0, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BCOND, Convert__Imm1_0__imm_95_9, 0, { MCK_Imm }, },
  { 168 /* bne */, Sparc::BPICC, Convert__Imm1_1__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPXCC, Convert__Imm1_1__imm_95_9, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BCONDA, Convert__Imm1_1__imm_95_9, 0, { MCK_a, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPICCA, Convert__Imm1_2__imm_95_9, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_9, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_9, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_9, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPICC, Convert__Imm1_2__imm_95_9, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPXCC, Convert__Imm1_2__imm_95_9, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_9, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_9, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPICCA, Convert__Imm1_3__imm_95_9, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 168 /* bne */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_9, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BCOND, Convert__Imm1_0__imm_95_6, 0, { MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPICC, Convert__Imm1_1__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPXCC, Convert__Imm1_1__imm_95_6, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BCONDA, Convert__Imm1_1__imm_95_6, 0, { MCK_a, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPICCA, Convert__Imm1_2__imm_95_6, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_6, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_6, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_6, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPICC, Convert__Imm1_2__imm_95_6, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPXCC, Convert__Imm1_2__imm_95_6, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_6, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_6, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPICCA, Convert__Imm1_3__imm_95_6, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 172 /* bneg */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_6, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BCOND, Convert__Imm1_0__imm_95_9, 0, { MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPICC, Convert__Imm1_1__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPXCC, Convert__Imm1_1__imm_95_9, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BCONDA, Convert__Imm1_1__imm_95_9, 0, { MCK_a, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPICCA, Convert__Imm1_2__imm_95_9, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_9, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_9, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_9, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPICC, Convert__Imm1_2__imm_95_9, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPXCC, Convert__Imm1_2__imm_95_9, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_9, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_9, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPICCA, Convert__Imm1_3__imm_95_9, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 177 /* bnz */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_9, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BCOND, Convert__Imm1_0__imm_95_14, 0, { MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPICC, Convert__Imm1_1__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPXCC, Convert__Imm1_1__imm_95_14, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BCONDA, Convert__Imm1_1__imm_95_14, 0, { MCK_a, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPICCA, Convert__Imm1_2__imm_95_14, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_14, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_14, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_14, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPICC, Convert__Imm1_2__imm_95_14, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPXCC, Convert__Imm1_2__imm_95_14, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_14, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_14, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPICCA, Convert__Imm1_3__imm_95_14, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 181 /* bpos */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_14, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 186 /* brgez */, Sparc::BPGEZnapt, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm }, },
  { 186 /* brgez */, Sparc::BPGEZapt, Convert__Reg1_1__Imm1_2, 0, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 186 /* brgez */, Sparc::BPGEZnapn, Convert__Reg1_1__Imm1_2, 0, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 186 /* brgez */, Sparc::BPGEZnapt, Convert__Reg1_1__Imm1_2, 0, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 186 /* brgez */, Sparc::BPGEZapn, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 186 /* brgez */, Sparc::BPGEZapt, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 192 /* brgz */, Sparc::BPGZnapt, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm }, },
  { 192 /* brgz */, Sparc::BPGZapt, Convert__Reg1_1__Imm1_2, 0, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 192 /* brgz */, Sparc::BPGZnapn, Convert__Reg1_1__Imm1_2, 0, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 192 /* brgz */, Sparc::BPGZnapt, Convert__Reg1_1__Imm1_2, 0, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 192 /* brgz */, Sparc::BPGZapn, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 192 /* brgz */, Sparc::BPGZapt, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 197 /* brlez */, Sparc::BPLEZnapt, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm }, },
  { 197 /* brlez */, Sparc::BPLEZapt, Convert__Reg1_1__Imm1_2, 0, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 197 /* brlez */, Sparc::BPLEZnapn, Convert__Reg1_1__Imm1_2, 0, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 197 /* brlez */, Sparc::BPLEZnapt, Convert__Reg1_1__Imm1_2, 0, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 197 /* brlez */, Sparc::BPLEZapn, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 197 /* brlez */, Sparc::BPLEZapt, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 203 /* brlz */, Sparc::BPLZnapt, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm }, },
  { 203 /* brlz */, Sparc::BPLZapt, Convert__Reg1_1__Imm1_2, 0, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 203 /* brlz */, Sparc::BPLZnapn, Convert__Reg1_1__Imm1_2, 0, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 203 /* brlz */, Sparc::BPLZnapt, Convert__Reg1_1__Imm1_2, 0, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 203 /* brlz */, Sparc::BPLZapn, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 203 /* brlz */, Sparc::BPLZapt, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 208 /* brnz */, Sparc::BPNZnapt, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm }, },
  { 208 /* brnz */, Sparc::BPNZapt, Convert__Reg1_1__Imm1_2, 0, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 208 /* brnz */, Sparc::BPNZnapn, Convert__Reg1_1__Imm1_2, 0, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 208 /* brnz */, Sparc::BPNZnapt, Convert__Reg1_1__Imm1_2, 0, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 208 /* brnz */, Sparc::BPNZapn, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 208 /* brnz */, Sparc::BPNZapt, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 213 /* brz */, Sparc::BPZnapt, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm }, },
  { 213 /* brz */, Sparc::BPZapt, Convert__Reg1_1__Imm1_2, 0, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 213 /* brz */, Sparc::BPZnapn, Convert__Reg1_1__Imm1_2, 0, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 213 /* brz */, Sparc::BPZnapt, Convert__Reg1_1__Imm1_2, 0, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 213 /* brz */, Sparc::BPZapn, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 213 /* brz */, Sparc::BPZapt, Convert__Reg1_2__Imm1_3, 0, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 217 /* bset */, Sparc::ORrr, Convert__Reg1_1__Reg1_1__Reg1_0, 0, { MCK_IntRegs, MCK_IntRegs }, },
  { 217 /* bset */, Sparc::ORri, Convert__Reg1_1__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 222 /* bshuffle */, Sparc::BSHUFFLE, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS2, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 231 /* btog */, Sparc::XORrr, Convert__Reg1_1__Reg1_1__Reg1_0, 0, { MCK_IntRegs, MCK_IntRegs }, },
  { 231 /* btog */, Sparc::XORri, Convert__Reg1_1__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 236 /* btst */, Sparc::ANDCCrr, Convert__regG0__Reg1_1__Reg1_0, 0, { MCK_IntRegs, MCK_IntRegs }, },
  { 236 /* btst */, Sparc::ANDCCri, Convert__regG0__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 241 /* bvc */, Sparc::BCOND, Convert__Imm1_0__imm_95_15, 0, { MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPICC, Convert__Imm1_1__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPXCC, Convert__Imm1_1__imm_95_15, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BCONDA, Convert__Imm1_1__imm_95_15, 0, { MCK_a, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPICCA, Convert__Imm1_2__imm_95_15, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_15, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_15, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_15, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPICC, Convert__Imm1_2__imm_95_15, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPXCC, Convert__Imm1_2__imm_95_15, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_15, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_15, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPICCA, Convert__Imm1_3__imm_95_15, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 241 /* bvc */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_15, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BCOND, Convert__Imm1_0__imm_95_7, 0, { MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPICC, Convert__Imm1_1__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPXCC, Convert__Imm1_1__imm_95_7, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BCONDA, Convert__Imm1_1__imm_95_7, 0, { MCK_a, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPICCA, Convert__Imm1_2__imm_95_7, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_7, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_7, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_7, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPICC, Convert__Imm1_2__imm_95_7, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPXCC, Convert__Imm1_2__imm_95_7, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_7, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_7, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPICCA, Convert__Imm1_3__imm_95_7, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 245 /* bvs */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_7, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BCOND, Convert__Imm1_0__imm_95_1, 0, { MCK_Imm }, },
  { 249 /* bz */, Sparc::BPICC, Convert__Imm1_1__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPXCC, Convert__Imm1_1__imm_95_1, 0, { MCK__PCT_xcc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BCONDA, Convert__Imm1_1__imm_95_1, 0, { MCK_a, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPICCA, Convert__Imm1_2__imm_95_1, Feature_HasV9, { MCK_a, MCK__PCT_icc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPXCCA, Convert__Imm1_2__imm_95_1, 0, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPICCNT, Convert__Imm1_2__imm_95_1, Feature_HasV9, { MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPXCCNT, Convert__Imm1_2__imm_95_1, 0, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPICC, Convert__Imm1_2__imm_95_1, Feature_HasV9, { MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPXCC, Convert__Imm1_2__imm_95_1, 0, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPICCANT, Convert__Imm1_3__imm_95_1, Feature_HasV9, { MCK_a, MCK_pn, MCK__PCT_icc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPXCCANT, Convert__Imm1_3__imm_95_1, 0, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPICCA, Convert__Imm1_3__imm_95_1, Feature_HasV9, { MCK_a, MCK_pt, MCK__PCT_icc, MCK_Imm }, },
  { 249 /* bz */, Sparc::BPXCCA, Convert__Imm1_3__imm_95_1, 0, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 252 /* call */, Sparc::CALL, Convert__Imm1_0, 0, { MCK_Imm }, },
  { 252 /* call */, Sparc::JMPLri, Convert__regO7__MEMri2_0, 0, { MCK_MEMri }, },
  { 252 /* call */, Sparc::JMPLrr, Convert__regO7__MEMrr2_0, 0, { MCK_MEMrr }, },
  { 257 /* cas */, Sparc::CASrr, Convert__Reg1_4__Reg1_1__Reg1_3__Tie0, Feature_HasV9, { MCK__91_, MCK_IntRegs, MCK__93_, MCK_IntRegs, MCK_IntRegs }, },
  { 261 /* casx */, Sparc::CASXrr, Convert__Reg1_4__Reg1_1__Reg1_3__Tie0, 0, { MCK__91_, MCK_IntRegs, MCK__93_, MCK_IntRegs, MCK_IntRegs }, },
  { 266 /* clr */, Sparc::ORrr, Convert__Reg1_0__regG0__regG0, 0, { MCK_IntRegs }, },
  { 266 /* clr */, Sparc::STri, Convert__MEMri2_1__regG0, 0, { MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 266 /* clr */, Sparc::STrr, Convert__MEMrr2_1__regG0, 0, { MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 270 /* clrb */, Sparc::STBri, Convert__MEMri2_1__regG0, 0, { MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 270 /* clrb */, Sparc::STBrr, Convert__MEMrr2_1__regG0, 0, { MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 275 /* clrh */, Sparc::STHri, Convert__MEMri2_1__regG0, 0, { MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 275 /* clrh */, Sparc::STHrr, Convert__MEMrr2_1__regG0, 0, { MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 280 /* cmask16 */, Sparc::CMASK16, Convert__Reg1_0, Feature_HasVIS3, { MCK_IntRegs }, },
  { 288 /* cmask32 */, Sparc::CMASK32, Convert__Reg1_0, Feature_HasVIS3, { MCK_IntRegs }, },
  { 296 /* cmask8 */, Sparc::CMASK8, Convert__Reg1_0, Feature_HasVIS3, { MCK_IntRegs }, },
  { 303 /* cmp */, Sparc::CMPrr, Convert__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs }, },
  { 303 /* cmp */, Sparc::CMPri, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm }, },
  { 307 /* dec */, Sparc::SUBri, Convert__Reg1_0__Reg1_0__imm_95_1, 0, { MCK_IntRegs }, },
  { 307 /* dec */, Sparc::SUBri, Convert__Reg1_1__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 311 /* deccc */, Sparc::SUBCCri, Convert__Reg1_0__Reg1_0__imm_95_1, 0, { MCK_IntRegs }, },
  { 311 /* deccc */, Sparc::SUBCCri, Convert__Reg1_1__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 317 /* edge16 */, Sparc::EDGE16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 324 /* edge16l */, Sparc::EDGE16L, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 332 /* edge16ln */, Sparc::EDGE16LN, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 341 /* edge16n */, Sparc::EDGE16N, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 349 /* edge32 */, Sparc::EDGE32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 356 /* edge32l */, Sparc::EDGE32L, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 364 /* edge32ln */, Sparc::EDGE32LN, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 373 /* edge32n */, Sparc::EDGE32N, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 381 /* edge8 */, Sparc::EDGE8, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 387 /* edge8l */, Sparc::EDGE8L, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 394 /* edge8ln */, Sparc::EDGE8LN, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 402 /* edge8n */, Sparc::EDGE8N, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 409 /* fabsd */, Sparc::FABSD, Convert__Reg1_1__Reg1_0, Feature_HasV9, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 415 /* fabsq */, Sparc::FABSQ, Convert__Reg1_1__Reg1_0, Feature_HasV9, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 421 /* fabss */, Sparc::FABSS, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_FPRegs }, },
  { 427 /* faddd */, Sparc::FADDD, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 433 /* faddq */, Sparc::FADDQ, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_QFPRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 439 /* fadds */, Sparc::FADDS, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 445 /* faligndata */, Sparc::FALIGNADATA, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 456 /* fand */, Sparc::FAND, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 461 /* fandnot1 */, Sparc::FANDNOT1, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 470 /* fandnot1s */, Sparc::FANDNOT1S, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 480 /* fandnot2 */, Sparc::FANDNOT2, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 489 /* fandnot2s */, Sparc::FANDNOT2S, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 499 /* fands */, Sparc::FANDS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 505 /* fb */, Sparc::FBCOND, Convert__Imm1_0__imm_95_0, 0, { MCK_Imm }, },
  { 505 /* fb */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_0, 0, { MCK_a, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCC, Convert__Imm1_1__imm_95_0__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 505 /* fb */, Sparc::FBCOND, Convert__Imm1_1__Imm1_0, 0, { MCK_Imm, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_0__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_0__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCC, Convert__Imm1_2__imm_95_0__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 505 /* fb */, Sparc::FBCONDA, Convert__Imm1_2__Imm1_0, 0, { MCK_Imm, MCK_a, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCC, Convert__Imm1_2__Imm1_0__Reg1_1, Feature_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_0__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_0__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCCA, Convert__Imm1_3__Imm1_0__Reg1_2, Feature_HasV9, { MCK_Imm, MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCCNT, Convert__Imm1_3__Imm1_0__Reg1_2, Feature_HasV9, { MCK_Imm, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 505 /* fb */, Sparc::BPFCCANT, Convert__Imm1_4__Imm1_0__Reg1_3, Feature_HasV9, { MCK_Imm, MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 508 /* fba */, Sparc::FBCOND, Convert__Imm1_0__imm_95_0, 0, { MCK_Imm }, },
  { 508 /* fba */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_0, 0, { MCK_a, MCK_Imm }, },
  { 508 /* fba */, Sparc::BPFCC, Convert__Imm1_1__imm_95_0__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 508 /* fba */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_0__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 508 /* fba */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_0__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 508 /* fba */, Sparc::BPFCC, Convert__Imm1_2__imm_95_0__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 508 /* fba */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_0__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 508 /* fba */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_0__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 512 /* fbe */, Sparc::FBCOND, Convert__Imm1_0__imm_95_9, 0, { MCK_Imm }, },
  { 512 /* fbe */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_9, 0, { MCK_a, MCK_Imm }, },
  { 512 /* fbe */, Sparc::BPFCC, Convert__Imm1_1__imm_95_9__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 512 /* fbe */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_9__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 512 /* fbe */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_9__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 512 /* fbe */, Sparc::BPFCC, Convert__Imm1_2__imm_95_9__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 512 /* fbe */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_9__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 512 /* fbe */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_9__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 516 /* fbg */, Sparc::FBCOND, Convert__Imm1_0__imm_95_6, 0, { MCK_Imm }, },
  { 516 /* fbg */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_6, 0, { MCK_a, MCK_Imm }, },
  { 516 /* fbg */, Sparc::BPFCC, Convert__Imm1_1__imm_95_6__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 516 /* fbg */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_6__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 516 /* fbg */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_6__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 516 /* fbg */, Sparc::BPFCC, Convert__Imm1_2__imm_95_6__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 516 /* fbg */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_6__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 516 /* fbg */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_6__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 520 /* fbge */, Sparc::FBCOND, Convert__Imm1_0__imm_95_11, 0, { MCK_Imm }, },
  { 520 /* fbge */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_11, 0, { MCK_a, MCK_Imm }, },
  { 520 /* fbge */, Sparc::BPFCC, Convert__Imm1_1__imm_95_11__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 520 /* fbge */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_11__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 520 /* fbge */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_11__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 520 /* fbge */, Sparc::BPFCC, Convert__Imm1_2__imm_95_11__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 520 /* fbge */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_11__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 520 /* fbge */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_11__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 525 /* fbl */, Sparc::FBCOND, Convert__Imm1_0__imm_95_4, 0, { MCK_Imm }, },
  { 525 /* fbl */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_4, 0, { MCK_a, MCK_Imm }, },
  { 525 /* fbl */, Sparc::BPFCC, Convert__Imm1_1__imm_95_4__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 525 /* fbl */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_4__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 525 /* fbl */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_4__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 525 /* fbl */, Sparc::BPFCC, Convert__Imm1_2__imm_95_4__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 525 /* fbl */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_4__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 525 /* fbl */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_4__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 529 /* fble */, Sparc::FBCOND, Convert__Imm1_0__imm_95_13, 0, { MCK_Imm }, },
  { 529 /* fble */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_13, 0, { MCK_a, MCK_Imm }, },
  { 529 /* fble */, Sparc::BPFCC, Convert__Imm1_1__imm_95_13__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 529 /* fble */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_13__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 529 /* fble */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_13__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 529 /* fble */, Sparc::BPFCC, Convert__Imm1_2__imm_95_13__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 529 /* fble */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_13__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 529 /* fble */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_13__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 534 /* fblg */, Sparc::FBCOND, Convert__Imm1_0__imm_95_2, 0, { MCK_Imm }, },
  { 534 /* fblg */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_2, 0, { MCK_a, MCK_Imm }, },
  { 534 /* fblg */, Sparc::BPFCC, Convert__Imm1_1__imm_95_2__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 534 /* fblg */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_2__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 534 /* fblg */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_2__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 534 /* fblg */, Sparc::BPFCC, Convert__Imm1_2__imm_95_2__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 534 /* fblg */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_2__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 534 /* fblg */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_2__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 539 /* fbn */, Sparc::FBCOND, Convert__Imm1_0__imm_95_8, 0, { MCK_Imm }, },
  { 539 /* fbn */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_8, 0, { MCK_a, MCK_Imm }, },
  { 539 /* fbn */, Sparc::BPFCC, Convert__Imm1_1__imm_95_8__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 539 /* fbn */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_8__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 539 /* fbn */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_8__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 539 /* fbn */, Sparc::BPFCC, Convert__Imm1_2__imm_95_8__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 539 /* fbn */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_8__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 539 /* fbn */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_8__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 543 /* fbne */, Sparc::FBCOND, Convert__Imm1_0__imm_95_1, 0, { MCK_Imm }, },
  { 543 /* fbne */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_1, 0, { MCK_a, MCK_Imm }, },
  { 543 /* fbne */, Sparc::BPFCC, Convert__Imm1_1__imm_95_1__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 543 /* fbne */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_1__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 543 /* fbne */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_1__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 543 /* fbne */, Sparc::BPFCC, Convert__Imm1_2__imm_95_1__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 543 /* fbne */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_1__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 543 /* fbne */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_1__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 548 /* fbnz */, Sparc::FBCOND, Convert__Imm1_0__imm_95_1, 0, { MCK_Imm }, },
  { 548 /* fbnz */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_1, 0, { MCK_a, MCK_Imm }, },
  { 548 /* fbnz */, Sparc::BPFCC, Convert__Imm1_1__imm_95_1__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 548 /* fbnz */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_1__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 548 /* fbnz */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_1__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 548 /* fbnz */, Sparc::BPFCC, Convert__Imm1_2__imm_95_1__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 548 /* fbnz */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_1__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 548 /* fbnz */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_1__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 553 /* fbo */, Sparc::FBCOND, Convert__Imm1_0__imm_95_15, 0, { MCK_Imm }, },
  { 553 /* fbo */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_15, 0, { MCK_a, MCK_Imm }, },
  { 553 /* fbo */, Sparc::BPFCC, Convert__Imm1_1__imm_95_15__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 553 /* fbo */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_15__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 553 /* fbo */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_15__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 553 /* fbo */, Sparc::BPFCC, Convert__Imm1_2__imm_95_15__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 553 /* fbo */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_15__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 553 /* fbo */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_15__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 557 /* fbu */, Sparc::FBCOND, Convert__Imm1_0__imm_95_7, 0, { MCK_Imm }, },
  { 557 /* fbu */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_7, 0, { MCK_a, MCK_Imm }, },
  { 557 /* fbu */, Sparc::BPFCC, Convert__Imm1_1__imm_95_7__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 557 /* fbu */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_7__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 557 /* fbu */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_7__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 557 /* fbu */, Sparc::BPFCC, Convert__Imm1_2__imm_95_7__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 557 /* fbu */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_7__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 557 /* fbu */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_7__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 561 /* fbue */, Sparc::FBCOND, Convert__Imm1_0__imm_95_10, 0, { MCK_Imm }, },
  { 561 /* fbue */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_10, 0, { MCK_a, MCK_Imm }, },
  { 561 /* fbue */, Sparc::BPFCC, Convert__Imm1_1__imm_95_10__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 561 /* fbue */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_10__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 561 /* fbue */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_10__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 561 /* fbue */, Sparc::BPFCC, Convert__Imm1_2__imm_95_10__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 561 /* fbue */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_10__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 561 /* fbue */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_10__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 566 /* fbug */, Sparc::FBCOND, Convert__Imm1_0__imm_95_5, 0, { MCK_Imm }, },
  { 566 /* fbug */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_5, 0, { MCK_a, MCK_Imm }, },
  { 566 /* fbug */, Sparc::BPFCC, Convert__Imm1_1__imm_95_5__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 566 /* fbug */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_5__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 566 /* fbug */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_5__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 566 /* fbug */, Sparc::BPFCC, Convert__Imm1_2__imm_95_5__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 566 /* fbug */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_5__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 566 /* fbug */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_5__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 571 /* fbuge */, Sparc::FBCOND, Convert__Imm1_0__imm_95_12, 0, { MCK_Imm }, },
  { 571 /* fbuge */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_12, 0, { MCK_a, MCK_Imm }, },
  { 571 /* fbuge */, Sparc::BPFCC, Convert__Imm1_1__imm_95_12__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 571 /* fbuge */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_12__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 571 /* fbuge */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_12__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 571 /* fbuge */, Sparc::BPFCC, Convert__Imm1_2__imm_95_12__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 571 /* fbuge */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_12__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 571 /* fbuge */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_12__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 577 /* fbul */, Sparc::FBCOND, Convert__Imm1_0__imm_95_3, 0, { MCK_Imm }, },
  { 577 /* fbul */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_3, 0, { MCK_a, MCK_Imm }, },
  { 577 /* fbul */, Sparc::BPFCC, Convert__Imm1_1__imm_95_3__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 577 /* fbul */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_3__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 577 /* fbul */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_3__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 577 /* fbul */, Sparc::BPFCC, Convert__Imm1_2__imm_95_3__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 577 /* fbul */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_3__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 577 /* fbul */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_3__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 582 /* fbule */, Sparc::FBCOND, Convert__Imm1_0__imm_95_14, 0, { MCK_Imm }, },
  { 582 /* fbule */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_14, 0, { MCK_a, MCK_Imm }, },
  { 582 /* fbule */, Sparc::BPFCC, Convert__Imm1_1__imm_95_14__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 582 /* fbule */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_14__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 582 /* fbule */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_14__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 582 /* fbule */, Sparc::BPFCC, Convert__Imm1_2__imm_95_14__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 582 /* fbule */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_14__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 582 /* fbule */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_14__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 588 /* fbz */, Sparc::FBCOND, Convert__Imm1_0__imm_95_9, 0, { MCK_Imm }, },
  { 588 /* fbz */, Sparc::FBCONDA, Convert__Imm1_1__imm_95_9, 0, { MCK_a, MCK_Imm }, },
  { 588 /* fbz */, Sparc::BPFCC, Convert__Imm1_1__imm_95_9__Reg1_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 588 /* fbz */, Sparc::BPFCCA, Convert__Imm1_2__imm_95_9__Reg1_1, Feature_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 588 /* fbz */, Sparc::BPFCCNT, Convert__Imm1_2__imm_95_9__Reg1_1, Feature_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 588 /* fbz */, Sparc::BPFCC, Convert__Imm1_2__imm_95_9__Reg1_1, Feature_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 588 /* fbz */, Sparc::BPFCCANT, Convert__Imm1_3__imm_95_9__Reg1_2, Feature_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 588 /* fbz */, Sparc::BPFCCA, Convert__Imm1_3__imm_95_9__Reg1_2, Feature_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 592 /* fchksm16 */, Sparc::FCHKSM16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 601 /* fcmpd */, Sparc::V9FCMPD, Convert__regFCC0__Reg1_0__Reg1_1, 0, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 601 /* fcmpd */, Sparc::V9FCMPD, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 607 /* fcmped */, Sparc::V9FCMPED, Convert__regFCC0__Reg1_0__Reg1_1, 0, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 607 /* fcmped */, Sparc::V9FCMPED, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 614 /* fcmpeq */, Sparc::V9FCMPEQ, Convert__regFCC0__Reg1_0__Reg1_1, 0, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 614 /* fcmpeq */, Sparc::V9FCMPEQ, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 621 /* fcmpeq16 */, Sparc::FCMPEQ16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 630 /* fcmpeq32 */, Sparc::FCMPEQ32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 639 /* fcmpes */, Sparc::V9FCMPES, Convert__regFCC0__Reg1_0__Reg1_1, 0, { MCK_FPRegs, MCK_FPRegs }, },
  { 639 /* fcmpes */, Sparc::V9FCMPES, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 646 /* fcmpgt16 */, Sparc::FCMPGT16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 655 /* fcmpgt32 */, Sparc::FCMPGT32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 664 /* fcmple16 */, Sparc::FCMPLE16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 673 /* fcmple32 */, Sparc::FCMPLE32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 682 /* fcmpne16 */, Sparc::FCMPNE16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 691 /* fcmpne32 */, Sparc::FCMPNE32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 700 /* fcmpq */, Sparc::V9FCMPQ, Convert__regFCC0__Reg1_0__Reg1_1, 0, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 700 /* fcmpq */, Sparc::V9FCMPQ, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 706 /* fcmps */, Sparc::V9FCMPS, Convert__regFCC0__Reg1_0__Reg1_1, 0, { MCK_FPRegs, MCK_FPRegs }, },
  { 706 /* fcmps */, Sparc::V9FCMPS, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 712 /* fdivd */, Sparc::FDIVD, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 718 /* fdivq */, Sparc::FDIVQ, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_QFPRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 724 /* fdivs */, Sparc::FDIVS, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 730 /* fdmulq */, Sparc::FDMULQ, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_DFPRegs, MCK_DFPRegs, MCK_QFPRegs }, },
  { 737 /* fdtoi */, Sparc::FDTOI, Convert__Reg1_1__Reg1_0, 0, { MCK_DFPRegs, MCK_FPRegs }, },
  { 743 /* fdtoq */, Sparc::FDTOQ, Convert__Reg1_1__Reg1_0, 0, { MCK_DFPRegs, MCK_QFPRegs }, },
  { 749 /* fdtos */, Sparc::FDTOS, Convert__Reg1_1__Reg1_0, 0, { MCK_DFPRegs, MCK_FPRegs }, },
  { 755 /* fdtox */, Sparc::FDTOX, Convert__Reg1_1__Reg1_0, 0, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 761 /* fexpand */, Sparc::FEXPAND, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 769 /* fhaddd */, Sparc::FHADDD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 776 /* fhadds */, Sparc::FHADDS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 783 /* fhsubd */, Sparc::FHSUBD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 790 /* fhsubs */, Sparc::FHSUBS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 797 /* fitod */, Sparc::FITOD, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_DFPRegs }, },
  { 803 /* fitoq */, Sparc::FITOQ, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_QFPRegs }, },
  { 809 /* fitos */, Sparc::FITOS, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_FPRegs }, },
  { 815 /* flcmpd */, Sparc::FLCMPD, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasVIS3, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 822 /* flcmps */, Sparc::FLCMPS, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasVIS3, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 829 /* flush */, Sparc::FLUSH, Convert_NoOperands, 0, {  }, },
  { 829 /* flush */, Sparc::FLUSH, Convert_NoOperands, 0, { MCK__PCT_g0 }, },
  { 829 /* flush */, Sparc::FLUSHri, Convert__MEMri2_0, 0, { MCK_MEMri }, },
  { 829 /* flush */, Sparc::FLUSHrr, Convert__MEMrr2_0, 0, { MCK_MEMrr }, },
  { 835 /* flushw */, Sparc::FLUSHW, Convert_NoOperands, Feature_HasV9, {  }, },
  { 842 /* fmean16 */, Sparc::FMEAN16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 850 /* fmovd */, Sparc::FMOVD, Convert__Reg1_1__Reg1_0, Feature_HasV9, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 850 /* fmovd */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 850 /* fmovd */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 850 /* fmovd */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 850 /* fmovd */, Sparc::FMOVD_FCC, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_fcc0, MCK_DFPRegs, MCK_DFPRegs }, },
  { 850 /* fmovd */, Sparc::FMOVD_ICC, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 850 /* fmovd */, Sparc::FMOVD_XCC, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, 0, { MCK_Imm, MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 850 /* fmovd */, Sparc::V9FMOVD_FCC, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 856 /* fmovda */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 856 /* fmovda */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 856 /* fmovda */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 863 /* fmovdcc */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 863 /* fmovdcc */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 871 /* fmovdcs */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 871 /* fmovdcs */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 879 /* fmovde */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 879 /* fmovde */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 879 /* fmovde */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 886 /* fmovdeq */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 886 /* fmovdeq */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 894 /* fmovdg */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 894 /* fmovdg */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_10, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 894 /* fmovdg */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_6, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 901 /* fmovdge */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 901 /* fmovdge */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_11, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 901 /* fmovdge */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_11, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 909 /* fmovdgeu */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 909 /* fmovdgeu */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 918 /* fmovdgu */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 918 /* fmovdgu */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_12, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 926 /* fmovdl */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 926 /* fmovdl */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_3, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 926 /* fmovdl */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_4, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 933 /* fmovdle */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 933 /* fmovdle */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_2, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 933 /* fmovdle */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 941 /* fmovdleu */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 941 /* fmovdleu */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_4, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 950 /* fmovdlg */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_2, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 958 /* fmovdlu */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 958 /* fmovdlu */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 966 /* fmovdn */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 966 /* fmovdn */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_0, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 966 /* fmovdn */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 973 /* fmovdne */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 973 /* fmovdne */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 973 /* fmovdne */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 981 /* fmovdneg */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 981 /* fmovdneg */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_6, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 990 /* fmovdnz */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 990 /* fmovdnz */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 990 /* fmovdnz */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 998 /* fmovdo */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_15, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1005 /* fmovdpos */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1005 /* fmovdpos */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_14, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1014 /* fmovdu */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_7, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1021 /* fmovdue */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_10, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1029 /* fmovdug */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1037 /* fmovduge */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_12, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1046 /* fmovdul */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_3, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1054 /* fmovdule */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_14, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1063 /* fmovdvc */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1063 /* fmovdvc */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_15, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1071 /* fmovdvs */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1071 /* fmovdvs */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_7, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1079 /* fmovdz */, Sparc::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1079 /* fmovdz */, Sparc::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1079 /* fmovdz */, Sparc::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1086 /* fmovq */, Sparc::FMOVQ, Convert__Reg1_1__Reg1_0, Feature_HasV9, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 1086 /* fmovq */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1086 /* fmovq */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1086 /* fmovq */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1086 /* fmovq */, Sparc::FMOVQ_FCC, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_fcc0, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1086 /* fmovq */, Sparc::FMOVQ_ICC, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1086 /* fmovq */, Sparc::FMOVQ_XCC, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, 0, { MCK_Imm, MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1086 /* fmovq */, Sparc::V9FMOVQ_FCC, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1092 /* fmovqa */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1092 /* fmovqa */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1092 /* fmovqa */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1099 /* fmovqcc */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1099 /* fmovqcc */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1107 /* fmovqcs */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1107 /* fmovqcs */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1115 /* fmovqe */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1115 /* fmovqe */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1115 /* fmovqe */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1122 /* fmovqeq */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1122 /* fmovqeq */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1130 /* fmovqg */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1130 /* fmovqg */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_10, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1130 /* fmovqg */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_6, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1137 /* fmovqge */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1137 /* fmovqge */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_11, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1137 /* fmovqge */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_11, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1145 /* fmovqgeu */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1145 /* fmovqgeu */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1154 /* fmovqgu */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1154 /* fmovqgu */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_12, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1162 /* fmovql */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1162 /* fmovql */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_3, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1162 /* fmovql */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_4, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1169 /* fmovqle */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1169 /* fmovqle */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_2, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1169 /* fmovqle */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1177 /* fmovqleu */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1177 /* fmovqleu */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_4, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1186 /* fmovqlg */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_2, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1194 /* fmovqlu */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1194 /* fmovqlu */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1202 /* fmovqn */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1202 /* fmovqn */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_0, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1202 /* fmovqn */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1209 /* fmovqne */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1209 /* fmovqne */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1209 /* fmovqne */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1217 /* fmovqneg */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1217 /* fmovqneg */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_6, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1226 /* fmovqnz */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1226 /* fmovqnz */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1226 /* fmovqnz */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1234 /* fmovqo */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_15, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1241 /* fmovqpos */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1241 /* fmovqpos */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_14, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1250 /* fmovqu */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_7, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1257 /* fmovque */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_10, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1265 /* fmovqug */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1273 /* fmovquge */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_12, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1282 /* fmovqul */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_3, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1290 /* fmovqule */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_14, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1299 /* fmovqvc */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1299 /* fmovqvc */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_15, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1307 /* fmovqvs */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1307 /* fmovqvs */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_7, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1315 /* fmovqz */, Sparc::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1315 /* fmovqz */, Sparc::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1315 /* fmovqz */, Sparc::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1322 /* fmovrdgez */, Sparc::FMOVRGEZD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1332 /* fmovrdgz */, Sparc::FMOVRGZD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1341 /* fmovrdlez */, Sparc::FMOVRLEZD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1351 /* fmovrdlz */, Sparc::FMOVRLZD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1360 /* fmovrdnz */, Sparc::FMOVRNZD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1369 /* fmovrdz */, Sparc::FMOVRZD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1377 /* fmovrqgez */, Sparc::FMOVRGEZQ, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1387 /* fmovrqgz */, Sparc::FMOVRGZQ, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1396 /* fmovrqlez */, Sparc::FMOVRLEZQ, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1406 /* fmovrqlz */, Sparc::FMOVRLZQ, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1415 /* fmovrqnz */, Sparc::FMOVRNZQ, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1424 /* fmovrqz */, Sparc::FMOVRZQ, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1432 /* fmovrsgez */, Sparc::FMOVRGEZS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1442 /* fmovrsgz */, Sparc::FMOVRGZS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1451 /* fmovrslez */, Sparc::FMOVRLEZS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1461 /* fmovrslz */, Sparc::FMOVRLZS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1470 /* fmovrsnz */, Sparc::FMOVRNZS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1479 /* fmovrsz */, Sparc::FMOVRZS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1487 /* fmovs */, Sparc::FMOVS, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_FPRegs }, },
  { 1487 /* fmovs */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1487 /* fmovs */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1487 /* fmovs */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1487 /* fmovs */, Sparc::FMOVS_FCC, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_fcc0, MCK_FPRegs, MCK_FPRegs }, },
  { 1487 /* fmovs */, Sparc::FMOVS_ICC, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1487 /* fmovs */, Sparc::FMOVS_XCC, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, 0, { MCK_Imm, MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1487 /* fmovs */, Sparc::V9FMOVS_FCC, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1493 /* fmovsa */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1493 /* fmovsa */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1493 /* fmovsa */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1500 /* fmovscc */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1500 /* fmovscc */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1508 /* fmovscs */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1508 /* fmovscs */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1516 /* fmovse */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1516 /* fmovse */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1516 /* fmovse */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1523 /* fmovseq */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1523 /* fmovseq */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1531 /* fmovsg */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1531 /* fmovsg */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_10, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1531 /* fmovsg */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_6, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1538 /* fmovsge */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1538 /* fmovsge */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_11, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1538 /* fmovsge */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_11, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1546 /* fmovsgeu */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1546 /* fmovsgeu */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1555 /* fmovsgu */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1555 /* fmovsgu */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_12, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1563 /* fmovsl */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1563 /* fmovsl */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_3, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1563 /* fmovsl */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_4, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1570 /* fmovsle */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1570 /* fmovsle */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_2, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1570 /* fmovsle */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1578 /* fmovsleu */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1578 /* fmovsleu */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_4, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1587 /* fmovslg */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_2, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1595 /* fmovslu */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1595 /* fmovslu */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1603 /* fmovsn */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1603 /* fmovsn */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_0, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1603 /* fmovsn */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1610 /* fmovsne */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1610 /* fmovsne */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1610 /* fmovsne */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1618 /* fmovsneg */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1618 /* fmovsneg */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_6, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1627 /* fmovsnz */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1627 /* fmovsnz */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1627 /* fmovsnz */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1635 /* fmovso */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_15, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1642 /* fmovspos */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1642 /* fmovspos */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_14, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1651 /* fmovsu */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_7, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1658 /* fmovsue */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_10, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1666 /* fmovsug */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1674 /* fmovsuge */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_12, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1683 /* fmovsul */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_3, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1691 /* fmovsule */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_14, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1700 /* fmovsvc */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1700 /* fmovsvc */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_15, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1708 /* fmovsvs */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1708 /* fmovsvs */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_7, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1716 /* fmovsz */, Sparc::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_FPRegs, MCK_FPRegs }, },
  { 1716 /* fmovsz */, Sparc::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 1716 /* fmovsz */, Sparc::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1723 /* fmul8sux16 */, Sparc::FMUL8SUX16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1734 /* fmul8ulx16 */, Sparc::FMUL8ULX16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1745 /* fmul8x16 */, Sparc::FMUL8X16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1754 /* fmul8x16al */, Sparc::FMUL8X16AL, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1765 /* fmul8x16au */, Sparc::FMUL8X16AU, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1776 /* fmuld */, Sparc::FMULD, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1782 /* fmuld8sux16 */, Sparc::FMULD8SUX16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1794 /* fmuld8ulx16 */, Sparc::FMULD8ULX16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1806 /* fmulq */, Sparc::FMULQ, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_QFPRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1812 /* fmuls */, Sparc::FMULS, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1818 /* fnaddd */, Sparc::FNADDD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1825 /* fnadds */, Sparc::FNADDS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1832 /* fnand */, Sparc::FNAND, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1838 /* fnands */, Sparc::FNANDS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1845 /* fnegd */, Sparc::FNEGD, Convert__Reg1_1__Reg1_0, Feature_HasV9, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 1851 /* fnegq */, Sparc::FNEGQ, Convert__Reg1_1__Reg1_0, Feature_HasV9, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 1857 /* fnegs */, Sparc::FNEGS, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_FPRegs }, },
  { 1863 /* fnhaddd */, Sparc::FNHADDD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1863 /* fnhaddd */, Sparc::FNMULD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1871 /* fnhadds */, Sparc::FNHADDS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1871 /* fnhadds */, Sparc::FNMULS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1871 /* fnhadds */, Sparc::FNSMULD, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1879 /* fnor */, Sparc::FNOR, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1884 /* fnors */, Sparc::FNORS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1890 /* fnot1 */, Sparc::FNOT1, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 1896 /* fnot1s */, Sparc::FNOT1S, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs }, },
  { 1903 /* fnot2 */, Sparc::FNOT2, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 1909 /* fnot2s */, Sparc::FNOT2S, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs }, },
  { 1916 /* fone */, Sparc::FONE, Convert__Reg1_0__Tie0, Feature_HasVIS, { MCK_DFPRegs }, },
  { 1921 /* fones */, Sparc::FONES, Convert__Reg1_0__Tie0, Feature_HasVIS, { MCK_FPRegs }, },
  { 1927 /* for */, Sparc::FOR, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1931 /* fornot1 */, Sparc::FORNOT1, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1939 /* fornot1s */, Sparc::FORNOT1S, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1948 /* fornot2 */, Sparc::FORNOT2, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1956 /* fornot2s */, Sparc::FORNOT2S, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1965 /* fors */, Sparc::FORS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1970 /* fpack16 */, Sparc::FPACK16, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 1978 /* fpack32 */, Sparc::FPACK32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1986 /* fpackfix */, Sparc::FPACKFIX, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 1995 /* fpadd16 */, Sparc::FPADD16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2003 /* fpadd16s */, Sparc::FPADD16S, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2012 /* fpadd32 */, Sparc::FPADD32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2020 /* fpadd32s */, Sparc::FPADD32S, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2029 /* fpadd64 */, Sparc::FPADD64, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2037 /* fpmerge */, Sparc::FPMERGE, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2045 /* fpsub16 */, Sparc::FPSUB16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2053 /* fpsub16S */, Sparc::FPSUB16S, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2062 /* fpsub32 */, Sparc::FPSUB32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2070 /* fpsub32S */, Sparc::FPSUB32S, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2079 /* fqtod */, Sparc::FQTOD, Convert__Reg1_1__Reg1_0, 0, { MCK_QFPRegs, MCK_DFPRegs }, },
  { 2085 /* fqtoi */, Sparc::FQTOI, Convert__Reg1_1__Reg1_0, 0, { MCK_QFPRegs, MCK_FPRegs }, },
  { 2091 /* fqtos */, Sparc::FQTOS, Convert__Reg1_1__Reg1_0, 0, { MCK_QFPRegs, MCK_FPRegs }, },
  { 2097 /* fqtox */, Sparc::FQTOX, Convert__Reg1_1__Reg1_0, 0, { MCK_QFPRegs, MCK_DFPRegs }, },
  { 2103 /* fslas16 */, Sparc::FSLAS16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2111 /* fslas32 */, Sparc::FSLAS32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2119 /* fsll16 */, Sparc::FSLL16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2126 /* fsll32 */, Sparc::FSLL32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2133 /* fsmuld */, Sparc::FSMULD, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_FPRegs, MCK_FPRegs, MCK_DFPRegs }, },
  { 2140 /* fsqrtd */, Sparc::FSQRTD, Convert__Reg1_1__Reg1_0, 0, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2147 /* fsqrtq */, Sparc::FSQRTQ, Convert__Reg1_1__Reg1_0, 0, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 2154 /* fsqrts */, Sparc::FSQRTS, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_FPRegs }, },
  { 2161 /* fsra16 */, Sparc::FSRA16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2168 /* fsra32 */, Sparc::FSRA32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2175 /* fsrc1 */, Sparc::FSRC1, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2181 /* fsrc1s */, Sparc::FSRC1S, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs }, },
  { 2188 /* fsrc2 */, Sparc::FSRC2, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2194 /* fsrc2s */, Sparc::FSRC2S, Convert__Reg1_1__Reg1_0, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs }, },
  { 2201 /* fsrl16 */, Sparc::FSRL16, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2208 /* fsrl32 */, Sparc::FSRL32, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2215 /* fstod */, Sparc::FSTOD, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_DFPRegs }, },
  { 2221 /* fstoi */, Sparc::FSTOI, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_FPRegs }, },
  { 2227 /* fstoq */, Sparc::FSTOQ, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_QFPRegs }, },
  { 2233 /* fstox */, Sparc::FSTOX, Convert__Reg1_1__Reg1_0, 0, { MCK_FPRegs, MCK_DFPRegs }, },
  { 2239 /* fsubd */, Sparc::FSUBD, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2245 /* fsubq */, Sparc::FSUBQ, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_QFPRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2251 /* fsubs */, Sparc::FSUBS, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2257 /* fxnor */, Sparc::FXNOR, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2263 /* fxnors */, Sparc::FXNORS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2270 /* fxor */, Sparc::FXOR, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2275 /* fxors */, Sparc::FXORS, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2281 /* fxtod */, Sparc::FXTOD, Convert__Reg1_1__Reg1_0, 0, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2287 /* fxtoq */, Sparc::FXTOQ, Convert__Reg1_1__Reg1_0, 0, { MCK_DFPRegs, MCK_QFPRegs }, },
  { 2293 /* fxtos */, Sparc::FXTOS, Convert__Reg1_1__Reg1_0, 0, { MCK_DFPRegs, MCK_FPRegs }, },
  { 2299 /* fzero */, Sparc::FZERO, Convert__Reg1_0__Tie0, Feature_HasVIS, { MCK_DFPRegs }, },
  { 2305 /* fzeros */, Sparc::FZEROS, Convert__Reg1_0__Tie0, Feature_HasVIS, { MCK_FPRegs }, },
  { 2312 /* inc */, Sparc::ADDri, Convert__Reg1_0__Reg1_0__imm_95_1, 0, { MCK_IntRegs }, },
  { 2312 /* inc */, Sparc::ADDri, Convert__Reg1_1__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 2316 /* inccc */, Sparc::ADDCCri, Convert__Reg1_0__Reg1_0__imm_95_1, 0, { MCK_IntRegs }, },
  { 2316 /* inccc */, Sparc::ADDCCri, Convert__Reg1_1__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 2322 /* jmp */, Sparc::JMPLri, Convert__regG0__MEMri2_0, 0, { MCK_MEMri }, },
  { 2322 /* jmp */, Sparc::JMPLrr, Convert__regG0__MEMrr2_0, 0, { MCK_MEMrr }, },
  { 2326 /* jmpl */, Sparc::JMPLri, Convert__Reg1_1__MEMri2_0, 0, { MCK_MEMri, MCK_IntRegs }, },
  { 2326 /* jmpl */, Sparc::JMPLrr, Convert__Reg1_1__MEMrr2_0, 0, { MCK_MEMrr, MCK_IntRegs }, },
  { 2331 /* ld */, Sparc::LDFSRri, Convert__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_fsr }, },
  { 2331 /* ld */, Sparc::LDFri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_FPRegs }, },
  { 2331 /* ld */, Sparc::LDri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 2331 /* ld */, Sparc::LDFSRrr, Convert__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK__PCT_fsr }, },
  { 2331 /* ld */, Sparc::LDFrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_FPRegs }, },
  { 2331 /* ld */, Sparc::LDrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 2334 /* lda */, Sparc::LDFArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, Feature_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_FPRegs }, },
  { 2334 /* lda */, Sparc::LDArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_IntRegs }, },
  { 2338 /* ldd */, Sparc::LDDri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntPair }, },
  { 2338 /* ldd */, Sparc::LDDFri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_DFPRegs }, },
  { 2338 /* ldd */, Sparc::LDDrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntPair }, },
  { 2338 /* ldd */, Sparc::LDDFrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_DFPRegs }, },
  { 2342 /* ldda */, Sparc::LDDArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_IntPair }, },
  { 2342 /* ldda */, Sparc::LDDFArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, Feature_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_DFPRegs }, },
  { 2347 /* ldq */, Sparc::LDQFri, Convert__Reg1_3__MEMri2_1, Feature_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK_QFPRegs }, },
  { 2347 /* ldq */, Sparc::LDQFrr, Convert__Reg1_3__MEMrr2_1, Feature_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_QFPRegs }, },
  { 2351 /* ldqa */, Sparc::LDQFArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, Feature_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_QFPRegs }, },
  { 2356 /* ldsb */, Sparc::LDSBri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 2356 /* ldsb */, Sparc::LDSBrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 2361 /* ldsba */, Sparc::LDSBArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_IntRegs }, },
  { 2367 /* ldsh */, Sparc::LDSHri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 2367 /* ldsh */, Sparc::LDSHrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 2372 /* ldsha */, Sparc::LDSHArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_IntRegs }, },
  { 2378 /* ldstub */, Sparc::LDSTUBri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 2378 /* ldstub */, Sparc::LDSTUBrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 2385 /* ldstuba */, Sparc::LDSTUBArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_IntRegs }, },
  { 2393 /* ldsw */, Sparc::LDSWri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 2393 /* ldsw */, Sparc::LDSWrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 2398 /* ldub */, Sparc::LDUBri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 2398 /* ldub */, Sparc::LDUBrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 2403 /* lduba */, Sparc::LDUBArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_IntRegs }, },
  { 2409 /* lduh */, Sparc::LDUHri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 2409 /* lduh */, Sparc::LDUHrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 2414 /* lduha */, Sparc::LDUHArr, Convert__Reg1_4__MEMrr2_1__Imm1_3, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_IntRegs }, },
  { 2420 /* ldx */, Sparc::LDXFSRri, Convert__MEMri2_1, Feature_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_fsr }, },
  { 2420 /* ldx */, Sparc::LDXri, Convert__Reg1_3__MEMri2_1, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 2420 /* ldx */, Sparc::LDXFSRrr, Convert__MEMrr2_1, Feature_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK__PCT_fsr }, },
  { 2420 /* ldx */, Sparc::LDXrr, Convert__Reg1_3__MEMrr2_1, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 2424 /* lzcnt */, Sparc::LZCNT, Convert__Reg1_1__Reg1_0, Feature_HasVIS3, { MCK_IntRegs, MCK_IntRegs }, },
  { 2430 /* membar */, Sparc::MEMBARi, Convert__Imm1_0, Feature_HasV9, { MCK_Imm }, },
  { 2437 /* mov */, Sparc::RDPSR, Convert__Reg1_1, 0, { MCK__PCT_psr, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::RDTBR, Convert__Reg1_1, 0, { MCK__PCT_tbr, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::RDWIM, Convert__Reg1_1, 0, { MCK__PCT_wim, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::RDASR, Convert__Reg1_1__Reg1_0, 0, { MCK_ASRRegs, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::WRPSRrr, Convert__regG0__Reg1_0, 0, { MCK_IntRegs, MCK__PCT_psr }, },
  { 2437 /* mov */, Sparc::WRTBRrr, Convert__regG0__Reg1_0, 0, { MCK_IntRegs, MCK__PCT_tbr }, },
  { 2437 /* mov */, Sparc::WRWIMrr, Convert__regG0__Reg1_0, 0, { MCK_IntRegs, MCK__PCT_wim }, },
  { 2437 /* mov */, Sparc::WRASRrr, Convert__Reg1_1__regG0__Reg1_0, 0, { MCK_IntRegs, MCK_ASRRegs }, },
  { 2437 /* mov */, Sparc::ORrr, Convert__Reg1_1__regG0__Reg1_0, 0, { MCK_IntRegs, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::WRPSRri, Convert__regG0__Imm1_0, 0, { MCK_Imm, MCK__PCT_psr }, },
  { 2437 /* mov */, Sparc::WRTBRri, Convert__regG0__Imm1_0, 0, { MCK_Imm, MCK__PCT_tbr }, },
  { 2437 /* mov */, Sparc::WRWIMri, Convert__regG0__Imm1_0, 0, { MCK_Imm, MCK__PCT_wim }, },
  { 2437 /* mov */, Sparc::WRASRri, Convert__Reg1_1__regG0__Imm1_0, 0, { MCK_Imm, MCK_ASRRegs }, },
  { 2437 /* mov */, Sparc::ORri, Convert__Reg1_1__regG0__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVFCCrr, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_fcc0, MCK_IntRegs, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVFCCri, Convert__Reg1_3__Imm1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_fcc0, MCK_Imm, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVICCrr, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVICCri, Convert__Reg1_3__Imm1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVXCCrr, Convert__Reg1_3__Reg1_2__Tie0__Imm1_0, 0, { MCK_Imm, MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::MOVXCCri, Convert__Reg1_3__Imm1_2__Tie0__Imm1_0, 0, { MCK_Imm, MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::V9MOVFCCrr, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2437 /* mov */, Sparc::V9MOVFCCri, Convert__Reg1_3__Reg1_1__Imm1_2__Tie0__Imm1_0, Feature_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2441 /* mova */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2441 /* mova */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2441 /* mova */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2441 /* mova */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_8, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2441 /* mova */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2441 /* mova */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_0, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2446 /* movcc */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2446 /* movcc */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2446 /* movcc */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2446 /* movcc */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2452 /* movcs */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2452 /* movcs */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2452 /* movcs */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2452 /* movcs */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2458 /* movdtox */, Sparc::MOVDTOX, Convert__Reg1_1__Reg1_0, Feature_HasVIS3, { MCK_DFPRegs, MCK_IntRegs }, },
  { 2458 /* movdtox */, Sparc::MOVWTOS, Convert__Reg1_1__Reg1_0, Feature_HasVIS3, { MCK_IntRegs, MCK_DFPRegs }, },
  { 2458 /* movdtox */, Sparc::MOVXTOD, Convert__Reg1_1__Reg1_0, Feature_HasVIS3, { MCK_IntRegs, MCK_DFPRegs }, },
  { 2466 /* move */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2466 /* move */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2466 /* move */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2466 /* move */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2466 /* move */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2466 /* move */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2471 /* moveq */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2471 /* moveq */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2471 /* moveq */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2471 /* moveq */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2477 /* movg */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2477 /* movg */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2477 /* movg */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_10, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2477 /* movg */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_10, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2477 /* movg */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_6, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2477 /* movg */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_6, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2482 /* movge */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2482 /* movge */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2482 /* movge */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_11, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2482 /* movge */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_11, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2482 /* movge */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_11, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2482 /* movge */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_11, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2488 /* movgeu */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2488 /* movgeu */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2488 /* movgeu */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2488 /* movgeu */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_13, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2495 /* movgu */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2495 /* movgu */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2495 /* movgu */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_12, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2495 /* movgu */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_12, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2501 /* movl */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2501 /* movl */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2501 /* movl */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_3, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2501 /* movl */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_3, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2501 /* movl */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_4, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2501 /* movl */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_4, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2506 /* movle */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2506 /* movle */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2506 /* movle */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_2, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2506 /* movle */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_2, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2506 /* movle */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_13, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2506 /* movle */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_13, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2512 /* movleu */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2512 /* movleu */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2512 /* movleu */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_4, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2512 /* movleu */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_4, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2519 /* movlg */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_2, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2519 /* movlg */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_2, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2525 /* movlu */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2525 /* movlu */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2525 /* movlu */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2525 /* movlu */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_5, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2531 /* movn */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2531 /* movn */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2531 /* movn */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_0, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2531 /* movn */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_0, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2531 /* movn */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_8, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2531 /* movn */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_8, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2536 /* movne */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2536 /* movne */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2536 /* movne */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2536 /* movne */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2536 /* movne */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2536 /* movne */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2542 /* movneg */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2542 /* movneg */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2542 /* movneg */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_6, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2542 /* movneg */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_6, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2549 /* movnz */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2549 /* movnz */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2549 /* movnz */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2549 /* movnz */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_9, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2549 /* movnz */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2549 /* movnz */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_1, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2555 /* movo */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_15, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2555 /* movo */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_15, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2560 /* movpos */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2560 /* movpos */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2560 /* movpos */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_14, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2560 /* movpos */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_14, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2567 /* movrgez */, Sparc::MOVRGEZrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2567 /* movrgez */, Sparc::MOVRGEZri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2575 /* movrgz */, Sparc::MOVRGZrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2575 /* movrgz */, Sparc::MOVRGZri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2582 /* movrlez */, Sparc::MOVRLEZrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2582 /* movrlez */, Sparc::MOVRLEZri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2590 /* movrlz */, Sparc::MOVRLZrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2590 /* movrlz */, Sparc::MOVRLZri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2597 /* movrnz */, Sparc::MOVRNZrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2597 /* movrnz */, Sparc::MOVRNZri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2604 /* movrz */, Sparc::MOVRRZrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2604 /* movrz */, Sparc::MOVRRZri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2610 /* movstosw */, Sparc::MOVSTOSW, Convert__Reg1_1__Reg1_0, Feature_HasVIS3, { MCK_DFPRegs, MCK_IntRegs }, },
  { 2619 /* movstouw */, Sparc::MOVSTOUW, Convert__Reg1_1__Reg1_0, Feature_HasVIS3, { MCK_DFPRegs, MCK_IntRegs }, },
  { 2628 /* movu */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_7, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2628 /* movu */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_7, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2633 /* movue */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_10, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2633 /* movue */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_10, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2639 /* movug */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_5, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2639 /* movug */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_5, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2645 /* movuge */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_12, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2645 /* movuge */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_12, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2652 /* movul */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_3, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2652 /* movul */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_3, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2658 /* movule */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_14, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2658 /* movule */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_14, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2665 /* movvc */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2665 /* movvc */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2665 /* movvc */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_15, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2665 /* movvc */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_15, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2671 /* movvs */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2671 /* movvs */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2671 /* movvs */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_7, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2671 /* movvs */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_7, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2677 /* movz */, Sparc::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK_IntRegs }, },
  { 2677 /* movz */, Sparc::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_Imm, MCK_IntRegs }, },
  { 2677 /* movz */, Sparc::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 2677 /* movz */, Sparc::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0__imm_95_1, 0, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 2677 /* movz */, Sparc::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2677 /* movz */, Sparc::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0__imm_95_9, Feature_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 2682 /* mulscc */, Sparc::MULSCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2682 /* mulscc */, Sparc::MULSCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2689 /* mulx */, Sparc::MULXrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2689 /* mulx */, Sparc::MULXri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2694 /* neg */, Sparc::SUBrr, Convert__Reg1_0__regG0__Reg1_0, 0, { MCK_IntRegs }, },
  { 2694 /* neg */, Sparc::SUBrr, Convert__Reg1_1__regG0__Reg1_0, 0, { MCK_IntRegs, MCK_IntRegs }, },
  { 2698 /* nop */, Sparc::NOP, Convert_NoOperands, 0, {  }, },
  { 2702 /* not */, Sparc::XNORrr, Convert__Reg1_0__Reg1_0__regG0, 0, { MCK_IntRegs }, },
  { 2702 /* not */, Sparc::XNORrr, Convert__Reg1_1__Reg1_0__regG0, 0, { MCK_IntRegs, MCK_IntRegs }, },
  { 2706 /* or */, Sparc::ORrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2706 /* or */, Sparc::ORri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2709 /* orcc */, Sparc::ORCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2709 /* orcc */, Sparc::ORCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2714 /* orn */, Sparc::ORNrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2714 /* orn */, Sparc::ORNri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2718 /* orncc */, Sparc::ORNCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2718 /* orncc */, Sparc::ORNCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2724 /* pdist */, Sparc::PDIST, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2730 /* pdistn */, Sparc::PDISTN, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2737 /* popc */, Sparc::POPCrr, Convert__Reg1_1__Reg1_0, Feature_HasV9, { MCK_IntRegs, MCK_IntRegs }, },
  { 2742 /* rd */, Sparc::RDPSR, Convert__Reg1_1, 0, { MCK__PCT_psr, MCK_IntRegs }, },
  { 2742 /* rd */, Sparc::RDTBR, Convert__Reg1_1, 0, { MCK__PCT_tbr, MCK_IntRegs }, },
  { 2742 /* rd */, Sparc::RDWIM, Convert__Reg1_1, 0, { MCK__PCT_wim, MCK_IntRegs }, },
  { 2742 /* rd */, Sparc::RDASR, Convert__Reg1_1__Reg1_0, 0, { MCK_ASRRegs, MCK_IntRegs }, },
  { 2745 /* rdpr */, Sparc::RDPR, Convert__Reg1_1__Reg1_0, Feature_HasV9, { MCK_PRRegs, MCK_IntRegs }, },
  { 2750 /* restore */, Sparc::RESTORErr, Convert__regG0__regG0__regG0, 0, {  }, },
  { 2750 /* restore */, Sparc::RESTORErr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2750 /* restore */, Sparc::RESTOREri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2758 /* ret */, Sparc::RET, Convert__imm_95_8, 0, {  }, },
  { 2762 /* retl */, Sparc::RETL, Convert__imm_95_8, 0, {  }, },
  { 2767 /* rett */, Sparc::RETTri, Convert__MEMri2_0, 0, { MCK_MEMri }, },
  { 2767 /* rett */, Sparc::RETTrr, Convert__MEMrr2_0, 0, { MCK_MEMrr }, },
  { 2772 /* save */, Sparc::SAVErr, Convert__regG0__regG0__regG0, 0, {  }, },
  { 2772 /* save */, Sparc::SAVErr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2772 /* save */, Sparc::SAVEri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2777 /* sdiv */, Sparc::SDIVrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2777 /* sdiv */, Sparc::SDIVri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2782 /* sdivcc */, Sparc::SDIVCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2782 /* sdivcc */, Sparc::SDIVCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2789 /* sdivx */, Sparc::SDIVXrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2789 /* sdivx */, Sparc::SDIVXri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2795 /* set */, Sparc::SET, Convert__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 2799 /* sethi */, Sparc::SETHIi, Convert__Reg1_1__Imm1_0, 0, { MCK_Imm, MCK_IntRegs }, },
  { 2805 /* shutdown */, Sparc::SHUTDOWN, Convert_NoOperands, Feature_HasVIS, {  }, },
  { 2814 /* siam */, Sparc::SIAM, Convert_NoOperands, Feature_HasVIS2, {  }, },
  { 2819 /* signx */, Sparc::SRArr, Convert__Reg1_0__Reg1_0__regG0, Feature_HasV9, { MCK_IntRegs }, },
  { 2819 /* signx */, Sparc::SRArr, Convert__Reg1_1__Reg1_0__regG0, Feature_HasV9, { MCK_IntRegs, MCK_IntRegs }, },
  { 2825 /* sll */, Sparc::SLLrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2825 /* sll */, Sparc::SLLri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2829 /* sllx */, Sparc::SLLXrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2829 /* sllx */, Sparc::SLLXri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2834 /* smul */, Sparc::SMULrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2834 /* smul */, Sparc::SMULri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2839 /* smulcc */, Sparc::SMULCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2839 /* smulcc */, Sparc::SMULCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2846 /* sra */, Sparc::SRArr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2846 /* sra */, Sparc::SRAri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2850 /* srax */, Sparc::SRAXrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2850 /* srax */, Sparc::SRAXri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2855 /* srl */, Sparc::SRLrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2855 /* srl */, Sparc::SRLri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2859 /* srlx */, Sparc::SRLXrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2859 /* srlx */, Sparc::SRLXri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2864 /* st */, Sparc::STFSRri, Convert__MEMri2_2, 0, { MCK__PCT_fsr, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2864 /* st */, Sparc::STFSRrr, Convert__MEMrr2_2, 0, { MCK__PCT_fsr, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2864 /* st */, Sparc::STFri, Convert__MEMri2_2__Reg1_0, 0, { MCK_FPRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2864 /* st */, Sparc::STFrr, Convert__MEMrr2_2__Reg1_0, 0, { MCK_FPRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2864 /* st */, Sparc::STri, Convert__MEMri2_2__Reg1_0, 0, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2864 /* st */, Sparc::STrr, Convert__MEMrr2_2__Reg1_0, 0, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2867 /* sta */, Sparc::STFArr, Convert__MEMrr2_2__Reg1_0__Imm1_4, Feature_HasV9, { MCK_FPRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm }, },
  { 2867 /* sta */, Sparc::STArr, Convert__MEMrr2_2__Reg1_0__Imm1_4, 0, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm }, },
  { 2871 /* stb */, Sparc::STBri, Convert__MEMri2_2__Reg1_0, 0, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2871 /* stb */, Sparc::STBrr, Convert__MEMrr2_2__Reg1_0, 0, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2875 /* stba */, Sparc::STBArr, Convert__MEMrr2_2__Reg1_0__Imm1_4, 0, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm }, },
  { 2880 /* stbar */, Sparc::STBAR, Convert_NoOperands, 0, {  }, },
  { 2886 /* std */, Sparc::STDri, Convert__MEMri2_2__Reg1_0, 0, { MCK_IntPair, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2886 /* std */, Sparc::STDrr, Convert__MEMrr2_2__Reg1_0, 0, { MCK_IntPair, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2886 /* std */, Sparc::STDFri, Convert__MEMri2_2__Reg1_0, 0, { MCK_DFPRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2886 /* std */, Sparc::STDFrr, Convert__MEMrr2_2__Reg1_0, 0, { MCK_DFPRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2890 /* stda */, Sparc::STDArr, Convert__MEMrr2_2__Reg1_0__Imm1_4, 0, { MCK_IntPair, MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm }, },
  { 2890 /* stda */, Sparc::STDFArr, Convert__MEMrr2_2__Reg1_0__Imm1_4, Feature_HasV9, { MCK_DFPRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm }, },
  { 2895 /* sth */, Sparc::STHri, Convert__MEMri2_2__Reg1_0, 0, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2895 /* sth */, Sparc::STHrr, Convert__MEMrr2_2__Reg1_0, 0, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2899 /* stha */, Sparc::STHArr, Convert__MEMrr2_2__Reg1_0__Imm1_4, 0, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm }, },
  { 2904 /* stq */, Sparc::STQFri, Convert__MEMri2_2__Reg1_0, Feature_HasV9, { MCK_QFPRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2904 /* stq */, Sparc::STQFrr, Convert__MEMrr2_2__Reg1_0, Feature_HasV9, { MCK_QFPRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2908 /* stqa */, Sparc::STQFArr, Convert__MEMrr2_2__Reg1_0__Imm1_4, Feature_HasV9, { MCK_QFPRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm }, },
  { 2913 /* stx */, Sparc::STXFSRri, Convert__MEMri2_2, Feature_HasV9, { MCK__PCT_fsr, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2913 /* stx */, Sparc::STXFSRrr, Convert__MEMrr2_2, Feature_HasV9, { MCK__PCT_fsr, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2913 /* stx */, Sparc::STXri, Convert__MEMri2_2__Reg1_0, 0, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 2913 /* stx */, Sparc::STXrr, Convert__MEMrr2_2__Reg1_0, 0, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 2917 /* sub */, Sparc::SUBrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2917 /* sub */, Sparc::SUBri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2921 /* subcc */, Sparc::SUBCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2921 /* subcc */, Sparc::SUBCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2927 /* subx */, Sparc::SUBCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2927 /* subx */, Sparc::SUBCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2932 /* subxcc */, Sparc::SUBErr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2932 /* subxcc */, Sparc::SUBEri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2939 /* swap */, Sparc::SWAPri, Convert__Reg1_3__MEMri2_1__Tie0, 0, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 2939 /* swap */, Sparc::SWAPrr, Convert__Reg1_3__MEMrr2_1__Tie0, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 2944 /* swapa */, Sparc::SWAPArr, Convert__Reg1_4__MEMrr2_1__Imm1_3__Tie0, 0, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_Imm, MCK_IntRegs }, },
  { 2950 /* t */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_8, 0, { MCK_IntRegs }, },
  { 2950 /* t */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_8, 0, { MCK_Imm }, },
  { 2950 /* t */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2950 /* t */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2950 /* t */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_8, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2950 /* t */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_8, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2950 /* t */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_8, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2950 /* t */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_8, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2950 /* t */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2950 /* t */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2950 /* t */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_8, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2950 /* t */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_8, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2950 /* t */, Sparc::TICCrr, Convert__Reg1_2__Reg1_4__Imm1_0, 0, { MCK_Imm, MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2950 /* t */, Sparc::TICCri, Convert__Reg1_2__Imm1_4__Imm1_0, 0, { MCK_Imm, MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2950 /* t */, Sparc::TXCCrr, Convert__Reg1_2__Reg1_4__Imm1_0, 0, { MCK_Imm, MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2950 /* t */, Sparc::TXCCri, Convert__Reg1_2__Imm1_4__Imm1_0, 0, { MCK_Imm, MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2952 /* ta */, Sparc::TA3, Convert_NoOperands, 0, { MCK_3 }, },
  { 2952 /* ta */, Sparc::TA5, Convert_NoOperands, 0, { MCK_5 }, },
  { 2952 /* ta */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_8, 0, { MCK_IntRegs }, },
  { 2952 /* ta */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_8, 0, { MCK_Imm }, },
  { 2952 /* ta */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2952 /* ta */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2952 /* ta */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_8, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2952 /* ta */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_8, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2952 /* ta */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_8, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2952 /* ta */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_8, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2952 /* ta */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2952 /* ta */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_8, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2952 /* ta */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_8, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2952 /* ta */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_8, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2955 /* taddcc */, Sparc::TADDCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2955 /* taddcc */, Sparc::TADDCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2962 /* taddcctv */, Sparc::TADDCCTVrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 2962 /* taddcctv */, Sparc::TADDCCTVri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 2971 /* tcc */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_13, 0, { MCK_IntRegs }, },
  { 2971 /* tcc */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_13, 0, { MCK_Imm }, },
  { 2971 /* tcc */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2971 /* tcc */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2971 /* tcc */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_13, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2971 /* tcc */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_13, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2971 /* tcc */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_13, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2971 /* tcc */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_13, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2971 /* tcc */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2971 /* tcc */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2971 /* tcc */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_13, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2971 /* tcc */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_13, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2975 /* tcs */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_5, 0, { MCK_IntRegs }, },
  { 2975 /* tcs */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_5, 0, { MCK_Imm }, },
  { 2975 /* tcs */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2975 /* tcs */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2975 /* tcs */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_5, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2975 /* tcs */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_5, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2975 /* tcs */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_5, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2975 /* tcs */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_5, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2975 /* tcs */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2975 /* tcs */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2975 /* tcs */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_5, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2975 /* tcs */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_5, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2979 /* te */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_1, 0, { MCK_IntRegs }, },
  { 2979 /* te */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_1, 0, { MCK_Imm }, },
  { 2979 /* te */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2979 /* te */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2979 /* te */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2979 /* te */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2979 /* te */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_1, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2979 /* te */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_1, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2979 /* te */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2979 /* te */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2979 /* te */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2979 /* te */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2982 /* teq */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_1, 0, { MCK_IntRegs }, },
  { 2982 /* teq */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_1, 0, { MCK_Imm }, },
  { 2982 /* teq */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2982 /* teq */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2982 /* teq */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2982 /* teq */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2982 /* teq */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_1, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2982 /* teq */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_1, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2982 /* teq */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2982 /* teq */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2982 /* teq */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2982 /* teq */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2986 /* tg */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_10, 0, { MCK_IntRegs }, },
  { 2986 /* tg */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_10, 0, { MCK_Imm }, },
  { 2986 /* tg */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2986 /* tg */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2986 /* tg */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_10, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2986 /* tg */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_10, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2986 /* tg */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_10, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2986 /* tg */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_10, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2986 /* tg */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2986 /* tg */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_10, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2986 /* tg */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_10, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2986 /* tg */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_10, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2989 /* tge */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_11, 0, { MCK_IntRegs }, },
  { 2989 /* tge */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_11, 0, { MCK_Imm }, },
  { 2989 /* tge */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2989 /* tge */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2989 /* tge */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_11, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2989 /* tge */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_11, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2989 /* tge */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_11, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2989 /* tge */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_11, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2989 /* tge */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2989 /* tge */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_11, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2989 /* tge */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_11, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2989 /* tge */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_11, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2993 /* tgeu */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_13, 0, { MCK_IntRegs }, },
  { 2993 /* tgeu */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_13, 0, { MCK_Imm }, },
  { 2993 /* tgeu */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2993 /* tgeu */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2993 /* tgeu */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_13, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2993 /* tgeu */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_13, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2993 /* tgeu */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_13, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2993 /* tgeu */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_13, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2993 /* tgeu */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2993 /* tgeu */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_13, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2993 /* tgeu */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_13, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2993 /* tgeu */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_13, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2998 /* tgu */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_12, 0, { MCK_IntRegs }, },
  { 2998 /* tgu */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_12, 0, { MCK_Imm }, },
  { 2998 /* tgu */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 2998 /* tgu */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 2998 /* tgu */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_12, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 2998 /* tgu */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_12, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 2998 /* tgu */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_12, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2998 /* tgu */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_12, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2998 /* tgu */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2998 /* tgu */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_12, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 2998 /* tgu */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_12, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 2998 /* tgu */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_12, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3002 /* tl */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_3, 0, { MCK_IntRegs }, },
  { 3002 /* tl */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_3, 0, { MCK_Imm }, },
  { 3002 /* tl */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3002 /* tl */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3002 /* tl */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_3, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3002 /* tl */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_3, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3002 /* tl */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_3, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3002 /* tl */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_3, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3002 /* tl */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3002 /* tl */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_3, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3002 /* tl */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_3, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3002 /* tl */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_3, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3005 /* tle */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_2, 0, { MCK_IntRegs }, },
  { 3005 /* tle */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_2, 0, { MCK_Imm }, },
  { 3005 /* tle */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3005 /* tle */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3005 /* tle */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_2, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3005 /* tle */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_2, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3005 /* tle */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_2, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3005 /* tle */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_2, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3005 /* tle */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3005 /* tle */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_2, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3005 /* tle */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_2, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3005 /* tle */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_2, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3009 /* tleu */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_4, 0, { MCK_IntRegs }, },
  { 3009 /* tleu */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_4, 0, { MCK_Imm }, },
  { 3009 /* tleu */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3009 /* tleu */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3009 /* tleu */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_4, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3009 /* tleu */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_4, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3009 /* tleu */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_4, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3009 /* tleu */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_4, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3009 /* tleu */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3009 /* tleu */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_4, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3009 /* tleu */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_4, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3009 /* tleu */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_4, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3014 /* tlu */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_5, 0, { MCK_IntRegs }, },
  { 3014 /* tlu */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_5, 0, { MCK_Imm }, },
  { 3014 /* tlu */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3014 /* tlu */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3014 /* tlu */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_5, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3014 /* tlu */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_5, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3014 /* tlu */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_5, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3014 /* tlu */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_5, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3014 /* tlu */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3014 /* tlu */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_5, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3014 /* tlu */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_5, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3014 /* tlu */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_5, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3018 /* tn */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_0, 0, { MCK_IntRegs }, },
  { 3018 /* tn */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_0, 0, { MCK_Imm }, },
  { 3018 /* tn */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3018 /* tn */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3018 /* tn */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_0, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3018 /* tn */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_0, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3018 /* tn */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_0, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3018 /* tn */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_0, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3018 /* tn */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3018 /* tn */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_0, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3018 /* tn */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_0, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3018 /* tn */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_0, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3021 /* tne */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_9, 0, { MCK_IntRegs }, },
  { 3021 /* tne */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_9, 0, { MCK_Imm }, },
  { 3021 /* tne */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3021 /* tne */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3021 /* tne */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_9, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3021 /* tne */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_9, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3021 /* tne */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_9, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3021 /* tne */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_9, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3021 /* tne */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3021 /* tne */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3021 /* tne */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_9, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3021 /* tne */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_9, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3025 /* tneg */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_6, 0, { MCK_IntRegs }, },
  { 3025 /* tneg */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_6, 0, { MCK_Imm }, },
  { 3025 /* tneg */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3025 /* tneg */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3025 /* tneg */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_6, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3025 /* tneg */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_6, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3025 /* tneg */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_6, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3025 /* tneg */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_6, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3025 /* tneg */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3025 /* tneg */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_6, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3025 /* tneg */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_6, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3025 /* tneg */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_6, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3030 /* tnz */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_9, 0, { MCK_IntRegs }, },
  { 3030 /* tnz */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_9, 0, { MCK_Imm }, },
  { 3030 /* tnz */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3030 /* tnz */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3030 /* tnz */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_9, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3030 /* tnz */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_9, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3030 /* tnz */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_9, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3030 /* tnz */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_9, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3030 /* tnz */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3030 /* tnz */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_9, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3030 /* tnz */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_9, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3030 /* tnz */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_9, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3034 /* tpos */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_14, 0, { MCK_IntRegs }, },
  { 3034 /* tpos */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_14, 0, { MCK_Imm }, },
  { 3034 /* tpos */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3034 /* tpos */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3034 /* tpos */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_14, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3034 /* tpos */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_14, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3034 /* tpos */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_14, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3034 /* tpos */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_14, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3034 /* tpos */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3034 /* tpos */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_14, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3034 /* tpos */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_14, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3034 /* tpos */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_14, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3039 /* tst */, Sparc::ORCCrr, Convert__regG0__Reg1_0__regG0, 0, { MCK_IntRegs }, },
  { 3043 /* tsubcc */, Sparc::TSUBCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3043 /* tsubcc */, Sparc::TSUBCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3050 /* tsubcctv */, Sparc::TSUBCCTVrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3050 /* tsubcctv */, Sparc::TSUBCCTVri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3059 /* tvc */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_15, 0, { MCK_IntRegs }, },
  { 3059 /* tvc */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_15, 0, { MCK_Imm }, },
  { 3059 /* tvc */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3059 /* tvc */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3059 /* tvc */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_15, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3059 /* tvc */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_15, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3059 /* tvc */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_15, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3059 /* tvc */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_15, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3059 /* tvc */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3059 /* tvc */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_15, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3059 /* tvc */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_15, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3059 /* tvc */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_15, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3063 /* tvs */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_7, 0, { MCK_IntRegs }, },
  { 3063 /* tvs */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_7, 0, { MCK_Imm }, },
  { 3063 /* tvs */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3063 /* tvs */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3063 /* tvs */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_7, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3063 /* tvs */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_7, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3063 /* tvs */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_7, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3063 /* tvs */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_7, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3063 /* tvs */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3063 /* tvs */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_7, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3063 /* tvs */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_7, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3063 /* tvs */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_7, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3067 /* tz */, Sparc::TICCrr, Convert__regG0__Reg1_0__imm_95_1, 0, { MCK_IntRegs }, },
  { 3067 /* tz */, Sparc::TICCri, Convert__regG0__Imm1_0__imm_95_1, 0, { MCK_Imm }, },
  { 3067 /* tz */, Sparc::TICCrr, Convert__regG0__Reg1_1__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs }, },
  { 3067 /* tz */, Sparc::TICCri, Convert__regG0__Imm1_1__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_Imm }, },
  { 3067 /* tz */, Sparc::TXCCrr, Convert__regG0__Reg1_1__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3067 /* tz */, Sparc::TXCCri, Convert__regG0__Imm1_1__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3067 /* tz */, Sparc::TICCrr, Convert__Reg1_0__Reg1_2__imm_95_1, 0, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3067 /* tz */, Sparc::TICCri, Convert__Reg1_0__Imm1_2__imm_95_1, 0, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3067 /* tz */, Sparc::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3067 /* tz */, Sparc::TICCri, Convert__Reg1_1__Imm1_3__imm_95_1, Feature_HasV9, { MCK__PCT_icc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3067 /* tz */, Sparc::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3067 /* tz */, Sparc::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_1, Feature_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3070 /* udiv */, Sparc::UDIVrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3070 /* udiv */, Sparc::UDIVri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3075 /* udivcc */, Sparc::UDIVCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3075 /* udivcc */, Sparc::UDIVCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3082 /* udivx */, Sparc::UDIVXrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3082 /* udivx */, Sparc::UDIVXri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3088 /* umul */, Sparc::UMULrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3088 /* umul */, Sparc::UMULri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3093 /* umulcc */, Sparc::UMULCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3093 /* umulcc */, Sparc::UMULCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3100 /* umulxhi */, Sparc::UMULXHI, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3108 /* unimp */, Sparc::UNIMP, Convert__Imm1_0, 0, { MCK_Imm }, },
  { 3114 /* wr */, Sparc::WRPSRrr, Convert__regG0__Reg1_0, 0, { MCK_IntRegs, MCK__PCT_psr }, },
  { 3114 /* wr */, Sparc::WRTBRrr, Convert__regG0__Reg1_0, 0, { MCK_IntRegs, MCK__PCT_tbr }, },
  { 3114 /* wr */, Sparc::WRWIMrr, Convert__regG0__Reg1_0, 0, { MCK_IntRegs, MCK__PCT_wim }, },
  { 3114 /* wr */, Sparc::WRASRrr, Convert__Reg1_1__regG0__Reg1_0, 0, { MCK_IntRegs, MCK_ASRRegs }, },
  { 3114 /* wr */, Sparc::WRPSRri, Convert__regG0__Imm1_0, 0, { MCK_Imm, MCK__PCT_psr }, },
  { 3114 /* wr */, Sparc::WRTBRri, Convert__regG0__Imm1_0, 0, { MCK_Imm, MCK__PCT_tbr }, },
  { 3114 /* wr */, Sparc::WRWIMri, Convert__regG0__Imm1_0, 0, { MCK_Imm, MCK__PCT_wim }, },
  { 3114 /* wr */, Sparc::WRASRri, Convert__Reg1_1__regG0__Imm1_0, 0, { MCK_Imm, MCK_ASRRegs }, },
  { 3114 /* wr */, Sparc::WRPSRrr, Convert__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK__PCT_psr }, },
  { 3114 /* wr */, Sparc::WRTBRrr, Convert__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK__PCT_tbr }, },
  { 3114 /* wr */, Sparc::WRWIMrr, Convert__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK__PCT_wim }, },
  { 3114 /* wr */, Sparc::WRASRrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_ASRRegs }, },
  { 3114 /* wr */, Sparc::WRPSRri, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK__PCT_psr }, },
  { 3114 /* wr */, Sparc::WRTBRri, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK__PCT_tbr }, },
  { 3114 /* wr */, Sparc::WRWIMri, Convert__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK__PCT_wim }, },
  { 3114 /* wr */, Sparc::WRASRri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_ASRRegs }, },
  { 3117 /* wrpr */, Sparc::WRPRrr, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasV9, { MCK_IntRegs, MCK_IntRegs, MCK_PRRegs }, },
  { 3117 /* wrpr */, Sparc::WRPRri, Convert__Reg1_2__Reg1_0__Imm1_1, Feature_HasV9, { MCK_IntRegs, MCK_Imm, MCK_PRRegs }, },
  { 3122 /* xmulx */, Sparc::XMULX, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3128 /* xmulxhi */, Sparc::XMULXHI, Convert__Reg1_2__Reg1_0__Reg1_1, Feature_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3136 /* xnor */, Sparc::XNORrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3136 /* xnor */, Sparc::XNORri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3141 /* xnorcc */, Sparc::XNORCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3141 /* xnorcc */, Sparc::XNORCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3148 /* xor */, Sparc::XORrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3148 /* xor */, Sparc::XORri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3152 /* xorcc */, Sparc::XORCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, 0, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3152 /* xorcc */, Sparc::XORCCri, Convert__Reg1_2__Reg1_0__Imm1_1, 0, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
};

unsigned SparcAsmParser::
MatchInstructionImpl(const OperandVector &Operands,
                     MCInst &Inst, uint64_t &ErrorInfo,
                     bool matchingInlineAsm, unsigned VariantID) {
  // Eliminate obvious mismatches.
  if (Operands.size() > 6) {
    ErrorInfo = 6;
    return Match_InvalidOperand;
  }

  // Get the current feature set.
  uint64_t AvailableFeatures = getAvailableFeatures();

  // Get the instruction mnemonic, which is the first token.
  StringRef Mnemonic = ((SparcOperand&)*Operands[0]).getToken();

  // Process all MnemonicAliases to remap the mnemonic.
  applyMnemonicAliases(Mnemonic, AvailableFeatures, VariantID);

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
    for (unsigned i = 0; i != 5; ++i) {
      auto Formal = static_cast<MatchClassKind>(it->Classes[i]);
      if (i+1 >= Operands.size()) {
        OperandsValid = (Formal == InvalidMatchClass);
        if (!OperandsValid) ErrorInfo = i+1;
        break;
      }
      MCParsedAsmOperand &Actual = *Operands[i+1];
      unsigned Diag = validateOperandClass(Actual, Formal);
      if (Diag == Match_Success)
        continue;
      // If the generic handler indicates an invalid operand
      // failure, check for a special case.
      if (Diag == Match_InvalidOperand) {
        Diag = validateTargetOperandClass(Actual, Formal);
        if (Diag == Match_Success)
          continue;
      }
      // If this operand is broken for all of the instances of this
      // mnemonic, keep track of it so we can report loc info.
      // If we already had a match that only failed due to a
      // target predicate, that diagnostic is preferred.
      if (!HadMatchOtherThanPredicate &&
          (it == MnemonicRange.first || ErrorInfo <= i+1)) {
        ErrorInfo = i+1;
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

namespace {
  struct OperandMatchEntry {
    uint8_t RequiredFeatures;
    uint16_t Mnemonic;
    uint8_t Class;
    uint8_t OperandMask;

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
} // end anonymous namespace.

static const OperandMatchEntry OperandMatchTable[84] = {
  /* Operand List Mask, Mnemonic, Operand Class, Features */
  { 0, 252 /* call */, MCK_MEMri, 1 /* 0 */ },
  { 0, 252 /* call */, MCK_MEMrr, 1 /* 0 */ },
  { 0, 266 /* clr */, MCK_MEMri, 2 /* 1 */ },
  { 0, 266 /* clr */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 270 /* clrb */, MCK_MEMri, 2 /* 1 */ },
  { 0, 270 /* clrb */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 275 /* clrh */, MCK_MEMri, 2 /* 1 */ },
  { 0, 275 /* clrh */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 829 /* flush */, MCK_MEMri, 1 /* 0 */ },
  { 0, 829 /* flush */, MCK_MEMrr, 1 /* 0 */ },
  { 0, 2322 /* jmp */, MCK_MEMri, 1 /* 0 */ },
  { 0, 2322 /* jmp */, MCK_MEMrr, 1 /* 0 */ },
  { 0, 2326 /* jmpl */, MCK_MEMri, 1 /* 0 */ },
  { 0, 2326 /* jmpl */, MCK_MEMrr, 1 /* 0 */ },
  { 0, 2331 /* ld */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2331 /* ld */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2331 /* ld */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2331 /* ld */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2331 /* ld */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2331 /* ld */, MCK_MEMrr, 2 /* 1 */ },
  { Feature_HasV9, 2334 /* lda */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2334 /* lda */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2338 /* ldd */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2338 /* ldd */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2338 /* ldd */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2338 /* ldd */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2342 /* ldda */, MCK_MEMrr, 2 /* 1 */ },
  { Feature_HasV9, 2342 /* ldda */, MCK_MEMrr, 2 /* 1 */ },
  { Feature_HasV9, 2347 /* ldq */, MCK_MEMri, 2 /* 1 */ },
  { Feature_HasV9, 2347 /* ldq */, MCK_MEMrr, 2 /* 1 */ },
  { Feature_HasV9, 2351 /* ldqa */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2356 /* ldsb */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2356 /* ldsb */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2361 /* ldsba */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2367 /* ldsh */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2367 /* ldsh */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2372 /* ldsha */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2378 /* ldstub */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2378 /* ldstub */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2385 /* ldstuba */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2393 /* ldsw */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2393 /* ldsw */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2398 /* ldub */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2398 /* ldub */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2403 /* lduba */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2409 /* lduh */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2409 /* lduh */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2414 /* lduha */, MCK_MEMrr, 2 /* 1 */ },
  { Feature_HasV9, 2420 /* ldx */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2420 /* ldx */, MCK_MEMri, 2 /* 1 */ },
  { Feature_HasV9, 2420 /* ldx */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2420 /* ldx */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2767 /* rett */, MCK_MEMri, 1 /* 0 */ },
  { 0, 2767 /* rett */, MCK_MEMrr, 1 /* 0 */ },
  { 0, 2864 /* st */, MCK_MEMri, 4 /* 2 */ },
  { 0, 2864 /* st */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2864 /* st */, MCK_MEMri, 4 /* 2 */ },
  { 0, 2864 /* st */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2864 /* st */, MCK_MEMri, 4 /* 2 */ },
  { 0, 2864 /* st */, MCK_MEMrr, 4 /* 2 */ },
  { Feature_HasV9, 2867 /* sta */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2867 /* sta */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2871 /* stb */, MCK_MEMri, 4 /* 2 */ },
  { 0, 2871 /* stb */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2875 /* stba */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2886 /* std */, MCK_MEMri, 4 /* 2 */ },
  { 0, 2886 /* std */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2886 /* std */, MCK_MEMri, 4 /* 2 */ },
  { 0, 2886 /* std */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2890 /* stda */, MCK_MEMrr, 4 /* 2 */ },
  { Feature_HasV9, 2890 /* stda */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2895 /* sth */, MCK_MEMri, 4 /* 2 */ },
  { 0, 2895 /* sth */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2899 /* stha */, MCK_MEMrr, 4 /* 2 */ },
  { Feature_HasV9, 2904 /* stq */, MCK_MEMri, 4 /* 2 */ },
  { Feature_HasV9, 2904 /* stq */, MCK_MEMrr, 4 /* 2 */ },
  { Feature_HasV9, 2908 /* stqa */, MCK_MEMrr, 4 /* 2 */ },
  { Feature_HasV9, 2913 /* stx */, MCK_MEMri, 4 /* 2 */ },
  { Feature_HasV9, 2913 /* stx */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2913 /* stx */, MCK_MEMri, 4 /* 2 */ },
  { 0, 2913 /* stx */, MCK_MEMrr, 4 /* 2 */ },
  { 0, 2939 /* swap */, MCK_MEMri, 2 /* 1 */ },
  { 0, 2939 /* swap */, MCK_MEMrr, 2 /* 1 */ },
  { 0, 2944 /* swapa */, MCK_MEMrr, 2 /* 1 */ },
};

SparcAsmParser::OperandMatchResultTy SparcAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_MEMri:
    return parseMEMOperand(Operands);
  case MCK_MEMrr:
    return parseMEMOperand(Operands);
  default:
    return MatchOperand_NoMatch;
  }
  return MatchOperand_NoMatch;
}

SparcAsmParser::OperandMatchResultTy SparcAsmParser::
MatchOperandParserImpl(OperandVector &Operands,
                       StringRef Mnemonic) {
  // Get the current feature set.
  uint64_t AvailableFeatures = getAvailableFeatures();

  // Get the next operand index.
  unsigned NextOpNum = Operands.size() - 1;
  // Search the table.
  auto MnemonicRange =
    std::equal_range(std::begin(OperandMatchTable), std::end(OperandMatchTable),
                     Mnemonic, LessOpcodeOperand());

  if (MnemonicRange.first == MnemonicRange.second)
    return MatchOperand_NoMatch;

  for (const OperandMatchEntry *it = MnemonicRange.first,
       *ie = MnemonicRange.second; it != ie; ++it) {
    // equal_range guarantees that instruction mnemonic matches.
    assert(Mnemonic == it->getMnemonic());

    // check if the available features match
    if ((AvailableFeatures & it->RequiredFeatures) != it->RequiredFeatures) {
      continue;
    }

    // check if the operand in question has a custom parser.
    if (!(it->OperandMask & (1 << NextOpNum)))
      continue;

    // call custom parse method to handle the operand
    OperandMatchResultTy Result = tryCustomParseOperand(Operands, it->Class);
    if (Result != MatchOperand_NoMatch)
      return Result;
  }

  // Okay, we had no match.
  return MatchOperand_NoMatch;
}

#endif // GET_MATCHER_IMPLEMENTATION

