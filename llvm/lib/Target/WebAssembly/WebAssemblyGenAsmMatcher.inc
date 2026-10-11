/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: WebAssembly.td                                                       *|
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
  Feature_HasAtomicsBit = 0,
  Feature_HasBulkMemoryBit = 1,
  Feature_HasBulkMemoryOptBit = 2,
  Feature_HasCallIndirectOverlongBit = 3,
  Feature_HasExceptionHandlingBit = 4,
  Feature_HasExtendedConstBit = 5,
  Feature_HasFP16Bit = 6,
  Feature_HasGCBit = 7,
  Feature_HasMultiMemoryBit = 8,
  Feature_HasMultivalueBit = 9,
  Feature_HasMutableGlobalsBit = 10,
  Feature_HasNontrappingFPToIntBit = 11,
  Feature_NotHasNontrappingFPToIntBit = 19,
  Feature_HasReferenceTypesBit = 12,
  Feature_HasRelaxedAtomicsBit = 13,
  Feature_HasRelaxedSIMDBit = 14,
  Feature_HasSignExtBit = 16,
  Feature_HasSIMD128Bit = 15,
  Feature_HasTailCallBit = 17,
  Feature_HasWideArithmeticBit = 18,
};

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_HasAtomicsBit: return "atomics";
  case Feature_HasBulkMemoryBit: return "bulk-memory";
  case Feature_HasBulkMemoryOptBit: return "bulk-memory-opt";
  case Feature_HasCallIndirectOverlongBit: return "call-indirect-overlong";
  case Feature_HasExceptionHandlingBit: return "exception-handling";
  case Feature_HasExtendedConstBit: return "extended-const";
  case Feature_HasFP16Bit: return "fp16";
  case Feature_HasGCBit: return "gc";
  case Feature_HasMultiMemoryBit: return "multimemory";
  case Feature_HasMultivalueBit: return "multivalue";
  case Feature_HasMutableGlobalsBit: return "mutable-globals";
  case Feature_HasNontrappingFPToIntBit: return "nontrapping-fptoint";
  case Feature_NotHasNontrappingFPToIntBit: return "nontrapping-fptoint";
  case Feature_HasReferenceTypesBit: return "reference-types";
  case Feature_HasRelaxedAtomicsBit: return "relaxed-atomics";
  case Feature_HasRelaxedSIMDBit: return "relaxed-simd";
  case Feature_HasSignExtBit: return "sign-ext";
  case Feature_HasSIMD128Bit: return "simd128";
  case Feature_HasTailCallBit: return "tail-call";
  case Feature_HasWideArithmeticBit: return "wide-arithmetic";
  default: return "(unknown)";
  }
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
  CVT_95_addBrListOperands,
  CVT_imm_95_0,
  CVT_95_addFPImmf32Operands,
  CVT_95_addFPImmf64Operands,
  CVT_95_addTypeListOperands,
  CVT_95_addCatchListOperands,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Imm1_0,
  Convert__BrList1_0,
  Convert__Imm1_0__Imm1_1,
  Convert_NoOperands,
  Convert__imm_95_0__imm_95_0,
  Convert__imm_95_0,
  Convert__FPImmf321_0,
  Convert__Imm1_1__Imm1_0,
  Convert__FPImmf641_0,
  Convert__Imm1_0__Imm1_2__Imm1_1,
  Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3__Imm1_4__Imm1_5__Imm1_6__Imm1_7__Imm1_8__Imm1_9__Imm1_10__Imm1_11__Imm1_12__Imm1_13__Imm1_14__Imm1_15,
  Convert__TypeList1_0,
  Convert__Imm1_0__CatchList1_1,
  Convert__FPImmf641_0__FPImmf641_1,
  Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3,
  Convert__FPImmf321_0__FPImmf321_1__FPImmf321_2__FPImmf321_3,
  Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3__Imm1_4__Imm1_5__Imm1_6__Imm1_7,
  Convert__Imm1_1__Imm1_0__Imm1_2,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][33] = {
  // Convert__Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__BrList1_0
  { CVT_95_addBrListOperands, 1, CVT_Done },
  // Convert__Imm1_0__Imm1_1
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__imm_95_0__imm_95_0
  { CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_0
  { CVT_imm_95_0, 0, CVT_Done },
  // Convert__FPImmf321_0
  { CVT_95_addFPImmf32Operands, 1, CVT_Done },
  // Convert__Imm1_1__Imm1_0
  { CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__FPImmf641_0
  { CVT_95_addFPImmf64Operands, 1, CVT_Done },
  // Convert__Imm1_0__Imm1_2__Imm1_1
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3__Imm1_4__Imm1_5__Imm1_6__Imm1_7__Imm1_8__Imm1_9__Imm1_10__Imm1_11__Imm1_12__Imm1_13__Imm1_14__Imm1_15
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_95_addImmOperands, 7, CVT_95_addImmOperands, 8, CVT_95_addImmOperands, 9, CVT_95_addImmOperands, 10, CVT_95_addImmOperands, 11, CVT_95_addImmOperands, 12, CVT_95_addImmOperands, 13, CVT_95_addImmOperands, 14, CVT_95_addImmOperands, 15, CVT_95_addImmOperands, 16, CVT_Done },
  // Convert__TypeList1_0
  { CVT_95_addTypeListOperands, 1, CVT_Done },
  // Convert__Imm1_0__CatchList1_1
  { CVT_95_addImmOperands, 1, CVT_95_addCatchListOperands, 2, CVT_Done },
  // Convert__FPImmf641_0__FPImmf641_1
  { CVT_95_addFPImmf64Operands, 1, CVT_95_addFPImmf64Operands, 2, CVT_Done },
  // Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__FPImmf321_0__FPImmf321_1__FPImmf321_2__FPImmf321_3
  { CVT_95_addFPImmf32Operands, 1, CVT_95_addFPImmf32Operands, 2, CVT_95_addFPImmf32Operands, 3, CVT_95_addFPImmf32Operands, 4, CVT_Done },
  // Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3__Imm1_4__Imm1_5__Imm1_6__Imm1_7
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_95_addImmOperands, 7, CVT_95_addImmOperands, 8, CVT_Done },
  // Convert__Imm1_1__Imm1_0__Imm1_2
  { CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 3, CVT_Done },
};

void WebAssemblyAsmParser::
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
      static_cast<WebAssemblyOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
      static_cast<WebAssemblyOperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_addBrListOperands:
      static_cast<WebAssemblyOperand &>(*Operands[OpIdx]).addBrListOperands(Inst, 1);
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_95_addFPImmf32Operands:
      static_cast<WebAssemblyOperand &>(*Operands[OpIdx]).addFPImmf32Operands(Inst, 1);
      break;
    case CVT_95_addFPImmf64Operands:
      static_cast<WebAssemblyOperand &>(*Operands[OpIdx]).addFPImmf64Operands(Inst, 1);
      break;
    case CVT_95_addTypeListOperands:
      static_cast<WebAssemblyOperand &>(*Operands[OpIdx]).addTypeListOperands(Inst, 1);
      break;
    case CVT_95_addCatchListOperands:
      static_cast<WebAssemblyOperand &>(*Operands[OpIdx]).addCatchListOperands(Inst, 1);
      break;
    }
  }
}

void WebAssemblyAsmParser::
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
    case CVT_95_addBrListOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addFPImmf32Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addFPImmf64Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addTypeListOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addCatchListOperands:
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
  MCK_LAST_TOKEN = OptionalMatchClass,
  MCK_EXNREF, // register class 'EXNREF'
  MCK_EXTERNREF, // register class 'EXTERNREF'
  MCK_F32, // register class 'F32'
  MCK_F64, // register class 'F64'
  MCK_FUNCREF, // register class 'FUNCREF'
  MCK_V128, // register class 'V128'
  MCK_I32, // register class 'I32'
  MCK_I64, // register class 'I64'
  MCK_LAST_REGISTER = MCK_I64,
  MCK_RegByHwMode_wasm_ptr_rc, // register class by hwmode
  MCK_LAST_REGCLASS_BY_HWMODE = MCK_RegByHwMode_wasm_ptr_rc,
  MCK_BrList, // user defined class 'BrListAsmOperand'
  MCK_CatchList, // user defined class 'CatchListAsmOperand'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_TypeList, // user defined class 'TypeListAsmOperand'
  MCK_FPImmf32, // user defined class 'anonymous_13857'
  MCK_FPImmf64, // user defined class 'anonymous_13858'
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
  WebAssemblyOperand &Operand = (WebAssemblyOperand &)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  case MCK_BrList: {
    DiagnosticPredicate DP(Operand.isBrList());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_CatchList: {
    DiagnosticPredicate DP(Operand.isCatchList());
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
  case MCK_TypeList: {
    DiagnosticPredicate DP(Operand.isTypeList());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_FPImmf32: {
    DiagnosticPredicate DP(Operand.isFPImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_FPImmf64: {
    DiagnosticPredicate DP(Operand.isFPImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg() && Kind > MCK_LAST_REGISTER && Kind <= MCK_LAST_REGCLASS_BY_HWMODE) {
    static constexpr MatchClassKind RegClassByHwModeMatchTable[2][1] = {
      { // DefaultMode
        MCK_I32, // wasm_ptr_rc
      },
      { // WASM64
        MCK_I64, // wasm_ptr_rc
      },
    };

    static_assert(MCK_LAST_REGCLASS_BY_HWMODE - MCK_LAST_REGISTER == 1);
    const unsigned HwMode = STI.getHwMode(MCSubtargetInfo::HwMode_RegInfo);
    Kind = RegClassByHwModeMatchTable[HwMode][Kind - (MCK_LAST_REGISTER + 1)];
  }

  if (Operand.isReg()) {
    static constexpr uint16_t Table[WebAssembly::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      MCK_EXNREF,
      MCK_EXTERNREF,
      MCK_I32,
      MCK_I64,
      MCK_FUNCREF,
      MCK_I32,
      MCK_I64,
      MCK_F32,
      MCK_F64,
      MCK_I32,
      MCK_I64,
      MCK_V128,
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
  case MCK_EXNREF: return "MCK_EXNREF";
  case MCK_EXTERNREF: return "MCK_EXTERNREF";
  case MCK_F32: return "MCK_F32";
  case MCK_F64: return "MCK_F64";
  case MCK_FUNCREF: return "MCK_FUNCREF";
  case MCK_V128: return "MCK_V128";
  case MCK_I32: return "MCK_I32";
  case MCK_I64: return "MCK_I64";
  case MCK_RegByHwMode_wasm_ptr_rc: return "MCK_RegByHwMode_wasm_ptr_rc";
  case MCK_BrList: return "MCK_BrList";
  case MCK_CatchList: return "MCK_CatchList";
  case MCK_Imm: return "MCK_Imm";
  case MCK_TypeList: return "MCK_TypeList";
  case MCK_FPImmf32: return "MCK_FPImmf32";
  case MCK_FPImmf64: return "MCK_FPImmf64";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset WebAssemblyAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  if (FB[WebAssembly::FeatureAtomics])
    Features.set(Feature_HasAtomicsBit);
  if (FB[WebAssembly::FeatureBulkMemory])
    Features.set(Feature_HasBulkMemoryBit);
  if (FB[WebAssembly::FeatureBulkMemoryOpt])
    Features.set(Feature_HasBulkMemoryOptBit);
  if (FB[WebAssembly::FeatureCallIndirectOverlong])
    Features.set(Feature_HasCallIndirectOverlongBit);
  if (FB[WebAssembly::FeatureExceptionHandling])
    Features.set(Feature_HasExceptionHandlingBit);
  if (FB[WebAssembly::FeatureExtendedConst])
    Features.set(Feature_HasExtendedConstBit);
  if (FB[WebAssembly::FeatureFP16])
    Features.set(Feature_HasFP16Bit);
  if (FB[WebAssembly::FeatureGC])
    Features.set(Feature_HasGCBit);
  if (FB[WebAssembly::FeatureMultiMemory])
    Features.set(Feature_HasMultiMemoryBit);
  if (FB[WebAssembly::FeatureMultivalue])
    Features.set(Feature_HasMultivalueBit);
  if (FB[WebAssembly::FeatureMutableGlobals])
    Features.set(Feature_HasMutableGlobalsBit);
  if (FB[WebAssembly::FeatureNontrappingFPToInt])
    Features.set(Feature_HasNontrappingFPToIntBit);
  if (!FB[WebAssembly::FeatureNontrappingFPToInt])
    Features.set(Feature_NotHasNontrappingFPToIntBit);
  if (FB[WebAssembly::FeatureReferenceTypes])
    Features.set(Feature_HasReferenceTypesBit);
  if (FB[WebAssembly::FeatureRelaxedAtomics])
    Features.set(Feature_HasRelaxedAtomicsBit);
  if (FB[WebAssembly::FeatureRelaxedSIMD])
    Features.set(Feature_HasRelaxedSIMDBit);
  if (FB[WebAssembly::FeatureSignExt])
    Features.set(Feature_HasSignExtBit);
  if (FB[WebAssembly::FeatureSIMD128] || FB[WebAssembly::FeatureRelaxedSIMD])
    Features.set(Feature_HasSIMD128Bit);
  if (FB[WebAssembly::FeatureTailCall])
    Features.set(Feature_HasTailCallBit);
  if (FB[WebAssembly::FeatureWideArithmetic])
    Features.set(Feature_HasWideArithmeticBit);
  return Features;
}

static bool checkAsmTiedOperandConstraints(const WebAssemblyAsmParser&AsmParser,
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
    "\014atomic.fence\005block\002br\005br_if\010br_table\004call\015call_in"
    "direct\013call_params\010call_ref\014call_results\005catch\tcatch_all\010"
    "catchret\ncleanupret\016compiler_fence\tdata.drop\010delegate\004drop\004"
    "else\003end\tend_block\014end_function\006end_if\010end_loop\007end_try"
    "\015end_try_table\015exnref.select\020externref.select\tf16x8.abs\tf16x"
    "8.add\nf16x8.ceil\025f16x8.convert_i16x8_s\025f16x8.convert_i16x8_u\027"
    "f16x8.demote_f32x4_zero\tf16x8.div\010f16x8.eq\022f16x8.extract_lane\013"
    "f16x8.floor\010f16x8.ge\010f16x8.gt\010f16x8.le\010f16x8.lt\nf16x8.madd"
    "\tf16x8.max\tf16x8.min\tf16x8.mul\010f16x8.ne\015f16x8.nearest\tf16x8.n"
    "eg\013f16x8.nmadd\nf16x8.pmax\nf16x8.pmin\022f16x8.replace_lane\013f16x"
    "8.splat\nf16x8.sqrt\tf16x8.sub\013f16x8.trunc\007f32.abs\007f32.add\010"
    "f32.ceil\tf32.const\021f32.convert_i32_s\021f32.convert_i32_u\021f32.co"
    "nvert_i64_s\021f32.convert_i64_u\014f32.copysign\016f32.demote_f64\007f"
    "32.div\006f32.eq\tf32.floor\006f32.ge\006f32.gt\006f32.le\010f32.load\014"
    "f32.load_f16\006f32.lt\007f32.max\007f32.min\007f32.mul\006f32.ne\013f3"
    "2.nearest\007f32.neg\023f32.reinterpret_i32\nf32.select\010f32.sqrt\tf3"
    "2.store\015f32.store_f16\007f32.sub\tf32.trunc\tf32x4.abs\tf32x4.add\nf"
    "32x4.ceil\025f32x4.convert_i32x4_s\025f32x4.convert_i32x4_u\027f32x4.de"
    "mote_f64x2_zero\tf32x4.div\010f32x4.eq\022f32x4.extract_lane\013f32x4.f"
    "loor\010f32x4.ge\010f32x4.gt\010f32x4.le\010f32x4.lt\tf32x4.max\tf32x4."
    "min\tf32x4.mul\010f32x4.ne\015f32x4.nearest\tf32x4.neg\nf32x4.pmax\nf32"
    "x4.pmin\027f32x4.promote_low_f16x8 f32x4.relaxed_dot_bf16x8_add_f32\022"
    "f32x4.relaxed_madd\021f32x4.relaxed_max\021f32x4.relaxed_min\023f32x4.r"
    "elaxed_nmadd\022f32x4.replace_lane\013f32x4.splat\nf32x4.sqrt\tf32x4.su"
    "b\013f32x4.trunc\007f64.abs\007f64.add\010f64.ceil\tf64.const\021f64.co"
    "nvert_i32_s\021f64.convert_i32_u\021f64.convert_i64_s\021f64.convert_i6"
    "4_u\014f64.copysign\007f64.div\006f64.eq\tf64.floor\006f64.ge\006f64.gt"
    "\006f64.le\010f64.load\006f64.lt\007f64.max\007f64.min\007f64.mul\006f6"
    "4.ne\013f64.nearest\007f64.neg\017f64.promote_f32\023f64.reinterpret_i6"
    "4\nf64.select\010f64.sqrt\tf64.store\007f64.sub\tf64.trunc\tf64x2.abs\t"
    "f64x2.add\nf64x2.ceil\031f64x2.convert_low_i32x4_s\031f64x2.convert_low"
    "_i32x4_u\tf64x2.div\010f64x2.eq\022f64x2.extract_lane\013f64x2.floor\010"
    "f64x2.ge\010f64x2.gt\010f64x2.le\010f64x2.lt\tf64x2.max\tf64x2.min\tf64"
    "x2.mul\010f64x2.ne\015f64x2.nearest\tf64x2.neg\nf64x2.pmax\nf64x2.pmin\027"
    "f64x2.promote_low_f32x4\022f64x2.relaxed_madd\021f64x2.relaxed_max\021f"
    "64x2.relaxed_min\023f64x2.relaxed_nmadd\022f64x2.replace_lane\013f64x2."
    "splat\nf64x2.sqrt\tf64x2.sub\013f64x2.trunc\016funcref.select\nglobal.g"
    "et\nglobal.set\ti16x8.abs\ti16x8.add\017i16x8.add_sat_s\017i16x8.add_sa"
    "t_u\016i16x8.all_true\014i16x8.avgr_u\015i16x8.bitmask\010i16x8.eq\035i"
    "16x8.extadd_pairwise_i8x16_s\035i16x8.extadd_pairwise_i8x16_u\031i16x8."
    "extend_high_i8x16_s\031i16x8.extend_high_i8x16_u\030i16x8.extend_low_i8"
    "x16_s\030i16x8.extend_low_i8x16_u\031i16x8.extmul_high_i8x16_s\031i16x8"
    ".extmul_high_i8x16_u\030i16x8.extmul_low_i8x16_s\030i16x8.extmul_low_i8"
    "x16_u\024i16x8.extract_lane_s\024i16x8.extract_lane_u\ni16x8.ge_s\ni16x"
    "8.ge_u\ni16x8.gt_s\ni16x8.gt_u\ni16x8.le_s\ni16x8.le_u\017i16x8.load8x8"
    "_s\017i16x8.load8x8_u\ni16x8.lt_s\ni16x8.lt_u\013i16x8.max_s\013i16x8.m"
    "ax_u\013i16x8.min_s\013i16x8.min_u\ti16x8.mul\024i16x8.narrow_i32x4_s\024"
    "i16x8.narrow_i32x4_u\010i16x8.ne\ti16x8.neg\023i16x8.q15mulr_sat_s\037i"
    "16x8.relaxed_dot_i8x16_i7x16_s\030i16x8.relaxed_laneselect\027i16x8.rel"
    "axed_q15mulr_s\022i16x8.replace_lane\ti16x8.shl\013i16x8.shr_s\013i16x8"
    ".shr_u\013i16x8.splat\ti16x8.sub\017i16x8.sub_sat_s\017i16x8.sub_sat_u\027"
    "i16x8.trunc_sat_f16x8_s\027i16x8.trunc_sat_f16x8_u\007i32.add\007i32.an"
    "d\017i32.atomic.load\023i32.atomic.load16_u\022i32.atomic.load8_u\022i3"
    "2.atomic.rmw.add\022i32.atomic.rmw.and\026i32.atomic.rmw.cmpxchg\021i32"
    ".atomic.rmw.or\022i32.atomic.rmw.sub\023i32.atomic.rmw.xchg\022i32.atom"
    "ic.rmw.xor\026i32.atomic.rmw16.add_u\026i32.atomic.rmw16.and_u\032i32.a"
    "tomic.rmw16.cmpxchg_u\025i32.atomic.rmw16.or_u\026i32.atomic.rmw16.sub_"
    "u\027i32.atomic.rmw16.xchg_u\026i32.atomic.rmw16.xor_u\025i32.atomic.rm"
    "w8.add_u\025i32.atomic.rmw8.and_u\031i32.atomic.rmw8.cmpxchg_u\024i32.a"
    "tomic.rmw8.or_u\025i32.atomic.rmw8.sub_u\026i32.atomic.rmw8.xchg_u\025i"
    "32.atomic.rmw8.xor_u\020i32.atomic.store\022i32.atomic.store16\021i32.a"
    "tomic.store8\007i32.clz\ti32.const\007i32.ctz\ti32.div_s\ti32.div_u\006"
    "i32.eq\007i32.eqz\016i32.extend16_s\015i32.extend8_s\010i32.ge_s\010i32"
    ".ge_u\010i32.gt_s\010i32.gt_u\010i32.le_s\010i32.le_u\010i32.load\014i3"
    "2.load16_s\014i32.load16_u\013i32.load8_s\013i32.load8_u\010i32.lt_s\010"
    "i32.lt_u\007i32.mul\006i32.ne\006i32.or\ni32.popcnt\023i32.reinterpret_"
    "f32\ti32.rem_s\ti32.rem_u\010i32.rotl\010i32.rotr\ni32.select\007i32.sh"
    "l\ti32.shr_s\ti32.shr_u\ti32.store\013i32.store16\ni32.store8\007i32.su"
    "b\017i32.trunc_f32_s\017i32.trunc_f32_u\017i32.trunc_f64_s\017i32.trunc"
    "_f64_u\023i32.trunc_sat_f32_s\023i32.trunc_sat_f32_u\023i32.trunc_sat_f"
    "64_s\023i32.trunc_sat_f64_u\014i32.wrap_i64\007i32.xor\ti32x4.abs\ti32x"
    "4.add\016i32x4.all_true\015i32x4.bitmask\021i32x4.dot_i16x8_s\010i32x4."
    "eq\035i32x4.extadd_pairwise_i16x8_s\035i32x4.extadd_pairwise_i16x8_u\031"
    "i32x4.extend_high_i16x8_s\031i32x4.extend_high_i16x8_u\030i32x4.extend_"
    "low_i16x8_s\030i32x4.extend_low_i16x8_u\031i32x4.extmul_high_i16x8_s\031"
    "i32x4.extmul_high_i16x8_u\030i32x4.extmul_low_i16x8_s\030i32x4.extmul_l"
    "ow_i16x8_u\022i32x4.extract_lane\ni32x4.ge_s\ni32x4.ge_u\ni32x4.gt_s\ni"
    "32x4.gt_u\ni32x4.le_s\ni32x4.le_u\020i32x4.load16x4_s\020i32x4.load16x4"
    "_u\ni32x4.lt_s\ni32x4.lt_u\013i32x4.max_s\013i32x4.max_u\013i32x4.min_s"
    "\013i32x4.min_u\ti32x4.mul\010i32x4.ne\ti32x4.neg#i32x4.relaxed_dot_i8x"
    "16_i7x16_add_s\030i32x4.relaxed_laneselect\033i32x4.relaxed_trunc_f32x4"
    "_s\033i32x4.relaxed_trunc_f32x4_u i32x4.relaxed_trunc_f64x2_s_zero i32x"
    "4.relaxed_trunc_f64x2_u_zero\022i32x4.replace_lane\ti32x4.shl\013i32x4."
    "shr_s\013i32x4.shr_u\013i32x4.splat\ti32x4.sub\027i32x4.trunc_sat_f32x4"
    "_s\027i32x4.trunc_sat_f32x4_u\034i32x4.trunc_sat_f64x2_s_zero\034i32x4."
    "trunc_sat_f64x2_u_zero\007i64.add\ni64.add128\007i64.and\017i64.atomic."
    "load\023i64.atomic.load16_u\023i64.atomic.load32_u\022i64.atomic.load8_"
    "u\022i64.atomic.rmw.add\022i64.atomic.rmw.and\026i64.atomic.rmw.cmpxchg"
    "\021i64.atomic.rmw.or\022i64.atomic.rmw.sub\023i64.atomic.rmw.xchg\022i"
    "64.atomic.rmw.xor\026i64.atomic.rmw16.add_u\026i64.atomic.rmw16.and_u\032"
    "i64.atomic.rmw16.cmpxchg_u\025i64.atomic.rmw16.or_u\026i64.atomic.rmw16"
    ".sub_u\027i64.atomic.rmw16.xchg_u\026i64.atomic.rmw16.xor_u\026i64.atom"
    "ic.rmw32.add_u\026i64.atomic.rmw32.and_u\032i64.atomic.rmw32.cmpxchg_u\025"
    "i64.atomic.rmw32.or_u\026i64.atomic.rmw32.sub_u\027i64.atomic.rmw32.xch"
    "g_u\026i64.atomic.rmw32.xor_u\025i64.atomic.rmw8.add_u\025i64.atomic.rm"
    "w8.and_u\031i64.atomic.rmw8.cmpxchg_u\024i64.atomic.rmw8.or_u\025i64.at"
    "omic.rmw8.sub_u\026i64.atomic.rmw8.xchg_u\025i64.atomic.rmw8.xor_u\020i"
    "64.atomic.store\022i64.atomic.store16\022i64.atomic.store32\021i64.atom"
    "ic.store8\007i64.clz\ti64.const\007i64.ctz\ti64.div_s\ti64.div_u\006i64"
    ".eq\007i64.eqz\016i64.extend16_s\016i64.extend32_s\015i64.extend8_s\020"
    "i64.extend_i32_s\020i64.extend_i32_u\010i64.ge_s\010i64.ge_u\010i64.gt_"
    "s\010i64.gt_u\010i64.le_s\010i64.le_u\010i64.load\014i64.load16_s\014i6"
    "4.load16_u\014i64.load32_s\014i64.load32_u\013i64.load8_s\013i64.load8_"
    "u\010i64.lt_s\010i64.lt_u\007i64.mul\016i64.mul_wide_s\016i64.mul_wide_"
    "u\006i64.ne\006i64.or\ni64.popcnt\023i64.reinterpret_f64\ti64.rem_s\ti6"
    "4.rem_u\010i64.rotl\010i64.rotr\ni64.select\007i64.shl\ti64.shr_s\ti64."
    "shr_u\ti64.store\013i64.store16\013i64.store32\ni64.store8\007i64.sub\n"
    "i64.sub128\017i64.trunc_f32_s\017i64.trunc_f32_u\017i64.trunc_f64_s\017"
    "i64.trunc_f64_u\023i64.trunc_sat_f32_s\023i64.trunc_sat_f32_u\023i64.tr"
    "unc_sat_f64_s\023i64.trunc_sat_f64_u\007i64.xor\ti64x2.abs\ti64x2.add\016"
    "i64x2.all_true\015i64x2.bitmask\010i64x2.eq\031i64x2.extend_high_i32x4_"
    "s\031i64x2.extend_high_i32x4_u\030i64x2.extend_low_i32x4_s\030i64x2.ext"
    "end_low_i32x4_u\031i64x2.extmul_high_i32x4_s\031i64x2.extmul_high_i32x4"
    "_u\030i64x2.extmul_low_i32x4_s\030i64x2.extmul_low_i32x4_u\022i64x2.ext"
    "ract_lane\ni64x2.ge_s\ni64x2.gt_s\ni64x2.le_s\020i64x2.load32x2_s\020i6"
    "4x2.load32x2_u\ni64x2.lt_s\ti64x2.mul\010i64x2.ne\ti64x2.neg\030i64x2.r"
    "elaxed_laneselect\022i64x2.replace_lane\ti64x2.shl\013i64x2.shr_s\013i6"
    "4x2.shr_u\013i64x2.splat\ti64x2.sub\ti8x16.abs\ti8x16.add\017i8x16.add_"
    "sat_s\017i8x16.add_sat_u\016i8x16.all_true\014i8x16.avgr_u\015i8x16.bit"
    "mask\010i8x16.eq\024i8x16.extract_lane_s\024i8x16.extract_lane_u\ni8x16"
    ".ge_s\ni8x16.ge_u\ni8x16.gt_s\ni8x16.gt_u\ni8x16.le_s\ni8x16.le_u\ni8x1"
    "6.lt_s\ni8x16.lt_u\013i8x16.max_s\013i8x16.max_u\013i8x16.min_s\013i8x1"
    "6.min_u\024i8x16.narrow_i16x8_s\024i8x16.narrow_i16x8_u\010i8x16.ne\ti8"
    "x16.neg\014i8x16.popcnt\030i8x16.relaxed_laneselect\025i8x16.relaxed_sw"
    "izzle\022i8x16.replace_lane\ti8x16.shl\013i8x16.shr_s\013i8x16.shr_u\015"
    "i8x16.shuffle\013i8x16.splat\ti8x16.sub\017i8x16.sub_sat_s\017i8x16.sub"
    "_sat_u\015i8x16.swizzle\002if\tlocal.get\tlocal.set\tlocal.tee\004loop\024"
    "memory.atomic.notify\024memory.atomic.wait32\024memory.atomic.wait64\013"
    "memory.copy\013memory.fill\013memory.grow\013memory.init\013memory.size"
    "\003nop\010ref.cast\010ref.func\013ref.is_null\014ref.null_exn\017ref.n"
    "ull_extern\015ref.null_func\010ref.test\007rethrow\006return\013return_"
    "call\024return_call_indirect\017return_call_ref\023return_call_results\006"
    "select\ntable.copy\ntable.fill\ttable.get\ntable.grow\ttable.set\ntable"
    ".size\005throw\tthrow_ref\003try\ttry_table\013unreachable\010v128.and\013"
    "v128.andnot\015v128.any_true\016v128.bitselect\nv128.const\tv128.load\020"
    "v128.load16_lane\021v128.load16_splat\020v128.load32_lane\021v128.load3"
    "2_splat\020v128.load32_zero\020v128.load64_lane\021v128.load64_splat\020"
    "v128.load64_zero\017v128.load8_lane\020v128.load8_splat\010v128.not\007"
    "v128.or\013v128.select\nv128.store\021v128.store16_lane\021v128.store32"
    "_lane\021v128.store64_lane\020v128.store8_lane\010v128.xor";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
  AMFBS_HasAtomics,
  AMFBS_HasBulkMemoryOpt,
  AMFBS_HasExceptionHandling,
  AMFBS_HasFP16,
  AMFBS_HasGC,
  AMFBS_HasNontrappingFPToInt,
  AMFBS_HasReferenceTypes,
  AMFBS_HasRelaxedSIMD,
  AMFBS_HasSIMD128,
  AMFBS_HasSignExt,
  AMFBS_HasTailCall,
  AMFBS_HasWideArithmetic,
  AMFBS_HasReferenceTypes_HasExceptionHandling,
  AMFBS_HasSIMD128_HasFP16,
  AMFBS_HasSIMD128_HasRelaxedSIMD,
  AMFBS_HasTailCall_HasGC,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
  {Feature_HasAtomicsBit, }, // AMFBS_HasAtomics
  {Feature_HasBulkMemoryOptBit, }, // AMFBS_HasBulkMemoryOpt
  {Feature_HasExceptionHandlingBit, }, // AMFBS_HasExceptionHandling
  {Feature_HasFP16Bit, }, // AMFBS_HasFP16
  {Feature_HasGCBit, }, // AMFBS_HasGC
  {Feature_HasNontrappingFPToIntBit, }, // AMFBS_HasNontrappingFPToInt
  {Feature_HasReferenceTypesBit, }, // AMFBS_HasReferenceTypes
  {Feature_HasRelaxedSIMDBit, }, // AMFBS_HasRelaxedSIMD
  {Feature_HasSIMD128Bit, }, // AMFBS_HasSIMD128
  {Feature_HasSignExtBit, }, // AMFBS_HasSignExt
  {Feature_HasTailCallBit, }, // AMFBS_HasTailCall
  {Feature_HasWideArithmeticBit, }, // AMFBS_HasWideArithmetic
  {Feature_HasReferenceTypesBit, Feature_HasExceptionHandlingBit, }, // AMFBS_HasReferenceTypes_HasExceptionHandling
  {Feature_HasSIMD128Bit, Feature_HasFP16Bit, }, // AMFBS_HasSIMD128_HasFP16
  {Feature_HasSIMD128Bit, Feature_HasRelaxedSIMDBit, }, // AMFBS_HasSIMD128_HasRelaxedSIMD
  {Feature_HasTailCallBit, Feature_HasGCBit, }, // AMFBS_HasTailCall_HasGC
};

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
    uint32_t Opcode;
    uint8_t ConvertFn;
    uint8_t RequiredFeaturesIdx;
    uint8_t Classes[16];
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
  { 0 /* atomic.fence */, WebAssembly::ATOMIC_FENCE_S, Convert__Imm1_0, AMFBS_HasAtomics, { MCK_Imm }, },
  { 13 /* block */, WebAssembly::BLOCK_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 19 /* br */, WebAssembly::BR_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 22 /* br_if */, WebAssembly::BR_IF_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 28 /* br_table */, WebAssembly::BR_TABLE_I32_S, Convert__BrList1_0, AMFBS_None, { MCK_BrList }, },
  { 28 /* br_table */, WebAssembly::BR_TABLE_I64_S, Convert__BrList1_0, AMFBS_None, { MCK_BrList }, },
  { 37 /* call */, WebAssembly::CALL_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 42 /* call_indirect */, WebAssembly::CALL_INDIRECT_S, Convert__Imm1_0__Imm1_1, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 56 /* call_params */, WebAssembly::CALL_PARAMS_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 68 /* call_ref */, WebAssembly::CALL_REF_S, Convert__Imm1_0, AMFBS_HasGC, { MCK_Imm }, },
  { 77 /* call_results */, WebAssembly::CALL_RESULTS_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 90 /* catch */, WebAssembly::CATCH_LEGACY_S, Convert__Imm1_0, AMFBS_HasExceptionHandling, { MCK_Imm }, },
  { 96 /* catch_all */, WebAssembly::CATCH_ALL_LEGACY_S, Convert_NoOperands, AMFBS_HasExceptionHandling, {  }, },
  { 106 /* catchret */, WebAssembly::CATCHRET_S, Convert__imm_95_0__imm_95_0, AMFBS_HasExceptionHandling, {  }, },
  { 115 /* cleanupret */, WebAssembly::CLEANUPRET_S, Convert__imm_95_0, AMFBS_HasExceptionHandling, {  }, },
  { 126 /* compiler_fence */, WebAssembly::COMPILER_FENCE_S, Convert_NoOperands, AMFBS_HasAtomics, {  }, },
  { 141 /* data.drop */, WebAssembly::DATA_DROP_S, Convert__Imm1_0, AMFBS_HasBulkMemoryOpt, { MCK_Imm }, },
  { 151 /* delegate */, WebAssembly::DELEGATE_S, Convert__Imm1_0, AMFBS_HasExceptionHandling, { MCK_Imm }, },
  { 160 /* drop */, WebAssembly::DROP_EXNREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes_HasExceptionHandling, {  }, },
  { 160 /* drop */, WebAssembly::DROP_EXTERNREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 160 /* drop */, WebAssembly::DROP_FUNCREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 160 /* drop */, WebAssembly::DROP_V128_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 160 /* drop */, WebAssembly::DROP_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 160 /* drop */, WebAssembly::DROP_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 160 /* drop */, WebAssembly::DROP_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 160 /* drop */, WebAssembly::DROP_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 165 /* else */, WebAssembly::ELSE_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 170 /* end */, WebAssembly::END_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 174 /* end_block */, WebAssembly::END_BLOCK_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 184 /* end_function */, WebAssembly::END_FUNCTION_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 197 /* end_if */, WebAssembly::END_IF_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 204 /* end_loop */, WebAssembly::END_LOOP_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 213 /* end_try */, WebAssembly::END_TRY_S, Convert_NoOperands, AMFBS_HasExceptionHandling, {  }, },
  { 221 /* end_try_table */, WebAssembly::END_TRY_TABLE_S, Convert_NoOperands, AMFBS_HasExceptionHandling, {  }, },
  { 235 /* exnref.select */, WebAssembly::SELECT_EXNREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 249 /* externref.select */, WebAssembly::SELECT_EXTERNREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 266 /* f16x8.abs */, WebAssembly::ABS_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 276 /* f16x8.add */, WebAssembly::ADD_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 286 /* f16x8.ceil */, WebAssembly::CEIL_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 297 /* f16x8.convert_i16x8_s */, WebAssembly::sint_to_fp_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 319 /* f16x8.convert_i16x8_u */, WebAssembly::uint_to_fp_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 341 /* f16x8.demote_f32x4_zero */, WebAssembly::demote_zero_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 365 /* f16x8.div */, WebAssembly::DIV_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 375 /* f16x8.eq */, WebAssembly::EQ_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 384 /* f16x8.extract_lane */, WebAssembly::EXTRACT_LANE_F16x8_S, Convert__Imm1_0, AMFBS_HasFP16, { MCK_Imm }, },
  { 403 /* f16x8.floor */, WebAssembly::FLOOR_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 415 /* f16x8.ge */, WebAssembly::GE_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 424 /* f16x8.gt */, WebAssembly::GT_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 433 /* f16x8.le */, WebAssembly::LE_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 442 /* f16x8.lt */, WebAssembly::LT_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 451 /* f16x8.madd */, WebAssembly::MADD_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 462 /* f16x8.max */, WebAssembly::MAX_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 472 /* f16x8.min */, WebAssembly::MIN_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 482 /* f16x8.mul */, WebAssembly::MUL_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 492 /* f16x8.ne */, WebAssembly::NE_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 501 /* f16x8.nearest */, WebAssembly::NEAREST_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 515 /* f16x8.neg */, WebAssembly::NEG_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 525 /* f16x8.nmadd */, WebAssembly::NMADD_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 537 /* f16x8.pmax */, WebAssembly::PMAX_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 548 /* f16x8.pmin */, WebAssembly::PMIN_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 559 /* f16x8.replace_lane */, WebAssembly::REPLACE_LANE_F16x8_S, Convert__Imm1_0, AMFBS_HasFP16, { MCK_Imm }, },
  { 578 /* f16x8.splat */, WebAssembly::SPLAT_F16x8_S, Convert_NoOperands, AMFBS_HasFP16, {  }, },
  { 590 /* f16x8.sqrt */, WebAssembly::SQRT_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 601 /* f16x8.sub */, WebAssembly::SUB_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 611 /* f16x8.trunc */, WebAssembly::TRUNC_F16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 623 /* f32.abs */, WebAssembly::ABS_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 631 /* f32.add */, WebAssembly::ADD_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 639 /* f32.ceil */, WebAssembly::CEIL_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 648 /* f32.const */, WebAssembly::CONST_F32_S, Convert__FPImmf321_0, AMFBS_None, { MCK_FPImmf32 }, },
  { 658 /* f32.convert_i32_s */, WebAssembly::F32_CONVERT_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 676 /* f32.convert_i32_u */, WebAssembly::F32_CONVERT_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 694 /* f32.convert_i64_s */, WebAssembly::F32_CONVERT_S_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 712 /* f32.convert_i64_u */, WebAssembly::F32_CONVERT_U_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 730 /* f32.copysign */, WebAssembly::COPYSIGN_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 743 /* f32.demote_f64 */, WebAssembly::F32_DEMOTE_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 758 /* f32.div */, WebAssembly::DIV_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 766 /* f32.eq */, WebAssembly::EQ_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 773 /* f32.floor */, WebAssembly::FLOOR_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 783 /* f32.ge */, WebAssembly::GE_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 790 /* f32.gt */, WebAssembly::GT_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 797 /* f32.le */, WebAssembly::LE_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 804 /* f32.load */, WebAssembly::LOAD_F32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 804 /* f32.load */, WebAssembly::LOAD_F32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 813 /* f32.load_f16 */, WebAssembly::LOAD_F16_F32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasFP16, { MCK_Imm, MCK_Imm }, },
  { 813 /* f32.load_f16 */, WebAssembly::LOAD_F16_F32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasFP16, { MCK_Imm, MCK_Imm }, },
  { 826 /* f32.lt */, WebAssembly::LT_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 833 /* f32.max */, WebAssembly::MAX_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 841 /* f32.min */, WebAssembly::MIN_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 849 /* f32.mul */, WebAssembly::MUL_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 857 /* f32.ne */, WebAssembly::NE_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 864 /* f32.nearest */, WebAssembly::NEAREST_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 876 /* f32.neg */, WebAssembly::NEG_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 884 /* f32.reinterpret_i32 */, WebAssembly::F32_REINTERPRET_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 904 /* f32.select */, WebAssembly::SELECT_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 915 /* f32.sqrt */, WebAssembly::SQRT_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 924 /* f32.store */, WebAssembly::STORE_F32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 924 /* f32.store */, WebAssembly::STORE_F32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 934 /* f32.store_f16 */, WebAssembly::STORE_F16_F32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasFP16, { MCK_Imm, MCK_Imm }, },
  { 934 /* f32.store_f16 */, WebAssembly::STORE_F16_F32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasFP16, { MCK_Imm, MCK_Imm }, },
  { 948 /* f32.sub */, WebAssembly::SUB_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 956 /* f32.trunc */, WebAssembly::TRUNC_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 966 /* f32x4.abs */, WebAssembly::ABS_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 976 /* f32x4.add */, WebAssembly::ADD_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 986 /* f32x4.ceil */, WebAssembly::CEIL_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 997 /* f32x4.convert_i32x4_s */, WebAssembly::sint_to_fp_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1019 /* f32x4.convert_i32x4_u */, WebAssembly::uint_to_fp_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1041 /* f32x4.demote_f64x2_zero */, WebAssembly::demote_zero_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1065 /* f32x4.div */, WebAssembly::DIV_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1075 /* f32x4.eq */, WebAssembly::EQ_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1084 /* f32x4.extract_lane */, WebAssembly::EXTRACT_LANE_F32x4_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 1103 /* f32x4.floor */, WebAssembly::FLOOR_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1115 /* f32x4.ge */, WebAssembly::GE_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1124 /* f32x4.gt */, WebAssembly::GT_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1133 /* f32x4.le */, WebAssembly::LE_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1142 /* f32x4.lt */, WebAssembly::LT_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1151 /* f32x4.max */, WebAssembly::MAX_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1161 /* f32x4.min */, WebAssembly::MIN_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1171 /* f32x4.mul */, WebAssembly::MUL_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1181 /* f32x4.ne */, WebAssembly::NE_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1190 /* f32x4.nearest */, WebAssembly::NEAREST_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1204 /* f32x4.neg */, WebAssembly::NEG_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1214 /* f32x4.pmax */, WebAssembly::PMAX_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1225 /* f32x4.pmin */, WebAssembly::PMIN_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1236 /* f32x4.promote_low_f16x8 */, WebAssembly::promote_low_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 1260 /* f32x4.relaxed_dot_bf16x8_add_f32 */, WebAssembly::RELAXED_DOT_BFLOAT_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 1293 /* f32x4.relaxed_madd */, WebAssembly::MADD_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128_HasRelaxedSIMD, {  }, },
  { 1312 /* f32x4.relaxed_max */, WebAssembly::SIMD_RELAXED_FMAX_F32x4_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 1330 /* f32x4.relaxed_min */, WebAssembly::SIMD_RELAXED_FMIN_F32x4_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 1348 /* f32x4.relaxed_nmadd */, WebAssembly::NMADD_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128_HasRelaxedSIMD, {  }, },
  { 1368 /* f32x4.replace_lane */, WebAssembly::REPLACE_LANE_F32x4_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 1387 /* f32x4.splat */, WebAssembly::SPLAT_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1399 /* f32x4.sqrt */, WebAssembly::SQRT_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1410 /* f32x4.sub */, WebAssembly::SUB_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1420 /* f32x4.trunc */, WebAssembly::TRUNC_F32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1432 /* f64.abs */, WebAssembly::ABS_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1440 /* f64.add */, WebAssembly::ADD_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1448 /* f64.ceil */, WebAssembly::CEIL_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1457 /* f64.const */, WebAssembly::CONST_F64_S, Convert__FPImmf641_0, AMFBS_None, { MCK_FPImmf64 }, },
  { 1467 /* f64.convert_i32_s */, WebAssembly::F64_CONVERT_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1485 /* f64.convert_i32_u */, WebAssembly::F64_CONVERT_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1503 /* f64.convert_i64_s */, WebAssembly::F64_CONVERT_S_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1521 /* f64.convert_i64_u */, WebAssembly::F64_CONVERT_U_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1539 /* f64.copysign */, WebAssembly::COPYSIGN_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1552 /* f64.div */, WebAssembly::DIV_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1560 /* f64.eq */, WebAssembly::EQ_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1567 /* f64.floor */, WebAssembly::FLOOR_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1577 /* f64.ge */, WebAssembly::GE_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1584 /* f64.gt */, WebAssembly::GT_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1591 /* f64.le */, WebAssembly::LE_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1598 /* f64.load */, WebAssembly::LOAD_F64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 1598 /* f64.load */, WebAssembly::LOAD_F64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 1607 /* f64.lt */, WebAssembly::LT_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1614 /* f64.max */, WebAssembly::MAX_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1622 /* f64.min */, WebAssembly::MIN_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1630 /* f64.mul */, WebAssembly::MUL_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1638 /* f64.ne */, WebAssembly::NE_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1645 /* f64.nearest */, WebAssembly::NEAREST_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1657 /* f64.neg */, WebAssembly::NEG_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1665 /* f64.promote_f32 */, WebAssembly::F64_PROMOTE_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1681 /* f64.reinterpret_i64 */, WebAssembly::F64_REINTERPRET_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1701 /* f64.select */, WebAssembly::SELECT_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1712 /* f64.sqrt */, WebAssembly::SQRT_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1721 /* f64.store */, WebAssembly::STORE_F64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 1721 /* f64.store */, WebAssembly::STORE_F64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 1731 /* f64.sub */, WebAssembly::SUB_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1739 /* f64.trunc */, WebAssembly::TRUNC_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 1749 /* f64x2.abs */, WebAssembly::ABS_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1759 /* f64x2.add */, WebAssembly::ADD_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1769 /* f64x2.ceil */, WebAssembly::CEIL_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1780 /* f64x2.convert_low_i32x4_s */, WebAssembly::convert_low_s_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1806 /* f64x2.convert_low_i32x4_u */, WebAssembly::convert_low_u_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1832 /* f64x2.div */, WebAssembly::DIV_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1842 /* f64x2.eq */, WebAssembly::EQ_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1851 /* f64x2.extract_lane */, WebAssembly::EXTRACT_LANE_F64x2_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 1870 /* f64x2.floor */, WebAssembly::FLOOR_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1882 /* f64x2.ge */, WebAssembly::GE_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1891 /* f64x2.gt */, WebAssembly::GT_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1900 /* f64x2.le */, WebAssembly::LE_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1909 /* f64x2.lt */, WebAssembly::LT_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1918 /* f64x2.max */, WebAssembly::MAX_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1928 /* f64x2.min */, WebAssembly::MIN_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1938 /* f64x2.mul */, WebAssembly::MUL_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1948 /* f64x2.ne */, WebAssembly::NE_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1957 /* f64x2.nearest */, WebAssembly::NEAREST_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1971 /* f64x2.neg */, WebAssembly::NEG_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1981 /* f64x2.pmax */, WebAssembly::PMAX_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 1992 /* f64x2.pmin */, WebAssembly::PMIN_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2003 /* f64x2.promote_low_f32x4 */, WebAssembly::promote_low_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2027 /* f64x2.relaxed_madd */, WebAssembly::MADD_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128_HasRelaxedSIMD, {  }, },
  { 2046 /* f64x2.relaxed_max */, WebAssembly::SIMD_RELAXED_FMAX_F64x2_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 2064 /* f64x2.relaxed_min */, WebAssembly::SIMD_RELAXED_FMIN_F64x2_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 2082 /* f64x2.relaxed_nmadd */, WebAssembly::NMADD_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128_HasRelaxedSIMD, {  }, },
  { 2102 /* f64x2.replace_lane */, WebAssembly::REPLACE_LANE_F64x2_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 2121 /* f64x2.splat */, WebAssembly::SPLAT_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2133 /* f64x2.sqrt */, WebAssembly::SQRT_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2144 /* f64x2.sub */, WebAssembly::SUB_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2154 /* f64x2.trunc */, WebAssembly::TRUNC_F64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2166 /* funcref.select */, WebAssembly::SELECT_FUNCREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 2181 /* global.get */, WebAssembly::GLOBAL_GET_EXNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes_HasExceptionHandling, { MCK_Imm }, },
  { 2181 /* global.get */, WebAssembly::GLOBAL_GET_EXTERNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 2181 /* global.get */, WebAssembly::GLOBAL_GET_FUNCREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 2181 /* global.get */, WebAssembly::GLOBAL_GET_V128_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 2181 /* global.get */, WebAssembly::GLOBAL_GET_F32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 2181 /* global.get */, WebAssembly::GLOBAL_GET_F64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 2181 /* global.get */, WebAssembly::GLOBAL_GET_I32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 2181 /* global.get */, WebAssembly::GLOBAL_GET_I64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 2192 /* global.set */, WebAssembly::GLOBAL_SET_EXNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes_HasExceptionHandling, { MCK_Imm }, },
  { 2192 /* global.set */, WebAssembly::GLOBAL_SET_EXTERNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 2192 /* global.set */, WebAssembly::GLOBAL_SET_FUNCREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 2192 /* global.set */, WebAssembly::GLOBAL_SET_V128_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 2192 /* global.set */, WebAssembly::GLOBAL_SET_F32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 2192 /* global.set */, WebAssembly::GLOBAL_SET_F64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 2192 /* global.set */, WebAssembly::GLOBAL_SET_I32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 2192 /* global.set */, WebAssembly::GLOBAL_SET_I64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 2203 /* i16x8.abs */, WebAssembly::ABS_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2213 /* i16x8.add */, WebAssembly::ADD_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2223 /* i16x8.add_sat_s */, WebAssembly::ADD_SAT_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2239 /* i16x8.add_sat_u */, WebAssembly::ADD_SAT_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2255 /* i16x8.all_true */, WebAssembly::ALLTRUE_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2270 /* i16x8.avgr_u */, WebAssembly::AVGR_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2283 /* i16x8.bitmask */, WebAssembly::BITMASK_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2297 /* i16x8.eq */, WebAssembly::EQ_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2306 /* i16x8.extadd_pairwise_i8x16_s */, WebAssembly::extadd_pairwise_s_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2336 /* i16x8.extadd_pairwise_i8x16_u */, WebAssembly::extadd_pairwise_u_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2366 /* i16x8.extend_high_i8x16_s */, WebAssembly::extend_high_s_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2392 /* i16x8.extend_high_i8x16_u */, WebAssembly::extend_high_u_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2418 /* i16x8.extend_low_i8x16_s */, WebAssembly::extend_low_s_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2443 /* i16x8.extend_low_i8x16_u */, WebAssembly::extend_low_u_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2468 /* i16x8.extmul_high_i8x16_s */, WebAssembly::EXTMUL_HIGH_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2494 /* i16x8.extmul_high_i8x16_u */, WebAssembly::EXTMUL_HIGH_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2520 /* i16x8.extmul_low_i8x16_s */, WebAssembly::EXTMUL_LOW_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2545 /* i16x8.extmul_low_i8x16_u */, WebAssembly::EXTMUL_LOW_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2570 /* i16x8.extract_lane_s */, WebAssembly::EXTRACT_LANE_I16x8_s_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 2591 /* i16x8.extract_lane_u */, WebAssembly::EXTRACT_LANE_I16x8_u_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 2612 /* i16x8.ge_s */, WebAssembly::GE_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2623 /* i16x8.ge_u */, WebAssembly::GE_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2634 /* i16x8.gt_s */, WebAssembly::GT_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2645 /* i16x8.gt_u */, WebAssembly::GT_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2656 /* i16x8.le_s */, WebAssembly::LE_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2667 /* i16x8.le_u */, WebAssembly::LE_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2678 /* i16x8.load8x8_s */, WebAssembly::LOAD_EXTEND_S_I16x8_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 2678 /* i16x8.load8x8_s */, WebAssembly::LOAD_EXTEND_S_I16x8_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 2694 /* i16x8.load8x8_u */, WebAssembly::LOAD_EXTEND_U_I16x8_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 2694 /* i16x8.load8x8_u */, WebAssembly::LOAD_EXTEND_U_I16x8_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 2710 /* i16x8.lt_s */, WebAssembly::LT_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2721 /* i16x8.lt_u */, WebAssembly::LT_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2732 /* i16x8.max_s */, WebAssembly::MAX_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2744 /* i16x8.max_u */, WebAssembly::MAX_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2756 /* i16x8.min_s */, WebAssembly::MIN_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2768 /* i16x8.min_u */, WebAssembly::MIN_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2780 /* i16x8.mul */, WebAssembly::MUL_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2790 /* i16x8.narrow_i32x4_s */, WebAssembly::NARROW_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2811 /* i16x8.narrow_i32x4_u */, WebAssembly::NARROW_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2832 /* i16x8.ne */, WebAssembly::NE_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2841 /* i16x8.neg */, WebAssembly::NEG_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2851 /* i16x8.q15mulr_sat_s */, WebAssembly::Q15MULR_SAT_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2871 /* i16x8.relaxed_dot_i8x16_i7x16_s */, WebAssembly::RELAXED_DOT_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 2903 /* i16x8.relaxed_laneselect */, WebAssembly::LANESELECT_I16x8_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 2928 /* i16x8.relaxed_q15mulr_s */, WebAssembly::RELAXED_Q15MULR_S_I16x8_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 2952 /* i16x8.replace_lane */, WebAssembly::REPLACE_LANE_I16x8_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 2971 /* i16x8.shl */, WebAssembly::SHL_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2981 /* i16x8.shr_s */, WebAssembly::SHR_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 2993 /* i16x8.shr_u */, WebAssembly::SHR_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 3005 /* i16x8.splat */, WebAssembly::SPLAT_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 3017 /* i16x8.sub */, WebAssembly::SUB_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 3027 /* i16x8.sub_sat_s */, WebAssembly::SUB_SAT_S_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 3043 /* i16x8.sub_sat_u */, WebAssembly::SUB_SAT_U_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 3059 /* i16x8.trunc_sat_f16x8_s */, WebAssembly::fp_to_sint_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 3083 /* i16x8.trunc_sat_f16x8_u */, WebAssembly::fp_to_uint_I16x8_S, Convert_NoOperands, AMFBS_HasSIMD128_HasFP16, {  }, },
  { 3107 /* i32.add */, WebAssembly::ADD_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3115 /* i32.and */, WebAssembly::AND_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3123 /* i32.atomic.load */, WebAssembly::ATOMIC_LOAD_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3123 /* i32.atomic.load */, WebAssembly::ATOMIC_LOAD_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3139 /* i32.atomic.load16_u */, WebAssembly::ATOMIC_LOAD16_U_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3139 /* i32.atomic.load16_u */, WebAssembly::ATOMIC_LOAD16_U_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3159 /* i32.atomic.load8_u */, WebAssembly::ATOMIC_LOAD8_U_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3159 /* i32.atomic.load8_u */, WebAssembly::ATOMIC_LOAD8_U_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3178 /* i32.atomic.rmw.add */, WebAssembly::ATOMIC_RMW_ADD_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3178 /* i32.atomic.rmw.add */, WebAssembly::ATOMIC_RMW_ADD_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3197 /* i32.atomic.rmw.and */, WebAssembly::ATOMIC_RMW_AND_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3197 /* i32.atomic.rmw.and */, WebAssembly::ATOMIC_RMW_AND_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3216 /* i32.atomic.rmw.cmpxchg */, WebAssembly::ATOMIC_RMW_CMPXCHG_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3216 /* i32.atomic.rmw.cmpxchg */, WebAssembly::ATOMIC_RMW_CMPXCHG_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3239 /* i32.atomic.rmw.or */, WebAssembly::ATOMIC_RMW_OR_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3239 /* i32.atomic.rmw.or */, WebAssembly::ATOMIC_RMW_OR_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3257 /* i32.atomic.rmw.sub */, WebAssembly::ATOMIC_RMW_SUB_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3257 /* i32.atomic.rmw.sub */, WebAssembly::ATOMIC_RMW_SUB_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3276 /* i32.atomic.rmw.xchg */, WebAssembly::ATOMIC_RMW_XCHG_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3276 /* i32.atomic.rmw.xchg */, WebAssembly::ATOMIC_RMW_XCHG_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3296 /* i32.atomic.rmw.xor */, WebAssembly::ATOMIC_RMW_XOR_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3296 /* i32.atomic.rmw.xor */, WebAssembly::ATOMIC_RMW_XOR_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3315 /* i32.atomic.rmw16.add_u */, WebAssembly::ATOMIC_RMW16_U_ADD_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3315 /* i32.atomic.rmw16.add_u */, WebAssembly::ATOMIC_RMW16_U_ADD_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3338 /* i32.atomic.rmw16.and_u */, WebAssembly::ATOMIC_RMW16_U_AND_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3338 /* i32.atomic.rmw16.and_u */, WebAssembly::ATOMIC_RMW16_U_AND_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3361 /* i32.atomic.rmw16.cmpxchg_u */, WebAssembly::ATOMIC_RMW16_U_CMPXCHG_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3361 /* i32.atomic.rmw16.cmpxchg_u */, WebAssembly::ATOMIC_RMW16_U_CMPXCHG_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3388 /* i32.atomic.rmw16.or_u */, WebAssembly::ATOMIC_RMW16_U_OR_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3388 /* i32.atomic.rmw16.or_u */, WebAssembly::ATOMIC_RMW16_U_OR_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3410 /* i32.atomic.rmw16.sub_u */, WebAssembly::ATOMIC_RMW16_U_SUB_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3410 /* i32.atomic.rmw16.sub_u */, WebAssembly::ATOMIC_RMW16_U_SUB_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3433 /* i32.atomic.rmw16.xchg_u */, WebAssembly::ATOMIC_RMW16_U_XCHG_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3433 /* i32.atomic.rmw16.xchg_u */, WebAssembly::ATOMIC_RMW16_U_XCHG_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3457 /* i32.atomic.rmw16.xor_u */, WebAssembly::ATOMIC_RMW16_U_XOR_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3457 /* i32.atomic.rmw16.xor_u */, WebAssembly::ATOMIC_RMW16_U_XOR_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3480 /* i32.atomic.rmw8.add_u */, WebAssembly::ATOMIC_RMW8_U_ADD_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3480 /* i32.atomic.rmw8.add_u */, WebAssembly::ATOMIC_RMW8_U_ADD_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3502 /* i32.atomic.rmw8.and_u */, WebAssembly::ATOMIC_RMW8_U_AND_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3502 /* i32.atomic.rmw8.and_u */, WebAssembly::ATOMIC_RMW8_U_AND_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3524 /* i32.atomic.rmw8.cmpxchg_u */, WebAssembly::ATOMIC_RMW8_U_CMPXCHG_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3524 /* i32.atomic.rmw8.cmpxchg_u */, WebAssembly::ATOMIC_RMW8_U_CMPXCHG_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3550 /* i32.atomic.rmw8.or_u */, WebAssembly::ATOMIC_RMW8_U_OR_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3550 /* i32.atomic.rmw8.or_u */, WebAssembly::ATOMIC_RMW8_U_OR_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3571 /* i32.atomic.rmw8.sub_u */, WebAssembly::ATOMIC_RMW8_U_SUB_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3571 /* i32.atomic.rmw8.sub_u */, WebAssembly::ATOMIC_RMW8_U_SUB_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3593 /* i32.atomic.rmw8.xchg_u */, WebAssembly::ATOMIC_RMW8_U_XCHG_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3593 /* i32.atomic.rmw8.xchg_u */, WebAssembly::ATOMIC_RMW8_U_XCHG_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3616 /* i32.atomic.rmw8.xor_u */, WebAssembly::ATOMIC_RMW8_U_XOR_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3616 /* i32.atomic.rmw8.xor_u */, WebAssembly::ATOMIC_RMW8_U_XOR_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3638 /* i32.atomic.store */, WebAssembly::ATOMIC_STORE_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3638 /* i32.atomic.store */, WebAssembly::ATOMIC_STORE_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3655 /* i32.atomic.store16 */, WebAssembly::ATOMIC_STORE16_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3655 /* i32.atomic.store16 */, WebAssembly::ATOMIC_STORE16_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3674 /* i32.atomic.store8 */, WebAssembly::ATOMIC_STORE8_I32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3674 /* i32.atomic.store8 */, WebAssembly::ATOMIC_STORE8_I32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 3692 /* i32.clz */, WebAssembly::CLZ_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3700 /* i32.const */, WebAssembly::CONST_I32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 3710 /* i32.ctz */, WebAssembly::CTZ_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3718 /* i32.div_s */, WebAssembly::DIV_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3728 /* i32.div_u */, WebAssembly::DIV_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3738 /* i32.eq */, WebAssembly::EQ_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3745 /* i32.eqz */, WebAssembly::EQZ_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3753 /* i32.extend16_s */, WebAssembly::I32_EXTEND16_S_I32_S, Convert_NoOperands, AMFBS_HasSignExt, {  }, },
  { 3768 /* i32.extend8_s */, WebAssembly::I32_EXTEND8_S_I32_S, Convert_NoOperands, AMFBS_HasSignExt, {  }, },
  { 3782 /* i32.ge_s */, WebAssembly::GE_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3791 /* i32.ge_u */, WebAssembly::GE_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3800 /* i32.gt_s */, WebAssembly::GT_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3809 /* i32.gt_u */, WebAssembly::GT_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3818 /* i32.le_s */, WebAssembly::LE_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3827 /* i32.le_u */, WebAssembly::LE_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3836 /* i32.load */, WebAssembly::LOAD_I32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3836 /* i32.load */, WebAssembly::LOAD_I32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3845 /* i32.load16_s */, WebAssembly::LOAD16_S_I32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3845 /* i32.load16_s */, WebAssembly::LOAD16_S_I32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3858 /* i32.load16_u */, WebAssembly::LOAD16_U_I32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3858 /* i32.load16_u */, WebAssembly::LOAD16_U_I32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3871 /* i32.load8_s */, WebAssembly::LOAD8_S_I32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3871 /* i32.load8_s */, WebAssembly::LOAD8_S_I32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3883 /* i32.load8_u */, WebAssembly::LOAD8_U_I32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3883 /* i32.load8_u */, WebAssembly::LOAD8_U_I32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 3895 /* i32.lt_s */, WebAssembly::LT_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3904 /* i32.lt_u */, WebAssembly::LT_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3913 /* i32.mul */, WebAssembly::MUL_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3921 /* i32.ne */, WebAssembly::NE_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3928 /* i32.or */, WebAssembly::OR_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3935 /* i32.popcnt */, WebAssembly::POPCNT_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3946 /* i32.reinterpret_f32 */, WebAssembly::I32_REINTERPRET_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3966 /* i32.rem_s */, WebAssembly::REM_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3976 /* i32.rem_u */, WebAssembly::REM_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3986 /* i32.rotl */, WebAssembly::ROTL_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3995 /* i32.rotr */, WebAssembly::ROTR_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4004 /* i32.select */, WebAssembly::SELECT_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4015 /* i32.shl */, WebAssembly::SHL_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4023 /* i32.shr_s */, WebAssembly::SHR_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4033 /* i32.shr_u */, WebAssembly::SHR_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4043 /* i32.store */, WebAssembly::STORE_I32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 4043 /* i32.store */, WebAssembly::STORE_I32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 4053 /* i32.store16 */, WebAssembly::STORE16_I32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 4053 /* i32.store16 */, WebAssembly::STORE16_I32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 4065 /* i32.store8 */, WebAssembly::STORE8_I32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 4065 /* i32.store8 */, WebAssembly::STORE8_I32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 4076 /* i32.sub */, WebAssembly::SUB_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4084 /* i32.trunc_f32_s */, WebAssembly::I32_TRUNC_S_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4100 /* i32.trunc_f32_u */, WebAssembly::I32_TRUNC_U_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4116 /* i32.trunc_f64_s */, WebAssembly::I32_TRUNC_S_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4132 /* i32.trunc_f64_u */, WebAssembly::I32_TRUNC_U_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4148 /* i32.trunc_sat_f32_s */, WebAssembly::I32_TRUNC_S_SAT_F32_S, Convert_NoOperands, AMFBS_HasNontrappingFPToInt, {  }, },
  { 4168 /* i32.trunc_sat_f32_u */, WebAssembly::I32_TRUNC_U_SAT_F32_S, Convert_NoOperands, AMFBS_HasNontrappingFPToInt, {  }, },
  { 4188 /* i32.trunc_sat_f64_s */, WebAssembly::I32_TRUNC_S_SAT_F64_S, Convert_NoOperands, AMFBS_HasNontrappingFPToInt, {  }, },
  { 4208 /* i32.trunc_sat_f64_u */, WebAssembly::I32_TRUNC_U_SAT_F64_S, Convert_NoOperands, AMFBS_HasNontrappingFPToInt, {  }, },
  { 4228 /* i32.wrap_i64 */, WebAssembly::I32_WRAP_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4241 /* i32.xor */, WebAssembly::XOR_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 4249 /* i32x4.abs */, WebAssembly::ABS_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4259 /* i32x4.add */, WebAssembly::ADD_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4269 /* i32x4.all_true */, WebAssembly::ALLTRUE_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4284 /* i32x4.bitmask */, WebAssembly::BITMASK_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4298 /* i32x4.dot_i16x8_s */, WebAssembly::DOT_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4316 /* i32x4.eq */, WebAssembly::EQ_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4325 /* i32x4.extadd_pairwise_i16x8_s */, WebAssembly::extadd_pairwise_s_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4355 /* i32x4.extadd_pairwise_i16x8_u */, WebAssembly::extadd_pairwise_u_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4385 /* i32x4.extend_high_i16x8_s */, WebAssembly::extend_high_s_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4411 /* i32x4.extend_high_i16x8_u */, WebAssembly::extend_high_u_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4437 /* i32x4.extend_low_i16x8_s */, WebAssembly::extend_low_s_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4462 /* i32x4.extend_low_i16x8_u */, WebAssembly::extend_low_u_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4487 /* i32x4.extmul_high_i16x8_s */, WebAssembly::EXTMUL_HIGH_S_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4513 /* i32x4.extmul_high_i16x8_u */, WebAssembly::EXTMUL_HIGH_U_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4539 /* i32x4.extmul_low_i16x8_s */, WebAssembly::EXTMUL_LOW_S_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4564 /* i32x4.extmul_low_i16x8_u */, WebAssembly::EXTMUL_LOW_U_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4589 /* i32x4.extract_lane */, WebAssembly::EXTRACT_LANE_I32x4_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 4608 /* i32x4.ge_s */, WebAssembly::GE_S_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4619 /* i32x4.ge_u */, WebAssembly::GE_U_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4630 /* i32x4.gt_s */, WebAssembly::GT_S_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4641 /* i32x4.gt_u */, WebAssembly::GT_U_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4652 /* i32x4.le_s */, WebAssembly::LE_S_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4663 /* i32x4.le_u */, WebAssembly::LE_U_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4674 /* i32x4.load16x4_s */, WebAssembly::LOAD_EXTEND_S_I32x4_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 4674 /* i32x4.load16x4_s */, WebAssembly::LOAD_EXTEND_S_I32x4_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 4691 /* i32x4.load16x4_u */, WebAssembly::LOAD_EXTEND_U_I32x4_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 4691 /* i32x4.load16x4_u */, WebAssembly::LOAD_EXTEND_U_I32x4_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 4708 /* i32x4.lt_s */, WebAssembly::LT_S_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4719 /* i32x4.lt_u */, WebAssembly::LT_U_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4730 /* i32x4.max_s */, WebAssembly::MAX_S_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4742 /* i32x4.max_u */, WebAssembly::MAX_U_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4754 /* i32x4.min_s */, WebAssembly::MIN_S_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4766 /* i32x4.min_u */, WebAssembly::MIN_U_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4778 /* i32x4.mul */, WebAssembly::MUL_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4788 /* i32x4.ne */, WebAssembly::NE_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4797 /* i32x4.neg */, WebAssembly::NEG_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 4807 /* i32x4.relaxed_dot_i8x16_i7x16_add_s */, WebAssembly::RELAXED_DOT_ADD_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 4843 /* i32x4.relaxed_laneselect */, WebAssembly::LANESELECT_I32x4_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 4868 /* i32x4.relaxed_trunc_f32x4_s */, WebAssembly::int_wasm_relaxed_trunc_signed_I32x4_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 4896 /* i32x4.relaxed_trunc_f32x4_u */, WebAssembly::int_wasm_relaxed_trunc_unsigned_I32x4_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 4924 /* i32x4.relaxed_trunc_f64x2_s_zero */, WebAssembly::int_wasm_relaxed_trunc_signed_zero_I32x4_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 4957 /* i32x4.relaxed_trunc_f64x2_u_zero */, WebAssembly::int_wasm_relaxed_trunc_unsigned_zero_I32x4_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 4990 /* i32x4.replace_lane */, WebAssembly::REPLACE_LANE_I32x4_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 5009 /* i32x4.shl */, WebAssembly::SHL_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 5019 /* i32x4.shr_s */, WebAssembly::SHR_S_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 5031 /* i32x4.shr_u */, WebAssembly::SHR_U_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 5043 /* i32x4.splat */, WebAssembly::SPLAT_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 5055 /* i32x4.sub */, WebAssembly::SUB_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 5065 /* i32x4.trunc_sat_f32x4_s */, WebAssembly::fp_to_sint_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 5089 /* i32x4.trunc_sat_f32x4_u */, WebAssembly::fp_to_uint_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 5113 /* i32x4.trunc_sat_f64x2_s_zero */, WebAssembly::trunc_sat_zero_s_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 5142 /* i32x4.trunc_sat_f64x2_u_zero */, WebAssembly::trunc_sat_zero_u_I32x4_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 5171 /* i64.add */, WebAssembly::ADD_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 5179 /* i64.add128 */, WebAssembly::I64_ADD128_S, Convert_NoOperands, AMFBS_HasWideArithmetic, {  }, },
  { 5190 /* i64.and */, WebAssembly::AND_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 5198 /* i64.atomic.load */, WebAssembly::ATOMIC_LOAD_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5198 /* i64.atomic.load */, WebAssembly::ATOMIC_LOAD_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5214 /* i64.atomic.load16_u */, WebAssembly::ATOMIC_LOAD16_U_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5214 /* i64.atomic.load16_u */, WebAssembly::ATOMIC_LOAD16_U_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5234 /* i64.atomic.load32_u */, WebAssembly::ATOMIC_LOAD32_U_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5234 /* i64.atomic.load32_u */, WebAssembly::ATOMIC_LOAD32_U_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5254 /* i64.atomic.load8_u */, WebAssembly::ATOMIC_LOAD8_U_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5254 /* i64.atomic.load8_u */, WebAssembly::ATOMIC_LOAD8_U_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5273 /* i64.atomic.rmw.add */, WebAssembly::ATOMIC_RMW_ADD_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5273 /* i64.atomic.rmw.add */, WebAssembly::ATOMIC_RMW_ADD_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5292 /* i64.atomic.rmw.and */, WebAssembly::ATOMIC_RMW_AND_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5292 /* i64.atomic.rmw.and */, WebAssembly::ATOMIC_RMW_AND_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5311 /* i64.atomic.rmw.cmpxchg */, WebAssembly::ATOMIC_RMW_CMPXCHG_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5311 /* i64.atomic.rmw.cmpxchg */, WebAssembly::ATOMIC_RMW_CMPXCHG_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5334 /* i64.atomic.rmw.or */, WebAssembly::ATOMIC_RMW_OR_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5334 /* i64.atomic.rmw.or */, WebAssembly::ATOMIC_RMW_OR_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5352 /* i64.atomic.rmw.sub */, WebAssembly::ATOMIC_RMW_SUB_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5352 /* i64.atomic.rmw.sub */, WebAssembly::ATOMIC_RMW_SUB_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5371 /* i64.atomic.rmw.xchg */, WebAssembly::ATOMIC_RMW_XCHG_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5371 /* i64.atomic.rmw.xchg */, WebAssembly::ATOMIC_RMW_XCHG_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5391 /* i64.atomic.rmw.xor */, WebAssembly::ATOMIC_RMW_XOR_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5391 /* i64.atomic.rmw.xor */, WebAssembly::ATOMIC_RMW_XOR_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5410 /* i64.atomic.rmw16.add_u */, WebAssembly::ATOMIC_RMW16_U_ADD_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5410 /* i64.atomic.rmw16.add_u */, WebAssembly::ATOMIC_RMW16_U_ADD_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5433 /* i64.atomic.rmw16.and_u */, WebAssembly::ATOMIC_RMW16_U_AND_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5433 /* i64.atomic.rmw16.and_u */, WebAssembly::ATOMIC_RMW16_U_AND_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5456 /* i64.atomic.rmw16.cmpxchg_u */, WebAssembly::ATOMIC_RMW16_U_CMPXCHG_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5456 /* i64.atomic.rmw16.cmpxchg_u */, WebAssembly::ATOMIC_RMW16_U_CMPXCHG_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5483 /* i64.atomic.rmw16.or_u */, WebAssembly::ATOMIC_RMW16_U_OR_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5483 /* i64.atomic.rmw16.or_u */, WebAssembly::ATOMIC_RMW16_U_OR_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5505 /* i64.atomic.rmw16.sub_u */, WebAssembly::ATOMIC_RMW16_U_SUB_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5505 /* i64.atomic.rmw16.sub_u */, WebAssembly::ATOMIC_RMW16_U_SUB_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5528 /* i64.atomic.rmw16.xchg_u */, WebAssembly::ATOMIC_RMW16_U_XCHG_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5528 /* i64.atomic.rmw16.xchg_u */, WebAssembly::ATOMIC_RMW16_U_XCHG_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5552 /* i64.atomic.rmw16.xor_u */, WebAssembly::ATOMIC_RMW16_U_XOR_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5552 /* i64.atomic.rmw16.xor_u */, WebAssembly::ATOMIC_RMW16_U_XOR_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5575 /* i64.atomic.rmw32.add_u */, WebAssembly::ATOMIC_RMW32_U_ADD_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5575 /* i64.atomic.rmw32.add_u */, WebAssembly::ATOMIC_RMW32_U_ADD_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5598 /* i64.atomic.rmw32.and_u */, WebAssembly::ATOMIC_RMW32_U_AND_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5598 /* i64.atomic.rmw32.and_u */, WebAssembly::ATOMIC_RMW32_U_AND_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5621 /* i64.atomic.rmw32.cmpxchg_u */, WebAssembly::ATOMIC_RMW32_U_CMPXCHG_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5621 /* i64.atomic.rmw32.cmpxchg_u */, WebAssembly::ATOMIC_RMW32_U_CMPXCHG_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5648 /* i64.atomic.rmw32.or_u */, WebAssembly::ATOMIC_RMW32_U_OR_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5648 /* i64.atomic.rmw32.or_u */, WebAssembly::ATOMIC_RMW32_U_OR_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5670 /* i64.atomic.rmw32.sub_u */, WebAssembly::ATOMIC_RMW32_U_SUB_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5670 /* i64.atomic.rmw32.sub_u */, WebAssembly::ATOMIC_RMW32_U_SUB_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5693 /* i64.atomic.rmw32.xchg_u */, WebAssembly::ATOMIC_RMW32_U_XCHG_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5693 /* i64.atomic.rmw32.xchg_u */, WebAssembly::ATOMIC_RMW32_U_XCHG_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5717 /* i64.atomic.rmw32.xor_u */, WebAssembly::ATOMIC_RMW32_U_XOR_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5717 /* i64.atomic.rmw32.xor_u */, WebAssembly::ATOMIC_RMW32_U_XOR_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5740 /* i64.atomic.rmw8.add_u */, WebAssembly::ATOMIC_RMW8_U_ADD_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5740 /* i64.atomic.rmw8.add_u */, WebAssembly::ATOMIC_RMW8_U_ADD_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5762 /* i64.atomic.rmw8.and_u */, WebAssembly::ATOMIC_RMW8_U_AND_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5762 /* i64.atomic.rmw8.and_u */, WebAssembly::ATOMIC_RMW8_U_AND_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5784 /* i64.atomic.rmw8.cmpxchg_u */, WebAssembly::ATOMIC_RMW8_U_CMPXCHG_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5784 /* i64.atomic.rmw8.cmpxchg_u */, WebAssembly::ATOMIC_RMW8_U_CMPXCHG_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5810 /* i64.atomic.rmw8.or_u */, WebAssembly::ATOMIC_RMW8_U_OR_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5810 /* i64.atomic.rmw8.or_u */, WebAssembly::ATOMIC_RMW8_U_OR_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5831 /* i64.atomic.rmw8.sub_u */, WebAssembly::ATOMIC_RMW8_U_SUB_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5831 /* i64.atomic.rmw8.sub_u */, WebAssembly::ATOMIC_RMW8_U_SUB_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5853 /* i64.atomic.rmw8.xchg_u */, WebAssembly::ATOMIC_RMW8_U_XCHG_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5853 /* i64.atomic.rmw8.xchg_u */, WebAssembly::ATOMIC_RMW8_U_XCHG_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5876 /* i64.atomic.rmw8.xor_u */, WebAssembly::ATOMIC_RMW8_U_XOR_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5876 /* i64.atomic.rmw8.xor_u */, WebAssembly::ATOMIC_RMW8_U_XOR_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5898 /* i64.atomic.store */, WebAssembly::ATOMIC_STORE_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5898 /* i64.atomic.store */, WebAssembly::ATOMIC_STORE_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5915 /* i64.atomic.store16 */, WebAssembly::ATOMIC_STORE16_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5915 /* i64.atomic.store16 */, WebAssembly::ATOMIC_STORE16_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5934 /* i64.atomic.store32 */, WebAssembly::ATOMIC_STORE32_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5934 /* i64.atomic.store32 */, WebAssembly::ATOMIC_STORE32_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5953 /* i64.atomic.store8 */, WebAssembly::ATOMIC_STORE8_I64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5953 /* i64.atomic.store8 */, WebAssembly::ATOMIC_STORE8_I64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 5971 /* i64.clz */, WebAssembly::CLZ_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 5979 /* i64.const */, WebAssembly::CONST_I64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 5989 /* i64.ctz */, WebAssembly::CTZ_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 5997 /* i64.div_s */, WebAssembly::DIV_S_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6007 /* i64.div_u */, WebAssembly::DIV_U_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6017 /* i64.eq */, WebAssembly::EQ_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6024 /* i64.eqz */, WebAssembly::EQZ_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6032 /* i64.extend16_s */, WebAssembly::I64_EXTEND16_S_I64_S, Convert_NoOperands, AMFBS_HasSignExt, {  }, },
  { 6047 /* i64.extend32_s */, WebAssembly::I64_EXTEND32_S_I64_S, Convert_NoOperands, AMFBS_HasSignExt, {  }, },
  { 6062 /* i64.extend8_s */, WebAssembly::I64_EXTEND8_S_I64_S, Convert_NoOperands, AMFBS_HasSignExt, {  }, },
  { 6076 /* i64.extend_i32_s */, WebAssembly::I64_EXTEND_S_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6093 /* i64.extend_i32_u */, WebAssembly::I64_EXTEND_U_I32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6110 /* i64.ge_s */, WebAssembly::GE_S_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6119 /* i64.ge_u */, WebAssembly::GE_U_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6128 /* i64.gt_s */, WebAssembly::GT_S_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6137 /* i64.gt_u */, WebAssembly::GT_U_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6146 /* i64.le_s */, WebAssembly::LE_S_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6155 /* i64.le_u */, WebAssembly::LE_U_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6164 /* i64.load */, WebAssembly::LOAD_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6164 /* i64.load */, WebAssembly::LOAD_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6173 /* i64.load16_s */, WebAssembly::LOAD16_S_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6173 /* i64.load16_s */, WebAssembly::LOAD16_S_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6186 /* i64.load16_u */, WebAssembly::LOAD16_U_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6186 /* i64.load16_u */, WebAssembly::LOAD16_U_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6199 /* i64.load32_s */, WebAssembly::LOAD32_S_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6199 /* i64.load32_s */, WebAssembly::LOAD32_S_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6212 /* i64.load32_u */, WebAssembly::LOAD32_U_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6212 /* i64.load32_u */, WebAssembly::LOAD32_U_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6225 /* i64.load8_s */, WebAssembly::LOAD8_S_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6225 /* i64.load8_s */, WebAssembly::LOAD8_S_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6237 /* i64.load8_u */, WebAssembly::LOAD8_U_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6237 /* i64.load8_u */, WebAssembly::LOAD8_U_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6249 /* i64.lt_s */, WebAssembly::LT_S_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6258 /* i64.lt_u */, WebAssembly::LT_U_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6267 /* i64.mul */, WebAssembly::MUL_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6275 /* i64.mul_wide_s */, WebAssembly::I64_MUL_WIDE_S_S, Convert_NoOperands, AMFBS_HasWideArithmetic, {  }, },
  { 6290 /* i64.mul_wide_u */, WebAssembly::I64_MUL_WIDE_U_S, Convert_NoOperands, AMFBS_HasWideArithmetic, {  }, },
  { 6305 /* i64.ne */, WebAssembly::NE_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6312 /* i64.or */, WebAssembly::OR_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6319 /* i64.popcnt */, WebAssembly::POPCNT_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6330 /* i64.reinterpret_f64 */, WebAssembly::I64_REINTERPRET_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6350 /* i64.rem_s */, WebAssembly::REM_S_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6360 /* i64.rem_u */, WebAssembly::REM_U_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6370 /* i64.rotl */, WebAssembly::ROTL_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6379 /* i64.rotr */, WebAssembly::ROTR_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6388 /* i64.select */, WebAssembly::SELECT_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6399 /* i64.shl */, WebAssembly::SHL_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6407 /* i64.shr_s */, WebAssembly::SHR_S_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6417 /* i64.shr_u */, WebAssembly::SHR_U_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6427 /* i64.store */, WebAssembly::STORE_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6427 /* i64.store */, WebAssembly::STORE_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6437 /* i64.store16 */, WebAssembly::STORE16_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6437 /* i64.store16 */, WebAssembly::STORE16_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6449 /* i64.store32 */, WebAssembly::STORE32_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6449 /* i64.store32 */, WebAssembly::STORE32_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6461 /* i64.store8 */, WebAssembly::STORE8_I64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6461 /* i64.store8 */, WebAssembly::STORE8_I64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 6472 /* i64.sub */, WebAssembly::SUB_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6480 /* i64.sub128 */, WebAssembly::I64_SUB128_S, Convert_NoOperands, AMFBS_HasWideArithmetic, {  }, },
  { 6491 /* i64.trunc_f32_s */, WebAssembly::I64_TRUNC_S_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6507 /* i64.trunc_f32_u */, WebAssembly::I64_TRUNC_U_F32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6523 /* i64.trunc_f64_s */, WebAssembly::I64_TRUNC_S_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6539 /* i64.trunc_f64_u */, WebAssembly::I64_TRUNC_U_F64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6555 /* i64.trunc_sat_f32_s */, WebAssembly::I64_TRUNC_S_SAT_F32_S, Convert_NoOperands, AMFBS_HasNontrappingFPToInt, {  }, },
  { 6575 /* i64.trunc_sat_f32_u */, WebAssembly::I64_TRUNC_U_SAT_F32_S, Convert_NoOperands, AMFBS_HasNontrappingFPToInt, {  }, },
  { 6595 /* i64.trunc_sat_f64_s */, WebAssembly::I64_TRUNC_S_SAT_F64_S, Convert_NoOperands, AMFBS_HasNontrappingFPToInt, {  }, },
  { 6615 /* i64.trunc_sat_f64_u */, WebAssembly::I64_TRUNC_U_SAT_F64_S, Convert_NoOperands, AMFBS_HasNontrappingFPToInt, {  }, },
  { 6635 /* i64.xor */, WebAssembly::XOR_I64_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 6643 /* i64x2.abs */, WebAssembly::ABS_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6653 /* i64x2.add */, WebAssembly::ADD_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6663 /* i64x2.all_true */, WebAssembly::ALLTRUE_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6678 /* i64x2.bitmask */, WebAssembly::BITMASK_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6692 /* i64x2.eq */, WebAssembly::EQ_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6701 /* i64x2.extend_high_i32x4_s */, WebAssembly::extend_high_s_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6727 /* i64x2.extend_high_i32x4_u */, WebAssembly::extend_high_u_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6753 /* i64x2.extend_low_i32x4_s */, WebAssembly::extend_low_s_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6778 /* i64x2.extend_low_i32x4_u */, WebAssembly::extend_low_u_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6803 /* i64x2.extmul_high_i32x4_s */, WebAssembly::EXTMUL_HIGH_S_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6829 /* i64x2.extmul_high_i32x4_u */, WebAssembly::EXTMUL_HIGH_U_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6855 /* i64x2.extmul_low_i32x4_s */, WebAssembly::EXTMUL_LOW_S_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6880 /* i64x2.extmul_low_i32x4_u */, WebAssembly::EXTMUL_LOW_U_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6905 /* i64x2.extract_lane */, WebAssembly::EXTRACT_LANE_I64x2_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 6924 /* i64x2.ge_s */, WebAssembly::GE_S_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6935 /* i64x2.gt_s */, WebAssembly::GT_S_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6946 /* i64x2.le_s */, WebAssembly::LE_S_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 6957 /* i64x2.load32x2_s */, WebAssembly::LOAD_EXTEND_S_I64x2_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 6957 /* i64x2.load32x2_s */, WebAssembly::LOAD_EXTEND_S_I64x2_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 6974 /* i64x2.load32x2_u */, WebAssembly::LOAD_EXTEND_U_I64x2_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 6974 /* i64x2.load32x2_u */, WebAssembly::LOAD_EXTEND_U_I64x2_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 6991 /* i64x2.lt_s */, WebAssembly::LT_S_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7002 /* i64x2.mul */, WebAssembly::MUL_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7012 /* i64x2.ne */, WebAssembly::NE_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7021 /* i64x2.neg */, WebAssembly::NEG_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7031 /* i64x2.relaxed_laneselect */, WebAssembly::LANESELECT_I64x2_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 7056 /* i64x2.replace_lane */, WebAssembly::REPLACE_LANE_I64x2_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 7075 /* i64x2.shl */, WebAssembly::SHL_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7085 /* i64x2.shr_s */, WebAssembly::SHR_S_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7097 /* i64x2.shr_u */, WebAssembly::SHR_U_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7109 /* i64x2.splat */, WebAssembly::SPLAT_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7121 /* i64x2.sub */, WebAssembly::SUB_I64x2_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7131 /* i8x16.abs */, WebAssembly::ABS_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7141 /* i8x16.add */, WebAssembly::ADD_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7151 /* i8x16.add_sat_s */, WebAssembly::ADD_SAT_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7167 /* i8x16.add_sat_u */, WebAssembly::ADD_SAT_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7183 /* i8x16.all_true */, WebAssembly::ALLTRUE_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7198 /* i8x16.avgr_u */, WebAssembly::AVGR_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7211 /* i8x16.bitmask */, WebAssembly::BITMASK_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7225 /* i8x16.eq */, WebAssembly::EQ_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7234 /* i8x16.extract_lane_s */, WebAssembly::EXTRACT_LANE_I8x16_s_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 7255 /* i8x16.extract_lane_u */, WebAssembly::EXTRACT_LANE_I8x16_u_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 7276 /* i8x16.ge_s */, WebAssembly::GE_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7287 /* i8x16.ge_u */, WebAssembly::GE_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7298 /* i8x16.gt_s */, WebAssembly::GT_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7309 /* i8x16.gt_u */, WebAssembly::GT_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7320 /* i8x16.le_s */, WebAssembly::LE_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7331 /* i8x16.le_u */, WebAssembly::LE_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7342 /* i8x16.lt_s */, WebAssembly::LT_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7353 /* i8x16.lt_u */, WebAssembly::LT_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7364 /* i8x16.max_s */, WebAssembly::MAX_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7376 /* i8x16.max_u */, WebAssembly::MAX_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7388 /* i8x16.min_s */, WebAssembly::MIN_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7400 /* i8x16.min_u */, WebAssembly::MIN_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7412 /* i8x16.narrow_i16x8_s */, WebAssembly::NARROW_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7433 /* i8x16.narrow_i16x8_u */, WebAssembly::NARROW_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7454 /* i8x16.ne */, WebAssembly::NE_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7463 /* i8x16.neg */, WebAssembly::NEG_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7473 /* i8x16.popcnt */, WebAssembly::POPCNT_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7486 /* i8x16.relaxed_laneselect */, WebAssembly::LANESELECT_I8x16_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 7511 /* i8x16.relaxed_swizzle */, WebAssembly::RELAXED_SWIZZLE_S, Convert_NoOperands, AMFBS_HasRelaxedSIMD, {  }, },
  { 7533 /* i8x16.replace_lane */, WebAssembly::REPLACE_LANE_I8x16_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 7552 /* i8x16.shl */, WebAssembly::SHL_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7562 /* i8x16.shr_s */, WebAssembly::SHR_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7574 /* i8x16.shr_u */, WebAssembly::SHR_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7586 /* i8x16.shuffle */, WebAssembly::SHUFFLE_S, Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3__Imm1_4__Imm1_5__Imm1_6__Imm1_7__Imm1_8__Imm1_9__Imm1_10__Imm1_11__Imm1_12__Imm1_13__Imm1_14__Imm1_15, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 7600 /* i8x16.splat */, WebAssembly::SPLAT_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7612 /* i8x16.sub */, WebAssembly::SUB_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7622 /* i8x16.sub_sat_s */, WebAssembly::SUB_SAT_S_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7638 /* i8x16.sub_sat_u */, WebAssembly::SUB_SAT_U_I8x16_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7654 /* i8x16.swizzle */, WebAssembly::SWIZZLE_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 7668 /* if */, WebAssembly::IF_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7671 /* local.get */, WebAssembly::LOCAL_GET_EXNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes_HasExceptionHandling, { MCK_Imm }, },
  { 7671 /* local.get */, WebAssembly::LOCAL_GET_EXTERNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 7671 /* local.get */, WebAssembly::LOCAL_GET_FUNCREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 7671 /* local.get */, WebAssembly::LOCAL_GET_V128_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 7671 /* local.get */, WebAssembly::LOCAL_GET_F32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7671 /* local.get */, WebAssembly::LOCAL_GET_F64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7671 /* local.get */, WebAssembly::LOCAL_GET_I32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7671 /* local.get */, WebAssembly::LOCAL_GET_I64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7681 /* local.set */, WebAssembly::LOCAL_SET_EXNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes_HasExceptionHandling, { MCK_Imm }, },
  { 7681 /* local.set */, WebAssembly::LOCAL_SET_EXTERNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 7681 /* local.set */, WebAssembly::LOCAL_SET_FUNCREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 7681 /* local.set */, WebAssembly::LOCAL_SET_V128_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 7681 /* local.set */, WebAssembly::LOCAL_SET_F32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7681 /* local.set */, WebAssembly::LOCAL_SET_F64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7681 /* local.set */, WebAssembly::LOCAL_SET_I32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7681 /* local.set */, WebAssembly::LOCAL_SET_I64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7691 /* local.tee */, WebAssembly::LOCAL_TEE_EXNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes_HasExceptionHandling, { MCK_Imm }, },
  { 7691 /* local.tee */, WebAssembly::LOCAL_TEE_EXTERNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 7691 /* local.tee */, WebAssembly::LOCAL_TEE_FUNCREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 7691 /* local.tee */, WebAssembly::LOCAL_TEE_V128_S, Convert__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm }, },
  { 7691 /* local.tee */, WebAssembly::LOCAL_TEE_F32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7691 /* local.tee */, WebAssembly::LOCAL_TEE_F64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7691 /* local.tee */, WebAssembly::LOCAL_TEE_I32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7691 /* local.tee */, WebAssembly::LOCAL_TEE_I64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7701 /* loop */, WebAssembly::LOOP_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7706 /* memory.atomic.notify */, WebAssembly::MEMORY_ATOMIC_NOTIFY_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 7706 /* memory.atomic.notify */, WebAssembly::MEMORY_ATOMIC_NOTIFY_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 7727 /* memory.atomic.wait32 */, WebAssembly::MEMORY_ATOMIC_WAIT32_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 7727 /* memory.atomic.wait32 */, WebAssembly::MEMORY_ATOMIC_WAIT32_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 7748 /* memory.atomic.wait64 */, WebAssembly::MEMORY_ATOMIC_WAIT64_A32_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 7748 /* memory.atomic.wait64 */, WebAssembly::MEMORY_ATOMIC_WAIT64_A64_S, Convert__Imm1_0__Imm1_2__Imm1_1, AMFBS_HasAtomics, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 7769 /* memory.copy */, WebAssembly::MEMORY_COPY_A32_S, Convert__Imm1_0__Imm1_1, AMFBS_HasBulkMemoryOpt, { MCK_Imm, MCK_Imm }, },
  { 7769 /* memory.copy */, WebAssembly::MEMORY_COPY_A64_S, Convert__Imm1_0__Imm1_1, AMFBS_HasBulkMemoryOpt, { MCK_Imm, MCK_Imm }, },
  { 7781 /* memory.fill */, WebAssembly::MEMORY_FILL_A32_S, Convert__Imm1_0, AMFBS_HasBulkMemoryOpt, { MCK_Imm }, },
  { 7781 /* memory.fill */, WebAssembly::MEMORY_FILL_A64_S, Convert__Imm1_0, AMFBS_HasBulkMemoryOpt, { MCK_Imm }, },
  { 7793 /* memory.grow */, WebAssembly::anonymous_14027MEMORY_GROW_A32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7793 /* memory.grow */, WebAssembly::anonymous_14028MEMORY_GROW_A64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7805 /* memory.init */, WebAssembly::MEMORY_INIT_A32_S, Convert__Imm1_0__Imm1_1, AMFBS_HasBulkMemoryOpt, { MCK_Imm, MCK_Imm }, },
  { 7805 /* memory.init */, WebAssembly::MEMORY_INIT_A64_S, Convert__Imm1_0__Imm1_1, AMFBS_HasBulkMemoryOpt, { MCK_Imm, MCK_Imm }, },
  { 7817 /* memory.size */, WebAssembly::anonymous_14027MEMORY_SIZE_A32_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7817 /* memory.size */, WebAssembly::anonymous_14028MEMORY_SIZE_A64_S, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 7829 /* nop */, WebAssembly::NOP_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 7833 /* ref.cast */, WebAssembly::REF_CAST_FUNCREF_S, Convert__Imm1_0, AMFBS_HasGC, { MCK_Imm }, },
  { 7842 /* ref.func */, WebAssembly::REF_FUNC_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 7851 /* ref.is_null */, WebAssembly::REF_IS_NULL_EXNREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 7851 /* ref.is_null */, WebAssembly::REF_IS_NULL_EXTERNREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 7851 /* ref.is_null */, WebAssembly::REF_IS_NULL_FUNCREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 7863 /* ref.null_exn */, WebAssembly::REF_NULL_EXNREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 7876 /* ref.null_extern */, WebAssembly::REF_NULL_EXTERNREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 7892 /* ref.null_func */, WebAssembly::REF_NULL_FUNCREF_S, Convert_NoOperands, AMFBS_HasReferenceTypes, {  }, },
  { 7906 /* ref.test */, WebAssembly::REF_TEST_FUNCREF_S, Convert__Imm1_0, AMFBS_HasGC, { MCK_Imm }, },
  { 7915 /* rethrow */, WebAssembly::RETHROW_S, Convert__Imm1_0, AMFBS_HasExceptionHandling, { MCK_Imm }, },
  { 7923 /* return */, WebAssembly::RETURN_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 7930 /* return_call */, WebAssembly::RET_CALL_S, Convert__Imm1_0, AMFBS_HasTailCall, { MCK_Imm }, },
  { 7942 /* return_call_indirect */, WebAssembly::RET_CALL_INDIRECT_S, Convert__Imm1_0__Imm1_1, AMFBS_HasTailCall, { MCK_Imm, MCK_Imm }, },
  { 7963 /* return_call_ref */, WebAssembly::RET_CALL_REF_S, Convert__Imm1_0, AMFBS_HasTailCall_HasGC, { MCK_Imm }, },
  { 7979 /* return_call_results */, WebAssembly::RET_CALL_RESULTS_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 7999 /* select */, WebAssembly::SELECT_T_S, Convert__TypeList1_0, AMFBS_HasReferenceTypes, { MCK_TypeList }, },
  { 8006 /* table.copy */, WebAssembly::TABLE_COPY_S, Convert__Imm1_0__Imm1_1, AMFBS_HasReferenceTypes, { MCK_Imm, MCK_Imm }, },
  { 8017 /* table.fill */, WebAssembly::TABLE_FILL_EXNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes_HasExceptionHandling, { MCK_Imm }, },
  { 8017 /* table.fill */, WebAssembly::TABLE_FILL_EXTERNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 8017 /* table.fill */, WebAssembly::TABLE_FILL_FUNCREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 8028 /* table.get */, WebAssembly::TABLE_GET_EXNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes_HasExceptionHandling, { MCK_Imm }, },
  { 8028 /* table.get */, WebAssembly::TABLE_GET_EXTERNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 8028 /* table.get */, WebAssembly::TABLE_GET_FUNCREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 8038 /* table.grow */, WebAssembly::TABLE_GROW_EXNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes_HasExceptionHandling, { MCK_Imm }, },
  { 8038 /* table.grow */, WebAssembly::TABLE_GROW_EXTERNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 8038 /* table.grow */, WebAssembly::TABLE_GROW_FUNCREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 8049 /* table.set */, WebAssembly::TABLE_SET_EXNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes_HasExceptionHandling, { MCK_Imm }, },
  { 8049 /* table.set */, WebAssembly::TABLE_SET_EXTERNREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 8049 /* table.set */, WebAssembly::TABLE_SET_FUNCREF_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 8059 /* table.size */, WebAssembly::TABLE_SIZE_S, Convert__Imm1_0, AMFBS_HasReferenceTypes, { MCK_Imm }, },
  { 8070 /* throw */, WebAssembly::THROW_S, Convert__Imm1_0, AMFBS_HasExceptionHandling, { MCK_Imm }, },
  { 8076 /* throw_ref */, WebAssembly::THROW_REF_S, Convert_NoOperands, AMFBS_HasExceptionHandling, {  }, },
  { 8086 /* try */, WebAssembly::TRY_S, Convert__Imm1_0, AMFBS_HasExceptionHandling, { MCK_Imm }, },
  { 8090 /* try_table */, WebAssembly::TRY_TABLE_S, Convert__Imm1_0__CatchList1_1, AMFBS_HasExceptionHandling, { MCK_Imm, MCK_CatchList }, },
  { 8100 /* unreachable */, WebAssembly::DEBUG_UNREACHABLE_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 8100 /* unreachable */, WebAssembly::UNREACHABLE_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 8112 /* v128.and */, WebAssembly::AND_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 8121 /* v128.andnot */, WebAssembly::ANDNOT_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 8133 /* v128.any_true */, WebAssembly::ANYTRUE_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 8147 /* v128.bitselect */, WebAssembly::BITSELECT_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 8162 /* v128.const */, WebAssembly::CONST_V128_I64x2_S, Convert__Imm1_0__Imm1_1, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8162 /* v128.const */, WebAssembly::CONST_V128_F64x2_S, Convert__FPImmf641_0__FPImmf641_1, AMFBS_HasSIMD128, { MCK_FPImmf64, MCK_FPImmf64 }, },
  { 8162 /* v128.const */, WebAssembly::CONST_V128_I32x4_S, Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8162 /* v128.const */, WebAssembly::CONST_V128_F32x4_S, Convert__FPImmf321_0__FPImmf321_1__FPImmf321_2__FPImmf321_3, AMFBS_HasSIMD128, { MCK_FPImmf32, MCK_FPImmf32, MCK_FPImmf32, MCK_FPImmf32 }, },
  { 8162 /* v128.const */, WebAssembly::CONST_V128_I16x8_S, Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3__Imm1_4__Imm1_5__Imm1_6__Imm1_7, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8162 /* v128.const */, WebAssembly::CONST_V128_I8x16_S, Convert__Imm1_0__Imm1_1__Imm1_2__Imm1_3__Imm1_4__Imm1_5__Imm1_6__Imm1_7__Imm1_8__Imm1_9__Imm1_10__Imm1_11__Imm1_12__Imm1_13__Imm1_14__Imm1_15, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8173 /* v128.load */, WebAssembly::LOAD_V128_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8173 /* v128.load */, WebAssembly::LOAD_V128_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8183 /* v128.load16_lane */, WebAssembly::LOAD_LANE_16_A32_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8183 /* v128.load16_lane */, WebAssembly::LOAD_LANE_16_A64_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8200 /* v128.load16_splat */, WebAssembly::LOAD16_SPLAT_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8200 /* v128.load16_splat */, WebAssembly::LOAD16_SPLAT_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8218 /* v128.load32_lane */, WebAssembly::LOAD_LANE_32_A32_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8218 /* v128.load32_lane */, WebAssembly::LOAD_LANE_32_A64_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8235 /* v128.load32_splat */, WebAssembly::LOAD32_SPLAT_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8235 /* v128.load32_splat */, WebAssembly::LOAD32_SPLAT_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8253 /* v128.load32_zero */, WebAssembly::LOAD_ZERO_32_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8253 /* v128.load32_zero */, WebAssembly::LOAD_ZERO_32_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8270 /* v128.load64_lane */, WebAssembly::LOAD_LANE_64_A32_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8270 /* v128.load64_lane */, WebAssembly::LOAD_LANE_64_A64_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8287 /* v128.load64_splat */, WebAssembly::LOAD64_SPLAT_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8287 /* v128.load64_splat */, WebAssembly::LOAD64_SPLAT_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8305 /* v128.load64_zero */, WebAssembly::LOAD_ZERO_64_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8305 /* v128.load64_zero */, WebAssembly::LOAD_ZERO_64_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8322 /* v128.load8_lane */, WebAssembly::LOAD_LANE_8_A32_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8322 /* v128.load8_lane */, WebAssembly::LOAD_LANE_8_A64_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8338 /* v128.load8_splat */, WebAssembly::LOAD8_SPLAT_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8338 /* v128.load8_splat */, WebAssembly::LOAD8_SPLAT_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8355 /* v128.not */, WebAssembly::NOT_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 8364 /* v128.or */, WebAssembly::OR_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
  { 8372 /* v128.select */, WebAssembly::SELECT_V128_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 8384 /* v128.store */, WebAssembly::STORE_V128_A32_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8384 /* v128.store */, WebAssembly::STORE_V128_A64_S, Convert__Imm1_1__Imm1_0, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm }, },
  { 8395 /* v128.store16_lane */, WebAssembly::STORE_LANE_I16x8_A32_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8395 /* v128.store16_lane */, WebAssembly::STORE_LANE_I16x8_A64_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8413 /* v128.store32_lane */, WebAssembly::STORE_LANE_I32x4_A32_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8413 /* v128.store32_lane */, WebAssembly::STORE_LANE_I32x4_A64_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8431 /* v128.store64_lane */, WebAssembly::STORE_LANE_I64x2_A32_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8431 /* v128.store64_lane */, WebAssembly::STORE_LANE_I64x2_A64_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8449 /* v128.store8_lane */, WebAssembly::STORE_LANE_I8x16_A32_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8449 /* v128.store8_lane */, WebAssembly::STORE_LANE_I8x16_A64_S, Convert__Imm1_1__Imm1_0__Imm1_2, AMFBS_HasSIMD128, { MCK_Imm, MCK_Imm, MCK_Imm }, },
  { 8466 /* v128.xor */, WebAssembly::XOR_S, Convert_NoOperands, AMFBS_HasSIMD128, {  }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned WebAssemblyAsmParser::
MatchInstructionImpl(const OperandVector &Operands,
                     MCInst &Inst,
                     uint64_t &ErrorInfo,
                     FeatureBitset &MissingFeatures,
                     bool matchingInlineAsm, unsigned VariantID) {
  // Eliminate obvious mismatches.
  if (Operands.size() > 17) {
    ErrorInfo = 17;
    return Match_InvalidOperand;
  }

  // Get the current feature set.
  const FeatureBitset &AvailableFeatures = getAvailableFeatures();

  // Get the instruction mnemonic, which is the first token.
  StringRef Mnemonic = ((WebAssemblyOperand &)*Operands[0]).getToken();

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
    for (unsigned FormalIdx = 0; FormalIdx != 16; ++FormalIdx) {
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

static std::string WebAssemblyMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool WebAssemblyCheckMnemonic(StringRef Mnemonic,
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

