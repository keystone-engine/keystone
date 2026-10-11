/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: M68k.td                                                              *|
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
  Feature_AtLeastM68000Bit = 0,
  Feature_AtLeastM68010Bit = 1,
  Feature_AtLeastM68020Bit = 2,
  Feature_AtLeastM68040Bit = 3,
  Feature_AtLeastM68060Bit = 4,
  Feature_AtLeastM68881Bit = 5,
  Feature_AtLeastM68882Bit = 6,
};

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_AtLeastM68000Bit: return "";
  case Feature_AtLeastM68010Bit: return "";
  case Feature_AtLeastM68020Bit: return "";
  case Feature_AtLeastM68040Bit: return "";
  case Feature_AtLeastM68060Bit: return "";
  case Feature_AtLeastM68881Bit: return "";
  case Feature_AtLeastM68882Bit: return "";
  default: return "(unknown)";
  }
}

#endif // GET_SUBTARGET_FEATURE_NAME


#ifdef GET_MATCHER_IMPLEMENTATION
#undef GET_MATCHER_IMPLEMENTATION

enum {
  Tie0_1_1,
};

static const uint8_t TiedAsmOperandTable[][3] = {
  /* Tie0_1_1 */ { 0, 1, 1 },
};

namespace {
enum OperatorConversionKind {
  CVT_Done,
  CVT_Reg,
  CVT_Tied,
  CVT_imm_95_0,
  CVT_95_addRegOperands,
  CVT_95_addARIOperands,
  CVT_95_addARIDOperands,
  CVT_95_addARIIOperands,
  CVT_95_addImmOperands,
  CVT_95_addPCDOperands,
  CVT_95_addPCIOperands,
  CVT_95_addAddrOperands,
  CVT_95_addARIPDOperands,
  CVT_95_addARIPIOperands,
  CVT_95_addPCIBDOperands,
  CVT_95_Reg,
  CVT_95_addMoveMaskOperands,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__imm_95_0__imm_95_0,
  Convert__imm_95_0__imm_95_0__imm_95_0__imm_95_0,
  Convert__imm_95_0,
  Convert__DReg1_1__Tie0_1_1__ARI1_0,
  Convert__DReg1_1__Tie0_1_1__ARID2_0,
  Convert__DReg1_1__Tie0_1_1__ARII3_0,
  Convert__ARI1_1__MxImm1_0,
  Convert__ARID2_1__MxImm1_0,
  Convert__ARII3_1__MxImm1_0,
  Convert__DReg1_1__Tie0_1_1__MxImm1_0,
  Convert__DReg1_1__Tie0_1_1__PCD1_0,
  Convert__DReg1_1__Tie0_1_1__PCI2_0,
  Convert__ARI1_1__DReg1_0,
  Convert__ARID2_1__DReg1_0,
  Convert__ARII3_1__DReg1_0,
  Convert__DReg1_1__Tie0_1_1__DReg1_0,
  Convert__DReg1_1__Tie0_1_1__Reg1_0,
  Convert__AReg1_1__Tie0_1_1__ARI1_0,
  Convert__AReg1_1__Tie0_1_1__ARID2_0,
  Convert__AReg1_1__Tie0_1_1__ARII3_0,
  Convert__AReg1_1__Tie0_1_1__Addr321_0,
  Convert__AReg1_1__Tie0_1_1__MxImm1_0,
  Convert__AReg1_1__Tie0_1_1__PCD1_0,
  Convert__AReg1_1__Tie0_1_1__PCI2_0,
  Convert__AReg1_1__Tie0_1_1__Reg1_0,
  Convert__Addr81_0,
  Convert__Addr161_0,
  Convert__Addr321_0,
  Convert__ARIPD1_1__MxImm1_0,
  Convert__ARIPI1_1__MxImm1_0,
  Convert__DReg1_1__MxImm1_0,
  Convert__ARIPD1_1__DReg1_0,
  Convert__ARIPI1_1__DReg1_0,
  Convert__DReg1_1__DReg1_0,
  Convert__MxBkptImm1_0,
  Convert__PCD1_1__MxImm1_0,
  Convert__PCI2_1__MxImm1_0,
  Convert__PCD1_1__DReg1_0,
  Convert__PCI2_1__DReg1_0,
  Convert__DReg1_0__Tie0_1_1__DReg1_1__ARI1_2,
  Convert__DReg1_0__Tie0_1_1__DReg1_1__ARID2_2,
  Convert__DReg1_0__Tie0_1_1__DReg1_1__ARII3_2,
  Convert__DReg1_0__Tie0_1_1__DReg1_1__Addr81_2,
  Convert__DReg1_0__Tie0_1_1__DReg1_1__Addr321_2,
  Convert__DReg1_0__Tie0_1_1__DReg1_1__Addr161_2,
  Convert__DReg1_1__ARI1_0,
  Convert__DReg1_1__ARID2_0,
  Convert__DReg1_1__ARII3_0,
  Convert__DReg1_1__PCD1_0,
  Convert__DReg1_1__PCI2_0,
  Convert__DReg1_0__DReg1_1,
  Convert__Reg1_0__DReg1_1,
  Convert__MxImm1_0__ARI1_1,
  Convert__MxImm1_0__ARID2_1,
  Convert__MxImm1_0__ARII3_1,
  Convert__MxImm1_0__Addr321_1,
  Convert__MxImm1_0__PCD1_1,
  Convert__MxImm1_0__PCI2_1,
  Convert__MxImm1_0__DReg1_1,
  Convert__DReg1_0__Tie0_1_1,
  Convert__FPDReg1_1__FPDReg1_0,
  Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0,
  Convert__FPCReg1_1__AReg1_0,
  Convert__FPCReg1_1__DReg1_0,
  Convert__AReg1_1__FPCReg1_0,
  Convert__DReg1_1__FPCReg1_0,
  Convert_NoOperands,
  Convert__ARI1_0,
  Convert__ARID2_0,
  Convert__ARII3_0,
  Convert__PCD1_0,
  Convert__PCI2_0,
  Convert__PCIBD323_0,
  Convert__AReg1_1__ARID2_0,
  Convert__AReg1_1__ARII3_0,
  Convert__AReg1_1__Addr321_0,
  Convert__AReg1_1__PCD1_0,
  Convert__AReg1_1__PCI2_0,
  Convert__AReg1_1__PCIBD163_0,
  Convert__AReg1_1__PCIBD323_0,
  Convert__AReg1_0__MxImm1_1,
  Convert__ARI1_1__ARI1_0,
  Convert__ARID2_1__ARI1_0,
  Convert__ARII3_1__ARI1_0,
  Convert__ARIPD1_1__ARI1_0,
  Convert__ARIPI1_1__ARI1_0,
  Convert__Addr81_1__ARI1_0,
  Convert__ARI1_1__ARID2_0,
  Convert__ARID2_1__ARID2_0,
  Convert__ARII3_1__ARID2_0,
  Convert__ARIPD1_1__ARID2_0,
  Convert__ARIPI1_1__ARID2_0,
  Convert__Addr81_1__ARID2_0,
  Convert__ARI1_1__ARII3_0,
  Convert__ARID2_1__ARII3_0,
  Convert__ARII3_1__ARII3_0,
  Convert__ARIPD1_1__ARII3_0,
  Convert__ARIPI1_1__ARII3_0,
  Convert__Addr81_1__ARII3_0,
  Convert__ARI1_1__ARIPD1_0,
  Convert__ARID2_1__ARIPD1_0,
  Convert__ARII3_1__ARIPD1_0,
  Convert__ARIPD1_1__ARIPD1_0,
  Convert__ARIPI1_1__ARIPD1_0,
  Convert__Addr81_1__ARIPD1_0,
  Convert__DReg1_1__ARIPD1_0,
  Convert__ARI1_1__ARIPI1_0,
  Convert__ARID2_1__ARIPI1_0,
  Convert__ARII3_1__ARIPI1_0,
  Convert__ARIPD1_1__ARIPI1_0,
  Convert__ARIPI1_1__ARIPI1_0,
  Convert__Addr81_1__ARIPI1_0,
  Convert__DReg1_1__ARIPI1_0,
  Convert__ARI1_1__Addr81_0,
  Convert__ARID2_1__Addr81_0,
  Convert__ARII3_1__Addr81_0,
  Convert__ARIPD1_1__Addr81_0,
  Convert__ARIPI1_1__Addr81_0,
  Convert__Addr81_1__Addr81_0,
  Convert__DReg1_1__Addr81_0,
  Convert__Addr81_1__MxImm1_0,
  Convert__ARI1_1__PCD1_0,
  Convert__ARID2_1__PCD1_0,
  Convert__ARII3_1__PCD1_0,
  Convert__ARIPD1_1__PCD1_0,
  Convert__ARIPI1_1__PCD1_0,
  Convert__Addr81_1__PCD1_0,
  Convert__ARI1_1__PCI2_0,
  Convert__ARID2_1__PCI2_0,
  Convert__ARII3_1__PCI2_0,
  Convert__ARIPD1_1__PCI2_0,
  Convert__ARIPI1_1__PCI2_0,
  Convert__Addr81_1__PCI2_0,
  Convert__Addr81_1__DReg1_0,
  Convert__Addr321_1__ARI1_0,
  Convert__AReg1_1__ARI1_0,
  Convert__Reg1_1__ARI1_0,
  Convert__Addr321_1__ARID2_0,
  Convert__Reg1_1__ARID2_0,
  Convert__Addr321_1__ARII3_0,
  Convert__Reg1_1__ARII3_0,
  Convert__Addr321_1__ARIPD1_0,
  Convert__AReg1_1__ARIPD1_0,
  Convert__Reg1_1__ARIPD1_0,
  Convert__Addr321_1__ARIPI1_0,
  Convert__AReg1_1__ARIPI1_0,
  Convert__Reg1_1__ARIPI1_0,
  Convert__ARI1_1__Addr321_0,
  Convert__ARID2_1__Addr321_0,
  Convert__ARII3_1__Addr321_0,
  Convert__ARIPD1_1__Addr321_0,
  Convert__ARIPI1_1__Addr321_0,
  Convert__Addr321_1__Addr321_0,
  Convert__DReg1_1__Addr321_0,
  Convert__Reg1_1__Addr321_0,
  Convert__Addr321_1__MxImm1_0,
  Convert__AReg1_1__MxImm1_0,
  Convert__Reg1_1__MxImm1_0,
  Convert__Addr321_1__PCD1_0,
  Convert__Reg1_1__PCD1_0,
  Convert__Addr321_1__PCI2_0,
  Convert__Reg1_1__PCI2_0,
  Convert__ARI1_1__AReg1_0,
  Convert__ARID2_1__AReg1_0,
  Convert__ARII3_1__AReg1_0,
  Convert__ARIPD1_1__AReg1_0,
  Convert__ARIPI1_1__AReg1_0,
  Convert__Addr321_1__AReg1_0,
  Convert__AReg1_1__AReg1_0,
  Convert__Reg1_1__AReg1_0,
  Convert__Addr321_1__DReg1_0,
  Convert__ARI1_1__Reg1_0,
  Convert__ARID2_1__Reg1_0,
  Convert__ARII3_1__Reg1_0,
  Convert__ARIPD1_1__Reg1_0,
  Convert__ARIPI1_1__Reg1_0,
  Convert__Addr321_1__Reg1_0,
  Convert__AReg1_1__Reg1_0,
  Convert__Reg1_1__Reg1_0,
  Convert__Addr161_1__Reg1_0,
  Convert__DReg1_1__Reg1_0,
  Convert__Addr161_1__ARI1_0,
  Convert__Addr161_1__ARID2_0,
  Convert__Addr161_1__ARII3_0,
  Convert__Addr161_1__ARIPD1_0,
  Convert__Addr161_1__ARIPI1_0,
  Convert__Reg1_1__Addr161_0,
  Convert__ARI1_1__Addr161_0,
  Convert__ARID2_1__Addr161_0,
  Convert__ARII3_1__Addr161_0,
  Convert__ARIPD1_1__Addr161_0,
  Convert__ARIPI1_1__Addr161_0,
  Convert__Addr161_1__Addr161_0,
  Convert__AReg1_1__Addr161_0,
  Convert__DReg1_1__Addr161_0,
  Convert__Addr161_1__MxImm1_0,
  Convert__Addr161_1__PCD1_0,
  Convert__Addr161_1__PCI2_0,
  Convert__Addr161_1__AReg1_0,
  Convert__Reg1_1__DReg1_0,
  Convert__Addr161_1__DReg1_0,
  Convert__MoveMask1_1__ARI1_0,
  Convert__MoveMask1_1__ARID2_0,
  Convert__MoveMask1_1__ARII3_0,
  Convert__MoveMask1_1__ARIPD1_0,
  Convert__MoveMask1_1__ARIPI1_0,
  Convert__MoveMask1_1__Addr321_0,
  Convert__ARI1_1__MoveMask1_0,
  Convert__ARID2_1__MoveMask1_0,
  Convert__ARII3_1__MoveMask1_0,
  Convert__ARIPD1_1__MoveMask1_0,
  Convert__ARIPI1_1__MoveMask1_0,
  Convert__Addr321_1__MoveMask1_0,
  Convert__MoveMask1_1__PCD1_0,
  Convert__MoveMask1_1__PCI2_0,
  Convert__MoveMask1_1__Addr161_0,
  Convert__Addr161_1__MoveMask1_0,
  Convert__DReg1_0,
  Convert__MxTrapImm1_0,
  Convert__AReg1_0,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][9] = {
  // Convert__imm_95_0__imm_95_0
  { CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_0__imm_95_0__imm_95_0__imm_95_0
  { CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_0
  { CVT_imm_95_0, 0, CVT_Done },
  // Convert__DReg1_1__Tie0_1_1__ARI1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__DReg1_1__Tie0_1_1__ARID2_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__DReg1_1__Tie0_1_1__ARII3_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__ARI1_1__MxImm1_0
  { CVT_95_addARIOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__ARID2_1__MxImm1_0
  { CVT_95_addARIDOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__ARII3_1__MxImm1_0
  { CVT_95_addARIIOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__DReg1_1__Tie0_1_1__MxImm1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__DReg1_1__Tie0_1_1__PCD1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__DReg1_1__Tie0_1_1__PCI2_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__ARI1_1__DReg1_0
  { CVT_95_addARIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARID2_1__DReg1_0
  { CVT_95_addARIDOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARII3_1__DReg1_0
  { CVT_95_addARIIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__DReg1_1__Tie0_1_1__DReg1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__DReg1_1__Tie0_1_1__Reg1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__AReg1_1__Tie0_1_1__ARI1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__AReg1_1__Tie0_1_1__ARID2_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__AReg1_1__Tie0_1_1__ARII3_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__AReg1_1__Tie0_1_1__Addr321_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__AReg1_1__Tie0_1_1__MxImm1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__AReg1_1__Tie0_1_1__PCD1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__AReg1_1__Tie0_1_1__PCI2_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__AReg1_1__Tie0_1_1__Reg1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Addr81_0
  { CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Addr161_0
  { CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Addr321_0
  { CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__MxImm1_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__MxImm1_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__DReg1_1__MxImm1_0
  { CVT_95_addRegOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__DReg1_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__DReg1_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__DReg1_1__DReg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__MxBkptImm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__PCD1_1__MxImm1_0
  { CVT_95_addPCDOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__PCI2_1__MxImm1_0
  { CVT_95_addPCIOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__PCD1_1__DReg1_0
  { CVT_95_addPCDOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__PCI2_1__DReg1_0
  { CVT_95_addPCIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__DReg1_0__Tie0_1_1__DReg1_1__ARI1_2
  { CVT_95_addRegOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 2, CVT_95_addARIOperands, 3, CVT_Done },
  // Convert__DReg1_0__Tie0_1_1__DReg1_1__ARID2_2
  { CVT_95_addRegOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 2, CVT_95_addARIDOperands, 3, CVT_Done },
  // Convert__DReg1_0__Tie0_1_1__DReg1_1__ARII3_2
  { CVT_95_addRegOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 2, CVT_95_addARIIOperands, 3, CVT_Done },
  // Convert__DReg1_0__Tie0_1_1__DReg1_1__Addr81_2
  { CVT_95_addRegOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 2, CVT_95_addAddrOperands, 3, CVT_Done },
  // Convert__DReg1_0__Tie0_1_1__DReg1_1__Addr321_2
  { CVT_95_addRegOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 2, CVT_95_addAddrOperands, 3, CVT_Done },
  // Convert__DReg1_0__Tie0_1_1__DReg1_1__Addr161_2
  { CVT_95_addRegOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 2, CVT_95_addAddrOperands, 3, CVT_Done },
  // Convert__DReg1_1__ARI1_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__DReg1_1__ARID2_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__DReg1_1__ARII3_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__DReg1_1__PCD1_0
  { CVT_95_addRegOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__DReg1_1__PCI2_0
  { CVT_95_addRegOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__DReg1_0__DReg1_1
  { CVT_95_addRegOperands, 1, CVT_95_addRegOperands, 2, CVT_Done },
  // Convert__Reg1_0__DReg1_1
  { CVT_95_addRegOperands, 1, CVT_95_addRegOperands, 2, CVT_Done },
  // Convert__MxImm1_0__ARI1_1
  { CVT_95_addImmOperands, 1, CVT_95_addARIOperands, 2, CVT_Done },
  // Convert__MxImm1_0__ARID2_1
  { CVT_95_addImmOperands, 1, CVT_95_addARIDOperands, 2, CVT_Done },
  // Convert__MxImm1_0__ARII3_1
  { CVT_95_addImmOperands, 1, CVT_95_addARIIOperands, 2, CVT_Done },
  // Convert__MxImm1_0__Addr321_1
  { CVT_95_addImmOperands, 1, CVT_95_addAddrOperands, 2, CVT_Done },
  // Convert__MxImm1_0__PCD1_1
  { CVT_95_addImmOperands, 1, CVT_95_addPCDOperands, 2, CVT_Done },
  // Convert__MxImm1_0__PCI2_1
  { CVT_95_addImmOperands, 1, CVT_95_addPCIOperands, 2, CVT_Done },
  // Convert__MxImm1_0__DReg1_1
  { CVT_95_addImmOperands, 1, CVT_95_addRegOperands, 2, CVT_Done },
  // Convert__DReg1_0__Tie0_1_1
  { CVT_95_addRegOperands, 1, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__FPDReg1_1__FPDReg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0
  { CVT_95_addRegOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__FPCReg1_1__AReg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__FPCReg1_1__DReg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__AReg1_1__FPCReg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__DReg1_1__FPCReg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__ARI1_0
  { CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__ARID2_0
  { CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__ARII3_0
  { CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__PCD1_0
  { CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__PCI2_0
  { CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__PCIBD323_0
  { CVT_95_addPCIBDOperands, 1, CVT_Done },
  // Convert__AReg1_1__ARID2_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__AReg1_1__ARII3_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__AReg1_1__Addr321_0
  { CVT_95_addRegOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__AReg1_1__PCD1_0
  { CVT_95_addRegOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__AReg1_1__PCI2_0
  { CVT_95_addRegOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__AReg1_1__PCIBD163_0
  { CVT_95_addRegOperands, 2, CVT_95_addPCIBDOperands, 1, CVT_Done },
  // Convert__AReg1_1__PCIBD323_0
  { CVT_95_addRegOperands, 2, CVT_95_addPCIBDOperands, 1, CVT_Done },
  // Convert__AReg1_0__MxImm1_1
  { CVT_95_addRegOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__ARI1_1__ARI1_0
  { CVT_95_addARIOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__ARID2_1__ARI1_0
  { CVT_95_addARIDOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__ARII3_1__ARI1_0
  { CVT_95_addARIIOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__ARI1_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__ARI1_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__Addr81_1__ARI1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__ARI1_1__ARID2_0
  { CVT_95_addARIOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__ARID2_1__ARID2_0
  { CVT_95_addARIDOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__ARII3_1__ARID2_0
  { CVT_95_addARIIOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__ARID2_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__ARID2_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__Addr81_1__ARID2_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__ARI1_1__ARII3_0
  { CVT_95_addARIOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__ARID2_1__ARII3_0
  { CVT_95_addARIDOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__ARII3_1__ARII3_0
  { CVT_95_addARIIOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__ARII3_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__ARII3_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__Addr81_1__ARII3_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__ARI1_1__ARIPD1_0
  { CVT_95_addARIOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__ARID2_1__ARIPD1_0
  { CVT_95_addARIDOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__ARII3_1__ARIPD1_0
  { CVT_95_addARIIOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__ARIPD1_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__ARIPD1_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__Addr81_1__ARIPD1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__DReg1_1__ARIPD1_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__ARI1_1__ARIPI1_0
  { CVT_95_addARIOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__ARID2_1__ARIPI1_0
  { CVT_95_addARIDOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__ARII3_1__ARIPI1_0
  { CVT_95_addARIIOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__ARIPI1_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__ARIPI1_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__Addr81_1__ARIPI1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__DReg1_1__ARIPI1_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__ARI1_1__Addr81_0
  { CVT_95_addARIOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARID2_1__Addr81_0
  { CVT_95_addARIDOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARII3_1__Addr81_0
  { CVT_95_addARIIOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__Addr81_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__Addr81_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Addr81_1__Addr81_0
  { CVT_95_addAddrOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__DReg1_1__Addr81_0
  { CVT_95_addRegOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Addr81_1__MxImm1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__ARI1_1__PCD1_0
  { CVT_95_addARIOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__ARID2_1__PCD1_0
  { CVT_95_addARIDOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__ARII3_1__PCD1_0
  { CVT_95_addARIIOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__PCD1_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__PCD1_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__Addr81_1__PCD1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__ARI1_1__PCI2_0
  { CVT_95_addARIOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__ARID2_1__PCI2_0
  { CVT_95_addARIDOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__ARII3_1__PCI2_0
  { CVT_95_addARIIOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__PCI2_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__PCI2_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__Addr81_1__PCI2_0
  { CVT_95_addAddrOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__Addr81_1__DReg1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Addr321_1__ARI1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__AReg1_1__ARI1_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__Reg1_1__ARI1_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__Addr321_1__ARID2_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__Reg1_1__ARID2_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__Addr321_1__ARII3_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__Reg1_1__ARII3_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__Addr321_1__ARIPD1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__AReg1_1__ARIPD1_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__Reg1_1__ARIPD1_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__Addr321_1__ARIPI1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__AReg1_1__ARIPI1_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__Reg1_1__ARIPI1_0
  { CVT_95_addRegOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__ARI1_1__Addr321_0
  { CVT_95_addARIOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARID2_1__Addr321_0
  { CVT_95_addARIDOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARII3_1__Addr321_0
  { CVT_95_addARIIOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__Addr321_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__Addr321_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Addr321_1__Addr321_0
  { CVT_95_addAddrOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__DReg1_1__Addr321_0
  { CVT_95_addRegOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Reg1_1__Addr321_0
  { CVT_95_addRegOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Addr321_1__MxImm1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__AReg1_1__MxImm1_0
  { CVT_95_addRegOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__MxImm1_0
  { CVT_95_addRegOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Addr321_1__PCD1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__Reg1_1__PCD1_0
  { CVT_95_addRegOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__Addr321_1__PCI2_0
  { CVT_95_addAddrOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__Reg1_1__PCI2_0
  { CVT_95_addRegOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__ARI1_1__AReg1_0
  { CVT_95_addARIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARID2_1__AReg1_0
  { CVT_95_addARIDOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARII3_1__AReg1_0
  { CVT_95_addARIIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__AReg1_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__AReg1_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Addr321_1__AReg1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__AReg1_1__AReg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_1__AReg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Addr321_1__DReg1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARI1_1__Reg1_0
  { CVT_95_addARIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARID2_1__Reg1_0
  { CVT_95_addARIDOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARII3_1__Reg1_0
  { CVT_95_addARIIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__Reg1_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__Reg1_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Addr321_1__Reg1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__AReg1_1__Reg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_0
  { CVT_95_addRegOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Addr161_1__Reg1_0
  { CVT_95_addAddrOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__DReg1_1__Reg1_0
  { CVT_95_addRegOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Addr161_1__ARI1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__Addr161_1__ARID2_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__Addr161_1__ARII3_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__Addr161_1__ARIPD1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__Addr161_1__ARIPI1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__Reg1_1__Addr161_0
  { CVT_95_Reg, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARI1_1__Addr161_0
  { CVT_95_addARIOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARID2_1__Addr161_0
  { CVT_95_addARIDOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARII3_1__Addr161_0
  { CVT_95_addARIIOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__Addr161_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__Addr161_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Addr161_1__Addr161_0
  { CVT_95_addAddrOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__AReg1_1__Addr161_0
  { CVT_95_addRegOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__DReg1_1__Addr161_0
  { CVT_95_addRegOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Addr161_1__MxImm1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Addr161_1__PCD1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__Addr161_1__PCI2_0
  { CVT_95_addAddrOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__Addr161_1__AReg1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Reg1_1__DReg1_0
  { CVT_95_Reg, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__Addr161_1__DReg1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__MoveMask1_1__ARI1_0
  { CVT_95_addMoveMaskOperands, 2, CVT_95_addARIOperands, 1, CVT_Done },
  // Convert__MoveMask1_1__ARID2_0
  { CVT_95_addMoveMaskOperands, 2, CVT_95_addARIDOperands, 1, CVT_Done },
  // Convert__MoveMask1_1__ARII3_0
  { CVT_95_addMoveMaskOperands, 2, CVT_95_addARIIOperands, 1, CVT_Done },
  // Convert__MoveMask1_1__ARIPD1_0
  { CVT_95_addMoveMaskOperands, 2, CVT_95_addARIPDOperands, 1, CVT_Done },
  // Convert__MoveMask1_1__ARIPI1_0
  { CVT_95_addMoveMaskOperands, 2, CVT_95_addARIPIOperands, 1, CVT_Done },
  // Convert__MoveMask1_1__Addr321_0
  { CVT_95_addMoveMaskOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__ARI1_1__MoveMask1_0
  { CVT_95_addARIOperands, 2, CVT_95_addMoveMaskOperands, 1, CVT_Done },
  // Convert__ARID2_1__MoveMask1_0
  { CVT_95_addARIDOperands, 2, CVT_95_addMoveMaskOperands, 1, CVT_Done },
  // Convert__ARII3_1__MoveMask1_0
  { CVT_95_addARIIOperands, 2, CVT_95_addMoveMaskOperands, 1, CVT_Done },
  // Convert__ARIPD1_1__MoveMask1_0
  { CVT_95_addARIPDOperands, 2, CVT_95_addMoveMaskOperands, 1, CVT_Done },
  // Convert__ARIPI1_1__MoveMask1_0
  { CVT_95_addARIPIOperands, 2, CVT_95_addMoveMaskOperands, 1, CVT_Done },
  // Convert__Addr321_1__MoveMask1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addMoveMaskOperands, 1, CVT_Done },
  // Convert__MoveMask1_1__PCD1_0
  { CVT_95_addMoveMaskOperands, 2, CVT_95_addPCDOperands, 1, CVT_Done },
  // Convert__MoveMask1_1__PCI2_0
  { CVT_95_addMoveMaskOperands, 2, CVT_95_addPCIOperands, 1, CVT_Done },
  // Convert__MoveMask1_1__Addr161_0
  { CVT_95_addMoveMaskOperands, 2, CVT_95_addAddrOperands, 1, CVT_Done },
  // Convert__Addr161_1__MoveMask1_0
  { CVT_95_addAddrOperands, 2, CVT_95_addMoveMaskOperands, 1, CVT_Done },
  // Convert__DReg1_0
  { CVT_95_addRegOperands, 1, CVT_Done },
  // Convert__MxTrapImm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__AReg1_0
  { CVT_95_addRegOperands, 1, CVT_Done },
};

void M68kAsmParser::
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
      static_cast<M68kOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_95_addRegOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addARIOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addARIOperands(Inst, 1);
      break;
    case CVT_95_addARIDOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addARIDOperands(Inst, 2);
      break;
    case CVT_95_addARIIOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addARIIOperands(Inst, 3);
      break;
    case CVT_95_addImmOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_addPCDOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addPCDOperands(Inst, 1);
      break;
    case CVT_95_addPCIOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addPCIOperands(Inst, 2);
      break;
    case CVT_95_addAddrOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addAddrOperands(Inst, 1);
      break;
    case CVT_95_addARIPDOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addARIPDOperands(Inst, 1);
      break;
    case CVT_95_addARIPIOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addARIPIOperands(Inst, 1);
      break;
    case CVT_95_addPCIBDOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addPCIBDOperands(Inst, 3);
      break;
    case CVT_95_Reg:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addMoveMaskOperands:
      static_cast<M68kOperand &>(*Operands[OpIdx]).addMoveMaskOperands(Inst, 1);
      break;
    }
  }
}

void M68kAsmParser::
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
    case CVT_imm_95_0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addRegOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addARIOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addARIDOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 2;
      break;
    case CVT_95_addARIIOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 3;
      break;
    case CVT_95_addImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addPCDOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addPCIOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 2;
      break;
    case CVT_95_addAddrOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addARIPDOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addARIPIOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addPCIBDOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 3;
      break;
    case CVT_95_Reg:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("r");
      NumMCOperands += 1;
      break;
    case CVT_95_addMoveMaskOperands:
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
  MCK_be, // 'be'
  MCK_emitted, // 'emitted'
  MCK_error_COLON_, // 'error:'
  MCK_not, // 'not'
  MCK_should, // 'should'
  MCK_this, // 'this'
  MCK_LAST_TOKEN = MCK_this,
  MCK_CCRC, // register class 'CCRC'
  MCK_FPIC, // register class 'FPIC'
  MCK_PCC, // register class 'PCC'
  MCK_SPC, // register class 'SPC'
  MCK_SRC, // register class 'SRC'
  MCK_AR16_TC, // register class 'AR16_TC,AR32_TC'
  MCK_DR16_TC, // register class 'DR16_TC,DR32_TC'
  MCK_FPCSC, // register class 'FPCSC'
  MCK_FPSYSC, // register class 'FPSYSC'
  MCK_XR16_TC, // register class 'XR16_TC,XR32_TC'
  MCK_AR32_NOSP, // register class 'AR32_NOSP'
  MCK_AR16, // register class 'AR16'
  MCK_AR32, // register class 'AR32'
  MCK_DR16, // register class 'DR16'
  MCK_DR32, // register class 'DR32'
  MCK_DR8, // register class 'DR8'
  MCK_FPDR32, // register class 'FPDR32,FPDR64,FPDR80'
  MCK_SPILL, // register class 'SPILL,SPILL_R,XR32'
  MCK_XR16, // register class 'XR16'
  MCK_LAST_REGISTER = MCK_XR16,
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_ARI, // user defined class 'MxARI'
  MCK_ARID, // user defined class 'MxARID'
  MCK_ARII, // user defined class 'MxARII'
  MCK_ARIPD, // user defined class 'MxARIPD'
  MCK_ARIPI, // user defined class 'MxARIPI'
  MCK_Addr8, // user defined class 'MxAddr8'
  MCK_Addr16, // user defined class 'MxAddr16'
  MCK_Addr32, // user defined class 'MxAddr32'
  MCK_Addr, // user defined class 'MxAddr'
  MCK_MxBkptImm, // user defined class 'MxBkptImm'
  MCK_MxImm, // user defined class 'MxImm'
  MCK_MoveMask, // user defined class 'MxMoveMaskClass'
  MCK_PCD, // user defined class 'MxPCD'
  MCK_PCI, // user defined class 'MxPCI'
  MCK_PCIBD16, // user defined class 'MxPCIBD16Class'
  MCK_PCIBD32, // user defined class 'MxPCIBD32Class'
  MCK_AReg, // user defined class 'MxARegClass'
  MCK_DReg, // user defined class 'MxDRegClass'
  MCK_FPCReg, // user defined class 'MxFPCRegClass'
  MCK_FPDReg, // user defined class 'MxFPDRegClass'
  MCK_Reg, // user defined class 'MxRegClass'
  MCK_MxTrapImm, // user defined class 'MxTrapImm'
  NumMatchClassKinds
};

} // end anonymous namespace

static unsigned getDiagKindFromRegisterClass(MatchClassKind RegisterClass) {
  return MCTargetAsmParser::Match_InvalidOperand;
}

static MatchClassKind matchTokenString(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 1 string to match.
    if (memcmp(Name.data()+0, "be", 2) != 0)
      break;
    return MCK_be;	 // "be"
  case 3:	 // 1 string to match.
    if (memcmp(Name.data()+0, "not", 3) != 0)
      break;
    return MCK_not;	 // "not"
  case 4:	 // 1 string to match.
    if (memcmp(Name.data()+0, "this", 4) != 0)
      break;
    return MCK_this;	 // "this"
  case 6:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case 'e':	 // 1 string to match.
      if (memcmp(Name.data()+1, "rror:", 5) != 0)
        break;
      return MCK_error_COLON_;	 // "error:"
    case 's':	 // 1 string to match.
      if (memcmp(Name.data()+1, "hould", 5) != 0)
        break;
      return MCK_should;	 // "should"
    }
    break;
  case 7:	 // 1 string to match.
    if (memcmp(Name.data()+0, "emitted", 7) != 0)
      break;
    return MCK_emitted;	 // "emitted"
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
    {0, 16, 1},
    {1, 0, 0},
    {1, 20, 6},
    {7, 0, 0},
    {7, 17, 9},
    {16, 17, 9},
    {25, 16, 1},
    {26, 0, 0},
    {26, 25, 1},
    {27, 20, 6},
    {33, 26, 1},
    {34, 25, 1},
    {35, 26, 1},
    {36, 25, 1},
    {37, 0, 0},
    {37, 0, 0},
    {37, 0, 0},
    {37, 0, 0},
    {37, 0, 0},
    {37, 0, 0},
    {37, 0, 0},
    {37, 0, 0},
    {37, 0, 0},
    {37, 0, 0},
    {37, 34, 3},
    {40, 35, 2},
    {42, 36, 1},
    {43, 0, 0},
    {43, 0, 0},
    {43, 0, 0},
    {43, 0, 0},
    {43, 0, 0},
    {43, 0, 0},
    {43, 43, 1},
    {44, 0, 0},
    {44, 48, 1},
    {45, 48, 1},
    {46, 48, 1},
    {47, 48, 1},
    {48, 0, 0},
    {48, 0, 0},
  };

  static constexpr uint8_t Data[] = {
    0xC3,
    0x85,
    0x21,
    0x0F,
    0xFF,
    0xFF,
  };

  auto &Entry = Table[A];
  unsigned Idx = B - Entry.Start;
  if (Idx >= Entry.Length)
    return false;
  Idx += Entry.Offset;
  return (Data[Idx / 8] >> (Idx % 8)) & 1;
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind, const MCSubtargetInfo &STI) {
  M68kOperand &Operand = (M68kOperand &)GOp;
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
  case MCK_ARI: {
    DiagnosticPredicate DP(Operand.isARI());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_ARID: {
    DiagnosticPredicate DP(Operand.isARID());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_ARII: {
    DiagnosticPredicate DP(Operand.isARII());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_ARIPD: {
    DiagnosticPredicate DP(Operand.isARIPD());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_ARIPI: {
    DiagnosticPredicate DP(Operand.isARIPI());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Addr8: {
    DiagnosticPredicate DP(Operand.isAddr8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Addr16: {
    DiagnosticPredicate DP(Operand.isAddr16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Addr32: {
    DiagnosticPredicate DP(Operand.isAddr32());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Addr: {
    DiagnosticPredicate DP(Operand.isAddr());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MxBkptImm: {
    DiagnosticPredicate DP(Operand.isBkptImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MxImm: {
    DiagnosticPredicate DP(Operand.isImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MoveMask: {
    DiagnosticPredicate DP(Operand.isMoveMask());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_PCD: {
    DiagnosticPredicate DP(Operand.isPCD());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_PCI: {
    DiagnosticPredicate DP(Operand.isPCI());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_PCIBD16: {
    DiagnosticPredicate DP(Operand.isPCIBD16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_PCIBD32: {
    DiagnosticPredicate DP(Operand.isPCIBD32());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_AReg: {
    DiagnosticPredicate DP(Operand.isAReg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DReg: {
    DiagnosticPredicate DP(Operand.isDReg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_FPCReg: {
    DiagnosticPredicate DP(Operand.isFPCReg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_FPDReg: {
    DiagnosticPredicate DP(Operand.isFPDReg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Reg: {
    DiagnosticPredicate DP(Operand.isReg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MxTrapImm: {
    DiagnosticPredicate DP(Operand.isTrapImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg()) {
    static constexpr uint16_t Table[M68k::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      MCK_CCRC,
      MCK_FPCSC,
      MCK_FPIC,
      MCK_FPCSC,
      MCK_PCC,
      MCK_SPC,
      MCK_SRC,
      MCK_AR16,
      MCK_AR16_TC,
      MCK_AR16_TC,
      MCK_AR32_NOSP,
      MCK_AR32_NOSP,
      MCK_AR32_NOSP,
      MCK_AR32_NOSP,
      MCK_AR32_NOSP,
      MCK_DR8,
      MCK_DR8,
      MCK_DR8,
      MCK_DR8,
      MCK_DR8,
      MCK_DR8,
      MCK_DR8,
      MCK_DR8,
      MCK_DR16_TC,
      MCK_DR16_TC,
      MCK_DR32,
      MCK_DR32,
      MCK_DR32,
      MCK_DR32,
      MCK_DR32,
      MCK_DR32,
      MCK_FPDR32,
      MCK_FPDR32,
      MCK_FPDR32,
      MCK_FPDR32,
      MCK_FPDR32,
      MCK_FPDR32,
      MCK_FPDR32,
      MCK_FPDR32,
      MCK_AR16,
      MCK_AR16,
      MCK_AR16,
      MCK_AR16,
      MCK_AR16,
      MCK_AR16,
      MCK_AR16,
      MCK_DR16,
      MCK_DR16,
      MCK_DR16,
      MCK_DR16,
      MCK_DR16,
      MCK_DR16,
      MCK_DR16,
      MCK_DR16,
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
  case MCK_be: return "MCK_be";
  case MCK_emitted: return "MCK_emitted";
  case MCK_error_COLON_: return "MCK_error_COLON_";
  case MCK_not: return "MCK_not";
  case MCK_should: return "MCK_should";
  case MCK_this: return "MCK_this";
  case MCK_CCRC: return "MCK_CCRC";
  case MCK_FPIC: return "MCK_FPIC";
  case MCK_PCC: return "MCK_PCC";
  case MCK_SPC: return "MCK_SPC";
  case MCK_SRC: return "MCK_SRC";
  case MCK_AR16_TC: return "MCK_AR16_TC";
  case MCK_DR16_TC: return "MCK_DR16_TC";
  case MCK_FPCSC: return "MCK_FPCSC";
  case MCK_FPSYSC: return "MCK_FPSYSC";
  case MCK_XR16_TC: return "MCK_XR16_TC";
  case MCK_AR32_NOSP: return "MCK_AR32_NOSP";
  case MCK_AR16: return "MCK_AR16";
  case MCK_AR32: return "MCK_AR32";
  case MCK_DR16: return "MCK_DR16";
  case MCK_DR32: return "MCK_DR32";
  case MCK_DR8: return "MCK_DR8";
  case MCK_FPDR32: return "MCK_FPDR32";
  case MCK_SPILL: return "MCK_SPILL";
  case MCK_XR16: return "MCK_XR16";
  case MCK_Imm: return "MCK_Imm";
  case MCK_ARI: return "MCK_ARI";
  case MCK_ARID: return "MCK_ARID";
  case MCK_ARII: return "MCK_ARII";
  case MCK_ARIPD: return "MCK_ARIPD";
  case MCK_ARIPI: return "MCK_ARIPI";
  case MCK_Addr8: return "MCK_Addr8";
  case MCK_Addr16: return "MCK_Addr16";
  case MCK_Addr32: return "MCK_Addr32";
  case MCK_Addr: return "MCK_Addr";
  case MCK_MxBkptImm: return "MCK_MxBkptImm";
  case MCK_MxImm: return "MCK_MxImm";
  case MCK_MoveMask: return "MCK_MoveMask";
  case MCK_PCD: return "MCK_PCD";
  case MCK_PCI: return "MCK_PCI";
  case MCK_PCIBD16: return "MCK_PCIBD16";
  case MCK_PCIBD32: return "MCK_PCIBD32";
  case MCK_AReg: return "MCK_AReg";
  case MCK_DReg: return "MCK_DReg";
  case MCK_FPCReg: return "MCK_FPCReg";
  case MCK_FPDReg: return "MCK_FPDReg";
  case MCK_Reg: return "MCK_Reg";
  case MCK_MxTrapImm: return "MCK_MxTrapImm";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset M68kAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  if (FB[M68k::FeatureISA00])
    Features.set(Feature_AtLeastM68000Bit);
  if (FB[M68k::FeatureISA10])
    Features.set(Feature_AtLeastM68010Bit);
  if (FB[M68k::FeatureISA20])
    Features.set(Feature_AtLeastM68020Bit);
  if (FB[M68k::FeatureISA40])
    Features.set(Feature_AtLeastM68040Bit);
  if (FB[M68k::FeatureISA60])
    Features.set(Feature_AtLeastM68060Bit);
  if (FB[M68k::FeatureISA881])
    Features.set(Feature_AtLeastM68881Bit);
  if (FB[M68k::FeatureISA882])
    Features.set(Feature_AtLeastM68882Bit);
  return Features;
}

static bool checkAsmTiedOperandConstraints(const M68kAsmParser&AsmParser,
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
    "\001;\005add.b\005add.l\005add.w\006adda.l\006addx.b\006addx.l\006addx."
    "w\005and.b\005and.l\005and.w\005asr.b\005asr.l\005asr.w\003bcc\004bchg\004"
    "bclr\003bcs\003beq\003bge\003bgt\003bhi\004bkpt\003ble\003bls\003blt\003"
    "bmi\003bne\003bpl\003bra\004bset\005bsr.b\005bsr.l\005bsr.w\004btst\003"
    "bvc\003bvs\005cas.b\005cas.l\005cas.w\005cmp.b\005cmp.l\005cmp.w\006cmp"
    "i.b\006cmpi.l\006cmpi.w\004divs\006divs.l\004divu\006divu.l\005eor.b\005"
    "eor.l\005eor.w\006eori.b\006eori.l\006eori.w\005ext.l\005ext.w\006fabs."
    "x\006fadd.x\007fdabs.x\007fdadd.x\007fddiv.x\006fdiv.x\010fdmove.x\007f"
    "dmul.x\007fdneg.x\007fdsub.x\007fmove.l\007fmove.x\006fmul.x\006fneg.x\007"
    "fsabs.x\007fsadd.x\007fsdiv.x\010fsmove.x\007fsmul.x\007fsneg.x\007fssu"
    "b.x\006fsub.x\007illegal\003jmp\003jsr\003lea\006link.l\006link.w\005ls"
    "l.b\005lsl.l\005lsl.w\005lsr.b\005lsr.l\005lsr.w\006move.b\006move.l\006"
    "move.w\007movem.l\007movem.w\005moveq\004muls\006muls.l\004mulu\006mulu"
    ".l\005neg.b\005neg.l\005neg.w\006negx.b\006negx.l\006negx.w\003nop\005n"
    "ot.b\005not.l\005not.w\004or.b\004or.l\004or.w\005rol.b\005rol.l\005rol"
    ".w\005ror.b\005ror.l\005ror.w\003rte\003rts\003scc\003scs\003seq\002sf\003"
    "sge\003sgt\003shi\003sle\003sls\003slt\003smi\003sne\003spl\002st\005su"
    "b.b\005sub.l\005sub.w\006suba.l\006subx.b\006subx.l\006subx.w\003svc\003"
    "svs\004trap\005trapv\004unlk";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
  AMFBS_AtLeastM68010,
  AMFBS_AtLeastM68020,
  AMFBS_AtLeastM68040,
  AMFBS_AtLeastM68881,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
  {Feature_AtLeastM68010Bit, }, // AMFBS_AtLeastM68010
  {Feature_AtLeastM68020Bit, }, // AMFBS_AtLeastM68020
  {Feature_AtLeastM68040Bit, }, // AMFBS_AtLeastM68040
  {Feature_AtLeastM68881Bit, }, // AMFBS_AtLeastM68881
};

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
    uint32_t Opcode;
    uint8_t ConvertFn;
    uint8_t RequiredFeaturesIdx;
    uint8_t Classes[6];
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
  { 0 /* ; */, M68k::ADJCALLSTACKDOWN, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::ADJCALLSTACKUP, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::CMOV16d, Convert__imm_95_0__imm_95_0__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::CMOV32r, Convert__imm_95_0__imm_95_0__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::CMOV8d, Convert__imm_95_0__imm_95_0__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8bc, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8cb, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8ce, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8cf, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8cj, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8ck, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8co, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8cp, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8cq, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8ec, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8fc, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8jc, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8oc, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOV8pc, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVI16ri, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVI32ri, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVI8di, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVM16jm_P, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVM16mj_P, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVM16mp_P, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVM16pm_P, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVM32jm_P, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVM32mj_P, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVM32mp_P, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVM32pm_P, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd16d8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd16f8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd16j8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd16p8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd16q8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32d16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32d8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32f16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32f8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32j16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32j8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32p16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32p8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32q16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVSXd32q8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVXd16d8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVXd32d16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVXd32d8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd16d8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd16f8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd16j8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd16p8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd16q8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32d16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32d8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32f16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32f8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32j16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32j8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32p16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32p8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32q16, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::MOVZXd32q8, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::POP16d, Convert__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::POP32r, Convert__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::POP8d, Convert__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::PUSH16d, Convert__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::PUSH32r, Convert__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::PUSH8d, Convert__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::SALLOCA, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::SETCS_C16d, Convert__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::SETCS_C32d, Convert__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 0 /* ; */, M68k::SETCS_C8d, Convert__imm_95_0, AMFBS_None, { MCK_error_COLON_, MCK_this, MCK_should, MCK_not, MCK_be, MCK_emitted }, },
  { 2 /* add.b */, M68k::ADD8dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 2 /* add.b */, M68k::ADD8dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 2 /* add.b */, M68k::ADD8df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 2 /* add.b */, M68k::ADD8ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 2 /* add.b */, M68k::ADD8pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 2 /* add.b */, M68k::ADD8fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 2 /* add.b */, M68k::ADD8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 2 /* add.b */, M68k::ADD8dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 2 /* add.b */, M68k::ADD8dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 2 /* add.b */, M68k::ADD8jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 2 /* add.b */, M68k::ADD8pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 2 /* add.b */, M68k::ADD8fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 2 /* add.b */, M68k::ADD8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 8 /* add.l */, M68k::ADD32dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 8 /* add.l */, M68k::ADD32dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 8 /* add.l */, M68k::ADD32df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 8 /* add.l */, M68k::ADD32ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 8 /* add.l */, M68k::ADD32pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 8 /* add.l */, M68k::ADD32fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 8 /* add.l */, M68k::ADD32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 8 /* add.l */, M68k::ADD32dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 8 /* add.l */, M68k::ADD32dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 8 /* add.l */, M68k::ADD32jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 8 /* add.l */, M68k::ADD32pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 8 /* add.l */, M68k::ADD32fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 8 /* add.l */, M68k::ADD32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 8 /* add.l */, M68k::ADD32dr, Convert__DReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 14 /* add.w */, M68k::ADD16dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 14 /* add.w */, M68k::ADD16dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 14 /* add.w */, M68k::ADD16df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 14 /* add.w */, M68k::ADD16ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 14 /* add.w */, M68k::ADD16pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 14 /* add.w */, M68k::ADD16fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 14 /* add.w */, M68k::ADD16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 14 /* add.w */, M68k::ADD16dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 14 /* add.w */, M68k::ADD16dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 14 /* add.w */, M68k::ADD16jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 14 /* add.w */, M68k::ADD16pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 14 /* add.w */, M68k::ADD16fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 14 /* add.w */, M68k::ADD16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 14 /* add.w */, M68k::ADD16dr, Convert__DReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 20 /* adda.l */, M68k::ADD32aj, Convert__AReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_AReg }, },
  { 20 /* adda.l */, M68k::ADD32ap, Convert__AReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_AReg }, },
  { 20 /* adda.l */, M68k::ADD32af, Convert__AReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_AReg }, },
  { 20 /* adda.l */, M68k::ADD32ab, Convert__AReg1_1__Tie0_1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_AReg }, },
  { 20 /* adda.l */, M68k::ADD32ai, Convert__AReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_AReg }, },
  { 20 /* adda.l */, M68k::ADD32aq, Convert__AReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_AReg }, },
  { 20 /* adda.l */, M68k::ADD32ak, Convert__AReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_AReg }, },
  { 20 /* adda.l */, M68k::ADD32ar, Convert__AReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_AReg }, },
  { 27 /* addx.b */, M68k::ADDX8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 34 /* addx.l */, M68k::ADDX32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 41 /* addx.w */, M68k::ADDX16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 48 /* and.b */, M68k::AND8dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 48 /* and.b */, M68k::AND8dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 48 /* and.b */, M68k::AND8df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 48 /* and.b */, M68k::AND8ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 48 /* and.b */, M68k::AND8pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 48 /* and.b */, M68k::AND8fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 48 /* and.b */, M68k::AND8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 48 /* and.b */, M68k::AND8dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 48 /* and.b */, M68k::AND8dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 48 /* and.b */, M68k::AND8jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 48 /* and.b */, M68k::AND8pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 48 /* and.b */, M68k::AND8fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 48 /* and.b */, M68k::AND8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 54 /* and.l */, M68k::AND32dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 54 /* and.l */, M68k::AND32dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 54 /* and.l */, M68k::AND32df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 54 /* and.l */, M68k::AND32ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 54 /* and.l */, M68k::AND32pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 54 /* and.l */, M68k::AND32fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 54 /* and.l */, M68k::AND32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 54 /* and.l */, M68k::AND32dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 54 /* and.l */, M68k::AND32dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 54 /* and.l */, M68k::AND32jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 54 /* and.l */, M68k::AND32pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 54 /* and.l */, M68k::AND32fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 54 /* and.l */, M68k::AND32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 54 /* and.l */, M68k::AND32dr, Convert__DReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 60 /* and.w */, M68k::AND16dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 60 /* and.w */, M68k::AND16dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 60 /* and.w */, M68k::AND16df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 60 /* and.w */, M68k::AND16ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 60 /* and.w */, M68k::AND16pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 60 /* and.w */, M68k::AND16fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 60 /* and.w */, M68k::AND16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 60 /* and.w */, M68k::AND16dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 60 /* and.w */, M68k::AND16dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 60 /* and.w */, M68k::AND16jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 60 /* and.w */, M68k::AND16pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 60 /* and.w */, M68k::AND16fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 60 /* and.w */, M68k::AND16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 60 /* and.w */, M68k::AND16dr, Convert__DReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 66 /* asr.b */, M68k::ASR8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 66 /* asr.b */, M68k::ASR8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 72 /* asr.l */, M68k::ASR32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 72 /* asr.l */, M68k::ASR32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 78 /* asr.w */, M68k::ASR16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 78 /* asr.w */, M68k::ASR16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 84 /* bcc */, M68k::Bcc8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 84 /* bcc */, M68k::Bcc16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 84 /* bcc */, M68k::Bcc32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 88 /* bchg */, M68k::BCHG8ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 88 /* bchg */, M68k::BCHG8pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 88 /* bchg */, M68k::BCHG8fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 88 /* bchg */, M68k::BCHG8ei, Convert__ARIPD1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPD }, },
  { 88 /* bchg */, M68k::BCHG8oi, Convert__ARIPI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPI }, },
  { 88 /* bchg */, M68k::BCHG32di, Convert__DReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 88 /* bchg */, M68k::BCHG8jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 88 /* bchg */, M68k::BCHG8pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 88 /* bchg */, M68k::BCHG8fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 88 /* bchg */, M68k::BCHG8ed, Convert__ARIPD1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPD }, },
  { 88 /* bchg */, M68k::BCHG8od, Convert__ARIPI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPI }, },
  { 88 /* bchg */, M68k::BCHG32dd, Convert__DReg1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 93 /* bclr */, M68k::BCLR8ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 93 /* bclr */, M68k::BCLR8pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 93 /* bclr */, M68k::BCLR8fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 93 /* bclr */, M68k::BCLR8ei, Convert__ARIPD1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPD }, },
  { 93 /* bclr */, M68k::BCLR8oi, Convert__ARIPI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPI }, },
  { 93 /* bclr */, M68k::BCLR32di, Convert__DReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 93 /* bclr */, M68k::BCLR8jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 93 /* bclr */, M68k::BCLR8pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 93 /* bclr */, M68k::BCLR8fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 93 /* bclr */, M68k::BCLR8ed, Convert__ARIPD1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPD }, },
  { 93 /* bclr */, M68k::BCLR8od, Convert__ARIPI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPI }, },
  { 93 /* bclr */, M68k::BCLR32dd, Convert__DReg1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 98 /* bcs */, M68k::Bcs8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 98 /* bcs */, M68k::Bcs16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 98 /* bcs */, M68k::Bcs32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 102 /* beq */, M68k::Beq8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 102 /* beq */, M68k::Beq16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 102 /* beq */, M68k::Beq32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 106 /* bge */, M68k::Bge8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 106 /* bge */, M68k::Bge16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 106 /* bge */, M68k::Bge32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 110 /* bgt */, M68k::Bgt8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 110 /* bgt */, M68k::Bgt16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 110 /* bgt */, M68k::Bgt32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 114 /* bhi */, M68k::Bhi8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 114 /* bhi */, M68k::Bhi16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 114 /* bhi */, M68k::Bhi32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 118 /* bkpt */, M68k::BKPT, Convert__MxBkptImm1_0, AMFBS_None, { MCK_MxBkptImm }, },
  { 123 /* ble */, M68k::Ble8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 123 /* ble */, M68k::Ble16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 123 /* ble */, M68k::Ble32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 127 /* bls */, M68k::Bls8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 127 /* bls */, M68k::Bls16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 127 /* bls */, M68k::Bls32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 131 /* blt */, M68k::Blt8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 131 /* blt */, M68k::Blt16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 131 /* blt */, M68k::Blt32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 135 /* bmi */, M68k::Bmi8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 135 /* bmi */, M68k::Bmi16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 135 /* bmi */, M68k::Bmi32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 139 /* bne */, M68k::Bne8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 139 /* bne */, M68k::Bne16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 139 /* bne */, M68k::Bne32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 143 /* bpl */, M68k::Bpl8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 143 /* bpl */, M68k::Bpl16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 143 /* bpl */, M68k::Bpl32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 147 /* bra */, M68k::BRA8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 147 /* bra */, M68k::BRA16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 147 /* bra */, M68k::BRA32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 151 /* bset */, M68k::BSET8ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 151 /* bset */, M68k::BSET8pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 151 /* bset */, M68k::BSET8fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 151 /* bset */, M68k::BSET8ei, Convert__ARIPD1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPD }, },
  { 151 /* bset */, M68k::BSET8oi, Convert__ARIPI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPI }, },
  { 151 /* bset */, M68k::BSET32di, Convert__DReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 151 /* bset */, M68k::BSET8jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 151 /* bset */, M68k::BSET8pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 151 /* bset */, M68k::BSET8fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 151 /* bset */, M68k::BSET8ed, Convert__ARIPD1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPD }, },
  { 151 /* bset */, M68k::BSET8od, Convert__ARIPI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPI }, },
  { 151 /* bset */, M68k::BSET32dd, Convert__DReg1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 156 /* bsr.b */, M68k::BSR8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 162 /* bsr.l */, M68k::BSR32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 168 /* bsr.w */, M68k::BSR16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 174 /* btst */, M68k::BTST8ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 174 /* btst */, M68k::BTST8pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 174 /* btst */, M68k::BTST8fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 174 /* btst */, M68k::BTST8ei, Convert__ARIPD1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPD }, },
  { 174 /* btst */, M68k::BTST8oi, Convert__ARIPI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPI }, },
  { 174 /* btst */, M68k::BTST8qi, Convert__PCD1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_PCD }, },
  { 174 /* btst */, M68k::BTST8ki, Convert__PCI2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_PCI }, },
  { 174 /* btst */, M68k::BTST32di, Convert__DReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 174 /* btst */, M68k::BTST8jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 174 /* btst */, M68k::BTST8pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 174 /* btst */, M68k::BTST8fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 174 /* btst */, M68k::BTST8ed, Convert__ARIPD1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPD }, },
  { 174 /* btst */, M68k::BTST8od, Convert__ARIPI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPI }, },
  { 174 /* btst */, M68k::BTST8qd, Convert__PCD1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_PCD }, },
  { 174 /* btst */, M68k::BTST8kd, Convert__PCI2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_PCI }, },
  { 174 /* btst */, M68k::BTST32dd, Convert__DReg1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 179 /* bvc */, M68k::Bvc8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 179 /* bvc */, M68k::Bvc16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 179 /* bvc */, M68k::Bvc32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 183 /* bvs */, M68k::Bvs8, Convert__Addr81_0, AMFBS_None, { MCK_Addr8 }, },
  { 183 /* bvs */, M68k::Bvs16, Convert__Addr161_0, AMFBS_None, { MCK_Addr16 }, },
  { 183 /* bvs */, M68k::Bvs32, Convert__Addr321_0, AMFBS_AtLeastM68020, { MCK_Addr32 }, },
  { 187 /* cas.b */, M68k::CASARI8, Convert__DReg1_0__Tie0_1_1__DReg1_1__ARI1_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_ARI }, },
  { 187 /* cas.b */, M68k::CASARID8, Convert__DReg1_0__Tie0_1_1__DReg1_1__ARID2_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_ARID }, },
  { 187 /* cas.b */, M68k::CASARII8, Convert__DReg1_0__Tie0_1_1__DReg1_1__ARII3_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_ARII }, },
  { 187 /* cas.b */, M68k::CASAL8, Convert__DReg1_0__Tie0_1_1__DReg1_1__Addr81_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_Addr8 }, },
  { 193 /* cas.l */, M68k::CASARI32, Convert__DReg1_0__Tie0_1_1__DReg1_1__ARI1_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_ARI }, },
  { 193 /* cas.l */, M68k::CASARID32, Convert__DReg1_0__Tie0_1_1__DReg1_1__ARID2_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_ARID }, },
  { 193 /* cas.l */, M68k::CASARII32, Convert__DReg1_0__Tie0_1_1__DReg1_1__ARII3_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_ARII }, },
  { 193 /* cas.l */, M68k::CASAL32, Convert__DReg1_0__Tie0_1_1__DReg1_1__Addr321_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_Addr32 }, },
  { 199 /* cas.w */, M68k::CASARI16, Convert__DReg1_0__Tie0_1_1__DReg1_1__ARI1_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_ARI }, },
  { 199 /* cas.w */, M68k::CASARID16, Convert__DReg1_0__Tie0_1_1__DReg1_1__ARID2_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_ARID }, },
  { 199 /* cas.w */, M68k::CASARII16, Convert__DReg1_0__Tie0_1_1__DReg1_1__ARII3_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_ARII }, },
  { 199 /* cas.w */, M68k::CASAL16, Convert__DReg1_0__Tie0_1_1__DReg1_1__Addr161_2, AMFBS_AtLeastM68020, { MCK_DReg, MCK_DReg, MCK_Addr16 }, },
  { 205 /* cmp.b */, M68k::CMP8dj, Convert__DReg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 205 /* cmp.b */, M68k::CMP8dp, Convert__DReg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 205 /* cmp.b */, M68k::CMP8df, Convert__DReg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 205 /* cmp.b */, M68k::CMP8dq, Convert__DReg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 205 /* cmp.b */, M68k::CMP8dk, Convert__DReg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 205 /* cmp.b */, M68k::CMP8dd, Convert__DReg1_0__DReg1_1, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 211 /* cmp.l */, M68k::CMP32dj, Convert__DReg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 211 /* cmp.l */, M68k::CMP32dp, Convert__DReg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 211 /* cmp.l */, M68k::CMP32df, Convert__DReg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 211 /* cmp.l */, M68k::CMP32dq, Convert__DReg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 211 /* cmp.l */, M68k::CMP32dk, Convert__DReg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 211 /* cmp.l */, M68k::CMP32dr, Convert__Reg1_0__DReg1_1, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 217 /* cmp.w */, M68k::CMP16dj, Convert__DReg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 217 /* cmp.w */, M68k::CMP16dp, Convert__DReg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 217 /* cmp.w */, M68k::CMP16df, Convert__DReg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 217 /* cmp.w */, M68k::CMP16dq, Convert__DReg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 217 /* cmp.w */, M68k::CMP16dk, Convert__DReg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 217 /* cmp.w */, M68k::CMP16dr, Convert__Reg1_0__DReg1_1, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 223 /* cmpi.b */, M68k::CMP8ji, Convert__MxImm1_0__ARI1_1, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 223 /* cmpi.b */, M68k::CMP8pi, Convert__MxImm1_0__ARID2_1, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 223 /* cmpi.b */, M68k::CMP8fi, Convert__MxImm1_0__ARII3_1, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 223 /* cmpi.b */, M68k::CMP8bi, Convert__MxImm1_0__Addr321_1, AMFBS_None, { MCK_MxImm, MCK_Addr32 }, },
  { 223 /* cmpi.b */, M68k::CMP8qi, Convert__MxImm1_0__PCD1_1, AMFBS_None, { MCK_MxImm, MCK_PCD }, },
  { 223 /* cmpi.b */, M68k::CMP8ki, Convert__MxImm1_0__PCI2_1, AMFBS_None, { MCK_MxImm, MCK_PCI }, },
  { 223 /* cmpi.b */, M68k::CMP8di, Convert__MxImm1_0__DReg1_1, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 230 /* cmpi.l */, M68k::CMP32ji, Convert__MxImm1_0__ARI1_1, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 230 /* cmpi.l */, M68k::CMP32pi, Convert__MxImm1_0__ARID2_1, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 230 /* cmpi.l */, M68k::CMP32fi, Convert__MxImm1_0__ARII3_1, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 230 /* cmpi.l */, M68k::CMP32bi, Convert__MxImm1_0__Addr321_1, AMFBS_None, { MCK_MxImm, MCK_Addr32 }, },
  { 230 /* cmpi.l */, M68k::CMP32qi, Convert__MxImm1_0__PCD1_1, AMFBS_None, { MCK_MxImm, MCK_PCD }, },
  { 230 /* cmpi.l */, M68k::CMP32ki, Convert__MxImm1_0__PCI2_1, AMFBS_None, { MCK_MxImm, MCK_PCI }, },
  { 230 /* cmpi.l */, M68k::CMP32di, Convert__MxImm1_0__DReg1_1, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 237 /* cmpi.w */, M68k::CMP16ji, Convert__MxImm1_0__ARI1_1, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 237 /* cmpi.w */, M68k::CMP16pi, Convert__MxImm1_0__ARID2_1, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 237 /* cmpi.w */, M68k::CMP16fi, Convert__MxImm1_0__ARII3_1, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 237 /* cmpi.w */, M68k::CMP16bi, Convert__MxImm1_0__Addr321_1, AMFBS_None, { MCK_MxImm, MCK_Addr32 }, },
  { 237 /* cmpi.w */, M68k::CMP16qi, Convert__MxImm1_0__PCD1_1, AMFBS_None, { MCK_MxImm, MCK_PCD }, },
  { 237 /* cmpi.w */, M68k::CMP16ki, Convert__MxImm1_0__PCI2_1, AMFBS_None, { MCK_MxImm, MCK_PCI }, },
  { 237 /* cmpi.w */, M68k::CMP16di, Convert__MxImm1_0__DReg1_1, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 244 /* divs */, M68k::SDIVd32i16, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 244 /* divs */, M68k::SDIVd32d16, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 249 /* divs.l */, M68k::SDIVd32d32, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 256 /* divu */, M68k::UDIVd32i16, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 256 /* divu */, M68k::UDIVd32d16, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 261 /* divu.l */, M68k::UDIVd32d32, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 268 /* eor.b */, M68k::XOR8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 274 /* eor.l */, M68k::XOR32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 280 /* eor.w */, M68k::XOR16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 286 /* eori.b */, M68k::XOR8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 293 /* eori.l */, M68k::XOR32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 300 /* eori.w */, M68k::XOR16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 307 /* ext.l */, M68k::EXT32, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 313 /* ext.w */, M68k::EXT16, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 319 /* fabs.x */, M68k::FABS80fp_fp, Convert__FPDReg1_1__FPDReg1_0, AMFBS_AtLeastM68881, { MCK_FPDReg, MCK_FPDReg }, },
  { 326 /* fadd.x */, M68k::FADD80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68881, { MCK_FPDReg, MCK_FPDReg }, },
  { 333 /* fdabs.x */, M68k::FDABS80fp_fp, Convert__FPDReg1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 341 /* fdadd.x */, M68k::FDADD80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 349 /* fddiv.x */, M68k::FDDIV80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 357 /* fdiv.x */, M68k::FDIV80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68881, { MCK_FPDReg, MCK_FPDReg }, },
  { 364 /* fdmove.x */, M68k::FDMOV80fp_fp, Convert__FPDReg1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 373 /* fdmul.x */, M68k::FDMUL80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 381 /* fdneg.x */, M68k::FDNEG80fp_fp, Convert__FPDReg1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 389 /* fdsub.x */, M68k::FDSUB80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 397 /* fmove.l */, M68k::FMOVE32fpi_a, Convert__FPCReg1_1__AReg1_0, AMFBS_AtLeastM68881, { MCK_AReg, MCK_FPCReg }, },
  { 397 /* fmove.l */, M68k::FMOVE32fpcs_d, Convert__FPCReg1_1__DReg1_0, AMFBS_AtLeastM68881, { MCK_DReg, MCK_FPCReg }, },
  { 397 /* fmove.l */, M68k::FMOVE32a_fpi, Convert__AReg1_1__FPCReg1_0, AMFBS_AtLeastM68881, { MCK_FPCReg, MCK_AReg }, },
  { 397 /* fmove.l */, M68k::FMOVE32d_fpcs, Convert__DReg1_1__FPCReg1_0, AMFBS_AtLeastM68881, { MCK_FPCReg, MCK_DReg }, },
  { 405 /* fmove.x */, M68k::FMOV80fp_fp, Convert__FPDReg1_1__FPDReg1_0, AMFBS_AtLeastM68881, { MCK_FPDReg, MCK_FPDReg }, },
  { 413 /* fmul.x */, M68k::FMUL80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68881, { MCK_FPDReg, MCK_FPDReg }, },
  { 420 /* fneg.x */, M68k::FNEG80fp_fp, Convert__FPDReg1_1__FPDReg1_0, AMFBS_AtLeastM68881, { MCK_FPDReg, MCK_FPDReg }, },
  { 427 /* fsabs.x */, M68k::FSABS80fp_fp, Convert__FPDReg1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 435 /* fsadd.x */, M68k::FSADD80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 443 /* fsdiv.x */, M68k::FSDIV80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 451 /* fsmove.x */, M68k::FSMOV80fp_fp, Convert__FPDReg1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 460 /* fsmul.x */, M68k::FSMUL80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 468 /* fsneg.x */, M68k::FSNEG80fp_fp, Convert__FPDReg1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 476 /* fssub.x */, M68k::FSSUB80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68040, { MCK_FPDReg, MCK_FPDReg }, },
  { 484 /* fsub.x */, M68k::FSUB80fp_fp, Convert__FPDReg1_1__Tie0_1_1__FPDReg1_0, AMFBS_AtLeastM68881, { MCK_FPDReg, MCK_FPDReg }, },
  { 491 /* illegal */, M68k::ILLEGAL, Convert_NoOperands, AMFBS_None, {  }, },
  { 499 /* jmp */, M68k::JMP32j, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 503 /* jsr */, M68k::CALLj, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 503 /* jsr */, M68k::CALLp, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 503 /* jsr */, M68k::CALLf, Convert__ARII3_0, AMFBS_None, { MCK_ARII }, },
  { 503 /* jsr */, M68k::CALLb, Convert__Addr321_0, AMFBS_None, { MCK_Addr32 }, },
  { 503 /* jsr */, M68k::CALLq, Convert__PCD1_0, AMFBS_None, { MCK_PCD }, },
  { 503 /* jsr */, M68k::CALLk, Convert__PCI2_0, AMFBS_None, { MCK_PCI }, },
  { 503 /* jsr */, M68k::CALLl, Convert__PCIBD323_0, AMFBS_None, { MCK_PCIBD32 }, },
  { 507 /* lea */, M68k::LEA32p, Convert__AReg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_AReg }, },
  { 507 /* lea */, M68k::LEA32f, Convert__AReg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_AReg }, },
  { 507 /* lea */, M68k::LEA32b, Convert__AReg1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_AReg }, },
  { 507 /* lea */, M68k::LEA32q, Convert__AReg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_AReg }, },
  { 507 /* lea */, M68k::LEA32k, Convert__AReg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_AReg }, },
  { 507 /* lea */, M68k::LEA32L, Convert__AReg1_1__PCIBD163_0, AMFBS_None, { MCK_PCIBD16, MCK_AReg }, },
  { 507 /* lea */, M68k::LEA32l, Convert__AReg1_1__PCIBD323_0, AMFBS_None, { MCK_PCIBD32, MCK_AReg }, },
  { 511 /* link.l */, M68k::LINK32, Convert__AReg1_0__MxImm1_1, AMFBS_None, { MCK_AReg, MCK_MxImm }, },
  { 518 /* link.w */, M68k::LINK16, Convert__AReg1_0__MxImm1_1, AMFBS_None, { MCK_AReg, MCK_MxImm }, },
  { 525 /* lsl.b */, M68k::SHL8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 525 /* lsl.b */, M68k::SHL8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 531 /* lsl.l */, M68k::SHL32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 531 /* lsl.l */, M68k::SHL32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 537 /* lsl.w */, M68k::SHL16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 537 /* lsl.w */, M68k::SHL16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 543 /* lsr.b */, M68k::LSR8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 543 /* lsr.b */, M68k::LSR8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 549 /* lsr.l */, M68k::LSR32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 549 /* lsr.l */, M68k::LSR32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 555 /* lsr.w */, M68k::LSR16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 555 /* lsr.w */, M68k::LSR16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8jj, Convert__ARI1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8pj, Convert__ARID2_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8fj, Convert__ARII3_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8ej, Convert__ARIPD1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8oj, Convert__ARIPI1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8bj, Convert__Addr81_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8dj, Convert__DReg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8jp, Convert__ARI1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8pp, Convert__ARID2_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8fp, Convert__ARII3_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8ep, Convert__ARIPD1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8op, Convert__ARIPI1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8bp, Convert__Addr81_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8dp, Convert__DReg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8jf, Convert__ARI1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8pf, Convert__ARID2_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8ff, Convert__ARII3_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8ef, Convert__ARIPD1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8of, Convert__ARIPI1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8bf, Convert__Addr81_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8df, Convert__DReg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8je, Convert__ARI1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8pe, Convert__ARID2_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8fe, Convert__ARII3_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8ee, Convert__ARIPD1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8oe, Convert__ARIPI1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8be, Convert__Addr81_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8de, Convert__DReg1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8jo, Convert__ARI1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8po, Convert__ARID2_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8fo, Convert__ARII3_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8eo, Convert__ARIPD1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8oo, Convert__ARIPI1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8bo, Convert__Addr81_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8do, Convert__DReg1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8jb, Convert__ARI1_1__Addr81_0, AMFBS_None, { MCK_Addr8, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8pb, Convert__ARID2_1__Addr81_0, AMFBS_None, { MCK_Addr8, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8fb, Convert__ARII3_1__Addr81_0, AMFBS_None, { MCK_Addr8, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8eb, Convert__ARIPD1_1__Addr81_0, AMFBS_None, { MCK_Addr8, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8ob, Convert__ARIPI1_1__Addr81_0, AMFBS_None, { MCK_Addr8, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8bb, Convert__Addr81_1__Addr81_0, AMFBS_None, { MCK_Addr8, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8db, Convert__DReg1_1__Addr81_0, AMFBS_None, { MCK_Addr8, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8ei, Convert__ARIPD1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8oi, Convert__ARIPI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8bi, Convert__Addr81_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8di, Convert__DReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8jq, Convert__ARI1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8pq, Convert__ARID2_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8fq, Convert__ARII3_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8eq, Convert__ARIPD1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8oq, Convert__ARIPI1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8bq, Convert__Addr81_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8dq, Convert__DReg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8jk, Convert__ARI1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8pk, Convert__ARID2_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8fk, Convert__ARII3_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8ek, Convert__ARIPD1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8ok, Convert__ARIPI1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8bk, Convert__Addr81_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8dk, Convert__DReg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 561 /* move.b */, M68k::MOV8jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 561 /* move.b */, M68k::MOV8pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 561 /* move.b */, M68k::MOV8fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 561 /* move.b */, M68k::MOV8ed, Convert__ARIPD1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPD }, },
  { 561 /* move.b */, M68k::MOV8od, Convert__ARIPI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPI }, },
  { 561 /* move.b */, M68k::MOV8bd, Convert__Addr81_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_Addr8 }, },
  { 561 /* move.b */, M68k::MOV8dd, Convert__DReg1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32jj, Convert__ARI1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pj, Convert__ARID2_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fj, Convert__ARII3_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32ej, Convert__ARIPD1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32oj, Convert__ARIPI1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32bj, Convert__Addr321_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32aj, Convert__AReg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32dj, Convert__DReg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32rj, Convert__Reg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32jp, Convert__ARI1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pp, Convert__ARID2_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fp, Convert__ARII3_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32ep, Convert__ARIPD1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32op, Convert__ARIPI1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32bp, Convert__Addr321_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32ap, Convert__AReg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32dp, Convert__DReg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32rp, Convert__Reg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32jf, Convert__ARI1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pf, Convert__ARID2_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32ff, Convert__ARII3_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32ef, Convert__ARIPD1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32of, Convert__ARIPI1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32bf, Convert__Addr321_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32af, Convert__AReg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32df, Convert__DReg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32rf, Convert__Reg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32je, Convert__ARI1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pe, Convert__ARID2_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fe, Convert__ARII3_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32ee, Convert__ARIPD1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32oe, Convert__ARIPI1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32be, Convert__Addr321_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32ae, Convert__AReg1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32de, Convert__DReg1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32re, Convert__Reg1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32jo, Convert__ARI1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32po, Convert__ARID2_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fo, Convert__ARII3_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32eo, Convert__ARIPD1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32oo, Convert__ARIPI1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32bo, Convert__Addr321_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32ao, Convert__AReg1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32do, Convert__DReg1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32ro, Convert__Reg1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32jb, Convert__ARI1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pb, Convert__ARID2_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fb, Convert__ARII3_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32eb, Convert__ARIPD1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32ob, Convert__ARIPI1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32bb, Convert__Addr321_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32ab, Convert__AReg1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32db, Convert__DReg1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32rb, Convert__Reg1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32ei, Convert__ARIPD1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32oi, Convert__ARIPI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32bi, Convert__Addr321_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32ai, Convert__AReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32di, Convert__DReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32ri, Convert__Reg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32jq, Convert__ARI1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pq, Convert__ARID2_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fq, Convert__ARII3_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32eq, Convert__ARIPD1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32oq, Convert__ARIPI1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32bq, Convert__Addr321_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32aq, Convert__AReg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32dq, Convert__DReg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32rq, Convert__Reg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32jk, Convert__ARI1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pk, Convert__ARID2_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fk, Convert__ARII3_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32ek, Convert__ARIPD1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32ok, Convert__ARIPI1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32bk, Convert__Addr321_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32ak, Convert__AReg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32dk, Convert__DReg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32rk, Convert__Reg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32ja, Convert__ARI1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pa, Convert__ARID2_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fa, Convert__ARII3_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32ea, Convert__ARIPD1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32oa, Convert__ARIPI1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32ba, Convert__Addr321_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32aa, Convert__AReg1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32ra, Convert__Reg1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_Reg }, },
  { 568 /* move.l */, M68k::MOV32jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32ed, Convert__ARIPD1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32od, Convert__ARIPI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32bd, Convert__Addr321_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32dd, Convert__DReg1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 568 /* move.l */, M68k::MOV32jr, Convert__ARI1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARI }, },
  { 568 /* move.l */, M68k::MOV32pr, Convert__ARID2_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARID }, },
  { 568 /* move.l */, M68k::MOV32fr, Convert__ARII3_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARII }, },
  { 568 /* move.l */, M68k::MOV32er, Convert__ARIPD1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARIPD }, },
  { 568 /* move.l */, M68k::MOV32or, Convert__ARIPI1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARIPI }, },
  { 568 /* move.l */, M68k::MOV32br, Convert__Addr321_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_Addr32 }, },
  { 568 /* move.l */, M68k::MOV32ar, Convert__AReg1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_AReg }, },
  { 568 /* move.l */, M68k::MOV32rr, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16jc, Convert__ARI1_1__Reg1_0, AMFBS_AtLeastM68010, { MCK_CCRC, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pc, Convert__ARID2_1__Reg1_0, AMFBS_AtLeastM68010, { MCK_CCRC, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fc, Convert__ARII3_1__Reg1_0, AMFBS_AtLeastM68010, { MCK_CCRC, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16ec, Convert__ARIPD1_1__Reg1_0, AMFBS_AtLeastM68010, { MCK_CCRC, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16oc, Convert__ARIPI1_1__Reg1_0, AMFBS_AtLeastM68010, { MCK_CCRC, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bc, Convert__Addr161_1__Reg1_0, AMFBS_AtLeastM68010, { MCK_CCRC, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16dc, Convert__DReg1_1__Reg1_0, AMFBS_AtLeastM68010, { MCK_CCRC, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16js, Convert__ARI1_1__Reg1_0, AMFBS_None, { MCK_SRC, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16ps, Convert__ARID2_1__Reg1_0, AMFBS_None, { MCK_SRC, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fs, Convert__ARII3_1__Reg1_0, AMFBS_None, { MCK_SRC, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16es, Convert__ARIPD1_1__Reg1_0, AMFBS_None, { MCK_SRC, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16os, Convert__ARIPI1_1__Reg1_0, AMFBS_None, { MCK_SRC, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bs, Convert__Addr161_1__Reg1_0, AMFBS_None, { MCK_SRC, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16ds, Convert__DReg1_1__Reg1_0, AMFBS_None, { MCK_SRC, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16cj, Convert__Reg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_CCRC }, },
  { 575 /* move.w */, M68k::MOV16sj, Convert__Reg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_SRC }, },
  { 575 /* move.w */, M68k::MOV16jj, Convert__ARI1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pj, Convert__ARID2_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fj, Convert__ARII3_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16ej, Convert__ARIPD1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16oj, Convert__ARIPI1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bj, Convert__Addr161_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16aj, Convert__AReg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16dj, Convert__DReg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16rj, Convert__Reg1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16cp, Convert__Reg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_CCRC }, },
  { 575 /* move.w */, M68k::MOV16sp, Convert__Reg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_SRC }, },
  { 575 /* move.w */, M68k::MOV16jp, Convert__ARI1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pp, Convert__ARID2_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fp, Convert__ARII3_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16ep, Convert__ARIPD1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16op, Convert__ARIPI1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bp, Convert__Addr161_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16ap, Convert__AReg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16dp, Convert__DReg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16rp, Convert__Reg1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16cf, Convert__Reg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_CCRC }, },
  { 575 /* move.w */, M68k::MOV16sf, Convert__Reg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_SRC }, },
  { 575 /* move.w */, M68k::MOV16jf, Convert__ARI1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pf, Convert__ARID2_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16ff, Convert__ARII3_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16ef, Convert__ARIPD1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16of, Convert__ARIPI1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bf, Convert__Addr161_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16af, Convert__AReg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16df, Convert__DReg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16rf, Convert__Reg1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16ce, Convert__Reg1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_CCRC }, },
  { 575 /* move.w */, M68k::MOV16se, Convert__Reg1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_SRC }, },
  { 575 /* move.w */, M68k::MOV16je, Convert__ARI1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pe, Convert__ARID2_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fe, Convert__ARII3_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16ee, Convert__ARIPD1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16oe, Convert__ARIPI1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16be, Convert__Addr161_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16ae, Convert__AReg1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16de, Convert__DReg1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16re, Convert__Reg1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16co, Convert__Reg1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_CCRC }, },
  { 575 /* move.w */, M68k::MOV16so, Convert__Reg1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_SRC }, },
  { 575 /* move.w */, M68k::MOV16jo, Convert__ARI1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16po, Convert__ARID2_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fo, Convert__ARII3_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16eo, Convert__ARIPD1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16oo, Convert__ARIPI1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bo, Convert__Addr161_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16ao, Convert__AReg1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16do, Convert__DReg1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16ro, Convert__Reg1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16cb, Convert__Reg1_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_CCRC }, },
  { 575 /* move.w */, M68k::MOV16sb, Convert__Reg1_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_SRC }, },
  { 575 /* move.w */, M68k::MOV16jb, Convert__ARI1_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pb, Convert__ARID2_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fb, Convert__ARII3_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16eb, Convert__ARIPD1_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16ob, Convert__ARIPI1_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bb, Convert__Addr161_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16ab, Convert__AReg1_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16db, Convert__DReg1_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16rb, Convert__Reg1_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16ei, Convert__ARIPD1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16oi, Convert__ARIPI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bi, Convert__Addr161_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16ai, Convert__AReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16di, Convert__DReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16ri, Convert__Reg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16cq, Convert__Reg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_CCRC }, },
  { 575 /* move.w */, M68k::MOV16sq, Convert__Reg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_SRC }, },
  { 575 /* move.w */, M68k::MOV16jq, Convert__ARI1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pq, Convert__ARID2_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fq, Convert__ARII3_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16eq, Convert__ARIPD1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16oq, Convert__ARIPI1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bq, Convert__Addr161_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16aq, Convert__AReg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16dq, Convert__DReg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16rq, Convert__Reg1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16ck, Convert__Reg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_CCRC }, },
  { 575 /* move.w */, M68k::MOV16sk, Convert__Reg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_SRC }, },
  { 575 /* move.w */, M68k::MOV16jk, Convert__ARI1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pk, Convert__ARID2_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fk, Convert__ARII3_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16ek, Convert__ARIPD1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16ok, Convert__ARIPI1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bk, Convert__Addr161_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16ak, Convert__AReg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16dk, Convert__DReg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16rk, Convert__Reg1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16ja, Convert__ARI1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pa, Convert__ARID2_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fa, Convert__ARII3_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16ea, Convert__ARIPD1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16oa, Convert__ARIPI1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16ba, Convert__Addr161_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16aa, Convert__AReg1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16ra, Convert__Reg1_1__AReg1_0, AMFBS_None, { MCK_AReg, MCK_Reg }, },
  { 575 /* move.w */, M68k::MOV16cd, Convert__Reg1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_CCRC }, },
  { 575 /* move.w */, M68k::MOV16sd, Convert__Reg1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_SRC }, },
  { 575 /* move.w */, M68k::MOV16jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16ed, Convert__ARIPD1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16od, Convert__ARIPI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16bd, Convert__Addr161_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16dd, Convert__DReg1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 575 /* move.w */, M68k::MOV16jr, Convert__ARI1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARI }, },
  { 575 /* move.w */, M68k::MOV16pr, Convert__ARID2_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARID }, },
  { 575 /* move.w */, M68k::MOV16fr, Convert__ARII3_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARII }, },
  { 575 /* move.w */, M68k::MOV16er, Convert__ARIPD1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARIPD }, },
  { 575 /* move.w */, M68k::MOV16or, Convert__ARIPI1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_ARIPI }, },
  { 575 /* move.w */, M68k::MOV16br, Convert__Addr161_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_Addr16 }, },
  { 575 /* move.w */, M68k::MOV16ar, Convert__AReg1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_AReg }, },
  { 575 /* move.w */, M68k::MOV16rr, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_Reg }, },
  { 582 /* movem.l */, M68k::MOVM32mj, Convert__MoveMask1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_MoveMask }, },
  { 582 /* movem.l */, M68k::MOVM32mp, Convert__MoveMask1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_MoveMask }, },
  { 582 /* movem.l */, M68k::MOVM32mf, Convert__MoveMask1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_MoveMask }, },
  { 582 /* movem.l */, M68k::MOVM32me, Convert__MoveMask1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_MoveMask }, },
  { 582 /* movem.l */, M68k::MOVM32mo, Convert__MoveMask1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_MoveMask }, },
  { 582 /* movem.l */, M68k::MOVM32mb, Convert__MoveMask1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_MoveMask }, },
  { 582 /* movem.l */, M68k::MOVM32jm, Convert__ARI1_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARI }, },
  { 582 /* movem.l */, M68k::MOVM32pm, Convert__ARID2_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARID }, },
  { 582 /* movem.l */, M68k::MOVM32fm, Convert__ARII3_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARII }, },
  { 582 /* movem.l */, M68k::MOVM32em, Convert__ARIPD1_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARIPD }, },
  { 582 /* movem.l */, M68k::MOVM32om, Convert__ARIPI1_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARIPI }, },
  { 582 /* movem.l */, M68k::MOVM32bm, Convert__Addr321_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_Addr32 }, },
  { 582 /* movem.l */, M68k::MOVM32mq, Convert__MoveMask1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_MoveMask }, },
  { 582 /* movem.l */, M68k::MOVM32mk, Convert__MoveMask1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_MoveMask }, },
  { 590 /* movem.w */, M68k::MOVM16mj, Convert__MoveMask1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_MoveMask }, },
  { 590 /* movem.w */, M68k::MOVM16mp, Convert__MoveMask1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_MoveMask }, },
  { 590 /* movem.w */, M68k::MOVM16mf, Convert__MoveMask1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_MoveMask }, },
  { 590 /* movem.w */, M68k::MOVM16me, Convert__MoveMask1_1__ARIPD1_0, AMFBS_None, { MCK_ARIPD, MCK_MoveMask }, },
  { 590 /* movem.w */, M68k::MOVM16mo, Convert__MoveMask1_1__ARIPI1_0, AMFBS_None, { MCK_ARIPI, MCK_MoveMask }, },
  { 590 /* movem.w */, M68k::MOVM16mb, Convert__MoveMask1_1__Addr161_0, AMFBS_None, { MCK_Addr16, MCK_MoveMask }, },
  { 590 /* movem.w */, M68k::MOVM16jm, Convert__ARI1_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARI }, },
  { 590 /* movem.w */, M68k::MOVM16pm, Convert__ARID2_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARID }, },
  { 590 /* movem.w */, M68k::MOVM16fm, Convert__ARII3_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARII }, },
  { 590 /* movem.w */, M68k::MOVM16em, Convert__ARIPD1_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARIPD }, },
  { 590 /* movem.w */, M68k::MOVM16om, Convert__ARIPI1_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_ARIPI }, },
  { 590 /* movem.w */, M68k::MOVM16bm, Convert__Addr161_1__MoveMask1_0, AMFBS_None, { MCK_MoveMask, MCK_Addr16 }, },
  { 590 /* movem.w */, M68k::MOVM16mq, Convert__MoveMask1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_MoveMask }, },
  { 590 /* movem.w */, M68k::MOVM16mk, Convert__MoveMask1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_MoveMask }, },
  { 598 /* moveq */, M68k::MOVQ, Convert__DReg1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 604 /* muls */, M68k::SMULd32i16, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 604 /* muls */, M68k::SMULd32d16, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 609 /* muls.l */, M68k::SMULd32d32, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 616 /* mulu */, M68k::UMULd32i16, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 616 /* mulu */, M68k::UMULd32d16, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 621 /* mulu.l */, M68k::UMULd32d32, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 628 /* neg.b */, M68k::NEG8d, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 634 /* neg.l */, M68k::NEG32d, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 640 /* neg.w */, M68k::NEG16d, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 646 /* negx.b */, M68k::NEGX8d, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 653 /* negx.l */, M68k::NEGX32d, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 660 /* negx.w */, M68k::NEGX16d, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 667 /* nop */, M68k::NOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 671 /* not.b */, M68k::NOT8d, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 677 /* not.l */, M68k::NOT32d, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 683 /* not.w */, M68k::NOT16d, Convert__DReg1_0__Tie0_1_1, AMFBS_None, { MCK_DReg }, },
  { 689 /* or.b */, M68k::OR8dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 689 /* or.b */, M68k::OR8dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 689 /* or.b */, M68k::OR8df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 689 /* or.b */, M68k::OR8ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 689 /* or.b */, M68k::OR8pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 689 /* or.b */, M68k::OR8fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 689 /* or.b */, M68k::OR8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 689 /* or.b */, M68k::OR8dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 689 /* or.b */, M68k::OR8dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 689 /* or.b */, M68k::OR8jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 689 /* or.b */, M68k::OR8pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 689 /* or.b */, M68k::OR8fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 689 /* or.b */, M68k::OR8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 694 /* or.l */, M68k::OR32dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 694 /* or.l */, M68k::OR32dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 694 /* or.l */, M68k::OR32df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 694 /* or.l */, M68k::OR32ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 694 /* or.l */, M68k::OR32pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 694 /* or.l */, M68k::OR32fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 694 /* or.l */, M68k::OR32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 694 /* or.l */, M68k::OR32dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 694 /* or.l */, M68k::OR32dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 694 /* or.l */, M68k::OR32jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 694 /* or.l */, M68k::OR32pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 694 /* or.l */, M68k::OR32fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 694 /* or.l */, M68k::OR32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 694 /* or.l */, M68k::OR32dr, Convert__DReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 699 /* or.w */, M68k::OR16dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 699 /* or.w */, M68k::OR16dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 699 /* or.w */, M68k::OR16df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 699 /* or.w */, M68k::OR16ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 699 /* or.w */, M68k::OR16pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 699 /* or.w */, M68k::OR16fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 699 /* or.w */, M68k::OR16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 699 /* or.w */, M68k::OR16dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 699 /* or.w */, M68k::OR16dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 699 /* or.w */, M68k::OR16jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 699 /* or.w */, M68k::OR16pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 699 /* or.w */, M68k::OR16fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 699 /* or.w */, M68k::OR16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 699 /* or.w */, M68k::OR16dr, Convert__DReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 704 /* rol.b */, M68k::ROL8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 704 /* rol.b */, M68k::ROL8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 710 /* rol.l */, M68k::ROL32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 710 /* rol.l */, M68k::ROL32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 716 /* rol.w */, M68k::ROL16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 716 /* rol.w */, M68k::ROL16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 722 /* ror.b */, M68k::ROR8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 722 /* ror.b */, M68k::ROR8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 728 /* ror.l */, M68k::ROR32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 728 /* ror.l */, M68k::ROR32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 734 /* ror.w */, M68k::ROR16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 734 /* ror.w */, M68k::ROR16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 740 /* rte */, M68k::RTE, Convert_NoOperands, AMFBS_None, {  }, },
  { 744 /* rts */, M68k::RTS, Convert_NoOperands, AMFBS_None, {  }, },
  { 748 /* scc */, M68k::SETj8cc, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 748 /* scc */, M68k::SETp8cc, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 748 /* scc */, M68k::SETd8cc, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 752 /* scs */, M68k::SETj8cs, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 752 /* scs */, M68k::SETp8cs, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 752 /* scs */, M68k::SETd8cs, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 756 /* seq */, M68k::SETj8eq, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 756 /* seq */, M68k::SETp8eq, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 756 /* seq */, M68k::SETd8eq, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 760 /* sf */, M68k::SETj8f, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 760 /* sf */, M68k::SETp8f, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 760 /* sf */, M68k::SETd8f, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 763 /* sge */, M68k::SETj8ge, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 763 /* sge */, M68k::SETp8ge, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 763 /* sge */, M68k::SETd8ge, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 767 /* sgt */, M68k::SETj8gt, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 767 /* sgt */, M68k::SETp8gt, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 767 /* sgt */, M68k::SETd8gt, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 771 /* shi */, M68k::SETj8hi, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 771 /* shi */, M68k::SETp8hi, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 771 /* shi */, M68k::SETd8hi, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 775 /* sle */, M68k::SETj8le, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 775 /* sle */, M68k::SETp8le, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 775 /* sle */, M68k::SETd8le, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 779 /* sls */, M68k::SETj8ls, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 779 /* sls */, M68k::SETp8ls, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 779 /* sls */, M68k::SETd8ls, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 783 /* slt */, M68k::SETj8lt, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 783 /* slt */, M68k::SETp8lt, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 783 /* slt */, M68k::SETd8lt, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 787 /* smi */, M68k::SETj8mi, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 787 /* smi */, M68k::SETp8mi, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 787 /* smi */, M68k::SETd8mi, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 791 /* sne */, M68k::SETj8ne, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 791 /* sne */, M68k::SETp8ne, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 791 /* sne */, M68k::SETd8ne, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 795 /* spl */, M68k::SETj8pl, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 795 /* spl */, M68k::SETp8pl, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 795 /* spl */, M68k::SETd8pl, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 799 /* st */, M68k::SETj8t, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 799 /* st */, M68k::SETp8t, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 799 /* st */, M68k::SETd8t, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 802 /* sub.b */, M68k::SUB8dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 802 /* sub.b */, M68k::SUB8dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 802 /* sub.b */, M68k::SUB8df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 802 /* sub.b */, M68k::SUB8ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 802 /* sub.b */, M68k::SUB8pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 802 /* sub.b */, M68k::SUB8fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 802 /* sub.b */, M68k::SUB8di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 802 /* sub.b */, M68k::SUB8dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 802 /* sub.b */, M68k::SUB8dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 802 /* sub.b */, M68k::SUB8jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 802 /* sub.b */, M68k::SUB8pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 802 /* sub.b */, M68k::SUB8fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 802 /* sub.b */, M68k::SUB8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 808 /* sub.l */, M68k::SUB32dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 808 /* sub.l */, M68k::SUB32dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 808 /* sub.l */, M68k::SUB32df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 808 /* sub.l */, M68k::SUB32ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 808 /* sub.l */, M68k::SUB32pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 808 /* sub.l */, M68k::SUB32fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 808 /* sub.l */, M68k::SUB32di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 808 /* sub.l */, M68k::SUB32dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 808 /* sub.l */, M68k::SUB32dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 808 /* sub.l */, M68k::SUB32jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 808 /* sub.l */, M68k::SUB32pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 808 /* sub.l */, M68k::SUB32fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 808 /* sub.l */, M68k::SUB32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 808 /* sub.l */, M68k::SUB32dr, Convert__DReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 814 /* sub.w */, M68k::SUB16dj, Convert__DReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_DReg }, },
  { 814 /* sub.w */, M68k::SUB16dp, Convert__DReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_DReg }, },
  { 814 /* sub.w */, M68k::SUB16df, Convert__DReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_DReg }, },
  { 814 /* sub.w */, M68k::SUB16ji, Convert__ARI1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARI }, },
  { 814 /* sub.w */, M68k::SUB16pi, Convert__ARID2_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARID }, },
  { 814 /* sub.w */, M68k::SUB16fi, Convert__ARII3_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_ARII }, },
  { 814 /* sub.w */, M68k::SUB16di, Convert__DReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_DReg }, },
  { 814 /* sub.w */, M68k::SUB16dq, Convert__DReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_DReg }, },
  { 814 /* sub.w */, M68k::SUB16dk, Convert__DReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_DReg }, },
  { 814 /* sub.w */, M68k::SUB16jd, Convert__ARI1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARI }, },
  { 814 /* sub.w */, M68k::SUB16pd, Convert__ARID2_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARID }, },
  { 814 /* sub.w */, M68k::SUB16fd, Convert__ARII3_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_ARII }, },
  { 814 /* sub.w */, M68k::SUB16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 814 /* sub.w */, M68k::SUB16dr, Convert__DReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_DReg }, },
  { 820 /* suba.l */, M68k::SUB32aj, Convert__AReg1_1__Tie0_1_1__ARI1_0, AMFBS_None, { MCK_ARI, MCK_AReg }, },
  { 820 /* suba.l */, M68k::SUB32ap, Convert__AReg1_1__Tie0_1_1__ARID2_0, AMFBS_None, { MCK_ARID, MCK_AReg }, },
  { 820 /* suba.l */, M68k::SUB32af, Convert__AReg1_1__Tie0_1_1__ARII3_0, AMFBS_None, { MCK_ARII, MCK_AReg }, },
  { 820 /* suba.l */, M68k::SUB32ab, Convert__AReg1_1__Tie0_1_1__Addr321_0, AMFBS_None, { MCK_Addr32, MCK_AReg }, },
  { 820 /* suba.l */, M68k::SUB32ai, Convert__AReg1_1__Tie0_1_1__MxImm1_0, AMFBS_None, { MCK_MxImm, MCK_AReg }, },
  { 820 /* suba.l */, M68k::SUB32aq, Convert__AReg1_1__Tie0_1_1__PCD1_0, AMFBS_None, { MCK_PCD, MCK_AReg }, },
  { 820 /* suba.l */, M68k::SUB32ak, Convert__AReg1_1__Tie0_1_1__PCI2_0, AMFBS_None, { MCK_PCI, MCK_AReg }, },
  { 820 /* suba.l */, M68k::SUB32ar, Convert__AReg1_1__Tie0_1_1__Reg1_0, AMFBS_None, { MCK_Reg, MCK_AReg }, },
  { 827 /* subx.b */, M68k::SUBX8dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 834 /* subx.l */, M68k::SUBX32dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 841 /* subx.w */, M68k::SUBX16dd, Convert__DReg1_1__Tie0_1_1__DReg1_0, AMFBS_None, { MCK_DReg, MCK_DReg }, },
  { 848 /* svc */, M68k::SETj8vc, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 848 /* svc */, M68k::SETp8vc, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 848 /* svc */, M68k::SETd8vc, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 852 /* svs */, M68k::SETj8vs, Convert__ARI1_0, AMFBS_None, { MCK_ARI }, },
  { 852 /* svs */, M68k::SETp8vs, Convert__ARID2_0, AMFBS_None, { MCK_ARID }, },
  { 852 /* svs */, M68k::SETd8vs, Convert__DReg1_0, AMFBS_None, { MCK_DReg }, },
  { 856 /* trap */, M68k::TRAP, Convert__MxTrapImm1_0, AMFBS_None, { MCK_MxTrapImm }, },
  { 861 /* trapv */, M68k::TRAPV, Convert_NoOperands, AMFBS_None, {  }, },
  { 867 /* unlk */, M68k::UNLK, Convert__AReg1_0, AMFBS_None, { MCK_AReg }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned M68kAsmParser::
MatchInstructionImpl(const OperandVector &Operands,
                     MCInst &Inst,
                     uint64_t &ErrorInfo,
                     FeatureBitset &MissingFeatures,
                     bool matchingInlineAsm, unsigned VariantID) {
  // Eliminate obvious mismatches.
  if (Operands.size() > 7) {
    ErrorInfo = 7;
    return Match_InvalidOperand;
  }

  // Get the current feature set.
  const FeatureBitset &AvailableFeatures = getAvailableFeatures();

  // Get the instruction mnemonic, which is the first token.
  StringRef Mnemonic = ((M68kOperand &)*Operands[0]).getToken();

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
    for (unsigned FormalIdx = 0; FormalIdx != 6; ++FormalIdx) {
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

static const OperandMatchEntry OperandMatchTable[1411] = {
  /* Operand List Mnemonic, Mask, Operand Class, Features */
  { 2 /* add.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 2 /* add.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 2 /* add.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 2 /* add.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 8 /* add.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 14 /* add.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 20 /* adda.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 20 /* adda.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 20 /* adda.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 20 /* adda.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 20 /* adda.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 20 /* adda.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 20 /* adda.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 20 /* adda.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 20 /* adda.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 20 /* adda.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 20 /* adda.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 20 /* adda.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 20 /* adda.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 20 /* adda.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 20 /* adda.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 20 /* adda.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 27 /* addx.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 34 /* addx.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 41 /* addx.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 48 /* and.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 48 /* and.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 54 /* and.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 60 /* and.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 66 /* asr.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 66 /* asr.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 66 /* asr.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 72 /* asr.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 72 /* asr.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 72 /* asr.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 78 /* asr.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 78 /* asr.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 78 /* asr.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 84 /* bcc */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 84 /* bcc */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 84 /* bcc */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 88 /* bchg */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 88 /* bchg */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 88 /* bchg */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 93 /* bclr */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 93 /* bclr */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 93 /* bclr */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 98 /* bcs */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 98 /* bcs */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 98 /* bcs */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 102 /* beq */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 102 /* beq */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 102 /* beq */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 106 /* bge */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 106 /* bge */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 106 /* bge */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 110 /* bgt */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 110 /* bgt */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 110 /* bgt */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 114 /* bhi */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 114 /* bhi */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 114 /* bhi */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 118 /* bkpt */, 1 /* 0 */, MCK_MxBkptImm, AMFBS_None },
  { 123 /* ble */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 123 /* ble */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 123 /* ble */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 127 /* bls */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 127 /* bls */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 127 /* bls */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 131 /* blt */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 131 /* blt */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 131 /* blt */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 135 /* bmi */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 135 /* bmi */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 135 /* bmi */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 139 /* bne */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 139 /* bne */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 139 /* bne */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 143 /* bpl */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 143 /* bpl */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 143 /* bpl */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 147 /* bra */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 147 /* bra */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 147 /* bra */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 151 /* bset */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 151 /* bset */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 151 /* bset */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 151 /* bset */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 156 /* bsr.b */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 162 /* bsr.l */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 168 /* bsr.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_PCD, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_PCI, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_PCD, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 174 /* btst */, 2 /* 1 */, MCK_PCI, AMFBS_None },
  { 174 /* btst */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 174 /* btst */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 179 /* bvc */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 179 /* bvc */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 179 /* bvc */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 183 /* bvs */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 183 /* bvs */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 183 /* bvs */, 1 /* 0 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 187 /* cas.b */, 4 /* 2 */, MCK_ARI, AMFBS_AtLeastM68020 },
  { 187 /* cas.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 187 /* cas.b */, 4 /* 2 */, MCK_ARID, AMFBS_AtLeastM68020 },
  { 187 /* cas.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 187 /* cas.b */, 4 /* 2 */, MCK_ARII, AMFBS_AtLeastM68020 },
  { 187 /* cas.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 187 /* cas.b */, 4 /* 2 */, MCK_Addr8, AMFBS_AtLeastM68020 },
  { 187 /* cas.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 193 /* cas.l */, 4 /* 2 */, MCK_ARI, AMFBS_AtLeastM68020 },
  { 193 /* cas.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 193 /* cas.l */, 4 /* 2 */, MCK_ARID, AMFBS_AtLeastM68020 },
  { 193 /* cas.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 193 /* cas.l */, 4 /* 2 */, MCK_ARII, AMFBS_AtLeastM68020 },
  { 193 /* cas.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 193 /* cas.l */, 4 /* 2 */, MCK_Addr32, AMFBS_AtLeastM68020 },
  { 193 /* cas.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 199 /* cas.w */, 4 /* 2 */, MCK_ARI, AMFBS_AtLeastM68020 },
  { 199 /* cas.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 199 /* cas.w */, 4 /* 2 */, MCK_ARID, AMFBS_AtLeastM68020 },
  { 199 /* cas.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 199 /* cas.w */, 4 /* 2 */, MCK_ARII, AMFBS_AtLeastM68020 },
  { 199 /* cas.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 199 /* cas.w */, 4 /* 2 */, MCK_Addr16, AMFBS_AtLeastM68020 },
  { 199 /* cas.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_AtLeastM68020 },
  { 205 /* cmp.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 205 /* cmp.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 205 /* cmp.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 205 /* cmp.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 205 /* cmp.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 205 /* cmp.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 205 /* cmp.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 205 /* cmp.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 205 /* cmp.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 205 /* cmp.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 205 /* cmp.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 211 /* cmp.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 211 /* cmp.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 211 /* cmp.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 211 /* cmp.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 211 /* cmp.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 211 /* cmp.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 211 /* cmp.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 211 /* cmp.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 211 /* cmp.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 211 /* cmp.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 211 /* cmp.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 211 /* cmp.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 217 /* cmp.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 217 /* cmp.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 217 /* cmp.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 217 /* cmp.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 217 /* cmp.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 217 /* cmp.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 217 /* cmp.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 217 /* cmp.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 217 /* cmp.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 217 /* cmp.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 217 /* cmp.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 217 /* cmp.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 223 /* cmpi.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 223 /* cmpi.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 223 /* cmpi.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 223 /* cmpi.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 223 /* cmpi.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 223 /* cmpi.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 223 /* cmpi.b */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 223 /* cmpi.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 223 /* cmpi.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 223 /* cmpi.b */, 2 /* 1 */, MCK_PCD, AMFBS_None },
  { 223 /* cmpi.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 223 /* cmpi.b */, 2 /* 1 */, MCK_PCI, AMFBS_None },
  { 223 /* cmpi.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 223 /* cmpi.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 230 /* cmpi.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 230 /* cmpi.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 230 /* cmpi.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 230 /* cmpi.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 230 /* cmpi.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 230 /* cmpi.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 230 /* cmpi.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 230 /* cmpi.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 230 /* cmpi.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 230 /* cmpi.l */, 2 /* 1 */, MCK_PCD, AMFBS_None },
  { 230 /* cmpi.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 230 /* cmpi.l */, 2 /* 1 */, MCK_PCI, AMFBS_None },
  { 230 /* cmpi.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 230 /* cmpi.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 237 /* cmpi.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 237 /* cmpi.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 237 /* cmpi.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 237 /* cmpi.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 237 /* cmpi.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 237 /* cmpi.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 237 /* cmpi.w */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 237 /* cmpi.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 237 /* cmpi.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 237 /* cmpi.w */, 2 /* 1 */, MCK_PCD, AMFBS_None },
  { 237 /* cmpi.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 237 /* cmpi.w */, 2 /* 1 */, MCK_PCI, AMFBS_None },
  { 237 /* cmpi.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 237 /* cmpi.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 244 /* divs */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 244 /* divs */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 244 /* divs */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 249 /* divs.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 256 /* divu */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 256 /* divu */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 256 /* divu */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 261 /* divu.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 268 /* eor.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 274 /* eor.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 280 /* eor.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 286 /* eori.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 286 /* eori.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 293 /* eori.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 293 /* eori.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 300 /* eori.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 300 /* eori.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 307 /* ext.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 313 /* ext.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 319 /* fabs.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68881 },
  { 326 /* fadd.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68881 },
  { 333 /* fdabs.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 341 /* fdadd.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 349 /* fddiv.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 357 /* fdiv.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68881 },
  { 364 /* fdmove.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 373 /* fdmul.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 381 /* fdneg.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 389 /* fdsub.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 397 /* fmove.l */, 1 /* 0 */, MCK_AReg, AMFBS_AtLeastM68881 },
  { 397 /* fmove.l */, 2 /* 1 */, MCK_FPCReg, AMFBS_AtLeastM68881 },
  { 397 /* fmove.l */, 1 /* 0 */, MCK_DReg, AMFBS_AtLeastM68881 },
  { 397 /* fmove.l */, 2 /* 1 */, MCK_FPCReg, AMFBS_AtLeastM68881 },
  { 397 /* fmove.l */, 2 /* 1 */, MCK_AReg, AMFBS_AtLeastM68881 },
  { 397 /* fmove.l */, 1 /* 0 */, MCK_FPCReg, AMFBS_AtLeastM68881 },
  { 397 /* fmove.l */, 2 /* 1 */, MCK_DReg, AMFBS_AtLeastM68881 },
  { 397 /* fmove.l */, 1 /* 0 */, MCK_FPCReg, AMFBS_AtLeastM68881 },
  { 405 /* fmove.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68881 },
  { 413 /* fmul.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68881 },
  { 420 /* fneg.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68881 },
  { 427 /* fsabs.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 435 /* fsadd.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 443 /* fsdiv.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 451 /* fsmove.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 460 /* fsmul.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 468 /* fsneg.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 476 /* fssub.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68040 },
  { 484 /* fsub.x */, 3 /* 0, 1 */, MCK_FPDReg, AMFBS_AtLeastM68881 },
  { 499 /* jmp */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 503 /* jsr */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 503 /* jsr */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 503 /* jsr */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 503 /* jsr */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 503 /* jsr */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 503 /* jsr */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 503 /* jsr */, 1 /* 0 */, MCK_PCIBD32, AMFBS_None },
  { 507 /* lea */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 507 /* lea */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 507 /* lea */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 507 /* lea */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 507 /* lea */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 507 /* lea */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 507 /* lea */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 507 /* lea */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 507 /* lea */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 507 /* lea */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 507 /* lea */, 1 /* 0 */, MCK_PCIBD16, AMFBS_None },
  { 507 /* lea */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 507 /* lea */, 1 /* 0 */, MCK_PCIBD32, AMFBS_None },
  { 507 /* lea */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 511 /* link.l */, 2 /* 1 */, MCK_MxImm, AMFBS_None },
  { 511 /* link.l */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 518 /* link.w */, 2 /* 1 */, MCK_MxImm, AMFBS_None },
  { 518 /* link.w */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 525 /* lsl.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 525 /* lsl.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 525 /* lsl.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 531 /* lsl.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 531 /* lsl.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 531 /* lsl.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 537 /* lsl.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 537 /* lsl.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 537 /* lsl.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 543 /* lsr.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 543 /* lsr.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 543 /* lsr.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 549 /* lsr.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 549 /* lsr.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 549 /* lsr.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 555 /* lsr.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 555 /* lsr.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 555 /* lsr.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 3 /* 0, 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 3 /* 0, 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 3 /* 0, 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 3 /* 0, 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 3 /* 0, 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 3 /* 0, 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 2 /* 1 */, MCK_Addr8, AMFBS_None },
  { 561 /* move.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 561 /* move.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 3 /* 0, 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 3 /* 0, 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 3 /* 0, 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 3 /* 0, 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 3 /* 0, 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 3 /* 0, 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 3 /* 0, 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 568 /* move.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 568 /* move.l */, 3 /* 0, 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_AtLeastM68010 },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_AtLeastM68010 },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_AtLeastM68010 },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_AtLeastM68010 },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_AtLeastM68010 },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_AtLeastM68010 },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_AtLeastM68010 },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 3 /* 0, 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 3 /* 0, 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 3 /* 0, 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 3 /* 0, 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 3 /* 0, 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 3 /* 0, 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 3 /* 0, 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 575 /* move.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 575 /* move.w */, 3 /* 0, 1 */, MCK_Reg, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_Addr32, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 582 /* movem.l */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 582 /* movem.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_ARIPD, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_ARIPI, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_Addr16, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_ARIPD, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_ARIPI, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_Addr16, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 590 /* movem.w */, 2 /* 1 */, MCK_MoveMask, AMFBS_None },
  { 590 /* movem.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 598 /* moveq */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 598 /* moveq */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 604 /* muls */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 604 /* muls */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 604 /* muls */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 609 /* muls.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 616 /* mulu */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 616 /* mulu */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 616 /* mulu */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 621 /* mulu.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 628 /* neg.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 634 /* neg.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 640 /* neg.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 646 /* negx.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 653 /* negx.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 660 /* negx.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 671 /* not.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 677 /* not.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 683 /* not.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 689 /* or.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 689 /* or.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 694 /* or.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 699 /* or.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 704 /* rol.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 704 /* rol.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 704 /* rol.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 710 /* rol.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 710 /* rol.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 710 /* rol.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 716 /* rol.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 716 /* rol.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 716 /* rol.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 722 /* ror.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 722 /* ror.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 722 /* ror.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 728 /* ror.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 728 /* ror.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 728 /* ror.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 734 /* ror.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 734 /* ror.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 734 /* ror.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 748 /* scc */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 748 /* scc */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 748 /* scc */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 752 /* scs */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 752 /* scs */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 752 /* scs */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 756 /* seq */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 756 /* seq */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 756 /* seq */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 760 /* sf */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 760 /* sf */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 760 /* sf */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 763 /* sge */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 763 /* sge */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 763 /* sge */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 767 /* sgt */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 767 /* sgt */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 767 /* sgt */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 771 /* shi */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 771 /* shi */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 771 /* shi */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 775 /* sle */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 775 /* sle */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 775 /* sle */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 779 /* sls */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 779 /* sls */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 779 /* sls */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 783 /* slt */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 783 /* slt */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 783 /* slt */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 787 /* smi */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 787 /* smi */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 787 /* smi */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 791 /* sne */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 791 /* sne */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 791 /* sne */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 795 /* spl */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 795 /* spl */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 795 /* spl */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 799 /* st */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 799 /* st */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 799 /* st */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 802 /* sub.b */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 802 /* sub.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 808 /* sub.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_ARI, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_ARID, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_ARII, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 2 /* 1 */, MCK_DReg, AMFBS_None },
  { 814 /* sub.w */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 820 /* suba.l */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 820 /* suba.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 820 /* suba.l */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 820 /* suba.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 820 /* suba.l */, 1 /* 0 */, MCK_ARII, AMFBS_None },
  { 820 /* suba.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 820 /* suba.l */, 1 /* 0 */, MCK_Addr32, AMFBS_None },
  { 820 /* suba.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 820 /* suba.l */, 1 /* 0 */, MCK_MxImm, AMFBS_None },
  { 820 /* suba.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 820 /* suba.l */, 1 /* 0 */, MCK_PCD, AMFBS_None },
  { 820 /* suba.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 820 /* suba.l */, 1 /* 0 */, MCK_PCI, AMFBS_None },
  { 820 /* suba.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 820 /* suba.l */, 2 /* 1 */, MCK_AReg, AMFBS_None },
  { 820 /* suba.l */, 1 /* 0 */, MCK_Reg, AMFBS_None },
  { 827 /* subx.b */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 834 /* subx.l */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 841 /* subx.w */, 3 /* 0, 1 */, MCK_DReg, AMFBS_None },
  { 848 /* svc */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 848 /* svc */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 848 /* svc */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 852 /* svs */, 1 /* 0 */, MCK_ARI, AMFBS_None },
  { 852 /* svs */, 1 /* 0 */, MCK_ARID, AMFBS_None },
  { 852 /* svs */, 1 /* 0 */, MCK_DReg, AMFBS_None },
  { 856 /* trap */, 1 /* 0 */, MCK_MxTrapImm, AMFBS_None },
  { 867 /* unlk */, 1 /* 0 */, MCK_AReg, AMFBS_None },
};

ParseStatus M68kAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_ARI:
    return parseMemOp(Operands);
  case MCK_ARID:
    return parseMemOp(Operands);
  case MCK_ARII:
    return parseMemOp(Operands);
  case MCK_ARIPD:
    return parseMemOp(Operands);
  case MCK_ARIPI:
    return parseMemOp(Operands);
  case MCK_Addr8:
    return parseMemOp(Operands);
  case MCK_Addr16:
    return parseMemOp(Operands);
  case MCK_Addr32:
    return parseMemOp(Operands);
  case MCK_Addr:
    return parseMemOp(Operands);
  case MCK_MxBkptImm:
    return parseImm(Operands);
  case MCK_MxImm:
    return parseImm(Operands);
  case MCK_MoveMask:
    return parseMemOp(Operands);
  case MCK_PCD:
    return parseMemOp(Operands);
  case MCK_PCI:
    return parseMemOp(Operands);
  case MCK_PCIBD16:
    return parseMemOp(Operands);
  case MCK_PCIBD32:
    return parseMemOp(Operands);
  case MCK_AReg:
    return parseMemOp(Operands);
  case MCK_DReg:
    return parseMemOp(Operands);
  case MCK_FPCReg:
    return parseMemOp(Operands);
  case MCK_FPDReg:
    return parseMemOp(Operands);
  case MCK_Reg:
    return parseMemOp(Operands);
  case MCK_MxTrapImm:
    return parseImm(Operands);
  default:
    return ParseStatus::NoMatch;
  }
  return ParseStatus::NoMatch;
}

ParseStatus M68kAsmParser::
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

static std::string M68kMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool M68kCheckMnemonic(StringRef Mnemonic,
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

