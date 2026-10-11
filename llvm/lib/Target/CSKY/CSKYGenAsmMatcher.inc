/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: CSKY.td                                                              *|
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

  Match_InvalidCSKYSymbol,
  Match_InvalidConstpool,
  Match_InvalidOImm12,
  Match_InvalidOImm16,
  Match_InvalidOImm3,
  Match_InvalidOImm4,
  Match_InvalidOImm5,
  Match_InvalidOImm6,
  Match_InvalidOImm8,
  Match_InvalidPSRFlag,
  Match_InvalidRegList,
  Match_InvalidRegSeq,
  Match_InvalidSImm8,
  Match_InvalidUImm1,
  Match_InvalidUImm12,
  Match_InvalidUImm12Shift1,
  Match_InvalidUImm12Shift2,
  Match_InvalidUImm16,
  Match_InvalidUImm16Shift16,
  Match_InvalidUImm16Shift8,
  Match_InvalidUImm2,
  Match_InvalidUImm20,
  Match_InvalidUImm24,
  Match_InvalidUImm24Shift8,
  Match_InvalidUImm3,
  Match_InvalidUImm4,
  Match_InvalidUImm5,
  Match_InvalidUImm5Shift1,
  Match_InvalidUImm5Shift2,
  Match_InvalidUImm6,
  Match_InvalidUImm7,
  Match_InvalidUImm7Shift1,
  Match_InvalidUImm7Shift2,
  Match_InvalidUImm7Shift3,
  Match_InvalidUImm8,
  Match_InvalidUImm8Shift16,
  Match_InvalidUImm8Shift2,
  Match_InvalidUImm8Shift24,
  Match_InvalidUImm8Shift3,
  Match_InvalidUImm8Shift8,
  END_OPERAND_DIAGNOSTIC_TYPES
#endif // GET_OPERAND_DIAGNOSTIC_TYPES


#ifdef GET_REGISTER_MATCHER
#undef GET_REGISTER_MATCHER

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_HasFPUv2_SFBit = 11,
  Feature_HasFPUv2_DFBit = 10,
  Feature_HasFdivduBit = 16,
  Feature_HasFPUv3_HIBit = 14,
  Feature_HasFPUv3_HFBit = 13,
  Feature_HasFPUv3_SFBit = 15,
  Feature_HasFPUv3_DFBit = 12,
  Feature_iHasFLOATE1Bit = 44,
  Feature_iHasFLOAT1E2Bit = 40,
  Feature_iHasFLOAT1E3Bit = 41,
  Feature_iHasFLOAT3E4Bit = 42,
  Feature_iHasFLOAT7E60Bit = 43,
  Feature_HasHWDivBit = 17,
  Feature_HasSTMBit = 22,
  Feature_HasPushPopBit = 21,
  Feature_HasDSPBit = 5,
  Feature_iHasDSP1E2Bit = 36,
  Feature_iHasDSPE60Bit = 37,
  Feature_HasDSPV2Bit = 6,
  Feature_HasDSP_SilanBit = 7,
  Feature_HasBTST16Bit = 3,
  Feature_HasExtendLrwBit = 9,
  Feature_HasTrustBit = 23,
  Feature_HasJAVABit = 19,
  Feature_HasCacheBit = 4,
  Feature_HasNVICBit = 20,
  Feature_HasDoloopBit = 8,
  Feature_HasHighRegistersBit = 18,
  Feature_SmartModeBit = 27,
  Feature_HasVDSPV2Bit = 25,
  Feature_iHasVDSP2E3Bit = 47,
  Feature_iHasVDSP2E60FBit = 48,
  Feature_ReadTPHardBit = 26,
  Feature_EnableInterruptAttributeBit = 1,
  Feature_DumpConstPoolBit = 0,
  Feature_EnableStackSizeBit = 2,
  Feature_UseCCRTBit = 28,
  Feature_HasVDSPV1_128Bit = 24,
  Feature_iHasE1Bit = 38,
  Feature_iHasE2Bit = 39,
  Feature_iHas2E3Bit = 29,
  Feature_iHasMPBit = 45,
  Feature_iHas3E3r1Bit = 30,
  Feature_iHas3r1E3r2Bit = 32,
  Feature_iHas3r2E3r3Bit = 33,
  Feature_iHas3E7Bit = 31,
  Feature_iHasMP1E2Bit = 46,
  Feature_iHas7E10Bit = 34,
  Feature_iHas10E60Bit = 35,
  Feature_isCK801Bit = 49,
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
      return CSKY::R0;	 // "r0"
    case '1':	 // 2 strings to match.
      return CSKY::R1;	 // "r1"
    case '2':	 // 2 strings to match.
      return CSKY::R2;	 // "r2"
    case '3':	 // 2 strings to match.
      return CSKY::R3;	 // "r3"
    case '4':	 // 2 strings to match.
      return CSKY::R4;	 // "r4"
    case '5':	 // 2 strings to match.
      return CSKY::R5;	 // "r5"
    case '6':	 // 2 strings to match.
      return CSKY::R6;	 // "r6"
    case '7':	 // 2 strings to match.
      return CSKY::R7;	 // "r7"
    case '8':	 // 2 strings to match.
      return CSKY::R8;	 // "r8"
    case '9':	 // 2 strings to match.
      return CSKY::R9;	 // "r9"
    }
    break;
  case 3:	 // 76 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(Name.data()+1, "r0", 2) != 0)
        break;
      return CSKY::C;	 // "cr0"
    case 'f':	 // 30 strings to match.
      if (Name[1] != 'r')
        break;
      switch (Name[2]) {
      default: break;
      case '0':	 // 3 strings to match.
        return CSKY::F0_32;	 // "fr0"
      case '1':	 // 3 strings to match.
        return CSKY::F1_32;	 // "fr1"
      case '2':	 // 3 strings to match.
        return CSKY::F2_32;	 // "fr2"
      case '3':	 // 3 strings to match.
        return CSKY::F3_32;	 // "fr3"
      case '4':	 // 3 strings to match.
        return CSKY::F4_32;	 // "fr4"
      case '5':	 // 3 strings to match.
        return CSKY::F5_32;	 // "fr5"
      case '6':	 // 3 strings to match.
        return CSKY::F6_32;	 // "fr6"
      case '7':	 // 3 strings to match.
        return CSKY::F7_32;	 // "fr7"
      case '8':	 // 3 strings to match.
        return CSKY::F8_32;	 // "fr8"
      case '9':	 // 3 strings to match.
        return CSKY::F9_32;	 // "fr9"
      }
      break;
    case 'r':	 // 45 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return CSKY::R10;	 // "r10"
        case '1':	 // 2 strings to match.
          return CSKY::R11;	 // "r11"
        case '2':	 // 2 strings to match.
          return CSKY::R12;	 // "r12"
        case '3':	 // 2 strings to match.
          return CSKY::R13;	 // "r13"
        case '4':	 // 2 strings to match.
          return CSKY::R14;	 // "r14"
        case '5':	 // 2 strings to match.
          return CSKY::R15;	 // "r15"
        case '6':	 // 2 strings to match.
          return CSKY::R16;	 // "r16"
        case '7':	 // 2 strings to match.
          return CSKY::R17;	 // "r17"
        case '8':	 // 2 strings to match.
          return CSKY::R18;	 // "r18"
        case '9':	 // 2 strings to match.
          return CSKY::R19;	 // "r19"
        }
        break;
      case '2':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return CSKY::R20;	 // "r20"
        case '1':	 // 2 strings to match.
          return CSKY::R21;	 // "r21"
        case '2':	 // 2 strings to match.
          return CSKY::R22;	 // "r22"
        case '3':	 // 2 strings to match.
          return CSKY::R23;	 // "r23"
        case '4':	 // 2 strings to match.
          return CSKY::R24;	 // "r24"
        case '5':	 // 2 strings to match.
          return CSKY::R25;	 // "r25"
        case '6':	 // 2 strings to match.
          return CSKY::R26;	 // "r26"
        case '7':	 // 2 strings to match.
          return CSKY::R27;	 // "r27"
        case '8':	 // 2 strings to match.
          return CSKY::R28;	 // "r28"
        case '9':	 // 2 strings to match.
          return CSKY::R29;	 // "r29"
        }
        break;
      case '3':	 // 5 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return CSKY::R30;	 // "r30"
        case '1':	 // 2 strings to match.
          return CSKY::R31;	 // "r31"
        case '2':	 // 1 string to match.
          return CSKY::R32;	 // "r32"
        }
        break;
      }
      break;
    }
    break;
  case 4:	 // 66 strings to match.
    if (memcmp(Name.data()+0, "fr", 2) != 0)
      break;
    switch (Name[2]) {
    default: break;
    case '1':	 // 30 strings to match.
      switch (Name[3]) {
      default: break;
      case '0':	 // 3 strings to match.
        return CSKY::F10_32;	 // "fr10"
      case '1':	 // 3 strings to match.
        return CSKY::F11_32;	 // "fr11"
      case '2':	 // 3 strings to match.
        return CSKY::F12_32;	 // "fr12"
      case '3':	 // 3 strings to match.
        return CSKY::F13_32;	 // "fr13"
      case '4':	 // 3 strings to match.
        return CSKY::F14_32;	 // "fr14"
      case '5':	 // 3 strings to match.
        return CSKY::F15_32;	 // "fr15"
      case '6':	 // 3 strings to match.
        return CSKY::F16_32;	 // "fr16"
      case '7':	 // 3 strings to match.
        return CSKY::F17_32;	 // "fr17"
      case '8':	 // 3 strings to match.
        return CSKY::F18_32;	 // "fr18"
      case '9':	 // 3 strings to match.
        return CSKY::F19_32;	 // "fr19"
      }
      break;
    case '2':	 // 30 strings to match.
      switch (Name[3]) {
      default: break;
      case '0':	 // 3 strings to match.
        return CSKY::F20_32;	 // "fr20"
      case '1':	 // 3 strings to match.
        return CSKY::F21_32;	 // "fr21"
      case '2':	 // 3 strings to match.
        return CSKY::F22_32;	 // "fr22"
      case '3':	 // 3 strings to match.
        return CSKY::F23_32;	 // "fr23"
      case '4':	 // 3 strings to match.
        return CSKY::F24_32;	 // "fr24"
      case '5':	 // 3 strings to match.
        return CSKY::F25_32;	 // "fr25"
      case '6':	 // 3 strings to match.
        return CSKY::F26_32;	 // "fr26"
      case '7':	 // 3 strings to match.
        return CSKY::F27_32;	 // "fr27"
      case '8':	 // 3 strings to match.
        return CSKY::F28_32;	 // "fr28"
      case '9':	 // 3 strings to match.
        return CSKY::F29_32;	 // "fr29"
      }
      break;
    case '3':	 // 6 strings to match.
      switch (Name[3]) {
      default: break;
      case '0':	 // 3 strings to match.
        return CSKY::F30_32;	 // "fr30"
      case '1':	 // 3 strings to match.
        return CSKY::F31_32;	 // "fr31"
      }
      break;
    }
    break;
  }
  return CSKY::NoRegister;
}

static MCRegister MatchRegisterAltName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 52 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 8 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return CSKY::R0;	 // "a0"
      case '1':	 // 2 strings to match.
        return CSKY::R1;	 // "a1"
      case '2':	 // 2 strings to match.
        return CSKY::R2;	 // "a2"
      case '3':	 // 2 strings to match.
        return CSKY::R3;	 // "a3"
      }
      break;
    case 'l':	 // 22 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return CSKY::R4;	 // "l0"
      case '1':	 // 2 strings to match.
        return CSKY::R5;	 // "l1"
      case '2':	 // 2 strings to match.
        return CSKY::R6;	 // "l2"
      case '3':	 // 2 strings to match.
        return CSKY::R7;	 // "l3"
      case '4':	 // 2 strings to match.
        return CSKY::R8;	 // "l4"
      case '5':	 // 2 strings to match.
        return CSKY::R9;	 // "l5"
      case '6':	 // 2 strings to match.
        return CSKY::R10;	 // "l6"
      case '7':	 // 2 strings to match.
        return CSKY::R11;	 // "l7"
      case '8':	 // 2 strings to match.
        return CSKY::R16;	 // "l8"
      case '9':	 // 2 strings to match.
        return CSKY::R17;	 // "l9"
      case 'r':	 // 2 strings to match.
        return CSKY::R15;	 // "lr"
      }
      break;
    case 's':	 // 2 strings to match.
      if (Name[1] != 'p')
        break;
      return CSKY::R14;	 // "sp"
    case 't':	 // 20 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return CSKY::R12;	 // "t0"
      case '1':	 // 2 strings to match.
        return CSKY::R13;	 // "t1"
      case '2':	 // 2 strings to match.
        return CSKY::R18;	 // "t2"
      case '3':	 // 2 strings to match.
        return CSKY::R19;	 // "t3"
      case '4':	 // 2 strings to match.
        return CSKY::R20;	 // "t4"
      case '5':	 // 2 strings to match.
        return CSKY::R21;	 // "t5"
      case '6':	 // 2 strings to match.
        return CSKY::R22;	 // "t6"
      case '7':	 // 2 strings to match.
        return CSKY::R23;	 // "t7"
      case '8':	 // 2 strings to match.
        return CSKY::R24;	 // "t8"
      case '9':	 // 2 strings to match.
        return CSKY::R25;	 // "t9"
      }
      break;
    }
    break;
  case 3:	 // 42 strings to match.
    switch (Name[0]) {
    default: break;
    case 'p':	 // 1 string to match.
      if (memcmp(Name.data()+1, "sr", 2) != 0)
        break;
      return CSKY::C;	 // "psr"
    case 'r':	 // 9 strings to match.
      switch (Name[1]) {
      default: break;
      case '2':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '6':	 // 2 strings to match.
          return CSKY::R26;	 // "r26"
        case '7':	 // 2 strings to match.
          return CSKY::R27;	 // "r27"
        }
        break;
      case '3':	 // 1 string to match.
        if (Name[2] != '2')
          break;
        return CSKY::R32;	 // "r32"
      case 'g':	 // 2 strings to match.
        if (Name[2] != 'b')
          break;
        return CSKY::R28;	 // "rgb"
      case 't':	 // 2 strings to match.
        if (Name[2] != 'b')
          break;
        return CSKY::R29;	 // "rtb"
      }
      break;
    case 't':	 // 2 strings to match.
      if (memcmp(Name.data()+1, "ls", 2) != 0)
        break;
      return CSKY::R31;	 // "tls"
    case 'v':	 // 30 strings to match.
      if (Name[1] != 'r')
        break;
      switch (Name[2]) {
      default: break;
      case '0':	 // 3 strings to match.
        return CSKY::F0_32;	 // "vr0"
      case '1':	 // 3 strings to match.
        return CSKY::F1_32;	 // "vr1"
      case '2':	 // 3 strings to match.
        return CSKY::F2_32;	 // "vr2"
      case '3':	 // 3 strings to match.
        return CSKY::F3_32;	 // "vr3"
      case '4':	 // 3 strings to match.
        return CSKY::F4_32;	 // "vr4"
      case '5':	 // 3 strings to match.
        return CSKY::F5_32;	 // "vr5"
      case '6':	 // 3 strings to match.
        return CSKY::F6_32;	 // "vr6"
      case '7':	 // 3 strings to match.
        return CSKY::F7_32;	 // "vr7"
      case '8':	 // 3 strings to match.
        return CSKY::F8_32;	 // "vr8"
      case '9':	 // 3 strings to match.
        return CSKY::F9_32;	 // "vr9"
      }
      break;
    }
    break;
  case 4:	 // 68 strings to match.
    switch (Name[0]) {
    default: break;
    case 's':	 // 2 strings to match.
      if (memcmp(Name.data()+1, "vbr", 3) != 0)
        break;
      return CSKY::R30;	 // "svbr"
    case 'v':	 // 66 strings to match.
      if (Name[1] != 'r')
        break;
      switch (Name[2]) {
      default: break;
      case '1':	 // 30 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 3 strings to match.
          return CSKY::F10_32;	 // "vr10"
        case '1':	 // 3 strings to match.
          return CSKY::F11_32;	 // "vr11"
        case '2':	 // 3 strings to match.
          return CSKY::F12_32;	 // "vr12"
        case '3':	 // 3 strings to match.
          return CSKY::F13_32;	 // "vr13"
        case '4':	 // 3 strings to match.
          return CSKY::F14_32;	 // "vr14"
        case '5':	 // 3 strings to match.
          return CSKY::F15_32;	 // "vr15"
        case '6':	 // 3 strings to match.
          return CSKY::F16_32;	 // "vr16"
        case '7':	 // 3 strings to match.
          return CSKY::F17_32;	 // "vr17"
        case '8':	 // 3 strings to match.
          return CSKY::F18_32;	 // "vr18"
        case '9':	 // 3 strings to match.
          return CSKY::F19_32;	 // "vr19"
        }
        break;
      case '2':	 // 30 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 3 strings to match.
          return CSKY::F20_32;	 // "vr20"
        case '1':	 // 3 strings to match.
          return CSKY::F21_32;	 // "vr21"
        case '2':	 // 3 strings to match.
          return CSKY::F22_32;	 // "vr22"
        case '3':	 // 3 strings to match.
          return CSKY::F23_32;	 // "vr23"
        case '4':	 // 3 strings to match.
          return CSKY::F24_32;	 // "vr24"
        case '5':	 // 3 strings to match.
          return CSKY::F25_32;	 // "vr25"
        case '6':	 // 3 strings to match.
          return CSKY::F26_32;	 // "vr26"
        case '7':	 // 3 strings to match.
          return CSKY::F27_32;	 // "vr27"
        case '8':	 // 3 strings to match.
          return CSKY::F28_32;	 // "vr28"
        case '9':	 // 3 strings to match.
          return CSKY::F29_32;	 // "vr29"
        }
        break;
      case '3':	 // 6 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 3 strings to match.
          return CSKY::F30_32;	 // "vr30"
        case '1':	 // 3 strings to match.
          return CSKY::F31_32;	 // "vr31"
        }
        break;
      }
      break;
    }
    break;
  }
  return CSKY::NoRegister;
}

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_HasFPUv2_SFBit: return "Enable FPUv2 single float instructions";
  case Feature_HasFPUv2_DFBit: return "Enable FPUv2 double float instructions";
  case Feature_HasFdivduBit: return "Enable float divide instructions";
  case Feature_HasFPUv3_HIBit: return "Enable FPUv3 half word converting instructions";
  case Feature_HasFPUv3_HFBit: return "Enable FPUv3 half precision operate instructions";
  case Feature_HasFPUv3_SFBit: return "Enable FPUv3 single float instructions";
  case Feature_HasFPUv3_DFBit: return "Enable FPUv3 double float instructions";
  case Feature_iHasFLOATE1Bit: return "Support CSKY floate1 instructions";
  case Feature_iHasFLOAT1E2Bit: return "Support CSKY float1e2 instructions";
  case Feature_iHasFLOAT1E3Bit: return "Support CSKY float1e3 instructions";
  case Feature_iHasFLOAT3E4Bit: return "Support CSKY float3e4 instructions";
  case Feature_iHasFLOAT7E60Bit: return "Support CSKY float7e60 instructions";
  case Feature_HasHWDivBit: return "Enable divide instructions";
  case Feature_HasSTMBit: return "Enable multiple load/store instructions";
  case Feature_HasPushPopBit: return "Enable push/pop instructions";
  case Feature_HasDSPBit: return "Enable DSP instructions";
  case Feature_iHasDSP1E2Bit: return "Support CSKY dsp1e2 instructions";
  case Feature_iHasDSPE60Bit: return "Support CSKY dspe60 instructions";
  case Feature_HasDSPV2Bit: return "Enable DSP V2.0 instructions";
  case Feature_HasDSP_SilanBit: return "Enable DSP Silan instructions";
  case Feature_HasBTST16Bit: return "Use the 16-bit btsti instruction";
  case Feature_HasExtendLrwBit: return "Use the extend LRW instruction";
  case Feature_HasTrustBit: return "Enable trust instructions";
  case Feature_HasJAVABit: return "Enable java instructions";
  case Feature_HasCacheBit: return "Enable cache";
  case Feature_HasNVICBit: return "Enable NVIC";
  case Feature_HasDoloopBit: return "Enable doloop instructions";
  case Feature_HasHighRegistersBit: return "Enable r16-r31 registers";
  case Feature_SmartModeBit: return "Let CPU work in Smart Mode";
  case Feature_HasVDSPV2Bit: return "Enable vdsp-v2 instructions";
  case Feature_iHasVDSP2E3Bit: return "Support CSKY vdsp2e3 instructions";
  case Feature_iHasVDSP2E60FBit: return "Support CSKY vdsp2e60f instructions";
  case Feature_ReadTPHardBit: return "Enable TLS Pointer register";
  case Feature_EnableInterruptAttributeBit: return "Enable interrupt attribute";
  case Feature_DumpConstPoolBit: return "Dump the constant pool by compiler";
  case Feature_EnableStackSizeBit: return "Output stack size information";
  case Feature_UseCCRTBit: return "Use CSKY compiler runtime";
  case Feature_HasVDSPV1_128Bit: return "Enable 128bit vdsp-v1 instructions";
  case Feature_iHasE1Bit: return "Support CSKY e1 instructions";
  case Feature_iHasE2Bit: return "Support CSKY e2 instructions";
  case Feature_iHas2E3Bit: return "Support CSKY 2e3 instructions";
  case Feature_iHasMPBit: return "Support CSKY mp instructions";
  case Feature_iHas3E3r1Bit: return "Support CSKY 3e3r1 instructions";
  case Feature_iHas3r1E3r2Bit: return "Support CSKY 3e3r2 instructions";
  case Feature_iHas3r2E3r3Bit: return "Support CSKY 3e3r3 instructions";
  case Feature_iHas3E7Bit: return "Support CSKY 3e7 instructions";
  case Feature_iHasMP1E2Bit: return "Support CSKY mp1e2 instructions";
  case Feature_iHas7E10Bit: return "Support CSKY 7e10 instructions";
  case Feature_iHas10E60Bit: return "Support CSKY 10e60 instructions";
  case Feature_isCK801Bit: return "";
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
  CVT_95_Reg,
  CVT_imm_95_0,
  CVT_95_addImmOperands,
  CVT_95_addRegSeqOperands,
  CVT_95_addConstpoolOperands,
  CVT_regC,
  CVT_regR0,
  CVT_95_addRegListOperands,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Reg1_0__Reg1_1,
  Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__imm_95_0,
  Convert__Reg1_0__imm_95_0__Reg1_1__Reg1_2__imm_95_0,
  Convert__Reg1_0__Tie0_1_1__OImm81_1,
  Convert__Reg1_0__Reg1_1__UImm7Shift21_2,
  Convert__Reg1_0__Reg1_1__UImm8Shift21_2,
  Convert__Reg1_0__Reg1_1__OImm31_2,
  Convert__Reg1_0__Reg1_1__OImm121_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1,
  Convert__Reg1_0__Reg1_1__Reg1_2,
  Convert__Reg1_0__Reg1_1__UImm121_2,
  Convert__Reg1_0__imm_95_0__Reg1_1__OImm51_2,
  Convert__Reg1_0__Reg1_1__UImm51_2,
  Convert_NoOperands,
  Convert__Reg1_0__Tie0_1_1__UImm51_1,
  Convert__Reg1_0__CSKYSymbol1_1,
  Convert__imm_95_0__CSKYSymbol1_0,
  Convert__Reg1_0__UImm51_1,
  Convert__Reg1_0__OImm51_1,
  Convert__Reg1_0__Tie0_1_1__CSKYSymbol1_1,
  Convert__Reg1_0,
  Convert__CSKYSymbol1_0,
  Convert__imm_95_0__Reg1_0__UImm51_1,
  Convert__imm_95_0,
  Convert__Reg1_0__imm_95_0__Tie0_1_1,
  Convert__imm_95_0__Reg1_0__Reg1_1,
  Convert__imm_95_0__Reg1_0__OImm51_1,
  Convert__imm_95_0__Reg1_0__OImm161_1,
  Convert__imm_95_0__Reg1_0__UImm161_1,
  Convert__UImm51_1__UImm201_2,
  Convert__imm_95_0__UImm51_1__UImm121_2,
  Convert__Reg1_0__UImm51_2__UImm121_3,
  Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__UImm51_2,
  Convert__Reg1_0__imm_95_0__Reg1_1__UImm51_2,
  Convert__imm_95_0__Reg1_0,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2,
  Convert__Reg1_0__Reg1_2__UImm8Shift21_3,
  Convert__Reg1_0__Reg1_2__UImm8Shift31_3,
  Convert__Reg1_2__RegSeqV22_0,
  Convert__Reg1_2__RegSeqV12_0,
  Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5,
  Convert__Reg1_0__Constpool1_1,
  Convert__Reg1_0__imm_95_0__Reg1_1__Reg1_2,
  Convert__Imm1_0,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2__UImm51_3,
  Convert__regC__CSKYSymbol1_0,
  Convert__Constpool1_0,
  Convert__Reg1_0__Imm1_1,
  Convert__Reg1_0__Reg1_2__UImm51_3,
  Convert__Reg1_0__Reg1_2__UImm5Shift11_3,
  Convert__Reg1_0__Reg1_2__UImm5Shift21_3,
  Convert__Reg1_0__Reg1_2__UImm121_3,
  Convert__Reg1_0__Reg1_2__UImm12Shift21_3,
  Convert__Reg1_0__Reg1_2__UImm12Shift11_3,
  Convert__Reg1_2__RegSeq2_0,
  Convert__Reg1_0__DataSymbol1_1,
  Convert__Reg1_0__UImm81_1,
  Convert__Reg1_0__UImm161_1,
  Convert__Reg1_0__imm_95_0,
  Convert__regR0__regR0,
  Convert__Reg1_0__Reg1_1__UImm161_2,
  Convert__Reg1_1__UImm12Shift21_2,
  Convert__RegList1_0,
  Convert__UImm41_0,
  Convert__Reg1_0__Reg1_1__UImm51_2__UImm51_3,
  Convert__Reg1_0__Tie0_1_1__Reg1_2__UImm12Shift21_3,
  Convert__UImm51_0,
  Convert__UImm21_0,
  Convert__Reg1_0__imm_95_0__Reg1_1__OImm51_2__imm_95_0,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][11] = {
  // Convert__Reg1_0__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__imm_95_0
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_0__Reg1_1__Reg1_2__imm_95_0
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__OImm81_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm7Shift21_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm8Shift21_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__OImm31_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__OImm121_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm121_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__imm_95_0__Reg1_1__OImm51_2
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm51_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__UImm51_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__CSKYSymbol1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__imm_95_0__CSKYSymbol1_0
  { CVT_imm_95_0, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__UImm51_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__OImm51_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__CSKYSymbol1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__CSKYSymbol1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__imm_95_0__Reg1_0__UImm51_1
  { CVT_imm_95_0, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__imm_95_0
  { CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_0__Tie0_1_1
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__imm_95_0__Reg1_0__Reg1_1
  { CVT_imm_95_0, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__imm_95_0__Reg1_0__OImm51_1
  { CVT_imm_95_0, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__imm_95_0__Reg1_0__OImm161_1
  { CVT_imm_95_0, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__imm_95_0__Reg1_0__UImm161_1
  { CVT_imm_95_0, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__UImm51_1__UImm201_2
  { CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__imm_95_0__UImm51_1__UImm121_2
  { CVT_imm_95_0, 0, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__UImm51_2__UImm121_3
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__UImm51_2
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__imm_95_0__Reg1_1__UImm51_2
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__imm_95_0__Reg1_0
  { CVT_imm_95_0, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_2__UImm8Shift21_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_2__UImm8Shift31_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_2__RegSeqV22_0
  { CVT_95_Reg, 3, CVT_95_addRegSeqOperands, 1, CVT_Done },
  // Convert__Reg1_2__RegSeqV12_0
  { CVT_95_Reg, 3, CVT_95_addRegSeqOperands, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__Reg1_0__Constpool1_1
  { CVT_95_Reg, 1, CVT_95_addConstpoolOperands, 2, CVT_Done },
  // Convert__Reg1_0__imm_95_0__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2__UImm51_3
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__regC__CSKYSymbol1_0
  { CVT_regC, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Constpool1_0
  { CVT_95_addConstpoolOperands, 1, CVT_Done },
  // Convert__Reg1_0__Imm1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_2__UImm51_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_2__UImm5Shift11_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_2__UImm5Shift21_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_2__UImm121_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_2__UImm12Shift21_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_2__UImm12Shift11_3
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_2__RegSeq2_0
  { CVT_95_Reg, 3, CVT_95_addRegSeqOperands, 1, CVT_Done },
  // Convert__Reg1_0__DataSymbol1_1
  { CVT_95_Reg, 1, CVT_95_addConstpoolOperands, 2, CVT_Done },
  // Convert__Reg1_0__UImm81_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__UImm161_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__imm_95_0
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__regR0__regR0
  { CVT_regR0, 0, CVT_regR0, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm161_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_1__UImm12Shift21_2
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegList1_0
  { CVT_95_addRegListOperands, 1, CVT_Done },
  // Convert__UImm41_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm51_2__UImm51_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_2__UImm12Shift21_3
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__UImm51_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__UImm21_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__imm_95_0__Reg1_1__OImm51_2__imm_95_0
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_Done },
};

void CSKYAsmParser::
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
      static_cast<CSKYOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
      static_cast<CSKYOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_95_addImmOperands:
      static_cast<CSKYOperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_addRegSeqOperands:
      static_cast<CSKYOperand &>(*Operands[OpIdx]).addRegSeqOperands(Inst, 2);
      break;
    case CVT_95_addConstpoolOperands:
      static_cast<CSKYOperand &>(*Operands[OpIdx]).addConstpoolOperands(Inst, 1);
      break;
    case CVT_regC:
      Inst.addOperand(MCOperand::createReg(CSKY::C));
      break;
    case CVT_regR0:
      Inst.addOperand(MCOperand::createReg(CSKY::R0));
      break;
    case CVT_95_addRegListOperands:
      static_cast<CSKYOperand &>(*Operands[OpIdx]).addRegListOperands(Inst, 1);
      break;
    }
  }
}

void CSKYAsmParser::
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
    case CVT_95_addImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegSeqOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 2;
      break;
    case CVT_95_addConstpoolOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_regC:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_regR0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addRegListOperands:
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
  MCK__40_, // '('
  MCK__41_, // ')'
  MCK__LT_, // '<'
  MCK__LT__LT_, // '<<'
  MCK__GT_, // '>'
  MCK_LAST_TOKEN = MCK__GT_,
  MCK_Reg18, // derived register class
  MCK_Reg17, // derived register class
  MCK_CARRY, // register class 'CARRY'
  MCK_GPRSP, // register class 'GPRSP'
  MCK_Reg11, // derived register class
  MCK_Reg12, // derived register class
  MCK_mGPR, // register class 'mGPR'
  MCK_Reg13, // derived register class
  MCK_Reg14, // derived register class
  MCK_sFPR128, // register class 'sFPR128'
  MCK_sFPR32, // register class 'sFPR32'
  MCK_sFPR64, // register class 'sFPR64,sFPR64_V'
  MCK_sGPR, // register class 'sGPR'
  MCK_Reg15, // derived register class
  MCK_FPR128, // register class 'FPR128'
  MCK_FPR32, // register class 'FPR32'
  MCK_FPR64, // register class 'FPR64'
  MCK_GPR, // register class 'GPR'
  MCK_GPRPair, // register class 'GPRPair'
  MCK_LAST_REGISTER = MCK_GPRPair,
  MCK_CSKYSymbol, // user defined class 'CSKYSymbol'
  MCK_Constpool, // user defined class 'Constpool'
  MCK_DataSymbol, // user defined class 'DataAsmClass'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_PSRFlag, // user defined class 'PSRFlag'
  MCK_RegList, // user defined class 'RegListAsmOperand'
  MCK_UImm16, // user defined class 'anonymous_13887'
  MCK_UImm2, // user defined class 'anonymous_13888'
  MCK_OImm3, // user defined class 'anonymous_13889'
  MCK_OImm4, // user defined class 'anonymous_13890'
  MCK_OImm5, // user defined class 'anonymous_13891'
  MCK_OImm6, // user defined class 'anonymous_13892'
  MCK_OImm8, // user defined class 'anonymous_13893'
  MCK_OImm12, // user defined class 'anonymous_13894'
  MCK_OImm16, // user defined class 'anonymous_13895'
  MCK_UImm12, // user defined class 'anonymous_13896'
  MCK_UImm1, // user defined class 'anonymous_13897'
  MCK_UImm3, // user defined class 'anonymous_13898'
  MCK_UImm4, // user defined class 'anonymous_13899'
  MCK_UImm5, // user defined class 'anonymous_13900'
  MCK_UImm5Shift1, // user defined class 'anonymous_13901'
  MCK_UImm5Shift2, // user defined class 'anonymous_13902'
  MCK_UImm6, // user defined class 'anonymous_13903'
  MCK_UImm7, // user defined class 'anonymous_13904'
  MCK_UImm7Shift1, // user defined class 'anonymous_13905'
  MCK_UImm7Shift2, // user defined class 'anonymous_13906'
  MCK_UImm7Shift3, // user defined class 'anonymous_13907'
  MCK_UImm8, // user defined class 'anonymous_13908'
  MCK_UImm8Shift2, // user defined class 'anonymous_13909'
  MCK_UImm8Shift3, // user defined class 'anonymous_13910'
  MCK_UImm8Shift8, // user defined class 'anonymous_13911'
  MCK_UImm8Shift16, // user defined class 'anonymous_13912'
  MCK_UImm8Shift24, // user defined class 'anonymous_13913'
  MCK_UImm12Shift1, // user defined class 'anonymous_13914'
  MCK_UImm12Shift2, // user defined class 'anonymous_13915'
  MCK_UImm16Shift8, // user defined class 'anonymous_13916'
  MCK_UImm16Shift16, // user defined class 'anonymous_13917'
  MCK_UImm20, // user defined class 'anonymous_13918'
  MCK_UImm24, // user defined class 'anonymous_13919'
  MCK_UImm24Shift8, // user defined class 'anonymous_13920'
  MCK_SImm8, // user defined class 'anonymous_13921'
  MCK_RegSeq, // user defined class 'anonymous_13922'
  MCK_RegSeqV1, // user defined class 'anonymous_14410'
  MCK_RegSeqV2, // user defined class 'anonymous_14627'
  NumMatchClassKinds
};

} // end anonymous namespace

static unsigned getDiagKindFromRegisterClass(MatchClassKind RegisterClass) {
  return MCTargetAsmParser::Match_InvalidOperand;
}

static MatchClassKind matchTokenString(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 4 strings to match.
    switch (Name[0]) {
    default: break;
    case '(':	 // 1 string to match.
      return MCK__40_;	 // "("
    case ')':	 // 1 string to match.
      return MCK__41_;	 // ")"
    case '<':	 // 1 string to match.
      return MCK__LT_;	 // "<"
    case '>':	 // 1 string to match.
      return MCK__GT_;	 // ">"
    }
    break;
  case 2:	 // 1 string to match.
    if (memcmp(Name.data()+0, "<<", 2) != 0)
      break;
    return MCK__LT__LT_;	 // "<<"
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
    {0, 14, 12},
    {12, 14, 12},
    {24, 0, 0},
    {24, 19, 6},
    {30, 12, 14},
    {44, 14, 12},
    {56, 19, 6},
    {62, 15, 11},
    {73, 20, 6},
    {79, 21, 1},
    {80, 22, 1},
    {81, 23, 1},
    {82, 24, 1},
    {83, 25, 1},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
    {84, 0, 0},
  };

  static constexpr uint8_t Data[] = {
    0x43,
    0x38,
    0x84,
    0x61,
    0x43,
    0x38,
    0x84,
    0x61,
    0x08,
    0xC3,
    0x0F,
  };

  auto &Entry = Table[A];
  unsigned Idx = B - Entry.Start;
  if (Idx >= Entry.Length)
    return false;
  Idx += Entry.Offset;
  return (Data[Idx / 8] >> (Idx % 8)) & 1;
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind, const MCSubtargetInfo &STI) {
  CSKYOperand &Operand = (CSKYOperand &)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  case MCK_CSKYSymbol: {
    DiagnosticPredicate DP(Operand.isCSKYSymbol());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidCSKYSymbol;
    break;
  }
  case MCK_Constpool: {
    DiagnosticPredicate DP(Operand.isConstpool());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidConstpool;
    break;
  }
  case MCK_DataSymbol: {
    DiagnosticPredicate DP(Operand.isDataSymbol());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidConstpool;
    break;
  }
  case MCK_Imm: {
    DiagnosticPredicate DP(Operand.isImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_PSRFlag: {
    DiagnosticPredicate DP(Operand.isPSRFlag());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidPSRFlag;
    break;
  }
  case MCK_RegList: {
    DiagnosticPredicate DP(Operand.isRegList());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidRegList;
    break;
  }
  case MCK_UImm16: {
    DiagnosticPredicate DP(Operand.isUImm16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm16;
    break;
  }
  case MCK_UImm2: {
    DiagnosticPredicate DP(Operand.isUImm2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm2;
    break;
  }
  case MCK_OImm3: {
    DiagnosticPredicate DP(Operand.isOImm3());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidOImm3;
    break;
  }
  case MCK_OImm4: {
    DiagnosticPredicate DP(Operand.isOImm4());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidOImm4;
    break;
  }
  case MCK_OImm5: {
    DiagnosticPredicate DP(Operand.isOImm5());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidOImm5;
    break;
  }
  case MCK_OImm6: {
    DiagnosticPredicate DP(Operand.isOImm6());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidOImm6;
    break;
  }
  case MCK_OImm8: {
    DiagnosticPredicate DP(Operand.isOImm8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidOImm8;
    break;
  }
  case MCK_OImm12: {
    DiagnosticPredicate DP(Operand.isOImm12());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidOImm12;
    break;
  }
  case MCK_OImm16: {
    DiagnosticPredicate DP(Operand.isOImm16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidOImm16;
    break;
  }
  case MCK_UImm12: {
    DiagnosticPredicate DP(Operand.isUImm12());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm12;
    break;
  }
  case MCK_UImm1: {
    DiagnosticPredicate DP(Operand.isUImm1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm1;
    break;
  }
  case MCK_UImm3: {
    DiagnosticPredicate DP(Operand.isUImm3());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm3;
    break;
  }
  case MCK_UImm4: {
    DiagnosticPredicate DP(Operand.isUImm4());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm4;
    break;
  }
  case MCK_UImm5: {
    DiagnosticPredicate DP(Operand.isUImm5());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm5;
    break;
  }
  case MCK_UImm5Shift1: {
    DiagnosticPredicate DP(Operand.isUImm5Shift1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm5Shift1;
    break;
  }
  case MCK_UImm5Shift2: {
    DiagnosticPredicate DP(Operand.isUImm5Shift2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm5Shift2;
    break;
  }
  case MCK_UImm6: {
    DiagnosticPredicate DP(Operand.isUImm6());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm6;
    break;
  }
  case MCK_UImm7: {
    DiagnosticPredicate DP(Operand.isUImm7());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm7;
    break;
  }
  case MCK_UImm7Shift1: {
    DiagnosticPredicate DP(Operand.isUImm7Shift1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm7Shift1;
    break;
  }
  case MCK_UImm7Shift2: {
    DiagnosticPredicate DP(Operand.isUImm7Shift2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm7Shift2;
    break;
  }
  case MCK_UImm7Shift3: {
    DiagnosticPredicate DP(Operand.isUImm7Shift3());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm7Shift3;
    break;
  }
  case MCK_UImm8: {
    DiagnosticPredicate DP(Operand.isUImm8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm8;
    break;
  }
  case MCK_UImm8Shift2: {
    DiagnosticPredicate DP(Operand.isUImm8Shift2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm8Shift2;
    break;
  }
  case MCK_UImm8Shift3: {
    DiagnosticPredicate DP(Operand.isUImm8Shift3());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm8Shift3;
    break;
  }
  case MCK_UImm8Shift8: {
    DiagnosticPredicate DP(Operand.isUImm8Shift8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm8Shift8;
    break;
  }
  case MCK_UImm8Shift16: {
    DiagnosticPredicate DP(Operand.isUImm8Shift16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm8Shift16;
    break;
  }
  case MCK_UImm8Shift24: {
    DiagnosticPredicate DP(Operand.isUImm8Shift24());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm8Shift24;
    break;
  }
  case MCK_UImm12Shift1: {
    DiagnosticPredicate DP(Operand.isUImm12Shift1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm12Shift1;
    break;
  }
  case MCK_UImm12Shift2: {
    DiagnosticPredicate DP(Operand.isUImm12Shift2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm12Shift2;
    break;
  }
  case MCK_UImm16Shift8: {
    DiagnosticPredicate DP(Operand.isUImm16Shift8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm16Shift8;
    break;
  }
  case MCK_UImm16Shift16: {
    DiagnosticPredicate DP(Operand.isUImm16Shift16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm16Shift16;
    break;
  }
  case MCK_UImm20: {
    DiagnosticPredicate DP(Operand.isUImm20());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm20;
    break;
  }
  case MCK_UImm24: {
    DiagnosticPredicate DP(Operand.isUImm24());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm24;
    break;
  }
  case MCK_UImm24Shift8: {
    DiagnosticPredicate DP(Operand.isUImm24Shift8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidUImm24Shift8;
    break;
  }
  case MCK_SImm8: {
    DiagnosticPredicate DP(Operand.isSImm8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidSImm8;
    break;
  }
  case MCK_RegSeq: {
    DiagnosticPredicate DP(Operand.isRegSeq());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidRegSeq;
    break;
  }
  case MCK_RegSeqV1: {
    DiagnosticPredicate DP(Operand.isRegSeqV1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidRegSeq;
    break;
  }
  case MCK_RegSeqV2: {
    DiagnosticPredicate DP(Operand.isRegSeqV2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return CSKYAsmParser::Match_InvalidRegSeq;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg()) {
    static constexpr uint16_t Table[CSKY::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      MCK_CARRY,
      MCK_mGPR,
      MCK_mGPR,
      MCK_mGPR,
      MCK_mGPR,
      MCK_mGPR,
      MCK_mGPR,
      MCK_mGPR,
      MCK_mGPR,
      MCK_sGPR,
      MCK_sGPR,
      MCK_sGPR,
      MCK_sGPR,
      MCK_sGPR,
      MCK_sGPR,
      MCK_GPRSP,
      MCK_sGPR,
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
      InvalidMatchClass,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_sFPR32,
      MCK_sFPR64,
      MCK_sFPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_FPR32,
      MCK_FPR64,
      MCK_FPR128,
      MCK_Reg11,
      MCK_Reg11,
      MCK_Reg11,
      MCK_Reg11,
      MCK_Reg11,
      MCK_Reg11,
      MCK_Reg11,
      MCK_Reg12,
      MCK_Reg13,
      MCK_Reg13,
      MCK_Reg13,
      MCK_Reg13,
      MCK_Reg13,
      MCK_Reg17,
      MCK_Reg18,
      MCK_Reg14,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_Reg15,
      MCK_GPRPair,
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
  case MCK__40_: return "MCK__40_";
  case MCK__41_: return "MCK__41_";
  case MCK__LT_: return "MCK__LT_";
  case MCK__LT__LT_: return "MCK__LT__LT_";
  case MCK__GT_: return "MCK__GT_";
  case MCK_Reg18: return "MCK_Reg18";
  case MCK_Reg17: return "MCK_Reg17";
  case MCK_CARRY: return "MCK_CARRY";
  case MCK_GPRSP: return "MCK_GPRSP";
  case MCK_Reg11: return "MCK_Reg11";
  case MCK_Reg12: return "MCK_Reg12";
  case MCK_mGPR: return "MCK_mGPR";
  case MCK_Reg13: return "MCK_Reg13";
  case MCK_Reg14: return "MCK_Reg14";
  case MCK_sFPR128: return "MCK_sFPR128";
  case MCK_sFPR32: return "MCK_sFPR32";
  case MCK_sFPR64: return "MCK_sFPR64";
  case MCK_sGPR: return "MCK_sGPR";
  case MCK_Reg15: return "MCK_Reg15";
  case MCK_FPR128: return "MCK_FPR128";
  case MCK_FPR32: return "MCK_FPR32";
  case MCK_FPR64: return "MCK_FPR64";
  case MCK_GPR: return "MCK_GPR";
  case MCK_GPRPair: return "MCK_GPRPair";
  case MCK_CSKYSymbol: return "MCK_CSKYSymbol";
  case MCK_Constpool: return "MCK_Constpool";
  case MCK_DataSymbol: return "MCK_DataSymbol";
  case MCK_Imm: return "MCK_Imm";
  case MCK_PSRFlag: return "MCK_PSRFlag";
  case MCK_RegList: return "MCK_RegList";
  case MCK_UImm16: return "MCK_UImm16";
  case MCK_UImm2: return "MCK_UImm2";
  case MCK_OImm3: return "MCK_OImm3";
  case MCK_OImm4: return "MCK_OImm4";
  case MCK_OImm5: return "MCK_OImm5";
  case MCK_OImm6: return "MCK_OImm6";
  case MCK_OImm8: return "MCK_OImm8";
  case MCK_OImm12: return "MCK_OImm12";
  case MCK_OImm16: return "MCK_OImm16";
  case MCK_UImm12: return "MCK_UImm12";
  case MCK_UImm1: return "MCK_UImm1";
  case MCK_UImm3: return "MCK_UImm3";
  case MCK_UImm4: return "MCK_UImm4";
  case MCK_UImm5: return "MCK_UImm5";
  case MCK_UImm5Shift1: return "MCK_UImm5Shift1";
  case MCK_UImm5Shift2: return "MCK_UImm5Shift2";
  case MCK_UImm6: return "MCK_UImm6";
  case MCK_UImm7: return "MCK_UImm7";
  case MCK_UImm7Shift1: return "MCK_UImm7Shift1";
  case MCK_UImm7Shift2: return "MCK_UImm7Shift2";
  case MCK_UImm7Shift3: return "MCK_UImm7Shift3";
  case MCK_UImm8: return "MCK_UImm8";
  case MCK_UImm8Shift2: return "MCK_UImm8Shift2";
  case MCK_UImm8Shift3: return "MCK_UImm8Shift3";
  case MCK_UImm8Shift8: return "MCK_UImm8Shift8";
  case MCK_UImm8Shift16: return "MCK_UImm8Shift16";
  case MCK_UImm8Shift24: return "MCK_UImm8Shift24";
  case MCK_UImm12Shift1: return "MCK_UImm12Shift1";
  case MCK_UImm12Shift2: return "MCK_UImm12Shift2";
  case MCK_UImm16Shift8: return "MCK_UImm16Shift8";
  case MCK_UImm16Shift16: return "MCK_UImm16Shift16";
  case MCK_UImm20: return "MCK_UImm20";
  case MCK_UImm24: return "MCK_UImm24";
  case MCK_UImm24Shift8: return "MCK_UImm24Shift8";
  case MCK_SImm8: return "MCK_SImm8";
  case MCK_RegSeq: return "MCK_RegSeq";
  case MCK_RegSeqV1: return "MCK_RegSeqV1";
  case MCK_RegSeqV2: return "MCK_RegSeqV2";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset CSKYAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  if (FB[CSKY::FeatureFPUV2_SF])
    Features.set(Feature_HasFPUv2_SFBit);
  if (FB[CSKY::FeatureFPUV2_DF])
    Features.set(Feature_HasFPUv2_DFBit);
  if (FB[CSKY::FeatureFdivdu])
    Features.set(Feature_HasFdivduBit);
  if (FB[CSKY::FeatureFPUV3_HI])
    Features.set(Feature_HasFPUv3_HIBit);
  if (FB[CSKY::FeatureFPUV3_HF])
    Features.set(Feature_HasFPUv3_HFBit);
  if (FB[CSKY::FeatureFPUV3_SF])
    Features.set(Feature_HasFPUv3_SFBit);
  if (FB[CSKY::FeatureFPUV3_DF])
    Features.set(Feature_HasFPUv3_DFBit);
  if (FB[CSKY::HasFLOATE1])
    Features.set(Feature_iHasFLOATE1Bit);
  if (FB[CSKY::HasFLOAT1E2])
    Features.set(Feature_iHasFLOAT1E2Bit);
  if (FB[CSKY::HasFLOAT1E3])
    Features.set(Feature_iHasFLOAT1E3Bit);
  if (FB[CSKY::HasFLOAT3E4])
    Features.set(Feature_iHasFLOAT3E4Bit);
  if (FB[CSKY::HasFLOAT7E60])
    Features.set(Feature_iHasFLOAT7E60Bit);
  if (FB[CSKY::FeatureHWDiv])
    Features.set(Feature_HasHWDivBit);
  if (FB[CSKY::FeatureSTM])
    Features.set(Feature_HasSTMBit);
  if (FB[CSKY::FeaturePushPop])
    Features.set(Feature_HasPushPopBit);
  if (FB[CSKY::FeatureDSP])
    Features.set(Feature_HasDSPBit);
  if (FB[CSKY::HasDSP1E2])
    Features.set(Feature_iHasDSP1E2Bit);
  if (FB[CSKY::HasDSPE60])
    Features.set(Feature_iHasDSPE60Bit);
  if (FB[CSKY::FeatureDSPV2])
    Features.set(Feature_HasDSPV2Bit);
  if (FB[CSKY::FeatureDSP_Silan])
    Features.set(Feature_HasDSP_SilanBit);
  if (FB[CSKY::FeatureBTST16])
    Features.set(Feature_HasBTST16Bit);
  if (FB[CSKY::FeatureExtendLrw])
    Features.set(Feature_HasExtendLrwBit);
  if (FB[CSKY::FeatureTrust])
    Features.set(Feature_HasTrustBit);
  if (FB[CSKY::FeatureJAVA])
    Features.set(Feature_HasJAVABit);
  if (FB[CSKY::FeatureCache])
    Features.set(Feature_HasCacheBit);
  if (FB[CSKY::FeatureNVIC])
    Features.set(Feature_HasNVICBit);
  if (FB[CSKY::FeatureDoloop])
    Features.set(Feature_HasDoloopBit);
  if (FB[CSKY::FeatureHighreg])
    Features.set(Feature_HasHighRegistersBit);
  if (FB[CSKY::FeatureSmart])
    Features.set(Feature_SmartModeBit);
  if (FB[CSKY::FeatureVDSPV2])
    Features.set(Feature_HasVDSPV2Bit);
  if (FB[CSKY::HasVDSP2E3])
    Features.set(Feature_iHasVDSP2E3Bit);
  if (FB[CSKY::HasVDSP2E60F])
    Features.set(Feature_iHasVDSP2E60FBit);
  if (FB[CSKY::FeatureHardTP])
    Features.set(Feature_ReadTPHardBit);
  if (FB[CSKY::FeatureIstack])
    Features.set(Feature_EnableInterruptAttributeBit);
  if (FB[CSKY::FeatureConstPool])
    Features.set(Feature_DumpConstPoolBit);
  if (FB[CSKY::FeatureStackSize])
    Features.set(Feature_EnableStackSizeBit);
  if (FB[CSKY::FeatureCCRT])
    Features.set(Feature_UseCCRTBit);
  if (FB[CSKY::FeatureVDSPV1_128])
    Features.set(Feature_HasVDSPV1_128Bit);
  if (FB[CSKY::HasE1])
    Features.set(Feature_iHasE1Bit);
  if (FB[CSKY::HasE2])
    Features.set(Feature_iHasE2Bit);
  if (FB[CSKY::Has2E3])
    Features.set(Feature_iHas2E3Bit);
  if (FB[CSKY::HasMP])
    Features.set(Feature_iHasMPBit);
  if (FB[CSKY::Has3E3r1])
    Features.set(Feature_iHas3E3r1Bit);
  if (FB[CSKY::Has3r1E3r2])
    Features.set(Feature_iHas3r1E3r2Bit);
  if (FB[CSKY::Has3r2E3r3])
    Features.set(Feature_iHas3r2E3r3Bit);
  if (FB[CSKY::Has3E7])
    Features.set(Feature_iHas3E7Bit);
  if (FB[CSKY::HasMP1E2])
    Features.set(Feature_iHasMP1E2Bit);
  if (FB[CSKY::Has7E10])
    Features.set(Feature_iHas7E10Bit);
  if (FB[CSKY::Has10E60])
    Features.set(Feature_iHas10E60Bit);
  if (FB[CSKY::ProcCK801])
    Features.set(Feature_isCK801Bit);
  return Features;
}

static bool checkAsmTiedOperandConstraints(const CSKYAsmParser&AsmParser,
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
    "\005abs32\006addc16\006addc32\006addi16\006addi32\006addu16\006addu32\005"
    "and16\005and32\006andi32\006andn16\006andn32\007andni32\005asr16\005asr"
    "32\006asrc32\006asri16\006asri32\010bar.brar\tbar.brars\tbar.brarw\nbar"
    ".brarws\nbar.brwarw\013bar.brwarws\tbar.brwaw\nbar.brwaws\010bar.bwaw\t"
    "bar.bwaws\007bclri16\007bclri32\005bez32\004bf16\004bf32\005bgeni\007bg"
    "eni16\007bgeni32\007bgenr32\006bhsz32\005bhz32\004bkpt\006blsz32\005blz"
    "32\010bmaski32\006bnez32\010bnezad32\006bpop.h\006bpop.w\007bpush.h\007"
    "bpush.w\004br16\004br32\006brev32\007bseti16\007bseti32\003bsr\005bsr32"
    "\004bt16\004bt32\007btsti16\007btsti32\006clrc32\006clrf32\006clrt32\007"
    "cmphs16\007cmphs32\010cmphsi16\010cmphsi32\007cmplt16\007cmplt32\010cmp"
    "lti16\010cmplti32\007cmpne16\007cmpne32\010cmpnei16\010cmpnei32\006cpop"
    "32\006cprc32\007cprcr32\007cprgr32\007cpwcr32\007cpwgr32\015dcache32.ca"
    "ll\016dcache32.ciall\015dcache32.cisw\015dcache32.civa\014dcache32.csw\014"
    "dcache32.cva\016dcache32.cval1\015dcache32.iall\014dcache32.isw\014dcac"
    "he32.iva\006decf32\007decgt32\007declt32\007decne32\006dect32\006divs32"
    "\006divu32\006doze32\007fabs.32\007fabs.64\005fabsd\005fabsm\005fabss\007"
    "fadd.32\007fadd.64\005faddd\005faddm\005fadds\tfcmphs.32\tfcmphs.64\007"
    "fcmphsd\007fcmphss\nfcmphsz.32\nfcmphsz.64\tfcmphz.32\tfcmphz.64\nfcmpl"
    "sz.32\nfcmplsz.64\tfcmplt.32\tfcmplt.64\007fcmpltd\007fcmplts\nfcmpltz."
    "32\nfcmpltz.64\tfcmpne.32\tfcmpne.64\007fcmpned\007fcmpnes\nfcmpnez.32\n"
    "fcmpnez.64\tfcmpuo.32\tfcmpuo.64\007fcmpuod\007fcmpuos\nfcmpuoz.32\nfcm"
    "puoz.64\010fcmpzhsd\010fcmpzhss\010fcmpzlsd\010fcmpzlss\010fcmpzned\010"
    "fcmpznes\010fcmpzuod\010fcmpzuos\007fdiv.32\007fdiv.64\005fdivd\005fdiv"
    "s\005fdtos\tfdtosi.rn\nfdtosi.rni\nfdtosi.rpi\tfdtosi.rz\tfdtoui.rn\nfd"
    "toui.rni\nfdtoui.rpi\tfdtoui.rz\006ff0.32\006ff1.32\tffmula.32\tffmula."
    "64\tffmuls.32\tffmuls.64\nffnmula.32\nffnmula.64\nffnmuls.32\nffnmuls.6"
    "4\015fftofi.f32.rn\016fftofi.f32.rni\016fftofi.f32.rpi\015fftofi.f32.rz"
    "\015fftofi.f64.rn\016fftofi.f64.rni\016fftofi.f64.rpi\015fftofi.f64.rz\015"
    "fftoi.f32.s32\020fftoi.f32.s32.rn\021fftoi.f32.s32.rni\021fftoi.f32.s32"
    ".rpi\020fftoi.f32.s32.rz\015fftoi.f32.u32\020fftoi.f32.u32.rn\021fftoi."
    "f32.u32.rni\021fftoi.f32.u32.rpi\020fftoi.f32.u32.rz\015fftoi.f64.s32\020"
    "fftoi.f64.s32.rn\021fftoi.f64.s32.rni\021fftoi.f64.s32.rpi\020fftoi.f64"
    ".s32.rz\015fftoi.f64.u32\020fftoi.f64.u32.rn\021fftoi.f64.u32.rni\021ff"
    "toi.f64.u32.rpi\020fftoi.f64.u32.rz\015fftox.f32.s32\015fftox.f32.u32\015"
    "fftox.f64.s32\015fftox.f64.u32\007fins.32\015fitof.s32.f32\015fitof.s32"
    ".f64\015fitof.u32.f32\015fitof.u32.f64\006fld.32\006fld.64\004fldd\004f"
    "ldm\007fldm.32\007fldm.64\005fldmd\005fldmm\005fldms\010fldmu.32\010fld"
    "mu.64\007fldr.32\007fldr.64\005fldrd\005fldrm\005fldrs\004flds\007flrw."
    "32\007flrw.64\005fmacd\005fmacm\005fmacs\tfmaxnm.32\tfmaxnm.64\nfmfvr.3"
    "2.1\nfmfvr.32.2\010fmfvr.64\006fmfvrh\006fmfvrl\tfminnm.32\tfminnm.64\007"
    "fmov.32\007fmov.64\005fmovd\005fmovm\005fmovs\010fmovx.32\005fmscd\005f"
    "mscm\005fmscs\nfmtvr.32.1\nfmtvr.32.2\010fmtvr.64\006fmtvrh\006fmtvrl\007"
    "fmul.32\007fmul.64\010fmula.32\010fmula.64\005fmuld\005fmulm\005fmuls\010"
    "fmuls.32\010fmuls.64\007fneg.32\007fneg.64\005fnegd\005fnegm\005fnegs\006"
    "fnmacd\006fnmacm\006fnmacs\006fnmscd\006fnmscm\006fnmscs\010fnmul.32\010"
    "fnmul.64\tfnmula.32\tfnmula.64\006fnmuld\006fnmulm\006fnmuls\tfnmuls.32"
    "\tfnmuls.64\tfrecip.32\tfrecip.64\007frecipd\007frecips\007fsel.32\007f"
    "sel.64\006fsitod\006fsitos\010fsqrt.32\010fsqrt.64\006fsqrtd\006fsqrts\006"
    "fst.32\006fst.64\004fstd\004fstm\007fstm.32\007fstm.64\005fstmd\005fstm"
    "m\005fstms\010fstmu.32\010fstmu.64\005fstod\tfstosi.rn\nfstosi.rni\nfst"
    "osi.rpi\tfstosi.rz\tfstoui.rn\nfstoui.rni\nfstoui.rpi\tfstoui.rz\007fst"
    "r.32\007fstr.64\005fstrd\005fstrm\005fstrs\004fsts\007fsub.32\007fsub.6"
    "4\005fsubd\005fsubm\005fsubs\006fuitod\006fuitos\015fxtof.s32.f32\015fx"
    "tof.s32.f64\015fxtof.u32.f32\015fxtof.u32.f64\003grs\005grs32\015icache"
    "32.iall\016icache32.ialls\014icache32.iva\006idly32\006incf32\006inct32"
    "\005ins32\006ipop16\007ipush16\005ixd32\005ixh32\005ixw32\003jbf\003jbr"
    "\004jbsr\006jbsr32\003jbt\005jmp16\005jmp32\004jmpi\006jmpi32\007jmpix1"
    "6\005jsr16\005jsr32\004jsri\006jsri32\014l2cache.call\015l2cache.ciall\014"
    "l2cache.iall\006ld16.b\006ld16.h\006ld16.w\006ld32.b\007ld32.bs\006ld32"
    ".d\006ld32.h\007ld32.hs\006ld32.w\010ldex32.w\005ldm32\005ldq32\007ldr3"
    "2.b\010ldr32.bs\007ldr32.h\010ldr32.hs\007ldr32.w\007lrs32.b\007lrs32.h"
    "\007lrs32.w\003lrw\005lrw16\005lrw32\005lsl16\005lsl32\006lslc32\006lsl"
    "i16\006lsli32\005lsr16\005lsr32\006lsrc32\006lsri16\006lsri32\005mov16\006"
    "movi16\006movi32\007movih32\007mul.s32\007mul.u32\010mula.s32\010mula.u"
    "32\007mulsh16\007mulsh32\006mult16\006mult32\005mvc32\006mvcv16\006mvcv"
    "32\003nie\003nir\003nop\005nor16\005nor32\004or16\004or32\005ori32\006p"
    "ldr32\006pldw32\005pop16\006push16\006revb16\006revb32\006revh16\006rev"
    "h32\005rfi32\006rotl16\006rotl32\007rotli32\005sce32\004se32\006setc32\006"
    "sext32\007sextb16\007sexth16\007srs32.b\007srs32.h\007srs32.w\006st16.b"
    "\006st16.h\006st16.w\006st32.b\006st32.d\006st32.h\006st32.w\010stex32."
    "w\005stm32\006stop32\005stq32\007str32.b\007str32.h\007str32.w\006subc1"
    "6\006subc32\006subi16\006subi32\006subu16\006subu32\006sync32\010sync32"
    ".i\tsync32.is\010sync32.s\ntlbi32.all\013tlbi32.alls\013tlbi32.asid\014"
    "tlbi32.asids\ttlbi32.va\ntlbi32.vaa\013tlbi32.vaas\ntlbi32.vas\006trap3"
    "2\005tst16\005tst32\010tstnbz16\010tstnbz32\006wait32\004we32\005wsc32\005"
    "xor16\005xor32\006xori32\005xsr32\010xtrb0.32\010xtrb1.32\010xtrb2.32\010"
    "xtrb3.32\006zext32\007zextb16\007zexth16";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
  AMFBS_HasBTST16,
  AMFBS_HasExtendLrw,
  AMFBS_HasFPUv2_DF,
  AMFBS_HasFPUv2_SF,
  AMFBS_HasFPUv3_DF,
  AMFBS_HasFPUv3_SF,
  AMFBS_HasJAVA,
  AMFBS_iHas2E3,
  AMFBS_iHas3E3r1,
  AMFBS_iHas3r2E3r3,
  AMFBS_iHasE1,
  AMFBS_iHasE2,
  AMFBS_iHasMP1E2,
  AMFBS_iHas2E3_iHas10E60,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
  {Feature_HasBTST16Bit, }, // AMFBS_HasBTST16
  {Feature_HasExtendLrwBit, }, // AMFBS_HasExtendLrw
  {Feature_HasFPUv2_DFBit, }, // AMFBS_HasFPUv2_DF
  {Feature_HasFPUv2_SFBit, }, // AMFBS_HasFPUv2_SF
  {Feature_HasFPUv3_DFBit, }, // AMFBS_HasFPUv3_DF
  {Feature_HasFPUv3_SFBit, }, // AMFBS_HasFPUv3_SF
  {Feature_HasJAVABit, }, // AMFBS_HasJAVA
  {Feature_iHas2E3Bit, }, // AMFBS_iHas2E3
  {Feature_iHas3E3r1Bit, }, // AMFBS_iHas3E3r1
  {Feature_iHas3r2E3r3Bit, }, // AMFBS_iHas3r2E3r3
  {Feature_iHasE1Bit, }, // AMFBS_iHasE1
  {Feature_iHasE2Bit, }, // AMFBS_iHasE2
  {Feature_iHasMP1E2Bit, }, // AMFBS_iHasMP1E2
  {Feature_iHas2E3Bit, Feature_iHas10E60Bit, }, // AMFBS_iHas2E3_iHas10E60
};

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
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
  { 0 /* abs32 */, CSKY::ABS32, Convert__Reg1_0__Reg1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR }, },
  { 6 /* addc16 */, CSKY::ADDC16, Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__imm_95_0, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 13 /* addc32 */, CSKY::ADDC32, Convert__Reg1_0__imm_95_0__Reg1_1__Reg1_2__imm_95_0, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 20 /* addi16 */, CSKY::ADDI16, Convert__Reg1_0__Tie0_1_1__OImm81_1, AMFBS_None, { MCK_mGPR, MCK_OImm8 }, },
  { 20 /* addi16 */, CSKY::ADDI16SPSP, Convert__Reg1_0__Reg1_1__UImm7Shift21_2, AMFBS_None, { MCK_GPRSP, MCK_GPRSP, MCK_UImm7Shift2 }, },
  { 20 /* addi16 */, CSKY::ADDI16ZSP, Convert__Reg1_0__Reg1_1__UImm8Shift21_2, AMFBS_None, { MCK_mGPR, MCK_GPRSP, MCK_UImm8Shift2 }, },
  { 20 /* addi16 */, CSKY::ADDI16XZ, Convert__Reg1_0__Reg1_1__OImm31_2, AMFBS_None, { MCK_mGPR, MCK_mGPR, MCK_OImm3 }, },
  { 27 /* addi32 */, CSKY::ADDI32, Convert__Reg1_0__Reg1_1__OImm121_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_OImm12 }, },
  { 34 /* addu16 */, CSKY::ADDU16XZ, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 34 /* addu16 */, CSKY::ADDU16, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_mGPR, MCK_mGPR, MCK_mGPR }, },
  { 41 /* addu32 */, CSKY::ADDU32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 48 /* and16 */, CSKY::AND16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 54 /* and32 */, CSKY::AND32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 60 /* andi32 */, CSKY::ANDI32, Convert__Reg1_0__Reg1_1__UImm121_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm12 }, },
  { 67 /* andn16 */, CSKY::ANDN16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 74 /* andn32 */, CSKY::ANDN32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 81 /* andni32 */, CSKY::ANDNI32, Convert__Reg1_0__Reg1_1__UImm121_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm12 }, },
  { 89 /* asr16 */, CSKY::ASR16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 95 /* asr32 */, CSKY::ASR32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 101 /* asrc32 */, CSKY::ASRC32, Convert__Reg1_0__imm_95_0__Reg1_1__OImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_OImm5 }, },
  { 108 /* asri16 */, CSKY::ASRI16, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_mGPR, MCK_mGPR, MCK_UImm5 }, },
  { 115 /* asri32 */, CSKY::ASRI32, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 122 /* bar.brar */, CSKY::BRAR, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 131 /* bar.brars */, CSKY::BRARS, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 141 /* bar.brarw */, CSKY::BRARW, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 151 /* bar.brarws */, CSKY::BRARWS, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 162 /* bar.brwarw */, CSKY::BRWARW, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 173 /* bar.brwarws */, CSKY::BRWARWS, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 185 /* bar.brwaw */, CSKY::BRWAW, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 195 /* bar.brwaws */, CSKY::BRWAWS, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 206 /* bar.bwaw */, CSKY::BWAW, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 215 /* bar.bwaws */, CSKY::BWAWS, Convert_NoOperands, AMFBS_iHasMP1E2, {  }, },
  { 225 /* bclri16 */, CSKY::BCLRI16, Convert__Reg1_0__Tie0_1_1__UImm51_1, AMFBS_None, { MCK_mGPR, MCK_UImm5 }, },
  { 233 /* bclri32 */, CSKY::BCLRI32, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 241 /* bez32 */, CSKY::BEZ32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_CSKYSymbol }, },
  { 247 /* bf16 */, CSKY::BF16, Convert__imm_95_0__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 252 /* bf32 */, CSKY::BF32, Convert__imm_95_0__CSKYSymbol1_0, AMFBS_iHasE2, { MCK_CSKYSymbol }, },
  { 257 /* bgeni */, CSKY::BGENI, Convert__Reg1_0__UImm51_1, AMFBS_iHasE2, { MCK_GPR, MCK_UImm5 }, },
  { 263 /* bgeni16 */, CSKY::BGENI, Convert__Reg1_0__UImm51_1, AMFBS_None, { MCK_GPR, MCK_UImm5 }, },
  { 271 /* bgeni32 */, CSKY::BGENI, Convert__Reg1_0__UImm51_1, AMFBS_None, { MCK_GPR, MCK_UImm5 }, },
  { 279 /* bgenr32 */, CSKY::BGENR32, Convert__Reg1_0__Reg1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR }, },
  { 287 /* bhsz32 */, CSKY::BHSZ32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_CSKYSymbol }, },
  { 294 /* bhz32 */, CSKY::BHZ32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_CSKYSymbol }, },
  { 300 /* bkpt */, CSKY::BKPT, Convert_NoOperands, AMFBS_None, {  }, },
  { 305 /* blsz32 */, CSKY::BLSZ32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_CSKYSymbol }, },
  { 312 /* blz32 */, CSKY::BLZ32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_CSKYSymbol }, },
  { 318 /* bmaski32 */, CSKY::BMASKI32, Convert__Reg1_0__OImm51_1, AMFBS_iHasE2, { MCK_GPR, MCK_OImm5 }, },
  { 327 /* bnez32 */, CSKY::BNEZ32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_CSKYSymbol }, },
  { 334 /* bnezad32 */, CSKY::BNEZAD32, Convert__Reg1_0__Tie0_1_1__CSKYSymbol1_1, AMFBS_iHas2E3_iHas10E60, { MCK_GPR, MCK_CSKYSymbol }, },
  { 343 /* bpop.h */, CSKY::BPOPH, Convert__Reg1_0, AMFBS_HasJAVA, { MCK_mGPR }, },
  { 350 /* bpop.w */, CSKY::BPOPW, Convert__Reg1_0, AMFBS_HasJAVA, { MCK_mGPR }, },
  { 357 /* bpush.h */, CSKY::BPUSHH, Convert__Reg1_0, AMFBS_HasJAVA, { MCK_mGPR }, },
  { 365 /* bpush.w */, CSKY::BPUSHW, Convert__Reg1_0, AMFBS_HasJAVA, { MCK_mGPR }, },
  { 373 /* br16 */, CSKY::BR16, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 378 /* br32 */, CSKY::BR32, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 383 /* brev32 */, CSKY::BREV32, Convert__Reg1_0__Reg1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR }, },
  { 390 /* bseti16 */, CSKY::BSETI16, Convert__Reg1_0__Tie0_1_1__UImm51_1, AMFBS_None, { MCK_mGPR, MCK_UImm5 }, },
  { 398 /* bseti32 */, CSKY::BSETI32, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 406 /* bsr */, CSKY::BSR32, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 410 /* bsr32 */, CSKY::BSR32, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 416 /* bt16 */, CSKY::BT16, Convert__imm_95_0__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 421 /* bt32 */, CSKY::BT32, Convert__imm_95_0__CSKYSymbol1_0, AMFBS_iHasE2, { MCK_CSKYSymbol }, },
  { 426 /* btsti16 */, CSKY::BTSTI16, Convert__imm_95_0__Reg1_0__UImm51_1, AMFBS_HasBTST16, { MCK_mGPR, MCK_UImm5 }, },
  { 434 /* btsti32 */, CSKY::BTSTI32, Convert__imm_95_0__Reg1_0__UImm51_1, AMFBS_iHasE2, { MCK_GPR, MCK_UImm5 }, },
  { 442 /* clrc32 */, CSKY::CLRC32, Convert__imm_95_0, AMFBS_iHas2E3, {  }, },
  { 449 /* clrf32 */, CSKY::CLRF32, Convert__Reg1_0__imm_95_0__Tie0_1_1, AMFBS_iHas2E3, { MCK_GPR }, },
  { 456 /* clrt32 */, CSKY::CLRT32, Convert__Reg1_0__imm_95_0__Tie0_1_1, AMFBS_iHas2E3, { MCK_GPR }, },
  { 463 /* cmphs16 */, CSKY::CMPHS16, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 471 /* cmphs32 */, CSKY::CMPHS32, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR }, },
  { 479 /* cmphsi16 */, CSKY::CMPHSI16, Convert__imm_95_0__Reg1_0__OImm51_1, AMFBS_None, { MCK_mGPR, MCK_OImm5 }, },
  { 488 /* cmphsi32 */, CSKY::CMPHSI32, Convert__imm_95_0__Reg1_0__OImm161_1, AMFBS_iHasE2, { MCK_GPR, MCK_OImm16 }, },
  { 497 /* cmplt16 */, CSKY::CMPLT16, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 505 /* cmplt32 */, CSKY::CMPLT32, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR }, },
  { 513 /* cmplti16 */, CSKY::CMPLTI16, Convert__imm_95_0__Reg1_0__OImm51_1, AMFBS_None, { MCK_mGPR, MCK_OImm5 }, },
  { 522 /* cmplti32 */, CSKY::CMPLTI32, Convert__imm_95_0__Reg1_0__OImm161_1, AMFBS_iHasE2, { MCK_GPR, MCK_OImm16 }, },
  { 531 /* cmpne16 */, CSKY::CMPNE16, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 539 /* cmpne32 */, CSKY::CMPNE32, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR }, },
  { 547 /* cmpnei16 */, CSKY::CMPNEI16, Convert__imm_95_0__Reg1_0__UImm51_1, AMFBS_None, { MCK_mGPR, MCK_UImm5 }, },
  { 556 /* cmpnei32 */, CSKY::CMPNEI32, Convert__imm_95_0__Reg1_0__UImm161_1, AMFBS_iHasE2, { MCK_GPR, MCK_UImm16 }, },
  { 565 /* cpop32 */, CSKY::CPOP32, Convert__UImm51_1__UImm201_2, AMFBS_None, { MCK__LT_, MCK_UImm5, MCK_UImm20, MCK__GT_ }, },
  { 572 /* cprc32 */, CSKY::CPRC32, Convert__imm_95_0__UImm51_1__UImm121_2, AMFBS_None, { MCK__LT_, MCK_UImm5, MCK_UImm12, MCK__GT_ }, },
  { 579 /* cprcr32 */, CSKY::CPRCR32, Convert__Reg1_0__UImm51_2__UImm121_3, AMFBS_None, { MCK_GPR, MCK__LT_, MCK_UImm5, MCK_UImm12, MCK__GT_ }, },
  { 587 /* cprgr32 */, CSKY::CPRGR32, Convert__Reg1_0__UImm51_2__UImm121_3, AMFBS_None, { MCK_GPR, MCK__LT_, MCK_UImm5, MCK_UImm12, MCK__GT_ }, },
  { 595 /* cpwcr32 */, CSKY::CPWCR32, Convert__Reg1_0__UImm51_2__UImm121_3, AMFBS_None, { MCK_GPR, MCK__LT_, MCK_UImm5, MCK_UImm12, MCK__GT_ }, },
  { 603 /* cpwgr32 */, CSKY::CPWGR32, Convert__Reg1_0__UImm51_2__UImm121_3, AMFBS_None, { MCK_GPR, MCK__LT_, MCK_UImm5, MCK_UImm12, MCK__GT_ }, },
  { 611 /* dcache32.call */, CSKY::DCACHE_CALL32, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 625 /* dcache32.ciall */, CSKY::DCACHE_CIALL32, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 640 /* dcache32.cisw */, CSKY::DCACHE_CISW32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 654 /* dcache32.civa */, CSKY::DCACHE_CIVA32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 668 /* dcache32.csw */, CSKY::DCACHE_CSW32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 681 /* dcache32.cva */, CSKY::DCACHE_CVA32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 694 /* dcache32.cval1 */, CSKY::DCACHE_CVAL32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 709 /* dcache32.iall */, CSKY::DCACHE_IALL32, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 723 /* dcache32.isw */, CSKY::DCACHE_ISW32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 736 /* dcache32.iva */, CSKY::DCACHE_IVA32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 749 /* decf32 */, CSKY::DECF32, Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 756 /* decgt32 */, CSKY::DECGT32, Convert__Reg1_0__imm_95_0__Reg1_1__UImm51_2, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 764 /* declt32 */, CSKY::DECLT32, Convert__Reg1_0__imm_95_0__Reg1_1__UImm51_2, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 772 /* decne32 */, CSKY::DECNE32, Convert__Reg1_0__imm_95_0__Reg1_1__UImm51_2, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 780 /* dect32 */, CSKY::DECT32, Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 787 /* divs32 */, CSKY::DIVS32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 794 /* divu32 */, CSKY::DIVU32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 801 /* doze32 */, CSKY::DOZE32, Convert_NoOperands, AMFBS_None, {  }, },
  { 808 /* fabs.32 */, CSKY::f2FABS_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 816 /* fabs.64 */, CSKY::f2FABS_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64 }, },
  { 824 /* fabsd */, CSKY::FABS_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 830 /* fabsm */, CSKY::FABSM, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 836 /* fabss */, CSKY::FABS_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 842 /* fadd.32 */, CSKY::f2FADD_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 850 /* fadd.64 */, CSKY::f2FADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 858 /* faddd */, CSKY::FADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 864 /* faddm */, CSKY::FADDM, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 870 /* fadds */, CSKY::FADD_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32, MCK_sFPR32 }, },
  { 876 /* fcmphs.32 */, CSKY::f2FCMPHS_S, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 886 /* fcmphs.64 */, CSKY::f2FCMPHS_D, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64 }, },
  { 896 /* fcmphsd */, CSKY::FCMPHS_D, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 904 /* fcmphss */, CSKY::FCMPHS_S, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 912 /* fcmphsz.32 */, CSKY::f2FCMPHSZ_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_SF, { MCK_FPR32 }, },
  { 923 /* fcmphsz.64 */, CSKY::f2FCMPHSZ_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_DF, { MCK_FPR64 }, },
  { 934 /* fcmphz.32 */, CSKY::f2FCMPHZ_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_SF, { MCK_FPR32 }, },
  { 944 /* fcmphz.64 */, CSKY::f2FCMPHZ_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_DF, { MCK_FPR64 }, },
  { 954 /* fcmplsz.32 */, CSKY::f2FCMPLSZ_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_SF, { MCK_FPR32 }, },
  { 965 /* fcmplsz.64 */, CSKY::f2FCMPLSZ_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_DF, { MCK_FPR64 }, },
  { 976 /* fcmplt.32 */, CSKY::f2FCMPLT_S, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 986 /* fcmplt.64 */, CSKY::f2FCMPLT_D, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64 }, },
  { 996 /* fcmpltd */, CSKY::FCMPLT_D, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1004 /* fcmplts */, CSKY::FCMPLT_S, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 1012 /* fcmpltz.32 */, CSKY::f2FCMPLTZ_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_SF, { MCK_FPR32 }, },
  { 1023 /* fcmpltz.64 */, CSKY::f2FCMPLTZ_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_DF, { MCK_FPR64 }, },
  { 1034 /* fcmpne.32 */, CSKY::f2FCMPNE_S, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1044 /* fcmpne.64 */, CSKY::f2FCMPNE_D, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64 }, },
  { 1054 /* fcmpned */, CSKY::FCMPNE_D, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1062 /* fcmpnes */, CSKY::FCMPNE_S, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 1070 /* fcmpnez.32 */, CSKY::f2FCMPNEZ_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_SF, { MCK_FPR32 }, },
  { 1081 /* fcmpnez.64 */, CSKY::f2FCMPNEZ_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_DF, { MCK_FPR64 }, },
  { 1092 /* fcmpuo.32 */, CSKY::f2FCMPUO_S, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1102 /* fcmpuo.64 */, CSKY::f2FCMPUO_D, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64 }, },
  { 1112 /* fcmpuod */, CSKY::FCMPUO_D, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1120 /* fcmpuos */, CSKY::FCMPUO_S, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 1128 /* fcmpuoz.32 */, CSKY::f2FCMPUOZ_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_SF, { MCK_FPR32 }, },
  { 1139 /* fcmpuoz.64 */, CSKY::f2FCMPUOZ_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv3_DF, { MCK_FPR64 }, },
  { 1150 /* fcmpzhsd */, CSKY::FCMPZHS_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv2_DF, { MCK_sFPR64 }, },
  { 1159 /* fcmpzhss */, CSKY::FCMPZHS_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv2_SF, { MCK_sFPR32 }, },
  { 1168 /* fcmpzlsd */, CSKY::FCMPZLS_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv2_DF, { MCK_sFPR64 }, },
  { 1177 /* fcmpzlss */, CSKY::FCMPZLS_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv2_SF, { MCK_sFPR32 }, },
  { 1186 /* fcmpzned */, CSKY::FCMPZNE_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv2_DF, { MCK_sFPR64 }, },
  { 1195 /* fcmpznes */, CSKY::FCMPZNE_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv2_SF, { MCK_sFPR32 }, },
  { 1204 /* fcmpzuod */, CSKY::FCMPZUO_D, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv2_DF, { MCK_sFPR64 }, },
  { 1213 /* fcmpzuos */, CSKY::FCMPZUO_S, Convert__imm_95_0__Reg1_0, AMFBS_HasFPUv2_SF, { MCK_sFPR32 }, },
  { 1222 /* fdiv.32 */, CSKY::f2FDIV_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1230 /* fdiv.64 */, CSKY::f2FDIV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1238 /* fdivd */, CSKY::FDIV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 1244 /* fdivs */, CSKY::FDIV_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32, MCK_sFPR32 }, },
  { 1250 /* fdtos */, CSKY::FDTOS, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR32, MCK_sFPR64 }, },
  { 1250 /* fdtos */, CSKY::f2FDTOS, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1256 /* fdtosi.rn */, CSKY::rnFDTOSI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1266 /* fdtosi.rni */, CSKY::rniFDTOSI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1277 /* fdtosi.rpi */, CSKY::rpiFDTOSI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1288 /* fdtosi.rz */, CSKY::rzFDTOSI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1298 /* fdtoui.rn */, CSKY::rnFDTOUI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1308 /* fdtoui.rni */, CSKY::rniFDTOUI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1319 /* fdtoui.rpi */, CSKY::rpiFDTOUI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1330 /* fdtoui.rz */, CSKY::rzFDTOUI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 1340 /* ff0.32 */, CSKY::FF0, Convert__Reg1_0__Reg1_1, AMFBS_iHasE2, { MCK_GPR, MCK_GPR }, },
  { 1347 /* ff1.32 */, CSKY::FF1, Convert__Reg1_0__Reg1_1, AMFBS_iHasE2, { MCK_GPR, MCK_GPR }, },
  { 1354 /* ffmula.32 */, CSKY::f2FFMULA_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1364 /* ffmula.64 */, CSKY::f2FFMULA_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1374 /* ffmuls.32 */, CSKY::f2FFMULS_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1384 /* ffmuls.64 */, CSKY::f2FFMULS_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1394 /* ffnmula.32 */, CSKY::f2FFNMULA_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1405 /* ffnmula.64 */, CSKY::f2FFNMULA_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1416 /* ffnmuls.32 */, CSKY::f2FFNMULS_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1427 /* ffnmuls.64 */, CSKY::f2FFNMULS_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1438 /* fftofi.f32.rn */, CSKY::f2FF32TOFI32_RN, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1452 /* fftofi.f32.rni */, CSKY::f2FF32TOFI32_RNI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1467 /* fftofi.f32.rpi */, CSKY::f2FF32TOFI32_RPI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1482 /* fftofi.f32.rz */, CSKY::f2FF32TOFI32_RZ, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1496 /* fftofi.f64.rn */, CSKY::f2FF64TOFI32_RN, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR32 }, },
  { 1510 /* fftofi.f64.rni */, CSKY::f2FF64TOFI32_RNI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR32 }, },
  { 1525 /* fftofi.f64.rpi */, CSKY::f2FF64TOFI32_RPI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR32 }, },
  { 1540 /* fftofi.f64.rz */, CSKY::f2FF64TOFI32_RZ, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR32 }, },
  { 1554 /* fftoi.f32.s32 */, CSKY::f2FFTOS32_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1568 /* fftoi.f32.s32.rn */, CSKY::f2FF32TOSI32_RN, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1585 /* fftoi.f32.s32.rni */, CSKY::f2FF32TOSI32_RNI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1603 /* fftoi.f32.s32.rpi */, CSKY::f2FF32TOSI32_RPI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1621 /* fftoi.f32.s32.rz */, CSKY::f2FF32TOSI32_RZ, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1638 /* fftoi.f32.u32 */, CSKY::f2FFTOU32_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1652 /* fftoi.f32.u32.rn */, CSKY::f2FF32TOUI32_RN, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1669 /* fftoi.f32.u32.rni */, CSKY::f2FF32TOUI32_RNI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1687 /* fftoi.f32.u32.rpi */, CSKY::f2FF32TOUI32_RPI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1705 /* fftoi.f32.u32.rz */, CSKY::f2FF32TOUI32_RZ, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1722 /* fftoi.f64.s32 */, CSKY::f2FFTOS32_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1736 /* fftoi.f64.s32.rn */, CSKY::f2FF64TOSI32_RN, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1753 /* fftoi.f64.s32.rni */, CSKY::f2FF64TOSI32_RNI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1771 /* fftoi.f64.s32.rpi */, CSKY::f2FF64TOSI32_RPI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1789 /* fftoi.f64.s32.rz */, CSKY::f2FF64TOSI32_RZ, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1806 /* fftoi.f64.u32 */, CSKY::f2FFTOU32_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1820 /* fftoi.f64.u32.rn */, CSKY::f2FF64TOUI32_RN, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1837 /* fftoi.f64.u32.rni */, CSKY::f2FF64TOUI32_RNI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1855 /* fftoi.f64.u32.rpi */, CSKY::f2FF64TOUI32_RPI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1873 /* fftoi.f64.u32.rz */, CSKY::f2FF64TOUI32_RZ, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR64 }, },
  { 1890 /* fftox.f32.s32 */, CSKY::f2FFTOXS32_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1904 /* fftox.f32.u32 */, CSKY::f2FFTOXU32_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1918 /* fftox.f64.s32 */, CSKY::f2FFTOXS32_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR32 }, },
  { 1932 /* fftox.f64.u32 */, CSKY::f2FFTOXU32_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR32 }, },
  { 1946 /* fins.32 */, CSKY::f2FINS, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1954 /* fitof.s32.f32 */, CSKY::f2FS32TOF_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1968 /* fitof.s32.f64 */, CSKY::f2FS32TOF_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR32 }, },
  { 1982 /* fitof.u32.f32 */, CSKY::f2FU32TOF_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 1996 /* fitof.u32.f64 */, CSKY::f2FU32TOF_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR32 }, },
  { 2010 /* fld.32 */, CSKY::f2FLD_S, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK__40_, MCK_GPR, MCK_UImm8Shift2, MCK__41_ }, },
  { 2017 /* fld.64 */, CSKY::f2FLD_D, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK__40_, MCK_GPR, MCK_UImm8Shift2, MCK__41_ }, },
  { 2024 /* fldd */, CSKY::FLD_D, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK__40_, MCK_GPR, MCK_UImm8Shift2, MCK__41_ }, },
  { 2029 /* fldm */, CSKY::FLDM, Convert__Reg1_0__Reg1_2__UImm8Shift31_3, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK__40_, MCK_GPR, MCK_UImm8Shift3, MCK__41_ }, },
  { 2034 /* fldm.32 */, CSKY::f2FLDM_S, Convert__Reg1_2__RegSeqV22_0, AMFBS_HasFPUv3_SF, { MCK_RegSeqV2, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2042 /* fldm.64 */, CSKY::f2FLDM_D, Convert__Reg1_2__RegSeqV22_0, AMFBS_HasFPUv3_DF, { MCK_RegSeqV2, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2050 /* fldmd */, CSKY::FLDM_D, Convert__Reg1_2__RegSeqV12_0, AMFBS_HasFPUv2_DF, { MCK_RegSeqV1, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2056 /* fldmm */, CSKY::FLDMM, Convert__Reg1_2__RegSeqV12_0, AMFBS_HasFPUv2_DF, { MCK_RegSeqV1, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2062 /* fldms */, CSKY::FLDM_S, Convert__Reg1_2__RegSeqV12_0, AMFBS_None, { MCK_RegSeqV1, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2068 /* fldmu.32 */, CSKY::f2FLDMU_S, Convert__Reg1_2__RegSeqV22_0, AMFBS_HasFPUv3_SF, { MCK_RegSeqV2, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2077 /* fldmu.64 */, CSKY::f2FLDMU_D, Convert__Reg1_2__RegSeqV22_0, AMFBS_HasFPUv3_DF, { MCK_RegSeqV2, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2086 /* fldr.32 */, CSKY::f2FLDR_S, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2094 /* fldr.64 */, CSKY::f2FLDR_D, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2102 /* fldrd */, CSKY::FLDR_D, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2108 /* fldrm */, CSKY::FLDRM, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2114 /* fldrs */, CSKY::FLDR_S, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_None, { MCK_sFPR32, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2120 /* flds */, CSKY::FLD_S, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_None, { MCK_sFPR32, MCK__40_, MCK_GPR, MCK_UImm8Shift2, MCK__41_ }, },
  { 2125 /* flrw.32 */, CSKY::f2FLRW_S, Convert__Reg1_0__Constpool1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_Constpool }, },
  { 2133 /* flrw.64 */, CSKY::f2FLRW_D, Convert__Reg1_0__Constpool1_1, AMFBS_HasFPUv3_SF, { MCK_FPR64, MCK_Constpool }, },
  { 2141 /* fmacd */, CSKY::FMAC_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2147 /* fmacm */, CSKY::FMACM, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2153 /* fmacs */, CSKY::FMAC_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32, MCK_sFPR32 }, },
  { 2159 /* fmaxnm.32 */, CSKY::f2FMAXNM_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2169 /* fmaxnm.64 */, CSKY::f2FMAXNM_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2179 /* fmfvr.32.1 */, CSKY::f2FMFVRL, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_GPR, MCK_FPR32 }, },
  { 2190 /* fmfvr.32.2 */, CSKY::f2FMFVRL_2, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_GPR, MCK_GPR, MCK_FPR64 }, },
  { 2201 /* fmfvr.64 */, CSKY::f2FMFVR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_GPR, MCK_GPR, MCK_FPR64 }, },
  { 2210 /* fmfvrh */, CSKY::FMFVRH_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_GPR, MCK_sFPR64 }, },
  { 2210 /* fmfvrh */, CSKY::f2FMFVRH_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_GPR, MCK_FPR64 }, },
  { 2217 /* fmfvrl */, CSKY::FMFVRL, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_GPR, MCK_sFPR32 }, },
  { 2224 /* fminnm.32 */, CSKY::f2FMINNM_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2234 /* fminnm.64 */, CSKY::f2FMINNM_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2244 /* fmov.32 */, CSKY::f2FMOV_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 2252 /* fmov.64 */, CSKY::f2FMOV_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64 }, },
  { 2260 /* fmovd */, CSKY::FMOV_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 2266 /* fmovm */, CSKY::FMOVM, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 2272 /* fmovs */, CSKY::FMOV_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2278 /* fmovx.32 */, CSKY::f2FMOVX, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 2287 /* fmscd */, CSKY::FMSC_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2293 /* fmscm */, CSKY::FMSCM, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2299 /* fmscs */, CSKY::FMSC_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32, MCK_sFPR32 }, },
  { 2305 /* fmtvr.32.1 */, CSKY::f2FMTVRL, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_GPR }, },
  { 2316 /* fmtvr.32.2 */, CSKY::f2FMTVRL_2, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_GPR, MCK_GPR }, },
  { 2327 /* fmtvr.64 */, CSKY::f2FMTVR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_GPR, MCK_GPR }, },
  { 2336 /* fmtvrh */, CSKY::FMTVRH_D, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_GPR }, },
  { 2336 /* fmtvrh */, CSKY::f2FMTVRH_D, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_GPR }, },
  { 2343 /* fmtvrl */, CSKY::FMTVRL, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_GPR }, },
  { 2350 /* fmul.32 */, CSKY::f2FMUL_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2358 /* fmul.64 */, CSKY::f2FMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2366 /* fmula.32 */, CSKY::f2FMULA_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2375 /* fmula.64 */, CSKY::f2FMULA_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2384 /* fmuld */, CSKY::FMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2390 /* fmulm */, CSKY::FMULM, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2396 /* fmuls */, CSKY::FMUL_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32, MCK_sFPR32 }, },
  { 2402 /* fmuls.32 */, CSKY::f2FMULS_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2411 /* fmuls.64 */, CSKY::f2FMULS_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2420 /* fneg.32 */, CSKY::f2FNEG_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 2428 /* fneg.64 */, CSKY::f2FNEG_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64 }, },
  { 2436 /* fnegd */, CSKY::FNEG_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 2442 /* fnegm */, CSKY::FNEGM, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 2448 /* fnegs */, CSKY::FNEG_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2454 /* fnmacd */, CSKY::FNMAC_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2461 /* fnmacm */, CSKY::FNMACM, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2468 /* fnmacs */, CSKY::FNMAC_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32, MCK_sFPR32 }, },
  { 2475 /* fnmscd */, CSKY::FNMSC_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2482 /* fnmscm */, CSKY::FNMSCM, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2489 /* fnmscs */, CSKY::FNMSC_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32, MCK_sFPR32 }, },
  { 2496 /* fnmul.32 */, CSKY::f2FNMUL_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2505 /* fnmul.64 */, CSKY::f2FNMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2514 /* fnmula.32 */, CSKY::f2FNMULA_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2524 /* fnmula.64 */, CSKY::f2FNMULA_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2534 /* fnmuld */, CSKY::FNMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2541 /* fnmulm */, CSKY::FNMULM, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2548 /* fnmuls */, CSKY::FNMUL_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32, MCK_sFPR32 }, },
  { 2555 /* fnmuls.32 */, CSKY::f2FNMULS_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2565 /* fnmuls.64 */, CSKY::f2FNMULS_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2575 /* frecip.32 */, CSKY::f2RECIP_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 2585 /* frecip.64 */, CSKY::f2RECIP_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64 }, },
  { 2595 /* frecipd */, CSKY::FRECIP_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 2603 /* frecips */, CSKY::FRECIP_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2611 /* fsel.32 */, CSKY::f2FSEL_S, Convert__Reg1_0__imm_95_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2619 /* fsel.64 */, CSKY::f2FSEL_D, Convert__Reg1_0__imm_95_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2627 /* fsitod */, CSKY::FSITOD, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 2634 /* fsitos */, CSKY::FSITOS, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2641 /* fsqrt.32 */, CSKY::f2FSQRT_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 2650 /* fsqrt.64 */, CSKY::f2FSQRT_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64 }, },
  { 2659 /* fsqrtd */, CSKY::FSQRT_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 2666 /* fsqrts */, CSKY::FSQRT_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2673 /* fst.32 */, CSKY::f2FST_S, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK__40_, MCK_GPR, MCK_UImm8Shift2, MCK__41_ }, },
  { 2680 /* fst.64 */, CSKY::f2FST_D, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK__40_, MCK_GPR, MCK_UImm8Shift2, MCK__41_ }, },
  { 2687 /* fstd */, CSKY::FST_D, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK__40_, MCK_GPR, MCK_UImm8Shift2, MCK__41_ }, },
  { 2692 /* fstm */, CSKY::FSTM, Convert__Reg1_0__Reg1_2__UImm8Shift31_3, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK__40_, MCK_GPR, MCK_UImm8Shift3, MCK__41_ }, },
  { 2697 /* fstm.32 */, CSKY::f2FSTM_S, Convert__Reg1_2__RegSeqV22_0, AMFBS_HasFPUv3_SF, { MCK_RegSeqV2, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2705 /* fstm.64 */, CSKY::f2FSTM_D, Convert__Reg1_2__RegSeqV22_0, AMFBS_HasFPUv3_DF, { MCK_RegSeqV2, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2713 /* fstmd */, CSKY::FSTM_D, Convert__Reg1_2__RegSeqV12_0, AMFBS_HasFPUv2_DF, { MCK_RegSeqV1, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2719 /* fstmm */, CSKY::FSTMM, Convert__Reg1_2__RegSeqV12_0, AMFBS_HasFPUv2_DF, { MCK_RegSeqV1, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2725 /* fstms */, CSKY::FSTM_S, Convert__Reg1_2__RegSeqV12_0, AMFBS_None, { MCK_RegSeqV1, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2731 /* fstmu.32 */, CSKY::f2FSTMU_S, Convert__Reg1_2__RegSeqV22_0, AMFBS_HasFPUv3_SF, { MCK_RegSeqV2, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2740 /* fstmu.64 */, CSKY::f2FSTMU_D, Convert__Reg1_2__RegSeqV22_0, AMFBS_HasFPUv3_DF, { MCK_RegSeqV2, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2749 /* fstod */, CSKY::FSTOD, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR32 }, },
  { 2749 /* fstod */, CSKY::f2FSTOD, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR32 }, },
  { 2755 /* fstosi.rn */, CSKY::rnFSTOSI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2765 /* fstosi.rni */, CSKY::rniFSTOSI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2776 /* fstosi.rpi */, CSKY::rpiFSTOSI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2787 /* fstosi.rz */, CSKY::rzFSTOSI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2797 /* fstoui.rn */, CSKY::rnFSTOUI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2807 /* fstoui.rni */, CSKY::rniFSTOUI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2818 /* fstoui.rpi */, CSKY::rpiFSTOUI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2829 /* fstoui.rz */, CSKY::rzFSTOUI, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2839 /* fstr.32 */, CSKY::f2FSTR_S, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2847 /* fstr.64 */, CSKY::f2FSTR_D, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2855 /* fstrd */, CSKY::FSTR_D, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2861 /* fstrm */, CSKY::FSTRM, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2867 /* fstrs */, CSKY::FSTR_S, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_None, { MCK_sFPR32, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 2873 /* fsts */, CSKY::FST_S, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_None, { MCK_sFPR32, MCK__40_, MCK_GPR, MCK_UImm8Shift2, MCK__41_ }, },
  { 2878 /* fsub.32 */, CSKY::f2FSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2886 /* fsub.64 */, CSKY::f2FSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv3_DF, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2894 /* fsubd */, CSKY::FSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_DF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2900 /* fsubm */, CSKY::FSUBM, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64, MCK_sFPR64 }, },
  { 2906 /* fsubs */, CSKY::FSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32, MCK_sFPR32 }, },
  { 2912 /* fuitod */, CSKY::FUITOD, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR64, MCK_sFPR64 }, },
  { 2919 /* fuitos */, CSKY::FUITOS, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv2_SF, { MCK_sFPR32, MCK_sFPR32 }, },
  { 2926 /* fxtof.s32.f32 */, CSKY::f2FXTOFS32_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 2940 /* fxtof.s32.f64 */, CSKY::f2FXTOFS32_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR32 }, },
  { 2954 /* fxtof.u32.f32 */, CSKY::f2FXTOFU32_S, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_SF, { MCK_FPR32, MCK_FPR32 }, },
  { 2968 /* fxtof.u32.f64 */, CSKY::f2FXTOFU32_D, Convert__Reg1_0__Reg1_1, AMFBS_HasFPUv3_DF, { MCK_FPR32, MCK_FPR32 }, },
  { 2982 /* grs */, CSKY::GRS32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_None, { MCK_GPR, MCK_CSKYSymbol }, },
  { 2986 /* grs32 */, CSKY::GRS32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_CSKYSymbol }, },
  { 2992 /* icache32.iall */, CSKY::ICACHE_IALL32, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 3006 /* icache32.ialls */, CSKY::ICACHE_IALLS32, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 3021 /* icache32.iva */, CSKY::ICACHE_IVA32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 3034 /* idly32 */, CSKY::IDLY32, Convert__Imm1_0, AMFBS_HasExtendLrw, { MCK_Imm }, },
  { 3041 /* incf32 */, CSKY::INCF32, Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3048 /* inct32 */, CSKY::INCT32, Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3055 /* ins32 */, CSKY::INS32, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2__UImm51_3, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR, MCK_UImm5, MCK_UImm5 }, },
  { 3061 /* ipop16 */, CSKY::IPOP16, Convert_NoOperands, AMFBS_iHasE1, {  }, },
  { 3068 /* ipush16 */, CSKY::IPUSH16, Convert_NoOperands, AMFBS_iHasE1, {  }, },
  { 3076 /* ixd32 */, CSKY::IXD32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3082 /* ixh32 */, CSKY::IXH32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3088 /* ixw32 */, CSKY::IXW32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3094 /* jbf */, CSKY::JBF16, Convert__regC__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 3098 /* jbr */, CSKY::JBR16, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 3102 /* jbsr */, CSKY::JBSR32, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 3107 /* jbsr32 */, CSKY::JBSR32, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 3114 /* jbt */, CSKY::JBT16, Convert__regC__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 3118 /* jmp16 */, CSKY::JMP16, Convert__Reg1_0, AMFBS_None, { MCK_sGPR }, },
  { 3124 /* jmp32 */, CSKY::JMP32, Convert__Reg1_0, AMFBS_iHas2E3, { MCK_GPR }, },
  { 3130 /* jmpi */, CSKY::PseudoJMPI32, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 3130 /* jmpi */, CSKY::JMPI32, Convert__Constpool1_0, AMFBS_None, { MCK_Constpool }, },
  { 3135 /* jmpi32 */, CSKY::PseudoJMPI32, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 3135 /* jmpi32 */, CSKY::JMPI32, Convert__Constpool1_0, AMFBS_iHas2E3, { MCK_Constpool }, },
  { 3142 /* jmpix16 */, CSKY::JMPIX16, Convert__Reg1_0__Imm1_1, AMFBS_HasJAVA, { MCK_mGPR, MCK_Imm }, },
  { 3150 /* jsr16 */, CSKY::JSR16, Convert__Reg1_0, AMFBS_None, { MCK_sGPR }, },
  { 3156 /* jsr32 */, CSKY::JSR32, Convert__Reg1_0, AMFBS_iHas2E3, { MCK_GPR }, },
  { 3162 /* jsri */, CSKY::PseudoJSRI32, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 3162 /* jsri */, CSKY::JSRI32, Convert__Constpool1_0, AMFBS_None, { MCK_Constpool }, },
  { 3167 /* jsri32 */, CSKY::PseudoJSRI32, Convert__CSKYSymbol1_0, AMFBS_None, { MCK_CSKYSymbol }, },
  { 3167 /* jsri32 */, CSKY::JSRI32, Convert__Constpool1_0, AMFBS_iHas2E3, { MCK_Constpool }, },
  { 3174 /* l2cache.call */, CSKY::L2CACHE_CALL, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 3187 /* l2cache.ciall */, CSKY::L2CACHE_CIALL, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 3201 /* l2cache.iall */, CSKY::L2CACHE_IALL, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 3214 /* ld16.b */, CSKY::LD16B, Convert__Reg1_0__Reg1_2__UImm51_3, AMFBS_None, { MCK_mGPR, MCK__40_, MCK_mGPR, MCK_UImm5, MCK__41_ }, },
  { 3221 /* ld16.h */, CSKY::LD16H, Convert__Reg1_0__Reg1_2__UImm5Shift11_3, AMFBS_None, { MCK_mGPR, MCK__40_, MCK_mGPR, MCK_UImm5Shift1, MCK__41_ }, },
  { 3228 /* ld16.w */, CSKY::LD16WSP, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_None, { MCK_mGPR, MCK__40_, MCK_GPRSP, MCK_UImm8Shift2, MCK__41_ }, },
  { 3228 /* ld16.w */, CSKY::LD16W, Convert__Reg1_0__Reg1_2__UImm5Shift21_3, AMFBS_None, { MCK_mGPR, MCK__40_, MCK_mGPR, MCK_UImm5Shift2, MCK__41_ }, },
  { 3235 /* ld32.b */, CSKY::LD32B, Convert__Reg1_0__Reg1_2__UImm121_3, AMFBS_None, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12, MCK__41_ }, },
  { 3242 /* ld32.bs */, CSKY::LD32BS, Convert__Reg1_0__Reg1_2__UImm121_3, AMFBS_iHasE2, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12, MCK__41_ }, },
  { 3250 /* ld32.d */, CSKY::LD32D, Convert__Reg1_0__Reg1_2__UImm12Shift21_3, AMFBS_None, { MCK_GPRPair, MCK__40_, MCK_GPR, MCK_UImm12Shift2, MCK__41_ }, },
  { 3257 /* ld32.h */, CSKY::LD32H, Convert__Reg1_0__Reg1_2__UImm12Shift11_3, AMFBS_None, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12Shift1, MCK__41_ }, },
  { 3264 /* ld32.hs */, CSKY::LD32HS, Convert__Reg1_0__Reg1_2__UImm12Shift11_3, AMFBS_iHasE2, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12Shift1, MCK__41_ }, },
  { 3272 /* ld32.w */, CSKY::LD32W, Convert__Reg1_0__Reg1_2__UImm12Shift21_3, AMFBS_None, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12Shift2, MCK__41_ }, },
  { 3279 /* ldex32.w */, CSKY::LDEX32W, Convert__Reg1_0__Reg1_2__UImm12Shift21_3, AMFBS_iHasMP1E2, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12Shift2, MCK__41_ }, },
  { 3288 /* ldm32 */, CSKY::LDM32, Convert__Reg1_2__RegSeq2_0, AMFBS_iHasE2, { MCK_RegSeq, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 3294 /* ldq32 */, CSKY::LDQ32, Convert__Reg1_2__RegSeq2_0, AMFBS_iHasE2, { MCK_RegSeq, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 3300 /* ldr32.b */, CSKY::LDR32B, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_iHas2E3, { MCK_GPR, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 3308 /* ldr32.bs */, CSKY::LDR32BS, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_iHas2E3, { MCK_GPR, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 3317 /* ldr32.h */, CSKY::LDR32H, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_iHas2E3, { MCK_GPR, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 3325 /* ldr32.hs */, CSKY::LDR32HS, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_iHas2E3, { MCK_GPR, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 3334 /* ldr32.w */, CSKY::LDR32W, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_iHas2E3, { MCK_GPR, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 3342 /* lrs32.b */, CSKY::LRS32B, Convert__Reg1_0__Constpool1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_Constpool }, },
  { 3350 /* lrs32.h */, CSKY::LRS32H, Convert__Reg1_0__Constpool1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_Constpool }, },
  { 3358 /* lrs32.w */, CSKY::LRS32W, Convert__Reg1_0__DataSymbol1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_DataSymbol }, },
  { 3366 /* lrw */, CSKY::PseudoLRW16, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_None, { MCK_mGPR, MCK_CSKYSymbol }, },
  { 3366 /* lrw */, CSKY::LRW16, Convert__Reg1_0__Constpool1_1, AMFBS_None, { MCK_mGPR, MCK_Constpool }, },
  { 3366 /* lrw */, CSKY::PseudoLRW32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_None, { MCK_GPR, MCK_CSKYSymbol }, },
  { 3366 /* lrw */, CSKY::LRW32, Convert__Reg1_0__Constpool1_1, AMFBS_None, { MCK_GPR, MCK_Constpool }, },
  { 3370 /* lrw16 */, CSKY::PseudoLRW16, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_None, { MCK_mGPR, MCK_CSKYSymbol }, },
  { 3370 /* lrw16 */, CSKY::LRW16, Convert__Reg1_0__Constpool1_1, AMFBS_None, { MCK_mGPR, MCK_Constpool }, },
  { 3376 /* lrw32 */, CSKY::PseudoLRW32, Convert__Reg1_0__CSKYSymbol1_1, AMFBS_None, { MCK_GPR, MCK_CSKYSymbol }, },
  { 3376 /* lrw32 */, CSKY::LRW32, Convert__Reg1_0__Constpool1_1, AMFBS_None, { MCK_GPR, MCK_Constpool }, },
  { 3382 /* lsl16 */, CSKY::LSL16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3388 /* lsl32 */, CSKY::LSL32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3394 /* lslc32 */, CSKY::LSLC32, Convert__Reg1_0__imm_95_0__Reg1_1__OImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_OImm5 }, },
  { 3401 /* lsli16 */, CSKY::LSLI16, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_mGPR, MCK_mGPR, MCK_UImm5 }, },
  { 3408 /* lsli32 */, CSKY::LSLI32, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3415 /* lsr16 */, CSKY::LSR16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3421 /* lsr32 */, CSKY::LSR32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3427 /* lsrc32 */, CSKY::LSRC32, Convert__Reg1_0__imm_95_0__Reg1_1__OImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_OImm5 }, },
  { 3434 /* lsri16 */, CSKY::LSRI16, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_mGPR, MCK_mGPR, MCK_UImm5 }, },
  { 3441 /* lsri32 */, CSKY::LSRI32, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3448 /* mov16 */, CSKY::MOV16, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3454 /* movi16 */, CSKY::MOVI16, Convert__Reg1_0__UImm81_1, AMFBS_None, { MCK_mGPR, MCK_UImm8 }, },
  { 3461 /* movi32 */, CSKY::MOVI32, Convert__Reg1_0__UImm161_1, AMFBS_iHasE2, { MCK_GPR, MCK_UImm16 }, },
  { 3468 /* movih32 */, CSKY::MOVIH32, Convert__Reg1_0__UImm161_1, AMFBS_iHasE2, { MCK_GPR, MCK_UImm16 }, },
  { 3476 /* mul.s32 */, CSKY::MULTS32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHas3E3r1, { MCK_GPRPair, MCK_GPR, MCK_GPR }, },
  { 3484 /* mul.u32 */, CSKY::MULTU32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHas3E3r1, { MCK_GPRPair, MCK_GPR, MCK_GPR }, },
  { 3492 /* mula.s32 */, CSKY::MULATS32, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_iHas3E3r1, { MCK_GPRPair, MCK_GPR, MCK_GPR }, },
  { 3501 /* mula.u32 */, CSKY::MULATU32, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_iHas3E3r1, { MCK_GPRPair, MCK_GPR, MCK_GPR }, },
  { 3510 /* mulsh16 */, CSKY::MULSH16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3518 /* mulsh32 */, CSKY::MULSH32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3526 /* mult16 */, CSKY::MULT16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3533 /* mult32 */, CSKY::MULT32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3540 /* mvc32 */, CSKY::MVC32, Convert__Reg1_0__imm_95_0, AMFBS_iHasE2, { MCK_GPR }, },
  { 3546 /* mvcv16 */, CSKY::MVCV16, Convert__Reg1_0__imm_95_0, AMFBS_None, { MCK_sGPR }, },
  { 3553 /* mvcv32 */, CSKY::MVCV32, Convert__Reg1_0__imm_95_0, AMFBS_iHas2E3, { MCK_GPR }, },
  { 3560 /* nie */, CSKY::NIE, Convert_NoOperands, AMFBS_None, {  }, },
  { 3564 /* nir */, CSKY::NIR, Convert_NoOperands, AMFBS_None, {  }, },
  { 3568 /* nop */, CSKY::MOV32, Convert__regR0__regR0, AMFBS_iHasE2, {  }, },
  { 3568 /* nop */, CSKY::MOV16, Convert__regR0__regR0, AMFBS_None, {  }, },
  { 3572 /* nor16 */, CSKY::NOR16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3578 /* nor32 */, CSKY::NOR32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3584 /* or16 */, CSKY::OR16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3589 /* or32 */, CSKY::OR32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3594 /* ori32 */, CSKY::ORI32, Convert__Reg1_0__Reg1_1__UImm161_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm16 }, },
  { 3600 /* pldr32 */, CSKY::PLDR32, Convert__Reg1_1__UImm12Shift21_2, AMFBS_None, { MCK__40_, MCK_GPR, MCK_UImm12Shift2, MCK__41_ }, },
  { 3607 /* pldw32 */, CSKY::PLDW32, Convert__Reg1_1__UImm12Shift21_2, AMFBS_None, { MCK__40_, MCK_GPR, MCK_UImm12Shift2, MCK__41_ }, },
  { 3614 /* pop16 */, CSKY::POP16, Convert__RegList1_0, AMFBS_iHasE1, { MCK_RegList }, },
  { 3620 /* push16 */, CSKY::PUSH16, Convert__RegList1_0, AMFBS_iHasE1, { MCK_RegList }, },
  { 3627 /* revb16 */, CSKY::REVB16, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3634 /* revb32 */, CSKY::REVB32, Convert__Reg1_0__Reg1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR }, },
  { 3641 /* revh16 */, CSKY::REVH16, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3648 /* revh32 */, CSKY::REVH32, Convert__Reg1_0__Reg1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR }, },
  { 3655 /* rfi32 */, CSKY::RFI32, Convert_NoOperands, AMFBS_iHas2E3, {  }, },
  { 3661 /* rotl16 */, CSKY::ROTL16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3668 /* rotl32 */, CSKY::ROTL32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3675 /* rotli32 */, CSKY::ROTLI32, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3683 /* sce32 */, CSKY::SCE32, Convert__UImm41_0, AMFBS_iHas2E3, { MCK_UImm4 }, },
  { 3689 /* se32 */, CSKY::SE32, Convert_NoOperands, AMFBS_None, {  }, },
  { 3694 /* setc32 */, CSKY::SETC32, Convert__imm_95_0, AMFBS_iHas2E3, {  }, },
  { 3701 /* sext32 */, CSKY::SEXT32, Convert__Reg1_0__Reg1_1__UImm51_2__UImm51_3, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR, MCK_UImm5, MCK_UImm5 }, },
  { 3708 /* sextb16 */, CSKY::SEXTB16, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3716 /* sexth16 */, CSKY::SEXTH16, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3724 /* srs32.b */, CSKY::SRS32B, Convert__Reg1_0__Constpool1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_Constpool }, },
  { 3732 /* srs32.h */, CSKY::SRS32H, Convert__Reg1_0__Constpool1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_Constpool }, },
  { 3740 /* srs32.w */, CSKY::SRS32W, Convert__Reg1_0__DataSymbol1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_DataSymbol }, },
  { 3748 /* st16.b */, CSKY::ST16B, Convert__Reg1_0__Reg1_2__UImm51_3, AMFBS_None, { MCK_mGPR, MCK__40_, MCK_mGPR, MCK_UImm5, MCK__41_ }, },
  { 3755 /* st16.h */, CSKY::ST16H, Convert__Reg1_0__Reg1_2__UImm5Shift11_3, AMFBS_None, { MCK_mGPR, MCK__40_, MCK_mGPR, MCK_UImm5Shift1, MCK__41_ }, },
  { 3762 /* st16.w */, CSKY::ST16WSP, Convert__Reg1_0__Reg1_2__UImm8Shift21_3, AMFBS_None, { MCK_mGPR, MCK__40_, MCK_GPRSP, MCK_UImm8Shift2, MCK__41_ }, },
  { 3762 /* st16.w */, CSKY::ST16W, Convert__Reg1_0__Reg1_2__UImm5Shift21_3, AMFBS_None, { MCK_mGPR, MCK__40_, MCK_mGPR, MCK_UImm5Shift2, MCK__41_ }, },
  { 3769 /* st32.b */, CSKY::ST32B, Convert__Reg1_0__Reg1_2__UImm121_3, AMFBS_None, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12, MCK__41_ }, },
  { 3776 /* st32.d */, CSKY::ST32D, Convert__Reg1_0__Reg1_2__UImm12Shift21_3, AMFBS_None, { MCK_GPRPair, MCK__40_, MCK_GPR, MCK_UImm12Shift2, MCK__41_ }, },
  { 3783 /* st32.h */, CSKY::ST32H, Convert__Reg1_0__Reg1_2__UImm12Shift11_3, AMFBS_None, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12Shift1, MCK__41_ }, },
  { 3790 /* st32.w */, CSKY::ST32W, Convert__Reg1_0__Reg1_2__UImm12Shift21_3, AMFBS_None, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12Shift2, MCK__41_ }, },
  { 3797 /* stex32.w */, CSKY::STEX32W, Convert__Reg1_0__Tie0_1_1__Reg1_2__UImm12Shift21_3, AMFBS_iHasMP1E2, { MCK_GPR, MCK__40_, MCK_GPR, MCK_UImm12Shift2, MCK__41_ }, },
  { 3806 /* stm32 */, CSKY::STM32, Convert__Reg1_2__RegSeq2_0, AMFBS_iHasE2, { MCK_RegSeq, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 3812 /* stop32 */, CSKY::STOP32, Convert_NoOperands, AMFBS_None, {  }, },
  { 3819 /* stq32 */, CSKY::STQ32, Convert__Reg1_2__RegSeq2_0, AMFBS_iHasE2, { MCK_RegSeq, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 3825 /* str32.b */, CSKY::STR32B, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_iHas2E3, { MCK_GPR, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 3833 /* str32.h */, CSKY::STR32H, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_iHas2E3, { MCK_GPR, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 3841 /* str32.w */, CSKY::STR32W, Convert__Reg1_0__Reg1_2__Reg1_3__UImm21_5, AMFBS_iHas2E3, { MCK_GPR, MCK__40_, MCK_GPR, MCK_GPR, MCK__LT__LT_, MCK_UImm2, MCK__41_ }, },
  { 3849 /* subc16 */, CSKY::SUBC16, Convert__Reg1_0__imm_95_0__Tie0_1_1__Reg1_1__imm_95_0, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3856 /* subc32 */, CSKY::SUBC32, Convert__Reg1_0__imm_95_0__Reg1_1__Reg1_2__imm_95_0, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3863 /* subi16 */, CSKY::SUBI16, Convert__Reg1_0__Tie0_1_1__OImm81_1, AMFBS_None, { MCK_mGPR, MCK_OImm8 }, },
  { 3863 /* subi16 */, CSKY::SUBI16SPSP, Convert__Reg1_0__Reg1_1__UImm7Shift21_2, AMFBS_None, { MCK_GPRSP, MCK_GPRSP, MCK_UImm7Shift2 }, },
  { 3863 /* subi16 */, CSKY::SUBI16XZ, Convert__Reg1_0__Reg1_1__OImm31_2, AMFBS_None, { MCK_mGPR, MCK_mGPR, MCK_OImm3 }, },
  { 3870 /* subi32 */, CSKY::SUBI32, Convert__Reg1_0__Reg1_1__OImm121_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_OImm12 }, },
  { 3877 /* subu16 */, CSKY::SUBU16XZ, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 3877 /* subu16 */, CSKY::SUBU16, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_mGPR, MCK_mGPR, MCK_mGPR }, },
  { 3884 /* subu32 */, CSKY::SUBU32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3891 /* sync32 */, CSKY::SYNC0_32, Convert_NoOperands, AMFBS_None, {  }, },
  { 3891 /* sync32 */, CSKY::SYNC32, Convert__UImm51_0, AMFBS_None, { MCK_UImm5 }, },
  { 3898 /* sync32.i */, CSKY::SYNC_32_I, Convert_NoOperands, AMFBS_None, {  }, },
  { 3907 /* sync32.is */, CSKY::SYNC_32_IS, Convert_NoOperands, AMFBS_None, {  }, },
  { 3917 /* sync32.s */, CSKY::SYNC_32_S, Convert_NoOperands, AMFBS_None, {  }, },
  { 3926 /* tlbi32.all */, CSKY::TLBI_ALL32, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 3937 /* tlbi32.alls */, CSKY::TLBI_ALLS32, Convert_NoOperands, AMFBS_iHas3r2E3r3, {  }, },
  { 3949 /* tlbi32.asid */, CSKY::TLBI_ASID32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 3961 /* tlbi32.asids */, CSKY::TLBI_ASIDS32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 3974 /* tlbi32.va */, CSKY::TLBI_VA32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 3984 /* tlbi32.vaa */, CSKY::TLBI_VAA32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 3995 /* tlbi32.vaas */, CSKY::TLBI_VAAS32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 4007 /* tlbi32.vas */, CSKY::TLBI_VAS32, Convert__Reg1_0, AMFBS_iHas3r2E3r3, { MCK_GPR }, },
  { 4018 /* trap32 */, CSKY::TRAP32, Convert__UImm21_0, AMFBS_None, { MCK_UImm2 }, },
  { 4025 /* tst16 */, CSKY::TST16, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 4031 /* tst32 */, CSKY::TST32, Convert__imm_95_0__Reg1_0__Reg1_1, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR }, },
  { 4037 /* tstnbz16 */, CSKY::TSTNBZ16, Convert__imm_95_0__Reg1_0, AMFBS_None, { MCK_sGPR }, },
  { 4046 /* tstnbz32 */, CSKY::TSTNBZ32, Convert__imm_95_0__Reg1_0, AMFBS_iHas2E3, { MCK_GPR }, },
  { 4055 /* wait32 */, CSKY::WAIT32, Convert_NoOperands, AMFBS_None, {  }, },
  { 4062 /* we32 */, CSKY::WE32, Convert_NoOperands, AMFBS_None, {  }, },
  { 4067 /* wsc32 */, CSKY::WSC32, Convert_NoOperands, AMFBS_None, {  }, },
  { 4073 /* xor16 */, CSKY::XOR16, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 4079 /* xor32 */, CSKY::XOR32, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 4085 /* xori32 */, CSKY::XORI32, Convert__Reg1_0__Reg1_1__UImm121_2, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_UImm12 }, },
  { 4092 /* xsr32 */, CSKY::XSR32, Convert__Reg1_0__imm_95_0__Reg1_1__OImm51_2__imm_95_0, AMFBS_iHasE2, { MCK_GPR, MCK_GPR, MCK_OImm5 }, },
  { 4098 /* xtrb0.32 */, CSKY::XTRB0, Convert__Reg1_0__Reg1_1, AMFBS_iHasE2, { MCK_GPR, MCK_GPR }, },
  { 4107 /* xtrb1.32 */, CSKY::XTRB1, Convert__Reg1_0__Reg1_1, AMFBS_iHasE2, { MCK_GPR, MCK_GPR }, },
  { 4116 /* xtrb2.32 */, CSKY::XTRB2, Convert__Reg1_0__Reg1_1, AMFBS_iHasE2, { MCK_GPR, MCK_GPR }, },
  { 4125 /* xtrb3.32 */, CSKY::XTRB3, Convert__Reg1_0__Reg1_1, AMFBS_iHasE2, { MCK_GPR, MCK_GPR }, },
  { 4134 /* zext32 */, CSKY::ZEXT32, Convert__Reg1_0__Reg1_1__UImm51_2__UImm51_3, AMFBS_iHas2E3, { MCK_GPR, MCK_GPR, MCK_UImm5, MCK_UImm5 }, },
  { 4141 /* zextb16 */, CSKY::ZEXTB16, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
  { 4149 /* zexth16 */, CSKY::ZEXTH16, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_sGPR, MCK_sGPR }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned CSKYAsmParser::
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
  StringRef Mnemonic = ((CSKYOperand &)*Operands[0]).getToken();

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

static const OperandMatchEntry OperandMatchTable[66] = {
  /* Operand List Mnemonic, Mask, Operand Class, Features */
  { 241 /* bez32 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_iHas2E3 },
  { 247 /* bf16 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 252 /* bf32 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_iHasE2 },
  { 287 /* bhsz32 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_iHas2E3 },
  { 294 /* bhz32 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_iHas2E3 },
  { 305 /* blsz32 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_iHas2E3 },
  { 312 /* blz32 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_iHas2E3 },
  { 327 /* bnez32 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_iHas2E3 },
  { 334 /* bnezad32 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_iHas2E3_iHas10E60 },
  { 373 /* br16 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 378 /* br32 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 406 /* bsr */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 410 /* bsr32 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 416 /* bt16 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 421 /* bt32 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_iHasE2 },
  { 2034 /* fldm.32 */, 1 /* 0 */, MCK_RegSeqV2, AMFBS_HasFPUv3_SF },
  { 2042 /* fldm.64 */, 1 /* 0 */, MCK_RegSeqV2, AMFBS_HasFPUv3_DF },
  { 2050 /* fldmd */, 1 /* 0 */, MCK_RegSeqV1, AMFBS_HasFPUv2_DF },
  { 2056 /* fldmm */, 1 /* 0 */, MCK_RegSeqV1, AMFBS_HasFPUv2_DF },
  { 2062 /* fldms */, 1 /* 0 */, MCK_RegSeqV1, AMFBS_None },
  { 2068 /* fldmu.32 */, 1 /* 0 */, MCK_RegSeqV2, AMFBS_HasFPUv3_SF },
  { 2077 /* fldmu.64 */, 1 /* 0 */, MCK_RegSeqV2, AMFBS_HasFPUv3_DF },
  { 2125 /* flrw.32 */, 2 /* 1 */, MCK_Constpool, AMFBS_HasFPUv3_SF },
  { 2133 /* flrw.64 */, 2 /* 1 */, MCK_Constpool, AMFBS_HasFPUv3_SF },
  { 2697 /* fstm.32 */, 1 /* 0 */, MCK_RegSeqV2, AMFBS_HasFPUv3_SF },
  { 2705 /* fstm.64 */, 1 /* 0 */, MCK_RegSeqV2, AMFBS_HasFPUv3_DF },
  { 2713 /* fstmd */, 1 /* 0 */, MCK_RegSeqV1, AMFBS_HasFPUv2_DF },
  { 2719 /* fstmm */, 1 /* 0 */, MCK_RegSeqV1, AMFBS_HasFPUv2_DF },
  { 2725 /* fstms */, 1 /* 0 */, MCK_RegSeqV1, AMFBS_None },
  { 2731 /* fstmu.32 */, 1 /* 0 */, MCK_RegSeqV2, AMFBS_HasFPUv3_SF },
  { 2740 /* fstmu.64 */, 1 /* 0 */, MCK_RegSeqV2, AMFBS_HasFPUv3_DF },
  { 2982 /* grs */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_None },
  { 2986 /* grs32 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_iHas2E3 },
  { 3094 /* jbf */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 3098 /* jbr */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 3102 /* jbsr */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 3107 /* jbsr32 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 3114 /* jbt */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 3130 /* jmpi */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 3130 /* jmpi */, 1 /* 0 */, MCK_Constpool, AMFBS_None },
  { 3135 /* jmpi32 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 3135 /* jmpi32 */, 1 /* 0 */, MCK_Constpool, AMFBS_iHas2E3 },
  { 3162 /* jsri */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 3162 /* jsri */, 1 /* 0 */, MCK_Constpool, AMFBS_None },
  { 3167 /* jsri32 */, 1 /* 0 */, MCK_CSKYSymbol, AMFBS_None },
  { 3167 /* jsri32 */, 1 /* 0 */, MCK_Constpool, AMFBS_iHas2E3 },
  { 3288 /* ldm32 */, 1 /* 0 */, MCK_RegSeq, AMFBS_iHasE2 },
  { 3294 /* ldq32 */, 1 /* 0 */, MCK_RegSeq, AMFBS_iHasE2 },
  { 3342 /* lrs32.b */, 2 /* 1 */, MCK_Constpool, AMFBS_iHas2E3 },
  { 3350 /* lrs32.h */, 2 /* 1 */, MCK_Constpool, AMFBS_iHas2E3 },
  { 3358 /* lrs32.w */, 2 /* 1 */, MCK_DataSymbol, AMFBS_iHas2E3 },
  { 3366 /* lrw */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_None },
  { 3366 /* lrw */, 2 /* 1 */, MCK_Constpool, AMFBS_None },
  { 3366 /* lrw */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_None },
  { 3366 /* lrw */, 2 /* 1 */, MCK_Constpool, AMFBS_None },
  { 3370 /* lrw16 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_None },
  { 3370 /* lrw16 */, 2 /* 1 */, MCK_Constpool, AMFBS_None },
  { 3376 /* lrw32 */, 2 /* 1 */, MCK_CSKYSymbol, AMFBS_None },
  { 3376 /* lrw32 */, 2 /* 1 */, MCK_Constpool, AMFBS_None },
  { 3614 /* pop16 */, 1 /* 0 */, MCK_RegList, AMFBS_iHasE1 },
  { 3620 /* push16 */, 1 /* 0 */, MCK_RegList, AMFBS_iHasE1 },
  { 3724 /* srs32.b */, 2 /* 1 */, MCK_Constpool, AMFBS_iHas2E3 },
  { 3732 /* srs32.h */, 2 /* 1 */, MCK_Constpool, AMFBS_iHas2E3 },
  { 3740 /* srs32.w */, 2 /* 1 */, MCK_DataSymbol, AMFBS_iHas2E3 },
  { 3806 /* stm32 */, 1 /* 0 */, MCK_RegSeq, AMFBS_iHasE2 },
  { 3819 /* stq32 */, 1 /* 0 */, MCK_RegSeq, AMFBS_iHasE2 },
};

ParseStatus CSKYAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_CSKYSymbol:
    return parseCSKYSymbol(Operands);
  case MCK_Constpool:
    return parseConstpoolSymbol(Operands);
  case MCK_DataSymbol:
    return parseDataSymbol(Operands);
  case MCK_PSRFlag:
    return parsePSRFlag(Operands);
  case MCK_RegList:
    return parseRegList(Operands);
  case MCK_RegSeq:
    return parseRegSeq(Operands);
  case MCK_RegSeqV1:
    return parseRegSeq(Operands);
  case MCK_RegSeqV2:
    return parseRegSeq(Operands);
  default:
    return ParseStatus::NoMatch;
  }
  return ParseStatus::NoMatch;
}

ParseStatus CSKYAsmParser::
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

static std::string CSKYMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool CSKYCheckMnemonic(StringRef Mnemonic,
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

