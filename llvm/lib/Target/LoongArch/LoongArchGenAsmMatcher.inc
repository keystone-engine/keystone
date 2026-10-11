/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: LoongArch.td                                                         *|
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

  Match_InvalidBareSymbol,
  Match_InvalidImm32,
  Match_InvalidImm64,
  Match_InvalidSImm10,
  Match_InvalidSImm10lsl2,
  Match_InvalidSImm11lsl1,
  Match_InvalidSImm12,
  Match_InvalidSImm12addlike,
  Match_InvalidSImm12lu52id,
  Match_InvalidSImm13,
  Match_InvalidSImm14lsl2,
  Match_InvalidSImm16,
  Match_InvalidSImm16lsl2,
  Match_InvalidSImm20,
  Match_InvalidSImm20lu12iw,
  Match_InvalidSImm20lu32id,
  Match_InvalidSImm20pcaddi,
  Match_InvalidSImm20pcaddu12i,
  Match_InvalidSImm20pcaddu18i,
  Match_InvalidSImm20pcalau12i,
  Match_InvalidSImm21lsl2,
  Match_InvalidSImm26Operand,
  Match_InvalidSImm5,
  Match_InvalidSImm8,
  Match_InvalidSImm8lsl1,
  Match_InvalidSImm8lsl2,
  Match_InvalidSImm8lsl3,
  Match_InvalidSImm9lsl3,
  Match_InvalidTPRelAddSymbol,
  Match_InvalidUImm1,
  Match_InvalidUImm12,
  Match_InvalidUImm12ori,
  Match_InvalidUImm14,
  Match_InvalidUImm15,
  Match_InvalidUImm2,
  Match_InvalidUImm2plus1,
  Match_InvalidUImm3,
  Match_InvalidUImm4,
  Match_InvalidUImm5,
  Match_InvalidUImm6,
  Match_InvalidUImm7,
  Match_InvalidUImm8,
  END_OPERAND_DIAGNOSTIC_TYPES
#endif // GET_OPERAND_DIAGNOSTIC_TYPES


#ifdef GET_REGISTER_MATCHER
#undef GET_REGISTER_MATCHER

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_IsLA64Bit = 4,
  Feature_IsLA32Bit = 3,
  Feature_HasLaGlobalWithPcrelBit = 1,
  Feature_HasLaGlobalWithAbsBit = 0,
  Feature_HasLaLocalWithAbsBit = 2,
};

static MCRegister MatchRegisterName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 30 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 20 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return LoongArch::F0;	 // "f0"
      case '1':	 // 2 strings to match.
        return LoongArch::F1;	 // "f1"
      case '2':	 // 2 strings to match.
        return LoongArch::F2;	 // "f2"
      case '3':	 // 2 strings to match.
        return LoongArch::F3;	 // "f3"
      case '4':	 // 2 strings to match.
        return LoongArch::F4;	 // "f4"
      case '5':	 // 2 strings to match.
        return LoongArch::F5;	 // "f5"
      case '6':	 // 2 strings to match.
        return LoongArch::F6;	 // "f6"
      case '7':	 // 2 strings to match.
        return LoongArch::F7;	 // "f7"
      case '8':	 // 2 strings to match.
        return LoongArch::F8;	 // "f8"
      case '9':	 // 2 strings to match.
        return LoongArch::F9;	 // "f9"
      }
      break;
    case 'r':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return LoongArch::R0;	 // "r0"
      case '1':	 // 1 string to match.
        return LoongArch::R1;	 // "r1"
      case '2':	 // 1 string to match.
        return LoongArch::R2;	 // "r2"
      case '3':	 // 1 string to match.
        return LoongArch::R3;	 // "r3"
      case '4':	 // 1 string to match.
        return LoongArch::R4;	 // "r4"
      case '5':	 // 1 string to match.
        return LoongArch::R5;	 // "r5"
      case '6':	 // 1 string to match.
        return LoongArch::R6;	 // "r6"
      case '7':	 // 1 string to match.
        return LoongArch::R7;	 // "r7"
      case '8':	 // 1 string to match.
        return LoongArch::R8;	 // "r8"
      case '9':	 // 1 string to match.
        return LoongArch::R9;	 // "r9"
      }
      break;
    }
    break;
  case 3:	 // 86 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 44 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return LoongArch::F10;	 // "f10"
        case '1':	 // 2 strings to match.
          return LoongArch::F11;	 // "f11"
        case '2':	 // 2 strings to match.
          return LoongArch::F12;	 // "f12"
        case '3':	 // 2 strings to match.
          return LoongArch::F13;	 // "f13"
        case '4':	 // 2 strings to match.
          return LoongArch::F14;	 // "f14"
        case '5':	 // 2 strings to match.
          return LoongArch::F15;	 // "f15"
        case '6':	 // 2 strings to match.
          return LoongArch::F16;	 // "f16"
        case '7':	 // 2 strings to match.
          return LoongArch::F17;	 // "f17"
        case '8':	 // 2 strings to match.
          return LoongArch::F18;	 // "f18"
        case '9':	 // 2 strings to match.
          return LoongArch::F19;	 // "f19"
        }
        break;
      case '2':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return LoongArch::F20;	 // "f20"
        case '1':	 // 2 strings to match.
          return LoongArch::F21;	 // "f21"
        case '2':	 // 2 strings to match.
          return LoongArch::F22;	 // "f22"
        case '3':	 // 2 strings to match.
          return LoongArch::F23;	 // "f23"
        case '4':	 // 2 strings to match.
          return LoongArch::F24;	 // "f24"
        case '5':	 // 2 strings to match.
          return LoongArch::F25;	 // "f25"
        case '6':	 // 2 strings to match.
          return LoongArch::F26;	 // "f26"
        case '7':	 // 2 strings to match.
          return LoongArch::F27;	 // "f27"
        case '8':	 // 2 strings to match.
          return LoongArch::F28;	 // "f28"
        case '9':	 // 2 strings to match.
          return LoongArch::F29;	 // "f29"
        }
        break;
      case '3':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return LoongArch::F30;	 // "f30"
        case '1':	 // 2 strings to match.
          return LoongArch::F31;	 // "f31"
        }
        break;
      }
      break;
    case 'r':	 // 22 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return LoongArch::R10;	 // "r10"
        case '1':	 // 1 string to match.
          return LoongArch::R11;	 // "r11"
        case '2':	 // 1 string to match.
          return LoongArch::R12;	 // "r12"
        case '3':	 // 1 string to match.
          return LoongArch::R13;	 // "r13"
        case '4':	 // 1 string to match.
          return LoongArch::R14;	 // "r14"
        case '5':	 // 1 string to match.
          return LoongArch::R15;	 // "r15"
        case '6':	 // 1 string to match.
          return LoongArch::R16;	 // "r16"
        case '7':	 // 1 string to match.
          return LoongArch::R17;	 // "r17"
        case '8':	 // 1 string to match.
          return LoongArch::R18;	 // "r18"
        case '9':	 // 1 string to match.
          return LoongArch::R19;	 // "r19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return LoongArch::R20;	 // "r20"
        case '1':	 // 1 string to match.
          return LoongArch::R21;	 // "r21"
        case '2':	 // 1 string to match.
          return LoongArch::R22;	 // "r22"
        case '3':	 // 1 string to match.
          return LoongArch::R23;	 // "r23"
        case '4':	 // 1 string to match.
          return LoongArch::R24;	 // "r24"
        case '5':	 // 1 string to match.
          return LoongArch::R25;	 // "r25"
        case '6':	 // 1 string to match.
          return LoongArch::R26;	 // "r26"
        case '7':	 // 1 string to match.
          return LoongArch::R27;	 // "r27"
        case '8':	 // 1 string to match.
          return LoongArch::R28;	 // "r28"
        case '9':	 // 1 string to match.
          return LoongArch::R29;	 // "r29"
        }
        break;
      case '3':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return LoongArch::R30;	 // "r30"
        case '1':	 // 1 string to match.
          return LoongArch::R31;	 // "r31"
        }
        break;
      }
      break;
    case 'v':	 // 10 strings to match.
      if (Name[1] != 'r')
        break;
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        return LoongArch::VR0;	 // "vr0"
      case '1':	 // 1 string to match.
        return LoongArch::VR1;	 // "vr1"
      case '2':	 // 1 string to match.
        return LoongArch::VR2;	 // "vr2"
      case '3':	 // 1 string to match.
        return LoongArch::VR3;	 // "vr3"
      case '4':	 // 1 string to match.
        return LoongArch::VR4;	 // "vr4"
      case '5':	 // 1 string to match.
        return LoongArch::VR5;	 // "vr5"
      case '6':	 // 1 string to match.
        return LoongArch::VR6;	 // "vr6"
      case '7':	 // 1 string to match.
        return LoongArch::VR7;	 // "vr7"
      case '8':	 // 1 string to match.
        return LoongArch::VR8;	 // "vr8"
      case '9':	 // 1 string to match.
        return LoongArch::VR9;	 // "vr9"
      }
      break;
    case 'x':	 // 10 strings to match.
      if (Name[1] != 'r')
        break;
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        return LoongArch::XR0;	 // "xr0"
      case '1':	 // 1 string to match.
        return LoongArch::XR1;	 // "xr1"
      case '2':	 // 1 string to match.
        return LoongArch::XR2;	 // "xr2"
      case '3':	 // 1 string to match.
        return LoongArch::XR3;	 // "xr3"
      case '4':	 // 1 string to match.
        return LoongArch::XR4;	 // "xr4"
      case '5':	 // 1 string to match.
        return LoongArch::XR5;	 // "xr5"
      case '6':	 // 1 string to match.
        return LoongArch::XR6;	 // "xr6"
      case '7':	 // 1 string to match.
        return LoongArch::XR7;	 // "xr7"
      case '8':	 // 1 string to match.
        return LoongArch::XR8;	 // "xr8"
      case '9':	 // 1 string to match.
        return LoongArch::XR9;	 // "xr9"
      }
      break;
    }
    break;
  case 4:	 // 56 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 8 strings to match.
      if (memcmp(Name.data()+1, "cc", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 1 string to match.
        return LoongArch::FCC0;	 // "fcc0"
      case '1':	 // 1 string to match.
        return LoongArch::FCC1;	 // "fcc1"
      case '2':	 // 1 string to match.
        return LoongArch::FCC2;	 // "fcc2"
      case '3':	 // 1 string to match.
        return LoongArch::FCC3;	 // "fcc3"
      case '4':	 // 1 string to match.
        return LoongArch::FCC4;	 // "fcc4"
      case '5':	 // 1 string to match.
        return LoongArch::FCC5;	 // "fcc5"
      case '6':	 // 1 string to match.
        return LoongArch::FCC6;	 // "fcc6"
      case '7':	 // 1 string to match.
        return LoongArch::FCC7;	 // "fcc7"
      }
      break;
    case 's':	 // 4 strings to match.
      if (memcmp(Name.data()+1, "cr", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 1 string to match.
        return LoongArch::SCR0;	 // "scr0"
      case '1':	 // 1 string to match.
        return LoongArch::SCR1;	 // "scr1"
      case '2':	 // 1 string to match.
        return LoongArch::SCR2;	 // "scr2"
      case '3':	 // 1 string to match.
        return LoongArch::SCR3;	 // "scr3"
      }
      break;
    case 'v':	 // 22 strings to match.
      if (Name[1] != 'r')
        break;
      switch (Name[2]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return LoongArch::VR10;	 // "vr10"
        case '1':	 // 1 string to match.
          return LoongArch::VR11;	 // "vr11"
        case '2':	 // 1 string to match.
          return LoongArch::VR12;	 // "vr12"
        case '3':	 // 1 string to match.
          return LoongArch::VR13;	 // "vr13"
        case '4':	 // 1 string to match.
          return LoongArch::VR14;	 // "vr14"
        case '5':	 // 1 string to match.
          return LoongArch::VR15;	 // "vr15"
        case '6':	 // 1 string to match.
          return LoongArch::VR16;	 // "vr16"
        case '7':	 // 1 string to match.
          return LoongArch::VR17;	 // "vr17"
        case '8':	 // 1 string to match.
          return LoongArch::VR18;	 // "vr18"
        case '9':	 // 1 string to match.
          return LoongArch::VR19;	 // "vr19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return LoongArch::VR20;	 // "vr20"
        case '1':	 // 1 string to match.
          return LoongArch::VR21;	 // "vr21"
        case '2':	 // 1 string to match.
          return LoongArch::VR22;	 // "vr22"
        case '3':	 // 1 string to match.
          return LoongArch::VR23;	 // "vr23"
        case '4':	 // 1 string to match.
          return LoongArch::VR24;	 // "vr24"
        case '5':	 // 1 string to match.
          return LoongArch::VR25;	 // "vr25"
        case '6':	 // 1 string to match.
          return LoongArch::VR26;	 // "vr26"
        case '7':	 // 1 string to match.
          return LoongArch::VR27;	 // "vr27"
        case '8':	 // 1 string to match.
          return LoongArch::VR28;	 // "vr28"
        case '9':	 // 1 string to match.
          return LoongArch::VR29;	 // "vr29"
        }
        break;
      case '3':	 // 2 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return LoongArch::VR30;	 // "vr30"
        case '1':	 // 1 string to match.
          return LoongArch::VR31;	 // "vr31"
        }
        break;
      }
      break;
    case 'x':	 // 22 strings to match.
      if (Name[1] != 'r')
        break;
      switch (Name[2]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return LoongArch::XR10;	 // "xr10"
        case '1':	 // 1 string to match.
          return LoongArch::XR11;	 // "xr11"
        case '2':	 // 1 string to match.
          return LoongArch::XR12;	 // "xr12"
        case '3':	 // 1 string to match.
          return LoongArch::XR13;	 // "xr13"
        case '4':	 // 1 string to match.
          return LoongArch::XR14;	 // "xr14"
        case '5':	 // 1 string to match.
          return LoongArch::XR15;	 // "xr15"
        case '6':	 // 1 string to match.
          return LoongArch::XR16;	 // "xr16"
        case '7':	 // 1 string to match.
          return LoongArch::XR17;	 // "xr17"
        case '8':	 // 1 string to match.
          return LoongArch::XR18;	 // "xr18"
        case '9':	 // 1 string to match.
          return LoongArch::XR19;	 // "xr19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return LoongArch::XR20;	 // "xr20"
        case '1':	 // 1 string to match.
          return LoongArch::XR21;	 // "xr21"
        case '2':	 // 1 string to match.
          return LoongArch::XR22;	 // "xr22"
        case '3':	 // 1 string to match.
          return LoongArch::XR23;	 // "xr23"
        case '4':	 // 1 string to match.
          return LoongArch::XR24;	 // "xr24"
        case '5':	 // 1 string to match.
          return LoongArch::XR25;	 // "xr25"
        case '6':	 // 1 string to match.
          return LoongArch::XR26;	 // "xr26"
        case '7':	 // 1 string to match.
          return LoongArch::XR27;	 // "xr27"
        case '8':	 // 1 string to match.
          return LoongArch::XR28;	 // "xr28"
        case '9':	 // 1 string to match.
          return LoongArch::XR29;	 // "xr29"
        }
        break;
      case '3':	 // 2 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return LoongArch::XR30;	 // "xr30"
        case '1':	 // 1 string to match.
          return LoongArch::XR31;	 // "xr31"
        }
        break;
      }
      break;
    }
    break;
  case 5:	 // 4 strings to match.
    if (memcmp(Name.data()+0, "fcsr", 4) != 0)
      break;
    switch (Name[4]) {
    default: break;
    case '0':	 // 1 string to match.
      return LoongArch::FCSR0;	 // "fcsr0"
    case '1':	 // 1 string to match.
      return LoongArch::FCSR1;	 // "fcsr1"
    case '2':	 // 1 string to match.
      return LoongArch::FCSR2;	 // "fcsr2"
    case '3':	 // 1 string to match.
      return LoongArch::FCSR3;	 // "fcsr3"
    }
    break;
  }
  return LoongArch::NoRegister;
}

static MCRegister MatchRegisterAltName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 31 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 8 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return LoongArch::R4;	 // "a0"
      case '1':	 // 1 string to match.
        return LoongArch::R5;	 // "a1"
      case '2':	 // 1 string to match.
        return LoongArch::R6;	 // "a2"
      case '3':	 // 1 string to match.
        return LoongArch::R7;	 // "a3"
      case '4':	 // 1 string to match.
        return LoongArch::R8;	 // "a4"
      case '5':	 // 1 string to match.
        return LoongArch::R9;	 // "a5"
      case '6':	 // 1 string to match.
        return LoongArch::R10;	 // "a6"
      case '7':	 // 1 string to match.
        return LoongArch::R11;	 // "a7"
      }
      break;
    case 'f':	 // 1 string to match.
      if (Name[1] != 'p')
        break;
      return LoongArch::R22;	 // "fp"
    case 'r':	 // 1 string to match.
      if (Name[1] != 'a')
        break;
      return LoongArch::R1;	 // "ra"
    case 's':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return LoongArch::R23;	 // "s0"
      case '1':	 // 1 string to match.
        return LoongArch::R24;	 // "s1"
      case '2':	 // 1 string to match.
        return LoongArch::R25;	 // "s2"
      case '3':	 // 1 string to match.
        return LoongArch::R26;	 // "s3"
      case '4':	 // 1 string to match.
        return LoongArch::R27;	 // "s4"
      case '5':	 // 1 string to match.
        return LoongArch::R28;	 // "s5"
      case '6':	 // 1 string to match.
        return LoongArch::R29;	 // "s6"
      case '7':	 // 1 string to match.
        return LoongArch::R30;	 // "s7"
      case '8':	 // 1 string to match.
        return LoongArch::R31;	 // "s8"
      case '9':	 // 1 string to match.
        return LoongArch::R22;	 // "s9"
      case 'p':	 // 1 string to match.
        return LoongArch::R3;	 // "sp"
      }
      break;
    case 't':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return LoongArch::R12;	 // "t0"
      case '1':	 // 1 string to match.
        return LoongArch::R13;	 // "t1"
      case '2':	 // 1 string to match.
        return LoongArch::R14;	 // "t2"
      case '3':	 // 1 string to match.
        return LoongArch::R15;	 // "t3"
      case '4':	 // 1 string to match.
        return LoongArch::R16;	 // "t4"
      case '5':	 // 1 string to match.
        return LoongArch::R17;	 // "t5"
      case '6':	 // 1 string to match.
        return LoongArch::R18;	 // "t6"
      case '7':	 // 1 string to match.
        return LoongArch::R19;	 // "t7"
      case '8':	 // 1 string to match.
        return LoongArch::R20;	 // "t8"
      case 'p':	 // 1 string to match.
        return LoongArch::R2;	 // "tp"
      }
      break;
    }
    break;
  case 3:	 // 52 strings to match.
    if (Name[0] != 'f')
      break;
    switch (Name[1]) {
    default: break;
    case 'a':	 // 16 strings to match.
      switch (Name[2]) {
      default: break;
      case '0':	 // 2 strings to match.
        return LoongArch::F0;	 // "fa0"
      case '1':	 // 2 strings to match.
        return LoongArch::F1;	 // "fa1"
      case '2':	 // 2 strings to match.
        return LoongArch::F2;	 // "fa2"
      case '3':	 // 2 strings to match.
        return LoongArch::F3;	 // "fa3"
      case '4':	 // 2 strings to match.
        return LoongArch::F4;	 // "fa4"
      case '5':	 // 2 strings to match.
        return LoongArch::F5;	 // "fa5"
      case '6':	 // 2 strings to match.
        return LoongArch::F6;	 // "fa6"
      case '7':	 // 2 strings to match.
        return LoongArch::F7;	 // "fa7"
      }
      break;
    case 's':	 // 16 strings to match.
      switch (Name[2]) {
      default: break;
      case '0':	 // 2 strings to match.
        return LoongArch::F24;	 // "fs0"
      case '1':	 // 2 strings to match.
        return LoongArch::F25;	 // "fs1"
      case '2':	 // 2 strings to match.
        return LoongArch::F26;	 // "fs2"
      case '3':	 // 2 strings to match.
        return LoongArch::F27;	 // "fs3"
      case '4':	 // 2 strings to match.
        return LoongArch::F28;	 // "fs4"
      case '5':	 // 2 strings to match.
        return LoongArch::F29;	 // "fs5"
      case '6':	 // 2 strings to match.
        return LoongArch::F30;	 // "fs6"
      case '7':	 // 2 strings to match.
        return LoongArch::F31;	 // "fs7"
      }
      break;
    case 't':	 // 20 strings to match.
      switch (Name[2]) {
      default: break;
      case '0':	 // 2 strings to match.
        return LoongArch::F8;	 // "ft0"
      case '1':	 // 2 strings to match.
        return LoongArch::F9;	 // "ft1"
      case '2':	 // 2 strings to match.
        return LoongArch::F10;	 // "ft2"
      case '3':	 // 2 strings to match.
        return LoongArch::F11;	 // "ft3"
      case '4':	 // 2 strings to match.
        return LoongArch::F12;	 // "ft4"
      case '5':	 // 2 strings to match.
        return LoongArch::F13;	 // "ft5"
      case '6':	 // 2 strings to match.
        return LoongArch::F14;	 // "ft6"
      case '7':	 // 2 strings to match.
        return LoongArch::F15;	 // "ft7"
      case '8':	 // 2 strings to match.
        return LoongArch::F16;	 // "ft8"
      case '9':	 // 2 strings to match.
        return LoongArch::F17;	 // "ft9"
      }
      break;
    }
    break;
  case 4:	 // 13 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 12 strings to match.
      if (memcmp(Name.data()+1, "t1", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 2 strings to match.
        return LoongArch::F18;	 // "ft10"
      case '1':	 // 2 strings to match.
        return LoongArch::F19;	 // "ft11"
      case '2':	 // 2 strings to match.
        return LoongArch::F20;	 // "ft12"
      case '3':	 // 2 strings to match.
        return LoongArch::F21;	 // "ft13"
      case '4':	 // 2 strings to match.
        return LoongArch::F22;	 // "ft14"
      case '5':	 // 2 strings to match.
        return LoongArch::F23;	 // "ft15"
      }
      break;
    case 'z':	 // 1 string to match.
      if (memcmp(Name.data()+1, "ero", 3) != 0)
        break;
      return LoongArch::R0;	 // "zero"
    }
    break;
  }
  return LoongArch::NoRegister;
}

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_IsLA64Bit: return "LA64 Basic Integer and Privilege Instruction Set";
  case Feature_IsLA32Bit: return "LA32 Basic Integer and Privilege Instruction Set";
  case Feature_HasLaGlobalWithPcrelBit: return "Expand la.global as la.pcrel";
  case Feature_HasLaGlobalWithAbsBit: return "Expand la.global as la.abs";
  case Feature_HasLaLocalWithAbsBit: return "Expand la.local as la.abs";
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
  CVT_95_addImmOperands,
  CVT_95_addRegOperands,
  CVT_regR0,
  CVT_imm_95_0,
  CVT_regR1,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Reg1_0__Reg1_1__Reg1_2,
  Convert__Reg1_0__Reg1_1__Reg1_2__TPRelAddSymbol1_3,
  Convert__Reg1_0__Reg1_1__SImm12addlike1_2,
  Convert__Reg1_0__Reg1_1__SImm51_2,
  Convert__Reg1_0__Reg1_1__SImm161_2,
  Convert__Reg1_0__Reg1_1__Reg1_2__UImm2plus11_3,
  Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2,
  Convert__Reg1_0__Reg1_1__UImm121_2,
  Convert__Reg1_0__Reg1_1__UImm41_2,
  Convert__Reg1_0__UImm81_1,
  Convert__Reg1_0__UImm41_1,
  Convert__Reg1_0__UImm51_1__UImm41_2,
  Convert__Reg1_0__Reg1_1,
  Convert__SImm26OperandB1_0,
  Convert__Reg1_0__SImm21lsl21_1,
  Convert__Reg1_0__Reg1_1__SImm16lsl21_2,
  Convert__Reg1_0__regR0__SImm16lsl21_1,
  Convert__Reg1_1__Reg1_0__SImm16lsl21_2,
  Convert__regR0__Reg1_0__SImm16lsl21_1,
  Convert__SImm26OperandBL1_0,
  Convert__UImm151_0,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2__UImm61_3,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2__UImm51_3,
  Convert__Reg1_0__Reg1_1__UImm61_2__UImm61_3,
  Convert__Reg1_0__Reg1_1__UImm51_2__UImm51_3,
  Convert__Reg1_0__Reg1_1__Reg1_2__UImm31_3,
  Convert__Reg1_0__Reg1_1__Reg1_2__UImm21_3,
  Convert__UImm51_0__Reg1_1__SImm121_2,
  Convert__BareSymbol1_0,
  Convert__Reg1_0__UImm141_1,
  Convert__Reg1_0__Tie0_1_1__UImm141_1,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm141_2,
  Convert_NoOperands,
  Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3,
  Convert__Reg1_2__Reg1_1__UImm51_0,
  Convert__SImm21lsl21_0,
  Convert__regR0__Reg1_0__imm_95_0,
  Convert__Reg1_0__BareSymbol1_1,
  Convert__Reg1_0__imm_95_0__BareSymbol1_1,
  Convert__Reg1_0__Reg1_1__BareSymbol1_2,
  Convert__Reg1_0__Reg1_1__UImm81_2,
  Convert__Reg1_0__Reg1_1__SImm14lsl21_2,
  Convert__Reg1_0__Imm641_1,
  Convert__Reg1_0__Imm321_1,
  Convert__Reg1_0__SImm20lu12iw1_1,
  Convert__Reg1_0__Tie0_1_1__SImm20lu32id1_1,
  Convert__Reg1_0__Reg1_1__SImm12lu52id1_2,
  Convert__Reg1_0__Reg1_1__regR0,
  Convert__Reg1_0__Tie0_1_1__Reg1_1,
  Convert__regR0__regR0__imm_95_0,
  Convert__Reg1_0__Reg1_1__UImm12ori1_2,
  Convert__Reg1_0__SImm20pcaddi1_1,
  Convert__Reg1_0__SImm20pcaddu12i1_1,
  Convert__Reg1_0__SImm20pcaddu18i1_1,
  Convert__Reg1_0__SImm20pcalau12i1_1,
  Convert__UImm51_0__Reg1_1__Reg1_2,
  Convert__Reg1_0__Reg1_1__UImm31_2,
  Convert__Reg1_0__Reg1_1__UImm61_2,
  Convert__Reg1_0__Reg1_1__UImm51_2,
  Convert__regR0__Reg1_0,
  Convert__Reg1_0__regR0,
  Convert__regR0__regR1__imm_95_0,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__SImm14lsl21_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2,
  Convert__Reg1_0__Reg1_1__SImm121_2,
  Convert__UImm51_0,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm11_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm31_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm21_2,
  Convert__Reg1_0__SImm131_1,
  Convert__Reg1_0__Reg1_1__SImm9lsl31_2,
  Convert__Reg1_0__Reg1_1__SImm11lsl11_2,
  Convert__Reg1_0__Reg1_1__SImm10lsl21_2,
  Convert__Reg1_0__Reg1_1__UImm11_2,
  Convert__Reg1_0__Reg1_1__UImm21_2,
  Convert__Reg1_0__SImm101_1,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2,
  Convert__Reg1_0__Reg1_1__SImm81_2__UImm41_3,
  Convert__Reg1_0__Reg1_1__SImm8lsl31_2__UImm11_3,
  Convert__Reg1_0__Reg1_1__SImm8lsl11_2__UImm31_3,
  Convert__Reg1_0__Reg1_1__SImm8lsl21_2__UImm21_3,
  Convert__Reg1_0,
  Convert__UImm31_0,
  Convert__Reg1_0__UImm31_1,
  Convert__Reg1_0__UImm61_1,
  Convert__Reg1_0__UImm51_1,
  Convert__Reg1_0__UImm51_1__UImm81_2,
  Convert__Reg1_0__Reg1_1__SImm81_2__UImm51_3,
  Convert__Reg1_0__Reg1_1__SImm8lsl31_2__UImm21_3,
  Convert__Reg1_0__Reg1_1__SImm8lsl11_2__UImm41_3,
  Convert__Reg1_0__Reg1_1__SImm8lsl21_2__UImm31_3,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][11] = {
  // Convert__Reg1_0__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__TPRelAddSymbol1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm12addlike1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm51_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm161_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__UImm2plus11_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addRegOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addRegOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm121_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm41_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__UImm81_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__UImm41_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__UImm51_1__UImm41_2
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__SImm26OperandB1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__SImm21lsl21_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm16lsl21_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__regR0__SImm16lsl21_1
  { CVT_95_Reg, 1, CVT_regR0, 0, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_1__Reg1_0__SImm16lsl21_2
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__regR0__Reg1_0__SImm16lsl21_1
  { CVT_regR0, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__SImm26OperandBL1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__UImm151_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2__UImm61_3
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2__UImm51_3
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm61_2__UImm61_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm51_2__UImm51_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__UImm31_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__UImm21_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__UImm51_0__Reg1_1__SImm121_2
  { CVT_95_addImmOperands, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__BareSymbol1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__UImm141_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__UImm141_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm141_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_2__Reg1_1__UImm51_0
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__SImm21lsl21_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__regR0__Reg1_0__imm_95_0
  { CVT_regR0, 0, CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__BareSymbol1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__imm_95_0__BareSymbol1_1
  { CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__BareSymbol1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm81_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm14lsl21_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Imm641_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Imm321_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__SImm20lu12iw1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__SImm20lu32id1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm12lu52id1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__regR0
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_regR0, 0, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_Done },
  // Convert__regR0__regR0__imm_95_0
  { CVT_regR0, 0, CVT_regR0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm12ori1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__SImm20pcaddi1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__SImm20pcaddu12i1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__SImm20pcaddu18i1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__SImm20pcalau12i1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__UImm51_0__Reg1_1__Reg1_2
  { CVT_95_addImmOperands, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm31_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm61_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm51_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__regR0__Reg1_0
  { CVT_regR0, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__regR0
  { CVT_95_Reg, 1, CVT_regR0, 0, CVT_Done },
  // Convert__regR0__regR1__imm_95_0
  { CVT_regR0, 0, CVT_regR1, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__SImm14lsl21_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm121_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__UImm51_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm11_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm31_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm21_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__SImm131_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm9lsl31_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm11lsl11_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm10lsl21_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm11_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm21_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__SImm101_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm81_2__UImm41_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm8lsl31_2__UImm11_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm8lsl11_2__UImm31_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm8lsl21_2__UImm21_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__UImm31_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__UImm31_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__UImm61_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__UImm51_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__UImm51_1__UImm81_2
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm81_2__UImm51_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm8lsl31_2__UImm21_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm8lsl11_2__UImm41_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm8lsl21_2__UImm31_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
};

void LoongArchAsmParser::
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
      static_cast<LoongArchOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
      static_cast<LoongArchOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addImmOperands:
      static_cast<LoongArchOperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_addRegOperands:
      static_cast<LoongArchOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_regR0:
      Inst.addOperand(MCOperand::createReg(LoongArch::R0));
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_regR1:
      Inst.addOperand(MCOperand::createReg(LoongArch::R1));
      break;
    }
  }
}

void LoongArchAsmParser::
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
    case CVT_95_addRegOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
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
  MCK_FCSR, // register class 'FCSR'
  MCK_SCR, // register class 'SCR'
  MCK_CFR, // register class 'CFR'
  MCK_GPRT, // register class 'GPRT'
  MCK_GPRNoR0R1, // register class 'GPRNoR0R1'
  MCK_GPRJR, // register class 'GPRJR'
  MCK_FPR32, // register class 'FPR32'
  MCK_FPR64, // register class 'FPR64'
  MCK_GPR, // register class 'GPR'
  MCK_LASX256, // register class 'LASX256'
  MCK_LSX128, // register class 'LSX128'
  MCK_LAST_REGISTER = MCK_LSX128,
  MCK_AtomicMemAsmOperand, // user defined class 'AtomicMemAsmOperand'
  MCK_BareSymbol, // user defined class 'BareSymbol'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_SImm26OperandB, // user defined class 'SImm26OperandB'
  MCK_SImm26OperandBL, // user defined class 'SImm26OperandBL'
  MCK_TPRelAddSymbol, // user defined class 'TPRelAddSymbol'
  MCK_Imm32, // user defined class 'anonymous_13866'
  MCK_Imm64, // user defined class 'anonymous_13867'
  MCK_UImm1, // user defined class 'anonymous_13868'
  MCK_UImm2, // user defined class 'anonymous_13869'
  MCK_UImm2plus1, // user defined class 'anonymous_13870'
  MCK_UImm3, // user defined class 'anonymous_13871'
  MCK_UImm4, // user defined class 'anonymous_13872'
  MCK_UImm5, // user defined class 'anonymous_13873'
  MCK_UImm6, // user defined class 'anonymous_13874'
  MCK_UImm7, // user defined class 'anonymous_13875'
  MCK_UImm8, // user defined class 'anonymous_13876'
  MCK_UImm12, // user defined class 'anonymous_13877'
  MCK_UImm12ori, // user defined class 'anonymous_13878'
  MCK_UImm14, // user defined class 'anonymous_13879'
  MCK_UImm15, // user defined class 'anonymous_13880'
  MCK_SImm5, // user defined class 'anonymous_13881'
  MCK_SImm8, // user defined class 'anonymous_13882'
  MCK_SImm8lsl1, // user defined class 'anonymous_13883'
  MCK_SImm8lsl2, // user defined class 'anonymous_13884'
  MCK_SImm8lsl3, // user defined class 'anonymous_13885'
  MCK_SImm9lsl3, // user defined class 'anonymous_13886'
  MCK_SImm10, // user defined class 'anonymous_13887'
  MCK_SImm10lsl2, // user defined class 'anonymous_13888'
  MCK_SImm11lsl1, // user defined class 'anonymous_13889'
  MCK_SImm12, // user defined class 'anonymous_13890'
  MCK_SImm12addlike, // user defined class 'anonymous_13891'
  MCK_SImm12lu52id, // user defined class 'anonymous_13892'
  MCK_SImm13, // user defined class 'anonymous_13893'
  MCK_SImm14lsl2, // user defined class 'anonymous_13894'
  MCK_SImm16, // user defined class 'anonymous_13895'
  MCK_SImm16lsl2, // user defined class 'anonymous_13896'
  MCK_SImm20, // user defined class 'anonymous_13897'
  MCK_SImm20pcalau12i, // user defined class 'anonymous_13898'
  MCK_SImm20lu12iw, // user defined class 'anonymous_13899'
  MCK_SImm20lu32id, // user defined class 'anonymous_13900'
  MCK_SImm20pcaddu12i, // user defined class 'anonymous_13901'
  MCK_SImm20pcaddu18i, // user defined class 'anonymous_13902'
  MCK_SImm20pcaddi, // user defined class 'anonymous_13903'
  MCK_SImm21lsl2, // user defined class 'anonymous_13904'
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
    {0, 6, 5},
    {5, 7, 4},
    {9, 10, 1},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
    {10, 0, 0},
  };

  static constexpr uint8_t Data[] = {
    0x33,
    0x03,
  };

  auto &Entry = Table[A];
  unsigned Idx = B - Entry.Start;
  if (Idx >= Entry.Length)
    return false;
  Idx += Entry.Offset;
  return (Data[Idx / 8] >> (Idx % 8)) & 1;
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind, const MCSubtargetInfo &STI) {
  LoongArchOperand &Operand = (LoongArchOperand &)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  case MCK_AtomicMemAsmOperand: {
    DiagnosticPredicate DP(Operand.isGPR());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_BareSymbol: {
    DiagnosticPredicate DP(Operand.isBareSymbol());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidBareSymbol;
    break;
  }
  case MCK_Imm: {
    DiagnosticPredicate DP(Operand.isImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_SImm26OperandB: {
    DiagnosticPredicate DP(Operand.isSImm26Operand());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm26Operand;
    break;
  }
  case MCK_SImm26OperandBL: {
    DiagnosticPredicate DP(Operand.isSImm26Operand());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm26Operand;
    break;
  }
  case MCK_TPRelAddSymbol: {
    DiagnosticPredicate DP(Operand.isTPRelAddSymbol());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidTPRelAddSymbol;
    break;
  }
  case MCK_Imm32: {
    DiagnosticPredicate DP(Operand.isImm32());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidImm32;
    break;
  }
  case MCK_Imm64: {
    DiagnosticPredicate DP(Operand.isImm64());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidImm64;
    break;
  }
  case MCK_UImm1: {
    DiagnosticPredicate DP(Operand.isUImm1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm1;
    break;
  }
  case MCK_UImm2: {
    DiagnosticPredicate DP(Operand.isUImm2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm2;
    break;
  }
  case MCK_UImm2plus1: {
    DiagnosticPredicate DP(Operand.isUImm2plus1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm2plus1;
    break;
  }
  case MCK_UImm3: {
    DiagnosticPredicate DP(Operand.isUImm3());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm3;
    break;
  }
  case MCK_UImm4: {
    DiagnosticPredicate DP(Operand.isUImm4());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm4;
    break;
  }
  case MCK_UImm5: {
    DiagnosticPredicate DP(Operand.isUImm5());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm5;
    break;
  }
  case MCK_UImm6: {
    DiagnosticPredicate DP(Operand.isUImm6());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm6;
    break;
  }
  case MCK_UImm7: {
    DiagnosticPredicate DP(Operand.isUImm7());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm7;
    break;
  }
  case MCK_UImm8: {
    DiagnosticPredicate DP(Operand.isUImm8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm8;
    break;
  }
  case MCK_UImm12: {
    DiagnosticPredicate DP(Operand.isUImm12());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm12;
    break;
  }
  case MCK_UImm12ori: {
    DiagnosticPredicate DP(Operand.isUImm12ori());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm12ori;
    break;
  }
  case MCK_UImm14: {
    DiagnosticPredicate DP(Operand.isUImm14());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm14;
    break;
  }
  case MCK_UImm15: {
    DiagnosticPredicate DP(Operand.isUImm15());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidUImm15;
    break;
  }
  case MCK_SImm5: {
    DiagnosticPredicate DP(Operand.isSImm5());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm5;
    break;
  }
  case MCK_SImm8: {
    DiagnosticPredicate DP(Operand.isSImm8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm8;
    break;
  }
  case MCK_SImm8lsl1: {
    DiagnosticPredicate DP(Operand.isSImm8lsl1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm8lsl1;
    break;
  }
  case MCK_SImm8lsl2: {
    DiagnosticPredicate DP(Operand.isSImm8lsl2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm8lsl2;
    break;
  }
  case MCK_SImm8lsl3: {
    DiagnosticPredicate DP(Operand.isSImm8lsl3());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm8lsl3;
    break;
  }
  case MCK_SImm9lsl3: {
    DiagnosticPredicate DP(Operand.isSImm9lsl3());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm9lsl3;
    break;
  }
  case MCK_SImm10: {
    DiagnosticPredicate DP(Operand.isSImm10());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm10;
    break;
  }
  case MCK_SImm10lsl2: {
    DiagnosticPredicate DP(Operand.isSImm10lsl2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm10lsl2;
    break;
  }
  case MCK_SImm11lsl1: {
    DiagnosticPredicate DP(Operand.isSImm11lsl1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm11lsl1;
    break;
  }
  case MCK_SImm12: {
    DiagnosticPredicate DP(Operand.isSImm12());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm12;
    break;
  }
  case MCK_SImm12addlike: {
    DiagnosticPredicate DP(Operand.isSImm12addlike());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm12addlike;
    break;
  }
  case MCK_SImm12lu52id: {
    DiagnosticPredicate DP(Operand.isSImm12lu52id());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm12lu52id;
    break;
  }
  case MCK_SImm13: {
    DiagnosticPredicate DP(Operand.isSImm13());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm13;
    break;
  }
  case MCK_SImm14lsl2: {
    DiagnosticPredicate DP(Operand.isSImm14lsl2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm14lsl2;
    break;
  }
  case MCK_SImm16: {
    DiagnosticPredicate DP(Operand.isSImm16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm16;
    break;
  }
  case MCK_SImm16lsl2: {
    DiagnosticPredicate DP(Operand.isSImm16lsl2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm16lsl2;
    break;
  }
  case MCK_SImm20: {
    DiagnosticPredicate DP(Operand.isSImm20());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm20;
    break;
  }
  case MCK_SImm20pcalau12i: {
    DiagnosticPredicate DP(Operand.isSImm20pcalau12i());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm20pcalau12i;
    break;
  }
  case MCK_SImm20lu12iw: {
    DiagnosticPredicate DP(Operand.isSImm20lu12iw());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm20lu12iw;
    break;
  }
  case MCK_SImm20lu32id: {
    DiagnosticPredicate DP(Operand.isSImm20lu32id());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm20lu32id;
    break;
  }
  case MCK_SImm20pcaddu12i: {
    DiagnosticPredicate DP(Operand.isSImm20pcaddu12i());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm20pcaddu12i;
    break;
  }
  case MCK_SImm20pcaddu18i: {
    DiagnosticPredicate DP(Operand.isSImm20pcaddu18i());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm20pcaddu18i;
    break;
  }
  case MCK_SImm20pcaddi: {
    DiagnosticPredicate DP(Operand.isSImm20pcaddi());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm20pcaddi;
    break;
  }
  case MCK_SImm21lsl2: {
    DiagnosticPredicate DP(Operand.isSImm21lsl2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return LoongArchAsmParser::Match_InvalidSImm21lsl2;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg()) {
    static constexpr uint16_t Table[LoongArch::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_FPR32,
      MCK_CFR,
      MCK_CFR,
      MCK_CFR,
      MCK_CFR,
      MCK_CFR,
      MCK_CFR,
      MCK_CFR,
      MCK_CFR,
      MCK_FCSR,
      MCK_FCSR,
      MCK_FCSR,
      MCK_FCSR,
      MCK_GPRJR,
      MCK_GPR,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRT,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_GPRNoR0R1,
      MCK_SCR,
      MCK_SCR,
      MCK_SCR,
      MCK_SCR,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LSX128,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_LASX256,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
      MCK_FPR64,
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
  case MCK_FCSR: return "MCK_FCSR";
  case MCK_SCR: return "MCK_SCR";
  case MCK_CFR: return "MCK_CFR";
  case MCK_GPRT: return "MCK_GPRT";
  case MCK_GPRNoR0R1: return "MCK_GPRNoR0R1";
  case MCK_GPRJR: return "MCK_GPRJR";
  case MCK_FPR32: return "MCK_FPR32";
  case MCK_FPR64: return "MCK_FPR64";
  case MCK_GPR: return "MCK_GPR";
  case MCK_LASX256: return "MCK_LASX256";
  case MCK_LSX128: return "MCK_LSX128";
  case MCK_AtomicMemAsmOperand: return "MCK_AtomicMemAsmOperand";
  case MCK_BareSymbol: return "MCK_BareSymbol";
  case MCK_Imm: return "MCK_Imm";
  case MCK_SImm26OperandB: return "MCK_SImm26OperandB";
  case MCK_SImm26OperandBL: return "MCK_SImm26OperandBL";
  case MCK_TPRelAddSymbol: return "MCK_TPRelAddSymbol";
  case MCK_Imm32: return "MCK_Imm32";
  case MCK_Imm64: return "MCK_Imm64";
  case MCK_UImm1: return "MCK_UImm1";
  case MCK_UImm2: return "MCK_UImm2";
  case MCK_UImm2plus1: return "MCK_UImm2plus1";
  case MCK_UImm3: return "MCK_UImm3";
  case MCK_UImm4: return "MCK_UImm4";
  case MCK_UImm5: return "MCK_UImm5";
  case MCK_UImm6: return "MCK_UImm6";
  case MCK_UImm7: return "MCK_UImm7";
  case MCK_UImm8: return "MCK_UImm8";
  case MCK_UImm12: return "MCK_UImm12";
  case MCK_UImm12ori: return "MCK_UImm12ori";
  case MCK_UImm14: return "MCK_UImm14";
  case MCK_UImm15: return "MCK_UImm15";
  case MCK_SImm5: return "MCK_SImm5";
  case MCK_SImm8: return "MCK_SImm8";
  case MCK_SImm8lsl1: return "MCK_SImm8lsl1";
  case MCK_SImm8lsl2: return "MCK_SImm8lsl2";
  case MCK_SImm8lsl3: return "MCK_SImm8lsl3";
  case MCK_SImm9lsl3: return "MCK_SImm9lsl3";
  case MCK_SImm10: return "MCK_SImm10";
  case MCK_SImm10lsl2: return "MCK_SImm10lsl2";
  case MCK_SImm11lsl1: return "MCK_SImm11lsl1";
  case MCK_SImm12: return "MCK_SImm12";
  case MCK_SImm12addlike: return "MCK_SImm12addlike";
  case MCK_SImm12lu52id: return "MCK_SImm12lu52id";
  case MCK_SImm13: return "MCK_SImm13";
  case MCK_SImm14lsl2: return "MCK_SImm14lsl2";
  case MCK_SImm16: return "MCK_SImm16";
  case MCK_SImm16lsl2: return "MCK_SImm16lsl2";
  case MCK_SImm20: return "MCK_SImm20";
  case MCK_SImm20pcalau12i: return "MCK_SImm20pcalau12i";
  case MCK_SImm20lu12iw: return "MCK_SImm20lu12iw";
  case MCK_SImm20lu32id: return "MCK_SImm20lu32id";
  case MCK_SImm20pcaddu12i: return "MCK_SImm20pcaddu12i";
  case MCK_SImm20pcaddu18i: return "MCK_SImm20pcaddu18i";
  case MCK_SImm20pcaddi: return "MCK_SImm20pcaddi";
  case MCK_SImm21lsl2: return "MCK_SImm21lsl2";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset LoongArchAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  if (FB[LoongArch::Feature64Bit])
    Features.set(Feature_IsLA64Bit);
  if (!FB[LoongArch::Feature64Bit])
    Features.set(Feature_IsLA32Bit);
  if (FB[LoongArch::LaGlobalWithPcrel])
    Features.set(Feature_HasLaGlobalWithPcrelBit);
  if (FB[LoongArch::LaGlobalWithAbs])
    Features.set(Feature_HasLaGlobalWithAbsBit);
  if (FB[LoongArch::LaLocalWithAbs])
    Features.set(Feature_HasLaLocalWithAbsBit);
  return Features;
}

static bool checkAsmTiedOperandConstraints(const LoongArchAsmParser&AsmParser,
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
    "\005adc.b\005adc.d\005adc.h\005adc.w\005add.d\005add.w\006addi.d\006add"
    "i.w\taddu12i.d\taddu12i.w\taddu16i.d\006alsl.d\006alsl.w\007alsl.wu\007"
    "amadd.b\007amadd.d\007amadd.h\007amadd.w\namadd_db.b\namadd_db.d\namadd"
    "_db.h\namadd_db.w\007amand.d\007amand.w\namand_db.d\namand_db.w\007amca"
    "s.b\007amcas.d\007amcas.h\007amcas.w\namcas_db.b\namcas_db.d\namcas_db."
    "h\namcas_db.w\007ammax.d\010ammax.du\007ammax.w\010ammax.wu\nammax_db.d"
    "\013ammax_db.du\nammax_db.w\013ammax_db.wu\007ammin.d\010ammin.du\007am"
    "min.w\010ammin.wu\nammin_db.d\013ammin_db.du\nammin_db.w\013ammin_db.wu"
    "\006amor.d\006amor.w\tamor_db.d\tamor_db.w\010amswap.b\010amswap.d\010a"
    "mswap.h\010amswap.w\013amswap_db.b\013amswap_db.d\013amswap_db.h\013ams"
    "wap_db.w\007amxor.d\007amxor.w\namxor_db.d\namxor_db.w\003and\004andi\004"
    "andn\010armadc.w\010armadd.w\010armand.w\tarmmfflag\010armmov.d\010armm"
    "ov.w\007armmove\tarmmtflag\010armnot.w\007armor.w\tarmrotr.w\narmrotri."
    "w\010armrrx.w\010armsbc.w\010armsll.w\tarmslli.w\010armsra.w\tarmsrai.w"
    "\010armsrl.w\tarmsrli.w\010armsub.w\010armxor.w\010asrtgt.d\010asrtle.d"
    "\001b\005bceqz\005bcnez\003beq\004beqz\003bge\004bgeu\004bgez\003bgt\004"
    "bgtu\004bgtz\tbitrev.4b\tbitrev.8b\010bitrev.d\010bitrev.w\002bl\003ble"
    "\004bleu\004blez\003blt\004bltu\004bltz\003bne\004bnez\005break\tbstrin"
    "s.d\tbstrins.w\nbstrpick.d\nbstrpick.w\nbytepick.d\nbytepick.w\005cacop"
    "\004call\006call30\006call36\005clo.d\005clo.w\005clz.d\005clz.w\006cpu"
    "cfg\tcrc.w.b.w\tcrc.w.d.w\tcrc.w.h.w\tcrc.w.w.w\ncrcc.w.b.w\ncrcc.w.d.w"
    "\ncrcc.w.h.w\ncrcc.w.w.w\005csrrd\005csrwr\007csrxchg\005cto.d\005cto.w"
    "\005ctz.d\005ctz.w\004dbar\004dbcl\005div.d\006div.du\005div.w\006div.w"
    "u\004ertn\007ext.w.b\007ext.w.h\006fabs.d\006fabs.s\006fadd.d\006fadd.s"
    "\010fclass.d\010fclass.s\nfcmp.caf.d\nfcmp.caf.s\nfcmp.ceq.d\nfcmp.ceq."
    "s\nfcmp.cle.d\nfcmp.cle.s\nfcmp.clt.d\nfcmp.clt.s\nfcmp.cne.d\nfcmp.cne"
    ".s\nfcmp.cor.d\nfcmp.cor.s\013fcmp.cueq.d\013fcmp.cueq.s\013fcmp.cule.d"
    "\013fcmp.cule.s\013fcmp.cult.d\013fcmp.cult.s\nfcmp.cun.d\nfcmp.cun.s\013"
    "fcmp.cune.d\013fcmp.cune.s\nfcmp.saf.d\nfcmp.saf.s\nfcmp.seq.d\nfcmp.se"
    "q.s\nfcmp.sle.d\nfcmp.sle.s\nfcmp.slt.d\nfcmp.slt.s\nfcmp.sne.d\nfcmp.s"
    "ne.s\nfcmp.sor.d\nfcmp.sor.s\013fcmp.sueq.d\013fcmp.sueq.s\013fcmp.sule"
    ".d\013fcmp.sule.s\013fcmp.sult.d\013fcmp.sult.s\nfcmp.sun.d\nfcmp.sun.s"
    "\013fcmp.sune.d\013fcmp.sune.s\013fcopysign.d\013fcopysign.s\tfcvt.d.ld"
    "\010fcvt.d.s\tfcvt.ld.d\010fcvt.s.d\tfcvt.ud.d\006fdiv.d\006fdiv.s\tffi"
    "nt.d.l\tffint.d.w\tffint.s.l\tffint.s.w\005fld.d\005fld.s\007fldgt.d\007"
    "fldgt.s\007fldle.d\007fldle.s\006fldx.d\006fldx.s\007flogb.d\007flogb.s"
    "\007fmadd.d\007fmadd.s\006fmax.d\006fmax.s\007fmaxa.d\007fmaxa.s\006fmi"
    "n.d\006fmin.s\007fmina.d\007fmina.s\006fmov.d\006fmov.s\007fmsub.d\007f"
    "msub.s\006fmul.d\006fmul.s\006fneg.d\006fneg.s\010fnmadd.d\010fnmadd.s\010"
    "fnmsub.d\010fnmsub.s\010frecip.d\010frecip.s\tfrecipe.d\tfrecipe.s\007f"
    "rint.d\007frint.s\010frsqrt.d\010frsqrt.s\tfrsqrte.d\tfrsqrte.s\tfscale"
    "b.d\tfscaleb.s\004fsel\007fsqrt.d\007fsqrt.s\005fst.d\005fst.s\007fstgt"
    ".d\007fstgt.s\007fstle.d\007fstle.s\006fstx.d\006fstx.s\006fsub.d\006fs"
    "ub.s\tftint.l.d\tftint.l.s\tftint.w.d\tftint.w.s\013ftintrm.l.d\013ftin"
    "trm.l.s\013ftintrm.w.d\013ftintrm.w.s\014ftintrne.l.d\014ftintrne.l.s\014"
    "ftintrne.w.d\014ftintrne.w.s\013ftintrp.l.d\013ftintrp.l.s\013ftintrp.w"
    ".d\013ftintrp.w.s\013ftintrz.l.d\013ftintrz.l.s\013ftintrz.w.d\013ftint"
    "rz.w.s\006gcsrrd\006gcsrwr\010gcsrxchg\tgtlbflush\004hvcl\004ibar\004id"
    "le\006invtlb\tiocsrrd.b\tiocsrrd.d\tiocsrrd.h\tiocsrrd.w\tiocsrwr.b\tio"
    "csrwr.d\tiocsrwr.h\tiocsrwr.w\004jirl\006jiscr0\006jiscr1\002jr\002la\006"
    "la.abs\tla.global\006la.got\010la.local\010la.pcrel\013la.tls.desc\tla."
    "tls.gd\tla.tls.ie\tla.tls.ld\tla.tls.le\004ld.b\005ld.bu\004ld.d\004ld."
    "h\005ld.hu\004ld.w\005ld.wu\005lddir\006ldgt.b\006ldgt.d\006ldgt.h\006l"
    "dgt.w\005ldl.d\005ldl.w\006ldle.b\006ldle.d\006ldle.h\006ldle.w\005ldpt"
    "e\007ldptr.d\007ldptr.w\005ldr.d\005ldr.w\005ldx.b\006ldx.bu\005ldx.d\005"
    "ldx.h\006ldx.hu\005ldx.w\006ldx.wu\004li.d\004li.w\004ll.d\004ll.w\007l"
    "lacq.d\007llacq.w\007lu12i.w\007lu32i.d\007lu52i.d\007maskeqz\007maskne"
    "z\005mod.d\006mod.du\005mod.w\006mod.wu\010movcf2fr\010movcf2gr\004move"
    "\nmovfcsr2gr\010movfr2cf\nmovfr2gr.d\nmovfr2gr.s\013movfrh2gr.s\010movg"
    "r2cf\nmovgr2fcsr\nmovgr2fr.d\nmovgr2fr.w\013movgr2frh.w\tmovgr2scr\tmov"
    "scr2gr\005mul.d\005mul.w\006mulh.d\007mulh.du\006mulh.w\007mulh.wu\010m"
    "ulw.d.w\tmulw.d.wu\003nop\003nor\002or\003ori\003orn\006pcaddi\tpcaddu1"
    "2i\tpcaddu18i\tpcalau12i\005preld\006preldx\005rcr.b\005rcr.d\005rcr.h\005"
    "rcr.w\006rcri.b\006rcri.d\006rcri.h\006rcri.w\trdcntid.w\trdcntvh.w\trd"
    "cntvl.w\010rdtime.d\trdtimeh.w\trdtimel.w\003ret\007revb.2h\007revb.2w\007"
    "revb.4h\006revb.d\007revh.2w\006revh.d\006rotr.b\006rotr.d\006rotr.h\006"
    "rotr.w\007rotri.b\007rotri.d\007rotri.h\007rotri.w\005sbc.b\005sbc.d\005"
    "sbc.h\005sbc.w\004sc.d\004sc.q\004sc.w\007screl.d\007screl.w\007setarmj"
    "\007setx86j\013setx86loope\014setx86loopne\005sll.d\005sll.w\006slli.d\006"
    "slli.w\003slt\004slti\004sltu\005sltui\005sra.d\005sra.w\006srai.d\006s"
    "rai.w\005srl.d\005srl.w\006srli.d\006srli.w\004st.b\004st.d\004st.h\004"
    "st.w\006stgt.b\006stgt.d\006stgt.h\006stgt.w\005stl.d\005stl.w\006stle."
    "b\006stle.d\006stle.h\006stle.w\007stptr.d\007stptr.w\005str.d\005str.w"
    "\005stx.b\005stx.d\005stx.h\005stx.w\005sub.d\005sub.w\007syscall\004ta"
    "il\006tail30\006tail36\006tlbclr\007tlbfill\010tlbflush\005tlbrd\007tlb"
    "srch\005tlbwr\002ud\007vabsd.b\010vabsd.bu\007vabsd.d\010vabsd.du\007va"
    "bsd.h\010vabsd.hu\007vabsd.w\010vabsd.wu\006vadd.b\006vadd.d\006vadd.h\006"
    "vadd.q\006vadd.w\007vadda.b\007vadda.d\007vadda.h\007vadda.w\010vaddi.b"
    "u\010vaddi.du\010vaddi.hu\010vaddi.wu\013vaddwev.d.w\014vaddwev.d.wu\016"
    "vaddwev.d.wu.w\013vaddwev.h.b\014vaddwev.h.bu\016vaddwev.h.bu.b\013vadd"
    "wev.q.d\014vaddwev.q.du\016vaddwev.q.du.d\013vaddwev.w.h\014vaddwev.w.h"
    "u\016vaddwev.w.hu.h\013vaddwod.d.w\014vaddwod.d.wu\016vaddwod.d.wu.w\013"
    "vaddwod.h.b\014vaddwod.h.bu\016vaddwod.h.bu.b\013vaddwod.q.d\014vaddwod"
    ".q.du\016vaddwod.q.du.d\013vaddwod.w.h\014vaddwod.w.hu\016vaddwod.w.hu."
    "h\006vand.v\007vandi.b\007vandn.v\006vavg.b\007vavg.bu\006vavg.d\007vav"
    "g.du\006vavg.h\007vavg.hu\006vavg.w\007vavg.wu\007vavgr.b\010vavgr.bu\007"
    "vavgr.d\010vavgr.du\007vavgr.h\010vavgr.hu\007vavgr.w\010vavgr.wu\tvbit"
    "clr.b\tvbitclr.d\tvbitclr.h\tvbitclr.w\nvbitclri.b\nvbitclri.d\nvbitclr"
    "i.h\nvbitclri.w\tvbitrev.b\tvbitrev.d\tvbitrev.h\tvbitrev.w\nvbitrevi.b"
    "\nvbitrevi.d\nvbitrevi.h\nvbitrevi.w\tvbitsel.v\nvbitseli.b\tvbitset.b\t"
    "vbitset.d\tvbitset.h\tvbitset.w\nvbitseti.b\nvbitseti.d\nvbitseti.h\nvb"
    "itseti.w\007vbsll.v\007vbsrl.v\006vclo.b\006vclo.d\006vclo.h\006vclo.w\006"
    "vclz.b\006vclz.d\006vclz.h\006vclz.w\006vdiv.b\007vdiv.bu\006vdiv.d\007"
    "vdiv.du\006vdiv.h\007vdiv.hu\006vdiv.w\007vdiv.wu\013vext2xv.d.b\013vex"
    "t2xv.d.h\013vext2xv.d.w\015vext2xv.du.bu\015vext2xv.du.hu\015vext2xv.du"
    ".wu\013vext2xv.h.b\015vext2xv.hu.bu\013vext2xv.w.b\013vext2xv.w.h\015ve"
    "xt2xv.wu.bu\015vext2xv.wu.hu\tvexth.d.w\013vexth.du.wu\tvexth.h.b\013ve"
    "xth.hu.bu\tvexth.q.d\013vexth.qu.du\tvexth.w.h\013vexth.wu.hu\tvextl.q."
    "d\013vextl.qu.du\nvextrins.b\nvextrins.d\nvextrins.h\nvextrins.w\007vfa"
    "dd.d\007vfadd.s\tvfclass.d\tvfclass.s\013vfcmp.caf.d\013vfcmp.caf.s\013"
    "vfcmp.ceq.d\013vfcmp.ceq.s\013vfcmp.cle.d\013vfcmp.cle.s\013vfcmp.clt.d"
    "\013vfcmp.clt.s\013vfcmp.cne.d\013vfcmp.cne.s\013vfcmp.cor.d\013vfcmp.c"
    "or.s\014vfcmp.cueq.d\014vfcmp.cueq.s\014vfcmp.cule.d\014vfcmp.cule.s\014"
    "vfcmp.cult.d\014vfcmp.cult.s\013vfcmp.cun.d\013vfcmp.cun.s\014vfcmp.cun"
    "e.d\014vfcmp.cune.s\013vfcmp.saf.d\013vfcmp.saf.s\013vfcmp.seq.d\013vfc"
    "mp.seq.s\013vfcmp.sle.d\013vfcmp.sle.s\013vfcmp.slt.d\013vfcmp.slt.s\013"
    "vfcmp.sne.d\013vfcmp.sne.s\013vfcmp.sor.d\013vfcmp.sor.s\014vfcmp.sueq."
    "d\014vfcmp.sueq.s\014vfcmp.sule.d\014vfcmp.sule.s\014vfcmp.sult.d\014vf"
    "cmp.sult.s\013vfcmp.sun.d\013vfcmp.sun.s\014vfcmp.sune.d\014vfcmp.sune."
    "s\tvfcvt.h.s\tvfcvt.s.d\nvfcvth.d.s\nvfcvth.s.h\nvfcvtl.d.s\nvfcvtl.s.h"
    "\007vfdiv.d\007vfdiv.s\nvffint.d.l\013vffint.d.lu\nvffint.s.l\nvffint.s"
    ".w\013vffint.s.wu\013vffinth.d.w\013vffintl.d.w\010vflogb.d\010vflogb.s"
    "\010vfmadd.d\010vfmadd.s\007vfmax.d\007vfmax.s\010vfmaxa.d\010vfmaxa.s\007"
    "vfmin.d\007vfmin.s\010vfmina.d\010vfmina.s\010vfmsub.d\010vfmsub.s\007v"
    "fmul.d\007vfmul.s\tvfnmadd.d\tvfnmadd.s\tvfnmsub.d\tvfnmsub.s\tvfrecip."
    "d\tvfrecip.s\nvfrecipe.d\nvfrecipe.s\010vfrint.d\010vfrint.s\nvfrintrm."
    "d\nvfrintrm.s\013vfrintrne.d\013vfrintrne.s\nvfrintrp.d\nvfrintrp.s\nvf"
    "rintrz.d\nvfrintrz.s\tvfrsqrt.d\tvfrsqrt.s\nvfrsqrte.d\nvfrsqrte.s\010v"
    "frstp.b\010vfrstp.h\tvfrstpi.b\tvfrstpi.h\010vfsqrt.d\010vfsqrt.s\007vf"
    "sub.d\007vfsub.s\nvftint.l.d\013vftint.lu.d\nvftint.w.d\nvftint.w.s\013"
    "vftint.wu.s\013vftinth.l.s\013vftintl.l.s\014vftintrm.l.d\014vftintrm.w"
    ".d\014vftintrm.w.s\015vftintrmh.l.s\015vftintrml.l.s\015vftintrne.l.d\015"
    "vftintrne.w.d\015vftintrne.w.s\016vftintrneh.l.s\016vftintrnel.l.s\014v"
    "ftintrp.l.d\014vftintrp.w.d\014vftintrp.w.s\015vftintrph.l.s\015vftintr"
    "pl.l.s\014vftintrz.l.d\015vftintrz.lu.d\014vftintrz.w.d\014vftintrz.w.s"
    "\015vftintrz.wu.s\015vftintrzh.l.s\015vftintrzl.l.s\nvhaddw.d.w\014vhad"
    "dw.du.wu\nvhaddw.h.b\014vhaddw.hu.bu\nvhaddw.q.d\014vhaddw.qu.du\nvhadd"
    "w.w.h\014vhaddw.wu.hu\nvhsubw.d.w\014vhsubw.du.wu\nvhsubw.h.b\014vhsubw"
    ".hu.bu\nvhsubw.q.d\014vhsubw.qu.du\nvhsubw.w.h\014vhsubw.wu.hu\007vilvh"
    ".b\007vilvh.d\007vilvh.h\007vilvh.w\007vilvl.b\007vilvl.d\007vilvl.h\007"
    "vilvl.w\013vinsgr2vr.b\013vinsgr2vr.d\013vinsgr2vr.h\013vinsgr2vr.w\003"
    "vld\004vldi\tvldrepl.b\tvldrepl.d\tvldrepl.h\tvldrepl.w\004vldx\007vmad"
    "d.b\007vmadd.d\007vmadd.h\007vmadd.w\014vmaddwev.d.w\015vmaddwev.d.wu\017"
    "vmaddwev.d.wu.w\014vmaddwev.h.b\015vmaddwev.h.bu\017vmaddwev.h.bu.b\014"
    "vmaddwev.q.d\015vmaddwev.q.du\017vmaddwev.q.du.d\014vmaddwev.w.h\015vma"
    "ddwev.w.hu\017vmaddwev.w.hu.h\014vmaddwod.d.w\015vmaddwod.d.wu\017vmadd"
    "wod.d.wu.w\014vmaddwod.h.b\015vmaddwod.h.bu\017vmaddwod.h.bu.b\014vmadd"
    "wod.q.d\015vmaddwod.q.du\017vmaddwod.q.du.d\014vmaddwod.w.h\015vmaddwod"
    ".w.hu\017vmaddwod.w.hu.h\006vmax.b\007vmax.bu\006vmax.d\007vmax.du\006v"
    "max.h\007vmax.hu\006vmax.w\007vmax.wu\007vmaxi.b\010vmaxi.bu\007vmaxi.d"
    "\010vmaxi.du\007vmaxi.h\010vmaxi.hu\007vmaxi.w\010vmaxi.wu\006vmin.b\007"
    "vmin.bu\006vmin.d\007vmin.du\006vmin.h\007vmin.hu\006vmin.w\007vmin.wu\007"
    "vmini.b\010vmini.bu\007vmini.d\010vmini.du\007vmini.h\010vmini.hu\007vm"
    "ini.w\010vmini.wu\006vmod.b\007vmod.bu\006vmod.d\007vmod.du\006vmod.h\007"
    "vmod.hu\006vmod.w\007vmod.wu\tvmskgez.b\tvmskltz.b\tvmskltz.d\tvmskltz."
    "h\tvmskltz.w\010vmsknz.b\007vmsub.b\007vmsub.d\007vmsub.h\007vmsub.w\006"
    "vmuh.b\007vmuh.bu\006vmuh.d\007vmuh.du\006vmuh.h\007vmuh.hu\006vmuh.w\007"
    "vmuh.wu\006vmul.b\006vmul.d\006vmul.h\006vmul.w\013vmulwev.d.w\014vmulw"
    "ev.d.wu\016vmulwev.d.wu.w\013vmulwev.h.b\014vmulwev.h.bu\016vmulwev.h.b"
    "u.b\013vmulwev.q.d\014vmulwev.q.du\016vmulwev.q.du.d\013vmulwev.w.h\014"
    "vmulwev.w.hu\016vmulwev.w.hu.h\013vmulwod.d.w\014vmulwod.d.wu\016vmulwo"
    "d.d.wu.w\013vmulwod.h.b\014vmulwod.h.bu\016vmulwod.h.bu.b\013vmulwod.q."
    "d\014vmulwod.q.du\016vmulwod.q.du.d\013vmulwod.w.h\014vmulwod.w.hu\016v"
    "mulwod.w.hu.h\006vneg.b\006vneg.d\006vneg.h\006vneg.w\006vnor.v\007vnor"
    "i.b\005vor.v\006vori.b\006vorn.v\tvpackev.b\tvpackev.d\tvpackev.h\tvpac"
    "kev.w\tvpackod.b\tvpackod.d\tvpackod.h\tvpackod.w\007vpcnt.b\007vpcnt.d"
    "\007vpcnt.h\007vpcnt.w\010vpermi.w\tvpickev.b\tvpickev.d\tvpickev.h\tvp"
    "ickev.w\tvpickod.b\tvpickod.d\tvpickod.h\tvpickod.w\014vpickve2gr.b\015"
    "vpickve2gr.bu\014vpickve2gr.d\015vpickve2gr.du\014vpickve2gr.h\015vpick"
    "ve2gr.hu\014vpickve2gr.w\015vpickve2gr.wu\014vreplgr2vr.b\014vreplgr2vr"
    ".d\014vreplgr2vr.h\014vreplgr2vr.w\010vrepli.b\010vrepli.d\010vrepli.h\010"
    "vrepli.w\tvreplve.b\tvreplve.d\tvreplve.h\tvreplve.w\nvreplvei.b\nvrepl"
    "vei.d\nvreplvei.h\nvreplvei.w\007vrotr.b\007vrotr.d\007vrotr.h\007vrotr"
    ".w\010vrotri.b\010vrotri.d\010vrotri.h\010vrotri.w\007vsadd.b\010vsadd."
    "bu\007vsadd.d\010vsadd.du\007vsadd.h\010vsadd.hu\007vsadd.w\010vsadd.wu"
    "\006vsat.b\007vsat.bu\006vsat.d\007vsat.du\006vsat.h\007vsat.hu\006vsat"
    ".w\007vsat.wu\006vseq.b\006vseq.d\006vseq.h\006vseq.w\007vseqi.b\007vse"
    "qi.d\007vseqi.h\007vseqi.w\014vsetallnez.b\014vsetallnez.d\014vsetallne"
    "z.h\014vsetallnez.w\014vsetanyeqz.b\014vsetanyeqz.d\014vsetanyeqz.h\014"
    "vsetanyeqz.w\tvseteqz.v\tvsetnez.v\007vshuf.b\007vshuf.d\007vshuf.h\007"
    "vshuf.w\tvshuf4i.b\tvshuf4i.d\tvshuf4i.h\tvshuf4i.w\nvsigncov.b\nvsignc"
    "ov.d\nvsigncov.h\nvsigncov.w\006vsle.b\007vsle.bu\006vsle.d\007vsle.du\006"
    "vsle.h\007vsle.hu\006vsle.w\007vsle.wu\007vslei.b\010vslei.bu\007vslei."
    "d\010vslei.du\007vslei.h\010vslei.hu\007vslei.w\010vslei.wu\006vsll.b\006"
    "vsll.d\006vsll.h\006vsll.w\007vslli.b\007vslli.d\007vslli.h\007vslli.w\013"
    "vsllwil.d.w\015vsllwil.du.wu\013vsllwil.h.b\015vsllwil.hu.bu\013vsllwil"
    ".w.h\015vsllwil.wu.hu\006vslt.b\007vslt.bu\006vslt.d\007vslt.du\006vslt"
    ".h\007vslt.hu\006vslt.w\007vslt.wu\007vslti.b\010vslti.bu\007vslti.d\010"
    "vslti.du\007vslti.h\010vslti.hu\007vslti.w\010vslti.wu\006vsra.b\006vsr"
    "a.d\006vsra.h\006vsra.w\007vsrai.b\007vsrai.d\007vsrai.h\007vsrai.w\tvs"
    "ran.b.h\tvsran.h.w\tvsran.w.d\nvsrani.b.h\nvsrani.d.q\nvsrani.h.w\nvsra"
    "ni.w.d\007vsrar.b\007vsrar.d\007vsrar.h\007vsrar.w\010vsrari.b\010vsrar"
    "i.d\010vsrari.h\010vsrari.w\nvsrarn.b.h\nvsrarn.h.w\nvsrarn.w.d\013vsra"
    "rni.b.h\013vsrarni.d.q\013vsrarni.h.w\013vsrarni.w.d\006vsrl.b\006vsrl."
    "d\006vsrl.h\006vsrl.w\007vsrli.b\007vsrli.d\007vsrli.h\007vsrli.w\tvsrl"
    "n.b.h\tvsrln.h.w\tvsrln.w.d\nvsrlni.b.h\nvsrlni.d.q\nvsrlni.h.w\nvsrlni"
    ".w.d\007vsrlr.b\007vsrlr.d\007vsrlr.h\007vsrlr.w\010vsrlri.b\010vsrlri."
    "d\010vsrlri.h\010vsrlri.w\nvsrlrn.b.h\nvsrlrn.h.w\nvsrlrn.w.d\013vsrlrn"
    "i.b.h\013vsrlrni.d.q\013vsrlrni.h.w\013vsrlrni.w.d\nvssran.b.h\013vssra"
    "n.bu.h\nvssran.h.w\013vssran.hu.w\nvssran.w.d\013vssran.wu.d\013vssrani"
    ".b.h\014vssrani.bu.h\013vssrani.d.q\014vssrani.du.q\013vssrani.h.w\014v"
    "ssrani.hu.w\013vssrani.w.d\014vssrani.wu.d\013vssrarn.b.h\014vssrarn.bu"
    ".h\013vssrarn.h.w\014vssrarn.hu.w\013vssrarn.w.d\014vssrarn.wu.d\014vss"
    "rarni.b.h\015vssrarni.bu.h\014vssrarni.d.q\015vssrarni.du.q\014vssrarni"
    ".h.w\015vssrarni.hu.w\014vssrarni.w.d\015vssrarni.wu.d\nvssrln.b.h\013v"
    "ssrln.bu.h\nvssrln.h.w\013vssrln.hu.w\nvssrln.w.d\013vssrln.wu.d\013vss"
    "rlni.b.h\014vssrlni.bu.h\013vssrlni.d.q\014vssrlni.du.q\013vssrlni.h.w\014"
    "vssrlni.hu.w\013vssrlni.w.d\014vssrlni.wu.d\013vssrlrn.b.h\014vssrlrn.b"
    "u.h\013vssrlrn.h.w\014vssrlrn.hu.w\013vssrlrn.w.d\014vssrlrn.wu.d\014vs"
    "srlrni.b.h\015vssrlrni.bu.h\014vssrlrni.d.q\015vssrlrni.du.q\014vssrlrn"
    "i.h.w\015vssrlrni.hu.w\014vssrlrni.w.d\015vssrlrni.wu.d\007vssub.b\010v"
    "ssub.bu\007vssub.d\010vssub.du\007vssub.h\010vssub.hu\007vssub.w\010vss"
    "ub.wu\003vst\010vstelm.b\010vstelm.d\010vstelm.h\010vstelm.w\004vstx\006"
    "vsub.b\006vsub.d\006vsub.h\006vsub.q\006vsub.w\010vsubi.bu\010vsubi.du\010"
    "vsubi.hu\010vsubi.wu\013vsubwev.d.w\014vsubwev.d.wu\013vsubwev.h.b\014v"
    "subwev.h.bu\013vsubwev.q.d\014vsubwev.q.du\013vsubwev.w.h\014vsubwev.w."
    "hu\013vsubwod.d.w\014vsubwod.d.wu\013vsubwod.h.b\014vsubwod.h.bu\013vsu"
    "bwod.q.d\014vsubwod.q.du\013vsubwod.w.h\014vsubwod.w.hu\006vxor.v\007vx"
    "ori.b\010x86adc.b\010x86adc.d\010x86adc.h\010x86adc.w\010x86add.b\010x8"
    "6add.d\tx86add.du\010x86add.h\010x86add.w\tx86add.wu\010x86and.b\010x86"
    "and.d\010x86and.h\010x86and.w\010x86clrtm\010x86dec.b\010x86dec.d\010x8"
    "6dec.h\010x86dec.w\tx86dectop\010x86inc.b\010x86inc.d\010x86inc.h\010x8"
    "6inc.w\tx86inctop\tx86mfflag\010x86mftop\tx86mtflag\010x86mttop\010x86m"
    "ul.b\tx86mul.bu\010x86mul.d\tx86mul.du\010x86mul.h\tx86mul.hu\010x86mul"
    ".w\tx86mul.wu\007x86or.b\007x86or.d\007x86or.h\007x86or.w\010x86rcl.b\010"
    "x86rcl.d\010x86rcl.h\010x86rcl.w\tx86rcli.b\tx86rcli.d\tx86rcli.h\tx86r"
    "cli.w\010x86rcr.b\010x86rcr.d\010x86rcr.h\010x86rcr.w\tx86rcri.b\tx86rc"
    "ri.d\tx86rcri.h\tx86rcri.w\tx86rotl.b\tx86rotl.d\tx86rotl.h\tx86rotl.w\n"
    "x86rotli.b\nx86rotli.d\nx86rotli.h\nx86rotli.w\tx86rotr.b\tx86rotr.d\tx"
    "86rotr.h\tx86rotr.w\nx86rotri.b\nx86rotri.d\nx86rotri.h\nx86rotri.w\010"
    "x86sbc.b\010x86sbc.d\010x86sbc.h\010x86sbc.w\tx86settag\010x86settm\010"
    "x86sll.b\010x86sll.d\010x86sll.h\010x86sll.w\tx86slli.b\tx86slli.d\tx86"
    "slli.h\tx86slli.w\010x86sra.b\010x86sra.d\010x86sra.h\010x86sra.w\tx86s"
    "rai.b\tx86srai.d\tx86srai.h\tx86srai.w\010x86srl.b\010x86srl.d\010x86sr"
    "l.h\010x86srl.w\tx86srli.b\tx86srli.d\tx86srli.h\tx86srli.w\010x86sub.b"
    "\010x86sub.d\tx86sub.du\010x86sub.h\010x86sub.w\tx86sub.wu\010x86xor.b\010"
    "x86xor.d\010x86xor.h\010x86xor.w\003xor\004xori\010xvabsd.b\txvabsd.bu\010"
    "xvabsd.d\txvabsd.du\010xvabsd.h\txvabsd.hu\010xvabsd.w\txvabsd.wu\007xv"
    "add.b\007xvadd.d\007xvadd.h\007xvadd.q\007xvadd.w\010xvadda.b\010xvadda"
    ".d\010xvadda.h\010xvadda.w\txvaddi.bu\txvaddi.du\txvaddi.hu\txvaddi.wu\014"
    "xvaddwev.d.w\015xvaddwev.d.wu\017xvaddwev.d.wu.w\014xvaddwev.h.b\015xva"
    "ddwev.h.bu\017xvaddwev.h.bu.b\014xvaddwev.q.d\015xvaddwev.q.du\017xvadd"
    "wev.q.du.d\014xvaddwev.w.h\015xvaddwev.w.hu\017xvaddwev.w.hu.h\014xvadd"
    "wod.d.w\015xvaddwod.d.wu\017xvaddwod.d.wu.w\014xvaddwod.h.b\015xvaddwod"
    ".h.bu\017xvaddwod.h.bu.b\014xvaddwod.q.d\015xvaddwod.q.du\017xvaddwod.q"
    ".du.d\014xvaddwod.w.h\015xvaddwod.w.hu\017xvaddwod.w.hu.h\007xvand.v\010"
    "xvandi.b\010xvandn.v\007xvavg.b\010xvavg.bu\007xvavg.d\010xvavg.du\007x"
    "vavg.h\010xvavg.hu\007xvavg.w\010xvavg.wu\010xvavgr.b\txvavgr.bu\010xva"
    "vgr.d\txvavgr.du\010xvavgr.h\txvavgr.hu\010xvavgr.w\txvavgr.wu\nxvbitcl"
    "r.b\nxvbitclr.d\nxvbitclr.h\nxvbitclr.w\013xvbitclri.b\013xvbitclri.d\013"
    "xvbitclri.h\013xvbitclri.w\nxvbitrev.b\nxvbitrev.d\nxvbitrev.h\nxvbitre"
    "v.w\013xvbitrevi.b\013xvbitrevi.d\013xvbitrevi.h\013xvbitrevi.w\nxvbits"
    "el.v\013xvbitseli.b\nxvbitset.b\nxvbitset.d\nxvbitset.h\nxvbitset.w\013"
    "xvbitseti.b\013xvbitseti.d\013xvbitseti.h\013xvbitseti.w\010xvbsll.v\010"
    "xvbsrl.v\007xvclo.b\007xvclo.d\007xvclo.h\007xvclo.w\007xvclz.b\007xvcl"
    "z.d\007xvclz.h\007xvclz.w\007xvdiv.b\010xvdiv.bu\007xvdiv.d\010xvdiv.du"
    "\007xvdiv.h\010xvdiv.hu\007xvdiv.w\010xvdiv.wu\nxvexth.d.w\014xvexth.du"
    ".wu\nxvexth.h.b\014xvexth.hu.bu\nxvexth.q.d\014xvexth.qu.du\nxvexth.w.h"
    "\014xvexth.wu.hu\nxvextl.q.d\014xvextl.qu.du\013xvextrins.b\013xvextrin"
    "s.d\013xvextrins.h\013xvextrins.w\010xvfadd.d\010xvfadd.s\nxvfclass.d\n"
    "xvfclass.s\014xvfcmp.caf.d\014xvfcmp.caf.s\014xvfcmp.ceq.d\014xvfcmp.ce"
    "q.s\014xvfcmp.cle.d\014xvfcmp.cle.s\014xvfcmp.clt.d\014xvfcmp.clt.s\014"
    "xvfcmp.cne.d\014xvfcmp.cne.s\014xvfcmp.cor.d\014xvfcmp.cor.s\015xvfcmp."
    "cueq.d\015xvfcmp.cueq.s\015xvfcmp.cule.d\015xvfcmp.cule.s\015xvfcmp.cul"
    "t.d\015xvfcmp.cult.s\014xvfcmp.cun.d\014xvfcmp.cun.s\015xvfcmp.cune.d\015"
    "xvfcmp.cune.s\014xvfcmp.saf.d\014xvfcmp.saf.s\014xvfcmp.seq.d\014xvfcmp"
    ".seq.s\014xvfcmp.sle.d\014xvfcmp.sle.s\014xvfcmp.slt.d\014xvfcmp.slt.s\014"
    "xvfcmp.sne.d\014xvfcmp.sne.s\014xvfcmp.sor.d\014xvfcmp.sor.s\015xvfcmp."
    "sueq.d\015xvfcmp.sueq.s\015xvfcmp.sule.d\015xvfcmp.sule.s\015xvfcmp.sul"
    "t.d\015xvfcmp.sult.s\014xvfcmp.sun.d\014xvfcmp.sun.s\015xvfcmp.sune.d\015"
    "xvfcmp.sune.s\nxvfcvt.h.s\nxvfcvt.s.d\013xvfcvth.d.s\013xvfcvth.s.h\013"
    "xvfcvtl.d.s\013xvfcvtl.s.h\010xvfdiv.d\010xvfdiv.s\013xvffint.d.l\014xv"
    "ffint.d.lu\013xvffint.s.l\013xvffint.s.w\014xvffint.s.wu\014xvffinth.d."
    "w\014xvffintl.d.w\txvflogb.d\txvflogb.s\txvfmadd.d\txvfmadd.s\010xvfmax"
    ".d\010xvfmax.s\txvfmaxa.d\txvfmaxa.s\010xvfmin.d\010xvfmin.s\txvfmina.d"
    "\txvfmina.s\txvfmsub.d\txvfmsub.s\010xvfmul.d\010xvfmul.s\nxvfnmadd.d\n"
    "xvfnmadd.s\nxvfnmsub.d\nxvfnmsub.s\nxvfrecip.d\nxvfrecip.s\013xvfrecipe"
    ".d\013xvfrecipe.s\txvfrint.d\txvfrint.s\013xvfrintrm.d\013xvfrintrm.s\014"
    "xvfrintrne.d\014xvfrintrne.s\013xvfrintrp.d\013xvfrintrp.s\013xvfrintrz"
    ".d\013xvfrintrz.s\nxvfrsqrt.d\nxvfrsqrt.s\013xvfrsqrte.d\013xvfrsqrte.s"
    "\txvfrstp.b\txvfrstp.h\nxvfrstpi.b\nxvfrstpi.h\txvfsqrt.d\txvfsqrt.s\010"
    "xvfsub.d\010xvfsub.s\013xvftint.l.d\014xvftint.lu.d\013xvftint.w.d\013x"
    "vftint.w.s\014xvftint.wu.s\014xvftinth.l.s\014xvftintl.l.s\015xvftintrm"
    ".l.d\015xvftintrm.w.d\015xvftintrm.w.s\016xvftintrmh.l.s\016xvftintrml."
    "l.s\016xvftintrne.l.d\016xvftintrne.w.d\016xvftintrne.w.s\017xvftintrne"
    "h.l.s\017xvftintrnel.l.s\015xvftintrp.l.d\015xvftintrp.w.d\015xvftintrp"
    ".w.s\016xvftintrph.l.s\016xvftintrpl.l.s\015xvftintrz.l.d\016xvftintrz."
    "lu.d\015xvftintrz.w.d\015xvftintrz.w.s\016xvftintrz.wu.s\016xvftintrzh."
    "l.s\016xvftintrzl.l.s\013xvhaddw.d.w\015xvhaddw.du.wu\013xvhaddw.h.b\015"
    "xvhaddw.hu.bu\013xvhaddw.q.d\015xvhaddw.qu.du\013xvhaddw.w.h\015xvhaddw"
    ".wu.hu\txvhseli.d\013xvhsubw.d.w\015xvhsubw.du.wu\013xvhsubw.h.b\015xvh"
    "subw.hu.bu\013xvhsubw.q.d\015xvhsubw.qu.du\013xvhsubw.w.h\015xvhsubw.wu"
    ".hu\010xvilvh.b\010xvilvh.d\010xvilvh.h\010xvilvh.w\010xvilvl.b\010xvil"
    "vl.d\010xvilvl.h\010xvilvl.w\014xvinsgr2vr.d\014xvinsgr2vr.w\nxvinsve0."
    "d\nxvinsve0.w\004xvld\005xvldi\nxvldrepl.b\nxvldrepl.d\nxvldrepl.h\nxvl"
    "drepl.w\005xvldx\010xvmadd.b\010xvmadd.d\010xvmadd.h\010xvmadd.w\015xvm"
    "addwev.d.w\016xvmaddwev.d.wu\020xvmaddwev.d.wu.w\015xvmaddwev.h.b\016xv"
    "maddwev.h.bu\020xvmaddwev.h.bu.b\015xvmaddwev.q.d\016xvmaddwev.q.du\020"
    "xvmaddwev.q.du.d\015xvmaddwev.w.h\016xvmaddwev.w.hu\020xvmaddwev.w.hu.h"
    "\015xvmaddwod.d.w\016xvmaddwod.d.wu\020xvmaddwod.d.wu.w\015xvmaddwod.h."
    "b\016xvmaddwod.h.bu\020xvmaddwod.h.bu.b\015xvmaddwod.q.d\016xvmaddwod.q"
    ".du\020xvmaddwod.q.du.d\015xvmaddwod.w.h\016xvmaddwod.w.hu\020xvmaddwod"
    ".w.hu.h\007xvmax.b\010xvmax.bu\007xvmax.d\010xvmax.du\007xvmax.h\010xvm"
    "ax.hu\007xvmax.w\010xvmax.wu\010xvmaxi.b\txvmaxi.bu\010xvmaxi.d\txvmaxi"
    ".du\010xvmaxi.h\txvmaxi.hu\010xvmaxi.w\txvmaxi.wu\007xvmin.b\010xvmin.b"
    "u\007xvmin.d\010xvmin.du\007xvmin.h\010xvmin.hu\007xvmin.w\010xvmin.wu\010"
    "xvmini.b\txvmini.bu\010xvmini.d\txvmini.du\010xvmini.h\txvmini.hu\010xv"
    "mini.w\txvmini.wu\007xvmod.b\010xvmod.bu\007xvmod.d\010xvmod.du\007xvmo"
    "d.h\010xvmod.hu\007xvmod.w\010xvmod.wu\nxvmskgez.b\nxvmskltz.b\nxvmsklt"
    "z.d\nxvmskltz.h\nxvmskltz.w\txvmsknz.b\010xvmsub.b\010xvmsub.d\010xvmsu"
    "b.h\010xvmsub.w\007xvmuh.b\010xvmuh.bu\007xvmuh.d\010xvmuh.du\007xvmuh."
    "h\010xvmuh.hu\007xvmuh.w\010xvmuh.wu\007xvmul.b\007xvmul.d\007xvmul.h\007"
    "xvmul.w\014xvmulwev.d.w\015xvmulwev.d.wu\017xvmulwev.d.wu.w\014xvmulwev"
    ".h.b\015xvmulwev.h.bu\017xvmulwev.h.bu.b\014xvmulwev.q.d\015xvmulwev.q."
    "du\017xvmulwev.q.du.d\014xvmulwev.w.h\015xvmulwev.w.hu\017xvmulwev.w.hu"
    ".h\014xvmulwod.d.w\015xvmulwod.d.wu\017xvmulwod.d.wu.w\014xvmulwod.h.b\015"
    "xvmulwod.h.bu\017xvmulwod.h.bu.b\014xvmulwod.q.d\015xvmulwod.q.du\017xv"
    "mulwod.q.du.d\014xvmulwod.w.h\015xvmulwod.w.hu\017xvmulwod.w.hu.h\007xv"
    "neg.b\007xvneg.d\007xvneg.h\007xvneg.w\007xvnor.v\010xvnori.b\006xvor.v"
    "\007xvori.b\007xvorn.v\nxvpackev.b\nxvpackev.d\nxvpackev.h\nxvpackev.w\n"
    "xvpackod.b\nxvpackod.d\nxvpackod.h\nxvpackod.w\010xvpcnt.b\010xvpcnt.d\010"
    "xvpcnt.h\010xvpcnt.w\010xvperm.w\txvpermi.d\txvpermi.q\txvpermi.w\nxvpi"
    "ckev.b\nxvpickev.d\nxvpickev.h\nxvpickev.w\nxvpickod.b\nxvpickod.d\nxvp"
    "ickod.h\nxvpickod.w\nxvpickve.d\nxvpickve.w\015xvpickve2gr.d\016xvpickv"
    "e2gr.du\015xvpickve2gr.w\016xvpickve2gr.wu\016xvrepl128vei.b\016xvrepl1"
    "28vei.d\016xvrepl128vei.h\016xvrepl128vei.w\015xvreplgr2vr.b\015xvreplg"
    "r2vr.d\015xvreplgr2vr.h\015xvreplgr2vr.w\txvrepli.b\txvrepli.d\txvrepli"
    ".h\txvrepli.w\nxvreplve.b\nxvreplve.d\nxvreplve.h\nxvreplve.w\013xvrepl"
    "ve0.b\013xvreplve0.d\013xvreplve0.h\013xvreplve0.q\013xvreplve0.w\010xv"
    "rotr.b\010xvrotr.d\010xvrotr.h\010xvrotr.w\txvrotri.b\txvrotri.d\txvrot"
    "ri.h\txvrotri.w\010xvsadd.b\txvsadd.bu\010xvsadd.d\txvsadd.du\010xvsadd"
    ".h\txvsadd.hu\010xvsadd.w\txvsadd.wu\007xvsat.b\010xvsat.bu\007xvsat.d\010"
    "xvsat.du\007xvsat.h\010xvsat.hu\007xvsat.w\010xvsat.wu\007xvseq.b\007xv"
    "seq.d\007xvseq.h\007xvseq.w\010xvseqi.b\010xvseqi.d\010xvseqi.h\010xvse"
    "qi.w\015xvsetallnez.b\015xvsetallnez.d\015xvsetallnez.h\015xvsetallnez."
    "w\015xvsetanyeqz.b\015xvsetanyeqz.d\015xvsetanyeqz.h\015xvsetanyeqz.w\n"
    "xvseteqz.v\nxvsetnez.v\010xvshuf.b\010xvshuf.d\010xvshuf.h\010xvshuf.w\n"
    "xvshuf4i.b\nxvshuf4i.d\nxvshuf4i.h\nxvshuf4i.w\013xvsigncov.b\013xvsign"
    "cov.d\013xvsigncov.h\013xvsigncov.w\007xvsle.b\010xvsle.bu\007xvsle.d\010"
    "xvsle.du\007xvsle.h\010xvsle.hu\007xvsle.w\010xvsle.wu\010xvslei.b\txvs"
    "lei.bu\010xvslei.d\txvslei.du\010xvslei.h\txvslei.hu\010xvslei.w\txvsle"
    "i.wu\007xvsll.b\007xvsll.d\007xvsll.h\007xvsll.w\010xvslli.b\010xvslli."
    "d\010xvslli.h\010xvslli.w\014xvsllwil.d.w\016xvsllwil.du.wu\014xvsllwil"
    ".h.b\016xvsllwil.hu.bu\014xvsllwil.w.h\016xvsllwil.wu.hu\007xvslt.b\010"
    "xvslt.bu\007xvslt.d\010xvslt.du\007xvslt.h\010xvslt.hu\007xvslt.w\010xv"
    "slt.wu\010xvslti.b\txvslti.bu\010xvslti.d\txvslti.du\010xvslti.h\txvslt"
    "i.hu\010xvslti.w\txvslti.wu\007xvsra.b\007xvsra.d\007xvsra.h\007xvsra.w"
    "\010xvsrai.b\010xvsrai.d\010xvsrai.h\010xvsrai.w\nxvsran.b.h\nxvsran.h."
    "w\nxvsran.w.d\013xvsrani.b.h\013xvsrani.d.q\013xvsrani.h.w\013xvsrani.w"
    ".d\010xvsrar.b\010xvsrar.d\010xvsrar.h\010xvsrar.w\txvsrari.b\txvsrari."
    "d\txvsrari.h\txvsrari.w\013xvsrarn.b.h\013xvsrarn.h.w\013xvsrarn.w.d\014"
    "xvsrarni.b.h\014xvsrarni.d.q\014xvsrarni.h.w\014xvsrarni.w.d\007xvsrl.b"
    "\007xvsrl.d\007xvsrl.h\007xvsrl.w\010xvsrli.b\010xvsrli.d\010xvsrli.h\010"
    "xvsrli.w\nxvsrln.b.h\nxvsrln.h.w\nxvsrln.w.d\013xvsrlni.b.h\013xvsrlni."
    "d.q\013xvsrlni.h.w\013xvsrlni.w.d\010xvsrlr.b\010xvsrlr.d\010xvsrlr.h\010"
    "xvsrlr.w\txvsrlri.b\txvsrlri.d\txvsrlri.h\txvsrlri.w\013xvsrlrn.b.h\013"
    "xvsrlrn.h.w\013xvsrlrn.w.d\014xvsrlrni.b.h\014xvsrlrni.d.q\014xvsrlrni."
    "h.w\014xvsrlrni.w.d\013xvssran.b.h\014xvssran.bu.h\013xvssran.h.w\014xv"
    "ssran.hu.w\013xvssran.w.d\014xvssran.wu.d\014xvssrani.b.h\015xvssrani.b"
    "u.h\014xvssrani.d.q\015xvssrani.du.q\014xvssrani.h.w\015xvssrani.hu.w\014"
    "xvssrani.w.d\015xvssrani.wu.d\014xvssrarn.b.h\015xvssrarn.bu.h\014xvssr"
    "arn.h.w\015xvssrarn.hu.w\014xvssrarn.w.d\015xvssrarn.wu.d\015xvssrarni."
    "b.h\016xvssrarni.bu.h\015xvssrarni.d.q\016xvssrarni.du.q\015xvssrarni.h"
    ".w\016xvssrarni.hu.w\015xvssrarni.w.d\016xvssrarni.wu.d\013xvssrln.b.h\014"
    "xvssrln.bu.h\013xvssrln.h.w\014xvssrln.hu.w\013xvssrln.w.d\014xvssrln.w"
    "u.d\014xvssrlni.b.h\015xvssrlni.bu.h\014xvssrlni.d.q\015xvssrlni.du.q\014"
    "xvssrlni.h.w\015xvssrlni.hu.w\014xvssrlni.w.d\015xvssrlni.wu.d\014xvssr"
    "lrn.b.h\015xvssrlrn.bu.h\014xvssrlrn.h.w\015xvssrlrn.hu.w\014xvssrlrn.w"
    ".d\015xvssrlrn.wu.d\015xvssrlrni.b.h\016xvssrlrni.bu.h\015xvssrlrni.d.q"
    "\016xvssrlrni.du.q\015xvssrlrni.h.w\016xvssrlrni.hu.w\015xvssrlrni.w.d\016"
    "xvssrlrni.wu.d\010xvssub.b\txvssub.bu\010xvssub.d\txvssub.du\010xvssub."
    "h\txvssub.hu\010xvssub.w\txvssub.wu\004xvst\txvstelm.b\txvstelm.d\txvst"
    "elm.h\txvstelm.w\005xvstx\007xvsub.b\007xvsub.d\007xvsub.h\007xvsub.q\007"
    "xvsub.w\txvsubi.bu\txvsubi.du\txvsubi.hu\txvsubi.wu\014xvsubwev.d.w\015"
    "xvsubwev.d.wu\014xvsubwev.h.b\015xvsubwev.h.bu\014xvsubwev.q.d\015xvsub"
    "wev.q.du\014xvsubwev.w.h\015xvsubwev.w.hu\014xvsubwod.d.w\015xvsubwod.d"
    ".wu\014xvsubwod.h.b\015xvsubwod.h.bu\014xvsubwod.q.d\015xvsubwod.q.du\014"
    "xvsubwod.w.h\015xvsubwod.w.hu\007xvxor.v\010xvxori.b";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
  AMFBS_HasLaGlobalWithAbs,
  AMFBS_HasLaGlobalWithPcrel,
  AMFBS_HasLaLocalWithAbs,
  AMFBS_IsLA32,
  AMFBS_IsLA64,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
  {Feature_HasLaGlobalWithAbsBit, }, // AMFBS_HasLaGlobalWithAbs
  {Feature_HasLaGlobalWithPcrelBit, }, // AMFBS_HasLaGlobalWithPcrel
  {Feature_HasLaLocalWithAbsBit, }, // AMFBS_HasLaLocalWithAbs
  {Feature_IsLA32Bit, }, // AMFBS_IsLA32
  {Feature_IsLA64Bit, }, // AMFBS_IsLA64
};

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
    uint32_t Opcode;
    uint8_t ConvertFn;
    uint8_t RequiredFeaturesIdx;
    uint8_t Classes[4];
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
  { 0 /* adc.b */, LoongArch::ADC_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 6 /* adc.d */, LoongArch::ADC_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 12 /* adc.h */, LoongArch::ADC_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 18 /* adc.w */, LoongArch::ADC_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 24 /* add.d */, LoongArch::ADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 24 /* add.d */, LoongArch::PseudoAddTPRel_D, Convert__Reg1_0__Reg1_1__Reg1_2__TPRelAddSymbol1_3, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR, MCK_TPRelAddSymbol }, },
  { 30 /* add.w */, LoongArch::ADD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 30 /* add.w */, LoongArch::PseudoAddTPRel_W, Convert__Reg1_0__Reg1_1__Reg1_2__TPRelAddSymbol1_3, AMFBS_IsLA32, { MCK_GPR, MCK_GPR, MCK_GPR, MCK_TPRelAddSymbol }, },
  { 36 /* addi.d */, LoongArch::ADDI_D, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 43 /* addi.w */, LoongArch::ADDI_W, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 50 /* addu12i.d */, LoongArch::ADDU12I_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm5 }, },
  { 60 /* addu12i.w */, LoongArch::ADDU12I_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm5 }, },
  { 70 /* addu16i.d */, LoongArch::ADDU16I_D, Convert__Reg1_0__Reg1_1__SImm161_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm16 }, },
  { 80 /* alsl.d */, LoongArch::ALSL_D, Convert__Reg1_0__Reg1_1__Reg1_2__UImm2plus11_3, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR, MCK_UImm2plus1 }, },
  { 87 /* alsl.w */, LoongArch::ALSL_W, Convert__Reg1_0__Reg1_1__Reg1_2__UImm2plus11_3, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR, MCK_UImm2plus1 }, },
  { 94 /* alsl.wu */, LoongArch::ALSL_WU, Convert__Reg1_0__Reg1_1__Reg1_2__UImm2plus11_3, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR, MCK_UImm2plus1 }, },
  { 102 /* amadd.b */, LoongArch::AMADD_B, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 110 /* amadd.d */, LoongArch::AMADD_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 118 /* amadd.h */, LoongArch::AMADD_H, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 126 /* amadd.w */, LoongArch::AMADD_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 134 /* amadd_db.b */, LoongArch::AMADD__DB_B, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 145 /* amadd_db.d */, LoongArch::AMADD__DB_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 156 /* amadd_db.h */, LoongArch::AMADD__DB_H, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 167 /* amadd_db.w */, LoongArch::AMADD__DB_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 178 /* amand.d */, LoongArch::AMAND_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 186 /* amand.w */, LoongArch::AMAND_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 194 /* amand_db.d */, LoongArch::AMAND__DB_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 205 /* amand_db.w */, LoongArch::AMAND__DB_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 216 /* amcas.b */, LoongArch::AMCAS_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 224 /* amcas.d */, LoongArch::AMCAS_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 232 /* amcas.h */, LoongArch::AMCAS_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 240 /* amcas.w */, LoongArch::AMCAS_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 248 /* amcas_db.b */, LoongArch::AMCAS__DB_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 259 /* amcas_db.d */, LoongArch::AMCAS__DB_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 270 /* amcas_db.h */, LoongArch::AMCAS__DB_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 281 /* amcas_db.w */, LoongArch::AMCAS__DB_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 292 /* ammax.d */, LoongArch::AMMAX_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 300 /* ammax.du */, LoongArch::AMMAX_DU, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 309 /* ammax.w */, LoongArch::AMMAX_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 317 /* ammax.wu */, LoongArch::AMMAX_WU, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 326 /* ammax_db.d */, LoongArch::AMMAX__DB_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 337 /* ammax_db.du */, LoongArch::AMMAX__DB_DU, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 349 /* ammax_db.w */, LoongArch::AMMAX__DB_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 360 /* ammax_db.wu */, LoongArch::AMMAX__DB_WU, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 372 /* ammin.d */, LoongArch::AMMIN_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 380 /* ammin.du */, LoongArch::AMMIN_DU, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 389 /* ammin.w */, LoongArch::AMMIN_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 397 /* ammin.wu */, LoongArch::AMMIN_WU, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 406 /* ammin_db.d */, LoongArch::AMMIN__DB_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 417 /* ammin_db.du */, LoongArch::AMMIN__DB_DU, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 429 /* ammin_db.w */, LoongArch::AMMIN__DB_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 440 /* ammin_db.wu */, LoongArch::AMMIN__DB_WU, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 452 /* amor.d */, LoongArch::AMOR_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 459 /* amor.w */, LoongArch::AMOR_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 466 /* amor_db.d */, LoongArch::AMOR__DB_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 476 /* amor_db.w */, LoongArch::AMOR__DB_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 486 /* amswap.b */, LoongArch::AMSWAP_B, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 495 /* amswap.d */, LoongArch::AMSWAP_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 504 /* amswap.h */, LoongArch::AMSWAP_H, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 513 /* amswap.w */, LoongArch::AMSWAP_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 522 /* amswap_db.b */, LoongArch::AMSWAP__DB_B, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 534 /* amswap_db.d */, LoongArch::AMSWAP__DB_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 546 /* amswap_db.h */, LoongArch::AMSWAP__DB_H, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 558 /* amswap_db.w */, LoongArch::AMSWAP__DB_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 570 /* amxor.d */, LoongArch::AMXOR_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 578 /* amxor.w */, LoongArch::AMXOR_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 586 /* amxor_db.d */, LoongArch::AMXOR__DB_D, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 597 /* amxor_db.w */, LoongArch::AMXOR__DB_W, Convert__Reg1_0__Reg1_1__AtomicMemAsmOperand1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_AtomicMemAsmOperand }, },
  { 608 /* and */, LoongArch::AND, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 612 /* andi */, LoongArch::ANDI, Convert__Reg1_0__Reg1_1__UImm121_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm12 }, },
  { 617 /* andn */, LoongArch::ANDN, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 622 /* armadc.w */, LoongArch::ARMADC_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 631 /* armadd.w */, LoongArch::ARMADD_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 640 /* armand.w */, LoongArch::ARMAND_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 649 /* armmfflag */, LoongArch::ARMMFFLAG, Convert__Reg1_0__UImm81_1, AMFBS_None, { MCK_GPR, MCK_UImm8 }, },
  { 659 /* armmov.d */, LoongArch::ARMMOV_D, Convert__Reg1_0__UImm41_1, AMFBS_IsLA64, { MCK_GPR, MCK_UImm4 }, },
  { 668 /* armmov.w */, LoongArch::ARMMOV_W, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 677 /* armmove */, LoongArch::ARMMOVE, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 685 /* armmtflag */, LoongArch::ARMMTFLAG, Convert__Reg1_0__UImm81_1, AMFBS_None, { MCK_GPR, MCK_UImm8 }, },
  { 695 /* armnot.w */, LoongArch::ARMNOT_W, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 704 /* armor.w */, LoongArch::ARMOR_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 712 /* armrotr.w */, LoongArch::ARMROTR_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 722 /* armrotri.w */, LoongArch::ARMROTRI_W, Convert__Reg1_0__UImm51_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_UImm5, MCK_UImm4 }, },
  { 733 /* armrrx.w */, LoongArch::ARMRRX_W, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 742 /* armsbc.w */, LoongArch::ARMSBC_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 751 /* armsll.w */, LoongArch::ARMSLL_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 760 /* armslli.w */, LoongArch::ARMSLLI_W, Convert__Reg1_0__UImm51_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_UImm5, MCK_UImm4 }, },
  { 770 /* armsra.w */, LoongArch::ARMSRA_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 779 /* armsrai.w */, LoongArch::ARMSRAI_W, Convert__Reg1_0__UImm51_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_UImm5, MCK_UImm4 }, },
  { 789 /* armsrl.w */, LoongArch::ARMSRL_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 798 /* armsrli.w */, LoongArch::ARMSRLI_W, Convert__Reg1_0__UImm51_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_UImm5, MCK_UImm4 }, },
  { 808 /* armsub.w */, LoongArch::ARMSUB_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 817 /* armxor.w */, LoongArch::ARMXOR_W, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 826 /* asrtgt.d */, LoongArch::ASRTGT_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 835 /* asrtle.d */, LoongArch::ASRTLE_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 844 /* b */, LoongArch::B, Convert__SImm26OperandB1_0, AMFBS_None, { MCK_SImm26OperandB }, },
  { 846 /* bceqz */, LoongArch::BCEQZ, Convert__Reg1_0__SImm21lsl21_1, AMFBS_None, { MCK_CFR, MCK_SImm21lsl2 }, },
  { 852 /* bcnez */, LoongArch::BCNEZ, Convert__Reg1_0__SImm21lsl21_1, AMFBS_None, { MCK_CFR, MCK_SImm21lsl2 }, },
  { 858 /* beq */, LoongArch::BEQ, Convert__Reg1_0__Reg1_1__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 862 /* beqz */, LoongArch::BEQZ, Convert__Reg1_0__SImm21lsl21_1, AMFBS_None, { MCK_GPR, MCK_SImm21lsl2 }, },
  { 867 /* bge */, LoongArch::BGE, Convert__Reg1_0__Reg1_1__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 871 /* bgeu */, LoongArch::BGEU, Convert__Reg1_0__Reg1_1__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 876 /* bgez */, LoongArch::BGE, Convert__Reg1_0__regR0__SImm16lsl21_1, AMFBS_None, { MCK_GPR, MCK_SImm16lsl2 }, },
  { 881 /* bgt */, LoongArch::BLT, Convert__Reg1_1__Reg1_0__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 885 /* bgtu */, LoongArch::BLTU, Convert__Reg1_1__Reg1_0__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 890 /* bgtz */, LoongArch::BLT, Convert__regR0__Reg1_0__SImm16lsl21_1, AMFBS_None, { MCK_GPR, MCK_SImm16lsl2 }, },
  { 895 /* bitrev.4b */, LoongArch::BITREV_4B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 905 /* bitrev.8b */, LoongArch::BITREV_8B, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 915 /* bitrev.d */, LoongArch::BITREV_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 924 /* bitrev.w */, LoongArch::BITREV_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 933 /* bl */, LoongArch::BL, Convert__SImm26OperandBL1_0, AMFBS_None, { MCK_SImm26OperandBL }, },
  { 936 /* ble */, LoongArch::BGE, Convert__Reg1_1__Reg1_0__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 940 /* bleu */, LoongArch::BGEU, Convert__Reg1_1__Reg1_0__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 945 /* blez */, LoongArch::BGE, Convert__regR0__Reg1_0__SImm16lsl21_1, AMFBS_None, { MCK_GPR, MCK_SImm16lsl2 }, },
  { 950 /* blt */, LoongArch::BLT, Convert__Reg1_0__Reg1_1__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 954 /* bltu */, LoongArch::BLTU, Convert__Reg1_0__Reg1_1__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 959 /* bltz */, LoongArch::BLT, Convert__Reg1_0__regR0__SImm16lsl21_1, AMFBS_None, { MCK_GPR, MCK_SImm16lsl2 }, },
  { 964 /* bne */, LoongArch::BNE, Convert__Reg1_0__Reg1_1__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 968 /* bnez */, LoongArch::BNEZ, Convert__Reg1_0__SImm21lsl21_1, AMFBS_None, { MCK_GPR, MCK_SImm21lsl2 }, },
  { 973 /* break */, LoongArch::BREAK, Convert__UImm151_0, AMFBS_None, { MCK_UImm15 }, },
  { 979 /* bstrins.d */, LoongArch::BSTRINS_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2__UImm61_3, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_UImm6, MCK_UImm6 }, },
  { 989 /* bstrins.w */, LoongArch::BSTRINS_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2__UImm51_3, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm5, MCK_UImm5 }, },
  { 999 /* bstrpick.d */, LoongArch::BSTRPICK_D, Convert__Reg1_0__Reg1_1__UImm61_2__UImm61_3, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_UImm6, MCK_UImm6 }, },
  { 1010 /* bstrpick.w */, LoongArch::BSTRPICK_W, Convert__Reg1_0__Reg1_1__UImm51_2__UImm51_3, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm5, MCK_UImm5 }, },
  { 1021 /* bytepick.d */, LoongArch::BYTEPICK_D, Convert__Reg1_0__Reg1_1__Reg1_2__UImm31_3, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR, MCK_UImm3 }, },
  { 1032 /* bytepick.w */, LoongArch::BYTEPICK_W, Convert__Reg1_0__Reg1_1__Reg1_2__UImm21_3, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR, MCK_UImm2 }, },
  { 1043 /* cacop */, LoongArch::CACOP, Convert__UImm51_0__Reg1_1__SImm121_2, AMFBS_None, { MCK_UImm5, MCK_GPR, MCK_SImm12 }, },
  { 1049 /* call */, LoongArch::PseudoCALL, Convert__BareSymbol1_0, AMFBS_None, { MCK_BareSymbol }, },
  { 1054 /* call30 */, LoongArch::PseudoCALL30, Convert__BareSymbol1_0, AMFBS_None, { MCK_BareSymbol }, },
  { 1061 /* call36 */, LoongArch::PseudoCALL36, Convert__BareSymbol1_0, AMFBS_IsLA64, { MCK_BareSymbol }, },
  { 1068 /* clo.d */, LoongArch::CLO_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 1074 /* clo.w */, LoongArch::CLO_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 1080 /* clz.d */, LoongArch::CLZ_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 1086 /* clz.w */, LoongArch::CLZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 1092 /* cpucfg */, LoongArch::CPUCFG, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 1099 /* crc.w.b.w */, LoongArch::CRC_W_B_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1109 /* crc.w.d.w */, LoongArch::CRC_W_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1119 /* crc.w.h.w */, LoongArch::CRC_W_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1129 /* crc.w.w.w */, LoongArch::CRC_W_W_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1139 /* crcc.w.b.w */, LoongArch::CRCC_W_B_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1150 /* crcc.w.d.w */, LoongArch::CRCC_W_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1161 /* crcc.w.h.w */, LoongArch::CRCC_W_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1172 /* crcc.w.w.w */, LoongArch::CRCC_W_W_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1183 /* csrrd */, LoongArch::CSRRD, Convert__Reg1_0__UImm141_1, AMFBS_None, { MCK_GPR, MCK_UImm14 }, },
  { 1189 /* csrwr */, LoongArch::CSRWR, Convert__Reg1_0__Tie0_1_1__UImm141_1, AMFBS_None, { MCK_GPR, MCK_UImm14 }, },
  { 1195 /* csrxchg */, LoongArch::CSRXCHG, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm141_2, AMFBS_None, { MCK_GPR, MCK_GPRNoR0R1, MCK_UImm14 }, },
  { 1203 /* cto.d */, LoongArch::CTO_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 1209 /* cto.w */, LoongArch::CTO_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 1215 /* ctz.d */, LoongArch::CTZ_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 1221 /* ctz.w */, LoongArch::CTZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 1227 /* dbar */, LoongArch::DBAR, Convert__UImm151_0, AMFBS_None, { MCK_UImm15 }, },
  { 1232 /* dbcl */, LoongArch::DBCL, Convert__UImm151_0, AMFBS_None, { MCK_UImm15 }, },
  { 1237 /* div.d */, LoongArch::DIV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1243 /* div.du */, LoongArch::DIV_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1250 /* div.w */, LoongArch::DIV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1256 /* div.wu */, LoongArch::DIV_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1263 /* ertn */, LoongArch::ERTN, Convert_NoOperands, AMFBS_None, {  }, },
  { 1268 /* ext.w.b */, LoongArch::EXT_W_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 1276 /* ext.w.h */, LoongArch::EXT_W_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 1284 /* fabs.d */, LoongArch::FABS_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 1291 /* fabs.s */, LoongArch::FABS_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 1298 /* fadd.d */, LoongArch::FADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1305 /* fadd.s */, LoongArch::FADD_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1312 /* fclass.d */, LoongArch::FCLASS_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 1321 /* fclass.s */, LoongArch::FCLASS_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 1330 /* fcmp.caf.d */, LoongArch::FCMP_CAF_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1341 /* fcmp.caf.s */, LoongArch::FCMP_CAF_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1352 /* fcmp.ceq.d */, LoongArch::FCMP_CEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1363 /* fcmp.ceq.s */, LoongArch::FCMP_CEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1374 /* fcmp.cle.d */, LoongArch::FCMP_CLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1385 /* fcmp.cle.s */, LoongArch::FCMP_CLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1396 /* fcmp.clt.d */, LoongArch::FCMP_CLT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1407 /* fcmp.clt.s */, LoongArch::FCMP_CLT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1418 /* fcmp.cne.d */, LoongArch::FCMP_CNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1429 /* fcmp.cne.s */, LoongArch::FCMP_CNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1440 /* fcmp.cor.d */, LoongArch::FCMP_COR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1451 /* fcmp.cor.s */, LoongArch::FCMP_COR_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1462 /* fcmp.cueq.d */, LoongArch::FCMP_CUEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1474 /* fcmp.cueq.s */, LoongArch::FCMP_CUEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1486 /* fcmp.cule.d */, LoongArch::FCMP_CULE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1498 /* fcmp.cule.s */, LoongArch::FCMP_CULE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1510 /* fcmp.cult.d */, LoongArch::FCMP_CULT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1522 /* fcmp.cult.s */, LoongArch::FCMP_CULT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1534 /* fcmp.cun.d */, LoongArch::FCMP_CUN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1545 /* fcmp.cun.s */, LoongArch::FCMP_CUN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1556 /* fcmp.cune.d */, LoongArch::FCMP_CUNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1568 /* fcmp.cune.s */, LoongArch::FCMP_CUNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1580 /* fcmp.saf.d */, LoongArch::FCMP_SAF_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1591 /* fcmp.saf.s */, LoongArch::FCMP_SAF_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1602 /* fcmp.seq.d */, LoongArch::FCMP_SEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1613 /* fcmp.seq.s */, LoongArch::FCMP_SEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1624 /* fcmp.sle.d */, LoongArch::FCMP_SLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1635 /* fcmp.sle.s */, LoongArch::FCMP_SLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1646 /* fcmp.slt.d */, LoongArch::FCMP_SLT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1657 /* fcmp.slt.s */, LoongArch::FCMP_SLT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1668 /* fcmp.sne.d */, LoongArch::FCMP_SNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1679 /* fcmp.sne.s */, LoongArch::FCMP_SNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1690 /* fcmp.sor.d */, LoongArch::FCMP_SOR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1701 /* fcmp.sor.s */, LoongArch::FCMP_SOR_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1712 /* fcmp.sueq.d */, LoongArch::FCMP_SUEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1724 /* fcmp.sueq.s */, LoongArch::FCMP_SUEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1736 /* fcmp.sule.d */, LoongArch::FCMP_SULE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1748 /* fcmp.sule.s */, LoongArch::FCMP_SULE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1760 /* fcmp.sult.d */, LoongArch::FCMP_SULT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1772 /* fcmp.sult.s */, LoongArch::FCMP_SULT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1784 /* fcmp.sun.d */, LoongArch::FCMP_SUN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1795 /* fcmp.sun.s */, LoongArch::FCMP_SUN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1806 /* fcmp.sune.d */, LoongArch::FCMP_SUNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR64, MCK_FPR64 }, },
  { 1818 /* fcmp.sune.s */, LoongArch::FCMP_SUNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_CFR, MCK_FPR32, MCK_FPR32 }, },
  { 1830 /* fcopysign.d */, LoongArch::FCOPYSIGN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1842 /* fcopysign.s */, LoongArch::FCOPYSIGN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1854 /* fcvt.d.ld */, LoongArch::FCVT_D_LD, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1864 /* fcvt.d.s */, LoongArch::FCVT_D_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR32 }, },
  { 1873 /* fcvt.ld.d */, LoongArch::FCVT_LD_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 1883 /* fcvt.s.d */, LoongArch::FCVT_S_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR64 }, },
  { 1892 /* fcvt.ud.d */, LoongArch::FCVT_UD_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 1902 /* fdiv.d */, LoongArch::FDIV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1909 /* fdiv.s */, LoongArch::FDIV_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1916 /* ffint.d.l */, LoongArch::FFINT_D_L, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 1926 /* ffint.d.w */, LoongArch::FFINT_D_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR32 }, },
  { 1936 /* ffint.s.l */, LoongArch::FFINT_S_L, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR64 }, },
  { 1946 /* ffint.s.w */, LoongArch::FFINT_S_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 1956 /* fld.d */, LoongArch::FLD_D, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_FPR64, MCK_GPR, MCK_SImm12addlike }, },
  { 1962 /* fld.s */, LoongArch::FLD_S, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_FPR32, MCK_GPR, MCK_SImm12addlike }, },
  { 1968 /* fldgt.d */, LoongArch::FLDGT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_GPR, MCK_GPR }, },
  { 1976 /* fldgt.s */, LoongArch::FLDGT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_GPR, MCK_GPR }, },
  { 1984 /* fldle.d */, LoongArch::FLDLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_GPR, MCK_GPR }, },
  { 1992 /* fldle.s */, LoongArch::FLDLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_GPR, MCK_GPR }, },
  { 2000 /* fldx.d */, LoongArch::FLDX_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_GPR, MCK_GPR }, },
  { 2007 /* fldx.s */, LoongArch::FLDX_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_GPR, MCK_GPR }, },
  { 2014 /* flogb.d */, LoongArch::FLOGB_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2022 /* flogb.s */, LoongArch::FLOGB_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2030 /* fmadd.d */, LoongArch::FMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2038 /* fmadd.s */, LoongArch::FMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2046 /* fmax.d */, LoongArch::FMAX_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2053 /* fmax.s */, LoongArch::FMAX_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2060 /* fmaxa.d */, LoongArch::FMAXA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2068 /* fmaxa.s */, LoongArch::FMAXA_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2076 /* fmin.d */, LoongArch::FMIN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2083 /* fmin.s */, LoongArch::FMIN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2090 /* fmina.d */, LoongArch::FMINA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2098 /* fmina.s */, LoongArch::FMINA_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2106 /* fmov.d */, LoongArch::FMOV_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2113 /* fmov.s */, LoongArch::FMOV_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2120 /* fmsub.d */, LoongArch::FMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2128 /* fmsub.s */, LoongArch::FMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2136 /* fmul.d */, LoongArch::FMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2143 /* fmul.s */, LoongArch::FMUL_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2150 /* fneg.d */, LoongArch::FNEG_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2157 /* fneg.s */, LoongArch::FNEG_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2164 /* fnmadd.d */, LoongArch::FNMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2173 /* fnmadd.s */, LoongArch::FNMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2182 /* fnmsub.d */, LoongArch::FNMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2191 /* fnmsub.s */, LoongArch::FNMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2200 /* frecip.d */, LoongArch::FRECIP_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2209 /* frecip.s */, LoongArch::FRECIP_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2218 /* frecipe.d */, LoongArch::FRECIPE_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2228 /* frecipe.s */, LoongArch::FRECIPE_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2238 /* frint.d */, LoongArch::FRINT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2246 /* frint.s */, LoongArch::FRINT_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2254 /* frsqrt.d */, LoongArch::FRSQRT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2263 /* frsqrt.s */, LoongArch::FRSQRT_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2272 /* frsqrte.d */, LoongArch::FRSQRTE_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2282 /* frsqrte.s */, LoongArch::FRSQRTE_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2292 /* fscaleb.d */, LoongArch::FSCALEB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2302 /* fscaleb.s */, LoongArch::FSCALEB_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2312 /* fsel */, LoongArch::FSEL_xS, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_CFR }, },
  { 2317 /* fsqrt.d */, LoongArch::FSQRT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2325 /* fsqrt.s */, LoongArch::FSQRT_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2333 /* fst.d */, LoongArch::FST_D, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_FPR64, MCK_GPR, MCK_SImm12addlike }, },
  { 2339 /* fst.s */, LoongArch::FST_S, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_FPR32, MCK_GPR, MCK_SImm12addlike }, },
  { 2345 /* fstgt.d */, LoongArch::FSTGT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_GPR, MCK_GPR }, },
  { 2353 /* fstgt.s */, LoongArch::FSTGT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_GPR, MCK_GPR }, },
  { 2361 /* fstle.d */, LoongArch::FSTLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_GPR, MCK_GPR }, },
  { 2369 /* fstle.s */, LoongArch::FSTLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_GPR, MCK_GPR }, },
  { 2377 /* fstx.d */, LoongArch::FSTX_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_GPR, MCK_GPR }, },
  { 2384 /* fstx.s */, LoongArch::FSTX_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_GPR, MCK_GPR }, },
  { 2391 /* fsub.d */, LoongArch::FSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 2398 /* fsub.s */, LoongArch::FSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 2405 /* ftint.l.d */, LoongArch::FTINT_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2415 /* ftint.l.s */, LoongArch::FTINT_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR32 }, },
  { 2425 /* ftint.w.d */, LoongArch::FTINT_W_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR64 }, },
  { 2435 /* ftint.w.s */, LoongArch::FTINT_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2445 /* ftintrm.l.d */, LoongArch::FTINTRM_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2457 /* ftintrm.l.s */, LoongArch::FTINTRM_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR32 }, },
  { 2469 /* ftintrm.w.d */, LoongArch::FTINTRM_W_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR64 }, },
  { 2481 /* ftintrm.w.s */, LoongArch::FTINTRM_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2493 /* ftintrne.l.d */, LoongArch::FTINTRNE_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2506 /* ftintrne.l.s */, LoongArch::FTINTRNE_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR32 }, },
  { 2519 /* ftintrne.w.d */, LoongArch::FTINTRNE_W_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR64 }, },
  { 2532 /* ftintrne.w.s */, LoongArch::FTINTRNE_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2545 /* ftintrp.l.d */, LoongArch::FTINTRP_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2557 /* ftintrp.l.s */, LoongArch::FTINTRP_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR32 }, },
  { 2569 /* ftintrp.w.d */, LoongArch::FTINTRP_W_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR64 }, },
  { 2581 /* ftintrp.w.s */, LoongArch::FTINTRP_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2593 /* ftintrz.l.d */, LoongArch::FTINTRZ_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR64 }, },
  { 2605 /* ftintrz.l.s */, LoongArch::FTINTRZ_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_FPR32 }, },
  { 2617 /* ftintrz.w.d */, LoongArch::FTINTRZ_W_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR64 }, },
  { 2629 /* ftintrz.w.s */, LoongArch::FTINTRZ_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_FPR32 }, },
  { 2641 /* gcsrrd */, LoongArch::GCSRRD, Convert__Reg1_0__UImm141_1, AMFBS_None, { MCK_GPR, MCK_UImm14 }, },
  { 2648 /* gcsrwr */, LoongArch::GCSRWR, Convert__Reg1_0__Tie0_1_1__UImm141_1, AMFBS_None, { MCK_GPR, MCK_UImm14 }, },
  { 2655 /* gcsrxchg */, LoongArch::GCSRXCHG, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm141_2, AMFBS_None, { MCK_GPR, MCK_GPRNoR0R1, MCK_UImm14 }, },
  { 2664 /* gtlbflush */, LoongArch::GTLBFLUSH, Convert_NoOperands, AMFBS_None, {  }, },
  { 2674 /* hvcl */, LoongArch::HVCL, Convert__UImm151_0, AMFBS_None, { MCK_UImm15 }, },
  { 2679 /* ibar */, LoongArch::IBAR, Convert__UImm151_0, AMFBS_None, { MCK_UImm15 }, },
  { 2684 /* idle */, LoongArch::IDLE, Convert__UImm151_0, AMFBS_None, { MCK_UImm15 }, },
  { 2689 /* invtlb */, LoongArch::INVTLB, Convert__Reg1_2__Reg1_1__UImm51_0, AMFBS_None, { MCK_UImm5, MCK_GPR, MCK_GPR }, },
  { 2696 /* iocsrrd.b */, LoongArch::IOCSRRD_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 2706 /* iocsrrd.d */, LoongArch::IOCSRRD_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 2716 /* iocsrrd.h */, LoongArch::IOCSRRD_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 2726 /* iocsrrd.w */, LoongArch::IOCSRRD_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 2736 /* iocsrwr.b */, LoongArch::IOCSRWR_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 2746 /* iocsrwr.d */, LoongArch::IOCSRWR_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 2756 /* iocsrwr.h */, LoongArch::IOCSRWR_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 2766 /* iocsrwr.w */, LoongArch::IOCSRWR_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 2776 /* jirl */, LoongArch::JIRL, Convert__Reg1_0__Reg1_1__SImm16lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm16lsl2 }, },
  { 2781 /* jiscr0 */, LoongArch::JISCR0, Convert__SImm21lsl21_0, AMFBS_None, { MCK_SImm21lsl2 }, },
  { 2788 /* jiscr1 */, LoongArch::JISCR1, Convert__SImm21lsl21_0, AMFBS_None, { MCK_SImm21lsl2 }, },
  { 2795 /* jr */, LoongArch::JIRL, Convert__regR0__Reg1_0__imm_95_0, AMFBS_None, { MCK_GPR }, },
  { 2798 /* la */, LoongArch::PseudoLA_PCREL, Convert__Reg1_0__BareSymbol1_1, AMFBS_HasLaGlobalWithPcrel, { MCK_GPR, MCK_BareSymbol }, },
  { 2798 /* la */, LoongArch::PseudoLA_ABS, Convert__Reg1_0__BareSymbol1_1, AMFBS_HasLaGlobalWithAbs, { MCK_GPR, MCK_BareSymbol }, },
  { 2798 /* la */, LoongArch::PseudoLA_GOT, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2801 /* la.abs */, LoongArch::PseudoLA_ABS, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2801 /* la.abs */, LoongArch::PseudoLA_ABS_LARGE, Convert__Reg1_0__imm_95_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2808 /* la.global */, LoongArch::PseudoLA_PCREL, Convert__Reg1_0__BareSymbol1_1, AMFBS_HasLaGlobalWithPcrel, { MCK_GPR, MCK_BareSymbol }, },
  { 2808 /* la.global */, LoongArch::PseudoLA_ABS, Convert__Reg1_0__BareSymbol1_1, AMFBS_HasLaGlobalWithAbs, { MCK_GPR, MCK_BareSymbol }, },
  { 2808 /* la.global */, LoongArch::PseudoLA_GOT, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2808 /* la.global */, LoongArch::PseudoLA_PCREL_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_HasLaGlobalWithPcrel, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2808 /* la.global */, LoongArch::PseudoLA_ABS_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_HasLaGlobalWithAbs, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2808 /* la.global */, LoongArch::PseudoLA_GOT_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2818 /* la.got */, LoongArch::PseudoLA_GOT, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2818 /* la.got */, LoongArch::PseudoLA_GOT_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2825 /* la.local */, LoongArch::PseudoLA_ABS, Convert__Reg1_0__BareSymbol1_1, AMFBS_HasLaLocalWithAbs, { MCK_GPR, MCK_BareSymbol }, },
  { 2825 /* la.local */, LoongArch::PseudoLA_PCREL, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2825 /* la.local */, LoongArch::PseudoLA_ABS_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_HasLaLocalWithAbs, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2825 /* la.local */, LoongArch::PseudoLA_PCREL_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2834 /* la.pcrel */, LoongArch::PseudoLA_PCREL, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2834 /* la.pcrel */, LoongArch::PseudoLA_PCREL_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2843 /* la.tls.desc */, LoongArch::PseudoLA_TLS_DESC, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2843 /* la.tls.desc */, LoongArch::PseudoLA_TLS_DESC_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2855 /* la.tls.gd */, LoongArch::PseudoLA_TLS_GD, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2855 /* la.tls.gd */, LoongArch::PseudoLA_TLS_GD_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2865 /* la.tls.ie */, LoongArch::PseudoLA_TLS_IE, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2865 /* la.tls.ie */, LoongArch::PseudoLA_TLS_IE_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2875 /* la.tls.ld */, LoongArch::PseudoLA_TLS_LD, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2875 /* la.tls.ld */, LoongArch::PseudoLA_TLS_LD_LARGE, Convert__Reg1_0__Reg1_1__BareSymbol1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_BareSymbol }, },
  { 2885 /* la.tls.le */, LoongArch::PseudoLA_TLS_LE, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 2895 /* ld.b */, LoongArch::LD_B, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 2900 /* ld.bu */, LoongArch::LD_BU, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 2906 /* ld.d */, LoongArch::LD_D, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 2911 /* ld.h */, LoongArch::LD_H, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 2916 /* ld.hu */, LoongArch::LD_HU, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 2922 /* ld.w */, LoongArch::LD_W, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 2927 /* ld.wu */, LoongArch::LD_WU, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 2933 /* lddir */, LoongArch::LDDIR, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm8 }, },
  { 2939 /* ldgt.b */, LoongArch::LDGT_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2946 /* ldgt.d */, LoongArch::LDGT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2953 /* ldgt.h */, LoongArch::LDGT_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2960 /* ldgt.w */, LoongArch::LDGT_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2967 /* ldl.d */, LoongArch::LDL_D, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 2973 /* ldl.w */, LoongArch::LDL_W, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 2979 /* ldle.b */, LoongArch::LDLE_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2986 /* ldle.d */, LoongArch::LDLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2993 /* ldle.h */, LoongArch::LDLE_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3000 /* ldle.w */, LoongArch::LDLE_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3007 /* ldpte */, LoongArch::LDPTE, Convert__Reg1_0__UImm81_1, AMFBS_None, { MCK_GPR, MCK_UImm8 }, },
  { 3013 /* ldptr.d */, LoongArch::LDPTR_D, Convert__Reg1_0__Reg1_1__SImm14lsl21_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm14lsl2 }, },
  { 3021 /* ldptr.w */, LoongArch::LDPTR_W, Convert__Reg1_0__Reg1_1__SImm14lsl21_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm14lsl2 }, },
  { 3029 /* ldr.d */, LoongArch::LDR_D, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 3035 /* ldr.w */, LoongArch::LDR_W, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 3041 /* ldx.b */, LoongArch::LDX_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3047 /* ldx.bu */, LoongArch::LDX_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3054 /* ldx.d */, LoongArch::LDX_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3060 /* ldx.h */, LoongArch::LDX_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3066 /* ldx.hu */, LoongArch::LDX_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3073 /* ldx.w */, LoongArch::LDX_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3079 /* ldx.wu */, LoongArch::LDX_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3086 /* li.d */, LoongArch::PseudoLI_D, Convert__Reg1_0__Imm641_1, AMFBS_IsLA64, { MCK_GPR, MCK_Imm64 }, },
  { 3091 /* li.w */, LoongArch::PseudoLI_W, Convert__Reg1_0__Imm321_1, AMFBS_None, { MCK_GPR, MCK_Imm32 }, },
  { 3096 /* ll.d */, LoongArch::LL_D, Convert__Reg1_0__Reg1_1__SImm14lsl21_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm14lsl2 }, },
  { 3101 /* ll.w */, LoongArch::LL_W, Convert__Reg1_0__Reg1_1__SImm14lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm14lsl2 }, },
  { 3106 /* llacq.d */, LoongArch::LLACQ_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3114 /* llacq.w */, LoongArch::LLACQ_W, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3122 /* lu12i.w */, LoongArch::LU12I_W, Convert__Reg1_0__SImm20lu12iw1_1, AMFBS_None, { MCK_GPR, MCK_SImm20lu12iw }, },
  { 3130 /* lu32i.d */, LoongArch::LU32I_D, Convert__Reg1_0__Tie0_1_1__SImm20lu32id1_1, AMFBS_IsLA64, { MCK_GPR, MCK_SImm20lu32id }, },
  { 3138 /* lu52i.d */, LoongArch::LU52I_D, Convert__Reg1_0__Reg1_1__SImm12lu52id1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm12lu52id }, },
  { 3146 /* maskeqz */, LoongArch::MASKEQZ, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3154 /* masknez */, LoongArch::MASKNEZ, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3162 /* mod.d */, LoongArch::MOD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3168 /* mod.du */, LoongArch::MOD_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3175 /* mod.w */, LoongArch::MOD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3181 /* mod.wu */, LoongArch::MOD_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3188 /* movcf2fr */, LoongArch::MOVCF2FR_xS, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_CFR }, },
  { 3197 /* movcf2gr */, LoongArch::MOVCF2GR, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_CFR }, },
  { 3206 /* move */, LoongArch::OR, Convert__Reg1_0__Reg1_1__regR0, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 3211 /* movfcsr2gr */, LoongArch::MOVFCSR2GR, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_FCSR }, },
  { 3222 /* movfr2cf */, LoongArch::MOVFR2CF_xS, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_FPR32 }, },
  { 3231 /* movfr2gr.d */, LoongArch::MOVFR2GR_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_FPR64 }, },
  { 3242 /* movfr2gr.s */, LoongArch::MOVFR2GR_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_FPR32 }, },
  { 3253 /* movfrh2gr.s */, LoongArch::MOVFRH2GR_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_FPR64 }, },
  { 3265 /* movgr2cf */, LoongArch::MOVGR2CF, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_GPR }, },
  { 3274 /* movgr2fcsr */, LoongArch::MOVGR2FCSR, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FCSR, MCK_GPR }, },
  { 3285 /* movgr2fr.d */, LoongArch::MOVGR2FR_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_FPR64, MCK_GPR }, },
  { 3296 /* movgr2fr.w */, LoongArch::MOVGR2FR_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPR32, MCK_GPR }, },
  { 3307 /* movgr2frh.w */, LoongArch::MOVGR2FRH_W, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_None, { MCK_FPR64, MCK_GPR }, },
  { 3319 /* movgr2scr */, LoongArch::MOVGR2SCR, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_SCR, MCK_GPR }, },
  { 3329 /* movscr2gr */, LoongArch::MOVSCR2GR, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_SCR }, },
  { 3339 /* mul.d */, LoongArch::MUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3345 /* mul.w */, LoongArch::MUL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3351 /* mulh.d */, LoongArch::MULH_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3358 /* mulh.du */, LoongArch::MULH_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3366 /* mulh.w */, LoongArch::MULH_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3373 /* mulh.wu */, LoongArch::MULH_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3381 /* mulw.d.w */, LoongArch::MULW_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3390 /* mulw.d.wu */, LoongArch::MULW_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3400 /* nop */, LoongArch::ANDI, Convert__regR0__regR0__imm_95_0, AMFBS_None, {  }, },
  { 3404 /* nor */, LoongArch::NOR, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3408 /* or */, LoongArch::OR, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3411 /* ori */, LoongArch::ORI, Convert__Reg1_0__Reg1_1__UImm12ori1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm12ori }, },
  { 3415 /* orn */, LoongArch::ORN, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3419 /* pcaddi */, LoongArch::PCADDI, Convert__Reg1_0__SImm20pcaddi1_1, AMFBS_None, { MCK_GPR, MCK_SImm20pcaddi }, },
  { 3426 /* pcaddu12i */, LoongArch::PCADDU12I, Convert__Reg1_0__SImm20pcaddu12i1_1, AMFBS_None, { MCK_GPR, MCK_SImm20pcaddu12i }, },
  { 3436 /* pcaddu18i */, LoongArch::PCADDU18I, Convert__Reg1_0__SImm20pcaddu18i1_1, AMFBS_IsLA64, { MCK_GPR, MCK_SImm20pcaddu18i }, },
  { 3446 /* pcalau12i */, LoongArch::PCALAU12I, Convert__Reg1_0__SImm20pcalau12i1_1, AMFBS_None, { MCK_GPR, MCK_SImm20pcalau12i }, },
  { 3456 /* preld */, LoongArch::PRELD, Convert__UImm51_0__Reg1_1__SImm121_2, AMFBS_None, { MCK_UImm5, MCK_GPR, MCK_SImm12 }, },
  { 3462 /* preldx */, LoongArch::PRELDX, Convert__UImm51_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_UImm5, MCK_GPR, MCK_GPR }, },
  { 3469 /* rcr.b */, LoongArch::RCR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3475 /* rcr.d */, LoongArch::RCR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3481 /* rcr.h */, LoongArch::RCR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3487 /* rcr.w */, LoongArch::RCR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3493 /* rcri.b */, LoongArch::RCRI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm3 }, },
  { 3500 /* rcri.d */, LoongArch::RCRI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_UImm6 }, },
  { 3507 /* rcri.h */, LoongArch::RCRI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 3514 /* rcri.w */, LoongArch::RCRI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3521 /* rdcntid.w */, LoongArch::RDTIMEL_W, Convert__regR0__Reg1_0, AMFBS_None, { MCK_GPR }, },
  { 3531 /* rdcntvh.w */, LoongArch::RDTIMEH_W, Convert__Reg1_0__regR0, AMFBS_None, { MCK_GPR }, },
  { 3541 /* rdcntvl.w */, LoongArch::RDTIMEL_W, Convert__Reg1_0__regR0, AMFBS_None, { MCK_GPR }, },
  { 3551 /* rdtime.d */, LoongArch::RDTIME_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3560 /* rdtimeh.w */, LoongArch::RDTIMEH_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 3570 /* rdtimel.w */, LoongArch::RDTIMEL_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 3580 /* ret */, LoongArch::JIRL, Convert__regR0__regR1__imm_95_0, AMFBS_None, {  }, },
  { 3584 /* revb.2h */, LoongArch::REVB_2H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 3592 /* revb.2w */, LoongArch::REVB_2W, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3600 /* revb.4h */, LoongArch::REVB_4H, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3608 /* revb.d */, LoongArch::REVB_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3615 /* revh.2w */, LoongArch::REVH_2W, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3623 /* revh.d */, LoongArch::REVH_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3630 /* rotr.b */, LoongArch::ROTR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3637 /* rotr.d */, LoongArch::ROTR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3644 /* rotr.h */, LoongArch::ROTR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3651 /* rotr.w */, LoongArch::ROTR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3658 /* rotri.b */, LoongArch::ROTRI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm3 }, },
  { 3666 /* rotri.d */, LoongArch::ROTRI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_UImm6 }, },
  { 3674 /* rotri.h */, LoongArch::ROTRI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm4 }, },
  { 3682 /* rotri.w */, LoongArch::ROTRI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3690 /* sbc.b */, LoongArch::SBC_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3696 /* sbc.d */, LoongArch::SBC_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3702 /* sbc.h */, LoongArch::SBC_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3708 /* sbc.w */, LoongArch::SBC_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3714 /* sc.d */, LoongArch::SC_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__SImm14lsl21_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm14lsl2 }, },
  { 3719 /* sc.q */, LoongArch::SC_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3724 /* sc.w */, LoongArch::SC_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__SImm14lsl21_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm14lsl2 }, },
  { 3729 /* screl.d */, LoongArch::SCREL_D, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3737 /* screl.w */, LoongArch::SCREL_W, Convert__Reg1_0__Tie0_1_1__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 3745 /* setarmj */, LoongArch::SETARMJ, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 3753 /* setx86j */, LoongArch::SETX86J, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 3761 /* setx86loope */, LoongArch::SETX86LOOPE, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 3773 /* setx86loopne */, LoongArch::SETX86LOOPNE, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 3786 /* sll.d */, LoongArch::SLL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3792 /* sll.w */, LoongArch::SLL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3798 /* slli.d */, LoongArch::SLLI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_UImm6 }, },
  { 3805 /* slli.w */, LoongArch::SLLI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3812 /* slt */, LoongArch::SLT, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3816 /* slti */, LoongArch::SLTI, Convert__Reg1_0__Reg1_1__SImm121_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 3821 /* sltu */, LoongArch::SLTU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3826 /* sltui */, LoongArch::SLTUI, Convert__Reg1_0__Reg1_1__SImm121_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 3832 /* sra.d */, LoongArch::SRA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3838 /* sra.w */, LoongArch::SRA_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3844 /* srai.d */, LoongArch::SRAI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_UImm6 }, },
  { 3851 /* srai.w */, LoongArch::SRAI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3858 /* srl.d */, LoongArch::SRL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3864 /* srl.w */, LoongArch::SRL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3870 /* srli.d */, LoongArch::SRLI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_UImm6 }, },
  { 3877 /* srli.w */, LoongArch::SRLI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 3884 /* st.b */, LoongArch::ST_B, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 3889 /* st.d */, LoongArch::ST_D, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 3894 /* st.h */, LoongArch::ST_H, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 3899 /* st.w */, LoongArch::ST_W, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 3904 /* stgt.b */, LoongArch::STGT_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3911 /* stgt.d */, LoongArch::STGT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3918 /* stgt.h */, LoongArch::STGT_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3925 /* stgt.w */, LoongArch::STGT_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3932 /* stl.d */, LoongArch::STL_D, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 3938 /* stl.w */, LoongArch::STL_W, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 3944 /* stle.b */, LoongArch::STLE_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3951 /* stle.d */, LoongArch::STLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3958 /* stle.h */, LoongArch::STLE_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3965 /* stle.w */, LoongArch::STLE_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 3972 /* stptr.d */, LoongArch::STPTR_D, Convert__Reg1_0__Reg1_1__SImm14lsl21_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm14lsl2 }, },
  { 3980 /* stptr.w */, LoongArch::STPTR_W, Convert__Reg1_0__Reg1_1__SImm14lsl21_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm14lsl2 }, },
  { 3988 /* str.d */, LoongArch::STR_D, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 3994 /* str.w */, LoongArch::STR_W, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_SImm12addlike }, },
  { 4000 /* stx.b */, LoongArch::STX_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 4006 /* stx.d */, LoongArch::STX_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 4012 /* stx.h */, LoongArch::STX_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 4018 /* stx.w */, LoongArch::STX_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 4024 /* sub.d */, LoongArch::SUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_IsLA64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 4030 /* sub.w */, LoongArch::SUB_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 4036 /* syscall */, LoongArch::SYSCALL, Convert__UImm151_0, AMFBS_None, { MCK_UImm15 }, },
  { 4044 /* tail */, LoongArch::PseudoTAIL, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 4049 /* tail30 */, LoongArch::PseudoTAIL30, Convert__Reg1_0__BareSymbol1_1, AMFBS_None, { MCK_GPR, MCK_BareSymbol }, },
  { 4056 /* tail36 */, LoongArch::PseudoTAIL36, Convert__Reg1_0__BareSymbol1_1, AMFBS_IsLA64, { MCK_GPR, MCK_BareSymbol }, },
  { 4063 /* tlbclr */, LoongArch::TLBCLR, Convert_NoOperands, AMFBS_None, {  }, },
  { 4070 /* tlbfill */, LoongArch::TLBFILL, Convert_NoOperands, AMFBS_None, {  }, },
  { 4078 /* tlbflush */, LoongArch::TLBFLUSH, Convert_NoOperands, AMFBS_None, {  }, },
  { 4087 /* tlbrd */, LoongArch::TLBRD, Convert_NoOperands, AMFBS_None, {  }, },
  { 4093 /* tlbsrch */, LoongArch::TLBSRCH, Convert_NoOperands, AMFBS_None, {  }, },
  { 4101 /* tlbwr */, LoongArch::TLBWR, Convert_NoOperands, AMFBS_None, {  }, },
  { 4107 /* ud */, LoongArch::UD, Convert__UImm51_0, AMFBS_None, { MCK_UImm5 }, },
  { 4110 /* vabsd.b */, LoongArch::VABSD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4118 /* vabsd.bu */, LoongArch::VABSD_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4127 /* vabsd.d */, LoongArch::VABSD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4135 /* vabsd.du */, LoongArch::VABSD_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4144 /* vabsd.h */, LoongArch::VABSD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4152 /* vabsd.hu */, LoongArch::VABSD_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4161 /* vabsd.w */, LoongArch::VABSD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4169 /* vabsd.wu */, LoongArch::VABSD_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4178 /* vadd.b */, LoongArch::VADD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4185 /* vadd.d */, LoongArch::VADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4192 /* vadd.h */, LoongArch::VADD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4199 /* vadd.q */, LoongArch::VADD_Q, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4206 /* vadd.w */, LoongArch::VADD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4213 /* vadda.b */, LoongArch::VADDA_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4221 /* vadda.d */, LoongArch::VADDA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4229 /* vadda.h */, LoongArch::VADDA_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4237 /* vadda.w */, LoongArch::VADDA_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4245 /* vaddi.bu */, LoongArch::VADDI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 4254 /* vaddi.du */, LoongArch::VADDI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 4263 /* vaddi.hu */, LoongArch::VADDI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 4272 /* vaddi.wu */, LoongArch::VADDI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 4281 /* vaddwev.d.w */, LoongArch::VADDWEV_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4293 /* vaddwev.d.wu */, LoongArch::VADDWEV_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4306 /* vaddwev.d.wu.w */, LoongArch::VADDWEV_D_WU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4321 /* vaddwev.h.b */, LoongArch::VADDWEV_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4333 /* vaddwev.h.bu */, LoongArch::VADDWEV_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4346 /* vaddwev.h.bu.b */, LoongArch::VADDWEV_H_BU_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4361 /* vaddwev.q.d */, LoongArch::VADDWEV_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4373 /* vaddwev.q.du */, LoongArch::VADDWEV_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4386 /* vaddwev.q.du.d */, LoongArch::VADDWEV_Q_DU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4401 /* vaddwev.w.h */, LoongArch::VADDWEV_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4413 /* vaddwev.w.hu */, LoongArch::VADDWEV_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4426 /* vaddwev.w.hu.h */, LoongArch::VADDWEV_W_HU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4441 /* vaddwod.d.w */, LoongArch::VADDWOD_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4453 /* vaddwod.d.wu */, LoongArch::VADDWOD_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4466 /* vaddwod.d.wu.w */, LoongArch::VADDWOD_D_WU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4481 /* vaddwod.h.b */, LoongArch::VADDWOD_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4493 /* vaddwod.h.bu */, LoongArch::VADDWOD_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4506 /* vaddwod.h.bu.b */, LoongArch::VADDWOD_H_BU_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4521 /* vaddwod.q.d */, LoongArch::VADDWOD_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4533 /* vaddwod.q.du */, LoongArch::VADDWOD_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4546 /* vaddwod.q.du.d */, LoongArch::VADDWOD_Q_DU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4561 /* vaddwod.w.h */, LoongArch::VADDWOD_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4573 /* vaddwod.w.hu */, LoongArch::VADDWOD_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4586 /* vaddwod.w.hu.h */, LoongArch::VADDWOD_W_HU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4601 /* vand.v */, LoongArch::VAND_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4608 /* vandi.b */, LoongArch::VANDI_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 4616 /* vandn.v */, LoongArch::VANDN_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4624 /* vavg.b */, LoongArch::VAVG_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4631 /* vavg.bu */, LoongArch::VAVG_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4639 /* vavg.d */, LoongArch::VAVG_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4646 /* vavg.du */, LoongArch::VAVG_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4654 /* vavg.h */, LoongArch::VAVG_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4661 /* vavg.hu */, LoongArch::VAVG_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4669 /* vavg.w */, LoongArch::VAVG_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4676 /* vavg.wu */, LoongArch::VAVG_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4684 /* vavgr.b */, LoongArch::VAVGR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4692 /* vavgr.bu */, LoongArch::VAVGR_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4701 /* vavgr.d */, LoongArch::VAVGR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4709 /* vavgr.du */, LoongArch::VAVGR_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4718 /* vavgr.h */, LoongArch::VAVGR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4726 /* vavgr.hu */, LoongArch::VAVGR_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4735 /* vavgr.w */, LoongArch::VAVGR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4743 /* vavgr.wu */, LoongArch::VAVGR_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4752 /* vbitclr.b */, LoongArch::VBITCLR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4762 /* vbitclr.d */, LoongArch::VBITCLR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4772 /* vbitclr.h */, LoongArch::VBITCLR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4782 /* vbitclr.w */, LoongArch::VBITCLR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4792 /* vbitclri.b */, LoongArch::VBITCLRI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 4803 /* vbitclri.d */, LoongArch::VBITCLRI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 4814 /* vbitclri.h */, LoongArch::VBITCLRI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 4825 /* vbitclri.w */, LoongArch::VBITCLRI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 4836 /* vbitrev.b */, LoongArch::VBITREV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4846 /* vbitrev.d */, LoongArch::VBITREV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4856 /* vbitrev.h */, LoongArch::VBITREV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4866 /* vbitrev.w */, LoongArch::VBITREV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4876 /* vbitrevi.b */, LoongArch::VBITREVI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 4887 /* vbitrevi.d */, LoongArch::VBITREVI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 4898 /* vbitrevi.h */, LoongArch::VBITREVI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 4909 /* vbitrevi.w */, LoongArch::VBITREVI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 4920 /* vbitsel.v */, LoongArch::VBITSEL_V, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4930 /* vbitseli.b */, LoongArch::VBITSELI_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 4941 /* vbitset.b */, LoongArch::VBITSET_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4951 /* vbitset.d */, LoongArch::VBITSET_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4961 /* vbitset.h */, LoongArch::VBITSET_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4971 /* vbitset.w */, LoongArch::VBITSET_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 4981 /* vbitseti.b */, LoongArch::VBITSETI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 4992 /* vbitseti.d */, LoongArch::VBITSETI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 5003 /* vbitseti.h */, LoongArch::VBITSETI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 5014 /* vbitseti.w */, LoongArch::VBITSETI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 5025 /* vbsll.v */, LoongArch::VBSLL_V, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 5033 /* vbsrl.v */, LoongArch::VBSRL_V, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 5041 /* vclo.b */, LoongArch::VCLO_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5048 /* vclo.d */, LoongArch::VCLO_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5055 /* vclo.h */, LoongArch::VCLO_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5062 /* vclo.w */, LoongArch::VCLO_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5069 /* vclz.b */, LoongArch::VCLZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5076 /* vclz.d */, LoongArch::VCLZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5083 /* vclz.h */, LoongArch::VCLZ_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5090 /* vclz.w */, LoongArch::VCLZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5097 /* vdiv.b */, LoongArch::VDIV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5104 /* vdiv.bu */, LoongArch::VDIV_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5112 /* vdiv.d */, LoongArch::VDIV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5119 /* vdiv.du */, LoongArch::VDIV_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5127 /* vdiv.h */, LoongArch::VDIV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5134 /* vdiv.hu */, LoongArch::VDIV_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5142 /* vdiv.w */, LoongArch::VDIV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5149 /* vdiv.wu */, LoongArch::VDIV_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5157 /* vext2xv.d.b */, LoongArch::VEXT2XV_D_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5169 /* vext2xv.d.h */, LoongArch::VEXT2XV_D_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5181 /* vext2xv.d.w */, LoongArch::VEXT2XV_D_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5193 /* vext2xv.du.bu */, LoongArch::VEXT2XV_DU_BU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5207 /* vext2xv.du.hu */, LoongArch::VEXT2XV_DU_HU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5221 /* vext2xv.du.wu */, LoongArch::VEXT2XV_DU_WU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5235 /* vext2xv.h.b */, LoongArch::VEXT2XV_H_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5247 /* vext2xv.hu.bu */, LoongArch::VEXT2XV_HU_BU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5261 /* vext2xv.w.b */, LoongArch::VEXT2XV_W_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5273 /* vext2xv.w.h */, LoongArch::VEXT2XV_W_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5285 /* vext2xv.wu.bu */, LoongArch::VEXT2XV_WU_BU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5299 /* vext2xv.wu.hu */, LoongArch::VEXT2XV_WU_HU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 5313 /* vexth.d.w */, LoongArch::VEXTH_D_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5323 /* vexth.du.wu */, LoongArch::VEXTH_DU_WU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5335 /* vexth.h.b */, LoongArch::VEXTH_H_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5345 /* vexth.hu.bu */, LoongArch::VEXTH_HU_BU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5357 /* vexth.q.d */, LoongArch::VEXTH_Q_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5367 /* vexth.qu.du */, LoongArch::VEXTH_QU_DU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5379 /* vexth.w.h */, LoongArch::VEXTH_W_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5389 /* vexth.wu.hu */, LoongArch::VEXTH_WU_HU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5401 /* vextl.q.d */, LoongArch::VEXTL_Q_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5411 /* vextl.qu.du */, LoongArch::VEXTL_QU_DU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5423 /* vextrins.b */, LoongArch::VEXTRINS_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 5434 /* vextrins.d */, LoongArch::VEXTRINS_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 5445 /* vextrins.h */, LoongArch::VEXTRINS_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 5456 /* vextrins.w */, LoongArch::VEXTRINS_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 5467 /* vfadd.d */, LoongArch::VFADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5475 /* vfadd.s */, LoongArch::VFADD_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5483 /* vfclass.d */, LoongArch::VFCLASS_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5493 /* vfclass.s */, LoongArch::VFCLASS_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 5503 /* vfcmp.caf.d */, LoongArch::VFCMP_CAF_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5515 /* vfcmp.caf.s */, LoongArch::VFCMP_CAF_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5527 /* vfcmp.ceq.d */, LoongArch::VFCMP_CEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5539 /* vfcmp.ceq.s */, LoongArch::VFCMP_CEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5551 /* vfcmp.cle.d */, LoongArch::VFCMP_CLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5563 /* vfcmp.cle.s */, LoongArch::VFCMP_CLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5575 /* vfcmp.clt.d */, LoongArch::VFCMP_CLT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5587 /* vfcmp.clt.s */, LoongArch::VFCMP_CLT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5599 /* vfcmp.cne.d */, LoongArch::VFCMP_CNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5611 /* vfcmp.cne.s */, LoongArch::VFCMP_CNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5623 /* vfcmp.cor.d */, LoongArch::VFCMP_COR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5635 /* vfcmp.cor.s */, LoongArch::VFCMP_COR_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5647 /* vfcmp.cueq.d */, LoongArch::VFCMP_CUEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5660 /* vfcmp.cueq.s */, LoongArch::VFCMP_CUEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5673 /* vfcmp.cule.d */, LoongArch::VFCMP_CULE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5686 /* vfcmp.cule.s */, LoongArch::VFCMP_CULE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5699 /* vfcmp.cult.d */, LoongArch::VFCMP_CULT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5712 /* vfcmp.cult.s */, LoongArch::VFCMP_CULT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5725 /* vfcmp.cun.d */, LoongArch::VFCMP_CUN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5737 /* vfcmp.cun.s */, LoongArch::VFCMP_CUN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5749 /* vfcmp.cune.d */, LoongArch::VFCMP_CUNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5762 /* vfcmp.cune.s */, LoongArch::VFCMP_CUNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5775 /* vfcmp.saf.d */, LoongArch::VFCMP_SAF_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5787 /* vfcmp.saf.s */, LoongArch::VFCMP_SAF_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5799 /* vfcmp.seq.d */, LoongArch::VFCMP_SEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5811 /* vfcmp.seq.s */, LoongArch::VFCMP_SEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5823 /* vfcmp.sle.d */, LoongArch::VFCMP_SLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5835 /* vfcmp.sle.s */, LoongArch::VFCMP_SLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5847 /* vfcmp.slt.d */, LoongArch::VFCMP_SLT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5859 /* vfcmp.slt.s */, LoongArch::VFCMP_SLT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5871 /* vfcmp.sne.d */, LoongArch::VFCMP_SNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5883 /* vfcmp.sne.s */, LoongArch::VFCMP_SNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5895 /* vfcmp.sor.d */, LoongArch::VFCMP_SOR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5907 /* vfcmp.sor.s */, LoongArch::VFCMP_SOR_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5919 /* vfcmp.sueq.d */, LoongArch::VFCMP_SUEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5932 /* vfcmp.sueq.s */, LoongArch::VFCMP_SUEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5945 /* vfcmp.sule.d */, LoongArch::VFCMP_SULE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5958 /* vfcmp.sule.s */, LoongArch::VFCMP_SULE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5971 /* vfcmp.sult.d */, LoongArch::VFCMP_SULT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5984 /* vfcmp.sult.s */, LoongArch::VFCMP_SULT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 5997 /* vfcmp.sun.d */, LoongArch::VFCMP_SUN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6009 /* vfcmp.sun.s */, LoongArch::VFCMP_SUN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6021 /* vfcmp.sune.d */, LoongArch::VFCMP_SUNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6034 /* vfcmp.sune.s */, LoongArch::VFCMP_SUNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6047 /* vfcvt.h.s */, LoongArch::VFCVT_H_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6057 /* vfcvt.s.d */, LoongArch::VFCVT_S_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6067 /* vfcvth.d.s */, LoongArch::VFCVTH_D_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6078 /* vfcvth.s.h */, LoongArch::VFCVTH_S_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6089 /* vfcvtl.d.s */, LoongArch::VFCVTL_D_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6100 /* vfcvtl.s.h */, LoongArch::VFCVTL_S_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6111 /* vfdiv.d */, LoongArch::VFDIV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6119 /* vfdiv.s */, LoongArch::VFDIV_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6127 /* vffint.d.l */, LoongArch::VFFINT_D_L, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6138 /* vffint.d.lu */, LoongArch::VFFINT_D_LU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6150 /* vffint.s.l */, LoongArch::VFFINT_S_L, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6161 /* vffint.s.w */, LoongArch::VFFINT_S_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6172 /* vffint.s.wu */, LoongArch::VFFINT_S_WU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6184 /* vffinth.d.w */, LoongArch::VFFINTH_D_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6196 /* vffintl.d.w */, LoongArch::VFFINTL_D_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6208 /* vflogb.d */, LoongArch::VFLOGB_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6217 /* vflogb.s */, LoongArch::VFLOGB_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6226 /* vfmadd.d */, LoongArch::VFMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6235 /* vfmadd.s */, LoongArch::VFMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6244 /* vfmax.d */, LoongArch::VFMAX_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6252 /* vfmax.s */, LoongArch::VFMAX_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6260 /* vfmaxa.d */, LoongArch::VFMAXA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6269 /* vfmaxa.s */, LoongArch::VFMAXA_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6278 /* vfmin.d */, LoongArch::VFMIN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6286 /* vfmin.s */, LoongArch::VFMIN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6294 /* vfmina.d */, LoongArch::VFMINA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6303 /* vfmina.s */, LoongArch::VFMINA_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6312 /* vfmsub.d */, LoongArch::VFMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6321 /* vfmsub.s */, LoongArch::VFMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6330 /* vfmul.d */, LoongArch::VFMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6338 /* vfmul.s */, LoongArch::VFMUL_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6346 /* vfnmadd.d */, LoongArch::VFNMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6356 /* vfnmadd.s */, LoongArch::VFNMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6366 /* vfnmsub.d */, LoongArch::VFNMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6376 /* vfnmsub.s */, LoongArch::VFNMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6386 /* vfrecip.d */, LoongArch::VFRECIP_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6396 /* vfrecip.s */, LoongArch::VFRECIP_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6406 /* vfrecipe.d */, LoongArch::VFRECIPE_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6417 /* vfrecipe.s */, LoongArch::VFRECIPE_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6428 /* vfrint.d */, LoongArch::VFRINT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6437 /* vfrint.s */, LoongArch::VFRINT_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6446 /* vfrintrm.d */, LoongArch::VFRINTRM_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6457 /* vfrintrm.s */, LoongArch::VFRINTRM_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6468 /* vfrintrne.d */, LoongArch::VFRINTRNE_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6480 /* vfrintrne.s */, LoongArch::VFRINTRNE_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6492 /* vfrintrp.d */, LoongArch::VFRINTRP_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6503 /* vfrintrp.s */, LoongArch::VFRINTRP_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6514 /* vfrintrz.d */, LoongArch::VFRINTRZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6525 /* vfrintrz.s */, LoongArch::VFRINTRZ_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6536 /* vfrsqrt.d */, LoongArch::VFRSQRT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6546 /* vfrsqrt.s */, LoongArch::VFRSQRT_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6556 /* vfrsqrte.d */, LoongArch::VFRSQRTE_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6567 /* vfrsqrte.s */, LoongArch::VFRSQRTE_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6578 /* vfrstp.b */, LoongArch::VFRSTP_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6587 /* vfrstp.h */, LoongArch::VFRSTP_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6596 /* vfrstpi.b */, LoongArch::VFRSTPI_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 6606 /* vfrstpi.h */, LoongArch::VFRSTPI_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 6616 /* vfsqrt.d */, LoongArch::VFSQRT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6625 /* vfsqrt.s */, LoongArch::VFSQRT_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6634 /* vfsub.d */, LoongArch::VFSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6642 /* vfsub.s */, LoongArch::VFSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6650 /* vftint.l.d */, LoongArch::VFTINT_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6661 /* vftint.lu.d */, LoongArch::VFTINT_LU_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6673 /* vftint.w.d */, LoongArch::VFTINT_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6684 /* vftint.w.s */, LoongArch::VFTINT_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6695 /* vftint.wu.s */, LoongArch::VFTINT_WU_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6707 /* vftinth.l.s */, LoongArch::VFTINTH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6719 /* vftintl.l.s */, LoongArch::VFTINTL_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6731 /* vftintrm.l.d */, LoongArch::VFTINTRM_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6744 /* vftintrm.w.d */, LoongArch::VFTINTRM_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6757 /* vftintrm.w.s */, LoongArch::VFTINTRM_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6770 /* vftintrmh.l.s */, LoongArch::VFTINTRMH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6784 /* vftintrml.l.s */, LoongArch::VFTINTRML_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6798 /* vftintrne.l.d */, LoongArch::VFTINTRNE_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6812 /* vftintrne.w.d */, LoongArch::VFTINTRNE_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6826 /* vftintrne.w.s */, LoongArch::VFTINTRNE_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6840 /* vftintrneh.l.s */, LoongArch::VFTINTRNEH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6855 /* vftintrnel.l.s */, LoongArch::VFTINTRNEL_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6870 /* vftintrp.l.d */, LoongArch::VFTINTRP_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6883 /* vftintrp.w.d */, LoongArch::VFTINTRP_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6896 /* vftintrp.w.s */, LoongArch::VFTINTRP_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6909 /* vftintrph.l.s */, LoongArch::VFTINTRPH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6923 /* vftintrpl.l.s */, LoongArch::VFTINTRPL_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6937 /* vftintrz.l.d */, LoongArch::VFTINTRZ_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6950 /* vftintrz.lu.d */, LoongArch::VFTINTRZ_LU_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6964 /* vftintrz.w.d */, LoongArch::VFTINTRZ_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 6977 /* vftintrz.w.s */, LoongArch::VFTINTRZ_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 6990 /* vftintrz.wu.s */, LoongArch::VFTINTRZ_WU_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 7004 /* vftintrzh.l.s */, LoongArch::VFTINTRZH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 7018 /* vftintrzl.l.s */, LoongArch::VFTINTRZL_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 7032 /* vhaddw.d.w */, LoongArch::VHADDW_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7043 /* vhaddw.du.wu */, LoongArch::VHADDW_DU_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7056 /* vhaddw.h.b */, LoongArch::VHADDW_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7067 /* vhaddw.hu.bu */, LoongArch::VHADDW_HU_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7080 /* vhaddw.q.d */, LoongArch::VHADDW_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7091 /* vhaddw.qu.du */, LoongArch::VHADDW_QU_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7104 /* vhaddw.w.h */, LoongArch::VHADDW_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7115 /* vhaddw.wu.hu */, LoongArch::VHADDW_WU_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7128 /* vhsubw.d.w */, LoongArch::VHSUBW_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7139 /* vhsubw.du.wu */, LoongArch::VHSUBW_DU_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7152 /* vhsubw.h.b */, LoongArch::VHSUBW_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7163 /* vhsubw.hu.bu */, LoongArch::VHSUBW_HU_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7176 /* vhsubw.q.d */, LoongArch::VHSUBW_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7187 /* vhsubw.qu.du */, LoongArch::VHSUBW_QU_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7200 /* vhsubw.w.h */, LoongArch::VHSUBW_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7211 /* vhsubw.wu.hu */, LoongArch::VHSUBW_WU_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7224 /* vilvh.b */, LoongArch::VILVH_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7232 /* vilvh.d */, LoongArch::VILVH_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7240 /* vilvh.h */, LoongArch::VILVH_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7248 /* vilvh.w */, LoongArch::VILVH_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7256 /* vilvl.b */, LoongArch::VILVL_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7264 /* vilvl.d */, LoongArch::VILVL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7272 /* vilvl.h */, LoongArch::VILVL_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7280 /* vilvl.w */, LoongArch::VILVL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7288 /* vinsgr2vr.b */, LoongArch::VINSGR2VR_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_UImm4 }, },
  { 7300 /* vinsgr2vr.d */, LoongArch::VINSGR2VR_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm11_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_UImm1 }, },
  { 7312 /* vinsgr2vr.h */, LoongArch::VINSGR2VR_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_UImm3 }, },
  { 7324 /* vinsgr2vr.w */, LoongArch::VINSGR2VR_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm21_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_UImm2 }, },
  { 7336 /* vld */, LoongArch::VLD, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm12addlike }, },
  { 7340 /* vldi */, LoongArch::VLDI, Convert__Reg1_0__SImm131_1, AMFBS_None, { MCK_LSX128, MCK_SImm13 }, },
  { 7345 /* vldrepl.b */, LoongArch::VLDREPL_B, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm12addlike }, },
  { 7355 /* vldrepl.d */, LoongArch::VLDREPL_D, Convert__Reg1_0__Reg1_1__SImm9lsl31_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm9lsl3 }, },
  { 7365 /* vldrepl.h */, LoongArch::VLDREPL_H, Convert__Reg1_0__Reg1_1__SImm11lsl11_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm11lsl1 }, },
  { 7375 /* vldrepl.w */, LoongArch::VLDREPL_W, Convert__Reg1_0__Reg1_1__SImm10lsl21_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm10lsl2 }, },
  { 7385 /* vldx */, LoongArch::VLDX, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_GPR }, },
  { 7390 /* vmadd.b */, LoongArch::VMADD_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7398 /* vmadd.d */, LoongArch::VMADD_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7406 /* vmadd.h */, LoongArch::VMADD_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7414 /* vmadd.w */, LoongArch::VMADD_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7422 /* vmaddwev.d.w */, LoongArch::VMADDWEV_D_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7435 /* vmaddwev.d.wu */, LoongArch::VMADDWEV_D_WU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7449 /* vmaddwev.d.wu.w */, LoongArch::VMADDWEV_D_WU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7465 /* vmaddwev.h.b */, LoongArch::VMADDWEV_H_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7478 /* vmaddwev.h.bu */, LoongArch::VMADDWEV_H_BU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7492 /* vmaddwev.h.bu.b */, LoongArch::VMADDWEV_H_BU_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7508 /* vmaddwev.q.d */, LoongArch::VMADDWEV_Q_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7521 /* vmaddwev.q.du */, LoongArch::VMADDWEV_Q_DU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7535 /* vmaddwev.q.du.d */, LoongArch::VMADDWEV_Q_DU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7551 /* vmaddwev.w.h */, LoongArch::VMADDWEV_W_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7564 /* vmaddwev.w.hu */, LoongArch::VMADDWEV_W_HU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7578 /* vmaddwev.w.hu.h */, LoongArch::VMADDWEV_W_HU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7594 /* vmaddwod.d.w */, LoongArch::VMADDWOD_D_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7607 /* vmaddwod.d.wu */, LoongArch::VMADDWOD_D_WU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7621 /* vmaddwod.d.wu.w */, LoongArch::VMADDWOD_D_WU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7637 /* vmaddwod.h.b */, LoongArch::VMADDWOD_H_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7650 /* vmaddwod.h.bu */, LoongArch::VMADDWOD_H_BU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7664 /* vmaddwod.h.bu.b */, LoongArch::VMADDWOD_H_BU_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7680 /* vmaddwod.q.d */, LoongArch::VMADDWOD_Q_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7693 /* vmaddwod.q.du */, LoongArch::VMADDWOD_Q_DU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7707 /* vmaddwod.q.du.d */, LoongArch::VMADDWOD_Q_DU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7723 /* vmaddwod.w.h */, LoongArch::VMADDWOD_W_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7736 /* vmaddwod.w.hu */, LoongArch::VMADDWOD_W_HU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7750 /* vmaddwod.w.hu.h */, LoongArch::VMADDWOD_W_HU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7766 /* vmax.b */, LoongArch::VMAX_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7773 /* vmax.bu */, LoongArch::VMAX_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7781 /* vmax.d */, LoongArch::VMAX_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7788 /* vmax.du */, LoongArch::VMAX_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7796 /* vmax.h */, LoongArch::VMAX_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7803 /* vmax.hu */, LoongArch::VMAX_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7811 /* vmax.w */, LoongArch::VMAX_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7818 /* vmax.wu */, LoongArch::VMAX_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7826 /* vmaxi.b */, LoongArch::VMAXI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 7834 /* vmaxi.bu */, LoongArch::VMAXI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 7843 /* vmaxi.d */, LoongArch::VMAXI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 7851 /* vmaxi.du */, LoongArch::VMAXI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 7860 /* vmaxi.h */, LoongArch::VMAXI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 7868 /* vmaxi.hu */, LoongArch::VMAXI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 7877 /* vmaxi.w */, LoongArch::VMAXI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 7885 /* vmaxi.wu */, LoongArch::VMAXI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 7894 /* vmin.b */, LoongArch::VMIN_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7901 /* vmin.bu */, LoongArch::VMIN_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7909 /* vmin.d */, LoongArch::VMIN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7916 /* vmin.du */, LoongArch::VMIN_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7924 /* vmin.h */, LoongArch::VMIN_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7931 /* vmin.hu */, LoongArch::VMIN_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7939 /* vmin.w */, LoongArch::VMIN_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7946 /* vmin.wu */, LoongArch::VMIN_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 7954 /* vmini.b */, LoongArch::VMINI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 7962 /* vmini.bu */, LoongArch::VMINI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 7971 /* vmini.d */, LoongArch::VMINI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 7979 /* vmini.du */, LoongArch::VMINI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 7988 /* vmini.h */, LoongArch::VMINI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 7996 /* vmini.hu */, LoongArch::VMINI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 8005 /* vmini.w */, LoongArch::VMINI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 8013 /* vmini.wu */, LoongArch::VMINI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 8022 /* vmod.b */, LoongArch::VMOD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8029 /* vmod.bu */, LoongArch::VMOD_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8037 /* vmod.d */, LoongArch::VMOD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8044 /* vmod.du */, LoongArch::VMOD_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8052 /* vmod.h */, LoongArch::VMOD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8059 /* vmod.hu */, LoongArch::VMOD_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8067 /* vmod.w */, LoongArch::VMOD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8074 /* vmod.wu */, LoongArch::VMOD_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8082 /* vmskgez.b */, LoongArch::VMSKGEZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8092 /* vmskltz.b */, LoongArch::VMSKLTZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8102 /* vmskltz.d */, LoongArch::VMSKLTZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8112 /* vmskltz.h */, LoongArch::VMSKLTZ_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8122 /* vmskltz.w */, LoongArch::VMSKLTZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8132 /* vmsknz.b */, LoongArch::VMSKNZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8141 /* vmsub.b */, LoongArch::VMSUB_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8149 /* vmsub.d */, LoongArch::VMSUB_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8157 /* vmsub.h */, LoongArch::VMSUB_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8165 /* vmsub.w */, LoongArch::VMSUB_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8173 /* vmuh.b */, LoongArch::VMUH_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8180 /* vmuh.bu */, LoongArch::VMUH_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8188 /* vmuh.d */, LoongArch::VMUH_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8195 /* vmuh.du */, LoongArch::VMUH_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8203 /* vmuh.h */, LoongArch::VMUH_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8210 /* vmuh.hu */, LoongArch::VMUH_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8218 /* vmuh.w */, LoongArch::VMUH_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8225 /* vmuh.wu */, LoongArch::VMUH_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8233 /* vmul.b */, LoongArch::VMUL_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8240 /* vmul.d */, LoongArch::VMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8247 /* vmul.h */, LoongArch::VMUL_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8254 /* vmul.w */, LoongArch::VMUL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8261 /* vmulwev.d.w */, LoongArch::VMULWEV_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8273 /* vmulwev.d.wu */, LoongArch::VMULWEV_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8286 /* vmulwev.d.wu.w */, LoongArch::VMULWEV_D_WU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8301 /* vmulwev.h.b */, LoongArch::VMULWEV_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8313 /* vmulwev.h.bu */, LoongArch::VMULWEV_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8326 /* vmulwev.h.bu.b */, LoongArch::VMULWEV_H_BU_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8341 /* vmulwev.q.d */, LoongArch::VMULWEV_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8353 /* vmulwev.q.du */, LoongArch::VMULWEV_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8366 /* vmulwev.q.du.d */, LoongArch::VMULWEV_Q_DU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8381 /* vmulwev.w.h */, LoongArch::VMULWEV_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8393 /* vmulwev.w.hu */, LoongArch::VMULWEV_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8406 /* vmulwev.w.hu.h */, LoongArch::VMULWEV_W_HU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8421 /* vmulwod.d.w */, LoongArch::VMULWOD_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8433 /* vmulwod.d.wu */, LoongArch::VMULWOD_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8446 /* vmulwod.d.wu.w */, LoongArch::VMULWOD_D_WU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8461 /* vmulwod.h.b */, LoongArch::VMULWOD_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8473 /* vmulwod.h.bu */, LoongArch::VMULWOD_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8486 /* vmulwod.h.bu.b */, LoongArch::VMULWOD_H_BU_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8501 /* vmulwod.q.d */, LoongArch::VMULWOD_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8513 /* vmulwod.q.du */, LoongArch::VMULWOD_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8526 /* vmulwod.q.du.d */, LoongArch::VMULWOD_Q_DU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8541 /* vmulwod.w.h */, LoongArch::VMULWOD_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8553 /* vmulwod.w.hu */, LoongArch::VMULWOD_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8566 /* vmulwod.w.hu.h */, LoongArch::VMULWOD_W_HU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8581 /* vneg.b */, LoongArch::VNEG_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8588 /* vneg.d */, LoongArch::VNEG_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8595 /* vneg.h */, LoongArch::VNEG_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8602 /* vneg.w */, LoongArch::VNEG_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8609 /* vnor.v */, LoongArch::VNOR_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8616 /* vnori.b */, LoongArch::VNORI_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 8624 /* vor.v */, LoongArch::VOR_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8630 /* vori.b */, LoongArch::VORI_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 8637 /* vorn.v */, LoongArch::VORN_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8644 /* vpackev.b */, LoongArch::VPACKEV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8654 /* vpackev.d */, LoongArch::VPACKEV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8664 /* vpackev.h */, LoongArch::VPACKEV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8674 /* vpackev.w */, LoongArch::VPACKEV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8684 /* vpackod.b */, LoongArch::VPACKOD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8694 /* vpackod.d */, LoongArch::VPACKOD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8704 /* vpackod.h */, LoongArch::VPACKOD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8714 /* vpackod.w */, LoongArch::VPACKOD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8724 /* vpcnt.b */, LoongArch::VPCNT_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8732 /* vpcnt.d */, LoongArch::VPCNT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8740 /* vpcnt.h */, LoongArch::VPCNT_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8748 /* vpcnt.w */, LoongArch::VPCNT_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_LSX128 }, },
  { 8756 /* vpermi.w */, LoongArch::VPERMI_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 8765 /* vpickev.b */, LoongArch::VPICKEV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8775 /* vpickev.d */, LoongArch::VPICKEV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8785 /* vpickev.h */, LoongArch::VPICKEV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8795 /* vpickev.w */, LoongArch::VPICKEV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8805 /* vpickod.b */, LoongArch::VPICKOD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8815 /* vpickod.d */, LoongArch::VPICKOD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8825 /* vpickod.h */, LoongArch::VPICKOD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8835 /* vpickod.w */, LoongArch::VPICKOD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 8845 /* vpickve2gr.b */, LoongArch::VPICKVE2GR_B, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_LSX128, MCK_UImm4 }, },
  { 8858 /* vpickve2gr.bu */, LoongArch::VPICKVE2GR_BU, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_GPR, MCK_LSX128, MCK_UImm4 }, },
  { 8872 /* vpickve2gr.d */, LoongArch::VPICKVE2GR_D, Convert__Reg1_0__Reg1_1__UImm11_2, AMFBS_None, { MCK_GPR, MCK_LSX128, MCK_UImm1 }, },
  { 8885 /* vpickve2gr.du */, LoongArch::VPICKVE2GR_DU, Convert__Reg1_0__Reg1_1__UImm11_2, AMFBS_None, { MCK_GPR, MCK_LSX128, MCK_UImm1 }, },
  { 8899 /* vpickve2gr.h */, LoongArch::VPICKVE2GR_H, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_GPR, MCK_LSX128, MCK_UImm3 }, },
  { 8912 /* vpickve2gr.hu */, LoongArch::VPICKVE2GR_HU, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_GPR, MCK_LSX128, MCK_UImm3 }, },
  { 8926 /* vpickve2gr.w */, LoongArch::VPICKVE2GR_W, Convert__Reg1_0__Reg1_1__UImm21_2, AMFBS_None, { MCK_GPR, MCK_LSX128, MCK_UImm2 }, },
  { 8939 /* vpickve2gr.wu */, LoongArch::VPICKVE2GR_WU, Convert__Reg1_0__Reg1_1__UImm21_2, AMFBS_None, { MCK_GPR, MCK_LSX128, MCK_UImm2 }, },
  { 8953 /* vreplgr2vr.b */, LoongArch::VREPLGR2VR_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_GPR }, },
  { 8966 /* vreplgr2vr.d */, LoongArch::VREPLGR2VR_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_GPR }, },
  { 8979 /* vreplgr2vr.h */, LoongArch::VREPLGR2VR_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_GPR }, },
  { 8992 /* vreplgr2vr.w */, LoongArch::VREPLGR2VR_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LSX128, MCK_GPR }, },
  { 9005 /* vrepli.b */, LoongArch::PseudoVREPLI_B, Convert__Reg1_0__SImm101_1, AMFBS_None, { MCK_LSX128, MCK_SImm10 }, },
  { 9014 /* vrepli.d */, LoongArch::PseudoVREPLI_D, Convert__Reg1_0__SImm101_1, AMFBS_None, { MCK_LSX128, MCK_SImm10 }, },
  { 9023 /* vrepli.h */, LoongArch::PseudoVREPLI_H, Convert__Reg1_0__SImm101_1, AMFBS_None, { MCK_LSX128, MCK_SImm10 }, },
  { 9032 /* vrepli.w */, LoongArch::PseudoVREPLI_W, Convert__Reg1_0__SImm101_1, AMFBS_None, { MCK_LSX128, MCK_SImm10 }, },
  { 9041 /* vreplve.b */, LoongArch::VREPLVE_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_GPR }, },
  { 9051 /* vreplve.d */, LoongArch::VREPLVE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_GPR }, },
  { 9061 /* vreplve.h */, LoongArch::VREPLVE_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_GPR }, },
  { 9071 /* vreplve.w */, LoongArch::VREPLVE_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_GPR }, },
  { 9081 /* vreplvei.b */, LoongArch::VREPLVEI_B, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 9092 /* vreplvei.d */, LoongArch::VREPLVEI_D, Convert__Reg1_0__Reg1_1__UImm11_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm1 }, },
  { 9103 /* vreplvei.h */, LoongArch::VREPLVEI_H, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 9114 /* vreplvei.w */, LoongArch::VREPLVEI_W, Convert__Reg1_0__Reg1_1__UImm21_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm2 }, },
  { 9125 /* vrotr.b */, LoongArch::VROTR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9133 /* vrotr.d */, LoongArch::VROTR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9141 /* vrotr.h */, LoongArch::VROTR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9149 /* vrotr.w */, LoongArch::VROTR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9157 /* vrotri.b */, LoongArch::VROTRI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 9166 /* vrotri.d */, LoongArch::VROTRI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 9175 /* vrotri.h */, LoongArch::VROTRI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 9184 /* vrotri.w */, LoongArch::VROTRI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9193 /* vsadd.b */, LoongArch::VSADD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9201 /* vsadd.bu */, LoongArch::VSADD_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9210 /* vsadd.d */, LoongArch::VSADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9218 /* vsadd.du */, LoongArch::VSADD_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9227 /* vsadd.h */, LoongArch::VSADD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9235 /* vsadd.hu */, LoongArch::VSADD_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9244 /* vsadd.w */, LoongArch::VSADD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9252 /* vsadd.wu */, LoongArch::VSADD_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9261 /* vsat.b */, LoongArch::VSAT_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 9268 /* vsat.bu */, LoongArch::VSAT_BU, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 9276 /* vsat.d */, LoongArch::VSAT_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 9283 /* vsat.du */, LoongArch::VSAT_DU, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 9291 /* vsat.h */, LoongArch::VSAT_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 9298 /* vsat.hu */, LoongArch::VSAT_HU, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 9306 /* vsat.w */, LoongArch::VSAT_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9313 /* vsat.wu */, LoongArch::VSAT_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9321 /* vseq.b */, LoongArch::VSEQ_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9328 /* vseq.d */, LoongArch::VSEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9335 /* vseq.h */, LoongArch::VSEQ_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9342 /* vseq.w */, LoongArch::VSEQ_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9349 /* vseqi.b */, LoongArch::VSEQI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9357 /* vseqi.d */, LoongArch::VSEQI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9365 /* vseqi.h */, LoongArch::VSEQI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9373 /* vseqi.w */, LoongArch::VSEQI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9381 /* vsetallnez.b */, LoongArch::VSETALLNEZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9394 /* vsetallnez.d */, LoongArch::VSETALLNEZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9407 /* vsetallnez.h */, LoongArch::VSETALLNEZ_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9420 /* vsetallnez.w */, LoongArch::VSETALLNEZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9433 /* vsetanyeqz.b */, LoongArch::VSETANYEQZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9446 /* vsetanyeqz.d */, LoongArch::VSETANYEQZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9459 /* vsetanyeqz.h */, LoongArch::VSETANYEQZ_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9472 /* vsetanyeqz.w */, LoongArch::VSETANYEQZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9485 /* vseteqz.v */, LoongArch::VSETEQZ_V, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9495 /* vsetnez.v */, LoongArch::VSETNEZ_V, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LSX128 }, },
  { 9505 /* vshuf.b */, LoongArch::VSHUF_B, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9513 /* vshuf.d */, LoongArch::VSHUF_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9521 /* vshuf.h */, LoongArch::VSHUF_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9529 /* vshuf.w */, LoongArch::VSHUF_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9537 /* vshuf4i.b */, LoongArch::VSHUF4I_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 9547 /* vshuf4i.d */, LoongArch::VSHUF4I_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 9557 /* vshuf4i.h */, LoongArch::VSHUF4I_H, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 9567 /* vshuf4i.w */, LoongArch::VSHUF4I_W, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 9577 /* vsigncov.b */, LoongArch::VSIGNCOV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9588 /* vsigncov.d */, LoongArch::VSIGNCOV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9599 /* vsigncov.h */, LoongArch::VSIGNCOV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9610 /* vsigncov.w */, LoongArch::VSIGNCOV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9621 /* vsle.b */, LoongArch::VSLE_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9628 /* vsle.bu */, LoongArch::VSLE_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9636 /* vsle.d */, LoongArch::VSLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9643 /* vsle.du */, LoongArch::VSLE_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9651 /* vsle.h */, LoongArch::VSLE_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9658 /* vsle.hu */, LoongArch::VSLE_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9666 /* vsle.w */, LoongArch::VSLE_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9673 /* vsle.wu */, LoongArch::VSLE_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9681 /* vslei.b */, LoongArch::VSLEI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9689 /* vslei.bu */, LoongArch::VSLEI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9698 /* vslei.d */, LoongArch::VSLEI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9706 /* vslei.du */, LoongArch::VSLEI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9715 /* vslei.h */, LoongArch::VSLEI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9723 /* vslei.hu */, LoongArch::VSLEI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9732 /* vslei.w */, LoongArch::VSLEI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9740 /* vslei.wu */, LoongArch::VSLEI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9749 /* vsll.b */, LoongArch::VSLL_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9756 /* vsll.d */, LoongArch::VSLL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9763 /* vsll.h */, LoongArch::VSLL_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9770 /* vsll.w */, LoongArch::VSLL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9777 /* vslli.b */, LoongArch::VSLLI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 9785 /* vslli.d */, LoongArch::VSLLI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 9793 /* vslli.h */, LoongArch::VSLLI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 9801 /* vslli.w */, LoongArch::VSLLI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9809 /* vsllwil.d.w */, LoongArch::VSLLWIL_D_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9821 /* vsllwil.du.wu */, LoongArch::VSLLWIL_DU_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9835 /* vsllwil.h.b */, LoongArch::VSLLWIL_H_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 9847 /* vsllwil.hu.bu */, LoongArch::VSLLWIL_HU_BU, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 9861 /* vsllwil.w.h */, LoongArch::VSLLWIL_W_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 9873 /* vsllwil.wu.hu */, LoongArch::VSLLWIL_WU_HU, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 9887 /* vslt.b */, LoongArch::VSLT_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9894 /* vslt.bu */, LoongArch::VSLT_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9902 /* vslt.d */, LoongArch::VSLT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9909 /* vslt.du */, LoongArch::VSLT_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9917 /* vslt.h */, LoongArch::VSLT_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9924 /* vslt.hu */, LoongArch::VSLT_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9932 /* vslt.w */, LoongArch::VSLT_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9939 /* vslt.wu */, LoongArch::VSLT_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 9947 /* vslti.b */, LoongArch::VSLTI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9955 /* vslti.bu */, LoongArch::VSLTI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9964 /* vslti.d */, LoongArch::VSLTI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9972 /* vslti.du */, LoongArch::VSLTI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9981 /* vslti.h */, LoongArch::VSLTI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 9989 /* vslti.hu */, LoongArch::VSLTI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 9998 /* vslti.w */, LoongArch::VSLTI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_SImm5 }, },
  { 10006 /* vslti.wu */, LoongArch::VSLTI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10015 /* vsra.b */, LoongArch::VSRA_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10022 /* vsra.d */, LoongArch::VSRA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10029 /* vsra.h */, LoongArch::VSRA_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10036 /* vsra.w */, LoongArch::VSRA_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10043 /* vsrai.b */, LoongArch::VSRAI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 10051 /* vsrai.d */, LoongArch::VSRAI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10059 /* vsrai.h */, LoongArch::VSRAI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10067 /* vsrai.w */, LoongArch::VSRAI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10075 /* vsran.b.h */, LoongArch::VSRAN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10085 /* vsran.h.w */, LoongArch::VSRAN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10095 /* vsran.w.d */, LoongArch::VSRAN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10105 /* vsrani.b.h */, LoongArch::VSRANI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10116 /* vsrani.d.q */, LoongArch::VSRANI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 10127 /* vsrani.h.w */, LoongArch::VSRANI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10138 /* vsrani.w.d */, LoongArch::VSRANI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10149 /* vsrar.b */, LoongArch::VSRAR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10157 /* vsrar.d */, LoongArch::VSRAR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10165 /* vsrar.h */, LoongArch::VSRAR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10173 /* vsrar.w */, LoongArch::VSRAR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10181 /* vsrari.b */, LoongArch::VSRARI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 10190 /* vsrari.d */, LoongArch::VSRARI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10199 /* vsrari.h */, LoongArch::VSRARI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10208 /* vsrari.w */, LoongArch::VSRARI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10217 /* vsrarn.b.h */, LoongArch::VSRARN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10228 /* vsrarn.h.w */, LoongArch::VSRARN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10239 /* vsrarn.w.d */, LoongArch::VSRARN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10250 /* vsrarni.b.h */, LoongArch::VSRARNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10262 /* vsrarni.d.q */, LoongArch::VSRARNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 10274 /* vsrarni.h.w */, LoongArch::VSRARNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10286 /* vsrarni.w.d */, LoongArch::VSRARNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10298 /* vsrl.b */, LoongArch::VSRL_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10305 /* vsrl.d */, LoongArch::VSRL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10312 /* vsrl.h */, LoongArch::VSRL_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10319 /* vsrl.w */, LoongArch::VSRL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10326 /* vsrli.b */, LoongArch::VSRLI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 10334 /* vsrli.d */, LoongArch::VSRLI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10342 /* vsrli.h */, LoongArch::VSRLI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10350 /* vsrli.w */, LoongArch::VSRLI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10358 /* vsrln.b.h */, LoongArch::VSRLN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10368 /* vsrln.h.w */, LoongArch::VSRLN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10378 /* vsrln.w.d */, LoongArch::VSRLN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10388 /* vsrlni.b.h */, LoongArch::VSRLNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10399 /* vsrlni.d.q */, LoongArch::VSRLNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 10410 /* vsrlni.h.w */, LoongArch::VSRLNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10421 /* vsrlni.w.d */, LoongArch::VSRLNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10432 /* vsrlr.b */, LoongArch::VSRLR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10440 /* vsrlr.d */, LoongArch::VSRLR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10448 /* vsrlr.h */, LoongArch::VSRLR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10456 /* vsrlr.w */, LoongArch::VSRLR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10464 /* vsrlri.b */, LoongArch::VSRLRI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm3 }, },
  { 10473 /* vsrlri.d */, LoongArch::VSRLRI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10482 /* vsrlri.h */, LoongArch::VSRLRI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10491 /* vsrlri.w */, LoongArch::VSRLRI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10500 /* vsrlrn.b.h */, LoongArch::VSRLRN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10511 /* vsrlrn.h.w */, LoongArch::VSRLRN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10522 /* vsrlrn.w.d */, LoongArch::VSRLRN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10533 /* vsrlrni.b.h */, LoongArch::VSRLRNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10545 /* vsrlrni.d.q */, LoongArch::VSRLRNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 10557 /* vsrlrni.h.w */, LoongArch::VSRLRNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10569 /* vsrlrni.w.d */, LoongArch::VSRLRNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10581 /* vssran.b.h */, LoongArch::VSSRAN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10592 /* vssran.bu.h */, LoongArch::VSSRAN_BU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10604 /* vssran.h.w */, LoongArch::VSSRAN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10615 /* vssran.hu.w */, LoongArch::VSSRAN_HU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10627 /* vssran.w.d */, LoongArch::VSSRAN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10638 /* vssran.wu.d */, LoongArch::VSSRAN_WU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10650 /* vssrani.b.h */, LoongArch::VSSRANI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10662 /* vssrani.bu.h */, LoongArch::VSSRANI_BU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10675 /* vssrani.d.q */, LoongArch::VSSRANI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 10687 /* vssrani.du.q */, LoongArch::VSSRANI_DU_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 10700 /* vssrani.h.w */, LoongArch::VSSRANI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10712 /* vssrani.hu.w */, LoongArch::VSSRANI_HU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10725 /* vssrani.w.d */, LoongArch::VSSRANI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10737 /* vssrani.wu.d */, LoongArch::VSSRANI_WU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10750 /* vssrarn.b.h */, LoongArch::VSSRARN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10762 /* vssrarn.bu.h */, LoongArch::VSSRARN_BU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10775 /* vssrarn.h.w */, LoongArch::VSSRARN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10787 /* vssrarn.hu.w */, LoongArch::VSSRARN_HU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10800 /* vssrarn.w.d */, LoongArch::VSSRARN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10812 /* vssrarn.wu.d */, LoongArch::VSSRARN_WU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10825 /* vssrarni.b.h */, LoongArch::VSSRARNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10838 /* vssrarni.bu.h */, LoongArch::VSSRARNI_BU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 10852 /* vssrarni.d.q */, LoongArch::VSSRARNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 10865 /* vssrarni.du.q */, LoongArch::VSSRARNI_DU_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 10879 /* vssrarni.h.w */, LoongArch::VSSRARNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10892 /* vssrarni.hu.w */, LoongArch::VSSRARNI_HU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 10906 /* vssrarni.w.d */, LoongArch::VSSRARNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10919 /* vssrarni.wu.d */, LoongArch::VSSRARNI_WU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 10933 /* vssrln.b.h */, LoongArch::VSSRLN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10944 /* vssrln.bu.h */, LoongArch::VSSRLN_BU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10956 /* vssrln.h.w */, LoongArch::VSSRLN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10967 /* vssrln.hu.w */, LoongArch::VSSRLN_HU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10979 /* vssrln.w.d */, LoongArch::VSSRLN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 10990 /* vssrln.wu.d */, LoongArch::VSSRLN_WU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11002 /* vssrlni.b.h */, LoongArch::VSSRLNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 11014 /* vssrlni.bu.h */, LoongArch::VSSRLNI_BU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 11027 /* vssrlni.d.q */, LoongArch::VSSRLNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 11039 /* vssrlni.du.q */, LoongArch::VSSRLNI_DU_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 11052 /* vssrlni.h.w */, LoongArch::VSSRLNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 11064 /* vssrlni.hu.w */, LoongArch::VSSRLNI_HU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 11077 /* vssrlni.w.d */, LoongArch::VSSRLNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 11089 /* vssrlni.wu.d */, LoongArch::VSSRLNI_WU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 11102 /* vssrlrn.b.h */, LoongArch::VSSRLRN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11114 /* vssrlrn.bu.h */, LoongArch::VSSRLRN_BU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11127 /* vssrlrn.h.w */, LoongArch::VSSRLRN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11139 /* vssrlrn.hu.w */, LoongArch::VSSRLRN_HU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11152 /* vssrlrn.w.d */, LoongArch::VSSRLRN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11164 /* vssrlrn.wu.d */, LoongArch::VSSRLRN_WU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11177 /* vssrlrni.b.h */, LoongArch::VSSRLRNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 11190 /* vssrlrni.bu.h */, LoongArch::VSSRLRNI_BU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm4 }, },
  { 11204 /* vssrlrni.d.q */, LoongArch::VSSRLRNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 11217 /* vssrlrni.du.q */, LoongArch::VSSRLRNI_DU_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm7 }, },
  { 11231 /* vssrlrni.h.w */, LoongArch::VSSRLRNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 11244 /* vssrlrni.hu.w */, LoongArch::VSSRLRNI_HU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 11258 /* vssrlrni.w.d */, LoongArch::VSSRLRNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 11271 /* vssrlrni.wu.d */, LoongArch::VSSRLRNI_WU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm6 }, },
  { 11285 /* vssub.b */, LoongArch::VSSUB_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11293 /* vssub.bu */, LoongArch::VSSUB_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11302 /* vssub.d */, LoongArch::VSSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11310 /* vssub.du */, LoongArch::VSSUB_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11319 /* vssub.h */, LoongArch::VSSUB_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11327 /* vssub.hu */, LoongArch::VSSUB_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11336 /* vssub.w */, LoongArch::VSSUB_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11344 /* vssub.wu */, LoongArch::VSSUB_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11353 /* vst */, LoongArch::VST, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm12addlike }, },
  { 11357 /* vstelm.b */, LoongArch::VSTELM_B, Convert__Reg1_0__Reg1_1__SImm81_2__UImm41_3, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm8, MCK_UImm4 }, },
  { 11366 /* vstelm.d */, LoongArch::VSTELM_D, Convert__Reg1_0__Reg1_1__SImm8lsl31_2__UImm11_3, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm8lsl3, MCK_UImm1 }, },
  { 11375 /* vstelm.h */, LoongArch::VSTELM_H, Convert__Reg1_0__Reg1_1__SImm8lsl11_2__UImm31_3, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm8lsl1, MCK_UImm3 }, },
  { 11384 /* vstelm.w */, LoongArch::VSTELM_W, Convert__Reg1_0__Reg1_1__SImm8lsl21_2__UImm21_3, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_SImm8lsl2, MCK_UImm2 }, },
  { 11393 /* vstx */, LoongArch::VSTX, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_GPR, MCK_GPR }, },
  { 11398 /* vsub.b */, LoongArch::VSUB_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11405 /* vsub.d */, LoongArch::VSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11412 /* vsub.h */, LoongArch::VSUB_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11419 /* vsub.q */, LoongArch::VSUB_Q, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11426 /* vsub.w */, LoongArch::VSUB_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11433 /* vsubi.bu */, LoongArch::VSUBI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 11442 /* vsubi.du */, LoongArch::VSUBI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 11451 /* vsubi.hu */, LoongArch::VSUBI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 11460 /* vsubi.wu */, LoongArch::VSUBI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm5 }, },
  { 11469 /* vsubwev.d.w */, LoongArch::VSUBWEV_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11481 /* vsubwev.d.wu */, LoongArch::VSUBWEV_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11494 /* vsubwev.h.b */, LoongArch::VSUBWEV_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11506 /* vsubwev.h.bu */, LoongArch::VSUBWEV_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11519 /* vsubwev.q.d */, LoongArch::VSUBWEV_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11531 /* vsubwev.q.du */, LoongArch::VSUBWEV_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11544 /* vsubwev.w.h */, LoongArch::VSUBWEV_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11556 /* vsubwev.w.hu */, LoongArch::VSUBWEV_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11569 /* vsubwod.d.w */, LoongArch::VSUBWOD_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11581 /* vsubwod.d.wu */, LoongArch::VSUBWOD_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11594 /* vsubwod.h.b */, LoongArch::VSUBWOD_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11606 /* vsubwod.h.bu */, LoongArch::VSUBWOD_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11619 /* vsubwod.q.d */, LoongArch::VSUBWOD_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11631 /* vsubwod.q.du */, LoongArch::VSUBWOD_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11644 /* vsubwod.w.h */, LoongArch::VSUBWOD_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11656 /* vsubwod.w.hu */, LoongArch::VSUBWOD_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11669 /* vxor.v */, LoongArch::VXOR_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_LSX128 }, },
  { 11676 /* vxori.b */, LoongArch::VXORI_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LSX128, MCK_LSX128, MCK_UImm8 }, },
  { 11684 /* x86adc.b */, LoongArch::X86ADC_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11693 /* x86adc.d */, LoongArch::X86ADC_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 11702 /* x86adc.h */, LoongArch::X86ADC_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11711 /* x86adc.w */, LoongArch::X86ADC_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11720 /* x86add.b */, LoongArch::X86ADD_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11729 /* x86add.d */, LoongArch::X86ADD_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 11738 /* x86add.du */, LoongArch::X86ADD_DU, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 11748 /* x86add.h */, LoongArch::X86ADD_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11757 /* x86add.w */, LoongArch::X86ADD_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11766 /* x86add.wu */, LoongArch::X86ADD_WU, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 11776 /* x86and.b */, LoongArch::X86AND_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11785 /* x86and.d */, LoongArch::X86AND_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 11794 /* x86and.h */, LoongArch::X86AND_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11803 /* x86and.w */, LoongArch::X86AND_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11812 /* x86clrtm */, LoongArch::X86CLRTM, Convert_NoOperands, AMFBS_None, {  }, },
  { 11821 /* x86dec.b */, LoongArch::X86DEC_B, Convert__Reg1_0, AMFBS_None, { MCK_GPR }, },
  { 11830 /* x86dec.d */, LoongArch::X86DEC_D, Convert__Reg1_0, AMFBS_IsLA64, { MCK_GPR }, },
  { 11839 /* x86dec.h */, LoongArch::X86DEC_H, Convert__Reg1_0, AMFBS_None, { MCK_GPR }, },
  { 11848 /* x86dec.w */, LoongArch::X86DEC_W, Convert__Reg1_0, AMFBS_None, { MCK_GPR }, },
  { 11857 /* x86dectop */, LoongArch::X86DECTOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 11867 /* x86inc.b */, LoongArch::X86INC_B, Convert__Reg1_0, AMFBS_None, { MCK_GPR }, },
  { 11876 /* x86inc.d */, LoongArch::X86INC_D, Convert__Reg1_0, AMFBS_IsLA64, { MCK_GPR }, },
  { 11885 /* x86inc.h */, LoongArch::X86INC_H, Convert__Reg1_0, AMFBS_None, { MCK_GPR }, },
  { 11894 /* x86inc.w */, LoongArch::X86INC_W, Convert__Reg1_0, AMFBS_None, { MCK_GPR }, },
  { 11903 /* x86inctop */, LoongArch::X86INCTOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 11913 /* x86mfflag */, LoongArch::X86MFFLAG, Convert__Reg1_0__UImm81_1, AMFBS_None, { MCK_GPR, MCK_UImm8 }, },
  { 11923 /* x86mftop */, LoongArch::X86MFTOP, Convert__Reg1_0, AMFBS_None, { MCK_GPR }, },
  { 11932 /* x86mtflag */, LoongArch::X86MTFLAG, Convert__Reg1_0__UImm81_1, AMFBS_None, { MCK_GPR, MCK_UImm8 }, },
  { 11942 /* x86mttop */, LoongArch::X86MTTOP, Convert__UImm31_0, AMFBS_None, { MCK_UImm3 }, },
  { 11951 /* x86mul.b */, LoongArch::X86MUL_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11960 /* x86mul.bu */, LoongArch::X86MUL_BU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11970 /* x86mul.d */, LoongArch::X86MUL_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 11979 /* x86mul.du */, LoongArch::X86MUL_DU, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 11989 /* x86mul.h */, LoongArch::X86MUL_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 11998 /* x86mul.hu */, LoongArch::X86MUL_HU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12008 /* x86mul.w */, LoongArch::X86MUL_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12017 /* x86mul.wu */, LoongArch::X86MUL_WU, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12027 /* x86or.b */, LoongArch::X86OR_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12035 /* x86or.d */, LoongArch::X86OR_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12043 /* x86or.h */, LoongArch::X86OR_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12051 /* x86or.w */, LoongArch::X86OR_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12059 /* x86rcl.b */, LoongArch::X86RCL_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12068 /* x86rcl.d */, LoongArch::X86RCL_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12077 /* x86rcl.h */, LoongArch::X86RCL_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12086 /* x86rcl.w */, LoongArch::X86RCL_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12095 /* x86rcli.b */, LoongArch::X86RCLI_B, Convert__Reg1_0__UImm31_1, AMFBS_None, { MCK_GPR, MCK_UImm3 }, },
  { 12105 /* x86rcli.d */, LoongArch::X86RCLI_D, Convert__Reg1_0__UImm61_1, AMFBS_IsLA64, { MCK_GPR, MCK_UImm6 }, },
  { 12115 /* x86rcli.h */, LoongArch::X86RCLI_H, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 12125 /* x86rcli.w */, LoongArch::X86RCLI_W, Convert__Reg1_0__UImm51_1, AMFBS_None, { MCK_GPR, MCK_UImm5 }, },
  { 12135 /* x86rcr.b */, LoongArch::X86RCR_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12144 /* x86rcr.d */, LoongArch::X86RCR_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12153 /* x86rcr.h */, LoongArch::X86RCR_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12162 /* x86rcr.w */, LoongArch::X86RCR_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12171 /* x86rcri.b */, LoongArch::X86RCRI_B, Convert__Reg1_0__UImm31_1, AMFBS_None, { MCK_GPR, MCK_UImm3 }, },
  { 12181 /* x86rcri.d */, LoongArch::X86RCRI_D, Convert__Reg1_0__UImm61_1, AMFBS_IsLA64, { MCK_GPR, MCK_UImm6 }, },
  { 12191 /* x86rcri.h */, LoongArch::X86RCRI_H, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 12201 /* x86rcri.w */, LoongArch::X86RCRI_W, Convert__Reg1_0__UImm51_1, AMFBS_None, { MCK_GPR, MCK_UImm5 }, },
  { 12211 /* x86rotl.b */, LoongArch::X86ROTL_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12221 /* x86rotl.d */, LoongArch::X86ROTL_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12231 /* x86rotl.h */, LoongArch::X86ROTL_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12241 /* x86rotl.w */, LoongArch::X86ROTL_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12251 /* x86rotli.b */, LoongArch::X86ROTLI_B, Convert__Reg1_0__UImm31_1, AMFBS_None, { MCK_GPR, MCK_UImm3 }, },
  { 12262 /* x86rotli.d */, LoongArch::X86ROTLI_D, Convert__Reg1_0__UImm61_1, AMFBS_IsLA64, { MCK_GPR, MCK_UImm6 }, },
  { 12273 /* x86rotli.h */, LoongArch::X86ROTLI_H, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 12284 /* x86rotli.w */, LoongArch::X86ROTLI_W, Convert__Reg1_0__UImm51_1, AMFBS_None, { MCK_GPR, MCK_UImm5 }, },
  { 12295 /* x86rotr.b */, LoongArch::X86ROTR_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12305 /* x86rotr.d */, LoongArch::X86ROTR_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12315 /* x86rotr.h */, LoongArch::X86ROTR_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12325 /* x86rotr.w */, LoongArch::X86ROTR_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12335 /* x86rotri.b */, LoongArch::X86ROTRI_B, Convert__Reg1_0__UImm31_1, AMFBS_None, { MCK_GPR, MCK_UImm3 }, },
  { 12346 /* x86rotri.d */, LoongArch::X86ROTRI_D, Convert__Reg1_0__UImm61_1, AMFBS_IsLA64, { MCK_GPR, MCK_UImm6 }, },
  { 12357 /* x86rotri.h */, LoongArch::X86ROTRI_H, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 12368 /* x86rotri.w */, LoongArch::X86ROTRI_W, Convert__Reg1_0__UImm51_1, AMFBS_None, { MCK_GPR, MCK_UImm5 }, },
  { 12379 /* x86sbc.b */, LoongArch::X86SBC_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12388 /* x86sbc.d */, LoongArch::X86SBC_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12397 /* x86sbc.h */, LoongArch::X86SBC_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12406 /* x86sbc.w */, LoongArch::X86SBC_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12415 /* x86settag */, LoongArch::X86SETTAG, Convert__Reg1_0__UImm51_1__UImm81_2, AMFBS_None, { MCK_GPR, MCK_UImm5, MCK_UImm8 }, },
  { 12425 /* x86settm */, LoongArch::X86SETTM, Convert_NoOperands, AMFBS_None, {  }, },
  { 12434 /* x86sll.b */, LoongArch::X86SLL_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12443 /* x86sll.d */, LoongArch::X86SLL_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12452 /* x86sll.h */, LoongArch::X86SLL_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12461 /* x86sll.w */, LoongArch::X86SLL_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12470 /* x86slli.b */, LoongArch::X86SLLI_B, Convert__Reg1_0__UImm31_1, AMFBS_None, { MCK_GPR, MCK_UImm3 }, },
  { 12480 /* x86slli.d */, LoongArch::X86SLLI_D, Convert__Reg1_0__UImm61_1, AMFBS_IsLA64, { MCK_GPR, MCK_UImm6 }, },
  { 12490 /* x86slli.h */, LoongArch::X86SLLI_H, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 12500 /* x86slli.w */, LoongArch::X86SLLI_W, Convert__Reg1_0__UImm51_1, AMFBS_None, { MCK_GPR, MCK_UImm5 }, },
  { 12510 /* x86sra.b */, LoongArch::X86SRA_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12519 /* x86sra.d */, LoongArch::X86SRA_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12528 /* x86sra.h */, LoongArch::X86SRA_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12537 /* x86sra.w */, LoongArch::X86SRA_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12546 /* x86srai.b */, LoongArch::X86SRAI_B, Convert__Reg1_0__UImm31_1, AMFBS_None, { MCK_GPR, MCK_UImm3 }, },
  { 12556 /* x86srai.d */, LoongArch::X86SRAI_D, Convert__Reg1_0__UImm61_1, AMFBS_IsLA64, { MCK_GPR, MCK_UImm6 }, },
  { 12566 /* x86srai.h */, LoongArch::X86SRAI_H, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 12576 /* x86srai.w */, LoongArch::X86SRAI_W, Convert__Reg1_0__UImm51_1, AMFBS_None, { MCK_GPR, MCK_UImm5 }, },
  { 12586 /* x86srl.b */, LoongArch::X86SRL_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12595 /* x86srl.d */, LoongArch::X86SRL_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12604 /* x86srl.h */, LoongArch::X86SRL_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12613 /* x86srl.w */, LoongArch::X86SRL_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12622 /* x86srli.b */, LoongArch::X86SRLI_B, Convert__Reg1_0__UImm31_1, AMFBS_None, { MCK_GPR, MCK_UImm3 }, },
  { 12632 /* x86srli.d */, LoongArch::X86SRLI_D, Convert__Reg1_0__UImm61_1, AMFBS_IsLA64, { MCK_GPR, MCK_UImm6 }, },
  { 12642 /* x86srli.h */, LoongArch::X86SRLI_H, Convert__Reg1_0__UImm41_1, AMFBS_None, { MCK_GPR, MCK_UImm4 }, },
  { 12652 /* x86srli.w */, LoongArch::X86SRLI_W, Convert__Reg1_0__UImm51_1, AMFBS_None, { MCK_GPR, MCK_UImm5 }, },
  { 12662 /* x86sub.b */, LoongArch::X86SUB_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12671 /* x86sub.d */, LoongArch::X86SUB_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12680 /* x86sub.du */, LoongArch::X86SUB_DU, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12690 /* x86sub.h */, LoongArch::X86SUB_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12699 /* x86sub.w */, LoongArch::X86SUB_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12708 /* x86sub.wu */, LoongArch::X86SUB_WU, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12718 /* x86xor.b */, LoongArch::X86XOR_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12727 /* x86xor.d */, LoongArch::X86XOR_D, Convert__Reg1_0__Reg1_1, AMFBS_IsLA64, { MCK_GPR, MCK_GPR }, },
  { 12736 /* x86xor.h */, LoongArch::X86XOR_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12745 /* x86xor.w */, LoongArch::X86XOR_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_GPR, MCK_GPR }, },
  { 12754 /* xor */, LoongArch::XOR, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 12758 /* xori */, LoongArch::XORI, Convert__Reg1_0__Reg1_1__UImm121_2, AMFBS_None, { MCK_GPR, MCK_GPR, MCK_UImm12 }, },
  { 12763 /* xvabsd.b */, LoongArch::XVABSD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12772 /* xvabsd.bu */, LoongArch::XVABSD_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12782 /* xvabsd.d */, LoongArch::XVABSD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12791 /* xvabsd.du */, LoongArch::XVABSD_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12801 /* xvabsd.h */, LoongArch::XVABSD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12810 /* xvabsd.hu */, LoongArch::XVABSD_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12820 /* xvabsd.w */, LoongArch::XVABSD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12829 /* xvabsd.wu */, LoongArch::XVABSD_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12839 /* xvadd.b */, LoongArch::XVADD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12847 /* xvadd.d */, LoongArch::XVADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12855 /* xvadd.h */, LoongArch::XVADD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12863 /* xvadd.q */, LoongArch::XVADD_Q, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12871 /* xvadd.w */, LoongArch::XVADD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12879 /* xvadda.b */, LoongArch::XVADDA_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12888 /* xvadda.d */, LoongArch::XVADDA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12897 /* xvadda.h */, LoongArch::XVADDA_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12906 /* xvadda.w */, LoongArch::XVADDA_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12915 /* xvaddi.bu */, LoongArch::XVADDI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 12925 /* xvaddi.du */, LoongArch::XVADDI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 12935 /* xvaddi.hu */, LoongArch::XVADDI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 12945 /* xvaddi.wu */, LoongArch::XVADDI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 12955 /* xvaddwev.d.w */, LoongArch::XVADDWEV_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12968 /* xvaddwev.d.wu */, LoongArch::XVADDWEV_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12982 /* xvaddwev.d.wu.w */, LoongArch::XVADDWEV_D_WU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 12998 /* xvaddwev.h.b */, LoongArch::XVADDWEV_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13011 /* xvaddwev.h.bu */, LoongArch::XVADDWEV_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13025 /* xvaddwev.h.bu.b */, LoongArch::XVADDWEV_H_BU_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13041 /* xvaddwev.q.d */, LoongArch::XVADDWEV_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13054 /* xvaddwev.q.du */, LoongArch::XVADDWEV_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13068 /* xvaddwev.q.du.d */, LoongArch::XVADDWEV_Q_DU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13084 /* xvaddwev.w.h */, LoongArch::XVADDWEV_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13097 /* xvaddwev.w.hu */, LoongArch::XVADDWEV_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13111 /* xvaddwev.w.hu.h */, LoongArch::XVADDWEV_W_HU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13127 /* xvaddwod.d.w */, LoongArch::XVADDWOD_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13140 /* xvaddwod.d.wu */, LoongArch::XVADDWOD_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13154 /* xvaddwod.d.wu.w */, LoongArch::XVADDWOD_D_WU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13170 /* xvaddwod.h.b */, LoongArch::XVADDWOD_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13183 /* xvaddwod.h.bu */, LoongArch::XVADDWOD_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13197 /* xvaddwod.h.bu.b */, LoongArch::XVADDWOD_H_BU_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13213 /* xvaddwod.q.d */, LoongArch::XVADDWOD_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13226 /* xvaddwod.q.du */, LoongArch::XVADDWOD_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13240 /* xvaddwod.q.du.d */, LoongArch::XVADDWOD_Q_DU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13256 /* xvaddwod.w.h */, LoongArch::XVADDWOD_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13269 /* xvaddwod.w.hu */, LoongArch::XVADDWOD_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13283 /* xvaddwod.w.hu.h */, LoongArch::XVADDWOD_W_HU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13299 /* xvand.v */, LoongArch::XVAND_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13307 /* xvandi.b */, LoongArch::XVANDI_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 13316 /* xvandn.v */, LoongArch::XVANDN_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13325 /* xvavg.b */, LoongArch::XVAVG_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13333 /* xvavg.bu */, LoongArch::XVAVG_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13342 /* xvavg.d */, LoongArch::XVAVG_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13350 /* xvavg.du */, LoongArch::XVAVG_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13359 /* xvavg.h */, LoongArch::XVAVG_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13367 /* xvavg.hu */, LoongArch::XVAVG_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13376 /* xvavg.w */, LoongArch::XVAVG_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13384 /* xvavg.wu */, LoongArch::XVAVG_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13393 /* xvavgr.b */, LoongArch::XVAVGR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13402 /* xvavgr.bu */, LoongArch::XVAVGR_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13412 /* xvavgr.d */, LoongArch::XVAVGR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13421 /* xvavgr.du */, LoongArch::XVAVGR_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13431 /* xvavgr.h */, LoongArch::XVAVGR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13440 /* xvavgr.hu */, LoongArch::XVAVGR_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13450 /* xvavgr.w */, LoongArch::XVAVGR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13459 /* xvavgr.wu */, LoongArch::XVAVGR_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13469 /* xvbitclr.b */, LoongArch::XVBITCLR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13480 /* xvbitclr.d */, LoongArch::XVBITCLR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13491 /* xvbitclr.h */, LoongArch::XVBITCLR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13502 /* xvbitclr.w */, LoongArch::XVBITCLR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13513 /* xvbitclri.b */, LoongArch::XVBITCLRI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 13525 /* xvbitclri.d */, LoongArch::XVBITCLRI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 13537 /* xvbitclri.h */, LoongArch::XVBITCLRI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 13549 /* xvbitclri.w */, LoongArch::XVBITCLRI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 13561 /* xvbitrev.b */, LoongArch::XVBITREV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13572 /* xvbitrev.d */, LoongArch::XVBITREV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13583 /* xvbitrev.h */, LoongArch::XVBITREV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13594 /* xvbitrev.w */, LoongArch::XVBITREV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13605 /* xvbitrevi.b */, LoongArch::XVBITREVI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 13617 /* xvbitrevi.d */, LoongArch::XVBITREVI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 13629 /* xvbitrevi.h */, LoongArch::XVBITREVI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 13641 /* xvbitrevi.w */, LoongArch::XVBITREVI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 13653 /* xvbitsel.v */, LoongArch::XVBITSEL_V, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13664 /* xvbitseli.b */, LoongArch::XVBITSELI_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 13676 /* xvbitset.b */, LoongArch::XVBITSET_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13687 /* xvbitset.d */, LoongArch::XVBITSET_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13698 /* xvbitset.h */, LoongArch::XVBITSET_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13709 /* xvbitset.w */, LoongArch::XVBITSET_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13720 /* xvbitseti.b */, LoongArch::XVBITSETI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 13732 /* xvbitseti.d */, LoongArch::XVBITSETI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 13744 /* xvbitseti.h */, LoongArch::XVBITSETI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 13756 /* xvbitseti.w */, LoongArch::XVBITSETI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 13768 /* xvbsll.v */, LoongArch::XVBSLL_V, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 13777 /* xvbsrl.v */, LoongArch::XVBSRL_V, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 13786 /* xvclo.b */, LoongArch::XVCLO_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13794 /* xvclo.d */, LoongArch::XVCLO_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13802 /* xvclo.h */, LoongArch::XVCLO_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13810 /* xvclo.w */, LoongArch::XVCLO_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13818 /* xvclz.b */, LoongArch::XVCLZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13826 /* xvclz.d */, LoongArch::XVCLZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13834 /* xvclz.h */, LoongArch::XVCLZ_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13842 /* xvclz.w */, LoongArch::XVCLZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13850 /* xvdiv.b */, LoongArch::XVDIV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13858 /* xvdiv.bu */, LoongArch::XVDIV_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13867 /* xvdiv.d */, LoongArch::XVDIV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13875 /* xvdiv.du */, LoongArch::XVDIV_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13884 /* xvdiv.h */, LoongArch::XVDIV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13892 /* xvdiv.hu */, LoongArch::XVDIV_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13901 /* xvdiv.w */, LoongArch::XVDIV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13909 /* xvdiv.wu */, LoongArch::XVDIV_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 13918 /* xvexth.d.w */, LoongArch::XVEXTH_D_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13929 /* xvexth.du.wu */, LoongArch::XVEXTH_DU_WU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13942 /* xvexth.h.b */, LoongArch::XVEXTH_H_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13953 /* xvexth.hu.bu */, LoongArch::XVEXTH_HU_BU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13966 /* xvexth.q.d */, LoongArch::XVEXTH_Q_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13977 /* xvexth.qu.du */, LoongArch::XVEXTH_QU_DU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 13990 /* xvexth.w.h */, LoongArch::XVEXTH_W_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14001 /* xvexth.wu.hu */, LoongArch::XVEXTH_WU_HU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14014 /* xvextl.q.d */, LoongArch::XVEXTL_Q_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14025 /* xvextl.qu.du */, LoongArch::XVEXTL_QU_DU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14038 /* xvextrins.b */, LoongArch::XVEXTRINS_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 14050 /* xvextrins.d */, LoongArch::XVEXTRINS_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 14062 /* xvextrins.h */, LoongArch::XVEXTRINS_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 14074 /* xvextrins.w */, LoongArch::XVEXTRINS_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 14086 /* xvfadd.d */, LoongArch::XVFADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14095 /* xvfadd.s */, LoongArch::XVFADD_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14104 /* xvfclass.d */, LoongArch::XVFCLASS_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14115 /* xvfclass.s */, LoongArch::XVFCLASS_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14126 /* xvfcmp.caf.d */, LoongArch::XVFCMP_CAF_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14139 /* xvfcmp.caf.s */, LoongArch::XVFCMP_CAF_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14152 /* xvfcmp.ceq.d */, LoongArch::XVFCMP_CEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14165 /* xvfcmp.ceq.s */, LoongArch::XVFCMP_CEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14178 /* xvfcmp.cle.d */, LoongArch::XVFCMP_CLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14191 /* xvfcmp.cle.s */, LoongArch::XVFCMP_CLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14204 /* xvfcmp.clt.d */, LoongArch::XVFCMP_CLT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14217 /* xvfcmp.clt.s */, LoongArch::XVFCMP_CLT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14230 /* xvfcmp.cne.d */, LoongArch::XVFCMP_CNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14243 /* xvfcmp.cne.s */, LoongArch::XVFCMP_CNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14256 /* xvfcmp.cor.d */, LoongArch::XVFCMP_COR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14269 /* xvfcmp.cor.s */, LoongArch::XVFCMP_COR_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14282 /* xvfcmp.cueq.d */, LoongArch::XVFCMP_CUEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14296 /* xvfcmp.cueq.s */, LoongArch::XVFCMP_CUEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14310 /* xvfcmp.cule.d */, LoongArch::XVFCMP_CULE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14324 /* xvfcmp.cule.s */, LoongArch::XVFCMP_CULE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14338 /* xvfcmp.cult.d */, LoongArch::XVFCMP_CULT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14352 /* xvfcmp.cult.s */, LoongArch::XVFCMP_CULT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14366 /* xvfcmp.cun.d */, LoongArch::XVFCMP_CUN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14379 /* xvfcmp.cun.s */, LoongArch::XVFCMP_CUN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14392 /* xvfcmp.cune.d */, LoongArch::XVFCMP_CUNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14406 /* xvfcmp.cune.s */, LoongArch::XVFCMP_CUNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14420 /* xvfcmp.saf.d */, LoongArch::XVFCMP_SAF_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14433 /* xvfcmp.saf.s */, LoongArch::XVFCMP_SAF_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14446 /* xvfcmp.seq.d */, LoongArch::XVFCMP_SEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14459 /* xvfcmp.seq.s */, LoongArch::XVFCMP_SEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14472 /* xvfcmp.sle.d */, LoongArch::XVFCMP_SLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14485 /* xvfcmp.sle.s */, LoongArch::XVFCMP_SLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14498 /* xvfcmp.slt.d */, LoongArch::XVFCMP_SLT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14511 /* xvfcmp.slt.s */, LoongArch::XVFCMP_SLT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14524 /* xvfcmp.sne.d */, LoongArch::XVFCMP_SNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14537 /* xvfcmp.sne.s */, LoongArch::XVFCMP_SNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14550 /* xvfcmp.sor.d */, LoongArch::XVFCMP_SOR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14563 /* xvfcmp.sor.s */, LoongArch::XVFCMP_SOR_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14576 /* xvfcmp.sueq.d */, LoongArch::XVFCMP_SUEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14590 /* xvfcmp.sueq.s */, LoongArch::XVFCMP_SUEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14604 /* xvfcmp.sule.d */, LoongArch::XVFCMP_SULE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14618 /* xvfcmp.sule.s */, LoongArch::XVFCMP_SULE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14632 /* xvfcmp.sult.d */, LoongArch::XVFCMP_SULT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14646 /* xvfcmp.sult.s */, LoongArch::XVFCMP_SULT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14660 /* xvfcmp.sun.d */, LoongArch::XVFCMP_SUN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14673 /* xvfcmp.sun.s */, LoongArch::XVFCMP_SUN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14686 /* xvfcmp.sune.d */, LoongArch::XVFCMP_SUNE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14700 /* xvfcmp.sune.s */, LoongArch::XVFCMP_SUNE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14714 /* xvfcvt.h.s */, LoongArch::XVFCVT_H_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14725 /* xvfcvt.s.d */, LoongArch::XVFCVT_S_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14736 /* xvfcvth.d.s */, LoongArch::XVFCVTH_D_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14748 /* xvfcvth.s.h */, LoongArch::XVFCVTH_S_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14760 /* xvfcvtl.d.s */, LoongArch::XVFCVTL_D_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14772 /* xvfcvtl.s.h */, LoongArch::XVFCVTL_S_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14784 /* xvfdiv.d */, LoongArch::XVFDIV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14793 /* xvfdiv.s */, LoongArch::XVFDIV_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14802 /* xvffint.d.l */, LoongArch::XVFFINT_D_L, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14814 /* xvffint.d.lu */, LoongArch::XVFFINT_D_LU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14827 /* xvffint.s.l */, LoongArch::XVFFINT_S_L, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14839 /* xvffint.s.w */, LoongArch::XVFFINT_S_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14851 /* xvffint.s.wu */, LoongArch::XVFFINT_S_WU, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14864 /* xvffinth.d.w */, LoongArch::XVFFINTH_D_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14877 /* xvffintl.d.w */, LoongArch::XVFFINTL_D_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14890 /* xvflogb.d */, LoongArch::XVFLOGB_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14900 /* xvflogb.s */, LoongArch::XVFLOGB_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 14910 /* xvfmadd.d */, LoongArch::XVFMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14920 /* xvfmadd.s */, LoongArch::XVFMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14930 /* xvfmax.d */, LoongArch::XVFMAX_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14939 /* xvfmax.s */, LoongArch::XVFMAX_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14948 /* xvfmaxa.d */, LoongArch::XVFMAXA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14958 /* xvfmaxa.s */, LoongArch::XVFMAXA_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14968 /* xvfmin.d */, LoongArch::XVFMIN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14977 /* xvfmin.s */, LoongArch::XVFMIN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14986 /* xvfmina.d */, LoongArch::XVFMINA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 14996 /* xvfmina.s */, LoongArch::XVFMINA_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15006 /* xvfmsub.d */, LoongArch::XVFMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15016 /* xvfmsub.s */, LoongArch::XVFMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15026 /* xvfmul.d */, LoongArch::XVFMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15035 /* xvfmul.s */, LoongArch::XVFMUL_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15044 /* xvfnmadd.d */, LoongArch::XVFNMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15055 /* xvfnmadd.s */, LoongArch::XVFNMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15066 /* xvfnmsub.d */, LoongArch::XVFNMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15077 /* xvfnmsub.s */, LoongArch::XVFNMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15088 /* xvfrecip.d */, LoongArch::XVFRECIP_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15099 /* xvfrecip.s */, LoongArch::XVFRECIP_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15110 /* xvfrecipe.d */, LoongArch::XVFRECIPE_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15122 /* xvfrecipe.s */, LoongArch::XVFRECIPE_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15134 /* xvfrint.d */, LoongArch::XVFRINT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15144 /* xvfrint.s */, LoongArch::XVFRINT_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15154 /* xvfrintrm.d */, LoongArch::XVFRINTRM_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15166 /* xvfrintrm.s */, LoongArch::XVFRINTRM_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15178 /* xvfrintrne.d */, LoongArch::XVFRINTRNE_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15191 /* xvfrintrne.s */, LoongArch::XVFRINTRNE_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15204 /* xvfrintrp.d */, LoongArch::XVFRINTRP_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15216 /* xvfrintrp.s */, LoongArch::XVFRINTRP_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15228 /* xvfrintrz.d */, LoongArch::XVFRINTRZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15240 /* xvfrintrz.s */, LoongArch::XVFRINTRZ_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15252 /* xvfrsqrt.d */, LoongArch::XVFRSQRT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15263 /* xvfrsqrt.s */, LoongArch::XVFRSQRT_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15274 /* xvfrsqrte.d */, LoongArch::XVFRSQRTE_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15286 /* xvfrsqrte.s */, LoongArch::XVFRSQRTE_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15298 /* xvfrstp.b */, LoongArch::XVFRSTP_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15308 /* xvfrstp.h */, LoongArch::XVFRSTP_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15318 /* xvfrstpi.b */, LoongArch::XVFRSTPI_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 15329 /* xvfrstpi.h */, LoongArch::XVFRSTPI_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 15340 /* xvfsqrt.d */, LoongArch::XVFSQRT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15350 /* xvfsqrt.s */, LoongArch::XVFSQRT_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15360 /* xvfsub.d */, LoongArch::XVFSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15369 /* xvfsub.s */, LoongArch::XVFSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15378 /* xvftint.l.d */, LoongArch::XVFTINT_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15390 /* xvftint.lu.d */, LoongArch::XVFTINT_LU_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15403 /* xvftint.w.d */, LoongArch::XVFTINT_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15415 /* xvftint.w.s */, LoongArch::XVFTINT_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15427 /* xvftint.wu.s */, LoongArch::XVFTINT_WU_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15440 /* xvftinth.l.s */, LoongArch::XVFTINTH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15453 /* xvftintl.l.s */, LoongArch::XVFTINTL_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15466 /* xvftintrm.l.d */, LoongArch::XVFTINTRM_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15480 /* xvftintrm.w.d */, LoongArch::XVFTINTRM_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15494 /* xvftintrm.w.s */, LoongArch::XVFTINTRM_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15508 /* xvftintrmh.l.s */, LoongArch::XVFTINTRMH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15523 /* xvftintrml.l.s */, LoongArch::XVFTINTRML_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15538 /* xvftintrne.l.d */, LoongArch::XVFTINTRNE_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15553 /* xvftintrne.w.d */, LoongArch::XVFTINTRNE_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15568 /* xvftintrne.w.s */, LoongArch::XVFTINTRNE_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15583 /* xvftintrneh.l.s */, LoongArch::XVFTINTRNEH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15599 /* xvftintrnel.l.s */, LoongArch::XVFTINTRNEL_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15615 /* xvftintrp.l.d */, LoongArch::XVFTINTRP_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15629 /* xvftintrp.w.d */, LoongArch::XVFTINTRP_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15643 /* xvftintrp.w.s */, LoongArch::XVFTINTRP_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15657 /* xvftintrph.l.s */, LoongArch::XVFTINTRPH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15672 /* xvftintrpl.l.s */, LoongArch::XVFTINTRPL_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15687 /* xvftintrz.l.d */, LoongArch::XVFTINTRZ_L_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15701 /* xvftintrz.lu.d */, LoongArch::XVFTINTRZ_LU_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15716 /* xvftintrz.w.d */, LoongArch::XVFTINTRZ_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15730 /* xvftintrz.w.s */, LoongArch::XVFTINTRZ_W_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15744 /* xvftintrz.wu.s */, LoongArch::XVFTINTRZ_WU_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15759 /* xvftintrzh.l.s */, LoongArch::XVFTINTRZH_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15774 /* xvftintrzl.l.s */, LoongArch::XVFTINTRZL_L_S, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 15789 /* xvhaddw.d.w */, LoongArch::XVHADDW_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15801 /* xvhaddw.du.wu */, LoongArch::XVHADDW_DU_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15815 /* xvhaddw.h.b */, LoongArch::XVHADDW_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15827 /* xvhaddw.hu.bu */, LoongArch::XVHADDW_HU_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15841 /* xvhaddw.q.d */, LoongArch::XVHADDW_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15853 /* xvhaddw.qu.du */, LoongArch::XVHADDW_QU_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15867 /* xvhaddw.w.h */, LoongArch::XVHADDW_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15879 /* xvhaddw.wu.hu */, LoongArch::XVHADDW_WU_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15893 /* xvhseli.d */, LoongArch::XVHSELI_D, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 15903 /* xvhsubw.d.w */, LoongArch::XVHSUBW_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15915 /* xvhsubw.du.wu */, LoongArch::XVHSUBW_DU_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15929 /* xvhsubw.h.b */, LoongArch::XVHSUBW_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15941 /* xvhsubw.hu.bu */, LoongArch::XVHSUBW_HU_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15955 /* xvhsubw.q.d */, LoongArch::XVHSUBW_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15967 /* xvhsubw.qu.du */, LoongArch::XVHSUBW_QU_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15981 /* xvhsubw.w.h */, LoongArch::XVHSUBW_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 15993 /* xvhsubw.wu.hu */, LoongArch::XVHSUBW_WU_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16007 /* xvilvh.b */, LoongArch::XVILVH_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16016 /* xvilvh.d */, LoongArch::XVILVH_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16025 /* xvilvh.h */, LoongArch::XVILVH_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16034 /* xvilvh.w */, LoongArch::XVILVH_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16043 /* xvilvl.b */, LoongArch::XVILVL_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16052 /* xvilvl.d */, LoongArch::XVILVL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16061 /* xvilvl.h */, LoongArch::XVILVL_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16070 /* xvilvl.w */, LoongArch::XVILVL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16079 /* xvinsgr2vr.d */, LoongArch::XVINSGR2VR_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm21_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_UImm2 }, },
  { 16092 /* xvinsgr2vr.w */, LoongArch::XVINSGR2VR_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_UImm3 }, },
  { 16105 /* xvinsve0.d */, LoongArch::XVINSVE0_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm21_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm2 }, },
  { 16116 /* xvinsve0.w */, LoongArch::XVINSVE0_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 16127 /* xvld */, LoongArch::XVLD, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm12addlike }, },
  { 16132 /* xvldi */, LoongArch::XVLDI, Convert__Reg1_0__SImm131_1, AMFBS_None, { MCK_LASX256, MCK_SImm13 }, },
  { 16138 /* xvldrepl.b */, LoongArch::XVLDREPL_B, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm12addlike }, },
  { 16149 /* xvldrepl.d */, LoongArch::XVLDREPL_D, Convert__Reg1_0__Reg1_1__SImm9lsl31_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm9lsl3 }, },
  { 16160 /* xvldrepl.h */, LoongArch::XVLDREPL_H, Convert__Reg1_0__Reg1_1__SImm11lsl11_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm11lsl1 }, },
  { 16171 /* xvldrepl.w */, LoongArch::XVLDREPL_W, Convert__Reg1_0__Reg1_1__SImm10lsl21_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm10lsl2 }, },
  { 16182 /* xvldx */, LoongArch::XVLDX, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_GPR }, },
  { 16188 /* xvmadd.b */, LoongArch::XVMADD_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16197 /* xvmadd.d */, LoongArch::XVMADD_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16206 /* xvmadd.h */, LoongArch::XVMADD_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16215 /* xvmadd.w */, LoongArch::XVMADD_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16224 /* xvmaddwev.d.w */, LoongArch::XVMADDWEV_D_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16238 /* xvmaddwev.d.wu */, LoongArch::XVMADDWEV_D_WU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16253 /* xvmaddwev.d.wu.w */, LoongArch::XVMADDWEV_D_WU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16270 /* xvmaddwev.h.b */, LoongArch::XVMADDWEV_H_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16284 /* xvmaddwev.h.bu */, LoongArch::XVMADDWEV_H_BU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16299 /* xvmaddwev.h.bu.b */, LoongArch::XVMADDWEV_H_BU_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16316 /* xvmaddwev.q.d */, LoongArch::XVMADDWEV_Q_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16330 /* xvmaddwev.q.du */, LoongArch::XVMADDWEV_Q_DU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16345 /* xvmaddwev.q.du.d */, LoongArch::XVMADDWEV_Q_DU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16362 /* xvmaddwev.w.h */, LoongArch::XVMADDWEV_W_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16376 /* xvmaddwev.w.hu */, LoongArch::XVMADDWEV_W_HU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16391 /* xvmaddwev.w.hu.h */, LoongArch::XVMADDWEV_W_HU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16408 /* xvmaddwod.d.w */, LoongArch::XVMADDWOD_D_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16422 /* xvmaddwod.d.wu */, LoongArch::XVMADDWOD_D_WU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16437 /* xvmaddwod.d.wu.w */, LoongArch::XVMADDWOD_D_WU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16454 /* xvmaddwod.h.b */, LoongArch::XVMADDWOD_H_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16468 /* xvmaddwod.h.bu */, LoongArch::XVMADDWOD_H_BU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16483 /* xvmaddwod.h.bu.b */, LoongArch::XVMADDWOD_H_BU_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16500 /* xvmaddwod.q.d */, LoongArch::XVMADDWOD_Q_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16514 /* xvmaddwod.q.du */, LoongArch::XVMADDWOD_Q_DU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16529 /* xvmaddwod.q.du.d */, LoongArch::XVMADDWOD_Q_DU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16546 /* xvmaddwod.w.h */, LoongArch::XVMADDWOD_W_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16560 /* xvmaddwod.w.hu */, LoongArch::XVMADDWOD_W_HU, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16575 /* xvmaddwod.w.hu.h */, LoongArch::XVMADDWOD_W_HU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16592 /* xvmax.b */, LoongArch::XVMAX_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16600 /* xvmax.bu */, LoongArch::XVMAX_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16609 /* xvmax.d */, LoongArch::XVMAX_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16617 /* xvmax.du */, LoongArch::XVMAX_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16626 /* xvmax.h */, LoongArch::XVMAX_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16634 /* xvmax.hu */, LoongArch::XVMAX_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16643 /* xvmax.w */, LoongArch::XVMAX_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16651 /* xvmax.wu */, LoongArch::XVMAX_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16660 /* xvmaxi.b */, LoongArch::XVMAXI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 16669 /* xvmaxi.bu */, LoongArch::XVMAXI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 16679 /* xvmaxi.d */, LoongArch::XVMAXI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 16688 /* xvmaxi.du */, LoongArch::XVMAXI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 16698 /* xvmaxi.h */, LoongArch::XVMAXI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 16707 /* xvmaxi.hu */, LoongArch::XVMAXI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 16717 /* xvmaxi.w */, LoongArch::XVMAXI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 16726 /* xvmaxi.wu */, LoongArch::XVMAXI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 16736 /* xvmin.b */, LoongArch::XVMIN_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16744 /* xvmin.bu */, LoongArch::XVMIN_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16753 /* xvmin.d */, LoongArch::XVMIN_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16761 /* xvmin.du */, LoongArch::XVMIN_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16770 /* xvmin.h */, LoongArch::XVMIN_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16778 /* xvmin.hu */, LoongArch::XVMIN_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16787 /* xvmin.w */, LoongArch::XVMIN_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16795 /* xvmin.wu */, LoongArch::XVMIN_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16804 /* xvmini.b */, LoongArch::XVMINI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 16813 /* xvmini.bu */, LoongArch::XVMINI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 16823 /* xvmini.d */, LoongArch::XVMINI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 16832 /* xvmini.du */, LoongArch::XVMINI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 16842 /* xvmini.h */, LoongArch::XVMINI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 16851 /* xvmini.hu */, LoongArch::XVMINI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 16861 /* xvmini.w */, LoongArch::XVMINI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 16870 /* xvmini.wu */, LoongArch::XVMINI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 16880 /* xvmod.b */, LoongArch::XVMOD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16888 /* xvmod.bu */, LoongArch::XVMOD_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16897 /* xvmod.d */, LoongArch::XVMOD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16905 /* xvmod.du */, LoongArch::XVMOD_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16914 /* xvmod.h */, LoongArch::XVMOD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16922 /* xvmod.hu */, LoongArch::XVMOD_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16931 /* xvmod.w */, LoongArch::XVMOD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16939 /* xvmod.wu */, LoongArch::XVMOD_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 16948 /* xvmskgez.b */, LoongArch::XVMSKGEZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 16959 /* xvmskltz.b */, LoongArch::XVMSKLTZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 16970 /* xvmskltz.d */, LoongArch::XVMSKLTZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 16981 /* xvmskltz.h */, LoongArch::XVMSKLTZ_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 16992 /* xvmskltz.w */, LoongArch::XVMSKLTZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17003 /* xvmsknz.b */, LoongArch::XVMSKNZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17013 /* xvmsub.b */, LoongArch::XVMSUB_B, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17022 /* xvmsub.d */, LoongArch::XVMSUB_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17031 /* xvmsub.h */, LoongArch::XVMSUB_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17040 /* xvmsub.w */, LoongArch::XVMSUB_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17049 /* xvmuh.b */, LoongArch::XVMUH_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17057 /* xvmuh.bu */, LoongArch::XVMUH_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17066 /* xvmuh.d */, LoongArch::XVMUH_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17074 /* xvmuh.du */, LoongArch::XVMUH_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17083 /* xvmuh.h */, LoongArch::XVMUH_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17091 /* xvmuh.hu */, LoongArch::XVMUH_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17100 /* xvmuh.w */, LoongArch::XVMUH_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17108 /* xvmuh.wu */, LoongArch::XVMUH_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17117 /* xvmul.b */, LoongArch::XVMUL_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17125 /* xvmul.d */, LoongArch::XVMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17133 /* xvmul.h */, LoongArch::XVMUL_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17141 /* xvmul.w */, LoongArch::XVMUL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17149 /* xvmulwev.d.w */, LoongArch::XVMULWEV_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17162 /* xvmulwev.d.wu */, LoongArch::XVMULWEV_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17176 /* xvmulwev.d.wu.w */, LoongArch::XVMULWEV_D_WU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17192 /* xvmulwev.h.b */, LoongArch::XVMULWEV_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17205 /* xvmulwev.h.bu */, LoongArch::XVMULWEV_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17219 /* xvmulwev.h.bu.b */, LoongArch::XVMULWEV_H_BU_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17235 /* xvmulwev.q.d */, LoongArch::XVMULWEV_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17248 /* xvmulwev.q.du */, LoongArch::XVMULWEV_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17262 /* xvmulwev.q.du.d */, LoongArch::XVMULWEV_Q_DU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17278 /* xvmulwev.w.h */, LoongArch::XVMULWEV_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17291 /* xvmulwev.w.hu */, LoongArch::XVMULWEV_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17305 /* xvmulwev.w.hu.h */, LoongArch::XVMULWEV_W_HU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17321 /* xvmulwod.d.w */, LoongArch::XVMULWOD_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17334 /* xvmulwod.d.wu */, LoongArch::XVMULWOD_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17348 /* xvmulwod.d.wu.w */, LoongArch::XVMULWOD_D_WU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17364 /* xvmulwod.h.b */, LoongArch::XVMULWOD_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17377 /* xvmulwod.h.bu */, LoongArch::XVMULWOD_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17391 /* xvmulwod.h.bu.b */, LoongArch::XVMULWOD_H_BU_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17407 /* xvmulwod.q.d */, LoongArch::XVMULWOD_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17420 /* xvmulwod.q.du */, LoongArch::XVMULWOD_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17434 /* xvmulwod.q.du.d */, LoongArch::XVMULWOD_Q_DU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17450 /* xvmulwod.w.h */, LoongArch::XVMULWOD_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17463 /* xvmulwod.w.hu */, LoongArch::XVMULWOD_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17477 /* xvmulwod.w.hu.h */, LoongArch::XVMULWOD_W_HU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17493 /* xvneg.b */, LoongArch::XVNEG_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17501 /* xvneg.d */, LoongArch::XVNEG_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17509 /* xvneg.h */, LoongArch::XVNEG_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17517 /* xvneg.w */, LoongArch::XVNEG_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17525 /* xvnor.v */, LoongArch::XVNOR_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17533 /* xvnori.b */, LoongArch::XVNORI_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 17542 /* xvor.v */, LoongArch::XVOR_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17549 /* xvori.b */, LoongArch::XVORI_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 17557 /* xvorn.v */, LoongArch::XVORN_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17565 /* xvpackev.b */, LoongArch::XVPACKEV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17576 /* xvpackev.d */, LoongArch::XVPACKEV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17587 /* xvpackev.h */, LoongArch::XVPACKEV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17598 /* xvpackev.w */, LoongArch::XVPACKEV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17609 /* xvpackod.b */, LoongArch::XVPACKOD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17620 /* xvpackod.d */, LoongArch::XVPACKOD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17631 /* xvpackod.h */, LoongArch::XVPACKOD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17642 /* xvpackod.w */, LoongArch::XVPACKOD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17653 /* xvpcnt.b */, LoongArch::XVPCNT_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17662 /* xvpcnt.d */, LoongArch::XVPCNT_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17671 /* xvpcnt.h */, LoongArch::XVPCNT_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17680 /* xvpcnt.w */, LoongArch::XVPCNT_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 17689 /* xvperm.w */, LoongArch::XVPERM_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17698 /* xvpermi.d */, LoongArch::XVPERMI_D, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 17708 /* xvpermi.q */, LoongArch::XVPERMI_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 17718 /* xvpermi.w */, LoongArch::XVPERMI_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 17728 /* xvpickev.b */, LoongArch::XVPICKEV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17739 /* xvpickev.d */, LoongArch::XVPICKEV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17750 /* xvpickev.h */, LoongArch::XVPICKEV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17761 /* xvpickev.w */, LoongArch::XVPICKEV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17772 /* xvpickod.b */, LoongArch::XVPICKOD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17783 /* xvpickod.d */, LoongArch::XVPICKOD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17794 /* xvpickod.h */, LoongArch::XVPICKOD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17805 /* xvpickod.w */, LoongArch::XVPICKOD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 17816 /* xvpickve.d */, LoongArch::XVPICKVE_D, Convert__Reg1_0__Reg1_1__UImm21_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm2 }, },
  { 17827 /* xvpickve.w */, LoongArch::XVPICKVE_W, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 17838 /* xvpickve2gr.d */, LoongArch::XVPICKVE2GR_D, Convert__Reg1_0__Reg1_1__UImm21_2, AMFBS_None, { MCK_GPR, MCK_LASX256, MCK_UImm2 }, },
  { 17852 /* xvpickve2gr.du */, LoongArch::XVPICKVE2GR_DU, Convert__Reg1_0__Reg1_1__UImm21_2, AMFBS_None, { MCK_GPR, MCK_LASX256, MCK_UImm2 }, },
  { 17867 /* xvpickve2gr.w */, LoongArch::XVPICKVE2GR_W, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_GPR, MCK_LASX256, MCK_UImm3 }, },
  { 17881 /* xvpickve2gr.wu */, LoongArch::XVPICKVE2GR_WU, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_GPR, MCK_LASX256, MCK_UImm3 }, },
  { 17896 /* xvrepl128vei.b */, LoongArch::XVREPL128VEI_B, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 17911 /* xvrepl128vei.d */, LoongArch::XVREPL128VEI_D, Convert__Reg1_0__Reg1_1__UImm11_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm1 }, },
  { 17926 /* xvrepl128vei.h */, LoongArch::XVREPL128VEI_H, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 17941 /* xvrepl128vei.w */, LoongArch::XVREPL128VEI_W, Convert__Reg1_0__Reg1_1__UImm21_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm2 }, },
  { 17956 /* xvreplgr2vr.b */, LoongArch::XVREPLGR2VR_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_GPR }, },
  { 17970 /* xvreplgr2vr.d */, LoongArch::XVREPLGR2VR_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_GPR }, },
  { 17984 /* xvreplgr2vr.h */, LoongArch::XVREPLGR2VR_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_GPR }, },
  { 17998 /* xvreplgr2vr.w */, LoongArch::XVREPLGR2VR_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_GPR }, },
  { 18012 /* xvrepli.b */, LoongArch::PseudoXVREPLI_B, Convert__Reg1_0__SImm101_1, AMFBS_None, { MCK_LASX256, MCK_SImm10 }, },
  { 18022 /* xvrepli.d */, LoongArch::PseudoXVREPLI_D, Convert__Reg1_0__SImm101_1, AMFBS_None, { MCK_LASX256, MCK_SImm10 }, },
  { 18032 /* xvrepli.h */, LoongArch::PseudoXVREPLI_H, Convert__Reg1_0__SImm101_1, AMFBS_None, { MCK_LASX256, MCK_SImm10 }, },
  { 18042 /* xvrepli.w */, LoongArch::PseudoXVREPLI_W, Convert__Reg1_0__SImm101_1, AMFBS_None, { MCK_LASX256, MCK_SImm10 }, },
  { 18052 /* xvreplve.b */, LoongArch::XVREPLVE_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_GPR }, },
  { 18063 /* xvreplve.d */, LoongArch::XVREPLVE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_GPR }, },
  { 18074 /* xvreplve.h */, LoongArch::XVREPLVE_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_GPR }, },
  { 18085 /* xvreplve.w */, LoongArch::XVREPLVE_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_GPR }, },
  { 18096 /* xvreplve0.b */, LoongArch::XVREPLVE0_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 18108 /* xvreplve0.d */, LoongArch::XVREPLVE0_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 18120 /* xvreplve0.h */, LoongArch::XVREPLVE0_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 18132 /* xvreplve0.q */, LoongArch::XVREPLVE0_Q, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 18144 /* xvreplve0.w */, LoongArch::XVREPLVE0_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_LASX256, MCK_LASX256 }, },
  { 18156 /* xvrotr.b */, LoongArch::XVROTR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18165 /* xvrotr.d */, LoongArch::XVROTR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18174 /* xvrotr.h */, LoongArch::XVROTR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18183 /* xvrotr.w */, LoongArch::XVROTR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18192 /* xvrotri.b */, LoongArch::XVROTRI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 18202 /* xvrotri.d */, LoongArch::XVROTRI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 18212 /* xvrotri.h */, LoongArch::XVROTRI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 18222 /* xvrotri.w */, LoongArch::XVROTRI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18232 /* xvsadd.b */, LoongArch::XVSADD_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18241 /* xvsadd.bu */, LoongArch::XVSADD_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18251 /* xvsadd.d */, LoongArch::XVSADD_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18260 /* xvsadd.du */, LoongArch::XVSADD_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18270 /* xvsadd.h */, LoongArch::XVSADD_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18279 /* xvsadd.hu */, LoongArch::XVSADD_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18289 /* xvsadd.w */, LoongArch::XVSADD_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18298 /* xvsadd.wu */, LoongArch::XVSADD_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18308 /* xvsat.b */, LoongArch::XVSAT_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 18316 /* xvsat.bu */, LoongArch::XVSAT_BU, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 18325 /* xvsat.d */, LoongArch::XVSAT_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 18333 /* xvsat.du */, LoongArch::XVSAT_DU, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 18342 /* xvsat.h */, LoongArch::XVSAT_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 18350 /* xvsat.hu */, LoongArch::XVSAT_HU, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 18359 /* xvsat.w */, LoongArch::XVSAT_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18367 /* xvsat.wu */, LoongArch::XVSAT_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18376 /* xvseq.b */, LoongArch::XVSEQ_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18384 /* xvseq.d */, LoongArch::XVSEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18392 /* xvseq.h */, LoongArch::XVSEQ_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18400 /* xvseq.w */, LoongArch::XVSEQ_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18408 /* xvseqi.b */, LoongArch::XVSEQI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 18417 /* xvseqi.d */, LoongArch::XVSEQI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 18426 /* xvseqi.h */, LoongArch::XVSEQI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 18435 /* xvseqi.w */, LoongArch::XVSEQI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 18444 /* xvsetallnez.b */, LoongArch::XVSETALLNEZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18458 /* xvsetallnez.d */, LoongArch::XVSETALLNEZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18472 /* xvsetallnez.h */, LoongArch::XVSETALLNEZ_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18486 /* xvsetallnez.w */, LoongArch::XVSETALLNEZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18500 /* xvsetanyeqz.b */, LoongArch::XVSETANYEQZ_B, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18514 /* xvsetanyeqz.d */, LoongArch::XVSETANYEQZ_D, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18528 /* xvsetanyeqz.h */, LoongArch::XVSETANYEQZ_H, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18542 /* xvsetanyeqz.w */, LoongArch::XVSETANYEQZ_W, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18556 /* xvseteqz.v */, LoongArch::XVSETEQZ_V, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18567 /* xvsetnez.v */, LoongArch::XVSETNEZ_V, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_CFR, MCK_LASX256 }, },
  { 18578 /* xvshuf.b */, LoongArch::XVSHUF_B, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18587 /* xvshuf.d */, LoongArch::XVSHUF_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18596 /* xvshuf.h */, LoongArch::XVSHUF_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18605 /* xvshuf.w */, LoongArch::XVSHUF_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18614 /* xvshuf4i.b */, LoongArch::XVSHUF4I_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 18625 /* xvshuf4i.d */, LoongArch::XVSHUF4I_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 18636 /* xvshuf4i.h */, LoongArch::XVSHUF4I_H, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 18647 /* xvshuf4i.w */, LoongArch::XVSHUF4I_W, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
  { 18658 /* xvsigncov.b */, LoongArch::XVSIGNCOV_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18670 /* xvsigncov.d */, LoongArch::XVSIGNCOV_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18682 /* xvsigncov.h */, LoongArch::XVSIGNCOV_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18694 /* xvsigncov.w */, LoongArch::XVSIGNCOV_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18706 /* xvsle.b */, LoongArch::XVSLE_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18714 /* xvsle.bu */, LoongArch::XVSLE_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18723 /* xvsle.d */, LoongArch::XVSLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18731 /* xvsle.du */, LoongArch::XVSLE_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18740 /* xvsle.h */, LoongArch::XVSLE_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18748 /* xvsle.hu */, LoongArch::XVSLE_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18757 /* xvsle.w */, LoongArch::XVSLE_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18765 /* xvsle.wu */, LoongArch::XVSLE_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18774 /* xvslei.b */, LoongArch::XVSLEI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 18783 /* xvslei.bu */, LoongArch::XVSLEI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18793 /* xvslei.d */, LoongArch::XVSLEI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 18802 /* xvslei.du */, LoongArch::XVSLEI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18812 /* xvslei.h */, LoongArch::XVSLEI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 18821 /* xvslei.hu */, LoongArch::XVSLEI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18831 /* xvslei.w */, LoongArch::XVSLEI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 18840 /* xvslei.wu */, LoongArch::XVSLEI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18850 /* xvsll.b */, LoongArch::XVSLL_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18858 /* xvsll.d */, LoongArch::XVSLL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18866 /* xvsll.h */, LoongArch::XVSLL_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18874 /* xvsll.w */, LoongArch::XVSLL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 18882 /* xvslli.b */, LoongArch::XVSLLI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 18891 /* xvslli.d */, LoongArch::XVSLLI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 18900 /* xvslli.h */, LoongArch::XVSLLI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 18909 /* xvslli.w */, LoongArch::XVSLLI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18918 /* xvsllwil.d.w */, LoongArch::XVSLLWIL_D_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18931 /* xvsllwil.du.wu */, LoongArch::XVSLLWIL_DU_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 18946 /* xvsllwil.h.b */, LoongArch::XVSLLWIL_H_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 18959 /* xvsllwil.hu.bu */, LoongArch::XVSLLWIL_HU_BU, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 18974 /* xvsllwil.w.h */, LoongArch::XVSLLWIL_W_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 18987 /* xvsllwil.wu.hu */, LoongArch::XVSLLWIL_WU_HU, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19002 /* xvslt.b */, LoongArch::XVSLT_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19010 /* xvslt.bu */, LoongArch::XVSLT_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19019 /* xvslt.d */, LoongArch::XVSLT_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19027 /* xvslt.du */, LoongArch::XVSLT_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19036 /* xvslt.h */, LoongArch::XVSLT_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19044 /* xvslt.hu */, LoongArch::XVSLT_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19053 /* xvslt.w */, LoongArch::XVSLT_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19061 /* xvslt.wu */, LoongArch::XVSLT_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19070 /* xvslti.b */, LoongArch::XVSLTI_B, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 19079 /* xvslti.bu */, LoongArch::XVSLTI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19089 /* xvslti.d */, LoongArch::XVSLTI_D, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 19098 /* xvslti.du */, LoongArch::XVSLTI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19108 /* xvslti.h */, LoongArch::XVSLTI_H, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 19117 /* xvslti.hu */, LoongArch::XVSLTI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19127 /* xvslti.w */, LoongArch::XVSLTI_W, Convert__Reg1_0__Reg1_1__SImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_SImm5 }, },
  { 19136 /* xvslti.wu */, LoongArch::XVSLTI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19146 /* xvsra.b */, LoongArch::XVSRA_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19154 /* xvsra.d */, LoongArch::XVSRA_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19162 /* xvsra.h */, LoongArch::XVSRA_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19170 /* xvsra.w */, LoongArch::XVSRA_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19178 /* xvsrai.b */, LoongArch::XVSRAI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 19187 /* xvsrai.d */, LoongArch::XVSRAI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19196 /* xvsrai.h */, LoongArch::XVSRAI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19205 /* xvsrai.w */, LoongArch::XVSRAI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19214 /* xvsran.b.h */, LoongArch::XVSRAN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19225 /* xvsran.h.w */, LoongArch::XVSRAN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19236 /* xvsran.w.d */, LoongArch::XVSRAN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19247 /* xvsrani.b.h */, LoongArch::XVSRANI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19259 /* xvsrani.d.q */, LoongArch::XVSRANI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 19271 /* xvsrani.h.w */, LoongArch::XVSRANI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19283 /* xvsrani.w.d */, LoongArch::XVSRANI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19295 /* xvsrar.b */, LoongArch::XVSRAR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19304 /* xvsrar.d */, LoongArch::XVSRAR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19313 /* xvsrar.h */, LoongArch::XVSRAR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19322 /* xvsrar.w */, LoongArch::XVSRAR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19331 /* xvsrari.b */, LoongArch::XVSRARI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 19341 /* xvsrari.d */, LoongArch::XVSRARI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19351 /* xvsrari.h */, LoongArch::XVSRARI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19361 /* xvsrari.w */, LoongArch::XVSRARI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19371 /* xvsrarn.b.h */, LoongArch::XVSRARN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19383 /* xvsrarn.h.w */, LoongArch::XVSRARN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19395 /* xvsrarn.w.d */, LoongArch::XVSRARN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19407 /* xvsrarni.b.h */, LoongArch::XVSRARNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19420 /* xvsrarni.d.q */, LoongArch::XVSRARNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 19433 /* xvsrarni.h.w */, LoongArch::XVSRARNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19446 /* xvsrarni.w.d */, LoongArch::XVSRARNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19459 /* xvsrl.b */, LoongArch::XVSRL_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19467 /* xvsrl.d */, LoongArch::XVSRL_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19475 /* xvsrl.h */, LoongArch::XVSRL_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19483 /* xvsrl.w */, LoongArch::XVSRL_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19491 /* xvsrli.b */, LoongArch::XVSRLI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 19500 /* xvsrli.d */, LoongArch::XVSRLI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19509 /* xvsrli.h */, LoongArch::XVSRLI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19518 /* xvsrli.w */, LoongArch::XVSRLI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19527 /* xvsrln.b.h */, LoongArch::XVSRLN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19538 /* xvsrln.h.w */, LoongArch::XVSRLN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19549 /* xvsrln.w.d */, LoongArch::XVSRLN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19560 /* xvsrlni.b.h */, LoongArch::XVSRLNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19572 /* xvsrlni.d.q */, LoongArch::XVSRLNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 19584 /* xvsrlni.h.w */, LoongArch::XVSRLNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19596 /* xvsrlni.w.d */, LoongArch::XVSRLNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19608 /* xvsrlr.b */, LoongArch::XVSRLR_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19617 /* xvsrlr.d */, LoongArch::XVSRLR_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19626 /* xvsrlr.h */, LoongArch::XVSRLR_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19635 /* xvsrlr.w */, LoongArch::XVSRLR_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19644 /* xvsrlri.b */, LoongArch::XVSRLRI_B, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm3 }, },
  { 19654 /* xvsrlri.d */, LoongArch::XVSRLRI_D, Convert__Reg1_0__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19664 /* xvsrlri.h */, LoongArch::XVSRLRI_H, Convert__Reg1_0__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19674 /* xvsrlri.w */, LoongArch::XVSRLRI_W, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19684 /* xvsrlrn.b.h */, LoongArch::XVSRLRN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19696 /* xvsrlrn.h.w */, LoongArch::XVSRLRN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19708 /* xvsrlrn.w.d */, LoongArch::XVSRLRN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19720 /* xvsrlrni.b.h */, LoongArch::XVSRLRNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19733 /* xvsrlrni.d.q */, LoongArch::XVSRLRNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 19746 /* xvsrlrni.h.w */, LoongArch::XVSRLRNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19759 /* xvsrlrni.w.d */, LoongArch::XVSRLRNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19772 /* xvssran.b.h */, LoongArch::XVSSRAN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19784 /* xvssran.bu.h */, LoongArch::XVSSRAN_BU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19797 /* xvssran.h.w */, LoongArch::XVSSRAN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19809 /* xvssran.hu.w */, LoongArch::XVSSRAN_HU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19822 /* xvssran.w.d */, LoongArch::XVSSRAN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19834 /* xvssran.wu.d */, LoongArch::XVSSRAN_WU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19847 /* xvssrani.b.h */, LoongArch::XVSSRANI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19860 /* xvssrani.bu.h */, LoongArch::XVSSRANI_BU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 19874 /* xvssrani.d.q */, LoongArch::XVSSRANI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 19887 /* xvssrani.du.q */, LoongArch::XVSSRANI_DU_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 19901 /* xvssrani.h.w */, LoongArch::XVSSRANI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19914 /* xvssrani.hu.w */, LoongArch::XVSSRANI_HU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 19928 /* xvssrani.w.d */, LoongArch::XVSSRANI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19941 /* xvssrani.wu.d */, LoongArch::XVSSRANI_WU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 19955 /* xvssrarn.b.h */, LoongArch::XVSSRARN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19968 /* xvssrarn.bu.h */, LoongArch::XVSSRARN_BU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19982 /* xvssrarn.h.w */, LoongArch::XVSSRARN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 19995 /* xvssrarn.hu.w */, LoongArch::XVSSRARN_HU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20009 /* xvssrarn.w.d */, LoongArch::XVSSRARN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20022 /* xvssrarn.wu.d */, LoongArch::XVSSRARN_WU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20036 /* xvssrarni.b.h */, LoongArch::XVSSRARNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 20050 /* xvssrarni.bu.h */, LoongArch::XVSSRARNI_BU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 20065 /* xvssrarni.d.q */, LoongArch::XVSSRARNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 20079 /* xvssrarni.du.q */, LoongArch::XVSSRARNI_DU_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 20094 /* xvssrarni.h.w */, LoongArch::XVSSRARNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20108 /* xvssrarni.hu.w */, LoongArch::XVSSRARNI_HU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20123 /* xvssrarni.w.d */, LoongArch::XVSSRARNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 20137 /* xvssrarni.wu.d */, LoongArch::XVSSRARNI_WU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 20152 /* xvssrln.b.h */, LoongArch::XVSSRLN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20164 /* xvssrln.bu.h */, LoongArch::XVSSRLN_BU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20177 /* xvssrln.h.w */, LoongArch::XVSSRLN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20189 /* xvssrln.hu.w */, LoongArch::XVSSRLN_HU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20202 /* xvssrln.w.d */, LoongArch::XVSSRLN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20214 /* xvssrln.wu.d */, LoongArch::XVSSRLN_WU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20227 /* xvssrlni.b.h */, LoongArch::XVSSRLNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 20240 /* xvssrlni.bu.h */, LoongArch::XVSSRLNI_BU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 20254 /* xvssrlni.d.q */, LoongArch::XVSSRLNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 20267 /* xvssrlni.du.q */, LoongArch::XVSSRLNI_DU_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 20281 /* xvssrlni.h.w */, LoongArch::XVSSRLNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20294 /* xvssrlni.hu.w */, LoongArch::XVSSRLNI_HU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20308 /* xvssrlni.w.d */, LoongArch::XVSSRLNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 20321 /* xvssrlni.wu.d */, LoongArch::XVSSRLNI_WU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 20335 /* xvssrlrn.b.h */, LoongArch::XVSSRLRN_B_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20348 /* xvssrlrn.bu.h */, LoongArch::XVSSRLRN_BU_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20362 /* xvssrlrn.h.w */, LoongArch::XVSSRLRN_H_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20375 /* xvssrlrn.hu.w */, LoongArch::XVSSRLRN_HU_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20389 /* xvssrlrn.w.d */, LoongArch::XVSSRLRN_W_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20402 /* xvssrlrn.wu.d */, LoongArch::XVSSRLRN_WU_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20416 /* xvssrlrni.b.h */, LoongArch::XVSSRLRNI_B_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 20430 /* xvssrlrni.bu.h */, LoongArch::XVSSRLRNI_BU_H, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm41_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm4 }, },
  { 20445 /* xvssrlrni.d.q */, LoongArch::XVSSRLRNI_D_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 20459 /* xvssrlrni.du.q */, LoongArch::XVSSRLRNI_DU_Q, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm7 }, },
  { 20474 /* xvssrlrni.h.w */, LoongArch::XVSSRLRNI_H_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20488 /* xvssrlrni.hu.w */, LoongArch::XVSSRLRNI_HU_W, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20503 /* xvssrlrni.w.d */, LoongArch::XVSSRLRNI_W_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 20517 /* xvssrlrni.wu.d */, LoongArch::XVSSRLRNI_WU_D, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm61_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm6 }, },
  { 20532 /* xvssub.b */, LoongArch::XVSSUB_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20541 /* xvssub.bu */, LoongArch::XVSSUB_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20551 /* xvssub.d */, LoongArch::XVSSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20560 /* xvssub.du */, LoongArch::XVSSUB_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20570 /* xvssub.h */, LoongArch::XVSSUB_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20579 /* xvssub.hu */, LoongArch::XVSSUB_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20589 /* xvssub.w */, LoongArch::XVSSUB_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20598 /* xvssub.wu */, LoongArch::XVSSUB_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20608 /* xvst */, LoongArch::XVST, Convert__Reg1_0__Reg1_1__SImm12addlike1_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm12addlike }, },
  { 20613 /* xvstelm.b */, LoongArch::XVSTELM_B, Convert__Reg1_0__Reg1_1__SImm81_2__UImm51_3, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm8, MCK_UImm5 }, },
  { 20623 /* xvstelm.d */, LoongArch::XVSTELM_D, Convert__Reg1_0__Reg1_1__SImm8lsl31_2__UImm21_3, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm8lsl3, MCK_UImm2 }, },
  { 20633 /* xvstelm.h */, LoongArch::XVSTELM_H, Convert__Reg1_0__Reg1_1__SImm8lsl11_2__UImm41_3, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm8lsl1, MCK_UImm4 }, },
  { 20643 /* xvstelm.w */, LoongArch::XVSTELM_W, Convert__Reg1_0__Reg1_1__SImm8lsl21_2__UImm31_3, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_SImm8lsl2, MCK_UImm3 }, },
  { 20653 /* xvstx */, LoongArch::XVSTX, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_GPR, MCK_GPR }, },
  { 20659 /* xvsub.b */, LoongArch::XVSUB_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20667 /* xvsub.d */, LoongArch::XVSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20675 /* xvsub.h */, LoongArch::XVSUB_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20683 /* xvsub.q */, LoongArch::XVSUB_Q, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20691 /* xvsub.w */, LoongArch::XVSUB_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20699 /* xvsubi.bu */, LoongArch::XVSUBI_BU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20709 /* xvsubi.du */, LoongArch::XVSUBI_DU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20719 /* xvsubi.hu */, LoongArch::XVSUBI_HU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20729 /* xvsubi.wu */, LoongArch::XVSUBI_WU, Convert__Reg1_0__Reg1_1__UImm51_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm5 }, },
  { 20739 /* xvsubwev.d.w */, LoongArch::XVSUBWEV_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20752 /* xvsubwev.d.wu */, LoongArch::XVSUBWEV_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20766 /* xvsubwev.h.b */, LoongArch::XVSUBWEV_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20779 /* xvsubwev.h.bu */, LoongArch::XVSUBWEV_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20793 /* xvsubwev.q.d */, LoongArch::XVSUBWEV_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20806 /* xvsubwev.q.du */, LoongArch::XVSUBWEV_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20820 /* xvsubwev.w.h */, LoongArch::XVSUBWEV_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20833 /* xvsubwev.w.hu */, LoongArch::XVSUBWEV_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20847 /* xvsubwod.d.w */, LoongArch::XVSUBWOD_D_W, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20860 /* xvsubwod.d.wu */, LoongArch::XVSUBWOD_D_WU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20874 /* xvsubwod.h.b */, LoongArch::XVSUBWOD_H_B, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20887 /* xvsubwod.h.bu */, LoongArch::XVSUBWOD_H_BU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20901 /* xvsubwod.q.d */, LoongArch::XVSUBWOD_Q_D, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20914 /* xvsubwod.q.du */, LoongArch::XVSUBWOD_Q_DU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20928 /* xvsubwod.w.h */, LoongArch::XVSUBWOD_W_H, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20941 /* xvsubwod.w.hu */, LoongArch::XVSUBWOD_W_HU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20955 /* xvxor.v */, LoongArch::XVXOR_V, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_LASX256 }, },
  { 20963 /* xvxori.b */, LoongArch::XVXORI_B, Convert__Reg1_0__Reg1_1__UImm81_2, AMFBS_None, { MCK_LASX256, MCK_LASX256, MCK_UImm8 }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned LoongArchAsmParser::
MatchInstructionImpl(const OperandVector &Operands,
                     MCInst &Inst,
                     uint64_t &ErrorInfo,
                     FeatureBitset &MissingFeatures,
                     bool matchingInlineAsm, unsigned VariantID) {
  // Eliminate obvious mismatches.
  if (Operands.size() > 5) {
    ErrorInfo = 5;
    return Match_InvalidOperand;
  }

  // Get the current feature set.
  const FeatureBitset &AvailableFeatures = getAvailableFeatures();

  // Get the instruction mnemonic, which is the first token.
  StringRef Mnemonic = ((LoongArchOperand &)*Operands[0]).getToken();

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
    for (unsigned FormalIdx = 0; FormalIdx != 4; ++FormalIdx) {
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

static const OperandMatchEntry OperandMatchTable[90] = {
  /* Operand List Mnemonic, Mask, Operand Class, Features */
  { 24 /* add.d */, 8 /* 3 */, MCK_TPRelAddSymbol, AMFBS_IsLA64 },
  { 30 /* add.w */, 8 /* 3 */, MCK_TPRelAddSymbol, AMFBS_IsLA32 },
  { 102 /* amadd.b */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 110 /* amadd.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 118 /* amadd.h */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 126 /* amadd.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 134 /* amadd_db.b */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 145 /* amadd_db.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 156 /* amadd_db.h */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 167 /* amadd_db.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 178 /* amand.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 186 /* amand.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 194 /* amand_db.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 205 /* amand_db.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 216 /* amcas.b */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 224 /* amcas.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 232 /* amcas.h */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 240 /* amcas.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 248 /* amcas_db.b */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 259 /* amcas_db.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 270 /* amcas_db.h */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 281 /* amcas_db.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 292 /* ammax.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 300 /* ammax.du */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 309 /* ammax.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 317 /* ammax.wu */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 326 /* ammax_db.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 337 /* ammax_db.du */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 349 /* ammax_db.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 360 /* ammax_db.wu */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 372 /* ammin.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 380 /* ammin.du */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 389 /* ammin.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 397 /* ammin.wu */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 406 /* ammin_db.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 417 /* ammin_db.du */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 429 /* ammin_db.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 440 /* ammin_db.wu */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 452 /* amor.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 459 /* amor.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 466 /* amor_db.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 476 /* amor_db.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 486 /* amswap.b */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 495 /* amswap.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 504 /* amswap.h */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 513 /* amswap.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 522 /* amswap_db.b */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 534 /* amswap_db.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 546 /* amswap_db.h */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 558 /* amswap_db.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 570 /* amxor.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 578 /* amxor.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 586 /* amxor_db.d */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 597 /* amxor_db.w */, 4 /* 2 */, MCK_AtomicMemAsmOperand, AMFBS_IsLA64 },
  { 844 /* b */, 1 /* 0 */, MCK_SImm26OperandB, AMFBS_None },
  { 933 /* bl */, 1 /* 0 */, MCK_SImm26OperandBL, AMFBS_None },
  { 1049 /* call */, 1 /* 0 */, MCK_BareSymbol, AMFBS_None },
  { 1054 /* call30 */, 1 /* 0 */, MCK_BareSymbol, AMFBS_None },
  { 1061 /* call36 */, 1 /* 0 */, MCK_BareSymbol, AMFBS_IsLA64 },
  { 2798 /* la */, 2 /* 1 */, MCK_BareSymbol, AMFBS_HasLaGlobalWithPcrel },
  { 2798 /* la */, 2 /* 1 */, MCK_BareSymbol, AMFBS_HasLaGlobalWithAbs },
  { 2798 /* la */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2801 /* la.abs */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2801 /* la.abs */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2808 /* la.global */, 2 /* 1 */, MCK_BareSymbol, AMFBS_HasLaGlobalWithPcrel },
  { 2808 /* la.global */, 2 /* 1 */, MCK_BareSymbol, AMFBS_HasLaGlobalWithAbs },
  { 2808 /* la.global */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2808 /* la.global */, 4 /* 2 */, MCK_BareSymbol, AMFBS_HasLaGlobalWithPcrel },
  { 2808 /* la.global */, 4 /* 2 */, MCK_BareSymbol, AMFBS_HasLaGlobalWithAbs },
  { 2808 /* la.global */, 4 /* 2 */, MCK_BareSymbol, AMFBS_None },
  { 2818 /* la.got */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2818 /* la.got */, 4 /* 2 */, MCK_BareSymbol, AMFBS_IsLA64 },
  { 2825 /* la.local */, 2 /* 1 */, MCK_BareSymbol, AMFBS_HasLaLocalWithAbs },
  { 2825 /* la.local */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2825 /* la.local */, 4 /* 2 */, MCK_BareSymbol, AMFBS_HasLaLocalWithAbs },
  { 2825 /* la.local */, 4 /* 2 */, MCK_BareSymbol, AMFBS_None },
  { 2834 /* la.pcrel */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2834 /* la.pcrel */, 4 /* 2 */, MCK_BareSymbol, AMFBS_IsLA64 },
  { 2843 /* la.tls.desc */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2843 /* la.tls.desc */, 4 /* 2 */, MCK_BareSymbol, AMFBS_IsLA64 },
  { 2855 /* la.tls.gd */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2855 /* la.tls.gd */, 4 /* 2 */, MCK_BareSymbol, AMFBS_IsLA64 },
  { 2865 /* la.tls.ie */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2865 /* la.tls.ie */, 4 /* 2 */, MCK_BareSymbol, AMFBS_IsLA64 },
  { 2875 /* la.tls.ld */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 2875 /* la.tls.ld */, 4 /* 2 */, MCK_BareSymbol, AMFBS_IsLA64 },
  { 2885 /* la.tls.le */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 4044 /* tail */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 4049 /* tail30 */, 2 /* 1 */, MCK_BareSymbol, AMFBS_None },
  { 4056 /* tail36 */, 2 /* 1 */, MCK_BareSymbol, AMFBS_IsLA64 },
};

ParseStatus LoongArchAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_AtomicMemAsmOperand:
    return parseAtomicMemOp(Operands);
  case MCK_BareSymbol:
    return parseImmediate(Operands);
  case MCK_SImm26OperandB:
    return parseImmediate(Operands);
  case MCK_SImm26OperandBL:
    return parseSImm26Operand(Operands);
  case MCK_TPRelAddSymbol:
    return parseOperandWithModifier(Operands);
  default:
    return ParseStatus::NoMatch;
  }
  return ParseStatus::NoMatch;
}

ParseStatus LoongArchAsmParser::
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

static std::string LoongArchMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool LoongArchCheckMnemonic(StringRef Mnemonic,
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

