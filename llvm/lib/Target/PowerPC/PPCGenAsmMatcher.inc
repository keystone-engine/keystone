/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: PPC.td                                                               *|
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
  Feature_ModernAsBit = 0,
};

static MCRegister MatchRegisterName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 12 strings to match.
    switch (Name[0]) {
    default: break;
    case '0':	 // 3 strings to match.
      return PPC::ZERO;	 // "0"
    case '1':	 // 1 string to match.
      return PPC::CR0GT;	 // "1"
    case '2':	 // 1 string to match.
      return PPC::CR0EQ;	 // "2"
    case '3':	 // 1 string to match.
      return PPC::CR0UN;	 // "3"
    case '4':	 // 1 string to match.
      return PPC::CR1LT;	 // "4"
    case '5':	 // 1 string to match.
      return PPC::CR1GT;	 // "5"
    case '6':	 // 1 string to match.
      return PPC::CR1EQ;	 // "6"
    case '7':	 // 1 string to match.
      return PPC::CR1UN;	 // "7"
    case '8':	 // 1 string to match.
      return PPC::CR2LT;	 // "8"
    case '9':	 // 1 string to match.
      return PPC::CR2GT;	 // "9"
    }
    break;
  case 2:	 // 89 strings to match.
    switch (Name[0]) {
    default: break;
    case '1':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::CR2EQ;	 // "10"
      case '1':	 // 1 string to match.
        return PPC::CR2UN;	 // "11"
      case '2':	 // 1 string to match.
        return PPC::CR3LT;	 // "12"
      case '3':	 // 1 string to match.
        return PPC::CR3GT;	 // "13"
      case '4':	 // 1 string to match.
        return PPC::CR3EQ;	 // "14"
      case '5':	 // 1 string to match.
        return PPC::CR3UN;	 // "15"
      case '6':	 // 1 string to match.
        return PPC::CR4LT;	 // "16"
      case '7':	 // 1 string to match.
        return PPC::CR4GT;	 // "17"
      case '8':	 // 1 string to match.
        return PPC::CR4EQ;	 // "18"
      case '9':	 // 1 string to match.
        return PPC::CR4UN;	 // "19"
      }
      break;
    case '2':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::CR5LT;	 // "20"
      case '1':	 // 1 string to match.
        return PPC::CR5GT;	 // "21"
      case '2':	 // 1 string to match.
        return PPC::CR5EQ;	 // "22"
      case '3':	 // 1 string to match.
        return PPC::CR5UN;	 // "23"
      case '4':	 // 1 string to match.
        return PPC::CR6LT;	 // "24"
      case '5':	 // 1 string to match.
        return PPC::CR6GT;	 // "25"
      case '6':	 // 1 string to match.
        return PPC::CR6EQ;	 // "26"
      case '7':	 // 1 string to match.
        return PPC::CR6UN;	 // "27"
      case '8':	 // 1 string to match.
        return PPC::CR7LT;	 // "28"
      case '9':	 // 1 string to match.
        return PPC::CR7GT;	 // "29"
      }
      break;
    case '3':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::CR7EQ;	 // "30"
      case '1':	 // 1 string to match.
        return PPC::CR7UN;	 // "31"
      }
      break;
    case 'f':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::F0;	 // "f0"
      case '1':	 // 1 string to match.
        return PPC::F1;	 // "f1"
      case '2':	 // 1 string to match.
        return PPC::F2;	 // "f2"
      case '3':	 // 1 string to match.
        return PPC::F3;	 // "f3"
      case '4':	 // 1 string to match.
        return PPC::F4;	 // "f4"
      case '5':	 // 1 string to match.
        return PPC::F5;	 // "f5"
      case '6':	 // 1 string to match.
        return PPC::F6;	 // "f6"
      case '7':	 // 1 string to match.
        return PPC::F7;	 // "f7"
      case '8':	 // 1 string to match.
        return PPC::F8;	 // "f8"
      case '9':	 // 1 string to match.
        return PPC::F9;	 // "f9"
      }
      break;
    case 'l':	 // 2 strings to match.
      if (Name[1] != 'r')
        break;
      return PPC::LR;	 // "lr"
    case 'r':	 // 35 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 4 strings to match.
        return PPC::R0;	 // "r0"
      case '1':	 // 3 strings to match.
        return PPC::R1;	 // "r1"
      case '2':	 // 4 strings to match.
        return PPC::R2;	 // "r2"
      case '3':	 // 3 strings to match.
        return PPC::R3;	 // "r3"
      case '4':	 // 4 strings to match.
        return PPC::R4;	 // "r4"
      case '5':	 // 3 strings to match.
        return PPC::R5;	 // "r5"
      case '6':	 // 4 strings to match.
        return PPC::R6;	 // "r6"
      case '7':	 // 3 strings to match.
        return PPC::R7;	 // "r7"
      case '8':	 // 4 strings to match.
        return PPC::R8;	 // "r8"
      case '9':	 // 3 strings to match.
        return PPC::R9;	 // "r9"
      }
      break;
    case 'v':	 // 20 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return PPC::V0;	 // "v0"
      case '1':	 // 2 strings to match.
        return PPC::V1;	 // "v1"
      case '2':	 // 2 strings to match.
        return PPC::V2;	 // "v2"
      case '3':	 // 2 strings to match.
        return PPC::V3;	 // "v3"
      case '4':	 // 2 strings to match.
        return PPC::V4;	 // "v4"
      case '5':	 // 2 strings to match.
        return PPC::V5;	 // "v5"
      case '6':	 // 2 strings to match.
        return PPC::V6;	 // "v6"
      case '7':	 // 2 strings to match.
        return PPC::V7;	 // "v7"
      case '8':	 // 2 strings to match.
        return PPC::V8;	 // "v8"
      case '9':	 // 2 strings to match.
        return PPC::V9;	 // "v9"
      }
      break;
    }
    break;
  case 3:	 // 170 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case 'r':	 // 8 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::CR0;	 // "cr0"
        case '1':	 // 1 string to match.
          return PPC::CR1;	 // "cr1"
        case '2':	 // 1 string to match.
          return PPC::CR2;	 // "cr2"
        case '3':	 // 1 string to match.
          return PPC::CR3;	 // "cr3"
        case '4':	 // 1 string to match.
          return PPC::CR4;	 // "cr4"
        case '5':	 // 1 string to match.
          return PPC::CR5;	 // "cr5"
        case '6':	 // 1 string to match.
          return PPC::CR6;	 // "cr6"
        case '7':	 // 1 string to match.
          return PPC::CR7;	 // "cr7"
        }
        break;
      case 't':	 // 2 strings to match.
        if (Name[2] != 'r')
          break;
        return PPC::CTR;	 // "ctr"
      }
      break;
    case 'f':	 // 27 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::F10;	 // "f10"
        case '1':	 // 1 string to match.
          return PPC::F11;	 // "f11"
        case '2':	 // 1 string to match.
          return PPC::F12;	 // "f12"
        case '3':	 // 1 string to match.
          return PPC::F13;	 // "f13"
        case '4':	 // 1 string to match.
          return PPC::F14;	 // "f14"
        case '5':	 // 1 string to match.
          return PPC::F15;	 // "f15"
        case '6':	 // 1 string to match.
          return PPC::F16;	 // "f16"
        case '7':	 // 1 string to match.
          return PPC::F17;	 // "f17"
        case '8':	 // 1 string to match.
          return PPC::F18;	 // "f18"
        case '9':	 // 1 string to match.
          return PPC::F19;	 // "f19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::F20;	 // "f20"
        case '1':	 // 1 string to match.
          return PPC::F21;	 // "f21"
        case '2':	 // 1 string to match.
          return PPC::F22;	 // "f22"
        case '3':	 // 1 string to match.
          return PPC::F23;	 // "f23"
        case '4':	 // 1 string to match.
          return PPC::F24;	 // "f24"
        case '5':	 // 1 string to match.
          return PPC::F25;	 // "f25"
        case '6':	 // 1 string to match.
          return PPC::F26;	 // "f26"
        case '7':	 // 1 string to match.
          return PPC::F27;	 // "f27"
        case '8':	 // 1 string to match.
          return PPC::F28;	 // "f28"
        case '9':	 // 1 string to match.
          return PPC::F29;	 // "f29"
        }
        break;
      case '3':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::F30;	 // "f30"
        case '1':	 // 1 string to match.
          return PPC::F31;	 // "f31"
        }
        break;
      case 'p':	 // 5 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::Fpair0;	 // "fp0"
        case '2':	 // 1 string to match.
          return PPC::Fpair2;	 // "fp2"
        case '4':	 // 1 string to match.
          return PPC::Fpair4;	 // "fp4"
        case '6':	 // 1 string to match.
          return PPC::Fpair6;	 // "fp6"
        case '8':	 // 1 string to match.
          return PPC::Fpair8;	 // "fp8"
        }
        break;
      }
      break;
    case 'r':	 // 77 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 35 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 4 strings to match.
          return PPC::R10;	 // "r10"
        case '1':	 // 3 strings to match.
          return PPC::R11;	 // "r11"
        case '2':	 // 4 strings to match.
          return PPC::R12;	 // "r12"
        case '3':	 // 3 strings to match.
          return PPC::R13;	 // "r13"
        case '4':	 // 4 strings to match.
          return PPC::R14;	 // "r14"
        case '5':	 // 3 strings to match.
          return PPC::R15;	 // "r15"
        case '6':	 // 4 strings to match.
          return PPC::R16;	 // "r16"
        case '7':	 // 3 strings to match.
          return PPC::R17;	 // "r17"
        case '8':	 // 4 strings to match.
          return PPC::R18;	 // "r18"
        case '9':	 // 3 strings to match.
          return PPC::R19;	 // "r19"
        }
        break;
      case '2':	 // 35 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 4 strings to match.
          return PPC::R20;	 // "r20"
        case '1':	 // 3 strings to match.
          return PPC::R21;	 // "r21"
        case '2':	 // 4 strings to match.
          return PPC::R22;	 // "r22"
        case '3':	 // 3 strings to match.
          return PPC::R23;	 // "r23"
        case '4':	 // 4 strings to match.
          return PPC::R24;	 // "r24"
        case '5':	 // 3 strings to match.
          return PPC::R25;	 // "r25"
        case '6':	 // 4 strings to match.
          return PPC::R26;	 // "r26"
        case '7':	 // 3 strings to match.
          return PPC::R27;	 // "r27"
        case '8':	 // 4 strings to match.
          return PPC::R28;	 // "r28"
        case '9':	 // 3 strings to match.
          return PPC::R29;	 // "r29"
        }
        break;
      case '3':	 // 7 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 4 strings to match.
          return PPC::R30;	 // "r30"
        case '1':	 // 3 strings to match.
          return PPC::R31;	 // "r31"
        }
        break;
      }
      break;
    case 'v':	 // 54 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return PPC::V10;	 // "v10"
        case '1':	 // 2 strings to match.
          return PPC::V11;	 // "v11"
        case '2':	 // 2 strings to match.
          return PPC::V12;	 // "v12"
        case '3':	 // 2 strings to match.
          return PPC::V13;	 // "v13"
        case '4':	 // 2 strings to match.
          return PPC::V14;	 // "v14"
        case '5':	 // 2 strings to match.
          return PPC::V15;	 // "v15"
        case '6':	 // 2 strings to match.
          return PPC::V16;	 // "v16"
        case '7':	 // 2 strings to match.
          return PPC::V17;	 // "v17"
        case '8':	 // 2 strings to match.
          return PPC::V18;	 // "v18"
        case '9':	 // 2 strings to match.
          return PPC::V19;	 // "v19"
        }
        break;
      case '2':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return PPC::V20;	 // "v20"
        case '1':	 // 2 strings to match.
          return PPC::V21;	 // "v21"
        case '2':	 // 2 strings to match.
          return PPC::V22;	 // "v22"
        case '3':	 // 2 strings to match.
          return PPC::V23;	 // "v23"
        case '4':	 // 2 strings to match.
          return PPC::V24;	 // "v24"
        case '5':	 // 2 strings to match.
          return PPC::V25;	 // "v25"
        case '6':	 // 2 strings to match.
          return PPC::V26;	 // "v26"
        case '7':	 // 2 strings to match.
          return PPC::V27;	 // "v27"
        case '8':	 // 2 strings to match.
          return PPC::V28;	 // "v28"
        case '9':	 // 2 strings to match.
          return PPC::V29;	 // "v29"
        }
        break;
      case '3':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return PPC::V30;	 // "v30"
        case '1':	 // 2 strings to match.
          return PPC::V31;	 // "v31"
        }
        break;
      case 's':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSL0;	 // "vs0"
        case '1':	 // 1 string to match.
          return PPC::VSL1;	 // "vs1"
        case '2':	 // 1 string to match.
          return PPC::VSL2;	 // "vs2"
        case '3':	 // 1 string to match.
          return PPC::VSL3;	 // "vs3"
        case '4':	 // 1 string to match.
          return PPC::VSL4;	 // "vs4"
        case '5':	 // 1 string to match.
          return PPC::VSL5;	 // "vs5"
        case '6':	 // 1 string to match.
          return PPC::VSL6;	 // "vs6"
        case '7':	 // 1 string to match.
          return PPC::VSL7;	 // "vs7"
        case '8':	 // 1 string to match.
          return PPC::VSL8;	 // "vs8"
        case '9':	 // 1 string to match.
          return PPC::VSL9;	 // "vs9"
        }
        break;
      }
      break;
    case 'x':	 // 2 strings to match.
      if (memcmp(Name.data()+1, "er", 2) != 0)
        break;
      return PPC::CARRY;	 // "xer"
    }
    break;
  case 4:	 // 94 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 16 strings to match.
      if (memcmp(Name.data()+1, "cc", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 2 strings to match.
        return PPC::ACC0;	 // "acc0"
      case '1':	 // 2 strings to match.
        return PPC::ACC1;	 // "acc1"
      case '2':	 // 2 strings to match.
        return PPC::ACC2;	 // "acc2"
      case '3':	 // 2 strings to match.
        return PPC::ACC3;	 // "acc3"
      case '4':	 // 2 strings to match.
        return PPC::ACC4;	 // "acc4"
      case '5':	 // 2 strings to match.
        return PPC::ACC5;	 // "acc5"
      case '6':	 // 2 strings to match.
        return PPC::ACC6;	 // "acc6"
      case '7':	 // 2 strings to match.
        return PPC::ACC7;	 // "acc7"
      }
      break;
    case 'd':	 // 8 strings to match.
      if (memcmp(Name.data()+1, "mr", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::DMR0;	 // "dmr0"
      case '1':	 // 1 string to match.
        return PPC::DMR1;	 // "dmr1"
      case '2':	 // 1 string to match.
        return PPC::DMR2;	 // "dmr2"
      case '3':	 // 1 string to match.
        return PPC::DMR3;	 // "dmr3"
      case '4':	 // 1 string to match.
        return PPC::DMR4;	 // "dmr4"
      case '5':	 // 1 string to match.
        return PPC::DMR5;	 // "dmr5"
      case '6':	 // 1 string to match.
        return PPC::DMR6;	 // "dmr6"
      case '7':	 // 1 string to match.
        return PPC::DMR7;	 // "dmr7"
      }
      break;
    case 'f':	 // 11 strings to match.
      if (Name[1] != 'p')
        break;
      switch (Name[2]) {
      default: break;
      case '1':	 // 5 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::Fpair10;	 // "fp10"
        case '2':	 // 1 string to match.
          return PPC::Fpair12;	 // "fp12"
        case '4':	 // 1 string to match.
          return PPC::Fpair14;	 // "fp14"
        case '6':	 // 1 string to match.
          return PPC::Fpair16;	 // "fp16"
        case '8':	 // 1 string to match.
          return PPC::Fpair18;	 // "fp18"
        }
        break;
      case '2':	 // 5 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::Fpair20;	 // "fp20"
        case '2':	 // 1 string to match.
          return PPC::Fpair22;	 // "fp22"
        case '4':	 // 1 string to match.
          return PPC::Fpair24;	 // "fp24"
        case '6':	 // 1 string to match.
          return PPC::Fpair26;	 // "fp26"
        case '8':	 // 1 string to match.
          return PPC::Fpair28;	 // "fp28"
        }
        break;
      case '3':	 // 1 string to match.
        if (Name[3] != '0')
          break;
        return PPC::Fpair30;	 // "fp30"
      }
      break;
    case 'v':	 // 59 strings to match.
      if (Name[1] != 's')
        break;
      switch (Name[2]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSL10;	 // "vs10"
        case '1':	 // 1 string to match.
          return PPC::VSL11;	 // "vs11"
        case '2':	 // 1 string to match.
          return PPC::VSL12;	 // "vs12"
        case '3':	 // 1 string to match.
          return PPC::VSL13;	 // "vs13"
        case '4':	 // 1 string to match.
          return PPC::VSL14;	 // "vs14"
        case '5':	 // 1 string to match.
          return PPC::VSL15;	 // "vs15"
        case '6':	 // 1 string to match.
          return PPC::VSL16;	 // "vs16"
        case '7':	 // 1 string to match.
          return PPC::VSL17;	 // "vs17"
        case '8':	 // 1 string to match.
          return PPC::VSL18;	 // "vs18"
        case '9':	 // 1 string to match.
          return PPC::VSL19;	 // "vs19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSL20;	 // "vs20"
        case '1':	 // 1 string to match.
          return PPC::VSL21;	 // "vs21"
        case '2':	 // 1 string to match.
          return PPC::VSL22;	 // "vs22"
        case '3':	 // 1 string to match.
          return PPC::VSL23;	 // "vs23"
        case '4':	 // 1 string to match.
          return PPC::VSL24;	 // "vs24"
        case '5':	 // 1 string to match.
          return PPC::VSL25;	 // "vs25"
        case '6':	 // 1 string to match.
          return PPC::VSL26;	 // "vs26"
        case '7':	 // 1 string to match.
          return PPC::VSL27;	 // "vs27"
        case '8':	 // 1 string to match.
          return PPC::VSL28;	 // "vs28"
        case '9':	 // 1 string to match.
          return PPC::VSL29;	 // "vs29"
        }
        break;
      case '3':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSL30;	 // "vs30"
        case '1':	 // 1 string to match.
          return PPC::VSL31;	 // "vs31"
        case '2':	 // 1 string to match.
          return PPC::VSX32;	 // "vs32"
        case '3':	 // 1 string to match.
          return PPC::VSX33;	 // "vs33"
        case '4':	 // 1 string to match.
          return PPC::VSX34;	 // "vs34"
        case '5':	 // 1 string to match.
          return PPC::VSX35;	 // "vs35"
        case '6':	 // 1 string to match.
          return PPC::VSX36;	 // "vs36"
        case '7':	 // 1 string to match.
          return PPC::VSX37;	 // "vs37"
        case '8':	 // 1 string to match.
          return PPC::VSX38;	 // "vs38"
        case '9':	 // 1 string to match.
          return PPC::VSX39;	 // "vs39"
        }
        break;
      case '4':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSX40;	 // "vs40"
        case '1':	 // 1 string to match.
          return PPC::VSX41;	 // "vs41"
        case '2':	 // 1 string to match.
          return PPC::VSX42;	 // "vs42"
        case '3':	 // 1 string to match.
          return PPC::VSX43;	 // "vs43"
        case '4':	 // 1 string to match.
          return PPC::VSX44;	 // "vs44"
        case '5':	 // 1 string to match.
          return PPC::VSX45;	 // "vs45"
        case '6':	 // 1 string to match.
          return PPC::VSX46;	 // "vs46"
        case '7':	 // 1 string to match.
          return PPC::VSX47;	 // "vs47"
        case '8':	 // 1 string to match.
          return PPC::VSX48;	 // "vs48"
        case '9':	 // 1 string to match.
          return PPC::VSX49;	 // "vs49"
        }
        break;
      case '5':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSX50;	 // "vs50"
        case '1':	 // 1 string to match.
          return PPC::VSX51;	 // "vs51"
        case '2':	 // 1 string to match.
          return PPC::VSX52;	 // "vs52"
        case '3':	 // 1 string to match.
          return PPC::VSX53;	 // "vs53"
        case '4':	 // 1 string to match.
          return PPC::VSX54;	 // "vs54"
        case '5':	 // 1 string to match.
          return PPC::VSX55;	 // "vs55"
        case '6':	 // 1 string to match.
          return PPC::VSX56;	 // "vs56"
        case '7':	 // 1 string to match.
          return PPC::VSX57;	 // "vs57"
        case '8':	 // 1 string to match.
          return PPC::VSX58;	 // "vs58"
        case '9':	 // 1 string to match.
          return PPC::VSX59;	 // "vs59"
        }
        break;
      case '6':	 // 4 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSX60;	 // "vs60"
        case '1':	 // 1 string to match.
          return PPC::VSX61;	 // "vs61"
        case '2':	 // 1 string to match.
          return PPC::VSX62;	 // "vs62"
        case '3':	 // 1 string to match.
          return PPC::VSX63;	 // "vs63"
        }
        break;
      case 'p':	 // 5 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSRp0;	 // "vsp0"
        case '2':	 // 1 string to match.
          return PPC::VSRp1;	 // "vsp2"
        case '4':	 // 1 string to match.
          return PPC::VSRp2;	 // "vsp4"
        case '6':	 // 1 string to match.
          return PPC::VSRp3;	 // "vsp6"
        case '8':	 // 1 string to match.
          return PPC::VSRp4;	 // "vsp8"
        }
        break;
      }
      break;
    }
    break;
  case 5:	 // 39 strings to match.
    switch (Name[0]) {
    default: break;
    case 'd':	 // 4 strings to match.
      if (memcmp(Name.data()+1, "mrp", 3) != 0)
        break;
      switch (Name[4]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::DMRp0;	 // "dmrp0"
      case '1':	 // 1 string to match.
        return PPC::DMRp1;	 // "dmrp1"
      case '2':	 // 1 string to match.
        return PPC::DMRp2;	 // "dmrp2"
      case '3':	 // 1 string to match.
        return PPC::DMRp3;	 // "dmrp3"
      }
      break;
    case 'v':	 // 27 strings to match.
      if (memcmp(Name.data()+1, "sp", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case '1':	 // 5 strings to match.
        switch (Name[4]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSRp5;	 // "vsp10"
        case '2':	 // 1 string to match.
          return PPC::VSRp6;	 // "vsp12"
        case '4':	 // 1 string to match.
          return PPC::VSRp7;	 // "vsp14"
        case '6':	 // 1 string to match.
          return PPC::VSRp8;	 // "vsp16"
        case '8':	 // 1 string to match.
          return PPC::VSRp9;	 // "vsp18"
        }
        break;
      case '2':	 // 5 strings to match.
        switch (Name[4]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSRp10;	 // "vsp20"
        case '2':	 // 1 string to match.
          return PPC::VSRp11;	 // "vsp22"
        case '4':	 // 1 string to match.
          return PPC::VSRp12;	 // "vsp24"
        case '6':	 // 1 string to match.
          return PPC::VSRp13;	 // "vsp26"
        case '8':	 // 1 string to match.
          return PPC::VSRp14;	 // "vsp28"
        }
        break;
      case '3':	 // 5 strings to match.
        switch (Name[4]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSRp15;	 // "vsp30"
        case '2':	 // 1 string to match.
          return PPC::VSRp16;	 // "vsp32"
        case '4':	 // 1 string to match.
          return PPC::VSRp17;	 // "vsp34"
        case '6':	 // 1 string to match.
          return PPC::VSRp18;	 // "vsp36"
        case '8':	 // 1 string to match.
          return PPC::VSRp19;	 // "vsp38"
        }
        break;
      case '4':	 // 5 strings to match.
        switch (Name[4]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSRp20;	 // "vsp40"
        case '2':	 // 1 string to match.
          return PPC::VSRp21;	 // "vsp42"
        case '4':	 // 1 string to match.
          return PPC::VSRp22;	 // "vsp44"
        case '6':	 // 1 string to match.
          return PPC::VSRp23;	 // "vsp46"
        case '8':	 // 1 string to match.
          return PPC::VSRp24;	 // "vsp48"
        }
        break;
      case '5':	 // 5 strings to match.
        switch (Name[4]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSRp25;	 // "vsp50"
        case '2':	 // 1 string to match.
          return PPC::VSRp26;	 // "vsp52"
        case '4':	 // 1 string to match.
          return PPC::VSRp27;	 // "vsp54"
        case '6':	 // 1 string to match.
          return PPC::VSRp28;	 // "vsp56"
        case '8':	 // 1 string to match.
          return PPC::VSRp29;	 // "vsp58"
        }
        break;
      case '6':	 // 2 strings to match.
        switch (Name[4]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::VSRp30;	 // "vsp60"
        case '2':	 // 1 string to match.
          return PPC::VSRp31;	 // "vsp62"
        }
        break;
      }
      break;
    case 'w':	 // 8 strings to match.
      if (memcmp(Name.data()+1, "acc", 3) != 0)
        break;
      switch (Name[4]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::WACC0;	 // "wacc0"
      case '1':	 // 1 string to match.
        return PPC::WACC1;	 // "wacc1"
      case '2':	 // 1 string to match.
        return PPC::WACC2;	 // "wacc2"
      case '3':	 // 1 string to match.
        return PPC::WACC3;	 // "wacc3"
      case '4':	 // 1 string to match.
        return PPC::WACC4;	 // "wacc4"
      case '5':	 // 1 string to match.
        return PPC::WACC5;	 // "wacc5"
      case '6':	 // 1 string to match.
        return PPC::WACC6;	 // "wacc6"
      case '7':	 // 1 string to match.
        return PPC::WACC7;	 // "wacc7"
      }
      break;
    }
    break;
  case 6:	 // 1 string to match.
    if (memcmp(Name.data()+0, "vrsave", 6) != 0)
      break;
    return PPC::VRSAVE;	 // "vrsave"
  case 7:	 // 11 strings to match.
    switch (Name[0]) {
    default: break;
    case 'd':	 // 10 strings to match.
      if (memcmp(Name.data()+1, "mrrow", 5) != 0)
        break;
      switch (Name[6]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::DMRROW0;	 // "dmrrow0"
      case '1':	 // 1 string to match.
        return PPC::DMRROW1;	 // "dmrrow1"
      case '2':	 // 1 string to match.
        return PPC::DMRROW2;	 // "dmrrow2"
      case '3':	 // 1 string to match.
        return PPC::DMRROW3;	 // "dmrrow3"
      case '4':	 // 1 string to match.
        return PPC::DMRROW4;	 // "dmrrow4"
      case '5':	 // 1 string to match.
        return PPC::DMRROW5;	 // "dmrrow5"
      case '6':	 // 1 string to match.
        return PPC::DMRROW6;	 // "dmrrow6"
      case '7':	 // 1 string to match.
        return PPC::DMRROW7;	 // "dmrrow7"
      case '8':	 // 1 string to match.
        return PPC::DMRROW8;	 // "dmrrow8"
      case '9':	 // 1 string to match.
        return PPC::DMRROW9;	 // "dmrrow9"
      }
      break;
    case 's':	 // 1 string to match.
      if (memcmp(Name.data()+1, "pefscr", 6) != 0)
        break;
      return PPC::SPEFSCR;	 // "spefscr"
    }
    break;
  case 8:	 // 72 strings to match.
    switch (Name[0]) {
    default: break;
    case 'd':	 // 64 strings to match.
      if (memcmp(Name.data()+1, "mrrow", 5) != 0)
        break;
      switch (Name[6]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::DMRROW10;	 // "dmrrow10"
        case '1':	 // 1 string to match.
          return PPC::DMRROW11;	 // "dmrrow11"
        case '2':	 // 1 string to match.
          return PPC::DMRROW12;	 // "dmrrow12"
        case '3':	 // 1 string to match.
          return PPC::DMRROW13;	 // "dmrrow13"
        case '4':	 // 1 string to match.
          return PPC::DMRROW14;	 // "dmrrow14"
        case '5':	 // 1 string to match.
          return PPC::DMRROW15;	 // "dmrrow15"
        case '6':	 // 1 string to match.
          return PPC::DMRROW16;	 // "dmrrow16"
        case '7':	 // 1 string to match.
          return PPC::DMRROW17;	 // "dmrrow17"
        case '8':	 // 1 string to match.
          return PPC::DMRROW18;	 // "dmrrow18"
        case '9':	 // 1 string to match.
          return PPC::DMRROW19;	 // "dmrrow19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::DMRROW20;	 // "dmrrow20"
        case '1':	 // 1 string to match.
          return PPC::DMRROW21;	 // "dmrrow21"
        case '2':	 // 1 string to match.
          return PPC::DMRROW22;	 // "dmrrow22"
        case '3':	 // 1 string to match.
          return PPC::DMRROW23;	 // "dmrrow23"
        case '4':	 // 1 string to match.
          return PPC::DMRROW24;	 // "dmrrow24"
        case '5':	 // 1 string to match.
          return PPC::DMRROW25;	 // "dmrrow25"
        case '6':	 // 1 string to match.
          return PPC::DMRROW26;	 // "dmrrow26"
        case '7':	 // 1 string to match.
          return PPC::DMRROW27;	 // "dmrrow27"
        case '8':	 // 1 string to match.
          return PPC::DMRROW28;	 // "dmrrow28"
        case '9':	 // 1 string to match.
          return PPC::DMRROW29;	 // "dmrrow29"
        }
        break;
      case '3':	 // 10 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::DMRROW30;	 // "dmrrow30"
        case '1':	 // 1 string to match.
          return PPC::DMRROW31;	 // "dmrrow31"
        case '2':	 // 1 string to match.
          return PPC::DMRROW32;	 // "dmrrow32"
        case '3':	 // 1 string to match.
          return PPC::DMRROW33;	 // "dmrrow33"
        case '4':	 // 1 string to match.
          return PPC::DMRROW34;	 // "dmrrow34"
        case '5':	 // 1 string to match.
          return PPC::DMRROW35;	 // "dmrrow35"
        case '6':	 // 1 string to match.
          return PPC::DMRROW36;	 // "dmrrow36"
        case '7':	 // 1 string to match.
          return PPC::DMRROW37;	 // "dmrrow37"
        case '8':	 // 1 string to match.
          return PPC::DMRROW38;	 // "dmrrow38"
        case '9':	 // 1 string to match.
          return PPC::DMRROW39;	 // "dmrrow39"
        }
        break;
      case '4':	 // 10 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::DMRROW40;	 // "dmrrow40"
        case '1':	 // 1 string to match.
          return PPC::DMRROW41;	 // "dmrrow41"
        case '2':	 // 1 string to match.
          return PPC::DMRROW42;	 // "dmrrow42"
        case '3':	 // 1 string to match.
          return PPC::DMRROW43;	 // "dmrrow43"
        case '4':	 // 1 string to match.
          return PPC::DMRROW44;	 // "dmrrow44"
        case '5':	 // 1 string to match.
          return PPC::DMRROW45;	 // "dmrrow45"
        case '6':	 // 1 string to match.
          return PPC::DMRROW46;	 // "dmrrow46"
        case '7':	 // 1 string to match.
          return PPC::DMRROW47;	 // "dmrrow47"
        case '8':	 // 1 string to match.
          return PPC::DMRROW48;	 // "dmrrow48"
        case '9':	 // 1 string to match.
          return PPC::DMRROW49;	 // "dmrrow49"
        }
        break;
      case '5':	 // 10 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::DMRROW50;	 // "dmrrow50"
        case '1':	 // 1 string to match.
          return PPC::DMRROW51;	 // "dmrrow51"
        case '2':	 // 1 string to match.
          return PPC::DMRROW52;	 // "dmrrow52"
        case '3':	 // 1 string to match.
          return PPC::DMRROW53;	 // "dmrrow53"
        case '4':	 // 1 string to match.
          return PPC::DMRROW54;	 // "dmrrow54"
        case '5':	 // 1 string to match.
          return PPC::DMRROW55;	 // "dmrrow55"
        case '6':	 // 1 string to match.
          return PPC::DMRROW56;	 // "dmrrow56"
        case '7':	 // 1 string to match.
          return PPC::DMRROW57;	 // "dmrrow57"
        case '8':	 // 1 string to match.
          return PPC::DMRROW58;	 // "dmrrow58"
        case '9':	 // 1 string to match.
          return PPC::DMRROW59;	 // "dmrrow59"
        }
        break;
      case '6':	 // 4 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::DMRROW60;	 // "dmrrow60"
        case '1':	 // 1 string to match.
          return PPC::DMRROW61;	 // "dmrrow61"
        case '2':	 // 1 string to match.
          return PPC::DMRROW62;	 // "dmrrow62"
        case '3':	 // 1 string to match.
          return PPC::DMRROW63;	 // "dmrrow63"
        }
        break;
      case 'p':	 // 10 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return PPC::DMRROWp0;	 // "dmrrowp0"
        case '1':	 // 1 string to match.
          return PPC::DMRROWp1;	 // "dmrrowp1"
        case '2':	 // 1 string to match.
          return PPC::DMRROWp2;	 // "dmrrowp2"
        case '3':	 // 1 string to match.
          return PPC::DMRROWp3;	 // "dmrrowp3"
        case '4':	 // 1 string to match.
          return PPC::DMRROWp4;	 // "dmrrowp4"
        case '5':	 // 1 string to match.
          return PPC::DMRROWp5;	 // "dmrrowp5"
        case '6':	 // 1 string to match.
          return PPC::DMRROWp6;	 // "dmrrowp6"
        case '7':	 // 1 string to match.
          return PPC::DMRROWp7;	 // "dmrrowp7"
        case '8':	 // 1 string to match.
          return PPC::DMRROWp8;	 // "dmrrowp8"
        case '9':	 // 1 string to match.
          return PPC::DMRROWp9;	 // "dmrrowp9"
        }
        break;
      }
      break;
    case 'w':	 // 8 strings to match.
      if (memcmp(Name.data()+1, "acc_hi", 6) != 0)
        break;
      switch (Name[7]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::WACC_HI0;	 // "wacc_hi0"
      case '1':	 // 1 string to match.
        return PPC::WACC_HI1;	 // "wacc_hi1"
      case '2':	 // 1 string to match.
        return PPC::WACC_HI2;	 // "wacc_hi2"
      case '3':	 // 1 string to match.
        return PPC::WACC_HI3;	 // "wacc_hi3"
      case '4':	 // 1 string to match.
        return PPC::WACC_HI4;	 // "wacc_hi4"
      case '5':	 // 1 string to match.
        return PPC::WACC_HI5;	 // "wacc_hi5"
      case '6':	 // 1 string to match.
        return PPC::WACC_HI6;	 // "wacc_hi6"
      case '7':	 // 1 string to match.
        return PPC::WACC_HI7;	 // "wacc_hi7"
      }
      break;
    }
    break;
  case 9:	 // 22 strings to match.
    if (memcmp(Name.data()+0, "dmrrowp", 7) != 0)
      break;
    switch (Name[7]) {
    default: break;
    case '1':	 // 10 strings to match.
      switch (Name[8]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::DMRROWp10;	 // "dmrrowp10"
      case '1':	 // 1 string to match.
        return PPC::DMRROWp11;	 // "dmrrowp11"
      case '2':	 // 1 string to match.
        return PPC::DMRROWp12;	 // "dmrrowp12"
      case '3':	 // 1 string to match.
        return PPC::DMRROWp13;	 // "dmrrowp13"
      case '4':	 // 1 string to match.
        return PPC::DMRROWp14;	 // "dmrrowp14"
      case '5':	 // 1 string to match.
        return PPC::DMRROWp15;	 // "dmrrowp15"
      case '6':	 // 1 string to match.
        return PPC::DMRROWp16;	 // "dmrrowp16"
      case '7':	 // 1 string to match.
        return PPC::DMRROWp17;	 // "dmrrowp17"
      case '8':	 // 1 string to match.
        return PPC::DMRROWp18;	 // "dmrrowp18"
      case '9':	 // 1 string to match.
        return PPC::DMRROWp19;	 // "dmrrowp19"
      }
      break;
    case '2':	 // 10 strings to match.
      switch (Name[8]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::DMRROWp20;	 // "dmrrowp20"
      case '1':	 // 1 string to match.
        return PPC::DMRROWp21;	 // "dmrrowp21"
      case '2':	 // 1 string to match.
        return PPC::DMRROWp22;	 // "dmrrowp22"
      case '3':	 // 1 string to match.
        return PPC::DMRROWp23;	 // "dmrrowp23"
      case '4':	 // 1 string to match.
        return PPC::DMRROWp24;	 // "dmrrowp24"
      case '5':	 // 1 string to match.
        return PPC::DMRROWp25;	 // "dmrrowp25"
      case '6':	 // 1 string to match.
        return PPC::DMRROWp26;	 // "dmrrowp26"
      case '7':	 // 1 string to match.
        return PPC::DMRROWp27;	 // "dmrrowp27"
      case '8':	 // 1 string to match.
        return PPC::DMRROWp28;	 // "dmrrowp28"
      case '9':	 // 1 string to match.
        return PPC::DMRROWp29;	 // "dmrrowp29"
      }
      break;
    case '3':	 // 2 strings to match.
      switch (Name[8]) {
      default: break;
      case '0':	 // 1 string to match.
        return PPC::DMRROWp30;	 // "dmrrowp30"
      case '1':	 // 1 string to match.
        return PPC::DMRROWp31;	 // "dmrrowp31"
      }
      break;
    }
    break;
  case 16:	 // 2 strings to match.
    if (memcmp(Name.data()+0, "**BASE POINTER**", 16) != 0)
      break;
    return PPC::BP;	 // "**BASE POINTER**"
  case 17:	 // 3 strings to match.
    if (memcmp(Name.data()+0, "**", 2) != 0)
      break;
    switch (Name[2]) {
    default: break;
    case 'F':	 // 2 strings to match.
      if (memcmp(Name.data()+3, "RAME POINTER**", 14) != 0)
        break;
      return PPC::FP;	 // "**FRAME POINTER**"
    case 'R':	 // 1 string to match.
      if (memcmp(Name.data()+3, "OUNDING MODE**", 14) != 0)
        break;
      return PPC::RM;	 // "**ROUNDING MODE**"
    }
    break;
  }
  return PPC::NoRegister;
}

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_ModernAsBit: return "";
  default: return "(unknown)";
  }
}

#endif // GET_SUBTARGET_FEATURE_NAME


#ifdef GET_MATCHER_IMPLEMENTATION
#undef GET_MATCHER_IMPLEMENTATION

static void applyMnemonicAliases(StringRef &Mnemonic, const FeatureBitset &Features, unsigned VariantID) {
  switch (Mnemonic.size()) {
  default: break;
  case 5:	 // 1 string to match.
    if (memcmp(Mnemonic.data()+0, "cntlz", 5) != 0)
      break;
    Mnemonic = "cntlzw";	 // "cntlz"
    return;
  case 6:	 // 1 string to match.
    if (memcmp(Mnemonic.data()+0, "cntlz.", 6) != 0)
      break;
    Mnemonic = "cntlzw.";	 // "cntlz."
    return;
  }
}

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
  CVT_95_addRegG8RCOperands,
  CVT_95_addTLSRegOperands,
  CVT_95_addRegGPRCOperands,
  CVT_95_addImmOperands,
  CVT_95_addRegGPRC_95_NOR0Operands,
  CVT_95_addS16ImmOperands,
  CVT_95_addU16ImmOperands,
  CVT_95_addBranchTargetOperands,
  CVT_95_addRegCRBITRCOperands,
  CVT_imm_95_3,
  CVT_imm_95_2,
  CVT_imm_95_0,
  CVT_95_addRegVRRCOperands,
  CVT_imm_95_8,
  CVT_imm_95_10,
  CVT_imm_95_76,
  CVT_regCR0,
  CVT_95_addRegCRRCOperands,
  CVT_imm_95_79,
  CVT_imm_95_78,
  CVT_imm_95_4,
  CVT_imm_95_7,
  CVT_imm_95_6,
  CVT_imm_95_44,
  CVT_imm_95_47,
  CVT_imm_95_46,
  CVT_imm_95_36,
  CVT_imm_95_39,
  CVT_imm_95_38,
  CVT_imm_95_12,
  CVT_imm_95_15,
  CVT_imm_95_14,
  CVT_imm_95_68,
  CVT_imm_95_71,
  CVT_imm_95_70,
  CVT_imm_95_100,
  CVT_imm_95_103,
  CVT_imm_95_102,
  CVT_imm_95_108,
  CVT_imm_95_111,
  CVT_imm_95_110,
  CVT_imm_95_31,
  CVT_95_addRegF8RCOperands,
  CVT_95_addRegFpRCOperands,
  CVT_95_addRegGxRCNoR0Operands,
  CVT_95_addRegGxRCOperands,
  CVT_regR0,
  CVT_95_addRegDMRpRCOperands,
  CVT_95_addRegDMRRCOperands,
  CVT_imm_95_1,
  CVT_95_addRegVSRpRCOperands,
  CVT_95_addRegVSRCOperands,
  CVT_95_addRegDMRROWpRCOperands,
  CVT_95_addRegACCRCOperands,
  CVT_95_addRegSPERCOperands,
  CVT_95_addRegF4RCOperands,
  CVT_95_addRegG8RC_95_NOX0Operands,
  CVT_regCR0EQ,
  CVT_regCR0GT,
  CVT_regCR0LT,
  CVT_95_addRegG8pRCOperands,
  CVT_regZERO8,
  CVT_regZERO,
  CVT_95_addRegVFRCOperands,
  CVT_95_addRegVSFRCOperands,
  CVT_95_addRegVSSRCOperands,
  CVT_imm_95_29,
  CVT_imm_95_280,
  CVT_imm_95_128,
  CVT_imm_95_129,
  CVT_imm_95_130,
  CVT_imm_95_131,
  CVT_imm_95_132,
  CVT_imm_95_133,
  CVT_imm_95_134,
  CVT_imm_95_135,
  CVT_imm_95_28,
  CVT_imm_95_9,
  CVT_imm_95_19,
  CVT_imm_95_537,
  CVT_imm_95_539,
  CVT_imm_95_541,
  CVT_imm_95_543,
  CVT_imm_95_536,
  CVT_imm_95_538,
  CVT_imm_95_540,
  CVT_imm_95_542,
  CVT_imm_95_1018,
  CVT_imm_95_981,
  CVT_imm_95_22,
  CVT_imm_95_17,
  CVT_imm_95_18,
  CVT_imm_95_980,
  CVT_imm_95_529,
  CVT_imm_95_531,
  CVT_imm_95_533,
  CVT_imm_95_535,
  CVT_imm_95_528,
  CVT_imm_95_530,
  CVT_imm_95_532,
  CVT_imm_95_534,
  CVT_imm_95_1019,
  CVT_95_addCRBitMaskOperands,
  CVT_imm_95_48,
  CVT_imm_95_896,
  CVT_imm_95_287,
  CVT_imm_95_5,
  CVT_imm_95_25,
  CVT_imm_95_512,
  CVT_imm_95_272,
  CVT_imm_95_273,
  CVT_imm_95_274,
  CVT_imm_95_275,
  CVT_imm_95_260,
  CVT_imm_95_261,
  CVT_imm_95_262,
  CVT_imm_95_263,
  CVT_imm_95_26,
  CVT_imm_95_27,
  CVT_imm_95_990,
  CVT_imm_95_991,
  CVT_imm_95_268,
  CVT_imm_95_988,
  CVT_imm_95_989,
  CVT_imm_95_269,
  CVT_imm_95_986,
  CVT_imm_95_13,
  CVT_imm_95_255,
  CVT_imm_95_284,
  CVT_imm_95_285,
  CVT_regX0,
  CVT_95_addRegVSRpEvenRCOperands,
  CVT_95_addNegImmOperands,
  CVT_imm_95_20,
  CVT_imm_95_16,
  CVT_imm_95_24,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__RegG8RC1_0__RegG8RC1_1__TLSReg1_2,
  Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2,
  Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3,
  Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__U2Imm1_3,
  Convert__RegGPRC1_0__RegGPRC_NOR01_1__S16Imm1_2,
  Convert__RegGPRC1_0__RegGPRC1_1__S16Imm1_2,
  Convert__RegGPRC1_1__RegGPRC1_2__S16Imm1_3,
  Convert__RegGPRC1_0__RegGPRC_NOR01_1__S17Imm1_2,
  Convert__RegGPRC1_0__RegGPRC1_1,
  Convert__RegGPRC1_1__RegGPRC1_2,
  Convert__RegG8RC1_0__Imm1_1,
  Convert__RegGPRC1_1__RegGPRC1_2__U16Imm1_3,
  Convert_NoOperands,
  Convert__DirectBr1_0,
  Convert__U5Imm1_0__RegCRBITRC1_1__CondBr1_2,
  Convert__U5Imm1_1__ATBitsAsHint1_0__RegCRBITRC1_2__CondBr1_3,
  Convert__U5Imm1_0__imm_95_3__RegCRBITRC1_1__CondBr1_2,
  Convert__U5Imm1_0__imm_95_2__RegCRBITRC1_1__CondBr1_2,
  Convert__U5Imm1_0__RegCRBITRC1_1__imm_95_0,
  Convert__U5Imm1_0__RegCRBITRC1_1__Imm1_2,
  Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3__U1Imm1_4,
  Convert__RegVRRC1_1__RegVRRC1_2__U1Imm1_3,
  Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3,
  Convert__RegVRRC1_1__RegVRRC1_2,
  Convert__CondBr1_0,
  Convert__imm_95_0__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_0__RegCRBITRC1_0__imm_95_0,
  Convert__imm_95_8__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_8__RegCRBITRC1_0__imm_95_0,
  Convert__imm_95_2__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_2__RegCRBITRC1_0__imm_95_0,
  Convert__imm_95_10__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_10__RegCRBITRC1_0__imm_95_0,
  Convert__imm_95_76__regCR0__CondBr1_0,
  Convert__imm_95_76__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_79__regCR0__CondBr1_0,
  Convert__imm_95_79__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_78__regCR0__CondBr1_0,
  Convert__imm_95_78__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_76__regCR0,
  Convert__imm_95_76__RegCRRC1_0,
  Convert__imm_95_79__regCR0,
  Convert__imm_95_79__RegCRRC1_0,
  Convert__imm_95_78__regCR0,
  Convert__imm_95_78__RegCRRC1_0,
  Convert__imm_95_4__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_7__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_6__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_4__RegCRBITRC1_0__imm_95_0,
  Convert__imm_95_7__RegCRBITRC1_0__imm_95_0,
  Convert__imm_95_6__RegCRBITRC1_0__imm_95_0,
  Convert__imm_95_4__regCR0__CondBr1_0,
  Convert__imm_95_4__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_7__regCR0__CondBr1_0,
  Convert__imm_95_7__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_6__regCR0__CondBr1_0,
  Convert__imm_95_6__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_4__regCR0,
  Convert__imm_95_4__RegCRRC1_0,
  Convert__imm_95_7__regCR0,
  Convert__imm_95_7__RegCRRC1_0,
  Convert__imm_95_6__regCR0,
  Convert__imm_95_6__RegCRRC1_0,
  Convert__imm_95_44__regCR0__CondBr1_0,
  Convert__imm_95_44__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_47__regCR0__CondBr1_0,
  Convert__imm_95_47__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_46__regCR0__CondBr1_0,
  Convert__imm_95_46__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_44__regCR0,
  Convert__imm_95_44__RegCRRC1_0,
  Convert__imm_95_47__regCR0,
  Convert__imm_95_47__RegCRRC1_0,
  Convert__imm_95_46__regCR0,
  Convert__imm_95_46__RegCRRC1_0,
  Convert__DirectBr1_0__Imm1_1,
  Convert__imm_95_36__regCR0__CondBr1_0,
  Convert__imm_95_36__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_39__regCR0__CondBr1_0,
  Convert__imm_95_39__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_38__regCR0__CondBr1_0,
  Convert__imm_95_38__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_36__regCR0,
  Convert__imm_95_36__RegCRRC1_0,
  Convert__imm_95_39__regCR0,
  Convert__imm_95_39__RegCRRC1_0,
  Convert__imm_95_38__regCR0,
  Convert__imm_95_38__RegCRRC1_0,
  Convert__imm_95_12__regCR0__CondBr1_0,
  Convert__imm_95_12__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_15__regCR0__CondBr1_0,
  Convert__imm_95_15__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_14__regCR0__CondBr1_0,
  Convert__imm_95_14__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_12__regCR0,
  Convert__imm_95_12__RegCRRC1_0,
  Convert__imm_95_15__regCR0,
  Convert__imm_95_15__RegCRRC1_0,
  Convert__imm_95_14__regCR0,
  Convert__imm_95_14__RegCRRC1_0,
  Convert__imm_95_68__regCR0__CondBr1_0,
  Convert__imm_95_68__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_71__regCR0__CondBr1_0,
  Convert__imm_95_71__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_70__regCR0__CondBr1_0,
  Convert__imm_95_70__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_68__regCR0,
  Convert__imm_95_68__RegCRRC1_0,
  Convert__imm_95_71__regCR0,
  Convert__imm_95_71__RegCRRC1_0,
  Convert__imm_95_70__regCR0,
  Convert__imm_95_70__RegCRRC1_0,
  Convert__imm_95_100__regCR0__CondBr1_0,
  Convert__imm_95_100__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_103__regCR0__CondBr1_0,
  Convert__imm_95_103__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_102__regCR0__CondBr1_0,
  Convert__imm_95_102__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_100__regCR0,
  Convert__imm_95_100__RegCRRC1_0,
  Convert__imm_95_103__regCR0,
  Convert__imm_95_103__RegCRRC1_0,
  Convert__imm_95_102__regCR0,
  Convert__imm_95_102__RegCRRC1_0,
  Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2,
  Convert__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_108__regCR0__CondBr1_0,
  Convert__imm_95_108__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_111__regCR0__CondBr1_0,
  Convert__imm_95_111__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_110__regCR0__CondBr1_0,
  Convert__imm_95_110__RegCRRC1_0__CondBr1_1,
  Convert__imm_95_108__regCR0,
  Convert__imm_95_108__RegCRRC1_0,
  Convert__imm_95_111__regCR0,
  Convert__imm_95_111__RegCRRC1_0,
  Convert__imm_95_110__regCR0,
  Convert__imm_95_110__RegCRRC1_0,
  Convert__imm_95_12__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_15__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_14__RegCRBITRC1_0__CondBr1_1,
  Convert__imm_95_12__RegCRBITRC1_0__imm_95_0,
  Convert__imm_95_15__RegCRBITRC1_0__imm_95_0,
  Convert__imm_95_14__RegCRBITRC1_0__imm_95_0,
  Convert__RegG8RC1_0__RegG8RC1_1__imm_95_0__U6Imm1_2,
  Convert__RegG8RC1_0__RegGPRC1_1__imm_95_0__U6Imm1_2,
  Convert__RegG8RC1_1__RegG8RC1_2__imm_95_0__U6Imm1_3,
  Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__U6Imm1_3,
  Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4,
  Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3,
  Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4,
  Convert__RegG8RC1_0__RegG8RC1_1__imm_95_0__U5Imm1_2__imm_95_31,
  Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0__U5Imm1_2__imm_95_31,
  Convert__RegG8RC1_1__RegG8RC1_2__imm_95_0__U5Imm1_3__imm_95_31,
  Convert__RegGPRC1_1__RegGPRC1_2__imm_95_0__U5Imm1_3__imm_95_31,
  Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2,
  Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3,
  Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2,
  Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3,
  Convert__RegCRRC1_0__RegGPRC1_2__RegGPRC1_3,
  Convert__RegCRRC1_0__RegG8RC1_2__RegG8RC1_3,
  Convert__regCR0__RegG8RC1_0__RegG8RC1_1,
  Convert__RegCRRC1_0__RegG8RC1_1__RegG8RC1_2,
  Convert__regCR0__RegG8RC1_0__S16Imm1_1,
  Convert__RegCRRC1_0__RegG8RC1_1__S16Imm1_2,
  Convert__RegCRRC1_0__RegGPRC1_2__S16Imm1_3,
  Convert__RegCRRC1_0__RegG8RC1_2__S16Imm1_3,
  Convert__regCR0__RegG8RC1_0__U16Imm1_1,
  Convert__RegCRRC1_0__RegG8RC1_1__U16Imm1_2,
  Convert__RegCRRC1_0__RegGPRC1_2__U16Imm1_3,
  Convert__RegCRRC1_0__RegG8RC1_2__U16Imm1_3,
  Convert__regCR0__RegGPRC1_0__RegGPRC1_1,
  Convert__RegCRRC1_0__RegGPRC1_1__RegGPRC1_2,
  Convert__regCR0__RegGPRC1_0__U16Imm1_1,
  Convert__RegCRRC1_0__RegGPRC1_1__U16Imm1_2,
  Convert__RegCRRC1_0__U1Imm1_1__RegGPRC1_2__RegGPRC1_3,
  Convert__regCR0__RegGPRC1_0__S16Imm1_1,
  Convert__RegCRRC1_0__RegGPRC1_1__S16Imm1_2,
  Convert__RegG8RC1_1__RegG8RC1_2,
  Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2,
  Convert__RegCRBITRC1_0__RegCRBITRC1_0__RegCRBITRC1_0,
  Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_1,
  Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2,
  Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3,
  Convert__RegFpRC1_0__RegFpRC1_1__RegFpRC1_2,
  Convert__RegFpRC1_1__RegFpRC1_2__RegFpRC1_3,
  Convert__RegG8RC1_0__U2Imm1_1,
  Convert__RegGxRCNoR01_0__RegGxRC1_1,
  Convert__U3Imm1_2__RegGxRCNoR01_0__RegGxRC1_1,
  Convert__U5Imm1_2__RegGxRCNoR01_0__RegGxRC1_1,
  Convert__RegGxRCNoR01_0__RegGxRC1_1__U5Imm1_2,
  Convert__RegGxRCNoR01_1__RegGxRC1_2__U5Imm1_0,
  Convert__regR0__regR0,
  Convert__RegF8RC1_0__RegF8RC1_1,
  Convert__RegF8RC1_1__RegF8RC1_2,
  Convert__RegFpRC1_0__RegF8RC1_1,
  Convert__RegFpRC1_1__RegF8RC1_2,
  Convert__RegFpRC1_0__RegVRRC1_1,
  Convert__RegCRRC1_0__RegF8RC1_1__RegF8RC1_2,
  Convert__RegCRRC1_0__RegFpRC1_1__RegFpRC1_2,
  Convert__RegF8RC1_0__RegFpRC1_1,
  Convert__RegF8RC1_1__RegFpRC1_2,
  Convert__RegVRRC1_0__RegFpRC1_1,
  Convert__RegF8RC1_1__U2Imm1_0__RegF8RC1_2,
  Convert__RegF8RC1_2__U2Imm1_1__RegF8RC1_3,
  Convert__RegFpRC1_1__U2Imm1_0__RegFpRC1_2,
  Convert__RegFpRC1_2__U2Imm1_1__RegFpRC1_3,
  Convert__RegF8RC1_1__U1Imm1_0__RegF8RC1_2,
  Convert__RegF8RC1_2__U1Imm1_1__RegF8RC1_3,
  Convert__RegFpRC1_1__U1Imm1_0__RegFpRC1_2,
  Convert__RegFpRC1_2__U1Imm1_1__RegFpRC1_3,
  Convert__RegFpRC1_0__RegF8RC1_1__RegFpRC1_2,
  Convert__RegFpRC1_1__RegF8RC1_2__RegFpRC1_3,
  Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3,
  Convert__RegDMRpRC1_0__Tie0_1_1__imm_95_12,
  Convert__RegDMRRC1_0__RegDMRRC1_1,
  Convert__RegDMRRC1_0,
  Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1__imm_95_0,
  Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1__U1Imm1_2,
  Convert__RegDMRpRC1_0__Tie0_1_1__imm_95_0,
  Convert__RegDMRpRC1_0__Tie0_1_1__U5Imm1_1,
  Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1__imm_95_1,
  Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1,
  Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2,
  Convert__RegVSRpRC1_0__RegDMRROWpRC1_1__U2Imm1_2,
  Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegACCRC1_2,
  Convert__RegDMRROWpRC1_0__RegVSRpRC1_1__U2Imm1_2,
  Convert__RegACCRC1_0__RegVSRpRC1_1__RegVSRpRC1_2,
  Convert__RegACCRC1_0__Tie0_1_1,
  Convert__RegACCRC1_0,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_3__imm_95_0__imm_95_0,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_3,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_2,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_1,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_0,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_2__imm_95_0__imm_95_0,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_1__U1Imm1_2__imm_95_1,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_1__U1Imm1_2__imm_95_0,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__U2Imm1_2__U1Imm1_3__U2Imm1_4,
  Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__U2Imm1_3,
  Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__U2Imm1_4,
  Convert__RegF8RC1_1__S5Imm1_0__RegF8RC1_2__U2Imm1_3,
  Convert__RegF8RC1_2__S5Imm1_1__RegF8RC1_3__U2Imm1_4,
  Convert__RegFpRC1_1__S5Imm1_0__RegFpRC1_2__U2Imm1_3,
  Convert__RegFpRC1_2__S5Imm1_1__RegFpRC1_3__U2Imm1_4,
  Convert__RegFpRC1_0__RegFpRC1_1__RegFpRC1_2__U2Imm1_3,
  Convert__RegFpRC1_1__RegFpRC1_2__RegFpRC1_3__U2Imm1_4,
  Convert__RegFpRC1_0__RegFpRC1_1,
  Convert__RegFpRC1_1__RegFpRC1_2,
  Convert__RegF8RC1_1__U1Imm1_0__RegF8RC1_2__U2Imm1_3,
  Convert__RegF8RC1_2__U1Imm1_1__RegF8RC1_3__U2Imm1_4,
  Convert__RegFpRC1_1__U1Imm1_0__RegFpRC1_2__U2Imm1_3,
  Convert__RegFpRC1_2__U1Imm1_1__RegFpRC1_3__U2Imm1_4,
  Convert__RegFpRC1_0__RegF8RC1_1__RegFpRC1_2__U2Imm1_3,
  Convert__RegFpRC1_1__RegF8RC1_2__RegFpRC1_3__U2Imm1_4,
  Convert__RegF8RC1_0__RegF8RC1_1__U6Imm1_2,
  Convert__RegF8RC1_1__RegF8RC1_2__U6Imm1_3,
  Convert__RegFpRC1_0__RegFpRC1_1__U6Imm1_2,
  Convert__RegFpRC1_1__RegFpRC1_2__U6Imm1_3,
  Convert__U5Imm1_0,
  Convert__U5Imm1_2__RegGPRC1_0__RegGPRC1_1,
  Convert__RegCRRC1_0__RegF8RC1_1__U6Imm1_2,
  Convert__RegCRRC1_0__RegFpRC1_1__U6Imm1_2,
  Convert__RegCRRC1_0__U6Imm1_1__RegF8RC1_2,
  Convert__RegCRRC1_0__U6Imm1_1__RegFpRC1_2,
  Convert__RegCRRC1_0__RegF8RC1_1__RegFpRC1_2,
  Convert__RegSPERC1_0__RegSPERC1_1,
  Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2,
  Convert__RegSPERC1_0__RegGPRC1_1,
  Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2,
  Convert__RegGPRC1_0__RegSPERC1_1,
  Convert__RegSPERC1_0__RegSPERC1_2__U5Imm1_1,
  Convert__RegSPERC1_0__DispSPE81_1__RegGxRCNoR01_2,
  Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegSPERC1_0__DispSPE21_1__RegGxRCNoR01_2,
  Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2,
  Convert__RegSPERC1_0__RegGPRC1_1__RegGPRC1_2,
  Convert__RegSPERC1_0__RegSPERC1_1__U5Imm1_2,
  Convert__RegSPERC1_1__RegSPERC1_2__RegSPERC1_3__imm_95_0,
  Convert__RegSPERC1_0__S5Imm1_1,
  Convert__RegSPERC1_0__U5Imm1_1__RegSPERC1_2,
  Convert__RegF4RC1_0__RegF4RC1_1,
  Convert__RegF4RC1_1__RegF4RC1_2,
  Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2,
  Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3,
  Convert__RegF4RC1_0__RegF8RC1_1,
  Convert__RegF4RC1_1__RegF8RC1_2,
  Convert__RegCRRC1_0__RegF4RC1_1__RegF4RC1_2,
  Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3,
  Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__RegF8RC1_4,
  Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3,
  Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3__RegF4RC1_4,
  Convert__RegF4RC1_0__RegF8RC1_1__RegF4RC1_2__RegF4RC1_3,
  Convert__RegF4RC1_1__RegF8RC1_2__RegF4RC1_3__RegF4RC1_4,
  Convert__RegCRRC1_0__RegF8RC1_1,
  Convert__RegGPRC1_0__DispRIHash1_1__RegGxRCNoR01_2,
  Convert__imm_95_0__imm_95_0,
  Convert__imm_95_0,
  Convert__U4Imm1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__U4Imm1_1__RegGxRCNoR01_2__RegGxRC1_3,
  Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__RegCRBITRC1_3,
  Convert__RegG8RC1_0__RegG8RC_NOX01_1__RegG8RC1_2__regCR0EQ,
  Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__regCR0EQ,
  Convert__RegG8RC1_0__RegG8RC_NOX01_1__RegG8RC1_2__regCR0GT,
  Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__regCR0GT,
  Convert__RegG8RC1_0__RegG8RC_NOX01_1__RegG8RC1_2__regCR0LT,
  Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__regCR0LT,
  Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2,
  Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegGPRC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2,
  Convert__RegGPRC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2,
  Convert__RegG8RC1_0__DispRIX1_1__RegGxRCNoR01_2,
  Convert__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegG8pRC1_0__Tie0_1_1__RegGxRCNoR01_1__U5Imm1_2,
  Convert__RegG8RC1_0__imm_95_0__DispRIX1_1__RegGxRCNoR01_2,
  Convert__RegG8RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegF8RC1_0__DispRI1_1__RegGxRCNoR01_2,
  Convert__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegF8RC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2,
  Convert__RegF8RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegF8RC1_0__RegGxRCNoR01_1__TLSReg1_2,
  Convert__RegF4RC1_0__DispRI1_1__RegGxRCNoR01_2,
  Convert__RegF4RC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2,
  Convert__RegF4RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegF4RC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegF4RC1_0__RegGxRCNoR01_1__TLSReg1_2,
  Convert__RegG8RC1_0__regZERO8__S16Imm1_1,
  Convert__RegGPRC1_0__S16Imm1_1,
  Convert__RegGPRC1_0__regZERO__S16Imm1_1,
  Convert__RegG8RC1_0__regZERO8__S17Imm1_1,
  Convert__RegGPRC1_0__S17Imm1_1,
  Convert__RegGPRC1_0__regZERO__S17Imm1_1,
  Convert__RegG8RC1_0__imm_95_0,
  Convert__RegG8pRC1_0__DispRIX161_1__RegGxRCNoR01_2,
  Convert__RegG8pRC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__imm_95_1,
  Convert__RegVFRC1_0__DispRIX1_1__RegGxRCNoR01_2,
  Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegVSSRC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegVSRC1_0__DispRIX161_1__RegGxRCNoR01_2,
  Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegVSRC1_0__U5Imm1_1,
  Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2,
  Convert__RegVSRpRC1_0__DispRIX161_1__RegGxRCNoR01_2,
  Convert__RegVSRpRC1_0__Imm1_1__RegG8RC1_2,
  Convert__RegVSRpRC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3,
  Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3,
  Convert__RegCRRC1_0__RegCRRC1_1,
  Convert__RegCRRC1_0,
  Convert__RegG8RC1_0__imm_95_29,
  Convert__RegGPRC1_0__imm_95_29,
  Convert__RegG8RC1_0__imm_95_280,
  Convert__RegGPRC1_0__imm_95_280,
  Convert__RegGPRC1_0__U10Imm1_1,
  Convert__RegGPRC1_0__imm_95_128,
  Convert__RegGPRC1_0__imm_95_129,
  Convert__RegGPRC1_0__imm_95_130,
  Convert__RegGPRC1_0__imm_95_131,
  Convert__RegGPRC1_0__imm_95_132,
  Convert__RegGPRC1_0__imm_95_133,
  Convert__RegGPRC1_0__imm_95_134,
  Convert__RegGPRC1_0__imm_95_135,
  Convert__RegG8RC1_0__imm_95_28,
  Convert__RegGPRC1_0__imm_95_28,
  Convert__RegGPRC1_0,
  Convert__RegG8RC1_0__imm_95_9,
  Convert__RegGPRC1_0__imm_95_9,
  Convert__RegG8RC1_0__imm_95_19,
  Convert__RegGPRC1_0__imm_95_19,
  Convert__RegGPRC1_0__imm_95_537,
  Convert__RegGPRC1_0__imm_95_539,
  Convert__RegGPRC1_0__imm_95_541,
  Convert__RegGPRC1_0__imm_95_543,
  Convert__RegGPRC1_0__imm_95_536,
  Convert__RegGPRC1_0__imm_95_538,
  Convert__RegGPRC1_0__imm_95_540,
  Convert__RegGPRC1_0__imm_95_542,
  Convert__RegGPRC1_0__imm_95_1018,
  Convert__RegGPRC1_0__Imm1_1,
  Convert__RegGPRC1_0__imm_95_981,
  Convert__RegG8RC1_0__imm_95_22,
  Convert__RegGPRC1_0__imm_95_22,
  Convert__RegG8RC1_0__imm_95_17,
  Convert__RegGPRC1_0__imm_95_17,
  Convert__RegG8RC1_0__imm_95_18,
  Convert__RegGPRC1_0__imm_95_18,
  Convert__RegGPRC1_0__imm_95_980,
  Convert__RegG8RC1_0__RegF8RC1_1,
  Convert__RegGPRC1_0__RegF8RC1_1,
  Convert__RegF8RC1_0,
  Convert__RegF8RC1_1,
  Convert__RegF8RC1_0__U3Imm1_1,
  Convert__RegF8RC1_0__U2Imm1_1,
  Convert__RegGPRC1_0__imm_95_529,
  Convert__RegGPRC1_0__imm_95_531,
  Convert__RegGPRC1_0__imm_95_533,
  Convert__RegGPRC1_0__imm_95_535,
  Convert__RegGPRC1_0__imm_95_528,
  Convert__RegGPRC1_0__imm_95_530,
  Convert__RegGPRC1_0__imm_95_532,
  Convert__RegGPRC1_0__imm_95_534,
  Convert__RegGPRC1_0__imm_95_1019,
  Convert__RegG8RC1_0__imm_95_8,
  Convert__RegGPRC1_0__imm_95_8,
  Convert__RegGPRC1_0__CRBitMask1_1,
  Convert__RegGPRC1_0__imm_95_48,
  Convert__RegGPRC1_0__imm_95_896,
  Convert__RegG8RC1_0__imm_95_287,
  Convert__RegGPRC1_0__imm_95_287,
  Convert__RegG8RC1_0__imm_95_5,
  Convert__RegGPRC1_0__imm_95_5,
  Convert__RegG8RC1_0__imm_95_4,
  Convert__RegGPRC1_0__imm_95_4,
  Convert__RegG8RC1_0__imm_95_25,
  Convert__RegGPRC1_0__imm_95_25,
  Convert__RegG8RC1_0__imm_95_512,
  Convert__RegGPRC1_0__imm_95_512,
  Convert__RegG8RC1_0__imm_95_272,
  Convert__RegG8RC1_0__imm_95_273,
  Convert__RegG8RC1_0__imm_95_274,
  Convert__RegG8RC1_0__imm_95_275,
  Convert__RegGPRC1_0__imm_95_272,
  Convert__RegGPRC1_0__imm_95_273,
  Convert__RegGPRC1_0__imm_95_274,
  Convert__RegGPRC1_0__imm_95_275,
  Convert__RegGPRC1_0__imm_95_260,
  Convert__RegGPRC1_0__imm_95_261,
  Convert__RegGPRC1_0__imm_95_262,
  Convert__RegGPRC1_0__imm_95_263,
  Convert__RegGPRC1_0__U4Imm1_1,
  Convert__RegG8RC1_0__imm_95_26,
  Convert__RegGPRC1_0__imm_95_26,
  Convert__RegG8RC1_0__imm_95_27,
  Convert__RegGPRC1_0__imm_95_27,
  Convert__RegGPRC1_0__imm_95_990,
  Convert__RegGPRC1_0__imm_95_991,
  Convert__RegGPRC1_0__imm_95_268,
  Convert__RegGPRC1_0__imm_95_988,
  Convert__RegGPRC1_0__imm_95_989,
  Convert__RegGPRC1_0__imm_95_269,
  Convert__RegGPRC1_0__imm_95_986,
  Convert__RegG8RC1_0__imm_95_13,
  Convert__RegGPRC1_0__imm_95_13,
  Convert__RegG8RC1_0__imm_95_3,
  Convert__RegGPRC1_0__imm_95_3,
  Convert__RegG8RC1_0__RegVRRC1_1,
  Convert__RegGPRC1_0__RegVRRC1_1,
  Convert__RegVRRC1_0,
  Convert__RegG8RC1_0__RegVSFRC1_1,
  Convert__RegG8RC1_0__RegVSRC1_1,
  Convert__RegGPRC1_0__RegVSFRC1_1,
  Convert__RegG8RC1_0__imm_95_1,
  Convert__RegGPRC1_0__imm_95_1,
  Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_1,
  Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_1,
  Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_2,
  Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_2,
  Convert__imm_95_29__RegG8RC1_0,
  Convert__imm_95_29__RegGPRC1_0,
  Convert__imm_95_280__RegG8RC1_0,
  Convert__imm_95_280__RegGPRC1_0,
  Convert__imm_95_28__RegG8RC1_0,
  Convert__imm_95_28__RegGPRC1_0,
  Convert__imm_95_255__RegG8RC1_0,
  Convert__imm_95_255__RegGPRC1_0,
  Convert__Imm1_0__RegGPRC1_1,
  Convert__imm_95_9__RegG8RC1_0,
  Convert__imm_95_9__RegGPRC1_0,
  Convert__imm_95_19__RegG8RC1_0,
  Convert__imm_95_19__RegGPRC1_0,
  Convert__imm_95_537__RegGPRC1_1,
  Convert__imm_95_539__RegGPRC1_1,
  Convert__imm_95_541__RegGPRC1_1,
  Convert__imm_95_543__RegGPRC1_1,
  Convert__imm_95_536__RegGPRC1_1,
  Convert__imm_95_538__RegGPRC1_1,
  Convert__imm_95_540__RegGPRC1_1,
  Convert__imm_95_542__RegGPRC1_1,
  Convert__imm_95_1018__RegGPRC1_0,
  Convert__RegGPRC1_1__Imm1_0,
  Convert__imm_95_981__RegGPRC1_0,
  Convert__imm_95_22__RegG8RC1_0,
  Convert__imm_95_22__RegGPRC1_0,
  Convert__imm_95_17__RegG8RC1_0,
  Convert__imm_95_17__RegGPRC1_0,
  Convert__imm_95_18__RegG8RC1_0,
  Convert__imm_95_18__RegGPRC1_0,
  Convert__imm_95_980__RegGPRC1_0,
  Convert__RegF8RC1_0__RegG8RC1_1,
  Convert__RegF8RC1_0__RegGPRC1_1,
  Convert__Imm1_0__RegF8RC1_1__imm_95_0__imm_95_0,
  Convert__Imm1_1__RegF8RC1_2__imm_95_0__imm_95_0,
  Convert__Imm1_0__RegF8RC1_1__U1Imm1_2__Imm1_3,
  Convert__Imm1_1__RegF8RC1_2__U1Imm1_3__Imm1_4,
  Convert__U3Imm1_0__U4Imm1_1__imm_95_0,
  Convert__U3Imm1_1__U4Imm1_2__imm_95_0,
  Convert__U3Imm1_0__U4Imm1_1__Imm1_2,
  Convert__U3Imm1_1__U4Imm1_2__U1Imm1_3,
  Convert__imm_95_529__RegGPRC1_1,
  Convert__imm_95_531__RegGPRC1_1,
  Convert__imm_95_533__RegGPRC1_1,
  Convert__imm_95_535__RegGPRC1_1,
  Convert__imm_95_528__RegGPRC1_1,
  Convert__imm_95_530__RegGPRC1_1,
  Convert__imm_95_532__RegGPRC1_1,
  Convert__imm_95_534__RegGPRC1_1,
  Convert__imm_95_1019__RegGPRC1_0,
  Convert__imm_95_8__RegG8RC1_0,
  Convert__imm_95_8__RegGPRC1_0,
  Convert__RegGPRC1_0__imm_95_0,
  Convert__RegGPRC1_0__U1Imm1_1,
  Convert__CRBitMask1_0__RegGPRC1_1,
  Convert__imm_95_48__RegGPRC1_0,
  Convert__imm_95_896__RegGPRC1_0,
  Convert__imm_95_25__RegG8RC1_0,
  Convert__imm_95_25__RegGPRC1_0,
  Convert__imm_95_512__RegG8RC1_0,
  Convert__imm_95_512__RegGPRC1_0,
  Convert__RegGPRC1_1,
  Convert__imm_95_272__RegG8RC1_1,
  Convert__imm_95_272__RegGPRC1_1,
  Convert__imm_95_273__RegG8RC1_1,
  Convert__imm_95_273__RegGPRC1_1,
  Convert__imm_95_274__RegG8RC1_1,
  Convert__imm_95_274__RegGPRC1_1,
  Convert__imm_95_275__RegG8RC1_1,
  Convert__imm_95_275__RegGPRC1_1,
  Convert__imm_95_260__RegGPRC1_1,
  Convert__imm_95_261__RegGPRC1_1,
  Convert__imm_95_262__RegGPRC1_1,
  Convert__imm_95_263__RegGPRC1_1,
  Convert__imm_95_272__RegG8RC1_0,
  Convert__imm_95_272__RegGPRC1_0,
  Convert__imm_95_273__RegG8RC1_0,
  Convert__imm_95_273__RegGPRC1_0,
  Convert__imm_95_274__RegG8RC1_0,
  Convert__imm_95_274__RegGPRC1_0,
  Convert__imm_95_275__RegG8RC1_0,
  Convert__imm_95_275__RegGPRC1_0,
  Convert__imm_95_260__RegGPRC1_0,
  Convert__imm_95_261__RegGPRC1_0,
  Convert__imm_95_262__RegGPRC1_0,
  Convert__imm_95_263__RegGPRC1_0,
  Convert__RegGPRC1_1__U4Imm1_0,
  Convert__imm_95_26__RegG8RC1_0,
  Convert__imm_95_26__RegGPRC1_0,
  Convert__imm_95_27__RegG8RC1_0,
  Convert__imm_95_27__RegGPRC1_0,
  Convert__imm_95_990__RegGPRC1_0,
  Convert__imm_95_991__RegGPRC1_0,
  Convert__imm_95_988__RegGPRC1_0,
  Convert__imm_95_284__RegG8RC1_0,
  Convert__imm_95_284__RegGPRC1_0,
  Convert__imm_95_989__RegGPRC1_0,
  Convert__imm_95_285__RegG8RC1_0,
  Convert__imm_95_285__RegGPRC1_0,
  Convert__imm_95_986__RegGPRC1_0,
  Convert__imm_95_13__RegG8RC1_0,
  Convert__imm_95_13__RegGPRC1_0,
  Convert__imm_95_3__RegG8RC1_0,
  Convert__imm_95_3__RegGPRC1_0,
  Convert__RegVRRC1_0__RegG8RC1_1,
  Convert__RegVRRC1_0__RegGPRC1_1,
  Convert__RegVRRC1_0__U16Imm1_1,
  Convert__RegVSFRC1_0__RegG8RC1_1,
  Convert__RegVSRC1_0__RegG8RC_NOX01_1__RegG8RC1_2,
  Convert__RegVSFRC1_0__RegGPRC1_1,
  Convert__RegVSRC1_0__RegGPRC1_1,
  Convert__imm_95_1__RegG8RC1_0,
  Convert__imm_95_1__RegGPRC1_0,
  Convert__regR0__regR0__imm_95_0,
  Convert__regX0__regX0__imm_95_0,
  Convert__RegGPRC1_0__RegGPRC1_1__U16Imm1_2,
  Convert__RegG8RC1_0__RegG8RC_NOX01_1__S34Imm1_2,
  Convert__RegGPRC1_0__ImmZero1_1__S34Imm1_2,
  Convert__RegGPRC1_0__RegGPRC_NOR01_1__S34Imm1_2,
  Convert__RegG8RC1_0__RegG8RC_NOX01_1__S32Imm1_2,
  Convert__RegGPRC1_0__RegGPRC_NOR01_1__S32Imm1_2,
  Convert__RegGPRC1_0__ImmZero1_1__S32Imm1_2,
  Convert__RegGPRC1_1__RegGPRC1_2__imm_95_1,
  Convert__RegGPRC1_1__RegGPRC1_2__U1Imm1_3,
  Convert__imm_95_2__imm_95_0,
  Convert__imm_95_4__imm_95_0,
  Convert__RegG8RC1_0__S34Imm1_1,
  Convert__RegGPRC1_0__S34Imm1_1,
  Convert__RegG8RC1_0__RegG8RC_NOX01_2__S34Imm1_1,
  Convert__RegGPRC1_0__RegGPRC_NOR01_2__S34Imm1_1,
  Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2,
  Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2,
  Convert__RegG8RC1_0__DispRI341_1__RegGxRCNoR01_2,
  Convert__RegG8RC1_0__DispRI341_1__ImmZero1_2,
  Convert__RegF8RC1_0__S34Imm1_1,
  Convert__RegF8RC1_0__DispRI341_1__RegGxRCNoR01_2,
  Convert__RegF8RC1_0__DispRI341_1__ImmZero1_2,
  Convert__RegF4RC1_0__S34Imm1_1,
  Convert__RegF4RC1_0__DispRI341_1__RegGxRCNoR01_2,
  Convert__RegF4RC1_0__DispRI341_1__ImmZero1_2,
  Convert__RegG8RC1_0__regZERO8__S32Imm1_1,
  Convert__RegGPRC1_0__regZERO__S32Imm1_1,
  Convert__imm_95_5__imm_95_0,
  Convert__RegVFRC1_0__S34Imm1_1,
  Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2,
  Convert__RegVFRC1_0__DispRI341_1__ImmZero1_2,
  Convert__RegVSRC1_0__S34Imm1_1,
  Convert__RegVSRC1_0__DispRI341_1__RegGxRCNoR01_2,
  Convert__RegVSRC1_0__DispRI341_1__ImmZero1_2,
  Convert__RegVSRpRC1_0__S34Imm1_1,
  Convert__RegVSRpRC1_0__DispRI341_1__RegGxRCNoR01_2,
  Convert__RegVSRpRC1_0__DispRI341_1__ImmZero1_2,
  Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5,
  Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U4Imm1_5,
  Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U4Imm1_5,
  Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5,
  Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5,
  Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4,
  Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4,
  Convert__RegACCRC1_0__RegVSRpEvenRC1_1__RegVSRC1_2__U4Imm1_3__U2Imm1_4,
  Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2__U4Imm1_3__U2Imm1_4,
  Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U8Imm1_5,
  Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U8Imm1_5,
  Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U4Imm1_5,
  Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U4Imm1_5,
  Convert__RegG8RC1_0__RegG8RC_NOX01_1__NegS32Imm1_2,
  Convert__RegGPRC1_0__RegGPRC_NOR01_1__NegS32Imm1_2,
  Convert__imm_95_2,
  Convert__RegG8RC1_0,
  Convert__U1Imm1_0,
  Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2__U6Imm1_3,
  Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3__U6Imm1_4,
  Convert__RegG8RC1_0__Tie0_1_1__RegG8RC1_1__U6Imm1_2__U6Imm1_3,
  Convert__RegG8RC1_1__Tie0_1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4,
  Convert__RegG8RC1_0__RegG8RC1_1__U5Imm1_2__Imm1_3,
  Convert__RegG8RC1_1__RegG8RC1_2__U5Imm1_3__Imm1_4,
  Convert__RegGPRC1_0__Tie0_1_1__RegGPRC1_1__U5Imm1_2__U5Imm1_3__U5Imm1_4,
  Convert__RegGPRC1_1__Tie0_1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4__U5Imm1_5,
  Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3__U5Imm1_4,
  Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4__U5Imm1_5,
  Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4,
  Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3__U5Imm1_4__U5Imm1_5,
  Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2__imm_95_0,
  Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3__imm_95_0,
  Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__imm_95_0,
  Convert__RegG8RC1_0__RegGPRC1_1__U6Imm1_2__imm_95_0,
  Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__imm_95_0,
  Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2__imm_95_0__imm_95_31,
  Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__imm_95_0__imm_95_31,
  Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3__imm_95_0__imm_95_31,
  Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3__imm_95_0__imm_95_31,
  Convert__RegG8RC1_0__RegG8RC1_1__U5Imm1_2__imm_95_0__imm_95_31,
  Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__imm_95_0__imm_95_31,
  Convert__RegG8RC1_1__RegG8RC1_2__U5Imm1_3__imm_95_0__imm_95_31,
  Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__imm_95_0__imm_95_31,
  Convert__Imm1_0,
  Convert__RegGPRC1_0__RegCRRC1_1,
  Convert__RegGPRC1_0__RegCRBITRC1_1,
  Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2,
  Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3,
  Convert__RegGPRC1_1__RegGxRCNoR01_2__RegGxRC1_3,
  Convert__imm_95_0__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2,
  Convert__imm_95_0__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__imm_95_0__imm_95_2,
  Convert__RegG8RC1_0__RegGxRCNoR01_1__U5Imm1_2,
  Convert__RegG8RC1_1__RegGxRCNoR01_2__RegGxRC1_3,
  Convert__imm_95_0__RegG8RC1_0__DispRIX1_1__RegGxRCNoR01_2,
  Convert__imm_95_0__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__imm_95_0__RegF8RC1_0__DispRI1_1__RegGxRCNoR01_2,
  Convert__imm_95_0__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__imm_95_0__RegF4RC1_0__DispRI1_1__RegGxRCNoR01_2,
  Convert__imm_95_0__RegF4RC1_0__RegGxRCNoR01_1__RegGxRC1_2,
  Convert__imm_95_1__imm_95_1,
  Convert__RegG8pRC1_0__DispRIX1_1__RegGxRCNoR01_2,
  Convert__RegG8pRC1_1__RegGxRCNoR01_2__RegGxRC1_3,
  Convert__imm_95_0__imm_95_3,
  Convert__RegGPRC1_0__RegGxRCNoR01_1__U5Imm1_2,
  Convert__RegG8RC1_0__RegG8RC1_2__RegG8RC1_1,
  Convert__RegGPRC1_0__RegGPRC1_2__RegGPRC1_1,
  Convert__RegG8RC1_1__RegG8RC1_3__RegG8RC1_2,
  Convert__RegGPRC1_1__RegGPRC1_3__RegGPRC1_2,
  Convert__RegG8RC1_0__RegG8RC1_2__RegG8RC1_3__U1Imm1_1,
  Convert__RegG8RC1_1__RegG8RC1_3__RegG8RC1_4__U1Imm1_2,
  Convert__RegG8RC1_0__S16Imm1_1,
  Convert__U2Imm1_0,
  Convert__U3Imm1_0__imm_95_0,
  Convert__U3Imm1_0__U2Imm1_1,
  Convert__U5Imm1_1__RegGPRC1_2__RegGPRC1_3,
  Convert__U5Imm1_1__RegGPRC1_2__U5Imm1_3,
  Convert__U1Imm1_1,
  Convert__U5Imm1_0__RegG8RC1_1__RegG8RC1_2,
  Convert__imm_95_4__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_4__RegG8RC1_0__S16Imm1_1,
  Convert__imm_95_12__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_12__RegG8RC1_0__S16Imm1_1,
  Convert__imm_95_8__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_8__RegG8RC1_0__S16Imm1_1,
  Convert__U5Imm1_0__RegG8RC1_1__S16Imm1_2,
  Convert__imm_95_20__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_20__RegG8RC1_0__S16Imm1_1,
  Convert__imm_95_5__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_5__RegG8RC1_0__S16Imm1_1,
  Convert__imm_95_1__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_1__RegG8RC1_0__S16Imm1_1,
  Convert__imm_95_6__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_6__RegG8RC1_0__S16Imm1_1,
  Convert__imm_95_2__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_2__RegG8RC1_0__S16Imm1_1,
  Convert__imm_95_16__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_16__RegG8RC1_0__S16Imm1_1,
  Convert__imm_95_24__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_24__RegG8RC1_0__S16Imm1_1,
  Convert__imm_95_31__RegG8RC1_0__RegG8RC1_1,
  Convert__imm_95_31__RegG8RC1_0__S16Imm1_1,
  Convert__regR0__RegGPRC1_0,
  Convert__regR0__RegGPRC1_0__imm_95_0__imm_95_0__imm_95_0,
  Convert__RegGPRC1_1__RegGPRC1_0,
  Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0__imm_95_0__imm_95_0,
  Convert__RegGPRC1_0__RegGPRC1_1__U2Imm1_2__U1Imm1_3__U1Imm1_4,
  Convert__RegG8RC1_0__RegG8RC1_1__U2Imm1_2,
  Convert__U2Imm1_0__RegGPRC1_1__RegGPRC1_2,
  Convert__imm_95_0__regR0__regR0,
  Convert__imm_95_1__regR0__regR0,
  Convert__imm_95_3__regR0__RegGPRC1_0,
  Convert__imm_95_3__RegGPRC1_0__RegGPRC1_1,
  Convert__RegGPRC1_0__RegGPRC1_1__Imm1_2,
  Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0,
  Convert__RegGPRC1_0__RegGPRC1_1__imm_95_1,
  Convert__imm_95_31__regR0__regR0,
  Convert__U5Imm1_0__RegGPRC1_1__RegGPRC1_2,
  Convert__imm_95_4__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_4__RegGPRC1_0__S16Imm1_1,
  Convert__imm_95_12__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_12__RegGPRC1_0__S16Imm1_1,
  Convert__imm_95_8__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_8__RegGPRC1_0__S16Imm1_1,
  Convert__U5Imm1_0__RegGPRC1_1__S16Imm1_2,
  Convert__imm_95_20__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_20__RegGPRC1_0__S16Imm1_1,
  Convert__imm_95_5__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_5__RegGPRC1_0__S16Imm1_1,
  Convert__imm_95_1__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_1__RegGPRC1_0__S16Imm1_1,
  Convert__imm_95_6__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_6__RegGPRC1_0__S16Imm1_1,
  Convert__imm_95_2__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_2__RegGPRC1_0__S16Imm1_1,
  Convert__imm_95_16__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_16__RegGPRC1_0__S16Imm1_1,
  Convert__imm_95_24__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_24__RegGPRC1_0__S16Imm1_1,
  Convert__imm_95_31__RegGPRC1_0__RegGPRC1_1,
  Convert__imm_95_31__RegGPRC1_0__S16Imm1_1,
  Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2,
  Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3,
  Convert__RegVRRC1_0__U5Imm1_2__RegVRRC1_1,
  Convert__RegVRRC1_0__RegVRRC1_1__RegGPRC1_2,
  Convert__RegVRRC1_0__RegVRRC1_1,
  Convert__RegCRRC1_0__RegVRRC1_1__RegVRRC1_2,
  Convert__RegG8RC1_0__RegVRRC1_1__U1Imm1_2,
  Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3,
  Convert__RegVRRC1_0__U4Imm1_2__RegVRRC1_1,
  Convert__RegG8RC1_0__RegG8RC1_1__RegVRRC1_2,
  Convert__RegG8RC1_0__RegVRRC1_1__U3Imm1_2,
  Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegGPRC1_2,
  Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegVRRC1_2,
  Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegG8RC1_1,
  Convert__RegVRRC1_0__Tie0_1_1__RegG8RC1_1__RegG8RC1_2,
  Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegVRRC1_1,
  Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegGPRC1_1,
  Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_1,
  Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__Tie0_1_1,
  Convert__RegVRRC1_0__RegVRRC1_1__U1Imm1_2__U4Imm1_3,
  Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__U3Imm1_3,
  Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__U4Imm1_3,
  Convert__RegVRRC1_0__S5Imm1_1,
  Convert__RegVRRC1_0__RegVRRC1_1__U2Imm1_2,
  Convert__RegVRRC1_0__RegVRRC1_1__U3Imm1_2,
  Convert__RegVRRC1_0__RegVRRC1_1__U1Imm1_2,
  Convert__imm_95_1__imm_95_0,
  Convert__U2Imm1_0__U2Imm1_1,
  Convert__RegVSFRC1_0__RegVSFRC1_1,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2,
  Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2,
  Convert__RegVSSRC1_0__RegVSSRC1_1__RegVSSRC1_2,
  Convert__RegVSRC1_0__RegVSFRC1_1__RegVSFRC1_2,
  Convert__RegCRRC1_0__RegVSFRC1_1__RegVSFRC1_2,
  Convert__RegVRRC1_0__RegVFRC1_1,
  Convert__RegVSRC1_0__RegVSSRC1_1,
  Convert__RegVFRC1_0__RegVRRC1_1,
  Convert__RegVSSRC1_0__RegVSRC1_1,
  Convert__RegVSSRC1_0__RegVSFRC1_1,
  Convert__RegVSRC1_0__RegG8RC1_1__RegG8RC1_2,
  Convert__RegVRRC1_0__RegVRRC1_1__RegVSFRC1_2,
  Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2,
  Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2,
  Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2,
  Convert__RegVSSRC1_0__RegVSSRC1_1,
  Convert__RegVRRC1_1__U1Imm1_0__RegVRRC1_2__U2Imm1_3,
  Convert__RegCRRC1_0__RegVSFRC1_1,
  Convert__RegCRRC1_0__U7Imm1_2__RegVSFRC1_1,
  Convert__RegCRRC1_0__U7Imm1_2__RegVRRC1_1,
  Convert__RegCRRC1_0__U7Imm1_2__RegVSSRC1_1,
  Convert__RegVSRC1_0__RegVSRC1_1,
  Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2,
  Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2,
  Convert__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3,
  Convert__RegACCRC1_0__RegVSRpEvenRC1_1__RegVSRC1_2,
  Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2,
  Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1,
  Convert__RegCRRC1_0__RegVSRC1_1__RegVSRC1_2,
  Convert__RegCRRC1_0__RegVSRC1_1,
  Convert__RegVSRC1_0__U7Imm1_2__RegVSRC1_1,
  Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_0,
  Convert__RegVSRpRC1_0__RegVSRpRC1_1__imm_95_0,
  Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_1,
  Convert__RegVSRpRC1_0__RegVSRpRC1_1__imm_95_1,
  Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_2,
  Convert__RegVSRpRC1_0__RegVSRpRC1_1__imm_95_2,
  Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__U2Imm1_3,
  Convert__RegVSRpRC1_0__RegVSRpRC1_1__U2Imm1_2,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3__U8Imm1_4,
  Convert__RegVSFRC1_0__RegVSRC1_1__U4Imm1_2,
  Convert__RegVSRC1_0__RegVRRC1_1__S5Imm1_2,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_0,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_1,
  Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__U4Imm1_2,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_3,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U3Imm1_3,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3__U1Imm1_4__U1Imm1_5,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3__U1Imm1_4,
  Convert__RegVSRC1_0__RegVSRC1_1__Tie0_1_1__RegVSRC1_2,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U2Imm1_3,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3__U3Imm1_4,
  Convert__RegVSRC1_0__RegVSFRC1_1__imm_95_0,
  Convert__RegVSRC1_0__RegVSFRC1_1__imm_95_3,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1__imm_95_0,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1__imm_95_3,
  Convert__RegVSRC1_0__Tie0_1_1__U1Imm1_1__Imm1_2,
  Convert__RegVSRC1_0__U8Imm1_1,
  Convert__RegVSRC1_0__Imm1_1,
  Convert__RegVSRC1_0__RegVSRC1_1__U2Imm1_2,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3__U1Imm1_4,
  Convert__RegVSRC1_0__RegVSFRC1_1__imm_95_2,
  Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1__imm_95_2,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][15] = {
  // Convert__RegG8RC1_0__RegG8RC1_1__TLSReg1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addTLSRegOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__U2Imm1_3
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_1__S16Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 2, CVT_95_addS16ImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__S16Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addS16ImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__S16Imm1_3
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addS16ImmOperands, 4, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_1__S17Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 2, CVT_95_addS16ImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__Imm1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__U16Imm1_3
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addU16ImmOperands, 4, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__DirectBr1_0
  { CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__U5Imm1_0__RegCRBITRC1_1__CondBr1_2
  { CVT_95_addImmOperands, 1, CVT_95_addRegCRBITRCOperands, 2, CVT_95_addBranchTargetOperands, 3, CVT_Done },
  // Convert__U5Imm1_1__ATBitsAsHint1_0__RegCRBITRC1_2__CondBr1_3
  { CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegCRBITRCOperands, 3, CVT_95_addBranchTargetOperands, 4, CVT_Done },
  // Convert__U5Imm1_0__imm_95_3__RegCRBITRC1_1__CondBr1_2
  { CVT_95_addImmOperands, 1, CVT_imm_95_3, 0, CVT_95_addRegCRBITRCOperands, 2, CVT_95_addBranchTargetOperands, 3, CVT_Done },
  // Convert__U5Imm1_0__imm_95_2__RegCRBITRC1_1__CondBr1_2
  { CVT_95_addImmOperands, 1, CVT_imm_95_2, 0, CVT_95_addRegCRBITRCOperands, 2, CVT_95_addBranchTargetOperands, 3, CVT_Done },
  // Convert__U5Imm1_0__RegCRBITRC1_1__imm_95_0
  { CVT_95_addImmOperands, 1, CVT_95_addRegCRBITRCOperands, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__U5Imm1_0__RegCRBITRC1_1__Imm1_2
  { CVT_95_addImmOperands, 1, CVT_95_addRegCRBITRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3__U1Imm1_4
  { CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_95_addRegVRRCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegVRRC1_1__RegVRRC1_2__U1Imm1_3
  { CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3
  { CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_95_addRegVRRCOperands, 4, CVT_Done },
  // Convert__RegVRRC1_1__RegVRRC1_2
  { CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_Done },
  // Convert__CondBr1_0
  { CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_0__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_0, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_0__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_0, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_8__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_8, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_8__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_8, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_2__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_2, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_2__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_2, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_10__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_10, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_10__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_10, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_76__regCR0__CondBr1_0
  { CVT_imm_95_76, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_76__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_76, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_79__regCR0__CondBr1_0
  { CVT_imm_95_79, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_79__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_79, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_78__regCR0__CondBr1_0
  { CVT_imm_95_78, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_78__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_78, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_76__regCR0
  { CVT_imm_95_76, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_76__RegCRRC1_0
  { CVT_imm_95_76, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_79__regCR0
  { CVT_imm_95_79, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_79__RegCRRC1_0
  { CVT_imm_95_79, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_78__regCR0
  { CVT_imm_95_78, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_78__RegCRRC1_0
  { CVT_imm_95_78, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_4__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_4, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_7__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_7, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_6__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_6, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_4__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_4, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_7__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_7, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_6__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_6, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_4__regCR0__CondBr1_0
  { CVT_imm_95_4, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_4__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_4, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_7__regCR0__CondBr1_0
  { CVT_imm_95_7, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_7__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_7, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_6__regCR0__CondBr1_0
  { CVT_imm_95_6, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_6__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_6, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_4__regCR0
  { CVT_imm_95_4, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_4__RegCRRC1_0
  { CVT_imm_95_4, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_7__regCR0
  { CVT_imm_95_7, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_7__RegCRRC1_0
  { CVT_imm_95_7, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_6__regCR0
  { CVT_imm_95_6, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_6__RegCRRC1_0
  { CVT_imm_95_6, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_44__regCR0__CondBr1_0
  { CVT_imm_95_44, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_44__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_44, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_47__regCR0__CondBr1_0
  { CVT_imm_95_47, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_47__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_47, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_46__regCR0__CondBr1_0
  { CVT_imm_95_46, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_46__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_46, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_44__regCR0
  { CVT_imm_95_44, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_44__RegCRRC1_0
  { CVT_imm_95_44, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_47__regCR0
  { CVT_imm_95_47, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_47__RegCRRC1_0
  { CVT_imm_95_47, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_46__regCR0
  { CVT_imm_95_46, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_46__RegCRRC1_0
  { CVT_imm_95_46, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__DirectBr1_0__Imm1_1
  { CVT_95_addBranchTargetOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__imm_95_36__regCR0__CondBr1_0
  { CVT_imm_95_36, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_36__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_36, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_39__regCR0__CondBr1_0
  { CVT_imm_95_39, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_39__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_39, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_38__regCR0__CondBr1_0
  { CVT_imm_95_38, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_38__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_38, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_36__regCR0
  { CVT_imm_95_36, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_36__RegCRRC1_0
  { CVT_imm_95_36, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_39__regCR0
  { CVT_imm_95_39, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_39__RegCRRC1_0
  { CVT_imm_95_39, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_38__regCR0
  { CVT_imm_95_38, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_38__RegCRRC1_0
  { CVT_imm_95_38, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_12__regCR0__CondBr1_0
  { CVT_imm_95_12, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_12__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_12, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_15__regCR0__CondBr1_0
  { CVT_imm_95_15, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_15__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_15, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_14__regCR0__CondBr1_0
  { CVT_imm_95_14, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_14__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_14, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_12__regCR0
  { CVT_imm_95_12, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_12__RegCRRC1_0
  { CVT_imm_95_12, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_15__regCR0
  { CVT_imm_95_15, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_15__RegCRRC1_0
  { CVT_imm_95_15, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_14__regCR0
  { CVT_imm_95_14, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_14__RegCRRC1_0
  { CVT_imm_95_14, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_68__regCR0__CondBr1_0
  { CVT_imm_95_68, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_68__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_68, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_71__regCR0__CondBr1_0
  { CVT_imm_95_71, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_71__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_71, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_70__regCR0__CondBr1_0
  { CVT_imm_95_70, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_70__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_70, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_68__regCR0
  { CVT_imm_95_68, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_68__RegCRRC1_0
  { CVT_imm_95_68, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_71__regCR0
  { CVT_imm_95_71, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_71__RegCRRC1_0
  { CVT_imm_95_71, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_70__regCR0
  { CVT_imm_95_70, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_70__RegCRRC1_0
  { CVT_imm_95_70, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_100__regCR0__CondBr1_0
  { CVT_imm_95_100, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_100__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_100, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_103__regCR0__CondBr1_0
  { CVT_imm_95_103, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_103__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_103, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_102__regCR0__CondBr1_0
  { CVT_imm_95_102, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_102__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_102, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_100__regCR0
  { CVT_imm_95_100, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_100__RegCRRC1_0
  { CVT_imm_95_100, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_103__regCR0
  { CVT_imm_95_103, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_103__RegCRRC1_0
  { CVT_imm_95_103, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_102__regCR0
  { CVT_imm_95_102, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_102__RegCRRC1_0
  { CVT_imm_95_102, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_108__regCR0__CondBr1_0
  { CVT_imm_95_108, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_108__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_108, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_111__regCR0__CondBr1_0
  { CVT_imm_95_111, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_111__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_111, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_110__regCR0__CondBr1_0
  { CVT_imm_95_110, 0, CVT_regCR0, 0, CVT_95_addBranchTargetOperands, 1, CVT_Done },
  // Convert__imm_95_110__RegCRRC1_0__CondBr1_1
  { CVT_imm_95_110, 0, CVT_95_addRegCRRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_108__regCR0
  { CVT_imm_95_108, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_108__RegCRRC1_0
  { CVT_imm_95_108, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_111__regCR0
  { CVT_imm_95_111, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_111__RegCRRC1_0
  { CVT_imm_95_111, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_110__regCR0
  { CVT_imm_95_110, 0, CVT_regCR0, 0, CVT_Done },
  // Convert__imm_95_110__RegCRRC1_0
  { CVT_imm_95_110, 0, CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__imm_95_12__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_12, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_15__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_15, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_14__RegCRBITRC1_0__CondBr1_1
  { CVT_imm_95_14, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addBranchTargetOperands, 2, CVT_Done },
  // Convert__imm_95_12__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_12, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_15__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_15, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_14__RegCRBITRC1_0__imm_95_0
  { CVT_imm_95_14, 0, CVT_95_addRegCRBITRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__imm_95_0__U6Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_imm_95_0, 0, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegGPRC1_1__imm_95_0__U6Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_imm_95_0, 0, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__imm_95_0__U6Imm1_3
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_imm_95_0, 0, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__U6Imm1_3
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__imm_95_0__U5Imm1_2__imm_95_31
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_imm_95_0, 0, CVT_95_addImmOperands, 3, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0__U5Imm1_2__imm_95_31
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_imm_95_0, 0, CVT_95_addImmOperands, 3, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__imm_95_0__U5Imm1_3__imm_95_31
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_imm_95_0, 0, CVT_95_addImmOperands, 4, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__imm_95_0__U5Imm1_3__imm_95_31
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_imm_95_0, 0, CVT_95_addImmOperands, 4, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegCRRC1_0__RegGPRC1_2__RegGPRC1_3
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_Done },
  // Convert__RegCRRC1_0__RegG8RC1_2__RegG8RC1_3
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegG8RCOperands, 4, CVT_Done },
  // Convert__regCR0__RegG8RC1_0__RegG8RC1_1
  { CVT_regCR0, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegG8RC1_1__RegG8RC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__regCR0__RegG8RC1_0__S16Imm1_1
  { CVT_regCR0, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegG8RC1_1__S16Imm1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addS16ImmOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__RegGPRC1_2__S16Imm1_3
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegGPRCOperands, 3, CVT_95_addS16ImmOperands, 4, CVT_Done },
  // Convert__RegCRRC1_0__RegG8RC1_2__S16Imm1_3
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegG8RCOperands, 3, CVT_95_addS16ImmOperands, 4, CVT_Done },
  // Convert__regCR0__RegG8RC1_0__U16Imm1_1
  { CVT_regCR0, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addU16ImmOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegG8RC1_1__U16Imm1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addU16ImmOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__RegGPRC1_2__U16Imm1_3
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegGPRCOperands, 3, CVT_95_addU16ImmOperands, 4, CVT_Done },
  // Convert__RegCRRC1_0__RegG8RC1_2__U16Imm1_3
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegG8RCOperands, 3, CVT_95_addU16ImmOperands, 4, CVT_Done },
  // Convert__regCR0__RegGPRC1_0__RegGPRC1_1
  { CVT_regCR0, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegGPRC1_1__RegGPRC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__regCR0__RegGPRC1_0__U16Imm1_1
  { CVT_regCR0, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addU16ImmOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegGPRC1_1__U16Imm1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addU16ImmOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__U1Imm1_1__RegGPRC1_2__RegGPRC1_3
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_Done },
  // Convert__regCR0__RegGPRC1_0__S16Imm1_1
  { CVT_regCR0, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegGPRC1_1__S16Imm1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addS16ImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2
  { CVT_95_addRegCRBITRCOperands, 1, CVT_95_addRegCRBITRCOperands, 2, CVT_95_addRegCRBITRCOperands, 3, CVT_Done },
  // Convert__RegCRBITRC1_0__RegCRBITRC1_0__RegCRBITRC1_0
  { CVT_95_addRegCRBITRCOperands, 1, CVT_95_addRegCRBITRCOperands, 1, CVT_95_addRegCRBITRCOperands, 1, CVT_Done },
  // Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_1
  { CVT_95_addRegCRBITRCOperands, 1, CVT_95_addRegCRBITRCOperands, 2, CVT_95_addRegCRBITRCOperands, 2, CVT_Done },
  // Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_Done },
  // Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addRegF8RCOperands, 4, CVT_Done },
  // Convert__RegFpRC1_0__RegFpRC1_1__RegFpRC1_2
  { CVT_95_addRegFpRCOperands, 1, CVT_95_addRegFpRCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_Done },
  // Convert__RegFpRC1_1__RegFpRC1_2__RegFpRC1_3
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_95_addRegFpRCOperands, 4, CVT_Done },
  // Convert__RegG8RC1_0__U2Imm1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegGxRCNoR01_0__RegGxRC1_1
  { CVT_95_addRegGxRCNoR0Operands, 1, CVT_95_addRegGxRCOperands, 2, CVT_Done },
  // Convert__U3Imm1_2__RegGxRCNoR01_0__RegGxRC1_1
  { CVT_95_addImmOperands, 3, CVT_95_addRegGxRCNoR0Operands, 1, CVT_95_addRegGxRCOperands, 2, CVT_Done },
  // Convert__U5Imm1_2__RegGxRCNoR01_0__RegGxRC1_1
  { CVT_95_addImmOperands, 3, CVT_95_addRegGxRCNoR0Operands, 1, CVT_95_addRegGxRCOperands, 2, CVT_Done },
  // Convert__RegGxRCNoR01_0__RegGxRC1_1__U5Imm1_2
  { CVT_95_addRegGxRCNoR0Operands, 1, CVT_95_addRegGxRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegGxRCNoR01_1__RegGxRC1_2__U5Imm1_0
  { CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__regR0__regR0
  { CVT_regR0, 0, CVT_regR0, 0, CVT_Done },
  // Convert__RegF8RC1_0__RegF8RC1_1
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_Done },
  // Convert__RegF8RC1_1__RegF8RC1_2
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_Done },
  // Convert__RegFpRC1_0__RegF8RC1_1
  { CVT_95_addRegFpRCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_Done },
  // Convert__RegFpRC1_1__RegF8RC1_2
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_Done },
  // Convert__RegFpRC1_0__RegVRRC1_1
  { CVT_95_addRegFpRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegF8RC1_1__RegF8RC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__RegFpRC1_1__RegFpRC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegFpRCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_Done },
  // Convert__RegF8RC1_0__RegFpRC1_1
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegFpRCOperands, 2, CVT_Done },
  // Convert__RegF8RC1_1__RegFpRC1_2
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__RegFpRC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegFpRCOperands, 2, CVT_Done },
  // Convert__RegF8RC1_1__U2Imm1_0__RegF8RC1_2
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegF8RCOperands, 3, CVT_Done },
  // Convert__RegF8RC1_2__U2Imm1_1__RegF8RC1_3
  { CVT_95_addRegF8RCOperands, 3, CVT_95_addImmOperands, 2, CVT_95_addRegF8RCOperands, 4, CVT_Done },
  // Convert__RegFpRC1_1__U2Imm1_0__RegFpRC1_2
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegFpRCOperands, 3, CVT_Done },
  // Convert__RegFpRC1_2__U2Imm1_1__RegFpRC1_3
  { CVT_95_addRegFpRCOperands, 3, CVT_95_addImmOperands, 2, CVT_95_addRegFpRCOperands, 4, CVT_Done },
  // Convert__RegF8RC1_1__U1Imm1_0__RegF8RC1_2
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegF8RCOperands, 3, CVT_Done },
  // Convert__RegF8RC1_2__U1Imm1_1__RegF8RC1_3
  { CVT_95_addRegF8RCOperands, 3, CVT_95_addImmOperands, 2, CVT_95_addRegF8RCOperands, 4, CVT_Done },
  // Convert__RegFpRC1_1__U1Imm1_0__RegFpRC1_2
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegFpRCOperands, 3, CVT_Done },
  // Convert__RegFpRC1_2__U1Imm1_1__RegFpRC1_3
  { CVT_95_addRegFpRCOperands, 3, CVT_95_addImmOperands, 2, CVT_95_addRegFpRCOperands, 4, CVT_Done },
  // Convert__RegFpRC1_0__RegF8RC1_1__RegFpRC1_2
  { CVT_95_addRegFpRCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_Done },
  // Convert__RegFpRC1_1__RegF8RC1_2__RegFpRC1_3
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addRegFpRCOperands, 4, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegG8RCOperands, 4, CVT_Done },
  // Convert__RegDMRpRC1_0__Tie0_1_1__imm_95_12
  { CVT_95_addRegDMRpRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_imm_95_12, 0, CVT_Done },
  // Convert__RegDMRRC1_0__RegDMRRC1_1
  { CVT_95_addRegDMRRCOperands, 1, CVT_95_addRegDMRRCOperands, 2, CVT_Done },
  // Convert__RegDMRRC1_0
  { CVT_95_addRegDMRRCOperands, 1, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1__imm_95_0
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegDMRRCOperands, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1__U1Imm1_2
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegDMRRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegDMRpRC1_0__Tie0_1_1__imm_95_0
  { CVT_95_addRegDMRpRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegDMRpRC1_0__Tie0_1_1__U5Imm1_1
  { CVT_95_addRegDMRpRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1__imm_95_1
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegDMRRCOperands, 2, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegDMRRCOperands, 2, CVT_Done },
  // Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2
  { CVT_95_addRegDMRRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegVSRpRC1_0__RegDMRROWpRC1_1__U2Imm1_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegDMRROWpRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegACCRC1_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegACCRCOperands, 3, CVT_Done },
  // Convert__RegDMRROWpRC1_0__RegVSRpRC1_1__U2Imm1_2
  { CVT_95_addRegDMRROWpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegACCRC1_0__RegVSRpRC1_1__RegVSRpRC1_2
  { CVT_95_addRegACCRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRpRCOperands, 3, CVT_Done },
  // Convert__RegACCRC1_0__Tie0_1_1
  { CVT_95_addRegACCRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__RegACCRC1_0
  { CVT_95_addRegACCRCOperands, 1, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_3__imm_95_0__imm_95_0
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_3, 0, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_3
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_0, 0, CVT_95_addImmOperands, 3, CVT_imm_95_3, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_2
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_0, 0, CVT_95_addImmOperands, 3, CVT_imm_95_2, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_1
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_0, 0, CVT_95_addImmOperands, 3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_0
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_0, 0, CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_2__imm_95_0__imm_95_0
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_2, 0, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_1__U1Imm1_2__imm_95_1
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_1, 0, CVT_95_addImmOperands, 3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_1__U1Imm1_2__imm_95_0
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_1, 0, CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__U2Imm1_2__U1Imm1_3__U2Imm1_4
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__U2Imm1_3
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__U2Imm1_4
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addRegF8RCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegF8RC1_1__S5Imm1_0__RegF8RC1_2__U2Imm1_3
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegF8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegF8RC1_2__S5Imm1_1__RegF8RC1_3__U2Imm1_4
  { CVT_95_addRegF8RCOperands, 3, CVT_95_addImmOperands, 2, CVT_95_addRegF8RCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegFpRC1_1__S5Imm1_0__RegFpRC1_2__U2Imm1_3
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegFpRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegFpRC1_2__S5Imm1_1__RegFpRC1_3__U2Imm1_4
  { CVT_95_addRegFpRCOperands, 3, CVT_95_addImmOperands, 2, CVT_95_addRegFpRCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegFpRC1_0__RegFpRC1_1__RegFpRC1_2__U2Imm1_3
  { CVT_95_addRegFpRCOperands, 1, CVT_95_addRegFpRCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegFpRC1_1__RegFpRC1_2__RegFpRC1_3__U2Imm1_4
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_95_addRegFpRCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegFpRC1_0__RegFpRC1_1
  { CVT_95_addRegFpRCOperands, 1, CVT_95_addRegFpRCOperands, 2, CVT_Done },
  // Convert__RegFpRC1_1__RegFpRC1_2
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_Done },
  // Convert__RegF8RC1_1__U1Imm1_0__RegF8RC1_2__U2Imm1_3
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegF8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegF8RC1_2__U1Imm1_1__RegF8RC1_3__U2Imm1_4
  { CVT_95_addRegF8RCOperands, 3, CVT_95_addImmOperands, 2, CVT_95_addRegF8RCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegFpRC1_1__U1Imm1_0__RegFpRC1_2__U2Imm1_3
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegFpRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegFpRC1_2__U1Imm1_1__RegFpRC1_3__U2Imm1_4
  { CVT_95_addRegFpRCOperands, 3, CVT_95_addImmOperands, 2, CVT_95_addRegFpRCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegFpRC1_0__RegF8RC1_1__RegFpRC1_2__U2Imm1_3
  { CVT_95_addRegFpRCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegFpRC1_1__RegF8RC1_2__RegFpRC1_3__U2Imm1_4
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addRegFpRCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegF8RC1_0__RegF8RC1_1__U6Imm1_2
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegF8RC1_1__RegF8RC1_2__U6Imm1_3
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegFpRC1_0__RegFpRC1_1__U6Imm1_2
  { CVT_95_addRegFpRCOperands, 1, CVT_95_addRegFpRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegFpRC1_1__RegFpRC1_2__U6Imm1_3
  { CVT_95_addRegFpRCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__U5Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__U5Imm1_2__RegGPRC1_0__RegGPRC1_1
  { CVT_95_addImmOperands, 3, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegF8RC1_1__U6Imm1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__RegFpRC1_1__U6Imm1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegFpRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__U6Imm1_1__RegF8RC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__U6Imm1_1__RegFpRC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__RegF8RC1_1__RegFpRC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addRegFpRCOperands, 3, CVT_Done },
  // Convert__RegSPERC1_0__RegSPERC1_1
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addRegSPERCOperands, 2, CVT_Done },
  // Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addRegSPERCOperands, 2, CVT_95_addRegSPERCOperands, 3, CVT_Done },
  // Convert__RegSPERC1_0__RegGPRC1_1
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegSPERCOperands, 2, CVT_95_addRegSPERCOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__RegSPERC1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegSPERCOperands, 2, CVT_Done },
  // Convert__RegSPERC1_0__RegSPERC1_2__U5Imm1_1
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addRegSPERCOperands, 3, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegSPERC1_0__DispSPE81_1__RegGxRCNoR01_2
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegSPERC1_0__DispSPE21_1__RegGxRCNoR01_2
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegSPERC1_0__RegGPRC1_1__RegGPRC1_2
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__RegSPERC1_0__RegSPERC1_1__U5Imm1_2
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addRegSPERCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegSPERC1_1__RegSPERC1_2__RegSPERC1_3__imm_95_0
  { CVT_95_addRegSPERCOperands, 2, CVT_95_addRegSPERCOperands, 3, CVT_95_addRegSPERCOperands, 4, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegSPERC1_0__S5Imm1_1
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegSPERC1_0__U5Imm1_1__RegSPERC1_2
  { CVT_95_addRegSPERCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegSPERCOperands, 3, CVT_Done },
  // Convert__RegF4RC1_0__RegF4RC1_1
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addRegF4RCOperands, 2, CVT_Done },
  // Convert__RegF4RC1_1__RegF4RC1_2
  { CVT_95_addRegF4RCOperands, 2, CVT_95_addRegF4RCOperands, 3, CVT_Done },
  // Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addRegF4RCOperands, 2, CVT_95_addRegF4RCOperands, 3, CVT_Done },
  // Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3
  { CVT_95_addRegF4RCOperands, 2, CVT_95_addRegF4RCOperands, 3, CVT_95_addRegF4RCOperands, 4, CVT_Done },
  // Convert__RegF4RC1_0__RegF8RC1_1
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_Done },
  // Convert__RegF4RC1_1__RegF8RC1_2
  { CVT_95_addRegF4RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__RegF4RC1_1__RegF4RC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegF4RCOperands, 2, CVT_95_addRegF4RCOperands, 3, CVT_Done },
  // Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addRegF8RCOperands, 4, CVT_Done },
  // Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__RegF8RC1_4
  { CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addRegF8RCOperands, 4, CVT_95_addRegF8RCOperands, 5, CVT_Done },
  // Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addRegF4RCOperands, 2, CVT_95_addRegF4RCOperands, 3, CVT_95_addRegF4RCOperands, 4, CVT_Done },
  // Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3__RegF4RC1_4
  { CVT_95_addRegF4RCOperands, 2, CVT_95_addRegF4RCOperands, 3, CVT_95_addRegF4RCOperands, 4, CVT_95_addRegF4RCOperands, 5, CVT_Done },
  // Convert__RegF4RC1_0__RegF8RC1_1__RegF4RC1_2__RegF4RC1_3
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addRegF4RCOperands, 3, CVT_95_addRegF4RCOperands, 4, CVT_Done },
  // Convert__RegF4RC1_1__RegF8RC1_2__RegF4RC1_3__RegF4RC1_4
  { CVT_95_addRegF4RCOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addRegF4RCOperands, 4, CVT_95_addRegF4RCOperands, 5, CVT_Done },
  // Convert__RegCRRC1_0__RegF8RC1_1
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__DispRIHash1_1__RegGxRCNoR01_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__imm_95_0__imm_95_0
  { CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_0
  { CVT_imm_95_0, 0, CVT_Done },
  // Convert__U4Imm1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addImmOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__U4Imm1_1__RegGxRCNoR01_2__RegGxRC1_3
  { CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_95_addRegGxRCOperands, 4, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__RegCRBITRC1_3
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegCRBITRCOperands, 4, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC_NOX01_1__RegG8RC1_2__regCR0EQ
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RC_95_NOX0Operands, 2, CVT_95_addRegG8RCOperands, 3, CVT_regCR0EQ, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__regCR0EQ
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 2, CVT_95_addRegGPRCOperands, 3, CVT_regCR0EQ, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC_NOX01_1__RegG8RC1_2__regCR0GT
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RC_95_NOX0Operands, 2, CVT_95_addRegG8RCOperands, 3, CVT_regCR0GT, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__regCR0GT
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 2, CVT_95_addRegGPRCOperands, 3, CVT_regCR0GT, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC_NOX01_1__RegG8RC1_2__regCR0LT
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RC_95_NOX0Operands, 2, CVT_95_addRegG8RCOperands, 3, CVT_regCR0LT, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__regCR0LT
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 2, CVT_95_addRegGPRCOperands, 3, CVT_regCR0LT, 0, CVT_Done },
  // Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_0, 0, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_0, 0, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addTLSRegOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__DispRIX1_1__RegGxRCNoR01_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegG8pRC1_0__Tie0_1_1__RegGxRCNoR01_1__U5Imm1_2
  { CVT_95_addRegG8pRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_0__DispRIX1_1__RegGxRCNoR01_2
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_0, 0, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_0, 0, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegF8RC1_0__DispRI1_1__RegGxRCNoR01_2
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegF8RC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2
  { CVT_95_addRegF8RCOperands, 1, CVT_imm_95_0, 0, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegF8RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegF8RCOperands, 1, CVT_imm_95_0, 0, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegF8RC1_0__RegGxRCNoR01_1__TLSReg1_2
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addTLSRegOperands, 3, CVT_Done },
  // Convert__RegF4RC1_0__DispRI1_1__RegGxRCNoR01_2
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegF4RC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2
  { CVT_95_addRegF4RCOperands, 1, CVT_imm_95_0, 0, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegF4RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegF4RCOperands, 1, CVT_imm_95_0, 0, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegF4RC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegF4RC1_0__RegGxRCNoR01_1__TLSReg1_2
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addTLSRegOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__regZERO8__S16Imm1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_regZERO8, 0, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__S16Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__regZERO__S16Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_regZERO, 0, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__RegG8RC1_0__regZERO8__S17Imm1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_regZERO8, 0, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__S17Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__regZERO__S17Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_regZERO, 0, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_0
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegG8pRC1_0__DispRIX161_1__RegGxRCNoR01_2
  { CVT_95_addRegG8pRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegG8pRC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegG8pRCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__imm_95_1
  { CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegVFRC1_0__DispRIX1_1__RegGxRCNoR01_2
  { CVT_95_addRegVFRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegVSFRCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegVSSRC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegVSSRCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__DispRIX161_1__RegGxRCNoR01_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__U5Imm1_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__RegVSRpRC1_0__DispRIX161_1__RegGxRCNoR01_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegVSRpRC1_0__Imm1_1__RegG8RC1_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__RegVSRpRC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegG8RCOperands, 4, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_Done },
  // Convert__RegCRRC1_0__RegCRRC1_1
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegCRRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0
  { CVT_95_addRegCRRCOperands, 1, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_29
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_29, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_29
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_29, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_280
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_280, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_280
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_280, 0, CVT_Done },
  // Convert__RegGPRC1_0__U10Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_128
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_128, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_129
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_129, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_130
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_130, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_131
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_131, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_132
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_132, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_133
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_133, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_134
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_134, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_135
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_135, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_28
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_28, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_28
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_28, 0, CVT_Done },
  // Convert__RegGPRC1_0
  { CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_9
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_9, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_9
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_9, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_19
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_19, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_19
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_19, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_537
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_537, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_539
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_539, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_541
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_541, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_543
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_543, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_536
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_536, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_538
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_538, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_540
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_540, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_542
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_542, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_1018
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_1018, 0, CVT_Done },
  // Convert__RegGPRC1_0__Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_981
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_981, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_22
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_22, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_22
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_22, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_17
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_17, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_17
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_17, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_18
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_18, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_18
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_18, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_980
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_980, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegF8RC1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__RegF8RC1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_Done },
  // Convert__RegF8RC1_0
  { CVT_95_addRegF8RCOperands, 1, CVT_Done },
  // Convert__RegF8RC1_1
  { CVT_95_addRegF8RCOperands, 2, CVT_Done },
  // Convert__RegF8RC1_0__U3Imm1_1
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegF8RC1_0__U2Imm1_1
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_529
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_529, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_531
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_531, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_533
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_533, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_535
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_535, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_528
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_528, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_530
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_530, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_532
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_532, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_534
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_534, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_1019
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_1019, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_8
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_8, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_8
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_8, 0, CVT_Done },
  // Convert__RegGPRC1_0__CRBitMask1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addCRBitMaskOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_48
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_48, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_896
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_896, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_287
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_287, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_287
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_287, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_5
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_5, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_5
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_5, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_4
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_4, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_4
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_4, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_25
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_25, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_25
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_25, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_512
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_512, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_512
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_512, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_272
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_272, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_273
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_273, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_274
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_274, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_275
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_275, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_272
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_272, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_273
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_273, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_274
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_274, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_275
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_275, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_260
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_260, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_261
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_261, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_262
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_262, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_263
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_263, 0, CVT_Done },
  // Convert__RegGPRC1_0__U4Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_26
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_26, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_26
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_26, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_27
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_27, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_27
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_27, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_990
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_990, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_991
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_991, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_268
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_268, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_988
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_988, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_989
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_989, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_269
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_269, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_986
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_986, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_13
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_13, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_13
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_13, 0, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_3
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_3, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_3
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_3, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegVRRC1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__RegVRRC1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0
  { CVT_95_addRegVRRCOperands, 1, CVT_Done },
  // Convert__RegG8RC1_0__RegVSFRC1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_Done },
  // Convert__RegG8RC1_0__RegVSRC1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__RegVSFRC1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_Done },
  // Convert__RegG8RC1_0__imm_95_1
  { CVT_95_addRegG8RCOperands, 1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_1
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_2
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_2
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__imm_95_29__RegG8RC1_0
  { CVT_imm_95_29, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_29__RegGPRC1_0
  { CVT_imm_95_29, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_280__RegG8RC1_0
  { CVT_imm_95_280, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_280__RegGPRC1_0
  { CVT_imm_95_280, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_28__RegG8RC1_0
  { CVT_imm_95_28, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_28__RegGPRC1_0
  { CVT_imm_95_28, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_255__RegG8RC1_0
  { CVT_imm_95_255, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_255__RegGPRC1_0
  { CVT_imm_95_255, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__Imm1_0__RegGPRC1_1
  { CVT_95_addImmOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_9__RegG8RC1_0
  { CVT_imm_95_9, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_9__RegGPRC1_0
  { CVT_imm_95_9, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_19__RegG8RC1_0
  { CVT_imm_95_19, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_19__RegGPRC1_0
  { CVT_imm_95_19, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_537__RegGPRC1_1
  { CVT_imm_95_537, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_539__RegGPRC1_1
  { CVT_imm_95_539, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_541__RegGPRC1_1
  { CVT_imm_95_541, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_543__RegGPRC1_1
  { CVT_imm_95_543, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_536__RegGPRC1_1
  { CVT_imm_95_536, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_538__RegGPRC1_1
  { CVT_imm_95_538, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_540__RegGPRC1_1
  { CVT_imm_95_540, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_542__RegGPRC1_1
  { CVT_imm_95_542, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_1018__RegGPRC1_0
  { CVT_imm_95_1018, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__RegGPRC1_1__Imm1_0
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__imm_95_981__RegGPRC1_0
  { CVT_imm_95_981, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_22__RegG8RC1_0
  { CVT_imm_95_22, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_22__RegGPRC1_0
  { CVT_imm_95_22, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_17__RegG8RC1_0
  { CVT_imm_95_17, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_17__RegGPRC1_0
  { CVT_imm_95_17, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_18__RegG8RC1_0
  { CVT_imm_95_18, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_18__RegGPRC1_0
  { CVT_imm_95_18, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_980__RegGPRC1_0
  { CVT_imm_95_980, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__RegF8RC1_0__RegG8RC1_1
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__RegF8RC1_0__RegGPRC1_1
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__Imm1_0__RegF8RC1_1__imm_95_0__imm_95_0
  { CVT_95_addImmOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Imm1_1__RegF8RC1_2__imm_95_0__imm_95_0
  { CVT_95_addImmOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Imm1_0__RegF8RC1_1__U1Imm1_2__Imm1_3
  { CVT_95_addImmOperands, 1, CVT_95_addRegF8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Imm1_1__RegF8RC1_2__U1Imm1_3__Imm1_4
  { CVT_95_addImmOperands, 2, CVT_95_addRegF8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__U3Imm1_0__U4Imm1_1__imm_95_0
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__U3Imm1_1__U4Imm1_2__imm_95_0
  { CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__U3Imm1_0__U4Imm1_1__Imm1_2
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__U3Imm1_1__U4Imm1_2__U1Imm1_3
  { CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__imm_95_529__RegGPRC1_1
  { CVT_imm_95_529, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_531__RegGPRC1_1
  { CVT_imm_95_531, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_533__RegGPRC1_1
  { CVT_imm_95_533, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_535__RegGPRC1_1
  { CVT_imm_95_535, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_528__RegGPRC1_1
  { CVT_imm_95_528, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_530__RegGPRC1_1
  { CVT_imm_95_530, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_532__RegGPRC1_1
  { CVT_imm_95_532, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_534__RegGPRC1_1
  { CVT_imm_95_534, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_1019__RegGPRC1_0
  { CVT_imm_95_1019, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_8__RegG8RC1_0
  { CVT_imm_95_8, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_8__RegGPRC1_0
  { CVT_imm_95_8, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__RegGPRC1_0__imm_95_0
  { CVT_95_addRegGPRCOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegGPRC1_0__U1Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__CRBitMask1_0__RegGPRC1_1
  { CVT_95_addCRBitMaskOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_48__RegGPRC1_0
  { CVT_imm_95_48, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_896__RegGPRC1_0
  { CVT_imm_95_896, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_25__RegG8RC1_0
  { CVT_imm_95_25, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_25__RegGPRC1_0
  { CVT_imm_95_25, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_512__RegG8RC1_0
  { CVT_imm_95_512, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_512__RegGPRC1_0
  { CVT_imm_95_512, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__RegGPRC1_1
  { CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_272__RegG8RC1_1
  { CVT_imm_95_272, 0, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_272__RegGPRC1_1
  { CVT_imm_95_272, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_273__RegG8RC1_1
  { CVT_imm_95_273, 0, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_273__RegGPRC1_1
  { CVT_imm_95_273, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_274__RegG8RC1_1
  { CVT_imm_95_274, 0, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_274__RegGPRC1_1
  { CVT_imm_95_274, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_275__RegG8RC1_1
  { CVT_imm_95_275, 0, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_275__RegGPRC1_1
  { CVT_imm_95_275, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_260__RegGPRC1_1
  { CVT_imm_95_260, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_261__RegGPRC1_1
  { CVT_imm_95_261, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_262__RegGPRC1_1
  { CVT_imm_95_262, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_263__RegGPRC1_1
  { CVT_imm_95_263, 0, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_272__RegG8RC1_0
  { CVT_imm_95_272, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_272__RegGPRC1_0
  { CVT_imm_95_272, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_273__RegG8RC1_0
  { CVT_imm_95_273, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_273__RegGPRC1_0
  { CVT_imm_95_273, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_274__RegG8RC1_0
  { CVT_imm_95_274, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_274__RegGPRC1_0
  { CVT_imm_95_274, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_275__RegG8RC1_0
  { CVT_imm_95_275, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_275__RegGPRC1_0
  { CVT_imm_95_275, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_260__RegGPRC1_0
  { CVT_imm_95_260, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_261__RegGPRC1_0
  { CVT_imm_95_261, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_262__RegGPRC1_0
  { CVT_imm_95_262, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_263__RegGPRC1_0
  { CVT_imm_95_263, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__RegGPRC1_1__U4Imm1_0
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__imm_95_26__RegG8RC1_0
  { CVT_imm_95_26, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_26__RegGPRC1_0
  { CVT_imm_95_26, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_27__RegG8RC1_0
  { CVT_imm_95_27, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_27__RegGPRC1_0
  { CVT_imm_95_27, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_990__RegGPRC1_0
  { CVT_imm_95_990, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_991__RegGPRC1_0
  { CVT_imm_95_991, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_988__RegGPRC1_0
  { CVT_imm_95_988, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_284__RegG8RC1_0
  { CVT_imm_95_284, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_284__RegGPRC1_0
  { CVT_imm_95_284, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_989__RegGPRC1_0
  { CVT_imm_95_989, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_285__RegG8RC1_0
  { CVT_imm_95_285, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_285__RegGPRC1_0
  { CVT_imm_95_285, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_986__RegGPRC1_0
  { CVT_imm_95_986, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_13__RegG8RC1_0
  { CVT_imm_95_13, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_13__RegGPRC1_0
  { CVT_imm_95_13, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_3__RegG8RC1_0
  { CVT_imm_95_3, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_3__RegGPRC1_0
  { CVT_imm_95_3, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__RegVRRC1_0__RegG8RC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0__RegGPRC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0__U16Imm1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addU16ImmOperands, 2, CVT_Done },
  // Convert__RegVSFRC1_0__RegG8RC1_1
  { CVT_95_addRegVSFRCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__RegG8RC_NOX01_1__RegG8RC1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegG8RC_95_NOX0Operands, 2, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__RegVSFRC1_0__RegGPRC1_1
  { CVT_95_addRegVSFRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__RegGPRC1_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_1__RegG8RC1_0
  { CVT_imm_95_1, 0, CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__imm_95_1__RegGPRC1_0
  { CVT_imm_95_1, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__regR0__regR0__imm_95_0
  { CVT_regR0, 0, CVT_regR0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__regX0__regX0__imm_95_0
  { CVT_regX0, 0, CVT_regX0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__U16Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addU16ImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC_NOX01_1__S34Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RC_95_NOX0Operands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__ImmZero1_1__S34Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_1__S34Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC_NOX01_1__S32Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RC_95_NOX0Operands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_1__S32Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__ImmZero1_1__S32Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__imm_95_1
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__U1Imm1_3
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__imm_95_2__imm_95_0
  { CVT_imm_95_2, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__imm_95_4__imm_95_0
  { CVT_imm_95_4, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegG8RC1_0__S34Imm1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__S34Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC_NOX01_2__S34Imm1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RC_95_NOX0Operands, 3, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_2__S34Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 3, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__DispRI341_1__RegGxRCNoR01_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegG8RC1_0__DispRI341_1__ImmZero1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegF8RC1_0__S34Imm1_1
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegF8RC1_0__DispRI341_1__RegGxRCNoR01_2
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegF8RC1_0__DispRI341_1__ImmZero1_2
  { CVT_95_addRegF8RCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegF4RC1_0__S34Imm1_1
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegF4RC1_0__DispRI341_1__RegGxRCNoR01_2
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegF4RC1_0__DispRI341_1__ImmZero1_2
  { CVT_95_addRegF4RCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__regZERO8__S32Imm1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_regZERO8, 0, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__regZERO__S32Imm1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_regZERO, 0, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__imm_95_5__imm_95_0
  { CVT_imm_95_5, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegVFRC1_0__S34Imm1_1
  { CVT_95_addRegVFRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2
  { CVT_95_addRegVFRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegVFRC1_0__DispRI341_1__ImmZero1_2
  { CVT_95_addRegVFRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__S34Imm1_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__DispRI341_1__RegGxRCNoR01_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegVSRC1_0__DispRI341_1__ImmZero1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVSRpRC1_0__S34Imm1_1
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegVSRpRC1_0__DispRI341_1__RegGxRCNoR01_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegVSRpRC1_0__DispRI341_1__ImmZero1_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5
  { CVT_95_addRegDMRRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U4Imm1_5
  { CVT_95_addRegDMRRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U4Imm1_5
  { CVT_95_addRegDMRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5
  { CVT_95_addRegACCRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5
  { CVT_95_addRegACCRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4
  { CVT_95_addRegACCRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4
  { CVT_95_addRegACCRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegACCRC1_0__RegVSRpEvenRC1_1__RegVSRC1_2__U4Imm1_3__U2Imm1_4
  { CVT_95_addRegACCRCOperands, 1, CVT_95_addRegVSRpEvenRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2__U4Imm1_3__U2Imm1_4
  { CVT_95_addRegACCRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRpEvenRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U8Imm1_5
  { CVT_95_addRegACCRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U8Imm1_5
  { CVT_95_addRegACCRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U4Imm1_5
  { CVT_95_addRegACCRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U4Imm1_5
  { CVT_95_addRegACCRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC_NOX01_1__NegS32Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RC_95_NOX0Operands, 2, CVT_95_addNegImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC_NOR01_1__NegS32Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRC_95_NOR0Operands, 2, CVT_95_addNegImmOperands, 3, CVT_Done },
  // Convert__imm_95_2
  { CVT_imm_95_2, 0, CVT_Done },
  // Convert__RegG8RC1_0
  { CVT_95_addRegG8RCOperands, 1, CVT_Done },
  // Convert__U1Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2__U6Imm1_3
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3__U6Imm1_4
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegG8RC1_0__Tie0_1_1__RegG8RC1_1__U6Imm1_2__U6Imm1_3
  { CVT_95_addRegG8RCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegG8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegG8RC1_1__Tie0_1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4
  { CVT_95_addRegG8RCOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addRegG8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__U5Imm1_2__Imm1_3
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__U5Imm1_3__Imm1_4
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegGPRC1_0__Tie0_1_1__RegGPRC1_1__U5Imm1_2__U5Imm1_3__U5Imm1_4
  { CVT_95_addRegGPRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegGPRC1_1__Tie0_1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4__U5Imm1_5
  { CVT_95_addRegGPRCOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3__U5Imm1_4
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4__U5Imm1_5
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3__U5Imm1_4__U5Imm1_5
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2__imm_95_0
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3__imm_95_0
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__imm_95_0
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegGPRC1_1__U6Imm1_2__imm_95_0
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__imm_95_0
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2__imm_95_0__imm_95_31
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_imm_95_0, 0, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__imm_95_0__imm_95_31
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_imm_95_0, 0, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3__imm_95_0__imm_95_31
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegG8RCOperands, 4, CVT_imm_95_0, 0, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3__imm_95_0__imm_95_31
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_imm_95_0, 0, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__U5Imm1_2__imm_95_0__imm_95_31
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__imm_95_0__imm_95_31
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__U5Imm1_3__imm_95_0__imm_95_31
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addImmOperands, 4, CVT_imm_95_0, 0, CVT_imm_95_31, 0, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__imm_95_0__imm_95_31
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_imm_95_0, 0, CVT_imm_95_31, 0, CVT_Done },
  // Convert__Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__RegGPRC1_0__RegCRRC1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegCRRCOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__RegCRBITRC1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegCRBITRCOperands, 2, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_Done },
  // Convert__RegGPRC1_1__RegGxRCNoR01_2__RegGxRC1_3
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_95_addRegGxRCOperands, 4, CVT_Done },
  // Convert__imm_95_0__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2
  { CVT_imm_95_0, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__imm_95_0__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_imm_95_0, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__imm_95_0__imm_95_2
  { CVT_imm_95_0, 0, CVT_imm_95_2, 0, CVT_Done },
  // Convert__RegG8RC1_0__RegGxRCNoR01_1__U5Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_1__RegGxRCNoR01_2__RegGxRC1_3
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_95_addRegGxRCOperands, 4, CVT_Done },
  // Convert__imm_95_0__RegG8RC1_0__DispRIX1_1__RegGxRCNoR01_2
  { CVT_imm_95_0, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__imm_95_0__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_imm_95_0, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__imm_95_0__RegF8RC1_0__DispRI1_1__RegGxRCNoR01_2
  { CVT_imm_95_0, 0, CVT_95_addRegF8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__imm_95_0__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_imm_95_0, 0, CVT_95_addRegF8RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__imm_95_0__RegF4RC1_0__DispRI1_1__RegGxRCNoR01_2
  { CVT_imm_95_0, 0, CVT_95_addRegF4RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__imm_95_0__RegF4RC1_0__RegGxRCNoR01_1__RegGxRC1_2
  { CVT_imm_95_0, 0, CVT_95_addRegF4RCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addRegGxRCOperands, 3, CVT_Done },
  // Convert__imm_95_1__imm_95_1
  { CVT_imm_95_1, 0, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegG8pRC1_0__DispRIX1_1__RegGxRCNoR01_2
  { CVT_95_addRegG8pRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_Done },
  // Convert__RegG8pRC1_1__RegGxRCNoR01_2__RegGxRC1_3
  { CVT_95_addRegG8pRCOperands, 2, CVT_95_addRegGxRCNoR0Operands, 3, CVT_95_addRegGxRCOperands, 4, CVT_Done },
  // Convert__imm_95_0__imm_95_3
  { CVT_imm_95_0, 0, CVT_imm_95_3, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGxRCNoR01_1__U5Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGxRCNoR0Operands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_2__RegG8RC1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_2__RegGPRC1_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_3__RegG8RC1_2
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 4, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_3__RegGPRC1_2
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 4, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_2__RegG8RC1_3__U1Imm1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 3, CVT_95_addRegG8RCOperands, 4, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegG8RC1_1__RegG8RC1_3__RegG8RC1_4__U1Imm1_2
  { CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 4, CVT_95_addRegG8RCOperands, 5, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__S16Imm1_1
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__U2Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__U3Imm1_0__imm_95_0
  { CVT_95_addImmOperands, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__U3Imm1_0__U2Imm1_1
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__U5Imm1_1__RegGPRC1_2__RegGPRC1_3
  { CVT_95_addImmOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_Done },
  // Convert__U5Imm1_1__RegGPRC1_2__U5Imm1_3
  { CVT_95_addImmOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__U1Imm1_1
  { CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__U5Imm1_0__RegG8RC1_1__RegG8RC1_2
  { CVT_95_addImmOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__imm_95_4__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_4, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_4__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_4, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_12__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_12, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_12__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_12, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_8__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_8, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_8__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_8, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__U5Imm1_0__RegG8RC1_1__S16Imm1_2
  { CVT_95_addImmOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addS16ImmOperands, 3, CVT_Done },
  // Convert__imm_95_20__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_20, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_20__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_20, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_5__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_5, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_5__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_5, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_1__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_1, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_1__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_1, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_6__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_6, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_6__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_6, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_2__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_2, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_2__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_2, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_16__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_16, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_16__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_16, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_24__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_24, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_24__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_24, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_31__RegG8RC1_0__RegG8RC1_1
  { CVT_imm_95_31, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__imm_95_31__RegG8RC1_0__S16Imm1_1
  { CVT_imm_95_31, 0, CVT_95_addRegG8RCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__regR0__RegGPRC1_0
  { CVT_regR0, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__regR0__RegGPRC1_0__imm_95_0__imm_95_0__imm_95_0
  { CVT_regR0, 0, CVT_95_addRegGPRCOperands, 1, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegGPRC1_1__RegGPRC1_0
  { CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0__imm_95_0__imm_95_0
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__U2Imm1_2__U1Imm1_3__U1Imm1_4
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__U2Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__U2Imm1_0__RegGPRC1_1__RegGPRC1_2
  { CVT_95_addImmOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__imm_95_0__regR0__regR0
  { CVT_imm_95_0, 0, CVT_regR0, 0, CVT_regR0, 0, CVT_Done },
  // Convert__imm_95_1__regR0__regR0
  { CVT_imm_95_1, 0, CVT_regR0, 0, CVT_regR0, 0, CVT_Done },
  // Convert__imm_95_3__regR0__RegGPRC1_0
  { CVT_imm_95_3, 0, CVT_regR0, 0, CVT_95_addRegGPRCOperands, 1, CVT_Done },
  // Convert__imm_95_3__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_3, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__Imm1_2
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegGPRC1_0__RegGPRC1_1__imm_95_1
  { CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_imm_95_1, 0, CVT_Done },
  // Convert__imm_95_31__regR0__regR0
  { CVT_imm_95_31, 0, CVT_regR0, 0, CVT_regR0, 0, CVT_Done },
  // Convert__U5Imm1_0__RegGPRC1_1__RegGPRC1_2
  { CVT_95_addImmOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__imm_95_4__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_4, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_4__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_4, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_12__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_12, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_12__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_12, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_8__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_8, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_8__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_8, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__U5Imm1_0__RegGPRC1_1__S16Imm1_2
  { CVT_95_addImmOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_95_addS16ImmOperands, 3, CVT_Done },
  // Convert__imm_95_20__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_20, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_20__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_20, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_5__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_5, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_5__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_5, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_1__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_1, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_1__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_1, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_6__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_6, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_6__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_6, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_2__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_2, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_2__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_2, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_16__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_16, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_16__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_16, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_24__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_24, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_24__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_24, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__imm_95_31__RegGPRC1_0__RegGPRC1_1
  { CVT_imm_95_31, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__imm_95_31__RegGPRC1_0__S16Imm1_1
  { CVT_imm_95_31, 0, CVT_95_addRegGPRCOperands, 1, CVT_95_addS16ImmOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_95_addRegVRRCOperands, 4, CVT_Done },
  // Convert__RegVRRC1_0__U5Imm1_2__RegVRRC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addImmOperands, 3, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__RegGPRC1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegVRRC1_1__RegVRRC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegVRRC1_1__U1Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_95_addRegGPRCOperands, 4, CVT_Done },
  // Convert__RegVRRC1_0__U4Imm1_2__RegVRRC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addImmOperands, 3, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegG8RC1_0__RegG8RC1_1__RegVRRC1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_Done },
  // Convert__RegG8RC1_0__RegVRRC1_1__U3Imm1_2
  { CVT_95_addRegG8RCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegGPRC1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegGPRCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegVRRC1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegGPRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegG8RC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 3, CVT_95_addRegG8RCOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0__Tie0_1_1__RegG8RC1_1__RegG8RC1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegVRRC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 3, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegGPRC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 3, CVT_95_addRegGPRCOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__Tie0_1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__U1Imm1_2__U4Imm1_3
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__U3Imm1_3
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__U4Imm1_3
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegVRRC1_0__S5Imm1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__U2Imm1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__U3Imm1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__U1Imm1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__imm_95_1__imm_95_0
  { CVT_imm_95_1, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__U2Imm1_0__U2Imm1_1
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegVSFRC1_0__RegVSFRC1_1
  { CVT_95_addRegVSFRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2
  { CVT_95_addRegVSFRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_95_addRegVSFRCOperands, 3, CVT_Done },
  // Convert__RegVSSRC1_0__RegVSSRC1_1__RegVSSRC1_2
  { CVT_95_addRegVSSRCOperands, 1, CVT_95_addRegVSSRCOperands, 2, CVT_95_addRegVSSRCOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__RegVSFRC1_1__RegVSFRC1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_95_addRegVSFRCOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__RegVSFRC1_1__RegVSFRC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_95_addRegVSFRCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__RegVFRC1_1
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVFRCOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__RegVSSRC1_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSSRCOperands, 2, CVT_Done },
  // Convert__RegVFRC1_0__RegVRRC1_1
  { CVT_95_addRegVFRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegVSSRC1_0__RegVSRC1_1
  { CVT_95_addRegVSSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_Done },
  // Convert__RegVSSRC1_0__RegVSFRC1_1
  { CVT_95_addRegVSSRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__RegG8RC1_1__RegG8RC1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegG8RCOperands, 2, CVT_95_addRegG8RCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__RegVRRC1_1__RegVSFRC1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVSFRCOperands, 3, CVT_Done },
  // Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2
  { CVT_95_addRegVSFRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSFRCOperands, 2, CVT_95_addRegVSFRCOperands, 3, CVT_Done },
  // Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2
  { CVT_95_addRegVSSRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSSRCOperands, 2, CVT_95_addRegVSSRCOperands, 3, CVT_Done },
  // Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2
  { CVT_95_addRegVRRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVRRCOperands, 2, CVT_95_addRegVRRCOperands, 3, CVT_Done },
  // Convert__RegVSSRC1_0__RegVSSRC1_1
  { CVT_95_addRegVSSRCOperands, 1, CVT_95_addRegVSSRCOperands, 2, CVT_Done },
  // Convert__RegVRRC1_1__U1Imm1_0__RegVRRC1_2__U2Imm1_3
  { CVT_95_addRegVRRCOperands, 2, CVT_95_addImmOperands, 1, CVT_95_addRegVRRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegCRRC1_0__RegVSFRC1_1
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__U7Imm1_2__RegVSFRC1_1
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addImmOperands, 3, CVT_95_addRegVSFRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__U7Imm1_2__RegVRRC1_1
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addImmOperands, 3, CVT_95_addRegVRRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__U7Imm1_2__RegVSSRC1_1
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addImmOperands, 3, CVT_95_addRegVSSRCOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_Done },
  // Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2
  { CVT_95_addRegACCRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2
  { CVT_95_addRegACCRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3
  { CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addRegVSRCOperands, 4, CVT_Done },
  // Convert__RegACCRC1_0__RegVSRpEvenRC1_1__RegVSRC1_2
  { CVT_95_addRegACCRCOperands, 1, CVT_95_addRegVSRpEvenRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2
  { CVT_95_addRegACCRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRpEvenRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 2, CVT_Done },
  // Convert__RegCRRC1_0__RegVSRC1_1__RegVSRC1_2
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegCRRC1_0__RegVSRC1_1
  { CVT_95_addRegCRRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__U7Imm1_2__RegVSRC1_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addImmOperands, 3, CVT_95_addRegVSRCOperands, 2, CVT_Done },
  // Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_0
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRpRCOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegVSRpRC1_0__RegVSRpRC1_1__imm_95_0
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_1
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRpRCOperands, 3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegVSRpRC1_0__RegVSRpRC1_1__imm_95_1
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRpRCOperands, 3, CVT_imm_95_2, 0, CVT_Done },
  // Convert__RegVSRpRC1_0__RegVSRpRC1_1__imm_95_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_imm_95_2, 0, CVT_Done },
  // Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__U2Imm1_3
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addRegVSRpRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegVSRpRC1_0__RegVSRpRC1_1__U2Imm1_2
  { CVT_95_addRegVSRpRCOperands, 1, CVT_95_addRegVSRpRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addRegVSRCOperands, 4, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3__U8Imm1_4
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addRegVSRCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegVSFRC1_0__RegVSRC1_1__U4Imm1_2
  { CVT_95_addRegVSFRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__RegVRRC1_1__S5Imm1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVRRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_0
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__U4Imm1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_3
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_imm_95_3, 0, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U3Imm1_3
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3__U1Imm1_4__U1Imm1_5
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 6, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3__U1Imm1_4
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__Tie0_1_1__RegVSRC1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addRegVSRCOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U2Imm1_3
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3__U3Imm1_4
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addRegVSRCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegVSRC1_0__RegVSFRC1_1__imm_95_0
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegVSRC1_0__RegVSFRC1_1__imm_95_3
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_imm_95_3, 0, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1__imm_95_0
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1__imm_95_3
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_3, 0, CVT_Done },
  // Convert__RegVSRC1_0__Tie0_1_1__U1Imm1_1__Imm1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__U8Imm1_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__Imm1_1
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__U2Imm1_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3__U1Imm1_4
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 3, CVT_95_addRegVSRCOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__RegVSRC1_0__RegVSFRC1_1__imm_95_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSFRCOperands, 2, CVT_imm_95_2, 0, CVT_Done },
  // Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1__imm_95_2
  { CVT_95_addRegVSRCOperands, 1, CVT_95_addRegVSRCOperands, 2, CVT_95_addRegVSRCOperands, 2, CVT_imm_95_2, 0, CVT_Done },
};

void PPCAsmParser::
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
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
    case CVT_95_addRegG8RCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegG8RCOperands(Inst, 1);
      break;
    case CVT_95_addTLSRegOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addTLSRegOperands(Inst, 1);
      break;
    case CVT_95_addRegGPRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegGPRCOperands(Inst, 1);
      break;
    case CVT_95_addImmOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_addRegGPRC_95_NOR0Operands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegGPRC_NOR0Operands(Inst, 1);
      break;
    case CVT_95_addS16ImmOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addS16ImmOperands(Inst, 1);
      break;
    case CVT_95_addU16ImmOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addU16ImmOperands(Inst, 1);
      break;
    case CVT_95_addBranchTargetOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addBranchTargetOperands(Inst, 1);
      break;
    case CVT_95_addRegCRBITRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegCRBITRCOperands(Inst, 1);
      break;
    case CVT_imm_95_3:
      Inst.addOperand(MCOperand::createImm(3));
      break;
    case CVT_imm_95_2:
      Inst.addOperand(MCOperand::createImm(2));
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_95_addRegVRRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegVRRCOperands(Inst, 1);
      break;
    case CVT_imm_95_8:
      Inst.addOperand(MCOperand::createImm(8));
      break;
    case CVT_imm_95_10:
      Inst.addOperand(MCOperand::createImm(10));
      break;
    case CVT_imm_95_76:
      Inst.addOperand(MCOperand::createImm(76));
      break;
    case CVT_regCR0:
      Inst.addOperand(MCOperand::createReg(PPC::CR0));
      break;
    case CVT_95_addRegCRRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegCRRCOperands(Inst, 1);
      break;
    case CVT_imm_95_79:
      Inst.addOperand(MCOperand::createImm(79));
      break;
    case CVT_imm_95_78:
      Inst.addOperand(MCOperand::createImm(78));
      break;
    case CVT_imm_95_4:
      Inst.addOperand(MCOperand::createImm(4));
      break;
    case CVT_imm_95_7:
      Inst.addOperand(MCOperand::createImm(7));
      break;
    case CVT_imm_95_6:
      Inst.addOperand(MCOperand::createImm(6));
      break;
    case CVT_imm_95_44:
      Inst.addOperand(MCOperand::createImm(44));
      break;
    case CVT_imm_95_47:
      Inst.addOperand(MCOperand::createImm(47));
      break;
    case CVT_imm_95_46:
      Inst.addOperand(MCOperand::createImm(46));
      break;
    case CVT_imm_95_36:
      Inst.addOperand(MCOperand::createImm(36));
      break;
    case CVT_imm_95_39:
      Inst.addOperand(MCOperand::createImm(39));
      break;
    case CVT_imm_95_38:
      Inst.addOperand(MCOperand::createImm(38));
      break;
    case CVT_imm_95_12:
      Inst.addOperand(MCOperand::createImm(12));
      break;
    case CVT_imm_95_15:
      Inst.addOperand(MCOperand::createImm(15));
      break;
    case CVT_imm_95_14:
      Inst.addOperand(MCOperand::createImm(14));
      break;
    case CVT_imm_95_68:
      Inst.addOperand(MCOperand::createImm(68));
      break;
    case CVT_imm_95_71:
      Inst.addOperand(MCOperand::createImm(71));
      break;
    case CVT_imm_95_70:
      Inst.addOperand(MCOperand::createImm(70));
      break;
    case CVT_imm_95_100:
      Inst.addOperand(MCOperand::createImm(100));
      break;
    case CVT_imm_95_103:
      Inst.addOperand(MCOperand::createImm(103));
      break;
    case CVT_imm_95_102:
      Inst.addOperand(MCOperand::createImm(102));
      break;
    case CVT_imm_95_108:
      Inst.addOperand(MCOperand::createImm(108));
      break;
    case CVT_imm_95_111:
      Inst.addOperand(MCOperand::createImm(111));
      break;
    case CVT_imm_95_110:
      Inst.addOperand(MCOperand::createImm(110));
      break;
    case CVT_imm_95_31:
      Inst.addOperand(MCOperand::createImm(31));
      break;
    case CVT_95_addRegF8RCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegF8RCOperands(Inst, 1);
      break;
    case CVT_95_addRegFpRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegFpRCOperands(Inst, 1);
      break;
    case CVT_95_addRegGxRCNoR0Operands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegGxRCNoR0Operands(Inst, 1);
      break;
    case CVT_95_addRegGxRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegGxRCOperands(Inst, 1);
      break;
    case CVT_regR0:
      Inst.addOperand(MCOperand::createReg(PPC::R0));
      break;
    case CVT_95_addRegDMRpRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegDMRpRCOperands(Inst, 1);
      break;
    case CVT_95_addRegDMRRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegDMRRCOperands(Inst, 1);
      break;
    case CVT_imm_95_1:
      Inst.addOperand(MCOperand::createImm(1));
      break;
    case CVT_95_addRegVSRpRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegVSRpRCOperands(Inst, 1);
      break;
    case CVT_95_addRegVSRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegVSRCOperands(Inst, 1);
      break;
    case CVT_95_addRegDMRROWpRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegDMRROWpRCOperands(Inst, 1);
      break;
    case CVT_95_addRegACCRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegACCRCOperands(Inst, 1);
      break;
    case CVT_95_addRegSPERCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegSPERCOperands(Inst, 1);
      break;
    case CVT_95_addRegF4RCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegF4RCOperands(Inst, 1);
      break;
    case CVT_95_addRegG8RC_95_NOX0Operands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegG8RC_NOX0Operands(Inst, 1);
      break;
    case CVT_regCR0EQ:
      Inst.addOperand(MCOperand::createReg(PPC::CR0EQ));
      break;
    case CVT_regCR0GT:
      Inst.addOperand(MCOperand::createReg(PPC::CR0GT));
      break;
    case CVT_regCR0LT:
      Inst.addOperand(MCOperand::createReg(PPC::CR0LT));
      break;
    case CVT_95_addRegG8pRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegG8pRCOperands(Inst, 1);
      break;
    case CVT_regZERO8:
      Inst.addOperand(MCOperand::createReg(PPC::ZERO8));
      break;
    case CVT_regZERO:
      Inst.addOperand(MCOperand::createReg(PPC::ZERO));
      break;
    case CVT_95_addRegVFRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegVFRCOperands(Inst, 1);
      break;
    case CVT_95_addRegVSFRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegVSFRCOperands(Inst, 1);
      break;
    case CVT_95_addRegVSSRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegVSSRCOperands(Inst, 1);
      break;
    case CVT_imm_95_29:
      Inst.addOperand(MCOperand::createImm(29));
      break;
    case CVT_imm_95_280:
      Inst.addOperand(MCOperand::createImm(280));
      break;
    case CVT_imm_95_128:
      Inst.addOperand(MCOperand::createImm(128));
      break;
    case CVT_imm_95_129:
      Inst.addOperand(MCOperand::createImm(129));
      break;
    case CVT_imm_95_130:
      Inst.addOperand(MCOperand::createImm(130));
      break;
    case CVT_imm_95_131:
      Inst.addOperand(MCOperand::createImm(131));
      break;
    case CVT_imm_95_132:
      Inst.addOperand(MCOperand::createImm(132));
      break;
    case CVT_imm_95_133:
      Inst.addOperand(MCOperand::createImm(133));
      break;
    case CVT_imm_95_134:
      Inst.addOperand(MCOperand::createImm(134));
      break;
    case CVT_imm_95_135:
      Inst.addOperand(MCOperand::createImm(135));
      break;
    case CVT_imm_95_28:
      Inst.addOperand(MCOperand::createImm(28));
      break;
    case CVT_imm_95_9:
      Inst.addOperand(MCOperand::createImm(9));
      break;
    case CVT_imm_95_19:
      Inst.addOperand(MCOperand::createImm(19));
      break;
    case CVT_imm_95_537:
      Inst.addOperand(MCOperand::createImm(537));
      break;
    case CVT_imm_95_539:
      Inst.addOperand(MCOperand::createImm(539));
      break;
    case CVT_imm_95_541:
      Inst.addOperand(MCOperand::createImm(541));
      break;
    case CVT_imm_95_543:
      Inst.addOperand(MCOperand::createImm(543));
      break;
    case CVT_imm_95_536:
      Inst.addOperand(MCOperand::createImm(536));
      break;
    case CVT_imm_95_538:
      Inst.addOperand(MCOperand::createImm(538));
      break;
    case CVT_imm_95_540:
      Inst.addOperand(MCOperand::createImm(540));
      break;
    case CVT_imm_95_542:
      Inst.addOperand(MCOperand::createImm(542));
      break;
    case CVT_imm_95_1018:
      Inst.addOperand(MCOperand::createImm(1018));
      break;
    case CVT_imm_95_981:
      Inst.addOperand(MCOperand::createImm(981));
      break;
    case CVT_imm_95_22:
      Inst.addOperand(MCOperand::createImm(22));
      break;
    case CVT_imm_95_17:
      Inst.addOperand(MCOperand::createImm(17));
      break;
    case CVT_imm_95_18:
      Inst.addOperand(MCOperand::createImm(18));
      break;
    case CVT_imm_95_980:
      Inst.addOperand(MCOperand::createImm(980));
      break;
    case CVT_imm_95_529:
      Inst.addOperand(MCOperand::createImm(529));
      break;
    case CVT_imm_95_531:
      Inst.addOperand(MCOperand::createImm(531));
      break;
    case CVT_imm_95_533:
      Inst.addOperand(MCOperand::createImm(533));
      break;
    case CVT_imm_95_535:
      Inst.addOperand(MCOperand::createImm(535));
      break;
    case CVT_imm_95_528:
      Inst.addOperand(MCOperand::createImm(528));
      break;
    case CVT_imm_95_530:
      Inst.addOperand(MCOperand::createImm(530));
      break;
    case CVT_imm_95_532:
      Inst.addOperand(MCOperand::createImm(532));
      break;
    case CVT_imm_95_534:
      Inst.addOperand(MCOperand::createImm(534));
      break;
    case CVT_imm_95_1019:
      Inst.addOperand(MCOperand::createImm(1019));
      break;
    case CVT_95_addCRBitMaskOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addCRBitMaskOperands(Inst, 1);
      break;
    case CVT_imm_95_48:
      Inst.addOperand(MCOperand::createImm(48));
      break;
    case CVT_imm_95_896:
      Inst.addOperand(MCOperand::createImm(896));
      break;
    case CVT_imm_95_287:
      Inst.addOperand(MCOperand::createImm(287));
      break;
    case CVT_imm_95_5:
      Inst.addOperand(MCOperand::createImm(5));
      break;
    case CVT_imm_95_25:
      Inst.addOperand(MCOperand::createImm(25));
      break;
    case CVT_imm_95_512:
      Inst.addOperand(MCOperand::createImm(512));
      break;
    case CVT_imm_95_272:
      Inst.addOperand(MCOperand::createImm(272));
      break;
    case CVT_imm_95_273:
      Inst.addOperand(MCOperand::createImm(273));
      break;
    case CVT_imm_95_274:
      Inst.addOperand(MCOperand::createImm(274));
      break;
    case CVT_imm_95_275:
      Inst.addOperand(MCOperand::createImm(275));
      break;
    case CVT_imm_95_260:
      Inst.addOperand(MCOperand::createImm(260));
      break;
    case CVT_imm_95_261:
      Inst.addOperand(MCOperand::createImm(261));
      break;
    case CVT_imm_95_262:
      Inst.addOperand(MCOperand::createImm(262));
      break;
    case CVT_imm_95_263:
      Inst.addOperand(MCOperand::createImm(263));
      break;
    case CVT_imm_95_26:
      Inst.addOperand(MCOperand::createImm(26));
      break;
    case CVT_imm_95_27:
      Inst.addOperand(MCOperand::createImm(27));
      break;
    case CVT_imm_95_990:
      Inst.addOperand(MCOperand::createImm(990));
      break;
    case CVT_imm_95_991:
      Inst.addOperand(MCOperand::createImm(991));
      break;
    case CVT_imm_95_268:
      Inst.addOperand(MCOperand::createImm(268));
      break;
    case CVT_imm_95_988:
      Inst.addOperand(MCOperand::createImm(988));
      break;
    case CVT_imm_95_989:
      Inst.addOperand(MCOperand::createImm(989));
      break;
    case CVT_imm_95_269:
      Inst.addOperand(MCOperand::createImm(269));
      break;
    case CVT_imm_95_986:
      Inst.addOperand(MCOperand::createImm(986));
      break;
    case CVT_imm_95_13:
      Inst.addOperand(MCOperand::createImm(13));
      break;
    case CVT_imm_95_255:
      Inst.addOperand(MCOperand::createImm(255));
      break;
    case CVT_imm_95_284:
      Inst.addOperand(MCOperand::createImm(284));
      break;
    case CVT_imm_95_285:
      Inst.addOperand(MCOperand::createImm(285));
      break;
    case CVT_regX0:
      Inst.addOperand(MCOperand::createReg(PPC::X0));
      break;
    case CVT_95_addRegVSRpEvenRCOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addRegVSRpEvenRCOperands(Inst, 1);
      break;
    case CVT_95_addNegImmOperands:
      static_cast<PPCOperand &>(*Operands[OpIdx]).addNegImmOperands(Inst, 1);
      break;
    case CVT_imm_95_20:
      Inst.addOperand(MCOperand::createImm(20));
      break;
    case CVT_imm_95_16:
      Inst.addOperand(MCOperand::createImm(16));
      break;
    case CVT_imm_95_24:
      Inst.addOperand(MCOperand::createImm(24));
      break;
    }
  }
}

void PPCAsmParser::
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
    case CVT_95_addRegG8RCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addTLSRegOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegGPRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegGPRC_95_NOR0Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addS16ImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addU16ImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addBranchTargetOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegCRBITRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
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
    case CVT_imm_95_0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addRegVRRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_8:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_10:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_76:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_regCR0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addRegCRRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_79:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_78:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_4:
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
    case CVT_imm_95_44:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_47:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_46:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_36:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_39:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_38:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_12:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_15:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_14:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_68:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_71:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_70:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_100:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_103:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_102:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_108:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_111:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_110:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_31:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addRegF8RCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegFpRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegGxRCNoR0Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegGxRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_regR0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addRegDMRpRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegDMRRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_1:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addRegVSRpRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegVSRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegDMRROWpRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegACCRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegSPERCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegF4RCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegG8RC_95_NOX0Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_regCR0EQ:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_regCR0GT:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_regCR0LT:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addRegG8pRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_regZERO8:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_regZERO:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addRegVFRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegVSFRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRegVSSRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_29:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_280:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_128:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_129:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_130:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_131:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_132:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_133:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_134:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_135:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_28:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_9:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_19:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_537:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_539:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_541:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_543:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_536:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_538:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_540:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_542:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_1018:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_981:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_22:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_17:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_18:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_980:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_529:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_531:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_533:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_535:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_528:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_530:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_532:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_534:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_1019:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addCRBitMaskOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_48:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_896:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_287:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_5:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_25:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_512:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_272:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_273:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_274:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_275:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_260:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_261:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_262:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_263:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_26:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_27:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_990:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_991:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_268:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_988:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_989:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_269:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_986:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_13:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_255:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_284:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_285:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_regX0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addRegVSRpEvenRCOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addNegImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_20:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_16:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_24:
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
  MCK__DOT_, // '.'
  MCK_0, // '0'
  MCK_1, // '1'
  MCK_2, // '2'
  MCK_3, // '3'
  MCK_4, // '4'
  MCK_5, // '5'
  MCK_6, // '6'
  MCK_7, // '7'
  MCK_crD, // 'crD'
  MCK_LAST_TOKEN = MCK_crD,
  MCK_CTRRC, // register class 'CTRRC'
  MCK_CTRRC8, // register class 'CTRRC8'
  MCK_LR8RC, // register class 'LR8RC'
  MCK_LRRC, // register class 'LRRC'
  MCK_VRSAVERC, // register class 'VRSAVERC'
  MCK_CARRYRC, // register class 'CARRYRC'
  MCK_Reg45, // derived register class
  MCK_Reg42, // derived register class
  MCK_Reg46, // derived register class
  MCK_Reg43, // derived register class
  MCK_DMRpRC, // register class 'DMRpRC'
  MCK_Reg26, // derived register class
  MCK_Reg16, // derived register class
  MCK_ACCRC, // register class 'ACCRC'
  MCK_CRRC, // register class 'CRRC'
  MCK_DMRRC, // register class 'DMRRC'
  MCK_UACCRC, // register class 'UACCRC'
  MCK_WACCRC, // register class 'WACCRC'
  MCK_WACC_HIRC, // register class 'WACC_HIRC'
  MCK_Reg30, // derived register class
  MCK_Reg24, // derived register class
  MCK_Reg10, // derived register class
  MCK_Reg33, // derived register class
  MCK_Reg31, // derived register class
  MCK_Reg27, // derived register class
  MCK_FpRC, // register class 'FpRC'
  MCK_G8pRC, // register class 'G8pRC'
  MCK_Reg29, // derived register class
  MCK_Reg20, // derived register class
  MCK_Reg18, // derived register class
  MCK_Reg9, // derived register class
  MCK_CRBITRC, // register class 'CRBITRC'
  MCK_DMRROWpRC, // register class 'DMRROWpRC'
  MCK_F4RC, // register class 'F4RC,F8RC'
  MCK_FHRC, // register class 'FHRC'
  MCK_GPRC32, // register class 'GPRC32'
  MCK_SPERC, // register class 'SPERC'
  MCK_VFHRC, // register class 'VFHRC'
  MCK_VFRC, // register class 'VFRC'
  MCK_VRRC, // register class 'VRRC'
  MCK_VSLRC, // register class 'VSLRC'
  MCK_VSRpRC, // register class 'VSRpRC'
  MCK_Reg7, // derived register class
  MCK_Reg2, // derived register class
  MCK_Reg23, // derived register class
  MCK_Reg13, // derived register class
  MCK_G8RC, // register class 'G8RC'
  MCK_G8RC_NOX0, // register class 'G8RC_NOX0'
  MCK_GPRC, // register class 'GPRC'
  MCK_GPRC_NOR0, // register class 'GPRC_NOR0'
  MCK_DMRROWRC, // register class 'DMRROWRC'
  MCK_VSRC, // register class 'VSRC'
  MCK_VSSRC, // register class 'VSSRC,VSFRC'
  MCK_SPILLTOVSRRC, // register class 'SPILLTOVSRRC'
  MCK_LAST_REGISTER = MCK_SPILLTOVSRRC,
  MCK_RegByHwMode_ppc_ptr_rc, // register class by hwmode
  MCK_RegByHwMode_ptr_rc_idx_by_hwmode, // register class by hwmode
  MCK_RegByHwMode_ptr_rc_nor0_by_hwmode, // register class by hwmode
  MCK_LAST_REGCLASS_BY_HWMODE = MCK_RegByHwMode_ptr_rc_nor0_by_hwmode,
  MCK_ATBitsAsHint, // user defined class 'ATBitsAsHint'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_ImmZero, // user defined class 'ImmZero'
  MCK_NegS32Imm, // user defined class 'NegS32Imm'
  MCK_CRBitMask, // user defined class 'PPCCRBitMaskOperand'
  MCK_CondBr, // user defined class 'PPCCondBrAsmOperand'
  MCK_DirectBr, // user defined class 'PPCDirectBrAsmOperand'
  MCK_DispRI34, // user defined class 'PPCDispRI34Operand'
  MCK_DispRIHash, // user defined class 'PPCDispRIHashOperand'
  MCK_DispRI, // user defined class 'PPCDispRIOperand'
  MCK_DispRIX16, // user defined class 'PPCDispRIX16Operand'
  MCK_DispRIX, // user defined class 'PPCDispRIXOperand'
  MCK_DispSPE2, // user defined class 'PPCDispSPE2Operand'
  MCK_DispSPE4, // user defined class 'PPCDispSPE4Operand'
  MCK_DispSPE8, // user defined class 'PPCDispSPE8Operand'
  MCK_RegACCRC, // user defined class 'PPCRegACCRCAsmOperand'
  MCK_RegCRBITRC, // user defined class 'PPCRegCRBITRCAsmOperand'
  MCK_RegCRRC, // user defined class 'PPCRegCRRCAsmOperand'
  MCK_RegDMRRC, // user defined class 'PPCRegDMRRCAsmOperand'
  MCK_RegDMRROWRC, // user defined class 'PPCRegDMRROWRCAsmOperand'
  MCK_RegDMRROWpRC, // user defined class 'PPCRegDMRROWpRCAsmOperand'
  MCK_RegDMRpRC, // user defined class 'PPCRegDMRpRCAsmOperand'
  MCK_RegF4RC, // user defined class 'PPCRegF4RCAsmOperand'
  MCK_RegF8RC, // user defined class 'PPCRegF8RCAsmOperand'
  MCK_RegFpRC, // user defined class 'PPCRegFpRCAsmOperand'
  MCK_RegG8RC, // user defined class 'PPCRegG8RCAsmOperand'
  MCK_RegG8RC_NOX0, // user defined class 'PPCRegG8RC_NOX0AsmOperand'
  MCK_RegG8pRC, // user defined class 'PPCRegG8pRCAsmOperand'
  MCK_RegGPRC, // user defined class 'PPCRegGPRCAsmOperand'
  MCK_RegGPRC_NOR0, // user defined class 'PPCRegGPRC_NOR0AsmOperand'
  MCK_RegGxRCNoR0, // user defined class 'PPCRegGxRCNoR0Operand'
  MCK_RegGxRC, // user defined class 'PPCRegGxRCOperand'
  MCK_RegSPERC, // user defined class 'PPCRegSPERCAsmOperand'
  MCK_RegSPILLTOVSRRC, // user defined class 'PPCRegSPILLTOVSRRCAsmOperand'
  MCK_RegVFRC, // user defined class 'PPCRegVFRCAsmOperand'
  MCK_RegVRRC, // user defined class 'PPCRegVRRCAsmOperand'
  MCK_RegVSFRC, // user defined class 'PPCRegVSFRCAsmOperand'
  MCK_RegVSRC, // user defined class 'PPCRegVSRCAsmOperand'
  MCK_RegVSRpEvenRC, // user defined class 'PPCRegVSRpEvenRCAsmOperand'
  MCK_RegVSRpRC, // user defined class 'PPCRegVSRpRCAsmOperand'
  MCK_RegVSSRC, // user defined class 'PPCRegVSSRCAsmOperand'
  MCK_TLSReg, // user defined class 'PPCTLSRegOperand'
  MCK_S16Imm, // user defined class 'S16Imm'
  MCK_S17Imm, // user defined class 'S17Imm'
  MCK_S32Imm, // user defined class 'S32Imm'
  MCK_S34Imm, // user defined class 'S34Imm'
  MCK_S5Imm, // user defined class 'S5Imm'
  MCK_U10Imm, // user defined class 'U10Imm'
  MCK_U12Imm, // user defined class 'U12Imm'
  MCK_U16Imm, // user defined class 'U16Imm'
  MCK_U1Imm, // user defined class 'U1Imm'
  MCK_U2Imm, // user defined class 'U2Imm'
  MCK_U32Imm, // user defined class 'U32Imm'
  MCK_U3Imm, // user defined class 'U3Imm'
  MCK_U4Imm, // user defined class 'U4Imm'
  MCK_U5Imm, // user defined class 'U5Imm'
  MCK_U6Imm, // user defined class 'U6Imm'
  MCK_U7Imm, // user defined class 'U7Imm'
  MCK_U8Imm, // user defined class 'U8Imm'
  NumMatchClassKinds
};

} // end anonymous namespace

static unsigned getDiagKindFromRegisterClass(MatchClassKind RegisterClass) {
  return MCTargetAsmParser::Match_InvalidOperand;
}

static MatchClassKind matchTokenString(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 9 strings to match.
    switch (Name[0]) {
    default: break;
    case '.':	 // 1 string to match.
      return MCK__DOT_;	 // "."
    case '0':	 // 1 string to match.
      return MCK_0;	 // "0"
    case '1':	 // 1 string to match.
      return MCK_1;	 // "1"
    case '2':	 // 1 string to match.
      return MCK_2;	 // "2"
    case '3':	 // 1 string to match.
      return MCK_3;	 // "3"
    case '4':	 // 1 string to match.
      return MCK_4;	 // "4"
    case '5':	 // 1 string to match.
      return MCK_5;	 // "5"
    case '6':	 // 1 string to match.
      return MCK_6;	 // "6"
    case '7':	 // 1 string to match.
      return MCK_7;	 // "7"
    }
    break;
  case 3:	 // 1 string to match.
    if (memcmp(Name.data()+0, "crD", 3) != 0)
      break;
    return MCK_crD;	 // "crD"
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
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 20, 9},
    {9, 21, 5},
    {14, 28, 1},
    {15, 25, 1},
    {16, 0, 0},
    {16, 36, 18},
    {34, 37, 1},
    {35, 0, 0},
    {35, 0, 0},
    {35, 0, 0},
    {35, 0, 0},
    {35, 0, 0},
    {35, 0, 0},
    {35, 35, 19},
    {54, 52, 12},
    {66, 45, 21},
    {87, 38, 1},
    {88, 53, 1},
    {89, 53, 1},
    {90, 0, 0},
    {90, 0, 0},
    {90, 53, 1},
    {91, 51, 13},
    {104, 50, 16},
    {120, 48, 1},
    {121, 0, 0},
    {121, 0, 0},
    {121, 64, 1},
    {122, 0, 0},
    {122, 0, 0},
    {122, 0, 0},
    {122, 0, 0},
    {122, 64, 1},
    {123, 63, 1},
    {124, 63, 1},
    {125, 0, 0},
    {125, 58, 8},
    {133, 60, 2},
    {135, 63, 1},
    {136, 64, 2},
    {138, 65, 1},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
    {139, 0, 0},
  };

  static constexpr uint8_t Data[] = {
    0x01,
    0xE3,
    0x09,
    0x00,
    0x8E,
    0x00,
    0x60,
    0x04,
    0x06,
    0x40,
    0xE0,
    0x0F,
    0x81,
    0x81,
    0xC0,
    0x7F,
    0xF0,
    0x07,
  };

  auto &Entry = Table[A];
  unsigned Idx = B - Entry.Start;
  if (Idx >= Entry.Length)
    return false;
  Idx += Entry.Offset;
  return (Data[Idx / 8] >> (Idx % 8)) & 1;
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind, const MCSubtargetInfo &STI) {
  PPCOperand &Operand = (PPCOperand &)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  case MCK_ATBitsAsHint: {
    DiagnosticPredicate DP(Operand.isATBitsAsHint());
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
  case MCK_ImmZero: {
    DiagnosticPredicate DP(Operand.isImmZero());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_NegS32Imm: {
    DiagnosticPredicate DP(Operand.isS32Imm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_CRBitMask: {
    DiagnosticPredicate DP(Operand.isCRBitMask());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_CondBr: {
    DiagnosticPredicate DP(Operand.isCondBr());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DirectBr: {
    DiagnosticPredicate DP(Operand.isDirectBr());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DispRI34: {
    DiagnosticPredicate DP(Operand.isS34Imm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DispRIHash: {
    DiagnosticPredicate DP(Operand.isHashImmX8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DispRI: {
    DiagnosticPredicate DP(Operand.isS16Imm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DispRIX16: {
    DiagnosticPredicate DP(Operand.isS16ImmX16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DispRIX: {
    DiagnosticPredicate DP(Operand.isS16ImmX4());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DispSPE2: {
    DiagnosticPredicate DP(Operand.isU6ImmX2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DispSPE4: {
    DiagnosticPredicate DP(Operand.isU7ImmX4());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_DispSPE8: {
    DiagnosticPredicate DP(Operand.isU8ImmX8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegACCRC: {
    DiagnosticPredicate DP(Operand.isACCRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegCRBITRC: {
    DiagnosticPredicate DP(Operand.isCRBitNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegCRRC: {
    DiagnosticPredicate DP(Operand.isCCRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegDMRRC: {
    DiagnosticPredicate DP(Operand.isDMRRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegDMRROWRC: {
    DiagnosticPredicate DP(Operand.isDMRROWRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegDMRROWpRC: {
    DiagnosticPredicate DP(Operand.isDMRROWpRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegDMRpRC: {
    DiagnosticPredicate DP(Operand.isDMRpRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegF4RC: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegF8RC: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegFpRC: {
    DiagnosticPredicate DP(Operand.isEvenRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegG8RC: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegG8RC_NOX0: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegG8pRC: {
    DiagnosticPredicate DP(Operand.isEvenRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegGPRC: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegGPRC_NOR0: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegGxRCNoR0: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegGxRC: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegSPERC: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegSPILLTOVSRRC: {
    DiagnosticPredicate DP(Operand.isVSRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegVFRC: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegVRRC: {
    DiagnosticPredicate DP(Operand.isRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegVSFRC: {
    DiagnosticPredicate DP(Operand.isVSRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegVSRC: {
    DiagnosticPredicate DP(Operand.isVSRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegVSRpEvenRC: {
    DiagnosticPredicate DP(Operand.isVSRpEvenRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegVSRpRC: {
    DiagnosticPredicate DP(Operand.isVSRpEvenRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RegVSSRC: {
    DiagnosticPredicate DP(Operand.isVSRegNumber());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_TLSReg: {
    DiagnosticPredicate DP(Operand.isTLSReg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_S16Imm: {
    DiagnosticPredicate DP(Operand.isS16Imm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_S17Imm: {
    DiagnosticPredicate DP(Operand.isS17Imm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_S32Imm: {
    DiagnosticPredicate DP(Operand.isS32Imm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_S34Imm: {
    DiagnosticPredicate DP(Operand.isS34Imm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_S5Imm: {
    DiagnosticPredicate DP(Operand.isSImm<5>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U10Imm: {
    DiagnosticPredicate DP(Operand.isUImm<10>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U12Imm: {
    DiagnosticPredicate DP(Operand.isUImm<12>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U16Imm: {
    DiagnosticPredicate DP(Operand.isU16Imm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U1Imm: {
    DiagnosticPredicate DP(Operand.isUImm<1>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U2Imm: {
    DiagnosticPredicate DP(Operand.isUImm<2>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U32Imm: {
    DiagnosticPredicate DP(Operand.isUImm<32>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U3Imm: {
    DiagnosticPredicate DP(Operand.isUImm<3>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U4Imm: {
    DiagnosticPredicate DP(Operand.isUImm<4>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U5Imm: {
    DiagnosticPredicate DP(Operand.isUImm<5>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U6Imm: {
    DiagnosticPredicate DP(Operand.isUImm<6>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U7Imm: {
    DiagnosticPredicate DP(Operand.isUImm<7>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_U8Imm: {
    DiagnosticPredicate DP(Operand.isUImm<8>());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg() && Kind > MCK_LAST_REGISTER && Kind <= MCK_LAST_REGCLASS_BY_HWMODE) {
    static constexpr MatchClassKind RegClassByHwModeMatchTable[2][3] = {
      { // DefaultMode
        MCK_GPRC, // ppc_ptr_rc
        MCK_GPRC, // ptr_rc_idx_by_hwmode
        MCK_GPRC_NOR0, // ptr_rc_nor0_by_hwmode
      },
      { // PPC64
        MCK_G8RC, // ppc_ptr_rc
        MCK_G8RC, // ptr_rc_idx_by_hwmode
        MCK_G8RC_NOX0, // ptr_rc_nor0_by_hwmode
      },
    };

    static_assert(MCK_LAST_REGCLASS_BY_HWMODE - MCK_LAST_REGISTER == 3);
    const unsigned HwMode = STI.getHwMode(MCSubtargetInfo::HwMode_RegInfo);
    Kind = RegClassByHwModeMatchTable[HwMode][Kind - (MCK_LAST_REGISTER + 1)];
  }

  if (Operand.isReg()) {
    static constexpr uint16_t Table[PPC::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      MCK_Reg2,
      MCK_CARRYRC,
      MCK_CTRRC,
      MCK_Reg2,
      MCK_LRRC,
      InvalidMatchClass,
      InvalidMatchClass,
      MCK_VRSAVERC,
      MCK_CARRYRC,
      MCK_GPRC_NOR0,
      MCK_Reg42,
      MCK_Reg42,
      MCK_Reg42,
      MCK_Reg43,
      MCK_ACCRC,
      MCK_ACCRC,
      MCK_ACCRC,
      MCK_ACCRC,
      MCK_Reg7,
      MCK_CRRC,
      MCK_CRRC,
      MCK_CRRC,
      MCK_CRRC,
      MCK_CRRC,
      MCK_CRRC,
      MCK_CRRC,
      MCK_CRRC,
      MCK_CTRRC8,
      MCK_DMRRC,
      MCK_DMRRC,
      MCK_DMRRC,
      MCK_DMRRC,
      MCK_DMRRC,
      MCK_DMRRC,
      MCK_DMRRC,
      MCK_DMRRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRROWpRC,
      MCK_DMRpRC,
      MCK_DMRpRC,
      MCK_DMRpRC,
      MCK_DMRpRC,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_Reg10,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_F4RC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_FHRC,
      MCK_Reg7,
      MCK_Reg16,
      MCK_Reg16,
      MCK_Reg16,
      MCK_Reg16,
      MCK_Reg16,
      MCK_Reg16,
      MCK_Reg16,
      MCK_FpRC,
      MCK_FpRC,
      MCK_FpRC,
      MCK_FpRC,
      MCK_FpRC,
      MCK_FpRC,
      MCK_FpRC,
      MCK_FpRC,
      MCK_FpRC,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_GPRC32,
      MCK_LR8RC,
      MCK_GPRC,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_Reg2,
      MCK_SPERC,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg45,
      MCK_Reg45,
      MCK_Reg45,
      MCK_Reg46,
      MCK_UACCRC,
      MCK_UACCRC,
      MCK_UACCRC,
      MCK_UACCRC,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_Reg20,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_VRRC,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_Reg18,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_VFHRC,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_VSLRC,
      MCK_Reg26,
      MCK_Reg26,
      MCK_Reg26,
      MCK_Reg26,
      MCK_Reg26,
      MCK_Reg26,
      MCK_Reg26,
      MCK_Reg27,
      MCK_Reg27,
      MCK_Reg27,
      MCK_Reg27,
      MCK_Reg27,
      MCK_Reg27,
      MCK_Reg27,
      MCK_Reg27,
      MCK_Reg27,
      MCK_Reg30,
      MCK_Reg30,
      MCK_Reg30,
      MCK_Reg30,
      MCK_Reg30,
      MCK_Reg30,
      MCK_Reg30,
      MCK_Reg30,
      MCK_Reg30,
      MCK_Reg30,
      MCK_Reg31,
      MCK_Reg31,
      MCK_Reg31,
      MCK_Reg31,
      MCK_Reg31,
      MCK_Reg31,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      InvalidMatchClass,
      MCK_WACCRC,
      MCK_WACCRC,
      MCK_WACCRC,
      MCK_WACCRC,
      MCK_WACCRC,
      MCK_WACCRC,
      MCK_WACCRC,
      MCK_WACCRC,
      MCK_WACC_HIRC,
      MCK_WACC_HIRC,
      MCK_WACC_HIRC,
      MCK_WACC_HIRC,
      MCK_WACC_HIRC,
      MCK_WACC_HIRC,
      MCK_WACC_HIRC,
      MCK_WACC_HIRC,
      MCK_G8RC,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_Reg7,
      MCK_G8RC_NOX0,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_CRBITRC,
      MCK_G8pRC,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
      MCK_Reg33,
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
  case MCK__DOT_: return "MCK__DOT_";
  case MCK_0: return "MCK_0";
  case MCK_1: return "MCK_1";
  case MCK_2: return "MCK_2";
  case MCK_3: return "MCK_3";
  case MCK_4: return "MCK_4";
  case MCK_5: return "MCK_5";
  case MCK_6: return "MCK_6";
  case MCK_7: return "MCK_7";
  case MCK_crD: return "MCK_crD";
  case MCK_CTRRC: return "MCK_CTRRC";
  case MCK_CTRRC8: return "MCK_CTRRC8";
  case MCK_LR8RC: return "MCK_LR8RC";
  case MCK_LRRC: return "MCK_LRRC";
  case MCK_VRSAVERC: return "MCK_VRSAVERC";
  case MCK_CARRYRC: return "MCK_CARRYRC";
  case MCK_Reg45: return "MCK_Reg45";
  case MCK_Reg42: return "MCK_Reg42";
  case MCK_Reg46: return "MCK_Reg46";
  case MCK_Reg43: return "MCK_Reg43";
  case MCK_DMRpRC: return "MCK_DMRpRC";
  case MCK_Reg26: return "MCK_Reg26";
  case MCK_Reg16: return "MCK_Reg16";
  case MCK_ACCRC: return "MCK_ACCRC";
  case MCK_CRRC: return "MCK_CRRC";
  case MCK_DMRRC: return "MCK_DMRRC";
  case MCK_UACCRC: return "MCK_UACCRC";
  case MCK_WACCRC: return "MCK_WACCRC";
  case MCK_WACC_HIRC: return "MCK_WACC_HIRC";
  case MCK_Reg30: return "MCK_Reg30";
  case MCK_Reg24: return "MCK_Reg24";
  case MCK_Reg10: return "MCK_Reg10";
  case MCK_Reg33: return "MCK_Reg33";
  case MCK_Reg31: return "MCK_Reg31";
  case MCK_Reg27: return "MCK_Reg27";
  case MCK_FpRC: return "MCK_FpRC";
  case MCK_G8pRC: return "MCK_G8pRC";
  case MCK_Reg29: return "MCK_Reg29";
  case MCK_Reg20: return "MCK_Reg20";
  case MCK_Reg18: return "MCK_Reg18";
  case MCK_Reg9: return "MCK_Reg9";
  case MCK_CRBITRC: return "MCK_CRBITRC";
  case MCK_DMRROWpRC: return "MCK_DMRROWpRC";
  case MCK_F4RC: return "MCK_F4RC";
  case MCK_FHRC: return "MCK_FHRC";
  case MCK_GPRC32: return "MCK_GPRC32";
  case MCK_SPERC: return "MCK_SPERC";
  case MCK_VFHRC: return "MCK_VFHRC";
  case MCK_VFRC: return "MCK_VFRC";
  case MCK_VRRC: return "MCK_VRRC";
  case MCK_VSLRC: return "MCK_VSLRC";
  case MCK_VSRpRC: return "MCK_VSRpRC";
  case MCK_Reg7: return "MCK_Reg7";
  case MCK_Reg2: return "MCK_Reg2";
  case MCK_Reg23: return "MCK_Reg23";
  case MCK_Reg13: return "MCK_Reg13";
  case MCK_G8RC: return "MCK_G8RC";
  case MCK_G8RC_NOX0: return "MCK_G8RC_NOX0";
  case MCK_GPRC: return "MCK_GPRC";
  case MCK_GPRC_NOR0: return "MCK_GPRC_NOR0";
  case MCK_DMRROWRC: return "MCK_DMRROWRC";
  case MCK_VSRC: return "MCK_VSRC";
  case MCK_VSSRC: return "MCK_VSSRC";
  case MCK_SPILLTOVSRRC: return "MCK_SPILLTOVSRRC";
  case MCK_RegByHwMode_ppc_ptr_rc: return "MCK_RegByHwMode_ppc_ptr_rc";
  case MCK_RegByHwMode_ptr_rc_idx_by_hwmode: return "MCK_RegByHwMode_ptr_rc_idx_by_hwmode";
  case MCK_RegByHwMode_ptr_rc_nor0_by_hwmode: return "MCK_RegByHwMode_ptr_rc_nor0_by_hwmode";
  case MCK_ATBitsAsHint: return "MCK_ATBitsAsHint";
  case MCK_Imm: return "MCK_Imm";
  case MCK_ImmZero: return "MCK_ImmZero";
  case MCK_NegS32Imm: return "MCK_NegS32Imm";
  case MCK_CRBitMask: return "MCK_CRBitMask";
  case MCK_CondBr: return "MCK_CondBr";
  case MCK_DirectBr: return "MCK_DirectBr";
  case MCK_DispRI34: return "MCK_DispRI34";
  case MCK_DispRIHash: return "MCK_DispRIHash";
  case MCK_DispRI: return "MCK_DispRI";
  case MCK_DispRIX16: return "MCK_DispRIX16";
  case MCK_DispRIX: return "MCK_DispRIX";
  case MCK_DispSPE2: return "MCK_DispSPE2";
  case MCK_DispSPE4: return "MCK_DispSPE4";
  case MCK_DispSPE8: return "MCK_DispSPE8";
  case MCK_RegACCRC: return "MCK_RegACCRC";
  case MCK_RegCRBITRC: return "MCK_RegCRBITRC";
  case MCK_RegCRRC: return "MCK_RegCRRC";
  case MCK_RegDMRRC: return "MCK_RegDMRRC";
  case MCK_RegDMRROWRC: return "MCK_RegDMRROWRC";
  case MCK_RegDMRROWpRC: return "MCK_RegDMRROWpRC";
  case MCK_RegDMRpRC: return "MCK_RegDMRpRC";
  case MCK_RegF4RC: return "MCK_RegF4RC";
  case MCK_RegF8RC: return "MCK_RegF8RC";
  case MCK_RegFpRC: return "MCK_RegFpRC";
  case MCK_RegG8RC: return "MCK_RegG8RC";
  case MCK_RegG8RC_NOX0: return "MCK_RegG8RC_NOX0";
  case MCK_RegG8pRC: return "MCK_RegG8pRC";
  case MCK_RegGPRC: return "MCK_RegGPRC";
  case MCK_RegGPRC_NOR0: return "MCK_RegGPRC_NOR0";
  case MCK_RegGxRCNoR0: return "MCK_RegGxRCNoR0";
  case MCK_RegGxRC: return "MCK_RegGxRC";
  case MCK_RegSPERC: return "MCK_RegSPERC";
  case MCK_RegSPILLTOVSRRC: return "MCK_RegSPILLTOVSRRC";
  case MCK_RegVFRC: return "MCK_RegVFRC";
  case MCK_RegVRRC: return "MCK_RegVRRC";
  case MCK_RegVSFRC: return "MCK_RegVSFRC";
  case MCK_RegVSRC: return "MCK_RegVSRC";
  case MCK_RegVSRpEvenRC: return "MCK_RegVSRpEvenRC";
  case MCK_RegVSRpRC: return "MCK_RegVSRpRC";
  case MCK_RegVSSRC: return "MCK_RegVSSRC";
  case MCK_TLSReg: return "MCK_TLSReg";
  case MCK_S16Imm: return "MCK_S16Imm";
  case MCK_S17Imm: return "MCK_S17Imm";
  case MCK_S32Imm: return "MCK_S32Imm";
  case MCK_S34Imm: return "MCK_S34Imm";
  case MCK_S5Imm: return "MCK_S5Imm";
  case MCK_U10Imm: return "MCK_U10Imm";
  case MCK_U12Imm: return "MCK_U12Imm";
  case MCK_U16Imm: return "MCK_U16Imm";
  case MCK_U1Imm: return "MCK_U1Imm";
  case MCK_U2Imm: return "MCK_U2Imm";
  case MCK_U32Imm: return "MCK_U32Imm";
  case MCK_U3Imm: return "MCK_U3Imm";
  case MCK_U4Imm: return "MCK_U4Imm";
  case MCK_U5Imm: return "MCK_U5Imm";
  case MCK_U6Imm: return "MCK_U6Imm";
  case MCK_U7Imm: return "MCK_U7Imm";
  case MCK_U8Imm: return "MCK_U8Imm";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset PPCAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  if (!FB[PPC::AIXOS] || FB[PPC::FeatureModernAIXAs])
    Features.set(Feature_ModernAsBit);
  return Features;
}

static bool checkAsmTiedOperandConstraints(const PPCAsmParser&AsmParser,
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
    "\003add\004addc\005addco\004adde\005addeo\005addex\006addg6s\004addi\005"
    "addic\005addis\005addme\006addmeo\004addo\007addpcis\005addze\006addzeo"
    "\003and\004andc\004andi\005andis\004attn\001b\002ba\002bc\003bc+\003bc-"
    "\003bca\004bca+\004bca-\005bcctr\006bcctrl\006bcdadd\006bcdcfn\007bcdcf"
    "sq\006bcdcfz\010bcdcpsgn\006bcdctn\007bcdctsq\006bcdctz\004bcds\tbcdset"
    "sgn\005bcdsr\006bcdsub\010bcdtrunc\005bcdus\tbcdutrunc\003bcl\004bcl+\004"
    "bcl-\004bcla\005bcla+\005bcla-\004bclr\005bclrl\004bctr\005bctrl\004bdn"
    "z\005bdnz+\005bdnz-\005bdnza\006bdnza+\006bdnza-\005bdnzf\006bdnzfa\006"
    "bdnzfl\007bdnzfla\007bdnzflr\010bdnzflrl\005bdnzl\006bdnzl+\006bdnzl-\006"
    "bdnzla\007bdnzla+\007bdnzla-\006bdnzlr\007bdnzlr+\007bdnzlr-\007bdnzlrl"
    "\010bdnzlrl+\010bdnzlrl-\005bdnzt\006bdnzta\006bdnztl\007bdnztla\007bdn"
    "ztlr\010bdnztlrl\003bdz\004bdz+\004bdz-\004bdza\005bdza+\005bdza-\004bd"
    "zf\005bdzfa\005bdzfl\006bdzfla\006bdzflr\007bdzflrl\004bdzl\005bdzl+\005"
    "bdzl-\005bdzla\006bdzla+\006bdzla-\005bdzlr\006bdzlr+\006bdzlr-\006bdzl"
    "rl\007bdzlrl+\007bdzlrl-\004bdzt\005bdzta\005bdztl\006bdztla\006bdztlr\007"
    "bdztlrl\003beq\004beq+\004beq-\004beqa\005beqa+\005beqa-\006beqctr\007b"
    "eqctr+\007beqctr-\007beqctrl\010beqctrl+\010beqctrl-\004beql\005beql+\005"
    "beql-\005beqla\006beqla+\006beqla-\005beqlr\006beqlr+\006beqlr-\006beql"
    "rl\007beqlrl+\007beqlrl-\002bf\003bf+\003bf-\003bfa\004bfa+\004bfa-\005"
    "bfctr\006bfctr+\006bfctr-\006bfctrl\007bfctrl+\007bfctrl-\003bfl\004bfl"
    "+\004bfl-\004bfla\005bfla+\005bfla-\004bflr\005bflr+\005bflr-\005bflrl\006"
    "bflrl+\006bflrl-\003bge\004bge+\004bge-\004bgea\005bgea+\005bgea-\006bg"
    "ectr\007bgectr+\007bgectr-\007bgectrl\010bgectrl+\010bgectrl-\004bgel\005"
    "bgel+\005bgel-\005bgela\006bgela+\006bgela-\005bgelr\006bgelr+\006bgelr"
    "-\006bgelrl\007bgelrl+\007bgelrl-\003bgt\004bgt+\004bgt-\004bgta\005bgt"
    "a+\005bgta-\006bgtctr\007bgtctr+\007bgtctr-\007bgtctrl\010bgtctrl+\010b"
    "gtctrl-\004bgtl\005bgtl+\005bgtl-\005bgtla\006bgtla+\006bgtla-\005bgtlr"
    "\006bgtlr+\006bgtlr-\006bgtlrl\007bgtlrl+\007bgtlrl-\002bl\003bla\003bl"
    "e\004ble+\004ble-\004blea\005blea+\005blea-\006blectr\007blectr+\007ble"
    "ctr-\007blectrl\010blectrl+\010blectrl-\004blel\005blel+\005blel-\005bl"
    "ela\006blela+\006blela-\005blelr\006blelr+\006blelr-\006blelrl\007blelr"
    "l+\007blelrl-\003blr\004blrl\003blt\004blt+\004blt-\004blta\005blta+\005"
    "blta-\006bltctr\007bltctr+\007bltctr-\007bltctrl\010bltctrl+\010bltctrl"
    "-\004bltl\005bltl+\005bltl-\005bltla\006bltla+\006bltla-\005bltlr\006bl"
    "tlr+\006bltlr-\006bltlrl\007bltlrl+\007bltlrl-\003bne\004bne+\004bne-\004"
    "bnea\005bnea+\005bnea-\006bnectr\007bnectr+\007bnectr-\007bnectrl\010bn"
    "ectrl+\010bnectrl-\004bnel\005bnel+\005bnel-\005bnela\006bnela+\006bnel"
    "a-\005bnelr\006bnelr+\006bnelr-\006bnelrl\007bnelrl+\007bnelrl-\003bng\004"
    "bng+\004bng-\004bnga\005bnga+\005bnga-\006bngctr\007bngctr+\007bngctr-\007"
    "bngctrl\010bngctrl+\010bngctrl-\004bngl\005bngl+\005bngl-\005bngla\006b"
    "ngla+\006bngla-\005bnglr\006bnglr+\006bnglr-\006bnglrl\007bnglrl+\007bn"
    "glrl-\003bnl\004bnl+\004bnl-\004bnla\005bnla+\005bnla-\006bnlctr\007bnl"
    "ctr+\007bnlctr-\007bnlctrl\010bnlctrl+\010bnlctrl-\004bnll\005bnll+\005"
    "bnll-\005bnlla\006bnlla+\006bnlla-\005bnllr\006bnllr+\006bnllr-\006bnll"
    "rl\007bnllrl+\007bnllrl-\003bns\004bns+\004bns-\004bnsa\005bnsa+\005bns"
    "a-\006bnsctr\007bnsctr+\007bnsctr-\007bnsctrl\010bnsctrl+\010bnsctrl-\004"
    "bnsl\005bnsl+\005bnsl-\005bnsla\006bnsla+\006bnsla-\005bnslr\006bnslr+\006"
    "bnslr-\006bnslrl\007bnslrl+\007bnslrl-\003bnu\004bnu+\004bnu-\004bnua\005"
    "bnua+\005bnua-\006bnuctr\007bnuctr+\007bnuctr-\007bnuctrl\010bnuctrl+\010"
    "bnuctrl-\004bnul\005bnul+\005bnul-\005bnula\006bnula+\006bnula-\005bnul"
    "r\006bnulr+\006bnulr-\006bnulrl\007bnulrl+\007bnulrl-\006bpermd\003brd\003"
    "brh\005brinc\003brw\003bso\004bso+\004bso-\004bsoa\005bsoa+\005bsoa-\006"
    "bsoctr\007bsoctr+\007bsoctr-\007bsoctrl\010bsoctrl+\010bsoctrl-\004bsol"
    "\005bsol+\005bsol-\005bsola\006bsola+\006bsola-\005bsolr\006bsolr+\006b"
    "solr-\006bsolrl\007bsolrl+\007bsolrl-\002bt\003bt+\003bt-\003bta\004bta"
    "+\004bta-\005btctr\006btctr+\006btctr-\006btctrl\007btctrl+\007btctrl-\003"
    "btl\004btl+\004btl-\004btla\005btla+\005btla-\004btlr\005btlr+\005btlr-"
    "\005btlrl\006btlrl+\006btlrl-\003bun\004bun+\004bun-\004buna\005buna+\005"
    "buna-\006bunctr\007bunctr+\007bunctr-\007bunctrl\010bunctrl+\010bunctrl"
    "-\004bunl\005bunl+\005bunl-\005bunla\006bunla+\006bunla-\005bunlr\006bu"
    "nlr+\006bunlr-\006bunlrl\007bunlrl+\007bunlrl-\006cbcdtd\006cdtbcd\006c"
    "fuged\007clrbhrb\006clrldi\010clrlsldi\010clrlslwi\006clrlwi\006clrrdi\006"
    "clrrwi\003cmp\004cmpb\004cmpd\005cmpdi\006cmpeqb\004cmpi\004cmpl\005cmp"
    "ld\006cmpldi\005cmpli\005cmplw\006cmplwi\005cmprb\004cmpw\005cmpwi\006c"
    "ntlzd\007cntlzdm\006cntlzw\006cnttzd\007cnttzdm\006cnttzw\004copy\007cp"
    "abort\005crand\006crandc\005crclr\005creqv\006crmove\006crnand\005crnor"
    "\005crnot\004cror\005crorc\005crset\005crxor\004dadd\005daddq\004darn\004"
    "dcba\004dcbf\006dcbfep\005dcbfl\006dcbflp\006dcbfps\004dcbi\005dcbst\007"
    "dcbstep\007dcbstps\004dcbt\006dcbtct\006dcbtds\006dcbtep\006dcbtst\010d"
    "cbtstct\010dcbtstds\010dcbtstep\007dcbtstt\005dcbtt\004dcbz\006dcbzep\005"
    "dcbzl\007dcbzlep\005dccci\006dcffix\007dcffixq\010dcffixqq\003dci\005dc"
    "mpo\006dcmpoq\005dcmpu\006dcmpuq\005dctdp\006dctfix\007dctfixq\010dctfi"
    "xqq\006dctqpq\006ddedpd\007ddedpdq\004ddiv\005ddivq\006denbcd\007denbcd"
    "q\004diex\005diexq\004divd\005divde\006divdeo\006divdeu\007divdeuo\005d"
    "ivdo\005divdu\006divduo\004divw\005divwe\006divweo\006divweu\007divweuo"
    "\005divwo\005divwu\006divwuo\ndmcryshash\004dmmr\tdmsetdmrz\014dmsha256"
    "hash\ndmsha2hash\010dmsha3dw\ndmsha3hash\014dmsha512hash\004dmul\005dmu"
    "lq\005dmxor\015dmxvbf16gerx2\017dmxvbf16gerx2nn\017dmxvbf16gerx2np\017d"
    "mxvbf16gerx2pn\017dmxvbf16gerx2pp\014dmxvf16gerx2\016dmxvf16gerx2nn\016"
    "dmxvf16gerx2np\016dmxvf16gerx2pn\016dmxvf16gerx2pp\013dmxvi8gerx4\015dm"
    "xvi8gerx4pp\016dmxvi8gerx4spp\016dmxxextfdmr256\016dmxxextfdmr512\016dm"
    "xxinstdmr256\016dmxxinstdmr512\ndmxxmmfacc\ndmxxmmtacc\013dmxxsetaccz\020"
    "dmxxsha224256pad\016dmxxsha3224pad\016dmxxsha3256pad\016dmxxsha3384pad\016"
    "dmxxsha3512pad\020dmxxsha384512pad\017dmxxshake128pad\017dmxxshake256pa"
    "d\ndmxxshapad\004dqua\005dquai\006dquaiq\005dquaq\005drdpq\006drintn\007"
    "drintnq\006drintx\007drintxq\005drrnd\006drrndq\004drsp\005dscli\006dsc"
    "liq\005dscri\006dscriq\003dss\006dssall\003dst\005dstst\006dststt\004ds"
    "tt\004dsub\005dsubq\006dtstdc\007dtstdcq\006dtstdg\007dtstdgq\006dtstex"
    "\007dtstexq\006dtstsf\007dtstsfi\010dtstsfiq\007dtstsfq\004dxex\005dxex"
    "q\006efdabs\006efdadd\006efdcfs\007efdcfsf\007efdcfsi\010efdcfsid\007ef"
    "dcfuf\007efdcfui\010efdcfuid\010efdcmpeq\010efdcmpgt\010efdcmplt\007efd"
    "ctsf\007efdctsi\tefdctsidz\010efdctsiz\007efdctuf\007efdctui\tefdctuidz"
    "\010efdctuiz\006efddiv\006efdmul\007efdnabs\006efdneg\006efdsub\010efdt"
    "steq\010efdtstgt\010efdtstlt\006efsabs\006efsadd\006efscfd\007efscfsf\007"
    "efscfsi\007efscfuf\007efscfui\010efscmpeq\010efscmpgt\010efscmplt\007ef"
    "sctsf\007efsctsi\010efsctsiz\007efsctuf\007efsctui\010efsctuiz\006efsdi"
    "v\006efsmul\007efsnabs\006efsneg\006efssub\010efststeq\010efststgt\010e"
    "fststlt\005eieio\003eqv\005evabs\007evaddiw\013evaddsmiaaw\013evaddssia"
    "aw\013evaddumiaaw\013evaddusiaaw\006evaddw\005evand\006evandc\007evcmpe"
    "q\010evcmpgts\010evcmpgtu\010evcmplts\010evcmpltu\010evcntlsw\010evcntl"
    "zw\007evdivws\007evdivwu\005eveqv\007evextsb\007evextsh\007evfsabs\007e"
    "vfsadd\010evfscfsf\010evfscfsi\010evfscfuf\010evfscfui\tevfscmpeq\tevfs"
    "cmpgt\tevfscmplt\010evfsctsf\010evfsctsi\tevfsctsiz\010evfsctui\007evfs"
    "div\007evfsmul\010evfsnabs\007evfsneg\007evfssub\tevfststeq\tevfststgt\t"
    "evfststlt\005evldd\006evlddx\005evldh\006evldhx\005evldw\006evldwx\013e"
    "vlhhesplat\014evlhhesplatx\014evlhhossplat\015evlhhossplatx\014evlhhous"
    "plat\015evlhhousplatx\006evlwhe\007evlwhex\007evlwhos\010evlwhosx\007ev"
    "lwhou\010evlwhoux\nevlwhsplat\013evlwhsplatx\nevlwwsplat\013evlwwsplatx"
    "\tevmergehi\013evmergehilo\tevmergelo\013evmergelohi\013evmhegsmfaa\013"
    "evmhegsmfan\013evmhegsmiaa\013evmhegsmian\013evmhegumiaa\013evmhegumian"
    "\010evmhesmf\tevmhesmfa\013evmhesmfaaw\013evmhesmfanw\010evmhesmi\tevmh"
    "esmia\013evmhesmiaaw\013evmhesmianw\010evmhessf\tevmhessfa\013evmhessfa"
    "aw\013evmhessfanw\013evmhessiaaw\013evmhessianw\010evmheumi\tevmheumia\013"
    "evmheumiaaw\013evmheumianw\013evmheusiaaw\013evmheusianw\013evmhogsmfaa"
    "\013evmhogsmfan\013evmhogsmiaa\013evmhogsmian\013evmhogumiaa\013evmhogu"
    "mian\010evmhosmf\tevmhosmfa\013evmhosmfaaw\013evmhosmfanw\010evmhosmi\t"
    "evmhosmia\013evmhosmiaaw\013evmhosmianw\010evmhossf\tevmhossfa\013evmho"
    "ssfaaw\013evmhossfanw\013evmhossiaaw\013evmhossianw\010evmhoumi\tevmhou"
    "mia\013evmhoumiaaw\013evmhoumianw\013evmhousiaaw\013evmhousianw\005evmr"
    "a\010evmwhsmf\tevmwhsmfa\010evmwhsmi\tevmwhsmia\010evmwhssf\tevmwhssfa\010"
    "evmwhumi\tevmwhumia\013evmwlsmiaaw\013evmwlsmianw\013evmwlssiaaw\013evm"
    "wlssianw\010evmwlumi\tevmwlumia\013evmwlumiaaw\013evmwlumianw\013evmwlu"
    "siaaw\013evmwlusianw\007evmwsmf\010evmwsmfa\tevmwsmfaa\tevmwsmfan\007ev"
    "mwsmi\010evmwsmia\tevmwsmiaa\tevmwsmian\007evmwssf\010evmwssfa\tevmwssf"
    "aa\tevmwssfan\007evmwumi\010evmwumia\tevmwumiaa\tevmwumian\006evnand\005"
    "evneg\005evnor\004evor\005evorc\005evrlw\006evrlwi\006evrndw\005evsel\005"
    "evslw\006evslwi\tevsplatfi\010evsplati\007evsrwis\007evsrwiu\006evsrws\006"
    "evsrwu\006evstdd\007evstddx\006evstdh\007evstdhx\006evstdw\007evstdwx\007"
    "evstwhe\010evstwhex\007evstwho\010evstwhox\007evstwwe\010evstwwex\007ev"
    "stwwo\010evstwwox\014evsubfsmiaaw\014evsubfssiaaw\014evsubfumiaaw\014ev"
    "subfusiaaw\007evsubfw\010evsubifw\005evxor\006extldi\006extlwi\006extrd"
    "i\006extrwi\005extsb\005extsh\005extsw\010extswsli\004fabs\004fadd\005f"
    "adds\005fcfid\006fcfids\006fcfidu\007fcfidus\005fcmpo\005fcmpu\006fcpsg"
    "n\005fctid\006fctidu\007fctiduz\006fctidz\005fctiw\006fctiwu\007fctiwuz"
    "\006fctiwz\004fdiv\005fdivs\005fmadd\006fmadds\003fmr\005fmsub\006fmsub"
    "s\004fmul\005fmuls\005fnabs\004fneg\006fnmadd\007fnmadds\006fnmsub\007f"
    "nmsubs\003fre\004fres\004frim\004frin\004frip\004friz\004frsp\007frsqrt"
    "e\010frsqrtes\004fsel\005fsqrt\006fsqrts\004fsub\005fsubs\005ftdiv\006f"
    "tsqrt\007hashchk\010hashchkp\006hashst\007hashstp\005hrfid\006hwsync\004"
    "icbi\006icbiep\005icblc\005icblq\004icbt\006icbtls\005iccci\003ici\006i"
    "nslwi\006insrdi\006insrwi\004isel\006iseleq\006iselgt\006isellt\005isyn"
    "c\002la\005lbarx\005lbepx\003lbz\006lbzcix\004lbzu\005lbzux\004lbzx\002"
    "ld\005ldarx\004ldat\005ldbrx\005ldcix\003ldu\004ldux\003ldx\003lfd\006l"
    "fdepx\004lfdu\005lfdux\004lfdx\006lfiwax\006lfiwzx\003lfs\004lfsu\005lf"
    "sux\004lfsx\003lha\005lharx\004lhau\005lhaux\004lhax\005lhbrx\005lhepx\003"
    "lhz\006lhzcix\004lhzu\005lhzux\004lhzx\002li\003lis\003lmw\004lnia\002l"
    "q\005lqarx\004lswi\005lvebx\005lvehx\005lvewx\004lvsl\004lvsr\003lvx\004"
    "lvxl\003lwa\005lwarx\004lwat\005lwaux\004lwax\005lwbrx\005lwepx\006lwsy"
    "nc\003lwz\006lwzcix\004lwzu\005lwzux\004lwzx\004lxsd\005lxsdx\007lxsibz"
    "x\007lxsihzx\007lxsiwax\007lxsiwzx\005lxssp\006lxsspx\003lxv\007lxvb16x"
    "\006lxvd2x\006lxvdsx\006lxvh8x\005lxvkq\004lxvl\005lxvll\004lxvp\010lxv"
    "pb32x\006lxvprl\007lxvprll\005lxvpx\006lxvrbx\006lxvrdx\006lxvrhx\005lx"
    "vrl\006lxvrll\006lxvrwx\006lxvw4x\006lxvwsx\004lxvx\006maddhd\007maddhd"
    "u\006maddld\004mbar\004mcrf\005mcrfs\006mcrxrx\005mfamr\005mfasr\007mfb"
    "hrbe\005mfbr0\005mfbr1\005mfbr2\005mfbr3\005mfbr4\005mfbr5\005mfbr6\005"
    "mfbr7\006mfcfar\004mfcr\005mfctr\005mfdar\007mfdbatl\007mfdbatu\006mfdc"
    "cr\005mfdcr\006mfdear\005mfdec\006mfdscr\007mfdsisr\005mfesr\006mffprd\007"
    "mffprwz\004mffs\010mffscdrn\tmffscdrni\006mffsce\007mffscrn\010mffscrni"
    "\005mffsl\007mfibatl\007mfibatu\006mficcr\004mflr\005mfmsr\006mfocrf\005"
    "mfpid\006mfpidr\005mfpmr\005mfppr\005mfpvr\006mfrtcl\006mfrtcu\006mfsdr"
    "1\tmfspefscr\005mfspr\006mfsprg\007mfsprg0\007mfsprg1\007mfsprg2\007mfs"
    "prg3\007mfsprg4\007mfsprg5\007mfsprg6\007mfsprg7\004mfsr\006mfsrin\006m"
    "fsrr0\006mfsrr1\006mfsrr2\006mfsrr3\004mftb\006mftbhi\005mftbl\006mftbl"
    "o\005mftbu\005mftcr\006mfuamr\007mfudscr\005mfvrd\010mfvrsave\006mfvrwz"
    "\006mfvscr\006mfvsrd\007mfvsrld\007mfvsrwz\005mfxer\005modsd\005modsw\005"
    "modud\005moduw\002mr\007msgsndp\007msgsync\005msync\005mtamr\005mtasr\005"
    "mtbr0\005mtbr1\005mtbr2\005mtbr3\005mtbr4\005mtbr5\005mtbr6\005mtbr7\006"
    "mtcfar\004mtcr\005mtcrf\005mtctr\005mtdar\007mtdbatl\007mtdbatu\006mtdc"
    "cr\005mtdcr\006mtdear\005mtdec\006mtdscr\007mtdsisr\005mtesr\006mtfprd\007"
    "mtfprwa\007mtfprwz\006mtfsb0\006mtfsb1\005mtfsf\006mtfsfi\007mtibatl\007"
    "mtibatu\006mticcr\005mtlpl\004mtlr\005mtmsr\006mtmsrd\006mtocrf\005mtpi"
    "d\006mtpidr\005mtpmr\005mtppr\006mtsdr1\tmtspefscr\005mtspr\006mtsprg\007"
    "mtsprg0\007mtsprg1\007mtsprg2\007mtsprg3\007mtsprg4\007mtsprg5\007mtspr"
    "g6\007mtsprg7\004mtsr\006mtsrin\006mtsrr0\006mtsrr1\006mtsrr2\006mtsrr3"
    "\006mttbhi\005mttbl\006mttblo\005mttbu\005mttcr\006mtuamr\007mtudscr\005"
    "mtvrd\010mtvrsave\006mtvrwa\006mtvrwz\006mtvscr\007mtvsrbm\010mtvsrbmi\006"
    "mtvsrd\007mtvsrdd\007mtvsrdm\007mtvsrhm\007mtvsrqm\007mtvsrwa\007mtvsrw"
    "m\007mtvsrws\007mtvsrwz\005mtxer\005mulhd\006mulhdu\005mulhw\006mulhwu\005"
    "mulld\006mulldo\005mulli\005mullw\006mullwo\004nand\003nap\003neg\004ne"
    "go\003nop\003nor\003not\002or\003orc\003ori\004oris\005paddi\006paddis\005"
    "paste\013pause_short\005pdepd\005pextd\007phwsync\003pla\004plbz\003pld"
    "\004plfd\004plfs\004plha\004plhz\003pli\004plis\004plwa\007plwsync\004p"
    "lwz\005plxsd\006plxssp\004plxv\005plxvp\017pmdmxvbf16gerx2\021pmdmxvbf1"
    "6gerx2nn\021pmdmxvbf16gerx2np\021pmdmxvbf16gerx2pn\021pmdmxvbf16gerx2pp"
    "\016pmdmxvf16gerx2\020pmdmxvf16gerx2nn\020pmdmxvf16gerx2np\020pmdmxvf16"
    "gerx2pn\020pmdmxvf16gerx2pp\015pmdmxvi8gerx4\017pmdmxvi8gerx4pp\020pmdm"
    "xvi8gerx4spp\014pmxvbf16ger2\016pmxvbf16ger2nn\016pmxvbf16ger2np\016pmx"
    "vbf16ger2pn\016pmxvbf16ger2pp\013pmxvf16ger2\015pmxvf16ger2nn\015pmxvf1"
    "6ger2np\015pmxvf16ger2pn\015pmxvf16ger2pp\npmxvf32ger\014pmxvf32gernn\014"
    "pmxvf32gernp\014pmxvf32gerpn\014pmxvf32gerpp\npmxvf64ger\014pmxvf64gern"
    "n\014pmxvf64gernp\014pmxvf64gerpn\014pmxvf64gerpp\013pmxvi16ger2\015pmx"
    "vi16ger2pp\014pmxvi16ger2s\016pmxvi16ger2spp\npmxvi4ger8\014pmxvi4ger8p"
    "p\npmxvi8ger4\014pmxvi8ger4pp\015pmxvi8ger4spp\007popcntb\007popcntd\007"
    "popcntw\004pstb\004pstd\005pstfd\005pstfs\004psth\004pstw\006pstxsd\007"
    "pstxssp\005pstxv\006pstxvp\005psubi\006psubis\007ptesync\tptesyncio\004"
    "rfci\004rfdi\005rfebb\003rfi\004rfid\005rfmci\005rldcl\005rldcr\005rldi"
    "c\006rldicl\006rldicr\006rldimi\006rlwimi\006rlwinm\005rlwnm\005rotld\006"
    "rotldi\005rotlw\006rotlwi\006rotrdi\006rotrwi\002sc\003scv\004setb\005s"
    "etbc\006setbcr\006setnbc\007setnbcr\006slbfee\005slbia\005slbie\006slbi"
    "eg\007slbmfee\007slbmfev\006slbmte\007slbsync\003sld\004sldi\003slw\004"
    "slwi\004srad\005sradi\004sraw\005srawi\003srd\004srdi\003srw\004srwi\003"
    "stb\006stbcix\005stbcx\006stbepx\004stbu\005stbux\004stbx\010stcisync\003"
    "std\005stdat\006stdbrx\006stdcix\005stdcx\004stdu\005stdux\004stdx\004s"
    "tfd\007stfdepx\005stfdu\006stfdux\005stfdx\006stfiwx\004stfs\005stfsu\006"
    "stfsux\005stfsx\003sth\006sthbrx\006sthcix\005sthcx\006sthepx\004sthu\005"
    "sthux\004sthx\004stmw\tstncisync\004stop\003stq\005stqcx\005stswi\006st"
    "sync\006stvebx\006stvehx\006stvewx\004stvx\005stvxl\003stw\005stwat\006"
    "stwbrx\006stwcix\005stwcx\006stwepx\004stwu\005stwux\004stwx\005stxsd\006"
    "stxsdx\007stxsibx\007stxsihx\007stxsiwx\006stxssp\007stxsspx\004stxv\010"
    "stxvb16x\007stxvd2x\007stxvh8x\005stxvl\006stxvll\005stxvp\tstxvpb32x\007"
    "stxvprl\010stxvprll\006stxvpx\007stxvrbx\007stxvrdx\007stxvrhx\006stxvr"
    "l\007stxvrll\007stxvrwx\007stxvw4x\005stxvx\003sub\004subc\004subf\005s"
    "ubfc\006subfco\005subfe\006subfeo\006subfic\006subfme\007subfmeo\005sub"
    "fo\006subfus\006subfze\007subfzeo\004subi\005subic\005subis\007subpcis\004"
    "sync\006tabort\010tabortdc\ttabortdci\010tabortwc\ttabortwci\006tbegin\006"
    "tcheck\002td\004tdeq\005tdeqi\004tdge\005tdgei\004tdgt\005tdgti\003tdi\004"
    "tdle\005tdlei\005tdlge\006tdlgei\005tdlgt\006tdlgti\005tdlle\006tdllei\005"
    "tdllt\006tdllti\005tdlng\006tdlngi\005tdlnl\006tdlnli\004tdlt\005tdlti\004"
    "tdne\005tdnei\004tdng\005tdngi\004tdnl\005tdnli\003tdu\004tdui\004tend\007"
    "tendall\005tlbia\005tlbie\007tlbieio\006tlbiel\006tlbiep\006tlbilx\ntlb"
    "ilxlpid\ttlbilxpid\010tlbilxva\007tlbivax\005tlbld\005tlbli\005tlbre\007"
    "tlbrehi\007tlbrelo\005tlbsx\007tlbsync\ttlbsyncio\005tlbwe\007tlbwehi\007"
    "tlbwelo\004trap\010trechkpt\010treclaim\007tresume\003tsr\010tsuspend\002"
    "tw\004tweq\005tweqi\004twge\005twgei\004twgt\005twgti\003twi\004twle\005"
    "twlei\005twlge\006twlgei\005twlgt\006twlgti\005twlle\006twllei\005twllt"
    "\006twllti\005twlng\006twlngi\005twlnl\006twlnli\004twlt\005twlti\004tw"
    "ne\005twnei\004twng\005twngi\004twnl\005twnli\003twu\004twui\007vabsdub"
    "\007vabsduh\007vabsduw\007vaddcuq\007vaddcuw\010vaddecuq\010vaddeuqm\006"
    "vaddfp\007vaddsbs\007vaddshs\007vaddsws\007vaddubm\007vaddubs\007vaddud"
    "m\007vadduhm\007vadduhs\007vadduqm\007vadduwm\007vadduws\004vand\005van"
    "dc\006vavgsb\006vavgsh\006vavgsw\006vavgub\006vavguh\006vavguw\007vbper"
    "md\007vbpermq\005vcfsx\007vcfuged\005vcfux\007vcipher\013vcipherlast\006"
    "vclrlb\006vclrrb\005vclzb\005vclzd\006vclzdm\005vclzh\010vclzlsbb\005vc"
    "lzw\007vcmpbfp\010vcmpeqfp\010vcmpequb\010vcmpequd\010vcmpequh\010vcmpe"
    "quq\010vcmpequw\010vcmpgefp\010vcmpgtfp\010vcmpgtsb\010vcmpgtsd\010vcmp"
    "gtsh\010vcmpgtsq\010vcmpgtsw\010vcmpgtub\010vcmpgtud\010vcmpgtuh\010vcm"
    "pgtuq\010vcmpgtuw\007vcmpneb\007vcmpneh\007vcmpnew\010vcmpnezb\010vcmpn"
    "ezh\010vcmpnezw\006vcmpsq\006vcmpuq\007vcntmbb\007vcntmbd\007vcntmbh\007"
    "vcntmbw\006vctsxs\006vctuxs\005vctzb\005vctzd\006vctzdm\005vctzh\010vct"
    "zlsbb\005vctzw\007vdivesd\007vdivesq\007vdivesw\007vdiveud\007vdiveuq\007"
    "vdiveuw\006vdivsd\006vdivsq\006vdivsw\006vdivud\006vdivuq\006vdivuw\004"
    "veqv\tvexpandbm\tvexpanddm\tvexpandhm\tvexpandqm\tvexpandwm\010vexptefp"
    "\tvextddvlx\tvextddvrx\nvextdubvlx\nvextdubvrx\nvextduhvlx\nvextduhvrx\n"
    "vextduwvlx\nvextduwvrx\nvextractbm\tvextractd\nvextractdm\nvextracthm\n"
    "vextractqm\nvextractub\nvextractuh\nvextractuw\nvextractwm\010vextsb2d\010"
    "vextsb2w\010vextsd2q\010vextsh2d\010vextsh2w\010vextsw2d\010vextublx\010"
    "vextubrx\010vextuhlx\010vextuhrx\010vextuwlx\010vextuwrx\005vgbbd\004vg"
    "nb\007vinsblx\007vinsbrx\010vinsbvlx\010vinsbvrx\005vinsd\007vinsdlx\007"
    "vinsdrx\010vinsertb\010vinsertd\010vinserth\010vinsertw\007vinshlx\007v"
    "inshrx\010vinshvlx\010vinshvrx\005vinsw\007vinswlx\007vinswrx\010vinswv"
    "lx\010vinswvrx\007vlogefp\007vmaddfp\006vmaxfp\006vmaxsb\006vmaxsd\006v"
    "maxsh\006vmaxsw\006vmaxub\006vmaxud\006vmaxuh\006vmaxuw\tvmhaddshs\nvmh"
    "raddshs\006vminfp\006vminsb\006vminsd\006vminsh\006vminsw\006vminub\006"
    "vminud\006vminuh\006vminuw\tvmladduhm\006vmodsd\006vmodsq\006vmodsw\006"
    "vmodud\006vmoduq\006vmoduw\003vmr\006vmrgew\006vmrghb\006vmrghh\006vmrg"
    "hw\006vmrglb\006vmrglh\006vmrglw\006vmrgow\010vmsumcud\010vmsummbm\010v"
    "msumshm\010vmsumshs\010vmsumubm\010vmsumudm\010vmsumuhm\010vmsumuhs\tvm"
    "ul10cuq\nvmul10ecuq\tvmul10euq\010vmul10uq\007vmulesb\007vmulesd\007vmu"
    "lesh\007vmulesw\007vmuleub\007vmuleud\007vmuleuh\007vmuleuw\007vmulhsd\007"
    "vmulhsw\007vmulhud\007vmulhuw\006vmulld\007vmulosb\007vmulosd\007vmulos"
    "h\007vmulosw\007vmuloub\007vmuloud\007vmulouh\007vmulouw\007vmuluwm\005"
    "vnand\010vncipher\014vncipherlast\005vnegd\005vnegw\010vnmsubfp\004vnor"
    "\004vnot\003vor\004vorc\006vpdepd\005vperm\006vpermr\010vpermxor\006vpe"
    "xtd\005vpkpx\007vpksdss\007vpksdus\007vpkshss\007vpkshus\007vpkswss\007"
    "vpkswus\007vpkudum\007vpkudus\007vpkuhum\007vpkuhus\007vpkuwum\007vpkuw"
    "us\007vpmsumb\007vpmsumd\007vpmsumh\007vpmsumw\010vpopcntb\010vpopcntd\010"
    "vpopcnth\010vpopcntw\007vprtybd\007vprtybq\007vprtybw\005vrefp\005vrfim"
    "\005vrfin\005vrfip\005vrfiz\004vrlb\004vrld\006vrldmi\006vrldnm\004vrlh"
    "\004vrlq\006vrlqmi\006vrlqnm\004vrlw\006vrlwmi\006vrlwnm\tvrsqrtefp\005"
    "vsbox\004vsel\nvshasigmad\nvshasigmaw\003vsl\004vslb\004vsld\006vsldbi\006"
    "vsldoi\004vslh\004vslo\004vslq\004vslv\004vslw\006vspltb\006vsplth\010v"
    "spltisb\010vspltish\010vspltisw\006vspltw\003vsr\005vsrab\005vsrad\005v"
    "srah\005vsraq\005vsraw\004vsrb\004vsrd\006vsrdbi\004vsrh\004vsro\004vsr"
    "q\004vsrv\004vsrw\007vstribl\007vstribr\007vstrihl\007vstrihr\007vsubcu"
    "q\007vsubcuw\010vsubecuq\010vsubeuqm\006vsubfp\007vsubsbs\007vsubshs\007"
    "vsubsws\007vsububm\007vsububs\007vsubudm\007vsubuhm\007vsubuhs\007vsubu"
    "qm\007vsubuwm\007vsubuws\010vsum2sws\010vsum4sbs\010vsum4shs\010vsum4ub"
    "s\007vsumsws\010vucmprhb\010vucmprhh\010vucmprhn\010vucmprlb\010vucmprl"
    "h\010vucmprln\007vupkhpx\007vupkhsb\007vupkhsh\nvupkhsntob\007vupkhsw\016"
    "vupkint4tobf16\016vupkint4tofp32\016vupkint8tobf16\016vupkint8tofp32\007"
    "vupklpx\007vupklsb\007vupklsh\nvupklsntob\007vupklsw\004vxor\004wait\010"
    "waitimpl\007waitrsv\005wrtee\006wrteei\005wsync\004xnop\003xor\004xori\005"
    "xoris\007xsabsdp\007xsabsqp\014xsaddaddsuqm\013xsaddadduqm\007xsadddp\007"
    "xsaddqp\010xsaddqpo\007xsaddsp\014xsaddsubsuqm\013xsaddsubuqm\txscmpeqd"
    "p\txscmpeqqp\nxscmpexpdp\nxscmpexpqp\txscmpgedp\txscmpgeqp\txscmpgtdp\t"
    "xscmpgtqp\010xscmpodp\010xscmpoqp\010xscmpudp\010xscmpuqp\txscpsgndp\tx"
    "scpsgnqp\010xscvdphp\010xscvdpqp\010xscvdpsp\txscvdpspn\nxscvdpsxds\nxs"
    "cvdpsxws\nxscvdpuxds\nxscvdpuxws\010xscvhpdp\010xscvqpdp\txscvqpdpo\txs"
    "cvqpsdz\txscvqpsqz\txscvqpswz\txscvqpudz\txscvqpuqz\txscvqpuwz\010xscvs"
    "dqp\010xscvspdp\txscvspdpn\010xscvsqqp\txscvsxddp\txscvsxdsp\010xscvudq"
    "p\010xscvuqqp\txscvuxddp\txscvuxdsp\007xsdivdp\007xsdivqp\010xsdivqpo\007"
    "xsdivsp\010xsiexpdp\010xsiexpqp\txsmaddadp\txsmaddasp\txsmaddmdp\txsmad"
    "dmsp\010xsmaddqp\txsmaddqpo\010xsmaxcdp\010xsmaxcqp\007xsmaxdp\010xsmax"
    "jdp\015xsmerge2t1uqm\015xsmerge2t2uqm\015xsmerge2t3uqm\015xsmerge3t1uqm"
    "\010xsmincdp\010xsmincqp\007xsmindp\010xsminjdp\txsmsubadp\txsmsubasp\t"
    "xsmsubmdp\txsmsubmsp\010xsmsubqp\txsmsubqpo\007xsmuldp\007xsmulqp\010xs"
    "mulqpo\007xsmulsp\010xsnabsdp\010xsnabsqp\007xsnegdp\007xsnegqp\nxsnmad"
    "dadp\nxsnmaddasp\nxsnmaddmdp\nxsnmaddmsp\txsnmaddqp\nxsnmaddqpo\nxsnmsu"
    "badp\nxsnmsubasp\nxsnmsubmdp\nxsnmsubmsp\txsnmsubqp\nxsnmsubqpo\006xsrd"
    "pi\007xsrdpic\007xsrdpim\007xsrdpip\007xsrdpiz\016xsrebase2t1uqm\016xsr"
    "ebase2t2uqm\016xsrebase2t3uqm\016xsrebase2t4uqm\016xsrebase3t1uqm\016xs"
    "rebase3t2uqm\016xsrebase3t3uqm\006xsredp\006xsresp\006xsrqpi\007xsrqpix"
    "\007xsrqpxp\005xsrsp\nxsrsqrtedp\nxsrsqrtesp\010xssqrtdp\010xssqrtqp\tx"
    "ssqrtqpo\010xssqrtsp\007xssubdp\007xssubqp\010xssubqpo\007xssubsp\010xs"
    "tdivdp\txstsqrtdp\txststdcdp\txststdcqp\txststdcsp\010xsxexpdp\010xsxex"
    "pqp\010xsxsigdp\010xsxsigqp\007xvabsdp\007xvabssp\007xvadddp\007xvaddsp"
    "\010xvadduhm\010xvadduwm\nxvbf16ger2\014xvbf16ger2nn\014xvbf16ger2np\014"
    "xvbf16ger2pn\014xvbf16ger2pp\txvcmpeqdp\txvcmpeqsp\txvcmpgedp\txvcmpges"
    "p\txvcmpgtdp\txvcmpgtsp\txvcpsgndp\txvcpsgnsp\013xvcvbf16spn\010xvcvdps"
    "p\nxvcvdpsxds\nxvcvdpsxws\nxvcvdpuxds\nxvcvdpuxws\010xvcvhpsp\nxvcvspbf"
    "16\010xvcvspdp\010xvcvsphp\nxvcvspsxds\nxvcvspsxws\nxvcvspuxds\nxvcvspu"
    "xws\txvcvsxddp\txvcvsxdsp\txvcvsxwdp\txvcvsxwsp\txvcvuxddp\txvcvuxdsp\t"
    "xvcvuxwdp\txvcvuxwsp\007xvdivdp\007xvdivsp\txvf16ger2\013xvf16ger2nn\013"
    "xvf16ger2np\013xvf16ger2pn\013xvf16ger2pp\010xvf32ger\nxvf32gernn\nxvf3"
    "2gernp\nxvf32gerpn\nxvf32gerpp\010xvf64ger\nxvf64gernn\nxvf64gernp\nxvf"
    "64gerpn\nxvf64gerpp\txvi16ger2\013xvi16ger2pp\nxvi16ger2s\014xvi16ger2s"
    "pp\010xvi4ger8\nxvi4ger8pp\010xvi8ger4\nxvi8ger4pp\013xvi8ger4spp\010xv"
    "iexpdp\010xviexpsp\txvmaddadp\txvmaddasp\txvmaddmdp\txvmaddmsp\007xvmax"
    "dp\007xvmaxsp\007xvmindp\007xvminsp\007xvmovdp\007xvmovsp\txvmsubadp\tx"
    "vmsubasp\txvmsubmdp\txvmsubmsp\007xvmuldp\010xvmulhsh\010xvmulhsw\010xv"
    "mulhuh\010xvmulhuw\007xvmulsp\010xvmuluhm\010xvmuluwm\010xvnabsdp\010xv"
    "nabssp\007xvnegdp\007xvnegsp\nxvnmaddadp\nxvnmaddasp\nxvnmaddmdp\nxvnma"
    "ddmsp\nxvnmsubadp\nxvnmsubasp\nxvnmsubmdp\nxvnmsubmsp\006xvrdpi\007xvrd"
    "pic\007xvrdpim\007xvrdpip\007xvrdpiz\006xvredp\006xvresp\005xvrlw\006xv"
    "rspi\007xvrspic\007xvrspim\007xvrspip\007xvrspiz\nxvrsqrtedp\nxvrsqrtes"
    "p\010xvsqrtdp\010xvsqrtsp\007xvsubdp\007xvsubsp\010xvsubuhm\010xvsubuwm"
    "\010xvtdivdp\010xvtdivsp\007xvtlsbb\txvtsqrtdp\txvtsqrtsp\txvtstdcdp\tx"
    "vtstdcsp\010xvxexpdp\010xvxexpsp\010xvxsigdp\010xvxsigsp\014xxaes128dec"
    "p\014xxaes128encp\016xxaes128genlkp\014xxaes192decp\014xxaes192encp\016"
    "xxaes192genlkp\014xxaes256decp\014xxaes256encp\016xxaes256genlkp\txxaes"
    "decp\txxaesencp\013xxaesgenlkp\txxblendvb\txxblendvd\txxblendvh\txxblen"
    "dvw\005xxbrd\005xxbrh\005xxbrq\005xxbrw\006xxeval\013xxextractuw\nxxgen"
    "pcvbm\nxxgenpcvdm\nxxgenpcvhm\nxxgenpcvwm\nxxgfmul128\015xxgfmul128gcm\015"
    "xxgfmul128xts\txxinsertw\006xxland\007xxlandc\006xxleqv\007xxlnand\006x"
    "xlnor\005xxlor\006xxlorc\006xxlxor\007xxmfacc\007xxmrghd\007xxmrghw\007"
    "xxmrgld\007xxmrglw\007xxmtacc\010xxmulmul\015xxmulmulhiadd\015xxmulmull"
    "oadd\006xxperm\010xxpermdi\007xxpermr\007xxpermx\005xxsel\txxsetaccz\007"
    "xxsldwi\007xxspltd\013xxsplti32dx\010xxspltib\txxspltidp\010xxspltiw\007"
    "xxspltw\txxssumudm\nxxssumudmc\015xxssumudmcext\007xxswapd";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
  AMFBS_ModernAs,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
  {Feature_ModernAsBit, }, // AMFBS_ModernAs
};

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
    uint32_t Opcode;
    uint16_t ConvertFn;
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
  { 0 /* add */, PPC::ADD8TLS_, Convert__RegG8RC1_0__RegG8RC1_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_TLSReg }, },
  { 0 /* add */, PPC::ADD4, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 0 /* add */, PPC::ADD4_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4 /* addc */, PPC::ADDC, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4 /* addc */, PPC::ADDC_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9 /* addco */, PPC::ADDCO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9 /* addco */, PPC::ADDCO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 15 /* adde */, PPC::ADDE, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 15 /* adde */, PPC::ADDE_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 20 /* addeo */, PPC::ADDEO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 20 /* addeo */, PPC::ADDEO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 26 /* addex */, PPC::ADDEX, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__U2Imm1_3, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC, MCK_U2Imm }, },
  { 32 /* addg6s */, PPC::ADDG6S, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 39 /* addi */, PPC::ADDI, Convert__RegGPRC1_0__RegGPRC_NOR01_1__S16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_S16Imm }, },
  { 44 /* addic */, PPC::ADDIC, Convert__RegGPRC1_0__RegGPRC1_1__S16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_S16Imm }, },
  { 44 /* addic */, PPC::ADDIC_rec, Convert__RegGPRC1_1__RegGPRC1_2__S16Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_S16Imm }, },
  { 50 /* addis */, PPC::ADDIS, Convert__RegGPRC1_0__RegGPRC_NOR01_1__S17Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_S17Imm }, },
  { 56 /* addme */, PPC::ADDME, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 56 /* addme */, PPC::ADDME_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 62 /* addmeo */, PPC::ADDMEO, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 62 /* addmeo */, PPC::ADDMEO_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 69 /* addo */, PPC::ADD4O, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 69 /* addo */, PPC::ADD4O_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 74 /* addpcis */, PPC::ADDPCIS, Convert__RegG8RC1_0__Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_Imm }, },
  { 82 /* addze */, PPC::ADDZE, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 82 /* addze */, PPC::ADDZE_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 88 /* addzeo */, PPC::ADDZEO, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 88 /* addzeo */, PPC::ADDZEO_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 95 /* and */, PPC::AND, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 95 /* and */, PPC::AND_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 99 /* andc */, PPC::ANDC, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 99 /* andc */, PPC::ANDC_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 104 /* andi */, PPC::ANDI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U16Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U16Imm }, },
  { 109 /* andis */, PPC::ANDIS_rec, Convert__RegGPRC1_1__RegGPRC1_2__U16Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U16Imm }, },
  { 115 /* attn */, PPC::ATTN, Convert_NoOperands, AMFBS_None, {  }, },
  { 120 /* b */, PPC::B, Convert__DirectBr1_0, AMFBS_None, { MCK_DirectBr }, },
  { 122 /* ba */, PPC::BA, Convert__DirectBr1_0, AMFBS_None, { MCK_DirectBr }, },
  { 125 /* bc */, PPC::gBC, Convert__U5Imm1_0__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 125 /* bc */, PPC::gBCat, Convert__U5Imm1_1__ATBitsAsHint1_0__RegCRBITRC1_2__CondBr1_3, AMFBS_None, { MCK_ATBitsAsHint, MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 128 /* bc+ */, PPC::gBCat, Convert__U5Imm1_0__imm_95_3__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 132 /* bc- */, PPC::gBCat, Convert__U5Imm1_0__imm_95_2__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 136 /* bca */, PPC::gBCA, Convert__U5Imm1_0__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 136 /* bca */, PPC::gBCAat, Convert__U5Imm1_1__ATBitsAsHint1_0__RegCRBITRC1_2__CondBr1_3, AMFBS_None, { MCK_ATBitsAsHint, MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 140 /* bca+ */, PPC::gBCAat, Convert__U5Imm1_0__imm_95_3__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 145 /* bca- */, PPC::gBCAat, Convert__U5Imm1_0__imm_95_2__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 150 /* bcctr */, PPC::gBCCTR, Convert__U5Imm1_0__RegCRBITRC1_1__imm_95_0, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC }, },
  { 150 /* bcctr */, PPC::gBCCTR, Convert__U5Imm1_0__RegCRBITRC1_1__Imm1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_Imm }, },
  { 156 /* bcctrl */, PPC::gBCCTRL, Convert__U5Imm1_0__RegCRBITRC1_1__imm_95_0, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC }, },
  { 156 /* bcctrl */, PPC::gBCCTRL, Convert__U5Imm1_0__RegCRBITRC1_1__Imm1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_Imm }, },
  { 163 /* bcdadd */, PPC::BCDADD_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3__U1Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 170 /* bcdcfn */, PPC::BCDCFN_rec, Convert__RegVRRC1_1__RegVRRC1_2__U1Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 177 /* bcdcfsq */, PPC::BCDCFSQ_rec, Convert__RegVRRC1_1__RegVRRC1_2__U1Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 185 /* bcdcfz */, PPC::BCDCFZ_rec, Convert__RegVRRC1_1__RegVRRC1_2__U1Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 192 /* bcdcpsgn */, PPC::BCDCPSGN_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 201 /* bcdctn */, PPC::BCDCTN_rec, Convert__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC }, },
  { 208 /* bcdctsq */, PPC::BCDCTSQ_rec, Convert__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC }, },
  { 216 /* bcdctz */, PPC::BCDCTZ_rec, Convert__RegVRRC1_1__RegVRRC1_2__U1Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 223 /* bcds */, PPC::BCDS_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3__U1Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 228 /* bcdsetsgn */, PPC::BCDSETSGN_rec, Convert__RegVRRC1_1__RegVRRC1_2__U1Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 238 /* bcdsr */, PPC::BCDSR_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3__U1Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 244 /* bcdsub */, PPC::BCDSUB_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3__U1Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 251 /* bcdtrunc */, PPC::BCDTRUNC_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3__U1Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 260 /* bcdus */, PPC::BCDUS_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 266 /* bcdutrunc */, PPC::BCDUTRUNC_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 276 /* bcl */, PPC::gBCL, Convert__U5Imm1_0__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 276 /* bcl */, PPC::gBCLat, Convert__U5Imm1_1__ATBitsAsHint1_0__RegCRBITRC1_2__CondBr1_3, AMFBS_None, { MCK_ATBitsAsHint, MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 280 /* bcl+ */, PPC::gBCLat, Convert__U5Imm1_0__imm_95_3__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 285 /* bcl- */, PPC::gBCLat, Convert__U5Imm1_0__imm_95_2__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 290 /* bcla */, PPC::gBCLA, Convert__U5Imm1_0__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 290 /* bcla */, PPC::gBCLAat, Convert__U5Imm1_1__ATBitsAsHint1_0__RegCRBITRC1_2__CondBr1_3, AMFBS_None, { MCK_ATBitsAsHint, MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 295 /* bcla+ */, PPC::gBCLAat, Convert__U5Imm1_0__imm_95_3__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 301 /* bcla- */, PPC::gBCLAat, Convert__U5Imm1_0__imm_95_2__RegCRBITRC1_1__CondBr1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_CondBr }, },
  { 307 /* bclr */, PPC::gBCLR, Convert__U5Imm1_0__RegCRBITRC1_1__imm_95_0, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC }, },
  { 307 /* bclr */, PPC::gBCLR, Convert__U5Imm1_0__RegCRBITRC1_1__Imm1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_Imm }, },
  { 312 /* bclrl */, PPC::gBCLRL, Convert__U5Imm1_0__RegCRBITRC1_1__imm_95_0, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC }, },
  { 312 /* bclrl */, PPC::gBCLRL, Convert__U5Imm1_0__RegCRBITRC1_1__Imm1_2, AMFBS_None, { MCK_U5Imm, MCK_RegCRBITRC, MCK_Imm }, },
  { 318 /* bctr */, PPC::BCTR, Convert_NoOperands, AMFBS_None, {  }, },
  { 323 /* bctrl */, PPC::BCTRL, Convert_NoOperands, AMFBS_None, {  }, },
  { 329 /* bdnz */, PPC::BDNZ, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 334 /* bdnz+ */, PPC::BDNZp, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 340 /* bdnz- */, PPC::BDNZm, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 346 /* bdnza */, PPC::BDNZA, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 352 /* bdnza+ */, PPC::BDNZAp, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 359 /* bdnza- */, PPC::BDNZAm, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 366 /* bdnzf */, PPC::gBC, Convert__imm_95_0__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 372 /* bdnzfa */, PPC::gBCA, Convert__imm_95_0__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 379 /* bdnzfl */, PPC::gBCL, Convert__imm_95_0__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 386 /* bdnzfla */, PPC::gBCLA, Convert__imm_95_0__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 394 /* bdnzflr */, PPC::gBCLR, Convert__imm_95_0__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 402 /* bdnzflrl */, PPC::gBCLRL, Convert__imm_95_0__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 411 /* bdnzl */, PPC::BDNZL, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 417 /* bdnzl+ */, PPC::BDNZLp, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 424 /* bdnzl- */, PPC::BDNZLm, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 431 /* bdnzla */, PPC::BDNZLA, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 438 /* bdnzla+ */, PPC::BDNZLAp, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 446 /* bdnzla- */, PPC::BDNZLAm, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 454 /* bdnzlr */, PPC::BDNZLR, Convert_NoOperands, AMFBS_None, {  }, },
  { 461 /* bdnzlr+ */, PPC::BDNZLRp, Convert_NoOperands, AMFBS_None, {  }, },
  { 469 /* bdnzlr- */, PPC::BDNZLRm, Convert_NoOperands, AMFBS_None, {  }, },
  { 477 /* bdnzlrl */, PPC::BDNZLRL, Convert_NoOperands, AMFBS_None, {  }, },
  { 485 /* bdnzlrl+ */, PPC::BDNZLRLp, Convert_NoOperands, AMFBS_None, {  }, },
  { 494 /* bdnzlrl- */, PPC::BDNZLRLm, Convert_NoOperands, AMFBS_None, {  }, },
  { 503 /* bdnzt */, PPC::gBC, Convert__imm_95_8__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 509 /* bdnzta */, PPC::gBCA, Convert__imm_95_8__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 516 /* bdnztl */, PPC::gBCL, Convert__imm_95_8__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 523 /* bdnztla */, PPC::gBCLA, Convert__imm_95_8__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 531 /* bdnztlr */, PPC::gBCLR, Convert__imm_95_8__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 539 /* bdnztlrl */, PPC::gBCLRL, Convert__imm_95_8__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 548 /* bdz */, PPC::BDZ, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 552 /* bdz+ */, PPC::BDZp, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 557 /* bdz- */, PPC::BDZm, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 562 /* bdza */, PPC::BDZA, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 567 /* bdza+ */, PPC::BDZAp, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 573 /* bdza- */, PPC::BDZAm, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 579 /* bdzf */, PPC::gBC, Convert__imm_95_2__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 584 /* bdzfa */, PPC::gBCA, Convert__imm_95_2__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 590 /* bdzfl */, PPC::gBCL, Convert__imm_95_2__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 596 /* bdzfla */, PPC::gBCLA, Convert__imm_95_2__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 603 /* bdzflr */, PPC::gBCLR, Convert__imm_95_2__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 610 /* bdzflrl */, PPC::gBCLRL, Convert__imm_95_2__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 618 /* bdzl */, PPC::BDZL, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 623 /* bdzl+ */, PPC::BDZLp, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 629 /* bdzl- */, PPC::BDZLm, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 635 /* bdzla */, PPC::BDZLA, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 641 /* bdzla+ */, PPC::BDZLAp, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 648 /* bdzla- */, PPC::BDZLAm, Convert__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 655 /* bdzlr */, PPC::BDZLR, Convert_NoOperands, AMFBS_None, {  }, },
  { 661 /* bdzlr+ */, PPC::BDZLRp, Convert_NoOperands, AMFBS_None, {  }, },
  { 668 /* bdzlr- */, PPC::BDZLRm, Convert_NoOperands, AMFBS_None, {  }, },
  { 675 /* bdzlrl */, PPC::BDZLRL, Convert_NoOperands, AMFBS_None, {  }, },
  { 682 /* bdzlrl+ */, PPC::BDZLRLp, Convert_NoOperands, AMFBS_None, {  }, },
  { 690 /* bdzlrl- */, PPC::BDZLRLm, Convert_NoOperands, AMFBS_None, {  }, },
  { 698 /* bdzt */, PPC::gBC, Convert__imm_95_10__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 703 /* bdzta */, PPC::gBCA, Convert__imm_95_10__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 709 /* bdztl */, PPC::gBCL, Convert__imm_95_10__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 715 /* bdztla */, PPC::gBCLA, Convert__imm_95_10__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 722 /* bdztlr */, PPC::gBCLR, Convert__imm_95_10__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 729 /* bdztlrl */, PPC::gBCLRL, Convert__imm_95_10__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 737 /* beq */, PPC::BCC, Convert__imm_95_76__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 737 /* beq */, PPC::BCC, Convert__imm_95_76__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 741 /* beq+ */, PPC::BCC, Convert__imm_95_79__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 741 /* beq+ */, PPC::BCC, Convert__imm_95_79__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 746 /* beq- */, PPC::BCC, Convert__imm_95_78__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 746 /* beq- */, PPC::BCC, Convert__imm_95_78__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 751 /* beqa */, PPC::BCCA, Convert__imm_95_76__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 751 /* beqa */, PPC::BCCA, Convert__imm_95_76__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 756 /* beqa+ */, PPC::BCCA, Convert__imm_95_79__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 756 /* beqa+ */, PPC::BCCA, Convert__imm_95_79__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 762 /* beqa- */, PPC::BCCA, Convert__imm_95_78__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 762 /* beqa- */, PPC::BCCA, Convert__imm_95_78__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 768 /* beqctr */, PPC::BCCCTR, Convert__imm_95_76__regCR0, AMFBS_None, {  }, },
  { 768 /* beqctr */, PPC::BCCCTR, Convert__imm_95_76__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 775 /* beqctr+ */, PPC::BCCCTR, Convert__imm_95_79__regCR0, AMFBS_None, {  }, },
  { 775 /* beqctr+ */, PPC::BCCCTR, Convert__imm_95_79__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 783 /* beqctr- */, PPC::BCCCTR, Convert__imm_95_78__regCR0, AMFBS_None, {  }, },
  { 783 /* beqctr- */, PPC::BCCCTR, Convert__imm_95_78__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 791 /* beqctrl */, PPC::BCCCTRL, Convert__imm_95_76__regCR0, AMFBS_None, {  }, },
  { 791 /* beqctrl */, PPC::BCCCTRL, Convert__imm_95_76__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 799 /* beqctrl+ */, PPC::BCCCTRL, Convert__imm_95_79__regCR0, AMFBS_None, {  }, },
  { 799 /* beqctrl+ */, PPC::BCCCTRL, Convert__imm_95_79__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 808 /* beqctrl- */, PPC::BCCCTRL, Convert__imm_95_78__regCR0, AMFBS_None, {  }, },
  { 808 /* beqctrl- */, PPC::BCCCTRL, Convert__imm_95_78__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 817 /* beql */, PPC::BCCL, Convert__imm_95_76__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 817 /* beql */, PPC::BCCL, Convert__imm_95_76__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 822 /* beql+ */, PPC::BCCL, Convert__imm_95_79__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 822 /* beql+ */, PPC::BCCL, Convert__imm_95_79__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 828 /* beql- */, PPC::BCCL, Convert__imm_95_78__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 828 /* beql- */, PPC::BCCL, Convert__imm_95_78__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 834 /* beqla */, PPC::BCCLA, Convert__imm_95_76__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 834 /* beqla */, PPC::BCCLA, Convert__imm_95_76__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 840 /* beqla+ */, PPC::BCCLA, Convert__imm_95_79__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 840 /* beqla+ */, PPC::BCCLA, Convert__imm_95_79__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 847 /* beqla- */, PPC::BCCLA, Convert__imm_95_78__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 847 /* beqla- */, PPC::BCCLA, Convert__imm_95_78__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 854 /* beqlr */, PPC::BCCLR, Convert__imm_95_76__regCR0, AMFBS_None, {  }, },
  { 854 /* beqlr */, PPC::BCCLR, Convert__imm_95_76__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 860 /* beqlr+ */, PPC::BCCLR, Convert__imm_95_79__regCR0, AMFBS_None, {  }, },
  { 860 /* beqlr+ */, PPC::BCCLR, Convert__imm_95_79__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 867 /* beqlr- */, PPC::BCCLR, Convert__imm_95_78__regCR0, AMFBS_None, {  }, },
  { 867 /* beqlr- */, PPC::BCCLR, Convert__imm_95_78__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 874 /* beqlrl */, PPC::BCCLRL, Convert__imm_95_76__regCR0, AMFBS_None, {  }, },
  { 874 /* beqlrl */, PPC::BCCLRL, Convert__imm_95_76__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 881 /* beqlrl+ */, PPC::BCCLRL, Convert__imm_95_79__regCR0, AMFBS_None, {  }, },
  { 881 /* beqlrl+ */, PPC::BCCLRL, Convert__imm_95_79__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 889 /* beqlrl- */, PPC::BCCLRL, Convert__imm_95_78__regCR0, AMFBS_None, {  }, },
  { 889 /* beqlrl- */, PPC::BCCLRL, Convert__imm_95_78__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 897 /* bf */, PPC::gBC, Convert__imm_95_4__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 900 /* bf+ */, PPC::gBC, Convert__imm_95_7__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 904 /* bf- */, PPC::gBC, Convert__imm_95_6__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 908 /* bfa */, PPC::gBCA, Convert__imm_95_4__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 912 /* bfa+ */, PPC::gBCA, Convert__imm_95_7__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 917 /* bfa- */, PPC::gBCA, Convert__imm_95_6__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 922 /* bfctr */, PPC::gBCCTR, Convert__imm_95_4__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 928 /* bfctr+ */, PPC::gBCCTR, Convert__imm_95_7__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 935 /* bfctr- */, PPC::gBCCTR, Convert__imm_95_6__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 942 /* bfctrl */, PPC::gBCCTRL, Convert__imm_95_4__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 949 /* bfctrl+ */, PPC::gBCCTRL, Convert__imm_95_7__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 957 /* bfctrl- */, PPC::gBCCTRL, Convert__imm_95_6__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 965 /* bfl */, PPC::gBCL, Convert__imm_95_4__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 969 /* bfl+ */, PPC::gBCL, Convert__imm_95_7__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 974 /* bfl- */, PPC::gBCL, Convert__imm_95_6__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 979 /* bfla */, PPC::gBCLA, Convert__imm_95_4__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 984 /* bfla+ */, PPC::gBCLA, Convert__imm_95_7__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 990 /* bfla- */, PPC::gBCLA, Convert__imm_95_6__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 996 /* bflr */, PPC::gBCLR, Convert__imm_95_4__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 1001 /* bflr+ */, PPC::gBCLR, Convert__imm_95_7__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 1007 /* bflr- */, PPC::gBCLR, Convert__imm_95_6__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 1013 /* bflrl */, PPC::gBCLRL, Convert__imm_95_4__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 1019 /* bflrl+ */, PPC::gBCLRL, Convert__imm_95_7__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 1026 /* bflrl- */, PPC::gBCLRL, Convert__imm_95_6__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 1033 /* bge */, PPC::BCC, Convert__imm_95_4__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1033 /* bge */, PPC::BCC, Convert__imm_95_4__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1037 /* bge+ */, PPC::BCC, Convert__imm_95_7__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1037 /* bge+ */, PPC::BCC, Convert__imm_95_7__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1042 /* bge- */, PPC::BCC, Convert__imm_95_6__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1042 /* bge- */, PPC::BCC, Convert__imm_95_6__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1047 /* bgea */, PPC::BCCA, Convert__imm_95_4__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1047 /* bgea */, PPC::BCCA, Convert__imm_95_4__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1052 /* bgea+ */, PPC::BCCA, Convert__imm_95_7__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1052 /* bgea+ */, PPC::BCCA, Convert__imm_95_7__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1058 /* bgea- */, PPC::BCCA, Convert__imm_95_6__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1058 /* bgea- */, PPC::BCCA, Convert__imm_95_6__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1064 /* bgectr */, PPC::BCCCTR, Convert__imm_95_4__regCR0, AMFBS_None, {  }, },
  { 1064 /* bgectr */, PPC::BCCCTR, Convert__imm_95_4__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1071 /* bgectr+ */, PPC::BCCCTR, Convert__imm_95_7__regCR0, AMFBS_None, {  }, },
  { 1071 /* bgectr+ */, PPC::BCCCTR, Convert__imm_95_7__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1079 /* bgectr- */, PPC::BCCCTR, Convert__imm_95_6__regCR0, AMFBS_None, {  }, },
  { 1079 /* bgectr- */, PPC::BCCCTR, Convert__imm_95_6__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1087 /* bgectrl */, PPC::BCCCTRL, Convert__imm_95_4__regCR0, AMFBS_None, {  }, },
  { 1087 /* bgectrl */, PPC::BCCCTRL, Convert__imm_95_4__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1095 /* bgectrl+ */, PPC::BCCCTRL, Convert__imm_95_7__regCR0, AMFBS_None, {  }, },
  { 1095 /* bgectrl+ */, PPC::BCCCTRL, Convert__imm_95_7__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1104 /* bgectrl- */, PPC::BCCCTRL, Convert__imm_95_6__regCR0, AMFBS_None, {  }, },
  { 1104 /* bgectrl- */, PPC::BCCCTRL, Convert__imm_95_6__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1113 /* bgel */, PPC::BCCL, Convert__imm_95_4__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1113 /* bgel */, PPC::BCCL, Convert__imm_95_4__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1118 /* bgel+ */, PPC::BCCL, Convert__imm_95_7__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1118 /* bgel+ */, PPC::BCCL, Convert__imm_95_7__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1124 /* bgel- */, PPC::BCCL, Convert__imm_95_6__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1124 /* bgel- */, PPC::BCCL, Convert__imm_95_6__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1130 /* bgela */, PPC::BCCLA, Convert__imm_95_4__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1130 /* bgela */, PPC::BCCLA, Convert__imm_95_4__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1136 /* bgela+ */, PPC::BCCLA, Convert__imm_95_7__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1136 /* bgela+ */, PPC::BCCLA, Convert__imm_95_7__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1143 /* bgela- */, PPC::BCCLA, Convert__imm_95_6__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1143 /* bgela- */, PPC::BCCLA, Convert__imm_95_6__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1150 /* bgelr */, PPC::BCCLR, Convert__imm_95_4__regCR0, AMFBS_None, {  }, },
  { 1150 /* bgelr */, PPC::BCCLR, Convert__imm_95_4__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1156 /* bgelr+ */, PPC::BCCLR, Convert__imm_95_7__regCR0, AMFBS_None, {  }, },
  { 1156 /* bgelr+ */, PPC::BCCLR, Convert__imm_95_7__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1163 /* bgelr- */, PPC::BCCLR, Convert__imm_95_6__regCR0, AMFBS_None, {  }, },
  { 1163 /* bgelr- */, PPC::BCCLR, Convert__imm_95_6__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1170 /* bgelrl */, PPC::BCCLRL, Convert__imm_95_4__regCR0, AMFBS_None, {  }, },
  { 1170 /* bgelrl */, PPC::BCCLRL, Convert__imm_95_4__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1177 /* bgelrl+ */, PPC::BCCLRL, Convert__imm_95_7__regCR0, AMFBS_None, {  }, },
  { 1177 /* bgelrl+ */, PPC::BCCLRL, Convert__imm_95_7__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1185 /* bgelrl- */, PPC::BCCLRL, Convert__imm_95_6__regCR0, AMFBS_None, {  }, },
  { 1185 /* bgelrl- */, PPC::BCCLRL, Convert__imm_95_6__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1193 /* bgt */, PPC::BCC, Convert__imm_95_44__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1193 /* bgt */, PPC::BCC, Convert__imm_95_44__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1197 /* bgt+ */, PPC::BCC, Convert__imm_95_47__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1197 /* bgt+ */, PPC::BCC, Convert__imm_95_47__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1202 /* bgt- */, PPC::BCC, Convert__imm_95_46__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1202 /* bgt- */, PPC::BCC, Convert__imm_95_46__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1207 /* bgta */, PPC::BCCA, Convert__imm_95_44__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1207 /* bgta */, PPC::BCCA, Convert__imm_95_44__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1212 /* bgta+ */, PPC::BCCA, Convert__imm_95_47__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1212 /* bgta+ */, PPC::BCCA, Convert__imm_95_47__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1218 /* bgta- */, PPC::BCCA, Convert__imm_95_46__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1218 /* bgta- */, PPC::BCCA, Convert__imm_95_46__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1224 /* bgtctr */, PPC::BCCCTR, Convert__imm_95_44__regCR0, AMFBS_None, {  }, },
  { 1224 /* bgtctr */, PPC::BCCCTR, Convert__imm_95_44__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1231 /* bgtctr+ */, PPC::BCCCTR, Convert__imm_95_47__regCR0, AMFBS_None, {  }, },
  { 1231 /* bgtctr+ */, PPC::BCCCTR, Convert__imm_95_47__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1239 /* bgtctr- */, PPC::BCCCTR, Convert__imm_95_46__regCR0, AMFBS_None, {  }, },
  { 1239 /* bgtctr- */, PPC::BCCCTR, Convert__imm_95_46__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1247 /* bgtctrl */, PPC::BCCCTRL, Convert__imm_95_44__regCR0, AMFBS_None, {  }, },
  { 1247 /* bgtctrl */, PPC::BCCCTRL, Convert__imm_95_44__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1255 /* bgtctrl+ */, PPC::BCCCTRL, Convert__imm_95_47__regCR0, AMFBS_None, {  }, },
  { 1255 /* bgtctrl+ */, PPC::BCCCTRL, Convert__imm_95_47__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1264 /* bgtctrl- */, PPC::BCCCTRL, Convert__imm_95_46__regCR0, AMFBS_None, {  }, },
  { 1264 /* bgtctrl- */, PPC::BCCCTRL, Convert__imm_95_46__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1273 /* bgtl */, PPC::BCCL, Convert__imm_95_44__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1273 /* bgtl */, PPC::BCCL, Convert__imm_95_44__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1278 /* bgtl+ */, PPC::BCCL, Convert__imm_95_47__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1278 /* bgtl+ */, PPC::BCCL, Convert__imm_95_47__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1284 /* bgtl- */, PPC::BCCL, Convert__imm_95_46__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1284 /* bgtl- */, PPC::BCCL, Convert__imm_95_46__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1290 /* bgtla */, PPC::BCCLA, Convert__imm_95_44__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1290 /* bgtla */, PPC::BCCLA, Convert__imm_95_44__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1296 /* bgtla+ */, PPC::BCCLA, Convert__imm_95_47__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1296 /* bgtla+ */, PPC::BCCLA, Convert__imm_95_47__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1303 /* bgtla- */, PPC::BCCLA, Convert__imm_95_46__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1303 /* bgtla- */, PPC::BCCLA, Convert__imm_95_46__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1310 /* bgtlr */, PPC::BCCLR, Convert__imm_95_44__regCR0, AMFBS_None, {  }, },
  { 1310 /* bgtlr */, PPC::BCCLR, Convert__imm_95_44__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1316 /* bgtlr+ */, PPC::BCCLR, Convert__imm_95_47__regCR0, AMFBS_None, {  }, },
  { 1316 /* bgtlr+ */, PPC::BCCLR, Convert__imm_95_47__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1323 /* bgtlr- */, PPC::BCCLR, Convert__imm_95_46__regCR0, AMFBS_None, {  }, },
  { 1323 /* bgtlr- */, PPC::BCCLR, Convert__imm_95_46__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1330 /* bgtlrl */, PPC::BCCLRL, Convert__imm_95_44__regCR0, AMFBS_None, {  }, },
  { 1330 /* bgtlrl */, PPC::BCCLRL, Convert__imm_95_44__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1337 /* bgtlrl+ */, PPC::BCCLRL, Convert__imm_95_47__regCR0, AMFBS_None, {  }, },
  { 1337 /* bgtlrl+ */, PPC::BCCLRL, Convert__imm_95_47__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1345 /* bgtlrl- */, PPC::BCCLRL, Convert__imm_95_46__regCR0, AMFBS_None, {  }, },
  { 1345 /* bgtlrl- */, PPC::BCCLRL, Convert__imm_95_46__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1353 /* bl */, PPC::BL, Convert__DirectBr1_0, AMFBS_None, { MCK_DirectBr }, },
  { 1353 /* bl */, PPC::BL8_TLS_, Convert__DirectBr1_0__Imm1_1, AMFBS_None, { MCK_DirectBr, MCK_Imm }, },
  { 1356 /* bla */, PPC::BLA, Convert__DirectBr1_0, AMFBS_None, { MCK_DirectBr }, },
  { 1360 /* ble */, PPC::BCC, Convert__imm_95_36__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1360 /* ble */, PPC::BCC, Convert__imm_95_36__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1364 /* ble+ */, PPC::BCC, Convert__imm_95_39__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1364 /* ble+ */, PPC::BCC, Convert__imm_95_39__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1369 /* ble- */, PPC::BCC, Convert__imm_95_38__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1369 /* ble- */, PPC::BCC, Convert__imm_95_38__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1374 /* blea */, PPC::BCCA, Convert__imm_95_36__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1374 /* blea */, PPC::BCCA, Convert__imm_95_36__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1379 /* blea+ */, PPC::BCCA, Convert__imm_95_39__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1379 /* blea+ */, PPC::BCCA, Convert__imm_95_39__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1385 /* blea- */, PPC::BCCA, Convert__imm_95_38__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1385 /* blea- */, PPC::BCCA, Convert__imm_95_38__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1391 /* blectr */, PPC::BCCCTR, Convert__imm_95_36__regCR0, AMFBS_None, {  }, },
  { 1391 /* blectr */, PPC::BCCCTR, Convert__imm_95_36__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1398 /* blectr+ */, PPC::BCCCTR, Convert__imm_95_39__regCR0, AMFBS_None, {  }, },
  { 1398 /* blectr+ */, PPC::BCCCTR, Convert__imm_95_39__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1406 /* blectr- */, PPC::BCCCTR, Convert__imm_95_38__regCR0, AMFBS_None, {  }, },
  { 1406 /* blectr- */, PPC::BCCCTR, Convert__imm_95_38__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1414 /* blectrl */, PPC::BCCCTRL, Convert__imm_95_36__regCR0, AMFBS_None, {  }, },
  { 1414 /* blectrl */, PPC::BCCCTRL, Convert__imm_95_36__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1422 /* blectrl+ */, PPC::BCCCTRL, Convert__imm_95_39__regCR0, AMFBS_None, {  }, },
  { 1422 /* blectrl+ */, PPC::BCCCTRL, Convert__imm_95_39__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1431 /* blectrl- */, PPC::BCCCTRL, Convert__imm_95_38__regCR0, AMFBS_None, {  }, },
  { 1431 /* blectrl- */, PPC::BCCCTRL, Convert__imm_95_38__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1440 /* blel */, PPC::BCCL, Convert__imm_95_36__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1440 /* blel */, PPC::BCCL, Convert__imm_95_36__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1445 /* blel+ */, PPC::BCCL, Convert__imm_95_39__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1445 /* blel+ */, PPC::BCCL, Convert__imm_95_39__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1451 /* blel- */, PPC::BCCL, Convert__imm_95_38__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1451 /* blel- */, PPC::BCCL, Convert__imm_95_38__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1457 /* blela */, PPC::BCCLA, Convert__imm_95_36__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1457 /* blela */, PPC::BCCLA, Convert__imm_95_36__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1463 /* blela+ */, PPC::BCCLA, Convert__imm_95_39__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1463 /* blela+ */, PPC::BCCLA, Convert__imm_95_39__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1470 /* blela- */, PPC::BCCLA, Convert__imm_95_38__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1470 /* blela- */, PPC::BCCLA, Convert__imm_95_38__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1477 /* blelr */, PPC::BCCLR, Convert__imm_95_36__regCR0, AMFBS_None, {  }, },
  { 1477 /* blelr */, PPC::BCCLR, Convert__imm_95_36__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1483 /* blelr+ */, PPC::BCCLR, Convert__imm_95_39__regCR0, AMFBS_None, {  }, },
  { 1483 /* blelr+ */, PPC::BCCLR, Convert__imm_95_39__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1490 /* blelr- */, PPC::BCCLR, Convert__imm_95_38__regCR0, AMFBS_None, {  }, },
  { 1490 /* blelr- */, PPC::BCCLR, Convert__imm_95_38__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1497 /* blelrl */, PPC::BCCLRL, Convert__imm_95_36__regCR0, AMFBS_None, {  }, },
  { 1497 /* blelrl */, PPC::BCCLRL, Convert__imm_95_36__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1504 /* blelrl+ */, PPC::BCCLRL, Convert__imm_95_39__regCR0, AMFBS_None, {  }, },
  { 1504 /* blelrl+ */, PPC::BCCLRL, Convert__imm_95_39__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1512 /* blelrl- */, PPC::BCCLRL, Convert__imm_95_38__regCR0, AMFBS_None, {  }, },
  { 1512 /* blelrl- */, PPC::BCCLRL, Convert__imm_95_38__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1520 /* blr */, PPC::BLR, Convert_NoOperands, AMFBS_None, {  }, },
  { 1524 /* blrl */, PPC::BLRL, Convert_NoOperands, AMFBS_None, {  }, },
  { 1529 /* blt */, PPC::BCC, Convert__imm_95_12__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1529 /* blt */, PPC::BCC, Convert__imm_95_12__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1533 /* blt+ */, PPC::BCC, Convert__imm_95_15__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1533 /* blt+ */, PPC::BCC, Convert__imm_95_15__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1538 /* blt- */, PPC::BCC, Convert__imm_95_14__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1538 /* blt- */, PPC::BCC, Convert__imm_95_14__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1543 /* blta */, PPC::BCCA, Convert__imm_95_12__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1543 /* blta */, PPC::BCCA, Convert__imm_95_12__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1548 /* blta+ */, PPC::BCCA, Convert__imm_95_15__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1548 /* blta+ */, PPC::BCCA, Convert__imm_95_15__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1554 /* blta- */, PPC::BCCA, Convert__imm_95_14__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1554 /* blta- */, PPC::BCCA, Convert__imm_95_14__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1560 /* bltctr */, PPC::BCCCTR, Convert__imm_95_12__regCR0, AMFBS_None, {  }, },
  { 1560 /* bltctr */, PPC::BCCCTR, Convert__imm_95_12__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1567 /* bltctr+ */, PPC::BCCCTR, Convert__imm_95_15__regCR0, AMFBS_None, {  }, },
  { 1567 /* bltctr+ */, PPC::BCCCTR, Convert__imm_95_15__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1575 /* bltctr- */, PPC::BCCCTR, Convert__imm_95_14__regCR0, AMFBS_None, {  }, },
  { 1575 /* bltctr- */, PPC::BCCCTR, Convert__imm_95_14__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1583 /* bltctrl */, PPC::BCCCTRL, Convert__imm_95_12__regCR0, AMFBS_None, {  }, },
  { 1583 /* bltctrl */, PPC::BCCCTRL, Convert__imm_95_12__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1591 /* bltctrl+ */, PPC::BCCCTRL, Convert__imm_95_15__regCR0, AMFBS_None, {  }, },
  { 1591 /* bltctrl+ */, PPC::BCCCTRL, Convert__imm_95_15__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1600 /* bltctrl- */, PPC::BCCCTRL, Convert__imm_95_14__regCR0, AMFBS_None, {  }, },
  { 1600 /* bltctrl- */, PPC::BCCCTRL, Convert__imm_95_14__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1609 /* bltl */, PPC::BCCL, Convert__imm_95_12__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1609 /* bltl */, PPC::BCCL, Convert__imm_95_12__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1614 /* bltl+ */, PPC::BCCL, Convert__imm_95_15__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1614 /* bltl+ */, PPC::BCCL, Convert__imm_95_15__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1620 /* bltl- */, PPC::BCCL, Convert__imm_95_14__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1620 /* bltl- */, PPC::BCCL, Convert__imm_95_14__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1626 /* bltla */, PPC::BCCLA, Convert__imm_95_12__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1626 /* bltla */, PPC::BCCLA, Convert__imm_95_12__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1632 /* bltla+ */, PPC::BCCLA, Convert__imm_95_15__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1632 /* bltla+ */, PPC::BCCLA, Convert__imm_95_15__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1639 /* bltla- */, PPC::BCCLA, Convert__imm_95_14__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1639 /* bltla- */, PPC::BCCLA, Convert__imm_95_14__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1646 /* bltlr */, PPC::BCCLR, Convert__imm_95_12__regCR0, AMFBS_None, {  }, },
  { 1646 /* bltlr */, PPC::BCCLR, Convert__imm_95_12__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1652 /* bltlr+ */, PPC::BCCLR, Convert__imm_95_15__regCR0, AMFBS_None, {  }, },
  { 1652 /* bltlr+ */, PPC::BCCLR, Convert__imm_95_15__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1659 /* bltlr- */, PPC::BCCLR, Convert__imm_95_14__regCR0, AMFBS_None, {  }, },
  { 1659 /* bltlr- */, PPC::BCCLR, Convert__imm_95_14__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1666 /* bltlrl */, PPC::BCCLRL, Convert__imm_95_12__regCR0, AMFBS_None, {  }, },
  { 1666 /* bltlrl */, PPC::BCCLRL, Convert__imm_95_12__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1673 /* bltlrl+ */, PPC::BCCLRL, Convert__imm_95_15__regCR0, AMFBS_None, {  }, },
  { 1673 /* bltlrl+ */, PPC::BCCLRL, Convert__imm_95_15__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1681 /* bltlrl- */, PPC::BCCLRL, Convert__imm_95_14__regCR0, AMFBS_None, {  }, },
  { 1681 /* bltlrl- */, PPC::BCCLRL, Convert__imm_95_14__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1689 /* bne */, PPC::BCC, Convert__imm_95_68__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1689 /* bne */, PPC::BCC, Convert__imm_95_68__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1693 /* bne+ */, PPC::BCC, Convert__imm_95_71__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1693 /* bne+ */, PPC::BCC, Convert__imm_95_71__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1698 /* bne- */, PPC::BCC, Convert__imm_95_70__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1698 /* bne- */, PPC::BCC, Convert__imm_95_70__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1703 /* bnea */, PPC::BCCA, Convert__imm_95_68__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1703 /* bnea */, PPC::BCCA, Convert__imm_95_68__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1708 /* bnea+ */, PPC::BCCA, Convert__imm_95_71__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1708 /* bnea+ */, PPC::BCCA, Convert__imm_95_71__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1714 /* bnea- */, PPC::BCCA, Convert__imm_95_70__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1714 /* bnea- */, PPC::BCCA, Convert__imm_95_70__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1720 /* bnectr */, PPC::BCCCTR, Convert__imm_95_68__regCR0, AMFBS_None, {  }, },
  { 1720 /* bnectr */, PPC::BCCCTR, Convert__imm_95_68__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1727 /* bnectr+ */, PPC::BCCCTR, Convert__imm_95_71__regCR0, AMFBS_None, {  }, },
  { 1727 /* bnectr+ */, PPC::BCCCTR, Convert__imm_95_71__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1735 /* bnectr- */, PPC::BCCCTR, Convert__imm_95_70__regCR0, AMFBS_None, {  }, },
  { 1735 /* bnectr- */, PPC::BCCCTR, Convert__imm_95_70__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1743 /* bnectrl */, PPC::BCCCTRL, Convert__imm_95_68__regCR0, AMFBS_None, {  }, },
  { 1743 /* bnectrl */, PPC::BCCCTRL, Convert__imm_95_68__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1751 /* bnectrl+ */, PPC::BCCCTRL, Convert__imm_95_71__regCR0, AMFBS_None, {  }, },
  { 1751 /* bnectrl+ */, PPC::BCCCTRL, Convert__imm_95_71__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1760 /* bnectrl- */, PPC::BCCCTRL, Convert__imm_95_70__regCR0, AMFBS_None, {  }, },
  { 1760 /* bnectrl- */, PPC::BCCCTRL, Convert__imm_95_70__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1769 /* bnel */, PPC::BCCL, Convert__imm_95_68__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1769 /* bnel */, PPC::BCCL, Convert__imm_95_68__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1774 /* bnel+ */, PPC::BCCL, Convert__imm_95_71__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1774 /* bnel+ */, PPC::BCCL, Convert__imm_95_71__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1780 /* bnel- */, PPC::BCCL, Convert__imm_95_70__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1780 /* bnel- */, PPC::BCCL, Convert__imm_95_70__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1786 /* bnela */, PPC::BCCLA, Convert__imm_95_68__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1786 /* bnela */, PPC::BCCLA, Convert__imm_95_68__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1792 /* bnela+ */, PPC::BCCLA, Convert__imm_95_71__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1792 /* bnela+ */, PPC::BCCLA, Convert__imm_95_71__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1799 /* bnela- */, PPC::BCCLA, Convert__imm_95_70__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1799 /* bnela- */, PPC::BCCLA, Convert__imm_95_70__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1806 /* bnelr */, PPC::BCCLR, Convert__imm_95_68__regCR0, AMFBS_None, {  }, },
  { 1806 /* bnelr */, PPC::BCCLR, Convert__imm_95_68__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1812 /* bnelr+ */, PPC::BCCLR, Convert__imm_95_71__regCR0, AMFBS_None, {  }, },
  { 1812 /* bnelr+ */, PPC::BCCLR, Convert__imm_95_71__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1819 /* bnelr- */, PPC::BCCLR, Convert__imm_95_70__regCR0, AMFBS_None, {  }, },
  { 1819 /* bnelr- */, PPC::BCCLR, Convert__imm_95_70__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1826 /* bnelrl */, PPC::BCCLRL, Convert__imm_95_68__regCR0, AMFBS_None, {  }, },
  { 1826 /* bnelrl */, PPC::BCCLRL, Convert__imm_95_68__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1833 /* bnelrl+ */, PPC::BCCLRL, Convert__imm_95_71__regCR0, AMFBS_None, {  }, },
  { 1833 /* bnelrl+ */, PPC::BCCLRL, Convert__imm_95_71__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1841 /* bnelrl- */, PPC::BCCLRL, Convert__imm_95_70__regCR0, AMFBS_None, {  }, },
  { 1841 /* bnelrl- */, PPC::BCCLRL, Convert__imm_95_70__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1849 /* bng */, PPC::BCC, Convert__imm_95_36__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1849 /* bng */, PPC::BCC, Convert__imm_95_36__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1853 /* bng+ */, PPC::BCC, Convert__imm_95_39__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1853 /* bng+ */, PPC::BCC, Convert__imm_95_39__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1858 /* bng- */, PPC::BCC, Convert__imm_95_38__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1858 /* bng- */, PPC::BCC, Convert__imm_95_38__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1863 /* bnga */, PPC::BCCA, Convert__imm_95_36__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1863 /* bnga */, PPC::BCCA, Convert__imm_95_36__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1868 /* bnga+ */, PPC::BCCA, Convert__imm_95_39__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1868 /* bnga+ */, PPC::BCCA, Convert__imm_95_39__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1874 /* bnga- */, PPC::BCCA, Convert__imm_95_38__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1874 /* bnga- */, PPC::BCCA, Convert__imm_95_38__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1880 /* bngctr */, PPC::BCCCTR, Convert__imm_95_36__regCR0, AMFBS_None, {  }, },
  { 1880 /* bngctr */, PPC::BCCCTR, Convert__imm_95_36__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1887 /* bngctr+ */, PPC::BCCCTR, Convert__imm_95_39__regCR0, AMFBS_None, {  }, },
  { 1887 /* bngctr+ */, PPC::BCCCTR, Convert__imm_95_39__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1895 /* bngctr- */, PPC::BCCCTR, Convert__imm_95_38__regCR0, AMFBS_None, {  }, },
  { 1895 /* bngctr- */, PPC::BCCCTR, Convert__imm_95_38__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1903 /* bngctrl */, PPC::BCCCTRL, Convert__imm_95_36__regCR0, AMFBS_None, {  }, },
  { 1903 /* bngctrl */, PPC::BCCCTRL, Convert__imm_95_36__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1911 /* bngctrl+ */, PPC::BCCCTRL, Convert__imm_95_39__regCR0, AMFBS_None, {  }, },
  { 1911 /* bngctrl+ */, PPC::BCCCTRL, Convert__imm_95_39__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1920 /* bngctrl- */, PPC::BCCCTRL, Convert__imm_95_38__regCR0, AMFBS_None, {  }, },
  { 1920 /* bngctrl- */, PPC::BCCCTRL, Convert__imm_95_38__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1929 /* bngl */, PPC::BCCL, Convert__imm_95_36__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1929 /* bngl */, PPC::BCCL, Convert__imm_95_36__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1934 /* bngl+ */, PPC::BCCL, Convert__imm_95_39__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1934 /* bngl+ */, PPC::BCCL, Convert__imm_95_39__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1940 /* bngl- */, PPC::BCCL, Convert__imm_95_38__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1940 /* bngl- */, PPC::BCCL, Convert__imm_95_38__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1946 /* bngla */, PPC::BCCLA, Convert__imm_95_36__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1946 /* bngla */, PPC::BCCLA, Convert__imm_95_36__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1952 /* bngla+ */, PPC::BCCLA, Convert__imm_95_39__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1952 /* bngla+ */, PPC::BCCLA, Convert__imm_95_39__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1959 /* bngla- */, PPC::BCCLA, Convert__imm_95_38__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 1959 /* bngla- */, PPC::BCCLA, Convert__imm_95_38__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 1966 /* bnglr */, PPC::BCCLR, Convert__imm_95_36__regCR0, AMFBS_None, {  }, },
  { 1966 /* bnglr */, PPC::BCCLR, Convert__imm_95_36__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1972 /* bnglr+ */, PPC::BCCLR, Convert__imm_95_39__regCR0, AMFBS_None, {  }, },
  { 1972 /* bnglr+ */, PPC::BCCLR, Convert__imm_95_39__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1979 /* bnglr- */, PPC::BCCLR, Convert__imm_95_38__regCR0, AMFBS_None, {  }, },
  { 1979 /* bnglr- */, PPC::BCCLR, Convert__imm_95_38__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1986 /* bnglrl */, PPC::BCCLRL, Convert__imm_95_36__regCR0, AMFBS_None, {  }, },
  { 1986 /* bnglrl */, PPC::BCCLRL, Convert__imm_95_36__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 1993 /* bnglrl+ */, PPC::BCCLRL, Convert__imm_95_39__regCR0, AMFBS_None, {  }, },
  { 1993 /* bnglrl+ */, PPC::BCCLRL, Convert__imm_95_39__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2001 /* bnglrl- */, PPC::BCCLRL, Convert__imm_95_38__regCR0, AMFBS_None, {  }, },
  { 2001 /* bnglrl- */, PPC::BCCLRL, Convert__imm_95_38__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2009 /* bnl */, PPC::BCC, Convert__imm_95_4__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2009 /* bnl */, PPC::BCC, Convert__imm_95_4__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2013 /* bnl+ */, PPC::BCC, Convert__imm_95_7__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2013 /* bnl+ */, PPC::BCC, Convert__imm_95_7__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2018 /* bnl- */, PPC::BCC, Convert__imm_95_6__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2018 /* bnl- */, PPC::BCC, Convert__imm_95_6__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2023 /* bnla */, PPC::BCCA, Convert__imm_95_4__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2023 /* bnla */, PPC::BCCA, Convert__imm_95_4__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2028 /* bnla+ */, PPC::BCCA, Convert__imm_95_7__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2028 /* bnla+ */, PPC::BCCA, Convert__imm_95_7__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2034 /* bnla- */, PPC::BCCA, Convert__imm_95_6__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2034 /* bnla- */, PPC::BCCA, Convert__imm_95_6__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2040 /* bnlctr */, PPC::BCCCTR, Convert__imm_95_4__regCR0, AMFBS_None, {  }, },
  { 2040 /* bnlctr */, PPC::BCCCTR, Convert__imm_95_4__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2047 /* bnlctr+ */, PPC::BCCCTR, Convert__imm_95_7__regCR0, AMFBS_None, {  }, },
  { 2047 /* bnlctr+ */, PPC::BCCCTR, Convert__imm_95_7__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2055 /* bnlctr- */, PPC::BCCCTR, Convert__imm_95_6__regCR0, AMFBS_None, {  }, },
  { 2055 /* bnlctr- */, PPC::BCCCTR, Convert__imm_95_6__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2063 /* bnlctrl */, PPC::BCCCTRL, Convert__imm_95_4__regCR0, AMFBS_None, {  }, },
  { 2063 /* bnlctrl */, PPC::BCCCTRL, Convert__imm_95_4__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2071 /* bnlctrl+ */, PPC::BCCCTRL, Convert__imm_95_7__regCR0, AMFBS_None, {  }, },
  { 2071 /* bnlctrl+ */, PPC::BCCCTRL, Convert__imm_95_7__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2080 /* bnlctrl- */, PPC::BCCCTRL, Convert__imm_95_6__regCR0, AMFBS_None, {  }, },
  { 2080 /* bnlctrl- */, PPC::BCCCTRL, Convert__imm_95_6__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2089 /* bnll */, PPC::BCCL, Convert__imm_95_4__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2089 /* bnll */, PPC::BCCL, Convert__imm_95_4__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2094 /* bnll+ */, PPC::BCCL, Convert__imm_95_7__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2094 /* bnll+ */, PPC::BCCL, Convert__imm_95_7__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2100 /* bnll- */, PPC::BCCL, Convert__imm_95_6__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2100 /* bnll- */, PPC::BCCL, Convert__imm_95_6__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2106 /* bnlla */, PPC::BCCLA, Convert__imm_95_4__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2106 /* bnlla */, PPC::BCCLA, Convert__imm_95_4__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2112 /* bnlla+ */, PPC::BCCLA, Convert__imm_95_7__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2112 /* bnlla+ */, PPC::BCCLA, Convert__imm_95_7__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2119 /* bnlla- */, PPC::BCCLA, Convert__imm_95_6__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2119 /* bnlla- */, PPC::BCCLA, Convert__imm_95_6__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2126 /* bnllr */, PPC::BCCLR, Convert__imm_95_4__regCR0, AMFBS_None, {  }, },
  { 2126 /* bnllr */, PPC::BCCLR, Convert__imm_95_4__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2132 /* bnllr+ */, PPC::BCCLR, Convert__imm_95_7__regCR0, AMFBS_None, {  }, },
  { 2132 /* bnllr+ */, PPC::BCCLR, Convert__imm_95_7__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2139 /* bnllr- */, PPC::BCCLR, Convert__imm_95_6__regCR0, AMFBS_None, {  }, },
  { 2139 /* bnllr- */, PPC::BCCLR, Convert__imm_95_6__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2146 /* bnllrl */, PPC::BCCLRL, Convert__imm_95_4__regCR0, AMFBS_None, {  }, },
  { 2146 /* bnllrl */, PPC::BCCLRL, Convert__imm_95_4__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2153 /* bnllrl+ */, PPC::BCCLRL, Convert__imm_95_7__regCR0, AMFBS_None, {  }, },
  { 2153 /* bnllrl+ */, PPC::BCCLRL, Convert__imm_95_7__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2161 /* bnllrl- */, PPC::BCCLRL, Convert__imm_95_6__regCR0, AMFBS_None, {  }, },
  { 2161 /* bnllrl- */, PPC::BCCLRL, Convert__imm_95_6__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2169 /* bns */, PPC::BCC, Convert__imm_95_100__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2169 /* bns */, PPC::BCC, Convert__imm_95_100__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2173 /* bns+ */, PPC::BCC, Convert__imm_95_103__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2173 /* bns+ */, PPC::BCC, Convert__imm_95_103__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2178 /* bns- */, PPC::BCC, Convert__imm_95_102__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2178 /* bns- */, PPC::BCC, Convert__imm_95_102__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2183 /* bnsa */, PPC::BCCA, Convert__imm_95_100__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2183 /* bnsa */, PPC::BCCA, Convert__imm_95_100__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2188 /* bnsa+ */, PPC::BCCA, Convert__imm_95_103__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2188 /* bnsa+ */, PPC::BCCA, Convert__imm_95_103__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2194 /* bnsa- */, PPC::BCCA, Convert__imm_95_102__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2194 /* bnsa- */, PPC::BCCA, Convert__imm_95_102__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2200 /* bnsctr */, PPC::BCCCTR, Convert__imm_95_100__regCR0, AMFBS_None, {  }, },
  { 2200 /* bnsctr */, PPC::BCCCTR, Convert__imm_95_100__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2207 /* bnsctr+ */, PPC::BCCCTR, Convert__imm_95_103__regCR0, AMFBS_None, {  }, },
  { 2207 /* bnsctr+ */, PPC::BCCCTR, Convert__imm_95_103__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2215 /* bnsctr- */, PPC::BCCCTR, Convert__imm_95_102__regCR0, AMFBS_None, {  }, },
  { 2215 /* bnsctr- */, PPC::BCCCTR, Convert__imm_95_102__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2223 /* bnsctrl */, PPC::BCCCTRL, Convert__imm_95_100__regCR0, AMFBS_None, {  }, },
  { 2223 /* bnsctrl */, PPC::BCCCTRL, Convert__imm_95_100__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2231 /* bnsctrl+ */, PPC::BCCCTRL, Convert__imm_95_103__regCR0, AMFBS_None, {  }, },
  { 2231 /* bnsctrl+ */, PPC::BCCCTRL, Convert__imm_95_103__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2240 /* bnsctrl- */, PPC::BCCCTRL, Convert__imm_95_102__regCR0, AMFBS_None, {  }, },
  { 2240 /* bnsctrl- */, PPC::BCCCTRL, Convert__imm_95_102__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2249 /* bnsl */, PPC::BCCL, Convert__imm_95_100__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2249 /* bnsl */, PPC::BCCL, Convert__imm_95_100__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2254 /* bnsl+ */, PPC::BCCL, Convert__imm_95_103__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2254 /* bnsl+ */, PPC::BCCL, Convert__imm_95_103__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2260 /* bnsl- */, PPC::BCCL, Convert__imm_95_102__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2260 /* bnsl- */, PPC::BCCL, Convert__imm_95_102__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2266 /* bnsla */, PPC::BCCLA, Convert__imm_95_100__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2266 /* bnsla */, PPC::BCCLA, Convert__imm_95_100__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2272 /* bnsla+ */, PPC::BCCLA, Convert__imm_95_103__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2272 /* bnsla+ */, PPC::BCCLA, Convert__imm_95_103__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2279 /* bnsla- */, PPC::BCCLA, Convert__imm_95_102__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2279 /* bnsla- */, PPC::BCCLA, Convert__imm_95_102__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2286 /* bnslr */, PPC::BCCLR, Convert__imm_95_100__regCR0, AMFBS_None, {  }, },
  { 2286 /* bnslr */, PPC::BCCLR, Convert__imm_95_100__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2292 /* bnslr+ */, PPC::BCCLR, Convert__imm_95_103__regCR0, AMFBS_None, {  }, },
  { 2292 /* bnslr+ */, PPC::BCCLR, Convert__imm_95_103__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2299 /* bnslr- */, PPC::BCCLR, Convert__imm_95_102__regCR0, AMFBS_None, {  }, },
  { 2299 /* bnslr- */, PPC::BCCLR, Convert__imm_95_102__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2306 /* bnslrl */, PPC::BCCLRL, Convert__imm_95_100__regCR0, AMFBS_None, {  }, },
  { 2306 /* bnslrl */, PPC::BCCLRL, Convert__imm_95_100__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2313 /* bnslrl+ */, PPC::BCCLRL, Convert__imm_95_103__regCR0, AMFBS_None, {  }, },
  { 2313 /* bnslrl+ */, PPC::BCCLRL, Convert__imm_95_103__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2321 /* bnslrl- */, PPC::BCCLRL, Convert__imm_95_102__regCR0, AMFBS_None, {  }, },
  { 2321 /* bnslrl- */, PPC::BCCLRL, Convert__imm_95_102__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2329 /* bnu */, PPC::BCC, Convert__imm_95_100__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2329 /* bnu */, PPC::BCC, Convert__imm_95_100__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2333 /* bnu+ */, PPC::BCC, Convert__imm_95_103__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2333 /* bnu+ */, PPC::BCC, Convert__imm_95_103__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2338 /* bnu- */, PPC::BCC, Convert__imm_95_102__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2338 /* bnu- */, PPC::BCC, Convert__imm_95_102__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2343 /* bnua */, PPC::BCCA, Convert__imm_95_100__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2343 /* bnua */, PPC::BCCA, Convert__imm_95_100__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2348 /* bnua+ */, PPC::BCCA, Convert__imm_95_103__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2348 /* bnua+ */, PPC::BCCA, Convert__imm_95_103__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2354 /* bnua- */, PPC::BCCA, Convert__imm_95_102__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2354 /* bnua- */, PPC::BCCA, Convert__imm_95_102__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2360 /* bnuctr */, PPC::BCCCTR, Convert__imm_95_100__regCR0, AMFBS_None, {  }, },
  { 2360 /* bnuctr */, PPC::BCCCTR, Convert__imm_95_100__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2367 /* bnuctr+ */, PPC::BCCCTR, Convert__imm_95_103__regCR0, AMFBS_None, {  }, },
  { 2367 /* bnuctr+ */, PPC::BCCCTR, Convert__imm_95_103__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2375 /* bnuctr- */, PPC::BCCCTR, Convert__imm_95_102__regCR0, AMFBS_None, {  }, },
  { 2375 /* bnuctr- */, PPC::BCCCTR, Convert__imm_95_102__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2383 /* bnuctrl */, PPC::BCCCTRL, Convert__imm_95_100__regCR0, AMFBS_None, {  }, },
  { 2383 /* bnuctrl */, PPC::BCCCTRL, Convert__imm_95_100__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2391 /* bnuctrl+ */, PPC::BCCCTRL, Convert__imm_95_103__regCR0, AMFBS_None, {  }, },
  { 2391 /* bnuctrl+ */, PPC::BCCCTRL, Convert__imm_95_103__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2400 /* bnuctrl- */, PPC::BCCCTRL, Convert__imm_95_102__regCR0, AMFBS_None, {  }, },
  { 2400 /* bnuctrl- */, PPC::BCCCTRL, Convert__imm_95_102__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2409 /* bnul */, PPC::BCCL, Convert__imm_95_100__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2409 /* bnul */, PPC::BCCL, Convert__imm_95_100__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2414 /* bnul+ */, PPC::BCCL, Convert__imm_95_103__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2414 /* bnul+ */, PPC::BCCL, Convert__imm_95_103__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2420 /* bnul- */, PPC::BCCL, Convert__imm_95_102__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2420 /* bnul- */, PPC::BCCL, Convert__imm_95_102__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2426 /* bnula */, PPC::BCCLA, Convert__imm_95_100__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2426 /* bnula */, PPC::BCCLA, Convert__imm_95_100__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2432 /* bnula+ */, PPC::BCCLA, Convert__imm_95_103__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2432 /* bnula+ */, PPC::BCCLA, Convert__imm_95_103__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2439 /* bnula- */, PPC::BCCLA, Convert__imm_95_102__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2439 /* bnula- */, PPC::BCCLA, Convert__imm_95_102__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2446 /* bnulr */, PPC::BCCLR, Convert__imm_95_100__regCR0, AMFBS_None, {  }, },
  { 2446 /* bnulr */, PPC::BCCLR, Convert__imm_95_100__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2452 /* bnulr+ */, PPC::BCCLR, Convert__imm_95_103__regCR0, AMFBS_None, {  }, },
  { 2452 /* bnulr+ */, PPC::BCCLR, Convert__imm_95_103__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2459 /* bnulr- */, PPC::BCCLR, Convert__imm_95_102__regCR0, AMFBS_None, {  }, },
  { 2459 /* bnulr- */, PPC::BCCLR, Convert__imm_95_102__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2466 /* bnulrl */, PPC::BCCLRL, Convert__imm_95_100__regCR0, AMFBS_None, {  }, },
  { 2466 /* bnulrl */, PPC::BCCLRL, Convert__imm_95_100__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2473 /* bnulrl+ */, PPC::BCCLRL, Convert__imm_95_103__regCR0, AMFBS_None, {  }, },
  { 2473 /* bnulrl+ */, PPC::BCCLRL, Convert__imm_95_103__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2481 /* bnulrl- */, PPC::BCCLRL, Convert__imm_95_102__regCR0, AMFBS_None, {  }, },
  { 2481 /* bnulrl- */, PPC::BCCLRL, Convert__imm_95_102__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2489 /* bpermd */, PPC::BPERMD, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 2496 /* brd */, PPC::BRD, Convert__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 2500 /* brh */, PPC::BRH, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 2504 /* brinc */, PPC::BRINC, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 2510 /* brw */, PPC::BRW, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 2514 /* bso */, PPC::BCC, Convert__imm_95_108__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2514 /* bso */, PPC::BCC, Convert__imm_95_108__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2518 /* bso+ */, PPC::BCC, Convert__imm_95_111__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2518 /* bso+ */, PPC::BCC, Convert__imm_95_111__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2523 /* bso- */, PPC::BCC, Convert__imm_95_110__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2523 /* bso- */, PPC::BCC, Convert__imm_95_110__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2528 /* bsoa */, PPC::BCCA, Convert__imm_95_108__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2528 /* bsoa */, PPC::BCCA, Convert__imm_95_108__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2533 /* bsoa+ */, PPC::BCCA, Convert__imm_95_111__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2533 /* bsoa+ */, PPC::BCCA, Convert__imm_95_111__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2539 /* bsoa- */, PPC::BCCA, Convert__imm_95_110__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2539 /* bsoa- */, PPC::BCCA, Convert__imm_95_110__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2545 /* bsoctr */, PPC::BCCCTR, Convert__imm_95_108__regCR0, AMFBS_None, {  }, },
  { 2545 /* bsoctr */, PPC::BCCCTR, Convert__imm_95_108__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2552 /* bsoctr+ */, PPC::BCCCTR, Convert__imm_95_111__regCR0, AMFBS_None, {  }, },
  { 2552 /* bsoctr+ */, PPC::BCCCTR, Convert__imm_95_111__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2560 /* bsoctr- */, PPC::BCCCTR, Convert__imm_95_110__regCR0, AMFBS_None, {  }, },
  { 2560 /* bsoctr- */, PPC::BCCCTR, Convert__imm_95_110__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2568 /* bsoctrl */, PPC::BCCCTRL, Convert__imm_95_108__regCR0, AMFBS_None, {  }, },
  { 2568 /* bsoctrl */, PPC::BCCCTRL, Convert__imm_95_108__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2576 /* bsoctrl+ */, PPC::BCCCTRL, Convert__imm_95_111__regCR0, AMFBS_None, {  }, },
  { 2576 /* bsoctrl+ */, PPC::BCCCTRL, Convert__imm_95_111__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2585 /* bsoctrl- */, PPC::BCCCTRL, Convert__imm_95_110__regCR0, AMFBS_None, {  }, },
  { 2585 /* bsoctrl- */, PPC::BCCCTRL, Convert__imm_95_110__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2594 /* bsol */, PPC::BCCL, Convert__imm_95_108__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2594 /* bsol */, PPC::BCCL, Convert__imm_95_108__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2599 /* bsol+ */, PPC::BCCL, Convert__imm_95_111__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2599 /* bsol+ */, PPC::BCCL, Convert__imm_95_111__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2605 /* bsol- */, PPC::BCCL, Convert__imm_95_110__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2605 /* bsol- */, PPC::BCCL, Convert__imm_95_110__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2611 /* bsola */, PPC::BCCLA, Convert__imm_95_108__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2611 /* bsola */, PPC::BCCLA, Convert__imm_95_108__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2617 /* bsola+ */, PPC::BCCLA, Convert__imm_95_111__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2617 /* bsola+ */, PPC::BCCLA, Convert__imm_95_111__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2624 /* bsola- */, PPC::BCCLA, Convert__imm_95_110__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2624 /* bsola- */, PPC::BCCLA, Convert__imm_95_110__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2631 /* bsolr */, PPC::BCCLR, Convert__imm_95_108__regCR0, AMFBS_None, {  }, },
  { 2631 /* bsolr */, PPC::BCCLR, Convert__imm_95_108__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2637 /* bsolr+ */, PPC::BCCLR, Convert__imm_95_111__regCR0, AMFBS_None, {  }, },
  { 2637 /* bsolr+ */, PPC::BCCLR, Convert__imm_95_111__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2644 /* bsolr- */, PPC::BCCLR, Convert__imm_95_110__regCR0, AMFBS_None, {  }, },
  { 2644 /* bsolr- */, PPC::BCCLR, Convert__imm_95_110__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2651 /* bsolrl */, PPC::BCCLRL, Convert__imm_95_108__regCR0, AMFBS_None, {  }, },
  { 2651 /* bsolrl */, PPC::BCCLRL, Convert__imm_95_108__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2658 /* bsolrl+ */, PPC::BCCLRL, Convert__imm_95_111__regCR0, AMFBS_None, {  }, },
  { 2658 /* bsolrl+ */, PPC::BCCLRL, Convert__imm_95_111__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2666 /* bsolrl- */, PPC::BCCLRL, Convert__imm_95_110__regCR0, AMFBS_None, {  }, },
  { 2666 /* bsolrl- */, PPC::BCCLRL, Convert__imm_95_110__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2674 /* bt */, PPC::gBC, Convert__imm_95_12__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2677 /* bt+ */, PPC::gBC, Convert__imm_95_15__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2681 /* bt- */, PPC::gBC, Convert__imm_95_14__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2685 /* bta */, PPC::gBCA, Convert__imm_95_12__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2689 /* bta+ */, PPC::gBCA, Convert__imm_95_15__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2694 /* bta- */, PPC::gBCA, Convert__imm_95_14__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2699 /* btctr */, PPC::gBCCTR, Convert__imm_95_12__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2705 /* btctr+ */, PPC::gBCCTR, Convert__imm_95_15__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2712 /* btctr- */, PPC::gBCCTR, Convert__imm_95_14__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2719 /* btctrl */, PPC::gBCCTRL, Convert__imm_95_12__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2726 /* btctrl+ */, PPC::gBCCTRL, Convert__imm_95_15__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2734 /* btctrl- */, PPC::gBCCTRL, Convert__imm_95_14__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2742 /* btl */, PPC::gBCL, Convert__imm_95_12__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2746 /* btl+ */, PPC::gBCL, Convert__imm_95_15__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2751 /* btl- */, PPC::gBCL, Convert__imm_95_14__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2756 /* btla */, PPC::gBCLA, Convert__imm_95_12__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2761 /* btla+ */, PPC::gBCLA, Convert__imm_95_15__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2767 /* btla- */, PPC::gBCLA, Convert__imm_95_14__RegCRBITRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_CondBr }, },
  { 2773 /* btlr */, PPC::gBCLR, Convert__imm_95_12__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2778 /* btlr+ */, PPC::gBCLR, Convert__imm_95_15__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2784 /* btlr- */, PPC::gBCLR, Convert__imm_95_14__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2790 /* btlrl */, PPC::gBCLRL, Convert__imm_95_12__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2796 /* btlrl+ */, PPC::gBCLRL, Convert__imm_95_15__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2803 /* btlrl- */, PPC::gBCLRL, Convert__imm_95_14__RegCRBITRC1_0__imm_95_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 2810 /* bun */, PPC::BCC, Convert__imm_95_108__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2810 /* bun */, PPC::BCC, Convert__imm_95_108__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2814 /* bun+ */, PPC::BCC, Convert__imm_95_111__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2814 /* bun+ */, PPC::BCC, Convert__imm_95_111__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2819 /* bun- */, PPC::BCC, Convert__imm_95_110__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2819 /* bun- */, PPC::BCC, Convert__imm_95_110__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2824 /* buna */, PPC::BCCA, Convert__imm_95_108__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2824 /* buna */, PPC::BCCA, Convert__imm_95_108__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2829 /* buna+ */, PPC::BCCA, Convert__imm_95_111__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2829 /* buna+ */, PPC::BCCA, Convert__imm_95_111__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2835 /* buna- */, PPC::BCCA, Convert__imm_95_110__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2835 /* buna- */, PPC::BCCA, Convert__imm_95_110__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2841 /* bunctr */, PPC::BCCCTR, Convert__imm_95_108__regCR0, AMFBS_None, {  }, },
  { 2841 /* bunctr */, PPC::BCCCTR, Convert__imm_95_108__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2848 /* bunctr+ */, PPC::BCCCTR, Convert__imm_95_111__regCR0, AMFBS_None, {  }, },
  { 2848 /* bunctr+ */, PPC::BCCCTR, Convert__imm_95_111__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2856 /* bunctr- */, PPC::BCCCTR, Convert__imm_95_110__regCR0, AMFBS_None, {  }, },
  { 2856 /* bunctr- */, PPC::BCCCTR, Convert__imm_95_110__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2864 /* bunctrl */, PPC::BCCCTRL, Convert__imm_95_108__regCR0, AMFBS_None, {  }, },
  { 2864 /* bunctrl */, PPC::BCCCTRL, Convert__imm_95_108__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2872 /* bunctrl+ */, PPC::BCCCTRL, Convert__imm_95_111__regCR0, AMFBS_None, {  }, },
  { 2872 /* bunctrl+ */, PPC::BCCCTRL, Convert__imm_95_111__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2881 /* bunctrl- */, PPC::BCCCTRL, Convert__imm_95_110__regCR0, AMFBS_None, {  }, },
  { 2881 /* bunctrl- */, PPC::BCCCTRL, Convert__imm_95_110__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2890 /* bunl */, PPC::BCCL, Convert__imm_95_108__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2890 /* bunl */, PPC::BCCL, Convert__imm_95_108__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2895 /* bunl+ */, PPC::BCCL, Convert__imm_95_111__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2895 /* bunl+ */, PPC::BCCL, Convert__imm_95_111__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2901 /* bunl- */, PPC::BCCL, Convert__imm_95_110__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2901 /* bunl- */, PPC::BCCL, Convert__imm_95_110__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2907 /* bunla */, PPC::BCCLA, Convert__imm_95_108__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2907 /* bunla */, PPC::BCCLA, Convert__imm_95_108__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2913 /* bunla+ */, PPC::BCCLA, Convert__imm_95_111__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2913 /* bunla+ */, PPC::BCCLA, Convert__imm_95_111__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2920 /* bunla- */, PPC::BCCLA, Convert__imm_95_110__regCR0__CondBr1_0, AMFBS_None, { MCK_CondBr }, },
  { 2920 /* bunla- */, PPC::BCCLA, Convert__imm_95_110__RegCRRC1_0__CondBr1_1, AMFBS_None, { MCK_RegCRRC, MCK_CondBr }, },
  { 2927 /* bunlr */, PPC::BCCLR, Convert__imm_95_108__regCR0, AMFBS_None, {  }, },
  { 2927 /* bunlr */, PPC::BCCLR, Convert__imm_95_108__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2933 /* bunlr+ */, PPC::BCCLR, Convert__imm_95_111__regCR0, AMFBS_None, {  }, },
  { 2933 /* bunlr+ */, PPC::BCCLR, Convert__imm_95_111__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2940 /* bunlr- */, PPC::BCCLR, Convert__imm_95_110__regCR0, AMFBS_None, {  }, },
  { 2940 /* bunlr- */, PPC::BCCLR, Convert__imm_95_110__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2947 /* bunlrl */, PPC::BCCLRL, Convert__imm_95_108__regCR0, AMFBS_None, {  }, },
  { 2947 /* bunlrl */, PPC::BCCLRL, Convert__imm_95_108__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2954 /* bunlrl+ */, PPC::BCCLRL, Convert__imm_95_111__regCR0, AMFBS_None, {  }, },
  { 2954 /* bunlrl+ */, PPC::BCCLRL, Convert__imm_95_111__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2962 /* bunlrl- */, PPC::BCCLRL, Convert__imm_95_110__regCR0, AMFBS_None, {  }, },
  { 2962 /* bunlrl- */, PPC::BCCLRL, Convert__imm_95_110__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 2970 /* cbcdtd */, PPC::CBCDTD, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 2977 /* cdtbcd */, PPC::CDTBCD, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 2984 /* cfuged */, PPC::CFUGED, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 2991 /* clrbhrb */, PPC::CLRBHRB, Convert_NoOperands, AMFBS_None, {  }, },
  { 2999 /* clrldi */, PPC::RLDICL, Convert__RegG8RC1_0__RegG8RC1_1__imm_95_0__U6Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 2999 /* clrldi */, PPC::RLDICL_32_64, Convert__RegG8RC1_0__RegGPRC1_1__imm_95_0__U6Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGPRC, MCK_U6Imm }, },
  { 2999 /* clrldi */, PPC::RLDICL_rec, Convert__RegG8RC1_1__RegG8RC1_2__imm_95_0__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 3006 /* clrlsldi */, PPC::CLRLSLDI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 3006 /* clrlsldi */, PPC::CLRLSLDI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 3015 /* clrlslwi */, PPC::CLRLSLWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 3015 /* clrlslwi */, PPC::CLRLSLWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 3024 /* clrlwi */, PPC::RLWINM8, Convert__RegG8RC1_0__RegG8RC1_1__imm_95_0__U5Imm1_2__imm_95_31, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm }, },
  { 3024 /* clrlwi */, PPC::RLWINM, Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0__U5Imm1_2__imm_95_31, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 3024 /* clrlwi */, PPC::RLWINM8_rec, Convert__RegG8RC1_1__RegG8RC1_2__imm_95_0__U5Imm1_3__imm_95_31, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm }, },
  { 3024 /* clrlwi */, PPC::RLWINM_rec, Convert__RegGPRC1_1__RegGPRC1_2__imm_95_0__U5Imm1_3__imm_95_31, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 3031 /* clrrdi */, PPC::CLRRDI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 3031 /* clrrdi */, PPC::CLRRDI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 3038 /* clrrwi */, PPC::CLRRWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 3038 /* clrrwi */, PPC::CLRRWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 3045 /* cmp */, PPC::CMPW, Convert__RegCRRC1_0__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegCRRC, MCK_0, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3045 /* cmp */, PPC::CMPD, Convert__RegCRRC1_0__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK_RegCRRC, MCK_1, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3049 /* cmpb */, PPC::CMPB, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3054 /* cmpd */, PPC::CMPD, Convert__regCR0__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 3054 /* cmpd */, PPC::CMPD, Convert__RegCRRC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3059 /* cmpdi */, PPC::CMPDI, Convert__regCR0__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 3059 /* cmpdi */, PPC::CMPDI, Convert__RegCRRC1_0__RegG8RC1_1__S16Imm1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegG8RC, MCK_S16Imm }, },
  { 3065 /* cmpeqb */, PPC::CMPEQB, Convert__RegCRRC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3072 /* cmpi */, PPC::CMPWI, Convert__RegCRRC1_0__RegGPRC1_2__S16Imm1_3, AMFBS_None, { MCK_RegCRRC, MCK_0, MCK_RegGPRC, MCK_S16Imm }, },
  { 3072 /* cmpi */, PPC::CMPDI, Convert__RegCRRC1_0__RegG8RC1_2__S16Imm1_3, AMFBS_None, { MCK_RegCRRC, MCK_1, MCK_RegG8RC, MCK_S16Imm }, },
  { 3077 /* cmpl */, PPC::CMPLW, Convert__RegCRRC1_0__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegCRRC, MCK_0, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3077 /* cmpl */, PPC::CMPLD, Convert__RegCRRC1_0__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK_RegCRRC, MCK_1, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3082 /* cmpld */, PPC::CMPLD, Convert__regCR0__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 3082 /* cmpld */, PPC::CMPLD, Convert__RegCRRC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3088 /* cmpldi */, PPC::CMPLDI, Convert__regCR0__RegG8RC1_0__U16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_U16Imm }, },
  { 3088 /* cmpldi */, PPC::CMPLDI, Convert__RegCRRC1_0__RegG8RC1_1__U16Imm1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegG8RC, MCK_U16Imm }, },
  { 3095 /* cmpli */, PPC::CMPLWI, Convert__RegCRRC1_0__RegGPRC1_2__U16Imm1_3, AMFBS_None, { MCK_RegCRRC, MCK_0, MCK_RegGPRC, MCK_U16Imm }, },
  { 3095 /* cmpli */, PPC::CMPLDI, Convert__RegCRRC1_0__RegG8RC1_2__U16Imm1_3, AMFBS_None, { MCK_RegCRRC, MCK_1, MCK_RegG8RC, MCK_U16Imm }, },
  { 3101 /* cmplw */, PPC::CMPLW, Convert__regCR0__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 3101 /* cmplw */, PPC::CMPLW, Convert__RegCRRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3107 /* cmplwi */, PPC::CMPLWI, Convert__regCR0__RegGPRC1_0__U16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_U16Imm }, },
  { 3107 /* cmplwi */, PPC::CMPLWI, Convert__RegCRRC1_0__RegGPRC1_1__U16Imm1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegGPRC, MCK_U16Imm }, },
  { 3114 /* cmprb */, PPC::CMPRB, Convert__RegCRRC1_0__U1Imm1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegCRRC, MCK_U1Imm, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3120 /* cmpw */, PPC::CMPW, Convert__regCR0__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 3120 /* cmpw */, PPC::CMPW, Convert__RegCRRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3125 /* cmpwi */, PPC::CMPWI, Convert__regCR0__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 3125 /* cmpwi */, PPC::CMPWI, Convert__RegCRRC1_0__RegGPRC1_1__S16Imm1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegGPRC, MCK_S16Imm }, },
  { 3131 /* cntlzd */, PPC::CNTLZD, Convert__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 3131 /* cntlzd */, PPC::CNTLZD_rec, Convert__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3138 /* cntlzdm */, PPC::CNTLZDM, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3146 /* cntlzw */, PPC::CNTLZW8, Convert__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 3146 /* cntlzw */, PPC::CNTLZW, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 3146 /* cntlzw */, PPC::CNTLZW, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 3146 /* cntlzw */, PPC::CNTLZW8_rec, Convert__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3146 /* cntlzw */, PPC::CNTLZW_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3146 /* cntlzw */, PPC::CNTLZW_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3153 /* cnttzd */, PPC::CNTTZD, Convert__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 3153 /* cnttzd */, PPC::CNTTZD_rec, Convert__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3160 /* cnttzdm */, PPC::CNTTZDM, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3168 /* cnttzw */, PPC::CNTTZW, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 3168 /* cnttzw */, PPC::CNTTZW_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3175 /* copy */, PPC::CP_COPY, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 3180 /* cpabort */, PPC::CP_ABORT, Convert_NoOperands, AMFBS_None, {  }, },
  { 3188 /* crand */, PPC::CRAND, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3194 /* crandc */, PPC::CRANDC, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3201 /* crclr */, PPC::CRXOR, Convert__RegCRBITRC1_0__RegCRBITRC1_0__RegCRBITRC1_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 3207 /* creqv */, PPC::CREQV, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3213 /* crmove */, PPC::CROR, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3220 /* crnand */, PPC::CRNAND, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3227 /* crnor */, PPC::CRNOR, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3233 /* crnot */, PPC::CRNOR, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_1, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3239 /* cror */, PPC::CROR, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3244 /* crorc */, PPC::CRORC, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3250 /* crset */, PPC::CREQV, Convert__RegCRBITRC1_0__RegCRBITRC1_0__RegCRBITRC1_0, AMFBS_None, { MCK_RegCRBITRC }, },
  { 3256 /* crxor */, PPC::CRXOR, Convert__RegCRBITRC1_0__RegCRBITRC1_1__RegCRBITRC1_2, AMFBS_None, { MCK_RegCRBITRC, MCK_RegCRBITRC, MCK_RegCRBITRC }, },
  { 3262 /* dadd */, PPC::DADD, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3262 /* dadd */, PPC::DADD_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3267 /* daddq */, PPC::DADDQ, Convert__RegFpRC1_0__RegFpRC1_1__RegFpRC1_2, AMFBS_None, { MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3267 /* daddq */, PPC::DADDQ_rec, Convert__RegFpRC1_1__RegFpRC1_2__RegFpRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3273 /* darn */, PPC::DARN, Convert__RegG8RC1_0__U2Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_U2Imm }, },
  { 3278 /* dcba */, PPC::DCBA, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3283 /* dcbf */, PPC::DCBFx, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3283 /* dcbf */, PPC::DCBF, Convert__U3Imm1_2__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_U3Imm }, },
  { 3288 /* dcbfep */, PPC::DCBFEP, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3295 /* dcbfl */, PPC::DCBFL, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3301 /* dcbflp */, PPC::DCBFLP, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3308 /* dcbfps */, PPC::DCBFPS, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3315 /* dcbi */, PPC::DCBI, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3320 /* dcbst */, PPC::DCBST, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3326 /* dcbstep */, PPC::DCBSTEP, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3334 /* dcbstps */, PPC::DCBSTPS, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3342 /* dcbt */, PPC::DCBTx, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3342 /* dcbt */, PPC::DCBT, Convert__U5Imm1_2__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_U5Imm }, },
  { 3347 /* dcbtct */, PPC::DCBTCT, Convert__RegGxRCNoR01_0__RegGxRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_U5Imm }, },
  { 3354 /* dcbtds */, PPC::DCBTDS, Convert__RegGxRCNoR01_0__RegGxRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_U5Imm }, },
  { 3361 /* dcbtep */, PPC::DCBTEP, Convert__RegGxRCNoR01_1__RegGxRC1_2__U5Imm1_0, AMFBS_None, { MCK_U5Imm, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3368 /* dcbtst */, PPC::DCBTSTx, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3368 /* dcbtst */, PPC::DCBTST, Convert__U5Imm1_2__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_U5Imm }, },
  { 3375 /* dcbtstct */, PPC::DCBTSTCT, Convert__RegGxRCNoR01_0__RegGxRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_U5Imm }, },
  { 3384 /* dcbtstds */, PPC::DCBTSTDS, Convert__RegGxRCNoR01_0__RegGxRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_U5Imm }, },
  { 3393 /* dcbtstep */, PPC::DCBTSTEP, Convert__RegGxRCNoR01_1__RegGxRC1_2__U5Imm1_0, AMFBS_None, { MCK_U5Imm, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3402 /* dcbtstt */, PPC::DCBTSTT, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3410 /* dcbtt */, PPC::DCBTT, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3416 /* dcbz */, PPC::DCBZ, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3421 /* dcbzep */, PPC::DCBZEP, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3428 /* dcbzl */, PPC::DCBZL, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3434 /* dcbzlep */, PPC::DCBZLEP, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 3442 /* dccci */, PPC::DCCCI, Convert__regR0__regR0, AMFBS_None, {  }, },
  { 3442 /* dccci */, PPC::DCCCI, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 3448 /* dcffix */, PPC::DCFFIX, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 3448 /* dcffix */, PPC::DCFFIX_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3455 /* dcffixq */, PPC::DCFFIXQ, Convert__RegFpRC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegFpRC, MCK_RegF8RC }, },
  { 3455 /* dcffixq */, PPC::DCFFIXQ_rec, Convert__RegFpRC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegF8RC }, },
  { 3463 /* dcffixqq */, PPC::DCFFIXQQ, Convert__RegFpRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegFpRC, MCK_RegVRRC }, },
  { 3472 /* dci */, PPC::DCCCI, Convert__regR0__regR0, AMFBS_None, { MCK_0 }, },
  { 3476 /* dcmpo */, PPC::DCMPO, Convert__RegCRRC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3482 /* dcmpoq */, PPC::DCMPOQ, Convert__RegCRRC1_0__RegFpRC1_1__RegFpRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3489 /* dcmpu */, PPC::DCMPU, Convert__RegCRRC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3495 /* dcmpuq */, PPC::DCMPUQ, Convert__RegCRRC1_0__RegFpRC1_1__RegFpRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3502 /* dctdp */, PPC::DCTDP, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 3502 /* dctdp */, PPC::DCTDP_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3508 /* dctfix */, PPC::DCTFIX, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 3508 /* dctfix */, PPC::DCTFIX_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3515 /* dctfixq */, PPC::DCTFIXQ, Convert__RegF8RC1_0__RegFpRC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegFpRC }, },
  { 3515 /* dctfixq */, PPC::DCTFIXQ_rec, Convert__RegF8RC1_1__RegFpRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegFpRC }, },
  { 3523 /* dctfixqq */, PPC::DCTFIXQQ, Convert__RegVRRC1_0__RegFpRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegFpRC }, },
  { 3532 /* dctqpq */, PPC::DCTQPQ, Convert__RegFpRC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegFpRC, MCK_RegF8RC }, },
  { 3532 /* dctqpq */, PPC::DCTQPQ_rec, Convert__RegFpRC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegF8RC }, },
  { 3539 /* ddedpd */, PPC::DDEDPD, Convert__RegF8RC1_1__U2Imm1_0__RegF8RC1_2, AMFBS_None, { MCK_U2Imm, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3539 /* ddedpd */, PPC::DDEDPD_rec, Convert__RegF8RC1_2__U2Imm1_1__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_U2Imm, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3546 /* ddedpdq */, PPC::DDEDPDQ, Convert__RegFpRC1_1__U2Imm1_0__RegFpRC1_2, AMFBS_None, { MCK_U2Imm, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3546 /* ddedpdq */, PPC::DDEDPDQ_rec, Convert__RegFpRC1_2__U2Imm1_1__RegFpRC1_3, AMFBS_None, { MCK__DOT_, MCK_U2Imm, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3554 /* ddiv */, PPC::DDIV, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3554 /* ddiv */, PPC::DDIV_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3559 /* ddivq */, PPC::DDIVQ, Convert__RegFpRC1_0__RegFpRC1_1__RegFpRC1_2, AMFBS_None, { MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3559 /* ddivq */, PPC::DDIVQ_rec, Convert__RegFpRC1_1__RegFpRC1_2__RegFpRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3565 /* denbcd */, PPC::DENBCD, Convert__RegF8RC1_1__U1Imm1_0__RegF8RC1_2, AMFBS_None, { MCK_U1Imm, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3565 /* denbcd */, PPC::DENBCD_rec, Convert__RegF8RC1_2__U1Imm1_1__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_U1Imm, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3572 /* denbcdq */, PPC::DENBCDQ, Convert__RegFpRC1_1__U1Imm1_0__RegFpRC1_2, AMFBS_None, { MCK_U1Imm, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3572 /* denbcdq */, PPC::DENBCDQ_rec, Convert__RegFpRC1_2__U1Imm1_1__RegFpRC1_3, AMFBS_None, { MCK__DOT_, MCK_U1Imm, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3580 /* diex */, PPC::DIEX, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3580 /* diex */, PPC::DIEX_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3585 /* diexq */, PPC::DIEXQ, Convert__RegFpRC1_0__RegF8RC1_1__RegFpRC1_2, AMFBS_None, { MCK_RegFpRC, MCK_RegF8RC, MCK_RegFpRC }, },
  { 3585 /* diexq */, PPC::DIEXQ_rec, Convert__RegFpRC1_1__RegF8RC1_2__RegFpRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegF8RC, MCK_RegFpRC }, },
  { 3591 /* divd */, PPC::DIVD, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3591 /* divd */, PPC::DIVD_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3596 /* divde */, PPC::DIVDE, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3596 /* divde */, PPC::DIVDE_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3602 /* divdeo */, PPC::DIVDEO, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3602 /* divdeo */, PPC::DIVDEO_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3609 /* divdeu */, PPC::DIVDEU, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3609 /* divdeu */, PPC::DIVDEU_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3616 /* divdeuo */, PPC::DIVDEUO, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3616 /* divdeuo */, PPC::DIVDEUO_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3624 /* divdo */, PPC::DIVDO, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3624 /* divdo */, PPC::DIVDO_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3630 /* divdu */, PPC::DIVDU, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3630 /* divdu */, PPC::DIVDU_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3636 /* divduo */, PPC::DIVDUO, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3636 /* divduo */, PPC::DIVDUO_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 3643 /* divw */, PPC::DIVW, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3643 /* divw */, PPC::DIVW_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3648 /* divwe */, PPC::DIVWE, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3648 /* divwe */, PPC::DIVWE_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3654 /* divweo */, PPC::DIVWEO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3654 /* divweo */, PPC::DIVWEO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3661 /* divweu */, PPC::DIVWEU, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3661 /* divweu */, PPC::DIVWEU_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3668 /* divweuo */, PPC::DIVWEUO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3668 /* divweuo */, PPC::DIVWEUO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3676 /* divwo */, PPC::DIVWO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3676 /* divwo */, PPC::DIVWO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3682 /* divwu */, PPC::DIVWU, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3682 /* divwu */, PPC::DIVWU_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3688 /* divwuo */, PPC::DIVWUO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3688 /* divwuo */, PPC::DIVWUO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 3695 /* dmcryshash */, PPC::DMSHA3HASH, Convert__RegDMRpRC1_0__Tie0_1_1__imm_95_12, AMFBS_None, { MCK_RegDMRpRC }, },
  { 3706 /* dmmr */, PPC::DMMR, Convert__RegDMRRC1_0__RegDMRRC1_1, AMFBS_None, { MCK_RegDMRRC, MCK_RegDMRRC }, },
  { 3711 /* dmsetdmrz */, PPC::DMSETDMRZ, Convert__RegDMRRC1_0, AMFBS_None, { MCK_RegDMRRC }, },
  { 3721 /* dmsha256hash */, PPC::DMSHA2HASH, Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1__imm_95_0, AMFBS_None, { MCK_RegDMRRC, MCK_RegDMRRC }, },
  { 3734 /* dmsha2hash */, PPC::DMSHA2HASH, Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1__U1Imm1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegDMRRC, MCK_U1Imm }, },
  { 3745 /* dmsha3dw */, PPC::DMSHA3HASH, Convert__RegDMRpRC1_0__Tie0_1_1__imm_95_0, AMFBS_None, { MCK_RegDMRpRC }, },
  { 3754 /* dmsha3hash */, PPC::DMSHA3HASH, Convert__RegDMRpRC1_0__Tie0_1_1__U5Imm1_1, AMFBS_None, { MCK_RegDMRpRC, MCK_U5Imm }, },
  { 3765 /* dmsha512hash */, PPC::DMSHA2HASH, Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1__imm_95_1, AMFBS_None, { MCK_RegDMRRC, MCK_RegDMRRC }, },
  { 3778 /* dmul */, PPC::DMUL, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3778 /* dmul */, PPC::DMUL_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 3783 /* dmulq */, PPC::DMULQ, Convert__RegFpRC1_0__RegFpRC1_1__RegFpRC1_2, AMFBS_None, { MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3783 /* dmulq */, PPC::DMULQ_rec, Convert__RegFpRC1_1__RegFpRC1_2__RegFpRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 3789 /* dmxor */, PPC::DMXOR, Convert__RegDMRRC1_0__Tie0_1_1__RegDMRRC1_1, AMFBS_None, { MCK_RegDMRRC, MCK_RegDMRRC }, },
  { 3795 /* dmxvbf16gerx2 */, PPC::DMXVBF16GERX2, Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3809 /* dmxvbf16gerx2nn */, PPC::DMXVBF16GERX2NN, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3825 /* dmxvbf16gerx2np */, PPC::DMXVBF16GERX2NP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3841 /* dmxvbf16gerx2pn */, PPC::DMXVBF16GERX2PN, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3857 /* dmxvbf16gerx2pp */, PPC::DMXVBF16GERX2PP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3873 /* dmxvf16gerx2 */, PPC::DMXVF16GERX2, Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3886 /* dmxvf16gerx2nn */, PPC::DMXVF16GERX2NN, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3901 /* dmxvf16gerx2np */, PPC::DMXVF16GERX2NP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3916 /* dmxvf16gerx2pn */, PPC::DMXVF16GERX2PN, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3931 /* dmxvf16gerx2pp */, PPC::DMXVF16GERX2PP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3946 /* dmxvi8gerx4 */, PPC::DMXVI8GERX4, Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3958 /* dmxvi8gerx4pp */, PPC::DMXVI8GERX4PP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3972 /* dmxvi8gerx4spp */, PPC::DMXVI8GERX4SPP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC }, },
  { 3987 /* dmxxextfdmr256 */, PPC::DMXXEXTFDMR256, Convert__RegVSRpRC1_0__RegDMRROWpRC1_1__U2Imm1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_RegDMRROWpRC, MCK_U2Imm }, },
  { 4002 /* dmxxextfdmr512 */, PPC::DMXXEXTFDMR512, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegACCRC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegACCRC, MCK_0 }, },
  { 4002 /* dmxxextfdmr512 */, PPC::DMXXEXTFDMR512_HI, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegACCRC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegACCRC, MCK_1 }, },
  { 4017 /* dmxxinstdmr256 */, PPC::DMXXINSTDMR256, Convert__RegDMRROWpRC1_0__RegVSRpRC1_1__U2Imm1_2, AMFBS_None, { MCK_RegDMRROWpRC, MCK_RegVSRpRC, MCK_U2Imm }, },
  { 4032 /* dmxxinstdmr512 */, PPC::DMXXINSTDMR512, Convert__RegACCRC1_0__RegVSRpRC1_1__RegVSRpRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_0 }, },
  { 4032 /* dmxxinstdmr512 */, PPC::DMXXINSTDMR512_HI, Convert__RegACCRC1_0__RegVSRpRC1_1__RegVSRpRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_1 }, },
  { 4047 /* dmxxmmfacc */, PPC::XXMFACC, Convert__RegACCRC1_0__Tie0_1_1, AMFBS_None, { MCK_RegACCRC }, },
  { 4058 /* dmxxmmtacc */, PPC::XXMTACC, Convert__RegACCRC1_0__Tie0_1_1, AMFBS_None, { MCK_RegACCRC }, },
  { 4069 /* dmxxsetaccz */, PPC::XXSETACCZ, Convert__RegACCRC1_0, AMFBS_None, { MCK_RegACCRC }, },
  { 4081 /* dmxxsha224256pad */, PPC::DMXXSHAPAD, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_3__imm_95_0__imm_95_0, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRC }, },
  { 4098 /* dmxxsha3224pad */, PPC::DMXXSHAPAD, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_3, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 4113 /* dmxxsha3256pad */, PPC::DMXXSHAPAD, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_2, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 4128 /* dmxxsha3384pad */, PPC::DMXXSHAPAD, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_1, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 4143 /* dmxxsha3512pad */, PPC::DMXXSHAPAD, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_0__U1Imm1_2__imm_95_0, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 4158 /* dmxxsha384512pad */, PPC::DMXXSHAPAD, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_2__imm_95_0__imm_95_0, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRC }, },
  { 4175 /* dmxxshake128pad */, PPC::DMXXSHAPAD, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_1__U1Imm1_2__imm_95_1, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 4191 /* dmxxshake256pad */, PPC::DMXXSHAPAD, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__imm_95_1__U1Imm1_2__imm_95_0, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 4207 /* dmxxshapad */, PPC::DMXXSHAPAD, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRC1_1__U2Imm1_2__U1Imm1_3__U2Imm1_4, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRC, MCK_U2Imm, MCK_U1Imm, MCK_U2Imm }, },
  { 4218 /* dqua */, PPC::DQUA, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__U2Imm1_3, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4218 /* dqua */, PPC::DQUA_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4223 /* dquai */, PPC::DQUAI, Convert__RegF8RC1_1__S5Imm1_0__RegF8RC1_2__U2Imm1_3, AMFBS_None, { MCK_S5Imm, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4223 /* dquai */, PPC::DQUAI_rec, Convert__RegF8RC1_2__S5Imm1_1__RegF8RC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_S5Imm, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4229 /* dquaiq */, PPC::DQUAIQ, Convert__RegFpRC1_1__S5Imm1_0__RegFpRC1_2__U2Imm1_3, AMFBS_None, { MCK_S5Imm, MCK_RegFpRC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4229 /* dquaiq */, PPC::DQUAIQ_rec, Convert__RegFpRC1_2__S5Imm1_1__RegFpRC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_S5Imm, MCK_RegFpRC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4236 /* dquaq */, PPC::DQUAQ, Convert__RegFpRC1_0__RegFpRC1_1__RegFpRC1_2__U2Imm1_3, AMFBS_None, { MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4236 /* dquaq */, PPC::DQUAQ_rec, Convert__RegFpRC1_1__RegFpRC1_2__RegFpRC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4242 /* drdpq */, PPC::DRDPQ, Convert__RegFpRC1_0__RegFpRC1_1, AMFBS_None, { MCK_RegFpRC, MCK_RegFpRC }, },
  { 4242 /* drdpq */, PPC::DRDPQ_rec, Convert__RegFpRC1_1__RegFpRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegFpRC }, },
  { 4248 /* drintn */, PPC::DRINTN, Convert__RegF8RC1_1__U1Imm1_0__RegF8RC1_2__U2Imm1_3, AMFBS_None, { MCK_U1Imm, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4248 /* drintn */, PPC::DRINTN_rec, Convert__RegF8RC1_2__U1Imm1_1__RegF8RC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_U1Imm, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4255 /* drintnq */, PPC::DRINTNQ, Convert__RegFpRC1_1__U1Imm1_0__RegFpRC1_2__U2Imm1_3, AMFBS_None, { MCK_U1Imm, MCK_RegFpRC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4255 /* drintnq */, PPC::DRINTNQ_rec, Convert__RegFpRC1_2__U1Imm1_1__RegFpRC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_U1Imm, MCK_RegFpRC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4263 /* drintx */, PPC::DRINTX, Convert__RegF8RC1_1__U1Imm1_0__RegF8RC1_2__U2Imm1_3, AMFBS_None, { MCK_U1Imm, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4263 /* drintx */, PPC::DRINTX_rec, Convert__RegF8RC1_2__U1Imm1_1__RegF8RC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_U1Imm, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4270 /* drintxq */, PPC::DRINTXQ, Convert__RegFpRC1_1__U1Imm1_0__RegFpRC1_2__U2Imm1_3, AMFBS_None, { MCK_U1Imm, MCK_RegFpRC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4270 /* drintxq */, PPC::DRINTXQ_rec, Convert__RegFpRC1_2__U1Imm1_1__RegFpRC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_U1Imm, MCK_RegFpRC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4278 /* drrnd */, PPC::DRRND, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__U2Imm1_3, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4278 /* drrnd */, PPC::DRRND_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_U2Imm }, },
  { 4284 /* drrndq */, PPC::DRRNDQ, Convert__RegFpRC1_0__RegF8RC1_1__RegFpRC1_2__U2Imm1_3, AMFBS_None, { MCK_RegFpRC, MCK_RegF8RC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4284 /* drrndq */, PPC::DRRNDQ_rec, Convert__RegFpRC1_1__RegF8RC1_2__RegFpRC1_3__U2Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegF8RC, MCK_RegFpRC, MCK_U2Imm }, },
  { 4291 /* drsp */, PPC::DRSP, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 4291 /* drsp */, PPC::DRSP_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 4296 /* dscli */, PPC::DSCLI, Convert__RegF8RC1_0__RegF8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_U6Imm }, },
  { 4296 /* dscli */, PPC::DSCLI_rec, Convert__RegF8RC1_1__RegF8RC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_U6Imm }, },
  { 4302 /* dscliq */, PPC::DSCLIQ, Convert__RegFpRC1_0__RegFpRC1_1__U6Imm1_2, AMFBS_None, { MCK_RegFpRC, MCK_RegFpRC, MCK_U6Imm }, },
  { 4302 /* dscliq */, PPC::DSCLIQ_rec, Convert__RegFpRC1_1__RegFpRC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegFpRC, MCK_U6Imm }, },
  { 4309 /* dscri */, PPC::DSCRI, Convert__RegF8RC1_0__RegF8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_U6Imm }, },
  { 4309 /* dscri */, PPC::DSCRI_rec, Convert__RegF8RC1_1__RegF8RC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_U6Imm }, },
  { 4315 /* dscriq */, PPC::DSCRIQ, Convert__RegFpRC1_0__RegFpRC1_1__U6Imm1_2, AMFBS_None, { MCK_RegFpRC, MCK_RegFpRC, MCK_U6Imm }, },
  { 4315 /* dscriq */, PPC::DSCRIQ_rec, Convert__RegFpRC1_1__RegFpRC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegFpRC, MCK_U6Imm }, },
  { 4322 /* dss */, PPC::DSS, Convert__U5Imm1_0, AMFBS_None, { MCK_U5Imm }, },
  { 4326 /* dssall */, PPC::DSSALL, Convert_NoOperands, AMFBS_None, {  }, },
  { 4333 /* dst */, PPC::DST, Convert__U5Imm1_2__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 4337 /* dstst */, PPC::DSTST, Convert__U5Imm1_2__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 4343 /* dststt */, PPC::DSTSTT, Convert__U5Imm1_2__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 4350 /* dstt */, PPC::DSTT, Convert__U5Imm1_2__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 4355 /* dsub */, PPC::DSUB, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 4355 /* dsub */, PPC::DSUB_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 4360 /* dsubq */, PPC::DSUBQ, Convert__RegFpRC1_0__RegFpRC1_1__RegFpRC1_2, AMFBS_None, { MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 4360 /* dsubq */, PPC::DSUBQ_rec, Convert__RegFpRC1_1__RegFpRC1_2__RegFpRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegFpRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 4366 /* dtstdc */, PPC::DTSTDC, Convert__RegCRRC1_0__RegF8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF8RC, MCK_U6Imm }, },
  { 4373 /* dtstdcq */, PPC::DTSTDCQ, Convert__RegCRRC1_0__RegFpRC1_1__U6Imm1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegFpRC, MCK_U6Imm }, },
  { 4381 /* dtstdg */, PPC::DTSTDG, Convert__RegCRRC1_0__RegF8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF8RC, MCK_U6Imm }, },
  { 4388 /* dtstdgq */, PPC::DTSTDGQ, Convert__RegCRRC1_0__RegFpRC1_1__U6Imm1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegFpRC, MCK_U6Imm }, },
  { 4396 /* dtstex */, PPC::DTSTEX, Convert__RegCRRC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 4403 /* dtstexq */, PPC::DTSTEXQ, Convert__RegCRRC1_0__RegFpRC1_1__RegFpRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegFpRC, MCK_RegFpRC }, },
  { 4411 /* dtstsf */, PPC::DTSTSF, Convert__RegCRRC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 4418 /* dtstsfi */, PPC::DTSTSFI, Convert__RegCRRC1_0__U6Imm1_1__RegF8RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_U6Imm, MCK_RegF8RC }, },
  { 4426 /* dtstsfiq */, PPC::DTSTSFIQ, Convert__RegCRRC1_0__U6Imm1_1__RegFpRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_U6Imm, MCK_RegFpRC }, },
  { 4435 /* dtstsfq */, PPC::DTSTSFQ, Convert__RegCRRC1_0__RegF8RC1_1__RegFpRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF8RC, MCK_RegFpRC }, },
  { 4443 /* dxex */, PPC::DXEX, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 4443 /* dxex */, PPC::DXEX_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 4448 /* dxexq */, PPC::DXEXQ, Convert__RegF8RC1_0__RegFpRC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegFpRC }, },
  { 4448 /* dxexq */, PPC::DXEXQ_rec, Convert__RegF8RC1_1__RegFpRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegFpRC }, },
  { 4454 /* efdabs */, PPC::EFDABS, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 4461 /* efdadd */, PPC::EFDADD, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4468 /* efdcfs */, PPC::EFDCFS, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4475 /* efdcfsf */, PPC::EFDCFSF, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4483 /* efdcfsi */, PPC::EFDCFSI, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4491 /* efdcfsid */, PPC::EFDCFSID, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4500 /* efdcfuf */, PPC::EFDCFUF, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4508 /* efdcfui */, PPC::EFDCFUI, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4516 /* efdcfuid */, PPC::EFDCFUID, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4525 /* efdcmpeq */, PPC::EFDCMPEQ, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4534 /* efdcmpgt */, PPC::EFDCMPGT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4543 /* efdcmplt */, PPC::EFDCMPLT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4552 /* efdctsf */, PPC::EFDCTSF, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4560 /* efdctsi */, PPC::EFDCTSI, Convert__RegGPRC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegSPERC }, },
  { 4568 /* efdctsidz */, PPC::EFDCTSIDZ, Convert__RegGPRC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegSPERC }, },
  { 4578 /* efdctsiz */, PPC::EFDCTSIZ, Convert__RegGPRC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegSPERC }, },
  { 4587 /* efdctuf */, PPC::EFDCTUF, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4595 /* efdctui */, PPC::EFDCTUI, Convert__RegGPRC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegSPERC }, },
  { 4603 /* efdctuidz */, PPC::EFDCTUIDZ, Convert__RegGPRC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegSPERC }, },
  { 4613 /* efdctuiz */, PPC::EFDCTUIZ, Convert__RegGPRC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegSPERC }, },
  { 4622 /* efddiv */, PPC::EFDDIV, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4629 /* efdmul */, PPC::EFDMUL, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4636 /* efdnabs */, PPC::EFDNABS, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 4644 /* efdneg */, PPC::EFDNEG, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 4651 /* efdsub */, PPC::EFDSUB, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4658 /* efdtsteq */, PPC::EFDTSTEQ, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4667 /* efdtstgt */, PPC::EFDTSTGT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4676 /* efdtstlt */, PPC::EFDTSTLT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4685 /* efsabs */, PPC::EFSABS, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4692 /* efsadd */, PPC::EFSADD, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4699 /* efscfd */, PPC::EFSCFD, Convert__RegGPRC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegSPERC }, },
  { 4706 /* efscfsf */, PPC::EFSCFSF, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4714 /* efscfsi */, PPC::EFSCFSI, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4722 /* efscfuf */, PPC::EFSCFUF, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4730 /* efscfui */, PPC::EFSCFUI, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4738 /* efscmpeq */, PPC::EFSCMPEQ, Convert__RegCRRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4747 /* efscmpgt */, PPC::EFSCMPGT, Convert__RegCRRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4756 /* efscmplt */, PPC::EFSCMPLT, Convert__RegCRRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4765 /* efsctsf */, PPC::EFSCTSF, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4773 /* efsctsi */, PPC::EFSCTSI, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4781 /* efsctsiz */, PPC::EFSCTSIZ, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4790 /* efsctuf */, PPC::EFSCTUF, Convert__RegSPERC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC }, },
  { 4798 /* efsctui */, PPC::EFSCTUI, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4806 /* efsctuiz */, PPC::EFSCTUIZ, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4815 /* efsdiv */, PPC::EFSDIV, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4822 /* efsmul */, PPC::EFSMUL, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4829 /* efsnabs */, PPC::EFSNABS, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4837 /* efsneg */, PPC::EFSNEG, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 4844 /* efssub */, PPC::EFSSUB, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4851 /* efststeq */, PPC::EFSTSTEQ, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4860 /* efststgt */, PPC::EFSTSTGT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4869 /* efststlt */, PPC::EFSTSTLT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4878 /* eieio */, PPC::EnforceIEIO, Convert_NoOperands, AMFBS_None, {  }, },
  { 4884 /* eqv */, PPC::EQV, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4884 /* eqv */, PPC::EQV_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 4888 /* evabs */, PPC::EVABS, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 4894 /* evaddiw */, PPC::EVADDIW, Convert__RegSPERC1_0__RegSPERC1_2__U5Imm1_1, AMFBS_None, { MCK_RegSPERC, MCK_U5Imm, MCK_RegSPERC }, },
  { 4902 /* evaddsmiaaw */, PPC::EVADDSMIAAW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 4914 /* evaddssiaaw */, PPC::EVADDSSIAAW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 4926 /* evaddumiaaw */, PPC::EVADDUMIAAW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 4938 /* evaddusiaaw */, PPC::EVADDUSIAAW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 4950 /* evaddw */, PPC::EVADDW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4957 /* evand */, PPC::EVAND, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4963 /* evandc */, PPC::EVANDC, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4970 /* evcmpeq */, PPC::EVCMPEQ, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4978 /* evcmpgts */, PPC::EVCMPGTS, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4987 /* evcmpgtu */, PPC::EVCMPGTU, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 4996 /* evcmplts */, PPC::EVCMPLTS, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5005 /* evcmpltu */, PPC::EVCMPLTU, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5014 /* evcntlsw */, PPC::EVCNTLSW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5023 /* evcntlzw */, PPC::EVCNTLZW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5032 /* evdivws */, PPC::EVDIVWS, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5040 /* evdivwu */, PPC::EVDIVWU, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5048 /* eveqv */, PPC::EVEQV, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5054 /* evextsb */, PPC::EVEXTSB, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5062 /* evextsh */, PPC::EVEXTSH, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5070 /* evfsabs */, PPC::EVFSABS, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5078 /* evfsadd */, PPC::EVFSADD, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5086 /* evfscfsf */, PPC::EVFSCFSF, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5095 /* evfscfsi */, PPC::EVFSCFSI, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5104 /* evfscfuf */, PPC::EVFSCFUF, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5113 /* evfscfui */, PPC::EVFSCFUI, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5122 /* evfscmpeq */, PPC::EVFSCMPEQ, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5132 /* evfscmpgt */, PPC::EVFSCMPGT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5142 /* evfscmplt */, PPC::EVFSCMPLT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5152 /* evfsctsf */, PPC::EVFSCTSF, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5152 /* evfsctsf */, PPC::EVFSCTUF, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5161 /* evfsctsi */, PPC::EVFSCTSI, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5170 /* evfsctsiz */, PPC::EVFSCTSIZ, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5170 /* evfsctsiz */, PPC::EVFSCTUIZ, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5180 /* evfsctui */, PPC::EVFSCTUI, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5189 /* evfsdiv */, PPC::EVFSDIV, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5197 /* evfsmul */, PPC::EVFSMUL, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5205 /* evfsnabs */, PPC::EVFSNABS, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5214 /* evfsneg */, PPC::EVFSNEG, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 5222 /* evfssub */, PPC::EVFSSUB, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5230 /* evfststeq */, PPC::EVFSTSTEQ, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5240 /* evfststgt */, PPC::EVFSTSTGT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5250 /* evfststlt */, PPC::EVFSTSTLT, Convert__RegCRRC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5260 /* evldd */, PPC::EVLDD, Convert__RegSPERC1_0__DispSPE81_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE8, MCK_RegGxRCNoR0 }, },
  { 5266 /* evlddx */, PPC::EVLDDX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5273 /* evldh */, PPC::EVLDH, Convert__RegSPERC1_0__DispSPE81_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE8, MCK_RegGxRCNoR0 }, },
  { 5279 /* evldhx */, PPC::EVLDHX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5286 /* evldw */, PPC::EVLDW, Convert__RegSPERC1_0__DispSPE81_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE8, MCK_RegGxRCNoR0 }, },
  { 5292 /* evldwx */, PPC::EVLDWX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5299 /* evlhhesplat */, PPC::EVLHHESPLAT, Convert__RegSPERC1_0__DispSPE21_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE2, MCK_RegGxRCNoR0 }, },
  { 5311 /* evlhhesplatx */, PPC::EVLHHESPLATX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5324 /* evlhhossplat */, PPC::EVLHHOSSPLAT, Convert__RegSPERC1_0__DispSPE21_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE2, MCK_RegGxRCNoR0 }, },
  { 5337 /* evlhhossplatx */, PPC::EVLHHOSSPLATX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5351 /* evlhhousplat */, PPC::EVLHHOUSPLAT, Convert__RegSPERC1_0__DispSPE21_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE2, MCK_RegGxRCNoR0 }, },
  { 5364 /* evlhhousplatx */, PPC::EVLHHOUSPLATX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5378 /* evlwhe */, PPC::EVLWHE, Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE4, MCK_RegGxRCNoR0 }, },
  { 5385 /* evlwhex */, PPC::EVLWHEX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5393 /* evlwhos */, PPC::EVLWHOS, Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE4, MCK_RegGxRCNoR0 }, },
  { 5401 /* evlwhosx */, PPC::EVLWHOSX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5410 /* evlwhou */, PPC::EVLWHOU, Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE4, MCK_RegGxRCNoR0 }, },
  { 5418 /* evlwhoux */, PPC::EVLWHOUX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5427 /* evlwhsplat */, PPC::EVLWHSPLAT, Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE4, MCK_RegGxRCNoR0 }, },
  { 5438 /* evlwhsplatx */, PPC::EVLWHSPLATX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5450 /* evlwwsplat */, PPC::EVLWWSPLAT, Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE4, MCK_RegGxRCNoR0 }, },
  { 5461 /* evlwwsplatx */, PPC::EVLWWSPLATX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 5473 /* evmergehi */, PPC::EVMERGEHI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5483 /* evmergehilo */, PPC::EVMERGEHILO, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5495 /* evmergelo */, PPC::EVMERGELO, Convert__RegSPERC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 5505 /* evmergelohi */, PPC::EVMERGELOHI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5517 /* evmhegsmfaa */, PPC::EVMHEGSMFAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5529 /* evmhegsmfan */, PPC::EVMHEGSMFAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5541 /* evmhegsmiaa */, PPC::EVMHEGSMIAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5553 /* evmhegsmian */, PPC::EVMHEGSMIAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5565 /* evmhegumiaa */, PPC::EVMHEGUMIAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5577 /* evmhegumian */, PPC::EVMHEGUMIAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5589 /* evmhesmf */, PPC::EVMHESMF, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5598 /* evmhesmfa */, PPC::EVMHESMFA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5608 /* evmhesmfaaw */, PPC::EVMHESMFAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5620 /* evmhesmfanw */, PPC::EVMHESMFANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5632 /* evmhesmi */, PPC::EVMHESMI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5641 /* evmhesmia */, PPC::EVMHESMIA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5651 /* evmhesmiaaw */, PPC::EVMHESMIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5663 /* evmhesmianw */, PPC::EVMHESMIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5675 /* evmhessf */, PPC::EVMHESSF, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5684 /* evmhessfa */, PPC::EVMHESSFA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5694 /* evmhessfaaw */, PPC::EVMHESSFAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5706 /* evmhessfanw */, PPC::EVMHESSFANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5718 /* evmhessiaaw */, PPC::EVMHESSIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5730 /* evmhessianw */, PPC::EVMHESSIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5742 /* evmheumi */, PPC::EVMHEUMI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5751 /* evmheumia */, PPC::EVMHEUMIA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5761 /* evmheumiaaw */, PPC::EVMHEUMIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5773 /* evmheumianw */, PPC::EVMHEUMIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5785 /* evmheusiaaw */, PPC::EVMHEUSIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5797 /* evmheusianw */, PPC::EVMHEUSIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5809 /* evmhogsmfaa */, PPC::EVMHOGSMFAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5821 /* evmhogsmfan */, PPC::EVMHOGSMFAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5833 /* evmhogsmiaa */, PPC::EVMHOGSMIAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5845 /* evmhogsmian */, PPC::EVMHOGSMIAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5857 /* evmhogumiaa */, PPC::EVMHOGUMIAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5869 /* evmhogumian */, PPC::EVMHOGUMIAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5881 /* evmhosmf */, PPC::EVMHOSMF, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5890 /* evmhosmfa */, PPC::EVMHOSMFA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5900 /* evmhosmfaaw */, PPC::EVMHOSMFAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5912 /* evmhosmfanw */, PPC::EVMHOSMFANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5924 /* evmhosmi */, PPC::EVMHOSMI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5933 /* evmhosmia */, PPC::EVMHOSMIA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5943 /* evmhosmiaaw */, PPC::EVMHOSMIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5955 /* evmhosmianw */, PPC::EVMHOSMIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5967 /* evmhossf */, PPC::EVMHOSSF, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5976 /* evmhossfa */, PPC::EVMHOSSFA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5986 /* evmhossfaaw */, PPC::EVMHOSSFAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 5998 /* evmhossfanw */, PPC::EVMHOSSFANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6010 /* evmhossiaaw */, PPC::EVMHOSSIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6022 /* evmhossianw */, PPC::EVMHOSSIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6034 /* evmhoumi */, PPC::EVMHOUMI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6043 /* evmhoumia */, PPC::EVMHOUMIA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6053 /* evmhoumiaaw */, PPC::EVMHOUMIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6065 /* evmhoumianw */, PPC::EVMHOUMIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6077 /* evmhousiaaw */, PPC::EVMHOUSIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6089 /* evmhousianw */, PPC::EVMHOUSIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6101 /* evmra */, PPC::EVMRA, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 6107 /* evmwhsmf */, PPC::EVMWHSMF, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6116 /* evmwhsmfa */, PPC::EVMWHSMFA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6126 /* evmwhsmi */, PPC::EVMWHSMI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6135 /* evmwhsmia */, PPC::EVMWHSMIA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6145 /* evmwhssf */, PPC::EVMWHSSF, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6154 /* evmwhssfa */, PPC::EVMWHSSFA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6164 /* evmwhumi */, PPC::EVMWHUMI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6173 /* evmwhumia */, PPC::EVMWHUMIA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6183 /* evmwlsmiaaw */, PPC::EVMWLSMIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6195 /* evmwlsmianw */, PPC::EVMWLSMIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6207 /* evmwlssiaaw */, PPC::EVMWLSSIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6219 /* evmwlssianw */, PPC::EVMWLSSIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6231 /* evmwlumi */, PPC::EVMWLUMI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6240 /* evmwlumia */, PPC::EVMWLUMIA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6250 /* evmwlumiaaw */, PPC::EVMWLUMIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6262 /* evmwlumianw */, PPC::EVMWLUMIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6274 /* evmwlusiaaw */, PPC::EVMWLUSIAAW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6286 /* evmwlusianw */, PPC::EVMWLUSIANW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6298 /* evmwsmf */, PPC::EVMWSMF, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6306 /* evmwsmfa */, PPC::EVMWSMFA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6315 /* evmwsmfaa */, PPC::EVMWSMFAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6325 /* evmwsmfan */, PPC::EVMWSMFAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6335 /* evmwsmi */, PPC::EVMWSMI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6343 /* evmwsmia */, PPC::EVMWSMIA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6352 /* evmwsmiaa */, PPC::EVMWSMIAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6362 /* evmwsmian */, PPC::EVMWSMIAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6372 /* evmwssf */, PPC::EVMWSSF, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6380 /* evmwssfa */, PPC::EVMWSSFA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6389 /* evmwssfaa */, PPC::EVMWSSFAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6399 /* evmwssfan */, PPC::EVMWSSFAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6409 /* evmwumi */, PPC::EVMWUMI, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6417 /* evmwumia */, PPC::EVMWUMIA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6426 /* evmwumiaa */, PPC::EVMWUMIAA, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6436 /* evmwumian */, PPC::EVMWUMIAN, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6446 /* evnand */, PPC::EVNAND, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6453 /* evneg */, PPC::EVNEG, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 6459 /* evnor */, PPC::EVNOR, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6465 /* evor */, PPC::EVOR, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6470 /* evorc */, PPC::EVORC, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6476 /* evrlw */, PPC::EVRLW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6482 /* evrlwi */, PPC::EVRLWI, Convert__RegSPERC1_0__RegSPERC1_1__U5Imm1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_U5Imm }, },
  { 6489 /* evrndw */, PPC::EVRNDW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 6496 /* evsel */, PPC::EVSEL, Convert__RegSPERC1_1__RegSPERC1_2__RegSPERC1_3__imm_95_0, AMFBS_None, { MCK_crD, MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6502 /* evslw */, PPC::EVSLW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6508 /* evslwi */, PPC::EVSLWI, Convert__RegSPERC1_0__RegSPERC1_1__U5Imm1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_U5Imm }, },
  { 6515 /* evsplatfi */, PPC::EVSPLATFI, Convert__RegSPERC1_0__S5Imm1_1, AMFBS_None, { MCK_RegSPERC, MCK_S5Imm }, },
  { 6525 /* evsplati */, PPC::EVSPLATI, Convert__RegSPERC1_0__S5Imm1_1, AMFBS_None, { MCK_RegSPERC, MCK_S5Imm }, },
  { 6534 /* evsrwis */, PPC::EVSRWIS, Convert__RegSPERC1_0__RegSPERC1_1__U5Imm1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_U5Imm }, },
  { 6542 /* evsrwiu */, PPC::EVSRWIU, Convert__RegSPERC1_0__RegSPERC1_1__U5Imm1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_U5Imm }, },
  { 6550 /* evsrws */, PPC::EVSRWS, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6557 /* evsrwu */, PPC::EVSRWU, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6564 /* evstdd */, PPC::EVSTDD, Convert__RegSPERC1_0__DispSPE81_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE8, MCK_RegGxRCNoR0 }, },
  { 6571 /* evstddx */, PPC::EVSTDDX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 6579 /* evstdh */, PPC::EVSTDH, Convert__RegSPERC1_0__DispSPE81_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE8, MCK_RegGxRCNoR0 }, },
  { 6586 /* evstdhx */, PPC::EVSTDHX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 6594 /* evstdw */, PPC::EVSTDW, Convert__RegSPERC1_0__DispSPE81_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE8, MCK_RegGxRCNoR0 }, },
  { 6601 /* evstdwx */, PPC::EVSTDWX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 6609 /* evstwhe */, PPC::EVSTWHE, Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE4, MCK_RegGxRCNoR0 }, },
  { 6617 /* evstwhex */, PPC::EVSTWHEX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 6626 /* evstwho */, PPC::EVSTWHO, Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE4, MCK_RegGxRCNoR0 }, },
  { 6634 /* evstwhox */, PPC::EVSTWHOX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 6643 /* evstwwe */, PPC::EVSTWWE, Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE4, MCK_RegGxRCNoR0 }, },
  { 6651 /* evstwwex */, PPC::EVSTWWEX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 6660 /* evstwwo */, PPC::EVSTWWO, Convert__RegSPERC1_0__DispSPE41_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegSPERC, MCK_DispSPE4, MCK_RegGxRCNoR0 }, },
  { 6668 /* evstwwox */, PPC::EVSTWWOX, Convert__RegSPERC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 6677 /* evsubfsmiaaw */, PPC::EVSUBFSMIAAW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 6690 /* evsubfssiaaw */, PPC::EVSUBFSSIAAW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 6703 /* evsubfumiaaw */, PPC::EVSUBFUMIAAW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 6716 /* evsubfusiaaw */, PPC::EVSUBFUSIAAW, Convert__RegSPERC1_0__RegSPERC1_1, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC }, },
  { 6729 /* evsubfw */, PPC::EVSUBFW, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6737 /* evsubifw */, PPC::EVSUBIFW, Convert__RegSPERC1_0__U5Imm1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_U5Imm, MCK_RegSPERC }, },
  { 6746 /* evxor */, PPC::EVXOR, Convert__RegSPERC1_0__RegSPERC1_1__RegSPERC1_2, AMFBS_None, { MCK_RegSPERC, MCK_RegSPERC, MCK_RegSPERC }, },
  { 6752 /* extldi */, PPC::EXTLDI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 6752 /* extldi */, PPC::EXTLDI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 6759 /* extlwi */, PPC::EXTLWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 6759 /* extlwi */, PPC::EXTLWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 6766 /* extrdi */, PPC::EXTRDI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 6766 /* extrdi */, PPC::EXTRDI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 6773 /* extrwi */, PPC::EXTRWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 6773 /* extrwi */, PPC::EXTRWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 6780 /* extsb */, PPC::EXTSB, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 6780 /* extsb */, PPC::EXTSB_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 6786 /* extsh */, PPC::EXTSH, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 6786 /* extsh */, PPC::EXTSH_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 6792 /* extsw */, PPC::EXTSW, Convert__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 6792 /* extsw */, PPC::EXTSW_rec, Convert__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC }, },
  { 6798 /* extswsli */, PPC::EXTSWSLI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 6798 /* extswsli */, PPC::EXTSWSLI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 6807 /* fabs */, PPC::FABSS, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 6807 /* fabs */, PPC::FABSS_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6812 /* fadd */, PPC::FADD, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6812 /* fadd */, PPC::FADD_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6817 /* fadds */, PPC::FADDS, Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6817 /* fadds */, PPC::FADDS_rec, Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6823 /* fcfid */, PPC::FCFID, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6823 /* fcfid */, PPC::FCFID_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6829 /* fcfids */, PPC::FCFIDS, Convert__RegF4RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF8RC }, },
  { 6829 /* fcfids */, PPC::FCFIDS_rec, Convert__RegF4RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF8RC }, },
  { 6836 /* fcfidu */, PPC::FCFIDU, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6836 /* fcfidu */, PPC::FCFIDU_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6843 /* fcfidus */, PPC::FCFIDUS, Convert__RegF4RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF8RC }, },
  { 6843 /* fcfidus */, PPC::FCFIDUS_rec, Convert__RegF4RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF8RC }, },
  { 6851 /* fcmpo */, PPC::FCMPOS, Convert__RegCRRC1_0__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6857 /* fcmpu */, PPC::FCMPUS, Convert__RegCRRC1_0__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6863 /* fcpsgn */, PPC::FCPSGNS, Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6863 /* fcpsgn */, PPC::FCPSGNS_rec, Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6870 /* fctid */, PPC::FCTID, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6870 /* fctid */, PPC::FCTID_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6876 /* fctidu */, PPC::FCTIDU, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6876 /* fctidu */, PPC::FCTIDU_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6883 /* fctiduz */, PPC::FCTIDUZ, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6883 /* fctiduz */, PPC::FCTIDUZ_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6891 /* fctidz */, PPC::FCTIDZ, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6891 /* fctidz */, PPC::FCTIDZ_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6898 /* fctiw */, PPC::FCTIW, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6898 /* fctiw */, PPC::FCTIW_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6904 /* fctiwu */, PPC::FCTIWU, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6904 /* fctiwu */, PPC::FCTIWU_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6911 /* fctiwuz */, PPC::FCTIWUZ, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6911 /* fctiwuz */, PPC::FCTIWUZ_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6919 /* fctiwz */, PPC::FCTIWZ, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 6919 /* fctiwz */, PPC::FCTIWZ_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6926 /* fdiv */, PPC::FDIV, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6926 /* fdiv */, PPC::FDIV_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6931 /* fdivs */, PPC::FDIVS, Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6931 /* fdivs */, PPC::FDIVS_rec, Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6937 /* fmadd */, PPC::FMADD, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6937 /* fmadd */, PPC::FMADD_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__RegF8RC1_4, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6943 /* fmadds */, PPC::FMADDS, Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6943 /* fmadds */, PPC::FMADDS_rec, Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3__RegF4RC1_4, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6950 /* fmr */, PPC::FMR, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 6950 /* fmr */, PPC::FMR_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6954 /* fmsub */, PPC::FMSUB, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6954 /* fmsub */, PPC::FMSUB_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__RegF8RC1_4, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6960 /* fmsubs */, PPC::FMSUBS, Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6960 /* fmsubs */, PPC::FMSUBS_rec, Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3__RegF4RC1_4, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6967 /* fmul */, PPC::FMUL, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6967 /* fmul */, PPC::FMUL_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6972 /* fmuls */, PPC::FMULS, Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6972 /* fmuls */, PPC::FMULS_rec, Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6978 /* fnabs */, PPC::FNABSS, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 6978 /* fnabs */, PPC::FNABSS_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6984 /* fneg */, PPC::FNEGS, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 6984 /* fneg */, PPC::FNEGS_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6989 /* fnmadd */, PPC::FNMADD, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6989 /* fnmadd */, PPC::FNMADD_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__RegF8RC1_4, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 6996 /* fnmadds */, PPC::FNMADDS, Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 6996 /* fnmadds */, PPC::FNMADDS_rec, Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3__RegF4RC1_4, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7004 /* fnmsub */, PPC::FNMSUB, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 7004 /* fnmsub */, PPC::FNMSUB_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3__RegF8RC1_4, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 7011 /* fnmsubs */, PPC::FNMSUBS, Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7011 /* fnmsubs */, PPC::FNMSUBS_rec, Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3__RegF4RC1_4, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7019 /* fre */, PPC::FRE, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 7019 /* fre */, PPC::FRE_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 7023 /* fres */, PPC::FRES, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 7023 /* fres */, PPC::FRES_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7028 /* frim */, PPC::FRIMS, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 7028 /* frim */, PPC::FRIMS_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7033 /* frin */, PPC::FRINS, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 7033 /* frin */, PPC::FRINS_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7038 /* frip */, PPC::FRIPS, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 7038 /* frip */, PPC::FRIPS_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7043 /* friz */, PPC::FRIZS, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 7043 /* friz */, PPC::FRIZS_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7048 /* frsp */, PPC::FRSP, Convert__RegF4RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF8RC }, },
  { 7048 /* frsp */, PPC::FRSP_rec, Convert__RegF4RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF8RC }, },
  { 7053 /* frsqrte */, PPC::FRSQRTE, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 7053 /* frsqrte */, PPC::FRSQRTE_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 7061 /* frsqrtes */, PPC::FRSQRTES, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 7061 /* frsqrtes */, PPC::FRSQRTES_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7070 /* fsel */, PPC::FSELS, Convert__RegF4RC1_0__RegF8RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK_RegF4RC, MCK_RegF8RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7070 /* fsel */, PPC::FSELS_rec, Convert__RegF4RC1_1__RegF8RC1_2__RegF4RC1_3__RegF4RC1_4, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF8RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7075 /* fsqrt */, PPC::FSQRT, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 7075 /* fsqrt */, PPC::FSQRT_rec, Convert__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC }, },
  { 7081 /* fsqrts */, PPC::FSQRTS, Convert__RegF4RC1_0__RegF4RC1_1, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC }, },
  { 7081 /* fsqrts */, PPC::FSQRTS_rec, Convert__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7088 /* fsub */, PPC::FSUB, Convert__RegF8RC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 7088 /* fsub */, PPC::FSUB_rec, Convert__RegF8RC1_1__RegF8RC1_2__RegF8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF8RC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 7093 /* fsubs */, PPC::FSUBS, Convert__RegF4RC1_0__RegF4RC1_1__RegF4RC1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7093 /* fsubs */, PPC::FSUBS_rec, Convert__RegF4RC1_1__RegF4RC1_2__RegF4RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegF4RC, MCK_RegF4RC, MCK_RegF4RC }, },
  { 7099 /* ftdiv */, PPC::FTDIV, Convert__RegCRRC1_0__RegF8RC1_1__RegF8RC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegF8RC, MCK_RegF8RC }, },
  { 7105 /* ftsqrt */, PPC::FTSQRT, Convert__RegCRRC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegF8RC }, },
  { 7112 /* hashchk */, PPC::HASHCHK, Convert__RegGPRC1_0__DispRIHash1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRIHash, MCK_RegGxRCNoR0 }, },
  { 7120 /* hashchkp */, PPC::HASHCHKP, Convert__RegGPRC1_0__DispRIHash1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRIHash, MCK_RegGxRCNoR0 }, },
  { 7129 /* hashst */, PPC::HASHST, Convert__RegGPRC1_0__DispRIHash1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRIHash, MCK_RegGxRCNoR0 }, },
  { 7136 /* hashstp */, PPC::HASHSTP, Convert__RegGPRC1_0__DispRIHash1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRIHash, MCK_RegGxRCNoR0 }, },
  { 7144 /* hrfid */, PPC::HRFID, Convert_NoOperands, AMFBS_None, {  }, },
  { 7150 /* hwsync */, PPC::SYNCP10, Convert__imm_95_0__imm_95_0, AMFBS_None, {  }, },
  { 7150 /* hwsync */, PPC::SYNC, Convert__imm_95_0, AMFBS_None, {  }, },
  { 7157 /* icbi */, PPC::ICBI, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7162 /* icbiep */, PPC::ICBIEP, Convert__RegGxRCNoR01_0__RegGxRC1_1, AMFBS_None, { MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7169 /* icblc */, PPC::ICBLC, Convert__U4Imm1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_U4Imm, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7175 /* icblq */, PPC::ICBLQ, Convert__U4Imm1_1__RegGxRCNoR01_2__RegGxRC1_3, AMFBS_None, { MCK__DOT_, MCK_U4Imm, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7181 /* icbt */, PPC::ICBT, Convert__U4Imm1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_U4Imm, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7186 /* icbtls */, PPC::ICBTLS, Convert__U4Imm1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_U4Imm, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7193 /* iccci */, PPC::ICCCI, Convert__regR0__regR0, AMFBS_None, {  }, },
  { 7193 /* iccci */, PPC::ICCCI, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 7199 /* ici */, PPC::ICCCI, Convert__regR0__regR0, AMFBS_None, { MCK_0 }, },
  { 7203 /* inslwi */, PPC::INSLWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 7203 /* inslwi */, PPC::INSLWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 7210 /* insrdi */, PPC::INSRDI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 7210 /* insrdi */, PPC::INSRDI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 7217 /* insrwi */, PPC::INSRWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 7217 /* insrwi */, PPC::INSRWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 7224 /* isel */, PPC::ISEL, Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__RegCRBITRC1_3, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_RegGPRC, MCK_RegCRBITRC }, },
  { 7229 /* iseleq */, PPC::ISEL8, Convert__RegG8RC1_0__RegG8RC_NOX01_1__RegG8RC1_2__regCR0EQ, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC_NOX0, MCK_RegG8RC }, },
  { 7229 /* iseleq */, PPC::ISEL, Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__regCR0EQ, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_RegGPRC }, },
  { 7236 /* iselgt */, PPC::ISEL8, Convert__RegG8RC1_0__RegG8RC_NOX01_1__RegG8RC1_2__regCR0GT, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC_NOX0, MCK_RegG8RC }, },
  { 7236 /* iselgt */, PPC::ISEL, Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__regCR0GT, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_RegGPRC }, },
  { 7243 /* isellt */, PPC::ISEL8, Convert__RegG8RC1_0__RegG8RC_NOX01_1__RegG8RC1_2__regCR0LT, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC_NOX0, MCK_RegG8RC }, },
  { 7243 /* isellt */, PPC::ISEL, Convert__RegGPRC1_0__RegGPRC_NOR01_1__RegGPRC1_2__regCR0LT, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_RegGPRC }, },
  { 7250 /* isync */, PPC::ISYNC, Convert_NoOperands, AMFBS_None, {  }, },
  { 7256 /* la */, PPC::LAx, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7259 /* lbarx */, PPC::LBARX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7259 /* lbarx */, PPC::LBARXL, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_1 }, },
  { 7265 /* lbepx */, PPC::LBEPX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7271 /* lbz */, PPC::LBZ, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7275 /* lbzcix */, PPC::LBZCIX, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 7282 /* lbzu */, PPC::LBZU, Convert__RegGPRC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7287 /* lbzux */, PPC::LBZUX, Convert__RegGPRC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7293 /* lbzx */, PPC::LBZXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 7293 /* lbzx */, PPC::LBZX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7298 /* ld */, PPC::LD, Convert__RegG8RC1_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 7301 /* ldarx */, PPC::LDARX, Convert__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7301 /* ldarx */, PPC::LDARXL, Convert__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_1 }, },
  { 7307 /* ldat */, PPC::LDAT, Convert__RegG8pRC1_0__Tie0_1_1__RegGxRCNoR01_1__U5Imm1_2, AMFBS_None, { MCK_RegG8pRC, MCK_RegGxRCNoR0, MCK_U5Imm }, },
  { 7312 /* ldbrx */, PPC::LDBRX, Convert__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7318 /* ldcix */, PPC::LDCIX, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 7324 /* ldu */, PPC::LDU, Convert__RegG8RC1_0__imm_95_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 7328 /* ldux */, PPC::LDUX, Convert__RegG8RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7333 /* ldx */, PPC::LDX, Convert__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7333 /* ldx */, PPC::LDXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 7337 /* lfd */, PPC::LFD, Convert__RegF8RC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7341 /* lfdepx */, PPC::LFDEPX, Convert__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7348 /* lfdu */, PPC::LFDU, Convert__RegF8RC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7353 /* lfdux */, PPC::LFDUX, Convert__RegF8RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7359 /* lfdx */, PPC::LFDX, Convert__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7359 /* lfdx */, PPC::LFDXTLS_, Convert__RegF8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 7364 /* lfiwax */, PPC::LFIWAX, Convert__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7371 /* lfiwzx */, PPC::LFIWZX, Convert__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7378 /* lfs */, PPC::LFS, Convert__RegF4RC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7382 /* lfsu */, PPC::LFSU, Convert__RegF4RC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7387 /* lfsux */, PPC::LFSUX, Convert__RegF4RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7393 /* lfsx */, PPC::LFSX, Convert__RegF4RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7393 /* lfsx */, PPC::LFSXTLS_, Convert__RegF4RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 7398 /* lha */, PPC::LHA, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7402 /* lharx */, PPC::LHARX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7402 /* lharx */, PPC::LHARXL, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_1 }, },
  { 7408 /* lhau */, PPC::LHAU, Convert__RegGPRC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7413 /* lhaux */, PPC::LHAUX, Convert__RegGPRC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7419 /* lhax */, PPC::LHAXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 7419 /* lhax */, PPC::LHAX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7424 /* lhbrx */, PPC::LHBRX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7430 /* lhepx */, PPC::LHEPX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7436 /* lhz */, PPC::LHZ, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7440 /* lhzcix */, PPC::LHZCIX, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 7447 /* lhzu */, PPC::LHZU, Convert__RegGPRC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7452 /* lhzux */, PPC::LHZUX, Convert__RegGPRC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7458 /* lhzx */, PPC::LHZXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 7458 /* lhzx */, PPC::LHZX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7463 /* li */, PPC::ADDI8, Convert__RegG8RC1_0__regZERO8__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 7463 /* li */, PPC::LI, Convert__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 7463 /* li */, PPC::ADDI, Convert__RegGPRC1_0__regZERO__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 7466 /* lis */, PPC::ADDIS8, Convert__RegG8RC1_0__regZERO8__S17Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S17Imm }, },
  { 7466 /* lis */, PPC::LIS, Convert__RegGPRC1_0__S17Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S17Imm }, },
  { 7466 /* lis */, PPC::ADDIS, Convert__RegGPRC1_0__regZERO__S17Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S17Imm }, },
  { 7470 /* lmw */, PPC::LMW, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7474 /* lnia */, PPC::ADDPCIS, Convert__RegG8RC1_0__imm_95_0, AMFBS_None, { MCK_RegG8RC }, },
  { 7479 /* lq */, PPC::LQ, Convert__RegG8pRC1_0__DispRIX161_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8pRC, MCK_DispRIX16, MCK_RegGxRCNoR0 }, },
  { 7482 /* lqarx */, PPC::LQARX, Convert__RegG8pRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8pRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7482 /* lqarx */, PPC::LQARXL, Convert__RegG8pRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8pRC, MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_1 }, },
  { 7488 /* lswi */, PPC::LSWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 7493 /* lvebx */, PPC::LVEBX, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7499 /* lvehx */, PPC::LVEHX, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7505 /* lvewx */, PPC::LVEWX, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7511 /* lvsl */, PPC::LVSL, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7516 /* lvsr */, PPC::LVSR, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7521 /* lvx */, PPC::LVX, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7525 /* lvxl */, PPC::LVXL, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7530 /* lwa */, PPC::LWA, Convert__RegG8RC1_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 7534 /* lwarx */, PPC::LWARX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7534 /* lwarx */, PPC::LWARXL, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC, MCK_1 }, },
  { 7540 /* lwat */, PPC::LWAT, Convert__RegG8pRC1_0__Tie0_1_1__RegGxRCNoR01_1__U5Imm1_2, AMFBS_None, { MCK_RegG8pRC, MCK_RegGxRCNoR0, MCK_U5Imm }, },
  { 7545 /* lwaux */, PPC::LWAUX, Convert__RegG8RC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7551 /* lwax */, PPC::LWAX, Convert__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7551 /* lwax */, PPC::LWAXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 7556 /* lwbrx */, PPC::LWBRX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7562 /* lwepx */, PPC::LWEPX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7568 /* lwsync */, PPC::SYNC, Convert__imm_95_1, AMFBS_None, {  }, },
  { 7575 /* lwz */, PPC::LWZ, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7575 /* lwz */, PPC::SPELWZ, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7579 /* lwzcix */, PPC::LWZCIX, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 7586 /* lwzu */, PPC::LWZU, Convert__RegGPRC1_0__imm_95_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 7591 /* lwzux */, PPC::LWZUX, Convert__RegGPRC1_0__imm_95_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7597 /* lwzx */, PPC::LWZXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 7597 /* lwzx */, PPC::LWZX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7597 /* lwzx */, PPC::SPELWZX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7602 /* lxsd */, PPC::LXSD, Convert__RegVFRC1_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 7607 /* lxsdx */, PPC::LXSDX, Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7613 /* lxsibzx */, PPC::LXSIBZX, Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7621 /* lxsihzx */, PPC::LXSIHZX, Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7629 /* lxsiwax */, PPC::LXSIWAX, Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7637 /* lxsiwzx */, PPC::LXSIWZX, Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7645 /* lxssp */, PPC::LXSSP, Convert__RegVFRC1_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 7651 /* lxsspx */, PPC::LXSSPX, Convert__RegVSSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7658 /* lxv */, PPC::LXV, Convert__RegVSRC1_0__DispRIX161_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRC, MCK_DispRIX16, MCK_RegGxRCNoR0 }, },
  { 7662 /* lxvb16x */, PPC::LXVB16X, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7670 /* lxvd2x */, PPC::LXVD2X, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7677 /* lxvdsx */, PPC::LXVDSX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7684 /* lxvh8x */, PPC::LXVH8X, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7691 /* lxvkq */, PPC::LXVKQ, Convert__RegVSRC1_0__U5Imm1_1, AMFBS_None, { MCK_RegVSRC, MCK_U5Imm }, },
  { 7697 /* lxvl */, PPC::LXVL, Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_Imm, MCK_RegG8RC }, },
  { 7702 /* lxvll */, PPC::LXVLL, Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_Imm, MCK_RegG8RC }, },
  { 7708 /* lxvp */, PPC::LXVP, Convert__RegVSRpRC1_0__DispRIX161_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRpRC, MCK_DispRIX16, MCK_RegGxRCNoR0 }, },
  { 7713 /* lxvpb32x */, PPC::LXVPB32X, Convert__RegVSRpRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_Imm, MCK_RegG8RC }, },
  { 7722 /* lxvprl */, PPC::LXVPRL, Convert__RegVSRpRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_Imm, MCK_RegG8RC }, },
  { 7729 /* lxvprll */, PPC::LXVPRLL, Convert__RegVSRpRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_Imm, MCK_RegG8RC }, },
  { 7737 /* lxvpx */, PPC::LXVPX, Convert__RegVSRpRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7743 /* lxvrbx */, PPC::LXVRBX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7750 /* lxvrdx */, PPC::LXVRDX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7757 /* lxvrhx */, PPC::LXVRHX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7764 /* lxvrl */, PPC::LXVRL, Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_Imm, MCK_RegG8RC }, },
  { 7770 /* lxvrll */, PPC::LXVRLL, Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_Imm, MCK_RegG8RC }, },
  { 7777 /* lxvrwx */, PPC::LXVRWX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7784 /* lxvw4x */, PPC::LXVW4X, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7791 /* lxvwsx */, PPC::LXVWSX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7798 /* lxvx */, PPC::LXVX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 7803 /* maddhd */, PPC::MADDHD, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 7810 /* maddhdu */, PPC::MADDHDU, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 7818 /* maddld */, PPC::MADDLD, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 7825 /* mbar */, PPC::MBAR, Convert__imm_95_0, AMFBS_None, {  }, },
  { 7825 /* mbar */, PPC::MBAR, Convert__U5Imm1_0, AMFBS_None, { MCK_U5Imm }, },
  { 7830 /* mcrf */, PPC::MCRF, Convert__RegCRRC1_0__RegCRRC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegCRRC }, },
  { 7835 /* mcrfs */, PPC::MCRFS, Convert__RegCRRC1_0__RegCRRC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegCRRC }, },
  { 7841 /* mcrxrx */, PPC::MCRXRX, Convert__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 7848 /* mfamr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_29, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 7848 /* mfamr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_29, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7854 /* mfasr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_280, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 7854 /* mfasr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_280, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7860 /* mfbhrbe */, PPC::MFBHRBE, Convert__RegGPRC1_0__U10Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_U10Imm }, },
  { 7868 /* mfbr0 */, PPC::MFDCR, Convert__RegGPRC1_0__imm_95_128, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7874 /* mfbr1 */, PPC::MFDCR, Convert__RegGPRC1_0__imm_95_129, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7880 /* mfbr2 */, PPC::MFDCR, Convert__RegGPRC1_0__imm_95_130, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7886 /* mfbr3 */, PPC::MFDCR, Convert__RegGPRC1_0__imm_95_131, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7892 /* mfbr4 */, PPC::MFDCR, Convert__RegGPRC1_0__imm_95_132, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7898 /* mfbr5 */, PPC::MFDCR, Convert__RegGPRC1_0__imm_95_133, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7904 /* mfbr6 */, PPC::MFDCR, Convert__RegGPRC1_0__imm_95_134, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7910 /* mfbr7 */, PPC::MFDCR, Convert__RegGPRC1_0__imm_95_135, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7916 /* mfcfar */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_28, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 7916 /* mfcfar */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_28, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7923 /* mfcr */, PPC::MFCR, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 7928 /* mfctr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_9, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 7928 /* mfctr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_9, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7928 /* mfctr */, PPC::MFCTR, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 7934 /* mfdar */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_19, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 7934 /* mfdar */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_19, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7940 /* mfdbatl */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_537, AMFBS_ModernAs, { MCK_RegGPRC, MCK_0 }, },
  { 7940 /* mfdbatl */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_539, AMFBS_ModernAs, { MCK_RegGPRC, MCK_1 }, },
  { 7940 /* mfdbatl */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_541, AMFBS_ModernAs, { MCK_RegGPRC, MCK_2 }, },
  { 7940 /* mfdbatl */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_543, AMFBS_ModernAs, { MCK_RegGPRC, MCK_3 }, },
  { 7948 /* mfdbatu */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_536, AMFBS_ModernAs, { MCK_RegGPRC, MCK_0 }, },
  { 7948 /* mfdbatu */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_538, AMFBS_ModernAs, { MCK_RegGPRC, MCK_1 }, },
  { 7948 /* mfdbatu */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_540, AMFBS_ModernAs, { MCK_RegGPRC, MCK_2 }, },
  { 7948 /* mfdbatu */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_542, AMFBS_ModernAs, { MCK_RegGPRC, MCK_3 }, },
  { 7956 /* mfdccr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_1018, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7963 /* mfdcr */, PPC::MFDCR, Convert__RegGPRC1_0__Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_Imm }, },
  { 7969 /* mfdear */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_981, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7976 /* mfdec */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_22, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 7976 /* mfdec */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_22, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7982 /* mfdscr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_17, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 7982 /* mfdscr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_17, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7989 /* mfdsisr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_18, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 7989 /* mfdsisr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_18, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 7997 /* mfesr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_980, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8003 /* mffprd */, PPC::MFVSRD, Convert__RegG8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegF8RC }, },
  { 8010 /* mffprwz */, PPC::MFVSRWZ, Convert__RegGPRC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegF8RC }, },
  { 8018 /* mffs */, PPC::MFFS, Convert__RegF8RC1_0, AMFBS_None, { MCK_RegF8RC }, },
  { 8018 /* mffs */, PPC::MFFS_rec, Convert__RegF8RC1_1, AMFBS_None, { MCK__DOT_, MCK_RegF8RC }, },
  { 8023 /* mffscdrn */, PPC::MFFSCDRN, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 8032 /* mffscdrni */, PPC::MFFSCDRNI, Convert__RegF8RC1_0__U3Imm1_1, AMFBS_None, { MCK_RegF8RC, MCK_U3Imm }, },
  { 8042 /* mffsce */, PPC::MFFSCE, Convert__RegF8RC1_0, AMFBS_None, { MCK_RegF8RC }, },
  { 8049 /* mffscrn */, PPC::MFFSCRN, Convert__RegF8RC1_0__RegF8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegF8RC }, },
  { 8057 /* mffscrni */, PPC::MFFSCRNI, Convert__RegF8RC1_0__U2Imm1_1, AMFBS_None, { MCK_RegF8RC, MCK_U2Imm }, },
  { 8066 /* mffsl */, PPC::MFFSL, Convert__RegF8RC1_0, AMFBS_None, { MCK_RegF8RC }, },
  { 8072 /* mfibatl */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_529, AMFBS_ModernAs, { MCK_RegGPRC, MCK_0 }, },
  { 8072 /* mfibatl */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_531, AMFBS_ModernAs, { MCK_RegGPRC, MCK_1 }, },
  { 8072 /* mfibatl */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_533, AMFBS_ModernAs, { MCK_RegGPRC, MCK_2 }, },
  { 8072 /* mfibatl */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_535, AMFBS_ModernAs, { MCK_RegGPRC, MCK_3 }, },
  { 8080 /* mfibatu */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_528, AMFBS_ModernAs, { MCK_RegGPRC, MCK_0 }, },
  { 8080 /* mfibatu */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_530, AMFBS_ModernAs, { MCK_RegGPRC, MCK_1 }, },
  { 8080 /* mfibatu */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_532, AMFBS_ModernAs, { MCK_RegGPRC, MCK_2 }, },
  { 8080 /* mfibatu */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_534, AMFBS_ModernAs, { MCK_RegGPRC, MCK_3 }, },
  { 8088 /* mficcr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_1019, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8095 /* mflr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_8, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8095 /* mflr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_8, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8095 /* mflr */, PPC::MFLR, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 8100 /* mfmsr */, PPC::MFMSR, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 8106 /* mfocrf */, PPC::MFOCRF, Convert__RegGPRC1_0__CRBitMask1_1, AMFBS_None, { MCK_RegGPRC, MCK_CRBitMask }, },
  { 8113 /* mfpid */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_48, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8119 /* mfpidr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_48, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8126 /* mfpmr */, PPC::MFPMR, Convert__RegGPRC1_0__Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_Imm }, },
  { 8132 /* mfppr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_896, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8138 /* mfpvr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_287, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8138 /* mfpvr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_287, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8144 /* mfrtcl */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_5, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8144 /* mfrtcl */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_5, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8151 /* mfrtcu */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_4, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8151 /* mfrtcu */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_4, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8158 /* mfsdr1 */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_25, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8158 /* mfsdr1 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_25, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8165 /* mfspefscr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_512, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8165 /* mfspefscr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_512, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8175 /* mfspr */, PPC::MFUDSCR, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC, MCK_3 }, },
  { 8175 /* mfspr */, PPC::MFSPR, Convert__RegGPRC1_0__Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_Imm }, },
  { 8181 /* mfsprg */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_272, AMFBS_ModernAs, { MCK_RegG8RC, MCK_0 }, },
  { 8181 /* mfsprg */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_273, AMFBS_ModernAs, { MCK_RegG8RC, MCK_1 }, },
  { 8181 /* mfsprg */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_274, AMFBS_ModernAs, { MCK_RegG8RC, MCK_2 }, },
  { 8181 /* mfsprg */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_275, AMFBS_ModernAs, { MCK_RegG8RC, MCK_3 }, },
  { 8181 /* mfsprg */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_272, AMFBS_ModernAs, { MCK_RegGPRC, MCK_0 }, },
  { 8181 /* mfsprg */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_273, AMFBS_ModernAs, { MCK_RegGPRC, MCK_1 }, },
  { 8181 /* mfsprg */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_274, AMFBS_ModernAs, { MCK_RegGPRC, MCK_2 }, },
  { 8181 /* mfsprg */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_275, AMFBS_ModernAs, { MCK_RegGPRC, MCK_3 }, },
  { 8181 /* mfsprg */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_260, AMFBS_ModernAs, { MCK_RegGPRC, MCK_4 }, },
  { 8181 /* mfsprg */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_261, AMFBS_ModernAs, { MCK_RegGPRC, MCK_5 }, },
  { 8181 /* mfsprg */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_262, AMFBS_ModernAs, { MCK_RegGPRC, MCK_6 }, },
  { 8181 /* mfsprg */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_263, AMFBS_ModernAs, { MCK_RegGPRC, MCK_7 }, },
  { 8188 /* mfsprg0 */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_272, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8188 /* mfsprg0 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_272, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8196 /* mfsprg1 */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_273, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8196 /* mfsprg1 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_273, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8204 /* mfsprg2 */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_274, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8204 /* mfsprg2 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_274, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8212 /* mfsprg3 */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_275, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8212 /* mfsprg3 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_275, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8220 /* mfsprg4 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_260, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8228 /* mfsprg5 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_261, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8236 /* mfsprg6 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_262, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8244 /* mfsprg7 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_263, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8252 /* mfsr */, PPC::MFSR, Convert__RegGPRC1_0__U4Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_U4Imm }, },
  { 8257 /* mfsrin */, PPC::MFSRIN, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 8264 /* mfsrr0 */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_26, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8264 /* mfsrr0 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_26, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8271 /* mfsrr1 */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_27, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8271 /* mfsrr1 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_27, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8278 /* mfsrr2 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_990, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8285 /* mfsrr3 */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_991, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8292 /* mftb */, PPC::MFTB, Convert__RegGPRC1_0__imm_95_268, AMFBS_None, { MCK_RegGPRC }, },
  { 8292 /* mftb */, PPC::MFTB, Convert__RegGPRC1_0__Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_Imm }, },
  { 8297 /* mftbhi */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_988, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8304 /* mftbl */, PPC::MFTB, Convert__RegGPRC1_0__imm_95_268, AMFBS_None, { MCK_RegGPRC }, },
  { 8310 /* mftblo */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_989, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8317 /* mftbu */, PPC::MFTB, Convert__RegGPRC1_0__imm_95_269, AMFBS_None, { MCK_RegGPRC }, },
  { 8323 /* mftcr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_986, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8329 /* mfuamr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_13, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8329 /* mfuamr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_13, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8336 /* mfudscr */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_3, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8336 /* mfudscr */, PPC::MFUDSCR, Convert__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8336 /* mfudscr */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_3, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8344 /* mfvrd */, PPC::MFVRD, Convert__RegG8RC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegVRRC }, },
  { 8350 /* mfvrsave */, PPC::MFVRSAVE, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 8359 /* mfvrwz */, PPC::MFVRWZ, Convert__RegGPRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegVRRC }, },
  { 8366 /* mfvscr */, PPC::MFVSCR, Convert__RegVRRC1_0, AMFBS_None, { MCK_RegVRRC }, },
  { 8373 /* mfvsrd */, PPC::MFVSRD, Convert__RegG8RC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegVSFRC }, },
  { 8380 /* mfvsrld */, PPC::MFVSRLD, Convert__RegG8RC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegVSRC }, },
  { 8388 /* mfvsrwz */, PPC::MFVSRWZ, Convert__RegGPRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegVSFRC }, },
  { 8396 /* mfxer */, PPC::MFSPR8, Convert__RegG8RC1_0__imm_95_1, AMFBS_None, { MCK_RegG8RC }, },
  { 8396 /* mfxer */, PPC::MFSPR, Convert__RegGPRC1_0__imm_95_1, AMFBS_None, { MCK_RegGPRC }, },
  { 8402 /* modsd */, PPC::MODSD, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 8408 /* modsw */, PPC::MODSW, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 8414 /* modud */, PPC::MODUD, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 8420 /* moduw */, PPC::MODUW, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 8426 /* mr */, PPC::OR8, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 8426 /* mr */, PPC::OR, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 8426 /* mr */, PPC::OR8_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC }, },
  { 8426 /* mr */, PPC::OR_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 8429 /* msgsndp */, PPC::MSGSNDP, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 8437 /* msgsync */, PPC::MSGSYNC, Convert_NoOperands, AMFBS_None, {  }, },
  { 8445 /* msync */, PPC::SYNC, Convert__imm_95_0, AMFBS_None, {  }, },
  { 8451 /* mtamr */, PPC::MTSPR8, Convert__imm_95_29__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8451 /* mtamr */, PPC::MTSPR, Convert__imm_95_29__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8457 /* mtasr */, PPC::MTSPR8, Convert__imm_95_280__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8457 /* mtasr */, PPC::MTSPR, Convert__imm_95_280__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8463 /* mtbr0 */, PPC::MTDCR, Convert__RegGPRC1_0__imm_95_128, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8469 /* mtbr1 */, PPC::MTDCR, Convert__RegGPRC1_0__imm_95_129, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8475 /* mtbr2 */, PPC::MTDCR, Convert__RegGPRC1_0__imm_95_130, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8481 /* mtbr3 */, PPC::MTDCR, Convert__RegGPRC1_0__imm_95_131, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8487 /* mtbr4 */, PPC::MTDCR, Convert__RegGPRC1_0__imm_95_132, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8493 /* mtbr5 */, PPC::MTDCR, Convert__RegGPRC1_0__imm_95_133, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8499 /* mtbr6 */, PPC::MTDCR, Convert__RegGPRC1_0__imm_95_134, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8505 /* mtbr7 */, PPC::MTDCR, Convert__RegGPRC1_0__imm_95_135, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8511 /* mtcfar */, PPC::MTSPR8, Convert__imm_95_28__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8511 /* mtcfar */, PPC::MTSPR, Convert__imm_95_28__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8518 /* mtcr */, PPC::MTCRF8, Convert__imm_95_255__RegG8RC1_0, AMFBS_None, { MCK_RegG8RC }, },
  { 8518 /* mtcr */, PPC::MTCRF, Convert__imm_95_255__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 8523 /* mtcrf */, PPC::MTCRF, Convert__Imm1_0__RegGPRC1_1, AMFBS_None, { MCK_Imm, MCK_RegGPRC }, },
  { 8529 /* mtctr */, PPC::MTSPR8, Convert__imm_95_9__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8529 /* mtctr */, PPC::MTSPR, Convert__imm_95_9__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8529 /* mtctr */, PPC::MTCTR, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 8535 /* mtdar */, PPC::MTSPR8, Convert__imm_95_19__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8535 /* mtdar */, PPC::MTSPR, Convert__imm_95_19__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8541 /* mtdbatl */, PPC::MTSPR, Convert__imm_95_537__RegGPRC1_1, AMFBS_ModernAs, { MCK_0, MCK_RegGPRC }, },
  { 8541 /* mtdbatl */, PPC::MTSPR, Convert__imm_95_539__RegGPRC1_1, AMFBS_ModernAs, { MCK_1, MCK_RegGPRC }, },
  { 8541 /* mtdbatl */, PPC::MTSPR, Convert__imm_95_541__RegGPRC1_1, AMFBS_ModernAs, { MCK_2, MCK_RegGPRC }, },
  { 8541 /* mtdbatl */, PPC::MTSPR, Convert__imm_95_543__RegGPRC1_1, AMFBS_ModernAs, { MCK_3, MCK_RegGPRC }, },
  { 8549 /* mtdbatu */, PPC::MTSPR, Convert__imm_95_536__RegGPRC1_1, AMFBS_ModernAs, { MCK_0, MCK_RegGPRC }, },
  { 8549 /* mtdbatu */, PPC::MTSPR, Convert__imm_95_538__RegGPRC1_1, AMFBS_ModernAs, { MCK_1, MCK_RegGPRC }, },
  { 8549 /* mtdbatu */, PPC::MTSPR, Convert__imm_95_540__RegGPRC1_1, AMFBS_ModernAs, { MCK_2, MCK_RegGPRC }, },
  { 8549 /* mtdbatu */, PPC::MTSPR, Convert__imm_95_542__RegGPRC1_1, AMFBS_ModernAs, { MCK_3, MCK_RegGPRC }, },
  { 8557 /* mtdccr */, PPC::MTSPR, Convert__imm_95_1018__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8564 /* mtdcr */, PPC::MTDCR, Convert__RegGPRC1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_RegGPRC }, },
  { 8570 /* mtdear */, PPC::MTSPR, Convert__imm_95_981__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8577 /* mtdec */, PPC::MTSPR8, Convert__imm_95_22__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8577 /* mtdec */, PPC::MTSPR, Convert__imm_95_22__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8583 /* mtdscr */, PPC::MTSPR8, Convert__imm_95_17__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8583 /* mtdscr */, PPC::MTSPR, Convert__imm_95_17__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8590 /* mtdsisr */, PPC::MTSPR8, Convert__imm_95_18__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8590 /* mtdsisr */, PPC::MTSPR, Convert__imm_95_18__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8598 /* mtesr */, PPC::MTSPR, Convert__imm_95_980__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8604 /* mtfprd */, PPC::MTVSRD, Convert__RegF8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegG8RC }, },
  { 8611 /* mtfprwa */, PPC::MTVSRWA, Convert__RegF8RC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegGPRC }, },
  { 8619 /* mtfprwz */, PPC::MTVSRWZ, Convert__RegF8RC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegF8RC, MCK_RegGPRC }, },
  { 8627 /* mtfsb0 */, PPC::MTFSB0, Convert__U5Imm1_0, AMFBS_None, { MCK_U5Imm }, },
  { 8634 /* mtfsb1 */, PPC::MTFSB1, Convert__U5Imm1_0, AMFBS_None, { MCK_U5Imm }, },
  { 8641 /* mtfsf */, PPC::MTFSF, Convert__Imm1_0__RegF8RC1_1__imm_95_0__imm_95_0, AMFBS_None, { MCK_Imm, MCK_RegF8RC }, },
  { 8641 /* mtfsf */, PPC::MTFSF_rec, Convert__Imm1_1__RegF8RC1_2__imm_95_0__imm_95_0, AMFBS_None, { MCK__DOT_, MCK_Imm, MCK_RegF8RC }, },
  { 8641 /* mtfsf */, PPC::MTFSF, Convert__Imm1_0__RegF8RC1_1__U1Imm1_2__Imm1_3, AMFBS_None, { MCK_Imm, MCK_RegF8RC, MCK_U1Imm, MCK_Imm }, },
  { 8641 /* mtfsf */, PPC::MTFSF_rec, Convert__Imm1_1__RegF8RC1_2__U1Imm1_3__Imm1_4, AMFBS_None, { MCK__DOT_, MCK_Imm, MCK_RegF8RC, MCK_U1Imm, MCK_Imm }, },
  { 8647 /* mtfsfi */, PPC::MTFSFI, Convert__U3Imm1_0__U4Imm1_1__imm_95_0, AMFBS_None, { MCK_U3Imm, MCK_U4Imm }, },
  { 8647 /* mtfsfi */, PPC::MTFSFI_rec, Convert__U3Imm1_1__U4Imm1_2__imm_95_0, AMFBS_None, { MCK__DOT_, MCK_U3Imm, MCK_U4Imm }, },
  { 8647 /* mtfsfi */, PPC::MTFSFI, Convert__U3Imm1_0__U4Imm1_1__Imm1_2, AMFBS_None, { MCK_U3Imm, MCK_U4Imm, MCK_Imm }, },
  { 8647 /* mtfsfi */, PPC::MTFSFI_rec, Convert__U3Imm1_1__U4Imm1_2__U1Imm1_3, AMFBS_None, { MCK__DOT_, MCK_U3Imm, MCK_U4Imm, MCK_U1Imm }, },
  { 8654 /* mtibatl */, PPC::MTSPR, Convert__imm_95_529__RegGPRC1_1, AMFBS_ModernAs, { MCK_0, MCK_RegGPRC }, },
  { 8654 /* mtibatl */, PPC::MTSPR, Convert__imm_95_531__RegGPRC1_1, AMFBS_ModernAs, { MCK_1, MCK_RegGPRC }, },
  { 8654 /* mtibatl */, PPC::MTSPR, Convert__imm_95_533__RegGPRC1_1, AMFBS_ModernAs, { MCK_2, MCK_RegGPRC }, },
  { 8654 /* mtibatl */, PPC::MTSPR, Convert__imm_95_535__RegGPRC1_1, AMFBS_ModernAs, { MCK_3, MCK_RegGPRC }, },
  { 8662 /* mtibatu */, PPC::MTSPR, Convert__imm_95_528__RegGPRC1_1, AMFBS_ModernAs, { MCK_0, MCK_RegGPRC }, },
  { 8662 /* mtibatu */, PPC::MTSPR, Convert__imm_95_530__RegGPRC1_1, AMFBS_ModernAs, { MCK_1, MCK_RegGPRC }, },
  { 8662 /* mtibatu */, PPC::MTSPR, Convert__imm_95_532__RegGPRC1_1, AMFBS_ModernAs, { MCK_2, MCK_RegGPRC }, },
  { 8662 /* mtibatu */, PPC::MTSPR, Convert__imm_95_534__RegGPRC1_1, AMFBS_ModernAs, { MCK_3, MCK_RegGPRC }, },
  { 8670 /* mticcr */, PPC::MTSPR, Convert__imm_95_1019__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8677 /* mtlpl */, PPC::MTLPL, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 8683 /* mtlr */, PPC::MTSPR8, Convert__imm_95_8__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8683 /* mtlr */, PPC::MTSPR, Convert__imm_95_8__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8683 /* mtlr */, PPC::MTLR, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 8688 /* mtmsr */, PPC::MTMSR, Convert__RegGPRC1_0__imm_95_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8688 /* mtmsr */, PPC::MTMSR, Convert__RegGPRC1_0__U1Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_U1Imm }, },
  { 8694 /* mtmsrd */, PPC::MTMSRD, Convert__RegGPRC1_0__imm_95_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8694 /* mtmsrd */, PPC::MTMSRD, Convert__RegGPRC1_0__U1Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_U1Imm }, },
  { 8701 /* mtocrf */, PPC::MTOCRF, Convert__CRBitMask1_0__RegGPRC1_1, AMFBS_None, { MCK_CRBitMask, MCK_RegGPRC }, },
  { 8708 /* mtpid */, PPC::MTSPR, Convert__imm_95_48__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8714 /* mtpidr */, PPC::MTSPR, Convert__imm_95_48__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8721 /* mtpmr */, PPC::MTPMR, Convert__Imm1_0__RegGPRC1_1, AMFBS_None, { MCK_Imm, MCK_RegGPRC }, },
  { 8727 /* mtppr */, PPC::MTSPR, Convert__imm_95_896__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8733 /* mtsdr1 */, PPC::MTSPR8, Convert__imm_95_25__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8733 /* mtsdr1 */, PPC::MTSPR, Convert__imm_95_25__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8740 /* mtspefscr */, PPC::MTSPR8, Convert__imm_95_512__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8740 /* mtspefscr */, PPC::MTSPR, Convert__imm_95_512__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8750 /* mtspr */, PPC::MTUDSCR, Convert__RegGPRC1_1, AMFBS_None, { MCK_3, MCK_RegGPRC }, },
  { 8750 /* mtspr */, PPC::MTSPR, Convert__Imm1_0__RegGPRC1_1, AMFBS_None, { MCK_Imm, MCK_RegGPRC }, },
  { 8756 /* mtsprg */, PPC::MTSPR8, Convert__imm_95_272__RegG8RC1_1, AMFBS_ModernAs, { MCK_0, MCK_RegG8RC }, },
  { 8756 /* mtsprg */, PPC::MTSPR, Convert__imm_95_272__RegGPRC1_1, AMFBS_ModernAs, { MCK_0, MCK_RegGPRC }, },
  { 8756 /* mtsprg */, PPC::MTSPR8, Convert__imm_95_273__RegG8RC1_1, AMFBS_ModernAs, { MCK_1, MCK_RegG8RC }, },
  { 8756 /* mtsprg */, PPC::MTSPR, Convert__imm_95_273__RegGPRC1_1, AMFBS_ModernAs, { MCK_1, MCK_RegGPRC }, },
  { 8756 /* mtsprg */, PPC::MTSPR8, Convert__imm_95_274__RegG8RC1_1, AMFBS_ModernAs, { MCK_2, MCK_RegG8RC }, },
  { 8756 /* mtsprg */, PPC::MTSPR, Convert__imm_95_274__RegGPRC1_1, AMFBS_ModernAs, { MCK_2, MCK_RegGPRC }, },
  { 8756 /* mtsprg */, PPC::MTSPR8, Convert__imm_95_275__RegG8RC1_1, AMFBS_ModernAs, { MCK_3, MCK_RegG8RC }, },
  { 8756 /* mtsprg */, PPC::MTSPR, Convert__imm_95_275__RegGPRC1_1, AMFBS_ModernAs, { MCK_3, MCK_RegGPRC }, },
  { 8756 /* mtsprg */, PPC::MTSPR, Convert__imm_95_260__RegGPRC1_1, AMFBS_ModernAs, { MCK_4, MCK_RegGPRC }, },
  { 8756 /* mtsprg */, PPC::MTSPR, Convert__imm_95_261__RegGPRC1_1, AMFBS_ModernAs, { MCK_5, MCK_RegGPRC }, },
  { 8756 /* mtsprg */, PPC::MTSPR, Convert__imm_95_262__RegGPRC1_1, AMFBS_ModernAs, { MCK_6, MCK_RegGPRC }, },
  { 8756 /* mtsprg */, PPC::MTSPR, Convert__imm_95_263__RegGPRC1_1, AMFBS_ModernAs, { MCK_7, MCK_RegGPRC }, },
  { 8763 /* mtsprg0 */, PPC::MTSPR8, Convert__imm_95_272__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8763 /* mtsprg0 */, PPC::MTSPR, Convert__imm_95_272__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8771 /* mtsprg1 */, PPC::MTSPR8, Convert__imm_95_273__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8771 /* mtsprg1 */, PPC::MTSPR, Convert__imm_95_273__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8779 /* mtsprg2 */, PPC::MTSPR8, Convert__imm_95_274__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8779 /* mtsprg2 */, PPC::MTSPR, Convert__imm_95_274__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8787 /* mtsprg3 */, PPC::MTSPR8, Convert__imm_95_275__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8787 /* mtsprg3 */, PPC::MTSPR, Convert__imm_95_275__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8795 /* mtsprg4 */, PPC::MTSPR, Convert__imm_95_260__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8803 /* mtsprg5 */, PPC::MTSPR, Convert__imm_95_261__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8811 /* mtsprg6 */, PPC::MTSPR, Convert__imm_95_262__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8819 /* mtsprg7 */, PPC::MTSPR, Convert__imm_95_263__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8827 /* mtsr */, PPC::MTSR, Convert__RegGPRC1_1__U4Imm1_0, AMFBS_None, { MCK_U4Imm, MCK_RegGPRC }, },
  { 8832 /* mtsrin */, PPC::MTSRIN, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 8839 /* mtsrr0 */, PPC::MTSPR8, Convert__imm_95_26__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8839 /* mtsrr0 */, PPC::MTSPR, Convert__imm_95_26__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8846 /* mtsrr1 */, PPC::MTSPR8, Convert__imm_95_27__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8846 /* mtsrr1 */, PPC::MTSPR, Convert__imm_95_27__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8853 /* mtsrr2 */, PPC::MTSPR, Convert__imm_95_990__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8860 /* mtsrr3 */, PPC::MTSPR, Convert__imm_95_991__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8867 /* mttbhi */, PPC::MTSPR, Convert__imm_95_988__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8874 /* mttbl */, PPC::MTSPR8, Convert__imm_95_284__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8874 /* mttbl */, PPC::MTSPR, Convert__imm_95_284__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8880 /* mttblo */, PPC::MTSPR, Convert__imm_95_989__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8887 /* mttbu */, PPC::MTSPR8, Convert__imm_95_285__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8887 /* mttbu */, PPC::MTSPR, Convert__imm_95_285__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8893 /* mttcr */, PPC::MTSPR, Convert__imm_95_986__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8899 /* mtuamr */, PPC::MTSPR8, Convert__imm_95_13__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8899 /* mtuamr */, PPC::MTSPR, Convert__imm_95_13__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8906 /* mtudscr */, PPC::MTSPR8, Convert__imm_95_3__RegG8RC1_0, AMFBS_ModernAs, { MCK_RegG8RC }, },
  { 8906 /* mtudscr */, PPC::MTUDSCR, Convert__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8906 /* mtudscr */, PPC::MTSPR, Convert__imm_95_3__RegGPRC1_0, AMFBS_ModernAs, { MCK_RegGPRC }, },
  { 8914 /* mtvrd */, PPC::MTVRD, Convert__RegVRRC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegG8RC }, },
  { 8920 /* mtvrsave */, PPC::MTVRSAVE, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 8929 /* mtvrwa */, PPC::MTVRWA, Convert__RegVRRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC }, },
  { 8936 /* mtvrwz */, PPC::MTVRWZ, Convert__RegVRRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC }, },
  { 8943 /* mtvscr */, PPC::MTVSCR, Convert__RegVRRC1_0, AMFBS_None, { MCK_RegVRRC }, },
  { 8950 /* mtvsrbm */, PPC::MTVSRBM, Convert__RegVRRC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegG8RC }, },
  { 8958 /* mtvsrbmi */, PPC::MTVSRBMI, Convert__RegVRRC1_0__U16Imm1_1, AMFBS_None, { MCK_RegVRRC, MCK_U16Imm }, },
  { 8967 /* mtvsrd */, PPC::MTVSRD, Convert__RegVSFRC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegG8RC }, },
  { 8974 /* mtvsrdd */, PPC::MTVSRDD, Convert__RegVSRC1_0__RegG8RC_NOX01_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegG8RC_NOX0, MCK_RegG8RC }, },
  { 8982 /* mtvsrdm */, PPC::MTVSRDM, Convert__RegVRRC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegG8RC }, },
  { 8990 /* mtvsrhm */, PPC::MTVSRHM, Convert__RegVRRC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegG8RC }, },
  { 8998 /* mtvsrqm */, PPC::MTVSRQM, Convert__RegVRRC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegG8RC }, },
  { 9006 /* mtvsrwa */, PPC::MTVSRWA, Convert__RegVSFRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegGPRC }, },
  { 9014 /* mtvsrwm */, PPC::MTVSRWM, Convert__RegVRRC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegG8RC }, },
  { 9022 /* mtvsrws */, PPC::MTVSRWS, Convert__RegVSRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegGPRC }, },
  { 9030 /* mtvsrwz */, PPC::MTVSRWZ, Convert__RegVSFRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegGPRC }, },
  { 9038 /* mtxer */, PPC::MTSPR8, Convert__imm_95_1__RegG8RC1_0, AMFBS_None, { MCK_RegG8RC }, },
  { 9038 /* mtxer */, PPC::MTSPR, Convert__imm_95_1__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 9044 /* mulhd */, PPC::MULHD, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9044 /* mulhd */, PPC::MULHD_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9050 /* mulhdu */, PPC::MULHDU, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9050 /* mulhdu */, PPC::MULHDU_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9057 /* mulhw */, PPC::MULHW, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9057 /* mulhw */, PPC::MULHW_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9063 /* mulhwu */, PPC::MULHWU, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9063 /* mulhwu */, PPC::MULHWU_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9070 /* mulld */, PPC::MULLD, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9070 /* mulld */, PPC::MULLD_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9076 /* mulldo */, PPC::MULLDO, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9076 /* mulldo */, PPC::MULLDO_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9083 /* mulli */, PPC::MULLI, Convert__RegGPRC1_0__RegGPRC1_1__S16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_S16Imm }, },
  { 9089 /* mullw */, PPC::MULLW, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9089 /* mullw */, PPC::MULLW_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9095 /* mullwo */, PPC::MULLWO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9095 /* mullwo */, PPC::MULLWO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9102 /* nand */, PPC::NAND, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9102 /* nand */, PPC::NAND_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9107 /* nap */, PPC::NAP, Convert_NoOperands, AMFBS_None, {  }, },
  { 9111 /* neg */, PPC::NEG, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 9111 /* neg */, PPC::NEG_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9115 /* nego */, PPC::NEGO, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 9115 /* nego */, PPC::NEGO_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9120 /* nop */, PPC::NOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 9120 /* nop */, PPC::ORI, Convert__regR0__regR0__imm_95_0, AMFBS_None, {  }, },
  { 9120 /* nop */, PPC::ORI8, Convert__regX0__regX0__imm_95_0, AMFBS_None, {  }, },
  { 9124 /* nor */, PPC::NOR, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9124 /* nor */, PPC::NOR_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9128 /* not */, PPC::NOR8, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 9128 /* not */, PPC::NOR, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 9128 /* not */, PPC::NOR8_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9128 /* not */, PPC::NOR_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9132 /* or */, PPC::OR, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9132 /* or */, PPC::OR_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9135 /* orc */, PPC::ORC, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9135 /* orc */, PPC::ORC_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9139 /* ori */, PPC::ORI, Convert__RegGPRC1_0__RegGPRC1_1__U16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U16Imm }, },
  { 9143 /* oris */, PPC::ORIS, Convert__RegGPRC1_0__RegGPRC1_1__U16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U16Imm }, },
  { 9148 /* paddi */, PPC::PADDI8, Convert__RegG8RC1_0__RegG8RC_NOX01_1__S34Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC_NOX0, MCK_S34Imm }, },
  { 9148 /* paddi */, PPC::PADDIpc, Convert__RegGPRC1_0__ImmZero1_1__S34Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_ImmZero, MCK_S34Imm, MCK_1 }, },
  { 9148 /* paddi */, PPC::PADDI, Convert__RegGPRC1_0__RegGPRC_NOR01_1__S34Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_S34Imm, MCK_0 }, },
  { 9154 /* paddis */, PPC::PADDIS8, Convert__RegG8RC1_0__RegG8RC_NOX01_1__S32Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC_NOX0, MCK_S32Imm }, },
  { 9154 /* paddis */, PPC::PADDIS, Convert__RegGPRC1_0__RegGPRC_NOR01_1__S32Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_S32Imm }, },
  { 9154 /* paddis */, PPC::PADDISpc, Convert__RegGPRC1_0__ImmZero1_1__S32Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_ImmZero, MCK_S32Imm, MCK_1 }, },
  { 9154 /* paddis */, PPC::PADDIS, Convert__RegGPRC1_0__RegGPRC_NOR01_1__S32Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_S32Imm, MCK_0 }, },
  { 9161 /* paste */, PPC::CP_PASTE_rec, Convert__RegGPRC1_1__RegGPRC1_2__imm_95_1, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 9161 /* paste */, PPC::CP_PASTE_rec, Convert__RegGPRC1_1__RegGPRC1_2__U1Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U1Imm }, },
  { 9167 /* pause_short */, PPC::WAITP10, Convert__imm_95_2__imm_95_0, AMFBS_None, {  }, },
  { 9179 /* pdepd */, PPC::PDEPD, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9185 /* pextd */, PPC::PEXTD, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 9191 /* phwsync */, PPC::SYNCP10, Convert__imm_95_4__imm_95_0, AMFBS_None, {  }, },
  { 9199 /* pla */, PPC::PLA8pc, Convert__RegG8RC1_0__S34Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S34Imm }, },
  { 9199 /* pla */, PPC::PLApc, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9199 /* pla */, PPC::PLA8, Convert__RegG8RC1_0__RegG8RC_NOX01_2__S34Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S34Imm, MCK_RegG8RC_NOX0 }, },
  { 9199 /* pla */, PPC::PLA, Convert__RegGPRC1_0__RegGPRC_NOR01_2__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm, MCK_RegGPRC_NOR0 }, },
  { 9203 /* plbz */, PPC::PLBZonlypc, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9203 /* plbz */, PPC::PLBZnopc, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9203 /* plbz */, PPC::PLBZpc, Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9203 /* plbz */, PPC::PLBZ, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9208 /* pld */, PPC::PLDonlypc, Convert__RegG8RC1_0__S34Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S34Imm }, },
  { 9208 /* pld */, PPC::PLDnopc, Convert__RegG8RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9208 /* pld */, PPC::PLDpc, Convert__RegG8RC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9208 /* pld */, PPC::PLD, Convert__RegG8RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9212 /* plfd */, PPC::PLFDonlypc, Convert__RegF8RC1_0__S34Imm1_1, AMFBS_None, { MCK_RegF8RC, MCK_S34Imm }, },
  { 9212 /* plfd */, PPC::PLFDnopc, Convert__RegF8RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9212 /* plfd */, PPC::PLFDpc, Convert__RegF8RC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9212 /* plfd */, PPC::PLFD, Convert__RegF8RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9217 /* plfs */, PPC::PLFSonlypc, Convert__RegF4RC1_0__S34Imm1_1, AMFBS_None, { MCK_RegF4RC, MCK_S34Imm }, },
  { 9217 /* plfs */, PPC::PLFSnopc, Convert__RegF4RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9217 /* plfs */, PPC::PLFSpc, Convert__RegF4RC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9217 /* plfs */, PPC::PLFS, Convert__RegF4RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9222 /* plha */, PPC::PLHAonlypc, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9222 /* plha */, PPC::PLHAnopc, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9222 /* plha */, PPC::PLHApc, Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9222 /* plha */, PPC::PLHA, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9227 /* plhz */, PPC::PLHZonlypc, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9227 /* plhz */, PPC::PLHZnopc, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9227 /* plhz */, PPC::PLHZpc, Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9227 /* plhz */, PPC::PLHZ, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9232 /* pli */, PPC::PLI, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9236 /* plis */, PPC::PADDIS8, Convert__RegG8RC1_0__regZERO8__S32Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S32Imm }, },
  { 9236 /* plis */, PPC::PADDIS, Convert__RegGPRC1_0__regZERO__S32Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S32Imm }, },
  { 9241 /* plwa */, PPC::PLWAonlypc, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9241 /* plwa */, PPC::PLWAnopc, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9241 /* plwa */, PPC::PLWApc, Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9241 /* plwa */, PPC::PLWA, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9246 /* plwsync */, PPC::SYNCP10, Convert__imm_95_5__imm_95_0, AMFBS_None, {  }, },
  { 9254 /* plwz */, PPC::PLWZonlypc, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9254 /* plwz */, PPC::PLWZnopc, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9254 /* plwz */, PPC::PLWZpc, Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9254 /* plwz */, PPC::PLWZ, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9259 /* plxsd */, PPC::PLXSDonlypc, Convert__RegVFRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegVFRC, MCK_S34Imm }, },
  { 9259 /* plxsd */, PPC::PLXSDnopc, Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9259 /* plxsd */, PPC::PLXSDpc, Convert__RegVFRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9259 /* plxsd */, PPC::PLXSD, Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9265 /* plxssp */, PPC::PLXSSPonlypc, Convert__RegVFRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegVFRC, MCK_S34Imm }, },
  { 9265 /* plxssp */, PPC::PLXSSPnopc, Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9265 /* plxssp */, PPC::PLXSSPpc, Convert__RegVFRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9265 /* plxssp */, PPC::PLXSSP, Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9272 /* plxv */, PPC::PLXVonlypc, Convert__RegVSRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegVSRC, MCK_S34Imm }, },
  { 9272 /* plxv */, PPC::PLXVnopc, Convert__RegVSRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9272 /* plxv */, PPC::PLXVpc, Convert__RegVSRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegVSRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9272 /* plxv */, PPC::PLXV, Convert__RegVSRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9277 /* plxvp */, PPC::PLXVPonlypc, Convert__RegVSRpRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegVSRpRC, MCK_S34Imm }, },
  { 9277 /* plxvp */, PPC::PLXVPnopc, Convert__RegVSRpRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRpRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9277 /* plxvp */, PPC::PLXVPpc, Convert__RegVSRpRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9277 /* plxvp */, PPC::PLXVP, Convert__RegVSRpRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRpRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9283 /* pmdmxvbf16gerx2 */, PPC::PMDMXVBF16GERX2, Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9299 /* pmdmxvbf16gerx2nn */, PPC::PMDMXVBF16GERX2NN, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9317 /* pmdmxvbf16gerx2np */, PPC::PMDMXVBF16GERX2NP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9335 /* pmdmxvbf16gerx2pn */, PPC::PMDMXVBF16GERX2PN, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9353 /* pmdmxvbf16gerx2pp */, PPC::PMDMXVBF16GERX2PP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9371 /* pmdmxvf16gerx2 */, PPC::PMDMXVF16GERX2, Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9386 /* pmdmxvf16gerx2nn */, PPC::PMDMXVF16GERX2NN, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9403 /* pmdmxvf16gerx2np */, PPC::PMDMXVF16GERX2NP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9420 /* pmdmxvf16gerx2pn */, PPC::PMDMXVF16GERX2PN, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9437 /* pmdmxvf16gerx2pp */, PPC::PMDMXVF16GERX2PP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9454 /* pmdmxvi8gerx4 */, PPC::PMDMXVI8GERX4, Convert__RegDMRRC1_0__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U4Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U4Imm }, },
  { 9468 /* pmdmxvi8gerx4pp */, PPC::PMDMXVI8GERX4PP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U4Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U4Imm }, },
  { 9484 /* pmdmxvi8gerx4spp */, PPC::PMDMXVI8GERX4SPP, Convert__RegDMRRC1_0__Tie0_1_1__RegVSRpRC1_1__RegVSRC1_2__U8Imm1_3__U4Imm1_4__U4Imm1_5, AMFBS_None, { MCK_RegDMRRC, MCK_RegVSRpRC, MCK_RegVSRC, MCK_U8Imm, MCK_U4Imm, MCK_U4Imm }, },
  { 9501 /* pmxvbf16ger2 */, PPC::PMXVBF16GER2, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9514 /* pmxvbf16ger2nn */, PPC::PMXVBF16GER2NN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9529 /* pmxvbf16ger2np */, PPC::PMXVBF16GER2NP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9544 /* pmxvbf16ger2pn */, PPC::PMXVBF16GER2PN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9559 /* pmxvbf16ger2pp */, PPC::PMXVBF16GER2PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9574 /* pmxvf16ger2 */, PPC::PMXVF16GER2, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9586 /* pmxvf16ger2nn */, PPC::PMXVF16GER2NN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9600 /* pmxvf16ger2np */, PPC::PMXVF16GER2NP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9614 /* pmxvf16ger2pn */, PPC::PMXVF16GER2PN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9628 /* pmxvf16ger2pp */, PPC::PMXVF16GER2PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9642 /* pmxvf32ger */, PPC::PMXVF32GER, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm }, },
  { 9653 /* pmxvf32gernn */, PPC::PMXVF32GERNN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm }, },
  { 9666 /* pmxvf32gernp */, PPC::PMXVF32GERNP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm }, },
  { 9679 /* pmxvf32gerpn */, PPC::PMXVF32GERPN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm }, },
  { 9692 /* pmxvf32gerpp */, PPC::PMXVF32GERPP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm }, },
  { 9705 /* pmxvf64ger */, PPC::PMXVF64GER, Convert__RegACCRC1_0__RegVSRpEvenRC1_1__RegVSRC1_2__U4Imm1_3__U2Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC, MCK_U4Imm, MCK_U2Imm }, },
  { 9716 /* pmxvf64gernn */, PPC::PMXVF64GERNN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2__U4Imm1_3__U2Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC, MCK_U4Imm, MCK_U2Imm }, },
  { 9729 /* pmxvf64gernp */, PPC::PMXVF64GERNP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2__U4Imm1_3__U2Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC, MCK_U4Imm, MCK_U2Imm }, },
  { 9742 /* pmxvf64gerpn */, PPC::PMXVF64GERPN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2__U4Imm1_3__U2Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC, MCK_U4Imm, MCK_U2Imm }, },
  { 9755 /* pmxvf64gerpp */, PPC::PMXVF64GERPP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2__U4Imm1_3__U2Imm1_4, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC, MCK_U4Imm, MCK_U2Imm }, },
  { 9768 /* pmxvi16ger2 */, PPC::PMXVI16GER2, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9780 /* pmxvi16ger2pp */, PPC::PMXVI16GER2PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9794 /* pmxvi16ger2s */, PPC::PMXVI16GER2S, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9807 /* pmxvi16ger2spp */, PPC::PMXVI16GER2SPP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U2Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U2Imm }, },
  { 9822 /* pmxvi4ger8 */, PPC::PMXVI4GER8, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U8Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U8Imm }, },
  { 9833 /* pmxvi4ger8pp */, PPC::PMXVI4GER8PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U8Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U8Imm }, },
  { 9846 /* pmxvi8ger4 */, PPC::PMXVI8GER4, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U4Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U4Imm }, },
  { 9857 /* pmxvi8ger4pp */, PPC::PMXVI8GER4PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U4Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U4Imm }, },
  { 9870 /* pmxvi8ger4spp */, PPC::PMXVI8GER4SPP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2__U4Imm1_3__U4Imm1_4__U4Imm1_5, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm, MCK_U4Imm, MCK_U4Imm }, },
  { 9884 /* popcntb */, PPC::POPCNTB, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 9892 /* popcntd */, PPC::POPCNTD, Convert__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 9900 /* popcntw */, PPC::POPCNTW, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 9908 /* pstb */, PPC::PSTBonlypc, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9908 /* pstb */, PPC::PSTBnopc, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9908 /* pstb */, PPC::PSTBpc, Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9908 /* pstb */, PPC::PSTB, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9913 /* pstd */, PPC::PSTDonlypc, Convert__RegG8RC1_0__S34Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S34Imm }, },
  { 9913 /* pstd */, PPC::PSTDnopc, Convert__RegG8RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9913 /* pstd */, PPC::PSTDpc, Convert__RegG8RC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9913 /* pstd */, PPC::PSTD, Convert__RegG8RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9918 /* pstfd */, PPC::PSTFDonlypc, Convert__RegF8RC1_0__S34Imm1_1, AMFBS_None, { MCK_RegF8RC, MCK_S34Imm }, },
  { 9918 /* pstfd */, PPC::PSTFDnopc, Convert__RegF8RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9918 /* pstfd */, PPC::PSTFDpc, Convert__RegF8RC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9918 /* pstfd */, PPC::PSTFD, Convert__RegF8RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9924 /* pstfs */, PPC::PSTFSonlypc, Convert__RegF4RC1_0__S34Imm1_1, AMFBS_None, { MCK_RegF4RC, MCK_S34Imm }, },
  { 9924 /* pstfs */, PPC::PSTFSnopc, Convert__RegF4RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9924 /* pstfs */, PPC::PSTFSpc, Convert__RegF4RC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9924 /* pstfs */, PPC::PSTFS, Convert__RegF4RC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9930 /* psth */, PPC::PSTHonlypc, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9930 /* psth */, PPC::PSTHnopc, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9930 /* psth */, PPC::PSTHpc, Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9930 /* psth */, PPC::PSTH, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9935 /* pstw */, PPC::PSTWonlypc, Convert__RegGPRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S34Imm }, },
  { 9935 /* pstw */, PPC::PSTWnopc, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9935 /* pstw */, PPC::PSTWpc, Convert__RegGPRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9935 /* pstw */, PPC::PSTW, Convert__RegGPRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9940 /* pstxsd */, PPC::PSTXSDonlypc, Convert__RegVFRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegVFRC, MCK_S34Imm }, },
  { 9940 /* pstxsd */, PPC::PSTXSDnopc, Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9940 /* pstxsd */, PPC::PSTXSDpc, Convert__RegVFRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9940 /* pstxsd */, PPC::PSTXSD, Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9947 /* pstxssp */, PPC::PSTXSSPonlypc, Convert__RegVFRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegVFRC, MCK_S34Imm }, },
  { 9947 /* pstxssp */, PPC::PSTXSSPnopc, Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9947 /* pstxssp */, PPC::PSTXSSPpc, Convert__RegVFRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9947 /* pstxssp */, PPC::PSTXSSP, Convert__RegVFRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9955 /* pstxv */, PPC::PSTXVonlypc, Convert__RegVSRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegVSRC, MCK_S34Imm }, },
  { 9955 /* pstxv */, PPC::PSTXVnopc, Convert__RegVSRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9955 /* pstxv */, PPC::PSTXVpc, Convert__RegVSRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegVSRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9955 /* pstxv */, PPC::PSTXV, Convert__RegVSRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9961 /* pstxvp */, PPC::PSTXVPonlypc, Convert__RegVSRpRC1_0__S34Imm1_1, AMFBS_None, { MCK_RegVSRpRC, MCK_S34Imm }, },
  { 9961 /* pstxvp */, PPC::PSTXVPnopc, Convert__RegVSRpRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRpRC, MCK_DispRI34, MCK_RegGxRCNoR0 }, },
  { 9961 /* pstxvp */, PPC::PSTXVPpc, Convert__RegVSRpRC1_0__DispRI341_1__ImmZero1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_DispRI34, MCK_ImmZero, MCK_1 }, },
  { 9961 /* pstxvp */, PPC::PSTXVP, Convert__RegVSRpRC1_0__DispRI341_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRpRC, MCK_DispRI34, MCK_RegGxRCNoR0, MCK_0 }, },
  { 9968 /* psubi */, PPC::PSUBI, Convert__RegG8RC1_0__RegG8RC_NOX01_1__S34Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC_NOX0, MCK_S34Imm }, },
  { 9974 /* psubis */, PPC::PADDIS8, Convert__RegG8RC1_0__RegG8RC_NOX01_1__NegS32Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC_NOX0, MCK_NegS32Imm }, },
  { 9974 /* psubis */, PPC::PADDIS, Convert__RegGPRC1_0__RegGPRC_NOR01_1__NegS32Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC_NOR0, MCK_NegS32Imm }, },
  { 9981 /* ptesync */, PPC::SYNCP10, Convert__imm_95_2__imm_95_0, AMFBS_None, {  }, },
  { 9981 /* ptesync */, PPC::SYNC, Convert__imm_95_2, AMFBS_None, {  }, },
  { 9989 /* ptesyncio */, PPC::PTESYNCIO, Convert__RegG8RC1_0, AMFBS_None, { MCK_RegG8RC }, },
  { 9999 /* rfci */, PPC::RFCI, Convert_NoOperands, AMFBS_None, {  }, },
  { 10004 /* rfdi */, PPC::RFDI, Convert_NoOperands, AMFBS_None, {  }, },
  { 10009 /* rfebb */, PPC::RFEBB, Convert__imm_95_1, AMFBS_None, {  }, },
  { 10009 /* rfebb */, PPC::RFEBB, Convert__U1Imm1_0, AMFBS_None, { MCK_U1Imm }, },
  { 10015 /* rfi */, PPC::RFI, Convert_NoOperands, AMFBS_None, {  }, },
  { 10019 /* rfid */, PPC::RFID, Convert_NoOperands, AMFBS_None, {  }, },
  { 10024 /* rfmci */, PPC::RFMCI, Convert_NoOperands, AMFBS_None, {  }, },
  { 10030 /* rldcl */, PPC::RLDCL, Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC, MCK_U6Imm }, },
  { 10030 /* rldcl */, PPC::RLDCL_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC, MCK_U6Imm }, },
  { 10036 /* rldcr */, PPC::RLDCR, Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC, MCK_U6Imm }, },
  { 10036 /* rldcr */, PPC::RLDCR_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC, MCK_U6Imm }, },
  { 10042 /* rldic */, PPC::RLDIC, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 10042 /* rldic */, PPC::RLDIC_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 10048 /* rldicl */, PPC::RLDICL, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 10048 /* rldicl */, PPC::RLDICL_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 10055 /* rldicr */, PPC::RLDICR, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 10055 /* rldicr */, PPC::RLDICR_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 10062 /* rldimi */, PPC::RLDIMI, Convert__RegG8RC1_0__Tie0_1_1__RegG8RC1_1__U6Imm1_2__U6Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 10062 /* rldimi */, PPC::RLDIMI_rec, Convert__RegG8RC1_1__Tie0_1_1__RegG8RC1_2__U6Imm1_3__U6Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm, MCK_U6Imm }, },
  { 10069 /* rlwimi */, PPC::RLWIMIbm, Convert__RegG8RC1_0__RegG8RC1_1__U5Imm1_2__Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm, MCK_Imm }, },
  { 10069 /* rlwimi */, PPC::RLWIMIbm_rec, Convert__RegG8RC1_1__RegG8RC1_2__U5Imm1_3__Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm, MCK_Imm }, },
  { 10069 /* rlwimi */, PPC::RLWIMI, Convert__RegGPRC1_0__Tie0_1_1__RegGPRC1_1__U5Imm1_2__U5Imm1_3__U5Imm1_4, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm, MCK_U5Imm }, },
  { 10069 /* rlwimi */, PPC::RLWIMI_rec, Convert__RegGPRC1_1__Tie0_1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4__U5Imm1_5, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm, MCK_U5Imm }, },
  { 10076 /* rlwinm */, PPC::RLWINMbm, Convert__RegG8RC1_0__RegG8RC1_1__U5Imm1_2__Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm, MCK_Imm }, },
  { 10076 /* rlwinm */, PPC::RLWINMbm_rec, Convert__RegG8RC1_1__RegG8RC1_2__U5Imm1_3__Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm, MCK_Imm }, },
  { 10076 /* rlwinm */, PPC::RLWINM, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__U5Imm1_3__U5Imm1_4, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm, MCK_U5Imm }, },
  { 10076 /* rlwinm */, PPC::RLWINM_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4__U5Imm1_5, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm, MCK_U5Imm }, },
  { 10083 /* rlwnm */, PPC::RLWNMbm, Convert__RegG8RC1_0__RegG8RC1_1__U5Imm1_2__Imm1_3, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm, MCK_Imm }, },
  { 10083 /* rlwnm */, PPC::RLWNMbm_rec, Convert__RegG8RC1_1__RegG8RC1_2__U5Imm1_3__Imm1_4, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm, MCK_Imm }, },
  { 10083 /* rlwnm */, PPC::RLWNM, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__U5Imm1_4, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 10083 /* rlwnm */, PPC::RLWNM_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3__U5Imm1_4__U5Imm1_5, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm, MCK_U5Imm }, },
  { 10089 /* rotld */, PPC::RLDCL, Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2__imm_95_0, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC }, },
  { 10089 /* rotld */, PPC::RLDCL_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3__imm_95_0, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC }, },
  { 10095 /* rotldi */, PPC::RLDICL, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2__imm_95_0, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10095 /* rotldi */, PPC::RLDICL_32_64, Convert__RegG8RC1_0__RegGPRC1_1__U6Imm1_2__imm_95_0, AMFBS_None, { MCK_RegG8RC, MCK_RegGPRC, MCK_U6Imm }, },
  { 10095 /* rotldi */, PPC::RLDICL_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3__imm_95_0, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10102 /* rotlw */, PPC::RLWNM8, Convert__RegG8RC1_0__RegG8RC1_1__RegG8RC1_2__imm_95_0__imm_95_31, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 10102 /* rotlw */, PPC::RLWNM, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2__imm_95_0__imm_95_31, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10102 /* rotlw */, PPC::RLWNM8_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegG8RC1_3__imm_95_0__imm_95_31, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 10102 /* rotlw */, PPC::RLWNM_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3__imm_95_0__imm_95_31, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10108 /* rotlwi */, PPC::RLWINM8, Convert__RegG8RC1_0__RegG8RC1_1__U5Imm1_2__imm_95_0__imm_95_31, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm }, },
  { 10108 /* rotlwi */, PPC::RLWINM, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2__imm_95_0__imm_95_31, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10108 /* rotlwi */, PPC::RLWINM8_rec, Convert__RegG8RC1_1__RegG8RC1_2__U5Imm1_3__imm_95_0__imm_95_31, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U5Imm }, },
  { 10108 /* rotlwi */, PPC::RLWINM_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3__imm_95_0__imm_95_31, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10115 /* rotrdi */, PPC::ROTRDI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10115 /* rotrdi */, PPC::ROTRDI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10122 /* rotrwi */, PPC::ROTRWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10122 /* rotrwi */, PPC::ROTRWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10129 /* sc */, PPC::SC, Convert__imm_95_0, AMFBS_None, {  }, },
  { 10129 /* sc */, PPC::SC, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 10132 /* scv */, PPC::SCV, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 10136 /* setb */, PPC::SETB, Convert__RegGPRC1_0__RegCRRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegCRRC }, },
  { 10141 /* setbc */, PPC::SETBC, Convert__RegGPRC1_0__RegCRBITRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegCRBITRC }, },
  { 10147 /* setbcr */, PPC::SETBCR, Convert__RegGPRC1_0__RegCRBITRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegCRBITRC }, },
  { 10154 /* setnbc */, PPC::SETNBC, Convert__RegGPRC1_0__RegCRBITRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegCRBITRC }, },
  { 10161 /* setnbcr */, PPC::SETNBCR, Convert__RegGPRC1_0__RegCRBITRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegCRBITRC }, },
  { 10169 /* slbfee */, PPC::SLBFEE_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10176 /* slbia */, PPC::SLBIA, Convert_NoOperands, AMFBS_None, {  }, },
  { 10182 /* slbie */, PPC::SLBIE, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 10188 /* slbieg */, PPC::SLBIEG, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 10195 /* slbmfee */, PPC::SLBMFEE, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 10203 /* slbmfev */, PPC::SLBMFEV, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 10211 /* slbmte */, PPC::SLBMTE, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 10218 /* slbsync */, PPC::SLBSYNC, Convert_NoOperands, AMFBS_None, {  }, },
  { 10226 /* sld */, PPC::SLD, Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC }, },
  { 10226 /* sld */, PPC::SLD_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC }, },
  { 10230 /* sldi */, PPC::SLDI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10230 /* sldi */, PPC::SLDI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10235 /* slw */, PPC::SLW, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10235 /* slw */, PPC::SLW_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10239 /* slwi */, PPC::SLWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10239 /* slwi */, PPC::SLWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10244 /* srad */, PPC::SRAD, Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC }, },
  { 10244 /* srad */, PPC::SRAD_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC }, },
  { 10249 /* sradi */, PPC::SRADI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10249 /* sradi */, PPC::SRADI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10255 /* sraw */, PPC::SRAW, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10255 /* sraw */, PPC::SRAW_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10260 /* srawi */, PPC::SRAWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10260 /* srawi */, PPC::SRAWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10266 /* srd */, PPC::SRD, Convert__RegG8RC1_0__RegG8RC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC }, },
  { 10266 /* srd */, PPC::SRD_rec, Convert__RegG8RC1_1__RegG8RC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegGPRC }, },
  { 10270 /* srdi */, PPC::SRDI, Convert__RegG8RC1_0__RegG8RC1_1__U6Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10270 /* srdi */, PPC::SRDI_rec, Convert__RegG8RC1_1__RegG8RC1_2__U6Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_U6Imm }, },
  { 10275 /* srw */, PPC::SRW, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10275 /* srw */, PPC::SRW_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10279 /* srwi */, PPC::SRWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10279 /* srwi */, PPC::SRWI_rec, Convert__RegGPRC1_1__RegGPRC1_2__U5Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10284 /* stb */, PPC::STB, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10288 /* stbcix */, PPC::STBCIX, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10295 /* stbcx */, PPC::STBCX, Convert__RegGPRC1_1__RegGxRCNoR01_2__RegGxRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10301 /* stbepx */, PPC::STBEPX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10308 /* stbu */, PPC::STBU, Convert__imm_95_0__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10313 /* stbux */, PPC::STBUX, Convert__imm_95_0__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10319 /* stbx */, PPC::STBXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 10319 /* stbx */, PPC::STBX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10324 /* stcisync */, PPC::SYNCP10, Convert__imm_95_0__imm_95_2, AMFBS_None, {  }, },
  { 10333 /* std */, PPC::STD, Convert__RegG8RC1_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 10337 /* stdat */, PPC::STDAT, Convert__RegG8RC1_0__RegGxRCNoR01_1__U5Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_U5Imm }, },
  { 10343 /* stdbrx */, PPC::STDBRX, Convert__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10350 /* stdcix */, PPC::STDCIX, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10357 /* stdcx */, PPC::STDCX, Convert__RegG8RC1_1__RegGxRCNoR01_2__RegGxRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10363 /* stdu */, PPC::STDU, Convert__imm_95_0__RegG8RC1_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8RC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 10368 /* stdux */, PPC::STDUX, Convert__imm_95_0__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10374 /* stdx */, PPC::STDX, Convert__RegG8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10374 /* stdx */, PPC::STDXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 10379 /* stfd */, PPC::STFD, Convert__RegF8RC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10384 /* stfdepx */, PPC::STFDEPX, Convert__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10392 /* stfdu */, PPC::STFDU, Convert__imm_95_0__RegF8RC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF8RC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10398 /* stfdux */, PPC::STFDUX, Convert__imm_95_0__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10405 /* stfdx */, PPC::STFDX, Convert__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10405 /* stfdx */, PPC::STFDXTLS_, Convert__RegF8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 10411 /* stfiwx */, PPC::STFIWX, Convert__RegF8RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF8RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10418 /* stfs */, PPC::STFS, Convert__RegF4RC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10423 /* stfsu */, PPC::STFSU, Convert__imm_95_0__RegF4RC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegF4RC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10429 /* stfsux */, PPC::STFSUX, Convert__imm_95_0__RegF4RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10436 /* stfsx */, PPC::STFSX, Convert__RegF4RC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10436 /* stfsx */, PPC::STFSXTLS_, Convert__RegF4RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegF4RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 10442 /* sth */, PPC::STH, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10446 /* sthbrx */, PPC::STHBRX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10453 /* sthcix */, PPC::STHCIX, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10460 /* sthcx */, PPC::STHCX, Convert__RegGPRC1_1__RegGxRCNoR01_2__RegGxRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10466 /* sthepx */, PPC::STHEPX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10473 /* sthu */, PPC::STHU, Convert__imm_95_0__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10478 /* sthux */, PPC::STHUX, Convert__imm_95_0__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10484 /* sthx */, PPC::STHXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 10484 /* sthx */, PPC::STHX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10489 /* stmw */, PPC::STMW, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10494 /* stncisync */, PPC::SYNCP10, Convert__imm_95_1__imm_95_1, AMFBS_None, {  }, },
  { 10504 /* stop */, PPC::STOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 10509 /* stq */, PPC::STQ, Convert__RegG8pRC1_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegG8pRC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 10513 /* stqcx */, PPC::STQCX, Convert__RegG8pRC1_1__RegGxRCNoR01_2__RegGxRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegG8pRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10519 /* stswi */, PPC::STSWI, Convert__RegGPRC1_0__RegGPRC1_1__U5Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U5Imm }, },
  { 10525 /* stsync */, PPC::SYNCP10, Convert__imm_95_0__imm_95_3, AMFBS_None, {  }, },
  { 10532 /* stvebx */, PPC::STVEBX, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10539 /* stvehx */, PPC::STVEHX, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10546 /* stvewx */, PPC::STVEWX, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10553 /* stvx */, PPC::STVX, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10558 /* stvxl */, PPC::STVXL, Convert__RegVRRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10564 /* stw */, PPC::SPESTW, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10564 /* stw */, PPC::STW, Convert__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10568 /* stwat */, PPC::STWAT, Convert__RegGPRC1_0__RegGxRCNoR01_1__U5Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_U5Imm }, },
  { 10574 /* stwbrx */, PPC::STWBRX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10581 /* stwcix */, PPC::STWCIX, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10588 /* stwcx */, PPC::STWCX, Convert__RegGPRC1_1__RegGxRCNoR01_2__RegGxRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10594 /* stwepx */, PPC::STWEPX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10601 /* stwu */, PPC::STWU, Convert__imm_95_0__RegGPRC1_0__DispRI1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegGPRC, MCK_DispRI, MCK_RegGxRCNoR0 }, },
  { 10606 /* stwux */, PPC::STWUX, Convert__imm_95_0__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10612 /* stwx */, PPC::STWXTLS_, Convert__RegG8RC1_0__RegGxRCNoR01_1__TLSReg1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegGxRCNoR0, MCK_TLSReg }, },
  { 10612 /* stwx */, PPC::SPESTWX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10612 /* stwx */, PPC::STWX, Convert__RegGPRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10617 /* stxsd */, PPC::STXSD, Convert__RegVFRC1_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 10623 /* stxsdx */, PPC::STXSDX, Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10630 /* stxsibx */, PPC::STXSIBX, Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10638 /* stxsihx */, PPC::STXSIHX, Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10646 /* stxsiwx */, PPC::STXSIWX, Convert__RegVSFRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10654 /* stxssp */, PPC::STXSSP, Convert__RegVFRC1_0__DispRIX1_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVFRC, MCK_DispRIX, MCK_RegGxRCNoR0 }, },
  { 10661 /* stxsspx */, PPC::STXSSPX, Convert__RegVSSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10669 /* stxv */, PPC::STXV, Convert__RegVSRC1_0__DispRIX161_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRC, MCK_DispRIX16, MCK_RegGxRCNoR0 }, },
  { 10674 /* stxvb16x */, PPC::STXVB16X, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10683 /* stxvd2x */, PPC::STXVD2X, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10691 /* stxvh8x */, PPC::STXVH8X, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10699 /* stxvl */, PPC::STXVL, Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_Imm, MCK_RegG8RC }, },
  { 10705 /* stxvll */, PPC::STXVLL, Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_Imm, MCK_RegG8RC }, },
  { 10712 /* stxvp */, PPC::STXVP, Convert__RegVSRpRC1_0__DispRIX161_1__RegGxRCNoR01_2, AMFBS_None, { MCK_RegVSRpRC, MCK_DispRIX16, MCK_RegGxRCNoR0 }, },
  { 10718 /* stxvpb32x */, PPC::STXVPB32X, Convert__RegVSRpRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_Imm, MCK_RegG8RC }, },
  { 10728 /* stxvprl */, PPC::STXVPRL, Convert__RegVSRpRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_Imm, MCK_RegG8RC }, },
  { 10736 /* stxvprll */, PPC::STXVPRLL, Convert__RegVSRpRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_Imm, MCK_RegG8RC }, },
  { 10745 /* stxvpx */, PPC::STXVPX, Convert__RegVSRpRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10752 /* stxvrbx */, PPC::STXVRBX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10760 /* stxvrdx */, PPC::STXVRDX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10768 /* stxvrhx */, PPC::STXVRHX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10776 /* stxvrl */, PPC::STXVRL, Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_Imm, MCK_RegG8RC }, },
  { 10783 /* stxvrll */, PPC::STXVRLL, Convert__RegVSRC1_0__Imm1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_Imm, MCK_RegG8RC }, },
  { 10791 /* stxvrwx */, PPC::STXVRWX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10799 /* stxvw4x */, PPC::STXVW4X, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10807 /* stxvx */, PPC::STXVX, Convert__RegVSRC1_0__RegGxRCNoR01_1__RegGxRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegGxRCNoR0, MCK_RegGxRC }, },
  { 10813 /* sub */, PPC::SUBF8, Convert__RegG8RC1_0__RegG8RC1_2__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 10813 /* sub */, PPC::SUBF, Convert__RegGPRC1_0__RegGPRC1_2__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10813 /* sub */, PPC::SUBF8_rec, Convert__RegG8RC1_1__RegG8RC1_3__RegG8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 10813 /* sub */, PPC::SUBF_rec, Convert__RegGPRC1_1__RegGPRC1_3__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10817 /* subc */, PPC::SUBFC8, Convert__RegG8RC1_0__RegG8RC1_2__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 10817 /* subc */, PPC::SUBFC, Convert__RegGPRC1_0__RegGPRC1_2__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10817 /* subc */, PPC::SUBFC8_rec, Convert__RegG8RC1_1__RegG8RC1_3__RegG8RC1_2, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 10817 /* subc */, PPC::SUBFC_rec, Convert__RegGPRC1_1__RegGPRC1_3__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10822 /* subf */, PPC::SUBF, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10822 /* subf */, PPC::SUBF_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10827 /* subfc */, PPC::SUBFC, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10827 /* subfc */, PPC::SUBFC_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10833 /* subfco */, PPC::SUBFCO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10833 /* subfco */, PPC::SUBFCO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10840 /* subfe */, PPC::SUBFE, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10840 /* subfe */, PPC::SUBFE_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10846 /* subfeo */, PPC::SUBFEO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10846 /* subfeo */, PPC::SUBFEO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10853 /* subfic */, PPC::SUBFIC, Convert__RegGPRC1_0__RegGPRC1_1__S16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_S16Imm }, },
  { 10860 /* subfme */, PPC::SUBFME, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 10860 /* subfme */, PPC::SUBFME_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10867 /* subfmeo */, PPC::SUBFMEO, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 10867 /* subfmeo */, PPC::SUBFMEO_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10875 /* subfo */, PPC::SUBFO, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10875 /* subfo */, PPC::SUBFO_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10881 /* subfus */, PPC::SUBFUS, Convert__RegG8RC1_0__RegG8RC1_2__RegG8RC1_3__U1Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_U1Imm, MCK_RegG8RC, MCK_RegG8RC }, },
  { 10881 /* subfus */, PPC::SUBFUS_rec, Convert__RegG8RC1_1__RegG8RC1_3__RegG8RC1_4__U1Imm1_2, AMFBS_None, { MCK__DOT_, MCK_RegG8RC, MCK_U1Imm, MCK_RegG8RC, MCK_RegG8RC }, },
  { 10888 /* subfze */, PPC::SUBFZE, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 10888 /* subfze */, PPC::SUBFZE_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10895 /* subfzeo */, PPC::SUBFZEO, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 10895 /* subfzeo */, PPC::SUBFZEO_rec, Convert__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10903 /* subi */, PPC::SUBI, Convert__RegGPRC1_0__RegGPRC1_1__S16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_S16Imm }, },
  { 10908 /* subic */, PPC::SUBIC, Convert__RegGPRC1_0__RegGPRC1_1__S16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_S16Imm }, },
  { 10908 /* subic */, PPC::SUBIC_rec, Convert__RegGPRC1_1__RegGPRC1_2__S16Imm1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_S16Imm }, },
  { 10914 /* subis */, PPC::SUBIS, Convert__RegGPRC1_0__RegGPRC1_1__S16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_S16Imm }, },
  { 10920 /* subpcis */, PPC::SUBPCIS, Convert__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 10928 /* sync */, PPC::SYNCP10, Convert__imm_95_0__imm_95_0, AMFBS_None, {  }, },
  { 10928 /* sync */, PPC::SYNC, Convert__imm_95_0, AMFBS_None, {  }, },
  { 10928 /* sync */, PPC::SYNC, Convert__U2Imm1_0, AMFBS_None, { MCK_U2Imm }, },
  { 10928 /* sync */, PPC::SYNCP10, Convert__U3Imm1_0__imm_95_0, AMFBS_None, { MCK_U3Imm }, },
  { 10928 /* sync */, PPC::SYNCP10, Convert__U3Imm1_0__U2Imm1_1, AMFBS_None, { MCK_U3Imm, MCK_U2Imm }, },
  { 10933 /* tabort */, PPC::TABORT, Convert__RegGPRC1_1, AMFBS_None, { MCK__DOT_, MCK_RegGPRC }, },
  { 10940 /* tabortdc */, PPC::TABORTDC, Convert__U5Imm1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_U5Imm, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10949 /* tabortdci */, PPC::TABORTDCI, Convert__U5Imm1_1__RegGPRC1_2__U5Imm1_3, AMFBS_None, { MCK__DOT_, MCK_U5Imm, MCK_RegGPRC, MCK_U5Imm }, },
  { 10959 /* tabortwc */, PPC::TABORTWC, Convert__U5Imm1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_U5Imm, MCK_RegGPRC, MCK_RegGPRC }, },
  { 10968 /* tabortwci */, PPC::TABORTWCI, Convert__U5Imm1_1__RegGPRC1_2__U5Imm1_3, AMFBS_None, { MCK__DOT_, MCK_U5Imm, MCK_RegGPRC, MCK_U5Imm }, },
  { 10978 /* tbegin */, PPC::TBEGIN, Convert__U1Imm1_1, AMFBS_None, { MCK__DOT_, MCK_U1Imm }, },
  { 10985 /* tcheck */, PPC::TCHECK, Convert__RegCRRC1_0, AMFBS_None, { MCK_RegCRRC }, },
  { 10992 /* td */, PPC::TD, Convert__U5Imm1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_U5Imm, MCK_RegG8RC, MCK_RegG8RC }, },
  { 10995 /* tdeq */, PPC::TD, Convert__imm_95_4__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11000 /* tdeqi */, PPC::TDI, Convert__imm_95_4__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11006 /* tdge */, PPC::TD, Convert__imm_95_12__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11011 /* tdgei */, PPC::TDI, Convert__imm_95_12__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11017 /* tdgt */, PPC::TD, Convert__imm_95_8__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11022 /* tdgti */, PPC::TDI, Convert__imm_95_8__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11028 /* tdi */, PPC::TDI, Convert__U5Imm1_0__RegG8RC1_1__S16Imm1_2, AMFBS_None, { MCK_U5Imm, MCK_RegG8RC, MCK_S16Imm }, },
  { 11032 /* tdle */, PPC::TD, Convert__imm_95_20__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11037 /* tdlei */, PPC::TDI, Convert__imm_95_20__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11043 /* tdlge */, PPC::TD, Convert__imm_95_5__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11049 /* tdlgei */, PPC::TDI, Convert__imm_95_5__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11056 /* tdlgt */, PPC::TD, Convert__imm_95_1__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11062 /* tdlgti */, PPC::TDI, Convert__imm_95_1__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11069 /* tdlle */, PPC::TD, Convert__imm_95_6__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11075 /* tdllei */, PPC::TDI, Convert__imm_95_6__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11082 /* tdllt */, PPC::TD, Convert__imm_95_2__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11088 /* tdllti */, PPC::TDI, Convert__imm_95_2__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11095 /* tdlng */, PPC::TD, Convert__imm_95_6__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11101 /* tdlngi */, PPC::TDI, Convert__imm_95_6__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11108 /* tdlnl */, PPC::TD, Convert__imm_95_5__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11114 /* tdlnli */, PPC::TDI, Convert__imm_95_5__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11121 /* tdlt */, PPC::TD, Convert__imm_95_16__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11126 /* tdlti */, PPC::TDI, Convert__imm_95_16__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11132 /* tdne */, PPC::TD, Convert__imm_95_24__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11137 /* tdnei */, PPC::TDI, Convert__imm_95_24__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11143 /* tdng */, PPC::TD, Convert__imm_95_20__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11148 /* tdngi */, PPC::TDI, Convert__imm_95_20__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11154 /* tdnl */, PPC::TD, Convert__imm_95_12__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11159 /* tdnli */, PPC::TDI, Convert__imm_95_12__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11165 /* tdu */, PPC::TD, Convert__imm_95_31__RegG8RC1_0__RegG8RC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC }, },
  { 11169 /* tdui */, PPC::TDI, Convert__imm_95_31__RegG8RC1_0__S16Imm1_1, AMFBS_None, { MCK_RegG8RC, MCK_S16Imm }, },
  { 11174 /* tend */, PPC::TEND, Convert__imm_95_0, AMFBS_None, { MCK__DOT_ }, },
  { 11174 /* tend */, PPC::TEND, Convert__U1Imm1_1, AMFBS_None, { MCK__DOT_, MCK_U1Imm }, },
  { 11179 /* tendall */, PPC::TEND, Convert__imm_95_1, AMFBS_None, { MCK__DOT_ }, },
  { 11187 /* tlbia */, PPC::TLBIA, Convert_NoOperands, AMFBS_None, {  }, },
  { 11193 /* tlbie */, PPC::TLBIE, Convert__regR0__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 11193 /* tlbie */, PPC::TLBIEP9, Convert__regR0__RegGPRC1_0__imm_95_0__imm_95_0__imm_95_0, AMFBS_None, { MCK_RegGPRC }, },
  { 11193 /* tlbie */, PPC::TLBIE, Convert__RegGPRC1_1__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11193 /* tlbie */, PPC::TLBIEP9, Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0__imm_95_0__imm_95_0, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11193 /* tlbie */, PPC::TLBIEP9, Convert__RegGPRC1_0__RegGPRC1_1__U2Imm1_2__U1Imm1_3__U1Imm1_4, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U2Imm, MCK_U1Imm, MCK_U1Imm }, },
  { 11199 /* tlbieio */, PPC::TLBIEIO, Convert__RegG8RC1_0__RegG8RC1_1__U2Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_U2Imm }, },
  { 11207 /* tlbiel */, PPC::TLBIEL, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 11214 /* tlbiep */, PPC::TLBIEP, Convert__RegGPRC1_0__RegGPRC1_1__U2Imm1_2__U1Imm1_3__U1Imm1_4, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U2Imm, MCK_U1Imm, MCK_U1Imm }, },
  { 11221 /* tlbilx */, PPC::TLBILX, Convert__U2Imm1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_U2Imm, MCK_RegGPRC, MCK_RegGPRC }, },
  { 11228 /* tlbilxlpid */, PPC::TLBILX, Convert__imm_95_0__regR0__regR0, AMFBS_None, {  }, },
  { 11239 /* tlbilxpid */, PPC::TLBILX, Convert__imm_95_1__regR0__regR0, AMFBS_None, {  }, },
  { 11249 /* tlbilxva */, PPC::TLBILX, Convert__imm_95_3__regR0__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 11249 /* tlbilxva */, PPC::TLBILX, Convert__imm_95_3__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11258 /* tlbivax */, PPC::TLBIVAX, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11266 /* tlbld */, PPC::TLBLD, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 11272 /* tlbli */, PPC::TLBLI, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 11278 /* tlbre */, PPC::TLBRE, Convert_NoOperands, AMFBS_None, {  }, },
  { 11278 /* tlbre */, PPC::TLBRE2, Convert__RegGPRC1_0__RegGPRC1_1__Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_Imm }, },
  { 11284 /* tlbrehi */, PPC::TLBRE2, Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11292 /* tlbrelo */, PPC::TLBRE2, Convert__RegGPRC1_0__RegGPRC1_1__imm_95_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11300 /* tlbsx */, PPC::TLBSX, Convert__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11300 /* tlbsx */, PPC::TLBSX2, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 11300 /* tlbsx */, PPC::TLBSX2D, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 11306 /* tlbsync */, PPC::TLBSYNC, Convert_NoOperands, AMFBS_None, {  }, },
  { 11314 /* tlbsyncio */, PPC::TLBSYNCIO, Convert__RegG8RC1_0, AMFBS_None, { MCK_RegG8RC }, },
  { 11324 /* tlbwe */, PPC::TLBWE, Convert_NoOperands, AMFBS_None, {  }, },
  { 11324 /* tlbwe */, PPC::TLBWE2, Convert__RegGPRC1_0__RegGPRC1_1__Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_Imm }, },
  { 11330 /* tlbwehi */, PPC::TLBWE2, Convert__RegGPRC1_0__RegGPRC1_1__imm_95_0, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11338 /* tlbwelo */, PPC::TLBWE2, Convert__RegGPRC1_0__RegGPRC1_1__imm_95_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11346 /* trap */, PPC::TRAP, Convert_NoOperands, AMFBS_None, {  }, },
  { 11346 /* trap */, PPC::TW, Convert__imm_95_31__regR0__regR0, AMFBS_None, {  }, },
  { 11351 /* trechkpt */, PPC::TRECHKPT, Convert_NoOperands, AMFBS_None, { MCK__DOT_ }, },
  { 11360 /* treclaim */, PPC::TRECLAIM, Convert__RegGPRC1_1, AMFBS_None, { MCK__DOT_, MCK_RegGPRC }, },
  { 11369 /* tresume */, PPC::TSR, Convert__imm_95_1, AMFBS_None, { MCK__DOT_ }, },
  { 11377 /* tsr */, PPC::TSR, Convert__U1Imm1_1, AMFBS_None, { MCK__DOT_, MCK_U1Imm }, },
  { 11381 /* tsuspend */, PPC::TSR, Convert__imm_95_0, AMFBS_None, { MCK__DOT_ }, },
  { 11390 /* tw */, PPC::TW, Convert__U5Imm1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_U5Imm, MCK_RegGPRC, MCK_RegGPRC }, },
  { 11393 /* tweq */, PPC::TW, Convert__imm_95_4__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11398 /* tweqi */, PPC::TWI, Convert__imm_95_4__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11404 /* twge */, PPC::TW, Convert__imm_95_12__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11409 /* twgei */, PPC::TWI, Convert__imm_95_12__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11415 /* twgt */, PPC::TW, Convert__imm_95_8__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11420 /* twgti */, PPC::TWI, Convert__imm_95_8__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11426 /* twi */, PPC::TWI, Convert__U5Imm1_0__RegGPRC1_1__S16Imm1_2, AMFBS_None, { MCK_U5Imm, MCK_RegGPRC, MCK_S16Imm }, },
  { 11430 /* twle */, PPC::TW, Convert__imm_95_20__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11435 /* twlei */, PPC::TWI, Convert__imm_95_20__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11441 /* twlge */, PPC::TW, Convert__imm_95_5__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11447 /* twlgei */, PPC::TWI, Convert__imm_95_5__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11454 /* twlgt */, PPC::TW, Convert__imm_95_1__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11460 /* twlgti */, PPC::TWI, Convert__imm_95_1__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11467 /* twlle */, PPC::TW, Convert__imm_95_6__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11473 /* twllei */, PPC::TWI, Convert__imm_95_6__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11480 /* twllt */, PPC::TW, Convert__imm_95_2__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11486 /* twllti */, PPC::TWI, Convert__imm_95_2__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11493 /* twlng */, PPC::TW, Convert__imm_95_6__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11499 /* twlngi */, PPC::TWI, Convert__imm_95_6__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11506 /* twlnl */, PPC::TW, Convert__imm_95_5__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11512 /* twlnli */, PPC::TWI, Convert__imm_95_5__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11519 /* twlt */, PPC::TW, Convert__imm_95_16__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11524 /* twlti */, PPC::TWI, Convert__imm_95_16__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11530 /* twne */, PPC::TW, Convert__imm_95_24__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11535 /* twnei */, PPC::TWI, Convert__imm_95_24__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11541 /* twng */, PPC::TW, Convert__imm_95_20__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11546 /* twngi */, PPC::TWI, Convert__imm_95_20__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11552 /* twnl */, PPC::TW, Convert__imm_95_12__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11557 /* twnli */, PPC::TWI, Convert__imm_95_12__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11563 /* twu */, PPC::TW, Convert__imm_95_31__RegGPRC1_0__RegGPRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC }, },
  { 11567 /* twui */, PPC::TWI, Convert__imm_95_31__RegGPRC1_0__S16Imm1_1, AMFBS_None, { MCK_RegGPRC, MCK_S16Imm }, },
  { 11572 /* vabsdub */, PPC::VABSDUB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11580 /* vabsduh */, PPC::VABSDUH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11588 /* vabsduw */, PPC::VABSDUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11596 /* vaddcuq */, PPC::VADDCUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11604 /* vaddcuw */, PPC::VADDCUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11612 /* vaddecuq */, PPC::VADDECUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11621 /* vaddeuqm */, PPC::VADDEUQM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11630 /* vaddfp */, PPC::VADDFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11637 /* vaddsbs */, PPC::VADDSBS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11645 /* vaddshs */, PPC::VADDSHS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11653 /* vaddsws */, PPC::VADDSWS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11661 /* vaddubm */, PPC::VADDUBM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11669 /* vaddubs */, PPC::VADDUBS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11677 /* vaddudm */, PPC::VADDUDM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11685 /* vadduhm */, PPC::VADDUHM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11693 /* vadduhs */, PPC::VADDUHS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11701 /* vadduqm */, PPC::VADDUQM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11709 /* vadduwm */, PPC::VADDUWM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11717 /* vadduws */, PPC::VADDUWS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11725 /* vand */, PPC::VAND, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11730 /* vandc */, PPC::VANDC, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11736 /* vavgsb */, PPC::VAVGSB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11743 /* vavgsh */, PPC::VAVGSH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11750 /* vavgsw */, PPC::VAVGSW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11757 /* vavgub */, PPC::VAVGUB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11764 /* vavguh */, PPC::VAVGUH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11771 /* vavguw */, PPC::VAVGUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11778 /* vbpermd */, PPC::VBPERMD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11786 /* vbpermq */, PPC::VBPERMQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11794 /* vcfsx */, PPC::VCFSX, Convert__RegVRRC1_0__U5Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U5Imm }, },
  { 11800 /* vcfuged */, PPC::VCFUGED, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11808 /* vcfux */, PPC::VCFUX, Convert__RegVRRC1_0__U5Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U5Imm }, },
  { 11814 /* vcipher */, PPC::VCIPHER, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11822 /* vcipherlast */, PPC::VCIPHERLAST, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11834 /* vclrlb */, PPC::VCLRLB, Convert__RegVRRC1_0__RegVRRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 11841 /* vclrrb */, PPC::VCLRRB, Convert__RegVRRC1_0__RegVRRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 11848 /* vclzb */, PPC::VCLZB, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 11854 /* vclzd */, PPC::VCLZD, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 11860 /* vclzdm */, PPC::VCLZDM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11867 /* vclzh */, PPC::VCLZH, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 11873 /* vclzlsbb */, PPC::VCLZLSBB, Convert__RegGPRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegVRRC }, },
  { 11882 /* vclzw */, PPC::VCLZW, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 11888 /* vcmpbfp */, PPC::VCMPBFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11888 /* vcmpbfp */, PPC::VCMPBFP_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11896 /* vcmpeqfp */, PPC::VCMPEQFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11896 /* vcmpeqfp */, PPC::VCMPEQFP_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11905 /* vcmpequb */, PPC::VCMPEQUB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11905 /* vcmpequb */, PPC::VCMPEQUB_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11914 /* vcmpequd */, PPC::VCMPEQUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11914 /* vcmpequd */, PPC::VCMPEQUD_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11923 /* vcmpequh */, PPC::VCMPEQUH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11923 /* vcmpequh */, PPC::VCMPEQUH_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11932 /* vcmpequq */, PPC::VCMPEQUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11932 /* vcmpequq */, PPC::VCMPEQUQ_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11941 /* vcmpequw */, PPC::VCMPEQUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11941 /* vcmpequw */, PPC::VCMPEQUW_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11950 /* vcmpgefp */, PPC::VCMPGEFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11950 /* vcmpgefp */, PPC::VCMPGEFP_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11959 /* vcmpgtfp */, PPC::VCMPGTFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11959 /* vcmpgtfp */, PPC::VCMPGTFP_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11968 /* vcmpgtsb */, PPC::VCMPGTSB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11968 /* vcmpgtsb */, PPC::VCMPGTSB_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11977 /* vcmpgtsd */, PPC::VCMPGTSD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11977 /* vcmpgtsd */, PPC::VCMPGTSD_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11986 /* vcmpgtsh */, PPC::VCMPGTSH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11986 /* vcmpgtsh */, PPC::VCMPGTSH_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11995 /* vcmpgtsq */, PPC::VCMPGTSQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 11995 /* vcmpgtsq */, PPC::VCMPGTSQ_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12004 /* vcmpgtsw */, PPC::VCMPGTSW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12004 /* vcmpgtsw */, PPC::VCMPGTSW_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12013 /* vcmpgtub */, PPC::VCMPGTUB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12013 /* vcmpgtub */, PPC::VCMPGTUB_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12022 /* vcmpgtud */, PPC::VCMPGTUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12022 /* vcmpgtud */, PPC::VCMPGTUD_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12031 /* vcmpgtuh */, PPC::VCMPGTUH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12031 /* vcmpgtuh */, PPC::VCMPGTUH_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12040 /* vcmpgtuq */, PPC::VCMPGTUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12040 /* vcmpgtuq */, PPC::VCMPGTUQ_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12049 /* vcmpgtuw */, PPC::VCMPGTUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12049 /* vcmpgtuw */, PPC::VCMPGTUW_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12058 /* vcmpneb */, PPC::VCMPNEB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12058 /* vcmpneb */, PPC::VCMPNEB_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12066 /* vcmpneh */, PPC::VCMPNEH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12066 /* vcmpneh */, PPC::VCMPNEH_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12074 /* vcmpnew */, PPC::VCMPNEW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12074 /* vcmpnew */, PPC::VCMPNEW_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12082 /* vcmpnezb */, PPC::VCMPNEZB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12082 /* vcmpnezb */, PPC::VCMPNEZB_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12091 /* vcmpnezh */, PPC::VCMPNEZH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12091 /* vcmpnezh */, PPC::VCMPNEZH_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12100 /* vcmpnezw */, PPC::VCMPNEZW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12100 /* vcmpnezw */, PPC::VCMPNEZW_rec, Convert__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12109 /* vcmpsq */, PPC::VCMPSQ, Convert__RegCRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12116 /* vcmpuq */, PPC::VCMPUQ, Convert__RegCRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12123 /* vcntmbb */, PPC::VCNTMBB, Convert__RegG8RC1_0__RegVRRC1_1__U1Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegVRRC, MCK_U1Imm }, },
  { 12131 /* vcntmbd */, PPC::VCNTMBD, Convert__RegG8RC1_0__RegVRRC1_1__U1Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegVRRC, MCK_U1Imm }, },
  { 12139 /* vcntmbh */, PPC::VCNTMBH, Convert__RegG8RC1_0__RegVRRC1_1__U1Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegVRRC, MCK_U1Imm }, },
  { 12147 /* vcntmbw */, PPC::VCNTMBW, Convert__RegG8RC1_0__RegVRRC1_1__U1Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegVRRC, MCK_U1Imm }, },
  { 12155 /* vctsxs */, PPC::VCTSXS, Convert__RegVRRC1_0__U5Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U5Imm }, },
  { 12162 /* vctuxs */, PPC::VCTUXS, Convert__RegVRRC1_0__U5Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U5Imm }, },
  { 12169 /* vctzb */, PPC::VCTZB, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12175 /* vctzd */, PPC::VCTZD, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12181 /* vctzdm */, PPC::VCTZDM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12188 /* vctzh */, PPC::VCTZH, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12194 /* vctzlsbb */, PPC::VCTZLSBB, Convert__RegGPRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegVRRC }, },
  { 12203 /* vctzw */, PPC::VCTZW, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12209 /* vdivesd */, PPC::VDIVESD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12217 /* vdivesq */, PPC::VDIVESQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12225 /* vdivesw */, PPC::VDIVESW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12233 /* vdiveud */, PPC::VDIVEUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12241 /* vdiveuq */, PPC::VDIVEUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12249 /* vdiveuw */, PPC::VDIVEUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12257 /* vdivsd */, PPC::VDIVSD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12264 /* vdivsq */, PPC::VDIVSQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12271 /* vdivsw */, PPC::VDIVSW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12278 /* vdivud */, PPC::VDIVUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12285 /* vdivuq */, PPC::VDIVUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12292 /* vdivuw */, PPC::VDIVUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12299 /* veqv */, PPC::VEQV, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12304 /* vexpandbm */, PPC::VEXPANDBM, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12314 /* vexpanddm */, PPC::VEXPANDDM, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12324 /* vexpandhm */, PPC::VEXPANDHM, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12334 /* vexpandqm */, PPC::VEXPANDQM, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12344 /* vexpandwm */, PPC::VEXPANDWM, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12354 /* vexptefp */, PPC::VEXPTEFP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12363 /* vextddvlx */, PPC::VEXTDDVLX, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 12373 /* vextddvrx */, PPC::VEXTDDVRX, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 12383 /* vextdubvlx */, PPC::VEXTDUBVLX, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 12394 /* vextdubvrx */, PPC::VEXTDUBVRX, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 12405 /* vextduhvlx */, PPC::VEXTDUHVLX, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 12416 /* vextduhvrx */, PPC::VEXTDUHVRX, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 12427 /* vextduwvlx */, PPC::VEXTDUWVLX, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 12438 /* vextduwvrx */, PPC::VEXTDUWVRX, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegGPRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegGPRC }, },
  { 12449 /* vextractbm */, PPC::VEXTRACTBM, Convert__RegGPRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegVRRC }, },
  { 12460 /* vextractd */, PPC::VEXTRACTD, Convert__RegVRRC1_0__U4Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U4Imm }, },
  { 12470 /* vextractdm */, PPC::VEXTRACTDM, Convert__RegGPRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegVRRC }, },
  { 12481 /* vextracthm */, PPC::VEXTRACTHM, Convert__RegGPRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegVRRC }, },
  { 12492 /* vextractqm */, PPC::VEXTRACTQM, Convert__RegGPRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegVRRC }, },
  { 12503 /* vextractub */, PPC::VEXTRACTUB, Convert__RegVRRC1_0__U4Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U4Imm }, },
  { 12514 /* vextractuh */, PPC::VEXTRACTUH, Convert__RegVRRC1_0__U4Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U4Imm }, },
  { 12525 /* vextractuw */, PPC::VEXTRACTUW, Convert__RegVRRC1_0__U4Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U4Imm }, },
  { 12536 /* vextractwm */, PPC::VEXTRACTWM, Convert__RegGPRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegGPRC, MCK_RegVRRC }, },
  { 12547 /* vextsb2d */, PPC::VEXTSB2D, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12556 /* vextsb2w */, PPC::VEXTSB2W, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12565 /* vextsd2q */, PPC::VEXTSD2Q, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12574 /* vextsh2d */, PPC::VEXTSH2D, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12583 /* vextsh2w */, PPC::VEXTSH2W, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12592 /* vextsw2d */, PPC::VEXTSW2D, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12601 /* vextublx */, PPC::VEXTUBLX, Convert__RegG8RC1_0__RegG8RC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegVRRC }, },
  { 12610 /* vextubrx */, PPC::VEXTUBRX, Convert__RegG8RC1_0__RegG8RC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegVRRC }, },
  { 12619 /* vextuhlx */, PPC::VEXTUHLX, Convert__RegG8RC1_0__RegG8RC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegVRRC }, },
  { 12628 /* vextuhrx */, PPC::VEXTUHRX, Convert__RegG8RC1_0__RegG8RC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegVRRC }, },
  { 12637 /* vextuwlx */, PPC::VEXTUWLX, Convert__RegG8RC1_0__RegG8RC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegVRRC }, },
  { 12646 /* vextuwrx */, PPC::VEXTUWRX, Convert__RegG8RC1_0__RegG8RC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegG8RC, MCK_RegVRRC }, },
  { 12655 /* vgbbd */, PPC::VGBBD, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12661 /* vgnb */, PPC::VGNB, Convert__RegG8RC1_0__RegVRRC1_1__U3Imm1_2, AMFBS_None, { MCK_RegG8RC, MCK_RegVRRC, MCK_U3Imm }, },
  { 12666 /* vinsblx */, PPC::VINSBLX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 12674 /* vinsbrx */, PPC::VINSBRX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 12682 /* vinsbvlx */, PPC::VINSBVLX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegVRRC }, },
  { 12691 /* vinsbvrx */, PPC::VINSBVRX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegVRRC }, },
  { 12700 /* vinsd */, PPC::VINSD, Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegG8RC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegG8RC, MCK_U4Imm }, },
  { 12706 /* vinsdlx */, PPC::VINSDLX, Convert__RegVRRC1_0__Tie0_1_1__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 12714 /* vinsdrx */, PPC::VINSDRX, Convert__RegVRRC1_0__Tie0_1_1__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 12722 /* vinsertb */, PPC::VINSERTB, Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U4Imm }, },
  { 12731 /* vinsertd */, PPC::VINSERTD, Convert__RegVRRC1_0__U4Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U4Imm }, },
  { 12740 /* vinserth */, PPC::VINSERTH, Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U4Imm }, },
  { 12749 /* vinsertw */, PPC::VINSERTW, Convert__RegVRRC1_0__U4Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U4Imm }, },
  { 12758 /* vinshlx */, PPC::VINSHLX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 12766 /* vinshrx */, PPC::VINSHRX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 12774 /* vinshvlx */, PPC::VINSHVLX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegVRRC }, },
  { 12783 /* vinshvrx */, PPC::VINSHVRX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegVRRC }, },
  { 12792 /* vinsw */, PPC::VINSW, Convert__RegVRRC1_0__Tie0_1_1__U4Imm1_2__RegGPRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_U4Imm }, },
  { 12798 /* vinswlx */, PPC::VINSWLX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 12806 /* vinswrx */, PPC::VINSWRX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 12814 /* vinswvlx */, PPC::VINSWVLX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegVRRC }, },
  { 12823 /* vinswvrx */, PPC::VINSWVRX, Convert__RegVRRC1_0__Tie0_1_1__RegGPRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegGPRC, MCK_RegVRRC }, },
  { 12832 /* vlogefp */, PPC::VLOGEFP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 12840 /* vmaddfp */, PPC::VMADDFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12848 /* vmaxfp */, PPC::VMAXFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12855 /* vmaxsb */, PPC::VMAXSB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12862 /* vmaxsd */, PPC::VMAXSD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12869 /* vmaxsh */, PPC::VMAXSH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12876 /* vmaxsw */, PPC::VMAXSW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12883 /* vmaxub */, PPC::VMAXUB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12890 /* vmaxud */, PPC::VMAXUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12897 /* vmaxuh */, PPC::VMAXUH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12904 /* vmaxuw */, PPC::VMAXUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12911 /* vmhaddshs */, PPC::VMHADDSHS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12921 /* vmhraddshs */, PPC::VMHRADDSHS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12932 /* vminfp */, PPC::VMINFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12939 /* vminsb */, PPC::VMINSB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12946 /* vminsd */, PPC::VMINSD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12953 /* vminsh */, PPC::VMINSH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12960 /* vminsw */, PPC::VMINSW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12967 /* vminub */, PPC::VMINUB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12974 /* vminud */, PPC::VMINUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12981 /* vminuh */, PPC::VMINUH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12988 /* vminuw */, PPC::VMINUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 12995 /* vmladduhm */, PPC::VMLADDUHM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13005 /* vmodsd */, PPC::VMODSD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13012 /* vmodsq */, PPC::VMODSQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13019 /* vmodsw */, PPC::VMODSW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13026 /* vmodud */, PPC::VMODUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13033 /* vmoduq */, PPC::VMODUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13040 /* vmoduw */, PPC::VMODUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13047 /* vmr */, PPC::VOR, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13051 /* vmrgew */, PPC::VMRGEW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13058 /* vmrghb */, PPC::VMRGHB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13065 /* vmrghh */, PPC::VMRGHH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13072 /* vmrghw */, PPC::VMRGHW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13079 /* vmrglb */, PPC::VMRGLB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13086 /* vmrglh */, PPC::VMRGLH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13093 /* vmrglw */, PPC::VMRGLW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13100 /* vmrgow */, PPC::VMRGOW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13107 /* vmsumcud */, PPC::VMSUMCUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13116 /* vmsummbm */, PPC::VMSUMMBM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13125 /* vmsumshm */, PPC::VMSUMSHM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13134 /* vmsumshs */, PPC::VMSUMSHS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13143 /* vmsumubm */, PPC::VMSUMUBM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13152 /* vmsumudm */, PPC::VMSUMUDM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13161 /* vmsumuhm */, PPC::VMSUMUHM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13170 /* vmsumuhs */, PPC::VMSUMUHS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13179 /* vmul10cuq */, PPC::VMUL10CUQ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13189 /* vmul10ecuq */, PPC::VMUL10ECUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13200 /* vmul10euq */, PPC::VMUL10EUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13210 /* vmul10uq */, PPC::VMUL10UQ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13219 /* vmulesb */, PPC::VMULESB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13227 /* vmulesd */, PPC::VMULESD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13235 /* vmulesh */, PPC::VMULESH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13243 /* vmulesw */, PPC::VMULESW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13251 /* vmuleub */, PPC::VMULEUB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13259 /* vmuleud */, PPC::VMULEUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13267 /* vmuleuh */, PPC::VMULEUH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13275 /* vmuleuw */, PPC::VMULEUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13283 /* vmulhsd */, PPC::VMULHSD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13291 /* vmulhsw */, PPC::VMULHSW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13299 /* vmulhud */, PPC::VMULHUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13307 /* vmulhuw */, PPC::VMULHUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13315 /* vmulld */, PPC::VMULLD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13322 /* vmulosb */, PPC::VMULOSB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13330 /* vmulosd */, PPC::VMULOSD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13338 /* vmulosh */, PPC::VMULOSH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13346 /* vmulosw */, PPC::VMULOSW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13354 /* vmuloub */, PPC::VMULOUB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13362 /* vmuloud */, PPC::VMULOUD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13370 /* vmulouh */, PPC::VMULOUH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13378 /* vmulouw */, PPC::VMULOUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13386 /* vmuluwm */, PPC::VMULUWM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13394 /* vnand */, PPC::VNAND, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13400 /* vncipher */, PPC::VNCIPHER, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13409 /* vncipherlast */, PPC::VNCIPHERLAST, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13422 /* vnegd */, PPC::VNEGD, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13428 /* vnegw */, PPC::VNEGW, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13434 /* vnmsubfp */, PPC::VNMSUBFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13443 /* vnor */, PPC::VNOR, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13448 /* vnot */, PPC::VNOR, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13453 /* vor */, PPC::VOR, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13457 /* vorc */, PPC::VORC, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13462 /* vpdepd */, PPC::VPDEPD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13469 /* vperm */, PPC::VPERM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13475 /* vpermr */, PPC::VPERMR, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13482 /* vpermxor */, PPC::VPERMXOR, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13491 /* vpextd */, PPC::VPEXTD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13498 /* vpkpx */, PPC::VPKPX, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13504 /* vpksdss */, PPC::VPKSDSS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13512 /* vpksdus */, PPC::VPKSDUS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13520 /* vpkshss */, PPC::VPKSHSS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13528 /* vpkshus */, PPC::VPKSHUS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13536 /* vpkswss */, PPC::VPKSWSS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13544 /* vpkswus */, PPC::VPKSWUS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13552 /* vpkudum */, PPC::VPKUDUM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13560 /* vpkudus */, PPC::VPKUDUS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13568 /* vpkuhum */, PPC::VPKUHUM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13576 /* vpkuhus */, PPC::VPKUHUS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13584 /* vpkuwum */, PPC::VPKUWUM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13592 /* vpkuwus */, PPC::VPKUWUS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13600 /* vpmsumb */, PPC::VPMSUMB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13608 /* vpmsumd */, PPC::VPMSUMD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13616 /* vpmsumh */, PPC::VPMSUMH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13624 /* vpmsumw */, PPC::VPMSUMW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13632 /* vpopcntb */, PPC::VPOPCNTB, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13641 /* vpopcntd */, PPC::VPOPCNTD, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13650 /* vpopcnth */, PPC::VPOPCNTH, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13659 /* vpopcntw */, PPC::VPOPCNTW, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13668 /* vprtybd */, PPC::VPRTYBD, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13676 /* vprtybq */, PPC::VPRTYBQ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13684 /* vprtybw */, PPC::VPRTYBW, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13692 /* vrefp */, PPC::VREFP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13698 /* vrfim */, PPC::VRFIM, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13704 /* vrfin */, PPC::VRFIN, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13710 /* vrfip */, PPC::VRFIP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13716 /* vrfiz */, PPC::VRFIZ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13722 /* vrlb */, PPC::VRLB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13727 /* vrld */, PPC::VRLD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13732 /* vrldmi */, PPC::VRLDMI, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__Tie0_1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13739 /* vrldnm */, PPC::VRLDNM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13746 /* vrlh */, PPC::VRLH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13751 /* vrlq */, PPC::VRLQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13756 /* vrlqmi */, PPC::VRLQMI, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__Tie0_1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13763 /* vrlqnm */, PPC::VRLQNM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13770 /* vrlw */, PPC::VRLW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13775 /* vrlwmi */, PPC::VRLWMI, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__Tie0_1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13782 /* vrlwnm */, PPC::VRLWNM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13789 /* vrsqrtefp */, PPC::VRSQRTEFP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13799 /* vsbox */, PPC::VSBOX, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 13805 /* vsel */, PPC::VSEL, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13810 /* vshasigmad */, PPC::VSHASIGMAD, Convert__RegVRRC1_0__RegVRRC1_1__U1Imm1_2__U4Imm1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm, MCK_U4Imm }, },
  { 13821 /* vshasigmaw */, PPC::VSHASIGMAW, Convert__RegVRRC1_0__RegVRRC1_1__U1Imm1_2__U4Imm1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm, MCK_U4Imm }, },
  { 13832 /* vsl */, PPC::VSL, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13836 /* vslb */, PPC::VSLB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13841 /* vsld */, PPC::VSLD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13846 /* vsldbi */, PPC::VSLDBI, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__U3Imm1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_U3Imm }, },
  { 13853 /* vsldoi */, PPC::VSLDOI, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__U4Imm1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_U4Imm }, },
  { 13860 /* vslh */, PPC::VSLH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13865 /* vslo */, PPC::VSLO, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13870 /* vslq */, PPC::VSLQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13875 /* vslv */, PPC::VSLV, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13880 /* vslw */, PPC::VSLW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13885 /* vspltb */, PPC::VSPLTB, Convert__RegVRRC1_0__U5Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U5Imm }, },
  { 13892 /* vsplth */, PPC::VSPLTH, Convert__RegVRRC1_0__U5Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U5Imm }, },
  { 13899 /* vspltisb */, PPC::VSPLTISB, Convert__RegVRRC1_0__S5Imm1_1, AMFBS_None, { MCK_RegVRRC, MCK_S5Imm }, },
  { 13908 /* vspltish */, PPC::VSPLTISH, Convert__RegVRRC1_0__S5Imm1_1, AMFBS_None, { MCK_RegVRRC, MCK_S5Imm }, },
  { 13917 /* vspltisw */, PPC::VSPLTISW, Convert__RegVRRC1_0__S5Imm1_1, AMFBS_None, { MCK_RegVRRC, MCK_S5Imm }, },
  { 13926 /* vspltw */, PPC::VSPLTW, Convert__RegVRRC1_0__U5Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U5Imm }, },
  { 13933 /* vsr */, PPC::VSR, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13937 /* vsrab */, PPC::VSRAB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13943 /* vsrad */, PPC::VSRAD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13949 /* vsrah */, PPC::VSRAH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13955 /* vsraq */, PPC::VSRAQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13961 /* vsraw */, PPC::VSRAW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13967 /* vsrb */, PPC::VSRB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13972 /* vsrd */, PPC::VSRD, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13977 /* vsrdbi */, PPC::VSRDBI, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__U3Imm1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_U3Imm }, },
  { 13984 /* vsrh */, PPC::VSRH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13989 /* vsro */, PPC::VSRO, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13994 /* vsrq */, PPC::VSRQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 13999 /* vsrv */, PPC::VSRV, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14004 /* vsrw */, PPC::VSRW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14009 /* vstribl */, PPC::VSTRIBL, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14009 /* vstribl */, PPC::VSTRIBL_rec, Convert__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14017 /* vstribr */, PPC::VSTRIBR, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14017 /* vstribr */, PPC::VSTRIBR_rec, Convert__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14025 /* vstrihl */, PPC::VSTRIHL, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14025 /* vstrihl */, PPC::VSTRIHL_rec, Convert__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14033 /* vstrihr */, PPC::VSTRIHR, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14033 /* vstrihr */, PPC::VSTRIHR_rec, Convert__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK__DOT_, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14041 /* vsubcuq */, PPC::VSUBCUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14049 /* vsubcuw */, PPC::VSUBCUW, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14057 /* vsubecuq */, PPC::VSUBECUQ, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14066 /* vsubeuqm */, PPC::VSUBEUQM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2__RegVRRC1_3, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14075 /* vsubfp */, PPC::VSUBFP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14082 /* vsubsbs */, PPC::VSUBSBS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14090 /* vsubshs */, PPC::VSUBSHS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14098 /* vsubsws */, PPC::VSUBSWS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14106 /* vsububm */, PPC::VSUBUBM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14114 /* vsububs */, PPC::VSUBUBS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14122 /* vsubudm */, PPC::VSUBUDM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14130 /* vsubuhm */, PPC::VSUBUHM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14138 /* vsubuhs */, PPC::VSUBUHS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14146 /* vsubuqm */, PPC::VSUBUQM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14154 /* vsubuwm */, PPC::VSUBUWM, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14162 /* vsubuws */, PPC::VSUBUWS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14170 /* vsum2sws */, PPC::VSUM2SWS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14179 /* vsum4sbs */, PPC::VSUM4SBS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14188 /* vsum4shs */, PPC::VSUM4SHS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14197 /* vsum4ubs */, PPC::VSUM4UBS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14206 /* vsumsws */, PPC::VSUMSWS, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14214 /* vucmprhb */, PPC::VUCMPRHB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14223 /* vucmprhh */, PPC::VUCMPRHH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14232 /* vucmprhn */, PPC::VUCMPRHN, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14241 /* vucmprlb */, PPC::VUCMPRLB, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14250 /* vucmprlh */, PPC::VUCMPRLH, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14259 /* vucmprln */, PPC::VUCMPRLN, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14268 /* vupkhpx */, PPC::VUPKHPX, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14276 /* vupkhsb */, PPC::VUPKHSB, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14284 /* vupkhsh */, PPC::VUPKHSH, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14292 /* vupkhsntob */, PPC::VUPKHSNTOB, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14303 /* vupkhsw */, PPC::VUPKHSW, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14311 /* vupkint4tobf16 */, PPC::VUPKINT4TOBF16, Convert__RegVRRC1_0__RegVRRC1_1__U2Imm1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U2Imm }, },
  { 14326 /* vupkint4tofp32 */, PPC::VUPKINT4TOFP32, Convert__RegVRRC1_0__RegVRRC1_1__U3Imm1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U3Imm }, },
  { 14341 /* vupkint8tobf16 */, PPC::VUPKINT8TOBF16, Convert__RegVRRC1_0__RegVRRC1_1__U1Imm1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U1Imm }, },
  { 14356 /* vupkint8tofp32 */, PPC::VUPKINT8TOFP32, Convert__RegVRRC1_0__RegVRRC1_1__U2Imm1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_U2Imm }, },
  { 14371 /* vupklpx */, PPC::VUPKLPX, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14379 /* vupklsb */, PPC::VUPKLSB, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14387 /* vupklsh */, PPC::VUPKLSH, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14395 /* vupklsntob */, PPC::VUPKLSNTOB, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14406 /* vupklsw */, PPC::VUPKLSW, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14414 /* vxor */, PPC::VXOR, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14419 /* wait */, PPC::WAITP10, Convert__imm_95_0__imm_95_0, AMFBS_None, {  }, },
  { 14419 /* wait */, PPC::WAIT, Convert__imm_95_0, AMFBS_None, {  }, },
  { 14419 /* wait */, PPC::WAITP10, Convert__imm_95_0__imm_95_0, AMFBS_None, { MCK_0 }, },
  { 14419 /* wait */, PPC::WAITP10, Convert__imm_95_1__imm_95_0, AMFBS_None, { MCK_1 }, },
  { 14419 /* wait */, PPC::WAIT, Convert__U2Imm1_0, AMFBS_None, { MCK_U2Imm }, },
  { 14419 /* wait */, PPC::WAITP10, Convert__U2Imm1_0__U2Imm1_1, AMFBS_None, { MCK_U2Imm, MCK_U2Imm }, },
  { 14424 /* waitimpl */, PPC::WAIT, Convert__imm_95_2, AMFBS_None, {  }, },
  { 14433 /* waitrsv */, PPC::WAITP10, Convert__imm_95_1__imm_95_0, AMFBS_None, {  }, },
  { 14433 /* waitrsv */, PPC::WAIT, Convert__imm_95_1, AMFBS_None, {  }, },
  { 14441 /* wrtee */, PPC::WRTEE, Convert__RegGPRC1_0, AMFBS_None, { MCK_RegGPRC }, },
  { 14447 /* wrteei */, PPC::WRTEEI, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 14454 /* wsync */, PPC::SYNCP10, Convert__imm_95_1__imm_95_0, AMFBS_None, {  }, },
  { 14460 /* xnop */, PPC::XORI8, Convert__regX0__regX0__imm_95_0, AMFBS_None, {  }, },
  { 14460 /* xnop */, PPC::XORI, Convert__regR0__regR0__imm_95_0, AMFBS_None, {  }, },
  { 14465 /* xor */, PPC::XOR, Convert__RegGPRC1_0__RegGPRC1_1__RegGPRC1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 14465 /* xor */, PPC::XOR_rec, Convert__RegGPRC1_1__RegGPRC1_2__RegGPRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegGPRC, MCK_RegGPRC, MCK_RegGPRC }, },
  { 14469 /* xori */, PPC::XORI, Convert__RegGPRC1_0__RegGPRC1_1__U16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U16Imm }, },
  { 14474 /* xoris */, PPC::XORIS, Convert__RegGPRC1_0__RegGPRC1_1__U16Imm1_2, AMFBS_None, { MCK_RegGPRC, MCK_RegGPRC, MCK_U16Imm }, },
  { 14480 /* xsabsdp */, PPC::XSABSDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14488 /* xsabsqp */, PPC::XSABSQP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14496 /* xsaddaddsuqm */, PPC::XSADDADDSUQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 14509 /* xsaddadduqm */, PPC::XSADDADDUQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 14521 /* xsadddp */, PPC::XSADDDP, Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14529 /* xsaddqp */, PPC::XSADDQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14537 /* xsaddqpo */, PPC::XSADDQPO, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14546 /* xsaddsp */, PPC::XSADDSP, Convert__RegVSSRC1_0__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 14554 /* xsaddsubsuqm */, PPC::XSADDSUBSUQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 14567 /* xsaddsubuqm */, PPC::XSADDSUBUQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 14579 /* xscmpeqdp */, PPC::XSCMPEQDP, Convert__RegVSRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14589 /* xscmpeqqp */, PPC::XSCMPEQQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14599 /* xscmpexpdp */, PPC::XSCMPEXPDP, Convert__RegCRRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14610 /* xscmpexpqp */, PPC::XSCMPEXPQP, Convert__RegCRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14621 /* xscmpgedp */, PPC::XSCMPGEDP, Convert__RegVSRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14631 /* xscmpgeqp */, PPC::XSCMPGEQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14641 /* xscmpgtdp */, PPC::XSCMPGTDP, Convert__RegVSRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14651 /* xscmpgtqp */, PPC::XSCMPGTQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14661 /* xscmpodp */, PPC::XSCMPODP, Convert__RegCRRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14670 /* xscmpoqp */, PPC::XSCMPOQP, Convert__RegCRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14679 /* xscmpudp */, PPC::XSCMPUDP, Convert__RegCRRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14688 /* xscmpuqp */, PPC::XSCMPUQP, Convert__RegCRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14697 /* xscpsgndp */, PPC::XSCPSGNDP, Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14707 /* xscpsgnqp */, PPC::XSCPSGNQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14717 /* xscvdphp */, PPC::XSCVDPHP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14726 /* xscvdpqp */, PPC::XSCVDPQP, Convert__RegVRRC1_0__RegVFRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVFRC }, },
  { 14735 /* xscvdpsp */, PPC::XSCVDPSP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14744 /* xscvdpspn */, PPC::XSCVDPSPN, Convert__RegVSRC1_0__RegVSSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSSRC }, },
  { 14754 /* xscvdpsxds */, PPC::XSCVDPSXDS, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14765 /* xscvdpsxws */, PPC::XSCVDPSXWS, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14776 /* xscvdpuxds */, PPC::XSCVDPUXDS, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14787 /* xscvdpuxws */, PPC::XSCVDPUXWS, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14798 /* xscvhpdp */, PPC::XSCVHPDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14807 /* xscvqpdp */, PPC::XSCVQPDP, Convert__RegVFRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVFRC, MCK_RegVRRC }, },
  { 14816 /* xscvqpdpo */, PPC::XSCVQPDPO, Convert__RegVFRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVFRC, MCK_RegVRRC }, },
  { 14826 /* xscvqpsdz */, PPC::XSCVQPSDZ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14836 /* xscvqpsqz */, PPC::XSCVQPSQZ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14846 /* xscvqpswz */, PPC::XSCVQPSWZ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14856 /* xscvqpudz */, PPC::XSCVQPUDZ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14866 /* xscvqpuqz */, PPC::XSCVQPUQZ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14876 /* xscvqpuwz */, PPC::XSCVQPUWZ, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14886 /* xscvsdqp */, PPC::XSCVSDQP, Convert__RegVRRC1_0__RegVFRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVFRC }, },
  { 14895 /* xscvspdp */, PPC::XSCVSPDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14904 /* xscvspdpn */, PPC::XSCVSPDPN, Convert__RegVSSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSRC }, },
  { 14914 /* xscvsqqp */, PPC::XSCVSQQP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14923 /* xscvsxddp */, PPC::XSCVSXDDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14933 /* xscvsxdsp */, PPC::XSCVSXDSP, Convert__RegVSSRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSFRC }, },
  { 14943 /* xscvudqp */, PPC::XSCVUDQP, Convert__RegVRRC1_0__RegVFRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVFRC }, },
  { 14952 /* xscvuqqp */, PPC::XSCVUQQP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 14961 /* xscvuxddp */, PPC::XSCVUXDDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14971 /* xscvuxdsp */, PPC::XSCVUXDSP, Convert__RegVSSRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSFRC }, },
  { 14981 /* xsdivdp */, PPC::XSDIVDP, Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 14989 /* xsdivqp */, PPC::XSDIVQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 14997 /* xsdivqpo */, PPC::XSDIVQPO, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15006 /* xsdivsp */, PPC::XSDIVSP, Convert__RegVSSRC1_0__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15014 /* xsiexpdp */, PPC::XSIEXPDP, Convert__RegVSRC1_0__RegG8RC1_1__RegG8RC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegG8RC, MCK_RegG8RC }, },
  { 15023 /* xsiexpqp */, PPC::XSIEXPQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVSFRC }, },
  { 15032 /* xsmaddadp */, PPC::XSMADDADP, Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15042 /* xsmaddasp */, PPC::XSMADDASP, Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15052 /* xsmaddmdp */, PPC::XSMADDMDP, Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15062 /* xsmaddmsp */, PPC::XSMADDMSP, Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15072 /* xsmaddqp */, PPC::XSMADDQP, Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15081 /* xsmaddqpo */, PPC::XSMADDQPO, Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15091 /* xsmaxcdp */, PPC::XSMAXCDP, Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15100 /* xsmaxcqp */, PPC::XSMAXCQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15109 /* xsmaxdp */, PPC::XSMAXDP, Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15117 /* xsmaxjdp */, PPC::XSMAXJDP, Convert__RegVSRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15126 /* xsmerge2t1uqm */, PPC::XSMERGE2T1UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15140 /* xsmerge2t2uqm */, PPC::XSMERGE2T2UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15154 /* xsmerge2t3uqm */, PPC::XSMERGE2T3UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15168 /* xsmerge3t1uqm */, PPC::XSMERGE3T1UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15182 /* xsmincdp */, PPC::XSMINCDP, Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15191 /* xsmincqp */, PPC::XSMINCQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15200 /* xsmindp */, PPC::XSMINDP, Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15208 /* xsminjdp */, PPC::XSMINJDP, Convert__RegVSRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15217 /* xsmsubadp */, PPC::XSMSUBADP, Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15227 /* xsmsubasp */, PPC::XSMSUBASP, Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15237 /* xsmsubmdp */, PPC::XSMSUBMDP, Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15247 /* xsmsubmsp */, PPC::XSMSUBMSP, Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15257 /* xsmsubqp */, PPC::XSMSUBQP, Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15266 /* xsmsubqpo */, PPC::XSMSUBQPO, Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15276 /* xsmuldp */, PPC::XSMULDP, Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15284 /* xsmulqp */, PPC::XSMULQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15292 /* xsmulqpo */, PPC::XSMULQPO, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15301 /* xsmulsp */, PPC::XSMULSP, Convert__RegVSSRC1_0__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15309 /* xsnabsdp */, PPC::XSNABSDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15318 /* xsnabsqp */, PPC::XSNABSQP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 15327 /* xsnegdp */, PPC::XSNEGDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15335 /* xsnegqp */, PPC::XSNEGQP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 15343 /* xsnmaddadp */, PPC::XSNMADDADP, Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15354 /* xsnmaddasp */, PPC::XSNMADDASP, Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15365 /* xsnmaddmdp */, PPC::XSNMADDMDP, Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15376 /* xsnmaddmsp */, PPC::XSNMADDMSP, Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15387 /* xsnmaddqp */, PPC::XSNMADDQP, Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15397 /* xsnmaddqpo */, PPC::XSNMADDQPO, Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15408 /* xsnmsubadp */, PPC::XSNMSUBADP, Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15419 /* xsnmsubasp */, PPC::XSNMSUBASP, Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15430 /* xsnmsubmdp */, PPC::XSNMSUBMDP, Convert__RegVSFRC1_0__Tie0_1_1__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15441 /* xsnmsubmsp */, PPC::XSNMSUBMSP, Convert__RegVSSRC1_0__Tie0_1_1__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15452 /* xsnmsubqp */, PPC::XSNMSUBQP, Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15462 /* xsnmsubqpo */, PPC::XSNMSUBQPO, Convert__RegVRRC1_0__Tie0_1_1__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15473 /* xsrdpi */, PPC::XSRDPI, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15480 /* xsrdpic */, PPC::XSRDPIC, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15488 /* xsrdpim */, PPC::XSRDPIM, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15496 /* xsrdpip */, PPC::XSRDPIP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15504 /* xsrdpiz */, PPC::XSRDPIZ, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15512 /* xsrebase2t1uqm */, PPC::XSREBASE2T1UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15527 /* xsrebase2t2uqm */, PPC::XSREBASE2T2UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15542 /* xsrebase2t3uqm */, PPC::XSREBASE2T3UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15557 /* xsrebase2t4uqm */, PPC::XSREBASE2T4UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15572 /* xsrebase3t1uqm */, PPC::XSREBASE3T1UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15587 /* xsrebase3t2uqm */, PPC::XSREBASE3T2UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15602 /* xsrebase3t3uqm */, PPC::XSREBASE3T3UQM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15617 /* xsredp */, PPC::XSREDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15624 /* xsresp */, PPC::XSRESP, Convert__RegVSSRC1_0__RegVSSRC1_1, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15631 /* xsrqpi */, PPC::XSRQPI, Convert__RegVRRC1_1__U1Imm1_0__RegVRRC1_2__U2Imm1_3, AMFBS_None, { MCK_U1Imm, MCK_RegVRRC, MCK_RegVRRC, MCK_U2Imm }, },
  { 15638 /* xsrqpix */, PPC::XSRQPIX, Convert__RegVRRC1_1__U1Imm1_0__RegVRRC1_2__U2Imm1_3, AMFBS_None, { MCK_U1Imm, MCK_RegVRRC, MCK_RegVRRC, MCK_U2Imm }, },
  { 15646 /* xsrqpxp */, PPC::XSRQPXP, Convert__RegVRRC1_1__U1Imm1_0__RegVRRC1_2__U2Imm1_3, AMFBS_None, { MCK_U1Imm, MCK_RegVRRC, MCK_RegVRRC, MCK_U2Imm }, },
  { 15654 /* xsrsp */, PPC::XSRSP, Convert__RegVSSRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSFRC }, },
  { 15660 /* xsrsqrtedp */, PPC::XSRSQRTEDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15671 /* xsrsqrtesp */, PPC::XSRSQRTESP, Convert__RegVSSRC1_0__RegVSSRC1_1, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15682 /* xssqrtdp */, PPC::XSSQRTDP, Convert__RegVSFRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15691 /* xssqrtqp */, PPC::XSSQRTQP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 15700 /* xssqrtqpo */, PPC::XSSQRTQPO, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 15710 /* xssqrtsp */, PPC::XSSQRTSP, Convert__RegVSSRC1_0__RegVSSRC1_1, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15719 /* xssubdp */, PPC::XSSUBDP, Convert__RegVSFRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15727 /* xssubqp */, PPC::XSSUBQP, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15735 /* xssubqpo */, PPC::XSSUBQPO, Convert__RegVRRC1_0__RegVRRC1_1__RegVRRC1_2, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC, MCK_RegVRRC }, },
  { 15744 /* xssubsp */, PPC::XSSUBSP, Convert__RegVSSRC1_0__RegVSSRC1_1__RegVSSRC1_2, AMFBS_None, { MCK_RegVSSRC, MCK_RegVSSRC, MCK_RegVSSRC }, },
  { 15752 /* xstdivdp */, PPC::XSTDIVDP, Convert__RegCRRC1_0__RegVSFRC1_1__RegVSFRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVSFRC, MCK_RegVSFRC }, },
  { 15761 /* xstsqrtdp */, PPC::XSTSQRTDP, Convert__RegCRRC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegVSFRC }, },
  { 15771 /* xststdcdp */, PPC::XSTSTDCDP, Convert__RegCRRC1_0__U7Imm1_2__RegVSFRC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegVSFRC, MCK_U7Imm }, },
  { 15781 /* xststdcqp */, PPC::XSTSTDCQP, Convert__RegCRRC1_0__U7Imm1_2__RegVRRC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegVRRC, MCK_U7Imm }, },
  { 15791 /* xststdcsp */, PPC::XSTSTDCSP, Convert__RegCRRC1_0__U7Imm1_2__RegVSSRC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegVSSRC, MCK_U7Imm }, },
  { 15801 /* xsxexpdp */, PPC::XSXEXPDP, Convert__RegG8RC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegVSFRC }, },
  { 15810 /* xsxexpqp */, PPC::XSXEXPQP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 15819 /* xsxsigdp */, PPC::XSXSIGDP, Convert__RegG8RC1_0__RegVSFRC1_1, AMFBS_None, { MCK_RegG8RC, MCK_RegVSFRC }, },
  { 15828 /* xsxsigqp */, PPC::XSXSIGQP, Convert__RegVRRC1_0__RegVRRC1_1, AMFBS_None, { MCK_RegVRRC, MCK_RegVRRC }, },
  { 15837 /* xvabsdp */, PPC::XVABSDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 15845 /* xvabssp */, PPC::XVABSSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 15853 /* xvadddp */, PPC::XVADDDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15861 /* xvaddsp */, PPC::XVADDSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15869 /* xvadduhm */, PPC::XVADDUHM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15878 /* xvadduwm */, PPC::XVADDUWM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15887 /* xvbf16ger2 */, PPC::XVBF16GER2, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15898 /* xvbf16ger2nn */, PPC::XVBF16GER2NN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15911 /* xvbf16ger2np */, PPC::XVBF16GER2NP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15924 /* xvbf16ger2pn */, PPC::XVBF16GER2PN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15937 /* xvbf16ger2pp */, PPC::XVBF16GER2PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15950 /* xvcmpeqdp */, PPC::XVCMPEQDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15950 /* xvcmpeqdp */, PPC::XVCMPEQDP_rec, Convert__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15960 /* xvcmpeqsp */, PPC::XVCMPEQSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15960 /* xvcmpeqsp */, PPC::XVCMPEQSP_rec, Convert__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15970 /* xvcmpgedp */, PPC::XVCMPGEDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15970 /* xvcmpgedp */, PPC::XVCMPGEDP_rec, Convert__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15980 /* xvcmpgesp */, PPC::XVCMPGESP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15980 /* xvcmpgesp */, PPC::XVCMPGESP_rec, Convert__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15990 /* xvcmpgtdp */, PPC::XVCMPGTDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 15990 /* xvcmpgtdp */, PPC::XVCMPGTDP_rec, Convert__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16000 /* xvcmpgtsp */, PPC::XVCMPGTSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16000 /* xvcmpgtsp */, PPC::XVCMPGTSP_rec, Convert__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK__DOT_, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16010 /* xvcpsgndp */, PPC::XVCPSGNDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16020 /* xvcpsgnsp */, PPC::XVCPSGNSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16030 /* xvcvbf16spn */, PPC::XVCVBF16SPN, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16042 /* xvcvdpsp */, PPC::XVCVDPSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16051 /* xvcvdpsxds */, PPC::XVCVDPSXDS, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16062 /* xvcvdpsxws */, PPC::XVCVDPSXWS, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16073 /* xvcvdpuxds */, PPC::XVCVDPUXDS, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16084 /* xvcvdpuxws */, PPC::XVCVDPUXWS, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16095 /* xvcvhpsp */, PPC::XVCVHPSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16104 /* xvcvspbf16 */, PPC::XVCVSPBF16, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16115 /* xvcvspdp */, PPC::XVCVSPDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16124 /* xvcvsphp */, PPC::XVCVSPHP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16133 /* xvcvspsxds */, PPC::XVCVSPSXDS, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16144 /* xvcvspsxws */, PPC::XVCVSPSXWS, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16155 /* xvcvspuxds */, PPC::XVCVSPUXDS, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16166 /* xvcvspuxws */, PPC::XVCVSPUXWS, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16177 /* xvcvsxddp */, PPC::XVCVSXDDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16187 /* xvcvsxdsp */, PPC::XVCVSXDSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16197 /* xvcvsxwdp */, PPC::XVCVSXWDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16207 /* xvcvsxwsp */, PPC::XVCVSXWSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16217 /* xvcvuxddp */, PPC::XVCVUXDDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16227 /* xvcvuxdsp */, PPC::XVCVUXDSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16237 /* xvcvuxwdp */, PPC::XVCVUXWDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16247 /* xvcvuxwsp */, PPC::XVCVUXWSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16257 /* xvdivdp */, PPC::XVDIVDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16265 /* xvdivsp */, PPC::XVDIVSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16273 /* xvf16ger2 */, PPC::XVF16GER2, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16283 /* xvf16ger2nn */, PPC::XVF16GER2NN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16295 /* xvf16ger2np */, PPC::XVF16GER2NP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16307 /* xvf16ger2pn */, PPC::XVF16GER2PN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16319 /* xvf16ger2pp */, PPC::XVF16GER2PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16331 /* xvf32ger */, PPC::XVF32GER, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16340 /* xvf32gernn */, PPC::XVF32GERNN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16351 /* xvf32gernp */, PPC::XVF32GERNP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16362 /* xvf32gerpn */, PPC::XVF32GERPN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16373 /* xvf32gerpp */, PPC::XVF32GERPP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16384 /* xvf64ger */, PPC::XVF64GER, Convert__RegACCRC1_0__RegVSRpEvenRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC }, },
  { 16393 /* xvf64gernn */, PPC::XVF64GERNN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC }, },
  { 16404 /* xvf64gernp */, PPC::XVF64GERNP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC }, },
  { 16415 /* xvf64gerpn */, PPC::XVF64GERPN, Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC }, },
  { 16426 /* xvf64gerpp */, PPC::XVF64GERPP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRpEvenRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRpEvenRC, MCK_RegVSRC }, },
  { 16437 /* xvi16ger2 */, PPC::XVI16GER2, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16447 /* xvi16ger2pp */, PPC::XVI16GER2PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16459 /* xvi16ger2s */, PPC::XVI16GER2S, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16470 /* xvi16ger2spp */, PPC::XVI16GER2SPP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16483 /* xvi4ger8 */, PPC::XVI4GER8, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16492 /* xvi4ger8pp */, PPC::XVI4GER8PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16503 /* xvi8ger4 */, PPC::XVI8GER4, Convert__RegACCRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16512 /* xvi8ger4pp */, PPC::XVI8GER4PP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16523 /* xvi8ger4spp */, PPC::XVI8GER4SPP, Convert__RegACCRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegACCRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16535 /* xviexpdp */, PPC::XVIEXPDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16544 /* xviexpsp */, PPC::XVIEXPSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16553 /* xvmaddadp */, PPC::XVMADDADP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16563 /* xvmaddasp */, PPC::XVMADDASP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16573 /* xvmaddmdp */, PPC::XVMADDMDP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16583 /* xvmaddmsp */, PPC::XVMADDMSP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16593 /* xvmaxdp */, PPC::XVMAXDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16601 /* xvmaxsp */, PPC::XVMAXSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16609 /* xvmindp */, PPC::XVMINDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16617 /* xvminsp */, PPC::XVMINSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16625 /* xvmovdp */, PPC::XVCPSGNDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16633 /* xvmovsp */, PPC::XVCPSGNSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16641 /* xvmsubadp */, PPC::XVMSUBADP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16651 /* xvmsubasp */, PPC::XVMSUBASP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16661 /* xvmsubmdp */, PPC::XVMSUBMDP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16671 /* xvmsubmsp */, PPC::XVMSUBMSP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16681 /* xvmuldp */, PPC::XVMULDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16689 /* xvmulhsh */, PPC::XVMULHSH, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16698 /* xvmulhsw */, PPC::XVMULHSW, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16707 /* xvmulhuh */, PPC::XVMULHUH, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16716 /* xvmulhuw */, PPC::XVMULHUW, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16725 /* xvmulsp */, PPC::XVMULSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16733 /* xvmuluhm */, PPC::XVMULUHM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16742 /* xvmuluwm */, PPC::XVMULUWM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16751 /* xvnabsdp */, PPC::XVNABSDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16760 /* xvnabssp */, PPC::XVNABSSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16769 /* xvnegdp */, PPC::XVNEGDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16777 /* xvnegsp */, PPC::XVNEGSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16785 /* xvnmaddadp */, PPC::XVNMADDADP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16796 /* xvnmaddasp */, PPC::XVNMADDASP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16807 /* xvnmaddmdp */, PPC::XVNMADDMDP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16818 /* xvnmaddmsp */, PPC::XVNMADDMSP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16829 /* xvnmsubadp */, PPC::XVNMSUBADP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16840 /* xvnmsubasp */, PPC::XVNMSUBASP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16851 /* xvnmsubmdp */, PPC::XVNMSUBMDP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16862 /* xvnmsubmsp */, PPC::XVNMSUBMSP, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16873 /* xvrdpi */, PPC::XVRDPI, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16880 /* xvrdpic */, PPC::XVRDPIC, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16888 /* xvrdpim */, PPC::XVRDPIM, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16896 /* xvrdpip */, PPC::XVRDPIP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16904 /* xvrdpiz */, PPC::XVRDPIZ, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16912 /* xvredp */, PPC::XVREDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16919 /* xvresp */, PPC::XVRESP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16926 /* xvrlw */, PPC::XVRLW, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 16932 /* xvrspi */, PPC::XVRSPI, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16939 /* xvrspic */, PPC::XVRSPIC, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16947 /* xvrspim */, PPC::XVRSPIM, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16955 /* xvrspip */, PPC::XVRSPIP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16963 /* xvrspiz */, PPC::XVRSPIZ, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16971 /* xvrsqrtedp */, PPC::XVRSQRTEDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16982 /* xvrsqrtesp */, PPC::XVRSQRTESP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 16993 /* xvsqrtdp */, PPC::XVSQRTDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17002 /* xvsqrtsp */, PPC::XVSQRTSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17011 /* xvsubdp */, PPC::XVSUBDP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17019 /* xvsubsp */, PPC::XVSUBSP, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17027 /* xvsubuhm */, PPC::XVSUBUHM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17036 /* xvsubuwm */, PPC::XVSUBUWM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17045 /* xvtdivdp */, PPC::XVTDIVDP, Convert__RegCRRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17054 /* xvtdivsp */, PPC::XVTDIVSP, Convert__RegCRRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegCRRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17063 /* xvtlsbb */, PPC::XVTLSBB, Convert__RegCRRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegVSRC }, },
  { 17071 /* xvtsqrtdp */, PPC::XVTSQRTDP, Convert__RegCRRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegVSRC }, },
  { 17081 /* xvtsqrtsp */, PPC::XVTSQRTSP, Convert__RegCRRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegCRRC, MCK_RegVSRC }, },
  { 17091 /* xvtstdcdp */, PPC::XVTSTDCDP, Convert__RegVSRC1_0__U7Imm1_2__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_U7Imm }, },
  { 17101 /* xvtstdcsp */, PPC::XVTSTDCSP, Convert__RegVSRC1_0__U7Imm1_2__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_U7Imm }, },
  { 17111 /* xvxexpdp */, PPC::XVXEXPDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17120 /* xvxexpsp */, PPC::XVXEXPSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17129 /* xvxsigdp */, PPC::XVXSIGDP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17138 /* xvxsigsp */, PPC::XVXSIGSP, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17147 /* xxaes128decp */, PPC::XXAESDECP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_0, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegVSRpRC }, },
  { 17160 /* xxaes128encp */, PPC::XXAESENCP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_0, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegVSRpRC }, },
  { 17173 /* xxaes128genlkp */, PPC::XXAESGENLKP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__imm_95_0, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC }, },
  { 17188 /* xxaes192decp */, PPC::XXAESDECP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_1, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegVSRpRC }, },
  { 17201 /* xxaes192encp */, PPC::XXAESENCP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_1, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegVSRpRC }, },
  { 17214 /* xxaes192genlkp */, PPC::XXAESGENLKP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__imm_95_1, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC }, },
  { 17229 /* xxaes256decp */, PPC::XXAESDECP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_2, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegVSRpRC }, },
  { 17242 /* xxaes256encp */, PPC::XXAESENCP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__imm_95_2, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegVSRpRC }, },
  { 17255 /* xxaes256genlkp */, PPC::XXAESGENLKP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__imm_95_2, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC }, },
  { 17270 /* xxaesdecp */, PPC::XXAESDECP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__U2Imm1_3, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_U2Imm }, },
  { 17280 /* xxaesencp */, PPC::XXAESENCP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__RegVSRpRC1_2__U2Imm1_3, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_U2Imm }, },
  { 17290 /* xxaesgenlkp */, PPC::XXAESGENLKP, Convert__RegVSRpRC1_0__RegVSRpRC1_1__U2Imm1_2, AMFBS_None, { MCK_RegVSRpRC, MCK_RegVSRpRC, MCK_U2Imm }, },
  { 17302 /* xxblendvb */, PPC::XXBLENDVB, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17312 /* xxblendvd */, PPC::XXBLENDVD, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17322 /* xxblendvh */, PPC::XXBLENDVH, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17332 /* xxblendvw */, PPC::XXBLENDVW, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17342 /* xxbrd */, PPC::XXBRD, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17348 /* xxbrh */, PPC::XXBRH, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17354 /* xxbrq */, PPC::XXBRQ, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17360 /* xxbrw */, PPC::XXBRW, Convert__RegVSRC1_0__RegVSRC1_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
  { 17366 /* xxeval */, PPC::XXEVAL, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3__U8Imm1_4, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U8Imm }, },
  { 17373 /* xxextractuw */, PPC::XXEXTRACTUW, Convert__RegVSFRC1_0__RegVSRC1_1__U4Imm1_2, AMFBS_None, { MCK_RegVSFRC, MCK_RegVSRC, MCK_U4Imm }, },
  { 17385 /* xxgenpcvbm */, PPC::XXGENPCVBM, Convert__RegVSRC1_0__RegVRRC1_1__S5Imm1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVRRC, MCK_S5Imm }, },
  { 17396 /* xxgenpcvdm */, PPC::XXGENPCVDM, Convert__RegVSRC1_0__RegVRRC1_1__S5Imm1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVRRC, MCK_S5Imm }, },
  { 17407 /* xxgenpcvhm */, PPC::XXGENPCVHM, Convert__RegVSRC1_0__RegVRRC1_1__S5Imm1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVRRC, MCK_S5Imm }, },
  { 17418 /* xxgenpcvwm */, PPC::XXGENPCVWM, Convert__RegVSRC1_0__RegVRRC1_1__S5Imm1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVRRC, MCK_S5Imm }, },
  { 17429 /* xxgfmul128 */, PPC::XXGFMUL128, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 17440 /* xxgfmul128gcm */, PPC::XXGFMUL128, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_0, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17454 /* xxgfmul128xts */, PPC::XXGFMUL128, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_1, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17468 /* xxinsertw */, PPC::XXINSERTW, Convert__RegVSRC1_0__Tie0_1_1__RegVSRC1_1__U4Imm1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_U4Imm }, },
  { 17478 /* xxland */, PPC::XXLAND, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17485 /* xxlandc */, PPC::XXLANDC, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17493 /* xxleqv */, PPC::XXLEQV, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17500 /* xxlnand */, PPC::XXLNAND, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17508 /* xxlnor */, PPC::XXLNOR, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17515 /* xxlor */, PPC::XXLOR, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17521 /* xxlorc */, PPC::XXLORC, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17528 /* xxlxor */, PPC::XXLXOR, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17535 /* xxmfacc */, PPC::XXMFACC, Convert__RegACCRC1_0__Tie0_1_1, AMFBS_None, { MCK_RegACCRC }, },
  { 17543 /* xxmrghd */, PPC::XXPERMDI, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_0, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17551 /* xxmrghw */, PPC::XXMRGHW, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17559 /* xxmrgld */, PPC::XXPERMDI, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__imm_95_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17567 /* xxmrglw */, PPC::XXMRGLW, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17575 /* xxmtacc */, PPC::XXMTACC, Convert__RegACCRC1_0__Tie0_1_1, AMFBS_None, { MCK_RegACCRC }, },
  { 17583 /* xxmulmul */, PPC::XXMULMUL, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U3Imm1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U3Imm }, },
  { 17592 /* xxmulmulhiadd */, PPC::XXMULMULHIADD, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3__U1Imm1_4__U1Imm1_5, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U1Imm, MCK_U1Imm, MCK_U1Imm }, },
  { 17606 /* xxmulmulloadd */, PPC::XXMULMULLOADD, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3__U1Imm1_4, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U1Imm, MCK_U1Imm }, },
  { 17620 /* xxperm */, PPC::XXPERM, Convert__RegVSRC1_0__RegVSRC1_1__Tie0_1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17627 /* xxpermdi */, PPC::XXPERMDI, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U2Imm1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U2Imm }, },
  { 17636 /* xxpermr */, PPC::XXPERMR, Convert__RegVSRC1_0__RegVSRC1_1__Tie0_1_1__RegVSRC1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17644 /* xxpermx */, PPC::XXPERMX, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3__U3Imm1_4, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U3Imm }, },
  { 17652 /* xxsel */, PPC::XXSEL, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC }, },
  { 17658 /* xxsetaccz */, PPC::XXSETACCZ, Convert__RegACCRC1_0, AMFBS_None, { MCK_RegACCRC }, },
  { 17668 /* xxsldwi */, PPC::XXSLDWI, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U2Imm1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U2Imm }, },
  { 17676 /* xxspltd */, PPC::XXPERMDIs, Convert__RegVSRC1_0__RegVSFRC1_1__imm_95_0, AMFBS_ModernAs, { MCK_RegVSRC, MCK_RegVSFRC, MCK_0 }, },
  { 17676 /* xxspltd */, PPC::XXPERMDIs, Convert__RegVSRC1_0__RegVSFRC1_1__imm_95_3, AMFBS_ModernAs, { MCK_RegVSRC, MCK_RegVSFRC, MCK_1 }, },
  { 17676 /* xxspltd */, PPC::XXPERMDI, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1__imm_95_0, AMFBS_ModernAs, { MCK_RegVSRC, MCK_RegVSRC, MCK_0 }, },
  { 17676 /* xxspltd */, PPC::XXPERMDI, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1__imm_95_3, AMFBS_ModernAs, { MCK_RegVSRC, MCK_RegVSRC, MCK_1 }, },
  { 17684 /* xxsplti32dx */, PPC::XXSPLTI32DX, Convert__RegVSRC1_0__Tie0_1_1__U1Imm1_1__Imm1_2, AMFBS_None, { MCK_RegVSRC, MCK_U1Imm, MCK_Imm }, },
  { 17696 /* xxspltib */, PPC::XXSPLTIB, Convert__RegVSRC1_0__U8Imm1_1, AMFBS_None, { MCK_RegVSRC, MCK_U8Imm }, },
  { 17705 /* xxspltidp */, PPC::XXSPLTIDP, Convert__RegVSRC1_0__Imm1_1, AMFBS_None, { MCK_RegVSRC, MCK_Imm }, },
  { 17715 /* xxspltiw */, PPC::XXSPLTIW, Convert__RegVSRC1_0__Imm1_1, AMFBS_None, { MCK_RegVSRC, MCK_Imm }, },
  { 17724 /* xxspltw */, PPC::XXSPLTW, Convert__RegVSRC1_0__RegVSRC1_1__U2Imm1_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_U2Imm }, },
  { 17732 /* xxssumudm */, PPC::XXSSUMUDM, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 17742 /* xxssumudmc */, PPC::XXSSUMUDMC, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__U1Imm1_3, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 17753 /* xxssumudmcext */, PPC::XXSSUMUDMCEXT, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_2__RegVSRC1_3__U1Imm1_4, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_RegVSRC, MCK_U1Imm }, },
  { 17767 /* xxswapd */, PPC::XXPERMDIs, Convert__RegVSRC1_0__RegVSFRC1_1__imm_95_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSFRC }, },
  { 17767 /* xxswapd */, PPC::XXPERMDI, Convert__RegVSRC1_0__RegVSRC1_1__RegVSRC1_1__imm_95_2, AMFBS_None, { MCK_RegVSRC, MCK_RegVSRC }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned PPCAsmParser::
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
  StringRef Mnemonic = ((PPCOperand &)*Operands[0]).getToken();

  // Process all MnemonicAliases to remap the mnemonic.
  applyMnemonicAliases(Mnemonic, AvailableFeatures, VariantID);

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

    std::string Info;
    if (!getParser().getTargetParser().getTargetOptions().MCNoDeprecatedWarn &&
        MII.getDeprecatedInfo(Inst, getSTI(), Info)) {
      SMLoc Loc = ((PPCOperand &)*Operands[0]).getStartLoc();
      getParser().Warning(Loc, Info, {});
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

static std::string PPCMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool PPCCheckMnemonic(StringRef Mnemonic,
                                const FeatureBitset &AvailableFeatures,
                                unsigned VariantID) {
  // Process all MnemonicAliases to remap the mnemonic.
  applyMnemonicAliases(Mnemonic, AvailableFeatures, VariantID);

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

