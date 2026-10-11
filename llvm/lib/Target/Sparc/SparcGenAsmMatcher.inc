/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: Sparc.td                                                             *|
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
  Feature_Is32BitBit = 10,
  Feature_Is64BitBit = 11,
  Feature_UseSoftMulDivBit = 12,
  Feature_HasV9Bit = 6,
  Feature_HasVISBit = 7,
  Feature_HasVIS2Bit = 8,
  Feature_HasVIS3Bit = 9,
  Feature_HasUA2005Bit = 4,
  Feature_HasUA2007Bit = 5,
  Feature_HasOSA2011Bit = 2,
  Feature_HasCryptoBit = 1,
  Feature_HasCASABit = 0,
  Feature_HasPWRPSRBit = 3,
};

static MCRegister MatchRegisterName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 1 string to match.
    if (Name[0] != 'y')
      break;
    return SP::Y;	 // "y"
  case 2:	 // 86 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 16 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return SP::C0;	 // "c0"
      case '1':	 // 1 string to match.
        return SP::C1;	 // "c1"
      case '2':	 // 2 strings to match.
        return SP::C2;	 // "c2"
      case '3':	 // 1 string to match.
        return SP::C3;	 // "c3"
      case '4':	 // 2 strings to match.
        return SP::C4;	 // "c4"
      case '5':	 // 1 string to match.
        return SP::C5;	 // "c5"
      case '6':	 // 2 strings to match.
        return SP::C6;	 // "c6"
      case '7':	 // 1 string to match.
        return SP::C7;	 // "c7"
      case '8':	 // 2 strings to match.
        return SP::C8;	 // "c8"
      case '9':	 // 1 string to match.
        return SP::C9;	 // "c9"
      case 'q':	 // 1 string to match.
        return SP::CPQ;	 // "cq"
      }
      break;
    case 'f':	 // 20 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 3 strings to match.
        return SP::D0;	 // "f0"
      case '1':	 // 1 string to match.
        return SP::F1;	 // "f1"
      case '2':	 // 2 strings to match.
        return SP::D1;	 // "f2"
      case '3':	 // 1 string to match.
        return SP::F3;	 // "f3"
      case '4':	 // 3 strings to match.
        return SP::D2;	 // "f4"
      case '5':	 // 1 string to match.
        return SP::F5;	 // "f5"
      case '6':	 // 2 strings to match.
        return SP::D3;	 // "f6"
      case '7':	 // 1 string to match.
        return SP::F7;	 // "f7"
      case '8':	 // 3 strings to match.
        return SP::D4;	 // "f8"
      case '9':	 // 1 string to match.
        return SP::F9;	 // "f9"
      case 'p':	 // 1 string to match.
        return SP::I6;	 // "fp"
      case 'q':	 // 1 string to match.
        return SP::FQ;	 // "fq"
      }
      break;
    case 'g':	 // 13 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return SP::G0;	 // "g0"
      case '1':	 // 1 string to match.
        return SP::G1;	 // "g1"
      case '2':	 // 2 strings to match.
        return SP::G2;	 // "g2"
      case '3':	 // 1 string to match.
        return SP::G3;	 // "g3"
      case '4':	 // 2 strings to match.
        return SP::G4;	 // "g4"
      case '5':	 // 1 string to match.
        return SP::G5;	 // "g5"
      case '6':	 // 2 strings to match.
        return SP::G6;	 // "g6"
      case '7':	 // 1 string to match.
        return SP::G7;	 // "g7"
      case 'l':	 // 1 string to match.
        return SP::GL;	 // "gl"
      }
      break;
    case 'i':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return SP::I0;	 // "i0"
      case '1':	 // 1 string to match.
        return SP::I1;	 // "i1"
      case '2':	 // 2 strings to match.
        return SP::I2;	 // "i2"
      case '3':	 // 1 string to match.
        return SP::I3;	 // "i3"
      case '4':	 // 2 strings to match.
        return SP::I4;	 // "i4"
      case '5':	 // 1 string to match.
        return SP::I5;	 // "i5"
      case '6':	 // 1 string to match.
        return SP::I6_I7;	 // "i6"
      case '7':	 // 1 string to match.
        return SP::I7;	 // "i7"
      }
      break;
    case 'l':	 // 12 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return SP::L0;	 // "l0"
      case '1':	 // 1 string to match.
        return SP::L1;	 // "l1"
      case '2':	 // 2 strings to match.
        return SP::L2;	 // "l2"
      case '3':	 // 1 string to match.
        return SP::L3;	 // "l3"
      case '4':	 // 2 strings to match.
        return SP::L4;	 // "l4"
      case '5':	 // 1 string to match.
        return SP::L5;	 // "l5"
      case '6':	 // 2 strings to match.
        return SP::L6;	 // "l6"
      case '7':	 // 1 string to match.
        return SP::L7;	 // "l7"
      }
      break;
    case 'o':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return SP::O0;	 // "o0"
      case '1':	 // 1 string to match.
        return SP::O1;	 // "o1"
      case '2':	 // 2 strings to match.
        return SP::O2;	 // "o2"
      case '3':	 // 1 string to match.
        return SP::O3;	 // "o3"
      case '4':	 // 2 strings to match.
        return SP::O4;	 // "o4"
      case '5':	 // 1 string to match.
        return SP::O5;	 // "o5"
      case '6':	 // 1 string to match.
        return SP::O6_O7;	 // "o6"
      case '7':	 // 1 string to match.
        return SP::O7;	 // "o7"
      }
      break;
    case 's':	 // 1 string to match.
      if (Name[1] != 'p')
        break;
      return SP::O6;	 // "sp"
    case 't':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'l':	 // 1 string to match.
        return SP::TL;	 // "tl"
      case 't':	 // 1 string to match.
        return SP::TT;	 // "tt"
      }
      break;
    }
    break;
  case 3:	 // 106 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 35 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 15 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return SP::C10;	 // "c10"
        case '1':	 // 1 string to match.
          return SP::C11;	 // "c11"
        case '2':	 // 2 strings to match.
          return SP::C12;	 // "c12"
        case '3':	 // 1 string to match.
          return SP::C13;	 // "c13"
        case '4':	 // 2 strings to match.
          return SP::C14;	 // "c14"
        case '5':	 // 1 string to match.
          return SP::C15;	 // "c15"
        case '6':	 // 2 strings to match.
          return SP::C16;	 // "c16"
        case '7':	 // 1 string to match.
          return SP::C17;	 // "c17"
        case '8':	 // 2 strings to match.
          return SP::C18;	 // "c18"
        case '9':	 // 1 string to match.
          return SP::C19;	 // "c19"
        }
        break;
      case '2':	 // 15 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return SP::C20;	 // "c20"
        case '1':	 // 1 string to match.
          return SP::C21;	 // "c21"
        case '2':	 // 2 strings to match.
          return SP::C22;	 // "c22"
        case '3':	 // 1 string to match.
          return SP::C23;	 // "c23"
        case '4':	 // 2 strings to match.
          return SP::C24;	 // "c24"
        case '5':	 // 1 string to match.
          return SP::C25;	 // "c25"
        case '6':	 // 2 strings to match.
          return SP::C26;	 // "c26"
        case '7':	 // 1 string to match.
          return SP::C27;	 // "c27"
        case '8':	 // 2 strings to match.
          return SP::C28;	 // "c28"
        case '9':	 // 1 string to match.
          return SP::C29;	 // "c29"
        }
        break;
      case '3':	 // 3 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return SP::C30;	 // "c30"
        case '1':	 // 1 string to match.
          return SP::C31;	 // "c31"
        }
        break;
      case 's':	 // 1 string to match.
        if (Name[2] != 'r')
          break;
        return SP::CPSR;	 // "csr"
      case 'w':	 // 1 string to match.
        if (Name[2] != 'p')
          break;
        return SP::CWP;	 // "cwp"
      }
      break;
    case 'f':	 // 63 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 17 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return SP::D5;	 // "f10"
        case '1':	 // 1 string to match.
          return SP::F11;	 // "f11"
        case '2':	 // 3 strings to match.
          return SP::D6;	 // "f12"
        case '3':	 // 1 string to match.
          return SP::F13;	 // "f13"
        case '4':	 // 2 strings to match.
          return SP::D7;	 // "f14"
        case '5':	 // 1 string to match.
          return SP::F15;	 // "f15"
        case '6':	 // 3 strings to match.
          return SP::D8;	 // "f16"
        case '7':	 // 1 string to match.
          return SP::F17;	 // "f17"
        case '8':	 // 2 strings to match.
          return SP::D9;	 // "f18"
        case '9':	 // 1 string to match.
          return SP::F19;	 // "f19"
        }
        break;
      case '2':	 // 18 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 3 strings to match.
          return SP::D10;	 // "f20"
        case '1':	 // 1 string to match.
          return SP::F21;	 // "f21"
        case '2':	 // 2 strings to match.
          return SP::D11;	 // "f22"
        case '3':	 // 1 string to match.
          return SP::F23;	 // "f23"
        case '4':	 // 3 strings to match.
          return SP::D12;	 // "f24"
        case '5':	 // 1 string to match.
          return SP::F25;	 // "f25"
        case '6':	 // 2 strings to match.
          return SP::D13;	 // "f26"
        case '7':	 // 1 string to match.
          return SP::F27;	 // "f27"
        case '8':	 // 3 strings to match.
          return SP::D14;	 // "f28"
        case '9':	 // 1 string to match.
          return SP::F29;	 // "f29"
        }
        break;
      case '3':	 // 9 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return SP::D15;	 // "f30"
        case '1':	 // 1 string to match.
          return SP::F31;	 // "f31"
        case '2':	 // 2 strings to match.
          return SP::D16;	 // "f32"
        case '4':	 // 1 string to match.
          return SP::D17;	 // "f34"
        case '6':	 // 2 strings to match.
          return SP::D18;	 // "f36"
        case '8':	 // 1 string to match.
          return SP::D19;	 // "f38"
        }
        break;
      case '4':	 // 8 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return SP::D20;	 // "f40"
        case '2':	 // 1 string to match.
          return SP::D21;	 // "f42"
        case '4':	 // 2 strings to match.
          return SP::D22;	 // "f44"
        case '6':	 // 1 string to match.
          return SP::D23;	 // "f46"
        case '8':	 // 2 strings to match.
          return SP::D24;	 // "f48"
        }
        break;
      case '5':	 // 7 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return SP::D25;	 // "f50"
        case '2':	 // 2 strings to match.
          return SP::D26;	 // "f52"
        case '4':	 // 1 string to match.
          return SP::D27;	 // "f54"
        case '6':	 // 2 strings to match.
          return SP::D28;	 // "f56"
        case '8':	 // 1 string to match.
          return SP::D29;	 // "f58"
        }
        break;
      case '6':	 // 3 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return SP::D30;	 // "f60"
        case '2':	 // 1 string to match.
          return SP::D31;	 // "f62"
        }
        break;
      case 's':	 // 1 string to match.
        if (Name[2] != 'r')
          break;
        return SP::FSR;	 // "fsr"
      }
      break;
    case 'i':	 // 1 string to match.
      if (memcmp(Name.data()+1, "cc", 2) != 0)
        break;
      return SP::ICC;	 // "icc"
    case 'p':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'i':	 // 1 string to match.
        if (Name[2] != 'l')
          break;
        return SP::PIL;	 // "pil"
      case 's':	 // 1 string to match.
        if (Name[2] != 'r')
          break;
        return SP::PSR;	 // "psr"
      }
      break;
    case 't':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case 'b':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 1 string to match.
          return SP::TBA;	 // "tba"
        case 'r':	 // 1 string to match.
          return SP::TBR;	 // "tbr"
        }
        break;
      case 'p':	 // 1 string to match.
        if (Name[2] != 'c')
          break;
        return SP::TPC;	 // "tpc"
      }
      break;
    case 'v':	 // 1 string to match.
      if (memcmp(Name.data()+1, "er", 2) != 0)
        break;
      return SP::VER;	 // "ver"
    case 'w':	 // 1 string to match.
      if (memcmp(Name.data()+1, "im", 2) != 0)
        break;
      return SP::WIM;	 // "wim"
    }
    break;
  case 4:	 // 15 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 9 strings to match.
      if (memcmp(Name.data()+1, "sr", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case '1':	 // 1 string to match.
        return SP::ASR1;	 // "asr1"
      case '2':	 // 1 string to match.
        return SP::ASR2;	 // "asr2"
      case '3':	 // 1 string to match.
        return SP::ASR3;	 // "asr3"
      case '4':	 // 1 string to match.
        return SP::ASR4;	 // "asr4"
      case '5':	 // 1 string to match.
        return SP::ASR5;	 // "asr5"
      case '6':	 // 1 string to match.
        return SP::ASR6;	 // "asr6"
      case '7':	 // 1 string to match.
        return SP::ASR7;	 // "asr7"
      case '8':	 // 1 string to match.
        return SP::ASR8;	 // "asr8"
      case '9':	 // 1 string to match.
        return SP::ASR9;	 // "asr9"
      }
      break;
    case 'f':	 // 4 strings to match.
      if (memcmp(Name.data()+1, "cc", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 1 string to match.
        return SP::FCC0;	 // "fcc0"
      case '1':	 // 1 string to match.
        return SP::FCC1;	 // "fcc1"
      case '2':	 // 1 string to match.
        return SP::FCC2;	 // "fcc2"
      case '3':	 // 1 string to match.
        return SP::FCC3;	 // "fcc3"
      }
      break;
    case 't':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'i':	 // 1 string to match.
        if (memcmp(Name.data()+2, "ck", 2) != 0)
          break;
        return SP::TICK;	 // "tick"
      case 'n':	 // 1 string to match.
        if (memcmp(Name.data()+2, "pc", 2) != 0)
          break;
        return SP::TNPC;	 // "tnpc"
      }
      break;
    }
    break;
  case 5:	 // 22 strings to match.
    if (memcmp(Name.data()+0, "asr", 3) != 0)
      break;
    switch (Name[3]) {
    default: break;
    case '1':	 // 10 strings to match.
      switch (Name[4]) {
      default: break;
      case '0':	 // 1 string to match.
        return SP::ASR10;	 // "asr10"
      case '1':	 // 1 string to match.
        return SP::ASR11;	 // "asr11"
      case '2':	 // 1 string to match.
        return SP::ASR12;	 // "asr12"
      case '3':	 // 1 string to match.
        return SP::ASR13;	 // "asr13"
      case '4':	 // 1 string to match.
        return SP::ASR14;	 // "asr14"
      case '5':	 // 1 string to match.
        return SP::ASR15;	 // "asr15"
      case '6':	 // 1 string to match.
        return SP::ASR16;	 // "asr16"
      case '7':	 // 1 string to match.
        return SP::ASR17;	 // "asr17"
      case '8':	 // 1 string to match.
        return SP::ASR18;	 // "asr18"
      case '9':	 // 1 string to match.
        return SP::ASR19;	 // "asr19"
      }
      break;
    case '2':	 // 10 strings to match.
      switch (Name[4]) {
      default: break;
      case '0':	 // 1 string to match.
        return SP::ASR20;	 // "asr20"
      case '1':	 // 1 string to match.
        return SP::ASR21;	 // "asr21"
      case '2':	 // 1 string to match.
        return SP::ASR22;	 // "asr22"
      case '3':	 // 1 string to match.
        return SP::ASR23;	 // "asr23"
      case '4':	 // 1 string to match.
        return SP::ASR24;	 // "asr24"
      case '5':	 // 1 string to match.
        return SP::ASR25;	 // "asr25"
      case '6':	 // 1 string to match.
        return SP::ASR26;	 // "asr26"
      case '7':	 // 1 string to match.
        return SP::ASR27;	 // "asr27"
      case '8':	 // 1 string to match.
        return SP::ASR28;	 // "asr28"
      case '9':	 // 1 string to match.
        return SP::ASR29;	 // "asr29"
      }
      break;
    case '3':	 // 2 strings to match.
      switch (Name[4]) {
      default: break;
      case '0':	 // 1 string to match.
        return SP::ASR30;	 // "asr30"
      case '1':	 // 1 string to match.
        return SP::ASR31;	 // "asr31"
      }
      break;
    }
    break;
  case 6:	 // 3 strings to match.
    switch (Name[0]) {
    default: break;
    case 'p':	 // 1 string to match.
      if (memcmp(Name.data()+1, "state", 5) != 0)
        break;
      return SP::PSTATE;	 // "pstate"
    case 't':	 // 1 string to match.
      if (memcmp(Name.data()+1, "state", 5) != 0)
        break;
      return SP::TSTATE;	 // "tstate"
    case 'w':	 // 1 string to match.
      if (memcmp(Name.data()+1, "state", 5) != 0)
        break;
      return SP::WSTATE;	 // "wstate"
    }
    break;
  case 7:	 // 1 string to match.
    if (memcmp(Name.data()+0, "cansave", 7) != 0)
      break;
    return SP::CANSAVE;	 // "cansave"
  case 8:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(Name.data()+1, "leanwin", 7) != 0)
        break;
      return SP::CLEANWIN;	 // "cleanwin"
    case 'o':	 // 1 string to match.
      if (memcmp(Name.data()+1, "therwin", 7) != 0)
        break;
      return SP::OTHERWIN;	 // "otherwin"
    }
    break;
  case 10:	 // 1 string to match.
    if (memcmp(Name.data()+0, "canrestore", 10) != 0)
      break;
    return SP::CANRESTORE;	 // "canrestore"
  }
  return SP::NoRegister;
}

static MCRegister MatchRegisterAltName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 1 string to match.
    if (memcmp(Name.data()+0, "pc", 2) != 0)
      break;
    return SP::ASR5;	 // "pc"
  case 3:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(Name.data()+1, "si", 2) != 0)
        break;
      return SP::ASR3;	 // "asi"
    case 'c':	 // 1 string to match.
      if (memcmp(Name.data()+1, "cr", 2) != 0)
        break;
      return SP::ASR2;	 // "ccr"
    }
    break;
  case 4:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 1 string to match.
      if (memcmp(Name.data()+1, "prs", 3) != 0)
        break;
      return SP::ASR6;	 // "fprs"
    case 't':	 // 1 string to match.
      if (memcmp(Name.data()+1, "ick", 3) != 0)
        break;
      return SP::ASR4;	 // "tick"
    }
    break;
  }
  return SP::NoRegister;
}

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_Is32BitBit: return "";
  case Feature_Is64BitBit: return "";
  case Feature_UseSoftMulDivBit: return "";
  case Feature_HasV9Bit: return "";
  case Feature_HasVISBit: return "";
  case Feature_HasVIS2Bit: return "";
  case Feature_HasVIS3Bit: return "";
  case Feature_HasUA2005Bit: return "";
  case Feature_HasUA2007Bit: return "";
  case Feature_HasOSA2011Bit: return "";
  case Feature_HasCryptoBit: return "";
  case Feature_HasCASABit: return "";
  case Feature_HasPWRPSRBit: return "";
  default: return "(unknown)";
  }
}

#endif // GET_SUBTARGET_FEATURE_NAME


#ifdef GET_MATCHER_IMPLEMENTATION
#undef GET_MATCHER_IMPLEMENTATION

static void applyMnemonicAliases(StringRef &Mnemonic, const FeatureBitset &Features, unsigned VariantID) {
  switch (Mnemonic.size()) {
  default: break;
  case 3:	 // 4 strings to match.
    switch (Mnemonic[0]) {
    default: break;
    case 'l':	 // 2 strings to match.
      switch (Mnemonic[1]) {
      default: break;
      case 'd':	 // 1 string to match.
        if (Mnemonic[2] != 'n')
          break;
        if (Features.test(Feature_Is32BitBit))	 // "ldn"
          Mnemonic = "ld";
        else if (Features.test(Feature_Is64BitBit))
          Mnemonic = "ldx";
        return;
      case 'z':	 // 1 string to match.
        if (Mnemonic[2] != 'd')
          break;
        Mnemonic = "lzcnt";	 // "lzd"
        return;
      }
      break;
    case 's':	 // 2 strings to match.
      if (Mnemonic[1] != 't')
        break;
      switch (Mnemonic[2]) {
      default: break;
      case 'n':	 // 1 string to match.
        if (Features.test(Feature_Is32BitBit))	 // "stn"
          Mnemonic = "st";
        else if (Features.test(Feature_Is64BitBit))
          Mnemonic = "stx";
        return;
      case 'w':	 // 1 string to match.
        if (Features.test(Feature_HasV9Bit))	 // "stw"
          Mnemonic = "st";
        return;
      }
      break;
    }
    break;
  case 4:	 // 17 strings to match.
    switch (Mnemonic[0]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "ddc", 3) != 0)
        break;
      if (Features.test(Feature_HasV9Bit))	 // "addc"
        Mnemonic = "addx";
      return;
    case 'c':	 // 2 strings to match.
      switch (Mnemonic[1]) {
      default: break;
      case 'a':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "sn", 2) != 0)
          break;
        if (Features.test(Feature_Is32BitBit))	 // "casn"
          Mnemonic = "cas";
        else if (Features.test(Feature_Is64BitBit))
          Mnemonic = "casx";
        return;
      case 'l':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "rn", 2) != 0)
          break;
        if (Features.test(Feature_Is32BitBit))	 // "clrn"
          Mnemonic = "clr";
        else if (Features.test(Feature_Is64BitBit))
          Mnemonic = "clrx";
        return;
      }
      break;
    case 'l':	 // 2 strings to match.
      if (Mnemonic[1] != 'd')
        break;
      switch (Mnemonic[2]) {
      default: break;
      case 'n':	 // 1 string to match.
        if (Mnemonic[3] != 'a')
          break;
        if (Features.test(Feature_Is32BitBit))	 // "ldna"
          Mnemonic = "lda";
        else if (Features.test(Feature_Is64BitBit))
          Mnemonic = "ldxa";
        return;
      case 'u':	 // 1 string to match.
        if (Mnemonic[3] != 'w')
          break;
        if (Features.test(Feature_HasV9Bit))	 // "lduw"
          Mnemonic = "ld";
        return;
      }
      break;
    case 's':	 // 12 strings to match.
      switch (Mnemonic[1]) {
      default: break;
      case 'l':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "ln", 2) != 0)
          break;
        if (Features.test(Feature_Is32BitBit))	 // "slln"
          Mnemonic = "sll";
        else if (Features.test(Feature_Is64BitBit))
          Mnemonic = "sllx";
        return;
      case 'r':	 // 2 strings to match.
        switch (Mnemonic[2]) {
        default: break;
        case 'a':	 // 1 string to match.
          if (Mnemonic[3] != 'n')
            break;
          if (Features.test(Feature_Is32BitBit))	 // "sran"
            Mnemonic = "sra";
          else if (Features.test(Feature_Is64BitBit))
            Mnemonic = "srax";
          return;
        case 'l':	 // 1 string to match.
          if (Mnemonic[3] != 'n')
            break;
          if (Features.test(Feature_Is32BitBit))	 // "srln"
            Mnemonic = "srl";
          else if (Features.test(Feature_Is64BitBit))
            Mnemonic = "srlx";
          return;
        }
        break;
      case 't':	 // 8 strings to match.
        switch (Mnemonic[2]) {
        default: break;
        case 'n':	 // 1 string to match.
          if (Mnemonic[3] != 'a')
            break;
          if (Features.test(Feature_Is32BitBit))	 // "stna"
            Mnemonic = "sta";
          else if (Features.test(Feature_Is64BitBit))
            Mnemonic = "stxa";
          return;
        case 's':	 // 3 strings to match.
          switch (Mnemonic[3]) {
          default: break;
          case 'b':	 // 1 string to match.
            Mnemonic = "stb";	 // "stsb"
            return;
          case 'h':	 // 1 string to match.
            Mnemonic = "sth";	 // "stsh"
            return;
          case 'w':	 // 1 string to match.
            if (Features.test(Feature_HasV9Bit))	 // "stsw"
              Mnemonic = "st";
            return;
          }
          break;
        case 'u':	 // 3 strings to match.
          switch (Mnemonic[3]) {
          default: break;
          case 'b':	 // 1 string to match.
            Mnemonic = "stb";	 // "stub"
            return;
          case 'h':	 // 1 string to match.
            Mnemonic = "sth";	 // "stuh"
            return;
          case 'w':	 // 1 string to match.
            if (Features.test(Feature_HasV9Bit))	 // "stuw"
              Mnemonic = "st";
            return;
          }
          break;
        case 'w':	 // 1 string to match.
          if (Mnemonic[3] != 'a')
            break;
          if (Features.test(Feature_HasV9Bit))	 // "stwa"
            Mnemonic = "sta";
          return;
        }
        break;
      case 'u':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "bc", 2) != 0)
          break;
        if (Features.test(Feature_HasV9Bit))	 // "subc"
          Mnemonic = "subx";
        return;
      }
      break;
    }
    break;
  case 5:	 // 8 strings to match.
    switch (Mnemonic[0]) {
    default: break;
    case 'l':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "duwa", 4) != 0)
        break;
      if (Features.test(Feature_HasV9Bit))	 // "lduwa"
        Mnemonic = "lda";
      return;
    case 's':	 // 7 strings to match.
      switch (Mnemonic[1]) {
      default: break;
      case 'e':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "tuw", 3) != 0)
          break;
        if (Features.test(Feature_HasV9Bit))	 // "setuw"
          Mnemonic = "set";
        return;
      case 't':	 // 6 strings to match.
        switch (Mnemonic[2]) {
        default: break;
        case 's':	 // 3 strings to match.
          switch (Mnemonic[3]) {
          default: break;
          case 'b':	 // 1 string to match.
            if (Mnemonic[4] != 'a')
              break;
            Mnemonic = "stba";	 // "stsba"
            return;
          case 'h':	 // 1 string to match.
            if (Mnemonic[4] != 'a')
              break;
            Mnemonic = "stha";	 // "stsha"
            return;
          case 'w':	 // 1 string to match.
            if (Mnemonic[4] != 'a')
              break;
            if (Features.test(Feature_HasV9Bit))	 // "stswa"
              Mnemonic = "sta";
            return;
          }
          break;
        case 'u':	 // 3 strings to match.
          switch (Mnemonic[3]) {
          default: break;
          case 'b':	 // 1 string to match.
            if (Mnemonic[4] != 'a')
              break;
            Mnemonic = "stba";	 // "stuba"
            return;
          case 'h':	 // 1 string to match.
            if (Mnemonic[4] != 'a')
              break;
            Mnemonic = "stha";	 // "stuha"
            return;
          case 'w':	 // 1 string to match.
            if (Mnemonic[4] != 'a')
              break;
            if (Features.test(Feature_HasV9Bit))	 // "stuwa"
              Mnemonic = "sta";
            return;
          }
          break;
        }
        break;
      }
      break;
    }
    break;
  case 6:	 // 4 strings to match.
    switch (Mnemonic[0]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "ddccc", 5) != 0)
        break;
      if (Features.test(Feature_HasV9Bit))	 // "addccc"
        Mnemonic = "addxcc";
      return;
    case 'i':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "flush", 5) != 0)
        break;
      Mnemonic = "flush";	 // "iflush"
      return;
    case 'r':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "eturn", 5) != 0)
        break;
      if (Features.test(Feature_HasV9Bit))	 // "return"
        Mnemonic = "rett";
      return;
    case 's':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+1, "ubccc", 5) != 0)
        break;
      if (Features.test(Feature_HasV9Bit))	 // "subccc"
        Mnemonic = "subxcc";
      return;
    }
    break;
  case 7:	 // 1 string to match.
    if (memcmp(Mnemonic.data()+0, "illtrap", 7) != 0)
      break;
    Mnemonic = "unimp";	 // "illtrap"
    return;
  }
}

enum {
  Tie0_1_1,
  Tie0_3_3,
  Tie0_5_5,
};

static const uint8_t TiedAsmOperandTable[][3] = {
  /* Tie0_1_1 */ { 0, 1, 1 },
  /* Tie0_3_3 */ { 0, 3, 3 },
  /* Tie0_5_5 */ { 0, 5, 5 },
};

namespace {
enum OperatorConversionKind {
  CVT_Done,
  CVT_Reg,
  CVT_Tied,
  CVT_95_Reg,
  CVT_95_addImmOperands,
  CVT_95_addTailRelocSymOperands,
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
  CVT_imm_95_7,
  CVT_regG0,
  CVT_imm_95_15,
  CVT_95_addCallTargetOperands,
  CVT_regO7,
  CVT_95_addMEMriOperands,
  CVT_95_addMEMrrOperands,
  CVT_imm_95_128,
  CVT_95_addASITagOperands,
  CVT_imm_95_136,
  CVT_regFCC0,
  CVT_95_addMembarTagOperands,
  CVT_regASR27,
  CVT_95_addPrefetchTagOperands,
  CVT_95_addShiftAmtImm5Operands,
  CVT_95_addShiftAmtImm6Operands,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Reg1_2__Reg1_0__Reg1_1,
  Convert__Reg1_2__Reg1_0__Imm1_1,
  Convert__Reg1_2__Reg1_0__Reg1_1__TailRelocSymAdd_TLS1_3,
  Convert__Reg1_2__Reg1_1__Imm1_0,
  Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2,
  Convert__Reg1_3__Reg1_0__Reg1_1__Imm1_2,
  Convert_NoOperands,
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
  Convert__Imm1_2__Imm1_0__Reg1_1,
  Convert__Imm1_3__Imm1_0__Reg1_2,
  Convert__Imm1_4__Imm1_0__Reg1_3,
  Convert__Imm1_1__imm_95_1__Reg1_0,
  Convert__Imm1_2__imm_95_1__Reg1_1,
  Convert__Imm1_3__imm_95_1__Reg1_2,
  Convert__Imm1_1__imm_95_7__Reg1_0,
  Convert__Imm1_2__imm_95_7__Reg1_1,
  Convert__Imm1_3__imm_95_7__Reg1_2,
  Convert__Imm1_1__imm_95_6__Reg1_0,
  Convert__Imm1_2__imm_95_6__Reg1_1,
  Convert__Imm1_3__imm_95_6__Reg1_2,
  Convert__Imm1_1__imm_95_2__Reg1_0,
  Convert__Imm1_2__imm_95_2__Reg1_1,
  Convert__Imm1_3__imm_95_2__Reg1_2,
  Convert__Imm1_1__imm_95_3__Reg1_0,
  Convert__Imm1_2__imm_95_3__Reg1_1,
  Convert__Imm1_3__imm_95_3__Reg1_2,
  Convert__Imm1_1__imm_95_5__Reg1_0,
  Convert__Imm1_2__imm_95_5__Reg1_1,
  Convert__Imm1_3__imm_95_5__Reg1_2,
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
  Convert__CallTarget1_0,
  Convert__regO7__MEMri2_0,
  Convert__regO7__MEMrr2_0,
  Convert__CallTarget1_0__Imm1_1,
  Convert__CallTarget1_0__TailRelocSymCall_TLS1_1,
  Convert__MEMri2_0__Imm1_1,
  Convert__MEMrr2_0__Imm1_1,
  Convert__Reg1_4__Reg1_1__Reg1_3__Tie0_5_5__imm_95_128,
  Convert__Reg1_5__Reg1_1__Reg1_4__Tie0_1_1,
  Convert__Reg1_5__Reg1_1__Reg1_4__Tie0_1_1__ASITag1_3,
  Convert__Reg1_4__Reg1_1__Reg1_3__Tie0_5_5__imm_95_136,
  Convert__Reg1_0__regG0__regG0,
  Convert__MEMri2_1__regG0,
  Convert__MEMrr2_1__regG0,
  Convert__Reg1_0,
  Convert__regG0__Reg1_0__Reg1_1,
  Convert__regG0__Reg1_0__Imm1_1,
  Convert__Imm1_3__Imm1_0__Reg1_1__Reg1_2,
  Convert__Imm1_3__Imm1_0__Reg1_1__Imm1_2,
  Convert__Imm1_2__imm_95_13__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_13__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_5__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_5__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_1__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_1__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_10__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_10__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_11__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_11__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_12__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_12__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_3__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_3__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_2__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_2__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_4__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_4__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_9__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_9__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_6__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_6__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_14__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_14__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_15__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_15__Reg1_0__Imm1_1,
  Convert__Imm1_2__imm_95_7__Reg1_0__Reg1_1,
  Convert__Imm1_2__imm_95_7__Reg1_0__Imm1_1,
  Convert__Reg1_0__Reg1_0__imm_95_1,
  Convert__Reg1_1__Reg1_0,
  Convert__Imm1_1__imm_95_8__Reg1_0,
  Convert__Imm1_2__imm_95_8__Reg1_1,
  Convert__Imm1_3__imm_95_8__Reg1_2,
  Convert__Imm1_1__imm_95_9__Reg1_0,
  Convert__Imm1_2__imm_95_9__Reg1_1,
  Convert__Imm1_3__imm_95_9__Reg1_2,
  Convert__Imm1_1__imm_95_11__Reg1_0,
  Convert__Imm1_2__imm_95_11__Reg1_1,
  Convert__Imm1_3__imm_95_11__Reg1_2,
  Convert__Imm1_1__imm_95_4__Reg1_0,
  Convert__Imm1_2__imm_95_4__Reg1_1,
  Convert__Imm1_3__imm_95_4__Reg1_2,
  Convert__Imm1_1__imm_95_13__Reg1_0,
  Convert__Imm1_2__imm_95_13__Reg1_1,
  Convert__Imm1_3__imm_95_13__Reg1_2,
  Convert__Imm1_1__imm_95_0__Reg1_0,
  Convert__Imm1_2__imm_95_0__Reg1_1,
  Convert__Imm1_3__imm_95_0__Reg1_2,
  Convert__Imm1_1__imm_95_15__Reg1_0,
  Convert__Imm1_2__imm_95_15__Reg1_1,
  Convert__Imm1_3__imm_95_15__Reg1_2,
  Convert__Imm1_1__imm_95_10__Reg1_0,
  Convert__Imm1_2__imm_95_10__Reg1_1,
  Convert__Imm1_3__imm_95_10__Reg1_2,
  Convert__Imm1_1__imm_95_12__Reg1_0,
  Convert__Imm1_2__imm_95_12__Reg1_1,
  Convert__Imm1_3__imm_95_12__Reg1_2,
  Convert__Imm1_1__imm_95_14__Reg1_0,
  Convert__Imm1_2__imm_95_14__Reg1_1,
  Convert__Imm1_3__imm_95_14__Reg1_2,
  Convert__regFCC0__Reg1_0__Reg1_1,
  Convert__Reg1_0__Reg1_1__Reg1_2,
  Convert__MEMri2_0,
  Convert__MEMrr2_0,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8,
  Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0,
  Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_11,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_4,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_13,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_0,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_15,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_10,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_12,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3,
  Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_14,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15,
  Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7,
  Convert__regG0__MEMri2_0,
  Convert__regG0__MEMrr2_0,
  Convert__Reg1_1__MEMri2_0,
  Convert__Reg1_1__MEMrr2_0,
  Convert__MEMri2_1,
  Convert__Reg1_3__MEMri2_1,
  Convert__MEMrr2_1,
  Convert__Reg1_3__MEMrr2_1,
  Convert__Reg1_3__MEMrr2_1__TailRelocSymLoad_GOT1_4,
  Convert__Reg1_3__MEMrr2_1__TailRelocSymLoad_TLS1_4,
  Convert__Reg1_4__MEMri2_1,
  Convert__Reg1_4__MEMrr2_1__ASITag1_3,
  Convert__MembarTag1_0,
  Convert__Reg1_1,
  Convert__regG0__Reg1_0,
  Convert__Reg1_1__regG0__Reg1_0,
  Convert__regG0__Imm1_0,
  Convert__Reg1_1__regG0__Imm1_0,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_8,
  Convert__Reg1_3__Imm1_2__Tie0_1_1__Imm1_0,
  Convert__Reg1_3__Reg1_1__Imm1_2__Tie0_1_1__Imm1_0,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_9,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_6,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_11,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_11,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_12,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_4,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_2,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_13,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_4,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_2,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_0,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_0,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_1,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_6,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_15,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_14,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_7,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_3,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_5,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_10,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_12,
  Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_14,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_15,
  Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_7,
  Convert__Reg1_0__regG0__Reg1_0,
  Convert__Reg1_0__Reg1_0__regG0,
  Convert__Reg1_1__Reg1_0__regG0,
  Convert__regASR27__regG0__Reg1_0,
  Convert__regASR27__regG0__Imm1_0,
  Convert__MEMri2_1__PrefetchTag1_3,
  Convert__MEMrr2_1__PrefetchTag1_3,
  Convert__MEMri2_1__PrefetchTag1_4,
  Convert__MEMrr2_1__ASITag1_3__PrefetchTag1_4,
  Convert__Reg1_0__Reg1_1,
  Convert__Reg1_0__Imm1_1,
  Convert__regG0__regG0__regG0,
  Convert__imm_95_8,
  Convert__Reg1_1__Imm1_0,
  Convert__Reg1_2__Imm1_0__Reg1_1,
  Convert__imm_95_0,
  Convert__Reg1_2__Reg1_0__ShiftAmtImm51_1,
  Convert__Reg1_2__Reg1_0__ShiftAmtImm61_1,
  Convert__MEMri2_2,
  Convert__MEMrr2_2,
  Convert__MEMri2_2__Reg1_0,
  Convert__MEMrr2_2__Reg1_0,
  Convert__MEMrr2_2__Reg1_0__ASITag1_4,
  Convert__Reg1_3__MEMri2_1__Tie0_1_1,
  Convert__Reg1_3__MEMrr2_1__Tie0_1_1,
  Convert__Reg1_4__MEMri2_1__Tie0_1_1,
  Convert__Reg1_4__MEMrr2_1__ASITag1_3__Tie0_1_1,
  Convert__regG0__Reg1_0__imm_95_8,
  Convert__regG0__Imm1_0__imm_95_8,
  Convert__regG0__Reg1_1__imm_95_8,
  Convert__regG0__Imm1_1__imm_95_8,
  Convert__Reg1_0__Reg1_2__imm_95_8,
  Convert__Reg1_0__Imm1_2__imm_95_8,
  Convert__Reg1_1__Reg1_3__imm_95_8,
  Convert__Reg1_1__Imm1_3__imm_95_8,
  Convert__Reg1_1__Reg1_3__Imm1_0,
  Convert__Reg1_1__Imm1_3__Imm1_0,
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
  // Convert__Reg1_2__Reg1_0__Reg1_1__TailRelocSymAdd_TLS1_3
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addTailRelocSymOperands, 4, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Imm1_0
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2
  { CVT_95_Reg, 4, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_3__Reg1_0__Reg1_1__Imm1_2
  { CVT_95_Reg, 4, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
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
  // Convert__Imm1_2__Imm1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__Imm1_0__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 1, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_4__Imm1_0__Reg1_3
  { CVT_95_addImmOperands, 5, CVT_95_addImmOperands, 1, CVT_95_Reg, 4, CVT_Done },
  // Convert__Imm1_1__imm_95_1__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_1, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_1__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_1, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_1__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_1, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_7__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_7, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_7__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_7, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_7__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_7, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_6__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_6, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_6__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_6, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_6__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_6, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_2__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_2, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_2__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_2, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_2__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_2, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_3__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_3, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_3__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_3, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_3__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_3, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_5__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_5, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_5__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_5, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_5__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_5, 0, CVT_95_Reg, 3, CVT_Done },
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
  // Convert__CallTarget1_0
  { CVT_95_addCallTargetOperands, 1, CVT_Done },
  // Convert__regO7__MEMri2_0
  { CVT_regO7, 0, CVT_95_addMEMriOperands, 1, CVT_Done },
  // Convert__regO7__MEMrr2_0
  { CVT_regO7, 0, CVT_95_addMEMrrOperands, 1, CVT_Done },
  // Convert__CallTarget1_0__Imm1_1
  { CVT_95_addCallTargetOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__CallTarget1_0__TailRelocSymCall_TLS1_1
  { CVT_95_addCallTargetOperands, 1, CVT_95_addTailRelocSymOperands, 2, CVT_Done },
  // Convert__MEMri2_0__Imm1_1
  { CVT_95_addMEMriOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__MEMrr2_0__Imm1_1
  { CVT_95_addMEMrrOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_4__Reg1_1__Reg1_3__Tie0_5_5__imm_95_128
  { CVT_95_Reg, 5, CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_Tied, Tie0_5_5, CVT_imm_95_128, 0, CVT_Done },
  // Convert__Reg1_5__Reg1_1__Reg1_4__Tie0_1_1
  { CVT_95_Reg, 6, CVT_95_Reg, 2, CVT_95_Reg, 5, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_5__Reg1_1__Reg1_4__Tie0_1_1__ASITag1_3
  { CVT_95_Reg, 6, CVT_95_Reg, 2, CVT_95_Reg, 5, CVT_Tied, Tie0_1_1, CVT_95_addASITagOperands, 4, CVT_Done },
  // Convert__Reg1_4__Reg1_1__Reg1_3__Tie0_5_5__imm_95_136
  { CVT_95_Reg, 5, CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_Tied, Tie0_5_5, CVT_imm_95_136, 0, CVT_Done },
  // Convert__Reg1_0__regG0__regG0
  { CVT_95_Reg, 1, CVT_regG0, 0, CVT_regG0, 0, CVT_Done },
  // Convert__MEMri2_1__regG0
  { CVT_95_addMEMriOperands, 2, CVT_regG0, 0, CVT_Done },
  // Convert__MEMrr2_1__regG0
  { CVT_95_addMEMrrOperands, 2, CVT_regG0, 0, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__regG0__Reg1_0__Reg1_1
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__regG0__Reg1_0__Imm1_1
  { CVT_regG0, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_3__Imm1_0__Reg1_1__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_3__Imm1_0__Reg1_1__Imm1_2
  { CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Imm1_2__imm_95_13__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_13, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_13__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_13, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_5__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_5, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_5__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_5, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_1__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_1, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_1__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_1, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_10__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_10, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_10__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_10, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_11__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_11, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_11__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_11, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_12__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_12, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_12__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_12, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_3__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_3, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_3__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_3, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_2__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_2, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_2__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_2, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_4__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_4, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_4__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_4, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_9__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_9, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_9__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_9, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_6__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_6, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_6__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_6, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_14__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_14, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_14__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_14, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_15__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_15, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_15__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_15, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_7__Reg1_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_7, 0, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_2__imm_95_7__Reg1_0__Imm1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_7, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_0__imm_95_1
  { CVT_95_Reg, 1, CVT_95_Reg, 1, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_1__imm_95_8__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_8, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_8__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_8, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_8__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_8, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_9__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_9, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_9__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_9, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_9__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_9, 0, CVT_95_Reg, 3, CVT_Done },
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
  // Convert__Imm1_1__imm_95_0__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_0, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_0__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_0, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_0__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_0, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_15__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_15, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_15__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_15, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_15__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_15, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_10__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_10, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_10__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_10, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_10__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_10, 0, CVT_95_Reg, 3, CVT_Done },
  // Convert__Imm1_1__imm_95_12__Reg1_0
  { CVT_95_addImmOperands, 2, CVT_imm_95_12, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Imm1_2__imm_95_12__Reg1_1
  { CVT_95_addImmOperands, 3, CVT_imm_95_12, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__Imm1_3__imm_95_12__Reg1_2
  { CVT_95_addImmOperands, 4, CVT_imm_95_12, 0, CVT_95_Reg, 3, CVT_Done },
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
  // Convert__MEMri2_0
  { CVT_95_addMEMriOperands, 1, CVT_Done },
  // Convert__MEMrr2_0
  { CVT_95_addMEMrrOperands, 1, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0
  { CVT_95_Reg, 4, CVT_95_Reg, 3, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0
  { CVT_95_Reg, 4, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_11
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_4
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_13
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_0
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_15
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_10
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_12
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_14
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7
  { CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_7, 0, CVT_Done },
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
  // Convert__Reg1_3__MEMrr2_1__TailRelocSymLoad_GOT1_4
  { CVT_95_Reg, 4, CVT_95_addMEMrrOperands, 2, CVT_95_addTailRelocSymOperands, 5, CVT_Done },
  // Convert__Reg1_3__MEMrr2_1__TailRelocSymLoad_TLS1_4
  { CVT_95_Reg, 4, CVT_95_addMEMrrOperands, 2, CVT_95_addTailRelocSymOperands, 5, CVT_Done },
  // Convert__Reg1_4__MEMri2_1
  { CVT_95_Reg, 5, CVT_95_addMEMriOperands, 2, CVT_Done },
  // Convert__Reg1_4__MEMrr2_1__ASITag1_3
  { CVT_95_Reg, 5, CVT_95_addMEMrrOperands, 2, CVT_95_addASITagOperands, 4, CVT_Done },
  // Convert__MembarTag1_0
  { CVT_95_addMembarTagOperands, 1, CVT_Done },
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
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_8
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_3__Imm1_2__Tie0_1_1__Imm1_0
  { CVT_95_Reg, 4, CVT_95_addImmOperands, 3, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_3__Reg1_1__Imm1_2__Tie0_1_1__Imm1_0
  { CVT_95_Reg, 4, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_9
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_6
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_11
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_11
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_11, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_12
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_4
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_2
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_13
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_13, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_4
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_4, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_2
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_2, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_0
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_0
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_9, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_1, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_6
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_6, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_15
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_14
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_7
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_3
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_3, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_5
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_5, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_10
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_10, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_12
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_12, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_14
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_14, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_15
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_15, 0, CVT_Done },
  // Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_7
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 2, CVT_Tied, Tie0_3_3, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_0__regG0__Reg1_0
  { CVT_95_Reg, 1, CVT_regG0, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_0__regG0
  { CVT_95_Reg, 1, CVT_95_Reg, 1, CVT_regG0, 0, CVT_Done },
  // Convert__Reg1_1__Reg1_0__regG0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_regG0, 0, CVT_Done },
  // Convert__regASR27__regG0__Reg1_0
  { CVT_regASR27, 0, CVT_regG0, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__regASR27__regG0__Imm1_0
  { CVT_regASR27, 0, CVT_regG0, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__MEMri2_1__PrefetchTag1_3
  { CVT_95_addMEMriOperands, 2, CVT_95_addPrefetchTagOperands, 4, CVT_Done },
  // Convert__MEMrr2_1__PrefetchTag1_3
  { CVT_95_addMEMrrOperands, 2, CVT_95_addPrefetchTagOperands, 4, CVT_Done },
  // Convert__MEMri2_1__PrefetchTag1_4
  { CVT_95_addMEMriOperands, 2, CVT_95_addPrefetchTagOperands, 5, CVT_Done },
  // Convert__MEMrr2_1__ASITag1_3__PrefetchTag1_4
  { CVT_95_addMEMrrOperands, 2, CVT_95_addASITagOperands, 4, CVT_95_addPrefetchTagOperands, 5, CVT_Done },
  // Convert__Reg1_0__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Imm1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__regG0__regG0__regG0
  { CVT_regG0, 0, CVT_regG0, 0, CVT_regG0, 0, CVT_Done },
  // Convert__imm_95_8
  { CVT_imm_95_8, 0, CVT_Done },
  // Convert__Reg1_1__Imm1_0
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_2__Imm1_0__Reg1_1
  { CVT_95_Reg, 3, CVT_95_addImmOperands, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__imm_95_0
  { CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_2__Reg1_0__ShiftAmtImm51_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addShiftAmtImm5Operands, 2, CVT_Done },
  // Convert__Reg1_2__Reg1_0__ShiftAmtImm61_1
  { CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_addShiftAmtImm6Operands, 2, CVT_Done },
  // Convert__MEMri2_2
  { CVT_95_addMEMriOperands, 3, CVT_Done },
  // Convert__MEMrr2_2
  { CVT_95_addMEMrrOperands, 3, CVT_Done },
  // Convert__MEMri2_2__Reg1_0
  { CVT_95_addMEMriOperands, 3, CVT_95_Reg, 1, CVT_Done },
  // Convert__MEMrr2_2__Reg1_0
  { CVT_95_addMEMrrOperands, 3, CVT_95_Reg, 1, CVT_Done },
  // Convert__MEMrr2_2__Reg1_0__ASITag1_4
  { CVT_95_addMEMrrOperands, 3, CVT_95_Reg, 1, CVT_95_addASITagOperands, 5, CVT_Done },
  // Convert__Reg1_3__MEMri2_1__Tie0_1_1
  { CVT_95_Reg, 4, CVT_95_addMEMriOperands, 2, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_3__MEMrr2_1__Tie0_1_1
  { CVT_95_Reg, 4, CVT_95_addMEMrrOperands, 2, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_4__MEMri2_1__Tie0_1_1
  { CVT_95_Reg, 5, CVT_95_addMEMriOperands, 2, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_4__MEMrr2_1__ASITag1_3__Tie0_1_1
  { CVT_95_Reg, 5, CVT_95_addMEMrrOperands, 2, CVT_95_addASITagOperands, 4, CVT_Tied, Tie0_1_1, CVT_Done },
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
  // Convert__Reg1_1__Reg1_3__Imm1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Imm1_3__Imm1_0
  { CVT_95_Reg, 2, CVT_95_addImmOperands, 4, CVT_95_addImmOperands, 1, CVT_Done },
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
  for (const uint8_t *p = Converter; *p; p += 2) {
    unsigned OpIdx = *(p + 1);
    switch (*p) {
    default: llvm_unreachable("invalid conversion entry!");
    case CVT_Reg:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
      static_cast<SparcOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addImmOperands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_addTailRelocSymOperands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addTailRelocSymOperands(Inst, 1);
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
    case CVT_imm_95_7:
      Inst.addOperand(MCOperand::createImm(7));
      break;
    case CVT_regG0:
      Inst.addOperand(MCOperand::createReg(SP::G0));
      break;
    case CVT_imm_95_15:
      Inst.addOperand(MCOperand::createImm(15));
      break;
    case CVT_95_addCallTargetOperands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addCallTargetOperands(Inst, 1);
      break;
    case CVT_regO7:
      Inst.addOperand(MCOperand::createReg(SP::O7));
      break;
    case CVT_95_addMEMriOperands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addMEMriOperands(Inst, 2);
      break;
    case CVT_95_addMEMrrOperands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addMEMrrOperands(Inst, 2);
      break;
    case CVT_imm_95_128:
      Inst.addOperand(MCOperand::createImm(128));
      break;
    case CVT_95_addASITagOperands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addASITagOperands(Inst, 1);
      break;
    case CVT_imm_95_136:
      Inst.addOperand(MCOperand::createImm(136));
      break;
    case CVT_regFCC0:
      Inst.addOperand(MCOperand::createReg(SP::FCC0));
      break;
    case CVT_95_addMembarTagOperands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addMembarTagOperands(Inst, 1);
      break;
    case CVT_regASR27:
      Inst.addOperand(MCOperand::createReg(SP::ASR27));
      break;
    case CVT_95_addPrefetchTagOperands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addPrefetchTagOperands(Inst, 1);
      break;
    case CVT_95_addShiftAmtImm5Operands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addShiftAmtImm5Operands(Inst, 1);
      break;
    case CVT_95_addShiftAmtImm6Operands:
      static_cast<SparcOperand &>(*Operands[OpIdx]).addShiftAmtImm6Operands(Inst, 1);
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
    case CVT_95_addTailRelocSymOperands:
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
    case CVT_imm_95_7:
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
    case CVT_95_addCallTargetOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
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
    case CVT_imm_95_128:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addASITagOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_136:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_regFCC0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addMembarTagOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_regASR27:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addPrefetchTagOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addShiftAmtImm5Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addShiftAmtImm6Operands:
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
  MCK__PCT_asi, // '%asi'
  MCK__PCT_ncc, // '%ncc'
  MCK__PCT_xcc, // '%xcc'
  MCK__43_, // '+'
  MCK_1, // '1'
  MCK_3, // '3'
  MCK_5, // '5'
  MCK__91_, // '['
  MCK__93_, // ']'
  MCK_a, // 'a'
  MCK_pn, // 'pn'
  MCK_pt, // 'pt'
  MCK_LAST_TOKEN = MCK_pt,
  MCK_Reg12, // derived register class
  MCK_CPQ, // register class 'CPQ'
  MCK_CPSR, // register class 'CPSR'
  MCK_FCC0, // register class 'FCC0'
  MCK_FQ, // register class 'FQ'
  MCK_FSR, // register class 'FSR'
  MCK_G0, // register class 'G0'
  MCK_ICC, // register class 'ICC'
  MCK_PSR, // register class 'PSR'
  MCK_TBR, // register class 'TBR'
  MCK_WIM, // register class 'WIM'
  MCK_Reg25, // derived register class
  MCK_Reg24, // derived register class
  MCK_FCCRegs, // register class 'FCCRegs'
  MCK_GPRIncomingArg, // register class 'GPRIncomingArg'
  MCK_GPROutgoingArg, // register class 'GPROutgoingArg'
  MCK_LowQFPRegs, // register class 'LowQFPRegs'
  MCK_CoprocPair, // register class 'CoprocPair'
  MCK_IntPair, // register class 'IntPair'
  MCK_LowDFPRegs, // register class 'LowDFPRegs'
  MCK_QFPRegs, // register class 'QFPRegs'
  MCK_PRRegs, // register class 'PRRegs'
  MCK_CoprocRegs, // register class 'CoprocRegs'
  MCK_DFPRegs, // register class 'DFPRegs'
  MCK_FPRegs, // register class 'FPRegs'
  MCK_IntRegs, // register class 'IntRegs,I64Regs'
  MCK_ASRRegs, // register class 'ASRRegs'
  MCK_LAST_REGISTER = MCK_ASRRegs,
  MCK_RegByHwMode_sparc_ptr_rc, // register class by hwmode
  MCK_LAST_REGCLASS_BY_HWMODE = MCK_RegByHwMode_sparc_ptr_rc,
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_ASITag, // user defined class 'SparcASITagAsmOperand'
  MCK_CallTarget, // user defined class 'SparcCallTargetAsmOperand'
  MCK_MEMri, // user defined class 'SparcMEMriAsmOperand'
  MCK_MEMrr, // user defined class 'SparcMEMrrAsmOperand'
  MCK_MembarTag, // user defined class 'SparcMembarTagAsmOperand'
  MCK_PrefetchTag, // user defined class 'SparcPrefetchTagAsmOperand'
  MCK_ShiftAmtImm5, // user defined class 'anonymous_13952'
  MCK_ShiftAmtImm6, // user defined class 'anonymous_13953'
  MCK_TailRelocSymLoad_GOT, // user defined class 'anonymous_13954'
  MCK_TailRelocSymAdd_TLS, // user defined class 'anonymous_13955'
  MCK_TailRelocSymLoad_TLS, // user defined class 'anonymous_13956'
  MCK_TailRelocSymCall_TLS, // user defined class 'anonymous_13957'
  NumMatchClassKinds
};

} // end anonymous namespace

static unsigned getDiagKindFromRegisterClass(MatchClassKind RegisterClass) {
  return MCTargetAsmParser::Match_InvalidOperand;
}

static MatchClassKind matchTokenString(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 7 strings to match.
    switch (Name[0]) {
    default: break;
    case '+':	 // 1 string to match.
      return MCK__43_;	 // "+"
    case '1':	 // 1 string to match.
      return MCK_1;	 // "1"
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
  case 4:	 // 3 strings to match.
    if (Name[0] != '%')
      break;
    switch (Name[1]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(Name.data()+2, "si", 2) != 0)
        break;
      return MCK__PCT_asi;	 // "%asi"
    case 'n':	 // 1 string to match.
      if (memcmp(Name.data()+2, "cc", 2) != 0)
        break;
      return MCK__PCT_ncc;	 // "%ncc"
    case 'x':	 // 1 string to match.
      if (memcmp(Name.data()+2, "cc", 2) != 0)
        break;
      return MCK__PCT_xcc;	 // "%xcc"
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
    {0, 35, 6},
    {6, 0, 0},
    {6, 0, 0},
    {6, 27, 1},
    {7, 0, 0},
    {7, 0, 0},
    {7, 39, 1},
    {8, 0, 0},
    {8, 0, 0},
    {8, 0, 0},
    {8, 0, 0},
    {8, 32, 1},
    {9, 32, 1},
    {10, 0, 0},
    {10, 39, 1},
    {11, 39, 1},
    {12, 34, 1},
    {13, 0, 0},
    {13, 0, 0},
    {13, 37, 1},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
    {14, 0, 0},
  };

  static constexpr uint8_t Data[] = {
    0xE1,
    0x3F,
  };

  auto &Entry = Table[A];
  unsigned Idx = B - Entry.Start;
  if (Idx >= Entry.Length)
    return false;
  Idx += Entry.Offset;
  return (Data[Idx / 8] >> (Idx % 8)) & 1;
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind, const MCSubtargetInfo &STI) {
  SparcOperand &Operand = (SparcOperand &)GOp;
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
  case MCK_ASITag: {
    DiagnosticPredicate DP(Operand.isASITag());
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
  case MCK_MEMri: {
    DiagnosticPredicate DP(Operand.isMEMri());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MEMrr: {
    DiagnosticPredicate DP(Operand.isMEMrr());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MembarTag: {
    DiagnosticPredicate DP(Operand.isMembarTag());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_PrefetchTag: {
    DiagnosticPredicate DP(Operand.isPrefetchTag());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_ShiftAmtImm5: {
    DiagnosticPredicate DP(Operand.isShiftAmtImm5());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_ShiftAmtImm6: {
    DiagnosticPredicate DP(Operand.isShiftAmtImm6());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_TailRelocSymLoad_GOT: {
    DiagnosticPredicate DP(Operand.isTailRelocSym());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_TailRelocSymAdd_TLS: {
    DiagnosticPredicate DP(Operand.isTailRelocSym());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_TailRelocSymLoad_TLS: {
    DiagnosticPredicate DP(Operand.isTailRelocSym());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_TailRelocSymCall_TLS: {
    DiagnosticPredicate DP(Operand.isTailRelocSym());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg() && Kind > MCK_LAST_REGISTER && Kind <= MCK_LAST_REGCLASS_BY_HWMODE) {
    static constexpr MatchClassKind RegClassByHwModeMatchTable[2][1] = {
      { // DefaultMode
        MCK_IntRegs, // sparc_ptr_rc
      },
      { // SPARC64
        MCK_IntRegs, // sparc_ptr_rc
      },
    };

    static_assert(MCK_LAST_REGCLASS_BY_HWMODE - MCK_LAST_REGISTER == 1);
    const unsigned HwMode = STI.getHwMode(MCSubtargetInfo::HwMode_RegInfo);
    Kind = RegClassByHwModeMatchTable[HwMode][Kind - (MCK_LAST_REGISTER + 1)];
  }

  if (Operand.isReg()) {
    static constexpr uint16_t Table[SP::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      MCK_PRRegs,
      MCK_PRRegs,
      MCK_PRRegs,
      MCK_CPQ,
      MCK_CPSR,
      MCK_PRRegs,
      MCK_FQ,
      MCK_FSR,
      MCK_PRRegs,
      MCK_ICC,
      MCK_PRRegs,
      MCK_PRRegs,
      MCK_PSR,
      MCK_PRRegs,
      MCK_PRRegs,
      MCK_TBR,
      MCK_Reg12,
      MCK_PRRegs,
      MCK_PRRegs,
      MCK_PRRegs,
      MCK_PRRegs,
      MCK_PRRegs,
      MCK_PRRegs,
      MCK_WIM,
      MCK_PRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_ASRRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_CoprocRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_LowDFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_DFPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FPRegs,
      MCK_FCC0,
      MCK_FCCRegs,
      MCK_FCCRegs,
      MCK_FCCRegs,
      MCK_G0,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_GPRIncomingArg,
      MCK_GPRIncomingArg,
      MCK_GPRIncomingArg,
      MCK_GPRIncomingArg,
      MCK_GPRIncomingArg,
      MCK_GPRIncomingArg,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_GPROutgoingArg,
      MCK_GPROutgoingArg,
      MCK_GPROutgoingArg,
      MCK_GPROutgoingArg,
      MCK_GPROutgoingArg,
      MCK_GPROutgoingArg,
      MCK_IntRegs,
      MCK_IntRegs,
      MCK_LowQFPRegs,
      MCK_LowQFPRegs,
      MCK_LowQFPRegs,
      MCK_LowQFPRegs,
      MCK_LowQFPRegs,
      MCK_LowQFPRegs,
      MCK_LowQFPRegs,
      MCK_LowQFPRegs,
      MCK_QFPRegs,
      MCK_QFPRegs,
      MCK_QFPRegs,
      MCK_QFPRegs,
      MCK_QFPRegs,
      MCK_QFPRegs,
      MCK_QFPRegs,
      MCK_QFPRegs,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_CoprocPair,
      MCK_IntPair,
      MCK_IntPair,
      MCK_IntPair,
      MCK_IntPair,
      MCK_Reg25,
      MCK_Reg25,
      MCK_Reg25,
      MCK_IntPair,
      MCK_IntPair,
      MCK_IntPair,
      MCK_IntPair,
      MCK_IntPair,
      MCK_Reg24,
      MCK_Reg24,
      MCK_Reg24,
      MCK_IntPair,
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
  case MCK__PCT_asi: return "MCK__PCT_asi";
  case MCK__PCT_ncc: return "MCK__PCT_ncc";
  case MCK__PCT_xcc: return "MCK__PCT_xcc";
  case MCK__43_: return "MCK__43_";
  case MCK_1: return "MCK_1";
  case MCK_3: return "MCK_3";
  case MCK_5: return "MCK_5";
  case MCK__91_: return "MCK__91_";
  case MCK__93_: return "MCK__93_";
  case MCK_a: return "MCK_a";
  case MCK_pn: return "MCK_pn";
  case MCK_pt: return "MCK_pt";
  case MCK_Reg12: return "MCK_Reg12";
  case MCK_CPQ: return "MCK_CPQ";
  case MCK_CPSR: return "MCK_CPSR";
  case MCK_FCC0: return "MCK_FCC0";
  case MCK_FQ: return "MCK_FQ";
  case MCK_FSR: return "MCK_FSR";
  case MCK_G0: return "MCK_G0";
  case MCK_ICC: return "MCK_ICC";
  case MCK_PSR: return "MCK_PSR";
  case MCK_TBR: return "MCK_TBR";
  case MCK_WIM: return "MCK_WIM";
  case MCK_Reg25: return "MCK_Reg25";
  case MCK_Reg24: return "MCK_Reg24";
  case MCK_FCCRegs: return "MCK_FCCRegs";
  case MCK_GPRIncomingArg: return "MCK_GPRIncomingArg";
  case MCK_GPROutgoingArg: return "MCK_GPROutgoingArg";
  case MCK_LowQFPRegs: return "MCK_LowQFPRegs";
  case MCK_CoprocPair: return "MCK_CoprocPair";
  case MCK_IntPair: return "MCK_IntPair";
  case MCK_LowDFPRegs: return "MCK_LowDFPRegs";
  case MCK_QFPRegs: return "MCK_QFPRegs";
  case MCK_PRRegs: return "MCK_PRRegs";
  case MCK_CoprocRegs: return "MCK_CoprocRegs";
  case MCK_DFPRegs: return "MCK_DFPRegs";
  case MCK_FPRegs: return "MCK_FPRegs";
  case MCK_IntRegs: return "MCK_IntRegs";
  case MCK_ASRRegs: return "MCK_ASRRegs";
  case MCK_RegByHwMode_sparc_ptr_rc: return "MCK_RegByHwMode_sparc_ptr_rc";
  case MCK_Imm: return "MCK_Imm";
  case MCK_ASITag: return "MCK_ASITag";
  case MCK_CallTarget: return "MCK_CallTarget";
  case MCK_MEMri: return "MCK_MEMri";
  case MCK_MEMrr: return "MCK_MEMrr";
  case MCK_MembarTag: return "MCK_MembarTag";
  case MCK_PrefetchTag: return "MCK_PrefetchTag";
  case MCK_ShiftAmtImm5: return "MCK_ShiftAmtImm5";
  case MCK_ShiftAmtImm6: return "MCK_ShiftAmtImm6";
  case MCK_TailRelocSymLoad_GOT: return "MCK_TailRelocSymLoad_GOT";
  case MCK_TailRelocSymAdd_TLS: return "MCK_TailRelocSymAdd_TLS";
  case MCK_TailRelocSymLoad_TLS: return "MCK_TailRelocSymLoad_TLS";
  case MCK_TailRelocSymCall_TLS: return "MCK_TailRelocSymCall_TLS";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset SparcAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  if (!FB[Sparc::Feature64Bit])
    Features.set(Feature_Is32BitBit);
  if (FB[Sparc::Feature64Bit])
    Features.set(Feature_Is64BitBit);
  if (FB[Sparc::FeatureSoftMulDiv])
    Features.set(Feature_UseSoftMulDivBit);
  if (FB[Sparc::FeatureV9])
    Features.set(Feature_HasV9Bit);
  if (FB[Sparc::FeatureVIS])
    Features.set(Feature_HasVISBit);
  if (FB[Sparc::FeatureVIS2])
    Features.set(Feature_HasVIS2Bit);
  if (FB[Sparc::FeatureVIS3])
    Features.set(Feature_HasVIS3Bit);
  if (FB[Sparc::FeatureUA2005])
    Features.set(Feature_HasUA2005Bit);
  if (FB[Sparc::FeatureUA2007])
    Features.set(Feature_HasUA2007Bit);
  if (FB[Sparc::FeatureOSA2011])
    Features.set(Feature_HasOSA2011Bit);
  if (FB[Sparc::FeatureCrypto])
    Features.set(Feature_HasCryptoBit);
  if (FB[Sparc::LeonCASA] || FB[Sparc::FeatureV9])
    Features.set(Feature_HasCASABit);
  if (FB[Sparc::FeaturePWRPSR])
    Features.set(Feature_HasPWRPSRBit);
  return Features;
}

static bool checkAsmTiedOperandConstraints(const SparcAsmParser&AsmParser,
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
    "\003add\005addcc\004addx\005addxc\006addxcc\007addxccc\014aes_dround01\016"
    "aes_dround01_l\014aes_dround23\016aes_dround23_l\014aes_eround01\016aes"
    "_eround01_l\014aes_eround23\016aes_eround23_l\014aes_kexpand0\014aes_ke"
    "xpand1\014aes_kexpand2\talignaddr\nalignaddrl\010allclean\003and\005and"
    "cc\004andn\006andncc\007array16\007array32\006array8\001b\002ba\003bcc\004"
    "bclr\003bcs\002be\003beq\002bg\003bge\004bgeu\003bgt\003bgu\002bl\003bl"
    "e\004bleu\003blt\003blu\005bmask\002bn\003bne\004bneg\003bnz\004bpos\002"
    "br\003bre\005brgez\004brgz\005brlez\004brlz\004brne\004brnz\003brz\004b"
    "set\010bshuffle\004btog\004btst\003bvc\003bvs\002bz\004call\ncamellia_f"
    "\013camellia_fl\014camellia_fli\003cas\004casa\004casl\004casx\005casxa"
    "\005casxl\002cb\003cb0\004cb01\005cb012\005cb013\004cb02\005cb023\004cb"
    "03\003cb1\004cb12\005cb123\004cb13\003cb2\004cb23\003cb3\003cba\003cbn\003"
    "clr\004clrb\004clrh\004clrx\007cmask16\007cmask32\006cmask8\003cmp\006c"
    "rc32c\003cwb\005cwbcc\005cwbcs\004cwbe\004cwbg\005cwbge\006cwbgeu\005cw"
    "bgu\004cwbl\005cwble\006cwbleu\005cwblu\005cwbne\006cwbneg\006cwbpos\005"
    "cwbvc\005cwbvs\003cxb\005cxbcc\005cxbcs\004cxbe\004cxbg\005cxbge\006cxb"
    "geu\005cxbgu\004cxbl\005cxble\006cxbleu\005cxblu\005cxbne\006cxbneg\006"
    "cxbpos\005cxbvc\005cxbvs\003dec\005deccc\007des_iip\006des_ip\013des_ke"
    "xpand\tdes_round\004done\006edge16\007edge16l\010edge16ln\007edge16n\006"
    "edge32\007edge32l\010edge32ln\007edge32n\005edge8\006edge8l\007edge8ln\006"
    "edge8n\005fabsd\005fabsq\005fabss\005faddd\005faddq\005fadds\nfaligndat"
    "a\004fand\010fandnot1\tfandnot1s\010fandnot2\tfandnot2s\005fands\002fb\003"
    "fba\003fbe\003fbg\004fbge\003fbl\004fble\004fblg\003fbn\004fbne\004fbnz"
    "\003fbo\003fbu\004fbue\004fbug\005fbuge\004fbul\005fbule\003fbz\010fchk"
    "sm16\005fcmpd\006fcmped\006fcmpeq\010fcmpeq16\010fcmpeq32\006fcmpes\010"
    "fcmpgt16\010fcmpgt32\010fcmple16\010fcmple32\010fcmpne16\010fcmpne32\005"
    "fcmpq\005fcmps\005fdivd\005fdivq\005fdivs\006fdmulq\005fdtoi\005fdtoq\005"
    "fdtos\005fdtox\007fexpand\006fhaddd\006fhadds\006fhsubd\006fhsubs\005fi"
    "tod\005fitoq\005fitos\006flcmpd\006flcmps\005flush\006flushw\006fmaddd\006"
    "fmadds\007fmean16\005fmovd\006fmovda\007fmovdcc\007fmovdcs\006fmovde\007"
    "fmovdeq\006fmovdg\007fmovdge\010fmovdgeu\007fmovdgt\007fmovdgu\006fmovd"
    "l\007fmovdle\010fmovdleu\007fmovdlg\007fmovdlt\007fmovdlu\006fmovdn\007"
    "fmovdne\010fmovdneg\007fmovdnz\006fmovdo\010fmovdpos\006fmovdu\007fmovd"
    "ue\007fmovdug\010fmovduge\007fmovdul\010fmovdule\007fmovdvc\007fmovdvs\006"
    "fmovdz\005fmovq\006fmovqa\007fmovqcc\007fmovqcs\006fmovqe\007fmovqeq\006"
    "fmovqg\007fmovqge\010fmovqgeu\007fmovqgt\007fmovqgu\006fmovql\007fmovql"
    "e\010fmovqleu\007fmovqlg\007fmovqlt\007fmovqlu\006fmovqn\007fmovqne\010"
    "fmovqneg\007fmovqnz\006fmovqo\010fmovqpos\006fmovqu\007fmovque\007fmovq"
    "ug\010fmovquge\007fmovqul\010fmovqule\007fmovqvc\007fmovqvs\006fmovqz\006"
    "fmovrd\007fmovrde\tfmovrdgez\010fmovrdgz\tfmovrdlez\010fmovrdlz\010fmov"
    "rdne\010fmovrdnz\007fmovrdz\006fmovrq\007fmovrqe\tfmovrqgez\010fmovrqgz"
    "\tfmovrqlez\010fmovrqlz\010fmovrqne\010fmovrqnz\007fmovrqz\006fmovrs\007"
    "fmovrse\tfmovrsgez\010fmovrsgz\tfmovrslez\010fmovrslz\010fmovrsne\010fm"
    "ovrsnz\007fmovrsz\005fmovs\006fmovsa\007fmovscc\007fmovscs\006fmovse\007"
    "fmovseq\006fmovsg\007fmovsge\010fmovsgeu\007fmovsgt\007fmovsgu\006fmovs"
    "l\007fmovsle\010fmovsleu\007fmovslg\007fmovslt\007fmovslu\006fmovsn\007"
    "fmovsne\010fmovsneg\007fmovsnz\006fmovso\010fmovspos\006fmovsu\007fmovs"
    "ue\007fmovsug\010fmovsuge\007fmovsul\010fmovsule\007fmovsvc\007fmovsvs\006"
    "fmovsz\006fmsubd\006fmsubs\nfmul8sux16\nfmul8ulx16\010fmul8x16\nfmul8x1"
    "6al\nfmul8x16au\005fmuld\013fmuld8sux16\013fmuld8ulx16\005fmulq\005fmul"
    "s\006fnaddd\006fnadds\005fnand\006fnands\005fnegd\005fnegq\005fnegs\007"
    "fnhaddd\007fnhadds\007fnmaddd\007fnmadds\007fnmsubd\007fnmsubs\006fnmul"
    "d\006fnmuls\004fnor\005fnors\005fnot1\006fnot1s\005fnot2\006fnot2s\007f"
    "nsmuld\004fone\005fones\003for\007fornot1\010fornot1s\007fornot2\010for"
    "not2s\004fors\007fpack16\007fpack32\010fpackfix\007fpadd16\010fpadd16s\007"
    "fpadd32\010fpadd32s\007fpadd64\007fpmaddx\tfpmaddxhi\007fpmerge\007fpsu"
    "b16\010fpsub16s\007fpsub32\010fpsub32s\005fqtod\005fqtoi\005fqtos\005fq"
    "tox\007fslas16\007fslas32\006fsll16\006fsll32\006fsmuld\006fsqrtd\006fs"
    "qrtq\006fsqrts\006fsra16\006fsra32\005fsrc1\006fsrc1s\005fsrc2\006fsrc2"
    "s\006fsrl16\006fsrl32\005fstod\005fstoi\005fstoq\005fstox\005fsubd\005f"
    "subq\005fsubs\005fxnor\006fxnors\004fxor\005fxors\005fxtod\005fxtoq\005"
    "fxtos\005fzero\006fzeros\003inc\005inccc\006invalw\003jmp\004jmpl\002ld"
    "\003lda\003ldd\004ldda\003ldq\004ldqa\004ldsb\005ldsba\004ldsh\005ldsha"
    "\006ldstub\007ldstuba\004ldsw\005ldswa\004ldub\005lduba\004lduh\005lduh"
    "a\003ldx\004ldxa\005lzcnt\003md5\006membar\007montmul\007montsqr\003mov"
    "\004mova\005movcc\005movcs\007movdtox\004move\005moveq\004movg\005movge"
    "\006movgeu\005movgt\005movgu\004movl\005movle\006movleu\005movlg\005mov"
    "lt\005movlu\004movn\005movne\006movneg\005movnz\004movo\006movpos\004mo"
    "vr\005movre\007movrgez\006movrgz\007movrlez\006movrlz\006movrne\006movr"
    "nz\005movrz\010movstosw\010movstouw\004movu\005movue\005movug\006movuge"
    "\005movul\006movule\005movvc\005movvs\007movwtos\007movxtod\004movz\005"
    "mpmul\006mulscc\004mulx\003neg\003nop\007normalw\003not\002or\004orcc\003"
    "orn\005orncc\006otherw\005pause\005pdist\006pdistn\004popc\010prefetch\t"
    "prefetcha\003pwr\002rd\004rdpr\007restore\010restored\003ret\004retl\005"
    "retry\004rett\004save\005saved\004sdiv\006sdivcc\005sdivx\003set\005set"
    "hi\005setsw\004setx\004sha1\006sha256\006sha512\010shutdown\004siam\005"
    "signx\003sir\003sll\004sllx\004smac\004smul\006smulcc\003sra\004srax\003"
    "srl\004srlx\002st\003sta\003stb\004stba\005stbar\003std\004stda\003sth\004"
    "stha\003stq\004stqa\003stx\004stxa\003sub\005subcc\004subx\006subxcc\004"
    "swap\005swapa\001t\002ta\006taddcc\010taddcctv\003tcc\003tcs\002te\003t"
    "eq\002tg\003tge\004tgeu\003tgt\003tgu\002tl\003tle\004tleu\003tlt\003tl"
    "u\002tn\003tne\004tneg\003tnz\004tpos\003tst\006tsubcc\010tsubcctv\003t"
    "vc\003tvs\002tz\004udiv\006udivcc\005udivx\004umac\004umul\006umulcc\007"
    "umulxhi\005unimp\002wr\004wrpr\005xmulx\007xmulxhi\004xnor\006xnorcc\003"
    "xor\005xorcc";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
  AMFBS_HasCASA,
  AMFBS_HasCrypto,
  AMFBS_HasOSA2011,
  AMFBS_HasPWRPSR,
  AMFBS_HasUA2005,
  AMFBS_HasUA2007,
  AMFBS_HasV9,
  AMFBS_HasVIS,
  AMFBS_HasVIS2,
  AMFBS_HasVIS3,
  AMFBS_Is64Bit,
  AMFBS_HasV9_Is32Bit,
  AMFBS_HasV9_Is64Bit,
  AMFBS_Is32Bit_HasV9,
  AMFBS_Is64Bit_HasV9,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
  {Feature_HasCASABit, }, // AMFBS_HasCASA
  {Feature_HasCryptoBit, }, // AMFBS_HasCrypto
  {Feature_HasOSA2011Bit, }, // AMFBS_HasOSA2011
  {Feature_HasPWRPSRBit, }, // AMFBS_HasPWRPSR
  {Feature_HasUA2005Bit, }, // AMFBS_HasUA2005
  {Feature_HasUA2007Bit, }, // AMFBS_HasUA2007
  {Feature_HasV9Bit, }, // AMFBS_HasV9
  {Feature_HasVISBit, }, // AMFBS_HasVIS
  {Feature_HasVIS2Bit, }, // AMFBS_HasVIS2
  {Feature_HasVIS3Bit, }, // AMFBS_HasVIS3
  {Feature_Is64BitBit, }, // AMFBS_Is64Bit
  {Feature_HasV9Bit, Feature_Is32BitBit, }, // AMFBS_HasV9_Is32Bit
  {Feature_HasV9Bit, Feature_Is64BitBit, }, // AMFBS_HasV9_Is64Bit
  {Feature_Is32BitBit, Feature_HasV9Bit, }, // AMFBS_Is32Bit_HasV9
  {Feature_Is64BitBit, Feature_HasV9Bit, }, // AMFBS_Is64Bit_HasV9
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
  { 0 /* add */, SP::ADDrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 0 /* add */, SP::ADDri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 0 /* add */, SP::TLS_ADDrr, Convert__Reg1_2__Reg1_0__Reg1_1__TailRelocSymAdd_TLS1_3, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs, MCK_TailRelocSymAdd_TLS }, },
  { 4 /* addcc */, SP::ADDCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4 /* addcc */, SP::ADDCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 10 /* addx */, SP::ADDCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 10 /* addx */, SP::ADDCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 10 /* addx */, SP::ADDCri, Convert__Reg1_2__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs, MCK_IntRegs }, },
  { 15 /* addxc */, SP::ADDXC, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 21 /* addxcc */, SP::ADDErr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 21 /* addxcc */, SP::ADDEri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 28 /* addxccc */, SP::ADDXCCC, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 36 /* aes_dround01 */, SP::AES_DROUND01, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 49 /* aes_dround01_l */, SP::AES_DROUND01_LAST, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 64 /* aes_dround23 */, SP::AES_DROUND23, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 77 /* aes_dround23_l */, SP::AES_DROUND23_LAST, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 92 /* aes_eround01 */, SP::AES_EROUND01, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 105 /* aes_eround01_l */, SP::AES_EROUND01_LAST, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 120 /* aes_eround23 */, SP::AES_EROUND23, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 133 /* aes_eround23_l */, SP::AES_EROUND23_LAST, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 148 /* aes_kexpand0 */, SP::AES_KEXPAND0, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 161 /* aes_kexpand1 */, SP::AES_KEXPAND1, Convert__Reg1_3__Reg1_0__Reg1_1__Imm1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_Imm, MCK_DFPRegs }, },
  { 174 /* aes_kexpand2 */, SP::AES_KEXPAND2, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 187 /* alignaddr */, SP::ALIGNADDR, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 197 /* alignaddrl */, SP::ALIGNADDRL, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 208 /* allclean */, SP::ALLCLEAN, Convert_NoOperands, AMFBS_HasUA2005, {  }, },
  { 217 /* and */, SP::ANDrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 217 /* and */, SP::ANDri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 221 /* andcc */, SP::ANDCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 221 /* andcc */, SP::ANDCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 227 /* andn */, SP::ANDNrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 227 /* andn */, SP::ANDNri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 232 /* andncc */, SP::ANDNCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 232 /* andncc */, SP::ANDNCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 239 /* array16 */, SP::ARRAY16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 247 /* array32 */, SP::ARRAY32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 255 /* array8 */, SP::ARRAY8, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 262 /* b */, SP::BCOND, Convert__Imm1_0__imm_95_8, AMFBS_None, { MCK_Imm }, },
  { 262 /* b */, SP::BPICC, Convert__Imm1_1__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCC, Convert__Imm1_1__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCC, Convert__Imm1_1__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BCONDA, Convert__Imm1_1__imm_95_8, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 262 /* b */, SP::BPICC, Convert__Imm1_1__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 262 /* b */, SP::BCOND, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 262 /* b */, SP::BPICCA, Convert__Imm1_2__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCA, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCA, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BPICCA, Convert__Imm1_2__imm_95_8, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 262 /* b */, SP::BPICCNT, Convert__Imm1_2__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCNT, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCNT, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BPICCNT, Convert__Imm1_2__imm_95_8, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 262 /* b */, SP::BPICC, Convert__Imm1_2__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCC, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCC, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BPICC, Convert__Imm1_2__imm_95_8, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 262 /* b */, SP::BPXCC, Convert__Imm1_2__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BCONDA, Convert__Imm1_2__Imm1_0, AMFBS_None, { MCK_Imm, MCK_a, MCK_Imm }, },
  { 262 /* b */, SP::BPICC, Convert__Imm1_2__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_ICC, MCK_Imm }, },
  { 262 /* b */, SP::BPICCANT, Convert__Imm1_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCANT, Convert__Imm1_3__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCANT, Convert__Imm1_3__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BPICCANT, Convert__Imm1_3__imm_95_8, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 262 /* b */, SP::BPICCA, Convert__Imm1_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCA, Convert__Imm1_3__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCA, Convert__Imm1_3__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BPICCA, Convert__Imm1_3__imm_95_8, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCA, Convert__Imm1_3__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BPICCA, Convert__Imm1_3__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_a, MCK_ICC, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCNT, Convert__Imm1_3__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BPICCNT, Convert__Imm1_3__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 262 /* b */, SP::BPXCCANT, Convert__Imm1_4__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 262 /* b */, SP::BPICCANT, Convert__Imm1_4__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 264 /* ba */, SP::BA, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 264 /* ba */, SP::BCOND, Convert__Imm1_0__imm_95_8, AMFBS_None, { MCK_Imm }, },
  { 264 /* ba */, SP::BPICC, Convert__Imm1_1__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCC, Convert__Imm1_1__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCC, Convert__Imm1_1__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 264 /* ba */, SP::BCONDA, Convert__Imm1_1__imm_95_8, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 264 /* ba */, SP::BPICC, Convert__Imm1_1__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 264 /* ba */, SP::BPICCA, Convert__Imm1_2__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCCA, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCCA, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 264 /* ba */, SP::BPICCA, Convert__Imm1_2__imm_95_8, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 264 /* ba */, SP::BPICCNT, Convert__Imm1_2__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCCNT, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCCNT, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 264 /* ba */, SP::BPICCNT, Convert__Imm1_2__imm_95_8, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 264 /* ba */, SP::BPICC, Convert__Imm1_2__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCC, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCC, Convert__Imm1_2__imm_95_8, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 264 /* ba */, SP::BPICC, Convert__Imm1_2__imm_95_8, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 264 /* ba */, SP::BPICCANT, Convert__Imm1_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCCANT, Convert__Imm1_3__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCCANT, Convert__Imm1_3__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 264 /* ba */, SP::BPICCANT, Convert__Imm1_3__imm_95_8, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 264 /* ba */, SP::BPICCA, Convert__Imm1_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCCA, Convert__Imm1_3__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 264 /* ba */, SP::BPXCCA, Convert__Imm1_3__imm_95_8, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 264 /* ba */, SP::BPICCA, Convert__Imm1_3__imm_95_8, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 267 /* bcc */, SP::BCOND, Convert__Imm1_0__imm_95_13, AMFBS_None, { MCK_Imm }, },
  { 267 /* bcc */, SP::BPICC, Convert__Imm1_1__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCC, Convert__Imm1_1__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCC, Convert__Imm1_1__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 267 /* bcc */, SP::BCONDA, Convert__Imm1_1__imm_95_13, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICC, Convert__Imm1_1__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICCA, Convert__Imm1_2__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCCA, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCCA, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICCA, Convert__Imm1_2__imm_95_13, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICCNT, Convert__Imm1_2__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCCNT, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCCNT, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICCNT, Convert__Imm1_2__imm_95_13, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICC, Convert__Imm1_2__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCC, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCC, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICC, Convert__Imm1_2__imm_95_13, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICCANT, Convert__Imm1_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCCANT, Convert__Imm1_3__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCCANT, Convert__Imm1_3__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICCANT, Convert__Imm1_3__imm_95_13, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICCA, Convert__Imm1_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCCA, Convert__Imm1_3__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPXCCA, Convert__Imm1_3__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 267 /* bcc */, SP::BPICCA, Convert__Imm1_3__imm_95_13, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 271 /* bclr */, SP::ANDNrr, Convert__Reg1_1__Reg1_1__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_IntRegs }, },
  { 271 /* bclr */, SP::ANDNri, Convert__Reg1_1__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 276 /* bcs */, SP::BCOND, Convert__Imm1_0__imm_95_5, AMFBS_None, { MCK_Imm }, },
  { 276 /* bcs */, SP::BPICC, Convert__Imm1_1__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCC, Convert__Imm1_1__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCC, Convert__Imm1_1__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 276 /* bcs */, SP::BCONDA, Convert__Imm1_1__imm_95_5, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICC, Convert__Imm1_1__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICCA, Convert__Imm1_2__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCCA, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCCA, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICCA, Convert__Imm1_2__imm_95_5, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICCNT, Convert__Imm1_2__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCCNT, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCCNT, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICCNT, Convert__Imm1_2__imm_95_5, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICC, Convert__Imm1_2__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCC, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCC, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICC, Convert__Imm1_2__imm_95_5, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICCANT, Convert__Imm1_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCCANT, Convert__Imm1_3__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCCANT, Convert__Imm1_3__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICCANT, Convert__Imm1_3__imm_95_5, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICCA, Convert__Imm1_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCCA, Convert__Imm1_3__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPXCCA, Convert__Imm1_3__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 276 /* bcs */, SP::BPICCA, Convert__Imm1_3__imm_95_5, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 280 /* be */, SP::BCOND, Convert__Imm1_0__imm_95_1, AMFBS_None, { MCK_Imm }, },
  { 280 /* be */, SP::BPICC, Convert__Imm1_1__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCC, Convert__Imm1_1__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCC, Convert__Imm1_1__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 280 /* be */, SP::BCONDA, Convert__Imm1_1__imm_95_1, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 280 /* be */, SP::BPICC, Convert__Imm1_1__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 280 /* be */, SP::BPICCA, Convert__Imm1_2__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCCA, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCCA, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 280 /* be */, SP::BPICCA, Convert__Imm1_2__imm_95_1, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 280 /* be */, SP::BPICCNT, Convert__Imm1_2__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCCNT, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCCNT, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 280 /* be */, SP::BPICCNT, Convert__Imm1_2__imm_95_1, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 280 /* be */, SP::BPICC, Convert__Imm1_2__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCC, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCC, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 280 /* be */, SP::BPICC, Convert__Imm1_2__imm_95_1, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 280 /* be */, SP::BPICCANT, Convert__Imm1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCCANT, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCCANT, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 280 /* be */, SP::BPICCANT, Convert__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 280 /* be */, SP::BPICCA, Convert__Imm1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCCA, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 280 /* be */, SP::BPXCCA, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 280 /* be */, SP::BPICCA, Convert__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 283 /* beq */, SP::BCOND, Convert__Imm1_0__imm_95_1, AMFBS_None, { MCK_Imm }, },
  { 283 /* beq */, SP::BPICC, Convert__Imm1_1__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCC, Convert__Imm1_1__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCC, Convert__Imm1_1__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 283 /* beq */, SP::BCONDA, Convert__Imm1_1__imm_95_1, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 283 /* beq */, SP::BPICC, Convert__Imm1_1__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 283 /* beq */, SP::BPICCA, Convert__Imm1_2__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCCA, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCCA, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 283 /* beq */, SP::BPICCA, Convert__Imm1_2__imm_95_1, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 283 /* beq */, SP::BPICCNT, Convert__Imm1_2__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCCNT, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCCNT, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 283 /* beq */, SP::BPICCNT, Convert__Imm1_2__imm_95_1, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 283 /* beq */, SP::BPICC, Convert__Imm1_2__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCC, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCC, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 283 /* beq */, SP::BPICC, Convert__Imm1_2__imm_95_1, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 283 /* beq */, SP::BPICCANT, Convert__Imm1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCCANT, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCCANT, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 283 /* beq */, SP::BPICCANT, Convert__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 283 /* beq */, SP::BPICCA, Convert__Imm1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCCA, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 283 /* beq */, SP::BPXCCA, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 283 /* beq */, SP::BPICCA, Convert__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 287 /* bg */, SP::BCOND, Convert__Imm1_0__imm_95_10, AMFBS_None, { MCK_Imm }, },
  { 287 /* bg */, SP::BPICC, Convert__Imm1_1__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCC, Convert__Imm1_1__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCC, Convert__Imm1_1__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 287 /* bg */, SP::BCONDA, Convert__Imm1_1__imm_95_10, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 287 /* bg */, SP::BPICC, Convert__Imm1_1__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 287 /* bg */, SP::BPICCA, Convert__Imm1_2__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCCA, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCCA, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 287 /* bg */, SP::BPICCA, Convert__Imm1_2__imm_95_10, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 287 /* bg */, SP::BPICCNT, Convert__Imm1_2__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCCNT, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCCNT, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 287 /* bg */, SP::BPICCNT, Convert__Imm1_2__imm_95_10, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 287 /* bg */, SP::BPICC, Convert__Imm1_2__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCC, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCC, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 287 /* bg */, SP::BPICC, Convert__Imm1_2__imm_95_10, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 287 /* bg */, SP::BPICCANT, Convert__Imm1_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCCANT, Convert__Imm1_3__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCCANT, Convert__Imm1_3__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 287 /* bg */, SP::BPICCANT, Convert__Imm1_3__imm_95_10, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 287 /* bg */, SP::BPICCA, Convert__Imm1_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCCA, Convert__Imm1_3__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 287 /* bg */, SP::BPXCCA, Convert__Imm1_3__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 287 /* bg */, SP::BPICCA, Convert__Imm1_3__imm_95_10, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 290 /* bge */, SP::BCOND, Convert__Imm1_0__imm_95_11, AMFBS_None, { MCK_Imm }, },
  { 290 /* bge */, SP::BPICC, Convert__Imm1_1__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCC, Convert__Imm1_1__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCC, Convert__Imm1_1__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 290 /* bge */, SP::BCONDA, Convert__Imm1_1__imm_95_11, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 290 /* bge */, SP::BPICC, Convert__Imm1_1__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 290 /* bge */, SP::BPICCA, Convert__Imm1_2__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCCA, Convert__Imm1_2__imm_95_11, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCCA, Convert__Imm1_2__imm_95_11, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 290 /* bge */, SP::BPICCA, Convert__Imm1_2__imm_95_11, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 290 /* bge */, SP::BPICCNT, Convert__Imm1_2__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCCNT, Convert__Imm1_2__imm_95_11, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCCNT, Convert__Imm1_2__imm_95_11, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 290 /* bge */, SP::BPICCNT, Convert__Imm1_2__imm_95_11, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 290 /* bge */, SP::BPICC, Convert__Imm1_2__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCC, Convert__Imm1_2__imm_95_11, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCC, Convert__Imm1_2__imm_95_11, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 290 /* bge */, SP::BPICC, Convert__Imm1_2__imm_95_11, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 290 /* bge */, SP::BPICCANT, Convert__Imm1_3__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCCANT, Convert__Imm1_3__imm_95_11, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCCANT, Convert__Imm1_3__imm_95_11, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 290 /* bge */, SP::BPICCANT, Convert__Imm1_3__imm_95_11, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 290 /* bge */, SP::BPICCA, Convert__Imm1_3__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCCA, Convert__Imm1_3__imm_95_11, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 290 /* bge */, SP::BPXCCA, Convert__Imm1_3__imm_95_11, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 290 /* bge */, SP::BPICCA, Convert__Imm1_3__imm_95_11, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 294 /* bgeu */, SP::BCOND, Convert__Imm1_0__imm_95_13, AMFBS_None, { MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICC, Convert__Imm1_1__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCC, Convert__Imm1_1__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCC, Convert__Imm1_1__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BCONDA, Convert__Imm1_1__imm_95_13, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICC, Convert__Imm1_1__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICCA, Convert__Imm1_2__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCCA, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCCA, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICCA, Convert__Imm1_2__imm_95_13, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICCNT, Convert__Imm1_2__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCCNT, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCCNT, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICCNT, Convert__Imm1_2__imm_95_13, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICC, Convert__Imm1_2__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCC, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCC, Convert__Imm1_2__imm_95_13, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICC, Convert__Imm1_2__imm_95_13, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICCANT, Convert__Imm1_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCCANT, Convert__Imm1_3__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCCANT, Convert__Imm1_3__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICCANT, Convert__Imm1_3__imm_95_13, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICCA, Convert__Imm1_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCCA, Convert__Imm1_3__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPXCCA, Convert__Imm1_3__imm_95_13, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 294 /* bgeu */, SP::BPICCA, Convert__Imm1_3__imm_95_13, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 299 /* bgt */, SP::BCOND, Convert__Imm1_0__imm_95_10, AMFBS_None, { MCK_Imm }, },
  { 299 /* bgt */, SP::BPICC, Convert__Imm1_1__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCC, Convert__Imm1_1__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCC, Convert__Imm1_1__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 299 /* bgt */, SP::BCONDA, Convert__Imm1_1__imm_95_10, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICC, Convert__Imm1_1__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICCA, Convert__Imm1_2__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCCA, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCCA, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICCA, Convert__Imm1_2__imm_95_10, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICCNT, Convert__Imm1_2__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCCNT, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCCNT, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICCNT, Convert__Imm1_2__imm_95_10, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICC, Convert__Imm1_2__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCC, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCC, Convert__Imm1_2__imm_95_10, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICC, Convert__Imm1_2__imm_95_10, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICCANT, Convert__Imm1_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCCANT, Convert__Imm1_3__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCCANT, Convert__Imm1_3__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICCANT, Convert__Imm1_3__imm_95_10, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICCA, Convert__Imm1_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCCA, Convert__Imm1_3__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPXCCA, Convert__Imm1_3__imm_95_10, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 299 /* bgt */, SP::BPICCA, Convert__Imm1_3__imm_95_10, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 303 /* bgu */, SP::BCOND, Convert__Imm1_0__imm_95_12, AMFBS_None, { MCK_Imm }, },
  { 303 /* bgu */, SP::BPICC, Convert__Imm1_1__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCC, Convert__Imm1_1__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCC, Convert__Imm1_1__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 303 /* bgu */, SP::BCONDA, Convert__Imm1_1__imm_95_12, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICC, Convert__Imm1_1__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICCA, Convert__Imm1_2__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCCA, Convert__Imm1_2__imm_95_12, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCCA, Convert__Imm1_2__imm_95_12, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICCA, Convert__Imm1_2__imm_95_12, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICCNT, Convert__Imm1_2__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCCNT, Convert__Imm1_2__imm_95_12, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCCNT, Convert__Imm1_2__imm_95_12, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICCNT, Convert__Imm1_2__imm_95_12, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICC, Convert__Imm1_2__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCC, Convert__Imm1_2__imm_95_12, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCC, Convert__Imm1_2__imm_95_12, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICC, Convert__Imm1_2__imm_95_12, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICCANT, Convert__Imm1_3__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCCANT, Convert__Imm1_3__imm_95_12, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCCANT, Convert__Imm1_3__imm_95_12, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICCANT, Convert__Imm1_3__imm_95_12, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICCA, Convert__Imm1_3__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCCA, Convert__Imm1_3__imm_95_12, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPXCCA, Convert__Imm1_3__imm_95_12, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 303 /* bgu */, SP::BPICCA, Convert__Imm1_3__imm_95_12, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 307 /* bl */, SP::BCOND, Convert__Imm1_0__imm_95_3, AMFBS_None, { MCK_Imm }, },
  { 307 /* bl */, SP::BPICC, Convert__Imm1_1__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCC, Convert__Imm1_1__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCC, Convert__Imm1_1__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 307 /* bl */, SP::BCONDA, Convert__Imm1_1__imm_95_3, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 307 /* bl */, SP::BPICC, Convert__Imm1_1__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 307 /* bl */, SP::BPICCA, Convert__Imm1_2__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCCA, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCCA, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 307 /* bl */, SP::BPICCA, Convert__Imm1_2__imm_95_3, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 307 /* bl */, SP::BPICCNT, Convert__Imm1_2__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCCNT, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCCNT, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 307 /* bl */, SP::BPICCNT, Convert__Imm1_2__imm_95_3, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 307 /* bl */, SP::BPICC, Convert__Imm1_2__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCC, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCC, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 307 /* bl */, SP::BPICC, Convert__Imm1_2__imm_95_3, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 307 /* bl */, SP::BPICCANT, Convert__Imm1_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCCANT, Convert__Imm1_3__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCCANT, Convert__Imm1_3__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 307 /* bl */, SP::BPICCANT, Convert__Imm1_3__imm_95_3, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 307 /* bl */, SP::BPICCA, Convert__Imm1_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCCA, Convert__Imm1_3__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 307 /* bl */, SP::BPXCCA, Convert__Imm1_3__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 307 /* bl */, SP::BPICCA, Convert__Imm1_3__imm_95_3, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 310 /* ble */, SP::BCOND, Convert__Imm1_0__imm_95_2, AMFBS_None, { MCK_Imm }, },
  { 310 /* ble */, SP::BPICC, Convert__Imm1_1__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCC, Convert__Imm1_1__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCC, Convert__Imm1_1__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 310 /* ble */, SP::BCONDA, Convert__Imm1_1__imm_95_2, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 310 /* ble */, SP::BPICC, Convert__Imm1_1__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 310 /* ble */, SP::BPICCA, Convert__Imm1_2__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCCA, Convert__Imm1_2__imm_95_2, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCCA, Convert__Imm1_2__imm_95_2, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 310 /* ble */, SP::BPICCA, Convert__Imm1_2__imm_95_2, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 310 /* ble */, SP::BPICCNT, Convert__Imm1_2__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCCNT, Convert__Imm1_2__imm_95_2, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCCNT, Convert__Imm1_2__imm_95_2, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 310 /* ble */, SP::BPICCNT, Convert__Imm1_2__imm_95_2, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 310 /* ble */, SP::BPICC, Convert__Imm1_2__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCC, Convert__Imm1_2__imm_95_2, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCC, Convert__Imm1_2__imm_95_2, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 310 /* ble */, SP::BPICC, Convert__Imm1_2__imm_95_2, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 310 /* ble */, SP::BPICCANT, Convert__Imm1_3__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCCANT, Convert__Imm1_3__imm_95_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCCANT, Convert__Imm1_3__imm_95_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 310 /* ble */, SP::BPICCANT, Convert__Imm1_3__imm_95_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 310 /* ble */, SP::BPICCA, Convert__Imm1_3__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCCA, Convert__Imm1_3__imm_95_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 310 /* ble */, SP::BPXCCA, Convert__Imm1_3__imm_95_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 310 /* ble */, SP::BPICCA, Convert__Imm1_3__imm_95_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 314 /* bleu */, SP::BCOND, Convert__Imm1_0__imm_95_4, AMFBS_None, { MCK_Imm }, },
  { 314 /* bleu */, SP::BPICC, Convert__Imm1_1__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCC, Convert__Imm1_1__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCC, Convert__Imm1_1__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 314 /* bleu */, SP::BCONDA, Convert__Imm1_1__imm_95_4, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICC, Convert__Imm1_1__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICCA, Convert__Imm1_2__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCCA, Convert__Imm1_2__imm_95_4, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCCA, Convert__Imm1_2__imm_95_4, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICCA, Convert__Imm1_2__imm_95_4, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICCNT, Convert__Imm1_2__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCCNT, Convert__Imm1_2__imm_95_4, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCCNT, Convert__Imm1_2__imm_95_4, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICCNT, Convert__Imm1_2__imm_95_4, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICC, Convert__Imm1_2__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCC, Convert__Imm1_2__imm_95_4, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCC, Convert__Imm1_2__imm_95_4, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICC, Convert__Imm1_2__imm_95_4, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICCANT, Convert__Imm1_3__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCCANT, Convert__Imm1_3__imm_95_4, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCCANT, Convert__Imm1_3__imm_95_4, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICCANT, Convert__Imm1_3__imm_95_4, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICCA, Convert__Imm1_3__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCCA, Convert__Imm1_3__imm_95_4, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPXCCA, Convert__Imm1_3__imm_95_4, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 314 /* bleu */, SP::BPICCA, Convert__Imm1_3__imm_95_4, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 319 /* blt */, SP::BCOND, Convert__Imm1_0__imm_95_3, AMFBS_None, { MCK_Imm }, },
  { 319 /* blt */, SP::BPICC, Convert__Imm1_1__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCC, Convert__Imm1_1__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCC, Convert__Imm1_1__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 319 /* blt */, SP::BCONDA, Convert__Imm1_1__imm_95_3, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 319 /* blt */, SP::BPICC, Convert__Imm1_1__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 319 /* blt */, SP::BPICCA, Convert__Imm1_2__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCCA, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCCA, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 319 /* blt */, SP::BPICCA, Convert__Imm1_2__imm_95_3, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 319 /* blt */, SP::BPICCNT, Convert__Imm1_2__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCCNT, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCCNT, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 319 /* blt */, SP::BPICCNT, Convert__Imm1_2__imm_95_3, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 319 /* blt */, SP::BPICC, Convert__Imm1_2__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCC, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCC, Convert__Imm1_2__imm_95_3, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 319 /* blt */, SP::BPICC, Convert__Imm1_2__imm_95_3, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 319 /* blt */, SP::BPICCANT, Convert__Imm1_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCCANT, Convert__Imm1_3__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCCANT, Convert__Imm1_3__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 319 /* blt */, SP::BPICCANT, Convert__Imm1_3__imm_95_3, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 319 /* blt */, SP::BPICCA, Convert__Imm1_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCCA, Convert__Imm1_3__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 319 /* blt */, SP::BPXCCA, Convert__Imm1_3__imm_95_3, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 319 /* blt */, SP::BPICCA, Convert__Imm1_3__imm_95_3, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 323 /* blu */, SP::BCOND, Convert__Imm1_0__imm_95_5, AMFBS_None, { MCK_Imm }, },
  { 323 /* blu */, SP::BPICC, Convert__Imm1_1__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCC, Convert__Imm1_1__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCC, Convert__Imm1_1__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 323 /* blu */, SP::BCONDA, Convert__Imm1_1__imm_95_5, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 323 /* blu */, SP::BPICC, Convert__Imm1_1__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 323 /* blu */, SP::BPICCA, Convert__Imm1_2__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCCA, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCCA, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 323 /* blu */, SP::BPICCA, Convert__Imm1_2__imm_95_5, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 323 /* blu */, SP::BPICCNT, Convert__Imm1_2__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCCNT, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCCNT, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 323 /* blu */, SP::BPICCNT, Convert__Imm1_2__imm_95_5, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 323 /* blu */, SP::BPICC, Convert__Imm1_2__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCC, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCC, Convert__Imm1_2__imm_95_5, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 323 /* blu */, SP::BPICC, Convert__Imm1_2__imm_95_5, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 323 /* blu */, SP::BPICCANT, Convert__Imm1_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCCANT, Convert__Imm1_3__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCCANT, Convert__Imm1_3__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 323 /* blu */, SP::BPICCANT, Convert__Imm1_3__imm_95_5, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 323 /* blu */, SP::BPICCA, Convert__Imm1_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCCA, Convert__Imm1_3__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 323 /* blu */, SP::BPXCCA, Convert__Imm1_3__imm_95_5, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 323 /* blu */, SP::BPICCA, Convert__Imm1_3__imm_95_5, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 327 /* bmask */, SP::BMASK, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 333 /* bn */, SP::BCOND, Convert__Imm1_0__imm_95_0, AMFBS_None, { MCK_Imm }, },
  { 333 /* bn */, SP::BPICC, Convert__Imm1_1__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCC, Convert__Imm1_1__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCC, Convert__Imm1_1__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 333 /* bn */, SP::BCONDA, Convert__Imm1_1__imm_95_0, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 333 /* bn */, SP::BPICC, Convert__Imm1_1__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 333 /* bn */, SP::BPICCA, Convert__Imm1_2__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCCA, Convert__Imm1_2__imm_95_0, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCCA, Convert__Imm1_2__imm_95_0, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 333 /* bn */, SP::BPICCA, Convert__Imm1_2__imm_95_0, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 333 /* bn */, SP::BPICCNT, Convert__Imm1_2__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCCNT, Convert__Imm1_2__imm_95_0, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCCNT, Convert__Imm1_2__imm_95_0, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 333 /* bn */, SP::BPICCNT, Convert__Imm1_2__imm_95_0, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 333 /* bn */, SP::BPICC, Convert__Imm1_2__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCC, Convert__Imm1_2__imm_95_0, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCC, Convert__Imm1_2__imm_95_0, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 333 /* bn */, SP::BPICC, Convert__Imm1_2__imm_95_0, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 333 /* bn */, SP::BPICCANT, Convert__Imm1_3__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCCANT, Convert__Imm1_3__imm_95_0, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCCANT, Convert__Imm1_3__imm_95_0, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 333 /* bn */, SP::BPICCANT, Convert__Imm1_3__imm_95_0, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 333 /* bn */, SP::BPICCA, Convert__Imm1_3__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCCA, Convert__Imm1_3__imm_95_0, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 333 /* bn */, SP::BPXCCA, Convert__Imm1_3__imm_95_0, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 333 /* bn */, SP::BPICCA, Convert__Imm1_3__imm_95_0, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 336 /* bne */, SP::BCOND, Convert__Imm1_0__imm_95_9, AMFBS_None, { MCK_Imm }, },
  { 336 /* bne */, SP::BPICC, Convert__Imm1_1__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCC, Convert__Imm1_1__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCC, Convert__Imm1_1__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 336 /* bne */, SP::BCONDA, Convert__Imm1_1__imm_95_9, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 336 /* bne */, SP::BPICC, Convert__Imm1_1__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 336 /* bne */, SP::BPICCA, Convert__Imm1_2__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCCA, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCCA, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 336 /* bne */, SP::BPICCA, Convert__Imm1_2__imm_95_9, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 336 /* bne */, SP::BPICCNT, Convert__Imm1_2__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCCNT, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCCNT, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 336 /* bne */, SP::BPICCNT, Convert__Imm1_2__imm_95_9, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 336 /* bne */, SP::BPICC, Convert__Imm1_2__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCC, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCC, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 336 /* bne */, SP::BPICC, Convert__Imm1_2__imm_95_9, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 336 /* bne */, SP::BPICCANT, Convert__Imm1_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCCANT, Convert__Imm1_3__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCCANT, Convert__Imm1_3__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 336 /* bne */, SP::BPICCANT, Convert__Imm1_3__imm_95_9, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 336 /* bne */, SP::BPICCA, Convert__Imm1_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCCA, Convert__Imm1_3__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 336 /* bne */, SP::BPXCCA, Convert__Imm1_3__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 336 /* bne */, SP::BPICCA, Convert__Imm1_3__imm_95_9, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 340 /* bneg */, SP::BCOND, Convert__Imm1_0__imm_95_6, AMFBS_None, { MCK_Imm }, },
  { 340 /* bneg */, SP::BPICC, Convert__Imm1_1__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCC, Convert__Imm1_1__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCC, Convert__Imm1_1__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 340 /* bneg */, SP::BCONDA, Convert__Imm1_1__imm_95_6, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICC, Convert__Imm1_1__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICCA, Convert__Imm1_2__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCCA, Convert__Imm1_2__imm_95_6, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCCA, Convert__Imm1_2__imm_95_6, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICCA, Convert__Imm1_2__imm_95_6, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICCNT, Convert__Imm1_2__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCCNT, Convert__Imm1_2__imm_95_6, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCCNT, Convert__Imm1_2__imm_95_6, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICCNT, Convert__Imm1_2__imm_95_6, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICC, Convert__Imm1_2__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCC, Convert__Imm1_2__imm_95_6, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCC, Convert__Imm1_2__imm_95_6, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICC, Convert__Imm1_2__imm_95_6, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICCANT, Convert__Imm1_3__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCCANT, Convert__Imm1_3__imm_95_6, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCCANT, Convert__Imm1_3__imm_95_6, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICCANT, Convert__Imm1_3__imm_95_6, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICCA, Convert__Imm1_3__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCCA, Convert__Imm1_3__imm_95_6, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPXCCA, Convert__Imm1_3__imm_95_6, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 340 /* bneg */, SP::BPICCA, Convert__Imm1_3__imm_95_6, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 345 /* bnz */, SP::BCOND, Convert__Imm1_0__imm_95_9, AMFBS_None, { MCK_Imm }, },
  { 345 /* bnz */, SP::BPICC, Convert__Imm1_1__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCC, Convert__Imm1_1__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCC, Convert__Imm1_1__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 345 /* bnz */, SP::BCONDA, Convert__Imm1_1__imm_95_9, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICC, Convert__Imm1_1__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICCA, Convert__Imm1_2__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCCA, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCCA, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICCA, Convert__Imm1_2__imm_95_9, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICCNT, Convert__Imm1_2__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCCNT, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCCNT, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICCNT, Convert__Imm1_2__imm_95_9, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICC, Convert__Imm1_2__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCC, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCC, Convert__Imm1_2__imm_95_9, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICC, Convert__Imm1_2__imm_95_9, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICCANT, Convert__Imm1_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCCANT, Convert__Imm1_3__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCCANT, Convert__Imm1_3__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICCANT, Convert__Imm1_3__imm_95_9, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICCA, Convert__Imm1_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCCA, Convert__Imm1_3__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPXCCA, Convert__Imm1_3__imm_95_9, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 345 /* bnz */, SP::BPICCA, Convert__Imm1_3__imm_95_9, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 349 /* bpos */, SP::BCOND, Convert__Imm1_0__imm_95_14, AMFBS_None, { MCK_Imm }, },
  { 349 /* bpos */, SP::BPICC, Convert__Imm1_1__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCC, Convert__Imm1_1__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCC, Convert__Imm1_1__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 349 /* bpos */, SP::BCONDA, Convert__Imm1_1__imm_95_14, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICC, Convert__Imm1_1__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICCA, Convert__Imm1_2__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCCA, Convert__Imm1_2__imm_95_14, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCCA, Convert__Imm1_2__imm_95_14, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICCA, Convert__Imm1_2__imm_95_14, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICCNT, Convert__Imm1_2__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCCNT, Convert__Imm1_2__imm_95_14, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCCNT, Convert__Imm1_2__imm_95_14, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICCNT, Convert__Imm1_2__imm_95_14, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICC, Convert__Imm1_2__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCC, Convert__Imm1_2__imm_95_14, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCC, Convert__Imm1_2__imm_95_14, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICC, Convert__Imm1_2__imm_95_14, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICCANT, Convert__Imm1_3__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCCANT, Convert__Imm1_3__imm_95_14, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCCANT, Convert__Imm1_3__imm_95_14, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICCANT, Convert__Imm1_3__imm_95_14, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICCA, Convert__Imm1_3__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCCA, Convert__Imm1_3__imm_95_14, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPXCCA, Convert__Imm1_3__imm_95_14, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 349 /* bpos */, SP::BPICCA, Convert__Imm1_3__imm_95_14, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 354 /* br */, SP::BPR, Convert__Imm1_2__Imm1_0__Reg1_1, AMFBS_HasV9, { MCK_Imm, MCK_IntRegs, MCK_Imm }, },
  { 354 /* br */, SP::BPRA, Convert__Imm1_3__Imm1_0__Reg1_2, AMFBS_HasV9, { MCK_Imm, MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 354 /* br */, SP::BPRNT, Convert__Imm1_3__Imm1_0__Reg1_2, AMFBS_HasV9, { MCK_Imm, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 354 /* br */, SP::BPRANT, Convert__Imm1_4__Imm1_0__Reg1_3, AMFBS_HasV9, { MCK_Imm, MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 357 /* bre */, SP::BPR, Convert__Imm1_1__imm_95_1__Reg1_0, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm }, },
  { 357 /* bre */, SP::BPRA, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_Is64Bit, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 357 /* bre */, SP::BPRNT, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_Is64Bit, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 357 /* bre */, SP::BPR, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_Is64Bit, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 357 /* bre */, SP::BPRANT, Convert__Imm1_3__imm_95_1__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 357 /* bre */, SP::BPRA, Convert__Imm1_3__imm_95_1__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 361 /* brgez */, SP::BPR, Convert__Imm1_1__imm_95_7__Reg1_0, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm }, },
  { 361 /* brgez */, SP::BPRA, Convert__Imm1_2__imm_95_7__Reg1_1, AMFBS_Is64Bit, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 361 /* brgez */, SP::BPRNT, Convert__Imm1_2__imm_95_7__Reg1_1, AMFBS_Is64Bit, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 361 /* brgez */, SP::BPR, Convert__Imm1_2__imm_95_7__Reg1_1, AMFBS_Is64Bit, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 361 /* brgez */, SP::BPRANT, Convert__Imm1_3__imm_95_7__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 361 /* brgez */, SP::BPRA, Convert__Imm1_3__imm_95_7__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 367 /* brgz */, SP::BPR, Convert__Imm1_1__imm_95_6__Reg1_0, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm }, },
  { 367 /* brgz */, SP::BPRA, Convert__Imm1_2__imm_95_6__Reg1_1, AMFBS_Is64Bit, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 367 /* brgz */, SP::BPRNT, Convert__Imm1_2__imm_95_6__Reg1_1, AMFBS_Is64Bit, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 367 /* brgz */, SP::BPR, Convert__Imm1_2__imm_95_6__Reg1_1, AMFBS_Is64Bit, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 367 /* brgz */, SP::BPRANT, Convert__Imm1_3__imm_95_6__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 367 /* brgz */, SP::BPRA, Convert__Imm1_3__imm_95_6__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 372 /* brlez */, SP::BPR, Convert__Imm1_1__imm_95_2__Reg1_0, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm }, },
  { 372 /* brlez */, SP::BPRA, Convert__Imm1_2__imm_95_2__Reg1_1, AMFBS_Is64Bit, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 372 /* brlez */, SP::BPRNT, Convert__Imm1_2__imm_95_2__Reg1_1, AMFBS_Is64Bit, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 372 /* brlez */, SP::BPR, Convert__Imm1_2__imm_95_2__Reg1_1, AMFBS_Is64Bit, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 372 /* brlez */, SP::BPRANT, Convert__Imm1_3__imm_95_2__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 372 /* brlez */, SP::BPRA, Convert__Imm1_3__imm_95_2__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 378 /* brlz */, SP::BPR, Convert__Imm1_1__imm_95_3__Reg1_0, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm }, },
  { 378 /* brlz */, SP::BPRA, Convert__Imm1_2__imm_95_3__Reg1_1, AMFBS_Is64Bit, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 378 /* brlz */, SP::BPRNT, Convert__Imm1_2__imm_95_3__Reg1_1, AMFBS_Is64Bit, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 378 /* brlz */, SP::BPR, Convert__Imm1_2__imm_95_3__Reg1_1, AMFBS_Is64Bit, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 378 /* brlz */, SP::BPRANT, Convert__Imm1_3__imm_95_3__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 378 /* brlz */, SP::BPRA, Convert__Imm1_3__imm_95_3__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 383 /* brne */, SP::BPR, Convert__Imm1_1__imm_95_5__Reg1_0, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm }, },
  { 383 /* brne */, SP::BPRA, Convert__Imm1_2__imm_95_5__Reg1_1, AMFBS_Is64Bit, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 383 /* brne */, SP::BPRNT, Convert__Imm1_2__imm_95_5__Reg1_1, AMFBS_Is64Bit, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 383 /* brne */, SP::BPR, Convert__Imm1_2__imm_95_5__Reg1_1, AMFBS_Is64Bit, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 383 /* brne */, SP::BPRANT, Convert__Imm1_3__imm_95_5__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 383 /* brne */, SP::BPRA, Convert__Imm1_3__imm_95_5__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 388 /* brnz */, SP::BPR, Convert__Imm1_1__imm_95_5__Reg1_0, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm }, },
  { 388 /* brnz */, SP::BPRA, Convert__Imm1_2__imm_95_5__Reg1_1, AMFBS_Is64Bit, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 388 /* brnz */, SP::BPRNT, Convert__Imm1_2__imm_95_5__Reg1_1, AMFBS_Is64Bit, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 388 /* brnz */, SP::BPR, Convert__Imm1_2__imm_95_5__Reg1_1, AMFBS_Is64Bit, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 388 /* brnz */, SP::BPRANT, Convert__Imm1_3__imm_95_5__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 388 /* brnz */, SP::BPRA, Convert__Imm1_3__imm_95_5__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 393 /* brz */, SP::BPR, Convert__Imm1_1__imm_95_1__Reg1_0, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm }, },
  { 393 /* brz */, SP::BPRA, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_Is64Bit, { MCK_a, MCK_IntRegs, MCK_Imm }, },
  { 393 /* brz */, SP::BPRNT, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_Is64Bit, { MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 393 /* brz */, SP::BPR, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_Is64Bit, { MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 393 /* brz */, SP::BPRANT, Convert__Imm1_3__imm_95_1__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK_IntRegs, MCK_Imm }, },
  { 393 /* brz */, SP::BPRA, Convert__Imm1_3__imm_95_1__Reg1_2, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK_IntRegs, MCK_Imm }, },
  { 397 /* bset */, SP::ORrr, Convert__Reg1_1__Reg1_1__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_IntRegs }, },
  { 397 /* bset */, SP::ORri, Convert__Reg1_1__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 402 /* bshuffle */, SP::BSHUFFLE, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS2, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 411 /* btog */, SP::XORrr, Convert__Reg1_1__Reg1_1__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_IntRegs }, },
  { 411 /* btog */, SP::XORri, Convert__Reg1_1__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 416 /* btst */, SP::ANDCCrr, Convert__regG0__Reg1_1__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_IntRegs }, },
  { 416 /* btst */, SP::ANDCCri, Convert__regG0__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 421 /* bvc */, SP::BCOND, Convert__Imm1_0__imm_95_15, AMFBS_None, { MCK_Imm }, },
  { 421 /* bvc */, SP::BPICC, Convert__Imm1_1__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCC, Convert__Imm1_1__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCC, Convert__Imm1_1__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 421 /* bvc */, SP::BCONDA, Convert__Imm1_1__imm_95_15, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICC, Convert__Imm1_1__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICCA, Convert__Imm1_2__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCCA, Convert__Imm1_2__imm_95_15, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCCA, Convert__Imm1_2__imm_95_15, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICCA, Convert__Imm1_2__imm_95_15, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICCNT, Convert__Imm1_2__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCCNT, Convert__Imm1_2__imm_95_15, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCCNT, Convert__Imm1_2__imm_95_15, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICCNT, Convert__Imm1_2__imm_95_15, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICC, Convert__Imm1_2__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCC, Convert__Imm1_2__imm_95_15, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCC, Convert__Imm1_2__imm_95_15, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICC, Convert__Imm1_2__imm_95_15, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICCANT, Convert__Imm1_3__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCCANT, Convert__Imm1_3__imm_95_15, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCCANT, Convert__Imm1_3__imm_95_15, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICCANT, Convert__Imm1_3__imm_95_15, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICCA, Convert__Imm1_3__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCCA, Convert__Imm1_3__imm_95_15, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPXCCA, Convert__Imm1_3__imm_95_15, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 421 /* bvc */, SP::BPICCA, Convert__Imm1_3__imm_95_15, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 425 /* bvs */, SP::BCOND, Convert__Imm1_0__imm_95_7, AMFBS_None, { MCK_Imm }, },
  { 425 /* bvs */, SP::BPICC, Convert__Imm1_1__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCC, Convert__Imm1_1__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCC, Convert__Imm1_1__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 425 /* bvs */, SP::BCONDA, Convert__Imm1_1__imm_95_7, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICC, Convert__Imm1_1__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICCA, Convert__Imm1_2__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCCA, Convert__Imm1_2__imm_95_7, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCCA, Convert__Imm1_2__imm_95_7, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICCA, Convert__Imm1_2__imm_95_7, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICCNT, Convert__Imm1_2__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCCNT, Convert__Imm1_2__imm_95_7, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCCNT, Convert__Imm1_2__imm_95_7, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICCNT, Convert__Imm1_2__imm_95_7, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICC, Convert__Imm1_2__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCC, Convert__Imm1_2__imm_95_7, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCC, Convert__Imm1_2__imm_95_7, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICC, Convert__Imm1_2__imm_95_7, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICCANT, Convert__Imm1_3__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCCANT, Convert__Imm1_3__imm_95_7, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCCANT, Convert__Imm1_3__imm_95_7, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICCANT, Convert__Imm1_3__imm_95_7, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICCA, Convert__Imm1_3__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCCA, Convert__Imm1_3__imm_95_7, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPXCCA, Convert__Imm1_3__imm_95_7, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 425 /* bvs */, SP::BPICCA, Convert__Imm1_3__imm_95_7, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 429 /* bz */, SP::BCOND, Convert__Imm1_0__imm_95_1, AMFBS_None, { MCK_Imm }, },
  { 429 /* bz */, SP::BPICC, Convert__Imm1_1__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCC, Convert__Imm1_1__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCC, Convert__Imm1_1__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm }, },
  { 429 /* bz */, SP::BCONDA, Convert__Imm1_1__imm_95_1, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 429 /* bz */, SP::BPICC, Convert__Imm1_1__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 429 /* bz */, SP::BPICCA, Convert__Imm1_2__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCCA, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCCA, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK__PCT_xcc, MCK_Imm }, },
  { 429 /* bz */, SP::BPICCA, Convert__Imm1_2__imm_95_1, AMFBS_HasV9, { MCK_a, MCK_ICC, MCK_Imm }, },
  { 429 /* bz */, SP::BPICCNT, Convert__Imm1_2__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCCNT, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCCNT, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 429 /* bz */, SP::BPICCNT, Convert__Imm1_2__imm_95_1, AMFBS_HasV9, { MCK_pn, MCK_ICC, MCK_Imm }, },
  { 429 /* bz */, SP::BPICC, Convert__Imm1_2__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCC, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCC, Convert__Imm1_2__imm_95_1, AMFBS_Is64Bit, { MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 429 /* bz */, SP::BPICC, Convert__Imm1_2__imm_95_1, AMFBS_HasV9, { MCK_pt, MCK_ICC, MCK_Imm }, },
  { 429 /* bz */, SP::BPICCANT, Convert__Imm1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCCANT, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCCANT, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pn, MCK__PCT_xcc, MCK_Imm }, },
  { 429 /* bz */, SP::BPICCANT, Convert__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_ICC, MCK_Imm }, },
  { 429 /* bz */, SP::BPICCA, Convert__Imm1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCCA, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_ncc, MCK_Imm }, },
  { 429 /* bz */, SP::BPXCCA, Convert__Imm1_3__imm_95_1, AMFBS_Is64Bit, { MCK_a, MCK_pt, MCK__PCT_xcc, MCK_Imm }, },
  { 429 /* bz */, SP::BPICCA, Convert__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_ICC, MCK_Imm }, },
  { 432 /* call */, SP::CALL, Convert__CallTarget1_0, AMFBS_None, { MCK_CallTarget }, },
  { 432 /* call */, SP::JMPLri, Convert__regO7__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 432 /* call */, SP::JMPLrr, Convert__regO7__MEMrr2_0, AMFBS_None, { MCK_MEMrr }, },
  { 432 /* call */, SP::CALLi, Convert__CallTarget1_0__Imm1_1, AMFBS_None, { MCK_CallTarget, MCK_Imm }, },
  { 432 /* call */, SP::TLS_CALL, Convert__CallTarget1_0__TailRelocSymCall_TLS1_1, AMFBS_None, { MCK_CallTarget, MCK_TailRelocSymCall_TLS }, },
  { 432 /* call */, SP::CALLrii, Convert__MEMri2_0__Imm1_1, AMFBS_None, { MCK_MEMri, MCK_Imm }, },
  { 432 /* call */, SP::CALLrri, Convert__MEMrr2_0__Imm1_1, AMFBS_None, { MCK_MEMrr, MCK_Imm }, },
  { 437 /* camellia_f */, SP::CAMELLIA_F, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 448 /* camellia_fl */, SP::CAMELLIA_FL, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 460 /* camellia_fli */, SP::CAMELLIA_FLI, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 473 /* cas */, SP::CASArr, Convert__Reg1_4__Reg1_1__Reg1_3__Tie0_5_5__imm_95_128, AMFBS_HasV9, { MCK__91_, MCK_IntRegs, MCK__93_, MCK_IntRegs, MCK_IntRegs }, },
  { 477 /* casa */, SP::CASAri, Convert__Reg1_5__Reg1_1__Reg1_4__Tie0_1_1, AMFBS_HasV9, { MCK__91_, MCK_IntRegs, MCK__93_, MCK__PCT_asi, MCK_IntRegs, MCK_IntRegs }, },
  { 477 /* casa */, SP::CASArr, Convert__Reg1_5__Reg1_1__Reg1_4__Tie0_1_1__ASITag1_3, AMFBS_HasCASA, { MCK__91_, MCK_IntRegs, MCK__93_, MCK_ASITag, MCK_IntRegs, MCK_IntRegs }, },
  { 482 /* casl */, SP::CASArr, Convert__Reg1_4__Reg1_1__Reg1_3__Tie0_5_5__imm_95_136, AMFBS_HasV9, { MCK__91_, MCK_IntRegs, MCK__93_, MCK_IntRegs, MCK_IntRegs }, },
  { 487 /* casx */, SP::CASXArr, Convert__Reg1_4__Reg1_1__Reg1_3__Tie0_5_5__imm_95_128, AMFBS_HasV9, { MCK__91_, MCK_IntRegs, MCK__93_, MCK_IntRegs, MCK_IntRegs }, },
  { 492 /* casxa */, SP::CASXAri, Convert__Reg1_5__Reg1_1__Reg1_4__Tie0_1_1, AMFBS_HasV9, { MCK__91_, MCK_IntRegs, MCK__93_, MCK__PCT_asi, MCK_IntRegs, MCK_IntRegs }, },
  { 492 /* casxa */, SP::CASXArr, Convert__Reg1_5__Reg1_1__Reg1_4__Tie0_1_1__ASITag1_3, AMFBS_HasV9, { MCK__91_, MCK_IntRegs, MCK__93_, MCK_ASITag, MCK_IntRegs, MCK_IntRegs }, },
  { 498 /* casxl */, SP::CASXArr, Convert__Reg1_4__Reg1_1__Reg1_3__Tie0_5_5__imm_95_136, AMFBS_HasV9, { MCK__91_, MCK_IntRegs, MCK__93_, MCK_IntRegs, MCK_IntRegs }, },
  { 504 /* cb */, SP::CPBCOND, Convert__Imm1_0__imm_95_8, AMFBS_None, { MCK_Imm }, },
  { 504 /* cb */, SP::CPBCONDA, Convert__Imm1_1__imm_95_8, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 504 /* cb */, SP::CPBCOND, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 504 /* cb */, SP::CPBCONDA, Convert__Imm1_2__Imm1_0, AMFBS_None, { MCK_Imm, MCK_a, MCK_Imm }, },
  { 507 /* cb0 */, SP::CPBCOND, Convert__Imm1_0__imm_95_9, AMFBS_None, { MCK_Imm }, },
  { 507 /* cb0 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_9, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 511 /* cb01 */, SP::CPBCOND, Convert__Imm1_0__imm_95_13, AMFBS_None, { MCK_Imm }, },
  { 511 /* cb01 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_13, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 516 /* cb012 */, SP::CPBCOND, Convert__Imm1_0__imm_95_15, AMFBS_None, { MCK_Imm }, },
  { 516 /* cb012 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_15, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 522 /* cb013 */, SP::CPBCOND, Convert__Imm1_0__imm_95_14, AMFBS_None, { MCK_Imm }, },
  { 522 /* cb013 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_14, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 528 /* cb02 */, SP::CPBCOND, Convert__Imm1_0__imm_95_11, AMFBS_None, { MCK_Imm }, },
  { 528 /* cb02 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_11, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 533 /* cb023 */, SP::CPBCOND, Convert__Imm1_0__imm_95_12, AMFBS_None, { MCK_Imm }, },
  { 533 /* cb023 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_12, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 539 /* cb03 */, SP::CPBCOND, Convert__Imm1_0__imm_95_10, AMFBS_None, { MCK_Imm }, },
  { 539 /* cb03 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_10, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 544 /* cb1 */, SP::CPBCOND, Convert__Imm1_0__imm_95_4, AMFBS_None, { MCK_Imm }, },
  { 544 /* cb1 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_4, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 548 /* cb12 */, SP::CPBCOND, Convert__Imm1_0__imm_95_2, AMFBS_None, { MCK_Imm }, },
  { 548 /* cb12 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_2, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 553 /* cb123 */, SP::CPBCOND, Convert__Imm1_0__imm_95_1, AMFBS_None, { MCK_Imm }, },
  { 553 /* cb123 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_1, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 559 /* cb13 */, SP::CPBCOND, Convert__Imm1_0__imm_95_3, AMFBS_None, { MCK_Imm }, },
  { 559 /* cb13 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_3, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 564 /* cb2 */, SP::CPBCOND, Convert__Imm1_0__imm_95_6, AMFBS_None, { MCK_Imm }, },
  { 564 /* cb2 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_6, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 568 /* cb23 */, SP::CPBCOND, Convert__Imm1_0__imm_95_5, AMFBS_None, { MCK_Imm }, },
  { 568 /* cb23 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_5, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 573 /* cb3 */, SP::CPBCOND, Convert__Imm1_0__imm_95_7, AMFBS_None, { MCK_Imm }, },
  { 573 /* cb3 */, SP::CPBCONDA, Convert__Imm1_1__imm_95_7, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 577 /* cba */, SP::CPBCOND, Convert__Imm1_0__imm_95_8, AMFBS_None, { MCK_Imm }, },
  { 577 /* cba */, SP::CPBCONDA, Convert__Imm1_1__imm_95_8, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 581 /* cbn */, SP::CPBCOND, Convert__Imm1_0__imm_95_0, AMFBS_None, { MCK_Imm }, },
  { 581 /* cbn */, SP::CPBCONDA, Convert__Imm1_1__imm_95_0, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 585 /* clr */, SP::ORrr, Convert__Reg1_0__regG0__regG0, AMFBS_None, { MCK_IntRegs }, },
  { 585 /* clr */, SP::STri, Convert__MEMri2_1__regG0, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 585 /* clr */, SP::STrr, Convert__MEMrr2_1__regG0, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 589 /* clrb */, SP::STBri, Convert__MEMri2_1__regG0, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 589 /* clrb */, SP::STBrr, Convert__MEMrr2_1__regG0, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 594 /* clrh */, SP::STHri, Convert__MEMri2_1__regG0, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 594 /* clrh */, SP::STHrr, Convert__MEMrr2_1__regG0, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 599 /* clrx */, SP::STXri, Convert__MEMri2_1__regG0, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 599 /* clrx */, SP::STXrr, Convert__MEMrr2_1__regG0, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 604 /* cmask16 */, SP::CMASK16, Convert__Reg1_0, AMFBS_HasVIS3, { MCK_IntRegs }, },
  { 612 /* cmask32 */, SP::CMASK32, Convert__Reg1_0, AMFBS_HasVIS3, { MCK_IntRegs }, },
  { 620 /* cmask8 */, SP::CMASK8, Convert__Reg1_0, AMFBS_HasVIS3, { MCK_IntRegs }, },
  { 627 /* cmp */, SP::SUBCCrr, Convert__regG0__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs }, },
  { 627 /* cmp */, SP::SUBCCri, Convert__regG0__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm }, },
  { 631 /* crc32c */, SP::CRC32C, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 638 /* cwb */, SP::CWBCONDrr, Convert__Imm1_3__Imm1_0__Reg1_1__Reg1_2, AMFBS_HasOSA2011, { MCK_Imm, MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 638 /* cwb */, SP::CWBCONDri, Convert__Imm1_3__Imm1_0__Reg1_1__Imm1_2, AMFBS_HasOSA2011, { MCK_Imm, MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 642 /* cwbcc */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_13__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 642 /* cwbcc */, SP::CWBCONDri, Convert__Imm1_2__imm_95_13__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 648 /* cwbcs */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_5__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 648 /* cwbcs */, SP::CWBCONDri, Convert__Imm1_2__imm_95_5__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 654 /* cwbe */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_1__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 654 /* cwbe */, SP::CWBCONDri, Convert__Imm1_2__imm_95_1__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 659 /* cwbg */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_10__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 659 /* cwbg */, SP::CWBCONDri, Convert__Imm1_2__imm_95_10__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 664 /* cwbge */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_11__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 664 /* cwbge */, SP::CWBCONDri, Convert__Imm1_2__imm_95_11__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 670 /* cwbgeu */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_13__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 670 /* cwbgeu */, SP::CWBCONDri, Convert__Imm1_2__imm_95_13__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 677 /* cwbgu */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_12__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 677 /* cwbgu */, SP::CWBCONDri, Convert__Imm1_2__imm_95_12__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 683 /* cwbl */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_3__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 683 /* cwbl */, SP::CWBCONDri, Convert__Imm1_2__imm_95_3__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 688 /* cwble */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_2__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 688 /* cwble */, SP::CWBCONDri, Convert__Imm1_2__imm_95_2__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 694 /* cwbleu */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_4__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 694 /* cwbleu */, SP::CWBCONDri, Convert__Imm1_2__imm_95_4__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 701 /* cwblu */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_5__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 701 /* cwblu */, SP::CWBCONDri, Convert__Imm1_2__imm_95_5__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 707 /* cwbne */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_9__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 707 /* cwbne */, SP::CWBCONDri, Convert__Imm1_2__imm_95_9__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 713 /* cwbneg */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_6__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 713 /* cwbneg */, SP::CWBCONDri, Convert__Imm1_2__imm_95_6__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 720 /* cwbpos */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_14__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 720 /* cwbpos */, SP::CWBCONDri, Convert__Imm1_2__imm_95_14__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 727 /* cwbvc */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_15__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 727 /* cwbvc */, SP::CWBCONDri, Convert__Imm1_2__imm_95_15__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 733 /* cwbvs */, SP::CWBCONDrr, Convert__Imm1_2__imm_95_7__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 733 /* cwbvs */, SP::CWBCONDri, Convert__Imm1_2__imm_95_7__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 739 /* cxb */, SP::CXBCONDrr, Convert__Imm1_3__Imm1_0__Reg1_1__Reg1_2, AMFBS_HasOSA2011, { MCK_Imm, MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 739 /* cxb */, SP::CXBCONDri, Convert__Imm1_3__Imm1_0__Reg1_1__Imm1_2, AMFBS_HasOSA2011, { MCK_Imm, MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 743 /* cxbcc */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_13__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 743 /* cxbcc */, SP::CXBCONDri, Convert__Imm1_2__imm_95_13__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 749 /* cxbcs */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_5__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 749 /* cxbcs */, SP::CXBCONDri, Convert__Imm1_2__imm_95_5__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 755 /* cxbe */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_1__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 755 /* cxbe */, SP::CXBCONDri, Convert__Imm1_2__imm_95_1__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 760 /* cxbg */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_10__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 760 /* cxbg */, SP::CXBCONDri, Convert__Imm1_2__imm_95_10__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 765 /* cxbge */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_11__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 765 /* cxbge */, SP::CXBCONDri, Convert__Imm1_2__imm_95_11__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 771 /* cxbgeu */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_13__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 771 /* cxbgeu */, SP::CXBCONDri, Convert__Imm1_2__imm_95_13__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 778 /* cxbgu */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_12__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 778 /* cxbgu */, SP::CXBCONDri, Convert__Imm1_2__imm_95_12__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 784 /* cxbl */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_3__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 784 /* cxbl */, SP::CXBCONDri, Convert__Imm1_2__imm_95_3__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 789 /* cxble */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_2__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 789 /* cxble */, SP::CXBCONDri, Convert__Imm1_2__imm_95_2__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 795 /* cxbleu */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_4__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 795 /* cxbleu */, SP::CXBCONDri, Convert__Imm1_2__imm_95_4__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 802 /* cxblu */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_5__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 802 /* cxblu */, SP::CXBCONDri, Convert__Imm1_2__imm_95_5__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 808 /* cxbne */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_9__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 808 /* cxbne */, SP::CXBCONDri, Convert__Imm1_2__imm_95_9__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 814 /* cxbneg */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_6__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 814 /* cxbneg */, SP::CXBCONDri, Convert__Imm1_2__imm_95_6__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 821 /* cxbpos */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_14__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 821 /* cxbpos */, SP::CXBCONDri, Convert__Imm1_2__imm_95_14__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 828 /* cxbvc */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_15__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 828 /* cxbvc */, SP::CXBCONDri, Convert__Imm1_2__imm_95_15__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 834 /* cxbvs */, SP::CXBCONDrr, Convert__Imm1_2__imm_95_7__Reg1_0__Reg1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_IntRegs, MCK_Imm }, },
  { 834 /* cxbvs */, SP::CXBCONDri, Convert__Imm1_2__imm_95_7__Reg1_0__Imm1_1, AMFBS_HasOSA2011, { MCK_IntRegs, MCK_Imm, MCK_Imm }, },
  { 840 /* dec */, SP::SUBri, Convert__Reg1_0__Reg1_0__imm_95_1, AMFBS_None, { MCK_IntRegs }, },
  { 840 /* dec */, SP::SUBri, Convert__Reg1_1__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 844 /* deccc */, SP::SUBCCri, Convert__Reg1_0__Reg1_0__imm_95_1, AMFBS_None, { MCK_IntRegs }, },
  { 844 /* deccc */, SP::SUBCCri, Convert__Reg1_1__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 850 /* des_iip */, SP::DES_IIP, Convert__Reg1_1__Reg1_0, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 858 /* des_ip */, SP::DES_IP, Convert__Reg1_1__Reg1_0, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 865 /* des_kexpand */, SP::DES_KEXPAND, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_Imm, MCK_DFPRegs }, },
  { 877 /* des_round */, SP::DES_ROUND, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasCrypto, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 887 /* done */, SP::DONE, Convert_NoOperands, AMFBS_HasV9, {  }, },
  { 892 /* edge16 */, SP::EDGE16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 899 /* edge16l */, SP::EDGE16L, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 907 /* edge16ln */, SP::EDGE16LN, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 916 /* edge16n */, SP::EDGE16N, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 924 /* edge32 */, SP::EDGE32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 931 /* edge32l */, SP::EDGE32L, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 939 /* edge32ln */, SP::EDGE32LN, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 948 /* edge32n */, SP::EDGE32N, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 956 /* edge8 */, SP::EDGE8, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 962 /* edge8l */, SP::EDGE8L, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 969 /* edge8ln */, SP::EDGE8LN, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 977 /* edge8n */, SP::EDGE8N, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS2, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 984 /* fabsd */, SP::FABSD, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 990 /* fabsq */, SP::FABSQ, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 996 /* fabss */, SP::FABSS, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_FPRegs }, },
  { 1002 /* faddd */, SP::FADDD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1008 /* faddq */, SP::FADDQ, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_QFPRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1014 /* fadds */, SP::FADDS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1020 /* faligndata */, SP::FALIGNADATA, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1031 /* fand */, SP::FAND, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1036 /* fandnot1 */, SP::FANDNOT1, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1045 /* fandnot1s */, SP::FANDNOT1S, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1055 /* fandnot2 */, SP::FANDNOT2, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1064 /* fandnot2s */, SP::FANDNOT2S, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1074 /* fands */, SP::FANDS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1080 /* fb */, SP::FBCOND, Convert__Imm1_0__imm_95_8, AMFBS_None, { MCK_Imm }, },
  { 1080 /* fb */, SP::FBCONDA, Convert__Imm1_1__imm_95_8, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCC, Convert__Imm1_1__imm_95_8__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1080 /* fb */, SP::FBCOND, Convert__Imm1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCCA, Convert__Imm1_2__imm_95_8__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCCNT, Convert__Imm1_2__imm_95_8__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCC, Convert__Imm1_2__imm_95_8__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1080 /* fb */, SP::FBCONDA, Convert__Imm1_2__Imm1_0, AMFBS_None, { MCK_Imm, MCK_a, MCK_Imm }, },
  { 1080 /* fb */, SP::FBCOND_V9, Convert__Imm1_2__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCC0, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCC, Convert__Imm1_2__Imm1_0__Reg1_1, AMFBS_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCCANT, Convert__Imm1_3__imm_95_8__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCCA, Convert__Imm1_3__imm_95_8__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1080 /* fb */, SP::FBCONDA_V9, Convert__Imm1_3__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_a, MCK_FCC0, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCCA, Convert__Imm1_3__Imm1_0__Reg1_2, AMFBS_HasV9, { MCK_Imm, MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCCNT, Convert__Imm1_3__Imm1_0__Reg1_2, AMFBS_HasV9, { MCK_Imm, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1080 /* fb */, SP::BPFCCANT, Convert__Imm1_4__Imm1_0__Reg1_3, AMFBS_HasV9, { MCK_Imm, MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1083 /* fba */, SP::FBCOND, Convert__Imm1_0__imm_95_8, AMFBS_None, { MCK_Imm }, },
  { 1083 /* fba */, SP::FBCONDA, Convert__Imm1_1__imm_95_8, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1083 /* fba */, SP::BPFCC, Convert__Imm1_1__imm_95_8__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1083 /* fba */, SP::BPFCCA, Convert__Imm1_2__imm_95_8__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1083 /* fba */, SP::BPFCCNT, Convert__Imm1_2__imm_95_8__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1083 /* fba */, SP::BPFCC, Convert__Imm1_2__imm_95_8__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1083 /* fba */, SP::BPFCCANT, Convert__Imm1_3__imm_95_8__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1083 /* fba */, SP::BPFCCA, Convert__Imm1_3__imm_95_8__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1087 /* fbe */, SP::FBCOND, Convert__Imm1_0__imm_95_9, AMFBS_None, { MCK_Imm }, },
  { 1087 /* fbe */, SP::FBCONDA, Convert__Imm1_1__imm_95_9, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1087 /* fbe */, SP::BPFCC, Convert__Imm1_1__imm_95_9__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1087 /* fbe */, SP::BPFCCA, Convert__Imm1_2__imm_95_9__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1087 /* fbe */, SP::BPFCCNT, Convert__Imm1_2__imm_95_9__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1087 /* fbe */, SP::BPFCC, Convert__Imm1_2__imm_95_9__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1087 /* fbe */, SP::BPFCCANT, Convert__Imm1_3__imm_95_9__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1087 /* fbe */, SP::BPFCCA, Convert__Imm1_3__imm_95_9__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1091 /* fbg */, SP::FBCOND, Convert__Imm1_0__imm_95_6, AMFBS_None, { MCK_Imm }, },
  { 1091 /* fbg */, SP::FBCONDA, Convert__Imm1_1__imm_95_6, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1091 /* fbg */, SP::BPFCC, Convert__Imm1_1__imm_95_6__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1091 /* fbg */, SP::BPFCCA, Convert__Imm1_2__imm_95_6__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1091 /* fbg */, SP::BPFCCNT, Convert__Imm1_2__imm_95_6__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1091 /* fbg */, SP::BPFCC, Convert__Imm1_2__imm_95_6__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1091 /* fbg */, SP::BPFCCANT, Convert__Imm1_3__imm_95_6__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1091 /* fbg */, SP::BPFCCA, Convert__Imm1_3__imm_95_6__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1095 /* fbge */, SP::FBCOND, Convert__Imm1_0__imm_95_11, AMFBS_None, { MCK_Imm }, },
  { 1095 /* fbge */, SP::FBCONDA, Convert__Imm1_1__imm_95_11, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1095 /* fbge */, SP::BPFCC, Convert__Imm1_1__imm_95_11__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1095 /* fbge */, SP::BPFCCA, Convert__Imm1_2__imm_95_11__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1095 /* fbge */, SP::BPFCCNT, Convert__Imm1_2__imm_95_11__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1095 /* fbge */, SP::BPFCC, Convert__Imm1_2__imm_95_11__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1095 /* fbge */, SP::BPFCCANT, Convert__Imm1_3__imm_95_11__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1095 /* fbge */, SP::BPFCCA, Convert__Imm1_3__imm_95_11__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1100 /* fbl */, SP::FBCOND, Convert__Imm1_0__imm_95_4, AMFBS_None, { MCK_Imm }, },
  { 1100 /* fbl */, SP::FBCONDA, Convert__Imm1_1__imm_95_4, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1100 /* fbl */, SP::BPFCC, Convert__Imm1_1__imm_95_4__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1100 /* fbl */, SP::BPFCCA, Convert__Imm1_2__imm_95_4__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1100 /* fbl */, SP::BPFCCNT, Convert__Imm1_2__imm_95_4__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1100 /* fbl */, SP::BPFCC, Convert__Imm1_2__imm_95_4__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1100 /* fbl */, SP::BPFCCANT, Convert__Imm1_3__imm_95_4__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1100 /* fbl */, SP::BPFCCA, Convert__Imm1_3__imm_95_4__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1104 /* fble */, SP::FBCOND, Convert__Imm1_0__imm_95_13, AMFBS_None, { MCK_Imm }, },
  { 1104 /* fble */, SP::FBCONDA, Convert__Imm1_1__imm_95_13, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1104 /* fble */, SP::BPFCC, Convert__Imm1_1__imm_95_13__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1104 /* fble */, SP::BPFCCA, Convert__Imm1_2__imm_95_13__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1104 /* fble */, SP::BPFCCNT, Convert__Imm1_2__imm_95_13__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1104 /* fble */, SP::BPFCC, Convert__Imm1_2__imm_95_13__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1104 /* fble */, SP::BPFCCANT, Convert__Imm1_3__imm_95_13__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1104 /* fble */, SP::BPFCCA, Convert__Imm1_3__imm_95_13__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1109 /* fblg */, SP::FBCOND, Convert__Imm1_0__imm_95_2, AMFBS_None, { MCK_Imm }, },
  { 1109 /* fblg */, SP::FBCONDA, Convert__Imm1_1__imm_95_2, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1109 /* fblg */, SP::BPFCC, Convert__Imm1_1__imm_95_2__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1109 /* fblg */, SP::BPFCCA, Convert__Imm1_2__imm_95_2__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1109 /* fblg */, SP::BPFCCNT, Convert__Imm1_2__imm_95_2__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1109 /* fblg */, SP::BPFCC, Convert__Imm1_2__imm_95_2__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1109 /* fblg */, SP::BPFCCANT, Convert__Imm1_3__imm_95_2__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1109 /* fblg */, SP::BPFCCA, Convert__Imm1_3__imm_95_2__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1114 /* fbn */, SP::FBCOND, Convert__Imm1_0__imm_95_0, AMFBS_None, { MCK_Imm }, },
  { 1114 /* fbn */, SP::FBCONDA, Convert__Imm1_1__imm_95_0, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1114 /* fbn */, SP::BPFCC, Convert__Imm1_1__imm_95_0__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1114 /* fbn */, SP::BPFCCA, Convert__Imm1_2__imm_95_0__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1114 /* fbn */, SP::BPFCCNT, Convert__Imm1_2__imm_95_0__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1114 /* fbn */, SP::BPFCC, Convert__Imm1_2__imm_95_0__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1114 /* fbn */, SP::BPFCCANT, Convert__Imm1_3__imm_95_0__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1114 /* fbn */, SP::BPFCCA, Convert__Imm1_3__imm_95_0__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1118 /* fbne */, SP::FBCOND, Convert__Imm1_0__imm_95_1, AMFBS_None, { MCK_Imm }, },
  { 1118 /* fbne */, SP::FBCONDA, Convert__Imm1_1__imm_95_1, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1118 /* fbne */, SP::BPFCC, Convert__Imm1_1__imm_95_1__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1118 /* fbne */, SP::BPFCCA, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1118 /* fbne */, SP::BPFCCNT, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1118 /* fbne */, SP::BPFCC, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1118 /* fbne */, SP::BPFCCANT, Convert__Imm1_3__imm_95_1__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1118 /* fbne */, SP::BPFCCA, Convert__Imm1_3__imm_95_1__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1123 /* fbnz */, SP::FBCOND, Convert__Imm1_0__imm_95_1, AMFBS_None, { MCK_Imm }, },
  { 1123 /* fbnz */, SP::FBCONDA, Convert__Imm1_1__imm_95_1, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1123 /* fbnz */, SP::BPFCC, Convert__Imm1_1__imm_95_1__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1123 /* fbnz */, SP::BPFCCA, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1123 /* fbnz */, SP::BPFCCNT, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1123 /* fbnz */, SP::BPFCC, Convert__Imm1_2__imm_95_1__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1123 /* fbnz */, SP::BPFCCANT, Convert__Imm1_3__imm_95_1__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1123 /* fbnz */, SP::BPFCCA, Convert__Imm1_3__imm_95_1__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1128 /* fbo */, SP::FBCOND, Convert__Imm1_0__imm_95_15, AMFBS_None, { MCK_Imm }, },
  { 1128 /* fbo */, SP::FBCONDA, Convert__Imm1_1__imm_95_15, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1128 /* fbo */, SP::BPFCC, Convert__Imm1_1__imm_95_15__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1128 /* fbo */, SP::BPFCCA, Convert__Imm1_2__imm_95_15__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1128 /* fbo */, SP::BPFCCNT, Convert__Imm1_2__imm_95_15__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1128 /* fbo */, SP::BPFCC, Convert__Imm1_2__imm_95_15__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1128 /* fbo */, SP::BPFCCANT, Convert__Imm1_3__imm_95_15__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1128 /* fbo */, SP::BPFCCA, Convert__Imm1_3__imm_95_15__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1132 /* fbu */, SP::FBCOND, Convert__Imm1_0__imm_95_7, AMFBS_None, { MCK_Imm }, },
  { 1132 /* fbu */, SP::FBCONDA, Convert__Imm1_1__imm_95_7, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1132 /* fbu */, SP::BPFCC, Convert__Imm1_1__imm_95_7__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1132 /* fbu */, SP::BPFCCA, Convert__Imm1_2__imm_95_7__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1132 /* fbu */, SP::BPFCCNT, Convert__Imm1_2__imm_95_7__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1132 /* fbu */, SP::BPFCC, Convert__Imm1_2__imm_95_7__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1132 /* fbu */, SP::BPFCCANT, Convert__Imm1_3__imm_95_7__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1132 /* fbu */, SP::BPFCCA, Convert__Imm1_3__imm_95_7__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1136 /* fbue */, SP::FBCOND, Convert__Imm1_0__imm_95_10, AMFBS_None, { MCK_Imm }, },
  { 1136 /* fbue */, SP::FBCONDA, Convert__Imm1_1__imm_95_10, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1136 /* fbue */, SP::BPFCC, Convert__Imm1_1__imm_95_10__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1136 /* fbue */, SP::BPFCCA, Convert__Imm1_2__imm_95_10__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1136 /* fbue */, SP::BPFCCNT, Convert__Imm1_2__imm_95_10__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1136 /* fbue */, SP::BPFCC, Convert__Imm1_2__imm_95_10__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1136 /* fbue */, SP::BPFCCANT, Convert__Imm1_3__imm_95_10__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1136 /* fbue */, SP::BPFCCA, Convert__Imm1_3__imm_95_10__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1141 /* fbug */, SP::FBCOND, Convert__Imm1_0__imm_95_5, AMFBS_None, { MCK_Imm }, },
  { 1141 /* fbug */, SP::FBCONDA, Convert__Imm1_1__imm_95_5, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1141 /* fbug */, SP::BPFCC, Convert__Imm1_1__imm_95_5__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1141 /* fbug */, SP::BPFCCA, Convert__Imm1_2__imm_95_5__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1141 /* fbug */, SP::BPFCCNT, Convert__Imm1_2__imm_95_5__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1141 /* fbug */, SP::BPFCC, Convert__Imm1_2__imm_95_5__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1141 /* fbug */, SP::BPFCCANT, Convert__Imm1_3__imm_95_5__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1141 /* fbug */, SP::BPFCCA, Convert__Imm1_3__imm_95_5__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1146 /* fbuge */, SP::FBCOND, Convert__Imm1_0__imm_95_12, AMFBS_None, { MCK_Imm }, },
  { 1146 /* fbuge */, SP::FBCONDA, Convert__Imm1_1__imm_95_12, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1146 /* fbuge */, SP::BPFCC, Convert__Imm1_1__imm_95_12__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1146 /* fbuge */, SP::BPFCCA, Convert__Imm1_2__imm_95_12__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1146 /* fbuge */, SP::BPFCCNT, Convert__Imm1_2__imm_95_12__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1146 /* fbuge */, SP::BPFCC, Convert__Imm1_2__imm_95_12__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1146 /* fbuge */, SP::BPFCCANT, Convert__Imm1_3__imm_95_12__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1146 /* fbuge */, SP::BPFCCA, Convert__Imm1_3__imm_95_12__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1152 /* fbul */, SP::FBCOND, Convert__Imm1_0__imm_95_3, AMFBS_None, { MCK_Imm }, },
  { 1152 /* fbul */, SP::FBCONDA, Convert__Imm1_1__imm_95_3, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1152 /* fbul */, SP::BPFCC, Convert__Imm1_1__imm_95_3__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1152 /* fbul */, SP::BPFCCA, Convert__Imm1_2__imm_95_3__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1152 /* fbul */, SP::BPFCCNT, Convert__Imm1_2__imm_95_3__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1152 /* fbul */, SP::BPFCC, Convert__Imm1_2__imm_95_3__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1152 /* fbul */, SP::BPFCCANT, Convert__Imm1_3__imm_95_3__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1152 /* fbul */, SP::BPFCCA, Convert__Imm1_3__imm_95_3__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1157 /* fbule */, SP::FBCOND, Convert__Imm1_0__imm_95_14, AMFBS_None, { MCK_Imm }, },
  { 1157 /* fbule */, SP::FBCONDA, Convert__Imm1_1__imm_95_14, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1157 /* fbule */, SP::BPFCC, Convert__Imm1_1__imm_95_14__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1157 /* fbule */, SP::BPFCCA, Convert__Imm1_2__imm_95_14__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1157 /* fbule */, SP::BPFCCNT, Convert__Imm1_2__imm_95_14__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1157 /* fbule */, SP::BPFCC, Convert__Imm1_2__imm_95_14__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1157 /* fbule */, SP::BPFCCANT, Convert__Imm1_3__imm_95_14__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1157 /* fbule */, SP::BPFCCA, Convert__Imm1_3__imm_95_14__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1163 /* fbz */, SP::FBCOND, Convert__Imm1_0__imm_95_9, AMFBS_None, { MCK_Imm }, },
  { 1163 /* fbz */, SP::FBCONDA, Convert__Imm1_1__imm_95_9, AMFBS_None, { MCK_a, MCK_Imm }, },
  { 1163 /* fbz */, SP::BPFCC, Convert__Imm1_1__imm_95_9__Reg1_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm }, },
  { 1163 /* fbz */, SP::BPFCCA, Convert__Imm1_2__imm_95_9__Reg1_1, AMFBS_HasV9, { MCK_a, MCK_FCCRegs, MCK_Imm }, },
  { 1163 /* fbz */, SP::BPFCCNT, Convert__Imm1_2__imm_95_9__Reg1_1, AMFBS_HasV9, { MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1163 /* fbz */, SP::BPFCC, Convert__Imm1_2__imm_95_9__Reg1_1, AMFBS_HasV9, { MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1163 /* fbz */, SP::BPFCCANT, Convert__Imm1_3__imm_95_9__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pn, MCK_FCCRegs, MCK_Imm }, },
  { 1163 /* fbz */, SP::BPFCCA, Convert__Imm1_3__imm_95_9__Reg1_2, AMFBS_HasV9, { MCK_a, MCK_pt, MCK_FCCRegs, MCK_Imm }, },
  { 1167 /* fchksm16 */, SP::FCHKSM16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1176 /* fcmpd */, SP::V9FCMPD, Convert__regFCC0__Reg1_0__Reg1_1, AMFBS_None, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 1176 /* fcmpd */, SP::V9FCMPD, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1182 /* fcmped */, SP::V9FCMPED, Convert__regFCC0__Reg1_0__Reg1_1, AMFBS_None, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 1182 /* fcmped */, SP::V9FCMPED, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1189 /* fcmpeq */, SP::V9FCMPEQ, Convert__regFCC0__Reg1_0__Reg1_1, AMFBS_None, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 1189 /* fcmpeq */, SP::V9FCMPEQ, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1196 /* fcmpeq16 */, SP::FCMPEQ16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 1205 /* fcmpeq32 */, SP::FCMPEQ32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 1214 /* fcmpes */, SP::V9FCMPES, Convert__regFCC0__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPRegs, MCK_FPRegs }, },
  { 1214 /* fcmpes */, SP::V9FCMPES, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1221 /* fcmpgt16 */, SP::FCMPGT16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 1230 /* fcmpgt32 */, SP::FCMPGT32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 1239 /* fcmple16 */, SP::FCMPLE16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 1248 /* fcmple32 */, SP::FCMPLE32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 1257 /* fcmpne16 */, SP::FCMPNE16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 1266 /* fcmpne32 */, SP::FCMPNE32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 1275 /* fcmpq */, SP::V9FCMPQ, Convert__regFCC0__Reg1_0__Reg1_1, AMFBS_None, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 1275 /* fcmpq */, SP::V9FCMPQ, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1281 /* fcmps */, SP::V9FCMPS, Convert__regFCC0__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPRegs, MCK_FPRegs }, },
  { 1281 /* fcmps */, SP::V9FCMPS, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1287 /* fdivd */, SP::FDIVD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1293 /* fdivq */, SP::FDIVQ, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_QFPRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1299 /* fdivs */, SP::FDIVS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1305 /* fdmulq */, SP::FDMULQ, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_DFPRegs, MCK_DFPRegs, MCK_QFPRegs }, },
  { 1312 /* fdtoi */, SP::FDTOI, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_DFPRegs, MCK_FPRegs }, },
  { 1318 /* fdtoq */, SP::FDTOQ, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_DFPRegs, MCK_QFPRegs }, },
  { 1324 /* fdtos */, SP::FDTOS, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_DFPRegs, MCK_FPRegs }, },
  { 1330 /* fdtox */, SP::FDTOX, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 1336 /* fexpand */, SP::FEXPAND, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_FPRegs, MCK_DFPRegs }, },
  { 1344 /* fhaddd */, SP::FHADDD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1351 /* fhadds */, SP::FHADDS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1358 /* fhsubd */, SP::FHSUBD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1365 /* fhsubs */, SP::FHSUBS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1372 /* fitod */, SP::FITOD, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_DFPRegs }, },
  { 1378 /* fitoq */, SP::FITOQ, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_QFPRegs }, },
  { 1384 /* fitos */, SP::FITOS, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_FPRegs }, },
  { 1390 /* flcmpd */, SP::FLCMPD, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasVIS3, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1397 /* flcmps */, SP::FLCMPS, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasVIS3, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1404 /* flush */, SP::FLUSH, Convert_NoOperands, AMFBS_None, {  }, },
  { 1404 /* flush */, SP::FLUSH, Convert_NoOperands, AMFBS_None, { MCK_G0 }, },
  { 1404 /* flush */, SP::FLUSHri, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 1404 /* flush */, SP::FLUSHrr, Convert__MEMrr2_0, AMFBS_None, { MCK_MEMrr }, },
  { 1410 /* flushw */, SP::FLUSHW, Convert_NoOperands, AMFBS_HasV9, {  }, },
  { 1417 /* fmaddd */, SP::FMADDD, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasUA2007, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1424 /* fmadds */, SP::FMADDS, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasUA2007, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 1431 /* fmean16 */, SP::FMEAN16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::FMOVD, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::FMOVD_XCC, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::FMOVD_FCC, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCC0, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::FMOVD_ICC, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1439 /* fmovd */, SP::V9FMOVD_FCC, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1445 /* fmovda */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1445 /* fmovda */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1445 /* fmovda */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1445 /* fmovda */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1445 /* fmovda */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1452 /* fmovdcc */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1452 /* fmovdcc */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1452 /* fmovdcc */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1452 /* fmovdcc */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1460 /* fmovdcs */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1460 /* fmovdcs */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1460 /* fmovdcs */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1460 /* fmovdcs */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1468 /* fmovde */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1468 /* fmovde */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1468 /* fmovde */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1468 /* fmovde */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1468 /* fmovde */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1475 /* fmovdeq */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1475 /* fmovdeq */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1475 /* fmovdeq */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1475 /* fmovdeq */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1483 /* fmovdg */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1483 /* fmovdg */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1483 /* fmovdg */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1483 /* fmovdg */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1483 /* fmovdg */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1490 /* fmovdge */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1490 /* fmovdge */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1490 /* fmovdge */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1490 /* fmovdge */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1490 /* fmovdge */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1498 /* fmovdgeu */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1498 /* fmovdgeu */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1498 /* fmovdgeu */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1498 /* fmovdgeu */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1507 /* fmovdgt */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1507 /* fmovdgt */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1507 /* fmovdgt */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1507 /* fmovdgt */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1515 /* fmovdgu */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1515 /* fmovdgu */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1515 /* fmovdgu */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1515 /* fmovdgu */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1523 /* fmovdl */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1523 /* fmovdl */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1523 /* fmovdl */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1523 /* fmovdl */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1523 /* fmovdl */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1530 /* fmovdle */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1530 /* fmovdle */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1530 /* fmovdle */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1530 /* fmovdle */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1530 /* fmovdle */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1538 /* fmovdleu */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1538 /* fmovdleu */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1538 /* fmovdleu */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1538 /* fmovdleu */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1547 /* fmovdlg */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1555 /* fmovdlt */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1555 /* fmovdlt */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1555 /* fmovdlt */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1555 /* fmovdlt */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1563 /* fmovdlu */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1563 /* fmovdlu */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1563 /* fmovdlu */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1563 /* fmovdlu */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1571 /* fmovdn */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1571 /* fmovdn */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1571 /* fmovdn */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1571 /* fmovdn */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1571 /* fmovdn */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1578 /* fmovdne */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1578 /* fmovdne */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1578 /* fmovdne */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1578 /* fmovdne */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1578 /* fmovdne */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1586 /* fmovdneg */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1586 /* fmovdneg */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1586 /* fmovdneg */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1586 /* fmovdneg */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1595 /* fmovdnz */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1595 /* fmovdnz */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1595 /* fmovdnz */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1595 /* fmovdnz */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1595 /* fmovdnz */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1603 /* fmovdo */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1610 /* fmovdpos */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1610 /* fmovdpos */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1610 /* fmovdpos */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1610 /* fmovdpos */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1619 /* fmovdu */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1626 /* fmovdue */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1634 /* fmovdug */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1642 /* fmovduge */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1651 /* fmovdul */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1659 /* fmovdule */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1668 /* fmovdvc */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1668 /* fmovdvc */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1668 /* fmovdvc */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1668 /* fmovdvc */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1676 /* fmovdvs */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1676 /* fmovdvs */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1676 /* fmovdvs */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1676 /* fmovdvs */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1684 /* fmovdz */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1684 /* fmovdz */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1684 /* fmovdz */, SP::FMOVD_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1684 /* fmovdz */, SP::FMOVD_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1684 /* fmovdz */, SP::V9FMOVD_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1691 /* fmovq */, SP::FMOVQ, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 1691 /* fmovq */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1691 /* fmovq */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1691 /* fmovq */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1691 /* fmovq */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1691 /* fmovq */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1691 /* fmovq */, SP::FMOVQ_XCC, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1691 /* fmovq */, SP::FMOVQ_FCC, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCC0, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1691 /* fmovq */, SP::FMOVQ_ICC, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1691 /* fmovq */, SP::V9FMOVQ_FCC, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1697 /* fmovqa */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1697 /* fmovqa */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1697 /* fmovqa */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1697 /* fmovqa */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1697 /* fmovqa */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1704 /* fmovqcc */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1704 /* fmovqcc */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1704 /* fmovqcc */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1704 /* fmovqcc */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1712 /* fmovqcs */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1712 /* fmovqcs */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1712 /* fmovqcs */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1712 /* fmovqcs */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1720 /* fmovqe */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1720 /* fmovqe */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1720 /* fmovqe */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1720 /* fmovqe */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1720 /* fmovqe */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1727 /* fmovqeq */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1727 /* fmovqeq */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1727 /* fmovqeq */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1727 /* fmovqeq */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1735 /* fmovqg */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1735 /* fmovqg */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1735 /* fmovqg */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1735 /* fmovqg */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1735 /* fmovqg */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1742 /* fmovqge */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1742 /* fmovqge */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1742 /* fmovqge */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1742 /* fmovqge */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1742 /* fmovqge */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1750 /* fmovqgeu */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1750 /* fmovqgeu */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1750 /* fmovqgeu */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1750 /* fmovqgeu */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1759 /* fmovqgt */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1759 /* fmovqgt */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1759 /* fmovqgt */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1759 /* fmovqgt */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1767 /* fmovqgu */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1767 /* fmovqgu */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1767 /* fmovqgu */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1767 /* fmovqgu */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1775 /* fmovql */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1775 /* fmovql */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1775 /* fmovql */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1775 /* fmovql */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1775 /* fmovql */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1782 /* fmovqle */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1782 /* fmovqle */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1782 /* fmovqle */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1782 /* fmovqle */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1782 /* fmovqle */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1790 /* fmovqleu */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1790 /* fmovqleu */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1790 /* fmovqleu */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1790 /* fmovqleu */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1799 /* fmovqlg */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1807 /* fmovqlt */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1807 /* fmovqlt */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1807 /* fmovqlt */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1807 /* fmovqlt */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1815 /* fmovqlu */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1815 /* fmovqlu */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1815 /* fmovqlu */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1815 /* fmovqlu */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1823 /* fmovqn */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1823 /* fmovqn */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1823 /* fmovqn */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1823 /* fmovqn */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1823 /* fmovqn */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1830 /* fmovqne */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1830 /* fmovqne */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1830 /* fmovqne */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1830 /* fmovqne */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1830 /* fmovqne */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1838 /* fmovqneg */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1838 /* fmovqneg */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1838 /* fmovqneg */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1838 /* fmovqneg */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1847 /* fmovqnz */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1847 /* fmovqnz */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1847 /* fmovqnz */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1847 /* fmovqnz */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1847 /* fmovqnz */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1855 /* fmovqo */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1862 /* fmovqpos */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1862 /* fmovqpos */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1862 /* fmovqpos */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1862 /* fmovqpos */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1871 /* fmovqu */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1878 /* fmovque */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1886 /* fmovqug */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1894 /* fmovquge */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1903 /* fmovqul */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1911 /* fmovqule */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1920 /* fmovqvc */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1920 /* fmovqvc */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1920 /* fmovqvc */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1920 /* fmovqvc */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1928 /* fmovqvs */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1928 /* fmovqvs */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1928 /* fmovqvs */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1928 /* fmovqvs */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1936 /* fmovqz */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1936 /* fmovqz */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1936 /* fmovqz */, SP::FMOVQ_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1936 /* fmovqz */, SP::FMOVQ_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1936 /* fmovqz */, SP::V9FMOVQ_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 1943 /* fmovrd */, SP::FMOVRD, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_IntRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1950 /* fmovrde */, SP::FMOVRD, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1958 /* fmovrdgez */, SP::FMOVRD, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK_IntRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1968 /* fmovrdgz */, SP::FMOVRD, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK_IntRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1977 /* fmovrdlez */, SP::FMOVRD, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK_IntRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1987 /* fmovrdlz */, SP::FMOVRD, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK_IntRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 1996 /* fmovrdne */, SP::FMOVRD, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2005 /* fmovrdnz */, SP::FMOVRD, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2014 /* fmovrdz */, SP::FMOVRD, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2022 /* fmovrq */, SP::FMOVRQ, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_IntRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2029 /* fmovrqe */, SP::FMOVRQ, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2037 /* fmovrqgez */, SP::FMOVRQ, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK_IntRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2047 /* fmovrqgz */, SP::FMOVRQ, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK_IntRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2056 /* fmovrqlez */, SP::FMOVRQ, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK_IntRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2066 /* fmovrqlz */, SP::FMOVRQ, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK_IntRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2075 /* fmovrqne */, SP::FMOVRQ, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2084 /* fmovrqnz */, SP::FMOVRQ, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2093 /* fmovrqz */, SP::FMOVRQ, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2101 /* fmovrs */, SP::FMOVRS, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2108 /* fmovrse */, SP::FMOVRS, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2116 /* fmovrsgez */, SP::FMOVRS, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2126 /* fmovrsgz */, SP::FMOVRS, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2135 /* fmovrslez */, SP::FMOVRS, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2145 /* fmovrslz */, SP::FMOVRS, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2154 /* fmovrsne */, SP::FMOVRS, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2163 /* fmovrsnz */, SP::FMOVRS, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2172 /* fmovrsz */, SP::FMOVRS, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::FMOVS, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::FMOVS_XCC, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::FMOVS_FCC, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCC0, MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::FMOVS_ICC, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2180 /* fmovs */, SP::V9FMOVS_FCC, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2186 /* fmovsa */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2186 /* fmovsa */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2186 /* fmovsa */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2186 /* fmovsa */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2186 /* fmovsa */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2193 /* fmovscc */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2193 /* fmovscc */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2193 /* fmovscc */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2193 /* fmovscc */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2201 /* fmovscs */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2201 /* fmovscs */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2201 /* fmovscs */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2201 /* fmovscs */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2209 /* fmovse */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2209 /* fmovse */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2209 /* fmovse */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2209 /* fmovse */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2209 /* fmovse */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2216 /* fmovseq */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2216 /* fmovseq */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2216 /* fmovseq */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2216 /* fmovseq */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2224 /* fmovsg */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2224 /* fmovsg */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2224 /* fmovsg */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2224 /* fmovsg */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2224 /* fmovsg */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2231 /* fmovsge */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2231 /* fmovsge */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2231 /* fmovsge */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2231 /* fmovsge */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2231 /* fmovsge */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2239 /* fmovsgeu */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2239 /* fmovsgeu */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2239 /* fmovsgeu */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2239 /* fmovsgeu */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2248 /* fmovsgt */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2248 /* fmovsgt */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2248 /* fmovsgt */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2248 /* fmovsgt */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2256 /* fmovsgu */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2256 /* fmovsgu */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2256 /* fmovsgu */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2256 /* fmovsgu */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2264 /* fmovsl */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2264 /* fmovsl */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2264 /* fmovsl */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2264 /* fmovsl */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2264 /* fmovsl */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2271 /* fmovsle */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2271 /* fmovsle */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2271 /* fmovsle */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2271 /* fmovsle */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2271 /* fmovsle */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2279 /* fmovsleu */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2279 /* fmovsleu */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2279 /* fmovsleu */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2279 /* fmovsleu */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2288 /* fmovslg */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2296 /* fmovslt */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2296 /* fmovslt */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2296 /* fmovslt */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2296 /* fmovslt */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2304 /* fmovslu */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2304 /* fmovslu */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2304 /* fmovslu */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2304 /* fmovslu */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2312 /* fmovsn */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2312 /* fmovsn */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2312 /* fmovsn */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2312 /* fmovsn */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2312 /* fmovsn */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2319 /* fmovsne */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2319 /* fmovsne */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2319 /* fmovsne */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2319 /* fmovsne */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2319 /* fmovsne */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2327 /* fmovsneg */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2327 /* fmovsneg */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2327 /* fmovsneg */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2327 /* fmovsneg */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2336 /* fmovsnz */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2336 /* fmovsnz */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2336 /* fmovsnz */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2336 /* fmovsnz */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2336 /* fmovsnz */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2344 /* fmovso */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2351 /* fmovspos */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2351 /* fmovspos */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2351 /* fmovspos */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2351 /* fmovspos */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2360 /* fmovsu */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2367 /* fmovsue */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2375 /* fmovsug */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2383 /* fmovsuge */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2392 /* fmovsul */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2400 /* fmovsule */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2409 /* fmovsvc */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2409 /* fmovsvc */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2409 /* fmovsvc */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2409 /* fmovsvc */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2417 /* fmovsvs */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2417 /* fmovsvs */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2417 /* fmovsvs */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2417 /* fmovsvs */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2425 /* fmovsz */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2425 /* fmovsz */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_FPRegs, MCK_FPRegs }, },
  { 2425 /* fmovsz */, SP::FMOVS_XCC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_FPRegs, MCK_FPRegs }, },
  { 2425 /* fmovsz */, SP::FMOVS_ICC, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_FPRegs, MCK_FPRegs }, },
  { 2425 /* fmovsz */, SP::V9FMOVS_FCC, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2432 /* fmsubd */, SP::FMSUBD, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasUA2007, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2439 /* fmsubs */, SP::FMSUBS, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasUA2007, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2446 /* fmul8sux16 */, SP::FMUL8SUX16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2457 /* fmul8ulx16 */, SP::FMUL8ULX16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2468 /* fmul8x16 */, SP::FMUL8X16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2477 /* fmul8x16al */, SP::FMUL8X16AL, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_DFPRegs }, },
  { 2488 /* fmul8x16au */, SP::FMUL8X16AU, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_DFPRegs }, },
  { 2499 /* fmuld */, SP::FMULD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2505 /* fmuld8sux16 */, SP::FMULD8SUX16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_DFPRegs }, },
  { 2517 /* fmuld8ulx16 */, SP::FMULD8ULX16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_DFPRegs }, },
  { 2529 /* fmulq */, SP::FMULQ, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_QFPRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 2535 /* fmuls */, SP::FMULS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2541 /* fnaddd */, SP::FNADDD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2548 /* fnadds */, SP::FNADDS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2555 /* fnand */, SP::FNAND, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2561 /* fnands */, SP::FNANDS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2568 /* fnegd */, SP::FNEGD, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2574 /* fnegq */, SP::FNEGQ, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 2580 /* fnegs */, SP::FNEGS, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_FPRegs }, },
  { 2586 /* fnhaddd */, SP::FNHADDD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2594 /* fnhadds */, SP::FNHADDS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2602 /* fnmaddd */, SP::FNMADDD, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasUA2007, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2610 /* fnmadds */, SP::FNMADDS, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasUA2007, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2618 /* fnmsubd */, SP::FNMSUBD, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasUA2007, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2626 /* fnmsubs */, SP::FNMSUBS, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasUA2007, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2634 /* fnmuld */, SP::FNMULD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2641 /* fnmuls */, SP::FNMULS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2648 /* fnor */, SP::FNOR, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2653 /* fnors */, SP::FNORS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2659 /* fnot1 */, SP::FNOT1, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2665 /* fnot1s */, SP::FNOT1S, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs }, },
  { 2672 /* fnot2 */, SP::FNOT2, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2678 /* fnot2s */, SP::FNOT2S, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs }, },
  { 2685 /* fnsmuld */, SP::FNSMULD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_FPRegs, MCK_FPRegs, MCK_DFPRegs }, },
  { 2693 /* fone */, SP::FONE, Convert__Reg1_0, AMFBS_HasVIS, { MCK_DFPRegs }, },
  { 2698 /* fones */, SP::FONES, Convert__Reg1_0, AMFBS_HasVIS, { MCK_FPRegs }, },
  { 2704 /* for */, SP::FOR, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2708 /* fornot1 */, SP::FORNOT1, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2716 /* fornot1s */, SP::FORNOT1S, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2725 /* fornot2 */, SP::FORNOT2, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2733 /* fornot2s */, SP::FORNOT2S, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2742 /* fors */, SP::FORS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2747 /* fpack16 */, SP::FPACK16, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2755 /* fpack32 */, SP::FPACK32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2763 /* fpackfix */, SP::FPACKFIX, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_DFPRegs, MCK_FPRegs }, },
  { 2772 /* fpadd16 */, SP::FPADD16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2780 /* fpadd16s */, SP::FPADD16S, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2789 /* fpadd32 */, SP::FPADD32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2797 /* fpadd32s */, SP::FPADD32S, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2806 /* fpadd64 */, SP::FPADD64, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2814 /* fpmaddx */, SP::FPMADDX, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasOSA2011, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2822 /* fpmaddxhi */, SP::FPMADDXHI, Convert__Reg1_3__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasOSA2011, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2832 /* fpmerge */, SP::FPMERGE, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_DFPRegs }, },
  { 2840 /* fpsub16 */, SP::FPSUB16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2848 /* fpsub16s */, SP::FPSUB16S, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2857 /* fpsub32 */, SP::FPSUB32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2865 /* fpsub32s */, SP::FPSUB32S, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 2874 /* fqtod */, SP::FQTOD, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_QFPRegs, MCK_DFPRegs }, },
  { 2880 /* fqtoi */, SP::FQTOI, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_QFPRegs, MCK_FPRegs }, },
  { 2886 /* fqtos */, SP::FQTOS, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_QFPRegs, MCK_FPRegs }, },
  { 2892 /* fqtox */, SP::FQTOX, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_QFPRegs, MCK_DFPRegs }, },
  { 2898 /* fslas16 */, SP::FSLAS16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2906 /* fslas32 */, SP::FSLAS32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2914 /* fsll16 */, SP::FSLL16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2921 /* fsll32 */, SP::FSLL32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2928 /* fsmuld */, SP::FSMULD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPRegs, MCK_FPRegs, MCK_DFPRegs }, },
  { 2935 /* fsqrtd */, SP::FSQRTD, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2942 /* fsqrtq */, SP::FSQRTQ, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_QFPRegs, MCK_QFPRegs }, },
  { 2949 /* fsqrts */, SP::FSQRTS, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_FPRegs }, },
  { 2956 /* fsra16 */, SP::FSRA16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2963 /* fsra32 */, SP::FSRA32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 2970 /* fsrc1 */, SP::FSRC1, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2976 /* fsrc1s */, SP::FSRC1S, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs }, },
  { 2983 /* fsrc2 */, SP::FSRC2, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 2989 /* fsrc2s */, SP::FSRC2S, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs }, },
  { 2996 /* fsrl16 */, SP::FSRL16, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 3003 /* fsrl32 */, SP::FSRL32, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 3010 /* fstod */, SP::FSTOD, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_DFPRegs }, },
  { 3016 /* fstoi */, SP::FSTOI, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_FPRegs }, },
  { 3022 /* fstoq */, SP::FSTOQ, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK_QFPRegs }, },
  { 3028 /* fstox */, SP::FSTOX, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_FPRegs, MCK_DFPRegs }, },
  { 3034 /* fsubd */, SP::FSUBD, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 3040 /* fsubq */, SP::FSUBQ, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_QFPRegs, MCK_QFPRegs, MCK_QFPRegs }, },
  { 3046 /* fsubs */, SP::FSUBS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 3052 /* fxnor */, SP::FXNOR, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 3058 /* fxnors */, SP::FXNORS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 3065 /* fxor */, SP::FXOR, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 3070 /* fxors */, SP::FXORS, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_FPRegs, MCK_FPRegs, MCK_FPRegs }, },
  { 3076 /* fxtod */, SP::FXTOD, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_DFPRegs, MCK_DFPRegs }, },
  { 3082 /* fxtoq */, SP::FXTOQ, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_DFPRegs, MCK_QFPRegs }, },
  { 3088 /* fxtos */, SP::FXTOS, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_DFPRegs, MCK_FPRegs }, },
  { 3094 /* fzero */, SP::FZERO, Convert__Reg1_0, AMFBS_HasVIS, { MCK_DFPRegs }, },
  { 3100 /* fzeros */, SP::FZEROS, Convert__Reg1_0, AMFBS_HasVIS, { MCK_FPRegs }, },
  { 3107 /* inc */, SP::ADDri, Convert__Reg1_0__Reg1_0__imm_95_1, AMFBS_None, { MCK_IntRegs }, },
  { 3107 /* inc */, SP::ADDri, Convert__Reg1_1__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 3111 /* inccc */, SP::ADDCCri, Convert__Reg1_0__Reg1_0__imm_95_1, AMFBS_None, { MCK_IntRegs }, },
  { 3111 /* inccc */, SP::ADDCCri, Convert__Reg1_1__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 3117 /* invalw */, SP::INVALW, Convert_NoOperands, AMFBS_HasUA2005, {  }, },
  { 3124 /* jmp */, SP::JMPLri, Convert__regG0__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 3124 /* jmp */, SP::JMPLrr, Convert__regG0__MEMrr2_0, AMFBS_None, { MCK_MEMrr }, },
  { 3128 /* jmpl */, SP::JMPLri, Convert__Reg1_1__MEMri2_0, AMFBS_None, { MCK_MEMri, MCK_IntRegs }, },
  { 3128 /* jmpl */, SP::JMPLrr, Convert__Reg1_1__MEMrr2_0, AMFBS_None, { MCK_MEMrr, MCK_IntRegs }, },
  { 3133 /* ld */, SP::LDCSRri, Convert__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_CPSR }, },
  { 3133 /* ld */, SP::LDFSRri, Convert__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_FSR }, },
  { 3133 /* ld */, SP::LDCri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_CoprocRegs }, },
  { 3133 /* ld */, SP::LDFri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_FPRegs }, },
  { 3133 /* ld */, SP::LDri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 3133 /* ld */, SP::LDCSRrr, Convert__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_CPSR }, },
  { 3133 /* ld */, SP::LDFSRrr, Convert__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_FSR }, },
  { 3133 /* ld */, SP::LDCrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_CoprocRegs }, },
  { 3133 /* ld */, SP::LDFrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_FPRegs }, },
  { 3133 /* ld */, SP::LDrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 3133 /* ld */, SP::GDOP_LDrr, Convert__Reg1_3__MEMrr2_1__TailRelocSymLoad_GOT1_4, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs, MCK_TailRelocSymLoad_GOT }, },
  { 3133 /* ld */, SP::TLS_LDrr, Convert__Reg1_3__MEMrr2_1__TailRelocSymLoad_TLS1_4, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs, MCK_TailRelocSymLoad_TLS }, },
  { 3136 /* lda */, SP::LDFAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_FPRegs }, },
  { 3136 /* lda */, SP::LDAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntRegs }, },
  { 3136 /* lda */, SP::LDFArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_FPRegs }, },
  { 3136 /* lda */, SP::LDArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntRegs }, },
  { 3140 /* ldd */, SP::LDDCri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_CoprocPair }, },
  { 3140 /* ldd */, SP::LDDri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntPair }, },
  { 3140 /* ldd */, SP::LDDFri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_DFPRegs }, },
  { 3140 /* ldd */, SP::LDDCrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_CoprocPair }, },
  { 3140 /* ldd */, SP::LDDrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntPair }, },
  { 3140 /* ldd */, SP::LDDFrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_DFPRegs }, },
  { 3144 /* ldda */, SP::LDDAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntPair }, },
  { 3144 /* ldda */, SP::LDDFAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_DFPRegs }, },
  { 3144 /* ldda */, SP::LDDArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntPair }, },
  { 3144 /* ldda */, SP::LDDFArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_DFPRegs }, },
  { 3149 /* ldq */, SP::LDQFri, Convert__Reg1_3__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK_QFPRegs }, },
  { 3149 /* ldq */, SP::LDQFrr, Convert__Reg1_3__MEMrr2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_QFPRegs }, },
  { 3153 /* ldqa */, SP::LDQFAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_QFPRegs }, },
  { 3153 /* ldqa */, SP::LDQFArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_QFPRegs }, },
  { 3158 /* ldsb */, SP::LDSBri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 3158 /* ldsb */, SP::LDSBrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 3163 /* ldsba */, SP::LDSBAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntRegs }, },
  { 3163 /* ldsba */, SP::LDSBArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntRegs }, },
  { 3169 /* ldsh */, SP::LDSHri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 3169 /* ldsh */, SP::LDSHrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 3174 /* ldsha */, SP::LDSHAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntRegs }, },
  { 3174 /* ldsha */, SP::LDSHArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntRegs }, },
  { 3180 /* ldstub */, SP::LDSTUBri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 3180 /* ldstub */, SP::LDSTUBrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 3187 /* ldstuba */, SP::LDSTUBAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntRegs }, },
  { 3187 /* ldstuba */, SP::LDSTUBArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntRegs }, },
  { 3195 /* ldsw */, SP::LDSWri, Convert__Reg1_3__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 3195 /* ldsw */, SP::LDSWrr, Convert__Reg1_3__MEMrr2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 3200 /* ldswa */, SP::LDSWAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntRegs }, },
  { 3200 /* ldswa */, SP::LDSWArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntRegs }, },
  { 3206 /* ldub */, SP::LDUBri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 3206 /* ldub */, SP::LDUBrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 3211 /* lduba */, SP::LDUBAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntRegs }, },
  { 3211 /* lduba */, SP::LDUBArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntRegs }, },
  { 3217 /* lduh */, SP::LDUHri, Convert__Reg1_3__MEMri2_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 3217 /* lduh */, SP::LDUHrr, Convert__Reg1_3__MEMrr2_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 3222 /* lduha */, SP::LDUHAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntRegs }, },
  { 3222 /* lduha */, SP::LDUHArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntRegs }, },
  { 3228 /* ldx */, SP::LDXFSRri, Convert__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK_FSR }, },
  { 3228 /* ldx */, SP::LDXri, Convert__Reg1_3__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 3228 /* ldx */, SP::LDXFSRrr, Convert__MEMrr2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_FSR }, },
  { 3228 /* ldx */, SP::LDXrr, Convert__Reg1_3__MEMrr2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 3228 /* ldx */, SP::GDOP_LDXrr, Convert__Reg1_3__MEMrr2_1__TailRelocSymLoad_GOT1_4, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs, MCK_TailRelocSymLoad_GOT }, },
  { 3228 /* ldx */, SP::TLS_LDXrr, Convert__Reg1_3__MEMrr2_1__TailRelocSymLoad_TLS1_4, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs, MCK_TailRelocSymLoad_TLS }, },
  { 3232 /* ldxa */, SP::LDXAri, Convert__Reg1_4__MEMri2_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntRegs }, },
  { 3232 /* ldxa */, SP::LDXArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntRegs }, },
  { 3237 /* lzcnt */, SP::LZCNT, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS3, { MCK_IntRegs, MCK_IntRegs }, },
  { 3243 /* md5 */, SP::MD5, Convert_NoOperands, AMFBS_HasCrypto, {  }, },
  { 3247 /* membar */, SP::MEMBARi, Convert__MembarTag1_0, AMFBS_HasV9, { MCK_MembarTag }, },
  { 3254 /* montmul */, SP::MONTMUL, Convert__Imm1_0, AMFBS_HasCrypto, { MCK_Imm }, },
  { 3262 /* montsqr */, SP::MONTSQR, Convert__Imm1_0, AMFBS_HasCrypto, { MCK_Imm }, },
  { 3270 /* mov */, SP::RDPSR, Convert__Reg1_1, AMFBS_None, { MCK_PSR, MCK_IntRegs }, },
  { 3270 /* mov */, SP::RDTBR, Convert__Reg1_1, AMFBS_None, { MCK_TBR, MCK_IntRegs }, },
  { 3270 /* mov */, SP::RDWIM, Convert__Reg1_1, AMFBS_None, { MCK_WIM, MCK_IntRegs }, },
  { 3270 /* mov */, SP::WRPSRrr, Convert__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_PSR }, },
  { 3270 /* mov */, SP::WRTBRrr, Convert__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_TBR }, },
  { 3270 /* mov */, SP::WRWIMrr, Convert__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_WIM }, },
  { 3270 /* mov */, SP::ORrr, Convert__Reg1_1__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::WRASRrr, Convert__Reg1_1__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_ASRRegs }, },
  { 3270 /* mov */, SP::RDASR, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_ASRRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::WRPSRri, Convert__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_PSR }, },
  { 3270 /* mov */, SP::WRTBRri, Convert__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_TBR }, },
  { 3270 /* mov */, SP::WRWIMri, Convert__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_WIM }, },
  { 3270 /* mov */, SP::ORri, Convert__Reg1_1__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 3270 /* mov */, SP::WRASRri, Convert__Reg1_1__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_ASRRegs }, },
  { 3270 /* mov */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3270 /* mov */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVXCCrr, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVXCCri, Convert__Reg1_3__Imm1_2__Tie0_1_1__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVFCCrr, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCC0, MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVFCCri, Convert__Reg1_3__Imm1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCC0, MCK_Imm, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVICCrr, Convert__Reg1_3__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::MOVICCri, Convert__Reg1_3__Imm1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3270 /* mov */, SP::V9MOVFCCrr, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3270 /* mov */, SP::V9MOVFCCri, Convert__Reg1_3__Reg1_1__Imm1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3274 /* mova */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3274 /* mova */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3274 /* mova */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3274 /* mova */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3274 /* mova */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3274 /* mova */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3274 /* mova */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3274 /* mova */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3274 /* mova */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3274 /* mova */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_8, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3279 /* movcc */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3279 /* movcc */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3279 /* movcc */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3279 /* movcc */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3279 /* movcc */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3279 /* movcc */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3279 /* movcc */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3279 /* movcc */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3285 /* movcs */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3285 /* movcs */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3285 /* movcs */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3285 /* movcs */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3285 /* movcs */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3285 /* movcs */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3285 /* movcs */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3285 /* movcs */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3291 /* movdtox */, SP::MOVDTOX, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_IntRegs }, },
  { 3299 /* move */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3299 /* move */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3299 /* move */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3299 /* move */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3299 /* move */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3299 /* move */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3299 /* move */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3299 /* move */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3299 /* move */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3299 /* move */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3304 /* moveq */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3304 /* moveq */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3304 /* moveq */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3304 /* moveq */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3304 /* moveq */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3304 /* moveq */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3304 /* moveq */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3304 /* moveq */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3310 /* movg */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3310 /* movg */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3310 /* movg */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3310 /* movg */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3310 /* movg */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3310 /* movg */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3310 /* movg */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3310 /* movg */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3310 /* movg */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3310 /* movg */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3315 /* movge */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3315 /* movge */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3315 /* movge */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_11, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3315 /* movge */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3315 /* movge */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3315 /* movge */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_11, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3315 /* movge */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3315 /* movge */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3315 /* movge */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3315 /* movge */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_11, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3321 /* movgeu */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3321 /* movgeu */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3321 /* movgeu */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3321 /* movgeu */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3321 /* movgeu */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3321 /* movgeu */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3321 /* movgeu */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3321 /* movgeu */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3328 /* movgt */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3328 /* movgt */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3328 /* movgt */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3328 /* movgt */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3328 /* movgt */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3328 /* movgt */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3328 /* movgt */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3328 /* movgt */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3334 /* movgu */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3334 /* movgu */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3334 /* movgu */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_12, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3334 /* movgu */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3334 /* movgu */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3334 /* movgu */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_12, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3334 /* movgu */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3334 /* movgu */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3340 /* movl */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3340 /* movl */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3340 /* movl */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3340 /* movl */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3340 /* movl */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3340 /* movl */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3340 /* movl */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3340 /* movl */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3340 /* movl */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3340 /* movl */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3345 /* movle */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3345 /* movle */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3345 /* movle */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_2, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3345 /* movle */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3345 /* movle */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3345 /* movle */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3345 /* movle */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3345 /* movle */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3345 /* movle */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3345 /* movle */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_13, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3351 /* movleu */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3351 /* movleu */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3351 /* movleu */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_4, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3351 /* movleu */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3351 /* movleu */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3351 /* movleu */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_4, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3351 /* movleu */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3351 /* movleu */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3358 /* movlg */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3358 /* movlg */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_2, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3364 /* movlt */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3364 /* movlt */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3364 /* movlt */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3364 /* movlt */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3364 /* movlt */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3364 /* movlt */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3364 /* movlt */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3364 /* movlt */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3370 /* movlu */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3370 /* movlu */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3370 /* movlu */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3370 /* movlu */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3370 /* movlu */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3370 /* movlu */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3370 /* movlu */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3370 /* movlu */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3376 /* movn */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3376 /* movn */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3376 /* movn */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_0, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3376 /* movn */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3376 /* movn */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3376 /* movn */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_0, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3376 /* movn */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3376 /* movn */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3376 /* movn */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3376 /* movn */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_0, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3381 /* movne */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3381 /* movne */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3381 /* movne */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3381 /* movne */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3381 /* movne */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3381 /* movne */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3381 /* movne */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3381 /* movne */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3381 /* movne */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3381 /* movne */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3387 /* movneg */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3387 /* movneg */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3387 /* movneg */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_6, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3387 /* movneg */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3387 /* movneg */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3387 /* movneg */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3387 /* movneg */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3387 /* movneg */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3394 /* movnz */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3400 /* movo */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3400 /* movo */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3405 /* movpos */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3405 /* movpos */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3405 /* movpos */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_14, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3405 /* movpos */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3405 /* movpos */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3405 /* movpos */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_14, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3405 /* movpos */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3405 /* movpos */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3412 /* movr */, SP::MOVRrr, Convert__Reg1_3__Reg1_1__Reg1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3412 /* movr */, SP::MOVRri, Convert__Reg1_3__Reg1_1__Imm1_2__Tie0_1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3417 /* movre */, SP::MOVRrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3417 /* movre */, SP::MOVRri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3423 /* movrgez */, SP::MOVRrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3423 /* movrgez */, SP::MOVRri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3431 /* movrgz */, SP::MOVRrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3431 /* movrgz */, SP::MOVRri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_6, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3438 /* movrlez */, SP::MOVRrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3438 /* movrlez */, SP::MOVRri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_2, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3446 /* movrlz */, SP::MOVRrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3446 /* movrlz */, SP::MOVRri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3453 /* movrne */, SP::MOVRrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3453 /* movrne */, SP::MOVRri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3460 /* movrnz */, SP::MOVRrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3460 /* movrnz */, SP::MOVRri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3467 /* movrz */, SP::MOVRrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3467 /* movrz */, SP::MOVRri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3473 /* movstosw */, SP::MOVSTOSW, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS3, { MCK_FPRegs, MCK_IntRegs }, },
  { 3482 /* movstouw */, SP::MOVSTOUW, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS3, { MCK_FPRegs, MCK_IntRegs }, },
  { 3491 /* movu */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3491 /* movu */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3496 /* movue */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3496 /* movue */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_10, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3502 /* movug */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3502 /* movug */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_5, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3508 /* movuge */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3508 /* movuge */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_12, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3515 /* movul */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3515 /* movul */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_3, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3521 /* movule */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3521 /* movule */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_14, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3528 /* movvc */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3528 /* movvc */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3528 /* movvc */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_15, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3528 /* movvc */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3528 /* movvc */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3528 /* movvc */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_15, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3528 /* movvc */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3528 /* movvc */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3534 /* movvs */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3534 /* movvs */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3534 /* movvs */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_7, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3534 /* movvs */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3534 /* movvs */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3534 /* movvs */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_7, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3534 /* movvs */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3534 /* movvs */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3540 /* movwtos */, SP::MOVWTOS, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS3, { MCK_IntRegs, MCK_FPRegs }, },
  { 3548 /* movxtod */, SP::MOVXTOD, Convert__Reg1_1__Reg1_0, AMFBS_HasVIS3, { MCK_IntRegs, MCK_DFPRegs }, },
  { 3556 /* movz */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3556 /* movz */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK_IntRegs }, },
  { 3556 /* movz */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is32Bit_HasV9, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3556 /* movz */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_ncc, MCK_Imm, MCK_IntRegs }, },
  { 3556 /* movz */, SP::MOVXCCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_IntRegs, MCK_IntRegs }, },
  { 3556 /* movz */, SP::MOVXCCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_Is64Bit, { MCK__PCT_xcc, MCK_Imm, MCK_IntRegs }, },
  { 3556 /* movz */, SP::MOVICCrr, Convert__Reg1_2__Reg1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK_IntRegs }, },
  { 3556 /* movz */, SP::MOVICCri, Convert__Reg1_2__Imm1_1__Tie0_3_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_Imm, MCK_IntRegs }, },
  { 3556 /* movz */, SP::V9MOVFCCrr, Convert__Reg1_2__Reg1_0__Reg1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3556 /* movz */, SP::V9MOVFCCri, Convert__Reg1_2__Reg1_0__Imm1_1__Tie0_3_3__imm_95_9, AMFBS_HasV9, { MCK_FCCRegs, MCK_Imm, MCK_IntRegs }, },
  { 3561 /* mpmul */, SP::MPMUL, Convert__Imm1_0, AMFBS_HasCrypto, { MCK_Imm }, },
  { 3567 /* mulscc */, SP::MULSCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3567 /* mulscc */, SP::MULSCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3574 /* mulx */, SP::MULXrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3574 /* mulx */, SP::MULXri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3579 /* neg */, SP::SUBrr, Convert__Reg1_0__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs }, },
  { 3579 /* neg */, SP::SUBrr, Convert__Reg1_1__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_IntRegs }, },
  { 3583 /* nop */, SP::NOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 3587 /* normalw */, SP::NORMALW, Convert_NoOperands, AMFBS_HasUA2005, {  }, },
  { 3595 /* not */, SP::XNORrr, Convert__Reg1_0__Reg1_0__regG0, AMFBS_None, { MCK_IntRegs }, },
  { 3595 /* not */, SP::XNORrr, Convert__Reg1_1__Reg1_0__regG0, AMFBS_None, { MCK_IntRegs, MCK_IntRegs }, },
  { 3599 /* or */, SP::ORrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3599 /* or */, SP::ORri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3599 /* or */, SP::ORri, Convert__Reg1_2__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs, MCK_IntRegs }, },
  { 3602 /* orcc */, SP::ORCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3602 /* orcc */, SP::ORCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3607 /* orn */, SP::ORNrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3607 /* orn */, SP::ORNri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3611 /* orncc */, SP::ORNCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3611 /* orncc */, SP::ORNCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3617 /* otherw */, SP::OTHERW, Convert_NoOperands, AMFBS_HasUA2005, {  }, },
  { 3624 /* pause */, SP::WRASRrr, Convert__regASR27__regG0__Reg1_0, AMFBS_HasOSA2011, { MCK_IntRegs }, },
  { 3624 /* pause */, SP::WRASRri, Convert__regASR27__regG0__Imm1_0, AMFBS_HasOSA2011, { MCK_Imm }, },
  { 3630 /* pdist */, SP::PDIST, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS, { MCK_DFPRegs, MCK_DFPRegs, MCK_DFPRegs }, },
  { 3636 /* pdistn */, SP::PDISTN, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_DFPRegs, MCK_DFPRegs, MCK_IntRegs }, },
  { 3643 /* popc */, SP::POPCrr, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_IntRegs, MCK_IntRegs }, },
  { 3648 /* prefetch */, SP::PREFETCHi, Convert__MEMri2_1__PrefetchTag1_3, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK_PrefetchTag }, },
  { 3648 /* prefetch */, SP::PREFETCHr, Convert__MEMrr2_1__PrefetchTag1_3, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_PrefetchTag }, },
  { 3657 /* prefetcha */, SP::PREFETCHAi, Convert__MEMri2_1__PrefetchTag1_4, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_PrefetchTag }, },
  { 3657 /* prefetcha */, SP::PREFETCHAr, Convert__MEMrr2_1__ASITag1_3__PrefetchTag1_4, AMFBS_HasV9, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_PrefetchTag }, },
  { 3667 /* pwr */, SP::PWRPSRrr, Convert__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_PSR }, },
  { 3667 /* pwr */, SP::PWRPSRri, Convert__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_PSR }, },
  { 3667 /* pwr */, SP::PWRPSRrr, Convert__Reg1_0__Reg1_1, AMFBS_HasPWRPSR, { MCK_IntRegs, MCK_IntRegs, MCK_PSR }, },
  { 3667 /* pwr */, SP::PWRPSRri, Convert__Reg1_0__Imm1_1, AMFBS_HasPWRPSR, { MCK_IntRegs, MCK_Imm, MCK_PSR }, },
  { 3671 /* rd */, SP::RDPSR, Convert__Reg1_1, AMFBS_None, { MCK_PSR, MCK_IntRegs }, },
  { 3671 /* rd */, SP::RDTBR, Convert__Reg1_1, AMFBS_None, { MCK_TBR, MCK_IntRegs }, },
  { 3671 /* rd */, SP::RDWIM, Convert__Reg1_1, AMFBS_None, { MCK_WIM, MCK_IntRegs }, },
  { 3671 /* rd */, SP::RDASR, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_ASRRegs, MCK_IntRegs }, },
  { 3674 /* rdpr */, SP::RDFQ, Convert__Reg1_1, AMFBS_HasV9, { MCK_FQ, MCK_IntRegs }, },
  { 3674 /* rdpr */, SP::RDPR, Convert__Reg1_1__Reg1_0, AMFBS_HasV9, { MCK_PRRegs, MCK_IntRegs }, },
  { 3679 /* restore */, SP::RESTORErr, Convert__regG0__regG0__regG0, AMFBS_None, {  }, },
  { 3679 /* restore */, SP::RESTORErr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3679 /* restore */, SP::RESTOREri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3687 /* restored */, SP::RESTORED, Convert_NoOperands, AMFBS_HasV9, {  }, },
  { 3696 /* ret */, SP::RET, Convert__imm_95_8, AMFBS_None, {  }, },
  { 3700 /* retl */, SP::RETL, Convert__imm_95_8, AMFBS_None, {  }, },
  { 3705 /* retry */, SP::RETRY, Convert_NoOperands, AMFBS_HasV9, {  }, },
  { 3711 /* rett */, SP::RETTri, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 3711 /* rett */, SP::RETTrr, Convert__MEMrr2_0, AMFBS_None, { MCK_MEMrr }, },
  { 3716 /* save */, SP::SAVErr, Convert__regG0__regG0__regG0, AMFBS_None, {  }, },
  { 3716 /* save */, SP::SAVErr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3716 /* save */, SP::SAVEri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3721 /* saved */, SP::SAVED, Convert_NoOperands, AMFBS_HasV9, {  }, },
  { 3727 /* sdiv */, SP::SDIVrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3727 /* sdiv */, SP::SDIVri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3732 /* sdivcc */, SP::SDIVCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3732 /* sdivcc */, SP::SDIVCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3739 /* sdivx */, SP::SDIVXrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3739 /* sdivx */, SP::SDIVXri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3745 /* set */, SP::SET, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 3749 /* sethi */, SP::SETHIi, Convert__Reg1_1__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs }, },
  { 3755 /* setsw */, SP::SETSW, Convert__Reg1_1__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_IntRegs }, },
  { 3761 /* setx */, SP::SETX, Convert__Reg1_2__Imm1_0__Reg1_1, AMFBS_Is64Bit_HasV9, { MCK_Imm, MCK_IntRegs, MCK_IntRegs }, },
  { 3766 /* sha1 */, SP::SHA1, Convert_NoOperands, AMFBS_HasCrypto, {  }, },
  { 3771 /* sha256 */, SP::SHA256, Convert_NoOperands, AMFBS_HasCrypto, {  }, },
  { 3778 /* sha512 */, SP::SHA512, Convert_NoOperands, AMFBS_HasCrypto, {  }, },
  { 3785 /* shutdown */, SP::SHUTDOWN, Convert_NoOperands, AMFBS_HasVIS, {  }, },
  { 3794 /* siam */, SP::SIAM, Convert__Imm1_0, AMFBS_HasVIS2, { MCK_Imm }, },
  { 3799 /* signx */, SP::SRArr, Convert__Reg1_0__Reg1_0__regG0, AMFBS_HasV9, { MCK_IntRegs }, },
  { 3799 /* signx */, SP::SRArr, Convert__Reg1_1__Reg1_0__regG0, AMFBS_HasV9, { MCK_IntRegs, MCK_IntRegs }, },
  { 3805 /* sir */, SP::SIR, Convert__imm_95_0, AMFBS_None, {  }, },
  { 3805 /* sir */, SP::SIR, Convert__Imm1_0, AMFBS_HasV9, { MCK_Imm }, },
  { 3809 /* sll */, SP::SLLrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3809 /* sll */, SP::SLLri, Convert__Reg1_2__Reg1_0__ShiftAmtImm51_1, AMFBS_None, { MCK_IntRegs, MCK_ShiftAmtImm5, MCK_IntRegs }, },
  { 3813 /* sllx */, SP::SLLXrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3813 /* sllx */, SP::SLLXri, Convert__Reg1_2__Reg1_0__ShiftAmtImm61_1, AMFBS_HasV9, { MCK_IntRegs, MCK_ShiftAmtImm6, MCK_IntRegs }, },
  { 3818 /* smac */, SP::SMACrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3818 /* smac */, SP::SMACri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3823 /* smul */, SP::SMULrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3823 /* smul */, SP::SMULri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3828 /* smulcc */, SP::SMULCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3828 /* smulcc */, SP::SMULCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3835 /* sra */, SP::SRArr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3835 /* sra */, SP::SRAri, Convert__Reg1_2__Reg1_0__ShiftAmtImm51_1, AMFBS_None, { MCK_IntRegs, MCK_ShiftAmtImm5, MCK_IntRegs }, },
  { 3839 /* srax */, SP::SRAXrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3839 /* srax */, SP::SRAXri, Convert__Reg1_2__Reg1_0__ShiftAmtImm61_1, AMFBS_HasV9, { MCK_IntRegs, MCK_ShiftAmtImm6, MCK_IntRegs }, },
  { 3844 /* srl */, SP::SRLrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3844 /* srl */, SP::SRLri, Convert__Reg1_2__Reg1_0__ShiftAmtImm51_1, AMFBS_None, { MCK_IntRegs, MCK_ShiftAmtImm5, MCK_IntRegs }, },
  { 3848 /* srlx */, SP::SRLXrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3848 /* srlx */, SP::SRLXri, Convert__Reg1_2__Reg1_0__ShiftAmtImm61_1, AMFBS_HasV9, { MCK_IntRegs, MCK_ShiftAmtImm6, MCK_IntRegs }, },
  { 3853 /* st */, SP::STCSRri, Convert__MEMri2_2, AMFBS_None, { MCK_CPSR, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3853 /* st */, SP::STCSRrr, Convert__MEMrr2_2, AMFBS_None, { MCK_CPSR, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3853 /* st */, SP::STFSRri, Convert__MEMri2_2, AMFBS_None, { MCK_FSR, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3853 /* st */, SP::STFSRrr, Convert__MEMrr2_2, AMFBS_None, { MCK_FSR, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3853 /* st */, SP::STCri, Convert__MEMri2_2__Reg1_0, AMFBS_None, { MCK_CoprocRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3853 /* st */, SP::STCrr, Convert__MEMrr2_2__Reg1_0, AMFBS_None, { MCK_CoprocRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3853 /* st */, SP::STFri, Convert__MEMri2_2__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3853 /* st */, SP::STFrr, Convert__MEMrr2_2__Reg1_0, AMFBS_None, { MCK_FPRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3853 /* st */, SP::STri, Convert__MEMri2_2__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3853 /* st */, SP::STrr, Convert__MEMrr2_2__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3856 /* sta */, SP::STFAri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_FPRegs, MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi }, },
  { 3856 /* sta */, SP::STFArr, Convert__MEMrr2_2__Reg1_0__ASITag1_4, AMFBS_HasV9, { MCK_FPRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag }, },
  { 3856 /* sta */, SP::STAri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi }, },
  { 3856 /* sta */, SP::STArr, Convert__MEMrr2_2__Reg1_0__ASITag1_4, AMFBS_None, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag }, },
  { 3860 /* stb */, SP::STBri, Convert__MEMri2_2__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3860 /* stb */, SP::STBrr, Convert__MEMrr2_2__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3864 /* stba */, SP::STBAri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi }, },
  { 3864 /* stba */, SP::STBArr, Convert__MEMrr2_2__Reg1_0__ASITag1_4, AMFBS_None, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag }, },
  { 3869 /* stbar */, SP::STBAR, Convert_NoOperands, AMFBS_None, {  }, },
  { 3875 /* std */, SP::STDCQri, Convert__MEMri2_2, AMFBS_None, { MCK_CPQ, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3875 /* std */, SP::STDCQrr, Convert__MEMrr2_2, AMFBS_None, { MCK_CPQ, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3875 /* std */, SP::STDFQri, Convert__MEMri2_2, AMFBS_None, { MCK_FQ, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3875 /* std */, SP::STDFQrr, Convert__MEMrr2_2, AMFBS_None, { MCK_FQ, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3875 /* std */, SP::STDCri, Convert__MEMri2_2__Reg1_0, AMFBS_None, { MCK_CoprocPair, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3875 /* std */, SP::STDCrr, Convert__MEMrr2_2__Reg1_0, AMFBS_None, { MCK_CoprocPair, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3875 /* std */, SP::STDri, Convert__MEMri2_2__Reg1_0, AMFBS_None, { MCK_IntPair, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3875 /* std */, SP::STDrr, Convert__MEMrr2_2__Reg1_0, AMFBS_None, { MCK_IntPair, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3875 /* std */, SP::STDFri, Convert__MEMri2_2__Reg1_0, AMFBS_None, { MCK_DFPRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3875 /* std */, SP::STDFrr, Convert__MEMrr2_2__Reg1_0, AMFBS_None, { MCK_DFPRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3879 /* stda */, SP::STDAri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_IntPair, MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi }, },
  { 3879 /* stda */, SP::STDArr, Convert__MEMrr2_2__Reg1_0__ASITag1_4, AMFBS_None, { MCK_IntPair, MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag }, },
  { 3879 /* stda */, SP::STDFAri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_DFPRegs, MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi }, },
  { 3879 /* stda */, SP::STDFArr, Convert__MEMrr2_2__Reg1_0__ASITag1_4, AMFBS_HasV9, { MCK_DFPRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag }, },
  { 3884 /* sth */, SP::STHri, Convert__MEMri2_2__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3884 /* sth */, SP::STHrr, Convert__MEMrr2_2__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3888 /* stha */, SP::STHAri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi }, },
  { 3888 /* stha */, SP::STHArr, Convert__MEMrr2_2__Reg1_0__ASITag1_4, AMFBS_None, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag }, },
  { 3893 /* stq */, SP::STQFri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_QFPRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3893 /* stq */, SP::STQFrr, Convert__MEMrr2_2__Reg1_0, AMFBS_HasV9, { MCK_QFPRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3897 /* stqa */, SP::STQFAri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_QFPRegs, MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi }, },
  { 3897 /* stqa */, SP::STQFArr, Convert__MEMrr2_2__Reg1_0__ASITag1_4, AMFBS_HasV9, { MCK_QFPRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag }, },
  { 3902 /* stx */, SP::STXFSRri, Convert__MEMri2_2, AMFBS_HasV9, { MCK_FSR, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3902 /* stx */, SP::STXFSRrr, Convert__MEMrr2_2, AMFBS_HasV9, { MCK_FSR, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3902 /* stx */, SP::STXri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_ }, },
  { 3902 /* stx */, SP::STXrr, Convert__MEMrr2_2__Reg1_0, AMFBS_HasV9, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_ }, },
  { 3906 /* stxa */, SP::STXAri, Convert__MEMri2_2__Reg1_0, AMFBS_HasV9, { MCK_IntRegs, MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi }, },
  { 3906 /* stxa */, SP::STXArr, Convert__MEMrr2_2__Reg1_0__ASITag1_4, AMFBS_HasV9, { MCK_IntRegs, MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag }, },
  { 3911 /* sub */, SP::SUBrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3911 /* sub */, SP::SUBri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3915 /* subcc */, SP::SUBCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3915 /* subcc */, SP::SUBCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3921 /* subx */, SP::SUBCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3921 /* subx */, SP::SUBCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3926 /* subxcc */, SP::SUBErr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3926 /* subxcc */, SP::SUBEri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3933 /* swap */, SP::SWAPri, Convert__Reg1_3__MEMri2_1__Tie0_1_1, AMFBS_None, { MCK__91_, MCK_MEMri, MCK__93_, MCK_IntRegs }, },
  { 3933 /* swap */, SP::SWAPrr, Convert__Reg1_3__MEMrr2_1__Tie0_1_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_IntRegs }, },
  { 3938 /* swapa */, SP::SWAPAri, Convert__Reg1_4__MEMri2_1__Tie0_1_1, AMFBS_HasV9, { MCK__91_, MCK_MEMri, MCK__93_, MCK__PCT_asi, MCK_IntRegs }, },
  { 3938 /* swapa */, SP::SWAPArr, Convert__Reg1_4__MEMrr2_1__ASITag1_3__Tie0_1_1, AMFBS_None, { MCK__91_, MCK_MEMrr, MCK__93_, MCK_ASITag, MCK_IntRegs }, },
  { 3944 /* t */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_8, AMFBS_None, { MCK_IntRegs }, },
  { 3944 /* t */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_8, AMFBS_None, { MCK_Imm }, },
  { 3944 /* t */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3944 /* t */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_8, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3944 /* t */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3944 /* t */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_8, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3944 /* t */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_8, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3944 /* t */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_8, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3944 /* t */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3944 /* t */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3944 /* t */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_8, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3944 /* t */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_8, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3944 /* t */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3944 /* t */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_8, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3944 /* t */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3944 /* t */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_8, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3944 /* t */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_8, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3944 /* t */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_8, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3944 /* t */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3944 /* t */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3944 /* t */, SP::TRAPrr, Convert__Reg1_1__Reg1_3__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3944 /* t */, SP::TRAPri, Convert__Reg1_1__Imm1_3__Imm1_0, AMFBS_None, { MCK_Imm, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3944 /* t */, SP::TXCCrr, Convert__Reg1_2__Reg1_4__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3944 /* t */, SP::TXCCri, Convert__Reg1_2__Imm1_4__Imm1_0, AMFBS_Is64Bit, { MCK_Imm, MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3944 /* t */, SP::TICCrr, Convert__Reg1_2__Reg1_4__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3944 /* t */, SP::TICCri, Convert__Reg1_2__Imm1_4__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3946 /* ta */, SP::TA1, Convert_NoOperands, AMFBS_None, { MCK_1 }, },
  { 3946 /* ta */, SP::TA3, Convert_NoOperands, AMFBS_None, { MCK_3 }, },
  { 3946 /* ta */, SP::TA5, Convert_NoOperands, AMFBS_None, { MCK_5 }, },
  { 3946 /* ta */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_8, AMFBS_None, { MCK_IntRegs }, },
  { 3946 /* ta */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_8, AMFBS_None, { MCK_Imm }, },
  { 3946 /* ta */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3946 /* ta */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_8, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3946 /* ta */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3946 /* ta */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_8, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3946 /* ta */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_8, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3946 /* ta */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_8, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3946 /* ta */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3946 /* ta */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3946 /* ta */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_8, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3946 /* ta */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_8, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3946 /* ta */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3946 /* ta */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_8, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3946 /* ta */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_8, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3946 /* ta */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_8, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3946 /* ta */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_8, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3946 /* ta */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_8, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3946 /* ta */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3946 /* ta */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_8, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3949 /* taddcc */, SP::TADDCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3949 /* taddcc */, SP::TADDCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3956 /* taddcctv */, SP::TADDCCTVrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 3956 /* taddcctv */, SP::TADDCCTVri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_13, AMFBS_None, { MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_13, AMFBS_None, { MCK_Imm }, },
  { 3965 /* tcc */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_13, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3965 /* tcc */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_13, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3965 /* tcc */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_13, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_13, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3965 /* tcc */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3965 /* tcc */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_13, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_13, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3965 /* tcc */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_13, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3965 /* tcc */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_13, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3965 /* tcc */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_13, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_13, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3965 /* tcc */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3965 /* tcc */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3969 /* tcs */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_5, AMFBS_None, { MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_5, AMFBS_None, { MCK_Imm }, },
  { 3969 /* tcs */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_5, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3969 /* tcs */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_5, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3969 /* tcs */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_5, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_5, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3969 /* tcs */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3969 /* tcs */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_5, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_5, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3969 /* tcs */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_5, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3969 /* tcs */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_5, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3969 /* tcs */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_5, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_5, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3969 /* tcs */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3969 /* tcs */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3973 /* te */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_1, AMFBS_None, { MCK_IntRegs }, },
  { 3973 /* te */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_1, AMFBS_None, { MCK_Imm }, },
  { 3973 /* te */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3973 /* te */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3973 /* te */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3973 /* te */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3973 /* te */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3973 /* te */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3973 /* te */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3973 /* te */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3973 /* te */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_1, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3973 /* te */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_1, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3973 /* te */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3973 /* te */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3973 /* te */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3973 /* te */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3973 /* te */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3973 /* te */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3973 /* te */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3973 /* te */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3976 /* teq */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_1, AMFBS_None, { MCK_IntRegs }, },
  { 3976 /* teq */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_1, AMFBS_None, { MCK_Imm }, },
  { 3976 /* teq */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3976 /* teq */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3976 /* teq */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3976 /* teq */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3976 /* teq */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3976 /* teq */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3976 /* teq */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3976 /* teq */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3976 /* teq */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_1, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3976 /* teq */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_1, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3976 /* teq */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3976 /* teq */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3976 /* teq */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3976 /* teq */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3976 /* teq */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3976 /* teq */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3976 /* teq */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3976 /* teq */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3980 /* tg */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_10, AMFBS_None, { MCK_IntRegs }, },
  { 3980 /* tg */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_10, AMFBS_None, { MCK_Imm }, },
  { 3980 /* tg */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3980 /* tg */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_10, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3980 /* tg */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3980 /* tg */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_10, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3980 /* tg */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_10, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3980 /* tg */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_10, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3980 /* tg */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3980 /* tg */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3980 /* tg */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_10, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3980 /* tg */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_10, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3980 /* tg */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3980 /* tg */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_10, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3980 /* tg */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3980 /* tg */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_10, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3980 /* tg */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_10, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3980 /* tg */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_10, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3980 /* tg */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3980 /* tg */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3983 /* tge */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_11, AMFBS_None, { MCK_IntRegs }, },
  { 3983 /* tge */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_11, AMFBS_None, { MCK_Imm }, },
  { 3983 /* tge */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3983 /* tge */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_11, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3983 /* tge */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3983 /* tge */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_11, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3983 /* tge */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_11, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3983 /* tge */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_11, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3983 /* tge */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3983 /* tge */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3983 /* tge */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_11, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3983 /* tge */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_11, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3983 /* tge */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3983 /* tge */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_11, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3983 /* tge */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_11, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3983 /* tge */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_11, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3983 /* tge */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_11, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3983 /* tge */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_11, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3983 /* tge */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3983 /* tge */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_11, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3987 /* tgeu */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_13, AMFBS_None, { MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_13, AMFBS_None, { MCK_Imm }, },
  { 3987 /* tgeu */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_13, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3987 /* tgeu */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_13, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3987 /* tgeu */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_13, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_13, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3987 /* tgeu */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3987 /* tgeu */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_13, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_13, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3987 /* tgeu */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_13, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_13, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3987 /* tgeu */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_13, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3987 /* tgeu */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_13, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_13, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3987 /* tgeu */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3987 /* tgeu */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_13, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3992 /* tgt */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_10, AMFBS_None, { MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_10, AMFBS_None, { MCK_Imm }, },
  { 3992 /* tgt */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_10, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3992 /* tgt */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_10, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3992 /* tgt */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_10, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_10, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3992 /* tgt */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3992 /* tgt */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_10, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_10, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3992 /* tgt */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_10, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_10, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3992 /* tgt */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_10, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3992 /* tgt */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_10, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_10, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3992 /* tgt */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3992 /* tgt */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_10, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3996 /* tgu */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_12, AMFBS_None, { MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_12, AMFBS_None, { MCK_Imm }, },
  { 3996 /* tgu */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_12, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3996 /* tgu */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_12, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 3996 /* tgu */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_12, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_12, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 3996 /* tgu */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 3996 /* tgu */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_12, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_12, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3996 /* tgu */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_12, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_12, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3996 /* tgu */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_12, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3996 /* tgu */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_12, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_12, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 3996 /* tgu */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 3996 /* tgu */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_12, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4000 /* tl */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_3, AMFBS_None, { MCK_IntRegs }, },
  { 4000 /* tl */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_3, AMFBS_None, { MCK_Imm }, },
  { 4000 /* tl */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4000 /* tl */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_3, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4000 /* tl */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4000 /* tl */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_3, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4000 /* tl */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_3, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4000 /* tl */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_3, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4000 /* tl */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4000 /* tl */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4000 /* tl */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_3, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4000 /* tl */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_3, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4000 /* tl */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4000 /* tl */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_3, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4000 /* tl */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4000 /* tl */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_3, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4000 /* tl */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_3, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4000 /* tl */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_3, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4000 /* tl */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4000 /* tl */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4003 /* tle */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_2, AMFBS_None, { MCK_IntRegs }, },
  { 4003 /* tle */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_2, AMFBS_None, { MCK_Imm }, },
  { 4003 /* tle */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4003 /* tle */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_2, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4003 /* tle */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4003 /* tle */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_2, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4003 /* tle */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_2, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4003 /* tle */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_2, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4003 /* tle */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4003 /* tle */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4003 /* tle */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_2, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4003 /* tle */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_2, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4003 /* tle */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4003 /* tle */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_2, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4003 /* tle */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_2, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4003 /* tle */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_2, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4003 /* tle */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_2, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4003 /* tle */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_2, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4003 /* tle */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4003 /* tle */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_2, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4007 /* tleu */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_4, AMFBS_None, { MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_4, AMFBS_None, { MCK_Imm }, },
  { 4007 /* tleu */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_4, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4007 /* tleu */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_4, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4007 /* tleu */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_4, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_4, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4007 /* tleu */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4007 /* tleu */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_4, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_4, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4007 /* tleu */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_4, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_4, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4007 /* tleu */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_4, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4007 /* tleu */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_4, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_4, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4007 /* tleu */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4007 /* tleu */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_4, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4012 /* tlt */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_3, AMFBS_None, { MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_3, AMFBS_None, { MCK_Imm }, },
  { 4012 /* tlt */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_3, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4012 /* tlt */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_3, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4012 /* tlt */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_3, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_3, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4012 /* tlt */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4012 /* tlt */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_3, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_3, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4012 /* tlt */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_3, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_3, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4012 /* tlt */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_3, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4012 /* tlt */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_3, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_3, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4012 /* tlt */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4012 /* tlt */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_3, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4016 /* tlu */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_5, AMFBS_None, { MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_5, AMFBS_None, { MCK_Imm }, },
  { 4016 /* tlu */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_5, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4016 /* tlu */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_5, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4016 /* tlu */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_5, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_5, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4016 /* tlu */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4016 /* tlu */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_5, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_5, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4016 /* tlu */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_5, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_5, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4016 /* tlu */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_5, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4016 /* tlu */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_5, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_5, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4016 /* tlu */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4016 /* tlu */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_5, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4020 /* tn */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_0, AMFBS_None, { MCK_IntRegs }, },
  { 4020 /* tn */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_0, AMFBS_None, { MCK_Imm }, },
  { 4020 /* tn */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4020 /* tn */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_0, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4020 /* tn */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4020 /* tn */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_0, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4020 /* tn */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_0, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4020 /* tn */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_0, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4020 /* tn */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4020 /* tn */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4020 /* tn */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_0, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4020 /* tn */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_0, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4020 /* tn */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4020 /* tn */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_0, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4020 /* tn */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_0, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4020 /* tn */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_0, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4020 /* tn */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_0, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4020 /* tn */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_0, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4020 /* tn */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4020 /* tn */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_0, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4023 /* tne */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_9, AMFBS_None, { MCK_IntRegs }, },
  { 4023 /* tne */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_9, AMFBS_None, { MCK_Imm }, },
  { 4023 /* tne */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4023 /* tne */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_9, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4023 /* tne */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4023 /* tne */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_9, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4023 /* tne */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_9, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4023 /* tne */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_9, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4023 /* tne */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4023 /* tne */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4023 /* tne */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_9, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4023 /* tne */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_9, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4023 /* tne */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4023 /* tne */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_9, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4023 /* tne */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4023 /* tne */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_9, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4023 /* tne */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_9, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4023 /* tne */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_9, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4023 /* tne */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4023 /* tne */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4027 /* tneg */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_6, AMFBS_None, { MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_6, AMFBS_None, { MCK_Imm }, },
  { 4027 /* tneg */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_6, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4027 /* tneg */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_6, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4027 /* tneg */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_6, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_6, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4027 /* tneg */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4027 /* tneg */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_6, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_6, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4027 /* tneg */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_6, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_6, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4027 /* tneg */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_6, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4027 /* tneg */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_6, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_6, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4027 /* tneg */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4027 /* tneg */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_6, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4032 /* tnz */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_9, AMFBS_None, { MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_9, AMFBS_None, { MCK_Imm }, },
  { 4032 /* tnz */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_9, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4032 /* tnz */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_9, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4032 /* tnz */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_9, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_9, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4032 /* tnz */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4032 /* tnz */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_9, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_9, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4032 /* tnz */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_9, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_9, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4032 /* tnz */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_9, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4032 /* tnz */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_9, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_9, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4032 /* tnz */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4032 /* tnz */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_9, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4036 /* tpos */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_14, AMFBS_None, { MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_14, AMFBS_None, { MCK_Imm }, },
  { 4036 /* tpos */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_14, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4036 /* tpos */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_14, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4036 /* tpos */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_14, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_14, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4036 /* tpos */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4036 /* tpos */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_14, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_14, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4036 /* tpos */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_14, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_14, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4036 /* tpos */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_14, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4036 /* tpos */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_14, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_14, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4036 /* tpos */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4036 /* tpos */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_14, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4041 /* tst */, SP::ORCCrr, Convert__regG0__Reg1_0__regG0, AMFBS_None, { MCK_IntRegs }, },
  { 4045 /* tsubcc */, SP::TSUBCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4045 /* tsubcc */, SP::TSUBCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4052 /* tsubcctv */, SP::TSUBCCTVrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4052 /* tsubcctv */, SP::TSUBCCTVri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_15, AMFBS_None, { MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_15, AMFBS_None, { MCK_Imm }, },
  { 4061 /* tvc */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_15, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4061 /* tvc */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_15, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4061 /* tvc */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_15, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_15, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4061 /* tvc */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4061 /* tvc */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_15, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_15, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4061 /* tvc */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_15, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_15, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4061 /* tvc */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_15, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4061 /* tvc */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_15, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_15, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4061 /* tvc */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4061 /* tvc */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_15, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4065 /* tvs */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_7, AMFBS_None, { MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_7, AMFBS_None, { MCK_Imm }, },
  { 4065 /* tvs */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_7, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4065 /* tvs */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_7, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4065 /* tvs */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_7, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_7, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4065 /* tvs */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4065 /* tvs */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_7, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_7, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4065 /* tvs */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_7, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_7, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4065 /* tvs */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_7, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4065 /* tvs */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_7, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_7, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4065 /* tvs */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4065 /* tvs */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_7, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4069 /* tz */, SP::TRAPrr, Convert__regG0__Reg1_0__imm_95_1, AMFBS_None, { MCK_IntRegs }, },
  { 4069 /* tz */, SP::TRAPri, Convert__regG0__Imm1_0__imm_95_1, AMFBS_None, { MCK_Imm }, },
  { 4069 /* tz */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4069 /* tz */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs }, },
  { 4069 /* tz */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4069 /* tz */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_Imm }, },
  { 4069 /* tz */, SP::TXCCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs }, },
  { 4069 /* tz */, SP::TXCCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_Imm }, },
  { 4069 /* tz */, SP::TICCrr, Convert__regG0__Reg1_1__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs }, },
  { 4069 /* tz */, SP::TICCri, Convert__regG0__Imm1_1__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_Imm }, },
  { 4069 /* tz */, SP::TRAPrr, Convert__Reg1_0__Reg1_2__imm_95_1, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4069 /* tz */, SP::TRAPri, Convert__Reg1_0__Imm1_2__imm_95_1, AMFBS_None, { MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4069 /* tz */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4069 /* tz */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4069 /* tz */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9_Is32Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4069 /* tz */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9_Is64Bit, { MCK__PCT_ncc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4069 /* tz */, SP::TXCCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4069 /* tz */, SP::TXCCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK__PCT_xcc, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4069 /* tz */, SP::TICCrr, Convert__Reg1_1__Reg1_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_IntRegs }, },
  { 4069 /* tz */, SP::TICCri, Convert__Reg1_1__Imm1_3__imm_95_1, AMFBS_HasV9, { MCK_ICC, MCK_IntRegs, MCK__43_, MCK_Imm }, },
  { 4072 /* udiv */, SP::UDIVrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4072 /* udiv */, SP::UDIVri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4077 /* udivcc */, SP::UDIVCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4077 /* udivcc */, SP::UDIVCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4084 /* udivx */, SP::UDIVXrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4084 /* udivx */, SP::UDIVXri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4090 /* umac */, SP::UMACrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4090 /* umac */, SP::UMACri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4095 /* umul */, SP::UMULrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4095 /* umul */, SP::UMULri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4100 /* umulcc */, SP::UMULCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4100 /* umulcc */, SP::UMULCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4107 /* umulxhi */, SP::UMULXHI, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4115 /* unimp */, SP::UNIMP, Convert__imm_95_0, AMFBS_None, {  }, },
  { 4115 /* unimp */, SP::UNIMP, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 4121 /* wr */, SP::WRPSRrr, Convert__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_PSR }, },
  { 4121 /* wr */, SP::WRTBRrr, Convert__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_TBR }, },
  { 4121 /* wr */, SP::WRWIMrr, Convert__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_WIM }, },
  { 4121 /* wr */, SP::WRASRrr, Convert__Reg1_1__regG0__Reg1_0, AMFBS_None, { MCK_IntRegs, MCK_ASRRegs }, },
  { 4121 /* wr */, SP::WRPSRri, Convert__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_PSR }, },
  { 4121 /* wr */, SP::WRTBRri, Convert__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_TBR }, },
  { 4121 /* wr */, SP::WRWIMri, Convert__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_WIM }, },
  { 4121 /* wr */, SP::WRASRri, Convert__Reg1_1__regG0__Imm1_0, AMFBS_None, { MCK_Imm, MCK_ASRRegs }, },
  { 4121 /* wr */, SP::WRPSRrr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_PSR }, },
  { 4121 /* wr */, SP::WRTBRrr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_TBR }, },
  { 4121 /* wr */, SP::WRWIMrr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_WIM }, },
  { 4121 /* wr */, SP::WRASRrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_ASRRegs }, },
  { 4121 /* wr */, SP::WRPSRri, Convert__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_PSR }, },
  { 4121 /* wr */, SP::WRTBRri, Convert__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_TBR }, },
  { 4121 /* wr */, SP::WRWIMri, Convert__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_WIM }, },
  { 4121 /* wr */, SP::WRASRri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_ASRRegs }, },
  { 4124 /* wrpr */, SP::WRPRrr, Convert__Reg1_1__Reg1_0__regG0, AMFBS_HasV9, { MCK_IntRegs, MCK_PRRegs }, },
  { 4124 /* wrpr */, SP::WRPRri, Convert__Reg1_1__regG0__Imm1_0, AMFBS_HasV9, { MCK_Imm, MCK_PRRegs }, },
  { 4124 /* wrpr */, SP::WRPRrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_IntRegs, MCK_PRRegs }, },
  { 4124 /* wrpr */, SP::WRPRri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_HasV9, { MCK_IntRegs, MCK_Imm, MCK_PRRegs }, },
  { 4129 /* xmulx */, SP::XMULX, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4135 /* xmulxhi */, SP::XMULXHI, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_HasVIS3, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4143 /* xnor */, SP::XNORrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4143 /* xnor */, SP::XNORri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4148 /* xnorcc */, SP::XNORCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4148 /* xnorcc */, SP::XNORCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4155 /* xor */, SP::XORrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4155 /* xor */, SP::XORri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
  { 4159 /* xorcc */, SP::XORCCrr, Convert__Reg1_2__Reg1_0__Reg1_1, AMFBS_None, { MCK_IntRegs, MCK_IntRegs, MCK_IntRegs }, },
  { 4159 /* xorcc */, SP::XORCCri, Convert__Reg1_2__Reg1_0__Imm1_1, AMFBS_None, { MCK_IntRegs, MCK_Imm, MCK_IntRegs }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned SparcAsmParser::
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
  StringRef Mnemonic = ((SparcOperand &)*Operands[0]).getToken();

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

static const OperandMatchEntry OperandMatchTable[180] = {
  /* Operand List Mnemonic, Mask, Operand Class, Features */
  { 0 /* add */, 8 /* 3 */, MCK_TailRelocSymAdd_TLS, AMFBS_None },
  { 432 /* call */, 1 /* 0 */, MCK_CallTarget, AMFBS_None },
  { 432 /* call */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 432 /* call */, 1 /* 0 */, MCK_MEMrr, AMFBS_None },
  { 432 /* call */, 1 /* 0 */, MCK_CallTarget, AMFBS_None },
  { 432 /* call */, 1 /* 0 */, MCK_CallTarget, AMFBS_None },
  { 432 /* call */, 2 /* 1 */, MCK_TailRelocSymCall_TLS, AMFBS_None },
  { 432 /* call */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 432 /* call */, 1 /* 0 */, MCK_MEMrr, AMFBS_None },
  { 477 /* casa */, 8 /* 3 */, MCK_ASITag, AMFBS_HasCASA },
  { 492 /* casxa */, 8 /* 3 */, MCK_ASITag, AMFBS_HasV9 },
  { 585 /* clr */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 585 /* clr */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 589 /* clrb */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 589 /* clrb */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 594 /* clrh */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 594 /* clrh */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 599 /* clrx */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 599 /* clrx */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 1404 /* flush */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 1404 /* flush */, 1 /* 0 */, MCK_MEMrr, AMFBS_None },
  { 3124 /* jmp */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 3124 /* jmp */, 1 /* 0 */, MCK_MEMrr, AMFBS_None },
  { 3128 /* jmpl */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 3128 /* jmpl */, 1 /* 0 */, MCK_MEMrr, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3133 /* ld */, 16 /* 4 */, MCK_TailRelocSymLoad_GOT, AMFBS_None },
  { 3133 /* ld */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3133 /* ld */, 16 /* 4 */, MCK_TailRelocSymLoad_TLS, AMFBS_None },
  { 3136 /* lda */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3136 /* lda */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3136 /* lda */, 8 /* 3 */, MCK_ASITag, AMFBS_HasV9 },
  { 3136 /* lda */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3136 /* lda */, 8 /* 3 */, MCK_ASITag, AMFBS_None },
  { 3136 /* lda */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3140 /* ldd */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3140 /* ldd */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3140 /* ldd */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3140 /* ldd */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3140 /* ldd */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3140 /* ldd */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3144 /* ldda */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3144 /* ldda */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3144 /* ldda */, 8 /* 3 */, MCK_ASITag, AMFBS_None },
  { 3144 /* ldda */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3144 /* ldda */, 8 /* 3 */, MCK_ASITag, AMFBS_HasV9 },
  { 3144 /* ldda */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3149 /* ldq */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3149 /* ldq */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3153 /* ldqa */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3153 /* ldqa */, 8 /* 3 */, MCK_ASITag, AMFBS_HasV9 },
  { 3153 /* ldqa */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3158 /* ldsb */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3158 /* ldsb */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3163 /* ldsba */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3163 /* ldsba */, 8 /* 3 */, MCK_ASITag, AMFBS_None },
  { 3163 /* ldsba */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3169 /* ldsh */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3169 /* ldsh */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3174 /* ldsha */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3174 /* ldsha */, 8 /* 3 */, MCK_ASITag, AMFBS_None },
  { 3174 /* ldsha */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3180 /* ldstub */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3180 /* ldstub */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3187 /* ldstuba */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3187 /* ldstuba */, 8 /* 3 */, MCK_ASITag, AMFBS_None },
  { 3187 /* ldstuba */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3195 /* ldsw */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3195 /* ldsw */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3200 /* ldswa */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3200 /* ldswa */, 8 /* 3 */, MCK_ASITag, AMFBS_HasV9 },
  { 3200 /* ldswa */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3206 /* ldub */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3206 /* ldub */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3211 /* lduba */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3211 /* lduba */, 8 /* 3 */, MCK_ASITag, AMFBS_None },
  { 3211 /* lduba */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3217 /* lduh */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3217 /* lduh */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3222 /* lduha */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3222 /* lduha */, 8 /* 3 */, MCK_ASITag, AMFBS_None },
  { 3222 /* lduha */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3228 /* ldx */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3228 /* ldx */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3228 /* ldx */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3228 /* ldx */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3228 /* ldx */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3228 /* ldx */, 16 /* 4 */, MCK_TailRelocSymLoad_GOT, AMFBS_HasV9 },
  { 3228 /* ldx */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3228 /* ldx */, 16 /* 4 */, MCK_TailRelocSymLoad_TLS, AMFBS_HasV9 },
  { 3232 /* ldxa */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3232 /* ldxa */, 8 /* 3 */, MCK_ASITag, AMFBS_HasV9 },
  { 3232 /* ldxa */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3247 /* membar */, 1 /* 0 */, MCK_MembarTag, AMFBS_HasV9 },
  { 3648 /* prefetch */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3648 /* prefetch */, 8 /* 3 */, MCK_PrefetchTag, AMFBS_HasV9 },
  { 3648 /* prefetch */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3648 /* prefetch */, 8 /* 3 */, MCK_PrefetchTag, AMFBS_HasV9 },
  { 3657 /* prefetcha */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3657 /* prefetcha */, 16 /* 4 */, MCK_PrefetchTag, AMFBS_HasV9 },
  { 3657 /* prefetcha */, 8 /* 3 */, MCK_ASITag, AMFBS_HasV9 },
  { 3657 /* prefetcha */, 2 /* 1 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3657 /* prefetcha */, 16 /* 4 */, MCK_PrefetchTag, AMFBS_HasV9 },
  { 3711 /* rett */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 3711 /* rett */, 1 /* 0 */, MCK_MEMrr, AMFBS_None },
  { 3809 /* sll */, 2 /* 1 */, MCK_ShiftAmtImm5, AMFBS_None },
  { 3813 /* sllx */, 2 /* 1 */, MCK_ShiftAmtImm6, AMFBS_HasV9 },
  { 3835 /* sra */, 2 /* 1 */, MCK_ShiftAmtImm5, AMFBS_None },
  { 3839 /* srax */, 2 /* 1 */, MCK_ShiftAmtImm6, AMFBS_HasV9 },
  { 3844 /* srl */, 2 /* 1 */, MCK_ShiftAmtImm5, AMFBS_None },
  { 3848 /* srlx */, 2 /* 1 */, MCK_ShiftAmtImm6, AMFBS_HasV9 },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3853 /* st */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3856 /* sta */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3856 /* sta */, 16 /* 4 */, MCK_ASITag, AMFBS_HasV9 },
  { 3856 /* sta */, 4 /* 2 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3856 /* sta */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3856 /* sta */, 16 /* 4 */, MCK_ASITag, AMFBS_None },
  { 3856 /* sta */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3860 /* stb */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3860 /* stb */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3864 /* stba */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3864 /* stba */, 16 /* 4 */, MCK_ASITag, AMFBS_None },
  { 3864 /* stba */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3875 /* std */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3879 /* stda */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3879 /* stda */, 16 /* 4 */, MCK_ASITag, AMFBS_None },
  { 3879 /* stda */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3879 /* stda */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3879 /* stda */, 16 /* 4 */, MCK_ASITag, AMFBS_HasV9 },
  { 3879 /* stda */, 4 /* 2 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3884 /* sth */, 4 /* 2 */, MCK_MEMri, AMFBS_None },
  { 3884 /* sth */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3888 /* stha */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3888 /* stha */, 16 /* 4 */, MCK_ASITag, AMFBS_None },
  { 3888 /* stha */, 4 /* 2 */, MCK_MEMrr, AMFBS_None },
  { 3893 /* stq */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3893 /* stq */, 4 /* 2 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3897 /* stqa */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3897 /* stqa */, 16 /* 4 */, MCK_ASITag, AMFBS_HasV9 },
  { 3897 /* stqa */, 4 /* 2 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3902 /* stx */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3902 /* stx */, 4 /* 2 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3902 /* stx */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3902 /* stx */, 4 /* 2 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3906 /* stxa */, 4 /* 2 */, MCK_MEMri, AMFBS_HasV9 },
  { 3906 /* stxa */, 16 /* 4 */, MCK_ASITag, AMFBS_HasV9 },
  { 3906 /* stxa */, 4 /* 2 */, MCK_MEMrr, AMFBS_HasV9 },
  { 3933 /* swap */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 3933 /* swap */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
  { 3938 /* swapa */, 2 /* 1 */, MCK_MEMri, AMFBS_HasV9 },
  { 3938 /* swapa */, 8 /* 3 */, MCK_ASITag, AMFBS_None },
  { 3938 /* swapa */, 2 /* 1 */, MCK_MEMrr, AMFBS_None },
};

ParseStatus SparcAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_ASITag:
    return parseASITag(Operands);
  case MCK_CallTarget:
    return parseCallTarget(Operands);
  case MCK_MEMri:
    return parseMEMOperand(Operands);
  case MCK_MEMrr:
    return parseMEMOperand(Operands);
  case MCK_MembarTag:
    return parseMembarTag(Operands);
  case MCK_PrefetchTag:
    return parsePrefetchTag(Operands);
  case MCK_ShiftAmtImm5:
    return parseShiftAmtImm<5>(Operands);
  case MCK_ShiftAmtImm6:
    return parseShiftAmtImm<6>(Operands);
  case MCK_TailRelocSymLoad_GOT:
    return parseTailRelocSym<TailRelocKind::Load_GOT>(Operands);
  case MCK_TailRelocSymAdd_TLS:
    return parseTailRelocSym<TailRelocKind::Add_TLS>(Operands);
  case MCK_TailRelocSymLoad_TLS:
    return parseTailRelocSym<TailRelocKind::Load_TLS>(Operands);
  case MCK_TailRelocSymCall_TLS:
    return parseTailRelocSym<TailRelocKind::Call_TLS>(Operands);
  default:
    return ParseStatus::NoMatch;
  }
  return ParseStatus::NoMatch;
}

ParseStatus SparcAsmParser::
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

static std::string SparcMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool SparcCheckMnemonic(StringRef Mnemonic,
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

