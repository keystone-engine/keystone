/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: VE.td                                                                *|
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
  case 2:	 // 32 strings to match.
    switch (Name[0]) {
    default: break;
    case 'i':	 // 1 string to match.
      if (Name[1] != 'c')
        break;
      return VE::IC;	 // "ic"
    case 'q':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return VE::Q0;	 // "q0"
      case '1':	 // 1 string to match.
        return VE::Q1;	 // "q1"
      case '2':	 // 1 string to match.
        return VE::Q2;	 // "q2"
      case '3':	 // 1 string to match.
        return VE::Q3;	 // "q3"
      case '4':	 // 1 string to match.
        return VE::Q4;	 // "q4"
      case '5':	 // 1 string to match.
        return VE::Q5;	 // "q5"
      case '6':	 // 1 string to match.
        return VE::Q6;	 // "q6"
      case '7':	 // 1 string to match.
        return VE::Q7;	 // "q7"
      case '8':	 // 1 string to match.
        return VE::Q8;	 // "q8"
      case '9':	 // 1 string to match.
        return VE::Q9;	 // "q9"
      }
      break;
    case 's':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return VE::SX0;	 // "s0"
      case '1':	 // 1 string to match.
        return VE::SX1;	 // "s1"
      case '2':	 // 1 string to match.
        return VE::SX2;	 // "s2"
      case '3':	 // 1 string to match.
        return VE::SX3;	 // "s3"
      case '4':	 // 1 string to match.
        return VE::SX4;	 // "s4"
      case '5':	 // 1 string to match.
        return VE::SX5;	 // "s5"
      case '6':	 // 1 string to match.
        return VE::SX6;	 // "s6"
      case '7':	 // 1 string to match.
        return VE::SX7;	 // "s7"
      case '8':	 // 1 string to match.
        return VE::SX8;	 // "s8"
      case '9':	 // 1 string to match.
        return VE::SX9;	 // "s9"
      }
      break;
    case 'v':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return VE::V0;	 // "v0"
      case '1':	 // 1 string to match.
        return VE::V1;	 // "v1"
      case '2':	 // 1 string to match.
        return VE::V2;	 // "v2"
      case '3':	 // 1 string to match.
        return VE::V3;	 // "v3"
      case '4':	 // 1 string to match.
        return VE::V4;	 // "v4"
      case '5':	 // 1 string to match.
        return VE::V5;	 // "v5"
      case '6':	 // 1 string to match.
        return VE::V6;	 // "v6"
      case '7':	 // 1 string to match.
        return VE::V7;	 // "v7"
      case '8':	 // 1 string to match.
        return VE::V8;	 // "v8"
      case '9':	 // 1 string to match.
        return VE::V9;	 // "v9"
      case 'l':	 // 1 string to match.
        return VE::VL;	 // "vl"
      }
      break;
    }
    break;
  case 3:	 // 164 strings to match.
    switch (Name[0]) {
    default: break;
    case 'p':	 // 1 string to match.
      if (memcmp(Name.data()+1, "sw", 2) != 0)
        break;
      return VE::PSW;	 // "psw"
    case 'q':	 // 22 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::Q10;	 // "q10"
        case '1':	 // 1 string to match.
          return VE::Q11;	 // "q11"
        case '2':	 // 1 string to match.
          return VE::Q12;	 // "q12"
        case '3':	 // 1 string to match.
          return VE::Q13;	 // "q13"
        case '4':	 // 1 string to match.
          return VE::Q14;	 // "q14"
        case '5':	 // 1 string to match.
          return VE::Q15;	 // "q15"
        case '6':	 // 1 string to match.
          return VE::Q16;	 // "q16"
        case '7':	 // 1 string to match.
          return VE::Q17;	 // "q17"
        case '8':	 // 1 string to match.
          return VE::Q18;	 // "q18"
        case '9':	 // 1 string to match.
          return VE::Q19;	 // "q19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::Q20;	 // "q20"
        case '1':	 // 1 string to match.
          return VE::Q21;	 // "q21"
        case '2':	 // 1 string to match.
          return VE::Q22;	 // "q22"
        case '3':	 // 1 string to match.
          return VE::Q23;	 // "q23"
        case '4':	 // 1 string to match.
          return VE::Q24;	 // "q24"
        case '5':	 // 1 string to match.
          return VE::Q25;	 // "q25"
        case '6':	 // 1 string to match.
          return VE::Q26;	 // "q26"
        case '7':	 // 1 string to match.
          return VE::Q27;	 // "q27"
        case '8':	 // 1 string to match.
          return VE::Q28;	 // "q28"
        case '9':	 // 1 string to match.
          return VE::Q29;	 // "q29"
        }
        break;
      case '3':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::Q30;	 // "q30"
        case '1':	 // 1 string to match.
          return VE::Q31;	 // "q31"
        }
        break;
      }
      break;
    case 's':	 // 75 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::SX10;	 // "s10"
        case '1':	 // 1 string to match.
          return VE::SX11;	 // "s11"
        case '2':	 // 1 string to match.
          return VE::SX12;	 // "s12"
        case '3':	 // 1 string to match.
          return VE::SX13;	 // "s13"
        case '4':	 // 1 string to match.
          return VE::SX14;	 // "s14"
        case '5':	 // 1 string to match.
          return VE::SX15;	 // "s15"
        case '6':	 // 1 string to match.
          return VE::SX16;	 // "s16"
        case '7':	 // 1 string to match.
          return VE::SX17;	 // "s17"
        case '8':	 // 1 string to match.
          return VE::SX18;	 // "s18"
        case '9':	 // 1 string to match.
          return VE::SX19;	 // "s19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::SX20;	 // "s20"
        case '1':	 // 1 string to match.
          return VE::SX21;	 // "s21"
        case '2':	 // 1 string to match.
          return VE::SX22;	 // "s22"
        case '3':	 // 1 string to match.
          return VE::SX23;	 // "s23"
        case '4':	 // 1 string to match.
          return VE::SX24;	 // "s24"
        case '5':	 // 1 string to match.
          return VE::SX25;	 // "s25"
        case '6':	 // 1 string to match.
          return VE::SX26;	 // "s26"
        case '7':	 // 1 string to match.
          return VE::SX27;	 // "s27"
        case '8':	 // 1 string to match.
          return VE::SX28;	 // "s28"
        case '9':	 // 1 string to match.
          return VE::SX29;	 // "s29"
        }
        break;
      case '3':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::SX30;	 // "s30"
        case '1':	 // 1 string to match.
          return VE::SX31;	 // "s31"
        case '2':	 // 1 string to match.
          return VE::SX32;	 // "s32"
        case '3':	 // 1 string to match.
          return VE::SX33;	 // "s33"
        case '4':	 // 1 string to match.
          return VE::SX34;	 // "s34"
        case '5':	 // 1 string to match.
          return VE::SX35;	 // "s35"
        case '6':	 // 1 string to match.
          return VE::SX36;	 // "s36"
        case '7':	 // 1 string to match.
          return VE::SX37;	 // "s37"
        case '8':	 // 1 string to match.
          return VE::SX38;	 // "s38"
        case '9':	 // 1 string to match.
          return VE::SX39;	 // "s39"
        }
        break;
      case '4':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::SX40;	 // "s40"
        case '1':	 // 1 string to match.
          return VE::SX41;	 // "s41"
        case '2':	 // 1 string to match.
          return VE::SX42;	 // "s42"
        case '3':	 // 1 string to match.
          return VE::SX43;	 // "s43"
        case '4':	 // 1 string to match.
          return VE::SX44;	 // "s44"
        case '5':	 // 1 string to match.
          return VE::SX45;	 // "s45"
        case '6':	 // 1 string to match.
          return VE::SX46;	 // "s46"
        case '7':	 // 1 string to match.
          return VE::SX47;	 // "s47"
        case '8':	 // 1 string to match.
          return VE::SX48;	 // "s48"
        case '9':	 // 1 string to match.
          return VE::SX49;	 // "s49"
        }
        break;
      case '5':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::SX50;	 // "s50"
        case '1':	 // 1 string to match.
          return VE::SX51;	 // "s51"
        case '2':	 // 1 string to match.
          return VE::SX52;	 // "s52"
        case '3':	 // 1 string to match.
          return VE::SX53;	 // "s53"
        case '4':	 // 1 string to match.
          return VE::SX54;	 // "s54"
        case '5':	 // 1 string to match.
          return VE::SX55;	 // "s55"
        case '6':	 // 1 string to match.
          return VE::SX56;	 // "s56"
        case '7':	 // 1 string to match.
          return VE::SX57;	 // "s57"
        case '8':	 // 1 string to match.
          return VE::SX58;	 // "s58"
        case '9':	 // 1 string to match.
          return VE::SX59;	 // "s59"
        }
        break;
      case '6':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::SX60;	 // "s60"
        case '1':	 // 1 string to match.
          return VE::SX61;	 // "s61"
        case '2':	 // 1 string to match.
          return VE::SX62;	 // "s62"
        case '3':	 // 1 string to match.
          return VE::SX63;	 // "s63"
        }
        break;
      case 'a':	 // 1 string to match.
        if (Name[2] != 'r')
          break;
        return VE::SAR;	 // "sar"
      case 'f':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::SF0;	 // "sf0"
        case '1':	 // 1 string to match.
          return VE::SF1;	 // "sf1"
        case '2':	 // 1 string to match.
          return VE::SF2;	 // "sf2"
        case '3':	 // 1 string to match.
          return VE::SF3;	 // "sf3"
        case '4':	 // 1 string to match.
          return VE::SF4;	 // "sf4"
        case '5':	 // 1 string to match.
          return VE::SF5;	 // "sf5"
        case '6':	 // 1 string to match.
          return VE::SF6;	 // "sf6"
        case '7':	 // 1 string to match.
          return VE::SF7;	 // "sf7"
        case '8':	 // 1 string to match.
          return VE::SF8;	 // "sf8"
        case '9':	 // 1 string to match.
          return VE::SF9;	 // "sf9"
        }
        break;
      case 'w':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::SW0;	 // "sw0"
        case '1':	 // 1 string to match.
          return VE::SW1;	 // "sw1"
        case '2':	 // 1 string to match.
          return VE::SW2;	 // "sw2"
        case '3':	 // 1 string to match.
          return VE::SW3;	 // "sw3"
        case '4':	 // 1 string to match.
          return VE::SW4;	 // "sw4"
        case '5':	 // 1 string to match.
          return VE::SW5;	 // "sw5"
        case '6':	 // 1 string to match.
          return VE::SW6;	 // "sw6"
        case '7':	 // 1 string to match.
          return VE::SW7;	 // "sw7"
        case '8':	 // 1 string to match.
          return VE::SW8;	 // "sw8"
        case '9':	 // 1 string to match.
          return VE::SW9;	 // "sw9"
        }
        break;
      }
      break;
    case 'v':	 // 66 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V10;	 // "v10"
        case '1':	 // 1 string to match.
          return VE::V11;	 // "v11"
        case '2':	 // 1 string to match.
          return VE::V12;	 // "v12"
        case '3':	 // 1 string to match.
          return VE::V13;	 // "v13"
        case '4':	 // 1 string to match.
          return VE::V14;	 // "v14"
        case '5':	 // 1 string to match.
          return VE::V15;	 // "v15"
        case '6':	 // 1 string to match.
          return VE::V16;	 // "v16"
        case '7':	 // 1 string to match.
          return VE::V17;	 // "v17"
        case '8':	 // 1 string to match.
          return VE::V18;	 // "v18"
        case '9':	 // 1 string to match.
          return VE::V19;	 // "v19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V20;	 // "v20"
        case '1':	 // 1 string to match.
          return VE::V21;	 // "v21"
        case '2':	 // 1 string to match.
          return VE::V22;	 // "v22"
        case '3':	 // 1 string to match.
          return VE::V23;	 // "v23"
        case '4':	 // 1 string to match.
          return VE::V24;	 // "v24"
        case '5':	 // 1 string to match.
          return VE::V25;	 // "v25"
        case '6':	 // 1 string to match.
          return VE::V26;	 // "v26"
        case '7':	 // 1 string to match.
          return VE::V27;	 // "v27"
        case '8':	 // 1 string to match.
          return VE::V28;	 // "v28"
        case '9':	 // 1 string to match.
          return VE::V29;	 // "v29"
        }
        break;
      case '3':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V30;	 // "v30"
        case '1':	 // 1 string to match.
          return VE::V31;	 // "v31"
        case '2':	 // 1 string to match.
          return VE::V32;	 // "v32"
        case '3':	 // 1 string to match.
          return VE::V33;	 // "v33"
        case '4':	 // 1 string to match.
          return VE::V34;	 // "v34"
        case '5':	 // 1 string to match.
          return VE::V35;	 // "v35"
        case '6':	 // 1 string to match.
          return VE::V36;	 // "v36"
        case '7':	 // 1 string to match.
          return VE::V37;	 // "v37"
        case '8':	 // 1 string to match.
          return VE::V38;	 // "v38"
        case '9':	 // 1 string to match.
          return VE::V39;	 // "v39"
        }
        break;
      case '4':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V40;	 // "v40"
        case '1':	 // 1 string to match.
          return VE::V41;	 // "v41"
        case '2':	 // 1 string to match.
          return VE::V42;	 // "v42"
        case '3':	 // 1 string to match.
          return VE::V43;	 // "v43"
        case '4':	 // 1 string to match.
          return VE::V44;	 // "v44"
        case '5':	 // 1 string to match.
          return VE::V45;	 // "v45"
        case '6':	 // 1 string to match.
          return VE::V46;	 // "v46"
        case '7':	 // 1 string to match.
          return VE::V47;	 // "v47"
        case '8':	 // 1 string to match.
          return VE::V48;	 // "v48"
        case '9':	 // 1 string to match.
          return VE::V49;	 // "v49"
        }
        break;
      case '5':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V50;	 // "v50"
        case '1':	 // 1 string to match.
          return VE::V51;	 // "v51"
        case '2':	 // 1 string to match.
          return VE::V52;	 // "v52"
        case '3':	 // 1 string to match.
          return VE::V53;	 // "v53"
        case '4':	 // 1 string to match.
          return VE::V54;	 // "v54"
        case '5':	 // 1 string to match.
          return VE::V55;	 // "v55"
        case '6':	 // 1 string to match.
          return VE::V56;	 // "v56"
        case '7':	 // 1 string to match.
          return VE::V57;	 // "v57"
        case '8':	 // 1 string to match.
          return VE::V58;	 // "v58"
        case '9':	 // 1 string to match.
          return VE::V59;	 // "v59"
        }
        break;
      case '6':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V60;	 // "v60"
        case '1':	 // 1 string to match.
          return VE::V61;	 // "v61"
        case '2':	 // 1 string to match.
          return VE::V62;	 // "v62"
        case '3':	 // 1 string to match.
          return VE::V63;	 // "v63"
        }
        break;
      case 'i':	 // 1 string to match.
        if (Name[2] != 'x')
          break;
        return VE::VIX;	 // "vix"
      case 'm':	 // 11 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return VE::VM0;	 // "vm0"
        case '1':	 // 1 string to match.
          return VE::VM1;	 // "vm1"
        case '2':	 // 1 string to match.
          return VE::VM2;	 // "vm2"
        case '3':	 // 1 string to match.
          return VE::VM3;	 // "vm3"
        case '4':	 // 1 string to match.
          return VE::VM4;	 // "vm4"
        case '5':	 // 1 string to match.
          return VE::VM5;	 // "vm5"
        case '6':	 // 1 string to match.
          return VE::VM6;	 // "vm6"
        case '7':	 // 1 string to match.
          return VE::VM7;	 // "vm7"
        case '8':	 // 1 string to match.
          return VE::VM8;	 // "vm8"
        case '9':	 // 1 string to match.
          return VE::VM9;	 // "vm9"
        }
        break;
      }
      break;
    }
    break;
  case 4:	 // 132 strings to match.
    switch (Name[0]) {
    default: break;
    case 'p':	 // 11 strings to match.
      if (Name[1] != 'm')
        break;
      switch (Name[2]) {
      default: break;
      case 'c':	 // 10 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::PMC0;	 // "pmc0"
        case '1':	 // 1 string to match.
          return VE::PMC1;	 // "pmc1"
        case '2':	 // 1 string to match.
          return VE::PMC2;	 // "pmc2"
        case '3':	 // 1 string to match.
          return VE::PMC3;	 // "pmc3"
        case '4':	 // 1 string to match.
          return VE::PMC4;	 // "pmc4"
        case '5':	 // 1 string to match.
          return VE::PMC5;	 // "pmc5"
        case '6':	 // 1 string to match.
          return VE::PMC6;	 // "pmc6"
        case '7':	 // 1 string to match.
          return VE::PMC7;	 // "pmc7"
        case '8':	 // 1 string to match.
          return VE::PMC8;	 // "pmc8"
        case '9':	 // 1 string to match.
          return VE::PMC9;	 // "pmc9"
        }
        break;
      case 'm':	 // 1 string to match.
        if (Name[3] != 'r')
          break;
        return VE::PMMR;	 // "pmmr"
      }
      break;
    case 's':	 // 108 strings to match.
      switch (Name[1]) {
      default: break;
      case 'f':	 // 54 strings to match.
        switch (Name[2]) {
        default: break;
        case '1':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SF10;	 // "sf10"
          case '1':	 // 1 string to match.
            return VE::SF11;	 // "sf11"
          case '2':	 // 1 string to match.
            return VE::SF12;	 // "sf12"
          case '3':	 // 1 string to match.
            return VE::SF13;	 // "sf13"
          case '4':	 // 1 string to match.
            return VE::SF14;	 // "sf14"
          case '5':	 // 1 string to match.
            return VE::SF15;	 // "sf15"
          case '6':	 // 1 string to match.
            return VE::SF16;	 // "sf16"
          case '7':	 // 1 string to match.
            return VE::SF17;	 // "sf17"
          case '8':	 // 1 string to match.
            return VE::SF18;	 // "sf18"
          case '9':	 // 1 string to match.
            return VE::SF19;	 // "sf19"
          }
          break;
        case '2':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SF20;	 // "sf20"
          case '1':	 // 1 string to match.
            return VE::SF21;	 // "sf21"
          case '2':	 // 1 string to match.
            return VE::SF22;	 // "sf22"
          case '3':	 // 1 string to match.
            return VE::SF23;	 // "sf23"
          case '4':	 // 1 string to match.
            return VE::SF24;	 // "sf24"
          case '5':	 // 1 string to match.
            return VE::SF25;	 // "sf25"
          case '6':	 // 1 string to match.
            return VE::SF26;	 // "sf26"
          case '7':	 // 1 string to match.
            return VE::SF27;	 // "sf27"
          case '8':	 // 1 string to match.
            return VE::SF28;	 // "sf28"
          case '9':	 // 1 string to match.
            return VE::SF29;	 // "sf29"
          }
          break;
        case '3':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SF30;	 // "sf30"
          case '1':	 // 1 string to match.
            return VE::SF31;	 // "sf31"
          case '2':	 // 1 string to match.
            return VE::SF32;	 // "sf32"
          case '3':	 // 1 string to match.
            return VE::SF33;	 // "sf33"
          case '4':	 // 1 string to match.
            return VE::SF34;	 // "sf34"
          case '5':	 // 1 string to match.
            return VE::SF35;	 // "sf35"
          case '6':	 // 1 string to match.
            return VE::SF36;	 // "sf36"
          case '7':	 // 1 string to match.
            return VE::SF37;	 // "sf37"
          case '8':	 // 1 string to match.
            return VE::SF38;	 // "sf38"
          case '9':	 // 1 string to match.
            return VE::SF39;	 // "sf39"
          }
          break;
        case '4':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SF40;	 // "sf40"
          case '1':	 // 1 string to match.
            return VE::SF41;	 // "sf41"
          case '2':	 // 1 string to match.
            return VE::SF42;	 // "sf42"
          case '3':	 // 1 string to match.
            return VE::SF43;	 // "sf43"
          case '4':	 // 1 string to match.
            return VE::SF44;	 // "sf44"
          case '5':	 // 1 string to match.
            return VE::SF45;	 // "sf45"
          case '6':	 // 1 string to match.
            return VE::SF46;	 // "sf46"
          case '7':	 // 1 string to match.
            return VE::SF47;	 // "sf47"
          case '8':	 // 1 string to match.
            return VE::SF48;	 // "sf48"
          case '9':	 // 1 string to match.
            return VE::SF49;	 // "sf49"
          }
          break;
        case '5':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SF50;	 // "sf50"
          case '1':	 // 1 string to match.
            return VE::SF51;	 // "sf51"
          case '2':	 // 1 string to match.
            return VE::SF52;	 // "sf52"
          case '3':	 // 1 string to match.
            return VE::SF53;	 // "sf53"
          case '4':	 // 1 string to match.
            return VE::SF54;	 // "sf54"
          case '5':	 // 1 string to match.
            return VE::SF55;	 // "sf55"
          case '6':	 // 1 string to match.
            return VE::SF56;	 // "sf56"
          case '7':	 // 1 string to match.
            return VE::SF57;	 // "sf57"
          case '8':	 // 1 string to match.
            return VE::SF58;	 // "sf58"
          case '9':	 // 1 string to match.
            return VE::SF59;	 // "sf59"
          }
          break;
        case '6':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SF60;	 // "sf60"
          case '1':	 // 1 string to match.
            return VE::SF61;	 // "sf61"
          case '2':	 // 1 string to match.
            return VE::SF62;	 // "sf62"
          case '3':	 // 1 string to match.
            return VE::SF63;	 // "sf63"
          }
          break;
        }
        break;
      case 'w':	 // 54 strings to match.
        switch (Name[2]) {
        default: break;
        case '1':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SW10;	 // "sw10"
          case '1':	 // 1 string to match.
            return VE::SW11;	 // "sw11"
          case '2':	 // 1 string to match.
            return VE::SW12;	 // "sw12"
          case '3':	 // 1 string to match.
            return VE::SW13;	 // "sw13"
          case '4':	 // 1 string to match.
            return VE::SW14;	 // "sw14"
          case '5':	 // 1 string to match.
            return VE::SW15;	 // "sw15"
          case '6':	 // 1 string to match.
            return VE::SW16;	 // "sw16"
          case '7':	 // 1 string to match.
            return VE::SW17;	 // "sw17"
          case '8':	 // 1 string to match.
            return VE::SW18;	 // "sw18"
          case '9':	 // 1 string to match.
            return VE::SW19;	 // "sw19"
          }
          break;
        case '2':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SW20;	 // "sw20"
          case '1':	 // 1 string to match.
            return VE::SW21;	 // "sw21"
          case '2':	 // 1 string to match.
            return VE::SW22;	 // "sw22"
          case '3':	 // 1 string to match.
            return VE::SW23;	 // "sw23"
          case '4':	 // 1 string to match.
            return VE::SW24;	 // "sw24"
          case '5':	 // 1 string to match.
            return VE::SW25;	 // "sw25"
          case '6':	 // 1 string to match.
            return VE::SW26;	 // "sw26"
          case '7':	 // 1 string to match.
            return VE::SW27;	 // "sw27"
          case '8':	 // 1 string to match.
            return VE::SW28;	 // "sw28"
          case '9':	 // 1 string to match.
            return VE::SW29;	 // "sw29"
          }
          break;
        case '3':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SW30;	 // "sw30"
          case '1':	 // 1 string to match.
            return VE::SW31;	 // "sw31"
          case '2':	 // 1 string to match.
            return VE::SW32;	 // "sw32"
          case '3':	 // 1 string to match.
            return VE::SW33;	 // "sw33"
          case '4':	 // 1 string to match.
            return VE::SW34;	 // "sw34"
          case '5':	 // 1 string to match.
            return VE::SW35;	 // "sw35"
          case '6':	 // 1 string to match.
            return VE::SW36;	 // "sw36"
          case '7':	 // 1 string to match.
            return VE::SW37;	 // "sw37"
          case '8':	 // 1 string to match.
            return VE::SW38;	 // "sw38"
          case '9':	 // 1 string to match.
            return VE::SW39;	 // "sw39"
          }
          break;
        case '4':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SW40;	 // "sw40"
          case '1':	 // 1 string to match.
            return VE::SW41;	 // "sw41"
          case '2':	 // 1 string to match.
            return VE::SW42;	 // "sw42"
          case '3':	 // 1 string to match.
            return VE::SW43;	 // "sw43"
          case '4':	 // 1 string to match.
            return VE::SW44;	 // "sw44"
          case '5':	 // 1 string to match.
            return VE::SW45;	 // "sw45"
          case '6':	 // 1 string to match.
            return VE::SW46;	 // "sw46"
          case '7':	 // 1 string to match.
            return VE::SW47;	 // "sw47"
          case '8':	 // 1 string to match.
            return VE::SW48;	 // "sw48"
          case '9':	 // 1 string to match.
            return VE::SW49;	 // "sw49"
          }
          break;
        case '5':	 // 10 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SW50;	 // "sw50"
          case '1':	 // 1 string to match.
            return VE::SW51;	 // "sw51"
          case '2':	 // 1 string to match.
            return VE::SW52;	 // "sw52"
          case '3':	 // 1 string to match.
            return VE::SW53;	 // "sw53"
          case '4':	 // 1 string to match.
            return VE::SW54;	 // "sw54"
          case '5':	 // 1 string to match.
            return VE::SW55;	 // "sw55"
          case '6':	 // 1 string to match.
            return VE::SW56;	 // "sw56"
          case '7':	 // 1 string to match.
            return VE::SW57;	 // "sw57"
          case '8':	 // 1 string to match.
            return VE::SW58;	 // "sw58"
          case '9':	 // 1 string to match.
            return VE::SW59;	 // "sw59"
          }
          break;
        case '6':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case '0':	 // 1 string to match.
            return VE::SW60;	 // "sw60"
          case '1':	 // 1 string to match.
            return VE::SW61;	 // "sw61"
          case '2':	 // 1 string to match.
            return VE::SW62;	 // "sw62"
          case '3':	 // 1 string to match.
            return VE::SW63;	 // "sw63"
          }
          break;
        }
        break;
      }
      break;
    case 'v':	 // 13 strings to match.
      if (Name[1] != 'm')
        break;
      switch (Name[2]) {
      default: break;
      case '1':	 // 6 strings to match.
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::VM10;	 // "vm10"
        case '1':	 // 1 string to match.
          return VE::VM11;	 // "vm11"
        case '2':	 // 1 string to match.
          return VE::VM12;	 // "vm12"
        case '3':	 // 1 string to match.
          return VE::VM13;	 // "vm13"
        case '4':	 // 1 string to match.
          return VE::VM14;	 // "vm14"
        case '5':	 // 1 string to match.
          return VE::VM15;	 // "vm15"
        }
        break;
      case 'p':	 // 7 strings to match.
        switch (Name[3]) {
        default: break;
        case '1':	 // 1 string to match.
          return VE::VMP1;	 // "vmp1"
        case '2':	 // 1 string to match.
          return VE::VMP2;	 // "vmp2"
        case '3':	 // 1 string to match.
          return VE::VMP3;	 // "vmp3"
        case '4':	 // 1 string to match.
          return VE::VMP4;	 // "vmp4"
        case '5':	 // 1 string to match.
          return VE::VMP5;	 // "vmp5"
        case '6':	 // 1 string to match.
          return VE::VMP6;	 // "vmp6"
        case '7':	 // 1 string to match.
          return VE::VMP7;	 // "vmp7"
        }
        break;
      }
      break;
    }
    break;
  case 5:	 // 10 strings to match.
    switch (Name[0]) {
    default: break;
    case 'p':	 // 9 strings to match.
      if (memcmp(Name.data()+1, "mc", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case '1':	 // 5 strings to match.
        switch (Name[4]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::PMC10;	 // "pmc10"
        case '1':	 // 1 string to match.
          return VE::PMC11;	 // "pmc11"
        case '2':	 // 1 string to match.
          return VE::PMC12;	 // "pmc12"
        case '3':	 // 1 string to match.
          return VE::PMC13;	 // "pmc13"
        case '4':	 // 1 string to match.
          return VE::PMC14;	 // "pmc14"
        }
        break;
      case 'r':	 // 4 strings to match.
        switch (Name[4]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::PMCR0;	 // "pmcr0"
        case '1':	 // 1 string to match.
          return VE::PMCR1;	 // "pmcr1"
        case '2':	 // 1 string to match.
          return VE::PMCR2;	 // "pmcr2"
        case '3':	 // 1 string to match.
          return VE::PMCR3;	 // "pmcr3"
        }
        break;
      }
      break;
    case 'u':	 // 1 string to match.
      if (memcmp(Name.data()+1, "srcc", 4) != 0)
        break;
      return VE::USRCC;	 // "usrcc"
    }
    break;
  }
  return VE::NoRegister;
}

static MCRegister MatchRegisterAltName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 50 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 1 string to match.
      if (Name[1] != 'p')
        break;
      return VE::SX9;	 // "fp"
    case 'l':	 // 1 string to match.
      if (Name[1] != 'r')
        break;
      return VE::SX10;	 // "lr"
    case 's':	 // 37 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 4 strings to match.
        return VE::Q0;	 // "s0"
      case '1':	 // 3 strings to match.
        return VE::SF1;	 // "s1"
      case '2':	 // 4 strings to match.
        return VE::Q1;	 // "s2"
      case '3':	 // 3 strings to match.
        return VE::SF3;	 // "s3"
      case '4':	 // 4 strings to match.
        return VE::Q2;	 // "s4"
      case '5':	 // 3 strings to match.
        return VE::SF5;	 // "s5"
      case '6':	 // 4 strings to match.
        return VE::Q3;	 // "s6"
      case '7':	 // 3 strings to match.
        return VE::SF7;	 // "s7"
      case '8':	 // 4 strings to match.
        return VE::Q4;	 // "s8"
      case '9':	 // 3 strings to match.
        return VE::SF9;	 // "s9"
      case 'l':	 // 1 string to match.
        return VE::SX8;	 // "sl"
      case 'p':	 // 1 string to match.
        return VE::SX11;	 // "sp"
      }
      break;
    case 't':	 // 1 string to match.
      if (Name[1] != 'p')
        break;
      return VE::SX14;	 // "tp"
    case 'v':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return VE::V0;	 // "v0"
      case '1':	 // 1 string to match.
        return VE::V1;	 // "v1"
      case '2':	 // 1 string to match.
        return VE::V2;	 // "v2"
      case '3':	 // 1 string to match.
        return VE::V3;	 // "v3"
      case '4':	 // 1 string to match.
        return VE::V4;	 // "v4"
      case '5':	 // 1 string to match.
        return VE::V5;	 // "v5"
      case '6':	 // 1 string to match.
        return VE::V6;	 // "v6"
      case '7':	 // 1 string to match.
        return VE::V7;	 // "v7"
      case '8':	 // 1 string to match.
        return VE::V8;	 // "v8"
      case '9':	 // 1 string to match.
        return VE::V9;	 // "v9"
      }
      break;
    }
    break;
  case 3:	 // 261 strings to match.
    switch (Name[0]) {
    default: break;
    case 'g':	 // 1 string to match.
      if (memcmp(Name.data()+1, "ot", 2) != 0)
        break;
      return VE::SX15;	 // "got"
    case 'p':	 // 1 string to match.
      if (memcmp(Name.data()+1, "lt", 2) != 0)
        break;
      return VE::SX16;	 // "plt"
    case 's':	 // 189 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 35 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 4 strings to match.
          return VE::Q5;	 // "s10"
        case '1':	 // 3 strings to match.
          return VE::SF11;	 // "s11"
        case '2':	 // 4 strings to match.
          return VE::Q6;	 // "s12"
        case '3':	 // 3 strings to match.
          return VE::SF13;	 // "s13"
        case '4':	 // 4 strings to match.
          return VE::Q7;	 // "s14"
        case '5':	 // 3 strings to match.
          return VE::SF15;	 // "s15"
        case '6':	 // 4 strings to match.
          return VE::Q8;	 // "s16"
        case '7':	 // 3 strings to match.
          return VE::SF17;	 // "s17"
        case '8':	 // 4 strings to match.
          return VE::Q9;	 // "s18"
        case '9':	 // 3 strings to match.
          return VE::SF19;	 // "s19"
        }
        break;
      case '2':	 // 35 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 4 strings to match.
          return VE::Q10;	 // "s20"
        case '1':	 // 3 strings to match.
          return VE::SF21;	 // "s21"
        case '2':	 // 4 strings to match.
          return VE::Q11;	 // "s22"
        case '3':	 // 3 strings to match.
          return VE::SF23;	 // "s23"
        case '4':	 // 4 strings to match.
          return VE::Q12;	 // "s24"
        case '5':	 // 3 strings to match.
          return VE::SF25;	 // "s25"
        case '6':	 // 4 strings to match.
          return VE::Q13;	 // "s26"
        case '7':	 // 3 strings to match.
          return VE::SF27;	 // "s27"
        case '8':	 // 4 strings to match.
          return VE::Q14;	 // "s28"
        case '9':	 // 3 strings to match.
          return VE::SF29;	 // "s29"
        }
        break;
      case '3':	 // 35 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 4 strings to match.
          return VE::Q15;	 // "s30"
        case '1':	 // 3 strings to match.
          return VE::SF31;	 // "s31"
        case '2':	 // 4 strings to match.
          return VE::Q16;	 // "s32"
        case '3':	 // 3 strings to match.
          return VE::SF33;	 // "s33"
        case '4':	 // 4 strings to match.
          return VE::Q17;	 // "s34"
        case '5':	 // 3 strings to match.
          return VE::SF35;	 // "s35"
        case '6':	 // 4 strings to match.
          return VE::Q18;	 // "s36"
        case '7':	 // 3 strings to match.
          return VE::SF37;	 // "s37"
        case '8':	 // 4 strings to match.
          return VE::Q19;	 // "s38"
        case '9':	 // 3 strings to match.
          return VE::SF39;	 // "s39"
        }
        break;
      case '4':	 // 35 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 4 strings to match.
          return VE::Q20;	 // "s40"
        case '1':	 // 3 strings to match.
          return VE::SF41;	 // "s41"
        case '2':	 // 4 strings to match.
          return VE::Q21;	 // "s42"
        case '3':	 // 3 strings to match.
          return VE::SF43;	 // "s43"
        case '4':	 // 4 strings to match.
          return VE::Q22;	 // "s44"
        case '5':	 // 3 strings to match.
          return VE::SF45;	 // "s45"
        case '6':	 // 4 strings to match.
          return VE::Q23;	 // "s46"
        case '7':	 // 3 strings to match.
          return VE::SF47;	 // "s47"
        case '8':	 // 4 strings to match.
          return VE::Q24;	 // "s48"
        case '9':	 // 3 strings to match.
          return VE::SF49;	 // "s49"
        }
        break;
      case '5':	 // 35 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 4 strings to match.
          return VE::Q25;	 // "s50"
        case '1':	 // 3 strings to match.
          return VE::SF51;	 // "s51"
        case '2':	 // 4 strings to match.
          return VE::Q26;	 // "s52"
        case '3':	 // 3 strings to match.
          return VE::SF53;	 // "s53"
        case '4':	 // 4 strings to match.
          return VE::Q27;	 // "s54"
        case '5':	 // 3 strings to match.
          return VE::SF55;	 // "s55"
        case '6':	 // 4 strings to match.
          return VE::Q28;	 // "s56"
        case '7':	 // 3 strings to match.
          return VE::SF57;	 // "s57"
        case '8':	 // 4 strings to match.
          return VE::Q29;	 // "s58"
        case '9':	 // 3 strings to match.
          return VE::SF59;	 // "s59"
        }
        break;
      case '6':	 // 14 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 4 strings to match.
          return VE::Q30;	 // "s60"
        case '1':	 // 3 strings to match.
          return VE::SF61;	 // "s61"
        case '2':	 // 4 strings to match.
          return VE::Q31;	 // "s62"
        case '3':	 // 3 strings to match.
          return VE::SF63;	 // "s63"
        }
        break;
      }
      break;
    case 'v':	 // 70 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V10;	 // "v10"
        case '1':	 // 1 string to match.
          return VE::V11;	 // "v11"
        case '2':	 // 1 string to match.
          return VE::V12;	 // "v12"
        case '3':	 // 1 string to match.
          return VE::V13;	 // "v13"
        case '4':	 // 1 string to match.
          return VE::V14;	 // "v14"
        case '5':	 // 1 string to match.
          return VE::V15;	 // "v15"
        case '6':	 // 1 string to match.
          return VE::V16;	 // "v16"
        case '7':	 // 1 string to match.
          return VE::V17;	 // "v17"
        case '8':	 // 1 string to match.
          return VE::V18;	 // "v18"
        case '9':	 // 1 string to match.
          return VE::V19;	 // "v19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V20;	 // "v20"
        case '1':	 // 1 string to match.
          return VE::V21;	 // "v21"
        case '2':	 // 1 string to match.
          return VE::V22;	 // "v22"
        case '3':	 // 1 string to match.
          return VE::V23;	 // "v23"
        case '4':	 // 1 string to match.
          return VE::V24;	 // "v24"
        case '5':	 // 1 string to match.
          return VE::V25;	 // "v25"
        case '6':	 // 1 string to match.
          return VE::V26;	 // "v26"
        case '7':	 // 1 string to match.
          return VE::V27;	 // "v27"
        case '8':	 // 1 string to match.
          return VE::V28;	 // "v28"
        case '9':	 // 1 string to match.
          return VE::V29;	 // "v29"
        }
        break;
      case '3':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V30;	 // "v30"
        case '1':	 // 1 string to match.
          return VE::V31;	 // "v31"
        case '2':	 // 1 string to match.
          return VE::V32;	 // "v32"
        case '3':	 // 1 string to match.
          return VE::V33;	 // "v33"
        case '4':	 // 1 string to match.
          return VE::V34;	 // "v34"
        case '5':	 // 1 string to match.
          return VE::V35;	 // "v35"
        case '6':	 // 1 string to match.
          return VE::V36;	 // "v36"
        case '7':	 // 1 string to match.
          return VE::V37;	 // "v37"
        case '8':	 // 1 string to match.
          return VE::V38;	 // "v38"
        case '9':	 // 1 string to match.
          return VE::V39;	 // "v39"
        }
        break;
      case '4':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V40;	 // "v40"
        case '1':	 // 1 string to match.
          return VE::V41;	 // "v41"
        case '2':	 // 1 string to match.
          return VE::V42;	 // "v42"
        case '3':	 // 1 string to match.
          return VE::V43;	 // "v43"
        case '4':	 // 1 string to match.
          return VE::V44;	 // "v44"
        case '5':	 // 1 string to match.
          return VE::V45;	 // "v45"
        case '6':	 // 1 string to match.
          return VE::V46;	 // "v46"
        case '7':	 // 1 string to match.
          return VE::V47;	 // "v47"
        case '8':	 // 1 string to match.
          return VE::V48;	 // "v48"
        case '9':	 // 1 string to match.
          return VE::V49;	 // "v49"
        }
        break;
      case '5':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V50;	 // "v50"
        case '1':	 // 1 string to match.
          return VE::V51;	 // "v51"
        case '2':	 // 1 string to match.
          return VE::V52;	 // "v52"
        case '3':	 // 1 string to match.
          return VE::V53;	 // "v53"
        case '4':	 // 1 string to match.
          return VE::V54;	 // "v54"
        case '5':	 // 1 string to match.
          return VE::V55;	 // "v55"
        case '6':	 // 1 string to match.
          return VE::V56;	 // "v56"
        case '7':	 // 1 string to match.
          return VE::V57;	 // "v57"
        case '8':	 // 1 string to match.
          return VE::V58;	 // "v58"
        case '9':	 // 1 string to match.
          return VE::V59;	 // "v59"
        }
        break;
      case '6':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return VE::V60;	 // "v60"
        case '1':	 // 1 string to match.
          return VE::V61;	 // "v61"
        case '2':	 // 1 string to match.
          return VE::V62;	 // "v62"
        case '3':	 // 1 string to match.
          return VE::V63;	 // "v63"
        }
        break;
      case 'i':	 // 1 string to match.
        if (Name[2] != 'x')
          break;
        return VE::VIX;	 // "vix"
      case 'm':	 // 15 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return VE::VM0;	 // "vm0"
        case '1':	 // 1 string to match.
          return VE::VM1;	 // "vm1"
        case '2':	 // 2 strings to match.
          return VE::VM2;	 // "vm2"
        case '3':	 // 1 string to match.
          return VE::VM3;	 // "vm3"
        case '4':	 // 2 strings to match.
          return VE::VM4;	 // "vm4"
        case '5':	 // 1 string to match.
          return VE::VM5;	 // "vm5"
        case '6':	 // 2 strings to match.
          return VE::VM6;	 // "vm6"
        case '7':	 // 1 string to match.
          return VE::VM7;	 // "vm7"
        case '8':	 // 2 strings to match.
          return VE::VM8;	 // "vm8"
        case '9':	 // 1 string to match.
          return VE::VM9;	 // "vm9"
        }
        break;
      }
      break;
    }
    break;
  case 4:	 // 9 strings to match.
    if (memcmp(Name.data()+0, "vm1", 3) != 0)
      break;
    switch (Name[3]) {
    default: break;
    case '0':	 // 2 strings to match.
      return VE::VM10;	 // "vm10"
    case '1':	 // 1 string to match.
      return VE::VM11;	 // "vm11"
    case '2':	 // 2 strings to match.
      return VE::VM12;	 // "vm12"
    case '3':	 // 1 string to match.
      return VE::VM13;	 // "vm13"
    case '4':	 // 2 strings to match.
      return VE::VM14;	 // "vm14"
    case '5':	 // 1 string to match.
      return VE::VM15;	 // "vm15"
    }
    break;
  }
  return VE::NoRegister;
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

static void applyMnemonicAliases(StringRef &Mnemonic, const FeatureBitset &Features, unsigned VariantID) {
  switch (Mnemonic.size()) {
  default: break;
  case 4:	 // 1 string to match.
    if (memcmp(Mnemonic.data()+0, "vgtl", 4) != 0)
      break;
    Mnemonic = "vgtl.zx";	 // "vgtl"
    return;
  case 6:	 // 12 strings to match.
    switch (Mnemonic[0]) {
    default: break;
    case 'c':	 // 4 strings to match.
      if (memcmp(Mnemonic.data()+1, "mov.", 4) != 0)
        break;
      switch (Mnemonic[5]) {
      default: break;
      case 'd':	 // 1 string to match.
        Mnemonic = "cmov.d.at";	 // "cmov.d"
        return;
      case 'l':	 // 1 string to match.
        Mnemonic = "cmov.l.at";	 // "cmov.l"
        return;
      case 's':	 // 1 string to match.
        Mnemonic = "cmov.s.at";	 // "cmov.s"
        return;
      case 'w':	 // 1 string to match.
        Mnemonic = "cmov.w.at";	 // "cmov.w"
        return;
      }
      break;
    case 'v':	 // 8 strings to match.
      switch (Mnemonic[1]) {
      default: break;
      case 'f':	 // 4 strings to match.
        if (memcmp(Mnemonic.data()+2, "mk.", 3) != 0)
          break;
        switch (Mnemonic[5]) {
        default: break;
        case 'd':	 // 1 string to match.
          Mnemonic = "vfmk.d.at";	 // "vfmk.d"
          return;
        case 'l':	 // 1 string to match.
          Mnemonic = "vfmk.l.at";	 // "vfmk.l"
          return;
        case 's':	 // 1 string to match.
          Mnemonic = "pvfmk.s.up.at";	 // "vfmk.s"
          return;
        case 'w':	 // 1 string to match.
          Mnemonic = "vfmk.w.at";	 // "vfmk.w"
          return;
        }
        break;
      case 'm':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "rg.l", 4) != 0)
          break;
        Mnemonic = "vmrg";	 // "vmrg.l"
        return;
      case 'r':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "cp.s", 4) != 0)
          break;
        Mnemonic = "pvrcp.up";	 // "vrcp.s"
        return;
      case 's':	 // 2 strings to match.
        switch (Mnemonic[2]) {
        default: break;
        case 'l':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+3, "a.w", 3) != 0)
            break;
          Mnemonic = "pvsla.lo";	 // "vsla.w"
          return;
        case 'r':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+3, "a.w", 3) != 0)
            break;
          Mnemonic = "pvsra.lo";	 // "vsra.w"
          return;
        }
        break;
      }
      break;
    }
    break;
  case 7:	 // 19 strings to match.
    if (Mnemonic[0] != 'v')
      break;
    switch (Mnemonic[1]) {
    default: break;
    case 'a':	 // 2 strings to match.
      if (memcmp(Mnemonic.data()+2, "dd", 2) != 0)
        break;
      switch (Mnemonic[4]) {
      default: break;
      case 's':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+5, ".w", 2) != 0)
          break;
        Mnemonic = "pvadds.lo";	 // "vadds.w"
        return;
      case 'u':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+5, ".w", 2) != 0)
          break;
        Mnemonic = "pvaddu.lo";	 // "vaddu.w"
        return;
      }
      break;
    case 'c':	 // 2 strings to match.
      if (memcmp(Mnemonic.data()+2, "mp", 2) != 0)
        break;
      switch (Mnemonic[4]) {
      default: break;
      case 's':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+5, ".w", 2) != 0)
          break;
        Mnemonic = "pvcmps.lo";	 // "vcmps.w"
        return;
      case 'u':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+5, ".w", 2) != 0)
          break;
        Mnemonic = "pvcmpu.lo";	 // "vcmpu.w"
        return;
      }
      break;
    case 'd':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+2, "ivs.w", 5) != 0)
        break;
      Mnemonic = "vdivs.w.zx";	 // "vdivs.w"
      return;
    case 'f':	 // 8 strings to match.
      switch (Mnemonic[2]) {
      default: break;
      case 'a':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+3, "dd.s", 4) != 0)
          break;
        Mnemonic = "pvfadd.up";	 // "vfadd.s"
        return;
      case 'c':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+3, "mp.s", 4) != 0)
          break;
        Mnemonic = "pvfcmp.up";	 // "vfcmp.s"
        return;
      case 'm':	 // 5 strings to match.
        switch (Mnemonic[3]) {
        default: break;
        case 'a':	 // 2 strings to match.
          switch (Mnemonic[4]) {
          default: break;
          case 'd':	 // 1 string to match.
            if (memcmp(Mnemonic.data()+5, ".s", 2) != 0)
              break;
            Mnemonic = "pvfmad.up";	 // "vfmad.s"
            return;
          case 'x':	 // 1 string to match.
            if (memcmp(Mnemonic.data()+5, ".s", 2) != 0)
              break;
            Mnemonic = "pvfmax.up";	 // "vfmax.s"
            return;
          }
          break;
        case 'i':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+4, "n.s", 3) != 0)
            break;
          Mnemonic = "pvfmin.up";	 // "vfmin.s"
          return;
        case 's':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+4, "b.s", 3) != 0)
            break;
          Mnemonic = "pvfmsb.up";	 // "vfmsb.s"
          return;
        case 'u':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+4, "l.s", 3) != 0)
            break;
          Mnemonic = "pvfmul.up";	 // "vfmul.s"
          return;
        }
        break;
      case 's':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+3, "ub.s", 4) != 0)
          break;
        Mnemonic = "pvfsub.up";	 // "vfsub.s"
        return;
      }
      break;
    case 'g':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+2, "tl.nc", 5) != 0)
        break;
      Mnemonic = "vgtl.zx.nc";	 // "vgtl.nc"
      return;
    case 'm':	 // 3 strings to match.
      switch (Mnemonic[2]) {
      default: break;
      case 'a':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+3, "xs.w", 4) != 0)
          break;
        Mnemonic = "pvmaxs.lo";	 // "vmaxs.w"
        return;
      case 'i':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+3, "ns.w", 4) != 0)
          break;
        Mnemonic = "pvmins.lo";	 // "vmins.w"
        return;
      case 'u':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+3, "ls.w", 4) != 0)
          break;
        Mnemonic = "vmuls.w.zx";	 // "vmuls.w"
        return;
      }
      break;
    case 's':	 // 2 strings to match.
      if (memcmp(Mnemonic.data()+2, "ub", 2) != 0)
        break;
      switch (Mnemonic[4]) {
      default: break;
      case 's':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+5, ".w", 2) != 0)
          break;
        Mnemonic = "pvsubs.lo";	 // "vsubs.w"
        return;
      case 'u':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+5, ".w", 2) != 0)
          break;
        Mnemonic = "pvsubu.lo";	 // "vsubu.w"
        return;
      }
      break;
    }
    break;
  case 8:	 // 3 strings to match.
    if (Mnemonic[0] != 'v')
      break;
    switch (Mnemonic[1]) {
    default: break;
    case 'f':	 // 2 strings to match.
      if (memcmp(Mnemonic.data()+2, "nm", 2) != 0)
        break;
      switch (Mnemonic[4]) {
      default: break;
      case 'a':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+5, "d.s", 3) != 0)
          break;
        Mnemonic = "pvfnmad.up";	 // "vfnmad.s"
        return;
      case 's':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+5, "b.s", 3) != 0)
          break;
        Mnemonic = "pvfnmsb.up";	 // "vfnmsb.s"
        return;
      }
      break;
    case 'r':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+2, "sqrt.s", 6) != 0)
        break;
      Mnemonic = "pvrsqrt.up";	 // "vrsqrt.s"
      return;
    }
    break;
  case 9:	 // 10 strings to match.
    if (Mnemonic[0] != 'v')
      break;
    switch (Mnemonic[1]) {
    default: break;
    case 'f':	 // 8 strings to match.
      if (memcmp(Mnemonic.data()+2, "mk.s.", 5) != 0)
        break;
      switch (Mnemonic[7]) {
      default: break;
      case 'a':	 // 2 strings to match.
        switch (Mnemonic[8]) {
        default: break;
        case 'f':	 // 1 string to match.
          Mnemonic = "pvfmk.s.up.af";	 // "vfmk.s.af"
          return;
        case 't':	 // 1 string to match.
          Mnemonic = "pvfmk.s.up.at";	 // "vfmk.s.at"
          return;
        }
        break;
      case 'e':	 // 1 string to match.
        if (Mnemonic[8] != 'q')
          break;
        Mnemonic = "pvfmk.s.up.eq";	 // "vfmk.s.eq"
        return;
      case 'g':	 // 2 strings to match.
        switch (Mnemonic[8]) {
        default: break;
        case 'e':	 // 1 string to match.
          Mnemonic = "pvfmk.s.up.ge";	 // "vfmk.s.ge"
          return;
        case 't':	 // 1 string to match.
          Mnemonic = "pvfmk.s.up.gt";	 // "vfmk.s.gt"
          return;
        }
        break;
      case 'l':	 // 2 strings to match.
        switch (Mnemonic[8]) {
        default: break;
        case 'e':	 // 1 string to match.
          Mnemonic = "pvfmk.s.up.le";	 // "vfmk.s.le"
          return;
        case 't':	 // 1 string to match.
          Mnemonic = "pvfmk.s.up.lt";	 // "vfmk.s.lt"
          return;
        }
        break;
      case 'n':	 // 1 string to match.
        if (Mnemonic[8] != 'e')
          break;
        Mnemonic = "pvfmk.s.up.ne";	 // "vfmk.s.ne"
        return;
      }
      break;
    case 's':	 // 2 strings to match.
      switch (Mnemonic[2]) {
      default: break;
      case 'l':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+3, "a.w.zx", 6) != 0)
          break;
        Mnemonic = "pvsla.lo";	 // "vsla.w.zx"
        return;
      case 'r':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+3, "a.w.zx", 6) != 0)
          break;
        Mnemonic = "pvsra.lo";	 // "vsra.w.zx"
        return;
      }
      break;
    }
    break;
  case 10:	 // 11 strings to match.
    switch (Mnemonic[0]) {
    default: break;
    case 'p':	 // 4 strings to match.
      if (memcmp(Mnemonic.data()+1, "vfmk.", 5) != 0)
        break;
      switch (Mnemonic[6]) {
      default: break;
      case 's':	 // 2 strings to match.
        if (Mnemonic[7] != '.')
          break;
        switch (Mnemonic[8]) {
        default: break;
        case 'l':	 // 1 string to match.
          if (Mnemonic[9] != 'o')
            break;
          Mnemonic = "pvfmk.s.lo.at";	 // "pvfmk.s.lo"
          return;
        case 'u':	 // 1 string to match.
          if (Mnemonic[9] != 'p')
            break;
          Mnemonic = "pvfmk.s.up.at";	 // "pvfmk.s.up"
          return;
        }
        break;
      case 'w':	 // 2 strings to match.
        if (Mnemonic[7] != '.')
          break;
        switch (Mnemonic[8]) {
        default: break;
        case 'l':	 // 1 string to match.
          if (Mnemonic[9] != 'o')
            break;
          Mnemonic = "vfmk.w.at";	 // "pvfmk.w.lo"
          return;
        case 'u':	 // 1 string to match.
          if (Mnemonic[9] != 'p')
            break;
          Mnemonic = "pvfmk.w.up.at";	 // "pvfmk.w.up"
          return;
        }
        break;
      }
      break;
    case 'v':	 // 7 strings to match.
      switch (Mnemonic[1]) {
      default: break;
      case 'a':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "dds.w.zx", 8) != 0)
          break;
        Mnemonic = "pvadds.lo";	 // "vadds.w.zx"
        return;
      case 'c':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "mps.w.zx", 8) != 0)
          break;
        Mnemonic = "pvcmps.lo";	 // "vcmps.w.zx"
        return;
      case 'f':	 // 2 strings to match.
        if (memcmp(Mnemonic.data()+2, "mk.s.n", 6) != 0)
          break;
        switch (Mnemonic[8]) {
        default: break;
        case 'a':	 // 1 string to match.
          if (Mnemonic[9] != 'n')
            break;
          Mnemonic = "pvfmk.s.up.nan";	 // "vfmk.s.nan"
          return;
        case 'u':	 // 1 string to match.
          if (Mnemonic[9] != 'm')
            break;
          Mnemonic = "pvfmk.s.up.num";	 // "vfmk.s.num"
          return;
        }
        break;
      case 'm':	 // 2 strings to match.
        switch (Mnemonic[2]) {
        default: break;
        case 'a':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+3, "xs.w.zx", 7) != 0)
            break;
          Mnemonic = "pvmaxs.lo";	 // "vmaxs.w.zx"
          return;
        case 'i':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+3, "ns.w.zx", 7) != 0)
            break;
          Mnemonic = "pvmins.lo";	 // "vmins.w.zx"
          return;
        }
        break;
      case 's':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "ubs.w.zx", 8) != 0)
          break;
        Mnemonic = "pvsubs.lo";	 // "vsubs.w.zx"
        return;
      }
      break;
    }
    break;
  case 11:	 // 4 strings to match.
    if (memcmp(Mnemonic.data()+0, "pvs", 3) != 0)
      break;
    switch (Mnemonic[3]) {
    default: break;
    case 'l':	 // 2 strings to match.
      if (memcmp(Mnemonic.data()+4, "a.lo.", 5) != 0)
        break;
      switch (Mnemonic[9]) {
      default: break;
      case 's':	 // 1 string to match.
        if (Mnemonic[10] != 'x')
          break;
        Mnemonic = "vsla.w.sx";	 // "pvsla.lo.sx"
        return;
      case 'z':	 // 1 string to match.
        if (Mnemonic[10] != 'x')
          break;
        Mnemonic = "pvsla.lo";	 // "pvsla.lo.zx"
        return;
      }
      break;
    case 'r':	 // 2 strings to match.
      if (memcmp(Mnemonic.data()+4, "a.lo.", 5) != 0)
        break;
      switch (Mnemonic[9]) {
      default: break;
      case 's':	 // 1 string to match.
        if (Mnemonic[10] != 'x')
          break;
        Mnemonic = "vsra.w.sx";	 // "pvsra.lo.sx"
        return;
      case 'z':	 // 1 string to match.
        if (Mnemonic[10] != 'x')
          break;
        Mnemonic = "pvsra.lo";	 // "pvsra.lo.zx"
        return;
      }
      break;
    }
    break;
  case 12:	 // 17 strings to match.
    switch (Mnemonic[0]) {
    default: break;
    case 'p':	 // 10 strings to match.
      if (Mnemonic[1] != 'v')
        break;
      switch (Mnemonic[2]) {
      default: break;
      case 'a':	 // 2 strings to match.
        if (memcmp(Mnemonic.data()+3, "dds.lo.", 7) != 0)
          break;
        switch (Mnemonic[10]) {
        default: break;
        case 's':	 // 1 string to match.
          if (Mnemonic[11] != 'x')
            break;
          Mnemonic = "vadds.w.sx";	 // "pvadds.lo.sx"
          return;
        case 'z':	 // 1 string to match.
          if (Mnemonic[11] != 'x')
            break;
          Mnemonic = "pvadds.lo";	 // "pvadds.lo.zx"
          return;
        }
        break;
      case 'c':	 // 2 strings to match.
        if (memcmp(Mnemonic.data()+3, "mps.lo.", 7) != 0)
          break;
        switch (Mnemonic[10]) {
        default: break;
        case 's':	 // 1 string to match.
          if (Mnemonic[11] != 'x')
            break;
          Mnemonic = "vcmps.w.sx";	 // "pvcmps.lo.sx"
          return;
        case 'z':	 // 1 string to match.
          if (Mnemonic[11] != 'x')
            break;
          Mnemonic = "pvcmps.lo";	 // "pvcmps.lo.zx"
          return;
        }
        break;
      case 'm':	 // 4 strings to match.
        switch (Mnemonic[3]) {
        default: break;
        case 'a':	 // 2 strings to match.
          if (memcmp(Mnemonic.data()+4, "xs.lo.", 6) != 0)
            break;
          switch (Mnemonic[10]) {
          default: break;
          case 's':	 // 1 string to match.
            if (Mnemonic[11] != 'x')
              break;
            Mnemonic = "vmaxs.w.sx";	 // "pvmaxs.lo.sx"
            return;
          case 'z':	 // 1 string to match.
            if (Mnemonic[11] != 'x')
              break;
            Mnemonic = "pvmaxs.lo";	 // "pvmaxs.lo.zx"
            return;
          }
          break;
        case 'i':	 // 2 strings to match.
          if (memcmp(Mnemonic.data()+4, "ns.lo.", 6) != 0)
            break;
          switch (Mnemonic[10]) {
          default: break;
          case 's':	 // 1 string to match.
            if (Mnemonic[11] != 'x')
              break;
            Mnemonic = "vmins.w.sx";	 // "pvmins.lo.sx"
            return;
          case 'z':	 // 1 string to match.
            if (Mnemonic[11] != 'x')
              break;
            Mnemonic = "pvmins.lo";	 // "pvmins.lo.zx"
            return;
          }
          break;
        }
        break;
      case 's':	 // 2 strings to match.
        if (memcmp(Mnemonic.data()+3, "ubs.lo.", 7) != 0)
          break;
        switch (Mnemonic[10]) {
        default: break;
        case 's':	 // 1 string to match.
          if (Mnemonic[11] != 'x')
            break;
          Mnemonic = "vsubs.w.sx";	 // "pvsubs.lo.sx"
          return;
        case 'z':	 // 1 string to match.
          if (Mnemonic[11] != 'x')
            break;
          Mnemonic = "pvsubs.lo";	 // "pvsubs.lo.zx"
          return;
        }
        break;
      }
      break;
    case 'v':	 // 7 strings to match.
      switch (Mnemonic[1]) {
      default: break;
      case 'f':	 // 6 strings to match.
        if (memcmp(Mnemonic.data()+2, "mk.s.", 5) != 0)
          break;
        switch (Mnemonic[7]) {
        default: break;
        case 'e':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+8, "qnan", 4) != 0)
            break;
          Mnemonic = "pvfmk.s.up.eqnan";	 // "vfmk.s.eqnan"
          return;
        case 'g':	 // 2 strings to match.
          switch (Mnemonic[8]) {
          default: break;
          case 'e':	 // 1 string to match.
            if (memcmp(Mnemonic.data()+9, "nan", 3) != 0)
              break;
            Mnemonic = "pvfmk.s.up.genan";	 // "vfmk.s.genan"
            return;
          case 't':	 // 1 string to match.
            if (memcmp(Mnemonic.data()+9, "nan", 3) != 0)
              break;
            Mnemonic = "pvfmk.s.up.gtnan";	 // "vfmk.s.gtnan"
            return;
          }
          break;
        case 'l':	 // 2 strings to match.
          switch (Mnemonic[8]) {
          default: break;
          case 'e':	 // 1 string to match.
            if (memcmp(Mnemonic.data()+9, "nan", 3) != 0)
              break;
            Mnemonic = "pvfmk.s.up.lenan";	 // "vfmk.s.lenan"
            return;
          case 't':	 // 1 string to match.
            if (memcmp(Mnemonic.data()+9, "nan", 3) != 0)
              break;
            Mnemonic = "pvfmk.s.up.ltnan";	 // "vfmk.s.ltnan"
            return;
          }
          break;
        case 'n':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+8, "enan", 4) != 0)
            break;
          Mnemonic = "pvfmk.s.up.nenan";	 // "vfmk.s.nenan"
          return;
        }
        break;
      case 'r':	 // 1 string to match.
        if (memcmp(Mnemonic.data()+2, "sqrt.s.nex", 10) != 0)
          break;
        Mnemonic = "pvrsqrt.up.nex";	 // "vrsqrt.s.nex"
        return;
      }
      break;
    }
    break;
  case 13:	 // 8 strings to match.
    if (memcmp(Mnemonic.data()+0, "pvfmk.w.lo.", 11) != 0)
      break;
    switch (Mnemonic[11]) {
    default: break;
    case 'a':	 // 2 strings to match.
      switch (Mnemonic[12]) {
      default: break;
      case 'f':	 // 1 string to match.
        Mnemonic = "vfmk.w.af";	 // "pvfmk.w.lo.af"
        return;
      case 't':	 // 1 string to match.
        Mnemonic = "vfmk.w.at";	 // "pvfmk.w.lo.at"
        return;
      }
      break;
    case 'e':	 // 1 string to match.
      if (Mnemonic[12] != 'q')
        break;
      Mnemonic = "vfmk.w.eq";	 // "pvfmk.w.lo.eq"
      return;
    case 'g':	 // 2 strings to match.
      switch (Mnemonic[12]) {
      default: break;
      case 'e':	 // 1 string to match.
        Mnemonic = "vfmk.w.ge";	 // "pvfmk.w.lo.ge"
        return;
      case 't':	 // 1 string to match.
        Mnemonic = "vfmk.w.gt";	 // "pvfmk.w.lo.gt"
        return;
      }
      break;
    case 'l':	 // 2 strings to match.
      switch (Mnemonic[12]) {
      default: break;
      case 'e':	 // 1 string to match.
        Mnemonic = "vfmk.w.le";	 // "pvfmk.w.lo.le"
        return;
      case 't':	 // 1 string to match.
        Mnemonic = "vfmk.w.lt";	 // "pvfmk.w.lo.lt"
        return;
      }
      break;
    case 'n':	 // 1 string to match.
      if (Mnemonic[12] != 'e')
        break;
      Mnemonic = "vfmk.w.ne";	 // "pvfmk.w.lo.ne"
      return;
    }
    break;
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
  CVT_95_Reg,
  CVT_95_addMImmOperands,
  CVT_95_addSImm7Operands,
  CVT_95_addMEMriOperands,
  CVT_95_addUImm0to2Operands,
  CVT_95_addMEMziOperands,
  CVT_95_addCCOpOperands,
  CVT_95_addImmOperands,
  CVT_95_addZeroOperands,
  CVT_95_addMEMriiOperands,
  CVT_95_addMEMrriOperands,
  CVT_95_addMEMziiOperands,
  CVT_95_addMEMzriOperands,
  CVT_95_addUImm1Operands,
  CVT_95_addRDOpOperands,
  CVT_95_addUImm3Operands,
  CVT_95_addUImm2Operands,
  CVT_95_addUImm6Operands,
  CVT_95_addUImm7Operands,
  CVT_95_addUImm4Operands,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Reg1_0__Reg1_1__Reg1_2,
  Convert__Reg1_0__Reg1_1__MImm1_2,
  Convert__Reg1_0__Reg1_2__SImm71_1,
  Convert__Reg1_0__SImm71_1__MImm1_2,
  Convert__Reg1_0__MEMri2_1__Reg1_2__Tie0_1_1,
  Convert__Reg1_0__MEMri2_1__UImm0to21_2__Tie0_1_1,
  Convert__Reg1_0__MEMzi2_1__Reg1_2__Tie0_1_1,
  Convert__Reg1_0__MEMzi2_1__UImm0to21_2__Tie0_1_1,
  Convert__CCOp1_0__Reg1_2__MEMri2_3,
  Convert__CCOp1_0__Reg1_2__MEMzi2_3,
  Convert__CCOp1_0__SImm71_2__MEMri2_3,
  Convert__CCOp1_0__SImm71_2__MEMzi2_3,
  Convert__MEMri2_0,
  Convert__MEMzi2_0,
  Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4,
  Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4,
  Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4,
  Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4,
  Convert__Imm1_0,
  Convert__Reg1_0__Reg1_1,
  Convert__Reg1_0__MImm1_1,
  Convert__Reg1_0__MEMrii3_1,
  Convert__Reg1_0__MEMrri3_1,
  Convert__Reg1_0__MEMzii3_1,
  Convert__Reg1_0__MEMzri3_1,
  Convert__Reg1_0__Reg1_1__UImm11_2,
  Convert__Reg1_0__MImm1_1__UImm11_2,
  Convert__Reg1_0__MEMri2_1__SImm71_2__Tie0_1_1,
  Convert__Reg1_0__MEMzi2_1__SImm71_2__Tie0_1_1,
  Convert__Reg1_1__CCOp1_0__Reg1_3__Reg1_2__Tie0_1_1,
  Convert__Reg1_1__CCOp1_0__SImm71_3__Reg1_2__Tie0_1_1,
  Convert__Reg1_1__CCOp1_0__Reg1_3__MImm1_2__Tie0_1_1,
  Convert__Reg1_1__CCOp1_0__SImm71_3__MImm1_2__Tie0_1_1,
  Convert__Reg1_0__SImm71_1__Reg1_2,
  Convert__Reg1_0__SImm71_1,
  Convert__Reg1_1__RDOp1_0__Reg1_2,
  Convert__Reg1_1__RDOp1_0__SImm71_2,
  Convert__UImm31_0,
  Convert_NoOperands,
  Convert__UImm21_0,
  Convert__Reg1_0__Reg1_1__UImm31_2,
  Convert__Reg1_0__SImm71_1__UImm31_2,
  Convert__Reg1_0__Reg1_1__Zero1_2,
  Convert__Reg1_0__SImm71_1__Zero1_2,
  Convert__Reg1_0,
  Convert__UImm61_0,
  Convert__Reg1_0__MEMri2_1,
  Convert__Reg1_0__MEMzi2_1,
  Convert__Reg1_0__Reg1_2__Reg1_4,
  Convert__Reg1_0__Reg1_2__MImm1_4,
  Convert__Reg1_0__UImm71_2__Reg1_4,
  Convert__Reg1_0__UImm71_2__MImm1_4,
  Convert__SImm71_0,
  Convert__Reg1_0__UImm21_1__Reg1_2,
  Convert__Reg1_0__UImm21_1__MImm1_2,
  Convert__Reg1_0__Reg1_1__Reg1_3,
  Convert__Reg1_0__Reg1_1__UImm71_3,
  Convert__Reg1_0__Reg1_1__Reg1_2__Tie0_1_1,
  Convert__Reg1_0__Reg1_1__MImm1_2__Tie0_1_1,
  Convert__Reg1_0__SImm71_1__Reg1_2__Tie0_1_1,
  Convert__Reg1_0__SImm71_1__MImm1_2__Tie0_1_1,
  Convert__MEMrii3_0,
  Convert__MEMrri3_0,
  Convert__MEMzii3_0,
  Convert__MEMzri3_0,
  Convert__Reg1_0__Zero1_1,
  Convert__SImm71_0__Reg1_1,
  Convert__SImm71_0__Zero1_1,
  Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3,
  Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3,
  Convert__Reg1_0__MImm1_1__Reg1_2,
  Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3,
  Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3,
  Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3,
  Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4,
  Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4,
  Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4,
  Convert__Reg1_1__CCOp1_0__Reg1_2,
  Convert__Reg1_1__CCOp1_0__Reg1_2__Reg1_3,
  Convert__Reg1_0__Reg1_1__UImm71_2,
  Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3,
  Convert__Reg1_1__Reg1_2__Reg1_0,
  Convert__Reg1_1__Zero1_2__Reg1_0,
  Convert__SImm71_1__Reg1_2__Reg1_0,
  Convert__SImm71_1__Zero1_2__Reg1_0,
  Convert__MEMri2_1__Reg1_0,
  Convert__MEMzi2_1__Reg1_0,
  Convert__Reg1_0__MImm1_1__UImm71_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2,
  Convert__Reg1_0__Tie0_1_1__MImm1_1__Reg1_2,
  Convert__Reg1_0__Tie0_1_1__MImm1_1__UImm71_2,
  Convert__Reg1_0__Reg1_1__Tie0_1_1__Reg1_2,
  Convert__Reg1_0__Reg1_1__Tie0_1_1__UImm71_2,
  Convert__Reg1_0__MImm1_1__Tie0_1_1__Reg1_2,
  Convert__Reg1_0__MImm1_1__Tie0_1_1__UImm71_2,
  Convert__MEMrii3_1__Reg1_0,
  Convert__MEMrri3_1__Reg1_0,
  Convert__MEMzii3_1__Reg1_0,
  Convert__MEMzri3_1__Reg1_0,
  Convert__Reg1_0__Reg1_1__UImm21_2,
  Convert__Reg1_0__MEMri2_1__UImm71_2__Tie0_1_1,
  Convert__Reg1_0__MEMzi2_1__UImm71_2__Tie0_1_1,
  Convert__Reg1_0__MEMri2_1__UImm11_2__Tie0_1_1,
  Convert__Reg1_0__MEMzi2_1__UImm11_2__Tie0_1_1,
  Convert__Reg1_0__Reg1_1__Zero1_2__Tie0_1_1,
  Convert__Reg1_0__SImm71_1__Zero1_2__Tie0_1_1,
  Convert__Reg1_0__Reg1_1__SImm71_2,
  Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3,
  Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3,
  Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3,
  Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4,
  Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4,
  Convert__Reg1_0__UImm71_1__Reg1_2,
  Convert__Reg1_0__UImm71_1__Reg1_2__Reg1_3,
  Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0,
  Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0,
  Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0,
  Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0,
  Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4,
  Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4,
  Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4,
  Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4,
  Convert__Reg1_0__Reg1_1__Reg1_2__MImm1_3,
  Convert__Reg1_0__Reg1_1__UImm31_2__Reg1_3,
  Convert__Reg1_0__Reg1_1__UImm31_2__MImm1_3,
  Convert__Reg1_0__Reg1_1__Reg1_2__MImm1_3__Reg1_4,
  Convert__Reg1_0__Reg1_1__UImm31_2__Reg1_3__Reg1_4,
  Convert__Reg1_0__Reg1_1__UImm31_2__MImm1_3__Reg1_4,
  Convert__Reg1_0__Reg1_1__Reg1_2__UImm41_3,
  Convert__Reg1_0__Reg1_2__Reg1_3__Reg1_5,
  Convert__Reg1_0__Reg1_2__Reg1_3__UImm71_5,
  Convert__Reg1_0__Reg1_2__Reg1_3__Reg1_5__Reg1_6,
  Convert__Reg1_0__Reg1_2__Reg1_3__UImm71_5__Reg1_6,
  Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3,
  Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3,
  Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3,
  Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][11] = {
  // Convert__Reg1_0__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__MImm1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addMImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_2__SImm71_1
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addSImm7Operands, 2, CVT_Done },
  // Convert__Reg1_0__SImm71_1__MImm1_2
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_95_addMImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__MEMri2_1__Reg1_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMriOperands, 2, CVT_95_Reg, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__MEMri2_1__UImm0to21_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMriOperands, 2, CVT_95_addUImm0to2Operands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__MEMzi2_1__Reg1_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMziOperands, 2, CVT_95_Reg, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__MEMzi2_1__UImm0to21_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMziOperands, 2, CVT_95_addUImm0to2Operands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__CCOp1_0__Reg1_2__MEMri2_3
  { CVT_95_addCCOpOperands, 1, CVT_95_Reg, 3, CVT_95_addMEMriOperands, 4, CVT_Done },
  // Convert__CCOp1_0__Reg1_2__MEMzi2_3
  { CVT_95_addCCOpOperands, 1, CVT_95_Reg, 3, CVT_95_addMEMziOperands, 4, CVT_Done },
  // Convert__CCOp1_0__SImm71_2__MEMri2_3
  { CVT_95_addCCOpOperands, 1, CVT_95_addSImm7Operands, 3, CVT_95_addMEMriOperands, 4, CVT_Done },
  // Convert__CCOp1_0__SImm71_2__MEMzi2_3
  { CVT_95_addCCOpOperands, 1, CVT_95_addSImm7Operands, 3, CVT_95_addMEMziOperands, 4, CVT_Done },
  // Convert__MEMri2_0
  { CVT_95_addMEMriOperands, 1, CVT_Done },
  // Convert__MEMzi2_0
  { CVT_95_addMEMziOperands, 1, CVT_Done },
  // Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4
  { CVT_95_addCCOpOperands, 1, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4
  { CVT_95_addCCOpOperands, 1, CVT_95_Reg, 3, CVT_95_addZeroOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4
  { CVT_95_addCCOpOperands, 1, CVT_95_addSImm7Operands, 3, CVT_95_Reg, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4
  { CVT_95_addCCOpOperands, 1, CVT_95_addSImm7Operands, 3, CVT_95_addZeroOperands, 4, CVT_95_addImmOperands, 5, CVT_Done },
  // Convert__Imm1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__MImm1_1
  { CVT_95_Reg, 1, CVT_95_addMImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__MEMrii3_1
  { CVT_95_Reg, 1, CVT_95_addMEMriiOperands, 2, CVT_Done },
  // Convert__Reg1_0__MEMrri3_1
  { CVT_95_Reg, 1, CVT_95_addMEMrriOperands, 2, CVT_Done },
  // Convert__Reg1_0__MEMzii3_1
  { CVT_95_Reg, 1, CVT_95_addMEMziiOperands, 2, CVT_Done },
  // Convert__Reg1_0__MEMzri3_1
  { CVT_95_Reg, 1, CVT_95_addMEMzriOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm11_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm1Operands, 3, CVT_Done },
  // Convert__Reg1_0__MImm1_1__UImm11_2
  { CVT_95_Reg, 1, CVT_95_addMImmOperands, 2, CVT_95_addUImm1Operands, 3, CVT_Done },
  // Convert__Reg1_0__MEMri2_1__SImm71_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMriOperands, 2, CVT_95_addSImm7Operands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__MEMzi2_1__SImm71_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMziOperands, 2, CVT_95_addSImm7Operands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_1__CCOp1_0__Reg1_3__Reg1_2__Tie0_1_1
  { CVT_95_Reg, 2, CVT_95_addCCOpOperands, 1, CVT_95_Reg, 4, CVT_95_Reg, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_1__CCOp1_0__SImm71_3__Reg1_2__Tie0_1_1
  { CVT_95_Reg, 2, CVT_95_addCCOpOperands, 1, CVT_95_addSImm7Operands, 4, CVT_95_Reg, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_1__CCOp1_0__Reg1_3__MImm1_2__Tie0_1_1
  { CVT_95_Reg, 2, CVT_95_addCCOpOperands, 1, CVT_95_Reg, 4, CVT_95_addMImmOperands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_1__CCOp1_0__SImm71_3__MImm1_2__Tie0_1_1
  { CVT_95_Reg, 2, CVT_95_addCCOpOperands, 1, CVT_95_addSImm7Operands, 4, CVT_95_addMImmOperands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__SImm71_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__SImm71_1
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_Done },
  // Convert__Reg1_1__RDOp1_0__Reg1_2
  { CVT_95_Reg, 2, CVT_95_addRDOpOperands, 1, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_1__RDOp1_0__SImm71_2
  { CVT_95_Reg, 2, CVT_95_addRDOpOperands, 1, CVT_95_addSImm7Operands, 3, CVT_Done },
  // Convert__UImm31_0
  { CVT_95_addUImm3Operands, 1, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__UImm21_0
  { CVT_95_addUImm2Operands, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm31_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm3Operands, 3, CVT_Done },
  // Convert__Reg1_0__SImm71_1__UImm31_2
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_95_addUImm3Operands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Zero1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addZeroOperands, 3, CVT_Done },
  // Convert__Reg1_0__SImm71_1__Zero1_2
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_95_addZeroOperands, 3, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__UImm61_0
  { CVT_95_addUImm6Operands, 1, CVT_Done },
  // Convert__Reg1_0__MEMri2_1
  { CVT_95_Reg, 1, CVT_95_addMEMriOperands, 2, CVT_Done },
  // Convert__Reg1_0__MEMzi2_1
  { CVT_95_Reg, 1, CVT_95_addMEMziOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_2__Reg1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__Reg1_2__MImm1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_addMImmOperands, 5, CVT_Done },
  // Convert__Reg1_0__UImm71_2__Reg1_4
  { CVT_95_Reg, 1, CVT_95_addUImm7Operands, 3, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__UImm71_2__MImm1_4
  { CVT_95_Reg, 1, CVT_95_addUImm7Operands, 3, CVT_95_addMImmOperands, 5, CVT_Done },
  // Convert__SImm71_0
  { CVT_95_addSImm7Operands, 1, CVT_Done },
  // Convert__Reg1_0__UImm21_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_addUImm2Operands, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__UImm21_1__MImm1_2
  { CVT_95_Reg, 1, CVT_95_addUImm2Operands, 2, CVT_95_addMImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm71_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm7Operands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__Reg1_1__MImm1_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addMImmOperands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__SImm71_1__Reg1_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_95_Reg, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__SImm71_1__MImm1_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_95_addMImmOperands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__MEMrii3_0
  { CVT_95_addMEMriiOperands, 1, CVT_Done },
  // Convert__MEMrri3_0
  { CVT_95_addMEMrriOperands, 1, CVT_Done },
  // Convert__MEMzii3_0
  { CVT_95_addMEMziiOperands, 1, CVT_Done },
  // Convert__MEMzri3_0
  { CVT_95_addMEMzriOperands, 1, CVT_Done },
  // Convert__Reg1_0__Zero1_1
  { CVT_95_Reg, 1, CVT_95_addZeroOperands, 2, CVT_Done },
  // Convert__SImm71_0__Reg1_1
  { CVT_95_addSImm7Operands, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__SImm71_0__Zero1_1
  { CVT_95_addSImm7Operands, 1, CVT_95_addZeroOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_0__MImm1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_addMImmOperands, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3
  { CVT_95_Reg, 1, CVT_95_addMImmOperands, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3
  { CVT_95_Reg, 2, CVT_95_addRDOpOperands, 1, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addSImm7Operands, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addSImm7Operands, 3, CVT_95_Reg, 4, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_1__CCOp1_0__Reg1_2
  { CVT_95_Reg, 2, CVT_95_addCCOpOperands, 1, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_1__CCOp1_0__Reg1_2__Reg1_3
  { CVT_95_Reg, 2, CVT_95_addCCOpOperands, 1, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm71_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm7Operands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm7Operands, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_1__Reg1_2__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__Zero1_2__Reg1_0
  { CVT_95_Reg, 2, CVT_95_addZeroOperands, 3, CVT_95_Reg, 1, CVT_Done },
  // Convert__SImm71_1__Reg1_2__Reg1_0
  { CVT_95_addSImm7Operands, 2, CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_Done },
  // Convert__SImm71_1__Zero1_2__Reg1_0
  { CVT_95_addSImm7Operands, 2, CVT_95_addZeroOperands, 3, CVT_95_Reg, 1, CVT_Done },
  // Convert__MEMri2_1__Reg1_0
  { CVT_95_addMEMriOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__MEMzi2_1__Reg1_0
  { CVT_95_addMEMziOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__MImm1_1__UImm71_2
  { CVT_95_Reg, 1, CVT_95_addMImmOperands, 2, CVT_95_addUImm7Operands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addUImm7Operands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__MImm1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addMImmOperands, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__MImm1_1__UImm71_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addMImmOperands, 2, CVT_95_addUImm7Operands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Tie0_1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_1_1, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Tie0_1_1__UImm71_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_1_1, CVT_95_addUImm7Operands, 3, CVT_Done },
  // Convert__Reg1_0__MImm1_1__Tie0_1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_addMImmOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__MImm1_1__Tie0_1_1__UImm71_2
  { CVT_95_Reg, 1, CVT_95_addMImmOperands, 2, CVT_Tied, Tie0_1_1, CVT_95_addUImm7Operands, 3, CVT_Done },
  // Convert__MEMrii3_1__Reg1_0
  { CVT_95_addMEMriiOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__MEMrri3_1__Reg1_0
  { CVT_95_addMEMrriOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__MEMzii3_1__Reg1_0
  { CVT_95_addMEMziiOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__MEMzri3_1__Reg1_0
  { CVT_95_addMEMzriOperands, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm21_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm2Operands, 3, CVT_Done },
  // Convert__Reg1_0__MEMri2_1__UImm71_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMriOperands, 2, CVT_95_addUImm7Operands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__MEMzi2_1__UImm71_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMziOperands, 2, CVT_95_addUImm7Operands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__MEMri2_1__UImm11_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMriOperands, 2, CVT_95_addUImm1Operands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__MEMzi2_1__UImm11_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addMEMziOperands, 2, CVT_95_addUImm1Operands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Zero1_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addZeroOperands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__SImm71_1__Zero1_2__Tie0_1_1
  { CVT_95_Reg, 1, CVT_95_addSImm7Operands, 2, CVT_95_addZeroOperands, 3, CVT_Tied, Tie0_1_1, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm71_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addSImm7Operands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addSImm7Operands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addZeroOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addSImm7Operands, 3, CVT_95_addZeroOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addZeroOperands, 4, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addSImm7Operands, 3, CVT_95_addZeroOperands, 4, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__UImm71_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_addUImm7Operands, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__UImm71_1__Reg1_2__Reg1_3
  { CVT_95_Reg, 1, CVT_95_addUImm7Operands, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addZeroOperands, 4, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0
  { CVT_95_Reg, 2, CVT_95_addSImm7Operands, 3, CVT_95_Reg, 4, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0
  { CVT_95_Reg, 2, CVT_95_addSImm7Operands, 3, CVT_95_addZeroOperands, 4, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4
  { CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_Reg, 1, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4
  { CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addZeroOperands, 4, CVT_95_Reg, 1, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4
  { CVT_95_Reg, 2, CVT_95_addSImm7Operands, 3, CVT_95_Reg, 4, CVT_95_Reg, 1, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4
  { CVT_95_Reg, 2, CVT_95_addSImm7Operands, 3, CVT_95_addZeroOperands, 4, CVT_95_Reg, 1, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__MImm1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addMImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm31_2__Reg1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm3Operands, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm31_2__MImm1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm3Operands, 3, CVT_95_addMImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__MImm1_3__Reg1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addMImmOperands, 4, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm31_2__Reg1_3__Reg1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm3Operands, 3, CVT_95_Reg, 4, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm31_2__MImm1_3__Reg1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addUImm3Operands, 3, CVT_95_addMImmOperands, 4, CVT_95_Reg, 5, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__UImm41_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addUImm4Operands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_2__Reg1_3__Reg1_5
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_Reg, 6, CVT_Done },
  // Convert__Reg1_0__Reg1_2__Reg1_3__UImm71_5
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_addUImm7Operands, 6, CVT_Done },
  // Convert__Reg1_0__Reg1_2__Reg1_3__Reg1_5__Reg1_6
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_Reg, 6, CVT_95_Reg, 7, CVT_Done },
  // Convert__Reg1_0__Reg1_2__Reg1_3__UImm71_5__Reg1_6
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_addUImm7Operands, 6, CVT_95_Reg, 7, CVT_Done },
  // Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3
  { CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_Done },
  // Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3
  { CVT_95_Reg, 2, CVT_95_addZeroOperands, 3, CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_Done },
  // Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3
  { CVT_95_addSImm7Operands, 2, CVT_95_Reg, 3, CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_Done },
  // Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3
  { CVT_95_addSImm7Operands, 2, CVT_95_addZeroOperands, 3, CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_Done },
};

void VEAsmParser::
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
      static_cast<VEOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
      static_cast<VEOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addMImmOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addMImmOperands(Inst, 1);
      break;
    case CVT_95_addSImm7Operands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addSImm7Operands(Inst, 1);
      break;
    case CVT_95_addMEMriOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addMEMriOperands(Inst, 2);
      break;
    case CVT_95_addUImm0to2Operands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addUImm0to2Operands(Inst, 1);
      break;
    case CVT_95_addMEMziOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addMEMziOperands(Inst, 2);
      break;
    case CVT_95_addCCOpOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addCCOpOperands(Inst, 1);
      break;
    case CVT_95_addImmOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_95_addZeroOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addZeroOperands(Inst, 1);
      break;
    case CVT_95_addMEMriiOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addMEMriiOperands(Inst, 3);
      break;
    case CVT_95_addMEMrriOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addMEMrriOperands(Inst, 3);
      break;
    case CVT_95_addMEMziiOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addMEMziiOperands(Inst, 3);
      break;
    case CVT_95_addMEMzriOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addMEMzriOperands(Inst, 3);
      break;
    case CVT_95_addUImm1Operands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addUImm1Operands(Inst, 1);
      break;
    case CVT_95_addRDOpOperands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addRDOpOperands(Inst, 1);
      break;
    case CVT_95_addUImm3Operands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addUImm3Operands(Inst, 1);
      break;
    case CVT_95_addUImm2Operands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addUImm2Operands(Inst, 1);
      break;
    case CVT_95_addUImm6Operands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addUImm6Operands(Inst, 1);
      break;
    case CVT_95_addUImm7Operands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addUImm7Operands(Inst, 1);
      break;
    case CVT_95_addUImm4Operands:
      static_cast<VEOperand &>(*Operands[OpIdx]).addUImm4Operands(Inst, 1);
      break;
    }
  }
}

void VEAsmParser::
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
    case CVT_95_addMImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addSImm7Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addMEMriOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 2;
      break;
    case CVT_95_addUImm0to2Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addMEMziOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 2;
      break;
    case CVT_95_addCCOpOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addZeroOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addMEMriiOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 3;
      break;
    case CVT_95_addMEMrriOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 3;
      break;
    case CVT_95_addMEMziiOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 3;
      break;
    case CVT_95_addMEMzriOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 3;
      break;
    case CVT_95_addUImm1Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addRDOpOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addUImm3Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addUImm2Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addUImm6Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addUImm7Operands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_95_addUImm4Operands:
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
  MCK__DOT_d, // '.d'
  MCK__DOT_d_DOT_nt, // '.d.nt'
  MCK__DOT_d_DOT_t, // '.d.t'
  MCK__DOT_l, // '.l'
  MCK__DOT_l_DOT_nt, // '.l.nt'
  MCK__DOT_l_DOT_t, // '.l.t'
  MCK__DOT_s, // '.s'
  MCK__DOT_s_DOT_nt, // '.s.nt'
  MCK__DOT_s_DOT_t, // '.s.t'
  MCK__DOT_w, // '.w'
  MCK__DOT_w_DOT_nt, // '.w.nt'
  MCK__DOT_w_DOT_t, // '.w.t'
  MCK_LAST_TOKEN = MCK__DOT_w_DOT_t,
  MCK_VLS, // register class 'VLS'
  MCK_Reg9, // derived register class
  MCK_VM512, // register class 'VM512'
  MCK_VM, // register class 'VM'
  MCK_MISC, // register class 'MISC'
  MCK_F128, // register class 'F128'
  MCK_F32, // register class 'F32'
  MCK_I32, // register class 'I32'
  MCK_I64, // register class 'I64'
  MCK_V64, // register class 'V64'
  MCK_LAST_REGISTER = MCK_V64,
  MCK_CCOp, // user defined class 'CCOpAsmOperand'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_MImm, // user defined class 'MImmAsmOperand'
  MCK_RDOp, // user defined class 'RDOpAsmOperand'
  MCK_SImm7, // user defined class 'SImm7AsmOperand'
  MCK_UImm0to2, // user defined class 'UImm0to2AsmOperand'
  MCK_UImm1, // user defined class 'UImm1AsmOperand'
  MCK_UImm2, // user defined class 'UImm2AsmOperand'
  MCK_UImm3, // user defined class 'UImm3AsmOperand'
  MCK_UImm4, // user defined class 'UImm4AsmOperand'
  MCK_UImm6, // user defined class 'UImm6AsmOperand'
  MCK_UImm7, // user defined class 'UImm7AsmOperand'
  MCK_MEMri, // user defined class 'VEMEMriAsmOperand'
  MCK_MEMrii, // user defined class 'VEMEMriiAsmOperand'
  MCK_MEMrri, // user defined class 'VEMEMrriAsmOperand'
  MCK_MEMzi, // user defined class 'VEMEMziAsmOperand'
  MCK_MEMzii, // user defined class 'VEMEMziiAsmOperand'
  MCK_MEMzri, // user defined class 'VEMEMzriAsmOperand'
  MCK_Zero, // user defined class 'ZeroAsmOperand'
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
    case '(':	 // 1 string to match.
      return MCK__40_;	 // "("
    case ')':	 // 1 string to match.
      return MCK__41_;	 // ")"
    }
    break;
  case 2:	 // 4 strings to match.
    if (Name[0] != '.')
      break;
    switch (Name[1]) {
    default: break;
    case 'd':	 // 1 string to match.
      return MCK__DOT_d;	 // ".d"
    case 'l':	 // 1 string to match.
      return MCK__DOT_l;	 // ".l"
    case 's':	 // 1 string to match.
      return MCK__DOT_s;	 // ".s"
    case 'w':	 // 1 string to match.
      return MCK__DOT_w;	 // ".w"
    }
    break;
  case 4:	 // 4 strings to match.
    if (Name[0] != '.')
      break;
    switch (Name[1]) {
    default: break;
    case 'd':	 // 1 string to match.
      if (memcmp(Name.data()+2, ".t", 2) != 0)
        break;
      return MCK__DOT_d_DOT_t;	 // ".d.t"
    case 'l':	 // 1 string to match.
      if (memcmp(Name.data()+2, ".t", 2) != 0)
        break;
      return MCK__DOT_l_DOT_t;	 // ".l.t"
    case 's':	 // 1 string to match.
      if (memcmp(Name.data()+2, ".t", 2) != 0)
        break;
      return MCK__DOT_s_DOT_t;	 // ".s.t"
    case 'w':	 // 1 string to match.
      if (memcmp(Name.data()+2, ".t", 2) != 0)
        break;
      return MCK__DOT_w_DOT_t;	 // ".w.t"
    }
    break;
  case 5:	 // 4 strings to match.
    if (Name[0] != '.')
      break;
    switch (Name[1]) {
    default: break;
    case 'd':	 // 1 string to match.
      if (memcmp(Name.data()+2, ".nt", 3) != 0)
        break;
      return MCK__DOT_d_DOT_nt;	 // ".d.nt"
    case 'l':	 // 1 string to match.
      if (memcmp(Name.data()+2, ".nt", 3) != 0)
        break;
      return MCK__DOT_l_DOT_nt;	 // ".l.nt"
    case 's':	 // 1 string to match.
      if (memcmp(Name.data()+2, ".nt", 3) != 0)
        break;
      return MCK__DOT_s_DOT_nt;	 // ".s.nt"
    case 'w':	 // 1 string to match.
      if (memcmp(Name.data()+2, ".nt", 3) != 0)
        break;
      return MCK__DOT_w_DOT_nt;	 // ".w.nt"
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
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 18, 1},
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
  VEOperand &Operand = (VEOperand &)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  case MCK_CCOp: {
    DiagnosticPredicate DP(Operand.isCCOp());
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
  case MCK_MImm: {
    DiagnosticPredicate DP(Operand.isMImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_RDOp: {
    DiagnosticPredicate DP(Operand.isRDOp());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_SImm7: {
    DiagnosticPredicate DP(Operand.isSImm7());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_UImm0to2: {
    DiagnosticPredicate DP(Operand.isUImm0to2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_UImm1: {
    DiagnosticPredicate DP(Operand.isUImm1());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_UImm2: {
    DiagnosticPredicate DP(Operand.isUImm2());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_UImm3: {
    DiagnosticPredicate DP(Operand.isUImm3());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_UImm4: {
    DiagnosticPredicate DP(Operand.isUImm4());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_UImm6: {
    DiagnosticPredicate DP(Operand.isUImm6());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_UImm7: {
    DiagnosticPredicate DP(Operand.isUImm7());
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
  case MCK_MEMrii: {
    DiagnosticPredicate DP(Operand.isMEMrii());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MEMrri: {
    DiagnosticPredicate DP(Operand.isMEMrri());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MEMzi: {
    DiagnosticPredicate DP(Operand.isMEMzi());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MEMzii: {
    DiagnosticPredicate DP(Operand.isMEMzii());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_MEMzri: {
    DiagnosticPredicate DP(Operand.isMEMzri());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Zero: {
    DiagnosticPredicate DP(Operand.isZero());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg()) {
    static constexpr uint16_t Table[VE::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      InvalidMatchClass,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_V64,
      MCK_VLS,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_MISC,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F128,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_F32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I32,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_I64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_V64,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM,
      MCK_VM512,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
      MCK_Reg9,
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
  case MCK__DOT_d: return "MCK__DOT_d";
  case MCK__DOT_d_DOT_nt: return "MCK__DOT_d_DOT_nt";
  case MCK__DOT_d_DOT_t: return "MCK__DOT_d_DOT_t";
  case MCK__DOT_l: return "MCK__DOT_l";
  case MCK__DOT_l_DOT_nt: return "MCK__DOT_l_DOT_nt";
  case MCK__DOT_l_DOT_t: return "MCK__DOT_l_DOT_t";
  case MCK__DOT_s: return "MCK__DOT_s";
  case MCK__DOT_s_DOT_nt: return "MCK__DOT_s_DOT_nt";
  case MCK__DOT_s_DOT_t: return "MCK__DOT_s_DOT_t";
  case MCK__DOT_w: return "MCK__DOT_w";
  case MCK__DOT_w_DOT_nt: return "MCK__DOT_w_DOT_nt";
  case MCK__DOT_w_DOT_t: return "MCK__DOT_w_DOT_t";
  case MCK_VLS: return "MCK_VLS";
  case MCK_Reg9: return "MCK_Reg9";
  case MCK_VM512: return "MCK_VM512";
  case MCK_VM: return "MCK_VM";
  case MCK_MISC: return "MCK_MISC";
  case MCK_F128: return "MCK_F128";
  case MCK_F32: return "MCK_F32";
  case MCK_I32: return "MCK_I32";
  case MCK_I64: return "MCK_I64";
  case MCK_V64: return "MCK_V64";
  case MCK_CCOp: return "MCK_CCOp";
  case MCK_Imm: return "MCK_Imm";
  case MCK_MImm: return "MCK_MImm";
  case MCK_RDOp: return "MCK_RDOp";
  case MCK_SImm7: return "MCK_SImm7";
  case MCK_UImm0to2: return "MCK_UImm0to2";
  case MCK_UImm1: return "MCK_UImm1";
  case MCK_UImm2: return "MCK_UImm2";
  case MCK_UImm3: return "MCK_UImm3";
  case MCK_UImm4: return "MCK_UImm4";
  case MCK_UImm6: return "MCK_UImm6";
  case MCK_UImm7: return "MCK_UImm7";
  case MCK_MEMri: return "MCK_MEMri";
  case MCK_MEMrii: return "MCK_MEMrii";
  case MCK_MEMrri: return "MCK_MEMrri";
  case MCK_MEMzi: return "MCK_MEMzi";
  case MCK_MEMzii: return "MCK_MEMzii";
  case MCK_MEMzri: return "MCK_MEMzri";
  case MCK_Zero: return "MCK_Zero";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset VEAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  return Features;
}

static bool checkAsmTiedOperandConstraints(const VEAsmParser&AsmParser,
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
    "\006adds.l\tadds.w.sx\tadds.w.zx\006addu.l\006addu.w\003and\004andm\005"
    "atmam\001b\003b.d\006b.d.nt\005b.d.t\003b.l\006b.l.nt\005b.l.t\003b.s\006"
    "b.s.nt\005b.s.t\003b.w\006b.w.nt\005b.w.t\005baf.d\010baf.d.nt\007baf.d"
    ".t\005baf.l\010baf.l.nt\007baf.l.t\005baf.s\010baf.s.nt\007baf.s.t\005b"
    "af.w\010baf.w.nt\007baf.w.t\002br\004br.d\007br.d.nt\006br.d.t\004br.l\007"
    "br.l.nt\006br.l.t\004br.s\007br.s.nt\006br.s.t\004br.w\007br.w.nt\006br"
    ".w.t\006braf.d\tbraf.d.nt\010braf.d.t\006braf.l\tbraf.l.nt\010braf.l.t\006"
    "braf.s\tbraf.s.nt\010braf.s.t\006braf.w\tbraf.w.nt\010braf.w.t\003brv\004"
    "bsic\004bswp\005cas.l\005cas.w\007cmov.d.\007cmov.l.\007cmov.s.\007cmov"
    ".w.\006cmps.l\tcmps.w.sx\tcmps.w.zx\006cmpu.l\006cmpu.w\007cvt.d.l\007c"
    "vt.d.q\007cvt.d.s\007cvt.d.w\007cvt.l.d\007cvt.q.d\007cvt.q.s\007cvt.s."
    "d\007cvt.s.q\007cvt.s.w\ncvt.w.d.sx\ncvt.w.d.zx\ncvt.w.s.sx\ncvt.w.s.zx"
    "\006divs.l\tdivs.w.sx\tdivs.w.zx\006divu.l\006divu.w\003dld\007dldl.sx\007"
    "dldl.zx\004dldu\003eqv\004eqvm\006fadd.d\006fadd.q\006fadd.s\006fcmp.d\006"
    "fcmp.q\006fcmp.s\006fdiv.d\006fdiv.s\006fencec\006fencei\006fencem\005f"
    "idcr\006fmax.d\006fmax.s\006fmin.d\006fmin.s\006fmul.d\006fmul.q\006fmu"
    "l.s\006fsub.d\006fsub.q\006fsub.s\003lcr\002ld\007ld1b.sx\007ld1b.zx\007"
    "ld2b.sx\007ld2b.zx\006ldl.sx\006ldl.zx\003ldu\003ldz\003lea\006lea.sl\003"
    "lfr\005lhm.b\005lhm.h\005lhm.l\005lhm.w\003lpm\003lsv\004lvix\003lvl\003"
    "lvm\003lvs\004lzvm\006maxs.l\tmaxs.w.sx\tmaxs.w.zx\006mins.l\tmins.w.sx"
    "\tmins.w.zx\004monc\010monc.hdb\003mrg\006muls.l\010muls.l.w\tmuls.w.sx"
    "\tmuls.w.zx\006mulu.l\006mulu.w\004negm\003nnd\004nndm\003nop\002or\003"
    "orm\004pcnt\004pcvm\004pfch\005pfchv\010pfchv.nc\006pvadds\tpvadds.lo\t"
    "pvadds.up\006pvaddu\tpvaddu.lo\tpvaddu.up\005pvand\010pvand.lo\010pvand"
    ".up\005pvbrd\005pvbrv\010pvbrv.lo\010pvbrv.up\006pvcmps\tpvcmps.lo\tpvc"
    "mps.up\006pvcmpu\tpvcmpu.lo\tpvcmpu.up\tpvcvt.s.w\014pvcvt.s.w.lo\014pv"
    "cvt.s.w.up\tpvcvt.w.s\014pvcvt.w.s.lo\014pvcvt.w.s.up\005pveqv\010pveqv"
    ".lo\010pveqv.up\006pvfadd\tpvfadd.lo\tpvfadd.up\006pvfcmp\tpvfcmp.lo\tp"
    "vfcmp.up\006pvfmad\tpvfmad.lo\tpvfmad.up\006pvfmax\tpvfmax.lo\tpvfmax.u"
    "p\006pvfmin\tpvfmin.lo\tpvfmin.up\013pvfmk.s.lo.\015pvfmk.s.lo.af\015pv"
    "fmk.s.lo.at\013pvfmk.s.up.\015pvfmk.s.up.af\015pvfmk.s.up.at\013pvfmk.w"
    ".up.\015pvfmk.w.up.af\015pvfmk.w.up.at\006pvfmsb\tpvfmsb.lo\tpvfmsb.up\006"
    "pvfmul\tpvfmul.lo\tpvfmul.up\007pvfnmad\npvfnmad.lo\npvfnmad.up\007pvfn"
    "msb\npvfnmsb.lo\npvfnmsb.up\006pvfsub\tpvfsub.lo\tpvfsub.up\005pvldz\010"
    "pvldz.lo\010pvldz.up\006pvmaxs\tpvmaxs.lo\tpvmaxs.up\006pvmins\tpvmins."
    "lo\tpvmins.up\004pvor\007pvor.lo\007pvor.up\006pvpcnt\tpvpcnt.lo\tpvpcn"
    "t.up\005pvrcp\010pvrcp.lo\010pvrcp.up\007pvrsqrt\npvrsqrt.lo\016pvrsqrt"
    ".lo.nex\013pvrsqrt.nex\npvrsqrt.up\016pvrsqrt.up.nex\005pvseq\010pvseq."
    "lo\010pvseq.up\005pvsla\010pvsla.lo\010pvsla.up\005pvsll\010pvsll.lo\010"
    "pvsll.up\005pvsra\010pvsra.lo\010pvsra.up\005pvsrl\010pvsrl.lo\010pvsrl"
    ".up\006pvsubs\tpvsubs.lo\tpvsubs.up\006pvsubu\tpvsubu.lo\tpvsubu.up\005"
    "pvxor\010pvxor.lo\010pvxor.up\003scr\003sfr\005shm.b\005shm.h\005shm.l\005"
    "shm.w\003sic\005sla.l\010sla.w.sx\010sla.w.zx\003sld\003sll\004smir\004"
    "smvl\003spm\005sra.l\010sra.w.sx\010sra.w.zx\003srd\003srl\002st\004st1"
    "b\004st2b\003stl\003stu\006subs.l\tsubs.w.sx\tsubs.w.zx\006subu.l\006su"
    "bu.w\003svl\003svm\004svob\004tovm\007ts1am.l\007ts1am.w\005ts2am\005ts"
    "3am\004tscr\007vadds.l\nvadds.w.sx\007vaddu.l\004vand\004vbrd\005vbrdl\005"
    "vbrdu\004vbrv\007vcmps.l\nvcmps.w.sx\007vcmpu.l\003vcp\010vcvt.d.l\010v"
    "cvt.d.s\010vcvt.d.w\010vcvt.l.d\010vcvt.s.d\010vcvt.s.w\013vcvt.w.d.sx\013"
    "vcvt.w.d.zx\013vcvt.w.s.sx\013vcvt.w.s.zx\007vdivs.l\nvdivs.w.sx\nvdivs"
    ".w.zx\007vdivu.l\007vdivu.w\004veqv\003vex\007vfadd.d\007vfcmp.d\007vfd"
    "iv.d\007vfdiv.s\006vfia.d\006vfia.s\007vfiam.d\007vfiam.s\006vfim.d\006"
    "vfim.s\007vfima.d\007vfima.s\007vfims.d\007vfims.s\006vfis.d\006vfis.s\007"
    "vfism.d\007vfism.s\007vfmad.d\007vfmax.d\007vfmin.d\007vfmk.d.\tvfmk.d."
    "af\tvfmk.d.at\007vfmk.l.\tvfmk.l.af\tvfmk.l.at\007vfmk.w.\tvfmk.w.af\tv"
    "fmk.w.at\007vfmsb.d\007vfmul.d\010vfnmad.d\010vfnmsb.d\014vfrmax.d.fst\014"
    "vfrmax.d.lst\014vfrmax.s.fst\014vfrmax.s.lst\014vfrmin.d.fst\014vfrmin."
    "d.lst\014vfrmin.s.fst\014vfrmin.s.lst\010vfsqrt.d\010vfsqrt.s\007vfsub."
    "d\007vfsum.d\007vfsum.s\003vgt\006vgt.nc\007vgtl.sx\nvgtl.sx.nc\007vgtl"
    ".zx\nvgtl.zx.nc\004vgtu\007vgtu.nc\003vld\006vld.nc\005vld2d\010vld2d.n"
    "c\007vldl.sx\nvldl.sx.nc\007vldl.zx\nvldl.zx.nc\tvldl2d.sx\014vldl2d.sx"
    ".nc\tvldl2d.zx\014vldl2d.zx.nc\004vldu\007vldu.nc\006vldu2d\tvldu2d.nc\004"
    "vldz\007vmaxs.l\nvmaxs.w.sx\007vmins.l\nvmins.w.sx\004vmrg\006vmrg.w\007"
    "vmuls.l\tvmuls.l.w\nvmuls.w.sx\nvmuls.w.zx\007vmulu.l\007vmulu.w\003vmv"
    "\003vor\005vpcnt\005vrand\006vrcp.d\014vrmaxs.l.fst\014vrmaxs.l.lst\017"
    "vrmaxs.w.fst.sx\017vrmaxs.w.fst.zx\017vrmaxs.w.lst.sx\017vrmaxs.w.lst.z"
    "x\014vrmins.l.fst\014vrmins.l.lst\017vrmins.w.fst.sx\017vrmins.w.fst.zx"
    "\017vrmins.w.lst.sx\017vrmins.w.lst.zx\004vror\010vrsqrt.d\014vrsqrt.d."
    "nex\005vrxor\003vsc\006vsc.nc\tvsc.nc.ot\006vsc.ot\004vscl\007vscl.nc\n"
    "vscl.nc.ot\007vscl.ot\004vscu\007vscu.nc\nvscu.nc.ot\007vscu.ot\004vseq"
    "\004vsfa\004vshf\006vsla.l\tvsla.w.sx\004vsld\004vsll\006vsra.l\tvsra.w"
    ".sx\004vsrd\004vsrl\003vst\006vst.nc\tvst.nc.ot\006vst.ot\005vst2d\010v"
    "st2d.nc\013vst2d.nc.ot\010vst2d.ot\004vstl\007vstl.nc\nvstl.nc.ot\007vs"
    "tl.ot\006vstl2d\tvstl2d.nc\014vstl2d.nc.ot\tvstl2d.ot\004vstu\007vstu.n"
    "c\nvstu.nc.ot\007vstu.ot\006vstu2d\tvstu2d.nc\014vstu2d.nc.ot\tvstu2d.o"
    "t\007vsubs.l\nvsubs.w.sx\007vsubu.l\006vsum.l\tvsum.w.sx\tvsum.w.zx\004"
    "vxor\003xor\004xorm";

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
  { 0 /* adds.l */, VE::ADDSLrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 0 /* adds.l */, VE::ADDSLrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 0 /* adds.l */, VE::ADDSLri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 0 /* adds.l */, VE::ADDSLim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 7 /* adds.w.sx */, VE::ADDSWSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 7 /* adds.w.sx */, VE::ADDSWSXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 7 /* adds.w.sx */, VE::ADDSWSXri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 7 /* adds.w.sx */, VE::ADDSWSXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 17 /* adds.w.zx */, VE::ADDSWZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 17 /* adds.w.zx */, VE::ADDSWZXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 17 /* adds.w.zx */, VE::ADDSWZXri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 17 /* adds.w.zx */, VE::ADDSWZXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 27 /* addu.l */, VE::ADDULrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 27 /* addu.l */, VE::ADDULrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 27 /* addu.l */, VE::ADDULri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 27 /* addu.l */, VE::ADDULim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 34 /* addu.w */, VE::ADDUWrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 34 /* addu.w */, VE::ADDUWrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 34 /* addu.w */, VE::ADDUWri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 34 /* addu.w */, VE::ADDUWim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 41 /* and */, VE::ANDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 41 /* and */, VE::ANDrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 41 /* and */, VE::ANDri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 41 /* and */, VE::ANDim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 45 /* andm */, VE::ANDMmm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_VM, MCK_VM, MCK_VM }, },
  { 50 /* atmam */, VE::ATMAMrir, Convert__Reg1_0__MEMri2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_I64 }, },
  { 50 /* atmam */, VE::ATMAMrii, Convert__Reg1_0__MEMri2_1__UImm0to21_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_UImm0to2 }, },
  { 50 /* atmam */, VE::ATMAMzir, Convert__Reg1_0__MEMzi2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_I64 }, },
  { 50 /* atmam */, VE::ATMAMzii, Convert__Reg1_0__MEMzi2_1__UImm0to21_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_UImm0to2 }, },
  { 56 /* b */, VE::BCFDrri, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d, MCK_I64, MCK_MEMri }, },
  { 56 /* b */, VE::BCFDrzi, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d, MCK_I64, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFDiri, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFDizi, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFDrri_nt, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_nt, MCK_I64, MCK_MEMri }, },
  { 56 /* b */, VE::BCFDrzi_nt, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_nt, MCK_I64, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFDiri_nt, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_nt, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFDizi_nt, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_nt, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFDrri_t, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_t, MCK_I64, MCK_MEMri }, },
  { 56 /* b */, VE::BCFDrzi_t, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_t, MCK_I64, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFDiri_t, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_t, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFDizi_t, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_t, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFLrri, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l, MCK_I64, MCK_MEMri }, },
  { 56 /* b */, VE::BCFLrzi, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l, MCK_I64, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFLiri, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFLizi, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFLrri_nt, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_nt, MCK_I64, MCK_MEMri }, },
  { 56 /* b */, VE::BCFLrzi_nt, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_nt, MCK_I64, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFLiri_nt, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_nt, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFLizi_nt, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_nt, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFLrri_t, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_t, MCK_I64, MCK_MEMri }, },
  { 56 /* b */, VE::BCFLrzi_t, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_t, MCK_I64, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFLiri_t, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_t, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFLizi_t, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_t, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFSrri, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s, MCK_F32, MCK_MEMri }, },
  { 56 /* b */, VE::BCFSrzi, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s, MCK_F32, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFSiri, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFSizi, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFSrri_nt, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_nt, MCK_F32, MCK_MEMri }, },
  { 56 /* b */, VE::BCFSrzi_nt, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_nt, MCK_F32, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFSiri_nt, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_nt, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFSizi_nt, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_nt, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFSrri_t, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_t, MCK_F32, MCK_MEMri }, },
  { 56 /* b */, VE::BCFSrzi_t, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_t, MCK_F32, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFSiri_t, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_t, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFSizi_t, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_t, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFWrri, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w, MCK_I32, MCK_MEMri }, },
  { 56 /* b */, VE::BCFWrzi, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w, MCK_I32, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFWiri, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFWizi, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFWrri_nt, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_nt, MCK_I32, MCK_MEMri }, },
  { 56 /* b */, VE::BCFWrzi_nt, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_nt, MCK_I32, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFWiri_nt, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_nt, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFWizi_nt, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_nt, MCK_SImm7, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFWrri_t, Convert__CCOp1_0__Reg1_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_t, MCK_I32, MCK_MEMri }, },
  { 56 /* b */, VE::BCFWrzi_t, Convert__CCOp1_0__Reg1_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_t, MCK_I32, MCK_MEMzi }, },
  { 56 /* b */, VE::BCFWiri_t, Convert__CCOp1_0__SImm71_2__MEMri2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_t, MCK_SImm7, MCK_MEMri }, },
  { 56 /* b */, VE::BCFWizi_t, Convert__CCOp1_0__SImm71_2__MEMzi2_3, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_t, MCK_SImm7, MCK_MEMzi }, },
  { 58 /* b.d */, VE::BCFDari, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 58 /* b.d */, VE::BCFDazi, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 62 /* b.d.nt */, VE::BCFDari_nt, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 62 /* b.d.nt */, VE::BCFDazi_nt, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 69 /* b.d.t */, VE::BCFDari_t, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 69 /* b.d.t */, VE::BCFDazi_t, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 75 /* b.l */, VE::BCFLari, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 75 /* b.l */, VE::BCFLazi, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 79 /* b.l.nt */, VE::BCFLari_nt, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 79 /* b.l.nt */, VE::BCFLazi_nt, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 86 /* b.l.t */, VE::BCFLari_t, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 86 /* b.l.t */, VE::BCFLazi_t, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 92 /* b.s */, VE::BCFSari, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 92 /* b.s */, VE::BCFSazi, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 96 /* b.s.nt */, VE::BCFSari_nt, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 96 /* b.s.nt */, VE::BCFSazi_nt, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 103 /* b.s.t */, VE::BCFSari_t, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 103 /* b.s.t */, VE::BCFSazi_t, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 109 /* b.w */, VE::BCFWari, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 109 /* b.w */, VE::BCFWazi, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 113 /* b.w.nt */, VE::BCFWari_nt, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 113 /* b.w.nt */, VE::BCFWazi_nt, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 120 /* b.w.t */, VE::BCFWari_t, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 120 /* b.w.t */, VE::BCFWazi_t, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 126 /* baf.d */, VE::BCFDnari, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 126 /* baf.d */, VE::BCFDnazi, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 132 /* baf.d.nt */, VE::BCFDnari_nt, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 132 /* baf.d.nt */, VE::BCFDnazi_nt, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 141 /* baf.d.t */, VE::BCFDnari_t, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 141 /* baf.d.t */, VE::BCFDnazi_t, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 149 /* baf.l */, VE::BCFLnari, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 149 /* baf.l */, VE::BCFLnazi, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 155 /* baf.l.nt */, VE::BCFLnari_nt, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 155 /* baf.l.nt */, VE::BCFLnazi_nt, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 164 /* baf.l.t */, VE::BCFLnari_t, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 164 /* baf.l.t */, VE::BCFLnazi_t, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 172 /* baf.s */, VE::BCFSnari, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 172 /* baf.s */, VE::BCFSnazi, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 178 /* baf.s.nt */, VE::BCFSnari_nt, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 178 /* baf.s.nt */, VE::BCFSnazi_nt, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 187 /* baf.s.t */, VE::BCFSnari_t, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 187 /* baf.s.t */, VE::BCFSnazi_t, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 195 /* baf.w */, VE::BCFWnari, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 195 /* baf.w */, VE::BCFWnazi, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 201 /* baf.w.nt */, VE::BCFWnari_nt, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 201 /* baf.w.nt */, VE::BCFWnazi_nt, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 210 /* baf.w.t */, VE::BCFWnari_t, Convert__MEMri2_0, AMFBS_None, { MCK_MEMri }, },
  { 210 /* baf.w.t */, VE::BCFWnazi_t, Convert__MEMzi2_0, AMFBS_None, { MCK_MEMzi }, },
  { 218 /* br */, VE::BRCFDrr, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d, MCK_I64, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDrz, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d, MCK_I64, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDir, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d, MCK_SImm7, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDiz, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDrr_nt, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_nt, MCK_I64, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDrz_nt, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_nt, MCK_I64, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDir_nt, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_nt, MCK_SImm7, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDiz_nt, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_nt, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDrr_t, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_t, MCK_I64, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDrz_t, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_t, MCK_I64, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDir_t, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_t, MCK_SImm7, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFDiz_t, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_d_DOT_t, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLrr, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l, MCK_I64, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLrz, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l, MCK_I64, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLir, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l, MCK_SImm7, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLiz, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLrr_nt, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_nt, MCK_I64, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLrz_nt, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_nt, MCK_I64, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLir_nt, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_nt, MCK_SImm7, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLiz_nt, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_nt, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLrr_t, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_t, MCK_I64, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLrz_t, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_t, MCK_I64, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLir_t, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_t, MCK_SImm7, MCK_I64, MCK_Imm }, },
  { 218 /* br */, VE::BRCFLiz_t, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_l_DOT_t, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSrr, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s, MCK_F32, MCK_F32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSrz, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s, MCK_F32, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSir, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s, MCK_SImm7, MCK_F32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSiz, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSrr_nt, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_nt, MCK_F32, MCK_F32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSrz_nt, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_nt, MCK_F32, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSir_nt, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_nt, MCK_SImm7, MCK_F32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSiz_nt, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_nt, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSrr_t, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_t, MCK_F32, MCK_F32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSrz_t, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_t, MCK_F32, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSir_t, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_t, MCK_SImm7, MCK_F32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFSiz_t, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_s_DOT_t, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWrr, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w, MCK_I32, MCK_I32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWrz, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w, MCK_I32, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWir, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w, MCK_SImm7, MCK_I32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWiz, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWrr_nt, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_nt, MCK_I32, MCK_I32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWrz_nt, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_nt, MCK_I32, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWir_nt, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_nt, MCK_SImm7, MCK_I32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWiz_nt, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_nt, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWrr_t, Convert__CCOp1_0__Reg1_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_t, MCK_I32, MCK_I32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWrz_t, Convert__CCOp1_0__Reg1_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_t, MCK_I32, MCK_Zero, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWir_t, Convert__CCOp1_0__SImm71_2__Reg1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_t, MCK_SImm7, MCK_I32, MCK_Imm }, },
  { 218 /* br */, VE::BRCFWiz_t, Convert__CCOp1_0__SImm71_2__Zero1_3__Imm1_4, AMFBS_None, { MCK_CCOp, MCK__DOT_w_DOT_t, MCK_SImm7, MCK_Zero, MCK_Imm }, },
  { 221 /* br.d */, VE::BRCFDa, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 226 /* br.d.nt */, VE::BRCFDa_nt, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 234 /* br.d.t */, VE::BRCFDa_t, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 241 /* br.l */, VE::BRCFLa, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 246 /* br.l.nt */, VE::BRCFLa_nt, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 254 /* br.l.t */, VE::BRCFLa_t, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 261 /* br.s */, VE::BRCFSa, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 266 /* br.s.nt */, VE::BRCFSa_nt, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 274 /* br.s.t */, VE::BRCFSa_t, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 281 /* br.w */, VE::BRCFWa, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 286 /* br.w.nt */, VE::BRCFWa_nt, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 294 /* br.w.t */, VE::BRCFWa_t, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 301 /* braf.d */, VE::BRCFDna, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 308 /* braf.d.nt */, VE::BRCFDna_nt, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 318 /* braf.d.t */, VE::BRCFDna_t, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 327 /* braf.l */, VE::BRCFLna, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 334 /* braf.l.nt */, VE::BRCFLna_nt, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 344 /* braf.l.t */, VE::BRCFLna_t, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 353 /* braf.s */, VE::BRCFSna, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 360 /* braf.s.nt */, VE::BRCFSna_nt, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 370 /* braf.s.t */, VE::BRCFSna_t, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 379 /* braf.w */, VE::BRCFWna, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 386 /* braf.w.nt */, VE::BRCFWna_nt, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 396 /* braf.w.t */, VE::BRCFWna_t, Convert__Imm1_0, AMFBS_None, { MCK_Imm }, },
  { 405 /* brv */, VE::BRVr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_I64 }, },
  { 405 /* brv */, VE::BRVm, Convert__Reg1_0__MImm1_1, AMFBS_None, { MCK_I64, MCK_MImm }, },
  { 409 /* bsic */, VE::BSICrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I64, MCK_MEMrii }, },
  { 409 /* bsic */, VE::BSICrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I64, MCK_MEMrri }, },
  { 409 /* bsic */, VE::BSICzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I64, MCK_MEMzii }, },
  { 409 /* bsic */, VE::BSICzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I64, MCK_MEMzri }, },
  { 414 /* bswp */, VE::BSWPri, Convert__Reg1_0__Reg1_1__UImm11_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_UImm1 }, },
  { 414 /* bswp */, VE::BSWPmi, Convert__Reg1_0__MImm1_1__UImm11_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_UImm1 }, },
  { 419 /* cas.l */, VE::CASLrir, Convert__Reg1_0__MEMri2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_I64 }, },
  { 419 /* cas.l */, VE::CASLrii, Convert__Reg1_0__MEMri2_1__SImm71_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_SImm7 }, },
  { 419 /* cas.l */, VE::CASLzir, Convert__Reg1_0__MEMzi2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_I64 }, },
  { 419 /* cas.l */, VE::CASLzii, Convert__Reg1_0__MEMzi2_1__SImm71_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_SImm7 }, },
  { 425 /* cas.w */, VE::CASWrir, Convert__Reg1_0__MEMri2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I32, MCK_MEMri, MCK_I32 }, },
  { 425 /* cas.w */, VE::CASWrii, Convert__Reg1_0__MEMri2_1__SImm71_2__Tie0_1_1, AMFBS_None, { MCK_I32, MCK_MEMri, MCK_SImm7 }, },
  { 425 /* cas.w */, VE::CASWzir, Convert__Reg1_0__MEMzi2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I32, MCK_MEMzi, MCK_I32 }, },
  { 425 /* cas.w */, VE::CASWzii, Convert__Reg1_0__MEMzi2_1__SImm71_2__Tie0_1_1, AMFBS_None, { MCK_I32, MCK_MEMzi, MCK_SImm7 }, },
  { 431 /* cmov.d. */, VE::CMOVDrr, Convert__Reg1_1__CCOp1_0__Reg1_3__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_I64, MCK_I64 }, },
  { 431 /* cmov.d. */, VE::CMOVDir, Convert__Reg1_1__CCOp1_0__SImm71_3__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_I64, MCK_SImm7 }, },
  { 431 /* cmov.d. */, VE::CMOVDrm, Convert__Reg1_1__CCOp1_0__Reg1_3__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_MImm, MCK_I64 }, },
  { 431 /* cmov.d. */, VE::CMOVDim, Convert__Reg1_1__CCOp1_0__SImm71_3__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_MImm, MCK_SImm7 }, },
  { 439 /* cmov.l. */, VE::CMOVLrr, Convert__Reg1_1__CCOp1_0__Reg1_3__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_I64, MCK_I64 }, },
  { 439 /* cmov.l. */, VE::CMOVLir, Convert__Reg1_1__CCOp1_0__SImm71_3__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_I64, MCK_SImm7 }, },
  { 439 /* cmov.l. */, VE::CMOVLrm, Convert__Reg1_1__CCOp1_0__Reg1_3__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_MImm, MCK_I64 }, },
  { 439 /* cmov.l. */, VE::CMOVLim, Convert__Reg1_1__CCOp1_0__SImm71_3__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_MImm, MCK_SImm7 }, },
  { 447 /* cmov.s. */, VE::CMOVSrr, Convert__Reg1_1__CCOp1_0__Reg1_3__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_I64, MCK_F32 }, },
  { 447 /* cmov.s. */, VE::CMOVSir, Convert__Reg1_1__CCOp1_0__SImm71_3__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_I64, MCK_SImm7 }, },
  { 447 /* cmov.s. */, VE::CMOVSrm, Convert__Reg1_1__CCOp1_0__Reg1_3__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_MImm, MCK_F32 }, },
  { 447 /* cmov.s. */, VE::CMOVSim, Convert__Reg1_1__CCOp1_0__SImm71_3__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_MImm, MCK_SImm7 }, },
  { 455 /* cmov.w. */, VE::CMOVWrr, Convert__Reg1_1__CCOp1_0__Reg1_3__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_I64, MCK_I32 }, },
  { 455 /* cmov.w. */, VE::CMOVWir, Convert__Reg1_1__CCOp1_0__SImm71_3__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_I64, MCK_SImm7 }, },
  { 455 /* cmov.w. */, VE::CMOVWrm, Convert__Reg1_1__CCOp1_0__Reg1_3__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_MImm, MCK_I32 }, },
  { 455 /* cmov.w. */, VE::CMOVWim, Convert__Reg1_1__CCOp1_0__SImm71_3__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_CCOp, MCK_I64, MCK_MImm, MCK_SImm7 }, },
  { 463 /* cmps.l */, VE::CMPSLrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 463 /* cmps.l */, VE::CMPSLrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 463 /* cmps.l */, VE::CMPSLir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 463 /* cmps.l */, VE::CMPSLim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 470 /* cmps.w.sx */, VE::CMPSWSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 470 /* cmps.w.sx */, VE::CMPSWSXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 470 /* cmps.w.sx */, VE::CMPSWSXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 470 /* cmps.w.sx */, VE::CMPSWSXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 480 /* cmps.w.zx */, VE::CMPSWZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 480 /* cmps.w.zx */, VE::CMPSWZXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 480 /* cmps.w.zx */, VE::CMPSWZXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 480 /* cmps.w.zx */, VE::CMPSWZXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 490 /* cmpu.l */, VE::CMPULrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 490 /* cmpu.l */, VE::CMPULrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 490 /* cmpu.l */, VE::CMPULir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 490 /* cmpu.l */, VE::CMPULim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 497 /* cmpu.w */, VE::CMPUWrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 497 /* cmpu.w */, VE::CMPUWrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 497 /* cmpu.w */, VE::CMPUWir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 497 /* cmpu.w */, VE::CMPUWim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 504 /* cvt.d.l */, VE::CVTDLr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_I64 }, },
  { 504 /* cvt.d.l */, VE::CVTDLi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7 }, },
  { 512 /* cvt.d.q */, VE::CVTDQr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_F128 }, },
  { 512 /* cvt.d.q */, VE::CVTDQi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7 }, },
  { 520 /* cvt.d.s */, VE::CVTDSr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_F32 }, },
  { 520 /* cvt.d.s */, VE::CVTDSi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7 }, },
  { 528 /* cvt.d.w */, VE::CVTDWr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_I32 }, },
  { 528 /* cvt.d.w */, VE::CVTDWi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7 }, },
  { 536 /* cvt.l.d */, VE::CVTLDr, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_I64, MCK_I64 }, },
  { 536 /* cvt.l.d */, VE::CVTLDi, Convert__Reg1_1__RDOp1_0__SImm71_2, AMFBS_None, { MCK_RDOp, MCK_I64, MCK_SImm7 }, },
  { 544 /* cvt.q.d */, VE::CVTQDr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_F128, MCK_I64 }, },
  { 544 /* cvt.q.d */, VE::CVTQDi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_F128, MCK_SImm7 }, },
  { 552 /* cvt.q.s */, VE::CVTQSr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_F128, MCK_F32 }, },
  { 552 /* cvt.q.s */, VE::CVTQSi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_F128, MCK_SImm7 }, },
  { 560 /* cvt.s.d */, VE::CVTSDr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_F32, MCK_I64 }, },
  { 560 /* cvt.s.d */, VE::CVTSDi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_F32, MCK_SImm7 }, },
  { 568 /* cvt.s.q */, VE::CVTSQr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_F32, MCK_F128 }, },
  { 568 /* cvt.s.q */, VE::CVTSQi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_F32, MCK_SImm7 }, },
  { 576 /* cvt.s.w */, VE::CVTSWr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_F32, MCK_I32 }, },
  { 576 /* cvt.s.w */, VE::CVTSWi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_F32, MCK_SImm7 }, },
  { 584 /* cvt.w.d.sx */, VE::CVTWDSXr, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_I32, MCK_I64 }, },
  { 584 /* cvt.w.d.sx */, VE::CVTWDSXi, Convert__Reg1_1__RDOp1_0__SImm71_2, AMFBS_None, { MCK_RDOp, MCK_I32, MCK_SImm7 }, },
  { 595 /* cvt.w.d.zx */, VE::CVTWDZXr, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_I32, MCK_I64 }, },
  { 595 /* cvt.w.d.zx */, VE::CVTWDZXi, Convert__Reg1_1__RDOp1_0__SImm71_2, AMFBS_None, { MCK_RDOp, MCK_I32, MCK_SImm7 }, },
  { 606 /* cvt.w.s.sx */, VE::CVTWSSXr, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_I32, MCK_F32 }, },
  { 606 /* cvt.w.s.sx */, VE::CVTWSSXi, Convert__Reg1_1__RDOp1_0__SImm71_2, AMFBS_None, { MCK_RDOp, MCK_I32, MCK_SImm7 }, },
  { 617 /* cvt.w.s.zx */, VE::CVTWSZXr, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_I32, MCK_F32 }, },
  { 617 /* cvt.w.s.zx */, VE::CVTWSZXi, Convert__Reg1_1__RDOp1_0__SImm71_2, AMFBS_None, { MCK_RDOp, MCK_I32, MCK_SImm7 }, },
  { 628 /* divs.l */, VE::DIVSLrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 628 /* divs.l */, VE::DIVSLrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 628 /* divs.l */, VE::DIVSLir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 628 /* divs.l */, VE::DIVSLim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 635 /* divs.w.sx */, VE::DIVSWSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 635 /* divs.w.sx */, VE::DIVSWSXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 635 /* divs.w.sx */, VE::DIVSWSXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 635 /* divs.w.sx */, VE::DIVSWSXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 645 /* divs.w.zx */, VE::DIVSWZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 645 /* divs.w.zx */, VE::DIVSWZXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 645 /* divs.w.zx */, VE::DIVSWZXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 645 /* divs.w.zx */, VE::DIVSWZXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 655 /* divu.l */, VE::DIVULrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 655 /* divu.l */, VE::DIVULrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 655 /* divu.l */, VE::DIVULir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 655 /* divu.l */, VE::DIVULim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 662 /* divu.w */, VE::DIVUWrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 662 /* divu.w */, VE::DIVUWrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 662 /* divu.w */, VE::DIVUWir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 662 /* divu.w */, VE::DIVUWim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 669 /* dld */, VE::DLDrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I64, MCK_MEMrii }, },
  { 669 /* dld */, VE::DLDrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I64, MCK_MEMrri }, },
  { 669 /* dld */, VE::DLDzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I64, MCK_MEMzii }, },
  { 669 /* dld */, VE::DLDzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I64, MCK_MEMzri }, },
  { 673 /* dldl.sx */, VE::DLDLSXrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 673 /* dldl.sx */, VE::DLDLSXrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 673 /* dldl.sx */, VE::DLDLSXzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 673 /* dldl.sx */, VE::DLDLSXzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 681 /* dldl.zx */, VE::DLDLZXrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 681 /* dldl.zx */, VE::DLDLZXrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 681 /* dldl.zx */, VE::DLDLZXzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 681 /* dldl.zx */, VE::DLDLZXzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 689 /* dldu */, VE::DLDUrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_F32, MCK_MEMrii }, },
  { 689 /* dldu */, VE::DLDUrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_F32, MCK_MEMrri }, },
  { 689 /* dldu */, VE::DLDUzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_F32, MCK_MEMzii }, },
  { 689 /* dldu */, VE::DLDUzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_F32, MCK_MEMzri }, },
  { 694 /* eqv */, VE::EQVrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 694 /* eqv */, VE::EQVrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 694 /* eqv */, VE::EQVri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 694 /* eqv */, VE::EQVim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 698 /* eqvm */, VE::EQVMmm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_VM, MCK_VM, MCK_VM }, },
  { 703 /* fadd.d */, VE::FADDDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 703 /* fadd.d */, VE::FADDDrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 703 /* fadd.d */, VE::FADDDir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 703 /* fadd.d */, VE::FADDDim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 710 /* fadd.q */, VE::FADDQrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F128, MCK_F128, MCK_F128 }, },
  { 710 /* fadd.q */, VE::FADDQrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F128, MCK_F128, MCK_MImm }, },
  { 710 /* fadd.q */, VE::FADDQir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F128, MCK_SImm7, MCK_F128 }, },
  { 710 /* fadd.q */, VE::FADDQim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F128, MCK_SImm7, MCK_MImm }, },
  { 717 /* fadd.s */, VE::FADDSrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_F32 }, },
  { 717 /* fadd.s */, VE::FADDSrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_MImm }, },
  { 717 /* fadd.s */, VE::FADDSir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_F32 }, },
  { 717 /* fadd.s */, VE::FADDSim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_MImm }, },
  { 724 /* fcmp.d */, VE::FCMPDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 724 /* fcmp.d */, VE::FCMPDrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 724 /* fcmp.d */, VE::FCMPDir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 724 /* fcmp.d */, VE::FCMPDim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 731 /* fcmp.q */, VE::FCMPQrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_F128, MCK_F128 }, },
  { 731 /* fcmp.q */, VE::FCMPQrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_F128, MCK_MImm }, },
  { 731 /* fcmp.q */, VE::FCMPQir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_F128 }, },
  { 731 /* fcmp.q */, VE::FCMPQim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 738 /* fcmp.s */, VE::FCMPSrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_F32 }, },
  { 738 /* fcmp.s */, VE::FCMPSrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_MImm }, },
  { 738 /* fcmp.s */, VE::FCMPSir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_F32 }, },
  { 738 /* fcmp.s */, VE::FCMPSim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_MImm }, },
  { 745 /* fdiv.d */, VE::FDIVDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 745 /* fdiv.d */, VE::FDIVDrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 745 /* fdiv.d */, VE::FDIVDir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 745 /* fdiv.d */, VE::FDIVDim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 752 /* fdiv.s */, VE::FDIVSrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_F32 }, },
  { 752 /* fdiv.s */, VE::FDIVSrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_MImm }, },
  { 752 /* fdiv.s */, VE::FDIVSir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_F32 }, },
  { 752 /* fdiv.s */, VE::FDIVSim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_MImm }, },
  { 759 /* fencec */, VE::FENCEC, Convert__UImm31_0, AMFBS_None, { MCK_UImm3 }, },
  { 766 /* fencei */, VE::FENCEI, Convert_NoOperands, AMFBS_None, {  }, },
  { 773 /* fencem */, VE::FENCEM, Convert__UImm21_0, AMFBS_None, { MCK_UImm2 }, },
  { 780 /* fidcr */, VE::FIDCRri, Convert__Reg1_0__Reg1_1__UImm31_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_UImm3 }, },
  { 780 /* fidcr */, VE::FIDCRii, Convert__Reg1_0__SImm71_1__UImm31_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_UImm3 }, },
  { 786 /* fmax.d */, VE::FMAXDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 786 /* fmax.d */, VE::FMAXDrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 786 /* fmax.d */, VE::FMAXDir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 786 /* fmax.d */, VE::FMAXDim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 793 /* fmax.s */, VE::FMAXSrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_F32 }, },
  { 793 /* fmax.s */, VE::FMAXSrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_MImm }, },
  { 793 /* fmax.s */, VE::FMAXSir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_F32 }, },
  { 793 /* fmax.s */, VE::FMAXSim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_MImm }, },
  { 800 /* fmin.d */, VE::FMINDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 800 /* fmin.d */, VE::FMINDrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 800 /* fmin.d */, VE::FMINDir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 800 /* fmin.d */, VE::FMINDim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 807 /* fmin.s */, VE::FMINSrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_F32 }, },
  { 807 /* fmin.s */, VE::FMINSrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_MImm }, },
  { 807 /* fmin.s */, VE::FMINSir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_F32 }, },
  { 807 /* fmin.s */, VE::FMINSim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_MImm }, },
  { 814 /* fmul.d */, VE::FMULDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 814 /* fmul.d */, VE::FMULDrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 814 /* fmul.d */, VE::FMULDir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 814 /* fmul.d */, VE::FMULDim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 821 /* fmul.q */, VE::FMULQrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F128, MCK_F128, MCK_F128 }, },
  { 821 /* fmul.q */, VE::FMULQrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F128, MCK_F128, MCK_MImm }, },
  { 821 /* fmul.q */, VE::FMULQir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F128, MCK_SImm7, MCK_F128 }, },
  { 821 /* fmul.q */, VE::FMULQim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F128, MCK_SImm7, MCK_MImm }, },
  { 828 /* fmul.s */, VE::FMULSrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_F32 }, },
  { 828 /* fmul.s */, VE::FMULSrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_MImm }, },
  { 828 /* fmul.s */, VE::FMULSir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_F32 }, },
  { 828 /* fmul.s */, VE::FMULSim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_MImm }, },
  { 835 /* fsub.d */, VE::FSUBDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 835 /* fsub.d */, VE::FSUBDrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 835 /* fsub.d */, VE::FSUBDir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 835 /* fsub.d */, VE::FSUBDim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 842 /* fsub.q */, VE::FSUBQrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F128, MCK_F128, MCK_F128 }, },
  { 842 /* fsub.q */, VE::FSUBQrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F128, MCK_F128, MCK_MImm }, },
  { 842 /* fsub.q */, VE::FSUBQir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F128, MCK_SImm7, MCK_F128 }, },
  { 842 /* fsub.q */, VE::FSUBQim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F128, MCK_SImm7, MCK_MImm }, },
  { 849 /* fsub.s */, VE::FSUBSrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_F32 }, },
  { 849 /* fsub.s */, VE::FSUBSrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_F32, MCK_MImm }, },
  { 849 /* fsub.s */, VE::FSUBSir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_F32 }, },
  { 849 /* fsub.s */, VE::FSUBSim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_F32, MCK_SImm7, MCK_MImm }, },
  { 856 /* lcr */, VE::LCRrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 856 /* lcr */, VE::LCRrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_Zero }, },
  { 856 /* lcr */, VE::LCRir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 856 /* lcr */, VE::LCRiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 860 /* ld */, VE::LDrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I64, MCK_MEMrii }, },
  { 860 /* ld */, VE::LDrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I64, MCK_MEMrri }, },
  { 860 /* ld */, VE::LDzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I64, MCK_MEMzii }, },
  { 860 /* ld */, VE::LDzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I64, MCK_MEMzri }, },
  { 863 /* ld1b.sx */, VE::LD1BSXrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 863 /* ld1b.sx */, VE::LD1BSXrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 863 /* ld1b.sx */, VE::LD1BSXzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 863 /* ld1b.sx */, VE::LD1BSXzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 871 /* ld1b.zx */, VE::LD1BZXrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 871 /* ld1b.zx */, VE::LD1BZXrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 871 /* ld1b.zx */, VE::LD1BZXzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 871 /* ld1b.zx */, VE::LD1BZXzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 879 /* ld2b.sx */, VE::LD2BSXrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 879 /* ld2b.sx */, VE::LD2BSXrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 879 /* ld2b.sx */, VE::LD2BSXzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 879 /* ld2b.sx */, VE::LD2BSXzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 887 /* ld2b.zx */, VE::LD2BZXrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 887 /* ld2b.zx */, VE::LD2BZXrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 887 /* ld2b.zx */, VE::LD2BZXzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 887 /* ld2b.zx */, VE::LD2BZXzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 895 /* ldl.sx */, VE::LDLSXrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 895 /* ldl.sx */, VE::LDLSXrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 895 /* ldl.sx */, VE::LDLSXzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 895 /* ldl.sx */, VE::LDLSXzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 902 /* ldl.zx */, VE::LDLZXrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 902 /* ldl.zx */, VE::LDLZXrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 902 /* ldl.zx */, VE::LDLZXzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 902 /* ldl.zx */, VE::LDLZXzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 909 /* ldu */, VE::LDUrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_F32, MCK_MEMrii }, },
  { 909 /* ldu */, VE::LDUrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_F32, MCK_MEMrri }, },
  { 909 /* ldu */, VE::LDUzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_F32, MCK_MEMzii }, },
  { 909 /* ldu */, VE::LDUzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_F32, MCK_MEMzri }, },
  { 913 /* ldz */, VE::LDZr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_I64 }, },
  { 913 /* ldz */, VE::LDZm, Convert__Reg1_0__MImm1_1, AMFBS_None, { MCK_I64, MCK_MImm }, },
  { 917 /* lea */, VE::LEArii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I64, MCK_MEMrii }, },
  { 917 /* lea */, VE::LEArri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I64, MCK_MEMrri }, },
  { 917 /* lea */, VE::LEAzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I64, MCK_MEMzii }, },
  { 917 /* lea */, VE::LEAzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I64, MCK_MEMzri }, },
  { 921 /* lea.sl */, VE::LEASLrii, Convert__Reg1_0__MEMrii3_1, AMFBS_None, { MCK_I64, MCK_MEMrii }, },
  { 921 /* lea.sl */, VE::LEASLrri, Convert__Reg1_0__MEMrri3_1, AMFBS_None, { MCK_I64, MCK_MEMrri }, },
  { 921 /* lea.sl */, VE::LEASLzii, Convert__Reg1_0__MEMzii3_1, AMFBS_None, { MCK_I64, MCK_MEMzii }, },
  { 921 /* lea.sl */, VE::LEASLzri, Convert__Reg1_0__MEMzri3_1, AMFBS_None, { MCK_I64, MCK_MEMzri }, },
  { 928 /* lfr */, VE::LFRr, Convert__Reg1_0, AMFBS_None, { MCK_I64 }, },
  { 928 /* lfr */, VE::LFRi, Convert__UImm61_0, AMFBS_None, { MCK_UImm6 }, },
  { 932 /* lhm.b */, VE::LHMBri, Convert__Reg1_0__MEMri2_1, AMFBS_None, { MCK_I64, MCK_MEMri }, },
  { 932 /* lhm.b */, VE::LHMBzi, Convert__Reg1_0__MEMzi2_1, AMFBS_None, { MCK_I64, MCK_MEMzi }, },
  { 938 /* lhm.h */, VE::LHMHri, Convert__Reg1_0__MEMri2_1, AMFBS_None, { MCK_I64, MCK_MEMri }, },
  { 938 /* lhm.h */, VE::LHMHzi, Convert__Reg1_0__MEMzi2_1, AMFBS_None, { MCK_I64, MCK_MEMzi }, },
  { 944 /* lhm.l */, VE::LHMLri, Convert__Reg1_0__MEMri2_1, AMFBS_None, { MCK_I64, MCK_MEMri }, },
  { 944 /* lhm.l */, VE::LHMLzi, Convert__Reg1_0__MEMzi2_1, AMFBS_None, { MCK_I64, MCK_MEMzi }, },
  { 950 /* lhm.w */, VE::LHMWri, Convert__Reg1_0__MEMri2_1, AMFBS_None, { MCK_I64, MCK_MEMri }, },
  { 950 /* lhm.w */, VE::LHMWzi, Convert__Reg1_0__MEMzi2_1, AMFBS_None, { MCK_I64, MCK_MEMzi }, },
  { 956 /* lpm */, VE::LPM, Convert__Reg1_0, AMFBS_None, { MCK_I64 }, },
  { 960 /* lsv */, VE::LSVrr, Convert__Reg1_0__Reg1_2__Reg1_4, AMFBS_None, { MCK_V64, MCK__40_, MCK_I64, MCK__41_, MCK_I64 }, },
  { 960 /* lsv */, VE::LSVrm, Convert__Reg1_0__Reg1_2__MImm1_4, AMFBS_None, { MCK_V64, MCK__40_, MCK_I64, MCK__41_, MCK_MImm }, },
  { 960 /* lsv */, VE::LSVir, Convert__Reg1_0__UImm71_2__Reg1_4, AMFBS_None, { MCK_V64, MCK__40_, MCK_UImm7, MCK__41_, MCK_I64 }, },
  { 960 /* lsv */, VE::LSVim, Convert__Reg1_0__UImm71_2__MImm1_4, AMFBS_None, { MCK_V64, MCK__40_, MCK_UImm7, MCK__41_, MCK_MImm }, },
  { 964 /* lvix */, VE::LVIXr, Convert__Reg1_0, AMFBS_None, { MCK_I64 }, },
  { 964 /* lvix */, VE::LVIXi, Convert__UImm61_0, AMFBS_None, { MCK_UImm6 }, },
  { 969 /* lvl */, VE::LVLr, Convert__Reg1_0, AMFBS_None, { MCK_I64 }, },
  { 969 /* lvl */, VE::LVLi, Convert__SImm71_0, AMFBS_None, { MCK_SImm7 }, },
  { 973 /* lvm */, VE::LVMrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_VM, MCK_I64, MCK_I64 }, },
  { 973 /* lvm */, VE::LVMrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_VM, MCK_I64, MCK_MImm }, },
  { 973 /* lvm */, VE::LVMir, Convert__Reg1_0__UImm21_1__Reg1_2, AMFBS_None, { MCK_VM, MCK_UImm2, MCK_I64 }, },
  { 973 /* lvm */, VE::LVMim, Convert__Reg1_0__UImm21_1__MImm1_2, AMFBS_None, { MCK_VM, MCK_UImm2, MCK_MImm }, },
  { 977 /* lvs */, VE::LVSvr, Convert__Reg1_0__Reg1_1__Reg1_3, AMFBS_None, { MCK_I64, MCK_V64, MCK__40_, MCK_I64, MCK__41_ }, },
  { 977 /* lvs */, VE::LVSvi, Convert__Reg1_0__Reg1_1__UImm71_3, AMFBS_None, { MCK_I64, MCK_V64, MCK__40_, MCK_UImm7, MCK__41_ }, },
  { 981 /* lzvm */, VE::LZVMm, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_VM }, },
  { 986 /* maxs.l */, VE::MAXSLrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 986 /* maxs.l */, VE::MAXSLrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 986 /* maxs.l */, VE::MAXSLri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 986 /* maxs.l */, VE::MAXSLim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 993 /* maxs.w.sx */, VE::MAXSWSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 993 /* maxs.w.sx */, VE::MAXSWSXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 993 /* maxs.w.sx */, VE::MAXSWSXri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 993 /* maxs.w.sx */, VE::MAXSWSXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 1003 /* maxs.w.zx */, VE::MAXSWZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 1003 /* maxs.w.zx */, VE::MAXSWZXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 1003 /* maxs.w.zx */, VE::MAXSWZXri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 1003 /* maxs.w.zx */, VE::MAXSWZXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 1013 /* mins.l */, VE::MINSLrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 1013 /* mins.l */, VE::MINSLrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 1013 /* mins.l */, VE::MINSLri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 1013 /* mins.l */, VE::MINSLim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 1020 /* mins.w.sx */, VE::MINSWSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 1020 /* mins.w.sx */, VE::MINSWSXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 1020 /* mins.w.sx */, VE::MINSWSXri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 1020 /* mins.w.sx */, VE::MINSWSXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 1030 /* mins.w.zx */, VE::MINSWZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 1030 /* mins.w.zx */, VE::MINSWZXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 1030 /* mins.w.zx */, VE::MINSWZXri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 1030 /* mins.w.zx */, VE::MINSWZXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 1040 /* monc */, VE::MONC, Convert_NoOperands, AMFBS_None, {  }, },
  { 1045 /* monc.hdb */, VE::MONCHDB, Convert_NoOperands, AMFBS_None, {  }, },
  { 1054 /* mrg */, VE::MRGrr, Convert__Reg1_0__Reg1_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 1054 /* mrg */, VE::MRGrm, Convert__Reg1_0__Reg1_1__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 1054 /* mrg */, VE::MRGir, Convert__Reg1_0__SImm71_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 1054 /* mrg */, VE::MRGim, Convert__Reg1_0__SImm71_1__MImm1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 1058 /* muls.l */, VE::MULSLrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 1058 /* muls.l */, VE::MULSLrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 1058 /* muls.l */, VE::MULSLri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 1058 /* muls.l */, VE::MULSLim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 1065 /* muls.l.w */, VE::MULSLWrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I32, MCK_I32 }, },
  { 1065 /* muls.l.w */, VE::MULSLWrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I32, MCK_MImm }, },
  { 1065 /* muls.l.w */, VE::MULSLWri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I32 }, },
  { 1065 /* muls.l.w */, VE::MULSLWim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 1074 /* muls.w.sx */, VE::MULSWSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 1074 /* muls.w.sx */, VE::MULSWSXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 1074 /* muls.w.sx */, VE::MULSWSXri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 1074 /* muls.w.sx */, VE::MULSWSXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 1084 /* muls.w.zx */, VE::MULSWZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 1084 /* muls.w.zx */, VE::MULSWZXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 1084 /* muls.w.zx */, VE::MULSWZXri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 1084 /* muls.w.zx */, VE::MULSWZXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 1094 /* mulu.l */, VE::MULULrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 1094 /* mulu.l */, VE::MULULrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 1094 /* mulu.l */, VE::MULULri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 1094 /* mulu.l */, VE::MULULim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 1101 /* mulu.w */, VE::MULUWrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 1101 /* mulu.w */, VE::MULUWrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 1101 /* mulu.w */, VE::MULUWri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 1101 /* mulu.w */, VE::MULUWim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 1108 /* negm */, VE::NEGMm, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 1113 /* nnd */, VE::NNDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 1113 /* nnd */, VE::NNDrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 1113 /* nnd */, VE::NNDir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 1113 /* nnd */, VE::NNDim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 1117 /* nndm */, VE::NNDMmm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_VM, MCK_VM, MCK_VM }, },
  { 1122 /* nop */, VE::NOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 1126 /* or */, VE::ORrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 1126 /* or */, VE::ORrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 1126 /* or */, VE::ORri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 1126 /* or */, VE::ORim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 1129 /* orm */, VE::ORMmm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_VM, MCK_VM, MCK_VM }, },
  { 1133 /* pcnt */, VE::PCNTr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_I64 }, },
  { 1133 /* pcnt */, VE::PCNTm, Convert__Reg1_0__MImm1_1, AMFBS_None, { MCK_I64, MCK_MImm }, },
  { 1138 /* pcvm */, VE::PCVMm, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_VM }, },
  { 1143 /* pfch */, VE::PFCHrii, Convert__MEMrii3_0, AMFBS_None, { MCK_MEMrii }, },
  { 1143 /* pfch */, VE::PFCHrri, Convert__MEMrri3_0, AMFBS_None, { MCK_MEMrri }, },
  { 1143 /* pfch */, VE::PFCHzii, Convert__MEMzii3_0, AMFBS_None, { MCK_MEMzii }, },
  { 1143 /* pfch */, VE::PFCHzri, Convert__MEMzri3_0, AMFBS_None, { MCK_MEMzri }, },
  { 1148 /* pfchv */, VE::PFCHVrr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_I64 }, },
  { 1148 /* pfchv */, VE::PFCHVrz, Convert__Reg1_0__Zero1_1, AMFBS_None, { MCK_I64, MCK_Zero }, },
  { 1148 /* pfchv */, VE::PFCHVir, Convert__SImm71_0__Reg1_1, AMFBS_None, { MCK_SImm7, MCK_I64 }, },
  { 1148 /* pfchv */, VE::PFCHViz, Convert__SImm71_0__Zero1_1, AMFBS_None, { MCK_SImm7, MCK_Zero }, },
  { 1154 /* pfchv.nc */, VE::PFCHVNCrr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_I64 }, },
  { 1154 /* pfchv.nc */, VE::PFCHVNCrz, Convert__Reg1_0__Zero1_1, AMFBS_None, { MCK_I64, MCK_Zero }, },
  { 1154 /* pfchv.nc */, VE::PFCHVNCir, Convert__SImm71_0__Reg1_1, AMFBS_None, { MCK_SImm7, MCK_I64 }, },
  { 1154 /* pfchv.nc */, VE::PFCHVNCiz, Convert__SImm71_0__Zero1_1, AMFBS_None, { MCK_SImm7, MCK_Zero }, },
  { 1163 /* pvadds */, VE::PVADDSrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1163 /* pvadds */, VE::PVADDSvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1163 /* pvadds */, VE::PVADDSiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1163 /* pvadds */, VE::PVADDSrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1163 /* pvadds */, VE::PVADDSvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1163 /* pvadds */, VE::PVADDSivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1170 /* pvadds.lo */, VE::PVADDSLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 1170 /* pvadds.lo */, VE::PVADDSLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1170 /* pvadds.lo */, VE::PVADDSLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1170 /* pvadds.lo */, VE::PVADDSLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 1170 /* pvadds.lo */, VE::PVADDSLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1170 /* pvadds.lo */, VE::PVADDSLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1180 /* pvadds.up */, VE::PVADDSUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1180 /* pvadds.up */, VE::PVADDSUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1180 /* pvadds.up */, VE::PVADDSUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1180 /* pvadds.up */, VE::PVADDSUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1180 /* pvadds.up */, VE::PVADDSUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1180 /* pvadds.up */, VE::PVADDSUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1190 /* pvaddu */, VE::PVADDUrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1190 /* pvaddu */, VE::PVADDUvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1190 /* pvaddu */, VE::PVADDUiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1190 /* pvaddu */, VE::PVADDUrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1190 /* pvaddu */, VE::PVADDUvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1190 /* pvaddu */, VE::PVADDUivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1197 /* pvaddu.lo */, VE::PVADDULOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 1197 /* pvaddu.lo */, VE::PVADDULOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1197 /* pvaddu.lo */, VE::PVADDULOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1197 /* pvaddu.lo */, VE::PVADDULOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 1197 /* pvaddu.lo */, VE::PVADDULOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1197 /* pvaddu.lo */, VE::PVADDULOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1207 /* pvaddu.up */, VE::PVADDUUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1207 /* pvaddu.up */, VE::PVADDUUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1207 /* pvaddu.up */, VE::PVADDUUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1207 /* pvaddu.up */, VE::PVADDUUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1207 /* pvaddu.up */, VE::PVADDUUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1207 /* pvaddu.up */, VE::PVADDUUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1217 /* pvand */, VE::PVANDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1217 /* pvand */, VE::PVANDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1217 /* pvand */, VE::PVANDmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 1217 /* pvand */, VE::PVANDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1217 /* pvand */, VE::PVANDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1217 /* pvand */, VE::PVANDmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM512 }, },
  { 1223 /* pvand.lo */, VE::PVANDLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 1223 /* pvand.lo */, VE::PVANDLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1223 /* pvand.lo */, VE::PVANDLOmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 1223 /* pvand.lo */, VE::PVANDLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 1223 /* pvand.lo */, VE::PVANDLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1223 /* pvand.lo */, VE::PVANDLOmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 1232 /* pvand.up */, VE::PVANDUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 1232 /* pvand.up */, VE::PVANDUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1232 /* pvand.up */, VE::PVANDUPmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 1232 /* pvand.up */, VE::PVANDUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1232 /* pvand.up */, VE::PVANDUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1232 /* pvand.up */, VE::PVANDUPmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 1241 /* pvbrd */, VE::PVBRDr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_I64 }, },
  { 1241 /* pvbrd */, VE::PVBRDi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_V64, MCK_SImm7 }, },
  { 1241 /* pvbrd */, VE::PVBRDrm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_VM512 }, },
  { 1241 /* pvbrd */, VE::PVBRDim, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_VM512 }, },
  { 1247 /* pvbrv */, VE::PVBRVv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1247 /* pvbrv */, VE::PVBRVvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1253 /* pvbrv.lo */, VE::PVBRVLOv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1253 /* pvbrv.lo */, VE::PVBRVLOvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1262 /* pvbrv.up */, VE::PVBRVUPv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1262 /* pvbrv.up */, VE::PVBRVUPvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1271 /* pvcmps */, VE::PVCMPSrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1271 /* pvcmps */, VE::PVCMPSvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1271 /* pvcmps */, VE::PVCMPSiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1271 /* pvcmps */, VE::PVCMPSrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1271 /* pvcmps */, VE::PVCMPSvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1271 /* pvcmps */, VE::PVCMPSivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1278 /* pvcmps.lo */, VE::PVCMPSLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 1278 /* pvcmps.lo */, VE::PVCMPSLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1278 /* pvcmps.lo */, VE::PVCMPSLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1278 /* pvcmps.lo */, VE::PVCMPSLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 1278 /* pvcmps.lo */, VE::PVCMPSLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1278 /* pvcmps.lo */, VE::PVCMPSLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1288 /* pvcmps.up */, VE::PVCMPSUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1288 /* pvcmps.up */, VE::PVCMPSUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1288 /* pvcmps.up */, VE::PVCMPSUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1288 /* pvcmps.up */, VE::PVCMPSUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1288 /* pvcmps.up */, VE::PVCMPSUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1288 /* pvcmps.up */, VE::PVCMPSUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1298 /* pvcmpu */, VE::PVCMPUrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1298 /* pvcmpu */, VE::PVCMPUvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1298 /* pvcmpu */, VE::PVCMPUiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1298 /* pvcmpu */, VE::PVCMPUrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1298 /* pvcmpu */, VE::PVCMPUvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1298 /* pvcmpu */, VE::PVCMPUivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1305 /* pvcmpu.lo */, VE::PVCMPULOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 1305 /* pvcmpu.lo */, VE::PVCMPULOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1305 /* pvcmpu.lo */, VE::PVCMPULOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1305 /* pvcmpu.lo */, VE::PVCMPULOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 1305 /* pvcmpu.lo */, VE::PVCMPULOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1305 /* pvcmpu.lo */, VE::PVCMPULOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1315 /* pvcmpu.up */, VE::PVCMPUUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1315 /* pvcmpu.up */, VE::PVCMPUUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1315 /* pvcmpu.up */, VE::PVCMPUUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1315 /* pvcmpu.up */, VE::PVCMPUUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1315 /* pvcmpu.up */, VE::PVCMPUUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1315 /* pvcmpu.up */, VE::PVCMPUUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1325 /* pvcvt.s.w */, VE::PVCVTSWv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1325 /* pvcvt.s.w */, VE::PVCVTSWvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1335 /* pvcvt.s.w.lo */, VE::PVCVTSWLOv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1335 /* pvcvt.s.w.lo */, VE::PVCVTSWLOvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1348 /* pvcvt.s.w.up */, VE::PVCVTSWUPv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1348 /* pvcvt.s.w.up */, VE::PVCVTSWUPvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1361 /* pvcvt.w.s */, VE::PVCVTWSv, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64 }, },
  { 1361 /* pvcvt.w.s */, VE::PVCVTWSvm, Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1371 /* pvcvt.w.s.lo */, VE::PVCVTWSLOv, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64 }, },
  { 1371 /* pvcvt.w.s.lo */, VE::PVCVTWSLOvm, Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64, MCK_VM }, },
  { 1384 /* pvcvt.w.s.up */, VE::PVCVTWSUPv, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64 }, },
  { 1384 /* pvcvt.w.s.up */, VE::PVCVTWSUPvm, Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64, MCK_VM }, },
  { 1397 /* pveqv */, VE::PVEQVrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1397 /* pveqv */, VE::PVEQVvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1397 /* pveqv */, VE::PVEQVmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 1397 /* pveqv */, VE::PVEQVrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1397 /* pveqv */, VE::PVEQVvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1397 /* pveqv */, VE::PVEQVmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM512 }, },
  { 1403 /* pveqv.lo */, VE::PVEQVLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 1403 /* pveqv.lo */, VE::PVEQVLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1403 /* pveqv.lo */, VE::PVEQVLOmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 1403 /* pveqv.lo */, VE::PVEQVLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 1403 /* pveqv.lo */, VE::PVEQVLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1403 /* pveqv.lo */, VE::PVEQVLOmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 1412 /* pveqv.up */, VE::PVEQVUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 1412 /* pveqv.up */, VE::PVEQVUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1412 /* pveqv.up */, VE::PVEQVUPmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 1412 /* pveqv.up */, VE::PVEQVUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1412 /* pveqv.up */, VE::PVEQVUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1412 /* pveqv.up */, VE::PVEQVUPmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 1421 /* pvfadd */, VE::PVFADDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1421 /* pvfadd */, VE::PVFADDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1421 /* pvfadd */, VE::PVFADDiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1421 /* pvfadd */, VE::PVFADDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1421 /* pvfadd */, VE::PVFADDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1421 /* pvfadd */, VE::PVFADDivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1428 /* pvfadd.lo */, VE::PVFADDLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1428 /* pvfadd.lo */, VE::PVFADDLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1428 /* pvfadd.lo */, VE::PVFADDLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1428 /* pvfadd.lo */, VE::PVFADDLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1428 /* pvfadd.lo */, VE::PVFADDLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1428 /* pvfadd.lo */, VE::PVFADDLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1438 /* pvfadd.up */, VE::PVFADDUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 1438 /* pvfadd.up */, VE::PVFADDUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1438 /* pvfadd.up */, VE::PVFADDUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1438 /* pvfadd.up */, VE::PVFADDUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1438 /* pvfadd.up */, VE::PVFADDUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1438 /* pvfadd.up */, VE::PVFADDUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1448 /* pvfcmp */, VE::PVFCMPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1448 /* pvfcmp */, VE::PVFCMPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1448 /* pvfcmp */, VE::PVFCMPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1448 /* pvfcmp */, VE::PVFCMPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1448 /* pvfcmp */, VE::PVFCMPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1448 /* pvfcmp */, VE::PVFCMPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1455 /* pvfcmp.lo */, VE::PVFCMPLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1455 /* pvfcmp.lo */, VE::PVFCMPLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1455 /* pvfcmp.lo */, VE::PVFCMPLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1455 /* pvfcmp.lo */, VE::PVFCMPLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1455 /* pvfcmp.lo */, VE::PVFCMPLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1455 /* pvfcmp.lo */, VE::PVFCMPLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1465 /* pvfcmp.up */, VE::PVFCMPUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 1465 /* pvfcmp.up */, VE::PVFCMPUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1465 /* pvfcmp.up */, VE::PVFCMPUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1465 /* pvfcmp.up */, VE::PVFCMPUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1465 /* pvfcmp.up */, VE::PVFCMPUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1465 /* pvfcmp.up */, VE::PVFCMPUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1475 /* pvfmad */, VE::PVFMADrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 1475 /* pvfmad */, VE::PVFMADvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 1475 /* pvfmad */, VE::PVFMADvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1475 /* pvfmad */, VE::PVFMADviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1475 /* pvfmad */, VE::PVFMADivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1475 /* pvfmad */, VE::PVFMADrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1475 /* pvfmad */, VE::PVFMADvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1475 /* pvfmad */, VE::PVFMADvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1475 /* pvfmad */, VE::PVFMADvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1475 /* pvfmad */, VE::PVFMADivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1482 /* pvfmad.lo */, VE::PVFMADLOivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_V64 }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_V64 }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_V64, MCK_VM }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1492 /* pvfmad.up */, VE::PVFMADUPivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 1502 /* pvfmax */, VE::PVFMAXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1502 /* pvfmax */, VE::PVFMAXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1502 /* pvfmax */, VE::PVFMAXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1502 /* pvfmax */, VE::PVFMAXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1502 /* pvfmax */, VE::PVFMAXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1502 /* pvfmax */, VE::PVFMAXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1509 /* pvfmax.lo */, VE::PVFMAXLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1509 /* pvfmax.lo */, VE::PVFMAXLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1509 /* pvfmax.lo */, VE::PVFMAXLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1509 /* pvfmax.lo */, VE::PVFMAXLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1509 /* pvfmax.lo */, VE::PVFMAXLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1509 /* pvfmax.lo */, VE::PVFMAXLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1519 /* pvfmax.up */, VE::PVFMAXUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 1519 /* pvfmax.up */, VE::PVFMAXUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1519 /* pvfmax.up */, VE::PVFMAXUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1519 /* pvfmax.up */, VE::PVFMAXUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1519 /* pvfmax.up */, VE::PVFMAXUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1519 /* pvfmax.up */, VE::PVFMAXUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1529 /* pvfmin */, VE::PVFMINrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1529 /* pvfmin */, VE::PVFMINvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1529 /* pvfmin */, VE::PVFMINiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1529 /* pvfmin */, VE::PVFMINrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1529 /* pvfmin */, VE::PVFMINvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1529 /* pvfmin */, VE::PVFMINivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1536 /* pvfmin.lo */, VE::PVFMINLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1536 /* pvfmin.lo */, VE::PVFMINLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1536 /* pvfmin.lo */, VE::PVFMINLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1536 /* pvfmin.lo */, VE::PVFMINLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1536 /* pvfmin.lo */, VE::PVFMINLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1536 /* pvfmin.lo */, VE::PVFMINLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1546 /* pvfmin.up */, VE::PVFMINUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 1546 /* pvfmin.up */, VE::PVFMINUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1546 /* pvfmin.up */, VE::PVFMINUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1546 /* pvfmin.up */, VE::PVFMINUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1546 /* pvfmin.up */, VE::PVFMINUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1546 /* pvfmin.up */, VE::PVFMINUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1556 /* pvfmk.s.lo. */, VE::PVFMKSLOv, Convert__Reg1_1__CCOp1_0__Reg1_2, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64 }, },
  { 1556 /* pvfmk.s.lo. */, VE::PVFMKSLOvm, Convert__Reg1_1__CCOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64, MCK_VM }, },
  { 1568 /* pvfmk.s.lo.af */, VE::PVFMKSLOna, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 1568 /* pvfmk.s.lo.af */, VE::PVFMKSLOnam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 1582 /* pvfmk.s.lo.at */, VE::PVFMKSLOa, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 1582 /* pvfmk.s.lo.at */, VE::PVFMKSLOam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 1596 /* pvfmk.s.up. */, VE::PVFMKSUPv, Convert__Reg1_1__CCOp1_0__Reg1_2, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64 }, },
  { 1596 /* pvfmk.s.up. */, VE::PVFMKSUPvm, Convert__Reg1_1__CCOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64, MCK_VM }, },
  { 1608 /* pvfmk.s.up.af */, VE::PVFMKSUPna, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 1608 /* pvfmk.s.up.af */, VE::PVFMKSUPnam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 1622 /* pvfmk.s.up.at */, VE::PVFMKSUPa, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 1622 /* pvfmk.s.up.at */, VE::PVFMKSUPam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 1636 /* pvfmk.w.up. */, VE::PVFMKWUPv, Convert__Reg1_1__CCOp1_0__Reg1_2, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64 }, },
  { 1636 /* pvfmk.w.up. */, VE::PVFMKWUPvm, Convert__Reg1_1__CCOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64, MCK_VM }, },
  { 1648 /* pvfmk.w.up.af */, VE::PVFMKWUPna, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 1648 /* pvfmk.w.up.af */, VE::PVFMKWUPnam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 1662 /* pvfmk.w.up.at */, VE::PVFMKWUPa, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 1662 /* pvfmk.w.up.at */, VE::PVFMKWUPam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 1676 /* pvfmsb */, VE::PVFMSBrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 1676 /* pvfmsb */, VE::PVFMSBvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 1676 /* pvfmsb */, VE::PVFMSBvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1676 /* pvfmsb */, VE::PVFMSBviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1676 /* pvfmsb */, VE::PVFMSBivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1676 /* pvfmsb */, VE::PVFMSBrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1676 /* pvfmsb */, VE::PVFMSBvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1676 /* pvfmsb */, VE::PVFMSBvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1676 /* pvfmsb */, VE::PVFMSBvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1676 /* pvfmsb */, VE::PVFMSBivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1683 /* pvfmsb.lo */, VE::PVFMSBLOivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_V64 }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_V64 }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_V64, MCK_VM }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1693 /* pvfmsb.up */, VE::PVFMSBUPivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 1703 /* pvfmul */, VE::PVFMULrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1703 /* pvfmul */, VE::PVFMULvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1703 /* pvfmul */, VE::PVFMULiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1703 /* pvfmul */, VE::PVFMULrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1703 /* pvfmul */, VE::PVFMULvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1703 /* pvfmul */, VE::PVFMULivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1710 /* pvfmul.lo */, VE::PVFMULLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1710 /* pvfmul.lo */, VE::PVFMULLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1710 /* pvfmul.lo */, VE::PVFMULLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1710 /* pvfmul.lo */, VE::PVFMULLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1710 /* pvfmul.lo */, VE::PVFMULLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1710 /* pvfmul.lo */, VE::PVFMULLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1720 /* pvfmul.up */, VE::PVFMULUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 1720 /* pvfmul.up */, VE::PVFMULUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1720 /* pvfmul.up */, VE::PVFMULUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1720 /* pvfmul.up */, VE::PVFMULUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1720 /* pvfmul.up */, VE::PVFMULUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1720 /* pvfmul.up */, VE::PVFMULUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1730 /* pvfnmad */, VE::PVFNMADrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 1730 /* pvfnmad */, VE::PVFNMADvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 1730 /* pvfnmad */, VE::PVFNMADvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1730 /* pvfnmad */, VE::PVFNMADviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1730 /* pvfnmad */, VE::PVFNMADivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1730 /* pvfnmad */, VE::PVFNMADrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1730 /* pvfnmad */, VE::PVFNMADvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1730 /* pvfnmad */, VE::PVFNMADvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1730 /* pvfnmad */, VE::PVFNMADvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1730 /* pvfnmad */, VE::PVFNMADivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1738 /* pvfnmad.lo */, VE::PVFNMADLOivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_V64 }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_V64 }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_V64, MCK_VM }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1749 /* pvfnmad.up */, VE::PVFNMADUPivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1760 /* pvfnmsb */, VE::PVFNMSBivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1768 /* pvfnmsb.lo */, VE::PVFNMSBLOivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_V64 }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_V64 }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_V64, MCK_VM }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1779 /* pvfnmsb.up */, VE::PVFNMSBUPivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 1790 /* pvfsub */, VE::PVFSUBrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1790 /* pvfsub */, VE::PVFSUBvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1790 /* pvfsub */, VE::PVFSUBiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1790 /* pvfsub */, VE::PVFSUBrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1790 /* pvfsub */, VE::PVFSUBvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1790 /* pvfsub */, VE::PVFSUBivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1797 /* pvfsub.lo */, VE::PVFSUBLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1797 /* pvfsub.lo */, VE::PVFSUBLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1797 /* pvfsub.lo */, VE::PVFSUBLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1797 /* pvfsub.lo */, VE::PVFSUBLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1797 /* pvfsub.lo */, VE::PVFSUBLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1797 /* pvfsub.lo */, VE::PVFSUBLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1807 /* pvfsub.up */, VE::PVFSUBUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 1807 /* pvfsub.up */, VE::PVFSUBUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1807 /* pvfsub.up */, VE::PVFSUBUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1807 /* pvfsub.up */, VE::PVFSUBUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1807 /* pvfsub.up */, VE::PVFSUBUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1807 /* pvfsub.up */, VE::PVFSUBUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1817 /* pvldz */, VE::PVLDZv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1817 /* pvldz */, VE::PVLDZvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1823 /* pvldz.lo */, VE::PVLDZLOv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1823 /* pvldz.lo */, VE::PVLDZLOvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1832 /* pvldz.up */, VE::PVLDZUPv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1832 /* pvldz.up */, VE::PVLDZUPvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1841 /* pvmaxs */, VE::PVMAXSrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1841 /* pvmaxs */, VE::PVMAXSvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1841 /* pvmaxs */, VE::PVMAXSiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1841 /* pvmaxs */, VE::PVMAXSrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1841 /* pvmaxs */, VE::PVMAXSvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1841 /* pvmaxs */, VE::PVMAXSivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1848 /* pvmaxs.lo */, VE::PVMAXSLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 1848 /* pvmaxs.lo */, VE::PVMAXSLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1848 /* pvmaxs.lo */, VE::PVMAXSLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1848 /* pvmaxs.lo */, VE::PVMAXSLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 1848 /* pvmaxs.lo */, VE::PVMAXSLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1848 /* pvmaxs.lo */, VE::PVMAXSLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1858 /* pvmaxs.up */, VE::PVMAXSUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1858 /* pvmaxs.up */, VE::PVMAXSUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1858 /* pvmaxs.up */, VE::PVMAXSUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1858 /* pvmaxs.up */, VE::PVMAXSUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1858 /* pvmaxs.up */, VE::PVMAXSUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1858 /* pvmaxs.up */, VE::PVMAXSUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1868 /* pvmins */, VE::PVMINSrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1868 /* pvmins */, VE::PVMINSvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1868 /* pvmins */, VE::PVMINSiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1868 /* pvmins */, VE::PVMINSrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1868 /* pvmins */, VE::PVMINSvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1868 /* pvmins */, VE::PVMINSivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 1875 /* pvmins.lo */, VE::PVMINSLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 1875 /* pvmins.lo */, VE::PVMINSLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1875 /* pvmins.lo */, VE::PVMINSLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1875 /* pvmins.lo */, VE::PVMINSLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 1875 /* pvmins.lo */, VE::PVMINSLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1875 /* pvmins.lo */, VE::PVMINSLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1885 /* pvmins.up */, VE::PVMINSUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1885 /* pvmins.up */, VE::PVMINSUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1885 /* pvmins.up */, VE::PVMINSUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 1885 /* pvmins.up */, VE::PVMINSUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 1885 /* pvmins.up */, VE::PVMINSUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1885 /* pvmins.up */, VE::PVMINSUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 1895 /* pvor */, VE::PVORrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 1895 /* pvor */, VE::PVORvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1895 /* pvor */, VE::PVORmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 1895 /* pvor */, VE::PVORrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 1895 /* pvor */, VE::PVORvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1895 /* pvor */, VE::PVORmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM512 }, },
  { 1900 /* pvor.lo */, VE::PVORLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 1900 /* pvor.lo */, VE::PVORLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1900 /* pvor.lo */, VE::PVORLOmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 1900 /* pvor.lo */, VE::PVORLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 1900 /* pvor.lo */, VE::PVORLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1900 /* pvor.lo */, VE::PVORLOmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 1908 /* pvor.up */, VE::PVORUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 1908 /* pvor.up */, VE::PVORUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 1908 /* pvor.up */, VE::PVORUPmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 1908 /* pvor.up */, VE::PVORUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 1908 /* pvor.up */, VE::PVORUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 1908 /* pvor.up */, VE::PVORUPmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 1916 /* pvpcnt */, VE::PVPCNTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1916 /* pvpcnt */, VE::PVPCNTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1923 /* pvpcnt.lo */, VE::PVPCNTLOv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1923 /* pvpcnt.lo */, VE::PVPCNTLOvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1933 /* pvpcnt.up */, VE::PVPCNTUPv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1933 /* pvpcnt.up */, VE::PVPCNTUPvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1943 /* pvrcp */, VE::PVRCPv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1943 /* pvrcp */, VE::PVRCPvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1949 /* pvrcp.lo */, VE::PVRCPLOv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1949 /* pvrcp.lo */, VE::PVRCPLOvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1958 /* pvrcp.up */, VE::PVRCPUPv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1958 /* pvrcp.up */, VE::PVRCPUPvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1967 /* pvrsqrt */, VE::PVRSQRTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1967 /* pvrsqrt */, VE::PVRSQRTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM512 }, },
  { 1975 /* pvrsqrt.lo */, VE::PVRSQRTLOv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1975 /* pvrsqrt.lo */, VE::PVRSQRTLOvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 1986 /* pvrsqrt.lo.nex */, VE::PVRSQRTLONEXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 1986 /* pvrsqrt.lo.nex */, VE::PVRSQRTLONEXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2001 /* pvrsqrt.nex */, VE::PVRSQRTNEXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2001 /* pvrsqrt.nex */, VE::PVRSQRTNEXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM512 }, },
  { 2013 /* pvrsqrt.up */, VE::PVRSQRTUPv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2013 /* pvrsqrt.up */, VE::PVRSQRTUPvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2024 /* pvrsqrt.up.nex */, VE::PVRSQRTUPNEXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2024 /* pvrsqrt.up.nex */, VE::PVRSQRTUPNEXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2039 /* pvseq */, VE::PVSEQ, Convert__Reg1_0, AMFBS_None, { MCK_V64 }, },
  { 2039 /* pvseq */, VE::PVSEQm, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_VM512 }, },
  { 2045 /* pvseq.lo */, VE::PVSEQLO, Convert__Reg1_0, AMFBS_None, { MCK_V64 }, },
  { 2045 /* pvseq.lo */, VE::PVSEQLOm, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_VM }, },
  { 2054 /* pvseq.up */, VE::PVSEQUP, Convert__Reg1_0, AMFBS_None, { MCK_V64 }, },
  { 2054 /* pvseq.up */, VE::PVSEQUPm, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_VM }, },
  { 2063 /* pvsla */, VE::PVSLAvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2063 /* pvsla */, VE::PVSLAvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2063 /* pvsla */, VE::PVSLAvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2063 /* pvsla */, VE::PVSLAvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM512 }, },
  { 2063 /* pvsla */, VE::PVSLAvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 2063 /* pvsla */, VE::PVSLAvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM512 }, },
  { 2069 /* pvsla.lo */, VE::PVSLALOvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32 }, },
  { 2069 /* pvsla.lo */, VE::PVSLALOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2069 /* pvsla.lo */, VE::PVSLALOvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2069 /* pvsla.lo */, VE::PVSLALOvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32, MCK_VM }, },
  { 2069 /* pvsla.lo */, VE::PVSLALOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2069 /* pvsla.lo */, VE::PVSLALOvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 2078 /* pvsla.up */, VE::PVSLAUPvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32 }, },
  { 2078 /* pvsla.up */, VE::PVSLAUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2078 /* pvsla.up */, VE::PVSLAUPvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2078 /* pvsla.up */, VE::PVSLAUPvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_VM }, },
  { 2078 /* pvsla.up */, VE::PVSLAUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2078 /* pvsla.up */, VE::PVSLAUPvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 2087 /* pvsll */, VE::PVSLLvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2087 /* pvsll */, VE::PVSLLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2087 /* pvsll */, VE::PVSLLvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2087 /* pvsll */, VE::PVSLLvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM512 }, },
  { 2087 /* pvsll */, VE::PVSLLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 2087 /* pvsll */, VE::PVSLLvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM512 }, },
  { 2093 /* pvsll.lo */, VE::PVSLLLOvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32 }, },
  { 2093 /* pvsll.lo */, VE::PVSLLLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2093 /* pvsll.lo */, VE::PVSLLLOvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2093 /* pvsll.lo */, VE::PVSLLLOvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32, MCK_VM }, },
  { 2093 /* pvsll.lo */, VE::PVSLLLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2093 /* pvsll.lo */, VE::PVSLLLOvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 2102 /* pvsll.up */, VE::PVSLLUPvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32 }, },
  { 2102 /* pvsll.up */, VE::PVSLLUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2102 /* pvsll.up */, VE::PVSLLUPvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2102 /* pvsll.up */, VE::PVSLLUPvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_VM }, },
  { 2102 /* pvsll.up */, VE::PVSLLUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2102 /* pvsll.up */, VE::PVSLLUPvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 2111 /* pvsra */, VE::PVSRAvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2111 /* pvsra */, VE::PVSRAvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2111 /* pvsra */, VE::PVSRAvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2111 /* pvsra */, VE::PVSRAvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM512 }, },
  { 2111 /* pvsra */, VE::PVSRAvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 2111 /* pvsra */, VE::PVSRAvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM512 }, },
  { 2117 /* pvsra.lo */, VE::PVSRALOvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32 }, },
  { 2117 /* pvsra.lo */, VE::PVSRALOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2117 /* pvsra.lo */, VE::PVSRALOvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2117 /* pvsra.lo */, VE::PVSRALOvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32, MCK_VM }, },
  { 2117 /* pvsra.lo */, VE::PVSRALOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2117 /* pvsra.lo */, VE::PVSRALOvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 2126 /* pvsra.up */, VE::PVSRAUPvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32 }, },
  { 2126 /* pvsra.up */, VE::PVSRAUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2126 /* pvsra.up */, VE::PVSRAUPvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2126 /* pvsra.up */, VE::PVSRAUPvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_VM }, },
  { 2126 /* pvsra.up */, VE::PVSRAUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2126 /* pvsra.up */, VE::PVSRAUPvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 2135 /* pvsrl */, VE::PVSRLvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2135 /* pvsrl */, VE::PVSRLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2135 /* pvsrl */, VE::PVSRLvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2135 /* pvsrl */, VE::PVSRLvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM512 }, },
  { 2135 /* pvsrl */, VE::PVSRLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 2135 /* pvsrl */, VE::PVSRLvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM512 }, },
  { 2141 /* pvsrl.lo */, VE::PVSRLLOvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32 }, },
  { 2141 /* pvsrl.lo */, VE::PVSRLLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2141 /* pvsrl.lo */, VE::PVSRLLOvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2141 /* pvsrl.lo */, VE::PVSRLLOvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32, MCK_VM }, },
  { 2141 /* pvsrl.lo */, VE::PVSRLLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2141 /* pvsrl.lo */, VE::PVSRLLOvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 2150 /* pvsrl.up */, VE::PVSRLUPvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32 }, },
  { 2150 /* pvsrl.up */, VE::PVSRLUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2150 /* pvsrl.up */, VE::PVSRLUPvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 2150 /* pvsrl.up */, VE::PVSRLUPvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_VM }, },
  { 2150 /* pvsrl.up */, VE::PVSRLUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2150 /* pvsrl.up */, VE::PVSRLUPvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 2159 /* pvsubs */, VE::PVSUBSrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2159 /* pvsubs */, VE::PVSUBSvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2159 /* pvsubs */, VE::PVSUBSiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2159 /* pvsubs */, VE::PVSUBSrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 2159 /* pvsubs */, VE::PVSUBSvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 2159 /* pvsubs */, VE::PVSUBSivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 2166 /* pvsubs.lo */, VE::PVSUBSLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 2166 /* pvsubs.lo */, VE::PVSUBSLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2166 /* pvsubs.lo */, VE::PVSUBSLOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2166 /* pvsubs.lo */, VE::PVSUBSLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 2166 /* pvsubs.lo */, VE::PVSUBSLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2166 /* pvsubs.lo */, VE::PVSUBSLOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2176 /* pvsubs.up */, VE::PVSUBSUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2176 /* pvsubs.up */, VE::PVSUBSUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2176 /* pvsubs.up */, VE::PVSUBSUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2176 /* pvsubs.up */, VE::PVSUBSUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2176 /* pvsubs.up */, VE::PVSUBSUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2176 /* pvsubs.up */, VE::PVSUBSUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2186 /* pvsubu */, VE::PVSUBUrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2186 /* pvsubu */, VE::PVSUBUvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2186 /* pvsubu */, VE::PVSUBUiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2186 /* pvsubu */, VE::PVSUBUrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 2186 /* pvsubu */, VE::PVSUBUvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 2186 /* pvsubu */, VE::PVSUBUivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 2193 /* pvsubu.lo */, VE::PVSUBULOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 2193 /* pvsubu.lo */, VE::PVSUBULOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2193 /* pvsubu.lo */, VE::PVSUBULOiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2193 /* pvsubu.lo */, VE::PVSUBULOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 2193 /* pvsubu.lo */, VE::PVSUBULOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2193 /* pvsubu.lo */, VE::PVSUBULOivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2203 /* pvsubu.up */, VE::PVSUBUUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2203 /* pvsubu.up */, VE::PVSUBUUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2203 /* pvsubu.up */, VE::PVSUBUUPiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2203 /* pvsubu.up */, VE::PVSUBUUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2203 /* pvsubu.up */, VE::PVSUBUUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2203 /* pvsubu.up */, VE::PVSUBUUPivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2213 /* pvxor */, VE::PVXORrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2213 /* pvxor */, VE::PVXORvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2213 /* pvxor */, VE::PVXORmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 2213 /* pvxor */, VE::PVXORrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 2213 /* pvxor */, VE::PVXORvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 2213 /* pvxor */, VE::PVXORmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM512 }, },
  { 2219 /* pvxor.lo */, VE::PVXORLOrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 2219 /* pvxor.lo */, VE::PVXORLOvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2219 /* pvxor.lo */, VE::PVXORLOmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 2219 /* pvxor.lo */, VE::PVXORLOrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 2219 /* pvxor.lo */, VE::PVXORLOvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2219 /* pvxor.lo */, VE::PVXORLOmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 2228 /* pvxor.up */, VE::PVXORUPrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 2228 /* pvxor.up */, VE::PVXORUPvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2228 /* pvxor.up */, VE::PVXORUPmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 2228 /* pvxor.up */, VE::PVXORUPrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 2228 /* pvxor.up */, VE::PVXORUPvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2228 /* pvxor.up */, VE::PVXORUPmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 2237 /* scr */, VE::SCRrrr, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 2237 /* scr */, VE::SCRrzr, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_I64, MCK_I64, MCK_Zero }, },
  { 2237 /* scr */, VE::SCRirr, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 2237 /* scr */, VE::SCRizr, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 2241 /* sfr */, VE::SFR, Convert__Reg1_0, AMFBS_None, { MCK_I64 }, },
  { 2245 /* shm.b */, VE::SHMBri, Convert__MEMri2_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMri }, },
  { 2245 /* shm.b */, VE::SHMBzi, Convert__MEMzi2_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMzi }, },
  { 2251 /* shm.h */, VE::SHMHri, Convert__MEMri2_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMri }, },
  { 2251 /* shm.h */, VE::SHMHzi, Convert__MEMzi2_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMzi }, },
  { 2257 /* shm.l */, VE::SHMLri, Convert__MEMri2_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMri }, },
  { 2257 /* shm.l */, VE::SHMLzi, Convert__MEMzi2_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMzi }, },
  { 2263 /* shm.w */, VE::SHMWri, Convert__MEMri2_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMri }, },
  { 2263 /* shm.w */, VE::SHMWzi, Convert__MEMzi2_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMzi }, },
  { 2269 /* sic */, VE::SIC, Convert__Reg1_0, AMFBS_None, { MCK_I32 }, },
  { 2273 /* sla.l */, VE::SLALrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I32 }, },
  { 2273 /* sla.l */, VE::SLALri, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_UImm7 }, },
  { 2273 /* sla.l */, VE::SLALmr, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_I32 }, },
  { 2273 /* sla.l */, VE::SLALmi, Convert__Reg1_0__MImm1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_UImm7 }, },
  { 2279 /* sla.w.sx */, VE::SLAWSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 2279 /* sla.w.sx */, VE::SLAWSXri, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_UImm7 }, },
  { 2279 /* sla.w.sx */, VE::SLAWSXmr, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_MImm, MCK_I32 }, },
  { 2279 /* sla.w.sx */, VE::SLAWSXmi, Convert__Reg1_0__MImm1_1__UImm71_2, AMFBS_None, { MCK_I32, MCK_MImm, MCK_UImm7 }, },
  { 2288 /* sla.w.zx */, VE::SLAWZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 2288 /* sla.w.zx */, VE::SLAWZXri, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_UImm7 }, },
  { 2288 /* sla.w.zx */, VE::SLAWZXmr, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_MImm, MCK_I32 }, },
  { 2288 /* sla.w.zx */, VE::SLAWZXmi, Convert__Reg1_0__MImm1_1__UImm71_2, AMFBS_None, { MCK_I32, MCK_MImm, MCK_UImm7 }, },
  { 2297 /* sld */, VE::SLDrrr, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I32 }, },
  { 2297 /* sld */, VE::SLDrri, Convert__Reg1_0__Tie0_1_1__Reg1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_UImm7 }, },
  { 2297 /* sld */, VE::SLDrmr, Convert__Reg1_0__Tie0_1_1__MImm1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_I32 }, },
  { 2297 /* sld */, VE::SLDrmi, Convert__Reg1_0__Tie0_1_1__MImm1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_UImm7 }, },
  { 2301 /* sll */, VE::SLLrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I32 }, },
  { 2301 /* sll */, VE::SLLri, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_UImm7 }, },
  { 2301 /* sll */, VE::SLLmr, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_I32 }, },
  { 2301 /* sll */, VE::SLLmi, Convert__Reg1_0__MImm1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_UImm7 }, },
  { 2305 /* smir */, VE::SMIR, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_MISC }, },
  { 2310 /* smvl */, VE::SMVL, Convert__Reg1_0, AMFBS_None, { MCK_I64 }, },
  { 2315 /* spm */, VE::SPM, Convert__Reg1_0, AMFBS_None, { MCK_I64 }, },
  { 2319 /* sra.l */, VE::SRALrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I32 }, },
  { 2319 /* sra.l */, VE::SRALri, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_UImm7 }, },
  { 2319 /* sra.l */, VE::SRALmr, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_I32 }, },
  { 2319 /* sra.l */, VE::SRALmi, Convert__Reg1_0__MImm1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_UImm7 }, },
  { 2325 /* sra.w.sx */, VE::SRAWSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 2325 /* sra.w.sx */, VE::SRAWSXri, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_UImm7 }, },
  { 2325 /* sra.w.sx */, VE::SRAWSXmr, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_MImm, MCK_I32 }, },
  { 2325 /* sra.w.sx */, VE::SRAWSXmi, Convert__Reg1_0__MImm1_1__UImm71_2, AMFBS_None, { MCK_I32, MCK_MImm, MCK_UImm7 }, },
  { 2334 /* sra.w.zx */, VE::SRAWZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 2334 /* sra.w.zx */, VE::SRAWZXri, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_UImm7 }, },
  { 2334 /* sra.w.zx */, VE::SRAWZXmr, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_MImm, MCK_I32 }, },
  { 2334 /* sra.w.zx */, VE::SRAWZXmi, Convert__Reg1_0__MImm1_1__UImm71_2, AMFBS_None, { MCK_I32, MCK_MImm, MCK_UImm7 }, },
  { 2343 /* srd */, VE::SRDrrr, Convert__Reg1_0__Reg1_1__Tie0_1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I32 }, },
  { 2343 /* srd */, VE::SRDrri, Convert__Reg1_0__Reg1_1__Tie0_1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_UImm7 }, },
  { 2343 /* srd */, VE::SRDmrr, Convert__Reg1_0__MImm1_1__Tie0_1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_I32 }, },
  { 2343 /* srd */, VE::SRDmri, Convert__Reg1_0__MImm1_1__Tie0_1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_UImm7 }, },
  { 2347 /* srl */, VE::SRLrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I32 }, },
  { 2347 /* srl */, VE::SRLri, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_UImm7 }, },
  { 2347 /* srl */, VE::SRLmr, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_I32 }, },
  { 2347 /* srl */, VE::SRLmi, Convert__Reg1_0__MImm1_1__UImm71_2, AMFBS_None, { MCK_I64, MCK_MImm, MCK_UImm7 }, },
  { 2351 /* st */, VE::STrii, Convert__MEMrii3_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMrii }, },
  { 2351 /* st */, VE::STrri, Convert__MEMrri3_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMrri }, },
  { 2351 /* st */, VE::STzii, Convert__MEMzii3_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMzii }, },
  { 2351 /* st */, VE::STzri, Convert__MEMzri3_1__Reg1_0, AMFBS_None, { MCK_I64, MCK_MEMzri }, },
  { 2354 /* st1b */, VE::ST1Brii, Convert__MEMrii3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 2354 /* st1b */, VE::ST1Brri, Convert__MEMrri3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 2354 /* st1b */, VE::ST1Bzii, Convert__MEMzii3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 2354 /* st1b */, VE::ST1Bzri, Convert__MEMzri3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 2359 /* st2b */, VE::ST2Brii, Convert__MEMrii3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 2359 /* st2b */, VE::ST2Brri, Convert__MEMrri3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 2359 /* st2b */, VE::ST2Bzii, Convert__MEMzii3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 2359 /* st2b */, VE::ST2Bzri, Convert__MEMzri3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 2364 /* stl */, VE::STLrii, Convert__MEMrii3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMrii }, },
  { 2364 /* stl */, VE::STLrri, Convert__MEMrri3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMrri }, },
  { 2364 /* stl */, VE::STLzii, Convert__MEMzii3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMzii }, },
  { 2364 /* stl */, VE::STLzri, Convert__MEMzri3_1__Reg1_0, AMFBS_None, { MCK_I32, MCK_MEMzri }, },
  { 2368 /* stu */, VE::STUrii, Convert__MEMrii3_1__Reg1_0, AMFBS_None, { MCK_F32, MCK_MEMrii }, },
  { 2368 /* stu */, VE::STUrri, Convert__MEMrri3_1__Reg1_0, AMFBS_None, { MCK_F32, MCK_MEMrri }, },
  { 2368 /* stu */, VE::STUzii, Convert__MEMzii3_1__Reg1_0, AMFBS_None, { MCK_F32, MCK_MEMzii }, },
  { 2368 /* stu */, VE::STUzri, Convert__MEMzri3_1__Reg1_0, AMFBS_None, { MCK_F32, MCK_MEMzri }, },
  { 2372 /* subs.l */, VE::SUBSLrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 2372 /* subs.l */, VE::SUBSLrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 2372 /* subs.l */, VE::SUBSLir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 2372 /* subs.l */, VE::SUBSLim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 2379 /* subs.w.sx */, VE::SUBSWSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 2379 /* subs.w.sx */, VE::SUBSWSXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 2379 /* subs.w.sx */, VE::SUBSWSXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 2379 /* subs.w.sx */, VE::SUBSWSXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 2389 /* subs.w.zx */, VE::SUBSWZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 2389 /* subs.w.zx */, VE::SUBSWZXrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 2389 /* subs.w.zx */, VE::SUBSWZXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 2389 /* subs.w.zx */, VE::SUBSWZXim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 2399 /* subu.l */, VE::SUBULrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 2399 /* subu.l */, VE::SUBULrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 2399 /* subu.l */, VE::SUBULir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 2399 /* subu.l */, VE::SUBULim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 2406 /* subu.w */, VE::SUBUWrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_I32 }, },
  { 2406 /* subu.w */, VE::SUBUWrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_I32, MCK_MImm }, },
  { 2406 /* subu.w */, VE::SUBUWir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_I32 }, },
  { 2406 /* subu.w */, VE::SUBUWim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I32, MCK_SImm7, MCK_MImm }, },
  { 2413 /* svl */, VE::SVL, Convert__Reg1_0, AMFBS_None, { MCK_I64 }, },
  { 2417 /* svm */, VE::SVMmr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_VM, MCK_I64 }, },
  { 2417 /* svm */, VE::SVMmi, Convert__Reg1_0__Reg1_1__UImm21_2, AMFBS_None, { MCK_I64, MCK_VM, MCK_UImm2 }, },
  { 2421 /* svob */, VE::SVOB, Convert_NoOperands, AMFBS_None, {  }, },
  { 2426 /* tovm */, VE::TOVMm, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_I64, MCK_VM }, },
  { 2431 /* ts1am.l */, VE::TS1AMLrir, Convert__Reg1_0__MEMri2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_I64 }, },
  { 2431 /* ts1am.l */, VE::TS1AMLrii, Convert__Reg1_0__MEMri2_1__UImm71_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_UImm7 }, },
  { 2431 /* ts1am.l */, VE::TS1AMLzir, Convert__Reg1_0__MEMzi2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_I64 }, },
  { 2431 /* ts1am.l */, VE::TS1AMLzii, Convert__Reg1_0__MEMzi2_1__UImm71_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_UImm7 }, },
  { 2439 /* ts1am.w */, VE::TS1AMWrir, Convert__Reg1_0__MEMri2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I32, MCK_MEMri, MCK_I32 }, },
  { 2439 /* ts1am.w */, VE::TS1AMWrii, Convert__Reg1_0__MEMri2_1__UImm71_2__Tie0_1_1, AMFBS_None, { MCK_I32, MCK_MEMri, MCK_UImm7 }, },
  { 2439 /* ts1am.w */, VE::TS1AMWzir, Convert__Reg1_0__MEMzi2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I32, MCK_MEMzi, MCK_I32 }, },
  { 2439 /* ts1am.w */, VE::TS1AMWzii, Convert__Reg1_0__MEMzi2_1__UImm71_2__Tie0_1_1, AMFBS_None, { MCK_I32, MCK_MEMzi, MCK_UImm7 }, },
  { 2447 /* ts2am */, VE::TS2AMrir, Convert__Reg1_0__MEMri2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_I64 }, },
  { 2447 /* ts2am */, VE::TS2AMrii, Convert__Reg1_0__MEMri2_1__UImm71_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_UImm7 }, },
  { 2447 /* ts2am */, VE::TS2AMzir, Convert__Reg1_0__MEMzi2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_I64 }, },
  { 2447 /* ts2am */, VE::TS2AMzii, Convert__Reg1_0__MEMzi2_1__UImm71_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_UImm7 }, },
  { 2453 /* ts3am */, VE::TS3AMrir, Convert__Reg1_0__MEMri2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_I64 }, },
  { 2453 /* ts3am */, VE::TS3AMrii, Convert__Reg1_0__MEMri2_1__UImm11_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMri, MCK_UImm1 }, },
  { 2453 /* ts3am */, VE::TS3AMzir, Convert__Reg1_0__MEMzi2_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_I64 }, },
  { 2453 /* ts3am */, VE::TS3AMzii, Convert__Reg1_0__MEMzi2_1__UImm11_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_MEMzi, MCK_UImm1 }, },
  { 2459 /* tscr */, VE::TSCRrrr, Convert__Reg1_0__Reg1_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 2459 /* tscr */, VE::TSCRrzr, Convert__Reg1_0__Reg1_1__Zero1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_I64, MCK_Zero }, },
  { 2459 /* tscr */, VE::TSCRirr, Convert__Reg1_0__SImm71_1__Reg1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 2459 /* tscr */, VE::TSCRizr, Convert__Reg1_0__SImm71_1__Zero1_2__Tie0_1_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 2464 /* vadds.l */, VE::VADDSLrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2464 /* vadds.l */, VE::VADDSLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2464 /* vadds.l */, VE::VADDSLiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2464 /* vadds.l */, VE::VADDSLrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2464 /* vadds.l */, VE::VADDSLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2464 /* vadds.l */, VE::VADDSLivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2472 /* vadds.w.sx */, VE::VADDSWSXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 2472 /* vadds.w.sx */, VE::VADDSWSXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2472 /* vadds.w.sx */, VE::VADDSWSXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2472 /* vadds.w.sx */, VE::VADDSWSXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 2472 /* vadds.w.sx */, VE::VADDSWSXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2472 /* vadds.w.sx */, VE::VADDSWSXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2483 /* vaddu.l */, VE::VADDULrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2483 /* vaddu.l */, VE::VADDULvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2483 /* vaddu.l */, VE::VADDULiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2483 /* vaddu.l */, VE::VADDULrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2483 /* vaddu.l */, VE::VADDULvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2483 /* vaddu.l */, VE::VADDULivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2491 /* vand */, VE::VANDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2491 /* vand */, VE::VANDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2491 /* vand */, VE::VANDmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 2491 /* vand */, VE::VANDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2491 /* vand */, VE::VANDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2491 /* vand */, VE::VANDmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 2496 /* vbrd */, VE::VBRDr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_I64 }, },
  { 2496 /* vbrd */, VE::VBRDi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_V64, MCK_SImm7 }, },
  { 2496 /* vbrd */, VE::VBRDrm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_VM }, },
  { 2496 /* vbrd */, VE::VBRDim, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2501 /* vbrdl */, VE::VBRDLr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_I32 }, },
  { 2501 /* vbrdl */, VE::VBRDLi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_V64, MCK_SImm7 }, },
  { 2501 /* vbrdl */, VE::VBRDLrm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_VM }, },
  { 2501 /* vbrdl */, VE::VBRDLim, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2507 /* vbrdu */, VE::VBRDUr, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_F32 }, },
  { 2507 /* vbrdu */, VE::VBRDUi, Convert__Reg1_0__SImm71_1, AMFBS_None, { MCK_V64, MCK_SImm7 }, },
  { 2507 /* vbrdu */, VE::VBRDUrm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_VM }, },
  { 2507 /* vbrdu */, VE::VBRDUim, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2513 /* vbrv */, VE::VBRVv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2513 /* vbrv */, VE::VBRVvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2518 /* vcmps.l */, VE::VCMPSLrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2518 /* vcmps.l */, VE::VCMPSLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2518 /* vcmps.l */, VE::VCMPSLiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2518 /* vcmps.l */, VE::VCMPSLrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2518 /* vcmps.l */, VE::VCMPSLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2518 /* vcmps.l */, VE::VCMPSLivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2526 /* vcmps.w.sx */, VE::VCMPSWSXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 2526 /* vcmps.w.sx */, VE::VCMPSWSXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2526 /* vcmps.w.sx */, VE::VCMPSWSXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2526 /* vcmps.w.sx */, VE::VCMPSWSXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 2526 /* vcmps.w.sx */, VE::VCMPSWSXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2526 /* vcmps.w.sx */, VE::VCMPSWSXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2537 /* vcmpu.l */, VE::VCMPULrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2537 /* vcmpu.l */, VE::VCMPULvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2537 /* vcmpu.l */, VE::VCMPULiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2537 /* vcmpu.l */, VE::VCMPULrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2537 /* vcmpu.l */, VE::VCMPULvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2537 /* vcmpu.l */, VE::VCMPULivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2545 /* vcp */, VE::VCPv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2545 /* vcp */, VE::VCPvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2549 /* vcvt.d.l */, VE::VCVTDLv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2549 /* vcvt.d.l */, VE::VCVTDLvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2558 /* vcvt.d.s */, VE::VCVTDSv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2558 /* vcvt.d.s */, VE::VCVTDSvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2567 /* vcvt.d.w */, VE::VCVTDWv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2567 /* vcvt.d.w */, VE::VCVTDWvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2576 /* vcvt.l.d */, VE::VCVTLDv, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64 }, },
  { 2576 /* vcvt.l.d */, VE::VCVTLDvm, Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64, MCK_VM }, },
  { 2585 /* vcvt.s.d */, VE::VCVTSDv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2585 /* vcvt.s.d */, VE::VCVTSDvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2594 /* vcvt.s.w */, VE::VCVTSWv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2594 /* vcvt.s.w */, VE::VCVTSWvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2603 /* vcvt.w.d.sx */, VE::VCVTWDSXv, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64 }, },
  { 2603 /* vcvt.w.d.sx */, VE::VCVTWDSXvm, Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64, MCK_VM }, },
  { 2615 /* vcvt.w.d.zx */, VE::VCVTWDZXv, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64 }, },
  { 2615 /* vcvt.w.d.zx */, VE::VCVTWDZXvm, Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64, MCK_VM }, },
  { 2627 /* vcvt.w.s.sx */, VE::VCVTWSSXv, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64 }, },
  { 2627 /* vcvt.w.s.sx */, VE::VCVTWSSXvm, Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64, MCK_VM }, },
  { 2639 /* vcvt.w.s.zx */, VE::VCVTWSZXv, Convert__Reg1_1__RDOp1_0__Reg1_2, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64 }, },
  { 2639 /* vcvt.w.s.zx */, VE::VCVTWSZXvm, Convert__Reg1_1__RDOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_RDOp, MCK_V64, MCK_V64, MCK_VM }, },
  { 2651 /* vdivs.l */, VE::VDIVSLrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2651 /* vdivs.l */, VE::VDIVSLvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2651 /* vdivs.l */, VE::VDIVSLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2651 /* vdivs.l */, VE::VDIVSLvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2651 /* vdivs.l */, VE::VDIVSLiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2651 /* vdivs.l */, VE::VDIVSLrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2651 /* vdivs.l */, VE::VDIVSLvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM }, },
  { 2651 /* vdivs.l */, VE::VDIVSLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2651 /* vdivs.l */, VE::VDIVSLvim, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2651 /* vdivs.l */, VE::VDIVSLivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32 }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32, MCK_VM }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXvim, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2659 /* vdivs.w.sx */, VE::VDIVSWSXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32 }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32, MCK_VM }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXvim, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2670 /* vdivs.w.zx */, VE::VDIVSWZXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2681 /* vdivu.l */, VE::VDIVULrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2681 /* vdivu.l */, VE::VDIVULvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2681 /* vdivu.l */, VE::VDIVULvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2681 /* vdivu.l */, VE::VDIVULvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2681 /* vdivu.l */, VE::VDIVULiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2681 /* vdivu.l */, VE::VDIVULrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2681 /* vdivu.l */, VE::VDIVULvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM }, },
  { 2681 /* vdivu.l */, VE::VDIVULvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2681 /* vdivu.l */, VE::VDIVULvim, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2681 /* vdivu.l */, VE::VDIVULivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2689 /* vdivu.w */, VE::VDIVUWrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 2689 /* vdivu.w */, VE::VDIVUWvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32 }, },
  { 2689 /* vdivu.w */, VE::VDIVUWvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2689 /* vdivu.w */, VE::VDIVUWvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2689 /* vdivu.w */, VE::VDIVUWiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2689 /* vdivu.w */, VE::VDIVUWrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 2689 /* vdivu.w */, VE::VDIVUWvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32, MCK_VM }, },
  { 2689 /* vdivu.w */, VE::VDIVUWvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2689 /* vdivu.w */, VE::VDIVUWvim, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2689 /* vdivu.w */, VE::VDIVUWivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2697 /* veqv */, VE::VEQVrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2697 /* veqv */, VE::VEQVvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2697 /* veqv */, VE::VEQVmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 2697 /* veqv */, VE::VEQVrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2697 /* veqv */, VE::VEQVvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2697 /* veqv */, VE::VEQVmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 2702 /* vex */, VE::VEXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2702 /* vex */, VE::VEXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2706 /* vfadd.d */, VE::VFADDDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2706 /* vfadd.d */, VE::VFADDDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2706 /* vfadd.d */, VE::VFADDDiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2706 /* vfadd.d */, VE::VFADDDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2706 /* vfadd.d */, VE::VFADDDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2706 /* vfadd.d */, VE::VFADDDivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2714 /* vfcmp.d */, VE::VFCMPDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2714 /* vfcmp.d */, VE::VFCMPDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2714 /* vfcmp.d */, VE::VFCMPDiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2714 /* vfcmp.d */, VE::VFCMPDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2714 /* vfcmp.d */, VE::VFCMPDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2714 /* vfcmp.d */, VE::VFCMPDivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDvim, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2722 /* vfdiv.d */, VE::VFDIVDivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64 }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32 }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_F32, MCK_V64, MCK_VM }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32, MCK_VM }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSvim, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_VM }, },
  { 2730 /* vfdiv.s */, VE::VFDIVSivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2738 /* vfia.d */, VE::VFIADvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2738 /* vfia.d */, VE::VFIADvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2745 /* vfia.s */, VE::VFIASvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32 }, },
  { 2745 /* vfia.s */, VE::VFIASvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2752 /* vfiam.d */, VE::VFIAMDvvr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_I64 }, },
  { 2752 /* vfiam.d */, VE::VFIAMDvvi, Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2760 /* vfiam.s */, VE::VFIAMSvvr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_F32 }, },
  { 2760 /* vfiam.s */, VE::VFIAMSvvi, Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2768 /* vfim.d */, VE::VFIMDvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2768 /* vfim.d */, VE::VFIMDvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2775 /* vfim.s */, VE::VFIMSvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32 }, },
  { 2775 /* vfim.s */, VE::VFIMSvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2782 /* vfima.d */, VE::VFIMADvvr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_I64 }, },
  { 2782 /* vfima.d */, VE::VFIMADvvi, Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2790 /* vfima.s */, VE::VFIMASvvr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_F32 }, },
  { 2790 /* vfima.s */, VE::VFIMASvvi, Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2798 /* vfims.d */, VE::VFIMSDvvr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_I64 }, },
  { 2798 /* vfims.d */, VE::VFIMSDvvi, Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2806 /* vfims.s */, VE::VFIMSSvvr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_F32 }, },
  { 2806 /* vfims.s */, VE::VFIMSSvvi, Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2814 /* vfis.d */, VE::VFISDvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 2814 /* vfis.d */, VE::VFISDvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2821 /* vfis.s */, VE::VFISSvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_F32 }, },
  { 2821 /* vfis.s */, VE::VFISSvi, Convert__Reg1_0__Reg1_1__SImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2828 /* vfism.d */, VE::VFISMDvvr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_I64 }, },
  { 2828 /* vfism.d */, VE::VFISMDvvi, Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2836 /* vfism.s */, VE::VFISMSvvr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_F32 }, },
  { 2836 /* vfism.s */, VE::VFISMSvvi, Convert__Reg1_0__Reg1_1__Reg1_2__SImm71_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_SImm7 }, },
  { 2844 /* vfmad.d */, VE::VFMADDrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 2844 /* vfmad.d */, VE::VFMADDvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 2844 /* vfmad.d */, VE::VFMADDvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 2844 /* vfmad.d */, VE::VFMADDviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2844 /* vfmad.d */, VE::VFMADDivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 2844 /* vfmad.d */, VE::VFMADDrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2844 /* vfmad.d */, VE::VFMADDvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2844 /* vfmad.d */, VE::VFMADDvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2844 /* vfmad.d */, VE::VFMADDvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2844 /* vfmad.d */, VE::VFMADDivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 2852 /* vfmax.d */, VE::VFMAXDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2852 /* vfmax.d */, VE::VFMAXDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2852 /* vfmax.d */, VE::VFMAXDiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2852 /* vfmax.d */, VE::VFMAXDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2852 /* vfmax.d */, VE::VFMAXDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2852 /* vfmax.d */, VE::VFMAXDivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2860 /* vfmin.d */, VE::VFMINDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2860 /* vfmin.d */, VE::VFMINDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2860 /* vfmin.d */, VE::VFMINDiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2860 /* vfmin.d */, VE::VFMINDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2860 /* vfmin.d */, VE::VFMINDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2860 /* vfmin.d */, VE::VFMINDivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2868 /* vfmk.d. */, VE::VFMKDv, Convert__Reg1_1__CCOp1_0__Reg1_2, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64 }, },
  { 2868 /* vfmk.d. */, VE::VFMKDvm, Convert__Reg1_1__CCOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64, MCK_VM }, },
  { 2876 /* vfmk.d.af */, VE::VFMKDna, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 2876 /* vfmk.d.af */, VE::VFMKDnam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 2886 /* vfmk.d.at */, VE::VFMKDa, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 2886 /* vfmk.d.at */, VE::VFMKDam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 2896 /* vfmk.l. */, VE::VFMKLv, Convert__Reg1_1__CCOp1_0__Reg1_2, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64 }, },
  { 2896 /* vfmk.l. */, VE::VFMKLvm, Convert__Reg1_1__CCOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64, MCK_VM }, },
  { 2904 /* vfmk.l.af */, VE::VFMKLna, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 2904 /* vfmk.l.af */, VE::VFMKLnam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 2914 /* vfmk.l.at */, VE::VFMKLa, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 2914 /* vfmk.l.at */, VE::VFMKLam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 2924 /* vfmk.w. */, VE::VFMKWv, Convert__Reg1_1__CCOp1_0__Reg1_2, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64 }, },
  { 2924 /* vfmk.w. */, VE::VFMKWvm, Convert__Reg1_1__CCOp1_0__Reg1_2__Reg1_3, AMFBS_None, { MCK_CCOp, MCK_VM, MCK_V64, MCK_VM }, },
  { 2932 /* vfmk.w.af */, VE::VFMKWna, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 2932 /* vfmk.w.af */, VE::VFMKWnam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 2942 /* vfmk.w.at */, VE::VFMKWa, Convert__Reg1_0, AMFBS_None, { MCK_VM }, },
  { 2942 /* vfmk.w.at */, VE::VFMKWam, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_VM, MCK_VM }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2952 /* vfmsb.d */, VE::VFMSBDivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 2960 /* vfmul.d */, VE::VFMULDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 2960 /* vfmul.d */, VE::VFMULDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 2960 /* vfmul.d */, VE::VFMULDiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2960 /* vfmul.d */, VE::VFMULDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2960 /* vfmul.d */, VE::VFMULDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2960 /* vfmul.d */, VE::VFMULDivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2968 /* vfnmad.d */, VE::VFNMADDivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDrvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64 }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDvrv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64 }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDvvv, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64 }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDviv, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDivv, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64 }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDrvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDvrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDvvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDvivm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 2977 /* vfnmsb.d */, VE::VFNMSBDivvm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_V64, MCK_VM }, },
  { 2986 /* vfrmax.d.fst */, VE::VFRMAXDFSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2986 /* vfrmax.d.fst */, VE::VFRMAXDFSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 2999 /* vfrmax.d.lst */, VE::VFRMAXDLSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 2999 /* vfrmax.d.lst */, VE::VFRMAXDLSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3012 /* vfrmax.s.fst */, VE::VFRMAXSFSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3012 /* vfrmax.s.fst */, VE::VFRMAXSFSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3025 /* vfrmax.s.lst */, VE::VFRMAXSLSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3025 /* vfrmax.s.lst */, VE::VFRMAXSLSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3038 /* vfrmin.d.fst */, VE::VFRMINDFSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3038 /* vfrmin.d.fst */, VE::VFRMINDFSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3051 /* vfrmin.d.lst */, VE::VFRMINDLSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3051 /* vfrmin.d.lst */, VE::VFRMINDLSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3064 /* vfrmin.s.fst */, VE::VFRMINSFSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3064 /* vfrmin.s.fst */, VE::VFRMINSFSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3077 /* vfrmin.s.lst */, VE::VFRMINSLSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3077 /* vfrmin.s.lst */, VE::VFRMINSLSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3090 /* vfsqrt.d */, VE::VFSQRTDv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3090 /* vfsqrt.d */, VE::VFSQRTDvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3099 /* vfsqrt.s */, VE::VFSQRTSv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3099 /* vfsqrt.s */, VE::VFSQRTSvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3108 /* vfsub.d */, VE::VFSUBDrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 3108 /* vfsub.d */, VE::VFSUBDvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3108 /* vfsub.d */, VE::VFSUBDiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3108 /* vfsub.d */, VE::VFSUBDrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 3108 /* vfsub.d */, VE::VFSUBDvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3108 /* vfsub.d */, VE::VFSUBDivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3116 /* vfsum.d */, VE::VFSUMDv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3116 /* vfsum.d */, VE::VFSUMDvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3124 /* vfsum.s */, VE::VFSUMSv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3124 /* vfsum.s */, VE::VFSUMSvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3132 /* vgt */, VE::VGTsrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3132 /* vgt */, VE::VGTsrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3132 /* vgt */, VE::VGTsir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3132 /* vgt */, VE::VGTsiz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3132 /* vgt */, VE::VGTvrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3132 /* vgt */, VE::VGTvrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3132 /* vgt */, VE::VGTvir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3132 /* vgt */, VE::VGTviz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3132 /* vgt */, VE::VGTsrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3132 /* vgt */, VE::VGTsrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3132 /* vgt */, VE::VGTsirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3132 /* vgt */, VE::VGTsizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3132 /* vgt */, VE::VGTvrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3132 /* vgt */, VE::VGTvrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3132 /* vgt */, VE::VGTvirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3132 /* vgt */, VE::VGTvizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3136 /* vgt.nc */, VE::VGTNCsrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3136 /* vgt.nc */, VE::VGTNCsrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3136 /* vgt.nc */, VE::VGTNCsir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3136 /* vgt.nc */, VE::VGTNCsiz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3136 /* vgt.nc */, VE::VGTNCvrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3136 /* vgt.nc */, VE::VGTNCvrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3136 /* vgt.nc */, VE::VGTNCvir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3136 /* vgt.nc */, VE::VGTNCviz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3136 /* vgt.nc */, VE::VGTNCsrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3136 /* vgt.nc */, VE::VGTNCsrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3136 /* vgt.nc */, VE::VGTNCsirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3136 /* vgt.nc */, VE::VGTNCsizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3136 /* vgt.nc */, VE::VGTNCvrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3136 /* vgt.nc */, VE::VGTNCvrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3136 /* vgt.nc */, VE::VGTNCvirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3136 /* vgt.nc */, VE::VGTNCvizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXsrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXsrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXsir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXsiz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXvrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXvrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXvir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXviz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXsrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXsrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXsirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXsizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXvrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXvrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXvirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3143 /* vgtl.sx */, VE::VGTLSXvizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCsrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCsrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCsir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCsiz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCvrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCvrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCvir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCviz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCsrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCsrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCsirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCsizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCvrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCvrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCvirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3151 /* vgtl.sx.nc */, VE::VGTLSXNCvizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXsrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXsrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXsir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXsiz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXvrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXvrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXvir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXviz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXsrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXsrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXsirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXsizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXvrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXvrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXvirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3162 /* vgtl.zx */, VE::VGTLZXvizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCsrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCsrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCsir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCsiz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCvrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCvrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCvir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCviz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCsrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCsrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCsirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCsizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCvrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCvrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCvirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3170 /* vgtl.zx.nc */, VE::VGTLZXNCvizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3181 /* vgtu */, VE::VGTUsrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3181 /* vgtu */, VE::VGTUsrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3181 /* vgtu */, VE::VGTUsir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3181 /* vgtu */, VE::VGTUsiz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3181 /* vgtu */, VE::VGTUvrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3181 /* vgtu */, VE::VGTUvrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3181 /* vgtu */, VE::VGTUvir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3181 /* vgtu */, VE::VGTUviz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3181 /* vgtu */, VE::VGTUsrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3181 /* vgtu */, VE::VGTUsrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3181 /* vgtu */, VE::VGTUsirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3181 /* vgtu */, VE::VGTUsizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3181 /* vgtu */, VE::VGTUvrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3181 /* vgtu */, VE::VGTUvrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3181 /* vgtu */, VE::VGTUvirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3181 /* vgtu */, VE::VGTUvizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCsrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCsrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCsir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCsiz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCvrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCvrz, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCvir, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCviz, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCsrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCsrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCsirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCsizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCvrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCvrzm, Convert__Reg1_0__Reg1_1__Reg1_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCvirm, Convert__Reg1_0__Reg1_1__SImm71_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3186 /* vgtu.nc */, VE::VGTUNCvizm, Convert__Reg1_0__Reg1_1__SImm71_2__Zero1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3194 /* vld */, VE::VLDrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3194 /* vld */, VE::VLDrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3194 /* vld */, VE::VLDir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3194 /* vld */, VE::VLDiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3198 /* vld.nc */, VE::VLDNCrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3198 /* vld.nc */, VE::VLDNCrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3198 /* vld.nc */, VE::VLDNCir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3198 /* vld.nc */, VE::VLDNCiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3205 /* vld2d */, VE::VLD2Drr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3205 /* vld2d */, VE::VLD2Drz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3205 /* vld2d */, VE::VLD2Dir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3205 /* vld2d */, VE::VLD2Diz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3211 /* vld2d.nc */, VE::VLD2DNCrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3211 /* vld2d.nc */, VE::VLD2DNCrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3211 /* vld2d.nc */, VE::VLD2DNCir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3211 /* vld2d.nc */, VE::VLD2DNCiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3220 /* vldl.sx */, VE::VLDLSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3220 /* vldl.sx */, VE::VLDLSXrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3220 /* vldl.sx */, VE::VLDLSXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3220 /* vldl.sx */, VE::VLDLSXiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3228 /* vldl.sx.nc */, VE::VLDLSXNCrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3228 /* vldl.sx.nc */, VE::VLDLSXNCrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3228 /* vldl.sx.nc */, VE::VLDLSXNCir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3228 /* vldl.sx.nc */, VE::VLDLSXNCiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3239 /* vldl.zx */, VE::VLDLZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3239 /* vldl.zx */, VE::VLDLZXrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3239 /* vldl.zx */, VE::VLDLZXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3239 /* vldl.zx */, VE::VLDLZXiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3247 /* vldl.zx.nc */, VE::VLDLZXNCrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3247 /* vldl.zx.nc */, VE::VLDLZXNCrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3247 /* vldl.zx.nc */, VE::VLDLZXNCir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3247 /* vldl.zx.nc */, VE::VLDLZXNCiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3258 /* vldl2d.sx */, VE::VLDL2DSXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3258 /* vldl2d.sx */, VE::VLDL2DSXrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3258 /* vldl2d.sx */, VE::VLDL2DSXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3258 /* vldl2d.sx */, VE::VLDL2DSXiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3268 /* vldl2d.sx.nc */, VE::VLDL2DSXNCrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3268 /* vldl2d.sx.nc */, VE::VLDL2DSXNCrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3268 /* vldl2d.sx.nc */, VE::VLDL2DSXNCir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3268 /* vldl2d.sx.nc */, VE::VLDL2DSXNCiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3281 /* vldl2d.zx */, VE::VLDL2DZXrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3281 /* vldl2d.zx */, VE::VLDL2DZXrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3281 /* vldl2d.zx */, VE::VLDL2DZXir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3281 /* vldl2d.zx */, VE::VLDL2DZXiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3291 /* vldl2d.zx.nc */, VE::VLDL2DZXNCrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3291 /* vldl2d.zx.nc */, VE::VLDL2DZXNCrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3291 /* vldl2d.zx.nc */, VE::VLDL2DZXNCir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3291 /* vldl2d.zx.nc */, VE::VLDL2DZXNCiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3304 /* vldu */, VE::VLDUrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3304 /* vldu */, VE::VLDUrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3304 /* vldu */, VE::VLDUir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3304 /* vldu */, VE::VLDUiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3309 /* vldu.nc */, VE::VLDUNCrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3309 /* vldu.nc */, VE::VLDUNCrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3309 /* vldu.nc */, VE::VLDUNCir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3309 /* vldu.nc */, VE::VLDUNCiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3317 /* vldu2d */, VE::VLDU2Drr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3317 /* vldu2d */, VE::VLDU2Drz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3317 /* vldu2d */, VE::VLDU2Dir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3317 /* vldu2d */, VE::VLDU2Diz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3324 /* vldu2d.nc */, VE::VLDU2DNCrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3324 /* vldu2d.nc */, VE::VLDU2DNCrz, Convert__Reg1_0__Reg1_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3324 /* vldu2d.nc */, VE::VLDU2DNCir, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3324 /* vldu2d.nc */, VE::VLDU2DNCiz, Convert__Reg1_0__SImm71_1__Zero1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3334 /* vldz */, VE::VLDZv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3334 /* vldz */, VE::VLDZvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3339 /* vmaxs.l */, VE::VMAXSLrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 3339 /* vmaxs.l */, VE::VMAXSLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3339 /* vmaxs.l */, VE::VMAXSLiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3339 /* vmaxs.l */, VE::VMAXSLrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 3339 /* vmaxs.l */, VE::VMAXSLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3339 /* vmaxs.l */, VE::VMAXSLivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3347 /* vmaxs.w.sx */, VE::VMAXSWSXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 3347 /* vmaxs.w.sx */, VE::VMAXSWSXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3347 /* vmaxs.w.sx */, VE::VMAXSWSXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3347 /* vmaxs.w.sx */, VE::VMAXSWSXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 3347 /* vmaxs.w.sx */, VE::VMAXSWSXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3347 /* vmaxs.w.sx */, VE::VMAXSWSXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3358 /* vmins.l */, VE::VMINSLrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 3358 /* vmins.l */, VE::VMINSLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3358 /* vmins.l */, VE::VMINSLiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3358 /* vmins.l */, VE::VMINSLrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 3358 /* vmins.l */, VE::VMINSLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3358 /* vmins.l */, VE::VMINSLivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3366 /* vmins.w.sx */, VE::VMINSWSXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 3366 /* vmins.w.sx */, VE::VMINSWSXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3366 /* vmins.w.sx */, VE::VMINSWSXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3366 /* vmins.w.sx */, VE::VMINSWSXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 3366 /* vmins.w.sx */, VE::VMINSWSXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3366 /* vmins.w.sx */, VE::VMINSWSXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3377 /* vmrg */, VE::VMRGrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 3377 /* vmrg */, VE::VMRGvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3377 /* vmrg */, VE::VMRGiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3377 /* vmrg */, VE::VMRGrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 3377 /* vmrg */, VE::VMRGvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3377 /* vmrg */, VE::VMRGivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3382 /* vmrg.w */, VE::VMRGWrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 3382 /* vmrg.w */, VE::VMRGWvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3382 /* vmrg.w */, VE::VMRGWiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3382 /* vmrg.w */, VE::VMRGWrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM512 }, },
  { 3382 /* vmrg.w */, VE::VMRGWvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM512 }, },
  { 3382 /* vmrg.w */, VE::VMRGWivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM512 }, },
  { 3389 /* vmuls.l */, VE::VMULSLrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 3389 /* vmuls.l */, VE::VMULSLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3389 /* vmuls.l */, VE::VMULSLiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3389 /* vmuls.l */, VE::VMULSLrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 3389 /* vmuls.l */, VE::VMULSLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3389 /* vmuls.l */, VE::VMULSLivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3397 /* vmuls.l.w */, VE::VMULSLWrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 3397 /* vmuls.l.w */, VE::VMULSLWvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3397 /* vmuls.l.w */, VE::VMULSLWiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3397 /* vmuls.l.w */, VE::VMULSLWrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 3397 /* vmuls.l.w */, VE::VMULSLWvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3397 /* vmuls.l.w */, VE::VMULSLWivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3407 /* vmuls.w.sx */, VE::VMULSWSXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 3407 /* vmuls.w.sx */, VE::VMULSWSXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3407 /* vmuls.w.sx */, VE::VMULSWSXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3407 /* vmuls.w.sx */, VE::VMULSWSXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 3407 /* vmuls.w.sx */, VE::VMULSWSXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3407 /* vmuls.w.sx */, VE::VMULSWSXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3418 /* vmuls.w.zx */, VE::VMULSWZXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 3418 /* vmuls.w.zx */, VE::VMULSWZXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3418 /* vmuls.w.zx */, VE::VMULSWZXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3418 /* vmuls.w.zx */, VE::VMULSWZXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 3418 /* vmuls.w.zx */, VE::VMULSWZXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3418 /* vmuls.w.zx */, VE::VMULSWZXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3429 /* vmulu.l */, VE::VMULULrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 3429 /* vmulu.l */, VE::VMULULvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3429 /* vmulu.l */, VE::VMULULiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3429 /* vmulu.l */, VE::VMULULrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 3429 /* vmulu.l */, VE::VMULULvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3429 /* vmulu.l */, VE::VMULULivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3437 /* vmulu.w */, VE::VMULUWrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 3437 /* vmulu.w */, VE::VMULUWvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3437 /* vmulu.w */, VE::VMULUWiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 3437 /* vmulu.w */, VE::VMULUWrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 3437 /* vmulu.w */, VE::VMULUWvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3437 /* vmulu.w */, VE::VMULUWivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 3445 /* vmv */, VE::VMVrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 3445 /* vmv */, VE::VMViv, Convert__Reg1_0__UImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_UImm7, MCK_V64 }, },
  { 3445 /* vmv */, VE::VMVrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 3445 /* vmv */, VE::VMVivm, Convert__Reg1_0__UImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_UImm7, MCK_V64, MCK_VM }, },
  { 3449 /* vor */, VE::VORrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 3449 /* vor */, VE::VORvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3449 /* vor */, VE::VORmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 3449 /* vor */, VE::VORrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 3449 /* vor */, VE::VORvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3449 /* vor */, VE::VORmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 3453 /* vpcnt */, VE::VPCNTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3453 /* vpcnt */, VE::VPCNTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3459 /* vrand */, VE::VRANDv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3459 /* vrand */, VE::VRANDvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3465 /* vrcp.d */, VE::VRCPDv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3465 /* vrcp.d */, VE::VRCPDvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3472 /* vrmaxs.l.fst */, VE::VRMAXSLFSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3472 /* vrmaxs.l.fst */, VE::VRMAXSLFSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3485 /* vrmaxs.l.lst */, VE::VRMAXSLLSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3485 /* vrmaxs.l.lst */, VE::VRMAXSLLSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3498 /* vrmaxs.w.fst.sx */, VE::VRMAXSWFSTSXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3498 /* vrmaxs.w.fst.sx */, VE::VRMAXSWFSTSXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3514 /* vrmaxs.w.fst.zx */, VE::VRMAXSWFSTZXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3514 /* vrmaxs.w.fst.zx */, VE::VRMAXSWFSTZXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3530 /* vrmaxs.w.lst.sx */, VE::VRMAXSWLSTSXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3530 /* vrmaxs.w.lst.sx */, VE::VRMAXSWLSTSXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3546 /* vrmaxs.w.lst.zx */, VE::VRMAXSWLSTZXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3546 /* vrmaxs.w.lst.zx */, VE::VRMAXSWLSTZXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3562 /* vrmins.l.fst */, VE::VRMINSLFSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3562 /* vrmins.l.fst */, VE::VRMINSLFSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3575 /* vrmins.l.lst */, VE::VRMINSLLSTv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3575 /* vrmins.l.lst */, VE::VRMINSLLSTvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3588 /* vrmins.w.fst.sx */, VE::VRMINSWFSTSXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3588 /* vrmins.w.fst.sx */, VE::VRMINSWFSTSXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3604 /* vrmins.w.fst.zx */, VE::VRMINSWFSTZXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3604 /* vrmins.w.fst.zx */, VE::VRMINSWFSTZXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3620 /* vrmins.w.lst.sx */, VE::VRMINSWLSTSXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3620 /* vrmins.w.lst.sx */, VE::VRMINSWLSTSXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3636 /* vrmins.w.lst.zx */, VE::VRMINSWLSTZXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3636 /* vrmins.w.lst.zx */, VE::VRMINSWLSTZXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3652 /* vror */, VE::VRORv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3652 /* vror */, VE::VRORvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3657 /* vrsqrt.d */, VE::VRSQRTDv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3657 /* vrsqrt.d */, VE::VRSQRTDvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3666 /* vrsqrt.d.nex */, VE::VRSQRTDNEXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3666 /* vrsqrt.d.nex */, VE::VRSQRTDNEXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3679 /* vrxor */, VE::VRXORv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 3679 /* vrxor */, VE::VRXORvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 3685 /* vsc */, VE::VSCsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3685 /* vsc */, VE::VSCsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3685 /* vsc */, VE::VSCsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3685 /* vsc */, VE::VSCsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3685 /* vsc */, VE::VSCvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3685 /* vsc */, VE::VSCvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3685 /* vsc */, VE::VSCvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3685 /* vsc */, VE::VSCvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3685 /* vsc */, VE::VSCsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3685 /* vsc */, VE::VSCsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3685 /* vsc */, VE::VSCsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3685 /* vsc */, VE::VSCsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3685 /* vsc */, VE::VSCvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3685 /* vsc */, VE::VSCvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3685 /* vsc */, VE::VSCvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3685 /* vsc */, VE::VSCvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3689 /* vsc.nc */, VE::VSCNCsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3689 /* vsc.nc */, VE::VSCNCsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3689 /* vsc.nc */, VE::VSCNCsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3689 /* vsc.nc */, VE::VSCNCsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3689 /* vsc.nc */, VE::VSCNCvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3689 /* vsc.nc */, VE::VSCNCvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3689 /* vsc.nc */, VE::VSCNCvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3689 /* vsc.nc */, VE::VSCNCvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3689 /* vsc.nc */, VE::VSCNCsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3689 /* vsc.nc */, VE::VSCNCsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3689 /* vsc.nc */, VE::VSCNCsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3689 /* vsc.nc */, VE::VSCNCsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3689 /* vsc.nc */, VE::VSCNCvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3689 /* vsc.nc */, VE::VSCNCvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3689 /* vsc.nc */, VE::VSCNCvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3689 /* vsc.nc */, VE::VSCNCvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3696 /* vsc.nc.ot */, VE::VSCNCOTvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3706 /* vsc.ot */, VE::VSCOTsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3706 /* vsc.ot */, VE::VSCOTsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3706 /* vsc.ot */, VE::VSCOTsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3706 /* vsc.ot */, VE::VSCOTsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3706 /* vsc.ot */, VE::VSCOTvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3706 /* vsc.ot */, VE::VSCOTvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3706 /* vsc.ot */, VE::VSCOTvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3706 /* vsc.ot */, VE::VSCOTvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3706 /* vsc.ot */, VE::VSCOTsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3706 /* vsc.ot */, VE::VSCOTsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3706 /* vsc.ot */, VE::VSCOTsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3706 /* vsc.ot */, VE::VSCOTsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3706 /* vsc.ot */, VE::VSCOTvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3706 /* vsc.ot */, VE::VSCOTvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3706 /* vsc.ot */, VE::VSCOTvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3706 /* vsc.ot */, VE::VSCOTvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3713 /* vscl */, VE::VSCLsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3713 /* vscl */, VE::VSCLsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3713 /* vscl */, VE::VSCLsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3713 /* vscl */, VE::VSCLsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3713 /* vscl */, VE::VSCLvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3713 /* vscl */, VE::VSCLvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3713 /* vscl */, VE::VSCLvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3713 /* vscl */, VE::VSCLvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3713 /* vscl */, VE::VSCLsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3713 /* vscl */, VE::VSCLsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3713 /* vscl */, VE::VSCLsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3713 /* vscl */, VE::VSCLsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3713 /* vscl */, VE::VSCLvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3713 /* vscl */, VE::VSCLvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3713 /* vscl */, VE::VSCLvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3713 /* vscl */, VE::VSCLvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3718 /* vscl.nc */, VE::VSCLNCsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3718 /* vscl.nc */, VE::VSCLNCsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3718 /* vscl.nc */, VE::VSCLNCsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3718 /* vscl.nc */, VE::VSCLNCsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3718 /* vscl.nc */, VE::VSCLNCvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3718 /* vscl.nc */, VE::VSCLNCvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3718 /* vscl.nc */, VE::VSCLNCvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3718 /* vscl.nc */, VE::VSCLNCvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3718 /* vscl.nc */, VE::VSCLNCsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3718 /* vscl.nc */, VE::VSCLNCsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3718 /* vscl.nc */, VE::VSCLNCsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3718 /* vscl.nc */, VE::VSCLNCsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3718 /* vscl.nc */, VE::VSCLNCvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3718 /* vscl.nc */, VE::VSCLNCvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3718 /* vscl.nc */, VE::VSCLNCvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3718 /* vscl.nc */, VE::VSCLNCvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3726 /* vscl.nc.ot */, VE::VSCLNCOTvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3737 /* vscl.ot */, VE::VSCLOTsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3737 /* vscl.ot */, VE::VSCLOTsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3737 /* vscl.ot */, VE::VSCLOTsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3737 /* vscl.ot */, VE::VSCLOTsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3737 /* vscl.ot */, VE::VSCLOTvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3737 /* vscl.ot */, VE::VSCLOTvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3737 /* vscl.ot */, VE::VSCLOTvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3737 /* vscl.ot */, VE::VSCLOTvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3737 /* vscl.ot */, VE::VSCLOTsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3737 /* vscl.ot */, VE::VSCLOTsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3737 /* vscl.ot */, VE::VSCLOTsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3737 /* vscl.ot */, VE::VSCLOTsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3737 /* vscl.ot */, VE::VSCLOTvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3737 /* vscl.ot */, VE::VSCLOTvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3737 /* vscl.ot */, VE::VSCLOTvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3737 /* vscl.ot */, VE::VSCLOTvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3745 /* vscu */, VE::VSCUsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3745 /* vscu */, VE::VSCUsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3745 /* vscu */, VE::VSCUsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3745 /* vscu */, VE::VSCUsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3745 /* vscu */, VE::VSCUvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3745 /* vscu */, VE::VSCUvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3745 /* vscu */, VE::VSCUvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3745 /* vscu */, VE::VSCUvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3745 /* vscu */, VE::VSCUsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3745 /* vscu */, VE::VSCUsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3745 /* vscu */, VE::VSCUsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3745 /* vscu */, VE::VSCUsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3745 /* vscu */, VE::VSCUvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3745 /* vscu */, VE::VSCUvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3745 /* vscu */, VE::VSCUvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3745 /* vscu */, VE::VSCUvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3750 /* vscu.nc */, VE::VSCUNCsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3750 /* vscu.nc */, VE::VSCUNCsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3750 /* vscu.nc */, VE::VSCUNCsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3750 /* vscu.nc */, VE::VSCUNCsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3750 /* vscu.nc */, VE::VSCUNCvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3750 /* vscu.nc */, VE::VSCUNCvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3750 /* vscu.nc */, VE::VSCUNCvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3750 /* vscu.nc */, VE::VSCUNCvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3750 /* vscu.nc */, VE::VSCUNCsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3750 /* vscu.nc */, VE::VSCUNCsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3750 /* vscu.nc */, VE::VSCUNCsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3750 /* vscu.nc */, VE::VSCUNCsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3750 /* vscu.nc */, VE::VSCUNCvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3750 /* vscu.nc */, VE::VSCUNCvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3750 /* vscu.nc */, VE::VSCUNCvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3750 /* vscu.nc */, VE::VSCUNCvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3758 /* vscu.nc.ot */, VE::VSCUNCOTvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3769 /* vscu.ot */, VE::VSCUOTsrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64 }, },
  { 3769 /* vscu.ot */, VE::VSCUOTsrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero }, },
  { 3769 /* vscu.ot */, VE::VSCUOTsirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 3769 /* vscu.ot */, VE::VSCUOTsizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero }, },
  { 3769 /* vscu.ot */, VE::VSCUOTvrrv, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3769 /* vscu.ot */, VE::VSCUOTvrzv, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero }, },
  { 3769 /* vscu.ot */, VE::VSCUOTvirv, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3769 /* vscu.ot */, VE::VSCUOTvizv, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3769 /* vscu.ot */, VE::VSCUOTsrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3769 /* vscu.ot */, VE::VSCUOTsrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3769 /* vscu.ot */, VE::VSCUOTsirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3769 /* vscu.ot */, VE::VSCUOTsizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_I64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3769 /* vscu.ot */, VE::VSCUOTvrrvm, Convert__Reg1_1__Reg1_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3769 /* vscu.ot */, VE::VSCUOTvrzvm, Convert__Reg1_1__Reg1_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3769 /* vscu.ot */, VE::VSCUOTvirvm, Convert__Reg1_1__SImm71_2__Reg1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3769 /* vscu.ot */, VE::VSCUOTvizvm, Convert__Reg1_1__SImm71_2__Zero1_3__Reg1_0__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3777 /* vseq */, VE::VSEQ, Convert__Reg1_0, AMFBS_None, { MCK_V64 }, },
  { 3777 /* vseq */, VE::VSEQm, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_VM }, },
  { 3782 /* vsfa */, VE::VSFAvrr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64 }, },
  { 3782 /* vsfa */, VE::VSFAvrm, Convert__Reg1_0__Reg1_1__Reg1_2__MImm1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_MImm }, },
  { 3782 /* vsfa */, VE::VSFAvir, Convert__Reg1_0__Reg1_1__UImm31_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm3, MCK_I64 }, },
  { 3782 /* vsfa */, VE::VSFAvim, Convert__Reg1_0__Reg1_1__UImm31_2__MImm1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm3, MCK_MImm }, },
  { 3782 /* vsfa */, VE::VSFAvrrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3782 /* vsfa */, VE::VSFAvrmm, Convert__Reg1_0__Reg1_1__Reg1_2__MImm1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_MImm, MCK_VM }, },
  { 3782 /* vsfa */, VE::VSFAvirm, Convert__Reg1_0__Reg1_1__UImm31_2__Reg1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm3, MCK_I64, MCK_VM }, },
  { 3782 /* vsfa */, VE::VSFAvimm, Convert__Reg1_0__Reg1_1__UImm31_2__MImm1_3__Reg1_4, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm3, MCK_MImm, MCK_VM }, },
  { 3787 /* vshf */, VE::VSHFvvr, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_I64 }, },
  { 3787 /* vshf */, VE::VSHFvvi, Convert__Reg1_0__Reg1_1__Reg1_2__UImm41_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_UImm4 }, },
  { 3792 /* vsla.l */, VE::VSLALvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 3792 /* vsla.l */, VE::VSLALvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3792 /* vsla.l */, VE::VSLALvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 3792 /* vsla.l */, VE::VSLALvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM }, },
  { 3792 /* vsla.l */, VE::VSLALvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3792 /* vsla.l */, VE::VSLALvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 3799 /* vsla.w.sx */, VE::VSLAWSXvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32 }, },
  { 3799 /* vsla.w.sx */, VE::VSLAWSXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3799 /* vsla.w.sx */, VE::VSLAWSXvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 3799 /* vsla.w.sx */, VE::VSLAWSXvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32, MCK_VM }, },
  { 3799 /* vsla.w.sx */, VE::VSLAWSXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3799 /* vsla.w.sx */, VE::VSLAWSXvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 3809 /* vsld */, VE::VSLDvvr, Convert__Reg1_0__Reg1_2__Reg1_3__Reg1_5, AMFBS_None, { MCK_V64, MCK__40_, MCK_V64, MCK_V64, MCK__41_, MCK_I64 }, },
  { 3809 /* vsld */, VE::VSLDvvi, Convert__Reg1_0__Reg1_2__Reg1_3__UImm71_5, AMFBS_None, { MCK_V64, MCK__40_, MCK_V64, MCK_V64, MCK__41_, MCK_UImm7 }, },
  { 3809 /* vsld */, VE::VSLDvvrm, Convert__Reg1_0__Reg1_2__Reg1_3__Reg1_5__Reg1_6, AMFBS_None, { MCK_V64, MCK__40_, MCK_V64, MCK_V64, MCK__41_, MCK_I64, MCK_VM }, },
  { 3809 /* vsld */, VE::VSLDvvim, Convert__Reg1_0__Reg1_2__Reg1_3__UImm71_5__Reg1_6, AMFBS_None, { MCK_V64, MCK__40_, MCK_V64, MCK_V64, MCK__41_, MCK_UImm7, MCK_VM }, },
  { 3814 /* vsll */, VE::VSLLvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 3814 /* vsll */, VE::VSLLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3814 /* vsll */, VE::VSLLvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 3814 /* vsll */, VE::VSLLvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM }, },
  { 3814 /* vsll */, VE::VSLLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3814 /* vsll */, VE::VSLLvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 3819 /* vsra.l */, VE::VSRALvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 3819 /* vsra.l */, VE::VSRALvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3819 /* vsra.l */, VE::VSRALvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 3819 /* vsra.l */, VE::VSRALvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM }, },
  { 3819 /* vsra.l */, VE::VSRALvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3819 /* vsra.l */, VE::VSRALvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 3826 /* vsra.w.sx */, VE::VSRAWSXvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32 }, },
  { 3826 /* vsra.w.sx */, VE::VSRAWSXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3826 /* vsra.w.sx */, VE::VSRAWSXvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 3826 /* vsra.w.sx */, VE::VSRAWSXvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I32, MCK_VM }, },
  { 3826 /* vsra.w.sx */, VE::VSRAWSXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3826 /* vsra.w.sx */, VE::VSRAWSXvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 3836 /* vsrd */, VE::VSRDvvr, Convert__Reg1_0__Reg1_2__Reg1_3__Reg1_5, AMFBS_None, { MCK_V64, MCK__40_, MCK_V64, MCK_V64, MCK__41_, MCK_I64 }, },
  { 3836 /* vsrd */, VE::VSRDvvi, Convert__Reg1_0__Reg1_2__Reg1_3__UImm71_5, AMFBS_None, { MCK_V64, MCK__40_, MCK_V64, MCK_V64, MCK__41_, MCK_UImm7 }, },
  { 3836 /* vsrd */, VE::VSRDvvrm, Convert__Reg1_0__Reg1_2__Reg1_3__Reg1_5__Reg1_6, AMFBS_None, { MCK_V64, MCK__40_, MCK_V64, MCK_V64, MCK__41_, MCK_I64, MCK_VM }, },
  { 3836 /* vsrd */, VE::VSRDvvim, Convert__Reg1_0__Reg1_2__Reg1_3__UImm71_5__Reg1_6, AMFBS_None, { MCK_V64, MCK__40_, MCK_V64, MCK_V64, MCK__41_, MCK_UImm7, MCK_VM }, },
  { 3841 /* vsrl */, VE::VSRLvr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64 }, },
  { 3841 /* vsrl */, VE::VSRLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 3841 /* vsrl */, VE::VSRLvi, Convert__Reg1_0__Reg1_1__UImm71_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7 }, },
  { 3841 /* vsrl */, VE::VSRLvrm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_I64, MCK_VM }, },
  { 3841 /* vsrl */, VE::VSRLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 3841 /* vsrl */, VE::VSRLvim, Convert__Reg1_0__Reg1_1__UImm71_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_UImm7, MCK_VM }, },
  { 3846 /* vst */, VE::VSTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3846 /* vst */, VE::VSTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3846 /* vst */, VE::VSTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3846 /* vst */, VE::VSTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3846 /* vst */, VE::VSTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3846 /* vst */, VE::VSTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3846 /* vst */, VE::VSTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3846 /* vst */, VE::VSTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3850 /* vst.nc */, VE::VSTNCrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3850 /* vst.nc */, VE::VSTNCrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3850 /* vst.nc */, VE::VSTNCirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3850 /* vst.nc */, VE::VSTNCizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3850 /* vst.nc */, VE::VSTNCrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3850 /* vst.nc */, VE::VSTNCrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3850 /* vst.nc */, VE::VSTNCirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3850 /* vst.nc */, VE::VSTNCizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3857 /* vst.nc.ot */, VE::VSTNCOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3857 /* vst.nc.ot */, VE::VSTNCOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3857 /* vst.nc.ot */, VE::VSTNCOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3857 /* vst.nc.ot */, VE::VSTNCOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3857 /* vst.nc.ot */, VE::VSTNCOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3857 /* vst.nc.ot */, VE::VSTNCOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3857 /* vst.nc.ot */, VE::VSTNCOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3857 /* vst.nc.ot */, VE::VSTNCOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3867 /* vst.ot */, VE::VSTOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3867 /* vst.ot */, VE::VSTOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3867 /* vst.ot */, VE::VSTOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3867 /* vst.ot */, VE::VSTOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3867 /* vst.ot */, VE::VSTOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3867 /* vst.ot */, VE::VSTOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3867 /* vst.ot */, VE::VSTOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3867 /* vst.ot */, VE::VSTOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3874 /* vst2d */, VE::VST2Drrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3874 /* vst2d */, VE::VST2Drzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3874 /* vst2d */, VE::VST2Dirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3874 /* vst2d */, VE::VST2Dizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3874 /* vst2d */, VE::VST2Drrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3874 /* vst2d */, VE::VST2Drzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3874 /* vst2d */, VE::VST2Dirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3874 /* vst2d */, VE::VST2Dizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3880 /* vst2d.nc */, VE::VST2DNCrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3880 /* vst2d.nc */, VE::VST2DNCrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3880 /* vst2d.nc */, VE::VST2DNCirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3880 /* vst2d.nc */, VE::VST2DNCizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3880 /* vst2d.nc */, VE::VST2DNCrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3880 /* vst2d.nc */, VE::VST2DNCrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3880 /* vst2d.nc */, VE::VST2DNCirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3880 /* vst2d.nc */, VE::VST2DNCizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3889 /* vst2d.nc.ot */, VE::VST2DNCOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3889 /* vst2d.nc.ot */, VE::VST2DNCOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3889 /* vst2d.nc.ot */, VE::VST2DNCOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3889 /* vst2d.nc.ot */, VE::VST2DNCOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3889 /* vst2d.nc.ot */, VE::VST2DNCOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3889 /* vst2d.nc.ot */, VE::VST2DNCOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3889 /* vst2d.nc.ot */, VE::VST2DNCOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3889 /* vst2d.nc.ot */, VE::VST2DNCOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3901 /* vst2d.ot */, VE::VST2DOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3901 /* vst2d.ot */, VE::VST2DOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3901 /* vst2d.ot */, VE::VST2DOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3901 /* vst2d.ot */, VE::VST2DOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3901 /* vst2d.ot */, VE::VST2DOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3901 /* vst2d.ot */, VE::VST2DOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3901 /* vst2d.ot */, VE::VST2DOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3901 /* vst2d.ot */, VE::VST2DOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3910 /* vstl */, VE::VSTLrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3910 /* vstl */, VE::VSTLrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3910 /* vstl */, VE::VSTLirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3910 /* vstl */, VE::VSTLizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3910 /* vstl */, VE::VSTLrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3910 /* vstl */, VE::VSTLrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3910 /* vstl */, VE::VSTLirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3910 /* vstl */, VE::VSTLizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3915 /* vstl.nc */, VE::VSTLNCrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3915 /* vstl.nc */, VE::VSTLNCrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3915 /* vstl.nc */, VE::VSTLNCirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3915 /* vstl.nc */, VE::VSTLNCizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3915 /* vstl.nc */, VE::VSTLNCrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3915 /* vstl.nc */, VE::VSTLNCrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3915 /* vstl.nc */, VE::VSTLNCirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3915 /* vstl.nc */, VE::VSTLNCizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3923 /* vstl.nc.ot */, VE::VSTLNCOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3923 /* vstl.nc.ot */, VE::VSTLNCOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3923 /* vstl.nc.ot */, VE::VSTLNCOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3923 /* vstl.nc.ot */, VE::VSTLNCOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3923 /* vstl.nc.ot */, VE::VSTLNCOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3923 /* vstl.nc.ot */, VE::VSTLNCOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3923 /* vstl.nc.ot */, VE::VSTLNCOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3923 /* vstl.nc.ot */, VE::VSTLNCOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3934 /* vstl.ot */, VE::VSTLOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3934 /* vstl.ot */, VE::VSTLOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3934 /* vstl.ot */, VE::VSTLOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3934 /* vstl.ot */, VE::VSTLOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3934 /* vstl.ot */, VE::VSTLOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3934 /* vstl.ot */, VE::VSTLOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3934 /* vstl.ot */, VE::VSTLOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3934 /* vstl.ot */, VE::VSTLOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3942 /* vstl2d */, VE::VSTL2Drrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3942 /* vstl2d */, VE::VSTL2Drzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3942 /* vstl2d */, VE::VSTL2Dirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3942 /* vstl2d */, VE::VSTL2Dizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3942 /* vstl2d */, VE::VSTL2Drrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3942 /* vstl2d */, VE::VSTL2Drzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3942 /* vstl2d */, VE::VSTL2Dirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3942 /* vstl2d */, VE::VSTL2Dizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3949 /* vstl2d.nc */, VE::VSTL2DNCrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3949 /* vstl2d.nc */, VE::VSTL2DNCrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3949 /* vstl2d.nc */, VE::VSTL2DNCirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3949 /* vstl2d.nc */, VE::VSTL2DNCizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3949 /* vstl2d.nc */, VE::VSTL2DNCrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3949 /* vstl2d.nc */, VE::VSTL2DNCrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3949 /* vstl2d.nc */, VE::VSTL2DNCirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3949 /* vstl2d.nc */, VE::VSTL2DNCizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3959 /* vstl2d.nc.ot */, VE::VSTL2DNCOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3959 /* vstl2d.nc.ot */, VE::VSTL2DNCOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3959 /* vstl2d.nc.ot */, VE::VSTL2DNCOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3959 /* vstl2d.nc.ot */, VE::VSTL2DNCOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3959 /* vstl2d.nc.ot */, VE::VSTL2DNCOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3959 /* vstl2d.nc.ot */, VE::VSTL2DNCOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3959 /* vstl2d.nc.ot */, VE::VSTL2DNCOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3959 /* vstl2d.nc.ot */, VE::VSTL2DNCOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3972 /* vstl2d.ot */, VE::VSTL2DOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3972 /* vstl2d.ot */, VE::VSTL2DOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3972 /* vstl2d.ot */, VE::VSTL2DOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3972 /* vstl2d.ot */, VE::VSTL2DOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3972 /* vstl2d.ot */, VE::VSTL2DOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3972 /* vstl2d.ot */, VE::VSTL2DOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3972 /* vstl2d.ot */, VE::VSTL2DOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3972 /* vstl2d.ot */, VE::VSTL2DOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3982 /* vstu */, VE::VSTUrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3982 /* vstu */, VE::VSTUrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3982 /* vstu */, VE::VSTUirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3982 /* vstu */, VE::VSTUizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3982 /* vstu */, VE::VSTUrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3982 /* vstu */, VE::VSTUrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3982 /* vstu */, VE::VSTUirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3982 /* vstu */, VE::VSTUizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3987 /* vstu.nc */, VE::VSTUNCrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3987 /* vstu.nc */, VE::VSTUNCrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3987 /* vstu.nc */, VE::VSTUNCirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3987 /* vstu.nc */, VE::VSTUNCizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3987 /* vstu.nc */, VE::VSTUNCrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3987 /* vstu.nc */, VE::VSTUNCrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3987 /* vstu.nc */, VE::VSTUNCirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3987 /* vstu.nc */, VE::VSTUNCizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 3995 /* vstu.nc.ot */, VE::VSTUNCOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 3995 /* vstu.nc.ot */, VE::VSTUNCOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 3995 /* vstu.nc.ot */, VE::VSTUNCOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 3995 /* vstu.nc.ot */, VE::VSTUNCOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 3995 /* vstu.nc.ot */, VE::VSTUNCOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 3995 /* vstu.nc.ot */, VE::VSTUNCOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 3995 /* vstu.nc.ot */, VE::VSTUNCOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 3995 /* vstu.nc.ot */, VE::VSTUNCOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 4006 /* vstu.ot */, VE::VSTUOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 4006 /* vstu.ot */, VE::VSTUOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 4006 /* vstu.ot */, VE::VSTUOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 4006 /* vstu.ot */, VE::VSTUOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 4006 /* vstu.ot */, VE::VSTUOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 4006 /* vstu.ot */, VE::VSTUOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 4006 /* vstu.ot */, VE::VSTUOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 4006 /* vstu.ot */, VE::VSTUOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 4014 /* vstu2d */, VE::VSTU2Drrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 4014 /* vstu2d */, VE::VSTU2Drzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 4014 /* vstu2d */, VE::VSTU2Dirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 4014 /* vstu2d */, VE::VSTU2Dizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 4014 /* vstu2d */, VE::VSTU2Drrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 4014 /* vstu2d */, VE::VSTU2Drzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 4014 /* vstu2d */, VE::VSTU2Dirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 4014 /* vstu2d */, VE::VSTU2Dizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 4021 /* vstu2d.nc */, VE::VSTU2DNCrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 4021 /* vstu2d.nc */, VE::VSTU2DNCrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 4021 /* vstu2d.nc */, VE::VSTU2DNCirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 4021 /* vstu2d.nc */, VE::VSTU2DNCizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 4021 /* vstu2d.nc */, VE::VSTU2DNCrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 4021 /* vstu2d.nc */, VE::VSTU2DNCrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 4021 /* vstu2d.nc */, VE::VSTU2DNCirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 4021 /* vstu2d.nc */, VE::VSTU2DNCizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 4031 /* vstu2d.nc.ot */, VE::VSTU2DNCOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 4031 /* vstu2d.nc.ot */, VE::VSTU2DNCOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 4031 /* vstu2d.nc.ot */, VE::VSTU2DNCOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 4031 /* vstu2d.nc.ot */, VE::VSTU2DNCOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 4031 /* vstu2d.nc.ot */, VE::VSTU2DNCOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 4031 /* vstu2d.nc.ot */, VE::VSTU2DNCOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 4031 /* vstu2d.nc.ot */, VE::VSTU2DNCOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 4031 /* vstu2d.nc.ot */, VE::VSTU2DNCOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 4044 /* vstu2d.ot */, VE::VSTU2DOTrrv, Convert__Reg1_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64 }, },
  { 4044 /* vstu2d.ot */, VE::VSTU2DOTrzv, Convert__Reg1_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero }, },
  { 4044 /* vstu2d.ot */, VE::VSTU2DOTirv, Convert__SImm71_1__Reg1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64 }, },
  { 4044 /* vstu2d.ot */, VE::VSTU2DOTizv, Convert__SImm71_1__Zero1_2__Reg1_0, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero }, },
  { 4044 /* vstu2d.ot */, VE::VSTU2DOTrrvm, Convert__Reg1_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_I64, MCK_VM }, },
  { 4044 /* vstu2d.ot */, VE::VSTU2DOTrzvm, Convert__Reg1_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_Zero, MCK_VM }, },
  { 4044 /* vstu2d.ot */, VE::VSTU2DOTirvm, Convert__SImm71_1__Reg1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_I64, MCK_VM }, },
  { 4044 /* vstu2d.ot */, VE::VSTU2DOTizvm, Convert__SImm71_1__Zero1_2__Reg1_0__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_Zero, MCK_VM }, },
  { 4054 /* vsubs.l */, VE::VSUBSLrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 4054 /* vsubs.l */, VE::VSUBSLvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 4054 /* vsubs.l */, VE::VSUBSLiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 4054 /* vsubs.l */, VE::VSUBSLrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 4054 /* vsubs.l */, VE::VSUBSLvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 4054 /* vsubs.l */, VE::VSUBSLivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 4062 /* vsubs.w.sx */, VE::VSUBSWSXrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64 }, },
  { 4062 /* vsubs.w.sx */, VE::VSUBSWSXvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 4062 /* vsubs.w.sx */, VE::VSUBSWSXiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 4062 /* vsubs.w.sx */, VE::VSUBSWSXrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I32, MCK_V64, MCK_VM }, },
  { 4062 /* vsubs.w.sx */, VE::VSUBSWSXvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 4062 /* vsubs.w.sx */, VE::VSUBSWSXivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 4073 /* vsubu.l */, VE::VSUBULrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 4073 /* vsubu.l */, VE::VSUBULvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 4073 /* vsubu.l */, VE::VSUBULiv, Convert__Reg1_0__SImm71_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64 }, },
  { 4073 /* vsubu.l */, VE::VSUBULrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 4073 /* vsubu.l */, VE::VSUBULvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 4073 /* vsubu.l */, VE::VSUBULivm, Convert__Reg1_0__SImm71_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_SImm7, MCK_V64, MCK_VM }, },
  { 4081 /* vsum.l */, VE::VSUMLv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 4081 /* vsum.l */, VE::VSUMLvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 4088 /* vsum.w.sx */, VE::VSUMWSXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 4088 /* vsum.w.sx */, VE::VSUMWSXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 4098 /* vsum.w.zx */, VE::VSUMWZXv, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_V64, MCK_V64 }, },
  { 4098 /* vsum.w.zx */, VE::VSUMWZXvm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_VM }, },
  { 4108 /* vxor */, VE::VXORrv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64 }, },
  { 4108 /* vxor */, VE::VXORvv, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64 }, },
  { 4108 /* vxor */, VE::VXORmv, Convert__Reg1_0__MImm1_1__Reg1_2, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64 }, },
  { 4108 /* vxor */, VE::VXORrvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_I64, MCK_V64, MCK_VM }, },
  { 4108 /* vxor */, VE::VXORvvm, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_V64, MCK_V64, MCK_VM }, },
  { 4108 /* vxor */, VE::VXORmvm, Convert__Reg1_0__MImm1_1__Reg1_2__Reg1_3, AMFBS_None, { MCK_V64, MCK_MImm, MCK_V64, MCK_VM }, },
  { 4113 /* xor */, VE::XORrr, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_I64 }, },
  { 4113 /* xor */, VE::XORrm, Convert__Reg1_0__Reg1_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_I64, MCK_MImm }, },
  { 4113 /* xor */, VE::XORri, Convert__Reg1_0__Reg1_2__SImm71_1, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_I64 }, },
  { 4113 /* xor */, VE::XORim, Convert__Reg1_0__SImm71_1__MImm1_2, AMFBS_None, { MCK_I64, MCK_SImm7, MCK_MImm }, },
  { 4117 /* xorm */, VE::XORMmm, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_VM, MCK_VM, MCK_VM }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned VEAsmParser::
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
  StringRef Mnemonic = ((VEOperand &)*Operands[0]).getToken();

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

static const OperandMatchEntry OperandMatchTable[408] = {
  /* Operand List Mnemonic, Mask, Operand Class, Features */
  { 0 /* adds.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 0 /* adds.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 7 /* adds.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 7 /* adds.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 17 /* adds.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 17 /* adds.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 27 /* addu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 27 /* addu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 34 /* addu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 34 /* addu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 41 /* and */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 41 /* and */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 50 /* atmam */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 50 /* atmam */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 50 /* atmam */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 50 /* atmam */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMri, AMFBS_None },
  { 56 /* b */, 8 /* 3 */, MCK_MEMzi, AMFBS_None },
  { 58 /* b.d */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 58 /* b.d */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 62 /* b.d.nt */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 62 /* b.d.nt */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 69 /* b.d.t */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 69 /* b.d.t */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 75 /* b.l */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 75 /* b.l */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 79 /* b.l.nt */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 79 /* b.l.nt */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 86 /* b.l.t */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 86 /* b.l.t */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 92 /* b.s */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 92 /* b.s */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 96 /* b.s.nt */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 96 /* b.s.nt */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 103 /* b.s.t */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 103 /* b.s.t */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 109 /* b.w */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 109 /* b.w */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 113 /* b.w.nt */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 113 /* b.w.nt */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 120 /* b.w.t */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 120 /* b.w.t */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 126 /* baf.d */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 126 /* baf.d */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 132 /* baf.d.nt */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 132 /* baf.d.nt */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 141 /* baf.d.t */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 141 /* baf.d.t */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 149 /* baf.l */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 149 /* baf.l */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 155 /* baf.l.nt */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 155 /* baf.l.nt */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 164 /* baf.l.t */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 164 /* baf.l.t */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 172 /* baf.s */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 172 /* baf.s */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 178 /* baf.s.nt */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 178 /* baf.s.nt */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 187 /* baf.s.t */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 187 /* baf.s.t */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 195 /* baf.w */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 195 /* baf.w */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 201 /* baf.w.nt */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 201 /* baf.w.nt */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 210 /* baf.w.t */, 1 /* 0 */, MCK_MEMri, AMFBS_None },
  { 210 /* baf.w.t */, 1 /* 0 */, MCK_MEMzi, AMFBS_None },
  { 405 /* brv */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 409 /* bsic */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 409 /* bsic */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 409 /* bsic */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 409 /* bsic */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 414 /* bswp */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 419 /* cas.l */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 419 /* cas.l */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 419 /* cas.l */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 419 /* cas.l */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 425 /* cas.w */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 425 /* cas.w */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 425 /* cas.w */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 425 /* cas.w */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 431 /* cmov.d. */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 431 /* cmov.d. */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 439 /* cmov.l. */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 439 /* cmov.l. */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 447 /* cmov.s. */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 447 /* cmov.s. */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 455 /* cmov.w. */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 455 /* cmov.w. */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 463 /* cmps.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 463 /* cmps.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 470 /* cmps.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 470 /* cmps.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 480 /* cmps.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 480 /* cmps.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 490 /* cmpu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 490 /* cmpu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 497 /* cmpu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 497 /* cmpu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 628 /* divs.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 628 /* divs.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 635 /* divs.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 635 /* divs.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 645 /* divs.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 645 /* divs.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 655 /* divu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 655 /* divu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 662 /* divu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 662 /* divu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 669 /* dld */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 669 /* dld */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 669 /* dld */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 669 /* dld */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 673 /* dldl.sx */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 673 /* dldl.sx */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 673 /* dldl.sx */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 673 /* dldl.sx */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 681 /* dldl.zx */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 681 /* dldl.zx */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 681 /* dldl.zx */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 681 /* dldl.zx */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 689 /* dldu */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 689 /* dldu */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 689 /* dldu */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 689 /* dldu */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 694 /* eqv */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 694 /* eqv */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 703 /* fadd.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 703 /* fadd.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 710 /* fadd.q */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 710 /* fadd.q */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 717 /* fadd.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 717 /* fadd.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 724 /* fcmp.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 724 /* fcmp.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 731 /* fcmp.q */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 731 /* fcmp.q */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 738 /* fcmp.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 738 /* fcmp.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 745 /* fdiv.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 745 /* fdiv.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 752 /* fdiv.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 752 /* fdiv.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 786 /* fmax.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 786 /* fmax.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 793 /* fmax.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 793 /* fmax.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 800 /* fmin.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 800 /* fmin.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 807 /* fmin.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 807 /* fmin.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 814 /* fmul.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 814 /* fmul.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 821 /* fmul.q */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 821 /* fmul.q */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 828 /* fmul.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 828 /* fmul.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 835 /* fsub.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 835 /* fsub.d */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 842 /* fsub.q */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 842 /* fsub.q */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 849 /* fsub.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 849 /* fsub.s */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 860 /* ld */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 860 /* ld */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 860 /* ld */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 860 /* ld */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 863 /* ld1b.sx */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 863 /* ld1b.sx */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 863 /* ld1b.sx */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 863 /* ld1b.sx */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 871 /* ld1b.zx */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 871 /* ld1b.zx */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 871 /* ld1b.zx */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 871 /* ld1b.zx */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 879 /* ld2b.sx */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 879 /* ld2b.sx */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 879 /* ld2b.sx */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 879 /* ld2b.sx */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 887 /* ld2b.zx */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 887 /* ld2b.zx */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 887 /* ld2b.zx */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 887 /* ld2b.zx */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 895 /* ldl.sx */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 895 /* ldl.sx */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 895 /* ldl.sx */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 895 /* ldl.sx */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 902 /* ldl.zx */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 902 /* ldl.zx */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 902 /* ldl.zx */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 902 /* ldl.zx */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 909 /* ldu */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 909 /* ldu */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 909 /* ldu */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 909 /* ldu */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 913 /* ldz */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 917 /* lea */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 917 /* lea */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 917 /* lea */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 917 /* lea */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 921 /* lea.sl */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 921 /* lea.sl */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 921 /* lea.sl */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 921 /* lea.sl */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 932 /* lhm.b */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 932 /* lhm.b */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 938 /* lhm.h */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 938 /* lhm.h */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 944 /* lhm.l */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 944 /* lhm.l */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 950 /* lhm.w */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 950 /* lhm.w */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 960 /* lsv */, 16 /* 4 */, MCK_MImm, AMFBS_None },
  { 960 /* lsv */, 16 /* 4 */, MCK_MImm, AMFBS_None },
  { 973 /* lvm */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 973 /* lvm */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 986 /* maxs.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 986 /* maxs.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 993 /* maxs.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 993 /* maxs.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1003 /* maxs.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1003 /* maxs.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1013 /* mins.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1013 /* mins.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1020 /* mins.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1020 /* mins.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1030 /* mins.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1030 /* mins.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1054 /* mrg */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1054 /* mrg */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1058 /* muls.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1058 /* muls.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1065 /* muls.l.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1065 /* muls.l.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1074 /* muls.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1074 /* muls.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1084 /* muls.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1084 /* muls.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1094 /* mulu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1094 /* mulu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1101 /* mulu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1101 /* mulu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1113 /* nnd */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1113 /* nnd */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1126 /* or */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1126 /* or */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 1133 /* pcnt */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1143 /* pfch */, 1 /* 0 */, MCK_MEMrii, AMFBS_None },
  { 1143 /* pfch */, 1 /* 0 */, MCK_MEMrri, AMFBS_None },
  { 1143 /* pfch */, 1 /* 0 */, MCK_MEMzii, AMFBS_None },
  { 1143 /* pfch */, 1 /* 0 */, MCK_MEMzri, AMFBS_None },
  { 1217 /* pvand */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1217 /* pvand */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1223 /* pvand.lo */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1223 /* pvand.lo */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1232 /* pvand.up */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1232 /* pvand.up */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1397 /* pveqv */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1397 /* pveqv */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1403 /* pveqv.lo */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1403 /* pveqv.lo */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1412 /* pveqv.up */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1412 /* pveqv.up */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1895 /* pvor */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1895 /* pvor */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1900 /* pvor.lo */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1900 /* pvor.lo */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1908 /* pvor.up */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 1908 /* pvor.up */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2213 /* pvxor */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2213 /* pvxor */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2219 /* pvxor.lo */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2219 /* pvxor.lo */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2228 /* pvxor.up */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2228 /* pvxor.up */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2245 /* shm.b */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2245 /* shm.b */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2251 /* shm.h */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2251 /* shm.h */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2257 /* shm.l */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2257 /* shm.l */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2263 /* shm.w */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2263 /* shm.w */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2273 /* sla.l */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2273 /* sla.l */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2279 /* sla.w.sx */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2279 /* sla.w.sx */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2288 /* sla.w.zx */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2288 /* sla.w.zx */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2297 /* sld */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2297 /* sld */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2301 /* sll */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2301 /* sll */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2319 /* sra.l */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2319 /* sra.l */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2325 /* sra.w.sx */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2325 /* sra.w.sx */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2334 /* sra.w.zx */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2334 /* sra.w.zx */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2343 /* srd */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2343 /* srd */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2347 /* srl */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2347 /* srl */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2351 /* st */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 2351 /* st */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 2351 /* st */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 2351 /* st */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 2354 /* st1b */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 2354 /* st1b */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 2354 /* st1b */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 2354 /* st1b */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 2359 /* st2b */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 2359 /* st2b */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 2359 /* st2b */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 2359 /* st2b */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 2364 /* stl */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 2364 /* stl */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 2364 /* stl */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 2364 /* stl */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 2368 /* stu */, 2 /* 1 */, MCK_MEMrii, AMFBS_None },
  { 2368 /* stu */, 2 /* 1 */, MCK_MEMrri, AMFBS_None },
  { 2368 /* stu */, 2 /* 1 */, MCK_MEMzii, AMFBS_None },
  { 2368 /* stu */, 2 /* 1 */, MCK_MEMzri, AMFBS_None },
  { 2372 /* subs.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2372 /* subs.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2379 /* subs.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2379 /* subs.w.sx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2389 /* subs.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2389 /* subs.w.zx */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2399 /* subu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2399 /* subu.l */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2406 /* subu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2406 /* subu.w */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 2431 /* ts1am.l */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2431 /* ts1am.l */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2431 /* ts1am.l */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2431 /* ts1am.l */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2439 /* ts1am.w */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2439 /* ts1am.w */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2439 /* ts1am.w */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2439 /* ts1am.w */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2447 /* ts2am */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2447 /* ts2am */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2447 /* ts2am */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2447 /* ts2am */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2453 /* ts3am */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2453 /* ts3am */, 2 /* 1 */, MCK_MEMri, AMFBS_None },
  { 2453 /* ts3am */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2453 /* ts3am */, 2 /* 1 */, MCK_MEMzi, AMFBS_None },
  { 2491 /* vand */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2491 /* vand */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2697 /* veqv */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 2697 /* veqv */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 3449 /* vor */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 3449 /* vor */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 3782 /* vsfa */, 8 /* 3 */, MCK_MImm, AMFBS_None },
  { 3782 /* vsfa */, 8 /* 3 */, MCK_MImm, AMFBS_None },
  { 3782 /* vsfa */, 8 /* 3 */, MCK_MImm, AMFBS_None },
  { 3782 /* vsfa */, 8 /* 3 */, MCK_MImm, AMFBS_None },
  { 4108 /* vxor */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 4108 /* vxor */, 2 /* 1 */, MCK_MImm, AMFBS_None },
  { 4113 /* xor */, 4 /* 2 */, MCK_MImm, AMFBS_None },
  { 4113 /* xor */, 4 /* 2 */, MCK_MImm, AMFBS_None },
};

ParseStatus VEAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_MImm:
    return parseMImmOperand(Operands);
  case MCK_MEMri:
    return parseMEMAsOperand(Operands);
  case MCK_MEMrii:
    return parseMEMOperand(Operands);
  case MCK_MEMrri:
    return parseMEMOperand(Operands);
  case MCK_MEMzi:
    return parseMEMAsOperand(Operands);
  case MCK_MEMzii:
    return parseMEMOperand(Operands);
  case MCK_MEMzri:
    return parseMEMOperand(Operands);
  default:
    return ParseStatus::NoMatch;
  }
  return ParseStatus::NoMatch;
}

ParseStatus VEAsmParser::
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

static std::string VEMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool VECheckMnemonic(StringRef Mnemonic,
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

