/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: Xtensa.td                                                            *|
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

  Match_InvalidB4const,
  Match_InvalidB4constu,
  Match_InvalidImm12,
  Match_InvalidImm12m,
  Match_InvalidImm1_16,
  Match_InvalidImm1n_15,
  Match_InvalidImm32n_95,
  Match_InvalidImm64n_4n,
  Match_InvalidImm8,
  Match_InvalidImm8_sh8,
  Match_InvalidImm8n_7,
  Match_InvalidOffset4m32,
  Match_InvalidOffset8m16,
  Match_InvalidOffset8m32,
  Match_InvalidOffset8m8,
  Match_InvalidSelect_256,
  Match_InvalidShimm1_31,
  Match_InvalidUimm4,
  Match_InvalidUimm5,
  Match_Invalidentry_imm12,
  Match_Invalidimm7_22,
  END_OPERAND_DIAGNOSTIC_TYPES
#endif // GET_OPERAND_DIAGNOSTIC_TYPES


#ifdef GET_REGISTER_MATCHER
#undef GET_REGISTER_MATCHER

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_HasDensityBit = 6,
  Feature_HasSingleFloatBit = 27,
  Feature_HasWindowedBit = 29,
  Feature_HasMAC16Bit = 15,
  Feature_HasBooleanBit = 0,
  Feature_HasLoopBit = 14,
  Feature_HasSEXTBit = 26,
  Feature_HasCLAMPSBit = 1,
  Feature_HasNSABit = 21,
  Feature_HasMINMAXBit = 16,
  Feature_HasMul16Bit = 18,
  Feature_HasMul32Bit = 19,
  Feature_HasMul32HighBit = 20,
  Feature_HasDiv32Bit = 7,
  Feature_HasS32C1IBit = 25,
  Feature_HasForcedAtomicsBit = 11,
  Feature_HasRegionProtectionBit = 23,
  Feature_HasRelocatableVectorBit = 24,
  Feature_HasMiscSRBit = 17,
  Feature_HasExtendedL32RBit = 10,
  Feature_HasDataCacheBit = 4,
  Feature_HasTHREADPTRBit = 28,
  Feature_HasHighPriInterruptsBit = 12,
  Feature_HasInterruptBit = 13,
  Feature_HasExceptionBit = 9,
  Feature_HasDebugBit = 5,
  Feature_HasPRIDBit = 22,
  Feature_HasCoprocessorBit = 2,
  Feature_HasDFPAccelBit = 3,
  Feature_HasESP32S2OpsBit = 8,
};

static MCRegister MatchRegisterName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 36 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return Xtensa::A0;	 // "a0"
      case '1':	 // 1 string to match.
        return Xtensa::SP;	 // "a1"
      case '2':	 // 1 string to match.
        return Xtensa::A2;	 // "a2"
      case '3':	 // 1 string to match.
        return Xtensa::A3;	 // "a3"
      case '4':	 // 1 string to match.
        return Xtensa::A4;	 // "a4"
      case '5':	 // 1 string to match.
        return Xtensa::A5;	 // "a5"
      case '6':	 // 1 string to match.
        return Xtensa::A6;	 // "a6"
      case '7':	 // 1 string to match.
        return Xtensa::A7;	 // "a7"
      case '8':	 // 1 string to match.
        return Xtensa::A8;	 // "a8"
      case '9':	 // 1 string to match.
        return Xtensa::A9;	 // "a9"
      }
      break;
    case 'b':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return Xtensa::B0;	 // "b0"
      case '1':	 // 1 string to match.
        return Xtensa::B1;	 // "b1"
      case '2':	 // 1 string to match.
        return Xtensa::B2;	 // "b2"
      case '3':	 // 1 string to match.
        return Xtensa::B3;	 // "b3"
      case '4':	 // 1 string to match.
        return Xtensa::B4;	 // "b4"
      case '5':	 // 1 string to match.
        return Xtensa::B5;	 // "b5"
      case '6':	 // 1 string to match.
        return Xtensa::B6;	 // "b6"
      case '7':	 // 1 string to match.
        return Xtensa::B7;	 // "b7"
      case '8':	 // 1 string to match.
        return Xtensa::B8;	 // "b8"
      case '9':	 // 1 string to match.
        return Xtensa::B9;	 // "b9"
      case 'r':	 // 1 string to match.
        return Xtensa::BREG;	 // "br"
      }
      break;
    case 'f':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return Xtensa::F0;	 // "f0"
      case '1':	 // 1 string to match.
        return Xtensa::F1;	 // "f1"
      case '2':	 // 1 string to match.
        return Xtensa::F2;	 // "f2"
      case '3':	 // 1 string to match.
        return Xtensa::F3;	 // "f3"
      case '4':	 // 1 string to match.
        return Xtensa::F4;	 // "f4"
      case '5':	 // 1 string to match.
        return Xtensa::F5;	 // "f5"
      case '6':	 // 1 string to match.
        return Xtensa::F6;	 // "f6"
      case '7':	 // 1 string to match.
        return Xtensa::F7;	 // "f7"
      case '8':	 // 1 string to match.
        return Xtensa::F8;	 // "f8"
      case '9':	 // 1 string to match.
        return Xtensa::F9;	 // "f9"
      }
      break;
    case 'm':	 // 4 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return Xtensa::M0;	 // "m0"
      case '1':	 // 1 string to match.
        return Xtensa::M1;	 // "m1"
      case '2':	 // 1 string to match.
        return Xtensa::M2;	 // "m2"
      case '3':	 // 1 string to match.
        return Xtensa::M3;	 // "m3"
      }
      break;
    case 'p':	 // 1 string to match.
      if (Name[1] != 's')
        break;
      return Xtensa::PS;	 // "ps"
    }
    break;
  case 3:	 // 22 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 6 strings to match.
      if (Name[1] != '1')
        break;
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        return Xtensa::A10;	 // "a10"
      case '1':	 // 1 string to match.
        return Xtensa::A11;	 // "a11"
      case '2':	 // 1 string to match.
        return Xtensa::A12;	 // "a12"
      case '3':	 // 1 string to match.
        return Xtensa::A13;	 // "a13"
      case '4':	 // 1 string to match.
        return Xtensa::A14;	 // "a14"
      case '5':	 // 1 string to match.
        return Xtensa::A15;	 // "a15"
      }
      break;
    case 'b':	 // 6 strings to match.
      if (Name[1] != '1')
        break;
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        return Xtensa::B10;	 // "b10"
      case '1':	 // 1 string to match.
        return Xtensa::B11;	 // "b11"
      case '2':	 // 1 string to match.
        return Xtensa::B12;	 // "b12"
      case '3':	 // 1 string to match.
        return Xtensa::B13;	 // "b13"
      case '4':	 // 1 string to match.
        return Xtensa::B14;	 // "b14"
      case '5':	 // 1 string to match.
        return Xtensa::B15;	 // "b15"
      }
      break;
    case 'd':	 // 1 string to match.
      if (memcmp(Name.data()+1, "dr", 2) != 0)
        break;
      return Xtensa::DDR;	 // "ddr"
    case 'f':	 // 8 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 6 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::F10;	 // "f10"
        case '1':	 // 1 string to match.
          return Xtensa::F11;	 // "f11"
        case '2':	 // 1 string to match.
          return Xtensa::F12;	 // "f12"
        case '3':	 // 1 string to match.
          return Xtensa::F13;	 // "f13"
        case '4':	 // 1 string to match.
          return Xtensa::F14;	 // "f14"
        case '5':	 // 1 string to match.
          return Xtensa::F15;	 // "f15"
        }
        break;
      case 'c':	 // 1 string to match.
        if (Name[2] != 'r')
          break;
        return Xtensa::FCR;	 // "fcr"
      case 's':	 // 1 string to match.
        if (Name[2] != 'r')
          break;
        return Xtensa::FSR;	 // "fsr"
      }
      break;
    case 's':	 // 1 string to match.
      if (memcmp(Name.data()+1, "ar", 2) != 0)
        break;
      return Xtensa::SAR;	 // "sar"
    }
    break;
  case 4:	 // 18 strings to match.
    switch (Name[0]) {
    default: break;
    case 'd':	 // 1 string to match.
      if (memcmp(Name.data()+1, "epc", 3) != 0)
        break;
      return Xtensa::DEPC;	 // "depc"
    case 'e':	 // 13 strings to match.
      if (Name[1] != 'p')
        break;
      switch (Name[2]) {
      default: break;
      case 'c':	 // 7 strings to match.
        switch (Name[3]) {
        default: break;
        case '1':	 // 1 string to match.
          return Xtensa::EPC1;	 // "epc1"
        case '2':	 // 1 string to match.
          return Xtensa::EPC2;	 // "epc2"
        case '3':	 // 1 string to match.
          return Xtensa::EPC3;	 // "epc3"
        case '4':	 // 1 string to match.
          return Xtensa::EPC4;	 // "epc4"
        case '5':	 // 1 string to match.
          return Xtensa::EPC5;	 // "epc5"
        case '6':	 // 1 string to match.
          return Xtensa::EPC6;	 // "epc6"
        case '7':	 // 1 string to match.
          return Xtensa::EPC7;	 // "epc7"
        }
        break;
      case 's':	 // 6 strings to match.
        switch (Name[3]) {
        default: break;
        case '2':	 // 1 string to match.
          return Xtensa::EPS2;	 // "eps2"
        case '3':	 // 1 string to match.
          return Xtensa::EPS3;	 // "eps3"
        case '4':	 // 1 string to match.
          return Xtensa::EPS4;	 // "eps4"
        case '5':	 // 1 string to match.
          return Xtensa::EPS5;	 // "eps5"
        case '6':	 // 1 string to match.
          return Xtensa::EPS6;	 // "eps6"
        case '7':	 // 1 string to match.
          return Xtensa::EPS7;	 // "eps7"
        }
        break;
      }
      break;
    case 'f':	 // 1 string to match.
      if (memcmp(Name.data()+1, "64s", 3) != 0)
        break;
      return Xtensa::F64S;	 // "f64s"
    case 'l':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'b':	 // 1 string to match.
        if (memcmp(Name.data()+2, "eg", 2) != 0)
          break;
        return Xtensa::LBEG;	 // "lbeg"
      case 'e':	 // 1 string to match.
        if (memcmp(Name.data()+2, "nd", 2) != 0)
          break;
        return Xtensa::LEND;	 // "lend"
      }
      break;
    case 'p':	 // 1 string to match.
      if (memcmp(Name.data()+1, "rid", 3) != 0)
        break;
      return Xtensa::PRID;	 // "prid"
    }
    break;
  case 5:	 // 6 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 2 strings to match.
      if (memcmp(Name.data()+1, "cc", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case 'h':	 // 1 string to match.
        if (Name[4] != 'i')
          break;
        return Xtensa::ACCHI;	 // "acchi"
      case 'l':	 // 1 string to match.
        if (Name[4] != 'o')
          break;
        return Xtensa::ACCLO;	 // "acclo"
      }
      break;
    case 'm':	 // 4 strings to match.
      if (memcmp(Name.data()+1, "isc", 3) != 0)
        break;
      switch (Name[4]) {
      default: break;
      case '0':	 // 1 string to match.
        return Xtensa::MISC0;	 // "misc0"
      case '1':	 // 1 string to match.
        return Xtensa::MISC1;	 // "misc1"
      case '2':	 // 1 string to match.
        return Xtensa::MISC2;	 // "misc2"
      case '3':	 // 1 string to match.
        return Xtensa::MISC3;	 // "misc3"
      }
      break;
    }
    break;
  case 6:	 // 5 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(Name.data()+1, "count", 5) != 0)
        break;
      return Xtensa::CCOUNT;	 // "ccount"
    case 'i':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 1 string to match.
        if (memcmp(Name.data()+2, "ount", 4) != 0)
          break;
        return Xtensa::ICOUNT;	 // "icount"
      case 'n':	 // 1 string to match.
        if (memcmp(Name.data()+2, "tset", 4) != 0)
          break;
        return Xtensa::INTSET;	 // "intset"
      }
      break;
    case 'l':	 // 1 string to match.
      if (memcmp(Name.data()+1, "count", 5) != 0)
        break;
      return Xtensa::LCOUNT;	 // "lcount"
    case 'm':	 // 1 string to match.
      if (memcmp(Name.data()+1, "emctl", 5) != 0)
        break;
      return Xtensa::MEMCTL;	 // "memctl"
    }
    break;
  case 7:	 // 5 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(Name.data()+1, "tomctl", 6) != 0)
        break;
      return Xtensa::ATOMCTL;	 // "atomctl"
    case 'f':	 // 2 strings to match.
      if (memcmp(Name.data()+1, "64r_", 4) != 0)
        break;
      switch (Name[5]) {
      default: break;
      case 'h':	 // 1 string to match.
        if (Name[6] != 'i')
          break;
        return Xtensa::F64R_HI;	 // "f64r_hi"
      case 'l':	 // 1 string to match.
        if (Name[6] != 'o')
          break;
        return Xtensa::F64R_LO;	 // "f64r_lo"
      }
      break;
    case 'l':	 // 1 string to match.
      if (memcmp(Name.data()+1, "itbase", 6) != 0)
        break;
      return Xtensa::LITBASE;	 // "litbase"
    case 'v':	 // 1 string to match.
      if (memcmp(Name.data()+1, "ecbase", 6) != 0)
        break;
      return Xtensa::VECBASE;	 // "vecbase"
    }
    break;
  case 8:	 // 18 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(Name.data()+1, "penable", 7) != 0)
        break;
      return Xtensa::CPENABLE;	 // "cpenable"
    case 'd':	 // 4 strings to match.
      if (memcmp(Name.data()+1, "break", 5) != 0)
        break;
      switch (Name[6]) {
      default: break;
      case 'a':	 // 2 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::DBREAKA0;	 // "dbreaka0"
        case '1':	 // 1 string to match.
          return Xtensa::DBREAKA1;	 // "dbreaka1"
        }
        break;
      case 'c':	 // 2 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::DBREAKC0;	 // "dbreakc0"
        case '1':	 // 1 string to match.
          return Xtensa::DBREAKC1;	 // "dbreakc1"
        }
        break;
      }
      break;
    case 'e':	 // 9 strings to match.
      if (memcmp(Name.data()+1, "xc", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case 'c':	 // 1 string to match.
        if (memcmp(Name.data()+4, "ause", 4) != 0)
          break;
        return Xtensa::EXCCAUSE;	 // "exccause"
      case 's':	 // 7 strings to match.
        if (memcmp(Name.data()+4, "ave", 3) != 0)
          break;
        switch (Name[7]) {
        default: break;
        case '1':	 // 1 string to match.
          return Xtensa::EXCSAVE1;	 // "excsave1"
        case '2':	 // 1 string to match.
          return Xtensa::EXCSAVE2;	 // "excsave2"
        case '3':	 // 1 string to match.
          return Xtensa::EXCSAVE3;	 // "excsave3"
        case '4':	 // 1 string to match.
          return Xtensa::EXCSAVE4;	 // "excsave4"
        case '5':	 // 1 string to match.
          return Xtensa::EXCSAVE5;	 // "excsave5"
        case '6':	 // 1 string to match.
          return Xtensa::EXCSAVE6;	 // "excsave6"
        case '7':	 // 1 string to match.
          return Xtensa::EXCSAVE7;	 // "excsave7"
        }
        break;
      case 'v':	 // 1 string to match.
        if (memcmp(Name.data()+4, "addr", 4) != 0)
          break;
        return Xtensa::EXCVADDR;	 // "excvaddr"
      }
      break;
    case 'g':	 // 1 string to match.
      if (memcmp(Name.data()+1, "pio_out", 7) != 0)
        break;
      return Xtensa::GPIO_OUT_S2;	 // "gpio_out"
    case 'i':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case 'b':	 // 2 strings to match.
        if (memcmp(Name.data()+2, "reaka", 5) != 0)
          break;
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::IBREAKA0;	 // "ibreaka0"
        case '1':	 // 1 string to match.
          return Xtensa::IBREAKA1;	 // "ibreaka1"
        }
        break;
      case 'n':	 // 1 string to match.
        if (memcmp(Name.data()+2, "tclear", 6) != 0)
          break;
        return Xtensa::INTCLEAR;	 // "intclear"
      }
      break;
    }
    break;
  case 9:	 // 9 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 5 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 3 strings to match.
        if (memcmp(Name.data()+2, "ompare", 6) != 0)
          break;
        switch (Name[8]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::CCOMPARE0;	 // "ccompare0"
        case '1':	 // 1 string to match.
          return Xtensa::CCOMPARE1;	 // "ccompare1"
        case '2':	 // 1 string to match.
          return Xtensa::CCOMPARE2;	 // "ccompare2"
        }
        break;
      case 'o':	 // 2 strings to match.
        if (memcmp(Name.data()+2, "nfigid", 6) != 0)
          break;
        switch (Name[8]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::CONFIGID0;	 // "configid0"
        case '1':	 // 1 string to match.
          return Xtensa::CONFIGID1;	 // "configid1"
        }
        break;
      }
      break;
    case 'i':	 // 2 strings to match.
      if (memcmp(Name.data()+1, "nte", 3) != 0)
        break;
      switch (Name[4]) {
      default: break;
      case 'n':	 // 1 string to match.
        if (memcmp(Name.data()+5, "able", 4) != 0)
          break;
        return Xtensa::INTENABLE;	 // "intenable"
      case 'r':	 // 1 string to match.
        if (memcmp(Name.data()+5, "rupt", 4) != 0)
          break;
        return Xtensa::INTERRUPT;	 // "interrupt"
      }
      break;
    case 's':	 // 1 string to match.
      if (memcmp(Name.data()+1, "compare1", 8) != 0)
        break;
      return Xtensa::SCOMPARE1;	 // "scompare1"
    case 't':	 // 1 string to match.
      if (memcmp(Name.data()+1, "hreadptr", 8) != 0)
        break;
      return Xtensa::THREADPTR;	 // "threadptr"
    }
    break;
  case 10:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case 'd':	 // 1 string to match.
      if (memcmp(Name.data()+1, "ebugcause", 9) != 0)
        break;
      return Xtensa::DEBUGCAUSE;	 // "debugcause"
    case 'w':	 // 1 string to match.
      if (memcmp(Name.data()+1, "indowbase", 9) != 0)
        break;
      return Xtensa::WINDOWBASE;	 // "windowbase"
    }
    break;
  case 11:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case 'i':	 // 1 string to match.
      if (memcmp(Name.data()+1, "countlevel", 10) != 0)
        break;
      return Xtensa::ICOUNTLEVEL;	 // "icountlevel"
    case 'w':	 // 1 string to match.
      if (memcmp(Name.data()+1, "indowstart", 10) != 0)
        break;
      return Xtensa::WINDOWSTART;	 // "windowstart"
    }
    break;
  case 12:	 // 1 string to match.
    if (memcmp(Name.data()+0, "ibreakenable", 12) != 0)
      break;
    return Xtensa::IBREAKENABLE;	 // "ibreakenable"
  }
  return Xtensa::NoRegister;
}

static MCRegister MatchRegisterAltName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 6 strings to match.
    switch (Name[0]) {
    default: break;
    case '0':	 // 1 string to match.
      return Xtensa::LBEG;	 // "0"
    case '1':	 // 1 string to match.
      return Xtensa::LEND;	 // "1"
    case '2':	 // 1 string to match.
      return Xtensa::LCOUNT;	 // "2"
    case '3':	 // 1 string to match.
      return Xtensa::SAR;	 // "3"
    case '4':	 // 1 string to match.
      return Xtensa::BREG;	 // "4"
    case '5':	 // 1 string to match.
      return Xtensa::LITBASE;	 // "5"
    }
    break;
  case 2:	 // 19 strings to match.
    switch (Name[0]) {
    default: break;
    case '1':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case '2':	 // 1 string to match.
        return Xtensa::SCOMPARE1;	 // "12"
      case '6':	 // 1 string to match.
        return Xtensa::ACCLO;	 // "16"
      case '7':	 // 1 string to match.
        return Xtensa::ACCHI;	 // "17"
      }
      break;
    case '3':	 // 4 strings to match.
      switch (Name[1]) {
      default: break;
      case '2':	 // 1 string to match.
        return Xtensa::M0;	 // "32"
      case '3':	 // 1 string to match.
        return Xtensa::M1;	 // "33"
      case '4':	 // 1 string to match.
        return Xtensa::M2;	 // "34"
      case '5':	 // 1 string to match.
        return Xtensa::M3;	 // "35"
      }
      break;
    case '7':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case '2':	 // 1 string to match.
        return Xtensa::WINDOWBASE;	 // "72"
      case '3':	 // 1 string to match.
        return Xtensa::WINDOWSTART;	 // "73"
      }
      break;
    case '9':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case '6':	 // 1 string to match.
        return Xtensa::IBREAKENABLE;	 // "96"
      case '7':	 // 1 string to match.
        return Xtensa::MEMCTL;	 // "97"
      case '9':	 // 1 string to match.
        return Xtensa::ATOMCTL;	 // "99"
      }
      break;
    case 'B':	 // 1 string to match.
      if (Name[1] != 'R')
        break;
      return Xtensa::BREG;	 // "BR"
    case 'M':	 // 4 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return Xtensa::M0;	 // "M0"
      case '1':	 // 1 string to match.
        return Xtensa::M1;	 // "M1"
      case '2':	 // 1 string to match.
        return Xtensa::M2;	 // "M2"
      case '3':	 // 1 string to match.
        return Xtensa::M3;	 // "M3"
      }
      break;
    case 'P':	 // 1 string to match.
      if (Name[1] != 'S')
        break;
      return Xtensa::PS;	 // "PS"
    case 's':	 // 1 string to match.
      if (Name[1] != 'p')
        break;
      return Xtensa::SP;	 // "sp"
    }
    break;
  case 3:	 // 54 strings to match.
    switch (Name[0]) {
    default: break;
    case '1':	 // 22 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        if (Name[2] != '4')
          break;
        return Xtensa::DDR;	 // "104"
      case '2':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case '8':	 // 1 string to match.
          return Xtensa::IBREAKA0;	 // "128"
        case '9':	 // 1 string to match.
          return Xtensa::IBREAKA1;	 // "129"
        }
        break;
      case '4':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case '4':	 // 1 string to match.
          return Xtensa::DBREAKA0;	 // "144"
        case '5':	 // 1 string to match.
          return Xtensa::DBREAKA1;	 // "145"
        }
        break;
      case '6':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::DBREAKC0;	 // "160"
        case '1':	 // 1 string to match.
          return Xtensa::DBREAKC1;	 // "161"
        }
        break;
      case '7':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '6':	 // 1 string to match.
          return Xtensa::CONFIGID0;	 // "176"
        case '7':	 // 1 string to match.
          return Xtensa::EPC1;	 // "177"
        case '8':	 // 1 string to match.
          return Xtensa::EPC2;	 // "178"
        case '9':	 // 1 string to match.
          return Xtensa::EPC3;	 // "179"
        }
        break;
      case '8':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::EPC4;	 // "180"
        case '1':	 // 1 string to match.
          return Xtensa::EPC5;	 // "181"
        case '2':	 // 1 string to match.
          return Xtensa::EPC6;	 // "182"
        case '3':	 // 1 string to match.
          return Xtensa::EPC7;	 // "183"
        }
        break;
      case '9':	 // 7 strings to match.
        switch (Name[2]) {
        default: break;
        case '2':	 // 1 string to match.
          return Xtensa::DEPC;	 // "192"
        case '4':	 // 1 string to match.
          return Xtensa::EPS2;	 // "194"
        case '5':	 // 1 string to match.
          return Xtensa::EPS3;	 // "195"
        case '6':	 // 1 string to match.
          return Xtensa::EPS4;	 // "196"
        case '7':	 // 1 string to match.
          return Xtensa::EPS5;	 // "197"
        case '8':	 // 1 string to match.
          return Xtensa::EPS6;	 // "198"
        case '9':	 // 1 string to match.
          return Xtensa::EPS7;	 // "199"
        }
        break;
      }
      break;
    case '2':	 // 28 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case '8':	 // 1 string to match.
          return Xtensa::CONFIGID1;	 // "208"
        case '9':	 // 1 string to match.
          return Xtensa::EXCSAVE1;	 // "209"
        }
        break;
      case '1':	 // 6 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::EXCSAVE2;	 // "210"
        case '1':	 // 1 string to match.
          return Xtensa::EXCSAVE3;	 // "211"
        case '2':	 // 1 string to match.
          return Xtensa::EXCSAVE4;	 // "212"
        case '3':	 // 1 string to match.
          return Xtensa::EXCSAVE5;	 // "213"
        case '4':	 // 1 string to match.
          return Xtensa::EXCSAVE6;	 // "214"
        case '5':	 // 1 string to match.
          return Xtensa::EXCSAVE7;	 // "215"
        }
        break;
      case '2':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '4':	 // 1 string to match.
          return Xtensa::CPENABLE;	 // "224"
        case '6':	 // 1 string to match.
          return Xtensa::INTERRUPT;	 // "226"
        case '7':	 // 1 string to match.
          return Xtensa::INTCLEAR;	 // "227"
        case '8':	 // 1 string to match.
          return Xtensa::INTENABLE;	 // "228"
        }
        break;
      case '3':	 // 9 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::PS;	 // "230"
        case '1':	 // 1 string to match.
          return Xtensa::VECBASE;	 // "231"
        case '2':	 // 1 string to match.
          return Xtensa::EXCCAUSE;	 // "232"
        case '3':	 // 1 string to match.
          return Xtensa::DEBUGCAUSE;	 // "233"
        case '4':	 // 1 string to match.
          return Xtensa::CCOUNT;	 // "234"
        case '5':	 // 1 string to match.
          return Xtensa::PRID;	 // "235"
        case '6':	 // 1 string to match.
          return Xtensa::ICOUNT;	 // "236"
        case '7':	 // 1 string to match.
          return Xtensa::ICOUNTLEVEL;	 // "237"
        case '8':	 // 1 string to match.
          return Xtensa::EXCVADDR;	 // "238"
        }
        break;
      case '4':	 // 7 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::CCOMPARE0;	 // "240"
        case '1':	 // 1 string to match.
          return Xtensa::CCOMPARE1;	 // "241"
        case '2':	 // 1 string to match.
          return Xtensa::CCOMPARE2;	 // "242"
        case '4':	 // 1 string to match.
          return Xtensa::MISC0;	 // "244"
        case '5':	 // 1 string to match.
          return Xtensa::MISC1;	 // "245"
        case '6':	 // 1 string to match.
          return Xtensa::MISC2;	 // "246"
        case '7':	 // 1 string to match.
          return Xtensa::MISC3;	 // "247"
        }
        break;
      }
      break;
    case 'D':	 // 1 string to match.
      if (memcmp(Name.data()+1, "DR", 2) != 0)
        break;
      return Xtensa::DDR;	 // "DDR"
    case 'F':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'C':	 // 1 string to match.
        if (Name[2] != 'R')
          break;
        return Xtensa::FCR;	 // "FCR"
      case 'S':	 // 1 string to match.
        if (Name[2] != 'R')
          break;
        return Xtensa::FSR;	 // "FSR"
      }
      break;
    case 'S':	 // 1 string to match.
      if (memcmp(Name.data()+1, "AR", 2) != 0)
        break;
      return Xtensa::SAR;	 // "SAR"
    }
    break;
  case 4:	 // 18 strings to match.
    switch (Name[0]) {
    default: break;
    case 'D':	 // 1 string to match.
      if (memcmp(Name.data()+1, "EPC", 3) != 0)
        break;
      return Xtensa::DEPC;	 // "DEPC"
    case 'E':	 // 13 strings to match.
      if (Name[1] != 'P')
        break;
      switch (Name[2]) {
      default: break;
      case 'C':	 // 7 strings to match.
        switch (Name[3]) {
        default: break;
        case '1':	 // 1 string to match.
          return Xtensa::EPC1;	 // "EPC1"
        case '2':	 // 1 string to match.
          return Xtensa::EPC2;	 // "EPC2"
        case '3':	 // 1 string to match.
          return Xtensa::EPC3;	 // "EPC3"
        case '4':	 // 1 string to match.
          return Xtensa::EPC4;	 // "EPC4"
        case '5':	 // 1 string to match.
          return Xtensa::EPC5;	 // "EPC5"
        case '6':	 // 1 string to match.
          return Xtensa::EPC6;	 // "EPC6"
        case '7':	 // 1 string to match.
          return Xtensa::EPC7;	 // "EPC7"
        }
        break;
      case 'S':	 // 6 strings to match.
        switch (Name[3]) {
        default: break;
        case '2':	 // 1 string to match.
          return Xtensa::EPS2;	 // "EPS2"
        case '3':	 // 1 string to match.
          return Xtensa::EPS3;	 // "EPS3"
        case '4':	 // 1 string to match.
          return Xtensa::EPS4;	 // "EPS4"
        case '5':	 // 1 string to match.
          return Xtensa::EPS5;	 // "EPS5"
        case '6':	 // 1 string to match.
          return Xtensa::EPS6;	 // "EPS6"
        case '7':	 // 1 string to match.
          return Xtensa::EPS7;	 // "EPS7"
        }
        break;
      }
      break;
    case 'F':	 // 1 string to match.
      if (memcmp(Name.data()+1, "64S", 3) != 0)
        break;
      return Xtensa::F64S;	 // "F64S"
    case 'L':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'B':	 // 1 string to match.
        if (memcmp(Name.data()+2, "EG", 2) != 0)
          break;
        return Xtensa::LBEG;	 // "LBEG"
      case 'E':	 // 1 string to match.
        if (memcmp(Name.data()+2, "ND", 2) != 0)
          break;
        return Xtensa::LEND;	 // "LEND"
      }
      break;
    case 'P':	 // 1 string to match.
      if (memcmp(Name.data()+1, "RID", 3) != 0)
        break;
      return Xtensa::PRID;	 // "PRID"
    }
    break;
  case 5:	 // 6 strings to match.
    switch (Name[0]) {
    default: break;
    case 'A':	 // 2 strings to match.
      if (memcmp(Name.data()+1, "CC", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case 'H':	 // 1 string to match.
        if (Name[4] != 'I')
          break;
        return Xtensa::ACCHI;	 // "ACCHI"
      case 'L':	 // 1 string to match.
        if (Name[4] != 'O')
          break;
        return Xtensa::ACCLO;	 // "ACCLO"
      }
      break;
    case 'M':	 // 4 strings to match.
      if (memcmp(Name.data()+1, "ISC", 3) != 0)
        break;
      switch (Name[4]) {
      default: break;
      case '0':	 // 1 string to match.
        return Xtensa::MISC0;	 // "MISC0"
      case '1':	 // 1 string to match.
        return Xtensa::MISC1;	 // "MISC1"
      case '2':	 // 1 string to match.
        return Xtensa::MISC2;	 // "MISC2"
      case '3':	 // 1 string to match.
        return Xtensa::MISC3;	 // "MISC3"
      }
      break;
    }
    break;
  case 6:	 // 5 strings to match.
    switch (Name[0]) {
    default: break;
    case 'C':	 // 1 string to match.
      if (memcmp(Name.data()+1, "COUNT", 5) != 0)
        break;
      return Xtensa::CCOUNT;	 // "CCOUNT"
    case 'I':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'C':	 // 1 string to match.
        if (memcmp(Name.data()+2, "OUNT", 4) != 0)
          break;
        return Xtensa::ICOUNT;	 // "ICOUNT"
      case 'N':	 // 1 string to match.
        if (memcmp(Name.data()+2, "TSET", 4) != 0)
          break;
        return Xtensa::INTSET;	 // "INTSET"
      }
      break;
    case 'L':	 // 1 string to match.
      if (memcmp(Name.data()+1, "COUNT", 5) != 0)
        break;
      return Xtensa::LCOUNT;	 // "LCOUNT"
    case 'M':	 // 1 string to match.
      if (memcmp(Name.data()+1, "EMCTL", 5) != 0)
        break;
      return Xtensa::MEMCTL;	 // "MEMCTL"
    }
    break;
  case 7:	 // 5 strings to match.
    switch (Name[0]) {
    default: break;
    case 'A':	 // 1 string to match.
      if (memcmp(Name.data()+1, "TOMCTL", 6) != 0)
        break;
      return Xtensa::ATOMCTL;	 // "ATOMCTL"
    case 'F':	 // 2 strings to match.
      if (memcmp(Name.data()+1, "64R_", 4) != 0)
        break;
      switch (Name[5]) {
      default: break;
      case 'H':	 // 1 string to match.
        if (Name[6] != 'I')
          break;
        return Xtensa::F64R_HI;	 // "F64R_HI"
      case 'L':	 // 1 string to match.
        if (Name[6] != 'O')
          break;
        return Xtensa::F64R_LO;	 // "F64R_LO"
      }
      break;
    case 'L':	 // 1 string to match.
      if (memcmp(Name.data()+1, "ITBASE", 6) != 0)
        break;
      return Xtensa::LITBASE;	 // "LITBASE"
    case 'V':	 // 1 string to match.
      if (memcmp(Name.data()+1, "ECBASE", 6) != 0)
        break;
      return Xtensa::VECBASE;	 // "VECBASE"
    }
    break;
  case 8:	 // 18 strings to match.
    switch (Name[0]) {
    default: break;
    case 'C':	 // 1 string to match.
      if (memcmp(Name.data()+1, "PENABLE", 7) != 0)
        break;
      return Xtensa::CPENABLE;	 // "CPENABLE"
    case 'D':	 // 4 strings to match.
      if (memcmp(Name.data()+1, "BREAK", 5) != 0)
        break;
      switch (Name[6]) {
      default: break;
      case 'A':	 // 2 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::DBREAKA0;	 // "DBREAKA0"
        case '1':	 // 1 string to match.
          return Xtensa::DBREAKA1;	 // "DBREAKA1"
        }
        break;
      case 'C':	 // 2 strings to match.
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::DBREAKC0;	 // "DBREAKC0"
        case '1':	 // 1 string to match.
          return Xtensa::DBREAKC1;	 // "DBREAKC1"
        }
        break;
      }
      break;
    case 'E':	 // 9 strings to match.
      if (memcmp(Name.data()+1, "XC", 2) != 0)
        break;
      switch (Name[3]) {
      default: break;
      case 'C':	 // 1 string to match.
        if (memcmp(Name.data()+4, "AUSE", 4) != 0)
          break;
        return Xtensa::EXCCAUSE;	 // "EXCCAUSE"
      case 'S':	 // 7 strings to match.
        if (memcmp(Name.data()+4, "AVE", 3) != 0)
          break;
        switch (Name[7]) {
        default: break;
        case '1':	 // 1 string to match.
          return Xtensa::EXCSAVE1;	 // "EXCSAVE1"
        case '2':	 // 1 string to match.
          return Xtensa::EXCSAVE2;	 // "EXCSAVE2"
        case '3':	 // 1 string to match.
          return Xtensa::EXCSAVE3;	 // "EXCSAVE3"
        case '4':	 // 1 string to match.
          return Xtensa::EXCSAVE4;	 // "EXCSAVE4"
        case '5':	 // 1 string to match.
          return Xtensa::EXCSAVE5;	 // "EXCSAVE5"
        case '6':	 // 1 string to match.
          return Xtensa::EXCSAVE6;	 // "EXCSAVE6"
        case '7':	 // 1 string to match.
          return Xtensa::EXCSAVE7;	 // "EXCSAVE7"
        }
        break;
      case 'V':	 // 1 string to match.
        if (memcmp(Name.data()+4, "ADDR", 4) != 0)
          break;
        return Xtensa::EXCVADDR;	 // "EXCVADDR"
      }
      break;
    case 'G':	 // 1 string to match.
      if (memcmp(Name.data()+1, "PIO_OUT", 7) != 0)
        break;
      return Xtensa::GPIO_OUT_S2;	 // "GPIO_OUT"
    case 'I':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case 'B':	 // 2 strings to match.
        if (memcmp(Name.data()+2, "REAKA", 5) != 0)
          break;
        switch (Name[7]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::IBREAKA0;	 // "IBREAKA0"
        case '1':	 // 1 string to match.
          return Xtensa::IBREAKA1;	 // "IBREAKA1"
        }
        break;
      case 'N':	 // 1 string to match.
        if (memcmp(Name.data()+2, "TCLEAR", 6) != 0)
          break;
        return Xtensa::INTCLEAR;	 // "INTCLEAR"
      }
      break;
    }
    break;
  case 9:	 // 9 strings to match.
    switch (Name[0]) {
    default: break;
    case 'C':	 // 5 strings to match.
      switch (Name[1]) {
      default: break;
      case 'C':	 // 3 strings to match.
        if (memcmp(Name.data()+2, "OMPARE", 6) != 0)
          break;
        switch (Name[8]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::CCOMPARE0;	 // "CCOMPARE0"
        case '1':	 // 1 string to match.
          return Xtensa::CCOMPARE1;	 // "CCOMPARE1"
        case '2':	 // 1 string to match.
          return Xtensa::CCOMPARE2;	 // "CCOMPARE2"
        }
        break;
      case 'O':	 // 2 strings to match.
        if (memcmp(Name.data()+2, "NFIGID", 6) != 0)
          break;
        switch (Name[8]) {
        default: break;
        case '0':	 // 1 string to match.
          return Xtensa::CONFIGID0;	 // "CONFIGID0"
        case '1':	 // 1 string to match.
          return Xtensa::CONFIGID1;	 // "CONFIGID1"
        }
        break;
      }
      break;
    case 'I':	 // 2 strings to match.
      if (memcmp(Name.data()+1, "NTE", 3) != 0)
        break;
      switch (Name[4]) {
      default: break;
      case 'N':	 // 1 string to match.
        if (memcmp(Name.data()+5, "ABLE", 4) != 0)
          break;
        return Xtensa::INTENABLE;	 // "INTENABLE"
      case 'R':	 // 1 string to match.
        if (memcmp(Name.data()+5, "RUPT", 4) != 0)
          break;
        return Xtensa::INTERRUPT;	 // "INTERRUPT"
      }
      break;
    case 'S':	 // 1 string to match.
      if (memcmp(Name.data()+1, "COMPARE1", 8) != 0)
        break;
      return Xtensa::SCOMPARE1;	 // "SCOMPARE1"
    case 'T':	 // 1 string to match.
      if (memcmp(Name.data()+1, "HREADPTR", 8) != 0)
        break;
      return Xtensa::THREADPTR;	 // "THREADPTR"
    }
    break;
  case 10:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case 'D':	 // 1 string to match.
      if (memcmp(Name.data()+1, "EBUGCAUSE", 9) != 0)
        break;
      return Xtensa::DEBUGCAUSE;	 // "DEBUGCAUSE"
    case 'W':	 // 1 string to match.
      if (memcmp(Name.data()+1, "INDOWBASE", 9) != 0)
        break;
      return Xtensa::WINDOWBASE;	 // "WINDOWBASE"
    }
    break;
  case 11:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case 'I':	 // 1 string to match.
      if (memcmp(Name.data()+1, "COUNTLEVEL", 10) != 0)
        break;
      return Xtensa::ICOUNTLEVEL;	 // "ICOUNTLEVEL"
    case 'W':	 // 1 string to match.
      if (memcmp(Name.data()+1, "INDOWSTART", 10) != 0)
        break;
      return Xtensa::WINDOWSTART;	 // "WINDOWSTART"
    }
    break;
  case 12:	 // 1 string to match.
    if (memcmp(Name.data()+0, "IBREAKENABLE", 12) != 0)
      break;
    return Xtensa::IBREAKENABLE;	 // "IBREAKENABLE"
  }
  return Xtensa::NoRegister;
}

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_HasDensityBit: return "";
  case Feature_HasSingleFloatBit: return "";
  case Feature_HasWindowedBit: return "";
  case Feature_HasMAC16Bit: return "";
  case Feature_HasBooleanBit: return "";
  case Feature_HasLoopBit: return "";
  case Feature_HasSEXTBit: return "";
  case Feature_HasCLAMPSBit: return "";
  case Feature_HasNSABit: return "";
  case Feature_HasMINMAXBit: return "";
  case Feature_HasMul16Bit: return "";
  case Feature_HasMul32Bit: return "";
  case Feature_HasMul32HighBit: return "";
  case Feature_HasDiv32Bit: return "";
  case Feature_HasS32C1IBit: return "";
  case Feature_HasForcedAtomicsBit: return "";
  case Feature_HasRegionProtectionBit: return "";
  case Feature_HasRelocatableVectorBit: return "";
  case Feature_HasMiscSRBit: return "";
  case Feature_HasExtendedL32RBit: return "";
  case Feature_HasDataCacheBit: return "";
  case Feature_HasTHREADPTRBit: return "";
  case Feature_HasHighPriInterruptsBit: return "";
  case Feature_HasInterruptBit: return "";
  case Feature_HasExceptionBit: return "";
  case Feature_HasDebugBit: return "";
  case Feature_HasPRIDBit: return "";
  case Feature_HasCoprocessorBit: return "";
  case Feature_HasDFPAccelBit: return "";
  case Feature_HasESP32S2OpsBit: return "";
  default: return "(unknown)";
  }
}

#endif // GET_SUBTARGET_FEATURE_NAME


#ifdef GET_MATCHER_IMPLEMENTATION
#undef GET_MATCHER_IMPLEMENTATION

enum {
  Tie0_1_1,
  Tie1_2_2,
};

static const uint8_t TiedAsmOperandTable[][3] = {
  /* Tie0_1_1 */ { 0, 1, 1 },
  /* Tie1_2_2 */ { 1, 2, 2 },
};

namespace {
enum OperatorConversionKind {
  CVT_Done,
  CVT_Reg,
  CVT_Tied,
  CVT_95_Reg,
  CVT_95_addImmOperands,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Reg1_0__PCRelTarget1_1,
  Convert__Uimm41_0,
  Convert__Reg1_0__Imm32n_951_1,
  Convert_NoOperands,
  Convert__Reg1_0__Reg1_1,
  Convert__Reg1_0__Reg1_1__Reg1_2,
  Convert__Reg1_0__Reg1_1__Imm81_2,
  Convert__Reg1_0__Reg1_1__Imm1n_151_2,
  Convert__Reg1_0__Reg1_1__Imm8_sh81_2,
  Convert__Reg1_0__Reg1_1__PCRelTarget1_2,
  Convert__Reg1_0__Uimm51_1__PCRelTarget1_2,
  Convert__Reg1_0__B4const1_1__PCRelTarget1_2,
  Convert__Reg1_0__B4constu1_1__PCRelTarget1_2,
  Convert__Uimm41_0__Uimm41_1,
  Convert__PCRelTarget1_0,
  Convert__Reg1_0,
  Convert__Reg1_0__Reg1_1__Uimm41_2,
  Convert__Reg1_0__Reg1_1__imm7_221_2,
  Convert__Select_2561_0,
  Convert__Reg1_0__Uimm41_1,
  Convert__Reg1_0__entry_imm121_1,
  Convert__Reg1_0__Reg1_1__Uimm51_2__Imm1_161_3,
  Convert__Reg1_0__Reg1_1__Offset8m161_2,
  Convert__Reg1_0__Reg1_1__Imm64n_4n1_2,
  Convert__Reg1_0__Reg1_1__Offset8m321_2,
  Convert__Reg1_0__Reg1_1__Offset4m321_2,
  Convert__Reg1_0__Reg1_1__Offset8m81_2,
  Convert__Reg1_0__Reg1_1__Tie1_2_2,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2,
  Convert__Reg1_0__Reg1_1__Reg1_1,
  Convert__Reg1_0__Imm12m1_1,
  Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3,
  Convert__Imm8n_71_0,
  Convert__Reg1_0__Tie0_1_1__Reg1_1__Offset8m321_2,
  Convert__Reg1_0__Reg1_1__Shimm1_311_2,
  Convert__Reg1_0__Reg1_1__Uimm51_2,
  Convert__Uimm51_0,
  Convert__Reg1_1__Reg1_0,
  Convert__Reg1_0__Reg1_1__Tie0_1_1__Tie1_2_2,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][11] = {
  // Convert__Reg1_0__PCRelTarget1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Uimm41_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__Imm32n_951_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__Reg1_0__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Imm81_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Imm1n_151_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Imm8_sh81_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__PCRelTarget1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Uimm51_1__PCRelTarget1_2
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__B4const1_1__PCRelTarget1_2
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__B4constu1_1__PCRelTarget1_2
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Uimm41_0__Uimm41_1
  { CVT_95_addImmOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__PCRelTarget1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Uimm41_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__imm7_221_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Select_2561_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__Uimm41_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__entry_imm121_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Uimm51_2__Imm1_161_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_95_addImmOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Offset8m161_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Imm64n_4n1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Offset8m321_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Offset4m321_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Offset8m81_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Tie1_2_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie1_2_2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Imm12m1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie1_2_2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_Done },
  // Convert__Imm8n_71_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1__Offset8m321_2
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Shimm1_311_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Uimm51_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Uimm51_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_1__Reg1_0
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Tie0_1_1__Tie1_2_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Tied, Tie0_1_1, CVT_Tied, Tie1_2_2, CVT_Done },
};

void XtensaAsmParser::
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
      static_cast<XtensaOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
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
      static_cast<XtensaOperand &>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addImmOperands:
      static_cast<XtensaOperand &>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    }
  }
}

void XtensaAsmParser::
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
  MCK_MR01, // register class 'MR01'
  MCK_MR23, // register class 'MR23'
  MCK_MR, // register class 'MR'
  MCK_UR, // register class 'UR'
  MCK_AR, // register class 'AR'
  MCK_BR, // register class 'BR'
  MCK_FPR, // register class 'FPR'
  MCK_SR, // register class 'SR'
  MCK_LAST_REGISTER = MCK_SR,
  MCK_B4const, // user defined class 'B4const_AsmOperand'
  MCK_B4constu, // user defined class 'B4constu_AsmOperand'
  MCK_entry_imm12, // user defined class 'Entry_Imm12_AsmOperand'
  MCK_Imm12, // user defined class 'Imm12_AsmOperand'
  MCK_Imm12m, // user defined class 'Imm12m_AsmOperand'
  MCK_Imm1_16, // user defined class 'Imm1_16_AsmOperand'
  MCK_Imm1n_15, // user defined class 'Imm1n_15_AsmOperand'
  MCK_Imm32n_95, // user defined class 'Imm32n_95_AsmOperand'
  MCK_Imm64n_4n, // user defined class 'Imm64n_4n_AsmOperand'
  MCK_imm7_22, // user defined class 'Imm7_22_AsmOperand'
  MCK_Imm8, // user defined class 'Imm8_AsmOperand'
  MCK_Imm8_sh8, // user defined class 'Imm8_sh8_AsmOperand'
  MCK_Imm8n_7, // user defined class 'Imm8n_7_AsmOperand'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_Offset4m32, // user defined class 'Offset4m32_AsmOperand'
  MCK_Offset8m16, // user defined class 'Offset8m16_AsmOperand'
  MCK_Offset8m32, // user defined class 'Offset8m32_AsmOperand'
  MCK_Offset8m8, // user defined class 'Offset8m8_AsmOperand'
  MCK_Select_256, // user defined class 'Select_256_AsmOperand'
  MCK_Shimm1_31, // user defined class 'Shimm1_31_AsmOperand'
  MCK_Uimm4, // user defined class 'Uimm4_AsmOperand'
  MCK_Uimm5, // user defined class 'Uimm5_AsmOperand'
  MCK_PCRelTarget, // user defined class 'XtensaPCRelTargetAsmOperand'
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
    {0, 4, 6},
    {6, 4, 6},
    {12, 9, 1},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
    {13, 0, 0},
  };

  static constexpr uint8_t Data[] = {
    0x61,
    0x18,
  };

  auto &Entry = Table[A];
  unsigned Idx = B - Entry.Start;
  if (Idx >= Entry.Length)
    return false;
  Idx += Entry.Offset;
  return (Data[Idx / 8] >> (Idx % 8)) & 1;
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind, const MCSubtargetInfo &STI) {
  XtensaOperand &Operand = (XtensaOperand &)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  case MCK_B4const: {
    DiagnosticPredicate DP(Operand.isB4const());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidB4const;
    break;
  }
  case MCK_B4constu: {
    DiagnosticPredicate DP(Operand.isB4constu());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidB4constu;
    break;
  }
  case MCK_entry_imm12: {
    DiagnosticPredicate DP(Operand.isentry_imm12());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_Invalidentry_imm12;
    break;
  }
  case MCK_Imm12: {
    DiagnosticPredicate DP(Operand.isImm12());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidImm12;
    break;
  }
  case MCK_Imm12m: {
    DiagnosticPredicate DP(Operand.isImm12m());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidImm12m;
    break;
  }
  case MCK_Imm1_16: {
    DiagnosticPredicate DP(Operand.isImm1_16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidImm1_16;
    break;
  }
  case MCK_Imm1n_15: {
    DiagnosticPredicate DP(Operand.isImm1n_15());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidImm1n_15;
    break;
  }
  case MCK_Imm32n_95: {
    DiagnosticPredicate DP(Operand.isImm32n_95());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidImm32n_95;
    break;
  }
  case MCK_Imm64n_4n: {
    DiagnosticPredicate DP(Operand.isImm64n_4n());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidImm64n_4n;
    break;
  }
  case MCK_imm7_22: {
    DiagnosticPredicate DP(Operand.isimm7_22());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_Invalidimm7_22;
    break;
  }
  case MCK_Imm8: {
    DiagnosticPredicate DP(Operand.isImm8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidImm8;
    break;
  }
  case MCK_Imm8_sh8: {
    DiagnosticPredicate DP(Operand.isImm8_sh8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidImm8_sh8;
    break;
  }
  case MCK_Imm8n_7: {
    DiagnosticPredicate DP(Operand.isImm8n_7());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidImm8n_7;
    break;
  }
  case MCK_Imm: {
    DiagnosticPredicate DP(Operand.isImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  case MCK_Offset4m32: {
    DiagnosticPredicate DP(Operand.isOffset4m32());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidOffset4m32;
    break;
  }
  case MCK_Offset8m16: {
    DiagnosticPredicate DP(Operand.isOffset8m16());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidOffset8m16;
    break;
  }
  case MCK_Offset8m32: {
    DiagnosticPredicate DP(Operand.isOffset8m32());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidOffset8m32;
    break;
  }
  case MCK_Offset8m8: {
    DiagnosticPredicate DP(Operand.isOffset8m8());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidOffset8m8;
    break;
  }
  case MCK_Select_256: {
    DiagnosticPredicate DP(Operand.isSelect_256());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidSelect_256;
    break;
  }
  case MCK_Shimm1_31: {
    DiagnosticPredicate DP(Operand.isShimm1_31());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidShimm1_31;
    break;
  }
  case MCK_Uimm4: {
    DiagnosticPredicate DP(Operand.isUimm4());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidUimm4;
    break;
  }
  case MCK_Uimm5: {
    DiagnosticPredicate DP(Operand.isUimm5());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return XtensaAsmParser::Match_InvalidUimm5;
    break;
  }
  case MCK_PCRelTarget: {
    DiagnosticPredicate DP(Operand.isImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
  }
  } // end switch (Kind)

  if (Operand.isReg()) {
    static constexpr uint16_t Table[Xtensa::NUM_TARGET_REGS] = {
      InvalidMatchClass,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_UR,
      MCK_UR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_AR,
      MCK_UR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_AR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_BR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_FPR,
      MCK_UR,
      MCK_SR,
      MCK_SR,
      MCK_MR01,
      MCK_MR01,
      MCK_MR23,
      MCK_MR23,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_SR,
      MCK_UR,
      MCK_UR,
      MCK_UR,
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
  case MCK_MR01: return "MCK_MR01";
  case MCK_MR23: return "MCK_MR23";
  case MCK_MR: return "MCK_MR";
  case MCK_UR: return "MCK_UR";
  case MCK_AR: return "MCK_AR";
  case MCK_BR: return "MCK_BR";
  case MCK_FPR: return "MCK_FPR";
  case MCK_SR: return "MCK_SR";
  case MCK_B4const: return "MCK_B4const";
  case MCK_B4constu: return "MCK_B4constu";
  case MCK_entry_imm12: return "MCK_entry_imm12";
  case MCK_Imm12: return "MCK_Imm12";
  case MCK_Imm12m: return "MCK_Imm12m";
  case MCK_Imm1_16: return "MCK_Imm1_16";
  case MCK_Imm1n_15: return "MCK_Imm1n_15";
  case MCK_Imm32n_95: return "MCK_Imm32n_95";
  case MCK_Imm64n_4n: return "MCK_Imm64n_4n";
  case MCK_imm7_22: return "MCK_imm7_22";
  case MCK_Imm8: return "MCK_Imm8";
  case MCK_Imm8_sh8: return "MCK_Imm8_sh8";
  case MCK_Imm8n_7: return "MCK_Imm8n_7";
  case MCK_Imm: return "MCK_Imm";
  case MCK_Offset4m32: return "MCK_Offset4m32";
  case MCK_Offset8m16: return "MCK_Offset8m16";
  case MCK_Offset8m32: return "MCK_Offset8m32";
  case MCK_Offset8m8: return "MCK_Offset8m8";
  case MCK_Select_256: return "MCK_Select_256";
  case MCK_Shimm1_31: return "MCK_Shimm1_31";
  case MCK_Uimm4: return "MCK_Uimm4";
  case MCK_Uimm5: return "MCK_Uimm5";
  case MCK_PCRelTarget: return "MCK_PCRelTarget";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
FeatureBitset XtensaAsmParser::
ComputeAvailableFeatures(const FeatureBitset &FB) const {
  FeatureBitset Features;
  if (FB[Xtensa::FeatureDensity])
    Features.set(Feature_HasDensityBit);
  if (FB[Xtensa::FeatureSingleFloat])
    Features.set(Feature_HasSingleFloatBit);
  if (FB[Xtensa::FeatureWindowed])
    Features.set(Feature_HasWindowedBit);
  if (FB[Xtensa::FeatureMAC16])
    Features.set(Feature_HasMAC16Bit);
  if (FB[Xtensa::FeatureBoolean])
    Features.set(Feature_HasBooleanBit);
  if (FB[Xtensa::FeatureLoop])
    Features.set(Feature_HasLoopBit);
  if (FB[Xtensa::FeatureSEXT])
    Features.set(Feature_HasSEXTBit);
  if (FB[Xtensa::FeatureCLAMPS])
    Features.set(Feature_HasCLAMPSBit);
  if (FB[Xtensa::FeatureNSA])
    Features.set(Feature_HasNSABit);
  if (FB[Xtensa::FeatureMINMAX])
    Features.set(Feature_HasMINMAXBit);
  if (FB[Xtensa::FeatureMul16])
    Features.set(Feature_HasMul16Bit);
  if (FB[Xtensa::FeatureMul32])
    Features.set(Feature_HasMul32Bit);
  if (FB[Xtensa::FeatureMul32High])
    Features.set(Feature_HasMul32HighBit);
  if (FB[Xtensa::FeatureDiv32])
    Features.set(Feature_HasDiv32Bit);
  if (FB[Xtensa::FeatureS32C1I])
    Features.set(Feature_HasS32C1IBit);
  if (FB[Xtensa::FeatureForcedAtomics])
    Features.set(Feature_HasForcedAtomicsBit);
  if (FB[Xtensa::FeatureRegionProtection])
    Features.set(Feature_HasRegionProtectionBit);
  if (FB[Xtensa::FeatureRelocatableVector])
    Features.set(Feature_HasRelocatableVectorBit);
  if (FB[Xtensa::FeatureMiscSR])
    Features.set(Feature_HasMiscSRBit);
  if (FB[Xtensa::FeatureExtendedL32R])
    Features.set(Feature_HasExtendedL32RBit);
  if (FB[Xtensa::FeatureDataCache])
    Features.set(Feature_HasDataCacheBit);
  if (FB[Xtensa::FeatureTHREADPTR])
    Features.set(Feature_HasTHREADPTRBit);
  if (FB[Xtensa::FeatureHighPriInterrupts])
    Features.set(Feature_HasHighPriInterruptsBit);
  if (FB[Xtensa::FeatureInterrupt])
    Features.set(Feature_HasInterruptBit);
  if (FB[Xtensa::FeatureException])
    Features.set(Feature_HasExceptionBit);
  if (FB[Xtensa::FeatureDebug])
    Features.set(Feature_HasDebugBit);
  if (FB[Xtensa::FeaturePRID])
    Features.set(Feature_HasPRIDBit);
  if (FB[Xtensa::FeatureCoprocessor])
    Features.set(Feature_HasCoprocessorBit);
  if (FB[Xtensa::FeatureDFPAccel])
    Features.set(Feature_HasDFPAccelBit);
  if (FB[Xtensa::FeatureESP32S2Ops])
    Features.set(Feature_HasESP32S2OpsBit);
  return Features;
}

static bool checkAsmTiedOperandConstraints(const XtensaAsmParser&AsmParser,
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
    "\003_bf\010_break.n\003_bt\005_loop\010_loopgtz\010_loopnez\007_movi.n\005"
    "_retw\007_retw.n\003abs\005abs.s\003add\005add.n\005add.s\010addexp.s\t"
    "addexpm.s\004addi\006addi.n\005addmi\005addx2\005addx4\005addx8\004all4"
    "\004all8\003and\004andb\005andbc\004any4\004any8\004ball\004bany\003bbc"
    "\004bbci\003bbs\004bbsi\003beq\004beqi\004beqz\006beqz.n\002bf\003bge\004"
    "bgei\004bgeu\005bgeui\004bgez\003blt\004blti\004bltu\005bltui\004bltz\005"
    "bnall\003bne\004bnei\004bnez\006bnez.n\005bnone\005break\007break.n\002"
    "bt\005call0\006call12\005call4\005call8\006callx0\007callx12\006callx4\006"
    "callx8\006ceil.s\006clamps\020clr_bit_gpio_out\007const.s\006div0.s\006"
    "divn.s\005dsync\005entry\005esync\004excw\005extui\004extw\007float.s\007"
    "floor.s\013get_gpio_in\005idtlb\005iitlb\003ill\005ill.n\005isync\001j\002"
    "jx\005l16si\005l16ui\004l32e\004l32i\006l32i.n\004l32r\004l8ui\005lddec"
    "\010lddr32.p\005ldinc\004loop\007loopgtz\007loopnez\003lsi\004lsip\003l"
    "sx\004lsxp\006madd.s\007maddn.s\003max\004maxu\004memw\003min\004minu\010"
    "mkdadj.s\010mksadj.s\003mov\005mov.n\005mov.s\006moveqz\010moveqz.s\004"
    "movf\006movf.s\006movgez\010movgez.s\004movi\006movi.n\006movltz\010mov"
    "ltz.s\006movnez\010movnez.s\005movsp\004movt\006movt.s\006msub.s\tmul.a"
    "a.hh\tmul.aa.hl\tmul.aa.lh\tmul.aa.ll\tmul.ad.hh\tmul.ad.hl\tmul.ad.lh\t"
    "mul.ad.ll\tmul.da.hh\tmul.da.hl\tmul.da.lh\tmul.da.ll\tmul.dd.hh\tmul.d"
    "d.hl\tmul.dd.lh\tmul.dd.ll\005mul.s\006mul16s\006mul16u\nmula.aa.hh\nmu"
    "la.aa.hl\nmula.aa.lh\nmula.aa.ll\nmula.ad.hh\nmula.ad.hl\nmula.ad.lh\nm"
    "ula.ad.ll\nmula.da.hh\020mula.da.hh.lddec\020mula.da.hh.ldinc\nmula.da."
    "hl\020mula.da.hl.lddec\020mula.da.hl.ldinc\nmula.da.lh\020mula.da.lh.ld"
    "dec\020mula.da.lh.ldinc\nmula.da.ll\020mula.da.ll.lddec\020mula.da.ll.l"
    "dinc\nmula.dd.hh\020mula.dd.hh.lddec\020mula.dd.hh.ldinc\nmula.dd.hl\020"
    "mula.dd.hl.lddec\020mula.dd.hl.ldinc\nmula.dd.lh\020mula.dd.lh.lddec\020"
    "mula.dd.lh.ldinc\nmula.dd.ll\020mula.dd.ll.lddec\020mula.dd.ll.ldinc\004"
    "mull\nmuls.aa.hh\nmuls.aa.hl\nmuls.aa.lh\nmuls.aa.ll\nmuls.ad.hh\nmuls."
    "ad.hl\nmuls.ad.lh\nmuls.ad.ll\nmuls.da.hh\nmuls.da.hl\nmuls.da.lh\nmuls"
    ".da.ll\nmuls.dd.hh\nmuls.dd.hl\nmuls.dd.lh\nmuls.dd.ll\005mulsh\005mulu"
    "h\003neg\005neg.s\010nexp01.s\003nop\005nop.n\003nsa\004nsau\005oeq.s\005"
    "ole.s\005olt.s\002or\003orb\004orbc\005pdtlb\005pitlb\004quos\004quou\006"
    "rdtlb0\006rdtlb1\010recip0.s\004rems\004remu\003ret\005ret.n\004retw\006"
    "retw.n\004rfde\003rfe\003rfi\003rfr\004rfwo\004rfwu\006ritlb0\006ritlb1"
    "\004rotw\007round.s\004rsil\010rsqrt0.s\003rsr\005rsync\003rur\004s16i\006"
    "s32c1i\004s32e\004s32i\006s32i.n\003s8i\010sddr32.p\020set_bit_gpio_out"
    "\004sext\003sll\004slli\007sqrt0.s\003sra\004srai\003src\003srl\004srli"
    "\005ssa8l\004ssai\003ssi\004ssip\003ssl\003ssr\003ssx\004ssxp\003sub\005"
    "sub.s\005subx2\005subx4\005subx8\007syscall\007trunc.s\005ueq.s\010uflo"
    "at.s\005ule.s\005ult.s\numul.aa.hh\numul.aa.hl\numul.aa.lh\numul.aa.ll\004"
    "un.s\010utrunc.s\005waiti\005wdtlb\003wfr\005witlb\020wr_mask_gpio_out\003"
    "wsr\003wur\003xor\004xorb\003xsr";

// Feature bitsets.
enum : uint8_t {
  AMFBS_None,
  AMFBS_HasBoolean,
  AMFBS_HasCLAMPS,
  AMFBS_HasDebug,
  AMFBS_HasDensity,
  AMFBS_HasDiv32,
  AMFBS_HasESP32S2Ops,
  AMFBS_HasException,
  AMFBS_HasHighPriInterrupts,
  AMFBS_HasInterrupt,
  AMFBS_HasLoop,
  AMFBS_HasMAC16,
  AMFBS_HasMINMAX,
  AMFBS_HasMul16,
  AMFBS_HasMul32,
  AMFBS_HasMul32High,
  AMFBS_HasNSA,
  AMFBS_HasRegionProtection,
  AMFBS_HasS32C1I,
  AMFBS_HasSEXT,
  AMFBS_HasSingleFloat,
  AMFBS_HasWindowed,
  AMFBS_HasBoolean_HasSingleFloat,
  AMFBS_HasDensity_HasDebug,
  AMFBS_HasWindowed_HasDensity,
};

static constexpr FeatureBitset FeatureBitsets[] = {
  {}, // AMFBS_None
  {Feature_HasBooleanBit, }, // AMFBS_HasBoolean
  {Feature_HasCLAMPSBit, }, // AMFBS_HasCLAMPS
  {Feature_HasDebugBit, }, // AMFBS_HasDebug
  {Feature_HasDensityBit, }, // AMFBS_HasDensity
  {Feature_HasDiv32Bit, }, // AMFBS_HasDiv32
  {Feature_HasESP32S2OpsBit, }, // AMFBS_HasESP32S2Ops
  {Feature_HasExceptionBit, }, // AMFBS_HasException
  {Feature_HasHighPriInterruptsBit, }, // AMFBS_HasHighPriInterrupts
  {Feature_HasInterruptBit, }, // AMFBS_HasInterrupt
  {Feature_HasLoopBit, }, // AMFBS_HasLoop
  {Feature_HasMAC16Bit, }, // AMFBS_HasMAC16
  {Feature_HasMINMAXBit, }, // AMFBS_HasMINMAX
  {Feature_HasMul16Bit, }, // AMFBS_HasMul16
  {Feature_HasMul32Bit, }, // AMFBS_HasMul32
  {Feature_HasMul32HighBit, }, // AMFBS_HasMul32High
  {Feature_HasNSABit, }, // AMFBS_HasNSA
  {Feature_HasRegionProtectionBit, }, // AMFBS_HasRegionProtection
  {Feature_HasS32C1IBit, }, // AMFBS_HasS32C1I
  {Feature_HasSEXTBit, }, // AMFBS_HasSEXT
  {Feature_HasSingleFloatBit, }, // AMFBS_HasSingleFloat
  {Feature_HasWindowedBit, }, // AMFBS_HasWindowed
  {Feature_HasBooleanBit, Feature_HasSingleFloatBit, }, // AMFBS_HasBoolean_HasSingleFloat
  {Feature_HasDensityBit, Feature_HasDebugBit, }, // AMFBS_HasDensity_HasDebug
  {Feature_HasWindowedBit, Feature_HasDensityBit, }, // AMFBS_HasWindowed_HasDensity
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
  { 0 /* _BF */, Xtensa::BF, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_BR, MCK_PCRelTarget }, },
  { 4 /* _break.n */, Xtensa::BREAK_N, Convert__Uimm41_0, AMFBS_None, { MCK_Uimm4 }, },
  { 13 /* _BT */, Xtensa::BT, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_BR, MCK_PCRelTarget }, },
  { 17 /* _loop */, Xtensa::LOOP, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_AR, MCK_PCRelTarget }, },
  { 23 /* _loopgtz */, Xtensa::LOOPGTZ, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_AR, MCK_PCRelTarget }, },
  { 32 /* _loopnez */, Xtensa::LOOPNEZ, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_AR, MCK_PCRelTarget }, },
  { 41 /* _movi.n */, Xtensa::MOVI_N, Convert__Reg1_0__Imm32n_951_1, AMFBS_None, { MCK_AR, MCK_Imm32n_95 }, },
  { 49 /* _retw */, Xtensa::RETW, Convert_NoOperands, AMFBS_None, {  }, },
  { 55 /* _retw.n */, Xtensa::RETW_N, Convert_NoOperands, AMFBS_None, {  }, },
  { 63 /* abs */, Xtensa::ABS, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_AR, MCK_AR }, },
  { 67 /* abs.s */, Xtensa::ABS_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 73 /* add */, Xtensa::ADD, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 77 /* add.n */, Xtensa::ADD_N, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasDensity, { MCK_AR, MCK_AR, MCK_AR }, },
  { 83 /* add.s */, Xtensa::ADD_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_FPR }, },
  { 89 /* addexp.s */, Xtensa::ADDEXP_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 98 /* addexpm.s */, Xtensa::ADDEXPM_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 108 /* addi */, Xtensa::ADDI, Convert__Reg1_0__Reg1_1__Imm81_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Imm8 }, },
  { 113 /* addi.n */, Xtensa::ADDI_N, Convert__Reg1_0__Reg1_1__Imm1n_151_2, AMFBS_HasDensity, { MCK_AR, MCK_AR, MCK_Imm1n_15 }, },
  { 120 /* addmi */, Xtensa::ADDMI, Convert__Reg1_0__Reg1_1__Imm8_sh81_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Imm8_sh8 }, },
  { 126 /* addx2 */, Xtensa::ADDX2, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 132 /* addx4 */, Xtensa::ADDX4, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 138 /* addx8 */, Xtensa::ADDX8, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 144 /* all4 */, Xtensa::ALL4, Convert__Reg1_0__Reg1_1, AMFBS_HasBoolean, { MCK_BR, MCK_BR }, },
  { 149 /* all8 */, Xtensa::ALL8, Convert__Reg1_0__Reg1_1, AMFBS_HasBoolean, { MCK_BR, MCK_BR }, },
  { 154 /* and */, Xtensa::AND, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 158 /* andb */, Xtensa::ANDB, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasBoolean, { MCK_BR, MCK_BR, MCK_BR }, },
  { 163 /* andbc */, Xtensa::ANDBC, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasBoolean, { MCK_BR, MCK_BR, MCK_BR }, },
  { 169 /* any4 */, Xtensa::ANY4, Convert__Reg1_0__Reg1_1, AMFBS_HasBoolean, { MCK_BR, MCK_BR }, },
  { 174 /* any8 */, Xtensa::ANY8, Convert__Reg1_0__Reg1_1, AMFBS_HasBoolean, { MCK_BR, MCK_BR }, },
  { 179 /* ball */, Xtensa::BALL, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 184 /* bany */, Xtensa::BANY, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 189 /* bbc */, Xtensa::BBC, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 193 /* bbci */, Xtensa::BBCI, Convert__Reg1_0__Uimm51_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_Uimm5, MCK_PCRelTarget }, },
  { 198 /* bbs */, Xtensa::BBS, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 202 /* bbsi */, Xtensa::BBSI, Convert__Reg1_0__Uimm51_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_Uimm5, MCK_PCRelTarget }, },
  { 207 /* beq */, Xtensa::BEQ, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 211 /* beqi */, Xtensa::BEQI, Convert__Reg1_0__B4const1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_B4const, MCK_PCRelTarget }, },
  { 216 /* beqz */, Xtensa::BEQZ, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_AR, MCK_PCRelTarget }, },
  { 221 /* beqz.n */, Xtensa::BEQZ_N, Convert__Reg1_0__PCRelTarget1_1, AMFBS_HasDensity, { MCK_AR, MCK_PCRelTarget }, },
  { 228 /* bf */, Xtensa::BF, Convert__Reg1_0__PCRelTarget1_1, AMFBS_HasBoolean, { MCK_BR, MCK_PCRelTarget }, },
  { 231 /* bge */, Xtensa::BGE, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 235 /* bgei */, Xtensa::BGEI, Convert__Reg1_0__B4const1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_B4const, MCK_PCRelTarget }, },
  { 240 /* bgeu */, Xtensa::BGEU, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 245 /* bgeui */, Xtensa::BGEUI, Convert__Reg1_0__B4constu1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_B4constu, MCK_PCRelTarget }, },
  { 251 /* bgez */, Xtensa::BGEZ, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_AR, MCK_PCRelTarget }, },
  { 256 /* blt */, Xtensa::BLT, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 260 /* blti */, Xtensa::BLTI, Convert__Reg1_0__B4const1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_B4const, MCK_PCRelTarget }, },
  { 265 /* bltu */, Xtensa::BLTU, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 270 /* bltui */, Xtensa::BLTUI, Convert__Reg1_0__B4constu1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_B4constu, MCK_PCRelTarget }, },
  { 276 /* bltz */, Xtensa::BLTZ, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_AR, MCK_PCRelTarget }, },
  { 281 /* bnall */, Xtensa::BNALL, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 287 /* bne */, Xtensa::BNE, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 291 /* bnei */, Xtensa::BNEI, Convert__Reg1_0__B4const1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_B4const, MCK_PCRelTarget }, },
  { 296 /* bnez */, Xtensa::BNEZ, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_AR, MCK_PCRelTarget }, },
  { 301 /* bnez.n */, Xtensa::BNEZ_N, Convert__Reg1_0__PCRelTarget1_1, AMFBS_HasDensity, { MCK_AR, MCK_PCRelTarget }, },
  { 308 /* bnone */, Xtensa::BNONE, Convert__Reg1_0__Reg1_1__PCRelTarget1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_PCRelTarget }, },
  { 314 /* break */, Xtensa::BREAK, Convert__Uimm41_0__Uimm41_1, AMFBS_HasDebug, { MCK_Uimm4, MCK_Uimm4 }, },
  { 320 /* break.n */, Xtensa::BREAK_N, Convert__Uimm41_0, AMFBS_HasDensity_HasDebug, { MCK_Uimm4 }, },
  { 328 /* bt */, Xtensa::BT, Convert__Reg1_0__PCRelTarget1_1, AMFBS_HasBoolean, { MCK_BR, MCK_PCRelTarget }, },
  { 331 /* call0 */, Xtensa::CALL0, Convert__PCRelTarget1_0, AMFBS_None, { MCK_PCRelTarget }, },
  { 337 /* call12 */, Xtensa::CALL12, Convert__PCRelTarget1_0, AMFBS_HasWindowed, { MCK_PCRelTarget }, },
  { 344 /* call4 */, Xtensa::CALL4, Convert__PCRelTarget1_0, AMFBS_HasWindowed, { MCK_PCRelTarget }, },
  { 350 /* call8 */, Xtensa::CALL8, Convert__PCRelTarget1_0, AMFBS_HasWindowed, { MCK_PCRelTarget }, },
  { 356 /* callx0 */, Xtensa::CALLX0, Convert__Reg1_0, AMFBS_None, { MCK_AR }, },
  { 363 /* callx12 */, Xtensa::CALLX12, Convert__Reg1_0, AMFBS_HasWindowed, { MCK_AR }, },
  { 371 /* callx4 */, Xtensa::CALLX4, Convert__Reg1_0, AMFBS_HasWindowed, { MCK_AR }, },
  { 378 /* callx8 */, Xtensa::CALLX8, Convert__Reg1_0, AMFBS_HasWindowed, { MCK_AR }, },
  { 385 /* ceil.s */, Xtensa::CEIL_S, Convert__Reg1_0__Reg1_1__Uimm41_2, AMFBS_HasSingleFloat, { MCK_AR, MCK_FPR, MCK_Uimm4 }, },
  { 392 /* clamps */, Xtensa::CLAMPS, Convert__Reg1_0__Reg1_1__imm7_221_2, AMFBS_HasCLAMPS, { MCK_AR, MCK_AR, MCK_imm7_22 }, },
  { 399 /* clr_bit_gpio_out */, Xtensa::CLR_BIT_GPIO_OUT, Convert__Select_2561_0, AMFBS_HasESP32S2Ops, { MCK_Select_256 }, },
  { 416 /* const.s */, Xtensa::CONST_S, Convert__Reg1_0__Uimm41_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_Uimm4 }, },
  { 424 /* div0.s */, Xtensa::DIV0_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 431 /* divn.s */, Xtensa::DIVN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_FPR }, },
  { 438 /* dsync */, Xtensa::DSYNC, Convert_NoOperands, AMFBS_None, {  }, },
  { 444 /* entry */, Xtensa::ENTRY, Convert__Reg1_0__entry_imm121_1, AMFBS_HasWindowed, { MCK_AR, MCK_entry_imm12 }, },
  { 450 /* esync */, Xtensa::ESYNC, Convert_NoOperands, AMFBS_None, {  }, },
  { 456 /* excw */, Xtensa::EXCW, Convert_NoOperands, AMFBS_HasException, {  }, },
  { 461 /* extui */, Xtensa::EXTUI, Convert__Reg1_0__Reg1_1__Uimm51_2__Imm1_161_3, AMFBS_None, { MCK_AR, MCK_AR, MCK_Uimm5, MCK_Imm1_16 }, },
  { 467 /* extw */, Xtensa::EXTW, Convert_NoOperands, AMFBS_None, {  }, },
  { 472 /* float.s */, Xtensa::FLOAT_S, Convert__Reg1_0__Reg1_1__Uimm41_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_Uimm4 }, },
  { 480 /* floor.s */, Xtensa::FLOOR_S, Convert__Reg1_0__Reg1_1__Uimm41_2, AMFBS_HasSingleFloat, { MCK_AR, MCK_FPR, MCK_Uimm4 }, },
  { 488 /* get_gpio_in */, Xtensa::GET_GPIO_IN, Convert__Reg1_0, AMFBS_HasESP32S2Ops, { MCK_AR }, },
  { 500 /* idtlb */, Xtensa::IDTLB, Convert__Reg1_0, AMFBS_HasRegionProtection, { MCK_AR }, },
  { 506 /* iitlb */, Xtensa::IITLB, Convert__Reg1_0, AMFBS_HasRegionProtection, { MCK_AR }, },
  { 512 /* ill */, Xtensa::ILL, Convert_NoOperands, AMFBS_None, {  }, },
  { 516 /* ill.n */, Xtensa::ILL_N, Convert_NoOperands, AMFBS_HasDensity, {  }, },
  { 522 /* isync */, Xtensa::ISYNC, Convert_NoOperands, AMFBS_None, {  }, },
  { 528 /* j */, Xtensa::J, Convert__PCRelTarget1_0, AMFBS_None, { MCK_PCRelTarget }, },
  { 530 /* jx */, Xtensa::JX, Convert__Reg1_0, AMFBS_None, { MCK_AR }, },
  { 533 /* l16si */, Xtensa::L16SI, Convert__Reg1_0__Reg1_1__Offset8m161_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Offset8m16 }, },
  { 539 /* l16ui */, Xtensa::L16UI, Convert__Reg1_0__Reg1_1__Offset8m161_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Offset8m16 }, },
  { 545 /* l32e */, Xtensa::L32E, Convert__Reg1_0__Reg1_1__Imm64n_4n1_2, AMFBS_HasWindowed, { MCK_AR, MCK_AR, MCK_Imm64n_4n }, },
  { 550 /* l32i */, Xtensa::L32I, Convert__Reg1_0__Reg1_1__Offset8m321_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Offset8m32 }, },
  { 555 /* l32i.n */, Xtensa::L32I_N, Convert__Reg1_0__Reg1_1__Offset4m321_2, AMFBS_HasDensity, { MCK_AR, MCK_AR, MCK_Offset4m32 }, },
  { 562 /* l32r */, Xtensa::L32R, Convert__Reg1_0__PCRelTarget1_1, AMFBS_None, { MCK_AR, MCK_PCRelTarget }, },
  { 567 /* l8ui */, Xtensa::L8UI, Convert__Reg1_0__Reg1_1__Offset8m81_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Offset8m8 }, },
  { 572 /* lddec */, Xtensa::LDDEC, Convert__Reg1_0__Reg1_1__Tie1_2_2, AMFBS_HasMAC16, { MCK_MR, MCK_AR }, },
  { 578 /* lddr32.p */, Xtensa::LDDR32P, Convert__Reg1_0, AMFBS_HasDebug, { MCK_AR }, },
  { 587 /* ldinc */, Xtensa::LDINC, Convert__Reg1_0__Reg1_1__Tie1_2_2, AMFBS_HasMAC16, { MCK_MR, MCK_AR }, },
  { 593 /* loop */, Xtensa::LOOP, Convert__Reg1_0__PCRelTarget1_1, AMFBS_HasLoop, { MCK_AR, MCK_PCRelTarget }, },
  { 598 /* loopgtz */, Xtensa::LOOPGTZ, Convert__Reg1_0__PCRelTarget1_1, AMFBS_HasLoop, { MCK_AR, MCK_PCRelTarget }, },
  { 606 /* loopnez */, Xtensa::LOOPNEZ, Convert__Reg1_0__PCRelTarget1_1, AMFBS_HasLoop, { MCK_AR, MCK_PCRelTarget }, },
  { 614 /* lsi */, Xtensa::LSI, Convert__Reg1_0__Reg1_1__Offset8m321_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_Offset8m32 }, },
  { 618 /* lsip */, Xtensa::LSIP, Convert__Reg1_0__Reg1_1__Offset8m321_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_Offset8m32 }, },
  { 623 /* lsx */, Xtensa::LSX, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_AR }, },
  { 627 /* lsxp */, Xtensa::LSXP, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_AR }, },
  { 632 /* madd.s */, Xtensa::MADD_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_FPR }, },
  { 639 /* maddn.s */, Xtensa::MADDN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_FPR }, },
  { 647 /* max */, Xtensa::MAX, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasMINMAX, { MCK_AR, MCK_AR, MCK_AR }, },
  { 651 /* maxu */, Xtensa::MAXU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasMINMAX, { MCK_AR, MCK_AR, MCK_AR }, },
  { 656 /* memw */, Xtensa::MEMW, Convert_NoOperands, AMFBS_None, {  }, },
  { 661 /* min */, Xtensa::MIN, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasMINMAX, { MCK_AR, MCK_AR, MCK_AR }, },
  { 665 /* minu */, Xtensa::MINU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasMINMAX, { MCK_AR, MCK_AR, MCK_AR }, },
  { 670 /* mkdadj.s */, Xtensa::MKDADJ_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 679 /* mksadj.s */, Xtensa::MKSADJ_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 688 /* mov */, Xtensa::OR, Convert__Reg1_0__Reg1_1__Reg1_1, AMFBS_None, { MCK_AR, MCK_AR }, },
  { 692 /* mov.n */, Xtensa::MOV_N, Convert__Reg1_0__Reg1_1, AMFBS_HasDensity, { MCK_AR, MCK_AR }, },
  { 698 /* mov.s */, Xtensa::MOV_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 704 /* moveqz */, Xtensa::MOVEQZ, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 711 /* moveqz.s */, Xtensa::MOVEQZ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_AR }, },
  { 720 /* movf */, Xtensa::MOVF, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasBoolean, { MCK_AR, MCK_AR, MCK_BR }, },
  { 725 /* movf.s */, Xtensa::MOVF_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasBoolean_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_BR }, },
  { 732 /* movgez */, Xtensa::MOVGEZ, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 739 /* movgez.s */, Xtensa::MOVGEZ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_AR }, },
  { 748 /* movi */, Xtensa::MOVI, Convert__Reg1_0__Imm12m1_1, AMFBS_None, { MCK_AR, MCK_Imm12m }, },
  { 753 /* movi.n */, Xtensa::MOVI_N, Convert__Reg1_0__Imm32n_951_1, AMFBS_HasDensity, { MCK_AR, MCK_Imm32n_95 }, },
  { 760 /* movltz */, Xtensa::MOVLTZ, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 767 /* movltz.s */, Xtensa::MOVLTZ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_AR }, },
  { 776 /* movnez */, Xtensa::MOVNEZ, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 783 /* movnez.s */, Xtensa::MOVNEZ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_AR }, },
  { 792 /* movsp */, Xtensa::MOVSP, Convert__Reg1_0__Reg1_1, AMFBS_HasWindowed, { MCK_AR, MCK_AR }, },
  { 798 /* movt */, Xtensa::MOVT, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasBoolean, { MCK_AR, MCK_AR, MCK_BR }, },
  { 803 /* movt.s */, Xtensa::MOVT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasBoolean_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_BR }, },
  { 810 /* msub.s */, Xtensa::MSUB_S, Convert__Reg1_0__Tie0_1_1__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_FPR }, },
  { 817 /* mul.aa.hh */, Xtensa::MUL_AA_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 827 /* mul.aa.hl */, Xtensa::MUL_AA_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 837 /* mul.aa.lh */, Xtensa::MUL_AA_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 847 /* mul.aa.ll */, Xtensa::MUL_AA_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 857 /* mul.ad.hh */, Xtensa::MUL_AD_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 867 /* mul.ad.hl */, Xtensa::MUL_AD_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 877 /* mul.ad.lh */, Xtensa::MUL_AD_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 887 /* mul.ad.ll */, Xtensa::MUL_AD_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 897 /* mul.da.hh */, Xtensa::MUL_DA_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 907 /* mul.da.hl */, Xtensa::MUL_DA_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 917 /* mul.da.lh */, Xtensa::MUL_DA_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 927 /* mul.da.ll */, Xtensa::MUL_DA_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 937 /* mul.dd.hh */, Xtensa::MUL_DD_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 947 /* mul.dd.hl */, Xtensa::MUL_DD_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 957 /* mul.dd.lh */, Xtensa::MUL_DD_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 967 /* mul.dd.ll */, Xtensa::MUL_DD_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 977 /* mul.s */, Xtensa::MUL_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_FPR }, },
  { 983 /* mul16s */, Xtensa::MUL16S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasMul16, { MCK_AR, MCK_AR, MCK_AR }, },
  { 990 /* mul16u */, Xtensa::MUL16U, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasMul16, { MCK_AR, MCK_AR, MCK_AR }, },
  { 997 /* mula.aa.hh */, Xtensa::MULA_AA_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 1008 /* mula.aa.hl */, Xtensa::MULA_AA_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 1019 /* mula.aa.lh */, Xtensa::MULA_AA_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 1030 /* mula.aa.ll */, Xtensa::MULA_AA_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 1041 /* mula.ad.hh */, Xtensa::MULA_AD_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 1052 /* mula.ad.hl */, Xtensa::MULA_AD_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 1063 /* mula.ad.lh */, Xtensa::MULA_AD_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 1074 /* mula.ad.ll */, Xtensa::MULA_AD_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 1085 /* mula.da.hh */, Xtensa::MULA_DA_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 1096 /* mula.da.hh.lddec */, Xtensa::MULA_DA_HH_LDDEC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_AR }, },
  { 1113 /* mula.da.hh.ldinc */, Xtensa::MULA_DA_HH_LDINC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR, MCK_AR }, },
  { 1130 /* mula.da.hl */, Xtensa::MULA_DA_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 1141 /* mula.da.hl.lddec */, Xtensa::MULA_DA_HL_LDDEC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_AR }, },
  { 1158 /* mula.da.hl.ldinc */, Xtensa::MULA_DA_HL_LDINC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR, MCK_AR }, },
  { 1175 /* mula.da.lh */, Xtensa::MULA_DA_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 1186 /* mula.da.lh.lddec */, Xtensa::MULA_DA_LH_LDDEC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_AR }, },
  { 1203 /* mula.da.lh.ldinc */, Xtensa::MULA_DA_LH_LDINC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR, MCK_AR }, },
  { 1220 /* mula.da.ll */, Xtensa::MULA_DA_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 1231 /* mula.da.ll.lddec */, Xtensa::MULA_DA_LL_LDDEC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_AR }, },
  { 1248 /* mula.da.ll.ldinc */, Xtensa::MULA_DA_LL_LDINC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR, MCK_AR }, },
  { 1265 /* mula.dd.hh */, Xtensa::MULA_DD_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 1276 /* mula.dd.hh.lddec */, Xtensa::MULA_DD_HH_LDDEC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_MR23 }, },
  { 1293 /* mula.dd.hh.ldinc */, Xtensa::MULA_DD_HH_LDINC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_MR23 }, },
  { 1310 /* mula.dd.hl */, Xtensa::MULA_DD_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 1321 /* mula.dd.hl.lddec */, Xtensa::MULA_DD_HL_LDDEC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_MR23 }, },
  { 1338 /* mula.dd.hl.ldinc */, Xtensa::MULA_DD_HL_LDINC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_MR23 }, },
  { 1355 /* mula.dd.lh */, Xtensa::MULA_DD_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 1366 /* mula.dd.lh.lddec */, Xtensa::MULA_DD_LH_LDDEC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_MR23 }, },
  { 1383 /* mula.dd.lh.ldinc */, Xtensa::MULA_DD_LH_LDINC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_MR23 }, },
  { 1400 /* mula.dd.ll */, Xtensa::MULA_DD_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 1411 /* mula.dd.ll.lddec */, Xtensa::MULA_DD_LL_LDDEC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_MR23 }, },
  { 1428 /* mula.dd.ll.ldinc */, Xtensa::MULA_DD_LL_LDINC, Convert__Reg1_0__Reg1_1__Tie1_2_2__Reg1_2__Reg1_3, AMFBS_HasMAC16, { MCK_MR, MCK_AR, MCK_MR01, MCK_MR23 }, },
  { 1445 /* mull */, Xtensa::MULL, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasMul32, { MCK_AR, MCK_AR, MCK_AR }, },
  { 1450 /* muls.aa.hh */, Xtensa::MULS_AA_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 1461 /* muls.aa.hl */, Xtensa::MULS_AA_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 1472 /* muls.aa.lh */, Xtensa::MULS_AA_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 1483 /* muls.aa.ll */, Xtensa::MULS_AA_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 1494 /* muls.ad.hh */, Xtensa::MULS_AD_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 1505 /* muls.ad.hl */, Xtensa::MULS_AD_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 1516 /* muls.ad.lh */, Xtensa::MULS_AD_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 1527 /* muls.ad.ll */, Xtensa::MULS_AD_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_MR23 }, },
  { 1538 /* muls.da.hh */, Xtensa::MULS_DA_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 1549 /* muls.da.hl */, Xtensa::MULS_DA_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 1560 /* muls.da.lh */, Xtensa::MULS_DA_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 1571 /* muls.da.ll */, Xtensa::MULS_DA_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_AR }, },
  { 1582 /* muls.dd.hh */, Xtensa::MULS_DD_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 1593 /* muls.dd.hl */, Xtensa::MULS_DD_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 1604 /* muls.dd.lh */, Xtensa::MULS_DD_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 1615 /* muls.dd.ll */, Xtensa::MULS_DD_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_MR01, MCK_MR23 }, },
  { 1626 /* mulsh */, Xtensa::MULSH, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasMul32High, { MCK_AR, MCK_AR, MCK_AR }, },
  { 1632 /* muluh */, Xtensa::MULUH, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasMul32High, { MCK_AR, MCK_AR, MCK_AR }, },
  { 1638 /* neg */, Xtensa::NEG, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_AR, MCK_AR }, },
  { 1642 /* neg.s */, Xtensa::NEG_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 1648 /* nexp01.s */, Xtensa::NEXP01_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 1657 /* nop */, Xtensa::NOP, Convert_NoOperands, AMFBS_None, {  }, },
  { 1661 /* nop.n */, Xtensa::NOP_N, Convert_NoOperands, AMFBS_HasDensity, {  }, },
  { 1667 /* nsa */, Xtensa::NSA, Convert__Reg1_0__Reg1_1, AMFBS_HasNSA, { MCK_AR, MCK_AR }, },
  { 1671 /* nsau */, Xtensa::NSAU, Convert__Reg1_0__Reg1_1, AMFBS_HasNSA, { MCK_AR, MCK_AR }, },
  { 1676 /* oeq.s */, Xtensa::OEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_BR, MCK_FPR, MCK_FPR }, },
  { 1682 /* ole.s */, Xtensa::OLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_BR, MCK_FPR, MCK_FPR }, },
  { 1688 /* olt.s */, Xtensa::OLT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_BR, MCK_FPR, MCK_FPR }, },
  { 1694 /* or */, Xtensa::OR, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 1697 /* orb */, Xtensa::ORB, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasBoolean, { MCK_BR, MCK_BR, MCK_BR }, },
  { 1701 /* orbc */, Xtensa::ORBC, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasBoolean, { MCK_BR, MCK_BR, MCK_BR }, },
  { 1706 /* pdtlb */, Xtensa::PDTLB, Convert__Reg1_0__Reg1_1, AMFBS_HasRegionProtection, { MCK_AR, MCK_AR }, },
  { 1712 /* pitlb */, Xtensa::PITLB, Convert__Reg1_0__Reg1_1, AMFBS_HasRegionProtection, { MCK_AR, MCK_AR }, },
  { 1718 /* quos */, Xtensa::QUOS, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasDiv32, { MCK_AR, MCK_AR, MCK_AR }, },
  { 1723 /* quou */, Xtensa::QUOU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasDiv32, { MCK_AR, MCK_AR, MCK_AR }, },
  { 1728 /* rdtlb0 */, Xtensa::RDTLB0, Convert__Reg1_0__Reg1_1, AMFBS_HasRegionProtection, { MCK_AR, MCK_AR }, },
  { 1735 /* rdtlb1 */, Xtensa::RDTLB1, Convert__Reg1_0__Reg1_1, AMFBS_HasRegionProtection, { MCK_AR, MCK_AR }, },
  { 1742 /* recip0.s */, Xtensa::RECIP0_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 1751 /* rems */, Xtensa::REMS, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasDiv32, { MCK_AR, MCK_AR, MCK_AR }, },
  { 1756 /* remu */, Xtensa::REMU, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasDiv32, { MCK_AR, MCK_AR, MCK_AR }, },
  { 1761 /* ret */, Xtensa::RET, Convert_NoOperands, AMFBS_None, {  }, },
  { 1765 /* ret.n */, Xtensa::RET_N, Convert_NoOperands, AMFBS_HasDensity, {  }, },
  { 1771 /* retw */, Xtensa::RETW, Convert_NoOperands, AMFBS_HasWindowed, {  }, },
  { 1776 /* retw.n */, Xtensa::RETW_N, Convert_NoOperands, AMFBS_HasWindowed_HasDensity, {  }, },
  { 1783 /* rfde */, Xtensa::RFDE, Convert_NoOperands, AMFBS_HasException, {  }, },
  { 1788 /* rfe */, Xtensa::RFE, Convert_NoOperands, AMFBS_HasException, {  }, },
  { 1792 /* rfi */, Xtensa::RFI, Convert__Uimm41_0, AMFBS_HasHighPriInterrupts, { MCK_Uimm4 }, },
  { 1796 /* rfr */, Xtensa::RFR, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_AR, MCK_FPR }, },
  { 1800 /* rfwo */, Xtensa::RFWO, Convert_NoOperands, AMFBS_HasWindowed, {  }, },
  { 1805 /* rfwu */, Xtensa::RFWU, Convert_NoOperands, AMFBS_HasWindowed, {  }, },
  { 1810 /* ritlb0 */, Xtensa::RITLB0, Convert__Reg1_0__Reg1_1, AMFBS_HasRegionProtection, { MCK_AR, MCK_AR }, },
  { 1817 /* ritlb1 */, Xtensa::RITLB1, Convert__Reg1_0__Reg1_1, AMFBS_HasRegionProtection, { MCK_AR, MCK_AR }, },
  { 1824 /* rotw */, Xtensa::ROTW, Convert__Imm8n_71_0, AMFBS_HasWindowed, { MCK_Imm8n_7 }, },
  { 1829 /* round.s */, Xtensa::ROUND_S, Convert__Reg1_0__Reg1_1__Uimm41_2, AMFBS_HasSingleFloat, { MCK_AR, MCK_FPR, MCK_Uimm4 }, },
  { 1837 /* rsil */, Xtensa::RSIL, Convert__Reg1_0__Uimm41_1, AMFBS_HasInterrupt, { MCK_AR, MCK_Uimm4 }, },
  { 1842 /* rsqrt0.s */, Xtensa::RSQRT0_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 1851 /* rsr */, Xtensa::RSR, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_AR, MCK_SR }, },
  { 1855 /* rsync */, Xtensa::RSYNC, Convert_NoOperands, AMFBS_None, {  }, },
  { 1861 /* rur */, Xtensa::RUR, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_AR, MCK_UR }, },
  { 1865 /* s16i */, Xtensa::S16I, Convert__Reg1_0__Reg1_1__Offset8m161_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Offset8m16 }, },
  { 1870 /* s32c1i */, Xtensa::S32C1I, Convert__Reg1_0__Tie0_1_1__Reg1_1__Offset8m321_2, AMFBS_HasS32C1I, { MCK_AR, MCK_AR, MCK_Offset8m32 }, },
  { 1877 /* s32e */, Xtensa::S32E, Convert__Reg1_0__Reg1_1__Imm64n_4n1_2, AMFBS_HasWindowed, { MCK_AR, MCK_AR, MCK_Imm64n_4n }, },
  { 1882 /* s32i */, Xtensa::S32I, Convert__Reg1_0__Reg1_1__Offset8m321_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Offset8m32 }, },
  { 1887 /* s32i.n */, Xtensa::S32I_N, Convert__Reg1_0__Reg1_1__Offset4m321_2, AMFBS_HasDensity, { MCK_AR, MCK_AR, MCK_Offset4m32 }, },
  { 1894 /* s8i */, Xtensa::S8I, Convert__Reg1_0__Reg1_1__Offset8m81_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Offset8m8 }, },
  { 1898 /* sddr32.p */, Xtensa::SDDR32P, Convert__Reg1_0, AMFBS_HasDebug, { MCK_AR }, },
  { 1907 /* set_bit_gpio_out */, Xtensa::SET_BIT_GPIO_OUT, Convert__Select_2561_0, AMFBS_HasESP32S2Ops, { MCK_Select_256 }, },
  { 1924 /* sext */, Xtensa::SEXT, Convert__Reg1_0__Reg1_1__imm7_221_2, AMFBS_HasSEXT, { MCK_AR, MCK_AR, MCK_imm7_22 }, },
  { 1929 /* sll */, Xtensa::SLL, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_AR, MCK_AR }, },
  { 1933 /* slli */, Xtensa::SLLI, Convert__Reg1_0__Reg1_1__Shimm1_311_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Shimm1_31 }, },
  { 1938 /* sqrt0.s */, Xtensa::SQRT0_S, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR }, },
  { 1946 /* sra */, Xtensa::SRA, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_AR, MCK_AR }, },
  { 1950 /* srai */, Xtensa::SRAI, Convert__Reg1_0__Reg1_1__Uimm51_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Uimm5 }, },
  { 1955 /* src */, Xtensa::SRC, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 1959 /* srl */, Xtensa::SRL, Convert__Reg1_0__Reg1_1, AMFBS_None, { MCK_AR, MCK_AR }, },
  { 1963 /* srli */, Xtensa::SRLI, Convert__Reg1_0__Reg1_1__Uimm41_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_Uimm4 }, },
  { 1968 /* ssa8l */, Xtensa::SSA8L, Convert__Reg1_0, AMFBS_None, { MCK_AR }, },
  { 1974 /* ssai */, Xtensa::SSAI, Convert__Uimm51_0, AMFBS_None, { MCK_Uimm5 }, },
  { 1979 /* ssi */, Xtensa::SSI, Convert__Reg1_0__Reg1_1__Offset8m321_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_Offset8m32 }, },
  { 1983 /* ssip */, Xtensa::SSIP, Convert__Reg1_0__Reg1_1__Offset8m321_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_Offset8m32 }, },
  { 1988 /* ssl */, Xtensa::SSL, Convert__Reg1_0, AMFBS_None, { MCK_AR }, },
  { 1992 /* ssr */, Xtensa::SSR, Convert__Reg1_0, AMFBS_None, { MCK_AR }, },
  { 1996 /* ssx */, Xtensa::SSX, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_AR }, },
  { 2000 /* ssxp */, Xtensa::SSXP, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_AR }, },
  { 2005 /* sub */, Xtensa::SUB, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 2009 /* sub.s */, Xtensa::SUB_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_FPR, MCK_FPR }, },
  { 2015 /* subx2 */, Xtensa::SUBX2, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 2021 /* subx4 */, Xtensa::SUBX4, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 2027 /* subx8 */, Xtensa::SUBX8, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 2033 /* syscall */, Xtensa::SYSCALL, Convert_NoOperands, AMFBS_HasException, {  }, },
  { 2041 /* trunc.s */, Xtensa::TRUNC_S, Convert__Reg1_0__Reg1_1__Uimm41_2, AMFBS_HasSingleFloat, { MCK_AR, MCK_FPR, MCK_Uimm4 }, },
  { 2049 /* ueq.s */, Xtensa::UEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_BR, MCK_FPR, MCK_FPR }, },
  { 2055 /* ufloat.s */, Xtensa::UFLOAT_S, Convert__Reg1_0__Reg1_1__Uimm41_2, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR, MCK_Uimm4 }, },
  { 2064 /* ule.s */, Xtensa::ULE_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_BR, MCK_FPR, MCK_FPR }, },
  { 2070 /* ult.s */, Xtensa::ULT_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_BR, MCK_FPR, MCK_FPR }, },
  { 2076 /* umul.aa.hh */, Xtensa::UMUL_AA_HH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 2087 /* umul.aa.hl */, Xtensa::UMUL_AA_HL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 2098 /* umul.aa.lh */, Xtensa::UMUL_AA_LH, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 2109 /* umul.aa.ll */, Xtensa::UMUL_AA_LL, Convert__Reg1_0__Reg1_1, AMFBS_HasMAC16, { MCK_AR, MCK_AR }, },
  { 2120 /* un.s */, Xtensa::UN_S, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasSingleFloat, { MCK_BR, MCK_FPR, MCK_FPR }, },
  { 2125 /* utrunc.s */, Xtensa::UTRUNC_S, Convert__Reg1_0__Reg1_1__Uimm41_2, AMFBS_HasSingleFloat, { MCK_AR, MCK_FPR, MCK_Uimm4 }, },
  { 2134 /* waiti */, Xtensa::WAITI, Convert__Uimm41_0, AMFBS_HasInterrupt, { MCK_Uimm4 }, },
  { 2140 /* wdtlb */, Xtensa::WDTLB, Convert__Reg1_0__Reg1_1, AMFBS_HasRegionProtection, { MCK_AR, MCK_AR }, },
  { 2146 /* wfr */, Xtensa::WFR, Convert__Reg1_0__Reg1_1, AMFBS_HasSingleFloat, { MCK_FPR, MCK_AR }, },
  { 2150 /* witlb */, Xtensa::WITLB, Convert__Reg1_0__Reg1_1, AMFBS_HasRegionProtection, { MCK_AR, MCK_AR }, },
  { 2156 /* wr_mask_gpio_out */, Xtensa::WR_MASK_GPIO_OUT, Convert__Reg1_0__Reg1_1, AMFBS_HasESP32S2Ops, { MCK_AR, MCK_AR }, },
  { 2173 /* wsr */, Xtensa::WSR, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_AR, MCK_SR }, },
  { 2177 /* wur */, Xtensa::WUR, Convert__Reg1_1__Reg1_0, AMFBS_None, { MCK_AR, MCK_UR }, },
  { 2181 /* xor */, Xtensa::XOR, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_None, { MCK_AR, MCK_AR, MCK_AR }, },
  { 2185 /* xorb */, Xtensa::XORB, Convert__Reg1_0__Reg1_1__Reg1_2, AMFBS_HasBoolean, { MCK_BR, MCK_BR, MCK_BR }, },
  { 2190 /* xsr */, Xtensa::XSR, Convert__Reg1_0__Reg1_1__Tie0_1_1__Tie1_2_2, AMFBS_None, { MCK_AR, MCK_SR }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned XtensaAsmParser::
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
  StringRef Mnemonic = ((XtensaOperand &)*Operands[0]).getToken();

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

static const OperandMatchEntry OperandMatchTable[42] = {
  /* Operand List Mnemonic, Mask, Operand Class, Features */
  { 0 /* _BF */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 13 /* _BT */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 17 /* _loop */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 23 /* _loopgtz */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 32 /* _loopnez */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 179 /* ball */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 184 /* bany */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 189 /* bbc */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 193 /* bbci */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 198 /* bbs */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 202 /* bbsi */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 207 /* beq */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 211 /* beqi */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 216 /* beqz */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 221 /* beqz.n */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_HasDensity },
  { 228 /* bf */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_HasBoolean },
  { 231 /* bge */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 235 /* bgei */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 240 /* bgeu */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 245 /* bgeui */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 251 /* bgez */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 256 /* blt */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 260 /* blti */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 265 /* bltu */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 270 /* bltui */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 276 /* bltz */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 281 /* bnall */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 287 /* bne */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 291 /* bnei */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 296 /* bnez */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 301 /* bnez.n */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_HasDensity },
  { 308 /* bnone */, 4 /* 2 */, MCK_PCRelTarget, AMFBS_None },
  { 328 /* bt */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_HasBoolean },
  { 331 /* call0 */, 1 /* 0 */, MCK_PCRelTarget, AMFBS_None },
  { 337 /* call12 */, 1 /* 0 */, MCK_PCRelTarget, AMFBS_HasWindowed },
  { 344 /* call4 */, 1 /* 0 */, MCK_PCRelTarget, AMFBS_HasWindowed },
  { 350 /* call8 */, 1 /* 0 */, MCK_PCRelTarget, AMFBS_HasWindowed },
  { 528 /* j */, 1 /* 0 */, MCK_PCRelTarget, AMFBS_None },
  { 562 /* l32r */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_None },
  { 593 /* loop */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_HasLoop },
  { 598 /* loopgtz */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_HasLoop },
  { 606 /* loopnez */, 2 /* 1 */, MCK_PCRelTarget, AMFBS_HasLoop },
};

ParseStatus XtensaAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_PCRelTarget:
    return parsePCRelTarget(Operands);
  default:
    return ParseStatus::NoMatch;
  }
  return ParseStatus::NoMatch;
}

ParseStatus XtensaAsmParser::
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

static std::string XtensaMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS, unsigned VariantID) {
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

static bool XtensaCheckMnemonic(StringRef Mnemonic,
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

