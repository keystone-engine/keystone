/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

extern const int16_t LanaiRegDiffLists[] = {
  /* 0 */ -22, 0,
  /* 2 */ -19, 0,
  /* 4 */ -11, 0,
  /* 6 */ -7, 0,
  /* 8 */ -6, 0,
  /* 10 */ 6, 0,
  /* 12 */ 7, 0,
  /* 14 */ 11, 0,
  /* 16 */ 19, 0,
  /* 18 */ 22, 0,
};

extern const LaneBitmask LanaiLaneMaskLists[] = {
  /* 0 */ LaneBitmask(0x0000000000000001), 
  /* 1 */ LaneBitmask(0xFFFFFFFFFFFFFFFF), 
};

extern const uint16_t LanaiSubRegIdxLists[] = {
  /* 0 */ 1, 
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char LanaiRegStrings[] = {
  /* 0 */ "R10\000"
  /* 4 */ "R20\000"
  /* 8 */ "R30\000"
  /* 12 */ "R0\000"
  /* 15 */ "R11\000"
  /* 19 */ "R21\000"
  /* 23 */ "R31\000"
  /* 27 */ "RR1\000"
  /* 31 */ "R12\000"
  /* 35 */ "R22\000"
  /* 39 */ "RR2\000"
  /* 43 */ "R13\000"
  /* 47 */ "R23\000"
  /* 51 */ "R3\000"
  /* 54 */ "R14\000"
  /* 58 */ "R24\000"
  /* 62 */ "R4\000"
  /* 65 */ "R15\000"
  /* 69 */ "R25\000"
  /* 73 */ "R5\000"
  /* 76 */ "R16\000"
  /* 80 */ "R26\000"
  /* 84 */ "R6\000"
  /* 87 */ "R17\000"
  /* 91 */ "R27\000"
  /* 95 */ "R7\000"
  /* 98 */ "R18\000"
  /* 102 */ "R28\000"
  /* 106 */ "R8\000"
  /* 109 */ "R19\000"
  /* 113 */ "R29\000"
  /* 117 */ "R9\000"
  /* 120 */ "RCA\000"
  /* 124 */ "PC\000"
  /* 127 */ "FP\000"
  /* 130 */ "SP\000"
  /* 133 */ "SR\000"
  /* 136 */ "RV\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const MCRegisterDesc LanaiRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0, 0, 0 },
  { 127, 14, 1, 0, 4096, 0, 0, 0 },
  { 124, 12, 1, 0, 4097, 0, 0, 0 },
  { 120, 16, 1, 0, 4098, 0, 0, 0 },
  { 136, 14, 1, 0, 4099, 0, 0, 0 },
  { 130, 10, 1, 0, 4100, 0, 0, 0 },
  { 133, 1, 1, 1, 4101, 1, 0, 0 },
  { 12, 1, 1, 1, 4102, 1, 0, 0 },
  { 28, 1, 1, 1, 4103, 1, 0, 0 },
  { 40, 1, 6, 1, 4097, 1, 0, 0 },
  { 51, 1, 1, 1, 4104, 1, 0, 0 },
  { 62, 1, 8, 1, 4100, 1, 0, 0 },
  { 73, 1, 4, 1, 4096, 1, 0, 0 },
  { 84, 1, 1, 1, 4105, 1, 0, 0 },
  { 95, 1, 1, 1, 4106, 1, 0, 0 },
  { 106, 1, 4, 1, 4099, 1, 0, 0 },
  { 117, 1, 1, 1, 4107, 1, 0, 0 },
  { 0, 1, 18, 1, 4108, 1, 0, 0 },
  { 15, 1, 18, 1, 4109, 1, 0, 0 },
  { 31, 1, 1, 1, 4110, 1, 0, 0 },
  { 43, 1, 1, 1, 4111, 1, 0, 0 },
  { 54, 1, 1, 1, 4112, 1, 0, 0 },
  { 65, 1, 2, 1, 4098, 1, 0, 0 },
  { 76, 1, 1, 1, 4113, 1, 0, 0 },
  { 87, 1, 1, 1, 4114, 1, 0, 0 },
  { 98, 1, 1, 1, 4115, 1, 0, 0 },
  { 109, 1, 1, 1, 4116, 1, 0, 0 },
  { 4, 1, 1, 1, 4117, 1, 0, 0 },
  { 19, 1, 1, 1, 4118, 1, 0, 0 },
  { 35, 1, 1, 1, 4119, 1, 0, 0 },
  { 47, 1, 1, 1, 4120, 1, 0, 0 },
  { 58, 1, 1, 1, 4121, 1, 0, 0 },
  { 69, 1, 1, 1, 4122, 1, 0, 0 },
  { 80, 1, 1, 1, 4123, 1, 0, 0 },
  { 91, 1, 1, 1, 4124, 1, 0, 0 },
  { 102, 1, 1, 1, 4125, 1, 0, 0 },
  { 113, 1, 1, 1, 4126, 1, 0, 0 },
  { 8, 1, 1, 1, 4127, 1, 0, 0 },
  { 23, 1, 1, 1, 4128, 1, 0, 0 },
  { 27, 0, 1, 0, 4108, 0, 0, 0 },
  { 39, 0, 1, 0, 4109, 0, 0, 0 },
};

extern const MCPhysReg LanaiRegUnitRoots[][2] = {
  { Lanai::R5 },
  { Lanai::R2 },
  { Lanai::R15 },
  { Lanai::R8 },
  { Lanai::R4 },
  { Lanai::SR },
  { Lanai::R0 },
  { Lanai::R1 },
  { Lanai::R3 },
  { Lanai::R6 },
  { Lanai::R7 },
  { Lanai::R9 },
  { Lanai::R10 },
  { Lanai::R11 },
  { Lanai::R12 },
  { Lanai::R13 },
  { Lanai::R14 },
  { Lanai::R16 },
  { Lanai::R17 },
  { Lanai::R18 },
  { Lanai::R19 },
  { Lanai::R20 },
  { Lanai::R21 },
  { Lanai::R22 },
  { Lanai::R23 },
  { Lanai::R24 },
  { Lanai::R25 },
  { Lanai::R26 },
  { Lanai::R27 },
  { Lanai::R28 },
  { Lanai::R29 },
  { Lanai::R30 },
  { Lanai::R31 },
};

// Register classes...

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char LanaiRegClassStrings[] = {
  /* 0 */ "GPR_with_sub_32\000"
  /* 16 */ "CCR\000"
  /* 20 */ "GPR\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using LanaiRegisterClassStorage = MCRegisterClassStorage<3, 47, 13, 4, 2, 1>;
extern const MCRegisterClassStorage<3, 47, 13, 4, 2, 1> LanaiMCRegisterClassStorage = {
  {
    {
      offsetof(LanaiRegisterClassStorage, Regs[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(LanaiRegisterClassStorage, BitSets[0]) - 0 * sizeof(MCRegisterClass),
      20,
      32,
      39,
      6,
      Lanai::GPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LanaiRegisterClassStorage, SubClassMasks[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(LanaiRegisterClassStorage, SuperRegIdxSeqs[0]) - 0 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LanaiRegisterClassStorage, SuperClasses[0]) - 0 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(LanaiRegisterClassStorage, Regs[39]) - 1 * sizeof(MCRegisterClass),
      offsetof(LanaiRegisterClassStorage, BitSets[6]) - 1 * sizeof(MCRegisterClass),
      0,
      32,
      7,
      6,
      Lanai::GPR_with_sub_32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LanaiRegisterClassStorage, SubClassMasks[2]) - 1 * sizeof(MCRegisterClass),
      offsetof(LanaiRegisterClassStorage, SuperRegIdxSeqs[1]) - 1 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LanaiRegisterClassStorage, SuperClasses[0]) - 1 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(LanaiRegisterClassStorage, Regs[46]) - 2 * sizeof(MCRegisterClass),
      offsetof(LanaiRegisterClassStorage, BitSets[12]) - 2 * sizeof(MCRegisterClass),
      16,
      32,
      1,
      1,
      Lanai::CCRRegClassID,
      255, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(LanaiRegisterClassStorage, SubClassMasks[3]) - 2 * sizeof(MCRegisterClass),
      offsetof(LanaiRegisterClassStorage, SuperRegIdxSeqs[1]) - 2 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LanaiRegisterClassStorage, SuperClasses[1]) - 2 * sizeof(MCRegisterClass),
      0
    },
  },
  {
    /* 0 */ Lanai::R3, Lanai::R9, Lanai::R12, Lanai::R13, Lanai::R14, Lanai::R16, Lanai::R17, Lanai::R20, Lanai::R21, Lanai::R22, Lanai::R23, Lanai::R24, Lanai::R25, Lanai::R26, Lanai::R27, Lanai::R28, Lanai::R29, Lanai::R30, Lanai::R31, Lanai::R6, Lanai::R7, Lanai::R18, Lanai::R19, Lanai::R15, Lanai::RCA, Lanai::R10, Lanai::RR1, Lanai::R11, Lanai::RR2, Lanai::R8, Lanai::RV, Lanai::R5, Lanai::FP, Lanai::R4, Lanai::SP, Lanai::R2, Lanai::PC, Lanai::R1, Lanai::R0, 
    /* 39 */ Lanai::RCA, Lanai::RR1, Lanai::RR2, Lanai::RV, Lanai::FP, Lanai::SP, Lanai::PC, 
    /* 46 */ Lanai::SR, 
  },
  {
    /* 0 */ 0xbe, 0xff, 0xff, 0xff, 0xff, 0x01, 
    /* 6 */ 0x3e, 0x00, 0x00, 0x00, 0x80, 0x01, 
    /* 12 */ 0x40, 
  },
  {
    // 0 GPR
    0x00000003, 
    0x00000002, // sub_32
    // 2 GPR_with_sub_32
    0x00000002, 
    // 3 CCR
    0x00000004, 
  },
  {
  /* 0 */ 1, 0,
  },
  {
    /* 0 GPR */ 
    /* 0 GPR_with_sub_32 */ Lanai::GPRRegClassID, 
    /* 1 CCR */ 
  }
};

const MCRegisterClass &getLanaiMCRegisterClass(unsigned RC) {
  return LanaiMCRegisterClassStorage.Classes[RC];
}

// Lanai Dwarf<->LLVM register mappings.
extern const MCRegisterInfo::DwarfLLVMRegPair LanaiDwarfFlavour0Dwarf2L[] = {
  { 0U, Lanai::R0 },
  { 1U, Lanai::R1 },
  { 2U, Lanai::R2 },
  { 3U, Lanai::R3 },
  { 4U, Lanai::R4 },
  { 5U, Lanai::R5 },
  { 6U, Lanai::R6 },
  { 7U, Lanai::R7 },
  { 8U, Lanai::R8 },
  { 9U, Lanai::R9 },
  { 10U, Lanai::R10 },
  { 11U, Lanai::R11 },
  { 12U, Lanai::R12 },
  { 13U, Lanai::R13 },
  { 14U, Lanai::R14 },
  { 15U, Lanai::R15 },
  { 16U, Lanai::R16 },
  { 17U, Lanai::R17 },
  { 18U, Lanai::R18 },
  { 19U, Lanai::R19 },
  { 20U, Lanai::R20 },
  { 21U, Lanai::R21 },
  { 22U, Lanai::R22 },
  { 23U, Lanai::R23 },
  { 24U, Lanai::R24 },
  { 25U, Lanai::R25 },
  { 26U, Lanai::R26 },
  { 27U, Lanai::R27 },
  { 28U, Lanai::R28 },
  { 29U, Lanai::R29 },
  { 30U, Lanai::R30 },
  { 31U, Lanai::R31 },
};
extern const unsigned LanaiDwarfFlavour0Dwarf2LSize = std::size(LanaiDwarfFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair LanaiEHFlavour0Dwarf2L[] = {
  { 0U, Lanai::R0 },
  { 1U, Lanai::R1 },
  { 2U, Lanai::R2 },
  { 3U, Lanai::R3 },
  { 4U, Lanai::R4 },
  { 5U, Lanai::R5 },
  { 6U, Lanai::R6 },
  { 7U, Lanai::R7 },
  { 8U, Lanai::R8 },
  { 9U, Lanai::R9 },
  { 10U, Lanai::R10 },
  { 11U, Lanai::R11 },
  { 12U, Lanai::R12 },
  { 13U, Lanai::R13 },
  { 14U, Lanai::R14 },
  { 15U, Lanai::R15 },
  { 16U, Lanai::R16 },
  { 17U, Lanai::R17 },
  { 18U, Lanai::R18 },
  { 19U, Lanai::R19 },
  { 20U, Lanai::R20 },
  { 21U, Lanai::R21 },
  { 22U, Lanai::R22 },
  { 23U, Lanai::R23 },
  { 24U, Lanai::R24 },
  { 25U, Lanai::R25 },
  { 26U, Lanai::R26 },
  { 27U, Lanai::R27 },
  { 28U, Lanai::R28 },
  { 29U, Lanai::R29 },
  { 30U, Lanai::R30 },
  { 31U, Lanai::R31 },
};
extern const unsigned LanaiEHFlavour0Dwarf2LSize = std::size(LanaiEHFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair LanaiDwarfFlavour0L2Dwarf[] = {
  { Lanai::FP, 5U },
  { Lanai::PC, 2U },
  { Lanai::RCA, 15U },
  { Lanai::RV, 8U },
  { Lanai::SP, 4U },
  { Lanai::R0, 0U },
  { Lanai::R1, 1U },
  { Lanai::R2, 2U },
  { Lanai::R3, 3U },
  { Lanai::R4, 4U },
  { Lanai::R5, 5U },
  { Lanai::R6, 6U },
  { Lanai::R7, 7U },
  { Lanai::R8, 8U },
  { Lanai::R9, 9U },
  { Lanai::R10, 10U },
  { Lanai::R11, 11U },
  { Lanai::R12, 12U },
  { Lanai::R13, 13U },
  { Lanai::R14, 14U },
  { Lanai::R15, 15U },
  { Lanai::R16, 16U },
  { Lanai::R17, 17U },
  { Lanai::R18, 18U },
  { Lanai::R19, 19U },
  { Lanai::R20, 20U },
  { Lanai::R21, 21U },
  { Lanai::R22, 22U },
  { Lanai::R23, 23U },
  { Lanai::R24, 24U },
  { Lanai::R25, 25U },
  { Lanai::R26, 26U },
  { Lanai::R27, 27U },
  { Lanai::R28, 28U },
  { Lanai::R29, 29U },
  { Lanai::R30, 30U },
  { Lanai::R31, 31U },
  { Lanai::RR1, 10U },
  { Lanai::RR2, 11U },
};
extern const unsigned LanaiDwarfFlavour0L2DwarfSize = std::size(LanaiDwarfFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair LanaiEHFlavour0L2Dwarf[] = {
  { Lanai::FP, 5U },
  { Lanai::PC, 2U },
  { Lanai::RCA, 15U },
  { Lanai::RV, 8U },
  { Lanai::SP, 4U },
  { Lanai::R0, 0U },
  { Lanai::R1, 1U },
  { Lanai::R2, 2U },
  { Lanai::R3, 3U },
  { Lanai::R4, 4U },
  { Lanai::R5, 5U },
  { Lanai::R6, 6U },
  { Lanai::R7, 7U },
  { Lanai::R8, 8U },
  { Lanai::R9, 9U },
  { Lanai::R10, 10U },
  { Lanai::R11, 11U },
  { Lanai::R12, 12U },
  { Lanai::R13, 13U },
  { Lanai::R14, 14U },
  { Lanai::R15, 15U },
  { Lanai::R16, 16U },
  { Lanai::R17, 17U },
  { Lanai::R18, 18U },
  { Lanai::R19, 19U },
  { Lanai::R20, 20U },
  { Lanai::R21, 21U },
  { Lanai::R22, 22U },
  { Lanai::R23, 23U },
  { Lanai::R24, 24U },
  { Lanai::R25, 25U },
  { Lanai::R26, 26U },
  { Lanai::R27, 27U },
  { Lanai::R28, 28U },
  { Lanai::R29, 29U },
  { Lanai::R30, 30U },
  { Lanai::R31, 31U },
  { Lanai::RR1, 10U },
  { Lanai::RR2, 11U },
};
extern const unsigned LanaiEHFlavour0L2DwarfSize = std::size(LanaiEHFlavour0L2Dwarf);

extern const uint16_t LanaiRegEncodingTable[] = {
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
};
static inline void InitLanaiMCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(LanaiRegDesc, 41, RA, PC, LanaiMCRegisterClassStorage.Classes, 3, LanaiRegUnitRoots, 33, LanaiRegDiffLists, LanaiLaneMaskLists, LanaiRegStrings, LanaiRegClassStrings, LanaiSubRegIdxLists, 2,
LanaiRegEncodingTable, nullptr);

  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(LanaiDwarfFlavour0Dwarf2L, LanaiDwarfFlavour0Dwarf2LSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(LanaiEHFlavour0Dwarf2L, LanaiEHFlavour0Dwarf2LSize, true);
    break;
  }
  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(LanaiDwarfFlavour0L2Dwarf, LanaiDwarfFlavour0L2DwarfSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(LanaiEHFlavour0L2Dwarf, LanaiEHFlavour0L2DwarfSize, true);
    break;
  }
}


} // namespace llvm_ks
