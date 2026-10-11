/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

extern const int16_t MSP430RegDiffLists[] = {
  /* 0 */ -12, 0,
  /* 2 */ -1, 0,
  /* 4 */ 1, 0,
  /* 6 */ 12, 0,
};

extern const LaneBitmask MSP430LaneMaskLists[] = {
  /* 0 */ LaneBitmask(0x0000000000000001), 
  /* 1 */ LaneBitmask(0xFFFFFFFFFFFFFFFF), 
};

extern const uint16_t MSP430SubRegIdxLists[] = {
  /* 0 */ 1, 
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char MSP430RegStrings[] = {
  /* 0 */ "R10\000"
  /* 4 */ "R11\000"
  /* 8 */ "R12\000"
  /* 12 */ "R13\000"
  /* 16 */ "R14\000"
  /* 20 */ "R4\000"
  /* 23 */ "R15\000"
  /* 27 */ "R5\000"
  /* 30 */ "R6\000"
  /* 33 */ "R7\000"
  /* 36 */ "R8\000"
  /* 39 */ "R9\000"
  /* 42 */ "R10B\000"
  /* 47 */ "R11B\000"
  /* 52 */ "R12B\000"
  /* 57 */ "R13B\000"
  /* 62 */ "R14B\000"
  /* 67 */ "R4B\000"
  /* 71 */ "R15B\000"
  /* 76 */ "R5B\000"
  /* 80 */ "R6B\000"
  /* 84 */ "R7B\000"
  /* 88 */ "R8B\000"
  /* 92 */ "R9B\000"
  /* 96 */ "PCB\000"
  /* 100 */ "CGB\000"
  /* 104 */ "SPB\000"
  /* 108 */ "SRB\000"
  /* 112 */ "PC\000"
  /* 115 */ "CG\000"
  /* 118 */ "SP\000"
  /* 121 */ "SR\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const MCRegisterDesc MSP430RegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0, 0, 0 },
  { 115, 4, 1, 0, 4096, 0, 0, 0 },
  { 100, 1, 2, 1, 4096, 1, 0, 0 },
  { 112, 4, 1, 0, 4097, 0, 0, 0 },
  { 96, 1, 2, 1, 4097, 1, 0, 0 },
  { 118, 4, 1, 0, 4098, 0, 0, 0 },
  { 104, 1, 2, 1, 4098, 1, 0, 0 },
  { 121, 4, 1, 0, 4099, 0, 0, 0 },
  { 108, 1, 2, 1, 4099, 1, 0, 0 },
  { 20, 6, 1, 0, 4100, 0, 0, 0 },
  { 27, 6, 1, 0, 4101, 0, 0, 0 },
  { 30, 6, 1, 0, 4102, 0, 0, 0 },
  { 33, 6, 1, 0, 4103, 0, 0, 0 },
  { 36, 6, 1, 0, 4104, 0, 0, 0 },
  { 39, 6, 1, 0, 4105, 0, 0, 0 },
  { 0, 6, 1, 0, 4106, 0, 0, 0 },
  { 4, 6, 1, 0, 4107, 0, 0, 0 },
  { 8, 6, 1, 0, 4108, 0, 0, 0 },
  { 12, 6, 1, 0, 4109, 0, 0, 0 },
  { 16, 6, 1, 0, 4110, 0, 0, 0 },
  { 23, 6, 1, 0, 4111, 0, 0, 0 },
  { 67, 1, 0, 1, 4100, 1, 0, 0 },
  { 76, 1, 0, 1, 4101, 1, 0, 0 },
  { 80, 1, 0, 1, 4102, 1, 0, 0 },
  { 84, 1, 0, 1, 4103, 1, 0, 0 },
  { 88, 1, 0, 1, 4104, 1, 0, 0 },
  { 92, 1, 0, 1, 4105, 1, 0, 0 },
  { 42, 1, 0, 1, 4106, 1, 0, 0 },
  { 47, 1, 0, 1, 4107, 1, 0, 0 },
  { 52, 1, 0, 1, 4108, 1, 0, 0 },
  { 57, 1, 0, 1, 4109, 1, 0, 0 },
  { 62, 1, 0, 1, 4110, 1, 0, 0 },
  { 71, 1, 0, 1, 4111, 1, 0, 0 },
};

extern const MCPhysReg MSP430RegUnitRoots[][2] = {
  { MSP430::CGB },
  { MSP430::PCB },
  { MSP430::SPB },
  { MSP430::SRB },
  { MSP430::R4B },
  { MSP430::R5B },
  { MSP430::R6B },
  { MSP430::R7B },
  { MSP430::R8B },
  { MSP430::R9B },
  { MSP430::R10B },
  { MSP430::R11B },
  { MSP430::R12B },
  { MSP430::R13B },
  { MSP430::R14B },
  { MSP430::R15B },
};

// Register classes...

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char MSP430RegClassStrings[] = {
  /* 0 */ "GR16\000"
  /* 5 */ "GR8\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using MSP430RegisterClassStorage = MCRegisterClassStorage<2, 32, 8, 3, 2, 0>;
extern const MCRegisterClassStorage<2, 32, 8, 3, 2, 0> MSP430MCRegisterClassStorage = {
  {
    {
      offsetof(MSP430RegisterClassStorage, Regs[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(MSP430RegisterClassStorage, BitSets[0]) - 0 * sizeof(MCRegisterClass),
      5,
      8,
      16,
      5,
      MSP430::GR8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(MSP430RegisterClassStorage, SubClassMasks[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(MSP430RegisterClassStorage, SuperRegIdxSeqs[0]) - 0 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(MSP430RegisterClassStorage, SuperClasses[0]) - 0 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(MSP430RegisterClassStorage, Regs[16]) - 1 * sizeof(MCRegisterClass),
      offsetof(MSP430RegisterClassStorage, BitSets[5]) - 1 * sizeof(MCRegisterClass),
      0,
      16,
      16,
      3,
      MSP430::GR16RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(MSP430RegisterClassStorage, SubClassMasks[2]) - 1 * sizeof(MCRegisterClass),
      offsetof(MSP430RegisterClassStorage, SuperRegIdxSeqs[1]) - 1 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(MSP430RegisterClassStorage, SuperClasses[0]) - 1 * sizeof(MCRegisterClass),
      0
    },
  },
  {
    /* 0 */ MSP430::R12B, MSP430::R13B, MSP430::R14B, MSP430::R15B, MSP430::R11B, MSP430::R10B, MSP430::R9B, MSP430::R8B, MSP430::R7B, MSP430::R6B, MSP430::R5B, MSP430::R4B, MSP430::PCB, MSP430::SPB, MSP430::SRB, MSP430::CGB, 
    /* 16 */ MSP430::R12, MSP430::R13, MSP430::R14, MSP430::R15, MSP430::R11, MSP430::R10, MSP430::R9, MSP430::R8, MSP430::R7, MSP430::R6, MSP430::R5, MSP430::R4, MSP430::PC, MSP430::SP, MSP430::SR, MSP430::CG, 
  },
  {
    /* 0 */ 0x54, 0x01, 0xe0, 0xff, 0x01, 
    /* 5 */ 0xaa, 0xfe, 0x1f, 
  },
  {
    // 0 GR8
    0x00000001, 
    0x00000002, // subreg_8bit
    // 2 GR16
    0x00000002, 
  },
  {
  /* 0 */ 1, 0,
  },
  {
    /* 0 GR8 */ 
    /* 0 GR16 */ 
  }
};

const MCRegisterClass &getMSP430MCRegisterClass(unsigned RC) {
  return MSP430MCRegisterClassStorage.Classes[RC];
}

// MSP430 Dwarf<->LLVM register mappings.
extern const MCRegisterInfo::DwarfLLVMRegPair MSP430DwarfFlavour0Dwarf2L[] = {
  { 0U, MSP430::PC },
  { 1U, MSP430::SP },
  { 2U, MSP430::SR },
  { 3U, MSP430::CG },
  { 4U, MSP430::R4 },
  { 5U, MSP430::R5 },
  { 6U, MSP430::R6 },
  { 7U, MSP430::R7 },
  { 8U, MSP430::R8 },
  { 9U, MSP430::R9 },
  { 10U, MSP430::R10 },
  { 11U, MSP430::R11 },
  { 12U, MSP430::R12 },
  { 13U, MSP430::R13 },
  { 14U, MSP430::R14 },
  { 15U, MSP430::R15 },
  { 16U, MSP430::PCB },
  { 17U, MSP430::SPB },
  { 18U, MSP430::SRB },
  { 19U, MSP430::CGB },
  { 20U, MSP430::R4B },
  { 21U, MSP430::R5B },
  { 22U, MSP430::R6B },
  { 23U, MSP430::R7B },
  { 24U, MSP430::R8B },
  { 25U, MSP430::R9B },
  { 26U, MSP430::R10B },
  { 27U, MSP430::R11B },
  { 28U, MSP430::R12B },
  { 29U, MSP430::R13B },
  { 30U, MSP430::R14B },
  { 31U, MSP430::R15B },
};
extern const unsigned MSP430DwarfFlavour0Dwarf2LSize = std::size(MSP430DwarfFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair MSP430EHFlavour0Dwarf2L[] = {
  { 0U, MSP430::PC },
  { 1U, MSP430::SP },
  { 2U, MSP430::SR },
  { 3U, MSP430::CG },
  { 4U, MSP430::R4 },
  { 5U, MSP430::R5 },
  { 6U, MSP430::R6 },
  { 7U, MSP430::R7 },
  { 8U, MSP430::R8 },
  { 9U, MSP430::R9 },
  { 10U, MSP430::R10 },
  { 11U, MSP430::R11 },
  { 12U, MSP430::R12 },
  { 13U, MSP430::R13 },
  { 14U, MSP430::R14 },
  { 15U, MSP430::R15 },
  { 16U, MSP430::PCB },
  { 17U, MSP430::SPB },
  { 18U, MSP430::SRB },
  { 19U, MSP430::CGB },
  { 20U, MSP430::R4B },
  { 21U, MSP430::R5B },
  { 22U, MSP430::R6B },
  { 23U, MSP430::R7B },
  { 24U, MSP430::R8B },
  { 25U, MSP430::R9B },
  { 26U, MSP430::R10B },
  { 27U, MSP430::R11B },
  { 28U, MSP430::R12B },
  { 29U, MSP430::R13B },
  { 30U, MSP430::R14B },
  { 31U, MSP430::R15B },
};
extern const unsigned MSP430EHFlavour0Dwarf2LSize = std::size(MSP430EHFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair MSP430DwarfFlavour0L2Dwarf[] = {
  { MSP430::CG, 3U },
  { MSP430::CGB, 19U },
  { MSP430::PC, 0U },
  { MSP430::PCB, 16U },
  { MSP430::SP, 1U },
  { MSP430::SPB, 17U },
  { MSP430::SR, 2U },
  { MSP430::SRB, 18U },
  { MSP430::R4, 4U },
  { MSP430::R5, 5U },
  { MSP430::R6, 6U },
  { MSP430::R7, 7U },
  { MSP430::R8, 8U },
  { MSP430::R9, 9U },
  { MSP430::R10, 10U },
  { MSP430::R11, 11U },
  { MSP430::R12, 12U },
  { MSP430::R13, 13U },
  { MSP430::R14, 14U },
  { MSP430::R15, 15U },
  { MSP430::R4B, 20U },
  { MSP430::R5B, 21U },
  { MSP430::R6B, 22U },
  { MSP430::R7B, 23U },
  { MSP430::R8B, 24U },
  { MSP430::R9B, 25U },
  { MSP430::R10B, 26U },
  { MSP430::R11B, 27U },
  { MSP430::R12B, 28U },
  { MSP430::R13B, 29U },
  { MSP430::R14B, 30U },
  { MSP430::R15B, 31U },
};
extern const unsigned MSP430DwarfFlavour0L2DwarfSize = std::size(MSP430DwarfFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair MSP430EHFlavour0L2Dwarf[] = {
  { MSP430::CG, 3U },
  { MSP430::CGB, 19U },
  { MSP430::PC, 0U },
  { MSP430::PCB, 16U },
  { MSP430::SP, 1U },
  { MSP430::SPB, 17U },
  { MSP430::SR, 2U },
  { MSP430::SRB, 18U },
  { MSP430::R4, 4U },
  { MSP430::R5, 5U },
  { MSP430::R6, 6U },
  { MSP430::R7, 7U },
  { MSP430::R8, 8U },
  { MSP430::R9, 9U },
  { MSP430::R10, 10U },
  { MSP430::R11, 11U },
  { MSP430::R12, 12U },
  { MSP430::R13, 13U },
  { MSP430::R14, 14U },
  { MSP430::R15, 15U },
  { MSP430::R4B, 20U },
  { MSP430::R5B, 21U },
  { MSP430::R6B, 22U },
  { MSP430::R7B, 23U },
  { MSP430::R8B, 24U },
  { MSP430::R9B, 25U },
  { MSP430::R10B, 26U },
  { MSP430::R11B, 27U },
  { MSP430::R12B, 28U },
  { MSP430::R13B, 29U },
  { MSP430::R14B, 30U },
  { MSP430::R15B, 31U },
};
extern const unsigned MSP430EHFlavour0L2DwarfSize = std::size(MSP430EHFlavour0L2Dwarf);

extern const uint16_t MSP430RegEncodingTable[] = {
  0,
  3,
  3,
  0,
  0,
  1,
  1,
  2,
  2,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
};
static inline void InitMSP430MCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(MSP430RegDesc, 33, RA, PC, MSP430MCRegisterClassStorage.Classes, 2, MSP430RegUnitRoots, 16, MSP430RegDiffLists, MSP430LaneMaskLists, MSP430RegStrings, MSP430RegClassStrings, MSP430SubRegIdxLists, 2,
MSP430RegEncodingTable, nullptr);

  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(MSP430DwarfFlavour0Dwarf2L, MSP430DwarfFlavour0Dwarf2LSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(MSP430EHFlavour0Dwarf2L, MSP430EHFlavour0Dwarf2LSize, true);
    break;
  }
  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(MSP430DwarfFlavour0L2Dwarf, MSP430DwarfFlavour0L2DwarfSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(MSP430EHFlavour0L2Dwarf, MSP430EHFlavour0L2DwarfSize, true);
    break;
  }
}


} // namespace llvm_ks
