/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

extern const int16_t BPFRegDiffLists[] = {
  /* 0 */ -12, 0,
  /* 2 */ 12, 0,
};

extern const LaneBitmask BPFLaneMaskLists[] = {
  /* 0 */ LaneBitmask(0x0000000000000001), 
  /* 1 */ LaneBitmask(0xFFFFFFFFFFFFFFFF), 
};

extern const uint16_t BPFSubRegIdxLists[] = {
  /* 0 */ 1, 
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char BPFRegStrings[] = {
  /* 0 */ "R10\000"
  /* 4 */ "W10\000"
  /* 8 */ "R0\000"
  /* 11 */ "W0\000"
  /* 14 */ "R11\000"
  /* 18 */ "W11\000"
  /* 22 */ "R1\000"
  /* 25 */ "W1\000"
  /* 28 */ "R2\000"
  /* 31 */ "W2\000"
  /* 34 */ "R3\000"
  /* 37 */ "W3\000"
  /* 40 */ "R4\000"
  /* 43 */ "W4\000"
  /* 46 */ "R5\000"
  /* 49 */ "W5\000"
  /* 52 */ "R6\000"
  /* 55 */ "W6\000"
  /* 58 */ "R7\000"
  /* 61 */ "W7\000"
  /* 64 */ "R8\000"
  /* 67 */ "W8\000"
  /* 70 */ "R9\000"
  /* 73 */ "W9\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const MCRegisterDesc BPFRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0, 0, 0 },
  { 8, 2, 1, 0, 4096, 0, 0, 0 },
  { 22, 2, 1, 0, 4097, 0, 0, 0 },
  { 28, 2, 1, 0, 4098, 0, 0, 0 },
  { 34, 2, 1, 0, 4099, 0, 0, 0 },
  { 40, 2, 1, 0, 4100, 0, 0, 0 },
  { 46, 2, 1, 0, 4101, 0, 0, 0 },
  { 52, 2, 1, 0, 4102, 0, 0, 0 },
  { 58, 2, 1, 0, 4103, 0, 0, 0 },
  { 64, 2, 1, 0, 4104, 0, 0, 0 },
  { 70, 2, 1, 0, 4105, 0, 0, 0 },
  { 0, 2, 1, 0, 4106, 0, 0, 0 },
  { 14, 2, 1, 0, 4107, 0, 0, 0 },
  { 11, 1, 0, 1, 4096, 1, 0, 0 },
  { 25, 1, 0, 1, 4097, 1, 0, 0 },
  { 31, 1, 0, 1, 4098, 1, 0, 0 },
  { 37, 1, 0, 1, 4099, 1, 0, 0 },
  { 43, 1, 0, 1, 4100, 1, 0, 0 },
  { 49, 1, 0, 1, 4101, 1, 0, 0 },
  { 55, 1, 0, 1, 4102, 1, 0, 0 },
  { 61, 1, 0, 1, 4103, 1, 0, 0 },
  { 67, 1, 0, 1, 4104, 1, 0, 0 },
  { 73, 1, 0, 1, 4105, 1, 0, 0 },
  { 4, 1, 0, 1, 4106, 1, 0, 0 },
  { 18, 1, 0, 1, 4107, 1, 0, 0 },
};

extern const MCPhysReg BPFRegUnitRoots[][2] = {
  { BPF::W0 },
  { BPF::W1 },
  { BPF::W2 },
  { BPF::W3 },
  { BPF::W4 },
  { BPF::W5 },
  { BPF::W6 },
  { BPF::W7 },
  { BPF::W8 },
  { BPF::W9 },
  { BPF::W10 },
  { BPF::W11 },
};

// Register classes...

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char BPFRegClassStrings[] = {
  /* 0 */ "GPR32\000"
  /* 6 */ "GPR\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using BPFRegisterClassStorage = MCRegisterClassStorage<2, 24, 6, 3, 2, 0>;
extern const MCRegisterClassStorage<2, 24, 6, 3, 2, 0> BPFMCRegisterClassStorage = {
  {
    {
      offsetof(BPFRegisterClassStorage, Regs[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(BPFRegisterClassStorage, BitSets[0]) - 0 * sizeof(MCRegisterClass),
      0,
      32,
      12,
      4,
      BPF::GPR32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(BPFRegisterClassStorage, SubClassMasks[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(BPFRegisterClassStorage, SuperRegIdxSeqs[0]) - 0 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(BPFRegisterClassStorage, SuperClasses[0]) - 0 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(BPFRegisterClassStorage, Regs[12]) - 1 * sizeof(MCRegisterClass),
      offsetof(BPFRegisterClassStorage, BitSets[4]) - 1 * sizeof(MCRegisterClass),
      6,
      64,
      12,
      2,
      BPF::GPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(BPFRegisterClassStorage, SubClassMasks[2]) - 1 * sizeof(MCRegisterClass),
      offsetof(BPFRegisterClassStorage, SuperRegIdxSeqs[1]) - 1 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(BPFRegisterClassStorage, SuperClasses[0]) - 1 * sizeof(MCRegisterClass),
      0
    },
  },
  {
    /* 0 */ BPF::W1, BPF::W2, BPF::W3, BPF::W4, BPF::W5, BPF::W6, BPF::W7, BPF::W8, BPF::W9, BPF::W0, BPF::W11, BPF::W10, 
    /* 12 */ BPF::R1, BPF::R2, BPF::R3, BPF::R4, BPF::R5, BPF::R6, BPF::R7, BPF::R8, BPF::R9, BPF::R0, BPF::R11, BPF::R10, 
  },
  {
    /* 0 */ 0x00, 0xe0, 0xff, 0x01, 
    /* 4 */ 0xfe, 0x1f, 
  },
  {
    // 0 GPR32
    0x00000001, 
    0x00000002, // sub_32
    // 2 GPR
    0x00000002, 
  },
  {
  /* 0 */ 1, 0,
  },
  {
    /* 0 GPR32 */ 
    /* 0 GPR */ 
  }
};

const MCRegisterClass &getBPFMCRegisterClass(unsigned RC) {
  return BPFMCRegisterClassStorage.Classes[RC];
}

// BPF Dwarf<->LLVM register mappings.
extern const MCRegisterInfo::DwarfLLVMRegPair BPFDwarfFlavour0Dwarf2L[] = {
  { 0U, BPF::W0 },
  { 1U, BPF::W1 },
  { 2U, BPF::W2 },
  { 3U, BPF::W3 },
  { 4U, BPF::W4 },
  { 5U, BPF::W5 },
  { 6U, BPF::W6 },
  { 7U, BPF::W7 },
  { 8U, BPF::W8 },
  { 9U, BPF::W9 },
  { 10U, BPF::W10 },
  { 11U, BPF::W11 },
};
extern const unsigned BPFDwarfFlavour0Dwarf2LSize = std::size(BPFDwarfFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair BPFEHFlavour0Dwarf2L[] = {
  { 0U, BPF::W0 },
  { 1U, BPF::W1 },
  { 2U, BPF::W2 },
  { 3U, BPF::W3 },
  { 4U, BPF::W4 },
  { 5U, BPF::W5 },
  { 6U, BPF::W6 },
  { 7U, BPF::W7 },
  { 8U, BPF::W8 },
  { 9U, BPF::W9 },
  { 10U, BPF::W10 },
  { 11U, BPF::W11 },
};
extern const unsigned BPFEHFlavour0Dwarf2LSize = std::size(BPFEHFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair BPFDwarfFlavour0L2Dwarf[] = {
  { BPF::R0, 0U },
  { BPF::R1, 1U },
  { BPF::R2, 2U },
  { BPF::R3, 3U },
  { BPF::R4, 4U },
  { BPF::R5, 5U },
  { BPF::R6, 6U },
  { BPF::R7, 7U },
  { BPF::R8, 8U },
  { BPF::R9, 9U },
  { BPF::R10, 10U },
  { BPF::R11, 11U },
  { BPF::W0, 0U },
  { BPF::W1, 1U },
  { BPF::W2, 2U },
  { BPF::W3, 3U },
  { BPF::W4, 4U },
  { BPF::W5, 5U },
  { BPF::W6, 6U },
  { BPF::W7, 7U },
  { BPF::W8, 8U },
  { BPF::W9, 9U },
  { BPF::W10, 10U },
  { BPF::W11, 11U },
};
extern const unsigned BPFDwarfFlavour0L2DwarfSize = std::size(BPFDwarfFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair BPFEHFlavour0L2Dwarf[] = {
  { BPF::R0, 0U },
  { BPF::R1, 1U },
  { BPF::R2, 2U },
  { BPF::R3, 3U },
  { BPF::R4, 4U },
  { BPF::R5, 5U },
  { BPF::R6, 6U },
  { BPF::R7, 7U },
  { BPF::R8, 8U },
  { BPF::R9, 9U },
  { BPF::R10, 10U },
  { BPF::R11, 11U },
  { BPF::W0, 0U },
  { BPF::W1, 1U },
  { BPF::W2, 2U },
  { BPF::W3, 3U },
  { BPF::W4, 4U },
  { BPF::W5, 5U },
  { BPF::W6, 6U },
  { BPF::W7, 7U },
  { BPF::W8, 8U },
  { BPF::W9, 9U },
  { BPF::W10, 10U },
  { BPF::W11, 11U },
};
extern const unsigned BPFEHFlavour0L2DwarfSize = std::size(BPFEHFlavour0L2Dwarf);

extern const uint16_t BPFRegEncodingTable[] = {
  0,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
};
static inline void InitBPFMCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(BPFRegDesc, 25, RA, PC, BPFMCRegisterClassStorage.Classes, 2, BPFRegUnitRoots, 12, BPFRegDiffLists, BPFLaneMaskLists, BPFRegStrings, BPFRegClassStrings, BPFSubRegIdxLists, 2,
BPFRegEncodingTable, nullptr);

  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(BPFDwarfFlavour0Dwarf2L, BPFDwarfFlavour0Dwarf2LSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(BPFEHFlavour0Dwarf2L, BPFEHFlavour0Dwarf2LSize, true);
    break;
  }
  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(BPFDwarfFlavour0L2Dwarf, BPFDwarfFlavour0L2DwarfSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(BPFEHFlavour0L2Dwarf, BPFEHFlavour0L2DwarfSize, true);
    break;
  }
}


} // namespace llvm_ks
