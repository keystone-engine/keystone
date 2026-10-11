/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

extern const int16_t M68kRegDiffLists[] = {
  /* 0 */ 23, -31, 0,
  /* 3 */ 31, -23, 0,
  /* 6 */ -6, 0,
  /* 8 */ -2, 0,
  /* 10 */ 2, 0,
  /* 12 */ 6, 0,
  /* 14 */ 31, 0,
};

extern const LaneBitmask M68kLaneMaskLists[] = {
  /* 0 */ LaneBitmask(0x0000000000000001), 
  /* 1 */ LaneBitmask(0xFFFFFFFFFFFFFFFF), 
};

extern const uint16_t M68kSubRegIdxLists[] = {
  /* 0 */ 2, 1, 
  /* 2 */ 2, 
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char M68kRegStrings[] = {
  /* 0 */ "WA0\000"
  /* 4 */ "BD0\000"
  /* 8 */ "WD0\000"
  /* 12 */ "FP0\000"
  /* 16 */ "WA1\000"
  /* 20 */ "BD1\000"
  /* 24 */ "WD1\000"
  /* 28 */ "FP1\000"
  /* 32 */ "WA2\000"
  /* 36 */ "BD2\000"
  /* 40 */ "WD2\000"
  /* 44 */ "FP2\000"
  /* 48 */ "WA3\000"
  /* 52 */ "BD3\000"
  /* 56 */ "WD3\000"
  /* 60 */ "FP3\000"
  /* 64 */ "WA4\000"
  /* 68 */ "BD4\000"
  /* 72 */ "WD4\000"
  /* 76 */ "FP4\000"
  /* 80 */ "WA5\000"
  /* 84 */ "BD5\000"
  /* 88 */ "WD5\000"
  /* 92 */ "FP5\000"
  /* 96 */ "WA6\000"
  /* 100 */ "BD6\000"
  /* 104 */ "WD6\000"
  /* 108 */ "FP6\000"
  /* 112 */ "BD7\000"
  /* 116 */ "WD7\000"
  /* 120 */ "FP7\000"
  /* 124 */ "FPC\000"
  /* 128 */ "WSP\000"
  /* 132 */ "FPIAR\000"
  /* 138 */ "CCR\000"
  /* 142 */ "SR\000"
  /* 145 */ "FPS\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const MCRegisterDesc M68kRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0, 0, 0 },
  { 138, 2, 12, 2, 8192, 1, 0, 0 },
  { 124, 2, 2, 2, 8193, 1, 0, 0 },
  { 132, 2, 2, 2, 8194, 1, 0, 0 },
  { 145, 2, 2, 2, 8195, 1, 0, 0 },
  { 125, 2, 2, 2, 8196, 1, 0, 0 },
  { 129, 10, 2, 2, 8197, 0, 0, 0 },
  { 142, 6, 2, 1, 8192, 0, 0, 0 },
  { 128, 2, 8, 2, 8197, 1, 0, 0 },
  { 1, 14, 2, 2, 8198, 0, 0, 0 },
  { 17, 14, 2, 2, 8199, 0, 0, 0 },
  { 33, 14, 2, 2, 8200, 0, 0, 0 },
  { 49, 14, 2, 2, 8201, 0, 0, 0 },
  { 65, 14, 2, 2, 8202, 0, 0, 0 },
  { 81, 14, 2, 2, 8203, 0, 0, 0 },
  { 97, 14, 2, 2, 8204, 0, 0, 0 },
  { 4, 2, 3, 2, 8205, 1, 0, 0 },
  { 20, 2, 3, 2, 8206, 1, 0, 0 },
  { 36, 2, 3, 2, 8207, 1, 0, 0 },
  { 52, 2, 3, 2, 8208, 1, 0, 0 },
  { 68, 2, 3, 2, 8209, 1, 0, 0 },
  { 84, 2, 3, 2, 8210, 1, 0, 0 },
  { 100, 2, 3, 2, 8211, 1, 0, 0 },
  { 112, 2, 3, 2, 8212, 1, 0, 0 },
  { 5, 0, 2, 0, 8205, 0, 0, 0 },
  { 21, 0, 2, 0, 8206, 0, 0, 0 },
  { 37, 0, 2, 0, 8207, 0, 0, 0 },
  { 53, 0, 2, 0, 8208, 0, 0, 0 },
  { 69, 0, 2, 0, 8209, 0, 0, 0 },
  { 85, 0, 2, 0, 8210, 0, 0, 0 },
  { 101, 0, 2, 0, 8211, 0, 0, 0 },
  { 113, 0, 2, 0, 8212, 0, 0, 0 },
  { 12, 2, 2, 2, 8213, 1, 0, 0 },
  { 28, 2, 2, 2, 8214, 1, 0, 0 },
  { 44, 2, 2, 2, 8215, 1, 0, 0 },
  { 60, 2, 2, 2, 8216, 1, 0, 0 },
  { 76, 2, 2, 2, 8217, 1, 0, 0 },
  { 92, 2, 2, 2, 8218, 1, 0, 0 },
  { 108, 2, 2, 2, 8219, 1, 0, 0 },
  { 120, 2, 2, 2, 8220, 1, 0, 0 },
  { 0, 2, 1, 2, 8198, 1, 0, 0 },
  { 16, 2, 1, 2, 8199, 1, 0, 0 },
  { 32, 2, 1, 2, 8200, 1, 0, 0 },
  { 48, 2, 1, 2, 8201, 1, 0, 0 },
  { 64, 2, 1, 2, 8202, 1, 0, 0 },
  { 80, 2, 1, 2, 8203, 1, 0, 0 },
  { 96, 2, 1, 2, 8204, 1, 0, 0 },
  { 8, 1, 4, 1, 8205, 0, 0, 0 },
  { 24, 1, 4, 1, 8206, 0, 0, 0 },
  { 40, 1, 4, 1, 8207, 0, 0, 0 },
  { 56, 1, 4, 1, 8208, 0, 0, 0 },
  { 72, 1, 4, 1, 8209, 0, 0, 0 },
  { 88, 1, 4, 1, 8210, 0, 0, 0 },
  { 104, 1, 4, 1, 8211, 0, 0, 0 },
  { 116, 1, 4, 1, 8212, 0, 0, 0 },
};

extern const MCPhysReg M68kRegUnitRoots[][2] = {
  { M68k::CCR },
  { M68k::FPC },
  { M68k::FPIAR },
  { M68k::FPS },
  { M68k::PC },
  { M68k::WSP },
  { M68k::WA0 },
  { M68k::WA1 },
  { M68k::WA2 },
  { M68k::WA3 },
  { M68k::WA4 },
  { M68k::WA5 },
  { M68k::WA6 },
  { M68k::BD0 },
  { M68k::BD1 },
  { M68k::BD2 },
  { M68k::BD3 },
  { M68k::BD4 },
  { M68k::BD5 },
  { M68k::BD6 },
  { M68k::BD7 },
  { M68k::FP0 },
  { M68k::FP1 },
  { M68k::FP2 },
  { M68k::FP3 },
  { M68k::FP4 },
  { M68k::FP5 },
  { M68k::FP6 },
  { M68k::FP7 },
};

// Register classes...

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char M68kRegClassStrings[] = {
  /* 0 */ "FPDR80\000"
  /* 7 */ "AR32\000"
  /* 12 */ "FPDR32\000"
  /* 19 */ "XR32\000"
  /* 24 */ "FPDR64\000"
  /* 31 */ "AR16\000"
  /* 36 */ "DR16\000"
  /* 41 */ "XR16\000"
  /* 46 */ "DR8\000"
  /* 50 */ "PCC\000"
  /* 54 */ "FPIC\000"
  /* 59 */ "SPC\000"
  /* 63 */ "CCRC\000"
  /* 68 */ "SRC\000"
  /* 72 */ "FPCSC\000"
  /* 78 */ "FPSYSC\000"
  /* 85 */ "AR32_TC\000"
  /* 93 */ "DR32_TC\000"
  /* 101 */ "XR32_TC\000"
  /* 109 */ "AR16_TC\000"
  /* 117 */ "DR16_TC\000"
  /* 125 */ "XR16_TC\000"
  /* 133 */ "SPILL\000"
  /* 139 */ "AR32_NOSP\000"
  /* 149 */ "SPILL_R\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using M68kRegisterClassStorage = MCRegisterClassStorage<26, 161, 85, 31, 4, 48>;
extern const MCRegisterClassStorage<26, 161, 85, 31, 4, 48> M68kMCRegisterClassStorage = {
  {
    {
      offsetof(M68kRegisterClassStorage, Regs[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[0]) - 0 * sizeof(MCRegisterClass),
      46,
      8,
      8,
      3,
      M68k::DR8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[0]) - 0 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[0]) - 0 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[8]) - 1 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[3]) - 1 * sizeof(MCRegisterClass),
      63,
      8,
      1,
      1,
      M68k::CCRCRegClassID,
      255, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[2]) - 1 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[0]) - 1 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[0]) - 1 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[9]) - 2 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[4]) - 2 * sizeof(MCRegisterClass),
      41,
      16,
      16,
      7,
      M68k::XR16RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[4]) - 2 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[2]) - 2 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[0]) - 2 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[25]) - 3 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[11]) - 3 * sizeof(MCRegisterClass),
      31,
      16,
      8,
      6,
      M68k::AR16RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[6]) - 3 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[2]) - 3 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[0]) - 3 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[33]) - 4 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[17]) - 4 * sizeof(MCRegisterClass),
      36,
      16,
      8,
      7,
      M68k::DR16RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[8]) - 4 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[2]) - 4 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[1]) - 4 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[41]) - 5 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[24]) - 5 * sizeof(MCRegisterClass),
      125,
      16,
      4,
      4,
      M68k::XR16_TCRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[10]) - 5 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 5 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[2]) - 5 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[45]) - 6 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[28]) - 6 * sizeof(MCRegisterClass),
      109,
      16,
      2,
      2,
      M68k::AR16_TCRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[11]) - 6 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 6 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[2]) - 6 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[47]) - 7 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[30]) - 7 * sizeof(MCRegisterClass),
      117,
      16,
      2,
      4,
      M68k::DR16_TCRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[12]) - 7 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 7 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[3]) - 7 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[49]) - 8 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[34]) - 8 * sizeof(MCRegisterClass),
      68,
      16,
      1,
      1,
      M68k::SRCRegClassID,
      255, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[13]) - 8 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 8 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[4]) - 8 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[50]) - 9 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[35]) - 9 * sizeof(MCRegisterClass),
      133,
      32,
      16,
      4,
      M68k::SPILLRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[14]) - 9 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 9 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[4]) - 9 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[66]) - 10 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[39]) - 10 * sizeof(MCRegisterClass),
      149,
      32,
      16,
      4,
      M68k::SPILL_RRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[15]) - 10 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 10 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[6]) - 10 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[82]) - 11 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[43]) - 11 * sizeof(MCRegisterClass),
      19,
      32,
      16,
      4,
      M68k::XR32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[16]) - 11 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 11 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[8]) - 11 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[98]) - 12 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[47]) - 12 * sizeof(MCRegisterClass),
      7,
      32,
      8,
      2,
      M68k::AR32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[17]) - 12 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 12 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[10]) - 12 * sizeof(MCRegisterClass),
      3
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[106]) - 13 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[49]) - 13 * sizeof(MCRegisterClass),
      14,
      32,
      8,
      4,
      M68k::DR32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[18]) - 13 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 13 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[13]) - 13 * sizeof(MCRegisterClass),
      3
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[114]) - 14 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[53]) - 14 * sizeof(MCRegisterClass),
      12,
      32,
      8,
      5,
      M68k::FPDR32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[19]) - 14 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 14 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[16]) - 14 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[122]) - 15 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[58]) - 15 * sizeof(MCRegisterClass),
      139,
      32,
      7,
      2,
      M68k::AR32_NOSPRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[20]) - 15 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 15 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[16]) - 15 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[129]) - 16 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[60]) - 16 * sizeof(MCRegisterClass),
      101,
      32,
      4,
      4,
      M68k::XR32_TCRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[21]) - 16 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 16 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[20]) - 16 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[133]) - 17 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[64]) - 17 * sizeof(MCRegisterClass),
      78,
      32,
      3,
      1,
      M68k::FPSYSCRegClassID,
      255, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[22]) - 17 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 17 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[24]) - 17 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[136]) - 18 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[65]) - 18 * sizeof(MCRegisterClass),
      85,
      32,
      2,
      2,
      M68k::AR32_TCRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[23]) - 18 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 18 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[24]) - 18 * sizeof(MCRegisterClass),
      8
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[138]) - 19 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[67]) - 19 * sizeof(MCRegisterClass),
      93,
      32,
      2,
      4,
      M68k::DR32_TCRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[24]) - 19 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 19 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[32]) - 19 * sizeof(MCRegisterClass),
      7
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[140]) - 20 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[71]) - 20 * sizeof(MCRegisterClass),
      72,
      32,
      2,
      1,
      M68k::FPCSCRegClassID,
      255, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[25]) - 20 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 20 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[39]) - 20 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[142]) - 21 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[72]) - 21 * sizeof(MCRegisterClass),
      54,
      32,
      1,
      1,
      M68k::FPICRegClassID,
      255, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[26]) - 21 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 21 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[40]) - 21 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[143]) - 22 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[73]) - 22 * sizeof(MCRegisterClass),
      50,
      32,
      1,
      1,
      M68k::PCCRegClassID,
      1, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[27]) - 22 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 22 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[41]) - 22 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[144]) - 23 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[74]) - 23 * sizeof(MCRegisterClass),
      59,
      32,
      1,
      1,
      M68k::SPCRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[28]) - 23 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 23 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[41]) - 23 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[145]) - 24 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[75]) - 24 * sizeof(MCRegisterClass),
      24,
      64,
      8,
      5,
      M68k::FPDR64RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[29]) - 24 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 24 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[45]) - 24 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(M68kRegisterClassStorage, Regs[153]) - 25 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, BitSets[80]) - 25 * sizeof(MCRegisterClass),
      0,
      80,
      8,
      5,
      M68k::FPDR80RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(M68kRegisterClassStorage, SubClassMasks[30]) - 25 * sizeof(MCRegisterClass),
      offsetof(M68kRegisterClassStorage, SuperRegIdxSeqs[1]) - 25 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(M68kRegisterClassStorage, SuperClasses[46]) - 25 * sizeof(MCRegisterClass),
      2
    },
  },
  {
    /* 0 */ M68k::BD0, M68k::BD1, M68k::BD2, M68k::BD3, M68k::BD4, M68k::BD5, M68k::BD6, M68k::BD7, 
    /* 8 */ M68k::CCR, 
    /* 9 */ M68k::WD0, M68k::WD1, M68k::WD2, M68k::WD3, M68k::WD4, M68k::WD5, M68k::WD6, M68k::WD7, M68k::WA0, M68k::WA1, M68k::WA2, M68k::WA3, M68k::WA4, M68k::WA5, M68k::WA6, M68k::WSP, 
    /* 25 */ M68k::WA0, M68k::WA1, M68k::WA2, M68k::WA3, M68k::WA4, M68k::WA5, M68k::WA6, M68k::WSP, 
    /* 33 */ M68k::WD0, M68k::WD1, M68k::WD2, M68k::WD3, M68k::WD4, M68k::WD5, M68k::WD6, M68k::WD7, 
    /* 41 */ M68k::D0, M68k::D1, M68k::A0, M68k::A1, 
    /* 45 */ M68k::A0, M68k::A1, 
    /* 47 */ M68k::D0, M68k::D1, 
    /* 49 */ M68k::SR, 
    /* 50 */ M68k::D0, M68k::D1, M68k::D2, M68k::D3, M68k::D4, M68k::D5, M68k::D6, M68k::D7, M68k::A0, M68k::A1, M68k::A2, M68k::A3, M68k::A4, M68k::A5, M68k::A6, M68k::SP, 
    /* 66 */ M68k::SP, M68k::A6, M68k::A5, M68k::A4, M68k::A3, M68k::A2, M68k::A1, M68k::A0, M68k::D7, M68k::D6, M68k::D5, M68k::D4, M68k::D3, M68k::D2, M68k::D1, M68k::D0, 
    /* 82 */ M68k::D0, M68k::D1, M68k::D2, M68k::D3, M68k::D4, M68k::D5, M68k::D6, M68k::D7, M68k::A0, M68k::A1, M68k::A2, M68k::A3, M68k::A4, M68k::A5, M68k::A6, M68k::SP, 
    /* 98 */ M68k::A0, M68k::A1, M68k::A2, M68k::A3, M68k::A4, M68k::A5, M68k::A6, M68k::SP, 
    /* 106 */ M68k::D0, M68k::D1, M68k::D2, M68k::D3, M68k::D4, M68k::D5, M68k::D6, M68k::D7, 
    /* 114 */ M68k::FP0, M68k::FP1, M68k::FP2, M68k::FP3, M68k::FP4, M68k::FP5, M68k::FP6, M68k::FP7, 
    /* 122 */ M68k::A0, M68k::A1, M68k::A2, M68k::A3, M68k::A4, M68k::A5, M68k::A6, 
    /* 129 */ M68k::D0, M68k::D1, M68k::A0, M68k::A1, 
    /* 133 */ M68k::FPC, M68k::FPS, M68k::FPIAR, 
    /* 136 */ M68k::A0, M68k::A1, 
    /* 138 */ M68k::D0, M68k::D1, 
    /* 140 */ M68k::FPC, M68k::FPS, 
    /* 142 */ M68k::FPIAR, 
    /* 143 */ M68k::PC, 
    /* 144 */ M68k::SP, 
    /* 145 */ M68k::FP0, M68k::FP1, M68k::FP2, M68k::FP3, M68k::FP4, M68k::FP5, M68k::FP6, M68k::FP7, 
    /* 153 */ M68k::FP0, M68k::FP1, M68k::FP2, M68k::FP3, M68k::FP4, M68k::FP5, M68k::FP6, M68k::FP7, 
  },
  {
    /* 0 */ 0x00, 0x00, 0xff, 
    /* 3 */ 0x02, 
    /* 4 */ 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0x7f, 
    /* 11 */ 0x00, 0x01, 0x00, 0x00, 0x00, 0x7f, 
    /* 17 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x7f, 
    /* 24 */ 0x00, 0x06, 0x00, 0x03, 
    /* 28 */ 0x00, 0x06, 
    /* 30 */ 0x00, 0x00, 0x00, 0x03, 
    /* 34 */ 0x80, 
    /* 35 */ 0x40, 0xfe, 0x00, 0xff, 
    /* 39 */ 0x40, 0xfe, 0x00, 0xff, 
    /* 43 */ 0x40, 0xfe, 0x00, 0xff, 
    /* 47 */ 0x40, 0xfe, 
    /* 49 */ 0x00, 0x00, 0x00, 0xff, 
    /* 53 */ 0x00, 0x00, 0x00, 0x00, 0xff, 
    /* 58 */ 0x00, 0xfe, 
    /* 60 */ 0x00, 0x06, 0x00, 0x03, 
    /* 64 */ 0x1c, 
    /* 65 */ 0x00, 0x06, 
    /* 67 */ 0x00, 0x00, 0x00, 0x03, 
    /* 71 */ 0x14, 
    /* 72 */ 0x08, 
    /* 73 */ 0x20, 
    /* 74 */ 0x40, 
    /* 75 */ 0x00, 0x00, 0x00, 0x00, 0xff, 
    /* 80 */ 0x00, 0x00, 0x00, 0x00, 0xff, 
  },
  {
    // 0 DR8
    0x00000001, 
    0x00082090, // MxSubRegIndex8Lo
    // 2 CCRC
    0x00000002, 
    0x00000100, // MxSubRegIndex8Lo
    // 4 XR16
    0x0000001c, 
    0x008dbee0, // MxSubRegIndex16Lo
    // 6 AR16
    0x00000008, 
    0x00849040, // MxSubRegIndex16Lo
    // 8 DR16
    0x00000010, 
    0x00082080, // MxSubRegIndex16Lo
    // 10 XR16_TC
    0x000d00e0, 
    // 11 AR16_TC
    0x00040040, 
    // 12 DR16_TC
    0x00080080, 
    // 13 SRC
    0x00000100, 
    // 14 SPILL
    0x008dbe00, 
    // 15 SPILL_R
    0x008dbe00, 
    // 16 XR32
    0x008dbe00, 
    // 17 AR32
    0x00849000, 
    // 18 DR32
    0x00082000, 
    // 19 FPDR32
    0x03004000, 
    // 20 AR32_NOSP
    0x00048000, 
    // 21 XR32_TC
    0x000d0000, 
    // 22 FPSYSC
    0x00320000, 
    // 23 AR32_TC
    0x00040000, 
    // 24 DR32_TC
    0x00080000, 
    // 25 FPCSC
    0x00100000, 
    // 26 FPIC
    0x00200000, 
    // 27 PCC
    0x00400000, 
    // 28 SPC
    0x00800000, 
    // 29 FPDR64
    0x03000000, 
    // 30 FPDR80
    0x02000000, 
  },
  {
  /* 0 */ 1, 0,
  /* 2 */ 2, 0,
  },
  {
    /* 0 DR8 */ 
    /* 0 CCRC */ 
    /* 0 XR16 */ 
    /* 0 AR16 */ M68k::XR16RegClassID, 
    /* 1 DR16 */ M68k::XR16RegClassID, 
    /* 2 XR16_TC */ 
    /* 2 AR16_TC */ M68k::XR16_TCRegClassID, 
    /* 3 DR16_TC */ M68k::XR16_TCRegClassID, 
    /* 4 SRC */ 
    /* 4 SPILL */ M68k::SPILL_RRegClassID, M68k::XR32RegClassID, 
    /* 6 SPILL_R */ M68k::SPILLRegClassID, M68k::XR32RegClassID, 
    /* 8 XR32 */ M68k::SPILLRegClassID, M68k::SPILL_RRegClassID, 
    /* 10 AR32 */ M68k::SPILLRegClassID, M68k::SPILL_RRegClassID, M68k::XR32RegClassID, 
    /* 13 DR32 */ M68k::SPILLRegClassID, M68k::SPILL_RRegClassID, M68k::XR32RegClassID, 
    /* 16 FPDR32 */ 
    /* 16 AR32_NOSP */ M68k::SPILLRegClassID, M68k::SPILL_RRegClassID, M68k::XR32RegClassID, M68k::AR32RegClassID, 
    /* 20 XR32_TC */ M68k::XR16_TCRegClassID, M68k::SPILLRegClassID, M68k::SPILL_RRegClassID, M68k::XR32RegClassID, 
    /* 24 FPSYSC */ 
    /* 24 AR32_TC */ M68k::XR16_TCRegClassID, M68k::AR16_TCRegClassID, M68k::SPILLRegClassID, M68k::SPILL_RRegClassID, M68k::XR32RegClassID, M68k::AR32RegClassID, M68k::AR32_NOSPRegClassID, M68k::XR32_TCRegClassID, 
    /* 32 DR32_TC */ M68k::XR16_TCRegClassID, M68k::DR16_TCRegClassID, M68k::SPILLRegClassID, M68k::SPILL_RRegClassID, M68k::XR32RegClassID, M68k::DR32RegClassID, M68k::XR32_TCRegClassID, 
    /* 39 FPCSC */ M68k::FPSYSCRegClassID, 
    /* 40 FPIC */ M68k::FPSYSCRegClassID, 
    /* 41 PCC */ 
    /* 41 SPC */ M68k::SPILLRegClassID, M68k::SPILL_RRegClassID, M68k::XR32RegClassID, M68k::AR32RegClassID, 
    /* 45 FPDR64 */ M68k::FPDR32RegClassID, 
    /* 46 FPDR80 */ M68k::FPDR32RegClassID, M68k::FPDR64RegClassID, 
  }
};

const MCRegisterClass &getM68kMCRegisterClass(unsigned RC) {
  return M68kMCRegisterClassStorage.Classes[RC];
}

// M68k Dwarf<->LLVM register mappings.
extern const MCRegisterInfo::DwarfLLVMRegPair M68kDwarfFlavour0Dwarf2L[] = {
  { 0U, M68k::WD0 },
  { 1U, M68k::WD1 },
  { 2U, M68k::WD2 },
  { 3U, M68k::WD3 },
  { 4U, M68k::WD4 },
  { 5U, M68k::WD5 },
  { 6U, M68k::WD6 },
  { 7U, M68k::WD7 },
  { 8U, M68k::WA0 },
  { 9U, M68k::WA1 },
  { 10U, M68k::WA2 },
  { 11U, M68k::WA3 },
  { 12U, M68k::WA4 },
  { 13U, M68k::WA5 },
  { 14U, M68k::WA6 },
  { 15U, M68k::WSP },
  { 18U, M68k::FP0 },
  { 19U, M68k::FP1 },
  { 20U, M68k::FP2 },
  { 21U, M68k::FP3 },
  { 22U, M68k::FP4 },
  { 23U, M68k::FP5 },
  { 24U, M68k::FP6 },
  { 25U, M68k::FP7 },
  { 26U, M68k::FPC },
  { 27U, M68k::FPS },
  { 28U, M68k::FPIAR },
};
extern const unsigned M68kDwarfFlavour0Dwarf2LSize = std::size(M68kDwarfFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair M68kEHFlavour0Dwarf2L[] = {
  { 0U, M68k::WD0 },
  { 1U, M68k::WD1 },
  { 2U, M68k::WD2 },
  { 3U, M68k::WD3 },
  { 4U, M68k::WD4 },
  { 5U, M68k::WD5 },
  { 6U, M68k::WD6 },
  { 7U, M68k::WD7 },
  { 8U, M68k::WA0 },
  { 9U, M68k::WA1 },
  { 10U, M68k::WA2 },
  { 11U, M68k::WA3 },
  { 12U, M68k::WA4 },
  { 13U, M68k::WA5 },
  { 14U, M68k::WA6 },
  { 15U, M68k::WSP },
  { 18U, M68k::FP0 },
  { 19U, M68k::FP1 },
  { 20U, M68k::FP2 },
  { 21U, M68k::FP3 },
  { 22U, M68k::FP4 },
  { 23U, M68k::FP5 },
  { 24U, M68k::FP6 },
  { 25U, M68k::FP7 },
  { 26U, M68k::FPC },
  { 27U, M68k::FPS },
  { 28U, M68k::FPIAR },
};
extern const unsigned M68kEHFlavour0Dwarf2LSize = std::size(M68kEHFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair M68kDwarfFlavour0L2Dwarf[] = {
  { M68k::FPC, 26U },
  { M68k::FPIAR, 28U },
  { M68k::FPS, 27U },
  { M68k::SP, 15U },
  { M68k::WSP, 15U },
  { M68k::A0, 8U },
  { M68k::A1, 9U },
  { M68k::A2, 10U },
  { M68k::A3, 11U },
  { M68k::A4, 12U },
  { M68k::A5, 13U },
  { M68k::A6, 14U },
  { M68k::BD0, 0U },
  { M68k::BD1, 1U },
  { M68k::BD2, 2U },
  { M68k::BD3, 3U },
  { M68k::BD4, 4U },
  { M68k::BD5, 5U },
  { M68k::BD6, 6U },
  { M68k::BD7, 7U },
  { M68k::D0, 0U },
  { M68k::D1, 1U },
  { M68k::D2, 2U },
  { M68k::D3, 3U },
  { M68k::D4, 4U },
  { M68k::D5, 5U },
  { M68k::D6, 6U },
  { M68k::D7, 7U },
  { M68k::FP0, 18U },
  { M68k::FP1, 19U },
  { M68k::FP2, 20U },
  { M68k::FP3, 21U },
  { M68k::FP4, 22U },
  { M68k::FP5, 23U },
  { M68k::FP6, 24U },
  { M68k::FP7, 25U },
  { M68k::WA0, 8U },
  { M68k::WA1, 9U },
  { M68k::WA2, 10U },
  { M68k::WA3, 11U },
  { M68k::WA4, 12U },
  { M68k::WA5, 13U },
  { M68k::WA6, 14U },
  { M68k::WD0, 0U },
  { M68k::WD1, 1U },
  { M68k::WD2, 2U },
  { M68k::WD3, 3U },
  { M68k::WD4, 4U },
  { M68k::WD5, 5U },
  { M68k::WD6, 6U },
  { M68k::WD7, 7U },
};
extern const unsigned M68kDwarfFlavour0L2DwarfSize = std::size(M68kDwarfFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair M68kEHFlavour0L2Dwarf[] = {
  { M68k::FPC, 26U },
  { M68k::FPIAR, 28U },
  { M68k::FPS, 27U },
  { M68k::SP, 15U },
  { M68k::WSP, 15U },
  { M68k::A0, 8U },
  { M68k::A1, 9U },
  { M68k::A2, 10U },
  { M68k::A3, 11U },
  { M68k::A4, 12U },
  { M68k::A5, 13U },
  { M68k::A6, 14U },
  { M68k::BD0, 0U },
  { M68k::BD1, 1U },
  { M68k::BD2, 2U },
  { M68k::BD3, 3U },
  { M68k::BD4, 4U },
  { M68k::BD5, 5U },
  { M68k::BD6, 6U },
  { M68k::BD7, 7U },
  { M68k::D0, 0U },
  { M68k::D1, 1U },
  { M68k::D2, 2U },
  { M68k::D3, 3U },
  { M68k::D4, 4U },
  { M68k::D5, 5U },
  { M68k::D6, 6U },
  { M68k::D7, 7U },
  { M68k::FP0, 18U },
  { M68k::FP1, 19U },
  { M68k::FP2, 20U },
  { M68k::FP3, 21U },
  { M68k::FP4, 22U },
  { M68k::FP5, 23U },
  { M68k::FP6, 24U },
  { M68k::FP7, 25U },
  { M68k::WA0, 8U },
  { M68k::WA1, 9U },
  { M68k::WA2, 10U },
  { M68k::WA3, 11U },
  { M68k::WA4, 12U },
  { M68k::WA5, 13U },
  { M68k::WA6, 14U },
  { M68k::WD0, 0U },
  { M68k::WD1, 1U },
  { M68k::WD2, 2U },
  { M68k::WD3, 3U },
  { M68k::WD4, 4U },
  { M68k::WD5, 5U },
  { M68k::WD6, 6U },
  { M68k::WD7, 7U },
};
extern const unsigned M68kEHFlavour0L2DwarfSize = std::size(M68kEHFlavour0L2Dwarf);

extern const uint16_t M68kRegEncodingTable[] = {
  0,
  0,
  8,
  10,
  9,
  0,
  7,
  0,
  7,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
};
static inline void InitM68kMCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(M68kRegDesc, 55, RA, PC, M68kMCRegisterClassStorage.Classes, 26, M68kRegUnitRoots, 29, M68kRegDiffLists, M68kLaneMaskLists, M68kRegStrings, M68kRegClassStrings, M68kSubRegIdxLists, 3,
M68kRegEncodingTable, nullptr);

  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(M68kDwarfFlavour0Dwarf2L, M68kDwarfFlavour0Dwarf2LSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(M68kEHFlavour0Dwarf2L, M68kEHFlavour0Dwarf2LSize, true);
    break;
  }
  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(M68kDwarfFlavour0L2Dwarf, M68kDwarfFlavour0L2DwarfSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(M68kEHFlavour0L2Dwarf, M68kEHFlavour0L2DwarfSize, true);
    break;
  }
}


} // namespace llvm_ks
