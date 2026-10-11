/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

extern const int16_t AVRRegDiffLists[] = {
  /* 0 */ -2, 0,
  /* 2 */ 2, -1, 0,
  /* 5 */ -32, 1, 0,
  /* 8 */ -31, 1, 0,
  /* 11 */ -30, 1, 0,
  /* 14 */ -29, 1, 0,
  /* 17 */ -28, 1, 0,
  /* 20 */ -27, 1, 0,
  /* 23 */ -26, 1, 0,
  /* 26 */ 27, 1, 0,
  /* 29 */ 25, 0,
  /* 31 */ 26, 0,
  /* 33 */ 27, 0,
  /* 35 */ 28, 0,
  /* 37 */ 29, 0,
  /* 39 */ 30, 0,
  /* 41 */ 31, 0,
  /* 43 */ 32, 0,
};

extern const LaneBitmask AVRLaneMaskLists[] = {
  /* 0 */ LaneBitmask(0x0000000000000002), LaneBitmask(0x0000000000000001), 
  /* 2 */ LaneBitmask(0xFFFFFFFFFFFFFFFF), 
};

extern const uint16_t AVRSubRegIdxLists[] = {
  /* 0 */ 2, 1, 
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char AVRRegStrings[] = {
  /* 0 */ "R11R10\000"
  /* 7 */ "R21R20\000"
  /* 14 */ "R31R30\000"
  /* 21 */ "R1R0\000"
  /* 26 */ "R12R11\000"
  /* 33 */ "R22R21\000"
  /* 40 */ "R31\000"
  /* 44 */ "R1\000"
  /* 47 */ "R13R12\000"
  /* 54 */ "R23R22\000"
  /* 61 */ "R3R2\000"
  /* 66 */ "R14R13\000"
  /* 73 */ "R24R23\000"
  /* 80 */ "R3\000"
  /* 83 */ "R15R14\000"
  /* 90 */ "R25R24\000"
  /* 97 */ "R5R4\000"
  /* 102 */ "R16R15\000"
  /* 109 */ "R26R25\000"
  /* 116 */ "R5\000"
  /* 119 */ "R17R16\000"
  /* 126 */ "R27R26\000"
  /* 133 */ "R7R6\000"
  /* 138 */ "R18R17\000"
  /* 145 */ "R27\000"
  /* 149 */ "R7\000"
  /* 152 */ "R19R18\000"
  /* 159 */ "R29R28\000"
  /* 166 */ "R9R8\000"
  /* 171 */ "R20R19\000"
  /* 178 */ "R29\000"
  /* 182 */ "R10R9\000"
  /* 188 */ "SREG\000"
  /* 193 */ "SPH\000"
  /* 197 */ "SPL\000"
  /* 201 */ "SP\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const MCRegisterDesc AVRRegDesc[] = { // Descriptors
  { 6, 0, 0, 0, 0, 0, 0, 0 },
  { 201, 2, 1, 0, 24576, 0, 0, 0 },
  { 193, 1, 3, 2, 4097, 2, 0, 0 },
  { 197, 1, 0, 2, 4096, 2, 0, 0 },
  { 188, 1, 1, 2, 4098, 2, 0, 0 },
  { 23, 1, 43, 2, 4099, 2, 0, 0 },
  { 44, 1, 41, 2, 4100, 2, 0, 0 },
  { 63, 1, 41, 2, 4101, 2, 0, 0 },
  { 80, 1, 39, 2, 4102, 2, 0, 0 },
  { 99, 1, 39, 2, 4103, 2, 0, 0 },
  { 116, 1, 37, 2, 4104, 2, 0, 0 },
  { 135, 1, 37, 2, 4105, 2, 0, 0 },
  { 149, 1, 35, 2, 4106, 2, 0, 0 },
  { 168, 1, 35, 2, 4107, 2, 0, 0 },
  { 185, 1, 26, 2, 4108, 2, 0, 0 },
  { 3, 1, 26, 2, 4109, 2, 0, 0 },
  { 29, 1, 26, 2, 4110, 2, 0, 0 },
  { 50, 1, 26, 2, 4111, 2, 0, 0 },
  { 69, 1, 26, 2, 4112, 2, 0, 0 },
  { 86, 1, 26, 2, 4113, 2, 0, 0 },
  { 105, 1, 26, 2, 4114, 2, 0, 0 },
  { 122, 1, 26, 2, 4115, 2, 0, 0 },
  { 141, 1, 26, 2, 4116, 2, 0, 0 },
  { 155, 1, 26, 2, 4117, 2, 0, 0 },
  { 174, 1, 26, 2, 4118, 2, 0, 0 },
  { 10, 1, 26, 2, 4119, 2, 0, 0 },
  { 36, 1, 26, 2, 4120, 2, 0, 0 },
  { 57, 1, 26, 2, 4121, 2, 0, 0 },
  { 76, 1, 26, 2, 4122, 2, 0, 0 },
  { 93, 1, 26, 2, 4123, 2, 0, 0 },
  { 112, 1, 26, 2, 4124, 2, 0, 0 },
  { 129, 1, 26, 2, 4125, 2, 0, 0 },
  { 145, 1, 33, 2, 4126, 2, 0, 0 },
  { 162, 1, 33, 2, 4127, 2, 0, 0 },
  { 178, 1, 31, 2, 4128, 2, 0, 0 },
  { 17, 1, 31, 2, 4129, 2, 0, 0 },
  { 40, 1, 29, 2, 4130, 2, 0, 0 },
  { 21, 5, 1, 0, 24579, 0, 0, 0 },
  { 61, 8, 1, 0, 24581, 0, 0, 0 },
  { 97, 11, 1, 0, 24583, 0, 0, 0 },
  { 133, 14, 1, 0, 24585, 0, 0, 0 },
  { 166, 17, 1, 0, 24587, 0, 0, 0 },
  { 182, 17, 1, 0, 24588, 0, 0, 0 },
  { 0, 17, 1, 0, 24589, 0, 0, 0 },
  { 26, 17, 1, 0, 24590, 0, 0, 0 },
  { 47, 17, 1, 0, 24591, 0, 0, 0 },
  { 66, 17, 1, 0, 24592, 0, 0, 0 },
  { 83, 17, 1, 0, 24593, 0, 0, 0 },
  { 102, 17, 1, 0, 24594, 0, 0, 0 },
  { 119, 17, 1, 0, 24595, 0, 0, 0 },
  { 138, 17, 1, 0, 24596, 0, 0, 0 },
  { 152, 17, 1, 0, 24597, 0, 0, 0 },
  { 171, 17, 1, 0, 24598, 0, 0, 0 },
  { 7, 17, 1, 0, 24599, 0, 0, 0 },
  { 33, 17, 1, 0, 24600, 0, 0, 0 },
  { 54, 17, 1, 0, 24601, 0, 0, 0 },
  { 73, 17, 1, 0, 24602, 0, 0, 0 },
  { 90, 17, 1, 0, 24603, 0, 0, 0 },
  { 109, 17, 1, 0, 24604, 0, 0, 0 },
  { 126, 17, 1, 0, 24605, 0, 0, 0 },
  { 159, 20, 1, 0, 24607, 0, 0, 0 },
  { 14, 23, 1, 0, 24609, 0, 0, 0 },
};

extern const MCPhysReg AVRRegUnitRoots[][2] = {
  { AVR::SPL },
  { AVR::SPH },
  { AVR::SREG },
  { AVR::R0 },
  { AVR::R1 },
  { AVR::R2 },
  { AVR::R3 },
  { AVR::R4 },
  { AVR::R5 },
  { AVR::R6 },
  { AVR::R7 },
  { AVR::R8 },
  { AVR::R9 },
  { AVR::R10 },
  { AVR::R11 },
  { AVR::R12 },
  { AVR::R13 },
  { AVR::R14 },
  { AVR::R15 },
  { AVR::R16 },
  { AVR::R17 },
  { AVR::R18 },
  { AVR::R19 },
  { AVR::R20 },
  { AVR::R21 },
  { AVR::R22 },
  { AVR::R23 },
  { AVR::R24 },
  { AVR::R25 },
  { AVR::R26 },
  { AVR::R27 },
  { AVR::R28 },
  { AVR::R29 },
  { AVR::R30 },
  { AVR::R31 },
};

// Register classes...

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char AVRRegClassStrings[] = {
  /* 0 */ "GPR8NOZ_and_LD8\000"
  /* 16 */ "DREGSNOZ_and_DREGS_with_sub_hi_in_LD8\000"
  /* 54 */ "DREGSNOZ_and_DREGS_with_sub_lo_in_LD8\000"
  /* 92 */ "DREGS_with_sub_hi_in_LD8lo_and_DREGS_with_sub_lo_in_LD8\000"
  /* 148 */ "GPR8\000"
  /* 153 */ "ZREG\000"
  /* 158 */ "GPRSP\000"
  /* 164 */ "CCR\000"
  /* 168 */ "DLDREGS\000"
  /* 176 */ "DREGSNOZ_and_PTRDISPREGS\000"
  /* 201 */ "DREGSNOZ_and_PTRREGS\000"
  /* 222 */ "DREGSNOZ_and_IWREGS\000"
  /* 242 */ "DREGSMOVW\000"
  /* 252 */ "GPR8NOZ\000"
  /* 260 */ "DLDREGS_and_DREGSNOZ\000"
  /* 281 */ "DREGSMOVW_and_DREGSNOZ\000"
  /* 304 */ "DREGSLD8lo\000"
  /* 315 */ "DREGS_with_sub_hi_in_LD8lo\000"
  /* 342 */ "DREGS_with_sub_lo_in_LD8lo\000"
  /* 369 */ "DREGS_with_sub_hi_in_GPR8lo\000"
  /* 397 */ "DREGS_with_sub_hi_in_LD8_and_DREGS_with_sub_lo_in_GPR8lo\000"
  /* 454 */ "DREGSlo\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using AVRRegisterClassStorage = MCRegisterClassStorage<33, 340, 220, 90, 3, 153>;
extern const MCRegisterClassStorage<33, 340, 220, 90, 3, 153> AVRMCRegisterClassStorage = {
  {
    {
      offsetof(AVRRegisterClassStorage, Regs[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[0]) - 0 * sizeof(MCRegisterClass),
      148,
      8,
      32,
      5,
      AVR::GPR8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[0]) - 0 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[0]) - 0 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[32]) - 1 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[5]) - 1 * sizeof(MCRegisterClass),
      252,
      8,
      30,
      5,
      AVR::GPR8NOZRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[6]) - 1 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[0]) - 1 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[0]) - 1 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[62]) - 2 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[10]) - 2 * sizeof(MCRegisterClass),
      390,
      8,
      16,
      3,
      AVR::GPR8loRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[12]) - 2 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[0]) - 2 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[1]) - 2 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[78]) - 3 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[13]) - 3 * sizeof(MCRegisterClass),
      12,
      8,
      16,
      5,
      AVR::LD8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[18]) - 3 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[0]) - 3 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[3]) - 3 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[94]) - 4 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[18]) - 4 * sizeof(MCRegisterClass),
      0,
      8,
      14,
      5,
      AVR::GPR8NOZ_and_LD8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[24]) - 4 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[0]) - 4 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[4]) - 4 * sizeof(MCRegisterClass),
      3
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[108]) - 5 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[23]) - 5 * sizeof(MCRegisterClass),
      309,
      8,
      8,
      4,
      AVR::LD8loRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[30]) - 5 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[0]) - 5 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[7]) - 5 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[116]) - 6 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[27]) - 6 * sizeof(MCRegisterClass),
      164,
      8,
      1,
      1,
      AVR::CCRRegClassID,
      255, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[36]) - 6 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 6 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[11]) - 6 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[117]) - 7 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[28]) - 7 * sizeof(MCRegisterClass),
      170,
      16,
      25,
      8,
      AVR::DREGSRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[38]) - 7 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 7 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[11]) - 7 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[142]) - 8 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[36]) - 8 * sizeof(MCRegisterClass),
      272,
      16,
      24,
      8,
      AVR::DREGSNOZRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[40]) - 8 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 8 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[11]) - 8 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[166]) - 9 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[44]) - 9 * sizeof(MCRegisterClass),
      242,
      16,
      16,
      8,
      AVR::DREGSMOVWRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[42]) - 9 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 9 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[12]) - 9 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[182]) - 10 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[52]) - 10 * sizeof(MCRegisterClass),
      281,
      16,
      15,
      8,
      AVR::DREGSMOVW_and_DREGSNOZRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[44]) - 10 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 10 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[13]) - 10 * sizeof(MCRegisterClass),
      3
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[197]) - 11 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[60]) - 11 * sizeof(MCRegisterClass),
      29,
      16,
      14,
      8,
      AVR::DREGS_with_sub_hi_in_LD8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[46]) - 11 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 11 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[16]) - 11 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[211]) - 12 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[68]) - 12 * sizeof(MCRegisterClass),
      16,
      16,
      13,
      8,
      AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[48]) - 12 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 12 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[17]) - 12 * sizeof(MCRegisterClass),
      3
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[224]) - 13 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[76]) - 13 * sizeof(MCRegisterClass),
      67,
      16,
      13,
      8,
      AVR::DREGS_with_sub_lo_in_LD8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[50]) - 13 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 13 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[20]) - 13 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[237]) - 14 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[84]) - 14 * sizeof(MCRegisterClass),
      54,
      16,
      12,
      8,
      AVR::DREGSNOZ_and_DREGS_with_sub_lo_in_LD8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[52]) - 14 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 14 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[22]) - 14 * sizeof(MCRegisterClass),
      5
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[249]) - 15 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[92]) - 15 * sizeof(MCRegisterClass),
      426,
      16,
      12,
      7,
      AVR::DREGS_with_sub_lo_in_GPR8loRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[54]) - 15 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 15 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[27]) - 15 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[261]) - 16 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[99]) - 16 * sizeof(MCRegisterClass),
      369,
      16,
      11,
      6,
      AVR::DREGS_with_sub_hi_in_GPR8loRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[56]) - 16 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 16 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[29]) - 16 * sizeof(MCRegisterClass),
      3
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[272]) - 17 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[105]) - 17 * sizeof(MCRegisterClass),
      168,
      16,
      8,
      8,
      AVR::DLDREGSRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[58]) - 17 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 17 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[32]) - 17 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[280]) - 18 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[113]) - 18 * sizeof(MCRegisterClass),
      315,
      16,
      8,
      7,
      AVR::DREGS_with_sub_hi_in_LD8loRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[60]) - 18 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 18 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[36]) - 18 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[288]) - 19 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[120]) - 19 * sizeof(MCRegisterClass),
      342,
      16,
      8,
      8,
      AVR::DREGS_with_sub_lo_in_LD8loRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[62]) - 19 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 19 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[40]) - 19 * sizeof(MCRegisterClass),
      6
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[296]) - 20 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[128]) - 20 * sizeof(MCRegisterClass),
      454,
      16,
      8,
      6,
      AVR::DREGSloRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[64]) - 20 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 20 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[46]) - 20 * sizeof(MCRegisterClass),
      6
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[304]) - 21 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[134]) - 21 * sizeof(MCRegisterClass),
      260,
      16,
      7,
      8,
      AVR::DLDREGS_and_DREGSNOZRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[66]) - 21 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 21 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[52]) - 21 * sizeof(MCRegisterClass),
      9
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[311]) - 22 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[142]) - 22 * sizeof(MCRegisterClass),
      92,
      16,
      7,
      7,
      AVR::DREGS_with_sub_hi_in_LD8lo_and_DREGS_with_sub_lo_in_LD8RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[68]) - 22 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 22 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[61]) - 22 * sizeof(MCRegisterClass),
      8
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[318]) - 23 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[149]) - 23 * sizeof(MCRegisterClass),
      304,
      16,
      4,
      7,
      AVR::DREGSLD8loRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[70]) - 23 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 23 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[69]) - 23 * sizeof(MCRegisterClass),
      13
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[322]) - 24 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[156]) - 24 * sizeof(MCRegisterClass),
      235,
      16,
      4,
      8,
      AVR::IWREGSRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[72]) - 24 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 24 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[82]) - 24 * sizeof(MCRegisterClass),
      5
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[326]) - 25 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[164]) - 25 * sizeof(MCRegisterClass),
      222,
      16,
      3,
      8,
      AVR::DREGSNOZ_and_IWREGSRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[74]) - 25 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 25 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[87]) - 25 * sizeof(MCRegisterClass),
      11
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[329]) - 26 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[172]) - 26 * sizeof(MCRegisterClass),
      214,
      16,
      3,
      8,
      AVR::PTRREGSRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[76]) - 26 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 26 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[98]) - 26 * sizeof(MCRegisterClass),
      6
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[332]) - 27 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[180]) - 27 * sizeof(MCRegisterClass),
      201,
      16,
      2,
      8,
      AVR::DREGSNOZ_and_PTRREGSRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[78]) - 27 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 27 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[104]) - 27 * sizeof(MCRegisterClass),
      13
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[334]) - 28 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[188]) - 28 * sizeof(MCRegisterClass),
      189,
      16,
      2,
      8,
      AVR::PTRDISPREGSRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[80]) - 28 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 28 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[117]) - 28 * sizeof(MCRegisterClass),
      7
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[336]) - 29 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[196]) - 29 * sizeof(MCRegisterClass),
      176,
      16,
      1,
      8,
      AVR::DREGSNOZ_and_PTRDISPREGSRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[82]) - 29 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 29 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[124]) - 29 * sizeof(MCRegisterClass),
      15
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[337]) - 30 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[204]) - 30 * sizeof(MCRegisterClass),
      397,
      16,
      1,
      7,
      AVR::DREGS_with_sub_hi_in_LD8_and_DREGS_with_sub_lo_in_GPR8loRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[84]) - 30 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 30 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[139]) - 30 * sizeof(MCRegisterClass),
      6
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[338]) - 31 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[211]) - 31 * sizeof(MCRegisterClass),
      158,
      16,
      1,
      1,
      AVR::GPRSPRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[86]) - 31 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 31 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[145]) - 31 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(AVRRegisterClassStorage, Regs[339]) - 32 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, BitSets[212]) - 32 * sizeof(MCRegisterClass),
      153,
      16,
      1,
      8,
      AVR::ZREGRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(AVRRegisterClassStorage, SubClassMasks[88]) - 32 * sizeof(MCRegisterClass),
      offsetof(AVRRegisterClassStorage, SuperRegIdxSeqs[2]) - 32 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(AVRRegisterClassStorage, SuperClasses[145]) - 32 * sizeof(MCRegisterClass),
      8
    },
  },
  {
    /* 0 */ AVR::R24, AVR::R25, AVR::R18, AVR::R19, AVR::R20, AVR::R21, AVR::R22, AVR::R23, AVR::R30, AVR::R31, AVR::R26, AVR::R27, AVR::R28, AVR::R29, AVR::R17, AVR::R16, AVR::R15, AVR::R14, AVR::R13, AVR::R12, AVR::R11, AVR::R10, AVR::R9, AVR::R8, AVR::R7, AVR::R6, AVR::R5, AVR::R4, AVR::R3, AVR::R2, AVR::R0, AVR::R1, 
    /* 32 */ AVR::R24, AVR::R25, AVR::R18, AVR::R19, AVR::R20, AVR::R21, AVR::R22, AVR::R23, AVR::R26, AVR::R27, AVR::R28, AVR::R29, AVR::R17, AVR::R16, AVR::R15, AVR::R14, AVR::R13, AVR::R12, AVR::R11, AVR::R10, AVR::R9, AVR::R8, AVR::R7, AVR::R6, AVR::R5, AVR::R4, AVR::R3, AVR::R2, AVR::R0, AVR::R1, 
    /* 62 */ AVR::R15, AVR::R14, AVR::R13, AVR::R12, AVR::R11, AVR::R10, AVR::R9, AVR::R8, AVR::R7, AVR::R6, AVR::R5, AVR::R4, AVR::R3, AVR::R2, AVR::R0, AVR::R1, 
    /* 78 */ AVR::R24, AVR::R25, AVR::R18, AVR::R19, AVR::R20, AVR::R21, AVR::R22, AVR::R23, AVR::R30, AVR::R31, AVR::R26, AVR::R27, AVR::R28, AVR::R29, AVR::R17, AVR::R16, 
    /* 94 */ AVR::R24, AVR::R25, AVR::R18, AVR::R19, AVR::R20, AVR::R21, AVR::R22, AVR::R23, AVR::R26, AVR::R27, AVR::R28, AVR::R29, AVR::R17, AVR::R16, 
    /* 108 */ AVR::R23, AVR::R22, AVR::R21, AVR::R20, AVR::R19, AVR::R18, AVR::R17, AVR::R16, 
    /* 116 */ AVR::SREG, 
    /* 117 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R31R30, AVR::R27R26, AVR::R29R28, AVR::R17R16, AVR::R15R14, AVR::R13R12, AVR::R11R10, AVR::R9R8, AVR::R7R6, AVR::R5R4, AVR::R3R2, AVR::R1R0, AVR::R26R25, AVR::R24R23, AVR::R22R21, AVR::R20R19, AVR::R18R17, AVR::R16R15, AVR::R14R13, AVR::R12R11, AVR::R10R9, 
    /* 142 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R27R26, AVR::R29R28, AVR::R17R16, AVR::R15R14, AVR::R13R12, AVR::R11R10, AVR::R9R8, AVR::R7R6, AVR::R5R4, AVR::R3R2, AVR::R1R0, AVR::R26R25, AVR::R24R23, AVR::R22R21, AVR::R20R19, AVR::R18R17, AVR::R16R15, AVR::R14R13, AVR::R12R11, AVR::R10R9, 
    /* 166 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R31R30, AVR::R27R26, AVR::R29R28, AVR::R17R16, AVR::R15R14, AVR::R13R12, AVR::R11R10, AVR::R9R8, AVR::R7R6, AVR::R5R4, AVR::R3R2, AVR::R1R0, 
    /* 182 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R27R26, AVR::R29R28, AVR::R17R16, AVR::R15R14, AVR::R13R12, AVR::R11R10, AVR::R9R8, AVR::R7R6, AVR::R5R4, AVR::R3R2, AVR::R1R0, 
    /* 197 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R31R30, AVR::R27R26, AVR::R29R28, AVR::R17R16, AVR::R26R25, AVR::R24R23, AVR::R22R21, AVR::R20R19, AVR::R18R17, AVR::R16R15, 
    /* 211 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R27R26, AVR::R29R28, AVR::R17R16, AVR::R26R25, AVR::R24R23, AVR::R22R21, AVR::R20R19, AVR::R18R17, AVR::R16R15, 
    /* 224 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R31R30, AVR::R27R26, AVR::R29R28, AVR::R17R16, AVR::R26R25, AVR::R24R23, AVR::R22R21, AVR::R20R19, AVR::R18R17, 
    /* 237 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R27R26, AVR::R29R28, AVR::R17R16, AVR::R26R25, AVR::R24R23, AVR::R22R21, AVR::R20R19, AVR::R18R17, 
    /* 249 */ AVR::R15R14, AVR::R13R12, AVR::R11R10, AVR::R9R8, AVR::R7R6, AVR::R5R4, AVR::R3R2, AVR::R1R0, AVR::R16R15, AVR::R14R13, AVR::R12R11, AVR::R10R9, 
    /* 261 */ AVR::R15R14, AVR::R13R12, AVR::R11R10, AVR::R9R8, AVR::R7R6, AVR::R5R4, AVR::R3R2, AVR::R1R0, AVR::R14R13, AVR::R12R11, AVR::R10R9, 
    /* 272 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R31R30, AVR::R27R26, AVR::R29R28, AVR::R17R16, 
    /* 280 */ AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R17R16, AVR::R22R21, AVR::R20R19, AVR::R18R17, AVR::R16R15, 
    /* 288 */ AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R17R16, AVR::R24R23, AVR::R22R21, AVR::R20R19, AVR::R18R17, 
    /* 296 */ AVR::R15R14, AVR::R13R12, AVR::R11R10, AVR::R9R8, AVR::R7R6, AVR::R5R4, AVR::R3R2, AVR::R1R0, 
    /* 304 */ AVR::R25R24, AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R27R26, AVR::R29R28, AVR::R17R16, 
    /* 311 */ AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R17R16, AVR::R22R21, AVR::R20R19, AVR::R18R17, 
    /* 318 */ AVR::R19R18, AVR::R21R20, AVR::R23R22, AVR::R17R16, 
    /* 322 */ AVR::R25R24, AVR::R31R30, AVR::R27R26, AVR::R29R28, 
    /* 326 */ AVR::R25R24, AVR::R27R26, AVR::R29R28, 
    /* 329 */ AVR::R27R26, AVR::R29R28, AVR::R31R30, 
    /* 332 */ AVR::R27R26, AVR::R29R28, 
    /* 334 */ AVR::R31R30, AVR::R29R28, 
    /* 336 */ AVR::R29R28, 
    /* 337 */ AVR::R16R15, 
    /* 338 */ AVR::SP, 
    /* 339 */ AVR::R31R30, 
  },
  {
    /* 0 */ 0xe0, 0xff, 0xff, 0xff, 0x1f, 
    /* 5 */ 0xe0, 0xff, 0xff, 0xff, 0x07, 
    /* 10 */ 0xe0, 0xff, 0x1f, 
    /* 13 */ 0x00, 0x00, 0xe0, 0xff, 0x1f, 
    /* 18 */ 0x00, 0x00, 0xe0, 0xff, 0x07, 
    /* 23 */ 0x00, 0x00, 0xe0, 0x1f, 
    /* 27 */ 0x10, 
    /* 28 */ 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0x3f, 
    /* 36 */ 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0x1f, 
    /* 44 */ 0x00, 0x00, 0x00, 0x00, 0xe0, 0xab, 0xaa, 0x3a, 
    /* 52 */ 0x00, 0x00, 0x00, 0x00, 0xe0, 0xab, 0xaa, 0x1a, 
    /* 60 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 
    /* 68 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 
    /* 76 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x3f, 
    /* 84 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x1f, 
    /* 92 */ 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x01, 
    /* 99 */ 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 
    /* 105 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x3a, 
    /* 113 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
    /* 120 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
    /* 128 */ 0x00, 0x00, 0x00, 0x00, 0xe0, 0xab, 
    /* 134 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x1a, 
    /* 142 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 
    /* 149 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 
    /* 156 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 
    /* 164 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 
    /* 172 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 
    /* 180 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
    /* 188 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 
    /* 196 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 
    /* 204 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
    /* 211 */ 0x02, 
    /* 212 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  },
  {
    // 0 GPR8
    0x0000003f, 0x00000000, 
    0x7fffff80, 0x00000001, // sub_hi
    0x7fffff80, 0x00000001, // sub_lo
    // 6 GPR8NOZ
    0x00000036, 0x00000000, 
    0x6afdd500, 0x00000000, // sub_hi
    0x6afdd500, 0x00000000, // sub_lo
    // 12 GPR8lo
    0x00000004, 0x00000000, 
    0x00110000, 0x00000000, // sub_hi
    0x40118000, 0x00000000, // sub_lo
    // 18 LD8
    0x00000038, 0x00000000, 
    0x7fee7800, 0x00000001, // sub_hi
    0x3fea6000, 0x00000001, // sub_lo
    // 24 GPR8NOZ_and_LD8
    0x00000030, 0x00000000, 
    0x6aec5000, 0x00000000, // sub_hi
    0x2ae84000, 0x00000000, // sub_lo
    // 30 LD8lo
    0x00000020, 0x00000000, 
    0x40c40000, 0x00000000, // sub_hi
    0x00c80000, 0x00000000, // sub_lo
    // 36 CCR
    0x00000040, 0x00000000, 
    // 38 DREGS
    0x7fffff80, 0x00000001, 
    // 40 DREGSNOZ
    0x6afdd500, 0x00000000, 
    // 42 DREGSMOVW
    0x3fb20600, 0x00000001, 
    // 44 DREGSMOVW_and_DREGSNOZ
    0x2ab00400, 0x00000000, 
    // 46 DREGS_with_sub_hi_in_LD8
    0x7fee7800, 0x00000001, 
    // 48 DREGSNOZ_and_DREGS_with_sub_hi_in_LD8
    0x6aec5000, 0x00000000, 
    // 50 DREGS_with_sub_lo_in_LD8
    0x3fea6000, 0x00000001, 
    // 52 DREGSNOZ_and_DREGS_with_sub_lo_in_LD8
    0x2ae84000, 0x00000000, 
    // 54 DREGS_with_sub_lo_in_GPR8lo
    0x40118000, 0x00000000, 
    // 56 DREGS_with_sub_hi_in_GPR8lo
    0x00110000, 0x00000000, 
    // 58 DLDREGS
    0x3fa20000, 0x00000001, 
    // 60 DREGS_with_sub_hi_in_LD8lo
    0x40c40000, 0x00000000, 
    // 62 DREGS_with_sub_lo_in_LD8lo
    0x00c80000, 0x00000000, 
    // 64 DREGSlo
    0x00100000, 0x00000000, 
    // 66 DLDREGS_and_DREGSNOZ
    0x2aa00000, 0x00000000, 
    // 68 DREGS_with_sub_hi_in_LD8lo_and_DREGS_with_sub_lo_in_LD8
    0x00c00000, 0x00000000, 
    // 70 DREGSLD8lo
    0x00800000, 0x00000000, 
    // 72 IWREGS
    0x3f000000, 0x00000001, 
    // 74 DREGSNOZ_and_IWREGS
    0x2a000000, 0x00000000, 
    // 76 PTRREGS
    0x3c000000, 0x00000001, 
    // 78 DREGSNOZ_and_PTRREGS
    0x28000000, 0x00000000, 
    // 80 PTRDISPREGS
    0x30000000, 0x00000001, 
    // 82 DREGSNOZ_and_PTRDISPREGS
    0x20000000, 0x00000000, 
    // 84 DREGS_with_sub_hi_in_LD8_and_DREGS_with_sub_lo_in_GPR8lo
    0x40000000, 0x00000000, 
    // 86 GPRSP
    0x80000000, 0x00000000, 
    // 88 ZREG
    0x00000000, 0x00000001, 
  },
  {
  /* 0 */ 1, 2, 0,
  },
  {
    /* 0 GPR8 */ 
    /* 0 GPR8NOZ */ AVR::GPR8RegClassID, 
    /* 1 GPR8lo */ AVR::GPR8RegClassID, AVR::GPR8NOZRegClassID, 
    /* 3 LD8 */ AVR::GPR8RegClassID, 
    /* 4 GPR8NOZ_and_LD8 */ AVR::GPR8RegClassID, AVR::GPR8NOZRegClassID, AVR::LD8RegClassID, 
    /* 7 LD8lo */ AVR::GPR8RegClassID, AVR::GPR8NOZRegClassID, AVR::LD8RegClassID, AVR::GPR8NOZ_and_LD8RegClassID, 
    /* 11 CCR */ 
    /* 11 DREGS */ 
    /* 11 DREGSNOZ */ AVR::DREGSRegClassID, 
    /* 12 DREGSMOVW */ AVR::DREGSRegClassID, 
    /* 13 DREGSMOVW_and_DREGSNOZ */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGSMOVWRegClassID, 
    /* 16 DREGS_with_sub_hi_in_LD8 */ AVR::DREGSRegClassID, 
    /* 17 DREGSNOZ_and_DREGS_with_sub_hi_in_LD8 */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, 
    /* 20 DREGS_with_sub_lo_in_LD8 */ AVR::DREGSRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, 
    /* 22 DREGSNOZ_and_DREGS_with_sub_lo_in_LD8 */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, 
    /* 27 DREGS_with_sub_lo_in_GPR8lo */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, 
    /* 29 DREGS_with_sub_hi_in_GPR8lo */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGS_with_sub_lo_in_GPR8loRegClassID, 
    /* 32 DLDREGS */ AVR::DREGSRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, 
    /* 36 DREGS_with_sub_hi_in_LD8lo */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, 
    /* 40 DREGS_with_sub_lo_in_LD8lo */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_lo_in_LD8RegClassID, 
    /* 46 DREGSlo */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGSMOVW_and_DREGSNOZRegClassID, AVR::DREGS_with_sub_lo_in_GPR8loRegClassID, AVR::DREGS_with_sub_hi_in_GPR8loRegClassID, 
    /* 52 DLDREGS_and_DREGSNOZ */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGSMOVW_and_DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_lo_in_LD8RegClassID, AVR::DLDREGSRegClassID, 
    /* 61 DREGS_with_sub_hi_in_LD8lo_and_DREGS_with_sub_lo_in_LD8 */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_lo_in_LD8RegClassID, AVR::DREGS_with_sub_hi_in_LD8loRegClassID, AVR::DREGS_with_sub_lo_in_LD8loRegClassID, 
    /* 69 DREGSLD8lo */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGSMOVW_and_DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_lo_in_LD8RegClassID, AVR::DLDREGSRegClassID, AVR::DREGS_with_sub_hi_in_LD8loRegClassID, AVR::DREGS_with_sub_lo_in_LD8loRegClassID, AVR::DLDREGS_and_DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8lo_and_DREGS_with_sub_lo_in_LD8RegClassID, 
    /* 82 IWREGS */ AVR::DREGSRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DLDREGSRegClassID, 
    /* 87 DREGSNOZ_and_IWREGS */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGSMOVW_and_DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_lo_in_LD8RegClassID, AVR::DLDREGSRegClassID, AVR::DLDREGS_and_DREGSNOZRegClassID, AVR::IWREGSRegClassID, 
    /* 98 PTRREGS */ AVR::DREGSRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DLDREGSRegClassID, AVR::IWREGSRegClassID, 
    /* 104 DREGSNOZ_and_PTRREGS */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGSMOVW_and_DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_lo_in_LD8RegClassID, AVR::DLDREGSRegClassID, AVR::DLDREGS_and_DREGSNOZRegClassID, AVR::IWREGSRegClassID, AVR::DREGSNOZ_and_IWREGSRegClassID, AVR::PTRREGSRegClassID, 
    /* 117 PTRDISPREGS */ AVR::DREGSRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DLDREGSRegClassID, AVR::IWREGSRegClassID, AVR::PTRREGSRegClassID, 
    /* 124 DREGSNOZ_and_PTRDISPREGS */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGSMOVW_and_DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_lo_in_LD8RegClassID, AVR::DLDREGSRegClassID, AVR::DLDREGS_and_DREGSNOZRegClassID, AVR::IWREGSRegClassID, AVR::DREGSNOZ_and_IWREGSRegClassID, AVR::PTRREGSRegClassID, AVR::DREGSNOZ_and_PTRREGSRegClassID, AVR::PTRDISPREGSRegClassID, 
    /* 139 DREGS_with_sub_hi_in_LD8_and_DREGS_with_sub_lo_in_GPR8lo */ AVR::DREGSRegClassID, AVR::DREGSNOZRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_GPR8loRegClassID, AVR::DREGS_with_sub_hi_in_LD8loRegClassID, 
    /* 145 GPRSP */ 
    /* 145 ZREG */ AVR::DREGSRegClassID, AVR::DREGSMOVWRegClassID, AVR::DREGS_with_sub_hi_in_LD8RegClassID, AVR::DREGS_with_sub_lo_in_LD8RegClassID, AVR::DLDREGSRegClassID, AVR::IWREGSRegClassID, AVR::PTRREGSRegClassID, AVR::PTRDISPREGSRegClassID, 
  }
};

const MCRegisterClass &getAVRMCRegisterClass(unsigned RC) {
  return AVRMCRegisterClassStorage.Classes[RC];
}

// AVR Dwarf<->LLVM register mappings.
extern const MCRegisterInfo::DwarfLLVMRegPair AVRDwarfFlavour0Dwarf2L[] = {
  { 0U, AVR::R1R0 },
  { 1U, AVR::R1 },
  { 2U, AVR::R3R2 },
  { 3U, AVR::R3 },
  { 4U, AVR::R5R4 },
  { 5U, AVR::R5 },
  { 6U, AVR::R7R6 },
  { 7U, AVR::R7 },
  { 8U, AVR::R9R8 },
  { 9U, AVR::R10R9 },
  { 10U, AVR::R11R10 },
  { 11U, AVR::R12R11 },
  { 12U, AVR::R13R12 },
  { 13U, AVR::R14R13 },
  { 14U, AVR::R15R14 },
  { 15U, AVR::R16R15 },
  { 16U, AVR::R17R16 },
  { 17U, AVR::R18R17 },
  { 18U, AVR::R19R18 },
  { 19U, AVR::R20R19 },
  { 20U, AVR::R21R20 },
  { 21U, AVR::R22R21 },
  { 22U, AVR::R23R22 },
  { 23U, AVR::R24R23 },
  { 24U, AVR::R25R24 },
  { 25U, AVR::R26R25 },
  { 26U, AVR::R27R26 },
  { 27U, AVR::R27 },
  { 28U, AVR::R29R28 },
  { 29U, AVR::R29 },
  { 30U, AVR::R31R30 },
  { 31U, AVR::R31 },
  { 32U, AVR::SPL },
  { 33U, AVR::SPH },
  { 88U, AVR::SREG },
};
extern const unsigned AVRDwarfFlavour0Dwarf2LSize = std::size(AVRDwarfFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair AVREHFlavour0Dwarf2L[] = {
  { 0U, AVR::R1R0 },
  { 1U, AVR::R1 },
  { 2U, AVR::R3R2 },
  { 3U, AVR::R3 },
  { 4U, AVR::R5R4 },
  { 5U, AVR::R5 },
  { 6U, AVR::R7R6 },
  { 7U, AVR::R7 },
  { 8U, AVR::R9R8 },
  { 9U, AVR::R10R9 },
  { 10U, AVR::R11R10 },
  { 11U, AVR::R12R11 },
  { 12U, AVR::R13R12 },
  { 13U, AVR::R14R13 },
  { 14U, AVR::R15R14 },
  { 15U, AVR::R16R15 },
  { 16U, AVR::R17R16 },
  { 17U, AVR::R18R17 },
  { 18U, AVR::R19R18 },
  { 19U, AVR::R20R19 },
  { 20U, AVR::R21R20 },
  { 21U, AVR::R22R21 },
  { 22U, AVR::R23R22 },
  { 23U, AVR::R24R23 },
  { 24U, AVR::R25R24 },
  { 25U, AVR::R26R25 },
  { 26U, AVR::R27R26 },
  { 27U, AVR::R27 },
  { 28U, AVR::R29R28 },
  { 29U, AVR::R29 },
  { 30U, AVR::R31R30 },
  { 31U, AVR::R31 },
  { 32U, AVR::SPL },
  { 33U, AVR::SPH },
  { 88U, AVR::SREG },
};
extern const unsigned AVREHFlavour0Dwarf2LSize = std::size(AVREHFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair AVRDwarfFlavour0L2Dwarf[] = {
  { AVR::SP, 32U },
  { AVR::SPH, 33U },
  { AVR::SPL, 32U },
  { AVR::SREG, 88U },
  { AVR::R0, 0U },
  { AVR::R1, 1U },
  { AVR::R2, 2U },
  { AVR::R3, 3U },
  { AVR::R4, 4U },
  { AVR::R5, 5U },
  { AVR::R6, 6U },
  { AVR::R7, 7U },
  { AVR::R8, 8U },
  { AVR::R9, 9U },
  { AVR::R10, 10U },
  { AVR::R11, 11U },
  { AVR::R12, 12U },
  { AVR::R13, 13U },
  { AVR::R14, 14U },
  { AVR::R15, 15U },
  { AVR::R16, 16U },
  { AVR::R17, 17U },
  { AVR::R18, 18U },
  { AVR::R19, 19U },
  { AVR::R20, 20U },
  { AVR::R21, 21U },
  { AVR::R22, 22U },
  { AVR::R23, 23U },
  { AVR::R24, 24U },
  { AVR::R25, 25U },
  { AVR::R26, 26U },
  { AVR::R27, 27U },
  { AVR::R28, 28U },
  { AVR::R29, 29U },
  { AVR::R30, 30U },
  { AVR::R31, 31U },
  { AVR::R1R0, 0U },
  { AVR::R3R2, 2U },
  { AVR::R5R4, 4U },
  { AVR::R7R6, 6U },
  { AVR::R9R8, 8U },
  { AVR::R10R9, 9U },
  { AVR::R11R10, 10U },
  { AVR::R12R11, 11U },
  { AVR::R13R12, 12U },
  { AVR::R14R13, 13U },
  { AVR::R15R14, 14U },
  { AVR::R16R15, 15U },
  { AVR::R17R16, 16U },
  { AVR::R18R17, 17U },
  { AVR::R19R18, 18U },
  { AVR::R20R19, 19U },
  { AVR::R21R20, 20U },
  { AVR::R22R21, 21U },
  { AVR::R23R22, 22U },
  { AVR::R24R23, 23U },
  { AVR::R25R24, 24U },
  { AVR::R26R25, 25U },
  { AVR::R27R26, 26U },
  { AVR::R29R28, 28U },
  { AVR::R31R30, 30U },
};
extern const unsigned AVRDwarfFlavour0L2DwarfSize = std::size(AVRDwarfFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair AVREHFlavour0L2Dwarf[] = {
  { AVR::SP, 32U },
  { AVR::SPH, 33U },
  { AVR::SPL, 32U },
  { AVR::SREG, 88U },
  { AVR::R0, 0U },
  { AVR::R1, 1U },
  { AVR::R2, 2U },
  { AVR::R3, 3U },
  { AVR::R4, 4U },
  { AVR::R5, 5U },
  { AVR::R6, 6U },
  { AVR::R7, 7U },
  { AVR::R8, 8U },
  { AVR::R9, 9U },
  { AVR::R10, 10U },
  { AVR::R11, 11U },
  { AVR::R12, 12U },
  { AVR::R13, 13U },
  { AVR::R14, 14U },
  { AVR::R15, 15U },
  { AVR::R16, 16U },
  { AVR::R17, 17U },
  { AVR::R18, 18U },
  { AVR::R19, 19U },
  { AVR::R20, 20U },
  { AVR::R21, 21U },
  { AVR::R22, 22U },
  { AVR::R23, 23U },
  { AVR::R24, 24U },
  { AVR::R25, 25U },
  { AVR::R26, 26U },
  { AVR::R27, 27U },
  { AVR::R28, 28U },
  { AVR::R29, 29U },
  { AVR::R30, 30U },
  { AVR::R31, 31U },
  { AVR::R1R0, 0U },
  { AVR::R3R2, 2U },
  { AVR::R5R4, 4U },
  { AVR::R7R6, 6U },
  { AVR::R9R8, 8U },
  { AVR::R10R9, 9U },
  { AVR::R11R10, 10U },
  { AVR::R12R11, 11U },
  { AVR::R13R12, 12U },
  { AVR::R14R13, 13U },
  { AVR::R15R14, 14U },
  { AVR::R16R15, 15U },
  { AVR::R17R16, 16U },
  { AVR::R18R17, 17U },
  { AVR::R19R18, 18U },
  { AVR::R20R19, 19U },
  { AVR::R21R20, 20U },
  { AVR::R22R21, 21U },
  { AVR::R23R22, 22U },
  { AVR::R24R23, 23U },
  { AVR::R25R24, 24U },
  { AVR::R26R25, 25U },
  { AVR::R27R26, 26U },
  { AVR::R29R28, 28U },
  { AVR::R31R30, 30U },
};
extern const unsigned AVREHFlavour0L2DwarfSize = std::size(AVREHFlavour0L2Dwarf);

extern const uint16_t AVRRegEncodingTable[] = {
  0,
  16,
  33,
  32,
  14,
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
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  0,
  1,
  2,
  3,
  4,
  9,
  5,
  11,
  6,
  13,
  7,
  15,
  8,
  17,
  9,
  19,
  10,
  21,
  11,
  23,
  12,
  25,
  13,
  14,
  15,
};
static inline void InitAVRMCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(AVRRegDesc, 62, RA, PC, AVRMCRegisterClassStorage.Classes, 33, AVRRegUnitRoots, 35, AVRRegDiffLists, AVRLaneMaskLists, AVRRegStrings, AVRRegClassStrings, AVRSubRegIdxLists, 3,
AVRRegEncodingTable, nullptr);

  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(AVRDwarfFlavour0Dwarf2L, AVRDwarfFlavour0Dwarf2LSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(AVREHFlavour0Dwarf2L, AVREHFlavour0Dwarf2LSize, true);
    break;
  }
  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(AVRDwarfFlavour0L2Dwarf, AVRDwarfFlavour0L2DwarfSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(AVREHFlavour0L2Dwarf, AVREHFlavour0L2DwarfSize, true);
    break;
  }
}


} // namespace llvm_ks
