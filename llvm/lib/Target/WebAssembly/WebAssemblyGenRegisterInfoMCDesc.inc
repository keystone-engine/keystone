/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

extern const int16_t WebAssemblyRegDiffLists[] = {
  /* 0 */ 0,
};

extern const LaneBitmask WebAssemblyLaneMaskLists[] = {
  /* 0 */ LaneBitmask(0xFFFFFFFFFFFFFFFF), 
};

extern const uint16_t WebAssemblySubRegIdxLists[] = {
  /* 0 */ 
  /* dummy */ 0
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char WebAssemblyRegStrings[] = {
  /* 0 */ "F32_0\000"
  /* 6 */ "I32_0\000"
  /* 12 */ "F64_0\000"
  /* 18 */ "I64_0\000"
  /* 24 */ "V128_0\000"
  /* 31 */ "FUNCREF_0\000"
  /* 41 */ "EXTERNREF_0\000"
  /* 53 */ "EXNREF_0\000"
  /* 62 */ "FP32\000"
  /* 67 */ "SP32\000"
  /* 72 */ "FP64\000"
  /* 77 */ "SP64\000"
  /* 82 */ "VALUE_STACK\000"
  /* 94 */ "ARGUMENTS\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const MCRegisterDesc WebAssemblyRegDesc[] = { // Descriptors
  { 5, 0, 0, 0, 0, 0, 0, 0 },
  { 94, 0, 0, 0, 0, 0, 0, 0 },
  { 82, 0, 0, 0, 1, 0, 0, 0 },
  { 53, 0, 0, 0, 2, 0, 0, 0 },
  { 41, 0, 0, 0, 3, 0, 0, 0 },
  { 62, 0, 0, 0, 4, 0, 0, 0 },
  { 72, 0, 0, 0, 5, 0, 0, 0 },
  { 31, 0, 0, 0, 6, 0, 0, 0 },
  { 67, 0, 0, 0, 7, 0, 0, 0 },
  { 77, 0, 0, 0, 8, 0, 0, 0 },
  { 0, 0, 0, 0, 9, 0, 0, 0 },
  { 12, 0, 0, 0, 10, 0, 0, 0 },
  { 6, 0, 0, 0, 11, 0, 0, 0 },
  { 18, 0, 0, 0, 12, 0, 0, 0 },
  { 24, 0, 0, 0, 13, 0, 0, 0 },
};

extern const MCPhysReg WebAssemblyRegUnitRoots[][2] = {
  { WebAssembly::ARGUMENTS },
  { WebAssembly::VALUE_STACK },
  { WebAssembly::EXNREF_0 },
  { WebAssembly::EXTERNREF_0 },
  { WebAssembly::FP32 },
  { WebAssembly::FP64 },
  { WebAssembly::FUNCREF_0 },
  { WebAssembly::SP32 },
  { WebAssembly::SP64 },
  { WebAssembly::F32_0 },
  { WebAssembly::F64_0 },
  { WebAssembly::I32_0 },
  { WebAssembly::I64_0 },
  { WebAssembly::V128_0 },
};

// Register classes...

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char WebAssemblyRegClassStrings[] = {
  /* 0 */ "F32\000"
  /* 4 */ "I32\000"
  /* 8 */ "F64\000"
  /* 12 */ "I64\000"
  /* 16 */ "V128\000"
  /* 21 */ "FUNCREF\000"
  /* 29 */ "EXTERNREF\000"
  /* 39 */ "EXNREF\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using WebAssemblyRegisterClassStorage = MCRegisterClassStorage<8, 12, 13, 8, 1, 0>;
extern const MCRegisterClassStorage<8, 12, 13, 8, 1, 0> WebAssemblyMCRegisterClassStorage = {
  {
    {
      offsetof(WebAssemblyRegisterClassStorage, Regs[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, BitSets[0]) - 0 * sizeof(MCRegisterClass),
      39,
      0,
      1,
      1,
      WebAssembly::EXNREFRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(WebAssemblyRegisterClassStorage, SubClassMasks[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, SuperRegIdxSeqs[0]) - 0 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(WebAssemblyRegisterClassStorage, SuperClasses[0]) - 0 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(WebAssemblyRegisterClassStorage, Regs[1]) - 1 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, BitSets[1]) - 1 * sizeof(MCRegisterClass),
      29,
      0,
      1,
      1,
      WebAssembly::EXTERNREFRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(WebAssemblyRegisterClassStorage, SubClassMasks[1]) - 1 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, SuperRegIdxSeqs[0]) - 1 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(WebAssemblyRegisterClassStorage, SuperClasses[0]) - 1 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(WebAssemblyRegisterClassStorage, Regs[2]) - 2 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, BitSets[2]) - 2 * sizeof(MCRegisterClass),
      21,
      0,
      1,
      1,
      WebAssembly::FUNCREFRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(WebAssemblyRegisterClassStorage, SubClassMasks[2]) - 2 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, SuperRegIdxSeqs[0]) - 2 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(WebAssemblyRegisterClassStorage, SuperClasses[0]) - 2 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(WebAssemblyRegisterClassStorage, Regs[3]) - 3 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, BitSets[3]) - 3 * sizeof(MCRegisterClass),
      4,
      32,
      3,
      2,
      WebAssembly::I32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(WebAssemblyRegisterClassStorage, SubClassMasks[3]) - 3 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, SuperRegIdxSeqs[0]) - 3 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(WebAssemblyRegisterClassStorage, SuperClasses[0]) - 3 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(WebAssemblyRegisterClassStorage, Regs[6]) - 4 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, BitSets[5]) - 4 * sizeof(MCRegisterClass),
      0,
      32,
      1,
      2,
      WebAssembly::F32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(WebAssemblyRegisterClassStorage, SubClassMasks[4]) - 4 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, SuperRegIdxSeqs[0]) - 4 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(WebAssemblyRegisterClassStorage, SuperClasses[0]) - 4 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(WebAssemblyRegisterClassStorage, Regs[7]) - 5 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, BitSets[7]) - 5 * sizeof(MCRegisterClass),
      12,
      64,
      3,
      2,
      WebAssembly::I64RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(WebAssemblyRegisterClassStorage, SubClassMasks[5]) - 5 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, SuperRegIdxSeqs[0]) - 5 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(WebAssemblyRegisterClassStorage, SuperClasses[0]) - 5 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(WebAssemblyRegisterClassStorage, Regs[10]) - 6 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, BitSets[9]) - 6 * sizeof(MCRegisterClass),
      8,
      64,
      1,
      2,
      WebAssembly::F64RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(WebAssemblyRegisterClassStorage, SubClassMasks[6]) - 6 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, SuperRegIdxSeqs[0]) - 6 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(WebAssemblyRegisterClassStorage, SuperClasses[0]) - 6 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(WebAssemblyRegisterClassStorage, Regs[11]) - 7 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, BitSets[11]) - 7 * sizeof(MCRegisterClass),
      16,
      128,
      1,
      2,
      WebAssembly::V128RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(WebAssemblyRegisterClassStorage, SubClassMasks[7]) - 7 * sizeof(MCRegisterClass),
      offsetof(WebAssemblyRegisterClassStorage, SuperRegIdxSeqs[0]) - 7 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(WebAssemblyRegisterClassStorage, SuperClasses[0]) - 7 * sizeof(MCRegisterClass),
      0
    },
  },
  {
    /* 0 */ WebAssembly::EXNREF_0, 
    /* 1 */ WebAssembly::EXTERNREF_0, 
    /* 2 */ WebAssembly::FUNCREF_0, 
    /* 3 */ WebAssembly::FP32, WebAssembly::SP32, WebAssembly::I32_0, 
    /* 6 */ WebAssembly::F32_0, 
    /* 7 */ WebAssembly::FP64, WebAssembly::SP64, WebAssembly::I64_0, 
    /* 10 */ WebAssembly::F64_0, 
    /* 11 */ WebAssembly::V128_0, 
  },
  {
    /* 0 */ 0x08, 
    /* 1 */ 0x10, 
    /* 2 */ 0x80, 
    /* 3 */ 0x20, 0x11, 
    /* 5 */ 0x00, 0x04, 
    /* 7 */ 0x40, 0x22, 
    /* 9 */ 0x00, 0x08, 
    /* 11 */ 0x00, 0x40, 
  },
  {
    // 0 EXNREF
    0x00000001, 
    // 1 EXTERNREF
    0x00000002, 
    // 2 FUNCREF
    0x00000004, 
    // 3 I32
    0x00000008, 
    // 4 F32
    0x00000010, 
    // 5 I64
    0x00000020, 
    // 6 F64
    0x00000040, 
    // 7 V128
    0x00000080, 
  },
  {
  /* 0 */ 0,
  },
  {
    /* 0 EXNREF */ 
    /* 0 EXTERNREF */ 
    /* 0 FUNCREF */ 
    /* 0 I32 */ 
    /* 0 F32 */ 
    /* 0 I64 */ 
    /* 0 F64 */ 
    /* 0 V128 */ 
  }
};

const MCRegisterClass &getWebAssemblyMCRegisterClass(unsigned RC) {
  return WebAssemblyMCRegisterClassStorage.Classes[RC];
}

extern const uint16_t WebAssemblyRegEncodingTable[] = {
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
static inline void InitWebAssemblyMCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(WebAssemblyRegDesc, 15, RA, PC, WebAssemblyMCRegisterClassStorage.Classes, 8, WebAssemblyRegUnitRoots, 14, WebAssemblyRegDiffLists, WebAssemblyLaneMaskLists, WebAssemblyRegStrings, WebAssemblyRegClassStrings, WebAssemblySubRegIdxLists, 1,
WebAssemblyRegEncodingTable, nullptr);

}


} // namespace llvm_ks
