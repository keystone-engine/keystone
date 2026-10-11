/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getM68kMCRegisterClass(unsigned RC);
namespace M68k {

enum : unsigned {
  NoRegister,
  CCR = 1,
  FPC = 2,
  FPIAR = 3,
  FPS = 4,
  PC = 5,
  SP = 6,
  SR = 7,
  WSP = 8,
  A0 = 9,
  A1 = 10,
  A2 = 11,
  A3 = 12,
  A4 = 13,
  A5 = 14,
  A6 = 15,
  BD0 = 16,
  BD1 = 17,
  BD2 = 18,
  BD3 = 19,
  BD4 = 20,
  BD5 = 21,
  BD6 = 22,
  BD7 = 23,
  D0 = 24,
  D1 = 25,
  D2 = 26,
  D3 = 27,
  D4 = 28,
  D5 = 29,
  D6 = 30,
  D7 = 31,
  FP0 = 32,
  FP1 = 33,
  FP2 = 34,
  FP3 = 35,
  FP4 = 36,
  FP5 = 37,
  FP6 = 38,
  FP7 = 39,
  WA0 = 40,
  WA1 = 41,
  WA2 = 42,
  WA3 = 43,
  WA4 = 44,
  WA5 = 45,
  WA6 = 46,
  WD0 = 47,
  WD1 = 48,
  WD2 = 49,
  WD3 = 50,
  WD4 = 51,
  WD5 = 52,
  WD6 = 53,
  WD7 = 54,
  NUM_TARGET_REGS // 55
};

} // namespace M68k

// Register classes

namespace M68k {

enum {
  DR8RegClassID = 0,
  CCRCRegClassID = 1,
  XR16RegClassID = 2,
  AR16RegClassID = 3,
  DR16RegClassID = 4,
  XR16_TCRegClassID = 5,
  AR16_TCRegClassID = 6,
  DR16_TCRegClassID = 7,
  SRCRegClassID = 8,
  SPILLRegClassID = 9,
  SPILL_RRegClassID = 10,
  XR32RegClassID = 11,
  AR32RegClassID = 12,
  DR32RegClassID = 13,
  FPDR32RegClassID = 14,
  AR32_NOSPRegClassID = 15,
  XR32_TCRegClassID = 16,
  FPSYSCRegClassID = 17,
  AR32_TCRegClassID = 18,
  DR32_TCRegClassID = 19,
  FPCSCRegClassID = 20,
  FPICRegClassID = 21,
  PCCRegClassID = 22,
  SPCRegClassID = 23,
  FPDR64RegClassID = 24,
  FPDR80RegClassID = 25,

};

} // namespace M68k

// Subregister indices

namespace M68k {

enum : uint16_t {
  NoSubRegister,
  MxSubRegIndex8Lo,	// 1
  MxSubRegIndex16Lo,	// 2
  NUM_TARGET_SUBREGS
};

} // namespace M68k
// Register pressure sets enum.
namespace M68k {

enum RegisterPressureSets {
  CCRC = 0,
  SPC = 1,
  FPIC = 2,
  XR16_TC = 3,
  FPDR32 = 4,
  DR8 = 5,
  AR16 = 6,
  XR16 = 7,
};

} // namespace M68k

} // namespace llvm_ks
