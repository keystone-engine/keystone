/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getXtensaMCRegisterClass(unsigned RC);
namespace Xtensa {

enum : unsigned {
  NoRegister,
  ACCHI = 1,
  ACCLO = 2,
  ATOMCTL = 3,
  BREG = 4,
  CCOUNT = 5,
  CPENABLE = 6,
  DDR = 7,
  DEBUGCAUSE = 8,
  DEPC = 9,
  EXCCAUSE = 10,
  EXCVADDR = 11,
  FCR = 12,
  FSR = 13,
  IBREAKENABLE = 14,
  ICOUNT = 15,
  ICOUNTLEVEL = 16,
  INTCLEAR = 17,
  INTENABLE = 18,
  INTERRUPT = 19,
  INTSET = 20,
  LBEG = 21,
  LCOUNT = 22,
  LEND = 23,
  LITBASE = 24,
  MEMCTL = 25,
  PRID = 26,
  PS = 27,
  SAR = 28,
  SP = 29,
  THREADPTR = 30,
  VECBASE = 31,
  WINDOWBASE = 32,
  WINDOWSTART = 33,
  A0 = 34,
  A2 = 35,
  A3 = 36,
  A4 = 37,
  A5 = 38,
  A6 = 39,
  A7 = 40,
  A8 = 41,
  A9 = 42,
  A10 = 43,
  A11 = 44,
  A12 = 45,
  A13 = 46,
  A14 = 47,
  A15 = 48,
  B0 = 49,
  B1 = 50,
  B2 = 51,
  B3 = 52,
  B4 = 53,
  B5 = 54,
  B6 = 55,
  B7 = 56,
  B8 = 57,
  B9 = 58,
  B10 = 59,
  B11 = 60,
  B12 = 61,
  B13 = 62,
  B14 = 63,
  B15 = 64,
  CCOMPARE0 = 65,
  CCOMPARE1 = 66,
  CCOMPARE2 = 67,
  CONFIGID0 = 68,
  CONFIGID1 = 69,
  DBREAKA0 = 70,
  DBREAKA1 = 71,
  DBREAKC0 = 72,
  DBREAKC1 = 73,
  EPC1 = 74,
  EPC2 = 75,
  EPC3 = 76,
  EPC4 = 77,
  EPC5 = 78,
  EPC6 = 79,
  EPC7 = 80,
  EPS2 = 81,
  EPS3 = 82,
  EPS4 = 83,
  EPS5 = 84,
  EPS6 = 85,
  EPS7 = 86,
  EXCSAVE1 = 87,
  EXCSAVE2 = 88,
  EXCSAVE3 = 89,
  EXCSAVE4 = 90,
  EXCSAVE5 = 91,
  EXCSAVE6 = 92,
  EXCSAVE7 = 93,
  F0 = 94,
  F1 = 95,
  F2 = 96,
  F3 = 97,
  F4 = 98,
  F5 = 99,
  F6 = 100,
  F7 = 101,
  F8 = 102,
  F9 = 103,
  F10 = 104,
  F11 = 105,
  F12 = 106,
  F13 = 107,
  F14 = 108,
  F15 = 109,
  GPIO_OUT_S2 = 110,
  IBREAKA0 = 111,
  IBREAKA1 = 112,
  M0 = 113,
  M1 = 114,
  M2 = 115,
  M3 = 116,
  MISC0 = 117,
  MISC1 = 118,
  MISC2 = 119,
  MISC3 = 120,
  SCOMPARE1 = 121,
  F64R_HI = 122,
  F64R_LO = 123,
  F64S = 124,
  NUM_TARGET_REGS // 125
};

} // namespace Xtensa

// Register classes

namespace Xtensa {

enum {
  BRRegClassID = 0,
  SRRegClassID = 1,
  ARRegClassID = 2,
  FPRRegClassID = 3,
  URRegClassID = 4,
  MRRegClassID = 5,
  MR01RegClassID = 6,
  MR23RegClassID = 7,

};

} // namespace Xtensa
// Register pressure sets enum.
namespace Xtensa {

enum RegisterPressureSets {
  MR = 0,
  UR = 1,
  BR = 2,
  AR = 3,
  FPR = 4,
  SR = 5,
};

} // namespace Xtensa

} // namespace llvm_ks
