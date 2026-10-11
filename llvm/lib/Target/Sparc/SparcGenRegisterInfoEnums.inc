/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getSparcMCRegisterClass(unsigned RC);
namespace SP {

enum : unsigned {
  NoRegister,
  CANRESTORE = 1,
  CANSAVE = 2,
  CLEANWIN = 3,
  CPQ = 4,
  CPSR = 5,
  CWP = 6,
  FQ = 7,
  FSR = 8,
  GL = 9,
  ICC = 10,
  OTHERWIN = 11,
  PIL = 12,
  PSR = 13,
  PSTATE = 14,
  TBA = 15,
  TBR = 16,
  TICK = 17,
  TL = 18,
  TNPC = 19,
  TPC = 20,
  TSTATE = 21,
  TT = 22,
  VER = 23,
  WIM = 24,
  WSTATE = 25,
  Y = 26,
  ASR1 = 27,
  ASR2 = 28,
  ASR3 = 29,
  ASR4 = 30,
  ASR5 = 31,
  ASR6 = 32,
  ASR7 = 33,
  ASR8 = 34,
  ASR9 = 35,
  ASR10 = 36,
  ASR11 = 37,
  ASR12 = 38,
  ASR13 = 39,
  ASR14 = 40,
  ASR15 = 41,
  ASR16 = 42,
  ASR17 = 43,
  ASR18 = 44,
  ASR19 = 45,
  ASR20 = 46,
  ASR21 = 47,
  ASR22 = 48,
  ASR23 = 49,
  ASR24 = 50,
  ASR25 = 51,
  ASR26 = 52,
  ASR27 = 53,
  ASR28 = 54,
  ASR29 = 55,
  ASR30 = 56,
  ASR31 = 57,
  C0 = 58,
  C1 = 59,
  C2 = 60,
  C3 = 61,
  C4 = 62,
  C5 = 63,
  C6 = 64,
  C7 = 65,
  C8 = 66,
  C9 = 67,
  C10 = 68,
  C11 = 69,
  C12 = 70,
  C13 = 71,
  C14 = 72,
  C15 = 73,
  C16 = 74,
  C17 = 75,
  C18 = 76,
  C19 = 77,
  C20 = 78,
  C21 = 79,
  C22 = 80,
  C23 = 81,
  C24 = 82,
  C25 = 83,
  C26 = 84,
  C27 = 85,
  C28 = 86,
  C29 = 87,
  C30 = 88,
  C31 = 89,
  D0 = 90,
  D1 = 91,
  D2 = 92,
  D3 = 93,
  D4 = 94,
  D5 = 95,
  D6 = 96,
  D7 = 97,
  D8 = 98,
  D9 = 99,
  D10 = 100,
  D11 = 101,
  D12 = 102,
  D13 = 103,
  D14 = 104,
  D15 = 105,
  D16 = 106,
  D17 = 107,
  D18 = 108,
  D19 = 109,
  D20 = 110,
  D21 = 111,
  D22 = 112,
  D23 = 113,
  D24 = 114,
  D25 = 115,
  D26 = 116,
  D27 = 117,
  D28 = 118,
  D29 = 119,
  D30 = 120,
  D31 = 121,
  F0 = 122,
  F1 = 123,
  F2 = 124,
  F3 = 125,
  F4 = 126,
  F5 = 127,
  F6 = 128,
  F7 = 129,
  F8 = 130,
  F9 = 131,
  F10 = 132,
  F11 = 133,
  F12 = 134,
  F13 = 135,
  F14 = 136,
  F15 = 137,
  F16 = 138,
  F17 = 139,
  F18 = 140,
  F19 = 141,
  F20 = 142,
  F21 = 143,
  F22 = 144,
  F23 = 145,
  F24 = 146,
  F25 = 147,
  F26 = 148,
  F27 = 149,
  F28 = 150,
  F29 = 151,
  F30 = 152,
  F31 = 153,
  FCC0 = 154,
  FCC1 = 155,
  FCC2 = 156,
  FCC3 = 157,
  G0 = 158,
  G1 = 159,
  G2 = 160,
  G3 = 161,
  G4 = 162,
  G5 = 163,
  G6 = 164,
  G7 = 165,
  I0 = 166,
  I1 = 167,
  I2 = 168,
  I3 = 169,
  I4 = 170,
  I5 = 171,
  I6 = 172,
  I7 = 173,
  L0 = 174,
  L1 = 175,
  L2 = 176,
  L3 = 177,
  L4 = 178,
  L5 = 179,
  L6 = 180,
  L7 = 181,
  O0 = 182,
  O1 = 183,
  O2 = 184,
  O3 = 185,
  O4 = 186,
  O5 = 187,
  O6 = 188,
  O7 = 189,
  Q0 = 190,
  Q1 = 191,
  Q2 = 192,
  Q3 = 193,
  Q4 = 194,
  Q5 = 195,
  Q6 = 196,
  Q7 = 197,
  Q8 = 198,
  Q9 = 199,
  Q10 = 200,
  Q11 = 201,
  Q12 = 202,
  Q13 = 203,
  Q14 = 204,
  Q15 = 205,
  C0_C1 = 206,
  C2_C3 = 207,
  C4_C5 = 208,
  C6_C7 = 209,
  C8_C9 = 210,
  C10_C11 = 211,
  C12_C13 = 212,
  C14_C15 = 213,
  C16_C17 = 214,
  C18_C19 = 215,
  C20_C21 = 216,
  C22_C23 = 217,
  C24_C25 = 218,
  C26_C27 = 219,
  C28_C29 = 220,
  C30_C31 = 221,
  G0_G1 = 222,
  G2_G3 = 223,
  G4_G5 = 224,
  G6_G7 = 225,
  I0_I1 = 226,
  I2_I3 = 227,
  I4_I5 = 228,
  I6_I7 = 229,
  L0_L1 = 230,
  L2_L3 = 231,
  L4_L5 = 232,
  L6_L7 = 233,
  O0_O1 = 234,
  O2_O3 = 235,
  O4_O5 = 236,
  O6_O7 = 237,
  NUM_TARGET_REGS // 238
};

} // namespace SP

// Register classes

namespace SP {

enum {
  FCCRegsRegClassID = 0,
  ASRRegsRegClassID = 1,
  CoprocRegsRegClassID = 2,
  FPRegsRegClassID = 3,
  IntRegsRegClassID = 4,
  GPRIncomingArgRegClassID = 5,
  GPROutgoingArgRegClassID = 6,
  DFPRegsRegClassID = 7,
  I64RegsRegClassID = 8,
  PRRegsRegClassID = 9,
  CoprocPairRegClassID = 10,
  IntPairRegClassID = 11,
  LowDFPRegsRegClassID = 12,
  I64Regs_and_GPRIncomingArgRegClassID = 13,
  I64Regs_and_GPROutgoingArgRegClassID = 14,
  IntPair_with_sub_even_in_GPRIncomingArgRegClassID = 15,
  IntPair_with_sub_even_in_GPROutgoingArgRegClassID = 16,
  PRRegs_and_ASRRegsRegClassID = 17,
  QFPRegsRegClassID = 18,
  LowQFPRegsRegClassID = 19,

};

} // namespace SP

// Register alternate name indices

namespace SP {

enum {
  NoRegAltName,	// 0
  RegNamesStateReg,	// 1
  NUM_TARGET_REG_ALT_NAMES = 2
};

} // namespace SP

// Subregister indices

namespace SP {

enum : uint16_t {
  NoSubRegister,
  sub_even,	// 1
  sub_even64,	// 2
  sub_odd,	// 3
  sub_odd64,	// 4
  sub_odd64_then_sub_even,	// 5
  sub_odd64_then_sub_odd,	// 6
  NUM_TARGET_SUBREGS
};

} // namespace SP
// Register pressure sets enum.
namespace SP {

enum RegisterPressureSets {
  PRRegs_and_ASRRegs = 0,
  FCCRegs = 1,
  GPRIncomingArg = 2,
  GPROutgoingArg = 3,
  PRRegs = 4,
  FPRegs = 5,
  IntRegs = 6,
  DFPRegs = 7,
};

} // namespace SP

} // namespace llvm_ks
