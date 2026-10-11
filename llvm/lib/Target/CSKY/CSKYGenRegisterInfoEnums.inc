/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getCSKYMCRegisterClass(unsigned RC);
namespace CSKY {

enum : unsigned {
  NoRegister,
  C = 1,
  R0 = 2,
  R1 = 3,
  R2 = 4,
  R3 = 5,
  R4 = 6,
  R5 = 7,
  R6 = 8,
  R7 = 9,
  R8 = 10,
  R9 = 11,
  R10 = 12,
  R11 = 13,
  R12 = 14,
  R13 = 15,
  R14 = 16,
  R15 = 17,
  R16 = 18,
  R17 = 19,
  R18 = 20,
  R19 = 21,
  R20 = 22,
  R21 = 23,
  R22 = 24,
  R23 = 25,
  R24 = 26,
  R25 = 27,
  R26 = 28,
  R27 = 29,
  R28 = 30,
  R29 = 31,
  R30 = 32,
  R31 = 33,
  R32 = 34,
  F0_32 = 35,
  F0_64 = 36,
  F0_128 = 37,
  F1_32 = 38,
  F1_64 = 39,
  F1_128 = 40,
  F2_32 = 41,
  F2_64 = 42,
  F2_128 = 43,
  F3_32 = 44,
  F3_64 = 45,
  F3_128 = 46,
  F4_32 = 47,
  F4_64 = 48,
  F4_128 = 49,
  F5_32 = 50,
  F5_64 = 51,
  F5_128 = 52,
  F6_32 = 53,
  F6_64 = 54,
  F6_128 = 55,
  F7_32 = 56,
  F7_64 = 57,
  F7_128 = 58,
  F8_32 = 59,
  F8_64 = 60,
  F8_128 = 61,
  F9_32 = 62,
  F9_64 = 63,
  F9_128 = 64,
  F10_32 = 65,
  F10_64 = 66,
  F10_128 = 67,
  F11_32 = 68,
  F11_64 = 69,
  F11_128 = 70,
  F12_32 = 71,
  F12_64 = 72,
  F12_128 = 73,
  F13_32 = 74,
  F13_64 = 75,
  F13_128 = 76,
  F14_32 = 77,
  F14_64 = 78,
  F14_128 = 79,
  F15_32 = 80,
  F15_64 = 81,
  F15_128 = 82,
  F16_32 = 83,
  F16_64 = 84,
  F16_128 = 85,
  F17_32 = 86,
  F17_64 = 87,
  F17_128 = 88,
  F18_32 = 89,
  F18_64 = 90,
  F18_128 = 91,
  F19_32 = 92,
  F19_64 = 93,
  F19_128 = 94,
  F20_32 = 95,
  F20_64 = 96,
  F20_128 = 97,
  F21_32 = 98,
  F21_64 = 99,
  F21_128 = 100,
  F22_32 = 101,
  F22_64 = 102,
  F22_128 = 103,
  F23_32 = 104,
  F23_64 = 105,
  F23_128 = 106,
  F24_32 = 107,
  F24_64 = 108,
  F24_128 = 109,
  F25_32 = 110,
  F25_64 = 111,
  F25_128 = 112,
  F26_32 = 113,
  F26_64 = 114,
  F26_128 = 115,
  F27_32 = 116,
  F27_64 = 117,
  F27_128 = 118,
  F28_32 = 119,
  F28_64 = 120,
  F28_128 = 121,
  F29_32 = 122,
  F29_64 = 123,
  F29_128 = 124,
  F30_32 = 125,
  F30_64 = 126,
  F30_128 = 127,
  F31_32 = 128,
  F31_64 = 129,
  F31_128 = 130,
  R0_R1 = 131,
  R1_R2 = 132,
  R2_R3 = 133,
  R3_R4 = 134,
  R4_R5 = 135,
  R5_R6 = 136,
  R6_R7 = 137,
  R7_R8 = 138,
  R8_R9 = 139,
  R9_R10 = 140,
  R10_R11 = 141,
  R11_R12 = 142,
  R12_R13 = 143,
  R13_R14 = 144,
  R14_R15 = 145,
  R15_R16 = 146,
  R16_R17 = 147,
  R17_R18 = 148,
  R18_R19 = 149,
  R19_R20 = 150,
  R20_R21 = 151,
  R21_R22 = 152,
  R22_R23 = 153,
  R23_R24 = 154,
  R24_R25 = 155,
  R25_R26 = 156,
  R26_R27 = 157,
  R27_R28 = 158,
  R28_R29 = 159,
  R29_R30 = 160,
  R30_R31 = 161,
  R31_R32 = 162,
  NUM_TARGET_REGS // 163
};

} // namespace CSKY

// Register classes

namespace CSKY {

enum {
  FPR32RegClassID = 0,
  GPRRegClassID = 1,
  sFPR32RegClassID = 2,
  sGPRRegClassID = 3,
  mGPRRegClassID = 4,
  CARRYRegClassID = 5,
  GPRSPRegClassID = 6,
  FPR64RegClassID = 7,
  GPRPairRegClassID = 8,
  GPRPair_with_sub32_32_in_GPRRegClassID = 9,
  GPRPair_with_sub32_0_in_sGPRRegClassID = 10,
  sFPR64RegClassID = 11,
  sFPR64_VRegClassID = 12,
  GPRPair_with_sub32_32_in_sGPRRegClassID = 13,
  GPRPair_with_sub32_0_in_mGPRRegClassID = 14,
  GPRPair_with_sub32_32_in_mGPRRegClassID = 15,
  GPRPair_with_sub32_0_in_GPRSPRegClassID = 16,
  GPRPair_with_sub32_32_in_GPRSPRegClassID = 17,
  FPR128RegClassID = 18,
  sFPR128RegClassID = 19,

};

} // namespace CSKY

// Register alternate name indices

namespace CSKY {

enum {
  ABIRegAltName,	// 0
  NoRegAltName,	// 1
  NUM_TARGET_REG_ALT_NAMES = 2
};

} // namespace CSKY

// Subregister indices

namespace CSKY {

enum : uint16_t {
  NoSubRegister,
  sub32_0,	// 1
  sub32_32,	// 2
  sub64_0,	// 3
  sub64_64,	// 4
  NUM_TARGET_SUBREGS
};

} // namespace CSKY
// Register pressure sets enum.
namespace CSKY {

enum RegisterPressureSets {
  CARRY = 0,
  GPRSP = 1,
  mGPR = 2,
  sFPR32 = 3,
  sGPR = 4,
  FPR32 = 5,
  GPR = 6,
};

} // namespace CSKY

} // namespace llvm_ks
