/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getLoongArchMCRegisterClass(unsigned RC);
namespace LoongArch {

enum : unsigned {
  NoRegister,
  F0 = 1,
  F1 = 2,
  F2 = 3,
  F3 = 4,
  F4 = 5,
  F5 = 6,
  F6 = 7,
  F7 = 8,
  F8 = 9,
  F9 = 10,
  F10 = 11,
  F11 = 12,
  F12 = 13,
  F13 = 14,
  F14 = 15,
  F15 = 16,
  F16 = 17,
  F17 = 18,
  F18 = 19,
  F19 = 20,
  F20 = 21,
  F21 = 22,
  F22 = 23,
  F23 = 24,
  F24 = 25,
  F25 = 26,
  F26 = 27,
  F27 = 28,
  F28 = 29,
  F29 = 30,
  F30 = 31,
  F31 = 32,
  FCC0 = 33,
  FCC1 = 34,
  FCC2 = 35,
  FCC3 = 36,
  FCC4 = 37,
  FCC5 = 38,
  FCC6 = 39,
  FCC7 = 40,
  FCSR0 = 41,
  FCSR1 = 42,
  FCSR2 = 43,
  FCSR3 = 44,
  R0 = 45,
  R1 = 46,
  R2 = 47,
  R3 = 48,
  R4 = 49,
  R5 = 50,
  R6 = 51,
  R7 = 52,
  R8 = 53,
  R9 = 54,
  R10 = 55,
  R11 = 56,
  R12 = 57,
  R13 = 58,
  R14 = 59,
  R15 = 60,
  R16 = 61,
  R17 = 62,
  R18 = 63,
  R19 = 64,
  R20 = 65,
  R21 = 66,
  R22 = 67,
  R23 = 68,
  R24 = 69,
  R25 = 70,
  R26 = 71,
  R27 = 72,
  R28 = 73,
  R29 = 74,
  R30 = 75,
  R31 = 76,
  SCR0 = 77,
  SCR1 = 78,
  SCR2 = 79,
  SCR3 = 80,
  VR0 = 81,
  VR1 = 82,
  VR2 = 83,
  VR3 = 84,
  VR4 = 85,
  VR5 = 86,
  VR6 = 87,
  VR7 = 88,
  VR8 = 89,
  VR9 = 90,
  VR10 = 91,
  VR11 = 92,
  VR12 = 93,
  VR13 = 94,
  VR14 = 95,
  VR15 = 96,
  VR16 = 97,
  VR17 = 98,
  VR18 = 99,
  VR19 = 100,
  VR20 = 101,
  VR21 = 102,
  VR22 = 103,
  VR23 = 104,
  VR24 = 105,
  VR25 = 106,
  VR26 = 107,
  VR27 = 108,
  VR28 = 109,
  VR29 = 110,
  VR30 = 111,
  VR31 = 112,
  XR0 = 113,
  XR1 = 114,
  XR2 = 115,
  XR3 = 116,
  XR4 = 117,
  XR5 = 118,
  XR6 = 119,
  XR7 = 120,
  XR8 = 121,
  XR9 = 122,
  XR10 = 123,
  XR11 = 124,
  XR12 = 125,
  XR13 = 126,
  XR14 = 127,
  XR15 = 128,
  XR16 = 129,
  XR17 = 130,
  XR18 = 131,
  XR19 = 132,
  XR20 = 133,
  XR21 = 134,
  XR22 = 135,
  XR23 = 136,
  XR24 = 137,
  XR25 = 138,
  XR26 = 139,
  XR27 = 140,
  XR28 = 141,
  XR29 = 142,
  XR30 = 143,
  XR31 = 144,
  F0_64 = 145,
  F1_64 = 146,
  F2_64 = 147,
  F3_64 = 148,
  F4_64 = 149,
  F5_64 = 150,
  F6_64 = 151,
  F7_64 = 152,
  F8_64 = 153,
  F9_64 = 154,
  F10_64 = 155,
  F11_64 = 156,
  F12_64 = 157,
  F13_64 = 158,
  F14_64 = 159,
  F15_64 = 160,
  F16_64 = 161,
  F17_64 = 162,
  F18_64 = 163,
  F19_64 = 164,
  F20_64 = 165,
  F21_64 = 166,
  F22_64 = 167,
  F23_64 = 168,
  F24_64 = 169,
  F25_64 = 170,
  F26_64 = 171,
  F27_64 = 172,
  F28_64 = 173,
  F29_64 = 174,
  F30_64 = 175,
  F31_64 = 176,
  NUM_TARGET_REGS // 177
};

} // namespace LoongArch

// Register classes

namespace LoongArch {

enum {
  FPR32RegClassID = 0,
  GPRRegClassID = 1,
  GPRJRRegClassID = 2,
  GPRNoR0R1RegClassID = 3,
  GPRTRegClassID = 4,
  CFRRegClassID = 5,
  FCSRRegClassID = 6,
  SCRRegClassID = 7,
  FPR64RegClassID = 8,
  LSX128RegClassID = 9,
  LASX256RegClassID = 10,

};

} // namespace LoongArch

// Register alternate name indices

namespace LoongArch {

enum {
  NoRegAltName,	// 0
  RegAliasName,	// 1
  NUM_TARGET_REG_ALT_NAMES = 2
};

} // namespace LoongArch

// Subregister indices

namespace LoongArch {

enum : uint16_t {
  NoSubRegister,
  sub_32,	// 1
  sub_64,	// 2
  sub_128,	// 3
  NUM_TARGET_SUBREGS
};

} // namespace LoongArch
// Register pressure sets enum.
namespace LoongArch {

enum RegisterPressureSets {
  CFR = 0,
  GPRT = 1,
  FPR32 = 2,
  GPR = 3,
};

} // namespace LoongArch

} // namespace llvm_ks
