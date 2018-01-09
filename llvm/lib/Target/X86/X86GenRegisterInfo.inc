/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM
namespace llvm_ks {

class MCRegisterClass;
extern const MCRegisterClass X86MCRegisterClasses[];

namespace X86 {
enum {
  NoRegister,
  AH = 1,
  AL = 2,
  AX = 3,
  BH = 4,
  BL = 5,
  BP = 6,
  BPL = 7,
  BX = 8,
  CH = 9,
  CL = 10,
  CS = 11,
  CX = 12,
  DH = 13,
  DI = 14,
  DIL = 15,
  DL = 16,
  DS = 17,
  DX = 18,
  EAX = 19,
  EBP = 20,
  EBX = 21,
  ECX = 22,
  EDI = 23,
  EDX = 24,
  EFLAGS = 25,
  EIP = 26,
  EIZ = 27,
  ES = 28,
  ESI = 29,
  ESP = 30,
  FPSW = 31,
  FS = 32,
  GS = 33,
  IP = 34,
  RAX = 35,
  RBP = 36,
  RBX = 37,
  RCX = 38,
  RDI = 39,
  RDX = 40,
  RIP = 41,
  RIZ = 42,
  RSI = 43,
  RSP = 44,
  SI = 45,
  SIL = 46,
  SP = 47,
  SPL = 48,
  SS = 49,
  BND0 = 50,
  BND1 = 51,
  BND2 = 52,
  BND3 = 53,
  CR0 = 54,
  CR1 = 55,
  CR2 = 56,
  CR3 = 57,
  CR4 = 58,
  CR5 = 59,
  CR6 = 60,
  CR7 = 61,
  CR8 = 62,
  CR9 = 63,
  CR10 = 64,
  CR11 = 65,
  CR12 = 66,
  CR13 = 67,
  CR14 = 68,
  CR15 = 69,
  DR0 = 70,
  DR1 = 71,
  DR2 = 72,
  DR3 = 73,
  DR4 = 74,
  DR5 = 75,
  DR6 = 76,
  DR7 = 77,
  DR8 = 78,
  DR9 = 79,
  DR10 = 80,
  DR11 = 81,
  DR12 = 82,
  DR13 = 83,
  DR14 = 84,
  DR15 = 85,
  FP0 = 86,
  FP1 = 87,
  FP2 = 88,
  FP3 = 89,
  FP4 = 90,
  FP5 = 91,
  FP6 = 92,
  FP7 = 93,
  K0 = 94,
  K1 = 95,
  K2 = 96,
  K3 = 97,
  K4 = 98,
  K5 = 99,
  K6 = 100,
  K7 = 101,
  MM0 = 102,
  MM1 = 103,
  MM2 = 104,
  MM3 = 105,
  MM4 = 106,
  MM5 = 107,
  MM6 = 108,
  MM7 = 109,
  R8 = 110,
  R9 = 111,
  R10 = 112,
  R11 = 113,
  R12 = 114,
  R13 = 115,
  R14 = 116,
  R15 = 117,
  ST0 = 118,
  ST1 = 119,
  ST2 = 120,
  ST3 = 121,
  ST4 = 122,
  ST5 = 123,
  ST6 = 124,
  ST7 = 125,
  XMM0 = 126,
  XMM1 = 127,
  XMM2 = 128,
  XMM3 = 129,
  XMM4 = 130,
  XMM5 = 131,
  XMM6 = 132,
  XMM7 = 133,
  XMM8 = 134,
  XMM9 = 135,
  XMM10 = 136,
  XMM11 = 137,
  XMM12 = 138,
  XMM13 = 139,
  XMM14 = 140,
  XMM15 = 141,
  XMM16 = 142,
  XMM17 = 143,
  XMM18 = 144,
  XMM19 = 145,
  XMM20 = 146,
  XMM21 = 147,
  XMM22 = 148,
  XMM23 = 149,
  XMM24 = 150,
  XMM25 = 151,
  XMM26 = 152,
  XMM27 = 153,
  XMM28 = 154,
  XMM29 = 155,
  XMM30 = 156,
  XMM31 = 157,
  YMM0 = 158,
  YMM1 = 159,
  YMM2 = 160,
  YMM3 = 161,
  YMM4 = 162,
  YMM5 = 163,
  YMM6 = 164,
  YMM7 = 165,
  YMM8 = 166,
  YMM9 = 167,
  YMM10 = 168,
  YMM11 = 169,
  YMM12 = 170,
  YMM13 = 171,
  YMM14 = 172,
  YMM15 = 173,
  YMM16 = 174,
  YMM17 = 175,
  YMM18 = 176,
  YMM19 = 177,
  YMM20 = 178,
  YMM21 = 179,
  YMM22 = 180,
  YMM23 = 181,
  YMM24 = 182,
  YMM25 = 183,
  YMM26 = 184,
  YMM27 = 185,
  YMM28 = 186,
  YMM29 = 187,
  YMM30 = 188,
  YMM31 = 189,
  ZMM0 = 190,
  ZMM1 = 191,
  ZMM2 = 192,
  ZMM3 = 193,
  ZMM4 = 194,
  ZMM5 = 195,
  ZMM6 = 196,
  ZMM7 = 197,
  ZMM8 = 198,
  ZMM9 = 199,
  ZMM10 = 200,
  ZMM11 = 201,
  ZMM12 = 202,
  ZMM13 = 203,
  ZMM14 = 204,
  ZMM15 = 205,
  ZMM16 = 206,
  ZMM17 = 207,
  ZMM18 = 208,
  ZMM19 = 209,
  ZMM20 = 210,
  ZMM21 = 211,
  ZMM22 = 212,
  ZMM23 = 213,
  ZMM24 = 214,
  ZMM25 = 215,
  ZMM26 = 216,
  ZMM27 = 217,
  ZMM28 = 218,
  ZMM29 = 219,
  ZMM30 = 220,
  ZMM31 = 221,
  R8B = 222,
  R9B = 223,
  R10B = 224,
  R11B = 225,
  R12B = 226,
  R13B = 227,
  R14B = 228,
  R15B = 229,
  R8D = 230,
  R9D = 231,
  R10D = 232,
  R11D = 233,
  R12D = 234,
  R13D = 235,
  R14D = 236,
  R15D = 237,
  R8W = 238,
  R9W = 239,
  R10W = 240,
  R11W = 241,
  R12W = 242,
  R13W = 243,
  R14W = 244,
  R15W = 245,
  NUM_TARGET_REGS 	// 246
};
}

// Register classes
namespace X86 {
enum {
  GR8RegClassID = 0,
  GR8_NOREXRegClassID = 1,
  VK1RegClassID = 2,
  VK2RegClassID = 3,
  VK4RegClassID = 4,
  VK8RegClassID = 5,
  VK1WMRegClassID = 6,
  VK2WMRegClassID = 7,
  VK4WMRegClassID = 8,
  VK8WMRegClassID = 9,
  GR8_ABCD_HRegClassID = 10,
  GR8_ABCD_LRegClassID = 11,
  GR16RegClassID = 12,
  GR16_NOREXRegClassID = 13,
  VK16RegClassID = 14,
  VK16WMRegClassID = 15,
  SEGMENT_REGRegClassID = 16,
  GR16_ABCDRegClassID = 17,
  FPCCRRegClassID = 18,
  FR32XRegClassID = 19,
  FR32RegClassID = 20,
  GR32RegClassID = 21,
  GR32_NOAXRegClassID = 22,
  GR32_NOSPRegClassID = 23,
  GR32_NOAX_and_GR32_NOSPRegClassID = 24,
  DEBUG_REGRegClassID = 25,
  GR32_NOREXRegClassID = 26,
  VK32RegClassID = 27,
  GR32_NOAX_and_GR32_NOREXRegClassID = 28,
  GR32_NOREX_NOSPRegClassID = 29,
  RFP32RegClassID = 30,
  VK32WMRegClassID = 31,
  GR32_NOAX_and_GR32_NOREX_NOSPRegClassID = 32,
  GR32_ABCDRegClassID = 33,
  GR32_ABCD_and_GR32_NOAXRegClassID = 34,
  GR32_TCRegClassID = 35,
  GR32_ADRegClassID = 36,
  GR32_NOAX_and_GR32_TCRegClassID = 37,
  CCRRegClassID = 38,
  GR32_AD_and_GR32_NOAXRegClassID = 39,
  RFP64RegClassID = 40,
  FR64XRegClassID = 41,
  GR64RegClassID = 42,
  CONTROL_REGRegClassID = 43,
  FR64RegClassID = 44,
  GR64_with_sub_8bitRegClassID = 45,
  GR64_NOSPRegClassID = 46,
  GR64_with_sub_32bit_in_GR32_NOAXRegClassID = 47,
  GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPRegClassID = 48,
  GR64_NOREXRegClassID = 49,
  GR64_TCRegClassID = 50,
  GR64_NOSP_and_GR64_TCRegClassID = 51,
  GR64_TCW64RegClassID = 52,
  GR64_with_sub_16bit_in_GR16_NOREXRegClassID = 53,
  VK64RegClassID = 54,
  VR64RegClassID = 55,
  GR64_NOREX_NOSPRegClassID = 56,
  GR64_NOSP_and_GR64_TCW64RegClassID = 57,
  GR64_TC_and_GR64_TCW64RegClassID = 58,
  GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID = 59,
  GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXRegClassID = 60,
  VK64WMRegClassID = 61,
  GR64_NOREX_and_GR64_TCRegClassID = 62,
  GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID = 63,
  GR64_TC_and_GR64_NOSP_and_GR64_TCW64RegClassID = 64,
  GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPRegClassID = 65,
  GR64_NOREX_NOSP_and_GR64_TCRegClassID = 66,
  GR64_TCW64_and_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID = 67,
  GR64_ABCDRegClassID = 68,
  GR64_NOREX_and_GR64_TCW64RegClassID = 69,
  GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXRegClassID = 70,
  GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXRegClassID = 71,
  GR64_with_sub_32bit_in_GR32_TCRegClassID = 72,
  GR64_with_sub_32bit_in_GR32_ADRegClassID = 73,
  GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCRegClassID = 74,
  GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXRegClassID = 75,
  RSTRegClassID = 76,
  RFP80RegClassID = 77,
  VR128XRegClassID = 78,
  FR128RegClassID = 79,
  VR128RegClassID = 80,
  BNDRRegClassID = 81,
  VR256XRegClassID = 82,
  VR256RegClassID = 83,
  VR512RegClassID = 84,
  VR512_with_sub_xmm_in_FR128RegClassID = 85,

  };
}

} // End llvm namespace
#endif // GET_REGINFO_ENUM

/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC
namespace llvm_ks {

extern const MCPhysReg X86RegDiffLists[] = {
  /* 0 */ 0, 1, 0,
  /* 3 */ 2, 1, 0,
  /* 6 */ 5, 1, 0,
  /* 9 */ 65522, 16, 1, 0,
  /* 13 */ 65522, 17, 1, 0,
  /* 17 */ 65427, 1, 0,
  /* 20 */ 65475, 1, 0,
  /* 23 */ 65520, 65522, 1, 0,
  /* 27 */ 65520, 65527, 1, 0,
  /* 31 */ 8, 2, 0,
  /* 34 */ 4, 0,
  /* 36 */ 65521, 8, 0,
  /* 39 */ 9, 0,
  /* 41 */ 13, 0,
  /* 43 */ 65535, 65519, 14, 0,
  /* 47 */ 65535, 65520, 14, 0,
  /* 51 */ 65528, 15, 0,
  /* 54 */ 2, 6, 16, 0,
  /* 58 */ 5, 6, 16, 0,
  /* 62 */ 65535, 9, 16, 0,
  /* 66 */ 2, 10, 16, 0,
  /* 70 */ 3, 10, 16, 0,
  /* 74 */ 3, 13, 16, 0,
  /* 78 */ 4, 13, 16, 0,
  /* 82 */ 65535, 14, 16, 0,
  /* 86 */ 1, 16, 16, 0,
  /* 90 */ 2, 16, 16, 0,
  /* 94 */ 17, 0,
  /* 96 */ 32, 32, 0,
  /* 99 */ 65221, 0,
  /* 101 */ 65381, 0,
  /* 103 */ 65389, 0,
  /* 105 */ 65397, 0,
  /* 107 */ 16, 65528, 65416, 0,
  /* 111 */ 65445, 0,
  /* 113 */ 65477, 0,
  /* 115 */ 65504, 65504, 0,
  /* 118 */ 65509, 0,
  /* 120 */ 120, 8, 65520, 0,
  /* 124 */ 65523, 0,
  /* 126 */ 65530, 0,
  /* 128 */ 65531, 0,
  /* 130 */ 65532, 0,
  /* 132 */ 65520, 65530, 65534, 65533, 0,
  /* 137 */ 65534, 0,
  /* 139 */ 65520, 65523, 65533, 65535, 0,
  /* 144 */ 65520, 65526, 65534, 65535, 0,
  /* 149 */ 65520, 65520, 65535, 65535, 0,
};

extern const unsigned X86LaneMaskLists[] = {
  /* 0 */ 0x00000000, ~0u,
  /* 2 */ 0x00000002, 0x00000001, ~0u,
  /* 5 */ 0x00000003, ~0u,
  /* 7 */ 0x00000004, ~0u,
};

extern const uint16_t X86SubRegIdxLists[] = {
  /* 0 */ 4, 3, 1, 0,
  /* 4 */ 4, 3, 1, 2, 0,
  /* 9 */ 4, 3, 0,
  /* 12 */ 6, 5, 0,
};

extern const MCRegisterInfo::SubRegCoveredBits X86SubRegIdxRanges[] = {
  { 65535, 65535 },
  { 0, 8 },	// sub_8bit
  { 8, 8 },	// sub_8bit_hi
  { 0, 16 },	// sub_16bit
  { 0, 32 },	// sub_32bit
  { 0, 128 },	// sub_xmm
  { 0, 256 },	// sub_ymm
};

extern const char X86RegStrings[] = {
  /* 0 */ 'X', 'M', 'M', '1', '0', 0,
  /* 6 */ 'Y', 'M', 'M', '1', '0', 0,
  /* 12 */ 'Z', 'M', 'M', '1', '0', 0,
  /* 18 */ 'C', 'R', '1', '0', 0,
  /* 23 */ 'D', 'R', '1', '0', 0,
  /* 28 */ 'X', 'M', 'M', '2', '0', 0,
  /* 34 */ 'Y', 'M', 'M', '2', '0', 0,
  /* 40 */ 'Z', 'M', 'M', '2', '0', 0,
  /* 46 */ 'X', 'M', 'M', '3', '0', 0,
  /* 52 */ 'Y', 'M', 'M', '3', '0', 0,
  /* 58 */ 'Z', 'M', 'M', '3', '0', 0,
  /* 64 */ 'B', 'N', 'D', '0', 0,
  /* 69 */ 'K', '0', 0,
  /* 72 */ 'X', 'M', 'M', '0', 0,
  /* 77 */ 'Y', 'M', 'M', '0', 0,
  /* 82 */ 'Z', 'M', 'M', '0', 0,
  /* 87 */ 'F', 'P', '0', 0,
  /* 91 */ 'C', 'R', '0', 0,
  /* 95 */ 'D', 'R', '0', 0,
  /* 99 */ 'S', 'T', '0', 0,
  /* 103 */ 'X', 'M', 'M', '1', '1', 0,
  /* 109 */ 'Y', 'M', 'M', '1', '1', 0,
  /* 115 */ 'Z', 'M', 'M', '1', '1', 0,
  /* 121 */ 'C', 'R', '1', '1', 0,
  /* 126 */ 'D', 'R', '1', '1', 0,
  /* 131 */ 'X', 'M', 'M', '2', '1', 0,
  /* 137 */ 'Y', 'M', 'M', '2', '1', 0,
  /* 143 */ 'Z', 'M', 'M', '2', '1', 0,
  /* 149 */ 'X', 'M', 'M', '3', '1', 0,
  /* 155 */ 'Y', 'M', 'M', '3', '1', 0,
  /* 161 */ 'Z', 'M', 'M', '3', '1', 0,
  /* 167 */ 'B', 'N', 'D', '1', 0,
  /* 172 */ 'K', '1', 0,
  /* 175 */ 'X', 'M', 'M', '1', 0,
  /* 180 */ 'Y', 'M', 'M', '1', 0,
  /* 185 */ 'Z', 'M', 'M', '1', 0,
  /* 190 */ 'F', 'P', '1', 0,
  /* 194 */ 'C', 'R', '1', 0,
  /* 198 */ 'D', 'R', '1', 0,
  /* 202 */ 'S', 'T', '1', 0,
  /* 206 */ 'X', 'M', 'M', '1', '2', 0,
  /* 212 */ 'Y', 'M', 'M', '1', '2', 0,
  /* 218 */ 'Z', 'M', 'M', '1', '2', 0,
  /* 224 */ 'C', 'R', '1', '2', 0,
  /* 229 */ 'D', 'R', '1', '2', 0,
  /* 234 */ 'X', 'M', 'M', '2', '2', 0,
  /* 240 */ 'Y', 'M', 'M', '2', '2', 0,
  /* 246 */ 'Z', 'M', 'M', '2', '2', 0,
  /* 252 */ 'B', 'N', 'D', '2', 0,
  /* 257 */ 'K', '2', 0,
  /* 260 */ 'X', 'M', 'M', '2', 0,
  /* 265 */ 'Y', 'M', 'M', '2', 0,
  /* 270 */ 'Z', 'M', 'M', '2', 0,
  /* 275 */ 'F', 'P', '2', 0,
  /* 279 */ 'C', 'R', '2', 0,
  /* 283 */ 'D', 'R', '2', 0,
  /* 287 */ 'S', 'T', '2', 0,
  /* 291 */ 'X', 'M', 'M', '1', '3', 0,
  /* 297 */ 'Y', 'M', 'M', '1', '3', 0,
  /* 303 */ 'Z', 'M', 'M', '1', '3', 0,
  /* 309 */ 'C', 'R', '1', '3', 0,
  /* 314 */ 'D', 'R', '1', '3', 0,
  /* 319 */ 'X', 'M', 'M', '2', '3', 0,
  /* 325 */ 'Y', 'M', 'M', '2', '3', 0,
  /* 331 */ 'Z', 'M', 'M', '2', '3', 0,
  /* 337 */ 'B', 'N', 'D', '3', 0,
  /* 342 */ 'K', '3', 0,
  /* 345 */ 'X', 'M', 'M', '3', 0,
  /* 350 */ 'Y', 'M', 'M', '3', 0,
  /* 355 */ 'Z', 'M', 'M', '3', 0,
  /* 360 */ 'F', 'P', '3', 0,
  /* 364 */ 'C', 'R', '3', 0,
  /* 368 */ 'D', 'R', '3', 0,
  /* 372 */ 'S', 'T', '3', 0,
  /* 376 */ 'X', 'M', 'M', '1', '4', 0,
  /* 382 */ 'Y', 'M', 'M', '1', '4', 0,
  /* 388 */ 'Z', 'M', 'M', '1', '4', 0,
  /* 394 */ 'C', 'R', '1', '4', 0,
  /* 399 */ 'D', 'R', '1', '4', 0,
  /* 404 */ 'X', 'M', 'M', '2', '4', 0,
  /* 410 */ 'Y', 'M', 'M', '2', '4', 0,
  /* 416 */ 'Z', 'M', 'M', '2', '4', 0,
  /* 422 */ 'K', '4', 0,
  /* 425 */ 'X', 'M', 'M', '4', 0,
  /* 430 */ 'Y', 'M', 'M', '4', 0,
  /* 435 */ 'Z', 'M', 'M', '4', 0,
  /* 440 */ 'F', 'P', '4', 0,
  /* 444 */ 'C', 'R', '4', 0,
  /* 448 */ 'D', 'R', '4', 0,
  /* 452 */ 'S', 'T', '4', 0,
  /* 456 */ 'X', 'M', 'M', '1', '5', 0,
  /* 462 */ 'Y', 'M', 'M', '1', '5', 0,
  /* 468 */ 'Z', 'M', 'M', '1', '5', 0,
  /* 474 */ 'C', 'R', '1', '5', 0,
  /* 479 */ 'D', 'R', '1', '5', 0,
  /* 484 */ 'X', 'M', 'M', '2', '5', 0,
  /* 490 */ 'Y', 'M', 'M', '2', '5', 0,
  /* 496 */ 'Z', 'M', 'M', '2', '5', 0,
  /* 502 */ 'K', '5', 0,
  /* 505 */ 'X', 'M', 'M', '5', 0,
  /* 510 */ 'Y', 'M', 'M', '5', 0,
  /* 515 */ 'Z', 'M', 'M', '5', 0,
  /* 520 */ 'F', 'P', '5', 0,
  /* 524 */ 'C', 'R', '5', 0,
  /* 528 */ 'D', 'R', '5', 0,
  /* 532 */ 'S', 'T', '5', 0,
  /* 536 */ 'X', 'M', 'M', '1', '6', 0,
  /* 542 */ 'Y', 'M', 'M', '1', '6', 0,
  /* 548 */ 'Z', 'M', 'M', '1', '6', 0,
  /* 554 */ 'X', 'M', 'M', '2', '6', 0,
  /* 560 */ 'Y', 'M', 'M', '2', '6', 0,
  /* 566 */ 'Z', 'M', 'M', '2', '6', 0,
  /* 572 */ 'K', '6', 0,
  /* 575 */ 'X', 'M', 'M', '6', 0,
  /* 580 */ 'Y', 'M', 'M', '6', 0,
  /* 585 */ 'Z', 'M', 'M', '6', 0,
  /* 590 */ 'F', 'P', '6', 0,
  /* 594 */ 'C', 'R', '6', 0,
  /* 598 */ 'D', 'R', '6', 0,
  /* 602 */ 'S', 'T', '6', 0,
  /* 606 */ 'X', 'M', 'M', '1', '7', 0,
  /* 612 */ 'Y', 'M', 'M', '1', '7', 0,
  /* 618 */ 'Z', 'M', 'M', '1', '7', 0,
  /* 624 */ 'X', 'M', 'M', '2', '7', 0,
  /* 630 */ 'Y', 'M', 'M', '2', '7', 0,
  /* 636 */ 'Z', 'M', 'M', '2', '7', 0,
  /* 642 */ 'K', '7', 0,
  /* 645 */ 'X', 'M', 'M', '7', 0,
  /* 650 */ 'Y', 'M', 'M', '7', 0,
  /* 655 */ 'Z', 'M', 'M', '7', 0,
  /* 660 */ 'F', 'P', '7', 0,
  /* 664 */ 'C', 'R', '7', 0,
  /* 668 */ 'D', 'R', '7', 0,
  /* 672 */ 'S', 'T', '7', 0,
  /* 676 */ 'X', 'M', 'M', '1', '8', 0,
  /* 682 */ 'Y', 'M', 'M', '1', '8', 0,
  /* 688 */ 'Z', 'M', 'M', '1', '8', 0,
  /* 694 */ 'X', 'M', 'M', '2', '8', 0,
  /* 700 */ 'Y', 'M', 'M', '2', '8', 0,
  /* 706 */ 'Z', 'M', 'M', '2', '8', 0,
  /* 712 */ 'X', 'M', 'M', '8', 0,
  /* 717 */ 'Y', 'M', 'M', '8', 0,
  /* 722 */ 'Z', 'M', 'M', '8', 0,
  /* 727 */ 'C', 'R', '8', 0,
  /* 731 */ 'D', 'R', '8', 0,
  /* 735 */ 'X', 'M', 'M', '1', '9', 0,
  /* 741 */ 'Y', 'M', 'M', '1', '9', 0,
  /* 747 */ 'Z', 'M', 'M', '1', '9', 0,
  /* 753 */ 'X', 'M', 'M', '2', '9', 0,
  /* 759 */ 'Y', 'M', 'M', '2', '9', 0,
  /* 765 */ 'Z', 'M', 'M', '2', '9', 0,
  /* 771 */ 'X', 'M', 'M', '9', 0,
  /* 776 */ 'Y', 'M', 'M', '9', 0,
  /* 781 */ 'Z', 'M', 'M', '9', 0,
  /* 786 */ 'C', 'R', '9', 0,
  /* 790 */ 'D', 'R', '9', 0,
  /* 794 */ 'R', '1', '0', 'B', 0,
  /* 799 */ 'R', '1', '1', 'B', 0,
  /* 804 */ 'R', '1', '2', 'B', 0,
  /* 809 */ 'R', '1', '3', 'B', 0,
  /* 814 */ 'R', '1', '4', 'B', 0,
  /* 819 */ 'R', '1', '5', 'B', 0,
  /* 824 */ 'R', '8', 'B', 0,
  /* 828 */ 'R', '9', 'B', 0,
  /* 832 */ 'R', '1', '0', 'D', 0,
  /* 837 */ 'R', '1', '1', 'D', 0,
  /* 842 */ 'R', '1', '2', 'D', 0,
  /* 847 */ 'R', '1', '3', 'D', 0,
  /* 852 */ 'R', '1', '4', 'D', 0,
  /* 857 */ 'R', '1', '5', 'D', 0,
  /* 862 */ 'R', '8', 'D', 0,
  /* 866 */ 'R', '9', 'D', 0,
  /* 870 */ 'A', 'H', 0,
  /* 873 */ 'B', 'H', 0,
  /* 876 */ 'C', 'H', 0,
  /* 879 */ 'D', 'H', 0,
  /* 882 */ 'E', 'D', 'I', 0,
  /* 886 */ 'R', 'D', 'I', 0,
  /* 890 */ 'E', 'S', 'I', 0,
  /* 894 */ 'R', 'S', 'I', 0,
  /* 898 */ 'A', 'L', 0,
  /* 901 */ 'B', 'L', 0,
  /* 904 */ 'C', 'L', 0,
  /* 907 */ 'D', 'L', 0,
  /* 910 */ 'D', 'I', 'L', 0,
  /* 914 */ 'S', 'I', 'L', 0,
  /* 918 */ 'B', 'P', 'L', 0,
  /* 922 */ 'S', 'P', 'L', 0,
  /* 926 */ 'E', 'B', 'P', 0,
  /* 930 */ 'R', 'B', 'P', 0,
  /* 934 */ 'E', 'I', 'P', 0,
  /* 938 */ 'R', 'I', 'P', 0,
  /* 942 */ 'E', 'S', 'P', 0,
  /* 946 */ 'R', 'S', 'P', 0,
  /* 950 */ 'C', 'S', 0,
  /* 953 */ 'D', 'S', 0,
  /* 956 */ 'E', 'S', 0,
  /* 959 */ 'F', 'S', 0,
  /* 962 */ 'E', 'F', 'L', 'A', 'G', 'S', 0,
  /* 969 */ 'S', 'S', 0,
  /* 972 */ 'R', '1', '0', 'W', 0,
  /* 977 */ 'R', '1', '1', 'W', 0,
  /* 982 */ 'R', '1', '2', 'W', 0,
  /* 987 */ 'R', '1', '3', 'W', 0,
  /* 992 */ 'R', '1', '4', 'W', 0,
  /* 997 */ 'R', '1', '5', 'W', 0,
  /* 1002 */ 'R', '8', 'W', 0,
  /* 1006 */ 'R', '9', 'W', 0,
  /* 1010 */ 'F', 'P', 'S', 'W', 0,
  /* 1015 */ 'E', 'A', 'X', 0,
  /* 1019 */ 'R', 'A', 'X', 0,
  /* 1023 */ 'E', 'B', 'X', 0,
  /* 1027 */ 'R', 'B', 'X', 0,
  /* 1031 */ 'E', 'C', 'X', 0,
  /* 1035 */ 'R', 'C', 'X', 0,
  /* 1039 */ 'E', 'D', 'X', 0,
  /* 1043 */ 'R', 'D', 'X', 0,
  /* 1047 */ 'E', 'I', 'Z', 0,
  /* 1051 */ 'R', 'I', 'Z', 0,
};

extern const MCRegisterDesc X86RegDesc[] = { // Descriptors
  { 5, 0, 0, 0, 0, 0 },
  { 870, 2, 90, 3, 2273, 0 },
  { 898, 2, 86, 3, 2273, 0 },
  { 1016, 151, 87, 6, 0, 2 },
  { 873, 2, 78, 3, 2193, 0 },
  { 901, 2, 74, 3, 2193, 0 },
  { 927, 1, 83, 2, 544, 3 },
  { 918, 2, 82, 3, 544, 0 },
  { 1024, 141, 75, 6, 48, 2 },
  { 876, 2, 70, 3, 2081, 0 },
  { 904, 2, 66, 3, 2081, 0 },
  { 950, 2, 2, 3, 2081, 0 },
  { 1032, 146, 67, 6, 96, 2 },
  { 879, 2, 58, 3, 2049, 0 },
  { 883, 1, 63, 2, 624, 3 },
  { 910, 2, 62, 3, 624, 0 },
  { 907, 2, 54, 3, 2017, 0 },
  { 953, 2, 2, 3, 2017, 0 },
  { 1040, 134, 55, 6, 496, 2 },
  { 1015, 150, 56, 5, 0, 2 },
  { 926, 24, 56, 1, 544, 3 },
  { 1023, 140, 56, 5, 323, 2 },
  { 1031, 145, 56, 5, 323, 2 },
  { 882, 28, 56, 1, 624, 3 },
  { 1039, 133, 56, 5, 496, 2 },
  { 962, 2, 2, 3, 1985, 0 },
  { 934, 37, 52, 10, 1985, 5 },
  { 1047, 2, 2, 3, 1985, 0 },
  { 956, 2, 2, 3, 1985, 0 },
  { 890, 10, 45, 1, 1985, 3 },
  { 942, 14, 45, 1, 1985, 3 },
  { 1010, 2, 2, 3, 1985, 0 },
  { 959, 2, 2, 3, 1985, 0 },
  { 966, 2, 2, 3, 1985, 0 },
  { 935, 2, 51, 3, 656, 0 },
  { 1019, 149, 2, 4, 0, 2 },
  { 930, 23, 2, 0, 544, 3 },
  { 1027, 139, 2, 4, 275, 2 },
  { 1035, 144, 2, 4, 275, 2 },
  { 886, 27, 2, 0, 624, 3 },
  { 1043, 132, 2, 4, 496, 2 },
  { 938, 36, 2, 9, 1592, 5 },
  { 1051, 2, 2, 3, 1592, 0 },
  { 894, 9, 2, 0, 1889, 3 },
  { 946, 13, 2, 0, 1889, 3 },
  { 891, 1, 48, 2, 896, 3 },
  { 914, 2, 47, 3, 896, 0 },
  { 943, 1, 44, 2, 1504, 3 },
  { 922, 2, 43, 3, 1504, 0 },
  { 969, 2, 2, 3, 1889, 0 },
  { 64, 2, 2, 3, 1889, 0 },
  { 167, 2, 2, 3, 1889, 0 },
  { 252, 2, 2, 3, 1889, 0 },
  { 337, 2, 2, 3, 1889, 0 },
  { 91, 2, 2, 3, 1889, 0 },
  { 194, 2, 2, 3, 1889, 0 },
  { 279, 2, 2, 3, 1889, 0 },
  { 364, 2, 2, 3, 1889, 0 },
  { 444, 2, 2, 3, 1889, 0 },
  { 524, 2, 2, 3, 1889, 0 },
  { 594, 2, 2, 3, 1889, 0 },
  { 664, 2, 2, 3, 1889, 0 },
  { 727, 2, 2, 3, 1889, 0 },
  { 786, 2, 2, 3, 1889, 0 },
  { 18, 2, 2, 3, 1889, 0 },
  { 121, 2, 2, 3, 1889, 0 },
  { 224, 2, 2, 3, 1889, 0 },
  { 309, 2, 2, 3, 1889, 0 },
  { 394, 2, 2, 3, 1889, 0 },
  { 474, 2, 2, 3, 1889, 0 },
  { 95, 2, 2, 3, 1889, 0 },
  { 198, 2, 2, 3, 1889, 0 },
  { 283, 2, 2, 3, 1889, 0 },
  { 368, 2, 2, 3, 1889, 0 },
  { 448, 2, 2, 3, 1889, 0 },
  { 528, 2, 2, 3, 1889, 0 },
  { 598, 2, 2, 3, 1889, 0 },
  { 668, 2, 2, 3, 1889, 0 },
  { 731, 2, 2, 3, 1889, 0 },
  { 790, 2, 2, 3, 1889, 0 },
  { 23, 2, 2, 3, 1889, 0 },
  { 126, 2, 2, 3, 1889, 0 },
  { 229, 2, 2, 3, 1889, 0 },
  { 314, 2, 2, 3, 1889, 0 },
  { 399, 2, 2, 3, 1889, 0 },
  { 479, 2, 2, 3, 1889, 0 },
  { 87, 2, 2, 3, 1889, 0 },
  { 190, 2, 2, 3, 1889, 0 },
  { 275, 2, 2, 3, 1889, 0 },
  { 360, 2, 2, 3, 1889, 0 },
  { 440, 2, 2, 3, 1889, 0 },
  { 520, 2, 2, 3, 1889, 0 },
  { 590, 2, 2, 3, 1889, 0 },
  { 660, 2, 2, 3, 1889, 0 },
  { 69, 2, 2, 3, 1889, 0 },
  { 172, 2, 2, 3, 1889, 0 },
  { 257, 2, 2, 3, 1889, 0 },
  { 342, 2, 2, 3, 1889, 0 },
  { 422, 2, 2, 3, 1889, 0 },
  { 502, 2, 2, 3, 1889, 0 },
  { 572, 2, 2, 3, 1889, 0 },
  { 642, 2, 2, 3, 1889, 0 },
  { 73, 2, 2, 3, 1889, 0 },
  { 176, 2, 2, 3, 1889, 0 },
  { 261, 2, 2, 3, 1889, 0 },
  { 346, 2, 2, 3, 1889, 0 },
  { 426, 2, 2, 3, 1889, 0 },
  { 506, 2, 2, 3, 1889, 0 },
  { 576, 2, 2, 3, 1889, 0 },
  { 646, 2, 2, 3, 1889, 0 },
  { 728, 120, 2, 0, 1889, 3 },
  { 787, 120, 2, 0, 1889, 3 },
  { 19, 120, 2, 0, 1889, 3 },
  { 122, 120, 2, 0, 1889, 3 },
  { 225, 120, 2, 0, 1889, 3 },
  { 310, 120, 2, 0, 1889, 3 },
  { 395, 120, 2, 0, 1889, 3 },
  { 475, 120, 2, 0, 1889, 3 },
  { 99, 2, 2, 3, 1889, 0 },
  { 202, 2, 2, 3, 1889, 0 },
  { 287, 2, 2, 3, 1889, 0 },
  { 372, 2, 2, 3, 1889, 0 },
  { 452, 2, 2, 3, 1889, 0 },
  { 532, 2, 2, 3, 1889, 0 },
  { 602, 2, 2, 3, 1889, 0 },
  { 672, 2, 2, 3, 1889, 0 },
  { 72, 2, 96, 3, 1889, 0 },
  { 175, 2, 96, 3, 1889, 0 },
  { 260, 2, 96, 3, 1889, 0 },
  { 345, 2, 96, 3, 1889, 0 },
  { 425, 2, 96, 3, 1889, 0 },
  { 505, 2, 96, 3, 1889, 0 },
  { 575, 2, 96, 3, 1889, 0 },
  { 645, 2, 96, 3, 1889, 0 },
  { 712, 2, 96, 3, 1889, 0 },
  { 771, 2, 96, 3, 1889, 0 },
  { 0, 2, 96, 3, 1889, 0 },
  { 103, 2, 96, 3, 1889, 0 },
  { 206, 2, 96, 3, 1889, 0 },
  { 291, 2, 96, 3, 1889, 0 },
  { 376, 2, 96, 3, 1889, 0 },
  { 456, 2, 96, 3, 1889, 0 },
  { 536, 2, 96, 3, 1889, 0 },
  { 606, 2, 96, 3, 1889, 0 },
  { 676, 2, 96, 3, 1889, 0 },
  { 735, 2, 96, 3, 1889, 0 },
  { 28, 2, 96, 3, 1889, 0 },
  { 131, 2, 96, 3, 1889, 0 },
  { 234, 2, 96, 3, 1889, 0 },
  { 319, 2, 96, 3, 1889, 0 },
  { 404, 2, 96, 3, 1889, 0 },
  { 484, 2, 96, 3, 1889, 0 },
  { 554, 2, 96, 3, 1889, 0 },
  { 624, 2, 96, 3, 1889, 0 },
  { 694, 2, 96, 3, 1889, 0 },
  { 753, 2, 96, 3, 1889, 0 },
  { 46, 2, 96, 3, 1889, 0 },
  { 149, 2, 96, 3, 1889, 0 },
  { 77, 116, 97, 13, 1809, 7 },
  { 180, 116, 97, 13, 1809, 7 },
  { 265, 116, 97, 13, 1809, 7 },
  { 350, 116, 97, 13, 1809, 7 },
  { 430, 116, 97, 13, 1809, 7 },
  { 510, 116, 97, 13, 1809, 7 },
  { 580, 116, 97, 13, 1809, 7 },
  { 650, 116, 97, 13, 1809, 7 },
  { 717, 116, 97, 13, 1809, 7 },
  { 776, 116, 97, 13, 1809, 7 },
  { 6, 116, 97, 13, 1809, 7 },
  { 109, 116, 97, 13, 1809, 7 },
  { 212, 116, 97, 13, 1809, 7 },
  { 297, 116, 97, 13, 1809, 7 },
  { 382, 116, 97, 13, 1809, 7 },
  { 462, 116, 97, 13, 1809, 7 },
  { 542, 116, 97, 13, 1809, 7 },
  { 612, 116, 97, 13, 1809, 7 },
  { 682, 116, 97, 13, 1809, 7 },
  { 741, 116, 97, 13, 1809, 7 },
  { 34, 116, 97, 13, 1809, 7 },
  { 137, 116, 97, 13, 1809, 7 },
  { 240, 116, 97, 13, 1809, 7 },
  { 325, 116, 97, 13, 1809, 7 },
  { 410, 116, 97, 13, 1809, 7 },
  { 490, 116, 97, 13, 1809, 7 },
  { 560, 116, 97, 13, 1809, 7 },
  { 630, 116, 97, 13, 1809, 7 },
  { 700, 116, 97, 13, 1809, 7 },
  { 759, 116, 97, 13, 1809, 7 },
  { 52, 116, 97, 13, 1809, 7 },
  { 155, 116, 97, 13, 1809, 7 },
  { 82, 115, 2, 12, 1777, 7 },
  { 185, 115, 2, 12, 1777, 7 },
  { 270, 115, 2, 12, 1777, 7 },
  { 355, 115, 2, 12, 1777, 7 },
  { 435, 115, 2, 12, 1777, 7 },
  { 515, 115, 2, 12, 1777, 7 },
  { 585, 115, 2, 12, 1777, 7 },
  { 655, 115, 2, 12, 1777, 7 },
  { 722, 115, 2, 12, 1777, 7 },
  { 781, 115, 2, 12, 1777, 7 },
  { 12, 115, 2, 12, 1777, 7 },
  { 115, 115, 2, 12, 1777, 7 },
  { 218, 115, 2, 12, 1777, 7 },
  { 303, 115, 2, 12, 1777, 7 },
  { 388, 115, 2, 12, 1777, 7 },
  { 468, 115, 2, 12, 1777, 7 },
  { 548, 115, 2, 12, 1777, 7 },
  { 618, 115, 2, 12, 1777, 7 },
  { 688, 115, 2, 12, 1777, 7 },
  { 747, 115, 2, 12, 1777, 7 },
  { 40, 115, 2, 12, 1777, 7 },
  { 143, 115, 2, 12, 1777, 7 },
  { 246, 115, 2, 12, 1777, 7 },
  { 331, 115, 2, 12, 1777, 7 },
  { 416, 115, 2, 12, 1777, 7 },
  { 496, 115, 2, 12, 1777, 7 },
  { 566, 115, 2, 12, 1777, 7 },
  { 636, 115, 2, 12, 1777, 7 },
  { 706, 115, 2, 12, 1777, 7 },
  { 765, 115, 2, 12, 1777, 7 },
  { 58, 115, 2, 12, 1777, 7 },
  { 161, 115, 2, 12, 1777, 7 },
  { 824, 2, 107, 3, 1681, 0 },
  { 828, 2, 107, 3, 1681, 0 },
  { 794, 2, 107, 3, 1681, 0 },
  { 799, 2, 107, 3, 1681, 0 },
  { 804, 2, 107, 3, 1681, 0 },
  { 809, 2, 107, 3, 1681, 0 },
  { 814, 2, 107, 3, 1681, 0 },
  { 819, 2, 107, 3, 1681, 0 },
  { 862, 121, 109, 1, 1649, 3 },
  { 866, 121, 109, 1, 1649, 3 },
  { 832, 121, 109, 1, 1649, 3 },
  { 837, 121, 109, 1, 1649, 3 },
  { 842, 121, 109, 1, 1649, 3 },
  { 847, 121, 109, 1, 1649, 3 },
  { 852, 121, 109, 1, 1649, 3 },
  { 857, 121, 109, 1, 1649, 3 },
  { 1002, 122, 108, 2, 1617, 3 },
  { 1006, 122, 108, 2, 1617, 3 },
  { 972, 122, 108, 2, 1617, 3 },
  { 977, 122, 108, 2, 1617, 3 },
  { 982, 122, 108, 2, 1617, 3 },
  { 987, 122, 108, 2, 1617, 3 },
  { 992, 122, 108, 2, 1617, 3 },
  { 997, 122, 108, 2, 1617, 3 },
};

extern const MCPhysReg X86RegUnitRoots[][2] = {
  { X86::AH },
  { X86::AL },
  { X86::BH },
  { X86::BL },
  { X86::BPL },
  { X86::CH },
  { X86::CL },
  { X86::CS },
  { X86::DH },
  { X86::DIL },
  { X86::DL },
  { X86::DS },
  { X86::EFLAGS },
  { X86::IP },
  { X86::EIZ },
  { X86::ES },
  { X86::SIL },
  { X86::SPL },
  { X86::FPSW },
  { X86::FS },
  { X86::GS },
  { X86::RIZ },
  { X86::SS },
  { X86::BND0 },
  { X86::BND1 },
  { X86::BND2 },
  { X86::BND3 },
  { X86::CR0 },
  { X86::CR1 },
  { X86::CR2 },
  { X86::CR3 },
  { X86::CR4 },
  { X86::CR5 },
  { X86::CR6 },
  { X86::CR7 },
  { X86::CR8 },
  { X86::CR9 },
  { X86::CR10 },
  { X86::CR11 },
  { X86::CR12 },
  { X86::CR13 },
  { X86::CR14 },
  { X86::CR15 },
  { X86::DR0 },
  { X86::DR1 },
  { X86::DR2 },
  { X86::DR3 },
  { X86::DR4 },
  { X86::DR5 },
  { X86::DR6 },
  { X86::DR7 },
  { X86::DR8 },
  { X86::DR9 },
  { X86::DR10 },
  { X86::DR11 },
  { X86::DR12 },
  { X86::DR13 },
  { X86::DR14 },
  { X86::DR15 },
  { X86::FP0 },
  { X86::FP1 },
  { X86::FP2 },
  { X86::FP3 },
  { X86::FP4 },
  { X86::FP5 },
  { X86::FP6 },
  { X86::FP7 },
  { X86::K0 },
  { X86::K1 },
  { X86::K2 },
  { X86::K3 },
  { X86::K4 },
  { X86::K5 },
  { X86::K6 },
  { X86::K7 },
  { X86::MM0 },
  { X86::MM1 },
  { X86::MM2 },
  { X86::MM3 },
  { X86::MM4 },
  { X86::MM5 },
  { X86::MM6 },
  { X86::MM7 },
  { X86::R8B },
  { X86::R9B },
  { X86::R10B },
  { X86::R11B },
  { X86::R12B },
  { X86::R13B },
  { X86::R14B },
  { X86::R15B },
  { X86::ST0 },
  { X86::ST1 },
  { X86::ST2 },
  { X86::ST3 },
  { X86::ST4 },
  { X86::ST5 },
  { X86::ST6 },
  { X86::ST7 },
  { X86::XMM0 },
  { X86::XMM1 },
  { X86::XMM2 },
  { X86::XMM3 },
  { X86::XMM4 },
  { X86::XMM5 },
  { X86::XMM6 },
  { X86::XMM7 },
  { X86::XMM8 },
  { X86::XMM9 },
  { X86::XMM10 },
  { X86::XMM11 },
  { X86::XMM12 },
  { X86::XMM13 },
  { X86::XMM14 },
  { X86::XMM15 },
  { X86::XMM16 },
  { X86::XMM17 },
  { X86::XMM18 },
  { X86::XMM19 },
  { X86::XMM20 },
  { X86::XMM21 },
  { X86::XMM22 },
  { X86::XMM23 },
  { X86::XMM24 },
  { X86::XMM25 },
  { X86::XMM26 },
  { X86::XMM27 },
  { X86::XMM28 },
  { X86::XMM29 },
  { X86::XMM30 },
  { X86::XMM31 },
};

namespace {     // Register classes...
  // GR8 Register Class...
  const MCPhysReg GR8[] = {
    X86::AL, X86::CL, X86::DL, X86::AH, X86::CH, X86::DH, X86::BL, X86::BH, X86::SIL, X86::DIL, X86::BPL, X86::SPL, X86::R8B, X86::R9B, X86::R10B, X86::R11B, X86::R14B, X86::R15B, X86::R12B, X86::R13B, 
  };

  // GR8 Bit set.
  const uint8_t GR8Bits[] = {
    0xb6, 0xa6, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR8_NOREX Register Class...
  const MCPhysReg GR8_NOREX[] = {
    X86::AL, X86::CL, X86::DL, X86::AH, X86::CH, X86::DH, X86::BL, X86::BH, 
  };

  // GR8_NOREX Bit set.
  const uint8_t GR8_NOREXBits[] = {
    0x36, 0x26, 0x01, 
  };

  // VK1 Register Class...
  const MCPhysReg VK1[] = {
    X86::K0, X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK1 Bit set.
  const uint8_t VK1Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // VK2 Register Class...
  const MCPhysReg VK2[] = {
    X86::K0, X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK2 Bit set.
  const uint8_t VK2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // VK4 Register Class...
  const MCPhysReg VK4[] = {
    X86::K0, X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK4 Bit set.
  const uint8_t VK4Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // VK8 Register Class...
  const MCPhysReg VK8[] = {
    X86::K0, X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK8 Bit set.
  const uint8_t VK8Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // VK1WM Register Class...
  const MCPhysReg VK1WM[] = {
    X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK1WM Bit set.
  const uint8_t VK1WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 
  };

  // VK2WM Register Class...
  const MCPhysReg VK2WM[] = {
    X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK2WM Bit set.
  const uint8_t VK2WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 
  };

  // VK4WM Register Class...
  const MCPhysReg VK4WM[] = {
    X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK4WM Bit set.
  const uint8_t VK4WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 
  };

  // VK8WM Register Class...
  const MCPhysReg VK8WM[] = {
    X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK8WM Bit set.
  const uint8_t VK8WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 
  };

  // GR8_ABCD_H Register Class...
  const MCPhysReg GR8_ABCD_H[] = {
    X86::AH, X86::CH, X86::DH, X86::BH, 
  };

  // GR8_ABCD_H Bit set.
  const uint8_t GR8_ABCD_HBits[] = {
    0x12, 0x22, 
  };

  // GR8_ABCD_L Register Class...
  const MCPhysReg GR8_ABCD_L[] = {
    X86::AL, X86::CL, X86::DL, X86::BL, 
  };

  // GR8_ABCD_L Bit set.
  const uint8_t GR8_ABCD_LBits[] = {
    0x24, 0x04, 0x01, 
  };

  // GR16 Register Class...
  const MCPhysReg GR16[] = {
    X86::AX, X86::CX, X86::DX, X86::SI, X86::DI, X86::BX, X86::BP, X86::SP, X86::R8W, X86::R9W, X86::R10W, X86::R11W, X86::R14W, X86::R15W, X86::R12W, X86::R13W, 
  };

  // GR16 Bit set.
  const uint8_t GR16Bits[] = {
    0x48, 0x51, 0x04, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR16_NOREX Register Class...
  const MCPhysReg GR16_NOREX[] = {
    X86::AX, X86::CX, X86::DX, X86::SI, X86::DI, X86::BX, X86::BP, X86::SP, 
  };

  // GR16_NOREX Bit set.
  const uint8_t GR16_NOREXBits[] = {
    0x48, 0x51, 0x04, 0x00, 0x00, 0xa0, 
  };

  // VK16 Register Class...
  const MCPhysReg VK16[] = {
    X86::K0, X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK16 Bit set.
  const uint8_t VK16Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // VK16WM Register Class...
  const MCPhysReg VK16WM[] = {
    X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK16WM Bit set.
  const uint8_t VK16WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 
  };

  // SEGMENT_REG Register Class...
  const MCPhysReg SEGMENT_REG[] = {
    X86::CS, X86::DS, X86::SS, X86::ES, X86::FS, X86::GS, 
  };

  // SEGMENT_REG Bit set.
  const uint8_t SEGMENT_REGBits[] = {
    0x00, 0x08, 0x02, 0x10, 0x03, 0x00, 0x02, 
  };

  // GR16_ABCD Register Class...
  const MCPhysReg GR16_ABCD[] = {
    X86::AX, X86::CX, X86::DX, X86::BX, 
  };

  // GR16_ABCD Bit set.
  const uint8_t GR16_ABCDBits[] = {
    0x08, 0x11, 0x04, 
  };

  // FPCCR Register Class...
  const MCPhysReg FPCCR[] = {
    X86::FPSW, 
  };

  // FPCCR Bit set.
  const uint8_t FPCCRBits[] = {
    0x00, 0x00, 0x00, 0x80, 
  };

  // FR32X Register Class...
  const MCPhysReg FR32X[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, X86::XMM16, X86::XMM17, X86::XMM18, X86::XMM19, X86::XMM20, X86::XMM21, X86::XMM22, X86::XMM23, X86::XMM24, X86::XMM25, X86::XMM26, X86::XMM27, X86::XMM28, X86::XMM29, X86::XMM30, X86::XMM31, 
  };

  // FR32X Bit set.
  const uint8_t FR32XBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // FR32 Register Class...
  const MCPhysReg FR32[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, 
  };

  // FR32 Bit set.
  const uint8_t FR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x3f, 
  };

  // GR32 Register Class...
  const MCPhysReg GR32[] = {
    X86::EAX, X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, X86::ESP, X86::R8D, X86::R9D, X86::R10D, X86::R11D, X86::R14D, X86::R15D, X86::R12D, X86::R13D, 
  };

  // GR32 Bit set.
  const uint8_t GR32Bits[] = {
    0x00, 0x00, 0xf8, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR32_NOAX Register Class...
  const MCPhysReg GR32_NOAX[] = {
    X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, X86::ESP, X86::R8D, X86::R9D, X86::R10D, X86::R11D, X86::R14D, X86::R15D, X86::R12D, X86::R13D, 
  };

  // GR32_NOAX Bit set.
  const uint8_t GR32_NOAXBits[] = {
    0x00, 0x00, 0xf0, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR32_NOSP Register Class...
  const MCPhysReg GR32_NOSP[] = {
    X86::EAX, X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, X86::R8D, X86::R9D, X86::R10D, X86::R11D, X86::R14D, X86::R15D, X86::R12D, X86::R13D, 
  };

  // GR32_NOSP Bit set.
  const uint8_t GR32_NOSPBits[] = {
    0x00, 0x00, 0xf8, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR32_NOAX_and_GR32_NOSP Register Class...
  const MCPhysReg GR32_NOAX_and_GR32_NOSP[] = {
    X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, X86::R8D, X86::R9D, X86::R10D, X86::R11D, X86::R14D, X86::R15D, X86::R12D, X86::R13D, 
  };

  // GR32_NOAX_and_GR32_NOSP Bit set.
  const uint8_t GR32_NOAX_and_GR32_NOSPBits[] = {
    0x00, 0x00, 0xf0, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // DEBUG_REG Register Class...
  const MCPhysReg DEBUG_REG[] = {
    X86::DR0, X86::DR1, X86::DR2, X86::DR3, X86::DR4, X86::DR5, X86::DR6, X86::DR7, 
  };

  // DEBUG_REG Bit set.
  const uint8_t DEBUG_REGBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR32_NOREX Register Class...
  const MCPhysReg GR32_NOREX[] = {
    X86::EAX, X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, X86::ESP, 
  };

  // GR32_NOREX Bit set.
  const uint8_t GR32_NOREXBits[] = {
    0x00, 0x00, 0xf8, 0x61, 
  };

  // VK32 Register Class...
  const MCPhysReg VK32[] = {
    X86::K0, X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK32 Bit set.
  const uint8_t VK32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR32_NOAX_and_GR32_NOREX Register Class...
  const MCPhysReg GR32_NOAX_and_GR32_NOREX[] = {
    X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, X86::ESP, 
  };

  // GR32_NOAX_and_GR32_NOREX Bit set.
  const uint8_t GR32_NOAX_and_GR32_NOREXBits[] = {
    0x00, 0x00, 0xf0, 0x61, 
  };

  // GR32_NOREX_NOSP Register Class...
  const MCPhysReg GR32_NOREX_NOSP[] = {
    X86::EAX, X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, 
  };

  // GR32_NOREX_NOSP Bit set.
  const uint8_t GR32_NOREX_NOSPBits[] = {
    0x00, 0x00, 0xf8, 0x21, 
  };

  // RFP32 Register Class...
  const MCPhysReg RFP32[] = {
    X86::FP0, X86::FP1, X86::FP2, X86::FP3, X86::FP4, X86::FP5, X86::FP6, 
  };

  // RFP32 Bit set.
  const uint8_t RFP32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x1f, 
  };

  // VK32WM Register Class...
  const MCPhysReg VK32WM[] = {
    X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK32WM Bit set.
  const uint8_t VK32WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 
  };

  // GR32_NOAX_and_GR32_NOREX_NOSP Register Class...
  const MCPhysReg GR32_NOAX_and_GR32_NOREX_NOSP[] = {
    X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, 
  };

  // GR32_NOAX_and_GR32_NOREX_NOSP Bit set.
  const uint8_t GR32_NOAX_and_GR32_NOREX_NOSPBits[] = {
    0x00, 0x00, 0xf0, 0x21, 
  };

  // GR32_ABCD Register Class...
  const MCPhysReg GR32_ABCD[] = {
    X86::EAX, X86::ECX, X86::EDX, X86::EBX, 
  };

  // GR32_ABCD Bit set.
  const uint8_t GR32_ABCDBits[] = {
    0x00, 0x00, 0x68, 0x01, 
  };

  // GR32_ABCD_and_GR32_NOAX Register Class...
  const MCPhysReg GR32_ABCD_and_GR32_NOAX[] = {
    X86::ECX, X86::EDX, X86::EBX, 
  };

  // GR32_ABCD_and_GR32_NOAX Bit set.
  const uint8_t GR32_ABCD_and_GR32_NOAXBits[] = {
    0x00, 0x00, 0x60, 0x01, 
  };

  // GR32_TC Register Class...
  const MCPhysReg GR32_TC[] = {
    X86::EAX, X86::ECX, X86::EDX, 
  };

  // GR32_TC Bit set.
  const uint8_t GR32_TCBits[] = {
    0x00, 0x00, 0x48, 0x01, 
  };

  // GR32_AD Register Class...
  const MCPhysReg GR32_AD[] = {
    X86::EAX, X86::EDX, 
  };

  // GR32_AD Bit set.
  const uint8_t GR32_ADBits[] = {
    0x00, 0x00, 0x08, 0x01, 
  };

  // GR32_NOAX_and_GR32_TC Register Class...
  const MCPhysReg GR32_NOAX_and_GR32_TC[] = {
    X86::ECX, X86::EDX, 
  };

  // GR32_NOAX_and_GR32_TC Bit set.
  const uint8_t GR32_NOAX_and_GR32_TCBits[] = {
    0x00, 0x00, 0x40, 0x01, 
  };

  // CCR Register Class...
  const MCPhysReg CCR[] = {
    X86::EFLAGS, 
  };

  // CCR Bit set.
  const uint8_t CCRBits[] = {
    0x00, 0x00, 0x00, 0x02, 
  };

  // GR32_AD_and_GR32_NOAX Register Class...
  const MCPhysReg GR32_AD_and_GR32_NOAX[] = {
    X86::EDX, 
  };

  // GR32_AD_and_GR32_NOAX Bit set.
  const uint8_t GR32_AD_and_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x01, 
  };

  // RFP64 Register Class...
  const MCPhysReg RFP64[] = {
    X86::FP0, X86::FP1, X86::FP2, X86::FP3, X86::FP4, X86::FP5, X86::FP6, 
  };

  // RFP64 Bit set.
  const uint8_t RFP64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x1f, 
  };

  // FR64X Register Class...
  const MCPhysReg FR64X[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, X86::XMM16, X86::XMM17, X86::XMM18, X86::XMM19, X86::XMM20, X86::XMM21, X86::XMM22, X86::XMM23, X86::XMM24, X86::XMM25, X86::XMM26, X86::XMM27, X86::XMM28, X86::XMM29, X86::XMM30, X86::XMM31, 
  };

  // FR64X Bit set.
  const uint8_t FR64XBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // GR64 Register Class...
  const MCPhysReg GR64[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R10, X86::R11, X86::RBX, X86::R14, X86::R15, X86::R12, X86::R13, X86::RBP, X86::RSP, X86::RIP, 
  };

  // GR64 Bit set.
  const uint8_t GR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // CONTROL_REG Register Class...
  const MCPhysReg CONTROL_REG[] = {
    X86::CR0, X86::CR1, X86::CR2, X86::CR3, X86::CR4, X86::CR5, X86::CR6, X86::CR7, X86::CR8, X86::CR9, X86::CR10, X86::CR11, X86::CR12, X86::CR13, X86::CR14, X86::CR15, 
  };

  // CONTROL_REG Bit set.
  const uint8_t CONTROL_REGBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x3f, 
  };

  // FR64 Register Class...
  const MCPhysReg FR64[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, 
  };

  // FR64 Bit set.
  const uint8_t FR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x3f, 
  };

  // GR64_with_sub_8bit Register Class...
  const MCPhysReg GR64_with_sub_8bit[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R10, X86::R11, X86::RBX, X86::R14, X86::R15, X86::R12, X86::R13, X86::RBP, X86::RSP, 
  };

  // GR64_with_sub_8bit Bit set.
  const uint8_t GR64_with_sub_8bitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR64_NOSP Register Class...
  const MCPhysReg GR64_NOSP[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R10, X86::R11, X86::RBX, X86::R14, X86::R15, X86::R12, X86::R13, X86::RBP, 
  };

  // GR64_NOSP Bit set.
  const uint8_t GR64_NOSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX Register Class...
  const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX[] = {
    X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R10, X86::R11, X86::RBX, X86::R14, X86::R15, X86::R12, X86::R13, X86::RBP, X86::RSP, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX Bit set.
  const uint8_t GR64_with_sub_32bit_in_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf0, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSP Register Class...
  const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSP[] = {
    X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R10, X86::R11, X86::RBX, X86::R14, X86::R15, X86::R12, X86::R13, X86::RBP, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSP Bit set.
  const uint8_t GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf0, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR64_NOREX Register Class...
  const MCPhysReg GR64_NOREX[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::RBX, X86::RBP, X86::RSP, X86::RIP, 
  };

  // GR64_NOREX Bit set.
  const uint8_t GR64_NOREXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x1b, 
  };

  // GR64_TC Register Class...
  const MCPhysReg GR64_TC[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R11, X86::RIP, 
  };

  // GR64_TC Bit set.
  const uint8_t GR64_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x02, 
  };

  // GR64_NOSP_and_GR64_TC Register Class...
  const MCPhysReg GR64_NOSP_and_GR64_TC[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R11, 
  };

  // GR64_NOSP_and_GR64_TC Bit set.
  const uint8_t GR64_NOSP_and_GR64_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x02, 
  };

  // GR64_TCW64 Register Class...
  const MCPhysReg GR64_TCW64[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::R8, X86::R9, X86::R10, X86::R11, X86::RIP, 
  };

  // GR64_TCW64 Bit set.
  const uint8_t GR64_TCW64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03, 
  };

  // GR64_with_sub_16bit_in_GR16_NOREX Register Class...
  const MCPhysReg GR64_with_sub_16bit_in_GR16_NOREX[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::RBX, X86::RBP, X86::RSP, 
  };

  // GR64_with_sub_16bit_in_GR16_NOREX Bit set.
  const uint8_t GR64_with_sub_16bit_in_GR16_NOREXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x19, 
  };

  // VK64 Register Class...
  const MCPhysReg VK64[] = {
    X86::K0, X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK64 Bit set.
  const uint8_t VK64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // VR64 Register Class...
  const MCPhysReg VR64[] = {
    X86::MM0, X86::MM1, X86::MM2, X86::MM3, X86::MM4, X86::MM5, X86::MM6, X86::MM7, 
  };

  // VR64 Bit set.
  const uint8_t VR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // GR64_NOREX_NOSP Register Class...
  const MCPhysReg GR64_NOREX_NOSP[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::RBX, X86::RBP, 
  };

  // GR64_NOREX_NOSP Bit set.
  const uint8_t GR64_NOREX_NOSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x09, 
  };

  // GR64_NOSP_and_GR64_TCW64 Register Class...
  const MCPhysReg GR64_NOSP_and_GR64_TCW64[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::R8, X86::R9, X86::R10, X86::R11, 
  };

  // GR64_NOSP_and_GR64_TCW64 Bit set.
  const uint8_t GR64_NOSP_and_GR64_TCW64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03, 
  };

  // GR64_TC_and_GR64_TCW64 Register Class...
  const MCPhysReg GR64_TC_and_GR64_TCW64[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::R8, X86::R9, X86::R11, X86::RIP, 
  };

  // GR64_TC_and_GR64_TCW64 Bit set.
  const uint8_t GR64_TC_and_GR64_TCW64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x02, 
  };

  // GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX Register Class...
  const MCPhysReg GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX[] = {
    X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R11, 
  };

  // GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX Bit set.
  const uint8_t GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc0, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x02, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX Register Class...
  const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX[] = {
    X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::RBX, X86::RBP, X86::RSP, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX Bit set.
  const uint8_t GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf0, 0x19, 
  };

  // VK64WM Register Class...
  const MCPhysReg VK64WM[] = {
    X86::K1, X86::K2, X86::K3, X86::K4, X86::K5, X86::K6, X86::K7, 
  };

  // VK64WM Bit set.
  const uint8_t VK64WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 
  };

  // GR64_NOREX_and_GR64_TC Register Class...
  const MCPhysReg GR64_NOREX_and_GR64_TC[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::RIP, 
  };

  // GR64_NOREX_and_GR64_TC Bit set.
  const uint8_t GR64_NOREX_and_GR64_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x0b, 
  };

  // GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAX Register Class...
  const MCPhysReg GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAX[] = {
    X86::RCX, X86::RDX, X86::R8, X86::R9, X86::R10, X86::R11, 
  };

  // GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAX Bit set.
  const uint8_t GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03, 
  };

  // GR64_TC_and_GR64_NOSP_and_GR64_TCW64 Register Class...
  const MCPhysReg GR64_TC_and_GR64_NOSP_and_GR64_TCW64[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::R8, X86::R9, X86::R11, 
  };

  // GR64_TC_and_GR64_NOSP_and_GR64_TCW64 Bit set.
  const uint8_t GR64_TC_and_GR64_NOSP_and_GR64_TCW64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x02, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSP Register Class...
  const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSP[] = {
    X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::RBX, X86::RBP, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSP Bit set.
  const uint8_t GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf0, 0x09, 
  };

  // GR64_NOREX_NOSP_and_GR64_TC Register Class...
  const MCPhysReg GR64_NOREX_NOSP_and_GR64_TC[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, 
  };

  // GR64_NOREX_NOSP_and_GR64_TC Bit set.
  const uint8_t GR64_NOREX_NOSP_and_GR64_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x09, 
  };

  // GR64_TCW64_and_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX Register Class...
  const MCPhysReg GR64_TCW64_and_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX[] = {
    X86::RCX, X86::RDX, X86::R8, X86::R9, X86::R11, 
  };

  // GR64_TCW64_and_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX Bit set.
  const uint8_t GR64_TCW64_and_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x02, 
  };

  // GR64_ABCD Register Class...
  const MCPhysReg GR64_ABCD[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RBX, 
  };

  // GR64_ABCD Bit set.
  const uint8_t GR64_ABCDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x68, 0x01, 
  };

  // GR64_NOREX_and_GR64_TCW64 Register Class...
  const MCPhysReg GR64_NOREX_and_GR64_TCW64[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RIP, 
  };

  // GR64_NOREX_and_GR64_TCW64 Bit set.
  const uint8_t GR64_NOREX_and_GR64_TCW64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x48, 0x03, 
  };

  // GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX Register Class...
  const MCPhysReg GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX[] = {
    X86::RCX, X86::RDX, X86::RSI, X86::RDI, 
  };

  // GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX Bit set.
  const uint8_t GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc0, 0x09, 
  };

  // GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAX Register Class...
  const MCPhysReg GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAX[] = {
    X86::RCX, X86::RDX, X86::RBX, 
  };

  // GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAX Bit set.
  const uint8_t GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x60, 0x01, 
  };

  // GR64_with_sub_32bit_in_GR32_TC Register Class...
  const MCPhysReg GR64_with_sub_32bit_in_GR32_TC[] = {
    X86::RAX, X86::RCX, X86::RDX, 
  };

  // GR64_with_sub_32bit_in_GR32_TC Bit set.
  const uint8_t GR64_with_sub_32bit_in_GR32_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 
  };

  // GR64_with_sub_32bit_in_GR32_AD Register Class...
  const MCPhysReg GR64_with_sub_32bit_in_GR32_AD[] = {
    X86::RAX, X86::RDX, 
  };

  // GR64_with_sub_32bit_in_GR32_AD Bit set.
  const uint8_t GR64_with_sub_32bit_in_GR32_ADBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TC Register Class...
  const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TC[] = {
    X86::RCX, X86::RDX, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TC Bit set.
  const uint8_t GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 
  };

  // GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAX Register Class...
  const MCPhysReg GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAX[] = {
    X86::RDX, 
  };

  // GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAX Bit set.
  const uint8_t GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

  // RST Register Class...
  const MCPhysReg RST[] = {
    X86::ST0, X86::ST1, X86::ST2, X86::ST3, X86::ST4, X86::ST5, X86::ST6, X86::ST7, 
  };

  // RST Bit set.
  const uint8_t RSTBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // RFP80 Register Class...
  const MCPhysReg RFP80[] = {
    X86::FP0, X86::FP1, X86::FP2, X86::FP3, X86::FP4, X86::FP5, X86::FP6, 
  };

  // RFP80 Bit set.
  const uint8_t RFP80Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x1f, 
  };

  // VR128X Register Class...
  const MCPhysReg VR128X[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, X86::XMM16, X86::XMM17, X86::XMM18, X86::XMM19, X86::XMM20, X86::XMM21, X86::XMM22, X86::XMM23, X86::XMM24, X86::XMM25, X86::XMM26, X86::XMM27, X86::XMM28, X86::XMM29, X86::XMM30, X86::XMM31, 
  };

  // VR128X Bit set.
  const uint8_t VR128XBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // FR128 Register Class...
  const MCPhysReg FR128[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, 
  };

  // FR128 Bit set.
  const uint8_t FR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x3f, 
  };

  // VR128 Register Class...
  const MCPhysReg VR128[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, 
  };

  // VR128 Bit set.
  const uint8_t VR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x3f, 
  };

  // BNDR Register Class...
  const MCPhysReg BNDR[] = {
    X86::BND0, X86::BND1, X86::BND2, X86::BND3, 
  };

  // BNDR Bit set.
  const uint8_t BNDRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 
  };

  // VR256X Register Class...
  const MCPhysReg VR256X[] = {
    X86::YMM0, X86::YMM1, X86::YMM2, X86::YMM3, X86::YMM4, X86::YMM5, X86::YMM6, X86::YMM7, X86::YMM8, X86::YMM9, X86::YMM10, X86::YMM11, X86::YMM12, X86::YMM13, X86::YMM14, X86::YMM15, X86::YMM16, X86::YMM17, X86::YMM18, X86::YMM19, X86::YMM20, X86::YMM21, X86::YMM22, X86::YMM23, X86::YMM24, X86::YMM25, X86::YMM26, X86::YMM27, X86::YMM28, X86::YMM29, X86::YMM30, X86::YMM31, 
  };

  // VR256X Bit set.
  const uint8_t VR256XBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // VR256 Register Class...
  const MCPhysReg VR256[] = {
    X86::YMM0, X86::YMM1, X86::YMM2, X86::YMM3, X86::YMM4, X86::YMM5, X86::YMM6, X86::YMM7, X86::YMM8, X86::YMM9, X86::YMM10, X86::YMM11, X86::YMM12, X86::YMM13, X86::YMM14, X86::YMM15, 
  };

  // VR256 Bit set.
  const uint8_t VR256Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x3f, 
  };

  // VR512 Register Class...
  const MCPhysReg VR512[] = {
    X86::ZMM0, X86::ZMM1, X86::ZMM2, X86::ZMM3, X86::ZMM4, X86::ZMM5, X86::ZMM6, X86::ZMM7, X86::ZMM8, X86::ZMM9, X86::ZMM10, X86::ZMM11, X86::ZMM12, X86::ZMM13, X86::ZMM14, X86::ZMM15, X86::ZMM16, X86::ZMM17, X86::ZMM18, X86::ZMM19, X86::ZMM20, X86::ZMM21, X86::ZMM22, X86::ZMM23, X86::ZMM24, X86::ZMM25, X86::ZMM26, X86::ZMM27, X86::ZMM28, X86::ZMM29, X86::ZMM30, X86::ZMM31, 
  };

  // VR512 Bit set.
  const uint8_t VR512Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // VR512_with_sub_xmm_in_FR128 Register Class...
  const MCPhysReg VR512_with_sub_xmm_in_FR128[] = {
    X86::ZMM0, X86::ZMM1, X86::ZMM2, X86::ZMM3, X86::ZMM4, X86::ZMM5, X86::ZMM6, X86::ZMM7, X86::ZMM8, X86::ZMM9, X86::ZMM10, X86::ZMM11, X86::ZMM12, X86::ZMM13, X86::ZMM14, X86::ZMM15, 
  };

  // VR512_with_sub_xmm_in_FR128 Bit set.
  const uint8_t VR512_with_sub_xmm_in_FR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x3f, 
  };

}

extern const char X86RegClassStrings[] = {
  /* 0 */ 'R', 'F', 'P', '8', '0', 0,
  /* 6 */ 'V', 'K', '1', 0,
  /* 10 */ 'V', 'R', '5', '1', '2', 0,
  /* 16 */ 'V', 'K', '3', '2', 0,
  /* 21 */ 'R', 'F', 'P', '3', '2', 0,
  /* 27 */ 'F', 'R', '3', '2', 0,
  /* 32 */ 'G', 'R', '3', '2', 0,
  /* 37 */ 'V', 'K', '2', 0,
  /* 41 */ 'V', 'K', '6', '4', 0,
  /* 46 */ 'R', 'F', 'P', '6', '4', 0,
  /* 52 */ 'F', 'R', '6', '4', 0,
  /* 57 */ 'G', 'R', '6', '4', 0,
  /* 62 */ 'V', 'R', '6', '4', 0,
  /* 67 */ 'G', 'R', '6', '4', '_', 'T', 'C', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'T', 'C', 'W', '6', '4', 0,
  /* 90 */ 'G', 'R', '6', '4', '_', 'T', 'C', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'N', 'O', 'S', 'P', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'T', 'C', 'W', '6', '4', 0,
  /* 127 */ 'G', 'R', '6', '4', '_', 'N', 'O', 'R', 'E', 'X', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'T', 'C', 'W', '6', '4', 0,
  /* 153 */ 'V', 'K', '4', 0,
  /* 157 */ 'V', 'K', '1', '6', 0,
  /* 162 */ 'G', 'R', '1', '6', 0,
  /* 167 */ 'V', 'R', '2', '5', '6', 0,
  /* 173 */ 'V', 'R', '5', '1', '2', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', 'x', 'm', 'm', '_', 'i', 'n', '_', 'F', 'R', '1', '2', '8', 0,
  /* 201 */ 'V', 'R', '1', '2', '8', 0,
  /* 207 */ 'V', 'K', '8', 0,
  /* 211 */ 'G', 'R', '8', 0,
  /* 215 */ 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'A', 'X', '_', 'a', 'n', 'd', '_', 'G', 'R', '3', '2', '_', 'T', 'C', 0,
  /* 260 */ 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'T', 'C', 0,
  /* 291 */ 'G', 'R', '6', '4', '_', 'N', 'O', 'S', 'P', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'T', 'C', 0,
  /* 313 */ 'G', 'R', '6', '4', '_', 'N', 'O', 'R', 'E', 'X', '_', 'N', 'O', 'S', 'P', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'T', 'C', 0,
  /* 341 */ 'G', 'R', '6', '4', '_', 'N', 'O', 'R', 'E', 'X', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'T', 'C', 0,
  /* 364 */ 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'A', 'D', 0,
  /* 395 */ 'G', 'R', '3', '2', '_', 'A', 'B', 'C', 'D', 0,
  /* 405 */ 'G', 'R', '6', '4', '_', 'A', 'B', 'C', 'D', 0,
  /* 415 */ 'G', 'R', '1', '6', '_', 'A', 'B', 'C', 'D', 0,
  /* 425 */ 'D', 'E', 'B', 'U', 'G', '_', 'R', 'E', 'G', 0,
  /* 435 */ 'C', 'O', 'N', 'T', 'R', 'O', 'L', '_', 'R', 'E', 'G', 0,
  /* 447 */ 'S', 'E', 'G', 'M', 'E', 'N', 'T', '_', 'R', 'E', 'G', 0,
  /* 459 */ 'G', 'R', '8', '_', 'A', 'B', 'C', 'D', '_', 'H', 0,
  /* 470 */ 'G', 'R', '8', '_', 'A', 'B', 'C', 'D', '_', 'L', 0,
  /* 481 */ 'V', 'K', '1', 'W', 'M', 0,
  /* 487 */ 'V', 'K', '3', '2', 'W', 'M', 0,
  /* 494 */ 'V', 'K', '2', 'W', 'M', 0,
  /* 500 */ 'V', 'K', '6', '4', 'W', 'M', 0,
  /* 507 */ 'V', 'K', '4', 'W', 'M', 0,
  /* 513 */ 'V', 'K', '1', '6', 'W', 'M', 0,
  /* 520 */ 'V', 'K', '8', 'W', 'M', 0,
  /* 526 */ 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'A', 'X', '_', 'a', 'n', 'd', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'S', 'P', 0,
  /* 573 */ 'G', 'R', '6', '4', '_', 'N', 'O', 'S', 'P', 0,
  /* 583 */ 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'A', 'X', '_', 'a', 'n', 'd', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'R', 'E', 'X', '_', 'N', 'O', 'S', 'P', 0,
  /* 636 */ 'G', 'R', '6', '4', '_', 'N', 'O', 'R', 'E', 'X', '_', 'N', 'O', 'S', 'P', 0,
  /* 652 */ 'F', 'P', 'C', 'C', 'R', 0,
  /* 658 */ 'B', 'N', 'D', 'R', 0,
  /* 663 */ 'R', 'S', 'T', 0,
  /* 667 */ 'F', 'R', '3', '2', 'X', 0,
  /* 673 */ 'F', 'R', '6', '4', 'X', 0,
  /* 679 */ 'V', 'R', '2', '5', '6', 'X', 0,
  /* 686 */ 'V', 'R', '1', '2', '8', 'X', 0,
  /* 693 */ 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'A', 'D', '_', 'a', 'n', 'd', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'A', 'X', 0,
  /* 738 */ 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'A', 'B', 'C', 'D', '_', 'a', 'n', 'd', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'A', 'X', 0,
  /* 785 */ 'G', 'R', '6', '4', '_', 'T', 'C', 'W', '6', '4', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'A', 'X', 0,
  /* 833 */ 'G', 'R', '6', '4', '_', 'T', 'C', 'W', '6', '4', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'T', 'C', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'A', 'X', 0,
  /* 893 */ 'G', 'R', '6', '4', '_', 'T', 'C', '_', 'a', 'n', 'd', '_', 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '3', '2', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'A', 'X', '_', 'a', 'n', 'd', '_', 'G', 'R', '3', '2', '_', 'N', 'O', 'R', 'E', 'X', 0,
  /* 953 */ 'G', 'R', '6', '4', '_', 'N', 'O', 'R', 'E', 'X', 0,
  /* 964 */ 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '1', '6', 'b', 'i', 't', '_', 'i', 'n', '_', 'G', 'R', '1', '6', '_', 'N', 'O', 'R', 'E', 'X', 0,
  /* 998 */ 'G', 'R', '8', '_', 'N', 'O', 'R', 'E', 'X', 0,
  /* 1008 */ 'G', 'R', '6', '4', '_', 'w', 'i', 't', 'h', '_', 's', 'u', 'b', '_', '8', 'b', 'i', 't', 0,
};

extern const MCRegisterClass X86MCRegisterClasses[] = {
  { GR8, GR8Bits, 211, 20, sizeof(GR8Bits), X86::GR8RegClassID, 1, 1, 1, 1 },
  { GR8_NOREX, GR8_NOREXBits, 998, 8, sizeof(GR8_NOREXBits), X86::GR8_NOREXRegClassID, 1, 1, 1, 1 },
  { VK1, VK1Bits, 6, 8, sizeof(VK1Bits), X86::VK1RegClassID, 1, 1, 1, 1 },
  { VK2, VK2Bits, 37, 8, sizeof(VK2Bits), X86::VK2RegClassID, 1, 1, 1, 1 },
  { VK4, VK4Bits, 153, 8, sizeof(VK4Bits), X86::VK4RegClassID, 1, 1, 1, 1 },
  { VK8, VK8Bits, 207, 8, sizeof(VK8Bits), X86::VK8RegClassID, 1, 1, 1, 1 },
  { VK1WM, VK1WMBits, 481, 7, sizeof(VK1WMBits), X86::VK1WMRegClassID, 1, 1, 1, 1 },
  { VK2WM, VK2WMBits, 494, 7, sizeof(VK2WMBits), X86::VK2WMRegClassID, 1, 1, 1, 1 },
  { VK4WM, VK4WMBits, 507, 7, sizeof(VK4WMBits), X86::VK4WMRegClassID, 1, 1, 1, 1 },
  { VK8WM, VK8WMBits, 520, 7, sizeof(VK8WMBits), X86::VK8WMRegClassID, 1, 1, 1, 1 },
  { GR8_ABCD_H, GR8_ABCD_HBits, 459, 4, sizeof(GR8_ABCD_HBits), X86::GR8_ABCD_HRegClassID, 1, 1, 1, 1 },
  { GR8_ABCD_L, GR8_ABCD_LBits, 470, 4, sizeof(GR8_ABCD_LBits), X86::GR8_ABCD_LRegClassID, 1, 1, 1, 1 },
  { GR16, GR16Bits, 162, 16, sizeof(GR16Bits), X86::GR16RegClassID, 2, 2, 1, 1 },
  { GR16_NOREX, GR16_NOREXBits, 987, 8, sizeof(GR16_NOREXBits), X86::GR16_NOREXRegClassID, 2, 2, 1, 1 },
  { VK16, VK16Bits, 157, 8, sizeof(VK16Bits), X86::VK16RegClassID, 2, 2, 1, 1 },
  { VK16WM, VK16WMBits, 513, 7, sizeof(VK16WMBits), X86::VK16WMRegClassID, 2, 2, 1, 1 },
  { SEGMENT_REG, SEGMENT_REGBits, 447, 6, sizeof(SEGMENT_REGBits), X86::SEGMENT_REGRegClassID, 2, 2, 1, 1 },
  { GR16_ABCD, GR16_ABCDBits, 415, 4, sizeof(GR16_ABCDBits), X86::GR16_ABCDRegClassID, 2, 2, 1, 1 },
  { FPCCR, FPCCRBits, 652, 1, sizeof(FPCCRBits), X86::FPCCRRegClassID, 2, 2, -1, 0 },
  { FR32X, FR32XBits, 667, 32, sizeof(FR32XBits), X86::FR32XRegClassID, 4, 4, 1, 1 },
  { FR32, FR32Bits, 27, 16, sizeof(FR32Bits), X86::FR32RegClassID, 4, 4, 1, 1 },
  { GR32, GR32Bits, 32, 16, sizeof(GR32Bits), X86::GR32RegClassID, 4, 4, 1, 1 },
  { GR32_NOAX, GR32_NOAXBits, 728, 15, sizeof(GR32_NOAXBits), X86::GR32_NOAXRegClassID, 4, 4, 1, 1 },
  { GR32_NOSP, GR32_NOSPBits, 563, 15, sizeof(GR32_NOSPBits), X86::GR32_NOSPRegClassID, 4, 4, 1, 1 },
  { GR32_NOAX_and_GR32_NOSP, GR32_NOAX_and_GR32_NOSPBits, 549, 14, sizeof(GR32_NOAX_and_GR32_NOSPBits), X86::GR32_NOAX_and_GR32_NOSPRegClassID, 4, 4, 1, 1 },
  { DEBUG_REG, DEBUG_REGBits, 425, 8, sizeof(DEBUG_REGBits), X86::DEBUG_REGRegClassID, 4, 4, 1, 1 },
  { GR32_NOREX, GR32_NOREXBits, 942, 8, sizeof(GR32_NOREXBits), X86::GR32_NOREXRegClassID, 4, 4, 1, 1 },
  { VK32, VK32Bits, 16, 8, sizeof(VK32Bits), X86::VK32RegClassID, 4, 4, 1, 1 },
  { GR32_NOAX_and_GR32_NOREX, GR32_NOAX_and_GR32_NOREXBits, 928, 7, sizeof(GR32_NOAX_and_GR32_NOREXBits), X86::GR32_NOAX_and_GR32_NOREXRegClassID, 4, 4, 1, 1 },
  { GR32_NOREX_NOSP, GR32_NOREX_NOSPBits, 620, 7, sizeof(GR32_NOREX_NOSPBits), X86::GR32_NOREX_NOSPRegClassID, 4, 4, 1, 1 },
  { RFP32, RFP32Bits, 21, 7, sizeof(RFP32Bits), X86::RFP32RegClassID, 4, 4, 1, 1 },
  { VK32WM, VK32WMBits, 487, 7, sizeof(VK32WMBits), X86::VK32WMRegClassID, 4, 4, 1, 1 },
  { GR32_NOAX_and_GR32_NOREX_NOSP, GR32_NOAX_and_GR32_NOREX_NOSPBits, 606, 6, sizeof(GR32_NOAX_and_GR32_NOREX_NOSPBits), X86::GR32_NOAX_and_GR32_NOREX_NOSPRegClassID, 4, 4, 1, 1 },
  { GR32_ABCD, GR32_ABCDBits, 395, 4, sizeof(GR32_ABCDBits), X86::GR32_ABCDRegClassID, 4, 4, 1, 1 },
  { GR32_ABCD_and_GR32_NOAX, GR32_ABCD_and_GR32_NOAXBits, 761, 3, sizeof(GR32_ABCD_and_GR32_NOAXBits), X86::GR32_ABCD_and_GR32_NOAXRegClassID, 4, 4, 1, 1 },
  { GR32_TC, GR32_TCBits, 252, 3, sizeof(GR32_TCBits), X86::GR32_TCRegClassID, 4, 4, 1, 1 },
  { GR32_AD, GR32_ADBits, 387, 2, sizeof(GR32_ADBits), X86::GR32_ADRegClassID, 4, 4, 1, 1 },
  { GR32_NOAX_and_GR32_TC, GR32_NOAX_and_GR32_TCBits, 238, 2, sizeof(GR32_NOAX_and_GR32_TCBits), X86::GR32_NOAX_and_GR32_TCRegClassID, 4, 4, 1, 1 },
  { CCR, CCRBits, 654, 1, sizeof(CCRBits), X86::CCRRegClassID, 4, 4, -1, 0 },
  { GR32_AD_and_GR32_NOAX, GR32_AD_and_GR32_NOAXBits, 716, 1, sizeof(GR32_AD_and_GR32_NOAXBits), X86::GR32_AD_and_GR32_NOAXRegClassID, 4, 4, 1, 1 },
  { RFP64, RFP64Bits, 46, 7, sizeof(RFP64Bits), X86::RFP64RegClassID, 8, 4, 1, 1 },
  { FR64X, FR64XBits, 673, 32, sizeof(FR64XBits), X86::FR64XRegClassID, 8, 8, 1, 1 },
  { GR64, GR64Bits, 57, 17, sizeof(GR64Bits), X86::GR64RegClassID, 8, 8, 1, 1 },
  { CONTROL_REG, CONTROL_REGBits, 435, 16, sizeof(CONTROL_REGBits), X86::CONTROL_REGRegClassID, 8, 8, 1, 1 },
  { FR64, FR64Bits, 52, 16, sizeof(FR64Bits), X86::FR64RegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_8bit, GR64_with_sub_8bitBits, 1008, 16, sizeof(GR64_with_sub_8bitBits), X86::GR64_with_sub_8bitRegClassID, 8, 8, 1, 1 },
  { GR64_NOSP, GR64_NOSPBits, 573, 15, sizeof(GR64_NOSPBits), X86::GR64_NOSPRegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_32bit_in_GR32_NOAX, GR64_with_sub_32bit_in_GR32_NOAXBits, 800, 15, sizeof(GR64_with_sub_32bit_in_GR32_NOAXBits), X86::GR64_with_sub_32bit_in_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSP, GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPBits, 526, 14, sizeof(GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPBits), X86::GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPRegClassID, 8, 8, 1, 1 },
  { GR64_NOREX, GR64_NOREXBits, 953, 9, sizeof(GR64_NOREXBits), X86::GR64_NOREXRegClassID, 8, 8, 1, 1 },
  { GR64_TC, GR64_TCBits, 305, 9, sizeof(GR64_TCBits), X86::GR64_TCRegClassID, 8, 8, 1, 1 },
  { GR64_NOSP_and_GR64_TC, GR64_NOSP_and_GR64_TCBits, 291, 8, sizeof(GR64_NOSP_and_GR64_TCBits), X86::GR64_NOSP_and_GR64_TCRegClassID, 8, 8, 1, 1 },
  { GR64_TCW64, GR64_TCW64Bits, 79, 8, sizeof(GR64_TCW64Bits), X86::GR64_TCW64RegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_16bit_in_GR16_NOREX, GR64_with_sub_16bit_in_GR16_NOREXBits, 964, 8, sizeof(GR64_with_sub_16bit_in_GR16_NOREXBits), X86::GR64_with_sub_16bit_in_GR16_NOREXRegClassID, 8, 8, 1, 1 },
  { VK64, VK64Bits, 41, 8, sizeof(VK64Bits), X86::VK64RegClassID, 8, 8, 1, 1 },
  { VR64, VR64Bits, 62, 8, sizeof(VR64Bits), X86::VR64RegClassID, 8, 8, 1, 1 },
  { GR64_NOREX_NOSP, GR64_NOREX_NOSPBits, 636, 7, sizeof(GR64_NOREX_NOSPBits), X86::GR64_NOREX_NOSPRegClassID, 8, 8, 1, 1 },
  { GR64_NOSP_and_GR64_TCW64, GR64_NOSP_and_GR64_TCW64Bits, 102, 7, sizeof(GR64_NOSP_and_GR64_TCW64Bits), X86::GR64_NOSP_and_GR64_TCW64RegClassID, 8, 8, 1, 1 },
  { GR64_TC_and_GR64_TCW64, GR64_TC_and_GR64_TCW64Bits, 67, 7, sizeof(GR64_TC_and_GR64_TCW64Bits), X86::GR64_TC_and_GR64_TCW64RegClassID, 8, 8, 1, 1 },
  { GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX, GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXBits, 848, 7, sizeof(GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXBits), X86::GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX, GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits, 905, 7, sizeof(GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits), X86::GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXRegClassID, 8, 8, 1, 1 },
  { VK64WM, VK64WMBits, 500, 7, sizeof(VK64WMBits), X86::VK64WMRegClassID, 8, 8, 1, 1 },
  { GR64_NOREX_and_GR64_TC, GR64_NOREX_and_GR64_TCBits, 341, 6, sizeof(GR64_NOREX_and_GR64_TCBits), X86::GR64_NOREX_and_GR64_TCRegClassID, 8, 8, 1, 1 },
  { GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAX, GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXBits, 785, 6, sizeof(GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXBits), X86::GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { GR64_TC_and_GR64_NOSP_and_GR64_TCW64, GR64_TC_and_GR64_NOSP_and_GR64_TCW64Bits, 90, 6, sizeof(GR64_TC_and_GR64_NOSP_and_GR64_TCW64Bits), X86::GR64_TC_and_GR64_NOSP_and_GR64_TCW64RegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSP, GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPBits, 583, 6, sizeof(GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPBits), X86::GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPRegClassID, 8, 8, 1, 1 },
  { GR64_NOREX_NOSP_and_GR64_TC, GR64_NOREX_NOSP_and_GR64_TCBits, 313, 5, sizeof(GR64_NOREX_NOSP_and_GR64_TCBits), X86::GR64_NOREX_NOSP_and_GR64_TCRegClassID, 8, 8, 1, 1 },
  { GR64_TCW64_and_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX, GR64_TCW64_and_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXBits, 833, 5, sizeof(GR64_TCW64_and_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXBits), X86::GR64_TCW64_and_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { GR64_ABCD, GR64_ABCDBits, 405, 4, sizeof(GR64_ABCDBits), X86::GR64_ABCDRegClassID, 8, 8, 1, 1 },
  { GR64_NOREX_and_GR64_TCW64, GR64_NOREX_and_GR64_TCW64Bits, 127, 4, sizeof(GR64_NOREX_and_GR64_TCW64Bits), X86::GR64_NOREX_and_GR64_TCW64RegClassID, 8, 8, 1, 1 },
  { GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX, GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits, 893, 4, sizeof(GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits), X86::GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXRegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAX, GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXBits, 738, 3, sizeof(GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXBits), X86::GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_32bit_in_GR32_TC, GR64_with_sub_32bit_in_GR32_TCBits, 260, 3, sizeof(GR64_with_sub_32bit_in_GR32_TCBits), X86::GR64_with_sub_32bit_in_GR32_TCRegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_32bit_in_GR32_AD, GR64_with_sub_32bit_in_GR32_ADBits, 364, 2, sizeof(GR64_with_sub_32bit_in_GR32_ADBits), X86::GR64_with_sub_32bit_in_GR32_ADRegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TC, GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCBits, 215, 2, sizeof(GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCBits), X86::GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCRegClassID, 8, 8, 1, 1 },
  { GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAX, GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXBits, 693, 1, sizeof(GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXBits), X86::GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { RST, RSTBits, 663, 8, sizeof(RSTBits), X86::RSTRegClassID, 10, 4, 1, 0 },
  { RFP80, RFP80Bits, 0, 7, sizeof(RFP80Bits), X86::RFP80RegClassID, 10, 4, 1, 1 },
  { VR128X, VR128XBits, 686, 32, sizeof(VR128XBits), X86::VR128XRegClassID, 16, 16, 1, 1 },
  { FR128, FR128Bits, 195, 16, sizeof(FR128Bits), X86::FR128RegClassID, 16, 16, 1, 1 },
  { VR128, VR128Bits, 201, 16, sizeof(VR128Bits), X86::VR128RegClassID, 16, 16, 1, 1 },
  { BNDR, BNDRBits, 658, 4, sizeof(BNDRBits), X86::BNDRRegClassID, 16, 16, 1, 1 },
  { VR256X, VR256XBits, 679, 32, sizeof(VR256XBits), X86::VR256XRegClassID, 32, 32, 1, 1 },
  { VR256, VR256Bits, 167, 16, sizeof(VR256Bits), X86::VR256RegClassID, 32, 32, 1, 1 },
  { VR512, VR512Bits, 10, 32, sizeof(VR512Bits), X86::VR512RegClassID, 64, 64, 1, 1 },
  { VR512_with_sub_xmm_in_FR128, VR512_with_sub_xmm_in_FR128Bits, 173, 16, sizeof(VR512_with_sub_xmm_in_FR128Bits), X86::VR512_with_sub_xmm_in_FR128RegClassID, 64, 64, 1, 1 },
};

// X86 Dwarf<->LLVM register mappings.
extern const MCRegisterInfo::DwarfLLVMRegPair X86DwarfFlavour0Dwarf2L[] = {
  { 0U, X86::RAX },
  { 1U, X86::RDX },
  { 2U, X86::RCX },
  { 3U, X86::RBX },
  { 4U, X86::RSI },
  { 5U, X86::RDI },
  { 6U, X86::RBP },
  { 7U, X86::RSP },
  { 8U, X86::R8 },
  { 9U, X86::R9 },
  { 10U, X86::R10 },
  { 11U, X86::R11 },
  { 12U, X86::R12 },
  { 13U, X86::R13 },
  { 14U, X86::R14 },
  { 15U, X86::R15 },
  { 16U, X86::RIP },
  { 17U, X86::XMM0 },
  { 18U, X86::XMM1 },
  { 19U, X86::XMM2 },
  { 20U, X86::XMM3 },
  { 21U, X86::XMM4 },
  { 22U, X86::XMM5 },
  { 23U, X86::XMM6 },
  { 24U, X86::XMM7 },
  { 25U, X86::XMM8 },
  { 26U, X86::XMM9 },
  { 27U, X86::XMM10 },
  { 28U, X86::XMM11 },
  { 29U, X86::XMM12 },
  { 30U, X86::XMM13 },
  { 31U, X86::XMM14 },
  { 32U, X86::XMM15 },
  { 33U, X86::ST0 },
  { 34U, X86::ST1 },
  { 35U, X86::ST2 },
  { 36U, X86::ST3 },
  { 37U, X86::ST4 },
  { 38U, X86::ST5 },
  { 39U, X86::ST6 },
  { 40U, X86::ST7 },
  { 41U, X86::MM0 },
  { 42U, X86::MM1 },
  { 43U, X86::MM2 },
  { 44U, X86::MM3 },
  { 45U, X86::MM4 },
  { 46U, X86::MM5 },
  { 47U, X86::MM6 },
  { 48U, X86::MM7 },
  { 60U, X86::XMM16 },
  { 61U, X86::XMM17 },
  { 62U, X86::XMM18 },
  { 63U, X86::XMM19 },
  { 64U, X86::XMM20 },
  { 65U, X86::XMM21 },
  { 66U, X86::XMM22 },
  { 67U, X86::XMM23 },
  { 68U, X86::XMM24 },
  { 69U, X86::XMM25 },
  { 70U, X86::XMM26 },
  { 71U, X86::XMM27 },
  { 72U, X86::XMM28 },
  { 73U, X86::XMM29 },
  { 74U, X86::XMM30 },
  { 75U, X86::XMM31 },
  { 118U, X86::K0 },
  { 119U, X86::K1 },
  { 120U, X86::K2 },
  { 121U, X86::K3 },
  { 122U, X86::K4 },
  { 123U, X86::K5 },
  { 124U, X86::K6 },
  { 125U, X86::K7 },
};
extern const unsigned X86DwarfFlavour0Dwarf2LSize = array_lengthof(X86DwarfFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair X86DwarfFlavour1Dwarf2L[] = {
  { 0U, X86::EAX },
  { 1U, X86::ECX },
  { 2U, X86::EDX },
  { 3U, X86::EBX },
  { 4U, X86::EBP },
  { 5U, X86::ESP },
  { 6U, X86::ESI },
  { 7U, X86::EDI },
  { 8U, X86::EIP },
  { 12U, X86::ST0 },
  { 13U, X86::ST1 },
  { 14U, X86::ST2 },
  { 15U, X86::ST3 },
  { 16U, X86::ST4 },
  { 17U, X86::ST5 },
  { 18U, X86::ST6 },
  { 19U, X86::ST7 },
  { 21U, X86::XMM0 },
  { 22U, X86::XMM1 },
  { 23U, X86::XMM2 },
  { 24U, X86::XMM3 },
  { 25U, X86::XMM4 },
  { 26U, X86::XMM5 },
  { 27U, X86::XMM6 },
  { 28U, X86::XMM7 },
  { 29U, X86::MM0 },
  { 30U, X86::MM1 },
  { 31U, X86::MM2 },
  { 32U, X86::MM3 },
  { 33U, X86::MM4 },
  { 34U, X86::MM5 },
  { 35U, X86::MM6 },
  { 36U, X86::MM7 },
};
extern const unsigned X86DwarfFlavour1Dwarf2LSize = array_lengthof(X86DwarfFlavour1Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair X86DwarfFlavour2Dwarf2L[] = {
  { 0U, X86::EAX },
  { 1U, X86::ECX },
  { 2U, X86::EDX },
  { 3U, X86::EBX },
  { 4U, X86::ESP },
  { 5U, X86::EBP },
  { 6U, X86::ESI },
  { 7U, X86::EDI },
  { 8U, X86::EIP },
  { 11U, X86::ST0 },
  { 12U, X86::ST1 },
  { 13U, X86::ST2 },
  { 14U, X86::ST3 },
  { 15U, X86::ST4 },
  { 16U, X86::ST5 },
  { 17U, X86::ST6 },
  { 18U, X86::ST7 },
  { 21U, X86::XMM0 },
  { 22U, X86::XMM1 },
  { 23U, X86::XMM2 },
  { 24U, X86::XMM3 },
  { 25U, X86::XMM4 },
  { 26U, X86::XMM5 },
  { 27U, X86::XMM6 },
  { 28U, X86::XMM7 },
  { 29U, X86::MM0 },
  { 30U, X86::MM1 },
  { 31U, X86::MM2 },
  { 32U, X86::MM3 },
  { 33U, X86::MM4 },
  { 34U, X86::MM5 },
  { 35U, X86::MM6 },
  { 36U, X86::MM7 },
};
extern const unsigned X86DwarfFlavour2Dwarf2LSize = array_lengthof(X86DwarfFlavour2Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair X86EHFlavour0Dwarf2L[] = {
  { 0U, X86::RAX },
  { 1U, X86::RDX },
  { 2U, X86::RCX },
  { 3U, X86::RBX },
  { 4U, X86::RSI },
  { 5U, X86::RDI },
  { 6U, X86::RBP },
  { 7U, X86::RSP },
  { 8U, X86::R8 },
  { 9U, X86::R9 },
  { 10U, X86::R10 },
  { 11U, X86::R11 },
  { 12U, X86::R12 },
  { 13U, X86::R13 },
  { 14U, X86::R14 },
  { 15U, X86::R15 },
  { 16U, X86::RIP },
  { 17U, X86::XMM0 },
  { 18U, X86::XMM1 },
  { 19U, X86::XMM2 },
  { 20U, X86::XMM3 },
  { 21U, X86::XMM4 },
  { 22U, X86::XMM5 },
  { 23U, X86::XMM6 },
  { 24U, X86::XMM7 },
  { 25U, X86::XMM8 },
  { 26U, X86::XMM9 },
  { 27U, X86::XMM10 },
  { 28U, X86::XMM11 },
  { 29U, X86::XMM12 },
  { 30U, X86::XMM13 },
  { 31U, X86::XMM14 },
  { 32U, X86::XMM15 },
  { 33U, X86::ST0 },
  { 34U, X86::ST1 },
  { 35U, X86::ST2 },
  { 36U, X86::ST3 },
  { 37U, X86::ST4 },
  { 38U, X86::ST5 },
  { 39U, X86::ST6 },
  { 40U, X86::ST7 },
  { 41U, X86::MM0 },
  { 42U, X86::MM1 },
  { 43U, X86::MM2 },
  { 44U, X86::MM3 },
  { 45U, X86::MM4 },
  { 46U, X86::MM5 },
  { 47U, X86::MM6 },
  { 48U, X86::MM7 },
  { 60U, X86::XMM16 },
  { 61U, X86::XMM17 },
  { 62U, X86::XMM18 },
  { 63U, X86::XMM19 },
  { 64U, X86::XMM20 },
  { 65U, X86::XMM21 },
  { 66U, X86::XMM22 },
  { 67U, X86::XMM23 },
  { 68U, X86::XMM24 },
  { 69U, X86::XMM25 },
  { 70U, X86::XMM26 },
  { 71U, X86::XMM27 },
  { 72U, X86::XMM28 },
  { 73U, X86::XMM29 },
  { 74U, X86::XMM30 },
  { 75U, X86::XMM31 },
  { 118U, X86::K0 },
  { 119U, X86::K1 },
  { 120U, X86::K2 },
  { 121U, X86::K3 },
  { 122U, X86::K4 },
  { 123U, X86::K5 },
  { 124U, X86::K6 },
  { 125U, X86::K7 },
};
extern const unsigned X86EHFlavour0Dwarf2LSize = array_lengthof(X86EHFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair X86EHFlavour1Dwarf2L[] = {
  { 0U, X86::EAX },
  { 1U, X86::ECX },
  { 2U, X86::EDX },
  { 3U, X86::EBX },
  { 4U, X86::EBP },
  { 5U, X86::ESP },
  { 6U, X86::ESI },
  { 7U, X86::EDI },
  { 8U, X86::EIP },
  { 12U, X86::ST0 },
  { 13U, X86::ST1 },
  { 14U, X86::ST2 },
  { 15U, X86::ST3 },
  { 16U, X86::ST4 },
  { 17U, X86::ST5 },
  { 18U, X86::ST6 },
  { 19U, X86::ST7 },
  { 21U, X86::XMM0 },
  { 22U, X86::XMM1 },
  { 23U, X86::XMM2 },
  { 24U, X86::XMM3 },
  { 25U, X86::XMM4 },
  { 26U, X86::XMM5 },
  { 27U, X86::XMM6 },
  { 28U, X86::XMM7 },
  { 29U, X86::MM0 },
  { 30U, X86::MM1 },
  { 31U, X86::MM2 },
  { 32U, X86::MM3 },
  { 33U, X86::MM4 },
  { 34U, X86::MM5 },
  { 35U, X86::MM6 },
  { 36U, X86::MM7 },
};
extern const unsigned X86EHFlavour1Dwarf2LSize = array_lengthof(X86EHFlavour1Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair X86EHFlavour2Dwarf2L[] = {
  { 0U, X86::EAX },
  { 1U, X86::ECX },
  { 2U, X86::EDX },
  { 3U, X86::EBX },
  { 4U, X86::ESP },
  { 5U, X86::EBP },
  { 6U, X86::ESI },
  { 7U, X86::EDI },
  { 8U, X86::EIP },
  { 11U, X86::ST0 },
  { 12U, X86::ST1 },
  { 13U, X86::ST2 },
  { 14U, X86::ST3 },
  { 15U, X86::ST4 },
  { 16U, X86::ST5 },
  { 17U, X86::ST6 },
  { 18U, X86::ST7 },
  { 21U, X86::XMM0 },
  { 22U, X86::XMM1 },
  { 23U, X86::XMM2 },
  { 24U, X86::XMM3 },
  { 25U, X86::XMM4 },
  { 26U, X86::XMM5 },
  { 27U, X86::XMM6 },
  { 28U, X86::XMM7 },
  { 29U, X86::MM0 },
  { 30U, X86::MM1 },
  { 31U, X86::MM2 },
  { 32U, X86::MM3 },
  { 33U, X86::MM4 },
  { 34U, X86::MM5 },
  { 35U, X86::MM6 },
  { 36U, X86::MM7 },
};
extern const unsigned X86EHFlavour2Dwarf2LSize = array_lengthof(X86EHFlavour2Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair X86DwarfFlavour0L2Dwarf[] = {
  { X86::EAX, -2U },
  { X86::EBP, -2U },
  { X86::EBX, -2U },
  { X86::ECX, -2U },
  { X86::EDI, -2U },
  { X86::EDX, -2U },
  { X86::EIP, -2U },
  { X86::ESI, -2U },
  { X86::ESP, -2U },
  { X86::RAX, 0U },
  { X86::RBP, 6U },
  { X86::RBX, 3U },
  { X86::RCX, 2U },
  { X86::RDI, 5U },
  { X86::RDX, 1U },
  { X86::RIP, 16U },
  { X86::RSI, 4U },
  { X86::RSP, 7U },
  { X86::K0, 118U },
  { X86::K1, 119U },
  { X86::K2, 120U },
  { X86::K3, 121U },
  { X86::K4, 122U },
  { X86::K5, 123U },
  { X86::K6, 124U },
  { X86::K7, 125U },
  { X86::MM0, 41U },
  { X86::MM1, 42U },
  { X86::MM2, 43U },
  { X86::MM3, 44U },
  { X86::MM4, 45U },
  { X86::MM5, 46U },
  { X86::MM6, 47U },
  { X86::MM7, 48U },
  { X86::R8, 8U },
  { X86::R9, 9U },
  { X86::R10, 10U },
  { X86::R11, 11U },
  { X86::R12, 12U },
  { X86::R13, 13U },
  { X86::R14, 14U },
  { X86::R15, 15U },
  { X86::ST0, 33U },
  { X86::ST1, 34U },
  { X86::ST2, 35U },
  { X86::ST3, 36U },
  { X86::ST4, 37U },
  { X86::ST5, 38U },
  { X86::ST6, 39U },
  { X86::ST7, 40U },
  { X86::XMM0, 17U },
  { X86::XMM1, 18U },
  { X86::XMM2, 19U },
  { X86::XMM3, 20U },
  { X86::XMM4, 21U },
  { X86::XMM5, 22U },
  { X86::XMM6, 23U },
  { X86::XMM7, 24U },
  { X86::XMM8, 25U },
  { X86::XMM9, 26U },
  { X86::XMM10, 27U },
  { X86::XMM11, 28U },
  { X86::XMM12, 29U },
  { X86::XMM13, 30U },
  { X86::XMM14, 31U },
  { X86::XMM15, 32U },
  { X86::XMM16, 60U },
  { X86::XMM17, 61U },
  { X86::XMM18, 62U },
  { X86::XMM19, 63U },
  { X86::XMM20, 64U },
  { X86::XMM21, 65U },
  { X86::XMM22, 66U },
  { X86::XMM23, 67U },
  { X86::XMM24, 68U },
  { X86::XMM25, 69U },
  { X86::XMM26, 70U },
  { X86::XMM27, 71U },
  { X86::XMM28, 72U },
  { X86::XMM29, 73U },
  { X86::XMM30, 74U },
  { X86::XMM31, 75U },
  { X86::YMM0, 17U },
  { X86::YMM1, 18U },
  { X86::YMM2, 19U },
  { X86::YMM3, 20U },
  { X86::YMM4, 21U },
  { X86::YMM5, 22U },
  { X86::YMM6, 23U },
  { X86::YMM7, 24U },
  { X86::YMM8, 25U },
  { X86::YMM9, 26U },
  { X86::YMM10, 27U },
  { X86::YMM11, 28U },
  { X86::YMM12, 29U },
  { X86::YMM13, 30U },
  { X86::YMM14, 31U },
  { X86::YMM15, 32U },
  { X86::YMM16, 60U },
  { X86::YMM17, 61U },
  { X86::YMM18, 62U },
  { X86::YMM19, 63U },
  { X86::YMM20, 64U },
  { X86::YMM21, 65U },
  { X86::YMM22, 66U },
  { X86::YMM23, 67U },
  { X86::YMM24, 68U },
  { X86::YMM25, 69U },
  { X86::YMM26, 70U },
  { X86::YMM27, 71U },
  { X86::YMM28, 72U },
  { X86::YMM29, 73U },
  { X86::YMM30, 74U },
  { X86::YMM31, 75U },
  { X86::ZMM0, 17U },
  { X86::ZMM1, 18U },
  { X86::ZMM2, 19U },
  { X86::ZMM3, 20U },
  { X86::ZMM4, 21U },
  { X86::ZMM5, 22U },
  { X86::ZMM6, 23U },
  { X86::ZMM7, 24U },
  { X86::ZMM8, 25U },
  { X86::ZMM9, 26U },
  { X86::ZMM10, 27U },
  { X86::ZMM11, 28U },
  { X86::ZMM12, 29U },
  { X86::ZMM13, 30U },
  { X86::ZMM14, 31U },
  { X86::ZMM15, 32U },
  { X86::ZMM16, 60U },
  { X86::ZMM17, 61U },
  { X86::ZMM18, 62U },
  { X86::ZMM19, 63U },
  { X86::ZMM20, 64U },
  { X86::ZMM21, 65U },
  { X86::ZMM22, 66U },
  { X86::ZMM23, 67U },
  { X86::ZMM24, 68U },
  { X86::ZMM25, 69U },
  { X86::ZMM26, 70U },
  { X86::ZMM27, 71U },
  { X86::ZMM28, 72U },
  { X86::ZMM29, 73U },
  { X86::ZMM30, 74U },
  { X86::ZMM31, 75U },
};
extern const unsigned X86DwarfFlavour0L2DwarfSize = array_lengthof(X86DwarfFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair X86DwarfFlavour1L2Dwarf[] = {
  { X86::EAX, 0U },
  { X86::EBP, 4U },
  { X86::EBX, 3U },
  { X86::ECX, 1U },
  { X86::EDI, 7U },
  { X86::EDX, 2U },
  { X86::EIP, 8U },
  { X86::ESI, 6U },
  { X86::ESP, 5U },
  { X86::RAX, -2U },
  { X86::RBP, -2U },
  { X86::RBX, -2U },
  { X86::RCX, -2U },
  { X86::RDI, -2U },
  { X86::RDX, -2U },
  { X86::RIP, -2U },
  { X86::RSI, -2U },
  { X86::RSP, -2U },
  { X86::K0, -2U },
  { X86::K1, -2U },
  { X86::K2, -2U },
  { X86::K3, -2U },
  { X86::K4, -2U },
  { X86::K5, -2U },
  { X86::K6, -2U },
  { X86::K7, -2U },
  { X86::MM0, 29U },
  { X86::MM1, 30U },
  { X86::MM2, 31U },
  { X86::MM3, 32U },
  { X86::MM4, 33U },
  { X86::MM5, 34U },
  { X86::MM6, 35U },
  { X86::MM7, 36U },
  { X86::R8, -2U },
  { X86::R9, -2U },
  { X86::R10, -2U },
  { X86::R11, -2U },
  { X86::R12, -2U },
  { X86::R13, -2U },
  { X86::R14, -2U },
  { X86::R15, -2U },
  { X86::ST0, 12U },
  { X86::ST1, 13U },
  { X86::ST2, 14U },
  { X86::ST3, 15U },
  { X86::ST4, 16U },
  { X86::ST5, 17U },
  { X86::ST6, 18U },
  { X86::ST7, 19U },
  { X86::XMM0, 21U },
  { X86::XMM1, 22U },
  { X86::XMM2, 23U },
  { X86::XMM3, 24U },
  { X86::XMM4, 25U },
  { X86::XMM5, 26U },
  { X86::XMM6, 27U },
  { X86::XMM7, 28U },
  { X86::XMM8, -2U },
  { X86::XMM9, -2U },
  { X86::XMM10, -2U },
  { X86::XMM11, -2U },
  { X86::XMM12, -2U },
  { X86::XMM13, -2U },
  { X86::XMM14, -2U },
  { X86::XMM15, -2U },
  { X86::XMM16, -2U },
  { X86::XMM17, -2U },
  { X86::XMM18, -2U },
  { X86::XMM19, -2U },
  { X86::XMM20, -2U },
  { X86::XMM21, -2U },
  { X86::XMM22, -2U },
  { X86::XMM23, -2U },
  { X86::XMM24, -2U },
  { X86::XMM25, -2U },
  { X86::XMM26, -2U },
  { X86::XMM27, -2U },
  { X86::XMM28, -2U },
  { X86::XMM29, -2U },
  { X86::XMM30, -2U },
  { X86::XMM31, -2U },
  { X86::YMM0, 21U },
  { X86::YMM1, 22U },
  { X86::YMM2, 23U },
  { X86::YMM3, 24U },
  { X86::YMM4, 25U },
  { X86::YMM5, 26U },
  { X86::YMM6, 27U },
  { X86::YMM7, 28U },
  { X86::YMM8, -2U },
  { X86::YMM9, -2U },
  { X86::YMM10, -2U },
  { X86::YMM11, -2U },
  { X86::YMM12, -2U },
  { X86::YMM13, -2U },
  { X86::YMM14, -2U },
  { X86::YMM15, -2U },
  { X86::YMM16, -2U },
  { X86::YMM17, -2U },
  { X86::YMM18, -2U },
  { X86::YMM19, -2U },
  { X86::YMM20, -2U },
  { X86::YMM21, -2U },
  { X86::YMM22, -2U },
  { X86::YMM23, -2U },
  { X86::YMM24, -2U },
  { X86::YMM25, -2U },
  { X86::YMM26, -2U },
  { X86::YMM27, -2U },
  { X86::YMM28, -2U },
  { X86::YMM29, -2U },
  { X86::YMM30, -2U },
  { X86::YMM31, -2U },
  { X86::ZMM0, 21U },
  { X86::ZMM1, 22U },
  { X86::ZMM2, 23U },
  { X86::ZMM3, 24U },
  { X86::ZMM4, 25U },
  { X86::ZMM5, 26U },
  { X86::ZMM6, 27U },
  { X86::ZMM7, 28U },
  { X86::ZMM8, -2U },
  { X86::ZMM9, -2U },
  { X86::ZMM10, -2U },
  { X86::ZMM11, -2U },
  { X86::ZMM12, -2U },
  { X86::ZMM13, -2U },
  { X86::ZMM14, -2U },
  { X86::ZMM15, -2U },
  { X86::ZMM16, -2U },
  { X86::ZMM17, -2U },
  { X86::ZMM18, -2U },
  { X86::ZMM19, -2U },
  { X86::ZMM20, -2U },
  { X86::ZMM21, -2U },
  { X86::ZMM22, -2U },
  { X86::ZMM23, -2U },
  { X86::ZMM24, -2U },
  { X86::ZMM25, -2U },
  { X86::ZMM26, -2U },
  { X86::ZMM27, -2U },
  { X86::ZMM28, -2U },
  { X86::ZMM29, -2U },
  { X86::ZMM30, -2U },
  { X86::ZMM31, -2U },
};
extern const unsigned X86DwarfFlavour1L2DwarfSize = array_lengthof(X86DwarfFlavour1L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair X86DwarfFlavour2L2Dwarf[] = {
  { X86::EAX, 0U },
  { X86::EBP, 5U },
  { X86::EBX, 3U },
  { X86::ECX, 1U },
  { X86::EDI, 7U },
  { X86::EDX, 2U },
  { X86::EIP, 8U },
  { X86::ESI, 6U },
  { X86::ESP, 4U },
  { X86::RAX, -2U },
  { X86::RBP, -2U },
  { X86::RBX, -2U },
  { X86::RCX, -2U },
  { X86::RDI, -2U },
  { X86::RDX, -2U },
  { X86::RIP, -2U },
  { X86::RSI, -2U },
  { X86::RSP, -2U },
  { X86::K0, -2U },
  { X86::K1, -2U },
  { X86::K2, -2U },
  { X86::K3, -2U },
  { X86::K4, -2U },
  { X86::K5, -2U },
  { X86::K6, -2U },
  { X86::K7, -2U },
  { X86::MM0, 29U },
  { X86::MM1, 30U },
  { X86::MM2, 31U },
  { X86::MM3, 32U },
  { X86::MM4, 33U },
  { X86::MM5, 34U },
  { X86::MM6, 35U },
  { X86::MM7, 36U },
  { X86::R8, -2U },
  { X86::R9, -2U },
  { X86::R10, -2U },
  { X86::R11, -2U },
  { X86::R12, -2U },
  { X86::R13, -2U },
  { X86::R14, -2U },
  { X86::R15, -2U },
  { X86::ST0, 11U },
  { X86::ST1, 12U },
  { X86::ST2, 13U },
  { X86::ST3, 14U },
  { X86::ST4, 15U },
  { X86::ST5, 16U },
  { X86::ST6, 17U },
  { X86::ST7, 18U },
  { X86::XMM0, 21U },
  { X86::XMM1, 22U },
  { X86::XMM2, 23U },
  { X86::XMM3, 24U },
  { X86::XMM4, 25U },
  { X86::XMM5, 26U },
  { X86::XMM6, 27U },
  { X86::XMM7, 28U },
  { X86::XMM8, -2U },
  { X86::XMM9, -2U },
  { X86::XMM10, -2U },
  { X86::XMM11, -2U },
  { X86::XMM12, -2U },
  { X86::XMM13, -2U },
  { X86::XMM14, -2U },
  { X86::XMM15, -2U },
  { X86::XMM16, -2U },
  { X86::XMM17, -2U },
  { X86::XMM18, -2U },
  { X86::XMM19, -2U },
  { X86::XMM20, -2U },
  { X86::XMM21, -2U },
  { X86::XMM22, -2U },
  { X86::XMM23, -2U },
  { X86::XMM24, -2U },
  { X86::XMM25, -2U },
  { X86::XMM26, -2U },
  { X86::XMM27, -2U },
  { X86::XMM28, -2U },
  { X86::XMM29, -2U },
  { X86::XMM30, -2U },
  { X86::XMM31, -2U },
  { X86::YMM0, 21U },
  { X86::YMM1, 22U },
  { X86::YMM2, 23U },
  { X86::YMM3, 24U },
  { X86::YMM4, 25U },
  { X86::YMM5, 26U },
  { X86::YMM6, 27U },
  { X86::YMM7, 28U },
  { X86::YMM8, -2U },
  { X86::YMM9, -2U },
  { X86::YMM10, -2U },
  { X86::YMM11, -2U },
  { X86::YMM12, -2U },
  { X86::YMM13, -2U },
  { X86::YMM14, -2U },
  { X86::YMM15, -2U },
  { X86::YMM16, -2U },
  { X86::YMM17, -2U },
  { X86::YMM18, -2U },
  { X86::YMM19, -2U },
  { X86::YMM20, -2U },
  { X86::YMM21, -2U },
  { X86::YMM22, -2U },
  { X86::YMM23, -2U },
  { X86::YMM24, -2U },
  { X86::YMM25, -2U },
  { X86::YMM26, -2U },
  { X86::YMM27, -2U },
  { X86::YMM28, -2U },
  { X86::YMM29, -2U },
  { X86::YMM30, -2U },
  { X86::YMM31, -2U },
  { X86::ZMM0, 21U },
  { X86::ZMM1, 22U },
  { X86::ZMM2, 23U },
  { X86::ZMM3, 24U },
  { X86::ZMM4, 25U },
  { X86::ZMM5, 26U },
  { X86::ZMM6, 27U },
  { X86::ZMM7, 28U },
  { X86::ZMM8, -2U },
  { X86::ZMM9, -2U },
  { X86::ZMM10, -2U },
  { X86::ZMM11, -2U },
  { X86::ZMM12, -2U },
  { X86::ZMM13, -2U },
  { X86::ZMM14, -2U },
  { X86::ZMM15, -2U },
  { X86::ZMM16, -2U },
  { X86::ZMM17, -2U },
  { X86::ZMM18, -2U },
  { X86::ZMM19, -2U },
  { X86::ZMM20, -2U },
  { X86::ZMM21, -2U },
  { X86::ZMM22, -2U },
  { X86::ZMM23, -2U },
  { X86::ZMM24, -2U },
  { X86::ZMM25, -2U },
  { X86::ZMM26, -2U },
  { X86::ZMM27, -2U },
  { X86::ZMM28, -2U },
  { X86::ZMM29, -2U },
  { X86::ZMM30, -2U },
  { X86::ZMM31, -2U },
};
extern const unsigned X86DwarfFlavour2L2DwarfSize = array_lengthof(X86DwarfFlavour2L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair X86EHFlavour0L2Dwarf[] = {
  { X86::EAX, -2U },
  { X86::EBP, -2U },
  { X86::EBX, -2U },
  { X86::ECX, -2U },
  { X86::EDI, -2U },
  { X86::EDX, -2U },
  { X86::EIP, -2U },
  { X86::ESI, -2U },
  { X86::ESP, -2U },
  { X86::RAX, 0U },
  { X86::RBP, 6U },
  { X86::RBX, 3U },
  { X86::RCX, 2U },
  { X86::RDI, 5U },
  { X86::RDX, 1U },
  { X86::RIP, 16U },
  { X86::RSI, 4U },
  { X86::RSP, 7U },
  { X86::K0, 118U },
  { X86::K1, 119U },
  { X86::K2, 120U },
  { X86::K3, 121U },
  { X86::K4, 122U },
  { X86::K5, 123U },
  { X86::K6, 124U },
  { X86::K7, 125U },
  { X86::MM0, 41U },
  { X86::MM1, 42U },
  { X86::MM2, 43U },
  { X86::MM3, 44U },
  { X86::MM4, 45U },
  { X86::MM5, 46U },
  { X86::MM6, 47U },
  { X86::MM7, 48U },
  { X86::R8, 8U },
  { X86::R9, 9U },
  { X86::R10, 10U },
  { X86::R11, 11U },
  { X86::R12, 12U },
  { X86::R13, 13U },
  { X86::R14, 14U },
  { X86::R15, 15U },
  { X86::ST0, 33U },
  { X86::ST1, 34U },
  { X86::ST2, 35U },
  { X86::ST3, 36U },
  { X86::ST4, 37U },
  { X86::ST5, 38U },
  { X86::ST6, 39U },
  { X86::ST7, 40U },
  { X86::XMM0, 17U },
  { X86::XMM1, 18U },
  { X86::XMM2, 19U },
  { X86::XMM3, 20U },
  { X86::XMM4, 21U },
  { X86::XMM5, 22U },
  { X86::XMM6, 23U },
  { X86::XMM7, 24U },
  { X86::XMM8, 25U },
  { X86::XMM9, 26U },
  { X86::XMM10, 27U },
  { X86::XMM11, 28U },
  { X86::XMM12, 29U },
  { X86::XMM13, 30U },
  { X86::XMM14, 31U },
  { X86::XMM15, 32U },
  { X86::XMM16, 60U },
  { X86::XMM17, 61U },
  { X86::XMM18, 62U },
  { X86::XMM19, 63U },
  { X86::XMM20, 64U },
  { X86::XMM21, 65U },
  { X86::XMM22, 66U },
  { X86::XMM23, 67U },
  { X86::XMM24, 68U },
  { X86::XMM25, 69U },
  { X86::XMM26, 70U },
  { X86::XMM27, 71U },
  { X86::XMM28, 72U },
  { X86::XMM29, 73U },
  { X86::XMM30, 74U },
  { X86::XMM31, 75U },
  { X86::YMM0, 17U },
  { X86::YMM1, 18U },
  { X86::YMM2, 19U },
  { X86::YMM3, 20U },
  { X86::YMM4, 21U },
  { X86::YMM5, 22U },
  { X86::YMM6, 23U },
  { X86::YMM7, 24U },
  { X86::YMM8, 25U },
  { X86::YMM9, 26U },
  { X86::YMM10, 27U },
  { X86::YMM11, 28U },
  { X86::YMM12, 29U },
  { X86::YMM13, 30U },
  { X86::YMM14, 31U },
  { X86::YMM15, 32U },
  { X86::YMM16, 60U },
  { X86::YMM17, 61U },
  { X86::YMM18, 62U },
  { X86::YMM19, 63U },
  { X86::YMM20, 64U },
  { X86::YMM21, 65U },
  { X86::YMM22, 66U },
  { X86::YMM23, 67U },
  { X86::YMM24, 68U },
  { X86::YMM25, 69U },
  { X86::YMM26, 70U },
  { X86::YMM27, 71U },
  { X86::YMM28, 72U },
  { X86::YMM29, 73U },
  { X86::YMM30, 74U },
  { X86::YMM31, 75U },
  { X86::ZMM0, 17U },
  { X86::ZMM1, 18U },
  { X86::ZMM2, 19U },
  { X86::ZMM3, 20U },
  { X86::ZMM4, 21U },
  { X86::ZMM5, 22U },
  { X86::ZMM6, 23U },
  { X86::ZMM7, 24U },
  { X86::ZMM8, 25U },
  { X86::ZMM9, 26U },
  { X86::ZMM10, 27U },
  { X86::ZMM11, 28U },
  { X86::ZMM12, 29U },
  { X86::ZMM13, 30U },
  { X86::ZMM14, 31U },
  { X86::ZMM15, 32U },
  { X86::ZMM16, 60U },
  { X86::ZMM17, 61U },
  { X86::ZMM18, 62U },
  { X86::ZMM19, 63U },
  { X86::ZMM20, 64U },
  { X86::ZMM21, 65U },
  { X86::ZMM22, 66U },
  { X86::ZMM23, 67U },
  { X86::ZMM24, 68U },
  { X86::ZMM25, 69U },
  { X86::ZMM26, 70U },
  { X86::ZMM27, 71U },
  { X86::ZMM28, 72U },
  { X86::ZMM29, 73U },
  { X86::ZMM30, 74U },
  { X86::ZMM31, 75U },
};
extern const unsigned X86EHFlavour0L2DwarfSize = array_lengthof(X86EHFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair X86EHFlavour1L2Dwarf[] = {
  { X86::EAX, 0U },
  { X86::EBP, 4U },
  { X86::EBX, 3U },
  { X86::ECX, 1U },
  { X86::EDI, 7U },
  { X86::EDX, 2U },
  { X86::EIP, 8U },
  { X86::ESI, 6U },
  { X86::ESP, 5U },
  { X86::RAX, -2U },
  { X86::RBP, -2U },
  { X86::RBX, -2U },
  { X86::RCX, -2U },
  { X86::RDI, -2U },
  { X86::RDX, -2U },
  { X86::RIP, -2U },
  { X86::RSI, -2U },
  { X86::RSP, -2U },
  { X86::K0, -2U },
  { X86::K1, -2U },
  { X86::K2, -2U },
  { X86::K3, -2U },
  { X86::K4, -2U },
  { X86::K5, -2U },
  { X86::K6, -2U },
  { X86::K7, -2U },
  { X86::MM0, 29U },
  { X86::MM1, 30U },
  { X86::MM2, 31U },
  { X86::MM3, 32U },
  { X86::MM4, 33U },
  { X86::MM5, 34U },
  { X86::MM6, 35U },
  { X86::MM7, 36U },
  { X86::R8, -2U },
  { X86::R9, -2U },
  { X86::R10, -2U },
  { X86::R11, -2U },
  { X86::R12, -2U },
  { X86::R13, -2U },
  { X86::R14, -2U },
  { X86::R15, -2U },
  { X86::ST0, 12U },
  { X86::ST1, 13U },
  { X86::ST2, 14U },
  { X86::ST3, 15U },
  { X86::ST4, 16U },
  { X86::ST5, 17U },
  { X86::ST6, 18U },
  { X86::ST7, 19U },
  { X86::XMM0, 21U },
  { X86::XMM1, 22U },
  { X86::XMM2, 23U },
  { X86::XMM3, 24U },
  { X86::XMM4, 25U },
  { X86::XMM5, 26U },
  { X86::XMM6, 27U },
  { X86::XMM7, 28U },
  { X86::XMM8, -2U },
  { X86::XMM9, -2U },
  { X86::XMM10, -2U },
  { X86::XMM11, -2U },
  { X86::XMM12, -2U },
  { X86::XMM13, -2U },
  { X86::XMM14, -2U },
  { X86::XMM15, -2U },
  { X86::XMM16, -2U },
  { X86::XMM17, -2U },
  { X86::XMM18, -2U },
  { X86::XMM19, -2U },
  { X86::XMM20, -2U },
  { X86::XMM21, -2U },
  { X86::XMM22, -2U },
  { X86::XMM23, -2U },
  { X86::XMM24, -2U },
  { X86::XMM25, -2U },
  { X86::XMM26, -2U },
  { X86::XMM27, -2U },
  { X86::XMM28, -2U },
  { X86::XMM29, -2U },
  { X86::XMM30, -2U },
  { X86::XMM31, -2U },
  { X86::YMM0, 21U },
  { X86::YMM1, 22U },
  { X86::YMM2, 23U },
  { X86::YMM3, 24U },
  { X86::YMM4, 25U },
  { X86::YMM5, 26U },
  { X86::YMM6, 27U },
  { X86::YMM7, 28U },
  { X86::YMM8, -2U },
  { X86::YMM9, -2U },
  { X86::YMM10, -2U },
  { X86::YMM11, -2U },
  { X86::YMM12, -2U },
  { X86::YMM13, -2U },
  { X86::YMM14, -2U },
  { X86::YMM15, -2U },
  { X86::YMM16, -2U },
  { X86::YMM17, -2U },
  { X86::YMM18, -2U },
  { X86::YMM19, -2U },
  { X86::YMM20, -2U },
  { X86::YMM21, -2U },
  { X86::YMM22, -2U },
  { X86::YMM23, -2U },
  { X86::YMM24, -2U },
  { X86::YMM25, -2U },
  { X86::YMM26, -2U },
  { X86::YMM27, -2U },
  { X86::YMM28, -2U },
  { X86::YMM29, -2U },
  { X86::YMM30, -2U },
  { X86::YMM31, -2U },
  { X86::ZMM0, 21U },
  { X86::ZMM1, 22U },
  { X86::ZMM2, 23U },
  { X86::ZMM3, 24U },
  { X86::ZMM4, 25U },
  { X86::ZMM5, 26U },
  { X86::ZMM6, 27U },
  { X86::ZMM7, 28U },
  { X86::ZMM8, -2U },
  { X86::ZMM9, -2U },
  { X86::ZMM10, -2U },
  { X86::ZMM11, -2U },
  { X86::ZMM12, -2U },
  { X86::ZMM13, -2U },
  { X86::ZMM14, -2U },
  { X86::ZMM15, -2U },
  { X86::ZMM16, -2U },
  { X86::ZMM17, -2U },
  { X86::ZMM18, -2U },
  { X86::ZMM19, -2U },
  { X86::ZMM20, -2U },
  { X86::ZMM21, -2U },
  { X86::ZMM22, -2U },
  { X86::ZMM23, -2U },
  { X86::ZMM24, -2U },
  { X86::ZMM25, -2U },
  { X86::ZMM26, -2U },
  { X86::ZMM27, -2U },
  { X86::ZMM28, -2U },
  { X86::ZMM29, -2U },
  { X86::ZMM30, -2U },
  { X86::ZMM31, -2U },
};
extern const unsigned X86EHFlavour1L2DwarfSize = array_lengthof(X86EHFlavour1L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair X86EHFlavour2L2Dwarf[] = {
  { X86::EAX, 0U },
  { X86::EBP, 5U },
  { X86::EBX, 3U },
  { X86::ECX, 1U },
  { X86::EDI, 7U },
  { X86::EDX, 2U },
  { X86::EIP, 8U },
  { X86::ESI, 6U },
  { X86::ESP, 4U },
  { X86::RAX, -2U },
  { X86::RBP, -2U },
  { X86::RBX, -2U },
  { X86::RCX, -2U },
  { X86::RDI, -2U },
  { X86::RDX, -2U },
  { X86::RIP, -2U },
  { X86::RSI, -2U },
  { X86::RSP, -2U },
  { X86::K0, -2U },
  { X86::K1, -2U },
  { X86::K2, -2U },
  { X86::K3, -2U },
  { X86::K4, -2U },
  { X86::K5, -2U },
  { X86::K6, -2U },
  { X86::K7, -2U },
  { X86::MM0, 29U },
  { X86::MM1, 30U },
  { X86::MM2, 31U },
  { X86::MM3, 32U },
  { X86::MM4, 33U },
  { X86::MM5, 34U },
  { X86::MM6, 35U },
  { X86::MM7, 36U },
  { X86::R8, -2U },
  { X86::R9, -2U },
  { X86::R10, -2U },
  { X86::R11, -2U },
  { X86::R12, -2U },
  { X86::R13, -2U },
  { X86::R14, -2U },
  { X86::R15, -2U },
  { X86::ST0, 11U },
  { X86::ST1, 12U },
  { X86::ST2, 13U },
  { X86::ST3, 14U },
  { X86::ST4, 15U },
  { X86::ST5, 16U },
  { X86::ST6, 17U },
  { X86::ST7, 18U },
  { X86::XMM0, 21U },
  { X86::XMM1, 22U },
  { X86::XMM2, 23U },
  { X86::XMM3, 24U },
  { X86::XMM4, 25U },
  { X86::XMM5, 26U },
  { X86::XMM6, 27U },
  { X86::XMM7, 28U },
  { X86::XMM8, -2U },
  { X86::XMM9, -2U },
  { X86::XMM10, -2U },
  { X86::XMM11, -2U },
  { X86::XMM12, -2U },
  { X86::XMM13, -2U },
  { X86::XMM14, -2U },
  { X86::XMM15, -2U },
  { X86::XMM16, -2U },
  { X86::XMM17, -2U },
  { X86::XMM18, -2U },
  { X86::XMM19, -2U },
  { X86::XMM20, -2U },
  { X86::XMM21, -2U },
  { X86::XMM22, -2U },
  { X86::XMM23, -2U },
  { X86::XMM24, -2U },
  { X86::XMM25, -2U },
  { X86::XMM26, -2U },
  { X86::XMM27, -2U },
  { X86::XMM28, -2U },
  { X86::XMM29, -2U },
  { X86::XMM30, -2U },
  { X86::XMM31, -2U },
  { X86::YMM0, 21U },
  { X86::YMM1, 22U },
  { X86::YMM2, 23U },
  { X86::YMM3, 24U },
  { X86::YMM4, 25U },
  { X86::YMM5, 26U },
  { X86::YMM6, 27U },
  { X86::YMM7, 28U },
  { X86::YMM8, -2U },
  { X86::YMM9, -2U },
  { X86::YMM10, -2U },
  { X86::YMM11, -2U },
  { X86::YMM12, -2U },
  { X86::YMM13, -2U },
  { X86::YMM14, -2U },
  { X86::YMM15, -2U },
  { X86::YMM16, -2U },
  { X86::YMM17, -2U },
  { X86::YMM18, -2U },
  { X86::YMM19, -2U },
  { X86::YMM20, -2U },
  { X86::YMM21, -2U },
  { X86::YMM22, -2U },
  { X86::YMM23, -2U },
  { X86::YMM24, -2U },
  { X86::YMM25, -2U },
  { X86::YMM26, -2U },
  { X86::YMM27, -2U },
  { X86::YMM28, -2U },
  { X86::YMM29, -2U },
  { X86::YMM30, -2U },
  { X86::YMM31, -2U },
  { X86::ZMM0, 21U },
  { X86::ZMM1, 22U },
  { X86::ZMM2, 23U },
  { X86::ZMM3, 24U },
  { X86::ZMM4, 25U },
  { X86::ZMM5, 26U },
  { X86::ZMM6, 27U },
  { X86::ZMM7, 28U },
  { X86::ZMM8, -2U },
  { X86::ZMM9, -2U },
  { X86::ZMM10, -2U },
  { X86::ZMM11, -2U },
  { X86::ZMM12, -2U },
  { X86::ZMM13, -2U },
  { X86::ZMM14, -2U },
  { X86::ZMM15, -2U },
  { X86::ZMM16, -2U },
  { X86::ZMM17, -2U },
  { X86::ZMM18, -2U },
  { X86::ZMM19, -2U },
  { X86::ZMM20, -2U },
  { X86::ZMM21, -2U },
  { X86::ZMM22, -2U },
  { X86::ZMM23, -2U },
  { X86::ZMM24, -2U },
  { X86::ZMM25, -2U },
  { X86::ZMM26, -2U },
  { X86::ZMM27, -2U },
  { X86::ZMM28, -2U },
  { X86::ZMM29, -2U },
  { X86::ZMM30, -2U },
  { X86::ZMM31, -2U },
};
extern const unsigned X86EHFlavour2L2DwarfSize = array_lengthof(X86EHFlavour2L2Dwarf);

extern const uint16_t X86RegEncodingTable[] = {
  0,
  4,
  0,
  0,
  7,
  3,
  5,
  5,
  3,
  5,
  1,
  1,
  1,
  6,
  7,
  7,
  2,
  3,
  2,
  0,
  5,
  3,
  1,
  7,
  2,
  0,
  0,
  4,
  0,
  6,
  4,
  0,
  4,
  5,
  0,
  0,
  5,
  3,
  1,
  7,
  2,
  0,
  4,
  6,
  4,
  6,
  6,
  4,
  4,
  2,
  0,
  1,
  2,
  3,
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
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
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
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
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
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
};
static inline void InitX86MCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(X86RegDesc, 246, RA, PC, X86MCRegisterClasses, 86, X86RegUnitRoots, 131, X86RegDiffLists, X86LaneMaskLists, X86RegStrings, X86RegClassStrings, X86SubRegIdxLists, 7,
X86SubRegIdxRanges, X86RegEncodingTable);

  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(X86DwarfFlavour0Dwarf2L, X86DwarfFlavour0Dwarf2LSize, false);
    break;
  case 1:
    RI->mapDwarfRegsToLLVMRegs(X86DwarfFlavour1Dwarf2L, X86DwarfFlavour1Dwarf2LSize, false);
    break;
  case 2:
    RI->mapDwarfRegsToLLVMRegs(X86DwarfFlavour2Dwarf2L, X86DwarfFlavour2Dwarf2LSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(X86EHFlavour0Dwarf2L, X86EHFlavour0Dwarf2LSize, true);
    break;
  case 1:
    RI->mapDwarfRegsToLLVMRegs(X86EHFlavour1Dwarf2L, X86EHFlavour1Dwarf2LSize, true);
    break;
  case 2:
    RI->mapDwarfRegsToLLVMRegs(X86EHFlavour2Dwarf2L, X86EHFlavour2Dwarf2LSize, true);
    break;
  }
  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(X86DwarfFlavour0L2Dwarf, X86DwarfFlavour0L2DwarfSize, false);
    break;
  case 1:
    RI->mapLLVMRegsToDwarfRegs(X86DwarfFlavour1L2Dwarf, X86DwarfFlavour1L2DwarfSize, false);
    break;
  case 2:
    RI->mapLLVMRegsToDwarfRegs(X86DwarfFlavour2L2Dwarf, X86DwarfFlavour2L2DwarfSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(X86EHFlavour0L2Dwarf, X86EHFlavour0L2DwarfSize, true);
    break;
  case 1:
    RI->mapLLVMRegsToDwarfRegs(X86EHFlavour1L2Dwarf, X86EHFlavour1L2DwarfSize, true);
    break;
  case 2:
    RI->mapLLVMRegsToDwarfRegs(X86EHFlavour2L2Dwarf, X86EHFlavour2L2DwarfSize, true);
    break;
  }
}

} // End llvm namespace
#endif // GET_REGINFO_MC_DESC
