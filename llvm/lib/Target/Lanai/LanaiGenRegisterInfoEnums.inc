/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getLanaiMCRegisterClass(unsigned RC);
namespace Lanai {

enum : unsigned {
  NoRegister,
  FP = 1,
  PC = 2,
  RCA = 3,
  RV = 4,
  SP = 5,
  SR = 6,
  R0 = 7,
  R1 = 8,
  R2 = 9,
  R3 = 10,
  R4 = 11,
  R5 = 12,
  R6 = 13,
  R7 = 14,
  R8 = 15,
  R9 = 16,
  R10 = 17,
  R11 = 18,
  R12 = 19,
  R13 = 20,
  R14 = 21,
  R15 = 22,
  R16 = 23,
  R17 = 24,
  R18 = 25,
  R19 = 26,
  R20 = 27,
  R21 = 28,
  R22 = 29,
  R23 = 30,
  R24 = 31,
  R25 = 32,
  R26 = 33,
  R27 = 34,
  R28 = 35,
  R29 = 36,
  R30 = 37,
  R31 = 38,
  RR1 = 39,
  RR2 = 40,
  NUM_TARGET_REGS // 41
};

} // namespace Lanai

// Register classes

namespace Lanai {

enum {
  GPRRegClassID = 0,
  GPR_with_sub_32RegClassID = 1,
  CCRRegClassID = 2,

};

} // namespace Lanai

// Subregister indices

namespace Lanai {

enum : uint16_t {
  NoSubRegister,
  sub_32,	// 1
  NUM_TARGET_SUBREGS
};

} // namespace Lanai
// Register pressure sets enum.
namespace Lanai {

enum RegisterPressureSets {
  GPR_with_sub_32 = 0,
  GPR = 1,
};

} // namespace Lanai

} // namespace llvm_ks
