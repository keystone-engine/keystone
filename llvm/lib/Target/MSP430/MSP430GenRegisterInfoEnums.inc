/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getMSP430MCRegisterClass(unsigned RC);
namespace MSP430 {

enum : unsigned {
  NoRegister,
  CG = 1,
  CGB = 2,
  PC = 3,
  PCB = 4,
  SP = 5,
  SPB = 6,
  SR = 7,
  SRB = 8,
  R4 = 9,
  R5 = 10,
  R6 = 11,
  R7 = 12,
  R8 = 13,
  R9 = 14,
  R10 = 15,
  R11 = 16,
  R12 = 17,
  R13 = 18,
  R14 = 19,
  R15 = 20,
  R4B = 21,
  R5B = 22,
  R6B = 23,
  R7B = 24,
  R8B = 25,
  R9B = 26,
  R10B = 27,
  R11B = 28,
  R12B = 29,
  R13B = 30,
  R14B = 31,
  R15B = 32,
  NUM_TARGET_REGS // 33
};

} // namespace MSP430

// Register classes

namespace MSP430 {

enum {
  GR8RegClassID = 0,
  GR16RegClassID = 1,

};

} // namespace MSP430

// Subregister indices

namespace MSP430 {

enum : uint16_t {
  NoSubRegister,
  subreg_8bit,	// 1
  NUM_TARGET_SUBREGS
};

} // namespace MSP430
// Register pressure sets enum.
namespace MSP430 {

enum RegisterPressureSets {
  GR8 = 0,
};

} // namespace MSP430

} // namespace llvm_ks
