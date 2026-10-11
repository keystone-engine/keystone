/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getBPFMCRegisterClass(unsigned RC);
namespace BPF {

enum : unsigned {
  NoRegister,
  R0 = 1,
  R1 = 2,
  R2 = 3,
  R3 = 4,
  R4 = 5,
  R5 = 6,
  R6 = 7,
  R7 = 8,
  R8 = 9,
  R9 = 10,
  R10 = 11,
  R11 = 12,
  W0 = 13,
  W1 = 14,
  W2 = 15,
  W3 = 16,
  W4 = 17,
  W5 = 18,
  W6 = 19,
  W7 = 20,
  W8 = 21,
  W9 = 22,
  W10 = 23,
  W11 = 24,
  NUM_TARGET_REGS // 25
};

} // namespace BPF

// Register classes

namespace BPF {

enum {
  GPR32RegClassID = 0,
  GPRRegClassID = 1,

};

} // namespace BPF

// Subregister indices

namespace BPF {

enum : uint16_t {
  NoSubRegister,
  sub_32,	// 1
  NUM_TARGET_SUBREGS
};

} // namespace BPF
// Register pressure sets enum.
namespace BPF {

enum RegisterPressureSets {
  GPR32 = 0,
};

} // namespace BPF

} // namespace llvm_ks
