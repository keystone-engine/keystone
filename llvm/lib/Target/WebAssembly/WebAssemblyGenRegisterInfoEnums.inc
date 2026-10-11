/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getWebAssemblyMCRegisterClass(unsigned RC);
namespace WebAssembly {

enum : unsigned {
  NoRegister,
  ARGUMENTS = 1,
  VALUE_STACK = 2,
  EXNREF_0 = 3,
  EXTERNREF_0 = 4,
  FP32 = 5,
  FP64 = 6,
  FUNCREF_0 = 7,
  SP32 = 8,
  SP64 = 9,
  F32_0 = 10,
  F64_0 = 11,
  I32_0 = 12,
  I64_0 = 13,
  V128_0 = 14,
  NUM_TARGET_REGS // 15
};

} // namespace WebAssembly

// Register classes

namespace WebAssembly {

enum {
  EXNREFRegClassID = 0,
  EXTERNREFRegClassID = 1,
  FUNCREFRegClassID = 2,
  I32RegClassID = 3,
  F32RegClassID = 4,
  I64RegClassID = 5,
  F64RegClassID = 6,
  V128RegClassID = 7,

};

} // namespace WebAssembly
// Register pressure sets enum.
namespace WebAssembly {

enum RegisterPressureSets {
  EXNREF = 0,
  EXTERNREF = 1,
  FUNCREF = 2,
  F32 = 3,
  F64 = 4,
  V128 = 5,
  I32 = 6,
  I64 = 7,
};

} // namespace WebAssembly

} // namespace llvm_ks
