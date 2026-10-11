/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

class MCRegisterClass;
const MCRegisterClass &getAVRMCRegisterClass(unsigned RC);
namespace AVR {

enum : unsigned {
  NoRegister,
  SP = 1,
  SPH = 2,
  SPL = 3,
  SREG = 4,
  R0 = 5,
  R1 = 6,
  R2 = 7,
  R3 = 8,
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
  R16 = 21,
  R17 = 22,
  R18 = 23,
  R19 = 24,
  R20 = 25,
  R21 = 26,
  R22 = 27,
  R23 = 28,
  R24 = 29,
  R25 = 30,
  R26 = 31,
  R27 = 32,
  R28 = 33,
  R29 = 34,
  R30 = 35,
  R31 = 36,
  R1R0 = 37,
  R3R2 = 38,
  R5R4 = 39,
  R7R6 = 40,
  R9R8 = 41,
  R10R9 = 42,
  R11R10 = 43,
  R12R11 = 44,
  R13R12 = 45,
  R14R13 = 46,
  R15R14 = 47,
  R16R15 = 48,
  R17R16 = 49,
  R18R17 = 50,
  R19R18 = 51,
  R20R19 = 52,
  R21R20 = 53,
  R22R21 = 54,
  R23R22 = 55,
  R24R23 = 56,
  R25R24 = 57,
  R26R25 = 58,
  R27R26 = 59,
  R29R28 = 60,
  R31R30 = 61,
  NUM_TARGET_REGS // 62
};

} // namespace AVR

// Register classes

namespace AVR {

enum {
  GPR8RegClassID = 0,
  GPR8NOZRegClassID = 1,
  GPR8loRegClassID = 2,
  LD8RegClassID = 3,
  GPR8NOZ_and_LD8RegClassID = 4,
  LD8loRegClassID = 5,
  CCRRegClassID = 6,
  DREGSRegClassID = 7,
  DREGSNOZRegClassID = 8,
  DREGSMOVWRegClassID = 9,
  DREGSMOVW_and_DREGSNOZRegClassID = 10,
  DREGS_with_sub_hi_in_LD8RegClassID = 11,
  DREGSNOZ_and_DREGS_with_sub_hi_in_LD8RegClassID = 12,
  DREGS_with_sub_lo_in_LD8RegClassID = 13,
  DREGSNOZ_and_DREGS_with_sub_lo_in_LD8RegClassID = 14,
  DREGS_with_sub_lo_in_GPR8loRegClassID = 15,
  DREGS_with_sub_hi_in_GPR8loRegClassID = 16,
  DLDREGSRegClassID = 17,
  DREGS_with_sub_hi_in_LD8loRegClassID = 18,
  DREGS_with_sub_lo_in_LD8loRegClassID = 19,
  DREGSloRegClassID = 20,
  DLDREGS_and_DREGSNOZRegClassID = 21,
  DREGS_with_sub_hi_in_LD8lo_and_DREGS_with_sub_lo_in_LD8RegClassID = 22,
  DREGSLD8loRegClassID = 23,
  IWREGSRegClassID = 24,
  DREGSNOZ_and_IWREGSRegClassID = 25,
  PTRREGSRegClassID = 26,
  DREGSNOZ_and_PTRREGSRegClassID = 27,
  PTRDISPREGSRegClassID = 28,
  DREGSNOZ_and_PTRDISPREGSRegClassID = 29,
  DREGS_with_sub_hi_in_LD8_and_DREGS_with_sub_lo_in_GPR8loRegClassID = 30,
  GPRSPRegClassID = 31,
  ZREGRegClassID = 32,

};

} // namespace AVR

// Register alternate name indices

namespace AVR {

enum {
  NoRegAltName,	// 0
  ptr,	// 1
  NUM_TARGET_REG_ALT_NAMES = 2
};

} // namespace AVR

// Subregister indices

namespace AVR {

enum : uint16_t {
  NoSubRegister,
  sub_hi,	// 1
  sub_lo,	// 2
  NUM_TARGET_SUBREGS
};

} // namespace AVR
// Register pressure sets enum.
namespace AVR {

enum RegisterPressureSets {
  CCR = 0,
  DREGS_with_sub_hi_in_LD8_and_DREGS_with_sub_lo_in_GPR8lo = 1,
  GPRSP = 2,
  IWREGS = 3,
  LD8lo = 4,
  LD8 = 5,
  GPR8lo = 6,
  GPR8lo_with_LD8lo = 7,
  GPR8 = 8,
};

} // namespace AVR

} // namespace llvm_ks
