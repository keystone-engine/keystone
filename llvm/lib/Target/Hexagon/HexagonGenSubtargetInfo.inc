/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Subtarget Enumeration Source Fragment                                      *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_SUBTARGETINFO_ENUM
#undef GET_SUBTARGETINFO_ENUM
namespace llvm_ks {
namespace Hexagon {
enum : uint64_t {
  ArchV4 = 0,
  ArchV5 = 1,
  ArchV55 = 2,
  ArchV60 = 3,
  ExtensionHVX = 4,
  ExtensionHVXDbl = 5
};
}
} // end llvm namespace
#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC
namespace llvm_ks {
// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKV HexagonFeatureKV[] = {
  { "hvx", "Hexagon HVX instructions", { Hexagon::ExtensionHVX }, { } },
  { "hvx-double", "Hexagon HVX Double instructions", { Hexagon::ExtensionHVXDbl }, { } },
  { "v4", "Hexagon V4", { Hexagon::ArchV4 }, { } },
  { "v5", "Hexagon V5", { Hexagon::ArchV5 }, { } },
  { "v55", "Hexagon V55", { Hexagon::ArchV55 }, { } },
  { "v60", "Hexagon V60", { Hexagon::ArchV60 }, { } }
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetFeatureKV HexagonSubTypeKV[] = {
  { "hexagonv4", "Select the hexagonv4 processor", { Hexagon::ArchV4 }, { } },
  { "hexagonv5", "Select the hexagonv5 processor", { Hexagon::ArchV4, Hexagon::ArchV5 }, { } },
  { "hexagonv55", "Select the hexagonv55 processor", { Hexagon::ArchV4, Hexagon::ArchV5, Hexagon::ArchV55 }, { } },
  { "hexagonv60", "Select the hexagonv60 processor", { Hexagon::ArchV4, Hexagon::ArchV5, Hexagon::ArchV55, Hexagon::ArchV60, Hexagon::ExtensionHVX }, { } }
};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#ifndef NDEBUG
#define DBGFIELD(x) x,
#else
#define DBGFIELD(x)
#endif

// Functional units for "HexagonItinerariesV4"
namespace HexagonItinerariesV4FU {
  const unsigned SLOT0 = 1 << 0;
  const unsigned SLOT1 = 1 << 1;
  const unsigned SLOT2 = 1 << 2;
  const unsigned SLOT3 = 1 << 3;
  const unsigned SLOT_ENDLOOP = 1 << 4;
}

// Functional units for "HexagonItinerariesV55"
namespace HexagonItinerariesV55FU {
  const unsigned SLOT0 = 1 << 0;
  const unsigned SLOT1 = 1 << 1;
  const unsigned SLOT2 = 1 << 2;
  const unsigned SLOT3 = 1 << 3;
  const unsigned SLOT_ENDLOOP = 1 << 4;
}

// Functional units for "HexagonItinerariesV60"
namespace HexagonItinerariesV60FU {
  const unsigned SLOT0 = 1 << 0;
  const unsigned SLOT1 = 1 << 1;
  const unsigned SLOT2 = 1 << 2;
  const unsigned SLOT3 = 1 << 3;
  const unsigned SLOT_ENDLOOP = 1 << 4;
  const unsigned CVI_ST = 1 << 5;
  const unsigned CVI_XLANE = 1 << 6;
  const unsigned CVI_SHIFT = 1 << 7;
  const unsigned CVI_MPY0 = 1 << 8;
  const unsigned CVI_MPY1 = 1 << 9;
  const unsigned CVI_LD = 1 << 10;
  const unsigned CVI_XLSHF = 1 << 11;
  const unsigned CVI_MPY01 = 1 << 12;
  const unsigned CVI_ALL = 1 << 13;
}

extern const llvm_ks::InstrStage HexagonStages[] = {
  { 0, 0, 0, llvm_ks::InstrStage::Required }, // No itinerary
  { 1, HexagonItinerariesV4FU::SLOT2 | HexagonItinerariesV4FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 1
  { 1, HexagonItinerariesV4FU::SLOT0 | HexagonItinerariesV4FU::SLOT1 | HexagonItinerariesV4FU::SLOT2 | HexagonItinerariesV4FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 2
  { 1, HexagonItinerariesV4FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 3
  { 1, HexagonItinerariesV4FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 4
  { 1, HexagonItinerariesV4FU::SLOT0 | HexagonItinerariesV4FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 5
  { 1, HexagonItinerariesV4FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 6
  { 1, HexagonItinerariesV4FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 7
  { 1, HexagonItinerariesV4FU::SLOT2 | HexagonItinerariesV4FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV4FU::SLOT2 | HexagonItinerariesV4FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 8-9
  { 2, HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 10
  { 1, HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 11
  { 1, HexagonItinerariesV55FU::SLOT0 | HexagonItinerariesV55FU::SLOT1 | HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 12
  { 2, HexagonItinerariesV55FU::SLOT0 | HexagonItinerariesV55FU::SLOT1 | HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 13
  { 3, HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 14
  { 3, HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 15
  { 2, HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 16
  { 2, HexagonItinerariesV55FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 17
  { 3, HexagonItinerariesV55FU::SLOT0 | HexagonItinerariesV55FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 18
  { 1, HexagonItinerariesV55FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 19
  { 2, HexagonItinerariesV55FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 20
  { 1, HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV55FU::SLOT2 | HexagonItinerariesV55FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 21-22
  { 3, HexagonItinerariesV55FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 23
  { 2, HexagonItinerariesV55FU::SLOT0 | HexagonItinerariesV55FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 24
  { 1, HexagonItinerariesV55FU::SLOT0 | HexagonItinerariesV55FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 25
  { 2, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 26
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 27
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 28
  { 2, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 29
  { 3, HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 30
  { 3, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 31
  { 2, HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 32
  { 2, HexagonItinerariesV60FU::SLOT2, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 33
  { 3, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 34
  { 1, HexagonItinerariesV60FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 35
  { 2, HexagonItinerariesV60FU::SLOT_ENDLOOP, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 36
  { 4, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 37
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE | HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 38-39
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 40-41
  { 4, HexagonItinerariesV60FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 42
  { 2, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 43
  { 3, HexagonItinerariesV60FU::SLOT0, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 44
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE | HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 45-47
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 48
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE | HexagonItinerariesV60FU::CVI_SHIFT | HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 49-51
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY0 | HexagonItinerariesV60FU::CVI_MPY1, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 52-53
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLSHF | HexagonItinerariesV60FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 54-55
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 56-57
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_LD, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 58-61
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_LD, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 62-63
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::SLOT1, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ST, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLANE, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 64-67
  { 1, HexagonItinerariesV60FU::SLOT0, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ST, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 68-69
  { 1, HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_MPY01, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 70-71
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_SHIFT, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 72-73
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_XLSHF, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 74-75
  { 1, HexagonItinerariesV60FU::SLOT0 | HexagonItinerariesV60FU::SLOT1 | HexagonItinerariesV60FU::SLOT2 | HexagonItinerariesV60FU::SLOT3, 0, (llvm_ks::InstrStage::ReservationKinds)0 },   { 1, HexagonItinerariesV60FU::CVI_ALL, -1, (llvm_ks::InstrStage::ReservationKinds)0 }, // 76-77
  { 0, 0, 0, llvm_ks::InstrStage::Required } // End stages
};

static const llvm_ks::InstrItinerary HexagonItinerariesV4[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 1, 2, 0, 0 }, // 1 S_2op_tc_2_SLOT23
  { 1, 1, 2, 0, 0 }, // 2 S_2op_tc_1_SLOT23
  { 1, 2, 3, 0, 0 }, // 3 ALU32_3op_tc_1_SLOT0123
  { 1, 1, 2, 0, 0 }, // 4 ALU64_tc_1_SLOT23
  { 1, 1, 2, 0, 0 }, // 5 ALU64_tc_2_SLOT23
  { 1, 2, 3, 0, 0 }, // 6 ALU32_ADDI_tc_1_SLOT0123
  { 1, 2, 3, 0, 0 }, // 7 ALU32_3op_tc_2_SLOT0123
  { 1, 2, 3, 0, 0 }, // 8 ALU32_2op_tc_1_SLOT0123
  { 1, 3, 4, 0, 0 }, // 9 CR_tc_3x_SLOT3
  { 1, 1, 2, 0, 0 }, // 10 ALU64_tc_2early_SLOT23
  { 1, 1, 2, 0, 0 }, // 11 M_tc_3x_SLOT23
  { 1, 1, 2, 0, 0 }, // 12 S_3op_tc_1_SLOT23
  { 1, 1, 2, 0, 0 }, // 13 S_3op_tc_2early_SLOT23
  { 1, 1, 2, 0, 0 }, // 14 S_3op_tc_2_SLOT23
  { 1, 2, 3, 0, 0 }, // 15 EXTENDER_tc_1_SLOT0123
  { 1, 1, 2, 0, 0 }, // 16 S_3op_tc_3_SLOT23
  { 0, 0, 0, 0, 0 }, // 17 M_tc_3stall_SLOT23
  { 1, 2, 3, 0, 0 }, // 18 PSEUDO
  { 1, 1, 2, 0, 0 }, // 19 CR_tc_2early_SLOT23
  { 1, 1, 2, 0, 0 }, // 20 S_2op_tc_2early_SLOT23
  { 1, 2, 3, 0, 0 }, // 21 ALU32_3op_tc_2early_SLOT0123
  { 1, 2, 3, 0, 0 }, // 22 ALU32_2op_tc_2early_SLOT0123
  { 1, 3, 4, 0, 0 }, // 23 CR_tc_2_SLOT3
  { 1, 4, 5, 0, 0 }, // 24 J_tc_2early_SLOT2
  { 1, 1, 2, 0, 0 }, // 25 J_tc_2early_SLOT23
  { 1, 5, 6, 0, 0 }, // 26 LD_tc_ld_SLOT01
  { 1, 6, 7, 0, 0 }, // 27 DUPLEX
  { 1, 7, 8, 0, 0 }, // 28 J_tc_2early_SLOT0123
  { 1, 1, 2, 0, 0 }, // 29 S_2op_tc_3or4x_SLOT23
  { 1, 1, 2, 0, 0 }, // 30 ALU64_tc_3x_SLOT23
  { 1, 1, 2, 0, 0 }, // 31 M_tc_3or4x_SLOT23
  { 1, 1, 2, 0, 0 }, // 32 M_tc_3_SLOT23
  { 0, 0, 0, 0, 0 }, // 33 CVI_VA
  { 1, 8, 10, 0, 0 }, // 34 PSEUDOM
  { 1, 3, 4, 0, 0 }, // 35 CR_tc_2early_SLOT3
  { 1, 6, 7, 0, 0 }, // 36 NCJ_tc_3or4stall_SLOT0
  { 1, 1, 2, 0, 0 }, // 37 COMPOUND
  { 1, 5, 6, 0, 0 }, // 38 V2LDST_tc_ld_SLOT01
  { 1, 6, 7, 0, 0 }, // 39 LD_tc_ld_SLOT0
  { 1, 6, 7, 0, 0 }, // 40 V4LDST_tc_st_SLOT0
  { 1, 5, 6, 0, 0 }, // 41 V4LDST_tc_ld_SLOT01
  { 1, 6, 7, 0, 0 }, // 42 LD_tc_3or4stall_SLOT0
  { 0, 0, 0, 0, 0 }, // 43 CVI_VM_LD
  { 1, 1, 2, 0, 0 }, // 44 M_tc_2_SLOT23
  { 1, 1, 2, 0, 0 }, // 45 S_3op_tc_3x_SLOT23
  { 1, 6, 7, 0, 0 }, // 46 ST_tc_ld_SLOT0
  { 1, 5, 6, 0, 0 }, // 47 V2LDST_tc_st_SLOT01
  { 1, 5, 6, 0, 0 }, // 48 ST_tc_st_SLOT01
  { 1, 6, 7, 0, 0 }, // 49 V2LDST_tc_st_SLOT0
  { 1, 6, 7, 0, 0 }, // 50 ST_tc_st_SLOT0
  { 1, 5, 6, 0, 0 }, // 51 V4LDST_tc_st_SLOT01
  { 0, 0, 0, 0, 0 }, // 52 CVI_VM_ST
  { 0, 0, 0, 0, 0 }, // 53 PREFIX
  { 0, 0, 0, 0, 0 }, // 54 CVI_VX_LATE
  { 0, 0, 0, 0, 0 }, // 55 CVI_VA_DV
  { 0, 0, 0, 0, 0 }, // 56 CVI_VP_LONG
  { 0, 0, 0, 0, 0 }, // 57 CVI_VM_VP_LDU
  { 0, 0, 0, 0, 0 }, // 58 CVI_VM_CUR_LD
  { 0, 0, 0, 0, 0 }, // 59 CVI_VM_TMP_LD
  { 0, 0, 0, 0, 0 }, // 60 CVI_VM_STU
  { 0, 0, 0, 0, 0 }, // 61 CVI_VM_NEW_ST
  { 0, 0, 0, 0, 0 }, // 62 CVI_VX
  { 0, 0, 0, 0, 0 }, // 63 CVI_VX_DV
  { 0, 0, 0, 0, 0 }, // 64 CVI_VS
  { 0, 0, 0, 0, 0 }, // 65 CVI_VP_VS_LONG_EARLY
  { 0, 0, 0, 0, 0 }, // 66 CVI_VP
  { 0, 0, 0, 0, 0 }, // 67 CVI_VP_VS_LONG
  { 0, 0, 0, 0, 0 }, // 68 CVI_HIST
  { 0, 0, 0, 0, 0 }, // 69 CVI_VX_DV_LONG
  { 0, 0, 0, 0, 0 }, // 70 CVI_VX_LONG
  { 0, 0, 0, 0, 0 }, // 71 CVI_VINLANESAT
  { 0, 0, 0, 0, 0 }, // 72 CVI_VP_VS
  { 1, 6, 7, 0, 0 }, // 73 ST_tc_3stall_SLOT0
  { 0, ~0U, ~0U, ~0U, ~0U } // end marker
};

static const llvm_ks::InstrItinerary HexagonItinerariesV55[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 10, 11, 0, 0 }, // 1 S_2op_tc_2_SLOT23
  { 1, 11, 12, 0, 0 }, // 2 S_2op_tc_1_SLOT23
  { 1, 12, 13, 0, 0 }, // 3 ALU32_3op_tc_1_SLOT0123
  { 1, 11, 12, 0, 0 }, // 4 ALU64_tc_1_SLOT23
  { 1, 10, 11, 0, 0 }, // 5 ALU64_tc_2_SLOT23
  { 1, 12, 13, 0, 0 }, // 6 ALU32_ADDI_tc_1_SLOT0123
  { 1, 13, 14, 0, 0 }, // 7 ALU32_3op_tc_2_SLOT0123
  { 1, 12, 13, 0, 0 }, // 8 ALU32_2op_tc_1_SLOT0123
  { 1, 14, 15, 0, 0 }, // 9 CR_tc_3x_SLOT3
  { 1, 10, 11, 0, 0 }, // 10 ALU64_tc_2early_SLOT23
  { 1, 15, 16, 0, 0 }, // 11 M_tc_3x_SLOT23
  { 1, 11, 12, 0, 0 }, // 12 S_3op_tc_1_SLOT23
  { 1, 10, 11, 0, 0 }, // 13 S_3op_tc_2early_SLOT23
  { 1, 10, 11, 0, 0 }, // 14 S_3op_tc_2_SLOT23
  { 1, 12, 13, 0, 0 }, // 15 EXTENDER_tc_1_SLOT0123
  { 1, 15, 16, 0, 0 }, // 16 S_3op_tc_3_SLOT23
  { 1, 15, 16, 0, 0 }, // 17 M_tc_3stall_SLOT23
  { 1, 12, 13, 0, 0 }, // 18 PSEUDO
  { 1, 10, 11, 0, 0 }, // 19 CR_tc_2early_SLOT23
  { 1, 10, 11, 0, 0 }, // 20 S_2op_tc_2early_SLOT23
  { 1, 13, 14, 0, 0 }, // 21 ALU32_3op_tc_2early_SLOT0123
  { 1, 13, 14, 0, 0 }, // 22 ALU32_2op_tc_2early_SLOT0123
  { 1, 16, 17, 0, 0 }, // 23 CR_tc_2_SLOT3
  { 1, 17, 18, 0, 0 }, // 24 J_tc_2early_SLOT2
  { 1, 10, 11, 0, 0 }, // 25 J_tc_2early_SLOT23
  { 1, 18, 19, 0, 0 }, // 26 LD_tc_ld_SLOT01
  { 1, 19, 20, 0, 0 }, // 27 DUPLEX
  { 1, 20, 21, 0, 0 }, // 28 J_tc_2early_SLOT0123
  { 1, 15, 16, 0, 0 }, // 29 S_2op_tc_3or4x_SLOT23
  { 1, 15, 16, 0, 0 }, // 30 ALU64_tc_3x_SLOT23
  { 1, 15, 16, 0, 0 }, // 31 M_tc_3or4x_SLOT23
  { 1, 15, 16, 0, 0 }, // 32 M_tc_3_SLOT23
  { 0, 0, 0, 0, 0 }, // 33 CVI_VA
  { 1, 21, 23, 0, 0 }, // 34 PSEUDOM
  { 1, 16, 17, 0, 0 }, // 35 CR_tc_2early_SLOT3
  { 1, 23, 24, 0, 0 }, // 36 NCJ_tc_3or4stall_SLOT0
  { 1, 11, 12, 0, 0 }, // 37 COMPOUND
  { 1, 24, 25, 0, 0 }, // 38 V2LDST_tc_ld_SLOT01
  { 1, 23, 24, 0, 0 }, // 39 LD_tc_ld_SLOT0
  { 1, 19, 20, 0, 0 }, // 40 V4LDST_tc_st_SLOT0
  { 1, 18, 19, 0, 0 }, // 41 V4LDST_tc_ld_SLOT01
  { 1, 23, 24, 0, 0 }, // 42 LD_tc_3or4stall_SLOT0
  { 0, 0, 0, 0, 0 }, // 43 CVI_VM_LD
  { 1, 10, 11, 0, 0 }, // 44 M_tc_2_SLOT23
  { 1, 15, 16, 0, 0 }, // 45 S_3op_tc_3x_SLOT23
  { 1, 23, 24, 0, 0 }, // 46 ST_tc_ld_SLOT0
  { 1, 25, 26, 0, 0 }, // 47 V2LDST_tc_st_SLOT01
  { 1, 25, 26, 0, 0 }, // 48 ST_tc_st_SLOT01
  { 1, 19, 20, 0, 0 }, // 49 V2LDST_tc_st_SLOT0
  { 1, 19, 20, 0, 0 }, // 50 ST_tc_st_SLOT0
  { 1, 25, 26, 0, 0 }, // 51 V4LDST_tc_st_SLOT01
  { 0, 0, 0, 0, 0 }, // 52 CVI_VM_ST
  { 1, 12, 13, 0, 0 }, // 53 PREFIX
  { 0, 0, 0, 0, 0 }, // 54 CVI_VX_LATE
  { 0, 0, 0, 0, 0 }, // 55 CVI_VA_DV
  { 0, 0, 0, 0, 0 }, // 56 CVI_VP_LONG
  { 0, 0, 0, 0, 0 }, // 57 CVI_VM_VP_LDU
  { 0, 0, 0, 0, 0 }, // 58 CVI_VM_CUR_LD
  { 0, 0, 0, 0, 0 }, // 59 CVI_VM_TMP_LD
  { 0, 0, 0, 0, 0 }, // 60 CVI_VM_STU
  { 0, 0, 0, 0, 0 }, // 61 CVI_VM_NEW_ST
  { 0, 0, 0, 0, 0 }, // 62 CVI_VX
  { 0, 0, 0, 0, 0 }, // 63 CVI_VX_DV
  { 0, 0, 0, 0, 0 }, // 64 CVI_VS
  { 0, 0, 0, 0, 0 }, // 65 CVI_VP_VS_LONG_EARLY
  { 0, 0, 0, 0, 0 }, // 66 CVI_VP
  { 0, 0, 0, 0, 0 }, // 67 CVI_VP_VS_LONG
  { 0, 0, 0, 0, 0 }, // 68 CVI_HIST
  { 0, 0, 0, 0, 0 }, // 69 CVI_VX_DV_LONG
  { 0, 0, 0, 0, 0 }, // 70 CVI_VX_LONG
  { 0, 0, 0, 0, 0 }, // 71 CVI_VINLANESAT
  { 0, 0, 0, 0, 0 }, // 72 CVI_VP_VS
  { 1, 23, 24, 0, 0 }, // 73 ST_tc_3stall_SLOT0
  { 0, ~0U, ~0U, ~0U, ~0U } // end marker
};

static const llvm_ks::InstrItinerary HexagonItinerariesV60[] = {
  { 0, 0, 0, 0, 0 }, // 0 NoInstrModel
  { 1, 26, 27, 0, 0 }, // 1 S_2op_tc_2_SLOT23
  { 1, 27, 28, 0, 0 }, // 2 S_2op_tc_1_SLOT23
  { 1, 28, 29, 0, 0 }, // 3 ALU32_3op_tc_1_SLOT0123
  { 1, 27, 28, 0, 0 }, // 4 ALU64_tc_1_SLOT23
  { 1, 26, 27, 0, 0 }, // 5 ALU64_tc_2_SLOT23
  { 1, 28, 29, 0, 0 }, // 6 ALU32_ADDI_tc_1_SLOT0123
  { 1, 29, 30, 0, 0 }, // 7 ALU32_3op_tc_2_SLOT0123
  { 1, 28, 29, 0, 0 }, // 8 ALU32_2op_tc_1_SLOT0123
  { 1, 30, 31, 0, 0 }, // 9 CR_tc_3x_SLOT3
  { 1, 26, 27, 0, 0 }, // 10 ALU64_tc_2early_SLOT23
  { 1, 31, 32, 0, 0 }, // 11 M_tc_3x_SLOT23
  { 1, 27, 28, 0, 0 }, // 12 S_3op_tc_1_SLOT23
  { 1, 26, 27, 0, 0 }, // 13 S_3op_tc_2early_SLOT23
  { 1, 26, 27, 0, 0 }, // 14 S_3op_tc_2_SLOT23
  { 1, 28, 29, 0, 0 }, // 15 EXTENDER_tc_1_SLOT0123
  { 1, 31, 32, 0, 0 }, // 16 S_3op_tc_3_SLOT23
  { 1, 31, 32, 0, 0 }, // 17 M_tc_3stall_SLOT23
  { 1, 28, 29, 0, 0 }, // 18 PSEUDO
  { 1, 26, 27, 0, 0 }, // 19 CR_tc_2early_SLOT23
  { 1, 26, 27, 0, 0 }, // 20 S_2op_tc_2early_SLOT23
  { 1, 29, 30, 0, 0 }, // 21 ALU32_3op_tc_2early_SLOT0123
  { 1, 29, 30, 0, 0 }, // 22 ALU32_2op_tc_2early_SLOT0123
  { 1, 32, 33, 0, 0 }, // 23 CR_tc_2_SLOT3
  { 1, 33, 34, 0, 0 }, // 24 J_tc_2early_SLOT2
  { 1, 26, 27, 0, 0 }, // 25 J_tc_2early_SLOT23
  { 1, 34, 35, 0, 0 }, // 26 LD_tc_ld_SLOT01
  { 1, 35, 36, 0, 0 }, // 27 DUPLEX
  { 1, 36, 37, 0, 0 }, // 28 J_tc_2early_SLOT0123
  { 1, 37, 38, 0, 0 }, // 29 S_2op_tc_3or4x_SLOT23
  { 1, 31, 32, 0, 0 }, // 30 ALU64_tc_3x_SLOT23
  { 1, 37, 38, 0, 0 }, // 31 M_tc_3or4x_SLOT23
  { 1, 31, 32, 0, 0 }, // 32 M_tc_3_SLOT23
  { 1, 38, 40, 0, 0 }, // 33 CVI_VA
  { 1, 40, 42, 0, 0 }, // 34 PSEUDOM
  { 1, 32, 33, 0, 0 }, // 35 CR_tc_2early_SLOT3
  { 1, 42, 43, 0, 0 }, // 36 NCJ_tc_3or4stall_SLOT0
  { 1, 27, 28, 0, 0 }, // 37 COMPOUND
  { 1, 43, 44, 0, 0 }, // 38 V2LDST_tc_ld_SLOT01
  { 1, 44, 45, 0, 0 }, // 39 LD_tc_ld_SLOT0
  { 1, 35, 36, 0, 0 }, // 40 V4LDST_tc_st_SLOT0
  { 1, 34, 35, 0, 0 }, // 41 V4LDST_tc_ld_SLOT01
  { 1, 42, 43, 0, 0 }, // 42 LD_tc_3or4stall_SLOT0
  { 1, 45, 48, 0, 0 }, // 43 CVI_VM_LD
  { 1, 26, 27, 0, 0 }, // 44 M_tc_2_SLOT23
  { 1, 31, 32, 0, 0 }, // 45 S_3op_tc_3x_SLOT23
  { 1, 44, 45, 0, 0 }, // 46 ST_tc_ld_SLOT0
  { 1, 48, 49, 0, 0 }, // 47 V2LDST_tc_st_SLOT01
  { 1, 48, 49, 0, 0 }, // 48 ST_tc_st_SLOT01
  { 1, 35, 36, 0, 0 }, // 49 V2LDST_tc_st_SLOT0
  { 1, 35, 36, 0, 0 }, // 50 ST_tc_st_SLOT0
  { 1, 48, 49, 0, 0 }, // 51 V4LDST_tc_st_SLOT01
  { 1, 49, 52, 0, 0 }, // 52 CVI_VM_ST
  { 1, 28, 29, 0, 0 }, // 53 PREFIX
  { 1, 52, 54, 0, 0 }, // 54 CVI_VX_LATE
  { 1, 54, 56, 0, 0 }, // 55 CVI_VA_DV
  { 1, 56, 58, 0, 0 }, // 56 CVI_VP_LONG
  { 1, 58, 62, 0, 0 }, // 57 CVI_VM_VP_LDU
  { 1, 45, 48, 0, 0 }, // 58 CVI_VM_CUR_LD
  { 1, 62, 64, 0, 0 }, // 59 CVI_VM_TMP_LD
  { 1, 64, 68, 0, 0 }, // 60 CVI_VM_STU
  { 1, 68, 70, 0, 0 }, // 61 CVI_VM_NEW_ST
  { 1, 52, 54, 0, 0 }, // 62 CVI_VX
  { 1, 70, 72, 0, 0 }, // 63 CVI_VX_DV
  { 1, 72, 74, 0, 0 }, // 64 CVI_VS
  { 1, 74, 76, 0, 0 }, // 65 CVI_VP_VS_LONG_EARLY
  { 1, 56, 58, 0, 0 }, // 66 CVI_VP
  { 1, 74, 76, 0, 0 }, // 67 CVI_VP_VS_LONG
  { 1, 76, 78, 0, 0 }, // 68 CVI_HIST
  { 1, 70, 72, 0, 0 }, // 69 CVI_VX_DV_LONG
  { 1, 52, 54, 0, 0 }, // 70 CVI_VX_LONG
  { 1, 72, 74, 0, 0 }, // 71 CVI_VINLANESAT
  { 1, 74, 76, 0, 0 }, // 72 CVI_VP_VS
  { 1, 44, 45, 0, 0 }, // 73 ST_tc_3stall_SLOT0
  { 0, ~0U, ~0U, ~0U, ~0U } // end marker
};

// ===============================================================
// Data tables for the new per-operand machine model.

static const llvm_ks::MCSchedModel HexagonModelV4 = {
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  0, // PostRAScheduler
  1, // CompleteModel
  1, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  HexagonItinerariesV4};

static const llvm_ks::MCSchedModel HexagonModelV55 = {
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  0, // PostRAScheduler
  1, // CompleteModel
  2, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  HexagonItinerariesV55};

static const llvm_ks::MCSchedModel HexagonModelV60 = {
  4, // IssueWidth
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  1, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  0, // PostRAScheduler
  1, // CompleteModel
  3, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  HexagonItinerariesV60};

// Sorted (by key) array of itineraries for CPU subtype.
extern const llvm_ks::SubtargetInfoKV HexagonProcSchedKV[] = {
  { "hexagonv4", (const void *)&HexagonModelV4 },
  { "hexagonv5", (const void *)&HexagonModelV4 },
  { "hexagonv55", (const void *)&HexagonModelV55 },
  { "hexagonv60", (const void *)&HexagonModelV60 }
};
#undef DBGFIELD
static inline MCSubtargetInfo *createHexagonMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, HexagonFeatureKV, HexagonSubTypeKV,
          HexagonProcSchedKV);
}

} // end llvm namespace
#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::HexagonSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
  if (Bits[Hexagon::ArchV4] && HexagonArchVersion < V4) HexagonArchVersion = V4;
  if (Bits[Hexagon::ArchV5] && HexagonArchVersion < V5) HexagonArchVersion = V5;
  if (Bits[Hexagon::ArchV55] && HexagonArchVersion < V55) HexagonArchVersion = V55;
  if (Bits[Hexagon::ArchV60] && HexagonArchVersion < V60) HexagonArchVersion = V60;
  if (Bits[Hexagon::ExtensionHVX]) UseHVXOps = true;
  if (Bits[Hexagon::ExtensionHVXDbl]) UseHVXDblOps = true;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC
