/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

uint64_t RISCVMCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
    SmallVectorImpl<MCFixup> &Fixups,
    const MCSubtargetInfo &STI) const {
  static const uint64_t InstBits[] = {
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(51),	// ADD
    UINT64_C(19),	// ADDI
    UINT64_C(27),	// ADDIW
    UINT64_C(59),	// ADDW
    UINT64_C(12335),	// AMOADD_D
    UINT64_C(67121199),	// AMOADD_D_AQ
    UINT64_C(100675631),	// AMOADD_D_AQ_RL
    UINT64_C(33566767),	// AMOADD_D_RL
    UINT64_C(8239),	// AMOADD_W
    UINT64_C(67117103),	// AMOADD_W_AQ
    UINT64_C(100671535),	// AMOADD_W_AQ_RL
    UINT64_C(33562671),	// AMOADD_W_RL
    UINT64_C(1610625071),	// AMOAND_D
    UINT64_C(1677733935),	// AMOAND_D_AQ
    UINT64_C(1711288367),	// AMOAND_D_AQ_RL
    UINT64_C(1644179503),	// AMOAND_D_RL
    UINT64_C(1610620975),	// AMOAND_W
    UINT64_C(1677729839),	// AMOAND_W_AQ
    UINT64_C(1711284271),	// AMOAND_W_AQ_RL
    UINT64_C(1644175407),	// AMOAND_W_RL
    UINT64_C(3758108719),	// AMOMAXU_D
    UINT64_C(3825217583),	// AMOMAXU_D_AQ
    UINT64_C(3858772015),	// AMOMAXU_D_AQ_RL
    UINT64_C(3791663151),	// AMOMAXU_D_RL
    UINT64_C(3758104623),	// AMOMAXU_W
    UINT64_C(3825213487),	// AMOMAXU_W_AQ
    UINT64_C(3858767919),	// AMOMAXU_W_AQ_RL
    UINT64_C(3791659055),	// AMOMAXU_W_RL
    UINT64_C(2684366895),	// AMOMAX_D
    UINT64_C(2751475759),	// AMOMAX_D_AQ
    UINT64_C(2785030191),	// AMOMAX_D_AQ_RL
    UINT64_C(2717921327),	// AMOMAX_D_RL
    UINT64_C(2684362799),	// AMOMAX_W
    UINT64_C(2751471663),	// AMOMAX_W_AQ
    UINT64_C(2785026095),	// AMOMAX_W_AQ_RL
    UINT64_C(2717917231),	// AMOMAX_W_RL
    UINT64_C(3221237807),	// AMOMINU_D
    UINT64_C(3288346671),	// AMOMINU_D_AQ
    UINT64_C(3321901103),	// AMOMINU_D_AQ_RL
    UINT64_C(3254792239),	// AMOMINU_D_RL
    UINT64_C(3221233711),	// AMOMINU_W
    UINT64_C(3288342575),	// AMOMINU_W_AQ
    UINT64_C(3321897007),	// AMOMINU_W_AQ_RL
    UINT64_C(3254788143),	// AMOMINU_W_RL
    UINT64_C(2147495983),	// AMOMIN_D
    UINT64_C(2214604847),	// AMOMIN_D_AQ
    UINT64_C(2248159279),	// AMOMIN_D_AQ_RL
    UINT64_C(2181050415),	// AMOMIN_D_RL
    UINT64_C(2147491887),	// AMOMIN_W
    UINT64_C(2214600751),	// AMOMIN_W_AQ
    UINT64_C(2248155183),	// AMOMIN_W_AQ_RL
    UINT64_C(2181046319),	// AMOMIN_W_RL
    UINT64_C(1073754159),	// AMOOR_D
    UINT64_C(1140863023),	// AMOOR_D_AQ
    UINT64_C(1174417455),	// AMOOR_D_AQ_RL
    UINT64_C(1107308591),	// AMOOR_D_RL
    UINT64_C(1073750063),	// AMOOR_W
    UINT64_C(1140858927),	// AMOOR_W_AQ
    UINT64_C(1174413359),	// AMOOR_W_AQ_RL
    UINT64_C(1107304495),	// AMOOR_W_RL
    UINT64_C(134230063),	// AMOSWAP_D
    UINT64_C(201338927),	// AMOSWAP_D_AQ
    UINT64_C(234893359),	// AMOSWAP_D_AQ_RL
    UINT64_C(167784495),	// AMOSWAP_D_RL
    UINT64_C(134225967),	// AMOSWAP_W
    UINT64_C(201334831),	// AMOSWAP_W_AQ
    UINT64_C(234889263),	// AMOSWAP_W_AQ_RL
    UINT64_C(167780399),	// AMOSWAP_W_RL
    UINT64_C(536883247),	// AMOXOR_D
    UINT64_C(603992111),	// AMOXOR_D_AQ
    UINT64_C(637546543),	// AMOXOR_D_AQ_RL
    UINT64_C(570437679),	// AMOXOR_D_RL
    UINT64_C(536879151),	// AMOXOR_W
    UINT64_C(603988015),	// AMOXOR_W_AQ
    UINT64_C(637542447),	// AMOXOR_W_AQ_RL
    UINT64_C(570433583),	// AMOXOR_W_RL
    UINT64_C(28723),	// AND
    UINT64_C(28691),	// ANDI
    UINT64_C(23),	// AUIPC
    UINT64_C(99),	// BEQ
    UINT64_C(20579),	// BGE
    UINT64_C(28771),	// BGEU
    UINT64_C(16483),	// BLT
    UINT64_C(24675),	// BLTU
    UINT64_C(4195),	// BNE
    UINT64_C(12403),	// CSRRC
    UINT64_C(28787),	// CSRRCI
    UINT64_C(8307),	// CSRRS
    UINT64_C(24691),	// CSRRSI
    UINT64_C(4211),	// CSRRW
    UINT64_C(20595),	// CSRRWI
    UINT64_C(36866),	// C_ADD
    UINT64_C(1),	// C_ADDI
    UINT64_C(24833),	// C_ADDI16SP
    UINT64_C(0),	// C_ADDI4SPN
    UINT64_C(8193),	// C_ADDIW
    UINT64_C(39969),	// C_ADDW
    UINT64_C(35937),	// C_AND
    UINT64_C(34817),	// C_ANDI
    UINT64_C(49153),	// C_BEQZ
    UINT64_C(57345),	// C_BNEZ
    UINT64_C(36866),	// C_EBREAK
    UINT64_C(8192),	// C_FLD
    UINT64_C(8194),	// C_FLDSP
    UINT64_C(24576),	// C_FLW
    UINT64_C(24578),	// C_FLWSP
    UINT64_C(40960),	// C_FSD
    UINT64_C(40962),	// C_FSDSP
    UINT64_C(57344),	// C_FSW
    UINT64_C(57346),	// C_FSWSP
    UINT64_C(40961),	// C_J
    UINT64_C(8193),	// C_JAL
    UINT64_C(36866),	// C_JALR
    UINT64_C(32770),	// C_JR
    UINT64_C(24576),	// C_LD
    UINT64_C(24578),	// C_LDSP
    UINT64_C(16385),	// C_LI
    UINT64_C(24577),	// C_LUI
    UINT64_C(16384),	// C_LW
    UINT64_C(16386),	// C_LWSP
    UINT64_C(32770),	// C_MV
    UINT64_C(1),	// C_NOP
    UINT64_C(35905),	// C_OR
    UINT64_C(57344),	// C_SD
    UINT64_C(57346),	// C_SDSP
    UINT64_C(2),	// C_SLLI
    UINT64_C(33793),	// C_SRAI
    UINT64_C(32769),	// C_SRLI
    UINT64_C(35841),	// C_SUB
    UINT64_C(39937),	// C_SUBW
    UINT64_C(49152),	// C_SW
    UINT64_C(49154),	// C_SWSP
    UINT64_C(0),	// C_UNIMP
    UINT64_C(35873),	// C_XOR
    UINT64_C(33570867),	// DIV
    UINT64_C(33574963),	// DIVU
    UINT64_C(33574971),	// DIVUW
    UINT64_C(33570875),	// DIVW
    UINT64_C(1048691),	// EBREAK
    UINT64_C(115),	// ECALL
    UINT64_C(33554515),	// FADD_D
    UINT64_C(83),	// FADD_S
    UINT64_C(3791654995),	// FCLASS_D
    UINT64_C(3758100563),	// FCLASS_S
    UINT64_C(3525312595),	// FCVT_D_L
    UINT64_C(3526361171),	// FCVT_D_LU
    UINT64_C(1107296339),	// FCVT_D_S
    UINT64_C(3523215443),	// FCVT_D_W
    UINT64_C(3524264019),	// FCVT_D_WU
    UINT64_C(3257925715),	// FCVT_LU_D
    UINT64_C(3224371283),	// FCVT_LU_S
    UINT64_C(3256877139),	// FCVT_L_D
    UINT64_C(3223322707),	// FCVT_L_S
    UINT64_C(1074790483),	// FCVT_S_D
    UINT64_C(3491758163),	// FCVT_S_L
    UINT64_C(3492806739),	// FCVT_S_LU
    UINT64_C(3489661011),	// FCVT_S_W
    UINT64_C(3490709587),	// FCVT_S_WU
    UINT64_C(3255828563),	// FCVT_WU_D
    UINT64_C(3222274131),	// FCVT_WU_S
    UINT64_C(3254779987),	// FCVT_W_D
    UINT64_C(3221225555),	// FCVT_W_S
    UINT64_C(436207699),	// FDIV_D
    UINT64_C(402653267),	// FDIV_S
    UINT64_C(15),	// FENCE
    UINT64_C(4111),	// FENCE_I
    UINT64_C(2200961039),	// FENCE_TSO
    UINT64_C(2717917267),	// FEQ_D
    UINT64_C(2684362835),	// FEQ_S
    UINT64_C(12295),	// FLD
    UINT64_C(2717909075),	// FLE_D
    UINT64_C(2684354643),	// FLE_S
    UINT64_C(2717913171),	// FLT_D
    UINT64_C(2684358739),	// FLT_S
    UINT64_C(8199),	// FLW
    UINT64_C(33554499),	// FMADD_D
    UINT64_C(67),	// FMADD_S
    UINT64_C(704647251),	// FMAX_D
    UINT64_C(671092819),	// FMAX_S
    UINT64_C(704643155),	// FMIN_D
    UINT64_C(671088723),	// FMIN_S
    UINT64_C(33554503),	// FMSUB_D
    UINT64_C(71),	// FMSUB_S
    UINT64_C(301989971),	// FMUL_D
    UINT64_C(268435539),	// FMUL_S
    UINT64_C(4060086355),	// FMV_D_X
    UINT64_C(4026531923),	// FMV_W_X
    UINT64_C(3791650899),	// FMV_X_D
    UINT64_C(3758096467),	// FMV_X_W
    UINT64_C(33554511),	// FNMADD_D
    UINT64_C(79),	// FNMADD_S
    UINT64_C(33554507),	// FNMSUB_D
    UINT64_C(75),	// FNMSUB_S
    UINT64_C(12327),	// FSD
    UINT64_C(570429523),	// FSGNJN_D
    UINT64_C(536875091),	// FSGNJN_S
    UINT64_C(570433619),	// FSGNJX_D
    UINT64_C(536879187),	// FSGNJX_S
    UINT64_C(570425427),	// FSGNJ_D
    UINT64_C(536870995),	// FSGNJ_S
    UINT64_C(1509949523),	// FSQRT_D
    UINT64_C(1476395091),	// FSQRT_S
    UINT64_C(167772243),	// FSUB_D
    UINT64_C(134217811),	// FSUB_S
    UINT64_C(8231),	// FSW
    UINT64_C(111),	// JAL
    UINT64_C(103),	// JALR
    UINT64_C(3),	// LB
    UINT64_C(16387),	// LBU
    UINT64_C(12291),	// LD
    UINT64_C(4099),	// LH
    UINT64_C(20483),	// LHU
    UINT64_C(268447791),	// LR_D
    UINT64_C(335556655),	// LR_D_AQ
    UINT64_C(369111087),	// LR_D_AQ_RL
    UINT64_C(302002223),	// LR_D_RL
    UINT64_C(268443695),	// LR_W
    UINT64_C(335552559),	// LR_W_AQ
    UINT64_C(369106991),	// LR_W_AQ_RL
    UINT64_C(301998127),	// LR_W_RL
    UINT64_C(55),	// LUI
    UINT64_C(8195),	// LW
    UINT64_C(24579),	// LWU
    UINT64_C(807403635),	// MRET
    UINT64_C(33554483),	// MUL
    UINT64_C(33558579),	// MULH
    UINT64_C(33562675),	// MULHSU
    UINT64_C(33566771),	// MULHU
    UINT64_C(33554491),	// MULW
    UINT64_C(24627),	// OR
    UINT64_C(24595),	// ORI
    UINT64_C(33579059),	// REM
    UINT64_C(33583155),	// REMU
    UINT64_C(33583163),	// REMUW
    UINT64_C(33579067),	// REMW
    UINT64_C(35),	// SB
    UINT64_C(402665519),	// SC_D
    UINT64_C(469774383),	// SC_D_AQ
    UINT64_C(503328815),	// SC_D_AQ_RL
    UINT64_C(436219951),	// SC_D_RL
    UINT64_C(402661423),	// SC_W
    UINT64_C(469770287),	// SC_W_AQ
    UINT64_C(503324719),	// SC_W_AQ_RL
    UINT64_C(436215855),	// SC_W_RL
    UINT64_C(12323),	// SD
    UINT64_C(301990003),	// SFENCE_VMA
    UINT64_C(4131),	// SH
    UINT64_C(4147),	// SLL
    UINT64_C(4115),	// SLLI
    UINT64_C(4123),	// SLLIW
    UINT64_C(4155),	// SLLW
    UINT64_C(8243),	// SLT
    UINT64_C(8211),	// SLTI
    UINT64_C(12307),	// SLTIU
    UINT64_C(12339),	// SLTU
    UINT64_C(1073762355),	// SRA
    UINT64_C(1073762323),	// SRAI
    UINT64_C(1073762331),	// SRAIW
    UINT64_C(1073762363),	// SRAW
    UINT64_C(270532723),	// SRET
    UINT64_C(20531),	// SRL
    UINT64_C(20499),	// SRLI
    UINT64_C(20507),	// SRLIW
    UINT64_C(20539),	// SRLW
    UINT64_C(1073741875),	// SUB
    UINT64_C(1073741883),	// SUBW
    UINT64_C(8227),	// SW
    UINT64_C(3221229683),	// UNIMP
    UINT64_C(2097267),	// URET
    UINT64_C(273678451),	// WFI
    UINT64_C(16435),	// XOR
    UINT64_C(16403),	// XORI
    UINT64_C(0)
  };
  const unsigned opcode = MI.getOpcode();
  uint64_t Value = InstBits[opcode];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case RISCV::C_EBREAK:
    case RISCV::C_NOP:
    case RISCV::C_UNIMP:
    case RISCV::EBREAK:
    case RISCV::ECALL:
    case RISCV::FENCE_I:
    case RISCV::FENCE_TSO:
    case RISCV::MRET:
    case RISCV::SRET:
    case RISCV::UNIMP:
    case RISCV::URET:
    case RISCV::WFI: {
      break;
    }
    case RISCV::C_LI:
    case RISCV::C_LUI: {
      // op: imm
      op = getImmOpValue(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_FLDSP:
    case RISCV::C_LDSP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(24)) << 2;
      Value |= (op & UINT64_C(448)) >> 4;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_FLWSP:
    case RISCV::C_LWSP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(28)) << 2;
      Value |= (op & UINT64_C(192)) >> 4;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_ADDI:
    case RISCV::C_ADDIW: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_ANDI: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      break;
    }
    case RISCV::C_ADDI4SPN: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(48)) << 7;
      Value |= (op & UINT64_C(960)) << 1;
      Value |= (op & UINT64_C(4)) << 4;
      Value |= (op & UINT64_C(8)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      break;
    }
    case RISCV::C_ADDI16SP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(512)) << 3;
      Value |= (op & UINT64_C(16)) << 2;
      Value |= (op & UINT64_C(64)) >> 1;
      Value |= (op & UINT64_C(384)) >> 4;
      Value |= (op & UINT64_C(32)) >> 3;
      break;
    }
    case RISCV::C_FSDSP:
    case RISCV::C_SDSP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(448)) << 1;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 2;
      break;
    }
    case RISCV::C_FSWSP:
    case RISCV::C_SWSP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(60)) << 7;
      Value |= (op & UINT64_C(192)) << 1;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 2;
      break;
    }
    case RISCV::C_BEQZ:
    case RISCV::C_BNEZ: {
      // op: imm
      op = getImmOpValueAsr1(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(128)) << 5;
      Value |= (op & UINT64_C(12)) << 8;
      Value |= op & UINT64_C(96);
      Value |= (op & UINT64_C(3)) << 3;
      Value |= (op & UINT64_C(16)) >> 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      break;
    }
    case RISCV::C_SLLI: {
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_SRAI:
    case RISCV::C_SRLI: {
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      break;
    }
    case RISCV::FSD:
    case RISCV::FSW:
    case RISCV::SB:
    case RISCV::SD:
    case RISCV::SH:
    case RISCV::SW: {
      // op: imm12
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(4064)) << 20;
      Value |= (op & UINT64_C(31)) << 7;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      break;
    }
    case RISCV::ADDI:
    case RISCV::ADDIW:
    case RISCV::ANDI:
    case RISCV::FLD:
    case RISCV::FLW:
    case RISCV::JALR:
    case RISCV::LB:
    case RISCV::LBU:
    case RISCV::LD:
    case RISCV::LH:
    case RISCV::LHU:
    case RISCV::LW:
    case RISCV::LWU:
    case RISCV::ORI:
    case RISCV::SLTI:
    case RISCV::SLTIU:
    case RISCV::XORI: {
      // op: imm12
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(4095)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::BEQ:
    case RISCV::BGE:
    case RISCV::BGEU:
    case RISCV::BLT:
    case RISCV::BLTU:
    case RISCV::BNE: {
      // op: imm12
      op = getImmOpValueAsr1(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(2048)) << 20;
      Value |= (op & UINT64_C(1008)) << 21;
      Value |= (op & UINT64_C(15)) << 8;
      Value |= (op & UINT64_C(1024)) >> 3;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      break;
    }
    case RISCV::CSRRC:
    case RISCV::CSRRCI:
    case RISCV::CSRRS:
    case RISCV::CSRRSI:
    case RISCV::CSRRW:
    case RISCV::CSRRWI: {
      // op: imm12
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(4095)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::AUIPC:
    case RISCV::LUI: {
      // op: imm20
      op = getImmOpValue(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(1048575)) << 12;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::JAL: {
      // op: imm20
      op = getImmOpValueAsr1(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(524288)) << 12;
      Value |= (op & UINT64_C(1023)) << 21;
      Value |= (op & UINT64_C(1024)) << 10;
      Value |= (op & UINT64_C(522240)) << 1;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_J:
    case RISCV::C_JAL: {
      // op: offset
      op = getImmOpValueAsr1(MI, 0, Fixups, STI);
      Value |= (op & UINT64_C(1024)) << 2;
      Value |= (op & UINT64_C(8)) << 8;
      Value |= (op & UINT64_C(384)) << 2;
      Value |= (op & UINT64_C(512)) >> 1;
      Value |= (op & UINT64_C(32)) << 2;
      Value |= op & UINT64_C(64);
      Value |= (op & UINT64_C(7)) << 3;
      Value |= (op & UINT64_C(16)) >> 2;
      break;
    }
    case RISCV::FENCE: {
      // op: pred
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 24;
      // op: succ
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 20;
      break;
    }
    case RISCV::C_FLD:
    case RISCV::C_LD: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(192)) >> 1;
      break;
    }
    case RISCV::C_FLW:
    case RISCV::C_LW: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(4)) << 4;
      Value |= (op & UINT64_C(64)) >> 1;
      break;
    }
    case RISCV::C_JALR:
    case RISCV::C_JR: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_MV: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 2;
      break;
    }
    case RISCV::FCVT_D_L:
    case RISCV::FCVT_D_LU:
    case RISCV::FCVT_LU_D:
    case RISCV::FCVT_LU_S:
    case RISCV::FCVT_L_D:
    case RISCV::FCVT_L_S:
    case RISCV::FCVT_S_D:
    case RISCV::FCVT_S_L:
    case RISCV::FCVT_S_LU:
    case RISCV::FCVT_S_W:
    case RISCV::FCVT_S_WU:
    case RISCV::FCVT_WU_D:
    case RISCV::FCVT_WU_S:
    case RISCV::FCVT_W_D:
    case RISCV::FCVT_W_S:
    case RISCV::FSQRT_D:
    case RISCV::FSQRT_S: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: funct3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 12;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::FCLASS_D:
    case RISCV::FCLASS_S:
    case RISCV::FCVT_D_S:
    case RISCV::FCVT_D_W:
    case RISCV::FCVT_D_WU:
    case RISCV::FMV_D_X:
    case RISCV::FMV_W_X:
    case RISCV::FMV_X_D:
    case RISCV::FMV_X_W:
    case RISCV::LR_D:
    case RISCV::LR_D_AQ:
    case RISCV::LR_D_AQ_RL:
    case RISCV::LR_D_RL:
    case RISCV::LR_W:
    case RISCV::LR_W_AQ:
    case RISCV::LR_W_AQ_RL:
    case RISCV::LR_W_RL: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_ADD: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 2;
      break;
    }
    case RISCV::C_FSD:
    case RISCV::C_SD: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(192)) >> 1;
      break;
    }
    case RISCV::C_FSW:
    case RISCV::C_SW: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(4)) << 4;
      Value |= (op & UINT64_C(64)) >> 1;
      break;
    }
    case RISCV::SFENCE_VMA: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      break;
    }
    case RISCV::FADD_D:
    case RISCV::FADD_S:
    case RISCV::FDIV_D:
    case RISCV::FDIV_S:
    case RISCV::FMUL_D:
    case RISCV::FMUL_S:
    case RISCV::FSUB_D:
    case RISCV::FSUB_S: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: funct3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 12;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::ADD:
    case RISCV::ADDW:
    case RISCV::AMOADD_D:
    case RISCV::AMOADD_D_AQ:
    case RISCV::AMOADD_D_AQ_RL:
    case RISCV::AMOADD_D_RL:
    case RISCV::AMOADD_W:
    case RISCV::AMOADD_W_AQ:
    case RISCV::AMOADD_W_AQ_RL:
    case RISCV::AMOADD_W_RL:
    case RISCV::AMOAND_D:
    case RISCV::AMOAND_D_AQ:
    case RISCV::AMOAND_D_AQ_RL:
    case RISCV::AMOAND_D_RL:
    case RISCV::AMOAND_W:
    case RISCV::AMOAND_W_AQ:
    case RISCV::AMOAND_W_AQ_RL:
    case RISCV::AMOAND_W_RL:
    case RISCV::AMOMAXU_D:
    case RISCV::AMOMAXU_D_AQ:
    case RISCV::AMOMAXU_D_AQ_RL:
    case RISCV::AMOMAXU_D_RL:
    case RISCV::AMOMAXU_W:
    case RISCV::AMOMAXU_W_AQ:
    case RISCV::AMOMAXU_W_AQ_RL:
    case RISCV::AMOMAXU_W_RL:
    case RISCV::AMOMAX_D:
    case RISCV::AMOMAX_D_AQ:
    case RISCV::AMOMAX_D_AQ_RL:
    case RISCV::AMOMAX_D_RL:
    case RISCV::AMOMAX_W:
    case RISCV::AMOMAX_W_AQ:
    case RISCV::AMOMAX_W_AQ_RL:
    case RISCV::AMOMAX_W_RL:
    case RISCV::AMOMINU_D:
    case RISCV::AMOMINU_D_AQ:
    case RISCV::AMOMINU_D_AQ_RL:
    case RISCV::AMOMINU_D_RL:
    case RISCV::AMOMINU_W:
    case RISCV::AMOMINU_W_AQ:
    case RISCV::AMOMINU_W_AQ_RL:
    case RISCV::AMOMINU_W_RL:
    case RISCV::AMOMIN_D:
    case RISCV::AMOMIN_D_AQ:
    case RISCV::AMOMIN_D_AQ_RL:
    case RISCV::AMOMIN_D_RL:
    case RISCV::AMOMIN_W:
    case RISCV::AMOMIN_W_AQ:
    case RISCV::AMOMIN_W_AQ_RL:
    case RISCV::AMOMIN_W_RL:
    case RISCV::AMOOR_D:
    case RISCV::AMOOR_D_AQ:
    case RISCV::AMOOR_D_AQ_RL:
    case RISCV::AMOOR_D_RL:
    case RISCV::AMOOR_W:
    case RISCV::AMOOR_W_AQ:
    case RISCV::AMOOR_W_AQ_RL:
    case RISCV::AMOOR_W_RL:
    case RISCV::AMOSWAP_D:
    case RISCV::AMOSWAP_D_AQ:
    case RISCV::AMOSWAP_D_AQ_RL:
    case RISCV::AMOSWAP_D_RL:
    case RISCV::AMOSWAP_W:
    case RISCV::AMOSWAP_W_AQ:
    case RISCV::AMOSWAP_W_AQ_RL:
    case RISCV::AMOSWAP_W_RL:
    case RISCV::AMOXOR_D:
    case RISCV::AMOXOR_D_AQ:
    case RISCV::AMOXOR_D_AQ_RL:
    case RISCV::AMOXOR_D_RL:
    case RISCV::AMOXOR_W:
    case RISCV::AMOXOR_W_AQ:
    case RISCV::AMOXOR_W_AQ_RL:
    case RISCV::AMOXOR_W_RL:
    case RISCV::AND:
    case RISCV::DIV:
    case RISCV::DIVU:
    case RISCV::DIVUW:
    case RISCV::DIVW:
    case RISCV::FEQ_D:
    case RISCV::FEQ_S:
    case RISCV::FLE_D:
    case RISCV::FLE_S:
    case RISCV::FLT_D:
    case RISCV::FLT_S:
    case RISCV::FMAX_D:
    case RISCV::FMAX_S:
    case RISCV::FMIN_D:
    case RISCV::FMIN_S:
    case RISCV::FSGNJN_D:
    case RISCV::FSGNJN_S:
    case RISCV::FSGNJX_D:
    case RISCV::FSGNJX_S:
    case RISCV::FSGNJ_D:
    case RISCV::FSGNJ_S:
    case RISCV::MUL:
    case RISCV::MULH:
    case RISCV::MULHSU:
    case RISCV::MULHU:
    case RISCV::MULW:
    case RISCV::OR:
    case RISCV::REM:
    case RISCV::REMU:
    case RISCV::REMUW:
    case RISCV::REMW:
    case RISCV::SC_D:
    case RISCV::SC_D_AQ:
    case RISCV::SC_D_AQ_RL:
    case RISCV::SC_D_RL:
    case RISCV::SC_W:
    case RISCV::SC_W_AQ:
    case RISCV::SC_W_AQ_RL:
    case RISCV::SC_W_RL:
    case RISCV::SLL:
    case RISCV::SLLW:
    case RISCV::SLT:
    case RISCV::SLTU:
    case RISCV::SRA:
    case RISCV::SRAW:
    case RISCV::SRL:
    case RISCV::SRLW:
    case RISCV::SUB:
    case RISCV::SUBW:
    case RISCV::XOR: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_ADDW:
    case RISCV::C_AND:
    case RISCV::C_OR:
    case RISCV::C_SUB:
    case RISCV::C_SUBW:
    case RISCV::C_XOR: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      break;
    }
    case RISCV::FMADD_D:
    case RISCV::FMADD_S:
    case RISCV::FMSUB_D:
    case RISCV::FMSUB_S:
    case RISCV::FNMADD_D:
    case RISCV::FNMADD_S:
    case RISCV::FNMSUB_D:
    case RISCV::FNMSUB_S: {
      // op: rs3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 27;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: funct3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 12;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::SLLIW:
    case RISCV::SRAIW:
    case RISCV::SRLIW: {
      // op: shamt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::SLLI:
    case RISCV::SRAI:
    case RISCV::SRLI: {
      // op: shamt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
  default:
    std::string msg;
    raw_string_ostream Msg(msg);
    Msg << "Not supported instr: " << MI;
    report_fatal_error(Msg.str());
  }
  return Value;
}
