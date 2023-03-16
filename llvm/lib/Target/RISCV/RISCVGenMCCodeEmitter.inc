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

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER
#include <sstream>

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_HasStdExtMBit = 4,
  Feature_HasStdExtABit = 0,
  Feature_HasStdExtFBit = 3,
  Feature_HasStdExtDBit = 2,
  Feature_HasStdExtCBit = 1,
  Feature_IsRV64Bit = 7,
  Feature_IsRV32Bit = 5,
  Feature_IsRV32EBit = 6,
};

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_HasStdExtA",
  "Feature_HasStdExtC",
  "Feature_HasStdExtD",
  "Feature_HasStdExtF",
  "Feature_HasStdExtM",
  "Feature_IsRV32",
  "Feature_IsRV32E",
  "Feature_IsRV64",
  nullptr
};

#endif // NDEBUG
FeatureBitset RISCVMCCodeEmitter::
computeAvailableFeatures(const FeatureBitset& FB) const {
  FeatureBitset Features;
  if ((FB[RISCV::FeatureStdExtM]))
    Features[Feature_HasStdExtMBit] = 1;
  if ((FB[RISCV::FeatureStdExtA]))
    Features[Feature_HasStdExtABit] = 1;
  if ((FB[RISCV::FeatureStdExtF]))
    Features[Feature_HasStdExtFBit] = 1;
  if ((FB[RISCV::FeatureStdExtD]))
    Features[Feature_HasStdExtDBit] = 1;
  if ((FB[RISCV::FeatureStdExtC]))
    Features[Feature_HasStdExtCBit] = 1;
  if ((FB[RISCV::Feature64Bit]))
    Features[Feature_IsRV64Bit] = 1;
  if ((!FB[RISCV::Feature64Bit]))
    Features[Feature_IsRV32Bit] = 1;
  if ((FB[RISCV::FeatureRV32E]))
    Features[Feature_IsRV32EBit] = 1;
  return Features;
}

#ifndef NDEBUG
// Feature bitsets.
enum : uint8_t {
  CEFBS_None,
  CEFBS_HasStdExtA,
  CEFBS_HasStdExtC,
  CEFBS_HasStdExtD,
  CEFBS_HasStdExtF,
  CEFBS_HasStdExtM,
  CEFBS_IsRV32,
  CEFBS_IsRV64,
  CEFBS_HasStdExtA_IsRV64,
  CEFBS_HasStdExtC_HasStdExtD,
  CEFBS_HasStdExtC_IsRV32,
  CEFBS_HasStdExtC_IsRV64,
  CEFBS_HasStdExtD_IsRV64,
  CEFBS_HasStdExtF_IsRV64,
  CEFBS_HasStdExtM_IsRV64,
  CEFBS_HasStdExtC_HasStdExtF_IsRV32,
};

const static FeatureBitset FeatureBitsets[] {
  {}, // CEFBS_None
  {Feature_HasStdExtABit, },
  {Feature_HasStdExtCBit, },
  {Feature_HasStdExtDBit, },
  {Feature_HasStdExtFBit, },
  {Feature_HasStdExtMBit, },
  {Feature_IsRV32Bit, },
  {Feature_IsRV64Bit, },
  {Feature_HasStdExtABit, Feature_IsRV64Bit, },
  {Feature_HasStdExtCBit, Feature_HasStdExtDBit, },
  {Feature_HasStdExtCBit, Feature_IsRV32Bit, },
  {Feature_HasStdExtCBit, Feature_IsRV64Bit, },
  {Feature_HasStdExtDBit, Feature_IsRV64Bit, },
  {Feature_HasStdExtFBit, Feature_IsRV64Bit, },
  {Feature_HasStdExtMBit, Feature_IsRV64Bit, },
  {Feature_HasStdExtCBit, Feature_HasStdExtFBit, Feature_IsRV32Bit, },
};
#endif // NDEBUG

void RISCVMCCodeEmitter::verifyInstructionPredicates(
    const MCInst &Inst, const FeatureBitset &AvailableFeatures) const {
#ifndef NDEBUG
  static uint8_t RequiredFeaturesRefs[] = {
    CEFBS_None, // PHI = 0
    CEFBS_None, // INLINEASM = 1
    CEFBS_None, // INLINEASM_BR = 2
    CEFBS_None, // CFI_INSTRUCTION = 3
    CEFBS_None, // EH_LABEL = 4
    CEFBS_None, // GC_LABEL = 5
    CEFBS_None, // ANNOTATION_LABEL = 6
    CEFBS_None, // KILL = 7
    CEFBS_None, // EXTRACT_SUBREG = 8
    CEFBS_None, // INSERT_SUBREG = 9
    CEFBS_None, // IMPLICIT_DEF = 10
    CEFBS_None, // SUBREG_TO_REG = 11
    CEFBS_None, // COPY_TO_REGCLASS = 12
    CEFBS_None, // DBG_VALUE = 13
    CEFBS_None, // DBG_LABEL = 14
    CEFBS_None, // REG_SEQUENCE = 15
    CEFBS_None, // COPY = 16
    CEFBS_None, // BUNDLE = 17
    CEFBS_None, // LIFETIME_START = 18
    CEFBS_None, // LIFETIME_END = 19
    CEFBS_None, // STACKMAP = 20
    CEFBS_None, // FENTRY_CALL = 21
    CEFBS_None, // PATCHPOINT = 22
    CEFBS_None, // LOAD_STACK_GUARD = 23
    CEFBS_None, // STATEPOINT = 24
    CEFBS_None, // LOCAL_ESCAPE = 25
    CEFBS_None, // FAULTING_OP = 26
    CEFBS_None, // PATCHABLE_OP = 27
    CEFBS_None, // PATCHABLE_FUNCTION_ENTER = 28
    CEFBS_None, // PATCHABLE_RET = 29
    CEFBS_None, // PATCHABLE_FUNCTION_EXIT = 30
    CEFBS_None, // PATCHABLE_TAIL_CALL = 31
    CEFBS_None, // PATCHABLE_EVENT_CALL = 32
    CEFBS_None, // PATCHABLE_TYPED_EVENT_CALL = 33
    CEFBS_None, // ICALL_BRANCH_FUNNEL = 34
    CEFBS_None, // G_ADD = 35
    CEFBS_None, // G_SUB = 36
    CEFBS_None, // G_MUL = 37
    CEFBS_None, // G_SDIV = 38
    CEFBS_None, // G_UDIV = 39
    CEFBS_None, // G_SREM = 40
    CEFBS_None, // G_UREM = 41
    CEFBS_None, // G_AND = 42
    CEFBS_None, // G_OR = 43
    CEFBS_None, // G_XOR = 44
    CEFBS_None, // G_IMPLICIT_DEF = 45
    CEFBS_None, // G_PHI = 46
    CEFBS_None, // G_FRAME_INDEX = 47
    CEFBS_None, // G_GLOBAL_VALUE = 48
    CEFBS_None, // G_EXTRACT = 49
    CEFBS_None, // G_UNMERGE_VALUES = 50
    CEFBS_None, // G_INSERT = 51
    CEFBS_None, // G_MERGE_VALUES = 52
    CEFBS_None, // G_BUILD_VECTOR = 53
    CEFBS_None, // G_BUILD_VECTOR_TRUNC = 54
    CEFBS_None, // G_CONCAT_VECTORS = 55
    CEFBS_None, // G_PTRTOINT = 56
    CEFBS_None, // G_INTTOPTR = 57
    CEFBS_None, // G_BITCAST = 58
    CEFBS_None, // G_INTRINSIC_TRUNC = 59
    CEFBS_None, // G_INTRINSIC_ROUND = 60
    CEFBS_None, // G_LOAD = 61
    CEFBS_None, // G_SEXTLOAD = 62
    CEFBS_None, // G_ZEXTLOAD = 63
    CEFBS_None, // G_STORE = 64
    CEFBS_None, // G_ATOMIC_CMPXCHG_WITH_SUCCESS = 65
    CEFBS_None, // G_ATOMIC_CMPXCHG = 66
    CEFBS_None, // G_ATOMICRMW_XCHG = 67
    CEFBS_None, // G_ATOMICRMW_ADD = 68
    CEFBS_None, // G_ATOMICRMW_SUB = 69
    CEFBS_None, // G_ATOMICRMW_AND = 70
    CEFBS_None, // G_ATOMICRMW_NAND = 71
    CEFBS_None, // G_ATOMICRMW_OR = 72
    CEFBS_None, // G_ATOMICRMW_XOR = 73
    CEFBS_None, // G_ATOMICRMW_MAX = 74
    CEFBS_None, // G_ATOMICRMW_MIN = 75
    CEFBS_None, // G_ATOMICRMW_UMAX = 76
    CEFBS_None, // G_ATOMICRMW_UMIN = 77
    CEFBS_None, // G_FENCE = 78
    CEFBS_None, // G_BRCOND = 79
    CEFBS_None, // G_BRINDIRECT = 80
    CEFBS_None, // G_INTRINSIC = 81
    CEFBS_None, // G_INTRINSIC_W_SIDE_EFFECTS = 82
    CEFBS_None, // G_ANYEXT = 83
    CEFBS_None, // G_TRUNC = 84
    CEFBS_None, // G_CONSTANT = 85
    CEFBS_None, // G_FCONSTANT = 86
    CEFBS_None, // G_VASTART = 87
    CEFBS_None, // G_VAARG = 88
    CEFBS_None, // G_SEXT = 89
    CEFBS_None, // G_ZEXT = 90
    CEFBS_None, // G_SHL = 91
    CEFBS_None, // G_LSHR = 92
    CEFBS_None, // G_ASHR = 93
    CEFBS_None, // G_ICMP = 94
    CEFBS_None, // G_FCMP = 95
    CEFBS_None, // G_SELECT = 96
    CEFBS_None, // G_UADDO = 97
    CEFBS_None, // G_UADDE = 98
    CEFBS_None, // G_USUBO = 99
    CEFBS_None, // G_USUBE = 100
    CEFBS_None, // G_SADDO = 101
    CEFBS_None, // G_SADDE = 102
    CEFBS_None, // G_SSUBO = 103
    CEFBS_None, // G_SSUBE = 104
    CEFBS_None, // G_UMULO = 105
    CEFBS_None, // G_SMULO = 106
    CEFBS_None, // G_UMULH = 107
    CEFBS_None, // G_SMULH = 108
    CEFBS_None, // G_FADD = 109
    CEFBS_None, // G_FSUB = 110
    CEFBS_None, // G_FMUL = 111
    CEFBS_None, // G_FMA = 112
    CEFBS_None, // G_FDIV = 113
    CEFBS_None, // G_FREM = 114
    CEFBS_None, // G_FPOW = 115
    CEFBS_None, // G_FEXP = 116
    CEFBS_None, // G_FEXP2 = 117
    CEFBS_None, // G_FLOG = 118
    CEFBS_None, // G_FLOG2 = 119
    CEFBS_None, // G_FLOG10 = 120
    CEFBS_None, // G_FNEG = 121
    CEFBS_None, // G_FPEXT = 122
    CEFBS_None, // G_FPTRUNC = 123
    CEFBS_None, // G_FPTOSI = 124
    CEFBS_None, // G_FPTOUI = 125
    CEFBS_None, // G_SITOFP = 126
    CEFBS_None, // G_UITOFP = 127
    CEFBS_None, // G_FABS = 128
    CEFBS_None, // G_FCOPYSIGN = 129
    CEFBS_None, // G_FCANONICALIZE = 130
    CEFBS_None, // G_FMINNUM = 131
    CEFBS_None, // G_FMAXNUM = 132
    CEFBS_None, // G_FMINNUM_IEEE = 133
    CEFBS_None, // G_FMAXNUM_IEEE = 134
    CEFBS_None, // G_FMINIMUM = 135
    CEFBS_None, // G_FMAXIMUM = 136
    CEFBS_None, // G_GEP = 137
    CEFBS_None, // G_PTR_MASK = 138
    CEFBS_None, // G_SMIN = 139
    CEFBS_None, // G_SMAX = 140
    CEFBS_None, // G_UMIN = 141
    CEFBS_None, // G_UMAX = 142
    CEFBS_None, // G_BR = 143
    CEFBS_None, // G_BRJT = 144
    CEFBS_None, // G_INSERT_VECTOR_ELT = 145
    CEFBS_None, // G_EXTRACT_VECTOR_ELT = 146
    CEFBS_None, // G_SHUFFLE_VECTOR = 147
    CEFBS_None, // G_CTTZ = 148
    CEFBS_None, // G_CTTZ_ZERO_UNDEF = 149
    CEFBS_None, // G_CTLZ = 150
    CEFBS_None, // G_CTLZ_ZERO_UNDEF = 151
    CEFBS_None, // G_CTPOP = 152
    CEFBS_None, // G_BSWAP = 153
    CEFBS_None, // G_FCEIL = 154
    CEFBS_None, // G_FCOS = 155
    CEFBS_None, // G_FSIN = 156
    CEFBS_None, // G_FSQRT = 157
    CEFBS_None, // G_FFLOOR = 158
    CEFBS_None, // G_FRINT = 159
    CEFBS_None, // G_FNEARBYINT = 160
    CEFBS_None, // G_ADDRSPACE_CAST = 161
    CEFBS_None, // G_BLOCK_ADDR = 162
    CEFBS_None, // G_JUMP_TABLE = 163
    CEFBS_None, // ADJCALLSTACKDOWN = 164
    CEFBS_None, // ADJCALLSTACKUP = 165
    CEFBS_HasStdExtD, // BuildPairF64Pseudo = 166
    CEFBS_None, // PseudoAddTPRel = 167
    CEFBS_HasStdExtA, // PseudoAtomicLoadNand32 = 168
    CEFBS_HasStdExtA_IsRV64, // PseudoAtomicLoadNand64 = 169
    CEFBS_None, // PseudoBR = 170
    CEFBS_None, // PseudoBRIND = 171
    CEFBS_None, // PseudoCALL = 172
    CEFBS_None, // PseudoCALLIndirect = 173
    CEFBS_None, // PseudoCALLReg = 174
    CEFBS_HasStdExtA, // PseudoCmpXchg32 = 175
    CEFBS_HasStdExtA_IsRV64, // PseudoCmpXchg64 = 176
    CEFBS_HasStdExtD, // PseudoFLD = 177
    CEFBS_HasStdExtF, // PseudoFLW = 178
    CEFBS_HasStdExtD, // PseudoFSD = 179
    CEFBS_HasStdExtF, // PseudoFSW = 180
    CEFBS_None, // PseudoLA = 181
    CEFBS_None, // PseudoLA_TLS_GD = 182
    CEFBS_None, // PseudoLA_TLS_IE = 183
    CEFBS_None, // PseudoLB = 184
    CEFBS_None, // PseudoLBU = 185
    CEFBS_IsRV64, // PseudoLD = 186
    CEFBS_None, // PseudoLH = 187
    CEFBS_None, // PseudoLHU = 188
    CEFBS_None, // PseudoLI = 189
    CEFBS_None, // PseudoLLA = 190
    CEFBS_None, // PseudoLW = 191
    CEFBS_IsRV64, // PseudoLWU = 192
    CEFBS_HasStdExtA, // PseudoMaskedAtomicLoadAdd32 = 193
    CEFBS_HasStdExtA, // PseudoMaskedAtomicLoadMax32 = 194
    CEFBS_HasStdExtA, // PseudoMaskedAtomicLoadMin32 = 195
    CEFBS_HasStdExtA, // PseudoMaskedAtomicLoadNand32 = 196
    CEFBS_HasStdExtA, // PseudoMaskedAtomicLoadSub32 = 197
    CEFBS_HasStdExtA, // PseudoMaskedAtomicLoadUMax32 = 198
    CEFBS_HasStdExtA, // PseudoMaskedAtomicLoadUMin32 = 199
    CEFBS_HasStdExtA, // PseudoMaskedAtomicSwap32 = 200
    CEFBS_HasStdExtA, // PseudoMaskedCmpXchg32 = 201
    CEFBS_None, // PseudoRET = 202
    CEFBS_None, // PseudoSB = 203
    CEFBS_IsRV64, // PseudoSD = 204
    CEFBS_None, // PseudoSH = 205
    CEFBS_None, // PseudoSW = 206
    CEFBS_None, // PseudoTAIL = 207
    CEFBS_None, // PseudoTAILIndirect = 208
    CEFBS_IsRV32, // ReadCycleWide = 209
    CEFBS_HasStdExtF, // Select_FPR32_Using_CC_GPR = 210
    CEFBS_HasStdExtD, // Select_FPR64_Using_CC_GPR = 211
    CEFBS_None, // Select_GPR_Using_CC_GPR = 212
    CEFBS_HasStdExtD, // SplitF64Pseudo = 213
    CEFBS_None, // ADD = 214
    CEFBS_None, // ADDI = 215
    CEFBS_IsRV64, // ADDIW = 216
    CEFBS_IsRV64, // ADDW = 217
    CEFBS_HasStdExtA_IsRV64, // AMOADD_D = 218
    CEFBS_HasStdExtA_IsRV64, // AMOADD_D_AQ = 219
    CEFBS_HasStdExtA_IsRV64, // AMOADD_D_AQ_RL = 220
    CEFBS_HasStdExtA_IsRV64, // AMOADD_D_RL = 221
    CEFBS_HasStdExtA, // AMOADD_W = 222
    CEFBS_HasStdExtA, // AMOADD_W_AQ = 223
    CEFBS_HasStdExtA, // AMOADD_W_AQ_RL = 224
    CEFBS_HasStdExtA, // AMOADD_W_RL = 225
    CEFBS_HasStdExtA_IsRV64, // AMOAND_D = 226
    CEFBS_HasStdExtA_IsRV64, // AMOAND_D_AQ = 227
    CEFBS_HasStdExtA_IsRV64, // AMOAND_D_AQ_RL = 228
    CEFBS_HasStdExtA_IsRV64, // AMOAND_D_RL = 229
    CEFBS_HasStdExtA, // AMOAND_W = 230
    CEFBS_HasStdExtA, // AMOAND_W_AQ = 231
    CEFBS_HasStdExtA, // AMOAND_W_AQ_RL = 232
    CEFBS_HasStdExtA, // AMOAND_W_RL = 233
    CEFBS_HasStdExtA_IsRV64, // AMOMAXU_D = 234
    CEFBS_HasStdExtA_IsRV64, // AMOMAXU_D_AQ = 235
    CEFBS_HasStdExtA_IsRV64, // AMOMAXU_D_AQ_RL = 236
    CEFBS_HasStdExtA_IsRV64, // AMOMAXU_D_RL = 237
    CEFBS_HasStdExtA, // AMOMAXU_W = 238
    CEFBS_HasStdExtA, // AMOMAXU_W_AQ = 239
    CEFBS_HasStdExtA, // AMOMAXU_W_AQ_RL = 240
    CEFBS_HasStdExtA, // AMOMAXU_W_RL = 241
    CEFBS_HasStdExtA_IsRV64, // AMOMAX_D = 242
    CEFBS_HasStdExtA_IsRV64, // AMOMAX_D_AQ = 243
    CEFBS_HasStdExtA_IsRV64, // AMOMAX_D_AQ_RL = 244
    CEFBS_HasStdExtA_IsRV64, // AMOMAX_D_RL = 245
    CEFBS_HasStdExtA, // AMOMAX_W = 246
    CEFBS_HasStdExtA, // AMOMAX_W_AQ = 247
    CEFBS_HasStdExtA, // AMOMAX_W_AQ_RL = 248
    CEFBS_HasStdExtA, // AMOMAX_W_RL = 249
    CEFBS_HasStdExtA_IsRV64, // AMOMINU_D = 250
    CEFBS_HasStdExtA_IsRV64, // AMOMINU_D_AQ = 251
    CEFBS_HasStdExtA_IsRV64, // AMOMINU_D_AQ_RL = 252
    CEFBS_HasStdExtA_IsRV64, // AMOMINU_D_RL = 253
    CEFBS_HasStdExtA, // AMOMINU_W = 254
    CEFBS_HasStdExtA, // AMOMINU_W_AQ = 255
    CEFBS_HasStdExtA, // AMOMINU_W_AQ_RL = 256
    CEFBS_HasStdExtA, // AMOMINU_W_RL = 257
    CEFBS_HasStdExtA_IsRV64, // AMOMIN_D = 258
    CEFBS_HasStdExtA_IsRV64, // AMOMIN_D_AQ = 259
    CEFBS_HasStdExtA_IsRV64, // AMOMIN_D_AQ_RL = 260
    CEFBS_HasStdExtA_IsRV64, // AMOMIN_D_RL = 261
    CEFBS_HasStdExtA, // AMOMIN_W = 262
    CEFBS_HasStdExtA, // AMOMIN_W_AQ = 263
    CEFBS_HasStdExtA, // AMOMIN_W_AQ_RL = 264
    CEFBS_HasStdExtA, // AMOMIN_W_RL = 265
    CEFBS_HasStdExtA_IsRV64, // AMOOR_D = 266
    CEFBS_HasStdExtA_IsRV64, // AMOOR_D_AQ = 267
    CEFBS_HasStdExtA_IsRV64, // AMOOR_D_AQ_RL = 268
    CEFBS_HasStdExtA_IsRV64, // AMOOR_D_RL = 269
    CEFBS_HasStdExtA, // AMOOR_W = 270
    CEFBS_HasStdExtA, // AMOOR_W_AQ = 271
    CEFBS_HasStdExtA, // AMOOR_W_AQ_RL = 272
    CEFBS_HasStdExtA, // AMOOR_W_RL = 273
    CEFBS_HasStdExtA_IsRV64, // AMOSWAP_D = 274
    CEFBS_HasStdExtA_IsRV64, // AMOSWAP_D_AQ = 275
    CEFBS_HasStdExtA_IsRV64, // AMOSWAP_D_AQ_RL = 276
    CEFBS_HasStdExtA_IsRV64, // AMOSWAP_D_RL = 277
    CEFBS_HasStdExtA, // AMOSWAP_W = 278
    CEFBS_HasStdExtA, // AMOSWAP_W_AQ = 279
    CEFBS_HasStdExtA, // AMOSWAP_W_AQ_RL = 280
    CEFBS_HasStdExtA, // AMOSWAP_W_RL = 281
    CEFBS_HasStdExtA_IsRV64, // AMOXOR_D = 282
    CEFBS_HasStdExtA_IsRV64, // AMOXOR_D_AQ = 283
    CEFBS_HasStdExtA_IsRV64, // AMOXOR_D_AQ_RL = 284
    CEFBS_HasStdExtA_IsRV64, // AMOXOR_D_RL = 285
    CEFBS_HasStdExtA, // AMOXOR_W = 286
    CEFBS_HasStdExtA, // AMOXOR_W_AQ = 287
    CEFBS_HasStdExtA, // AMOXOR_W_AQ_RL = 288
    CEFBS_HasStdExtA, // AMOXOR_W_RL = 289
    CEFBS_None, // AND = 290
    CEFBS_None, // ANDI = 291
    CEFBS_None, // AUIPC = 292
    CEFBS_None, // BEQ = 293
    CEFBS_None, // BGE = 294
    CEFBS_None, // BGEU = 295
    CEFBS_None, // BLT = 296
    CEFBS_None, // BLTU = 297
    CEFBS_None, // BNE = 298
    CEFBS_None, // CSRRC = 299
    CEFBS_None, // CSRRCI = 300
    CEFBS_None, // CSRRS = 301
    CEFBS_None, // CSRRSI = 302
    CEFBS_None, // CSRRW = 303
    CEFBS_None, // CSRRWI = 304
    CEFBS_HasStdExtC, // C_ADD = 305
    CEFBS_HasStdExtC, // C_ADDI = 306
    CEFBS_HasStdExtC, // C_ADDI16SP = 307
    CEFBS_HasStdExtC, // C_ADDI4SPN = 308
    CEFBS_HasStdExtC_IsRV64, // C_ADDIW = 309
    CEFBS_HasStdExtC_IsRV64, // C_ADDW = 310
    CEFBS_HasStdExtC, // C_AND = 311
    CEFBS_HasStdExtC, // C_ANDI = 312
    CEFBS_HasStdExtC, // C_BEQZ = 313
    CEFBS_HasStdExtC, // C_BNEZ = 314
    CEFBS_HasStdExtC, // C_EBREAK = 315
    CEFBS_HasStdExtC_HasStdExtD, // C_FLD = 316
    CEFBS_HasStdExtC_HasStdExtD, // C_FLDSP = 317
    CEFBS_HasStdExtC_HasStdExtF_IsRV32, // C_FLW = 318
    CEFBS_HasStdExtC_HasStdExtF_IsRV32, // C_FLWSP = 319
    CEFBS_HasStdExtC_HasStdExtD, // C_FSD = 320
    CEFBS_HasStdExtC_HasStdExtD, // C_FSDSP = 321
    CEFBS_HasStdExtC_HasStdExtF_IsRV32, // C_FSW = 322
    CEFBS_HasStdExtC_HasStdExtF_IsRV32, // C_FSWSP = 323
    CEFBS_HasStdExtC, // C_J = 324
    CEFBS_HasStdExtC_IsRV32, // C_JAL = 325
    CEFBS_HasStdExtC, // C_JALR = 326
    CEFBS_HasStdExtC, // C_JR = 327
    CEFBS_HasStdExtC_IsRV64, // C_LD = 328
    CEFBS_HasStdExtC_IsRV64, // C_LDSP = 329
    CEFBS_HasStdExtC, // C_LI = 330
    CEFBS_HasStdExtC, // C_LUI = 331
    CEFBS_HasStdExtC, // C_LW = 332
    CEFBS_HasStdExtC, // C_LWSP = 333
    CEFBS_HasStdExtC, // C_MV = 334
    CEFBS_HasStdExtC, // C_NOP = 335
    CEFBS_HasStdExtC, // C_OR = 336
    CEFBS_HasStdExtC_IsRV64, // C_SD = 337
    CEFBS_HasStdExtC_IsRV64, // C_SDSP = 338
    CEFBS_HasStdExtC, // C_SLLI = 339
    CEFBS_HasStdExtC, // C_SRAI = 340
    CEFBS_HasStdExtC, // C_SRLI = 341
    CEFBS_HasStdExtC, // C_SUB = 342
    CEFBS_HasStdExtC_IsRV64, // C_SUBW = 343
    CEFBS_HasStdExtC, // C_SW = 344
    CEFBS_HasStdExtC, // C_SWSP = 345
    CEFBS_HasStdExtC, // C_UNIMP = 346
    CEFBS_HasStdExtC, // C_XOR = 347
    CEFBS_HasStdExtM, // DIV = 348
    CEFBS_HasStdExtM, // DIVU = 349
    CEFBS_HasStdExtM_IsRV64, // DIVUW = 350
    CEFBS_HasStdExtM_IsRV64, // DIVW = 351
    CEFBS_None, // EBREAK = 352
    CEFBS_None, // ECALL = 353
    CEFBS_HasStdExtD, // FADD_D = 354
    CEFBS_HasStdExtF, // FADD_S = 355
    CEFBS_HasStdExtD, // FCLASS_D = 356
    CEFBS_HasStdExtF, // FCLASS_S = 357
    CEFBS_HasStdExtD_IsRV64, // FCVT_D_L = 358
    CEFBS_HasStdExtD_IsRV64, // FCVT_D_LU = 359
    CEFBS_HasStdExtD, // FCVT_D_S = 360
    CEFBS_HasStdExtD, // FCVT_D_W = 361
    CEFBS_HasStdExtD, // FCVT_D_WU = 362
    CEFBS_HasStdExtD_IsRV64, // FCVT_LU_D = 363
    CEFBS_HasStdExtF_IsRV64, // FCVT_LU_S = 364
    CEFBS_HasStdExtD_IsRV64, // FCVT_L_D = 365
    CEFBS_HasStdExtF_IsRV64, // FCVT_L_S = 366
    CEFBS_HasStdExtD, // FCVT_S_D = 367
    CEFBS_HasStdExtF_IsRV64, // FCVT_S_L = 368
    CEFBS_HasStdExtF_IsRV64, // FCVT_S_LU = 369
    CEFBS_HasStdExtF, // FCVT_S_W = 370
    CEFBS_HasStdExtF, // FCVT_S_WU = 371
    CEFBS_HasStdExtD, // FCVT_WU_D = 372
    CEFBS_HasStdExtF, // FCVT_WU_S = 373
    CEFBS_HasStdExtD, // FCVT_W_D = 374
    CEFBS_HasStdExtF, // FCVT_W_S = 375
    CEFBS_HasStdExtD, // FDIV_D = 376
    CEFBS_HasStdExtF, // FDIV_S = 377
    CEFBS_None, // FENCE = 378
    CEFBS_None, // FENCE_I = 379
    CEFBS_None, // FENCE_TSO = 380
    CEFBS_HasStdExtD, // FEQ_D = 381
    CEFBS_HasStdExtF, // FEQ_S = 382
    CEFBS_HasStdExtD, // FLD = 383
    CEFBS_HasStdExtD, // FLE_D = 384
    CEFBS_HasStdExtF, // FLE_S = 385
    CEFBS_HasStdExtD, // FLT_D = 386
    CEFBS_HasStdExtF, // FLT_S = 387
    CEFBS_HasStdExtF, // FLW = 388
    CEFBS_HasStdExtD, // FMADD_D = 389
    CEFBS_HasStdExtF, // FMADD_S = 390
    CEFBS_HasStdExtD, // FMAX_D = 391
    CEFBS_HasStdExtF, // FMAX_S = 392
    CEFBS_HasStdExtD, // FMIN_D = 393
    CEFBS_HasStdExtF, // FMIN_S = 394
    CEFBS_HasStdExtD, // FMSUB_D = 395
    CEFBS_HasStdExtF, // FMSUB_S = 396
    CEFBS_HasStdExtD, // FMUL_D = 397
    CEFBS_HasStdExtF, // FMUL_S = 398
    CEFBS_HasStdExtD_IsRV64, // FMV_D_X = 399
    CEFBS_HasStdExtF, // FMV_W_X = 400
    CEFBS_HasStdExtD_IsRV64, // FMV_X_D = 401
    CEFBS_HasStdExtF, // FMV_X_W = 402
    CEFBS_HasStdExtD, // FNMADD_D = 403
    CEFBS_HasStdExtF, // FNMADD_S = 404
    CEFBS_HasStdExtD, // FNMSUB_D = 405
    CEFBS_HasStdExtF, // FNMSUB_S = 406
    CEFBS_HasStdExtD, // FSD = 407
    CEFBS_HasStdExtD, // FSGNJN_D = 408
    CEFBS_HasStdExtF, // FSGNJN_S = 409
    CEFBS_HasStdExtD, // FSGNJX_D = 410
    CEFBS_HasStdExtF, // FSGNJX_S = 411
    CEFBS_HasStdExtD, // FSGNJ_D = 412
    CEFBS_HasStdExtF, // FSGNJ_S = 413
    CEFBS_HasStdExtD, // FSQRT_D = 414
    CEFBS_HasStdExtF, // FSQRT_S = 415
    CEFBS_HasStdExtD, // FSUB_D = 416
    CEFBS_HasStdExtF, // FSUB_S = 417
    CEFBS_HasStdExtF, // FSW = 418
    CEFBS_None, // JAL = 419
    CEFBS_None, // JALR = 420
    CEFBS_None, // LB = 421
    CEFBS_None, // LBU = 422
    CEFBS_IsRV64, // LD = 423
    CEFBS_None, // LH = 424
    CEFBS_None, // LHU = 425
    CEFBS_HasStdExtA_IsRV64, // LR_D = 426
    CEFBS_HasStdExtA_IsRV64, // LR_D_AQ = 427
    CEFBS_HasStdExtA_IsRV64, // LR_D_AQ_RL = 428
    CEFBS_HasStdExtA_IsRV64, // LR_D_RL = 429
    CEFBS_HasStdExtA, // LR_W = 430
    CEFBS_HasStdExtA, // LR_W_AQ = 431
    CEFBS_HasStdExtA, // LR_W_AQ_RL = 432
    CEFBS_HasStdExtA, // LR_W_RL = 433
    CEFBS_None, // LUI = 434
    CEFBS_None, // LW = 435
    CEFBS_IsRV64, // LWU = 436
    CEFBS_None, // MRET = 437
    CEFBS_HasStdExtM, // MUL = 438
    CEFBS_HasStdExtM, // MULH = 439
    CEFBS_HasStdExtM, // MULHSU = 440
    CEFBS_HasStdExtM, // MULHU = 441
    CEFBS_HasStdExtM_IsRV64, // MULW = 442
    CEFBS_None, // OR = 443
    CEFBS_None, // ORI = 444
    CEFBS_HasStdExtM, // REM = 445
    CEFBS_HasStdExtM, // REMU = 446
    CEFBS_HasStdExtM_IsRV64, // REMUW = 447
    CEFBS_HasStdExtM_IsRV64, // REMW = 448
    CEFBS_None, // SB = 449
    CEFBS_HasStdExtA_IsRV64, // SC_D = 450
    CEFBS_HasStdExtA_IsRV64, // SC_D_AQ = 451
    CEFBS_HasStdExtA_IsRV64, // SC_D_AQ_RL = 452
    CEFBS_HasStdExtA_IsRV64, // SC_D_RL = 453
    CEFBS_HasStdExtA, // SC_W = 454
    CEFBS_HasStdExtA, // SC_W_AQ = 455
    CEFBS_HasStdExtA, // SC_W_AQ_RL = 456
    CEFBS_HasStdExtA, // SC_W_RL = 457
    CEFBS_IsRV64, // SD = 458
    CEFBS_None, // SFENCE_VMA = 459
    CEFBS_None, // SH = 460
    CEFBS_None, // SLL = 461
    CEFBS_None, // SLLI = 462
    CEFBS_IsRV64, // SLLIW = 463
    CEFBS_IsRV64, // SLLW = 464
    CEFBS_None, // SLT = 465
    CEFBS_None, // SLTI = 466
    CEFBS_None, // SLTIU = 467
    CEFBS_None, // SLTU = 468
    CEFBS_None, // SRA = 469
    CEFBS_None, // SRAI = 470
    CEFBS_IsRV64, // SRAIW = 471
    CEFBS_IsRV64, // SRAW = 472
    CEFBS_None, // SRET = 473
    CEFBS_None, // SRL = 474
    CEFBS_None, // SRLI = 475
    CEFBS_IsRV64, // SRLIW = 476
    CEFBS_IsRV64, // SRLW = 477
    CEFBS_None, // SUB = 478
    CEFBS_IsRV64, // SUBW = 479
    CEFBS_None, // SW = 480
    CEFBS_None, // UNIMP = 481
    CEFBS_None, // URET = 482
    CEFBS_None, // WFI = 483
    CEFBS_None, // XOR = 484
    CEFBS_None, // XORI = 485
  };

  assert(Inst.getOpcode() < 486);
  const FeatureBitset &RequiredFeatures = FeatureBitsets[RequiredFeaturesRefs[Inst.getOpcode()]];
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  if (MissingFeatures.any()) {
    std::ostringstream Msg;
    Msg << "Attempting to emit " << MCII.getName(Inst.getOpcode()).str()
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str());
  }
#else
// Silence unused variable warning on targets that don't use MCII for other purposes (e.g. BPF).
(void)MCII;
#endif // NDEBUG
}
#endif
