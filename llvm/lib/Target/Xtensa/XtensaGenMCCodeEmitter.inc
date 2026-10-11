/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

uint64_t XtensaMCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
    SmallVectorImpl<MCFixup> &Fixups,
    const MCSubtargetInfo &STI) const {
  static const uint64_t InstBits[] = {
    UINT64_C(6291712),	// ABS
    UINT64_C(16384016),	// ABS_S
    UINT64_C(8388608),	// ADD
    UINT64_C(16384240),	// ADDEXPM_S
    UINT64_C(16384224),	// ADDEXP_S
    UINT64_C(49154),	// ADDI
    UINT64_C(11),	// ADDI_N
    UINT64_C(53250),	// ADDMI
    UINT64_C(9437184),	// ADDX2
    UINT64_C(10485760),	// ADDX4
    UINT64_C(11534336),	// ADDX8
    UINT64_C(10),	// ADD_N
    UINT64_C(655360),	// ADD_S
    UINT64_C(36864),	// ALL4
    UINT64_C(45056),	// ALL8
    UINT64_C(1048576),	// AND
    UINT64_C(131072),	// ANDB
    UINT64_C(1179648),	// ANDBC
    UINT64_C(32768),	// ANY4
    UINT64_C(40960),	// ANY8
    UINT64_C(16391),	// BALL
    UINT64_C(32775),	// BANY
    UINT64_C(20487),	// BBC
    UINT64_C(24583),	// BBCI
    UINT64_C(53255),	// BBS
    UINT64_C(57351),	// BBSI
    UINT64_C(4103),	// BEQ
    UINT64_C(38),	// BEQI
    UINT64_C(22),	// BEQZ
    UINT64_C(140),	// BEQZ_N
    UINT64_C(118),	// BF
    UINT64_C(40967),	// BGE
    UINT64_C(230),	// BGEI
    UINT64_C(45063),	// BGEU
    UINT64_C(246),	// BGEUI
    UINT64_C(214),	// BGEZ
    UINT64_C(8199),	// BLT
    UINT64_C(166),	// BLTI
    UINT64_C(12295),	// BLTU
    UINT64_C(182),	// BLTUI
    UINT64_C(150),	// BLTZ
    UINT64_C(49159),	// BNALL
    UINT64_C(36871),	// BNE
    UINT64_C(102),	// BNEI
    UINT64_C(86),	// BNEZ
    UINT64_C(204),	// BNEZ_N
    UINT64_C(7),	// BNONE
    UINT64_C(16384),	// BREAK
    UINT64_C(61485),	// BREAK_N
    UINT64_C(4214),	// BT
    UINT64_C(5),	// CALL0
    UINT64_C(53),	// CALL12
    UINT64_C(21),	// CALL4
    UINT64_C(37),	// CALL8
    UINT64_C(192),	// CALLX0
    UINT64_C(240),	// CALLX12
    UINT64_C(208),	// CALLX4
    UINT64_C(224),	// CALLX8
    UINT64_C(12189696),	// CEIL_S
    UINT64_C(3342336),	// CLAMPS
    UINT64_C(393216),	// CLR_BIT_GPIO_OUT
    UINT64_C(16384048),	// CONST_S
    UINT64_C(16384112),	// DIV0_S
    UINT64_C(7995392),	// DIVN_S
    UINT64_C(8240),	// DSYNC
    UINT64_C(54),	// ENTRY
    UINT64_C(8224),	// ESYNC
    UINT64_C(8320),	// EXCW
    UINT64_C(262144),	// EXTUI
    UINT64_C(8400),	// EXTW
    UINT64_C(13238272),	// FLOAT_S
    UINT64_C(11141120),	// FLOOR_S
    UINT64_C(405504),	// GET_GPIO_IN
    UINT64_C(5292032),	// IDTLB
    UINT64_C(5259264),	// IITLB
    UINT64_C(0),	// ILL
    UINT64_C(61549),	// ILL_N
    UINT64_C(8192),	// ISYNC
    UINT64_C(6),	// J
    UINT64_C(160),	// JX
    UINT64_C(36866),	// L16SI
    UINT64_C(4098),	// L16UI
    UINT64_C(589824),	// L32E
    UINT64_C(8194),	// L32I
    UINT64_C(8),	// L32I_N
    UINT64_C(1),	// L32R
    UINT64_C(2),	// L8UI
    UINT64_C(9437188),	// LDDEC
    UINT64_C(28896),	// LDDR32P
    UINT64_C(8388612),	// LDINC
    UINT64_C(49154),	// LEA_ADD
    UINT64_C(32886),	// LOOP
    UINT64_C(41078),	// LOOPGTZ
    UINT64_C(36982),	// LOOPNEZ
    UINT64_C(3),	// LSI
    UINT64_C(32771),	// LSIP
    UINT64_C(524288),	// LSX
    UINT64_C(1572864),	// LSXP
    UINT64_C(6946816),	// MADDN_S
    UINT64_C(4849664),	// MADD_S
    UINT64_C(5439488),	// MAX
    UINT64_C(7536640),	// MAXU
    UINT64_C(8384),	// MEMW
    UINT64_C(4390912),	// MIN
    UINT64_C(6488064),	// MINU
    UINT64_C(16384208),	// MKDADJ_S
    UINT64_C(16384192),	// MKSADJ_S
    UINT64_C(8585216),	// MOVEQZ
    UINT64_C(9109504),	// MOVEQZ_S
    UINT64_C(12779520),	// MOVF
    UINT64_C(13303808),	// MOVF_S
    UINT64_C(11730944),	// MOVGEZ
    UINT64_C(12255232),	// MOVGEZ_S
    UINT64_C(40962),	// MOVI
    UINT64_C(12),	// MOVI_N
    UINT64_C(10682368),	// MOVLTZ
    UINT64_C(11206656),	// MOVLTZ_S
    UINT64_C(9633792),	// MOVNEZ
    UINT64_C(10158080),	// MOVNEZ_S
    UINT64_C(4096),	// MOVSP
    UINT64_C(13828096),	// MOVT
    UINT64_C(14352384),	// MOVT_S
    UINT64_C(13),	// MOV_N
    UINT64_C(16384000),	// MOV_S
    UINT64_C(5898240),	// MSUB_S
    UINT64_C(13697024),	// MUL16S
    UINT64_C(12648448),	// MUL16U
    UINT64_C(8060932),	// MULA_AA_HH
    UINT64_C(7929860),	// MULA_AA_HL
    UINT64_C(7995396),	// MULA_AA_LH
    UINT64_C(7864324),	// MULA_AA_LL
    UINT64_C(3866628),	// MULA_AD_HH
    UINT64_C(3735556),	// MULA_AD_HL
    UINT64_C(3801092),	// MULA_AD_LH
    UINT64_C(3670020),	// MULA_AD_LL
    UINT64_C(7012356),	// MULA_DA_HH
    UINT64_C(5963780),	// MULA_DA_HH_LDDEC
    UINT64_C(4915204),	// MULA_DA_HH_LDINC
    UINT64_C(6881284),	// MULA_DA_HL
    UINT64_C(5832708),	// MULA_DA_HL_LDDEC
    UINT64_C(4784132),	// MULA_DA_HL_LDINC
    UINT64_C(6946820),	// MULA_DA_LH
    UINT64_C(5898244),	// MULA_DA_LH_LDDEC
    UINT64_C(4849668),	// MULA_DA_LH_LDINC
    UINT64_C(6815748),	// MULA_DA_LL
    UINT64_C(5767172),	// MULA_DA_LL_LDDEC
    UINT64_C(4718596),	// MULA_DA_LL_LDINC
    UINT64_C(2818052),	// MULA_DD_HH
    UINT64_C(1769476),	// MULA_DD_HH_LDDEC
    UINT64_C(720900),	// MULA_DD_HH_LDINC
    UINT64_C(2686980),	// MULA_DD_HL
    UINT64_C(1638404),	// MULA_DD_HL_LDDEC
    UINT64_C(589828),	// MULA_DD_HL_LDINC
    UINT64_C(2752516),	// MULA_DD_LH
    UINT64_C(1703940),	// MULA_DD_LH_LDDEC
    UINT64_C(655364),	// MULA_DD_LH_LDINC
    UINT64_C(2621444),	// MULA_DD_LL
    UINT64_C(1572868),	// MULA_DD_LL_LDDEC
    UINT64_C(524292),	// MULA_DD_LL_LDINC
    UINT64_C(8519680),	// MULL
    UINT64_C(11665408),	// MULSH
    UINT64_C(8323076),	// MULS_AA_HH
    UINT64_C(8192004),	// MULS_AA_HL
    UINT64_C(8257540),	// MULS_AA_LH
    UINT64_C(8126468),	// MULS_AA_LL
    UINT64_C(4128772),	// MULS_AD_HH
    UINT64_C(3997700),	// MULS_AD_HL
    UINT64_C(4063236),	// MULS_AD_LH
    UINT64_C(3932164),	// MULS_AD_LL
    UINT64_C(7274500),	// MULS_DA_HH
    UINT64_C(7143428),	// MULS_DA_HL
    UINT64_C(7208964),	// MULS_DA_LH
    UINT64_C(7077892),	// MULS_DA_LL
    UINT64_C(3080196),	// MULS_DD_HH
    UINT64_C(2949124),	// MULS_DD_HL
    UINT64_C(3014660),	// MULS_DD_LH
    UINT64_C(2883588),	// MULS_DD_LL
    UINT64_C(10616832),	// MULUH
    UINT64_C(7798788),	// MUL_AA_HH
    UINT64_C(7667716),	// MUL_AA_HL
    UINT64_C(7733252),	// MUL_AA_LH
    UINT64_C(7602180),	// MUL_AA_LL
    UINT64_C(3604484),	// MUL_AD_HH
    UINT64_C(3473412),	// MUL_AD_HL
    UINT64_C(3538948),	// MUL_AD_LH
    UINT64_C(3407876),	// MUL_AD_LL
    UINT64_C(6750212),	// MUL_DA_HH
    UINT64_C(6619140),	// MUL_DA_HL
    UINT64_C(6684676),	// MUL_DA_LH
    UINT64_C(6553604),	// MUL_DA_LL
    UINT64_C(2555908),	// MUL_DD_HH
    UINT64_C(2424836),	// MUL_DD_HL
    UINT64_C(2490372),	// MUL_DD_LH
    UINT64_C(2359300),	// MUL_DD_LL
    UINT64_C(2752512),	// MUL_S
    UINT64_C(6291456),	// NEG
    UINT64_C(16384096),	// NEG_S
    UINT64_C(16384176),	// NEXP01_S
    UINT64_C(8432),	// NOP
    UINT64_C(61501),	// NOP_N
    UINT64_C(4251648),	// NSA
    UINT64_C(4255744),	// NSAU
    UINT64_C(2818048),	// OEQ_S
    UINT64_C(7012352),	// OLE_S
    UINT64_C(4915200),	// OLT_S
    UINT64_C(2097152),	// OR
    UINT64_C(2228224),	// ORB
    UINT64_C(3276800),	// ORBC
    UINT64_C(5296128),	// PDTLB
    UINT64_C(5263360),	// PITLB
    UINT64_C(13762560),	// QUOS
    UINT64_C(12713984),	// QUOU
    UINT64_C(5287936),	// RDTLB0
    UINT64_C(5304320),	// RDTLB1
    UINT64_C(16384128),	// RECIP0_S
    UINT64_C(15859712),	// REMS
    UINT64_C(14811136),	// REMU
    UINT64_C(128),	// RET
    UINT64_C(144),	// RETW
    UINT64_C(61469),	// RETW_N
    UINT64_C(61453),	// RET_N
    UINT64_C(12800),	// RFDE
    UINT64_C(12288),	// RFE
    UINT64_C(12304),	// RFI
    UINT64_C(16384064),	// RFR
    UINT64_C(13312),	// RFWO
    UINT64_C(13568),	// RFWU
    UINT64_C(5255168),	// RITLB0
    UINT64_C(5271552),	// RITLB1
    UINT64_C(4227072),	// ROTW
    UINT64_C(9043968),	// ROUND_S
    UINT64_C(24576),	// RSIL
    UINT64_C(16384160),	// RSQRT0_S
    UINT64_C(196608),	// RSR
    UINT64_C(8208),	// RSYNC
    UINT64_C(14876672),	// RUR
    UINT64_C(20482),	// S16I
    UINT64_C(57346),	// S32C1I
    UINT64_C(4784128),	// S32E
    UINT64_C(24578),	// S32I
    UINT64_C(9),	// S32I_N
    UINT64_C(16386),	// S8I
    UINT64_C(28912),	// SDDR32P
    UINT64_C(397312),	// SET_BIT_GPIO_OUT
    UINT64_C(2293760),	// SEXT
    UINT64_C(10551296),	// SLL
    UINT64_C(65536),	// SLLI
    UINT64_C(16384144),	// SQRT0_S
    UINT64_C(11599872),	// SRA
    UINT64_C(2162688),	// SRAI
    UINT64_C(8454144),	// SRC
    UINT64_C(9502720),	// SRL
    UINT64_C(4259840),	// SRLI
    UINT64_C(4202496),	// SSA8L
    UINT64_C(4210688),	// SSAI
    UINT64_C(16387),	// SSI
    UINT64_C(49155),	// SSIP
    UINT64_C(4198400),	// SSL
    UINT64_C(4194304),	// SSR
    UINT64_C(4718592),	// SSX
    UINT64_C(5767168),	// SSXP
    UINT64_C(12582912),	// SUB
    UINT64_C(13631488),	// SUBX2
    UINT64_C(14680064),	// SUBX4
    UINT64_C(15728640),	// SUBX8
    UINT64_C(1703936),	// SUB_S
    UINT64_C(20480),	// SYSCALL
    UINT64_C(10092544),	// TRUNC_S
    UINT64_C(3866624),	// UEQ_S
    UINT64_C(14286848),	// UFLOAT_S
    UINT64_C(8060928),	// ULE_S
    UINT64_C(5963776),	// ULT_S
    UINT64_C(7536644),	// UMUL_AA_HH
    UINT64_C(7405572),	// UMUL_AA_HL
    UINT64_C(7471108),	// UMUL_AA_LH
    UINT64_C(7340036),	// UMUL_AA_LL
    UINT64_C(1769472),	// UN_S
    UINT64_C(15335424),	// UTRUNC_S
    UINT64_C(28672),	// WAITI
    UINT64_C(5300224),	// WDTLB
    UINT64_C(16384080),	// WFR
    UINT64_C(5267456),	// WITLB
    UINT64_C(401408),	// WR_MASK_GPIO_OUT
    UINT64_C(1245184),	// WSR
    UINT64_C(15925248),	// WUR
    UINT64_C(3145728),	// XOR
    UINT64_C(4325376),	// XORB
    UINT64_C(6356992),	// XSR
  };
  constexpr unsigned FirstSupportedOpcode = 341;

  const unsigned opcode = MI.getOpcode();
  if (opcode < FirstSupportedOpcode)
    reportUnsupportedInst(MI);
  unsigned TableIndex = opcode - FirstSupportedOpcode;
  uint64_t Value = InstBits[TableIndex];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case Xtensa::DSYNC:
    case Xtensa::ESYNC:
    case Xtensa::EXCW:
    case Xtensa::EXTW:
    case Xtensa::ILL:
    case Xtensa::ILL_N:
    case Xtensa::ISYNC:
    case Xtensa::MEMW:
    case Xtensa::NOP:
    case Xtensa::NOP_N:
    case Xtensa::RET:
    case Xtensa::RETW:
    case Xtensa::RETW_N:
    case Xtensa::RET_N:
    case Xtensa::RFDE:
    case Xtensa::RFE:
    case Xtensa::RFWO:
    case Xtensa::RFWU:
    case Xtensa::RSYNC:
    case Xtensa::SYSCALL: {
      break;
    }
    case Xtensa::ROTW: {
      // op: imm
      op = getImm8n_7OpValue(MI, 0, Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::CLR_BIT_GPIO_OUT:
    case Xtensa::SET_BIT_GPIO_OUT: {
      // op: imm
      op = getSelect_256OpValue(MI, 0, Fixups, STI);
      Value |= (op & 0xff) << 4;
      break;
    }
    case Xtensa::BREAK_N:
    case Xtensa::RFI:
    case Xtensa::WAITI: {
      // op: imm
      op = getUimm4OpValue(MI, 0, Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::SSAI: {
      // op: imm
      op = getUimm5OpValue(MI, 0, Fixups, STI);
      Value |= (op & 0xf) << 8;
      Value |= (op & 0x10);
      break;
    }
    case Xtensa::MOVI_N: {
      // op: imm7
      op = getImm32n_95OpValue(MI, 1, Fixups, STI);
      Value |= (op & 0xf) << 12;
      Value |= (op & 0x70);
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::CALL0:
    case Xtensa::CALL12:
    case Xtensa::CALL4:
    case Xtensa::CALL8: {
      // op: offset
      op = getCallEncoding(MI, 0, Fixups, STI);
      Value |= (op & 0x3ffff) << 6;
      break;
    }
    case Xtensa::J: {
      // op: offset
      op = getJumpTargetEncoding(MI, 0, Fixups, STI);
      Value |= (op & 0x3ffff) << 6;
      break;
    }
    case Xtensa::CONST_S: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: imm
      op = getUimm4OpValue(MI, 1, Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::ABS_S:
    case Xtensa::ADDEXPM_S:
    case Xtensa::ADDEXP_S:
    case Xtensa::DIV0_S:
    case Xtensa::MKDADJ_S:
    case Xtensa::MKSADJ_S:
    case Xtensa::MOV_S:
    case Xtensa::NEG_S:
    case Xtensa::NEXP01_S:
    case Xtensa::RECIP0_S:
    case Xtensa::RFR:
    case Xtensa::RSQRT0_S:
    case Xtensa::SLL:
    case Xtensa::SQRT0_S:
    case Xtensa::WFR: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::ADDI_N: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: imm
      op = getImm1n_15OpValue(MI, 2, Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::CLAMPS:
    case Xtensa::SEXT: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: imm
      op = getImm7_22OpValue(MI, 2, Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::CEIL_S:
    case Xtensa::FLOAT_S:
    case Xtensa::FLOOR_S:
    case Xtensa::ROUND_S:
    case Xtensa::TRUNC_S:
    case Xtensa::UFLOAT_S:
    case Xtensa::UTRUNC_S: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: imm
      op = getUimm4OpValue(MI, 2, Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::SLLI: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: sa
      op = getShimm1_31OpValue(MI, 2, Fixups, STI);
      Value |= (op & 0x10) << 16;
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::ADD:
    case Xtensa::ADDX2:
    case Xtensa::ADDX4:
    case Xtensa::ADDX8:
    case Xtensa::ADD_N:
    case Xtensa::ADD_S:
    case Xtensa::AND:
    case Xtensa::ANDB:
    case Xtensa::ANDBC:
    case Xtensa::DIVN_S:
    case Xtensa::LSX:
    case Xtensa::LSXP:
    case Xtensa::MADDN_S:
    case Xtensa::MAX:
    case Xtensa::MAXU:
    case Xtensa::MIN:
    case Xtensa::MINU:
    case Xtensa::MOVEQZ:
    case Xtensa::MOVEQZ_S:
    case Xtensa::MOVF_S:
    case Xtensa::MOVGEZ:
    case Xtensa::MOVGEZ_S:
    case Xtensa::MOVLTZ:
    case Xtensa::MOVLTZ_S:
    case Xtensa::MOVNEZ:
    case Xtensa::MOVNEZ_S:
    case Xtensa::MOVT_S:
    case Xtensa::MUL16S:
    case Xtensa::MUL16U:
    case Xtensa::MULL:
    case Xtensa::MULSH:
    case Xtensa::MULUH:
    case Xtensa::MUL_S:
    case Xtensa::OEQ_S:
    case Xtensa::OLE_S:
    case Xtensa::OLT_S:
    case Xtensa::OR:
    case Xtensa::ORB:
    case Xtensa::ORBC:
    case Xtensa::QUOS:
    case Xtensa::QUOU:
    case Xtensa::REMS:
    case Xtensa::REMU:
    case Xtensa::SRC:
    case Xtensa::SSX:
    case Xtensa::SSXP:
    case Xtensa::SUB:
    case Xtensa::SUBX2:
    case Xtensa::SUBX4:
    case Xtensa::SUBX8:
    case Xtensa::SUB_S:
    case Xtensa::UEQ_S:
    case Xtensa::ULE_S:
    case Xtensa::ULT_S:
    case Xtensa::UN_S:
    case Xtensa::XOR:
    case Xtensa::XORB: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::MADD_S:
    case Xtensa::MSUB_S: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::ABS:
    case Xtensa::NEG:
    case Xtensa::SRA:
    case Xtensa::SRL: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::EXTUI: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: imm1
      op = getUimm5OpValue(MI, 2, Fixups, STI);
      Value |= (op & 0x10) << 12;
      Value |= (op & 0xf) << 8;
      // op: imm2
      op = getImm1_16OpValue(MI, 3, Fixups, STI);
      Value |= (op & 0xf) << 20;
      break;
    }
    case Xtensa::SRLI: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: sa
      op = getUimm4OpValue(MI, 2, Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::SRAI: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: sa
      op = getUimm5OpValue(MI, 2, Fixups, STI);
      Value |= (op & 0x10) << 16;
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::RUR: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: ur
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xff) << 4;
      break;
    }
    case Xtensa::MOVF:
    case Xtensa::MOVT: {
      // op: r
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::CALLX0:
    case Xtensa::CALLX12:
    case Xtensa::CALLX4:
    case Xtensa::CALLX8:
    case Xtensa::IDTLB:
    case Xtensa::IITLB:
    case Xtensa::JX:
    case Xtensa::LDDR32P:
    case Xtensa::SDDR32P:
    case Xtensa::SSA8L:
    case Xtensa::SSL:
    case Xtensa::SSR: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::BEQI:
    case Xtensa::BGEI:
    case Xtensa::BLTI:
    case Xtensa::BNEI: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: imm
      op = getB4constOpValue(MI, 1, Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: target
      op = getBranchTargetEncoding(MI, 2, Fixups, STI);
      Value |= (op & 0xff) << 16;
      break;
    }
    case Xtensa::BGEUI:
    case Xtensa::BLTUI: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: imm
      op = getB4constuOpValue(MI, 1, Fixups, STI);
      Value |= (op & 0xf) << 12;
      // op: target
      op = getBranchTargetEncoding(MI, 2, Fixups, STI);
      Value |= (op & 0xff) << 16;
      break;
    }
    case Xtensa::ENTRY: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: imm
      op = getEntry_Imm12OpValue(MI, 1, Fixups, STI);
      Value |= (op & 0x7ff8) << 9;
      break;
    }
    case Xtensa::MULA_AA_HH:
    case Xtensa::MULA_AA_HL:
    case Xtensa::MULA_AA_LH:
    case Xtensa::MULA_AA_LL:
    case Xtensa::MULS_AA_HH:
    case Xtensa::MULS_AA_HL:
    case Xtensa::MULS_AA_LH:
    case Xtensa::MULS_AA_LL:
    case Xtensa::MUL_AA_HH:
    case Xtensa::MUL_AA_HL:
    case Xtensa::MUL_AA_LH:
    case Xtensa::MUL_AA_LL:
    case Xtensa::UMUL_AA_HH:
    case Xtensa::UMUL_AA_HL:
    case Xtensa::UMUL_AA_LH:
    case Xtensa::UMUL_AA_LL:
    case Xtensa::WR_MASK_GPIO_OUT: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::BALL:
    case Xtensa::BANY:
    case Xtensa::BBC:
    case Xtensa::BBS:
    case Xtensa::BEQ:
    case Xtensa::BGE:
    case Xtensa::BGEU:
    case Xtensa::BLT:
    case Xtensa::BLTU:
    case Xtensa::BNALL:
    case Xtensa::BNE:
    case Xtensa::BNONE: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: target
      op = getBranchTargetEncoding(MI, 2, Fixups, STI);
      Value |= (op & 0xff) << 16;
      break;
    }
    case Xtensa::BEQZ_N:
    case Xtensa::BNEZ_N: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: target
      op = getBranchTargetEncoding(MI, 1, Fixups, STI);
      Value |= (op & 0xf) << 12;
      Value |= (op & 0x30);
      break;
    }
    case Xtensa::BEQZ:
    case Xtensa::BGEZ:
    case Xtensa::BLTZ:
    case Xtensa::BNEZ: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: target
      op = getBranchTargetEncoding(MI, 1, Fixups, STI);
      Value |= (op & 0xfff) << 12;
      break;
    }
    case Xtensa::BBCI:
    case Xtensa::BBSI: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: target
      op = getBranchTargetEncoding(MI, 2, Fixups, STI);
      Value |= (op & 0xff) << 16;
      // op: imm
      op = getUimm5OpValue(MI, 1, Fixups, STI);
      Value |= (op & 0x10) << 8;
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::LOOP:
    case Xtensa::LOOPGTZ:
    case Xtensa::LOOPNEZ: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: target
      op = getLoopTargetEncoding(MI, 1, Fixups, STI);
      Value |= (op & 0xff) << 16;
      break;
    }
    case Xtensa::MULA_AD_HH:
    case Xtensa::MULA_AD_HL:
    case Xtensa::MULA_AD_LH:
    case Xtensa::MULA_AD_LL:
    case Xtensa::MULS_AD_HH:
    case Xtensa::MULS_AD_HL:
    case Xtensa::MULS_AD_LH:
    case Xtensa::MULS_AD_LL:
    case Xtensa::MUL_AD_HH:
    case Xtensa::MUL_AD_HL:
    case Xtensa::MUL_AD_LH:
    case Xtensa::MUL_AD_LL: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: y
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 6;
      break;
    }
    case Xtensa::ALL4:
    case Xtensa::ALL8:
    case Xtensa::ANY4:
    case Xtensa::ANY8:
    case Xtensa::MOVSP:
    case Xtensa::MOV_N:
    case Xtensa::NSA:
    case Xtensa::NSAU:
    case Xtensa::PDTLB:
    case Xtensa::PITLB:
    case Xtensa::RDTLB0:
    case Xtensa::RDTLB1:
    case Xtensa::RITLB0:
    case Xtensa::RITLB1:
    case Xtensa::WDTLB:
    case Xtensa::WITLB: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::L32E:
    case Xtensa::S32E: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: imm
      op = getImm64n_4nOpValue(MI, 2, Fixups, STI);
      Value |= (op & 0x3c) << 10;
      break;
    }
    case Xtensa::ADDI: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: imm8
      op = getImm8OpValue(MI, 2, Fixups, STI);
      Value |= (op & 0xff) << 16;
      break;
    }
    case Xtensa::ADDMI: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: imm_sh8
      op = getImm8_sh8OpValue(MI, 2, Fixups, STI);
      Value |= (op & 0xff00) << 8;
      break;
    }
    case Xtensa::MULA_DA_HH_LDDEC:
    case Xtensa::MULA_DA_HH_LDINC:
    case Xtensa::MULA_DA_HL_LDDEC:
    case Xtensa::MULA_DA_HL_LDINC:
    case Xtensa::MULA_DA_LH_LDDEC:
    case Xtensa::MULA_DA_LH_LDINC:
    case Xtensa::MULA_DA_LL_LDDEC:
    case Xtensa::MULA_DA_LL_LDINC: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: x
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 14;
      // op: w
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 12;
      break;
    }
    case Xtensa::LDDEC:
    case Xtensa::LDINC: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: w
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 12;
      break;
    }
    case Xtensa::MULA_DD_HH_LDDEC:
    case Xtensa::MULA_DD_HH_LDINC:
    case Xtensa::MULA_DD_HL_LDDEC:
    case Xtensa::MULA_DD_HL_LDINC:
    case Xtensa::MULA_DD_LH_LDDEC:
    case Xtensa::MULA_DD_LH_LDINC:
    case Xtensa::MULA_DD_LL_LDDEC:
    case Xtensa::MULA_DD_LL_LDINC: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: x
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 14;
      // op: y
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 6;
      // op: w
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 12;
      break;
    }
    case Xtensa::BREAK: {
      // op: s
      op = getUimm4OpValue(MI, 0, Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: t
      op = getUimm4OpValue(MI, 1, Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::WSR: {
      // op: sr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xff) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::RSR: {
      // op: sr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xff) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::XSR: {
      // op: sr
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xff) << 8;
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::GET_GPIO_IN: {
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Xtensa::L32I_N:
    case Xtensa::S32I_N: {
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: addr
      op = getMemRegEncoding(MI, 1, Fixups, STI);
      Value |= (op & 0xff) << 8;
      break;
    }
    case Xtensa::L16SI:
    case Xtensa::L16UI:
    case Xtensa::L32I:
    case Xtensa::L8UI:
    case Xtensa::LEA_ADD:
    case Xtensa::LSI:
    case Xtensa::LSIP:
    case Xtensa::S16I:
    case Xtensa::S32I:
    case Xtensa::S8I:
    case Xtensa::SSI:
    case Xtensa::SSIP: {
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: addr
      op = getMemRegEncoding(MI, 1, Fixups, STI);
      Value |= (op & 0xff0) << 12;
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::MOVI: {
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: imm
      op = getImm12OpValue(MI, 1, Fixups, STI);
      Value |= (op & 0xff) << 16;
      Value |= (op & 0xf00);
      break;
    }
    case Xtensa::RSIL: {
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: imm
      op = getUimm4OpValue(MI, 1, Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::L32R: {
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: label
      op = getL32RTargetEncoding(MI, 1, Fixups, STI);
      Value |= (op & 0xffff) << 8;
      break;
    }
    case Xtensa::S32C1I: {
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: addr
      op = getMemRegEncoding(MI, 2, Fixups, STI);
      Value |= (op & 0xff0) << 12;
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::WUR: {
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: ur
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xff) << 8;
      break;
    }
    case Xtensa::MULA_DA_HH:
    case Xtensa::MULA_DA_HL:
    case Xtensa::MULA_DA_LH:
    case Xtensa::MULA_DA_LL:
    case Xtensa::MULS_DA_HH:
    case Xtensa::MULS_DA_HL:
    case Xtensa::MULS_DA_LH:
    case Xtensa::MULS_DA_LL:
    case Xtensa::MUL_DA_HH:
    case Xtensa::MUL_DA_HL:
    case Xtensa::MUL_DA_LH:
    case Xtensa::MUL_DA_LL: {
      // op: t
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: x
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1) << 14;
      break;
    }
    case Xtensa::BF:
    case Xtensa::BT: {
      // op: target
      op = getBranchTargetEncoding(MI, 1, Fixups, STI);
      Value |= (op & 0xff) << 16;
      // op: b
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Xtensa::MULA_DD_HH:
    case Xtensa::MULA_DD_HL:
    case Xtensa::MULA_DD_LH:
    case Xtensa::MULA_DD_LL:
    case Xtensa::MULS_DD_HH:
    case Xtensa::MULS_DD_HL:
    case Xtensa::MULS_DD_LH:
    case Xtensa::MULS_DD_LL:
    case Xtensa::MUL_DD_HH:
    case Xtensa::MUL_DD_HL:
    case Xtensa::MUL_DD_LH:
    case Xtensa::MUL_DD_LL: {
      // op: x
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1) << 14;
      // op: y
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 6;
      break;
    }
  default:
    reportUnsupportedInst(MI);
  }
  return Value;
}

#ifdef GET_OPERAND_BIT_OFFSET
#undef GET_OPERAND_BIT_OFFSET

uint32_t XtensaMCCodeEmitter::getOperandBitOffset(const MCInst &MI,
    unsigned OpNum,
    const MCSubtargetInfo &STI) const {
  switch (MI.getOpcode()) {
    case Xtensa::DSYNC:
    case Xtensa::ESYNC:
    case Xtensa::EXCW:
    case Xtensa::EXTW:
    case Xtensa::ILL:
    case Xtensa::ILL_N:
    case Xtensa::ISYNC:
    case Xtensa::MEMW:
    case Xtensa::NOP:
    case Xtensa::NOP_N:
    case Xtensa::RET:
    case Xtensa::RETW:
    case Xtensa::RETW_N:
    case Xtensa::RET_N:
    case Xtensa::RFDE:
    case Xtensa::RFE:
    case Xtensa::RFWO:
    case Xtensa::RFWU:
    case Xtensa::RSYNC:
    case Xtensa::SYSCALL: {
      break;
    }
    case Xtensa::CLR_BIT_GPIO_OUT:
    case Xtensa::ROTW:
    case Xtensa::SET_BIT_GPIO_OUT:
    case Xtensa::SSAI: {
      switch (OpNum) {
      case 0:
        // op: imm
        return 4;
      }
      break;
    }
    case Xtensa::BREAK_N:
    case Xtensa::RFI:
    case Xtensa::WAITI: {
      switch (OpNum) {
      case 0:
        // op: imm
        return 8;
      }
      break;
    }
    case Xtensa::CALL0:
    case Xtensa::CALL12:
    case Xtensa::CALL4:
    case Xtensa::CALL8:
    case Xtensa::J: {
      switch (OpNum) {
      case 0:
        // op: offset
        return 6;
      }
      break;
    }
    case Xtensa::CONST_S: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 1:
        // op: imm
        return 8;
      }
      break;
    }
    case Xtensa::ADDI_N:
    case Xtensa::CEIL_S:
    case Xtensa::CLAMPS:
    case Xtensa::FLOAT_S:
    case Xtensa::FLOOR_S:
    case Xtensa::ROUND_S:
    case Xtensa::SEXT:
    case Xtensa::TRUNC_S:
    case Xtensa::UFLOAT_S:
    case Xtensa::UTRUNC_S: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 1:
        // op: s
        return 8;
      case 2:
        // op: imm
        return 4;
      }
      break;
    }
    case Xtensa::SLLI: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 1:
        // op: s
        return 8;
      case 2:
        // op: sa
        return 4;
      }
      break;
    }
    case Xtensa::ADD:
    case Xtensa::ADDX2:
    case Xtensa::ADDX4:
    case Xtensa::ADDX8:
    case Xtensa::ADD_N:
    case Xtensa::ADD_S:
    case Xtensa::AND:
    case Xtensa::ANDB:
    case Xtensa::ANDBC:
    case Xtensa::DIVN_S:
    case Xtensa::LSX:
    case Xtensa::LSXP:
    case Xtensa::MADDN_S:
    case Xtensa::MAX:
    case Xtensa::MAXU:
    case Xtensa::MIN:
    case Xtensa::MINU:
    case Xtensa::MOVEQZ:
    case Xtensa::MOVEQZ_S:
    case Xtensa::MOVF_S:
    case Xtensa::MOVGEZ:
    case Xtensa::MOVGEZ_S:
    case Xtensa::MOVLTZ:
    case Xtensa::MOVLTZ_S:
    case Xtensa::MOVNEZ:
    case Xtensa::MOVNEZ_S:
    case Xtensa::MOVT_S:
    case Xtensa::MUL16S:
    case Xtensa::MUL16U:
    case Xtensa::MULL:
    case Xtensa::MULSH:
    case Xtensa::MULUH:
    case Xtensa::MUL_S:
    case Xtensa::OEQ_S:
    case Xtensa::OLE_S:
    case Xtensa::OLT_S:
    case Xtensa::OR:
    case Xtensa::ORB:
    case Xtensa::ORBC:
    case Xtensa::QUOS:
    case Xtensa::QUOU:
    case Xtensa::REMS:
    case Xtensa::REMU:
    case Xtensa::SRC:
    case Xtensa::SSX:
    case Xtensa::SSXP:
    case Xtensa::SUB:
    case Xtensa::SUBX2:
    case Xtensa::SUBX4:
    case Xtensa::SUBX8:
    case Xtensa::SUB_S:
    case Xtensa::UEQ_S:
    case Xtensa::ULE_S:
    case Xtensa::ULT_S:
    case Xtensa::UN_S:
    case Xtensa::XOR:
    case Xtensa::XORB: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 1:
        // op: s
        return 8;
      case 2:
        // op: t
        return 4;
      }
      break;
    }
    case Xtensa::ABS_S:
    case Xtensa::ADDEXPM_S:
    case Xtensa::ADDEXP_S:
    case Xtensa::DIV0_S:
    case Xtensa::MKDADJ_S:
    case Xtensa::MKSADJ_S:
    case Xtensa::MOV_S:
    case Xtensa::NEG_S:
    case Xtensa::NEXP01_S:
    case Xtensa::RECIP0_S:
    case Xtensa::RFR:
    case Xtensa::RSQRT0_S:
    case Xtensa::SLL:
    case Xtensa::SQRT0_S:
    case Xtensa::WFR: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 1:
        // op: s
        return 8;
      }
      break;
    }
    case Xtensa::EXTUI: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 1:
        // op: t
        return 4;
      case 2:
        // op: imm1
        return 8;
      case 3:
        // op: imm2
        return 20;
      }
      break;
    }
    case Xtensa::SRAI:
    case Xtensa::SRLI: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 1:
        // op: t
        return 4;
      case 2:
        // op: sa
        return 8;
      }
      break;
    }
    case Xtensa::ABS:
    case Xtensa::NEG:
    case Xtensa::SRA:
    case Xtensa::SRL: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 1:
        // op: t
        return 4;
      }
      break;
    }
    case Xtensa::RUR: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 1:
        // op: ur
        return 4;
      }
      break;
    }
    case Xtensa::MADD_S:
    case Xtensa::MSUB_S: {
      switch (OpNum) {
      case 0:
        // op: r
        return 12;
      case 2:
        // op: s
        return 8;
      case 3:
        // op: t
        return 4;
      }
      break;
    }
    case Xtensa::BEQI:
    case Xtensa::BGEI:
    case Xtensa::BGEUI:
    case Xtensa::BLTI:
    case Xtensa::BLTUI:
    case Xtensa::BNEI: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      case 1:
        // op: imm
        return 12;
      case 2:
        // op: target
        return 16;
      }
      break;
    }
    case Xtensa::ENTRY: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      case 1:
        // op: imm
        return 12;
      }
      break;
    }
    case Xtensa::BALL:
    case Xtensa::BANY:
    case Xtensa::BBC:
    case Xtensa::BBS:
    case Xtensa::BEQ:
    case Xtensa::BGE:
    case Xtensa::BGEU:
    case Xtensa::BLT:
    case Xtensa::BLTU:
    case Xtensa::BNALL:
    case Xtensa::BNE:
    case Xtensa::BNONE: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      case 1:
        // op: t
        return 4;
      case 2:
        // op: target
        return 16;
      }
      break;
    }
    case Xtensa::BREAK:
    case Xtensa::MULA_AA_HH:
    case Xtensa::MULA_AA_HL:
    case Xtensa::MULA_AA_LH:
    case Xtensa::MULA_AA_LL:
    case Xtensa::MULS_AA_HH:
    case Xtensa::MULS_AA_HL:
    case Xtensa::MULS_AA_LH:
    case Xtensa::MULS_AA_LL:
    case Xtensa::MUL_AA_HH:
    case Xtensa::MUL_AA_HL:
    case Xtensa::MUL_AA_LH:
    case Xtensa::MUL_AA_LL:
    case Xtensa::UMUL_AA_HH:
    case Xtensa::UMUL_AA_HL:
    case Xtensa::UMUL_AA_LH:
    case Xtensa::UMUL_AA_LL:
    case Xtensa::WR_MASK_GPIO_OUT: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      case 1:
        // op: t
        return 4;
      }
      break;
    }
    case Xtensa::BEQZ:
    case Xtensa::BGEZ:
    case Xtensa::BLTZ:
    case Xtensa::BNEZ: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      case 1:
        // op: target
        return 12;
      }
      break;
    }
    case Xtensa::LOOP:
    case Xtensa::LOOPGTZ:
    case Xtensa::LOOPNEZ: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      case 1:
        // op: target
        return 16;
      }
      break;
    }
    case Xtensa::BEQZ_N:
    case Xtensa::BNEZ_N: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      case 1:
        // op: target
        return 4;
      }
      break;
    }
    case Xtensa::MULA_AD_HH:
    case Xtensa::MULA_AD_HL:
    case Xtensa::MULA_AD_LH:
    case Xtensa::MULA_AD_LL:
    case Xtensa::MULS_AD_HH:
    case Xtensa::MULS_AD_HL:
    case Xtensa::MULS_AD_LH:
    case Xtensa::MULS_AD_LL:
    case Xtensa::MUL_AD_HH:
    case Xtensa::MUL_AD_HL:
    case Xtensa::MUL_AD_LH:
    case Xtensa::MUL_AD_LL: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      case 1:
        // op: y
        return 6;
      }
      break;
    }
    case Xtensa::BBCI:
    case Xtensa::BBSI: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      case 2:
        // op: target
        return 16;
      case 1:
        // op: imm
        return 4;
      }
      break;
    }
    case Xtensa::CALLX0:
    case Xtensa::CALLX12:
    case Xtensa::CALLX4:
    case Xtensa::CALLX8:
    case Xtensa::IDTLB:
    case Xtensa::IITLB:
    case Xtensa::JX:
    case Xtensa::LDDR32P:
    case Xtensa::SDDR32P:
    case Xtensa::SSA8L:
    case Xtensa::SSL:
    case Xtensa::SSR: {
      switch (OpNum) {
      case 0:
        // op: s
        return 8;
      }
      break;
    }
    case Xtensa::WSR: {
      switch (OpNum) {
      case 0:
        // op: sr
        return 8;
      case 1:
        // op: t
        return 4;
      }
      break;
    }
    case Xtensa::L16SI:
    case Xtensa::L16UI:
    case Xtensa::L32I:
    case Xtensa::L32I_N:
    case Xtensa::L8UI:
    case Xtensa::LEA_ADD:
    case Xtensa::LSI:
    case Xtensa::LSIP:
    case Xtensa::S16I:
    case Xtensa::S32I:
    case Xtensa::S32I_N:
    case Xtensa::S8I:
    case Xtensa::SSI:
    case Xtensa::SSIP: {
      switch (OpNum) {
      case 0:
        // op: t
        return 4;
      case 1:
        // op: addr
        return 8;
      }
      break;
    }
    case Xtensa::MOVI:
    case Xtensa::RSIL: {
      switch (OpNum) {
      case 0:
        // op: t
        return 4;
      case 1:
        // op: imm
        return 8;
      }
      break;
    }
    case Xtensa::L32R: {
      switch (OpNum) {
      case 0:
        // op: t
        return 4;
      case 1:
        // op: label
        return 8;
      }
      break;
    }
    case Xtensa::GET_GPIO_IN: {
      switch (OpNum) {
      case 0:
        // op: t
        return 4;
      }
      break;
    }
    case Xtensa::MULA_DD_HH:
    case Xtensa::MULA_DD_HL:
    case Xtensa::MULA_DD_LH:
    case Xtensa::MULA_DD_LL:
    case Xtensa::MULS_DD_HH:
    case Xtensa::MULS_DD_HL:
    case Xtensa::MULS_DD_LH:
    case Xtensa::MULS_DD_LL:
    case Xtensa::MUL_DD_HH:
    case Xtensa::MUL_DD_HL:
    case Xtensa::MUL_DD_LH:
    case Xtensa::MUL_DD_LL: {
      switch (OpNum) {
      case 0:
        // op: x
        return 14;
      case 1:
        // op: y
        return 6;
      }
      break;
    }
    case Xtensa::MOVI_N: {
      switch (OpNum) {
      case 1:
        // op: imm7
        return 4;
      case 0:
        // op: s
        return 8;
      }
      break;
    }
    case Xtensa::MOVF:
    case Xtensa::MOVT: {
      switch (OpNum) {
      case 1:
        // op: r
        return 12;
      case 2:
        // op: s
        return 8;
      case 3:
        // op: t
        return 4;
      }
      break;
    }
    case Xtensa::L32E:
    case Xtensa::S32E: {
      switch (OpNum) {
      case 1:
        // op: s
        return 8;
      case 0:
        // op: t
        return 4;
      case 2:
        // op: imm
        return 12;
      }
      break;
    }
    case Xtensa::ADDI: {
      switch (OpNum) {
      case 1:
        // op: s
        return 8;
      case 0:
        // op: t
        return 4;
      case 2:
        // op: imm8
        return 16;
      }
      break;
    }
    case Xtensa::ADDMI: {
      switch (OpNum) {
      case 1:
        // op: s
        return 8;
      case 0:
        // op: t
        return 4;
      case 2:
        // op: imm_sh8
        return 16;
      }
      break;
    }
    case Xtensa::ALL4:
    case Xtensa::ALL8:
    case Xtensa::ANY4:
    case Xtensa::ANY8:
    case Xtensa::MOVSP:
    case Xtensa::MOV_N:
    case Xtensa::NSA:
    case Xtensa::NSAU:
    case Xtensa::PDTLB:
    case Xtensa::PITLB:
    case Xtensa::RDTLB0:
    case Xtensa::RDTLB1:
    case Xtensa::RITLB0:
    case Xtensa::RITLB1:
    case Xtensa::WDTLB:
    case Xtensa::WITLB: {
      switch (OpNum) {
      case 1:
        // op: s
        return 8;
      case 0:
        // op: t
        return 4;
      }
      break;
    }
    case Xtensa::RSR: {
      switch (OpNum) {
      case 1:
        // op: sr
        return 8;
      case 0:
        // op: t
        return 4;
      }
      break;
    }
    case Xtensa::WUR: {
      switch (OpNum) {
      case 1:
        // op: t
        return 4;
      case 0:
        // op: ur
        return 8;
      }
      break;
    }
    case Xtensa::MULA_DA_HH:
    case Xtensa::MULA_DA_HL:
    case Xtensa::MULA_DA_LH:
    case Xtensa::MULA_DA_LL:
    case Xtensa::MULS_DA_HH:
    case Xtensa::MULS_DA_HL:
    case Xtensa::MULS_DA_LH:
    case Xtensa::MULS_DA_LL:
    case Xtensa::MUL_DA_HH:
    case Xtensa::MUL_DA_HL:
    case Xtensa::MUL_DA_LH:
    case Xtensa::MUL_DA_LL: {
      switch (OpNum) {
      case 1:
        // op: t
        return 4;
      case 0:
        // op: x
        return 14;
      }
      break;
    }
    case Xtensa::S32C1I: {
      switch (OpNum) {
      case 1:
        // op: t
        return 4;
      case 2:
        // op: addr
        return 8;
      }
      break;
    }
    case Xtensa::BF:
    case Xtensa::BT: {
      switch (OpNum) {
      case 1:
        // op: target
        return 16;
      case 0:
        // op: b
        return 8;
      }
      break;
    }
    case Xtensa::LDDEC:
    case Xtensa::LDINC: {
      switch (OpNum) {
      case 2:
        // op: s
        return 8;
      case 0:
        // op: w
        return 12;
      }
      break;
    }
    case Xtensa::MULA_DD_HH_LDDEC:
    case Xtensa::MULA_DD_HH_LDINC:
    case Xtensa::MULA_DD_HL_LDDEC:
    case Xtensa::MULA_DD_HL_LDINC:
    case Xtensa::MULA_DD_LH_LDDEC:
    case Xtensa::MULA_DD_LH_LDINC:
    case Xtensa::MULA_DD_LL_LDDEC:
    case Xtensa::MULA_DD_LL_LDINC: {
      switch (OpNum) {
      case 2:
        // op: s
        return 8;
      case 3:
        // op: x
        return 14;
      case 4:
        // op: y
        return 6;
      case 0:
        // op: w
        return 12;
      }
      break;
    }
    case Xtensa::MULA_DA_HH_LDDEC:
    case Xtensa::MULA_DA_HH_LDINC:
    case Xtensa::MULA_DA_HL_LDDEC:
    case Xtensa::MULA_DA_HL_LDINC:
    case Xtensa::MULA_DA_LH_LDDEC:
    case Xtensa::MULA_DA_LH_LDINC:
    case Xtensa::MULA_DA_LL_LDDEC:
    case Xtensa::MULA_DA_LL_LDINC: {
      switch (OpNum) {
      case 2:
        // op: s
        return 8;
      case 4:
        // op: t
        return 4;
      case 3:
        // op: x
        return 14;
      case 0:
        // op: w
        return 12;
      }
      break;
    }
    case Xtensa::XSR: {
      switch (OpNum) {
      case 3:
        // op: sr
        return 8;
      case 2:
        // op: t
        return 4;
      }
      break;
    }
  default:
    reportUnsupportedInst(MI);
  }
  reportUnsupportedOperand(MI, OpNum);
}

#endif // GET_OPERAND_BIT_OFFSET

