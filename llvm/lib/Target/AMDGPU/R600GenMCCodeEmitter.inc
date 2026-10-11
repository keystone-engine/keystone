/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

uint64_t R600MCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
    SmallVectorImpl<MCFixup> &Fixups,
    const MCSubtargetInfo &STI) const {
  static const uint64_t InstBits[] = {
    UINT64_C(0),	// ADD
    UINT64_C(45079976738816),	// ADDC_UINT
    UINT64_C(28587302322176),	// ADD_INT
    UINT64_C(0),	// ALU_CLAUSE
    UINT64_C(26388279066624),	// AND_INT
    UINT64_C(11544872091648),	// ASHR_eg
    UINT64_C(61572651155456),	// ASHR_r600
    UINT64_C(93458488360960),	// BCNT_INT
    UINT64_C(175921860444160),	// BFE_INT_eg
    UINT64_C(140737488355328),	// BFE_UINT_eg
    UINT64_C(211106232532992),	// BFI_INT_eg
    UINT64_C(87960930222080),	// BFM_INT_eg
    UINT64_C(422212465065984),	// BIT_ALIGN_INT_eg
    UINT64_C(9895604649984),	// CEIL
    UINT64_C(11529215046068469760),	// CF_ALU
    UINT64_C(13258597302978740224),	// CF_ALU_BREAK
    UINT64_C(12970366926827028480),	// CF_ALU_CONTINUE
    UINT64_C(13546827679130451968),	// CF_ALU_ELSE_AFTER
    UINT64_C(12105675798371893248),	// CF_ALU_POP_AFTER
    UINT64_C(11817445422220181504),	// CF_ALU_PUSH_BEFORE
    UINT64_C(9565645608534933504),	// CF_CALL_FS_EG
    UINT64_C(9907919180215091200),	// CF_CALL_FS_R600
    UINT64_C(9367487224930631680),	// CF_CONTINUE_EG
    UINT64_C(9511602413006487552),	// CF_CONTINUE_R600
    UINT64_C(9457559217478041600),	// CF_ELSE_EG
    UINT64_C(9691746398101307392),	// CF_ELSE_R600
    UINT64_C(9799832789158199296),	// CF_END_CM
    UINT64_C(9232379236109516800),	// CF_END_EG
    UINT64_C(9232379236109516800),	// CF_END_R600
    UINT64_C(9403516021949595648),	// CF_JUMP_EG
    UINT64_C(9583660007044415488),	// CF_JUMP_R600
    UINT64_C(9421530420459077632),	// CF_PUSH_EG
    UINT64_C(9655717601082343424),	// CF_PUSH_ELSE_R600
    UINT64_C(9241386435364257792),	// CF_TC_EG
    UINT64_C(9259400833873739776),	// CF_TC_R600
    UINT64_C(9259400833873739776),	// CF_VC_EG
    UINT64_C(9295429630892703744),	// CF_VC_R600
    UINT64_C(985162418487296),	// CNDE_INT
    UINT64_C(879609302220800),	// CNDE_eg
    UINT64_C(844424930131968),	// CNDE_r600
    UINT64_C(1055531162664960),	// CNDGE_INT
    UINT64_C(949978046398464),	// CNDGE_eg
    UINT64_C(914793674309632),	// CNDGE_r600
    UINT64_C(1020346790576128),	// CNDGT_INT
    UINT64_C(914793674309632),	// CNDGT_eg
    UINT64_C(879609302220800),	// CNDGT_r600
    UINT64_C(78065325572096),	// COS_cm
    UINT64_C(78065325572096),	// COS_eg
    UINT64_C(61022895341568),	// COS_r600
    UINT64_C(61022895341568),	// COS_r700
    UINT64_C(105553116266496),	// CUBE_eg_real
    UINT64_C(45079976738816),	// CUBE_r600_real
    UINT64_C(104453604638720),	// DOT4_eg
    UINT64_C(43980465111040),	// DOT4_r600
    UINT64_C(9223372036854775808),	// EG_ExportBuf
    UINT64_C(9223372040076001280),	// EG_ExportSwz
    UINT64_C(9313444029402185728),	// END_LOOP_EG
    UINT64_C(9403516021949595648),	// END_LOOP_R600
    UINT64_C(70918499991552),	// EXP_IEEE_cm
    UINT64_C(70918499991552),	// EXP_IEEE_eg
    UINT64_C(53326313947136),	// EXP_IEEE_r600
    UINT64_C(0),	// FETCH_CLAUSE
    UINT64_C(94008244174848),	// FFBH_UINT
    UINT64_C(94557999988736),	// FFBL_INT
    UINT64_C(10995116277760),	// FLOOR
    UINT64_C(89610197663744),	// FLT16_TO_FLT32
    UINT64_C(89060441849856),	// FLT32_TO_FLT16
    UINT64_C(43980465111040),	// FLT_TO_INT_eg
    UINT64_C(58823872086016),	// FLT_TO_INT_r600
    UINT64_C(84662395338752),	// FLT_TO_UINT_eg
    UINT64_C(66520453480448),	// FLT_TO_UINT_r600
    UINT64_C(246290604621824),	// FMA_eg
    UINT64_C(8796093022208),	// FRACT
    UINT64_C(46181635850240),	// GROUP_BARRIER
    UINT64_C(123145302310912),	// INTERP_LOAD_P0
    UINT64_C(4294967295),	// INTERP_PAIR_XY
    UINT64_C(4294967295),	// INTERP_PAIR_ZW
    UINT64_C(4294967295),	// INTERP_VEC_LOAD
    UINT64_C(5747147278385152),	// INTERP_XY
    UINT64_C(5747697034199040),	// INTERP_ZW
    UINT64_C(85212151152640),	// INT_TO_FLT_eg
    UINT64_C(59373627899904),	// INT_TO_FLT_r600
    UINT64_C(24739011624960),	// KILLGT
    UINT64_C(598134325510144),	// LDS_ADD
    UINT64_C(288828510477221888),	// LDS_ADD_RET
    UINT64_C(81662927618179072),	// LDS_AND
    UINT64_C(369893303769890816),	// LDS_AND_RET
    UINT64_C(486986894081523712),	// LDS_BYTE_READ_RET
    UINT64_C(162727720910848000),	// LDS_BYTE_WRITE
    UINT64_C(144713322401366016),	// LDS_CMPST
    UINT64_C(432943698553077760),	// LDS_CMPST_RET
    UINT64_C(54641329853956096),	// LDS_MAX_INT
    UINT64_C(342871706005667840),	// LDS_MAX_INT_RET
    UINT64_C(72655728363438080),	// LDS_MAX_UINT
    UINT64_C(360886104515149824),	// LDS_MAX_UINT_RET
    UINT64_C(45634130599215104),	// LDS_MIN_INT
    UINT64_C(333864506750926848),	// LDS_MIN_INT_RET
    UINT64_C(63648529108697088),	// LDS_MIN_UINT
    UINT64_C(351878905260408832),	// LDS_MIN_UINT_RET
    UINT64_C(90670126872920064),	// LDS_OR
    UINT64_C(378900503024631808),	// LDS_OR_RET
    UINT64_C(450958097062559744),	// LDS_READ_RET
    UINT64_C(505001292591005696),	// LDS_SHORT_READ_RET
    UINT64_C(171734920165588992),	// LDS_SHORT_WRITE
    UINT64_C(9605333580251136),	// LDS_SUB
    UINT64_C(297835709731962880),	// LDS_SUB_RET
    UINT64_C(495994093336264704),	// LDS_UBYTE_READ_RET
    UINT64_C(514008491845746688),	// LDS_USHORT_READ_RET
    UINT64_C(117691724637143040),	// LDS_WRITE
    UINT64_C(117691724637143040),	// LDS_WRXCHG
    UINT64_C(405922100788854784),	// LDS_WRXCHG_RET
    UINT64_C(99677326127661056),	// LDS_XOR
    UINT64_C(387907702279372800),	// LDS_XOR_RET
    UINT64_C(0),	// LITERALS
    UINT64_C(71468255805440),	// LOG_CLAMPED_eg
    UINT64_C(53876069761024),	// LOG_CLAMPED_r600
    UINT64_C(72018011619328),	// LOG_IEEE_cm
    UINT64_C(72018011619328),	// LOG_IEEE_eg
    UINT64_C(54425825574912),	// LOG_IEEE_r600
    UINT64_C(9385501623440113664),	// LOOP_BREAK_EG
    UINT64_C(9547631210025451520),	// LOOP_BREAK_R600
    UINT64_C(12644383719424),	// LSHL_eg
    UINT64_C(62672162783232),	// LSHL_r600
    UINT64_C(12094627905536),	// LSHR_eg
    UINT64_C(62122406969344),	// LSHR_r600
    UINT64_C(1649267441664),	// MAX
    UINT64_C(2748779069440),	// MAX_DX10
    UINT64_C(29686813949952),	// MAX_INT
    UINT64_C(30786325577728),	// MAX_UINT
    UINT64_C(2199023255552),	// MIN
    UINT64_C(3298534883328),	// MIN_DX10
    UINT64_C(30236569763840),	// MIN_INT
    UINT64_C(31336081391616),	// MIN_UINT
    UINT64_C(13743895347200),	// MOV
    UINT64_C(112150186033152),	// MOVA_INT_eg
    UINT64_C(549755813888),	// MUL
    UINT64_C(844424930131968),	// MULADD_IEEE_eg
    UINT64_C(703687441776640),	// MULADD_IEEE_r600
    UINT64_C(281474976710656),	// MULADD_INT24_cm
    UINT64_C(562949953421312),	// MULADD_UINT24_eg
    UINT64_C(703687441776640),	// MULADD_eg
    UINT64_C(562949953421312),	// MULADD_r600
    UINT64_C(79164837199872),	// MULHI_INT_cm
    UINT64_C(50577534877696),	// MULHI_INT_cm24
    UINT64_C(79164837199872),	// MULHI_INT_eg
    UINT64_C(63771674411008),	// MULHI_INT_r600
    UINT64_C(97856534872064),	// MULHI_UINT24_eg
    UINT64_C(80264348827648),	// MULHI_UINT_cm
    UINT64_C(97856534872064),	// MULHI_UINT_cm24
    UINT64_C(80264348827648),	// MULHI_UINT_eg
    UINT64_C(64871186038784),	// MULHI_UINT_r600
    UINT64_C(78615081385984),	// MULLO_INT_cm
    UINT64_C(78615081385984),	// MULLO_INT_eg
    UINT64_C(63221918597120),	// MULLO_INT_r600
    UINT64_C(79714593013760),	// MULLO_UINT_cm
    UINT64_C(79714593013760),	// MULLO_UINT_eg
    UINT64_C(64321430224896),	// MULLO_UINT_r600
    UINT64_C(1099511627776),	// MUL_IEEE
    UINT64_C(50027779063808),	// MUL_INT24_cm
    UINT64_C(1090715534753792),	// MUL_LIT_eg
    UINT64_C(422212465065984),	// MUL_LIT_r600
    UINT64_C(99505802313728),	// MUL_UINT24_eg
    UINT64_C(28037546508288),	// NOT_INT
    UINT64_C(26938034880512),	// OR_INT
    UINT64_C(0),	// PAD
    UINT64_C(9475573615987523584),	// POP_EG
    UINT64_C(9727775195120271360),	// POP_R600
    UINT64_C(17592186044416),	// PRED_SETE
    UINT64_C(36283883716608),	// PRED_SETE_INT
    UINT64_C(18691697672192),	// PRED_SETGE
    UINT64_C(37383395344384),	// PRED_SETGE_INT
    UINT64_C(18141941858304),	// PRED_SETGT
    UINT64_C(36833639530496),	// PRED_SETGT_INT
    UINT64_C(19241453486080),	// PRED_SETNE
    UINT64_C(37933151158272),	// PRED_SETNE_INT
    UINT64_C(9223372036854775808),	// R600_ExportBuf
    UINT64_C(9223372040076001280),	// R600_ExportSwz
    UINT64_C(10772874191460901488),	// RAT_ATOMIC_ADD_NORET
    UINT64_C(10772874191460900976),	// RAT_ATOMIC_ADD_RTN
    UINT64_C(10772874191460901600),	// RAT_ATOMIC_AND_NORET
    UINT64_C(10772874191460901088),	// RAT_ATOMIC_AND_RTN
    UINT64_C(10772874191460901440),	// RAT_ATOMIC_CMPXCHG_INT_NORET
    UINT64_C(10772874191460900928),	// RAT_ATOMIC_CMPXCHG_INT_RTN
    UINT64_C(10772874191460901680),	// RAT_ATOMIC_DEC_UINT_NORET
    UINT64_C(10772874191460901168),	// RAT_ATOMIC_DEC_UINT_RTN
    UINT64_C(10772874191460901664),	// RAT_ATOMIC_INC_UINT_NORET
    UINT64_C(10772874191460901152),	// RAT_ATOMIC_INC_UINT_RTN
    UINT64_C(10772874191460901568),	// RAT_ATOMIC_MAX_INT_NORET
    UINT64_C(10772874191460901056),	// RAT_ATOMIC_MAX_INT_RTN
    UINT64_C(10772874191460901584),	// RAT_ATOMIC_MAX_UINT_NORET
    UINT64_C(10772874191460901072),	// RAT_ATOMIC_MAX_UINT_RTN
    UINT64_C(10772874191460901536),	// RAT_ATOMIC_MIN_INT_NORET
    UINT64_C(10772874191460901024),	// RAT_ATOMIC_MIN_INT_RTN
    UINT64_C(10772874191460901552),	// RAT_ATOMIC_MIN_UINT_NORET
    UINT64_C(10772874191460901040),	// RAT_ATOMIC_MIN_UINT_RTN
    UINT64_C(10772874191460901616),	// RAT_ATOMIC_OR_NORET
    UINT64_C(10772874191460901104),	// RAT_ATOMIC_OR_RTN
    UINT64_C(10772874191460901520),	// RAT_ATOMIC_RSUB_NORET
    UINT64_C(10772874191460901008),	// RAT_ATOMIC_RSUB_RTN
    UINT64_C(10772874191460901504),	// RAT_ATOMIC_SUB_NORET
    UINT64_C(10772874191460900992),	// RAT_ATOMIC_SUB_RTN
    UINT64_C(10772874191460901408),	// RAT_ATOMIC_XCHG_INT_NORET
    UINT64_C(10772874191460900880),	// RAT_ATOMIC_XCHG_INT_RTN
    UINT64_C(10772874191460901632),	// RAT_ATOMIC_XOR_NORET
    UINT64_C(10772874191460901120),	// RAT_ATOMIC_XOR_RTN
    UINT64_C(10772874191460901136),	// RAT_MSKOR
    UINT64_C(10790888589970383168),	// RAT_STORE_DWORD128
    UINT64_C(10790642299365761344),	// RAT_STORE_DWORD32
    UINT64_C(10790677483737850176),	// RAT_STORE_DWORD64
    UINT64_C(10772874191460900880),	// RAT_STORE_TYPED_cm
    UINT64_C(10772874191460900880),	// RAT_STORE_TYPED_eg
    UINT64_C(10790888589970382880),	// RAT_WRITE_CACHELESS_128_eg
    UINT64_C(10790642299365761056),	// RAT_WRITE_CACHELESS_32_eg
    UINT64_C(10790677483737849888),	// RAT_WRITE_CACHELESS_64_eg
    UINT64_C(74217034874880),	// RECIPSQRT_CLAMPED_cm
    UINT64_C(74217034874880),	// RECIPSQRT_CLAMPED_eg
    UINT64_C(56624848830464),	// RECIPSQRT_CLAMPED_r600
    UINT64_C(75316546502656),	// RECIPSQRT_IEEE_cm
    UINT64_C(75316546502656),	// RECIPSQRT_IEEE_eg
    UINT64_C(57724360458240),	// RECIPSQRT_IEEE_r600
    UINT64_C(72567767433216),	// RECIP_CLAMPED_cm
    UINT64_C(72567767433216),	// RECIP_CLAMPED_eg
    UINT64_C(54975581388800),	// RECIP_CLAMPED_r600
    UINT64_C(73667279060992),	// RECIP_IEEE_cm
    UINT64_C(73667279060992),	// RECIP_IEEE_eg
    UINT64_C(56075093016576),	// RECIP_IEEE_r600
    UINT64_C(81363860455424),	// RECIP_UINT_eg
    UINT64_C(65970697666560),	// RECIP_UINT_r600
    UINT64_C(10445360463872),	// RNDNE
    UINT64_C(4398046511104),	// SETE
    UINT64_C(6597069766656),	// SETE_DX10
    UINT64_C(31885837205504),	// SETE_INT
    UINT64_C(7696581394432),	// SETGE_DX10
    UINT64_C(32985348833280),	// SETGE_INT
    UINT64_C(34634616274944),	// SETGE_UINT
    UINT64_C(7146825580544),	// SETGT_DX10
    UINT64_C(32435593019392),	// SETGT_INT
    UINT64_C(34084860461056),	// SETGT_UINT
    UINT64_C(8246337208320),	// SETNE_DX10
    UINT64_C(33535104647168),	// SETNE_INT
    UINT64_C(5497558138880),	// SGE
    UINT64_C(4947802324992),	// SGT
    UINT64_C(77515569758208),	// SIN_cm
    UINT64_C(77515569758208),	// SIN_eg
    UINT64_C(60473139527680),	// SIN_r600
    UINT64_C(60473139527680),	// SIN_r700
    UINT64_C(6047313952768),	// SNE
    UINT64_C(45629732552704),	// SUBB_UINT
    UINT64_C(29137058136064),	// SUB_INT
    UINT64_C(7),	// TEX_GET_GRADIENTS_H
    UINT64_C(8),	// TEX_GET_GRADIENTS_V
    UINT64_C(4),	// TEX_GET_TEXTURE_RESINFO
    UINT64_C(3),	// TEX_LD
    UINT64_C(35),	// TEX_LDPTR
    UINT64_C(16),	// TEX_SAMPLE
    UINT64_C(24),	// TEX_SAMPLE_C
    UINT64_C(28),	// TEX_SAMPLE_C_G
    UINT64_C(25),	// TEX_SAMPLE_C_L
    UINT64_C(26),	// TEX_SAMPLE_C_LB
    UINT64_C(20),	// TEX_SAMPLE_G
    UINT64_C(17),	// TEX_SAMPLE_L
    UINT64_C(18),	// TEX_SAMPLE_LB
    UINT64_C(11),	// TEX_SET_GRADIENTS_H
    UINT64_C(12),	// TEX_SET_GRADIENTS_V
    UINT64_C(16775081780284751936),	// TEX_VTX_CONSTBUF
    UINT64_C(9236056004066541632),	// TEX_VTX_TEXBUF
    UINT64_C(9345848836096),	// TRUNC
    UINT64_C(85761906966528),	// UINT_TO_FLT_eg
    UINT64_C(59923383713792),	// UINT_TO_FLT_r600
    UINT64_C(1769087820812517440),	// VTX_READ_128_cm
    UINT64_C(1769087821886259264),	// VTX_READ_128_eg
    UINT64_C(1251983104222953536),	// VTX_READ_16_cm
    UINT64_C(1251983104357171264),	// VTX_READ_16_eg
    UINT64_C(1396098292298809408),	// VTX_READ_32_cm
    UINT64_C(1396098292567244864),	// VTX_READ_32_eg
    UINT64_C(1684223115334254656),	// VTX_READ_64_cm
    UINT64_C(1684223115871125568),	// VTX_READ_64_eg
    UINT64_C(1179925510185025600),	// VTX_READ_8_cm
    UINT64_C(1179925510252134464),	// VTX_READ_8_eg
    UINT64_C(9331458427911667712),	// WHILE_LOOP_EG
    UINT64_C(9439544818968559616),	// WHILE_LOOP_R600
    UINT64_C(27487790694400),	// XOR_INT
  };
  constexpr unsigned FirstSupportedOpcode = 389;

  const unsigned opcode = MI.getOpcode();
  if (opcode < FirstSupportedOpcode)
    reportUnsupportedInst(MI);
  unsigned TableIndex = opcode - FirstSupportedOpcode;
  uint64_t Value = InstBits[TableIndex];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case R600::CF_CALL_FS_EG:
    case R600::CF_CALL_FS_R600:
    case R600::CF_END_CM:
    case R600::CF_END_EG:
    case R600::CF_END_R600:
    case R600::GROUP_BARRIER:
    case R600::INTERP_PAIR_XY:
    case R600::INTERP_PAIR_ZW:
    case R600::INTERP_VEC_LOAD:
    case R600::PAD: {
      break;
    }
    case R600::CF_ALU:
    case R600::CF_ALU_BREAK:
    case R600::CF_ALU_CONTINUE:
    case R600::CF_ALU_ELSE_AFTER:
    case R600::CF_ALU_POP_AFTER:
    case R600::CF_ALU_PUSH_BEFORE: {
      // op: ADDR
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3fffff);
      // op: KCACHE_BANK0
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 22;
      // op: KCACHE_BANK1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 26;
      // op: KCACHE_MODE0
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3) << 30;
      // op: KCACHE_MODE1
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x3) << 32;
      // op: KCACHE_ADDR0
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0xff) << 34;
      // op: KCACHE_ADDR1
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0xff) << 42;
      // op: COUNT
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0x7f) << 50;
      break;
    }
    case R600::CF_CONTINUE_EG:
    case R600::END_LOOP_EG:
    case R600::LOOP_BREAK_EG:
    case R600::WHILE_LOOP_EG: {
      // op: ADDR
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xffffff);
      break;
    }
    case R600::CF_TC_EG:
    case R600::CF_VC_EG: {
      // op: ADDR
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xffffff);
      // op: COUNT
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f) << 42;
      break;
    }
    case R600::CF_ELSE_EG:
    case R600::CF_JUMP_EG:
    case R600::CF_PUSH_EG:
    case R600::POP_EG: {
      // op: ADDR
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xffffff);
      // op: POP_COUNT
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 32;
      break;
    }
    case R600::CF_CONTINUE_R600:
    case R600::CF_PUSH_ELSE_R600:
    case R600::END_LOOP_R600:
    case R600::LOOP_BREAK_R600:
    case R600::WHILE_LOOP_R600: {
      // op: ADDR
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xffffffff);
      break;
    }
    case R600::CF_TC_R600:
    case R600::CF_VC_R600: {
      // op: ADDR
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xffffffff);
      // op: CNT
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x8) << 48;
      Value |= (op & 0x7) << 42;
      break;
    }
    case R600::CF_ELSE_R600:
    case R600::CF_JUMP_R600:
    case R600::POP_R600: {
      // op: ADDR
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xffffffff);
      // op: POP_COUNT
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 32;
      break;
    }
    case R600::TEX_GET_GRADIENTS_H:
    case R600::TEX_GET_GRADIENTS_V:
    case R600::TEX_GET_TEXTURE_RESINFO:
    case R600::TEX_LD:
    case R600::TEX_LDPTR:
    case R600::TEX_SAMPLE:
    case R600::TEX_SAMPLE_C:
    case R600::TEX_SAMPLE_C_G:
    case R600::TEX_SAMPLE_C_L:
    case R600::TEX_SAMPLE_C_LB:
    case R600::TEX_SAMPLE_G:
    case R600::TEX_SAMPLE_L:
    case R600::TEX_SAMPLE_LB:
    case R600::TEX_SET_GRADIENTS_H:
    case R600::TEX_SET_GRADIENTS_V: {
      // op: RESOURCE_ID
      op = getMachineOpValue(MI, MI.getOperand(13), Fixups, STI);
      Value |= (op & 0xff) << 8;
      // op: SRC_GPR
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 16;
      // op: DST_GPR
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 32;
      // op: DST_SEL_X
      op = getMachineOpValue(MI, MI.getOperand(9), Fixups, STI);
      Value |= (op & 0x7) << 41;
      // op: DST_SEL_Y
      op = getMachineOpValue(MI, MI.getOperand(10), Fixups, STI);
      Value |= (op & 0x7) << 44;
      // op: DST_SEL_Z
      op = getMachineOpValue(MI, MI.getOperand(11), Fixups, STI);
      Value |= (op & 0x7) << 47;
      // op: DST_SEL_W
      op = getMachineOpValue(MI, MI.getOperand(12), Fixups, STI);
      Value |= (op & 0x7) << 50;
      // op: COORD_TYPE_X
      op = getMachineOpValue(MI, MI.getOperand(15), Fixups, STI);
      Value |= (op & 0x1) << 60;
      // op: COORD_TYPE_Y
      op = getMachineOpValue(MI, MI.getOperand(16), Fixups, STI);
      Value |= (op & 0x1) << 61;
      // op: COORD_TYPE_Z
      op = getMachineOpValue(MI, MI.getOperand(17), Fixups, STI);
      Value |= (op & 0x1) << 62;
      // op: COORD_TYPE_W
      op = getMachineOpValue(MI, MI.getOperand(18), Fixups, STI);
      Value |= (op & 0x1) << 63;
      break;
    }
    case R600::ALU_CLAUSE:
    case R600::FETCH_CLAUSE: {
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xff);
      break;
    }
    case R600::EG_ExportBuf: {
      // op: arraybase
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1fff);
      // op: type
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 13;
      // op: gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 15;
      // op: arraySize
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xfff) << 32;
      // op: compMask
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0xf) << 44;
      // op: eop
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x1) << 53;
      // op: inst
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0xff) << 54;
      break;
    }
    case R600::R600_ExportBuf: {
      // op: arraybase
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1fff);
      // op: type
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 13;
      // op: gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 15;
      // op: arraySize
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xfff) << 32;
      // op: compMask
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0xf) << 44;
      // op: eop
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x1) << 53;
      // op: inst
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0xff) << 55;
      break;
    }
    case R600::EG_ExportSwz: {
      // op: arraybase
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1fff);
      // op: type
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 13;
      // op: gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 15;
      // op: sw_x
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 32;
      // op: sw_y
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 35;
      // op: sw_z
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x7) << 38;
      // op: sw_w
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x7) << 41;
      // op: eop
      op = getMachineOpValue(MI, MI.getOperand(8), Fixups, STI);
      Value |= (op & 0x1) << 53;
      // op: inst
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0xff) << 54;
      break;
    }
    case R600::R600_ExportSwz: {
      // op: arraybase
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1fff);
      // op: type
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 13;
      // op: gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 15;
      // op: sw_x
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 32;
      // op: sw_y
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 35;
      // op: sw_z
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x7) << 38;
      // op: sw_w
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x7) << 41;
      // op: eop
      op = getMachineOpValue(MI, MI.getOperand(8), Fixups, STI);
      Value |= (op & 0x1) << 53;
      // op: inst
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0xff) << 55;
      break;
    }
    case R600::TEX_VTX_CONSTBUF:
    case R600::TEX_VTX_TEXBUF: {
      // op: dst_gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 32;
      // op: src_gpr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 16;
      // op: buffer_id
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xff) << 8;
      break;
    }
    case R600::LITERALS: {
      // op: literal1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xffffffff);
      // op: literal2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xffffffff) << 32;
      break;
    }
    case R600::RAT_STORE_TYPED_cm: {
      // op: rat_id
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf);
      // op: rw_gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 15;
      // op: index_gpr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 23;
      break;
    }
    case R600::RAT_STORE_TYPED_eg: {
      // op: rat_id
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf);
      // op: rw_gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 15;
      // op: index_gpr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 23;
      // op: eop
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 53;
      break;
    }
    case R600::RAT_MSKOR:
    case R600::RAT_STORE_DWORD128:
    case R600::RAT_STORE_DWORD32:
    case R600::RAT_STORE_DWORD64: {
      // op: rw_gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 15;
      // op: index_gpr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 23;
      break;
    }
    case R600::RAT_WRITE_CACHELESS_128_eg:
    case R600::RAT_WRITE_CACHELESS_32_eg:
    case R600::RAT_WRITE_CACHELESS_64_eg: {
      // op: rw_gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 15;
      // op: index_gpr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 23;
      // op: eop
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 53;
      break;
    }
    case R600::RAT_ATOMIC_ADD_NORET:
    case R600::RAT_ATOMIC_ADD_RTN:
    case R600::RAT_ATOMIC_AND_NORET:
    case R600::RAT_ATOMIC_AND_RTN:
    case R600::RAT_ATOMIC_CMPXCHG_INT_NORET:
    case R600::RAT_ATOMIC_CMPXCHG_INT_RTN:
    case R600::RAT_ATOMIC_DEC_UINT_NORET:
    case R600::RAT_ATOMIC_DEC_UINT_RTN:
    case R600::RAT_ATOMIC_INC_UINT_NORET:
    case R600::RAT_ATOMIC_INC_UINT_RTN:
    case R600::RAT_ATOMIC_MAX_INT_NORET:
    case R600::RAT_ATOMIC_MAX_INT_RTN:
    case R600::RAT_ATOMIC_MAX_UINT_NORET:
    case R600::RAT_ATOMIC_MAX_UINT_RTN:
    case R600::RAT_ATOMIC_MIN_INT_NORET:
    case R600::RAT_ATOMIC_MIN_INT_RTN:
    case R600::RAT_ATOMIC_MIN_UINT_NORET:
    case R600::RAT_ATOMIC_MIN_UINT_RTN:
    case R600::RAT_ATOMIC_OR_NORET:
    case R600::RAT_ATOMIC_OR_RTN:
    case R600::RAT_ATOMIC_RSUB_NORET:
    case R600::RAT_ATOMIC_RSUB_RTN:
    case R600::RAT_ATOMIC_SUB_NORET:
    case R600::RAT_ATOMIC_SUB_RTN:
    case R600::RAT_ATOMIC_XCHG_INT_NORET:
    case R600::RAT_ATOMIC_XCHG_INT_RTN:
    case R600::RAT_ATOMIC_XOR_NORET:
    case R600::RAT_ATOMIC_XOR_RTN: {
      // op: rw_gpr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 15;
      // op: index_gpr
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7f) << 23;
      break;
    }
    case R600::LDS_CMPST: {
      // op: src0
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x600) << 1;
      Value |= (op & 0x1ff);
      // op: src0_rel
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 9;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x600) << 14;
      Value |= (op & 0x1ff) << 13;
      // op: src1_rel
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 22;
      // op: pred_sel
      op = getMachineOpValue(MI, MI.getOperand(10), Fixups, STI);
      Value |= (op & 0x3) << 29;
      // op: last
      op = getMachineOpValue(MI, MI.getOperand(9), Fixups, STI);
      Value |= (op & 0x1) << 31;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x600) << 33;
      Value |= (op & 0x1ff) << 32;
      // op: src2_rel
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0x1) << 41;
      // op: bank_swizzle
      op = getMachineOpValue(MI, MI.getOperand(11), Fixups, STI);
      Value |= (op & 0x7) << 50;
      break;
    }
    case R600::LDS_ADD:
    case R600::LDS_AND:
    case R600::LDS_BYTE_WRITE:
    case R600::LDS_MAX_INT:
    case R600::LDS_MAX_UINT:
    case R600::LDS_MIN_INT:
    case R600::LDS_MIN_UINT:
    case R600::LDS_OR:
    case R600::LDS_SHORT_WRITE:
    case R600::LDS_SUB:
    case R600::LDS_WRITE:
    case R600::LDS_WRXCHG:
    case R600::LDS_XOR: {
      // op: src0
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x600) << 1;
      Value |= (op & 0x1ff);
      // op: src0_rel
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 9;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x600) << 14;
      Value |= (op & 0x1ff) << 13;
      // op: src1_rel
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 22;
      // op: pred_sel
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0x3) << 29;
      // op: last
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x1) << 31;
      // op: bank_swizzle
      op = getMachineOpValue(MI, MI.getOperand(8), Fixups, STI);
      Value |= (op & 0x7) << 50;
      break;
    }
    case R600::LDS_BYTE_READ_RET:
    case R600::LDS_READ_RET:
    case R600::LDS_SHORT_READ_RET:
    case R600::LDS_UBYTE_READ_RET:
    case R600::LDS_USHORT_READ_RET: {
      // op: src0
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x600) << 1;
      Value |= (op & 0x1ff);
      // op: src0_rel
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 9;
      // op: pred_sel
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x3) << 29;
      // op: last
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 31;
      // op: bank_swizzle
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x7) << 50;
      break;
    }
    case R600::LDS_CMPST_RET: {
      // op: src0
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x600) << 1;
      Value |= (op & 0x1ff);
      // op: src0_rel
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 9;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x600) << 14;
      Value |= (op & 0x1ff) << 13;
      // op: src1_rel
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x1) << 22;
      // op: pred_sel
      op = getMachineOpValue(MI, MI.getOperand(11), Fixups, STI);
      Value |= (op & 0x3) << 29;
      // op: last
      op = getMachineOpValue(MI, MI.getOperand(10), Fixups, STI);
      Value |= (op & 0x1) << 31;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0x600) << 33;
      Value |= (op & 0x1ff) << 32;
      // op: src2_rel
      op = getMachineOpValue(MI, MI.getOperand(8), Fixups, STI);
      Value |= (op & 0x1) << 41;
      // op: bank_swizzle
      op = getMachineOpValue(MI, MI.getOperand(12), Fixups, STI);
      Value |= (op & 0x7) << 50;
      break;
    }
    case R600::LDS_ADD_RET:
    case R600::LDS_AND_RET:
    case R600::LDS_MAX_INT_RET:
    case R600::LDS_MAX_UINT_RET:
    case R600::LDS_MIN_INT_RET:
    case R600::LDS_MIN_UINT_RET:
    case R600::LDS_OR_RET:
    case R600::LDS_SUB_RET:
    case R600::LDS_WRXCHG_RET:
    case R600::LDS_XOR_RET: {
      // op: src0
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x600) << 1;
      Value |= (op & 0x1ff);
      // op: src0_rel
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 9;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x600) << 14;
      Value |= (op & 0x1ff) << 13;
      // op: src1_rel
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x1) << 22;
      // op: pred_sel
      op = getMachineOpValue(MI, MI.getOperand(8), Fixups, STI);
      Value |= (op & 0x3) << 29;
      // op: last
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0x1) << 31;
      // op: bank_swizzle
      op = getMachineOpValue(MI, MI.getOperand(9), Fixups, STI);
      Value |= (op & 0x7) << 50;
      break;
    }
    case R600::BFE_INT_eg:
    case R600::BFE_UINT_eg:
    case R600::BFI_INT_eg:
    case R600::BIT_ALIGN_INT_eg:
    case R600::CNDE_INT:
    case R600::CNDE_eg:
    case R600::CNDE_r600:
    case R600::CNDGE_INT:
    case R600::CNDGE_eg:
    case R600::CNDGE_r600:
    case R600::CNDGT_INT:
    case R600::CNDGT_eg:
    case R600::CNDGT_r600:
    case R600::FMA_eg:
    case R600::MULADD_IEEE_eg:
    case R600::MULADD_IEEE_r600:
    case R600::MULADD_INT24_cm:
    case R600::MULADD_UINT24_eg:
    case R600::MULADD_eg:
    case R600::MULADD_r600:
    case R600::MUL_LIT_eg:
    case R600::MUL_LIT_r600: {
      // op: src0
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x600) << 1;
      Value |= (op & 0x1ff);
      // op: src0_rel
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x1) << 9;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0x600) << 14;
      Value |= (op & 0x1ff) << 13;
      // op: src1_rel
      op = getMachineOpValue(MI, MI.getOperand(9), Fixups, STI);
      Value |= (op & 0x1) << 22;
      // op: pred_sel
      op = getMachineOpValue(MI, MI.getOperand(16), Fixups, STI);
      Value |= (op & 0x3) << 29;
      // op: last
      op = getMachineOpValue(MI, MI.getOperand(15), Fixups, STI);
      Value |= (op & 0x1) << 31;
      // op: src0_neg
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 12;
      // op: src1_neg
      op = getMachineOpValue(MI, MI.getOperand(8), Fixups, STI);
      Value |= (op & 0x1) << 25;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x600) << 52;
      Value |= (op & 0x7f) << 53;
      // op: bank_swizzle
      op = getMachineOpValue(MI, MI.getOperand(18), Fixups, STI);
      Value |= (op & 0x7) << 50;
      // op: dst_rel
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 60;
      // op: clamp
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 63;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(11), Fixups, STI);
      Value |= (op & 0x600) << 33;
      Value |= (op & 0x1ff) << 32;
      // op: src2_rel
      op = getMachineOpValue(MI, MI.getOperand(13), Fixups, STI);
      Value |= (op & 0x1) << 41;
      // op: src2_neg
      op = getMachineOpValue(MI, MI.getOperand(12), Fixups, STI);
      Value |= (op & 0x1) << 44;
      break;
    }
    case R600::BCNT_INT:
    case R600::CEIL:
    case R600::COS_cm:
    case R600::COS_eg:
    case R600::COS_r600:
    case R600::COS_r700:
    case R600::EXP_IEEE_cm:
    case R600::EXP_IEEE_eg:
    case R600::EXP_IEEE_r600:
    case R600::FFBH_UINT:
    case R600::FFBL_INT:
    case R600::FLOOR:
    case R600::FLT16_TO_FLT32:
    case R600::FLT32_TO_FLT16:
    case R600::FLT_TO_INT_eg:
    case R600::FLT_TO_INT_r600:
    case R600::FLT_TO_UINT_eg:
    case R600::FLT_TO_UINT_r600:
    case R600::FRACT:
    case R600::INTERP_LOAD_P0:
    case R600::INT_TO_FLT_eg:
    case R600::INT_TO_FLT_r600:
    case R600::LOG_CLAMPED_eg:
    case R600::LOG_CLAMPED_r600:
    case R600::LOG_IEEE_cm:
    case R600::LOG_IEEE_eg:
    case R600::LOG_IEEE_r600:
    case R600::MOV:
    case R600::MOVA_INT_eg:
    case R600::NOT_INT:
    case R600::RECIPSQRT_CLAMPED_cm:
    case R600::RECIPSQRT_CLAMPED_eg:
    case R600::RECIPSQRT_CLAMPED_r600:
    case R600::RECIPSQRT_IEEE_cm:
    case R600::RECIPSQRT_IEEE_eg:
    case R600::RECIPSQRT_IEEE_r600:
    case R600::RECIP_CLAMPED_cm:
    case R600::RECIP_CLAMPED_eg:
    case R600::RECIP_CLAMPED_r600:
    case R600::RECIP_IEEE_cm:
    case R600::RECIP_IEEE_eg:
    case R600::RECIP_IEEE_r600:
    case R600::RECIP_UINT_eg:
    case R600::RECIP_UINT_r600:
    case R600::RNDNE:
    case R600::SIN_cm:
    case R600::SIN_eg:
    case R600::SIN_r600:
    case R600::SIN_r700:
    case R600::TRUNC:
    case R600::UINT_TO_FLT_eg:
    case R600::UINT_TO_FLT_r600: {
      // op: src0
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x600) << 1;
      Value |= (op & 0x1ff);
      // op: src0_rel
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0x1) << 9;
      // op: pred_sel
      op = getMachineOpValue(MI, MI.getOperand(11), Fixups, STI);
      Value |= (op & 0x3) << 29;
      // op: last
      op = getMachineOpValue(MI, MI.getOperand(10), Fixups, STI);
      Value |= (op & 0x1) << 31;
      // op: src0_neg
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x1) << 12;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x600) << 52;
      Value |= (op & 0x7f) << 53;
      // op: bank_swizzle
      op = getMachineOpValue(MI, MI.getOperand(13), Fixups, STI);
      Value |= (op & 0x7) << 50;
      // op: dst_rel
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 60;
      // op: clamp
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 63;
      // op: src0_abs
      op = getMachineOpValue(MI, MI.getOperand(8), Fixups, STI);
      Value |= (op & 0x1) << 32;
      // op: write
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 36;
      // op: omod
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 37;
      break;
    }
    case R600::ADD:
    case R600::ADDC_UINT:
    case R600::ADD_INT:
    case R600::AND_INT:
    case R600::ASHR_eg:
    case R600::ASHR_r600:
    case R600::BFM_INT_eg:
    case R600::CUBE_eg_real:
    case R600::CUBE_r600_real:
    case R600::DOT4_eg:
    case R600::DOT4_r600:
    case R600::KILLGT:
    case R600::LSHL_eg:
    case R600::LSHL_r600:
    case R600::LSHR_eg:
    case R600::LSHR_r600:
    case R600::MAX:
    case R600::MAX_DX10:
    case R600::MAX_INT:
    case R600::MAX_UINT:
    case R600::MIN:
    case R600::MIN_DX10:
    case R600::MIN_INT:
    case R600::MIN_UINT:
    case R600::MUL:
    case R600::MULHI_INT_cm:
    case R600::MULHI_INT_cm24:
    case R600::MULHI_INT_eg:
    case R600::MULHI_INT_r600:
    case R600::MULHI_UINT24_eg:
    case R600::MULHI_UINT_cm:
    case R600::MULHI_UINT_cm24:
    case R600::MULHI_UINT_eg:
    case R600::MULHI_UINT_r600:
    case R600::MULLO_INT_cm:
    case R600::MULLO_INT_eg:
    case R600::MULLO_INT_r600:
    case R600::MULLO_UINT_cm:
    case R600::MULLO_UINT_eg:
    case R600::MULLO_UINT_r600:
    case R600::MUL_IEEE:
    case R600::MUL_INT24_cm:
    case R600::MUL_UINT24_eg:
    case R600::OR_INT:
    case R600::PRED_SETE:
    case R600::PRED_SETE_INT:
    case R600::PRED_SETGE:
    case R600::PRED_SETGE_INT:
    case R600::PRED_SETGT:
    case R600::PRED_SETGT_INT:
    case R600::PRED_SETNE:
    case R600::PRED_SETNE_INT:
    case R600::SETE:
    case R600::SETE_DX10:
    case R600::SETE_INT:
    case R600::SETGE_DX10:
    case R600::SETGE_INT:
    case R600::SETGE_UINT:
    case R600::SETGT_DX10:
    case R600::SETGT_INT:
    case R600::SETGT_UINT:
    case R600::SETNE_DX10:
    case R600::SETNE_INT:
    case R600::SGE:
    case R600::SGT:
    case R600::SNE:
    case R600::SUBB_UINT:
    case R600::SUB_INT:
    case R600::XOR_INT: {
      // op: src0
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0x600) << 1;
      Value |= (op & 0x1ff);
      // op: src0_rel
      op = getMachineOpValue(MI, MI.getOperand(9), Fixups, STI);
      Value |= (op & 0x1) << 9;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(12), Fixups, STI);
      Value |= (op & 0x600) << 14;
      Value |= (op & 0x1ff) << 13;
      // op: src1_rel
      op = getMachineOpValue(MI, MI.getOperand(14), Fixups, STI);
      Value |= (op & 0x1) << 22;
      // op: pred_sel
      op = getMachineOpValue(MI, MI.getOperand(18), Fixups, STI);
      Value |= (op & 0x3) << 29;
      // op: last
      op = getMachineOpValue(MI, MI.getOperand(17), Fixups, STI);
      Value |= (op & 0x1) << 31;
      // op: src0_neg
      op = getMachineOpValue(MI, MI.getOperand(8), Fixups, STI);
      Value |= (op & 0x1) << 12;
      // op: src1_neg
      op = getMachineOpValue(MI, MI.getOperand(13), Fixups, STI);
      Value |= (op & 0x1) << 25;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x600) << 52;
      Value |= (op & 0x7f) << 53;
      // op: bank_swizzle
      op = getMachineOpValue(MI, MI.getOperand(20), Fixups, STI);
      Value |= (op & 0x7) << 50;
      // op: dst_rel
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x1) << 60;
      // op: clamp
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x1) << 63;
      // op: src0_abs
      op = getMachineOpValue(MI, MI.getOperand(10), Fixups, STI);
      Value |= (op & 0x1) << 32;
      // op: src1_abs
      op = getMachineOpValue(MI, MI.getOperand(15), Fixups, STI);
      Value |= (op & 0x1) << 33;
      // op: update_exec_mask
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 34;
      // op: update_pred
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 35;
      // op: write
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 36;
      // op: omod
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x3) << 37;
      break;
    }
    case R600::INTERP_XY:
    case R600::INTERP_ZW: {
      // op: src0
      op = getMachineOpValue(MI, MI.getOperand(7), Fixups, STI);
      Value |= (op & 0x600) << 1;
      Value |= (op & 0x1ff);
      // op: src0_rel
      op = getMachineOpValue(MI, MI.getOperand(9), Fixups, STI);
      Value |= (op & 0x1) << 9;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(12), Fixups, STI);
      Value |= (op & 0x600) << 14;
      Value |= (op & 0x1ff) << 13;
      // op: src1_rel
      op = getMachineOpValue(MI, MI.getOperand(14), Fixups, STI);
      Value |= (op & 0x1) << 22;
      // op: pred_sel
      op = getMachineOpValue(MI, MI.getOperand(18), Fixups, STI);
      Value |= (op & 0x3) << 29;
      // op: last
      op = getMachineOpValue(MI, MI.getOperand(17), Fixups, STI);
      Value |= (op & 0x1) << 31;
      // op: src0_neg
      op = getMachineOpValue(MI, MI.getOperand(8), Fixups, STI);
      Value |= (op & 0x1) << 12;
      // op: src1_neg
      op = getMachineOpValue(MI, MI.getOperand(13), Fixups, STI);
      Value |= (op & 0x1) << 25;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x600) << 52;
      Value |= (op & 0x7f) << 53;
      // op: dst_rel
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x1) << 60;
      // op: clamp
      op = getMachineOpValue(MI, MI.getOperand(6), Fixups, STI);
      Value |= (op & 0x1) << 63;
      // op: src0_abs
      op = getMachineOpValue(MI, MI.getOperand(10), Fixups, STI);
      Value |= (op & 0x1) << 32;
      // op: src1_abs
      op = getMachineOpValue(MI, MI.getOperand(15), Fixups, STI);
      Value |= (op & 0x1) << 33;
      // op: update_exec_mask
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 34;
      // op: update_pred
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 35;
      // op: write
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 36;
      // op: omod
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x3) << 37;
      break;
    }
    case R600::VTX_READ_128_cm:
    case R600::VTX_READ_128_eg:
    case R600::VTX_READ_16_cm:
    case R600::VTX_READ_16_eg:
    case R600::VTX_READ_32_cm:
    case R600::VTX_READ_32_eg:
    case R600::VTX_READ_64_cm:
    case R600::VTX_READ_64_eg:
    case R600::VTX_READ_8_cm:
    case R600::VTX_READ_8_eg: {
      // op: src_gpr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 16;
      // op: buffer_id
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xff) << 8;
      // op: dst_gpr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f) << 32;
      break;
    }
  default:
    reportUnsupportedInst(MI);
  }
  return Value;
}

#ifdef GET_OPERAND_BIT_OFFSET
#undef GET_OPERAND_BIT_OFFSET

uint32_t R600MCCodeEmitter::getOperandBitOffset(const MCInst &MI,
    unsigned OpNum,
    const MCSubtargetInfo &STI) const {
  switch (MI.getOpcode()) {
    case R600::CF_CALL_FS_EG:
    case R600::CF_CALL_FS_R600:
    case R600::CF_END_CM:
    case R600::CF_END_EG:
    case R600::CF_END_R600:
    case R600::GROUP_BARRIER:
    case R600::INTERP_PAIR_XY:
    case R600::INTERP_PAIR_ZW:
    case R600::INTERP_VEC_LOAD:
    case R600::PAD: {
      break;
    }
    case R600::CF_TC_R600:
    case R600::CF_VC_R600: {
      switch (OpNum) {
      case 0:
        // op: ADDR
        return 0;
      case 1:
        // op: CNT
        return 42;
      }
      break;
    }
    case R600::CF_TC_EG:
    case R600::CF_VC_EG: {
      switch (OpNum) {
      case 0:
        // op: ADDR
        return 0;
      case 1:
        // op: COUNT
        return 42;
      }
      break;
    }
    case R600::CF_ALU:
    case R600::CF_ALU_BREAK:
    case R600::CF_ALU_CONTINUE:
    case R600::CF_ALU_ELSE_AFTER:
    case R600::CF_ALU_POP_AFTER:
    case R600::CF_ALU_PUSH_BEFORE: {
      switch (OpNum) {
      case 0:
        // op: ADDR
        return 0;
      case 1:
        // op: KCACHE_BANK0
        return 22;
      case 2:
        // op: KCACHE_BANK1
        return 26;
      case 3:
        // op: KCACHE_MODE0
        return 30;
      case 4:
        // op: KCACHE_MODE1
        return 32;
      case 5:
        // op: KCACHE_ADDR0
        return 34;
      case 6:
        // op: KCACHE_ADDR1
        return 42;
      case 7:
        // op: COUNT
        return 50;
      }
      break;
    }
    case R600::CF_ELSE_EG:
    case R600::CF_ELSE_R600:
    case R600::CF_JUMP_EG:
    case R600::CF_JUMP_R600:
    case R600::CF_PUSH_EG:
    case R600::POP_EG:
    case R600::POP_R600: {
      switch (OpNum) {
      case 0:
        // op: ADDR
        return 0;
      case 1:
        // op: POP_COUNT
        return 32;
      }
      break;
    }
    case R600::CF_CONTINUE_EG:
    case R600::CF_CONTINUE_R600:
    case R600::CF_PUSH_ELSE_R600:
    case R600::END_LOOP_EG:
    case R600::END_LOOP_R600:
    case R600::LOOP_BREAK_EG:
    case R600::LOOP_BREAK_R600:
    case R600::WHILE_LOOP_EG:
    case R600::WHILE_LOOP_R600: {
      switch (OpNum) {
      case 0:
        // op: ADDR
        return 0;
      }
      break;
    }
    case R600::ALU_CLAUSE:
    case R600::FETCH_CLAUSE: {
      switch (OpNum) {
      case 0:
        // op: addr
        return 0;
      }
      break;
    }
    case R600::TEX_VTX_CONSTBUF:
    case R600::TEX_VTX_TEXBUF: {
      switch (OpNum) {
      case 0:
        // op: dst_gpr
        return 32;
      case 1:
        // op: src_gpr
        return 16;
      case 3:
        // op: buffer_id
        return 8;
      }
      break;
    }
    case R600::LITERALS: {
      switch (OpNum) {
      case 0:
        // op: literal1
        return 0;
      case 1:
        // op: literal2
        return 32;
      }
      break;
    }
    case R600::RAT_WRITE_CACHELESS_128_eg:
    case R600::RAT_WRITE_CACHELESS_32_eg:
    case R600::RAT_WRITE_CACHELESS_64_eg: {
      switch (OpNum) {
      case 0:
        // op: rw_gpr
        return 15;
      case 1:
        // op: index_gpr
        return 23;
      case 2:
        // op: eop
        return 53;
      }
      break;
    }
    case R600::RAT_MSKOR:
    case R600::RAT_STORE_DWORD128:
    case R600::RAT_STORE_DWORD32:
    case R600::RAT_STORE_DWORD64: {
      switch (OpNum) {
      case 0:
        // op: rw_gpr
        return 15;
      case 1:
        // op: index_gpr
        return 23;
      }
      break;
    }
    case R600::LDS_CMPST: {
      switch (OpNum) {
      case 0:
        // op: src0
        return 0;
      case 1:
        // op: src0_rel
        return 9;
      case 3:
        // op: src1
        return 13;
      case 4:
        // op: src1_rel
        return 22;
      case 10:
        // op: pred_sel
        return 29;
      case 9:
        // op: last
        return 31;
      case 6:
        // op: src2
        return 32;
      case 7:
        // op: src2_rel
        return 41;
      case 11:
        // op: bank_swizzle
        return 50;
      }
      break;
    }
    case R600::LDS_ADD:
    case R600::LDS_AND:
    case R600::LDS_BYTE_WRITE:
    case R600::LDS_MAX_INT:
    case R600::LDS_MAX_UINT:
    case R600::LDS_MIN_INT:
    case R600::LDS_MIN_UINT:
    case R600::LDS_OR:
    case R600::LDS_SHORT_WRITE:
    case R600::LDS_SUB:
    case R600::LDS_WRITE:
    case R600::LDS_WRXCHG:
    case R600::LDS_XOR: {
      switch (OpNum) {
      case 0:
        // op: src0
        return 0;
      case 1:
        // op: src0_rel
        return 9;
      case 3:
        // op: src1
        return 13;
      case 4:
        // op: src1_rel
        return 22;
      case 7:
        // op: pred_sel
        return 29;
      case 6:
        // op: last
        return 31;
      case 8:
        // op: bank_swizzle
        return 50;
      }
      break;
    }
    case R600::TEX_GET_GRADIENTS_H:
    case R600::TEX_GET_GRADIENTS_V:
    case R600::TEX_GET_TEXTURE_RESINFO:
    case R600::TEX_LD:
    case R600::TEX_LDPTR:
    case R600::TEX_SAMPLE:
    case R600::TEX_SAMPLE_C:
    case R600::TEX_SAMPLE_C_G:
    case R600::TEX_SAMPLE_C_L:
    case R600::TEX_SAMPLE_C_LB:
    case R600::TEX_SAMPLE_G:
    case R600::TEX_SAMPLE_L:
    case R600::TEX_SAMPLE_LB:
    case R600::TEX_SET_GRADIENTS_H:
    case R600::TEX_SET_GRADIENTS_V: {
      switch (OpNum) {
      case 13:
        // op: RESOURCE_ID
        return 8;
      case 1:
        // op: SRC_GPR
        return 16;
      case 0:
        // op: DST_GPR
        return 32;
      case 9:
        // op: DST_SEL_X
        return 41;
      case 10:
        // op: DST_SEL_Y
        return 44;
      case 11:
        // op: DST_SEL_Z
        return 47;
      case 12:
        // op: DST_SEL_W
        return 50;
      case 15:
        // op: COORD_TYPE_X
        return 60;
      case 16:
        // op: COORD_TYPE_Y
        return 61;
      case 17:
        // op: COORD_TYPE_Z
        return 62;
      case 18:
        // op: COORD_TYPE_W
        return 63;
      }
      break;
    }
    case R600::RAT_ATOMIC_ADD_NORET:
    case R600::RAT_ATOMIC_ADD_RTN:
    case R600::RAT_ATOMIC_AND_NORET:
    case R600::RAT_ATOMIC_AND_RTN:
    case R600::RAT_ATOMIC_CMPXCHG_INT_NORET:
    case R600::RAT_ATOMIC_CMPXCHG_INT_RTN:
    case R600::RAT_ATOMIC_DEC_UINT_NORET:
    case R600::RAT_ATOMIC_DEC_UINT_RTN:
    case R600::RAT_ATOMIC_INC_UINT_NORET:
    case R600::RAT_ATOMIC_INC_UINT_RTN:
    case R600::RAT_ATOMIC_MAX_INT_NORET:
    case R600::RAT_ATOMIC_MAX_INT_RTN:
    case R600::RAT_ATOMIC_MAX_UINT_NORET:
    case R600::RAT_ATOMIC_MAX_UINT_RTN:
    case R600::RAT_ATOMIC_MIN_INT_NORET:
    case R600::RAT_ATOMIC_MIN_INT_RTN:
    case R600::RAT_ATOMIC_MIN_UINT_NORET:
    case R600::RAT_ATOMIC_MIN_UINT_RTN:
    case R600::RAT_ATOMIC_OR_NORET:
    case R600::RAT_ATOMIC_OR_RTN:
    case R600::RAT_ATOMIC_RSUB_NORET:
    case R600::RAT_ATOMIC_RSUB_RTN:
    case R600::RAT_ATOMIC_SUB_NORET:
    case R600::RAT_ATOMIC_SUB_RTN:
    case R600::RAT_ATOMIC_XCHG_INT_NORET:
    case R600::RAT_ATOMIC_XCHG_INT_RTN:
    case R600::RAT_ATOMIC_XOR_NORET:
    case R600::RAT_ATOMIC_XOR_RTN: {
      switch (OpNum) {
      case 1:
        // op: rw_gpr
        return 15;
      case 2:
        // op: index_gpr
        return 23;
      }
      break;
    }
    case R600::LDS_CMPST_RET: {
      switch (OpNum) {
      case 1:
        // op: src0
        return 0;
      case 2:
        // op: src0_rel
        return 9;
      case 4:
        // op: src1
        return 13;
      case 5:
        // op: src1_rel
        return 22;
      case 11:
        // op: pred_sel
        return 29;
      case 10:
        // op: last
        return 31;
      case 7:
        // op: src2
        return 32;
      case 8:
        // op: src2_rel
        return 41;
      case 12:
        // op: bank_swizzle
        return 50;
      }
      break;
    }
    case R600::LDS_ADD_RET:
    case R600::LDS_AND_RET:
    case R600::LDS_MAX_INT_RET:
    case R600::LDS_MAX_UINT_RET:
    case R600::LDS_MIN_INT_RET:
    case R600::LDS_MIN_UINT_RET:
    case R600::LDS_OR_RET:
    case R600::LDS_SUB_RET:
    case R600::LDS_WRXCHG_RET:
    case R600::LDS_XOR_RET: {
      switch (OpNum) {
      case 1:
        // op: src0
        return 0;
      case 2:
        // op: src0_rel
        return 9;
      case 4:
        // op: src1
        return 13;
      case 5:
        // op: src1_rel
        return 22;
      case 8:
        // op: pred_sel
        return 29;
      case 7:
        // op: last
        return 31;
      case 9:
        // op: bank_swizzle
        return 50;
      }
      break;
    }
    case R600::LDS_BYTE_READ_RET:
    case R600::LDS_READ_RET:
    case R600::LDS_SHORT_READ_RET:
    case R600::LDS_UBYTE_READ_RET:
    case R600::LDS_USHORT_READ_RET: {
      switch (OpNum) {
      case 1:
        // op: src0
        return 0;
      case 2:
        // op: src0_rel
        return 9;
      case 5:
        // op: pred_sel
        return 29;
      case 4:
        // op: last
        return 31;
      case 6:
        // op: bank_swizzle
        return 50;
      }
      break;
    }
    case R600::VTX_READ_128_cm:
    case R600::VTX_READ_128_eg:
    case R600::VTX_READ_16_cm:
    case R600::VTX_READ_16_eg:
    case R600::VTX_READ_32_cm:
    case R600::VTX_READ_32_eg:
    case R600::VTX_READ_64_cm:
    case R600::VTX_READ_64_eg:
    case R600::VTX_READ_8_cm:
    case R600::VTX_READ_8_eg: {
      switch (OpNum) {
      case 1:
        // op: src_gpr
        return 16;
      case 3:
        // op: buffer_id
        return 8;
      case 0:
        // op: dst_gpr
        return 32;
      }
      break;
    }
    case R600::EG_ExportBuf: {
      switch (OpNum) {
      case 2:
        // op: arraybase
        return 0;
      case 1:
        // op: type
        return 13;
      case 0:
        // op: gpr
        return 15;
      case 3:
        // op: arraySize
        return 32;
      case 4:
        // op: compMask
        return 44;
      case 6:
        // op: eop
        return 53;
      case 5:
        // op: inst
        return 54;
      }
      break;
    }
    case R600::R600_ExportBuf: {
      switch (OpNum) {
      case 2:
        // op: arraybase
        return 0;
      case 1:
        // op: type
        return 13;
      case 0:
        // op: gpr
        return 15;
      case 3:
        // op: arraySize
        return 32;
      case 4:
        // op: compMask
        return 44;
      case 6:
        // op: eop
        return 53;
      case 5:
        // op: inst
        return 55;
      }
      break;
    }
    case R600::EG_ExportSwz: {
      switch (OpNum) {
      case 2:
        // op: arraybase
        return 0;
      case 1:
        // op: type
        return 13;
      case 0:
        // op: gpr
        return 15;
      case 3:
        // op: sw_x
        return 32;
      case 4:
        // op: sw_y
        return 35;
      case 5:
        // op: sw_z
        return 38;
      case 6:
        // op: sw_w
        return 41;
      case 8:
        // op: eop
        return 53;
      case 7:
        // op: inst
        return 54;
      }
      break;
    }
    case R600::R600_ExportSwz: {
      switch (OpNum) {
      case 2:
        // op: arraybase
        return 0;
      case 1:
        // op: type
        return 13;
      case 0:
        // op: gpr
        return 15;
      case 3:
        // op: sw_x
        return 32;
      case 4:
        // op: sw_y
        return 35;
      case 5:
        // op: sw_z
        return 38;
      case 6:
        // op: sw_w
        return 41;
      case 8:
        // op: eop
        return 53;
      case 7:
        // op: inst
        return 55;
      }
      break;
    }
    case R600::RAT_STORE_TYPED_eg: {
      switch (OpNum) {
      case 2:
        // op: rat_id
        return 0;
      case 0:
        // op: rw_gpr
        return 15;
      case 1:
        // op: index_gpr
        return 23;
      case 3:
        // op: eop
        return 53;
      }
      break;
    }
    case R600::RAT_STORE_TYPED_cm: {
      switch (OpNum) {
      case 2:
        // op: rat_id
        return 0;
      case 0:
        // op: rw_gpr
        return 15;
      case 1:
        // op: index_gpr
        return 23;
      }
      break;
    }
    case R600::BFE_INT_eg:
    case R600::BFE_UINT_eg:
    case R600::BFI_INT_eg:
    case R600::BIT_ALIGN_INT_eg:
    case R600::CNDE_INT:
    case R600::CNDE_eg:
    case R600::CNDE_r600:
    case R600::CNDGE_INT:
    case R600::CNDGE_eg:
    case R600::CNDGE_r600:
    case R600::CNDGT_INT:
    case R600::CNDGT_eg:
    case R600::CNDGT_r600:
    case R600::FMA_eg:
    case R600::MULADD_IEEE_eg:
    case R600::MULADD_IEEE_r600:
    case R600::MULADD_INT24_cm:
    case R600::MULADD_UINT24_eg:
    case R600::MULADD_eg:
    case R600::MULADD_r600:
    case R600::MUL_LIT_eg:
    case R600::MUL_LIT_r600: {
      switch (OpNum) {
      case 3:
        // op: src0
        return 0;
      case 5:
        // op: src0_rel
        return 9;
      case 7:
        // op: src1
        return 13;
      case 9:
        // op: src1_rel
        return 22;
      case 16:
        // op: pred_sel
        return 29;
      case 15:
        // op: last
        return 31;
      case 4:
        // op: src0_neg
        return 12;
      case 8:
        // op: src1_neg
        return 25;
      case 0:
        // op: dst
        return 53;
      case 18:
        // op: bank_swizzle
        return 50;
      case 1:
        // op: dst_rel
        return 60;
      case 2:
        // op: clamp
        return 63;
      case 11:
        // op: src2
        return 32;
      case 13:
        // op: src2_rel
        return 41;
      case 12:
        // op: src2_neg
        return 44;
      }
      break;
    }
    case R600::BCNT_INT:
    case R600::CEIL:
    case R600::COS_cm:
    case R600::COS_eg:
    case R600::COS_r600:
    case R600::COS_r700:
    case R600::EXP_IEEE_cm:
    case R600::EXP_IEEE_eg:
    case R600::EXP_IEEE_r600:
    case R600::FFBH_UINT:
    case R600::FFBL_INT:
    case R600::FLOOR:
    case R600::FLT16_TO_FLT32:
    case R600::FLT32_TO_FLT16:
    case R600::FLT_TO_INT_eg:
    case R600::FLT_TO_INT_r600:
    case R600::FLT_TO_UINT_eg:
    case R600::FLT_TO_UINT_r600:
    case R600::FRACT:
    case R600::INTERP_LOAD_P0:
    case R600::INT_TO_FLT_eg:
    case R600::INT_TO_FLT_r600:
    case R600::LOG_CLAMPED_eg:
    case R600::LOG_CLAMPED_r600:
    case R600::LOG_IEEE_cm:
    case R600::LOG_IEEE_eg:
    case R600::LOG_IEEE_r600:
    case R600::MOV:
    case R600::MOVA_INT_eg:
    case R600::NOT_INT:
    case R600::RECIPSQRT_CLAMPED_cm:
    case R600::RECIPSQRT_CLAMPED_eg:
    case R600::RECIPSQRT_CLAMPED_r600:
    case R600::RECIPSQRT_IEEE_cm:
    case R600::RECIPSQRT_IEEE_eg:
    case R600::RECIPSQRT_IEEE_r600:
    case R600::RECIP_CLAMPED_cm:
    case R600::RECIP_CLAMPED_eg:
    case R600::RECIP_CLAMPED_r600:
    case R600::RECIP_IEEE_cm:
    case R600::RECIP_IEEE_eg:
    case R600::RECIP_IEEE_r600:
    case R600::RECIP_UINT_eg:
    case R600::RECIP_UINT_r600:
    case R600::RNDNE:
    case R600::SIN_cm:
    case R600::SIN_eg:
    case R600::SIN_r600:
    case R600::SIN_r700:
    case R600::TRUNC:
    case R600::UINT_TO_FLT_eg:
    case R600::UINT_TO_FLT_r600: {
      switch (OpNum) {
      case 5:
        // op: src0
        return 0;
      case 7:
        // op: src0_rel
        return 9;
      case 11:
        // op: pred_sel
        return 29;
      case 10:
        // op: last
        return 31;
      case 6:
        // op: src0_neg
        return 12;
      case 0:
        // op: dst
        return 53;
      case 13:
        // op: bank_swizzle
        return 50;
      case 3:
        // op: dst_rel
        return 60;
      case 4:
        // op: clamp
        return 63;
      case 8:
        // op: src0_abs
        return 32;
      case 1:
        // op: write
        return 36;
      case 2:
        // op: omod
        return 37;
      }
      break;
    }
    case R600::ADD:
    case R600::ADDC_UINT:
    case R600::ADD_INT:
    case R600::AND_INT:
    case R600::ASHR_eg:
    case R600::ASHR_r600:
    case R600::BFM_INT_eg:
    case R600::CUBE_eg_real:
    case R600::CUBE_r600_real:
    case R600::DOT4_eg:
    case R600::DOT4_r600:
    case R600::KILLGT:
    case R600::LSHL_eg:
    case R600::LSHL_r600:
    case R600::LSHR_eg:
    case R600::LSHR_r600:
    case R600::MAX:
    case R600::MAX_DX10:
    case R600::MAX_INT:
    case R600::MAX_UINT:
    case R600::MIN:
    case R600::MIN_DX10:
    case R600::MIN_INT:
    case R600::MIN_UINT:
    case R600::MUL:
    case R600::MULHI_INT_cm:
    case R600::MULHI_INT_cm24:
    case R600::MULHI_INT_eg:
    case R600::MULHI_INT_r600:
    case R600::MULHI_UINT24_eg:
    case R600::MULHI_UINT_cm:
    case R600::MULHI_UINT_cm24:
    case R600::MULHI_UINT_eg:
    case R600::MULHI_UINT_r600:
    case R600::MULLO_INT_cm:
    case R600::MULLO_INT_eg:
    case R600::MULLO_INT_r600:
    case R600::MULLO_UINT_cm:
    case R600::MULLO_UINT_eg:
    case R600::MULLO_UINT_r600:
    case R600::MUL_IEEE:
    case R600::MUL_INT24_cm:
    case R600::MUL_UINT24_eg:
    case R600::OR_INT:
    case R600::PRED_SETE:
    case R600::PRED_SETE_INT:
    case R600::PRED_SETGE:
    case R600::PRED_SETGE_INT:
    case R600::PRED_SETGT:
    case R600::PRED_SETGT_INT:
    case R600::PRED_SETNE:
    case R600::PRED_SETNE_INT:
    case R600::SETE:
    case R600::SETE_DX10:
    case R600::SETE_INT:
    case R600::SETGE_DX10:
    case R600::SETGE_INT:
    case R600::SETGE_UINT:
    case R600::SETGT_DX10:
    case R600::SETGT_INT:
    case R600::SETGT_UINT:
    case R600::SETNE_DX10:
    case R600::SETNE_INT:
    case R600::SGE:
    case R600::SGT:
    case R600::SNE:
    case R600::SUBB_UINT:
    case R600::SUB_INT:
    case R600::XOR_INT: {
      switch (OpNum) {
      case 7:
        // op: src0
        return 0;
      case 9:
        // op: src0_rel
        return 9;
      case 12:
        // op: src1
        return 13;
      case 14:
        // op: src1_rel
        return 22;
      case 18:
        // op: pred_sel
        return 29;
      case 17:
        // op: last
        return 31;
      case 8:
        // op: src0_neg
        return 12;
      case 13:
        // op: src1_neg
        return 25;
      case 0:
        // op: dst
        return 53;
      case 20:
        // op: bank_swizzle
        return 50;
      case 5:
        // op: dst_rel
        return 60;
      case 6:
        // op: clamp
        return 63;
      case 10:
        // op: src0_abs
        return 32;
      case 15:
        // op: src1_abs
        return 33;
      case 1:
        // op: update_exec_mask
        return 34;
      case 2:
        // op: update_pred
        return 35;
      case 3:
        // op: write
        return 36;
      case 4:
        // op: omod
        return 37;
      }
      break;
    }
    case R600::INTERP_XY:
    case R600::INTERP_ZW: {
      switch (OpNum) {
      case 7:
        // op: src0
        return 0;
      case 9:
        // op: src0_rel
        return 9;
      case 12:
        // op: src1
        return 13;
      case 14:
        // op: src1_rel
        return 22;
      case 18:
        // op: pred_sel
        return 29;
      case 17:
        // op: last
        return 31;
      case 8:
        // op: src0_neg
        return 12;
      case 13:
        // op: src1_neg
        return 25;
      case 0:
        // op: dst
        return 53;
      case 5:
        // op: dst_rel
        return 60;
      case 6:
        // op: clamp
        return 63;
      case 10:
        // op: src0_abs
        return 32;
      case 15:
        // op: src1_abs
        return 33;
      case 1:
        // op: update_exec_mask
        return 34;
      case 2:
        // op: update_pred
        return 35;
      case 3:
        // op: write
        return 36;
      case 4:
        // op: omod
        return 37;
      }
      break;
    }
  default:
    reportUnsupportedInst(MI);
  }
  reportUnsupportedOperand(MI, OpNum);
}

#endif // GET_OPERAND_BIT_OFFSET

