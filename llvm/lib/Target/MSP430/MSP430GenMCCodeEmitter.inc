/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

uint64_t MSP430MCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
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
    UINT64_C(20608),	// ADD16mc
    UINT64_C(20656),	// ADD16mi
    UINT64_C(20624),	// ADD16mm
    UINT64_C(20640),	// ADD16mn
    UINT64_C(20656),	// ADD16mp
    UINT64_C(20608),	// ADD16mr
    UINT64_C(20480),	// ADD16rc
    UINT64_C(20528),	// ADD16ri
    UINT64_C(20496),	// ADD16rm
    UINT64_C(20512),	// ADD16rn
    UINT64_C(20528),	// ADD16rp
    UINT64_C(20480),	// ADD16rr
    UINT64_C(20672),	// ADD8mc
    UINT64_C(20720),	// ADD8mi
    UINT64_C(20688),	// ADD8mm
    UINT64_C(20704),	// ADD8mn
    UINT64_C(20720),	// ADD8mp
    UINT64_C(20672),	// ADD8mr
    UINT64_C(20544),	// ADD8rc
    UINT64_C(20592),	// ADD8ri
    UINT64_C(20560),	// ADD8rm
    UINT64_C(20576),	// ADD8rn
    UINT64_C(20592),	// ADD8rp
    UINT64_C(20544),	// ADD8rr
    UINT64_C(24704),	// ADDC16mc
    UINT64_C(24752),	// ADDC16mi
    UINT64_C(24720),	// ADDC16mm
    UINT64_C(24736),	// ADDC16mn
    UINT64_C(24752),	// ADDC16mp
    UINT64_C(24704),	// ADDC16mr
    UINT64_C(24576),	// ADDC16rc
    UINT64_C(24624),	// ADDC16ri
    UINT64_C(24592),	// ADDC16rm
    UINT64_C(24608),	// ADDC16rn
    UINT64_C(24624),	// ADDC16rp
    UINT64_C(24576),	// ADDC16rr
    UINT64_C(24768),	// ADDC8mc
    UINT64_C(24816),	// ADDC8mi
    UINT64_C(24784),	// ADDC8mm
    UINT64_C(24800),	// ADDC8mn
    UINT64_C(24816),	// ADDC8mp
    UINT64_C(24768),	// ADDC8mr
    UINT64_C(24640),	// ADDC8rc
    UINT64_C(24688),	// ADDC8ri
    UINT64_C(24656),	// ADDC8rm
    UINT64_C(24672),	// ADDC8rn
    UINT64_C(24688),	// ADDC8rp
    UINT64_C(24640),	// ADDC8rr
    UINT64_C(0),	// ADDframe
    UINT64_C(0),	// ADJCALLSTACKDOWN
    UINT64_C(0),	// ADJCALLSTACKUP
    UINT64_C(61568),	// AND16mc
    UINT64_C(61616),	// AND16mi
    UINT64_C(61584),	// AND16mm
    UINT64_C(61600),	// AND16mn
    UINT64_C(61616),	// AND16mp
    UINT64_C(61568),	// AND16mr
    UINT64_C(61440),	// AND16rc
    UINT64_C(61488),	// AND16ri
    UINT64_C(61456),	// AND16rm
    UINT64_C(61472),	// AND16rn
    UINT64_C(61488),	// AND16rp
    UINT64_C(61440),	// AND16rr
    UINT64_C(61632),	// AND8mc
    UINT64_C(61680),	// AND8mi
    UINT64_C(61648),	// AND8mm
    UINT64_C(61664),	// AND8mn
    UINT64_C(61680),	// AND8mp
    UINT64_C(61632),	// AND8mr
    UINT64_C(61504),	// AND8rc
    UINT64_C(61552),	// AND8ri
    UINT64_C(61520),	// AND8rm
    UINT64_C(61536),	// AND8rn
    UINT64_C(61552),	// AND8rp
    UINT64_C(61504),	// AND8rr
    UINT64_C(49280),	// BIC16mc
    UINT64_C(49328),	// BIC16mi
    UINT64_C(49296),	// BIC16mm
    UINT64_C(49312),	// BIC16mn
    UINT64_C(49328),	// BIC16mp
    UINT64_C(49280),	// BIC16mr
    UINT64_C(49152),	// BIC16rc
    UINT64_C(49200),	// BIC16ri
    UINT64_C(49168),	// BIC16rm
    UINT64_C(49184),	// BIC16rn
    UINT64_C(49200),	// BIC16rp
    UINT64_C(49152),	// BIC16rr
    UINT64_C(49344),	// BIC8mc
    UINT64_C(49392),	// BIC8mi
    UINT64_C(49360),	// BIC8mm
    UINT64_C(49376),	// BIC8mn
    UINT64_C(49392),	// BIC8mp
    UINT64_C(49344),	// BIC8mr
    UINT64_C(49216),	// BIC8rc
    UINT64_C(49264),	// BIC8ri
    UINT64_C(49232),	// BIC8rm
    UINT64_C(49248),	// BIC8rn
    UINT64_C(49264),	// BIC8rp
    UINT64_C(49216),	// BIC8rr
    UINT64_C(53376),	// BIS16mc
    UINT64_C(53424),	// BIS16mi
    UINT64_C(53392),	// BIS16mm
    UINT64_C(53408),	// BIS16mn
    UINT64_C(53424),	// BIS16mp
    UINT64_C(53376),	// BIS16mr
    UINT64_C(53248),	// BIS16rc
    UINT64_C(53296),	// BIS16ri
    UINT64_C(53264),	// BIS16rm
    UINT64_C(53280),	// BIS16rn
    UINT64_C(53296),	// BIS16rp
    UINT64_C(53248),	// BIS16rr
    UINT64_C(53440),	// BIS8mc
    UINT64_C(53488),	// BIS8mi
    UINT64_C(53456),	// BIS8mm
    UINT64_C(53472),	// BIS8mn
    UINT64_C(53488),	// BIS8mp
    UINT64_C(53440),	// BIS8mr
    UINT64_C(53312),	// BIS8rc
    UINT64_C(53360),	// BIS8ri
    UINT64_C(53328),	// BIS8rm
    UINT64_C(53344),	// BIS8rn
    UINT64_C(53360),	// BIS8rp
    UINT64_C(53312),	// BIS8rr
    UINT64_C(45184),	// BIT16mc
    UINT64_C(45232),	// BIT16mi
    UINT64_C(45200),	// BIT16mm
    UINT64_C(45216),	// BIT16mn
    UINT64_C(45232),	// BIT16mp
    UINT64_C(45184),	// BIT16mr
    UINT64_C(45056),	// BIT16rc
    UINT64_C(45104),	// BIT16ri
    UINT64_C(45072),	// BIT16rm
    UINT64_C(45088),	// BIT16rn
    UINT64_C(45104),	// BIT16rp
    UINT64_C(45056),	// BIT16rr
    UINT64_C(45248),	// BIT8mc
    UINT64_C(45296),	// BIT8mi
    UINT64_C(45264),	// BIT8mm
    UINT64_C(45280),	// BIT8mn
    UINT64_C(45296),	// BIT8mp
    UINT64_C(45248),	// BIT8mr
    UINT64_C(45120),	// BIT8rc
    UINT64_C(45168),	// BIT8ri
    UINT64_C(45136),	// BIT8rm
    UINT64_C(45152),	// BIT8rn
    UINT64_C(45168),	// BIT8rp
    UINT64_C(45120),	// BIT8rr
    UINT64_C(16432),	// Bi
    UINT64_C(16400),	// Bm
    UINT64_C(16384),	// Br
    UINT64_C(4784),	// CALLi
    UINT64_C(4752),	// CALLm
    UINT64_C(4768),	// CALLn
    UINT64_C(4784),	// CALLp
    UINT64_C(4736),	// CALLr
    UINT64_C(36992),	// CMP16mc
    UINT64_C(37040),	// CMP16mi
    UINT64_C(37008),	// CMP16mm
    UINT64_C(37024),	// CMP16mn
    UINT64_C(37040),	// CMP16mp
    UINT64_C(36992),	// CMP16mr
    UINT64_C(36864),	// CMP16rc
    UINT64_C(36912),	// CMP16ri
    UINT64_C(36880),	// CMP16rm
    UINT64_C(36896),	// CMP16rn
    UINT64_C(36912),	// CMP16rp
    UINT64_C(36864),	// CMP16rr
    UINT64_C(37056),	// CMP8mc
    UINT64_C(37104),	// CMP8mi
    UINT64_C(37072),	// CMP8mm
    UINT64_C(37088),	// CMP8mn
    UINT64_C(37104),	// CMP8mp
    UINT64_C(37056),	// CMP8mr
    UINT64_C(36928),	// CMP8rc
    UINT64_C(36976),	// CMP8ri
    UINT64_C(36944),	// CMP8rm
    UINT64_C(36960),	// CMP8rn
    UINT64_C(36976),	// CMP8rp
    UINT64_C(36928),	// CMP8rr
    UINT64_C(41088),	// DADD16mc
    UINT64_C(41136),	// DADD16mi
    UINT64_C(41104),	// DADD16mm
    UINT64_C(41120),	// DADD16mn
    UINT64_C(41136),	// DADD16mp
    UINT64_C(41088),	// DADD16mr
    UINT64_C(40960),	// DADD16rc
    UINT64_C(41008),	// DADD16ri
    UINT64_C(40976),	// DADD16rm
    UINT64_C(40992),	// DADD16rn
    UINT64_C(41008),	// DADD16rp
    UINT64_C(40960),	// DADD16rr
    UINT64_C(41152),	// DADD8mc
    UINT64_C(41200),	// DADD8mi
    UINT64_C(41168),	// DADD8mm
    UINT64_C(41184),	// DADD8mn
    UINT64_C(41200),	// DADD8mp
    UINT64_C(41152),	// DADD8mr
    UINT64_C(41024),	// DADD8rc
    UINT64_C(41072),	// DADD8ri
    UINT64_C(41040),	// DADD8rm
    UINT64_C(41056),	// DADD8rn
    UINT64_C(41072),	// DADD8rp
    UINT64_C(41024),	// DADD8rr
    UINT64_C(8192),	// JCC
    UINT64_C(15360),	// JMP
    UINT64_C(16512),	// MOV16mc
    UINT64_C(16560),	// MOV16mi
    UINT64_C(16528),	// MOV16mm
    UINT64_C(16544),	// MOV16mn
    UINT64_C(16560),	// MOV16mp
    UINT64_C(16512),	// MOV16mr
    UINT64_C(16384),	// MOV16rc
    UINT64_C(16432),	// MOV16ri
    UINT64_C(16400),	// MOV16rm
    UINT64_C(16416),	// MOV16rn
    UINT64_C(16432),	// MOV16rp
    UINT64_C(16384),	// MOV16rr
    UINT64_C(16576),	// MOV8mc
    UINT64_C(16624),	// MOV8mi
    UINT64_C(16592),	// MOV8mm
    UINT64_C(16608),	// MOV8mn
    UINT64_C(16624),	// MOV8mp
    UINT64_C(16576),	// MOV8mr
    UINT64_C(16448),	// MOV8rc
    UINT64_C(16496),	// MOV8ri
    UINT64_C(16464),	// MOV8rm
    UINT64_C(16480),	// MOV8rn
    UINT64_C(16496),	// MOV8rp
    UINT64_C(16448),	// MOV8rr
    UINT64_C(16464),	// MOVZX16rm8
    UINT64_C(16448),	// MOVZX16rr8
    UINT64_C(16688),	// POP16r
    UINT64_C(4608),	// PUSH16c
    UINT64_C(4656),	// PUSH16i
    UINT64_C(4608),	// PUSH16r
    UINT64_C(4672),	// PUSH8r
    UINT64_C(16688),	// RET
    UINT64_C(4864),	// RETI
    UINT64_C(4368),	// RRA16m
    UINT64_C(4384),	// RRA16n
    UINT64_C(4400),	// RRA16p
    UINT64_C(4352),	// RRA16r
    UINT64_C(4432),	// RRA8m
    UINT64_C(4448),	// RRA8n
    UINT64_C(4464),	// RRA8p
    UINT64_C(4416),	// RRA8r
    UINT64_C(4112),	// RRC16m
    UINT64_C(4128),	// RRC16n
    UINT64_C(4144),	// RRC16p
    UINT64_C(4096),	// RRC16r
    UINT64_C(4176),	// RRC8m
    UINT64_C(4192),	// RRC8n
    UINT64_C(4208),	// RRC8p
    UINT64_C(4160),	// RRC8r
    UINT64_C(0),	// Rrcl16
    UINT64_C(0),	// Rrcl8
    UINT64_C(4496),	// SEXT16m
    UINT64_C(4512),	// SEXT16n
    UINT64_C(4528),	// SEXT16p
    UINT64_C(4480),	// SEXT16r
    UINT64_C(32896),	// SUB16mc
    UINT64_C(32944),	// SUB16mi
    UINT64_C(32912),	// SUB16mm
    UINT64_C(32928),	// SUB16mn
    UINT64_C(32944),	// SUB16mp
    UINT64_C(32896),	// SUB16mr
    UINT64_C(32768),	// SUB16rc
    UINT64_C(32816),	// SUB16ri
    UINT64_C(32784),	// SUB16rm
    UINT64_C(32800),	// SUB16rn
    UINT64_C(32816),	// SUB16rp
    UINT64_C(32768),	// SUB16rr
    UINT64_C(32960),	// SUB8mc
    UINT64_C(33008),	// SUB8mi
    UINT64_C(32976),	// SUB8mm
    UINT64_C(32992),	// SUB8mn
    UINT64_C(33008),	// SUB8mp
    UINT64_C(32960),	// SUB8mr
    UINT64_C(32832),	// SUB8rc
    UINT64_C(32880),	// SUB8ri
    UINT64_C(32848),	// SUB8rm
    UINT64_C(32864),	// SUB8rn
    UINT64_C(32880),	// SUB8rp
    UINT64_C(32832),	// SUB8rr
    UINT64_C(28800),	// SUBC16mc
    UINT64_C(28848),	// SUBC16mi
    UINT64_C(28816),	// SUBC16mm
    UINT64_C(28832),	// SUBC16mn
    UINT64_C(28848),	// SUBC16mp
    UINT64_C(28800),	// SUBC16mr
    UINT64_C(28672),	// SUBC16rc
    UINT64_C(28720),	// SUBC16ri
    UINT64_C(28688),	// SUBC16rm
    UINT64_C(28704),	// SUBC16rn
    UINT64_C(28720),	// SUBC16rp
    UINT64_C(28672),	// SUBC16rr
    UINT64_C(28864),	// SUBC8mc
    UINT64_C(28912),	// SUBC8mi
    UINT64_C(28880),	// SUBC8mm
    UINT64_C(28896),	// SUBC8mn
    UINT64_C(28912),	// SUBC8mp
    UINT64_C(28864),	// SUBC8mr
    UINT64_C(28736),	// SUBC8rc
    UINT64_C(28784),	// SUBC8ri
    UINT64_C(28752),	// SUBC8rm
    UINT64_C(28768),	// SUBC8rn
    UINT64_C(28784),	// SUBC8rp
    UINT64_C(28736),	// SUBC8rr
    UINT64_C(4240),	// SWPB16m
    UINT64_C(4256),	// SWPB16n
    UINT64_C(4272),	// SWPB16p
    UINT64_C(4224),	// SWPB16r
    UINT64_C(0),	// Select16
    UINT64_C(0),	// Select8
    UINT64_C(0),	// Shl16
    UINT64_C(0),	// Shl8
    UINT64_C(0),	// Sra16
    UINT64_C(0),	// Sra8
    UINT64_C(0),	// Srl16
    UINT64_C(0),	// Srl8
    UINT64_C(57472),	// XOR16mc
    UINT64_C(57520),	// XOR16mi
    UINT64_C(57488),	// XOR16mm
    UINT64_C(57504),	// XOR16mn
    UINT64_C(57520),	// XOR16mp
    UINT64_C(57472),	// XOR16mr
    UINT64_C(57344),	// XOR16rc
    UINT64_C(57392),	// XOR16ri
    UINT64_C(57360),	// XOR16rm
    UINT64_C(57376),	// XOR16rn
    UINT64_C(57392),	// XOR16rp
    UINT64_C(57344),	// XOR16rr
    UINT64_C(57536),	// XOR8mc
    UINT64_C(57584),	// XOR8mi
    UINT64_C(57552),	// XOR8mm
    UINT64_C(57568),	// XOR8mn
    UINT64_C(57584),	// XOR8mp
    UINT64_C(57536),	// XOR8mr
    UINT64_C(57408),	// XOR8rc
    UINT64_C(57456),	// XOR8ri
    UINT64_C(57424),	// XOR8rm
    UINT64_C(57440),	// XOR8rn
    UINT64_C(57456),	// XOR8rp
    UINT64_C(57408),	// XOR8rr
    UINT64_C(16448),	// ZEXT16r
    UINT64_C(0)
  };
  const unsigned opcode = MI.getOpcode();
  uint64_t Value = InstBits[opcode];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case MSP430::ADDframe:
    case MSP430::ADJCALLSTACKDOWN:
    case MSP430::ADJCALLSTACKUP:
    case MSP430::RET:
    case MSP430::RETI:
    case MSP430::Rrcl16:
    case MSP430::Rrcl8:
    case MSP430::Select16:
    case MSP430::Select8:
    case MSP430::Shl16:
    case MSP430::Shl8:
    case MSP430::Sra16:
    case MSP430::Sra8:
    case MSP430::Srl16:
    case MSP430::Srl8: {
      break;
    }
    case MSP430::JCC: {
      // op: cond
      op = getCCOpValue(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(7)) << 10;
      // op: dst
      op = getPCRelImmOpValue(MI, 0, Fixups, STI);
      Value |= op & UINT64_C(1023);
      break;
    }
    case MSP430::JMP: {
      // op: dst
      op = getPCRelImmOpValue(MI, 0, Fixups, STI);
      Value |= op & UINT64_C(1023);
      break;
    }
    case MSP430::PUSH16c: {
      // op: imm
      op = getCGImmOpValue(MI, 0, Fixups, STI);
      Value |= op & UINT64_C(63);
      break;
    }
    case MSP430::BIT16rc:
    case MSP430::BIT8rc:
    case MSP430::CMP16rc:
    case MSP430::CMP8rc:
    case MSP430::MOV16rc:
    case MSP430::MOV8rc: {
      // op: imm
      op = getCGImmOpValue(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      Value |= op & UINT64_C(48);
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::ADD16mc:
    case MSP430::ADD8mc:
    case MSP430::ADDC16mc:
    case MSP430::ADDC8mc:
    case MSP430::AND16mc:
    case MSP430::AND8mc:
    case MSP430::BIC16mc:
    case MSP430::BIC8mc:
    case MSP430::BIS16mc:
    case MSP430::BIS8mc:
    case MSP430::BIT8mc:
    case MSP430::CMP16mc:
    case MSP430::CMP8mc:
    case MSP430::DADD16mc:
    case MSP430::DADD8mc:
    case MSP430::MOV16mc:
    case MSP430::MOV8mc:
    case MSP430::SUB16mc:
    case MSP430::SUB8mc:
    case MSP430::SUBC16mc:
    case MSP430::SUBC8mc:
    case MSP430::XOR16mc:
    case MSP430::XOR8mc: {
      // op: imm
      op = getCGImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      Value |= op & UINT64_C(48);
      // op: dst
      op = getMemOpValue(MI, 0, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 12;
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::ADD16rc:
    case MSP430::ADD8rc:
    case MSP430::ADDC16rc:
    case MSP430::ADDC8rc:
    case MSP430::AND16rc:
    case MSP430::AND8rc:
    case MSP430::BIC16rc:
    case MSP430::BIC8rc:
    case MSP430::BIS16rc:
    case MSP430::BIS8rc:
    case MSP430::DADD16rc:
    case MSP430::DADD8rc:
    case MSP430::SUB16rc:
    case MSP430::SUB8rc:
    case MSP430::SUBC16rc:
    case MSP430::SUBC8rc:
    case MSP430::XOR16rc:
    case MSP430::XOR8rc: {
      // op: imm
      op = getCGImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      Value |= op & UINT64_C(48);
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::Bi:
    case MSP430::CALLi:
    case MSP430::PUSH16i: {
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(65535)) << 16;
      break;
    }
    case MSP430::BIT16mc: {
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      Value |= op & UINT64_C(48);
      // op: dst
      op = getMemOpValue(MI, 0, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 12;
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::ADD16mi:
    case MSP430::ADD8mi:
    case MSP430::ADDC16mi:
    case MSP430::ADDC8mi:
    case MSP430::AND16mi:
    case MSP430::AND8mi:
    case MSP430::BIC16mi:
    case MSP430::BIC8mi:
    case MSP430::BIS16mi:
    case MSP430::BIS8mi:
    case MSP430::BIT16mi:
    case MSP430::BIT8mi:
    case MSP430::CMP16mi:
    case MSP430::CMP8mi:
    case MSP430::DADD16mi:
    case MSP430::DADD8mi:
    case MSP430::MOV16mi:
    case MSP430::MOV8mi:
    case MSP430::SUB16mi:
    case MSP430::SUB8mi:
    case MSP430::SUBC16mi:
    case MSP430::SUBC8mi:
    case MSP430::XOR16mi:
    case MSP430::XOR8mi: {
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(65535)) << 16;
      // op: dst
      op = getMemOpValue(MI, 0, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 28;
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::POP16r: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::BIT16ri:
    case MSP430::BIT8ri:
    case MSP430::CMP16ri:
    case MSP430::CMP8ri:
    case MSP430::MOV16ri:
    case MSP430::MOV8ri: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(65535)) << 16;
      break;
    }
    case MSP430::ADD16ri:
    case MSP430::ADD8ri:
    case MSP430::ADDC16ri:
    case MSP430::ADDC8ri:
    case MSP430::AND16ri:
    case MSP430::AND8ri:
    case MSP430::BIC16ri:
    case MSP430::BIC8ri:
    case MSP430::BIS16ri:
    case MSP430::BIS8ri:
    case MSP430::DADD16ri:
    case MSP430::DADD8ri:
    case MSP430::SUB16ri:
    case MSP430::SUB8ri:
    case MSP430::SUBC16ri:
    case MSP430::SUBC8ri:
    case MSP430::XOR16ri:
    case MSP430::XOR8ri: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(65535)) << 16;
      break;
    }
    case MSP430::BIT16rm:
    case MSP430::BIT8rm:
    case MSP430::CMP16rm:
    case MSP430::CMP8rm:
    case MSP430::MOV16rm:
    case MSP430::MOV8rm:
    case MSP430::MOVZX16rm8: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: src
      op = getMemOpValue(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 12;
      Value |= (op & UINT64_C(15)) << 8;
      break;
    }
    case MSP430::ADD16rm:
    case MSP430::ADD8rm:
    case MSP430::ADDC16rm:
    case MSP430::ADDC8rm:
    case MSP430::AND16rm:
    case MSP430::AND8rm:
    case MSP430::BIC16rm:
    case MSP430::BIC8rm:
    case MSP430::BIS16rm:
    case MSP430::BIS8rm:
    case MSP430::DADD16rm:
    case MSP430::DADD8rm:
    case MSP430::SUB16rm:
    case MSP430::SUB8rm:
    case MSP430::SUBC16rm:
    case MSP430::SUBC8rm:
    case MSP430::XOR16rm:
    case MSP430::XOR8rm: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: src
      op = getMemOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 12;
      Value |= (op & UINT64_C(15)) << 8;
      break;
    }
    case MSP430::Br: {
      // op: rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      break;
    }
    case MSP430::CALLn:
    case MSP430::CALLp:
    case MSP430::CALLr:
    case MSP430::PUSH16r:
    case MSP430::PUSH8r:
    case MSP430::RRA16n:
    case MSP430::RRA16p:
    case MSP430::RRA8n:
    case MSP430::RRA8p:
    case MSP430::RRC16n:
    case MSP430::RRC16p:
    case MSP430::RRC8n:
    case MSP430::RRC8p:
    case MSP430::SEXT16n:
    case MSP430::SEXT16p:
    case MSP430::SWPB16n:
    case MSP430::SWPB16p: {
      // op: rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::BIT16rn:
    case MSP430::BIT16rp:
    case MSP430::BIT16rr:
    case MSP430::BIT8rn:
    case MSP430::BIT8rp:
    case MSP430::BIT8rr:
    case MSP430::CMP16rn:
    case MSP430::CMP16rp:
    case MSP430::CMP16rr:
    case MSP430::CMP8rn:
    case MSP430::CMP8rp:
    case MSP430::CMP8rr:
    case MSP430::MOV16rn:
    case MSP430::MOV16rr:
    case MSP430::MOV8rn:
    case MSP430::MOV8rr:
    case MSP430::MOVZX16rr8:
    case MSP430::ZEXT16r: {
      // op: rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::RRA16r:
    case MSP430::RRA8r:
    case MSP430::RRC16r:
    case MSP430::RRC8r:
    case MSP430::SEXT16r:
    case MSP430::SWPB16r: {
      // op: rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::ADD16mn:
    case MSP430::ADD16mp:
    case MSP430::ADD16mr:
    case MSP430::ADD8mn:
    case MSP430::ADD8mp:
    case MSP430::ADD8mr:
    case MSP430::ADDC16mn:
    case MSP430::ADDC16mp:
    case MSP430::ADDC16mr:
    case MSP430::ADDC8mn:
    case MSP430::ADDC8mp:
    case MSP430::ADDC8mr:
    case MSP430::AND16mn:
    case MSP430::AND16mp:
    case MSP430::AND16mr:
    case MSP430::AND8mn:
    case MSP430::AND8mp:
    case MSP430::AND8mr:
    case MSP430::BIC16mn:
    case MSP430::BIC16mp:
    case MSP430::BIC16mr:
    case MSP430::BIC8mn:
    case MSP430::BIC8mp:
    case MSP430::BIC8mr:
    case MSP430::BIS16mn:
    case MSP430::BIS16mp:
    case MSP430::BIS16mr:
    case MSP430::BIS8mn:
    case MSP430::BIS8mp:
    case MSP430::BIS8mr:
    case MSP430::BIT16mn:
    case MSP430::BIT16mp:
    case MSP430::BIT16mr:
    case MSP430::BIT8mn:
    case MSP430::BIT8mp:
    case MSP430::BIT8mr:
    case MSP430::CMP16mn:
    case MSP430::CMP16mp:
    case MSP430::CMP16mr:
    case MSP430::CMP8mn:
    case MSP430::CMP8mp:
    case MSP430::CMP8mr:
    case MSP430::DADD16mn:
    case MSP430::DADD16mp:
    case MSP430::DADD16mr:
    case MSP430::DADD8mn:
    case MSP430::DADD8mp:
    case MSP430::DADD8mr:
    case MSP430::MOV16mn:
    case MSP430::MOV16mp:
    case MSP430::MOV16mr:
    case MSP430::MOV8mn:
    case MSP430::MOV8mp:
    case MSP430::MOV8mr:
    case MSP430::SUB16mn:
    case MSP430::SUB16mp:
    case MSP430::SUB16mr:
    case MSP430::SUB8mn:
    case MSP430::SUB8mp:
    case MSP430::SUB8mr:
    case MSP430::SUBC16mn:
    case MSP430::SUBC16mp:
    case MSP430::SUBC16mr:
    case MSP430::SUBC8mn:
    case MSP430::SUBC8mp:
    case MSP430::SUBC8mr:
    case MSP430::XOR16mn:
    case MSP430::XOR16mp:
    case MSP430::XOR16mr:
    case MSP430::XOR8mn:
    case MSP430::XOR8mp:
    case MSP430::XOR8mr: {
      // op: rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      // op: dst
      op = getMemOpValue(MI, 0, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 12;
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::ADD16rn:
    case MSP430::ADD16rr:
    case MSP430::ADD8rn:
    case MSP430::ADD8rr:
    case MSP430::ADDC16rn:
    case MSP430::ADDC16rr:
    case MSP430::ADDC8rn:
    case MSP430::ADDC8rr:
    case MSP430::AND16rn:
    case MSP430::AND16rr:
    case MSP430::AND8rn:
    case MSP430::AND8rr:
    case MSP430::BIC16rn:
    case MSP430::BIC16rr:
    case MSP430::BIC8rn:
    case MSP430::BIC8rr:
    case MSP430::BIS16rn:
    case MSP430::BIS16rr:
    case MSP430::BIS8rn:
    case MSP430::BIS8rr:
    case MSP430::DADD16rn:
    case MSP430::DADD16rr:
    case MSP430::DADD8rn:
    case MSP430::DADD8rr:
    case MSP430::MOV16rp:
    case MSP430::MOV8rp:
    case MSP430::SUB16rn:
    case MSP430::SUB16rr:
    case MSP430::SUB8rn:
    case MSP430::SUB8rr:
    case MSP430::SUBC16rn:
    case MSP430::SUBC16rr:
    case MSP430::SUBC8rn:
    case MSP430::SUBC8rr:
    case MSP430::XOR16rn:
    case MSP430::XOR16rr:
    case MSP430::XOR8rn:
    case MSP430::XOR8rr: {
      // op: rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::ADD16rp:
    case MSP430::ADD8rp:
    case MSP430::ADDC16rp:
    case MSP430::ADDC8rp:
    case MSP430::AND16rp:
    case MSP430::AND8rp:
    case MSP430::BIC16rp:
    case MSP430::BIC8rp:
    case MSP430::BIS16rp:
    case MSP430::BIS8rp:
    case MSP430::DADD16rp:
    case MSP430::DADD8rp:
    case MSP430::SUB16rp:
    case MSP430::SUB8rp:
    case MSP430::SUBC16rp:
    case MSP430::SUBC8rp:
    case MSP430::XOR16rp:
    case MSP430::XOR8rp: {
      // op: rs
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::Bm: {
      // op: src
      op = getMemOpValue(MI, 0, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 12;
      Value |= (op & UINT64_C(15)) << 8;
      break;
    }
    case MSP430::CALLm:
    case MSP430::RRA16m:
    case MSP430::RRA8m:
    case MSP430::RRC16m:
    case MSP430::RRC8m:
    case MSP430::SEXT16m:
    case MSP430::SWPB16m: {
      // op: src
      op = getMemOpValue(MI, 0, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 12;
      Value |= op & UINT64_C(15);
      break;
    }
    case MSP430::ADD16mm:
    case MSP430::ADD8mm:
    case MSP430::ADDC16mm:
    case MSP430::ADDC8mm:
    case MSP430::AND16mm:
    case MSP430::AND8mm:
    case MSP430::BIC16mm:
    case MSP430::BIC8mm:
    case MSP430::BIS16mm:
    case MSP430::BIS8mm:
    case MSP430::BIT16mm:
    case MSP430::BIT8mm:
    case MSP430::CMP16mm:
    case MSP430::CMP8mm:
    case MSP430::DADD16mm:
    case MSP430::DADD8mm:
    case MSP430::MOV16mm:
    case MSP430::MOV8mm:
    case MSP430::SUB16mm:
    case MSP430::SUB8mm:
    case MSP430::SUBC16mm:
    case MSP430::SUBC8mm:
    case MSP430::XOR16mm:
    case MSP430::XOR8mm: {
      // op: src
      op = getMemOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 12;
      Value |= (op & UINT64_C(15)) << 8;
      // op: dst
      op = getMemOpValue(MI, 0, Fixups, STI);
      Value |= (op & UINT64_C(1048560)) << 28;
      Value |= op & UINT64_C(15);
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

