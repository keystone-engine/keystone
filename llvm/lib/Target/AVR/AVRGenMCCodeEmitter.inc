/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

uint64_t AVRMCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
    SmallVectorImpl<MCFixup> &Fixups,
    const MCSubtargetInfo &STI) const {
  static const uint64_t InstBits[] = {
    UINT64_C(7168),	// ADCRdRr
    UINT64_C(3072),	// ADDRdRr
    UINT64_C(38400),	// ADIWRdK
    UINT64_C(28672),	// ANDIRdK
    UINT64_C(8192),	// ANDRdRr
    UINT64_C(37893),	// ASRRd
    UINT64_C(38024),	// BCLRs
    UINT64_C(63488),	// BLD
    UINT64_C(62464),	// BRBCsk
    UINT64_C(61440),	// BRBSsk
    UINT64_C(38296),	// BREAK
    UINT64_C(61441),	// BREQk
    UINT64_C(62468),	// BRGEk
    UINT64_C(61440),	// BRLOk
    UINT64_C(61444),	// BRLTk
    UINT64_C(61442),	// BRMIk
    UINT64_C(62465),	// BRNEk
    UINT64_C(62466),	// BRPLk
    UINT64_C(62464),	// BRSHk
    UINT64_C(37896),	// BSETs
    UINT64_C(64000),	// BST
    UINT64_C(2483945472),	// CALLk
    UINT64_C(38912),	// CBIAb
    UINT64_C(37888),	// COMRd
    UINT64_C(1024),	// CPCRdRr
    UINT64_C(12288),	// CPIRdK
    UINT64_C(5120),	// CPRdRr
    UINT64_C(4096),	// CPSE
    UINT64_C(37898),	// DECRd
    UINT64_C(37899),	// DESK
    UINT64_C(38169),	// EICALL
    UINT64_C(37913),	// EIJMP
    UINT64_C(38360),	// ELPM
    UINT64_C(36870),	// ELPMRdZ
    UINT64_C(36871),	// ELPMRdZPi
    UINT64_C(9216),	// EORRdRr
    UINT64_C(776),	// FMUL
    UINT64_C(896),	// FMULS
    UINT64_C(904),	// FMULSU
    UINT64_C(38153),	// ICALL
    UINT64_C(37897),	// IJMP
    UINT64_C(37891),	// INCRd
    UINT64_C(45056),	// INRdA
    UINT64_C(2483814400),	// JMPk
    UINT64_C(37382),	// LACZRd
    UINT64_C(37381),	// LASZRd
    UINT64_C(37383),	// LATZRd
    UINT64_C(32768),	// LDDRdPtrQ
    UINT64_C(57344),	// LDIRdK
    UINT64_C(32768),	// LDRdPtr
    UINT64_C(32770),	// LDRdPtrPd
    UINT64_C(32769),	// LDRdPtrPi
    UINT64_C(2415919104),	// LDSRdK
    UINT64_C(40960),	// LDSRdKTiny
    UINT64_C(38344),	// LPM
    UINT64_C(36868),	// LPMRdZ
    UINT64_C(36869),	// LPMRdZPi
    UINT64_C(37894),	// LSRRd
    UINT64_C(11264),	// MOVRdRr
    UINT64_C(256),	// MOVWRdRr
    UINT64_C(39936),	// MULRdRr
    UINT64_C(512),	// MULSRdRr
    UINT64_C(768),	// MULSURdRr
    UINT64_C(37889),	// NEGRd
    UINT64_C(0),	// NOP
    UINT64_C(24576),	// ORIRdK
    UINT64_C(10240),	// ORRdRr
    UINT64_C(47104),	// OUTARr
    UINT64_C(36879),	// POPRd
    UINT64_C(37391),	// PUSHRr
    UINT64_C(53248),	// RCALLk
    UINT64_C(38152),	// RET
    UINT64_C(38168),	// RETI
    UINT64_C(49152),	// RJMPk
    UINT64_C(37895),	// RORRd
    UINT64_C(16384),	// SBCIRdK
    UINT64_C(2048),	// SBCRdRr
    UINT64_C(39424),	// SBIAb
    UINT64_C(39168),	// SBICAb
    UINT64_C(39680),	// SBISAb
    UINT64_C(38656),	// SBIWRdK
    UINT64_C(64512),	// SBRCRrB
    UINT64_C(65024),	// SBRSRrB
    UINT64_C(38280),	// SLEEP
    UINT64_C(38376),	// SPM
    UINT64_C(38392),	// SPMZPi
    UINT64_C(33280),	// STDPtrQRr
    UINT64_C(33282),	// STPtrPdRr
    UINT64_C(33281),	// STPtrPiRr
    UINT64_C(33280),	// STPtrRr
    UINT64_C(2449473536),	// STSKRr
    UINT64_C(43008),	// STSKRrTiny
    UINT64_C(20480),	// SUBIRdK
    UINT64_C(6144),	// SUBRdRr
    UINT64_C(37890),	// SWAPRd
    UINT64_C(38312),	// WDR
    UINT64_C(37380),	// XCHZRd
  };
  constexpr unsigned FirstSupportedOpcode = 426;

  const unsigned opcode = MI.getOpcode();
  if (opcode < FirstSupportedOpcode)
    reportUnsupportedInst(MI);
  unsigned TableIndex = opcode - FirstSupportedOpcode;
  uint64_t Value = InstBits[TableIndex];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case AVR::BREAK:
    case AVR::EICALL:
    case AVR::EIJMP:
    case AVR::ELPM:
    case AVR::ICALL:
    case AVR::IJMP:
    case AVR::LPM:
    case AVR::NOP:
    case AVR::RET:
    case AVR::RETI:
    case AVR::SLEEP:
    case AVR::SPM:
    case AVR::SPMZPi:
    case AVR::WDR: {
      break;
    }
    case AVR::OUTARr: {
      // op: A
      op = encodeImm<AVR::fixup_port6, 0>(MI, 0, Fixups, STI);
      Value |= (op & 0x30) << 5;
      Value |= (op & 0xf);
      // op: rr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      break;
    }
    case AVR::CBIAb:
    case AVR::SBIAb:
    case AVR::SBICAb:
    case AVR::SBISAb: {
      // op: addr
      op = encodeImm<AVR::fixup_port5, 0>(MI, 0, Fixups, STI);
      Value |= (op & 0x1f) << 3;
      // op: b
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case AVR::CALLk:
    case AVR::JMPk: {
      // op: k
      op = encodeCallTarget(MI, 0, Fixups, STI);
      Value |= (op & 0x3e0000) << 3;
      Value |= (op & 0x1ffff);
      break;
    }
    case AVR::RCALLk:
    case AVR::RJMPk: {
      // op: k
      op = encodeRelCondBrTarget<AVR::fixup_13_pcrel>(MI, 0, Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case AVR::BREQk:
    case AVR::BRGEk:
    case AVR::BRLOk:
    case AVR::BRLTk:
    case AVR::BRMIk:
    case AVR::BRNEk:
    case AVR::BRPLk:
    case AVR::BRSHk: {
      // op: k
      op = encodeRelCondBrTarget<AVR::fixup_7_pcrel>(MI, 0, Fixups, STI);
      Value |= (op & 0x7f) << 3;
      break;
    }
    case AVR::BRBCsk:
    case AVR::BRBSsk: {
      // op: k
      op = encodeRelCondBrTarget<AVR::fixup_7_pcrel>(MI, 1, Fixups, STI);
      Value |= (op & 0x7f) << 3;
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case AVR::DESK: {
      // op: k
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case AVR::STDPtrQRr: {
      // op: memri
      op = encodeMemri(MI, 0, Fixups, STI);
      Value |= (op & 0x20) << 8;
      Value |= (op & 0x18) << 7;
      Value |= (op & 0x40) >> 3;
      Value |= (op & 0x7);
      // op: reg
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      break;
    }
    case AVR::LDDRdPtrQ: {
      // op: memri
      op = encodeMemri(MI, 1, Fixups, STI);
      Value |= (op & 0x20) << 8;
      Value |= (op & 0x18) << 7;
      Value |= (op & 0x40) >> 3;
      Value |= (op & 0x7);
      // op: reg
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      break;
    }
    case AVR::LDSRdK: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 20;
      // op: k
      op = encodeImm<AVR::fixup_16, 2>(MI, 1, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case AVR::ASRRd:
    case AVR::COMRd:
    case AVR::DECRd:
    case AVR::ELPMRdZ:
    case AVR::ELPMRdZPi:
    case AVR::INCRd:
    case AVR::LACZRd:
    case AVR::LASZRd:
    case AVR::LATZRd:
    case AVR::LPMRdZ:
    case AVR::LPMRdZPi:
    case AVR::LSRRd:
    case AVR::NEGRd:
    case AVR::POPRd:
    case AVR::PUSHRr:
    case AVR::RORRd:
    case AVR::SWAPRd:
    case AVR::XCHZRd: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      break;
    }
    case AVR::INRdA: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      // op: A
      op = encodeImm<AVR::fixup_port6, 0>(MI, 1, Fixups, STI);
      Value |= (op & 0x30) << 5;
      Value |= (op & 0xf);
      break;
    }
    case AVR::BST:
    case AVR::SBRCRrB:
    case AVR::SBRSRrB: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      // op: b
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case AVR::BLD: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      // op: b
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case AVR::CPCRdRr:
    case AVR::CPRdRr:
    case AVR::CPSE:
    case AVR::MOVRdRr:
    case AVR::MULRdRr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      // op: rr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x10) << 5;
      Value |= (op & 0xf);
      break;
    }
    case AVR::ADCRdRr:
    case AVR::ADDRdRr:
    case AVR::ANDRdRr:
    case AVR::EORRdRr:
    case AVR::ORRdRr:
    case AVR::SBCRdRr:
    case AVR::SUBRdRr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      // op: rr
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x10) << 5;
      Value |= (op & 0xf);
      break;
    }
    case AVR::ADIWRdK:
    case AVR::SBIWRdK: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 4;
      // op: k
      op = encodeImm<AVR::fixup_6_adiw, 0>(MI, 2, Fixups, STI);
      Value |= (op & 0x30) << 2;
      Value |= (op & 0xf);
      break;
    }
    case AVR::FMUL:
    case AVR::FMULS:
    case AVR::FMULSU:
    case AVR::MULSURdRr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 4;
      // op: rr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case AVR::CPIRdK:
    case AVR::LDIRdK: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: k
      op = encodeImm<AVR::fixup_ldi, 0>(MI, 1, Fixups, STI);
      Value |= (op & 0xf0) << 4;
      Value |= (op & 0xf);
      break;
    }
    case AVR::ANDIRdK:
    case AVR::ORIRdK:
    case AVR::SBCIRdK:
    case AVR::SUBIRdK: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: k
      op = encodeImm<AVR::fixup_ldi, 0>(MI, 2, Fixups, STI);
      Value |= (op & 0xf0) << 4;
      Value |= (op & 0xf);
      break;
    }
    case AVR::LDSRdKTiny: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: k
      op = encodeImm<AVR::fixup_lds_sts_16, 0>(MI, 1, Fixups, STI);
      Value |= (op & 0x70) << 4;
      Value |= (op & 0xf);
      break;
    }
    case AVR::MOVWRdRr:
    case AVR::MULSRdRr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: rr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case AVR::STSKRr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 20;
      // op: k
      op = encodeImm<AVR::fixup_16, 2>(MI, 0, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case AVR::STSKRrTiny: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: k
      op = encodeImm<AVR::fixup_lds_sts_16, 0>(MI, 0, Fixups, STI);
      Value |= (op & 0x70) << 4;
      Value |= (op & 0xf);
      break;
    }
    case AVR::LDRdPtr:
    case AVR::LDRdPtrPd:
    case AVR::LDRdPtrPi: {
      // op: reg
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      Value = loadStorePostEncoder(MI, Value, STI);
      break;
    }
    case AVR::STPtrRr: {
      // op: reg
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      Value = loadStorePostEncoder(MI, Value, STI);
      break;
    }
    case AVR::STPtrPdRr:
    case AVR::STPtrPiRr: {
      // op: reg
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 4;
      Value = loadStorePostEncoder(MI, Value, STI);
      break;
    }
    case AVR::BCLRs:
    case AVR::BSETs: {
      // op: s
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 4;
      break;
    }
  default:
    reportUnsupportedInst(MI);
  }
  return Value;
}

#ifdef GET_OPERAND_BIT_OFFSET
#undef GET_OPERAND_BIT_OFFSET

uint32_t AVRMCCodeEmitter::getOperandBitOffset(const MCInst &MI,
    unsigned OpNum,
    const MCSubtargetInfo &STI) const {
  switch (MI.getOpcode()) {
    case AVR::BREAK:
    case AVR::EICALL:
    case AVR::EIJMP:
    case AVR::ELPM:
    case AVR::ICALL:
    case AVR::IJMP:
    case AVR::LPM:
    case AVR::NOP:
    case AVR::RET:
    case AVR::RETI:
    case AVR::SLEEP:
    case AVR::SPM:
    case AVR::SPMZPi:
    case AVR::WDR: {
      break;
    }
    case AVR::OUTARr: {
      switch (OpNum) {
      case 0:
        // op: A
        return 0;
      case 1:
        // op: rr
        return 4;
      }
      break;
    }
    case AVR::CBIAb:
    case AVR::SBIAb:
    case AVR::SBICAb:
    case AVR::SBISAb: {
      switch (OpNum) {
      case 0:
        // op: addr
        return 3;
      case 1:
        // op: b
        return 0;
      }
      break;
    }
    case AVR::CALLk:
    case AVR::JMPk:
    case AVR::RCALLk:
    case AVR::RJMPk: {
      switch (OpNum) {
      case 0:
        // op: k
        return 0;
      }
      break;
    }
    case AVR::BREQk:
    case AVR::BRGEk:
    case AVR::BRLOk:
    case AVR::BRLTk:
    case AVR::BRMIk:
    case AVR::BRNEk:
    case AVR::BRPLk:
    case AVR::BRSHk: {
      switch (OpNum) {
      case 0:
        // op: k
        return 3;
      }
      break;
    }
    case AVR::DESK: {
      switch (OpNum) {
      case 0:
        // op: k
        return 4;
      }
      break;
    }
    case AVR::STDPtrQRr: {
      switch (OpNum) {
      case 0:
        // op: memri
        return 0;
      case 2:
        // op: reg
        return 4;
      }
      break;
    }
    case AVR::LDSRdK: {
      switch (OpNum) {
      case 0:
        // op: rd
        return 20;
      case 1:
        // op: k
        return 0;
      }
      break;
    }
    case AVR::INRdA: {
      switch (OpNum) {
      case 0:
        // op: rd
        return 4;
      case 1:
        // op: A
        return 0;
      }
      break;
    }
    case AVR::BST:
    case AVR::SBRCRrB:
    case AVR::SBRSRrB: {
      switch (OpNum) {
      case 0:
        // op: rd
        return 4;
      case 1:
        // op: b
        return 0;
      }
      break;
    }
    case AVR::CPIRdK:
    case AVR::LDIRdK:
    case AVR::LDSRdKTiny: {
      switch (OpNum) {
      case 0:
        // op: rd
        return 4;
      case 1:
        // op: k
        return 0;
      }
      break;
    }
    case AVR::CPCRdRr:
    case AVR::CPRdRr:
    case AVR::CPSE:
    case AVR::FMUL:
    case AVR::FMULS:
    case AVR::FMULSU:
    case AVR::MOVRdRr:
    case AVR::MOVWRdRr:
    case AVR::MULRdRr:
    case AVR::MULSRdRr:
    case AVR::MULSURdRr: {
      switch (OpNum) {
      case 0:
        // op: rd
        return 4;
      case 1:
        // op: rr
        return 0;
      }
      break;
    }
    case AVR::BLD: {
      switch (OpNum) {
      case 0:
        // op: rd
        return 4;
      case 2:
        // op: b
        return 0;
      }
      break;
    }
    case AVR::ADIWRdK:
    case AVR::ANDIRdK:
    case AVR::ORIRdK:
    case AVR::SBCIRdK:
    case AVR::SBIWRdK:
    case AVR::SUBIRdK: {
      switch (OpNum) {
      case 0:
        // op: rd
        return 4;
      case 2:
        // op: k
        return 0;
      }
      break;
    }
    case AVR::ADCRdRr:
    case AVR::ADDRdRr:
    case AVR::ANDRdRr:
    case AVR::EORRdRr:
    case AVR::ORRdRr:
    case AVR::SBCRdRr:
    case AVR::SUBRdRr: {
      switch (OpNum) {
      case 0:
        // op: rd
        return 4;
      case 2:
        // op: rr
        return 0;
      }
      break;
    }
    case AVR::ASRRd:
    case AVR::COMRd:
    case AVR::DECRd:
    case AVR::ELPMRdZ:
    case AVR::ELPMRdZPi:
    case AVR::INCRd:
    case AVR::LACZRd:
    case AVR::LASZRd:
    case AVR::LATZRd:
    case AVR::LPMRdZ:
    case AVR::LPMRdZPi:
    case AVR::LSRRd:
    case AVR::NEGRd:
    case AVR::POPRd:
    case AVR::PUSHRr:
    case AVR::RORRd:
    case AVR::SWAPRd:
    case AVR::XCHZRd: {
      switch (OpNum) {
      case 0:
        // op: rd
        return 4;
      }
      break;
    }
    case AVR::LDRdPtr:
    case AVR::LDRdPtrPd:
    case AVR::LDRdPtrPi: {
      switch (OpNum) {
      case 0:
        // op: reg
        return 4;
      }
      break;
    }
    case AVR::BCLRs:
    case AVR::BSETs: {
      switch (OpNum) {
      case 0:
        // op: s
        return 4;
      }
      break;
    }
    case AVR::BRBCsk:
    case AVR::BRBSsk: {
      switch (OpNum) {
      case 1:
        // op: k
        return 3;
      case 0:
        // op: s
        return 0;
      }
      break;
    }
    case AVR::LDDRdPtrQ: {
      switch (OpNum) {
      case 1:
        // op: memri
        return 0;
      case 0:
        // op: reg
        return 4;
      }
      break;
    }
    case AVR::STSKRr: {
      switch (OpNum) {
      case 1:
        // op: rd
        return 20;
      case 0:
        // op: k
        return 0;
      }
      break;
    }
    case AVR::STSKRrTiny: {
      switch (OpNum) {
      case 1:
        // op: rd
        return 4;
      case 0:
        // op: k
        return 0;
      }
      break;
    }
    case AVR::STPtrRr: {
      switch (OpNum) {
      case 1:
        // op: reg
        return 4;
      }
      break;
    }
    case AVR::STPtrPdRr:
    case AVR::STPtrPiRr: {
      switch (OpNum) {
      case 2:
        // op: reg
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

