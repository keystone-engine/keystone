/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Compress instruction Source Fragment                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: CSKY.td                                                              *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GEN_COMPRESS_INSTR
#undef GEN_COMPRESS_INSTR

static bool CSKYValidateMCOperandForCompress(const MCOperand &MCOp,
                                             const MCSubtargetInfo &STI,
                                             unsigned PredicateIndex) {
  switch (PredicateIndex) {
  default:
    llvm_unreachable("Unknown MCOperandPredicate kind");
    break;
  case 1: {
    // oimm3
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isUInt<3>(Imm - 1);
    return MCOp.isBareSymbolRef();
  }
  case 2: {
    // oimm8
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isUInt<8>(Imm - 1);
    return MCOp.isBareSymbolRef();
  }
  case 3: {
    // uimm7_2
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<7, 2>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 4: {
    // uimm8_2
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<8, 2>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 5: {
    // uimm5
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<5, 0>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 6: {
    // oimm5
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isUInt<5>(Imm - 1);
    return MCOp.isBareSymbolRef();
  }
  case 7: {
    // uimm5_1
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<5, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 8: {
    // uimm5_2
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<5, 2>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 9: {
    // uimm8
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<8, 0>(Imm);
    return MCOp.isBareSymbolRef();
  }
  }
}

static bool compressInst(MCInst &OutInst,
                         const MCInst &MI,
                         const MCSubtargetInfo &STI) {
  switch (MI.getOpcode()) {
  default: return false;
  case CSKY::ADDC32: {
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(1).isReg() &&
        (MI.getOperand(4).getReg() == MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(4).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg()) &&
        MI.getOperand(3).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(3).getReg()) &&
        MI.getOperand(4).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg())) {
      // addc16	$rz, $rx
      OutInst.setOpcode(CSKY::ADDC16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(2));
      // Operand: cout
      OutInst.addOperand(MI.getOperand(4));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(3));
      // Operand: cin
      OutInst.addOperand(MI.getOperand(4));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDC32
  case CSKY::ADDI32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 1 /* oimm3 */)) {
      // addi16	$rz, $rx, $oimm3
      OutInst.setOpcode(CSKY::ADDI16XZ);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: oimm3
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 2 /* oimm8 */)) {
      // addi16	$rz, $imm8
      OutInst.setOpcode(CSKY::ADDI16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm8
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* uimm7_2 */)) {
      // addi16	$sp2, $sp1, $imm7
      OutInst.setOpcode(CSKY::ADDI16SPSP);
      // Operand: sp2
      OutInst.addOperand(MI.getOperand(1));
      // Operand: sp1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm7
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 4 /* uimm8_2 */)) {
      // addi16	$rz, $sp, $imm8
      OutInst.setOpcode(CSKY::ADDI16ZSP);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: sp
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm8
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDI32
  case CSKY::ADDU32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // addu16	$rz, $rx
      OutInst.setOpcode(CSKY::ADDU16XZ);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // addu16	$rz, $rx
      OutInst.setOpcode(CSKY::ADDU16XZ);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // addu16	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::ADDU16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDU32
  case CSKY::AND32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // and16	$rz, $rx
      OutInst.setOpcode(CSKY::AND16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // and16	$rz, $rx
      OutInst.setOpcode(CSKY::AND16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case AND32
  case CSKY::ANDN32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // andn16	$rz, $rx
      OutInst.setOpcode(CSKY::ANDN16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ANDN32
  case CSKY::ASR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // asr16	$rz, $rx
      OutInst.setOpcode(CSKY::ASR16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ASR32
  case CSKY::ASRI32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* uimm5 */)) {
      // asri16	$rz, $rx, $imm5
      OutInst.setOpcode(CSKY::ASRI16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ASRI32
  case CSKY::BCLRI32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* uimm5 */)) {
      // bclri16	$rz, $imm5
      OutInst.setOpcode(CSKY::BCLRI16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BCLRI32
  case CSKY::BSETI32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* uimm5 */)) {
      // bseti16	$rz, $imm5
      OutInst.setOpcode(CSKY::BSETI16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BSETI32
  case CSKY::BTSTI32: {
    if (STI.getFeatureBits()[CSKY::FeatureBTST16] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* uimm5 */)) {
      // btsti16	$rz, $imm5
      OutInst.setOpcode(CSKY::BTSTI16);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BTSTI32
  case CSKY::CMPHS32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // cmphs16	$rx, $ry
      OutInst.setOpcode(CSKY::CMPHS16);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPHS32
  case CSKY::CMPHSI32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 6 /* oimm5 */)) {
      // cmphsi16	$rx, $imm5
      OutInst.setOpcode(CSKY::CMPHSI16);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPHSI32
  case CSKY::CMPLT32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // cmplt16	$rx, $ry
      OutInst.setOpcode(CSKY::CMPLT16);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPLT32
  case CSKY::CMPLTI32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 6 /* oimm5 */)) {
      // cmplti16	$rx, $imm5
      OutInst.setOpcode(CSKY::CMPLTI16);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPLTI32
  case CSKY::CMPNE32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // cmpne16	$rx, $ry
      OutInst.setOpcode(CSKY::CMPNE16);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPNE32
  case CSKY::CMPNEI32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* uimm5 */)) {
      // cmpnei16	$rx, $imm5
      OutInst.setOpcode(CSKY::CMPNEI16);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPNEI32
  case CSKY::JSR32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg())) {
      // jsr16	$rx
      OutInst.setOpcode(CSKY::JSR16);
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case JSR32
  case CSKY::LD32B: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* uimm5 */)) {
      // ld16.b	$rz, ($rx, ${imm})
      OutInst.setOpcode(CSKY::LD16B);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LD32B
  case CSKY::LD32H: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 7 /* uimm5_1 */)) {
      // ld16.h	$rz, ($rx, ${imm})
      OutInst.setOpcode(CSKY::LD16H);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LD32H
  case CSKY::LD32W: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 8 /* uimm5_2 */)) {
      // ld16.w	$rz, ($rx, ${imm})
      OutInst.setOpcode(CSKY::LD16W);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 4 /* uimm8_2 */)) {
      // ld16.w	$rz, ($sp, ${addr})
      OutInst.setOpcode(CSKY::LD16WSP);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: sp
      OutInst.addOperand(MI.getOperand(1));
      // Operand: addr
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LD32W
  case CSKY::LSL32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // lsl16	$rz, $rx
      OutInst.setOpcode(CSKY::LSL16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LSL32
  case CSKY::LSLI32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* uimm5 */)) {
      // lsli16	$rz, $rx, $imm5
      OutInst.setOpcode(CSKY::LSLI16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LSLI32
  case CSKY::LSR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // lsr16	$rz, $rx
      OutInst.setOpcode(CSKY::LSR16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LSR32
  case CSKY::LSRI32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* uimm5 */)) {
      // lsri16	$rz, $rx, $imm5
      OutInst.setOpcode(CSKY::LSRI16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LSRI32
  case CSKY::MOV32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // mov16	$rz, $rx
      OutInst.setOpcode(CSKY::MOV16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case MOV32
  case CSKY::MOVI32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(1), STI, 9 /* uimm8 */)) {
      // movi16	$rz, $imm8
      OutInst.setOpcode(CSKY::MOVI16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm8
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case MOVI32
  case CSKY::MULT32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // mult16	$rz, $rx
      OutInst.setOpcode(CSKY::MULT16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // mult16	$rz, $rx
      OutInst.setOpcode(CSKY::MULT16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case MULT32
  case CSKY::MVCV32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(1).getReg())) {
      // mvcv16	$rz
      OutInst.setOpcode(CSKY::MVCV16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ca
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case MVCV32
  case CSKY::NOR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // nor16	$rz, $rx
      OutInst.setOpcode(CSKY::NOR16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case NOR32
  case CSKY::NOT32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // not16	$rz
      OutInst.setOpcode(CSKY::NOT16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case NOT32
  case CSKY::OR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // or16	$rz, $rx
      OutInst.setOpcode(CSKY::OR16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // or16	$rz, $rx
      OutInst.setOpcode(CSKY::OR16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case OR32
  case CSKY::REVB32: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // revb16	$rz, $rx
      OutInst.setOpcode(CSKY::REVB16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case REVB32
  case CSKY::ROTL32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // rotl16	$rz, $rx
      OutInst.setOpcode(CSKY::ROTL16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ROTL32
  case CSKY::SEXTB32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // sextb16	$rz, $rx
      OutInst.setOpcode(CSKY::SEXTB16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SEXTB32
  case CSKY::SEXTH32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // sexth16	$rz, $rx
      OutInst.setOpcode(CSKY::SEXTH16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SEXTH32
  case CSKY::ST32B: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* uimm5 */)) {
      // st16.b	$rz, ($rx, ${imm})
      OutInst.setOpcode(CSKY::ST16B);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ST32B
  case CSKY::ST32H: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 7 /* uimm5_1 */)) {
      // st16.h	$rz, ($rx, ${imm})
      OutInst.setOpcode(CSKY::ST16H);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ST32H
  case CSKY::ST32W: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 8 /* uimm5_2 */)) {
      // st16.w	$rz, ($rx, ${imm})
      OutInst.setOpcode(CSKY::ST16W);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 4 /* uimm8_2 */)) {
      // st16.w	$rz, ($sp, ${addr})
      OutInst.setOpcode(CSKY::ST16WSP);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: sp
      OutInst.addOperand(MI.getOperand(1));
      // Operand: addr
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ST32W
  case CSKY::SUBC32: {
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(1).isReg() &&
        (MI.getOperand(4).getReg() == MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(4).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg()) &&
        MI.getOperand(3).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(3).getReg()) &&
        MI.getOperand(4).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg())) {
      // subc16	$rz, $rx
      OutInst.setOpcode(CSKY::SUBC16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(2));
      // Operand: cout
      OutInst.addOperand(MI.getOperand(4));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(3));
      // Operand: cin
      OutInst.addOperand(MI.getOperand(4));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBC32
  case CSKY::SUBI32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 1 /* oimm3 */)) {
      // subi16	$rz, $rx, $oimm3
      OutInst.setOpcode(CSKY::SUBI16XZ);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: oimm3
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 2 /* oimm8 */)) {
      // subi16	$rz, $imm8
      OutInst.setOpcode(CSKY::SUBI16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm8
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* uimm7_2 */)) {
      // subi16	$sp2, $sp1, $imm7
      OutInst.setOpcode(CSKY::SUBI16SPSP);
      // Operand: sp2
      OutInst.addOperand(MI.getOperand(1));
      // Operand: sp1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm7
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBI32
  case CSKY::SUBU32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // subu16	$rz, $rx
      OutInst.setOpcode(CSKY::SUBU16XZ);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // subu16	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::SUBU16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBU32
  case CSKY::XOR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // xor16	$rz, $rx
      OutInst.setOpcode(CSKY::XOR16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // xor16	$rz, $rx
      OutInst.setOpcode(CSKY::XOR16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rZ
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case XOR32
  case CSKY::ZEXTB32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // zextb16	$rz, $rx
      OutInst.setOpcode(CSKY::ZEXTB16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ZEXTB32
  case CSKY::ZEXTH32: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // zexth16	$rz, $rx
      OutInst.setOpcode(CSKY::ZEXTH16);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ZEXTH32
  } // switch
  return false;
}

#endif // GEN_COMPRESS_INSTR

#ifdef GEN_UNCOMPRESS_INSTR
#undef GEN_UNCOMPRESS_INSTR

static bool CSKYValidateMCOperandForUncompress(const MCOperand &MCOp,
                                               const MCSubtargetInfo &STI,
                                               unsigned PredicateIndex) {
  switch (PredicateIndex) {
  default:
    llvm_unreachable("Unknown MCOperandPredicate kind");
    break;
  case 1: {
    // oimm8
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isUInt<8>(Imm - 1);
    return MCOp.isBareSymbolRef();
  }
  case 2: {
    // oimm12
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isUInt<12>(Imm - 1);
    return MCOp.isBareSymbolRef();
  }
  case 3: {
    // uimm7_2
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<7, 2>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 4: {
    // oimm3
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isUInt<3>(Imm - 1);
    return MCOp.isBareSymbolRef();
  }
  case 5: {
    // uimm8_2
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<8, 2>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 6: {
    // uimm5
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<5, 0>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 7: {
    // oimm5
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isUInt<5>(Imm - 1);
    return MCOp.isBareSymbolRef();
  }
  case 8: {
    // oimm16
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isUInt<16>(Imm - 1);
    return MCOp.isBareSymbolRef();
  }
  case 9: {
    // uimm16
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<16, 0>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 10: {
    // uimm12
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<12, 0>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 11: {
    // uimm5_1
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<5, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 12: {
    // uimm12_1
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<12, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 13: {
    // uimm5_2
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<5, 2>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 14: {
    // uimm12_2
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<12, 2>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 15: {
    // uimm8
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedUInt<8, 0>(Imm);
    return MCOp.isBareSymbolRef();
  }
  }
}

static bool uncompressInst(MCInst &OutInst,
                           const MCInst &MI,
                           const MCSubtargetInfo &STI) {
  switch (MI.getOpcode()) {
  default: return false;
  case CSKY::ADDC16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(3).getReg()) &&
        MI.getOperand(4).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg())) {
      // addc32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::ADDC32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: cout
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(3));
      // Operand: cin
      OutInst.addOperand(MI.getOperand(4));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDC16
  case CSKY::ADDI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 1 /* oimm8 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* oimm12 */)) {
      // addi32	$rz, $rx, $imm12
      OutInst.setOpcode(CSKY::ADDI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDI16
  case CSKY::ADDI16SPSP: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 3 /* uimm7_2 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* oimm12 */)) {
      // addi32	$rz, $rx, $imm12
      OutInst.setOpcode(CSKY::ADDI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDI16SPSP
  case CSKY::ADDI16XZ: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 4 /* oimm3 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* oimm12 */)) {
      // addi32	$rz, $rx, $imm12
      OutInst.setOpcode(CSKY::ADDI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDI16XZ
  case CSKY::ADDI16ZSP: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 5 /* uimm8_2 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* oimm12 */)) {
      // addi32	$rz, $rx, $imm12
      OutInst.setOpcode(CSKY::ADDI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDI16ZSP
  case CSKY::ADDU16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // addu32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::ADDU32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDU16
  case CSKY::ADDU16XZ: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // addu32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::ADDU32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg())) {
      // addu32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::ADDU32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDU16XZ
  case CSKY::AND16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // and32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::AND32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg())) {
      // and32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::AND32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case AND16
  case CSKY::ANDN16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // andn32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::ANDN32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ANDN16
  case CSKY::ASR16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // asr32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::ASR32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ASR16
  case CSKY::ASRI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 6 /* uimm5 */)) {
      // asri32	$rz, $rx, $imm5
      OutInst.setOpcode(CSKY::ASRI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ASRI16
  case CSKY::BCLRI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 6 /* uimm5 */)) {
      // bclri32	$rz, $rx, $imm5
      OutInst.setOpcode(CSKY::BCLRI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BCLRI16
  case CSKY::BSETI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 6 /* uimm5 */)) {
      // bseti32	$rz, $rx, $imm5
      OutInst.setOpcode(CSKY::BSETI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BSETI16
  case CSKY::BTSTI16: {
    if (STI.getFeatureBits()[CSKY::FeatureBTST16] &&
        STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 6 /* uimm5 */)) {
      // btsti32	$rx, $imm5
      OutInst.setOpcode(CSKY::BTSTI32);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BTSTI16
  case CSKY::CMPHS16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // cmphs32	$rx, $ry
      OutInst.setOpcode(CSKY::CMPHS32);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPHS16
  case CSKY::CMPHSI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 7 /* oimm5 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 8 /* oimm16 */)) {
      // cmphsi32	$rx, $imm16
      OutInst.setOpcode(CSKY::CMPHSI32);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm16
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPHSI16
  case CSKY::CMPLT16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // cmplt32	$rx, $ry
      OutInst.setOpcode(CSKY::CMPLT32);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPLT16
  case CSKY::CMPLTI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 7 /* oimm5 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 8 /* oimm16 */)) {
      // cmplti32	$rx, $imm16
      OutInst.setOpcode(CSKY::CMPLTI32);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm16
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPLTI16
  case CSKY::CMPNE16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // cmpne32	$rx, $ry
      OutInst.setOpcode(CSKY::CMPNE32);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPNE16
  case CSKY::CMPNEI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 6 /* uimm5 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 9 /* uimm16 */)) {
      // cmpnei32	$rx, $imm16
      OutInst.setOpcode(CSKY::CMPNEI32);
      // Operand: ca
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm16
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case CMPNEI16
  case CSKY::JSR16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg())) {
      // jsr32	$rx
      OutInst.setOpcode(CSKY::JSR32);
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case JSR16
  case CSKY::LD16B: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 6 /* uimm5 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 10 /* uimm12 */)) {
      // ld32.b	$rz, ($rx, ${imm12})
      OutInst.setOpcode(CSKY::LD32B);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LD16B
  case CSKY::LD16H: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 11 /* uimm5_1 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 12 /* uimm12_1 */)) {
      // ld32.h	$rz, ($rx, ${imm12})
      OutInst.setOpcode(CSKY::LD32H);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LD16H
  case CSKY::LD16W: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 13 /* uimm5_2 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 14 /* uimm12_2 */)) {
      // ld32.w	$rz, ($rx, ${imm12})
      OutInst.setOpcode(CSKY::LD32W);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LD16W
  case CSKY::LD16WSP: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 5 /* uimm8_2 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 14 /* uimm12_2 */)) {
      // ld32.w	$rz, ($rx, ${imm12})
      OutInst.setOpcode(CSKY::LD32W);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LD16WSP
  case CSKY::LSL16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // lsl32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::LSL32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LSL16
  case CSKY::LSLI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 6 /* uimm5 */)) {
      // lsli32	$rz, $rx, $imm5
      OutInst.setOpcode(CSKY::LSLI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LSLI16
  case CSKY::LSR16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // lsr32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::LSR32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LSR16
  case CSKY::LSRI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 6 /* uimm5 */)) {
      // lsri32	$rz, $rx, $imm5
      OutInst.setOpcode(CSKY::LSRI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LSRI16
  case CSKY::MOV16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // mov32	$rz, $rx
      OutInst.setOpcode(CSKY::MOV32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case MOV16
  case CSKY::MOVI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(1), STI, 15 /* uimm8 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(1), STI, 9 /* uimm16 */)) {
      // movi32	$rz, $imm16
      OutInst.setOpcode(CSKY::MOVI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm16
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case MOVI16
  case CSKY::MULT16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // mult32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::MULT32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg())) {
      // mult32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::MULT32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case MULT16
  case CSKY::MVCV16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(1).getReg())) {
      // mvcv32	$rz
      OutInst.setOpcode(CSKY::MVCV32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ca
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case MVCV16
  case CSKY::NOR16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // nor32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::NOR32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case NOR16
  case CSKY::NOT16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg())) {
      // not32	$rz, $rx
      OutInst.setOpcode(CSKY::NOT32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case NOT16
  case CSKY::OR16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // or32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::OR32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg())) {
      // or32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::OR32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case OR16
  case CSKY::REVB16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // revb32	$rz, $rx
      OutInst.setOpcode(CSKY::REVB32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case REVB16
  case CSKY::ROTL16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // rotl32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::ROTL32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ROTL16
  case CSKY::SEXTB16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // sextb32	$rz, $rx
      OutInst.setOpcode(CSKY::SEXTB32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SEXTB16
  case CSKY::SEXTH16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // sexth32	$rz, $rx
      OutInst.setOpcode(CSKY::SEXTH32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SEXTH16
  case CSKY::ST16B: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 6 /* uimm5 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 10 /* uimm12 */)) {
      // st32.b	$rz, ($rx, ${imm12})
      OutInst.setOpcode(CSKY::ST32B);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ST16B
  case CSKY::ST16H: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 11 /* uimm5_1 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 12 /* uimm12_1 */)) {
      // st32.h	$rz, ($rx, ${imm12})
      OutInst.setOpcode(CSKY::ST32H);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ST16H
  case CSKY::ST16W: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 13 /* uimm5_2 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 14 /* uimm12_2 */)) {
      // st32.w	$rz, ($rx, ${imm12})
      OutInst.setOpcode(CSKY::ST32W);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ST16W
  case CSKY::ST16WSP: {
    if (MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 5 /* uimm8_2 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 14 /* uimm12_2 */)) {
      // st32.w	$rz, ($rx, ${imm12})
      OutInst.setOpcode(CSKY::ST32W);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ST16WSP
  case CSKY::SUBC16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(3).getReg()) &&
        MI.getOperand(4).isReg() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg())) {
      // subc32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::SUBC32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: cout
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(3));
      // Operand: cin
      OutInst.addOperand(MI.getOperand(4));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBC16
  case CSKY::SUBI16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 1 /* oimm8 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* oimm12 */)) {
      // subi32	$rz, $rx, $imm12
      OutInst.setOpcode(CSKY::SUBI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBI16
  case CSKY::SUBI16SPSP: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 3 /* uimm7_2 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* oimm12 */)) {
      // subi32	$rz, $rx, $imm12
      OutInst.setOpcode(CSKY::SUBI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBI16SPSP
  case CSKY::SUBI16XZ: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 4 /* oimm3 */) &&
        CSKYValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* oimm12 */)) {
      // subi32	$rz, $rx, $imm12
      OutInst.setOpcode(CSKY::SUBI32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBI16XZ
  case CSKY::SUBU16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // subu32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::SUBU32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBU16
  case CSKY::SUBU16XZ: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // subu32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::SUBU32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBU16XZ
  case CSKY::XOR16: {
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // xor32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::XOR32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(0));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[CSKY::HasE2] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg())) {
      // xor32	$rz, $rx, $ry
      OutInst.setOpcode(CSKY::XOR32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(2));
      // Operand: ry
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case XOR16
  case CSKY::ZEXTB16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // zextb32	$rz, $rx
      OutInst.setOpcode(CSKY::ZEXTB32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ZEXTB16
  case CSKY::ZEXTH16: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // zexth32	$rz, $rx
      OutInst.setOpcode(CSKY::ZEXTH32);
      // Operand: rz
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rx
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ZEXTH16
  } // switch
  return false;
}

#endif // GEN_UNCOMPRESS_INSTR

#ifdef GEN_CHECK_COMPRESS_INSTR
#undef GEN_CHECK_COMPRESS_INSTR

static bool CSKYValidateMachineOperand(const MachineOperand &MO,
                                       const CSKYSubtarget *Subtarget,
                                       unsigned PredicateIndex) {
  int64_t Imm = MO.getImm();
  switch (PredicateIndex) {
  default:
    llvm_unreachable("Unknown ImmLeaf Predicate kind");
    break;
  case 1: {
    // oimm8
    return isUInt<8>(Imm - 1);
  }
  case 2: {
    // uimm7_2
    return isShiftedUInt<7, 2>(Imm);
  }
  case 3: {
    // oimm3
    return isUInt<3>(Imm - 1);
  }
  case 4: {
    // uimm8_2
    return isShiftedUInt<8, 2>(Imm);
  }
  case 5: {
    // uimm5
    return isShiftedUInt<5, 0>(Imm);
  }
  case 6: {
    // oimm5
    return isUInt<5>(Imm - 1);
  }
  case 7: {
    // uimm5_1
    return isShiftedUInt<5, 1>(Imm);
  }
  case 8: {
    // uimm5_2
    return isShiftedUInt<5, 2>(Imm);
  }
  case 9: {
    // uimm8
    return isShiftedUInt<8, 0>(Imm);
  }
  }
}

static bool isCompressibleInst(const MachineInstr &MI,
                               const CSKYSubtarget &STI) {
  switch (MI.getOpcode()) {
  default: return false;
  case CSKY::ADDC32: {
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(1).isReg() &&
        (MI.getOperand(4).getReg() == MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(4).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg()) &&
        MI.getOperand(3).isReg() && MI.getOperand(3).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(3).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(4).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg())) {
      // addc16	$rz, $rx
      // Operand: rz
      // Operand: cout
      // Operand: rZ
      // Operand: rx
      // Operand: cin
      return true;
    } // if
    break;
  } // case ADDC32
  case CSKY::ADDI32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 1 /* oimm8 */)) {
      // addi16	$rz, $imm8
      // Operand: rz
      // Operand: rZ
      // Operand: imm8
      return true;
    } // if
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 2 /* uimm7_2 */)) {
      // addi16	$sp2, $sp1, $imm7
      // Operand: sp2
      // Operand: sp1
      // Operand: imm7
      return true;
    } // if
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 3 /* oimm3 */)) {
      // addi16	$rz, $rx, $oimm3
      // Operand: rz
      // Operand: rx
      // Operand: oimm3
      return true;
    } // if
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 4 /* uimm8_2 */)) {
      // addi16	$rz, $sp, $imm8
      // Operand: rz
      // Operand: sp
      // Operand: imm8
      return true;
    } // if
    break;
  } // case ADDI32
  case CSKY::ADDU32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // addu16	$rz, $rx, $ry
      // Operand: rz
      // Operand: rx
      // Operand: ry
      return true;
    } // if
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // addu16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // addu16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case ADDU32
  case CSKY::AND32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // and16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // and16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case AND32
  case CSKY::ANDN32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // andn16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case ANDN32
  case CSKY::ASR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // asr16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case ASR32
  case CSKY::ASRI32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 5 /* uimm5 */)) {
      // asri16	$rz, $rx, $imm5
      // Operand: rz
      // Operand: rx
      // Operand: imm5
      return true;
    } // if
    break;
  } // case ASRI32
  case CSKY::BCLRI32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 5 /* uimm5 */)) {
      // bclri16	$rz, $imm5
      // Operand: rz
      // Operand: rZ
      // Operand: imm5
      return true;
    } // if
    break;
  } // case BCLRI32
  case CSKY::BSETI32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 5 /* uimm5 */)) {
      // bseti16	$rz, $imm5
      // Operand: rz
      // Operand: rZ
      // Operand: imm5
      return true;
    } // if
    break;
  } // case BSETI32
  case CSKY::BTSTI32: {
    if (STI.getFeatureBits()[CSKY::FeatureBTST16] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 5 /* uimm5 */)) {
      // btsti16	$rz, $imm5
      // Operand: ca
      // Operand: rz
      // Operand: imm5
      return true;
    } // if
    break;
  } // case BTSTI32
  case CSKY::CMPHS32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // cmphs16	$rx, $ry
      // Operand: ca
      // Operand: rx
      // Operand: ry
      return true;
    } // if
    break;
  } // case CMPHS32
  case CSKY::CMPHSI32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 6 /* oimm5 */)) {
      // cmphsi16	$rx, $imm5
      // Operand: ca
      // Operand: rx
      // Operand: imm5
      return true;
    } // if
    break;
  } // case CMPHSI32
  case CSKY::CMPLT32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // cmplt16	$rx, $ry
      // Operand: ca
      // Operand: rx
      // Operand: ry
      return true;
    } // if
    break;
  } // case CMPLT32
  case CSKY::CMPLTI32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 6 /* oimm5 */)) {
      // cmplti16	$rx, $imm5
      // Operand: ca
      // Operand: rx
      // Operand: imm5
      return true;
    } // if
    break;
  } // case CMPLTI32
  case CSKY::CMPNE32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // cmpne16	$rx, $ry
      // Operand: ca
      // Operand: rx
      // Operand: ry
      return true;
    } // if
    break;
  } // case CMPNE32
  case CSKY::CMPNEI32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 5 /* uimm5 */)) {
      // cmpnei16	$rx, $imm5
      // Operand: ca
      // Operand: rx
      // Operand: imm5
      return true;
    } // if
    break;
  } // case CMPNEI32
  case CSKY::JSR32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg())) {
      // jsr16	$rx
      // Operand: rx
      return true;
    } // if
    break;
  } // case JSR32
  case CSKY::LD32B: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 5 /* uimm5 */)) {
      // ld16.b	$rz, ($rx, ${imm})
      // Operand: rz
      // Operand: rx
      // Operand: imm
      return true;
    } // if
    break;
  } // case LD32B
  case CSKY::LD32H: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 7 /* uimm5_1 */)) {
      // ld16.h	$rz, ($rx, ${imm})
      // Operand: rz
      // Operand: rx
      // Operand: imm
      return true;
    } // if
    break;
  } // case LD32H
  case CSKY::LD32W: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 8 /* uimm5_2 */)) {
      // ld16.w	$rz, ($rx, ${imm})
      // Operand: rz
      // Operand: rx
      // Operand: imm
      return true;
    } // if
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 4 /* uimm8_2 */)) {
      // ld16.w	$rz, ($sp, ${addr})
      // Operand: rz
      // Operand: sp
      // Operand: addr
      return true;
    } // if
    break;
  } // case LD32W
  case CSKY::LSL32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // lsl16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case LSL32
  case CSKY::LSLI32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 5 /* uimm5 */)) {
      // lsli16	$rz, $rx, $imm5
      // Operand: rz
      // Operand: rx
      // Operand: imm5
      return true;
    } // if
    break;
  } // case LSLI32
  case CSKY::LSR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // lsr16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case LSR32
  case CSKY::LSRI32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 5 /* uimm5 */)) {
      // lsri16	$rz, $rx, $imm5
      // Operand: rz
      // Operand: rx
      // Operand: imm5
      return true;
    } // if
    break;
  } // case LSRI32
  case CSKY::MOV32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // mov16	$rz, $rx
      // Operand: rz
      // Operand: rx
      return true;
    } // if
    break;
  } // case MOV32
  case CSKY::MOVI32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(1), &STI, 9 /* uimm8 */)) {
      // movi16	$rz, $imm8
      // Operand: rz
      // Operand: imm8
      return true;
    } // if
    break;
  } // case MOVI32
  case CSKY::MULT32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // mult16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // mult16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case MULT32
  case CSKY::MVCV32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(1).getReg())) {
      // mvcv16	$rz
      // Operand: rz
      // Operand: ca
      return true;
    } // if
    break;
  } // case MVCV32
  case CSKY::NOR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // nor16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case NOR32
  case CSKY::NOT32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // not16	$rz
      // Operand: rz
      // Operand: rx
      return true;
    } // if
    break;
  } // case NOT32
  case CSKY::OR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // or16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // or16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case OR32
  case CSKY::REVB32: {
    if (STI.getFeatureBits()[CSKY::Has2E3] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // revb16	$rz, $rx
      // Operand: rz
      // Operand: rx
      return true;
    } // if
    break;
  } // case REVB32
  case CSKY::ROTL32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // rotl16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case ROTL32
  case CSKY::SEXTB32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // sextb16	$rz, $rx
      // Operand: rz
      // Operand: rx
      return true;
    } // if
    break;
  } // case SEXTB32
  case CSKY::SEXTH32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // sexth16	$rz, $rx
      // Operand: rz
      // Operand: rx
      return true;
    } // if
    break;
  } // case SEXTH32
  case CSKY::ST32B: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 5 /* uimm5 */)) {
      // st16.b	$rz, ($rx, ${imm})
      // Operand: rz
      // Operand: rx
      // Operand: imm
      return true;
    } // if
    break;
  } // case ST32B
  case CSKY::ST32H: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 7 /* uimm5_1 */)) {
      // st16.h	$rz, ($rx, ${imm})
      // Operand: rz
      // Operand: rx
      // Operand: imm
      return true;
    } // if
    break;
  } // case ST32H
  case CSKY::ST32W: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 8 /* uimm5_2 */)) {
      // st16.w	$rz, ($rx, ${imm})
      // Operand: rz
      // Operand: rx
      // Operand: imm
      return true;
    } // if
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 4 /* uimm8_2 */)) {
      // st16.w	$rz, ($sp, ${addr})
      // Operand: rz
      // Operand: sp
      // Operand: addr
      return true;
    } // if
    break;
  } // case ST32W
  case CSKY::SUBC32: {
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(1).isReg() &&
        (MI.getOperand(4).getReg() == MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(4).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg()) &&
        MI.getOperand(3).isReg() && MI.getOperand(3).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(3).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(4).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::CARRYRegClassID).contains(MI.getOperand(4).getReg())) {
      // subc16	$rz, $rx
      // Operand: rz
      // Operand: cout
      // Operand: rZ
      // Operand: rx
      // Operand: cin
      return true;
    } // if
    break;
  } // case SUBC32
  case CSKY::SUBI32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 1 /* oimm8 */)) {
      // subi16	$rz, $imm8
      // Operand: rz
      // Operand: rZ
      // Operand: imm8
      return true;
    } // if
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::GPRSPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 2 /* uimm7_2 */)) {
      // subi16	$sp2, $sp1, $imm7
      // Operand: sp2
      // Operand: sp1
      // Operand: imm7
      return true;
    } // if
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        CSKYValidateMachineOperand(MI.getOperand(2), &STI, 3 /* oimm3 */)) {
      // subi16	$rz, $rx, $oimm3
      // Operand: rz
      // Operand: rx
      // Operand: oimm3
      return true;
    } // if
    break;
  } // case SUBI32
  case CSKY::SUBU32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::mGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // subu16	$rz, $rx, $ry
      // Operand: rz
      // Operand: rx
      // Operand: ry
      return true;
    } // if
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // subu16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case SUBU32
  case CSKY::XOR32: {
    if (MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg())) {
      // xor16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    if (MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // xor16	$rz, $rx
      // Operand: rz
      // Operand: rZ
      // Operand: rx
      return true;
    } // if
    break;
  } // case XOR32
  case CSKY::ZEXTB32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // zextb16	$rz, $rx
      // Operand: rz
      // Operand: rx
      return true;
    } // if
    break;
  } // case ZEXTB32
  case CSKY::ZEXTH32: {
    if (MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getCSKYMCRegisterClass(CSKY::sGPRRegClassID).contains(MI.getOperand(1).getReg())) {
      // zexth16	$rz, $rx
      // Operand: rz
      // Operand: rx
      return true;
    } // if
    break;
  } // case ZEXTH32
  } // switch
  return false;
}

#endif // GEN_CHECK_COMPRESS_INSTR

