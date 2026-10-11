/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Compress instruction Source Fragment                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: RISCV.td                                                             *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GEN_COMPRESS_INSTR
#undef GEN_COMPRESS_INSTR

static bool RISCVValidateMCOperandForCompress(const MCOperand &MCOp,
                                              const MCSubtargetInfo &STI,
                                              unsigned PredicateIndex) {
  switch (PredicateIndex) {
  default:
    llvm_unreachable("Unknown MCOperandPredicate kind");
    break;
  case 1: {
    // uimm10_lsb00nonzero
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<8, 2>(Imm) && (Imm != 0);
  }
  case 2: {
    // simm6nonzero
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return (Imm != 0) && isInt<6>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 3: {
    // simm6
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isInt<6>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 4: {
    // simm10_lsb0000nonzero
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedInt<6, 4>(Imm) && (Imm != 0);
  }
  case 5: {
    // bare_simm9_lsb0
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedInt<8, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 6: {
    // uimmlog2xlennonzero
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    if (STI.getTargetTriple().isArch64Bit())
      return  isUInt<6>(Imm) && (Imm != 0);
    return isUInt<5>(Imm) && (Imm != 0);
  }
  case 7: {
    // uimm8_lsb000
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<5, 3>(Imm);
  }
  case 8: {
    // uimm9_lsb000
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<6, 3>(Imm);
  }
  case 9: {
    // uimm7_lsb00
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<5, 2>(Imm);
  }
  case 10: {
    // uimm8_lsb00
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<6, 2>(Imm);
  }
  case 11: {
    // bare_simm12_lsb0
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedInt<11, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 12: {
    // uimm2
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isUInt<2>(Imm);
  }
  case 13: {
    // uimm5
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isUInt<5>(Imm);
  }
  case 14: {
    // uimm4
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isUInt<4>(Imm);
  }
  case 15: {
    // uimm2_lsb0
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<1, 1>(Imm);
  }
  case 16: {
    // uimm6_lsb0
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<5, 1>(Imm);
  }
  case 17: {
    // uimm5_lsb0
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<4, 1>(Imm);
  }
  case 18: {
    // c_lui_imm
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return (Imm != 0) && (isUInt<5>(Imm) ||
           (Imm >= 0xfffe0 && Imm <= 0xfffff));
  }
  case 19: {
    // uimm5ge6_plus1
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return Imm >= 6 && Imm <= 32;
  }
  case 20: {
    // simm12_lo
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isInt<12>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 21: {
    // simm5nonzero
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return (Imm != 0) && isInt<5>(Imm);
  }
  case 22: {
    // bare_simm13_lsb0
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedInt<12, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 23: {
    // uimm5nonzero
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return (Imm != 0) && isUInt<5>(Imm);;
  }
  case 24: {
    // simm21_lsb0_jal
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedInt<20, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 25: {
    // simm20_li
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isInt<20>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 26: {
    // uimm5slist
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return ((Imm == 0)  || (Imm == 1)  ||
            (Imm == 2)  || (Imm == 4)  ||
            (Imm == 8)  || (Imm == 16) ||
            (Imm == 15) || (Imm == 31));
  }
  case 27: {
    // uimmlog2xlen
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    if (STI.getTargetTriple().isArch64Bit())
      return isUInt<6>(Imm);
    return isUInt<5>(Imm);
  }
  }
}

static bool compressInst(MCInst &OutInst,
                         const MCInst &MI,
                         const MCSubtargetInfo &STI) {
  switch (MI.getOpcode()) {
  default: return false;
  case RISCV::ADD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(2).getReg())) {
      // c.mv	$rs1, $rs2
      OutInst.setOpcode(RISCV::C_MV);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() &&
        (MI.getOperand(2).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.mv	$rs1, $rs2
      OutInst.setOpcode(RISCV::C_MV);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(2).getReg())) {
      // c.add	$rs1, $rs2
      OutInst.setOpcode(RISCV::C_ADD);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.add	$rs1, $rs2
      OutInst.setOpcode(RISCV::C_ADD);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADD
  case RISCV::ADDI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 1 /* uimm10_lsb00nonzero */)) {
      // c.addi4spn	$rd, $rs1, $imm
      OutInst.setOpcode(RISCV::C_ADDI4SPN);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0)) {
      // c.nop
      OutInst.setOpcode(RISCV::C_NOP);
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 2 /* simm6nonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* simm6 */)) {
      // c.addi	$rd, $imm
      OutInst.setOpcode(RISCV::C_ADDI);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* simm6 */)) {
      // c.li	$rd, $imm
      OutInst.setOpcode(RISCV::C_LI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X2) &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X2) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 4 /* simm10_lsb0000nonzero */)) {
      // c.addi16sp	$rd, $imm
      OutInst.setOpcode(RISCV::C_ADDI16SP);
      // Operand: rd_wb
      OutInst.addOperand(MCOperand::createReg(RISCV::X2));
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X2));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.mv	$rs1, $rs2
      OutInst.setOpcode(RISCV::C_MV);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDI
  case RISCV::ADDIW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* simm6 */)) {
      // c.addiw	$rd, $imm
      OutInst.setOpcode(RISCV::C_ADDIW);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* simm6 */)) {
      // c.li	$rd, $imm
      OutInst.setOpcode(RISCV::C_LI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDIW
  case RISCV::ADDW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.addw	$rd, $rs2
      OutInst.setOpcode(RISCV::C_ADDW);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.addw	$rd, $rs2
      OutInst.setOpcode(RISCV::C_ADDW);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADDW
  case RISCV::ADD_UW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZba] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        (MI.getOperand(2).getReg() == RISCV::X0) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.zext.w	$rd
      OutInst.setOpcode(RISCV::C_ZEXT_W);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ADD_UW
  case RISCV::AND: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.and	$rd, $rs2
      OutInst.setOpcode(RISCV::C_AND);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.and	$rd, $rs2
      OutInst.setOpcode(RISCV::C_AND);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case AND
  case RISCV::ANDI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* simm6 */)) {
      // c.andi	$rs1, $imm
      OutInst.setOpcode(RISCV::C_ANDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 255) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.zext.b	$rd
      OutInst.setOpcode(RISCV::C_ZEXT_B);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ANDI
  case RISCV::BEQ: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* bare_simm9_lsb0 */)) {
      // c.beqz	$rs1, $imm
      OutInst.setOpcode(RISCV::C_BEQZ);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* bare_simm9_lsb0 */)) {
      // c.beqz	$rs1, $imm
      OutInst.setOpcode(RISCV::C_BEQZ);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BEQ
  case RISCV::BEXTI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbs] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 6 /* uimmlog2xlennonzero */)) {
      // qc.c.bexti	$rs1, $shamt
      OutInst.setOpcode(RISCV::QC_C_BEXTI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: shamt
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BEXTI
  case RISCV::BNE: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* bare_simm9_lsb0 */)) {
      // c.bnez	$rs1, $imm
      OutInst.setOpcode(RISCV::C_BNEZ);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 5 /* bare_simm9_lsb0 */)) {
      // c.bnez	$rs1, $imm
      OutInst.setOpcode(RISCV::C_BNEZ);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BNE
  case RISCV::BSETI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbs] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 6 /* uimmlog2xlennonzero */)) {
      // qc.c.bseti	$rs1, $shamt
      OutInst.setOpcode(RISCV::QC_C_BSETI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: shamt
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case BSETI
  case RISCV::EBREAK: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca]) {
      // c.ebreak
      OutInst.setOpcode(RISCV::C_EBREAK);
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case EBREAK
  case RISCV::FLD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR64CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 7 /* uimm8_lsb000 */)) {
      // c.fld	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_FLD);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR64RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 8 /* uimm9_lsb000 */)) {
      // c.fldsp	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_FLDSP);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case FLD
  case RISCV::FLW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 9 /* uimm7_lsb00 */)) {
      // c.flw	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_FLW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR32RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 10 /* uimm8_lsb00 */)) {
      // c.flwsp	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_FLWSP);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case FLW
  case RISCV::FSD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR64CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 7 /* uimm8_lsb000 */)) {
      // c.fsd	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_FSD);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR64RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 8 /* uimm9_lsb000 */)) {
      // c.fsdsp	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_FSDSP);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case FSD
  case RISCV::FSW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 9 /* uimm7_lsb00 */)) {
      // c.fsw	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_FSW);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR32RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 10 /* uimm8_lsb00 */)) {
      // c.fswsp	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_FSWSP);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case FSW
  case RISCV::JAL: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X1) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 11 /* bare_simm12_lsb0 */)) {
      // c.jal	$offset
      OutInst.setOpcode(RISCV::C_JAL);
      // Operand: offset
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 11 /* bare_simm12_lsb0 */)) {
      // c.j	$offset
      OutInst.setOpcode(RISCV::C_J);
      // Operand: offset
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case JAL
  case RISCV::JALR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.jr	$rs1
      OutInst.setOpcode(RISCV::C_JR);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X1) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.jalr	$rs1
      OutInst.setOpcode(RISCV::C_JALR);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case JALR
  case RISCV::LBU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 12 /* uimm2 */)) {
      // c.lbu	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LBU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 13 /* uimm5 */)) {
      // qk.c.lbu	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::QK_C_LBU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 14 /* uimm4 */)) {
      // qk.c.lbusp	$rd_rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::QK_C_LBUSP);
      // Operand: rd_rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LBU
  case RISCV::LD: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 7 /* uimm8_lsb000 */)) {
      // c.ld	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LD);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 8 /* uimm9_lsb000 */)) {
      // c.ldsp	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LDSP);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LD
  case RISCV::LD_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRPairNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 8 /* uimm9_lsb000 */)) {
      // c.ldsp	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LDSP_RV32);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRPairCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 7 /* uimm8_lsb000 */)) {
      // c.ld	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LD_RV32);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LD_RV32
  case RISCV::LH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */)) {
      // c.lh	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LH);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LH
  case RISCV::LHU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */)) {
      // c.lhu	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LHU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 16 /* uimm6_lsb0 */)) {
      // qk.c.lhu	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::QK_C_LHU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 17 /* uimm5_lsb0 */)) {
      // qk.c.lhusp	$rd_rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::QK_C_LHUSP);
      // Operand: rd_rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LHU
  case RISCV::LH_INX: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRF16CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */)) {
      // c.lh	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LH_INX);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LH_INX
  case RISCV::LUI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0X2RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 18 /* c_lui_imm */)) {
      // c.lui	$rd, $imm
      OutInst.setOpcode(RISCV::C_LUI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LUI
  case RISCV::LW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 9 /* uimm7_lsb00 */)) {
      // c.lw	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 10 /* uimm8_lsb00 */)) {
      // c.lwsp	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LWSP);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LW
  case RISCV::LW_INX: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRF32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 9 /* uimm7_lsb00 */)) {
      // c.lw	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LW_INX);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRF32NoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 10 /* uimm8_lsb00 */)) {
      // c.lwsp	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LWSP_INX);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case LW_INX
  case RISCV::MUL: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZmmul] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.mul	$rd, $rs2
      OutInst.setOpcode(RISCV::C_MUL);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZmmul] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.mul	$rd, $rs2
      OutInst.setOpcode(RISCV::C_MUL);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case MUL
  case RISCV::OR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.or	$rd, $rs2
      OutInst.setOpcode(RISCV::C_OR);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.or	$rd, $rs2
      OutInst.setOpcode(RISCV::C_OR);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case OR
  case RISCV::QC_EXTU: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isImm() &&
        (MI.getOperand(3).getImm() == 0) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 19 /* uimm5ge6_plus1 */)) {
      // qc.c.extu	$rd, $width
      OutInst.setOpcode(RISCV::QC_C_EXTU);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: width
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbs] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 1) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(3), STI, 6 /* uimmlog2xlennonzero */)) {
      // qc.c.bexti	$rs1, $shamt
      OutInst.setOpcode(RISCV::QC_C_BEXTI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: shamt
      OutInst.addOperand(MI.getOperand(3));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_EXTU
  case RISCV::QC_E_ADDAI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 2 /* simm6nonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* simm6 */)) {
      // c.addi	$rd, $imm
      OutInst.setOpcode(RISCV::C_ADDI);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X2) &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X2) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 4 /* simm10_lsb0000nonzero */)) {
      // c.addi16sp	$rd, $imm
      OutInst.setOpcode(RISCV::C_ADDI16SP);
      // Operand: rd_wb
      OutInst.addOperand(MCOperand::createReg(RISCV::X2));
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X2));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ADDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_ADDAI
  case RISCV::QC_E_ADDI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 2 /* simm6nonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* simm6 */)) {
      // c.addi	$rd, $imm
      OutInst.setOpcode(RISCV::C_ADDI);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.mv	$rs1, $rs2
      OutInst.setOpcode(RISCV::C_MV);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X2) &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X2) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 4 /* simm10_lsb0000nonzero */)) {
      // c.addi16sp	$rd, $imm
      OutInst.setOpcode(RISCV::C_ADDI16SP);
      // Operand: rd_wb
      OutInst.addOperand(MCOperand::createReg(RISCV::X2));
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X2));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ADDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_ADDI
  case RISCV::QC_E_ANDAI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* simm6 */)) {
      // c.andi	$rs1, $imm
      OutInst.setOpcode(RISCV::C_ANDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // andi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ANDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_ANDAI
  case RISCV::QC_E_ANDI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 3 /* simm6 */)) {
      // c.andi	$rs1, $imm
      OutInst.setOpcode(RISCV::C_ANDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // andi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ANDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_ANDI
  case RISCV::QC_E_BEQI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 21 /* simm5nonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.beqi	$rs1, $rs2, $imm12
      OutInst.setOpcode(RISCV::QC_BEQI);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_BEQI
  case RISCV::QC_E_BGEI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 21 /* simm5nonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.bgei	$rs1, $rs2, $imm12
      OutInst.setOpcode(RISCV::QC_BGEI);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_BGEI
  case RISCV::QC_E_BGEUI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 23 /* uimm5nonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.bgeui	$rs1, $rs2, $imm12
      OutInst.setOpcode(RISCV::QC_BGEUI);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_BGEUI
  case RISCV::QC_E_BLTI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 21 /* simm5nonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.blti	$rs1, $rs2, $imm12
      OutInst.setOpcode(RISCV::QC_BLTI);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_BLTI
  case RISCV::QC_E_BLTUI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 23 /* uimm5nonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.bltui	$rs1, $rs2, $imm12
      OutInst.setOpcode(RISCV::QC_BLTUI);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_BLTUI
  case RISCV::QC_E_BNEI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 21 /* simm5nonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.bnei	$rs1, $rs2, $imm12
      OutInst.setOpcode(RISCV::QC_BNEI);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_BNEI
  case RISCV::QC_E_J: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilb] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForCompress(MI.getOperand(0), STI, 11 /* bare_simm12_lsb0 */)) {
      // c.j	$offset
      OutInst.setOpcode(RISCV::C_J);
      // Operand: offset
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilb] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForCompress(MI.getOperand(0), STI, 24 /* simm21_lsb0_jal */)) {
      // jal	$rd, $imm20
      OutInst.setOpcode(RISCV::JAL);
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X0));
      // Operand: imm20
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_J
  case RISCV::QC_E_JAL: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilb] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForCompress(MI.getOperand(0), STI, 11 /* bare_simm12_lsb0 */)) {
      // c.jal	$offset
      OutInst.setOpcode(RISCV::C_JAL);
      // Operand: offset
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilb] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForCompress(MI.getOperand(0), STI, 24 /* simm21_lsb0_jal */)) {
      // jal	$rd, $imm20
      OutInst.setOpcode(RISCV::JAL);
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X1));
      // Operand: imm20
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_JAL
  case RISCV::QC_E_LB: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // lb	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LB);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_LB
  case RISCV::QC_E_LBU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 12 /* uimm2 */)) {
      // c.lbu	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LBU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // lbu	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LBU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_LBU
  case RISCV::QC_E_LH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */)) {
      // c.lh	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LH);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // lh	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LH);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_LH
  case RISCV::QC_E_LHU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */)) {
      // c.lhu	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LHU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // lhu	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LHU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_LHU
  case RISCV::QC_E_LI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcili] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 3 /* simm6 */)) {
      // c.li	$rd, $imm
      OutInst.setOpcode(RISCV::C_LI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcili] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 25 /* simm20_li */)) {
      // qc.li	$rd, $imm20
      OutInst.setOpcode(RISCV::QC_LI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm20
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_LI
  case RISCV::QC_E_LW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 9 /* uimm7_lsb00 */)) {
      // c.lw	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 10 /* uimm8_lsb00 */)) {
      // c.lwsp	$rd, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_LWSP);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // lw	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_LW
  case RISCV::QC_E_ORAI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // ori	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ORI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_ORAI
  case RISCV::QC_E_ORI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // ori	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ORI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_ORI
  case RISCV::QC_E_SB: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 12 /* uimm2 */)) {
      // c.sb	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SB);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // sb	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SB);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_SB
  case RISCV::QC_E_SH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */)) {
      // c.sh	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SH);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // sh	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SH);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_SH
  case RISCV::QC_E_SW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 9 /* uimm7_lsb00 */)) {
      // c.sw	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SW);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 10 /* uimm8_lsb00 */)) {
      // c.swsp	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SWSP);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // sw	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SW);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_SW
  case RISCV::QC_E_XORAI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // xori	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::XORI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_XORAI
  case RISCV::QC_E_XORI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 20 /* simm12_lo */)) {
      // xori	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::XORI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_E_XORI
  case RISCV::QC_LI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcili] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(1), STI, 3 /* simm6 */)) {
      // c.li	$rd, $imm
      OutInst.setOpcode(RISCV::C_LI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_LI
  case RISCV::QC_MULIADD: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(3), STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      OutInst.setOpcode(RISCV::QC_C_MULIADD);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(2));
      // Operand: uimm
      OutInst.addOperand(MI.getOperand(3));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_MULIADD
  case RISCV::QC_MVEQI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcicm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isImm() &&
        (MI.getOperand(3).getImm() == 0) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(4).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(4).getReg())) {
      // qc.c.mveqz	$rd, $rs1
      OutInst.setOpcode(RISCV::QC_C_MVEQZ);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(4));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_MVEQI
  case RISCV::QC_MVLTUI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcicm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isImm() &&
        (MI.getOperand(3).getImm() == 1) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(4).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(4).getReg())) {
      // qc.c.mveqz	$rd, $rs1
      OutInst.setOpcode(RISCV::QC_C_MVEQZ);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(4));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_MVLTUI
  case RISCV::QC_SHLADD: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isImm() &&
        (MI.getOperand(3).getImm() == 4) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MCOperand::createImm(16), STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      OutInst.setOpcode(RISCV::QC_C_MULIADD);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: uimm
      OutInst.addOperand(MCOperand::createImm(16));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_SHLADD
  case RISCV::QC_SYNC: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForCompress(MI.getOperand(0), STI, 26 /* uimm5slist */)) {
      // qc.c.sync	$slist
      OutInst.setOpcode(RISCV::QC_C_SYNC);
      // Operand: slist
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_SYNC
  case RISCV::QC_SYNCR: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForCompress(MI.getOperand(0), STI, 26 /* uimm5slist */)) {
      // qc.c.syncr	$slist
      OutInst.setOpcode(RISCV::QC_C_SYNCR);
      // Operand: slist
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_SYNCR
  case RISCV::QC_SYNCWF: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForCompress(MI.getOperand(0), STI, 26 /* uimm5slist */)) {
      // qc.c.syncwf	$slist
      OutInst.setOpcode(RISCV::QC_C_SYNCWF);
      // Operand: slist
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_SYNCWF
  case RISCV::QC_SYNCWL: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForCompress(MI.getOperand(0), STI, 26 /* uimm5slist */)) {
      // qc.c.syncwl	$slist
      OutInst.setOpcode(RISCV::QC_C_SYNCWL);
      // Operand: slist
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_SYNCWL
  case RISCV::SB: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 12 /* uimm2 */)) {
      // c.sb	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SB);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 13 /* uimm5 */)) {
      // qk.c.sb	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::QK_C_SB);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 14 /* uimm4 */)) {
      // qk.c.sbsp	$rd_rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::QK_C_SBSP);
      // Operand: rd_rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SB
  case RISCV::SD: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 7 /* uimm8_lsb000 */)) {
      // c.sd	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SD);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 8 /* uimm9_lsb000 */)) {
      // c.sdsp	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SDSP);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SD
  case RISCV::SD_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRPairRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 8 /* uimm9_lsb000 */)) {
      // c.sdsp	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SDSP_RV32);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRPairCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 7 /* uimm8_lsb000 */)) {
      // c.sd	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SD_RV32);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SD_RV32
  case RISCV::SEXT_B: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.sext.b	$rd
      OutInst.setOpcode(RISCV::C_SEXT_B);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SEXT_B
  case RISCV::SEXT_H: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.sext.h	$rd
      OutInst.setOpcode(RISCV::C_SEXT_H);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SEXT_H
  case RISCV::SH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */)) {
      // c.sh	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SH);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 16 /* uimm6_lsb0 */)) {
      // qk.c.sh	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::QK_C_SH);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 17 /* uimm5_lsb0 */)) {
      // qk.c.shsp	$rd_rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::QK_C_SHSP);
      // Operand: rd_rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SH
  case RISCV::SH1ADD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZba] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MCOperand::createImm(2), STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      OutInst.setOpcode(RISCV::QC_C_MULIADD);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: uimm
      OutInst.addOperand(MCOperand::createImm(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SH1ADD
  case RISCV::SH2ADD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZba] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MCOperand::createImm(4), STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      OutInst.setOpcode(RISCV::QC_C_MULIADD);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: uimm
      OutInst.addOperand(MCOperand::createImm(4));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SH2ADD
  case RISCV::SH3ADD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZba] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MCOperand::createImm(8), STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      OutInst.setOpcode(RISCV::QC_C_MULIADD);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: uimm
      OutInst.addOperand(MCOperand::createImm(8));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SH3ADD
  case RISCV::SH_INX: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRF16CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */)) {
      // c.sh	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SH_INX);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SH_INX
  case RISCV::SLLI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 6 /* uimmlog2xlennonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 27 /* uimmlog2xlen */)) {
      // c.slli	$rd, $imm
      OutInst.setOpcode(RISCV::C_SLLI);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SLLI
  case RISCV::SRAI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 6 /* uimmlog2xlennonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 27 /* uimmlog2xlen */)) {
      // c.srai	$rs1, $imm
      OutInst.setOpcode(RISCV::C_SRAI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SRAI
  case RISCV::SRLI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 6 /* uimmlog2xlennonzero */) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 27 /* uimmlog2xlen */)) {
      // c.srli	$rs1, $imm
      OutInst.setOpcode(RISCV::C_SRLI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SRLI
  case RISCV::SSPOPCHK: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcmop] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X5)) {
      // c.sspopchk	$rs1
      OutInst.setOpcode(RISCV::C_SSPOPCHK);
      // Operand: rs1
      OutInst.addOperand(MCOperand::createReg(RISCV::X5));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SSPOPCHK
  case RISCV::SSPUSH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcmop] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X1)) {
      // c.sspush	$rs1
      OutInst.setOpcode(RISCV::C_SSPUSH);
      // Operand: rs1
      OutInst.addOperand(MCOperand::createReg(RISCV::X1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SSPUSH
  case RISCV::SUB: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.sub	$rd, $rs2
      OutInst.setOpcode(RISCV::C_SUB);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUB
  case RISCV::SUBW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.subw	$rd, $rs2
      OutInst.setOpcode(RISCV::C_SUBW);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SUBW
  case RISCV::SW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 9 /* uimm7_lsb00 */)) {
      // c.sw	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SW);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 10 /* uimm8_lsb00 */)) {
      // c.swsp	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SWSP);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SW
  case RISCV::SW_INX: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRF32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 9 /* uimm7_lsb00 */)) {
      // c.sw	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SW_INX);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRF32RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForCompress(MI.getOperand(2), STI, 10 /* uimm8_lsb00 */)) {
      // c.swsp	$rs2, ${imm}(${rs1})
      OutInst.setOpcode(RISCV::C_SWSP_INX);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case SW_INX
  case RISCV::UNIMP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca]) {
      // c.unimp
      OutInst.setOpcode(RISCV::C_UNIMP);
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case UNIMP
  case RISCV::XOR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.xor	$rd, $rs2
      OutInst.setOpcode(RISCV::C_XOR);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.xor	$rd, $rs2
      OutInst.setOpcode(RISCV::C_XOR);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(2));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case XOR
  case RISCV::XORI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == -1) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.not	$rd
      OutInst.setOpcode(RISCV::C_NOT);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case XORI
  case RISCV::ZEXT_H_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.zext.h	$rd
      OutInst.setOpcode(RISCV::C_ZEXT_H);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ZEXT_H_RV32
  case RISCV::ZEXT_H_RV64: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.zext.h	$rd
      OutInst.setOpcode(RISCV::C_ZEXT_H);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(1));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case ZEXT_H_RV64
  } // switch
  return false;
}

#endif // GEN_COMPRESS_INSTR

#ifdef GEN_UNCOMPRESS_INSTR
#undef GEN_UNCOMPRESS_INSTR

static bool RISCVValidateMCOperandForUncompress(const MCOperand &MCOp,
                                                const MCSubtargetInfo &STI,
                                                unsigned PredicateIndex) {
  switch (PredicateIndex) {
  default:
    llvm_unreachable("Unknown MCOperandPredicate kind");
    break;
  case 1: {
    // simm6nonzero
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return (Imm != 0) && isInt<6>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 2: {
    // simm12_lo
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isInt<12>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 3: {
    // simm10_lsb0000nonzero
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedInt<6, 4>(Imm) && (Imm != 0);
  }
  case 4: {
    // uimm10_lsb00nonzero
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<8, 2>(Imm) && (Imm != 0);
  }
  case 5: {
    // simm6
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isInt<6>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 6: {
    // bare_simm9_lsb0
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedInt<8, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 7: {
    // bare_simm13_lsb0
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedInt<12, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 8: {
    // uimm8_lsb000
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<5, 3>(Imm);
  }
  case 9: {
    // uimm9_lsb000
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<6, 3>(Imm);
  }
  case 10: {
    // uimm7_lsb00
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<5, 2>(Imm);
  }
  case 11: {
    // uimm8_lsb00
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<6, 2>(Imm);
  }
  case 12: {
    // bare_simm12_lsb0
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedInt<11, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 13: {
    // simm21_lsb0_jal
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isShiftedInt<20, 1>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 14: {
    // uimm2
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isUInt<2>(Imm);
  }
  case 15: {
    // uimm2_lsb0
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<1, 1>(Imm);
  }
  case 16: {
    // simm20_li
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isInt<20>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 17: {
    // c_lui_imm
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return (Imm != 0) && (isUInt<5>(Imm) ||
           (Imm >= 0xfffe0 && Imm <= 0xfffff));
  }
  case 18: {
    // uimm20_lui
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isUInt<20>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 19: {
    // uimmlog2xlennonzero
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    if (STI.getTargetTriple().isArch64Bit())
      return  isUInt<6>(Imm) && (Imm != 0);
    return isUInt<5>(Imm) && (Imm != 0);
  }
  case 20: {
    // uimmlog2xlen
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    if (STI.getTargetTriple().isArch64Bit())
      return isUInt<6>(Imm);
    return isUInt<5>(Imm);
  }
  case 21: {
    // uimm5ge6_plus1
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return Imm >= 6 && Imm <= 32;
  }
  case 22: {
    // uimm5_plus1
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return Imm > 0 && isUInt<5>(Imm - 1);
  }
  case 23: {
    // uimm5
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isUInt<5>(Imm);
  }
  case 24: {
    // simm5
    int64_t Imm;
    if (MCOp.evaluateAsConstantImm(Imm))
      return isInt<5>(Imm);
    return MCOp.isBareSymbolRef();
  }
  case 25: {
    // uimm5slist
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return ((Imm == 0)  || (Imm == 1)  ||
            (Imm == 2)  || (Imm == 4)  ||
            (Imm == 8)  || (Imm == 16) ||
            (Imm == 15) || (Imm == 31));
  }
  case 26: {
    // uimm4
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isUInt<4>(Imm);
  }
  case 27: {
    // uimm6_lsb0
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<5, 1>(Imm);
  }
  case 28: {
    // uimm5_lsb0
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedUInt<4, 1>(Imm);
  }
  }
}

static bool uncompressInst(MCInst &OutInst,
                           const MCInst &MI,
                           const MCSubtargetInfo &STI) {
  switch (MI.getOpcode()) {
  default: return false;
  case RISCV::C_ADD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(2).getReg())) {
      // add	$rd, $rs1, $rs2
      OutInst.setOpcode(RISCV::ADD);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ADD
  case RISCV::C_ADDI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 1 /* simm6nonzero */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ADDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ADDI
  case RISCV::C_ADDI16SP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X2) &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X2) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 3 /* simm10_lsb0000nonzero */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ADDI);
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X2));
      // Operand: rs1
      OutInst.addOperand(MCOperand::createReg(RISCV::X2));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ADDI16SP
  case RISCV::C_ADDI4SPN: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 4 /* uimm10_lsb00nonzero */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ADDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ADDI4SPN
  case RISCV::C_ADDIW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 5 /* simm6 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // addiw	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ADDIW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ADDIW
  case RISCV::C_ADDW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // addw	$rd, $rs1, $rs2
      OutInst.setOpcode(RISCV::ADDW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ADDW
  case RISCV::C_AND: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // and	$rd, $rs1, $rs2
      OutInst.setOpcode(RISCV::AND);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_AND
  case RISCV::C_ANDI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 5 /* simm6 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // andi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ANDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ANDI
  case RISCV::C_BEQZ: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 6 /* bare_simm9_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 7 /* bare_simm13_lsb0 */)) {
      // beq	$rs1, $rs2, $imm12
      OutInst.setOpcode(RISCV::BEQ);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MCOperand::createReg(RISCV::X0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_BEQZ
  case RISCV::C_BNEZ: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 6 /* bare_simm9_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 7 /* bare_simm13_lsb0 */)) {
      // bne	$rs1, $rs2, $imm12
      OutInst.setOpcode(RISCV::BNE);
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MCOperand::createReg(RISCV::X0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_BNEZ
  case RISCV::C_EBREAK: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca]) {
      // ebreak
      OutInst.setOpcode(RISCV::EBREAK);
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_EBREAK
  case RISCV::C_FLD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtD] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR64CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 8 /* uimm8_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // fld	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::FLD);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_FLD
  case RISCV::C_FLDSP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtD] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR64RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 9 /* uimm9_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // fld	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::FLD);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_FLDSP
  case RISCV::C_FLW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtF] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 10 /* uimm7_lsb00 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // flw	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::FLW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_FLW
  case RISCV::C_FLWSP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtF] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR32RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 11 /* uimm8_lsb00 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // flw	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::FLW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_FLWSP
  case RISCV::C_FSD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtD] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR64CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 8 /* uimm8_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // fsd	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::FSD);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_FSD
  case RISCV::C_FSDSP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtD] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR64RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 9 /* uimm9_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // fsd	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::FSD);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_FSDSP
  case RISCV::C_FSW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtF] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 10 /* uimm7_lsb00 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // fsw	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::FSW);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_FSW
  case RISCV::C_FSWSP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtF] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::FPR32RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 11 /* uimm8_lsb00 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // fsw	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::FSW);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_FSWSP
  case RISCV::C_J: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 12 /* bare_simm12_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 13 /* simm21_lsb0_jal */)) {
      // jal	$rd, $imm20
      OutInst.setOpcode(RISCV::JAL);
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X0));
      // Operand: imm20
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_J
  case RISCV::C_JAL: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 12 /* bare_simm12_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 13 /* simm21_lsb0_jal */)) {
      // jal	$rd, $imm20
      OutInst.setOpcode(RISCV::JAL);
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X1));
      // Operand: imm20
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_JAL
  case RISCV::C_JALR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MCOperand::createImm(0), STI, 2 /* simm12_lo */)) {
      // jalr	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::JALR);
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X1));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MCOperand::createImm(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_JALR
  case RISCV::C_JR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MCOperand::createImm(0), STI, 2 /* simm12_lo */)) {
      // jalr	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::JALR);
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MCOperand::createImm(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_JR
  case RISCV::C_LBU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 14 /* uimm2 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // lbu	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LBU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LBU
  case RISCV::C_LD: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 8 /* uimm8_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // ld	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LD);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LD
  case RISCV::C_LDSP: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 9 /* uimm9_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // ld	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LD);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LDSP
  case RISCV::C_LDSP_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZilsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRPairNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 9 /* uimm9_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // ld	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LD_RV32);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LDSP_RV32
  case RISCV::C_LD_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZilsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRPairCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 8 /* uimm8_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // ld	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LD_RV32);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LD_RV32
  case RISCV::C_LH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // lh	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LH);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LH
  case RISCV::C_LHU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // lhu	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LHU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LHU
  case RISCV::C_LI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 5 /* simm6 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 2 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ADDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MCOperand::createReg(RISCV::X0));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcili] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 5 /* simm6 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 16 /* simm20_li */)) {
      // qc.li	$rd, $imm20
      OutInst.setOpcode(RISCV::QC_LI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm20
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LI
  case RISCV::C_LUI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0X2RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 17 /* c_lui_imm */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(1), STI, 18 /* uimm20_lui */)) {
      // lui	$rd, $imm20
      OutInst.setOpcode(RISCV::LUI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm20
      OutInst.addOperand(MI.getOperand(1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LUI
  case RISCV::C_LW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 10 /* uimm7_lsb00 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // lw	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LW
  case RISCV::C_LWSP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 11 /* uimm8_lsb00 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // lw	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_LWSP
  case RISCV::C_MUL: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZmmul] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // mul	$rd, $rs1, $rs2
      OutInst.setOpcode(RISCV::MUL);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_MUL
  case RISCV::C_MV: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MCOperand::createImm(0), STI, 2 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ADDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MCOperand::createImm(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_MV
  case RISCV::C_NOP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        RISCVValidateMCOperandForUncompress(MCOperand::createImm(0), STI, 2 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ADDI);
      // Operand: rd
      OutInst.addOperand(MCOperand::createReg(RISCV::X0));
      // Operand: rs1
      OutInst.addOperand(MCOperand::createReg(RISCV::X0));
      // Operand: imm12
      OutInst.addOperand(MCOperand::createImm(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_NOP
  case RISCV::C_NOT: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MCOperand::createImm(-1), STI, 2 /* simm12_lo */)) {
      // xori	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::XORI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MCOperand::createImm(-1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_NOT
  case RISCV::C_OR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // or	$rd, $rs1, $rs2
      OutInst.setOpcode(RISCV::OR);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_OR
  case RISCV::C_SB: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 14 /* uimm2 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sb	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SB);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SB
  case RISCV::C_SD: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 8 /* uimm8_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sd	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SD);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SD
  case RISCV::C_SDSP: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 9 /* uimm9_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sd	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SD);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SDSP
  case RISCV::C_SDSP_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZilsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRPairRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 9 /* uimm9_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sd	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SD_RV32);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SDSP_RV32
  case RISCV::C_SD_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZilsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRPairCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 8 /* uimm8_lsb000 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sd	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SD_RV32);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SD_RV32
  case RISCV::C_SEXT_B: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg())) {
      // sext.b	$rd, $rs1
      OutInst.setOpcode(RISCV::SEXT_B);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SEXT_B
  case RISCV::C_SEXT_H: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg())) {
      // sext.h	$rd, $rs1
      OutInst.setOpcode(RISCV::SEXT_H);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SEXT_H
  case RISCV::C_SH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 15 /* uimm2_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sh	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SH);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SH
  case RISCV::C_SLLI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 19 /* uimmlog2xlennonzero */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 20 /* uimmlog2xlen */)) {
      // slli	$rd, $rs1, $shamt
      OutInst.setOpcode(RISCV::SLLI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: shamt
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SLLI
  case RISCV::C_SRAI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 19 /* uimmlog2xlennonzero */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 20 /* uimmlog2xlen */)) {
      // srai	$rd, $rs1, $shamt
      OutInst.setOpcode(RISCV::SRAI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: shamt
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SRAI
  case RISCV::C_SRLI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 19 /* uimmlog2xlennonzero */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 20 /* uimmlog2xlen */)) {
      // srli	$rd, $rs1, $shamt
      OutInst.setOpcode(RISCV::SRLI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: shamt
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SRLI
  case RISCV::C_SSPOPCHK: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcmop] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZimop] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X5)) {
      // sspopchk	$rs1
      OutInst.setOpcode(RISCV::SSPOPCHK);
      // Operand: rs1
      OutInst.addOperand(MCOperand::createReg(RISCV::X5));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SSPOPCHK
  case RISCV::C_SSPUSH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcmop] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZimop] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X1)) {
      // sspush	$rs2
      OutInst.setOpcode(RISCV::SSPUSH);
      // Operand: rs2
      OutInst.addOperand(MCOperand::createReg(RISCV::X1));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SSPUSH
  case RISCV::C_SUB: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // sub	$rd, $rs1, $rs2
      OutInst.setOpcode(RISCV::SUB);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SUB
  case RISCV::C_SUBW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // subw	$rd, $rs1, $rs2
      OutInst.setOpcode(RISCV::SUBW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SUBW
  case RISCV::C_SW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 10 /* uimm7_lsb00 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sw	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SW);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SW
  case RISCV::C_SWSP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 11 /* uimm8_lsb00 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sw	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SW);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_SWSP
  case RISCV::C_UNIMP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca]) {
      // unimp
      OutInst.setOpcode(RISCV::UNIMP);
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_UNIMP
  case RISCV::C_XOR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // xor	$rd, $rs1, $rs2
      OutInst.setOpcode(RISCV::XOR);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_XOR
  case RISCV::C_ZEXT_B: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MCOperand::createImm(255), STI, 2 /* simm12_lo */)) {
      // andi	$rd, $rs1, $imm12
      OutInst.setOpcode(RISCV::ANDI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm12
      OutInst.addOperand(MCOperand::createImm(255));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ZEXT_B
  case RISCV::C_ZEXT_H: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] || STI.getFeatureBits()[RISCV::FeatureStdExtZbkb]) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg())) {
      // zext.h	$rd, $rs1
      OutInst.setOpcode(RISCV::ZEXT_H_RV32);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] || STI.getFeatureBits()[RISCV::FeatureStdExtZbkb]) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg())) {
      // zext.h	$rd, $rs1
      OutInst.setOpcode(RISCV::ZEXT_H_RV64);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ZEXT_H
  case RISCV::C_ZEXT_W: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZba] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg())) {
      // add.uw	$rd, $rs1, $rs2
      OutInst.setOpcode(RISCV::ADD_UW);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs2
      OutInst.addOperand(MCOperand::createReg(RISCV::X0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case C_ZEXT_W
  case RISCV::QC_C_BEXTI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbs] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 19 /* uimmlog2xlennonzero */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 20 /* uimmlog2xlen */)) {
      // bexti	$rd, $rs1, $shamt
      OutInst.setOpcode(RISCV::BEXTI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: shamt
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_C_BEXTI
  case RISCV::QC_C_BSETI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbs] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 19 /* uimmlog2xlennonzero */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 20 /* uimmlog2xlen */)) {
      // bseti	$rd, $rs1, $shamt
      OutInst.setOpcode(RISCV::BSETI);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: shamt
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_C_BSETI
  case RISCV::QC_C_EXTU: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 21 /* uimm5ge6_plus1 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 22 /* uimm5_plus1 */) &&
        RISCVValidateMCOperandForUncompress(MCOperand::createImm(0), STI, 23 /* uimm5 */)) {
      // qc.extu	$rd, $rs1, $width, $shamt
      OutInst.setOpcode(RISCV::QC_EXTU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: width
      OutInst.addOperand(MI.getOperand(2));
      // Operand: shamt
      OutInst.addOperand(MCOperand::createImm(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_C_EXTU
  case RISCV::QC_C_MVEQZ: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcicm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        RISCVValidateMCOperandForUncompress(MCOperand::createImm(0), STI, 24 /* simm5 */) &&
        MI.getOperand(2).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // qc.mveqi	$rd, $rs1, $imm, $rs3
      OutInst.setOpcode(RISCV::QC_MVEQI);
      // Operand: rd_wb
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(0));
      // Operand: imm
      OutInst.addOperand(MCOperand::createImm(0));
      // Operand: rs3
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_C_MVEQZ
  case RISCV::QC_C_SYNC: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 25 /* uimm5slist */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 23 /* uimm5 */)) {
      // qc.sync	$imm5
      OutInst.setOpcode(RISCV::QC_SYNC);
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_C_SYNC
  case RISCV::QC_C_SYNCR: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 25 /* uimm5slist */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 23 /* uimm5 */)) {
      // qc.syncr	$imm5
      OutInst.setOpcode(RISCV::QC_SYNCR);
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_C_SYNCR
  case RISCV::QC_C_SYNCWF: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 25 /* uimm5slist */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 23 /* uimm5 */)) {
      // qc.syncwf	$imm5
      OutInst.setOpcode(RISCV::QC_SYNCWF);
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_C_SYNCWF
  case RISCV::QC_C_SYNCWL: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 25 /* uimm5slist */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(0), STI, 23 /* uimm5 */)) {
      // qc.syncwl	$imm5
      OutInst.setOpcode(RISCV::QC_SYNCWL);
      // Operand: imm5
      OutInst.addOperand(MI.getOperand(0));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QC_C_SYNCWL
  case RISCV::QK_C_LBU: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 23 /* uimm5 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // lbu	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LBU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QK_C_LBU
  case RISCV::QK_C_LBUSP: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 26 /* uimm4 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // lbu	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LBU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QK_C_LBUSP
  case RISCV::QK_C_LHU: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 27 /* uimm6_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // lhu	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LHU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QK_C_LHU
  case RISCV::QK_C_LHUSP: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 28 /* uimm5_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // lhu	$rd, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::LHU);
      // Operand: rd
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QK_C_LHUSP
  case RISCV::QK_C_SB: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 23 /* uimm5 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sb	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SB);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QK_C_SB
  case RISCV::QK_C_SBSP: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 26 /* uimm4 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sb	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SB);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QK_C_SBSP
  case RISCV::QK_C_SH: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 27 /* uimm6_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sh	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SH);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QK_C_SH
  case RISCV::QK_C_SHSP: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 28 /* uimm5_lsb0 */) &&
        RISCVValidateMCOperandForUncompress(MI.getOperand(2), STI, 2 /* simm12_lo */)) {
      // sh	$rs2, ${imm12}(${rs1})
      OutInst.setOpcode(RISCV::SH);
      // Operand: rs2
      OutInst.addOperand(MI.getOperand(0));
      // Operand: rs1
      OutInst.addOperand(MI.getOperand(1));
      // Operand: imm12
      OutInst.addOperand(MI.getOperand(2));
      OutInst.setLoc(MI.getLoc());
      return true;
    } // if
    break;
  } // case QK_C_SHSP
  } // switch
  return false;
}

#endif // GEN_UNCOMPRESS_INSTR

#ifdef GEN_CHECK_COMPRESS_INSTR
#undef GEN_CHECK_COMPRESS_INSTR

static bool RISCVValidateMachineOperand(const MachineOperand &MO,
                                        const RISCVSubtarget *Subtarget,
                                        unsigned PredicateIndex) {
  int64_t Imm = MO.getImm();
  switch (PredicateIndex) {
  default:
    llvm_unreachable("Unknown ImmLeaf Predicate kind");
    break;
  case 1: {
    // simm6nonzero
    return (Imm != 0) && isInt<6>(Imm);
  }
  case 2: {
    // simm6
    return isInt<6>(Imm);
  }
  case 3: {
    // simm10_lsb0000nonzero
    return (Imm != 0) && isShiftedInt<6, 4>(Imm);
  }
  case 4: {
    // uimm10_lsb00nonzero
    return isShiftedUInt<8, 2>(Imm) && (Imm != 0);
  }
  case 5: {
    // bare_simm9_lsb0
    return isShiftedInt<8, 1>(Imm);
  }
  case 6: {
    // uimmlog2xlennonzero
    if (Subtarget->is64Bit())
    return isUInt<6>(Imm) && (Imm != 0);
  return isUInt<5>(Imm) && (Imm != 0);
  }
  case 7: {
    // uimm8_lsb000
    return isShiftedUInt<5, 3>(Imm);
  }
  case 8: {
    // uimm9_lsb000
    return isShiftedUInt<6, 3>(Imm);
  }
  case 9: {
    // uimm7_lsb00
    return isShiftedUInt<5, 2>(Imm);
  }
  case 10: {
    // uimm8_lsb00
    return isShiftedUInt<6, 2>(Imm);
  }
  case 11: {
    // bare_simm12_lsb0
    return isShiftedInt<11, 1>(Imm);
  }
  case 12: {
    // uimm2
    return isUInt<2>(Imm);
  }
  case 13: {
    // uimm5
    return isUInt<5>(Imm);
  }
  case 14: {
    // uimm4
    return isUInt<4>(Imm);
  }
  case 15: {
    // uimm2_lsb0
    return isShiftedUInt<1, 1>(Imm);
  }
  case 16: {
    // uimm6_lsb0
    return isShiftedUInt<5, 1>(Imm);
  }
  case 17: {
    // uimm5_lsb0
    return isShiftedUInt<4, 1>(Imm);
  }
  case 18: {
    // c_lui_imm
    return (Imm != 0) &&
                                 (isUInt<5>(Imm) ||
                                  (Imm >= 0xfffe0 && Imm <= 0xfffff));
  }
  case 19: {
    // uimm5ge6_plus1
    return Imm >= 6 && Imm <= 32;
  }
  case 20: {
    // simm12_lo
    return isInt<12>(Imm);
  }
  case 21: {
    // simm5nonzero
    return (Imm != 0) && isInt<5>(Imm);
  }
  case 22: {
    // bare_simm13_lsb0
    return isShiftedInt<12, 1>(Imm);
  }
  case 23: {
    // uimm5nonzero
    return (Imm != 0) && isUInt<5>(Imm);
  }
  case 24: {
    // simm21_lsb0_jal
    return isShiftedInt<20, 1>(Imm);
  }
  case 25: {
    // simm20_li
    return isInt<20>(Imm);
  }
  case 26: {
    // uimm5slist
    return ((Imm == 0)  ||
            (Imm == 1)  ||
            (Imm == 2)  ||
            (Imm == 4)  ||
            (Imm == 8)  ||
            (Imm == 16) ||
            (Imm == 15) ||
            (Imm == 31));
  }
  case 27: {
    // uimmlog2xlen
    if (Subtarget->is64Bit())
    return isUInt<6>(Imm);
  return isUInt<5>(Imm);
  }
  }
}

static bool isCompressibleInst(const MachineInstr &MI,
                               const RISCVSubtarget &STI) {
  switch (MI.getOpcode()) {
  default: return false;
  case RISCV::ADD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(2).getReg())) {
      // c.add	$rs1, $rs2
      // Operand: rd
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.add	$rs1, $rs2
      // Operand: rd
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(2).getReg())) {
      // c.mv	$rs1, $rs2
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() &&
        (MI.getOperand(2).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.mv	$rs1, $rs2
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    break;
  } // case ADD
  case RISCV::ADDI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 1 /* simm6nonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 2 /* simm6 */)) {
      // c.addi	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X2) &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X2) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 3 /* simm10_lsb0000nonzero */)) {
      // c.addi16sp	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 4 /* uimm10_lsb00nonzero */)) {
      // c.addi4spn	$rd, $rs1, $imm
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 2 /* simm6 */)) {
      // c.li	$rd, $imm
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.mv	$rs1, $rs2
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0)) {
      // c.nop
      return true;
    } // if
    break;
  } // case ADDI
  case RISCV::ADDIW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 2 /* simm6 */)) {
      // c.addiw	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 2 /* simm6 */)) {
      // c.li	$rd, $imm
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    break;
  } // case ADDIW
  case RISCV::ADDW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.addw	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.addw	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    break;
  } // case ADDW
  case RISCV::ADD_UW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZba] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() &&
        (MI.getOperand(2).getReg() == RISCV::X0) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.zext.w	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
    break;
  } // case ADD_UW
  case RISCV::AND: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.and	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.and	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    break;
  } // case AND
  case RISCV::ANDI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 2 /* simm6 */)) {
      // c.andi	$rs1, $imm
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 255) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.zext.b	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
    break;
  } // case ANDI
  case RISCV::BEQ: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 5 /* bare_simm9_lsb0 */)) {
      // c.beqz	$rs1, $imm
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 5 /* bare_simm9_lsb0 */)) {
      // c.beqz	$rs1, $imm
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case BEQ
  case RISCV::BEXTI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbs] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 6 /* uimmlog2xlennonzero */)) {
      // qc.c.bexti	$rs1, $shamt
      // Operand: rd
      // Operand: rs1
      // Operand: shamt
      return true;
    } // if
    break;
  } // case BEXTI
  case RISCV::BNE: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X0) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 5 /* bare_simm9_lsb0 */)) {
      // c.bnez	$rs1, $imm
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 5 /* bare_simm9_lsb0 */)) {
      // c.bnez	$rs1, $imm
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case BNE
  case RISCV::BSETI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbs] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 6 /* uimmlog2xlennonzero */)) {
      // qc.c.bseti	$rs1, $shamt
      // Operand: rd
      // Operand: rs1
      // Operand: shamt
      return true;
    } // if
    break;
  } // case BSETI
  case RISCV::EBREAK: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca]) {
      // c.ebreak
      return true;
    } // if
    break;
  } // case EBREAK
  case RISCV::FLD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::FPR64CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 7 /* uimm8_lsb000 */)) {
      // c.fld	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::FPR64RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 8 /* uimm9_lsb000 */)) {
      // c.fldsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case FLD
  case RISCV::FLW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::FPR32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 9 /* uimm7_lsb00 */)) {
      // c.flw	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::FPR32RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 10 /* uimm8_lsb00 */)) {
      // c.flwsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case FLW
  case RISCV::FSD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::FPR64CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 7 /* uimm8_lsb000 */)) {
      // c.fsd	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcd] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::FPR64RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 8 /* uimm9_lsb000 */)) {
      // c.fsdsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case FSD
  case RISCV::FSW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::FPR32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 9 /* uimm7_lsb00 */)) {
      // c.fsw	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcf] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::FPR32RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 10 /* uimm8_lsb00 */)) {
      // c.fswsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case FSW
  case RISCV::JAL: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 11 /* bare_simm12_lsb0 */)) {
      // c.j	$offset
      // Operand: offset
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X1) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 11 /* bare_simm12_lsb0 */)) {
      // c.jal	$offset
      // Operand: offset
      return true;
    } // if
    break;
  } // case JAL
  case RISCV::JALR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X1) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.jalr	$rs1
      // Operand: rs1
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X0) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.jr	$rs1
      // Operand: rs1
      return true;
    } // if
    break;
  } // case JALR
  case RISCV::LBU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 12 /* uimm2 */)) {
      // c.lbu	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 13 /* uimm5 */)) {
      // qk.c.lbu	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 14 /* uimm4 */)) {
      // qk.c.lbusp	$rd_rs2, ${imm}(${rs1})
      // Operand: rd_rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case LBU
  case RISCV::LD: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 7 /* uimm8_lsb000 */)) {
      // c.ld	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 8 /* uimm9_lsb000 */)) {
      // c.ldsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case LD
  case RISCV::LD_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRPairNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 8 /* uimm9_lsb000 */)) {
      // c.ldsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRPairCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 7 /* uimm8_lsb000 */)) {
      // c.ld	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case LD_RV32
  case RISCV::LH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 15 /* uimm2_lsb0 */)) {
      // c.lh	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case LH
  case RISCV::LHU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 15 /* uimm2_lsb0 */)) {
      // c.lhu	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 16 /* uimm6_lsb0 */)) {
      // qk.c.lhu	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 17 /* uimm5_lsb0 */)) {
      // qk.c.lhusp	$rd_rs2, ${imm}(${rs1})
      // Operand: rd_rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case LHU
  case RISCV::LH_INX: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRF16CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 15 /* uimm2_lsb0 */)) {
      // c.lh	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case LH_INX
  case RISCV::LUI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0X2RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 18 /* c_lui_imm */)) {
      // c.lui	$rd, $imm
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    break;
  } // case LUI
  case RISCV::LW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 9 /* uimm7_lsb00 */)) {
      // c.lw	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 10 /* uimm8_lsb00 */)) {
      // c.lwsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case LW
  case RISCV::LW_INX: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRF32NoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 10 /* uimm8_lsb00 */)) {
      // c.lwsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRF32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 9 /* uimm7_lsb00 */)) {
      // c.lw	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case LW_INX
  case RISCV::MUL: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZmmul] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.mul	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZmmul] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.mul	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    break;
  } // case MUL
  case RISCV::OR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.or	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.or	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    break;
  } // case OR
  case RISCV::QC_EXTU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbs] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 1) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(3).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(3), &STI, 6 /* uimmlog2xlennonzero */)) {
      // qc.c.bexti	$rs1, $shamt
      // Operand: rd
      // Operand: rs1
      // Operand: shamt
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isImm() &&
        (MI.getOperand(3).getImm() == 0) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 19 /* uimm5ge6_plus1 */)) {
      // qc.c.extu	$rd, $width
      // Operand: rd_wb
      // Operand: rd
      // Operand: width
      return true;
    } // if
    break;
  } // case QC_EXTU
  case RISCV::QC_E_ADDAI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 1 /* simm6nonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 2 /* simm6 */)) {
      // c.addi	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X2) &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X2) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 3 /* simm10_lsb0000nonzero */)) {
      // c.addi16sp	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    break;
  } // case QC_E_ADDAI
  case RISCV::QC_E_ADDI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // addi	$rd, $rs1, $imm12
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 1 /* simm6nonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 2 /* simm6 */)) {
      // c.addi	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X2) &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(1).getReg() == RISCV::X2) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 3 /* simm10_lsb0000nonzero */)) {
      // c.addi16sp	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == 0) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg())) {
      // c.mv	$rs1, $rs2
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    break;
  } // case QC_E_ADDI
  case RISCV::QC_E_ANDAI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // andi	$rd, $rs1, $imm12
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 2 /* simm6 */)) {
      // c.andi	$rs1, $imm
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case QC_E_ANDAI
  case RISCV::QC_E_ANDI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // andi	$rd, $rs1, $imm12
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 2 /* simm6 */)) {
      // c.andi	$rs1, $imm
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case QC_E_ANDI
  case RISCV::QC_E_BEQI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 21 /* simm5nonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.beqi	$rs1, $rs2, $imm12
      // Operand: rs1
      // Operand: rs2
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_BEQI
  case RISCV::QC_E_BGEI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 21 /* simm5nonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.bgei	$rs1, $rs2, $imm12
      // Operand: rs1
      // Operand: rs2
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_BGEI
  case RISCV::QC_E_BGEUI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 23 /* uimm5nonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.bgeui	$rs1, $rs2, $imm12
      // Operand: rs1
      // Operand: rs2
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_BGEUI
  case RISCV::QC_E_BLTI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 21 /* simm5nonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.blti	$rs1, $rs2, $imm12
      // Operand: rs1
      // Operand: rs2
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_BLTI
  case RISCV::QC_E_BLTUI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 23 /* uimm5nonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.bltui	$rs1, $rs2, $imm12
      // Operand: rs1
      // Operand: rs2
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_BLTUI
  case RISCV::QC_E_BNEI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcibi] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 21 /* simm5nonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 22 /* bare_simm13_lsb0 */)) {
      // qc.bnei	$rs1, $rs2, $imm12
      // Operand: rs1
      // Operand: rs2
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_BNEI
  case RISCV::QC_E_J: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilb] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(0), &STI, 11 /* bare_simm12_lsb0 */)) {
      // c.j	$offset
      // Operand: offset
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilb] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(0), &STI, 24 /* simm21_lsb0_jal */)) {
      // jal	$rd, $imm20
      // Operand: rd
      // Operand: imm20
      return true;
    } // if
    break;
  } // case QC_E_J
  case RISCV::QC_E_JAL: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilb] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(0), &STI, 11 /* bare_simm12_lsb0 */)) {
      // c.jal	$offset
      // Operand: offset
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilb] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(0), &STI, 24 /* simm21_lsb0_jal */)) {
      // jal	$rd, $imm20
      // Operand: rd
      // Operand: imm20
      return true;
    } // if
    break;
  } // case QC_E_JAL
  case RISCV::QC_E_LB: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // lb	$rd, ${imm12}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_LB
  case RISCV::QC_E_LBU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 12 /* uimm2 */)) {
      // c.lbu	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // lbu	$rd, ${imm12}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_LBU
  case RISCV::QC_E_LH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 15 /* uimm2_lsb0 */)) {
      // c.lh	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // lh	$rd, ${imm12}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_LH
  case RISCV::QC_E_LHU: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 15 /* uimm2_lsb0 */)) {
      // c.lhu	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // lhu	$rd, ${imm12}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_LHU
  case RISCV::QC_E_LI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcili] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 2 /* simm6 */)) {
      // c.li	$rd, $imm
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcili] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 25 /* simm20_li */)) {
      // qc.li	$rd, $imm20
      // Operand: rd
      // Operand: imm20
      return true;
    } // if
    break;
  } // case QC_E_LI
  case RISCV::QC_E_LW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 9 /* uimm7_lsb00 */)) {
      // c.lw	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 10 /* uimm8_lsb00 */)) {
      // c.lwsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // lw	$rd, ${imm12}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_LW
  case RISCV::QC_E_ORAI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // ori	$rd, $rs1, $imm12
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_ORAI
  case RISCV::QC_E_ORI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // ori	$rd, $rs1, $imm12
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_ORI
  case RISCV::QC_E_SB: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 12 /* uimm2 */)) {
      // c.sb	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // sb	$rs2, ${imm12}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_SB
  case RISCV::QC_E_SH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 15 /* uimm2_lsb0 */)) {
      // c.sh	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // sh	$rs2, ${imm12}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_SH
  case RISCV::QC_E_SW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 9 /* uimm7_lsb00 */)) {
      // c.sw	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 10 /* uimm8_lsb00 */)) {
      // c.swsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilo] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // sw	$rs2, ${imm12}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_SW
  case RISCV::QC_E_XORAI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // xori	$rd, $rs1, $imm12
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_XORAI
  case RISCV::QC_E_XORI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcilia] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 20 /* simm12_lo */)) {
      // xori	$rd, $rs1, $imm12
      // Operand: rd
      // Operand: rs1
      // Operand: imm12
      return true;
    } // if
    break;
  } // case QC_E_XORI
  case RISCV::QC_LI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqcili] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(1), &STI, 2 /* simm6 */)) {
      // c.li	$rd, $imm
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    break;
  } // case QC_LI
  case RISCV::QC_MULIADD: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(3).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(3), &STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs1
      // Operand: uimm
      return true;
    } // if
    break;
  } // case QC_MULIADD
  case RISCV::QC_MVEQI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcicm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isImm() &&
        (MI.getOperand(3).getImm() == 0) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(4).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(4).getReg())) {
      // qc.c.mveqz	$rd, $rs1
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs1
      return true;
    } // if
    break;
  } // case QC_MVEQI
  case RISCV::QC_MVLTUI: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcicm] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isImm() &&
        (MI.getOperand(3).getImm() == 1) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(4).isReg() && MI.getOperand(4).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(4).getReg())) {
      // qc.c.mveqz	$rd, $rs1
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs1
      return true;
    } // if
    break;
  } // case QC_MVLTUI
  case RISCV::QC_SHLADD: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(3).isImm() &&
        (MI.getOperand(3).getImm() == 4) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMachineOperand(MachineOperand::CreateImm(16), &STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs1
      // Operand: uimm
      return true;
    } // if
    break;
  } // case QC_SHLADD
  case RISCV::QC_SYNC: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(0), &STI, 26 /* uimm5slist */)) {
      // qc.c.sync	$slist
      // Operand: slist
      return true;
    } // if
    break;
  } // case QC_SYNC
  case RISCV::QC_SYNCR: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(0), &STI, 26 /* uimm5slist */)) {
      // qc.c.syncr	$slist
      // Operand: slist
      return true;
    } // if
    break;
  } // case QC_SYNCR
  case RISCV::QC_SYNCWF: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(0), &STI, 26 /* uimm5slist */)) {
      // qc.c.syncwf	$slist
      // Operand: slist
      return true;
    } // if
    break;
  } // case QC_SYNCWF
  case RISCV::QC_SYNCWL: {
    if (STI.getFeatureBits()[RISCV::FeatureVendorXqcisync] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(0), &STI, 26 /* uimm5slist */)) {
      // qc.c.syncwl	$slist
      // Operand: slist
      return true;
    } // if
    break;
  } // case QC_SYNCWL
  case RISCV::SB: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 12 /* uimm2 */)) {
      // c.sb	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 13 /* uimm5 */)) {
      // qk.c.sb	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 14 /* uimm4 */)) {
      // qk.c.sbsp	$rd_rs2, ${imm}(${rs1})
      // Operand: rd_rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case SB
  case RISCV::SD: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 7 /* uimm8_lsb000 */)) {
      // c.sd	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 8 /* uimm9_lsb000 */)) {
      // c.sdsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case SD
  case RISCV::SD_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRPairRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 8 /* uimm9_lsb000 */)) {
      // c.sdsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZclsd] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRPairCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 7 /* uimm8_lsb000 */)) {
      // c.sd	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case SD_RV32
  case RISCV::SEXT_B: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.sext.b	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
    break;
  } // case SEXT_B
  case RISCV::SEXT_H: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.sext.h	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
    break;
  } // case SEXT_H
  case RISCV::SH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 15 /* uimm2_lsb0 */)) {
      // c.sh	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 16 /* uimm6_lsb0 */)) {
      // qk.c.sh	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureVendorXwchc] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 17 /* uimm5_lsb0 */)) {
      // qk.c.shsp	$rd_rs2, ${imm}(${rs1})
      // Operand: rd_rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case SH
  case RISCV::SH1ADD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZba] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMachineOperand(MachineOperand::CreateImm(2), &STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs1
      // Operand: uimm
      return true;
    } // if
    break;
  } // case SH1ADD
  case RISCV::SH2ADD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZba] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMachineOperand(MachineOperand::CreateImm(4), &STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs1
      // Operand: uimm
      return true;
    } // if
    break;
  } // case SH2ADD
  case RISCV::SH3ADD: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZba] &&
        STI.getFeatureBits()[RISCV::FeatureVendorXqciac] &&
        !STI.getFeatureBits()[RISCV::Feature64Bit] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        RISCVValidateMachineOperand(MachineOperand::CreateImm(8), &STI, 13 /* uimm5 */)) {
      // qc.c.muliadd	$rd, $rs1, $uimm
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs1
      // Operand: uimm
      return true;
    } // if
    break;
  } // case SH3ADD
  case RISCV::SH_INX: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRF16CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 15 /* uimm2_lsb0 */)) {
      // c.sh	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case SH_INX
  case RISCV::SLLI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRNoX0RegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 6 /* uimmlog2xlennonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 27 /* uimmlog2xlen */)) {
      // c.slli	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    break;
  } // case SLLI
  case RISCV::SRAI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 6 /* uimmlog2xlennonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 27 /* uimmlog2xlen */)) {
      // c.srai	$rs1, $imm
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case SRAI
  case RISCV::SRLI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 6 /* uimmlog2xlennonzero */) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 27 /* uimmlog2xlen */)) {
      // c.srli	$rs1, $imm
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case SRLI
  case RISCV::SSPOPCHK: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcmop] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X5)) {
      // c.sspopchk	$rs1
      // Operand: rs1
      return true;
    } // if
    break;
  } // case SSPOPCHK
  case RISCV::SSPUSH: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcmop] &&
        MI.getOperand(0).isReg() &&
        (MI.getOperand(0).getReg() == RISCV::X1)) {
      // c.sspush	$rs1
      // Operand: rs1
      return true;
    } // if
    break;
  } // case SSPUSH
  case RISCV::SUB: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.sub	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    break;
  } // case SUB
  case RISCV::SUBW: {
    if (STI.getFeatureBits()[RISCV::Feature64Bit] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.subw	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    break;
  } // case SUBW
  case RISCV::SW: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 9 /* uimm7_lsb00 */)) {
      // c.sw	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 10 /* uimm8_lsb00 */)) {
      // c.swsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case SW
  case RISCV::SW_INX: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRF32RegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::SPRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 10 /* uimm8_lsb00 */)) {
      // c.swsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRF32CRegClassID).contains(MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isImm() &&
        RISCVValidateMachineOperand(MI.getOperand(2), &STI, 9 /* uimm7_lsb00 */)) {
      // c.sw	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    break;
  } // case SW_INX
  case RISCV::UNIMP: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca]) {
      // c.unimp
      return true;
    } // if
    break;
  } // case UNIMP
  case RISCV::XOR: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg())) {
      // c.xor	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZca] &&
        MI.getOperand(2).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(2).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isReg() && MI.getOperand(2).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(2).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.xor	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    break;
  } // case XOR
  case RISCV::XORI: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(2).isImm() &&
        (MI.getOperand(2).getImm() == -1) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.not	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
    break;
  } // case XORI
  case RISCV::ZEXT_H_RV32: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.zext.h	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
    break;
  } // case ZEXT_H_RV32
  case RISCV::ZEXT_H_RV64: {
    if (STI.getFeatureBits()[RISCV::FeatureStdExtZbb] &&
        STI.getFeatureBits()[RISCV::FeatureStdExtZcb] &&
        MI.getOperand(1).isReg() && MI.getOperand(0).isReg() &&
        (MI.getOperand(1).getReg() == MI.getOperand(0).getReg()) &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg().isPhysical() &&
        getRISCVMCRegisterClass(RISCV::GPRCRegClassID).contains(MI.getOperand(1).getReg())) {
      // c.zext.h	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
    break;
  } // case ZEXT_H_RV64
  } // switch
  return false;
}

#endif // GEN_CHECK_COMPRESS_INSTR

