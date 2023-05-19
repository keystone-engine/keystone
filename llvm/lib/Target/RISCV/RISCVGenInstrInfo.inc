/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM
namespace llvm_ks {

namespace RISCV {
  enum {
    PHI	= 0,
    INLINEASM	= 1,
    INLINEASM_BR	= 2,
    CFI_INSTRUCTION	= 3,
    EH_LABEL	= 4,
    GC_LABEL	= 5,
    ANNOTATION_LABEL	= 6,
    KILL	= 7,
    EXTRACT_SUBREG	= 8,
    INSERT_SUBREG	= 9,
    IMPLICIT_DEF	= 10,
    SUBREG_TO_REG	= 11,
    COPY_TO_REGCLASS	= 12,
    DBG_VALUE	= 13,
    DBG_LABEL	= 14,
    REG_SEQUENCE	= 15,
    COPY	= 16,
    BUNDLE	= 17,
    LIFETIME_START	= 18,
    LIFETIME_END	= 19,
    STACKMAP	= 20,
    FENTRY_CALL	= 21,
    PATCHPOINT	= 22,
    LOAD_STACK_GUARD	= 23,
    STATEPOINT	= 24,
    LOCAL_ESCAPE	= 25,
    FAULTING_OP	= 26,
    PATCHABLE_OP	= 27,
    PATCHABLE_FUNCTION_ENTER	= 28,
    PATCHABLE_RET	= 29,
    PATCHABLE_FUNCTION_EXIT	= 30,
    PATCHABLE_TAIL_CALL	= 31,
    PATCHABLE_EVENT_CALL	= 32,
    PATCHABLE_TYPED_EVENT_CALL	= 33,
    ICALL_BRANCH_FUNNEL	= 34,
    G_ADD	= 35,
    G_SUB	= 36,
    G_MUL	= 37,
    G_SDIV	= 38,
    G_UDIV	= 39,
    G_SREM	= 40,
    G_UREM	= 41,
    G_AND	= 42,
    G_OR	= 43,
    G_XOR	= 44,
    G_IMPLICIT_DEF	= 45,
    G_PHI	= 46,
    G_FRAME_INDEX	= 47,
    G_GLOBAL_VALUE	= 48,
    G_EXTRACT	= 49,
    G_UNMERGE_VALUES	= 50,
    G_INSERT	= 51,
    G_MERGE_VALUES	= 52,
    G_BUILD_VECTOR	= 53,
    G_BUILD_VECTOR_TRUNC	= 54,
    G_CONCAT_VECTORS	= 55,
    G_PTRTOINT	= 56,
    G_INTTOPTR	= 57,
    G_BITCAST	= 58,
    G_INTRINSIC_TRUNC	= 59,
    G_INTRINSIC_ROUND	= 60,
    G_LOAD	= 61,
    G_SEXTLOAD	= 62,
    G_ZEXTLOAD	= 63,
    G_STORE	= 64,
    G_ATOMIC_CMPXCHG_WITH_SUCCESS	= 65,
    G_ATOMIC_CMPXCHG	= 66,
    G_ATOMICRMW_XCHG	= 67,
    G_ATOMICRMW_ADD	= 68,
    G_ATOMICRMW_SUB	= 69,
    G_ATOMICRMW_AND	= 70,
    G_ATOMICRMW_NAND	= 71,
    G_ATOMICRMW_OR	= 72,
    G_ATOMICRMW_XOR	= 73,
    G_ATOMICRMW_MAX	= 74,
    G_ATOMICRMW_MIN	= 75,
    G_ATOMICRMW_UMAX	= 76,
    G_ATOMICRMW_UMIN	= 77,
    G_FENCE	= 78,
    G_BRCOND	= 79,
    G_BRINDIRECT	= 80,
    G_INTRINSIC	= 81,
    G_INTRINSIC_W_SIDE_EFFECTS	= 82,
    G_ANYEXT	= 83,
    G_TRUNC	= 84,
    G_CONSTANT	= 85,
    G_FCONSTANT	= 86,
    G_VASTART	= 87,
    G_VAARG	= 88,
    G_SEXT	= 89,
    G_ZEXT	= 90,
    G_SHL	= 91,
    G_LSHR	= 92,
    G_ASHR	= 93,
    G_ICMP	= 94,
    G_FCMP	= 95,
    G_SELECT	= 96,
    G_UADDO	= 97,
    G_UADDE	= 98,
    G_USUBO	= 99,
    G_USUBE	= 100,
    G_SADDO	= 101,
    G_SADDE	= 102,
    G_SSUBO	= 103,
    G_SSUBE	= 104,
    G_UMULO	= 105,
    G_SMULO	= 106,
    G_UMULH	= 107,
    G_SMULH	= 108,
    G_FADD	= 109,
    G_FSUB	= 110,
    G_FMUL	= 111,
    G_FMA	= 112,
    G_FDIV	= 113,
    G_FREM	= 114,
    G_FPOW	= 115,
    G_FEXP	= 116,
    G_FEXP2	= 117,
    G_FLOG	= 118,
    G_FLOG2	= 119,
    G_FLOG10	= 120,
    G_FNEG	= 121,
    G_FPEXT	= 122,
    G_FPTRUNC	= 123,
    G_FPTOSI	= 124,
    G_FPTOUI	= 125,
    G_SITOFP	= 126,
    G_UITOFP	= 127,
    G_FABS	= 128,
    G_FCOPYSIGN	= 129,
    G_FCANONICALIZE	= 130,
    G_FMINNUM	= 131,
    G_FMAXNUM	= 132,
    G_FMINNUM_IEEE	= 133,
    G_FMAXNUM_IEEE	= 134,
    G_FMINIMUM	= 135,
    G_FMAXIMUM	= 136,
    G_GEP	= 137,
    G_PTR_MASK	= 138,
    G_SMIN	= 139,
    G_SMAX	= 140,
    G_UMIN	= 141,
    G_UMAX	= 142,
    G_BR	= 143,
    G_BRJT	= 144,
    G_INSERT_VECTOR_ELT	= 145,
    G_EXTRACT_VECTOR_ELT	= 146,
    G_SHUFFLE_VECTOR	= 147,
    G_CTTZ	= 148,
    G_CTTZ_ZERO_UNDEF	= 149,
    G_CTLZ	= 150,
    G_CTLZ_ZERO_UNDEF	= 151,
    G_CTPOP	= 152,
    G_BSWAP	= 153,
    G_FCEIL	= 154,
    G_FCOS	= 155,
    G_FSIN	= 156,
    G_FSQRT	= 157,
    G_FFLOOR	= 158,
    G_FRINT	= 159,
    G_FNEARBYINT	= 160,
    G_ADDRSPACE_CAST	= 161,
    G_BLOCK_ADDR	= 162,
    G_JUMP_TABLE	= 163,
    ADJCALLSTACKDOWN	= 164,
    ADJCALLSTACKUP	= 165,
    BuildPairF64Pseudo	= 166,
    PseudoAddTPRel	= 167,
    PseudoAtomicLoadNand32	= 168,
    PseudoAtomicLoadNand64	= 169,
    PseudoBR	= 170,
    PseudoBRIND	= 171,
    PseudoCALL	= 172,
    PseudoCALLIndirect	= 173,
    PseudoCALLReg	= 174,
    PseudoCmpXchg32	= 175,
    PseudoCmpXchg64	= 176,
    PseudoFLD	= 177,
    PseudoFLW	= 178,
    PseudoFSD	= 179,
    PseudoFSW	= 180,
    PseudoLA	= 181,
    PseudoLA_TLS_GD	= 182,
    PseudoLA_TLS_IE	= 183,
    PseudoLB	= 184,
    PseudoLBU	= 185,
    PseudoLD	= 186,
    PseudoLH	= 187,
    PseudoLHU	= 188,
    PseudoLI	= 189,
    PseudoLLA	= 190,
    PseudoLW	= 191,
    PseudoLWU	= 192,
    PseudoMaskedAtomicLoadAdd32	= 193,
    PseudoMaskedAtomicLoadMax32	= 194,
    PseudoMaskedAtomicLoadMin32	= 195,
    PseudoMaskedAtomicLoadNand32	= 196,
    PseudoMaskedAtomicLoadSub32	= 197,
    PseudoMaskedAtomicLoadUMax32	= 198,
    PseudoMaskedAtomicLoadUMin32	= 199,
    PseudoMaskedAtomicSwap32	= 200,
    PseudoMaskedCmpXchg32	= 201,
    PseudoRET	= 202,
    PseudoSB	= 203,
    PseudoSD	= 204,
    PseudoSH	= 205,
    PseudoSW	= 206,
    PseudoTAIL	= 207,
    PseudoTAILIndirect	= 208,
    ReadCycleWide	= 209,
    Select_FPR32_Using_CC_GPR	= 210,
    Select_FPR64_Using_CC_GPR	= 211,
    Select_GPR_Using_CC_GPR	= 212,
    SplitF64Pseudo	= 213,
    ADD	= 214,
    ADDI	= 215,
    ADDIW	= 216,
    ADDW	= 217,
    AMOADD_D	= 218,
    AMOADD_D_AQ	= 219,
    AMOADD_D_AQ_RL	= 220,
    AMOADD_D_RL	= 221,
    AMOADD_W	= 222,
    AMOADD_W_AQ	= 223,
    AMOADD_W_AQ_RL	= 224,
    AMOADD_W_RL	= 225,
    AMOAND_D	= 226,
    AMOAND_D_AQ	= 227,
    AMOAND_D_AQ_RL	= 228,
    AMOAND_D_RL	= 229,
    AMOAND_W	= 230,
    AMOAND_W_AQ	= 231,
    AMOAND_W_AQ_RL	= 232,
    AMOAND_W_RL	= 233,
    AMOMAXU_D	= 234,
    AMOMAXU_D_AQ	= 235,
    AMOMAXU_D_AQ_RL	= 236,
    AMOMAXU_D_RL	= 237,
    AMOMAXU_W	= 238,
    AMOMAXU_W_AQ	= 239,
    AMOMAXU_W_AQ_RL	= 240,
    AMOMAXU_W_RL	= 241,
    AMOMAX_D	= 242,
    AMOMAX_D_AQ	= 243,
    AMOMAX_D_AQ_RL	= 244,
    AMOMAX_D_RL	= 245,
    AMOMAX_W	= 246,
    AMOMAX_W_AQ	= 247,
    AMOMAX_W_AQ_RL	= 248,
    AMOMAX_W_RL	= 249,
    AMOMINU_D	= 250,
    AMOMINU_D_AQ	= 251,
    AMOMINU_D_AQ_RL	= 252,
    AMOMINU_D_RL	= 253,
    AMOMINU_W	= 254,
    AMOMINU_W_AQ	= 255,
    AMOMINU_W_AQ_RL	= 256,
    AMOMINU_W_RL	= 257,
    AMOMIN_D	= 258,
    AMOMIN_D_AQ	= 259,
    AMOMIN_D_AQ_RL	= 260,
    AMOMIN_D_RL	= 261,
    AMOMIN_W	= 262,
    AMOMIN_W_AQ	= 263,
    AMOMIN_W_AQ_RL	= 264,
    AMOMIN_W_RL	= 265,
    AMOOR_D	= 266,
    AMOOR_D_AQ	= 267,
    AMOOR_D_AQ_RL	= 268,
    AMOOR_D_RL	= 269,
    AMOOR_W	= 270,
    AMOOR_W_AQ	= 271,
    AMOOR_W_AQ_RL	= 272,
    AMOOR_W_RL	= 273,
    AMOSWAP_D	= 274,
    AMOSWAP_D_AQ	= 275,
    AMOSWAP_D_AQ_RL	= 276,
    AMOSWAP_D_RL	= 277,
    AMOSWAP_W	= 278,
    AMOSWAP_W_AQ	= 279,
    AMOSWAP_W_AQ_RL	= 280,
    AMOSWAP_W_RL	= 281,
    AMOXOR_D	= 282,
    AMOXOR_D_AQ	= 283,
    AMOXOR_D_AQ_RL	= 284,
    AMOXOR_D_RL	= 285,
    AMOXOR_W	= 286,
    AMOXOR_W_AQ	= 287,
    AMOXOR_W_AQ_RL	= 288,
    AMOXOR_W_RL	= 289,
    AND	= 290,
    ANDI	= 291,
    AUIPC	= 292,
    BEQ	= 293,
    BGE	= 294,
    BGEU	= 295,
    BLT	= 296,
    BLTU	= 297,
    BNE	= 298,
    CSRRC	= 299,
    CSRRCI	= 300,
    CSRRS	= 301,
    CSRRSI	= 302,
    CSRRW	= 303,
    CSRRWI	= 304,
    C_ADD	= 305,
    C_ADDI	= 306,
    C_ADDI16SP	= 307,
    C_ADDI4SPN	= 308,
    C_ADDIW	= 309,
    C_ADDW	= 310,
    C_AND	= 311,
    C_ANDI	= 312,
    C_BEQZ	= 313,
    C_BNEZ	= 314,
    C_EBREAK	= 315,
    C_FLD	= 316,
    C_FLDSP	= 317,
    C_FLW	= 318,
    C_FLWSP	= 319,
    C_FSD	= 320,
    C_FSDSP	= 321,
    C_FSW	= 322,
    C_FSWSP	= 323,
    C_J	= 324,
    C_JAL	= 325,
    C_JALR	= 326,
    C_JR	= 327,
    C_LD	= 328,
    C_LDSP	= 329,
    C_LI	= 330,
    C_LUI	= 331,
    C_LW	= 332,
    C_LWSP	= 333,
    C_MV	= 334,
    C_NOP	= 335,
    C_OR	= 336,
    C_SD	= 337,
    C_SDSP	= 338,
    C_SLLI	= 339,
    C_SRAI	= 340,
    C_SRLI	= 341,
    C_SUB	= 342,
    C_SUBW	= 343,
    C_SW	= 344,
    C_SWSP	= 345,
    C_UNIMP	= 346,
    C_XOR	= 347,
    DIV	= 348,
    DIVU	= 349,
    DIVUW	= 350,
    DIVW	= 351,
    EBREAK	= 352,
    ECALL	= 353,
    FADD_D	= 354,
    FADD_S	= 355,
    FCLASS_D	= 356,
    FCLASS_S	= 357,
    FCVT_D_L	= 358,
    FCVT_D_LU	= 359,
    FCVT_D_S	= 360,
    FCVT_D_W	= 361,
    FCVT_D_WU	= 362,
    FCVT_LU_D	= 363,
    FCVT_LU_S	= 364,
    FCVT_L_D	= 365,
    FCVT_L_S	= 366,
    FCVT_S_D	= 367,
    FCVT_S_L	= 368,
    FCVT_S_LU	= 369,
    FCVT_S_W	= 370,
    FCVT_S_WU	= 371,
    FCVT_WU_D	= 372,
    FCVT_WU_S	= 373,
    FCVT_W_D	= 374,
    FCVT_W_S	= 375,
    FDIV_D	= 376,
    FDIV_S	= 377,
    FENCE	= 378,
    FENCE_I	= 379,
    FENCE_TSO	= 380,
    FEQ_D	= 381,
    FEQ_S	= 382,
    FLD	= 383,
    FLE_D	= 384,
    FLE_S	= 385,
    FLT_D	= 386,
    FLT_S	= 387,
    FLW	= 388,
    FMADD_D	= 389,
    FMADD_S	= 390,
    FMAX_D	= 391,
    FMAX_S	= 392,
    FMIN_D	= 393,
    FMIN_S	= 394,
    FMSUB_D	= 395,
    FMSUB_S	= 396,
    FMUL_D	= 397,
    FMUL_S	= 398,
    FMV_D_X	= 399,
    FMV_W_X	= 400,
    FMV_X_D	= 401,
    FMV_X_W	= 402,
    FNMADD_D	= 403,
    FNMADD_S	= 404,
    FNMSUB_D	= 405,
    FNMSUB_S	= 406,
    FSD	= 407,
    FSGNJN_D	= 408,
    FSGNJN_S	= 409,
    FSGNJX_D	= 410,
    FSGNJX_S	= 411,
    FSGNJ_D	= 412,
    FSGNJ_S	= 413,
    FSQRT_D	= 414,
    FSQRT_S	= 415,
    FSUB_D	= 416,
    FSUB_S	= 417,
    FSW	= 418,
    JAL	= 419,
    JALR	= 420,
    LB	= 421,
    LBU	= 422,
    LD	= 423,
    LH	= 424,
    LHU	= 425,
    LR_D	= 426,
    LR_D_AQ	= 427,
    LR_D_AQ_RL	= 428,
    LR_D_RL	= 429,
    LR_W	= 430,
    LR_W_AQ	= 431,
    LR_W_AQ_RL	= 432,
    LR_W_RL	= 433,
    LUI	= 434,
    LW	= 435,
    LWU	= 436,
    MRET	= 437,
    MUL	= 438,
    MULH	= 439,
    MULHSU	= 440,
    MULHU	= 441,
    MULW	= 442,
    OR	= 443,
    ORI	= 444,
    REM	= 445,
    REMU	= 446,
    REMUW	= 447,
    REMW	= 448,
    SB	= 449,
    SC_D	= 450,
    SC_D_AQ	= 451,
    SC_D_AQ_RL	= 452,
    SC_D_RL	= 453,
    SC_W	= 454,
    SC_W_AQ	= 455,
    SC_W_AQ_RL	= 456,
    SC_W_RL	= 457,
    SD	= 458,
    SFENCE_VMA	= 459,
    SH	= 460,
    SLL	= 461,
    SLLI	= 462,
    SLLIW	= 463,
    SLLW	= 464,
    SLT	= 465,
    SLTI	= 466,
    SLTIU	= 467,
    SLTU	= 468,
    SRA	= 469,
    SRAI	= 470,
    SRAIW	= 471,
    SRAW	= 472,
    SRET	= 473,
    SRL	= 474,
    SRLI	= 475,
    SRLIW	= 476,
    SRLW	= 477,
    SUB	= 478,
    SUBW	= 479,
    SW	= 480,
    UNIMP	= 481,
    URET	= 482,
    WFI	= 483,
    XOR	= 484,
    XORI	= 485,
    INSTRUCTION_LIST_END = 486
  };

} // end RISCV namespace
} // end llvm namespace
#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC
namespace llvm_ks {

static const MCPhysReg ImplicitList1[] = { RISCV::X2, 0 };
static const MCPhysReg ImplicitList2[] = { RISCV::X1, 0 };

static const MCOperandInfo OperandInfo2[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo3[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo4[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo5[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo6[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo7[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo8[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo9[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo10[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo11[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo12[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo13[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo23[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo30[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { RISCV::GPRTCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo50[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo54[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo55[] = { { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo56[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo57[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo58[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo59[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo60[] = { { RISCV::FPR64CRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo61[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo62[] = { { RISCV::FPR32CRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo63[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo64[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo65[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo66[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo67[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo68[] = { { RISCV::GPRNoX0X2RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo69[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo70[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo71[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo72[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo73[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo74[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo75[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo76[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo77[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo78[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo79[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo80[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo81[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo82[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo83[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo84[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo85[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo86[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo87[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo88[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };

extern const MCInstrDesc RISCVInsts[] = {
  { 0,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #0 = PHI
  { 1,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1 = INLINEASM
  { 2,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2 = INLINEASM_BR
  { 3,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #3 = CFI_INSTRUCTION
  { 4,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #4 = EH_LABEL
  { 5,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #5 = GC_LABEL
  { 6,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #6 = ANNOTATION_LABEL
  { 7,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #7 = KILL
  { 8,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo4, -1 ,nullptr },  // Inst #8 = EXTRACT_SUBREG
  { 9,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #9 = INSERT_SUBREG
  { 10,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #10 = IMPLICIT_DEF
  { 11,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo6, -1 ,nullptr },  // Inst #11 = SUBREG_TO_REG
  { 12,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo4, -1 ,nullptr },  // Inst #12 = COPY_TO_REGCLASS
  { 13,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #13 = DBG_VALUE
  { 14,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #14 = DBG_LABEL
  { 15,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #15 = REG_SEQUENCE
  { 16,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #16 = COPY
  { 17,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #17 = BUNDLE
  { 18,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #18 = LIFETIME_START
  { 19,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #19 = LIFETIME_END
  { 20,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo8, -1 ,nullptr },  // Inst #20 = STACKMAP
  { 21,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #21 = FENTRY_CALL
  { 22,	6,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo9, -1 ,nullptr },  // Inst #22 = PATCHPOINT
  { 23,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo10, -1 ,nullptr },  // Inst #23 = LOAD_STACK_GUARD
  { 24,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #24 = STATEPOINT
  { 25,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #25 = LOCAL_ESCAPE
  { 26,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #26 = FAULTING_OP
  { 27,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #27 = PATCHABLE_OP
  { 28,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #28 = PATCHABLE_FUNCTION_ENTER
  { 29,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #29 = PATCHABLE_RET
  { 30,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #30 = PATCHABLE_FUNCTION_EXIT
  { 31,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #31 = PATCHABLE_TAIL_CALL
  { 32,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #32 = PATCHABLE_EVENT_CALL
  { 33,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #33 = PATCHABLE_TYPED_EVENT_CALL
  { 34,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #34 = ICALL_BRANCH_FUNNEL
  { 35,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #35 = G_ADD
  { 36,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #36 = G_SUB
  { 37,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #37 = G_MUL
  { 38,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #38 = G_SDIV
  { 39,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #39 = G_UDIV
  { 40,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #40 = G_SREM
  { 41,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #41 = G_UREM
  { 42,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #42 = G_AND
  { 43,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #43 = G_OR
  { 44,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #44 = G_XOR
  { 45,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #45 = G_IMPLICIT_DEF
  { 46,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #46 = G_PHI
  { 47,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #47 = G_FRAME_INDEX
  { 48,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #48 = G_GLOBAL_VALUE
  { 49,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #49 = G_EXTRACT
  { 50,	2,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #50 = G_UNMERGE_VALUES
  { 51,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #51 = G_INSERT
  { 52,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #52 = G_MERGE_VALUES
  { 53,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #53 = G_BUILD_VECTOR
  { 54,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #54 = G_BUILD_VECTOR_TRUNC
  { 55,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #55 = G_CONCAT_VECTORS
  { 56,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #56 = G_PTRTOINT
  { 57,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #57 = G_INTTOPTR
  { 58,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #58 = G_BITCAST
  { 59,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #59 = G_INTRINSIC_TRUNC
  { 60,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #60 = G_INTRINSIC_ROUND
  { 61,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #61 = G_LOAD
  { 62,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #62 = G_SEXTLOAD
  { 63,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #63 = G_ZEXTLOAD
  { 64,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #64 = G_STORE
  { 65,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #65 = G_ATOMIC_CMPXCHG_WITH_SUCCESS
  { 66,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #66 = G_ATOMIC_CMPXCHG
  { 67,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #67 = G_ATOMICRMW_XCHG
  { 68,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #68 = G_ATOMICRMW_ADD
  { 69,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #69 = G_ATOMICRMW_SUB
  { 70,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #70 = G_ATOMICRMW_AND
  { 71,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #71 = G_ATOMICRMW_NAND
  { 72,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #72 = G_ATOMICRMW_OR
  { 73,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #73 = G_ATOMICRMW_XOR
  { 74,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #74 = G_ATOMICRMW_MAX
  { 75,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #75 = G_ATOMICRMW_MIN
  { 76,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #76 = G_ATOMICRMW_UMAX
  { 77,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #77 = G_ATOMICRMW_UMIN
  { 78,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo8, -1 ,nullptr },  // Inst #78 = G_FENCE
  { 79,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #79 = G_BRCOND
  { 80,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #80 = G_BRINDIRECT
  { 81,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #81 = G_INTRINSIC
  { 82,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #82 = G_INTRINSIC_W_SIDE_EFFECTS
  { 83,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #83 = G_ANYEXT
  { 84,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #84 = G_TRUNC
  { 85,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #85 = G_CONSTANT
  { 86,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #86 = G_FCONSTANT
  { 87,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #87 = G_VASTART
  { 88,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #88 = G_VAARG
  { 89,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #89 = G_SEXT
  { 90,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #90 = G_ZEXT
  { 91,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #91 = G_SHL
  { 92,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #92 = G_LSHR
  { 93,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #93 = G_ASHR
  { 94,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #94 = G_ICMP
  { 95,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #95 = G_FCMP
  { 96,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #96 = G_SELECT
  { 97,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #97 = G_UADDO
  { 98,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #98 = G_UADDE
  { 99,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #99 = G_USUBO
  { 100,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #100 = G_USUBE
  { 101,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #101 = G_SADDO
  { 102,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #102 = G_SADDE
  { 103,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #103 = G_SSUBO
  { 104,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #104 = G_SSUBE
  { 105,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #105 = G_UMULO
  { 106,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #106 = G_SMULO
  { 107,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #107 = G_UMULH
  { 108,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #108 = G_SMULH
  { 109,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #109 = G_FADD
  { 110,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #110 = G_FSUB
  { 111,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #111 = G_FMUL
  { 112,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #112 = G_FMA
  { 113,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #113 = G_FDIV
  { 114,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #114 = G_FREM
  { 115,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #115 = G_FPOW
  { 116,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #116 = G_FEXP
  { 117,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #117 = G_FEXP2
  { 118,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #118 = G_FLOG
  { 119,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #119 = G_FLOG2
  { 120,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #120 = G_FLOG10
  { 121,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #121 = G_FNEG
  { 122,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #122 = G_FPEXT
  { 123,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #123 = G_FPTRUNC
  { 124,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #124 = G_FPTOSI
  { 125,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #125 = G_FPTOUI
  { 126,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #126 = G_SITOFP
  { 127,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #127 = G_UITOFP
  { 128,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #128 = G_FABS
  { 129,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #129 = G_FCOPYSIGN
  { 130,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #130 = G_FCANONICALIZE
  { 131,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #131 = G_FMINNUM
  { 132,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #132 = G_FMAXNUM
  { 133,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #133 = G_FMINNUM_IEEE
  { 134,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #134 = G_FMAXNUM_IEEE
  { 135,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #135 = G_FMINIMUM
  { 136,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #136 = G_FMAXIMUM
  { 137,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #137 = G_GEP
  { 138,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #138 = G_PTR_MASK
  { 139,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #139 = G_SMIN
  { 140,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #140 = G_SMAX
  { 141,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #141 = G_UMIN
  { 142,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #142 = G_UMAX
  { 143,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #143 = G_BR
  { 144,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #144 = G_BRJT
  { 145,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #145 = G_INSERT_VECTOR_ELT
  { 146,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #146 = G_EXTRACT_VECTOR_ELT
  { 147,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #147 = G_SHUFFLE_VECTOR
  { 148,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #148 = G_CTTZ
  { 149,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #149 = G_CTTZ_ZERO_UNDEF
  { 150,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #150 = G_CTLZ
  { 151,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #151 = G_CTLZ_ZERO_UNDEF
  { 152,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #152 = G_CTPOP
  { 153,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #153 = G_BSWAP
  { 154,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #154 = G_FCEIL
  { 155,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #155 = G_FCOS
  { 156,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #156 = G_FSIN
  { 157,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #157 = G_FSQRT
  { 158,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #158 = G_FFLOOR
  { 159,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #159 = G_FRINT
  { 160,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #160 = G_FNEARBYINT
  { 161,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #161 = G_ADDRSPACE_CAST
  { 162,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #162 = G_BLOCK_ADDR
  { 163,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #163 = G_JUMP_TABLE
  { 164,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo8, -1 ,nullptr },  // Inst #164 = ADJCALLSTACKDOWN
  { 165,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo8, -1 ,nullptr },  // Inst #165 = ADJCALLSTACKUP
  { 166,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #166 = BuildPairF64Pseudo
  { 167,	4,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #167 = PseudoAddTPRel
  { 168,	5,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #168 = PseudoAtomicLoadNand32
  { 169,	5,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #169 = PseudoAtomicLoadNand64
  { 170,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #170 = PseudoBR
  { 171,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, ImplicitList2, OperandInfo35, -1 ,nullptr },  // Inst #171 = PseudoBRIND
  { 172,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList2, OperandInfo2, -1 ,nullptr },  // Inst #172 = PseudoCALL
  { 173,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList2, OperandInfo36, -1 ,nullptr },  // Inst #173 = PseudoCALLIndirect
  { 174,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #174 = PseudoCALLReg
  { 175,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #175 = PseudoCmpXchg32
  { 176,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #176 = PseudoCmpXchg64
  { 177,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #177 = PseudoFLD
  { 178,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #178 = PseudoFLW
  { 179,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #179 = PseudoFSD
  { 180,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #180 = PseudoFSW
  { 181,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #181 = PseudoLA
  { 182,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #182 = PseudoLA_TLS_GD
  { 183,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #183 = PseudoLA_TLS_IE
  { 184,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #184 = PseudoLB
  { 185,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #185 = PseudoLBU
  { 186,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #186 = PseudoLD
  { 187,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #187 = PseudoLH
  { 188,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #188 = PseudoLHU
  { 189,	2,	1,	32,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #189 = PseudoLI
  { 190,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #190 = PseudoLLA
  { 191,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #191 = PseudoLW
  { 192,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #192 = PseudoLWU
  { 193,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #193 = PseudoMaskedAtomicLoadAdd32
  { 194,	8,	3,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #194 = PseudoMaskedAtomicLoadMax32
  { 195,	8,	3,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #195 = PseudoMaskedAtomicLoadMin32
  { 196,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #196 = PseudoMaskedAtomicLoadNand32
  { 197,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #197 = PseudoMaskedAtomicLoadSub32
  { 198,	7,	3,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #198 = PseudoMaskedAtomicLoadUMax32
  { 199,	7,	3,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #199 = PseudoMaskedAtomicLoadUMin32
  { 200,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #200 = PseudoMaskedAtomicSwap32
  { 201,	7,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #201 = PseudoMaskedCmpXchg32
  { 202,	0,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #202 = PseudoRET
  { 203,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #203 = PseudoSB
  { 204,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #204 = PseudoSD
  { 205,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #205 = PseudoSH
  { 206,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #206 = PseudoSW
  { 207,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList1, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #207 = PseudoTAIL
  { 208,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList1, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #208 = PseudoTAILIndirect
  { 209,	2,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #209 = ReadCycleWide
  { 210,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #210 = Select_FPR32_Using_CC_GPR
  { 211,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #211 = Select_FPR64_Using_CC_GPR
  { 212,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #212 = Select_GPR_Using_CC_GPR
  { 213,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #213 = SplitF64Pseudo
  { 214,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #214 = ADD
  { 215,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #215 = ADDI
  { 216,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #216 = ADDIW
  { 217,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #217 = ADDW
  { 218,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #218 = AMOADD_D
  { 219,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #219 = AMOADD_D_AQ
  { 220,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #220 = AMOADD_D_AQ_RL
  { 221,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #221 = AMOADD_D_RL
  { 222,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #222 = AMOADD_W
  { 223,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #223 = AMOADD_W_AQ
  { 224,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #224 = AMOADD_W_AQ_RL
  { 225,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #225 = AMOADD_W_RL
  { 226,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #226 = AMOAND_D
  { 227,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #227 = AMOAND_D_AQ
  { 228,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #228 = AMOAND_D_AQ_RL
  { 229,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #229 = AMOAND_D_RL
  { 230,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #230 = AMOAND_W
  { 231,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #231 = AMOAND_W_AQ
  { 232,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #232 = AMOAND_W_AQ_RL
  { 233,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #233 = AMOAND_W_RL
  { 234,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #234 = AMOMAXU_D
  { 235,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #235 = AMOMAXU_D_AQ
  { 236,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #236 = AMOMAXU_D_AQ_RL
  { 237,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #237 = AMOMAXU_D_RL
  { 238,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #238 = AMOMAXU_W
  { 239,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #239 = AMOMAXU_W_AQ
  { 240,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #240 = AMOMAXU_W_AQ_RL
  { 241,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #241 = AMOMAXU_W_RL
  { 242,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #242 = AMOMAX_D
  { 243,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #243 = AMOMAX_D_AQ
  { 244,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #244 = AMOMAX_D_AQ_RL
  { 245,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #245 = AMOMAX_D_RL
  { 246,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #246 = AMOMAX_W
  { 247,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #247 = AMOMAX_W_AQ
  { 248,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #248 = AMOMAX_W_AQ_RL
  { 249,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #249 = AMOMAX_W_RL
  { 250,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #250 = AMOMINU_D
  { 251,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #251 = AMOMINU_D_AQ
  { 252,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #252 = AMOMINU_D_AQ_RL
  { 253,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #253 = AMOMINU_D_RL
  { 254,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #254 = AMOMINU_W
  { 255,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #255 = AMOMINU_W_AQ
  { 256,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #256 = AMOMINU_W_AQ_RL
  { 257,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #257 = AMOMINU_W_RL
  { 258,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #258 = AMOMIN_D
  { 259,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #259 = AMOMIN_D_AQ
  { 260,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #260 = AMOMIN_D_AQ_RL
  { 261,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #261 = AMOMIN_D_RL
  { 262,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #262 = AMOMIN_W
  { 263,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #263 = AMOMIN_W_AQ
  { 264,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #264 = AMOMIN_W_AQ_RL
  { 265,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #265 = AMOMIN_W_RL
  { 266,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #266 = AMOOR_D
  { 267,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #267 = AMOOR_D_AQ
  { 268,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #268 = AMOOR_D_AQ_RL
  { 269,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #269 = AMOOR_D_RL
  { 270,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #270 = AMOOR_W
  { 271,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #271 = AMOOR_W_AQ
  { 272,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #272 = AMOOR_W_AQ_RL
  { 273,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #273 = AMOOR_W_RL
  { 274,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #274 = AMOSWAP_D
  { 275,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #275 = AMOSWAP_D_AQ
  { 276,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #276 = AMOSWAP_D_AQ_RL
  { 277,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #277 = AMOSWAP_D_RL
  { 278,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #278 = AMOSWAP_W
  { 279,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #279 = AMOSWAP_W_AQ
  { 280,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #280 = AMOSWAP_W_AQ_RL
  { 281,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #281 = AMOSWAP_W_RL
  { 282,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #282 = AMOXOR_D
  { 283,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #283 = AMOXOR_D_AQ
  { 284,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #284 = AMOXOR_D_AQ_RL
  { 285,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #285 = AMOXOR_D_RL
  { 286,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #286 = AMOXOR_W
  { 287,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #287 = AMOXOR_W_AQ
  { 288,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #288 = AMOXOR_W_AQ_RL
  { 289,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #289 = AMOXOR_W_RL
  { 290,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #290 = AND
  { 291,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #291 = ANDI
  { 292,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #292 = AUIPC
  { 293,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #293 = BEQ
  { 294,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #294 = BGE
  { 295,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #295 = BGEU
  { 296,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #296 = BLT
  { 297,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #297 = BLTU
  { 298,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #298 = BNE
  { 299,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #299 = CSRRC
  { 300,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #300 = CSRRCI
  { 301,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #301 = CSRRS
  { 302,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #302 = CSRRSI
  { 303,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #303 = CSRRW
  { 304,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #304 = CSRRWI
  { 305,	3,	1,	2,	0,	0, 0x8ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #305 = C_ADD
  { 306,	3,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #306 = C_ADDI
  { 307,	3,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #307 = C_ADDI16SP
  { 308,	3,	1,	2,	0,	0, 0xbULL, ImplicitList1, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #308 = C_ADDI4SPN
  { 309,	3,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #309 = C_ADDIW
  { 310,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #310 = C_ADDW
  { 311,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #311 = C_AND
  { 312,	3,	1,	2,	0,	0, 0xfULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #312 = C_ANDI
  { 313,	2,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #313 = C_BEQZ
  { 314,	2,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #314 = C_BNEZ
  { 315,	0,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #315 = C_EBREAK
  { 316,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0xcULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #316 = C_FLD
  { 317,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x9ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #317 = C_FLDSP
  { 318,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0xcULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #318 = C_FLW
  { 319,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x9ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #319 = C_FLWSP
  { 320,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xdULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #320 = C_FSD
  { 321,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xaULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #321 = C_FSDSP
  { 322,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xdULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #322 = C_FSW
  { 323,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xaULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #323 = C_FSWSP
  { 324,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x10ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #324 = C_J
  { 325,	1,	0,	2,	0,	0|(1ULL<<MCID::Call), 0x10ULL, nullptr, ImplicitList2, OperandInfo2, -1 ,nullptr },  // Inst #325 = C_JAL
  { 326,	1,	0,	2,	0,	0|(1ULL<<MCID::Call), 0x8ULL, nullptr, ImplicitList2, OperandInfo64, -1 ,nullptr },  // Inst #326 = C_JALR
  { 327,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x8ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #327 = C_JR
  { 328,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0xcULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #328 = C_LD
  { 329,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x9ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #329 = C_LDSP
  { 330,	2,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #330 = C_LI
  { 331,	2,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #331 = C_LUI
  { 332,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0xcULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #332 = C_LW
  { 333,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x9ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #333 = C_LWSP
  { 334,	2,	1,	2,	0,	0, 0x8ULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #334 = C_MV
  { 335,	0,	0,	2,	0,	0, 0x9ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #335 = C_NOP
  { 336,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #336 = C_OR
  { 337,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xdULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #337 = C_SD
  { 338,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xaULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #338 = C_SDSP
  { 339,	3,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #339 = C_SLLI
  { 340,	3,	1,	2,	0,	0, 0xfULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #340 = C_SRAI
  { 341,	3,	1,	2,	0,	0, 0xfULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #341 = C_SRLI
  { 342,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #342 = C_SUB
  { 343,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #343 = C_SUBW
  { 344,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xdULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #344 = C_SW
  { 345,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xaULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #345 = C_SWSP
  { 346,	0,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x11ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #346 = C_UNIMP
  { 347,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #347 = C_XOR
  { 348,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #348 = DIV
  { 349,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #349 = DIVU
  { 350,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #350 = DIVUW
  { 351,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #351 = DIVW
  { 352,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #352 = EBREAK
  { 353,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #353 = ECALL
  { 354,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #354 = FADD_D
  { 355,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #355 = FADD_S
  { 356,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #356 = FCLASS_D
  { 357,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #357 = FCLASS_S
  { 358,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #358 = FCVT_D_L
  { 359,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #359 = FCVT_D_LU
  { 360,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #360 = FCVT_D_S
  { 361,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #361 = FCVT_D_W
  { 362,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #362 = FCVT_D_WU
  { 363,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #363 = FCVT_LU_D
  { 364,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #364 = FCVT_LU_S
  { 365,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #365 = FCVT_L_D
  { 366,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #366 = FCVT_L_S
  { 367,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #367 = FCVT_S_D
  { 368,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #368 = FCVT_S_L
  { 369,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #369 = FCVT_S_LU
  { 370,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #370 = FCVT_S_W
  { 371,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #371 = FCVT_S_WU
  { 372,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #372 = FCVT_WU_D
  { 373,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #373 = FCVT_WU_S
  { 374,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #374 = FCVT_W_D
  { 375,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #375 = FCVT_W_S
  { 376,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #376 = FDIV_D
  { 377,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #377 = FDIV_S
  { 378,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #378 = FENCE
  { 379,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #379 = FENCE_I
  { 380,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #380 = FENCE_TSO
  { 381,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #381 = FEQ_D
  { 382,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #382 = FEQ_S
  { 383,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #383 = FLD
  { 384,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #384 = FLE_D
  { 385,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #385 = FLE_S
  { 386,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #386 = FLT_D
  { 387,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #387 = FLT_S
  { 388,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #388 = FLW
  { 389,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #389 = FMADD_D
  { 390,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #390 = FMADD_S
  { 391,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #391 = FMAX_D
  { 392,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #392 = FMAX_S
  { 393,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #393 = FMIN_D
  { 394,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #394 = FMIN_S
  { 395,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #395 = FMSUB_D
  { 396,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #396 = FMSUB_S
  { 397,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #397 = FMUL_D
  { 398,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #398 = FMUL_S
  { 399,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #399 = FMV_D_X
  { 400,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #400 = FMV_W_X
  { 401,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #401 = FMV_X_D
  { 402,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #402 = FMV_X_W
  { 403,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #403 = FNMADD_D
  { 404,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #404 = FNMADD_S
  { 405,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #405 = FNMSUB_D
  { 406,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #406 = FNMSUB_S
  { 407,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #407 = FSD
  { 408,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #408 = FSGNJN_D
  { 409,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #409 = FSGNJN_S
  { 410,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #410 = FSGNJX_D
  { 411,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #411 = FSGNJX_S
  { 412,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #412 = FSGNJ_D
  { 413,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #413 = FSGNJ_S
  { 414,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #414 = FSQRT_D
  { 415,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo88, -1 ,nullptr },  // Inst #415 = FSQRT_S
  { 416,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #416 = FSUB_D
  { 417,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #417 = FSUB_S
  { 418,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #418 = FSW
  { 419,	2,	1,	4,	0,	0|(1ULL<<MCID::Call), 0x7ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #419 = JAL
  { 420,	3,	1,	4,	0,	0|(1ULL<<MCID::Call), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #420 = JALR
  { 421,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #421 = LB
  { 422,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #422 = LBU
  { 423,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #423 = LD
  { 424,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #424 = LH
  { 425,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #425 = LHU
  { 426,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #426 = LR_D
  { 427,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #427 = LR_D_AQ
  { 428,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #428 = LR_D_AQ_RL
  { 429,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #429 = LR_D_RL
  { 430,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #430 = LR_W
  { 431,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #431 = LR_W_AQ
  { 432,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #432 = LR_W_AQ_RL
  { 433,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #433 = LR_W_RL
  { 434,	2,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #434 = LUI
  { 435,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #435 = LW
  { 436,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #436 = LWU
  { 437,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #437 = MRET
  { 438,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #438 = MUL
  { 439,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #439 = MULH
  { 440,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #440 = MULHSU
  { 441,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #441 = MULHU
  { 442,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #442 = MULW
  { 443,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #443 = OR
  { 444,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #444 = ORI
  { 445,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #445 = REM
  { 446,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #446 = REMU
  { 447,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #447 = REMUW
  { 448,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #448 = REMW
  { 449,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #449 = SB
  { 450,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #450 = SC_D
  { 451,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #451 = SC_D_AQ
  { 452,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #452 = SC_D_AQ_RL
  { 453,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #453 = SC_D_RL
  { 454,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #454 = SC_W
  { 455,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #455 = SC_W_AQ
  { 456,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #456 = SC_W_AQ_RL
  { 457,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #457 = SC_W_RL
  { 458,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #458 = SD
  { 459,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #459 = SFENCE_VMA
  { 460,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #460 = SH
  { 461,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #461 = SLL
  { 462,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #462 = SLLI
  { 463,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #463 = SLLIW
  { 464,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #464 = SLLW
  { 465,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #465 = SLT
  { 466,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #466 = SLTI
  { 467,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #467 = SLTIU
  { 468,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #468 = SLTU
  { 469,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #469 = SRA
  { 470,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #470 = SRAI
  { 471,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #471 = SRAIW
  { 472,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #472 = SRAW
  { 473,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #473 = SRET
  { 474,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #474 = SRL
  { 475,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #475 = SRLI
  { 476,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #476 = SRLIW
  { 477,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #477 = SRLW
  { 478,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #478 = SUB
  { 479,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #479 = SUBW
  { 480,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #480 = SW
  { 481,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #481 = UNIMP
  { 482,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #482 = URET
  { 483,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #483 = WFI
  { 484,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #484 = XOR
  { 485,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x3ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #485 = XORI
};

extern const char RISCVInstrNameData[] = {
  /* 0 */ 'G', '_', 'F', 'L', 'O', 'G', '1', '0', 0,
  /* 9 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'S', 'u', 'b', '3', '2', 0,
  /* 37 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'A', 'd', 'd', '3', '2', 0,
  /* 65 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'N', 'a', 'n', 'd', '3', '2', 0,
  /* 94 */ 'P', 's', 'e', 'u', 'd', 'o', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'N', 'a', 'n', 'd', '3', '2', 0,
  /* 117 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'C', 'm', 'p', 'X', 'c', 'h', 'g', '3', '2', 0,
  /* 139 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'm', 'p', 'X', 'c', 'h', 'g', '3', '2', 0,
  /* 155 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'U', 'M', 'i', 'n', '3', '2', 0,
  /* 184 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'M', 'i', 'n', '3', '2', 0,
  /* 212 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'S', 'w', 'a', 'p', '3', '2', 0,
  /* 237 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'U', 'M', 'a', 'x', '3', '2', 0,
  /* 266 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'M', 'a', 'x', '3', '2', 0,
  /* 294 */ 'G', '_', 'F', 'L', 'O', 'G', '2', 0,
  /* 302 */ 'G', '_', 'F', 'E', 'X', 'P', '2', 0,
  /* 310 */ 'P', 's', 'e', 'u', 'd', 'o', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'N', 'a', 'n', 'd', '6', '4', 0,
  /* 333 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'm', 'p', 'X', 'c', 'h', 'g', '6', '4', 0,
  /* 349 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'L', 'A', 0,
  /* 359 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'A', 0,
  /* 368 */ 'G', '_', 'F', 'M', 'A', 0,
  /* 374 */ 'S', 'F', 'E', 'N', 'C', 'E', '_', 'V', 'M', 'A', 0,
  /* 385 */ 'S', 'R', 'A', 0,
  /* 389 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'B', 0,
  /* 398 */ 'P', 's', 'e', 'u', 'd', 'o', 'S', 'B', 0,
  /* 407 */ 'G', '_', 'F', 'S', 'U', 'B', 0,
  /* 414 */ 'C', '_', 'S', 'U', 'B', 0,
  /* 420 */ 'G', '_', 'S', 'U', 'B', 0,
  /* 426 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'S', 'U', 'B', 0,
  /* 442 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', 0,
  /* 454 */ 'G', '_', 'F', 'P', 'T', 'R', 'U', 'N', 'C', 0,
  /* 464 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', '_', 'T', 'R', 'U', 'N', 'C', 0,
  /* 482 */ 'G', '_', 'T', 'R', 'U', 'N', 'C', 0,
  /* 490 */ 'G', '_', 'B', 'U', 'I', 'L', 'D', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'T', 'R', 'U', 'N', 'C', 0,
  /* 511 */ 'A', 'U', 'I', 'P', 'C', 0,
  /* 517 */ 'C', 'S', 'R', 'R', 'C', 0,
  /* 523 */ 'G', '_', 'S', 'E', 'X', 'T', 'L', 'O', 'A', 'D', 0,
  /* 534 */ 'G', '_', 'Z', 'E', 'X', 'T', 'L', 'O', 'A', 'D', 0,
  /* 545 */ 'G', '_', 'L', 'O', 'A', 'D', 0,
  /* 552 */ 'G', '_', 'F', 'A', 'D', 'D', 0,
  /* 559 */ 'C', '_', 'A', 'D', 'D', 0,
  /* 565 */ 'G', '_', 'A', 'D', 'D', 0,
  /* 571 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'A', 'D', 'D', 0,
  /* 587 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'A', '_', 'T', 'L', 'S', '_', 'G', 'D', 0,
  /* 603 */ 'C', '_', 'F', 'L', 'D', 0,
  /* 609 */ 'P', 's', 'e', 'u', 'd', 'o', 'F', 'L', 'D', 0,
  /* 619 */ 'C', '_', 'L', 'D', 0,
  /* 624 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'D', 0,
  /* 633 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'N', 'A', 'N', 'D', 0,
  /* 650 */ 'C', '_', 'A', 'N', 'D', 0,
  /* 656 */ 'G', '_', 'A', 'N', 'D', 0,
  /* 662 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'A', 'N', 'D', 0,
  /* 678 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'E', 'N', 'D', 0,
  /* 691 */ 'P', 's', 'e', 'u', 'd', 'o', 'B', 'R', 'I', 'N', 'D', 0,
  /* 703 */ 'G', '_', 'B', 'R', 'C', 'O', 'N', 'D', 0,
  /* 712 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', '_', 'R', 'O', 'U', 'N', 'D', 0,
  /* 730 */ 'L', 'O', 'A', 'D', '_', 'S', 'T', 'A', 'C', 'K', '_', 'G', 'U', 'A', 'R', 'D', 0,
  /* 747 */ 'C', '_', 'F', 'S', 'D', 0,
  /* 753 */ 'P', 's', 'e', 'u', 'd', 'o', 'F', 'S', 'D', 0,
  /* 763 */ 'C', '_', 'S', 'D', 0,
  /* 768 */ 'P', 's', 'e', 'u', 'd', 'o', 'S', 'D', 0,
  /* 777 */ 'F', 'S', 'U', 'B', '_', 'D', 0,
  /* 784 */ 'F', 'M', 'S', 'U', 'B', '_', 'D', 0,
  /* 792 */ 'F', 'N', 'M', 'S', 'U', 'B', '_', 'D', 0,
  /* 801 */ 'S', 'C', '_', 'D', 0,
  /* 806 */ 'F', 'A', 'D', 'D', '_', 'D', 0,
  /* 813 */ 'F', 'M', 'A', 'D', 'D', '_', 'D', 0,
  /* 821 */ 'F', 'N', 'M', 'A', 'D', 'D', '_', 'D', 0,
  /* 830 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', 0,
  /* 839 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', 0,
  /* 848 */ 'F', 'L', 'E', '_', 'D', 0,
  /* 854 */ 'F', 'S', 'G', 'N', 'J', '_', 'D', 0,
  /* 862 */ 'F', 'M', 'U', 'L', '_', 'D', 0,
  /* 869 */ 'F', 'C', 'V', 'T', '_', 'L', '_', 'D', 0,
  /* 878 */ 'F', 'M', 'I', 'N', '_', 'D', 0,
  /* 885 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', 0,
  /* 894 */ 'F', 'S', 'G', 'N', 'J', 'N', '_', 'D', 0,
  /* 903 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', 0,
  /* 913 */ 'F', 'E', 'Q', '_', 'D', 0,
  /* 919 */ 'L', 'R', '_', 'D', 0,
  /* 924 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', 0,
  /* 932 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', 0,
  /* 941 */ 'F', 'C', 'L', 'A', 'S', 'S', '_', 'D', 0,
  /* 950 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'D', 0,
  /* 959 */ 'F', 'L', 'T', '_', 'D', 0,
  /* 965 */ 'F', 'S', 'Q', 'R', 'T', '_', 'D', 0,
  /* 973 */ 'F', 'C', 'V', 'T', '_', 'L', 'U', '_', 'D', 0,
  /* 983 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', 0,
  /* 993 */ 'F', 'C', 'V', 'T', '_', 'W', 'U', '_', 'D', 0,
  /* 1003 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', 0,
  /* 1013 */ 'F', 'D', 'I', 'V', '_', 'D', 0,
  /* 1020 */ 'F', 'C', 'V', 'T', '_', 'W', '_', 'D', 0,
  /* 1029 */ 'F', 'M', 'A', 'X', '_', 'D', 0,
  /* 1036 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', 0,
  /* 1045 */ 'F', 'S', 'G', 'N', 'J', 'X', '_', 'D', 0,
  /* 1054 */ 'F', 'M', 'V', '_', 'X', '_', 'D', 0,
  /* 1062 */ 'G', '_', 'S', 'S', 'U', 'B', 'E', 0,
  /* 1070 */ 'G', '_', 'U', 'S', 'U', 'B', 'E', 0,
  /* 1078 */ 'G', '_', 'F', 'E', 'N', 'C', 'E', 0,
  /* 1086 */ 'R', 'E', 'G', '_', 'S', 'E', 'Q', 'U', 'E', 'N', 'C', 'E', 0,
  /* 1099 */ 'G', '_', 'S', 'A', 'D', 'D', 'E', 0,
  /* 1107 */ 'G', '_', 'U', 'A', 'D', 'D', 'E', 0,
  /* 1115 */ 'G', '_', 'F', 'M', 'I', 'N', 'N', 'U', 'M', '_', 'I', 'E', 'E', 'E', 0,
  /* 1130 */ 'G', '_', 'F', 'M', 'A', 'X', 'N', 'U', 'M', '_', 'I', 'E', 'E', 'E', 0,
  /* 1145 */ 'B', 'G', 'E', 0,
  /* 1149 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'A', '_', 'T', 'L', 'S', '_', 'I', 'E', 0,
  /* 1165 */ 'G', '_', 'J', 'U', 'M', 'P', '_', 'T', 'A', 'B', 'L', 'E', 0,
  /* 1178 */ 'B', 'U', 'N', 'D', 'L', 'E', 0,
  /* 1185 */ 'B', 'N', 'E', 0,
  /* 1189 */ 'L', 'O', 'C', 'A', 'L', '_', 'E', 'S', 'C', 'A', 'P', 'E', 0,
  /* 1202 */ 'G', '_', 'S', 'T', 'O', 'R', 'E', 0,
  /* 1210 */ 'D', 'B', 'G', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 1220 */ 'G', '_', 'G', 'L', 'O', 'B', 'A', 'L', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 1235 */ 'G', '_', 'F', 'C', 'A', 'N', 'O', 'N', 'I', 'C', 'A', 'L', 'I', 'Z', 'E', 0,
  /* 1251 */ 'G', '_', 'C', 'T', 'L', 'Z', '_', 'Z', 'E', 'R', 'O', '_', 'U', 'N', 'D', 'E', 'F', 0,
  /* 1269 */ 'G', '_', 'C', 'T', 'T', 'Z', '_', 'Z', 'E', 'R', 'O', '_', 'U', 'N', 'D', 'E', 'F', 0,
  /* 1287 */ 'G', '_', 'I', 'M', 'P', 'L', 'I', 'C', 'I', 'T', '_', 'D', 'E', 'F', 0,
  /* 1302 */ 'G', '_', 'F', 'N', 'E', 'G', 0,
  /* 1309 */ 'E', 'X', 'T', 'R', 'A', 'C', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 1324 */ 'I', 'N', 'S', 'E', 'R', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 1338 */ 'S', 'U', 'B', 'R', 'E', 'G', '_', 'T', 'O', '_', 'R', 'E', 'G', 0,
  /* 1352 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', '_', 'C', 'M', 'P', 'X', 'C', 'H', 'G', 0,
  /* 1369 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'X', 'C', 'H', 'G', 0,
  /* 1386 */ 'G', '_', 'F', 'L', 'O', 'G', 0,
  /* 1393 */ 'G', '_', 'V', 'A', 'A', 'R', 'G', 0,
  /* 1401 */ 'G', '_', 'S', 'M', 'U', 'L', 'H', 0,
  /* 1409 */ 'G', '_', 'U', 'M', 'U', 'L', 'H', 0,
  /* 1417 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'H', 0,
  /* 1426 */ 'P', 's', 'e', 'u', 'd', 'o', 'S', 'H', 0,
  /* 1435 */ 'C', '_', 'S', 'R', 'A', 'I', 0,
  /* 1442 */ 'C', 'S', 'R', 'R', 'C', 'I', 0,
  /* 1449 */ 'C', '_', 'A', 'D', 'D', 'I', 0,
  /* 1456 */ 'C', '_', 'A', 'N', 'D', 'I', 0,
  /* 1463 */ 'W', 'F', 'I', 0,
  /* 1467 */ 'G', '_', 'P', 'H', 'I', 0,
  /* 1473 */ 'C', '_', 'S', 'L', 'L', 'I', 0,
  /* 1480 */ 'C', '_', 'S', 'R', 'L', 'I', 0,
  /* 1487 */ 'C', '_', 'L', 'I', 0,
  /* 1492 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'I', 0,
  /* 1501 */ 'X', 'O', 'R', 'I', 0,
  /* 1506 */ 'G', '_', 'F', 'P', 'T', 'O', 'S', 'I', 0,
  /* 1515 */ 'C', 'S', 'R', 'R', 'S', 'I', 0,
  /* 1522 */ 'S', 'L', 'T', 'I', 0,
  /* 1527 */ 'C', '_', 'L', 'U', 'I', 0,
  /* 1533 */ 'G', '_', 'F', 'P', 'T', 'O', 'U', 'I', 0,
  /* 1542 */ 'C', 'S', 'R', 'R', 'W', 'I', 0,
  /* 1549 */ 'F', 'E', 'N', 'C', 'E', '_', 'I', 0,
  /* 1557 */ 'C', '_', 'J', 0,
  /* 1561 */ 'C', '_', 'E', 'B', 'R', 'E', 'A', 'K', 0,
  /* 1570 */ 'G', '_', 'P', 'T', 'R', '_', 'M', 'A', 'S', 'K', 0,
  /* 1581 */ 'C', '_', 'J', 'A', 'L', 0,
  /* 1587 */ 'G', 'C', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 1596 */ 'D', 'B', 'G', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 1606 */ 'E', 'H', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 1615 */ 'A', 'N', 'N', 'O', 'T', 'A', 'T', 'I', 'O', 'N', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 1632 */ 'I', 'C', 'A', 'L', 'L', '_', 'B', 'R', 'A', 'N', 'C', 'H', '_', 'F', 'U', 'N', 'N', 'E', 'L', 0,
  /* 1652 */ 'G', '_', 'S', 'H', 'L', 0,
  /* 1658 */ 'P', 's', 'e', 'u', 'd', 'o', 'T', 'A', 'I', 'L', 0,
  /* 1669 */ 'G', '_', 'F', 'C', 'E', 'I', 'L', 0,
  /* 1677 */ 'E', 'C', 'A', 'L', 'L', 0,
  /* 1683 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'T', 'A', 'I', 'L', '_', 'C', 'A', 'L', 'L', 0,
  /* 1703 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'T', 'Y', 'P', 'E', 'D', '_', 'E', 'V', 'E', 'N', 'T', '_', 'C', 'A', 'L', 'L', 0,
  /* 1730 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'E', 'V', 'E', 'N', 'T', '_', 'C', 'A', 'L', 'L', 0,
  /* 1751 */ 'F', 'E', 'N', 'T', 'R', 'Y', '_', 'C', 'A', 'L', 'L', 0,
  /* 1763 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'A', 'L', 'L', 0,
  /* 1774 */ 'K', 'I', 'L', 'L', 0,
  /* 1779 */ 'S', 'L', 'L', 0,
  /* 1783 */ 'S', 'R', 'L', 0,
  /* 1787 */ 'S', 'C', '_', 'D', '_', 'R', 'L', 0,
  /* 1795 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'R', 'L', 0,
  /* 1807 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'R', 'L', 0,
  /* 1819 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'R', 'L', 0,
  /* 1831 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'R', 'L', 0,
  /* 1844 */ 'L', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 1852 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 1863 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 1875 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'R', 'L', 0,
  /* 1888 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'R', 'L', 0,
  /* 1901 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'R', 'L', 0,
  /* 1913 */ 'S', 'C', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1924 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1939 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1954 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1969 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1985 */ 'L', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1996 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2010 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2025 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2041 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2057 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2072 */ 'S', 'C', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2083 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2098 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2113 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2128 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2144 */ 'L', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2155 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2169 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2184 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2200 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2216 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2231 */ 'S', 'C', '_', 'W', '_', 'R', 'L', 0,
  /* 2239 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'R', 'L', 0,
  /* 2251 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'R', 'L', 0,
  /* 2263 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'R', 'L', 0,
  /* 2275 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'R', 'L', 0,
  /* 2288 */ 'L', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 2296 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 2307 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 2319 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'R', 'L', 0,
  /* 2332 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'R', 'L', 0,
  /* 2345 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'R', 'L', 0,
  /* 2357 */ 'G', '_', 'F', 'M', 'U', 'L', 0,
  /* 2364 */ 'G', '_', 'M', 'U', 'L', 0,
  /* 2370 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'L', 0,
  /* 2379 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'L', 0,
  /* 2388 */ 'G', '_', 'F', 'R', 'E', 'M', 0,
  /* 2395 */ 'G', '_', 'S', 'R', 'E', 'M', 0,
  /* 2402 */ 'G', '_', 'U', 'R', 'E', 'M', 0,
  /* 2409 */ 'I', 'N', 'L', 'I', 'N', 'E', 'A', 'S', 'M', 0,
  /* 2419 */ 'G', '_', 'F', 'M', 'I', 'N', 'I', 'M', 'U', 'M', 0,
  /* 2430 */ 'G', '_', 'F', 'M', 'A', 'X', 'I', 'M', 'U', 'M', 0,
  /* 2441 */ 'G', '_', 'F', 'M', 'I', 'N', 'N', 'U', 'M', 0,
  /* 2451 */ 'G', '_', 'F', 'M', 'A', 'X', 'N', 'U', 'M', 0,
  /* 2461 */ 'G', '_', 'F', 'C', 'O', 'P', 'Y', 'S', 'I', 'G', 'N', 0,
  /* 2473 */ 'G', '_', 'S', 'M', 'I', 'N', 0,
  /* 2480 */ 'G', '_', 'U', 'M', 'I', 'N', 0,
  /* 2487 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'U', 'M', 'I', 'N', 0,
  /* 2504 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'M', 'I', 'N', 0,
  /* 2520 */ 'G', '_', 'F', 'S', 'I', 'N', 0,
  /* 2527 */ 'C', 'F', 'I', '_', 'I', 'N', 'S', 'T', 'R', 'U', 'C', 'T', 'I', 'O', 'N', 0,
  /* 2543 */ 'C', '_', 'A', 'D', 'D', 'I', '4', 'S', 'P', 'N', 0,
  /* 2554 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'D', 'O', 'W', 'N', 0,
  /* 2571 */ 'G', '_', 'S', 'S', 'U', 'B', 'O', 0,
  /* 2579 */ 'G', '_', 'U', 'S', 'U', 'B', 'O', 0,
  /* 2587 */ 'G', '_', 'S', 'A', 'D', 'D', 'O', 0,
  /* 2595 */ 'G', '_', 'U', 'A', 'D', 'D', 'O', 0,
  /* 2603 */ 'G', '_', 'S', 'M', 'U', 'L', 'O', 0,
  /* 2611 */ 'G', '_', 'U', 'M', 'U', 'L', 'O', 0,
  /* 2619 */ 'F', 'E', 'N', 'C', 'E', '_', 'T', 'S', 'O', 0,
  /* 2629 */ 'S', 'T', 'A', 'C', 'K', 'M', 'A', 'P', 0,
  /* 2638 */ 'G', '_', 'B', 'S', 'W', 'A', 'P', 0,
  /* 2646 */ 'G', '_', 'G', 'E', 'P', 0,
  /* 2652 */ 'G', '_', 'S', 'I', 'T', 'O', 'F', 'P', 0,
  /* 2661 */ 'G', '_', 'U', 'I', 'T', 'O', 'F', 'P', 0,
  /* 2670 */ 'G', '_', 'F', 'C', 'M', 'P', 0,
  /* 2677 */ 'G', '_', 'I', 'C', 'M', 'P', 0,
  /* 2684 */ 'C', '_', 'U', 'N', 'I', 'M', 'P', 0,
  /* 2692 */ 'C', '_', 'N', 'O', 'P', 0,
  /* 2698 */ 'G', '_', 'C', 'T', 'P', 'O', 'P', 0,
  /* 2706 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'O', 'P', 0,
  /* 2719 */ 'F', 'A', 'U', 'L', 'T', 'I', 'N', 'G', '_', 'O', 'P', 0,
  /* 2731 */ 'C', '_', 'A', 'D', 'D', 'I', '1', '6', 'S', 'P', 0,
  /* 2742 */ 'C', '_', 'F', 'L', 'D', 'S', 'P', 0,
  /* 2750 */ 'C', '_', 'L', 'D', 'S', 'P', 0,
  /* 2757 */ 'C', '_', 'F', 'S', 'D', 'S', 'P', 0,
  /* 2765 */ 'C', '_', 'S', 'D', 'S', 'P', 0,
  /* 2772 */ 'C', '_', 'F', 'L', 'W', 'S', 'P', 0,
  /* 2780 */ 'C', '_', 'L', 'W', 'S', 'P', 0,
  /* 2787 */ 'C', '_', 'F', 'S', 'W', 'S', 'P', 0,
  /* 2795 */ 'C', '_', 'S', 'W', 'S', 'P', 0,
  /* 2802 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'U', 'P', 0,
  /* 2817 */ 'G', '_', 'F', 'E', 'X', 'P', 0,
  /* 2824 */ 'S', 'C', '_', 'D', '_', 'A', 'Q', 0,
  /* 2832 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'A', 'Q', 0,
  /* 2844 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'A', 'Q', 0,
  /* 2856 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'A', 'Q', 0,
  /* 2868 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'A', 'Q', 0,
  /* 2881 */ 'L', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 2889 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 2900 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 2912 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'A', 'Q', 0,
  /* 2925 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'A', 'Q', 0,
  /* 2938 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'A', 'Q', 0,
  /* 2950 */ 'S', 'C', '_', 'W', '_', 'A', 'Q', 0,
  /* 2958 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'A', 'Q', 0,
  /* 2970 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'A', 'Q', 0,
  /* 2982 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'A', 'Q', 0,
  /* 2994 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'A', 'Q', 0,
  /* 3007 */ 'L', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 3015 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 3026 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 3038 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'A', 'Q', 0,
  /* 3051 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'A', 'Q', 0,
  /* 3064 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'A', 'Q', 0,
  /* 3076 */ 'B', 'E', 'Q', 0,
  /* 3080 */ 'G', '_', 'B', 'R', 0,
  /* 3085 */ 'I', 'N', 'L', 'I', 'N', 'E', 'A', 'S', 'M', '_', 'B', 'R', 0,
  /* 3098 */ 'P', 's', 'e', 'u', 'd', 'o', 'B', 'R', 0,
  /* 3107 */ 'G', '_', 'B', 'L', 'O', 'C', 'K', '_', 'A', 'D', 'D', 'R', 0,
  /* 3120 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'F', 'U', 'N', 'C', 'T', 'I', 'O', 'N', '_', 'E', 'N', 'T', 'E', 'R', 0,
  /* 3145 */ 'G', '_', 'A', 'S', 'H', 'R', 0,
  /* 3152 */ 'G', '_', 'L', 'S', 'H', 'R', 0,
  /* 3159 */ 'C', '_', 'J', 'R', 0,
  /* 3164 */ 'C', '_', 'J', 'A', 'L', 'R', 0,
  /* 3171 */ 'G', '_', 'F', 'F', 'L', 'O', 'O', 'R', 0,
  /* 3180 */ 'G', '_', 'B', 'U', 'I', 'L', 'D', '_', 'V', 'E', 'C', 'T', 'O', 'R', 0,
  /* 3195 */ 'G', '_', 'S', 'H', 'U', 'F', 'F', 'L', 'E', '_', 'V', 'E', 'C', 'T', 'O', 'R', 0,
  /* 3212 */ 'C', '_', 'X', 'O', 'R', 0,
  /* 3218 */ 'G', '_', 'X', 'O', 'R', 0,
  /* 3224 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'X', 'O', 'R', 0,
  /* 3240 */ 'C', '_', 'O', 'R', 0,
  /* 3245 */ 'G', '_', 'O', 'R', 0,
  /* 3250 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'O', 'R', 0,
  /* 3265 */ 'S', 'e', 'l', 'e', 'c', 't', '_', 'F', 'P', 'R', '3', '2', '_', 'U', 's', 'i', 'n', 'g', '_', 'C', 'C', '_', 'G', 'P', 'R', 0,
  /* 3291 */ 'S', 'e', 'l', 'e', 'c', 't', '_', 'F', 'P', 'R', '6', '4', '_', 'U', 's', 'i', 'n', 'g', '_', 'C', 'C', '_', 'G', 'P', 'R', 0,
  /* 3317 */ 'S', 'e', 'l', 'e', 'c', 't', '_', 'G', 'P', 'R', '_', 'U', 's', 'i', 'n', 'g', '_', 'C', 'C', '_', 'G', 'P', 'R', 0,
  /* 3341 */ 'G', '_', 'I', 'N', 'T', 'T', 'O', 'P', 'T', 'R', 0,
  /* 3352 */ 'G', '_', 'F', 'A', 'B', 'S', 0,
  /* 3359 */ 'G', '_', 'U', 'N', 'M', 'E', 'R', 'G', 'E', '_', 'V', 'A', 'L', 'U', 'E', 'S', 0,
  /* 3376 */ 'G', '_', 'M', 'E', 'R', 'G', 'E', '_', 'V', 'A', 'L', 'U', 'E', 'S', 0,
  /* 3391 */ 'G', '_', 'F', 'C', 'O', 'S', 0,
  /* 3398 */ 'G', '_', 'C', 'O', 'N', 'C', 'A', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', 'S', 0,
  /* 3415 */ 'C', 'S', 'R', 'R', 'S', 0,
  /* 3421 */ 'C', 'O', 'P', 'Y', '_', 'T', 'O', '_', 'R', 'E', 'G', 'C', 'L', 'A', 'S', 'S', 0,
  /* 3438 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', '_', 'C', 'M', 'P', 'X', 'C', 'H', 'G', '_', 'W', 'I', 'T', 'H', '_', 'S', 'U', 'C', 'C', 'E', 'S', 'S', 0,
  /* 3468 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', '_', 'W', '_', 'S', 'I', 'D', 'E', '_', 'E', 'F', 'F', 'E', 'C', 'T', 'S', 0,
  /* 3495 */ 'F', 'S', 'U', 'B', '_', 'S', 0,
  /* 3502 */ 'F', 'M', 'S', 'U', 'B', '_', 'S', 0,
  /* 3510 */ 'F', 'N', 'M', 'S', 'U', 'B', '_', 'S', 0,
  /* 3519 */ 'F', 'A', 'D', 'D', '_', 'S', 0,
  /* 3526 */ 'F', 'M', 'A', 'D', 'D', '_', 'S', 0,
  /* 3534 */ 'F', 'N', 'M', 'A', 'D', 'D', '_', 'S', 0,
  /* 3543 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'S', 0,
  /* 3552 */ 'F', 'L', 'E', '_', 'S', 0,
  /* 3558 */ 'F', 'S', 'G', 'N', 'J', '_', 'S', 0,
  /* 3566 */ 'F', 'M', 'U', 'L', '_', 'S', 0,
  /* 3573 */ 'F', 'C', 'V', 'T', '_', 'L', '_', 'S', 0,
  /* 3582 */ 'F', 'M', 'I', 'N', '_', 'S', 0,
  /* 3589 */ 'F', 'S', 'G', 'N', 'J', 'N', '_', 'S', 0,
  /* 3598 */ 'F', 'E', 'Q', '_', 'S', 0,
  /* 3604 */ 'F', 'C', 'L', 'A', 'S', 'S', '_', 'S', 0,
  /* 3613 */ 'F', 'L', 'T', '_', 'S', 0,
  /* 3619 */ 'F', 'S', 'Q', 'R', 'T', '_', 'S', 0,
  /* 3627 */ 'F', 'C', 'V', 'T', '_', 'L', 'U', '_', 'S', 0,
  /* 3637 */ 'F', 'C', 'V', 'T', '_', 'W', 'U', '_', 'S', 0,
  /* 3647 */ 'F', 'D', 'I', 'V', '_', 'S', 0,
  /* 3654 */ 'F', 'C', 'V', 'T', '_', 'W', '_', 'S', 0,
  /* 3663 */ 'F', 'M', 'A', 'X', '_', 'S', 0,
  /* 3670 */ 'F', 'S', 'G', 'N', 'J', 'X', '_', 'S', 0,
  /* 3679 */ 'G', '_', 'E', 'X', 'T', 'R', 'A', 'C', 'T', 0,
  /* 3689 */ 'G', '_', 'S', 'E', 'L', 'E', 'C', 'T', 0,
  /* 3698 */ 'G', '_', 'B', 'R', 'I', 'N', 'D', 'I', 'R', 'E', 'C', 'T', 0,
  /* 3711 */ 'M', 'R', 'E', 'T', 0,
  /* 3716 */ 'S', 'R', 'E', 'T', 0,
  /* 3721 */ 'U', 'R', 'E', 'T', 0,
  /* 3726 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'R', 'E', 'T', 0,
  /* 3740 */ 'P', 's', 'e', 'u', 'd', 'o', 'R', 'E', 'T', 0,
  /* 3750 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'F', 'U', 'N', 'C', 'T', 'I', 'O', 'N', '_', 'E', 'X', 'I', 'T', 0,
  /* 3774 */ 'G', '_', 'B', 'R', 'J', 'T', 0,
  /* 3781 */ 'B', 'L', 'T', 0,
  /* 3785 */ 'G', '_', 'E', 'X', 'T', 'R', 'A', 'C', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'E', 'L', 'T', 0,
  /* 3806 */ 'G', '_', 'I', 'N', 'S', 'E', 'R', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'E', 'L', 'T', 0,
  /* 3826 */ 'S', 'L', 'T', 0,
  /* 3830 */ 'G', '_', 'F', 'C', 'O', 'N', 'S', 'T', 'A', 'N', 'T', 0,
  /* 3842 */ 'G', '_', 'C', 'O', 'N', 'S', 'T', 'A', 'N', 'T', 0,
  /* 3853 */ 'S', 'T', 'A', 'T', 'E', 'P', 'O', 'I', 'N', 'T', 0,
  /* 3864 */ 'P', 'A', 'T', 'C', 'H', 'P', 'O', 'I', 'N', 'T', 0,
  /* 3875 */ 'G', '_', 'P', 'T', 'R', 'T', 'O', 'I', 'N', 'T', 0,
  /* 3886 */ 'G', '_', 'F', 'R', 'I', 'N', 'T', 0,
  /* 3894 */ 'G', '_', 'F', 'N', 'E', 'A', 'R', 'B', 'Y', 'I', 'N', 'T', 0,
  /* 3907 */ 'G', '_', 'V', 'A', 'S', 'T', 'A', 'R', 'T', 0,
  /* 3917 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'S', 'T', 'A', 'R', 'T', 0,
  /* 3932 */ 'G', '_', 'I', 'N', 'S', 'E', 'R', 'T', 0,
  /* 3941 */ 'G', '_', 'F', 'S', 'Q', 'R', 'T', 0,
  /* 3949 */ 'G', '_', 'B', 'I', 'T', 'C', 'A', 'S', 'T', 0,
  /* 3959 */ 'G', '_', 'A', 'D', 'D', 'R', 'S', 'P', 'A', 'C', 'E', '_', 'C', 'A', 'S', 'T', 0,
  /* 3976 */ 'G', '_', 'F', 'P', 'E', 'X', 'T', 0,
  /* 3984 */ 'G', '_', 'S', 'E', 'X', 'T', 0,
  /* 3991 */ 'G', '_', 'A', 'N', 'Y', 'E', 'X', 'T', 0,
  /* 4000 */ 'G', '_', 'Z', 'E', 'X', 'T', 0,
  /* 4007 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'B', 'U', 0,
  /* 4017 */ 'B', 'G', 'E', 'U', 0,
  /* 4022 */ 'M', 'U', 'L', 'H', 'U', 0,
  /* 4028 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'H', 'U', 0,
  /* 4038 */ 'S', 'L', 'T', 'I', 'U', 0,
  /* 4044 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'L', 'U', 0,
  /* 4054 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'L', 'U', 0,
  /* 4064 */ 'R', 'E', 'M', 'U', 0,
  /* 4069 */ 'M', 'U', 'L', 'H', 'S', 'U', 0,
  /* 4076 */ 'B', 'L', 'T', 'U', 0,
  /* 4081 */ 'S', 'L', 'T', 'U', 0,
  /* 4086 */ 'D', 'I', 'V', 'U', 0,
  /* 4091 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'W', 'U', 0,
  /* 4101 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'W', 'U', 0,
  /* 4111 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'W', 'U', 0,
  /* 4121 */ 'G', '_', 'F', 'D', 'I', 'V', 0,
  /* 4128 */ 'G', '_', 'S', 'D', 'I', 'V', 0,
  /* 4135 */ 'G', '_', 'U', 'D', 'I', 'V', 0,
  /* 4142 */ 'C', '_', 'M', 'V', 0,
  /* 4147 */ 'S', 'R', 'A', 'W', 0,
  /* 4152 */ 'C', '_', 'S', 'U', 'B', 'W', 0,
  /* 4159 */ 'C', '_', 'A', 'D', 'D', 'W', 0,
  /* 4166 */ 'S', 'R', 'A', 'I', 'W', 0,
  /* 4172 */ 'C', '_', 'A', 'D', 'D', 'I', 'W', 0,
  /* 4180 */ 'S', 'L', 'L', 'I', 'W', 0,
  /* 4186 */ 'S', 'R', 'L', 'I', 'W', 0,
  /* 4192 */ 'C', '_', 'F', 'L', 'W', 0,
  /* 4198 */ 'P', 's', 'e', 'u', 'd', 'o', 'F', 'L', 'W', 0,
  /* 4208 */ 'S', 'L', 'L', 'W', 0,
  /* 4213 */ 'S', 'R', 'L', 'W', 0,
  /* 4218 */ 'M', 'U', 'L', 'W', 0,
  /* 4223 */ 'C', '_', 'L', 'W', 0,
  /* 4228 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'W', 0,
  /* 4237 */ 'R', 'E', 'M', 'W', 0,
  /* 4242 */ 'G', '_', 'F', 'P', 'O', 'W', 0,
  /* 4249 */ 'C', 'S', 'R', 'R', 'W', 0,
  /* 4255 */ 'C', '_', 'F', 'S', 'W', 0,
  /* 4261 */ 'P', 's', 'e', 'u', 'd', 'o', 'F', 'S', 'W', 0,
  /* 4271 */ 'C', '_', 'S', 'W', 0,
  /* 4276 */ 'P', 's', 'e', 'u', 'd', 'o', 'S', 'W', 0,
  /* 4285 */ 'R', 'E', 'M', 'U', 'W', 0,
  /* 4291 */ 'D', 'I', 'V', 'U', 'W', 0,
  /* 4297 */ 'D', 'I', 'V', 'W', 0,
  /* 4302 */ 'S', 'C', '_', 'W', 0,
  /* 4307 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', 0,
  /* 4316 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', 0,
  /* 4325 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'W', 0,
  /* 4334 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', 0,
  /* 4343 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', 0,
  /* 4353 */ 'L', 'R', '_', 'W', 0,
  /* 4358 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', 0,
  /* 4366 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', 0,
  /* 4375 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'W', 0,
  /* 4384 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', 0,
  /* 4394 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', 0,
  /* 4404 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', 0,
  /* 4413 */ 'F', 'M', 'V', '_', 'X', '_', 'W', 0,
  /* 4421 */ 'G', '_', 'S', 'M', 'A', 'X', 0,
  /* 4428 */ 'G', '_', 'U', 'M', 'A', 'X', 0,
  /* 4435 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'U', 'M', 'A', 'X', 0,
  /* 4452 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'M', 'A', 'X', 0,
  /* 4468 */ 'G', '_', 'F', 'R', 'A', 'M', 'E', '_', 'I', 'N', 'D', 'E', 'X', 0,
  /* 4482 */ 'F', 'M', 'V', '_', 'D', '_', 'X', 0,
  /* 4490 */ 'F', 'M', 'V', '_', 'W', '_', 'X', 0,
  /* 4498 */ 'C', 'O', 'P', 'Y', 0,
  /* 4503 */ 'C', '_', 'B', 'N', 'E', 'Z', 0,
  /* 4510 */ 'G', '_', 'C', 'T', 'L', 'Z', 0,
  /* 4517 */ 'C', '_', 'B', 'E', 'Q', 'Z', 0,
  /* 4524 */ 'G', '_', 'C', 'T', 'T', 'Z', 0,
  /* 4531 */ 'R', 'e', 'a', 'd', 'C', 'y', 'c', 'l', 'e', 'W', 'i', 'd', 'e', 0,
  /* 4545 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'A', 'L', 'L', 'R', 'e', 'g', 0,
  /* 4559 */ 'P', 's', 'e', 'u', 'd', 'o', 'A', 'd', 'd', 'T', 'P', 'R', 'e', 'l', 0,
  /* 4574 */ 'B', 'u', 'i', 'l', 'd', 'P', 'a', 'i', 'r', 'F', '6', '4', 'P', 's', 'e', 'u', 'd', 'o', 0,
  /* 4593 */ 'S', 'p', 'l', 'i', 't', 'F', '6', '4', 'P', 's', 'e', 'u', 'd', 'o', 0,
  /* 4608 */ 'P', 's', 'e', 'u', 'd', 'o', 'T', 'A', 'I', 'L', 'I', 'n', 'd', 'i', 'r', 'e', 'c', 't', 0,
  /* 4627 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'A', 'L', 'L', 'I', 'n', 'd', 'i', 'r', 'e', 'c', 't', 0,
};

extern const unsigned RISCVInstrNameIndices[] = {
    1469U, 2409U, 3085U, 2527U, 1606U, 1587U, 1615U, 1774U, 
    1309U, 1324U, 1289U, 1338U, 3421U, 1210U, 1596U, 1086U, 
    4498U, 1178U, 3917U, 678U, 2629U, 1751U, 3864U, 730U, 
    3853U, 1189U, 2719U, 2706U, 3120U, 3726U, 3750U, 1683U, 
    1730U, 1703U, 1632U, 565U, 420U, 2364U, 4128U, 4135U, 
    2395U, 2402U, 656U, 3245U, 3218U, 1287U, 1467U, 4468U, 
    1220U, 3679U, 3359U, 3932U, 3376U, 3180U, 490U, 3398U, 
    3875U, 3341U, 3949U, 464U, 712U, 545U, 523U, 534U, 
    1202U, 3438U, 1352U, 1369U, 571U, 426U, 662U, 633U, 
    3250U, 3224U, 4452U, 2504U, 4435U, 2487U, 1078U, 703U, 
    3698U, 442U, 3468U, 3991U, 482U, 3842U, 3830U, 3907U, 
    1393U, 3984U, 4000U, 1652U, 3152U, 3145U, 2677U, 2670U, 
    3689U, 2595U, 1107U, 2579U, 1070U, 2587U, 1099U, 2571U, 
    1062U, 2611U, 2603U, 1409U, 1401U, 552U, 407U, 2357U, 
    368U, 4121U, 2388U, 4242U, 2817U, 302U, 1386U, 294U, 
    0U, 1302U, 3976U, 454U, 1506U, 1533U, 2652U, 2661U, 
    3352U, 2461U, 1235U, 2441U, 2451U, 1115U, 1130U, 2419U, 
    2430U, 2646U, 1570U, 2473U, 4421U, 2480U, 4428U, 3080U, 
    3774U, 3806U, 3785U, 3195U, 4524U, 1269U, 4510U, 1251U, 
    2698U, 2638U, 1669U, 3391U, 2520U, 3941U, 3171U, 3886U, 
    3894U, 3959U, 3107U, 1165U, 2554U, 2802U, 4574U, 4559U, 
    94U, 310U, 3098U, 691U, 1763U, 4627U, 4545U, 139U, 
    333U, 609U, 4198U, 753U, 4261U, 359U, 587U, 1149U, 
    389U, 4007U, 624U, 1417U, 4028U, 1492U, 349U, 4228U, 
    4091U, 37U, 266U, 184U, 65U, 9U, 237U, 155U, 
    212U, 117U, 3740U, 398U, 768U, 1426U, 4276U, 1658U, 
    4608U, 4531U, 3265U, 3291U, 3317U, 4593U, 555U, 1451U, 
    4174U, 4161U, 830U, 2832U, 1924U, 1795U, 4307U, 2958U, 
    2083U, 2239U, 839U, 2844U, 1939U, 1807U, 4316U, 2970U, 
    2098U, 2251U, 1003U, 2925U, 2041U, 1888U, 4394U, 3051U, 
    2200U, 2332U, 1036U, 2938U, 2057U, 1901U, 4404U, 3064U, 
    2216U, 2345U, 983U, 2912U, 2025U, 1875U, 4384U, 3038U, 
    2184U, 2319U, 885U, 2856U, 1954U, 1819U, 4334U, 2982U, 
    2113U, 2263U, 924U, 2889U, 1996U, 1852U, 4358U, 3015U, 
    2155U, 2296U, 903U, 2868U, 1969U, 1831U, 4343U, 2994U, 
    2128U, 2275U, 932U, 2900U, 2010U, 1863U, 4366U, 3026U, 
    2169U, 2307U, 646U, 1458U, 511U, 3076U, 1145U, 4017U, 
    3781U, 4076U, 1185U, 517U, 1442U, 3415U, 1515U, 4249U, 
    1542U, 559U, 1449U, 2731U, 2543U, 4172U, 4159U, 650U, 
    1456U, 4517U, 4503U, 1561U, 603U, 2742U, 4192U, 2772U, 
    747U, 2757U, 4255U, 2787U, 1557U, 1581U, 3164U, 3159U, 
    619U, 2750U, 1487U, 1527U, 4223U, 2780U, 4142U, 2692U, 
    3240U, 763U, 2765U, 1473U, 1435U, 1480U, 414U, 4152U, 
    4271U, 2795U, 2684U, 3212U, 4124U, 4086U, 4291U, 4297U, 
    1563U, 1677U, 806U, 3519U, 941U, 3604U, 2370U, 4044U, 
    3543U, 4325U, 4101U, 973U, 3627U, 869U, 3573U, 950U, 
    2379U, 4054U, 4375U, 4111U, 993U, 3637U, 1020U, 3654U, 
    1013U, 3647U, 1080U, 1549U, 2619U, 913U, 3598U, 605U, 
    848U, 3552U, 959U, 3613U, 4194U, 813U, 3526U, 1029U, 
    3663U, 878U, 3582U, 784U, 3502U, 862U, 3566U, 4482U, 
    4490U, 1054U, 4413U, 821U, 3534U, 792U, 3510U, 749U, 
    894U, 3589U, 1045U, 3670U, 854U, 3558U, 965U, 3619U, 
    777U, 3495U, 4257U, 1583U, 3166U, 395U, 4013U, 606U, 
    1406U, 4024U, 919U, 2881U, 1985U, 1844U, 4353U, 3007U, 
    2144U, 2288U, 1529U, 4195U, 4097U, 3711U, 2360U, 1404U, 
    4069U, 4022U, 4218U, 3177U, 1502U, 2391U, 4064U, 4285U, 
    4237U, 404U, 801U, 2824U, 1913U, 1787U, 4302U, 2950U, 
    2072U, 2231U, 750U, 374U, 1432U, 1779U, 1475U, 4180U, 
    4208U, 3826U, 1522U, 4038U, 4081U, 385U, 1437U, 4166U, 
    4147U, 3716U, 1783U, 1482U, 4186U, 4213U, 410U, 4154U, 
    4258U, 2686U, 3721U, 1463U, 3214U, 1501U, 
};

static inline void InitRISCVMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(RISCVInsts, RISCVInstrNameIndices, RISCVInstrNameData, 486);
}

} // end llvm namespace
#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER
namespace llvm_ks {
struct RISCVGenInstrInfo : public TargetInstrInfo {
  explicit RISCVGenInstrInfo(int CFSetupOpcode = -1, int CFDestroyOpcode = -1, int CatchRetOpcode = -1, int ReturnOpcode = -1);
  ~RISCVGenInstrInfo() override = default;

};
} // end llvm namespace
#endif // GET_INSTRINFO_HEADER

#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM
namespace llvm_ks {
namespace RISCV {
namespace OpName {
enum {
OPERAND_LAST
};
} // end namespace OpName
} // end namespace RISCV
} // end namespace llvm_ks
#endif //GET_INSTRINFO_OPERAND_ENUM

#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS
namespace llvm_ks {
namespace RISCV {
LLVM_READONLY
int16_t getNamedOperandIdx(uint16_t Opcode, uint16_t NamedIdx) {
  return -1;
}
} // end namespace RISCV
} // end namespace llvm_ks
#endif //GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_OPERAND_TYPES_ENUM
#undef GET_INSTRINFO_OPERAND_TYPES_ENUM
namespace llvm_ks {
namespace RISCV {
namespace OpTypes {
enum OperandType {
  bare_symbol = 0,
  c_lui_imm = 1,
  call_symbol = 2,
  csr_sysreg = 3,
  f32imm = 4,
  f64imm = 5,
  fencearg = 6,
  frmarg = 7,
  i16imm = 8,
  i1imm = 9,
  i32imm = 10,
  i64imm = 11,
  i8imm = 12,
  ixlenimm = 13,
  ixlenimm_li = 14,
  ptype0 = 15,
  ptype1 = 16,
  ptype2 = 17,
  ptype3 = 18,
  ptype4 = 19,
  ptype5 = 20,
  simm10_lsb0000nonzero = 21,
  simm12 = 22,
  simm12_lsb0 = 23,
  simm13_lsb0 = 24,
  simm21_lsb0_jal = 25,
  simm6 = 26,
  simm6nonzero = 27,
  simm9_lsb0 = 28,
  tprel_add_symbol = 29,
  type0 = 30,
  type1 = 31,
  type2 = 32,
  type3 = 33,
  type4 = 34,
  type5 = 35,
  uimm10_lsb00nonzero = 36,
  uimm20_auipc = 37,
  uimm20_lui = 38,
  uimm5 = 39,
  uimm7_lsb00 = 40,
  uimm8_lsb00 = 41,
  uimm8_lsb000 = 42,
  uimm9_lsb000 = 43,
  uimmlog2xlen = 44,
  uimmlog2xlennonzero = 45,
  OPERAND_TYPE_LIST_END
};
} // end namespace OpTypes
} // end namespace RISCV
} // end namespace llvm_ks
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM

#ifdef GET_INSTRINFO_OPERAND_TYPE
#undef GET_INSTRINFO_OPERAND_TYPE
namespace llvm_ks {
namespace RISCV {
LLVM_READONLY
int getOperandType(uint16_t Opcode, uint16_t OpIdx) {
  const int Offsets[] = {
    0,
    1,
    1,
    1,
    2,
    3,
    4,
    5,
    5,
    8,
    12,
    13,
    17,
    20,
    20,
    21,
    23,
    25,
    25,
    26,
    27,
    29,
    29,
    35,
    36,
    36,
    38,
    39,
    39,
    39,
    39,
    39,
    39,
    41,
    44,
    44,
    47,
    50,
    53,
    56,
    59,
    62,
    65,
    68,
    71,
    74,
    75,
    76,
    78,
    80,
    83,
    85,
    89,
    91,
    93,
    95,
    97,
    99,
    101,
    103,
    105,
    107,
    109,
    111,
    113,
    115,
    120,
    124,
    127,
    130,
    133,
    136,
    139,
    142,
    145,
    148,
    151,
    154,
    157,
    159,
    161,
    162,
    163,
    164,
    166,
    168,
    170,
    172,
    173,
    176,
    178,
    180,
    183,
    186,
    189,
    193,
    197,
    201,
    205,
    210,
    214,
    219,
    223,
    228,
    232,
    237,
    241,
    245,
    248,
    251,
    254,
    257,
    260,
    264,
    267,
    270,
    273,
    275,
    277,
    279,
    281,
    283,
    285,
    287,
    289,
    291,
    293,
    295,
    297,
    299,
    302,
    304,
    307,
    310,
    313,
    316,
    319,
    322,
    325,
    328,
    331,
    334,
    337,
    340,
    341,
    344,
    348,
    351,
    355,
    357,
    359,
    361,
    363,
    365,
    367,
    369,
    371,
    373,
    375,
    377,
    379,
    381,
    383,
    385,
    387,
    389,
    391,
    394,
    398,
    403,
    408,
    409,
    411,
    412,
    413,
    415,
    421,
    427,
    430,
    433,
    436,
    439,
    441,
    443,
    445,
    447,
    449,
    451,
    453,
    455,
    457,
    459,
    461,
    463,
    469,
    477,
    485,
    491,
    497,
    504,
    511,
    517,
    524,
    524,
    527,
    530,
    533,
    536,
    537,
    538,
    540,
    546,
    552,
    558,
    561,
    564,
    567,
    570,
    573,
    576,
    579,
    582,
    585,
    588,
    591,
    594,
    597,
    600,
    603,
    606,
    609,
    612,
    615,
    618,
    621,
    624,
    627,
    630,
    633,
    636,
    639,
    642,
    645,
    648,
    651,
    654,
    657,
    660,
    663,
    666,
    669,
    672,
    675,
    678,
    681,
    684,
    687,
    690,
    693,
    696,
    699,
    702,
    705,
    708,
    711,
    714,
    717,
    720,
    723,
    726,
    729,
    732,
    735,
    738,
    741,
    744,
    747,
    750,
    753,
    756,
    759,
    762,
    765,
    768,
    771,
    774,
    777,
    780,
    783,
    786,
    789,
    792,
    795,
    797,
    800,
    803,
    806,
    809,
    812,
    815,
    818,
    821,
    824,
    827,
    830,
    833,
    836,
    839,
    842,
    845,
    848,
    851,
    854,
    857,
    859,
    861,
    861,
    864,
    867,
    870,
    873,
    876,
    879,
    882,
    885,
    886,
    887,
    888,
    889,
    892,
    895,
    897,
    899,
    902,
    905,
    907,
    907,
    910,
    913,
    916,
    919,
    922,
    925,
    928,
    931,
    934,
    937,
    937,
    940,
    943,
    946,
    949,
    952,
    952,
    952,
    956,
    960,
    962,
    964,
    967,
    970,
    972,
    974,
    976,
    979,
    982,
    985,
    988,
    991,
    994,
    997,
    1000,
    1003,
    1006,
    1009,
    1012,
    1015,
    1019,
    1023,
    1025,
    1025,
    1025,
    1028,
    1031,
    1034,
    1037,
    1040,
    1043,
    1046,
    1049,
    1054,
    1059,
    1062,
    1065,
    1068,
    1071,
    1076,
    1081,
    1085,
    1089,
    1091,
    1093,
    1095,
    1097,
    1102,
    1107,
    1112,
    1117,
    1120,
    1123,
    1126,
    1129,
    1132,
    1135,
    1138,
    1141,
    1144,
    1148,
    1152,
    1155,
    1157,
    1160,
    1163,
    1166,
    1169,
    1172,
    1175,
    1177,
    1179,
    1181,
    1183,
    1185,
    1187,
    1189,
    1191,
    1193,
    1196,
    1199,
    1201,
    1204,
    1207,
    1210,
    1213,
    1216,
    1219,
    1222,
    1225,
    1228,
    1231,
    1234,
    1237,
    1240,
    1243,
    1246,
    1249,
    1252,
    1255,
    1258,
    1261,
    1264,
    1266,
    1269,
    1272,
    1275,
    1278,
    1281,
    1284,
    1287,
    1290,
    1293,
    1296,
    1299,
    1302,
    1305,
    1307,
    1310,
    1313,
    1316,
    1319,
    1322,
    1325,
    1328,
    1328,
    1330,
    1332,
    1335,
  };
  const int OpcodeOperandTypes[] = {
    -1, 
    /**/
    /**/
    OpTypes::i32imm, 
    OpTypes::i32imm, 
    OpTypes::i32imm, 
    OpTypes::i32imm, 
    /**/
    -1, -1, OpTypes::i32imm, 
    -1, -1, -1, OpTypes::i32imm, 
    -1, 
    -1, -1, -1, OpTypes::i32imm, 
    -1, -1, OpTypes::i32imm, 
    /**/
    -1, 
    -1, -1, 
    -1, -1, 
    /**/
    OpTypes::i32imm, 
    OpTypes::i32imm, 
    OpTypes::i64imm, OpTypes::i32imm, 
    /**/
    -1, OpTypes::i64imm, OpTypes::i32imm, -1, OpTypes::i32imm, OpTypes::i32imm, 
    -1, 
    /**/
    -1, OpTypes::i32imm, 
    -1, 
    /**/
    /**/
    /**/
    /**/
    /**/
    -1, OpTypes::i8imm, 
    OpTypes::i16imm, -1, OpTypes::i32imm, 
    /**/
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, 
    OpTypes::type0, 
    OpTypes::type0, -1, 
    OpTypes::type0, -1, 
    OpTypes::type0, OpTypes::type1, -1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, OpTypes::type1, -1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, 
    OpTypes::type0, OpTypes::ptype1, 
    OpTypes::type0, OpTypes::ptype1, 
    OpTypes::type0, OpTypes::ptype1, 
    OpTypes::type0, OpTypes::type1, OpTypes::type2, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::type0, OpTypes::ptype1, OpTypes::type0, 
    OpTypes::i32imm, OpTypes::i32imm, 
    OpTypes::type0, -1, 
    OpTypes::type0, 
    -1, 
    -1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, -1, 
    OpTypes::type0, -1, 
    OpTypes::type0, 
    OpTypes::type0, OpTypes::type1, -1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, -1, OpTypes::type1, OpTypes::type1, 
    OpTypes::type0, -1, OpTypes::type1, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type1, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, -1, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, OpTypes::type0, 
    -1, 
    OpTypes::ptype0, -1, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, OpTypes::type1, OpTypes::type2, 
    OpTypes::type0, OpTypes::type1, OpTypes::type2, 
    OpTypes::type0, OpTypes::type1, OpTypes::type1, OpTypes::type2, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type0, 
    OpTypes::type0, OpTypes::type1, 
    OpTypes::type0, -1, 
    OpTypes::type0, -1, 
    OpTypes::i32imm, OpTypes::i32imm, 
    OpTypes::i32imm, OpTypes::i32imm, 
    -1, -1, -1, 
    -1, -1, -1, OpTypes::tprel_add_symbol, 
    -1, -1, -1, -1, OpTypes::ixlenimm, 
    -1, -1, -1, -1, OpTypes::ixlenimm, 
    OpTypes::simm21_lsb0_jal, 
    -1, OpTypes::simm12, 
    OpTypes::call_symbol, 
    -1, 
    -1, OpTypes::call_symbol, 
    -1, -1, -1, -1, -1, OpTypes::ixlenimm, 
    -1, -1, -1, -1, -1, OpTypes::ixlenimm, 
    -1, -1, OpTypes::bare_symbol, 
    -1, -1, OpTypes::bare_symbol, 
    -1, -1, OpTypes::bare_symbol, 
    -1, -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::ixlenimm_li, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, OpTypes::bare_symbol, 
    -1, -1, -1, -1, -1, OpTypes::ixlenimm, 
    -1, -1, -1, -1, -1, -1, OpTypes::ixlenimm, OpTypes::ixlenimm, 
    -1, -1, -1, -1, -1, -1, OpTypes::ixlenimm, OpTypes::ixlenimm, 
    -1, -1, -1, -1, -1, OpTypes::ixlenimm, 
    -1, -1, -1, -1, -1, OpTypes::ixlenimm, 
    -1, -1, -1, -1, -1, -1, OpTypes::ixlenimm, 
    -1, -1, -1, -1, -1, -1, OpTypes::ixlenimm, 
    -1, -1, -1, -1, -1, OpTypes::ixlenimm, 
    -1, -1, -1, -1, -1, -1, OpTypes::ixlenimm, 
    /**/
    -1, -1, OpTypes::bare_symbol, 
    -1, -1, OpTypes::bare_symbol, 
    -1, -1, OpTypes::bare_symbol, 
    -1, -1, OpTypes::bare_symbol, 
    OpTypes::call_symbol, 
    -1, 
    -1, -1, 
    -1, -1, -1, OpTypes::ixlenimm, -1, -1, 
    -1, -1, -1, OpTypes::ixlenimm, -1, -1, 
    -1, -1, -1, OpTypes::ixlenimm, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
    -1, -1, OpTypes::simm12, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
    -1, OpTypes::uimm20_auipc, 
    -1, -1, OpTypes::simm13_lsb0, 
    -1, -1, OpTypes::simm13_lsb0, 
    -1, -1, OpTypes::simm13_lsb0, 
    -1, -1, OpTypes::simm13_lsb0, 
    -1, -1, OpTypes::simm13_lsb0, 
    -1, -1, OpTypes::simm13_lsb0, 
    -1, OpTypes::csr_sysreg, -1, 
    -1, OpTypes::csr_sysreg, OpTypes::uimm5, 
    -1, OpTypes::csr_sysreg, -1, 
    -1, OpTypes::csr_sysreg, OpTypes::uimm5, 
    -1, OpTypes::csr_sysreg, -1, 
    -1, OpTypes::csr_sysreg, OpTypes::uimm5, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm6nonzero, 
    -1, -1, OpTypes::simm10_lsb0000nonzero, 
    -1, -1, OpTypes::uimm10_lsb00nonzero, 
    -1, -1, OpTypes::simm6, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm6, 
    -1, OpTypes::simm9_lsb0, 
    -1, OpTypes::simm9_lsb0, 
    /**/
    -1, -1, OpTypes::uimm8_lsb000, 
    -1, -1, OpTypes::uimm9_lsb000, 
    -1, -1, OpTypes::uimm7_lsb00, 
    -1, -1, OpTypes::uimm8_lsb00, 
    -1, -1, OpTypes::uimm8_lsb000, 
    -1, -1, OpTypes::uimm9_lsb000, 
    -1, -1, OpTypes::uimm7_lsb00, 
    -1, -1, OpTypes::uimm8_lsb00, 
    OpTypes::simm12_lsb0, 
    OpTypes::simm12_lsb0, 
    -1, 
    -1, 
    -1, -1, OpTypes::uimm8_lsb000, 
    -1, -1, OpTypes::uimm9_lsb000, 
    -1, OpTypes::simm6, 
    -1, OpTypes::c_lui_imm, 
    -1, -1, OpTypes::uimm7_lsb00, 
    -1, -1, OpTypes::uimm8_lsb00, 
    -1, -1, 
    /**/
    -1, -1, -1, 
    -1, -1, OpTypes::uimm8_lsb000, 
    -1, -1, OpTypes::uimm9_lsb000, 
    -1, -1, OpTypes::uimmlog2xlennonzero, 
    -1, -1, OpTypes::uimmlog2xlennonzero, 
    -1, -1, OpTypes::uimmlog2xlennonzero, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::uimm7_lsb00, 
    -1, -1, OpTypes::uimm8_lsb00, 
    /**/
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    /**/
    /**/
    -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, OpTypes::frmarg, 
    -1, -1, 
    -1, -1, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, 
    -1, -1, 
    -1, -1, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, OpTypes::frmarg, 
    OpTypes::fencearg, OpTypes::fencearg, 
    /**/
    /**/
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
    -1, -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, OpTypes::frmarg, 
    -1, -1, 
    -1, -1, 
    -1, -1, 
    -1, -1, 
    -1, -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::simm12, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::frmarg, 
    -1, -1, -1, OpTypes::frmarg, 
    -1, -1, -1, OpTypes::frmarg, 
    -1, -1, OpTypes::simm12, 
    -1, OpTypes::simm21_lsb0_jal, 
    -1, -1, OpTypes::simm12, 
    -1, -1, OpTypes::simm12, 
    -1, -1, OpTypes::simm12, 
    -1, -1, OpTypes::simm12, 
    -1, -1, OpTypes::simm12, 
    -1, -1, OpTypes::simm12, 
    -1, -1, 
    -1, -1, 
    -1, -1, 
    -1, -1, 
    -1, -1, 
    -1, -1, 
    -1, -1, 
    -1, -1, 
    -1, OpTypes::uimm20_lui, 
    -1, -1, OpTypes::simm12, 
    -1, -1, OpTypes::simm12, 
    -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
    -1, -1, 
    -1, -1, OpTypes::simm12, 
    -1, -1, -1, 
    -1, -1, OpTypes::uimmlog2xlen, 
    -1, -1, OpTypes::uimm5, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
    -1, -1, OpTypes::simm12, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::uimmlog2xlen, 
    -1, -1, OpTypes::uimm5, 
    -1, -1, -1, 
    -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::uimmlog2xlen, 
    -1, -1, OpTypes::uimm5, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
    /**/
    -1, -1, 
    -1, -1, 
    -1, -1, -1, 
    -1, -1, OpTypes::simm12, 
  };
  return OpcodeOperandTypes[Offsets[Opcode] + OpIdx];
}
} // end namespace RISCV
} // end namespace llvm_ks
#endif //GET_INSTRINFO_OPERAND_TYPE

