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

namespace MSP430 {
  enum {
    PHI	= 0,
    INLINEASM	= 1,
    CFI_INSTRUCTION	= 2,
    EH_LABEL	= 3,
    GC_LABEL	= 4,
    KILL	= 5,
    EXTRACT_SUBREG	= 6,
    INSERT_SUBREG	= 7,
    IMPLICIT_DEF	= 8,
    SUBREG_TO_REG	= 9,
    COPY_TO_REGCLASS	= 10,
    DBG_VALUE	= 11,
    REG_SEQUENCE	= 12,
    COPY	= 13,
    BUNDLE	= 14,
    LIFETIME_START	= 15,
    LIFETIME_END	= 16,
    STACKMAP	= 17,
    PATCHPOINT	= 18,
    LOAD_STACK_GUARD	= 19,
    STATEPOINT	= 20,
    LOCAL_ESCAPE	= 21,
    FAULTING_LOAD_OP	= 22,
    PATCHABLE_OP	= 23,
    PATCHABLE_FUNCTION_ENTER	= 24,
    PATCHABLE_RET	= 25,
    G_ADD	= 26,
    G_OR	= 27,
    G_BR	= 28,
    ADD16mc	= 29,
    ADD16mi	= 30,
    ADD16mm	= 31,
    ADD16mn	= 32,
    ADD16mp	= 33,
    ADD16mr	= 34,
    ADD16rc	= 35,
    ADD16ri	= 36,
    ADD16rm	= 37,
    ADD16rn	= 38,
    ADD16rp	= 39,
    ADD16rr	= 40,
    ADD8mc	= 41,
    ADD8mi	= 42,
    ADD8mm	= 43,
    ADD8mn	= 44,
    ADD8mp	= 45,
    ADD8mr	= 46,
    ADD8rc	= 47,
    ADD8ri	= 48,
    ADD8rm	= 49,
    ADD8rn	= 50,
    ADD8rp	= 51,
    ADD8rr	= 52,
    ADDC16mc	= 53,
    ADDC16mi	= 54,
    ADDC16mm	= 55,
    ADDC16mn	= 56,
    ADDC16mp	= 57,
    ADDC16mr	= 58,
    ADDC16rc	= 59,
    ADDC16ri	= 60,
    ADDC16rm	= 61,
    ADDC16rn	= 62,
    ADDC16rp	= 63,
    ADDC16rr	= 64,
    ADDC8mc	= 65,
    ADDC8mi	= 66,
    ADDC8mm	= 67,
    ADDC8mn	= 68,
    ADDC8mp	= 69,
    ADDC8mr	= 70,
    ADDC8rc	= 71,
    ADDC8ri	= 72,
    ADDC8rm	= 73,
    ADDC8rn	= 74,
    ADDC8rp	= 75,
    ADDC8rr	= 76,
    ADDframe	= 77,
    ADJCALLSTACKDOWN	= 78,
    ADJCALLSTACKUP	= 79,
    AND16mc	= 80,
    AND16mi	= 81,
    AND16mm	= 82,
    AND16mn	= 83,
    AND16mp	= 84,
    AND16mr	= 85,
    AND16rc	= 86,
    AND16ri	= 87,
    AND16rm	= 88,
    AND16rn	= 89,
    AND16rp	= 90,
    AND16rr	= 91,
    AND8mc	= 92,
    AND8mi	= 93,
    AND8mm	= 94,
    AND8mn	= 95,
    AND8mp	= 96,
    AND8mr	= 97,
    AND8rc	= 98,
    AND8ri	= 99,
    AND8rm	= 100,
    AND8rn	= 101,
    AND8rp	= 102,
    AND8rr	= 103,
    BIC16mc	= 104,
    BIC16mi	= 105,
    BIC16mm	= 106,
    BIC16mn	= 107,
    BIC16mp	= 108,
    BIC16mr	= 109,
    BIC16rc	= 110,
    BIC16ri	= 111,
    BIC16rm	= 112,
    BIC16rn	= 113,
    BIC16rp	= 114,
    BIC16rr	= 115,
    BIC8mc	= 116,
    BIC8mi	= 117,
    BIC8mm	= 118,
    BIC8mn	= 119,
    BIC8mp	= 120,
    BIC8mr	= 121,
    BIC8rc	= 122,
    BIC8ri	= 123,
    BIC8rm	= 124,
    BIC8rn	= 125,
    BIC8rp	= 126,
    BIC8rr	= 127,
    BIS16mc	= 128,
    BIS16mi	= 129,
    BIS16mm	= 130,
    BIS16mn	= 131,
    BIS16mp	= 132,
    BIS16mr	= 133,
    BIS16rc	= 134,
    BIS16ri	= 135,
    BIS16rm	= 136,
    BIS16rn	= 137,
    BIS16rp	= 138,
    BIS16rr	= 139,
    BIS8mc	= 140,
    BIS8mi	= 141,
    BIS8mm	= 142,
    BIS8mn	= 143,
    BIS8mp	= 144,
    BIS8mr	= 145,
    BIS8rc	= 146,
    BIS8ri	= 147,
    BIS8rm	= 148,
    BIS8rn	= 149,
    BIS8rp	= 150,
    BIS8rr	= 151,
    BIT16mc	= 152,
    BIT16mi	= 153,
    BIT16mm	= 154,
    BIT16mn	= 155,
    BIT16mp	= 156,
    BIT16mr	= 157,
    BIT16rc	= 158,
    BIT16ri	= 159,
    BIT16rm	= 160,
    BIT16rn	= 161,
    BIT16rp	= 162,
    BIT16rr	= 163,
    BIT8mc	= 164,
    BIT8mi	= 165,
    BIT8mm	= 166,
    BIT8mn	= 167,
    BIT8mp	= 168,
    BIT8mr	= 169,
    BIT8rc	= 170,
    BIT8ri	= 171,
    BIT8rm	= 172,
    BIT8rn	= 173,
    BIT8rp	= 174,
    BIT8rr	= 175,
    Bi	= 176,
    Bm	= 177,
    Br	= 178,
    CALLi	= 179,
    CALLm	= 180,
    CALLn	= 181,
    CALLp	= 182,
    CALLr	= 183,
    CMP16mc	= 184,
    CMP16mi	= 185,
    CMP16mm	= 186,
    CMP16mn	= 187,
    CMP16mp	= 188,
    CMP16mr	= 189,
    CMP16rc	= 190,
    CMP16ri	= 191,
    CMP16rm	= 192,
    CMP16rn	= 193,
    CMP16rp	= 194,
    CMP16rr	= 195,
    CMP8mc	= 196,
    CMP8mi	= 197,
    CMP8mm	= 198,
    CMP8mn	= 199,
    CMP8mp	= 200,
    CMP8mr	= 201,
    CMP8rc	= 202,
    CMP8ri	= 203,
    CMP8rm	= 204,
    CMP8rn	= 205,
    CMP8rp	= 206,
    CMP8rr	= 207,
    DADD16mc	= 208,
    DADD16mi	= 209,
    DADD16mm	= 210,
    DADD16mn	= 211,
    DADD16mp	= 212,
    DADD16mr	= 213,
    DADD16rc	= 214,
    DADD16ri	= 215,
    DADD16rm	= 216,
    DADD16rn	= 217,
    DADD16rp	= 218,
    DADD16rr	= 219,
    DADD8mc	= 220,
    DADD8mi	= 221,
    DADD8mm	= 222,
    DADD8mn	= 223,
    DADD8mp	= 224,
    DADD8mr	= 225,
    DADD8rc	= 226,
    DADD8ri	= 227,
    DADD8rm	= 228,
    DADD8rn	= 229,
    DADD8rp	= 230,
    DADD8rr	= 231,
    JCC	= 232,
    JMP	= 233,
    MOV16mc	= 234,
    MOV16mi	= 235,
    MOV16mm	= 236,
    MOV16mn	= 237,
    MOV16mp	= 238,
    MOV16mr	= 239,
    MOV16rc	= 240,
    MOV16ri	= 241,
    MOV16rm	= 242,
    MOV16rn	= 243,
    MOV16rp	= 244,
    MOV16rr	= 245,
    MOV8mc	= 246,
    MOV8mi	= 247,
    MOV8mm	= 248,
    MOV8mn	= 249,
    MOV8mp	= 250,
    MOV8mr	= 251,
    MOV8rc	= 252,
    MOV8ri	= 253,
    MOV8rm	= 254,
    MOV8rn	= 255,
    MOV8rp	= 256,
    MOV8rr	= 257,
    MOVZX16rm8	= 258,
    MOVZX16rr8	= 259,
    POP16r	= 260,
    PUSH16c	= 261,
    PUSH16i	= 262,
    PUSH16r	= 263,
    PUSH8r	= 264,
    RET	= 265,
    RETI	= 266,
    RRA16m	= 267,
    RRA16n	= 268,
    RRA16p	= 269,
    RRA16r	= 270,
    RRA8m	= 271,
    RRA8n	= 272,
    RRA8p	= 273,
    RRA8r	= 274,
    RRC16m	= 275,
    RRC16n	= 276,
    RRC16p	= 277,
    RRC16r	= 278,
    RRC8m	= 279,
    RRC8n	= 280,
    RRC8p	= 281,
    RRC8r	= 282,
    Rrcl16	= 283,
    Rrcl8	= 284,
    SEXT16m	= 285,
    SEXT16n	= 286,
    SEXT16p	= 287,
    SEXT16r	= 288,
    SUB16mc	= 289,
    SUB16mi	= 290,
    SUB16mm	= 291,
    SUB16mn	= 292,
    SUB16mp	= 293,
    SUB16mr	= 294,
    SUB16rc	= 295,
    SUB16ri	= 296,
    SUB16rm	= 297,
    SUB16rn	= 298,
    SUB16rp	= 299,
    SUB16rr	= 300,
    SUB8mc	= 301,
    SUB8mi	= 302,
    SUB8mm	= 303,
    SUB8mn	= 304,
    SUB8mp	= 305,
    SUB8mr	= 306,
    SUB8rc	= 307,
    SUB8ri	= 308,
    SUB8rm	= 309,
    SUB8rn	= 310,
    SUB8rp	= 311,
    SUB8rr	= 312,
    SUBC16mc	= 313,
    SUBC16mi	= 314,
    SUBC16mm	= 315,
    SUBC16mn	= 316,
    SUBC16mp	= 317,
    SUBC16mr	= 318,
    SUBC16rc	= 319,
    SUBC16ri	= 320,
    SUBC16rm	= 321,
    SUBC16rn	= 322,
    SUBC16rp	= 323,
    SUBC16rr	= 324,
    SUBC8mc	= 325,
    SUBC8mi	= 326,
    SUBC8mm	= 327,
    SUBC8mn	= 328,
    SUBC8mp	= 329,
    SUBC8mr	= 330,
    SUBC8rc	= 331,
    SUBC8ri	= 332,
    SUBC8rm	= 333,
    SUBC8rn	= 334,
    SUBC8rp	= 335,
    SUBC8rr	= 336,
    SWPB16m	= 337,
    SWPB16n	= 338,
    SWPB16p	= 339,
    SWPB16r	= 340,
    Select16	= 341,
    Select8	= 342,
    Shl16	= 343,
    Shl8	= 344,
    Sra16	= 345,
    Sra8	= 346,
    Srl16	= 347,
    Srl8	= 348,
    XOR16mc	= 349,
    XOR16mi	= 350,
    XOR16mm	= 351,
    XOR16mn	= 352,
    XOR16mp	= 353,
    XOR16mr	= 354,
    XOR16rc	= 355,
    XOR16ri	= 356,
    XOR16rm	= 357,
    XOR16rn	= 358,
    XOR16rp	= 359,
    XOR16rr	= 360,
    XOR8mc	= 361,
    XOR8mi	= 362,
    XOR8mm	= 363,
    XOR8mn	= 364,
    XOR8mp	= 365,
    XOR8mr	= 366,
    XOR8rc	= 367,
    XOR8ri	= 368,
    XOR8rm	= 369,
    XOR8rn	= 370,
    XOR8rp	= 371,
    XOR8rr	= 372,
    ZEXT16r	= 373,
    INSTRUCTION_LIST_END = 374
  };

namespace Sched {
  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };
} // end Sched namespace
} // end MSP430 namespace
} // end llvm namespace
#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC
namespace llvm_ks {

static const MCPhysReg ImplicitList1[] = { MSP430::SR, 0 };
static const MCPhysReg ImplicitList2[] = { MSP430::SP, 0 };
static const MCPhysReg ImplicitList3[] = { MSP430::SP, MSP430::SR, 0 };
static const MCPhysReg ImplicitList4[] = { MSP430::R11, MSP430::R12, MSP430::R13, MSP430::R14, MSP430::R15, MSP430::SR, 0 };

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
static const MCOperandInfo OperandInfo12[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo13[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo23[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo30[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo46[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo47[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo50[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo51[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo54[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };

extern const MCInstrDesc MSP430Insts[] = {
  { 0,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #0 = PHI
  { 1,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1 = INLINEASM
  { 2,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #2 = CFI_INSTRUCTION
  { 3,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #3 = EH_LABEL
  { 4,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #4 = GC_LABEL
  { 5,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #5 = KILL
  { 6,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo4, -1 ,nullptr },  // Inst #6 = EXTRACT_SUBREG
  { 7,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #7 = INSERT_SUBREG
  { 8,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #8 = IMPLICIT_DEF
  { 9,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo6, -1 ,nullptr },  // Inst #9 = SUBREG_TO_REG
  { 10,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo4, -1 ,nullptr },  // Inst #10 = COPY_TO_REGCLASS
  { 11,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #11 = DBG_VALUE
  { 12,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #12 = REG_SEQUENCE
  { 13,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #13 = COPY
  { 14,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #14 = BUNDLE
  { 15,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #15 = LIFETIME_START
  { 16,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #16 = LIFETIME_END
  { 17,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo8, -1 ,nullptr },  // Inst #17 = STACKMAP
  { 18,	6,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo9, -1 ,nullptr },  // Inst #18 = PATCHPOINT
  { 19,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo10, -1 ,nullptr },  // Inst #19 = LOAD_STACK_GUARD
  { 20,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #20 = STATEPOINT
  { 21,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #21 = LOCAL_ESCAPE
  { 22,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #22 = FAULTING_LOAD_OP
  { 23,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #23 = PATCHABLE_OP
  { 24,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #24 = PATCHABLE_FUNCTION_ENTER
  { 25,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #25 = PATCHABLE_RET
  { 26,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #26 = G_ADD
  { 27,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #27 = G_OR
  { 28,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #28 = G_BR
  { 29,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #29 = ADD16mc
  { 30,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #30 = ADD16mi
  { 31,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #31 = ADD16mm
  { 32,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #32 = ADD16mn
  { 33,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #33 = ADD16mp
  { 34,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #34 = ADD16mr
  { 35,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #35 = ADD16rc
  { 36,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #36 = ADD16ri
  { 37,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #37 = ADD16rm
  { 38,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #38 = ADD16rn
  { 39,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #39 = ADD16rp
  { 40,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #40 = ADD16rr
  { 41,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #41 = ADD8mc
  { 42,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #42 = ADD8mi
  { 43,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #43 = ADD8mm
  { 44,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #44 = ADD8mn
  { 45,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #45 = ADD8mp
  { 46,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #46 = ADD8mr
  { 47,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #47 = ADD8rc
  { 48,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #48 = ADD8ri
  { 49,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #49 = ADD8rm
  { 50,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #50 = ADD8rn
  { 51,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #51 = ADD8rp
  { 52,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #52 = ADD8rr
  { 53,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #53 = ADDC16mc
  { 54,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #54 = ADDC16mi
  { 55,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #55 = ADDC16mm
  { 56,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #56 = ADDC16mn
  { 57,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #57 = ADDC16mp
  { 58,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #58 = ADDC16mr
  { 59,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #59 = ADDC16rc
  { 60,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #60 = ADDC16ri
  { 61,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #61 = ADDC16rm
  { 62,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #62 = ADDC16rn
  { 63,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #63 = ADDC16rp
  { 64,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #64 = ADDC16rr
  { 65,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #65 = ADDC8mc
  { 66,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #66 = ADDC8mi
  { 67,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #67 = ADDC8mm
  { 68,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #68 = ADDC8mn
  { 69,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #69 = ADDC8mp
  { 70,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #70 = ADDC8mr
  { 71,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #71 = ADDC8rc
  { 72,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #72 = ADDC8ri
  { 73,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #73 = ADDC8rm
  { 74,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #74 = ADDC8rn
  { 75,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #75 = ADDC8rp
  { 76,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #76 = ADDC8rr
  { 77,	3,	1,	0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, ImplicitList2, ImplicitList1, OperandInfo31, -1 ,nullptr },  // Inst #77 = ADDframe
  { 78,	1,	0,	0,	0,	0, 0x4ULL, ImplicitList2, ImplicitList3, OperandInfo3, -1 ,nullptr },  // Inst #78 = ADJCALLSTACKDOWN
  { 79,	2,	0,	0,	0,	0, 0x4ULL, ImplicitList2, ImplicitList3, OperandInfo8, -1 ,nullptr },  // Inst #79 = ADJCALLSTACKUP
  { 80,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #80 = AND16mc
  { 81,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #81 = AND16mi
  { 82,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #82 = AND16mm
  { 83,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #83 = AND16mn
  { 84,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #84 = AND16mp
  { 85,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #85 = AND16mr
  { 86,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #86 = AND16rc
  { 87,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #87 = AND16ri
  { 88,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #88 = AND16rm
  { 89,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #89 = AND16rn
  { 90,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #90 = AND16rp
  { 91,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #91 = AND16rr
  { 92,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #92 = AND8mc
  { 93,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #93 = AND8mi
  { 94,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #94 = AND8mm
  { 95,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #95 = AND8mn
  { 96,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #96 = AND8mp
  { 97,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #97 = AND8mr
  { 98,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #98 = AND8rc
  { 99,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #99 = AND8ri
  { 100,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #100 = AND8rm
  { 101,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #101 = AND8rn
  { 102,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #102 = AND8rp
  { 103,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #103 = AND8rr
  { 104,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #104 = BIC16mc
  { 105,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #105 = BIC16mi
  { 106,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #106 = BIC16mm
  { 107,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #107 = BIC16mn
  { 108,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #108 = BIC16mp
  { 109,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #109 = BIC16mr
  { 110,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #110 = BIC16rc
  { 111,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #111 = BIC16ri
  { 112,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #112 = BIC16rm
  { 113,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #113 = BIC16rn
  { 114,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #114 = BIC16rp
  { 115,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #115 = BIC16rr
  { 116,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #116 = BIC8mc
  { 117,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #117 = BIC8mi
  { 118,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #118 = BIC8mm
  { 119,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #119 = BIC8mn
  { 120,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #120 = BIC8mp
  { 121,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #121 = BIC8mr
  { 122,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #122 = BIC8rc
  { 123,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #123 = BIC8ri
  { 124,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #124 = BIC8rm
  { 125,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #125 = BIC8rn
  { 126,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #126 = BIC8rp
  { 127,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #127 = BIC8rr
  { 128,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #128 = BIS16mc
  { 129,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #129 = BIS16mi
  { 130,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #130 = BIS16mm
  { 131,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #131 = BIS16mn
  { 132,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #132 = BIS16mp
  { 133,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #133 = BIS16mr
  { 134,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #134 = BIS16rc
  { 135,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #135 = BIS16ri
  { 136,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #136 = BIS16rm
  { 137,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #137 = BIS16rn
  { 138,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #138 = BIS16rp
  { 139,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #139 = BIS16rr
  { 140,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #140 = BIS8mc
  { 141,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #141 = BIS8mi
  { 142,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #142 = BIS8mm
  { 143,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #143 = BIS8mn
  { 144,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #144 = BIS8mp
  { 145,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #145 = BIS8mr
  { 146,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #146 = BIS8rc
  { 147,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #147 = BIS8ri
  { 148,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #148 = BIS8rm
  { 149,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #149 = BIS8rn
  { 150,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #150 = BIS8rp
  { 151,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #151 = BIS8rr
  { 152,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #152 = BIT16mc
  { 153,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #153 = BIT16mi
  { 154,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #154 = BIT16mm
  { 155,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #155 = BIT16mn
  { 156,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #156 = BIT16mp
  { 157,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #157 = BIT16mr
  { 158,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #158 = BIT16rc
  { 159,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #159 = BIT16ri
  { 160,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #160 = BIT16rm
  { 161,	2,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #161 = BIT16rn
  { 162,	2,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #162 = BIT16rp
  { 163,	2,	0,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #163 = BIT16rr
  { 164,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #164 = BIT8mc
  { 165,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #165 = BIT8mi
  { 166,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #166 = BIT8mm
  { 167,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #167 = BIT8mn
  { 168,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #168 = BIT8mp
  { 169,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #169 = BIT8mr
  { 170,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #170 = BIT8rc
  { 171,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #171 = BIT8ri
  { 172,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #172 = BIT8rm
  { 173,	2,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #173 = BIT8rn
  { 174,	2,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #174 = BIT8rp
  { 175,	2,	0,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo41, -1 ,nullptr },  // Inst #175 = BIT8rr
  { 176,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #176 = Bi
  { 177,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #177 = Bm
  { 178,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #178 = Br
  { 179,	1,	0,	4,	0,	0|(1ULL<<MCID::Call), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo3, -1 ,nullptr },  // Inst #179 = CALLi
  { 180,	2,	0,	4,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo42, -1 ,nullptr },  // Inst #180 = CALLm
  { 181,	1,	0,	2,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo44, -1 ,nullptr },  // Inst #181 = CALLn
  { 182,	1,	0,	2,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo44, -1 ,nullptr },  // Inst #182 = CALLp
  { 183,	1,	0,	2,	0,	0|(1ULL<<MCID::Call), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo43, -1 ,nullptr },  // Inst #183 = CALLr
  { 184,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #184 = CMP16mc
  { 185,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #185 = CMP16mi
  { 186,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #186 = CMP16mm
  { 187,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #187 = CMP16mn
  { 188,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #188 = CMP16mp
  { 189,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #189 = CMP16mr
  { 190,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #190 = CMP16rc
  { 191,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #191 = CMP16ri
  { 192,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #192 = CMP16rm
  { 193,	2,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #193 = CMP16rn
  { 194,	2,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #194 = CMP16rp
  { 195,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #195 = CMP16rr
  { 196,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #196 = CMP8mc
  { 197,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #197 = CMP8mi
  { 198,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #198 = CMP8mm
  { 199,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #199 = CMP8mn
  { 200,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #200 = CMP8mp
  { 201,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #201 = CMP8mr
  { 202,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #202 = CMP8rc
  { 203,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #203 = CMP8ri
  { 204,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #204 = CMP8rm
  { 205,	2,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #205 = CMP8rn
  { 206,	2,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #206 = CMP8rp
  { 207,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo41, -1 ,nullptr },  // Inst #207 = CMP8rr
  { 208,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #208 = DADD16mc
  { 209,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #209 = DADD16mi
  { 210,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #210 = DADD16mm
  { 211,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #211 = DADD16mn
  { 212,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #212 = DADD16mp
  { 213,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #213 = DADD16mr
  { 214,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #214 = DADD16rc
  { 215,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #215 = DADD16ri
  { 216,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #216 = DADD16rm
  { 217,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #217 = DADD16rn
  { 218,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #218 = DADD16rp
  { 219,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #219 = DADD16rr
  { 220,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #220 = DADD8mc
  { 221,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #221 = DADD8mi
  { 222,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #222 = DADD8mm
  { 223,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #223 = DADD8mn
  { 224,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #224 = DADD8mp
  { 225,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #225 = DADD8mr
  { 226,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #226 = DADD8rc
  { 227,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #227 = DADD8ri
  { 228,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #228 = DADD8rm
  { 229,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #229 = DADD8rn
  { 230,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #230 = DADD8rp
  { 231,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #231 = DADD8rr
  { 232,	2,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList1, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #232 = JCC
  { 233,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #233 = JMP
  { 234,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #234 = MOV16mc
  { 235,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #235 = MOV16mi
  { 236,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #236 = MOV16mm
  { 237,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #237 = MOV16mn
  { 238,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #238 = MOV16mp
  { 239,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #239 = MOV16mr
  { 240,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #240 = MOV16rc
  { 241,	2,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #241 = MOV16ri
  { 242,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #242 = MOV16rm
  { 243,	2,	1,	2,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #243 = MOV16rn
  { 244,	3,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #244 = MOV16rp
  { 245,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #245 = MOV16rr
  { 246,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #246 = MOV8mc
  { 247,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #247 = MOV8mi
  { 248,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #248 = MOV8mm
  { 249,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #249 = MOV8mn
  { 250,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #250 = MOV8mp
  { 251,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #251 = MOV8mr
  { 252,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #252 = MOV8rc
  { 253,	2,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #253 = MOV8ri
  { 254,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #254 = MOV8rm
  { 255,	2,	1,	2,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #255 = MOV8rn
  { 256,	3,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #256 = MOV8rp
  { 257,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #257 = MOV8rr
  { 258,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #258 = MOVZX16rm8
  { 259,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #259 = MOVZX16rr8
  { 260,	1,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo43, -1 ,nullptr },  // Inst #260 = POP16r
  { 261,	1,	0,	2,	0,	0, 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo2, -1 ,nullptr },  // Inst #261 = PUSH16c
  { 262,	1,	0,	4,	0,	0, 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo3, -1 ,nullptr },  // Inst #262 = PUSH16i
  { 263,	1,	0,	2,	0,	0, 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo43, -1 ,nullptr },  // Inst #263 = PUSH16r
  { 264,	1,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo48, -1 ,nullptr },  // Inst #264 = PUSH8r
  { 265,	0,	0,	2,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #265 = RET
  { 266,	0,	0,	2,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #266 = RETI
  { 267,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo42, -1 ,nullptr },  // Inst #267 = RRA16m
  { 268,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #268 = RRA16n
  { 269,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #269 = RRA16p
  { 270,	2,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo49, -1 ,nullptr },  // Inst #270 = RRA16r
  { 271,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo42, -1 ,nullptr },  // Inst #271 = RRA8m
  { 272,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #272 = RRA8n
  { 273,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #273 = RRA8p
  { 274,	2,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo50, -1 ,nullptr },  // Inst #274 = RRA8r
  { 275,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo42, -1 ,nullptr },  // Inst #275 = RRC16m
  { 276,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #276 = RRC16n
  { 277,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #277 = RRC16p
  { 278,	2,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo49, -1 ,nullptr },  // Inst #278 = RRC16r
  { 279,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo42, -1 ,nullptr },  // Inst #279 = RRC8m
  { 280,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #280 = RRC8n
  { 281,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #281 = RRC8p
  { 282,	2,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo50, -1 ,nullptr },  // Inst #282 = RRC8r
  { 283,	2,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #283 = Rrcl16
  { 284,	2,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo41, -1 ,nullptr },  // Inst #284 = Rrcl8
  { 285,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo42, -1 ,nullptr },  // Inst #285 = SEXT16m
  { 286,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #286 = SEXT16n
  { 287,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #287 = SEXT16p
  { 288,	2,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo49, -1 ,nullptr },  // Inst #288 = SEXT16r
  { 289,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #289 = SUB16mc
  { 290,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #290 = SUB16mi
  { 291,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #291 = SUB16mm
  { 292,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #292 = SUB16mn
  { 293,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #293 = SUB16mp
  { 294,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #294 = SUB16mr
  { 295,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #295 = SUB16rc
  { 296,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #296 = SUB16ri
  { 297,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #297 = SUB16rm
  { 298,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #298 = SUB16rn
  { 299,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #299 = SUB16rp
  { 300,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #300 = SUB16rr
  { 301,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #301 = SUB8mc
  { 302,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #302 = SUB8mi
  { 303,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #303 = SUB8mm
  { 304,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #304 = SUB8mn
  { 305,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #305 = SUB8mp
  { 306,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #306 = SUB8mr
  { 307,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #307 = SUB8rc
  { 308,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #308 = SUB8ri
  { 309,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #309 = SUB8rm
  { 310,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #310 = SUB8rn
  { 311,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #311 = SUB8rp
  { 312,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #312 = SUB8rr
  { 313,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #313 = SUBC16mc
  { 314,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #314 = SUBC16mi
  { 315,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #315 = SUBC16mm
  { 316,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #316 = SUBC16mn
  { 317,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #317 = SUBC16mp
  { 318,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #318 = SUBC16mr
  { 319,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #319 = SUBC16rc
  { 320,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #320 = SUBC16ri
  { 321,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #321 = SUBC16rm
  { 322,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #322 = SUBC16rn
  { 323,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #323 = SUBC16rp
  { 324,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #324 = SUBC16rr
  { 325,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #325 = SUBC8mc
  { 326,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #326 = SUBC8mi
  { 327,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #327 = SUBC8mm
  { 328,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #328 = SUBC8mn
  { 329,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #329 = SUBC8mp
  { 330,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #330 = SUBC8mr
  { 331,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #331 = SUBC8rc
  { 332,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #332 = SUBC8ri
  { 333,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #333 = SUBC8rm
  { 334,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #334 = SUBC8rn
  { 335,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #335 = SUBC8rp
  { 336,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #336 = SUBC8rr
  { 337,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #337 = SWPB16m
  { 338,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #338 = SWPB16n
  { 339,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #339 = SWPB16p
  { 340,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #340 = SWPB16r
  { 341,	4,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, ImplicitList1, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #341 = Select16
  { 342,	4,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, ImplicitList1, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #342 = Select8
  { 343,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo53, -1 ,nullptr },  // Inst #343 = Shl16
  { 344,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo54, -1 ,nullptr },  // Inst #344 = Shl8
  { 345,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo53, -1 ,nullptr },  // Inst #345 = Sra16
  { 346,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo54, -1 ,nullptr },  // Inst #346 = Sra8
  { 347,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo53, -1 ,nullptr },  // Inst #347 = Srl16
  { 348,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo54, -1 ,nullptr },  // Inst #348 = Srl8
  { 349,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #349 = XOR16mc
  { 350,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #350 = XOR16mi
  { 351,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #351 = XOR16mm
  { 352,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #352 = XOR16mn
  { 353,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #353 = XOR16mp
  { 354,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #354 = XOR16mr
  { 355,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #355 = XOR16rc
  { 356,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #356 = XOR16ri
  { 357,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #357 = XOR16rm
  { 358,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #358 = XOR16rn
  { 359,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #359 = XOR16rp
  { 360,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #360 = XOR16rr
  { 361,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #361 = XOR8mc
  { 362,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #362 = XOR8mi
  { 363,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #363 = XOR8mm
  { 364,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #364 = XOR8mn
  { 365,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #365 = XOR8mp
  { 366,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #366 = XOR8mr
  { 367,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #367 = XOR8rc
  { 368,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #368 = XOR8ri
  { 369,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #369 = XOR8rm
  { 370,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #370 = XOR8rn
  { 371,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #371 = XOR8rp
  { 372,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #372 = XOR8rr
  { 373,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #373 = ZEXT16r
};

extern const char MSP430InstrNameData[] = {
  /* 0 */ 'S', 'r', 'a', '1', '6', 0,
  /* 6 */ 'R', 'r', 'c', 'l', '1', '6', 0,
  /* 13 */ 'S', 'h', 'l', '1', '6', 0,
  /* 19 */ 'S', 'r', 'l', '1', '6', 0,
  /* 25 */ 'S', 'e', 'l', 'e', 'c', 't', '1', '6', 0,
  /* 34 */ 'S', 'r', 'a', '8', 0,
  /* 39 */ 'R', 'r', 'c', 'l', '8', 0,
  /* 45 */ 'S', 'h', 'l', '8', 0,
  /* 50 */ 'S', 'r', 'l', '8', 0,
  /* 55 */ 'M', 'O', 'V', 'Z', 'X', '1', '6', 'r', 'm', '8', 0,
  /* 66 */ 'M', 'O', 'V', 'Z', 'X', '1', '6', 'r', 'r', '8', 0,
  /* 77 */ 'S', 'e', 'l', 'e', 'c', 't', '8', 0,
  /* 85 */ 'J', 'C', 'C', 0,
  /* 89 */ 'G', '_', 'A', 'D', 'D', 0,
  /* 95 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'E', 'N', 'D', 0,
  /* 108 */ 'L', 'O', 'A', 'D', '_', 'S', 'T', 'A', 'C', 'K', '_', 'G', 'U', 'A', 'R', 'D', 0,
  /* 125 */ 'R', 'E', 'G', '_', 'S', 'E', 'Q', 'U', 'E', 'N', 'C', 'E', 0,
  /* 138 */ 'B', 'U', 'N', 'D', 'L', 'E', 0,
  /* 145 */ 'L', 'O', 'C', 'A', 'L', '_', 'E', 'S', 'C', 'A', 'P', 'E', 0,
  /* 158 */ 'D', 'B', 'G', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 168 */ 'I', 'M', 'P', 'L', 'I', 'C', 'I', 'T', '_', 'D', 'E', 'F', 0,
  /* 181 */ 'E', 'X', 'T', 'R', 'A', 'C', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 196 */ 'I', 'N', 'S', 'E', 'R', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 210 */ 'S', 'U', 'B', 'R', 'E', 'G', '_', 'T', 'O', '_', 'R', 'E', 'G', 0,
  /* 224 */ 'P', 'H', 'I', 0,
  /* 228 */ 'R', 'E', 'T', 'I', 0,
  /* 233 */ 'G', 'C', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 242 */ 'E', 'H', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 251 */ 'K', 'I', 'L', 'L', 0,
  /* 256 */ 'I', 'N', 'L', 'I', 'N', 'E', 'A', 'S', 'M', 0,
  /* 266 */ 'C', 'F', 'I', '_', 'I', 'N', 'S', 'T', 'R', 'U', 'C', 'T', 'I', 'O', 'N', 0,
  /* 282 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'D', 'O', 'W', 'N', 0,
  /* 299 */ 'S', 'T', 'A', 'C', 'K', 'M', 'A', 'P', 0,
  /* 308 */ 'J', 'M', 'P', 0,
  /* 312 */ 'F', 'A', 'U', 'L', 'T', 'I', 'N', 'G', '_', 'L', 'O', 'A', 'D', '_', 'O', 'P', 0,
  /* 329 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'O', 'P', 0,
  /* 342 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'U', 'P', 0,
  /* 357 */ 'G', '_', 'B', 'R', 0,
  /* 362 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'F', 'U', 'N', 'C', 'T', 'I', 'O', 'N', '_', 'E', 'N', 'T', 'E', 'R', 0,
  /* 387 */ 'G', '_', 'O', 'R', 0,
  /* 392 */ 'C', 'O', 'P', 'Y', '_', 'T', 'O', '_', 'R', 'E', 'G', 'C', 'L', 'A', 'S', 'S', 0,
  /* 409 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'R', 'E', 'T', 0,
  /* 423 */ 'S', 'T', 'A', 'T', 'E', 'P', 'O', 'I', 'N', 'T', 0,
  /* 434 */ 'P', 'A', 'T', 'C', 'H', 'P', 'O', 'I', 'N', 'T', 0,
  /* 445 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'S', 'T', 'A', 'R', 'T', 0,
  /* 460 */ 'C', 'O', 'P', 'Y', 0,
  /* 465 */ 'P', 'U', 'S', 'H', '1', '6', 'c', 0,
  /* 473 */ 'S', 'U', 'B', '1', '6', 'm', 'c', 0,
  /* 481 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'c', 0,
  /* 490 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'c', 0,
  /* 499 */ 'B', 'I', 'C', '1', '6', 'm', 'c', 0,
  /* 507 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'c', 0,
  /* 516 */ 'A', 'N', 'D', '1', '6', 'm', 'c', 0,
  /* 524 */ 'C', 'M', 'P', '1', '6', 'm', 'c', 0,
  /* 532 */ 'X', 'O', 'R', '1', '6', 'm', 'c', 0,
  /* 540 */ 'B', 'I', 'S', '1', '6', 'm', 'c', 0,
  /* 548 */ 'B', 'I', 'T', '1', '6', 'm', 'c', 0,
  /* 556 */ 'M', 'O', 'V', '1', '6', 'm', 'c', 0,
  /* 564 */ 'S', 'U', 'B', '8', 'm', 'c', 0,
  /* 571 */ 'S', 'U', 'B', 'C', '8', 'm', 'c', 0,
  /* 579 */ 'A', 'D', 'D', 'C', '8', 'm', 'c', 0,
  /* 587 */ 'B', 'I', 'C', '8', 'm', 'c', 0,
  /* 594 */ 'D', 'A', 'D', 'D', '8', 'm', 'c', 0,
  /* 602 */ 'A', 'N', 'D', '8', 'm', 'c', 0,
  /* 609 */ 'C', 'M', 'P', '8', 'm', 'c', 0,
  /* 616 */ 'X', 'O', 'R', '8', 'm', 'c', 0,
  /* 623 */ 'B', 'I', 'S', '8', 'm', 'c', 0,
  /* 630 */ 'B', 'I', 'T', '8', 'm', 'c', 0,
  /* 637 */ 'M', 'O', 'V', '8', 'm', 'c', 0,
  /* 644 */ 'S', 'U', 'B', '1', '6', 'r', 'c', 0,
  /* 652 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'c', 0,
  /* 661 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'c', 0,
  /* 670 */ 'B', 'I', 'C', '1', '6', 'r', 'c', 0,
  /* 678 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'c', 0,
  /* 687 */ 'A', 'N', 'D', '1', '6', 'r', 'c', 0,
  /* 695 */ 'C', 'M', 'P', '1', '6', 'r', 'c', 0,
  /* 703 */ 'X', 'O', 'R', '1', '6', 'r', 'c', 0,
  /* 711 */ 'B', 'I', 'S', '1', '6', 'r', 'c', 0,
  /* 719 */ 'B', 'I', 'T', '1', '6', 'r', 'c', 0,
  /* 727 */ 'M', 'O', 'V', '1', '6', 'r', 'c', 0,
  /* 735 */ 'S', 'U', 'B', '8', 'r', 'c', 0,
  /* 742 */ 'S', 'U', 'B', 'C', '8', 'r', 'c', 0,
  /* 750 */ 'A', 'D', 'D', 'C', '8', 'r', 'c', 0,
  /* 758 */ 'B', 'I', 'C', '8', 'r', 'c', 0,
  /* 765 */ 'D', 'A', 'D', 'D', '8', 'r', 'c', 0,
  /* 773 */ 'A', 'N', 'D', '8', 'r', 'c', 0,
  /* 780 */ 'C', 'M', 'P', '8', 'r', 'c', 0,
  /* 787 */ 'X', 'O', 'R', '8', 'r', 'c', 0,
  /* 794 */ 'B', 'I', 'S', '8', 'r', 'c', 0,
  /* 801 */ 'B', 'I', 'T', '8', 'r', 'c', 0,
  /* 808 */ 'M', 'O', 'V', '8', 'r', 'c', 0,
  /* 815 */ 'A', 'D', 'D', 'f', 'r', 'a', 'm', 'e', 0,
  /* 824 */ 'P', 'U', 'S', 'H', '1', '6', 'i', 0,
  /* 832 */ 'B', 'i', 0,
  /* 835 */ 'C', 'A', 'L', 'L', 'i', 0,
  /* 841 */ 'S', 'U', 'B', '1', '6', 'm', 'i', 0,
  /* 849 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'i', 0,
  /* 858 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'i', 0,
  /* 867 */ 'B', 'I', 'C', '1', '6', 'm', 'i', 0,
  /* 875 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'i', 0,
  /* 884 */ 'A', 'N', 'D', '1', '6', 'm', 'i', 0,
  /* 892 */ 'C', 'M', 'P', '1', '6', 'm', 'i', 0,
  /* 900 */ 'X', 'O', 'R', '1', '6', 'm', 'i', 0,
  /* 908 */ 'B', 'I', 'S', '1', '6', 'm', 'i', 0,
  /* 916 */ 'B', 'I', 'T', '1', '6', 'm', 'i', 0,
  /* 924 */ 'M', 'O', 'V', '1', '6', 'm', 'i', 0,
  /* 932 */ 'S', 'U', 'B', '8', 'm', 'i', 0,
  /* 939 */ 'S', 'U', 'B', 'C', '8', 'm', 'i', 0,
  /* 947 */ 'A', 'D', 'D', 'C', '8', 'm', 'i', 0,
  /* 955 */ 'B', 'I', 'C', '8', 'm', 'i', 0,
  /* 962 */ 'D', 'A', 'D', 'D', '8', 'm', 'i', 0,
  /* 970 */ 'A', 'N', 'D', '8', 'm', 'i', 0,
  /* 977 */ 'C', 'M', 'P', '8', 'm', 'i', 0,
  /* 984 */ 'X', 'O', 'R', '8', 'm', 'i', 0,
  /* 991 */ 'B', 'I', 'S', '8', 'm', 'i', 0,
  /* 998 */ 'B', 'I', 'T', '8', 'm', 'i', 0,
  /* 1005 */ 'M', 'O', 'V', '8', 'm', 'i', 0,
  /* 1012 */ 'S', 'U', 'B', '1', '6', 'r', 'i', 0,
  /* 1020 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'i', 0,
  /* 1029 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'i', 0,
  /* 1038 */ 'B', 'I', 'C', '1', '6', 'r', 'i', 0,
  /* 1046 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'i', 0,
  /* 1055 */ 'A', 'N', 'D', '1', '6', 'r', 'i', 0,
  /* 1063 */ 'C', 'M', 'P', '1', '6', 'r', 'i', 0,
  /* 1071 */ 'X', 'O', 'R', '1', '6', 'r', 'i', 0,
  /* 1079 */ 'B', 'I', 'S', '1', '6', 'r', 'i', 0,
  /* 1087 */ 'B', 'I', 'T', '1', '6', 'r', 'i', 0,
  /* 1095 */ 'M', 'O', 'V', '1', '6', 'r', 'i', 0,
  /* 1103 */ 'S', 'U', 'B', '8', 'r', 'i', 0,
  /* 1110 */ 'S', 'U', 'B', 'C', '8', 'r', 'i', 0,
  /* 1118 */ 'A', 'D', 'D', 'C', '8', 'r', 'i', 0,
  /* 1126 */ 'B', 'I', 'C', '8', 'r', 'i', 0,
  /* 1133 */ 'D', 'A', 'D', 'D', '8', 'r', 'i', 0,
  /* 1141 */ 'A', 'N', 'D', '8', 'r', 'i', 0,
  /* 1148 */ 'C', 'M', 'P', '8', 'r', 'i', 0,
  /* 1155 */ 'X', 'O', 'R', '8', 'r', 'i', 0,
  /* 1162 */ 'B', 'I', 'S', '8', 'r', 'i', 0,
  /* 1169 */ 'B', 'I', 'T', '8', 'r', 'i', 0,
  /* 1176 */ 'M', 'O', 'V', '8', 'r', 'i', 0,
  /* 1183 */ 'R', 'R', 'A', '1', '6', 'm', 0,
  /* 1190 */ 'S', 'W', 'P', 'B', '1', '6', 'm', 0,
  /* 1198 */ 'R', 'R', 'C', '1', '6', 'm', 0,
  /* 1205 */ 'S', 'E', 'X', 'T', '1', '6', 'm', 0,
  /* 1213 */ 'R', 'R', 'A', '8', 'm', 0,
  /* 1219 */ 'R', 'R', 'C', '8', 'm', 0,
  /* 1225 */ 'B', 'm', 0,
  /* 1228 */ 'C', 'A', 'L', 'L', 'm', 0,
  /* 1234 */ 'S', 'U', 'B', '1', '6', 'm', 'm', 0,
  /* 1242 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'm', 0,
  /* 1251 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'm', 0,
  /* 1260 */ 'B', 'I', 'C', '1', '6', 'm', 'm', 0,
  /* 1268 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'm', 0,
  /* 1277 */ 'A', 'N', 'D', '1', '6', 'm', 'm', 0,
  /* 1285 */ 'C', 'M', 'P', '1', '6', 'm', 'm', 0,
  /* 1293 */ 'X', 'O', 'R', '1', '6', 'm', 'm', 0,
  /* 1301 */ 'B', 'I', 'S', '1', '6', 'm', 'm', 0,
  /* 1309 */ 'B', 'I', 'T', '1', '6', 'm', 'm', 0,
  /* 1317 */ 'M', 'O', 'V', '1', '6', 'm', 'm', 0,
  /* 1325 */ 'S', 'U', 'B', '8', 'm', 'm', 0,
  /* 1332 */ 'S', 'U', 'B', 'C', '8', 'm', 'm', 0,
  /* 1340 */ 'A', 'D', 'D', 'C', '8', 'm', 'm', 0,
  /* 1348 */ 'B', 'I', 'C', '8', 'm', 'm', 0,
  /* 1355 */ 'D', 'A', 'D', 'D', '8', 'm', 'm', 0,
  /* 1363 */ 'A', 'N', 'D', '8', 'm', 'm', 0,
  /* 1370 */ 'C', 'M', 'P', '8', 'm', 'm', 0,
  /* 1377 */ 'X', 'O', 'R', '8', 'm', 'm', 0,
  /* 1384 */ 'B', 'I', 'S', '8', 'm', 'm', 0,
  /* 1391 */ 'B', 'I', 'T', '8', 'm', 'm', 0,
  /* 1398 */ 'M', 'O', 'V', '8', 'm', 'm', 0,
  /* 1405 */ 'S', 'U', 'B', '1', '6', 'r', 'm', 0,
  /* 1413 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'm', 0,
  /* 1422 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'm', 0,
  /* 1431 */ 'B', 'I', 'C', '1', '6', 'r', 'm', 0,
  /* 1439 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'm', 0,
  /* 1448 */ 'A', 'N', 'D', '1', '6', 'r', 'm', 0,
  /* 1456 */ 'C', 'M', 'P', '1', '6', 'r', 'm', 0,
  /* 1464 */ 'X', 'O', 'R', '1', '6', 'r', 'm', 0,
  /* 1472 */ 'B', 'I', 'S', '1', '6', 'r', 'm', 0,
  /* 1480 */ 'B', 'I', 'T', '1', '6', 'r', 'm', 0,
  /* 1488 */ 'M', 'O', 'V', '1', '6', 'r', 'm', 0,
  /* 1496 */ 'S', 'U', 'B', '8', 'r', 'm', 0,
  /* 1503 */ 'S', 'U', 'B', 'C', '8', 'r', 'm', 0,
  /* 1511 */ 'A', 'D', 'D', 'C', '8', 'r', 'm', 0,
  /* 1519 */ 'B', 'I', 'C', '8', 'r', 'm', 0,
  /* 1526 */ 'D', 'A', 'D', 'D', '8', 'r', 'm', 0,
  /* 1534 */ 'A', 'N', 'D', '8', 'r', 'm', 0,
  /* 1541 */ 'C', 'M', 'P', '8', 'r', 'm', 0,
  /* 1548 */ 'X', 'O', 'R', '8', 'r', 'm', 0,
  /* 1555 */ 'B', 'I', 'S', '8', 'r', 'm', 0,
  /* 1562 */ 'B', 'I', 'T', '8', 'r', 'm', 0,
  /* 1569 */ 'M', 'O', 'V', '8', 'r', 'm', 0,
  /* 1576 */ 'R', 'R', 'A', '1', '6', 'n', 0,
  /* 1583 */ 'S', 'W', 'P', 'B', '1', '6', 'n', 0,
  /* 1591 */ 'R', 'R', 'C', '1', '6', 'n', 0,
  /* 1598 */ 'S', 'E', 'X', 'T', '1', '6', 'n', 0,
  /* 1606 */ 'R', 'R', 'A', '8', 'n', 0,
  /* 1612 */ 'R', 'R', 'C', '8', 'n', 0,
  /* 1618 */ 'C', 'A', 'L', 'L', 'n', 0,
  /* 1624 */ 'S', 'U', 'B', '1', '6', 'm', 'n', 0,
  /* 1632 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'n', 0,
  /* 1641 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'n', 0,
  /* 1650 */ 'B', 'I', 'C', '1', '6', 'm', 'n', 0,
  /* 1658 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'n', 0,
  /* 1667 */ 'A', 'N', 'D', '1', '6', 'm', 'n', 0,
  /* 1675 */ 'C', 'M', 'P', '1', '6', 'm', 'n', 0,
  /* 1683 */ 'X', 'O', 'R', '1', '6', 'm', 'n', 0,
  /* 1691 */ 'B', 'I', 'S', '1', '6', 'm', 'n', 0,
  /* 1699 */ 'B', 'I', 'T', '1', '6', 'm', 'n', 0,
  /* 1707 */ 'M', 'O', 'V', '1', '6', 'm', 'n', 0,
  /* 1715 */ 'S', 'U', 'B', '8', 'm', 'n', 0,
  /* 1722 */ 'S', 'U', 'B', 'C', '8', 'm', 'n', 0,
  /* 1730 */ 'A', 'D', 'D', 'C', '8', 'm', 'n', 0,
  /* 1738 */ 'B', 'I', 'C', '8', 'm', 'n', 0,
  /* 1745 */ 'D', 'A', 'D', 'D', '8', 'm', 'n', 0,
  /* 1753 */ 'A', 'N', 'D', '8', 'm', 'n', 0,
  /* 1760 */ 'C', 'M', 'P', '8', 'm', 'n', 0,
  /* 1767 */ 'X', 'O', 'R', '8', 'm', 'n', 0,
  /* 1774 */ 'B', 'I', 'S', '8', 'm', 'n', 0,
  /* 1781 */ 'B', 'I', 'T', '8', 'm', 'n', 0,
  /* 1788 */ 'M', 'O', 'V', '8', 'm', 'n', 0,
  /* 1795 */ 'S', 'U', 'B', '1', '6', 'r', 'n', 0,
  /* 1803 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'n', 0,
  /* 1812 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'n', 0,
  /* 1821 */ 'B', 'I', 'C', '1', '6', 'r', 'n', 0,
  /* 1829 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'n', 0,
  /* 1838 */ 'A', 'N', 'D', '1', '6', 'r', 'n', 0,
  /* 1846 */ 'C', 'M', 'P', '1', '6', 'r', 'n', 0,
  /* 1854 */ 'X', 'O', 'R', '1', '6', 'r', 'n', 0,
  /* 1862 */ 'B', 'I', 'S', '1', '6', 'r', 'n', 0,
  /* 1870 */ 'B', 'I', 'T', '1', '6', 'r', 'n', 0,
  /* 1878 */ 'M', 'O', 'V', '1', '6', 'r', 'n', 0,
  /* 1886 */ 'S', 'U', 'B', '8', 'r', 'n', 0,
  /* 1893 */ 'S', 'U', 'B', 'C', '8', 'r', 'n', 0,
  /* 1901 */ 'A', 'D', 'D', 'C', '8', 'r', 'n', 0,
  /* 1909 */ 'B', 'I', 'C', '8', 'r', 'n', 0,
  /* 1916 */ 'D', 'A', 'D', 'D', '8', 'r', 'n', 0,
  /* 1924 */ 'A', 'N', 'D', '8', 'r', 'n', 0,
  /* 1931 */ 'C', 'M', 'P', '8', 'r', 'n', 0,
  /* 1938 */ 'X', 'O', 'R', '8', 'r', 'n', 0,
  /* 1945 */ 'B', 'I', 'S', '8', 'r', 'n', 0,
  /* 1952 */ 'B', 'I', 'T', '8', 'r', 'n', 0,
  /* 1959 */ 'M', 'O', 'V', '8', 'r', 'n', 0,
  /* 1966 */ 'R', 'R', 'A', '1', '6', 'p', 0,
  /* 1973 */ 'S', 'W', 'P', 'B', '1', '6', 'p', 0,
  /* 1981 */ 'R', 'R', 'C', '1', '6', 'p', 0,
  /* 1988 */ 'S', 'E', 'X', 'T', '1', '6', 'p', 0,
  /* 1996 */ 'R', 'R', 'A', '8', 'p', 0,
  /* 2002 */ 'R', 'R', 'C', '8', 'p', 0,
  /* 2008 */ 'C', 'A', 'L', 'L', 'p', 0,
  /* 2014 */ 'S', 'U', 'B', '1', '6', 'm', 'p', 0,
  /* 2022 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'p', 0,
  /* 2031 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'p', 0,
  /* 2040 */ 'B', 'I', 'C', '1', '6', 'm', 'p', 0,
  /* 2048 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'p', 0,
  /* 2057 */ 'A', 'N', 'D', '1', '6', 'm', 'p', 0,
  /* 2065 */ 'C', 'M', 'P', '1', '6', 'm', 'p', 0,
  /* 2073 */ 'X', 'O', 'R', '1', '6', 'm', 'p', 0,
  /* 2081 */ 'B', 'I', 'S', '1', '6', 'm', 'p', 0,
  /* 2089 */ 'B', 'I', 'T', '1', '6', 'm', 'p', 0,
  /* 2097 */ 'M', 'O', 'V', '1', '6', 'm', 'p', 0,
  /* 2105 */ 'S', 'U', 'B', '8', 'm', 'p', 0,
  /* 2112 */ 'S', 'U', 'B', 'C', '8', 'm', 'p', 0,
  /* 2120 */ 'A', 'D', 'D', 'C', '8', 'm', 'p', 0,
  /* 2128 */ 'B', 'I', 'C', '8', 'm', 'p', 0,
  /* 2135 */ 'D', 'A', 'D', 'D', '8', 'm', 'p', 0,
  /* 2143 */ 'A', 'N', 'D', '8', 'm', 'p', 0,
  /* 2150 */ 'C', 'M', 'P', '8', 'm', 'p', 0,
  /* 2157 */ 'X', 'O', 'R', '8', 'm', 'p', 0,
  /* 2164 */ 'B', 'I', 'S', '8', 'm', 'p', 0,
  /* 2171 */ 'B', 'I', 'T', '8', 'm', 'p', 0,
  /* 2178 */ 'M', 'O', 'V', '8', 'm', 'p', 0,
  /* 2185 */ 'S', 'U', 'B', '1', '6', 'r', 'p', 0,
  /* 2193 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'p', 0,
  /* 2202 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'p', 0,
  /* 2211 */ 'B', 'I', 'C', '1', '6', 'r', 'p', 0,
  /* 2219 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'p', 0,
  /* 2228 */ 'A', 'N', 'D', '1', '6', 'r', 'p', 0,
  /* 2236 */ 'C', 'M', 'P', '1', '6', 'r', 'p', 0,
  /* 2244 */ 'X', 'O', 'R', '1', '6', 'r', 'p', 0,
  /* 2252 */ 'B', 'I', 'S', '1', '6', 'r', 'p', 0,
  /* 2260 */ 'B', 'I', 'T', '1', '6', 'r', 'p', 0,
  /* 2268 */ 'M', 'O', 'V', '1', '6', 'r', 'p', 0,
  /* 2276 */ 'S', 'U', 'B', '8', 'r', 'p', 0,
  /* 2283 */ 'S', 'U', 'B', 'C', '8', 'r', 'p', 0,
  /* 2291 */ 'A', 'D', 'D', 'C', '8', 'r', 'p', 0,
  /* 2299 */ 'B', 'I', 'C', '8', 'r', 'p', 0,
  /* 2306 */ 'D', 'A', 'D', 'D', '8', 'r', 'p', 0,
  /* 2314 */ 'A', 'N', 'D', '8', 'r', 'p', 0,
  /* 2321 */ 'C', 'M', 'P', '8', 'r', 'p', 0,
  /* 2328 */ 'X', 'O', 'R', '8', 'r', 'p', 0,
  /* 2335 */ 'B', 'I', 'S', '8', 'r', 'p', 0,
  /* 2342 */ 'B', 'I', 'T', '8', 'r', 'p', 0,
  /* 2349 */ 'M', 'O', 'V', '8', 'r', 'p', 0,
  /* 2356 */ 'R', 'R', 'A', '1', '6', 'r', 0,
  /* 2363 */ 'S', 'W', 'P', 'B', '1', '6', 'r', 0,
  /* 2371 */ 'R', 'R', 'C', '1', '6', 'r', 0,
  /* 2378 */ 'P', 'U', 'S', 'H', '1', '6', 'r', 0,
  /* 2386 */ 'P', 'O', 'P', '1', '6', 'r', 0,
  /* 2393 */ 'S', 'E', 'X', 'T', '1', '6', 'r', 0,
  /* 2401 */ 'Z', 'E', 'X', 'T', '1', '6', 'r', 0,
  /* 2409 */ 'R', 'R', 'A', '8', 'r', 0,
  /* 2415 */ 'R', 'R', 'C', '8', 'r', 0,
  /* 2421 */ 'P', 'U', 'S', 'H', '8', 'r', 0,
  /* 2428 */ 'B', 'r', 0,
  /* 2431 */ 'C', 'A', 'L', 'L', 'r', 0,
  /* 2437 */ 'S', 'U', 'B', '1', '6', 'm', 'r', 0,
  /* 2445 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'r', 0,
  /* 2454 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'r', 0,
  /* 2463 */ 'B', 'I', 'C', '1', '6', 'm', 'r', 0,
  /* 2471 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'r', 0,
  /* 2480 */ 'A', 'N', 'D', '1', '6', 'm', 'r', 0,
  /* 2488 */ 'C', 'M', 'P', '1', '6', 'm', 'r', 0,
  /* 2496 */ 'X', 'O', 'R', '1', '6', 'm', 'r', 0,
  /* 2504 */ 'B', 'I', 'S', '1', '6', 'm', 'r', 0,
  /* 2512 */ 'B', 'I', 'T', '1', '6', 'm', 'r', 0,
  /* 2520 */ 'M', 'O', 'V', '1', '6', 'm', 'r', 0,
  /* 2528 */ 'S', 'U', 'B', '8', 'm', 'r', 0,
  /* 2535 */ 'S', 'U', 'B', 'C', '8', 'm', 'r', 0,
  /* 2543 */ 'A', 'D', 'D', 'C', '8', 'm', 'r', 0,
  /* 2551 */ 'B', 'I', 'C', '8', 'm', 'r', 0,
  /* 2558 */ 'D', 'A', 'D', 'D', '8', 'm', 'r', 0,
  /* 2566 */ 'A', 'N', 'D', '8', 'm', 'r', 0,
  /* 2573 */ 'C', 'M', 'P', '8', 'm', 'r', 0,
  /* 2580 */ 'X', 'O', 'R', '8', 'm', 'r', 0,
  /* 2587 */ 'B', 'I', 'S', '8', 'm', 'r', 0,
  /* 2594 */ 'B', 'I', 'T', '8', 'm', 'r', 0,
  /* 2601 */ 'M', 'O', 'V', '8', 'm', 'r', 0,
  /* 2608 */ 'S', 'U', 'B', '1', '6', 'r', 'r', 0,
  /* 2616 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'r', 0,
  /* 2625 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'r', 0,
  /* 2634 */ 'B', 'I', 'C', '1', '6', 'r', 'r', 0,
  /* 2642 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'r', 0,
  /* 2651 */ 'A', 'N', 'D', '1', '6', 'r', 'r', 0,
  /* 2659 */ 'C', 'M', 'P', '1', '6', 'r', 'r', 0,
  /* 2667 */ 'X', 'O', 'R', '1', '6', 'r', 'r', 0,
  /* 2675 */ 'B', 'I', 'S', '1', '6', 'r', 'r', 0,
  /* 2683 */ 'B', 'I', 'T', '1', '6', 'r', 'r', 0,
  /* 2691 */ 'M', 'O', 'V', '1', '6', 'r', 'r', 0,
  /* 2699 */ 'S', 'U', 'B', '8', 'r', 'r', 0,
  /* 2706 */ 'S', 'U', 'B', 'C', '8', 'r', 'r', 0,
  /* 2714 */ 'A', 'D', 'D', 'C', '8', 'r', 'r', 0,
  /* 2722 */ 'B', 'I', 'C', '8', 'r', 'r', 0,
  /* 2729 */ 'D', 'A', 'D', 'D', '8', 'r', 'r', 0,
  /* 2737 */ 'A', 'N', 'D', '8', 'r', 'r', 0,
  /* 2744 */ 'C', 'M', 'P', '8', 'r', 'r', 0,
  /* 2751 */ 'X', 'O', 'R', '8', 'r', 'r', 0,
  /* 2758 */ 'B', 'I', 'S', '8', 'r', 'r', 0,
  /* 2765 */ 'B', 'I', 'T', '8', 'r', 'r', 0,
  /* 2772 */ 'M', 'O', 'V', '8', 'r', 'r', 0,
};

extern const unsigned MSP430InstrNameIndices[] = {
    224U, 256U, 266U, 242U, 233U, 251U, 181U, 196U, 
    168U, 210U, 392U, 158U, 125U, 460U, 138U, 445U, 
    95U, 299U, 434U, 108U, 423U, 145U, 312U, 329U, 
    362U, 409U, 89U, 387U, 357U, 508U, 876U, 1269U, 
    1659U, 2049U, 2472U, 679U, 1047U, 1440U, 1830U, 2220U, 
    2643U, 595U, 963U, 1356U, 1746U, 2136U, 2559U, 766U, 
    1134U, 1527U, 1917U, 2307U, 2730U, 490U, 858U, 1251U, 
    1641U, 2031U, 2454U, 661U, 1029U, 1422U, 1812U, 2202U, 
    2625U, 579U, 947U, 1340U, 1730U, 2120U, 2543U, 750U, 
    1118U, 1511U, 1901U, 2291U, 2714U, 815U, 282U, 342U, 
    516U, 884U, 1277U, 1667U, 2057U, 2480U, 687U, 1055U, 
    1448U, 1838U, 2228U, 2651U, 602U, 970U, 1363U, 1753U, 
    2143U, 2566U, 773U, 1141U, 1534U, 1924U, 2314U, 2737U, 
    499U, 867U, 1260U, 1650U, 2040U, 2463U, 670U, 1038U, 
    1431U, 1821U, 2211U, 2634U, 587U, 955U, 1348U, 1738U, 
    2128U, 2551U, 758U, 1126U, 1519U, 1909U, 2299U, 2722U, 
    540U, 908U, 1301U, 1691U, 2081U, 2504U, 711U, 1079U, 
    1472U, 1862U, 2252U, 2675U, 623U, 991U, 1384U, 1774U, 
    2164U, 2587U, 794U, 1162U, 1555U, 1945U, 2335U, 2758U, 
    548U, 916U, 1309U, 1699U, 2089U, 2512U, 719U, 1087U, 
    1480U, 1870U, 2260U, 2683U, 630U, 998U, 1391U, 1781U, 
    2171U, 2594U, 801U, 1169U, 1562U, 1952U, 2342U, 2765U, 
    832U, 1225U, 2428U, 835U, 1228U, 1618U, 2008U, 2431U, 
    524U, 892U, 1285U, 1675U, 2065U, 2488U, 695U, 1063U, 
    1456U, 1846U, 2236U, 2659U, 609U, 977U, 1370U, 1760U, 
    2150U, 2573U, 780U, 1148U, 1541U, 1931U, 2321U, 2744U, 
    507U, 875U, 1268U, 1658U, 2048U, 2471U, 678U, 1046U, 
    1439U, 1829U, 2219U, 2642U, 594U, 962U, 1355U, 1745U, 
    2135U, 2558U, 765U, 1133U, 1526U, 1916U, 2306U, 2729U, 
    85U, 308U, 556U, 924U, 1317U, 1707U, 2097U, 2520U, 
    727U, 1095U, 1488U, 1878U, 2268U, 2691U, 637U, 1005U, 
    1398U, 1788U, 2178U, 2601U, 808U, 1176U, 1569U, 1959U, 
    2349U, 2772U, 55U, 66U, 2386U, 465U, 824U, 2378U, 
    2421U, 419U, 228U, 1183U, 1576U, 1966U, 2356U, 1213U, 
    1606U, 1996U, 2409U, 1198U, 1591U, 1981U, 2371U, 1219U, 
    1612U, 2002U, 2415U, 6U, 39U, 1205U, 1598U, 1988U, 
    2393U, 473U, 841U, 1234U, 1624U, 2014U, 2437U, 644U, 
    1012U, 1405U, 1795U, 2185U, 2608U, 564U, 932U, 1325U, 
    1715U, 2105U, 2528U, 735U, 1103U, 1496U, 1886U, 2276U, 
    2699U, 481U, 849U, 1242U, 1632U, 2022U, 2445U, 652U, 
    1020U, 1413U, 1803U, 2193U, 2616U, 571U, 939U, 1332U, 
    1722U, 2112U, 2535U, 742U, 1110U, 1503U, 1893U, 2283U, 
    2706U, 1190U, 1583U, 1973U, 2363U, 25U, 77U, 13U, 
    45U, 0U, 34U, 19U, 50U, 532U, 900U, 1293U, 
    1683U, 2073U, 2496U, 703U, 1071U, 1464U, 1854U, 2244U, 
    2667U, 616U, 984U, 1377U, 1767U, 2157U, 2580U, 787U, 
    1155U, 1548U, 1938U, 2328U, 2751U, 2401U, 
};

static inline void InitMSP430MCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(MSP430Insts, MSP430InstrNameIndices, MSP430InstrNameData, 374);
}

} // end llvm namespace
#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER
namespace llvm_ks {
struct MSP430GenInstrInfo : public TargetInstrInfo {
  explicit MSP430GenInstrInfo(int CFSetupOpcode = -1, int CFDestroyOpcode = -1, int CatchRetOpcode = -1, int ReturnOpcode = -1);
  ~MSP430GenInstrInfo() override {}
};
} // end llvm namespace
#endif // GET_INSTRINFO_HEADER

#ifdef GET_INSTRINFO_CTOR_DTOR
#undef GET_INSTRINFO_CTOR_DTOR
namespace llvm_ks {
extern const MCInstrDesc MSP430Insts[];
extern const unsigned MSP430InstrNameIndices[];
extern const char MSP430InstrNameData[];
MSP430GenInstrInfo::MSP430GenInstrInfo(int CFSetupOpcode, int CFDestroyOpcode, int CatchRetOpcode, int ReturnOpcode)
  : TargetInstrInfo(CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(MSP430Insts, MSP430InstrNameIndices, MSP430InstrNameData, 374);
}
} // end llvm namespace
#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM
namespace llvm_ks {
namespace MSP430 {
namespace OpName {
enum {
OPERAND_LAST
};
} // end namespace OpName
} // end namespace MSP430
} // end namespace llvm_ks
#endif //GET_INSTRINFO_OPERAND_ENUM

#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS
namespace llvm_ks {
namespace MSP430 {
LLVM_READONLY
int16_t getNamedOperandIdx(uint16_t Opcode, uint16_t NamedIdx) {
  return -1;
}
} // end namespace MSP430
} // end namespace llvm_ks
#endif //GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_OPERAND_TYPES_ENUM
#undef GET_INSTRINFO_OPERAND_TYPES_ENUM
namespace llvm_ks {
namespace MSP430 {
namespace OpTypes {
enum OperandType {
  cc = 0,
  cg16imm = 1,
  cg8imm = 2,
  f32imm = 3,
  f64imm = 4,
  i16imm = 5,
  i1imm = 6,
  i32imm = 7,
  i64imm = 8,
  i8imm = 9,
  indreg = 10,
  jmptarget = 11,
  memdst = 12,
  memsrc = 13,
  postreg = 14,
  OPERAND_TYPE_LIST_END
};
} // end namespace OpTypes
} // end namespace MSP430
} // end namespace llvm_ks
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM

