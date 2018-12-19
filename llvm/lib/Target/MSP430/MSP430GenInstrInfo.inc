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
    BIT16mr	= 155,
    BIT16rc	= 156,
    BIT16ri	= 157,
    BIT16rm	= 158,
    BIT16rr	= 159,
    BIT8mc	= 160,
    BIT8mi	= 161,
    BIT8mm	= 162,
    BIT8mr	= 163,
    BIT8rc	= 164,
    BIT8ri	= 165,
    BIT8rm	= 166,
    BIT8rr	= 167,
    Bi	= 168,
    Bm	= 169,
    Br	= 170,
    CALLi	= 171,
    CALLm	= 172,
    CALLr	= 173,
    CMP16mc	= 174,
    CMP16mi	= 175,
    CMP16mr	= 176,
    CMP16rc	= 177,
    CMP16ri	= 178,
    CMP16rm	= 179,
    CMP16rr	= 180,
    CMP8mc	= 181,
    CMP8mi	= 182,
    CMP8mr	= 183,
    CMP8rc	= 184,
    CMP8ri	= 185,
    CMP8rm	= 186,
    CMP8rr	= 187,
    DADD16mc	= 188,
    DADD16mi	= 189,
    DADD16mm	= 190,
    DADD16mn	= 191,
    DADD16mp	= 192,
    DADD16mr	= 193,
    DADD16rc	= 194,
    DADD16ri	= 195,
    DADD16rm	= 196,
    DADD16rn	= 197,
    DADD16rp	= 198,
    DADD16rr	= 199,
    DADD8mc	= 200,
    DADD8mi	= 201,
    DADD8mm	= 202,
    DADD8mn	= 203,
    DADD8mp	= 204,
    DADD8mr	= 205,
    DADD8rc	= 206,
    DADD8ri	= 207,
    DADD8rm	= 208,
    DADD8rn	= 209,
    DADD8rp	= 210,
    DADD8rr	= 211,
    JCC	= 212,
    JMP	= 213,
    MOV16mc	= 214,
    MOV16mi	= 215,
    MOV16mm	= 216,
    MOV16mr	= 217,
    MOV16rc	= 218,
    MOV16ri	= 219,
    MOV16rm	= 220,
    MOV16rn	= 221,
    MOV16rp	= 222,
    MOV16rr	= 223,
    MOV8mc	= 224,
    MOV8mi	= 225,
    MOV8mm	= 226,
    MOV8mr	= 227,
    MOV8rc	= 228,
    MOV8ri	= 229,
    MOV8rm	= 230,
    MOV8rn	= 231,
    MOV8rp	= 232,
    MOV8rr	= 233,
    MOVZX16rm8	= 234,
    MOVZX16rr8	= 235,
    POP16r	= 236,
    PUSH16c	= 237,
    PUSH16i	= 238,
    PUSH16r	= 239,
    PUSH8r	= 240,
    RET	= 241,
    RETI	= 242,
    RRA16r	= 243,
    RRA8r	= 244,
    RRC16r	= 245,
    RRC8r	= 246,
    Rrcl16	= 247,
    Rrcl8	= 248,
    SEXT16r	= 249,
    SUB16mc	= 250,
    SUB16mi	= 251,
    SUB16mm	= 252,
    SUB16mn	= 253,
    SUB16mp	= 254,
    SUB16mr	= 255,
    SUB16rc	= 256,
    SUB16ri	= 257,
    SUB16rm	= 258,
    SUB16rn	= 259,
    SUB16rp	= 260,
    SUB16rr	= 261,
    SUB8mc	= 262,
    SUB8mi	= 263,
    SUB8mm	= 264,
    SUB8mn	= 265,
    SUB8mp	= 266,
    SUB8mr	= 267,
    SUB8rc	= 268,
    SUB8ri	= 269,
    SUB8rm	= 270,
    SUB8rn	= 271,
    SUB8rp	= 272,
    SUB8rr	= 273,
    SUBC16mc	= 274,
    SUBC16mi	= 275,
    SUBC16mm	= 276,
    SUBC16mn	= 277,
    SUBC16mp	= 278,
    SUBC16mr	= 279,
    SUBC16rc	= 280,
    SUBC16ri	= 281,
    SUBC16rm	= 282,
    SUBC16rn	= 283,
    SUBC16rp	= 284,
    SUBC16rr	= 285,
    SUBC8mc	= 286,
    SUBC8mi	= 287,
    SUBC8mm	= 288,
    SUBC8mn	= 289,
    SUBC8mp	= 290,
    SUBC8mr	= 291,
    SUBC8rc	= 292,
    SUBC8ri	= 293,
    SUBC8rm	= 294,
    SUBC8rn	= 295,
    SUBC8rp	= 296,
    SUBC8rr	= 297,
    SWPB16r	= 298,
    Select16	= 299,
    Select8	= 300,
    Shl16	= 301,
    Shl8	= 302,
    Sra16	= 303,
    Sra8	= 304,
    Srl16	= 305,
    Srl8	= 306,
    XOR16mc	= 307,
    XOR16mi	= 308,
    XOR16mm	= 309,
    XOR16mn	= 310,
    XOR16mp	= 311,
    XOR16mr	= 312,
    XOR16rc	= 313,
    XOR16ri	= 314,
    XOR16rm	= 315,
    XOR16rn	= 316,
    XOR16rp	= 317,
    XOR16rr	= 318,
    XOR8mc	= 319,
    XOR8mi	= 320,
    XOR8mm	= 321,
    XOR8mn	= 322,
    XOR8mp	= 323,
    XOR8mr	= 324,
    XOR8rc	= 325,
    XOR8ri	= 326,
    XOR8rm	= 327,
    XOR8rn	= 328,
    XOR8rp	= 329,
    XOR8rr	= 330,
    ZEXT16r	= 331,
    INSTRUCTION_LIST_END = 332
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
static const MCOperandInfo OperandInfo35[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo44[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo46[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo49[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo50[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };

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
  { 155,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #155 = BIT16mr
  { 156,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #156 = BIT16rc
  { 157,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #157 = BIT16ri
  { 158,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #158 = BIT16rm
  { 159,	2,	0,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #159 = BIT16rr
  { 160,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #160 = BIT8mc
  { 161,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #161 = BIT8mi
  { 162,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #162 = BIT8mm
  { 163,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #163 = BIT8mr
  { 164,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #164 = BIT8rc
  { 165,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #165 = BIT8ri
  { 166,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #166 = BIT8rm
  { 167,	2,	0,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #167 = BIT8rr
  { 168,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #168 = Bi
  { 169,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #169 = Bm
  { 170,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #170 = Br
  { 171,	1,	0,	4,	0,	0|(1ULL<<MCID::Call), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo3, -1 ,nullptr },  // Inst #171 = CALLi
  { 172,	2,	0,	4,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo40, -1 ,nullptr },  // Inst #172 = CALLm
  { 173,	1,	0,	2,	0,	0|(1ULL<<MCID::Call), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo41, -1 ,nullptr },  // Inst #173 = CALLr
  { 174,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #174 = CMP16mc
  { 175,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #175 = CMP16mi
  { 176,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #176 = CMP16mr
  { 177,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #177 = CMP16rc
  { 178,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #178 = CMP16ri
  { 179,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #179 = CMP16rm
  { 180,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #180 = CMP16rr
  { 181,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #181 = CMP8mc
  { 182,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #182 = CMP8mi
  { 183,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #183 = CMP8mr
  { 184,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #184 = CMP8rc
  { 185,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #185 = CMP8ri
  { 186,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #186 = CMP8rm
  { 187,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #187 = CMP8rr
  { 188,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #188 = DADD16mc
  { 189,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #189 = DADD16mi
  { 190,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #190 = DADD16mm
  { 191,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #191 = DADD16mn
  { 192,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #192 = DADD16mp
  { 193,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #193 = DADD16mr
  { 194,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #194 = DADD16rc
  { 195,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #195 = DADD16ri
  { 196,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #196 = DADD16rm
  { 197,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #197 = DADD16rn
  { 198,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #198 = DADD16rp
  { 199,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #199 = DADD16rr
  { 200,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #200 = DADD8mc
  { 201,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #201 = DADD8mi
  { 202,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #202 = DADD8mm
  { 203,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #203 = DADD8mn
  { 204,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #204 = DADD8mp
  { 205,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #205 = DADD8mr
  { 206,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #206 = DADD8rc
  { 207,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #207 = DADD8ri
  { 208,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #208 = DADD8rm
  { 209,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #209 = DADD8rn
  { 210,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #210 = DADD8rp
  { 211,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #211 = DADD8rr
  { 212,	2,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList1, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #212 = JCC
  { 213,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #213 = JMP
  { 214,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #214 = MOV16mc
  { 215,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #215 = MOV16mi
  { 216,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #216 = MOV16mm
  { 217,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #217 = MOV16mr
  { 218,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #218 = MOV16rc
  { 219,	2,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #219 = MOV16ri
  { 220,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #220 = MOV16rm
  { 221,	2,	1,	2,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #221 = MOV16rn
  { 222,	3,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #222 = MOV16rp
  { 223,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #223 = MOV16rr
  { 224,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #224 = MOV8mc
  { 225,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #225 = MOV8mi
  { 226,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #226 = MOV8mm
  { 227,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #227 = MOV8mr
  { 228,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #228 = MOV8rc
  { 229,	2,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #229 = MOV8ri
  { 230,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #230 = MOV8rm
  { 231,	2,	1,	2,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #231 = MOV8rn
  { 232,	3,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #232 = MOV8rp
  { 233,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #233 = MOV8rr
  { 234,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #234 = MOVZX16rm8
  { 235,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #235 = MOVZX16rr8
  { 236,	1,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo41, -1 ,nullptr },  // Inst #236 = POP16r
  { 237,	1,	0,	2,	0,	0, 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo2, -1 ,nullptr },  // Inst #237 = PUSH16c
  { 238,	1,	0,	4,	0,	0, 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo3, -1 ,nullptr },  // Inst #238 = PUSH16i
  { 239,	1,	0,	2,	0,	0, 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo41, -1 ,nullptr },  // Inst #239 = PUSH16r
  { 240,	1,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo47, -1 ,nullptr },  // Inst #240 = PUSH8r
  { 241,	0,	0,	2,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #241 = RET
  { 242,	0,	0,	2,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #242 = RETI
  { 243,	2,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo48, -1 ,nullptr },  // Inst #243 = RRA16r
  { 244,	2,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo49, -1 ,nullptr },  // Inst #244 = RRA8r
  { 245,	2,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo48, -1 ,nullptr },  // Inst #245 = RRC16r
  { 246,	2,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo49, -1 ,nullptr },  // Inst #246 = RRC8r
  { 247,	2,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #247 = Rrcl16
  { 248,	2,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #248 = Rrcl8
  { 249,	2,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo48, -1 ,nullptr },  // Inst #249 = SEXT16r
  { 250,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #250 = SUB16mc
  { 251,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #251 = SUB16mi
  { 252,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #252 = SUB16mm
  { 253,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #253 = SUB16mn
  { 254,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #254 = SUB16mp
  { 255,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #255 = SUB16mr
  { 256,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #256 = SUB16rc
  { 257,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #257 = SUB16ri
  { 258,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #258 = SUB16rm
  { 259,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #259 = SUB16rn
  { 260,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #260 = SUB16rp
  { 261,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #261 = SUB16rr
  { 262,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #262 = SUB8mc
  { 263,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #263 = SUB8mi
  { 264,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #264 = SUB8mm
  { 265,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #265 = SUB8mn
  { 266,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #266 = SUB8mp
  { 267,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #267 = SUB8mr
  { 268,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #268 = SUB8rc
  { 269,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #269 = SUB8ri
  { 270,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #270 = SUB8rm
  { 271,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #271 = SUB8rn
  { 272,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #272 = SUB8rp
  { 273,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #273 = SUB8rr
  { 274,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #274 = SUBC16mc
  { 275,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #275 = SUBC16mi
  { 276,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #276 = SUBC16mm
  { 277,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #277 = SUBC16mn
  { 278,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #278 = SUBC16mp
  { 279,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #279 = SUBC16mr
  { 280,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #280 = SUBC16rc
  { 281,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #281 = SUBC16ri
  { 282,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #282 = SUBC16rm
  { 283,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #283 = SUBC16rn
  { 284,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #284 = SUBC16rp
  { 285,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #285 = SUBC16rr
  { 286,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #286 = SUBC8mc
  { 287,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #287 = SUBC8mi
  { 288,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #288 = SUBC8mm
  { 289,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #289 = SUBC8mn
  { 290,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #290 = SUBC8mp
  { 291,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #291 = SUBC8mr
  { 292,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #292 = SUBC8rc
  { 293,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #293 = SUBC8ri
  { 294,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #294 = SUBC8rm
  { 295,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #295 = SUBC8rn
  { 296,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #296 = SUBC8rp
  { 297,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #297 = SUBC8rr
  { 298,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #298 = SWPB16r
  { 299,	4,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, ImplicitList1, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #299 = Select16
  { 300,	4,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, ImplicitList1, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #300 = Select8
  { 301,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo52, -1 ,nullptr },  // Inst #301 = Shl16
  { 302,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo53, -1 ,nullptr },  // Inst #302 = Shl8
  { 303,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo52, -1 ,nullptr },  // Inst #303 = Sra16
  { 304,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo53, -1 ,nullptr },  // Inst #304 = Sra8
  { 305,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo52, -1 ,nullptr },  // Inst #305 = Srl16
  { 306,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo53, -1 ,nullptr },  // Inst #306 = Srl8
  { 307,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #307 = XOR16mc
  { 308,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #308 = XOR16mi
  { 309,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #309 = XOR16mm
  { 310,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #310 = XOR16mn
  { 311,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #311 = XOR16mp
  { 312,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #312 = XOR16mr
  { 313,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #313 = XOR16rc
  { 314,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #314 = XOR16ri
  { 315,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #315 = XOR16rm
  { 316,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #316 = XOR16rn
  { 317,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #317 = XOR16rp
  { 318,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #318 = XOR16rr
  { 319,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #319 = XOR8mc
  { 320,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #320 = XOR8mi
  { 321,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #321 = XOR8mm
  { 322,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #322 = XOR8mn
  { 323,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #323 = XOR8mp
  { 324,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #324 = XOR8mr
  { 325,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #325 = XOR8rc
  { 326,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #326 = XOR8ri
  { 327,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #327 = XOR8rm
  { 328,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #328 = XOR8rn
  { 329,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #329 = XOR8rp
  { 330,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #330 = XOR8rr
  { 331,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #331 = ZEXT16r
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
  /* 1183 */ 'B', 'm', 0,
  /* 1186 */ 'C', 'A', 'L', 'L', 'm', 0,
  /* 1192 */ 'S', 'U', 'B', '1', '6', 'm', 'm', 0,
  /* 1200 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'm', 0,
  /* 1209 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'm', 0,
  /* 1218 */ 'B', 'I', 'C', '1', '6', 'm', 'm', 0,
  /* 1226 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'm', 0,
  /* 1235 */ 'A', 'N', 'D', '1', '6', 'm', 'm', 0,
  /* 1243 */ 'X', 'O', 'R', '1', '6', 'm', 'm', 0,
  /* 1251 */ 'B', 'I', 'S', '1', '6', 'm', 'm', 0,
  /* 1259 */ 'B', 'I', 'T', '1', '6', 'm', 'm', 0,
  /* 1267 */ 'M', 'O', 'V', '1', '6', 'm', 'm', 0,
  /* 1275 */ 'S', 'U', 'B', '8', 'm', 'm', 0,
  /* 1282 */ 'S', 'U', 'B', 'C', '8', 'm', 'm', 0,
  /* 1290 */ 'A', 'D', 'D', 'C', '8', 'm', 'm', 0,
  /* 1298 */ 'B', 'I', 'C', '8', 'm', 'm', 0,
  /* 1305 */ 'D', 'A', 'D', 'D', '8', 'm', 'm', 0,
  /* 1313 */ 'A', 'N', 'D', '8', 'm', 'm', 0,
  /* 1320 */ 'X', 'O', 'R', '8', 'm', 'm', 0,
  /* 1327 */ 'B', 'I', 'S', '8', 'm', 'm', 0,
  /* 1334 */ 'B', 'I', 'T', '8', 'm', 'm', 0,
  /* 1341 */ 'M', 'O', 'V', '8', 'm', 'm', 0,
  /* 1348 */ 'S', 'U', 'B', '1', '6', 'r', 'm', 0,
  /* 1356 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'm', 0,
  /* 1365 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'm', 0,
  /* 1374 */ 'B', 'I', 'C', '1', '6', 'r', 'm', 0,
  /* 1382 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'm', 0,
  /* 1391 */ 'A', 'N', 'D', '1', '6', 'r', 'm', 0,
  /* 1399 */ 'C', 'M', 'P', '1', '6', 'r', 'm', 0,
  /* 1407 */ 'X', 'O', 'R', '1', '6', 'r', 'm', 0,
  /* 1415 */ 'B', 'I', 'S', '1', '6', 'r', 'm', 0,
  /* 1423 */ 'B', 'I', 'T', '1', '6', 'r', 'm', 0,
  /* 1431 */ 'M', 'O', 'V', '1', '6', 'r', 'm', 0,
  /* 1439 */ 'S', 'U', 'B', '8', 'r', 'm', 0,
  /* 1446 */ 'S', 'U', 'B', 'C', '8', 'r', 'm', 0,
  /* 1454 */ 'A', 'D', 'D', 'C', '8', 'r', 'm', 0,
  /* 1462 */ 'B', 'I', 'C', '8', 'r', 'm', 0,
  /* 1469 */ 'D', 'A', 'D', 'D', '8', 'r', 'm', 0,
  /* 1477 */ 'A', 'N', 'D', '8', 'r', 'm', 0,
  /* 1484 */ 'C', 'M', 'P', '8', 'r', 'm', 0,
  /* 1491 */ 'X', 'O', 'R', '8', 'r', 'm', 0,
  /* 1498 */ 'B', 'I', 'S', '8', 'r', 'm', 0,
  /* 1505 */ 'B', 'I', 'T', '8', 'r', 'm', 0,
  /* 1512 */ 'M', 'O', 'V', '8', 'r', 'm', 0,
  /* 1519 */ 'S', 'U', 'B', '1', '6', 'm', 'n', 0,
  /* 1527 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'n', 0,
  /* 1536 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'n', 0,
  /* 1545 */ 'B', 'I', 'C', '1', '6', 'm', 'n', 0,
  /* 1553 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'n', 0,
  /* 1562 */ 'A', 'N', 'D', '1', '6', 'm', 'n', 0,
  /* 1570 */ 'X', 'O', 'R', '1', '6', 'm', 'n', 0,
  /* 1578 */ 'B', 'I', 'S', '1', '6', 'm', 'n', 0,
  /* 1586 */ 'S', 'U', 'B', '8', 'm', 'n', 0,
  /* 1593 */ 'S', 'U', 'B', 'C', '8', 'm', 'n', 0,
  /* 1601 */ 'A', 'D', 'D', 'C', '8', 'm', 'n', 0,
  /* 1609 */ 'B', 'I', 'C', '8', 'm', 'n', 0,
  /* 1616 */ 'D', 'A', 'D', 'D', '8', 'm', 'n', 0,
  /* 1624 */ 'A', 'N', 'D', '8', 'm', 'n', 0,
  /* 1631 */ 'X', 'O', 'R', '8', 'm', 'n', 0,
  /* 1638 */ 'B', 'I', 'S', '8', 'm', 'n', 0,
  /* 1645 */ 'S', 'U', 'B', '1', '6', 'r', 'n', 0,
  /* 1653 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'n', 0,
  /* 1662 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'n', 0,
  /* 1671 */ 'B', 'I', 'C', '1', '6', 'r', 'n', 0,
  /* 1679 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'n', 0,
  /* 1688 */ 'A', 'N', 'D', '1', '6', 'r', 'n', 0,
  /* 1696 */ 'X', 'O', 'R', '1', '6', 'r', 'n', 0,
  /* 1704 */ 'B', 'I', 'S', '1', '6', 'r', 'n', 0,
  /* 1712 */ 'M', 'O', 'V', '1', '6', 'r', 'n', 0,
  /* 1720 */ 'S', 'U', 'B', '8', 'r', 'n', 0,
  /* 1727 */ 'S', 'U', 'B', 'C', '8', 'r', 'n', 0,
  /* 1735 */ 'A', 'D', 'D', 'C', '8', 'r', 'n', 0,
  /* 1743 */ 'B', 'I', 'C', '8', 'r', 'n', 0,
  /* 1750 */ 'D', 'A', 'D', 'D', '8', 'r', 'n', 0,
  /* 1758 */ 'A', 'N', 'D', '8', 'r', 'n', 0,
  /* 1765 */ 'X', 'O', 'R', '8', 'r', 'n', 0,
  /* 1772 */ 'B', 'I', 'S', '8', 'r', 'n', 0,
  /* 1779 */ 'M', 'O', 'V', '8', 'r', 'n', 0,
  /* 1786 */ 'S', 'U', 'B', '1', '6', 'm', 'p', 0,
  /* 1794 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'p', 0,
  /* 1803 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'p', 0,
  /* 1812 */ 'B', 'I', 'C', '1', '6', 'm', 'p', 0,
  /* 1820 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'p', 0,
  /* 1829 */ 'A', 'N', 'D', '1', '6', 'm', 'p', 0,
  /* 1837 */ 'X', 'O', 'R', '1', '6', 'm', 'p', 0,
  /* 1845 */ 'B', 'I', 'S', '1', '6', 'm', 'p', 0,
  /* 1853 */ 'S', 'U', 'B', '8', 'm', 'p', 0,
  /* 1860 */ 'S', 'U', 'B', 'C', '8', 'm', 'p', 0,
  /* 1868 */ 'A', 'D', 'D', 'C', '8', 'm', 'p', 0,
  /* 1876 */ 'B', 'I', 'C', '8', 'm', 'p', 0,
  /* 1883 */ 'D', 'A', 'D', 'D', '8', 'm', 'p', 0,
  /* 1891 */ 'A', 'N', 'D', '8', 'm', 'p', 0,
  /* 1898 */ 'X', 'O', 'R', '8', 'm', 'p', 0,
  /* 1905 */ 'B', 'I', 'S', '8', 'm', 'p', 0,
  /* 1912 */ 'S', 'U', 'B', '1', '6', 'r', 'p', 0,
  /* 1920 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'p', 0,
  /* 1929 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'p', 0,
  /* 1938 */ 'B', 'I', 'C', '1', '6', 'r', 'p', 0,
  /* 1946 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'p', 0,
  /* 1955 */ 'A', 'N', 'D', '1', '6', 'r', 'p', 0,
  /* 1963 */ 'X', 'O', 'R', '1', '6', 'r', 'p', 0,
  /* 1971 */ 'B', 'I', 'S', '1', '6', 'r', 'p', 0,
  /* 1979 */ 'M', 'O', 'V', '1', '6', 'r', 'p', 0,
  /* 1987 */ 'S', 'U', 'B', '8', 'r', 'p', 0,
  /* 1994 */ 'S', 'U', 'B', 'C', '8', 'r', 'p', 0,
  /* 2002 */ 'A', 'D', 'D', 'C', '8', 'r', 'p', 0,
  /* 2010 */ 'B', 'I', 'C', '8', 'r', 'p', 0,
  /* 2017 */ 'D', 'A', 'D', 'D', '8', 'r', 'p', 0,
  /* 2025 */ 'A', 'N', 'D', '8', 'r', 'p', 0,
  /* 2032 */ 'X', 'O', 'R', '8', 'r', 'p', 0,
  /* 2039 */ 'B', 'I', 'S', '8', 'r', 'p', 0,
  /* 2046 */ 'M', 'O', 'V', '8', 'r', 'p', 0,
  /* 2053 */ 'R', 'R', 'A', '1', '6', 'r', 0,
  /* 2060 */ 'S', 'W', 'P', 'B', '1', '6', 'r', 0,
  /* 2068 */ 'R', 'R', 'C', '1', '6', 'r', 0,
  /* 2075 */ 'P', 'U', 'S', 'H', '1', '6', 'r', 0,
  /* 2083 */ 'P', 'O', 'P', '1', '6', 'r', 0,
  /* 2090 */ 'S', 'E', 'X', 'T', '1', '6', 'r', 0,
  /* 2098 */ 'Z', 'E', 'X', 'T', '1', '6', 'r', 0,
  /* 2106 */ 'R', 'R', 'A', '8', 'r', 0,
  /* 2112 */ 'R', 'R', 'C', '8', 'r', 0,
  /* 2118 */ 'P', 'U', 'S', 'H', '8', 'r', 0,
  /* 2125 */ 'B', 'r', 0,
  /* 2128 */ 'C', 'A', 'L', 'L', 'r', 0,
  /* 2134 */ 'S', 'U', 'B', '1', '6', 'm', 'r', 0,
  /* 2142 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'r', 0,
  /* 2151 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'r', 0,
  /* 2160 */ 'B', 'I', 'C', '1', '6', 'm', 'r', 0,
  /* 2168 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'r', 0,
  /* 2177 */ 'A', 'N', 'D', '1', '6', 'm', 'r', 0,
  /* 2185 */ 'C', 'M', 'P', '1', '6', 'm', 'r', 0,
  /* 2193 */ 'X', 'O', 'R', '1', '6', 'm', 'r', 0,
  /* 2201 */ 'B', 'I', 'S', '1', '6', 'm', 'r', 0,
  /* 2209 */ 'B', 'I', 'T', '1', '6', 'm', 'r', 0,
  /* 2217 */ 'M', 'O', 'V', '1', '6', 'm', 'r', 0,
  /* 2225 */ 'S', 'U', 'B', '8', 'm', 'r', 0,
  /* 2232 */ 'S', 'U', 'B', 'C', '8', 'm', 'r', 0,
  /* 2240 */ 'A', 'D', 'D', 'C', '8', 'm', 'r', 0,
  /* 2248 */ 'B', 'I', 'C', '8', 'm', 'r', 0,
  /* 2255 */ 'D', 'A', 'D', 'D', '8', 'm', 'r', 0,
  /* 2263 */ 'A', 'N', 'D', '8', 'm', 'r', 0,
  /* 2270 */ 'C', 'M', 'P', '8', 'm', 'r', 0,
  /* 2277 */ 'X', 'O', 'R', '8', 'm', 'r', 0,
  /* 2284 */ 'B', 'I', 'S', '8', 'm', 'r', 0,
  /* 2291 */ 'B', 'I', 'T', '8', 'm', 'r', 0,
  /* 2298 */ 'M', 'O', 'V', '8', 'm', 'r', 0,
  /* 2305 */ 'S', 'U', 'B', '1', '6', 'r', 'r', 0,
  /* 2313 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'r', 0,
  /* 2322 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'r', 0,
  /* 2331 */ 'B', 'I', 'C', '1', '6', 'r', 'r', 0,
  /* 2339 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'r', 0,
  /* 2348 */ 'A', 'N', 'D', '1', '6', 'r', 'r', 0,
  /* 2356 */ 'C', 'M', 'P', '1', '6', 'r', 'r', 0,
  /* 2364 */ 'X', 'O', 'R', '1', '6', 'r', 'r', 0,
  /* 2372 */ 'B', 'I', 'S', '1', '6', 'r', 'r', 0,
  /* 2380 */ 'B', 'I', 'T', '1', '6', 'r', 'r', 0,
  /* 2388 */ 'M', 'O', 'V', '1', '6', 'r', 'r', 0,
  /* 2396 */ 'S', 'U', 'B', '8', 'r', 'r', 0,
  /* 2403 */ 'S', 'U', 'B', 'C', '8', 'r', 'r', 0,
  /* 2411 */ 'A', 'D', 'D', 'C', '8', 'r', 'r', 0,
  /* 2419 */ 'B', 'I', 'C', '8', 'r', 'r', 0,
  /* 2426 */ 'D', 'A', 'D', 'D', '8', 'r', 'r', 0,
  /* 2434 */ 'A', 'N', 'D', '8', 'r', 'r', 0,
  /* 2441 */ 'C', 'M', 'P', '8', 'r', 'r', 0,
  /* 2448 */ 'X', 'O', 'R', '8', 'r', 'r', 0,
  /* 2455 */ 'B', 'I', 'S', '8', 'r', 'r', 0,
  /* 2462 */ 'B', 'I', 'T', '8', 'r', 'r', 0,
  /* 2469 */ 'M', 'O', 'V', '8', 'r', 'r', 0,
};

extern const unsigned MSP430InstrNameIndices[] = {
    224U, 256U, 266U, 242U, 233U, 251U, 181U, 196U, 
    168U, 210U, 392U, 158U, 125U, 460U, 138U, 445U, 
    95U, 299U, 434U, 108U, 423U, 145U, 312U, 329U, 
    362U, 409U, 89U, 387U, 357U, 508U, 876U, 1227U, 
    1554U, 1821U, 2169U, 679U, 1047U, 1383U, 1680U, 1947U, 
    2340U, 595U, 963U, 1306U, 1617U, 1884U, 2256U, 766U, 
    1134U, 1470U, 1751U, 2018U, 2427U, 490U, 858U, 1209U, 
    1536U, 1803U, 2151U, 661U, 1029U, 1365U, 1662U, 1929U, 
    2322U, 579U, 947U, 1290U, 1601U, 1868U, 2240U, 750U, 
    1118U, 1454U, 1735U, 2002U, 2411U, 815U, 282U, 342U, 
    516U, 884U, 1235U, 1562U, 1829U, 2177U, 687U, 1055U, 
    1391U, 1688U, 1955U, 2348U, 602U, 970U, 1313U, 1624U, 
    1891U, 2263U, 773U, 1141U, 1477U, 1758U, 2025U, 2434U, 
    499U, 867U, 1218U, 1545U, 1812U, 2160U, 670U, 1038U, 
    1374U, 1671U, 1938U, 2331U, 587U, 955U, 1298U, 1609U, 
    1876U, 2248U, 758U, 1126U, 1462U, 1743U, 2010U, 2419U, 
    540U, 908U, 1251U, 1578U, 1845U, 2201U, 711U, 1079U, 
    1415U, 1704U, 1971U, 2372U, 623U, 991U, 1327U, 1638U, 
    1905U, 2284U, 794U, 1162U, 1498U, 1772U, 2039U, 2455U, 
    548U, 916U, 1259U, 2209U, 719U, 1087U, 1423U, 2380U, 
    630U, 998U, 1334U, 2291U, 801U, 1169U, 1505U, 2462U, 
    832U, 1183U, 2125U, 835U, 1186U, 2128U, 524U, 892U, 
    2185U, 695U, 1063U, 1399U, 2356U, 609U, 977U, 2270U, 
    780U, 1148U, 1484U, 2441U, 507U, 875U, 1226U, 1553U, 
    1820U, 2168U, 678U, 1046U, 1382U, 1679U, 1946U, 2339U, 
    594U, 962U, 1305U, 1616U, 1883U, 2255U, 765U, 1133U, 
    1469U, 1750U, 2017U, 2426U, 85U, 308U, 556U, 924U, 
    1267U, 2217U, 727U, 1095U, 1431U, 1712U, 1979U, 2388U, 
    637U, 1005U, 1341U, 2298U, 808U, 1176U, 1512U, 1779U, 
    2046U, 2469U, 55U, 66U, 2083U, 465U, 824U, 2075U, 
    2118U, 419U, 228U, 2053U, 2106U, 2068U, 2112U, 6U, 
    39U, 2090U, 473U, 841U, 1192U, 1519U, 1786U, 2134U, 
    644U, 1012U, 1348U, 1645U, 1912U, 2305U, 564U, 932U, 
    1275U, 1586U, 1853U, 2225U, 735U, 1103U, 1439U, 1720U, 
    1987U, 2396U, 481U, 849U, 1200U, 1527U, 1794U, 2142U, 
    652U, 1020U, 1356U, 1653U, 1920U, 2313U, 571U, 939U, 
    1282U, 1593U, 1860U, 2232U, 742U, 1110U, 1446U, 1727U, 
    1994U, 2403U, 2060U, 25U, 77U, 13U, 45U, 0U, 
    34U, 19U, 50U, 532U, 900U, 1243U, 1570U, 1837U, 
    2193U, 703U, 1071U, 1407U, 1696U, 1963U, 2364U, 616U, 
    984U, 1320U, 1631U, 1898U, 2277U, 787U, 1155U, 1491U, 
    1765U, 2032U, 2448U, 2098U, 
};

static inline void InitMSP430MCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(MSP430Insts, MSP430InstrNameIndices, MSP430InstrNameData, 332);
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
  InitMCInstrInfo(MSP430Insts, MSP430InstrNameIndices, MSP430InstrNameData, 332);
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
} // end namespace llvm
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
} // end namespace llvm
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
} // end namespace llvm
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM

