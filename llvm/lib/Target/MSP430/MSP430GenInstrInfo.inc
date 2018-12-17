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
    BIC16mm	= 104,
    BIC16mr	= 105,
    BIC16rm	= 106,
    BIC16rr	= 107,
    BIC8mm	= 108,
    BIC8mr	= 109,
    BIC8rm	= 110,
    BIC8rr	= 111,
    BIS16mc	= 112,
    BIS16mi	= 113,
    BIS16mm	= 114,
    BIS16mn	= 115,
    BIS16mp	= 116,
    BIS16mr	= 117,
    BIS16rc	= 118,
    BIS16ri	= 119,
    BIS16rm	= 120,
    BIS16rn	= 121,
    BIS16rp	= 122,
    BIS16rr	= 123,
    BIS8mc	= 124,
    BIS8mi	= 125,
    BIS8mm	= 126,
    BIS8mn	= 127,
    BIS8mp	= 128,
    BIS8mr	= 129,
    BIS8rc	= 130,
    BIS8ri	= 131,
    BIS8rm	= 132,
    BIS8rn	= 133,
    BIS8rp	= 134,
    BIS8rr	= 135,
    BIT16mc	= 136,
    BIT16mi	= 137,
    BIT16mm	= 138,
    BIT16mr	= 139,
    BIT16rc	= 140,
    BIT16ri	= 141,
    BIT16rm	= 142,
    BIT16rr	= 143,
    BIT8mc	= 144,
    BIT8mi	= 145,
    BIT8mm	= 146,
    BIT8mr	= 147,
    BIT8rc	= 148,
    BIT8ri	= 149,
    BIT8rm	= 150,
    BIT8rr	= 151,
    Bi	= 152,
    Bm	= 153,
    Br	= 154,
    CALLi	= 155,
    CALLm	= 156,
    CALLr	= 157,
    CMP16mc	= 158,
    CMP16mi	= 159,
    CMP16mr	= 160,
    CMP16rc	= 161,
    CMP16ri	= 162,
    CMP16rm	= 163,
    CMP16rr	= 164,
    CMP8mc	= 165,
    CMP8mi	= 166,
    CMP8mr	= 167,
    CMP8rc	= 168,
    CMP8ri	= 169,
    CMP8rm	= 170,
    CMP8rr	= 171,
    DADD16mc	= 172,
    DADD16mi	= 173,
    DADD16mm	= 174,
    DADD16mn	= 175,
    DADD16mp	= 176,
    DADD16mr	= 177,
    DADD16rc	= 178,
    DADD16ri	= 179,
    DADD16rm	= 180,
    DADD16rn	= 181,
    DADD16rp	= 182,
    DADD16rr	= 183,
    DADD8mc	= 184,
    DADD8mi	= 185,
    DADD8mm	= 186,
    DADD8mn	= 187,
    DADD8mp	= 188,
    DADD8mr	= 189,
    DADD8rc	= 190,
    DADD8ri	= 191,
    DADD8rm	= 192,
    DADD8rn	= 193,
    DADD8rp	= 194,
    DADD8rr	= 195,
    JCC	= 196,
    JMP	= 197,
    MOV16mc	= 198,
    MOV16mi	= 199,
    MOV16mm	= 200,
    MOV16mr	= 201,
    MOV16rc	= 202,
    MOV16ri	= 203,
    MOV16rm	= 204,
    MOV16rn	= 205,
    MOV16rp	= 206,
    MOV16rr	= 207,
    MOV8mc	= 208,
    MOV8mi	= 209,
    MOV8mm	= 210,
    MOV8mr	= 211,
    MOV8rc	= 212,
    MOV8ri	= 213,
    MOV8rm	= 214,
    MOV8rn	= 215,
    MOV8rp	= 216,
    MOV8rr	= 217,
    MOVZX16rm8	= 218,
    MOVZX16rr8	= 219,
    POP16r	= 220,
    PUSH16c	= 221,
    PUSH16i	= 222,
    PUSH16r	= 223,
    PUSH8r	= 224,
    RET	= 225,
    RETI	= 226,
    RRA16r	= 227,
    RRA8r	= 228,
    RRC16r	= 229,
    RRC8r	= 230,
    Rrcl16	= 231,
    Rrcl8	= 232,
    SEXT16r	= 233,
    SUB16mc	= 234,
    SUB16mi	= 235,
    SUB16mm	= 236,
    SUB16mn	= 237,
    SUB16mp	= 238,
    SUB16mr	= 239,
    SUB16rc	= 240,
    SUB16ri	= 241,
    SUB16rm	= 242,
    SUB16rn	= 243,
    SUB16rp	= 244,
    SUB16rr	= 245,
    SUB8mc	= 246,
    SUB8mi	= 247,
    SUB8mm	= 248,
    SUB8mn	= 249,
    SUB8mp	= 250,
    SUB8mr	= 251,
    SUB8rc	= 252,
    SUB8ri	= 253,
    SUB8rm	= 254,
    SUB8rn	= 255,
    SUB8rp	= 256,
    SUB8rr	= 257,
    SUBC16mc	= 258,
    SUBC16mi	= 259,
    SUBC16mm	= 260,
    SUBC16mn	= 261,
    SUBC16mp	= 262,
    SUBC16mr	= 263,
    SUBC16rc	= 264,
    SUBC16ri	= 265,
    SUBC16rm	= 266,
    SUBC16rn	= 267,
    SUBC16rp	= 268,
    SUBC16rr	= 269,
    SUBC8mc	= 270,
    SUBC8mi	= 271,
    SUBC8mm	= 272,
    SUBC8mn	= 273,
    SUBC8mp	= 274,
    SUBC8mr	= 275,
    SUBC8rc	= 276,
    SUBC8ri	= 277,
    SUBC8rm	= 278,
    SUBC8rn	= 279,
    SUBC8rp	= 280,
    SUBC8rr	= 281,
    SWPB16r	= 282,
    Select16	= 283,
    Select8	= 284,
    Shl16	= 285,
    Shl8	= 286,
    Sra16	= 287,
    Sra8	= 288,
    Srl16	= 289,
    Srl8	= 290,
    XOR16mc	= 291,
    XOR16mi	= 292,
    XOR16mm	= 293,
    XOR16mn	= 294,
    XOR16mp	= 295,
    XOR16mr	= 296,
    XOR16rc	= 297,
    XOR16ri	= 298,
    XOR16rm	= 299,
    XOR16rn	= 300,
    XOR16rp	= 301,
    XOR16rr	= 302,
    XOR8mc	= 303,
    XOR8mi	= 304,
    XOR8mm	= 305,
    XOR8mn	= 306,
    XOR8mp	= 307,
    XOR8mr	= 308,
    XOR8rc	= 309,
    XOR8ri	= 310,
    XOR8rm	= 311,
    XOR8rn	= 312,
    XOR8rp	= 313,
    XOR8rr	= 314,
    ZEXT16r	= 315,
    INSTRUCTION_LIST_END = 316
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
static const MCOperandInfo OperandInfo32[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo48[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo50[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo53[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo54[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo55[] = { { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo56[] = { { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };

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
  { 104,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #104 = BIC16mm
  { 105,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #105 = BIC16mr
  { 106,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #106 = BIC16rm
  { 107,	3,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #107 = BIC16rr
  { 108,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #108 = BIC8mm
  { 109,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #109 = BIC8mr
  { 110,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #110 = BIC8rm
  { 111,	3,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #111 = BIC8rr
  { 112,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #112 = BIS16mc
  { 113,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #113 = BIS16mi
  { 114,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #114 = BIS16mm
  { 115,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #115 = BIS16mn
  { 116,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #116 = BIS16mp
  { 117,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #117 = BIS16mr
  { 118,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #118 = BIS16rc
  { 119,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #119 = BIS16ri
  { 120,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #120 = BIS16rm
  { 121,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #121 = BIS16rn
  { 122,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #122 = BIS16rp
  { 123,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #123 = BIS16rr
  { 124,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #124 = BIS8mc
  { 125,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #125 = BIS8mi
  { 126,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #126 = BIS8mm
  { 127,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #127 = BIS8mn
  { 128,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #128 = BIS8mp
  { 129,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #129 = BIS8mr
  { 130,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #130 = BIS8rc
  { 131,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #131 = BIS8ri
  { 132,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #132 = BIS8rm
  { 133,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #133 = BIS8rn
  { 134,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #134 = BIS8rp
  { 135,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #135 = BIS8rr
  { 136,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #136 = BIT16mc
  { 137,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #137 = BIT16mi
  { 138,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #138 = BIT16mm
  { 139,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #139 = BIT16mr
  { 140,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #140 = BIT16rc
  { 141,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #141 = BIT16ri
  { 142,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #142 = BIT16rm
  { 143,	2,	0,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #143 = BIT16rr
  { 144,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #144 = BIT8mc
  { 145,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #145 = BIT8mi
  { 146,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #146 = BIT8mm
  { 147,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #147 = BIT8mr
  { 148,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #148 = BIT8rc
  { 149,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo41, -1 ,nullptr },  // Inst #149 = BIT8ri
  { 150,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo42, -1 ,nullptr },  // Inst #150 = BIT8rm
  { 151,	2,	0,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo43, -1 ,nullptr },  // Inst #151 = BIT8rr
  { 152,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #152 = Bi
  { 153,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #153 = Bm
  { 154,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #154 = Br
  { 155,	1,	0,	4,	0,	0|(1ULL<<MCID::Call), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo3, -1 ,nullptr },  // Inst #155 = CALLi
  { 156,	2,	0,	4,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo44, -1 ,nullptr },  // Inst #156 = CALLm
  { 157,	1,	0,	2,	0,	0|(1ULL<<MCID::Call), 0x0ULL, ImplicitList2, ImplicitList4, OperandInfo45, -1 ,nullptr },  // Inst #157 = CALLr
  { 158,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #158 = CMP16mc
  { 159,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #159 = CMP16mi
  { 160,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #160 = CMP16mr
  { 161,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #161 = CMP16rc
  { 162,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #162 = CMP16ri
  { 163,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #163 = CMP16rm
  { 164,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #164 = CMP16rr
  { 165,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #165 = CMP8mc
  { 166,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #166 = CMP8mi
  { 167,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #167 = CMP8mr
  { 168,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #168 = CMP8rc
  { 169,	2,	0,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo41, -1 ,nullptr },  // Inst #169 = CMP8ri
  { 170,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo42, -1 ,nullptr },  // Inst #170 = CMP8rm
  { 171,	2,	0,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo43, -1 ,nullptr },  // Inst #171 = CMP8rr
  { 172,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #172 = DADD16mc
  { 173,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #173 = DADD16mi
  { 174,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #174 = DADD16mm
  { 175,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #175 = DADD16mn
  { 176,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #176 = DADD16mp
  { 177,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #177 = DADD16mr
  { 178,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #178 = DADD16rc
  { 179,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #179 = DADD16ri
  { 180,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #180 = DADD16rm
  { 181,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #181 = DADD16rn
  { 182,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #182 = DADD16rp
  { 183,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #183 = DADD16rr
  { 184,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #184 = DADD8mc
  { 185,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #185 = DADD8mi
  { 186,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #186 = DADD8mm
  { 187,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #187 = DADD8mn
  { 188,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #188 = DADD8mp
  { 189,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #189 = DADD8mr
  { 190,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #190 = DADD8rc
  { 191,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #191 = DADD8ri
  { 192,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #192 = DADD8rm
  { 193,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #193 = DADD8rn
  { 194,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #194 = DADD8rp
  { 195,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #195 = DADD8rr
  { 196,	2,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList1, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #196 = JCC
  { 197,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #197 = JMP
  { 198,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #198 = MOV16mc
  { 199,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #199 = MOV16mi
  { 200,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #200 = MOV16mm
  { 201,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #201 = MOV16mr
  { 202,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #202 = MOV16rc
  { 203,	2,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #203 = MOV16ri
  { 204,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #204 = MOV16rm
  { 205,	2,	1,	2,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #205 = MOV16rn
  { 206,	3,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #206 = MOV16rp
  { 207,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #207 = MOV16rr
  { 208,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #208 = MOV8mc
  { 209,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #209 = MOV8mi
  { 210,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #210 = MOV8mm
  { 211,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #211 = MOV8mr
  { 212,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #212 = MOV8rc
  { 213,	2,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #213 = MOV8ri
  { 214,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #214 = MOV8rm
  { 215,	2,	1,	2,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #215 = MOV8rn
  { 216,	3,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #216 = MOV8rp
  { 217,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #217 = MOV8rr
  { 218,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #218 = MOVZX16rm8
  { 219,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #219 = MOVZX16rr8
  { 220,	1,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo45, -1 ,nullptr },  // Inst #220 = POP16r
  { 221,	1,	0,	2,	0,	0, 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo2, -1 ,nullptr },  // Inst #221 = PUSH16c
  { 222,	1,	0,	4,	0,	0, 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo3, -1 ,nullptr },  // Inst #222 = PUSH16i
  { 223,	1,	0,	2,	0,	0, 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo45, -1 ,nullptr },  // Inst #223 = PUSH16r
  { 224,	1,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList2, ImplicitList2, OperandInfo51, -1 ,nullptr },  // Inst #224 = PUSH8r
  { 225,	0,	0,	2,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #225 = RET
  { 226,	0,	0,	2,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #226 = RETI
  { 227,	2,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo52, -1 ,nullptr },  // Inst #227 = RRA16r
  { 228,	2,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo53, -1 ,nullptr },  // Inst #228 = RRA8r
  { 229,	2,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo52, -1 ,nullptr },  // Inst #229 = RRC16r
  { 230,	2,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo53, -1 ,nullptr },  // Inst #230 = RRC8r
  { 231,	2,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #231 = Rrcl16
  { 232,	2,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo43, -1 ,nullptr },  // Inst #232 = Rrcl8
  { 233,	2,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo52, -1 ,nullptr },  // Inst #233 = SEXT16r
  { 234,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #234 = SUB16mc
  { 235,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #235 = SUB16mi
  { 236,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #236 = SUB16mm
  { 237,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #237 = SUB16mn
  { 238,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #238 = SUB16mp
  { 239,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #239 = SUB16mr
  { 240,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #240 = SUB16rc
  { 241,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #241 = SUB16ri
  { 242,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #242 = SUB16rm
  { 243,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #243 = SUB16rn
  { 244,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #244 = SUB16rp
  { 245,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #245 = SUB16rr
  { 246,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #246 = SUB8mc
  { 247,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #247 = SUB8mi
  { 248,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #248 = SUB8mm
  { 249,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #249 = SUB8mn
  { 250,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #250 = SUB8mp
  { 251,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #251 = SUB8mr
  { 252,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #252 = SUB8rc
  { 253,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #253 = SUB8ri
  { 254,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #254 = SUB8rm
  { 255,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #255 = SUB8rn
  { 256,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #256 = SUB8rp
  { 257,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #257 = SUB8rr
  { 258,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #258 = SUBC16mc
  { 259,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #259 = SUBC16mi
  { 260,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #260 = SUBC16mm
  { 261,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #261 = SUBC16mn
  { 262,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #262 = SUBC16mp
  { 263,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #263 = SUBC16mr
  { 264,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #264 = SUBC16rc
  { 265,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #265 = SUBC16ri
  { 266,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #266 = SUBC16rm
  { 267,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #267 = SUBC16rn
  { 268,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #268 = SUBC16rp
  { 269,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #269 = SUBC16rr
  { 270,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #270 = SUBC8mc
  { 271,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #271 = SUBC8mi
  { 272,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #272 = SUBC8mm
  { 273,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #273 = SUBC8mn
  { 274,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #274 = SUBC8mp
  { 275,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #275 = SUBC8mr
  { 276,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #276 = SUBC8rc
  { 277,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #277 = SUBC8ri
  { 278,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #278 = SUBC8rm
  { 279,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #279 = SUBC8rn
  { 280,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #280 = SUBC8rp
  { 281,	3,	1,	2,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #281 = SUBC8rr
  { 282,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #282 = SWPB16r
  { 283,	4,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, ImplicitList1, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #283 = Select16
  { 284,	4,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, ImplicitList1, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #284 = Select8
  { 285,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo56, -1 ,nullptr },  // Inst #285 = Shl16
  { 286,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #286 = Shl8
  { 287,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo56, -1 ,nullptr },  // Inst #287 = Sra16
  { 288,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #288 = Sra8
  { 289,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo56, -1 ,nullptr },  // Inst #289 = Srl16
  { 290,	3,	1,	0,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #290 = Srl8
  { 291,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #291 = XOR16mc
  { 292,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #292 = XOR16mi
  { 293,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #293 = XOR16mm
  { 294,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #294 = XOR16mn
  { 295,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #295 = XOR16mp
  { 296,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #296 = XOR16mr
  { 297,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #297 = XOR16rc
  { 298,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #298 = XOR16ri
  { 299,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #299 = XOR16rm
  { 300,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #300 = XOR16rn
  { 301,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #301 = XOR16rp
  { 302,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #302 = XOR16rr
  { 303,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #303 = XOR8mc
  { 304,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #304 = XOR8mi
  { 305,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #305 = XOR8mm
  { 306,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #306 = XOR8mn
  { 307,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #307 = XOR8mp
  { 308,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #308 = XOR8mr
  { 309,	3,	1,	2,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #309 = XOR8rc
  { 310,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #310 = XOR8ri
  { 311,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #311 = XOR8rm
  { 312,	3,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #312 = XOR8rn
  { 313,	4,	2,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #313 = XOR8rp
  { 314,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #314 = XOR8rr
  { 315,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #315 = ZEXT16r
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
  /* 499 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'c', 0,
  /* 508 */ 'A', 'N', 'D', '1', '6', 'm', 'c', 0,
  /* 516 */ 'C', 'M', 'P', '1', '6', 'm', 'c', 0,
  /* 524 */ 'X', 'O', 'R', '1', '6', 'm', 'c', 0,
  /* 532 */ 'B', 'I', 'S', '1', '6', 'm', 'c', 0,
  /* 540 */ 'B', 'I', 'T', '1', '6', 'm', 'c', 0,
  /* 548 */ 'M', 'O', 'V', '1', '6', 'm', 'c', 0,
  /* 556 */ 'S', 'U', 'B', '8', 'm', 'c', 0,
  /* 563 */ 'S', 'U', 'B', 'C', '8', 'm', 'c', 0,
  /* 571 */ 'A', 'D', 'D', 'C', '8', 'm', 'c', 0,
  /* 579 */ 'D', 'A', 'D', 'D', '8', 'm', 'c', 0,
  /* 587 */ 'A', 'N', 'D', '8', 'm', 'c', 0,
  /* 594 */ 'C', 'M', 'P', '8', 'm', 'c', 0,
  /* 601 */ 'X', 'O', 'R', '8', 'm', 'c', 0,
  /* 608 */ 'B', 'I', 'S', '8', 'm', 'c', 0,
  /* 615 */ 'B', 'I', 'T', '8', 'm', 'c', 0,
  /* 622 */ 'M', 'O', 'V', '8', 'm', 'c', 0,
  /* 629 */ 'S', 'U', 'B', '1', '6', 'r', 'c', 0,
  /* 637 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'c', 0,
  /* 646 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'c', 0,
  /* 655 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'c', 0,
  /* 664 */ 'A', 'N', 'D', '1', '6', 'r', 'c', 0,
  /* 672 */ 'C', 'M', 'P', '1', '6', 'r', 'c', 0,
  /* 680 */ 'X', 'O', 'R', '1', '6', 'r', 'c', 0,
  /* 688 */ 'B', 'I', 'S', '1', '6', 'r', 'c', 0,
  /* 696 */ 'B', 'I', 'T', '1', '6', 'r', 'c', 0,
  /* 704 */ 'M', 'O', 'V', '1', '6', 'r', 'c', 0,
  /* 712 */ 'S', 'U', 'B', '8', 'r', 'c', 0,
  /* 719 */ 'S', 'U', 'B', 'C', '8', 'r', 'c', 0,
  /* 727 */ 'A', 'D', 'D', 'C', '8', 'r', 'c', 0,
  /* 735 */ 'D', 'A', 'D', 'D', '8', 'r', 'c', 0,
  /* 743 */ 'A', 'N', 'D', '8', 'r', 'c', 0,
  /* 750 */ 'C', 'M', 'P', '8', 'r', 'c', 0,
  /* 757 */ 'X', 'O', 'R', '8', 'r', 'c', 0,
  /* 764 */ 'B', 'I', 'S', '8', 'r', 'c', 0,
  /* 771 */ 'B', 'I', 'T', '8', 'r', 'c', 0,
  /* 778 */ 'M', 'O', 'V', '8', 'r', 'c', 0,
  /* 785 */ 'A', 'D', 'D', 'f', 'r', 'a', 'm', 'e', 0,
  /* 794 */ 'P', 'U', 'S', 'H', '1', '6', 'i', 0,
  /* 802 */ 'B', 'i', 0,
  /* 805 */ 'C', 'A', 'L', 'L', 'i', 0,
  /* 811 */ 'S', 'U', 'B', '1', '6', 'm', 'i', 0,
  /* 819 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'i', 0,
  /* 828 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'i', 0,
  /* 837 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'i', 0,
  /* 846 */ 'A', 'N', 'D', '1', '6', 'm', 'i', 0,
  /* 854 */ 'C', 'M', 'P', '1', '6', 'm', 'i', 0,
  /* 862 */ 'X', 'O', 'R', '1', '6', 'm', 'i', 0,
  /* 870 */ 'B', 'I', 'S', '1', '6', 'm', 'i', 0,
  /* 878 */ 'B', 'I', 'T', '1', '6', 'm', 'i', 0,
  /* 886 */ 'M', 'O', 'V', '1', '6', 'm', 'i', 0,
  /* 894 */ 'S', 'U', 'B', '8', 'm', 'i', 0,
  /* 901 */ 'S', 'U', 'B', 'C', '8', 'm', 'i', 0,
  /* 909 */ 'A', 'D', 'D', 'C', '8', 'm', 'i', 0,
  /* 917 */ 'D', 'A', 'D', 'D', '8', 'm', 'i', 0,
  /* 925 */ 'A', 'N', 'D', '8', 'm', 'i', 0,
  /* 932 */ 'C', 'M', 'P', '8', 'm', 'i', 0,
  /* 939 */ 'X', 'O', 'R', '8', 'm', 'i', 0,
  /* 946 */ 'B', 'I', 'S', '8', 'm', 'i', 0,
  /* 953 */ 'B', 'I', 'T', '8', 'm', 'i', 0,
  /* 960 */ 'M', 'O', 'V', '8', 'm', 'i', 0,
  /* 967 */ 'S', 'U', 'B', '1', '6', 'r', 'i', 0,
  /* 975 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'i', 0,
  /* 984 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'i', 0,
  /* 993 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'i', 0,
  /* 1002 */ 'A', 'N', 'D', '1', '6', 'r', 'i', 0,
  /* 1010 */ 'C', 'M', 'P', '1', '6', 'r', 'i', 0,
  /* 1018 */ 'X', 'O', 'R', '1', '6', 'r', 'i', 0,
  /* 1026 */ 'B', 'I', 'S', '1', '6', 'r', 'i', 0,
  /* 1034 */ 'B', 'I', 'T', '1', '6', 'r', 'i', 0,
  /* 1042 */ 'M', 'O', 'V', '1', '6', 'r', 'i', 0,
  /* 1050 */ 'S', 'U', 'B', '8', 'r', 'i', 0,
  /* 1057 */ 'S', 'U', 'B', 'C', '8', 'r', 'i', 0,
  /* 1065 */ 'A', 'D', 'D', 'C', '8', 'r', 'i', 0,
  /* 1073 */ 'D', 'A', 'D', 'D', '8', 'r', 'i', 0,
  /* 1081 */ 'A', 'N', 'D', '8', 'r', 'i', 0,
  /* 1088 */ 'C', 'M', 'P', '8', 'r', 'i', 0,
  /* 1095 */ 'X', 'O', 'R', '8', 'r', 'i', 0,
  /* 1102 */ 'B', 'I', 'S', '8', 'r', 'i', 0,
  /* 1109 */ 'B', 'I', 'T', '8', 'r', 'i', 0,
  /* 1116 */ 'M', 'O', 'V', '8', 'r', 'i', 0,
  /* 1123 */ 'B', 'm', 0,
  /* 1126 */ 'C', 'A', 'L', 'L', 'm', 0,
  /* 1132 */ 'S', 'U', 'B', '1', '6', 'm', 'm', 0,
  /* 1140 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'm', 0,
  /* 1149 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'm', 0,
  /* 1158 */ 'B', 'I', 'C', '1', '6', 'm', 'm', 0,
  /* 1166 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'm', 0,
  /* 1175 */ 'A', 'N', 'D', '1', '6', 'm', 'm', 0,
  /* 1183 */ 'X', 'O', 'R', '1', '6', 'm', 'm', 0,
  /* 1191 */ 'B', 'I', 'S', '1', '6', 'm', 'm', 0,
  /* 1199 */ 'B', 'I', 'T', '1', '6', 'm', 'm', 0,
  /* 1207 */ 'M', 'O', 'V', '1', '6', 'm', 'm', 0,
  /* 1215 */ 'S', 'U', 'B', '8', 'm', 'm', 0,
  /* 1222 */ 'S', 'U', 'B', 'C', '8', 'm', 'm', 0,
  /* 1230 */ 'A', 'D', 'D', 'C', '8', 'm', 'm', 0,
  /* 1238 */ 'B', 'I', 'C', '8', 'm', 'm', 0,
  /* 1245 */ 'D', 'A', 'D', 'D', '8', 'm', 'm', 0,
  /* 1253 */ 'A', 'N', 'D', '8', 'm', 'm', 0,
  /* 1260 */ 'X', 'O', 'R', '8', 'm', 'm', 0,
  /* 1267 */ 'B', 'I', 'S', '8', 'm', 'm', 0,
  /* 1274 */ 'B', 'I', 'T', '8', 'm', 'm', 0,
  /* 1281 */ 'M', 'O', 'V', '8', 'm', 'm', 0,
  /* 1288 */ 'S', 'U', 'B', '1', '6', 'r', 'm', 0,
  /* 1296 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'm', 0,
  /* 1305 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'm', 0,
  /* 1314 */ 'B', 'I', 'C', '1', '6', 'r', 'm', 0,
  /* 1322 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'm', 0,
  /* 1331 */ 'A', 'N', 'D', '1', '6', 'r', 'm', 0,
  /* 1339 */ 'C', 'M', 'P', '1', '6', 'r', 'm', 0,
  /* 1347 */ 'X', 'O', 'R', '1', '6', 'r', 'm', 0,
  /* 1355 */ 'B', 'I', 'S', '1', '6', 'r', 'm', 0,
  /* 1363 */ 'B', 'I', 'T', '1', '6', 'r', 'm', 0,
  /* 1371 */ 'M', 'O', 'V', '1', '6', 'r', 'm', 0,
  /* 1379 */ 'S', 'U', 'B', '8', 'r', 'm', 0,
  /* 1386 */ 'S', 'U', 'B', 'C', '8', 'r', 'm', 0,
  /* 1394 */ 'A', 'D', 'D', 'C', '8', 'r', 'm', 0,
  /* 1402 */ 'B', 'I', 'C', '8', 'r', 'm', 0,
  /* 1409 */ 'D', 'A', 'D', 'D', '8', 'r', 'm', 0,
  /* 1417 */ 'A', 'N', 'D', '8', 'r', 'm', 0,
  /* 1424 */ 'C', 'M', 'P', '8', 'r', 'm', 0,
  /* 1431 */ 'X', 'O', 'R', '8', 'r', 'm', 0,
  /* 1438 */ 'B', 'I', 'S', '8', 'r', 'm', 0,
  /* 1445 */ 'B', 'I', 'T', '8', 'r', 'm', 0,
  /* 1452 */ 'M', 'O', 'V', '8', 'r', 'm', 0,
  /* 1459 */ 'S', 'U', 'B', '1', '6', 'm', 'n', 0,
  /* 1467 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'n', 0,
  /* 1476 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'n', 0,
  /* 1485 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'n', 0,
  /* 1494 */ 'A', 'N', 'D', '1', '6', 'm', 'n', 0,
  /* 1502 */ 'X', 'O', 'R', '1', '6', 'm', 'n', 0,
  /* 1510 */ 'B', 'I', 'S', '1', '6', 'm', 'n', 0,
  /* 1518 */ 'S', 'U', 'B', '8', 'm', 'n', 0,
  /* 1525 */ 'S', 'U', 'B', 'C', '8', 'm', 'n', 0,
  /* 1533 */ 'A', 'D', 'D', 'C', '8', 'm', 'n', 0,
  /* 1541 */ 'D', 'A', 'D', 'D', '8', 'm', 'n', 0,
  /* 1549 */ 'A', 'N', 'D', '8', 'm', 'n', 0,
  /* 1556 */ 'X', 'O', 'R', '8', 'm', 'n', 0,
  /* 1563 */ 'B', 'I', 'S', '8', 'm', 'n', 0,
  /* 1570 */ 'S', 'U', 'B', '1', '6', 'r', 'n', 0,
  /* 1578 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'n', 0,
  /* 1587 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'n', 0,
  /* 1596 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'n', 0,
  /* 1605 */ 'A', 'N', 'D', '1', '6', 'r', 'n', 0,
  /* 1613 */ 'X', 'O', 'R', '1', '6', 'r', 'n', 0,
  /* 1621 */ 'B', 'I', 'S', '1', '6', 'r', 'n', 0,
  /* 1629 */ 'M', 'O', 'V', '1', '6', 'r', 'n', 0,
  /* 1637 */ 'S', 'U', 'B', '8', 'r', 'n', 0,
  /* 1644 */ 'S', 'U', 'B', 'C', '8', 'r', 'n', 0,
  /* 1652 */ 'A', 'D', 'D', 'C', '8', 'r', 'n', 0,
  /* 1660 */ 'D', 'A', 'D', 'D', '8', 'r', 'n', 0,
  /* 1668 */ 'A', 'N', 'D', '8', 'r', 'n', 0,
  /* 1675 */ 'X', 'O', 'R', '8', 'r', 'n', 0,
  /* 1682 */ 'B', 'I', 'S', '8', 'r', 'n', 0,
  /* 1689 */ 'M', 'O', 'V', '8', 'r', 'n', 0,
  /* 1696 */ 'S', 'U', 'B', '1', '6', 'm', 'p', 0,
  /* 1704 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'p', 0,
  /* 1713 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'p', 0,
  /* 1722 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'p', 0,
  /* 1731 */ 'A', 'N', 'D', '1', '6', 'm', 'p', 0,
  /* 1739 */ 'X', 'O', 'R', '1', '6', 'm', 'p', 0,
  /* 1747 */ 'B', 'I', 'S', '1', '6', 'm', 'p', 0,
  /* 1755 */ 'S', 'U', 'B', '8', 'm', 'p', 0,
  /* 1762 */ 'S', 'U', 'B', 'C', '8', 'm', 'p', 0,
  /* 1770 */ 'A', 'D', 'D', 'C', '8', 'm', 'p', 0,
  /* 1778 */ 'D', 'A', 'D', 'D', '8', 'm', 'p', 0,
  /* 1786 */ 'A', 'N', 'D', '8', 'm', 'p', 0,
  /* 1793 */ 'X', 'O', 'R', '8', 'm', 'p', 0,
  /* 1800 */ 'B', 'I', 'S', '8', 'm', 'p', 0,
  /* 1807 */ 'S', 'U', 'B', '1', '6', 'r', 'p', 0,
  /* 1815 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'p', 0,
  /* 1824 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'p', 0,
  /* 1833 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'p', 0,
  /* 1842 */ 'A', 'N', 'D', '1', '6', 'r', 'p', 0,
  /* 1850 */ 'X', 'O', 'R', '1', '6', 'r', 'p', 0,
  /* 1858 */ 'B', 'I', 'S', '1', '6', 'r', 'p', 0,
  /* 1866 */ 'M', 'O', 'V', '1', '6', 'r', 'p', 0,
  /* 1874 */ 'S', 'U', 'B', '8', 'r', 'p', 0,
  /* 1881 */ 'S', 'U', 'B', 'C', '8', 'r', 'p', 0,
  /* 1889 */ 'A', 'D', 'D', 'C', '8', 'r', 'p', 0,
  /* 1897 */ 'D', 'A', 'D', 'D', '8', 'r', 'p', 0,
  /* 1905 */ 'A', 'N', 'D', '8', 'r', 'p', 0,
  /* 1912 */ 'X', 'O', 'R', '8', 'r', 'p', 0,
  /* 1919 */ 'B', 'I', 'S', '8', 'r', 'p', 0,
  /* 1926 */ 'M', 'O', 'V', '8', 'r', 'p', 0,
  /* 1933 */ 'R', 'R', 'A', '1', '6', 'r', 0,
  /* 1940 */ 'S', 'W', 'P', 'B', '1', '6', 'r', 0,
  /* 1948 */ 'R', 'R', 'C', '1', '6', 'r', 0,
  /* 1955 */ 'P', 'U', 'S', 'H', '1', '6', 'r', 0,
  /* 1963 */ 'P', 'O', 'P', '1', '6', 'r', 0,
  /* 1970 */ 'S', 'E', 'X', 'T', '1', '6', 'r', 0,
  /* 1978 */ 'Z', 'E', 'X', 'T', '1', '6', 'r', 0,
  /* 1986 */ 'R', 'R', 'A', '8', 'r', 0,
  /* 1992 */ 'R', 'R', 'C', '8', 'r', 0,
  /* 1998 */ 'P', 'U', 'S', 'H', '8', 'r', 0,
  /* 2005 */ 'B', 'r', 0,
  /* 2008 */ 'C', 'A', 'L', 'L', 'r', 0,
  /* 2014 */ 'S', 'U', 'B', '1', '6', 'm', 'r', 0,
  /* 2022 */ 'S', 'U', 'B', 'C', '1', '6', 'm', 'r', 0,
  /* 2031 */ 'A', 'D', 'D', 'C', '1', '6', 'm', 'r', 0,
  /* 2040 */ 'B', 'I', 'C', '1', '6', 'm', 'r', 0,
  /* 2048 */ 'D', 'A', 'D', 'D', '1', '6', 'm', 'r', 0,
  /* 2057 */ 'A', 'N', 'D', '1', '6', 'm', 'r', 0,
  /* 2065 */ 'C', 'M', 'P', '1', '6', 'm', 'r', 0,
  /* 2073 */ 'X', 'O', 'R', '1', '6', 'm', 'r', 0,
  /* 2081 */ 'B', 'I', 'S', '1', '6', 'm', 'r', 0,
  /* 2089 */ 'B', 'I', 'T', '1', '6', 'm', 'r', 0,
  /* 2097 */ 'M', 'O', 'V', '1', '6', 'm', 'r', 0,
  /* 2105 */ 'S', 'U', 'B', '8', 'm', 'r', 0,
  /* 2112 */ 'S', 'U', 'B', 'C', '8', 'm', 'r', 0,
  /* 2120 */ 'A', 'D', 'D', 'C', '8', 'm', 'r', 0,
  /* 2128 */ 'B', 'I', 'C', '8', 'm', 'r', 0,
  /* 2135 */ 'D', 'A', 'D', 'D', '8', 'm', 'r', 0,
  /* 2143 */ 'A', 'N', 'D', '8', 'm', 'r', 0,
  /* 2150 */ 'C', 'M', 'P', '8', 'm', 'r', 0,
  /* 2157 */ 'X', 'O', 'R', '8', 'm', 'r', 0,
  /* 2164 */ 'B', 'I', 'S', '8', 'm', 'r', 0,
  /* 2171 */ 'B', 'I', 'T', '8', 'm', 'r', 0,
  /* 2178 */ 'M', 'O', 'V', '8', 'm', 'r', 0,
  /* 2185 */ 'S', 'U', 'B', '1', '6', 'r', 'r', 0,
  /* 2193 */ 'S', 'U', 'B', 'C', '1', '6', 'r', 'r', 0,
  /* 2202 */ 'A', 'D', 'D', 'C', '1', '6', 'r', 'r', 0,
  /* 2211 */ 'B', 'I', 'C', '1', '6', 'r', 'r', 0,
  /* 2219 */ 'D', 'A', 'D', 'D', '1', '6', 'r', 'r', 0,
  /* 2228 */ 'A', 'N', 'D', '1', '6', 'r', 'r', 0,
  /* 2236 */ 'C', 'M', 'P', '1', '6', 'r', 'r', 0,
  /* 2244 */ 'X', 'O', 'R', '1', '6', 'r', 'r', 0,
  /* 2252 */ 'B', 'I', 'S', '1', '6', 'r', 'r', 0,
  /* 2260 */ 'B', 'I', 'T', '1', '6', 'r', 'r', 0,
  /* 2268 */ 'M', 'O', 'V', '1', '6', 'r', 'r', 0,
  /* 2276 */ 'S', 'U', 'B', '8', 'r', 'r', 0,
  /* 2283 */ 'S', 'U', 'B', 'C', '8', 'r', 'r', 0,
  /* 2291 */ 'A', 'D', 'D', 'C', '8', 'r', 'r', 0,
  /* 2299 */ 'B', 'I', 'C', '8', 'r', 'r', 0,
  /* 2306 */ 'D', 'A', 'D', 'D', '8', 'r', 'r', 0,
  /* 2314 */ 'A', 'N', 'D', '8', 'r', 'r', 0,
  /* 2321 */ 'C', 'M', 'P', '8', 'r', 'r', 0,
  /* 2328 */ 'X', 'O', 'R', '8', 'r', 'r', 0,
  /* 2335 */ 'B', 'I', 'S', '8', 'r', 'r', 0,
  /* 2342 */ 'B', 'I', 'T', '8', 'r', 'r', 0,
  /* 2349 */ 'M', 'O', 'V', '8', 'r', 'r', 0,
};

extern const unsigned MSP430InstrNameIndices[] = {
    224U, 256U, 266U, 242U, 233U, 251U, 181U, 196U, 
    168U, 210U, 392U, 158U, 125U, 460U, 138U, 445U, 
    95U, 299U, 434U, 108U, 423U, 145U, 312U, 329U, 
    362U, 409U, 89U, 387U, 357U, 500U, 838U, 1167U, 
    1486U, 1723U, 2049U, 656U, 994U, 1323U, 1597U, 1834U, 
    2220U, 580U, 918U, 1246U, 1542U, 1779U, 2136U, 736U, 
    1074U, 1410U, 1661U, 1898U, 2307U, 490U, 828U, 1149U, 
    1476U, 1713U, 2031U, 646U, 984U, 1305U, 1587U, 1824U, 
    2202U, 571U, 909U, 1230U, 1533U, 1770U, 2120U, 727U, 
    1065U, 1394U, 1652U, 1889U, 2291U, 785U, 282U, 342U, 
    508U, 846U, 1175U, 1494U, 1731U, 2057U, 664U, 1002U, 
    1331U, 1605U, 1842U, 2228U, 587U, 925U, 1253U, 1549U, 
    1786U, 2143U, 743U, 1081U, 1417U, 1668U, 1905U, 2314U, 
    1158U, 2040U, 1314U, 2211U, 1238U, 2128U, 1402U, 2299U, 
    532U, 870U, 1191U, 1510U, 1747U, 2081U, 688U, 1026U, 
    1355U, 1621U, 1858U, 2252U, 608U, 946U, 1267U, 1563U, 
    1800U, 2164U, 764U, 1102U, 1438U, 1682U, 1919U, 2335U, 
    540U, 878U, 1199U, 2089U, 696U, 1034U, 1363U, 2260U, 
    615U, 953U, 1274U, 2171U, 771U, 1109U, 1445U, 2342U, 
    802U, 1123U, 2005U, 805U, 1126U, 2008U, 516U, 854U, 
    2065U, 672U, 1010U, 1339U, 2236U, 594U, 932U, 2150U, 
    750U, 1088U, 1424U, 2321U, 499U, 837U, 1166U, 1485U, 
    1722U, 2048U, 655U, 993U, 1322U, 1596U, 1833U, 2219U, 
    579U, 917U, 1245U, 1541U, 1778U, 2135U, 735U, 1073U, 
    1409U, 1660U, 1897U, 2306U, 85U, 308U, 548U, 886U, 
    1207U, 2097U, 704U, 1042U, 1371U, 1629U, 1866U, 2268U, 
    622U, 960U, 1281U, 2178U, 778U, 1116U, 1452U, 1689U, 
    1926U, 2349U, 55U, 66U, 1963U, 465U, 794U, 1955U, 
    1998U, 419U, 228U, 1933U, 1986U, 1948U, 1992U, 6U, 
    39U, 1970U, 473U, 811U, 1132U, 1459U, 1696U, 2014U, 
    629U, 967U, 1288U, 1570U, 1807U, 2185U, 556U, 894U, 
    1215U, 1518U, 1755U, 2105U, 712U, 1050U, 1379U, 1637U, 
    1874U, 2276U, 481U, 819U, 1140U, 1467U, 1704U, 2022U, 
    637U, 975U, 1296U, 1578U, 1815U, 2193U, 563U, 901U, 
    1222U, 1525U, 1762U, 2112U, 719U, 1057U, 1386U, 1644U, 
    1881U, 2283U, 1940U, 25U, 77U, 13U, 45U, 0U, 
    34U, 19U, 50U, 524U, 862U, 1183U, 1502U, 1739U, 
    2073U, 680U, 1018U, 1347U, 1613U, 1850U, 2244U, 601U, 
    939U, 1260U, 1556U, 1793U, 2157U, 757U, 1095U, 1431U, 
    1675U, 1912U, 2328U, 1978U, 
};

static inline void InitMSP430MCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(MSP430Insts, MSP430InstrNameIndices, MSP430InstrNameData, 316);
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
  InitMCInstrInfo(MSP430Insts, MSP430InstrNameIndices, MSP430InstrNameData, 316);
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

