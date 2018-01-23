/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values                                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM
namespace llvm_ks {

namespace Mips {
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
    G_ADD	= 23,
    ABSMacro	= 24,
    ABSQ_S_PH	= 25,
    ABSQ_S_PH_MM	= 26,
    ABSQ_S_QB	= 27,
    ABSQ_S_QB_MMR2	= 28,
    ABSQ_S_W	= 29,
    ABSQ_S_W_MM	= 30,
    ABS_D_MMR6	= 31,
    ABS_S_MMR6	= 32,
    ADD	= 33,
    ADDIUPC	= 34,
    ADDIUPC_MM	= 35,
    ADDIUPC_MMR6	= 36,
    ADDIUR1SP_MM	= 37,
    ADDIUR2_MM	= 38,
    ADDIUS5_MM	= 39,
    ADDIUSP_MM	= 40,
    ADDIU_MMR6	= 41,
    ADDQH_PH	= 42,
    ADDQH_PH_MMR2	= 43,
    ADDQH_R_PH	= 44,
    ADDQH_R_PH_MMR2	= 45,
    ADDQH_R_W	= 46,
    ADDQH_R_W_MMR2	= 47,
    ADDQH_W	= 48,
    ADDQH_W_MMR2	= 49,
    ADDQ_PH	= 50,
    ADDQ_PH_MM	= 51,
    ADDQ_S_PH	= 52,
    ADDQ_S_PH_MM	= 53,
    ADDQ_S_W	= 54,
    ADDQ_S_W_MM	= 55,
    ADDSC	= 56,
    ADDSC_MM	= 57,
    ADDS_A_B	= 58,
    ADDS_A_D	= 59,
    ADDS_A_H	= 60,
    ADDS_A_W	= 61,
    ADDS_S_B	= 62,
    ADDS_S_D	= 63,
    ADDS_S_H	= 64,
    ADDS_S_W	= 65,
    ADDS_U_B	= 66,
    ADDS_U_D	= 67,
    ADDS_U_H	= 68,
    ADDS_U_W	= 69,
    ADDU16_MM	= 70,
    ADDU16_MMR6	= 71,
    ADDUH_QB	= 72,
    ADDUH_QB_MMR2	= 73,
    ADDUH_R_QB	= 74,
    ADDUH_R_QB_MMR2	= 75,
    ADDU_MMR6	= 76,
    ADDU_PH	= 77,
    ADDU_PH_MMR2	= 78,
    ADDU_QB	= 79,
    ADDU_QB_MM	= 80,
    ADDU_S_PH	= 81,
    ADDU_S_PH_MMR2	= 82,
    ADDU_S_QB	= 83,
    ADDU_S_QB_MM	= 84,
    ADDVI_B	= 85,
    ADDVI_D	= 86,
    ADDVI_H	= 87,
    ADDVI_W	= 88,
    ADDV_B	= 89,
    ADDV_D	= 90,
    ADDV_H	= 91,
    ADDV_W	= 92,
    ADDWC	= 93,
    ADDWC_MM	= 94,
    ADD_A_B	= 95,
    ADD_A_D	= 96,
    ADD_A_H	= 97,
    ADD_A_W	= 98,
    ADD_MM	= 99,
    ADD_MMR6	= 100,
    ADDi	= 101,
    ADDi_MM	= 102,
    ADDiu	= 103,
    ADDiu_MM	= 104,
    ADDu	= 105,
    ADDu_MM	= 106,
    ADJCALLSTACKDOWN	= 107,
    ADJCALLSTACKUP	= 108,
    ALIGN	= 109,
    ALIGN_MMR6	= 110,
    ALUIPC	= 111,
    ALUIPC_MMR6	= 112,
    AND	= 113,
    AND16_MM	= 114,
    AND16_MMR6	= 115,
    AND64	= 116,
    ANDI16_MM	= 117,
    ANDI16_MMR6	= 118,
    ANDI_B	= 119,
    ANDI_MMR6	= 120,
    AND_MM	= 121,
    AND_MMR6	= 122,
    AND_V	= 123,
    AND_V_D_PSEUDO	= 124,
    AND_V_H_PSEUDO	= 125,
    AND_V_W_PSEUDO	= 126,
    ANDi	= 127,
    ANDi64	= 128,
    ANDi_MM	= 129,
    APPEND	= 130,
    ASUB_S_B	= 131,
    ASUB_S_D	= 132,
    ASUB_S_H	= 133,
    ASUB_S_W	= 134,
    ASUB_U_B	= 135,
    ASUB_U_D	= 136,
    ASUB_U_H	= 137,
    ASUB_U_W	= 138,
    ATOMIC_CMP_SWAP_I16	= 139,
    ATOMIC_CMP_SWAP_I32	= 140,
    ATOMIC_CMP_SWAP_I64	= 141,
    ATOMIC_CMP_SWAP_I8	= 142,
    ATOMIC_LOAD_ADD_I16	= 143,
    ATOMIC_LOAD_ADD_I32	= 144,
    ATOMIC_LOAD_ADD_I64	= 145,
    ATOMIC_LOAD_ADD_I8	= 146,
    ATOMIC_LOAD_AND_I16	= 147,
    ATOMIC_LOAD_AND_I32	= 148,
    ATOMIC_LOAD_AND_I64	= 149,
    ATOMIC_LOAD_AND_I8	= 150,
    ATOMIC_LOAD_NAND_I16	= 151,
    ATOMIC_LOAD_NAND_I32	= 152,
    ATOMIC_LOAD_NAND_I64	= 153,
    ATOMIC_LOAD_NAND_I8	= 154,
    ATOMIC_LOAD_OR_I16	= 155,
    ATOMIC_LOAD_OR_I32	= 156,
    ATOMIC_LOAD_OR_I64	= 157,
    ATOMIC_LOAD_OR_I8	= 158,
    ATOMIC_LOAD_SUB_I16	= 159,
    ATOMIC_LOAD_SUB_I32	= 160,
    ATOMIC_LOAD_SUB_I64	= 161,
    ATOMIC_LOAD_SUB_I8	= 162,
    ATOMIC_LOAD_XOR_I16	= 163,
    ATOMIC_LOAD_XOR_I32	= 164,
    ATOMIC_LOAD_XOR_I64	= 165,
    ATOMIC_LOAD_XOR_I8	= 166,
    ATOMIC_SWAP_I16	= 167,
    ATOMIC_SWAP_I32	= 168,
    ATOMIC_SWAP_I64	= 169,
    ATOMIC_SWAP_I8	= 170,
    AUI	= 171,
    AUIPC	= 172,
    AUIPC_MMR6	= 173,
    AUI_MMR6	= 174,
    AVER_S_B	= 175,
    AVER_S_D	= 176,
    AVER_S_H	= 177,
    AVER_S_W	= 178,
    AVER_U_B	= 179,
    AVER_U_D	= 180,
    AVER_U_H	= 181,
    AVER_U_W	= 182,
    AVE_S_B	= 183,
    AVE_S_D	= 184,
    AVE_S_H	= 185,
    AVE_S_W	= 186,
    AVE_U_B	= 187,
    AVE_U_D	= 188,
    AVE_U_H	= 189,
    AVE_U_W	= 190,
    AddiuRxImmX16	= 191,
    AddiuRxPcImmX16	= 192,
    AddiuRxRxImm16	= 193,
    AddiuRxRxImmX16	= 194,
    AddiuRxRyOffMemX16	= 195,
    AddiuSpImm16	= 196,
    AddiuSpImmX16	= 197,
    AdduRxRyRz16	= 198,
    AndRxRxRy16	= 199,
    B	= 200,
    B16_MM	= 201,
    BADDu	= 202,
    BAL	= 203,
    BALC	= 204,
    BALC_MMR6	= 205,
    BALIGN	= 206,
    BAL_BR	= 207,
    BBIT0	= 208,
    BBIT032	= 209,
    BBIT1	= 210,
    BBIT132	= 211,
    BC	= 212,
    BC16_MMR6	= 213,
    BC1EQZ	= 214,
    BC1F	= 215,
    BC1FL	= 216,
    BC1F_MM	= 217,
    BC1NEZ	= 218,
    BC1T	= 219,
    BC1TL	= 220,
    BC1T_MM	= 221,
    BC2EQZ	= 222,
    BC2NEZ	= 223,
    BCLRI_B	= 224,
    BCLRI_D	= 225,
    BCLRI_H	= 226,
    BCLRI_W	= 227,
    BCLR_B	= 228,
    BCLR_D	= 229,
    BCLR_H	= 230,
    BCLR_W	= 231,
    BC_MMR6	= 232,
    BEQ	= 233,
    BEQ64	= 234,
    BEQC	= 235,
    BEQL	= 236,
    BEQZ16_MM	= 237,
    BEQZALC	= 238,
    BEQZALC_MMR6	= 239,
    BEQZC	= 240,
    BEQZC16_MMR6	= 241,
    BEQZC_MM	= 242,
    BEQ_MM	= 243,
    BGE	= 244,
    BGEC	= 245,
    BGEImmMacro	= 246,
    BGEL	= 247,
    BGELImmMacro	= 248,
    BGEU	= 249,
    BGEUC	= 250,
    BGEUImmMacro	= 251,
    BGEUL	= 252,
    BGEULImmMacro	= 253,
    BGEZ	= 254,
    BGEZ64	= 255,
    BGEZAL	= 256,
    BGEZALC	= 257,
    BGEZALC_MMR6	= 258,
    BGEZALL	= 259,
    BGEZALS_MM	= 260,
    BGEZAL_MM	= 261,
    BGEZC	= 262,
    BGEZL	= 263,
    BGEZ_MM	= 264,
    BGT	= 265,
    BGTImmMacro	= 266,
    BGTL	= 267,
    BGTLImmMacro	= 268,
    BGTU	= 269,
    BGTUImmMacro	= 270,
    BGTUL	= 271,
    BGTULImmMacro	= 272,
    BGTZ	= 273,
    BGTZ64	= 274,
    BGTZALC	= 275,
    BGTZALC_MMR6	= 276,
    BGTZC	= 277,
    BGTZL	= 278,
    BGTZ_MM	= 279,
    BINSLI_B	= 280,
    BINSLI_D	= 281,
    BINSLI_H	= 282,
    BINSLI_W	= 283,
    BINSL_B	= 284,
    BINSL_D	= 285,
    BINSL_H	= 286,
    BINSL_W	= 287,
    BINSRI_B	= 288,
    BINSRI_D	= 289,
    BINSRI_H	= 290,
    BINSRI_W	= 291,
    BINSR_B	= 292,
    BINSR_D	= 293,
    BINSR_H	= 294,
    BINSR_W	= 295,
    BITREV	= 296,
    BITSWAP	= 297,
    BITSWAP_MMR6	= 298,
    BLE	= 299,
    BLEImmMacro	= 300,
    BLEL	= 301,
    BLELImmMacro	= 302,
    BLEU	= 303,
    BLEUImmMacro	= 304,
    BLEUL	= 305,
    BLEULImmMacro	= 306,
    BLEZ	= 307,
    BLEZ64	= 308,
    BLEZALC	= 309,
    BLEZALC_MMR6	= 310,
    BLEZC	= 311,
    BLEZL	= 312,
    BLEZ_MM	= 313,
    BLT	= 314,
    BLTC	= 315,
    BLTImmMacro	= 316,
    BLTL	= 317,
    BLTLImmMacro	= 318,
    BLTU	= 319,
    BLTUC	= 320,
    BLTUImmMacro	= 321,
    BLTUL	= 322,
    BLTULImmMacro	= 323,
    BLTZ	= 324,
    BLTZ64	= 325,
    BLTZAL	= 326,
    BLTZALC	= 327,
    BLTZALC_MMR6	= 328,
    BLTZALL	= 329,
    BLTZALS_MM	= 330,
    BLTZAL_MM	= 331,
    BLTZC	= 332,
    BLTZL	= 333,
    BLTZ_MM	= 334,
    BMNZI_B	= 335,
    BMNZ_V	= 336,
    BMZI_B	= 337,
    BMZ_V	= 338,
    BNE	= 339,
    BNE64	= 340,
    BNEC	= 341,
    BNEGI_B	= 342,
    BNEGI_D	= 343,
    BNEGI_H	= 344,
    BNEGI_W	= 345,
    BNEG_B	= 346,
    BNEG_D	= 347,
    BNEG_H	= 348,
    BNEG_W	= 349,
    BNEL	= 350,
    BNEZ16_MM	= 351,
    BNEZALC	= 352,
    BNEZALC_MMR6	= 353,
    BNEZC	= 354,
    BNEZC16_MMR6	= 355,
    BNEZC_MM	= 356,
    BNE_MM	= 357,
    BNVC	= 358,
    BNZ_B	= 359,
    BNZ_D	= 360,
    BNZ_H	= 361,
    BNZ_V	= 362,
    BNZ_W	= 363,
    BOVC	= 364,
    BPOSGE32	= 365,
    BPOSGE32_PSEUDO	= 366,
    BREAK	= 367,
    BREAK16_MM	= 368,
    BREAK16_MMR6	= 369,
    BREAK_MM	= 370,
    BREAK_MMR6	= 371,
    BSELI_B	= 372,
    BSEL_D_PSEUDO	= 373,
    BSEL_FD_PSEUDO	= 374,
    BSEL_FW_PSEUDO	= 375,
    BSEL_H_PSEUDO	= 376,
    BSEL_V	= 377,
    BSEL_W_PSEUDO	= 378,
    BSETI_B	= 379,
    BSETI_D	= 380,
    BSETI_H	= 381,
    BSETI_W	= 382,
    BSET_B	= 383,
    BSET_D	= 384,
    BSET_H	= 385,
    BSET_W	= 386,
    BZ_B	= 387,
    BZ_D	= 388,
    BZ_H	= 389,
    BZ_V	= 390,
    BZ_W	= 391,
    B_MMR6_Pseudo	= 392,
    B_MM_Pseudo	= 393,
    BeqImm	= 394,
    BeqzRxImm16	= 395,
    BeqzRxImmX16	= 396,
    Bimm16	= 397,
    BimmX16	= 398,
    BneImm	= 399,
    BnezRxImm16	= 400,
    BnezRxImmX16	= 401,
    Break16	= 402,
    Bteqz16	= 403,
    BteqzT8CmpX16	= 404,
    BteqzT8CmpiX16	= 405,
    BteqzT8SltX16	= 406,
    BteqzT8SltiX16	= 407,
    BteqzT8SltiuX16	= 408,
    BteqzT8SltuX16	= 409,
    BteqzX16	= 410,
    Btnez16	= 411,
    BtnezT8CmpX16	= 412,
    BtnezT8CmpiX16	= 413,
    BtnezT8SltX16	= 414,
    BtnezT8SltiX16	= 415,
    BtnezT8SltiuX16	= 416,
    BtnezT8SltuX16	= 417,
    BtnezX16	= 418,
    BuildPairF64	= 419,
    BuildPairF64_64	= 420,
    CACHE	= 421,
    CACHEE	= 422,
    CACHEE_MM	= 423,
    CACHEE_MMR6	= 424,
    CACHE_MM	= 425,
    CACHE_MMR6	= 426,
    CACHE_R6	= 427,
    CEIL_L_D64	= 428,
    CEIL_L_D_MMR6	= 429,
    CEIL_L_S	= 430,
    CEIL_L_S_MMR6	= 431,
    CEIL_W_D32	= 432,
    CEIL_W_D64	= 433,
    CEIL_W_D_MMR6	= 434,
    CEIL_W_MM	= 435,
    CEIL_W_S	= 436,
    CEIL_W_S_MM	= 437,
    CEIL_W_S_MMR6	= 438,
    CEQI_B	= 439,
    CEQI_D	= 440,
    CEQI_H	= 441,
    CEQI_W	= 442,
    CEQ_B	= 443,
    CEQ_D	= 444,
    CEQ_H	= 445,
    CEQ_W	= 446,
    CFC1	= 447,
    CFC1_MM	= 448,
    CFCMSA	= 449,
    CINS	= 450,
    CINS32	= 451,
    CLASS_D	= 452,
    CLASS_D_MMR6	= 453,
    CLASS_S	= 454,
    CLASS_S_MMR6	= 455,
    CLEI_S_B	= 456,
    CLEI_S_D	= 457,
    CLEI_S_H	= 458,
    CLEI_S_W	= 459,
    CLEI_U_B	= 460,
    CLEI_U_D	= 461,
    CLEI_U_H	= 462,
    CLEI_U_W	= 463,
    CLE_S_B	= 464,
    CLE_S_D	= 465,
    CLE_S_H	= 466,
    CLE_S_W	= 467,
    CLE_U_B	= 468,
    CLE_U_D	= 469,
    CLE_U_H	= 470,
    CLE_U_W	= 471,
    CLO	= 472,
    CLO_MM	= 473,
    CLO_MMR6	= 474,
    CLO_R6	= 475,
    CLTI_S_B	= 476,
    CLTI_S_D	= 477,
    CLTI_S_H	= 478,
    CLTI_S_W	= 479,
    CLTI_U_B	= 480,
    CLTI_U_D	= 481,
    CLTI_U_H	= 482,
    CLTI_U_W	= 483,
    CLT_S_B	= 484,
    CLT_S_D	= 485,
    CLT_S_H	= 486,
    CLT_S_W	= 487,
    CLT_U_B	= 488,
    CLT_U_D	= 489,
    CLT_U_H	= 490,
    CLT_U_W	= 491,
    CLZ	= 492,
    CLZ_MM	= 493,
    CLZ_MMR6	= 494,
    CLZ_R6	= 495,
    CMPGDU_EQ_QB	= 496,
    CMPGDU_LE_QB	= 497,
    CMPGDU_LT_QB	= 498,
    CMPGU_EQ_QB	= 499,
    CMPGU_LE_QB	= 500,
    CMPGU_LT_QB	= 501,
    CMPU_EQ_QB	= 502,
    CMPU_LE_QB	= 503,
    CMPU_LT_QB	= 504,
    CMP_AF_D_MMR6	= 505,
    CMP_AF_S_MMR6	= 506,
    CMP_EQ_D	= 507,
    CMP_EQ_D_MMR6	= 508,
    CMP_EQ_PH	= 509,
    CMP_EQ_S	= 510,
    CMP_EQ_S_MMR6	= 511,
    CMP_F_D	= 512,
    CMP_F_S	= 513,
    CMP_LE_D	= 514,
    CMP_LE_D_MMR6	= 515,
    CMP_LE_PH	= 516,
    CMP_LE_S	= 517,
    CMP_LE_S_MMR6	= 518,
    CMP_LT_D	= 519,
    CMP_LT_D_MMR6	= 520,
    CMP_LT_PH	= 521,
    CMP_LT_S	= 522,
    CMP_LT_S_MMR6	= 523,
    CMP_SAF_D	= 524,
    CMP_SAF_D_MMR6	= 525,
    CMP_SAF_S	= 526,
    CMP_SAF_S_MMR6	= 527,
    CMP_SEQ_D	= 528,
    CMP_SEQ_D_MMR6	= 529,
    CMP_SEQ_S	= 530,
    CMP_SEQ_S_MMR6	= 531,
    CMP_SLE_D	= 532,
    CMP_SLE_D_MMR6	= 533,
    CMP_SLE_S	= 534,
    CMP_SLE_S_MMR6	= 535,
    CMP_SLT_D	= 536,
    CMP_SLT_D_MMR6	= 537,
    CMP_SLT_S	= 538,
    CMP_SLT_S_MMR6	= 539,
    CMP_SUEQ_D	= 540,
    CMP_SUEQ_D_MMR6	= 541,
    CMP_SUEQ_S	= 542,
    CMP_SUEQ_S_MMR6	= 543,
    CMP_SULE_D	= 544,
    CMP_SULE_D_MMR6	= 545,
    CMP_SULE_S	= 546,
    CMP_SULE_S_MMR6	= 547,
    CMP_SULT_D	= 548,
    CMP_SULT_D_MMR6	= 549,
    CMP_SULT_S	= 550,
    CMP_SULT_S_MMR6	= 551,
    CMP_SUN_D	= 552,
    CMP_SUN_D_MMR6	= 553,
    CMP_SUN_S	= 554,
    CMP_SUN_S_MMR6	= 555,
    CMP_UEQ_D	= 556,
    CMP_UEQ_D_MMR6	= 557,
    CMP_UEQ_S	= 558,
    CMP_UEQ_S_MMR6	= 559,
    CMP_ULE_D	= 560,
    CMP_ULE_D_MMR6	= 561,
    CMP_ULE_S	= 562,
    CMP_ULE_S_MMR6	= 563,
    CMP_ULT_D	= 564,
    CMP_ULT_D_MMR6	= 565,
    CMP_ULT_S	= 566,
    CMP_ULT_S_MMR6	= 567,
    CMP_UN_D	= 568,
    CMP_UN_D_MMR6	= 569,
    CMP_UN_S	= 570,
    CMP_UN_S_MMR6	= 571,
    CONSTPOOL_ENTRY	= 572,
    COPY_FD_PSEUDO	= 573,
    COPY_FW_PSEUDO	= 574,
    COPY_S_B	= 575,
    COPY_S_D	= 576,
    COPY_S_H	= 577,
    COPY_S_W	= 578,
    COPY_U_B	= 579,
    COPY_U_H	= 580,
    COPY_U_W	= 581,
    CTC1	= 582,
    CTC1_MM	= 583,
    CTCMSA	= 584,
    CVT_D32_S	= 585,
    CVT_D32_W	= 586,
    CVT_D32_W_MM	= 587,
    CVT_D64_L	= 588,
    CVT_D64_S	= 589,
    CVT_D64_W	= 590,
    CVT_D_L_MMR6	= 591,
    CVT_D_S_MM	= 592,
    CVT_D_S_MMR6	= 593,
    CVT_D_W_MMR6	= 594,
    CVT_L_D64	= 595,
    CVT_L_D64_MM	= 596,
    CVT_L_D_MMR6	= 597,
    CVT_L_S	= 598,
    CVT_L_S_MM	= 599,
    CVT_L_S_MMR6	= 600,
    CVT_S_D32	= 601,
    CVT_S_D32_MM	= 602,
    CVT_S_D64	= 603,
    CVT_S_D_MMR6	= 604,
    CVT_S_L	= 605,
    CVT_S_L_MMR6	= 606,
    CVT_S_W	= 607,
    CVT_S_W_MM	= 608,
    CVT_S_W_MMR6	= 609,
    CVT_W_D32	= 610,
    CVT_W_D64	= 611,
    CVT_W_D_MMR6	= 612,
    CVT_W_MM	= 613,
    CVT_W_S	= 614,
    CVT_W_S_MM	= 615,
    CVT_W_S_MMR6	= 616,
    C_EQ_D32	= 617,
    C_EQ_D64	= 618,
    C_EQ_S	= 619,
    C_F_D32	= 620,
    C_F_D64	= 621,
    C_F_S	= 622,
    C_LE_D32	= 623,
    C_LE_D64	= 624,
    C_LE_S	= 625,
    C_LT_D32	= 626,
    C_LT_D64	= 627,
    C_LT_S	= 628,
    C_NGE_D32	= 629,
    C_NGE_D64	= 630,
    C_NGE_S	= 631,
    C_NGLE_D32	= 632,
    C_NGLE_D64	= 633,
    C_NGLE_S	= 634,
    C_NGL_D32	= 635,
    C_NGL_D64	= 636,
    C_NGL_S	= 637,
    C_NGT_D32	= 638,
    C_NGT_D64	= 639,
    C_NGT_S	= 640,
    C_OLE_D32	= 641,
    C_OLE_D64	= 642,
    C_OLE_S	= 643,
    C_OLT_D32	= 644,
    C_OLT_D64	= 645,
    C_OLT_S	= 646,
    C_SEQ_D32	= 647,
    C_SEQ_D64	= 648,
    C_SEQ_S	= 649,
    C_SF_D32	= 650,
    C_SF_D64	= 651,
    C_SF_S	= 652,
    C_UEQ_D32	= 653,
    C_UEQ_D64	= 654,
    C_UEQ_S	= 655,
    C_ULE_D32	= 656,
    C_ULE_D64	= 657,
    C_ULE_S	= 658,
    C_ULT_D32	= 659,
    C_ULT_D64	= 660,
    C_ULT_S	= 661,
    C_UN_D32	= 662,
    C_UN_D64	= 663,
    C_UN_S	= 664,
    CmpRxRy16	= 665,
    CmpiRxImm16	= 666,
    CmpiRxImmX16	= 667,
    Constant32	= 668,
    DADD	= 669,
    DADDi	= 670,
    DADDiu	= 671,
    DADDu	= 672,
    DAHI	= 673,
    DAHI_MM64R6	= 674,
    DALIGN	= 675,
    DALIGN_MM64R6	= 676,
    DATI	= 677,
    DATI_MM64R6	= 678,
    DAUI	= 679,
    DAUI_MM64R6	= 680,
    DBITSWAP	= 681,
    DCLO	= 682,
    DCLO_R6	= 683,
    DCLZ	= 684,
    DCLZ_R6	= 685,
    DDIV	= 686,
    DDIVU	= 687,
    DDIVU_MM64R6	= 688,
    DDIV_MM64R6	= 689,
    DERET	= 690,
    DERET_MM	= 691,
    DERET_MMR6	= 692,
    DEXT	= 693,
    DEXTM	= 694,
    DEXTM_MM64R6	= 695,
    DEXTU	= 696,
    DEXTU_MM64R6	= 697,
    DEXT_MM64R6	= 698,
    DI	= 699,
    DINS	= 700,
    DINSM	= 701,
    DINSU	= 702,
    DIV	= 703,
    DIVU	= 704,
    DIVU_MMR6	= 705,
    DIV_MMR6	= 706,
    DIV_S_B	= 707,
    DIV_S_D	= 708,
    DIV_S_H	= 709,
    DIV_S_W	= 710,
    DIV_U_B	= 711,
    DIV_U_D	= 712,
    DIV_U_H	= 713,
    DIV_U_W	= 714,
    DI_MM	= 715,
    DI_MMR6	= 716,
    DLSA	= 717,
    DLSA_R6	= 718,
    DMFC0	= 719,
    DMFC1	= 720,
    DMFC2	= 721,
    DMFC2_OCTEON	= 722,
    DMOD	= 723,
    DMODU	= 724,
    DMODU_MM64R6	= 725,
    DMOD_MM64R6	= 726,
    DMTC0	= 727,
    DMTC1	= 728,
    DMTC2	= 729,
    DMTC2_OCTEON	= 730,
    DMUH	= 731,
    DMUHU	= 732,
    DMUL	= 733,
    DMULT	= 734,
    DMULTu	= 735,
    DMULU	= 736,
    DMUL_R6	= 737,
    DOTP_S_D	= 738,
    DOTP_S_H	= 739,
    DOTP_S_W	= 740,
    DOTP_U_D	= 741,
    DOTP_U_H	= 742,
    DOTP_U_W	= 743,
    DPADD_S_D	= 744,
    DPADD_S_H	= 745,
    DPADD_S_W	= 746,
    DPADD_U_D	= 747,
    DPADD_U_H	= 748,
    DPADD_U_W	= 749,
    DPAQX_SA_W_PH	= 750,
    DPAQX_SA_W_PH_MMR2	= 751,
    DPAQX_S_W_PH	= 752,
    DPAQX_S_W_PH_MMR2	= 753,
    DPAQ_SA_L_W	= 754,
    DPAQ_SA_L_W_MM	= 755,
    DPAQ_S_W_PH	= 756,
    DPAQ_S_W_PH_MM	= 757,
    DPAU_H_QBL	= 758,
    DPAU_H_QBL_MM	= 759,
    DPAU_H_QBR	= 760,
    DPAU_H_QBR_MM	= 761,
    DPAX_W_PH	= 762,
    DPAX_W_PH_MMR2	= 763,
    DPA_W_PH	= 764,
    DPA_W_PH_MMR2	= 765,
    DPOP	= 766,
    DPSQX_SA_W_PH	= 767,
    DPSQX_SA_W_PH_MMR2	= 768,
    DPSQX_S_W_PH	= 769,
    DPSQX_S_W_PH_MMR2	= 770,
    DPSQ_SA_L_W	= 771,
    DPSQ_SA_L_W_MM	= 772,
    DPSQ_S_W_PH	= 773,
    DPSQ_S_W_PH_MM	= 774,
    DPSUB_S_D	= 775,
    DPSUB_S_H	= 776,
    DPSUB_S_W	= 777,
    DPSUB_U_D	= 778,
    DPSUB_U_H	= 779,
    DPSUB_U_W	= 780,
    DPSU_H_QBL	= 781,
    DPSU_H_QBL_MM	= 782,
    DPSU_H_QBR	= 783,
    DPSU_H_QBR_MM	= 784,
    DPSX_W_PH	= 785,
    DPSX_W_PH_MMR2	= 786,
    DPS_W_PH	= 787,
    DPS_W_PH_MMR2	= 788,
    DROL	= 789,
    DROLImm	= 790,
    DROR	= 791,
    DRORImm	= 792,
    DROTR	= 793,
    DROTR32	= 794,
    DROTRV	= 795,
    DSBH	= 796,
    DSDIV	= 797,
    DSDivMacro	= 798,
    DSHD	= 799,
    DSLL	= 800,
    DSLL32	= 801,
    DSLL64_32	= 802,
    DSLLV	= 803,
    DSRA	= 804,
    DSRA32	= 805,
    DSRAV	= 806,
    DSRL	= 807,
    DSRL32	= 808,
    DSRLV	= 809,
    DSUB	= 810,
    DSUBu	= 811,
    DUDIV	= 812,
    DUDivMacro	= 813,
    DivRxRy16	= 814,
    DivuRxRy16	= 815,
    EHB	= 816,
    EHB_MM	= 817,
    EHB_MMR6	= 818,
    EI	= 819,
    EI_MM	= 820,
    EI_MMR6	= 821,
    ERET	= 822,
    ERETNC	= 823,
    ERETNC_MMR6	= 824,
    ERET_MM	= 825,
    ERET_MMR6	= 826,
    ERet	= 827,
    EXT	= 828,
    EXTP	= 829,
    EXTPDP	= 830,
    EXTPDPV	= 831,
    EXTPDPV_MM	= 832,
    EXTPDP_MM	= 833,
    EXTPV	= 834,
    EXTPV_MM	= 835,
    EXTP_MM	= 836,
    EXTRV_RS_W	= 837,
    EXTRV_RS_W_MM	= 838,
    EXTRV_R_W	= 839,
    EXTRV_R_W_MM	= 840,
    EXTRV_S_H	= 841,
    EXTRV_S_H_MM	= 842,
    EXTRV_W	= 843,
    EXTRV_W_MM	= 844,
    EXTR_RS_W	= 845,
    EXTR_RS_W_MM	= 846,
    EXTR_R_W	= 847,
    EXTR_R_W_MM	= 848,
    EXTR_S_H	= 849,
    EXTR_S_H_MM	= 850,
    EXTR_W	= 851,
    EXTR_W_MM	= 852,
    EXTS	= 853,
    EXTS32	= 854,
    EXT_MM	= 855,
    ExtractElementF64	= 856,
    ExtractElementF64_64	= 857,
    FABS_D	= 858,
    FABS_D32	= 859,
    FABS_D64	= 860,
    FABS_MM	= 861,
    FABS_S	= 862,
    FABS_S_MM	= 863,
    FABS_W	= 864,
    FADD_D	= 865,
    FADD_D32	= 866,
    FADD_D64	= 867,
    FADD_D_MMR6	= 868,
    FADD_MM	= 869,
    FADD_S	= 870,
    FADD_S_MM	= 871,
    FADD_S_MMR6	= 872,
    FADD_W	= 873,
    FCAF_D	= 874,
    FCAF_W	= 875,
    FCEQ_D	= 876,
    FCEQ_W	= 877,
    FCLASS_D	= 878,
    FCLASS_W	= 879,
    FCLE_D	= 880,
    FCLE_W	= 881,
    FCLT_D	= 882,
    FCLT_W	= 883,
    FCMP_D32	= 884,
    FCMP_D32_MM	= 885,
    FCMP_D64	= 886,
    FCMP_S32	= 887,
    FCMP_S32_MM	= 888,
    FCNE_D	= 889,
    FCNE_W	= 890,
    FCOR_D	= 891,
    FCOR_W	= 892,
    FCUEQ_D	= 893,
    FCUEQ_W	= 894,
    FCULE_D	= 895,
    FCULE_W	= 896,
    FCULT_D	= 897,
    FCULT_W	= 898,
    FCUNE_D	= 899,
    FCUNE_W	= 900,
    FCUN_D	= 901,
    FCUN_W	= 902,
    FDIV_D	= 903,
    FDIV_D32	= 904,
    FDIV_D64	= 905,
    FDIV_D_MMR6	= 906,
    FDIV_MM	= 907,
    FDIV_S	= 908,
    FDIV_S_MM	= 909,
    FDIV_S_MMR6	= 910,
    FDIV_W	= 911,
    FEXDO_H	= 912,
    FEXDO_W	= 913,
    FEXP2_D	= 914,
    FEXP2_D_1_PSEUDO	= 915,
    FEXP2_W	= 916,
    FEXP2_W_1_PSEUDO	= 917,
    FEXUPL_D	= 918,
    FEXUPL_W	= 919,
    FEXUPR_D	= 920,
    FEXUPR_W	= 921,
    FFINT_S_D	= 922,
    FFINT_S_W	= 923,
    FFINT_U_D	= 924,
    FFINT_U_W	= 925,
    FFQL_D	= 926,
    FFQL_W	= 927,
    FFQR_D	= 928,
    FFQR_W	= 929,
    FILL_B	= 930,
    FILL_D	= 931,
    FILL_FD_PSEUDO	= 932,
    FILL_FW_PSEUDO	= 933,
    FILL_H	= 934,
    FILL_W	= 935,
    FLOG2_D	= 936,
    FLOG2_W	= 937,
    FLOOR_L_D64	= 938,
    FLOOR_L_D_MMR6	= 939,
    FLOOR_L_S	= 940,
    FLOOR_L_S_MMR6	= 941,
    FLOOR_W_D32	= 942,
    FLOOR_W_D64	= 943,
    FLOOR_W_D_MMR6	= 944,
    FLOOR_W_MM	= 945,
    FLOOR_W_S	= 946,
    FLOOR_W_S_MM	= 947,
    FLOOR_W_S_MMR6	= 948,
    FMADD_D	= 949,
    FMADD_W	= 950,
    FMAX_A_D	= 951,
    FMAX_A_W	= 952,
    FMAX_D	= 953,
    FMAX_W	= 954,
    FMIN_A_D	= 955,
    FMIN_A_W	= 956,
    FMIN_D	= 957,
    FMIN_W	= 958,
    FMOV_D32	= 959,
    FMOV_D32_MM	= 960,
    FMOV_D64	= 961,
    FMOV_D_MMR6	= 962,
    FMOV_S	= 963,
    FMOV_S_MM	= 964,
    FMOV_S_MMR6	= 965,
    FMSUB_D	= 966,
    FMSUB_W	= 967,
    FMUL_D	= 968,
    FMUL_D32	= 969,
    FMUL_D64	= 970,
    FMUL_D_MMR6	= 971,
    FMUL_MM	= 972,
    FMUL_S	= 973,
    FMUL_S_MM	= 974,
    FMUL_S_MMR6	= 975,
    FMUL_W	= 976,
    FNEG_D32	= 977,
    FNEG_D64	= 978,
    FNEG_D_MMR6	= 979,
    FNEG_MM	= 980,
    FNEG_S	= 981,
    FNEG_S_MM	= 982,
    FNEG_S_MMR6	= 983,
    FRCP_D	= 984,
    FRCP_W	= 985,
    FRINT_D	= 986,
    FRINT_W	= 987,
    FRSQRT_D	= 988,
    FRSQRT_W	= 989,
    FSAF_D	= 990,
    FSAF_W	= 991,
    FSEQ_D	= 992,
    FSEQ_W	= 993,
    FSLE_D	= 994,
    FSLE_W	= 995,
    FSLT_D	= 996,
    FSLT_W	= 997,
    FSNE_D	= 998,
    FSNE_W	= 999,
    FSOR_D	= 1000,
    FSOR_W	= 1001,
    FSQRT_D	= 1002,
    FSQRT_D32	= 1003,
    FSQRT_D64	= 1004,
    FSQRT_MM	= 1005,
    FSQRT_S	= 1006,
    FSQRT_S_MM	= 1007,
    FSQRT_W	= 1008,
    FSUB_D	= 1009,
    FSUB_D32	= 1010,
    FSUB_D64	= 1011,
    FSUB_D_MMR6	= 1012,
    FSUB_MM	= 1013,
    FSUB_S	= 1014,
    FSUB_S_MM	= 1015,
    FSUB_S_MMR6	= 1016,
    FSUB_W	= 1017,
    FSUEQ_D	= 1018,
    FSUEQ_W	= 1019,
    FSULE_D	= 1020,
    FSULE_W	= 1021,
    FSULT_D	= 1022,
    FSULT_W	= 1023,
    FSUNE_D	= 1024,
    FSUNE_W	= 1025,
    FSUN_D	= 1026,
    FSUN_W	= 1027,
    FTINT_S_D	= 1028,
    FTINT_S_W	= 1029,
    FTINT_U_D	= 1030,
    FTINT_U_W	= 1031,
    FTQ_H	= 1032,
    FTQ_W	= 1033,
    FTRUNC_S_D	= 1034,
    FTRUNC_S_W	= 1035,
    FTRUNC_U_D	= 1036,
    FTRUNC_U_W	= 1037,
    GotPrologue16	= 1038,
    HADD_S_D	= 1039,
    HADD_S_H	= 1040,
    HADD_S_W	= 1041,
    HADD_U_D	= 1042,
    HADD_U_H	= 1043,
    HADD_U_W	= 1044,
    HSUB_S_D	= 1045,
    HSUB_S_H	= 1046,
    HSUB_S_W	= 1047,
    HSUB_U_D	= 1048,
    HSUB_U_H	= 1049,
    HSUB_U_W	= 1050,
    ILVEV_B	= 1051,
    ILVEV_D	= 1052,
    ILVEV_H	= 1053,
    ILVEV_W	= 1054,
    ILVL_B	= 1055,
    ILVL_D	= 1056,
    ILVL_H	= 1057,
    ILVL_W	= 1058,
    ILVOD_B	= 1059,
    ILVOD_D	= 1060,
    ILVOD_H	= 1061,
    ILVOD_W	= 1062,
    ILVR_B	= 1063,
    ILVR_D	= 1064,
    ILVR_H	= 1065,
    ILVR_W	= 1066,
    INS	= 1067,
    INSERT_B	= 1068,
    INSERT_B_VIDX64_PSEUDO	= 1069,
    INSERT_B_VIDX_PSEUDO	= 1070,
    INSERT_D	= 1071,
    INSERT_D_VIDX64_PSEUDO	= 1072,
    INSERT_D_VIDX_PSEUDO	= 1073,
    INSERT_FD_PSEUDO	= 1074,
    INSERT_FD_VIDX64_PSEUDO	= 1075,
    INSERT_FD_VIDX_PSEUDO	= 1076,
    INSERT_FW_PSEUDO	= 1077,
    INSERT_FW_VIDX64_PSEUDO	= 1078,
    INSERT_FW_VIDX_PSEUDO	= 1079,
    INSERT_H	= 1080,
    INSERT_H_VIDX64_PSEUDO	= 1081,
    INSERT_H_VIDX_PSEUDO	= 1082,
    INSERT_W	= 1083,
    INSERT_W_VIDX64_PSEUDO	= 1084,
    INSERT_W_VIDX_PSEUDO	= 1085,
    INSV	= 1086,
    INSVE_B	= 1087,
    INSVE_D	= 1088,
    INSVE_H	= 1089,
    INSVE_W	= 1090,
    INSV_MM	= 1091,
    INS_MM	= 1092,
    J	= 1093,
    JAL	= 1094,
    JALR	= 1095,
    JALR16_MM	= 1096,
    JALR64	= 1097,
    JALR64Pseudo	= 1098,
    JALRC16_MMR6	= 1099,
    JALRPseudo	= 1100,
    JALRS16_MM	= 1101,
    JALRS_MM	= 1102,
    JALR_HB	= 1103,
    JALR_MM	= 1104,
    JALS_MM	= 1105,
    JALX	= 1106,
    JALX_MM	= 1107,
    JAL_MM	= 1108,
    JIALC	= 1109,
    JIALC_MMR6	= 1110,
    JIC	= 1111,
    JIC_MMR6	= 1112,
    JR	= 1113,
    JR16_MM	= 1114,
    JR64	= 1115,
    JRADDIUSP	= 1116,
    JRC16_MM	= 1117,
    JRC16_MMR6	= 1118,
    JRCADDIUSP_MMR6	= 1119,
    JR_HB	= 1120,
    JR_HB_R6	= 1121,
    JR_MM	= 1122,
    J_MM	= 1123,
    Jal16	= 1124,
    JalB16	= 1125,
    JalOneReg	= 1126,
    JalTwoReg	= 1127,
    JrRa16	= 1128,
    JrcRa16	= 1129,
    JrcRx16	= 1130,
    JumpLinkReg16	= 1131,
    LB	= 1132,
    LB64	= 1133,
    LBE	= 1134,
    LBE_MM	= 1135,
    LBE_MMR6	= 1136,
    LBU16_MM	= 1137,
    LBUE_MMR6	= 1138,
    LBUX	= 1139,
    LBUX_MM	= 1140,
    LBU_MMR6	= 1141,
    LB_MM	= 1142,
    LB_MMR6	= 1143,
    LBu	= 1144,
    LBu64	= 1145,
    LBuE	= 1146,
    LBuE_MM	= 1147,
    LBu_MM	= 1148,
    LD	= 1149,
    LDC1	= 1150,
    LDC164	= 1151,
    LDC1_MM	= 1152,
    LDC2	= 1153,
    LDC2_R6	= 1154,
    LDC3	= 1155,
    LDI_B	= 1156,
    LDI_D	= 1157,
    LDI_H	= 1158,
    LDI_W	= 1159,
    LDL	= 1160,
    LDPC	= 1161,
    LDR	= 1162,
    LDXC1	= 1163,
    LDXC164	= 1164,
    LD_B	= 1165,
    LD_D	= 1166,
    LD_H	= 1167,
    LD_W	= 1168,
    LEA_ADDiu	= 1169,
    LEA_ADDiu64	= 1170,
    LEA_ADDiu_MM	= 1171,
    LH	= 1172,
    LH64	= 1173,
    LHE	= 1174,
    LHE_MM	= 1175,
    LHU16_MM	= 1176,
    LHX	= 1177,
    LHX_MM	= 1178,
    LH_MM	= 1179,
    LHu	= 1180,
    LHu64	= 1181,
    LHuE	= 1182,
    LHuE_MM	= 1183,
    LHu_MM	= 1184,
    LI16_MM	= 1185,
    LI16_MMR6	= 1186,
    LL	= 1187,
    LLD	= 1188,
    LLD_R6	= 1189,
    LLE	= 1190,
    LLE_MM	= 1191,
    LLE_MMR6	= 1192,
    LL_MM	= 1193,
    LL_R6	= 1194,
    LOAD_ACC128	= 1195,
    LOAD_ACC64	= 1196,
    LOAD_ACC64DSP	= 1197,
    LOAD_CCOND_DSP	= 1198,
    LONG_BRANCH_ADDiu	= 1199,
    LONG_BRANCH_DADDiu	= 1200,
    LONG_BRANCH_LUi	= 1201,
    LSA	= 1202,
    LSA_MMR6	= 1203,
    LSA_R6	= 1204,
    LUI_MMR6	= 1205,
    LUXC1	= 1206,
    LUXC164	= 1207,
    LUXC1_MM	= 1208,
    LUi	= 1209,
    LUi64	= 1210,
    LUi_MM	= 1211,
    LW	= 1212,
    LW16_MM	= 1213,
    LW64	= 1214,
    LWC1	= 1215,
    LWC1_MM	= 1216,
    LWC2	= 1217,
    LWC2_R6	= 1218,
    LWC3	= 1219,
    LWE	= 1220,
    LWE_MM	= 1221,
    LWE_MMR6	= 1222,
    LWGP_MM	= 1223,
    LWL	= 1224,
    LWL64	= 1225,
    LWLE	= 1226,
    LWLE_MM	= 1227,
    LWL_MM	= 1228,
    LWM16_MM	= 1229,
    LWM16_MMR6	= 1230,
    LWM32_MM	= 1231,
    LWM_MM	= 1232,
    LWPC	= 1233,
    LWPC_MMR6	= 1234,
    LWP_MM	= 1235,
    LWR	= 1236,
    LWR64	= 1237,
    LWRE	= 1238,
    LWRE_MM	= 1239,
    LWR_MM	= 1240,
    LWSP_MM	= 1241,
    LWUPC	= 1242,
    LWU_MM	= 1243,
    LWX	= 1244,
    LWXC1	= 1245,
    LWXC1_MM	= 1246,
    LWXS_MM	= 1247,
    LWX_MM	= 1248,
    LW_MM	= 1249,
    LW_MMR6	= 1250,
    LWu	= 1251,
    LbRxRyOffMemX16	= 1252,
    LbuRxRyOffMemX16	= 1253,
    LhRxRyOffMemX16	= 1254,
    LhuRxRyOffMemX16	= 1255,
    LiRxImm16	= 1256,
    LiRxImmAlignX16	= 1257,
    LiRxImmX16	= 1258,
    LoadAddrImm32	= 1259,
    LoadAddrImm64	= 1260,
    LoadAddrReg32	= 1261,
    LoadAddrReg64	= 1262,
    LoadImm32	= 1263,
    LoadImm64	= 1264,
    LwConstant32	= 1265,
    LwRxPcTcp16	= 1266,
    LwRxPcTcpX16	= 1267,
    LwRxRyOffMemX16	= 1268,
    LwRxSpImmX16	= 1269,
    MADD	= 1270,
    MADDF_D	= 1271,
    MADDF_D_MMR6	= 1272,
    MADDF_S	= 1273,
    MADDF_S_MMR6	= 1274,
    MADDR_Q_H	= 1275,
    MADDR_Q_W	= 1276,
    MADDU	= 1277,
    MADDU_DSP	= 1278,
    MADDU_DSP_MM	= 1279,
    MADDU_MM	= 1280,
    MADDV_B	= 1281,
    MADDV_D	= 1282,
    MADDV_H	= 1283,
    MADDV_W	= 1284,
    MADD_D32	= 1285,
    MADD_D32_MM	= 1286,
    MADD_D64	= 1287,
    MADD_DSP	= 1288,
    MADD_DSP_MM	= 1289,
    MADD_MM	= 1290,
    MADD_Q_H	= 1291,
    MADD_Q_W	= 1292,
    MADD_S	= 1293,
    MADD_S_MM	= 1294,
    MAQ_SA_W_PHL	= 1295,
    MAQ_SA_W_PHL_MM	= 1296,
    MAQ_SA_W_PHR	= 1297,
    MAQ_SA_W_PHR_MM	= 1298,
    MAQ_S_W_PHL	= 1299,
    MAQ_S_W_PHL_MM	= 1300,
    MAQ_S_W_PHR	= 1301,
    MAQ_S_W_PHR_MM	= 1302,
    MAXA_D	= 1303,
    MAXA_D_MMR6	= 1304,
    MAXA_S	= 1305,
    MAXA_S_MMR6	= 1306,
    MAXI_S_B	= 1307,
    MAXI_S_D	= 1308,
    MAXI_S_H	= 1309,
    MAXI_S_W	= 1310,
    MAXI_U_B	= 1311,
    MAXI_U_D	= 1312,
    MAXI_U_H	= 1313,
    MAXI_U_W	= 1314,
    MAX_A_B	= 1315,
    MAX_A_D	= 1316,
    MAX_A_H	= 1317,
    MAX_A_W	= 1318,
    MAX_D	= 1319,
    MAX_D_MMR6	= 1320,
    MAX_S	= 1321,
    MAX_S_B	= 1322,
    MAX_S_D	= 1323,
    MAX_S_H	= 1324,
    MAX_S_MMR6	= 1325,
    MAX_S_W	= 1326,
    MAX_U_B	= 1327,
    MAX_U_D	= 1328,
    MAX_U_H	= 1329,
    MAX_U_W	= 1330,
    MFC0	= 1331,
    MFC1	= 1332,
    MFC1_MM	= 1333,
    MFC2	= 1334,
    MFHC1_D32	= 1335,
    MFHC1_D64	= 1336,
    MFHC1_MM	= 1337,
    MFHI	= 1338,
    MFHI16_MM	= 1339,
    MFHI64	= 1340,
    MFHI_DSP	= 1341,
    MFHI_DSP_MM	= 1342,
    MFHI_MM	= 1343,
    MFLO	= 1344,
    MFLO16_MM	= 1345,
    MFLO64	= 1346,
    MFLO_DSP	= 1347,
    MFLO_DSP_MM	= 1348,
    MFLO_MM	= 1349,
    MINA_D	= 1350,
    MINA_D_MMR6	= 1351,
    MINA_S	= 1352,
    MINA_S_MMR6	= 1353,
    MINI_S_B	= 1354,
    MINI_S_D	= 1355,
    MINI_S_H	= 1356,
    MINI_S_W	= 1357,
    MINI_U_B	= 1358,
    MINI_U_D	= 1359,
    MINI_U_H	= 1360,
    MINI_U_W	= 1361,
    MIN_A_B	= 1362,
    MIN_A_D	= 1363,
    MIN_A_H	= 1364,
    MIN_A_W	= 1365,
    MIN_D	= 1366,
    MIN_D_MMR6	= 1367,
    MIN_S	= 1368,
    MIN_S_B	= 1369,
    MIN_S_D	= 1370,
    MIN_S_H	= 1371,
    MIN_S_MMR6	= 1372,
    MIN_S_W	= 1373,
    MIN_U_B	= 1374,
    MIN_U_D	= 1375,
    MIN_U_H	= 1376,
    MIN_U_W	= 1377,
    MIPSeh_return32	= 1378,
    MIPSeh_return64	= 1379,
    MOD	= 1380,
    MODSUB	= 1381,
    MODU	= 1382,
    MODU_MMR6	= 1383,
    MOD_MMR6	= 1384,
    MOD_S_B	= 1385,
    MOD_S_D	= 1386,
    MOD_S_H	= 1387,
    MOD_S_W	= 1388,
    MOD_U_B	= 1389,
    MOD_U_D	= 1390,
    MOD_U_H	= 1391,
    MOD_U_W	= 1392,
    MOVE16_MM	= 1393,
    MOVE16_MMR6	= 1394,
    MOVEP_MM	= 1395,
    MOVE_V	= 1396,
    MOVF_D32	= 1397,
    MOVF_D32_MM	= 1398,
    MOVF_D64	= 1399,
    MOVF_I	= 1400,
    MOVF_I64	= 1401,
    MOVF_I_MM	= 1402,
    MOVF_S	= 1403,
    MOVF_S_MM	= 1404,
    MOVN_I64_D64	= 1405,
    MOVN_I64_I	= 1406,
    MOVN_I64_I64	= 1407,
    MOVN_I64_S	= 1408,
    MOVN_I_D32	= 1409,
    MOVN_I_D32_MM	= 1410,
    MOVN_I_D64	= 1411,
    MOVN_I_I	= 1412,
    MOVN_I_I64	= 1413,
    MOVN_I_MM	= 1414,
    MOVN_I_S	= 1415,
    MOVN_I_S_MM	= 1416,
    MOVT_D32	= 1417,
    MOVT_D32_MM	= 1418,
    MOVT_D64	= 1419,
    MOVT_I	= 1420,
    MOVT_I64	= 1421,
    MOVT_I_MM	= 1422,
    MOVT_S	= 1423,
    MOVT_S_MM	= 1424,
    MOVZ_I64_D64	= 1425,
    MOVZ_I64_I	= 1426,
    MOVZ_I64_I64	= 1427,
    MOVZ_I64_S	= 1428,
    MOVZ_I_D32	= 1429,
    MOVZ_I_D32_MM	= 1430,
    MOVZ_I_D64	= 1431,
    MOVZ_I_I	= 1432,
    MOVZ_I_I64	= 1433,
    MOVZ_I_MM	= 1434,
    MOVZ_I_S	= 1435,
    MOVZ_I_S_MM	= 1436,
    MSUB	= 1437,
    MSUBF_D	= 1438,
    MSUBF_D_MMR6	= 1439,
    MSUBF_S	= 1440,
    MSUBF_S_MMR6	= 1441,
    MSUBR_Q_H	= 1442,
    MSUBR_Q_W	= 1443,
    MSUBU	= 1444,
    MSUBU_DSP	= 1445,
    MSUBU_DSP_MM	= 1446,
    MSUBU_MM	= 1447,
    MSUBV_B	= 1448,
    MSUBV_D	= 1449,
    MSUBV_H	= 1450,
    MSUBV_W	= 1451,
    MSUB_D32	= 1452,
    MSUB_D32_MM	= 1453,
    MSUB_D64	= 1454,
    MSUB_DSP	= 1455,
    MSUB_DSP_MM	= 1456,
    MSUB_MM	= 1457,
    MSUB_Q_H	= 1458,
    MSUB_Q_W	= 1459,
    MSUB_S	= 1460,
    MSUB_S_MM	= 1461,
    MTC0	= 1462,
    MTC1	= 1463,
    MTC1_MM	= 1464,
    MTC2	= 1465,
    MTHC1_D32	= 1466,
    MTHC1_D64	= 1467,
    MTHC1_MM	= 1468,
    MTHI	= 1469,
    MTHI64	= 1470,
    MTHI_DSP	= 1471,
    MTHI_DSP_MM	= 1472,
    MTHI_MM	= 1473,
    MTHLIP	= 1474,
    MTHLIP_MM	= 1475,
    MTLO	= 1476,
    MTLO64	= 1477,
    MTLO_DSP	= 1478,
    MTLO_DSP_MM	= 1479,
    MTLO_MM	= 1480,
    MTM0	= 1481,
    MTM1	= 1482,
    MTM2	= 1483,
    MTP0	= 1484,
    MTP1	= 1485,
    MTP2	= 1486,
    MUH	= 1487,
    MUHU	= 1488,
    MUHU_MMR6	= 1489,
    MUH_MMR6	= 1490,
    MUL	= 1491,
    MULEQ_S_W_PHL	= 1492,
    MULEQ_S_W_PHL_MM	= 1493,
    MULEQ_S_W_PHR	= 1494,
    MULEQ_S_W_PHR_MM	= 1495,
    MULEU_S_PH_QBL	= 1496,
    MULEU_S_PH_QBL_MM	= 1497,
    MULEU_S_PH_QBR	= 1498,
    MULEU_S_PH_QBR_MM	= 1499,
    MULQ_RS_PH	= 1500,
    MULQ_RS_PH_MM	= 1501,
    MULQ_RS_W	= 1502,
    MULQ_RS_W_MMR2	= 1503,
    MULQ_S_PH	= 1504,
    MULQ_S_PH_MMR2	= 1505,
    MULQ_S_W	= 1506,
    MULQ_S_W_MMR2	= 1507,
    MULR_Q_H	= 1508,
    MULR_Q_W	= 1509,
    MULSAQ_S_W_PH	= 1510,
    MULSA_W_PH	= 1511,
    MULT	= 1512,
    MULTU_DSP	= 1513,
    MULTU_DSP_MM	= 1514,
    MULT_DSP	= 1515,
    MULT_DSP_MM	= 1516,
    MULT_MM	= 1517,
    MULTu	= 1518,
    MULTu_MM	= 1519,
    MULU	= 1520,
    MULU_MMR6	= 1521,
    MULV_B	= 1522,
    MULV_D	= 1523,
    MULV_H	= 1524,
    MULV_W	= 1525,
    MUL_MM	= 1526,
    MUL_MMR6	= 1527,
    MUL_PH	= 1528,
    MUL_PH_MMR2	= 1529,
    MUL_Q_H	= 1530,
    MUL_Q_W	= 1531,
    MUL_R6	= 1532,
    MUL_S_PH	= 1533,
    MUL_S_PH_MMR2	= 1534,
    Mfhi16	= 1535,
    Mflo16	= 1536,
    Move32R16	= 1537,
    MoveR3216	= 1538,
    MultRxRy16	= 1539,
    MultRxRyRz16	= 1540,
    MultuRxRy16	= 1541,
    MultuRxRyRz16	= 1542,
    NLOC_B	= 1543,
    NLOC_D	= 1544,
    NLOC_H	= 1545,
    NLOC_W	= 1546,
    NLZC_B	= 1547,
    NLZC_D	= 1548,
    NLZC_H	= 1549,
    NLZC_W	= 1550,
    NMADD_D32	= 1551,
    NMADD_D32_MM	= 1552,
    NMADD_D64	= 1553,
    NMADD_S	= 1554,
    NMADD_S_MM	= 1555,
    NMSUB_D32	= 1556,
    NMSUB_D32_MM	= 1557,
    NMSUB_D64	= 1558,
    NMSUB_S	= 1559,
    NMSUB_S_MM	= 1560,
    NOP	= 1561,
    NOR	= 1562,
    NOR64	= 1563,
    NORI_B	= 1564,
    NORImm	= 1565,
    NOR_MM	= 1566,
    NOR_MMR6	= 1567,
    NOR_V	= 1568,
    NOR_V_D_PSEUDO	= 1569,
    NOR_V_H_PSEUDO	= 1570,
    NOR_V_W_PSEUDO	= 1571,
    NOT16_MM	= 1572,
    NOT16_MMR6	= 1573,
    NegRxRy16	= 1574,
    NotRxRy16	= 1575,
    OR	= 1576,
    OR16_MM	= 1577,
    OR16_MMR6	= 1578,
    OR64	= 1579,
    ORI_B	= 1580,
    ORI_MMR6	= 1581,
    OR_MM	= 1582,
    OR_MMR6	= 1583,
    OR_V	= 1584,
    OR_V_D_PSEUDO	= 1585,
    OR_V_H_PSEUDO	= 1586,
    OR_V_W_PSEUDO	= 1587,
    ORi	= 1588,
    ORi64	= 1589,
    ORi_MM	= 1590,
    OrRxRxRy16	= 1591,
    PACKRL_PH	= 1592,
    PACKRL_PH_MM	= 1593,
    PAUSE	= 1594,
    PAUSE_MM	= 1595,
    PAUSE_MMR6	= 1596,
    PCKEV_B	= 1597,
    PCKEV_D	= 1598,
    PCKEV_H	= 1599,
    PCKEV_W	= 1600,
    PCKOD_B	= 1601,
    PCKOD_D	= 1602,
    PCKOD_H	= 1603,
    PCKOD_W	= 1604,
    PCNT_B	= 1605,
    PCNT_D	= 1606,
    PCNT_H	= 1607,
    PCNT_W	= 1608,
    PICK_PH	= 1609,
    PICK_PH_MM	= 1610,
    PICK_QB	= 1611,
    PICK_QB_MM	= 1612,
    POP	= 1613,
    PRECEQU_PH_QBL	= 1614,
    PRECEQU_PH_QBLA	= 1615,
    PRECEQU_PH_QBLA_MM	= 1616,
    PRECEQU_PH_QBL_MM	= 1617,
    PRECEQU_PH_QBR	= 1618,
    PRECEQU_PH_QBRA	= 1619,
    PRECEQU_PH_QBRA_MM	= 1620,
    PRECEQU_PH_QBR_MM	= 1621,
    PRECEQ_W_PHL	= 1622,
    PRECEQ_W_PHL_MM	= 1623,
    PRECEQ_W_PHR	= 1624,
    PRECEQ_W_PHR_MM	= 1625,
    PRECEU_PH_QBL	= 1626,
    PRECEU_PH_QBLA	= 1627,
    PRECEU_PH_QBLA_MM	= 1628,
    PRECEU_PH_QBL_MM	= 1629,
    PRECEU_PH_QBR	= 1630,
    PRECEU_PH_QBRA	= 1631,
    PRECEU_PH_QBRA_MM	= 1632,
    PRECEU_PH_QBR_MM	= 1633,
    PRECRQU_S_QB_PH	= 1634,
    PRECRQU_S_QB_PH_MM	= 1635,
    PRECRQ_PH_W	= 1636,
    PRECRQ_PH_W_MM	= 1637,
    PRECRQ_QB_PH	= 1638,
    PRECRQ_QB_PH_MM	= 1639,
    PRECRQ_RS_PH_W	= 1640,
    PRECRQ_RS_PH_W_MM	= 1641,
    PRECR_QB_PH	= 1642,
    PRECR_QB_PH_MMR2	= 1643,
    PRECR_SRA_PH_W	= 1644,
    PRECR_SRA_PH_W_MMR2	= 1645,
    PRECR_SRA_R_PH_W	= 1646,
    PRECR_SRA_R_PH_W_MMR2	= 1647,
    PREF	= 1648,
    PREFE	= 1649,
    PREFE_MM	= 1650,
    PREFE_MMR6	= 1651,
    PREFX_MM	= 1652,
    PREF_MM	= 1653,
    PREF_MMR6	= 1654,
    PREF_R6	= 1655,
    PREPEND	= 1656,
    PREPEND_MMR2	= 1657,
    PseudoCMPU_EQ_QB	= 1658,
    PseudoCMPU_LE_QB	= 1659,
    PseudoCMPU_LT_QB	= 1660,
    PseudoCMP_EQ_PH	= 1661,
    PseudoCMP_LE_PH	= 1662,
    PseudoCMP_LT_PH	= 1663,
    PseudoCVT_D32_W	= 1664,
    PseudoCVT_D64_L	= 1665,
    PseudoCVT_D64_W	= 1666,
    PseudoCVT_S_L	= 1667,
    PseudoCVT_S_W	= 1668,
    PseudoDMULT	= 1669,
    PseudoDMULTu	= 1670,
    PseudoDSDIV	= 1671,
    PseudoDUDIV	= 1672,
    PseudoIndirectBranch	= 1673,
    PseudoIndirectBranch64	= 1674,
    PseudoMADD	= 1675,
    PseudoMADDU	= 1676,
    PseudoMFHI	= 1677,
    PseudoMFHI64	= 1678,
    PseudoMFLO	= 1679,
    PseudoMFLO64	= 1680,
    PseudoMSUB	= 1681,
    PseudoMSUBU	= 1682,
    PseudoMTLOHI	= 1683,
    PseudoMTLOHI64	= 1684,
    PseudoMTLOHI_DSP	= 1685,
    PseudoMULT	= 1686,
    PseudoMULTu	= 1687,
    PseudoPICK_PH	= 1688,
    PseudoPICK_QB	= 1689,
    PseudoReturn	= 1690,
    PseudoReturn64	= 1691,
    PseudoSDIV	= 1692,
    PseudoSELECTFP_F_D32	= 1693,
    PseudoSELECTFP_F_D64	= 1694,
    PseudoSELECTFP_F_I	= 1695,
    PseudoSELECTFP_F_I64	= 1696,
    PseudoSELECTFP_F_S	= 1697,
    PseudoSELECTFP_T_D32	= 1698,
    PseudoSELECTFP_T_D64	= 1699,
    PseudoSELECTFP_T_I	= 1700,
    PseudoSELECTFP_T_I64	= 1701,
    PseudoSELECTFP_T_S	= 1702,
    PseudoSELECT_D32	= 1703,
    PseudoSELECT_D64	= 1704,
    PseudoSELECT_I	= 1705,
    PseudoSELECT_I64	= 1706,
    PseudoSELECT_S	= 1707,
    PseudoUDIV	= 1708,
    RADDU_W_QB	= 1709,
    RADDU_W_QB_MM	= 1710,
    RDDSP	= 1711,
    RDDSP_MM	= 1712,
    RDHWR	= 1713,
    RDHWR64	= 1714,
    RDHWR_MM	= 1715,
    RDHWR_MMR6	= 1716,
    RDPGPR_MMR6	= 1717,
    RECIP_D_MMR6	= 1718,
    RECIP_S_MMR6	= 1719,
    REPLV_PH	= 1720,
    REPLV_PH_MM	= 1721,
    REPLV_QB	= 1722,
    REPLV_QB_MM	= 1723,
    REPL_PH	= 1724,
    REPL_PH_MM	= 1725,
    REPL_QB	= 1726,
    REPL_QB_MM	= 1727,
    RINT_D	= 1728,
    RINT_D_MMR6	= 1729,
    RINT_S	= 1730,
    RINT_S_MMR6	= 1731,
    ROL	= 1732,
    ROLImm	= 1733,
    ROR	= 1734,
    RORImm	= 1735,
    ROTR	= 1736,
    ROTRV	= 1737,
    ROTRV_MM	= 1738,
    ROTR_MM	= 1739,
    ROUND_L_D64	= 1740,
    ROUND_L_D_MMR6	= 1741,
    ROUND_L_S	= 1742,
    ROUND_L_S_MMR6	= 1743,
    ROUND_W_D32	= 1744,
    ROUND_W_D64	= 1745,
    ROUND_W_D_MMR6	= 1746,
    ROUND_W_MM	= 1747,
    ROUND_W_S	= 1748,
    ROUND_W_S_MM	= 1749,
    ROUND_W_S_MMR6	= 1750,
    RSQRT_D_MMR6	= 1751,
    RSQRT_S_MMR6	= 1752,
    Restore16	= 1753,
    RestoreX16	= 1754,
    RetRA	= 1755,
    RetRA16	= 1756,
    SAT_S_B	= 1757,
    SAT_S_D	= 1758,
    SAT_S_H	= 1759,
    SAT_S_W	= 1760,
    SAT_U_B	= 1761,
    SAT_U_D	= 1762,
    SAT_U_H	= 1763,
    SAT_U_W	= 1764,
    SB	= 1765,
    SB16_MM	= 1766,
    SB16_MMR6	= 1767,
    SB64	= 1768,
    SBE	= 1769,
    SBE_MM	= 1770,
    SBE_MMR6	= 1771,
    SB_MM	= 1772,
    SB_MMR6	= 1773,
    SC	= 1774,
    SCD	= 1775,
    SCD_R6	= 1776,
    SCE	= 1777,
    SCE_MM	= 1778,
    SCE_MMR6	= 1779,
    SC_MM	= 1780,
    SC_R6	= 1781,
    SD	= 1782,
    SDBBP	= 1783,
    SDBBP16_MM	= 1784,
    SDBBP16_MMR6	= 1785,
    SDBBP_MM	= 1786,
    SDBBP_MMR6	= 1787,
    SDBBP_R6	= 1788,
    SDC1	= 1789,
    SDC164	= 1790,
    SDC1_MM	= 1791,
    SDC2	= 1792,
    SDC2_R6	= 1793,
    SDC3	= 1794,
    SDIV	= 1795,
    SDIV_MM	= 1796,
    SDL	= 1797,
    SDR	= 1798,
    SDXC1	= 1799,
    SDXC164	= 1800,
    SDivMacro	= 1801,
    SEB	= 1802,
    SEB64	= 1803,
    SEB_MM	= 1804,
    SEB_MMR6	= 1805,
    SEH	= 1806,
    SEH64	= 1807,
    SEH_MM	= 1808,
    SEH_MMR6	= 1809,
    SELENZ_D_MMR6	= 1810,
    SELENZ_S_MMR6	= 1811,
    SELEQZ	= 1812,
    SELEQZ64	= 1813,
    SELEQZ_D	= 1814,
    SELEQZ_D_MMR6	= 1815,
    SELEQZ_MMR6	= 1816,
    SELEQZ_S	= 1817,
    SELEQZ_S_MMR6	= 1818,
    SELNEZ	= 1819,
    SELNEZ64	= 1820,
    SELNEZ_D	= 1821,
    SELNEZ_MMR6	= 1822,
    SELNEZ_S	= 1823,
    SEL_D	= 1824,
    SEL_D_MMR6	= 1825,
    SEL_S	= 1826,
    SEL_S_MMR6	= 1827,
    SEQ	= 1828,
    SEQi	= 1829,
    SH	= 1830,
    SH16_MM	= 1831,
    SH16_MMR6	= 1832,
    SH64	= 1833,
    SHE	= 1834,
    SHE_MM	= 1835,
    SHE_MMR6	= 1836,
    SHF_B	= 1837,
    SHF_H	= 1838,
    SHF_W	= 1839,
    SHILO	= 1840,
    SHILOV	= 1841,
    SHILOV_MM	= 1842,
    SHILO_MM	= 1843,
    SHLLV_PH	= 1844,
    SHLLV_PH_MM	= 1845,
    SHLLV_QB	= 1846,
    SHLLV_QB_MM	= 1847,
    SHLLV_S_PH	= 1848,
    SHLLV_S_PH_MM	= 1849,
    SHLLV_S_W	= 1850,
    SHLLV_S_W_MM	= 1851,
    SHLL_PH	= 1852,
    SHLL_PH_MM	= 1853,
    SHLL_QB	= 1854,
    SHLL_QB_MM	= 1855,
    SHLL_S_PH	= 1856,
    SHLL_S_PH_MM	= 1857,
    SHLL_S_W	= 1858,
    SHLL_S_W_MM	= 1859,
    SHRAV_PH	= 1860,
    SHRAV_PH_MM	= 1861,
    SHRAV_QB	= 1862,
    SHRAV_QB_MMR2	= 1863,
    SHRAV_R_PH	= 1864,
    SHRAV_R_PH_MM	= 1865,
    SHRAV_R_QB	= 1866,
    SHRAV_R_QB_MMR2	= 1867,
    SHRAV_R_W	= 1868,
    SHRAV_R_W_MM	= 1869,
    SHRA_PH	= 1870,
    SHRA_PH_MM	= 1871,
    SHRA_QB	= 1872,
    SHRA_QB_MMR2	= 1873,
    SHRA_R_PH	= 1874,
    SHRA_R_PH_MM	= 1875,
    SHRA_R_QB	= 1876,
    SHRA_R_QB_MMR2	= 1877,
    SHRA_R_W	= 1878,
    SHRA_R_W_MM	= 1879,
    SHRLV_PH	= 1880,
    SHRLV_PH_MMR2	= 1881,
    SHRLV_QB	= 1882,
    SHRLV_QB_MM	= 1883,
    SHRL_PH	= 1884,
    SHRL_PH_MMR2	= 1885,
    SHRL_QB	= 1886,
    SHRL_QB_MM	= 1887,
    SH_MM	= 1888,
    SH_MMR6	= 1889,
    SLDI_B	= 1890,
    SLDI_D	= 1891,
    SLDI_H	= 1892,
    SLDI_W	= 1893,
    SLD_B	= 1894,
    SLD_D	= 1895,
    SLD_H	= 1896,
    SLD_W	= 1897,
    SLL	= 1898,
    SLL16_MM	= 1899,
    SLL16_MMR6	= 1900,
    SLL64_32	= 1901,
    SLL64_64	= 1902,
    SLLI_B	= 1903,
    SLLI_D	= 1904,
    SLLI_H	= 1905,
    SLLI_W	= 1906,
    SLLV	= 1907,
    SLLV_MM	= 1908,
    SLL_B	= 1909,
    SLL_D	= 1910,
    SLL_H	= 1911,
    SLL_MM	= 1912,
    SLL_MMR6	= 1913,
    SLL_W	= 1914,
    SLT	= 1915,
    SLT64	= 1916,
    SLT_MM	= 1917,
    SLTi	= 1918,
    SLTi64	= 1919,
    SLTi_MM	= 1920,
    SLTiu	= 1921,
    SLTiu64	= 1922,
    SLTiu_MM	= 1923,
    SLTu	= 1924,
    SLTu64	= 1925,
    SLTu_MM	= 1926,
    SNE	= 1927,
    SNEi	= 1928,
    SNZ_B_PSEUDO	= 1929,
    SNZ_D_PSEUDO	= 1930,
    SNZ_H_PSEUDO	= 1931,
    SNZ_V_PSEUDO	= 1932,
    SNZ_W_PSEUDO	= 1933,
    SPLATI_B	= 1934,
    SPLATI_D	= 1935,
    SPLATI_H	= 1936,
    SPLATI_W	= 1937,
    SPLAT_B	= 1938,
    SPLAT_D	= 1939,
    SPLAT_H	= 1940,
    SPLAT_W	= 1941,
    SQRT_D_MMR6	= 1942,
    SQRT_S_MMR6	= 1943,
    SRA	= 1944,
    SRAI_B	= 1945,
    SRAI_D	= 1946,
    SRAI_H	= 1947,
    SRAI_W	= 1948,
    SRARI_B	= 1949,
    SRARI_D	= 1950,
    SRARI_H	= 1951,
    SRARI_W	= 1952,
    SRAR_B	= 1953,
    SRAR_D	= 1954,
    SRAR_H	= 1955,
    SRAR_W	= 1956,
    SRAV	= 1957,
    SRAV_MM	= 1958,
    SRA_B	= 1959,
    SRA_D	= 1960,
    SRA_H	= 1961,
    SRA_MM	= 1962,
    SRA_W	= 1963,
    SRL	= 1964,
    SRL16_MM	= 1965,
    SRL16_MMR6	= 1966,
    SRLI_B	= 1967,
    SRLI_D	= 1968,
    SRLI_H	= 1969,
    SRLI_W	= 1970,
    SRLRI_B	= 1971,
    SRLRI_D	= 1972,
    SRLRI_H	= 1973,
    SRLRI_W	= 1974,
    SRLR_B	= 1975,
    SRLR_D	= 1976,
    SRLR_H	= 1977,
    SRLR_W	= 1978,
    SRLV	= 1979,
    SRLV_MM	= 1980,
    SRL_B	= 1981,
    SRL_D	= 1982,
    SRL_H	= 1983,
    SRL_MM	= 1984,
    SRL_W	= 1985,
    SSNOP	= 1986,
    SSNOP_MM	= 1987,
    SSNOP_MMR6	= 1988,
    STORE_ACC128	= 1989,
    STORE_ACC64	= 1990,
    STORE_ACC64DSP	= 1991,
    STORE_CCOND_DSP	= 1992,
    ST_B	= 1993,
    ST_D	= 1994,
    ST_H	= 1995,
    ST_W	= 1996,
    SUB	= 1997,
    SUBQH_PH	= 1998,
    SUBQH_PH_MMR2	= 1999,
    SUBQH_R_PH	= 2000,
    SUBQH_R_PH_MMR2	= 2001,
    SUBQH_R_W	= 2002,
    SUBQH_R_W_MMR2	= 2003,
    SUBQH_W	= 2004,
    SUBQH_W_MMR2	= 2005,
    SUBQ_PH	= 2006,
    SUBQ_PH_MM	= 2007,
    SUBQ_S_PH	= 2008,
    SUBQ_S_PH_MM	= 2009,
    SUBQ_S_W	= 2010,
    SUBQ_S_W_MM	= 2011,
    SUBSUS_U_B	= 2012,
    SUBSUS_U_D	= 2013,
    SUBSUS_U_H	= 2014,
    SUBSUS_U_W	= 2015,
    SUBSUU_S_B	= 2016,
    SUBSUU_S_D	= 2017,
    SUBSUU_S_H	= 2018,
    SUBSUU_S_W	= 2019,
    SUBS_S_B	= 2020,
    SUBS_S_D	= 2021,
    SUBS_S_H	= 2022,
    SUBS_S_W	= 2023,
    SUBS_U_B	= 2024,
    SUBS_U_D	= 2025,
    SUBS_U_H	= 2026,
    SUBS_U_W	= 2027,
    SUBU16_MM	= 2028,
    SUBU16_MMR6	= 2029,
    SUBUH_QB	= 2030,
    SUBUH_QB_MMR2	= 2031,
    SUBUH_R_QB	= 2032,
    SUBUH_R_QB_MMR2	= 2033,
    SUBU_MMR6	= 2034,
    SUBU_PH	= 2035,
    SUBU_PH_MMR2	= 2036,
    SUBU_QB	= 2037,
    SUBU_QB_MM	= 2038,
    SUBU_S_PH	= 2039,
    SUBU_S_PH_MMR2	= 2040,
    SUBU_S_QB	= 2041,
    SUBU_S_QB_MM	= 2042,
    SUBVI_B	= 2043,
    SUBVI_D	= 2044,
    SUBVI_H	= 2045,
    SUBVI_W	= 2046,
    SUBV_B	= 2047,
    SUBV_D	= 2048,
    SUBV_H	= 2049,
    SUBV_W	= 2050,
    SUB_MM	= 2051,
    SUB_MMR6	= 2052,
    SUBu	= 2053,
    SUBu_MM	= 2054,
    SUXC1	= 2055,
    SUXC164	= 2056,
    SUXC1_MM	= 2057,
    SW	= 2058,
    SW16_MM	= 2059,
    SW16_MMR6	= 2060,
    SW64	= 2061,
    SWC1	= 2062,
    SWC1_MM	= 2063,
    SWC2	= 2064,
    SWC2_R6	= 2065,
    SWC3	= 2066,
    SWE	= 2067,
    SWE_MM	= 2068,
    SWE_MMR6	= 2069,
    SWL	= 2070,
    SWL64	= 2071,
    SWLE	= 2072,
    SWLE_MM	= 2073,
    SWL_MM	= 2074,
    SWM16_MM	= 2075,
    SWM16_MMR6	= 2076,
    SWM32_MM	= 2077,
    SWM_MM	= 2078,
    SWP_MM	= 2079,
    SWR	= 2080,
    SWR64	= 2081,
    SWRE	= 2082,
    SWRE_MM	= 2083,
    SWR_MM	= 2084,
    SWSP_MM	= 2085,
    SWSP_MMR6	= 2086,
    SWXC1	= 2087,
    SWXC1_MM	= 2088,
    SW_MM	= 2089,
    SW_MMR6	= 2090,
    SYNC	= 2091,
    SYNCI	= 2092,
    SYNCI_MMR6	= 2093,
    SYNC_MM	= 2094,
    SYNC_MMR6	= 2095,
    SYSCALL	= 2096,
    SYSCALL_MM	= 2097,
    SZ_B_PSEUDO	= 2098,
    SZ_D_PSEUDO	= 2099,
    SZ_H_PSEUDO	= 2100,
    SZ_V_PSEUDO	= 2101,
    SZ_W_PSEUDO	= 2102,
    Save16	= 2103,
    SaveX16	= 2104,
    SbRxRyOffMemX16	= 2105,
    SebRx16	= 2106,
    SehRx16	= 2107,
    SelBeqZ	= 2108,
    SelBneZ	= 2109,
    SelTBteqZCmp	= 2110,
    SelTBteqZCmpi	= 2111,
    SelTBteqZSlt	= 2112,
    SelTBteqZSlti	= 2113,
    SelTBteqZSltiu	= 2114,
    SelTBteqZSltu	= 2115,
    SelTBtneZCmp	= 2116,
    SelTBtneZCmpi	= 2117,
    SelTBtneZSlt	= 2118,
    SelTBtneZSlti	= 2119,
    SelTBtneZSltiu	= 2120,
    SelTBtneZSltu	= 2121,
    ShRxRyOffMemX16	= 2122,
    SllX16	= 2123,
    SllvRxRy16	= 2124,
    SltCCRxRy16	= 2125,
    SltRxRy16	= 2126,
    SltiCCRxImmX16	= 2127,
    SltiRxImm16	= 2128,
    SltiRxImmX16	= 2129,
    SltiuCCRxImmX16	= 2130,
    SltiuRxImm16	= 2131,
    SltiuRxImmX16	= 2132,
    SltuCCRxRy16	= 2133,
    SltuRxRy16	= 2134,
    SltuRxRyRz16	= 2135,
    SraX16	= 2136,
    SravRxRy16	= 2137,
    SrlX16	= 2138,
    SrlvRxRy16	= 2139,
    SubuRxRyRz16	= 2140,
    SwRxRyOffMemX16	= 2141,
    SwRxSpImmX16	= 2142,
    TAILCALL	= 2143,
    TAILCALL64_R	= 2144,
    TAILCALL_R	= 2145,
    TEQ	= 2146,
    TEQI	= 2147,
    TEQI_MM	= 2148,
    TEQ_MM	= 2149,
    TGE	= 2150,
    TGEI	= 2151,
    TGEIU	= 2152,
    TGEIU_MM	= 2153,
    TGEI_MM	= 2154,
    TGEU	= 2155,
    TGEU_MM	= 2156,
    TGE_MM	= 2157,
    TLBINV	= 2158,
    TLBINVF	= 2159,
    TLBP	= 2160,
    TLBP_MM	= 2161,
    TLBR	= 2162,
    TLBR_MM	= 2163,
    TLBWI	= 2164,
    TLBWI_MM	= 2165,
    TLBWR	= 2166,
    TLBWR_MM	= 2167,
    TLT	= 2168,
    TLTI	= 2169,
    TLTIU_MM	= 2170,
    TLTI_MM	= 2171,
    TLTU	= 2172,
    TLTU_MM	= 2173,
    TLT_MM	= 2174,
    TNE	= 2175,
    TNEI	= 2176,
    TNEI_MM	= 2177,
    TNE_MM	= 2178,
    TRAP	= 2179,
    TRUNC_L_D64	= 2180,
    TRUNC_L_D_MMR6	= 2181,
    TRUNC_L_S	= 2182,
    TRUNC_L_S_MMR6	= 2183,
    TRUNC_W_D32	= 2184,
    TRUNC_W_D64	= 2185,
    TRUNC_W_D_MMR6	= 2186,
    TRUNC_W_MM	= 2187,
    TRUNC_W_S	= 2188,
    TRUNC_W_S_MM	= 2189,
    TRUNC_W_S_MMR6	= 2190,
    TTLTIU	= 2191,
    UDIV	= 2192,
    UDIV_MM	= 2193,
    UDivMacro	= 2194,
    Ulh	= 2195,
    Ulhu	= 2196,
    Ulw	= 2197,
    V3MULU	= 2198,
    VMM0	= 2199,
    VMULU	= 2200,
    VSHF_B	= 2201,
    VSHF_D	= 2202,
    VSHF_H	= 2203,
    VSHF_W	= 2204,
    WAIT	= 2205,
    WAIT_MM	= 2206,
    WAIT_MMR6	= 2207,
    WRDSP	= 2208,
    WRDSP_MM	= 2209,
    WRPGPR_MMR6	= 2210,
    WSBH	= 2211,
    WSBH_MM	= 2212,
    WSBH_MMR6	= 2213,
    XOR	= 2214,
    XOR16_MM	= 2215,
    XOR16_MMR6	= 2216,
    XOR64	= 2217,
    XORI_B	= 2218,
    XORI_MMR6	= 2219,
    XOR_MM	= 2220,
    XOR_MMR6	= 2221,
    XOR_V	= 2222,
    XOR_V_D_PSEUDO	= 2223,
    XOR_V_H_PSEUDO	= 2224,
    XOR_V_W_PSEUDO	= 2225,
    XORi	= 2226,
    XORi64	= 2227,
    XORi_MM	= 2228,
    XorRxRxRy16	= 2229,
    INSTRUCTION_LIST_END = 2230
  };

namespace Sched {
  enum {
    NoInstrModel	= 0,
    IIPseudo	= 1,
    II_ABS	= 2,
    II_ADDU	= 3,
    II_ADDIU	= 4,
    II_AND	= 5,
    II_ANDI	= 6,
    IIM16Alu	= 7,
    II_B	= 8,
    II_BADDU	= 9,
    II_BCCZAL	= 10,
    II_BBIT	= 11,
    II_BC	= 12,
    II_BC1F	= 13,
    II_BC1FL	= 14,
    II_BC1T	= 15,
    II_BC1TL	= 16,
    II_BCC	= 17,
    II_BCCZ	= 18,
    II_BCCZC	= 19,
    II_BCCZALS	= 20,
    II_CEIL	= 21,
    II_CFC1	= 22,
    II_CLO	= 23,
    II_CLZ	= 24,
    II_CTC1	= 25,
    II_CVT	= 26,
    II_C_CC_D	= 27,
    II_C_CC_S	= 28,
    II_DADD	= 29,
    II_DADDIU	= 30,
    II_DADDU	= 31,
    II_EXT	= 32,
    II_INS	= 33,
    II_DMFC1	= 34,
    II_DMTC1	= 35,
    II_DMUL	= 36,
    II_DMULT	= 37,
    II_DMULTU	= 38,
    II_POP	= 39,
    II_DROTR	= 40,
    II_DROTR32	= 41,
    II_DROTRV	= 42,
    II_DDIV	= 43,
    II_DSLL	= 44,
    II_DSLL32	= 45,
    II_DSLLV	= 46,
    II_DSRA	= 47,
    II_DSRA32	= 48,
    II_DSRAV	= 49,
    II_DSRL	= 50,
    II_DSRL32	= 51,
    II_DSRLV	= 52,
    II_DSUB	= 53,
    II_DSUBU	= 54,
    II_DDIVU	= 55,
    II_ADD_D	= 56,
    II_ADD_S	= 57,
    II_DIV_D	= 58,
    II_DIV_S	= 59,
    II_FLOOR	= 60,
    II_MOV_D	= 61,
    II_MOV_S	= 62,
    II_MUL_D	= 63,
    II_MUL_S	= 64,
    II_NEG	= 65,
    II_SQRT_D	= 66,
    II_SQRT_S	= 67,
    II_SUB_D	= 68,
    II_SUB_S	= 69,
    II_J	= 70,
    II_JAL	= 71,
    II_JALR	= 72,
    II_JALRS	= 73,
    II_JALS	= 74,
    II_JR	= 75,
    II_JRADDIUSP	= 76,
    II_JRC	= 77,
    II_JALRC	= 78,
    II_LB	= 79,
    II_LBU	= 80,
    II_LD	= 81,
    II_LDC1	= 82,
    II_LDL	= 83,
    II_LDR	= 84,
    II_LDXC1	= 85,
    II_LH	= 86,
    II_LHU	= 87,
    II_LUI	= 88,
    II_LUXC1	= 89,
    II_LW	= 90,
    II_LWC1	= 91,
    II_LWL	= 92,
    II_LWR	= 93,
    II_LWU	= 94,
    II_LWXC1	= 95,
    II_MADD	= 96,
    II_MADDU	= 97,
    II_MADD_D	= 98,
    II_MADD_S	= 99,
    II_MFC1	= 100,
    II_MFHC1	= 101,
    II_MFHI_MFLO	= 102,
    II_MOVF_D	= 103,
    II_MOVF	= 104,
    II_MOVF_S	= 105,
    II_MOVN_D	= 106,
    II_MOVN	= 107,
    II_MOVN_S	= 108,
    II_MOVT_D	= 109,
    II_MOVT	= 110,
    II_MOVT_S	= 111,
    II_MOVZ_D	= 112,
    II_MOVZ	= 113,
    II_MOVZ_S	= 114,
    II_MSUB	= 115,
    II_MSUBU	= 116,
    II_MSUB_D	= 117,
    II_MSUB_S	= 118,
    II_MTC1	= 119,
    II_MTHC1	= 120,
    II_MTHI_MTLO	= 121,
    II_MUL	= 122,
    II_MULT	= 123,
    II_MULTU	= 124,
    II_NMADD_D	= 125,
    II_NMADD_S	= 126,
    II_NMSUB_D	= 127,
    II_NMSUB_S	= 128,
    II_NOR	= 129,
    II_OR	= 130,
    II_ORI	= 131,
    II_IndirectBranchPseudo	= 132,
    II_ReturnPseudo	= 133,
    II_DIV	= 134,
    II_DIVU	= 135,
    II_RDHWR	= 136,
    II_ROUND	= 137,
    II_ROTR	= 138,
    II_ROTRV	= 139,
    II_TRUNC	= 140,
    II_RESTORE	= 141,
    II_SB	= 142,
    II_SD	= 143,
    II_SDC1	= 144,
    II_SDL	= 145,
    II_SDR	= 146,
    II_SDXC1	= 147,
    II_SEB	= 148,
    II_SEH	= 149,
    II_SEQ_SNE	= 150,
    II_SEQI_SNEI	= 151,
    II_SH	= 152,
    II_SLL	= 153,
    II_SLLV	= 154,
    II_SLT_SLTU	= 155,
    II_SLTI_SLTIU	= 156,
    II_SRA	= 157,
    II_SRAV	= 158,
    II_SRL	= 159,
    II_SRLV	= 160,
    II_SUBU	= 161,
    II_SUXC1	= 162,
    II_SW	= 163,
    II_SWC1	= 164,
    II_SWL	= 165,
    II_SWR	= 166,
    II_SWXC1	= 167,
    II_SAVE	= 168,
    II_WSBH	= 169,
    II_XOR	= 170,
    II_XORI	= 171,
    ADD_A_B_ADD_A_D_ADD_A_H_ADD_A_W	= 172,
    ADDS_A_B_ADDS_A_D_ADDS_A_H_ADDS_A_W_ADDS_S_B_ADDS_S_D_ADDS_S_H_ADDS_S_W_ADDS_U_B_ADDS_U_D_ADDS_U_H_ADDS_U_W	= 173,
    ADDVI_B_ADDVI_D_ADDVI_H_ADDVI_W_ADDV_B_ADDV_D_ADDV_H_ADDV_W	= 174,
    ASUB_S_B_ASUB_S_D_ASUB_S_H_ASUB_S_W_ASUB_U_B_ASUB_U_D_ASUB_U_H_ASUB_U_W	= 175,
    AVER_S_B_AVER_S_D_AVER_S_H_AVER_S_W_AVER_U_B_AVER_U_D_AVER_U_H_AVER_U_W_AVE_S_B_AVE_S_D_AVE_S_H_AVE_S_W_AVE_U_B_AVE_U_D_AVE_U_H_AVE_U_W	= 176,
    MOVE_V	= 177,
    LDI_B_LDI_D_LDI_H_LDI_W	= 178,
    AND_V_NOR_V_OR_V_XOR_V	= 179,
    ANDI_B_NORI_B_ORI_B_XORI_B	= 180,
    ST_B_ST_D_ST_H_ST_W	= 181,
    LD_B_LD_D_LD_H_LD_W	= 182,
    SCHED_LIST_END = 183
  };
} // end Sched namespace
} // end Mips namespace
} // end llvm namespace 
#endif // GET_INSTRINFO_ENUM

/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Descriptors                                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC
namespace llvm_ks {

static const MCPhysReg ImplicitList1[] = { Mips::DSPOutFlag20, 0 };
static const MCPhysReg ImplicitList2[] = { Mips::DSPCarry, 0 };
static const MCPhysReg ImplicitList3[] = { Mips::SP, 0 };
static const MCPhysReg ImplicitList4[] = { Mips::AT, 0 };
static const MCPhysReg ImplicitList5[] = { Mips::RA, 0 };
static const MCPhysReg ImplicitList6[] = { Mips::DSPPos, 0 };
static const MCPhysReg ImplicitList7[] = { Mips::T8, 0 };
static const MCPhysReg ImplicitList8[] = { Mips::DSPCCond, 0 };
static const MCPhysReg ImplicitList9[] = { Mips::HI0, Mips::LO0, Mips::P0, Mips::P1, Mips::P2, 0 };
static const MCPhysReg ImplicitList10[] = { Mips::HI0_64, Mips::LO0_64, 0 };
static const MCPhysReg ImplicitList11[] = { Mips::DSPOutFlag16_19, 0 };
static const MCPhysReg ImplicitList12[] = { Mips::HI0, Mips::LO0, 0 };
static const MCPhysReg ImplicitList13[] = { Mips::DSPEFI, 0 };
static const MCPhysReg ImplicitList14[] = { Mips::DSPPos, Mips::DSPEFI, 0 };
static const MCPhysReg ImplicitList15[] = { Mips::DSPOutFlag23, 0 };
static const MCPhysReg ImplicitList16[] = { Mips::FCC0, 0 };
static const MCPhysReg ImplicitList17[] = { Mips::DSPPos, Mips::DSPSCount, 0 };
static const MCPhysReg ImplicitList18[] = { Mips::AC0, 0 };
static const MCPhysReg ImplicitList19[] = { Mips::AC0_64, 0 };
static const MCPhysReg ImplicitList20[] = { Mips::V0, Mips::V1, 0 };
static const MCPhysReg ImplicitList21[] = { Mips::HI0, 0 };
static const MCPhysReg ImplicitList22[] = { Mips::HI0_64, 0 };
static const MCPhysReg ImplicitList23[] = { Mips::LO0, 0 };
static const MCPhysReg ImplicitList24[] = { Mips::LO0_64, 0 };
static const MCPhysReg ImplicitList25[] = { Mips::MPL0, Mips::P0, Mips::P1, Mips::P2, 0 };
static const MCPhysReg ImplicitList26[] = { Mips::MPL1, Mips::P0, Mips::P1, Mips::P2, 0 };
static const MCPhysReg ImplicitList27[] = { Mips::MPL2, Mips::P0, Mips::P1, Mips::P2, 0 };
static const MCPhysReg ImplicitList28[] = { Mips::P0, 0 };
static const MCPhysReg ImplicitList29[] = { Mips::P1, 0 };
static const MCPhysReg ImplicitList30[] = { Mips::P2, 0 };
static const MCPhysReg ImplicitList31[] = { Mips::DSPOutFlag21, 0 };
static const MCPhysReg ImplicitList32[] = { Mips::DSPOutFlag22, 0 };
static const MCPhysReg ImplicitList33[] = { Mips::P0, Mips::P1, Mips::P2, 0 };
static const MCPhysReg ImplicitList34[] = { Mips::MPL1, Mips::MPL2, Mips::P0, Mips::P1, Mips::P2, 0 };

static const MCOperandInfo OperandInfo2[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo3[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo4[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo5[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo6[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo7[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo8[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo9[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo10[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo11[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo12[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo13[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo23[] = { { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo30[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo35[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo38[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsPlusSPRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo50[] = { { Mips::FCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { Mips::COP2RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo54[] = { { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo55[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo56[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo57[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo58[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo59[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo60[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo61[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo62[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo63[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo64[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo65[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo66[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo67[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo68[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo69[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo70[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo71[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo72[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo73[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo74[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo75[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo76[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo77[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo78[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo79[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo80[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo81[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo82[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CCRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo83[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSACtrlRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo84[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo85[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo86[] = { { Mips::FGRCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo87[] = { { Mips::FGRCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo88[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo89[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo90[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo91[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo92[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo93[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo94[] = { { Mips::CCRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo95[] = { { Mips::MSACtrlRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo96[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo97[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo98[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo99[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo100[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo101[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo102[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::COP0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo103[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo104[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::COP2RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo105[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo106[] = { { Mips::COP0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo107[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo108[] = { { Mips::COP2RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo109[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo110[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo111[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo112[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo113[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo114[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo115[] = { { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo116[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo117[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo118[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo119[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo120[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo121[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo122[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo123[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo124[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo125[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo126[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo127[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo128[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo129[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo130[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo131[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo132[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo133[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo134[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo135[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo136[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo137[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo138[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo139[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo140[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo141[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo142[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo143[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo144[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo145[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo146[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo147[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo148[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo149[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo150[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo151[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo152[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo153[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo154[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo155[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo156[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo157[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo158[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo159[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo160[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo161[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo162[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo163[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo164[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo165[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo166[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo167[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo168[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo169[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo170[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo171[] = { { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo172[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo173[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo174[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo175[] = { { Mips::COP2RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo176[] = { { Mips::COP3RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo177[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo178[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo179[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo180[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo181[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo182[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo183[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo184[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo185[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo186[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo187[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo188[] = { { Mips::ACC128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo189[] = { { Mips::ACC64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo190[] = { { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo191[] = { { Mips::DSPCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo192[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo193[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo194[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, };
static const MCOperandInfo OperandInfo195[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo196[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo197[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo198[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo199[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo200[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo201[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::CPU16RegsPlusSPRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo202[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo203[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo204[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPUSPRegRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo205[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo206[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo207[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo208[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo209[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo210[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::COP0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo211[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo212[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::COP2RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo213[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo214[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo215[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo216[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPRMM16MovePRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPRMM16MovePRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo217[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo218[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo219[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo220[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo221[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo222[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo223[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo224[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo225[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo226[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo227[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo228[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo229[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo230[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo231[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo232[] = { { Mips::COP0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo233[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo234[] = { { Mips::COP2RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo235[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo236[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo237[] = { { Mips::HI32DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo238[] = { { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo239[] = { { Mips::LO32DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo240[] = { { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo241[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo242[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo243[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo244[] = { { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo245[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo246[] = { { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo247[] = { { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo248[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo249[] = { { Mips::DSPCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo250[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo251[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo252[] = { { Mips::ACC128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo253[] = { { Mips::ACC64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::ACC64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo254[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::ACC64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo255[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::ACC128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo256[] = { { Mips::ACC64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo257[] = { { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPCCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo258[] = { { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::AFGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo259[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo260[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo261[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo262[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo263[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::HWRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo264[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::HWRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo265[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::HWRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo266[] = { { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo267[] = { { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo268[] = { { Mips::GPRMM16ZeroRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPRMM16RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo269[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo270[] = { { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo271[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo272[] = { { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGRCCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo273[] = { { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGRCCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::FGR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo274[] = { { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Mips::ACC64DSPRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo275[] = { { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo276[] = { { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::DSPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo277[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo278[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo279[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo280[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo281[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo282[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo283[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo284[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo285[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo286[] = { { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo287[] = { { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo288[] = { { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128DRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo289[] = { { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128HRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo290[] = { { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::MSA128WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::GPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo291[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, };
static const MCOperandInfo OperandInfo292[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo293[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo294[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo295[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo296[] = { { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Mips::CPU16RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };

extern const MCInstrDesc MipsInsts[] = {
  { 0,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #0 = PHI
  { 1,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1 = INLINEASM
  { 2,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #2 = CFI_INSTRUCTION
  { 3,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #3 = EH_LABEL
  { 4,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #4 = GC_LABEL
  { 5,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #5 = KILL
  { 6,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #6 = EXTRACT_SUBREG
  { 7,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo4, -1 ,nullptr },  // Inst #7 = INSERT_SUBREG
  { 8,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #8 = IMPLICIT_DEF
  { 9,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo6, -1 ,nullptr },  // Inst #9 = SUBREG_TO_REG
  { 10,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #10 = COPY_TO_REGCLASS
  { 11,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #11 = DBG_VALUE
  { 12,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #12 = REG_SEQUENCE
  { 13,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #13 = COPY
  { 14,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #14 = BUNDLE
  { 15,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #15 = LIFETIME_START
  { 16,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #16 = LIFETIME_END
  { 17,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo8, -1 ,nullptr },  // Inst #17 = STACKMAP
  { 18,	6,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo9, -1 ,nullptr },  // Inst #18 = PATCHPOINT
  { 19,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo10, -1 ,nullptr },  // Inst #19 = LOAD_STACK_GUARD
  { 20,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #20 = STATEPOINT
  { 21,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #21 = LOCAL_ESCAPE
  { 22,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #22 = FAULTING_LOAD_OP
  { 23,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #23 = G_ADD
  { 24,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #24 = ABSMacro
  { 25,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #25 = ABSQ_S_PH
  { 26,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #26 = ABSQ_S_PH_MM
  { 27,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #27 = ABSQ_S_QB
  { 28,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #28 = ABSQ_S_QB_MMR2
  { 29,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #29 = ABSQ_S_W
  { 30,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #30 = ABSQ_S_W_MM
  { 31,	2,	1,	4,	2,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #31 = ABS_D_MMR6
  { 32,	2,	1,	4,	2,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #32 = ABS_S_MMR6
  { 33,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #33 = ADD
  { 34,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #34 = ADDIUPC
  { 35,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #35 = ADDIUPC_MM
  { 36,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #36 = ADDIUPC_MMR6
  { 37,	2,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #37 = ADDIUR1SP_MM
  { 38,	3,	1,	2,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #38 = ADDIUR2_MM
  { 39,	3,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #39 = ADDIUS5_MM
  { 40,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #40 = ADDIUSP_MM
  { 41,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #41 = ADDIU_MMR6
  { 42,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #42 = ADDQH_PH
  { 43,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #43 = ADDQH_PH_MMR2
  { 44,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #44 = ADDQH_R_PH
  { 45,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #45 = ADDQH_R_PH_MMR2
  { 46,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #46 = ADDQH_R_W
  { 47,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #47 = ADDQH_R_W_MMR2
  { 48,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #48 = ADDQH_W
  { 49,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #49 = ADDQH_W_MMR2
  { 50,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #50 = ADDQ_PH
  { 51,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #51 = ADDQ_PH_MM
  { 52,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #52 = ADDQ_S_PH
  { 53,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #53 = ADDQ_S_PH_MM
  { 54,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #54 = ADDQ_S_W
  { 55,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #55 = ADDQ_S_W_MM
  { 56,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList2, OperandInfo17, -1 ,nullptr },  // Inst #56 = ADDSC
  { 57,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList2, OperandInfo17, -1 ,nullptr },  // Inst #57 = ADDSC_MM
  { 58,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #58 = ADDS_A_B
  { 59,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #59 = ADDS_A_D
  { 60,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #60 = ADDS_A_H
  { 61,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #61 = ADDS_A_W
  { 62,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #62 = ADDS_S_B
  { 63,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #63 = ADDS_S_D
  { 64,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #64 = ADDS_S_H
  { 65,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #65 = ADDS_S_W
  { 66,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #66 = ADDS_U_B
  { 67,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #67 = ADDS_U_D
  { 68,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #68 = ADDS_U_H
  { 69,	3,	1,	4,	173,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #69 = ADDS_U_W
  { 70,	3,	1,	2,	3,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #70 = ADDU16_MM
  { 71,	3,	1,	2,	3,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #71 = ADDU16_MMR6
  { 72,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #72 = ADDUH_QB
  { 73,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #73 = ADDUH_QB_MMR2
  { 74,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #74 = ADDUH_R_QB
  { 75,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #75 = ADDUH_R_QB_MMR2
  { 76,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #76 = ADDU_MMR6
  { 77,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #77 = ADDU_PH
  { 78,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #78 = ADDU_PH_MMR2
  { 79,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #79 = ADDU_QB
  { 80,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #80 = ADDU_QB_MM
  { 81,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #81 = ADDU_S_PH
  { 82,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #82 = ADDU_S_PH_MMR2
  { 83,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #83 = ADDU_S_QB
  { 84,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #84 = ADDU_S_QB_MM
  { 85,	3,	1,	4,	174,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #85 = ADDVI_B
  { 86,	3,	1,	4,	174,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #86 = ADDVI_D
  { 87,	3,	1,	4,	174,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #87 = ADDVI_H
  { 88,	3,	1,	4,	174,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #88 = ADDVI_W
  { 89,	3,	1,	4,	174,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #89 = ADDV_B
  { 90,	3,	1,	4,	174,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #90 = ADDV_D
  { 91,	3,	1,	4,	174,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #91 = ADDV_H
  { 92,	3,	1,	4,	174,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #92 = ADDV_W
  { 93,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList2, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #93 = ADDWC
  { 94,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList2, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #94 = ADDWC_MM
  { 95,	3,	1,	4,	172,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #95 = ADD_A_B
  { 96,	3,	1,	4,	172,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #96 = ADD_A_D
  { 97,	3,	1,	4,	172,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #97 = ADD_A_H
  { 98,	3,	1,	4,	172,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #98 = ADD_A_W
  { 99,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #99 = ADD_MM
  { 100,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #100 = ADD_MMR6
  { 101,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #101 = ADDi
  { 102,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #102 = ADDi_MM
  { 103,	3,	1,	4,	4,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #103 = ADDiu
  { 104,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #104 = ADDiu_MM
  { 105,	3,	1,	4,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #105 = ADDu
  { 106,	3,	1,	4,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #106 = ADDu_MM
  { 107,	1,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList3, ImplicitList3, OperandInfo2, -1 ,nullptr },  // Inst #107 = ADJCALLSTACKDOWN
  { 108,	2,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList3, ImplicitList3, OperandInfo8, -1 ,nullptr },  // Inst #108 = ADJCALLSTACKUP
  { 109,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #109 = ALIGN
  { 110,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #110 = ALIGN_MMR6
  { 111,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #111 = ALUIPC
  { 112,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #112 = ALUIPC_MMR6
  { 113,	3,	1,	4,	5,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #113 = AND
  { 114,	3,	1,	2,	5,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #114 = AND16_MM
  { 115,	3,	1,	2,	5,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #115 = AND16_MMR6
  { 116,	3,	1,	4,	5,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #116 = AND64
  { 117,	3,	1,	2,	5,	0, 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #117 = ANDI16_MM
  { 118,	3,	1,	2,	5,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #118 = ANDI16_MMR6
  { 119,	3,	1,	4,	180,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #119 = ANDI_B
  { 120,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #120 = ANDI_MMR6
  { 121,	3,	1,	4,	5,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #121 = AND_MM
  { 122,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #122 = AND_MMR6
  { 123,	3,	1,	4,	179,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #123 = AND_V
  { 124,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #124 = AND_V_D_PSEUDO
  { 125,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #125 = AND_V_H_PSEUDO
  { 126,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #126 = AND_V_W_PSEUDO
  { 127,	3,	1,	4,	6,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #127 = ANDi
  { 128,	3,	1,	4,	5,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #128 = ANDi64
  { 129,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #129 = ANDi_MM
  { 130,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #130 = APPEND
  { 131,	3,	1,	4,	175,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #131 = ASUB_S_B
  { 132,	3,	1,	4,	175,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #132 = ASUB_S_D
  { 133,	3,	1,	4,	175,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #133 = ASUB_S_H
  { 134,	3,	1,	4,	175,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #134 = ASUB_S_W
  { 135,	3,	1,	4,	175,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #135 = ASUB_U_B
  { 136,	3,	1,	4,	175,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #136 = ASUB_U_D
  { 137,	3,	1,	4,	175,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #137 = ASUB_U_H
  { 138,	3,	1,	4,	175,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #138 = ASUB_U_W
  { 139,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #139 = ATOMIC_CMP_SWAP_I16
  { 140,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #140 = ATOMIC_CMP_SWAP_I32
  { 141,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #141 = ATOMIC_CMP_SWAP_I64
  { 142,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #142 = ATOMIC_CMP_SWAP_I8
  { 143,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #143 = ATOMIC_LOAD_ADD_I16
  { 144,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #144 = ATOMIC_LOAD_ADD_I32
  { 145,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #145 = ATOMIC_LOAD_ADD_I64
  { 146,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #146 = ATOMIC_LOAD_ADD_I8
  { 147,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #147 = ATOMIC_LOAD_AND_I16
  { 148,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #148 = ATOMIC_LOAD_AND_I32
  { 149,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #149 = ATOMIC_LOAD_AND_I64
  { 150,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #150 = ATOMIC_LOAD_AND_I8
  { 151,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #151 = ATOMIC_LOAD_NAND_I16
  { 152,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #152 = ATOMIC_LOAD_NAND_I32
  { 153,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #153 = ATOMIC_LOAD_NAND_I64
  { 154,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #154 = ATOMIC_LOAD_NAND_I8
  { 155,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #155 = ATOMIC_LOAD_OR_I16
  { 156,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #156 = ATOMIC_LOAD_OR_I32
  { 157,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #157 = ATOMIC_LOAD_OR_I64
  { 158,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #158 = ATOMIC_LOAD_OR_I8
  { 159,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #159 = ATOMIC_LOAD_SUB_I16
  { 160,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #160 = ATOMIC_LOAD_SUB_I32
  { 161,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #161 = ATOMIC_LOAD_SUB_I64
  { 162,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #162 = ATOMIC_LOAD_SUB_I8
  { 163,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #163 = ATOMIC_LOAD_XOR_I16
  { 164,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #164 = ATOMIC_LOAD_XOR_I32
  { 165,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #165 = ATOMIC_LOAD_XOR_I64
  { 166,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #166 = ATOMIC_LOAD_XOR_I8
  { 167,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #167 = ATOMIC_SWAP_I16
  { 168,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #168 = ATOMIC_SWAP_I32
  { 169,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #169 = ATOMIC_SWAP_I64
  { 170,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #170 = ATOMIC_SWAP_I8
  { 171,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #171 = AUI
  { 172,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #172 = AUIPC
  { 173,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #173 = AUIPC_MMR6
  { 174,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #174 = AUI_MMR6
  { 175,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #175 = AVER_S_B
  { 176,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #176 = AVER_S_D
  { 177,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #177 = AVER_S_H
  { 178,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #178 = AVER_S_W
  { 179,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #179 = AVER_U_B
  { 180,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #180 = AVER_U_D
  { 181,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #181 = AVER_U_H
  { 182,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #182 = AVER_U_W
  { 183,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #183 = AVE_S_B
  { 184,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #184 = AVE_S_D
  { 185,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #185 = AVE_S_H
  { 186,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #186 = AVE_S_W
  { 187,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #187 = AVE_U_B
  { 188,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #188 = AVE_U_D
  { 189,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #189 = AVE_U_H
  { 190,	3,	1,	4,	176,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #190 = AVE_U_W
  { 191,	2,	1,	4,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #191 = AddiuRxImmX16
  { 192,	2,	1,	4,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #192 = AddiuRxPcImmX16
  { 193,	3,	1,	2,	7,	0|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #193 = AddiuRxRxImm16
  { 194,	3,	1,	4,	7,	0|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #194 = AddiuRxRxImmX16
  { 195,	3,	1,	4,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #195 = AddiuRxRyOffMemX16
  { 196,	1,	0,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList3, ImplicitList3, OperandInfo5, -1 ,nullptr },  // Inst #196 = AddiuSpImm16
  { 197,	1,	0,	4,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList3, ImplicitList3, OperandInfo5, -1 ,nullptr },  // Inst #197 = AddiuSpImmX16
  { 198,	3,	1,	2,	7,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #198 = AdduRxRyRz16
  { 199,	3,	1,	2,	7,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #199 = AndRxRxRy16
  { 200,	1,	0,	4,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, ImplicitList4, OperandInfo47, -1 ,nullptr },  // Inst #200 = B
  { 201,	1,	0,	2,	8,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList4, OperandInfo47, -1 ,nullptr },  // Inst #201 = B16_MM
  { 202,	3,	1,	4,	9,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #202 = BADDu
  { 203,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo47, -1 ,nullptr },  // Inst #203 = BAL
  { 204,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo47, -1 ,nullptr },  // Inst #204 = BALC
  { 205,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo47, -1 ,nullptr },  // Inst #205 = BALC_MMR6
  { 206,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #206 = BALIGN
  { 207,	1,	0,	4,	10,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList5, OperandInfo47, -1 ,nullptr },  // Inst #207 = BAL_BR
  { 208,	3,	0,	4,	11,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo48, -1 ,nullptr },  // Inst #208 = BBIT0
  { 209,	3,	0,	4,	11,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo48, -1 ,nullptr },  // Inst #209 = BBIT032
  { 210,	3,	0,	4,	11,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo48, -1 ,nullptr },  // Inst #210 = BBIT1
  { 211,	3,	0,	4,	11,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo48, -1 ,nullptr },  // Inst #211 = BBIT132
  { 212,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #212 = BC
  { 213,	1,	0,	2,	12,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList4, OperandInfo47, -1 ,nullptr },  // Inst #213 = BC16_MMR6
  { 214,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #214 = BC1EQZ
  { 215,	2,	0,	4,	13,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, ImplicitList4, OperandInfo50, -1 ,nullptr },  // Inst #215 = BC1F
  { 216,	2,	0,	4,	14,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, ImplicitList4, OperandInfo50, -1 ,nullptr },  // Inst #216 = BC1FL
  { 217,	2,	0,	4,	13,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, ImplicitList4, OperandInfo50, -1 ,nullptr },  // Inst #217 = BC1F_MM
  { 218,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #218 = BC1NEZ
  { 219,	2,	0,	4,	15,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, ImplicitList4, OperandInfo50, -1 ,nullptr },  // Inst #219 = BC1T
  { 220,	2,	0,	4,	16,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, ImplicitList4, OperandInfo50, -1 ,nullptr },  // Inst #220 = BC1TL
  { 221,	2,	0,	4,	15,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, ImplicitList4, OperandInfo50, -1 ,nullptr },  // Inst #221 = BC1T_MM
  { 222,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #222 = BC2EQZ
  { 223,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #223 = BC2NEZ
  { 224,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #224 = BCLRI_B
  { 225,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #225 = BCLRI_D
  { 226,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #226 = BCLRI_H
  { 227,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #227 = BCLRI_W
  { 228,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #228 = BCLR_B
  { 229,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #229 = BCLR_D
  { 230,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #230 = BCLR_H
  { 231,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #231 = BCLR_W
  { 232,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #232 = BC_MMR6
  { 233,	3,	0,	4,	17,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #233 = BEQ
  { 234,	3,	0,	4,	17,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo53, -1 ,nullptr },  // Inst #234 = BEQ64
  { 235,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #235 = BEQC
  { 236,	3,	0,	4,	17,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #236 = BEQL
  { 237,	2,	0,	2,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList4, OperandInfo54, -1 ,nullptr },  // Inst #237 = BEQZ16_MM
  { 238,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #238 = BEQZALC
  { 239,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #239 = BEQZALC_MMR6
  { 240,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #240 = BEQZC
  { 241,	2,	0,	2,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList4, OperandInfo54, -1 ,nullptr },  // Inst #241 = BEQZC16_MMR6
  { 242,	2,	0,	4,	19,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #242 = BEQZC_MM
  { 243,	3,	0,	4,	17,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #243 = BEQ_MM
  { 244,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #244 = BGE
  { 245,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #245 = BGEC
  { 246,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #246 = BGEImmMacro
  { 247,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #247 = BGEL
  { 248,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #248 = BGELImmMacro
  { 249,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #249 = BGEU
  { 250,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #250 = BGEUC
  { 251,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #251 = BGEUImmMacro
  { 252,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #252 = BGEUL
  { 253,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #253 = BGEULImmMacro
  { 254,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #254 = BGEZ
  { 255,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo57, -1 ,nullptr },  // Inst #255 = BGEZ64
  { 256,	2,	0,	4,	10,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #256 = BGEZAL
  { 257,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #257 = BGEZALC
  { 258,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #258 = BGEZALC_MMR6
  { 259,	2,	0,	4,	10,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #259 = BGEZALL
  { 260,	2,	0,	4,	20,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #260 = BGEZALS_MM
  { 261,	2,	0,	4,	10,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #261 = BGEZAL_MM
  { 262,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #262 = BGEZC
  { 263,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #263 = BGEZL
  { 264,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #264 = BGEZ_MM
  { 265,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #265 = BGT
  { 266,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #266 = BGTImmMacro
  { 267,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #267 = BGTL
  { 268,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #268 = BGTLImmMacro
  { 269,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #269 = BGTU
  { 270,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #270 = BGTUImmMacro
  { 271,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #271 = BGTUL
  { 272,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #272 = BGTULImmMacro
  { 273,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #273 = BGTZ
  { 274,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo57, -1 ,nullptr },  // Inst #274 = BGTZ64
  { 275,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #275 = BGTZALC
  { 276,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #276 = BGTZALC_MMR6
  { 277,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #277 = BGTZC
  { 278,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #278 = BGTZL
  { 279,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #279 = BGTZ_MM
  { 280,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #280 = BINSLI_B
  { 281,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #281 = BINSLI_D
  { 282,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #282 = BINSLI_H
  { 283,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #283 = BINSLI_W
  { 284,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #284 = BINSL_B
  { 285,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #285 = BINSL_D
  { 286,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #286 = BINSL_H
  { 287,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #287 = BINSL_W
  { 288,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #288 = BINSRI_B
  { 289,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #289 = BINSRI_D
  { 290,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #290 = BINSRI_H
  { 291,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #291 = BINSRI_W
  { 292,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #292 = BINSR_B
  { 293,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #293 = BINSR_D
  { 294,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #294 = BINSR_H
  { 295,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #295 = BINSR_W
  { 296,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #296 = BITREV
  { 297,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #297 = BITSWAP
  { 298,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #298 = BITSWAP_MMR6
  { 299,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #299 = BLE
  { 300,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #300 = BLEImmMacro
  { 301,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #301 = BLEL
  { 302,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #302 = BLELImmMacro
  { 303,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #303 = BLEU
  { 304,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #304 = BLEUImmMacro
  { 305,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #305 = BLEUL
  { 306,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #306 = BLEULImmMacro
  { 307,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #307 = BLEZ
  { 308,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo57, -1 ,nullptr },  // Inst #308 = BLEZ64
  { 309,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #309 = BLEZALC
  { 310,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #310 = BLEZALC_MMR6
  { 311,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #311 = BLEZC
  { 312,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #312 = BLEZL
  { 313,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #313 = BLEZ_MM
  { 314,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #314 = BLT
  { 315,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #315 = BLTC
  { 316,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #316 = BLTImmMacro
  { 317,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #317 = BLTL
  { 318,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #318 = BLTLImmMacro
  { 319,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #319 = BLTU
  { 320,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #320 = BLTUC
  { 321,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #321 = BLTUImmMacro
  { 322,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #322 = BLTUL
  { 323,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #323 = BLTULImmMacro
  { 324,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #324 = BLTZ
  { 325,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo57, -1 ,nullptr },  // Inst #325 = BLTZ64
  { 326,	2,	0,	4,	10,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #326 = BLTZAL
  { 327,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #327 = BLTZALC
  { 328,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #328 = BLTZALC_MMR6
  { 329,	2,	0,	4,	10,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #329 = BLTZALL
  { 330,	2,	0,	4,	20,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #330 = BLTZALS_MM
  { 331,	2,	0,	4,	10,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #331 = BLTZAL_MM
  { 332,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #332 = BLTZC
  { 333,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #333 = BLTZL
  { 334,	2,	0,	4,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #334 = BLTZ_MM
  { 335,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #335 = BMNZI_B
  { 336,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #336 = BMNZ_V
  { 337,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #337 = BMZI_B
  { 338,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #338 = BMZ_V
  { 339,	3,	0,	4,	17,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #339 = BNE
  { 340,	3,	0,	4,	17,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo53, -1 ,nullptr },  // Inst #340 = BNE64
  { 341,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #341 = BNEC
  { 342,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #342 = BNEGI_B
  { 343,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #343 = BNEGI_D
  { 344,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #344 = BNEGI_H
  { 345,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #345 = BNEGI_W
  { 346,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #346 = BNEG_B
  { 347,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #347 = BNEG_D
  { 348,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #348 = BNEG_H
  { 349,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #349 = BNEG_W
  { 350,	3,	0,	4,	17,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x2ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #350 = BNEL
  { 351,	2,	0,	2,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList4, OperandInfo54, -1 ,nullptr },  // Inst #351 = BNEZ16_MM
  { 352,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #352 = BNEZALC
  { 353,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo55, -1 ,nullptr },  // Inst #353 = BNEZALC_MMR6
  { 354,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #354 = BNEZC
  { 355,	2,	0,	2,	18,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList4, OperandInfo54, -1 ,nullptr },  // Inst #355 = BNEZC16_MMR6
  { 356,	2,	0,	4,	19,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList4, OperandInfo55, -1 ,nullptr },  // Inst #356 = BNEZC_MM
  { 357,	3,	0,	4,	17,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #357 = BNE_MM
  { 358,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #358 = BNVC
  { 359,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo66, -1 ,nullptr },  // Inst #359 = BNZ_B
  { 360,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo67, -1 ,nullptr },  // Inst #360 = BNZ_D
  { 361,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo68, -1 ,nullptr },  // Inst #361 = BNZ_H
  { 362,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo66, -1 ,nullptr },  // Inst #362 = BNZ_V
  { 363,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo69, -1 ,nullptr },  // Inst #363 = BNZ_W
  { 364,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo52, -1 ,nullptr },  // Inst #364 = BOVC
  { 365,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #365 = BPOSGE32
  { 366,	1,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList6, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #366 = BPOSGE32_PSEUDO
  { 367,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #367 = BREAK
  { 368,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #368 = BREAK16_MM
  { 369,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #369 = BREAK16_MMR6
  { 370,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #370 = BREAK_MM
  { 371,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #371 = BREAK_MMR6
  { 372,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #372 = BSELI_B
  { 373,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #373 = BSEL_D_PSEUDO
  { 374,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #374 = BSEL_FD_PSEUDO
  { 375,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #375 = BSEL_FW_PSEUDO
  { 376,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #376 = BSEL_H_PSEUDO
  { 377,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #377 = BSEL_V
  { 378,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #378 = BSEL_W_PSEUDO
  { 379,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #379 = BSETI_B
  { 380,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #380 = BSETI_D
  { 381,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #381 = BSETI_H
  { 382,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #382 = BSETI_W
  { 383,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #383 = BSET_B
  { 384,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #384 = BSET_D
  { 385,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #385 = BSET_H
  { 386,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #386 = BSET_W
  { 387,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo66, -1 ,nullptr },  // Inst #387 = BZ_B
  { 388,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo67, -1 ,nullptr },  // Inst #388 = BZ_D
  { 389,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo68, -1 ,nullptr },  // Inst #389 = BZ_H
  { 390,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo66, -1 ,nullptr },  // Inst #390 = BZ_V
  { 391,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo69, -1 ,nullptr },  // Inst #391 = BZ_W
  { 392,	1,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #392 = B_MMR6_Pseudo
  { 393,	1,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #393 = B_MM_Pseudo
  { 394,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #394 = BeqImm
  { 395,	2,	0,	2,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #395 = BeqzRxImm16
  { 396,	2,	0,	4,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #396 = BeqzRxImmX16
  { 397,	1,	0,	2,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #397 = Bimm16
  { 398,	1,	0,	4,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #398 = BimmX16
  { 399,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #399 = BneImm
  { 400,	2,	0,	2,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #400 = BnezRxImm16
  { 401,	2,	0,	4,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #401 = BnezRxImmX16
  { 402,	0,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #402 = Break16
  { 403,	1,	0,	2,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList7, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #403 = Bteqz16
  { 404,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #404 = BteqzT8CmpX16
  { 405,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #405 = BteqzT8CmpiX16
  { 406,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #406 = BteqzT8SltX16
  { 407,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #407 = BteqzT8SltiX16
  { 408,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #408 = BteqzT8SltiuX16
  { 409,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #409 = BteqzT8SltuX16
  { 410,	1,	0,	4,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList7, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #410 = BteqzX16
  { 411,	1,	0,	2,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList7, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #411 = Btnez16
  { 412,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #412 = BtnezT8CmpX16
  { 413,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #413 = BtnezT8CmpiX16
  { 414,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #414 = BtnezT8SltX16
  { 415,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #415 = BtnezT8SltiX16
  { 416,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #416 = BtnezT8SltiuX16
  { 417,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #417 = BtnezT8SltuX16
  { 418,	1,	0,	4,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList7, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #418 = BtnezX16
  { 419,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #419 = BuildPairF64
  { 420,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #420 = BuildPairF64_64
  { 421,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #421 = CACHE
  { 422,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #422 = CACHEE
  { 423,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #423 = CACHEE_MM
  { 424,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #424 = CACHEE_MMR6
  { 425,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #425 = CACHE_MM
  { 426,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #426 = CACHE_MMR6
  { 427,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #427 = CACHE_R6
  { 428,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #428 = CEIL_L_D64
  { 429,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #429 = CEIL_L_D_MMR6
  { 430,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #430 = CEIL_L_S
  { 431,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #431 = CEIL_L_S_MMR6
  { 432,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #432 = CEIL_W_D32
  { 433,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #433 = CEIL_W_D64
  { 434,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #434 = CEIL_W_D_MMR6
  { 435,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #435 = CEIL_W_MM
  { 436,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #436 = CEIL_W_S
  { 437,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #437 = CEIL_W_S_MM
  { 438,	2,	1,	4,	21,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #438 = CEIL_W_S_MMR6
  { 439,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #439 = CEQI_B
  { 440,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #440 = CEQI_D
  { 441,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #441 = CEQI_H
  { 442,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #442 = CEQI_W
  { 443,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #443 = CEQ_B
  { 444,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #444 = CEQ_D
  { 445,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #445 = CEQ_H
  { 446,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #446 = CEQ_W
  { 447,	2,	1,	4,	22,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #447 = CFC1
  { 448,	2,	1,	4,	22,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #448 = CFC1_MM
  { 449,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #449 = CFCMSA
  { 450,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #450 = CINS
  { 451,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #451 = CINS32
  { 452,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #452 = CLASS_D
  { 453,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #453 = CLASS_D_MMR6
  { 454,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #454 = CLASS_S
  { 455,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #455 = CLASS_S_MMR6
  { 456,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #456 = CLEI_S_B
  { 457,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #457 = CLEI_S_D
  { 458,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #458 = CLEI_S_H
  { 459,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #459 = CLEI_S_W
  { 460,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #460 = CLEI_U_B
  { 461,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #461 = CLEI_U_D
  { 462,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #462 = CLEI_U_H
  { 463,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #463 = CLEI_U_W
  { 464,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #464 = CLE_S_B
  { 465,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #465 = CLE_S_D
  { 466,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #466 = CLE_S_H
  { 467,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #467 = CLE_S_W
  { 468,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #468 = CLE_U_B
  { 469,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #469 = CLE_U_D
  { 470,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #470 = CLE_U_H
  { 471,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #471 = CLE_U_W
  { 472,	2,	1,	4,	23,	0, 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #472 = CLO
  { 473,	2,	1,	4,	23,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #473 = CLO_MM
  { 474,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #474 = CLO_MMR6
  { 475,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #475 = CLO_R6
  { 476,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #476 = CLTI_S_B
  { 477,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #477 = CLTI_S_D
  { 478,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #478 = CLTI_S_H
  { 479,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #479 = CLTI_S_W
  { 480,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #480 = CLTI_U_B
  { 481,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #481 = CLTI_U_D
  { 482,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #482 = CLTI_U_H
  { 483,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #483 = CLTI_U_W
  { 484,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #484 = CLT_S_B
  { 485,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #485 = CLT_S_D
  { 486,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #486 = CLT_S_H
  { 487,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #487 = CLT_S_W
  { 488,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #488 = CLT_U_B
  { 489,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #489 = CLT_U_D
  { 490,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #490 = CLT_U_H
  { 491,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #491 = CLT_U_W
  { 492,	2,	1,	4,	24,	0, 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #492 = CLZ
  { 493,	2,	1,	4,	24,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #493 = CLZ_MM
  { 494,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #494 = CLZ_MMR6
  { 495,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #495 = CLZ_R6
  { 496,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList8, OperandInfo85, -1 ,nullptr },  // Inst #496 = CMPGDU_EQ_QB
  { 497,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList8, OperandInfo85, -1 ,nullptr },  // Inst #497 = CMPGDU_LE_QB
  { 498,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList8, OperandInfo85, -1 ,nullptr },  // Inst #498 = CMPGDU_LT_QB
  { 499,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #499 = CMPGU_EQ_QB
  { 500,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #500 = CMPGU_LE_QB
  { 501,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #501 = CMPGU_LT_QB
  { 502,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList8, OperandInfo14, -1 ,nullptr },  // Inst #502 = CMPU_EQ_QB
  { 503,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList8, OperandInfo14, -1 ,nullptr },  // Inst #503 = CMPU_LE_QB
  { 504,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList8, OperandInfo14, -1 ,nullptr },  // Inst #504 = CMPU_LT_QB
  { 505,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #505 = CMP_AF_D_MMR6
  { 506,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #506 = CMP_AF_S_MMR6
  { 507,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #507 = CMP_EQ_D
  { 508,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #508 = CMP_EQ_D_MMR6
  { 509,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList8, OperandInfo14, -1 ,nullptr },  // Inst #509 = CMP_EQ_PH
  { 510,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #510 = CMP_EQ_S
  { 511,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #511 = CMP_EQ_S_MMR6
  { 512,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #512 = CMP_F_D
  { 513,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #513 = CMP_F_S
  { 514,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #514 = CMP_LE_D
  { 515,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #515 = CMP_LE_D_MMR6
  { 516,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList8, OperandInfo14, -1 ,nullptr },  // Inst #516 = CMP_LE_PH
  { 517,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #517 = CMP_LE_S
  { 518,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #518 = CMP_LE_S_MMR6
  { 519,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #519 = CMP_LT_D
  { 520,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #520 = CMP_LT_D_MMR6
  { 521,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList8, OperandInfo14, -1 ,nullptr },  // Inst #521 = CMP_LT_PH
  { 522,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #522 = CMP_LT_S
  { 523,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #523 = CMP_LT_S_MMR6
  { 524,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #524 = CMP_SAF_D
  { 525,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #525 = CMP_SAF_D_MMR6
  { 526,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #526 = CMP_SAF_S
  { 527,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #527 = CMP_SAF_S_MMR6
  { 528,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #528 = CMP_SEQ_D
  { 529,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #529 = CMP_SEQ_D_MMR6
  { 530,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #530 = CMP_SEQ_S
  { 531,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #531 = CMP_SEQ_S_MMR6
  { 532,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #532 = CMP_SLE_D
  { 533,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #533 = CMP_SLE_D_MMR6
  { 534,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #534 = CMP_SLE_S
  { 535,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #535 = CMP_SLE_S_MMR6
  { 536,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #536 = CMP_SLT_D
  { 537,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #537 = CMP_SLT_D_MMR6
  { 538,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #538 = CMP_SLT_S
  { 539,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #539 = CMP_SLT_S_MMR6
  { 540,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #540 = CMP_SUEQ_D
  { 541,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #541 = CMP_SUEQ_D_MMR6
  { 542,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #542 = CMP_SUEQ_S
  { 543,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #543 = CMP_SUEQ_S_MMR6
  { 544,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #544 = CMP_SULE_D
  { 545,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #545 = CMP_SULE_D_MMR6
  { 546,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #546 = CMP_SULE_S
  { 547,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #547 = CMP_SULE_S_MMR6
  { 548,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #548 = CMP_SULT_D
  { 549,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #549 = CMP_SULT_D_MMR6
  { 550,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #550 = CMP_SULT_S
  { 551,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #551 = CMP_SULT_S_MMR6
  { 552,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #552 = CMP_SUN_D
  { 553,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #553 = CMP_SUN_D_MMR6
  { 554,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #554 = CMP_SUN_S
  { 555,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #555 = CMP_SUN_S_MMR6
  { 556,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #556 = CMP_UEQ_D
  { 557,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #557 = CMP_UEQ_D_MMR6
  { 558,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #558 = CMP_UEQ_S
  { 559,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #559 = CMP_UEQ_S_MMR6
  { 560,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #560 = CMP_ULE_D
  { 561,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #561 = CMP_ULE_D_MMR6
  { 562,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #562 = CMP_ULE_S
  { 563,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #563 = CMP_ULE_S_MMR6
  { 564,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #564 = CMP_ULT_D
  { 565,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #565 = CMP_ULT_D_MMR6
  { 566,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #566 = CMP_ULT_S
  { 567,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #567 = CMP_ULT_S_MMR6
  { 568,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #568 = CMP_UN_D
  { 569,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #569 = CMP_UN_D_MMR6
  { 570,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #570 = CMP_UN_S
  { 571,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #571 = CMP_UN_S_MMR6
  { 572,	3,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #572 = CONSTPOOL_ENTRY
  { 573,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo88, -1 ,nullptr },  // Inst #573 = COPY_FD_PSEUDO
  { 574,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #574 = COPY_FW_PSEUDO
  { 575,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo90, -1 ,nullptr },  // Inst #575 = COPY_S_B
  { 576,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo91, -1 ,nullptr },  // Inst #576 = COPY_S_D
  { 577,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #577 = COPY_S_H
  { 578,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #578 = COPY_S_W
  { 579,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo90, -1 ,nullptr },  // Inst #579 = COPY_U_B
  { 580,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #580 = COPY_U_H
  { 581,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #581 = COPY_U_W
  { 582,	2,	1,	4,	25,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #582 = CTC1
  { 583,	2,	1,	4,	25,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #583 = CTC1_MM
  { 584,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #584 = CTCMSA
  { 585,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo96, -1 ,nullptr },  // Inst #585 = CVT_D32_S
  { 586,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo96, -1 ,nullptr },  // Inst #586 = CVT_D32_W
  { 587,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo96, -1 ,nullptr },  // Inst #587 = CVT_D32_W_MM
  { 588,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #588 = CVT_D64_L
  { 589,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #589 = CVT_D64_S
  { 590,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #590 = CVT_D64_W
  { 591,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #591 = CVT_D_L_MMR6
  { 592,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo96, -1 ,nullptr },  // Inst #592 = CVT_D_S_MM
  { 593,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #593 = CVT_D_S_MMR6
  { 594,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #594 = CVT_D_W_MMR6
  { 595,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #595 = CVT_L_D64
  { 596,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #596 = CVT_L_D64_MM
  { 597,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #597 = CVT_L_D_MMR6
  { 598,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #598 = CVT_L_S
  { 599,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #599 = CVT_L_S_MM
  { 600,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #600 = CVT_L_S_MMR6
  { 601,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #601 = CVT_S_D32
  { 602,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #602 = CVT_S_D32_MM
  { 603,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #603 = CVT_S_D64
  { 604,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo96, -1 ,nullptr },  // Inst #604 = CVT_S_D_MMR6
  { 605,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #605 = CVT_S_L
  { 606,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #606 = CVT_S_L_MMR6
  { 607,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #607 = CVT_S_W
  { 608,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #608 = CVT_S_W_MM
  { 609,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #609 = CVT_S_W_MMR6
  { 610,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #610 = CVT_W_D32
  { 611,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #611 = CVT_W_D64
  { 612,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #612 = CVT_W_D_MMR6
  { 613,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #613 = CVT_W_MM
  { 614,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #614 = CVT_W_S
  { 615,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #615 = CVT_W_S_MM
  { 616,	2,	1,	4,	26,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #616 = CVT_W_S_MMR6
  { 617,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #617 = C_EQ_D32
  { 618,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #618 = C_EQ_D64
  { 619,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #619 = C_EQ_S
  { 620,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #620 = C_F_D32
  { 621,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #621 = C_F_D64
  { 622,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #622 = C_F_S
  { 623,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #623 = C_LE_D32
  { 624,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #624 = C_LE_D64
  { 625,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #625 = C_LE_S
  { 626,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #626 = C_LT_D32
  { 627,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #627 = C_LT_D64
  { 628,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #628 = C_LT_S
  { 629,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #629 = C_NGE_D32
  { 630,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #630 = C_NGE_D64
  { 631,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #631 = C_NGE_S
  { 632,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #632 = C_NGLE_D32
  { 633,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #633 = C_NGLE_D64
  { 634,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #634 = C_NGLE_S
  { 635,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #635 = C_NGL_D32
  { 636,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #636 = C_NGL_D64
  { 637,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #637 = C_NGL_S
  { 638,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #638 = C_NGT_D32
  { 639,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #639 = C_NGT_D64
  { 640,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #640 = C_NGT_S
  { 641,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #641 = C_OLE_D32
  { 642,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #642 = C_OLE_D64
  { 643,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #643 = C_OLE_S
  { 644,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #644 = C_OLT_D32
  { 645,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #645 = C_OLT_D64
  { 646,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #646 = C_OLT_S
  { 647,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #647 = C_SEQ_D32
  { 648,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #648 = C_SEQ_D64
  { 649,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #649 = C_SEQ_S
  { 650,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #650 = C_SF_D32
  { 651,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #651 = C_SF_D64
  { 652,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #652 = C_SF_S
  { 653,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #653 = C_UEQ_D32
  { 654,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #654 = C_UEQ_D64
  { 655,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #655 = C_UEQ_S
  { 656,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #656 = C_ULE_D32
  { 657,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #657 = C_ULE_D64
  { 658,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #658 = C_ULE_S
  { 659,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #659 = C_ULT_D32
  { 660,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #660 = C_ULT_D64
  { 661,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #661 = C_ULT_S
  { 662,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #662 = C_UN_D32
  { 663,	2,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #663 = C_UN_D64
  { 664,	2,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #664 = C_UN_S
  { 665,	2,	0,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo97, -1 ,nullptr },  // Inst #665 = CmpRxRy16
  { 666,	2,	0,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo42, -1 ,nullptr },  // Inst #666 = CmpiRxImm16
  { 667,	2,	0,	4,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo42, -1 ,nullptr },  // Inst #667 = CmpiRxImmX16
  { 668,	1,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #668 = Constant32
  { 669,	3,	1,	4,	29,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #669 = DADD
  { 670,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #670 = DADDi
  { 671,	3,	1,	4,	30,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x2ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #671 = DADDiu
  { 672,	3,	1,	4,	31,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #672 = DADDu
  { 673,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #673 = DAHI
  { 674,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #674 = DAHI_MM64R6
  { 675,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #675 = DALIGN
  { 676,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #676 = DALIGN_MM64R6
  { 677,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #677 = DATI
  { 678,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #678 = DATI_MM64R6
  { 679,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #679 = DAUI
  { 680,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #680 = DAUI_MM64R6
  { 681,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #681 = DBITSWAP
  { 682,	2,	1,	4,	23,	0, 0x1ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #682 = DCLO
  { 683,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #683 = DCLO_R6
  { 684,	2,	1,	4,	24,	0, 0x1ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #684 = DCLZ
  { 685,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #685 = DCLZ_R6
  { 686,	3,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #686 = DDIV
  { 687,	3,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #687 = DDIVU
  { 688,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #688 = DDIVU_MM64R6
  { 689,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #689 = DDIV_MM64R6
  { 690,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #690 = DERET
  { 691,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #691 = DERET_MM
  { 692,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #692 = DERET_MMR6
  { 693,	4,	1,	4,	32,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #693 = DEXT
  { 694,	4,	1,	4,	32,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #694 = DEXTM
  { 695,	4,	1,	4,	32,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #695 = DEXTM_MM64R6
  { 696,	4,	1,	4,	32,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #696 = DEXTU
  { 697,	4,	1,	4,	32,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #697 = DEXTU_MM64R6
  { 698,	4,	1,	4,	32,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #698 = DEXT_MM64R6
  { 699,	1,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #699 = DI
  { 700,	5,	1,	4,	33,	0, 0x1ULL, nullptr, nullptr, OperandInfo101, -1 ,nullptr },  // Inst #700 = DINS
  { 701,	5,	1,	4,	33,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo101, -1 ,nullptr },  // Inst #701 = DINSM
  { 702,	5,	1,	4,	33,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo101, -1 ,nullptr },  // Inst #702 = DINSU
  { 703,	3,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #703 = DIV
  { 704,	3,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #704 = DIVU
  { 705,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #705 = DIVU_MMR6
  { 706,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #706 = DIV_MMR6
  { 707,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #707 = DIV_S_B
  { 708,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #708 = DIV_S_D
  { 709,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #709 = DIV_S_H
  { 710,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #710 = DIV_S_W
  { 711,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #711 = DIV_U_B
  { 712,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #712 = DIV_U_D
  { 713,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #713 = DIV_U_H
  { 714,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #714 = DIV_U_W
  { 715,	1,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #715 = DI_MM
  { 716,	1,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #716 = DI_MMR6
  { 717,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #717 = DLSA
  { 718,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #718 = DLSA_R6
  { 719,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo102, -1 ,nullptr },  // Inst #719 = DMFC0
  { 720,	2,	1,	4,	34,	0|(1ULL<<MCID::Bitcast), 0x4ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #720 = DMFC1
  { 721,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #721 = DMFC2
  { 722,	2,	2,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #722 = DMFC2_OCTEON
  { 723,	3,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #723 = DMOD
  { 724,	3,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #724 = DMODU
  { 725,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #725 = DMODU_MM64R6
  { 726,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #726 = DMOD_MM64R6
  { 727,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo106, -1 ,nullptr },  // Inst #727 = DMTC0
  { 728,	2,	1,	4,	35,	0|(1ULL<<MCID::Bitcast), 0x4ULL, nullptr, nullptr, OperandInfo107, -1 ,nullptr },  // Inst #728 = DMTC1
  { 729,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #729 = DMTC2
  { 730,	2,	2,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #730 = DMTC2_OCTEON
  { 731,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #731 = DMUH
  { 732,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #732 = DMUHU
  { 733,	3,	1,	4,	36,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, ImplicitList9, OperandInfo35, -1 ,nullptr },  // Inst #733 = DMUL
  { 734,	2,	0,	4,	37,	0|(1ULL<<MCID::Commutable), 0x1ULL, nullptr, ImplicitList10, OperandInfo100, -1 ,nullptr },  // Inst #734 = DMULT
  { 735,	2,	0,	4,	38,	0|(1ULL<<MCID::Commutable), 0x1ULL, nullptr, ImplicitList10, OperandInfo100, -1 ,nullptr },  // Inst #735 = DMULTu
  { 736,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #736 = DMULU
  { 737,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #737 = DMUL_R6
  { 738,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #738 = DOTP_S_D
  { 739,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #739 = DOTP_S_H
  { 740,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #740 = DOTP_S_W
  { 741,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #741 = DOTP_U_D
  { 742,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #742 = DOTP_U_H
  { 743,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #743 = DOTP_U_W
  { 744,	4,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo112, -1 ,nullptr },  // Inst #744 = DPADD_S_D
  { 745,	4,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #745 = DPADD_S_H
  { 746,	4,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #746 = DPADD_S_W
  { 747,	4,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo112, -1 ,nullptr },  // Inst #747 = DPADD_U_D
  { 748,	4,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #748 = DPADD_U_H
  { 749,	4,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #749 = DPADD_U_W
  { 750,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #750 = DPAQX_SA_W_PH
  { 751,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #751 = DPAQX_SA_W_PH_MMR2
  { 752,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #752 = DPAQX_S_W_PH
  { 753,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #753 = DPAQX_S_W_PH_MMR2
  { 754,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #754 = DPAQ_SA_L_W
  { 755,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #755 = DPAQ_SA_L_W_MM
  { 756,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #756 = DPAQ_S_W_PH
  { 757,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #757 = DPAQ_S_W_PH_MM
  { 758,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #758 = DPAU_H_QBL
  { 759,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #759 = DPAU_H_QBL_MM
  { 760,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #760 = DPAU_H_QBR
  { 761,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #761 = DPAU_H_QBR_MM
  { 762,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #762 = DPAX_W_PH
  { 763,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #763 = DPAX_W_PH_MMR2
  { 764,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #764 = DPA_W_PH
  { 765,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #765 = DPA_W_PH_MMR2
  { 766,	2,	1,	4,	39,	0, 0x1ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #766 = DPOP
  { 767,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #767 = DPSQX_SA_W_PH
  { 768,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #768 = DPSQX_SA_W_PH_MMR2
  { 769,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #769 = DPSQX_S_W_PH
  { 770,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #770 = DPSQX_S_W_PH_MMR2
  { 771,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #771 = DPSQ_SA_L_W
  { 772,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #772 = DPSQ_SA_L_W_MM
  { 773,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #773 = DPSQ_S_W_PH
  { 774,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #774 = DPSQ_S_W_PH_MM
  { 775,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo112, -1 ,nullptr },  // Inst #775 = DPSUB_S_D
  { 776,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #776 = DPSUB_S_H
  { 777,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #777 = DPSUB_S_W
  { 778,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo112, -1 ,nullptr },  // Inst #778 = DPSUB_U_D
  { 779,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #779 = DPSUB_U_H
  { 780,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #780 = DPSUB_U_W
  { 781,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #781 = DPSU_H_QBL
  { 782,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #782 = DPSU_H_QBL_MM
  { 783,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #783 = DPSU_H_QBR
  { 784,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #784 = DPSU_H_QBR_MM
  { 785,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #785 = DPSX_W_PH
  { 786,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #786 = DPSX_W_PH_MMR2
  { 787,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #787 = DPS_W_PH
  { 788,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #788 = DPS_W_PH_MMR2
  { 789,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #789 = DROL
  { 790,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #790 = DROLImm
  { 791,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #791 = DROR
  { 792,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #792 = DRORImm
  { 793,	3,	1,	4,	40,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #793 = DROTR
  { 794,	3,	1,	4,	41,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #794 = DROTR32
  { 795,	3,	1,	4,	42,	0, 0x1ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #795 = DROTRV
  { 796,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #796 = DSBH
  { 797,	2,	0,	4,	43,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList10, OperandInfo100, -1 ,nullptr },  // Inst #797 = DSDIV
  { 798,	2,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #798 = DSDivMacro
  { 799,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #799 = DSHD
  { 800,	3,	1,	4,	44,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #800 = DSLL
  { 801,	3,	1,	4,	45,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #801 = DSLL32
  { 802,	2,	1,	4,	44,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #802 = DSLL64_32
  { 803,	3,	1,	4,	46,	0, 0x1ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #803 = DSLLV
  { 804,	3,	1,	4,	47,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #804 = DSRA
  { 805,	3,	1,	4,	48,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #805 = DSRA32
  { 806,	3,	1,	4,	49,	0, 0x1ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #806 = DSRAV
  { 807,	3,	1,	4,	50,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #807 = DSRL
  { 808,	3,	1,	4,	51,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #808 = DSRL32
  { 809,	3,	1,	4,	52,	0, 0x1ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #809 = DSRLV
  { 810,	3,	1,	4,	53,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #810 = DSUB
  { 811,	3,	1,	4,	54,	0|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #811 = DSUBu
  { 812,	2,	0,	4,	55,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList10, OperandInfo100, -1 ,nullptr },  // Inst #812 = DUDIV
  { 813,	2,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #813 = DUDivMacro
  { 814,	2,	0,	2,	7,	0, 0x0ULL, nullptr, ImplicitList12, OperandInfo97, -1 ,nullptr },  // Inst #814 = DivRxRy16
  { 815,	2,	0,	2,	7,	0, 0x0ULL, nullptr, ImplicitList12, OperandInfo97, -1 ,nullptr },  // Inst #815 = DivuRxRy16
  { 816,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #816 = EHB
  { 817,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #817 = EHB_MM
  { 818,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #818 = EHB_MMR6
  { 819,	1,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #819 = EI
  { 820,	1,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #820 = EI_MM
  { 821,	1,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #821 = EI_MMR6
  { 822,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #822 = ERET
  { 823,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #823 = ERETNC
  { 824,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #824 = ERETNC_MMR6
  { 825,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #825 = ERET_MM
  { 826,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #826 = ERET_MMR6
  { 827,	0,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #827 = ERet
  { 828,	4,	1,	4,	32,	0, 0x1ULL, nullptr, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #828 = EXT
  { 829,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList6, ImplicitList13, OperandInfo119, -1 ,nullptr },  // Inst #829 = EXTP
  { 830,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList6, ImplicitList14, OperandInfo119, -1 ,nullptr },  // Inst #830 = EXTPDP
  { 831,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList6, ImplicitList14, OperandInfo120, -1 ,nullptr },  // Inst #831 = EXTPDPV
  { 832,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList6, ImplicitList14, OperandInfo120, -1 ,nullptr },  // Inst #832 = EXTPDPV_MM
  { 833,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList6, ImplicitList14, OperandInfo119, -1 ,nullptr },  // Inst #833 = EXTPDP_MM
  { 834,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList6, ImplicitList13, OperandInfo120, -1 ,nullptr },  // Inst #834 = EXTPV
  { 835,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList6, ImplicitList13, OperandInfo120, -1 ,nullptr },  // Inst #835 = EXTPV_MM
  { 836,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, ImplicitList6, ImplicitList13, OperandInfo119, -1 ,nullptr },  // Inst #836 = EXTP_MM
  { 837,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo120, -1 ,nullptr },  // Inst #837 = EXTRV_RS_W
  { 838,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo120, -1 ,nullptr },  // Inst #838 = EXTRV_RS_W_MM
  { 839,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo120, -1 ,nullptr },  // Inst #839 = EXTRV_R_W
  { 840,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo120, -1 ,nullptr },  // Inst #840 = EXTRV_R_W_MM
  { 841,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo120, -1 ,nullptr },  // Inst #841 = EXTRV_S_H
  { 842,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo120, -1 ,nullptr },  // Inst #842 = EXTRV_S_H_MM
  { 843,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo120, -1 ,nullptr },  // Inst #843 = EXTRV_W
  { 844,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo120, -1 ,nullptr },  // Inst #844 = EXTRV_W_MM
  { 845,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo119, -1 ,nullptr },  // Inst #845 = EXTR_RS_W
  { 846,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo119, -1 ,nullptr },  // Inst #846 = EXTR_RS_W_MM
  { 847,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo119, -1 ,nullptr },  // Inst #847 = EXTR_R_W
  { 848,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo119, -1 ,nullptr },  // Inst #848 = EXTR_R_W_MM
  { 849,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo119, -1 ,nullptr },  // Inst #849 = EXTR_S_H
  { 850,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo119, -1 ,nullptr },  // Inst #850 = EXTR_S_H_MM
  { 851,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo119, -1 ,nullptr },  // Inst #851 = EXTR_W
  { 852,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList15, OperandInfo119, -1 ,nullptr },  // Inst #852 = EXTR_W_MM
  { 853,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #853 = EXTS
  { 854,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #854 = EXTS32
  { 855,	4,	1,	4,	32,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #855 = EXT_MM
  { 856,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo121, -1 ,nullptr },  // Inst #856 = ExtractElementF64
  { 857,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #857 = ExtractElementF64_64
  { 858,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #858 = FABS_D
  { 859,	2,	1,	4,	2,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #859 = FABS_D32
  { 860,	2,	1,	4,	2,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #860 = FABS_D64
  { 861,	2,	1,	4,	2,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #861 = FABS_MM
  { 862,	2,	1,	4,	2,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #862 = FABS_S
  { 863,	2,	1,	4,	2,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #863 = FABS_S_MM
  { 864,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #864 = FABS_W
  { 865,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #865 = FADD_D
  { 866,	3,	1,	4,	56,	0|(1ULL<<MCID::Commutable), 0x4ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #866 = FADD_D32
  { 867,	3,	1,	4,	56,	0|(1ULL<<MCID::Commutable), 0x4ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #867 = FADD_D64
  { 868,	3,	1,	4,	56,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #868 = FADD_D_MMR6
  { 869,	3,	1,	4,	56,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #869 = FADD_MM
  { 870,	3,	1,	4,	57,	0|(1ULL<<MCID::Commutable), 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #870 = FADD_S
  { 871,	3,	1,	4,	57,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #871 = FADD_S_MM
  { 872,	3,	1,	4,	57,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #872 = FADD_S_MMR6
  { 873,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #873 = FADD_W
  { 874,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #874 = FCAF_D
  { 875,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #875 = FCAF_W
  { 876,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #876 = FCEQ_D
  { 877,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #877 = FCEQ_W
  { 878,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #878 = FCLASS_D
  { 879,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #879 = FCLASS_W
  { 880,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #880 = FCLE_D
  { 881,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #881 = FCLE_W
  { 882,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #882 = FCLT_D
  { 883,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #883 = FCLT_W
  { 884,	3,	0,	4,	27,	0, 0x4ULL, nullptr, ImplicitList16, OperandInfo128, -1 ,nullptr },  // Inst #884 = FCMP_D32
  { 885,	3,	0,	4,	27,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, ImplicitList16, OperandInfo128, -1 ,nullptr },  // Inst #885 = FCMP_D32_MM
  { 886,	3,	0,	4,	27,	0, 0x4ULL, nullptr, ImplicitList16, OperandInfo129, -1 ,nullptr },  // Inst #886 = FCMP_D64
  { 887,	3,	0,	4,	28,	0, 0x4ULL, nullptr, ImplicitList16, OperandInfo130, -1 ,nullptr },  // Inst #887 = FCMP_S32
  { 888,	3,	0,	4,	28,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, ImplicitList16, OperandInfo130, -1 ,nullptr },  // Inst #888 = FCMP_S32_MM
  { 889,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #889 = FCNE_D
  { 890,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #890 = FCNE_W
  { 891,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #891 = FCOR_D
  { 892,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #892 = FCOR_W
  { 893,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #893 = FCUEQ_D
  { 894,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #894 = FCUEQ_W
  { 895,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #895 = FCULE_D
  { 896,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #896 = FCULE_W
  { 897,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #897 = FCULT_D
  { 898,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #898 = FCULT_W
  { 899,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #899 = FCUNE_D
  { 900,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #900 = FCUNE_W
  { 901,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #901 = FCUN_D
  { 902,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #902 = FCUN_W
  { 903,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #903 = FDIV_D
  { 904,	3,	1,	4,	58,	0, 0x4ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #904 = FDIV_D32
  { 905,	3,	1,	4,	58,	0, 0x4ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #905 = FDIV_D64
  { 906,	3,	1,	4,	58,	0, 0x6ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #906 = FDIV_D_MMR6
  { 907,	3,	1,	4,	58,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #907 = FDIV_MM
  { 908,	3,	1,	4,	59,	0, 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #908 = FDIV_S
  { 909,	3,	1,	4,	59,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #909 = FDIV_S_MM
  { 910,	3,	1,	4,	59,	0, 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #910 = FDIV_S_MMR6
  { 911,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #911 = FDIV_W
  { 912,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #912 = FEXDO_H
  { 913,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #913 = FEXDO_W
  { 914,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #914 = FEXP2_D
  { 915,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #915 = FEXP2_D_1_PSEUDO
  { 916,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #916 = FEXP2_W
  { 917,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #917 = FEXP2_W_1_PSEUDO
  { 918,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #918 = FEXUPL_D
  { 919,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #919 = FEXUPL_W
  { 920,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #920 = FEXUPR_D
  { 921,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #921 = FEXUPR_W
  { 922,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #922 = FFINT_S_D
  { 923,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #923 = FFINT_S_W
  { 924,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #924 = FFINT_U_D
  { 925,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #925 = FFINT_U_W
  { 926,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #926 = FFQL_D
  { 927,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #927 = FFQL_W
  { 928,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #928 = FFQR_D
  { 929,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #929 = FFQR_W
  { 930,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo135, -1 ,nullptr },  // Inst #930 = FILL_B
  { 931,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo136, -1 ,nullptr },  // Inst #931 = FILL_D
  { 932,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo137, -1 ,nullptr },  // Inst #932 = FILL_FD_PSEUDO
  { 933,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo138, -1 ,nullptr },  // Inst #933 = FILL_FW_PSEUDO
  { 934,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo139, -1 ,nullptr },  // Inst #934 = FILL_H
  { 935,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo140, -1 ,nullptr },  // Inst #935 = FILL_W
  { 936,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #936 = FLOG2_D
  { 937,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #937 = FLOG2_W
  { 938,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #938 = FLOOR_L_D64
  { 939,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #939 = FLOOR_L_D_MMR6
  { 940,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #940 = FLOOR_L_S
  { 941,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #941 = FLOOR_L_S_MMR6
  { 942,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #942 = FLOOR_W_D32
  { 943,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #943 = FLOOR_W_D64
  { 944,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #944 = FLOOR_W_D_MMR6
  { 945,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #945 = FLOOR_W_MM
  { 946,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #946 = FLOOR_W_S
  { 947,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #947 = FLOOR_W_S_MM
  { 948,	2,	1,	4,	60,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #948 = FLOOR_W_S_MMR6
  { 949,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #949 = FMADD_D
  { 950,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #950 = FMADD_W
  { 951,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #951 = FMAX_A_D
  { 952,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #952 = FMAX_A_W
  { 953,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #953 = FMAX_D
  { 954,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #954 = FMAX_W
  { 955,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #955 = FMIN_A_D
  { 956,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #956 = FMIN_A_W
  { 957,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #957 = FMIN_D
  { 958,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #958 = FMIN_W
  { 959,	2,	1,	4,	61,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #959 = FMOV_D32
  { 960,	2,	1,	4,	61,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #960 = FMOV_D32_MM
  { 961,	2,	1,	4,	61,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #961 = FMOV_D64
  { 962,	2,	1,	4,	61,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #962 = FMOV_D_MMR6
  { 963,	2,	1,	4,	62,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #963 = FMOV_S
  { 964,	2,	1,	4,	62,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #964 = FMOV_S_MM
  { 965,	2,	1,	4,	62,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #965 = FMOV_S_MMR6
  { 966,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #966 = FMSUB_D
  { 967,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #967 = FMSUB_W
  { 968,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #968 = FMUL_D
  { 969,	3,	1,	4,	63,	0|(1ULL<<MCID::Commutable), 0x4ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #969 = FMUL_D32
  { 970,	3,	1,	4,	63,	0|(1ULL<<MCID::Commutable), 0x4ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #970 = FMUL_D64
  { 971,	3,	1,	4,	63,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #971 = FMUL_D_MMR6
  { 972,	3,	1,	4,	63,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #972 = FMUL_MM
  { 973,	3,	1,	4,	64,	0|(1ULL<<MCID::Commutable), 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #973 = FMUL_S
  { 974,	3,	1,	4,	64,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #974 = FMUL_S_MM
  { 975,	3,	1,	4,	64,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #975 = FMUL_S_MMR6
  { 976,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #976 = FMUL_W
  { 977,	2,	1,	4,	65,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #977 = FNEG_D32
  { 978,	2,	1,	4,	65,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #978 = FNEG_D64
  { 979,	2,	1,	4,	65,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #979 = FNEG_D_MMR6
  { 980,	2,	1,	4,	65,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #980 = FNEG_MM
  { 981,	2,	1,	4,	65,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #981 = FNEG_S
  { 982,	2,	1,	4,	65,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #982 = FNEG_S_MM
  { 983,	2,	1,	4,	65,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #983 = FNEG_S_MMR6
  { 984,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #984 = FRCP_D
  { 985,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #985 = FRCP_W
  { 986,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #986 = FRINT_D
  { 987,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #987 = FRINT_W
  { 988,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #988 = FRSQRT_D
  { 989,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #989 = FRSQRT_W
  { 990,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #990 = FSAF_D
  { 991,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #991 = FSAF_W
  { 992,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #992 = FSEQ_D
  { 993,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #993 = FSEQ_W
  { 994,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #994 = FSLE_D
  { 995,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #995 = FSLE_W
  { 996,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #996 = FSLT_D
  { 997,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #997 = FSLT_W
  { 998,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #998 = FSNE_D
  { 999,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #999 = FSNE_W
  { 1000,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1000 = FSOR_D
  { 1001,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1001 = FSOR_W
  { 1002,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #1002 = FSQRT_D
  { 1003,	2,	1,	4,	66,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1003 = FSQRT_D32
  { 1004,	2,	1,	4,	66,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #1004 = FSQRT_D64
  { 1005,	2,	1,	4,	66,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1005 = FSQRT_MM
  { 1006,	2,	1,	4,	67,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1006 = FSQRT_S
  { 1007,	2,	1,	4,	67,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1007 = FSQRT_S_MM
  { 1008,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #1008 = FSQRT_W
  { 1009,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1009 = FSUB_D
  { 1010,	3,	1,	4,	68,	0, 0x4ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1010 = FSUB_D32
  { 1011,	3,	1,	4,	68,	0, 0x4ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1011 = FSUB_D64
  { 1012,	3,	1,	4,	68,	0, 0x6ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1012 = FSUB_D_MMR6
  { 1013,	3,	1,	4,	68,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1013 = FSUB_MM
  { 1014,	3,	1,	4,	69,	0, 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1014 = FSUB_S
  { 1015,	3,	1,	4,	69,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1015 = FSUB_S_MM
  { 1016,	3,	1,	4,	69,	0, 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1016 = FSUB_S_MMR6
  { 1017,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1017 = FSUB_W
  { 1018,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1018 = FSUEQ_D
  { 1019,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1019 = FSUEQ_W
  { 1020,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1020 = FSULE_D
  { 1021,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1021 = FSULE_W
  { 1022,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1022 = FSULT_D
  { 1023,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1023 = FSULT_W
  { 1024,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1024 = FSUNE_D
  { 1025,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1025 = FSUNE_W
  { 1026,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1026 = FSUN_D
  { 1027,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1027 = FSUN_W
  { 1028,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #1028 = FTINT_S_D
  { 1029,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #1029 = FTINT_S_W
  { 1030,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #1030 = FTINT_U_D
  { 1031,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #1031 = FTINT_U_W
  { 1032,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #1032 = FTQ_H
  { 1033,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #1033 = FTQ_W
  { 1034,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #1034 = FTRUNC_S_D
  { 1035,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #1035 = FTRUNC_S_W
  { 1036,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #1036 = FTRUNC_U_D
  { 1037,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #1037 = FTRUNC_U_W
  { 1038,	4,	2,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo141, -1 ,nullptr },  // Inst #1038 = GotPrologue16
  { 1039,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1039 = HADD_S_D
  { 1040,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1040 = HADD_S_H
  { 1041,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #1041 = HADD_S_W
  { 1042,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1042 = HADD_U_D
  { 1043,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1043 = HADD_U_H
  { 1044,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #1044 = HADD_U_W
  { 1045,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1045 = HSUB_S_D
  { 1046,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1046 = HSUB_S_H
  { 1047,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #1047 = HSUB_S_W
  { 1048,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1048 = HSUB_U_D
  { 1049,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1049 = HSUB_U_H
  { 1050,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #1050 = HSUB_U_W
  { 1051,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1051 = ILVEV_B
  { 1052,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1052 = ILVEV_D
  { 1053,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1053 = ILVEV_H
  { 1054,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1054 = ILVEV_W
  { 1055,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1055 = ILVL_B
  { 1056,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1056 = ILVL_D
  { 1057,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1057 = ILVL_H
  { 1058,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1058 = ILVL_W
  { 1059,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1059 = ILVOD_B
  { 1060,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1060 = ILVOD_D
  { 1061,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1061 = ILVOD_H
  { 1062,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1062 = ILVOD_W
  { 1063,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1063 = ILVR_B
  { 1064,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1064 = ILVR_D
  { 1065,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1065 = ILVR_H
  { 1066,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1066 = ILVR_W
  { 1067,	5,	1,	4,	33,	0, 0x1ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1067 = INS
  { 1068,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo143, -1 ,nullptr },  // Inst #1068 = INSERT_B
  { 1069,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1069 = INSERT_B_VIDX64_PSEUDO
  { 1070,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1070 = INSERT_B_VIDX_PSEUDO
  { 1071,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo146, -1 ,nullptr },  // Inst #1071 = INSERT_D
  { 1072,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1072 = INSERT_D_VIDX64_PSEUDO
  { 1073,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1073 = INSERT_D_VIDX_PSEUDO
  { 1074,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #1074 = INSERT_FD_PSEUDO
  { 1075,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo150, -1 ,nullptr },  // Inst #1075 = INSERT_FD_VIDX64_PSEUDO
  { 1076,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo151, -1 ,nullptr },  // Inst #1076 = INSERT_FD_VIDX_PSEUDO
  { 1077,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo152, -1 ,nullptr },  // Inst #1077 = INSERT_FW_PSEUDO
  { 1078,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo153, -1 ,nullptr },  // Inst #1078 = INSERT_FW_VIDX64_PSEUDO
  { 1079,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo154, -1 ,nullptr },  // Inst #1079 = INSERT_FW_VIDX_PSEUDO
  { 1080,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo155, -1 ,nullptr },  // Inst #1080 = INSERT_H
  { 1081,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #1081 = INSERT_H_VIDX64_PSEUDO
  { 1082,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #1082 = INSERT_H_VIDX_PSEUDO
  { 1083,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo158, -1 ,nullptr },  // Inst #1083 = INSERT_W
  { 1084,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo159, -1 ,nullptr },  // Inst #1084 = INSERT_W_VIDX64_PSEUDO
  { 1085,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo160, -1 ,nullptr },  // Inst #1085 = INSERT_W_VIDX_PSEUDO
  { 1086,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, ImplicitList17, nullptr, OperandInfo161, -1 ,nullptr },  // Inst #1086 = INSV
  { 1087,	5,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo162, -1 ,nullptr },  // Inst #1087 = INSVE_B
  { 1088,	5,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo163, -1 ,nullptr },  // Inst #1088 = INSVE_D
  { 1089,	5,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo164, -1 ,nullptr },  // Inst #1089 = INSVE_H
  { 1090,	5,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo165, -1 ,nullptr },  // Inst #1090 = INSVE_W
  { 1091,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, ImplicitList17, nullptr, OperandInfo161, -1 ,nullptr },  // Inst #1091 = INSV_MM
  { 1092,	5,	1,	4,	33,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1092 = INS_MM
  { 1093,	1,	0,	4,	70,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x3ULL, nullptr, ImplicitList4, OperandInfo5, -1 ,nullptr },  // Inst #1093 = J
  { 1094,	1,	0,	4,	71,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call), 0x3ULL, nullptr, ImplicitList5, OperandInfo5, -1 ,nullptr },  // Inst #1094 = JAL
  { 1095,	2,	1,	4,	72,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList5, OperandInfo13, -1 ,nullptr },  // Inst #1095 = JALR
  { 1096,	1,	0,	2,	72,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList5, OperandInfo70, -1 ,nullptr },  // Inst #1096 = JALR16_MM
  { 1097,	2,	1,	4,	72,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList5, OperandInfo100, -1 ,nullptr },  // Inst #1097 = JALR64
  { 1098,	1,	0,	4,	72,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList5, OperandInfo166, -1 ,nullptr },  // Inst #1098 = JALR64Pseudo
  { 1099,	1,	0,	2,	72,	0|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList5, OperandInfo70, -1 ,nullptr },  // Inst #1099 = JALRC16_MMR6
  { 1100,	1,	0,	4,	72,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList5, OperandInfo70, -1 ,nullptr },  // Inst #1100 = JALRPseudo
  { 1101,	1,	0,	2,	73,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList5, OperandInfo70, -1 ,nullptr },  // Inst #1101 = JALRS16_MM
  { 1102,	2,	1,	4,	73,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList5, OperandInfo13, -1 ,nullptr },  // Inst #1102 = JALRS_MM
  { 1103,	2,	1,	4,	0,	0|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1103 = JALR_HB
  { 1104,	2,	1,	4,	72,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList5, OperandInfo13, -1 ,nullptr },  // Inst #1104 = JALR_MM
  { 1105,	1,	0,	4,	74,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, ImplicitList5, OperandInfo5, -1 ,nullptr },  // Inst #1105 = JALS_MM
  { 1106,	1,	0,	4,	71,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call), 0x3ULL, nullptr, ImplicitList5, OperandInfo5, -1 ,nullptr },  // Inst #1106 = JALX
  { 1107,	1,	0,	4,	71,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, ImplicitList5, OperandInfo5, -1 ,nullptr },  // Inst #1107 = JALX_MM
  { 1108,	1,	0,	4,	71,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, ImplicitList5, OperandInfo5, -1 ,nullptr },  // Inst #1108 = JAL_MM
  { 1109,	2,	0,	4,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo18, -1 ,nullptr },  // Inst #1109 = JIALC
  { 1110,	2,	0,	4,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList5, OperandInfo18, -1 ,nullptr },  // Inst #1110 = JIALC_MMR6
  { 1111,	2,	0,	4,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo18, -1 ,nullptr },  // Inst #1111 = JIC
  { 1112,	2,	0,	4,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList4, OperandInfo18, -1 ,nullptr },  // Inst #1112 = JIC_MMR6
  { 1113,	1,	0,	4,	75,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1113 = JR
  { 1114,	1,	0,	2,	75,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1114 = JR16_MM
  { 1115,	1,	0,	4,	75,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1115 = JR64
  { 1116,	1,	0,	2,	76,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1116 = JRADDIUSP
  { 1117,	1,	0,	2,	77,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1117 = JRC16_MM
  { 1118,	1,	0,	2,	75,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1118 = JRC16_MMR6
  { 1119,	1,	0,	2,	76,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1119 = JRCADDIUSP_MMR6
  { 1120,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1120 = JR_HB
  { 1121,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1121 = JR_HB_R6
  { 1122,	1,	0,	4,	75,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1122 = JR_MM
  { 1123,	1,	0,	4,	70,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, ImplicitList4, OperandInfo5, -1 ,nullptr },  // Inst #1123 = J_MM
  { 1124,	1,	0,	6,	7,	0|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList5, OperandInfo5, -1 ,nullptr },  // Inst #1124 = Jal16
  { 1125,	1,	0,	6,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList5, OperandInfo5, -1 ,nullptr },  // Inst #1125 = JalB16
  { 1126,	1,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1126 = JalOneReg
  { 1127,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1127 = JalTwoReg
  { 1128,	0,	0,	2,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1128 = JrRa16
  { 1129,	0,	0,	2,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1129 = JrcRa16
  { 1130,	1,	0,	2,	7,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo167, -1 ,nullptr },  // Inst #1130 = JrcRx16
  { 1131,	1,	0,	2,	78,	0|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList5, OperandInfo167, -1 ,nullptr },  // Inst #1131 = JumpLinkReg16
  { 1132,	3,	1,	4,	79,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1132 = LB
  { 1133,	3,	1,	4,	79,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1133 = LB64
  { 1134,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1134 = LBE
  { 1135,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1135 = LBE_MM
  { 1136,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1136 = LBE_MMR6
  { 1137,	3,	1,	2,	80,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo171, -1 ,nullptr },  // Inst #1137 = LBU16_MM
  { 1138,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1138 = LBUE_MMR6
  { 1139,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1139 = LBUX
  { 1140,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1140 = LBUX_MM
  { 1141,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1141 = LBU_MMR6
  { 1142,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1142 = LB_MM
  { 1143,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1143 = LB_MMR6
  { 1144,	3,	1,	4,	80,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1144 = LBu
  { 1145,	3,	1,	4,	80,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1145 = LBu64
  { 1146,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1146 = LBuE
  { 1147,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1147 = LBuE_MM
  { 1148,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1148 = LBu_MM
  { 1149,	3,	1,	4,	81,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1149 = LD
  { 1150,	3,	1,	4,	82,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1150 = LDC1
  { 1151,	3,	1,	4,	82,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1151 = LDC164
  { 1152,	3,	1,	4,	82,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1152 = LDC1_MM
  { 1153,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1153 = LDC2
  { 1154,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1154 = LDC2_R6
  { 1155,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1155 = LDC3
  { 1156,	2,	1,	4,	178,	0, 0x6ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1156 = LDI_B
  { 1157,	2,	1,	4,	178,	0, 0x6ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1157 = LDI_D
  { 1158,	2,	1,	4,	178,	0, 0x6ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1158 = LDI_H
  { 1159,	2,	1,	4,	178,	0, 0x6ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1159 = LDI_W
  { 1160,	4,	1,	4,	83,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1160 = LDL
  { 1161,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #1161 = LDPC
  { 1162,	4,	1,	4,	84,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1162 = LDR
  { 1163,	3,	1,	4,	85,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1163 = LDXC1
  { 1164,	3,	1,	4,	85,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1164 = LDXC164
  { 1165,	3,	1,	4,	182,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1165 = LD_B
  { 1166,	3,	1,	4,	182,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo185, -1 ,nullptr },  // Inst #1166 = LD_D
  { 1167,	3,	1,	4,	182,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1167 = LD_H
  { 1168,	3,	1,	4,	182,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1168 = LD_W
  { 1169,	3,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1169 = LEA_ADDiu
  { 1170,	3,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1170 = LEA_ADDiu64
  { 1171,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1171 = LEA_ADDiu_MM
  { 1172,	3,	1,	4,	86,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1172 = LH
  { 1173,	3,	1,	4,	86,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1173 = LH64
  { 1174,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1174 = LHE
  { 1175,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1175 = LHE_MM
  { 1176,	3,	1,	2,	87,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo171, -1 ,nullptr },  // Inst #1176 = LHU16_MM
  { 1177,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1177 = LHX
  { 1178,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1178 = LHX_MM
  { 1179,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1179 = LH_MM
  { 1180,	3,	1,	4,	87,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1180 = LHu
  { 1181,	3,	1,	4,	87,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1181 = LHu64
  { 1182,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1182 = LHuE
  { 1183,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1183 = LHuE_MM
  { 1184,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1184 = LHu_MM
  { 1185,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #1185 = LI16_MM
  { 1186,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #1186 = LI16_MMR6
  { 1187,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1187 = LL
  { 1188,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1188 = LLD
  { 1189,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1189 = LLD_R6
  { 1190,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1190 = LLE
  { 1191,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1191 = LLE_MM
  { 1192,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1192 = LLE_MMR6
  { 1193,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1193 = LL_MM
  { 1194,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1194 = LL_R6
  { 1195,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1195 = LOAD_ACC128
  { 1196,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1196 = LOAD_ACC64
  { 1197,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #1197 = LOAD_ACC64DSP
  { 1198,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #1198 = LOAD_CCOND_DSP
  { 1199,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1199 = LONG_BRANCH_ADDiu
  { 1200,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1200 = LONG_BRANCH_DADDiu
  { 1201,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1201 = LONG_BRANCH_LUi
  { 1202,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #1202 = LSA
  { 1203,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #1203 = LSA_MMR6
  { 1204,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #1204 = LSA_R6
  { 1205,	2,	1,	4,	88,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1205 = LUI_MMR6
  { 1206,	3,	1,	4,	89,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1206 = LUXC1
  { 1207,	3,	1,	4,	89,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1207 = LUXC164
  { 1208,	3,	1,	4,	89,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1208 = LUXC1_MM
  { 1209,	2,	1,	4,	88,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x2ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1209 = LUi
  { 1210,	2,	1,	4,	88,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x2ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #1210 = LUi64
  { 1211,	2,	1,	4,	88,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x2ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1211 = LUi_MM
  { 1212,	3,	1,	4,	90,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1212 = LW
  { 1213,	3,	1,	2,	90,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo171, -1 ,nullptr },  // Inst #1213 = LW16_MM
  { 1214,	3,	1,	4,	90,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1214 = LW64
  { 1215,	3,	1,	4,	91,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1215 = LWC1
  { 1216,	3,	1,	4,	91,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1216 = LWC1_MM
  { 1217,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1217 = LWC2
  { 1218,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1218 = LWC2_R6
  { 1219,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1219 = LWC3
  { 1220,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1220 = LWE
  { 1221,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1221 = LWE_MM
  { 1222,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1222 = LWE_MMR6
  { 1223,	3,	1,	2,	90,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo171, -1 ,nullptr },  // Inst #1223 = LWGP_MM
  { 1224,	4,	1,	4,	92,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1224 = LWL
  { 1225,	4,	1,	4,	92,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1225 = LWL64
  { 1226,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1226 = LWLE
  { 1227,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #1227 = LWLE_MM
  { 1228,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #1228 = LWL_MM
  { 1229,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #1229 = LWM16_MM
  { 1230,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #1230 = LWM16_MMR6
  { 1231,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #1231 = LWM32_MM
  { 1232,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #1232 = LWM_MM
  { 1233,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1233 = LWPC
  { 1234,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1234 = LWPC_MMR6
  { 1235,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1235 = LWP_MM
  { 1236,	4,	1,	4,	93,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1236 = LWR
  { 1237,	4,	1,	4,	93,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1237 = LWR64
  { 1238,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1238 = LWRE
  { 1239,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #1239 = LWRE_MM
  { 1240,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #1240 = LWR_MM
  { 1241,	3,	1,	2,	90,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1241 = LWSP_MM
  { 1242,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1242 = LWUPC
  { 1243,	3,	1,	4,	94,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1243 = LWU_MM
  { 1244,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1244 = LWX
  { 1245,	3,	1,	4,	95,	0|(1ULL<<MCID::MayLoad), 0x5ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1245 = LWXC1
  { 1246,	3,	1,	4,	95,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1246 = LWXC1_MM
  { 1247,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1247 = LWXS_MM
  { 1248,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1248 = LWX_MM
  { 1249,	3,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1249 = LW_MM
  { 1250,	3,	1,	4,	90,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1250 = LW_MMR6
  { 1251,	3,	1,	4,	94,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1251 = LWu
  { 1252,	4,	1,	4,	79,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1252 = LbRxRyOffMemX16
  { 1253,	4,	1,	4,	80,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1253 = LbuRxRyOffMemX16
  { 1254,	4,	1,	4,	86,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1254 = LhRxRyOffMemX16
  { 1255,	4,	1,	4,	87,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1255 = LhuRxRyOffMemX16
  { 1256,	2,	1,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #1256 = LiRxImm16
  { 1257,	2,	1,	4,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #1257 = LiRxImmAlignX16
  { 1258,	2,	1,	4,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #1258 = LiRxImmX16
  { 1259,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1259 = LoadAddrImm32
  { 1260,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #1260 = LoadAddrImm64
  { 1261,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1261 = LoadAddrReg32
  { 1262,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1262 = LoadAddrReg64
  { 1263,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1263 = LoadImm32
  { 1264,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #1264 = LoadImm64
  { 1265,	3,	1,	2,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1265 = LwConstant32
  { 1266,	3,	1,	2,	90,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo203, -1 ,nullptr },  // Inst #1266 = LwRxPcTcp16
  { 1267,	3,	1,	4,	90,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo203, -1 ,nullptr },  // Inst #1267 = LwRxPcTcpX16
  { 1268,	4,	1,	4,	90,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1268 = LwRxRyOffMemX16
  { 1269,	3,	1,	4,	90,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList3, nullptr, OperandInfo204, -1 ,nullptr },  // Inst #1269 = LwRxSpImmX16
  { 1270,	2,	0,	4,	96,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, ImplicitList12, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1270 = MADD
  { 1271,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo205, -1 ,nullptr },  // Inst #1271 = MADDF_D
  { 1272,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo205, -1 ,nullptr },  // Inst #1272 = MADDF_D_MMR6
  { 1273,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1273 = MADDF_S
  { 1274,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1274 = MADDF_S_MMR6
  { 1275,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #1275 = MADDR_Q_H
  { 1276,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #1276 = MADDR_Q_W
  { 1277,	2,	0,	4,	97,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, ImplicitList12, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1277 = MADDU
  { 1278,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1278 = MADDU_DSP
  { 1279,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1279 = MADDU_DSP_MM
  { 1280,	2,	0,	4,	97,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, ImplicitList12, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1280 = MADDU_MM
  { 1281,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1281 = MADDV_B
  { 1282,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #1282 = MADDV_D
  { 1283,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #1283 = MADDV_H
  { 1284,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #1284 = MADDV_W
  { 1285,	4,	1,	4,	98,	0, 0x4ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1285 = MADD_D32
  { 1286,	4,	1,	4,	98,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1286 = MADD_D32_MM
  { 1287,	4,	1,	4,	98,	0, 0x4ULL, nullptr, nullptr, OperandInfo208, -1 ,nullptr },  // Inst #1287 = MADD_D64
  { 1288,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1288 = MADD_DSP
  { 1289,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1289 = MADD_DSP_MM
  { 1290,	2,	0,	4,	96,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, ImplicitList12, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1290 = MADD_MM
  { 1291,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #1291 = MADD_Q_H
  { 1292,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #1292 = MADD_Q_W
  { 1293,	4,	1,	4,	99,	0, 0x4ULL, nullptr, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #1293 = MADD_S
  { 1294,	4,	1,	4,	99,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #1294 = MADD_S_MM
  { 1295,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #1295 = MAQ_SA_W_PHL
  { 1296,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #1296 = MAQ_SA_W_PHL_MM
  { 1297,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #1297 = MAQ_SA_W_PHR
  { 1298,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #1298 = MAQ_SA_W_PHR_MM
  { 1299,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #1299 = MAQ_S_W_PHL
  { 1300,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #1300 = MAQ_S_W_PHL_MM
  { 1301,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #1301 = MAQ_S_W_PHR
  { 1302,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #1302 = MAQ_S_W_PHR_MM
  { 1303,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1303 = MAXA_D
  { 1304,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1304 = MAXA_D_MMR6
  { 1305,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1305 = MAXA_S
  { 1306,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1306 = MAXA_S_MMR6
  { 1307,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1307 = MAXI_S_B
  { 1308,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1308 = MAXI_S_D
  { 1309,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1309 = MAXI_S_H
  { 1310,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1310 = MAXI_S_W
  { 1311,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1311 = MAXI_U_B
  { 1312,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1312 = MAXI_U_D
  { 1313,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1313 = MAXI_U_H
  { 1314,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1314 = MAXI_U_W
  { 1315,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1315 = MAX_A_B
  { 1316,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1316 = MAX_A_D
  { 1317,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1317 = MAX_A_H
  { 1318,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1318 = MAX_A_W
  { 1319,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1319 = MAX_D
  { 1320,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1320 = MAX_D_MMR6
  { 1321,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1321 = MAX_S
  { 1322,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1322 = MAX_S_B
  { 1323,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1323 = MAX_S_D
  { 1324,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1324 = MAX_S_H
  { 1325,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1325 = MAX_S_MMR6
  { 1326,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1326 = MAX_S_W
  { 1327,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1327 = MAX_U_B
  { 1328,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1328 = MAX_U_D
  { 1329,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1329 = MAX_U_H
  { 1330,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1330 = MAX_U_W
  { 1331,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1331 = MFC0
  { 1332,	2,	1,	4,	100,	0|(1ULL<<MCID::Bitcast), 0x4ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1332 = MFC1
  { 1333,	2,	1,	4,	100,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1333 = MFC1_MM
  { 1334,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1334 = MFC2
  { 1335,	2,	1,	4,	101,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #1335 = MFHC1_D32
  { 1336,	2,	1,	4,	101,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo214, -1 ,nullptr },  // Inst #1336 = MFHC1_D64
  { 1337,	2,	1,	4,	101,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #1337 = MFHC1_MM
  { 1338,	1,	1,	4,	102,	0, 0x1ULL, ImplicitList18, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1338 = MFHI
  { 1339,	1,	1,	2,	102,	0, 0x0ULL, ImplicitList18, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1339 = MFHI16_MM
  { 1340,	1,	1,	4,	102,	0, 0x1ULL, ImplicitList19, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1340 = MFHI64
  { 1341,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo215, -1 ,nullptr },  // Inst #1341 = MFHI_DSP
  { 1342,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo215, -1 ,nullptr },  // Inst #1342 = MFHI_DSP_MM
  { 1343,	1,	1,	4,	102,	0, 0x1ULL, ImplicitList18, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1343 = MFHI_MM
  { 1344,	1,	1,	4,	102,	0, 0x1ULL, ImplicitList18, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1344 = MFLO
  { 1345,	1,	1,	2,	102,	0, 0x0ULL, ImplicitList18, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1345 = MFLO16_MM
  { 1346,	1,	1,	4,	102,	0, 0x1ULL, ImplicitList19, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1346 = MFLO64
  { 1347,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo215, -1 ,nullptr },  // Inst #1347 = MFLO_DSP
  { 1348,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo215, -1 ,nullptr },  // Inst #1348 = MFLO_DSP_MM
  { 1349,	1,	1,	4,	102,	0, 0x1ULL, ImplicitList18, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1349 = MFLO_MM
  { 1350,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1350 = MINA_D
  { 1351,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1351 = MINA_D_MMR6
  { 1352,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1352 = MINA_S
  { 1353,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1353 = MINA_S_MMR6
  { 1354,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1354 = MINI_S_B
  { 1355,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1355 = MINI_S_D
  { 1356,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1356 = MINI_S_H
  { 1357,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1357 = MINI_S_W
  { 1358,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1358 = MINI_U_B
  { 1359,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1359 = MINI_U_D
  { 1360,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1360 = MINI_U_H
  { 1361,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1361 = MINI_U_W
  { 1362,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1362 = MIN_A_B
  { 1363,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1363 = MIN_A_D
  { 1364,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1364 = MIN_A_H
  { 1365,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1365 = MIN_A_W
  { 1366,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1366 = MIN_D
  { 1367,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1367 = MIN_D_MMR6
  { 1368,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1368 = MIN_S
  { 1369,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1369 = MIN_S_B
  { 1370,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1370 = MIN_S_D
  { 1371,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1371 = MIN_S_H
  { 1372,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1372 = MIN_S_MMR6
  { 1373,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1373 = MIN_S_W
  { 1374,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1374 = MIN_U_B
  { 1375,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1375 = MIN_U_D
  { 1376,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1376 = MIN_U_H
  { 1377,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1377 = MIN_U_W
  { 1378,	2,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList20, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1378 = MIPSeh_return32
  { 1379,	2,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList20, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #1379 = MIPSeh_return64
  { 1380,	3,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1380 = MOD
  { 1381,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1381 = MODSUB
  { 1382,	3,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1382 = MODU
  { 1383,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1383 = MODU_MMR6
  { 1384,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1384 = MOD_MMR6
  { 1385,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1385 = MOD_S_B
  { 1386,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1386 = MOD_S_D
  { 1387,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1387 = MOD_S_H
  { 1388,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1388 = MOD_S_W
  { 1389,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1389 = MOD_U_B
  { 1390,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1390 = MOD_U_D
  { 1391,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1391 = MOD_U_H
  { 1392,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1392 = MOD_U_W
  { 1393,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1393 = MOVE16_MM
  { 1394,	2,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1394 = MOVE16_MMR6
  { 1395,	4,	1,	2,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo216, -1 ,nullptr },  // Inst #1395 = MOVEP_MM
  { 1396,	2,	1,	4,	177,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo217, -1 ,nullptr },  // Inst #1396 = MOVE_V
  { 1397,	4,	1,	4,	103,	0, 0x4ULL, nullptr, nullptr, OperandInfo218, -1 ,nullptr },  // Inst #1397 = MOVF_D32
  { 1398,	4,	1,	4,	103,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo218, -1 ,nullptr },  // Inst #1398 = MOVF_D32_MM
  { 1399,	4,	1,	4,	103,	0, 0x4ULL, nullptr, nullptr, OperandInfo219, -1 ,nullptr },  // Inst #1399 = MOVF_D64
  { 1400,	4,	1,	4,	104,	0, 0x4ULL, nullptr, nullptr, OperandInfo220, -1 ,nullptr },  // Inst #1400 = MOVF_I
  { 1401,	4,	1,	4,	104,	0, 0x4ULL, nullptr, nullptr, OperandInfo221, -1 ,nullptr },  // Inst #1401 = MOVF_I64
  { 1402,	4,	1,	4,	104,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo220, -1 ,nullptr },  // Inst #1402 = MOVF_I_MM
  { 1403,	4,	1,	4,	105,	0, 0x4ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #1403 = MOVF_S
  { 1404,	4,	1,	4,	105,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #1404 = MOVF_S_MM
  { 1405,	4,	1,	4,	106,	0, 0x4ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #1405 = MOVN_I64_D64
  { 1406,	4,	1,	4,	107,	0, 0x4ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #1406 = MOVN_I64_I
  { 1407,	4,	1,	4,	107,	0, 0x4ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #1407 = MOVN_I64_I64
  { 1408,	4,	1,	4,	108,	0, 0x4ULL, nullptr, nullptr, OperandInfo226, -1 ,nullptr },  // Inst #1408 = MOVN_I64_S
  { 1409,	4,	1,	4,	106,	0, 0x4ULL, nullptr, nullptr, OperandInfo227, -1 ,nullptr },  // Inst #1409 = MOVN_I_D32
  { 1410,	4,	1,	4,	106,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo227, -1 ,nullptr },  // Inst #1410 = MOVN_I_D32_MM
  { 1411,	4,	1,	4,	106,	0, 0x4ULL, nullptr, nullptr, OperandInfo228, -1 ,nullptr },  // Inst #1411 = MOVN_I_D64
  { 1412,	4,	1,	4,	107,	0, 0x4ULL, nullptr, nullptr, OperandInfo229, -1 ,nullptr },  // Inst #1412 = MOVN_I_I
  { 1413,	4,	1,	4,	107,	0, 0x4ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #1413 = MOVN_I_I64
  { 1414,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo229, -1 ,nullptr },  // Inst #1414 = MOVN_I_MM
  { 1415,	4,	1,	4,	108,	0, 0x4ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #1415 = MOVN_I_S
  { 1416,	4,	1,	4,	108,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #1416 = MOVN_I_S_MM
  { 1417,	4,	1,	4,	109,	0, 0x4ULL, nullptr, nullptr, OperandInfo218, -1 ,nullptr },  // Inst #1417 = MOVT_D32
  { 1418,	4,	1,	4,	109,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo218, -1 ,nullptr },  // Inst #1418 = MOVT_D32_MM
  { 1419,	4,	1,	4,	109,	0, 0x4ULL, nullptr, nullptr, OperandInfo219, -1 ,nullptr },  // Inst #1419 = MOVT_D64
  { 1420,	4,	1,	4,	110,	0, 0x4ULL, nullptr, nullptr, OperandInfo220, -1 ,nullptr },  // Inst #1420 = MOVT_I
  { 1421,	4,	1,	4,	110,	0, 0x4ULL, nullptr, nullptr, OperandInfo221, -1 ,nullptr },  // Inst #1421 = MOVT_I64
  { 1422,	4,	1,	4,	110,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo220, -1 ,nullptr },  // Inst #1422 = MOVT_I_MM
  { 1423,	4,	1,	4,	111,	0, 0x4ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #1423 = MOVT_S
  { 1424,	4,	1,	4,	111,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #1424 = MOVT_S_MM
  { 1425,	4,	1,	4,	112,	0, 0x4ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #1425 = MOVZ_I64_D64
  { 1426,	4,	1,	4,	113,	0, 0x4ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #1426 = MOVZ_I64_I
  { 1427,	4,	1,	4,	113,	0, 0x4ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #1427 = MOVZ_I64_I64
  { 1428,	4,	1,	4,	114,	0, 0x4ULL, nullptr, nullptr, OperandInfo226, -1 ,nullptr },  // Inst #1428 = MOVZ_I64_S
  { 1429,	4,	1,	4,	112,	0, 0x4ULL, nullptr, nullptr, OperandInfo227, -1 ,nullptr },  // Inst #1429 = MOVZ_I_D32
  { 1430,	4,	1,	4,	112,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo227, -1 ,nullptr },  // Inst #1430 = MOVZ_I_D32_MM
  { 1431,	4,	1,	4,	112,	0, 0x4ULL, nullptr, nullptr, OperandInfo228, -1 ,nullptr },  // Inst #1431 = MOVZ_I_D64
  { 1432,	4,	1,	4,	113,	0, 0x4ULL, nullptr, nullptr, OperandInfo229, -1 ,nullptr },  // Inst #1432 = MOVZ_I_I
  { 1433,	4,	1,	4,	113,	0, 0x4ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #1433 = MOVZ_I_I64
  { 1434,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo229, -1 ,nullptr },  // Inst #1434 = MOVZ_I_MM
  { 1435,	4,	1,	4,	114,	0, 0x4ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #1435 = MOVZ_I_S
  { 1436,	4,	1,	4,	114,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #1436 = MOVZ_I_S_MM
  { 1437,	2,	0,	4,	115,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, ImplicitList12, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1437 = MSUB
  { 1438,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo205, -1 ,nullptr },  // Inst #1438 = MSUBF_D
  { 1439,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo205, -1 ,nullptr },  // Inst #1439 = MSUBF_D_MMR6
  { 1440,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1440 = MSUBF_S
  { 1441,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1441 = MSUBF_S_MMR6
  { 1442,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #1442 = MSUBR_Q_H
  { 1443,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #1443 = MSUBR_Q_W
  { 1444,	2,	0,	4,	116,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, ImplicitList12, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1444 = MSUBU
  { 1445,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1445 = MSUBU_DSP
  { 1446,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1446 = MSUBU_DSP_MM
  { 1447,	2,	0,	4,	116,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, ImplicitList12, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1447 = MSUBU_MM
  { 1448,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1448 = MSUBV_B
  { 1449,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #1449 = MSUBV_D
  { 1450,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #1450 = MSUBV_H
  { 1451,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #1451 = MSUBV_W
  { 1452,	4,	1,	4,	117,	0, 0x4ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1452 = MSUB_D32
  { 1453,	4,	1,	4,	117,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1453 = MSUB_D32_MM
  { 1454,	4,	1,	4,	117,	0, 0x4ULL, nullptr, nullptr, OperandInfo208, -1 ,nullptr },  // Inst #1454 = MSUB_D64
  { 1455,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1455 = MSUB_DSP
  { 1456,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1456 = MSUB_DSP_MM
  { 1457,	2,	0,	4,	115,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, ImplicitList12, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1457 = MSUB_MM
  { 1458,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #1458 = MSUB_Q_H
  { 1459,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #1459 = MSUB_Q_W
  { 1460,	4,	1,	4,	118,	0, 0x4ULL, nullptr, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #1460 = MSUB_S
  { 1461,	4,	1,	4,	118,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #1461 = MSUB_S_MM
  { 1462,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #1462 = MTC0
  { 1463,	2,	1,	4,	119,	0|(1ULL<<MCID::Bitcast), 0x4ULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #1463 = MTC1
  { 1464,	2,	1,	4,	119,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #1464 = MTC1_MM
  { 1465,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #1465 = MTC2
  { 1466,	3,	1,	4,	120,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #1466 = MTHC1_D32
  { 1467,	3,	1,	4,	120,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo236, -1 ,nullptr },  // Inst #1467 = MTHC1_D64
  { 1468,	3,	1,	4,	120,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #1468 = MTHC1_MM
  { 1469,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList21, OperandInfo70, -1 ,nullptr },  // Inst #1469 = MTHI
  { 1470,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList22, OperandInfo166, -1 ,nullptr },  // Inst #1470 = MTHI64
  { 1471,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo237, -1 ,nullptr },  // Inst #1471 = MTHI_DSP
  { 1472,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo237, -1 ,nullptr },  // Inst #1472 = MTHI_DSP_MM
  { 1473,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList21, OperandInfo70, -1 ,nullptr },  // Inst #1473 = MTHI_MM
  { 1474,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList6, OperandInfo238, -1 ,nullptr },  // Inst #1474 = MTHLIP
  { 1475,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList6, OperandInfo238, -1 ,nullptr },  // Inst #1475 = MTHLIP_MM
  { 1476,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList23, OperandInfo70, -1 ,nullptr },  // Inst #1476 = MTLO
  { 1477,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList24, OperandInfo166, -1 ,nullptr },  // Inst #1477 = MTLO64
  { 1478,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo239, -1 ,nullptr },  // Inst #1478 = MTLO_DSP
  { 1479,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo239, -1 ,nullptr },  // Inst #1479 = MTLO_DSP_MM
  { 1480,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList23, OperandInfo70, -1 ,nullptr },  // Inst #1480 = MTLO_MM
  { 1481,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList25, OperandInfo166, -1 ,nullptr },  // Inst #1481 = MTM0
  { 1482,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList26, OperandInfo166, -1 ,nullptr },  // Inst #1482 = MTM1
  { 1483,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList27, OperandInfo166, -1 ,nullptr },  // Inst #1483 = MTM2
  { 1484,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList28, OperandInfo166, -1 ,nullptr },  // Inst #1484 = MTP0
  { 1485,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList29, OperandInfo166, -1 ,nullptr },  // Inst #1485 = MTP1
  { 1486,	1,	0,	4,	121,	0, 0x1ULL, nullptr, ImplicitList30, OperandInfo166, -1 ,nullptr },  // Inst #1486 = MTP2
  { 1487,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1487 = MUH
  { 1488,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1488 = MUHU
  { 1489,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1489 = MUHU_MMR6
  { 1490,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1490 = MUH_MMR6
  { 1491,	3,	1,	4,	122,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, ImplicitList12, OperandInfo17, -1 ,nullptr },  // Inst #1491 = MUL
  { 1492,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo85, -1 ,nullptr },  // Inst #1492 = MULEQ_S_W_PHL
  { 1493,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo85, -1 ,nullptr },  // Inst #1493 = MULEQ_S_W_PHL_MM
  { 1494,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo85, -1 ,nullptr },  // Inst #1494 = MULEQ_S_W_PHR
  { 1495,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo85, -1 ,nullptr },  // Inst #1495 = MULEQ_S_W_PHR_MM
  { 1496,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1496 = MULEU_S_PH_QBL
  { 1497,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1497 = MULEU_S_PH_QBL_MM
  { 1498,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1498 = MULEU_S_PH_QBR
  { 1499,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1499 = MULEU_S_PH_QBR_MM
  { 1500,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1500 = MULQ_RS_PH
  { 1501,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1501 = MULQ_RS_PH_MM
  { 1502,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo17, -1 ,nullptr },  // Inst #1502 = MULQ_RS_W
  { 1503,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo17, -1 ,nullptr },  // Inst #1503 = MULQ_RS_W_MMR2
  { 1504,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1504 = MULQ_S_PH
  { 1505,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1505 = MULQ_S_PH_MMR2
  { 1506,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo17, -1 ,nullptr },  // Inst #1506 = MULQ_S_W
  { 1507,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo17, -1 ,nullptr },  // Inst #1507 = MULQ_S_W_MMR2
  { 1508,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1508 = MULR_Q_H
  { 1509,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1509 = MULR_Q_W
  { 1510,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList11, OperandInfo115, -1 ,nullptr },  // Inst #1510 = MULSAQ_S_W_PH
  { 1511,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1511 = MULSA_W_PH
  { 1512,	2,	0,	4,	123,	0|(1ULL<<MCID::Commutable), 0x1ULL, nullptr, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1512 = MULT
  { 1513,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo240, -1 ,nullptr },  // Inst #1513 = MULTU_DSP
  { 1514,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo240, -1 ,nullptr },  // Inst #1514 = MULTU_DSP_MM
  { 1515,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo240, -1 ,nullptr },  // Inst #1515 = MULT_DSP
  { 1516,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x6ULL, nullptr, nullptr, OperandInfo240, -1 ,nullptr },  // Inst #1516 = MULT_DSP_MM
  { 1517,	2,	0,	4,	123,	0|(1ULL<<MCID::Commutable), 0x1ULL, nullptr, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1517 = MULT_MM
  { 1518,	2,	0,	4,	124,	0|(1ULL<<MCID::Commutable), 0x1ULL, nullptr, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1518 = MULTu
  { 1519,	2,	0,	4,	124,	0|(1ULL<<MCID::Commutable), 0x1ULL, nullptr, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1519 = MULTu_MM
  { 1520,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1520 = MULU
  { 1521,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1521 = MULU_MMR6
  { 1522,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1522 = MULV_B
  { 1523,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1523 = MULV_D
  { 1524,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1524 = MULV_H
  { 1525,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1525 = MULV_W
  { 1526,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1526 = MUL_MM
  { 1527,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1527 = MUL_MMR6
  { 1528,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1528 = MUL_PH
  { 1529,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1529 = MUL_PH_MMR2
  { 1530,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1530 = MUL_Q_H
  { 1531,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1531 = MUL_Q_W
  { 1532,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1532 = MUL_R6
  { 1533,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1533 = MUL_S_PH
  { 1534,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList31, OperandInfo23, -1 ,nullptr },  // Inst #1534 = MUL_S_PH_MMR2
  { 1535,	1,	1,	2,	7,	0, 0x0ULL, ImplicitList21, nullptr, OperandInfo167, -1 ,nullptr },  // Inst #1535 = Mfhi16
  { 1536,	1,	1,	2,	7,	0, 0x0ULL, ImplicitList23, nullptr, OperandInfo167, -1 ,nullptr },  // Inst #1536 = Mflo16
  { 1537,	2,	1,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo241, -1 ,nullptr },  // Inst #1537 = Move32R16
  { 1538,	2,	1,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo242, -1 ,nullptr },  // Inst #1538 = MoveR3216
  { 1539,	2,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList12, OperandInfo97, -1 ,nullptr },  // Inst #1539 = MultRxRy16
  { 1540,	3,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList12, OperandInfo45, -1 ,nullptr },  // Inst #1540 = MultRxRyRz16
  { 1541,	2,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList12, OperandInfo97, -1 ,nullptr },  // Inst #1541 = MultuRxRy16
  { 1542,	3,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList12, OperandInfo45, -1 ,nullptr },  // Inst #1542 = MultuRxRyRz16
  { 1543,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo217, -1 ,nullptr },  // Inst #1543 = NLOC_B
  { 1544,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #1544 = NLOC_D
  { 1545,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo243, -1 ,nullptr },  // Inst #1545 = NLOC_H
  { 1546,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #1546 = NLOC_W
  { 1547,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo217, -1 ,nullptr },  // Inst #1547 = NLZC_B
  { 1548,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #1548 = NLZC_D
  { 1549,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo243, -1 ,nullptr },  // Inst #1549 = NLZC_H
  { 1550,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #1550 = NLZC_W
  { 1551,	4,	1,	4,	125,	0, 0x4ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1551 = NMADD_D32
  { 1552,	4,	1,	4,	125,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1552 = NMADD_D32_MM
  { 1553,	4,	1,	4,	125,	0, 0x4ULL, nullptr, nullptr, OperandInfo208, -1 ,nullptr },  // Inst #1553 = NMADD_D64
  { 1554,	4,	1,	4,	126,	0, 0x4ULL, nullptr, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #1554 = NMADD_S
  { 1555,	4,	1,	4,	126,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #1555 = NMADD_S_MM
  { 1556,	4,	1,	4,	127,	0, 0x4ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1556 = NMSUB_D32
  { 1557,	4,	1,	4,	127,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1557 = NMSUB_D32_MM
  { 1558,	4,	1,	4,	127,	0, 0x4ULL, nullptr, nullptr, OperandInfo208, -1 ,nullptr },  // Inst #1558 = NMSUB_D64
  { 1559,	4,	1,	4,	128,	0, 0x4ULL, nullptr, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #1559 = NMSUB_S
  { 1560,	4,	1,	4,	128,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #1560 = NMSUB_S_MM
  { 1561,	0,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1561 = NOP
  { 1562,	3,	1,	4,	129,	0|(1ULL<<MCID::Commutable), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1562 = NOR
  { 1563,	3,	1,	4,	129,	0|(1ULL<<MCID::Commutable), 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #1563 = NOR64
  { 1564,	3,	1,	4,	180,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1564 = NORI_B
  { 1565,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1565 = NORImm
  { 1566,	3,	1,	4,	129,	0|(1ULL<<MCID::Commutable), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1566 = NOR_MM
  { 1567,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1567 = NOR_MMR6
  { 1568,	3,	1,	4,	179,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1568 = NOR_V
  { 1569,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1569 = NOR_V_D_PSEUDO
  { 1570,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1570 = NOR_V_H_PSEUDO
  { 1571,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1571 = NOR_V_W_PSEUDO
  { 1572,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo244, -1 ,nullptr },  // Inst #1572 = NOT16_MM
  { 1573,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo244, -1 ,nullptr },  // Inst #1573 = NOT16_MMR6
  { 1574,	2,	1,	2,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #1574 = NegRxRy16
  { 1575,	2,	1,	2,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #1575 = NotRxRy16
  { 1576,	3,	1,	4,	130,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1576 = OR
  { 1577,	3,	1,	2,	130,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1577 = OR16_MM
  { 1578,	3,	1,	2,	130,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1578 = OR16_MMR6
  { 1579,	3,	1,	4,	130,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #1579 = OR64
  { 1580,	3,	1,	4,	180,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1580 = ORI_B
  { 1581,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1581 = ORI_MMR6
  { 1582,	3,	1,	4,	130,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1582 = OR_MM
  { 1583,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1583 = OR_MMR6
  { 1584,	3,	1,	4,	179,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1584 = OR_V
  { 1585,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1585 = OR_V_D_PSEUDO
  { 1586,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1586 = OR_V_H_PSEUDO
  { 1587,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1587 = OR_V_W_PSEUDO
  { 1588,	3,	1,	4,	131,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1588 = ORi
  { 1589,	3,	1,	4,	130,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #1589 = ORi64
  { 1590,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1590 = ORi_MM
  { 1591,	3,	1,	2,	7,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #1591 = OrRxRxRy16
  { 1592,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1592 = PACKRL_PH
  { 1593,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1593 = PACKRL_PH_MM
  { 1594,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1594 = PAUSE
  { 1595,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1595 = PAUSE_MM
  { 1596,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1596 = PAUSE_MMR6
  { 1597,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1597 = PCKEV_B
  { 1598,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1598 = PCKEV_D
  { 1599,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1599 = PCKEV_H
  { 1600,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1600 = PCKEV_W
  { 1601,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1601 = PCKOD_B
  { 1602,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1602 = PCKOD_D
  { 1603,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1603 = PCKOD_H
  { 1604,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1604 = PCKOD_W
  { 1605,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo217, -1 ,nullptr },  // Inst #1605 = PCNT_B
  { 1606,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #1606 = PCNT_D
  { 1607,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo243, -1 ,nullptr },  // Inst #1607 = PCNT_H
  { 1608,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #1608 = PCNT_W
  { 1609,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, ImplicitList8, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1609 = PICK_PH
  { 1610,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, ImplicitList8, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1610 = PICK_PH_MM
  { 1611,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, ImplicitList8, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1611 = PICK_QB
  { 1612,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, ImplicitList8, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1612 = PICK_QB_MM
  { 1613,	2,	1,	4,	39,	0, 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1613 = POP
  { 1614,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1614 = PRECEQU_PH_QBL
  { 1615,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1615 = PRECEQU_PH_QBLA
  { 1616,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1616 = PRECEQU_PH_QBLA_MM
  { 1617,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1617 = PRECEQU_PH_QBL_MM
  { 1618,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1618 = PRECEQU_PH_QBR
  { 1619,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1619 = PRECEQU_PH_QBRA
  { 1620,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1620 = PRECEQU_PH_QBRA_MM
  { 1621,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1621 = PRECEQU_PH_QBR_MM
  { 1622,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #1622 = PRECEQ_W_PHL
  { 1623,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #1623 = PRECEQ_W_PHL_MM
  { 1624,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #1624 = PRECEQ_W_PHR
  { 1625,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #1625 = PRECEQ_W_PHR_MM
  { 1626,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1626 = PRECEU_PH_QBL
  { 1627,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1627 = PRECEU_PH_QBLA
  { 1628,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1628 = PRECEU_PH_QBLA_MM
  { 1629,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1629 = PRECEU_PH_QBL_MM
  { 1630,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1630 = PRECEU_PH_QBR
  { 1631,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1631 = PRECEU_PH_QBRA
  { 1632,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1632 = PRECEU_PH_QBRA_MM
  { 1633,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1633 = PRECEU_PH_QBR_MM
  { 1634,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo23, -1 ,nullptr },  // Inst #1634 = PRECRQU_S_QB_PH
  { 1635,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo23, -1 ,nullptr },  // Inst #1635 = PRECRQU_S_QB_PH_MM
  { 1636,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo246, -1 ,nullptr },  // Inst #1636 = PRECRQ_PH_W
  { 1637,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo246, -1 ,nullptr },  // Inst #1637 = PRECRQ_PH_W_MM
  { 1638,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1638 = PRECRQ_QB_PH
  { 1639,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1639 = PRECRQ_QB_PH_MM
  { 1640,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo246, -1 ,nullptr },  // Inst #1640 = PRECRQ_RS_PH_W
  { 1641,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo246, -1 ,nullptr },  // Inst #1641 = PRECRQ_RS_PH_W_MM
  { 1642,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1642 = PRECR_QB_PH
  { 1643,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1643 = PRECR_QB_PH_MMR2
  { 1644,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #1644 = PRECR_SRA_PH_W
  { 1645,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #1645 = PRECR_SRA_PH_W_MMR2
  { 1646,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #1646 = PRECR_SRA_R_PH_W
  { 1647,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #1647 = PRECR_SRA_R_PH_W_MMR2
  { 1648,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #1648 = PREF
  { 1649,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #1649 = PREFE
  { 1650,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #1650 = PREFE_MM
  { 1651,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #1651 = PREFE_MMR6
  { 1652,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo248, -1 ,nullptr },  // Inst #1652 = PREFX_MM
  { 1653,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #1653 = PREF_MM
  { 1654,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #1654 = PREF_MMR6
  { 1655,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #1655 = PREF_R6
  { 1656,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #1656 = PREPEND
  { 1657,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #1657 = PREPEND_MMR2
  { 1658,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo249, -1 ,nullptr },  // Inst #1658 = PseudoCMPU_EQ_QB
  { 1659,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo249, -1 ,nullptr },  // Inst #1659 = PseudoCMPU_LE_QB
  { 1660,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo249, -1 ,nullptr },  // Inst #1660 = PseudoCMPU_LT_QB
  { 1661,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo249, -1 ,nullptr },  // Inst #1661 = PseudoCMP_EQ_PH
  { 1662,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo249, -1 ,nullptr },  // Inst #1662 = PseudoCMP_LE_PH
  { 1663,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo249, -1 ,nullptr },  // Inst #1663 = PseudoCMP_LT_PH
  { 1664,	2,	1,	4,	26,	0|(1ULL<<MCID::Pseudo), 0x4ULL, nullptr, nullptr, OperandInfo250, -1 ,nullptr },  // Inst #1664 = PseudoCVT_D32_W
  { 1665,	2,	1,	4,	26,	0|(1ULL<<MCID::Pseudo), 0x4ULL, nullptr, nullptr, OperandInfo107, -1 ,nullptr },  // Inst #1665 = PseudoCVT_D64_L
  { 1666,	2,	1,	4,	26,	0|(1ULL<<MCID::Pseudo), 0x4ULL, nullptr, nullptr, OperandInfo251, -1 ,nullptr },  // Inst #1666 = PseudoCVT_D64_W
  { 1667,	2,	1,	4,	26,	0|(1ULL<<MCID::Pseudo), 0x4ULL, nullptr, nullptr, OperandInfo107, -1 ,nullptr },  // Inst #1667 = PseudoCVT_S_L
  { 1668,	2,	1,	4,	26,	0|(1ULL<<MCID::Pseudo), 0x4ULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #1668 = PseudoCVT_S_W
  { 1669,	3,	1,	4,	37,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo252, -1 ,nullptr },  // Inst #1669 = PseudoDMULT
  { 1670,	3,	1,	4,	38,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo252, -1 ,nullptr },  // Inst #1670 = PseudoDMULTu
  { 1671,	3,	1,	4,	43,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo252, -1 ,nullptr },  // Inst #1671 = PseudoDSDIV
  { 1672,	3,	1,	4,	55,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo252, -1 ,nullptr },  // Inst #1672 = PseudoDUDIV
  { 1673,	1,	0,	4,	132,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1673 = PseudoIndirectBranch
  { 1674,	1,	0,	4,	132,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1674 = PseudoIndirectBranch64
  { 1675,	4,	1,	4,	96,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo253, -1 ,nullptr },  // Inst #1675 = PseudoMADD
  { 1676,	4,	1,	4,	97,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo253, -1 ,nullptr },  // Inst #1676 = PseudoMADDU
  { 1677,	2,	1,	4,	102,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo254, -1 ,nullptr },  // Inst #1677 = PseudoMFHI
  { 1678,	2,	1,	4,	102,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #1678 = PseudoMFHI64
  { 1679,	2,	1,	4,	102,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo254, -1 ,nullptr },  // Inst #1679 = PseudoMFLO
  { 1680,	2,	1,	4,	102,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #1680 = PseudoMFLO64
  { 1681,	4,	1,	4,	115,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo253, -1 ,nullptr },  // Inst #1681 = PseudoMSUB
  { 1682,	4,	1,	4,	116,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo253, -1 ,nullptr },  // Inst #1682 = PseudoMSUBU
  { 1683,	3,	1,	4,	121,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #1683 = PseudoMTLOHI
  { 1684,	3,	1,	4,	121,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo252, -1 ,nullptr },  // Inst #1684 = PseudoMTLOHI64
  { 1685,	3,	1,	4,	121,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo240, -1 ,nullptr },  // Inst #1685 = PseudoMTLOHI_DSP
  { 1686,	3,	1,	4,	123,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #1686 = PseudoMULT
  { 1687,	3,	1,	4,	124,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #1687 = PseudoMULTu
  { 1688,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo257, -1 ,nullptr },  // Inst #1688 = PseudoPICK_PH
  { 1689,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo257, -1 ,nullptr },  // Inst #1689 = PseudoPICK_QB
  { 1690,	1,	0,	4,	133,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x0ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #1690 = PseudoReturn
  { 1691,	1,	0,	4,	133,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x0ULL, nullptr, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1691 = PseudoReturn64
  { 1692,	3,	1,	4,	134,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #1692 = PseudoSDIV
  { 1693,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo258, -1 ,nullptr },  // Inst #1693 = PseudoSELECTFP_F_D32
  { 1694,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo259, -1 ,nullptr },  // Inst #1694 = PseudoSELECTFP_F_D64
  { 1695,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo260, -1 ,nullptr },  // Inst #1695 = PseudoSELECTFP_F_I
  { 1696,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo261, -1 ,nullptr },  // Inst #1696 = PseudoSELECTFP_F_I64
  { 1697,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo262, -1 ,nullptr },  // Inst #1697 = PseudoSELECTFP_F_S
  { 1698,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo258, -1 ,nullptr },  // Inst #1698 = PseudoSELECTFP_T_D32
  { 1699,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo259, -1 ,nullptr },  // Inst #1699 = PseudoSELECTFP_T_D64
  { 1700,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo260, -1 ,nullptr },  // Inst #1700 = PseudoSELECTFP_T_I
  { 1701,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo261, -1 ,nullptr },  // Inst #1701 = PseudoSELECTFP_T_I64
  { 1702,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo262, -1 ,nullptr },  // Inst #1702 = PseudoSELECTFP_T_S
  { 1703,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo258, -1 ,nullptr },  // Inst #1703 = PseudoSELECT_D32
  { 1704,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo259, -1 ,nullptr },  // Inst #1704 = PseudoSELECT_D64
  { 1705,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo260, -1 ,nullptr },  // Inst #1705 = PseudoSELECT_I
  { 1706,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo261, -1 ,nullptr },  // Inst #1706 = PseudoSELECT_I64
  { 1707,	4,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo262, -1 ,nullptr },  // Inst #1707 = PseudoSELECT_S
  { 1708,	3,	1,	4,	135,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #1708 = PseudoUDIV
  { 1709,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #1709 = RADDU_W_QB
  { 1710,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #1710 = RADDU_W_QB_MM
  { 1711,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1711 = RDDSP
  { 1712,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #1712 = RDDSP_MM
  { 1713,	2,	1,	4,	136,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo263, -1 ,nullptr },  // Inst #1713 = RDHWR
  { 1714,	2,	1,	4,	136,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo264, -1 ,nullptr },  // Inst #1714 = RDHWR64
  { 1715,	2,	1,	4,	136,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo263, -1 ,nullptr },  // Inst #1715 = RDHWR_MM
  { 1716,	3,	1,	4,	136,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo265, -1 ,nullptr },  // Inst #1716 = RDHWR_MMR6
  { 1717,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1717 = RDPGPR_MMR6
  { 1718,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1718 = RECIP_D_MMR6
  { 1719,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1719 = RECIP_S_MMR6
  { 1720,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo266, -1 ,nullptr },  // Inst #1720 = REPLV_PH
  { 1721,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo266, -1 ,nullptr },  // Inst #1721 = REPLV_PH_MM
  { 1722,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo266, -1 ,nullptr },  // Inst #1722 = REPLV_QB
  { 1723,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo266, -1 ,nullptr },  // Inst #1723 = REPLV_QB_MM
  { 1724,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo267, -1 ,nullptr },  // Inst #1724 = REPL_PH
  { 1725,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo267, -1 ,nullptr },  // Inst #1725 = REPL_PH_MM
  { 1726,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo267, -1 ,nullptr },  // Inst #1726 = REPL_QB
  { 1727,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo267, -1 ,nullptr },  // Inst #1727 = REPL_QB_MM
  { 1728,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #1728 = RINT_D
  { 1729,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #1729 = RINT_D_MMR6
  { 1730,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1730 = RINT_S
  { 1731,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1731 = RINT_S_MMR6
  { 1732,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1732 = ROL
  { 1733,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1733 = ROLImm
  { 1734,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1734 = ROR
  { 1735,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1735 = RORImm
  { 1736,	3,	1,	4,	138,	0, 0x1ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1736 = ROTR
  { 1737,	3,	1,	4,	139,	0, 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1737 = ROTRV
  { 1738,	3,	1,	4,	139,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1738 = ROTRV_MM
  { 1739,	3,	1,	4,	138,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1739 = ROTR_MM
  { 1740,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #1740 = ROUND_L_D64
  { 1741,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #1741 = ROUND_L_D_MMR6
  { 1742,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #1742 = ROUND_L_S
  { 1743,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #1743 = ROUND_L_S_MMR6
  { 1744,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #1744 = ROUND_W_D32
  { 1745,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #1745 = ROUND_W_D64
  { 1746,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #1746 = ROUND_W_D_MMR6
  { 1747,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #1747 = ROUND_W_MM
  { 1748,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1748 = ROUND_W_S
  { 1749,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1749 = ROUND_W_S_MM
  { 1750,	2,	1,	4,	137,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1750 = ROUND_W_S_MMR6
  { 1751,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #1751 = RSQRT_D_MMR6
  { 1752,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1752 = RSQRT_S_MMR6
  { 1753,	0,	0,	2,	141,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList3, ImplicitList3, nullptr, -1 ,nullptr },  // Inst #1753 = Restore16
  { 1754,	0,	0,	2,	141,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList3, ImplicitList3, nullptr, -1 ,nullptr },  // Inst #1754 = RestoreX16
  { 1755,	0,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1755 = RetRA
  { 1756,	0,	0,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1756 = RetRA16
  { 1757,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1757 = SAT_S_B
  { 1758,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1758 = SAT_S_D
  { 1759,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1759 = SAT_S_H
  { 1760,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1760 = SAT_S_W
  { 1761,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1761 = SAT_U_B
  { 1762,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1762 = SAT_U_D
  { 1763,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1763 = SAT_U_H
  { 1764,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1764 = SAT_U_W
  { 1765,	3,	0,	4,	142,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1765 = SB
  { 1766,	3,	0,	2,	142,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo268, -1 ,nullptr },  // Inst #1766 = SB16_MM
  { 1767,	3,	0,	2,	142,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo268, -1 ,nullptr },  // Inst #1767 = SB16_MMR6
  { 1768,	3,	0,	4,	142,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1768 = SB64
  { 1769,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1769 = SBE
  { 1770,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1770 = SBE_MM
  { 1771,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1771 = SBE_MMR6
  { 1772,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1772 = SB_MM
  { 1773,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1773 = SB_MMR6
  { 1774,	4,	1,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo269, -1 ,nullptr },  // Inst #1774 = SC
  { 1775,	4,	1,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo270, -1 ,nullptr },  // Inst #1775 = SCD
  { 1776,	4,	1,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo270, -1 ,nullptr },  // Inst #1776 = SCD_R6
  { 1777,	4,	1,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo269, -1 ,nullptr },  // Inst #1777 = SCE
  { 1778,	4,	1,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo271, -1 ,nullptr },  // Inst #1778 = SCE_MM
  { 1779,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1779 = SCE_MMR6
  { 1780,	4,	1,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo271, -1 ,nullptr },  // Inst #1780 = SC_MM
  { 1781,	4,	1,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo269, -1 ,nullptr },  // Inst #1781 = SC_R6
  { 1782,	3,	0,	4,	143,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1782 = SD
  { 1783,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1783 = SDBBP
  { 1784,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1784 = SDBBP16_MM
  { 1785,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1785 = SDBBP16_MMR6
  { 1786,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1786 = SDBBP_MM
  { 1787,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1787 = SDBBP_MMR6
  { 1788,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1788 = SDBBP_R6
  { 1789,	3,	0,	4,	144,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1789 = SDC1
  { 1790,	3,	0,	4,	144,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1790 = SDC164
  { 1791,	3,	0,	4,	144,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1791 = SDC1_MM
  { 1792,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1792 = SDC2
  { 1793,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1793 = SDC2_R6
  { 1794,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1794 = SDC3
  { 1795,	2,	0,	4,	134,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1795 = SDIV
  { 1796,	2,	0,	4,	134,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #1796 = SDIV_MM
  { 1797,	3,	0,	4,	145,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1797 = SDL
  { 1798,	3,	0,	4,	146,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1798 = SDR
  { 1799,	3,	0,	4,	147,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1799 = SDXC1
  { 1800,	3,	0,	4,	147,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1800 = SDXC164
  { 1801,	2,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1801 = SDivMacro
  { 1802,	2,	1,	4,	148,	0, 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1802 = SEB
  { 1803,	2,	1,	4,	148,	0, 0x1ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #1803 = SEB64
  { 1804,	2,	1,	4,	148,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1804 = SEB_MM
  { 1805,	2,	1,	4,	148,	0, 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1805 = SEB_MMR6
  { 1806,	2,	1,	4,	149,	0, 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1806 = SEH
  { 1807,	2,	1,	4,	149,	0, 0x1ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #1807 = SEH64
  { 1808,	2,	1,	4,	149,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1808 = SEH_MM
  { 1809,	2,	1,	4,	149,	0, 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1809 = SEH_MMR6
  { 1810,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1810 = SELENZ_D_MMR6
  { 1811,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1811 = SELENZ_S_MMR6
  { 1812,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1812 = SELEQZ
  { 1813,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #1813 = SELEQZ64
  { 1814,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1814 = SELEQZ_D
  { 1815,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1815 = SELEQZ_D_MMR6
  { 1816,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1816 = SELEQZ_MMR6
  { 1817,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1817 = SELEQZ_S
  { 1818,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1818 = SELEQZ_S_MMR6
  { 1819,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1819 = SELNEZ
  { 1820,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #1820 = SELNEZ64
  { 1821,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1821 = SELNEZ_D
  { 1822,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1822 = SELNEZ_MMR6
  { 1823,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1823 = SELNEZ_S
  { 1824,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo272, -1 ,nullptr },  // Inst #1824 = SEL_D
  { 1825,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x6ULL, nullptr, nullptr, OperandInfo272, -1 ,nullptr },  // Inst #1825 = SEL_D_MMR6
  { 1826,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo273, -1 ,nullptr },  // Inst #1826 = SEL_S
  { 1827,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo273, -1 ,nullptr },  // Inst #1827 = SEL_S_MMR6
  { 1828,	3,	1,	4,	150,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #1828 = SEQ
  { 1829,	3,	1,	4,	151,	0, 0x2ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #1829 = SEQi
  { 1830,	3,	0,	4,	152,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1830 = SH
  { 1831,	3,	0,	2,	152,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo268, -1 ,nullptr },  // Inst #1831 = SH16_MM
  { 1832,	3,	0,	2,	152,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo268, -1 ,nullptr },  // Inst #1832 = SH16_MMR6
  { 1833,	3,	0,	4,	152,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1833 = SH64
  { 1834,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1834 = SHE
  { 1835,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1835 = SHE_MM
  { 1836,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1836 = SHE_MMR6
  { 1837,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1837 = SHF_B
  { 1838,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1838 = SHF_H
  { 1839,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1839 = SHF_W
  { 1840,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo274, -1 ,nullptr },  // Inst #1840 = SHILO
  { 1841,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo238, -1 ,nullptr },  // Inst #1841 = SHILOV
  { 1842,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo238, -1 ,nullptr },  // Inst #1842 = SHILOV_MM
  { 1843,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo274, -1 ,nullptr },  // Inst #1843 = SHILO_MM
  { 1844,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo275, -1 ,nullptr },  // Inst #1844 = SHLLV_PH
  { 1845,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo275, -1 ,nullptr },  // Inst #1845 = SHLLV_PH_MM
  { 1846,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo275, -1 ,nullptr },  // Inst #1846 = SHLLV_QB
  { 1847,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo275, -1 ,nullptr },  // Inst #1847 = SHLLV_QB_MM
  { 1848,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo275, -1 ,nullptr },  // Inst #1848 = SHLLV_S_PH
  { 1849,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo275, -1 ,nullptr },  // Inst #1849 = SHLLV_S_PH_MM
  { 1850,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo17, -1 ,nullptr },  // Inst #1850 = SHLLV_S_W
  { 1851,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo17, -1 ,nullptr },  // Inst #1851 = SHLLV_S_W_MM
  { 1852,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo276, -1 ,nullptr },  // Inst #1852 = SHLL_PH
  { 1853,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo276, -1 ,nullptr },  // Inst #1853 = SHLL_PH_MM
  { 1854,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo276, -1 ,nullptr },  // Inst #1854 = SHLL_QB
  { 1855,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo276, -1 ,nullptr },  // Inst #1855 = SHLL_QB_MM
  { 1856,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo276, -1 ,nullptr },  // Inst #1856 = SHLL_S_PH
  { 1857,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo276, -1 ,nullptr },  // Inst #1857 = SHLL_S_PH_MM
  { 1858,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo22, -1 ,nullptr },  // Inst #1858 = SHLL_S_W
  { 1859,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList32, OperandInfo22, -1 ,nullptr },  // Inst #1859 = SHLL_S_W_MM
  { 1860,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1860 = SHRAV_PH
  { 1861,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1861 = SHRAV_PH_MM
  { 1862,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1862 = SHRAV_QB
  { 1863,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1863 = SHRAV_QB_MMR2
  { 1864,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1864 = SHRAV_R_PH
  { 1865,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1865 = SHRAV_R_PH_MM
  { 1866,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1866 = SHRAV_R_QB
  { 1867,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1867 = SHRAV_R_QB_MMR2
  { 1868,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1868 = SHRAV_R_W
  { 1869,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1869 = SHRAV_R_W_MM
  { 1870,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1870 = SHRA_PH
  { 1871,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1871 = SHRA_PH_MM
  { 1872,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1872 = SHRA_QB
  { 1873,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1873 = SHRA_QB_MMR2
  { 1874,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1874 = SHRA_R_PH
  { 1875,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1875 = SHRA_R_PH_MM
  { 1876,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1876 = SHRA_R_QB
  { 1877,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1877 = SHRA_R_QB_MMR2
  { 1878,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1878 = SHRA_R_W
  { 1879,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1879 = SHRA_R_W_MM
  { 1880,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1880 = SHRLV_PH
  { 1881,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1881 = SHRLV_PH_MMR2
  { 1882,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1882 = SHRLV_QB
  { 1883,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo275, -1 ,nullptr },  // Inst #1883 = SHRLV_QB_MM
  { 1884,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1884 = SHRL_PH
  { 1885,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1885 = SHRL_PH_MMR2
  { 1886,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1886 = SHRL_QB
  { 1887,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo276, -1 ,nullptr },  // Inst #1887 = SHRL_QB_MM
  { 1888,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1888 = SH_MM
  { 1889,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1889 = SH_MMR6
  { 1890,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #1890 = SLDI_B
  { 1891,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #1891 = SLDI_D
  { 1892,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #1892 = SLDI_H
  { 1893,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #1893 = SLDI_W
  { 1894,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo277, -1 ,nullptr },  // Inst #1894 = SLD_B
  { 1895,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo278, -1 ,nullptr },  // Inst #1895 = SLD_D
  { 1896,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo279, -1 ,nullptr },  // Inst #1896 = SLD_H
  { 1897,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo280, -1 ,nullptr },  // Inst #1897 = SLD_W
  { 1898,	3,	1,	4,	153,	0, 0x1ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1898 = SLL
  { 1899,	3,	1,	2,	153,	0, 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1899 = SLL16_MM
  { 1900,	3,	1,	2,	153,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1900 = SLL16_MMR6
  { 1901,	2,	1,	4,	153,	0, 0x1ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1901 = SLL64_32
  { 1902,	2,	1,	4,	153,	0, 0x1ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #1902 = SLL64_64
  { 1903,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1903 = SLLI_B
  { 1904,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1904 = SLLI_D
  { 1905,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1905 = SLLI_H
  { 1906,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1906 = SLLI_W
  { 1907,	3,	1,	4,	154,	0, 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1907 = SLLV
  { 1908,	3,	1,	4,	154,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1908 = SLLV_MM
  { 1909,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1909 = SLL_B
  { 1910,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1910 = SLL_D
  { 1911,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1911 = SLL_H
  { 1912,	3,	1,	4,	153,	0, 0x1ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1912 = SLL_MM
  { 1913,	3,	1,	4,	153,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1913 = SLL_MMR6
  { 1914,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1914 = SLL_W
  { 1915,	3,	1,	4,	155,	0, 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1915 = SLT
  { 1916,	3,	1,	4,	155,	0, 0x1ULL, nullptr, nullptr, OperandInfo281, -1 ,nullptr },  // Inst #1916 = SLT64
  { 1917,	3,	1,	4,	155,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1917 = SLT_MM
  { 1918,	3,	1,	4,	156,	0, 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1918 = SLTi
  { 1919,	3,	1,	4,	156,	0, 0x2ULL, nullptr, nullptr, OperandInfo282, -1 ,nullptr },  // Inst #1919 = SLTi64
  { 1920,	3,	1,	4,	156,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1920 = SLTi_MM
  { 1921,	3,	1,	4,	156,	0, 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1921 = SLTiu
  { 1922,	3,	1,	4,	156,	0, 0x2ULL, nullptr, nullptr, OperandInfo282, -1 ,nullptr },  // Inst #1922 = SLTiu64
  { 1923,	3,	1,	4,	156,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1923 = SLTiu_MM
  { 1924,	3,	1,	4,	155,	0, 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1924 = SLTu
  { 1925,	3,	1,	4,	155,	0, 0x1ULL, nullptr, nullptr, OperandInfo281, -1 ,nullptr },  // Inst #1925 = SLTu64
  { 1926,	3,	1,	4,	155,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1926 = SLTu_MM
  { 1927,	3,	1,	4,	150,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #1927 = SNE
  { 1928,	3,	1,	4,	151,	0, 0x2ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #1928 = SNEi
  { 1929,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo283, -1 ,nullptr },  // Inst #1929 = SNZ_B_PSEUDO
  { 1930,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo284, -1 ,nullptr },  // Inst #1930 = SNZ_D_PSEUDO
  { 1931,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo285, -1 ,nullptr },  // Inst #1931 = SNZ_H_PSEUDO
  { 1932,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo283, -1 ,nullptr },  // Inst #1932 = SNZ_V_PSEUDO
  { 1933,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo286, -1 ,nullptr },  // Inst #1933 = SNZ_W_PSEUDO
  { 1934,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1934 = SPLATI_B
  { 1935,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1935 = SPLATI_D
  { 1936,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1936 = SPLATI_H
  { 1937,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1937 = SPLATI_W
  { 1938,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo287, -1 ,nullptr },  // Inst #1938 = SPLAT_B
  { 1939,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo288, -1 ,nullptr },  // Inst #1939 = SPLAT_D
  { 1940,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo289, -1 ,nullptr },  // Inst #1940 = SPLAT_H
  { 1941,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo290, -1 ,nullptr },  // Inst #1941 = SPLAT_W
  { 1942,	2,	1,	4,	66,	0, 0x4ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1942 = SQRT_D_MMR6
  { 1943,	2,	1,	4,	67,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1943 = SQRT_S_MMR6
  { 1944,	3,	1,	4,	157,	0, 0x1ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1944 = SRA
  { 1945,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1945 = SRAI_B
  { 1946,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1946 = SRAI_D
  { 1947,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1947 = SRAI_H
  { 1948,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1948 = SRAI_W
  { 1949,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1949 = SRARI_B
  { 1950,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1950 = SRARI_D
  { 1951,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1951 = SRARI_H
  { 1952,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1952 = SRARI_W
  { 1953,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1953 = SRAR_B
  { 1954,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1954 = SRAR_D
  { 1955,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1955 = SRAR_H
  { 1956,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1956 = SRAR_W
  { 1957,	3,	1,	4,	158,	0, 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1957 = SRAV
  { 1958,	3,	1,	4,	158,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1958 = SRAV_MM
  { 1959,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1959 = SRA_B
  { 1960,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1960 = SRA_D
  { 1961,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1961 = SRA_H
  { 1962,	3,	1,	4,	157,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1962 = SRA_MM
  { 1963,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1963 = SRA_W
  { 1964,	3,	1,	4,	159,	0, 0x1ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1964 = SRL
  { 1965,	3,	1,	2,	159,	0, 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1965 = SRL16_MM
  { 1966,	3,	1,	2,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1966 = SRL16_MMR6
  { 1967,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1967 = SRLI_B
  { 1968,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1968 = SRLI_D
  { 1969,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1969 = SRLI_H
  { 1970,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1970 = SRLI_W
  { 1971,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #1971 = SRLRI_B
  { 1972,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1972 = SRLRI_D
  { 1973,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #1973 = SRLRI_H
  { 1974,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1974 = SRLRI_W
  { 1975,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1975 = SRLR_B
  { 1976,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1976 = SRLR_D
  { 1977,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1977 = SRLR_H
  { 1978,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1978 = SRLR_W
  { 1979,	3,	1,	4,	160,	0, 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1979 = SRLV
  { 1980,	3,	1,	4,	160,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1980 = SRLV_MM
  { 1981,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1981 = SRL_B
  { 1982,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1982 = SRL_D
  { 1983,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #1983 = SRL_H
  { 1984,	3,	1,	4,	159,	0, 0x1ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1984 = SRL_MM
  { 1985,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #1985 = SRL_W
  { 1986,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1986 = SSNOP
  { 1987,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1987 = SSNOP_MM
  { 1988,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1988 = SSNOP_MMR6
  { 1989,	3,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1989 = STORE_ACC128
  { 1990,	3,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1990 = STORE_ACC64
  { 1991,	3,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #1991 = STORE_ACC64DSP
  { 1992,	3,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #1992 = STORE_CCOND_DSP
  { 1993,	3,	0,	4,	181,	0|(1ULL<<MCID::MayStore), 0x6ULL, nullptr, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1993 = ST_B
  { 1994,	3,	0,	4,	181,	0|(1ULL<<MCID::MayStore), 0x6ULL, nullptr, nullptr, OperandInfo185, -1 ,nullptr },  // Inst #1994 = ST_D
  { 1995,	3,	0,	4,	181,	0|(1ULL<<MCID::MayStore), 0x6ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1995 = ST_H
  { 1996,	3,	0,	4,	181,	0|(1ULL<<MCID::MayStore), 0x6ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1996 = ST_W
  { 1997,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1997 = SUB
  { 1998,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1998 = SUBQH_PH
  { 1999,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1999 = SUBQH_PH_MMR2
  { 2000,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #2000 = SUBQH_R_PH
  { 2001,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #2001 = SUBQH_R_PH_MMR2
  { 2002,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2002 = SUBQH_R_W
  { 2003,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2003 = SUBQH_R_W_MMR2
  { 2004,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2004 = SUBQH_W
  { 2005,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2005 = SUBQH_W_MMR2
  { 2006,	3,	1,	4,	0,	0, 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2006 = SUBQ_PH
  { 2007,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2007 = SUBQ_PH_MM
  { 2008,	3,	1,	4,	0,	0, 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2008 = SUBQ_S_PH
  { 2009,	3,	1,	4,	0,	0, 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2009 = SUBQ_S_PH_MM
  { 2010,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #2010 = SUBQ_S_W
  { 2011,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #2011 = SUBQ_S_W_MM
  { 2012,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #2012 = SUBSUS_U_B
  { 2013,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #2013 = SUBSUS_U_D
  { 2014,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #2014 = SUBSUS_U_H
  { 2015,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #2015 = SUBSUS_U_W
  { 2016,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #2016 = SUBSUU_S_B
  { 2017,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #2017 = SUBSUU_S_D
  { 2018,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #2018 = SUBSUU_S_H
  { 2019,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #2019 = SUBSUU_S_W
  { 2020,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #2020 = SUBS_S_B
  { 2021,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #2021 = SUBS_S_D
  { 2022,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #2022 = SUBS_S_H
  { 2023,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #2023 = SUBS_S_W
  { 2024,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #2024 = SUBS_U_B
  { 2025,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #2025 = SUBS_U_D
  { 2026,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #2026 = SUBS_U_H
  { 2027,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #2027 = SUBS_U_W
  { 2028,	3,	1,	2,	161,	0, 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #2028 = SUBU16_MM
  { 2029,	3,	1,	2,	161,	0, 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #2029 = SUBU16_MMR6
  { 2030,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #2030 = SUBUH_QB
  { 2031,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #2031 = SUBUH_QB_MMR2
  { 2032,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #2032 = SUBUH_R_QB
  { 2033,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #2033 = SUBUH_R_QB_MMR2
  { 2034,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2034 = SUBU_MMR6
  { 2035,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2035 = SUBU_PH
  { 2036,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2036 = SUBU_PH_MMR2
  { 2037,	3,	1,	4,	0,	0, 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2037 = SUBU_QB
  { 2038,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2038 = SUBU_QB_MM
  { 2039,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2039 = SUBU_S_PH
  { 2040,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2040 = SUBU_S_PH_MMR2
  { 2041,	3,	1,	4,	0,	0, 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2041 = SUBU_S_QB
  { 2042,	3,	1,	4,	0,	0, 0x6ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #2042 = SUBU_S_QB_MM
  { 2043,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #2043 = SUBVI_B
  { 2044,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #2044 = SUBVI_D
  { 2045,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #2045 = SUBVI_H
  { 2046,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #2046 = SUBVI_W
  { 2047,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #2047 = SUBV_B
  { 2048,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #2048 = SUBV_D
  { 2049,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #2049 = SUBV_H
  { 2050,	3,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #2050 = SUBV_W
  { 2051,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2051 = SUB_MM
  { 2052,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2052 = SUB_MMR6
  { 2053,	3,	1,	4,	161,	0|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2053 = SUBu
  { 2054,	3,	1,	4,	161,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2054 = SUBu_MM
  { 2055,	3,	0,	4,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #2055 = SUXC1
  { 2056,	3,	0,	4,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #2056 = SUXC164
  { 2057,	3,	0,	4,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #2057 = SUXC1_MM
  { 2058,	3,	0,	4,	163,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2058 = SW
  { 2059,	3,	0,	2,	163,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo268, -1 ,nullptr },  // Inst #2059 = SW16_MM
  { 2060,	3,	0,	2,	163,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo268, -1 ,nullptr },  // Inst #2060 = SW16_MMR6
  { 2061,	3,	0,	4,	163,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #2061 = SW64
  { 2062,	3,	0,	4,	164,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2062 = SWC1
  { 2063,	3,	0,	4,	164,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2063 = SWC1_MM
  { 2064,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #2064 = SWC2
  { 2065,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #2065 = SWC2_R6
  { 2066,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #2066 = SWC3
  { 2067,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2067 = SWE
  { 2068,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2068 = SWE_MM
  { 2069,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2069 = SWE_MMR6
  { 2070,	3,	0,	4,	165,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2070 = SWL
  { 2071,	3,	0,	4,	165,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #2071 = SWL64
  { 2072,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2072 = SWLE
  { 2073,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #2073 = SWLE_MM
  { 2074,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #2074 = SWL_MM
  { 2075,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2075 = SWM16_MM
  { 2076,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2076 = SWM16_MMR6
  { 2077,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2077 = SWM32_MM
  { 2078,	3,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2078 = SWM_MM
  { 2079,	4,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2079 = SWP_MM
  { 2080,	3,	0,	4,	166,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2080 = SWR
  { 2081,	3,	0,	4,	166,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #2081 = SWR64
  { 2082,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2082 = SWRE
  { 2083,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #2083 = SWRE_MM
  { 2084,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #2084 = SWR_MM
  { 2085,	3,	0,	2,	163,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #2085 = SWSP_MM
  { 2086,	3,	0,	2,	163,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #2086 = SWSP_MMR6
  { 2087,	3,	0,	4,	167,	0|(1ULL<<MCID::MayStore), 0x5ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #2087 = SWXC1
  { 2088,	3,	0,	4,	167,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x5ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #2088 = SWXC1_MM
  { 2089,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2089 = SW_MM
  { 2090,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2090 = SW_MMR6
  { 2091,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #2091 = SYNC
  { 2092,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo291, -1 ,nullptr },  // Inst #2092 = SYNCI
  { 2093,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo291, -1 ,nullptr },  // Inst #2093 = SYNCI_MMR6
  { 2094,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #2094 = SYNC_MM
  { 2095,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #2095 = SYNC_MMR6
  { 2096,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #2096 = SYSCALL
  { 2097,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #2097 = SYSCALL_MM
  { 2098,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo283, -1 ,nullptr },  // Inst #2098 = SZ_B_PSEUDO
  { 2099,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo284, -1 ,nullptr },  // Inst #2099 = SZ_D_PSEUDO
  { 2100,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo285, -1 ,nullptr },  // Inst #2100 = SZ_H_PSEUDO
  { 2101,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo283, -1 ,nullptr },  // Inst #2101 = SZ_V_PSEUDO
  { 2102,	2,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo286, -1 ,nullptr },  // Inst #2102 = SZ_W_PSEUDO
  { 2103,	0,	0,	2,	168,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList3, ImplicitList3, nullptr, -1 ,nullptr },  // Inst #2103 = Save16
  { 2104,	0,	0,	2,	168,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList3, ImplicitList3, nullptr, -1 ,nullptr },  // Inst #2104 = SaveX16
  { 2105,	4,	0,	4,	142,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #2105 = SbRxRyOffMemX16
  { 2106,	2,	1,	2,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo292, -1 ,nullptr },  // Inst #2106 = SebRx16
  { 2107,	2,	1,	2,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo292, -1 ,nullptr },  // Inst #2107 = SehRx16
  { 2108,	4,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo293, -1 ,nullptr },  // Inst #2108 = SelBeqZ
  { 2109,	4,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo293, -1 ,nullptr },  // Inst #2109 = SelBneZ
  { 2110,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo294, -1 ,nullptr },  // Inst #2110 = SelTBteqZCmp
  { 2111,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo295, -1 ,nullptr },  // Inst #2111 = SelTBteqZCmpi
  { 2112,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo294, -1 ,nullptr },  // Inst #2112 = SelTBteqZSlt
  { 2113,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo295, -1 ,nullptr },  // Inst #2113 = SelTBteqZSlti
  { 2114,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo295, -1 ,nullptr },  // Inst #2114 = SelTBteqZSltiu
  { 2115,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo294, -1 ,nullptr },  // Inst #2115 = SelTBteqZSltu
  { 2116,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo294, -1 ,nullptr },  // Inst #2116 = SelTBtneZCmp
  { 2117,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo295, -1 ,nullptr },  // Inst #2117 = SelTBtneZCmpi
  { 2118,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo294, -1 ,nullptr },  // Inst #2118 = SelTBtneZSlt
  { 2119,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo295, -1 ,nullptr },  // Inst #2119 = SelTBtneZSlti
  { 2120,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo295, -1 ,nullptr },  // Inst #2120 = SelTBtneZSltiu
  { 2121,	5,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo294, -1 ,nullptr },  // Inst #2121 = SelTBtneZSltu
  { 2122,	4,	0,	4,	152,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #2122 = ShRxRyOffMemX16
  { 2123,	3,	1,	4,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo296, -1 ,nullptr },  // Inst #2123 = SllX16
  { 2124,	3,	1,	2,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #2124 = SllvRxRy16
  { 2125,	3,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #2125 = SltCCRxRy16
  { 2126,	2,	0,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo97, -1 ,nullptr },  // Inst #2126 = SltRxRy16
  { 2127,	3,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo296, -1 ,nullptr },  // Inst #2127 = SltiCCRxImmX16
  { 2128,	2,	0,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo42, -1 ,nullptr },  // Inst #2128 = SltiRxImm16
  { 2129,	2,	0,	4,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo42, -1 ,nullptr },  // Inst #2129 = SltiRxImmX16
  { 2130,	3,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo296, -1 ,nullptr },  // Inst #2130 = SltiuCCRxImmX16
  { 2131,	2,	0,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo42, -1 ,nullptr },  // Inst #2131 = SltiuRxImm16
  { 2132,	2,	0,	4,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo42, -1 ,nullptr },  // Inst #2132 = SltiuRxImmX16
  { 2133,	3,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #2133 = SltuCCRxRy16
  { 2134,	2,	0,	2,	7,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo97, -1 ,nullptr },  // Inst #2134 = SltuRxRy16
  { 2135,	3,	1,	2,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo45, -1 ,nullptr },  // Inst #2135 = SltuRxRyRz16
  { 2136,	3,	1,	4,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo296, -1 ,nullptr },  // Inst #2136 = SraX16
  { 2137,	3,	1,	2,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #2137 = SravRxRy16
  { 2138,	3,	1,	4,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo296, -1 ,nullptr },  // Inst #2138 = SrlX16
  { 2139,	3,	1,	2,	7,	0, 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #2139 = SrlvRxRy16
  { 2140,	3,	1,	2,	7,	0|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #2140 = SubuRxRyRz16
  { 2141,	4,	0,	4,	163,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #2141 = SwRxRyOffMemX16
  { 2142,	3,	0,	4,	163,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo204, -1 ,nullptr },  // Inst #2142 = SwRxSpImmX16
  { 2143,	1,	0,	4,	70,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x0ULL, nullptr, ImplicitList4, OperandInfo5, -1 ,nullptr },  // Inst #2143 = TAILCALL
  { 2144,	1,	0,	4,	75,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x0ULL, nullptr, ImplicitList4, OperandInfo166, -1 ,nullptr },  // Inst #2144 = TAILCALL64_R
  { 2145,	1,	0,	4,	75,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x0ULL, nullptr, ImplicitList4, OperandInfo70, -1 ,nullptr },  // Inst #2145 = TAILCALL_R
  { 2146,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2146 = TEQ
  { 2147,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2147 = TEQI
  { 2148,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2148 = TEQI_MM
  { 2149,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2149 = TEQ_MM
  { 2150,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2150 = TGE
  { 2151,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2151 = TGEI
  { 2152,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2152 = TGEIU
  { 2153,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2153 = TGEIU_MM
  { 2154,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2154 = TGEI_MM
  { 2155,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2155 = TGEU
  { 2156,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2156 = TGEU_MM
  { 2157,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2157 = TGE_MM
  { 2158,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2158 = TLBINV
  { 2159,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2159 = TLBINVF
  { 2160,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2160 = TLBP
  { 2161,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2161 = TLBP_MM
  { 2162,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2162 = TLBR
  { 2163,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2163 = TLBR_MM
  { 2164,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2164 = TLBWI
  { 2165,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2165 = TLBWI_MM
  { 2166,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2166 = TLBWR
  { 2167,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2167 = TLBWR_MM
  { 2168,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2168 = TLT
  { 2169,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2169 = TLTI
  { 2170,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2170 = TLTIU_MM
  { 2171,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2171 = TLTI_MM
  { 2172,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2172 = TLTU
  { 2173,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2173 = TLTU_MM
  { 2174,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2174 = TLT_MM
  { 2175,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2175 = TNE
  { 2176,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2176 = TNEI
  { 2177,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2177 = TNEI_MM
  { 2178,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2178 = TNE_MM
  { 2179,	0,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2179 = TRAP
  { 2180,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #2180 = TRUNC_L_D64
  { 2181,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #2181 = TRUNC_L_D_MMR6
  { 2182,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #2182 = TRUNC_L_S
  { 2183,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #2183 = TRUNC_L_S_MMR6
  { 2184,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #2184 = TRUNC_W_D32
  { 2185,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #2185 = TRUNC_W_D64
  { 2186,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #2186 = TRUNC_W_D_MMR6
  { 2187,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #2187 = TRUNC_W_MM
  { 2188,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #2188 = TRUNC_W_S
  { 2189,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #2189 = TRUNC_W_S_MM
  { 2190,	2,	1,	4,	140,	0, 0x4ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #2190 = TRUNC_W_S_MMR6
  { 2191,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2191 = TTLTIU
  { 2192,	2,	0,	4,	135,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #2192 = UDIV
  { 2193,	2,	0,	4,	135,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList12, OperandInfo13, -1 ,nullptr },  // Inst #2193 = UDIV_MM
  { 2194,	2,	0,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #2194 = UDivMacro
  { 2195,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2195 = Ulh
  { 2196,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2196 = Ulhu
  { 2197,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #2197 = Ulw
  { 2198,	3,	1,	4,	36,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList33, OperandInfo35, -1 ,nullptr },  // Inst #2198 = V3MULU
  { 2199,	3,	1,	4,	36,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList25, OperandInfo35, -1 ,nullptr },  // Inst #2199 = VMM0
  { 2200,	3,	1,	4,	36,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, ImplicitList34, OperandInfo35, -1 ,nullptr },  // Inst #2200 = VMULU
  { 2201,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #2201 = VSHF_B
  { 2202,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #2202 = VSHF_D
  { 2203,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #2203 = VSHF_H
  { 2204,	4,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #2204 = VSHF_W
  { 2205,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2205 = WAIT
  { 2206,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #2206 = WAIT_MM
  { 2207,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #2207 = WAIT_MMR6
  { 2208,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2208 = WRDSP
  { 2209,	2,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #2209 = WRDSP_MM
  { 2210,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #2210 = WRPGPR_MMR6
  { 2211,	2,	1,	4,	169,	0, 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #2211 = WSBH
  { 2212,	2,	1,	4,	169,	0, 0x1ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #2212 = WSBH_MM
  { 2213,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #2213 = WSBH_MMR6
  { 2214,	3,	1,	4,	170,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2214 = XOR
  { 2215,	3,	1,	2,	170,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #2215 = XOR16_MM
  { 2216,	3,	1,	2,	170,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #2216 = XOR16_MMR6
  { 2217,	3,	1,	4,	170,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #2217 = XOR64
  { 2218,	3,	1,	4,	180,	0, 0x6ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #2218 = XORI_B
  { 2219,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2219 = XORI_MMR6
  { 2220,	3,	1,	4,	170,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2220 = XOR_MM
  { 2221,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2221 = XOR_MMR6
  { 2222,	3,	1,	4,	179,	0, 0x6ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #2222 = XOR_V
  { 2223,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #2223 = XOR_V_D_PSEUDO
  { 2224,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #2224 = XOR_V_H_PSEUDO
  { 2225,	3,	1,	4,	1,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #2225 = XOR_V_W_PSEUDO
  { 2226,	3,	1,	4,	171,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2226 = XORi
  { 2227,	3,	1,	4,	170,	0|(1ULL<<MCID::Rematerializable), 0x2ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #2227 = XORi64
  { 2228,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #2228 = XORi_MM
  { 2229,	3,	1,	2,	7,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #2229 = XorRxRxRy16
};

static inline void InitMipsMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(MipsInsts, NULL, NULL, 2230);
}

} // end llvm namespace 
#endif // GET_INSTRINFO_MC_DESC


#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER
namespace llvm_ks {
struct MipsGenInstrInfo : public TargetInstrInfo {
  explicit MipsGenInstrInfo(int CFSetupOpcode = -1, int CFDestroyOpcode = -1, int CatchRetOpcode = -1);
  ~MipsGenInstrInfo() override {}
};
} // end llvm namespace 
#endif // GET_INSTRINFO_HEADER


#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM
namespace llvm_ks {
namespace Mips {
namespace OpName { 
enum {
OPERAND_LAST
};
} // end namespace OpName
} // end namespace Mips
} // end namespace llvm_ks
#endif //GET_INSTRINFO_OPERAND_ENUM
#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS
namespace llvm_ks {
namespace Mips {
LLVM_READONLY
int16_t getNamedOperandIdx(uint16_t Opcode, uint16_t NamedIdx) {
  return -1;
}
} // end namespace Mips
} // end namespace llvm_ks
#endif //GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_OPERAND_TYPES_ENUM
#undef GET_INSTRINFO_OPERAND_TYPES_ENUM
namespace llvm_ks {
namespace Mips {
namespace OpTypes { 
enum OperandType {
  InvertedImOperand = 0,
  InvertedImOperand64 = 1,
  PtrRC = 2,
  brtarget = 3,
  brtarget10_mm = 4,
  brtarget21 = 5,
  brtarget26 = 6,
  brtarget26_mm = 7,
  brtarget7_mm = 8,
  brtarget_mm = 9,
  calloffset16 = 10,
  calltarget = 11,
  calltarget_mm = 12,
  condcode = 13,
  cpinst_operand = 14,
  f32imm = 15,
  f64imm = 16,
  i16imm = 17,
  i1imm = 18,
  i32imm = 19,
  i64imm = 20,
  i8imm = 21,
  imm32 = 22,
  imm64 = 23,
  jmpoffset16 = 24,
  jmptarget = 25,
  jmptarget_mm = 26,
  li_simm7 = 27,
  mem = 28,
  mem16 = 29,
  mem16_ea = 30,
  mem_ea = 31,
  mem_mm_12 = 32,
  mem_mm_16 = 33,
  mem_mm_4 = 34,
  mem_mm_4_lsl1 = 35,
  mem_mm_4_lsl2 = 36,
  mem_mm_4sp = 37,
  mem_mm_9 = 38,
  mem_mm_gp_imm7_lsl2 = 39,
  mem_mm_sp_imm5_lsl2 = 40,
  mem_msa = 41,
  mem_simm11 = 42,
  mem_simm16 = 43,
  mem_simm9 = 44,
  mem_simm9gpr = 45,
  movep_regpair = 46,
  pcrel16 = 47,
  reglist = 48,
  reglist16 = 49,
  regpair = 50,
  simm10 = 51,
  simm10_64 = 52,
  simm11 = 53,
  simm12 = 54,
  simm16 = 55,
  simm16_64 = 56,
  simm18_lsl3 = 57,
  simm19_lsl2 = 58,
  simm20 = 59,
  simm23_lsl2 = 60,
  simm32 = 61,
  simm3_lsa2 = 62,
  simm4 = 63,
  simm5 = 64,
  simm6 = 65,
  simm7 = 66,
  simm9 = 67,
  simm9_addiusp = 68,
  size_ins = 69,
  uimm1 = 70,
  uimm10 = 71,
  uimm16 = 72,
  uimm16_64 = 73,
  uimm16_64_relaxed = 74,
  uimm16_relaxed = 75,
  uimm2 = 76,
  uimm20 = 77,
  uimm2_plus1 = 78,
  uimm3 = 79,
  uimm3_shift = 80,
  uimm4 = 81,
  uimm4_andi = 82,
  uimm4_ptr = 83,
  uimm5 = 84,
  uimm5_64 = 85,
  uimm5_64_report_uimm6 = 86,
  uimm5_lsl2 = 87,
  uimm5_plus1 = 88,
  uimm5_plus32 = 89,
  uimm5_plus32_normalize = 90,
  uimm5_plus32_normalize_64 = 91,
  uimm5_plus33 = 92,
  uimm6 = 93,
  uimm6_lsl2 = 94,
  uimm6_ptr = 95,
  uimm7 = 96,
  uimm8 = 97,
  uimmz = 98,
  vsplat_simm10 = 99,
  vsplat_simm5 = 100,
  vsplat_uimm1 = 101,
  vsplat_uimm2 = 102,
  vsplat_uimm3 = 103,
  vsplat_uimm4 = 104,
  vsplat_uimm5 = 105,
  vsplat_uimm6 = 106,
  vsplat_uimm8 = 107,
  OPERAND_TYPE_LIST_END
};
} // end namespace OpTypes
} // end namespace Mips
} // end namespace llvm_ks
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM
#ifdef GET_INSTRMAP_INFO
#undef GET_INSTRMAP_INFO
namespace llvm_ks {

namespace Mips {

enum Arch {
	Arch_dsp,
	Arch_mmdsp,
	Arch_mipsr6,
	Arch_micromipsr6,
	Arch_se,
	Arch_micromips
};

// Dsp2MicroMips
LLVM_READONLY
int Dsp2MicroMips(uint16_t Opcode, enum Arch inArch) {
static const uint16_t Dsp2MicroMipsTable[][3] = {
  { Mips::ABSQ_S_PH, Mips::ABSQ_S_PH, Mips::ABSQ_S_PH_MM },
  { Mips::ABSQ_S_QB, Mips::ABSQ_S_QB, Mips::ABSQ_S_QB_MMR2 },
  { Mips::ABSQ_S_W, Mips::ABSQ_S_W, Mips::ABSQ_S_W_MM },
  { Mips::ADDQH_PH, Mips::ADDQH_PH, Mips::ADDQH_PH_MMR2 },
  { Mips::ADDQH_R_PH, Mips::ADDQH_R_PH, Mips::ADDQH_R_PH_MMR2 },
  { Mips::ADDQH_R_W, Mips::ADDQH_R_W, Mips::ADDQH_R_W_MMR2 },
  { Mips::ADDQH_W, Mips::ADDQH_W, Mips::ADDQH_W_MMR2 },
  { Mips::ADDQ_PH, Mips::ADDQ_PH, Mips::ADDQ_PH_MM },
  { Mips::ADDQ_S_PH, Mips::ADDQ_S_PH, Mips::ADDQ_S_PH_MM },
  { Mips::ADDQ_S_W, Mips::ADDQ_S_W, Mips::ADDQ_S_W_MM },
  { Mips::ADDSC, Mips::ADDSC, Mips::ADDSC_MM },
  { Mips::ADDUH_QB, Mips::ADDUH_QB, Mips::ADDUH_QB_MMR2 },
  { Mips::ADDUH_R_QB, Mips::ADDUH_R_QB, Mips::ADDUH_R_QB_MMR2 },
  { Mips::ADDU_PH, Mips::ADDU_PH, Mips::ADDU_PH_MMR2 },
  { Mips::ADDU_QB, Mips::ADDU_QB, Mips::ADDU_QB_MM },
  { Mips::ADDU_S_PH, Mips::ADDU_S_PH, Mips::ADDU_S_PH_MMR2 },
  { Mips::ADDU_S_QB, Mips::ADDU_S_QB, Mips::ADDU_S_QB_MM },
  { Mips::ADDWC, Mips::ADDWC, Mips::ADDWC_MM },
  { Mips::DPAQX_SA_W_PH, Mips::DPAQX_SA_W_PH, Mips::DPAQX_SA_W_PH_MMR2 },
  { Mips::DPAQX_S_W_PH, Mips::DPAQX_S_W_PH, Mips::DPAQX_S_W_PH_MMR2 },
  { Mips::DPAQ_SA_L_W, Mips::DPAQ_SA_L_W, Mips::DPAQ_SA_L_W_MM },
  { Mips::DPAQ_S_W_PH, Mips::DPAQ_S_W_PH, Mips::DPAQ_S_W_PH_MM },
  { Mips::DPAU_H_QBL, Mips::DPAU_H_QBL, Mips::DPAU_H_QBL_MM },
  { Mips::DPAU_H_QBR, Mips::DPAU_H_QBR, Mips::DPAU_H_QBR_MM },
  { Mips::DPAX_W_PH, Mips::DPAX_W_PH, Mips::DPAX_W_PH_MMR2 },
  { Mips::DPA_W_PH, Mips::DPA_W_PH, Mips::DPA_W_PH_MMR2 },
  { Mips::DPSQX_SA_W_PH, Mips::DPSQX_SA_W_PH, Mips::DPSQX_SA_W_PH_MMR2 },
  { Mips::DPSQX_S_W_PH, Mips::DPSQX_S_W_PH, Mips::DPSQX_S_W_PH_MMR2 },
  { Mips::DPSQ_SA_L_W, Mips::DPSQ_SA_L_W, Mips::DPSQ_SA_L_W_MM },
  { Mips::DPSQ_S_W_PH, Mips::DPSQ_S_W_PH, Mips::DPSQ_S_W_PH_MM },
  { Mips::DPSU_H_QBL, Mips::DPSU_H_QBL, Mips::DPSU_H_QBL_MM },
  { Mips::DPSU_H_QBR, Mips::DPSU_H_QBR, Mips::DPSU_H_QBR_MM },
  { Mips::DPSX_W_PH, Mips::DPSX_W_PH, Mips::DPSX_W_PH_MMR2 },
  { Mips::DPS_W_PH, Mips::DPS_W_PH, Mips::DPS_W_PH_MMR2 },
  { Mips::EXTP, Mips::EXTP, Mips::EXTP_MM },
  { Mips::EXTPDP, Mips::EXTPDP, Mips::EXTPDP_MM },
  { Mips::EXTPDPV, Mips::EXTPDPV, Mips::EXTPDPV_MM },
  { Mips::EXTPV, Mips::EXTPV, Mips::EXTPV_MM },
  { Mips::EXTRV_RS_W, Mips::EXTRV_RS_W, Mips::EXTRV_RS_W_MM },
  { Mips::EXTRV_R_W, Mips::EXTRV_R_W, Mips::EXTRV_R_W_MM },
  { Mips::EXTRV_S_H, Mips::EXTRV_S_H, Mips::EXTRV_S_H_MM },
  { Mips::EXTRV_W, Mips::EXTRV_W, Mips::EXTRV_W_MM },
  { Mips::EXTR_RS_W, Mips::EXTR_RS_W, Mips::EXTR_RS_W_MM },
  { Mips::EXTR_R_W, Mips::EXTR_R_W, Mips::EXTR_R_W_MM },
  { Mips::EXTR_S_H, Mips::EXTR_S_H, Mips::EXTR_S_H_MM },
  { Mips::EXTR_W, Mips::EXTR_W, Mips::EXTR_W_MM },
  { Mips::INSV, Mips::INSV, Mips::INSV_MM },
  { Mips::LBUX, Mips::LBUX, Mips::LBUX_MM },
  { Mips::LHX, Mips::LHX, Mips::LHX_MM },
  { Mips::LWX, Mips::LWX, Mips::LWX_MM },
  { Mips::MADDU_DSP, Mips::MADDU_DSP, Mips::MADDU_DSP_MM },
  { Mips::MADD_DSP, Mips::MADD_DSP, Mips::MADD_DSP_MM },
  { Mips::MAQ_SA_W_PHL, Mips::MAQ_SA_W_PHL, Mips::MAQ_SA_W_PHL_MM },
  { Mips::MAQ_SA_W_PHR, Mips::MAQ_SA_W_PHR, Mips::MAQ_SA_W_PHR_MM },
  { Mips::MAQ_S_W_PHL, Mips::MAQ_S_W_PHL, Mips::MAQ_S_W_PHL_MM },
  { Mips::MAQ_S_W_PHR, Mips::MAQ_S_W_PHR, Mips::MAQ_S_W_PHR_MM },
  { Mips::MFHI_DSP, Mips::MFHI_DSP, Mips::MFHI_DSP_MM },
  { Mips::MFLO_DSP, Mips::MFLO_DSP, Mips::MFLO_DSP_MM },
  { Mips::MSUBU_DSP, Mips::MSUBU_DSP, Mips::MSUBU_DSP_MM },
  { Mips::MSUB_DSP, Mips::MSUB_DSP, Mips::MSUB_DSP_MM },
  { Mips::MTHI_DSP, Mips::MTHI_DSP, Mips::MTHI_DSP_MM },
  { Mips::MTHLIP, Mips::MTHLIP, Mips::MTHLIP_MM },
  { Mips::MTLO_DSP, Mips::MTLO_DSP, Mips::MTLO_DSP_MM },
  { Mips::MULEQ_S_W_PHL, Mips::MULEQ_S_W_PHL, Mips::MULEQ_S_W_PHL_MM },
  { Mips::MULEQ_S_W_PHR, Mips::MULEQ_S_W_PHR, Mips::MULEQ_S_W_PHR_MM },
  { Mips::MULEU_S_PH_QBL, Mips::MULEU_S_PH_QBL, Mips::MULEU_S_PH_QBL_MM },
  { Mips::MULEU_S_PH_QBR, Mips::MULEU_S_PH_QBR, Mips::MULEU_S_PH_QBR_MM },
  { Mips::MULQ_RS_PH, Mips::MULQ_RS_PH, Mips::MULQ_RS_PH_MM },
  { Mips::MULQ_RS_W, Mips::MULQ_RS_W, Mips::MULQ_RS_W_MMR2 },
  { Mips::MULQ_S_PH, Mips::MULQ_S_PH, Mips::MULQ_S_PH_MMR2 },
  { Mips::MULQ_S_W, Mips::MULQ_S_W, Mips::MULQ_S_W_MMR2 },
  { Mips::MULTU_DSP, Mips::MULTU_DSP, Mips::MULTU_DSP_MM },
  { Mips::MULT_DSP, Mips::MULT_DSP, Mips::MULT_DSP_MM },
  { Mips::MUL_PH, Mips::MUL_PH, Mips::MUL_PH_MMR2 },
  { Mips::MUL_S_PH, Mips::MUL_S_PH, Mips::MUL_S_PH_MMR2 },
  { Mips::PACKRL_PH, Mips::PACKRL_PH, Mips::PACKRL_PH_MM },
  { Mips::PICK_PH, Mips::PICK_PH, Mips::PICK_PH_MM },
  { Mips::PICK_QB, Mips::PICK_QB, Mips::PICK_QB_MM },
  { Mips::PRECEQU_PH_QBL, Mips::PRECEQU_PH_QBL, Mips::PRECEQU_PH_QBL_MM },
  { Mips::PRECEQU_PH_QBLA, Mips::PRECEQU_PH_QBLA, Mips::PRECEQU_PH_QBLA_MM },
  { Mips::PRECEQU_PH_QBR, Mips::PRECEQU_PH_QBR, Mips::PRECEQU_PH_QBR_MM },
  { Mips::PRECEQU_PH_QBRA, Mips::PRECEQU_PH_QBRA, Mips::PRECEQU_PH_QBRA_MM },
  { Mips::PRECEQ_W_PHL, Mips::PRECEQ_W_PHL, Mips::PRECEQ_W_PHL_MM },
  { Mips::PRECEQ_W_PHR, Mips::PRECEQ_W_PHR, Mips::PRECEQ_W_PHR_MM },
  { Mips::PRECEU_PH_QBL, Mips::PRECEU_PH_QBL, Mips::PRECEU_PH_QBL_MM },
  { Mips::PRECEU_PH_QBLA, Mips::PRECEU_PH_QBLA, Mips::PRECEU_PH_QBLA_MM },
  { Mips::PRECEU_PH_QBR, Mips::PRECEU_PH_QBR, Mips::PRECEU_PH_QBR_MM },
  { Mips::PRECEU_PH_QBRA, Mips::PRECEU_PH_QBRA, Mips::PRECEU_PH_QBRA_MM },
  { Mips::PRECRQU_S_QB_PH, Mips::PRECRQU_S_QB_PH, Mips::PRECRQU_S_QB_PH_MM },
  { Mips::PRECRQ_PH_W, Mips::PRECRQ_PH_W, Mips::PRECRQ_PH_W_MM },
  { Mips::PRECRQ_QB_PH, Mips::PRECRQ_QB_PH, Mips::PRECRQ_QB_PH_MM },
  { Mips::PRECRQ_RS_PH_W, Mips::PRECRQ_RS_PH_W, Mips::PRECRQ_RS_PH_W_MM },
  { Mips::PRECR_QB_PH, Mips::PRECR_QB_PH, Mips::PRECR_QB_PH_MMR2 },
  { Mips::PRECR_SRA_PH_W, Mips::PRECR_SRA_PH_W, Mips::PRECR_SRA_PH_W_MMR2 },
  { Mips::PRECR_SRA_R_PH_W, Mips::PRECR_SRA_R_PH_W, Mips::PRECR_SRA_R_PH_W_MMR2 },
  { Mips::PREPEND, Mips::PREPEND, Mips::PREPEND_MMR2 },
  { Mips::RADDU_W_QB, Mips::RADDU_W_QB, Mips::RADDU_W_QB_MM },
  { Mips::RDDSP, Mips::RDDSP, Mips::RDDSP_MM },
  { Mips::REPLV_PH, Mips::REPLV_PH, Mips::REPLV_PH_MM },
  { Mips::REPLV_QB, Mips::REPLV_QB, Mips::REPLV_QB_MM },
  { Mips::REPL_PH, Mips::REPL_PH, Mips::REPL_PH_MM },
  { Mips::REPL_QB, Mips::REPL_QB, Mips::REPL_QB_MM },
  { Mips::SHILO, Mips::SHILO, Mips::SHILO_MM },
  { Mips::SHILOV, Mips::SHILOV, Mips::SHILOV_MM },
  { Mips::SHLLV_PH, Mips::SHLLV_PH, Mips::SHLLV_PH_MM },
  { Mips::SHLLV_QB, Mips::SHLLV_QB, Mips::SHLLV_QB_MM },
  { Mips::SHLLV_S_PH, Mips::SHLLV_S_PH, Mips::SHLLV_S_PH_MM },
  { Mips::SHLLV_S_W, Mips::SHLLV_S_W, Mips::SHLLV_S_W_MM },
  { Mips::SHLL_PH, Mips::SHLL_PH, Mips::SHLL_PH_MM },
  { Mips::SHLL_QB, Mips::SHLL_QB, Mips::SHLL_QB_MM },
  { Mips::SHLL_S_PH, Mips::SHLL_S_PH, Mips::SHLL_S_PH_MM },
  { Mips::SHLL_S_W, Mips::SHLL_S_W, Mips::SHLL_S_W_MM },
  { Mips::SHRAV_PH, Mips::SHRAV_PH, Mips::SHRAV_PH_MM },
  { Mips::SHRAV_QB, Mips::SHRAV_QB, Mips::SHRAV_QB_MMR2 },
  { Mips::SHRAV_R_PH, Mips::SHRAV_R_PH, Mips::SHRAV_R_PH_MM },
  { Mips::SHRAV_R_QB, Mips::SHRAV_R_QB, Mips::SHRAV_R_QB_MMR2 },
  { Mips::SHRAV_R_W, Mips::SHRAV_R_W, Mips::SHRAV_R_W_MM },
  { Mips::SHRA_PH, Mips::SHRA_PH, Mips::SHRA_PH_MM },
  { Mips::SHRA_QB, Mips::SHRA_QB, Mips::SHRA_QB_MMR2 },
  { Mips::SHRA_R_PH, Mips::SHRA_R_PH, Mips::SHRA_R_PH_MM },
  { Mips::SHRA_R_QB, Mips::SHRA_R_QB, Mips::SHRA_R_QB_MMR2 },
  { Mips::SHRA_R_W, Mips::SHRA_R_W, Mips::SHRA_R_W_MM },
  { Mips::SHRLV_PH, Mips::SHRLV_PH, Mips::SHRLV_PH_MMR2 },
  { Mips::SHRLV_QB, Mips::SHRLV_QB, Mips::SHRLV_QB_MM },
  { Mips::SHRL_PH, Mips::SHRL_PH, Mips::SHRL_PH_MMR2 },
  { Mips::SHRL_QB, Mips::SHRL_QB, Mips::SHRL_QB_MM },
  { Mips::SUBQH_PH, Mips::SUBQH_PH, Mips::SUBQH_PH_MMR2 },
  { Mips::SUBQH_R_PH, Mips::SUBQH_R_PH, Mips::SUBQH_R_PH_MMR2 },
  { Mips::SUBQH_R_W, Mips::SUBQH_R_W, Mips::SUBQH_R_W_MMR2 },
  { Mips::SUBQH_W, Mips::SUBQH_W, Mips::SUBQH_W_MMR2 },
  { Mips::SUBQ_PH, Mips::SUBQ_PH, Mips::SUBQ_PH_MM },
  { Mips::SUBQ_S_PH, Mips::SUBQ_S_PH, Mips::SUBQ_S_PH_MM },
  { Mips::SUBQ_S_W, Mips::SUBQ_S_W, Mips::SUBQ_S_W_MM },
  { Mips::SUBUH_QB, Mips::SUBUH_QB, Mips::SUBUH_QB_MMR2 },
  { Mips::SUBUH_R_QB, Mips::SUBUH_R_QB, Mips::SUBUH_R_QB_MMR2 },
  { Mips::SUBU_PH, Mips::SUBU_PH, Mips::SUBU_PH_MMR2 },
  { Mips::SUBU_QB, Mips::SUBU_QB, Mips::SUBU_QB_MM },
  { Mips::SUBU_S_PH, Mips::SUBU_S_PH, Mips::SUBU_S_PH_MMR2 },
  { Mips::SUBU_S_QB, Mips::SUBU_S_QB, Mips::SUBU_S_QB_MM },
}; // End of Dsp2MicroMipsTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 139;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == Dsp2MicroMipsTable[mid][0]) {
      break;
    }
    if (Opcode < Dsp2MicroMipsTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inArch == Arch_dsp)
    return Dsp2MicroMipsTable[mid][1];
  if (inArch == Arch_mmdsp)
    return Dsp2MicroMipsTable[mid][2];
  return -1;}

// MipsR62MicroMipsR6
LLVM_READONLY
int MipsR62MicroMipsR6(uint16_t Opcode, enum Arch inArch) {
static const uint16_t MipsR62MicroMipsR6Table[][3] = {
  { Mips::ADDIUPC, Mips::ADDIUPC, Mips::ADDIUPC_MMR6 },
  { Mips::ALIGN, Mips::ALIGN, Mips::ALIGN_MMR6 },
  { Mips::ALUIPC, Mips::ALUIPC, Mips::ALUIPC_MMR6 },
  { Mips::AUI, Mips::AUI, Mips::AUI_MMR6 },
  { Mips::AUIPC, Mips::AUIPC, Mips::AUIPC_MMR6 },
  { Mips::BALC, Mips::BALC, Mips::BALC_MMR6 },
  { Mips::BC, Mips::BC, Mips::BC_MMR6 },
  { Mips::BEQZALC, Mips::BEQZALC, Mips::BEQZALC_MMR6 },
  { Mips::BGEZALC, Mips::BGEZALC, Mips::BGEZALC_MMR6 },
  { Mips::BGTZALC, Mips::BGTZALC, Mips::BGTZALC_MMR6 },
  { Mips::BITSWAP, Mips::BITSWAP, Mips::BITSWAP_MMR6 },
  { Mips::BLEZALC, Mips::BLEZALC, Mips::BLEZALC_MMR6 },
  { Mips::BLTZALC, Mips::BLTZALC, Mips::BLTZALC_MMR6 },
  { Mips::BNEZALC, Mips::BNEZALC, Mips::BNEZALC_MMR6 },
  { Mips::CACHE_R6, Mips::CACHE_R6, Mips::CACHE_MMR6 },
  { Mips::CLO_R6, Mips::CLO_R6, Mips::CLO_MMR6 },
  { Mips::CLZ_R6, Mips::CLZ_R6, Mips::CLZ_MMR6 },
  { Mips::DIV, Mips::DIV, Mips::DIV_MMR6 },
  { Mips::DIVU, Mips::DIVU, Mips::DIVU_MMR6 },
  { Mips::JIALC, Mips::JIALC, Mips::JIALC_MMR6 },
  { Mips::JIC, Mips::JIC, Mips::JIC_MMR6 },
  { Mips::LSA_R6, Mips::LSA_R6, Mips::LSA_MMR6 },
  { Mips::LWPC, Mips::LWPC, Mips::LWPC_MMR6 },
  { Mips::MOD, Mips::MOD, Mips::MOD_MMR6 },
  { Mips::MODU, Mips::MODU, Mips::MODU_MMR6 },
  { Mips::MUH, Mips::MUH, Mips::MUH_MMR6 },
  { Mips::MUHU, Mips::MUHU, Mips::MUHU_MMR6 },
  { Mips::MULU, Mips::MULU, Mips::MULU_MMR6 },
  { Mips::MUL_R6, Mips::MUL_R6, Mips::MUL_MMR6 },
  { Mips::PREF_R6, Mips::PREF_R6, Mips::PREF_MMR6 },
  { Mips::SELEQZ, Mips::SELEQZ, Mips::SELEQZ_MMR6 },
  { Mips::SELNEZ, Mips::SELNEZ, Mips::SELNEZ_MMR6 },
}; // End of MipsR62MicroMipsR6Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 32;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == MipsR62MicroMipsR6Table[mid][0]) {
      break;
    }
    if (Opcode < MipsR62MicroMipsR6Table[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inArch == Arch_mipsr6)
    return MipsR62MicroMipsR6Table[mid][1];
  if (inArch == Arch_micromipsr6)
    return MipsR62MicroMipsR6Table[mid][2];
  return -1;}

// Std2MicroMips
LLVM_READONLY
int Std2MicroMips(uint16_t Opcode, enum Arch inArch) {
static const uint16_t Std2MicroMipsTable[][3] = {
  { Mips::ADD, Mips::ADD, Mips::ADD_MM },
  { Mips::ADDi, Mips::ADDi, Mips::ADDi_MM },
  { Mips::ADDiu, Mips::ADDiu, Mips::ADDiu_MM },
  { Mips::ADDu, Mips::ADDu, Mips::ADDu_MM },
  { Mips::AND, Mips::AND, Mips::AND_MM },
  { Mips::ANDi, Mips::ANDi, Mips::ANDi_MM },
  { Mips::BC1F, Mips::BC1F, Mips::BC1F_MM },
  { Mips::BC1FL, Mips::BC1FL, (uint16_t)-1U },
  { Mips::BC1T, Mips::BC1T, Mips::BC1T_MM },
  { Mips::BC1TL, Mips::BC1TL, (uint16_t)-1U },
  { Mips::BEQ, Mips::BEQ, Mips::BEQ_MM },
  { Mips::BEQL, Mips::BEQL, (uint16_t)-1U },
  { Mips::BGEZ, Mips::BGEZ, Mips::BGEZ_MM },
  { Mips::BGEZAL, Mips::BGEZAL, Mips::BGEZAL_MM },
  { Mips::BGEZALL, Mips::BGEZALL, (uint16_t)-1U },
  { Mips::BGEZL, Mips::BGEZL, (uint16_t)-1U },
  { Mips::BGTZ, Mips::BGTZ, Mips::BGTZ_MM },
  { Mips::BGTZL, Mips::BGTZL, (uint16_t)-1U },
  { Mips::BLEZ, Mips::BLEZ, Mips::BLEZ_MM },
  { Mips::BLEZL, Mips::BLEZL, (uint16_t)-1U },
  { Mips::BLTZ, Mips::BLTZ, Mips::BLTZ_MM },
  { Mips::BLTZAL, Mips::BLTZAL, Mips::BLTZAL_MM },
  { Mips::BLTZALL, Mips::BLTZALL, (uint16_t)-1U },
  { Mips::BLTZL, Mips::BLTZL, (uint16_t)-1U },
  { Mips::BNE, Mips::BNE, Mips::BNE_MM },
  { Mips::BNEL, Mips::BNEL, (uint16_t)-1U },
  { Mips::BREAK, Mips::BREAK, Mips::BREAK_MM },
  { Mips::CACHE, Mips::CACHE, Mips::CACHE_MM },
  { Mips::CEIL_W_D32, Mips::CEIL_W_D32, Mips::CEIL_W_MM },
  { Mips::CEIL_W_S, Mips::CEIL_W_S, Mips::CEIL_W_S_MM },
  { Mips::CFC1, Mips::CFC1, Mips::CFC1_MM },
  { Mips::CLO, Mips::CLO, Mips::CLO_MM },
  { Mips::CLZ, Mips::CLZ, Mips::CLZ_MM },
  { Mips::CTC1, Mips::CTC1, Mips::CTC1_MM },
  { Mips::CVT_D32_S, Mips::CVT_D32_S, Mips::CVT_D_S_MM },
  { Mips::CVT_D32_W, Mips::CVT_D32_W, Mips::CVT_D32_W_MM },
  { Mips::CVT_L_D64, Mips::CVT_L_D64, Mips::CVT_L_D64_MM },
  { Mips::CVT_L_S, Mips::CVT_L_S, Mips::CVT_L_S_MM },
  { Mips::CVT_S_D32, Mips::CVT_S_D32, Mips::CVT_S_D32_MM },
  { Mips::CVT_S_W, Mips::CVT_S_W, Mips::CVT_S_W_MM },
  { Mips::CVT_W_D32, Mips::CVT_W_D32, Mips::CVT_W_MM },
  { Mips::CVT_W_S, Mips::CVT_W_S, Mips::CVT_W_S_MM },
  { Mips::DERET, Mips::DERET, Mips::DERET_MM },
  { Mips::DI, Mips::DI, Mips::DI_MM },
  { Mips::EHB, Mips::EHB, Mips::EHB_MM },
  { Mips::EI, Mips::EI, Mips::EI_MM },
  { Mips::ERET, Mips::ERET, Mips::ERET_MM },
  { Mips::ERETNC, Mips::ERETNC, (uint16_t)-1U },
  { Mips::EXT, Mips::EXT, Mips::EXT_MM },
  { Mips::FABS_D32, Mips::FABS_D32, Mips::FABS_MM },
  { Mips::FABS_S, Mips::FABS_S, Mips::FABS_S_MM },
  { Mips::FADD_D32, Mips::FADD_D32, Mips::FADD_MM },
  { Mips::FADD_S, Mips::FADD_S, Mips::FADD_S_MM },
  { Mips::FCMP_D32, Mips::FCMP_D32, Mips::FCMP_D32_MM },
  { Mips::FCMP_S32, Mips::FCMP_S32, Mips::FCMP_S32_MM },
  { Mips::FDIV_D32, Mips::FDIV_D32, Mips::FDIV_MM },
  { Mips::FDIV_S, Mips::FDIV_S, Mips::FDIV_S_MM },
  { Mips::FLOOR_W_D32, Mips::FLOOR_W_D32, Mips::FLOOR_W_MM },
  { Mips::FLOOR_W_S, Mips::FLOOR_W_S, Mips::FLOOR_W_S_MM },
  { Mips::FMOV_D32, Mips::FMOV_D32, Mips::FMOV_D32_MM },
  { Mips::FMOV_S, Mips::FMOV_S, Mips::FMOV_S_MM },
  { Mips::FMUL_D32, Mips::FMUL_D32, Mips::FMUL_MM },
  { Mips::FMUL_S, Mips::FMUL_S, Mips::FMUL_S_MM },
  { Mips::FNEG_D32, Mips::FNEG_D32, Mips::FNEG_MM },
  { Mips::FNEG_S, Mips::FNEG_S, Mips::FNEG_S_MM },
  { Mips::FSQRT_D32, Mips::FSQRT_D32, Mips::FSQRT_MM },
  { Mips::FSQRT_S, Mips::FSQRT_S, Mips::FSQRT_S_MM },
  { Mips::FSUB_D32, Mips::FSUB_D32, Mips::FSUB_MM },
  { Mips::FSUB_S, Mips::FSUB_S, Mips::FSUB_S_MM },
  { Mips::INS, Mips::INS, Mips::INS_MM },
  { Mips::J, Mips::J, Mips::J_MM },
  { Mips::JAL, Mips::JAL, Mips::JAL_MM },
  { Mips::JALX, Mips::JALX, Mips::JALX_MM },
  { Mips::JR, Mips::JR, Mips::JR_MM },
  { Mips::LB, Mips::LB, Mips::LB_MM },
  { Mips::LBu, Mips::LBu, Mips::LBu_MM },
  { Mips::LDC1, Mips::LDC1, Mips::LDC1_MM },
  { Mips::LEA_ADDiu, Mips::LEA_ADDiu, Mips::LEA_ADDiu_MM },
  { Mips::LH, Mips::LH, Mips::LH_MM },
  { Mips::LHu, Mips::LHu, Mips::LHu_MM },
  { Mips::LUXC1, Mips::LUXC1, Mips::LUXC1_MM },
  { Mips::LUi, Mips::LUi, Mips::LUi_MM },
  { Mips::LW, Mips::LW, Mips::LW_MM },
  { Mips::LWC1, Mips::LWC1, Mips::LWC1_MM },
  { Mips::LWXC1, Mips::LWXC1, Mips::LWXC1_MM },
  { Mips::MADD, Mips::MADD, Mips::MADD_MM },
  { Mips::MADDU, Mips::MADDU, Mips::MADDU_MM },
  { Mips::MADD_D32, Mips::MADD_D32, Mips::MADD_D32_MM },
  { Mips::MADD_S, Mips::MADD_S, Mips::MADD_S_MM },
  { Mips::MFC1, Mips::MFC1, Mips::MFC1_MM },
  { Mips::MFHC1_D32, Mips::MFHC1_D32, Mips::MFHC1_MM },
  { Mips::MFHI, Mips::MFHI, Mips::MFHI_MM },
  { Mips::MFLO, Mips::MFLO, Mips::MFLO_MM },
  { Mips::MOVF_D32, Mips::MOVF_D32, Mips::MOVF_D32_MM },
  { Mips::MOVF_I, Mips::MOVF_I, Mips::MOVF_I_MM },
  { Mips::MOVF_S, Mips::MOVF_S, Mips::MOVF_S_MM },
  { Mips::MOVN_I_D32, Mips::MOVN_I_D32, Mips::MOVN_I_D32_MM },
  { Mips::MOVN_I_I, Mips::MOVN_I_I, Mips::MOVN_I_MM },
  { Mips::MOVN_I_S, Mips::MOVN_I_S, Mips::MOVN_I_S_MM },
  { Mips::MOVT_D32, Mips::MOVT_D32, Mips::MOVT_D32_MM },
  { Mips::MOVT_I, Mips::MOVT_I, Mips::MOVT_I_MM },
  { Mips::MOVT_S, Mips::MOVT_S, Mips::MOVT_S_MM },
  { Mips::MOVZ_I_D32, Mips::MOVZ_I_D32, Mips::MOVZ_I_D32_MM },
  { Mips::MOVZ_I_I, Mips::MOVZ_I_I, Mips::MOVZ_I_MM },
  { Mips::MOVZ_I_S, Mips::MOVZ_I_S, Mips::MOVZ_I_S_MM },
  { Mips::MSUB, Mips::MSUB, Mips::MSUB_MM },
  { Mips::MSUBU, Mips::MSUBU, Mips::MSUBU_MM },
  { Mips::MSUB_D32, Mips::MSUB_D32, Mips::MSUB_D32_MM },
  { Mips::MSUB_S, Mips::MSUB_S, Mips::MSUB_S_MM },
  { Mips::MTC1, Mips::MTC1, Mips::MTC1_MM },
  { Mips::MTHC1_D32, Mips::MTHC1_D32, Mips::MTHC1_MM },
  { Mips::MTHI, Mips::MTHI, Mips::MTHI_MM },
  { Mips::MTLO, Mips::MTLO, Mips::MTLO_MM },
  { Mips::MUL, Mips::MUL, Mips::MUL_MM },
  { Mips::MULT, Mips::MULT, Mips::MULT_MM },
  { Mips::MULTu, Mips::MULTu, Mips::MULTu_MM },
  { Mips::NMADD_D32, Mips::NMADD_D32, Mips::NMADD_D32_MM },
  { Mips::NMADD_S, Mips::NMADD_S, Mips::NMADD_S_MM },
  { Mips::NMSUB_D32, Mips::NMSUB_D32, Mips::NMSUB_D32_MM },
  { Mips::NMSUB_S, Mips::NMSUB_S, Mips::NMSUB_S_MM },
  { Mips::NOR, Mips::NOR, Mips::NOR_MM },
  { Mips::OR, Mips::OR, Mips::OR_MM },
  { Mips::ORi, Mips::ORi, Mips::ORi_MM },
  { Mips::PAUSE, Mips::PAUSE, Mips::PAUSE_MM },
  { Mips::PREF, Mips::PREF, Mips::PREF_MM },
  { Mips::RDHWR, Mips::RDHWR, Mips::RDHWR_MM },
  { Mips::ROTR, Mips::ROTR, Mips::ROTR_MM },
  { Mips::ROTRV, Mips::ROTRV, Mips::ROTRV_MM },
  { Mips::ROUND_W_D32, Mips::ROUND_W_D32, Mips::ROUND_W_MM },
  { Mips::ROUND_W_S, Mips::ROUND_W_S, Mips::ROUND_W_S_MM },
  { Mips::SB, Mips::SB, Mips::SB_MM },
  { Mips::SDBBP, Mips::SDBBP, Mips::SDBBP_MM },
  { Mips::SDC1, Mips::SDC1, Mips::SDC1_MM },
  { Mips::SDIV, Mips::SDIV, Mips::SDIV_MM },
  { Mips::SEB, Mips::SEB, Mips::SEB_MM },
  { Mips::SEH, Mips::SEH, Mips::SEH_MM },
  { Mips::SH, Mips::SH, Mips::SH_MM },
  { Mips::SLL, Mips::SLL, Mips::SLL_MM },
  { Mips::SLLV, Mips::SLLV, Mips::SLLV_MM },
  { Mips::SLT, Mips::SLT, Mips::SLT_MM },
  { Mips::SLTi, Mips::SLTi, Mips::SLTi_MM },
  { Mips::SLTiu, Mips::SLTiu, Mips::SLTiu_MM },
  { Mips::SLTu, Mips::SLTu, Mips::SLTu_MM },
  { Mips::SRA, Mips::SRA, Mips::SRA_MM },
  { Mips::SRAV, Mips::SRAV, Mips::SRAV_MM },
  { Mips::SRL, Mips::SRL, Mips::SRL_MM },
  { Mips::SRLV, Mips::SRLV, Mips::SRLV_MM },
  { Mips::SSNOP, Mips::SSNOP, Mips::SSNOP_MM },
  { Mips::SUB, Mips::SUB, Mips::SUB_MM },
  { Mips::SUBu, Mips::SUBu, Mips::SUBu_MM },
  { Mips::SUXC1, Mips::SUXC1, Mips::SUXC1_MM },
  { Mips::SW, Mips::SW, Mips::SW_MM },
  { Mips::SWC1, Mips::SWC1, Mips::SWC1_MM },
  { Mips::SWXC1, Mips::SWXC1, Mips::SWXC1_MM },
  { Mips::SYNC, Mips::SYNC, Mips::SYNC_MM },
  { Mips::SYNCI, Mips::SYNCI, (uint16_t)-1U },
  { Mips::SYSCALL, Mips::SYSCALL, Mips::SYSCALL_MM },
  { Mips::TEQ, Mips::TEQ, Mips::TEQ_MM },
  { Mips::TEQI, Mips::TEQI, Mips::TEQI_MM },
  { Mips::TGE, Mips::TGE, Mips::TGE_MM },
  { Mips::TGEI, Mips::TGEI, Mips::TGEI_MM },
  { Mips::TGEIU, Mips::TGEIU, Mips::TGEIU_MM },
  { Mips::TGEU, Mips::TGEU, Mips::TGEU_MM },
  { Mips::TLBP, Mips::TLBP, Mips::TLBP_MM },
  { Mips::TLBR, Mips::TLBR, Mips::TLBR_MM },
  { Mips::TLBWI, Mips::TLBWI, Mips::TLBWI_MM },
  { Mips::TLBWR, Mips::TLBWR, Mips::TLBWR_MM },
  { Mips::TLT, Mips::TLT, Mips::TLT_MM },
  { Mips::TLTI, Mips::TLTI, Mips::TLTI_MM },
  { Mips::TLTU, Mips::TLTU, Mips::TLTU_MM },
  { Mips::TNE, Mips::TNE, Mips::TNE_MM },
  { Mips::TNEI, Mips::TNEI, Mips::TNEI_MM },
  { Mips::TRUNC_W_D32, Mips::TRUNC_W_D32, Mips::TRUNC_W_MM },
  { Mips::TRUNC_W_S, Mips::TRUNC_W_S, Mips::TRUNC_W_S_MM },
  { Mips::TTLTIU, Mips::TTLTIU, Mips::TLTIU_MM },
  { Mips::UDIV, Mips::UDIV, Mips::UDIV_MM },
  { Mips::WSBH, Mips::WSBH, Mips::WSBH_MM },
  { Mips::XOR, Mips::XOR, Mips::XOR_MM },
  { Mips::XORi, Mips::XORi, Mips::XORi_MM },
}; // End of Std2MicroMipsTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 179;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == Std2MicroMipsTable[mid][0]) {
      break;
    }
    if (Opcode < Std2MicroMipsTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inArch == Arch_se)
    return Std2MicroMipsTable[mid][1];
  if (inArch == Arch_micromips)
    return Std2MicroMipsTable[mid][2];
  return -1;}

// Std2MicroMipsR6
LLVM_READONLY
int Std2MicroMipsR6(uint16_t Opcode, enum Arch inArch) {
static const uint16_t Std2MicroMipsR6Table[][3] = {
  { Mips::ADD, Mips::ADD, Mips::ADD_MMR6 },
  { Mips::ADDiu, Mips::ADDiu, Mips::ADDIU_MMR6 },
  { Mips::ADDu, Mips::ADDu, Mips::ADDU_MMR6 },
  { Mips::AND, Mips::AND, Mips::AND_MMR6 },
  { Mips::ANDi, Mips::ANDi, Mips::ANDI_MMR6 },
  { Mips::BREAK, Mips::BREAK, Mips::BREAK_MMR6 },
  { Mips::CEIL_W_D64, Mips::CEIL_W_D64, Mips::CEIL_W_D_MMR6 },
  { Mips::CEIL_W_S, Mips::CEIL_W_S, Mips::CEIL_W_S_MMR6 },
  { Mips::CVT_W_D64, Mips::CVT_W_D64, Mips::CVT_W_D_MMR6 },
  { Mips::DI, Mips::DI, Mips::DI_MMR6 },
  { Mips::EI, Mips::EI, Mips::EI_MMR6 },
  { Mips::FLOOR_W_D64, Mips::FLOOR_W_D64, Mips::FLOOR_W_D_MMR6 },
  { Mips::FLOOR_W_S, Mips::FLOOR_W_S, Mips::FLOOR_W_S_MMR6 },
  { Mips::FSQRT_S, Mips::FSQRT_S, Mips::SQRT_S_MMR6 },
  { Mips::LW, Mips::LW, Mips::LW_MMR6 },
  { Mips::NOR, Mips::NOR, Mips::NOR_MMR6 },
  { Mips::OR, Mips::OR, Mips::OR_MMR6 },
  { Mips::ORi, Mips::ORi, Mips::ORI_MMR6 },
  { Mips::PAUSE, Mips::PAUSE, Mips::PAUSE_MMR6 },
  { Mips::ROUND_W_D64, Mips::ROUND_W_D64, Mips::ROUND_W_D_MMR6 },
  { Mips::ROUND_W_S, Mips::ROUND_W_S, Mips::ROUND_W_S_MMR6 },
  { Mips::SB, Mips::SB, Mips::SB_MMR6 },
  { Mips::SEB, Mips::SEB, Mips::SEB_MMR6 },
  { Mips::SEH, Mips::SEH, Mips::SEH_MMR6 },
  { Mips::SSNOP, Mips::SSNOP, Mips::SSNOP_MMR6 },
  { Mips::SYNC, Mips::SYNC, Mips::SYNC_MMR6 },
  { Mips::SYNCI, Mips::SYNCI, Mips::SYNCI_MMR6 },
  { Mips::TRUNC_W_D64, Mips::TRUNC_W_D64, Mips::TRUNC_W_D_MMR6 },
  { Mips::TRUNC_W_S, Mips::TRUNC_W_S, Mips::TRUNC_W_S_MMR6 },
  { Mips::XOR, Mips::XOR, Mips::XOR_MMR6 },
  { Mips::XORi, Mips::XORi, Mips::XORI_MMR6 },
}; // End of Std2MicroMipsR6Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 31;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == Std2MicroMipsR6Table[mid][0]) {
      break;
    }
    if (Opcode < Std2MicroMipsR6Table[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inArch == Arch_se)
    return Std2MicroMipsR6Table[mid][1];
  if (inArch == Arch_micromipsr6)
    return Std2MicroMipsR6Table[mid][2];
  return -1;}

} // End Mips namespace
} // End llvm namespace
#endif // GET_INSTRMAP_INFO

